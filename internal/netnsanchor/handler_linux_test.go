//go:build linux

package netnsanchor

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestAnchorHandlerRejectsRepeatedStop(t *testing.T) {
	expected := testContract()
	expected.Token = strings.Repeat("b", 64)
	value := request{
		Version: protocolVersion,
		Action:  "stop",
		RunID:   expected.RunID,
		Role:    expected.Role,
		Token:   expected.Token,
	}
	var state stopState

	firstServer, firstClient := unixConnectionPair(t)
	firstResult := make(chan struct {
		stopped bool
		err     error
	}, 1)
	go func() {
		stopped, err := handleAnchorConnection(
			firstServer,
			expected,
			-1,
			uint32(os.Geteuid()),
			&state,
		)
		firstResult <- struct {
			stopped bool
			err     error
		}{stopped: stopped, err: err}
	}()
	if err := sendRequest(firstClient, value); err != nil {
		t.Fatalf("send first stop: %v", err)
	}
	if _, _, err := receiveResponse(firstClient, false); err != nil {
		t.Fatalf("receive first stop: %v", err)
	}
	_ = firstClient.Close()
	_ = firstServer.Close()
	first := <-firstResult
	if first.err != nil || !first.stopped {
		t.Fatalf("first stop result = stopped:%t err:%v", first.stopped, first.err)
	}

	secondServer, secondClient := unixConnectionPair(t)
	secondResult := make(chan error, 1)
	go func() {
		_, err := handleAnchorConnection(
			secondServer,
			expected,
			-1,
			uint32(os.Geteuid()),
			&state,
		)
		secondResult <- err
	}()
	if err := sendRequest(secondClient, value); err != nil {
		t.Fatalf("send repeated stop: %v", err)
	}
	if _, _, err := receiveResponse(secondClient, false); err == nil ||
		!strings.Contains(err.Error(), "already stopped") {
		t.Fatalf("repeated stop response = %v", err)
	}
	_ = secondClient.Close()
	_ = secondServer.Close()
	if err := <-secondResult; err == nil ||
		!strings.Contains(err.Error(), "already stopped") {
		t.Fatalf("repeated stop handler result = %v", err)
	}
}

func TestWaitForAnchorExitUsesBoundedPidfd(t *testing.T) {
	t.Run("exit", func(t *testing.T) {
		command := exec.Command("/bin/sh", "-c", "exit 0")
		if err := command.Start(); err != nil {
			t.Fatalf("start exiting child: %v", err)
		}
		pidfd, err := unix.PidfdOpen(command.Process.Pid, 0)
		if errors.Is(err, unix.ENOSYS) {
			_ = command.Wait()
			t.Skip("pidfd_open is unavailable")
		}
		if err != nil {
			_ = command.Wait()
			t.Fatalf("open exiting child pidfd: %v", err)
		}
		defer unix.Close(pidfd)
		if err := waitForAnchorExit(pidfd, time.Second); err != nil {
			_ = command.Wait()
			t.Fatalf("wait for exited child: %v", err)
		}
		if err := command.Wait(); err != nil {
			t.Fatalf("reap exited child: %v", err)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		command := exec.Command("/bin/sh", "-c", "read value")
		stdin, err := command.StdinPipe()
		if err != nil {
			t.Fatalf("open blocking child stdin: %v", err)
		}
		if err := command.Start(); err != nil {
			t.Fatalf("start blocking child: %v", err)
		}
		reaped := false
		defer func() {
			if reaped {
				return
			}
			_, _ = io.WriteString(stdin, "release\n")
			_ = stdin.Close()
			_ = command.Wait()
		}()
		pidfd, err := unix.PidfdOpen(command.Process.Pid, 0)
		if errors.Is(err, unix.ENOSYS) {
			_, _ = io.WriteString(stdin, "release\n")
			_ = stdin.Close()
			_ = command.Wait()
			reaped = true
			t.Skip("pidfd_open is unavailable")
		}
		if err != nil {
			_, _ = io.WriteString(stdin, "release\n")
			_ = stdin.Close()
			_ = command.Wait()
			reaped = true
			t.Fatalf("open blocking child pidfd: %v", err)
		}
		defer unix.Close(pidfd)
		if err := waitForAnchorExit(pidfd, 20*time.Millisecond); err == nil {
			t.Fatal("live child unexpectedly satisfied bounded pidfd wait")
		}
		if _, err := io.WriteString(stdin, "release\n"); err != nil {
			t.Fatalf("release blocking child: %v", err)
		}
		if err := stdin.Close(); err != nil {
			t.Fatalf("close blocking child stdin: %v", err)
		}
		if err := waitForAnchorExit(pidfd, time.Second); err != nil {
			t.Fatalf("wait for released child: %v", err)
		}
		waitErr := command.Wait()
		reaped = true
		if waitErr != nil {
			t.Fatalf("reap released child: %v", waitErr)
		}
	})
}

func TestTerminateAndReapWorkerUsesExactPidfd(t *testing.T) {
	command := exec.Command("/bin/sleep", "30")
	if err := command.Start(); err != nil {
		t.Fatalf("start blocking direct child: %v", err)
	}
	pidfd, err := unix.PidfdOpen(command.Process.Pid, 0)
	if errors.Is(err, unix.ENOSYS) {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Skip("pidfd_open is unavailable")
	}
	if err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("open exact direct-child pidfd: %v", err)
	}
	defer unix.Close(pidfd)
	workerWait := make(chan error, 1)
	go func() {
		workerWait <- command.Wait()
	}()
	reaped := false
	defer func() {
		if reaped {
			return
		}
		_ = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
		select {
		case <-workerWait:
		case <-time.After(time.Second):
		}
	}()
	started := time.Now()
	if err := terminateAndReapWorker(pidfd, workerWait, time.Second); err != nil {
		t.Fatalf("terminate and reap exact direct child: %v", err)
	}
	reaped = true
	if elapsed := time.Since(started); elapsed >= 2*time.Second {
		t.Fatalf("pidfd reap took %s, want less than two seconds", elapsed)
	}
	if command.ProcessState == nil {
		t.Fatal("direct child was not reaped into a process state")
	}
}

func TestTerminateAndReapWorkerWaitsAfterSignalFailure(t *testing.T) {
	signalFailure := errors.New("injected pidfd signal failure")
	workerWait := make(chan error)
	signalCalled := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- terminateAndReapWorkerWithSignal(
			41,
			workerWait,
			time.Second,
			func(pidfd int, signal unix.Signal) error {
				if pidfd != 41 || signal != unix.SIGKILL {
					t.Errorf(
						"signal target = pidfd:%d signal:%d, want pidfd:41 SIGKILL",
						pidfd,
						signal,
					)
				}
				close(signalCalled)
				return signalFailure
			},
		)
	}()
	<-signalCalled

	reaped := make(chan struct{})
	go func() {
		workerWait <- nil
		close(reaped)
	}()
	select {
	case <-reaped:
	case earlyErr := <-result:
		t.Fatalf("signal failure returned before child reap: %v", earlyErr)
	case <-time.After(time.Second):
		t.Fatal("worker reap did not receive the eventual wait result")
	}
	err := <-result
	if !errors.Is(err, signalFailure) {
		t.Fatalf("combined worker result = %v, want signal failure", err)
	}
}

func TestTerminateAndReapWorkerConsumesAlreadyExitedWaitAfterSignalFailure(
	t *testing.T,
) {
	signalFailure := errors.New("injected signal failure after exit")
	workerWait := make(chan error, 1)
	workerWait <- nil
	err := terminateAndReapWorkerWithSignal(
		42,
		workerWait,
		time.Second,
		func(int, unix.Signal) error {
			return signalFailure
		},
	)
	if !errors.Is(err, signalFailure) {
		t.Fatalf("combined already-exited result = %v, want signal failure", err)
	}
	if remaining := len(workerWait); remaining != 0 {
		t.Fatalf("already-exited wait results remaining = %d, want zero", remaining)
	}
}

func TestTerminateAndReapWorkerCombinesSignalAndWaitFailures(t *testing.T) {
	signalFailure := errors.New("injected signal failure")
	waitFailure := errors.New("injected wait failure")
	workerWait := make(chan error, 1)
	workerWait <- waitFailure
	err := terminateAndReapWorkerWithSignal(
		42,
		workerWait,
		time.Second,
		func(int, unix.Signal) error {
			return signalFailure
		},
	)
	if !errors.Is(err, signalFailure) || !errors.Is(err, waitFailure) {
		t.Fatalf(
			"combined worker result = %v, want signal and wait failures",
			err,
		)
	}
}

func TestTerminateAndReapWorkerCombinesSignalFailureWithBoundedTimeout(
	t *testing.T,
) {
	signalFailure := errors.New("injected persistent signal failure")
	workerWait := make(chan error)
	err := terminateAndReapWorkerWithSignal(
		43,
		workerWait,
		20*time.Millisecond,
		func(int, unix.Signal) error {
			return signalFailure
		},
	)
	if !errors.Is(err, signalFailure) ||
		!strings.Contains(err.Error(), "not reaped before the bounded deadline") {
		t.Fatalf("combined timeout result = %v", err)
	}
}

func TestTerminateAndReapDirectChildWaitsAfterKillFailure(t *testing.T) {
	command := exec.Command("/bin/sh", "-c", "exit 0")
	if err := command.Start(); err != nil {
		t.Fatalf("start self-exiting direct child: %v", err)
	}
	killFailure := errors.New("injected direct-child kill failure")
	err := terminateAndReapDirectChildWithKill(
		command,
		time.Second,
		func() error {
			return killFailure
		},
	)
	if !errors.Is(err, killFailure) {
		t.Fatalf("combined direct-child result = %v, want kill failure", err)
	}
	if command.ProcessState == nil {
		t.Fatal("self-exiting direct child was not reaped after kill failure")
	}
}
