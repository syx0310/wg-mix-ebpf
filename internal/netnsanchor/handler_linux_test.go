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
