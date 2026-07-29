package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/control"
	"github.com/syx0310/wg-mix-ebpf/internal/lockfile"
	"github.com/syx0310/wg-mix-ebpf/internal/reconcile"
	"golang.org/x/sys/unix"
)

const testDaemonInstanceID = "0123456789abcdef0123456789abcdef"

func TestValidateConfigPathForRequest(t *testing.T) {
	status := &Status{ConfigPath: "/etc/wg-mix-ebpf/config.yaml"}
	if err := ValidateConfigPathForRequest(status, "/etc/wg-mix-ebpf/config.yaml", "reload"); err != nil {
		t.Fatalf("same config rejected: %v", err)
	}
	err := ValidateConfigPathForRequest(status, "/tmp/other.yaml", "reload")
	if err == nil {
		t.Fatal("expected mismatched config to be rejected")
	}
	if !strings.Contains(err.Error(), "refusing reload request") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRequestQueueAdmissionIsBounded(t *testing.T) {
	runDir := t.TempDir()
	if err := ensureRequestDirs(runDir); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxPendingRequestFiles-1; i++ {
		id := fmt.Sprintf("%032x", i)
		if err := os.WriteFile(requestPath(runDir, id), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var admitted atomic.Int32
	errs := make(chan error, 8)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := enqueueRequest(t.Context(), runDir, "reload", "/etc/wg-mix-ebpf/config.yaml", testDaemonInstanceID); err == nil {
				admitted.Add(1)
			} else if !strings.Contains(err.Error(), "request queue is full") {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent admission error = %v", err)
	}
	if admitted.Load() != 1 {
		t.Fatalf("concurrent admissions = %d, want exactly 1", admitted.Load())
	}
	if _, err := enqueueRequest(t.Context(), runDir, "reload", "/etc/wg-mix-ebpf/config.yaml", testDaemonInstanceID); err == nil ||
		!strings.Contains(err.Error(), "request queue is full") {
		t.Fatalf("request queue capacity error = %v", err)
	}
	count, err := countJSONFiles(filepath.Join(runDir, requestsDirName))
	if err != nil {
		t.Fatal(err)
	}
	if count != maxPendingRequestFiles {
		t.Fatalf("request file count = %d, want %d", count, maxPendingRequestFiles)
	}
}

func TestRequestQueueRejectsSymlinkDirectory(t *testing.T) {
	runDir := t.TempDir()
	target := t.TempDir()
	if err := os.Symlink(target, filepath.Join(runDir, requestsDirName)); err != nil {
		t.Fatal(err)
	}
	if err := ensureRequestDirs(runDir); err == nil || !strings.Contains(err.Error(), "not a real directory") {
		t.Fatalf("request symlink directory error = %v", err)
	}
}

func TestRequestControlFilesRejectSymlinkAndNonRegularFiles(t *testing.T) {
	t.Run("request-symlink", func(t *testing.T) {
		runDir := t.TempDir()
		targetRunDir := t.TempDir()
		if err := ensureRequestDirs(runDir); err != nil {
			t.Fatal(err)
		}
		request := daemonRequest{
			Version:            requestProtocolVersion,
			ID:                 "11111111111111111111111111111111",
			Kind:               "reload",
			ExpectedInstanceID: testDaemonInstanceID,
			CreatedAt:          time.Now(),
		}
		if err := writeRequestFile(targetRunDir, request); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(requestPath(targetRunDir, request.ID), requestPath(runDir, request.ID)); err != nil {
			t.Fatal(err)
		}
		if _, err := pendingRequests(runDir); err == nil || !strings.Contains(err.Error(), "symbolic-link") {
			t.Fatalf("symlink request error = %v", err)
		}
	})

	t.Run("ack-symlink", func(t *testing.T) {
		runDir := t.TempDir()
		targetRunDir := t.TempDir()
		if err := ensureRequestDirs(runDir); err != nil {
			t.Fatal(err)
		}
		if err := ensureRequestDirs(targetRunDir); err != nil {
			t.Fatal(err)
		}
		id := "22222222222222222222222222222222"
		if err := writeJSONAtomic(filepath.Join(targetRunDir, acksDirName), id+".json", requestAck{
			Version: requestProtocolVersion,
			ID:      id,
			Kind:    "reload",
		}); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(ackPath(targetRunDir, id), ackPath(runDir, id)); err != nil {
			t.Fatal(err)
		}
		if _, err := readRequestAck(runDir, id); err == nil || !strings.Contains(err.Error(), "symbolic-link") {
			t.Fatalf("symlink ack error = %v", err)
		}
	})

	t.Run("ack-fifo", func(t *testing.T) {
		runDir := t.TempDir()
		if err := ensureRequestDirs(runDir); err != nil {
			t.Fatal(err)
		}
		id := "33333333333333333333333333333333"
		if err := syscall.Mkfifo(ackPath(runDir, id), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readRequestAck(runDir, id); err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("non-regular ack error = %v", err)
		}
	})
}

func TestAckPruningIsBoundedAndPreservesCrashDedup(t *testing.T) {
	runDir := t.TempDir()
	if err := ensureRequestDirs(runDir); err != nil {
		t.Fatal(err)
	}
	base := time.Now().Add(-time.Hour)
	for i := 0; i < maxRetainedAckFiles+10; i++ {
		id := fmt.Sprintf("%032x", i)
		path := ackPath(runDir, id)
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		stamp := base.Add(time.Duration(i) * time.Second)
		if err := os.Chtimes(path, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	pairedID := fmt.Sprintf("%032x", 0)
	if err := os.WriteFile(requestPath(runDir, pairedID), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := pruneAcknowledgements(runDir); err != nil {
		t.Fatal(err)
	}
	count, err := countJSONFiles(filepath.Join(runDir, acksDirName))
	if err != nil {
		t.Fatal(err)
	}
	if count != maxRetainedAckFiles {
		t.Fatalf("retained ack count = %d, want %d", count, maxRetainedAckFiles)
	}
	if _, err := os.Stat(ackPath(runDir, pairedID)); err != nil {
		t.Fatalf("ack paired with an unremoved request was pruned: %v", err)
	}
	newestID := fmt.Sprintf("%032x", maxRetainedAckFiles+9)
	if _, err := os.Stat(ackPath(runDir, newestID)); err != nil {
		t.Fatalf("newest ack was pruned before older unpaired acks: %v", err)
	}
}

func TestConsumedAckCleanupWaitsForRequestRemoval(t *testing.T) {
	runDir := t.TempDir()
	if err := ensureRequestDirs(runDir); err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprintf("%032x", 1)
	if err := os.WriteFile(ackPath(runDir, id), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(requestPath(runDir, id), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	consumed, err := consumeAckIfRequestRemoved(runDir, id)
	if err != nil {
		t.Fatal(err)
	}
	if consumed {
		t.Fatal("ack was consumed before its request was removed")
	}
	if _, err := os.Stat(ackPath(runDir, id)); err != nil {
		t.Fatalf("ack needed to deduplicate a retained request was removed: %v", err)
	}
	if err := os.Remove(requestPath(runDir, id)); err != nil {
		t.Fatal(err)
	}
	consumed, err = consumeAckIfRequestRemoved(runDir, id)
	if err != nil {
		t.Fatal(err)
	}
	if !consumed {
		t.Fatal("ack was not consumed after its request was removed")
	}
	if _, err := os.Stat(ackPath(runDir, id)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("consumed ack was not removed: %v", err)
	}
}

func TestRequestReturnsValidatedAckBeforeRequestRemoval(t *testing.T) {
	runDir := t.TempDir()
	configPath := filepath.Join(runDir, "config.yaml")
	status := Status{
		PID:             os.Getpid(),
		ConfigPath:      configPath,
		State:           "active",
		RequestProtocol: requestProtocolVersion,
		InstanceID:      testDaemonInstanceID,
	}
	if err := writeStatus(runDir, status); err != nil {
		t.Fatal(err)
	}

	type ackResult struct {
		id  string
		err error
	}
	ackWritten := make(chan ackResult, 1)
	go func() {
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			entries, err := os.ReadDir(filepath.Join(runDir, requestsDirName))
			if err == nil {
				for _, entry := range entries {
					if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
						continue
					}
					id := strings.TrimSuffix(entry.Name(), ".json")
					data, err := readRegularControlFile(requestPath(runDir, id))
					if err != nil {
						ackWritten <- ackResult{err: err}
						return
					}
					var request daemonRequest
					if err := json.Unmarshal(data, &request); err != nil {
						ackWritten <- ackResult{err: err}
						return
					}
					err = writeJSONAtomic(filepath.Join(runDir, acksDirName), id+".json", requestAck{
						Version:     requestProtocolVersion,
						ID:          id,
						Kind:        request.Kind,
						CompletedAt: time.Now(),
						Status:      status,
					})
					ackWritten <- ackResult{id: id, err: err}
					return
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				ackWritten <- ackResult{err: err}
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		ackWritten <- ackResult{err: errors.New("request was not enqueued")}
	}()

	got, err := RequestReload(t.Context(), runDir, configPath, time.Second)
	if err != nil {
		t.Fatalf("request did not return the durable ack: %v", err)
	}
	if got.InstanceID != testDaemonInstanceID {
		t.Fatalf("ack status instance = %q, want %q", got.InstanceID, testDaemonInstanceID)
	}
	result := <-ackWritten
	if result.err != nil {
		t.Fatal(result.err)
	}
	if _, err := os.Stat(requestPath(runDir, result.id)); err != nil {
		t.Fatalf("request needed for crash deduplication was removed: %v", err)
	}
	if _, err := os.Stat(ackPath(runDir, result.id)); err != nil {
		t.Fatalf("ack needed for crash deduplication was removed: %v", err)
	}
}

func TestPendingRequestAckValidationBindsKindAndDaemonInstance(t *testing.T) {
	otherInstanceID := "fedcba9876543210fedcba9876543210"
	tests := []struct {
		name          string
		kind          string
		instanceID    string
		requestError  string
		errorCode     string
		wantErr       string
		wantProcessed bool
	}{
		{
			name:       "wrong-kind",
			kind:       "stop",
			instanceID: testDaemonInstanceID,
			wantErr:    "does not match request kind",
		},
		{
			name:       "normal-ack-from-wrong-instance",
			kind:       "reload",
			instanceID: otherInstanceID,
			wantErr:    "does not match request instance",
		},
		{
			name:         "daemon-changed-from-request-instance",
			kind:         "reload",
			instanceID:   testDaemonInstanceID,
			requestError: ErrDaemonNotRunning.Error(),
			errorCode:    ackErrorDaemonChanged,
			wantErr:      "was written by request instance",
		},
		{
			name:       "daemon-changed-without-error",
			kind:       "reload",
			instanceID: otherInstanceID,
			errorCode:  ackErrorDaemonChanged,
			wantErr:    "is missing an error",
		},
		{
			name:          "valid-normal-ack",
			kind:          "reload",
			instanceID:    testDaemonInstanceID,
			wantProcessed: true,
		},
		{
			name:          "valid-cross-instance-rejection",
			kind:          "reload",
			instanceID:    otherInstanceID,
			requestError:  ErrDaemonNotRunning.Error(),
			errorCode:     ackErrorDaemonChanged,
			wantProcessed: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runDir := t.TempDir()
			request, err := enqueueRequest(
				t.Context(),
				runDir,
				"reload",
				"/etc/wg-mix-ebpf/config.yaml",
				testDaemonInstanceID,
			)
			if err != nil {
				t.Fatal(err)
			}
			if err := writeJSONAtomic(filepath.Join(runDir, acksDirName), request.ID+".json", requestAck{
				Version:     requestProtocolVersion,
				ID:          request.ID,
				Kind:        tt.kind,
				CompletedAt: time.Now(),
				Status:      Status{InstanceID: tt.instanceID},
				Error:       tt.requestError,
				ErrorCode:   tt.errorCode,
			}); err != nil {
				t.Fatal(err)
			}

			pending, err := pendingRequests(runDir)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("pending request validation error = %v, want %q", err, tt.wantErr)
				}
				if _, statErr := os.Stat(requestPath(runDir, request.ID)); statErr != nil {
					t.Fatalf("invalid ack removed its request: %v", statErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !tt.wantProcessed || len(pending) != 0 {
				t.Fatalf("pending requests = %#v, want acknowledged request removed", pending)
			}
			if _, statErr := os.Stat(requestPath(runDir, request.ID)); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("acknowledged request was not removed: %v", statErr)
			}
			if _, statErr := os.Stat(ackPath(runDir, request.ID)); statErr != nil {
				t.Fatalf("deduplication ack was removed with request: %v", statErr)
			}
		})
	}
}

func TestReadStatusRejectsUnsafeControlFiles(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		runDir := t.TempDir()
		targetRunDir := t.TempDir()
		if err := writeStatus(targetRunDir, Status{PID: os.Getpid()}); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(
			filepath.Join(targetRunDir, "status.json"),
			filepath.Join(runDir, "status.json"),
		); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadStatus(runDir); err == nil || !strings.Contains(err.Error(), "symbolic-link") {
			t.Fatalf("symlink status error = %v", err)
		}
	})

	t.Run("fifo", func(t *testing.T) {
		runDir := t.TempDir()
		if err := syscall.Mkfifo(filepath.Join(runDir, "status.json"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadStatus(runDir); err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("fifo status error = %v", err)
		}
	})

	t.Run("hardlink", func(t *testing.T) {
		runDir := t.TempDir()
		target := filepath.Join(t.TempDir(), "status.json")
		if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(target, filepath.Join(runDir, "status.json")); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadStatus(runDir); err == nil || !strings.Contains(err.Error(), "links") {
			t.Fatalf("hard-linked status error = %v", err)
		}
	})

	t.Run("oversized", func(t *testing.T) {
		runDir := t.TempDir()
		if err := os.WriteFile(
			filepath.Join(runDir, "status.json"),
			bytes.Repeat([]byte("x"), maxControlFileBytes+1),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadStatus(runDir); err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("oversized status error = %v", err)
		}
	})
}

func TestReadOpenedRegularControlFileAllowsUnlinkedSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "request.json")
	want := []byte(`{"version":1,"id":"0123456789abcdef0123456789abcdef"}`)
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := openControlFileNoFollow(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	if stat.Nlink != 0 {
		t.Fatalf("unlinked open control file has %d links, want 0", stat.Nlink)
	}
	got, err := readOpenedRegularControlFile(file)
	if err != nil {
		t.Fatalf("read unlinked open control file: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("unlinked control snapshot = %q, want %q", got, want)
	}
}

func TestOpenedStatusSnapshotSurvivesAtomicReplacement(t *testing.T) {
	runDir := t.TempDir()
	oldStatus := Status{
		PID:             os.Getpid(),
		State:           "starting",
		RequestProtocol: requestProtocolVersion,
		InstanceID:      testDaemonInstanceID,
	}
	newStatus := oldStatus
	newStatus.State = "active"
	newStatus.InstanceID = "fedcba9876543210fedcba9876543210"
	if err := writeStatus(runDir, oldStatus); err != nil {
		t.Fatal(err)
	}
	file, err := openControlFileNoFollow(filepath.Join(runDir, "status.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := writeStatus(runDir, newStatus); err != nil {
		t.Fatal(err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	if stat.Nlink != 0 {
		t.Fatalf("atomically replaced status snapshot has %d links, want 0", stat.Nlink)
	}
	data, err := readOpenedRegularControlFile(file)
	if err != nil {
		t.Fatalf("read replaced status snapshot: %v", err)
	}
	var snapshot Status
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.InstanceID != oldStatus.InstanceID || snapshot.State != oldStatus.State {
		t.Fatalf("opened status snapshot = %#v, want old status %#v", snapshot, oldStatus)
	}
	current, err := ReadStatus(runDir)
	if err != nil {
		t.Fatal(err)
	}
	if current.InstanceID != newStatus.InstanceID || current.State != newStatus.State {
		t.Fatalf("current status = %#v, want replacement %#v", current, newStatus)
	}
}

func TestNewInstanceScanToleratesOldClientWithdrawalAfterEnumeration(t *testing.T) {
	runDir := t.TempDir()
	request, err := enqueueRequest(
		t.Context(),
		runDir,
		"stop",
		"/etc/wg-mix-ebpf/config.yaml",
		"fedcba9876543210fedcba9876543210",
	)
	if err != nil {
		t.Fatal(err)
	}
	requestDir := filepath.Join(runDir, requestsDirName)
	entries, err := os.ReadDir(requestDir)
	if err != nil {
		t.Fatal(err)
	}
	var enumeratedPath string
	for _, entry := range entries {
		if entry.Name() == request.ID+".json" {
			enumeratedPath = filepath.Join(requestDir, entry.Name())
			break
		}
	}
	if enumeratedPath == "" {
		t.Fatal("new daemon scan did not enumerate stale request")
	}

	// The old client observes the instance change and withdraws its request
	// after the new daemon has enumerated the directory but before it opens the
	// file.
	if err := os.Remove(enumeratedPath); err != nil {
		t.Fatal(err)
	}
	if pending, present, err := readPendingRequest(runDir, enumeratedPath, request.ID); err != nil || present {
		t.Fatalf("withdrawn request became fatal: pending=%#v present=%t err=%v", pending, present, err)
	}
}

func TestQueuedStopBeforeStartupIsAcknowledged(t *testing.T) {
	runDir := t.TempDir()
	leasePath := filepath.Join(t.TempDir(), "daemon.lease")
	maintenancePath := filepath.Join(filepath.Dir(leasePath), "maintenance.gate")
	opts := testOptions(runDir, leasePath, maintenancePath, nil)
	request, err := enqueueRequest(t.Context(), runDir, "stop", opts.ConfigPath, opts.hooks.instanceID)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		done <- Run(t.Context(), opts)
	}()
	ack := waitForAck(t, runDir, request.ID)
	if ack.Error != "" || ack.Status.State != "stopped" {
		t.Fatalf("startup stop ack = %#v", ack)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("daemon failed queued startup stop: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("daemon did not stop for request queued during startup")
	}
}

func TestStaleStopRequestCannotStopNewDaemonInstance(t *testing.T) {
	runDir := t.TempDir()
	leasePath := filepath.Join(t.TempDir(), "daemon.lease")
	maintenancePath := filepath.Join(filepath.Dir(leasePath), "maintenance.gate")
	opts := testOptions(runDir, leasePath, maintenancePath, nil)
	staleInstanceID := "fedcba9876543210fedcba9876543210"
	request, err := enqueueRequest(t.Context(), runDir, "stop", opts.ConfigPath, staleInstanceID)
	if err != nil {
		t.Fatal(err)
	}

	runCtx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- Run(runCtx, opts)
	}()
	ack := waitForAck(t, runDir, request.ID)
	if ack.ErrorCode != ackErrorDaemonChanged || !strings.Contains(ack.Error, ErrDaemonNotRunning.Error()) {
		t.Fatalf("stale stop ack = %#v", ack)
	}
	waitForDaemonState(t, runDir, "active")
	select {
	case err := <-done:
		t.Fatalf("stale stop terminated new daemon: %v", err)
	default:
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("new daemon cleanup failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("new daemon did not stop after test cancellation")
	}
}

func TestRequestRejectsNotRunningDaemonBeforeEnqueue(t *testing.T) {
	runDir := t.TempDir()
	configPath := filepath.Join(runDir, "config.yaml")
	if err := writeStatus(runDir, Status{
		PID:             1 << 30,
		ConfigPath:      configPath,
		State:           "active",
		RequestProtocol: requestProtocolVersion,
		InstanceID:      testDaemonInstanceID,
	}); err != nil {
		t.Fatal(err)
	}
	_, err := RequestReload(t.Context(), runDir, configPath, time.Second)
	if !errors.Is(err, ErrDaemonNotRunning) {
		t.Fatalf("not-running request error = %v", err)
	}
	if count, countErr := countJSONFiles(filepath.Join(runDir, requestsDirName)); countErr == nil || !errors.Is(countErr, os.ErrNotExist) || count != 0 {
		t.Fatalf("not-running daemon left queued request: count=%d err=%v", count, countErr)
	}
}

func TestRequestWithdrawsWhenDaemonExitsAfterInitialStatus(t *testing.T) {
	runDir := t.TempDir()
	configPath := filepath.Join(runDir, "config.yaml")
	status := Status{
		PID:             os.Getpid(),
		ConfigPath:      configPath,
		State:           "active",
		RequestProtocol: requestProtocolVersion,
		InstanceID:      testDaemonInstanceID,
	}
	if err := writeStatus(runDir, status); err != nil {
		t.Fatal(err)
	}
	statusUpdated := make(chan error, 1)
	go func() {
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			entries, err := os.ReadDir(filepath.Join(runDir, requestsDirName))
			if err == nil {
				for _, entry := range entries {
					if strings.HasSuffix(entry.Name(), ".json") {
						status.PID = 1 << 30
						statusUpdated <- writeStatus(runDir, status)
						return
					}
				}
			}
			time.Sleep(5 * time.Millisecond)
		}
		statusUpdated <- errors.New("request was not enqueued")
	}()

	_, err := RequestReload(t.Context(), runDir, configPath, time.Second)
	if !errors.Is(err, ErrDaemonNotRunning) {
		t.Fatalf("daemon exit race error = %v", err)
	}
	if updateErr := <-statusUpdated; updateErr != nil {
		t.Fatal(updateErr)
	}
	count, countErr := countJSONFiles(filepath.Join(runDir, requestsDirName))
	if countErr != nil {
		t.Fatal(countErr)
	}
	if count != 0 {
		t.Fatalf("withdrawn request count = %d, want 0", count)
	}
}

func TestRequestWaitIgnoresUnrelatedStatusUpdates(t *testing.T) {
	runDir := t.TempDir()
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(runDir, "config.yaml")
	status := Status{
		PID:             os.Getpid(),
		ConfigPath:      configPath,
		State:           "active",
		LastSuccess:     time.Now(),
		RequestProtocol: requestProtocolVersion,
		InstanceID:      testDaemonInstanceID,
	}
	if err := writeStatus(runDir, status); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(25 * time.Millisecond)
		status.LastSuccess = time.Now().Add(time.Second)
		status.LastReason = "poll-noop"
		_ = writeStatus(runDir, status)
		otherID, _ := newRequestID()
		_ = writeJSONAtomic(filepath.Join(runDir, acksDirName), otherID+".json", requestAck{
			Version:     requestProtocolVersion,
			ID:          otherID,
			Kind:        "reload",
			CompletedAt: time.Now(),
			Status:      status,
		})
	}()

	_, err := RequestReload(t.Context(), runDir, configPath, 125*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("unrelated status update acknowledged request: %v", err)
	}
}

func TestRequestRejectsDaemonWithoutAckProtocol(t *testing.T) {
	runDir := t.TempDir()
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(runDir, "config.yaml")
	if err := writeStatus(runDir, Status{
		PID:        os.Getpid(),
		ConfigPath: configPath,
		State:      "active",
	}); err != nil {
		t.Fatal(err)
	}
	_, err := RequestReload(t.Context(), runDir, configPath, time.Second)
	if err == nil || !strings.Contains(err.Error(), "restart the daemon") {
		t.Fatalf("old request protocol was not rejected clearly: %v", err)
	}
}

func TestConcurrentStopSupersedesReloadWithPerRequestAcks(t *testing.T) {
	runDir := t.TempDir()
	leasePath := filepath.Join(t.TempDir(), "daemon.lease")
	maintenancePath := filepath.Join(filepath.Dir(leasePath), "maintenance.gate")
	opts := testOptions(runDir, leasePath, maintenancePath, nil)
	reloadRequest, err := enqueueRequest(t.Context(), runDir, "reload", opts.ConfigPath, opts.hooks.instanceID)
	if err != nil {
		t.Fatal(err)
	}
	stopRequest, err := enqueueRequest(t.Context(), runDir, "stop", opts.ConfigPath, opts.hooks.instanceID)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- Run(t.Context(), opts)
	}()
	reloadAck := waitForAck(t, runDir, reloadRequest.ID)
	stopAck := waitForAck(t, runDir, stopRequest.ID)
	if !strings.Contains(reloadAck.Error, "superseded by stop request "+stopRequest.ID) {
		t.Fatalf("reload ack does not define stop precedence: %#v", reloadAck)
	}
	if stopAck.Error != "" || stopAck.Status.State != "stopped" {
		t.Fatalf("stop ack = %#v", stopAck)
	}
	if reloadAck.ID == stopAck.ID {
		t.Fatalf("concurrent requests shared ack id %q", reloadAck.ID)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("daemon stop failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("daemon did not exit after concurrent stop")
	}
}

func TestDelayedLegacyStopIsRecordedAndIgnored(t *testing.T) {
	runDir := t.TempDir()
	leasePath := filepath.Join(t.TempDir(), "daemon.lease")
	maintenancePath := filepath.Join(filepath.Dir(leasePath), "maintenance.gate")
	opts := testOptions(runDir, leasePath, maintenancePath, nil)
	runCtx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- Run(runCtx, opts)
	}()
	waitForDaemonState(t, runDir, "active")

	if err := os.WriteFile(filepath.Join(runDir, "reload.request"), []byte("stop:from-old-instance\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	status := waitForDaemonReason(t, runDir, "legacy-request-ignored")
	if !strings.Contains(status.LastError, "legacy stop request is disabled") {
		t.Fatalf("legacy stop warning = %#v", status)
	}
	select {
	case err := <-done:
		t.Fatalf("legacy stop terminated the versioned daemon: %v", err)
	default:
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("daemon cleanup failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("daemon did not stop after test cancellation")
	}
}

func TestUnsafeLegacyNotificationIsRecordedAndIgnored(t *testing.T) {
	runDir := t.TempDir()
	leasePath := filepath.Join(t.TempDir(), "daemon.lease")
	maintenancePath := filepath.Join(filepath.Dir(leasePath), "maintenance.gate")
	opts := testOptions(runDir, leasePath, maintenancePath, nil)
	runCtx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- Run(runCtx, opts)
	}()
	waitForDaemonState(t, runDir, "active")

	target := filepath.Join(t.TempDir(), "runtime.request")
	if err := os.WriteFile(target, []byte("ifup\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(runDir, "runtime.request")); err != nil {
		t.Fatal(err)
	}
	status := waitForDaemonReason(t, runDir, "legacy-request-ignored")
	if !strings.Contains(status.LastError, "symbolic-link") {
		t.Fatalf("unsafe legacy warning = %#v", status)
	}
	select {
	case err := <-done:
		t.Fatalf("unsafe legacy notification terminated daemon: %v", err)
	default:
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("daemon cleanup failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("daemon did not stop after test cancellation")
	}
}

func TestLegacyRequestStampUsesBoundedSafeReads(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		runDir := t.TempDir()
		target := filepath.Join(t.TempDir(), "reload.request")
		if err := os.WriteFile(target, []byte("reload:old\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(runDir, "reload.request")); err != nil {
			t.Fatal(err)
		}
		stamp := requestStamp(runDir)
		if !strings.Contains(stamp.Reload.ReadError, "symbolic-link") {
			t.Fatalf("symlink legacy stamp = %#v", stamp)
		}
	})

	t.Run("fifo", func(t *testing.T) {
		runDir := t.TempDir()
		if err := syscall.Mkfifo(filepath.Join(runDir, "runtime.request"), 0o600); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		stamp := requestStamp(runDir)
		if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
			t.Fatalf("FIFO legacy read blocked for %s", elapsed)
		}
		if !strings.Contains(stamp.Runtime.ReadError, "not a regular file") {
			t.Fatalf("FIFO legacy stamp = %#v", stamp)
		}
	})

	t.Run("hardlink", func(t *testing.T) {
		runDir := t.TempDir()
		target := filepath.Join(t.TempDir(), "reload.request")
		if err := os.WriteFile(target, []byte("reload:old\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(target, filepath.Join(runDir, "reload.request")); err != nil {
			t.Fatal(err)
		}
		stamp := requestStamp(runDir)
		if !strings.Contains(stamp.Reload.ReadError, "links") {
			t.Fatalf("hard-linked legacy stamp = %#v", stamp)
		}
	})

	t.Run("oversize", func(t *testing.T) {
		runDir := t.TempDir()
		if err := os.WriteFile(
			filepath.Join(runDir, "reload.request"),
			bytes.Repeat([]byte("x"), maxControlFileBytes+1),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
		stamp := requestStamp(runDir)
		if !strings.Contains(stamp.Reload.ReadError, "exceeds") {
			t.Fatalf("oversize legacy stamp = %#v", stamp)
		}
	})
}

func TestLifecycleLeasePathIsGlobalForMutatingDaemon(t *testing.T) {
	first := lifecycleLeasePath(Options{RunDir: "/tmp/first"}, "/tmp/first", "")
	second := lifecycleLeasePath(Options{RunDir: "/tmp/second"}, "/tmp/second", "")
	if first != DefaultLifecycleLeasePath || second != DefaultLifecycleLeasePath {
		t.Fatalf("mutating daemon lease paths = %q and %q, want global %q", first, second, DefaultLifecycleLeasePath)
	}
	if got := lifecycleLeasePath(Options{DryRun: true}, "/tmp/dry-run", ""); got != "/tmp/dry-run/daemon.lease" {
		t.Fatalf("dry-run lease path = %q", got)
	}
	if got := lifecycleMaintenancePath(
		Options{RunDir: "/tmp/first"},
		"/tmp/first",
		"",
	); got != DefaultLifecycleMaintenancePath {
		t.Fatalf("mutating daemon maintenance path = %q", got)
	}
	if got := lifecycleMaintenancePath(
		Options{DryRun: true},
		"/tmp/dry-run",
		"",
	); got != "/tmp/dry-run/.daemon-maintenance.gate" {
		t.Fatalf("dry-run maintenance path = %q", got)
	}
}

func TestRunRejectsConcurrentDaemonAcrossRunDirs(t *testing.T) {
	leasePath := filepath.Join(t.TempDir(), "global", "daemon.lease")
	maintenancePath := filepath.Join(filepath.Dir(leasePath), "maintenance.gate")
	firstRunDir := filepath.Join(t.TempDir(), "first")
	secondRunDir := filepath.Join(t.TempDir(), "second")
	firstCtx, cancelFirst := context.WithCancel(t.Context())
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- Run(
			firstCtx,
			testOptions(firstRunDir, leasePath, maintenancePath, nil),
		)
	}()
	waitForDaemonState(t, firstRunDir, "active")

	err := Run(
		t.Context(),
		testOptions(secondRunDir, leasePath, maintenancePath, nil),
	)
	if !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("second daemon error = %v, want ErrAlreadyRunning", err)
	}

	cancelFirst()
	select {
	case err := <-firstDone:
		if err != nil {
			t.Fatalf("first daemon shutdown failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first daemon did not stop")
	}
}

func TestLifecycleLeaseDoesNotConflictWithOperationLock(t *testing.T) {
	runDir := t.TempDir()
	lease, err := acquireLifecycleLease(
		filepath.Join(runDir, "daemon.lease"),
		filepath.Join(runDir, "maintenance.gate"),
		leaseOwner{PID: os.Getpid(), RunDir: runDir},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()

	lockCtx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := lockfile.WithLock(lockCtx, runDir, func() error { return nil }); err != nil {
		t.Fatalf("operation lock deadlocked behind lifecycle lease: %v", err)
	}
}

func TestMaintenanceContentionPreservesErrAlreadyRunning(t *testing.T) {
	root := t.TempDir()
	leasePath := filepath.Join(root, "daemon.lease")
	maintenancePath := filepath.Join(root, "maintenance.gate")
	maintenance, err := lockfile.BeginLifecycleMaintenanceAt(
		leasePath,
		maintenancePath,
		lockfile.LifecycleOwner{PID: os.Getpid(), Action: "maintenance"},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer maintenance.Close()

	lease, err := acquireLifecycleLease(
		leasePath,
		maintenancePath,
		leaseOwner{PID: os.Getpid(), Action: "daemon-contender"},
	)
	if lease != nil {
		_ = lease.Close()
		t.Fatal("daemon contender unexpectedly acquired lifecycle lease")
	}
	if !errors.Is(err, ErrAlreadyRunning) ||
		!errors.Is(err, lockfile.ErrLifecycleMaintenanceHeld) {
		t.Fatalf("daemon maintenance contention error = %v", err)
	}
}

func TestDaemonCleanupReusesHeldLeaseWithoutSelfLock(t *testing.T) {
	root := t.TempDir()
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	runDir := filepath.Join(root, "run")
	leasePath := filepath.Join(root, "daemon.lease")
	maintenancePath := filepath.Join(root, "maintenance.gate")
	configPath := filepath.Join(root, "config.yaml")
	fakeBin := filepath.Join(root, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fakeBin, "nft"), []byte(
		"#!/bin/sh\nprintf '%s\\n' 'Error: No such file or directory' 'list table inet wg_mix_ebpf_guard' >&2\nexit 1\n",
	), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := os.WriteFile(configPath, []byte(`version: 1
underlays: []
wireguards: []
profiles: {}
startup_guard:
  mode: none
`), 0o600); err != nil {
		t.Fatal(err)
	}
	hooks := successfulRunHooks(leasePath, maintenancePath)
	hooks.stop = nil
	opts := testOptions(runDir, leasePath, maintenancePath, hooks)
	opts.ConfigPath = configPath

	baseCtx := lockfile.WithLifecyclePathsForTest(
		t.Context(),
		leasePath,
		maintenancePath,
	)
	runCtx, cancel := context.WithCancel(baseCtx)
	done := make(chan error, 1)
	go func() {
		done <- Run(runCtx, opts)
	}()
	waitForDaemonState(t, runDir, "active")
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("daemon cleanup self-locked or failed: %v", err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("daemon cleanup self-locked on its lifecycle lease")
	}
}

func TestRunReturnsErrorWhenCleanupTimesOut(t *testing.T) {
	runDir := t.TempDir()
	leasePath := filepath.Join(t.TempDir(), "daemon.lease")
	maintenancePath := filepath.Join(filepath.Dir(leasePath), "maintenance.gate")
	hooks := successfulRunHooks(leasePath, maintenancePath)
	hooks.stop = func(ctx context.Context, _ Options, _ string) (*reconcile.Result, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	opts := testOptions(runDir, leasePath, maintenancePath, hooks)
	opts.ShutdownTimeout = 25 * time.Millisecond

	runCtx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- Run(runCtx, opts)
	}()
	waitForDaemonState(t, runDir, "active")
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("cleanup timeout error = %v, want context deadline exceeded", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("daemon cleanup exceeded its deadline")
	}
	status := waitForDaemonState(t, runDir, "degraded")
	if !strings.Contains(status.LastError, "deadline exceeded") {
		t.Fatalf("degraded status does not report timeout: %#v", status)
	}
}

func TestCleanupHardTimeoutRetainsLeaseUntilWorkerFinishes(t *testing.T) {
	runDir := t.TempDir()
	leasePath := filepath.Join(t.TempDir(), "daemon.lease")
	maintenancePath := filepath.Join(filepath.Dir(leasePath), "maintenance.gate")
	cleanupStarted := make(chan struct{})
	releaseCleanup := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseCleanup) }) }
	defer release()

	hooks := successfulRunHooks(leasePath, maintenancePath)
	hooks.stop = func(context.Context, Options, string) (*reconcile.Result, error) {
		close(cleanupStarted)
		<-releaseCleanup
		return &reconcile.Result{State: &control.State{}, Action: "stop"}, nil
	}
	opts := testOptions(runDir, leasePath, maintenancePath, hooks)
	opts.ShutdownTimeout = 25 * time.Millisecond

	runCtx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- Run(runCtx, opts)
	}()
	waitForDaemonState(t, runDir, "active")
	start := time.Now()
	cancel()
	select {
	case <-cleanupStarted:
	case <-time.After(time.Second):
		t.Fatal("cleanup did not start")
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("hard timeout error = %v", err)
		}
		if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
			t.Fatalf("Run exceeded wall-clock cleanup bound: %s", elapsed)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Run remained blocked on context-ignoring cleanup")
	}

	if second, err := acquireLifecycleLease(
		leasePath,
		maintenancePath,
		leaseOwner{PID: os.Getpid(), Action: "second"},
	); !errors.Is(err, ErrAlreadyRunning) {
		if err == nil {
			_ = second.Close()
		}
		t.Fatalf("timed-out cleanup released lease while worker was active: %v", err)
	}

	release()
	deadline := time.Now().Add(time.Second)
	for {
		second, err := acquireLifecycleLease(
			leasePath,
			maintenancePath,
			leaseOwner{PID: os.Getpid(), Action: "second"},
		)
		if err == nil {
			_ = second.Close()
			break
		}
		if !errors.Is(err, ErrAlreadyRunning) || time.Now().After(deadline) {
			t.Fatalf("lease was not released after cleanup worker finished: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestCleanupErrorIsJoinedWithConcurrentDeadline(t *testing.T) {
	runDir := t.TempDir()
	leasePath := filepath.Join(t.TempDir(), "daemon.lease")
	maintenancePath := filepath.Join(filepath.Dir(leasePath), "maintenance.gate")
	hooks := successfulRunHooks(leasePath, maintenancePath)
	hooks.stop = func(ctx context.Context, _ Options, _ string) (*reconcile.Result, error) {
		<-ctx.Done()
		return nil, errors.New("cleanup returned after cancellation")
	}
	opts := testOptions(runDir, leasePath, maintenancePath, hooks)
	opts.ShutdownTimeout = 25 * time.Millisecond

	runCtx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- Run(runCtx, opts)
	}()
	waitForDaemonState(t, runDir, "active")
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "cleanup returned after cancellation") {
			t.Fatalf("cleanup/deadline error was not joined: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("daemon did not return joined cleanup/deadline error")
	}
}

func TestStopRequestCleanupFailureReturnsError(t *testing.T) {
	runDir := t.TempDir()
	leasePath := filepath.Join(t.TempDir(), "daemon.lease")
	maintenancePath := filepath.Join(filepath.Dir(leasePath), "maintenance.gate")
	hooks := successfulRunHooks(leasePath, maintenancePath)
	hooks.stop = func(context.Context, Options, string) (*reconcile.Result, error) {
		return nil, errors.New("detach failed")
	}
	opts := testOptions(runDir, leasePath, maintenancePath, hooks)

	done := make(chan error, 1)
	go func() {
		done <- Run(t.Context(), opts)
	}()
	waitForDaemonState(t, runDir, "active")

	status, requestErr := RequestStop(t.Context(), runDir, opts.ConfigPath, 2*time.Second)
	if requestErr == nil || !strings.Contains(requestErr.Error(), "detach failed") {
		t.Fatalf("stop request error = %v, status=%#v", requestErr, status)
	}
	if status == nil || status.State != "degraded" {
		t.Fatalf("stop request status = %#v, want degraded", status)
	}
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "detach failed") {
			t.Fatalf("daemon exit error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("daemon did not exit after failed stop request")
	}
}

func TestShutdownAggregatesCleanupAndFinalStatusFailures(t *testing.T) {
	runDir := t.TempDir()
	leasePath := filepath.Join(t.TempDir(), "daemon.lease")
	maintenancePath := filepath.Join(filepath.Dir(leasePath), "maintenance.gate")
	hooks := successfulRunHooks(leasePath, maintenancePath)
	hooks.stop = func(context.Context, Options, string) (*reconcile.Result, error) {
		return nil, errors.New("cleanup failed")
	}
	hooks.writeStatus = func(dir string, status Status) error {
		if status.LastReason == "signal" {
			return errors.New("status disk full")
		}
		return writeStatus(dir, status)
	}
	opts := testOptions(runDir, leasePath, maintenancePath, hooks)

	runCtx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- Run(runCtx, opts)
	}()
	waitForDaemonState(t, runDir, "active")
	cancel()

	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "cleanup failed") || !strings.Contains(err.Error(), "status disk full") {
			t.Fatalf("aggregated shutdown error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("daemon did not return aggregated shutdown error")
	}
}

func TestRunOnceReturnsCriticalStatusWriteFailure(t *testing.T) {
	runDir := t.TempDir()
	leasePath := filepath.Join(t.TempDir(), "daemon.lease")
	maintenancePath := filepath.Join(filepath.Dir(leasePath), "maintenance.gate")
	hooks := successfulRunHooks(leasePath, maintenancePath)
	var writes atomic.Int32
	hooks.writeStatus = func(dir string, status Status) error {
		if writes.Add(1) == 2 {
			return errors.New("status write failed")
		}
		return writeStatus(dir, status)
	}
	opts := testOptions(runDir, leasePath, maintenancePath, hooks)
	opts.Once = true

	err := Run(t.Context(), opts)
	if err == nil || !strings.Contains(err.Error(), "status write failed") {
		t.Fatalf("run-once status error = %v", err)
	}
}

func TestReloadStatusWriteFailureIsPersistedAndReturned(t *testing.T) {
	runDir := t.TempDir()
	leasePath := filepath.Join(t.TempDir(), "daemon.lease")
	maintenancePath := filepath.Join(filepath.Dir(leasePath), "maintenance.gate")
	hooks := successfulRunHooks(leasePath, maintenancePath)
	var writes atomic.Int32
	hooks.writeStatus = func(dir string, status Status) error {
		if writes.Add(1) == 3 {
			return errors.New("reload status write failed")
		}
		return writeStatus(dir, status)
	}
	opts := testOptions(runDir, leasePath, maintenancePath, hooks)

	done := make(chan error, 1)
	go func() {
		done <- Run(t.Context(), opts)
	}()
	waitForDaemonState(t, runDir, "active")

	status, requestErr := RequestReload(t.Context(), runDir, opts.ConfigPath, 2*time.Second)
	if requestErr == nil || !strings.Contains(requestErr.Error(), "reload status write failed") {
		t.Fatalf("reload request error = %v, status=%#v", requestErr, status)
	}
	if status == nil || status.State != "degraded" || !strings.Contains(status.LastError, "reload status write failed") {
		t.Fatalf("final status did not preserve critical write failure: %#v", status)
	}
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "reload status write failed") {
			t.Fatalf("daemon exit error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("daemon did not exit after critical status write failure")
	}
}

func TestSecondSignalRestoresDefaultBehavior(t *testing.T) {
	runDir := t.TempDir()
	leasePath := filepath.Join(t.TempDir(), "daemon.lease")
	maintenancePath := filepath.Join(filepath.Dir(leasePath), "maintenance.gate")
	cleanupStarted := filepath.Join(t.TempDir(), "cleanup-started")
	cmd := exec.Command(os.Args[0], "-test.run=^TestDaemonSecondSignalHelper$")
	cmd.Env = append(os.Environ(),
		"WG_MIX_EBPF_SECOND_SIGNAL_HELPER=1",
		"WG_MIX_EBPF_TEST_RUN_DIR="+runDir,
		"WG_MIX_EBPF_TEST_LEASE_PATH="+leasePath,
		"WG_MIX_EBPF_TEST_MAINTENANCE_PATH="+maintenancePath,
		"WG_MIX_EBPF_TEST_CLEANUP_STARTED="+cleanupStarted,
	)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
		}
	}()
	waitForDaemonState(t, runDir, "active")

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("send first SIGTERM: %v", err)
	}
	waitForPath(t, cleanupStarted)
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("send second SIGTERM: %v", err)
	}

	waitDone := make(chan error, 1)
	go func() {
		waitDone <- cmd.Wait()
	}()
	select {
	case err := <-waitDone:
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("second SIGTERM did not terminate helper: %v", err)
		}
		waitStatus, ok := exitErr.Sys().(syscall.WaitStatus)
		if !ok || !waitStatus.Signaled() || waitStatus.Signal() != syscall.SIGTERM {
			t.Fatalf("helper exit status = %#v, want SIGTERM", exitErr.Sys())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("second SIGTERM did not restore default termination behavior")
	}
}

func TestDaemonSecondSignalHelper(t *testing.T) {
	if os.Getenv("WG_MIX_EBPF_SECOND_SIGNAL_HELPER") != "1" {
		return
	}
	runDir := os.Getenv("WG_MIX_EBPF_TEST_RUN_DIR")
	leasePath := os.Getenv("WG_MIX_EBPF_TEST_LEASE_PATH")
	maintenancePath := os.Getenv("WG_MIX_EBPF_TEST_MAINTENANCE_PATH")
	cleanupStarted := os.Getenv("WG_MIX_EBPF_TEST_CLEANUP_STARTED")
	hooks := successfulRunHooks(leasePath, maintenancePath)
	hooks.stop = func(context.Context, Options, string) (*reconcile.Result, error) {
		if err := os.WriteFile(cleanupStarted, []byte("started\n"), 0o600); err != nil {
			return nil, err
		}
		select {}
	}
	opts := testOptions(runDir, leasePath, maintenancePath, hooks)
	opts.ShutdownTimeout = time.Hour
	if err := Run(context.Background(), opts); err != nil {
		t.Fatalf("helper daemon returned before second signal: %v", err)
	}
}

func testOptions(
	runDir string,
	leasePath string,
	maintenancePath string,
	hooks *runHooks,
) Options {
	if hooks == nil {
		hooks = successfulRunHooks(leasePath, maintenancePath)
	}
	return Options{
		ConfigPath:   filepath.Join(runDir, "config.yaml"),
		RunDir:       runDir,
		StateDir:     filepath.Join(runDir, "state"),
		PollInterval: time.Hour,
		hooks:        hooks,
	}
}

func successfulRunHooks(leasePath string, maintenancePath string) *runHooks {
	return &runHooks{
		lifecycleLeasePath:       leasePath,
		lifecycleMaintenancePath: maintenancePath,
		instanceID:               testDaemonInstanceID,
		reload: func(context.Context, reconcile.Options) (*reconcile.Result, error) {
			return &reconcile.Result{State: &control.State{}}, nil
		},
		stop: func(context.Context, Options, string) (*reconcile.Result, error) {
			return &reconcile.Result{State: &control.State{}, Action: "stop"}, nil
		},
	}
}

func waitForDaemonState(t *testing.T, runDir string, want string) *Status {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		status, err := ReadStatus(runDir)
		if err == nil && status.State == want {
			return status
		}
		time.Sleep(10 * time.Millisecond)
	}
	status, err := ReadStatus(runDir)
	t.Fatalf("daemon state did not become %q: status=%#v err=%v", want, status, err)
	return nil
}

func waitForDaemonReason(t *testing.T, runDir string, want string) *Status {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		status, err := ReadStatus(runDir)
		if err == nil && status.LastReason == want {
			return status
		}
		time.Sleep(10 * time.Millisecond)
	}
	status, err := ReadStatus(runDir)
	t.Fatalf("daemon reason did not become %q: status=%#v err=%v", want, status, err)
	return nil
}

func waitForPath(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("path did not appear: %s", path)
}

func waitForAck(t *testing.T, runDir string, id string) *requestAck {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		ack, err := readRequestAck(runDir, id)
		if err == nil {
			return ack
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("read ack %s: %v", id, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("request %s was not acknowledged", id)
	return nil
}
