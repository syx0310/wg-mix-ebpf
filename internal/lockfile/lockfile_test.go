package lockfile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestWithLockHonorsContextWhileContended(t *testing.T) {
	dir := t.TempDir()
	held := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- WithLock(context.Background(), dir, func() error {
			close(held)
			<-release
			return nil
		})
	}()
	select {
	case <-held:
	case <-time.After(time.Second):
		t.Fatal("first lock was not acquired")
	}

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := WithLock(ctx, dir, func() error {
		t.Fatal("contended callback must not run")
		return nil
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("lock cancellation took too long: %s", elapsed)
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first lock failed: %v", err)
	}
}

func TestWithLockRejectsSymbolicLink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, FileName)); err != nil {
		t.Fatal(err)
	}
	err := WithLock(t.Context(), dir, func() error {
		t.Fatal("symbolic-link operation lock callback must not run")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "symbolic-link") {
		t.Fatalf("symbolic-link lock error = %v", err)
	}
}

func TestWithLockRejectsLifecycleLeaseHardLink(t *testing.T) {
	root := t.TempDir()
	leasePath := filepath.Join(root, "daemon.lease")
	lease, err := AcquireLifecycleAt(leasePath, LifecycleOwner{PID: os.Getpid(), Action: "daemon"})
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()

	runDir := filepath.Join(root, "run")
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(leasePath, filepath.Join(runDir, FileName)); err != nil {
		t.Fatal(err)
	}
	err = WithLock(t.Context(), runDir, func() error {
		t.Fatal("hard-linked operation lock callback must not run")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "links") {
		t.Fatalf("hard-linked lock error = %v", err)
	}
}

func TestAcquireLifecycleRejectsSymbolicLink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	leasePath := filepath.Join(root, "daemon.lease")
	if err := os.Symlink(target, leasePath); err != nil {
		t.Fatal(err)
	}
	_, err := AcquireLifecycleAt(leasePath, LifecycleOwner{PID: os.Getpid()})
	if err == nil || !strings.Contains(err.Error(), "symbolic-link") {
		t.Fatalf("symbolic-link lifecycle error = %v", err)
	}
}

func TestAcquireLifecycleRejectsHardLink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	leasePath := filepath.Join(root, "daemon.lease")
	if err := os.Link(target, leasePath); err != nil {
		t.Fatal(err)
	}
	_, err := AcquireLifecycleAt(leasePath, LifecycleOwner{PID: os.Getpid()})
	if err == nil || !strings.Contains(err.Error(), "links") {
		t.Fatalf("hard-linked lifecycle error = %v", err)
	}
}

func TestAcquireLifecycleRejectsNonRegularFile(t *testing.T) {
	leasePath := filepath.Join(t.TempDir(), "daemon.lease")
	if err := syscall.Mkfifo(leasePath, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := AcquireLifecycleAt(leasePath, LifecycleOwner{PID: os.Getpid()})
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("non-regular lifecycle error = %v", err)
	}
}

func TestRetainedLifecycleLeasePreventsReacquire(t *testing.T) {
	leasePath := filepath.Join(t.TempDir(), "daemon.lease")
	lease, err := AcquireLifecycleAt(leasePath, LifecycleOwner{PID: os.Getpid(), Action: "daemon"})
	if err != nil {
		t.Fatal(err)
	}
	retained, err := lease.Retain()
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireLifecycleAt(leasePath, LifecycleOwner{PID: os.Getpid(), Action: "second"}); !errors.Is(err, ErrLifecycleLeaseHeld) {
		t.Fatalf("retained lease did not block reacquire: %v", err)
	}
	if err := retained.Close(); err != nil {
		t.Fatal(err)
	}
	reacquired, err := AcquireLifecycleAt(leasePath, LifecycleOwner{PID: os.Getpid(), Action: "second"})
	if err != nil {
		t.Fatalf("lease was not released after all descriptors closed: %v", err)
	}
	if err := reacquired.Close(); err != nil {
		t.Fatal(err)
	}
}
