package lockfile

import (
	"context"
	"errors"
	"fmt"
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
	maintenancePath := filepath.Join(root, "maintenance.gate")
	lease, err := AcquireLifecycleAt(
		leasePath,
		maintenancePath,
		LifecycleOwner{PID: os.Getpid(), Action: "daemon"},
	)
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
	maintenancePath := filepath.Join(root, "maintenance.gate")
	if err := os.Symlink(target, leasePath); err != nil {
		t.Fatal(err)
	}
	_, err := AcquireLifecycleAt(
		leasePath,
		maintenancePath,
		LifecycleOwner{PID: os.Getpid()},
	)
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
	maintenancePath := filepath.Join(root, "maintenance.gate")
	if err := os.Link(target, leasePath); err != nil {
		t.Fatal(err)
	}
	_, err := AcquireLifecycleAt(
		leasePath,
		maintenancePath,
		LifecycleOwner{PID: os.Getpid()},
	)
	if err == nil || !strings.Contains(err.Error(), "links") {
		t.Fatalf("hard-linked lifecycle error = %v", err)
	}
}

func TestAcquireLifecycleRejectsNonRegularFile(t *testing.T) {
	root := t.TempDir()
	leasePath := filepath.Join(root, "daemon.lease")
	maintenancePath := filepath.Join(root, "maintenance.gate")
	if err := syscall.Mkfifo(leasePath, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := AcquireLifecycleAt(
		leasePath,
		maintenancePath,
		LifecycleOwner{PID: os.Getpid()},
	)
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("non-regular lifecycle error = %v", err)
	}
}

func TestRetainedLifecycleLeasePreventsReacquire(t *testing.T) {
	root := t.TempDir()
	leasePath := filepath.Join(root, "daemon.lease")
	maintenancePath := filepath.Join(root, "maintenance.gate")
	lease, err := AcquireLifecycleAt(
		leasePath,
		maintenancePath,
		LifecycleOwner{PID: os.Getpid(), Action: "daemon"},
	)
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
	if _, err := AcquireLifecycleAt(
		leasePath,
		maintenancePath,
		LifecycleOwner{PID: os.Getpid(), Action: "second"},
	); !errors.Is(err, ErrLifecycleLeaseHeld) {
		t.Fatalf("retained lease did not block reacquire: %v", err)
	}
	if err := retained.Close(); err != nil {
		t.Fatal(err)
	}
	reacquired, err := AcquireLifecycleAt(
		leasePath,
		maintenancePath,
		LifecycleOwner{PID: os.Getpid(), Action: "second"},
	)
	if err != nil {
		t.Fatalf("lease was not released after all descriptors closed: %v", err)
	}
	if err := reacquired.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestIsolatedLifecyclePathIsContextLocal(t *testing.T) {
	root := t.TempDir()
	isolatedPath := filepath.Join(root, "lifecycle.lease")
	maintenancePath := filepath.Join(root, "maintenance.gate")
	isolatedContext := WithIsolatedNetNSTestLifecyclePaths(
		t.Context(),
		isolatedPath,
		maintenancePath,
	)
	if got := LifecycleLeasePath(isolatedContext); got != isolatedPath {
		t.Fatalf("isolated lifecycle path = %q, want %q", got, isolatedPath)
	}
	if got := LifecycleLeasePath(t.Context()); got != DefaultLifecycleLeasePath {
		t.Fatalf("default lifecycle path changed to %q", got)
	}
	if got := LifecycleMaintenancePath(isolatedContext); got != maintenancePath {
		t.Fatalf("isolated maintenance path = %q, want %q", got, maintenancePath)
	}
	if got := LifecycleMaintenancePath(t.Context()); got != DefaultLifecycleMaintenancePath {
		t.Fatalf("default maintenance path changed to %q", got)
	}
}

func TestIsolatedLifecycleValidationRunsAfterLeaseAcquisition(t *testing.T) {
	root := t.TempDir()
	leasePath := filepath.Join(root, "lifecycle.lease")
	maintenancePath := filepath.Join(root, "maintenance.gate")
	validationCalls := 0
	ctx := WithIsolatedNetNSTestLifecycleValidation(
		t.Context(),
		leasePath,
		maintenancePath,
		func() error {
			validationCalls++
			contender, err := AcquireLifecycleAt(
				leasePath,
				maintenancePath,
				LifecycleOwner{PID: os.Getpid(), Action: "contender"},
			)
			if err == nil {
				_ = contender.Close()
				return errors.New("lifecycle validator ran without the lease held")
			}
			if !errors.Is(err, ErrLifecycleLeaseHeld) {
				return fmt.Errorf("probe held lifecycle lease: %w", err)
			}
			return nil
		},
	)
	callbackCalls := 0
	err := WithLifecycle(
		ctx,
		nil,
		LifecycleOwner{PID: os.Getpid(), Action: "mutation"},
		func(*LifecycleLease) error {
			callbackCalls++
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if validationCalls != 1 || callbackCalls != 1 {
		t.Fatalf(
			"validation calls=%d callback calls=%d, want 1 each",
			validationCalls,
			callbackCalls,
		)
	}
}

func TestIsolatedLifecycleValidationRejectsStaleContract(t *testing.T) {
	root := t.TempDir()
	leasePath := filepath.Join(root, "lifecycle.lease")
	maintenancePath := filepath.Join(root, "maintenance.gate")
	contractMarker := filepath.Join(root, "contract.marker")
	if err := os.WriteFile(contractMarker, []byte("owned\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := WithIsolatedNetNSTestLifecycleValidation(
		t.Context(),
		leasePath,
		maintenancePath,
		func() error {
			data, err := os.ReadFile(contractMarker)
			if err != nil {
				return err
			}
			if string(data) != "owned\n" {
				return errors.New("contract marker changed")
			}
			return nil
		},
	)

	// Model a process paused after its initial validation while teardown makes
	// the contract unusable. The mutation must revalidate after acquiring the
	// lease and may not execute with the stale result.
	if err := os.Rename(contractMarker, contractMarker+".unavailable"); err != nil {
		t.Fatal(err)
	}
	callbackCalled := false
	err := WithLifecycle(
		ctx,
		nil,
		LifecycleOwner{PID: os.Getpid(), Action: "stale-mutation"},
		func(*LifecycleLease) error {
			callbackCalled = true
			return nil
		},
	)
	if err == nil || !strings.Contains(err.Error(), "revalidate lifecycle contract") {
		t.Fatalf("stale contract error = %v", err)
	}
	if callbackCalled {
		t.Fatal("stale mutation callback unexpectedly ran")
	}
}
