package lockfile

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultLifecycleMaintenancePathIsOutsideRuntimeDirectory(t *testing.T) {
	if got := LifecycleMaintenancePath(DefaultLifecycleLeasePath); got !=
		DefaultLifecycleMaintenancePath {
		t.Fatalf("default maintenance path = %q, want %q", got, DefaultLifecycleMaintenancePath)
	}
	if filepath.Dir(DefaultLifecycleMaintenancePath) ==
		filepath.Dir(DefaultLifecycleLeasePath) {
		t.Fatalf(
			"default maintenance gate %s must be outside runtime directory %s",
			DefaultLifecycleMaintenancePath,
			filepath.Dir(DefaultLifecycleLeasePath),
		)
	}
}

func TestLifecycleMaintenanceProvidesConcurrentLeaseHandoff(t *testing.T) {
	leasePath := filepath.Join(t.TempDir(), "run", "daemon.lease")
	running, err := AcquireLifecycleAt(
		leasePath,
		LifecycleOwner{PID: os.Getpid(), Action: "daemon"},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer running.Close()

	maintenance, err := BeginLifecycleMaintenanceAt(
		leasePath,
		LifecycleOwner{PID: os.Getpid(), Action: "uninstall-maintenance"},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer maintenance.Close()
	gatePath := LifecycleMaintenancePath(leasePath)
	if filepath.Dir(gatePath) == filepath.Dir(leasePath) {
		t.Fatalf(
			"maintenance gate %s must be outside lifecycle directory %s",
			gatePath,
			filepath.Dir(leasePath),
		)
	}
	if _, err := AcquireLifecycleAt(
		leasePath,
		LifecycleOwner{PID: os.Getpid(), Action: "racing-daemon"},
	); !errors.Is(err, ErrLifecycleMaintenanceHeld) {
		t.Fatalf("racing daemon was not blocked by maintenance gate: %v", err)
	}
	if _, err := maintenance.TryAcquireLifecycle(
		LifecycleOwner{PID: os.Getpid(), Action: "uninstall"},
	); !errors.Is(err, ErrLifecycleLeaseHeld) {
		t.Fatalf("maintenance bypassed the running daemon lease: %v", err)
	}

	handoffCtx, cancelHandoff := context.WithTimeout(t.Context(), time.Second)
	defer cancelHandoff()
	handoff := make(chan struct {
		lease *LifecycleLease
		err   error
	}, 1)
	go func() {
		lease, waitErr := maintenance.WaitAcquireLifecycle(
			handoffCtx,
			LifecycleOwner{PID: os.Getpid(), Action: "uninstall"},
		)
		handoff <- struct {
			lease *LifecycleLease
			err   error
		}{lease: lease, err: waitErr}
	}()
	select {
	case result := <-handoff:
		if result.lease != nil {
			_ = result.lease.Close()
		}
		t.Fatalf("handoff completed before daemon released its lease: %v", result.err)
	case <-time.After(75 * time.Millisecond):
	}

	if err := running.Close(); err != nil {
		t.Fatal(err)
	}
	var uninstallLease *LifecycleLease
	select {
	case result := <-handoff:
		if result.err != nil {
			t.Fatal(result.err)
		}
		uninstallLease = result.lease
	case <-time.After(time.Second):
		t.Fatal("maintenance did not acquire the released lifecycle lease")
	}
	if _, err := AcquireLifecycleAt(
		leasePath,
		LifecycleOwner{PID: os.Getpid(), Action: "late-daemon"},
	); !errors.Is(err, ErrLifecycleMaintenanceHeld) {
		t.Fatalf("maintenance gate did not preserve handoff exclusivity: %v", err)
	}
	if err := uninstallLease.Close(); err != nil {
		t.Fatal(err)
	}
	if err := maintenance.Close(); err != nil {
		t.Fatal(err)
	}
	gateInfo, err := os.Lstat(gatePath)
	if err != nil {
		t.Fatalf("permanent maintenance gate disappeared: %v", err)
	}
	if !gateInfo.Mode().IsRegular() {
		t.Fatalf("permanent maintenance gate mode = %s", gateInfo.Mode())
	}
	reacquired, err := AcquireLifecycleAt(
		leasePath,
		LifecycleOwner{PID: os.Getpid(), Action: "post-maintenance-daemon"},
	)
	if err != nil {
		t.Fatalf("lifecycle remained blocked after maintenance: %v", err)
	}
	if err := reacquired.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLifecycleMaintenanceRejectsSymbolicLinkGate(t *testing.T) {
	root := t.TempDir()
	leasePath := filepath.Join(root, "run", "daemon.lease")
	gatePath := LifecycleMaintenancePath(leasePath)
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, gatePath); err != nil {
		t.Fatal(err)
	}
	_, err := BeginLifecycleMaintenanceAt(
		leasePath,
		LifecycleOwner{PID: os.Getpid(), Action: "maintenance"},
	)
	if err == nil || !strings.Contains(err.Error(), "symbolic-link") {
		t.Fatalf("symbolic-link maintenance gate error = %v", err)
	}
}

func TestLifecycleMaintenanceRejectsHardLinkedGate(t *testing.T) {
	root := t.TempDir()
	leasePath := filepath.Join(root, "run", "daemon.lease")
	gatePath := LifecycleMaintenancePath(leasePath)
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(target, gatePath); err != nil {
		t.Fatal(err)
	}
	_, err := BeginLifecycleMaintenanceAt(
		leasePath,
		LifecycleOwner{PID: os.Getpid(), Action: "maintenance"},
	)
	if err == nil || !strings.Contains(err.Error(), "links") {
		t.Fatalf("hard-linked maintenance gate error = %v", err)
	}
}

func TestLifecycleMaintenanceDetectsGateUnlinkAndRecreate(t *testing.T) {
	leasePath := filepath.Join(t.TempDir(), "run", "daemon.lease")
	maintenance, err := BeginLifecycleMaintenanceAt(
		leasePath,
		LifecycleOwner{PID: os.Getpid(), Action: "maintenance"},
	)
	if err != nil {
		t.Fatal(err)
	}
	gatePath := LifecycleMaintenancePath(leasePath)
	if err := os.Rename(gatePath, gatePath+".detached"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gatePath, []byte("replacement\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := maintenance.TryAcquireLifecycle(
		LifecycleOwner{PID: os.Getpid(), Action: "uninstall"},
	); err == nil || !strings.Contains(err.Error(), "pathname identity changed") {
		t.Fatalf("recreated maintenance gate error = %v", err)
	}
	if err := maintenance.Close(); err == nil ||
		!strings.Contains(err.Error(), "pathname identity changed") {
		t.Fatalf("close after recreated maintenance gate error = %v", err)
	}
}

func TestLifecycleMaintenanceDetectsAddedHardLink(t *testing.T) {
	leasePath := filepath.Join(t.TempDir(), "run", "daemon.lease")
	maintenance, err := BeginLifecycleMaintenanceAt(
		leasePath,
		LifecycleOwner{PID: os.Getpid(), Action: "maintenance"},
	)
	if err != nil {
		t.Fatal(err)
	}
	gatePath := LifecycleMaintenancePath(leasePath)
	if err := os.Link(gatePath, gatePath+".alias"); err != nil {
		t.Fatal(err)
	}
	if _, err := maintenance.TryAcquireLifecycle(
		LifecycleOwner{PID: os.Getpid(), Action: "uninstall"},
	); err == nil || !strings.Contains(err.Error(), "links") {
		t.Fatalf("added maintenance hard link error = %v", err)
	}
	if err := maintenance.Close(); err == nil ||
		!strings.Contains(err.Error(), "links") {
		t.Fatalf("close after added maintenance hard link error = %v", err)
	}
}

func TestLifecycleLeaseDetectsAtomicNameSwap(t *testing.T) {
	leasePath := filepath.Join(t.TempDir(), "run", "daemon.lease")
	lease, err := AcquireLifecycleAt(
		leasePath,
		LifecycleOwner{PID: os.Getpid(), Action: "daemon"},
	)
	if err != nil {
		t.Fatal(err)
	}
	replacement := leasePath + ".replacement"
	if err := os.WriteFile(replacement, []byte("replacement\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, leasePath); err != nil {
		t.Fatal(err)
	}
	if lease.HeldAt(leasePath) {
		t.Fatal("name-swapped lifecycle lease still reports ownership")
	}
	if retained, err := lease.Retain(); err == nil {
		_ = retained.Close()
		t.Fatal("name-swapped lifecycle lease was retained")
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLifecycleMaintenanceDetectsParentReplacement(t *testing.T) {
	root := t.TempDir()
	anchor := filepath.Join(root, "anchor")
	if err := os.Mkdir(anchor, 0o700); err != nil {
		t.Fatal(err)
	}
	leasePath := filepath.Join(anchor, "run", "daemon.lease")
	maintenance, err := BeginLifecycleMaintenanceAt(
		leasePath,
		LifecycleOwner{PID: os.Getpid(), Action: "maintenance"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(anchor, anchor+".detached"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(anchor, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := maintenance.TryAcquireLifecycle(
		LifecycleOwner{PID: os.Getpid(), Action: "uninstall"},
	); err == nil || !strings.Contains(err.Error(), "parent pathname identity changed") {
		t.Fatalf("replaced maintenance parent error = %v", err)
	}
	if err := maintenance.Close(); err == nil ||
		!strings.Contains(err.Error(), "parent pathname identity changed") {
		t.Fatalf("close after replaced maintenance parent error = %v", err)
	}
}

func TestLifecycleMaintenanceDetectsModeChange(t *testing.T) {
	leasePath := filepath.Join(t.TempDir(), "run", "daemon.lease")
	maintenance, err := BeginLifecycleMaintenanceAt(
		leasePath,
		LifecycleOwner{PID: os.Getpid(), Action: "maintenance"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(LifecycleMaintenancePath(leasePath), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := maintenance.TryAcquireLifecycle(
		LifecycleOwner{PID: os.Getpid(), Action: "uninstall"},
	); err == nil || !strings.Contains(err.Error(), "want 0600") {
		t.Fatalf("changed maintenance gate mode error = %v", err)
	}
	if err := maintenance.Close(); err == nil ||
		!strings.Contains(err.Error(), "want 0600") {
		t.Fatalf("close after changed maintenance mode error = %v", err)
	}
}

func TestLifecycleMaintenanceCancellationDoesNotLeakDescriptors(t *testing.T) {
	leasePath := filepath.Join(t.TempDir(), "run", "daemon.lease")
	ctx := WithLifecyclePathForTest(t.Context(), leasePath)
	maintenance, err := BeginLifecycleMaintenanceAt(
		leasePath,
		LifecycleOwner{PID: os.Getpid(), Action: "held-maintenance"},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer maintenance.Close()

	before := openDescriptorCount(t)
	for range 20 {
		waitCtx, cancel := context.WithTimeout(ctx, 5*time.Millisecond)
		_, err := BeginLifecycleMaintenance(
			waitCtx,
			LifecycleOwner{PID: os.Getpid(), Action: "contender"},
		)
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) ||
			!errors.Is(err, ErrLifecycleMaintenanceHeld) {
			t.Fatalf("canceled maintenance wait error = %v", err)
		}
	}
	after := openDescriptorCount(t)
	if after != before {
		t.Fatalf("maintenance cancellation leaked descriptors: before=%d after=%d", before, after)
	}
}

func TestLifecycleWaitCancellationDoesNotLeakDescriptors(t *testing.T) {
	leasePath := filepath.Join(t.TempDir(), "run", "daemon.lease")
	running, err := AcquireLifecycleAt(
		leasePath,
		LifecycleOwner{PID: os.Getpid(), Action: "daemon"},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer running.Close()
	maintenance, err := BeginLifecycleMaintenanceAt(
		leasePath,
		LifecycleOwner{PID: os.Getpid(), Action: "maintenance"},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer maintenance.Close()

	before := openDescriptorCount(t)
	for range 20 {
		waitCtx, cancel := context.WithTimeout(t.Context(), 5*time.Millisecond)
		_, err := maintenance.WaitAcquireLifecycle(
			waitCtx,
			LifecycleOwner{PID: os.Getpid(), Action: "uninstall"},
		)
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) ||
			!errors.Is(err, ErrLifecycleLeaseHeld) {
			t.Fatalf("canceled lifecycle wait error = %v", err)
		}
	}
	after := openDescriptorCount(t)
	if after != before {
		t.Fatalf("lifecycle cancellation leaked descriptors: before=%d after=%d", before, after)
	}
}

func TestIsolatedLifecycleValidationRunsAfterMaintenanceHandoff(t *testing.T) {
	leasePath := filepath.Join(t.TempDir(), "run", "lifecycle.lease")
	var held *LifecycleLease
	order := make([]string, 0, 2)
	ctx := WithIsolatedNetNSTestLifecycleValidation(
		t.Context(),
		leasePath,
		func() error {
			order = append(order, "validate")
			if held == nil || !held.HeldAt(leasePath) {
				return errors.New("isolated validation ran before lifecycle acquisition")
			}
			contender, err := AcquireLifecycleAt(
				leasePath,
				LifecycleOwner{PID: os.Getpid(), Action: "contender"},
			)
			if err == nil {
				_ = contender.Close()
				return errors.New("isolated validation ran without maintenance held")
			}
			if !errors.Is(err, ErrLifecycleMaintenanceHeld) {
				return fmt.Errorf("probe held maintenance gate: %w", err)
			}
			return nil
		},
	)
	maintenance, err := BeginLifecycleMaintenanceAt(
		leasePath,
		LifecycleOwner{PID: os.Getpid(), Action: "maintenance"},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer maintenance.Close()
	held, err = maintenance.WaitAcquireLifecycle(
		ctx,
		LifecycleOwner{PID: os.Getpid(), Action: "uninstall"},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	err = WithLifecycle(
		ctx,
		held,
		LifecycleOwner{PID: os.Getpid(), Action: "uninstall"},
		func(*LifecycleLease) error {
			order = append(order, "callback")
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(order, ","); got != "validate,callback" {
		t.Fatalf("isolated lifecycle order = %q", got)
	}
}

func openDescriptorCount(t *testing.T) int {
	t.Helper()
	for _, path := range []string{"/proc/self/fd", "/dev/fd"} {
		entries, err := os.ReadDir(path)
		if err == nil {
			return len(entries)
		}
	}
	t.Skip("this platform does not expose a process descriptor directory")
	return 0
}
