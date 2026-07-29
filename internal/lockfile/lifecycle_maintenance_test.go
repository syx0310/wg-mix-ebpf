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
	if got := LifecycleMaintenancePath(t.Context()); got != DefaultLifecycleMaintenancePath {
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

func TestDefaultLifecyclePathsRequireFixedPair(t *testing.T) {
	root := t.TempDir()
	customLease := filepath.Join(root, "daemon.lease")
	customGate := filepath.Join(root, "maintenance.gate")
	for _, test := range []struct {
		name  string
		lease string
		gate  string
	}{
		{
			name:  "default lease with custom gate",
			lease: DefaultLifecycleLeasePath,
			gate:  customGate,
		},
		{
			name:  "custom lease with default gate",
			lease: customLease,
			gate:  DefaultLifecycleMaintenancePath,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			maintenance, err := BeginLifecycleMaintenanceAt(
				test.lease,
				test.gate,
				LifecycleOwner{PID: os.Getpid(), Action: "maintenance"},
			)
			if maintenance != nil {
				_ = maintenance.Close()
				t.Fatal("mismatched default lifecycle pair unexpectedly acquired")
			}
			if err == nil || !strings.Contains(err.Error(), "fixed pair") {
				t.Fatalf("mismatched default lifecycle pair error = %v", err)
			}
		})
	}
}

func TestLifecycleMaintenanceProvidesConcurrentLeaseHandoff(t *testing.T) {
	leasePath, gatePath := newTestLifecyclePaths(t, "daemon.lease")
	running, err := AcquireLifecycleAt(
		leasePath,
		gatePath,
		LifecycleOwner{PID: os.Getpid(), Action: "daemon"},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer running.Close()

	maintenance, err := BeginLifecycleMaintenanceAt(
		leasePath,
		gatePath,
		LifecycleOwner{PID: os.Getpid(), Action: "uninstall-maintenance"},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer maintenance.Close()
	if filepath.Dir(gatePath) == filepath.Dir(leasePath) {
		t.Fatalf(
			"maintenance gate %s must be outside lifecycle directory %s",
			gatePath,
			filepath.Dir(leasePath),
		)
	}
	if _, err := AcquireLifecycleAt(
		leasePath,
		gatePath,
		LifecycleOwner{PID: os.Getpid(), Action: "racing-daemon"},
	); !errors.Is(err, ErrLifecycleMaintenanceHeld) ||
		!errors.Is(err, ErrLifecycleLeaseHeld) {
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
		gatePath,
		LifecycleOwner{PID: os.Getpid(), Action: "late-daemon"},
	); !errors.Is(err, ErrLifecycleMaintenanceHeld) ||
		!errors.Is(err, ErrLifecycleLeaseHeld) {
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
		gatePath,
		LifecycleOwner{PID: os.Getpid(), Action: "post-maintenance-daemon"},
	)
	if err != nil {
		t.Fatalf("lifecycle remained blocked after maintenance: %v", err)
	}
	if err := reacquired.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNormalAcquirePreservesLeaseHeldCompatibilityDuringMaintenance(t *testing.T) {
	leasePath, gatePath := newTestLifecyclePaths(t, "daemon.lease")
	maintenance, err := BeginLifecycleMaintenanceAt(
		leasePath,
		gatePath,
		LifecycleOwner{PID: os.Getpid(), Action: "maintenance"},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer maintenance.Close()

	const contenders = 32
	results := make(chan error, contenders)
	for range contenders {
		go func() {
			lease, acquireErr := AcquireLifecycleAt(
				leasePath,
				gatePath,
				LifecycleOwner{PID: os.Getpid(), Action: "daemon-contender"},
			)
			if lease != nil {
				_ = lease.Close()
			}
			results <- acquireErr
		}()
	}
	for range contenders {
		err := <-results
		if !errors.Is(err, ErrLifecycleLeaseHeld) ||
			!errors.Is(err, ErrLifecycleMaintenanceHeld) {
			t.Fatalf("normal maintenance contention error = %v", err)
		}
	}

	secondMaintenance, err := BeginLifecycleMaintenanceAt(
		leasePath,
		gatePath,
		LifecycleOwner{PID: os.Getpid(), Action: "second-maintenance"},
	)
	if secondMaintenance != nil {
		_ = secondMaintenance.Close()
		t.Fatal("second maintenance unexpectedly acquired the gate")
	}
	if !errors.Is(err, ErrLifecycleMaintenanceHeld) ||
		errors.Is(err, ErrLifecycleLeaseHeld) {
		t.Fatalf("explicit maintenance contention error = %v", err)
	}
}

func TestExplicitMaintenancePathsAvoidFormerBasenameCollision(t *testing.T) {
	root := t.TempDir()
	firstLease := filepath.Join(root, "a-b", "c")
	secondLease := filepath.Join(root, "a", "b-c")
	firstGate := filepath.Join(root, "gates", "first.gate")
	secondGate := filepath.Join(root, "gates", "second.gate")

	first, err := BeginLifecycleMaintenanceAt(
		firstLease,
		firstGate,
		LifecycleOwner{PID: os.Getpid(), Action: "first-maintenance"},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := AcquireLifecycleAt(
		secondLease,
		secondGate,
		LifecycleOwner{PID: os.Getpid(), Action: "second-daemon"},
	)
	if err != nil {
		t.Fatalf("explicit non-colliding gate was blocked: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLifecycleMaintenanceRejectsSymbolicLinkGate(t *testing.T) {
	root := t.TempDir()
	leasePath := filepath.Join(root, "run", "daemon.lease")
	gatePath := filepath.Join(root, "maintenance.gate")
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, gatePath); err != nil {
		t.Fatal(err)
	}
	_, err := BeginLifecycleMaintenanceAt(
		leasePath,
		gatePath,
		LifecycleOwner{PID: os.Getpid(), Action: "maintenance"},
	)
	if err == nil || !strings.Contains(err.Error(), "symbolic-link") {
		t.Fatalf("symbolic-link maintenance gate error = %v", err)
	}
}

func TestLifecycleMaintenanceRejectsHardLinkedGate(t *testing.T) {
	root := t.TempDir()
	leasePath := filepath.Join(root, "run", "daemon.lease")
	gatePath := filepath.Join(root, "maintenance.gate")
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(target, gatePath); err != nil {
		t.Fatal(err)
	}
	_, err := BeginLifecycleMaintenanceAt(
		leasePath,
		gatePath,
		LifecycleOwner{PID: os.Getpid(), Action: "maintenance"},
	)
	if err == nil || !strings.Contains(err.Error(), "links") {
		t.Fatalf("hard-linked maintenance gate error = %v", err)
	}
}

func TestLifecycleMaintenanceDetectsGateUnlinkAndRecreate(t *testing.T) {
	leasePath, gatePath := newTestLifecyclePaths(t, "daemon.lease")
	maintenance, err := BeginLifecycleMaintenanceAt(
		leasePath,
		gatePath,
		LifecycleOwner{PID: os.Getpid(), Action: "maintenance"},
	)
	if err != nil {
		t.Fatal(err)
	}
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
	leasePath, gatePath := newTestLifecyclePaths(t, "daemon.lease")
	maintenance, err := BeginLifecycleMaintenanceAt(
		leasePath,
		gatePath,
		LifecycleOwner{PID: os.Getpid(), Action: "maintenance"},
	)
	if err != nil {
		t.Fatal(err)
	}
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
	leasePath, gatePath := newTestLifecyclePaths(t, "daemon.lease")
	lease, err := AcquireLifecycleAt(
		leasePath,
		gatePath,
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
	gatePath := filepath.Join(anchor, "maintenance.gate")
	maintenance, err := BeginLifecycleMaintenanceAt(
		leasePath,
		gatePath,
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
	leasePath, gatePath := newTestLifecyclePaths(t, "daemon.lease")
	maintenance, err := BeginLifecycleMaintenanceAt(
		leasePath,
		gatePath,
		LifecycleOwner{PID: os.Getpid(), Action: "maintenance"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(gatePath, 0o640); err != nil {
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
	leasePath, gatePath := newTestLifecyclePaths(t, "daemon.lease")
	ctx := WithLifecyclePathsForTest(t.Context(), leasePath, gatePath)
	maintenance, err := BeginLifecycleMaintenanceAt(
		leasePath,
		gatePath,
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
		if errors.Is(err, ErrLifecycleLeaseHeld) {
			t.Fatalf("explicit maintenance wait reported lifecycle lease held: %v", err)
		}
	}
	after := openDescriptorCount(t)
	if after != before {
		t.Fatalf("maintenance cancellation leaked descriptors: before=%d after=%d", before, after)
	}
}

func TestLifecycleWaitCancellationDoesNotLeakDescriptors(t *testing.T) {
	leasePath, gatePath := newTestLifecyclePaths(t, "daemon.lease")
	running, err := AcquireLifecycleAt(
		leasePath,
		gatePath,
		LifecycleOwner{PID: os.Getpid(), Action: "daemon"},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer running.Close()
	maintenance, err := BeginLifecycleMaintenanceAt(
		leasePath,
		gatePath,
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
	leasePath, gatePath := newTestLifecyclePaths(t, "lifecycle.lease")
	order := make([]string, 0, 3)
	ctx := WithIsolatedNetNSTestLifecycleValidation(
		t.Context(),
		leasePath,
		gatePath,
		func() error {
			order = append(order, "validate")
			contender, err := acquireLifecycleWithoutMaintenance(
				leasePath,
				LifecycleOwner{PID: os.Getpid(), Action: "inner-contender"},
			)
			if err == nil {
				_ = contender.Close()
				return errors.New("isolated validation ran before lifecycle acquisition")
			}
			if !errors.Is(err, ErrLifecycleLeaseHeld) {
				return fmt.Errorf("probe held lifecycle lease: %w", err)
			}
			contender, err = AcquireLifecycleAt(
				leasePath,
				gatePath,
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
		gatePath,
		LifecycleOwner{PID: os.Getpid(), Action: "maintenance"},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer maintenance.Close()
	held, err := maintenance.WaitAcquireLifecycle(
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
	if got := strings.Join(order, ","); got != "validate,validate,callback" {
		t.Fatalf("isolated lifecycle order = %q", got)
	}
}

func TestLifecycleWaitRejectsStaleContractBeforeReturningLease(t *testing.T) {
	root := t.TempDir()
	leasePath := filepath.Join(root, "run", "lifecycle.lease")
	gatePath := filepath.Join(root, "maintenance.gate")
	contractMarker := filepath.Join(root, "contract.marker")
	if err := os.WriteFile(contractMarker, []byte("owned\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := WithIsolatedNetNSTestLifecycleValidation(
		t.Context(),
		leasePath,
		gatePath,
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
	maintenance, err := BeginLifecycleMaintenanceAt(
		leasePath,
		gatePath,
		LifecycleOwner{PID: os.Getpid(), Action: "maintenance"},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer maintenance.Close()
	if err := os.Rename(contractMarker, contractMarker+".stale"); err != nil {
		t.Fatal(err)
	}

	before := openDescriptorCount(t)
	lease, err := maintenance.WaitAcquireLifecycle(
		ctx,
		LifecycleOwner{PID: os.Getpid(), Action: "uninstall"},
	)
	if lease != nil {
		_ = lease.Close()
		t.Fatal("stale lifecycle contract returned a lease")
	}
	if err == nil || !strings.Contains(err.Error(), "revalidate lifecycle contract") {
		t.Fatalf("stale maintenance wait error = %v", err)
	}
	after := openDescriptorCount(t)
	if after != before {
		t.Fatalf("stale maintenance wait leaked descriptors: before=%d after=%d", before, after)
	}
	probe, err := acquireLifecycleWithoutMaintenance(
		leasePath,
		LifecycleOwner{PID: os.Getpid(), Action: "post-stale-probe"},
	)
	if err != nil {
		t.Fatalf("stale maintenance wait retained lifecycle lease: %v", err)
	}
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}
}

func newTestLifecyclePaths(t *testing.T, leaseName string) (string, string) {
	t.Helper()
	root := t.TempDir()
	return filepath.Join(root, "run", leaseName), filepath.Join(root, "maintenance.gate")
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
