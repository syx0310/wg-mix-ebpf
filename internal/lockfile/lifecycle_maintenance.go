package lockfile

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	DefaultLifecycleMaintenancePath = "/run/.wg-mix-ebpf-daemon.lease.maintenance"

	lifecycleMaintenanceRetryInterval = 25 * time.Millisecond
	lifecycleMaintenanceWaitLimit     = 30 * time.Second
)

var ErrLifecycleMaintenanceHeld = errors.New(
	"wg-mix-ebpf lifecycle maintenance gate is already held",
)

// LifecycleMaintenance holds the outer lifecycle gate across the handoff from
// stopping a daemon to acquiring its lifecycle lease. The gate always precedes
// the lifecycle lease in the lock order.
type LifecycleMaintenance struct {
	mu            sync.Mutex
	lifecyclePath string
	path          string
	lock          *anchoredLifecycleLock
}

// LifecycleMaintenancePath returns the permanent gate path for a lifecycle
// lease. The gate is a sibling of the lifecycle directory, so removing that
// directory cannot remove or replace the held gate.
func LifecycleMaintenancePath(lifecyclePath string) string {
	cleanPath := filepath.Clean(lifecyclePath)
	parent := filepath.Dir(cleanPath)
	if cleanPath == filepath.Clean(DefaultLifecycleLeasePath) {
		return DefaultLifecycleMaintenancePath
	}
	return filepath.Join(
		filepath.Dir(parent),
		"."+filepath.Base(parent)+"-"+filepath.Base(cleanPath)+".maintenance",
	)
}

// BeginLifecycleMaintenance waits a bounded amount of time for the outer gate.
// The returned gate remains held until Close; callers may stop the daemon and
// then use WaitAcquireLifecycle without opening a race for a new daemon.
func BeginLifecycleMaintenance(
	ctx context.Context,
	owner LifecycleOwner,
) (*LifecycleMaintenance, error) {
	waitCtx, cancel := boundedLifecycleMaintenanceContext(ctx)
	defer cancel()
	if err := waitCtx.Err(); err != nil {
		return nil, err
	}
	lifecyclePath := LifecycleLeasePath(ctx)
	for {
		if err := waitCtx.Err(); err != nil {
			return nil, err
		}
		maintenance, err := tryBeginLifecycleMaintenanceAt(lifecyclePath, owner)
		if err == nil {
			if waitErr := waitCtx.Err(); waitErr != nil {
				return nil, errors.Join(waitErr, maintenance.Close())
			}
			return maintenance, nil
		}
		if !errors.Is(err, ErrLifecycleMaintenanceHeld) {
			return nil, err
		}
		if waitErr := waitForLifecycleMaintenanceRetry(waitCtx); waitErr != nil {
			return nil, errors.Join(err, waitErr)
		}
	}
}

// BeginLifecycleMaintenanceAt attempts the outer gate once. Context-bearing
// production callers should use BeginLifecycleMaintenance for bounded waiting.
func BeginLifecycleMaintenanceAt(
	lifecyclePath string,
	owner LifecycleOwner,
) (*LifecycleMaintenance, error) {
	return tryBeginLifecycleMaintenanceAt(lifecyclePath, owner)
}

func tryBeginLifecycleMaintenanceAt(
	lifecyclePath string,
	owner LifecycleOwner,
) (*LifecycleMaintenance, error) {
	if lifecyclePath == "" {
		return nil, errors.New("global lifecycle lease path is empty")
	}
	cleanPath := filepath.Clean(lifecyclePath)
	if cleanPath != lifecyclePath || !filepath.IsAbs(cleanPath) {
		return nil, fmt.Errorf(
			"global lifecycle lease path must be a clean absolute path: %q",
			lifecyclePath,
		)
	}
	parent := filepath.Dir(cleanPath)
	if parent == string(os.PathSeparator) {
		return nil, fmt.Errorf(
			"global lifecycle lease parent may not be the filesystem root: %s",
			cleanPath,
		)
	}
	maintenancePath := LifecycleMaintenancePath(cleanPath)
	lock, err := acquireAnchoredLifecycleLock(
		maintenancePath,
		owner,
		ErrLifecycleMaintenanceHeld,
		"lifecycle maintenance gate",
	)
	if err != nil {
		return nil, err
	}
	return &LifecycleMaintenance{
		lifecyclePath: cleanPath,
		path:          maintenancePath,
		lock:          lock,
	}, nil
}

// TryAcquireLifecycle acquires the inner lifecycle lease while retaining the
// maintenance gate. It never bypasses an existing daemon lease.
func (maintenance *LifecycleMaintenance) TryAcquireLifecycle(
	owner LifecycleOwner,
) (*LifecycleLease, error) {
	if maintenance == nil {
		return nil, errors.New("cannot acquire lifecycle through nil maintenance gate")
	}
	maintenance.mu.Lock()
	defer maintenance.mu.Unlock()
	if maintenance.lock == nil {
		return nil, errors.New("cannot acquire lifecycle through closed maintenance gate")
	}
	if err := maintenance.validateLocked(); err != nil {
		return nil, err
	}
	lease, err := acquireLifecycleWithoutMaintenance(maintenance.lifecyclePath, owner)
	if err != nil {
		return nil, err
	}
	if err := maintenance.validateLocked(); err != nil {
		return nil, errors.Join(err, lease.Close())
	}
	if !lease.HeldAt(maintenance.lifecyclePath) {
		return nil, errors.Join(
			fmt.Errorf(
				"acquired lifecycle lease no longer owns %s",
				maintenance.lifecyclePath,
			),
			lease.Close(),
		)
	}
	return lease, nil
}

// WaitAcquireLifecycle waits for an existing daemon lease while continuously
// retaining the maintenance gate. Waiting honors the caller's context and is
// capped even when the caller supplies an unbounded context.
func (maintenance *LifecycleMaintenance) WaitAcquireLifecycle(
	ctx context.Context,
	owner LifecycleOwner,
) (*LifecycleLease, error) {
	waitCtx, cancel := boundedLifecycleMaintenanceContext(ctx)
	defer cancel()
	if err := waitCtx.Err(); err != nil {
		return nil, err
	}
	for {
		if err := waitCtx.Err(); err != nil {
			return nil, err
		}
		lease, err := maintenance.TryAcquireLifecycle(owner)
		if err == nil {
			if waitErr := waitCtx.Err(); waitErr != nil {
				return nil, errors.Join(waitErr, lease.Close())
			}
			return lease, nil
		}
		if !errors.Is(err, ErrLifecycleLeaseHeld) {
			return nil, err
		}
		if waitErr := waitForLifecycleMaintenanceRetry(waitCtx); waitErr != nil {
			return nil, errors.Join(err, waitErr)
		}
	}
}

func (maintenance *LifecycleMaintenance) validateLocked() error {
	if maintenance.lock == nil {
		return errors.New("lifecycle maintenance gate is closed")
	}
	if maintenance.path != LifecycleMaintenancePath(maintenance.lifecyclePath) ||
		maintenance.lock.path != maintenance.path {
		return fmt.Errorf(
			"lifecycle maintenance gate path changed for %s",
			maintenance.lifecyclePath,
		)
	}
	if err := maintenance.lock.validate(); err != nil {
		return fmt.Errorf(
			"validate lifecycle maintenance gate %s: %w",
			maintenance.path,
			err,
		)
	}
	return nil
}

func (maintenance *LifecycleMaintenance) Close() error {
	if maintenance == nil {
		return nil
	}
	maintenance.mu.Lock()
	defer maintenance.mu.Unlock()
	if maintenance.lock == nil {
		return nil
	}
	validateErr := maintenance.validateLocked()
	closeErr := maintenance.lock.close()
	maintenance.lock = nil
	if err := errors.Join(validateErr, closeErr); err != nil {
		return fmt.Errorf(
			"close lifecycle maintenance gate %s: %w",
			maintenance.path,
			err,
		)
	}
	return nil
}

func boundedLifecycleMaintenanceContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(ctx, lifecycleMaintenanceWaitLimit)
}

func waitForLifecycleMaintenanceRetry(ctx context.Context) error {
	timer := time.NewTimer(lifecycleMaintenanceRetryInterval)
	defer func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
