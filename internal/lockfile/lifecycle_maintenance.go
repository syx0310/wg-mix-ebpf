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
	maintenancePath := LifecycleMaintenancePath(ctx)
	for {
		if err := waitCtx.Err(); err != nil {
			return nil, err
		}
		maintenance, err := tryBeginLifecycleMaintenanceAt(
			lifecyclePath,
			maintenancePath,
			owner,
		)
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
	maintenancePath string,
	owner LifecycleOwner,
) (*LifecycleMaintenance, error) {
	return tryBeginLifecycleMaintenanceAt(lifecyclePath, maintenancePath, owner)
}

func tryBeginLifecycleMaintenanceAt(
	lifecyclePath string,
	maintenancePath string,
	owner LifecycleOwner,
) (*LifecycleMaintenance, error) {
	cleanPath, cleanMaintenancePath, err := validateLifecyclePathPair(
		lifecyclePath,
		maintenancePath,
	)
	if err != nil {
		return nil, err
	}
	lock, err := acquireAnchoredLifecycleLock(
		cleanMaintenancePath,
		owner,
		ErrLifecycleMaintenanceHeld,
		"lifecycle maintenance gate",
	)
	if err != nil {
		return nil, err
	}
	return &LifecycleMaintenance{
		lifecyclePath: cleanPath,
		path:          cleanMaintenancePath,
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
	return maintenance.tryAcquireLifecycleLocked(owner)
}

func (maintenance *LifecycleMaintenance) tryAcquireLifecycleLocked(
	owner LifecycleOwner,
) (*LifecycleLease, error) {
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
	if maintenance == nil {
		return nil, errors.New("cannot acquire lifecycle through nil maintenance gate")
	}
	for {
		if err := waitCtx.Err(); err != nil {
			return nil, err
		}
		lease, err := maintenance.tryAcquireValidatedLifecycle(
			waitCtx,
			ctx,
			owner,
		)
		if err == nil {
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

func (maintenance *LifecycleMaintenance) tryAcquireValidatedLifecycle(
	waitCtx context.Context,
	validationCtx context.Context,
	owner LifecycleOwner,
) (*LifecycleLease, error) {
	maintenance.mu.Lock()
	defer maintenance.mu.Unlock()
	lease, err := maintenance.tryAcquireLifecycleLocked(owner)
	if err != nil {
		return nil, err
	}
	if waitErr := waitCtx.Err(); waitErr != nil {
		return nil, errors.Join(waitErr, lease.Close())
	}
	if validateErr := validateLifecycleContextAfterLock(validationCtx); validateErr != nil {
		return nil, errors.Join(validateErr, lease.Close())
	}
	if waitErr := waitCtx.Err(); waitErr != nil {
		return nil, errors.Join(waitErr, lease.Close())
	}
	return lease, nil
}

func (maintenance *LifecycleMaintenance) validateLocked() error {
	if maintenance.lock == nil {
		return errors.New("lifecycle maintenance gate is closed")
	}
	if _, _, err := validateLifecyclePathPair(
		maintenance.lifecyclePath,
		maintenance.path,
	); err != nil {
		return err
	}
	if maintenance.lock.path != maintenance.path {
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

func validateLifecyclePathPair(
	lifecyclePath string,
	maintenancePath string,
) (string, string, error) {
	cleanLifecyclePath, err := validateLifecycleLockPath(
		"global lifecycle lease",
		lifecyclePath,
	)
	if err != nil {
		return "", "", err
	}
	cleanMaintenancePath, err := validateLifecycleLockPath(
		"lifecycle maintenance gate",
		maintenancePath,
	)
	if err != nil {
		return "", "", err
	}
	if cleanLifecyclePath == cleanMaintenancePath {
		return "", "", errors.New(
			"global lifecycle lease and maintenance gate paths must differ",
		)
	}
	defaultLease := cleanLifecyclePath == DefaultLifecycleLeasePath
	defaultMaintenance := cleanMaintenancePath == DefaultLifecycleMaintenancePath
	if defaultLease != defaultMaintenance {
		return "", "", fmt.Errorf(
			"default lifecycle paths must use the fixed pair %s and %s",
			DefaultLifecycleLeasePath,
			DefaultLifecycleMaintenancePath,
		)
	}
	return cleanLifecyclePath, cleanMaintenancePath, nil
}

func validateLifecycleLockPath(description string, path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("%s path is empty", description)
	}
	cleanPath := filepath.Clean(path)
	if cleanPath != path || !filepath.IsAbs(cleanPath) {
		return "", fmt.Errorf(
			"%s path must be a clean absolute path: %q",
			description,
			path,
		)
	}
	if filepath.Dir(cleanPath) == string(os.PathSeparator) {
		return "", fmt.Errorf(
			"%s parent may not be the filesystem root: %s",
			description,
			cleanPath,
		)
	}
	return cleanPath, nil
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
