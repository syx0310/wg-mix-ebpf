package lockfile

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

const DefaultLifecycleLeasePath = "/run/wg-mix-ebpf/daemon.lease"

var ErrLifecycleLeaseHeld = errors.New("wg-mix-ebpf global lifecycle lease is already held")

type LifecycleOwner struct {
	PID        int    `json:"pid"`
	Action     string `json:"action,omitempty"`
	ConfigPath string `json:"config_path,omitempty"`
	RunDir     string `json:"run_dir,omitempty"`
}

type LifecycleLease struct {
	mu   sync.Mutex
	path string
	lock *anchoredLifecycleLock
}

type lifecyclePathContextKey struct{}

type lifecycleContext struct {
	path              string
	validateAfterLock func() error
}

// WithLifecyclePathForTest redirects the global lifecycle lease for a test
// context. Production entrypoints never expose this through flags or
// environment variables.
func WithLifecyclePathForTest(ctx context.Context, path string) context.Context {
	if flag.Lookup("test.v") == nil {
		panic("WithLifecyclePathForTest is only available in Go test binaries")
	}
	return context.WithValue(ctx, lifecyclePathContextKey{}, lifecycleContext{path: path})
}

// WithIsolatedNetNSTestLifecyclePath redirects the lifecycle lease for the
// explicitly gated, non-initial-network-namespace smoke-test path. Callers
// must validate the complete run-owned layout before using this helper.
func WithIsolatedNetNSTestLifecyclePath(ctx context.Context, path string) context.Context {
	return context.WithValue(ctx, lifecyclePathContextKey{}, lifecycleContext{path: path})
}

// WithIsolatedNetNSTestLifecycleValidation redirects the lifecycle lease and
// revalidates the isolated test contract after the lease is held. This closes
// the gap between an initial path check and a delayed mutation.
func WithIsolatedNetNSTestLifecycleValidation(
	ctx context.Context,
	path string,
	validateAfterLock func() error,
) context.Context {
	return context.WithValue(ctx, lifecyclePathContextKey{}, lifecycleContext{
		path:              path,
		validateAfterLock: validateAfterLock,
	})
}

func LifecycleLeasePath(ctx context.Context) string {
	if ctx != nil {
		if lifecycle, ok := ctx.Value(lifecyclePathContextKey{}).(lifecycleContext); ok &&
			lifecycle.path != "" {
			return lifecycle.path
		}
	}
	return DefaultLifecycleLeasePath
}

func AcquireLifecycle(ctx context.Context, owner LifecycleOwner) (*LifecycleLease, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	return AcquireLifecycleAt(LifecycleLeasePath(ctx), owner)
}

func AcquireLifecycleAt(path string, owner LifecycleOwner) (*LifecycleLease, error) {
	maintenance, err := tryBeginLifecycleMaintenanceAt(path, owner)
	if err != nil {
		return nil, err
	}
	lease, acquireErr := maintenance.TryAcquireLifecycle(owner)
	closeErr := maintenance.Close()
	if acquireErr != nil {
		return nil, errors.Join(acquireErr, closeErr)
	}
	if closeErr != nil {
		return nil, errors.Join(closeErr, lease.Close())
	}
	return lease, nil
}

func acquireLifecycleWithoutMaintenance(path string, owner LifecycleOwner) (*LifecycleLease, error) {
	if path == "" {
		return nil, errors.New("global lifecycle lease path is empty")
	}
	cleanPath := filepath.Clean(path)
	if cleanPath != path || !filepath.IsAbs(cleanPath) {
		return nil, fmt.Errorf("global lifecycle lease path must be a clean absolute path: %q", path)
	}
	lock, err := acquireAnchoredLifecycleLock(
		cleanPath,
		owner,
		ErrLifecycleLeaseHeld,
		"global lifecycle lease",
	)
	if err != nil {
		return nil, err
	}
	return &LifecycleLease{path: cleanPath, lock: lock}, nil
}

func acquireAnchoredLifecycleLock(
	path string,
	owner LifecycleOwner,
	heldError error,
	description string,
) (*anchoredLifecycleLock, error) {
	lock, err := openAnchoredLifecycleLock(path)
	if err != nil {
		return nil, fmt.Errorf("open %s %s: %w", description, path, err)
	}
	if err := syscall.Flock(
		int(lock.file.Fd()),
		syscall.LOCK_EX|syscall.LOCK_NB,
	); err != nil {
		detail := ""
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			data := make([]byte, 4096)
			if n, readErr := lock.file.ReadAt(data, 0); readErr == nil || n > 0 {
				detail = strings.TrimSpace(string(data[:n]))
			}
			closeErr := lock.close()
			heldErr := fmt.Errorf("%w at %s", heldError, path)
			if detail != "" {
				heldErr = fmt.Errorf("%w; owner=%s", heldErr, detail)
			}
			return nil, errors.Join(heldErr, closeErr)
		}
		return nil, errors.Join(
			fmt.Errorf("acquire %s %s: %w", description, path, err),
			lock.close(),
		)
	}
	if err := lock.validate(); err != nil {
		return nil, releaseAnchoredLifecycleLock(
			lock,
			fmt.Errorf("validate acquired %s %s: %w", description, path, err),
		)
	}
	if err := recordLifecycleOwner(lock.file, owner); err != nil {
		return nil, releaseAnchoredLifecycleLock(
			lock,
			fmt.Errorf("record %s owner in %s: %w", description, path, err),
		)
	}
	if err := lock.validate(); err != nil {
		return nil, releaseAnchoredLifecycleLock(
			lock,
			fmt.Errorf("revalidate acquired %s %s: %w", description, path, err),
		)
	}
	return lock, nil
}

func releaseAnchoredLifecycleLock(lock *anchoredLifecycleLock, cause error) error {
	if lock == nil {
		return cause
	}
	unlockErr := syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN)
	closeErr := lock.close()
	return errors.Join(cause, unlockErr, closeErr)
}

func recordLifecycleOwner(file *os.File, owner LifecycleOwner) error {
	data, err := json.Marshal(owner)
	if err == nil {
		err = file.Truncate(0)
	}
	if err == nil {
		_, err = file.Seek(0, 0)
	}
	if err == nil {
		_, err = file.Write(append(data, '\n'))
	}
	if err == nil {
		err = file.Sync()
	}
	return err
}

func WithLifecycle(
	ctx context.Context,
	held *LifecycleLease,
	owner LifecycleOwner,
	fn func(*LifecycleLease) error,
) (retErr error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	path := LifecycleLeasePath(ctx)
	if held != nil {
		if !held.HeldAt(path) {
			return fmt.Errorf("provided lifecycle lease does not own %s", path)
		}
		if err := validateLifecycleContextAfterLock(ctx); err != nil {
			return err
		}
		return fn(held)
	}
	lease, err := AcquireLifecycleAt(path, owner)
	if err != nil {
		return err
	}
	defer func() {
		retErr = errors.Join(retErr, lease.Close())
	}()
	if err := validateLifecycleContextAfterLock(ctx); err != nil {
		return err
	}
	return fn(lease)
}

func validateLifecycleContextAfterLock(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	lifecycle, ok := ctx.Value(lifecyclePathContextKey{}).(lifecycleContext)
	if !ok || lifecycle.validateAfterLock == nil {
		return nil
	}
	if err := lifecycle.validateAfterLock(); err != nil {
		return fmt.Errorf("revalidate lifecycle contract after acquiring lease: %w", err)
	}
	return nil
}

func (l *LifecycleLease) HeldAt(path string) bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.lock == nil ||
		!filepath.IsAbs(path) ||
		filepath.Clean(path) != path ||
		path != l.path {
		return false
	}
	return l.lock.validate() == nil
}

// Retain duplicates the lease file description. Closing the original lease
// does not release flock ownership until every retained lease is closed.
func (l *LifecycleLease) Retain() (*LifecycleLease, error) {
	if l == nil {
		return nil, errors.New("cannot retain nil lifecycle lease")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.lock == nil {
		return nil, errors.New("cannot retain closed lifecycle lease")
	}
	duplicate, err := l.lock.duplicate()
	if err != nil {
		return nil, fmt.Errorf("retain global lifecycle lease %s: %w", l.path, err)
	}
	return &LifecycleLease{
		path: l.path,
		lock: duplicate,
	}, nil
}

func (l *LifecycleLease) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.lock == nil {
		return nil
	}
	err := l.lock.close()
	l.lock = nil
	if err != nil {
		return fmt.Errorf("close global lifecycle lease %s: %w", l.path, err)
	}
	return nil
}

func openRegularSingleLinkLock(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("refuse symbolic-link lock file: %w", err)
		}
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = file.Close()
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = file.Close()
		return nil, errors.New("lock path is not a regular file")
	}
	if stat.Nlink != 1 {
		_ = file.Close()
		return nil, fmt.Errorf("refuse lock file with %d links", stat.Nlink)
	}
	return file, nil
}
