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
	file *os.File
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
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return AcquireLifecycleAt(LifecycleLeasePath(ctx), owner)
}

func AcquireLifecycleAt(path string, owner LifecycleOwner) (*LifecycleLease, error) {
	if path == "" {
		return nil, errors.New("global lifecycle lease path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create global lifecycle lease directory: %w", err)
	}
	file, err := openRegularSingleLinkLock(path)
	if err != nil {
		return nil, fmt.Errorf("open global lifecycle lease %s: %w", path, err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("secure global lifecycle lease %s: %w", path, err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		detail := ""
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			data := make([]byte, 4096)
			if n, readErr := file.ReadAt(data, 0); readErr == nil || n > 0 {
				detail = strings.TrimSpace(string(data[:n]))
			}
			_ = file.Close()
			if detail != "" {
				return nil, fmt.Errorf("%w at %s; owner=%s", ErrLifecycleLeaseHeld, path, detail)
			}
			return nil, fmt.Errorf("%w at %s", ErrLifecycleLeaseHeld, path)
		}
		_ = file.Close()
		return nil, fmt.Errorf("acquire global lifecycle lease %s: %w", path, err)
	}

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
	if err != nil {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
		return nil, fmt.Errorf("record global lifecycle lease owner in %s: %w", path, err)
	}
	return &LifecycleLease{path: filepath.Clean(path), file: file}, nil
}

func WithLifecycle(
	ctx context.Context,
	held *LifecycleLease,
	owner LifecycleOwner,
	fn func(*LifecycleLease) error,
) (retErr error) {
	if err := ctx.Err(); err != nil {
		return err
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
	if l.file == nil || filepath.Clean(path) != l.path {
		return false
	}
	heldInfo, err := l.file.Stat()
	if err != nil {
		return false
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 {
		return false
	}
	return os.SameFile(heldInfo, pathInfo)
}

// Retain duplicates the lease file description. Closing the original lease
// does not release flock ownership until every retained lease is closed.
func (l *LifecycleLease) Retain() (*LifecycleLease, error) {
	if l == nil {
		return nil, errors.New("cannot retain nil lifecycle lease")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil, errors.New("cannot retain closed lifecycle lease")
	}
	fd, err := unix.FcntlInt(l.file.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("retain global lifecycle lease %s: %w", l.path, err)
	}
	return &LifecycleLease{
		path: l.path,
		file: os.NewFile(uintptr(fd), l.path),
	}, nil
}

func (l *LifecycleLease) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
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
