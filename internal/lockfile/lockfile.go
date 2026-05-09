package lockfile

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

const FileName = "lock"

func WithLock(ctx context.Context, runDir string, fn func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return fmt.Errorf("create lock dir %s: %w", runDir, err)
	}
	file, err := os.OpenFile(filepath.Join(runDir, FileName), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open lock file: %w", err)
	}
	defer file.Close()
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("acquire lock: %w", err)
	}
	defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	if err := ctx.Err(); err != nil {
		return err
	}
	return fn()
}
