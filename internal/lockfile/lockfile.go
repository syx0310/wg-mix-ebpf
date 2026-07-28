package lockfile

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const FileName = "lock"

func WithLock(ctx context.Context, runDir string, fn func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return fmt.Errorf("create lock dir %s: %w", runDir, err)
	}
	lockPath := filepath.Join(runDir, FileName)
	file, err := openRegularSingleLinkLock(lockPath)
	if err != nil {
		return fmt.Errorf("open operation lock file %s: %w", lockPath, err)
	}
	defer file.Close()
	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("secure operation lock file %s: %w", lockPath, err)
	}
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			return fmt.Errorf("acquire lock: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
	defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	if err := ctx.Err(); err != nil {
		return err
	}
	return fn()
}
