package lockfile

import (
	"context"
	"errors"
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
