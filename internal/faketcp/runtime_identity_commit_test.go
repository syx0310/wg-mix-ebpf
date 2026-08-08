package faketcp

import (
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
)

func copyEngineValue(t *testing.T, engine *Engine) *Engine {
	t.Helper()
	copyValue := reflect.New(reflect.TypeOf(engine).Elem())
	copyValue.Elem().Set(reflect.ValueOf(engine).Elem())
	return copyValue.Interface().(*Engine)
}

func TestEngineRuntimeIdentityCommitIsSingleUse(t *testing.T) {
	engine, _ := testEngine(t, nil)
	consumed := errors.New("consumed")
	var calls atomic.Int32
	if err := engine.commitRuntimeIdentityOnce(consumed, func() error {
		calls.Add(1)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := engine.commitRuntimeIdentityOnce(consumed, func() error {
		calls.Add(1)
		return nil
	}); !errors.Is(err, consumed) {
		t.Fatalf("second commit error=%v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("commit callbacks=%d want=1", calls.Load())
	}
}

func TestEngineRuntimeIdentityCommitRetainsFirstFailure(t *testing.T) {
	engine, _ := testEngine(t, nil)
	consumed := errors.New("consumed")
	firstFailure := errors.New("first failure")
	if err := engine.commitRuntimeIdentityOnce(consumed, func() error {
		return firstFailure
	}); !errors.Is(err, firstFailure) {
		t.Fatalf("first commit error=%v", err)
	}
	if err := engine.commitRuntimeIdentityOnce(consumed, func() error {
		t.Fatal("failed Engine retried its commit callback")
		return nil
	}); !errors.Is(err, consumed) || !errors.Is(err, firstFailure) {
		t.Fatalf("sticky commit error=%v", err)
	}
}

func TestEngineValueCopySharesConsumedRuntimeIdentityCommit(t *testing.T) {
	engine, _ := testEngine(t, nil)
	copyEngine := copyEngineValue(t, engine)
	if copyEngine == engine || copyEngine.Identity() != engine.Identity() ||
		copyEngine.runtimeIdentityCommit != engine.runtimeIdentityCommit {
		t.Fatal("Engine value copy did not preserve the shared identity capability")
	}
	consumed := errors.New("consumed")
	var calls atomic.Int32
	if err := engine.commitRuntimeIdentityOnce(consumed, func() error {
		calls.Add(1)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := copyEngine.commitRuntimeIdentityOnce(consumed, func() error {
		calls.Add(1)
		return nil
	}); !errors.Is(err, consumed) {
		t.Fatalf("copied Engine commit error=%v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("original and copied Engine callbacks=%d want=1", calls.Load())
	}
}

func TestZeroEngineRuntimeIdentityCommitFailsClosed(t *testing.T) {
	var engine Engine
	consumed := errors.New("consumed")
	called := false
	err := engine.commitRuntimeIdentityOnce(consumed, func() error {
		called = true
		return nil
	})
	if !errors.Is(err, consumed) || !errors.Is(err, errRuntimeIdentityCommitStateUnavailable) {
		t.Fatalf("zero Engine commit error=%v", err)
	}
	if called {
		t.Fatal("zero Engine executed runtime identity commit")
	}
}

func TestConcurrentEngineRuntimeIdentityCommitExecutesExactlyOnce(t *testing.T) {
	engine, _ := testEngine(t, nil)
	engines := []*Engine{copyEngineValue(t, engine), copyEngineValue(t, engine)}
	consumed := errors.New("consumed")
	var calls atomic.Int32
	start := make(chan struct{})
	results := make(chan error, 2)
	var group sync.WaitGroup
	for _, candidate := range engines {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			results <- candidate.commitRuntimeIdentityOnce(consumed, func() error {
				calls.Add(1)
				return nil
			})
		}()
	}
	close(start)
	group.Wait()
	close(results)

	successes, rejections := 0, 0
	for err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, consumed) {
			rejections++
		} else {
			t.Fatalf("unexpected concurrent commit error=%v", err)
		}
	}
	if successes != 1 || rejections != 1 || calls.Load() != 1 {
		t.Fatalf(
			"concurrent commits: success=%d rejected=%d callbacks=%d",
			successes, rejections, calls.Load(),
		)
	}
}
