package dataplane

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type controlledFakeTCPRuntime struct {
	mu sync.Mutex

	runStarted   chan struct{}
	stop         chan struct{}
	runErr       error
	stopErr      error
	closeErr     error
	stopCalls    int
	closeCalls   int
	closeEarly   bool
	wakeOnStop   bool
	ignoreCancel bool
}

func newControlledFakeTCPRuntime() *controlledFakeTCPRuntime {
	return &controlledFakeTCPRuntime{
		runStarted: make(chan struct{}),
		stop:       make(chan struct{}),
		wakeOnStop: true,
	}
}

func (runtime *controlledFakeTCPRuntime) Run(ctx context.Context) error {
	close(runtime.runStarted)
	if runtime.ignoreCancel {
		<-runtime.stop
		return runtime.runErr
	}
	select {
	case <-runtime.stop:
	case <-ctx.Done():
	}
	return runtime.runErr
}

func (runtime *controlledFakeTCPRuntime) RequestStop() error {
	runtime.mu.Lock()
	runtime.stopCalls++
	if runtime.stopCalls == 1 && runtime.wakeOnStop {
		close(runtime.stop)
	}
	err := runtime.stopErr
	runtime.mu.Unlock()
	return err
}

func (runtime *controlledFakeTCPRuntime) Close() error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	select {
	case <-runtime.stop:
	default:
		runtime.closeEarly = true
	}
	runtime.closeCalls++
	return runtime.closeErr
}

func (runtime *controlledFakeTCPRuntime) counts() (int, int, bool) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.stopCalls, runtime.closeCalls, runtime.closeEarly
}

func TestFakeTCPRuntimeSupervisorRepeatedEnsureOwnsOneRuntime(t *testing.T) {
	supervisor := &fakeTCPRuntimeSupervisor{}
	runtime := newControlledFakeTCPRuntime()
	key := fakeTCPRuntimeDesiredKey{1}
	buildCalls := 0
	build := func(context.Context) (fakeTCPRuntimeService, error) {
		buildCalls++
		return runtime, nil
	}
	if err := supervisor.Ensure(t.Context(), key, build); err != nil {
		t.Fatalf("first Ensure: %v", err)
	}
	<-runtime.runStarted
	if err := supervisor.Ensure(t.Context(), key, build); err != nil {
		t.Fatalf("repeated Ensure: %v", err)
	}
	if buildCalls != 1 {
		t.Fatalf("build calls = %d, want 1", buildCalls)
	}
	if !supervisor.Healthy(key) {
		t.Fatal("supervisor is not healthy for active key")
	}
	if err := supervisor.Stop(t.Context()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	stopCalls, closeCalls, closeEarly := runtime.counts()
	if stopCalls != 1 || closeCalls != 1 || closeEarly {
		t.Fatalf("runtime lifecycle = stop %d close %d early %t", stopCalls, closeCalls, closeEarly)
	}
}

func TestFakeTCPRuntimeSupervisorRejectsChangedLiveGeneration(t *testing.T) {
	supervisor := &fakeTCPRuntimeSupervisor{}
	runtime := newControlledFakeTCPRuntime()
	if err := supervisor.Ensure(
		t.Context(), fakeTCPRuntimeDesiredKey{1},
		func(context.Context) (fakeTCPRuntimeService, error) { return runtime, nil },
	); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	<-runtime.runStarted
	replacementBuilds := 0
	err := supervisor.Ensure(
		t.Context(), fakeTCPRuntimeDesiredKey{2},
		func(context.Context) (fakeTCPRuntimeService, error) {
			replacementBuilds++
			return newControlledFakeTCPRuntime(), nil
		},
	)
	if !errors.Is(err, errFakeTCPRuntimeReplacementUnsafe) {
		t.Fatalf("changed generation error = %v", err)
	}
	if replacementBuilds != 0 || !supervisor.Healthy(fakeTCPRuntimeDesiredKey{1}) {
		t.Fatalf("replacement builds = %d, old generation healthy = %t", replacementBuilds, supervisor.Healthy(fakeTCPRuntimeDesiredKey{1}))
	}
	if err := supervisor.Stop(t.Context()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestFakeTCPRuntimeSupervisorBuildFailureLeavesNoOwner(t *testing.T) {
	supervisor := &fakeTCPRuntimeSupervisor{}
	buildErr := errors.New("build failed")
	err := supervisor.Ensure(
		t.Context(), fakeTCPRuntimeDesiredKey{1},
		func(context.Context) (fakeTCPRuntimeService, error) { return nil, buildErr },
	)
	if !errors.Is(err, buildErr) {
		t.Fatalf("Ensure error = %v", err)
	}
	if supervisor.loadCurrent() != nil {
		t.Fatal("failed build left a supervised runtime")
	}
}

func TestFakeTCPRuntimeSupervisorCancellationClosesUnstartedOwner(t *testing.T) {
	supervisor := &fakeTCPRuntimeSupervisor{}
	runtime := newControlledFakeTCPRuntime()
	ctx, cancel := context.WithCancel(t.Context())
	err := supervisor.Ensure(ctx, fakeTCPRuntimeDesiredKey{1}, func(context.Context) (fakeTCPRuntimeService, error) {
		cancel()
		return runtime, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Ensure error = %v", err)
	}
	_, closeCalls, _ := runtime.counts()
	if closeCalls != 1 || supervisor.loadCurrent() != nil {
		t.Fatalf("close calls = %d, current = %#v", closeCalls, supervisor.loadCurrent())
	}
}

func TestFakeTCPRuntimeSupervisorReportsUnexpectedRunExit(t *testing.T) {
	supervisor := &fakeTCPRuntimeSupervisor{}
	runtime := newControlledFakeTCPRuntime()
	close(runtime.stop)
	if err := supervisor.Ensure(
		t.Context(), fakeTCPRuntimeDesiredKey{1},
		func(context.Context) (fakeTCPRuntimeService, error) { return runtime, nil },
	); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	select {
	case <-supervisor.loadCurrent().done:
	case <-time.After(time.Second):
		t.Fatal("runtime did not exit")
	}
	if supervisor.Healthy(fakeTCPRuntimeDesiredKey{1}) {
		t.Fatal("exited runtime reported healthy")
	}
	if !errors.Is(supervisor.RuntimeError(), errFakeTCPRuntimeExited) {
		t.Fatalf("RuntimeError = %v", supervisor.RuntimeError())
	}
	err := supervisor.Ensure(
		t.Context(), fakeTCPRuntimeDesiredKey{1},
		func(context.Context) (fakeTCPRuntimeService, error) {
			t.Fatal("replacement build ran before terminal error was reported")
			return nil, nil
		},
	)
	if !errors.Is(err, errFakeTCPRuntimeExited) {
		t.Fatalf("retire error = %v", err)
	}
	_, closeCalls, _ := runtime.counts()
	if closeCalls != 1 || supervisor.loadCurrent() != nil {
		t.Fatalf("close calls = %d, current = %#v", closeCalls, supervisor.loadCurrent())
	}
}

func TestFakeTCPRuntimeSupervisorStopTimeoutRetainsOwnership(t *testing.T) {
	supervisor := &fakeTCPRuntimeSupervisor{}
	runtime := newControlledFakeTCPRuntime()
	// Model a broken stop implementation: count the request without waking Run.
	runtime.wakeOnStop = false
	runtime.ignoreCancel = true
	runtime.stopErr = errors.New("stop unavailable")
	if err := supervisor.Ensure(
		t.Context(), fakeTCPRuntimeDesiredKey{1},
		func(context.Context) (fakeTCPRuntimeService, error) { return runtime, nil },
	); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	<-runtime.runStarted
	ctx, cancel := context.WithTimeout(t.Context(), time.Millisecond)
	defer cancel()
	if err := supervisor.Stop(ctx); !errors.Is(err, context.DeadlineExceeded) ||
		!errors.Is(err, runtime.stopErr) {
		t.Fatalf("Stop error = %v", err)
	}
	if supervisor.loadCurrent() == nil {
		t.Fatal("timed-out stop discarded runtime ownership")
	}
	_, closeCalls, _ := runtime.counts()
	if closeCalls != 0 {
		t.Fatalf("close calls = %d before Run exit", closeCalls)
	}
	close(runtime.stop)
	if err := supervisor.Stop(t.Context()); err != nil {
		t.Fatalf("retry Stop: %v", err)
	}
}
