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
	healthErr    error
	healthCalls  int
	stopCalls    int
	closeCalls   int
	closeEarly   bool
	wakeOnStop   bool
	ignoreCancel bool
}

// firstNilErrContext makes the pre-serialization Err observation visible. The
// first call always reports an active context and closes prechecked; later
// calls delegate to the cancellable parent.
type firstNilErrContext struct {
	context.Context
	prechecked chan struct{}
	once       sync.Once
}

func newFirstNilErrContext(parent context.Context) *firstNilErrContext {
	return &firstNilErrContext{
		Context:    parent,
		prechecked: make(chan struct{}),
	}
}

func (ctx *firstNilErrContext) Err() error {
	first := false
	ctx.once.Do(func() {
		first = true
		close(ctx.prechecked)
	})
	if first {
		return nil
	}
	return ctx.Context.Err()
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

func (runtime *controlledFakeTCPRuntime) Healthy(ctx context.Context) error {
	if ctx == nil {
		return errors.New("health context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.healthCalls++
	return runtime.healthErr
}

func (runtime *controlledFakeTCPRuntime) counts() (int, int, bool) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.stopCalls, runtime.closeCalls, runtime.closeEarly
}

func (runtime *controlledFakeTCPRuntime) setCloseError(err error) {
	runtime.mu.Lock()
	runtime.closeErr = err
	runtime.mu.Unlock()
}

func (runtime *controlledFakeTCPRuntime) setHealthError(err error) {
	runtime.mu.Lock()
	runtime.healthErr = err
	runtime.mu.Unlock()
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

func TestFakeTCPRuntimeSupervisorSeriallyReplacesChangedLiveGeneration(t *testing.T) {
	supervisor := &fakeTCPRuntimeSupervisor{}
	firstRuntime := newControlledFakeTCPRuntime()
	if err := supervisor.Ensure(
		t.Context(), fakeTCPRuntimeDesiredKey{1},
		func(context.Context) (fakeTCPRuntimeService, error) { return firstRuntime, nil },
	); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	<-firstRuntime.runStarted
	secondRuntime := newControlledFakeTCPRuntime()
	replacementBuilds := 0
	err := supervisor.Ensure(
		t.Context(), fakeTCPRuntimeDesiredKey{2},
		func(context.Context) (fakeTCPRuntimeService, error) {
			replacementBuilds++
			return secondRuntime, nil
		},
	)
	if err != nil {
		t.Fatalf("changed generation replacement: %v", err)
	}
	<-secondRuntime.runStarted
	if replacementBuilds != 1 || supervisor.Healthy(fakeTCPRuntimeDesiredKey{1}) ||
		!supervisor.Healthy(fakeTCPRuntimeDesiredKey{2}) {
		t.Fatalf(
			"replacement builds = %d, old healthy = %t, new healthy = %t",
			replacementBuilds,
			supervisor.Healthy(fakeTCPRuntimeDesiredKey{1}),
			supervisor.Healthy(fakeTCPRuntimeDesiredKey{2}),
		)
	}
	stopCalls, closeCalls, closeEarly := firstRuntime.counts()
	if stopCalls != 1 || closeCalls != 1 || closeEarly {
		t.Fatalf("old runtime lifecycle = stop %d close %d early %t", stopCalls, closeCalls, closeEarly)
	}
	if err := supervisor.Stop(t.Context()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestFakeTCPRuntimeSupervisorRebuildsUnhealthySameGeneration(t *testing.T) {
	supervisor := &fakeTCPRuntimeSupervisor{}
	key := fakeTCPRuntimeDesiredKey{1}
	firstRuntime := newControlledFakeTCPRuntime()
	if err := supervisor.Ensure(
		t.Context(), key,
		func(context.Context) (fakeTCPRuntimeService, error) { return firstRuntime, nil },
	); err != nil {
		t.Fatalf("first Ensure: %v", err)
	}
	<-firstRuntime.runStarted
	firstRuntime.setHealthError(errors.New("owned link disappeared"))
	secondRuntime := newControlledFakeTCPRuntime()
	builds := 0
	if err := supervisor.Ensure(
		t.Context(), key,
		func(context.Context) (fakeTCPRuntimeService, error) {
			builds++
			return secondRuntime, nil
		},
	); err != nil {
		t.Fatalf("unhealthy same-key Ensure: %v", err)
	}
	<-secondRuntime.runStarted
	if builds != 1 || !supervisor.Healthy(key) {
		t.Fatalf("replacement builds=%d healthy=%t", builds, supervisor.Healthy(key))
	}
	stopCalls, closeCalls, closeEarly := firstRuntime.counts()
	if stopCalls != 1 || closeCalls != 1 || closeEarly {
		t.Fatalf("old runtime lifecycle = stop %d close %d early %t", stopCalls, closeCalls, closeEarly)
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
	key := fakeTCPRuntimeDesiredKey{1}
	if supervisor.Healthy(key) {
		t.Fatal("stop-requested runtime reported healthy after timeout")
	}
	replacementBuilds := 0
	if err := supervisor.Ensure(
		t.Context(), key,
		func(context.Context) (fakeTCPRuntimeService, error) {
			replacementBuilds++
			return newControlledFakeTCPRuntime(), nil
		},
	); !errors.Is(err, errFakeTCPRuntimeStopping) {
		t.Fatalf("same-key Ensure during timed-out stop error = %v", err)
	}
	if replacementBuilds != 0 {
		t.Fatalf("same-key Ensure built %d overlapping runtimes", replacementBuilds)
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

func TestFakeTCPRuntimeSupervisorKeepsSYNQuotaOwnerUntilCloseCompletes(t *testing.T) {
	supervisor := &fakeTCPRuntimeSupervisor{}
	runtime := newControlledFakeTCPRuntime()
	closeErr := errors.New("injected runtime close failure")
	runtime.setCloseError(closeErr)
	key := fakeTCPRuntimeDesiredKey{1}
	if err := supervisor.Ensure(
		t.Context(), key,
		func(context.Context) (fakeTCPRuntimeService, error) { return runtime, nil },
	); err != nil {
		t.Fatal(err)
	}
	<-runtime.runStarted
	if err := supervisor.Stop(t.Context()); !errors.Is(err, closeErr) {
		t.Fatalf("first Stop error = %v", err)
	}
	if supervisor.loadCurrent() == nil {
		t.Fatal("failed Close discarded the only runtime owner")
	}
	replacementBuilds := 0
	restartKeys := []fakeTCPRuntimeDesiredKey{{1}, {2}, {3}, {255}}
	for attempt, restartKey := range restartKeys {
		if err := supervisor.Ensure(
			t.Context(), restartKey,
			func(context.Context) (fakeTCPRuntimeService, error) {
				replacementBuilds++
				return newControlledFakeTCPRuntime(), nil
			},
		); !errors.Is(err, closeErr) {
			t.Fatalf("restart attempt %d during quota-owner quarantine error = %v", attempt, err)
		}
		if replacementBuilds != 0 || supervisor.loadCurrent() == nil {
			t.Fatalf("restart attempt %d built overlapping quota owner: builds=%d current=%#v",
				attempt, replacementBuilds, supervisor.loadCurrent())
		}
	}
	runtime.setCloseError(nil)
	if err := supervisor.Stop(t.Context()); err != nil {
		t.Fatalf("retry Stop: %v", err)
	}
	if supervisor.loadCurrent() != nil {
		t.Fatal("successful retry retained quarantine owner")
	}
	_, closeCalls, _ := runtime.counts()
	wantCloseCalls := 2 + len(restartKeys)
	if closeCalls != wantCloseCalls {
		t.Fatalf("Close calls = %d, want initial Stop + %d restart attempts + final Stop",
			closeCalls, len(restartKeys))
	}

	replacement := newControlledFakeTCPRuntime()
	if err := supervisor.Ensure(
		t.Context(), fakeTCPRuntimeDesiredKey{2},
		func(context.Context) (fakeTCPRuntimeService, error) {
			replacementBuilds++
			return replacement, nil
		},
	); err != nil {
		t.Fatalf("Ensure after old quota owner closed: %v", err)
	}
	<-replacement.runStarted
	if replacementBuilds != 1 || !supervisor.Healthy(fakeTCPRuntimeDesiredKey{2}) {
		t.Fatalf("replacement quota owner builds=%d healthy=%t",
			replacementBuilds, supervisor.Healthy(fakeTCPRuntimeDesiredKey{2}))
	}
	if err := supervisor.Stop(t.Context()); err != nil {
		t.Fatalf("replacement Stop: %v", err)
	}
}

func TestFakeTCPRuntimeSupervisorQuarantinesUnstartedCloseFailure(t *testing.T) {
	supervisor := &fakeTCPRuntimeSupervisor{}
	runtime := newControlledFakeTCPRuntime()
	closeErr := errors.New("injected unstarted close failure")
	runtime.setCloseError(closeErr)
	ctx, cancel := context.WithCancel(t.Context())
	err := supervisor.Ensure(
		ctx,
		fakeTCPRuntimeDesiredKey{1},
		func(context.Context) (fakeTCPRuntimeService, error) {
			cancel()
			return runtime, nil
		},
	)
	if !errors.Is(err, context.Canceled) || !errors.Is(err, closeErr) {
		t.Fatalf("Ensure error = %v", err)
	}
	if supervisor.loadCurrent() == nil {
		t.Fatal("unstarted Close failure discarded runtime owner")
	}
	runtime.setCloseError(nil)
	if err := supervisor.Stop(t.Context()); err != nil {
		t.Fatalf("retry quarantined Close: %v", err)
	}
	if supervisor.loadCurrent() != nil {
		t.Fatal("quarantined unstarted owner remains after retry")
	}
}

func TestFakeTCPRuntimeSupervisorRechecksEnsureCancellationAfterSerialization(t *testing.T) {
	supervisor := &fakeTCPRuntimeSupervisor{}
	supervisor.operationMu.Lock()
	parent, cancel := context.WithCancel(t.Context())
	ctx := newFirstNilErrContext(parent)
	done := make(chan error, 1)
	buildCalls := 0
	go func() {
		done <- supervisor.Ensure(
			ctx,
			fakeTCPRuntimeDesiredKey{1},
			func(context.Context) (fakeTCPRuntimeService, error) {
				buildCalls++
				return newControlledFakeTCPRuntime(), nil
			},
		)
	}()
	<-ctx.prechecked
	cancel()
	supervisor.operationMu.Unlock()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Ensure error = %v", err)
	}
	if buildCalls != 0 || supervisor.loadCurrent() != nil {
		t.Fatalf("build calls = %d, current = %#v", buildCalls, supervisor.loadCurrent())
	}
}

func TestFakeTCPRuntimeSupervisorRechecksStopCancellationAfterSerialization(t *testing.T) {
	supervisor := &fakeTCPRuntimeSupervisor{}
	runtime := newControlledFakeTCPRuntime()
	if err := supervisor.Ensure(
		t.Context(),
		fakeTCPRuntimeDesiredKey{1},
		func(context.Context) (fakeTCPRuntimeService, error) { return runtime, nil },
	); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	<-runtime.runStarted

	supervisor.operationMu.Lock()
	parent, cancel := context.WithCancel(t.Context())
	ctx := newFirstNilErrContext(parent)
	done := make(chan error, 1)
	go func() { done <- supervisor.Stop(ctx) }()
	<-ctx.prechecked
	cancel()
	supervisor.operationMu.Unlock()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Stop error = %v", err)
	}
	stopCalls, closeCalls, _ := runtime.counts()
	if stopCalls != 0 || closeCalls != 0 || !supervisor.Healthy(fakeTCPRuntimeDesiredKey{1}) {
		t.Fatalf("runtime lifecycle = stop %d close %d healthy %t", stopCalls, closeCalls, supervisor.Healthy(fakeTCPRuntimeDesiredKey{1}))
	}
	if err := supervisor.Stop(t.Context()); err != nil {
		t.Fatalf("cleanup Stop: %v", err)
	}
}
