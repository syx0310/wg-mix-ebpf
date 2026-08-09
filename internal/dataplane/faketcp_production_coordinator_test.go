package dataplane

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"

	"github.com/syx0310/wg-mix-ebpf/internal/control"
)

type fakeTCPProductionTestEvents struct {
	mu     sync.Mutex
	values []string
}

func (events *fakeTCPProductionTestEvents) add(value string) {
	events.mu.Lock()
	events.values = append(events.values, value)
	events.mu.Unlock()
}

func (events *fakeTCPProductionTestEvents) snapshot() []string {
	events.mu.Lock()
	defer events.mu.Unlock()
	return append([]string(nil), events.values...)
}

func (events *fakeTCPProductionTestEvents) reset() {
	events.mu.Lock()
	events.values = nil
	events.mu.Unlock()
}

type fakeTCPProductionTestBaseline struct {
	events         *fakeTCPProductionTestEvents
	applyErr       error
	detachErr      error
	detachStaleErr error
	onApply        func()
	onDetach       func()

	mu               sync.Mutex
	applyCalls       int
	detachCalls      int
	detachStaleCalls int
}

func (baseline *fakeTCPProductionTestBaseline) Apply(
	context.Context,
	*control.State,
) error {
	baseline.mu.Lock()
	baseline.applyCalls++
	baseline.mu.Unlock()
	if baseline.onApply != nil {
		baseline.onApply()
	}
	if baseline.events != nil {
		baseline.events.add("baseline-apply")
	}
	return baseline.applyErr
}

func (baseline *fakeTCPProductionTestBaseline) Detach(
	context.Context,
	*control.State,
) error {
	baseline.mu.Lock()
	baseline.detachCalls++
	baseline.mu.Unlock()
	if baseline.onDetach != nil {
		baseline.onDetach()
	}
	if baseline.events != nil {
		baseline.events.add("baseline-detach")
	}
	return baseline.detachErr
}

func (baseline *fakeTCPProductionTestBaseline) DetachStale(
	context.Context,
	*control.State,
	*control.State,
) error {
	baseline.mu.Lock()
	baseline.detachStaleCalls++
	baseline.mu.Unlock()
	if baseline.events != nil {
		baseline.events.add("baseline-detach-stale")
	}
	return baseline.detachStaleErr
}

func (baseline *fakeTCPProductionTestBaseline) counts() (apply, detach, stale int) {
	baseline.mu.Lock()
	defer baseline.mu.Unlock()
	return baseline.applyCalls, baseline.detachCalls, baseline.detachStaleCalls
}

func fakeTCPProductionTestState() *control.State {
	return &control.State{
		WireGuards: []control.WireGuardState{{
			Name: "wg-faketcp", TransportMode: "faketcp",
		}},
	}
}

func newFakeTCPProductionTestCoordinator(
	baseline AttachStateLoader,
	gate fakeTCPActivationValidator,
	planner fakeTCPProductionPlanner,
) (*fakeTCPProductionCoordinator, *fakeTCPProductionCoordinatorState) {
	shared := &fakeTCPProductionCoordinatorState{
		supervisor: &fakeTCPRuntimeSupervisor{},
		owner:      dataplaneCoreOwnerUnknown,
	}
	return &fakeTCPProductionCoordinator{
		baseline:           baseline,
		shared:             shared,
		validateActivation: gate,
		planExperimental:   planner,
	}, shared
}

func TestFakeTCPProductionCoordinatorGatePrecedesEveryApplyMutation(t *testing.T) {
	gateErr := errors.New("closed activation gate")
	for _, state := range []*control.State{{}, fakeTCPProductionTestState()} {
		t.Run(func() string {
			if len(fakeTCPStateReferences(state)) == 0 {
				return "baseline"
			}
			return "experimental"
		}(), func(t *testing.T) {
			events := &fakeTCPProductionTestEvents{}
			baseline := &fakeTCPProductionTestBaseline{events: events}
			planCalls := 0
			coordinator, shared := newFakeTCPProductionTestCoordinator(
				baseline,
				func(*control.State) error {
					events.add("gate")
					return gateErr
				},
				func(context.Context, *control.State) (*fakeTCPProductionPlan, error) {
					planCalls++
					return nil, errors.New("planner must not run")
				},
			)

			err := coordinator.Apply(t.Context(), state)
			if !errors.Is(err, gateErr) {
				t.Fatalf("Apply error = %v, want gate error", err)
			}
			if got := events.snapshot(); !reflect.DeepEqual(got, []string{"gate"}) {
				t.Fatalf("events = %q, want gate only", got)
			}
			apply, detach, stale := baseline.counts()
			if planCalls != 0 || apply != 0 || detach != 0 || stale != 0 {
				t.Fatalf(
					"calls after closed gate: plan=%d apply=%d detach=%d stale=%d",
					planCalls, apply, detach, stale,
				)
			}
			if shared.owner != dataplaneCoreOwnerUnknown {
				t.Fatalf("owner changed across closed gate: %d", shared.owner)
			}
		})
	}
}

func TestFakeTCPProductionCoordinatorCommitsExclusiveCoreTransitions(t *testing.T) {
	events := &fakeTCPProductionTestEvents{}
	runtime := newControlledFakeTCPRuntime()
	baseline := &fakeTCPProductionTestBaseline{events: events}
	coordinator, shared := newFakeTCPProductionTestCoordinator(
		baseline,
		func(*control.State) error {
			events.add("gate")
			return nil
		},
		func(context.Context, *control.State) (*fakeTCPProductionPlan, error) {
			events.add("plan")
			return &fakeTCPProductionPlan{
				key: fakeTCPRuntimeDesiredKey{1},
				build: func(context.Context) (fakeTCPRuntimeService, error) {
					events.add("factory")
					return runtime, nil
				},
			}, nil
		},
	)

	if err := coordinator.Apply(t.Context(), &control.State{}); err != nil {
		t.Fatal(err)
	}
	if got, want := events.snapshot(), []string{"gate", "baseline-apply"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("initial baseline commit order = %q, want %q", got, want)
	}
	if shared.owner != dataplaneCoreOwnerBaseline {
		t.Fatalf("owner after initial baseline commit = %d", shared.owner)
	}

	events.reset()
	if err := coordinator.Apply(t.Context(), fakeTCPProductionTestState()); err != nil {
		t.Fatal(err)
	}
	<-runtime.runStarted
	if got, want := events.snapshot(), []string{"gate", "plan", "baseline-detach", "factory"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("experimental startup order = %q, want %q", got, want)
	}
	if shared.owner != dataplaneCoreOwnerExperimental {
		t.Fatalf("owner after experimental commit = %d", shared.owner)
	}

	baseline.onApply = func() {
		stopCalls, closeCalls, closeEarly := runtime.counts()
		if stopCalls != 1 || closeCalls != 1 || closeEarly {
			t.Errorf(
				"baseline started before experimental release: stop=%d close=%d early=%t",
				stopCalls, closeCalls, closeEarly,
			)
		}
	}
	events.reset()
	if err := coordinator.Apply(t.Context(), &control.State{}); err != nil {
		t.Fatal(err)
	}
	if got, want := events.snapshot(), []string{"gate", "baseline-apply"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("baseline transition order = %q, want %q", got, want)
	}
	if shared.owner != dataplaneCoreOwnerBaseline {
		t.Fatalf("owner after baseline commit = %d", shared.owner)
	}
}

func TestFakeTCPProductionCoordinatorCancelsUnclaimedPlanBeforeDetach(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	events := &fakeTCPProductionTestEvents{}
	baseline := &fakeTCPProductionTestBaseline{events: events}
	buildCalls := 0
	rollbackCalls := 0
	coordinator, shared := newFakeTCPProductionTestCoordinator(
		baseline,
		func(*control.State) error {
			events.add("gate")
			return nil
		},
		func(context.Context, *control.State) (*fakeTCPProductionPlan, error) {
			events.add("plan")
			cancel()
			return &fakeTCPProductionPlan{
				key: fakeTCPRuntimeDesiredKey{1},
				build: func(context.Context) (fakeTCPRuntimeService, error) {
					buildCalls++
					return nil, nil
				},
				rollback: func() error {
					rollbackCalls++
					events.add("plan-rollback")
					return nil
				},
			}, nil
		},
	)

	err := coordinator.Apply(ctx, fakeTCPProductionTestState())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Apply error = %v, want cancellation", err)
	}
	if got, want := events.snapshot(), []string{"gate", "plan", "plan-rollback"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("cancellation order = %q, want %q", got, want)
	}
	_, detach, _ := baseline.counts()
	if buildCalls != 0 || rollbackCalls != 1 || detach != 0 {
		t.Fatalf("canceled calls: build=%d rollback=%d detach=%d", buildCalls, rollbackCalls, detach)
	}
	if shared.owner != dataplaneCoreOwnerUnknown {
		t.Fatalf("owner changed before canceled mutation: %d", shared.owner)
	}
}

func TestFakeTCPProductionCoordinatorBuildFailureUsesFactoryRollback(t *testing.T) {
	buildErr := errors.New("factory build rolled back")
	runtime := newControlledFakeTCPRuntime()
	baseline := &fakeTCPProductionTestBaseline{}
	unclaimedRollbacks := 0
	coordinator, shared := newFakeTCPProductionTestCoordinator(
		baseline,
		func(*control.State) error { return nil },
		func(context.Context, *control.State) (*fakeTCPProductionPlan, error) {
			return &fakeTCPProductionPlan{
				key: fakeTCPRuntimeDesiredKey{1},
				build: func(context.Context) (fakeTCPRuntimeService, error) {
					return runtime, buildErr
				},
				rollback: func() error {
					unclaimedRollbacks++
					return nil
				},
			}, nil
		},
	)

	err := coordinator.Apply(t.Context(), fakeTCPProductionTestState())
	if !errors.Is(err, buildErr) {
		t.Fatalf("Apply error = %v, want factory error", err)
	}
	_, closeCalls, _ := runtime.counts()
	if closeCalls != 1 || unclaimedRollbacks != 0 {
		t.Fatalf("factory cleanup: runtime closes=%d unclaimed rollbacks=%d", closeCalls, unclaimedRollbacks)
	}
	if shared.owner != dataplaneCoreOwnerExperimental {
		t.Fatalf("failed build was not conservatively quarantined: owner=%d", shared.owner)
	}

	// A later baseline transition always enters Stop first. When the factory
	// already completed rollback there is no retained runtime, so baseline Apply
	// can safely establish the sole owner.
	if err := coordinator.Apply(t.Context(), &control.State{}); err != nil {
		t.Fatal(err)
	}
	if shared.owner != dataplaneCoreOwnerBaseline {
		t.Fatalf("owner after recovery baseline apply = %d", shared.owner)
	}
}

func TestFakeTCPProductionCoordinatorJoinsUnclaimedRollbackFailure(t *testing.T) {
	detachErr := errors.New("baseline detach failed")
	rollbackErr := errors.New("plan rollback failed")
	baseline := &fakeTCPProductionTestBaseline{detachErr: detachErr}
	rollbackCalls := 0
	coordinator, shared := newFakeTCPProductionTestCoordinator(
		baseline,
		func(*control.State) error { return nil },
		func(context.Context, *control.State) (*fakeTCPProductionPlan, error) {
			return &fakeTCPProductionPlan{
				key:   fakeTCPRuntimeDesiredKey{1},
				build: func(context.Context) (fakeTCPRuntimeService, error) { return nil, nil },
				rollback: func() error {
					rollbackCalls++
					return rollbackErr
				},
			}, nil
		},
	)

	err := coordinator.Apply(t.Context(), fakeTCPProductionTestState())
	if !errors.Is(err, detachErr) || !errors.Is(err, rollbackErr) {
		t.Fatalf("Apply error = %v, want detach and rollback failures", err)
	}
	if rollbackCalls != 1 || shared.owner != dataplaneCoreOwnerBaseline {
		t.Fatalf("failed prebuild rollback: calls=%d owner=%d", rollbackCalls, shared.owner)
	}
}

func TestFakeTCPProductionCoordinatorRollsBackUnusedSameKeyPlan(t *testing.T) {
	firstRuntime := newControlledFakeTCPRuntime()
	secondBuildCalls := 0
	secondRollbackCalls := 0
	plans := 0
	baseline := &fakeTCPProductionTestBaseline{}
	coordinator, _ := newFakeTCPProductionTestCoordinator(
		baseline,
		func(*control.State) error { return nil },
		func(context.Context, *control.State) (*fakeTCPProductionPlan, error) {
			plans++
			if plans == 1 {
				return &fakeTCPProductionPlan{
					key:   fakeTCPRuntimeDesiredKey{1},
					build: func(context.Context) (fakeTCPRuntimeService, error) { return firstRuntime, nil },
				}, nil
			}
			return &fakeTCPProductionPlan{
				key: fakeTCPRuntimeDesiredKey{1},
				build: func(context.Context) (fakeTCPRuntimeService, error) {
					secondBuildCalls++
					return newControlledFakeTCPRuntime(), nil
				},
				rollback: func() error {
					secondRollbackCalls++
					return nil
				},
			}, nil
		},
	)

	state := fakeTCPProductionTestState()
	if err := coordinator.Apply(t.Context(), state); err != nil {
		t.Fatal(err)
	}
	<-firstRuntime.runStarted
	if err := coordinator.Apply(t.Context(), state); err != nil {
		t.Fatal(err)
	}
	if secondBuildCalls != 0 || secondRollbackCalls != 1 {
		t.Fatalf("same-key plan: builds=%d rollbacks=%d", secondBuildCalls, secondRollbackCalls)
	}
	if err := coordinator.Detach(t.Context(), state); err != nil {
		t.Fatal(err)
	}
}

func TestFakeTCPProductionCoordinatorRetriesCloseBeforeBaselineDetach(t *testing.T) {
	closeErr := errors.New("retained runtime close")
	runtime := newControlledFakeTCPRuntime()
	runtime.setCloseError(closeErr)
	baseline := &fakeTCPProductionTestBaseline{}
	coordinator, shared := newFakeTCPProductionTestCoordinator(
		baseline,
		func(*control.State) error { return nil },
		func(context.Context, *control.State) (*fakeTCPProductionPlan, error) {
			return &fakeTCPProductionPlan{
				key:   fakeTCPRuntimeDesiredKey{1},
				build: func(context.Context) (fakeTCPRuntimeService, error) { return runtime, nil },
			}, nil
		},
	)
	state := fakeTCPProductionTestState()
	if err := coordinator.Apply(t.Context(), state); err != nil {
		t.Fatal(err)
	}
	<-runtime.runStarted
	_, initialDetaches, _ := baseline.counts()

	err := coordinator.Detach(t.Context(), state)
	if !errors.Is(err, closeErr) {
		t.Fatalf("first Detach error = %v, want retained close error", err)
	}
	_, detachesAfterFailure, _ := baseline.counts()
	if detachesAfterFailure != initialDetaches {
		t.Fatal("baseline detach ran while experimental close remained quarantined")
	}
	if shared.owner != dataplaneCoreOwnerExperimental {
		t.Fatalf("owner after failed close = %d", shared.owner)
	}

	runtime.setCloseError(nil)
	if err := coordinator.Detach(t.Context(), state); err != nil {
		t.Fatal(err)
	}
	_, finalDetaches, _ := baseline.counts()
	if finalDetaches != initialDetaches+1 {
		t.Fatalf("baseline detach calls after retry = %d, want %d", finalDetaches, initialDetaches+1)
	}
	_, closeCalls, _ := runtime.counts()
	if closeCalls != 2 || shared.owner != dataplaneCoreOwnerNone {
		t.Fatalf("close retry: calls=%d owner=%d", closeCalls, shared.owner)
	}
}

func TestFakeTCPProductionCoordinatorSerializesExperimentalStartAgainstBaselineOperations(t *testing.T) {
	tests := []struct {
		name       string
		second     func(*fakeTCPProductionCoordinator, context.Context) error
		wantApply  int
		wantDetach int
		wantOwner  dataplaneCoreOwner
	}{
		{
			name: "apply",
			second: func(coordinator *fakeTCPProductionCoordinator, ctx context.Context) error {
				return coordinator.Apply(ctx, &control.State{})
			},
			wantApply:  1,
			wantDetach: 1,
			wantOwner:  dataplaneCoreOwnerBaseline,
		},
		{
			name: "detach",
			second: func(coordinator *fakeTCPProductionCoordinator, ctx context.Context) error {
				return coordinator.Detach(ctx, fakeTCPProductionTestState())
			},
			wantDetach: 2,
			wantOwner:  dataplaneCoreOwnerNone,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plannerEntered := make(chan struct{})
			releasePlanner := make(chan struct{})
			runtime := newControlledFakeTCPRuntime()
			baseline := &fakeTCPProductionTestBaseline{}
			coordinator, shared := newFakeTCPProductionTestCoordinator(
				baseline,
				func(*control.State) error { return nil },
				func(context.Context, *control.State) (*fakeTCPProductionPlan, error) {
					close(plannerEntered)
					<-releasePlanner
					return &fakeTCPProductionPlan{
						key:   fakeTCPRuntimeDesiredKey{1},
						build: func(context.Context) (fakeTCPRuntimeService, error) { return runtime, nil },
					}, nil
				},
			)

			firstDone := make(chan error, 1)
			go func() {
				firstDone <- coordinator.Apply(t.Context(), fakeTCPProductionTestState())
			}()
			<-plannerEntered

			secondCtx := newFirstNilErrContext(t.Context())
			secondDone := make(chan error, 1)
			go func() { secondDone <- test.second(coordinator, secondCtx) }()
			<-secondCtx.prechecked
			select {
			case err := <-secondDone:
				t.Fatalf("baseline %s escaped production serialization: %v", test.name, err)
			default:
			}
			if shared.operationMu.TryLock() {
				shared.operationMu.Unlock()
				t.Fatal("experimental planner did not retain the production operation lock")
			}
			apply, detach, stale := baseline.counts()
			if apply != 0 || detach != 0 || stale != 0 {
				t.Fatalf(
					"baseline mutation interleaved with planner: apply=%d detach=%d stale=%d",
					apply, detach, stale,
				)
			}

			close(releasePlanner)
			if err := <-firstDone; err != nil {
				t.Fatalf("experimental Apply: %v", err)
			}
			if err := <-secondDone; err != nil {
				t.Fatalf("serialized baseline %s: %v", test.name, err)
			}
			apply, detach, stale = baseline.counts()
			if apply != test.wantApply || detach != test.wantDetach || stale != 0 {
				t.Fatalf(
					"serialized calls: apply=%d detach=%d stale=%d; want apply=%d detach=%d",
					apply, detach, stale, test.wantApply, test.wantDetach,
				)
			}
			stopCalls, closeCalls, closeEarly := runtime.counts()
			if stopCalls != 1 || closeCalls != 1 || closeEarly {
				t.Fatalf(
					"experimental release before baseline %s: stop=%d close=%d early=%t",
					test.name, stopCalls, closeCalls, closeEarly,
				)
			}
			if shared.owner != test.wantOwner {
				t.Fatalf("final owner = %d, want %d", shared.owner, test.wantOwner)
			}
		})
	}
}

func TestFakeTCPProductionCoordinatorSerializesApplyAndDetachStale(t *testing.T) {
	events := &fakeTCPProductionTestEvents{}
	applyEntered := make(chan struct{})
	releaseApply := make(chan struct{})
	baseline := &fakeTCPProductionTestBaseline{events: events}
	baseline.onApply = func() {
		close(applyEntered)
		<-releaseApply
	}
	coordinator, shared := newFakeTCPProductionTestCoordinator(
		baseline,
		func(*control.State) error {
			events.add("gate")
			return nil
		},
		nil,
	)

	applyDone := make(chan error, 1)
	go func() { applyDone <- coordinator.Apply(t.Context(), &control.State{}) }()
	<-applyEntered

	staleCtx := newFirstNilErrContext(t.Context())
	staleDone := make(chan error, 1)
	go func() {
		staleDone <- coordinator.DetachStale(staleCtx, &control.State{}, &control.State{})
	}()
	<-staleCtx.prechecked
	select {
	case err := <-staleDone:
		t.Fatalf("DetachStale escaped Apply serialization: %v", err)
	default:
	}
	_, _, stale := baseline.counts()
	if stale != 0 {
		t.Fatal("DetachStale mutation interleaved with Apply")
	}

	close(releaseApply)
	if err := <-applyDone; err != nil {
		t.Fatal(err)
	}
	if err := <-staleDone; err != nil {
		t.Fatal(err)
	}
	if got, want := events.snapshot(), []string{
		"gate", "baseline-apply", "gate", "baseline-detach-stale",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Apply/DetachStale order = %q, want %q", got, want)
	}
	apply, detach, stale := baseline.counts()
	if apply != 1 || detach != 0 || stale != 1 || shared.owner != dataplaneCoreOwnerBaseline {
		t.Fatalf(
			"final baseline state: apply=%d detach=%d stale=%d owner=%d",
			apply, detach, stale, shared.owner,
		)
	}
}

func TestFakeTCPProductionCoordinatorDetachStaleRetriesExperimentalClose(t *testing.T) {
	closeErr := errors.New("stale transition retained runtime close")
	runtime := newControlledFakeTCPRuntime()
	runtime.setCloseError(closeErr)
	baseline := &fakeTCPProductionTestBaseline{}
	coordinator, shared := newFakeTCPProductionTestCoordinator(
		baseline,
		func(*control.State) error { return nil },
		func(context.Context, *control.State) (*fakeTCPProductionPlan, error) {
			return &fakeTCPProductionPlan{
				key:   fakeTCPRuntimeDesiredKey{1},
				build: func(context.Context) (fakeTCPRuntimeService, error) { return runtime, nil },
			}, nil
		},
	)
	if err := coordinator.Apply(t.Context(), fakeTCPProductionTestState()); err != nil {
		t.Fatal(err)
	}
	<-runtime.runStarted

	err := coordinator.DetachStale(t.Context(), fakeTCPProductionTestState(), &control.State{})
	if !errors.Is(err, closeErr) {
		t.Fatalf("first DetachStale error = %v, want close error", err)
	}
	_, _, stale := baseline.counts()
	if stale != 0 || shared.owner != dataplaneCoreOwnerExperimental {
		t.Fatalf("stale mutation crossed failed close: stale=%d owner=%d", stale, shared.owner)
	}

	runtime.setCloseError(nil)
	if err := coordinator.DetachStale(t.Context(), fakeTCPProductionTestState(), &control.State{}); err != nil {
		t.Fatal(err)
	}
	_, _, stale = baseline.counts()
	_, closeCalls, _ := runtime.counts()
	if stale != 1 || closeCalls != 2 || shared.owner != dataplaneCoreOwnerBaseline {
		t.Fatalf("stale close retry: stale=%d closes=%d owner=%d", stale, closeCalls, shared.owner)
	}
}

func TestFakeTCPProductionCoordinatorDetachStaleDoesNotTouchExperimentalCore(t *testing.T) {
	runtime := newControlledFakeTCPRuntime()
	baseline := &fakeTCPProductionTestBaseline{}
	coordinator, shared := newFakeTCPProductionTestCoordinator(
		baseline,
		func(*control.State) error { return nil },
		func(context.Context, *control.State) (*fakeTCPProductionPlan, error) {
			return &fakeTCPProductionPlan{
				key:   fakeTCPRuntimeDesiredKey{1},
				build: func(context.Context) (fakeTCPRuntimeService, error) { return runtime, nil },
			}, nil
		},
	)
	state := fakeTCPProductionTestState()
	if err := coordinator.Apply(t.Context(), state); err != nil {
		t.Fatal(err)
	}
	<-runtime.runStarted
	if err := coordinator.DetachStale(t.Context(), &control.State{}, state); err != nil {
		t.Fatal(err)
	}
	stopCalls, closeCalls, _ := runtime.counts()
	_, _, stale := baseline.counts()
	if stopCalls != 0 || closeCalls != 0 || stale != 0 ||
		shared.owner != dataplaneCoreOwnerExperimental {
		t.Fatalf(
			"experimental stale no-op: stop=%d close=%d stale=%d owner=%d",
			stopCalls, closeCalls, stale, shared.owner,
		)
	}
	if err := coordinator.Detach(t.Context(), state); err != nil {
		t.Fatal(err)
	}
}
