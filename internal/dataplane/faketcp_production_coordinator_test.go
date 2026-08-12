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

type fakeTCPProductionTestLifecycle struct {
	mu          sync.Mutex
	ensureCalls int
	stopCalls   int
	onStop      func()
}

func (lifecycle *fakeTCPProductionTestLifecycle) Ensure(
	context.Context,
	fakeTCPRuntimeDesiredKey,
	fakeTCPRuntimeBuild,
) error {
	lifecycle.mu.Lock()
	lifecycle.ensureCalls++
	lifecycle.mu.Unlock()
	return nil
}

func (lifecycle *fakeTCPProductionTestLifecycle) Stop(context.Context) error {
	lifecycle.mu.Lock()
	lifecycle.stopCalls++
	onStop := lifecycle.onStop
	lifecycle.mu.Unlock()
	if onStop != nil {
		onStop()
	}
	return nil
}

func (lifecycle *fakeTCPProductionTestLifecycle) setOnStop(onStop func()) {
	lifecycle.mu.Lock()
	lifecycle.onStop = onStop
	lifecycle.mu.Unlock()
}

func (lifecycle *fakeTCPProductionTestLifecycle) counts() (ensure, stop int) {
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	return lifecycle.ensureCalls, lifecycle.stopCalls
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

func fakeTCPProductionTestScope() fakeTCPProductionScopeIdentity {
	return fakeTCPProductionScopeIdentity{
		objectKind:                 fakeTCPProductionObjectScopeFilesystem,
		objectPath:                 "/test/wg-mix-ebpf/object.o",
		fakeTCPObjectPath:          EmbeddedFakeTCPObjectSource,
		fakeTCPLegacy515ObjectPath: EmbeddedFakeTCPLegacy515ObjectSource,
		pinPath:                    "/test/wg-mix-ebpf/pins",
		lifecyclePath:              "/test/wg-mix-ebpf/lifecycle.lease",
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
		resolveScope: func(context.Context) (fakeTCPProductionScopeIdentity, error) {
			return fakeTCPProductionTestScope(), nil
		},
		planExperimental: planner,
	}, shared
}

func newFakeTCPProductionTestCoordinatorWithScope(
	baseline AttachStateLoader,
	shared *fakeTCPProductionCoordinatorState,
	scope fakeTCPProductionScopeIdentity,
	gate fakeTCPActivationValidator,
	planner fakeTCPProductionPlanner,
) *fakeTCPProductionCoordinator {
	return &fakeTCPProductionCoordinator{
		baseline:           baseline,
		shared:             shared,
		validateActivation: gate,
		resolveScope: func(context.Context) (fakeTCPProductionScopeIdentity, error) {
			return scope, nil
		},
		planExperimental: planner,
	}
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
	differentScope := fakeTCPProductionTestScope()
	differentScope.pinPath = "/test/wg-mix-ebpf/different-baseline-owner-pins"
	differentBaseline := &fakeTCPProductionTestBaseline{}
	differentHandle := newFakeTCPProductionTestCoordinatorWithScope(
		differentBaseline,
		shared,
		differentScope,
		func(*control.State) error { return nil },
		nil,
	)
	if err := differentHandle.Apply(t.Context(), &control.State{}); !errors.Is(err, errFakeTCPProductionScopeMismatch) {
		t.Fatalf("different scope crossed baseline owner: %v", err)
	}
	if apply, detach, stale := differentBaseline.counts(); apply != 0 || detach != 0 || stale != 0 {
		t.Fatalf("different scope mutated baseline owner: %d/%d/%d", apply, detach, stale)
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
	if !shared.scopeBound || shared.scope != fakeTCPProductionTestScope() {
		t.Fatalf("canceled Apply lost its conservative scope: bound=%t scope=%#v", shared.scopeBound, shared.scope)
	}
	differentScope := fakeTCPProductionTestScope()
	differentScope.lifecyclePath = "/test/wg-mix-ebpf/different-canceled.lease"
	differentBaseline := &fakeTCPProductionTestBaseline{}
	differentHandle := newFakeTCPProductionTestCoordinatorWithScope(
		differentBaseline,
		shared,
		differentScope,
		func(*control.State) error { return nil },
		nil,
	)
	if err := differentHandle.Detach(t.Context(), nil); !errors.Is(err, errFakeTCPProductionScopeMismatch) {
		t.Fatalf("different scope crossed canceled owner: %v", err)
	}
	if _, detach, _ := differentBaseline.counts(); detach != 0 {
		t.Fatal("different scope detached after canceled Apply")
	}
}

func TestFakeTCPProductionCoordinatorDetachCancellationDoesNotUnbindScope(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	baseline := &fakeTCPProductionTestBaseline{}
	lifecycle := &fakeTCPProductionTestLifecycle{}
	shared := &fakeTCPProductionCoordinatorState{
		supervisor: lifecycle,
		owner:      dataplaneCoreOwnerUnknown,
	}
	coordinator := newFakeTCPProductionTestCoordinatorWithScope(
		baseline,
		shared,
		fakeTCPProductionTestScope(),
		func(*control.State) error { return nil },
		nil,
	)
	if err := coordinator.Apply(t.Context(), &control.State{}); err != nil {
		t.Fatal(err)
	}
	_, detachBefore, _ := baseline.counts()
	lifecycle.setOnStop(cancel)
	err := coordinator.Detach(ctx, &control.State{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Detach error = %v, want cancellation", err)
	}
	_, detachAfter, _ := baseline.counts()
	if detachAfter != detachBefore {
		t.Fatal("baseline Detach ran after cancellation at the Stop boundary")
	}
	if !shared.scopeBound || shared.scope != fakeTCPProductionTestScope() ||
		shared.owner != dataplaneCoreOwnerNone {
		t.Fatalf(
			"canceled Detach unbound scope: bound=%t scope=%#v owner=%d",
			shared.scopeBound, shared.scope, shared.owner,
		)
	}
	if err := coordinator.Detach(t.Context(), &control.State{}); err != nil {
		t.Fatal(err)
	}
	if shared.scopeBound {
		t.Fatal("complete retry retained scope")
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
	if !shared.scopeBound || shared.scope != fakeTCPProductionTestScope() {
		t.Fatalf("failed close lost its scope: bound=%t scope=%#v", shared.scopeBound, shared.scope)
	}
	differentScope := fakeTCPProductionTestScope()
	differentScope.objectPath = "/test/wg-mix-ebpf/different-close-owner.o"
	differentBaseline := &fakeTCPProductionTestBaseline{}
	differentHandle := newFakeTCPProductionTestCoordinatorWithScope(
		differentBaseline,
		shared,
		differentScope,
		func(*control.State) error { return nil },
		nil,
	)
	if err := differentHandle.Apply(t.Context(), &control.State{}); !errors.Is(err, errFakeTCPProductionScopeMismatch) {
		t.Fatalf("different scope crossed retained close owner: %v", err)
	}
	if apply, detach, stale := differentBaseline.counts(); apply != 0 || detach != 0 || stale != 0 {
		t.Fatalf("different scope mutated during close retry: %d/%d/%d", apply, detach, stale)
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
	if shared.scopeBound {
		t.Fatal("complete close retry and baseline detach retained scope")
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
	if stale != 0 || shared.owner != dataplaneCoreOwnerExperimental ||
		!shared.scopeBound || shared.scope != fakeTCPProductionTestScope() {
		t.Fatalf(
			"stale mutation crossed failed close: stale=%d owner=%d bound=%t scope=%#v",
			stale,
			shared.owner,
			shared.scopeBound,
			shared.scope,
		)
	}

	runtime.setCloseError(nil)
	if err := coordinator.DetachStale(t.Context(), fakeTCPProductionTestState(), &control.State{}); err != nil {
		t.Fatal(err)
	}
	_, _, stale = baseline.counts()
	_, closeCalls, _ := runtime.counts()
	if stale != 1 || closeCalls != 2 || shared.owner != dataplaneCoreOwnerBaseline ||
		!shared.scopeBound || shared.scope != fakeTCPProductionTestScope() {
		t.Fatalf(
			"stale close retry: stale=%d closes=%d owner=%d bound=%t scope=%#v",
			stale,
			closeCalls,
			shared.owner,
			shared.scopeBound,
			shared.scope,
		)
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
		shared.owner != dataplaneCoreOwnerExperimental || !shared.scopeBound ||
		shared.scope != fakeTCPProductionTestScope() {
		t.Fatalf(
			"experimental stale no-op: stop=%d close=%d stale=%d owner=%d bound=%t scope=%#v",
			stopCalls,
			closeCalls,
			stale,
			shared.owner,
			shared.scopeBound,
			shared.scope,
		)
	}
	if err := coordinator.Detach(t.Context(), state); err != nil {
		t.Fatal(err)
	}
}

func TestFakeTCPProductionCoordinatorRejectsEveryDifferentHandleScopeBeforeMutation(t *testing.T) {
	scopeA := fakeTCPProductionTestScope()
	tests := []struct {
		name   string
		scopeB fakeTCPProductionScopeIdentity
	}{
		{
			name: "object",
			scopeB: func() fakeTCPProductionScopeIdentity {
				scope := scopeA
				scope.objectPath = "/test/wg-mix-ebpf/other-object.o"
				return scope
			}(),
		},
		{
			name: "pin",
			scopeB: func() fakeTCPProductionScopeIdentity {
				scope := scopeA
				scope.pinPath = "/test/wg-mix-ebpf/other-pins"
				return scope
			}(),
		},
		{
			name: "lifecycle",
			scopeB: func() fakeTCPProductionScopeIdentity {
				scope := scopeA
				scope.lifecyclePath = "/test/wg-mix-ebpf/other-lifecycle.lease"
				return scope
			}(),
		},
		{
			name: "adopt-legacy-pins",
			scopeB: func() fakeTCPProductionScopeIdentity {
				scope := scopeA
				scope.adoptLegacyPins = true
				return scope
			}(),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime := newControlledFakeTCPRuntime()
			baselineA := &fakeTCPProductionTestBaseline{}
			baselineB := &fakeTCPProductionTestBaseline{}
			shared := &fakeTCPProductionCoordinatorState{
				supervisor: &fakeTCPRuntimeSupervisor{},
				owner:      dataplaneCoreOwnerUnknown,
			}
			handleA := newFakeTCPProductionTestCoordinatorWithScope(
				baselineA,
				shared,
				scopeA,
				func(*control.State) error { return nil },
				func(context.Context, *control.State) (*fakeTCPProductionPlan, error) {
					return &fakeTCPProductionPlan{
						key:   fakeTCPRuntimeDesiredKey{1},
						build: func(context.Context) (fakeTCPRuntimeService, error) { return runtime, nil },
					}, nil
				},
			)
			plannerBCalls := 0
			handleB := newFakeTCPProductionTestCoordinatorWithScope(
				baselineB,
				shared,
				test.scopeB,
				func(*control.State) error { return nil },
				func(context.Context, *control.State) (*fakeTCPProductionPlan, error) {
					plannerBCalls++
					return nil, errors.New("mismatched handle planner must not run")
				},
			)
			fakeState := fakeTCPProductionTestState()
			if err := handleA.Apply(t.Context(), fakeState); err != nil {
				t.Fatal(err)
			}
			<-runtime.runStarted
			applyA, detachA, staleA := baselineA.counts()

			operations := []struct {
				name string
				run  func() error
			}{
				{"apply-baseline", func() error { return handleB.Apply(t.Context(), &control.State{}) }},
				{"apply-experimental", func() error { return handleB.Apply(t.Context(), fakeState) }},
				{"detach", func() error { return handleB.Detach(t.Context(), fakeState) }},
				{"detach-stale", func() error {
					return handleB.DetachStale(t.Context(), fakeState, &control.State{})
				}},
			}
			for _, operation := range operations {
				err := operation.run()
				if !errors.Is(err, errFakeTCPProductionScopeMismatch) {
					t.Fatalf("%s error = %v, want scope mismatch", operation.name, err)
				}
			}

			if plannerBCalls != 0 {
				t.Fatalf("mismatched handle planner calls = %d", plannerBCalls)
			}
			if gotApply, gotDetach, gotStale := baselineA.counts(); gotApply != applyA || gotDetach != detachA || gotStale != staleA {
				t.Fatalf(
					"handle B touched baseline A: before=%d/%d/%d after=%d/%d/%d",
					applyA, detachA, staleA, gotApply, gotDetach, gotStale,
				)
			}
			if applyB, detachB, staleB := baselineB.counts(); applyB != 0 || detachB != 0 || staleB != 0 {
				t.Fatalf(
					"mismatched handle B mutated baseline: apply=%d detach=%d stale=%d",
					applyB, detachB, staleB,
				)
			}
			stopCalls, closeCalls, closeEarly := runtime.counts()
			if stopCalls != 0 || closeCalls != 0 || closeEarly {
				t.Fatalf(
					"mismatched handle B touched supervisor A: stop=%d close=%d early=%t",
					stopCalls, closeCalls, closeEarly,
				)
			}
			if !shared.scopeBound || shared.scope != scopeA ||
				shared.owner != dataplaneCoreOwnerExperimental {
				t.Fatalf(
					"retained A scope/owner changed: bound=%t scope=%#v owner=%d",
					shared.scopeBound, shared.scope, shared.owner,
				)
			}

			if err := handleA.Detach(t.Context(), fakeState); err != nil {
				t.Fatal(err)
			}
			if shared.scopeBound || shared.scope != (fakeTCPProductionScopeIdentity{}) ||
				shared.owner != dataplaneCoreOwnerNone {
				t.Fatalf(
					"complete A detach did not release scope: bound=%t scope=%#v owner=%d",
					shared.scopeBound, shared.scope, shared.owner,
				)
			}
			if err := handleB.Apply(t.Context(), &control.State{}); err != nil {
				t.Fatalf("handle B did not bind after complete A detach: %v", err)
			}
			if !shared.scopeBound || shared.scope != test.scopeB ||
				shared.owner != dataplaneCoreOwnerBaseline {
				t.Fatalf(
					"handle B scope/owner = bound=%t scope=%#v owner=%d",
					shared.scopeBound, shared.scope, shared.owner,
				)
			}
			if err := handleB.Detach(t.Context(), &control.State{}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFakeTCPProductionCoordinatorRejectsDifferentScopeAcrossRetainedOwnerStates(t *testing.T) {
	setupErr := errors.New("conservative setup failure")
	tests := []struct {
		name        string
		state       *control.State
		baselineErr error
		plannerErr  error
		wantOwner   dataplaneCoreOwner
	}{
		{
			name:       "bound-unknown-after-planning-error",
			state:      fakeTCPProductionTestState(),
			plannerErr: setupErr,
			wantOwner:  dataplaneCoreOwnerUnknown,
		},
		{
			name:      "baseline",
			state:     &control.State{},
			wantOwner: dataplaneCoreOwnerBaseline,
		},
		{
			name:      "experimental",
			state:     fakeTCPProductionTestState(),
			wantOwner: dataplaneCoreOwnerExperimental,
		},
		{
			name:        "conservative-baseline-after-apply-error",
			state:       &control.State{},
			baselineErr: setupErr,
			wantOwner:   dataplaneCoreOwnerBaseline,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scopeA := fakeTCPProductionTestScope()
			scopeB := scopeA
			scopeB.pinPath = "/test/wg-mix-ebpf/other-owner-state-pins"
			baselineA := &fakeTCPProductionTestBaseline{applyErr: test.baselineErr}
			baselineB := &fakeTCPProductionTestBaseline{}
			lifecycle := &fakeTCPProductionTestLifecycle{}
			shared := &fakeTCPProductionCoordinatorState{
				supervisor: lifecycle,
				owner:      dataplaneCoreOwnerUnknown,
			}
			handleA := newFakeTCPProductionTestCoordinatorWithScope(
				baselineA,
				shared,
				scopeA,
				func(*control.State) error { return nil },
				func(context.Context, *control.State) (*fakeTCPProductionPlan, error) {
					if test.plannerErr != nil {
						return nil, test.plannerErr
					}
					return &fakeTCPProductionPlan{
						key: fakeTCPRuntimeDesiredKey{1},
						build: func(context.Context) (fakeTCPRuntimeService, error) {
							return newControlledFakeTCPRuntime(), nil
						},
					}, nil
				},
			)
			setupResult := handleA.Apply(t.Context(), test.state)
			if test.baselineErr != nil || test.plannerErr != nil {
				if !errors.Is(setupResult, setupErr) {
					t.Fatalf("setup error = %v, want %v", setupResult, setupErr)
				}
			} else if setupResult != nil {
				t.Fatal(setupResult)
			}
			if !shared.scopeBound || shared.scope != scopeA || shared.owner != test.wantOwner {
				t.Fatalf(
					"setup owner = bound=%t scope=%#v owner=%d, want owner=%d",
					shared.scopeBound,
					shared.scope,
					shared.owner,
					test.wantOwner,
				)
			}

			plannerBCalls := 0
			handleB := newFakeTCPProductionTestCoordinatorWithScope(
				baselineB,
				shared,
				scopeB,
				func(*control.State) error { return nil },
				func(context.Context, *control.State) (*fakeTCPProductionPlan, error) {
					plannerBCalls++
					return nil, errors.New("mismatched planner must not run")
				},
			)
			applyA, detachA, staleA := baselineA.counts()
			ensureA, stopA := lifecycle.counts()
			operations := []struct {
				name string
				run  func() error
			}{
				{name: "apply-baseline", run: func() error {
					return handleB.Apply(t.Context(), &control.State{})
				}},
				{name: "apply-experimental", run: func() error {
					return handleB.Apply(t.Context(), fakeTCPProductionTestState())
				}},
				{name: "detach", run: func() error {
					return handleB.Detach(t.Context(), test.state)
				}},
				{name: "detach-stale", run: func() error {
					return handleB.DetachStale(t.Context(), test.state, &control.State{})
				}},
			}
			for _, operation := range operations {
				if err := operation.run(); !errors.Is(err, errFakeTCPProductionScopeMismatch) {
					t.Fatalf("%s error = %v, want scope mismatch", operation.name, err)
				}
			}
			if gotApply, gotDetach, gotStale := baselineA.counts(); gotApply != applyA || gotDetach != detachA || gotStale != staleA {
				t.Fatalf(
					"mismatched handle touched owner baseline: before=%d/%d/%d after=%d/%d/%d",
					applyA,
					detachA,
					staleA,
					gotApply,
					gotDetach,
					gotStale,
				)
			}
			if gotEnsure, gotStop := lifecycle.counts(); gotEnsure != ensureA || gotStop != stopA {
				t.Fatalf(
					"mismatched handle touched owner lifecycle: before=%d/%d after=%d/%d",
					ensureA,
					stopA,
					gotEnsure,
					gotStop,
				)
			}
			if applyB, detachB, staleB := baselineB.counts(); applyB != 0 || detachB != 0 || staleB != 0 || plannerBCalls != 0 {
				t.Fatalf(
					"mismatched handle mutated: baseline=%d/%d/%d planner=%d",
					applyB,
					detachB,
					staleB,
					plannerBCalls,
				)
			}
			if !shared.scopeBound || shared.scope != scopeA || shared.owner != test.wantOwner {
				t.Fatal("mismatched operations changed the retained owner identity")
			}

			baselineA.applyErr = nil
			if err := handleA.Detach(t.Context(), test.state); err != nil {
				t.Fatalf("same-scope full detach: %v", err)
			}
			if shared.scopeBound {
				t.Fatal("same-scope full detach retained scope")
			}
			if err := handleB.Apply(t.Context(), &control.State{}); err != nil {
				t.Fatalf("new scope could not bind after full detach: %v", err)
			}
			if err := handleB.Detach(t.Context(), &control.State{}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFakeTCPProductionCoordinatorScopeResolutionFailsBeforeEveryMutation(t *testing.T) {
	scopeErr := errors.New("scope resolution failed")
	tests := []struct {
		name       string
		wantEvents []string
		run        func(*fakeTCPProductionCoordinator) error
	}{
		{
			name:       "apply-baseline",
			wantEvents: []string{"gate", "scope"},
			run: func(coordinator *fakeTCPProductionCoordinator) error {
				return coordinator.Apply(t.Context(), &control.State{})
			},
		},
		{
			name:       "apply-experimental",
			wantEvents: []string{"gate", "scope"},
			run: func(coordinator *fakeTCPProductionCoordinator) error {
				return coordinator.Apply(t.Context(), fakeTCPProductionTestState())
			},
		},
		{
			name:       "detach",
			wantEvents: []string{"scope"},
			run: func(coordinator *fakeTCPProductionCoordinator) error {
				return coordinator.Detach(t.Context(), &control.State{})
			},
		},
		{
			name:       "detach-stale",
			wantEvents: []string{"gate", "scope"},
			run: func(coordinator *fakeTCPProductionCoordinator) error {
				return coordinator.DetachStale(t.Context(), &control.State{}, &control.State{})
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			events := &fakeTCPProductionTestEvents{}
			baseline := &fakeTCPProductionTestBaseline{events: events}
			lifecycle := &fakeTCPProductionTestLifecycle{}
			plannerCalls := 0
			shared := &fakeTCPProductionCoordinatorState{
				supervisor: lifecycle,
				owner:      dataplaneCoreOwnerUnknown,
			}
			coordinator := &fakeTCPProductionCoordinator{
				baseline: baseline,
				shared:   shared,
				validateActivation: func(*control.State) error {
					events.add("gate")
					return nil
				},
				resolveScope: func(context.Context) (fakeTCPProductionScopeIdentity, error) {
					events.add("scope")
					return fakeTCPProductionScopeIdentity{}, scopeErr
				},
				planExperimental: func(context.Context, *control.State) (*fakeTCPProductionPlan, error) {
					plannerCalls++
					return nil, errors.New("planner must not run")
				},
			}
			err := test.run(coordinator)
			if !errors.Is(err, scopeErr) {
				t.Fatalf("operation error = %v, want scope error", err)
			}
			if got := events.snapshot(); !reflect.DeepEqual(got, test.wantEvents) {
				t.Fatalf("operation order = %q, want %q", got, test.wantEvents)
			}
			apply, detach, stale := baseline.counts()
			ensure, stop := lifecycle.counts()
			if apply != 0 || detach != 0 || stale != 0 || ensure != 0 || stop != 0 ||
				plannerCalls != 0 {
				t.Fatalf(
					"scope failure mutated: baseline=%d/%d/%d lifecycle=%d/%d planner=%d",
					apply, detach, stale, ensure, stop, plannerCalls,
				)
			}
			if shared.scopeBound || shared.owner != dataplaneCoreOwnerUnknown {
				t.Fatalf("scope failure bound state: bound=%t owner=%d", shared.scopeBound, shared.owner)
			}
		})
	}
}

func TestFakeTCPProductionCoordinatorScopeResolutionFailureRetainsActiveBinding(t *testing.T) {
	scopeErr := errors.New("active scope resolution failed")
	boundScope := fakeTCPProductionTestScope()
	baseline := &fakeTCPProductionTestBaseline{}
	lifecycle := &fakeTCPProductionTestLifecycle{}
	plannerCalls := 0
	shared := &fakeTCPProductionCoordinatorState{
		supervisor: lifecycle,
		owner:      dataplaneCoreOwnerExperimental,
		scope:      boundScope,
		scopeBound: true,
	}
	coordinator := &fakeTCPProductionCoordinator{
		baseline: baseline,
		shared:   shared,
		validateActivation: func(*control.State) error {
			return nil
		},
		resolveScope: func(context.Context) (fakeTCPProductionScopeIdentity, error) {
			return fakeTCPProductionScopeIdentity{}, scopeErr
		},
		planExperimental: func(context.Context, *control.State) (*fakeTCPProductionPlan, error) {
			plannerCalls++
			return nil, errors.New("planner must not run")
		},
	}
	operations := []struct {
		name string
		run  func() error
	}{
		{name: "apply-baseline", run: func() error {
			return coordinator.Apply(t.Context(), &control.State{})
		}},
		{name: "apply-experimental", run: func() error {
			return coordinator.Apply(t.Context(), fakeTCPProductionTestState())
		}},
		{name: "detach", run: func() error {
			return coordinator.Detach(t.Context(), &control.State{})
		}},
		{name: "detach-stale", run: func() error {
			return coordinator.DetachStale(t.Context(), &control.State{}, &control.State{})
		}},
	}
	for _, operation := range operations {
		if err := operation.run(); !errors.Is(err, scopeErr) {
			t.Fatalf("%s error = %v, want resolver error", operation.name, err)
		}
	}
	apply, detach, stale := baseline.counts()
	ensure, stop := lifecycle.counts()
	if apply != 0 || detach != 0 || stale != 0 || ensure != 0 || stop != 0 ||
		plannerCalls != 0 {
		t.Fatalf(
			"active resolver failure mutated: baseline=%d/%d/%d lifecycle=%d/%d planner=%d",
			apply,
			detach,
			stale,
			ensure,
			stop,
			plannerCalls,
		)
	}
	if !shared.scopeBound || shared.scope != boundScope ||
		shared.owner != dataplaneCoreOwnerExperimental {
		t.Fatalf(
			"resolver failure changed active binding: bound=%t scope=%#v owner=%d",
			shared.scopeBound,
			shared.scope,
			shared.owner,
		)
	}
}

func TestFakeTCPProductionCoordinatorReconcileHandlesShareExactScope(t *testing.T) {
	shared := &fakeTCPProductionCoordinatorState{
		supervisor: &fakeTCPRuntimeSupervisor{},
		owner:      dataplaneCoreOwnerUnknown,
	}
	scope := fakeTCPProductionTestScope()
	applyBaseline := &fakeTCPProductionTestBaseline{}
	staleBaseline := &fakeTCPProductionTestBaseline{}
	applyHandle := newFakeTCPProductionTestCoordinatorWithScope(
		applyBaseline,
		shared,
		scope,
		func(*control.State) error { return nil },
		nil,
	)
	staleHandle := newFakeTCPProductionTestCoordinatorWithScope(
		staleBaseline,
		shared,
		scope,
		func(*control.State) error { return nil },
		nil,
	)
	state := &control.State{}
	if err := applyHandle.Apply(t.Context(), state); err != nil {
		t.Fatal(err)
	}
	if err := staleHandle.DetachStale(t.Context(), &control.State{}, state); err != nil {
		t.Fatal(err)
	}
	apply, _, _ := applyBaseline.counts()
	_, _, stale := staleBaseline.counts()
	if apply != 1 || stale != 1 || !shared.scopeBound || shared.scope != scope ||
		shared.owner != dataplaneCoreOwnerBaseline {
		t.Fatalf(
			"same-scope reconcile: apply=%d stale=%d bound=%t scope=%#v owner=%d",
			apply, stale, shared.scopeBound, shared.scope, shared.owner,
		)
	}
	if err := staleHandle.Detach(t.Context(), state); err != nil {
		t.Fatal(err)
	}
}

func TestFakeTCPProductionCoordinatorSameObjectPathContentChangeUsesDesiredKey(t *testing.T) {
	scope := fakeTCPProductionTestScope()
	shared := &fakeTCPProductionCoordinatorState{
		supervisor: &fakeTCPRuntimeSupervisor{},
		owner:      dataplaneCoreOwnerUnknown,
	}
	firstRuntime := newControlledFakeTCPRuntime()
	first := newFakeTCPProductionTestCoordinatorWithScope(
		&fakeTCPProductionTestBaseline{},
		shared,
		scope,
		func(*control.State) error { return nil },
		func(context.Context, *control.State) (*fakeTCPProductionPlan, error) {
			// Model desired key material that includes object content digest A.
			return &fakeTCPProductionPlan{
				key:   fakeTCPRuntimeDesiredKey{1},
				build: func(context.Context) (fakeTCPRuntimeService, error) { return firstRuntime, nil },
			}, nil
		},
	)
	secondBuilds := 0
	secondRuntime := newControlledFakeTCPRuntime()
	second := newFakeTCPProductionTestCoordinatorWithScope(
		&fakeTCPProductionTestBaseline{},
		shared,
		scope,
		func(*control.State) error { return nil },
		func(context.Context, *control.State) (*fakeTCPProductionPlan, error) {
			// The path scope is unchanged, but digest B changes the desired key.
			return &fakeTCPProductionPlan{
				key: fakeTCPRuntimeDesiredKey{2},
				build: func(context.Context) (fakeTCPRuntimeService, error) {
					secondBuilds++
					return secondRuntime, nil
				},
			}, nil
		},
	)
	state := fakeTCPProductionTestState()
	if err := first.Apply(t.Context(), state); err != nil {
		t.Fatal(err)
	}
	<-firstRuntime.runStarted
	if err := second.Apply(t.Context(), state); err != nil {
		t.Fatalf("same-path content replacement: %v", err)
	}
	<-secondRuntime.runStarted
	if secondBuilds != 1 || !shared.scopeBound || shared.scope != scope ||
		shared.owner != dataplaneCoreOwnerExperimental {
		t.Fatalf(
			"same-path desired-key fence: builds=%d bound=%t scope=%#v owner=%d",
			secondBuilds, shared.scopeBound, shared.scope, shared.owner,
		)
	}
	stopCalls, closeCalls, _ := firstRuntime.counts()
	if stopCalls != 1 || closeCalls != 1 {
		t.Fatal("same-path desired-key replacement did not retire the active runtime")
	}
	if err := first.Detach(t.Context(), state); err != nil {
		t.Fatal(err)
	}
}
