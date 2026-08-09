package dataplane

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/syx0310/wg-mix-ebpf/internal/control"
)

// dataplaneCoreOwner records the coordinator's conservative ownership view.
// It never represents baseline and experimental ownership at the same time.
// Unknown is used on process startup because a durable baseline owner may
// predate this process; transitions therefore still perform an explicit
// detach before starting the experimental core.
type dataplaneCoreOwner uint8

const (
	dataplaneCoreOwnerUnknown dataplaneCoreOwner = iota
	dataplaneCoreOwnerNone
	dataplaneCoreOwnerBaseline
	dataplaneCoreOwnerExperimental
)

type fakeTCPProductionPlan struct {
	key      fakeTCPRuntimeDesiredKey
	build    fakeTCPRuntimeBuild
	rollback func() error
}

// fakeTCPProductionPlanner must be read-only. It may reserve userspace
// capabilities for one prospective build, but it must not load or attach BPF,
// mutate maps, or change network state. If build is never called, rollback is
// called exactly once before Apply returns.
type fakeTCPProductionPlanner func(
	context.Context,
	*control.State,
) (*fakeTCPProductionPlan, error)

type fakeTCPActivationValidator func(*control.State) error

type fakeTCPRuntimeLifecycle interface {
	Ensure(context.Context, fakeTCPRuntimeDesiredKey, fakeTCPRuntimeBuild) error
	Stop(context.Context) error
}

// fakeTCPProductionCoordinatorState is shared by every production Loader
// handle in a process. Reconcile constructs a new Loader on each pass, while
// an experimental userspace runtime must remain reachable until a later
// reload or stop. The shared operation lock also prevents a baseline mutation
// from overlapping an experimental start or teardown.
type fakeTCPProductionCoordinatorState struct {
	operationMu sync.Mutex
	supervisor  fakeTCPRuntimeLifecycle
	owner       dataplaneCoreOwner
}

// fakeTCPProductionCoordinator is the production Loader boundary. Baseline
// and experimental cores are mutually exclusive: an experimental start first
// detaches the baseline owner, while a baseline apply first stops and closes
// every experimental owner (including a quarantined close-retry owner).
type fakeTCPProductionCoordinator struct {
	baseline           AttachStateLoader
	shared             *fakeTCPProductionCoordinatorState
	validateActivation fakeTCPActivationValidator
	planExperimental   fakeTCPProductionPlanner
}

var _ AttachStateLoader = (*fakeTCPProductionCoordinator)(nil)

func (coordinator *fakeTCPProductionCoordinator) Apply(
	ctx context.Context,
	state *control.State,
) error {
	if coordinator == nil {
		return errors.New("production dataplane coordinator is nil")
	}
	if ctx == nil {
		return errors.New("apply context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if state == nil {
		return errors.New("apply control state is nil")
	}
	if coordinator.shared == nil || coordinator.shared.supervisor == nil {
		return errors.New("production dataplane coordinator state is incomplete")
	}
	if coordinator.baseline == nil {
		return errors.New("production baseline dataplane loader is nil")
	}
	if coordinator.validateActivation == nil {
		return errors.New("production FakeTCP activation gate is nil")
	}

	shared := coordinator.shared
	shared.operationMu.Lock()
	defer shared.operationMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}

	// This is the first state-dependent action under the production mutation
	// lock. In particular, neither baseline Stop/Apply/Detach nor experimental
	// planning/building can run before the hard capability gate.
	if err := coordinator.validateActivation(state); err != nil {
		return err
	}
	if len(fakeTCPStateReferences(state)) == 0 {
		return coordinator.applyBaselineLocked(ctx, state)
	}
	return coordinator.applyExperimentalLocked(ctx, state)
}

func (coordinator *fakeTCPProductionCoordinator) applyBaselineLocked(
	ctx context.Context,
	state *control.State,
) error {
	shared := coordinator.shared
	if err := shared.supervisor.Stop(ctx); err != nil {
		// Stop retains the runtime on every failed Close, so no baseline mutation
		// may begin until a later retry releases that exact owner.
		shared.owner = dataplaneCoreOwnerExperimental
		return fmt.Errorf("stop experimental core before baseline apply: %w", err)
	}
	shared.owner = dataplaneCoreOwnerNone
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := coordinator.baseline.Apply(ctx, state); err != nil {
		// Baseline Apply is transactional and may have restored a prior durable
		// generation. Keep the conservative owner instead of claiming none.
		shared.owner = dataplaneCoreOwnerBaseline
		return err
	}
	shared.owner = dataplaneCoreOwnerBaseline
	return nil
}

func (coordinator *fakeTCPProductionCoordinator) applyExperimentalLocked(
	ctx context.Context,
	state *control.State,
) (returnErr error) {
	if coordinator.planExperimental == nil {
		return errors.New("production experimental FakeTCP planner is nil")
	}
	plan, err := coordinator.planExperimental(ctx, state)
	if err != nil {
		return fmt.Errorf("plan experimental FakeTCP runtime: %w", err)
	}
	if plan == nil {
		return errors.New("plan experimental FakeTCP runtime: planner returned nil")
	}
	buildClaimed := false
	defer func() {
		if buildClaimed || plan.rollback == nil {
			return
		}
		rollback := plan.rollback
		plan.rollback = nil
		if err := rollback(); err != nil {
			returnErr = errors.Join(
				returnErr,
				fmt.Errorf("rollback unclaimed experimental FakeTCP production plan: %w", err),
			)
		}
	}()

	if plan.key == (fakeTCPRuntimeDesiredKey{}) {
		return errors.New("plan experimental FakeTCP runtime: desired key is empty")
	}
	if plan.build == nil {
		return errors.New("plan experimental FakeTCP runtime: builder is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	// A baseline owner may have been created by an earlier process, so this is
	// deliberately unconditional instead of relying only on the in-memory
	// owner enum. Detach is idempotent for an absent baseline owner.
	if err := coordinator.baseline.Detach(ctx, state); err != nil {
		coordinator.shared.owner = dataplaneCoreOwnerBaseline
		return fmt.Errorf("detach baseline core before experimental start: %w", err)
	}
	coordinator.shared.owner = dataplaneCoreOwnerNone
	if err := ctx.Err(); err != nil {
		return err
	}

	err = coordinator.shared.supervisor.Ensure(
		ctx,
		plan.key,
		func(buildCtx context.Context) (fakeTCPRuntimeService, error) {
			// From this point the builder owns every capability reserved by the
			// plan, including cleanup on failure. The coordinator must not race
			// it through the unclaimed-plan rollback path.
			buildClaimed = true
			return plan.build(buildCtx)
		},
	)
	if err != nil {
		// Ensure may retain a failed-build or failed-close runtime as the sole
		// retry capability. Conservatively exclude the baseline until Stop
		// proves that no such owner remains.
		coordinator.shared.owner = dataplaneCoreOwnerExperimental
		return err
	}
	coordinator.shared.owner = dataplaneCoreOwnerExperimental
	return nil
}

func (coordinator *fakeTCPProductionCoordinator) Detach(
	ctx context.Context,
	state *control.State,
) error {
	if coordinator == nil {
		return errors.New("production dataplane coordinator is nil")
	}
	if ctx == nil {
		return errors.New("detach context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if coordinator.shared == nil || coordinator.shared.supervisor == nil {
		return errors.New("production dataplane coordinator state is incomplete")
	}
	if coordinator.baseline == nil {
		return errors.New("production baseline dataplane loader is nil")
	}

	shared := coordinator.shared
	shared.operationMu.Lock()
	defer shared.operationMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := shared.supervisor.Stop(ctx); err != nil {
		shared.owner = dataplaneCoreOwnerExperimental
		return fmt.Errorf("stop experimental core before baseline detach: %w", err)
	}
	shared.owner = dataplaneCoreOwnerNone
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := coordinator.baseline.Detach(ctx, state); err != nil {
		shared.owner = dataplaneCoreOwnerBaseline
		return err
	}
	shared.owner = dataplaneCoreOwnerNone
	return nil
}

func (coordinator *fakeTCPProductionCoordinator) DetachStale(
	ctx context.Context,
	previous *control.State,
	current *control.State,
) error {
	if coordinator == nil {
		return errors.New("production dataplane coordinator is nil")
	}
	if ctx == nil {
		return errors.New("detach stale context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if current == nil {
		return errors.New("detach stale current control state is nil")
	}
	if coordinator.shared == nil || coordinator.baseline == nil {
		return errors.New("production dataplane coordinator is incomplete")
	}
	if coordinator.validateActivation == nil {
		return errors.New("production FakeTCP activation gate is nil")
	}

	shared := coordinator.shared
	shared.operationMu.Lock()
	defer shared.operationMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	// DetachStale is part of Apply orchestration and can mutate baseline TCX
	// state, so it observes the same gate-before-mutation rule.
	if err := coordinator.validateActivation(current); err != nil {
		return err
	}
	if len(fakeTCPStateReferences(current)) != 0 {
		// The experimental factory owns its complete canonical TC/XDP set; the
		// baseline compatibility hook must never touch it.
		return nil
	}
	if shared.supervisor == nil {
		return errors.New("production dataplane coordinator runtime supervisor is nil")
	}
	if err := shared.supervisor.Stop(ctx); err != nil {
		shared.owner = dataplaneCoreOwnerExperimental
		return fmt.Errorf("stop experimental core before baseline stale detach: %w", err)
	}
	shared.owner = dataplaneCoreOwnerNone
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := coordinator.baseline.DetachStale(ctx, previous, current); err != nil {
		// The current baseline generation may still be active even when pruning a
		// stale attachment fails, so retain the conservative baseline owner.
		shared.owner = dataplaneCoreOwnerBaseline
		return err
	}
	shared.owner = dataplaneCoreOwnerBaseline
	return nil
}
