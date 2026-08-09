//go:build linux

package dataplane

import (
	"context"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/syx0310/wg-mix-ebpf/internal/control"
	"github.com/syx0310/wg-mix-ebpf/internal/lockfile"
)

var errExperimentalFakeTCPProductionRequestUnavailable = errors.New(
	"experimental FakeTCP production request requires live lifecycle and generation-isolation planning",
)

// experimentalFakeTCPProductionRequest is the complete, still-unclaimed input
// to the acquisition/runtime factory. The coordinator owns rollback until it
// invokes factory; factory then consumes buildOptions.transaction at entry.
type experimentalFakeTCPProductionRequest struct {
	key          fakeTCPRuntimeDesiredKey
	spec         *ebpf.CollectionSpec
	source       string
	dependencies experimentalCollectionAcquisitionDependencies
	buildOptions experimentalFakeTCPRuntimeBuildOptions
	rollback     func() error
}

type experimentalFakeTCPProductionRequestBuilder func(
	context.Context,
	*control.State,
	LinuxLoader,
) (*experimentalFakeTCPProductionRequest, error)

type experimentalFakeTCPProductionFactory func(
	context.Context,
	*experimentalFakeTCPProductionRequest,
) (fakeTCPRuntimeService, error)

var liveFakeTCPProductionCoordinatorState = &fakeTCPProductionCoordinatorState{
	supervisor: &fakeTCPRuntimeSupervisor{},
	owner:      dataplaneCoreOwnerUnknown,
}

func newFakeTCPProductionLoader(baseline LinuxLoader) Loader {
	// Freeze both environment-backed selectors in the handle. Scope resolution
	// and every later baseline operation now use these exact values even if a
	// process mutates its environment between reconcile phases.
	baseline.ObjectPath = baseline.effectiveObjectPath()
	baseline.objectPathFrozen = true
	baseline.PinPath = pinPathFromEnv(baseline.PinPath)
	return &fakeTCPProductionCoordinator{
		baseline:           baseline,
		shared:             liveFakeTCPProductionCoordinatorState,
		validateActivation: ValidateFakeTCPActivation,
		resolveScope: func(ctx context.Context) (fakeTCPProductionScopeIdentity, error) {
			return resolveLinuxFakeTCPProductionScope(ctx, baseline)
		},
		planExperimental: composeExperimentalFakeTCPProductionPlanner(
			baseline,
			buildLiveExperimentalFakeTCPProductionRequest,
			acquireExperimentalFakeTCPProductionRuntime,
		),
	}
}

func resolveLinuxFakeTCPProductionScope(
	ctx context.Context,
	baseline LinuxLoader,
) (fakeTCPProductionScopeIdentity, error) {
	if ctx == nil {
		return fakeTCPProductionScopeIdentity{}, errors.New(
			"resolve Linux production dataplane scope: context is nil",
		)
	}
	objectPath := baseline.effectiveObjectPath()
	objectKind := fakeTCPProductionObjectScopeFilesystem
	if objectPath == "" {
		objectKind = fakeTCPProductionObjectScopeEmbedded
		objectPath = EmbeddedObjectSource
	} else {
		var err error
		objectPath, err = canonicalFakeTCPProductionPath("object", objectPath)
		if err != nil {
			return fakeTCPProductionScopeIdentity{}, err
		}
	}
	pinPath, err := canonicalFakeTCPProductionPath(
		"pin",
		pinPathFromEnv(baseline.PinPath),
	)
	if err != nil {
		return fakeTCPProductionScopeIdentity{}, err
	}
	lifecyclePath, err := canonicalFakeTCPProductionPath(
		"lifecycle lease",
		lockfile.LifecycleLeasePath(ctx),
	)
	if err != nil {
		return fakeTCPProductionScopeIdentity{}, err
	}
	return fakeTCPProductionScopeIdentity{
		objectKind:      objectKind,
		objectPath:      objectPath,
		pinPath:         pinPath,
		lifecyclePath:   lifecyclePath,
		adoptLegacyPins: baseline.AdoptLegacyPins,
	}, nil
}

// composeExperimentalFakeTCPProductionPlanner keeps request construction and
// the ownership-consuming factory injectable. Production NewLoader supplies
// the live request builder and the sole adapter that may call
// acquireAndBuildExperimentalFakeTCPRuntime; unit tests can replace both
// without loading BPF or changing network state.
func composeExperimentalFakeTCPProductionPlanner(
	baseline LinuxLoader,
	buildRequest experimentalFakeTCPProductionRequestBuilder,
	factory experimentalFakeTCPProductionFactory,
) fakeTCPProductionPlanner {
	return func(
		ctx context.Context,
		state *control.State,
	) (*fakeTCPProductionPlan, error) {
		if buildRequest == nil {
			return nil, errors.New("production experimental FakeTCP request builder is nil")
		}
		if factory == nil {
			return nil, errors.New("production experimental FakeTCP runtime factory is nil")
		}
		request, err := buildRequest(ctx, state, baseline)
		if err != nil {
			return nil, err
		}
		if request == nil {
			return nil, errors.New("production experimental FakeTCP request builder returned nil")
		}
		return &fakeTCPProductionPlan{
			key: request.key,
			build: func(buildCtx context.Context) (fakeTCPRuntimeService, error) {
				return factory(buildCtx, request)
			},
			rollback: request.rollbackUnclaimed,
		}, nil
	}
}

// acquireExperimentalFakeTCPProductionRuntime is the sole production adapter
// to the ownership-consuming factory. Keeping this call out of LinuxLoader and
// daemon/reconcile code makes the coordinator's gate and mutual-exclusion
// protocol mandatory for production activation.
func acquireExperimentalFakeTCPProductionRuntime(
	ctx context.Context,
	request *experimentalFakeTCPProductionRequest,
) (fakeTCPRuntimeService, error) {
	if request == nil {
		return nil, errors.New("acquire production experimental FakeTCP runtime: request is nil")
	}
	return acquireAndBuildExperimentalFakeTCPRuntime(
		ctx,
		request.spec,
		request.source,
		request.dependencies,
		request.buildOptions,
	)
}

func (request *experimentalFakeTCPProductionRequest) rollbackUnclaimed() error {
	if request == nil {
		return nil
	}
	var rollbackErr error
	if request.rollback != nil {
		rollback := request.rollback
		request.rollback = nil
		rollbackErr = rollback()
	}
	transaction := request.buildOptions.transaction
	request.buildOptions.transaction = nil
	if transaction != nil && !transaction.isClosed() {
		rollbackErr = errors.Join(
			rollbackErr,
			wrapNonNilError(
				"close unclaimed experimental FakeTCP generation transaction",
				transaction.Close(),
			),
		)
	}
	return rollbackErr
}

// buildLiveExperimentalFakeTCPProductionRequest deliberately remains
// fail-closed while the capability gate is incomplete. This seam is where a
// later capability-complete change must bind the retained lifecycle lease,
// generation-isolation backend, canonical snapshots, and attach requests.
// Keeping the failure in the read-only planning phase means an accidental gate
// change still cannot detach the baseline or reach the factory.
func buildLiveExperimentalFakeTCPProductionRequest(
	ctx context.Context,
	state *control.State,
	baseline LinuxLoader,
) (*experimentalFakeTCPProductionRequest, error) {
	if ctx == nil {
		return nil, errors.New("plan live experimental FakeTCP runtime: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if state == nil {
		return nil, errors.New("plan live experimental FakeTCP runtime: state is nil")
	}
	if len(fakeTCPStateReferences(state)) == 0 {
		return nil, errors.New("plan live experimental FakeTCP runtime: state has no FakeTCP reference")
	}
	return nil, fmt.Errorf(
		"plan live experimental FakeTCP runtime for baseline object %q: %w",
		baseline.ObjectPath,
		errExperimentalFakeTCPProductionRequestUnavailable,
	)
}
