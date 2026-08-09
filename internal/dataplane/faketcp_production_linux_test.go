//go:build linux

package dataplane

import (
	"context"
	"errors"
	"testing"

	"github.com/syx0310/wg-mix-ebpf/internal/control"
)

func TestNewLoaderReturnsSharedFakeTCPProductionCoordinator(t *testing.T) {
	first, ok := NewLoaderWithOptions(LoaderOptions{}).(*fakeTCPProductionCoordinator)
	if !ok {
		t.Fatalf("NewLoaderWithOptions returned %T, want production coordinator", NewLoaderWithOptions(LoaderOptions{}))
	}
	second, ok := NewLoader().(*fakeTCPProductionCoordinator)
	if !ok {
		t.Fatalf("NewLoader returned %T, want production coordinator", NewLoader())
	}
	if first.shared == nil || first.shared != second.shared ||
		first.shared != liveFakeTCPProductionCoordinatorState {
		t.Fatal("production Loader handles do not share one process runtime owner")
	}
	if _, ok := first.baseline.(LinuxLoader); !ok {
		t.Fatalf("coordinator baseline = %T, want LinuxLoader", first.baseline)
	}
	if first.validateActivation == nil || first.planExperimental == nil {
		t.Fatal("production coordinator dependencies are incomplete")
	}
}

func TestNewLoaderCoordinatorGatesBeforeInvalidBaselinePinPath(t *testing.T) {
	t.Setenv(EnvPinPath, "relative-path-must-not-be-touched")
	t.Setenv(EnvObjectPath, "object-must-not-be-opened")
	err := NewLoader().Apply(t.Context(), fakeTCPProductionTestState())
	if !errors.Is(err, ErrFakeTCPKernelGate) {
		t.Fatalf("production coordinator did not fail at the pre-mutation gate: %v", err)
	}
}

func TestExperimentalProductionPlannerInjectsRequestAndFactory(t *testing.T) {
	request := &experimentalFakeTCPProductionRequest{key: fakeTCPRuntimeDesiredKey{7}}
	runtime := newControlledFakeTCPRuntime()
	baseline := LinuxLoader{ObjectPath: "/baseline-test.o", PinPath: "/baseline-test"}
	requestCalls := 0
	factoryCalls := 0
	planner := composeExperimentalFakeTCPProductionPlanner(
		baseline,
		func(
			_ context.Context,
			_ *control.State,
			got LinuxLoader,
		) (*experimentalFakeTCPProductionRequest, error) {
			requestCalls++
			if got.ObjectPath != baseline.ObjectPath || got.PinPath != baseline.PinPath {
				t.Fatalf("request builder baseline = %#v, want %#v", got, baseline)
			}
			return request, nil
		},
		func(
			_ context.Context,
			got *experimentalFakeTCPProductionRequest,
		) (fakeTCPRuntimeService, error) {
			factoryCalls++
			if got != request {
				t.Fatal("factory received a copied or unrelated request")
			}
			return runtime, nil
		},
	)

	plan, err := planner(t.Context(), fakeTCPProductionTestState())
	if err != nil {
		t.Fatal(err)
	}
	if plan == nil || plan.key != request.key || plan.build == nil || plan.rollback == nil {
		t.Fatalf("composed production plan is incomplete: %#v", plan)
	}
	gotRuntime, err := plan.build(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if gotRuntime != runtime || requestCalls != 1 || factoryCalls != 1 {
		t.Fatalf(
			"injected production path: runtime=%T request calls=%d factory calls=%d",
			gotRuntime, requestCalls, factoryCalls,
		)
	}
}

func TestLiveExperimentalProductionPlanningRemainsPreMutationFailClosed(t *testing.T) {
	baseline := &fakeTCPProductionTestBaseline{}
	coordinator := &fakeTCPProductionCoordinator{
		baseline: baseline,
		shared: &fakeTCPProductionCoordinatorState{
			supervisor: &fakeTCPRuntimeSupervisor{},
			owner:      dataplaneCoreOwnerUnknown,
		},
		// Model a future gate opening without silently making the incomplete
		// request planner attachable.
		validateActivation: func(*control.State) error { return nil },
		planExperimental: composeExperimentalFakeTCPProductionPlanner(
			LinuxLoader{ObjectPath: "/experimental-planning-test.o"},
			buildLiveExperimentalFakeTCPProductionRequest,
			func(
				context.Context,
				*experimentalFakeTCPProductionRequest,
			) (fakeTCPRuntimeService, error) {
				t.Fatal("live factory ran without lifecycle/isolation request planning")
				return nil, nil
			},
		),
	}

	err := coordinator.Apply(t.Context(), fakeTCPProductionTestState())
	if !errors.Is(err, errExperimentalFakeTCPProductionRequestUnavailable) {
		t.Fatalf("Apply error = %v, want incomplete live planning error", err)
	}
	apply, detach, stale := baseline.counts()
	if apply != 0 || detach != 0 || stale != 0 {
		t.Fatalf("live planning failure mutated baseline: apply=%d detach=%d stale=%d", apply, detach, stale)
	}
}
