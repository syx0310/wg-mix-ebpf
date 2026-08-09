//go:build linux

package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/syx0310/wg-mix-ebpf/internal/control"
	"github.com/syx0310/wg-mix-ebpf/internal/lockfile"
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

func TestResolveLinuxFakeTCPProductionScopeIncludesEveryOwnershipSelector(t *testing.T) {
	root := fakeTCPProductionRealTempDir(t)
	objectPath := filepath.Join(root, "objects", "wg_mix_tc.o")
	if err := os.MkdirAll(filepath.Dir(objectPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(objectPath, []byte("object generation A"), 0o600); err != nil {
		t.Fatal(err)
	}
	pinPath := filepath.Join(root, "pins", "production")
	lifecyclePath := filepath.Join(root, "leases", "daemon.lease")
	maintenancePath := filepath.Join(root, "leases", "maintenance.lock")
	ctx := lockfile.WithLifecyclePathsForTest(
		t.Context(),
		lifecyclePath,
		maintenancePath,
	)
	baseline := LinuxLoader{
		ObjectPath:       objectPath,
		PinPath:          pinPath,
		AdoptLegacyPins:  true,
		objectPathFrozen: true,
	}

	got, err := resolveLinuxFakeTCPProductionScope(ctx, baseline)
	if err != nil {
		t.Fatal(err)
	}
	want := fakeTCPProductionScopeIdentity{
		objectKind:      fakeTCPProductionObjectScopeFilesystem,
		objectPath:      objectPath,
		pinPath:         pinPath,
		lifecyclePath:   lifecyclePath,
		adoptLegacyPins: true,
	}
	if got != want {
		t.Fatalf("resolved scope = %#v, want %#v", got, want)
	}
	if err := got.validate(); err != nil {
		t.Fatalf("resolved scope is invalid: %v", err)
	}

	otherLifecyclePath := filepath.Join(root, "leases", "other-daemon.lease")
	otherContext := lockfile.WithLifecyclePathsForTest(
		t.Context(),
		otherLifecyclePath,
		maintenancePath,
	)
	other, err := resolveLinuxFakeTCPProductionScope(otherContext, baseline)
	if err != nil {
		t.Fatal(err)
	}
	if other == got || other.lifecyclePath != otherLifecyclePath {
		t.Fatalf("lifecycle lease did not distinguish scope: first=%#v other=%#v", got, other)
	}
}

func TestResolveLinuxFakeTCPProductionScopeRepresentsEmbeddedObjectExplicitly(t *testing.T) {
	root := fakeTCPProductionRealTempDir(t)
	pinPath := filepath.Join(root, "pins", "production")
	lifecyclePath := filepath.Join(root, "leases", "daemon.lease")
	ctx := lockfile.WithLifecyclePathsForTest(
		t.Context(),
		lifecyclePath,
		filepath.Join(root, "leases", "maintenance.lock"),
	)
	got, err := resolveLinuxFakeTCPProductionScope(ctx, LinuxLoader{
		PinPath:          pinPath,
		objectPathFrozen: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.objectKind != fakeTCPProductionObjectScopeEmbedded ||
		got.objectPath != EmbeddedObjectSource || got.pinPath != pinPath ||
		got.lifecyclePath != lifecyclePath {
		t.Fatalf("embedded production scope = %#v", got)
	}
}

func TestNewProductionLoaderFreezesEnvironmentBackedScopeSelectors(t *testing.T) {
	root := fakeTCPProductionRealTempDir(t)
	objectA := filepath.Join(root, "object-a.o")
	objectB := filepath.Join(root, "object-b.o")
	pinA := filepath.Join(root, "pins-a")
	pinB := filepath.Join(root, "pins-b")
	lifecyclePath := filepath.Join(root, "daemon.lease")
	ctx := lockfile.WithLifecyclePathsForTest(
		t.Context(),
		lifecyclePath,
		filepath.Join(root, "maintenance.lock"),
	)

	t.Run("explicit environment selection", func(t *testing.T) {
		t.Setenv(EnvObjectPath, objectA)
		t.Setenv(EnvPinPath, pinA)
		coordinator, ok := NewLoaderWithOptions(LoaderOptions{AdoptLegacyPins: true}).(*fakeTCPProductionCoordinator)
		if !ok {
			t.Fatalf("NewLoaderWithOptions returned %T", NewLoaderWithOptions(LoaderOptions{}))
		}
		baseline, ok := coordinator.baseline.(LinuxLoader)
		if !ok || !baseline.objectPathFrozen {
			t.Fatalf("production baseline is not frozen: %#v", coordinator.baseline)
		}

		t.Setenv(EnvObjectPath, objectB)
		t.Setenv(EnvPinPath, pinB)
		scope, err := coordinator.resolveScope(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if scope.objectPath != objectA || scope.pinPath != pinA ||
			!scope.adoptLegacyPins {
			t.Fatalf("environment changed frozen scope: %#v", scope)
		}
	})

	t.Run("embedded selection", func(t *testing.T) {
		t.Setenv(EnvObjectPath, "")
		t.Setenv(EnvPinPath, pinA)
		coordinator, ok := NewLoader().(*fakeTCPProductionCoordinator)
		if !ok {
			t.Fatalf("NewLoader returned %T", NewLoader())
		}
		t.Setenv(EnvObjectPath, objectB)
		t.Setenv(EnvPinPath, pinB)
		scope, err := coordinator.resolveScope(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if scope.objectKind != fakeTCPProductionObjectScopeEmbedded ||
			scope.objectPath != EmbeddedObjectSource || scope.pinPath != pinA {
			t.Fatalf("environment changed frozen embedded scope: %#v", scope)
		}
	})
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
		resolveScope: func(context.Context) (fakeTCPProductionScopeIdentity, error) {
			return fakeTCPProductionTestScope(), nil
		},
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
