//go:build linux

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/syx0310/wg-mix-ebpf/internal/abi"
	"github.com/syx0310/wg-mix-ebpf/internal/config"
	"github.com/syx0310/wg-mix-ebpf/internal/control"
	"github.com/syx0310/wg-mix-ebpf/internal/faketcp"
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

func TestNewLoaderCoordinatorRequiresResidentRuntimeBeforePlanning(t *testing.T) {
	t.Setenv(EnvPinPath, filepath.Join(t.TempDir(), "pins"))
	t.Setenv(EnvObjectPath, "")
	t.Setenv(EnvFakeTCPObjectPath, "")
	err := NewLoader().Apply(t.Context(), fakeTCPProductionTestState())
	if !errors.Is(err, ErrFakeTCPResidentRuntimeRequired) {
		t.Fatalf("production coordinator did not fail at the resident gate: %v", err)
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
		objectKind:                 fakeTCPProductionObjectScopeFilesystem,
		objectPath:                 objectPath,
		fakeTCPObjectPath:          EmbeddedFakeTCPObjectSource,
		fakeTCPLegacy515ObjectPath: EmbeddedFakeTCPLegacy515ObjectSource,
		pinPath:                    pinPath,
		lifecyclePath:              lifecyclePath,
		adoptLegacyPins:            true,
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
		got.objectPath != EmbeddedObjectSource ||
		got.fakeTCPObjectPath != EmbeddedFakeTCPObjectSource || got.pinPath != pinPath ||
		got.lifecyclePath != lifecyclePath {
		t.Fatalf("embedded production scope = %#v", got)
	}
}

func TestNewProductionLoaderFreezesEnvironmentBackedScopeSelectors(t *testing.T) {
	root := fakeTCPProductionRealTempDir(t)
	objectA := filepath.Join(root, "object-a.o")
	objectB := filepath.Join(root, "object-b.o")
	fakeObjectA := filepath.Join(root, "faketcp-object-a.o")
	fakeObjectB := filepath.Join(root, "faketcp-object-b.o")
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
		t.Setenv(EnvFakeTCPObjectPath, fakeObjectA)
		t.Setenv(EnvPinPath, pinA)
		coordinator, ok := NewLoaderWithOptions(LoaderOptions{AdoptLegacyPins: true}).(*fakeTCPProductionCoordinator)
		if !ok {
			t.Fatalf("NewLoaderWithOptions returned %T", NewLoaderWithOptions(LoaderOptions{}))
		}
		baseline, ok := coordinator.baseline.(LinuxLoader)
		if !ok || !baseline.objectPathFrozen || !baseline.fakeTCPObjectPathFrozen {
			t.Fatalf("production baseline is not frozen: %#v", coordinator.baseline)
		}

		t.Setenv(EnvObjectPath, objectB)
		t.Setenv(EnvFakeTCPObjectPath, fakeObjectB)
		t.Setenv(EnvPinPath, pinB)
		scope, err := coordinator.resolveScope(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if scope.objectPath != objectA || scope.fakeTCPObjectPath != fakeObjectA ||
			scope.pinPath != pinA ||
			!scope.adoptLegacyPins {
			t.Fatalf("environment changed frozen scope: %#v", scope)
		}
	})

	t.Run("embedded selection", func(t *testing.T) {
		t.Setenv(EnvObjectPath, "")
		t.Setenv(EnvFakeTCPObjectPath, "")
		t.Setenv(EnvPinPath, pinA)
		coordinator, ok := NewLoader().(*fakeTCPProductionCoordinator)
		if !ok {
			t.Fatalf("NewLoader returned %T", NewLoader())
		}
		t.Setenv(EnvObjectPath, objectB)
		t.Setenv(EnvFakeTCPObjectPath, fakeObjectB)
		t.Setenv(EnvPinPath, pinB)
		scope, err := coordinator.resolveScope(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if scope.objectKind != fakeTCPProductionObjectScopeEmbedded ||
			scope.objectPath != EmbeddedObjectSource ||
			scope.fakeTCPObjectPath != EmbeddedFakeTCPObjectSource || scope.pinPath != pinA {
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

func TestLiveExperimentalProductionPlanningRequiresResidentRuntimeBeforeMutation(t *testing.T) {
	baseline := &fakeTCPProductionTestBaseline{}
	coordinator := &fakeTCPProductionCoordinator{
		baseline: baseline,
		shared: &fakeTCPProductionCoordinatorState{
			supervisor: &fakeTCPRuntimeSupervisor{},
			owner:      dataplaneCoreOwnerUnknown,
		},
		validateActivation: func(*control.State) error { return nil },
		resolveScope: func(context.Context) (fakeTCPProductionScopeIdentity, error) {
			return fakeTCPProductionTestScope(), nil
		},
		planExperimental: composeExperimentalFakeTCPProductionPlanner(
			LinuxLoader{
				ObjectPath:              "/experimental-planning-test.o",
				objectPathFrozen:        true,
				fakeTCPObjectPathFrozen: true,
			},
			buildLiveExperimentalFakeTCPProductionRequest,
			func(
				context.Context,
				*experimentalFakeTCPProductionRequest,
			) (fakeTCPRuntimeService, error) {
				t.Fatal("live factory ran without resident runtime ownership")
				return nil, nil
			},
		),
	}

	err := coordinator.Apply(t.Context(), fakeTCPProductionTestState())
	if !errors.Is(err, ErrFakeTCPResidentRuntimeRequired) {
		t.Fatalf("Apply error = %v, want resident runtime error", err)
	}
	apply, detach, stale := baseline.counts()
	if apply != 0 || detach != 0 || stale != 0 {
		t.Fatalf("live planning failure mutated baseline: apply=%d detach=%d stale=%d", apply, detach, stale)
	}
}

func TestLiveExperimentalProductionPlannerSelectsChecksumBeforeObjectAndLeasePlan(t *testing.T) {
	files := token.NewFileSet()
	parsed, err := parser.ParseFile(
		files, "faketcp_production_linux.go", nil, parser.SkipObjectResolution,
	)
	if err != nil {
		t.Fatal(err)
	}
	var target *ast.FuncDecl
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Name.Name == "buildLiveExperimentalFakeTCPProductionRequest" {
			target = function
			break
		}
	}
	if target == nil {
		t.Fatal("live production request builder is absent")
	}
	positions := map[string]token.Pos{}
	ast.Inspect(target.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		identifier, ok := call.Fun.(*ast.Ident)
		if !ok {
			return true
		}
		switch identifier.Name {
		case "ResolveFakeTCPChecksumBackend",
			"loadFakeTCPCollectionSpecFromResolvedPath",
			"newFakeTCPPolicyGenerationTransaction":
			if positions[identifier.Name] == token.NoPos {
				positions[identifier.Name] = identifier.Pos()
			}
		}
		return true
	})
	selection := positions["ResolveFakeTCPChecksumBackend"]
	load := positions["loadFakeTCPCollectionSpecFromResolvedPath"]
	transaction := positions["newFakeTCPPolicyGenerationTransaction"]
	if selection == token.NoPos || load == token.NoPos || transaction == token.NoPos ||
		!(selection < load && load < transaction) {
		t.Fatalf(
			"planner order selection=%d load=%d transaction=%d; want checksum selection before object/lease plan",
			selection, load, transaction,
		)
	}
}

func TestFakeTCPProductionChecksumHealthProbeOutlivesPlanningContext(t *testing.T) {
	planningCtx, cancel := context.WithCancel(t.Context())
	selection := fakeTCPProductionTestChecksumSelection(
		config.FakeTCPChecksumBackendKfunc,
		config.FakeTCPChecksumBackendKfunc,
	)
	var healthCtx context.Context
	selection.health = func(ctx context.Context, _ uint64) error {
		healthCtx = ctx
		return ctx.Err()
	}
	probe := fakeTCPProductionChecksumHealthProbe(planningCtx, selection)
	cancel()
	if err := probe(); err != nil {
		t.Fatalf("health probe inherited planning cancellation: %v", err)
	}
	if healthCtx == nil || healthCtx.Err() != nil {
		t.Fatalf("health context = %#v, want retained uncancelled context", healthCtx)
	}
}

func fakeTCPProductionTestChecksumSelection(requested, backend string) *FakeTCPChecksumSelection {
	selection := &FakeTCPChecksumSelection{
		Requested:    requested,
		Backend:      backend,
		Capability:   FakeTCPChecksumCapabilityFullGSOV1,
		Capabilities: append([]string(nil), fullFakeTCPChecksumCapabilities...),
		health:       func(context.Context, uint64) error { return nil },
	}
	switch backend {
	case config.FakeTCPChecksumBackendKfunc:
		selection.ObjectVariant = FakeTCPObjectVariantModernKfunc
		selection.Module = DefaultFakeTCPKfuncModule
	case config.FakeTCPChecksumBackendKprobe:
		selection.ObjectVariant = FakeTCPObjectVariantLegacy515
		selection.Module = DefaultFakeTCPKprobeModule
		selection.LeaseHeld = true
		selection.lease = io.NopCloser(strings.NewReader(""))
		selection.cookie = 1
	}
	return selection
}

func TestFakeTCPProductionDesiredKeyBindsCipherObjectAndChecksumIdentity(t *testing.T) {
	state := fakeTCPPolicyStateWithInterfaces(1)
	state.WireGuards[0].RuntimeStateAvailable = true
	state.WireGuards[0].RuntimeFirewallMark = 0x9001
	state.Ciphers = []control.CipherState{{ID: 1, Name: "secret", KeyLen: 16, KeyMask: 15}}
	state.Ciphers[0].Key[0] = 0x11
	plan, err := buildFakeTCPPolicyGenerationPlan(state, state.Generation)
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := abi.FromStateWithGeneration(state, state.Generation)
	if err != nil {
		t.Fatal(err)
	}
	tcx, err := fakeTCPProductionTCXRequests(state)
	if err != nil {
		t.Fatal(err)
	}
	xdp := fakeTCPProductionXDPRequests(plan)
	identity := ObjectIdentity{
		Source:   EmbeddedFakeTCPObjectSource,
		SHA256:   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Embedded: true,
	}
	scope := fakeTCPProductionTestScope()
	enginePlans := runtimeTestEnginePlans(state.Generation, 1)
	checksum := fakeTCPProductionTestChecksumSelection(
		config.FakeTCPChecksumBackendAuto,
		config.FakeTCPChecksumBackendKfunc,
	)
	first, err := fakeTCPProductionDesiredKey(
		state, identity, scope, baseline, plan, enginePlans, exactTCXBackend, checksum, tcx, xdp,
	)
	if err != nil {
		t.Fatal(err)
	}
	again, err := fakeTCPProductionDesiredKey(
		state, identity, scope, baseline, plan, enginePlans, exactTCXBackend, checksum, tcx, xdp,
	)
	if err != nil || again != first {
		t.Fatalf("stable desired key changed: first=%x again=%x err=%v", first, again, err)
	}
	state.Ciphers[0].Key[0] ^= 0xff
	secretBaseline, err := abi.FromStateWithGeneration(state, state.Generation)
	if err != nil {
		t.Fatal(err)
	}
	secretChanged, err := fakeTCPProductionDesiredKey(
		state, identity, scope, secretBaseline, plan, enginePlans, exactTCXBackend, checksum, tcx, xdp,
	)
	if err != nil || secretChanged == first {
		t.Fatalf("cipher-only change was not bound: key=%x err=%v", secretChanged, err)
	}
	state.Ciphers[0].Key[0] ^= 0xff
	identity.SHA256 = "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	objectChanged, err := fakeTCPProductionDesiredKey(
		state, identity, scope, baseline, plan, enginePlans, exactTCXBackend, checksum, tcx, xdp,
	)
	if err != nil || objectChanged == first {
		t.Fatalf("object-only change was not bound: key=%x err=%v", objectChanged, err)
	}

	identity.SHA256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	explicitKfunc := fakeTCPProductionTestChecksumSelection(
		config.FakeTCPChecksumBackendKfunc,
		config.FakeTCPChecksumBackendKfunc,
	)
	requestedChanged, err := fakeTCPProductionDesiredKey(
		state, identity, scope, baseline, plan, enginePlans, exactTCXBackend, explicitKfunc, tcx, xdp,
	)
	if err != nil || requestedChanged == first {
		t.Fatalf("checksum request-only change was not bound: key=%x err=%v", requestedChanged, err)
	}

	legacyScope := scope
	legacyScope.fakeTCPLegacy515ObjectPath = EmbeddedFakeTCPLegacy515ObjectSource
	legacyIdentity := identity
	legacyIdentity.Source = EmbeddedFakeTCPLegacy515ObjectSource
	legacyChecksum := fakeTCPProductionTestChecksumSelection(
		config.FakeTCPChecksumBackendKprobe,
		config.FakeTCPChecksumBackendKprobe,
	)
	legacyChanged, err := fakeTCPProductionDesiredKey(
		state, legacyIdentity, legacyScope, baseline, plan, enginePlans,
		classicTCBackend, legacyChecksum, tcx, xdp,
	)
	if err != nil || legacyChanged == first {
		t.Fatalf("legacy checksum/object/backend change was not bound: key=%x err=%v", legacyChanged, err)
	}
}

func TestValidateFakeTCPProductionReferencesRejectsAmbiguousOwnership(t *testing.T) {
	base := func() *control.State {
		return &control.State{
			Generation: 7,
			WireGuards: []control.WireGuardState{
				{ID: 1, Name: "fake", TransportMode: "faketcp"},
				{ID: 2, Name: "udp", TransportMode: "udp"},
			},
			EgressRules: []control.EgressRule{{
				Generation: 7, WGID: 1, TransportMode: "faketcp",
			}},
			IngressListeners: []control.IngressListener{{
				Generation: 7, WGID: 1, TransportMode: "faketcp",
			}},
		}
	}
	for _, test := range []struct {
		name   string
		mutate func(*control.State)
	}{
		{name: "no FakeTCP WireGuard", mutate: func(state *control.State) {
			state.WireGuards[0].TransportMode = "udp"
		}},
		{name: "egress FakeTCP wrong owner", mutate: func(state *control.State) {
			state.EgressRules[0].WGID = 2
		}},
		{name: "ingress selected owner wrong mode", mutate: func(state *control.State) {
			state.IngressListeners[0].TransportMode = "udp"
		}},
		{name: "duplicate WireGuard ID", mutate: func(state *control.State) {
			state.WireGuards[1].ID = 1
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := base()
			test.mutate(state)
			if _, err := validateFakeTCPProductionReferences(state); err == nil {
				t.Fatalf("ambiguous state was accepted: %#v", state)
			}
		})
	}
	state := base()
	selected, err := validateFakeTCPProductionReferences(state)
	if err != nil || len(selected) != 1 || selected[0].ID != 1 {
		t.Fatalf("valid sole-owner state rejected: selected=%#v err=%v", selected, err)
	}
	state.WireGuards[1].TransportMode = "faketcp"
	state.IngressListeners = append(state.IngressListeners, control.IngressListener{
		Generation: 7, WGID: 2, TransportMode: "faketcp",
	})
	selected, err = validateFakeTCPProductionReferences(state)
	if err != nil || len(selected) != 2 || selected[0].ID != 1 || selected[1].ID != 2 {
		t.Fatalf("valid multi-owner state rejected: selected=%#v err=%v", selected, err)
	}
}

func TestFakeTCPProductionDesiredKeyBindsEveryEnginePlan(t *testing.T) {
	state := fakeTCPPolicyStateWithInterfaces(1)
	plan, err := buildFakeTCPPolicyGenerationPlan(state, state.Generation)
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := abi.FromStateWithGeneration(state, state.Generation)
	if err != nil {
		t.Fatal(err)
	}
	identity := ObjectIdentity{
		Source:   EmbeddedFakeTCPObjectSource,
		SHA256:   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Embedded: true,
	}
	checksum := fakeTCPProductionTestChecksumSelection(
		config.FakeTCPChecksumBackendAuto, config.FakeTCPChecksumBackendKfunc,
	)
	attachments, err := fakeTCPProductionTCXRequests(state)
	if err != nil {
		t.Fatal(err)
	}
	plans := runtimeTestEnginePlans(state.Generation, 2)
	first, err := fakeTCPProductionDesiredKey(
		state, identity, fakeTCPProductionTestScope(), baseline, plan, plans,
		exactTCXBackend, checksum, attachments, fakeTCPProductionXDPRequests(plan),
	)
	if err != nil {
		t.Fatal(err)
	}
	changed := append([]faketcp.WGEnginePlan(nil), plans...)
	changed[1].Options.MaxPendingBytes++
	second, err := fakeTCPProductionDesiredKey(
		state, identity, fakeTCPProductionTestScope(), baseline, plan, changed,
		exactTCXBackend, checksum, attachments, fakeTCPProductionXDPRequests(plan),
	)
	if err != nil || second == first {
		t.Fatalf("second Engine plan change was not bound: first=%x second=%x err=%v", first, second, err)
	}
}

func TestFakeTCPProductionEnginePlansAreCanonicalPerWireGuard(t *testing.T) {
	state := fakeTCPPolicyTestState()
	for index := range state.WireGuards {
		wg := &state.WireGuards[index]
		wg.RuntimeStateAvailable = true
		wg.RuntimeFirewallMark = 0x9000 + wg.ID
		wg.FakeTCPSessionCapacity = 64
		wg.FakeTCPMaxHalfOpenSessions = 16
		wg.FakeTCPMaxHalfOpenPerSource = 4
		wg.FakeTCPSYNBurstPerSource = 2
		wg.FakeTCPSYNSourceLedgerCapacity = 32
		wg.FakeTCPSYNSourceLedgerTTLNanos = int64(time.Second)
		wg.FakeTCPMaxPendingFlows = 8
		wg.FakeTCPMaxPendingPacketsPerFlow = 2
		wg.FakeTCPMaxPendingBytes = 4096
		wg.FakeTCPHandshakeTimeoutNanos = int64(time.Second)
		wg.FakeTCPKeepaliveIntervalNanos = int64(time.Second)
		wg.FakeTCPIdleTimeoutNanos = int64(5 * time.Second)
	}
	wireGuards, err := validateFakeTCPProductionReferences(state)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := buildFakeTCPPolicyGenerationPlan(state, state.Generation)
	if err != nil {
		t.Fatal(err)
	}
	plans, err := fakeTCPProductionEnginePlans(wireGuards, policy, state.Generation)
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) != 2 || plans[0].WGID != 1 || plans[1].WGID != 2 ||
		len(plans[0].Routes) != 1 || len(plans[1].Routes) != 1 {
		t.Fatalf("production Engine plans = %#v", plans)
	}
	for _, enginePlan := range plans {
		route := enginePlan.Routes[0]
		if route.WGID != enginePlan.WGID || route.Generation != state.Generation ||
			route.FWMark != 0x9000+enginePlan.WGID || route.Action != abi.ActionRewrite ||
			enginePlan.Options.Store != nil {
			t.Fatalf("production Engine plan is not isolated/canonical: %#v", enginePlan)
		}
	}
}

func TestCloneFakeTCPProductionStateOwnsEverySlice(t *testing.T) {
	state := &control.State{
		Profiles:         []control.ProfileState{{ID: 1}},
		Ciphers:          []control.CipherState{{ID: 2}},
		WireGuards:       []control.WireGuardState{{ID: 3}},
		Underlays:        []control.UnderlayState{{ID: 4}},
		ManagedFwmarks:   []control.ManagedFwmarkRule{{FwMark: 5}},
		EgressRules:      []control.EgressRule{{WGID: 6}},
		IngressListeners: []control.IngressListener{{WGID: 7}},
		ICMPListeners:    []control.ICMPListener{{WGID: 8}},
		Warnings:         []string{"nine"},
	}
	frozen := cloneFakeTCPProductionState(state)
	state.Profiles[0].ID = 11
	state.Ciphers[0].ID = 12
	state.WireGuards[0].ID = 13
	state.Underlays[0].ID = 14
	state.ManagedFwmarks[0].FwMark = 15
	state.EgressRules[0].WGID = 16
	state.IngressListeners[0].WGID = 17
	state.ICMPListeners[0].WGID = 18
	state.Warnings[0] = "changed"
	if frozen.Profiles[0].ID != 1 || frozen.Ciphers[0].ID != 2 ||
		frozen.WireGuards[0].ID != 3 || frozen.Underlays[0].ID != 4 ||
		frozen.ManagedFwmarks[0].FwMark != 5 || frozen.EgressRules[0].WGID != 6 ||
		frozen.IngressListeners[0].WGID != 7 || frozen.ICMPListeners[0].WGID != 8 ||
		frozen.Warnings[0] != "nine" {
		t.Fatalf("frozen state aliases caller slices: %#v", frozen)
	}
}

func TestProductionFakeTCPTCXStageUsesEmptyRevisionFencedAggregates(t *testing.T) {
	state := &control.State{Underlays: []control.UnderlayState{{
		Name: "underlay", Parser: "ethernet", IfIndex: 7, Role: "transform", Resolved: true,
	}}}
	kernel := newFakeExactTCXKernel()
	commits := 0
	stage, err := stageProductionFakeTCPTCX(
		t.Context(), state,
		&fakeExperimentalOwnedProgram{id: 101},
		&fakeExperimentalOwnedProgram{id: 102},
		func() error { commits++; return nil },
		kernel.runtime(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if stage == nil {
		t.Fatal("stage is nil")
	}
	if len(stage.attachments) != 2 || commits != 1 {
		t.Fatalf("attachments=%d commits=%d", len(stage.attachments), commits)
	}
	if len(kernel.events) < 4 || kernel.events[0] != "query" ||
		kernel.events[1] != "query" || kernel.events[2] != "attach" {
		t.Fatalf("TCX stage did not preflight every hook before first attach: %v", kernel.events)
	}
	for _, attachment := range stage.attachments {
		if attachment.identity.LinkID == 0 || attachment.identity.ProgramID == 0 {
			t.Fatalf("incomplete exact TCX identity: %+v", attachment.identity)
		}
	}
	if err := stage.Healthy(t.Context()); err != nil {
		t.Fatalf("new exact TCX owner is unhealthy: %v", err)
	}
	eventsBeforeClose := len(kernel.events)
	wantFirstClose := stage.attachments[1].identity.LinkID
	wantSecondClose := stage.attachments[0].identity.LinkID
	if err := stage.Close(); err != nil {
		t.Fatal(err)
	}
	closeEvents := kernel.events[eventsBeforeClose:]
	if len(closeEvents) != 2 || closeEvents[0] != fmt.Sprintf("close:%d", wantFirstClose) ||
		closeEvents[1] != fmt.Sprintf("close:%d", wantSecondClose) {
		t.Fatalf("TCX owners were not closed in reverse order: %v", closeEvents)
	}
	if err := stage.Healthy(t.Context()); err == nil {
		t.Fatal("closed exact TCX owner reported healthy")
	}
	for _, attach := range []ebpf.AttachType{ebpf.AttachTCXIngress, ebpf.AttachTCXEgress} {
		query, err := kernel.runtime().query(7, attach)
		if err != nil || len(query.Programs) != 0 {
			t.Fatalf("TCX owner remained after close: attach=%s query=%+v err=%v", attach, query, err)
		}
	}
}

type mismatchedProductionTCXIdentityLink struct {
	exactTCXKernelLink
}

func (link mismatchedProductionTCXIdentityLink) Identity() (exactTCXLinkIdentity, error) {
	identity, err := link.exactTCXKernelLink.Identity()
	identity.ProgramID++
	return identity, err
}

func TestProductionFakeTCPTCXStageIdentityMismatchReturnsExactRollbackOwner(t *testing.T) {
	state := &control.State{Underlays: []control.UnderlayState{{
		Name: "underlay", Parser: "ethernet", IfIndex: 7, Role: "transform", Resolved: true,
	}}}
	kernel := newFakeExactTCXKernel()
	runtime := kernel.runtime()
	liveAttach := runtime.attach
	runtime.attach = func(
		ifindex int,
		attach ebpf.AttachType,
		revision uint64,
		program exactTCXProgram,
	) (exactTCXKernelLink, error) {
		owner, err := liveAttach(ifindex, attach, revision, program)
		if owner == nil {
			return nil, err
		}
		return mismatchedProductionTCXIdentityLink{exactTCXKernelLink: owner}, err
	}
	stage, err := stageProductionFakeTCPTCX(
		t.Context(), state,
		&fakeExperimentalOwnedProgram{id: 101},
		&fakeExperimentalOwnedProgram{id: 102},
		func() error { t.Fatal("commit ran after identity mismatch"); return nil },
		runtime,
	)
	if err == nil || stage == nil || len(stage.attachments) != 1 {
		t.Fatalf("identity mismatch lost exact rollback owner: stage=%#v err=%v", stage, err)
	}
	if err := stage.Close(); err != nil {
		t.Fatal(err)
	}
	query, err := kernel.runtime().query(7, ebpf.AttachTCXIngress)
	if err != nil || len(query.Programs) != 0 {
		t.Fatalf("identity mismatch rollback left attachment: query=%+v err=%v", query, err)
	}
}

func TestProductionFakeTCPTCXStageRefusesExistingAggregateBeforeAttach(t *testing.T) {
	state := &control.State{Underlays: []control.UnderlayState{{
		Name: "underlay", Parser: "ethernet", IfIndex: 7, Role: "transform", Resolved: true,
	}}}
	kernel := newFakeExactTCXKernel()
	kernel.addLink(7, ebpf.AttachTCXIngress, 99)
	stage, err := stageProductionFakeTCPTCX(
		t.Context(), state,
		&fakeExperimentalOwnedProgram{id: 101},
		&fakeExperimentalOwnedProgram{id: 102},
		func() error { t.Fatal("commit ran for occupied aggregate"); return nil },
		kernel.runtime(),
	)
	if err == nil || stage != nil {
		t.Fatalf("occupied aggregate was accepted: stage=%#v err=%v", stage, err)
	}
	if got := len(kernel.events); got != 1 {
		t.Fatalf("occupied aggregate caused later queries or writes: events=%v", kernel.events)
	}
}

func TestProductionFakeTCPTCXStageFinalRecheckCatchesEarlierHookRace(t *testing.T) {
	state := &control.State{Underlays: []control.UnderlayState{{
		Name: "underlay", Parser: "ethernet", IfIndex: 7, Role: "transform", Resolved: true,
	}}}
	kernel := newFakeExactTCXKernel()
	queries := 0
	kernel.beforeQuery = func(kernel *fakeExactTCXKernel, slot fakeExactTCXSlot) {
		queries++
		// Two preflight queries and two immediate post-attach queries precede
		// the final all-hooks pass. Race a foreign program into the first hook
		// exactly as that final pass begins.
		if queries == 5 && slot.attach == ebpf.AttachTCXIngress {
			kernel.addLink(slot.ifindex, slot.attach, 999)
		}
	}
	commits := 0
	stage, err := stageProductionFakeTCPTCX(
		t.Context(), state,
		&fakeExperimentalOwnedProgram{id: 101},
		&fakeExperimentalOwnedProgram{id: 102},
		func() error { commits++; return nil },
		kernel.runtime(),
	)
	if err == nil || stage == nil {
		t.Fatalf("final aggregate race was accepted: stage=%#v err=%v", stage, err)
	}
	if commits != 0 {
		t.Fatalf("commit ran after final aggregate race: %d", commits)
	}
	if err := stage.Close(); err != nil {
		t.Fatal(err)
	}
	query, err := kernel.runtime().query(7, ebpf.AttachTCXIngress)
	if err != nil || len(query.Programs) != 1 || query.Programs[0].ProgramID != 999 {
		t.Fatalf("rollback did not preserve only foreign owner: query=%+v err=%v", query, err)
	}
}

func TestProductionFakeTCPTCXStageRevisionRaceCreatesNoOwner(t *testing.T) {
	state := &control.State{Underlays: []control.UnderlayState{{
		Name: "underlay", Parser: "ethernet", IfIndex: 7, Role: "transform", Resolved: true,
	}}}
	kernel := newFakeExactTCXKernel()
	kernel.beforeAttach = func(kernel *fakeExactTCXKernel, slot fakeExactTCXSlot) {
		kernel.revs[slot] = kernel.revision(slot) + 1
		kernel.beforeAttach = nil
	}
	stage, err := stageProductionFakeTCPTCX(
		t.Context(), state,
		&fakeExperimentalOwnedProgram{id: 101},
		&fakeExperimentalOwnedProgram{id: 102},
		func() error { t.Fatal("commit ran after revision race"); return nil },
		kernel.runtime(),
	)
	if err == nil || stage != nil {
		t.Fatalf("revision race was accepted: stage=%#v err=%v", stage, err)
	}
	for _, link := range kernel.links {
		if link.attached {
			t.Fatalf("revision race created a TCX owner: %#v", link)
		}
	}
}

func TestProductionFakeTCPTCXStageCloseRetainsFailedOwnerForRetry(t *testing.T) {
	state := &control.State{Underlays: []control.UnderlayState{{
		Name: "underlay", Parser: "ethernet", IfIndex: 7, Role: "transform", Resolved: true,
	}}}
	kernel := newFakeExactTCXKernel()
	stage, err := stageProductionFakeTCPTCX(
		t.Context(), state,
		&fakeExperimentalOwnedProgram{id: 101},
		&fakeExperimentalOwnedProgram{id: 102},
		func() error { return nil },
		kernel.runtime(),
	)
	if err != nil {
		t.Fatal(err)
	}
	failedID := stage.attachments[1].identity.LinkID
	kernel.closeErrs[failedID] = []error{errors.New("injected close failure")}
	if err := stage.Close(); err == nil || len(stage.attachments) != 1 ||
		stage.attachments[0].identity.LinkID != failedID {
		t.Fatalf("failed close owner was not retained exactly: attachments=%#v err=%v", stage.attachments, err)
	}
	if err := stage.Close(); err != nil || len(stage.attachments) != 0 {
		t.Fatalf("retry did not close retained owner: attachments=%#v err=%v", stage.attachments, err)
	}
}
