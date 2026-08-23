//go:build linux

package dataplane

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

type experimentalAcquisitionFixture struct {
	order         []string
	raw           *ebpf.Collection
	rawCloseCalls int
	rawCloseErr   error
	owner         *experimentalCollectionOwner
	ownedMap      *fakeExperimentalOwnedMap
}

func newExperimentalAcquisitionFixture() *experimentalAcquisitionFixture {
	fixture := &experimentalAcquisitionFixture{
		raw: &ebpf.Collection{
			Maps:     map[string]*ebpf.Map{},
			Programs: map[string]*ebpf.Program{},
		},
	}
	fixture.ownedMap = &fakeExperimentalOwnedMap{
		name:     "owned",
		closeLog: &fixture.order,
	}
	fixture.owner = &experimentalCollectionOwner{
		maps: map[string]experimentalMapResource{
			"owned": fixture.ownedMap,
		},
		programs:  map[string]experimentalProgramResource{},
		closeDone: make(chan struct{}),
	}
	return fixture
}

func (fixture *experimentalAcquisitionFixture) dependencies(
	t *testing.T,
) experimentalCollectionAcquisitionDependencies {
	t.Helper()
	return experimentalCollectionAcquisitionDependencies{
		probeKernelDependency: func() error {
			fixture.order = append(fixture.order, "kernel-dependency")
			return nil
		},
		removeMemlock: func() error {
			fixture.order = append(fixture.order, "remove-memlock")
			return nil
		},
		newCollection: func(got *ebpf.CollectionSpec) (*ebpf.Collection, error) {
			fixture.order = append(fixture.order, "new-collection")
			if got == nil {
				t.Fatal("collection factory received nil spec")
			}
			return fixture.raw, nil
		},
		newOwner: func(got *ebpf.Collection) (*experimentalCollectionOwner, error) {
			fixture.order = append(fixture.order, "new-owner")
			if got != fixture.raw {
				t.Fatal("owner factory did not receive the newly loaded collection")
			}
			return fixture.owner, nil
		},
		closeUnownedCollection: func(got *ebpf.Collection) error {
			fixture.order = append(fixture.order, "close-raw")
			if got != fixture.raw {
				t.Fatal("raw closer did not receive the newly loaded collection")
			}
			fixture.rawCloseCalls++
			return fixture.rawCloseErr
		},
	}
}

func TestExperimentalCollectionAcquisitionTransfersSoleOwnership(t *testing.T) {
	fixture := newExperimentalAcquisitionFixture()
	dependencies := fixture.dependencies(t)
	dependencies.newOwner = func(got *ebpf.Collection) (*experimentalCollectionOwner, error) {
		fixture.order = append(fixture.order, "new-owner")
		return newExperimentalCollectionOwner(got)
	}
	owner, err := acquireExperimentalFakeTCPCollection(
		t.Context(),
		canonicalExperimentalCollectionSpec(),
		"/reviewed/experimental.o",
		dependencies,
	)
	if err != nil {
		t.Fatal(err)
	}
	if owner == nil {
		t.Fatal("acquisition returned a nil collection owner")
	}
	if fixture.rawCloseCalls != 0 {
		t.Fatalf("raw collection close calls = %d, want 0 after ownership transfer", fixture.rawCloseCalls)
	}
	if fixture.raw.Maps != nil || fixture.raw.Programs != nil {
		t.Fatal("raw collection retained resources after ownership transfer")
	}
	if got, want := strings.Join(fixture.order, ","), "kernel-dependency,remove-memlock,new-collection,new-owner"; got != want {
		t.Fatalf("acquisition order = %q, want %q", got, want)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if !owner.closed {
		t.Fatal("caller did not retain and close the transferred owner")
	}
}

func TestFakeTCPCollectionAcquisitionUsesVariantBoundManifest(t *testing.T) {
	legacyManifest, err := fakeTCPCollectionManifestForObjectVariant(
		FakeTCPObjectVariantLegacy515,
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture := newExperimentalAcquisitionFixture()
	owner, err := acquireFakeTCPCollection(
		t.Context(),
		canonicalLegacy515CollectionSpec(),
		"/reviewed/legacy-515.o",
		legacyManifest,
		fixture.dependencies(t),
	)
	if err != nil {
		t.Fatalf("legacy acquisition rejected its selected object family: %v", err)
	}
	if err := owner.Close(); err != nil {
		t.Fatalf("close acquired legacy collection owner: %v", err)
	}

	modernManifest, err := fakeTCPCollectionManifestForObjectVariant(
		FakeTCPObjectVariantModernKfunc,
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = acquireFakeTCPCollection(
		t.Context(),
		canonicalLegacy515CollectionSpec(),
		"/reviewed/legacy-515.o",
		modernManifest,
		newExperimentalAcquisitionFixture().dependencies(t),
	)
	if err == nil || !strings.Contains(err.Error(), "validate experimental FakeTCP BPF object") {
		t.Fatalf("modern manifest accepted legacy object or lost exact diagnostic: %v", err)
	}

	if _, err := fakeTCPCollectionManifestForObjectVariant("unreviewed"); err == nil ||
		!strings.Contains(err.Error(), "unsupported FakeTCP object variant") {
		t.Fatalf("unknown object variant did not fail closed: %v", err)
	}
}

func TestExperimentalVerifierLoadReusesAcquisitionThenExplicitlyCloses(t *testing.T) {
	spec := canonicalExperimentalCollectionSpec()
	fixture := newExperimentalAcquisitionFixture()
	dependencies := fixture.dependencies(t)
	originalNewCollection := dependencies.newCollection
	dependencies.newCollection = func(got *ebpf.CollectionSpec) (*ebpf.Collection, error) {
		if got != spec {
			t.Fatal("loader did not receive the manifest-validated collection spec")
		}
		for _, descriptor := range experimentalMapDescriptors() {
			if got.Maps[descriptor.name] == nil {
				t.Fatalf("loader spec is missing map %q", descriptor.name)
			}
		}
		for _, descriptor := range experimentalProgramDescriptors() {
			if got.Programs[descriptor.name] == nil {
				t.Fatalf("loader spec is missing program %q", descriptor.name)
			}
		}
		return originalNewCollection(got)
	}

	err := loadExperimentalFakeTCPCollection(
		t.Context(),
		spec,
		"/reviewed/experimental.o",
		dependencies,
	)
	if err != nil {
		t.Fatal(err)
	}
	if fixture.rawCloseCalls != 0 {
		t.Fatalf("raw collection close calls = %d, want 0 after transfer", fixture.rawCloseCalls)
	}
	if fixture.ownedMap.closes != 1 {
		t.Fatalf("verifier owner close calls = %d, want 1", fixture.ownedMap.closes)
	}
	if got, want := strings.Join(fixture.order, ","), "kernel-dependency,remove-memlock,new-collection,new-owner,map:owned"; got != want {
		t.Fatalf("load order = %q, want %q", got, want)
	}
}

func TestExperimentalVerifierLoadAggregatesOwnerCloseFailures(t *testing.T) {
	fixture := newExperimentalAcquisitionFixture()
	var closeLog []string
	mapErr := errors.New("injected map close failure")
	programErr := errors.New("injected program close failure")
	ownedMap := &fakeExperimentalOwnedMap{
		name: "map", closeLog: &closeLog, closeErr: mapErr,
	}
	ownedProgram := &fakeExperimentalOwnedProgram{
		name: "program", id: 1, closeLog: &closeLog, closeErr: programErr,
	}
	fixture.owner = &experimentalCollectionOwner{
		maps: map[string]experimentalMapResource{"map": ownedMap},
		programs: map[string]experimentalProgramResource{
			"program": ownedProgram,
		},
		closeDone: make(chan struct{}),
	}

	err := loadExperimentalFakeTCPCollection(
		t.Context(),
		canonicalExperimentalCollectionSpec(),
		"/reviewed/experimental.o",
		fixture.dependencies(t),
	)
	if !errors.Is(err, mapErr) || !errors.Is(err, programErr) {
		t.Fatalf("close error = %v, want both injected failures", err)
	}
	if fixture.rawCloseCalls != 0 {
		t.Fatalf("raw collection close calls = %d, want 0 after transfer", fixture.rawCloseCalls)
	}
	if ownedMap.closes != 1 || ownedProgram.closes != 1 {
		t.Fatalf("owner closes: map=%d program=%d, want exactly 1 each", ownedMap.closes, ownedProgram.closes)
	}
}

func TestExperimentalVerifierSweepAttemptsEveryProgramAndAggregatesFailures(t *testing.T) {
	spec := canonicalExperimentalCollectionSpec()
	firstErr := errors.New("first injected verifier failure")
	secondErr := errors.New("second injected verifier failure")
	failing := map[string]error{
		"wg_mix_faketcp_ingress": firstErr,
		"wg_mix_ingress":         secondErr,
	}
	var loaded []string
	probeCalls := 0
	memlockCalls := 0
	closeCalls := 0
	dependencies := experimentalCollectionAcquisitionDependencies{
		probeKernelDependency: func() error { probeCalls++; return nil },
		removeMemlock:         func() error { memlockCalls++; return nil },
		newCollection: func(isolated *ebpf.CollectionSpec) (*ebpf.Collection, error) {
			if len(isolated.Programs) != 1 {
				t.Fatalf("isolated program count = %d, want 1", len(isolated.Programs))
			}
			for name := range isolated.Programs {
				loaded = append(loaded, name)
				if err := failing[name]; err != nil {
					return nil, err
				}
			}
			return &ebpf.Collection{}, nil
		},
		newOwner: func(*ebpf.Collection) (*experimentalCollectionOwner, error) {
			return nil, errors.New("verifier sweep must not construct an owner")
		},
		closeUnownedCollection: func(*ebpf.Collection) error {
			closeCalls++
			return nil
		},
	}

	err := verifierLoadEveryExperimentalFakeTCPProgram(
		t.Context(), spec, "/reviewed/experimental.o", dependencies,
	)
	if !errors.Is(err, firstErr) || !errors.Is(err, secondErr) {
		t.Fatalf("sweep error = %v, want both verifier failures", err)
	}
	want := make([]string, 0, len(spec.Programs))
	for name := range spec.Programs {
		want = append(want, name)
	}
	sort.Strings(want)
	if strings.Join(loaded, ",") != strings.Join(want, ",") {
		t.Fatalf("loaded programs = %q, want sorted complete set %q", loaded, want)
	}
	if probeCalls != 1 || memlockCalls != 1 {
		t.Fatalf("preflight calls: probe=%d memlock=%d, want 1 each", probeCalls, memlockCalls)
	}
	if closeCalls != len(spec.Programs)-len(failing) {
		t.Fatalf("successful collection closes = %d, want %d", closeCalls, len(spec.Programs)-len(failing))
	}
}

func TestFakeTCPProgramInspectionReturnsValidatedSortedRealSet(t *testing.T) {
	spec := canonicalExperimentalCollectionSpec()
	identity := ObjectIdentity{Source: "/held/modern.o", SHA256: strings.Repeat("a", 64)}
	gotIdentity, names, err := inspectFakeTCPObjectTestPrograms(
		t.Context(),
		"/held/modern.o",
		"experimental FakeTCP",
		func(path string) (*ebpf.CollectionSpec, ObjectIdentity, error) {
			if path != identity.Source {
				t.Fatalf("inspection path = %q, want %q", path, identity.Source)
			}
			return spec, identity, nil
		},
		validateExperimentalExtensionManifest,
	)
	if err != nil {
		t.Fatal(err)
	}
	if gotIdentity != identity {
		t.Fatalf("inspection identity = %#v, want %#v", gotIdentity, identity)
	}
	want := sortedFakeTCPProgramNames(spec)
	if strings.Join(names, ",") != strings.Join(want, ",") || !sort.StringsAreSorted(names) {
		t.Fatalf("inspection programs = %q, want sorted %q", names, want)
	}
}

func TestFakeTCPSingleProgramLoadIsFreshAndExact(t *testing.T) {
	spec := canonicalExperimentalCollectionSpec()
	identity := ObjectIdentity{Source: "/held/modern.o", SHA256: strings.Repeat("b", 64)}
	programs := sortedFakeTCPProgramNames(spec)
	wanted := programs[len(programs)/2]
	loads := 0
	closes := 0
	dependencies := experimentalCollectionAcquisitionDependencies{
		probeKernelDependency: func() error { return nil },
		removeMemlock:         func() error { return nil },
		newCollection: func(isolated *ebpf.CollectionSpec) (*ebpf.Collection, error) {
			loads++
			if len(isolated.Programs) != 1 || isolated.Programs[wanted] == nil {
				t.Fatalf("single-program spec = %v, want only %q", isolated.Programs, wanted)
			}
			return &ebpf.Collection{}, nil
		},
		newOwner: func(*ebpf.Collection) (*experimentalCollectionOwner, error) {
			return nil, errors.New("single-program verifier must not construct an owner")
		},
		closeUnownedCollection: func(*ebpf.Collection) error {
			closes++
			return nil
		},
	}
	loadCalls := 0
	loader := func(string) (*ebpf.CollectionSpec, ObjectIdentity, error) {
		loadCalls++
		return spec.Copy(), identity, nil
	}
	got, err := loadFakeTCPObjectProgramTestIdentity(
		t.Context(), identity.Source, wanted, "experimental FakeTCP",
		loader, validateExperimentalExtensionManifest, dependencies,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got != identity || loadCalls != 2 || loads != 1 || closes != 1 {
		t.Fatalf("identity=%#v loads(spec=%d,kernel=%d,close=%d)", got, loadCalls, loads, closes)
	}

	_, err = loadFakeTCPObjectProgramTestIdentity(
		t.Context(), identity.Source, "not_in_object", "experimental FakeTCP",
		loader, validateExperimentalExtensionManifest, dependencies,
	)
	if err == nil || !strings.Contains(err.Error(), "not in the validated object") {
		t.Fatalf("unknown program error = %v", err)
	}
	if loads != 1 {
		t.Fatalf("unknown program reached kernel loader; loads=%d", loads)
	}
}

func TestExperimentalCollectionAcquisitionFailsBeforeKernelMutationOnManifestDrift(t *testing.T) {
	for _, mutate := range []func(*ebpf.CollectionSpec){
		func(spec *ebpf.CollectionSpec) {
			spec.Maps["faketcp_session_map"].Pinning = ebpf.PinByName
		},
		func(spec *ebpf.CollectionSpec) {
			spec.Maps["unknown"] = &ebpf.MapSpec{Name: "unknown"}
		},
		func(spec *ebpf.CollectionSpec) {
			spec.Programs["unknown"] = &ebpf.ProgramSpec{Name: "unknown"}
		},
	} {
		spec := canonicalExperimentalCollectionSpec()
		mutate(spec)
		fixture := newExperimentalAcquisitionFixture()
		_, err := acquireExperimentalFakeTCPCollection(
			t.Context(), spec, "/reviewed/experimental.o", fixture.dependencies(t),
		)
		if err == nil || !strings.Contains(err.Error(), "validate experimental FakeTCP BPF object") {
			t.Fatalf("manifest drift error = %v", err)
		}
		if len(fixture.order) != 0 || fixture.rawCloseCalls != 0 {
			t.Fatalf("manifest drift reached kernel steps: order=%v raw-closes=%d", fixture.order, fixture.rawCloseCalls)
		}
	}
}

func TestExperimentalCollectionAcquisitionStopsAfterKernelDependencyFailure(t *testing.T) {
	fixture := newExperimentalAcquisitionFixture()
	wantErr := errors.New("required module is unavailable")
	dependencies := fixture.dependencies(t)
	dependencies.probeKernelDependency = func() error {
		fixture.order = append(fixture.order, "kernel-dependency")
		return wantErr
	}

	_, err := acquireExperimentalFakeTCPCollection(
		t.Context(), canonicalExperimentalCollectionSpec(),
		"/reviewed/experimental.o", dependencies,
	)
	if !errors.Is(err, wantErr) || !strings.Contains(err.Error(), "kernel dependency") {
		t.Fatalf("dependency error = %v, want wrapped %v", err, wantErr)
	}
	if got := strings.Join(fixture.order, ","); got != "kernel-dependency" {
		t.Fatalf("dependency failure order = %q", got)
	}
}

func TestExperimentalCollectionAcquisitionStopsAfterMemlockFailure(t *testing.T) {
	fixture := newExperimentalAcquisitionFixture()
	wantErr := errors.New("memlock unavailable")
	dependencies := fixture.dependencies(t)
	dependencies.removeMemlock = func() error {
		fixture.order = append(fixture.order, "remove-memlock")
		return wantErr
	}

	_, err := acquireExperimentalFakeTCPCollection(
		t.Context(), canonicalExperimentalCollectionSpec(),
		"/reviewed/experimental.o", dependencies,
	)
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
	if got := strings.Join(fixture.order, ","); got != "kernel-dependency,remove-memlock" {
		t.Fatalf("memlock failure order = %q", got)
	}
}

func TestExperimentalCollectionAcquisitionClosesPartialNewCollectionFailure(t *testing.T) {
	fixture := newExperimentalAcquisitionFixture()
	loadErr := errors.New("injected collection load failure")
	closeErr := errors.New("injected raw close failure")
	fixture.rawCloseErr = closeErr
	dependencies := fixture.dependencies(t)
	dependencies.newCollection = func(*ebpf.CollectionSpec) (*ebpf.Collection, error) {
		fixture.order = append(fixture.order, "new-collection")
		return fixture.raw, loadErr
	}

	_, err := acquireExperimentalFakeTCPCollection(
		t.Context(), canonicalExperimentalCollectionSpec(),
		"/reviewed/experimental.o", dependencies,
	)
	if !errors.Is(err, loadErr) || !errors.Is(err, closeErr) {
		t.Fatalf("newCollection error = %v, want load and close failures", err)
	}
	if fixture.rawCloseCalls != 1 {
		t.Fatalf("partial collection close calls = %d, want 1", fixture.rawCloseCalls)
	}
	if got := strings.Join(fixture.order, ","); got != "kernel-dependency,remove-memlock,new-collection,close-raw" {
		t.Fatalf("newCollection failure order = %q", got)
	}
}

func TestExperimentalCollectionAcquisitionClosesOwnerConstructionFailures(t *testing.T) {
	wantErr := errors.New("injected owner construction failure")

	t.Run("ownership not transferred", func(t *testing.T) {
		fixture := newExperimentalAcquisitionFixture()
		dependencies := fixture.dependencies(t)
		dependencies.newOwner = func(*ebpf.Collection) (*experimentalCollectionOwner, error) {
			fixture.order = append(fixture.order, "new-owner")
			return nil, wantErr
		}
		_, err := acquireExperimentalFakeTCPCollection(
			t.Context(), canonicalExperimentalCollectionSpec(),
			"/reviewed/experimental.o", dependencies,
		)
		if !errors.Is(err, wantErr) {
			t.Fatalf("owner error = %v, want %v", err, wantErr)
		}
		if fixture.rawCloseCalls != 1 || fixture.ownedMap.closes != 0 {
			t.Fatalf("close counts: raw=%d owner=%d", fixture.rawCloseCalls, fixture.ownedMap.closes)
		}
	})

	t.Run("ownership transferred with error", func(t *testing.T) {
		fixture := newExperimentalAcquisitionFixture()
		dependencies := fixture.dependencies(t)
		dependencies.newOwner = func(*ebpf.Collection) (*experimentalCollectionOwner, error) {
			fixture.order = append(fixture.order, "new-owner")
			return fixture.owner, wantErr
		}
		_, err := acquireExperimentalFakeTCPCollection(
			t.Context(), canonicalExperimentalCollectionSpec(),
			"/reviewed/experimental.o", dependencies,
		)
		if !errors.Is(err, wantErr) {
			t.Fatalf("owner error = %v, want %v", err, wantErr)
		}
		if fixture.rawCloseCalls != 0 || fixture.ownedMap.closes != 1 {
			t.Fatalf("close counts: raw=%d owner=%d", fixture.rawCloseCalls, fixture.ownedMap.closes)
		}
	})
}

func TestExperimentalCollectionAcquisitionFailsClosedOnNilCollectionOrOwner(t *testing.T) {
	t.Run("nil collection", func(t *testing.T) {
		fixture := newExperimentalAcquisitionFixture()
		dependencies := fixture.dependencies(t)
		dependencies.newCollection = func(*ebpf.CollectionSpec) (*ebpf.Collection, error) {
			return nil, nil
		}
		_, err := acquireExperimentalFakeTCPCollection(
			t.Context(), canonicalExperimentalCollectionSpec(),
			"/reviewed/experimental.o", dependencies,
		)
		if err == nil || !strings.Contains(err.Error(), "loader returned nil collection") {
			t.Fatalf("nil collection error = %v", err)
		}
	})

	t.Run("nil collection after cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		fixture := newExperimentalAcquisitionFixture()
		dependencies := fixture.dependencies(t)
		dependencies.newCollection = func(*ebpf.CollectionSpec) (*ebpf.Collection, error) {
			fixture.order = append(fixture.order, "new-collection")
			cancel()
			return nil, nil
		}
		owner, err := acquireExperimentalFakeTCPCollection(
			ctx, canonicalExperimentalCollectionSpec(),
			"/reviewed/experimental.o", dependencies,
		)
		if owner != nil {
			t.Fatal("nil collection contract failure returned an owner")
		}
		if err == nil || !strings.Contains(err.Error(), "loader returned nil collection") ||
			!errors.Is(err, context.Canceled) {
			t.Fatalf("nil collection cancellation error = %v", err)
		}
		if got, want := strings.Join(fixture.order, ","), "kernel-dependency,remove-memlock,new-collection"; got != want {
			t.Fatalf("nil collection cancellation order = %q, want %q", got, want)
		}
		if fixture.rawCloseCalls != 0 || fixture.ownedMap.closes != 0 {
			t.Fatalf(
				"nil collection cancellation close counts: raw=%d owner=%d, want 0/0",
				fixture.rawCloseCalls, fixture.ownedMap.closes,
			)
		}
	})

	t.Run("nil owner", func(t *testing.T) {
		fixture := newExperimentalAcquisitionFixture()
		dependencies := fixture.dependencies(t)
		dependencies.newOwner = func(*ebpf.Collection) (*experimentalCollectionOwner, error) {
			return nil, nil
		}
		_, err := acquireExperimentalFakeTCPCollection(
			t.Context(), canonicalExperimentalCollectionSpec(),
			"/reviewed/experimental.o", dependencies,
		)
		if err == nil || !strings.Contains(err.Error(), "factory returned nil owner") {
			t.Fatalf("nil owner error = %v", err)
		}
		if fixture.rawCloseCalls != 1 {
			t.Fatalf("nil owner raw close calls = %d, want 1", fixture.rawCloseCalls)
		}
	})
}

func TestExperimentalCollectionAcquisitionCancellationCheckpointsFailClosed(t *testing.T) {
	tests := []struct {
		name      string
		configure func(context.CancelFunc, *experimentalAcquisitionFixture, *experimentalCollectionAcquisitionDependencies)
		preCancel bool
		wantOrder string
		wantRaw   int
		wantOwned int
	}{
		{name: "before validation", preCancel: true},
		{
			name: "after kernel dependency probe",
			configure: func(cancel context.CancelFunc, fixture *experimentalAcquisitionFixture, dependencies *experimentalCollectionAcquisitionDependencies) {
				dependencies.probeKernelDependency = func() error {
					fixture.order = append(fixture.order, "kernel-dependency")
					cancel()
					return nil
				}
			},
			wantOrder: "kernel-dependency",
		},
		{
			name: "after memlock removal",
			configure: func(cancel context.CancelFunc, fixture *experimentalAcquisitionFixture, dependencies *experimentalCollectionAcquisitionDependencies) {
				dependencies.removeMemlock = func() error {
					fixture.order = append(fixture.order, "remove-memlock")
					cancel()
					return nil
				}
			},
			wantOrder: "kernel-dependency,remove-memlock",
		},
		{
			name: "after collection load",
			configure: func(cancel context.CancelFunc, fixture *experimentalAcquisitionFixture, dependencies *experimentalCollectionAcquisitionDependencies) {
				dependencies.newCollection = func(*ebpf.CollectionSpec) (*ebpf.Collection, error) {
					fixture.order = append(fixture.order, "new-collection")
					cancel()
					return fixture.raw, nil
				}
			},
			wantOrder: "kernel-dependency,remove-memlock,new-collection,close-raw",
			wantRaw:   1,
		},
		{
			name: "after owner transfer",
			configure: func(cancel context.CancelFunc, fixture *experimentalAcquisitionFixture, dependencies *experimentalCollectionAcquisitionDependencies) {
				dependencies.newOwner = func(*ebpf.Collection) (*experimentalCollectionOwner, error) {
					fixture.order = append(fixture.order, "new-owner")
					cancel()
					return fixture.owner, nil
				}
			},
			wantOrder: "kernel-dependency,remove-memlock,new-collection,new-owner,map:owned",
			wantOwned: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			fixture := newExperimentalAcquisitionFixture()
			dependencies := fixture.dependencies(t)
			if test.configure != nil {
				test.configure(cancel, fixture, &dependencies)
			}
			if test.preCancel {
				cancel()
			}
			owner, err := acquireExperimentalFakeTCPCollection(
				ctx, canonicalExperimentalCollectionSpec(),
				"/reviewed/experimental.o", dependencies,
			)
			if owner != nil || !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation result: owner=%v error=%v", owner, err)
			}
			if got := strings.Join(fixture.order, ","); got != test.wantOrder {
				t.Fatalf("cancellation order = %q, want %q", got, test.wantOrder)
			}
			if fixture.rawCloseCalls != test.wantRaw || fixture.ownedMap.closes != test.wantOwned {
				t.Fatalf(
					"cancellation close counts: raw=%d owner=%d, want raw=%d owner=%d",
					fixture.rawCloseCalls, fixture.ownedMap.closes, test.wantRaw, test.wantOwned,
				)
			}
		})
	}
}

func TestExperimentalKernelDependencyProbeRequiresExactModuleAndKfuncBTF(t *testing.T) {
	wantErr := errors.New("module missing")
	err := probeExperimentalFakeTCPKernelDependencyWith(
		func(module string) (*btf.Spec, error) {
			if module != experimentalFakeTCPKfuncModule {
				t.Fatalf("module=%q, want %q", module, experimentalFakeTCPKfuncModule)
			}
			return nil, wantErr
		},
	)
	if !errors.Is(err, wantErr) {
		t.Fatalf("module load error=%v, want wrapped %v", err, wantErr)
	}

	emptyBuilder, err := btf.NewBuilder(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	emptySpec, err := emptyBuilder.Spec()
	if err != nil {
		t.Fatal(err)
	}
	err = probeExperimentalFakeTCPKernelDependencyWith(
		func(string) (*btf.Spec, error) { return emptySpec, nil },
	)
	if err == nil || !strings.Contains(err.Error(), experimentalFakeTCPPrepareKfuncName) {
		t.Fatalf("missing kfunc BTF error=%v", err)
	}

	intType := &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}
	u32Type := &btf.Int{Name: "unsigned int", Size: 4, Encoding: btf.Unsigned}
	u64Type := &btf.Int{Name: "long unsigned int", Size: 8, Encoding: btf.Unsigned}
	skbType := &btf.Struct{Name: "__sk_buff", Size: 192}
	types := make([]btf.Type, 0, len(experimentalFakeTCPKfuncNames))
	for _, name := range experimentalFakeTCPKfuncNames {
		params := []btf.FuncParam{
			{Name: "ctx", Type: &btf.Pointer{Target: skbType}},
			{Name: "network_offset", Type: u32Type},
			{Name: "transport_offset", Type: u32Type},
			{Name: "udp_length", Type: u32Type},
		}
		if name == experimentalFakeTCPGSOCommitKfuncName {
			params[3].Name = "sequence"
			params = append(params, btf.FuncParam{Name: "ack_window", Type: u64Type})
		}
		types = append(types, &btf.Func{
			Name: name,
			Type: &btf.FuncProto{Return: intType, Params: params},
		})
	}
	builder, err := btf.NewBuilder(types, nil)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := builder.Spec()
	if err != nil {
		t.Fatal(err)
	}
	if err := probeExperimentalFakeTCPKernelDependencyWith(
		func(string) (*btf.Spec, error) { return spec, nil },
	); err != nil {
		t.Fatalf("exact module/kfunc BTF probe failed: %v", err)
	}

	wrongTypes := []btf.Type{
		&btf.Func{
			Name: experimentalFakeTCPPrepareKfuncName,
			Type: &btf.FuncProto{Return: intType, Params: []btf.FuncParam{
				{Name: "ctx", Type: &btf.Pointer{Target: skbType}},
				{Name: "network_offset", Type: u32Type},
				{Name: "transport_offset", Type: u32Type},
				{Name: "udp_length", Type: u64Type},
			}},
		},
		&btf.Func{
			Name: experimentalFakeTCPGSOCommitKfuncName,
			Type: &btf.FuncProto{Return: intType, Params: []btf.FuncParam{
				{Name: "ctx", Type: &btf.Pointer{Target: skbType}},
				{Name: "network_offset", Type: u32Type},
				{Name: "transport_offset", Type: u32Type},
				{Name: "sequence", Type: u32Type},
				{Name: "ack_window", Type: u64Type},
			}},
		},
	}
	wrongBuilder, err := btf.NewBuilder(wrongTypes, nil)
	if err != nil {
		t.Fatal(err)
	}
	wrongSpec, err := wrongBuilder.Spec()
	if err != nil {
		t.Fatal(err)
	}
	err = probeExperimentalFakeTCPKernelDependencyWith(
		func(string) (*btf.Spec, error) { return wrongSpec, nil },
	)
	if err == nil || !strings.Contains(err.Error(), "parameter 3") {
		t.Fatalf("incompatible kfunc prototype error=%v", err)
	}
}

func TestExperimentalVerifierLoaderRejectsEmptyPathBeforeEnvironmentFallback(t *testing.T) {
	t.Setenv(EnvObjectPath, "/must/not/be/used.o")
	for _, path := range []string{"", "\t\n"} {
		_, err := LoadExperimentalFakeTCPObjectTestIdentity(t.Context(), path)
		if err == nil || !strings.Contains(err.Error(), "explicit non-empty object path") {
			t.Fatalf("path=%q error=%v", path, err)
		}
	}
}

func TestLegacy515VerifierLoaderRejectsEmptyPathBeforeEnvironmentFallback(t *testing.T) {
	t.Setenv(EnvFakeTCPLegacy515ObjectPath, "/must/not/be/used.o")
	for _, path := range []string{"", "\t\n"} {
		_, err := LoadLegacy515FakeTCPObjectTestIdentity(t.Context(), path)
		if err == nil || !strings.Contains(err.Error(), "explicit non-empty object path") {
			t.Fatalf("path=%q error=%v", path, err)
		}
	}
}

func TestExperimentalVerifierLoaderSourceHasNoAttachPinOrMapMutationCalls(t *testing.T) {
	newCollectionCalls := 0
	for _, source := range []string{
		"experimental_acquire_linux.go",
		"experimental_load_linux.go",
	} {
		file, err := parser.ParseFile(token.NewFileSet(), source, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			callName := ""
			switch function := call.Fun.(type) {
			case *ast.Ident:
				callName = function.Name
			case *ast.SelectorExpr:
				callName = function.Sel.Name
				if packageName, ok := function.X.(*ast.Ident); ok &&
					packageName.Name == "ebpf" && callName == "NewCollection" {
					newCollectionCalls++
				}
			}
			lower := strings.ToLower(callName)
			if strings.Contains(lower, "attach") || strings.Contains(lower, "pin") ||
				strings.Contains(lower, "populate") || callName == "Update" ||
				callName == "Put" || callName == "Delete" {
				t.Errorf("load-only source %s contains forbidden kernel mutation call %q", source, callName)
			}
			return true
		})
	}
	if newCollectionCalls != 1 {
		t.Fatalf("ebpf.NewCollection calls = %d, want exactly 1", newCollectionCalls)
	}
}
