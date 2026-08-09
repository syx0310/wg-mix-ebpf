//go:build linux

package dataplane

import (
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
)

type fakeOwnedXDPLink struct {
	mu sync.Mutex

	identity      fakeTCPXDPLinkIdentity
	identityErr   error
	releaseErrs   []error
	retainOnError []bool
	identityCalls int
	releaseCalls  int
	closes        int
	closeLog      *[]int
	closeEvents   *[]string
}

func (owned *fakeOwnedXDPLink) Identity() (fakeTCPXDPLinkIdentity, error) {
	owned.mu.Lock()
	defer owned.mu.Unlock()
	owned.identityCalls++
	return owned.identity, owned.identityErr
}

func (owned *fakeOwnedXDPLink) Release(
	expected fakeTCPXDPLinkIdentity,
) (fakeTCPXDPReleaseResult, error) {
	owned.mu.Lock()
	defer owned.mu.Unlock()
	owned.releaseCalls++
	result := fakeTCPXDPReleaseResult{Observed: owned.identity}
	if owned.identityErr != nil {
		return result, owned.identityErr
	}
	if owned.identity != expected {
		return result, errors.New("injected stale XDP owner identity")
	}
	if owned.closeEvents != nil {
		*owned.closeEvents = append(*owned.closeEvents, "xdp-close")
	}
	if owned.closeLog != nil {
		*owned.closeLog = append(*owned.closeLog, owned.identity.IfIndex)
	}
	owned.closes++
	var err error
	if len(owned.releaseErrs) > 0 {
		err = owned.releaseErrs[0]
		owned.releaseErrs = owned.releaseErrs[1:]
	}
	retained := false
	if len(owned.retainOnError) > 0 {
		retained = owned.retainOnError[0]
		owned.retainOnError = owned.retainOnError[1:]
	}
	result.Released = err == nil || !retained
	return result, err
}

func (owned *fakeOwnedXDPLink) setIdentity(identity fakeTCPXDPLinkIdentity) {
	owned.mu.Lock()
	owned.identity = identity
	owned.mu.Unlock()
}

type memoryFakeTCPXDPRuntime struct {
	mu sync.Mutex

	family       fakeTCPXDPBackendFamily
	capabilities fakeTCPXDPBackendCapabilities
	detectErr    error
	probes       map[int]fakeTCPXDPProbe
	probeErrs    map[int]error
	attachErrs   map[int]error
	links        map[int]*fakeOwnedXDPLink
	detectCalls  int
	probeCalls   []int
	attachCalls  []fakeTCPXDPAttachRequest
	attachProbes []fakeTCPXDPProbe
	events       *[]string
}

func (runtime *memoryFakeTCPXDPRuntime) backend() fakeTCPXDPRuntime {
	backend, err := newFakeTCPXDPRuntime(
		func() (fakeTCPXDPBackendCapabilities, error) {
			runtime.mu.Lock()
			defer runtime.mu.Unlock()
			runtime.detectCalls++
			return runtime.capabilities, runtime.detectErr
		},
		func(ifindex int) (fakeTCPXDPProbe, error) {
			runtime.mu.Lock()
			defer runtime.mu.Unlock()
			if runtime.events != nil {
				*runtime.events = append(*runtime.events, "xdp-probe")
			}
			runtime.probeCalls = append(runtime.probeCalls, ifindex)
			if err := runtime.probeErrs[ifindex]; err != nil {
				return fakeTCPXDPProbe{}, err
			}
			probe, exists := runtime.probes[ifindex]
			if !exists {
				probe = fakeTCPXDPProbe{IfIndex: ifindex}
			}
			return probe, nil
		},
		func(
			request fakeTCPXDPAttachRequest,
			expected fakeTCPXDPProbe,
			program experimentalProgramResource,
		) (fakeTCPXDPLink, error) {
			runtime.mu.Lock()
			defer runtime.mu.Unlock()
			if runtime.events != nil {
				*runtime.events = append(*runtime.events, "xdp-attach")
			}
			runtime.attachCalls = append(runtime.attachCalls, request)
			runtime.attachProbes = append(runtime.attachProbes, expected)
			owned := runtime.links[request.IfIndex]
			if owned == nil {
				programID, err := program.ID()
				if err != nil {
					return nil, err
				}
				identity := fakeTCPXDPLinkIdentity{
					Family: runtime.family, Mode: request.Mode,
					IfIndex: request.IfIndex, ProgramID: programID,
					OwnerID: uint64(100000 + request.IfIndex),
				}
				if runtime.family == fakeTCPXDPBackendLibXDP {
					identity.DispatcherProgramID = expected.ProgramID
					identity.DispatcherID = expected.DispatcherID
				}
				owned = &fakeOwnedXDPLink{
					identity: identity, closeEvents: runtime.events,
				}
				runtime.links[request.IfIndex] = owned
			}
			return owned, runtime.attachErrs[request.IfIndex]
		},
	)
	if err != nil {
		panic(err)
	}
	return backend
}

func newMemoryFakeTCPXDPRuntime() *memoryFakeTCPXDPRuntime {
	return newMemoryFakeTCPXDPRuntimeFor(fakeTCPXDPBackendDirect)
}

func newMemoryFakeTCPXDPRuntimeFor(
	family fakeTCPXDPBackendFamily,
) *memoryFakeTCPXDPRuntime {
	capabilities := fakeTCPXDPBackendCapabilities{
		Family: family, APIVersion: 1,
		Guarantee:               fakeTCPXDPExactSelectedModeLink,
		Scope:                   fakeTCPXDPOwnershipSelectedMode,
		ExactDispatcherIdentity: family == fakeTCPXDPBackendLibXDP,
	}
	if family == fakeTCPXDPBackendLibXDP {
		capabilities.Guarantee = fakeTCPXDPExactDispatcherComponent
		capabilities.Scope = fakeTCPXDPOwnershipAllHooks
	}
	return &memoryFakeTCPXDPRuntime{
		family: family, capabilities: capabilities,
		probes: make(map[int]fakeTCPXDPProbe), probeErrs: make(map[int]error),
		attachErrs: make(map[int]error), links: make(map[int]*fakeOwnedXDPLink),
	}
}

func directXDPIdentity(ifindex int, mode fakeTCPXDPAttachMode) fakeTCPXDPLinkIdentity {
	return fakeTCPXDPLinkIdentity{
		Family: fakeTCPXDPBackendDirect, Mode: mode, IfIndex: ifindex,
		ProgramID: 8001, OwnerID: uint64(100000 + ifindex),
	}
}

func TestFakeTCPXDPStageProbesThenOwnsSortedDirectLinks(t *testing.T) {
	runtime := newMemoryFakeTCPXDPRuntime()
	stage, err := stageFakeTCPXDPAttachments(
		t.Context(),
		[]fakeTCPXDPAttachRequest{
			{IfIndex: 11, Mode: fakeTCPXDPAttachGeneric},
			{IfIndex: 7, Mode: fakeTCPXDPAttachNative},
		},
		&fakeExperimentalOwnedProgram{id: 8001}, runtime.backend(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(runtime.probeCalls, []int{7, 11}) {
		t.Fatalf("probe order = %v", runtime.probeCalls)
	}
	if got := []int{runtime.attachCalls[0].IfIndex, runtime.attachCalls[1].IfIndex}; !slices.Equal(got, []int{7, 11}) {
		t.Fatalf("attach order = %v", got)
	}
	if !slices.Equal(runtime.attachProbes, []fakeTCPXDPProbe{{IfIndex: 7}, {IfIndex: 11}}) {
		t.Fatalf("attach expected probes = %+v", runtime.attachProbes)
	}
	if err := stage.Close(); err != nil {
		t.Fatal(err)
	}
	if runtime.links[7].closes != 1 || runtime.links[11].closes != 1 {
		t.Fatalf("owned links were not released once: 7=%d 11=%d",
			runtime.links[7].closes, runtime.links[11].closes)
	}
	if err := stage.Close(); err != nil || runtime.links[7].closes != 1 {
		t.Fatalf("idempotent close error=%v closes=%d", err, runtime.links[7].closes)
	}
}

func TestFakeTCPXDPStageRefusesUnownedReplacementBeforeAttach(t *testing.T) {
	runtime := newMemoryFakeTCPXDPRuntime()
	runtime.probes[7] = fakeTCPXDPProbe{IfIndex: 7, Attached: true, ProgramID: 7001}
	stage, err := stageFakeTCPXDPAttachments(
		t.Context(),
		[]fakeTCPXDPAttachRequest{{IfIndex: 7, Mode: fakeTCPXDPAttachNative}},
		&fakeExperimentalOwnedProgram{id: 8001}, runtime.backend(),
	)
	if stage != nil || err == nil || !strings.Contains(err.Error(), "replacement is refused") {
		t.Fatalf("stage=%#v error=%v", stage, err)
	}
	if len(runtime.attachCalls) != 0 {
		t.Fatalf("occupied XDP hook reached attach: %v", runtime.attachCalls)
	}
}

func TestFakeTCPXDPStageCompletesSingleProbePassBeforeMutation(t *testing.T) {
	runtime := newMemoryFakeTCPXDPRuntime()
	runtime.probes[11] = fakeTCPXDPProbe{IfIndex: 11, Attached: true, ProgramID: 7001}
	stage, err := stageFakeTCPXDPAttachments(
		t.Context(),
		[]fakeTCPXDPAttachRequest{
			{IfIndex: 7, Mode: fakeTCPXDPAttachNative},
			{IfIndex: 11, Mode: fakeTCPXDPAttachGeneric},
		},
		&fakeExperimentalOwnedProgram{id: 8001}, runtime.backend(),
	)
	if stage != nil || err == nil || !strings.Contains(err.Error(), "replacement is refused") {
		t.Fatalf("stage=%#v error=%v", stage, err)
	}
	if !slices.Equal(runtime.probeCalls, []int{7, 11}) || len(runtime.attachCalls) != 0 {
		t.Fatalf("probes=%v attaches=%v", runtime.probeCalls, runtime.attachCalls)
	}
}

func TestFakeTCPXDPRuntimeDetectsCapabilitiesOnlyAtConstruction(t *testing.T) {
	runtime := newMemoryFakeTCPXDPRuntime()
	backend := runtime.backend()
	if runtime.detectCalls != 1 {
		t.Fatalf("constructor capability detections = %d", runtime.detectCalls)
	}
	for _, ifindex := range []int{7, 11} {
		stage, err := stageFakeTCPXDPAttachments(
			t.Context(),
			[]fakeTCPXDPAttachRequest{{IfIndex: ifindex, Mode: fakeTCPXDPAttachNative}},
			&fakeExperimentalOwnedProgram{id: 8001}, backend,
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := stage.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if runtime.detectCalls != 1 {
		t.Fatalf("runtime repeated capability detection %d times", runtime.detectCalls)
	}
}

func TestFakeTCPXDPDirectCapabilityIsSelectedModeOnly(t *testing.T) {
	for _, mutate := range []func(*fakeTCPXDPBackendCapabilities){
		func(capabilities *fakeTCPXDPBackendCapabilities) {
			capabilities.Guarantee = fakeTCPXDPExactDispatcherComponent
		},
		func(capabilities *fakeTCPXDPBackendCapabilities) {
			capabilities.Scope = fakeTCPXDPOwnershipAllHooks
		},
	} {
		capabilities := newMemoryFakeTCPXDPRuntime().capabilities
		mutate(&capabilities)
		_, err := newFakeTCPXDPRuntime(
			func() (fakeTCPXDPBackendCapabilities, error) { return capabilities, nil },
			func(int) (fakeTCPXDPProbe, error) { return fakeTCPXDPProbe{}, nil },
			func(fakeTCPXDPAttachRequest, fakeTCPXDPProbe, experimentalProgramResource) (fakeTCPXDPLink, error) {
				t.Fatal("invalid direct capability reached attach")
				return nil, nil
			},
		)
		if err == nil || !strings.Contains(err.Error(), "selected-mode bpf_link") {
			t.Fatalf("constructor error = %v", err)
		}
	}
}

func TestFakeTCPXDPSelectedModeOwnerDoesNotClaimHardwareRace(t *testing.T) {
	runtime := newMemoryFakeTCPXDPRuntime()
	backend := runtime.backend()
	attach := backend.attach
	var foreignHardwareProgramID uint32
	backend.attach = func(
		request fakeTCPXDPAttachRequest,
		probe fakeTCPXDPProbe,
		program experimentalProgramResource,
	) (fakeTCPXDPLink, error) {
		// Model a foreign hardware-mode attachment appearing after the
		// compatibility snapshot and before the selected native-mode attach.
		foreignHardwareProgramID = 7001
		return attach(request, probe, program)
	}
	stage, err := stageFakeTCPXDPAttachments(
		t.Context(),
		[]fakeTCPXDPAttachRequest{{IfIndex: 7, Mode: fakeTCPXDPAttachNative}},
		&fakeExperimentalOwnedProgram{id: 8001},
		backend,
	)
	if err != nil {
		t.Fatal(err)
	}
	if backend.capabilities.Scope != fakeTCPXDPOwnershipSelectedMode ||
		foreignHardwareProgramID != 7001 {
		t.Fatalf("scope=%d foreign hardware program=%d",
			backend.capabilities.Scope, foreignHardwareProgramID)
	}
	if err := stage.Close(); err != nil {
		t.Fatal(err)
	}
	if foreignHardwareProgramID != 7001 || runtime.links[7].closes != 1 {
		t.Fatalf("foreign hardware program=%d selected closes=%d",
			foreignHardwareProgramID, runtime.links[7].closes)
	}
}

func TestFakeTCPXDPRuntimeRejectsUnprovenLibXDPCapability(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*fakeTCPXDPBackendCapabilities)
		match  string
	}{
		{name: "api", mutate: func(cap *fakeTCPXDPBackendCapabilities) { cap.APIVersion = 0 }, match: "not proven"},
		{name: "dispatcher component", mutate: func(cap *fakeTCPXDPBackendCapabilities) { cap.Guarantee = 0 }, match: "not proven"},
		{name: "all hooks", mutate: func(cap *fakeTCPXDPBackendCapabilities) { cap.Scope = fakeTCPXDPOwnershipSelectedMode }, match: "not proven"},
		{name: "dispatcher identity", mutate: func(cap *fakeTCPXDPBackendCapabilities) { cap.ExactDispatcherIdentity = false }, match: "dispatcher identity"},
	} {
		t.Run(test.name, func(t *testing.T) {
			capabilities := fakeTCPXDPBackendCapabilities{
				Family: fakeTCPXDPBackendLibXDP, APIVersion: 1,
				Guarantee:               fakeTCPXDPExactDispatcherComponent,
				Scope:                   fakeTCPXDPOwnershipAllHooks,
				ExactDispatcherIdentity: true,
			}
			test.mutate(&capabilities)
			_, err := newFakeTCPXDPRuntime(
				func() (fakeTCPXDPBackendCapabilities, error) { return capabilities, nil },
				func(int) (fakeTCPXDPProbe, error) { return fakeTCPXDPProbe{}, nil },
				func(fakeTCPXDPAttachRequest, fakeTCPXDPProbe, experimentalProgramResource) (fakeTCPXDPLink, error) {
					t.Fatal("unproven backend reached attach")
					return nil, nil
				},
			)
			if err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("constructor error = %v", err)
			}
		})
	}
}

func TestFakeTCPXDPStageRequiresExactLibXDPDispatcherAndOwner(t *testing.T) {
	runtime := newMemoryFakeTCPXDPRuntimeFor(fakeTCPXDPBackendLibXDP)
	backend := runtime.backend()
	request := []fakeTCPXDPAttachRequest{{IfIndex: 7, Mode: fakeTCPXDPAttachLibXDP}}
	for _, probe := range []fakeTCPXDPProbe{
		{IfIndex: 7, Attached: true, ProgramID: 7001, Dispatcher: true},
		{IfIndex: 7, Attached: true, ProgramID: 7001, DispatcherID: 77},
	} {
		runtime.probes[7] = probe
		stage, err := stageFakeTCPXDPAttachments(
			t.Context(), request, &fakeExperimentalOwnedProgram{id: 8001}, backend,
		)
		if stage != nil || err == nil || !strings.Contains(err.Error(), "dispatcher identity") {
			t.Fatalf("probe=%+v stage=%#v error=%v", probe, stage, err)
		}
	}
	runtime.probes[7] = fakeTCPXDPProbe{
		IfIndex: 7, Attached: true, ProgramID: 7001,
		Dispatcher: true, DispatcherID: 77,
	}
	stage, err := stageFakeTCPXDPAttachments(
		t.Context(), request, &fakeExperimentalOwnedProgram{id: 8001}, backend,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := stage.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestFakeTCPXDPStageQuarantinesChangedLibXDPDispatcher(t *testing.T) {
	runtime := newMemoryFakeTCPXDPRuntimeFor(fakeTCPXDPBackendLibXDP)
	runtime.probes[7] = fakeTCPXDPProbe{
		IfIndex: 7, Attached: true, ProgramID: 7001,
		Dispatcher: true, DispatcherID: 77,
	}
	runtime.links[7] = &fakeOwnedXDPLink{identity: fakeTCPXDPLinkIdentity{
		Family: fakeTCPXDPBackendLibXDP, Mode: fakeTCPXDPAttachLibXDP,
		IfIndex: 7, ProgramID: 8001, OwnerID: 9001,
		DispatcherProgramID: 7002, DispatcherID: 78,
	}}
	stage, err := stageFakeTCPXDPAttachments(
		t.Context(),
		[]fakeTCPXDPAttachRequest{{IfIndex: 7, Mode: fakeTCPXDPAttachLibXDP}},
		&fakeExperimentalOwnedProgram{id: 8001}, runtime.backend(),
	)
	if stage == nil || err == nil || !strings.Contains(err.Error(), "does not match dispatcher") {
		t.Fatalf("stage=%#v error=%v", stage, err)
	}
	if closeErr := stage.Close(); closeErr == nil ||
		!strings.Contains(closeErr.Error(), "never verified") {
		t.Fatalf("changed-dispatcher Close error=%v", closeErr)
	}
	if runtime.links[7].releaseCalls != 0 || runtime.links[7].closes != 0 {
		t.Fatalf("changed dispatcher reached release calls=%d closes=%d",
			runtime.links[7].releaseCalls, runtime.links[7].closes)
	}
}

func TestFakeTCPXDPStageDoesNotFallbackBetweenConstructedBackends(t *testing.T) {
	for _, test := range []struct {
		name   string
		family fakeTCPXDPBackendFamily
		mode   fakeTCPXDPAttachMode
	}{
		{name: "direct to libxdp", family: fakeTCPXDPBackendDirect, mode: fakeTCPXDPAttachLibXDP},
		{name: "libxdp to native", family: fakeTCPXDPBackendLibXDP, mode: fakeTCPXDPAttachNative},
		{name: "libxdp to generic", family: fakeTCPXDPBackendLibXDP, mode: fakeTCPXDPAttachGeneric},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime := newMemoryFakeTCPXDPRuntimeFor(test.family)
			stage, err := stageFakeTCPXDPAttachments(
				t.Context(),
				[]fakeTCPXDPAttachRequest{{IfIndex: 7, Mode: test.mode}},
				&fakeExperimentalOwnedProgram{id: 8001}, runtime.backend(),
			)
			if stage != nil || err == nil || !strings.Contains(err.Error(), "does not match constructed") {
				t.Fatalf("stage=%#v error=%v", stage, err)
			}
			if len(runtime.probeCalls) != 0 || len(runtime.attachCalls) != 0 {
				t.Fatalf("fallback reached probes=%v attaches=%v", runtime.probeCalls, runtime.attachCalls)
			}
		})
	}
}

func TestFakeTCPXDPStageReturnsAdoptedPrefixOnLaterFailure(t *testing.T) {
	runtime := newMemoryFakeTCPXDPRuntime()
	runtime.attachErrs[11] = errors.New("injected attach failure")
	stage, err := stageFakeTCPXDPAttachments(
		t.Context(),
		[]fakeTCPXDPAttachRequest{
			{IfIndex: 7, Mode: fakeTCPXDPAttachNative},
			{IfIndex: 11, Mode: fakeTCPXDPAttachGeneric},
		},
		&fakeExperimentalOwnedProgram{id: 8001}, runtime.backend(),
	)
	if stage == nil || err == nil || !strings.Contains(err.Error(), "injected attach failure") {
		t.Fatalf("stage=%#v error=%v", stage, err)
	}
	// The backend returned an exact owner with the error, so both mutations
	// are represented and safe to roll back.
	if err := stage.Close(); err != nil {
		t.Fatal(err)
	}
	if runtime.links[7].closes != 1 || runtime.links[11].closes != 1 {
		t.Fatalf("adopted rollback closes: 7=%d 11=%d",
			runtime.links[7].closes, runtime.links[11].closes)
	}
}

func TestFakeTCPXDPStageRetriesOnlyRetainedRelease(t *testing.T) {
	runtime := newMemoryFakeTCPXDPRuntime()
	var closeLog []int
	wantErr := errors.New("injected XDP release failure")
	runtime.links[7] = &fakeOwnedXDPLink{
		identity:    directXDPIdentity(7, fakeTCPXDPAttachNative),
		releaseErrs: []error{wantErr}, retainOnError: []bool{true}, closeLog: &closeLog,
	}
	runtime.links[11] = &fakeOwnedXDPLink{
		identity: directXDPIdentity(11, fakeTCPXDPAttachGeneric), closeLog: &closeLog,
	}
	stage, err := stageFakeTCPXDPAttachments(
		t.Context(),
		[]fakeTCPXDPAttachRequest{
			{IfIndex: 7, Mode: fakeTCPXDPAttachNative},
			{IfIndex: 11, Mode: fakeTCPXDPAttachGeneric},
		},
		&fakeExperimentalOwnedProgram{id: 8001}, runtime.backend(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := stage.Close(); !errors.Is(err, wantErr) {
		t.Fatalf("first close error = %v", err)
	}
	if !slices.Equal(closeLog, []int{11, 7}) {
		t.Fatalf("first reverse close order = %v", closeLog)
	}
	if err := stage.Close(); err != nil {
		t.Fatalf("retry close error: %v", err)
	}
	if !slices.Equal(closeLog, []int{11, 7, 7}) || runtime.links[7].closes != 2 ||
		runtime.links[11].closes != 1 {
		t.Fatalf("retry close log=%v link7=%d link11=%d",
			closeLog, runtime.links[7].closes, runtime.links[11].closes)
	}
}

func TestFakeTCPXDPStageConsumedReleaseErrorConvergesWithoutRetryingFD(t *testing.T) {
	runtime := newMemoryFakeTCPXDPRuntime()
	wantErr := errors.New("injected consumed close error")
	runtime.links[7] = &fakeOwnedXDPLink{
		identity:    directXDPIdentity(7, fakeTCPXDPAttachNative),
		releaseErrs: []error{wantErr}, retainOnError: []bool{false},
	}
	stage, err := stageFakeTCPXDPAttachments(
		t.Context(),
		[]fakeTCPXDPAttachRequest{{IfIndex: 7, Mode: fakeTCPXDPAttachNative}},
		&fakeExperimentalOwnedProgram{id: 8001}, runtime.backend(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := stage.Close(); !errors.Is(err, wantErr) {
		t.Fatalf("first Close = %v", err)
	}
	if err := stage.Close(); err != nil {
		t.Fatalf("converged Close = %v", err)
	}
	if runtime.links[7].closes != 1 {
		t.Fatalf("consumed owner release attempts = %d", runtime.links[7].closes)
	}
}

func TestFakeTCPXDPStageIdentityFailureQuarantinesWithoutRelease(t *testing.T) {
	runtime := newMemoryFakeTCPXDPRuntime()
	runtime.links[7] = &fakeOwnedXDPLink{
		identity: fakeTCPXDPLinkIdentity{
			Family: fakeTCPXDPBackendDirect, Mode: fakeTCPXDPAttachNative,
			IfIndex: 8, ProgramID: 8001, OwnerID: 100008,
		},
	}
	stage, err := stageFakeTCPXDPAttachments(
		t.Context(),
		[]fakeTCPXDPAttachRequest{{IfIndex: 7, Mode: fakeTCPXDPAttachNative}},
		&fakeExperimentalOwnedProgram{id: 8001}, runtime.backend(),
	)
	if stage == nil || err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("stage=%#v error=%v", stage, err)
	}
	if closeErr := stage.Close(); closeErr == nil ||
		!strings.Contains(closeErr.Error(), "never verified") {
		t.Fatalf("unverified Close error=%v", closeErr)
	}
	if runtime.links[7].releaseCalls != 0 || runtime.links[7].closes != 0 {
		t.Fatalf("unverified owner reached release: calls=%d closes=%d",
			runtime.links[7].releaseCalls, runtime.links[7].closes)
	}
}

func TestFakeTCPXDPStageRejectsStaleIdentityBeforeDestructiveRelease(t *testing.T) {
	runtime := newMemoryFakeTCPXDPRuntime()
	stage, err := stageFakeTCPXDPAttachments(
		t.Context(),
		[]fakeTCPXDPAttachRequest{{IfIndex: 7, Mode: fakeTCPXDPAttachNative}},
		&fakeExperimentalOwnedProgram{id: 8001}, runtime.backend(),
	)
	if err != nil {
		t.Fatal(err)
	}
	stale := directXDPIdentity(7, fakeTCPXDPAttachNative)
	stale.OwnerID++
	runtime.links[7].setIdentity(stale)
	if err := stage.Close(); err == nil || !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("stale Close error=%v", err)
	}
	if runtime.links[7].closes != 0 {
		t.Fatalf("stale identity triggered %d destructive closes", runtime.links[7].closes)
	}
	// Once stale, even restoring the numeric identity cannot authorize a
	// release: kernel IDs may have been recycled in the interim.
	runtime.links[7].setIdentity(directXDPIdentity(7, fakeTCPXDPAttachNative))
	if err := stage.Close(); err == nil || !strings.Contains(err.Error(), "is stale") {
		t.Fatalf("stale retry error=%v", err)
	}
	if runtime.links[7].releaseCalls != 1 || runtime.links[7].closes != 0 {
		t.Fatalf("stale retries release calls=%d closes=%d",
			runtime.links[7].releaseCalls, runtime.links[7].closes)
	}
}

func TestFakeTCPXDPStageConcurrentCloseReleasesEachOwnerOnce(t *testing.T) {
	runtime := newMemoryFakeTCPXDPRuntime()
	stage, err := stageFakeTCPXDPAttachments(
		t.Context(),
		[]fakeTCPXDPAttachRequest{
			{IfIndex: 7, Mode: fakeTCPXDPAttachNative},
			{IfIndex: 11, Mode: fakeTCPXDPAttachGeneric},
		},
		&fakeExperimentalOwnedProgram{id: 8001}, runtime.backend(),
	)
	if err != nil {
		t.Fatal(err)
	}
	const contenders = 32
	start := make(chan struct{})
	errs := make(chan error, contenders)
	var wait sync.WaitGroup
	for range contenders {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			errs <- stage.Close()
		}()
	}
	close(start)
	wait.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	for ifindex, owned := range runtime.links {
		if owned.closes != 1 || owned.releaseCalls != 1 {
			t.Fatalf("ifindex %d closes=%d releases=%d",
				ifindex, owned.closes, owned.releaseCalls)
		}
	}
}
