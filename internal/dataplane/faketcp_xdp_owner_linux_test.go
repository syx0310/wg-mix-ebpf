//go:build linux

package dataplane

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

type fakeOwnedXDPLink struct {
	ifindex     int
	programID   uint32
	identityErr error
	closeErrs   []error
	closes      int
	closeLog    *[]int
}

func (owned *fakeOwnedXDPLink) Identity() (int, uint32, error) {
	return owned.ifindex, owned.programID, owned.identityErr
}

func (owned *fakeOwnedXDPLink) Close() error {
	owned.closes++
	if owned.closeLog != nil {
		*owned.closeLog = append(*owned.closeLog, owned.ifindex)
	}
	if len(owned.closeErrs) == 0 {
		return nil
	}
	err := owned.closeErrs[0]
	owned.closeErrs = owned.closeErrs[1:]
	return err
}

type memoryFakeTCPXDPRuntime struct {
	probes      map[int]fakeTCPXDPProbe
	probeErrs   map[int]error
	attachErrs  map[int]error
	links       map[int]*fakeOwnedXDPLink
	probeCalls  []int
	attachCalls []fakeTCPXDPAttachRequest
	events      *[]string
}

func (runtime *memoryFakeTCPXDPRuntime) backend() fakeTCPXDPRuntime {
	return fakeTCPXDPRuntime{
		probe: func(ifindex int) (fakeTCPXDPProbe, error) {
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
		attach: func(
			request fakeTCPXDPAttachRequest,
			program experimentalProgramResource,
		) (fakeTCPXDPLink, error) {
			if runtime.events != nil {
				*runtime.events = append(*runtime.events, "xdp-attach")
			}
			runtime.attachCalls = append(runtime.attachCalls, request)
			if err := runtime.attachErrs[request.IfIndex]; err != nil {
				return nil, err
			}
			owned := runtime.links[request.IfIndex]
			if owned == nil {
				programID, err := program.ID()
				if err != nil {
					return nil, err
				}
				owned = &fakeOwnedXDPLink{ifindex: request.IfIndex, programID: programID}
				runtime.links[request.IfIndex] = owned
			}
			return owned, nil
		},
	}
}

func newMemoryFakeTCPXDPRuntime() *memoryFakeTCPXDPRuntime {
	return &memoryFakeTCPXDPRuntime{
		probes: make(map[int]fakeTCPXDPProbe), probeErrs: make(map[int]error),
		attachErrs: make(map[int]error), links: make(map[int]*fakeOwnedXDPLink),
	}
}

func TestFakeTCPXDPStageProbesThenOwnsSortedNativeAndGenericLinks(t *testing.T) {
	runtime := newMemoryFakeTCPXDPRuntime()
	stage, err := stageFakeTCPXDPAttachments(
		t.Context(),
		[]fakeTCPXDPAttachRequest{
			{IfIndex: 11, Mode: fakeTCPXDPAttachGeneric},
			{IfIndex: 7, Mode: fakeTCPXDPAttachNative},
		},
		&fakeExperimentalOwnedProgram{id: 8001},
		runtime.backend(),
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
	if err := stage.Close(); err != nil {
		t.Fatal(err)
	}
	if runtime.links[7].closes != 1 || runtime.links[11].closes != 1 {
		t.Fatalf("owned links were not closed once: 7=%d 11=%d",
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

func TestFakeTCPXDPStageCompletesAllProbesBeforeFirstAttach(t *testing.T) {
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

func TestFakeTCPXDPStageRequiresProvenLibXDPChaining(t *testing.T) {
	for _, test := range []struct {
		name      string
		probe     fakeTCPXDPProbe
		wantError bool
	}{
		{name: "plain program", probe: fakeTCPXDPProbe{IfIndex: 7, Attached: true, ProgramID: 7001}, wantError: true},
		{name: "dispatcher without API", probe: fakeTCPXDPProbe{IfIndex: 7, Attached: true, ProgramID: 7001, Dispatcher: true}, wantError: true},
		{name: "proven chaining", probe: fakeTCPXDPProbe{IfIndex: 7, Attached: true, ProgramID: 7001, Dispatcher: true, ChainingAvailable: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime := newMemoryFakeTCPXDPRuntime()
			runtime.probes[7] = test.probe
			stage, err := stageFakeTCPXDPAttachments(
				t.Context(),
				[]fakeTCPXDPAttachRequest{{IfIndex: 7, Mode: fakeTCPXDPAttachLibXDP}},
				&fakeExperimentalOwnedProgram{id: 8001}, runtime.backend(),
			)
			if test.wantError {
				if stage != nil || err == nil || !strings.Contains(err.Error(), "not proven") {
					t.Fatalf("stage=%#v error=%v", stage, err)
				}
				if len(runtime.attachCalls) != 0 {
					t.Fatalf("unproven chaining reached attach: %v", runtime.attachCalls)
				}
				return
			}
			if err != nil || stage == nil || len(runtime.attachCalls) != 1 {
				t.Fatalf("proven chaining stage=%#v error=%v attaches=%v", stage, err, runtime.attachCalls)
			}
			if err := stage.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFakeTCPXDPStageReturnsOwnedPrefixOnLaterFailure(t *testing.T) {
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
	if err := stage.Close(); err != nil {
		t.Fatal(err)
	}
	if runtime.links[7].closes != 1 {
		t.Fatalf("owned prefix close count = %d", runtime.links[7].closes)
	}
}

func TestFakeTCPXDPStageRetainsCloseErrorWithoutDoubleClose(t *testing.T) {
	runtime := newMemoryFakeTCPXDPRuntime()
	var closeLog []int
	wantErr := errors.New("injected XDP close failure")
	runtime.links[7] = &fakeOwnedXDPLink{
		ifindex: 7, programID: 8001, closeErrs: []error{wantErr}, closeLog: &closeLog,
	}
	runtime.links[11] = &fakeOwnedXDPLink{ifindex: 11, programID: 8001, closeLog: &closeLog}
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
	if err := stage.Close(); !errors.Is(err, wantErr) {
		t.Fatalf("retained close error: %v", err)
	}
	if !slices.Equal(closeLog, []int{11, 7}) || runtime.links[7].closes != 1 ||
		runtime.links[11].closes != 1 {
		t.Fatalf("retained close log=%v link7=%d link11=%d",
			closeLog, runtime.links[7].closes, runtime.links[11].closes)
	}
}

func TestFakeTCPXDPStageIdentityFailureRetainsLinkForRollback(t *testing.T) {
	runtime := newMemoryFakeTCPXDPRuntime()
	runtime.links[7] = &fakeOwnedXDPLink{ifindex: 8, programID: 8001}
	stage, err := stageFakeTCPXDPAttachments(
		t.Context(),
		[]fakeTCPXDPAttachRequest{{IfIndex: 7, Mode: fakeTCPXDPAttachNative}},
		&fakeExperimentalOwnedProgram{id: 8001}, runtime.backend(),
	)
	if stage == nil || err == nil || !strings.Contains(err.Error(), "link identity") {
		t.Fatalf("stage=%#v error=%v", stage, err)
	}
	if err := stage.Close(); err != nil || runtime.links[7].closes != 1 {
		t.Fatalf("identity-failure rollback error=%v closes=%d", err, runtime.links[7].closes)
	}
}
