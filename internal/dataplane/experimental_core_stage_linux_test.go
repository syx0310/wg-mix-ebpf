//go:build linux

package dataplane

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

type coreMemoryMapKind uint8

const (
	coreMemoryHash coreMemoryMapKind = iota
	coreMemoryControl
	coreMemoryProgramArray
)

type coreMemoryMap struct {
	name          string
	kind          coreMemoryMapKind
	entries       map[any]any
	events        *[]string
	programIDs    map[uint32]uint32
	failLookup    error
	failUpdate    error
	corruptUpdate any
}

func (memory *coreMemoryMap) Lookup(key, valueOut any) error {
	*memory.events = append(*memory.events, "lookup:"+memory.name)
	if memory.failLookup != nil {
		err := memory.failLookup
		memory.failLookup = nil
		return err
	}
	value, exists := memory.entries[key]
	if !exists {
		return ebpf.ErrKeyNotExist
	}
	target := reflect.ValueOf(valueOut)
	if target.Kind() != reflect.Pointer || target.IsNil() {
		return errors.New("lookup target is not a pointer")
	}
	source := reflect.ValueOf(value)
	if !source.Type().AssignableTo(target.Elem().Type()) {
		return fmt.Errorf("cannot assign %s to %s", source.Type(), target.Elem().Type())
	}
	target.Elem().Set(source)
	return nil
}

func (memory *coreMemoryMap) Update(
	key, value any,
	flags ebpf.MapUpdateFlags,
) error {
	*memory.events = append(*memory.events, "update:"+memory.name)
	if memory.failUpdate != nil {
		err := memory.failUpdate
		memory.failUpdate = nil
		return err
	}
	switch memory.kind {
	case coreMemoryHash:
		if flags != ebpf.UpdateNoExist {
			return fmt.Errorf("hash flags = %v", flags)
		}
		if _, exists := memory.entries[key]; exists {
			return ebpf.ErrKeyExist
		}
	case coreMemoryControl, coreMemoryProgramArray:
		if flags != ebpf.UpdateAny {
			return fmt.Errorf("array flags = %v", flags)
		}
	}
	stored := value
	if memory.kind == coreMemoryProgramArray {
		fd, ok := value.(uint32)
		if !ok {
			return fmt.Errorf("program FD type = %T", value)
		}
		programID, ok := memory.programIDs[fd]
		if !ok {
			return fmt.Errorf("unknown program FD %d", fd)
		}
		stored = programID
	}
	if memory.corruptUpdate != nil {
		stored = memory.corruptUpdate
		memory.corruptUpdate = nil
	}
	memory.entries[key] = stored
	return nil
}

func (memory *coreMemoryMap) Delete(key any) error {
	*memory.events = append(*memory.events, "delete:"+memory.name)
	if _, exists := memory.entries[key]; !exists {
		return ebpf.ErrKeyNotExist
	}
	delete(memory.entries, key)
	return nil
}

func (*coreMemoryMap) Close() error { return nil }

type coreStageFixture struct {
	owner      *experimentalCollectionOwner
	maps       map[string]*coreMemoryMap
	events     []string
	programFDs map[experimentalProgramResource]uint32
}

func newCoreStageFixture(t *testing.T) *coreStageFixture {
	t.Helper()
	fixture := &coreStageFixture{
		maps:       make(map[string]*coreMemoryMap),
		programFDs: make(map[experimentalProgramResource]uint32),
	}
	resources := make(map[string]experimentalMapResource)
	for _, name := range []string{
		"profile_map", "cipher_map", "underlay_config_map",
		"managed_fwmark_map", "egress_rule_map", "ingress_listener_map",
		"icmp_listener_map",
	} {
		memory := &coreMemoryMap{
			name: name, kind: coreMemoryHash,
			entries: make(map[any]any), events: &fixture.events,
		}
		fixture.maps[name] = memory
		resources[name] = memory
	}
	control := &coreMemoryMap{
		name: "control_map", kind: coreMemoryControl,
		entries: map[any]any{abi.ControlKeyGlobal: abi.ControlValue{}},
		events:  &fixture.events,
	}
	fixture.maps["control_map"] = control
	resources["control_map"] = control
	programs := make(map[string]experimentalProgramResource)
	programIDByFD := make(map[uint32]uint32)
	var closeLog []string
	nextID := uint32(100)
	for _, binding := range xorTailCallBindings {
		memory := &coreMemoryMap{
			name: binding.mapName, kind: coreMemoryProgramArray,
			entries: make(map[any]any), events: &fixture.events,
			programIDs: programIDByFD,
		}
		fixture.maps[binding.mapName] = memory
		resources[binding.mapName] = memory
		for _, programName := range binding.programNames {
			program := &fakeExperimentalOwnedProgram{
				name: programName, id: nextID, closeLog: &closeLog,
			}
			fd := nextID + 1000
			programs[programName] = program
			fixture.programFDs[program] = fd
			programIDByFD[fd] = nextID
			nextID++
		}
	}
	fixture.owner = &experimentalCollectionOwner{
		maps: resources, programs: programs, closeDone: make(chan struct{}),
	}
	return fixture
}

func coreTestSnapshot(generation uint64) *abi.Snapshot {
	return &abi.Snapshot{
		Control: map[abi.ControlKey]abi.ControlValue{
			abi.ControlKeyGlobal: {
				ActiveGeneration: generation,
				ABIVersion:       abi.Version,
			},
		},
		Profiles: map[abi.ProfileKey]abi.ProfileValue{
			{Generation: generation, ProfileID: 1}: {Generation: generation},
		},
		Ciphers:          map[abi.CipherKey]abi.CipherValue{},
		Underlays:        map[abi.UnderlayConfigKey]abi.UnderlayConfigValue{},
		ManagedFwmarks:   map[abi.ManagedFwmarkKey]abi.ManagedFwmarkValue{},
		EgressRules:      map[abi.EgressRuleKey]abi.EgressRuleValue{},
		IngressListeners: map[abi.IngressListenerKey]abi.IngressListenerValue{},
		ICMPListeners:    map[abi.ICMPListenerKey]abi.ICMPListenerValue{},
	}
}

func (fixture *coreStageFixture) stage(
	t *testing.T,
	generation uint64,
) *experimentalCoreStage {
	t.Helper()
	stage, err := stageExperimentalCoreCollection(
		t.Context(),
		mustResolveExperimentalCoreResources(t, fixture.owner),
		coreTestSnapshot(generation),
		experimentalCoreStageDependencies{
			programFD: func(program experimentalProgramResource) (uint32, error) {
				return fixture.programFDs[program], nil
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return stage
}

func mustResolveExperimentalCoreResources(
	t *testing.T,
	owner *experimentalCollectionOwner,
) experimentalCoreResources {
	t.Helper()
	resources, err := resolveExperimentalCoreResources(owner)
	if err != nil {
		t.Fatal(err)
	}
	return resources
}

func TestExperimentalCoreStageKeepsControlInactiveUntilCommitAndRollsBack(t *testing.T) {
	fixture := newCoreStageFixture(t)
	stage := fixture.stage(t, 91)
	control := fixture.maps["control_map"]
	if got := control.entries[abi.ControlKeyGlobal]; got != (abi.ControlValue{}) {
		t.Fatalf("control during stage = %#v", got)
	}
	if len(fixture.maps["profile_map"].entries) != 1 {
		t.Fatal("baseline profile was not staged")
	}
	for _, binding := range xorTailCallBindings {
		if got := len(fixture.maps[binding.mapName].entries); got != xorSegmentCount {
			t.Fatalf("%s entries = %d", binding.mapName, got)
		}
	}
	if err := stage.CommitControl(); err != nil {
		t.Fatal(err)
	}
	wantControl := coreTestSnapshot(91).Control[abi.ControlKeyGlobal]
	if got := control.entries[abi.ControlKeyGlobal]; got != wantControl {
		t.Fatalf("committed control = %#v, want %#v", got, wantControl)
	}
	if err := stage.Close(); err != nil {
		t.Fatal(err)
	}
	if got := control.entries[abi.ControlKeyGlobal]; got != (abi.ControlValue{}) {
		t.Fatalf("control after Close = %#v", got)
	}
	for name, memory := range fixture.maps {
		if name == "control_map" {
			continue
		}
		if len(memory.entries) != 0 {
			t.Fatalf("map %s retained entries: %v", name, memory.entries)
		}
	}
	lastStageUpdate := slices.Index(fixture.events, "update:xor_ingress_programs")
	firstControlUpdate := slices.Index(fixture.events, "update:control_map")
	if lastStageUpdate < 0 || firstControlUpdate <= lastStageUpdate {
		t.Fatalf("control was not committed after staging: %v", fixture.events)
	}
}

func TestExperimentalCoreStageReadbackFailureRollsBackOwnedPrefix(t *testing.T) {
	fixture := newCoreStageFixture(t)
	readErr := errors.New("injected profile readback failure")
	fixture.maps["profile_map"].failLookup = readErr
	stage, err := stageExperimentalCoreCollection(
		t.Context(),
		mustResolveExperimentalCoreResources(t, fixture.owner),
		coreTestSnapshot(91),
		experimentalCoreStageDependencies{
			programFD: func(program experimentalProgramResource) (uint32, error) {
				return fixture.programFDs[program], nil
			},
		},
	)
	if stage != nil || !errors.Is(err, readErr) {
		t.Fatalf("stage=%#v error=%v", stage, err)
	}
	if len(fixture.maps["profile_map"].entries) != 0 {
		t.Fatalf("failed stage retained profile entries: %v", fixture.maps["profile_map"].entries)
	}
	if got := fixture.maps["control_map"].entries[abi.ControlKeyGlobal]; got != (abi.ControlValue{}) {
		t.Fatalf("failed stage activated control: %#v", got)
	}
	for _, binding := range xorTailCallBindings {
		if got := len(fixture.maps[binding.mapName].entries); got != 0 {
			t.Fatalf("failed stage populated %s: %d", binding.mapName, got)
		}
	}
}

func TestExperimentalCoreCommitReadbackFailureRemainsRollbackOwned(t *testing.T) {
	fixture := newCoreStageFixture(t)
	stage := fixture.stage(t, 91)
	readErr := errors.New("injected control readback failure")
	fixture.maps["control_map"].failLookup = readErr
	if err := stage.CommitControl(); !errors.Is(err, readErr) {
		t.Fatalf("CommitControl error = %v", err)
	}
	if !stage.controlCommitted {
		t.Fatal("successful control update lost rollback ownership")
	}
	if err := stage.Close(); err != nil {
		t.Fatalf("Close after readback failure: %v", err)
	}
	if got := fixture.maps["control_map"].entries[abi.ControlKeyGlobal]; got != (abi.ControlValue{}) {
		t.Fatalf("control after rollback = %#v", got)
	}
}

func TestExperimentalCoreCommitMismatchRefusesForeignControlOverwrite(t *testing.T) {
	fixture := newCoreStageFixture(t)
	stage := fixture.stage(t, 91)
	foreign := abi.ControlValue{ActiveGeneration: 777, ABIVersion: abi.Version}
	fixture.maps["control_map"].corruptUpdate = foreign
	if err := stage.CommitControl(); err == nil || !strings.Contains(err.Error(), "committed value changed") {
		t.Fatalf("CommitControl error = %v", err)
	}
	if err := stage.Close(); err == nil || !strings.Contains(err.Error(), "value changed") {
		t.Fatalf("Close error = %v", err)
	}
	if got := fixture.maps["control_map"].entries[abi.ControlKeyGlobal]; got != foreign {
		t.Fatalf("foreign control was overwritten: %#v", got)
	}
}

func TestExperimentalCoreDeactivateFailureKeepsDependentMapsIntact(t *testing.T) {
	fixture := newCoreStageFixture(t)
	stage := fixture.stage(t, 91)
	if err := stage.CommitControl(); err != nil {
		t.Fatal(err)
	}
	deactivateErr := errors.New("injected deactivate update failure")
	fixture.maps["control_map"].failUpdate = deactivateErr
	if err := stage.Close(); !errors.Is(err, deactivateErr) {
		t.Fatalf("Close error = %v", err)
	}
	if len(fixture.maps["profile_map"].entries) != 1 {
		t.Fatal("deactivation failure deleted baseline profile")
	}
	for _, binding := range xorTailCallBindings {
		if got := len(fixture.maps[binding.mapName].entries); got != xorSegmentCount {
			t.Fatalf("deactivation failure deleted %s entries: %d", binding.mapName, got)
		}
	}
	if got := fixture.maps["control_map"].entries[abi.ControlKeyGlobal]; got != coreTestSnapshot(91).Control[abi.ControlKeyGlobal] {
		t.Fatalf("failed deactivate changed control: %#v", got)
	}
}
