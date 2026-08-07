//go:build linux

package dataplane

import (
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

func TestStageFakeTCPPolicyGenerationWritesReachabilityLatchLast(t *testing.T) {
	snapshot := mustFakeTCPPolicySnapshot(t, 91)
	policyMaps, trace := newMemoryFakeTCPPolicyMaps()
	stage, err := stageFakeTCPPolicyGeneration(policyMaps, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		fakeTCPControlPolicyMapName,
		fakeTCPControlPolicyMapName,
		fakeTCPManagedPortMapName,
		fakeTCPManagedPortMapName,
		fakeTCPManagedIfMapName,
		fakeTCPManagedIfMapName,
	}
	if !slices.Equal(trace.successfulUpdates, want) {
		t.Fatalf("update order = %v, want %v", trace.successfulUpdates, want)
	}
	for _, flags := range trace.updateFlags {
		if flags != ebpf.UpdateNoExist {
			t.Fatalf("policy update flags = %v, want UpdateNoExist", flags)
		}
	}
	assertMemoryPolicyMapMatches(t, policyMaps.ControlPolicies, snapshot.ControlPolicies)
	assertMemoryPolicyMapMatches(t, policyMaps.ManagedPorts, snapshot.ManagedPorts)
	assertMemoryPolicyMapMatches(t, policyMaps.ManagedInterfaces, snapshot.ManagedInterfaces)
	if err := stage.Disarm(); err != nil {
		t.Fatal(err)
	}
	if err := stage.Rollback(); err != nil {
		t.Fatal(err)
	}
	assertMemoryPolicyMapMatches(t, policyMaps.ControlPolicies, snapshot.ControlPolicies)
}

func TestStageFakeTCPPolicyGenerationRollsBackEveryWriteFailureInReverse(t *testing.T) {
	snapshot := mustFakeTCPPolicySnapshot(t, 91)
	totalWrites := len(snapshot.ControlPolicies) + len(snapshot.ManagedPorts) + len(snapshot.ManagedInterfaces)
	for failAt := 1; failAt <= totalWrites; failAt++ {
		t.Run(fmt.Sprintf("write-%d", failAt), func(t *testing.T) {
			policyMaps, trace := newMemoryFakeTCPPolicyMaps()
			old := seedOldFakeTCPPolicyGeneration(policyMaps, 90)
			trace.failUpdateAt = failAt
			stage, err := stageFakeTCPPolicyGeneration(policyMaps, snapshot)
			if stage != nil {
				t.Fatal("failed stage returned a rollback handle")
			}
			if err == nil || !strings.Contains(err.Error(), "injected update failure") {
				t.Fatalf("stage error = %v", err)
			}
			assertNoMemoryPolicyGeneration(t, policyMaps, snapshot.Generation)
			assertOldFakeTCPPolicyGeneration(t, policyMaps, old)

			wantDeletes := slices.Clone(trace.successfulUpdates)
			slices.Reverse(wantDeletes)
			if !slices.Equal(trace.deletes, wantDeletes) {
				t.Fatalf("rollback order = %v, want %v", trace.deletes, wantDeletes)
			}
		})
	}
}

func TestFakeTCPPolicyStageRollsBackLaterTransactionFailureAndIsIdempotent(t *testing.T) {
	snapshot := mustFakeTCPPolicySnapshot(t, 91)
	policyMaps, trace := newMemoryFakeTCPPolicyMaps()
	old := seedOldFakeTCPPolicyGeneration(policyMaps, 90)
	stage, err := stageFakeTCPPolicyGeneration(policyMaps, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	wantDeletes := slices.Clone(trace.successfulUpdates)
	slices.Reverse(wantDeletes)
	if err := stage.Rollback(); err != nil {
		t.Fatal(err)
	}
	assertNoMemoryPolicyGeneration(t, policyMaps, snapshot.Generation)
	assertOldFakeTCPPolicyGeneration(t, policyMaps, old)
	if !slices.Equal(trace.deletes, wantDeletes) {
		t.Fatalf("outer rollback order = %v, want %v", trace.deletes, wantDeletes)
	}
	deleteCount := len(trace.deletes)
	if err := stage.Rollback(); err != nil {
		t.Fatalf("idempotent rollback: %v", err)
	}
	if len(trace.deletes) != deleteCount {
		t.Fatalf("second rollback deleted more entries: %v", trace.deletes)
	}
	if err := stage.Disarm(); err == nil || !strings.Contains(err.Error(), "rolled-back") {
		t.Fatalf("disarm after rollback error = %v", err)
	}
}

func TestFakeTCPPolicyStageChangedValueIsRetryableAndNeverBlindDeleted(t *testing.T) {
	snapshot := mustFakeTCPPolicySnapshot(t, 91)
	policyMaps, _ := newMemoryFakeTCPPolicyMaps()
	stage, err := stageFakeTCPPolicyGeneration(policyMaps, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	managedInterfaces := policyMaps.ManagedInterfaces.(*memoryFakeTCPPolicyMap)
	var changedKey abi.FakeTCPManagedIfKey
	var inserted abi.FakeTCPManagedIfValue
	for key, value := range snapshot.ManagedInterfaces {
		changedKey, inserted = key, value
		break
	}
	changed := inserted
	changed.Generation++
	managedInterfaces.entries[changedKey] = changed

	err = stage.Rollback()
	if err == nil || !strings.Contains(err.Error(), "refusing rollback because inserted value changed") {
		t.Fatalf("changed-value rollback error = %v", err)
	}
	if got := managedInterfaces.entries[changedKey]; got != changed {
		t.Fatalf("changed value was blindly deleted or overwritten: %#v", got)
	}
	if err := stage.Disarm(); err == nil || !strings.Contains(err.Error(), "incomplete rollback") {
		t.Fatalf("disarm after incomplete rollback error = %v", err)
	}

	// Once the exact inserted value is restored, retry cleans the only residue;
	// already-removed entries are treated as an idempotent success.
	managedInterfaces.entries[changedKey] = inserted
	if err := stage.Rollback(); err != nil {
		t.Fatalf("retry exact rollback: %v", err)
	}
	assertNoMemoryPolicyGeneration(t, policyMaps, snapshot.Generation)
}

func TestStageFakeTCPPolicyGenerationRejectsExistingKeyWithoutResettingCursor(t *testing.T) {
	tests := []struct {
		name string
		seed func(fakeTCPPolicyMaps, *fakeTCPPolicySnapshot) (*memoryFakeTCPPolicyMap, any, any)
	}{
		{
			name: "control policy with live cursor",
			seed: func(policyMaps fakeTCPPolicyMaps, snapshot *fakeTCPPolicySnapshot) (*memoryFakeTCPPolicyMap, any, any) {
				var key abi.FakeTCPControlPolicyKey
				for key = range snapshot.ControlPolicies {
					break
				}
				value := snapshot.ControlPolicies[key]
				value.VirtualTimeNanos = 987654321
				return policyMaps.ControlPolicies.(*memoryFakeTCPPolicyMap), key, value
			},
		},
		{
			name: "managed port",
			seed: func(policyMaps fakeTCPPolicyMaps, snapshot *fakeTCPPolicySnapshot) (*memoryFakeTCPPolicyMap, any, any) {
				var key abi.FakeTCPManagedPortKey
				for key = range snapshot.ManagedPorts {
					break
				}
				return policyMaps.ManagedPorts.(*memoryFakeTCPPolicyMap), key, snapshot.ManagedPorts[key]
			},
		},
		{
			name: "managed interface",
			seed: func(policyMaps fakeTCPPolicyMaps, snapshot *fakeTCPPolicySnapshot) (*memoryFakeTCPPolicyMap, any, any) {
				var key abi.FakeTCPManagedIfKey
				for key = range snapshot.ManagedInterfaces {
					break
				}
				return policyMaps.ManagedInterfaces.(*memoryFakeTCPPolicyMap), key, snapshot.ManagedInterfaces[key]
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := mustFakeTCPPolicySnapshot(t, 91)
			policyMaps, trace := newMemoryFakeTCPPolicyMaps()
			memoryMap, key, existing := test.seed(policyMaps, snapshot)
			memoryMap.entries[key] = existing

			stage, err := stageFakeTCPPolicyGeneration(policyMaps, snapshot)
			if stage != nil {
				t.Fatal("existing-key stage returned a rollback handle")
			}
			if err == nil || !strings.Contains(err.Error(), "exact key already exists") {
				t.Fatalf("existing-key error = %v", err)
			}
			if len(trace.updateAttempts) != 0 || len(trace.deletes) != 0 {
				t.Fatalf("existing-key preflight mutated maps: updates=%v deletes=%v", trace.updateAttempts, trace.deletes)
			}
			if got := memoryMap.entries[key]; got != existing {
				t.Fatalf("existing value changed: got %#v want %#v", got, existing)
			}
		})
	}
}

func TestStageFakeTCPPolicyGenerationReadbackMismatchRollsBack(t *testing.T) {
	snapshot := mustFakeTCPPolicySnapshot(t, 91)
	policyMaps, _ := newMemoryFakeTCPPolicyMaps()
	policyMaps.ManagedPorts.(*memoryFakeTCPPolicyMap).corruptNextSuccessfulReadback = true
	stage, err := stageFakeTCPPolicyGeneration(policyMaps, snapshot)
	if stage != nil {
		t.Fatal("readback mismatch returned a rollback handle")
	}
	if err == nil || !strings.Contains(err.Error(), "read back value differs") {
		t.Fatalf("readback mismatch error = %v", err)
	}
	assertNoMemoryPolicyGeneration(t, policyMaps, snapshot.Generation)
}

func TestStageFakeTCPPolicyGenerationNeverDeletesChangedRollbackValue(t *testing.T) {
	snapshot := mustFakeTCPPolicySnapshot(t, 91)
	policyMaps, _ := newMemoryFakeTCPPolicyMaps()
	managedPorts := policyMaps.ManagedPorts.(*memoryFakeTCPPolicyMap)
	managedPorts.changeFirstInsertedValue = func(value any) any {
		changed := value.(abi.FakeTCPManagedPortValue)
		changed.WGID++
		return changed
	}
	stage, err := stageFakeTCPPolicyGeneration(policyMaps, snapshot)
	if stage == nil {
		t.Fatal("incomplete internal rollback did not return a retryable rollback handle")
	}
	if err == nil || !strings.Contains(err.Error(), "rollback incomplete") ||
		!strings.Contains(err.Error(), "refusing rollback because inserted value changed") {
		t.Fatalf("changed rollback value error = %v", err)
	}
	if len(managedPorts.entries) != 1 {
		t.Fatalf("changed value was deleted or unexpected residue remains: %#v", managedPorts.entries)
	}
	var changedKey abi.FakeTCPManagedPortKey
	var wantValue abi.FakeTCPManagedPortValue
	for key, value := range managedPorts.entries {
		changedKey = key.(abi.FakeTCPManagedPortKey)
		wantValue = snapshot.ManagedPorts[changedKey]
		if value == wantValue {
			t.Fatalf("test did not change inserted value: %#v", value)
		}
	}
	if len(policyMaps.ControlPolicies.(*memoryFakeTCPPolicyMap).entries) != 0 ||
		len(policyMaps.ManagedInterfaces.(*memoryFakeTCPPolicyMap).entries) != 0 {
		t.Fatal("safe exact rollback did not remove preceding unchanged entries")
	}
	if err := stage.Disarm(); err == nil || !strings.Contains(err.Error(), "incomplete rollback") {
		t.Fatalf("incomplete stage disarm error = %v", err)
	}
	managedPorts.entries[changedKey] = wantValue
	if err := stage.Rollback(); err != nil {
		t.Fatalf("retry incomplete stage rollback: %v", err)
	}
	assertNoMemoryPolicyGeneration(t, policyMaps, snapshot.Generation)
}

func TestStageFakeTCPPolicyGenerationRejectsMalformedSnapshotBeforeWrites(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*fakeTCPPolicySnapshot)
		wantErr string
	}{
		{
			name: "nonzero cursor",
			mutate: func(snapshot *fakeTCPPolicySnapshot) {
				for key, value := range snapshot.ControlPolicies {
					value.VirtualTimeNanos = 1
					snapshot.ControlPolicies[key] = value
					break
				}
			},
			wantErr: "nonzero BPF-owned virtual time",
		},
		{
			name: "missing interface latch",
			mutate: func(snapshot *fakeTCPPolicySnapshot) {
				for key := range snapshot.ManagedInterfaces {
					delete(snapshot.ManagedInterfaces, key)
					break
				}
			},
			wantErr: "has no interface latch",
		},
		{
			name: "missing control policy",
			mutate: func(snapshot *fakeTCPPolicySnapshot) {
				for key := range snapshot.ControlPolicies {
					delete(snapshot.ControlPolicies, key)
					break
				}
			},
			wantErr: "has no WireGuard control policy",
		},
		{
			name: "wrong generation",
			mutate: func(snapshot *fakeTCPPolicySnapshot) {
				for key, value := range snapshot.ManagedPorts {
					value.Generation++
					snapshot.ManagedPorts[key] = value
					break
				}
			},
			wantErr: "generation does not match",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := mustFakeTCPPolicySnapshot(t, 91)
			test.mutate(snapshot)
			policyMaps, trace := newMemoryFakeTCPPolicyMaps()
			stage, err := stageFakeTCPPolicyGeneration(policyMaps, snapshot)
			if stage != nil {
				t.Fatal("malformed snapshot returned a rollback handle")
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("malformed snapshot error = %v, want %q", err, test.wantErr)
			}
			if len(trace.updateAttempts) != 0 || len(trace.deletes) != 0 {
				t.Fatalf("malformed snapshot mutated maps: %#v", trace)
			}
		})
	}
}

func TestFakeTCPPolicyPrimitiveDoesNotClaimActivationCapability(t *testing.T) {
	if fakeTCPImplementedCapabilities&fakeTCPCapabilityManagedPolicyPopulation != 0 {
		t.Fatal("policy staging primitive claimed managed population before loader/XDP transaction integration")
	}
	if !strings.Contains(strings.Join(missingFakeTCPCapabilities(), "\n"),
		"atomic managed-interface/port policy population") {
		t.Fatal("activation gate stopped reporting managed policy population as incomplete")
	}
}

func TestFakeTCPPolicyPerGenerationLimitsMatchTwoBankELFMaps(t *testing.T) {
	want := map[string]uint32{
		fakeTCPControlPolicyMapName: uint32(fakeTCPControlPoliciesPerGeneration * 2),
		fakeTCPManagedPortMapName:   uint32(fakeTCPManagedPortsPerGeneration * 2),
		fakeTCPManagedIfMapName:     uint32(fakeTCPManagedInterfacesPerGeneration * 2),
	}
	for _, descriptor := range experimentalMapDescriptors() {
		capacity, relevant := want[descriptor.name]
		if !relevant {
			continue
		}
		if descriptor.maxEntries != capacity {
			t.Fatalf("%s entries = %d, want two policy banks (%d)",
				descriptor.name, descriptor.maxEntries, capacity)
		}
		delete(want, descriptor.name)
	}
	if len(want) != 0 {
		t.Fatalf("experimental manifest is missing policy maps: %v", want)
	}
}

type memoryFakeTCPPolicyTrace struct {
	updateAttempts    []string
	successfulUpdates []string
	updateFlags       []ebpf.MapUpdateFlags
	deletes           []string
	failUpdateAt      int
}

type memoryFakeTCPPolicyMap struct {
	name                          string
	entries                       map[any]any
	trace                         *memoryFakeTCPPolicyTrace
	corruptNextSuccessfulReadback bool
	changeFirstInsertedValue      func(any) any
}

func (m *memoryFakeTCPPolicyMap) Lookup(key, valueOut any) error {
	value, exists := m.entries[key]
	if !exists {
		return ebpf.ErrKeyNotExist
	}
	if m.corruptNextSuccessfulReadback {
		m.corruptNextSuccessfulReadback = false
		return assignMemoryPolicyValue(valueOut, reflect.Zero(reflect.TypeOf(value)).Interface())
	}
	return assignMemoryPolicyValue(valueOut, value)
}

func (m *memoryFakeTCPPolicyMap) Update(key, value any, flags ebpf.MapUpdateFlags) error {
	m.trace.updateAttempts = append(m.trace.updateAttempts, m.name)
	m.trace.updateFlags = append(m.trace.updateFlags, flags)
	if m.trace.failUpdateAt != 0 && len(m.trace.updateAttempts) == m.trace.failUpdateAt {
		return errors.New("injected update failure")
	}
	if flags != ebpf.UpdateNoExist {
		return fmt.Errorf("unexpected update flags %v", flags)
	}
	if _, exists := m.entries[key]; exists {
		return ebpf.ErrKeyExist
	}
	stored := value
	if m.changeFirstInsertedValue != nil {
		stored = m.changeFirstInsertedValue(value)
		m.changeFirstInsertedValue = nil
	}
	m.entries[key] = stored
	m.trace.successfulUpdates = append(m.trace.successfulUpdates, m.name)
	return nil
}

func (m *memoryFakeTCPPolicyMap) Delete(key any) error {
	if _, exists := m.entries[key]; !exists {
		return ebpf.ErrKeyNotExist
	}
	delete(m.entries, key)
	m.trace.deletes = append(m.trace.deletes, m.name)
	return nil
}

func assignMemoryPolicyValue(destination, value any) error {
	target := reflect.ValueOf(destination)
	if target.Kind() != reflect.Pointer || target.IsNil() {
		return errors.New("lookup destination must be a non-nil pointer")
	}
	source := reflect.ValueOf(value)
	if !source.Type().AssignableTo(target.Elem().Type()) {
		return fmt.Errorf("lookup value type %s is not assignable to %s", source.Type(), target.Elem().Type())
	}
	target.Elem().Set(source)
	return nil
}

func newMemoryFakeTCPPolicyMaps() (fakeTCPPolicyMaps, *memoryFakeTCPPolicyTrace) {
	trace := &memoryFakeTCPPolicyTrace{}
	newMap := func(name string) *memoryFakeTCPPolicyMap {
		return &memoryFakeTCPPolicyMap{name: name, entries: make(map[any]any), trace: trace}
	}
	return fakeTCPPolicyMaps{
		ControlPolicies:   newMap(fakeTCPControlPolicyMapName),
		ManagedPorts:      newMap(fakeTCPManagedPortMapName),
		ManagedInterfaces: newMap(fakeTCPManagedIfMapName),
	}, trace
}

type oldFakeTCPPolicyEntries struct {
	control    map[any]any
	ports      map[any]any
	interfaces map[any]any
}

func seedOldFakeTCPPolicyGeneration(
	policyMaps fakeTCPPolicyMaps,
	generation uint64,
) oldFakeTCPPolicyEntries {
	controlMap := policyMaps.ControlPolicies.(*memoryFakeTCPPolicyMap)
	portMap := policyMaps.ManagedPorts.(*memoryFakeTCPPolicyMap)
	interfaceMap := policyMaps.ManagedInterfaces.(*memoryFakeTCPPolicyMap)
	controlMap.entries[abi.FakeTCPControlPolicyKey{Generation: generation, WGID: 44}] =
		abi.FakeTCPControlPolicyValue{
			Generation: generation, VirtualTimeNanos: 1234,
			IntervalNanos: uint64(fakeTCPControlMinInterval), Burst: 1,
		}
	portMap.entries[abi.FakeTCPManagedPortKey{
		Generation: generation, UnderlayIndex: 55, DestinationPort: 32000,
	}] = abi.FakeTCPManagedPortValue{Generation: generation, WGID: 44, Action: abi.ActionRewrite}
	interfaceMap.entries[abi.FakeTCPManagedIfKey{
		Generation: generation, UnderlayIndex: 55,
	}] = abi.FakeTCPManagedIfValue{Generation: generation}
	return oldFakeTCPPolicyEntries{
		control:    maps.Clone(controlMap.entries),
		ports:      maps.Clone(portMap.entries),
		interfaces: maps.Clone(interfaceMap.entries),
	}
}

func assertOldFakeTCPPolicyGeneration(
	t *testing.T,
	policyMaps fakeTCPPolicyMaps,
	want oldFakeTCPPolicyEntries,
) {
	t.Helper()
	if got := policyMaps.ControlPolicies.(*memoryFakeTCPPolicyMap).entries; !reflect.DeepEqual(got, want.control) {
		t.Fatalf("old control generation changed: got %#v want %#v", got, want.control)
	}
	if got := policyMaps.ManagedPorts.(*memoryFakeTCPPolicyMap).entries; !reflect.DeepEqual(got, want.ports) {
		t.Fatalf("old port generation changed: got %#v want %#v", got, want.ports)
	}
	if got := policyMaps.ManagedInterfaces.(*memoryFakeTCPPolicyMap).entries; !reflect.DeepEqual(got, want.interfaces) {
		t.Fatalf("old interface generation changed: got %#v want %#v", got, want.interfaces)
	}
}

func assertNoMemoryPolicyGeneration(t *testing.T, policyMaps fakeTCPPolicyMaps, generation uint64) {
	t.Helper()
	for _, memoryMap := range []*memoryFakeTCPPolicyMap{
		policyMaps.ControlPolicies.(*memoryFakeTCPPolicyMap),
		policyMaps.ManagedPorts.(*memoryFakeTCPPolicyMap),
		policyMaps.ManagedInterfaces.(*memoryFakeTCPPolicyMap),
	} {
		for key := range memoryMap.entries {
			var keyGeneration uint64
			switch typed := key.(type) {
			case abi.FakeTCPControlPolicyKey:
				keyGeneration = typed.Generation
			case abi.FakeTCPManagedPortKey:
				keyGeneration = typed.Generation
			case abi.FakeTCPManagedIfKey:
				keyGeneration = typed.Generation
			default:
				t.Fatalf("unexpected key type %T", key)
			}
			if keyGeneration == generation {
				t.Fatalf("%s retained failed target-generation key %#v", memoryMap.name, key)
			}
		}
	}
}

func assertMemoryPolicyMapMatches[K comparable, V comparable](
	t *testing.T,
	policyMap fakeTCPPolicyMap,
	want map[K]V,
) {
	t.Helper()
	entries := policyMap.(*memoryFakeTCPPolicyMap).entries
	if len(entries) != len(want) {
		t.Fatalf("map entries = %d, want %d", len(entries), len(want))
	}
	for key, value := range want {
		if got, exists := entries[key]; !exists || got != value {
			t.Fatalf("map key %#v = %#v, want %#v", key, got, value)
		}
	}
}

func mustFakeTCPPolicySnapshot(t *testing.T, generation uint64) *fakeTCPPolicySnapshot {
	t.Helper()
	snapshot, err := buildFakeTCPPolicySnapshot(fakeTCPPolicyTestState(), generation)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}
