//go:build linux

package dataplane

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
	"github.com/syx0310/wg-mix-ebpf/internal/lockfile"
	"github.com/syx0310/wg-mix-ebpf/internal/pinidentity"
	"golang.org/x/sys/unix"
)

func testPinOwnerRecord(
	t *testing.T,
	root string,
) (pinPathRuntime, *pinPathParent, *pinOwnerRecord) {
	t.Helper()
	pinPath := filepath.Join(root, "bpffs", "wg-mix-ebpf-owner-test")
	base := filepath.Base(pinPath)
	const (
		parentDevice = 42
		parentInode  = 99
		mountID      = 101
	)
	key, err := pinidentity.Key(parentDevice, parentInode, base)
	if err != nil {
		t.Fatal(err)
	}
	resource := pinResourceIdentity{
		key:          key,
		parentDevice: parentDevice,
		parentInode:  parentInode,
		base:         base,
		pinPath:      pinPath,
	}
	parent := &pinPathParent{
		pinPath:  pinPath,
		base:     base,
		mountID:  mountID,
		resource: resource,
	}
	maps := make([]pinOwnerMapIdentity, 0, len(pinnedMapDescriptors()))
	for index, descriptor := range pinnedMapDescriptors() {
		maps = append(maps, pinOwnerMapIdentity{
			Name: descriptor.name,
			ID:   uint32(index + 1),
		})
	}
	var token [32]byte
	for index := range token {
		token[index] = byte(index + 1)
	}
	record, err := newActivePinOwnerRecord(
		parent,
		token,
		"12345678-1234-1234-1234-123456789abc",
		time.Date(2026, 7, 29, 1, 2, 3, 4, time.UTC),
		7,
		maps,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	runtime := pinPathRuntime{
		ownerRoot:            filepath.Join(root, "pin-owners"),
		expectedUID:          uint32(os.Getuid()),
		allowUnsafeAncestors: true,
	}
	parent.runtime = runtime
	return runtime, parent, record
}

type durableTCOwnerJournalFixture struct {
	handle             *pinPathHandle
	store              *pinOwnerStore
	intent             *pinOwnerRecord
	active             []tcFilterBinding
	desired            []tcFilterBinding
	mapStore           *fakePinnedMapStore
	programLoadErrors  map[string]error
	programPinErrors   map[string][]error
	programCloseErrors map[string][]error
	programIDs         map[string]uint32
	programMu          *sync.Mutex
	programOpens       map[string]int
	programCloses      map[string]int
	plan               *tcAttachPlan
	kernel             *fakeTCKernel
}

func (fixture *durableTCOwnerJournalFixture) programObservationCounts() (int, int) {
	fixture.programMu.Lock()
	defer fixture.programMu.Unlock()
	var opens int
	var closes int
	for _, count := range fixture.programOpens {
		opens += count
	}
	for _, count := range fixture.programCloses {
		closes += count
	}
	return opens, closes
}

func (fixture *durableTCOwnerJournalFixture) assertProgramObservationsBalanced(
	t *testing.T,
) {
	t.Helper()
	opens, closes := fixture.programObservationCounts()
	if opens != closes {
		t.Fatalf(
			"pinned program observations remain live: opens=%d closes=%d",
			opens,
			closes,
		)
	}
}

func newDurableTCOwnerJournalFixture(t *testing.T) *durableTCOwnerJournalFixture {
	return newDurableTCOwnerJournalFixtureWithActive(t, true)
}

func newDurableTCOwnerJournalFixtureWithActive(
	t *testing.T,
	withActive bool,
) *durableTCOwnerJournalFixture {
	t.Helper()
	bpffsRoot, validator := newTestBPFFS(t)
	pinPath := filepath.Join(bpffsRoot, "wg-mix-ebpf-journal-handoff")
	mapStore := writeCanonicalMockPins(t, pinPath)
	runtime := newTestPinPathRuntime(t, validator, mapStore)
	programLoadErrors := make(map[string]error)
	programPinErrors := make(map[string][]error)
	programCloseErrors := make(map[string][]error)
	programIDs := make(map[string]uint32)
	programFDs := map[uint32]int{21: 201, 22: 202, 31: 301, 32: 302}
	programOpens := make(map[string]int)
	programCloses := make(map[string]int)
	programMu := &sync.Mutex{}
	runtime.loadPinnedProgram = func(path string) (*pinnedProgramObservation, error) {
		name := filepath.Base(path)
		if err := programLoadErrors[name]; err != nil {
			return nil, err
		}
		id, ok := programIDs[name]
		if !ok && strings.HasSuffix(name, ".retired") {
			id, ok = programIDs[strings.TrimSuffix(name, ".retired")]
		}
		if !ok {
			return nil, fmt.Errorf("unknown fake program stage %s", name)
		}
		programMu.Lock()
		programOpens[name]++
		programMu.Unlock()
		fd, ok := programFDs[id]
		if !ok {
			fd = int(id) + 1000
		}
		return &pinnedProgramObservation{
			fd: fd,
			id: id,
			pin: func(path string) error {
				if failures := programPinErrors[name]; len(failures) != 0 {
					failure := failures[0]
					programPinErrors[name] = failures[1:]
					if failure != nil {
						return failure
					}
				}
				file, err := os.OpenFile(
					path,
					os.O_CREATE|os.O_EXCL|os.O_WRONLY,
					0o600,
				)
				if err != nil {
					return err
				}
				if _, err := file.WriteString("mock BPF program stage: " + name); err != nil {
					_ = file.Close()
					return err
				}
				if err := file.Close(); err != nil {
					return err
				}
				programIDs[filepath.Base(path)] = id
				return nil
			},
			close: func() error {
				programMu.Lock()
				defer programMu.Unlock()
				programCloses[name]++
				failures := programCloseErrors[name]
				if len(failures) == 0 {
					return nil
				}
				failure := failures[0]
				programCloseErrors[name] = failures[1:]
				return failure
			},
		}, nil
	}
	validated, err := validatePinPath(pinPath, validator)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := openPinPathParent(pinPath, validated, runtime)
	if err != nil {
		t.Fatal(err)
	}
	handle, _, err := openPinPathHandleFromParent(parent, validated, false)
	if err != nil {
		_ = parent.Close()
		t.Fatal(err)
	}
	store, err := openPinOwnerStore(runtime, handle.resource, true)
	if err != nil {
		_ = handle.Close()
		_ = parent.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = store.Close()
		_ = handle.Close()
		_ = parent.Close()
	})

	pins, err := inspectPinnedMapSet(handle, true)
	if err != nil {
		t.Fatal(err)
	}
	ownerMaps := ownerMapsFromPins(pins)
	if err := closePinnedMapPins(pins); err != nil {
		t.Fatal(err)
	}
	var token [32]byte
	for index := range token {
		token[index] = byte(index + 1)
	}
	slots := canonicalTCFilterSlots()
	active := []tcFilterBinding{
		{
			IfIndex: 11, Direction: "ingress", Parent: slots[0].parent,
			Handle: slots[0].handle, Priority: filterPriority, ProgramID: 21,
		},
		{
			IfIndex: 11, Direction: "egress", Parent: slots[1].parent,
			Handle: slots[1].handle, Priority: filterPriority, ProgramID: 22,
		},
	}
	if !withActive {
		active = []tcFilterBinding{}
		controlObservation := mapStore.observations["control_map"]
		controlObservation.control = abi.ControlValue{}
		mapStore.observations["control_map"] = controlObservation
	}
	desired := []tcFilterBinding{
		{
			IfIndex: 11, Direction: "ingress", Parent: slots[0].parent,
			Handle: slots[0].handle, Priority: filterPriority, ProgramID: 31,
		},
		{
			IfIndex: 11, Direction: "egress", Parent: slots[1].parent,
			Handle: slots[1].handle, Priority: filterPriority, ProgramID: 32,
		},
	}
	now := time.Date(2026, 8, 8, 1, 2, 3, 4, time.UTC)
	var activeRecord *pinOwnerRecord
	activeGeneration := uint64(0)
	if withActive {
		activeGeneration = 1
		activeRecord, err = newActivePinOwnerRecord(
			parent,
			token,
			"12345678-1234-1234-1234-123456789abc",
			now,
			activeGeneration,
			ownerMaps,
			active,
		)
		if err != nil {
			t.Fatal(err)
		}
	}
	applying, err := newApplyingPinOwnerRecord(
		parent,
		token,
		"12345678-1234-1234-1234-123456789abc",
		now.Add(time.Second),
		activeGeneration,
		activeGeneration+1,
		ownerMaps,
		active,
		desired,
		activeRecord,
	)
	if err != nil {
		t.Fatal(err)
	}
	mutating := advancePinOwnerRecord(
		applying,
		now.Add(2*time.Second),
		pinOwnerPhaseApplying,
		pinOwnerStepMutating,
	)
	observeOwnerMount(mutating, handle.mountID)
	for _, stage := range mutating.ProgramStages {
		programIDs[stage.FileName] = stage.ProgramID
		if err := os.WriteFile(
			filepath.Join(pinPath, stage.FileName),
			[]byte("mock BPF program pin"),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
	}
	sentinel, err := pinOwnerSentinelFor(handle.resource, token)
	if err != nil {
		t.Fatal(err)
	}
	ownerObservation := mapStore.observations["owner_map"]
	ownerObservation.owner = sentinel
	ownerObservation.ownerSeen = true
	mapStore.observations["owner_map"] = ownerObservation
	if activeRecord != nil {
		if err := store.Persist(activeRecord, nil, handle.mountID); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Persist(applying, activeRecord, handle.mountID); err != nil {
		t.Fatal(err)
	}
	if err := store.Persist(mutating, applying, handle.mountID); err != nil {
		t.Fatal(err)
	}
	tcKernel := newFakeTCKernel(11)
	for id, fd := range map[uint32]int{21: 201, 22: 202, 31: 301, 32: 302} {
		tcKernel.addProgram(id, fd)
	}
	tcKernel.addClsact(11)
	if withActive {
		tcKernel.addManagedFilter(11, slots[0], 21)
		tcKernel.addManagedFilter(11, slots[1], 22)
	}
	plan, err := prepareTCAttachPlan(
		testTCState(11),
		tcProgramIdentity{fd: 301, id: 31},
		tcProgramIdentity{fd: 302, id: 32},
		tcKernel.runtime(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.ValidatePreviousBindings(active, !withActive); err != nil {
		t.Fatal(err)
	}
	if err := plan.AddOwnedStaleRemovals(active); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = plan.Close() })
	return &durableTCOwnerJournalFixture{
		handle:             handle,
		store:              store,
		intent:             mutating,
		active:             active,
		desired:            desired,
		mapStore:           mapStore,
		programLoadErrors:  programLoadErrors,
		programPinErrors:   programPinErrors,
		programCloseErrors: programCloseErrors,
		programIDs:         programIDs,
		programMu:          programMu,
		programOpens:       programOpens,
		programCloses:      programCloses,
		plan:               plan,
		kernel:             tcKernel,
	}
}

func TestPrepareDurableTCOwnerJournalHandoffFaults(t *testing.T) {
	t.Run("exact durable coverage", func(t *testing.T) {
		fixture := newDurableTCOwnerJournalFixture(t)
		handoff, err := prepareDurableTCOwnerJournalHandoff(
			fixture.handle,
			fixture.store,
			fixture.intent,
			fixture.active,
			fixture.desired,
			fixture.plan,
		)
		if err != nil || handoff == nil ||
			handoff.resourceKey != fixture.intent.ResourceKey ||
			handoff.sequence != fixture.intent.Sequence {
			t.Fatalf("handoff=%#v error=%v", handoff, err)
		}
		if err := handoff.Close(); err != nil {
			t.Fatal(err)
		}
		fixture.assertProgramObservationsBalanced(t)
	})

	t.Run("read-back mismatch", func(t *testing.T) {
		fixture := newDurableTCOwnerJournalFixture(t)
		intent := clonePinOwnerRecord(fixture.intent)
		intent.Sequence++
		handoff, err := prepareDurableTCOwnerJournalHandoff(
			fixture.handle,
			fixture.store,
			intent,
			fixture.active,
			fixture.desired,
			fixture.plan,
		)
		if handoff != nil || err == nil || !strings.Contains(err.Error(), "differs") {
			t.Fatalf("handoff=%#v error=%v", handoff, err)
		}
	})

	t.Run("map identity fault", func(t *testing.T) {
		fixture := newDurableTCOwnerJournalFixture(t)
		observation := fixture.mapStore.observations["control_map"]
		observation.id++
		fixture.mapStore.observations["control_map"] = observation
		handoff, err := prepareDurableTCOwnerJournalHandoff(
			fixture.handle,
			fixture.store,
			fixture.intent,
			fixture.active,
			fixture.desired,
			fixture.plan,
		)
		if handoff != nil || err == nil || !strings.Contains(err.Error(), "map ID") {
			t.Fatalf("handoff=%#v error=%v", handoff, err)
		}
	})

	t.Run("program stage load fault", func(t *testing.T) {
		fixture := newDurableTCOwnerJournalFixture(t)
		stage := fixture.intent.ProgramStages[0]
		wantErr := errors.New("injected staged program load failure")
		fixture.programLoadErrors[stage.FileName] = wantErr
		handoff, err := prepareDurableTCOwnerJournalHandoff(
			fixture.handle,
			fixture.store,
			fixture.intent,
			fixture.active,
			fixture.desired,
			fixture.plan,
		)
		if handoff != nil || !errors.Is(err, wantErr) {
			t.Fatalf("handoff=%#v error=%v", handoff, err)
		}
	})
}

func TestAbortFailedOwnerApplyReportsRollbackVerificationBoundary(t *testing.T) {
	t.Run("TC mismatch leaves journal handoff responsible", func(t *testing.T) {
		fixture := newDurableTCOwnerJournalFixture(t)
		kernel := newFakeTCKernel(11)
		for id, fd := range map[uint32]int{21: 201, 22: 202, 31: 301, 32: 302} {
			kernel.addProgram(id, fd)
		}
		kernel.addClsact(11)
		kernel.addManagedFilter(11, canonicalTCFilterSlots()[0], 31)
		kernel.addManagedFilter(11, canonicalTCFilterSlots()[1], 32)
		verified, err := abortFailedOwnerApply(
			fixture.handle,
			fixture.store,
			fixture.intent,
			kernel.runtime(),
		)
		if verified || err == nil || !strings.Contains(err.Error(), "did not restore") {
			t.Fatalf("verified=%t error=%v", verified, err)
		}
		persisted, loadErr := fixture.store.Load(fixture.handle.mountID)
		if loadErr != nil || !sameExpectedOwnerRecord(persisted, fixture.intent) {
			t.Fatalf("unverified abort changed durable journal: record=%#v error=%v", persisted, loadErr)
		}
	})

	t.Run("exact active TC releases transient stage before later abort fault", func(t *testing.T) {
		fixture := newDurableTCOwnerJournalFixture(t)
		kernel := newFakeTCKernel(11)
		for id, fd := range map[uint32]int{21: 201, 22: 202, 31: 301, 32: 302} {
			kernel.addProgram(id, fd)
		}
		kernel.addClsact(11)
		kernel.addManagedFilter(11, canonicalTCFilterSlots()[0], 21)
		kernel.addManagedFilter(11, canonicalTCFilterSlots()[1], 22)
		verified, err := abortFailedOwnerApply(
			fixture.handle,
			fixture.store,
			fixture.intent,
			kernel.runtime(),
		)
		if !verified || err == nil || !strings.Contains(err.Error(), "clock") {
			t.Fatalf("verified=%t error=%v", verified, err)
		}
	})
}

func exactActiveOwnerTCKernel(
	t *testing.T,
	fixture *durableTCOwnerJournalFixture,
) *fakeTCKernel {
	t.Helper()
	kernel := newFakeTCKernel(11)
	for id, fd := range map[uint32]int{21: 201, 22: 202, 31: 301, 32: 302} {
		kernel.addProgram(id, fd)
	}
	kernel.addClsact(11)
	for _, binding := range fixture.active {
		slot, err := ownerFilterSlot(binding)
		if err != nil {
			t.Fatal(err)
		}
		kernel.addManagedFilter(binding.IfIndex, slot, binding.ProgramID)
	}
	return kernel
}

func TestAbortFailedOwnerApplyRollbackCleanupRestartConverges(t *testing.T) {
	recoveryNow := time.Date(2026, 8, 8, 1, 2, 6, 0, time.UTC)

	t.Run("quarantine failure resumes to active", func(t *testing.T) {
		fixture := newDurableTCOwnerJournalFixture(t)
		kernel := exactActiveOwnerTCKernel(t, fixture)
		fixture.handle.runtime.now = func() time.Time { return recoveryNow }
		wantErr := errors.New("injected rollback quarantine failure")
		fixture.handle.runtime.beforePinQuarantine = func(string) error { return wantErr }
		verified, err := abortFailedOwnerApply(
			fixture.handle,
			fixture.store,
			fixture.intent,
			kernel.runtime(),
		)
		if !verified || !errors.Is(err, wantErr) {
			t.Fatalf("verified=%t error=%v", verified, err)
		}
		persisted, err := fixture.store.Load(fixture.handle.mountID)
		if err != nil {
			t.Fatal(err)
		}
		if persisted.Phase != pinOwnerPhaseApplying ||
			persisted.Step != pinOwnerStepRollbackCleanup {
			t.Fatalf("durable rollback record = %s/%s", persisted.Phase, persisted.Step)
		}
		fixture.handle.runtime.beforePinQuarantine = nil
		recovered, err := recoverPinOwnerTransaction(
			fixture.handle,
			fixture.store,
			persisted,
			kernel.runtime(),
		)
		if err != nil {
			t.Fatalf("restart rollback recovery: %v", err)
		}
		if recovered.record == nil ||
			recovered.record.Phase != pinOwnerPhaseActive ||
			recovered.record.Step != pinOwnerStepReady ||
			recovered.record.ActiveGeneration != fixture.intent.ActiveGeneration {
			t.Fatalf("recovered owner = %#v", recovered.record)
		}
	})

	t.Run("unlink failure resumes from retired stage", func(t *testing.T) {
		fixture := newDurableTCOwnerJournalFixture(t)
		kernel := exactActiveOwnerTCKernel(t, fixture)
		fixture.handle.runtime.now = func() time.Time { return recoveryNow }
		wantErr := errors.New("injected rollback unlink failure")
		fixture.handle.runtime.beforePinUnlink = func(string) error { return wantErr }
		verified, err := abortFailedOwnerApply(
			fixture.handle,
			fixture.store,
			fixture.intent,
			kernel.runtime(),
		)
		if !verified || !errors.Is(err, wantErr) {
			t.Fatalf("verified=%t error=%v", verified, err)
		}
		persisted, err := fixture.store.Load(fixture.handle.mountID)
		if err != nil {
			t.Fatal(err)
		}
		if persisted.Step != pinOwnerStepRollbackCleanup {
			t.Fatalf("durable rollback step = %s", persisted.Step)
		}
		fixture.handle.runtime.beforePinUnlink = nil
		recovered, err := recoverPinOwnerTransaction(
			fixture.handle,
			fixture.store,
			persisted,
			kernel.runtime(),
		)
		if err != nil {
			t.Fatalf("restart retired-stage recovery: %v", err)
		}
		if recovered.record == nil || recovered.record.Phase != pinOwnerPhaseActive {
			t.Fatalf("recovered owner = %#v", recovered.record)
		}
	})

	t.Run("final persist failure is recovered from descriptor journal", func(t *testing.T) {
		fixture := newDurableTCOwnerJournalFixture(t)
		kernel := exactActiveOwnerTCKernel(t, fixture)
		fixture.handle.runtime.now = func() time.Time { return recoveryNow }
		exchanges := 0
		var closeErr error
		fixture.store.beforeOwnerExchange = func() {
			exchanges++
			if exchanges == 3 {
				closeErr = fixture.store.root.Close()
			}
		}
		verified, err := abortFailedOwnerApply(
			fixture.handle,
			fixture.store,
			fixture.intent,
			kernel.runtime(),
		)
		if closeErr != nil {
			t.Fatalf("inject owner root close: %v", closeErr)
		}
		if !verified || err == nil {
			t.Fatalf("verified=%t final Persist error=%v", verified, err)
		}
		restarted, err := openPinOwnerStore(
			fixture.handle.runtime,
			fixture.handle.resource,
			true,
		)
		if err != nil {
			t.Fatalf("reopen owner store after failed Persist: %v", err)
		}
		t.Cleanup(func() { _ = restarted.Close() })
		persisted, err := restarted.Load(fixture.handle.mountID)
		if err != nil {
			t.Fatal(err)
		}
		if persisted.Phase != pinOwnerPhaseActive ||
			persisted.Step != pinOwnerStepReady ||
			persisted.ActiveGeneration != fixture.intent.ActiveGeneration {
			t.Fatalf("descriptor recovery owner = %#v", persisted)
		}
	})

	t.Run("fresh apply resumes through detaching", func(t *testing.T) {
		fixture := newDurableTCOwnerJournalFixtureWithActive(t, false)
		kernel := exactActiveOwnerTCKernel(t, fixture)
		fixture.handle.runtime.now = func() time.Time { return recoveryNow }
		wantErr := errors.New("injected fresh rollback quarantine failure")
		fixture.handle.runtime.beforePinQuarantine = func(string) error { return wantErr }
		verified, err := abortFailedOwnerApply(
			fixture.handle,
			fixture.store,
			fixture.intent,
			kernel.runtime(),
		)
		if !verified || !errors.Is(err, wantErr) {
			t.Fatalf("verified=%t error=%v", verified, err)
		}
		persisted, err := fixture.store.Load(fixture.handle.mountID)
		if err != nil {
			t.Fatal(err)
		}
		if persisted.Step != pinOwnerStepRollbackCleanup {
			t.Fatalf("fresh durable rollback step = %s", persisted.Step)
		}
		fixture.handle.runtime.beforePinQuarantine = nil
		recovered, err := recoverPinOwnerTransaction(
			fixture.handle,
			fixture.store,
			persisted,
			kernel.runtime(),
		)
		if err != nil {
			t.Fatalf("restart fresh rollback recovery: %v", err)
		}
		if !recovered.directoryRemoved || recovered.record != nil {
			t.Fatalf("fresh rollback result = %#v", recovered)
		}
	})
}

func TestPinOwnerJSONFieldOrderAndCanonicalUTC(t *testing.T) {
	_, parent, record := testPinOwnerRecord(t, t.TempDir())
	data, err := marshalPinOwnerRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{
		`"version":`,
		`"sequence":`,
		`"resource_key":`,
		`"parent_device":`,
		`"parent_inode":`,
		`"pin_basename":`,
		`"pin_path":`,
		`"bpffs_root_path":`,
		`"bpffs_mount_ids":`,
		`"boot_id":`,
		`"token":`,
		`"created_at":`,
		`"updated_at":`,
		`"phase":`,
		`"step":`,
		`"active_generation":`,
		`"next_generation":`,
		`"maps":`,
		`"active_filters":`,
		`"desired_filters":`,
		`"program_stages":`,
		`"map_stages":`,
		`"retired_from_resource_key":`,
		`"retired_from_boot_id":`,
	}
	position := -1
	for _, key := range keys {
		next := bytes.Index(data, []byte(key))
		if next <= position {
			t.Fatalf("owner JSON field %s is out of order: %s", key, data)
		}
		position = next
	}
	nonUTC := clonePinOwnerRecord(record)
	nonUTC.UpdatedAt = "2026-07-29T09:02:03.000000004+08:00"
	if err := validatePinOwnerRecord(
		nonUTC,
		parent.resource,
		parent.mountID,
	); err == nil || !strings.Contains(err.Error(), "canonical RFC3339Nano UTC") {
		t.Fatalf("non-UTC owner timestamp error = %v", err)
	}
}

func TestPinOwnerPhaseStepMatrix(t *testing.T) {
	_, parent, active := testPinOwnerRecord(t, t.TempDir())
	var token [32]byte
	for index := range token {
		token[index] = byte(index + 1)
	}
	now := time.Date(2026, 7, 29, 1, 2, 4, 0, time.UTC)
	applying, err := newApplyingPinOwnerRecord(
		parent,
		token,
		active.BootID,
		now,
		active.ActiveGeneration,
		active.ActiveGeneration+1,
		active.Maps,
		active.ActiveFilters,
		active.ActiveFilters,
		active,
	)
	if err != nil {
		t.Fatal(err)
	}
	detaching, err := newDetachingPinOwnerRecord(active, now)
	if err != nil {
		t.Fatal(err)
	}
	validSteps := map[string][]string{
		pinOwnerPhaseActive: {
			pinOwnerStepReady,
		},
		pinOwnerPhaseApplying: {
			pinOwnerStepStaging,
			pinOwnerStepMutating,
			pinOwnerStepRollbackCleanup,
			pinOwnerStepCleanup,
		},
		pinOwnerPhaseDetaching: {
			pinOwnerStepStaging,
			pinOwnerStepMutatingTC,
			pinOwnerStepUnlinkingMaps,
			pinOwnerStepCleanupStages,
		},
	}
	bases := map[string]*pinOwnerRecord{
		pinOwnerPhaseActive:    active,
		pinOwnerPhaseApplying:  applying,
		pinOwnerPhaseDetaching: detaching,
	}
	allSteps := []string{
		pinOwnerStepReady,
		pinOwnerStepStaging,
		pinOwnerStepMutating,
		pinOwnerStepRollbackCleanup,
		pinOwnerStepMutatingTC,
		pinOwnerStepUnlinkingMaps,
		pinOwnerStepCleanup,
		pinOwnerStepCleanupStages,
	}
	for phase, base := range bases {
		for _, step := range allSteps {
			t.Run(phase+"/"+step, func(t *testing.T) {
				record := clonePinOwnerRecord(base)
				record.Step = step
				err := validatePinOwnerRecord(
					record,
					parent.resource,
					parent.mountID,
				)
				wantValid := false
				for _, valid := range validSteps[phase] {
					wantValid = wantValid || valid == step
				}
				if wantValid && err != nil {
					t.Fatalf("valid phase/step rejected: %v", err)
				}
				if !wantValid && err == nil {
					t.Fatal("invalid phase/step was accepted")
				}
			})
		}
	}
}

func TestPinOwnerDescriptorRecoveryPublishesOnlyNextSequence(t *testing.T) {
	runtime, parent, record := testPinOwnerRecord(t, t.TempDir())
	store, err := openPinOwnerStore(runtime, parent.resource, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Persist(record, nil, parent.mountID); err != nil {
		t.Fatal(err)
	}
	next := clonePinOwnerRecord(record)
	next.Sequence++
	next.UpdatedAt = time.Date(
		2026, 7, 29, 1, 2, 4, 0, time.UTC,
	).Format(time.RFC3339Nano)
	data, err := marshalPinOwnerRecord(next)
	if err != nil {
		t.Fatal(err)
	}
	nextFile, identity, err := createAnchoredRegularFileExclusive(
		store.root,
		store.nextName,
		0o600,
		store.expectedUID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAndSyncAnchoredFile(
		store.root,
		store.nextName,
		nextFile,
		identity,
		data,
		store.expectedUID,
	); err != nil {
		t.Fatal(err)
	}
	if err := nextFile.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	recoveredStore, err := openPinOwnerStore(runtime, parent.resource, false)
	if err != nil {
		t.Fatal(err)
	}
	defer recoveredStore.Close()
	recovered, err := recoveredStore.Load(parent.mountID)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Sequence != next.Sequence ||
		recovered.UpdatedAt != next.UpdatedAt {
		t.Fatalf("recovered owner = %#v, want sequence %d", recovered, next.Sequence)
	}
	index, exists, err := indexStoreFromOwner(recoveredStore).loadOptional()
	if err != nil {
		t.Fatal(err)
	}
	nextEntry, err := ownerIndexEntryFromRecord(
		next,
		pinOwnerIndexActive,
		"",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !exists ||
		len(index.Entries) != 1 ||
		len(index.Active) != 1 ||
		!samePinOwnerIndexEntries(index.Entries, []pinOwnerIndexEntry{nextEntry}) ||
		index.Active[0] != activePointerFromEntry(nextEntry) {
		t.Fatalf("recovered owner index = %#v", index)
	}
}

func TestPinOwnerDescriptorAndIndexRecoveryAtEveryDurablePhase(t *testing.T) {
	for _, phase := range []string{
		"staged",
		"exchanged",
		"index-synced",
	} {
		t.Run(phase, func(t *testing.T) {
			runtime, parent, record, store, _ :=
				openPersistedTestPinOwner(t)
			next := clonePinOwnerRecord(record)
			next.Sequence++
			next.UpdatedAt = time.Date(
				2026, 7, 29, 1, 2, 4, 0, time.UTC,
			).Format(time.RFC3339Nano)
			data, err := marshalPinOwnerRecord(next)
			if err != nil {
				t.Fatal(err)
			}
			nextFile, identity, err := createAnchoredRegularFileExclusive(
				store.root,
				store.nextName,
				0o600,
				store.expectedUID,
			)
			if err != nil {
				t.Fatal(err)
			}
			if err := writeAndSyncAnchoredFile(
				store.root,
				store.nextName,
				nextFile,
				identity,
				data,
				store.expectedUID,
			); err != nil {
				_ = nextFile.Close()
				t.Fatal(err)
			}
			if err := nextFile.Close(); err != nil {
				t.Fatal(err)
			}
			if phase == "exchanged" || phase == "index-synced" {
				if err := unix.Renameat2(
					store.root.FD(),
					store.nextName,
					store.root.FD(),
					store.fileName,
					unix.RENAME_EXCHANGE,
				); err != nil {
					t.Fatal(err)
				}
				if err := unix.Fsync(store.root.FD()); err != nil {
					t.Fatal(err)
				}
			}
			if phase == "index-synced" {
				if err := store.syncIndexRecord(next, false); err != nil {
					t.Fatal(err)
				}
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}

			recoveredStore, err := openPinOwnerStore(
				runtime,
				parent.resource,
				true,
			)
			if err != nil {
				t.Fatalf("recover descriptor phase %s: %v", phase, err)
			}
			defer recoveredStore.Close()
			recovered, err := recoveredStore.Load(parent.mountID)
			if err != nil {
				t.Fatal(err)
			}
			if !sameExpectedOwnerRecord(recovered, next) {
				t.Fatalf("recovered owner = %#v, want %#v", recovered, next)
			}
			nextEntry, err := ownerIndexEntryFromRecord(
				next,
				pinOwnerIndexActive,
				"",
			)
			if err != nil {
				t.Fatal(err)
			}
			index, exists, err := indexStoreFromOwner(
				recoveredStore,
			).loadOptional()
			if err != nil {
				t.Fatal(err)
			}
			if !exists ||
				len(index.Entries) != 1 ||
				len(index.Active) != 1 ||
				!samePinOwnerIndexEntries(
					index.Entries,
					[]pinOwnerIndexEntry{nextEntry},
				) ||
				index.Active[0] != activePointerFromEntry(nextEntry) {
				t.Fatalf("recovered owner index = %#v", index)
			}
			if _, err := os.Lstat(filepath.Join(
				runtime.ownerRoot,
				recoveredStore.nextName,
			)); !os.IsNotExist(err) {
				t.Fatalf(
					"recovered descriptor phase %s left old evidence: %v",
					phase,
					err,
				)
			}
		})
	}
}

func TestPinOwnerDraftPublicationRestartConvergenceMatrix(t *testing.T) {
	type faultCase struct {
		name                string
		point               string
		wantPublished       bool
		wantNextBeforeClose bool
	}
	faults := []faultCase{
		{name: "create", point: "owner-create"},
		{name: "validate-draft-before-write", point: "owner-validate-draft-1"},
		{name: "validate-draft-after-write", point: "owner-validate-draft-2"},
		{name: "validate-draft-before-rename", point: "owner-validate-draft-3"},
		{
			name:                "validate-next",
			point:               "owner-validate-next",
			wantPublished:       true,
			wantNextBeforeClose: true,
		},
		{name: "short-write", point: "owner-short-write"},
		{name: "file-sync", point: "owner-file-sync"},
		{name: "draft-publish-before", point: "owner-draft-rename-before"},
		{
			name:                "draft-publish-after",
			point:               "owner-draft-rename-after",
			wantPublished:       true,
			wantNextBeforeClose: true,
		},
		{
			name:                "draft-dir-sync",
			point:               "owner-draft-dir-sync",
			wantPublished:       true,
			wantNextBeforeClose: true,
		},
		{
			name:                "exchange-before",
			point:               "owner-exchange-before",
			wantPublished:       true,
			wantNextBeforeClose: true,
		},
		{
			name:                "exchange-after",
			point:               "owner-exchange-after",
			wantPublished:       true,
			wantNextBeforeClose: true,
		},
		{
			name:                "exchange-dir-sync",
			point:               "owner-exchange-dir-sync",
			wantPublished:       true,
			wantNextBeforeClose: true,
		},
		{name: "index-create", point: "index-create", wantPublished: true, wantNextBeforeClose: true},
		{name: "index-validate-draft-before-write", point: "index-validate-draft-1", wantPublished: true, wantNextBeforeClose: true},
		{name: "index-validate-draft-after-write", point: "index-validate-draft-2", wantPublished: true, wantNextBeforeClose: true},
		{name: "index-validate-draft-before-rename", point: "index-validate-draft-3", wantPublished: true, wantNextBeforeClose: true},
		{name: "index-short-write", point: "index-short-write", wantPublished: true, wantNextBeforeClose: true},
		{name: "index-file-sync", point: "index-file-sync", wantPublished: true, wantNextBeforeClose: true},
		{name: "index-draft-publish-before", point: "index-draft-rename-before", wantPublished: true, wantNextBeforeClose: true},
		{name: "index-draft-publish-after", point: "index-draft-rename-after", wantPublished: true, wantNextBeforeClose: true},
		{name: "index-draft-dir-sync", point: "index-draft-dir-sync", wantPublished: true, wantNextBeforeClose: true},
		{name: "index-validate-next", point: "index-validate-next", wantPublished: true, wantNextBeforeClose: true},
		{name: "index-exchange-before", point: "index-exchange-before", wantPublished: true, wantNextBeforeClose: true},
		{name: "index-exchange-after", point: "index-exchange-after", wantPublished: true, wantNextBeforeClose: true},
		{name: "index-exchange-dir-sync", point: "index-exchange-dir-sync", wantPublished: true, wantNextBeforeClose: true},
	}

	for _, phase := range []string{pinOwnerPhaseActive, pinOwnerPhaseDetaching} {
		for _, fault := range faults {
			t.Run(phase+"/"+fault.name, func(t *testing.T) {
				runtime, parent, record, store, _ := openPersistedTestPinOwner(t)
				next := clonePinOwnerRecord(record)
				if phase == pinOwnerPhaseDetaching {
					var err error
					next, err = newDetachingPinOwnerRecord(
						record,
						time.Date(2026, 7, 29, 1, 2, 4, 0, time.UTC),
					)
					if err != nil {
						t.Fatal(err)
					}
				} else {
					next.Sequence++
					next.UpdatedAt = time.Date(
						2026, 7, 29, 1, 2, 4, 0, time.UTC,
					).Format(time.RFC3339Nano)
				}

				wantErr := errors.New("injected descriptor durability fault")
				base := store.descriptorOps
				ops := base
				validateCalls := 0
				indexValidateCalls := 0
				lastRename := ""
				ops.create = func(
					root *anchoredDirectoryPath,
					name string,
					mode uint32,
					uid uint32,
				) (*os.File, pinPathInodeIdentity, error) {
					if fault.point == "owner-create" && name == store.draftName {
						return nil, pinPathInodeIdentity{}, wantErr
					}
					if fault.point == "index-create" && name == pinOwnerIndexDraftName {
						return nil, pinPathInodeIdentity{}, wantErr
					}
					return base.create(root, name, mode, uid)
				}
				ops.validate = func(
					root *anchoredDirectoryPath,
					name string,
					fd int,
					mode uint32,
					uid uint32,
					identity *pinPathInodeIdentity,
				) (pinPathInodeIdentity, error) {
					if name == store.draftName {
						validateCalls++
						if fault.point == fmt.Sprintf(
							"owner-validate-draft-%d",
							validateCalls,
						) {
							return pinPathInodeIdentity{}, wantErr
						}
					}
					if fault.point == "owner-validate-next" && name == store.nextName {
						return pinPathInodeIdentity{}, wantErr
					}
					if name == pinOwnerIndexDraftName {
						indexValidateCalls++
						if fault.point == fmt.Sprintf(
							"index-validate-draft-%d",
							indexValidateCalls,
						) {
							return pinPathInodeIdentity{}, wantErr
						}
					}
					if fault.point == "index-validate-next" && name == pinOwnerIndexNextName {
						return pinPathInodeIdentity{}, wantErr
					}
					return base.validate(root, name, fd, mode, uid, identity)
				}
				ops.write = func(file *os.File, data []byte) (int, error) {
					name := filepath.Base(file.Name())
					switch {
					case fault.point == "owner-short-write" && name == store.draftName,
						fault.point == "index-short-write" && name == pinOwnerIndexDraftName:
						if len(data) < 2 {
							return 0, wantErr
						}
						return base.write(file, data[:len(data)-1])
					default:
						return base.write(file, data)
					}
				}
				ops.syncFile = func(file *os.File) error {
					if fault.point == "owner-file-sync" &&
						filepath.Base(file.Name()) == store.draftName {
						return wantErr
					}
					if fault.point == "index-file-sync" &&
						filepath.Base(file.Name()) == pinOwnerIndexDraftName {
						return wantErr
					}
					return base.syncFile(file)
				}
				ops.rename = func(
					root *anchoredDirectoryPath,
					oldName string,
					newName string,
					flags uint,
				) error {
					lastRename = oldName + ">" + newName
					if fault.point == "owner-draft-rename-before" &&
						oldName == store.draftName {
						return wantErr
					}
					if fault.point == "owner-exchange-before" &&
						oldName == store.nextName && flags == unix.RENAME_EXCHANGE {
						return wantErr
					}
					if fault.point == "index-draft-rename-before" &&
						oldName == pinOwnerIndexDraftName {
						return wantErr
					}
					if fault.point == "index-exchange-before" &&
						oldName == pinOwnerIndexNextName && flags == unix.RENAME_EXCHANGE {
						return wantErr
					}
					if err := base.rename(root, oldName, newName, flags); err != nil {
						return err
					}
					if fault.point == "owner-draft-rename-after" &&
						oldName == store.draftName {
						return wantErr
					}
					if fault.point == "owner-exchange-after" &&
						oldName == store.nextName && flags == unix.RENAME_EXCHANGE {
						return wantErr
					}
					if fault.point == "index-draft-rename-after" &&
						oldName == pinOwnerIndexDraftName {
						return wantErr
					}
					if fault.point == "index-exchange-after" &&
						oldName == pinOwnerIndexNextName && flags == unix.RENAME_EXCHANGE {
						return wantErr
					}
					return nil
				}
				ops.syncDir = func(root *anchoredDirectoryPath) error {
					if fault.point == "owner-draft-dir-sync" &&
						lastRename == store.draftName+">"+store.nextName {
						return wantErr
					}
					if fault.point == "owner-exchange-dir-sync" &&
						lastRename == store.nextName+">"+store.fileName {
						return wantErr
					}
					if fault.point == "index-draft-dir-sync" &&
						lastRename == pinOwnerIndexDraftName+">"+pinOwnerIndexNextName {
						return wantErr
					}
					if fault.point == "index-exchange-dir-sync" &&
						lastRename == pinOwnerIndexNextName+">"+pinOwnerIndexFileName {
						return wantErr
					}
					return base.syncDir(root)
				}
				store.descriptorOps = ops

				err := store.Persist(next, record, parent.mountID)
				if !errors.Is(err, wantErr) &&
					!(fault.point == "owner-short-write" ||
						fault.point == "index-short-write") {
					t.Fatalf("Persist fault = %v, want injected error", err)
				}
				if err == nil {
					t.Fatal("faulted Persist unexpectedly succeeded")
				}
				_, nextErr := os.Lstat(filepath.Join(runtime.ownerRoot, store.nextName))
				if fault.wantNextBeforeClose != (nextErr == nil) {
					t.Fatalf("recoverable .next presence error=%v", nextErr)
				}
				if err := store.Close(); err != nil {
					t.Fatal(err)
				}

				restarted, err := openPinOwnerStore(runtime, parent.resource, true)
				if err != nil {
					t.Fatalf("restart owner recovery: %v", err)
				}
				defer restarted.Close()
				recovered, err := restarted.Load(parent.mountID)
				if err != nil {
					t.Fatal(err)
				}
				want := record
				if fault.wantPublished {
					want = next
				}
				if !sameExpectedOwnerRecord(recovered, want) {
					t.Fatalf("recovered owner=%#v, want %#v", recovered, want)
				}
				indexed, err := activeIndexedOwnerForRecord(
					indexStoreFromOwner(restarted),
					want,
				)
				if err != nil || indexed == nil {
					t.Fatalf("recovered owner index entry=%#v error=%v", indexed, err)
				}
				for _, name := range []string{
					restarted.draftName,
					restarted.nextName,
					pinOwnerIndexDraftName,
					pinOwnerIndexNextName,
				} {
					if _, err := os.Lstat(filepath.Join(runtime.ownerRoot, name)); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("restart left descriptor %s: %v", name, err)
					}
				}
			})
		}
	}
}

func TestInitialOwnerPublishRepairsMissingIndex(t *testing.T) {
	runtime, parent, record := testPinOwnerRecord(t, t.TempDir())
	store, err := openPinOwnerStore(runtime, parent.resource, true)
	if err != nil {
		t.Fatal(err)
	}
	data, err := marshalPinOwnerRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	nextFile, identity, err := createAnchoredRegularFileExclusive(
		store.root,
		store.nextName,
		0o600,
		store.expectedUID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAndSyncAnchoredFile(
		store.root,
		store.nextName,
		nextFile,
		identity,
		data,
		store.expectedUID,
	); err != nil {
		_ = nextFile.Close()
		t.Fatal(err)
	}
	if err := unix.Renameat2(
		store.root.FD(),
		store.nextName,
		store.root.FD(),
		store.fileName,
		unix.RENAME_NOREPLACE,
	); err != nil {
		_ = nextFile.Close()
		t.Fatal(err)
	}
	if err := unix.Fsync(store.root.FD()); err != nil {
		_ = nextFile.Close()
		t.Fatal(err)
	}
	if err := nextFile.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	recovered, err := openPinOwnerStore(runtime, parent.resource, true)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	index, exists, err := indexStoreFromOwner(recovered).loadOptional()
	if err != nil {
		t.Fatal(err)
	}
	entry, err := ownerIndexEntryFromRecord(
		record,
		pinOwnerIndexActive,
		"",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !exists ||
		len(index.Entries) != 1 ||
		!samePinOwnerIndexEntries(index.Entries, []pinOwnerIndexEntry{entry}) {
		t.Fatalf("repaired initial owner index = %#v", index)
	}
}

func TestPinOwnerDescriptorRecoveryRejectsImmutableBootSwap(t *testing.T) {
	runtime, parent, record, store, entry := openPersistedTestPinOwner(t)
	next := clonePinOwnerRecord(record)
	next.Sequence++
	next.BootID = "87654321-4321-4321-4321-cba987654321"
	next.UpdatedAt = time.Date(
		2026, 7, 29, 1, 2, 4, 0, time.UTC,
	).Format(time.RFC3339Nano)
	data, err := marshalPinOwnerRecord(next)
	if err != nil {
		t.Fatal(err)
	}
	nextFile, identity, err := createAnchoredRegularFileExclusive(
		store.root,
		store.nextName,
		0o600,
		store.expectedUID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAndSyncAnchoredFile(
		store.root,
		store.nextName,
		nextFile,
		identity,
		data,
		store.expectedUID,
	); err != nil {
		_ = nextFile.Close()
		t.Fatal(err)
	}
	if err := nextFile.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := openPinOwnerStore(
		runtime,
		parent.resource,
		true,
	); err == nil ||
		!strings.Contains(err.Error(), "immutable fields mismatch") {
		t.Fatalf("immutable boot-swap recovery error = %v", err)
	}
	for _, name := range []string{
		entry.RecordFileName,
		parent.resource.key + ".owner.next",
	} {
		if _, err := os.Lstat(filepath.Join(
			runtime.ownerRoot,
			name,
		)); err != nil {
			t.Fatalf("immutable mismatch evidence %s was lost: %v", name, err)
		}
	}
}

func TestPinOwnerExchangeRejectsTargetSwap(t *testing.T) {
	runtime, parent, record := testPinOwnerRecord(t, t.TempDir())
	store, err := openPinOwnerStore(runtime, parent.resource, true)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Persist(record, nil, parent.mountID); err != nil {
		t.Fatal(err)
	}
	next := clonePinOwnerRecord(record)
	next.Sequence++
	next.UpdatedAt = time.Date(
		2026, 7, 29, 1, 2, 4, 0, time.UTC,
	).Format(time.RFC3339Nano)
	store.beforeOwnerExchange = func() {
		target := filepath.Join(runtime.ownerRoot, store.fileName)
		if err := os.Rename(target, target+".swapped"); err != nil {
			t.Errorf("swap owner target: %v", err)
			return
		}
		if err := os.WriteFile(target, []byte("{}\n"), 0o600); err != nil {
			t.Errorf("replace owner target: %v", err)
		}
	}
	err = store.Persist(next, record, parent.mountID)
	if err == nil || !strings.Contains(err.Error(), "changed at exchange hook") {
		t.Fatalf("owner target swap error = %v", err)
	}
}

func TestPinOwnerIndexRetiresOldBootAndRemainsBounded(t *testing.T) {
	root := t.TempDir()
	runtime, parent, record := testPinOwnerRecord(t, root)
	runtime.now = func() time.Time {
		return time.Date(2026, 7, 29, 1, 2, 3, 4, time.UTC)
	}
	store, err := openPinOwnerStore(runtime, parent.resource, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Persist(record, nil, parent.mountID); err != nil {
		t.Fatal(err)
	}
	indexed, err := activeIndexedOwnerForRecord(
		indexStoreFromOwner(store),
		record,
	)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 30, 1, 2, 3, 4, time.UTC)
	historical, err := indexStoreFromOwner(store).archivePriorBootOwner(
		*indexed,
		record,
		false,
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if historical.Status != pinOwnerIndexRekeySource {
		t.Fatalf("archived owner status = %q", historical.Status)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	newBase := parent.resource.base
	newKey, err := pinidentity.Key(142, 199, newBase)
	if err != nil {
		t.Fatal(err)
	}
	newResource := pinResourceIdentity{
		key:          newKey,
		parentDevice: 142,
		parentInode:  199,
		base:         newBase,
		pinPath:      parent.pinPath,
	}
	newParent := *parent
	newParent.resource = newResource
	var newToken [32]byte
	for index := range newToken {
		newToken[index] = byte(0xa0 + index)
	}
	newRecord, err := newActivePinOwnerRecord(
		&newParent,
		newToken,
		"87654321-4321-4321-4321-cba987654321",
		now,
		record.ActiveGeneration,
		record.Maps,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	newRecord.RetiredFromResourceKey = record.ResourceKey
	newRecord.RetiredFromBootID = record.BootID
	if err := validatePinOwnerRecord(
		newRecord,
		newResource,
		parent.mountID,
	); err != nil {
		t.Fatal(err)
	}
	newStore, err := openPinOwnerStore(runtime, newResource, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := newStore.Persist(newRecord, nil, parent.mountID); err != nil {
		t.Fatal(err)
	}
	if err := newStore.Close(); err != nil {
		t.Fatal(err)
	}
	indexRoot, _, err := openAnchoredDirectoryPath(
		runtime.ownerRoot,
		false,
		0o700,
		runtime.expectedUID,
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer indexRoot.Close()
	indexStore := &pinOwnerIndexStore{
		root:        indexRoot,
		expectedUID: runtime.expectedUID,
		now:         runtime.now,
	}
	index, exists, err := indexStore.loadOptional()
	if err != nil {
		t.Fatal(err)
	}
	if !exists ||
		len(index.Entries) != 2 ||
		len(index.Active) != 1 {
		t.Fatalf("retired owner index = %#v", index)
	}
	statuses := make(map[string]string)
	for _, entry := range index.Entries {
		statuses[pinOwnerIndexEntryKey(entry.ResourceKey, entry.BootID)] =
			entry.Status
	}
	if statuses[pinOwnerIndexEntryKey(record.ResourceKey, record.BootID)] !=
		pinOwnerIndexRetiredStatus ||
		statuses[pinOwnerIndexEntryKey(newRecord.ResourceKey, newRecord.BootID)] !=
			pinOwnerIndexActive {
		t.Fatalf("owner index statuses = %#v", statuses)
	}
	if _, err := os.Stat(filepath.Join(
		runtime.ownerRoot,
		historical.RecordFileName,
	)); err != nil {
		t.Fatalf("historical owner record is not preserved: %v", err)
	}

	tooMany := &pinOwnerIndex{
		Version:   pinOwnerIndexVersion,
		Sequence:  1,
		UpdatedAt: now.Format(time.RFC3339Nano),
		Entries:   make([]pinOwnerIndexEntry, pinOwnerIndexMaxEntries+1),
	}
	if err := validatePinOwnerIndex(tooMany); err == nil ||
		!strings.Contains(err.Error(), "maximum") {
		t.Fatalf("oversized owner index error = %v", err)
	}
}

func TestSameKeyRebootOwnerPublishRecoversNextAndCanonicalCrash(t *testing.T) {
	for _, phase := range []string{"next", "canonical"} {
		t.Run(phase, func(t *testing.T) {
			runtime, parent, oldRecord, store, indexed :=
				openPersistedTestPinOwner(t)
			historical, err := indexStoreFromOwner(
				store,
			).archivePriorBootOwner(
				*indexed,
				oldRecord,
				false,
				time.Date(2026, 7, 30, 1, 2, 3, 4, time.UTC),
			)
			if err != nil {
				t.Fatal(err)
			}
			var token [32]byte
			for index := range token {
				token[index] = byte(0x80 + index)
			}
			current, err := newActivePinOwnerRecord(
				parent,
				token,
				"87654321-4321-4321-4321-cba987654321",
				time.Date(2026, 7, 30, 1, 3, 3, 4, time.UTC),
				oldRecord.ActiveGeneration,
				oldRecord.Maps,
				nil,
			)
			if err != nil {
				t.Fatal(err)
			}
			current.RetiredFromResourceKey = oldRecord.ResourceKey
			current.RetiredFromBootID = oldRecord.BootID
			normalizePinOwnerRecord(current)
			if err := validatePinOwnerRecord(
				current,
				parent.resource,
				parent.mountID,
			); err != nil {
				t.Fatal(err)
			}
			data, err := marshalPinOwnerRecord(current)
			if err != nil {
				t.Fatal(err)
			}
			nextFile, identity, err := createAnchoredRegularFileExclusive(
				store.root,
				store.nextName,
				0o600,
				store.expectedUID,
			)
			if err != nil {
				t.Fatal(err)
			}
			if err := writeAndSyncAnchoredFile(
				store.root,
				store.nextName,
				nextFile,
				identity,
				data,
				store.expectedUID,
			); err != nil {
				_ = nextFile.Close()
				t.Fatal(err)
			}
			if phase == "canonical" {
				if err := unix.Renameat2(
					store.root.FD(),
					store.nextName,
					store.root.FD(),
					store.fileName,
					unix.RENAME_NOREPLACE,
				); err != nil {
					_ = nextFile.Close()
					t.Fatal(err)
				}
				if err := unix.Fsync(store.root.FD()); err != nil {
					_ = nextFile.Close()
					t.Fatal(err)
				}
			}
			if err := nextFile.Close(); err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}

			recovered, err := openPinOwnerStore(
				runtime,
				parent.resource,
				true,
			)
			if err != nil {
				t.Fatalf(
					"recover same-key owner %s crash: %v",
					phase,
					err,
				)
			}
			defer recovered.Close()
			loaded, err := recovered.Load(parent.mountID)
			if err != nil {
				t.Fatal(err)
			}
			if !sameExpectedOwnerRecord(loaded, current) {
				t.Fatalf(
					"same-key recovered owner = %#v, want %#v",
					loaded,
					current,
				)
			}
			index, exists, err := indexStoreFromOwner(
				recovered,
			).loadOptional()
			if err != nil {
				t.Fatal(err)
			}
			if !exists ||
				index.Sequence != 3 ||
				len(index.Entries) != 2 ||
				len(index.Active) != 1 ||
				index.Active[0].ResourceKey != current.ResourceKey ||
				index.Active[0].BootID != current.BootID ||
				index.Active[0].Status != pinOwnerIndexActive {
				t.Fatalf("same-key recovered index = %#v", index)
			}
			statusByBoot := make(map[string]string, len(index.Entries))
			for _, entry := range index.Entries {
				statusByBoot[entry.BootID] = entry.Status
			}
			if statusByBoot[oldRecord.BootID] !=
				pinOwnerIndexRetiredStatus ||
				statusByBoot[current.BootID] != pinOwnerIndexActive {
				t.Fatalf(
					"same-key recovered statuses = %#v",
					statusByBoot,
				)
			}
			if _, err := os.Lstat(filepath.Join(
				runtime.ownerRoot,
				historical.RecordFileName,
			)); err != nil {
				t.Fatalf("same-key old evidence was lost: %v", err)
			}
		})
	}
}

func TestPinOwnerIndexJSONFieldOrderAndActivePathUniqueness(t *testing.T) {
	_, _, record := testPinOwnerRecord(t, t.TempDir())
	now := time.Date(2026, 7, 29, 1, 2, 3, 4, time.UTC)
	entry, err := ownerIndexEntryFromRecord(
		record,
		pinOwnerIndexActive,
		"",
	)
	if err != nil {
		t.Fatal(err)
	}
	index := &pinOwnerIndex{
		Version:   pinOwnerIndexVersion,
		Sequence:  1,
		UpdatedAt: now.Format(time.RFC3339Nano),
		Active: []pinOwnerIndexActivePointer{
			activePointerFromEntry(entry),
		},
		Entries: []pinOwnerIndexEntry{entry},
	}
	data, err := marshalPinOwnerIndex(index)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONFieldOrder(t, data, []string{
		`"version":`,
		`"sequence":`,
		`"updated_at":`,
		`"active":`,
		`"rotation":`,
		`"entries":`,
	})
	activeStart := bytes.Index(data, []byte(`"active":[{`))
	if activeStart < 0 {
		t.Fatalf("owner index has no active pointer object: %s", data)
	}
	assertJSONFieldOrder(t, data[activeStart:], []string{
		`"bpffs_root_path":`,
		`"pin_basename":`,
		`"resource_key":`,
		`"boot_id":`,
		`"record_filename":`,
		`"status":`,
	})
	entryStart := bytes.Index(data, []byte(`"entries":[{`))
	if entryStart < 0 {
		t.Fatalf("owner index has no entry object: %s", data)
	}
	assertJSONFieldOrder(t, data[entryStart:], []string{
		`"resource_key":`,
		`"parent_device":`,
		`"parent_inode":`,
		`"pin_basename":`,
		`"bpffs_root_path":`,
		`"bpffs_mount_ids":`,
		`"boot_id":`,
		`"record_filename":`,
		`"owner_digest":`,
		`"status":`,
		`"retired_at":`,
	})
	retired, err := ownerIndexEntryFromRecord(
		record,
		pinOwnerIndexRetiredStatus,
		now.Format(time.RFC3339Nano),
	)
	if err != nil {
		t.Fatal(err)
	}
	rotationIndex := &pinOwnerIndex{
		Version:   pinOwnerIndexVersion,
		Sequence:  2,
		UpdatedAt: now.Add(time.Second).Format(time.RFC3339Nano),
		Rotation: &pinOwnerIndexRotation{
			ResourceKey:        retired.ResourceKey,
			BootID:             retired.BootID,
			RecordFileName:     retired.RecordFileName,
			QuarantineFileName: retired.RecordFileName + pinOwnerRotationSuffix,
			OwnerDigest:        retired.OwnerDigest,
		},
		Entries: []pinOwnerIndexEntry{retired},
	}
	rotationData, err := marshalPinOwnerIndex(rotationIndex)
	if err != nil {
		t.Fatal(err)
	}
	rotationStart := bytes.Index(rotationData, []byte(`"rotation":{`))
	if rotationStart < 0 {
		t.Fatalf("owner index has no rotation object: %s", rotationData)
	}
	assertJSONFieldOrder(t, rotationData[rotationStart:], []string{
		`"resource_key":`,
		`"boot_id":`,
		`"record_filename":`,
		`"quarantine_filename":`,
		`"owner_digest":`,
	})

	duplicate := entry
	duplicate.ResourceKey, err = pinidentity.Key(
		entry.ParentDevice+1,
		entry.ParentInode+1,
		entry.PinBaseName,
	)
	if err != nil {
		t.Fatal(err)
	}
	duplicate.ParentDevice++
	duplicate.ParentInode++
	duplicate.RecordFileName = duplicate.ResourceKey + ".owner.json"
	index.Entries = append(index.Entries, duplicate)
	index.Active = append(
		index.Active,
		activePointerFromEntry(duplicate),
	)
	normalizePinOwnerIndex(index)
	if err := validatePinOwnerIndex(index); err == nil ||
		!strings.Contains(err.Error(), "repeats active pointer") {
		t.Fatalf("duplicate active pin path error = %v", err)
	}
}

func TestPinOwnerIndexRejectsDuplicateActiveResourceAcrossPathAliases(
	t *testing.T,
) {
	_, _, record := testPinOwnerRecord(t, t.TempDir())
	now := time.Date(2026, 7, 29, 1, 2, 3, 4, time.UTC)
	first, err := ownerIndexEntryFromRecord(
		record,
		pinOwnerIndexActive,
		"",
	)
	if err != nil {
		t.Fatal(err)
	}
	second := first
	second.BootID = "22345678-1234-1234-1234-123456789abc"
	second.BPFFSRootPath = filepath.Join(
		filepath.Dir(first.BPFFSRootPath),
		"bpffs-alias",
	)
	index := &pinOwnerIndex{
		Version:   pinOwnerIndexVersion,
		Sequence:  1,
		UpdatedAt: now.Format(time.RFC3339Nano),
		Active: []pinOwnerIndexActivePointer{
			activePointerFromEntry(first),
			activePointerFromEntry(second),
		},
		Entries: []pinOwnerIndexEntry{first, second},
	}
	normalizePinOwnerIndex(index)
	if err := validatePinOwnerIndex(index); err == nil ||
		!strings.Contains(err.Error(), "active pointer for resource") {
		t.Fatalf("duplicate active resource error = %v", err)
	}
}

func TestPinOwnerIndexRejectsDisagreeingPathAndResourcePointers(
	t *testing.T,
) {
	_, parent, record := testPinOwnerRecord(t, t.TempDir())
	now := time.Date(2026, 7, 29, 1, 2, 3, 4, time.UTC)
	resourceEntry, err := ownerIndexEntryFromRecord(
		record,
		pinOwnerIndexActive,
		"",
	)
	if err != nil {
		t.Fatal(err)
	}
	aliasRoot := filepath.Join(
		filepath.Dir(resourceEntry.BPFFSRootPath),
		"bpffs-alias",
	)
	pathEntry := resourceEntry
	pathEntry.ParentDevice++
	pathEntry.ParentInode++
	pathEntry.ResourceKey, err = pinidentity.Key(
		pathEntry.ParentDevice,
		pathEntry.ParentInode,
		pathEntry.PinBaseName,
	)
	if err != nil {
		t.Fatal(err)
	}
	pathEntry.BPFFSRootPath = aliasRoot
	pathEntry.BootID = "22345678-1234-1234-1234-123456789abc"
	pathEntry.RecordFileName = pathEntry.ResourceKey + ".owner.json"
	index := &pinOwnerIndex{
		Version:   pinOwnerIndexVersion,
		Sequence:  1,
		UpdatedAt: now.Format(time.RFC3339Nano),
		Active: []pinOwnerIndexActivePointer{
			activePointerFromEntry(resourceEntry),
			activePointerFromEntry(pathEntry),
		},
		Entries: []pinOwnerIndexEntry{resourceEntry, pathEntry},
	}
	normalizePinOwnerIndex(index)
	if err := validatePinOwnerIndex(index); err != nil {
		t.Fatalf("valid ambiguous fixture: %v", err)
	}
	resource := parent.resource
	resource.pinPath = filepath.Join(aliasRoot, resource.base)
	if _, err := pinOwnerIndexPointerForResourceOrPath(
		index,
		resource,
		aliasRoot,
	); err == nil ||
		!strings.Contains(err.Error(), "pointers disagree") {
		t.Fatalf("disagreeing path/resource pointer error = %v", err)
	}
}

func TestPinOwnerIndexStaleExpectedDoesNotStageNext(t *testing.T) {
	runtime, _, _, store, _ := openPersistedTestPinOwner(t)
	indexStore := indexStoreFromOwner(store)
	expected, exists, err := indexStore.loadOptional()
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("persisted owner index is unavailable")
	}
	advanced := clonePinOwnerIndex(expected)
	advanced.Sequence++
	advanced.UpdatedAt = time.Date(
		2026,
		7,
		29,
		2,
		2,
		3,
		4,
		time.UTC,
	).Format(time.RFC3339Nano)
	if err := indexStore.persist(advanced, expected); err != nil {
		t.Fatal(err)
	}
	staleNext := clonePinOwnerIndex(expected)
	staleNext.Sequence++
	staleNext.UpdatedAt = time.Date(
		2026,
		7,
		29,
		3,
		2,
		3,
		4,
		time.UTC,
	).Format(time.RFC3339Nano)
	if err := indexStore.persist(
		staleNext,
		expected,
	); err == nil ||
		!strings.Contains(err.Error(), "before staging next") {
		t.Fatalf("stale index persist error = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(
		runtime.ownerRoot,
		pinOwnerIndexNextName,
	)); !os.IsNotExist(err) {
		t.Fatalf("stale index writer left next descriptor: %v", err)
	}
	current, exists, err := indexStore.loadOptional()
	if err != nil {
		t.Fatal(err)
	}
	if !exists || !samePinOwnerIndex(current, advanced) {
		t.Fatalf(
			"stale index writer changed current:\ncurrent=%#v\nwant=%#v",
			current,
			advanced,
		)
	}
}

func TestConcurrentPinOwnerIndexUpdatesForDifferentResources(
	t *testing.T,
) {
	root := t.TempDir()
	runtime, firstParent, firstRecord := testPinOwnerRecord(t, root)
	secondPinPath := filepath.Join(
		firstRecord.BPFFSRootPath,
		"wg-mix-ebpf-owner-concurrent",
	)
	secondBase := filepath.Base(secondPinPath)
	secondKey, err := pinidentity.Key(
		firstParent.resource.parentDevice,
		firstParent.resource.parentInode,
		secondBase,
	)
	if err != nil {
		t.Fatal(err)
	}
	secondResource := pinResourceIdentity{
		key:          secondKey,
		parentDevice: firstParent.resource.parentDevice,
		parentInode:  firstParent.resource.parentInode,
		base:         secondBase,
		pinPath:      secondPinPath,
	}
	secondParent := &pinPathParent{
		pinPath:  secondPinPath,
		base:     secondBase,
		mountID:  firstParent.mountID,
		resource: secondResource,
		runtime:  runtime,
	}
	var secondToken [32]byte
	for index := range secondToken {
		secondToken[index] = byte(0x60 + index)
	}
	secondRecord, err := newActivePinOwnerRecord(
		secondParent,
		secondToken,
		"22345678-1234-1234-1234-123456789abc",
		time.Date(2026, 7, 29, 1, 2, 3, 4, time.UTC),
		firstRecord.ActiveGeneration,
		firstRecord.Maps,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	firstStore, err := openPinOwnerStore(
		runtime,
		firstParent.resource,
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer firstStore.Close()
	secondStore, err := openPinOwnerStore(
		runtime,
		secondParent.resource,
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer secondStore.Close()

	start := make(chan struct{})
	results := make(chan error, 2)
	go func() {
		<-start
		results <- firstStore.Persist(
			firstRecord,
			nil,
			firstParent.mountID,
		)
	}()
	go func() {
		<-start
		results <- secondStore.Persist(
			secondRecord,
			nil,
			secondParent.mountID,
		)
	}()
	close(start)
	for result := 0; result < 2; result++ {
		if err := <-results; err != nil {
			t.Fatalf("concurrent owner/index persist: %v", err)
		}
	}

	index, exists, err := indexStoreFromOwner(firstStore).loadOptional()
	if err != nil {
		t.Fatal(err)
	}
	if !exists ||
		index.Sequence != 2 ||
		len(index.Entries) != 2 ||
		len(index.Active) != 2 {
		t.Fatalf("concurrent owner index = %#v", index)
	}
	for _, name := range []string{
		pinOwnerIndexNextName,
		pinOwnerIndexRetired,
	} {
		if _, err := os.Lstat(filepath.Join(
			runtime.ownerRoot,
			name,
		)); !os.IsNotExist(err) {
			t.Fatalf(
				"concurrent owner index left transient %s: %v",
				name,
				err,
			)
		}
	}
	for _, record := range []*pinOwnerRecord{
		firstRecord,
		secondRecord,
	} {
		if _, err := os.Lstat(filepath.Join(
			runtime.ownerRoot,
			record.ResourceKey+".owner.json",
		)); err != nil {
			t.Fatalf(
				"concurrent owner record %s is unavailable: %v",
				record.ResourceKey,
				err,
			)
		}
	}
}

func assertJSONFieldOrder(
	t *testing.T,
	data []byte,
	keys []string,
) {
	t.Helper()
	position := -1
	for _, key := range keys {
		next := bytes.Index(data, []byte(key))
		if next <= position {
			t.Fatalf("JSON field %s is out of order: %s", key, data)
		}
		position = next
	}
}

func openPersistedTestPinOwner(
	t *testing.T,
) (
	pinPathRuntime,
	*pinPathParent,
	*pinOwnerRecord,
	*pinOwnerStore,
	*pinOwnerIndexEntry,
) {
	t.Helper()
	runtime, parent, record := testPinOwnerRecord(t, t.TempDir())
	runtime.now = func() time.Time {
		return time.Date(2026, 7, 29, 1, 2, 3, 4, time.UTC)
	}
	parent.runtime = runtime
	store, err := openPinOwnerStore(runtime, parent.resource, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("close test pin owner store: %v", err)
		}
	})
	if err := store.Persist(record, nil, parent.mountID); err != nil {
		t.Fatal(err)
	}
	entry, err := activeIndexedOwnerForRecord(
		indexStoreFromOwner(store),
		record,
	)
	if err != nil {
		t.Fatal(err)
	}
	return runtime, parent, record, store, entry
}

func TestPinOwnerArchiveRecoveryAtEveryDurablePhase(t *testing.T) {
	for _, phase := range []string{
		"canonical",
		"archive",
		"history",
		"indexed",
	} {
		t.Run(phase, func(t *testing.T) {
			runtime, parent, record, store, entry :=
				openPersistedTestPinOwner(t)
			now := time.Date(2026, 7, 30, 1, 2, 3, 4, time.UTC)
			historical := *entry
			historical.Status = pinOwnerIndexRekeySource
			historical.RetiredAt = now.Format(time.RFC3339Nano)
			historical.RecordFileName = pinOwnerHistoryFileName(historical)
			archiveName := pinOwnerArchiveFileName(entry.ResourceKey)

			switch phase {
			case "canonical":
			case "archive":
				if err := unix.Renameat2(
					store.root.FD(),
					entry.RecordFileName,
					store.root.FD(),
					archiveName,
					unix.RENAME_NOREPLACE,
				); err != nil {
					t.Fatal(err)
				}
				if err := unix.Fsync(store.root.FD()); err != nil {
					t.Fatal(err)
				}
			case "history":
				if err := unix.Renameat2(
					store.root.FD(),
					entry.RecordFileName,
					store.root.FD(),
					archiveName,
					unix.RENAME_NOREPLACE,
				); err != nil {
					t.Fatal(err)
				}
				if err := unix.Renameat2(
					store.root.FD(),
					archiveName,
					store.root.FD(),
					historical.RecordFileName,
					unix.RENAME_NOREPLACE,
				); err != nil {
					t.Fatal(err)
				}
				if err := unix.Fsync(store.root.FD()); err != nil {
					t.Fatal(err)
				}
			case "indexed":
				archived, err := indexStoreFromOwner(store).archivePriorBootOwner(
					*entry,
					record,
					false,
					now,
				)
				if err != nil {
					t.Fatal(err)
				}
				historical = *archived
			default:
				t.Fatalf("unknown archive phase %q", phase)
			}

			if err := indexStoreFromOwner(store).recoverOwnerArchive(
				parent.resource,
			); err != nil {
				t.Fatalf("recover owner archive phase %s: %v", phase, err)
			}
			index, exists, err := indexStoreFromOwner(store).loadOptional()
			if err != nil {
				t.Fatal(err)
			}
			if !exists || len(index.Active) != 1 {
				t.Fatalf("archive recovery index = %#v", index)
			}
			if phase == "indexed" {
				if index.Active[0] != activePointerFromEntry(historical) ||
					index.Active[0].Status != pinOwnerIndexRekeySource {
					t.Fatalf(
						"durable archive pointer = %#v, want %#v",
						index.Active[0],
						activePointerFromEntry(historical),
					)
				}
				if _, err := os.Lstat(filepath.Join(
					runtime.ownerRoot,
					historical.RecordFileName,
				)); err != nil {
					t.Fatalf("durable historical owner is unavailable: %v", err)
				}
				if _, err := os.Lstat(filepath.Join(
					runtime.ownerRoot,
					entry.RecordFileName,
				)); !os.IsNotExist(err) {
					t.Fatalf("canonical owner returned after durable archive: %v", err)
				}
				return
			}
			if index.Active[0] != activePointerFromEntry(*entry) {
				t.Fatalf(
					"rolled-back archive pointer = %#v, want %#v",
					index.Active[0],
					activePointerFromEntry(*entry),
				)
			}
			loaded, err := store.Load(parent.mountID)
			if err != nil {
				t.Fatalf("load rolled-back canonical owner: %v", err)
			}
			if !sameExpectedOwnerRecord(loaded, record) {
				t.Fatalf("rolled-back owner = %#v, want %#v", loaded, record)
			}
			for _, transient := range []string{
				archiveName,
				historical.RecordFileName,
			} {
				if _, err := os.Lstat(filepath.Join(
					runtime.ownerRoot,
					transient,
				)); !os.IsNotExist(err) {
					t.Fatalf(
						"archive transient %s remains after rollback: %v",
						transient,
						err,
					)
				}
			}
		})
	}
}

func TestPinOwnerArchiveRejectsExactTargetCollisions(t *testing.T) {
	for _, target := range []string{"archive", "history"} {
		t.Run(target, func(t *testing.T) {
			runtime, parent, record, store, entry :=
				openPersistedTestPinOwner(t)
			historical := *entry
			historical.Status = pinOwnerIndexRekeySource
			historical.RetiredAt = time.Date(
				2026, 7, 30, 1, 2, 3, 4, time.UTC,
			).Format(time.RFC3339Nano)
			historical.RecordFileName = pinOwnerHistoryFileName(historical)
			collisionName := pinOwnerArchiveFileName(entry.ResourceKey)
			if target == "history" {
				collisionName = historical.RecordFileName
			}
			if err := os.WriteFile(
				filepath.Join(runtime.ownerRoot, collisionName),
				[]byte("collision\n"),
				0o600,
			); err != nil {
				t.Fatal(err)
			}
			_, err := indexStoreFromOwner(store).archivePriorBootOwner(
				*entry,
				record,
				false,
				time.Date(2026, 7, 30, 1, 2, 3, 4, time.UTC),
			)
			if err == nil || !strings.Contains(err.Error(), "already exists") {
				t.Fatalf("%s collision error = %v", target, err)
			}
			loaded, err := store.Load(parent.mountID)
			if err != nil {
				t.Fatalf("canonical owner lost after %s collision: %v", target, err)
			}
			if !sameExpectedOwnerRecord(loaded, record) {
				t.Fatalf("canonical owner changed after %s collision", target)
			}
			index, exists, err := indexStoreFromOwner(store).loadOptional()
			if err != nil {
				t.Fatal(err)
			}
			if !exists ||
				len(index.Active) != 1 ||
				index.Active[0] != activePointerFromEntry(*entry) {
				t.Fatalf("index changed after %s collision: %#v", target, index)
			}
		})
	}
}

func TestPinOwnerArchiveRejectsCanonicalSwapAtHook(t *testing.T) {
	runtime, parent, record, store, entry := openPersistedTestPinOwner(t)
	swappedName := entry.RecordFileName + ".swapped"
	var hookErr error
	store.beforeOwnerExchange = func() {
		if hookErr != nil {
			return
		}
		hookErr = unix.Renameat2(
			store.root.FD(),
			entry.RecordFileName,
			store.root.FD(),
			swappedName,
			unix.RENAME_NOREPLACE,
		)
		if hookErr == nil {
			hookErr = os.WriteFile(
				filepath.Join(runtime.ownerRoot, entry.RecordFileName),
				[]byte("{}\n"),
				0o600,
			)
		}
	}
	_, err := indexStoreFromOwner(store).archivePriorBootOwner(
		*entry,
		record,
		false,
		time.Date(2026, 7, 30, 1, 2, 3, 4, time.UTC),
	)
	if hookErr != nil {
		t.Fatalf("archive swap hook: %v", hookErr)
	}
	if err == nil ||
		!strings.Contains(err.Error(), "changed at archive hook") {
		t.Fatalf("archive canonical-swap error = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(
		runtime.ownerRoot,
		swappedName,
	)); err != nil {
		t.Fatalf("original swapped owner evidence is unavailable: %v", err)
	}
	index, exists, indexErr := indexStoreFromOwner(store).loadOptional()
	if indexErr != nil {
		t.Fatal(indexErr)
	}
	if !exists ||
		len(index.Active) != 1 ||
		index.Active[0] != activePointerFromEntry(*entry) {
		t.Fatalf("index changed after canonical swap: %#v", index)
	}
	if _, loadErr := store.Load(parent.mountID); loadErr == nil {
		t.Fatal("replacement canonical owner unexpectedly validated")
	}
}

func advanceTestPinOwnerHistory(
	t *testing.T,
	parent *pinPathParent,
	store *pinOwnerStore,
	current *pinOwnerRecord,
	count int,
) (*pinOwnerRecord, []pinOwnerIndexEntry) {
	t.Helper()
	history := make([]pinOwnerIndexEntry, 0, count)
	baseTime := time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC)
	for generation := 1; generation <= count; generation++ {
		indexed, err := activeIndexedOwnerForRecord(
			indexStoreFromOwner(store),
			current,
		)
		if err != nil {
			t.Fatal(err)
		}
		transitionTime := baseTime.Add(time.Duration(generation) * time.Hour)
		archived, err := indexStoreFromOwner(store).archivePriorBootOwner(
			*indexed,
			current,
			false,
			transitionTime,
		)
		if err != nil {
			t.Fatal(err)
		}
		history = append(history, *archived)

		var token [32]byte
		for tokenIndex := range token {
			token[tokenIndex] = byte(0x20 + generation + tokenIndex)
		}
		next, err := newActivePinOwnerRecord(
			parent,
			token,
			fmt.Sprintf(
				"%08x-1234-1234-1234-%012x",
				0x20000000+generation,
				generation,
			),
			transitionTime.Add(time.Minute),
			current.ActiveGeneration,
			current.Maps,
			nil,
		)
		if err != nil {
			t.Fatal(err)
		}
		next.RetiredFromResourceKey = current.ResourceKey
		next.RetiredFromBootID = current.BootID
		normalizePinOwnerRecord(next)
		if err := validatePinOwnerRecord(
			next,
			parent.resource,
			parent.mountID,
		); err != nil {
			t.Fatal(err)
		}
		if err := store.Persist(next, nil, parent.mountID); err != nil {
			t.Fatal(err)
		}
		current = next
	}
	return current, history
}

func testPinOwnerHistoryAtCapacity(
	t *testing.T,
) (
	pinPathRuntime,
	*pinPathParent,
	*pinOwnerRecord,
	*pinOwnerStore,
	*pinOwnerIndex,
	pinOwnerIndexEntry,
) {
	t.Helper()
	runtime, parent, record, store, _ := openPersistedTestPinOwner(t)
	current, _ := advanceTestPinOwnerHistory(
		t,
		parent,
		store,
		record,
		pinOwnerIndexMaxHistory,
	)
	index, exists, err := indexStoreFromOwner(store).loadOptional()
	if err != nil {
		t.Fatal(err)
	}
	if !exists ||
		len(index.Entries) != pinOwnerIndexMaxHistory+1 ||
		len(index.Active) != 1 {
		t.Fatalf("history-at-capacity index = %#v", index)
	}
	var retired []pinOwnerIndexEntry
	for _, entry := range index.Entries {
		if entry.Status == pinOwnerIndexRetiredStatus {
			retired = append(retired, entry)
		}
	}
	sort.Slice(retired, func(i, j int) bool {
		if retired[i].RetiredAt != retired[j].RetiredAt {
			return retired[i].RetiredAt < retired[j].RetiredAt
		}
		return pinOwnerIndexEntryLess(retired[i], retired[j])
	})
	if len(retired) != pinOwnerIndexMaxHistory {
		t.Fatalf("retired history count = %d", len(retired))
	}
	return runtime, parent, current, store, index, retired[0]
}

func persistTestPinOwnerRotationJournal(
	t *testing.T,
	store *pinOwnerStore,
	index *pinOwnerIndex,
	victim pinOwnerIndexEntry,
) *pinOwnerIndex {
	t.Helper()
	next := clonePinOwnerIndex(index)
	next.Sequence++
	next.UpdatedAt = time.Date(
		2026, 8, 1, 1, 2, 3, 4, time.UTC,
	).Format(time.RFC3339Nano)
	next.Rotation = &pinOwnerIndexRotation{
		ResourceKey:        victim.ResourceKey,
		BootID:             victim.BootID,
		RecordFileName:     victim.RecordFileName,
		QuarantineFileName: victim.RecordFileName + pinOwnerRotationSuffix,
		OwnerDigest:        victim.OwnerDigest,
	}
	normalizePinOwnerIndex(next)
	if err := indexStoreFromOwner(store).persist(next, index); err != nil {
		t.Fatal(err)
	}
	return next
}

func TestPinOwnerHistoryBoundRotatesOnlyOldestExactRecord(t *testing.T) {
	runtime, parent, current, store, _, oldest :=
		testPinOwnerHistoryAtCapacity(t)
	currentIndexed, err := activeIndexedOwnerForRecord(
		indexStoreFromOwner(store),
		current,
	)
	if err != nil {
		t.Fatal(err)
	}
	archiveTime := time.Date(2026, 8, 1, 2, 0, 0, 0, time.UTC)
	latestHistory, err := indexStoreFromOwner(store).archivePriorBootOwner(
		*currentIndexed,
		current,
		false,
		archiveTime,
	)
	if err != nil {
		t.Fatal(err)
	}
	var nextToken [32]byte
	for index := range nextToken {
		nextToken[index] = byte(0xa0 + index)
	}
	next, err := newActivePinOwnerRecord(
		parent,
		nextToken,
		"87654321-4321-4321-4321-cba987654321",
		archiveTime.Add(time.Minute),
		current.ActiveGeneration,
		current.Maps,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	next.RetiredFromResourceKey = current.ResourceKey
	next.RetiredFromBootID = current.BootID
	normalizePinOwnerRecord(next)
	if err := store.Persist(next, nil, parent.mountID); err != nil {
		t.Fatal(err)
	}
	index, exists, err := indexStoreFromOwner(store).loadOptional()
	if err != nil {
		t.Fatal(err)
	}
	if !exists ||
		index.Rotation != nil ||
		len(index.Entries) != pinOwnerIndexMaxHistory+1 ||
		len(index.Active) != 1 ||
		index.Active[0].BootID != next.BootID ||
		index.Active[0].Status != pinOwnerIndexActive {
		t.Fatalf("rotated history index = %#v", index)
	}
	historyCount := 0
	for _, entry := range index.Entries {
		if entry.Status != pinOwnerIndexActive {
			historyCount++
		}
		if entry.ResourceKey == oldest.ResourceKey &&
			entry.BootID == oldest.BootID {
			t.Fatalf("oldest rotated entry remains indexed: %#v", entry)
		}
	}
	if historyCount != pinOwnerIndexMaxHistory {
		t.Fatalf("history count after bounded rotation = %d", historyCount)
	}
	if _, err := os.Lstat(filepath.Join(
		runtime.ownerRoot,
		oldest.RecordFileName,
	)); !os.IsNotExist(err) {
		t.Fatalf("oldest history remains after rotation: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(
		runtime.ownerRoot,
		oldest.RecordFileName+pinOwnerRotationSuffix,
	)); !os.IsNotExist(err) {
		t.Fatalf("oldest history quarantine remains after rotation: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(
		runtime.ownerRoot,
		latestHistory.RecordFileName,
	)); err != nil {
		t.Fatalf("latest exact history was not preserved: %v", err)
	}
}

func TestPinOwnerHistoryBoundCannotBeBypassedWithPathAliases(t *testing.T) {
	runtime, parent, current, store, _ := openPersistedTestPinOwner(t)
	aliasRoot := filepath.Join(
		filepath.Dir(current.BPFFSRootPath),
		"bpffs-alias",
	)
	aliasResource := parent.resource
	aliasResource.pinPath = filepath.Join(
		aliasRoot,
		aliasResource.base,
	)
	aliasParent := &pinPathParent{
		pinPath:  aliasResource.pinPath,
		base:     aliasResource.base,
		mountID:  parent.mountID + 1,
		resource: aliasResource,
		runtime:  runtime,
	}
	var archived []pinOwnerIndexEntry
	baseTime := time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC)
	for generation := 1; generation <= pinOwnerIndexMaxHistory+2; generation++ {
		indexed, err := activeIndexedOwnerForRecord(
			indexStoreFromOwner(store),
			current,
		)
		if err != nil {
			t.Fatal(err)
		}
		transitionTime := baseTime.Add(
			time.Duration(generation) * time.Hour,
		)
		history, err := indexStoreFromOwner(store).archivePriorBootOwner(
			*indexed,
			current,
			false,
			transitionTime,
		)
		if err != nil {
			t.Fatal(err)
		}
		archived = append(archived, *history)

		nextParent := parent
		if generation%2 != 0 {
			nextParent = aliasParent
		}
		var token [32]byte
		for tokenIndex := range token {
			token[tokenIndex] = byte(
				0x30 + generation + tokenIndex,
			)
		}
		next, err := newActivePinOwnerRecord(
			nextParent,
			token,
			fmt.Sprintf(
				"%08x-1234-1234-1234-%012x",
				0x30000000+generation,
				generation,
			),
			transitionTime.Add(time.Minute),
			current.ActiveGeneration,
			current.Maps,
			nil,
		)
		if err != nil {
			t.Fatal(err)
		}
		next.RetiredFromResourceKey = current.ResourceKey
		next.RetiredFromBootID = current.BootID
		normalizePinOwnerRecord(next)
		if err := store.Persist(
			next,
			nil,
			nextParent.mountID,
		); err != nil {
			t.Fatal(err)
		}
		current = next
	}

	index, exists, err := indexStoreFromOwner(store).loadOptional()
	if err != nil {
		t.Fatal(err)
	}
	if !exists || len(index.Active) != 1 {
		t.Fatalf("path-alias history index = %#v", index)
	}
	resourceHistory := 0
	historyByPath := make(map[string]int)
	for _, entry := range index.Entries {
		if entry.Status == pinOwnerIndexActive {
			continue
		}
		if entry.ResourceKey == parent.resource.key {
			resourceHistory++
		}
		historyByPath[pinOwnerIndexPathKey(
			entry.BPFFSRootPath,
			entry.PinBaseName,
		)]++
	}
	if resourceHistory != pinOwnerIndexMaxHistory {
		t.Fatalf(
			"path-alias resource history count = %d, want %d",
			resourceHistory,
			pinOwnerIndexMaxHistory,
		)
	}
	for path, count := range historyByPath {
		if count > pinOwnerIndexMaxHistory {
			t.Fatalf(
				"path-alias history for %q = %d, maximum %d",
				path,
				count,
				pinOwnerIndexMaxHistory,
			)
		}
	}
	rotated := len(archived) - pinOwnerIndexMaxHistory
	for historyIndex, history := range archived {
		_, err := os.Lstat(filepath.Join(
			runtime.ownerRoot,
			history.RecordFileName,
		))
		if historyIndex < rotated {
			if !os.IsNotExist(err) {
				t.Fatalf(
					"rotated path-alias history %s remains: %v",
					history.RecordFileName,
					err,
				)
			}
			continue
		}
		if err != nil {
			t.Fatalf(
				"retained path-alias history %s is unavailable: %v",
				history.RecordFileName,
				err,
			)
		}
	}
}

func TestPinOwnerArchiveCollisionAtHistoryBoundDoesNotRotate(t *testing.T) {
	runtime, _, current, store, before, oldest :=
		testPinOwnerHistoryAtCapacity(t)
	currentIndexed, err := activeIndexedOwnerForRecord(
		indexStoreFromOwner(store),
		current,
	)
	if err != nil {
		t.Fatal(err)
	}
	historical := *currentIndexed
	historical.Status = pinOwnerIndexRekeySource
	historical.RetiredAt = time.Date(
		2026, 8, 1, 2, 0, 0, 0, time.UTC,
	).Format(time.RFC3339Nano)
	historical.RecordFileName = pinOwnerHistoryFileName(historical)
	if err := os.WriteFile(
		filepath.Join(runtime.ownerRoot, historical.RecordFileName),
		[]byte("collision\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	_, err = indexStoreFromOwner(store).archivePriorBootOwner(
		*currentIndexed,
		current,
		false,
		time.Date(2026, 8, 1, 2, 0, 0, 0, time.UTC),
	)
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("history-bound archive collision error = %v", err)
	}
	after, exists, err := indexStoreFromOwner(store).loadOptional()
	if err != nil {
		t.Fatal(err)
	}
	if !exists || !samePinOwnerIndex(after, before) {
		t.Fatalf(
			"history index rotated before collision refusal:\nbefore=%#v\nafter=%#v",
			before,
			after,
		)
	}
	if _, err := os.Lstat(filepath.Join(
		runtime.ownerRoot,
		oldest.RecordFileName,
	)); err != nil {
		t.Fatalf("oldest evidence was removed before collision refusal: %v", err)
	}
}

func TestPinOwnerHistoryRotationRecoversEveryDurablePhase(t *testing.T) {
	for _, phase := range []string{
		"journaled",
		"quarantined",
		"unlinked",
	} {
		t.Run(phase, func(t *testing.T) {
			runtime, _, _, store, index, victim :=
				testPinOwnerHistoryAtCapacity(t)
			journal := persistTestPinOwnerRotationJournal(
				t,
				store,
				index,
				victim,
			)
			quarantineName := journal.Rotation.QuarantineFileName
			if phase == "quarantined" || phase == "unlinked" {
				if err := unix.Renameat2(
					store.root.FD(),
					victim.RecordFileName,
					store.root.FD(),
					quarantineName,
					unix.RENAME_NOREPLACE,
				); err != nil {
					t.Fatal(err)
				}
				if err := unix.Fsync(store.root.FD()); err != nil {
					t.Fatal(err)
				}
			}
			if phase == "unlinked" {
				history, err := validatePinOwnerHistoryAt(
					indexStoreFromOwner(store),
					victim,
					quarantineName,
				)
				if err != nil {
					t.Fatal(err)
				}
				if err := unlinkAnchoredRegularFile(
					store.root,
					quarantineName,
					int(history.file.Fd()),
					history.identity,
					store.expectedUID,
				); err != nil {
					_ = history.Close()
					t.Fatal(err)
				}
				if err := history.Close(); err != nil {
					t.Fatal(err)
				}
			}
			recovered, exists, err := indexStoreFromOwner(store).loadOptional()
			if err != nil {
				t.Fatalf("recover rotation phase %s: %v", phase, err)
			}
			if !exists ||
				recovered.Rotation != nil ||
				len(recovered.Entries) != len(index.Entries)-1 {
				t.Fatalf("recovered rotation index = %#v", recovered)
			}
			for _, entry := range recovered.Entries {
				if entry.ResourceKey == victim.ResourceKey &&
					entry.BootID == victim.BootID {
					t.Fatalf("rotation victim remains indexed: %#v", entry)
				}
			}
			for _, name := range []string{
				victim.RecordFileName,
				quarantineName,
			} {
				if _, err := os.Lstat(filepath.Join(
					runtime.ownerRoot,
					name,
				)); !os.IsNotExist(err) {
					t.Fatalf(
						"rotation phase %s left %s: %v",
						phase,
						name,
						err,
					)
				}
			}
		})
	}
}

func TestPinOwnerHistoryRotationFailsClosedOnArchiveCollision(t *testing.T) {
	runtime, _, _, store, index, victim :=
		testPinOwnerHistoryAtCapacity(t)
	journal := persistTestPinOwnerRotationJournal(
		t,
		store,
		index,
		victim,
	)
	original, err := os.ReadFile(filepath.Join(
		runtime.ownerRoot,
		victim.RecordFileName,
	))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(
			runtime.ownerRoot,
			journal.Rotation.QuarantineFileName,
		),
		original,
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if _, _, err := indexStoreFromOwner(store).loadOptional(); err == nil ||
		!strings.Contains(err.Error(), "both original and quarantine") {
		t.Fatalf("rotation collision error = %v", err)
	}
	for _, name := range []string{
		victim.RecordFileName,
		journal.Rotation.QuarantineFileName,
	} {
		if _, err := os.Lstat(filepath.Join(
			runtime.ownerRoot,
			name,
		)); err != nil {
			t.Fatalf("rotation collision evidence %s was lost: %v", name, err)
		}
	}
	file, _, err := openExistingAnchoredRegularFile(
		store.root,
		pinOwnerIndexFileName,
		0o600,
		store.expectedUID,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	stillJournaled, err := readPinOwnerIndex(file)
	if err != nil {
		t.Fatal(err)
	}
	if stillJournaled.Rotation == nil ||
		*stillJournaled.Rotation != *journal.Rotation {
		t.Fatalf("rotation journal changed after collision: %#v", stillJournaled)
	}
}

func TestPinOwnerIndexRemovesFileWhenLastEntryIsRemoved(t *testing.T) {
	root := t.TempDir()
	runtime, parent, record := testPinOwnerRecord(t, root)
	store, err := openPinOwnerStore(runtime, parent.resource, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Persist(record, nil, parent.mountID); err != nil {
		t.Fatal(err)
	}
	indexStore := indexStoreFromOwner(store)
	entry, err := ownerIndexEntryFromRecord(
		record,
		pinOwnerIndexActive,
		"",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := indexStore.updateEntry(
		entry,
		true,
		time.Date(2026, 7, 29, 2, 0, 0, 0, time.UTC),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(
		runtime.ownerRoot,
		pinOwnerIndexFileName,
	)); !os.IsNotExist(err) {
		t.Fatalf("empty owner index file still exists: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRekeyRebootedOwnerPreservesOldRecordAndRetiresIndex(t *testing.T) {
	bpffsRoot, validator := newTestBPFFS(t)
	pinPath := filepath.Join(bpffsRoot, "wg-mix-ebpf-rekey-test")
	mapStore := writeCanonicalMockPins(t, pinPath)
	runtime := newTestPinPathRuntime(t, validator, mapStore)
	runtime.random = bytes.NewReader(bytes.Repeat([]byte{0x5a}, 32))
	runtime.now = func() time.Time {
		return time.Date(2026, 7, 30, 1, 2, 3, 4, time.UTC)
	}
	validated, err := validatePinPath(pinPath, validator)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := openPinPathParent(pinPath, validated, runtime)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	handle, _, err := openPinPathHandleFromParent(parent, validated, false)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()

	oldResource := handle.resource
	oldResource.parentDevice += 1000
	oldResource.parentInode += 1000
	oldResource.key, err = pinidentity.Key(
		oldResource.parentDevice,
		oldResource.parentInode,
		oldResource.base,
	)
	if err != nil {
		t.Fatal(err)
	}
	oldParent := &pinPathParent{
		pinPath:  pinPath,
		base:     oldResource.base,
		mountID:  handle.mountID,
		resource: oldResource,
		runtime:  runtime,
	}
	pins, err := inspectPinnedMapSet(handle, true)
	if err != nil {
		t.Fatal(err)
	}
	oldMaps := ownerMapsFromPins(pins)
	if err := closePinnedMapPins(pins); err != nil {
		t.Fatal(err)
	}
	var oldToken [32]byte
	for index := range oldToken {
		oldToken[index] = byte(index + 1)
	}
	oldSentinel, err := pinOwnerSentinelFor(oldResource, oldToken)
	if err != nil {
		t.Fatal(err)
	}
	ownerObservation := mapStore.observations["owner_map"]
	ownerObservation.owner = oldSentinel
	ownerObservation.ownerSeen = true
	mapStore.observations["owner_map"] = ownerObservation
	oldRecord, err := newActivePinOwnerRecord(
		oldParent,
		oldToken,
		"12345678-1234-1234-1234-123456789abc",
		time.Date(2026, 7, 29, 1, 2, 3, 4, time.UTC),
		1,
		oldMaps,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	oldStore, err := openPinOwnerStore(runtime, oldResource, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := oldStore.Persist(oldRecord, nil, handle.mountID); err != nil {
		t.Fatal(err)
	}
	indexedOld, err := activeIndexedOwnerForRecord(
		indexStoreFromOwner(oldStore),
		oldRecord,
	)
	if err != nil {
		t.Fatal(err)
	}
	historical, err := indexStoreFromOwner(oldStore).archivePriorBootOwner(
		*indexedOld,
		oldRecord,
		true,
		runtime.now(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := oldStore.Close(); err != nil {
		t.Fatal(err)
	}

	currentStore, err := openPinOwnerStore(runtime, handle.resource, true)
	if err != nil {
		t.Fatal(err)
	}
	defer currentStore.Close()
	entry, err := indexedOwnerEntryForRekey(currentStore, handle)
	if err != nil {
		t.Fatal(err)
	}
	if entry == nil ||
		!samePinOwnerIndexEntries(
			[]pinOwnerIndexEntry{*entry},
			[]pinOwnerIndexEntry{*historical},
		) {
		t.Fatalf("indexed rekey source = %#v", entry)
	}
	currentBoot := "87654321-4321-4321-4321-cba987654321"
	rekeyed, err := rekeyRebootedPinOwner(
		handle,
		parent,
		currentStore,
		entry,
		currentBoot,
		runtime.now(),
		tcRuntime{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if rekeyed.ResourceKey != handle.resource.key ||
		rekeyed.RetiredFromResourceKey != oldResource.key ||
		rekeyed.RetiredFromBootID != oldRecord.BootID ||
		rekeyed.BootID != currentBoot ||
		len(rekeyed.ActiveFilters) != 0 {
		t.Fatalf("rekeyed owner = %#v", rekeyed)
	}
	if _, err := os.Stat(filepath.Join(
		runtime.ownerRoot,
		historical.RecordFileName,
	)); err != nil {
		t.Fatalf("old owner record was not preserved: %v", err)
	}
	index, exists, err := indexStoreFromOwner(currentStore).loadOptional()
	if err != nil {
		t.Fatal(err)
	}
	if !exists || len(index.Entries) != 2 {
		t.Fatalf("rekey owner index = %#v", index)
	}
	if index.Sequence != 3 {
		t.Fatalf(
			"rekey owner index sequence = %d, want archive plus publish to reach 3",
			index.Sequence,
		)
	}
	statuses := make(map[string]string)
	var activeEntry *pinOwnerIndexEntry
	for _, indexed := range index.Entries {
		statuses[pinOwnerIndexEntryKey(
			indexed.ResourceKey,
			indexed.BootID,
		)] = indexed.Status
		if indexed.Status == pinOwnerIndexActive {
			copy := indexed
			activeEntry = &copy
		}
	}
	if statuses[pinOwnerIndexEntryKey(
		oldResource.key,
		oldRecord.BootID,
	)] != pinOwnerIndexRetiredStatus ||
		statuses[pinOwnerIndexEntryKey(
			handle.resource.key,
			currentBoot,
		)] != pinOwnerIndexActive ||
		len(index.Active) != 1 ||
		activeEntry == nil ||
		index.Active[0] != activePointerFromEntry(*activeEntry) {
		t.Fatalf("rekey owner index statuses = %#v", statuses)
	}
}

func TestRekeyRebootedOwnerWithSameResourceKeyAndOlderHistory(t *testing.T) {
	bpffsRoot, validator := newTestBPFFS(t)
	pinPath := filepath.Join(bpffsRoot, "wg-mix-ebpf-same-key-rekey")
	mapStore := writeCanonicalMockPins(t, pinPath)
	runtime := newTestPinPathRuntime(t, validator, mapStore)
	runtime.random = bytes.NewReader(bytes.Repeat([]byte{0x5a}, 32))
	runtime.now = func() time.Time {
		return time.Date(2026, 7, 31, 1, 2, 3, 4, time.UTC)
	}
	validated, err := validatePinPath(pinPath, validator)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := openPinPathParent(pinPath, validated, runtime)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	handle, _, err := openPinPathHandleFromParent(parent, validated, false)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()

	pins, err := inspectPinnedMapSet(handle, true)
	if err != nil {
		t.Fatal(err)
	}
	ownerMaps := ownerMapsFromPins(pins)
	if err := closePinnedMapPins(pins); err != nil {
		t.Fatal(err)
	}
	var firstToken [32]byte
	for index := range firstToken {
		firstToken[index] = byte(index + 1)
	}
	firstBoot := "12345678-1234-1234-1234-123456789abc"
	firstRecord, err := newActivePinOwnerRecord(
		parent,
		firstToken,
		firstBoot,
		time.Date(2026, 7, 29, 1, 2, 3, 4, time.UTC),
		1,
		ownerMaps,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	firstSentinel, err := pinOwnerSentinelFor(
		handle.resource,
		firstToken,
	)
	if err != nil {
		t.Fatal(err)
	}
	ownerObservation := mapStore.observations["owner_map"]
	ownerObservation.owner = firstSentinel
	ownerObservation.ownerSeen = true
	mapStore.observations["owner_map"] = ownerObservation

	store, err := openPinOwnerStore(runtime, handle.resource, true)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Persist(firstRecord, nil, handle.mountID); err != nil {
		t.Fatal(err)
	}
	firstIndexed, err := activeIndexedOwnerForRecord(
		indexStoreFromOwner(store),
		firstRecord,
	)
	if err != nil {
		t.Fatal(err)
	}
	firstHistory, err := indexStoreFromOwner(store).archivePriorBootOwner(
		*firstIndexed,
		firstRecord,
		true,
		time.Date(2026, 7, 30, 1, 2, 3, 4, time.UTC),
	)
	if err != nil {
		t.Fatal(err)
	}

	var secondToken [32]byte
	for index := range secondToken {
		secondToken[index] = byte(0x40 + index)
	}
	secondBoot := "22345678-1234-1234-1234-123456789abc"
	secondRecord, err := newActivePinOwnerRecord(
		parent,
		secondToken,
		secondBoot,
		time.Date(2026, 7, 30, 2, 2, 3, 4, time.UTC),
		firstRecord.ActiveGeneration,
		ownerMaps,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	secondRecord.RetiredFromResourceKey = firstRecord.ResourceKey
	secondRecord.RetiredFromBootID = firstRecord.BootID
	normalizePinOwnerRecord(secondRecord)
	if err := validatePinOwnerRecord(
		secondRecord,
		handle.resource,
		handle.mountID,
	); err != nil {
		t.Fatal(err)
	}
	secondSentinel, err := pinOwnerSentinelFor(
		handle.resource,
		secondToken,
	)
	if err != nil {
		t.Fatal(err)
	}
	ownerObservation = mapStore.observations["owner_map"]
	ownerObservation.owner = secondSentinel
	mapStore.observations["owner_map"] = ownerObservation
	if err := store.Persist(
		secondRecord,
		nil,
		handle.mountID,
	); err != nil {
		t.Fatal(err)
	}
	secondIndexed, err := activeIndexedOwnerForRecord(
		indexStoreFromOwner(store),
		secondRecord,
	)
	if err != nil {
		t.Fatal(err)
	}
	secondHistory, err := indexStoreFromOwner(store).archivePriorBootOwner(
		*secondIndexed,
		secondRecord,
		true,
		runtime.now(),
	)
	if err != nil {
		t.Fatal(err)
	}

	rekeySource, err := indexedOwnerEntryForRekey(store, handle)
	if err != nil {
		t.Fatal(err)
	}
	if rekeySource == nil ||
		!samePinOwnerIndexEntries(
			[]pinOwnerIndexEntry{*rekeySource},
			[]pinOwnerIndexEntry{*secondHistory},
		) {
		t.Fatalf("same-key rekey source = %#v", rekeySource)
	}
	currentBoot := "87654321-4321-4321-4321-cba987654321"
	rekeyed, err := rekeyRebootedPinOwner(
		handle,
		parent,
		store,
		rekeySource,
		currentBoot,
		runtime.now(),
		tcRuntime{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if rekeyed.ResourceKey != firstRecord.ResourceKey ||
		rekeyed.RetiredFromResourceKey != secondRecord.ResourceKey ||
		rekeyed.RetiredFromBootID != secondBoot ||
		rekeyed.BootID != currentBoot {
		t.Fatalf("same-key rekeyed owner = %#v", rekeyed)
	}
	for _, history := range []*pinOwnerIndexEntry{
		firstHistory,
		secondHistory,
	} {
		if _, err := os.Stat(filepath.Join(
			runtime.ownerRoot,
			history.RecordFileName,
		)); err != nil {
			t.Fatalf(
				"same-key history %s is not preserved: %v",
				history.RecordFileName,
				err,
			)
		}
	}
	index, exists, err := indexStoreFromOwner(store).loadOptional()
	if err != nil {
		t.Fatal(err)
	}
	if !exists || len(index.Entries) != 3 || len(index.Active) != 1 {
		t.Fatalf("same-key rekey index = %#v", index)
	}
	statusByBoot := make(map[string]string, len(index.Entries))
	for _, entry := range index.Entries {
		if entry.ResourceKey != handle.resource.key {
			t.Fatalf("same-key history changed resource key: %#v", entry)
		}
		statusByBoot[entry.BootID] = entry.Status
	}
	if statusByBoot[firstBoot] != pinOwnerIndexRetiredStatus ||
		statusByBoot[secondBoot] != pinOwnerIndexRetiredStatus ||
		statusByBoot[currentBoot] != pinOwnerIndexActive ||
		index.Active[0].ResourceKey != handle.resource.key ||
		index.Active[0].BootID != currentBoot {
		t.Fatalf("same-key statuses = %#v active=%#v", statusByBoot, index.Active)
	}
}

func TestSameResourcePathAliasRetryRetiresExactRekeySource(t *testing.T) {
	runtime, parent, oldRecord, store, indexed :=
		openPersistedTestPinOwner(t)
	archiveTime := time.Date(2026, 7, 30, 1, 2, 3, 4, time.UTC)
	historical, err := indexStoreFromOwner(store).archivePriorBootOwner(
		*indexed,
		oldRecord,
		false,
		archiveTime,
	)
	if err != nil {
		t.Fatal(err)
	}

	aliasRoot := filepath.Join(
		filepath.Dir(oldRecord.BPFFSRootPath),
		"bpffs-alias",
	)
	aliasPinPath := filepath.Join(aliasRoot, parent.resource.base)
	aliasResource := parent.resource
	aliasResource.pinPath = aliasPinPath
	aliasParent := &pinPathParent{
		pinPath:  aliasPinPath,
		base:     aliasResource.base,
		mountID:  parent.mountID + 1,
		resource: aliasResource,
		runtime:  runtime,
	}
	aliasStore, err := openPinOwnerStore(
		runtime,
		aliasResource,
		true,
	)
	if err != nil {
		t.Fatalf("open owner store through path alias: %v", err)
	}
	defer aliasStore.Close()
	retrySource, err := indexedOwnerEntryForRekey(
		aliasStore,
		&pinPathHandle{
			pinPath:  aliasPinPath,
			resource: aliasResource,
		},
	)
	if err != nil {
		t.Fatalf("find rekey source through path alias: %v", err)
	}
	if retrySource == nil ||
		!samePinOwnerIndexEntries(
			[]pinOwnerIndexEntry{*retrySource},
			[]pinOwnerIndexEntry{*historical},
		) {
		t.Fatalf("path-alias rekey source = %#v", retrySource)
	}

	var token [32]byte
	for index := range token {
		token[index] = byte(0x90 + index)
	}
	current, err := newActivePinOwnerRecord(
		aliasParent,
		token,
		"87654321-4321-4321-4321-cba987654321",
		archiveTime.Add(time.Minute),
		oldRecord.ActiveGeneration,
		oldRecord.Maps,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	current.RetiredFromResourceKey = historical.ResourceKey
	current.RetiredFromBootID = historical.BootID
	normalizePinOwnerRecord(current)
	if err := aliasStore.Persist(
		current,
		nil,
		aliasParent.mountID,
	); err != nil {
		t.Fatalf("publish reboot owner through path alias: %v", err)
	}

	index, exists, err := indexStoreFromOwner(aliasStore).loadOptional()
	if err != nil {
		t.Fatal(err)
	}
	if !exists || len(index.Active) != 1 ||
		len(index.Entries) != 2 {
		t.Fatalf("path-alias retry index = %#v", index)
	}
	if index.Active[0].BPFFSRootPath != aliasRoot ||
		index.Active[0].ResourceKey != current.ResourceKey ||
		index.Active[0].BootID != current.BootID ||
		index.Active[0].Status != pinOwnerIndexActive {
		t.Fatalf("path-alias active pointer = %#v", index.Active[0])
	}
	statusByBoot := make(map[string]string, len(index.Entries))
	for _, entry := range index.Entries {
		statusByBoot[entry.BootID] = entry.Status
	}
	if statusByBoot[oldRecord.BootID] !=
		pinOwnerIndexRetiredStatus ||
		statusByBoot[current.BootID] != pinOwnerIndexActive {
		t.Fatalf("path-alias retry statuses = %#v", statusByBoot)
	}
	if _, err := os.Lstat(filepath.Join(
		runtime.ownerRoot,
		historical.RecordFileName,
	)); err != nil {
		t.Fatalf("path-alias retry lost old evidence: %v", err)
	}
	loaded, err := aliasStore.Load(aliasParent.mountID)
	if err != nil {
		t.Fatal(err)
	}
	if !sameExpectedOwnerRecord(loaded, current) {
		t.Fatalf("path-alias current owner = %#v, want %#v", loaded, current)
	}
}

func TestPinOwnershipMutationAPIsRequireMatchingLifecycleLease(t *testing.T) {
	root := t.TempDir()
	leasePath := filepath.Join(root, "daemon.lease")
	maintenancePath := filepath.Join(root, "maintenance.gate")
	ctx := lockfile.WithLifecyclePathsForTest(
		t.Context(),
		leasePath,
		maintenancePath,
	)
	if _, err := RecoverPinOwnership(
		ctx,
		"relative",
		nil,
	); !errors.Is(err, ErrPinOwnershipLifecycleLeaseRequired) {
		t.Fatalf("recover without lifecycle lease error = %v", err)
	}
	if err := DetachPinOwnership(
		ctx,
		"relative",
		nil,
	); !errors.Is(err, ErrPinOwnershipLifecycleLeaseRequired) {
		t.Fatalf("detach without lifecycle lease error = %v", err)
	}
	lease, err := lockfile.AcquireLifecycle(
		ctx,
		lockfile.LifecycleOwner{PID: os.Getpid(), Action: "test"},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if _, err := RecoverPinOwnership(
		ctx,
		"relative",
		lease,
	); errors.Is(err, ErrPinOwnershipLifecycleLeaseRequired) ||
		err == nil ||
		!strings.Contains(err.Error(), "path must be absolute") {
		t.Fatalf("recover with lifecycle lease error = %v", err)
	}
	if err := DetachPinOwnership(
		ctx,
		"relative",
		lease,
	); errors.Is(err, ErrPinOwnershipLifecycleLeaseRequired) ||
		err == nil ||
		!strings.Contains(err.Error(), "path must be absolute") {
		t.Fatalf("detach with lifecycle lease error = %v", err)
	}
	mismatchedRoot := t.TempDir()
	mismatchedCtx := lockfile.WithLifecyclePathsForTest(
		t.Context(),
		filepath.Join(mismatchedRoot, "other-daemon.lease"),
		filepath.Join(mismatchedRoot, "maintenance.gate"),
	)
	if _, err := RecoverPinOwnership(
		mismatchedCtx,
		"relative",
		lease,
	); !errors.Is(err, ErrPinOwnershipLifecycleLeaseRequired) {
		t.Fatalf("recover with mismatched lifecycle key error = %v", err)
	}
	if err := DetachPinOwnership(
		mismatchedCtx,
		"relative",
		lease,
	); !errors.Is(err, ErrPinOwnershipLifecycleLeaseRequired) {
		t.Fatalf("detach with mismatched lifecycle key error = %v", err)
	}
}

func TestPinOwnershipMutationRejectsClosedAndReplacedLifecycleLease(t *testing.T) {
	t.Run("closed", func(t *testing.T) {
		root := t.TempDir()
		leasePath := filepath.Join(root, "daemon.lease")
		ctx := lockfile.WithLifecyclePathsForTest(
			t.Context(),
			leasePath,
			filepath.Join(root, "maintenance.gate"),
		)
		lease, err := lockfile.AcquireLifecycle(
			ctx,
			lockfile.LifecycleOwner{PID: os.Getpid(), Action: "test"},
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := lease.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := RecoverPinOwnership(
			ctx,
			"relative",
			lease,
		); !errors.Is(err, ErrPinOwnershipLifecycleLeaseRequired) {
			t.Fatalf("recover with closed lifecycle lease error = %v", err)
		}
	})
	t.Run("replaced-path-entry", func(t *testing.T) {
		root := t.TempDir()
		leasePath := filepath.Join(root, "daemon.lease")
		ctx := lockfile.WithLifecyclePathsForTest(
			t.Context(),
			leasePath,
			filepath.Join(root, "maintenance.gate"),
		)
		lease, err := lockfile.AcquireLifecycle(
			ctx,
			lockfile.LifecycleOwner{PID: os.Getpid(), Action: "test"},
		)
		if err != nil {
			t.Fatal(err)
		}
		defer lease.Close()
		if err := os.Rename(leasePath, leasePath+".moved"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(
			leasePath,
			[]byte("{}\n"),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
		if err := DetachPinOwnership(
			ctx,
			"relative",
			lease,
		); !errors.Is(err, ErrPinOwnershipLifecycleLeaseRequired) {
			t.Fatalf("detach with replaced lifecycle entry error = %v", err)
		}
	})
}

func TestPinOwnershipRetainedLeaseSurvivesCallerClose(t *testing.T) {
	root := t.TempDir()
	leasePath := filepath.Join(root, "daemon.lease")
	ctx := lockfile.WithLifecyclePathsForTest(
		t.Context(),
		leasePath,
		filepath.Join(root, "maintenance.gate"),
	)
	lease, err := lockfile.AcquireLifecycle(
		ctx,
		lockfile.LifecycleOwner{PID: os.Getpid(), Action: "test"},
	)
	if err != nil {
		t.Fatal(err)
	}
	retained, err := retainPinOwnershipLifecycleLease(ctx, lease)
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if reacquired, err := lockfile.AcquireLifecycle(
		ctx,
		lockfile.LifecycleOwner{PID: os.Getpid(), Action: "contender"},
	); !errors.Is(err, lockfile.ErrLifecycleLeaseHeld) {
		if reacquired != nil {
			_ = reacquired.Close()
		}
		t.Fatalf("lifecycle lease was released before retained close: %v", err)
	}
	if err := retained.Close(); err != nil {
		t.Fatal(err)
	}
	reacquired, err := lockfile.AcquireLifecycle(
		ctx,
		lockfile.LifecycleOwner{PID: os.Getpid(), Action: "after-close"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := reacquired.Close(); err != nil {
		t.Fatal(err)
	}
}

func snapshotFlatTestDirectory(
	t *testing.T,
	path string,
) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := make(map[string]string, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			t.Fatalf("unexpected subdirectory %s/%s", path, entry.Name())
		}
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(path, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		snapshot[entry.Name()] = fmt.Sprintf(
			"%#o:%d:%s",
			info.Mode().Perm(),
			len(data),
			data,
		)
	}
	return snapshot
}

func TestInspectPinOwnershipDoesNotMutateOwnerIndexOrPins(t *testing.T) {
	bpffsRoot, validator := newTestBPFFS(t)
	pinPath := filepath.Join(bpffsRoot, "wg-mix-ebpf-inspect-read-only")
	mapStore := writeCanonicalMockPins(t, pinPath)
	runtime := newTestPinPathRuntime(t, validator, mapStore)
	validated, err := validatePinPath(pinPath, validator)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := openPinPathParent(pinPath, validated, runtime)
	if err != nil {
		t.Fatal(err)
	}
	handle, _, err := openPinPathHandleFromParent(parent, validated, false)
	if err != nil {
		_ = parent.Close()
		t.Fatal(err)
	}
	pins, err := inspectPinnedMapSet(handle, true)
	if err != nil {
		_ = handle.Close()
		_ = parent.Close()
		t.Fatal(err)
	}
	ownerMaps := ownerMapsFromPins(pins)
	if err := closePinnedMapPins(pins); err != nil {
		_ = handle.Close()
		_ = parent.Close()
		t.Fatal(err)
	}
	var token [32]byte
	for index := range token {
		token[index] = byte(index + 1)
	}
	record, err := newActivePinOwnerRecord(
		parent,
		token,
		"12345678-1234-1234-1234-123456789abc",
		time.Date(2026, 7, 29, 1, 2, 3, 4, time.UTC),
		1,
		ownerMaps,
		nil,
	)
	if err != nil {
		_ = handle.Close()
		_ = parent.Close()
		t.Fatal(err)
	}
	sentinel, err := pinOwnerSentinelFor(handle.resource, token)
	if err != nil {
		_ = handle.Close()
		_ = parent.Close()
		t.Fatal(err)
	}
	ownerObservation := mapStore.observations["owner_map"]
	ownerObservation.owner = sentinel
	ownerObservation.ownerSeen = true
	mapStore.observations["owner_map"] = ownerObservation
	store, err := openPinOwnerStore(runtime, handle.resource, true)
	if err != nil {
		_ = handle.Close()
		_ = parent.Close()
		t.Fatal(err)
	}
	if err := store.Persist(record, nil, handle.mountID); err != nil {
		_ = store.Close()
		_ = handle.Close()
		_ = parent.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		_ = handle.Close()
		_ = parent.Close()
		t.Fatal(err)
	}
	if err := handle.Close(); err != nil {
		_ = parent.Close()
		t.Fatal(err)
	}
	if err := parent.Close(); err != nil {
		t.Fatal(err)
	}

	ownerBefore := snapshotFlatTestDirectory(t, runtime.ownerRoot)
	pinsBefore := snapshotFlatTestDirectory(t, pinPath)
	runtime.beforeOwnerExchange = func() {
		t.Error("read-only inspection attempted an owner/index exchange")
	}
	runtime.beforePinQuarantine = func(name string) error {
		return fmt.Errorf("read-only inspection attempted to quarantine %s", name)
	}
	runtime.beforePinUnlink = func(name string) error {
		return fmt.Errorf("read-only inspection attempted to unlink %s", name)
	}
	// The internal API still requires a complete TC dependency set. Since this
	// owner has no filters, the fake runtime must remain entirely untouched.
	tcKernel := newFakeTCKernel()
	status, err := inspectPinOwnershipWithRuntime(
		t.Context(),
		pinPath,
		false,
		runtime,
		tcKernel.runtime(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !status.DirectoryExists ||
		!status.OwnerExists ||
		status.RecoveryRequired ||
		status.ResourceKey != record.ResourceKey ||
		status.Sequence != record.Sequence {
		t.Fatalf("read-only ownership status = %#v", status)
	}
	ownerAfter := snapshotFlatTestDirectory(t, runtime.ownerRoot)
	pinsAfter := snapshotFlatTestDirectory(t, pinPath)
	if !maps.Equal(ownerAfter, ownerBefore) {
		t.Fatalf(
			"owner/index files changed during inspection:\nbefore=%#v\nafter=%#v",
			ownerBefore,
			ownerAfter,
		)
	}
	if !maps.Equal(pinsAfter, pinsBefore) {
		t.Fatalf(
			"pin files changed during inspection:\nbefore=%#v\nafter=%#v",
			pinsBefore,
			pinsAfter,
		)
	}
	if len(tcKernel.filterLists) != 0 ||
		len(tcKernel.writes) != 0 ||
		len(tcKernel.retained) != 0 {
		t.Fatalf(
			"read-only inspection touched TC state: lists=%v writes=%v retained=%v",
			tcKernel.filterLists,
			tcKernel.writes,
			tcKernel.retained,
		)
	}
	lockEntries, err := os.ReadDir(runtime.lockRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(lockEntries) != 1 {
		t.Fatalf("resource lease entries after inspection = %v", lockEntries)
	}
}

func TestMissingPinDirectoryPreservesAndReportsOwnershipEvidence(
	t *testing.T,
) {
	for _, archived := range []bool{false, true} {
		name := "active"
		if archived {
			name = "rekey-source"
		}
		t.Run(name, func(t *testing.T) {
			bpffsRoot, validator := newTestBPFFS(t)
			pinPath := filepath.Join(
				bpffsRoot,
				"wg-mix-ebpf-missing-owner",
			)
			runtime := newTestPinPathRuntime(
				t,
				validator,
				newFakePinnedMapStore(),
			)
			validated, err := validatePinPath(pinPath, validator)
			if err != nil {
				t.Fatal(err)
			}
			parent, err := openPinPathParent(
				pinPath,
				validated,
				runtime,
			)
			if err != nil {
				t.Fatal(err)
			}
			_, _, template := testPinOwnerRecord(t, t.TempDir())
			var token [32]byte
			for index := range token {
				token[index] = byte(index + 1)
			}
			record, err := newActivePinOwnerRecord(
				parent,
				token,
				"12345678-1234-1234-1234-123456789abc",
				time.Date(2026, 7, 29, 1, 2, 3, 4, time.UTC),
				1,
				template.Maps,
				nil,
			)
			if err != nil {
				_ = parent.Close()
				t.Fatal(err)
			}
			store, err := openPinOwnerStore(
				runtime,
				parent.resource,
				true,
			)
			if err != nil {
				_ = parent.Close()
				t.Fatal(err)
			}
			if err := store.Persist(
				record,
				nil,
				parent.mountID,
			); err != nil {
				_ = store.Close()
				_ = parent.Close()
				t.Fatal(err)
			}
			expectedRecordPath := filepath.Join(
				runtime.ownerRoot,
				record.ResourceKey+".owner.json",
			)
			if archived {
				indexed, err := activeIndexedOwnerForRecord(
					indexStoreFromOwner(store),
					record,
				)
				if err != nil {
					_ = store.Close()
					_ = parent.Close()
					t.Fatal(err)
				}
				history, err := indexStoreFromOwner(
					store,
				).archivePriorBootOwner(
					*indexed,
					record,
					false,
					time.Date(
						2026,
						7,
						30,
						1,
						2,
						3,
						4,
						time.UTC,
					),
				)
				if err != nil {
					_ = store.Close()
					_ = parent.Close()
					t.Fatal(err)
				}
				expectedRecordPath = filepath.Join(
					runtime.ownerRoot,
					history.RecordFileName,
				)
			}
			if err := store.Close(); err != nil {
				_ = parent.Close()
				t.Fatal(err)
			}
			if err := parent.Close(); err != nil {
				t.Fatal(err)
			}

			before := snapshotFlatTestDirectory(
				t,
				runtime.ownerRoot,
			)
			runtime.beforeOwnerExchange = func() {
				t.Error(
					"missing-directory inspection attempted an owner/index exchange",
				)
			}
			runtime.beforePinQuarantine = func(name string) error {
				return fmt.Errorf(
					"missing-directory inspection attempted to quarantine %s",
					name,
				)
			}
			runtime.beforePinUnlink = func(name string) error {
				return fmt.Errorf(
					"missing-directory inspection attempted to unlink %s",
					name,
				)
			}
			status, err := inspectPinOwnershipWithRuntime(
				t.Context(),
				pinPath,
				false,
				runtime,
				tcRuntime{},
			)
			if err != nil {
				t.Fatal(err)
			}
			if status.DirectoryExists ||
				!status.OwnerExists ||
				!status.RecoveryRequired ||
				status.ResourceKey != record.ResourceKey ||
				status.RecordPath != expectedRecordPath {
				t.Fatalf(
					"missing-directory ownership status = %#v",
					status,
				)
			}
			afterInspect := snapshotFlatTestDirectory(
				t,
				runtime.ownerRoot,
			)
			if !maps.Equal(afterInspect, before) {
				t.Fatalf(
					"missing-directory inspection changed evidence:\nbefore=%#v\nafter=%#v",
					before,
					afterInspect,
				)
			}

			loader := LinuxLoader{
				PinPath: pinPath,
				runtime: &runtime,
			}
			err = loader.Detach(t.Context(), nil)
			if err == nil ||
				!strings.Contains(err.Error(), "directory is missing") {
				t.Fatalf(
					"missing-directory detach error = %v",
					err,
				)
			}
			afterDetach := snapshotFlatTestDirectory(
				t,
				runtime.ownerRoot,
			)
			if !maps.Equal(afterDetach, before) {
				t.Fatalf(
					"missing-directory detach changed evidence:\nbefore=%#v\nafter=%#v",
					before,
					afterDetach,
				)
			}
		})
	}
}

func TestReadOnlyOwnershipInspectionReportsJournalsWithoutRecovery(t *testing.T) {
	t.Run("owner-next", func(t *testing.T) {
		runtime, _, record, store, _ := openPersistedTestPinOwner(t)
		next := clonePinOwnerRecord(record)
		next.Sequence++
		next.UpdatedAt = time.Date(
			2026, 7, 29, 1, 2, 4, 0, time.UTC,
		).Format(time.RFC3339Nano)
		data, err := marshalPinOwnerRecord(next)
		if err != nil {
			t.Fatal(err)
		}
		nextFile, identity, err := createAnchoredRegularFileExclusive(
			store.root,
			store.nextName,
			0o600,
			store.expectedUID,
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := writeAndSyncAnchoredFile(
			store.root,
			store.nextName,
			nextFile,
			identity,
			data,
			store.expectedUID,
		); err != nil {
			_ = nextFile.Close()
			t.Fatal(err)
		}
		if err := nextFile.Close(); err != nil {
			t.Fatal(err)
		}
		before := snapshotFlatTestDirectory(t, runtime.ownerRoot)
		pending, err := inspectPinOwnerDescriptorsReadOnly(store)
		if err != nil {
			t.Fatal(err)
		}
		if !pending {
			t.Fatal("read-only owner inspection missed pending next record")
		}
		_, exists, indexPending, err := indexStoreFromOwner(
			store,
		).inspectOptionalReadOnly()
		if err != nil {
			t.Fatal(err)
		}
		if !exists || indexPending {
			t.Fatalf(
				"steady index read-only state exists=%t pending=%t",
				exists,
				indexPending,
			)
		}
		after := snapshotFlatTestDirectory(t, runtime.ownerRoot)
		if !maps.Equal(after, before) {
			t.Fatalf(
				"read-only descriptor inspection changed files:\nbefore=%#v\nafter=%#v",
				before,
				after,
			)
		}
	})
	t.Run("history-rotation", func(t *testing.T) {
		runtime, _, _, store, index, victim :=
			testPinOwnerHistoryAtCapacity(t)
		persistTestPinOwnerRotationJournal(
			t,
			store,
			index,
			victim,
		)
		before := snapshotFlatTestDirectory(t, runtime.ownerRoot)
		inspected, exists, pending, err := indexStoreFromOwner(
			store,
		).inspectOptionalReadOnly()
		if err != nil {
			t.Fatal(err)
		}
		if !exists || !pending || inspected.Rotation == nil {
			t.Fatalf(
				"read-only rotation state exists=%t pending=%t index=%#v",
				exists,
				pending,
				inspected,
			)
		}
		after := snapshotFlatTestDirectory(t, runtime.ownerRoot)
		if !maps.Equal(after, before) {
			t.Fatalf(
				"read-only rotation inspection changed files:\nbefore=%#v\nafter=%#v",
				before,
				after,
			)
		}
	})
}

func TestOwnerMapUnlinkFailureAtEveryPositionRestoresCanonicalSet(t *testing.T) {
	for failAt := 1; failAt <= len(pinnedMapDescriptors()); failAt++ {
		t.Run(fmt.Sprintf("unlink-%02d", failAt), func(t *testing.T) {
			bpffsRoot, validator := newTestBPFFS(t)
			pinPath := filepath.Join(bpffsRoot, "wg-mix-ebpf-unlink-test")
			mapStore := writeCanonicalMockPins(t, pinPath)
			runtime := newTestPinPathRuntime(t, validator, mapStore)
			validated, err := validatePinPath(pinPath, validator)
			if err != nil {
				t.Fatal(err)
			}
			parent, err := openPinPathParent(pinPath, validated, runtime)
			if err != nil {
				t.Fatal(err)
			}
			defer parent.Close()
			handle, _, err := openPinPathHandleFromParent(
				parent,
				validated,
				false,
			)
			if err != nil {
				t.Fatal(err)
			}
			defer handle.Close()
			pins, err := inspectPinnedMapSet(handle, true)
			if err != nil {
				t.Fatal(err)
			}
			defer closePinnedMapPins(pins)
			var token [32]byte
			for index := range token {
				token[index] = byte(index + 1)
			}
			active, err := newActivePinOwnerRecord(
				parent,
				token,
				"12345678-1234-1234-1234-123456789abc",
				time.Date(2026, 7, 29, 1, 2, 3, 4, time.UTC),
				1,
				ownerMapsFromPins(pins),
				nil,
			)
			if err != nil {
				t.Fatal(err)
			}
			sentinel, err := pinOwnerSentinelFor(handle.resource, token)
			if err != nil {
				t.Fatal(err)
			}
			ownerObservation := mapStore.observations["owner_map"]
			ownerObservation.owner = sentinel
			ownerObservation.ownerSeen = true
			mapStore.observations["owner_map"] = ownerObservation
			detaching, err := newDetachingPinOwnerRecord(
				active,
				time.Date(2026, 7, 29, 1, 2, 4, 0, time.UTC),
			)
			if err != nil {
				t.Fatal(err)
			}
			if err := stageOwnerMaps(handle, detaching, pins); err != nil {
				t.Fatal(err)
			}
			stages, err := loadOwnerMapStages(handle, detaching)
			if err != nil {
				t.Fatal(err)
			}
			defer stages.Close()
			unlinks := 0
			handle.runtime.beforePinUnlink = func(string) error {
				unlinks++
				if unlinks == failAt {
					return errors.New("injected map unlink failure")
				}
				return nil
			}
			err = removeCanonicalOwnerMaps(handle, detaching, stages)
			if err == nil || !strings.Contains(err.Error(), "injected map unlink failure") {
				t.Fatalf("canonical unlink error = %v", err)
			}
			if err := restoreCanonicalOwnerMaps(
				handle,
				detaching,
				stages,
			); err != nil {
				t.Fatalf("restore canonical owner maps: %v", err)
			}
			for _, stage := range detaching.MapStages {
				descriptor, err := ownerMapDescriptor(stage.Name)
				if err != nil {
					t.Fatal(err)
				}
				pin, err := validatePinnedMapAt(
					handle,
					descriptor,
					stage.Name,
					stage.MapID,
				)
				if err != nil {
					t.Fatalf("canonical map %s was not restored: %v", stage.Name, err)
				}
				if err := pin.observation.Close(); err != nil {
					t.Fatal(err)
				}
				if _, err := os.Lstat(filepath.Join(
					pinPath,
					stage.FileName+".canonical-retired",
				)); !os.IsNotExist(err) {
					t.Fatalf("canonical quarantine %s remains: %v", stage.Name, err)
				}
			}
			if err := removeOwnerMapStages(handle, detaching); err != nil {
				t.Fatal(err)
			}
		})
	}
}
