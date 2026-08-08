//go:build linux

package dataplane

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/syx0310/wg-mix-ebpf/internal/abi"
	"golang.org/x/sys/unix"
)

type exactTCXOwnerTestFixture struct {
	runtime  pinPathRuntime
	parent   *pinPathParent
	handle   *pinPathHandle
	store    *pinOwnerStore
	mapStore *fakePinnedMapStore
	token    [32]byte
	maps     []pinOwnerMapIdentity
	now      time.Time
}

type faultExactTCXOwnerStore struct {
	base       exactTCXOwnerStore
	failAt     int
	persisted  int
	persistErr error
	attempts   []*pinOwnerRecord
}

func (store *faultExactTCXOwnerStore) Persist(
	record *pinOwnerRecord,
	expected *pinOwnerRecord,
	mountID uint64,
) error {
	store.persisted++
	store.attempts = append(store.attempts, clonePinOwnerRecord(record))
	if store.persisted == store.failAt {
		return store.persistErr
	}
	return store.base.Persist(record, expected, mountID)
}

func (store *faultExactTCXOwnerStore) Remove(record *pinOwnerRecord) error {
	return store.base.Remove(record)
}

func newExactTCXOwnerTestFixture(t *testing.T) *exactTCXOwnerTestFixture {
	t.Helper()
	bpffsRoot, validator := newTestBPFFS(t)
	pinPath := filepath.Join(bpffsRoot, "wg-mix-ebpf-tcx-owner-test")
	mapStore := writeCanonicalMockPins(t, pinPath)
	runtime := newTestPinPathRuntime(t, validator, mapStore)
	now := time.Date(2026, 8, 8, 8, 8, 8, 0, time.UTC)
	runtime.now = func() time.Time { return now.Add(time.Minute) }
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
	fixture := &exactTCXOwnerTestFixture{
		runtime:  runtime,
		parent:   parent,
		handle:   handle,
		store:    store,
		mapStore: mapStore,
		now:      now,
	}
	for index := range fixture.token {
		fixture.token[index] = byte(index + 1)
	}
	sentinel, err := pinOwnerSentinelFor(handle.resource, fixture.token)
	if err != nil {
		t.Fatal(err)
	}
	ownerObservation := mapStore.observations["owner_map"]
	ownerObservation.owner = sentinel
	ownerObservation.ownerSeen = true
	mapStore.observations["owner_map"] = ownerObservation
	controlObservation := mapStore.observations["control_map"]
	controlObservation.control.ActiveGeneration = 7
	controlObservation.controlSeen = true
	mapStore.observations["control_map"] = controlObservation
	for index, descriptor := range pinnedMapDescriptors() {
		fixture.maps = append(fixture.maps, pinOwnerMapIdentity{
			Name: descriptor.name,
			ID:   uint32(index + 100),
		})
	}
	t.Cleanup(func() {
		_ = store.Close()
		_ = handle.Close()
		_ = parent.Close()
	})
	return fixture
}

func (fixture *exactTCXOwnerTestFixture) mutatingRecord(
	t *testing.T,
	active []exactTCXBinding,
	desired []exactTCXBinding,
) *pinOwnerRecord {
	t.Helper()
	activeGeneration := uint64(0)
	var previous *pinOwnerRecord
	if len(active) != 0 {
		activeGeneration = 7
		var err error
		previous, err = newActivePinOwnerRecord(
			fixture.parent,
			fixture.token,
			"12345678-1234-1234-1234-123456789abc",
			fixture.now,
			activeGeneration,
			fixture.maps,
			active,
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := fixture.store.Persist(previous, nil, fixture.handle.mountID); err != nil {
			t.Fatal(err)
		}
	}
	applying, err := newApplyingPinOwnerRecord(
		fixture.parent,
		fixture.token,
		"12345678-1234-1234-1234-123456789abc",
		fixture.now.Add(time.Second),
		activeGeneration,
		8,
		fixture.maps,
		active,
		desired,
		previous,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.Persist(applying, previous, fixture.handle.mountID); err != nil {
		t.Fatal(err)
	}
	mutating := advancePinOwnerRecord(
		applying,
		fixture.now.Add(2*time.Second),
		pinOwnerPhaseApplying,
		pinOwnerStepMutating,
	)
	if err := fixture.store.Persist(mutating, applying, fixture.handle.mountID); err != nil {
		t.Fatal(err)
	}
	return mutating
}

func fakeLoadedOwnerPrograms(ids ...uint32) *loadedOwnerPrograms {
	loaded := &loadedOwnerPrograms{byID: make(map[uint32]*pinnedProgramObservation)}
	for _, id := range ids {
		loaded.byID[id] = &pinnedProgramObservation{fd: int(id), id: id}
	}
	return loaded
}

func exactTCXMutationEvents(events []string) []string {
	var mutations []string
	for _, event := range events {
		if event == "attach" || event == "pin" || event == "compare-update" ||
			strings.HasPrefix(event, "detach:") || strings.HasPrefix(event, "unpin:") {
			mutations = append(mutations, event)
		}
	}
	return mutations
}

func persistDetachedDesiredExactTCX(
	t *testing.T,
	fixture *exactTCXOwnerTestFixture,
	kernel *fakeExactTCXKernel,
	desired exactTCXBinding,
) (*pinOwnerRecord, *exactTCXAttachment, string) {
	t.Helper()
	record := fixture.mutatingRecord(t, nil, []exactTCXBinding{desired})
	journal := &fakeExactTCXJournal{events: &kernel.events}
	owner, pinPath := stageTestExactTCXAtPath(
		t, kernel, desired, journal, fixture.handle.procPath(),
	)
	published, err := ownerRecordWithDesiredLinkIdentity(record, owner.binding, fixture.runtime)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.Persist(published, record, fixture.handle.mountID); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("hold detached exact TCX pin")
	kernel.unpinErrs[owner.binding.LinkID] = []error{injected}
	if err := owner.Rollback(); !errors.Is(err, injected) {
		t.Fatalf("detach desired exact TCX link: %v", err)
	}
	if err := owner.Release(); err != nil {
		t.Fatal(err)
	}
	return published, owner, pinPath
}

func persistDetachedActiveReplacementExactTCX(
	t *testing.T,
	fixture *exactTCXOwnerTestFixture,
	kernel *fakeExactTCXKernel,
	activeIntent exactTCXBinding,
	desiredProgramID uint32,
) (*pinOwnerRecord, exactTCXBinding, exactTCXBinding, string) {
	t.Helper()
	journal := &fakeExactTCXJournal{events: &kernel.events}
	owner, pinPath := stageTestExactTCXAtPath(
		t, kernel, activeIntent, journal, fixture.handle.procPath(),
	)
	active := owner.binding
	desired := active
	desired.ProgramID = desiredProgramID
	record := fixture.mutatingRecord(
		t, []exactTCXBinding{active}, []exactTCXBinding{desired},
	)
	injected := errors.New("hold detached active exact TCX pin")
	kernel.unpinErrs[active.LinkID] = []error{injected}
	if err := owner.Rollback(); !errors.Is(err, injected) {
		t.Fatalf("detach active exact TCX link: %v", err)
	}
	if err := owner.Release(); err != nil {
		t.Fatal(err)
	}
	return record, active, desired, pinPath
}

func establishCompletedRollbackReplacementExactTCX(
	t *testing.T,
	fixture *exactTCXOwnerTestFixture,
	kernel *fakeExactTCXKernel,
	activeIntent exactTCXBinding,
	desiredProgramID uint32,
) (*pinOwnerRecord, exactTCXBinding, exactTCXBinding) {
	t.Helper()
	record, active, desired, _ := persistDetachedActiveReplacementExactTCX(
		t, fixture, kernel, activeIntent, desiredProgramID,
	)
	forward, err := convergeOwnerApplyExactTCXLinks(
		t.Context(), fixture.handle, fixture.store, record,
		fakeLoadedOwnerPrograms(active.ProgramID, desired.ProgramID), kernel.runtime(),
	)
	if err != nil {
		t.Fatal(err)
	}
	target := forward.DesiredLinks[0]
	rollingBack := advancePinOwnerRecord(
		forward,
		fixture.now.Add(2*time.Minute),
		pinOwnerPhaseApplying,
		pinOwnerStepRollingBack,
	)
	if err := fixture.store.Persist(rollingBack, forward, fixture.handle.mountID); err != nil {
		t.Fatal(err)
	}
	recovered, err := rollbackFailedExactOwnerApplyLinks(
		t.Context(), fixture.handle, rollingBack,
		fakeLoadedOwnerPrograms(active.ProgramID, desired.ProgramID),
		fixture.store, kernel.runtime(),
	)
	if err != nil {
		t.Fatal(err)
	}
	return recovered, active, target
}

func TestConvergeOwnerExactTCXPublishesAttachIdentity(t *testing.T) {
	fixture := newExactTCXOwnerTestFixture(t)
	kernel := newFakeExactTCXKernel()
	kernel.materializePins = true
	desired := testExactTCXBinding(21, exactTCXIngress, 501)
	record := fixture.mutatingRecord(t, nil, []exactTCXBinding{desired})

	converged, err := convergeOwnerApplyExactTCXLinks(
		t.Context(),
		fixture.handle,
		fixture.store,
		record,
		fakeLoadedOwnerPrograms(501),
		kernel.runtime(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(converged.DesiredLinks) != 1 || converged.DesiredLinks[0].LinkID == 0 {
		t.Fatalf("converged desired links = %+v", converged.DesiredLinks)
	}
	linkID := converged.DesiredLinks[0].LinkID
	if !kernel.links[linkID].attached || kernel.links[linkID].identity.ProgramID != 501 {
		t.Fatalf("converged kernel link = %+v", kernel.links[linkID])
	}
	persisted, err := fixture.store.Load(fixture.handle.mountID)
	if err != nil {
		t.Fatal(err)
	}
	if !bindingSetsEqualExactTCX(persisted.DesiredLinks, converged.DesiredLinks) {
		t.Fatalf("persisted desired links = %+v, want %+v", persisted.DesiredLinks, converged.DesiredLinks)
	}
}

func TestConvergeOwnerExactTCXRecoversIdentityPersistedBeforePinFailure(t *testing.T) {
	fixture := newExactTCXOwnerTestFixture(t)
	kernel := newFakeExactTCXKernel()
	kernel.materializePins = true
	desired := testExactTCXBinding(22, exactTCXEgress, 502)
	record := fixture.mutatingRecord(t, nil, []exactTCXBinding{desired})
	pinPath := filepath.Join(fixture.handle.procPath(), desired.PinName)
	injected := errors.New("injected pin failure after identity persistence")
	kernel.pinErr = injected
	current := record
	owner, err := stageExactTCXAttachment(
		t.Context(),
		desired,
		pinPath,
		exactTCXProgram{id: desired.ProgramID},
		ownerExactTCXJournal(&current, fixture.handle, fixture.store),
		kernel.runtime(),
	)
	if !errors.Is(err, injected) || owner != nil {
		t.Fatalf("stage owner=%#v error=%v", owner, err)
	}
	crashedLinkID := current.DesiredLinks[0].LinkID
	if crashedLinkID == 0 || kernel.links[crashedLinkID].attached {
		t.Fatalf("journal/link after failed pin: desired=%+v link=%+v", current.DesiredLinks, kernel.links[crashedLinkID])
	}
	kernel.pinErr = nil

	converged, err := convergeOwnerApplyExactTCXLinks(
		t.Context(),
		fixture.handle,
		fixture.store,
		current,
		fakeLoadedOwnerPrograms(502),
		kernel.runtime(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if converged.DesiredLinks[0].LinkID == 0 || converged.DesiredLinks[0].LinkID == crashedLinkID {
		t.Fatalf("recovered link ID = %d, retired failed-pin identity %d", converged.DesiredLinks[0].LinkID, crashedLinkID)
	}
	if kernel.links[crashedLinkID].attached || !kernel.links[converged.DesiredLinks[0].LinkID].attached {
		t.Fatalf("failed/recovered exact links: %+v", kernel.links)
	}
}

func TestConvergeOwnerExactTCXRecoversPinBeforeCompletionPersist(t *testing.T) {
	fixture := newExactTCXOwnerTestFixture(t)
	kernel := newFakeExactTCXKernel()
	kernel.materializePins = true
	desired := testExactTCXBinding(29, exactTCXEgress, 503)
	record := fixture.mutatingRecord(t, nil, []exactTCXBinding{desired})
	pinPath := filepath.Join(fixture.handle.procPath(), desired.PinName)
	current := record
	baseJournal := ownerExactTCXJournal(&current, fixture.handle, fixture.store)
	injected := errors.New("injected crash after pin before completion persist")
	identityPersists := 0
	journal := baseJournal
	journal.persistIdentity = func(binding exactTCXBinding, intent exactTCXJournalIntent) error {
		identityPersists++
		if identityPersists == 2 {
			return injected
		}
		return baseJournal.persistIdentity(binding, intent)
	}
	owner, err := stageExactTCXAttachment(
		t.Context(), desired, pinPath,
		exactTCXProgram{id: desired.ProgramID}, journal, kernel.runtime(),
	)
	if !errors.Is(err, injected) || owner == nil || !owner.pinned {
		t.Fatalf("stage owner=%#v error=%v", owner, err)
	}
	pinnedID := owner.binding.LinkID
	if current.DesiredLinks[0].LinkID != pinnedID || !current.DesiredLinks[0].PinPending {
		t.Fatalf("pending-pin journal=%+v pinned ID=%d", current.DesiredLinks, pinnedID)
	}
	if err := owner.Release(); err != nil {
		t.Fatal(err)
	}

	converged, err := convergeOwnerApplyExactTCXLinks(
		t.Context(), fixture.handle, fixture.store, current,
		fakeLoadedOwnerPrograms(desired.ProgramID), kernel.runtime(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if converged.DesiredLinks[0].LinkID != pinnedID ||
		converged.DesiredLinks[0].PinPending || len(kernel.links) != 1 {
		t.Fatalf("recovered pending pin: links=%+v journal=%+v", kernel.links, converged.DesiredLinks)
	}
}

func TestConvergeOwnerExactTCXReattachesAfterRecordedLinkDetachedBeforeUnpin(t *testing.T) {
	fixture := newExactTCXOwnerTestFixture(t)
	kernel := newFakeExactTCXKernel()
	kernel.materializePins = true
	desired := testExactTCXBinding(25, exactTCXIngress, 503)
	record := fixture.mutatingRecord(t, nil, []exactTCXBinding{desired})
	journal := &fakeExactTCXJournal{events: &kernel.events}
	owner, _ := stageTestExactTCXAtPath(
		t, kernel, desired, journal, fixture.handle.procPath(),
	)
	oldLinkID := owner.binding.LinkID
	published, err := ownerRecordWithDesiredLinkIdentity(record, owner.binding, fixture.runtime)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.Persist(published, record, fixture.handle.mountID); err != nil {
		t.Fatal(err)
	}
	record = published
	injected := errors.New("injected crash after detach before unpin")
	kernel.unpinErrs[oldLinkID] = []error{injected}
	if err := owner.Rollback(); !errors.Is(err, injected) {
		t.Fatalf("rollback error = %v", err)
	}
	if err := owner.link.Close(); err != nil {
		t.Fatal(err)
	}
	owner.link = nil
	owner.closed = true

	converged, err := convergeOwnerApplyExactTCXLinks(
		t.Context(),
		fixture.handle,
		fixture.store,
		record,
		fakeLoadedOwnerPrograms(503),
		kernel.runtime(),
	)
	if err != nil {
		t.Fatal(err)
	}
	newLinkID := converged.DesiredLinks[0].LinkID
	if newLinkID == 0 || newLinkID == oldLinkID {
		t.Fatalf("recovered link ID = %d, old detached ID = %d", newLinkID, oldLinkID)
	}
	if kernel.links[oldLinkID].attached || !kernel.links[newLinkID].attached {
		t.Fatalf("old/new link states = %+v / %+v", kernel.links[oldLinkID], kernel.links[newLinkID])
	}
}

func TestConvergeOwnerExactTCXReplacesDetachedActiveWithoutTouchingReusedSlot(t *testing.T) {
	fixture := newExactTCXOwnerTestFixture(t)
	kernel := newFakeExactTCXKernel()
	kernel.materializePins = true
	activeIntent := testExactTCXBinding(26, exactTCXIngress, 511)
	journal := &fakeExactTCXJournal{events: &kernel.events}
	owner, _ := stageTestExactTCXAtPath(
		t, kernel, activeIntent, journal, fixture.handle.procPath(),
	)
	active := owner.binding
	desired := active
	desired.ProgramID = 512
	record := fixture.mutatingRecord(
		t, []exactTCXBinding{active}, []exactTCXBinding{desired},
	)
	unpinErr := errors.New("injected crash after active detach")
	kernel.unpinErrs[active.LinkID] = []error{unpinErr}
	if err := owner.Rollback(); !errors.Is(err, unpinErr) {
		t.Fatalf("detach boundary error=%v", err)
	}
	if err := owner.Release(); err != nil {
		t.Fatal(err)
	}
	foreignID := kernel.addLink(active.IfIndex, ebpf.AttachType(active.AttachType), 999)
	injected := errors.New("injected replacement attach preflight failure")
	queries := 0
	kernel.beforeQuery = func(kernel *fakeExactTCXKernel, _ fakeExactTCXSlot) {
		queries++
		if queries == 2 {
			kernel.beforeQuery = nil
			kernel.queryErr = injected
		}
	}

	converged, err := convergeOwnerApplyExactTCXLinks(
		t.Context(),
		fixture.handle,
		fixture.store,
		record,
		fakeLoadedOwnerPrograms(active.ProgramID, desired.ProgramID),
		kernel.runtime(),
	)
	if !errors.Is(err, injected) {
		t.Fatalf("replacement fault boundary error=%v", err)
	}
	if converged == nil || converged.DesiredLinks[0].LinkID != 0 ||
		converged.DesiredLinks[0].ReplacesLinkID != active.LinkID {
		t.Fatalf("durable detached replacement boundary=%+v", converged)
	}
	if err := validateOwnerDirectoryEntries(fixture.handle, converged); err != nil {
		t.Fatalf("replacement boundary is not restart-valid: %v", err)
	}
	kernel.queryErr = nil
	converged, err = convergeOwnerApplyExactTCXLinks(
		t.Context(),
		fixture.handle,
		fixture.store,
		converged,
		fakeLoadedOwnerPrograms(active.ProgramID, desired.ProgramID),
		kernel.runtime(),
	)
	if err != nil {
		t.Fatal(err)
	}
	replacement := converged.DesiredLinks[0]
	if replacement.LinkID == 0 || replacement.LinkID == active.LinkID ||
		replacement.ReplacesLinkID != active.LinkID {
		t.Fatalf("replacement journal=%+v active=%+v", replacement, active)
	}
	if kernel.links[active.LinkID].attached || !kernel.links[replacement.LinkID].attached ||
		!kernel.links[foreignID].attached {
		t.Fatalf("detached/replacement/foreign links=%+v", kernel.links)
	}
}

func TestConvergeOwnerExactTCXPersistsDesiredRetirementBeforeMutation(t *testing.T) {
	fixture := newExactTCXOwnerTestFixture(t)
	kernel := newFakeExactTCXKernel()
	kernel.materializePins = true
	desired := testExactTCXBinding(31, exactTCXIngress, 521)
	record, owner, pinPath := persistDetachedDesiredExactTCX(t, fixture, kernel, desired)
	linkID := owner.binding.LinkID
	injected := errors.New("injected desired retirement persist failure")
	faults := &faultExactTCXOwnerStore{
		base: fixture.store, failAt: 1, persistErr: injected,
	}

	current, err := convergeOwnerApplyExactTCXLinks(
		t.Context(), fixture.handle, faults, record,
		fakeLoadedOwnerPrograms(desired.ProgramID), kernel.runtime(),
	)
	if !errors.Is(err, injected) || current != record {
		t.Fatalf("converge current=%p/%p error=%v", current, record, err)
	}
	if kernel.pins[pinPath] != linkID || kernel.links[linkID].attached {
		t.Fatalf("persist failure mutated detached desired link: pin=%d link=%+v", kernel.pins[pinPath], kernel.links[linkID])
	}
	persisted, err := fixture.store.Load(fixture.handle.mountID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.DesiredLinks[0].Retiring || persisted.Sequence != record.Sequence {
		t.Fatalf("failed retirement changed durable record: %+v", persisted.DesiredLinks)
	}

	converged, err := convergeOwnerApplyExactTCXLinks(
		t.Context(), fixture.handle, fixture.store, record,
		fakeLoadedOwnerPrograms(desired.ProgramID), kernel.runtime(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if converged.DesiredLinks[0].LinkID == 0 ||
		converged.DesiredLinks[0].LinkID == linkID ||
		!kernel.links[converged.DesiredLinks[0].LinkID].attached {
		t.Fatalf("desired retirement retry did not converge: record=%+v links=%+v", converged.DesiredLinks, kernel.links)
	}
}

func TestConvergeOwnerExactTCXRecoversRetirementCompletionPersistFailure(t *testing.T) {
	fixture := newExactTCXOwnerTestFixture(t)
	kernel := newFakeExactTCXKernel()
	kernel.materializePins = true
	desired := testExactTCXBinding(37, exactTCXIngress, 581)
	record, owner, pinPath := persistDetachedDesiredExactTCX(t, fixture, kernel, desired)
	oldLinkID := owner.binding.LinkID
	injected := errors.New("injected retirement completion persist failure")
	faults := &faultExactTCXOwnerStore{
		base: fixture.store, failAt: 2, persistErr: injected,
	}

	current, err := convergeOwnerApplyExactTCXLinks(
		t.Context(), fixture.handle, faults, record,
		fakeLoadedOwnerPrograms(desired.ProgramID), kernel.runtime(),
	)
	if !errors.Is(err, injected) || current == nil ||
		!current.DesiredLinks[0].Retiring {
		t.Fatalf("retirement completion current=%+v error=%v", current, err)
	}
	if _, exists := kernel.pins[pinPath]; exists || kernel.links[oldLinkID].attached {
		t.Fatalf("fault boundary did not retire exact old link: pins=%+v link=%+v", kernel.pins, kernel.links[oldLinkID])
	}
	persisted, err := fixture.store.Load(fixture.handle.mountID)
	if err != nil {
		t.Fatal(err)
	}
	if !persisted.DesiredLinks[0].Retiring {
		t.Fatalf("restart lost retiring intent: %+v", persisted.DesiredLinks)
	}
	converged, err := convergeOwnerApplyExactTCXLinks(
		t.Context(), fixture.handle, fixture.store, persisted,
		fakeLoadedOwnerPrograms(desired.ProgramID), kernel.runtime(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if converged.DesiredLinks[0].LinkID == 0 ||
		converged.DesiredLinks[0].LinkID == oldLinkID ||
		converged.DesiredLinks[0].Retiring {
		t.Fatalf("restart did not converge desired link: %+v", converged.DesiredLinks)
	}
}

func TestConvergeOwnerExactTCXPersistsDetachedActiveReplacementBeforeMutation(t *testing.T) {
	fixture := newExactTCXOwnerTestFixture(t)
	kernel := newFakeExactTCXKernel()
	kernel.materializePins = true
	record, active, desired, pinPath := persistDetachedActiveReplacementExactTCX(
		t, fixture, kernel,
		testExactTCXBinding(32, exactTCXEgress, 531),
		532,
	)
	injected := errors.New("injected detached active marker persist failure")
	faults := &faultExactTCXOwnerStore{
		base: fixture.store, failAt: 1, persistErr: injected,
	}

	current, err := convergeOwnerApplyExactTCXLinks(
		t.Context(), fixture.handle, faults, record,
		fakeLoadedOwnerPrograms(active.ProgramID, desired.ProgramID), kernel.runtime(),
	)
	if !errors.Is(err, injected) || current != record {
		t.Fatalf("converge current=%p/%p error=%v", current, record, err)
	}
	if kernel.pins[pinPath] != active.LinkID || kernel.links[active.LinkID].attached {
		t.Fatalf("marker persist failure mutated old link: pin=%d link=%+v", kernel.pins[pinPath], kernel.links[active.LinkID])
	}
	persisted, err := fixture.store.Load(fixture.handle.mountID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.DesiredLinks[0].ReplacesLinkID != 0 || persisted.Sequence != record.Sequence {
		t.Fatalf("failed replacement marker changed journal: %+v", persisted.DesiredLinks)
	}
}

func TestConvergeOwnerExactTCXReplacementMarkerCrashBoundaries(t *testing.T) {
	for _, boundary := range []string{"old-pin-present", "old-pin-absent", "new-pin-present"} {
		t.Run(boundary, func(t *testing.T) {
			fixture := newExactTCXOwnerTestFixture(t)
			kernel := newFakeExactTCXKernel()
			kernel.materializePins = true
			record, active, desired, pinPath := persistDetachedActiveReplacementExactTCX(
				t, fixture, kernel,
				testExactTCXBinding(33, exactTCXIngress, 541),
				542,
			)
			marked, err := ownerRecordReplacingDetachedLink(
				record, active, fixture.handle, fixture.store,
			)
			if err != nil {
				t.Fatal(err)
			}
			current := marked
			switch boundary {
			case "old-pin-absent":
				if err := removeOwnedExactTCXLink(fixture.handle, active, kernel.runtime()); err != nil {
					t.Fatal(err)
				}
			case "new-pin-present":
				current, err = convergeOwnerApplyExactTCXLinks(
					t.Context(), fixture.handle, fixture.store, current,
					fakeLoadedOwnerPrograms(active.ProgramID, desired.ProgramID), kernel.runtime(),
				)
				if err != nil {
					t.Fatal(err)
				}
				if current.DesiredLinks[0].LinkID == 0 || kernel.pins[pinPath] != current.DesiredLinks[0].LinkID {
					t.Fatalf("new-pin boundary=%+v pins=%+v", current.DesiredLinks, kernel.pins)
				}
			}

			converged, err := convergeOwnerApplyExactTCXLinks(
				t.Context(), fixture.handle, fixture.store, current,
				fakeLoadedOwnerPrograms(active.ProgramID, desired.ProgramID), kernel.runtime(),
			)
			if err != nil {
				t.Fatal(err)
			}
			replacement := converged.DesiredLinks[0]
			if replacement.ReplacesLinkID != active.LinkID || replacement.LinkID == 0 ||
				replacement.LinkID == active.LinkID || !kernel.links[replacement.LinkID].attached ||
				kernel.links[replacement.LinkID].identity.ProgramID != desired.ProgramID {
				t.Fatalf("boundary %s did not converge: replacement=%+v links=%+v", boundary, replacement, kernel.links)
			}
			if kernel.links[active.LinkID].attached {
				t.Fatalf("boundary %s revived retired old link: %+v", boundary, kernel.links[active.LinkID])
			}
		})
	}
}

func TestRollbackExactOwnerApplyRebuildsOldProgramWithPersistedReplacementIdentity(t *testing.T) {
	for _, failAt := range []int{0, 1, 2, 3} {
		name := "no-fault"
		if failAt != 0 {
			name = fmt.Sprintf("persist-%d", failAt)
		}
		t.Run(name, func(t *testing.T) {
			fixture := newExactTCXOwnerTestFixture(t)
			kernel := newFakeExactTCXKernel()
			kernel.materializePins = true
			record, active, desired, _ := persistDetachedActiveReplacementExactTCX(
				t, fixture, kernel,
				testExactTCXBinding(35, exactTCXIngress, 561),
				562,
			)
			forward, err := convergeOwnerApplyExactTCXLinks(
				t.Context(), fixture.handle, fixture.store, record,
				fakeLoadedOwnerPrograms(active.ProgramID, desired.ProgramID), kernel.runtime(),
			)
			if err != nil {
				t.Fatal(err)
			}
			targetID := forward.DesiredLinks[0].LinkID
			if targetID == 0 || targetID == active.LinkID {
				t.Fatalf("forward replacement=%+v", forward.DesiredLinks)
			}
			rollingBack := advancePinOwnerRecord(
				forward,
				fixture.now.Add(2*time.Minute),
				pinOwnerPhaseApplying,
				pinOwnerStepRollingBack,
			)
			if err := fixture.store.Persist(rollingBack, forward, fixture.handle.mountID); err != nil {
				t.Fatal(err)
			}
			foreignID := kernel.addLink(
				active.IfIndex, ebpf.AttachType(active.AttachType), 999,
			)
			var store exactTCXOwnerStore = fixture.store
			injected := errors.New("injected rollback journal persist failure")
			if failAt != 0 {
				store = &faultExactTCXOwnerStore{
					base: fixture.store, failAt: failAt, persistErr: injected,
				}
			}
			current, rollbackErr := rollbackFailedExactOwnerApplyLinks(
				t.Context(), fixture.handle, rollingBack,
				fakeLoadedOwnerPrograms(active.ProgramID, desired.ProgramID),
				store, kernel.runtime(),
			)
			if failAt == 0 {
				if rollbackErr != nil {
					t.Fatal(rollbackErr)
				}
			} else {
				if !errors.Is(rollbackErr, injected) {
					t.Fatalf("rollback error=%v, want %v", rollbackErr, injected)
				}
				persisted, err := fixture.store.Load(fixture.handle.mountID)
				if err != nil {
					t.Fatal(err)
				}
				if persisted.Step != pinOwnerStepRollingBack {
					t.Fatalf("persist failure escaped rolling_back: %+v", persisted)
				}
				current, rollbackErr = rollbackFailedExactOwnerApplyLinks(
					t.Context(), fixture.handle, persisted,
					fakeLoadedOwnerPrograms(active.ProgramID, desired.ProgramID),
					fixture.store, kernel.runtime(),
				)
				if rollbackErr != nil {
					t.Fatalf("restart rollback: %v", rollbackErr)
				}
			}
			rollbackActive := current.ActiveLinks[0]
			if rollbackActive.ProgramID != active.ProgramID ||
				rollbackActive.LinkID == 0 || rollbackActive.LinkID == active.LinkID ||
				rollbackActive.LinkID == targetID ||
				rollbackActive.ReplacesLinkID != active.LinkID ||
				rollbackActive.PinPending || rollbackActive.Retiring {
				t.Fatalf("rollback identity=%+v old=%+v target=%d", rollbackActive, active, targetID)
			}
			persisted, err := fixture.store.Load(fixture.handle.mountID)
			if err != nil {
				t.Fatal(err)
			}
			if persisted.ActiveLinks[0] != rollbackActive {
				t.Fatalf("replacement identity was not durable: persisted=%+v current=%+v", persisted.ActiveLinks, current.ActiveLinks)
			}
			if kernel.links[targetID].attached || !kernel.links[rollbackActive.LinkID].attached ||
				kernel.links[rollbackActive.LinkID].identity.ProgramID != active.ProgramID {
				t.Fatalf("old/target/rollback links=%+v", kernel.links)
			}
			if !kernel.links[foreignID].attached {
				t.Fatal("rollback detached foreign TCX link in reused slot")
			}

			publishSource := clonePinOwnerRecord(current)
			publishSource.ActiveLinks[0].ReplacesLinkID = 0
			published, err := abortApplyingPinOwnerRecord(
				publishSource, fixture.now.Add(3*time.Minute),
			)
			if err != nil {
				t.Fatal(err)
			}
			if published.ActiveGeneration != 7 || published.ActiveLinks[0].LinkID != rollbackActive.LinkID ||
				published.ActiveLinks[0].ProgramID != active.ProgramID {
				t.Fatalf("published old generation=%+v", published)
			}
			finalPersistErr := errors.New("injected final active publish failure")
			finalFault := &faultExactTCXOwnerStore{
				base: fixture.store, failAt: 1, persistErr: finalPersistErr,
			}
			if err := finalFault.Persist(published, current, fixture.handle.mountID); !errors.Is(err, finalPersistErr) {
				t.Fatalf("final active publish error=%v", err)
			}
			stillRollingBack, err := fixture.store.Load(fixture.handle.mountID)
			if err != nil {
				t.Fatal(err)
			}
			if stillRollingBack.Step != pinOwnerStepRollingBack ||
				stillRollingBack.ActiveLinks[0].LinkID != rollbackActive.LinkID {
				t.Fatalf("failed active publish lost rollback identity: %+v", stillRollingBack)
			}
			recovered, err := rollbackFailedExactOwnerApplyLinks(
				t.Context(), fixture.handle, stillRollingBack,
				fakeLoadedOwnerPrograms(active.ProgramID, desired.ProgramID),
				fixture.store, kernel.runtime(),
			)
			if err != nil {
				t.Fatalf("recover final active publish boundary: %v", err)
			}
			recoveredSource := clonePinOwnerRecord(recovered)
			recoveredSource.ActiveLinks[0].ReplacesLinkID = 0
			recoveredActive, err := abortApplyingPinOwnerRecord(
				recoveredSource, fixture.now.Add(4*time.Minute),
			)
			if err != nil {
				t.Fatal(err)
			}
			if err := fixture.store.Persist(
				recoveredActive, recovered, fixture.handle.mountID,
			); err != nil {
				t.Fatal(err)
			}
			if recoveredActive.ActiveLinks[0].LinkID != rollbackActive.LinkID ||
				recoveredActive.ActiveLinks[0].ProgramID != active.ProgramID {
				t.Fatalf("recovered active identity=%+v", recoveredActive.ActiveLinks)
			}
		})
	}
}

func TestRollbackExactOwnerApplyCompletedReplacementRestartIsIdempotent(t *testing.T) {
	fixture := newExactTCXOwnerTestFixture(t)
	kernel := newFakeExactTCXKernel()
	kernel.materializePins = true
	current, original, target := establishCompletedRollbackReplacementExactTCX(
		t, fixture, kernel,
		testExactTCXBinding(43, exactTCXIngress, 631),
		632,
	)
	replacement := current.ActiveLinks[0]
	if replacement.LinkID == 0 || replacement.LinkID == original.LinkID ||
		replacement.ReplacesLinkID != original.LinkID ||
		replacement.ProgramID != original.ProgramID {
		t.Fatalf("completed rollback replacement=%+v original=%+v", replacement, original)
	}
	pinPath := filepath.Join(fixture.handle.procPath(), replacement.PinName)
	if kernel.pins[pinPath] != replacement.LinkID || kernel.links[target.LinkID].attached {
		t.Fatalf("replacement pin/retired target: pins=%+v links=%+v", kernel.pins, kernel.links)
	}
	foreignID := kernel.addLink(
		replacement.IfIndex, ebpf.AttachType(replacement.AttachType), 999,
	)

	for attempt := 1; attempt <= 2; attempt++ {
		beforeEvents := len(kernel.events)
		persistTrap := errors.New("idempotent restart attempted to persist")
		faults := &faultExactTCXOwnerStore{
			base: fixture.store, failAt: 1, persistErr: persistTrap,
		}
		recovered, err := rollbackFailedExactOwnerApplyLinks(
			t.Context(), fixture.handle, current,
			fakeLoadedOwnerPrograms(original.ProgramID, target.ProgramID),
			faults, kernel.runtime(),
		)
		if err != nil {
			t.Fatalf("idempotent restart %d: %v", attempt, err)
		}
		if faults.persisted != 0 {
			t.Fatalf("idempotent restart %d persisted %d records", attempt, faults.persisted)
		}
		if mutations := exactTCXMutationEvents(kernel.events[beforeEvents:]); len(mutations) != 0 {
			t.Fatalf("idempotent restart %d mutated TCX state: %v", attempt, mutations)
		}
		if recovered.Sequence != current.Sequence || recovered.ActiveLinks[0] != replacement {
			t.Fatalf("idempotent restart %d changed journal: before=%+v after=%+v", attempt, current, recovered)
		}
		if kernel.pins[pinPath] != replacement.LinkID ||
			!kernel.links[replacement.LinkID].attached ||
			kernel.links[replacement.LinkID].identity.ProgramID != original.ProgramID ||
			kernel.links[target.LinkID].attached || !kernel.links[foreignID].attached {
			t.Fatalf("idempotent restart %d changed replacement/target/foreign: %+v", attempt, kernel.links)
		}
		current = recovered
	}
}

func TestRollbackExactOwnerApplyCompletedReplacementForeignPinFailsClosed(t *testing.T) {
	fixture := newExactTCXOwnerTestFixture(t)
	kernel := newFakeExactTCXKernel()
	kernel.materializePins = true
	current, original, target := establishCompletedRollbackReplacementExactTCX(
		t, fixture, kernel,
		testExactTCXBinding(44, exactTCXEgress, 641),
		642,
	)
	replacement := current.ActiveLinks[0]
	pinPath := filepath.Join(fixture.handle.procPath(), replacement.PinName)
	foreignID := kernel.addLink(
		replacement.IfIndex,
		ebpf.AttachType(replacement.AttachType),
		replacement.ProgramID,
	)
	if kernel.pins[pinPath] != replacement.LinkID {
		t.Fatalf("rollback replacement pin=%d, want %d", kernel.pins[pinPath], replacement.LinkID)
	}
	kernel.links[replacement.LinkID].pins--
	kernel.links[replacement.LinkID].attached = false
	kernel.links[replacement.LinkID].identity.IfIndex = 0
	kernel.links[foreignID].pins++
	kernel.pins[pinPath] = foreignID

	beforeEvents := len(kernel.events)
	faults := &faultExactTCXOwnerStore{
		base:       fixture.store,
		failAt:     1,
		persistErr: errors.New("foreign pin path attempted to persist"),
	}
	_, err := rollbackFailedExactOwnerApplyLinks(
		t.Context(), fixture.handle, current,
		fakeLoadedOwnerPrograms(original.ProgramID, target.ProgramID),
		faults, kernel.runtime(),
	)
	if err == nil || !strings.Contains(err.Error(), "owner journal requires") {
		t.Fatalf("foreign rollback pin error=%v", err)
	}
	if faults.persisted != 0 {
		t.Fatalf("foreign rollback pin persisted %d records", faults.persisted)
	}
	if mutations := exactTCXMutationEvents(kernel.events[beforeEvents:]); len(mutations) != 0 {
		t.Fatalf("foreign rollback pin caused TCX mutation: %v", mutations)
	}
	if kernel.pins[pinPath] != foreignID || !kernel.links[foreignID].attached ||
		kernel.links[foreignID].identity.ProgramID != replacement.ProgramID ||
		kernel.links[target.LinkID].attached {
		t.Fatalf("foreign pin fail-closed state changed: pins=%+v links=%+v", kernel.pins, kernel.links)
	}
}

func TestRollbackExactOwnerApplyRebuildsDetachedSameLinkCASOnRestart(t *testing.T) {
	fixture := newExactTCXOwnerTestFixture(t)
	kernel := newFakeExactTCXKernel()
	kernel.materializePins = true
	journal := &fakeExactTCXJournal{events: &kernel.events}
	owner, _ := stageTestExactTCXAtPath(
		t, kernel,
		testExactTCXBinding(45, exactTCXIngress, 651),
		journal,
		fixture.handle.procPath(),
	)
	original := owner.binding
	if err := owner.Release(); err != nil {
		t.Fatal(err)
	}
	desired := original
	desired.ProgramID = 652
	record := fixture.mutatingRecord(
		t, []exactTCXBinding{original}, []exactTCXBinding{desired},
	)
	forward, err := convergeOwnerApplyExactTCXLinks(
		t.Context(), fixture.handle, fixture.store, record,
		fakeLoadedOwnerPrograms(original.ProgramID, desired.ProgramID), kernel.runtime(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if kernel.links[original.LinkID].identity.ProgramID != desired.ProgramID {
		t.Fatalf("same-link CAS did not publish desired program: %+v", kernel.links[original.LinkID])
	}
	rollingBack := advancePinOwnerRecord(
		forward,
		fixture.now.Add(2*time.Minute),
		pinOwnerPhaseApplying,
		pinOwnerStepRollingBack,
	)
	if err := fixture.store.Persist(rollingBack, forward, fixture.handle.mountID); err != nil {
		t.Fatal(err)
	}
	slot := fakeExactTCXSlot{
		ifindex: original.IfIndex,
		attach:  ebpf.AttachType(original.AttachType),
	}
	kernel.links[original.LinkID].attached = false
	kernel.links[original.LinkID].identity.IfIndex = 0
	kernel.revs[slot] = kernel.revision(slot) + 1
	marker, err := ownerRecordReplacingRollbackActive(
		rollingBack, original, fixture.handle, fixture.store,
	)
	if err != nil {
		t.Fatal(err)
	}
	if marker.ActiveLinks[0].LinkID != 0 ||
		marker.ActiveLinks[0].ReplacesLinkID != original.LinkID ||
		marker.DesiredLinks[0].LinkID != original.LinkID ||
		marker.DesiredLinks[0].ReplacesLinkID != 0 {
		t.Fatalf("detached same-link rollback marker=%+v", marker)
	}
	foreignID := kernel.addLink(
		original.IfIndex, ebpf.AttachType(original.AttachType), 999,
	)
	restarted, err := fixture.store.Load(fixture.handle.mountID)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := rollbackFailedExactOwnerApplyLinks(
		t.Context(), fixture.handle, restarted,
		fakeLoadedOwnerPrograms(original.ProgramID, desired.ProgramID),
		fixture.store, kernel.runtime(),
	)
	if err != nil {
		t.Fatal(err)
	}
	replacement := recovered.ActiveLinks[0]
	if replacement.LinkID == 0 || replacement.LinkID == original.LinkID ||
		replacement.ReplacesLinkID != original.LinkID ||
		replacement.ProgramID != original.ProgramID ||
		!kernel.links[replacement.LinkID].attached ||
		kernel.links[replacement.LinkID].identity.ProgramID != original.ProgramID ||
		kernel.links[original.LinkID].attached || !kernel.links[foreignID].attached {
		t.Fatalf("same-link CAS rollback replacement/old/foreign: replacement=%+v links=%+v", replacement, kernel.links)
	}

	beforeEvents := len(kernel.events)
	idempotent, err := rollbackFailedExactOwnerApplyLinks(
		t.Context(), fixture.handle, recovered,
		fakeLoadedOwnerPrograms(original.ProgramID, desired.ProgramID),
		fixture.store, kernel.runtime(),
	)
	if err != nil {
		t.Fatalf("same-link CAS second restart: %v", err)
	}
	if mutations := exactTCXMutationEvents(kernel.events[beforeEvents:]); len(mutations) != 0 {
		t.Fatalf("same-link CAS second restart mutated TCX state: %v", mutations)
	}
	if idempotent.ActiveLinks[0] != replacement || !kernel.links[foreignID].attached {
		t.Fatalf("same-link CAS second restart changed state: %+v links=%+v", idempotent, kernel.links)
	}
}

func TestRecoverMutatingExactOwnerRetriesAbortIntentAfterPersistFailure(t *testing.T) {
	fixture := newExactTCXOwnerTestFixture(t)
	kernel := newFakeExactTCXKernel()
	kernel.materializePins = true
	activeIntent := testExactTCXBinding(36, exactTCXEgress, 571)
	journal := &fakeExactTCXJournal{events: &kernel.events}
	owner, _ := stageTestExactTCXAtPath(
		t, kernel, activeIntent, journal, fixture.handle.procPath(),
	)
	active := owner.binding
	if err := owner.Release(); err != nil {
		t.Fatal(err)
	}
	desired := active
	desired.ProgramID = 572
	record := fixture.mutatingRecord(
		t, []exactTCXBinding{active}, []exactTCXBinding{desired},
	)
	beforeEvents := len(kernel.events)
	injected := errors.New("injected rolling_back intent persist failure")

	for attempt := 1; attempt <= 2; attempt++ {
		faults := &faultExactTCXOwnerStore{
			base: fixture.store, failAt: 1, persistErr: injected,
		}
		_, err := recoverExactApplyingPinOwnerTransaction(
			t.Context(), fixture.handle, faults, record, kernel.runtime(),
		)
		if !errors.Is(err, injected) {
			t.Fatalf("attempt %d recovery error=%v", attempt, err)
		}
		if len(faults.attempts) != 1 ||
			faults.attempts[0].Step != pinOwnerStepRollingBack {
			t.Fatalf("attempt %d persist attempts=%+v", attempt, faults.attempts)
		}
		persisted, loadErr := fixture.store.Load(fixture.handle.mountID)
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		if persisted.Step != pinOwnerStepMutating || persisted.Sequence != record.Sequence {
			t.Fatalf("attempt %d changed mutating journal=%+v", attempt, persisted)
		}
		record = persisted
	}
	if len(kernel.events) != beforeEvents ||
		kernel.links[active.LinkID].identity.ProgramID != active.ProgramID ||
		!kernel.links[active.LinkID].attached {
		t.Fatalf("abort-intent persist failures mutated/forwarded kernel: events=%v link=%+v", kernel.events[beforeEvents:], kernel.links[active.LinkID])
	}
}

func TestRecoverFreshMutatingExactOwnerTreatsZeroControlAsRollbackDecision(t *testing.T) {
	fixture := newExactTCXOwnerTestFixture(t)
	control := fixture.mapStore.observations["control_map"]
	control.control = abi.ControlValue{}
	control.controlSeen = true
	fixture.mapStore.observations["control_map"] = control
	kernel := newFakeExactTCXKernel()
	kernel.materializePins = true
	desired := testExactTCXBinding(42, exactTCXEgress, 621)
	record := fixture.mutatingRecord(t, nil, []exactTCXBinding{desired})
	injected := errors.New("injected fresh rolling_back persist failure")
	faults := &faultExactTCXOwnerStore{
		base: fixture.store, failAt: 1, persistErr: injected,
	}

	_, err := recoverExactApplyingPinOwnerTransaction(
		t.Context(), fixture.handle, faults, record, kernel.runtime(),
	)
	if !errors.Is(err, injected) {
		t.Fatalf("fresh mutating recovery error=%v", err)
	}
	if len(faults.attempts) != 1 ||
		faults.attempts[0].Step != pinOwnerStepRollingBack ||
		faults.attempts[0].ActiveGeneration != 0 {
		t.Fatalf("fresh mutating recovery did not choose rollback: %+v", faults.attempts)
	}
	if len(kernel.links) != 0 {
		t.Fatalf("fresh mutating recovery attached target before rollback intent: %+v", kernel.links)
	}
}

func TestRollbackExactOwnerApplyRecoversAfterTargetOnlyLinkAlreadyRemoved(t *testing.T) {
	fixture := newExactTCXOwnerTestFixture(t)
	kernel := newFakeExactTCXKernel()
	kernel.materializePins = true
	activeIntent := testExactTCXBinding(39, exactTCXIngress, 601)
	journal := &fakeExactTCXJournal{events: &kernel.events}
	owner, _ := stageTestExactTCXAtPath(
		t, kernel, activeIntent, journal, fixture.handle.procPath(),
	)
	active := owner.binding
	if err := owner.Release(); err != nil {
		t.Fatal(err)
	}
	targetOnly := testExactTCXBinding(40, exactTCXEgress, 602)
	desired := []exactTCXBinding{active, targetOnly}
	sortExactTCXBindings(desired)
	record := fixture.mutatingRecord(t, []exactTCXBinding{active}, desired)
	forward, err := convergeOwnerApplyExactTCXLinks(
		t.Context(), fixture.handle, fixture.store, record,
		fakeLoadedOwnerPrograms(active.ProgramID, targetOnly.ProgramID), kernel.runtime(),
	)
	if err != nil {
		t.Fatal(err)
	}
	var target exactTCXBinding
	for _, binding := range forward.DesiredLinks {
		if sameExactTCXSlot(binding, targetOnly) {
			target = binding
		}
	}
	if target.LinkID == 0 {
		t.Fatalf("target-only forward record=%+v", forward.DesiredLinks)
	}
	rollingBack := advancePinOwnerRecord(
		forward,
		fixture.now.Add(2*time.Minute),
		pinOwnerPhaseApplying,
		pinOwnerStepRollingBack,
	)
	if err := fixture.store.Persist(rollingBack, forward, fixture.handle.mountID); err != nil {
		t.Fatal(err)
	}
	if err := removeOwnedExactTCXLink(fixture.handle, target, kernel.runtime()); err != nil {
		t.Fatal(err)
	}
	foreignID := kernel.addLink(
		target.IfIndex, ebpf.AttachType(target.AttachType), 999,
	)

	recovered, err := rollbackFailedExactOwnerApplyLinks(
		t.Context(), fixture.handle, rollingBack,
		fakeLoadedOwnerPrograms(active.ProgramID, target.ProgramID),
		fixture.store, kernel.runtime(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(recovered.ActiveLinks) != 1 || recovered.ActiveLinks[0].LinkID != active.LinkID ||
		recovered.ActiveLinks[0].ProgramID != active.ProgramID {
		t.Fatalf("target-only rollback changed active identity: %+v", recovered.ActiveLinks)
	}
	if kernel.links[target.LinkID].attached || !kernel.links[foreignID].attached ||
		!kernel.links[active.LinkID].attached {
		t.Fatalf("target-only/foreign/active links=%+v", kernel.links)
	}
}

func TestRollbackCleanupRecoversWithProgramStagesAlreadyAbsent(t *testing.T) {
	fixture := newExactTCXOwnerTestFixture(t)
	kernel := newFakeExactTCXKernel()
	kernel.materializePins = true
	activeIntent := testExactTCXBinding(41, exactTCXIngress, 611)
	journal := &fakeExactTCXJournal{events: &kernel.events}
	owner, _ := stageTestExactTCXAtPath(
		t, kernel, activeIntent, journal, fixture.handle.procPath(),
	)
	active := owner.binding
	if err := owner.Release(); err != nil {
		t.Fatal(err)
	}
	desired := active
	desired.ProgramID = 612
	mutating := fixture.mutatingRecord(
		t, []exactTCXBinding{active}, []exactTCXBinding{desired},
	)
	cleanup := advancePinOwnerRecord(
		mutating,
		fixture.now.Add(2*time.Minute),
		pinOwnerPhaseApplying,
		pinOwnerStepRollbackCleanup,
	)
	if err := fixture.store.Persist(cleanup, mutating, fixture.handle.mountID); err != nil {
		t.Fatal(err)
	}
	for _, stage := range cleanup.ProgramStages {
		if _, err := os.Lstat(filepath.Join(fixture.handle.pinPath, stage.FileName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("program stage %s unexpectedly exists: %v", stage.FileName, err)
		}
	}
	foreignID := kernel.addLink(active.IfIndex, ebpf.AttachType(active.AttachType), 999)

	injected := errors.New("injected rollback cleanup active publish failure")
	faults := &faultExactTCXOwnerStore{
		base: fixture.store, failAt: 1, persistErr: injected,
	}
	if _, err := recoverExactRollbackCleanupPinOwnerTransaction(
		t.Context(), fixture.handle, faults, cleanup, kernel.runtime(),
	); !errors.Is(err, injected) {
		t.Fatalf("rollback cleanup publish error=%v", err)
	}
	persisted, err := fixture.store.Load(fixture.handle.mountID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Step != pinOwnerStepRollbackCleanup {
		t.Fatalf("failed cleanup publish changed journal=%+v", persisted)
	}
	recovered, err := recoverExactRollbackCleanupPinOwnerTransaction(
		t.Context(), fixture.handle, fixture.store, persisted, kernel.runtime(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if recovered == nil || recovered.record == nil ||
		recovered.record.Phase != pinOwnerPhaseActive ||
		recovered.record.ActiveGeneration != 7 ||
		len(recovered.record.ActiveLinks) != 1 ||
		recovered.record.ActiveLinks[0] != active {
		t.Fatalf("rollback cleanup recovery=%+v", recovered)
	}
	if !kernel.links[active.LinkID].attached || !kernel.links[foreignID].attached {
		t.Fatalf("rollback cleanup changed active/foreign links=%+v", kernel.links)
	}
}

func TestConvergeOwnerExactTCXUsesSameLinkIDForCASUpdate(t *testing.T) {
	fixture := newExactTCXOwnerTestFixture(t)
	kernel := newFakeExactTCXKernel()
	kernel.materializePins = true
	activeIntent := testExactTCXBinding(23, exactTCXIngress, 601)
	journal := &fakeExactTCXJournal{events: &kernel.events}
	owner, pinPath := stageTestExactTCXAtPath(t, kernel, activeIntent, journal, fixture.handle.procPath())
	active := owner.binding
	if err := owner.Release(); err != nil {
		t.Fatal(err)
	}
	desired := active
	desired.ProgramID = 602
	record := fixture.mutatingRecord(t, []exactTCXBinding{active}, []exactTCXBinding{desired})

	converged, err := convergeOwnerApplyExactTCXLinks(
		t.Context(),
		fixture.handle,
		fixture.store,
		record,
		fakeLoadedOwnerPrograms(601, 602),
		kernel.runtime(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if converged.DesiredLinks[0].LinkID != active.LinkID ||
		kernel.pins[pinPath] != active.LinkID ||
		kernel.links[active.LinkID].identity.ProgramID != 602 {
		t.Fatalf(
			"CAS update changed exact identity: record=%+v pin=%d kernel=%+v",
			converged.DesiredLinks[0], kernel.pins[pinPath], kernel.links[active.LinkID],
		)
	}
}

func TestRemoveOwnedExactTCXRecoversDetachedPinnedBoundary(t *testing.T) {
	fixture := newExactTCXOwnerTestFixture(t)
	kernel := newFakeExactTCXKernel()
	kernel.materializePins = true
	intent := testExactTCXBinding(24, exactTCXEgress, 701)
	journal := &fakeExactTCXJournal{events: &kernel.events}
	owner, _ := stageTestExactTCXAtPath(t, kernel, intent, journal, fixture.handle.procPath())
	binding := owner.binding
	injected := errors.New("injected crash before exact unpin")
	kernel.unpinErrs[binding.LinkID] = []error{injected}
	if err := owner.Rollback(); !errors.Is(err, injected) {
		t.Fatalf("first rollback error = %v", err)
	}
	if kernel.links[binding.LinkID].attached {
		t.Fatal("fault boundary did not detach exact link")
	}
	if err := owner.link.Close(); err != nil {
		t.Fatal(err)
	}
	owner.link = nil
	owner.closed = true
	// A removed netdevice may make QueryPrograms return ENODEV instead of an
	// empty revisioned slot. The exact detached identity still makes cleanup
	// safe and restart-convergent.
	kernel.queryErr = unix.ENODEV

	if err := removeOwnedExactTCXLink(fixture.handle, binding, kernel.runtime()); err != nil {
		t.Fatal(err)
	}
	if _, exists := kernel.pins[filepath.Join(fixture.handle.procPath(), binding.PinName)]; exists {
		t.Fatal("restart recovery left detached exact pin")
	}
	if kernel.links[binding.LinkID].attached {
		t.Fatal("restart recovery reattached or retained exact link")
	}
}

func TestReconcileDetachedActiveExactTCXPersistsTruthWithForeignSlotReuse(t *testing.T) {
	fixture := newExactTCXOwnerTestFixture(t)
	kernel := newFakeExactTCXKernel()
	kernel.materializePins = true
	intent := testExactTCXBinding(27, exactTCXEgress, 702)
	journal := &fakeExactTCXJournal{events: &kernel.events}
	owner, pinPath := stageTestExactTCXAtPath(
		t, kernel, intent, journal, fixture.handle.procPath(),
	)
	active := owner.binding
	record, err := newActivePinOwnerRecord(
		fixture.parent,
		fixture.token,
		"12345678-1234-1234-1234-123456789abc",
		fixture.now,
		7,
		fixture.maps,
		[]exactTCXBinding{active},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.Persist(record, nil, fixture.handle.mountID); err != nil {
		t.Fatal(err)
	}
	unpinErr := errors.New("injected active detach crash boundary")
	kernel.unpinErrs[active.LinkID] = []error{unpinErr}
	if err := owner.Rollback(); !errors.Is(err, unpinErr) {
		t.Fatalf("detach boundary error=%v", err)
	}
	if err := owner.Release(); err != nil {
		t.Fatal(err)
	}
	foreignID := kernel.addLink(active.IfIndex, ebpf.AttachType(active.AttachType), 999)

	recovered, err := recoverExactPinOwnerTransaction(
		t.Context(), fixture.handle, fixture.store, record, kernel.runtime(),
	)
	if err != nil {
		t.Fatal(err)
	}
	reconciled := recovered.record
	if len(reconciled.ActiveLinks) != 0 || reconciled.Sequence != record.Sequence+1 {
		t.Fatalf("reconciled active record=%+v", reconciled)
	}
	if _, exists := kernel.pins[pinPath]; exists || kernel.links[active.LinkID].attached {
		t.Fatalf("detached exact owner survived reconciliation: pin=%v link=%+v", exists, kernel.links[active.LinkID])
	}
	if !kernel.links[foreignID].attached {
		t.Fatal("reconciliation detached a foreign link on a reused ifindex")
	}
	persisted, err := fixture.store.Load(fixture.handle.mountID)
	if err != nil {
		t.Fatal(err)
	}
	if len(persisted.ActiveLinks) != 0 || persisted.Sequence != reconciled.Sequence {
		t.Fatalf("persisted reconciled record=%+v", persisted)
	}
	if err := executeExactOwnerDetachTransaction(
		t.Context(), fixture.handle, fixture.store, reconciled, kernel.runtime(),
	); err != nil {
		t.Fatalf("detach after active detached-link reconciliation: %v", err)
	}
	if _, err := os.Lstat(fixture.handle.pinPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("converged detach retained pin directory: %v", err)
	}
	if !kernel.links[foreignID].attached {
		t.Fatal("converged detach mutated the foreign link")
	}
}

func TestReconcileDetachedActiveExactTCXPersistsRetiringBeforeUnpin(t *testing.T) {
	fixture := newExactTCXOwnerTestFixture(t)
	kernel := newFakeExactTCXKernel()
	kernel.materializePins = true
	intent := testExactTCXBinding(34, exactTCXEgress, 551)
	journal := &fakeExactTCXJournal{events: &kernel.events}
	owner, pinPath := stageTestExactTCXAtPath(
		t, kernel, intent, journal, fixture.handle.procPath(),
	)
	active := owner.binding
	record, err := newActivePinOwnerRecord(
		fixture.parent,
		fixture.token,
		"12345678-1234-1234-1234-123456789abc",
		fixture.now,
		7,
		fixture.maps,
		[]exactTCXBinding{active},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.Persist(record, nil, fixture.handle.mountID); err != nil {
		t.Fatal(err)
	}
	injectedUnpin := errors.New("hold detached active pin")
	kernel.unpinErrs[active.LinkID] = []error{injectedUnpin}
	if err := owner.Rollback(); !errors.Is(err, injectedUnpin) {
		t.Fatalf("detach active link: %v", err)
	}
	if err := owner.Release(); err != nil {
		t.Fatal(err)
	}
	injectedPersist := errors.New("injected active retiring persist failure")
	faults := &faultExactTCXOwnerStore{
		base: fixture.store, failAt: 1, persistErr: injectedPersist,
	}

	current, err := reconcileDetachedActiveExactTCXLinks(
		fixture.handle, faults, record, kernel.runtime(),
	)
	if !errors.Is(err, injectedPersist) || current != record {
		t.Fatalf("reconcile current=%p/%p error=%v", current, record, err)
	}
	if kernel.pins[pinPath] != active.LinkID {
		t.Fatalf("retiring persist failure removed exact pin: pins=%+v", kernel.pins)
	}
	reconciled, err := reconcileDetachedActiveExactTCXLinks(
		fixture.handle, fixture.store, record, kernel.runtime(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if reconciled.Step != pinOwnerStepReady || len(reconciled.ActiveLinks) != 0 {
		t.Fatalf("active retirement did not converge: %+v", reconciled)
	}
}

func TestReconcileDetachedActiveExactTCXRecoversAfterTruthPersistFailure(t *testing.T) {
	fixture := newExactTCXOwnerTestFixture(t)
	kernel := newFakeExactTCXKernel()
	kernel.materializePins = true
	intent := testExactTCXBinding(38, exactTCXIngress, 591)
	journal := &fakeExactTCXJournal{events: &kernel.events}
	owner, pinPath := stageTestExactTCXAtPath(
		t, kernel, intent, journal, fixture.handle.procPath(),
	)
	active := owner.binding
	record, err := newActivePinOwnerRecord(
		fixture.parent,
		fixture.token,
		"12345678-1234-1234-1234-123456789abc",
		fixture.now,
		7,
		fixture.maps,
		[]exactTCXBinding{active},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.Persist(record, nil, fixture.handle.mountID); err != nil {
		t.Fatal(err)
	}
	injectedUnpin := errors.New("hold active pin before reconciliation")
	kernel.unpinErrs[active.LinkID] = []error{injectedUnpin}
	if err := owner.Rollback(); !errors.Is(err, injectedUnpin) {
		t.Fatal(err)
	}
	if err := owner.Release(); err != nil {
		t.Fatal(err)
	}
	injectedPersist := errors.New("injected active truth persist failure")
	faults := &faultExactTCXOwnerStore{
		base: fixture.store, failAt: 2, persistErr: injectedPersist,
	}
	current, err := reconcileDetachedActiveExactTCXLinks(
		fixture.handle, faults, record, kernel.runtime(),
	)
	if !errors.Is(err, injectedPersist) || current == nil ||
		current.Step != pinOwnerStepRetiring || !current.ActiveLinks[0].Retiring {
		t.Fatalf("active truth boundary current=%+v error=%v", current, err)
	}
	if _, exists := kernel.pins[pinPath]; exists || kernel.links[active.LinkID].attached {
		t.Fatalf("active truth boundary retained exact link: pins=%+v link=%+v", kernel.pins, kernel.links[active.LinkID])
	}
	persisted, err := fixture.store.Load(fixture.handle.mountID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Step != pinOwnerStepRetiring || !persisted.ActiveLinks[0].Retiring {
		t.Fatalf("active retiring marker not durable: %+v", persisted)
	}
	reconciled, err := reconcileDetachedActiveExactTCXLinks(
		fixture.handle, fixture.store, persisted, kernel.runtime(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if reconciled.Step != pinOwnerStepReady || len(reconciled.ActiveLinks) != 0 {
		t.Fatalf("active truth restart did not converge: %+v", reconciled)
	}
}

func TestObserveExactTCXPinRejectsInodeReplacementWithoutKernelMutation(t *testing.T) {
	fixture := newExactTCXOwnerTestFixture(t)
	kernel := newFakeExactTCXKernel()
	kernel.materializePins = true
	intent := testExactTCXBinding(28, exactTCXIngress, 703)
	journal := &fakeExactTCXJournal{events: &kernel.events}
	owner, pinPath := stageTestExactTCXAtPath(
		t, kernel, intent, journal, fixture.handle.procPath(),
	)
	binding := owner.binding
	if err := owner.Release(); err != nil {
		t.Fatal(err)
	}
	anchoredCopy := pinPath + ".owned-evidence"
	kernel.beforeQuery = func(kernel *fakeExactTCXKernel, _ fakeExactTCXSlot) {
		kernel.beforeQuery = nil
		if err := os.Rename(pinPath, anchoredCopy); err != nil {
			t.Fatalf("preserve owned pin inode: %v", err)
		}
		if err := os.WriteFile(pinPath, []byte("foreign"), 0o600); err != nil {
			t.Fatalf("materialize replacement inode: %v", err)
		}
	}

	observedOwner, observation, err := observePinnedExactTCXAt(
		fixture.handle,
		binding,
		[]uint32{binding.ProgramID},
		kernel.runtime(),
	)
	if observedOwner != nil || observation != nil || err == nil ||
		!strings.Contains(err.Error(), "changed while validating") {
		t.Fatalf("owner=%#v observation=%#v error=%v", observedOwner, observation, err)
	}
	if !kernel.links[binding.LinkID].attached || kernel.pins[pinPath] != binding.LinkID {
		t.Fatalf("inode race mutated exact kernel ownership: link=%+v pins=%+v", kernel.links[binding.LinkID], kernel.pins)
	}
}

func TestRollbackExactTCXRechecksAnchoredPinBeforeDetachAndUnpin(t *testing.T) {
	fixture := newExactTCXOwnerTestFixture(t)
	kernel := newFakeExactTCXKernel()
	kernel.materializePins = true
	intent := testExactTCXBinding(30, exactTCXEgress, 704)
	journal := &fakeExactTCXJournal{events: &kernel.events}
	staged, pinPath := stageTestExactTCXAtPath(
		t, kernel, intent, journal, fixture.handle.procPath(),
	)
	binding := staged.binding
	if err := staged.Release(); err != nil {
		t.Fatal(err)
	}
	owner, observation, err := observePinnedExactTCXAt(
		fixture.handle,
		binding,
		[]uint32{binding.ProgramID},
		kernel.runtime(),
	)
	if err != nil || !observation.Attached {
		t.Fatalf("observe owner=%#v observation=%#v error=%v", owner, observation, err)
	}
	if err := os.Rename(pinPath, pinPath+".owned-evidence"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pinPath, []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := owner.Rollback(); err == nil || !strings.Contains(err.Error(), "changed before mutation") {
		t.Fatalf("rollback after pin replacement error=%v", err)
	}
	if !kernel.links[binding.LinkID].attached || kernel.pins[pinPath] != binding.LinkID {
		t.Fatalf("rollback mutated exact link after pin swap: link=%+v pins=%+v", kernel.links[binding.LinkID], kernel.pins)
	}
	if err := owner.Release(); err != nil {
		t.Fatal(err)
	}
}

func stageTestExactTCXAtPath(
	t *testing.T,
	kernel *fakeExactTCXKernel,
	binding exactTCXBinding,
	journal *fakeExactTCXJournal,
	directory string,
) (*exactTCXAttachment, string) {
	t.Helper()
	pinPath := filepath.Join(directory, binding.PinName)
	owner, err := stageExactTCXAttachment(
		t.Context(),
		binding,
		pinPath,
		exactTCXProgram{id: binding.ProgramID},
		journal.callbacks(),
		kernel.runtime(),
	)
	if err != nil {
		t.Fatal(err)
	}
	return owner, pinPath
}
