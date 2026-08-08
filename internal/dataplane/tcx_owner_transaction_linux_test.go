//go:build linux

package dataplane

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

type exactTCXOwnerTestFixture struct {
	runtime pinPathRuntime
	parent  *pinPathParent
	handle  *pinPathHandle
	store   *pinOwnerStore
	token   [32]byte
	maps    []pinOwnerMapIdentity
	now     time.Time
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
		runtime: runtime,
		parent:  parent,
		handle:  handle,
		store:   store,
		now:     now,
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
