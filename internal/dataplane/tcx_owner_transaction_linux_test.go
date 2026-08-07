//go:build linux

package dataplane

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
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
	if err := os.Mkdir(pinPath, 0o700); err != nil {
		t.Fatal(err)
	}
	runtime := newTestPinPathRuntime(t, validator, newFakePinnedMapStore())
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

func TestConvergeOwnerExactTCXRecoversPinBeforeIdentityPublish(t *testing.T) {
	fixture := newExactTCXOwnerTestFixture(t)
	kernel := newFakeExactTCXKernel()
	kernel.materializePins = true
	desired := testExactTCXBinding(22, exactTCXEgress, 502)
	record := fixture.mutatingRecord(t, nil, []exactTCXBinding{desired})
	pinPath := filepath.Join(fixture.handle.procPath(), desired.PinName)
	injected := errors.New("injected identity publish crash")
	owner, err := stageExactTCXAttachment(
		t.Context(),
		desired,
		pinPath,
		exactTCXProgram{id: desired.ProgramID},
		exactTCXJournal{
			persistIntent: func(exactTCXJournalIntent) error { return nil },
			persistActive: func(exactTCXBinding, exactTCXJournalIntent) error {
				return injected
			},
		},
		kernel.runtime(),
	)
	if !errors.Is(err, injected) || owner == nil || !owner.pinned {
		t.Fatalf("stage owner=%#v error=%v", owner, err)
	}
	crashedLinkID := owner.binding.LinkID
	if err := owner.Release(); err != nil {
		t.Fatal(err)
	}

	converged, err := convergeOwnerApplyExactTCXLinks(
		t.Context(),
		fixture.handle,
		fixture.store,
		record,
		fakeLoadedOwnerPrograms(502),
		kernel.runtime(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if converged.DesiredLinks[0].LinkID != crashedLinkID {
		t.Fatalf(
			"recovered link ID = %d, want pinned crash identity %d",
			converged.DesiredLinks[0].LinkID,
			crashedLinkID,
		)
	}
	if len(kernel.links) != 1 {
		t.Fatalf("recovery created another exact link: %+v", kernel.links)
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
