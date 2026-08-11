//go:build linux

package dataplane

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	ciliumlink "github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

type fakeExactTCXSlot struct {
	ifindex int
	attach  ebpf.AttachType
}

type recordingLiveExactTCXLink struct {
	update *ciliumlink.RawLinkUpdateOptions
}

func (*recordingLiveExactTCXLink) Pin(string) error                { return nil }
func (*recordingLiveExactTCXLink) Unpin() error                    { return nil }
func (*recordingLiveExactTCXLink) Close() error                    { return nil }
func (*recordingLiveExactTCXLink) Detach() error                   { return nil }
func (*recordingLiveExactTCXLink) Info() (*ciliumlink.Info, error) { return nil, nil }
func (link *recordingLiveExactTCXLink) UpdateArgs(options ciliumlink.RawLinkUpdateOptions) error {
	copy := options
	link.update = &copy
	return nil
}

func TestLiveExactTCXCompareUpdatePassesReplaceCASArguments(t *testing.T) {
	backend := &recordingLiveExactTCXLink{}
	owned := &liveExactTCXLink{link: backend}
	oldProgram := &ebpf.Program{}
	newProgram := &ebpf.Program{}
	update := exactTCXLinkUpdate{
		Old:   exactTCXProgram{id: 1, kernel: oldProgram},
		New:   exactTCXProgram{id: 2, kernel: newProgram},
		Flags: unix.BPF_F_REPLACE,
	}
	if err := owned.CompareUpdate(update); err != nil {
		t.Fatal(err)
	}
	if backend.update == nil || backend.update.Old != oldProgram ||
		backend.update.New != newProgram || backend.update.Flags != unix.BPF_F_REPLACE {
		t.Fatalf("raw live link update=%+v", backend.update)
	}
	update.Flags = 0
	if err := owned.CompareUpdate(update); err == nil {
		t.Fatal("live exact TCX compare-update accepted missing BPF_F_REPLACE")
	}
}

type fakeExactTCXLinkState struct {
	identity exactTCXLinkIdentity
	attached bool
	fdRefs   int
	pins     int
}

type fakeExactTCXKernel struct {
	nextID uint32
	links  map[uint32]*fakeExactTCXLinkState
	pins   map[string]uint32
	revs   map[fakeExactTCXSlot]uint64
	events []string

	beforeAttach        func(*fakeExactTCXKernel, fakeExactTCXSlot)
	beforeCompareUpdate func(*fakeExactTCXKernel, uint32)
	beforeQuery         func(*fakeExactTCXKernel, fakeExactTCXSlot)
	lastUpdate          *exactTCXLinkUpdate
	queryErr            error
	pinErr              error
	detachErrs          map[uint32][]error
	unpinErrs           map[uint32][]error
	closeErrs           map[uint32][]error
	materializePins     bool
}

func newFakeExactTCXKernel() *fakeExactTCXKernel {
	return &fakeExactTCXKernel{
		nextID:     100,
		links:      make(map[uint32]*fakeExactTCXLinkState),
		pins:       make(map[string]uint32),
		revs:       make(map[fakeExactTCXSlot]uint64),
		detachErrs: make(map[uint32][]error),
		unpinErrs:  make(map[uint32][]error),
		closeErrs:  make(map[uint32][]error),
	}
}

func (kernel *fakeExactTCXKernel) revision(slot fakeExactTCXSlot) uint64 {
	if kernel.revs[slot] == 0 {
		kernel.revs[slot] = 1
	}
	return kernel.revs[slot]
}

func (kernel *fakeExactTCXKernel) addLink(
	ifindex int,
	attach ebpf.AttachType,
	programID uint32,
) uint32 {
	slot := fakeExactTCXSlot{ifindex: ifindex, attach: attach}
	kernel.nextID++
	id := kernel.nextID
	kernel.links[id] = &fakeExactTCXLinkState{
		identity: exactTCXLinkIdentity{
			IfIndex: ifindex, Attach: attach, LinkID: id, ProgramID: programID,
		},
		attached: true,
	}
	kernel.revs[slot] = kernel.revision(slot) + 1
	return id
}

func (kernel *fakeExactTCXKernel) runtime() exactTCXRuntime {
	return exactTCXRuntime{
		query: func(ifindex int, attach ebpf.AttachType) (exactTCXQuery, error) {
			slot := fakeExactTCXSlot{ifindex: ifindex, attach: attach}
			kernel.events = append(kernel.events, "query")
			if kernel.beforeQuery != nil {
				kernel.beforeQuery(kernel, slot)
			}
			if kernel.queryErr != nil {
				return exactTCXQuery{}, kernel.queryErr
			}
			query := exactTCXQuery{Revision: kernel.revision(slot)}
			for _, state := range kernel.links {
				if !state.attached ||
					state.identity.IfIndex != ifindex ||
					state.identity.Attach != attach {
					continue
				}
				query.Programs = append(query.Programs, exactTCXQueryProgram{
					LinkID: state.identity.LinkID, ProgramID: state.identity.ProgramID,
				})
			}
			return query, nil
		},
		attach: func(
			ifindex int,
			attach ebpf.AttachType,
			revision uint64,
			program exactTCXProgram,
		) (exactTCXKernelLink, error) {
			slot := fakeExactTCXSlot{ifindex: ifindex, attach: attach}
			kernel.events = append(kernel.events, "attach")
			if kernel.beforeAttach != nil {
				kernel.beforeAttach(kernel, slot)
			}
			if revision != kernel.revision(slot) {
				return nil, unix.ESTALE
			}
			id := kernel.addLink(ifindex, attach, program.id)
			kernel.links[id].fdRefs++
			return &fakeExactTCXHandle{kernel: kernel, id: id}, nil
		},
		loadPinned: func(path string) (exactTCXKernelLink, error) {
			kernel.events = append(kernel.events, "load")
			id, ok := kernel.pins[path]
			if !ok {
				return nil, unix.ENOENT
			}
			state := kernel.links[id]
			if state == nil {
				return nil, errors.New("fake pin points to missing link")
			}
			state.fdRefs++
			return &fakeExactTCXHandle{kernel: kernel, id: id, pinnedPath: path}, nil
		},
	}
}

type fakeExactTCXHandle struct {
	kernel     *fakeExactTCXKernel
	id         uint32
	pinnedPath string
	closed     bool
}

func (handle *fakeExactTCXHandle) state() (*fakeExactTCXLinkState, error) {
	if handle == nil || handle.kernel == nil || handle.closed {
		return nil, errors.New("fake TCX handle is closed")
	}
	state := handle.kernel.links[handle.id]
	if state == nil {
		return nil, errors.New("fake TCX link is missing")
	}
	return state, nil
}

func (handle *fakeExactTCXHandle) Identity() (exactTCXLinkIdentity, error) {
	handle.kernel.events = append(handle.kernel.events, "identity")
	state, err := handle.state()
	if err != nil {
		return exactTCXLinkIdentity{}, err
	}
	return state.identity, nil
}

func (handle *fakeExactTCXHandle) Pin(path string) error {
	handle.kernel.events = append(handle.kernel.events, "pin")
	state, err := handle.state()
	if err != nil {
		return err
	}
	if _, exists := handle.kernel.pins[path]; exists {
		return unix.EEXIST
	}
	if handle.kernel.pinErr != nil {
		return handle.kernel.pinErr
	}
	if handle.kernel.materializePins {
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		if err := file.Close(); err != nil {
			return err
		}
	}
	handle.kernel.pins[path] = handle.id
	handle.pinnedPath = path
	state.pins++
	return nil
}

func (handle *fakeExactTCXHandle) CompareUpdate(update exactTCXLinkUpdate) error {
	handle.kernel.events = append(handle.kernel.events, "compare-update")
	state, err := handle.state()
	if err != nil {
		return err
	}
	if update.New.id == 0 || update.Old.id == 0 || update.New.id == update.Old.id {
		return errors.New("fake TCX compare-update requires explicit distinct old/new programs")
	}
	if update.Flags != unix.BPF_F_REPLACE {
		return fmt.Errorf("fake TCX compare-update flags %#x, want BPF_F_REPLACE", update.Flags)
	}
	captured := update
	handle.kernel.lastUpdate = &captured
	if handle.kernel.beforeCompareUpdate != nil {
		handle.kernel.beforeCompareUpdate(handle.kernel, handle.id)
	}
	if state.identity.ProgramID != update.Old.id {
		return unix.ESTALE
	}
	state.identity.ProgramID = update.New.id
	slot := fakeExactTCXSlot{ifindex: state.identity.IfIndex, attach: state.identity.Attach}
	handle.kernel.revs[slot] = handle.kernel.revision(slot) + 1
	return nil
}

func (handle *fakeExactTCXHandle) Detach() error {
	handle.kernel.events = append(handle.kernel.events, fmt.Sprintf("detach:%d", handle.id))
	state, err := handle.state()
	if err != nil {
		return err
	}
	if injected := popExactTCXError(handle.kernel.detachErrs, handle.id); injected != nil {
		return injected
	}
	slot := fakeExactTCXSlot{ifindex: state.identity.IfIndex, attach: state.identity.Attach}
	state.attached = false
	state.identity.IfIndex = 0
	handle.kernel.revs[slot] = handle.kernel.revision(slot) + 1
	return nil
}

func (handle *fakeExactTCXHandle) Unpin() error {
	handle.kernel.events = append(handle.kernel.events, fmt.Sprintf("unpin:%d", handle.id))
	state, err := handle.state()
	if err != nil {
		return err
	}
	if injected := popExactTCXError(handle.kernel.unpinErrs, handle.id); injected != nil {
		return injected
	}
	if handle.pinnedPath == "" || handle.kernel.pins[handle.pinnedPath] != handle.id {
		return unix.ENOENT
	}
	if handle.kernel.materializePins {
		if err := os.Remove(handle.pinnedPath); err != nil {
			return err
		}
	}
	delete(handle.kernel.pins, handle.pinnedPath)
	handle.pinnedPath = ""
	state.pins--
	return nil
}

func (handle *fakeExactTCXHandle) Close() error {
	handle.kernel.events = append(handle.kernel.events, fmt.Sprintf("close:%d", handle.id))
	if handle.closed {
		return nil
	}
	state, err := handle.state()
	if err != nil {
		return err
	}
	if injected := popExactTCXError(handle.kernel.closeErrs, handle.id); injected != nil {
		return injected
	}
	handle.closed = true
	state.fdRefs--
	if state.fdRefs == 0 && state.pins == 0 {
		slot := fakeExactTCXSlot{ifindex: state.identity.IfIndex, attach: state.identity.Attach}
		state.attached = false
		if state.identity.IfIndex != 0 {
			state.identity.IfIndex = 0
			handle.kernel.revs[slot] = handle.kernel.revision(slot) + 1
		}
	}
	return nil
}

func popExactTCXError(byID map[uint32][]error, id uint32) error {
	errs := byID[id]
	if len(errs) == 0 {
		return nil
	}
	err := errs[0]
	byID[id] = errs[1:]
	return err
}

type fakeExactTCXJournal struct {
	events             *[]string
	intent             *exactTCXJournalIntent
	active             *exactTCXBinding
	persistIntentErr   error
	persistIdentityErr error
}

func (journal *fakeExactTCXJournal) callbacks() exactTCXJournal {
	return exactTCXJournal{
		persistIntent: func(intent exactTCXJournalIntent) error {
			*journal.events = append(*journal.events, "intent")
			cloned := cloneExactTCXIntent(intent)
			journal.intent = &cloned
			return journal.persistIntentErr
		},
		persistIdentity: func(binding exactTCXBinding, _ exactTCXJournalIntent) error {
			*journal.events = append(*journal.events, "journal-identity")
			value := binding
			journal.active = &value
			return journal.persistIdentityErr
		},
	}
}

func cloneExactTCXIntent(intent exactTCXJournalIntent) exactTCXJournalIntent {
	cloned := intent
	if intent.Active != nil {
		active := *intent.Active
		cloned.Active = &active
	}
	return cloned
}

func testExactTCXBinding(ifindex int, direction exactTCXDirection, programID uint32) exactTCXBinding {
	attach, err := exactTCXAttachType(direction)
	if err != nil {
		panic(err)
	}
	return exactTCXBinding{
		Backend: exactTCXBackend, IfIndex: ifindex, Direction: direction, AttachType: uint32(attach),
		PinName: exactTCXPinName(ifindex, direction), ProgramID: programID,
	}
}

func stageTestExactTCX(
	t *testing.T,
	kernel *fakeExactTCXKernel,
	binding exactTCXBinding,
	journal *fakeExactTCXJournal,
) (*exactTCXAttachment, string) {
	t.Helper()
	pinPath := "/sys/fs/bpf/wg-mix-ebpf-test/" + binding.PinName
	owner, err := stageExactTCXAttachment(
		t.Context(), binding, pinPath, exactTCXProgram{id: binding.ProgramID},
		journal.callbacks(), kernel.runtime(),
	)
	if err != nil {
		t.Fatalf("stage exact TCX: %v", err)
	}
	return owner, pinPath
}

func loadTestExactTCX(
	binding exactTCXBinding,
	pinPath string,
	runtime exactTCXRuntime,
) (*exactTCXAttachment, error) {
	owner, observed, err := observePinnedExactTCXAttachment(
		binding, pinPath, []uint32{binding.ProgramID}, runtime,
	)
	if err != nil {
		return nil, err
	}
	if !observed.Attached {
		return nil, errors.Join(errors.New("test exact TCX link is detached"), owner.Release())
	}
	owner.committed = true
	return owner, nil
}

func TestExactTCXStagePersistsIntentBeforeKernelMutation(t *testing.T) {
	kernel := newFakeExactTCXKernel()
	journal := &fakeExactTCXJournal{events: &kernel.events}
	binding := testExactTCXBinding(11, exactTCXIngress, 41)
	owner, pinPath := stageTestExactTCX(t, kernel, binding, journal)

	want := []string{
		"query", "intent", "attach", "identity",
		"journal-identity", "pin", "journal-identity",
	}
	if !slices.Equal(kernel.events, want) {
		t.Fatalf("events=%v want=%v", kernel.events, want)
	}
	if journal.intent == nil || journal.intent.Desired.LinkID != 0 {
		t.Fatalf("attach intent=%+v", journal.intent)
	}
	if journal.active == nil || journal.active.LinkID == 0 || journal.active.PinPending {
		t.Fatalf("active binding=%+v", journal.active)
	}
	linkID := journal.active.LinkID
	if kernel.pins[pinPath] != linkID || !kernel.links[linkID].attached {
		t.Fatalf("pin=%d link=%+v", kernel.pins[pinPath], kernel.links[linkID])
	}
	if err := owner.Release(); err != nil {
		t.Fatal(err)
	}
	if !kernel.links[linkID].attached || kernel.links[linkID].fdRefs != 0 {
		t.Fatalf("release broke persistent link: %+v", kernel.links[linkID])
	}

	restarted, err := loadTestExactTCX(*journal.active, pinPath, kernel.runtime())
	if err != nil {
		t.Fatalf("load after restart: %v", err)
	}
	if restarted.binding != *journal.active {
		t.Fatalf("restarted binding=%+v want=%+v", restarted.binding, *journal.active)
	}
	if err := restarted.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestExactTCXAttachRevisionFenceRejectsConcurrentForeignMutation(t *testing.T) {
	kernel := newFakeExactTCXKernel()
	kernel.beforeAttach = func(kernel *fakeExactTCXKernel, slot fakeExactTCXSlot) {
		kernel.beforeAttach = nil
		kernel.addLink(slot.ifindex, slot.attach, 999)
	}
	journal := &fakeExactTCXJournal{events: &kernel.events}
	binding := testExactTCXBinding(11, exactTCXEgress, 42)
	owner, err := stageExactTCXAttachment(
		t.Context(), binding,
		"/sys/fs/bpf/wg-mix-ebpf-test/"+binding.PinName,
		exactTCXProgram{id: 42}, journal.callbacks(), kernel.runtime(),
	)
	if owner != nil || !errors.Is(err, unix.ESTALE) {
		t.Fatalf("owner=%#v error=%v", owner, err)
	}
	if journal.intent == nil || journal.active != nil {
		t.Fatalf("intent=%+v active=%+v", journal.intent, journal.active)
	}
}

func TestExactTCXAttachRejectsIncompleteQueryBeforeIntent(t *testing.T) {
	kernel := newFakeExactTCXKernel()
	runtime := kernel.runtime()
	runtime.query = func(int, ebpf.AttachType) (exactTCXQuery, error) {
		kernel.events = append(kernel.events, "query")
		return exactTCXQuery{
			Revision: 1,
			Programs: []exactTCXQueryProgram{{LinkID: 0, ProgramID: 999}},
		}, nil
	}
	journal := &fakeExactTCXJournal{events: &kernel.events}
	binding := testExactTCXBinding(11, exactTCXIngress, 43)
	owner, err := stageExactTCXAttachment(
		t.Context(), binding,
		"/sys/fs/bpf/wg-mix-ebpf-test/"+binding.PinName,
		exactTCXProgram{id: binding.ProgramID}, journal.callbacks(), runtime,
	)
	if owner != nil || err == nil || !strings.Contains(err.Error(), "incomplete exact identity") {
		t.Fatalf("owner=%#v error=%v", owner, err)
	}
	if journal.intent != nil || journal.active != nil {
		t.Fatalf("invalid query reached owner journal: intent=%+v active=%+v", journal.intent, journal.active)
	}
	if !slices.Equal(kernel.events, []string{"query"}) {
		t.Fatalf("invalid query events=%v", kernel.events)
	}
}

func TestExactTCXPinFailureRetiresJournaledUnpinnedLink(t *testing.T) {
	kernel := newFakeExactTCXKernel()
	kernel.pinErr = errors.New("injected pin failure")
	journal := &fakeExactTCXJournal{events: &kernel.events}
	binding := testExactTCXBinding(11, exactTCXEgress, 44)
	owner, err := stageExactTCXAttachment(
		t.Context(), binding,
		"/sys/fs/bpf/wg-mix-ebpf-test/"+binding.PinName,
		exactTCXProgram{id: binding.ProgramID}, journal.callbacks(), kernel.runtime(),
	)
	if owner != nil || !errors.Is(err, kernel.pinErr) {
		t.Fatalf("owner=%#v error=%v", owner, err)
	}
	link := kernel.links[kernel.nextID]
	if link == nil || link.attached || link.fdRefs != 0 || link.pins != 0 {
		t.Fatalf("failed unpinned link was not closed exactly: %+v", link)
	}
	if journal.intent == nil || journal.active == nil ||
		journal.active.LinkID != kernel.nextID || !journal.active.PinPending {
		t.Fatalf("pin failure journal intent=%+v active=%+v", journal.intent, journal.active)
	}
	wantTail := []string{
		"pin",
		fmt.Sprintf("detach:%d", kernel.nextID),
		fmt.Sprintf("close:%d", kernel.nextID),
		"query",
	}
	if !slices.Equal(kernel.events[len(kernel.events)-len(wantTail):], wantTail) {
		t.Fatalf("pin failure events=%v want tail=%v", kernel.events, wantTail)
	}
}

func TestExactTCXPinDetachCloseFailureRetainsOwnerAndBlocksDuplicate(t *testing.T) {
	kernel := newFakeExactTCXKernel()
	binding := testExactTCXBinding(111, exactTCXIngress, 45)
	pinPath := "/sys/fs/bpf/wg-mix-ebpf-retained/" + binding.PinName
	pinErr := errors.New("injected pin failure")
	detachOne := errors.New("injected first detach failure")
	detachTwo := errors.New("injected retained detach failure")
	closeOne := errors.New("injected first close failure")
	closeTwo := errors.New("injected retained close failure")
	kernel.pinErr = pinErr
	failedID := kernel.nextID + 1
	kernel.detachErrs[failedID] = []error{detachOne, detachTwo}
	kernel.closeErrs[failedID] = []error{closeOne, closeTwo}
	journal := &fakeExactTCXJournal{events: &kernel.events}

	owner, err := stageExactTCXAttachment(
		t.Context(), binding, pinPath,
		exactTCXProgram{id: binding.ProgramID}, journal.callbacks(), kernel.runtime(),
	)
	if owner != nil || !errors.Is(err, pinErr) ||
		!errors.Is(err, detachOne) || !errors.Is(err, closeOne) {
		t.Fatalf("first failed stage owner=%#v error=%v", owner, err)
	}
	if state := kernel.links[failedID]; state == nil || !state.attached || state.fdRefs != 1 {
		t.Fatalf("failed link was not retained exactly: %+v", state)
	}

	kernel.pinErr = nil
	owner, err = stageExactTCXAttachment(
		t.Context(), binding, pinPath,
		exactTCXProgram{id: binding.ProgramID}, journal.callbacks(), kernel.runtime(),
	)
	if owner != nil || !errors.Is(err, detachTwo) || !errors.Is(err, closeTwo) {
		t.Fatalf("retained retry owner=%#v error=%v", owner, err)
	}
	if len(kernel.links) != 1 || !kernel.links[failedID].attached {
		t.Fatalf("retry created a duplicate while retained owner was live: %+v", kernel.links)
	}

	owner, err = stageExactTCXAttachment(
		t.Context(), binding, pinPath,
		exactTCXProgram{id: binding.ProgramID}, journal.callbacks(), kernel.runtime(),
	)
	if err != nil || owner == nil {
		t.Fatalf("settled retry owner=%#v error=%v", owner, err)
	}
	if kernel.links[failedID].attached || owner.binding.LinkID == failedID ||
		!kernel.links[owner.binding.LinkID].attached {
		t.Fatalf("old/new retained link states: old=%+v new=%+v", kernel.links[failedID], kernel.links[owner.binding.LinkID])
	}
	if err := owner.Rollback(); err != nil {
		t.Fatal(err)
	}
}

func TestExactTCXRollbackPreservesConcurrentForeignLink(t *testing.T) {
	kernel := newFakeExactTCXKernel()
	journal := &fakeExactTCXJournal{events: &kernel.events}
	binding := testExactTCXBinding(12, exactTCXIngress, 51)
	owner, _ := stageTestExactTCX(t, kernel, binding, journal)
	ownedID := owner.binding.LinkID

	// This is the race classic slot-addressed deletion cannot survive: another writer
	// installs a different program in the same logical direction after the
	// owner's last inspection. TCX gives each attachment a distinct link ID.
	foreignID := kernel.addLink(12, ebpf.AttachTCXIngress, 999)
	if err := owner.Rollback(); err != nil {
		t.Fatal(err)
	}
	if kernel.links[ownedID].attached {
		t.Fatal("exact owned link remains attached")
	}
	if !kernel.links[foreignID].attached {
		t.Fatal("exact rollback detached the concurrent foreign link")
	}
	if slices.Contains(kernel.events, "qdisc-delete") {
		t.Fatal("TCX rollback must not touch clsact")
	}
}

func TestExactTCXRollbackRetriesOnlyUnfinishedExactOperations(t *testing.T) {
	kernel := newFakeExactTCXKernel()
	journal := &fakeExactTCXJournal{events: &kernel.events}
	owner, _ := stageTestExactTCX(
		t, kernel, testExactTCXBinding(13, exactTCXEgress, 61), journal,
	)
	id := owner.binding.LinkID
	detachErr := errors.New("injected exact detach failure")
	unpinErr := errors.New("injected exact unpin failure")
	kernel.detachErrs[id] = []error{detachErr}
	kernel.unpinErrs[id] = []error{unpinErr}

	if err := owner.Rollback(); !errors.Is(err, detachErr) {
		t.Fatalf("first rollback=%v", err)
	}
	if !owner.pinned || owner.detached || !kernel.links[id].attached {
		t.Fatalf("owner after detach failure=%+v link=%+v", owner, kernel.links[id])
	}
	if err := owner.Rollback(); !errors.Is(err, unpinErr) {
		t.Fatalf("second rollback=%v", err)
	}
	if !owner.pinned || !owner.detached || kernel.links[id].attached {
		t.Fatalf("owner after unpin failure=%+v link=%+v", owner, kernel.links[id])
	}
	if err := owner.Rollback(); err != nil {
		t.Fatalf("third rollback=%v", err)
	}
	wantTail := []string{
		fmt.Sprintf("detach:%d", id),
		fmt.Sprintf("detach:%d", id),
		fmt.Sprintf("unpin:%d", id),
		fmt.Sprintf("unpin:%d", id),
		fmt.Sprintf("close:%d", id),
	}
	if !slices.Equal(kernel.events[len(kernel.events)-len(wantTail):], wantTail) {
		t.Fatalf("event tail=%v want=%v", kernel.events, wantTail)
	}
}

func TestExactTCXCompareUpdateUsesKernelOldProgramCAS(t *testing.T) {
	kernel := newFakeExactTCXKernel()
	journal := &fakeExactTCXJournal{events: &kernel.events}
	owner, _ := stageTestExactTCX(
		t, kernel, testExactTCXBinding(14, exactTCXIngress, 71), journal,
	)
	id := owner.binding.LinkID
	kernel.beforeCompareUpdate = func(kernel *fakeExactTCXKernel, linkID uint32) {
		kernel.beforeCompareUpdate = nil
		kernel.links[linkID].identity.ProgramID = 999
	}

	updateJournal := &fakeExactTCXJournal{events: &kernel.events}
	err := owner.CompareUpdateWithOld(
		exactTCXProgram{id: 71}, exactTCXProgram{id: 72}, updateJournal.callbacks(),
	)
	if !errors.Is(err, unix.ESTALE) {
		t.Fatalf("compare update error=%v", err)
	}
	if kernel.links[id].identity.ProgramID != 999 {
		t.Fatalf("CAS overwrote raced program: %+v", kernel.links[id].identity)
	}
	if updateJournal.intent == nil || updateJournal.active != nil {
		t.Fatalf("intent=%+v active=%+v", updateJournal.intent, updateJournal.active)
	}
	if kernel.lastUpdate == nil ||
		kernel.lastUpdate.Old.id != 71 ||
		kernel.lastUpdate.New.id != 72 ||
		kernel.lastUpdate.Flags != unix.BPF_F_REPLACE {
		t.Fatalf("explicit compare-update arguments=%+v", kernel.lastUpdate)
	}
	if owner.binding.ProgramID != 71 {
		t.Fatalf("failed CAS advanced process owner binding: %+v", owner.binding)
	}
}

func TestExactTCXUpdateRecoveryPublishesKernelCompletedCAS(t *testing.T) {
	kernel := newFakeExactTCXKernel()
	journal := &fakeExactTCXJournal{events: &kernel.events}
	owner, pinPath := stageTestExactTCX(
		t, kernel, testExactTCXBinding(15, exactTCXEgress, 81), journal,
	)
	updateJournal := &fakeExactTCXJournal{
		events: &kernel.events, persistIdentityErr: errors.New("injected owner persist failure"),
	}
	err := owner.CompareUpdateWithOld(
		exactTCXProgram{id: 81}, exactTCXProgram{id: 82}, updateJournal.callbacks(),
	)
	if err == nil || updateJournal.intent == nil {
		t.Fatalf("update error=%v intent=%+v", err, updateJournal.intent)
	}
	if owner.binding.ProgramID != 82 {
		t.Fatalf("kernel-completed owner binding=%+v", owner.binding)
	}
	if err := owner.Release(); err != nil {
		t.Fatal(err)
	}
	restarted, err := loadTestExactTCX(owner.binding, pinPath, kernel.runtime())
	if err != nil {
		t.Fatalf("load completed update: %v", err)
	}
	if err := restarted.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestExactTCXLoadRejectsReplacedPinWithoutMutatingForeignLink(t *testing.T) {
	kernel := newFakeExactTCXKernel()
	journal := &fakeExactTCXJournal{events: &kernel.events}
	owner, pinPath := stageTestExactTCX(
		t, kernel, testExactTCXBinding(16, exactTCXIngress, 91), journal,
	)
	ownedBinding := owner.binding
	if err := owner.Release(); err != nil {
		t.Fatal(err)
	}
	foreignID := kernel.addLink(16, ebpf.AttachTCXIngress, 999)
	oldID := kernel.pins[pinPath]
	kernel.links[oldID].pins--
	kernel.pins[pinPath] = foreignID
	kernel.links[foreignID].pins++

	loaded, err := loadTestExactTCX(ownedBinding, pinPath, kernel.runtime())
	if loaded != nil || err == nil {
		t.Fatalf("loaded=%#v error=%v", loaded, err)
	}
	if !kernel.links[foreignID].attached || kernel.pins[pinPath] != foreignID {
		t.Fatalf("foreign link was mutated: link=%+v pin=%d", kernel.links[foreignID], kernel.pins[pinPath])
	}
}

func TestExactTCXUnsupportedPreflightLeavesNoDurableIntent(t *testing.T) {
	kernel := newFakeExactTCXKernel()
	kernel.queryErr = ciliumlink.ErrNotSupported
	journal := &fakeExactTCXJournal{events: &kernel.events}
	binding := testExactTCXBinding(19, exactTCXIngress, 121)
	owner, err := stageExactTCXAttachment(
		t.Context(), binding,
		"/sys/fs/bpf/wg-mix-ebpf-test/"+binding.PinName,
		exactTCXProgram{id: 121}, journal.callbacks(), kernel.runtime(),
	)
	if owner != nil || !errors.Is(err, ciliumlink.ErrNotSupported) {
		t.Fatalf("owner=%#v error=%v", owner, err)
	}
	if journal.intent != nil || journal.active != nil || len(kernel.links) != 0 {
		t.Fatalf("unsupported preflight wrote state: intent=%+v active=%+v links=%v", journal.intent, journal.active, kernel.links)
	}
	if !slices.Equal(kernel.events, []string{"query"}) {
		t.Fatalf("events=%v", kernel.events)
	}
}

func TestExactTCXStageFailsBeforeKernelWriteWithoutDurableJournal(t *testing.T) {
	kernel := newFakeExactTCXKernel()
	binding := testExactTCXBinding(18, exactTCXIngress, 111)
	owner, err := stageExactTCXAttachment(
		t.Context(), binding,
		"/sys/fs/bpf/wg-mix-ebpf-test/"+binding.PinName,
		exactTCXProgram{id: 111}, exactTCXJournal{}, kernel.runtime(),
	)
	if owner != nil || err == nil {
		t.Fatalf("owner=%#v error=%v", owner, err)
	}
	if len(kernel.events) != 0 || len(kernel.links) != 0 {
		t.Fatalf("kernel changed before journal: events=%v links=%v", kernel.events, kernel.links)
	}
}
