//go:build linux

package dataplane

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/syx0310/wg-mix-ebpf/internal/control"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type fakeTCProgramRef struct {
	fd     int
	closed bool
}

func (program *fakeTCProgramRef) FD() int {
	if program.closed {
		return -1
	}
	return program.fd
}

func (program *fakeTCProgramRef) Close() error {
	program.closed = true
	return nil
}

type fakeTCFilterKey struct {
	ifindex int
	parent  uint32
}

type fakeTCKernel struct {
	links          map[int]netlink.Link
	qdiscs         map[int][]netlink.Qdisc
	filters        map[fakeTCFilterKey][]netlink.Filter
	programFDs     map[uint32]int
	programIDs     map[int]uint32
	retained       []*fakeTCProgramRef
	writes         []string
	failWrite      int
	qdiscDeletes   int
	filterListHook func(fakeTCFilterKey, int)
	filterLists    map[fakeTCFilterKey]int
}

func newFakeTCKernel(ifindexes ...int) *fakeTCKernel {
	kernel := &fakeTCKernel{
		links:       make(map[int]netlink.Link),
		qdiscs:      make(map[int][]netlink.Qdisc),
		filters:     make(map[fakeTCFilterKey][]netlink.Filter),
		programFDs:  make(map[uint32]int),
		programIDs:  make(map[int]uint32),
		filterLists: make(map[fakeTCFilterKey]int),
	}
	for _, ifindex := range ifindexes {
		kernel.links[ifindex] = &netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{
				Index: ifindex,
				Name:  fmt.Sprintf("eth%d", ifindex),
			},
		}
	}
	return kernel
}

func (kernel *fakeTCKernel) runtime() tcRuntime {
	return tcRuntime{
		linkByIndex: func(ifindex int) (netlink.Link, error) {
			link, ok := kernel.links[ifindex]
			if !ok {
				return nil, fmt.Errorf("missing link %d", ifindex)
			}
			return link, nil
		},
		qdiscList: func(link netlink.Link) ([]netlink.Qdisc, error) {
			return slices.Clone(kernel.qdiscs[link.Attrs().Index]), nil
		},
		qdiscAdd: func(qdisc netlink.Qdisc) error {
			if err := kernel.recordWrite("qdisc-add"); err != nil {
				return err
			}
			ifindex := qdisc.Attrs().LinkIndex
			kernel.qdiscs[ifindex] = append(kernel.qdiscs[ifindex], qdisc)
			return nil
		},
		filterList: func(link netlink.Link, parent uint32) ([]netlink.Filter, error) {
			key := fakeTCFilterKey{ifindex: link.Attrs().Index, parent: parent}
			kernel.filterLists[key]++
			if kernel.filterListHook != nil {
				kernel.filterListHook(key, kernel.filterLists[key])
			}
			filters := kernel.filters[key]
			out := make([]netlink.Filter, 0, len(filters))
			for _, filter := range filters {
				out = append(out, cloneFakeTCFilter(filter))
			}
			return out, nil
		},
		filterAdd: func(filter netlink.Filter) error {
			if err := kernel.recordWrite("filter-add"); err != nil {
				return err
			}
			key := fakeTCFilterKey{
				ifindex: filter.Attrs().LinkIndex,
				parent:  filter.Attrs().Parent,
			}
			for _, existing := range kernel.filters[key] {
				if existing.Attrs().Handle == filter.Attrs().Handle {
					return errors.New("file exists")
				}
			}
			kernel.filters[key] = append(
				kernel.filters[key],
				kernel.materializeFilter(filter),
			)
			return nil
		},
		filterReplace: func(filter netlink.Filter) error {
			if err := kernel.recordWrite("filter-replace"); err != nil {
				return err
			}
			key := fakeTCFilterKey{
				ifindex: filter.Attrs().LinkIndex,
				parent:  filter.Attrs().Parent,
			}
			materialized := kernel.materializeFilter(filter)
			for index, existing := range kernel.filters[key] {
				if existing.Attrs().Handle == filter.Attrs().Handle {
					kernel.filters[key][index] = materialized
					return nil
				}
			}
			kernel.filters[key] = append(kernel.filters[key], materialized)
			return nil
		},
		filterDelete: func(filter netlink.Filter) error {
			if err := kernel.recordWrite("filter-delete"); err != nil {
				return err
			}
			key := fakeTCFilterKey{
				ifindex: filter.Attrs().LinkIndex,
				parent:  filter.Attrs().Parent,
			}
			for index, existing := range kernel.filters[key] {
				if existing.Attrs().Handle != filter.Attrs().Handle {
					continue
				}
				kernel.filters[key] = append(
					kernel.filters[key][:index],
					kernel.filters[key][index+1:]...,
				)
				return nil
			}
			return errors.New("not found")
		},
		loadProgram: func(id uint32) (tcProgramRef, error) {
			fd, ok := kernel.programFDs[id]
			if !ok {
				return nil, fmt.Errorf("missing program ID %d", id)
			}
			program := &fakeTCProgramRef{fd: fd}
			kernel.retained = append(kernel.retained, program)
			return program, nil
		},
	}
}

func (kernel *fakeTCKernel) deleteQdisc(qdisc netlink.Qdisc) error {
	if err := kernel.recordWrite("qdisc-delete"); err != nil {
		return err
	}
	attrs := qdisc.Attrs()
	if attrs == nil {
		return errors.New("qdisc has no attributes")
	}
	qdiscs := kernel.qdiscs[attrs.LinkIndex]
	for index, existing := range qdiscs {
		if existing == nil || existing.Attrs() == nil ||
			existing.Type() != qdisc.Type() ||
			existing.Attrs().Handle != attrs.Handle ||
			existing.Attrs().Parent != attrs.Parent {
			continue
		}
		kernel.qdiscs[attrs.LinkIndex] = append(qdiscs[:index], qdiscs[index+1:]...)
		kernel.qdiscDeletes++
		// The real kernel destroys every child filter with a clsact qdisc.
		delete(kernel.filters, fakeTCFilterKey{
			ifindex: attrs.LinkIndex, parent: netlink.HANDLE_MIN_INGRESS,
		})
		delete(kernel.filters, fakeTCFilterKey{
			ifindex: attrs.LinkIndex, parent: netlink.HANDLE_MIN_EGRESS,
		})
		return nil
	}
	return errors.New("not found")
}

func (kernel *fakeTCKernel) recordWrite(action string) error {
	kernel.writes = append(kernel.writes, action)
	if kernel.failWrite != 0 && len(kernel.writes) == kernel.failWrite {
		return fmt.Errorf("injected %s failure", action)
	}
	return nil
}

func (kernel *fakeTCKernel) materializeFilter(filter netlink.Filter) netlink.Filter {
	cloned := cloneFakeTCFilter(filter).(*netlink.BpfFilter)
	id, ok := kernel.programIDs[cloned.Fd]
	if !ok {
		panic(fmt.Sprintf("fake kernel has no program ID for FD %d", cloned.Fd))
	}
	cloned.Id = int(id)
	return cloned
}

func (kernel *fakeTCKernel) addProgram(id uint32, fd int) {
	kernel.programFDs[id] = fd
	kernel.programIDs[fd] = id
}

func (kernel *fakeTCKernel) addClsact(ifindex int) {
	kernel.qdiscs[ifindex] = append(kernel.qdiscs[ifindex], canonicalClsact(ifindex))
}

func (kernel *fakeTCKernel) addManagedFilter(
	ifindex int,
	slot tcFilterSlot,
	programID uint32,
) {
	fd := kernel.programFDs[programID]
	filter := managedBpfFilter(ifindex, slot, fd).(*netlink.BpfFilter)
	filter.Id = int(programID)
	key := fakeTCFilterKey{ifindex: ifindex, parent: slot.parent}
	kernel.filters[key] = append(kernel.filters[key], filter)
}

func (kernel *fakeTCKernel) managedProgramID(
	t *testing.T,
	ifindex int,
	slot tcFilterSlot,
) uint32 {
	t.Helper()
	key := fakeTCFilterKey{ifindex: ifindex, parent: slot.parent}
	for _, filter := range kernel.filters[key] {
		bpfFilter, ok := filter.(*netlink.BpfFilter)
		if ok && bpfFilter.Name == slot.name && filter.Attrs().Handle == slot.handle {
			return uint32(bpfFilter.Id)
		}
	}
	return 0
}

func cloneFakeTCFilter(filter netlink.Filter) netlink.Filter {
	switch typed := filter.(type) {
	case *netlink.BpfFilter:
		cloned := *typed
		return &cloned
	case *netlink.GenericFilter:
		cloned := *typed
		return &cloned
	default:
		panic(fmt.Sprintf("unsupported fake filter type %T", filter))
	}
}

func testTCState(ifindexes ...int) *control.State {
	state := &control.State{}
	for _, ifindex := range ifindexes {
		state.Underlays = append(state.Underlays, control.UnderlayState{
			Name:     fmt.Sprintf("u%d", ifindex),
			IfIndex:  ifindex,
			Resolved: true,
		})
	}
	return state
}

func TestTCAttachTransactionCommitsAfterEveryDirection(t *testing.T) {
	kernel := newFakeTCKernel(11, 12)
	kernel.addProgram(101, 1001)
	kernel.addProgram(102, 1002)

	plan, err := prepareTCAttachPlan(
		testTCState(12, 11),
		tcProgramIdentity{fd: 1001, id: 101},
		tcProgramIdentity{fd: 1002, id: 102},
		kernel.runtime(),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Close()

	committedAfterWrites := 0
	if err := plan.Execute(func() error {
		committedAfterWrites = len(kernel.writes)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if committedAfterWrites != 6 {
		t.Fatalf("commit ran after %d writes, want 2 clsact + 4 filter writes", committedAfterWrites)
	}
	for _, ifindex := range []int{11, 12} {
		for _, slot := range canonicalTCFilterSlots() {
			want := uint32(101)
			if slot.parent == netlink.HANDLE_MIN_EGRESS {
				want = 102
			}
			if got := kernel.managedProgramID(t, ifindex, slot); got != want {
				t.Fatalf("ifindex %d %s program = %d, want %d", ifindex, slot.name, got, want)
			}
		}
	}
}

func TestTCAttachRetainedStageRestoresPriorFiltersOnClose(t *testing.T) {
	kernel := newFakeTCKernel(11)
	for id, fd := range map[uint32]int{
		21: 201,
		22: 202,
		31: 301,
		32: 302,
	} {
		kernel.addProgram(id, fd)
	}
	kernel.addClsact(11)
	kernel.addManagedFilter(11, canonicalTCFilterSlots()[0], 21)
	kernel.addManagedFilter(11, canonicalTCFilterSlots()[1], 22)
	plan, err := prepareTCAttachPlan(
		testTCState(11),
		tcProgramIdentity{fd: 301, id: 31},
		tcProgramIdentity{fd: 302, id: 32},
		kernel.runtime(),
	)
	if err != nil {
		t.Fatal(err)
	}
	stage, err := plan.ExecuteRetained(func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if got := kernel.managedProgramID(t, 11, canonicalTCFilterSlots()[0]); got != 31 {
		t.Fatalf("active ingress program = %d, want 31", got)
	}
	if got := kernel.managedProgramID(t, 11, canonicalTCFilterSlots()[1]); got != 32 {
		t.Fatalf("active egress program = %d, want 32", got)
	}
	if err := plan.Close(); err == nil || !strings.Contains(err.Error(), "retained stage") {
		t.Fatalf("plan Close while retained = %v", err)
	}
	if err := stage.Close(); err != nil {
		t.Fatalf("stage Close: %v", err)
	}
	if err := stage.Close(); err != nil {
		t.Fatalf("repeated stage Close: %v", err)
	}
	if got := kernel.managedProgramID(t, 11, canonicalTCFilterSlots()[0]); got != 21 {
		t.Fatalf("restored ingress program = %d, want 21", got)
	}
	if got := kernel.managedProgramID(t, 11, canonicalTCFilterSlots()[1]); got != 22 {
		t.Fatalf("restored egress program = %d, want 22", got)
	}
	for index, retained := range kernel.retained {
		if !retained.closed {
			t.Fatalf("retained prior program %d was not closed", index)
		}
	}
}

func TestTCAttachRetainedStageRemovesFreshFiltersAndPreservesClsact(t *testing.T) {
	kernel := newFakeTCKernel(11)
	kernel.addProgram(31, 301)
	kernel.addProgram(32, 302)
	plan, err := prepareTCAttachPlan(
		testTCState(11),
		tcProgramIdentity{fd: 301, id: 31},
		tcProgramIdentity{fd: 302, id: 32},
		kernel.runtime(),
	)
	if err != nil {
		t.Fatal(err)
	}
	stage, err := plan.ExecuteRetained(func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := stage.Close(); err != nil {
		t.Fatal(err)
	}
	for _, slot := range canonicalTCFilterSlots() {
		if got := kernel.managedProgramID(t, 11, slot); got != 0 {
			t.Fatalf("fresh %s program remains after stage Close: %d", slot.name, got)
		}
	}
	if got := len(kernel.qdiscs[11]); got != 1 || kernel.qdiscDeletes != 0 {
		t.Fatalf("shared clsact count=%d delete calls=%d", got, kernel.qdiscDeletes)
	}
}

func TestClassicFreshTCAttachRejectsUnrecordedReservedSlot(t *testing.T) {
	kernel := newFakeTCKernel(11)
	for id, fd := range map[uint32]int{21: 201, 31: 301, 32: 302} {
		kernel.addProgram(id, fd)
	}
	kernel.addClsact(11)
	kernel.addManagedFilter(11, canonicalTCFilterSlots()[0], 21)
	plan, err := prepareTCAttachPlan(
		testTCState(11),
		tcProgramIdentity{fd: 301, id: 31},
		tcProgramIdentity{fd: 302, id: 32},
		kernel.runtime(),
	)
	if err != nil {
		t.Fatal(err)
	}
	err = plan.ValidatePreviousBindings(nil, true)
	if err == nil || !strings.Contains(err.Error(), "pre-existing managed-looking") {
		t.Fatalf("validation error=%v", err)
	}
	if len(kernel.writes) != 0 {
		t.Fatalf("fresh ownership rejection performed writes: %v", kernel.writes)
	}
	if got := kernel.managedProgramID(t, 11, canonicalTCFilterSlots()[0]); got != 21 {
		t.Fatalf("foreign reserved slot changed to program %d", got)
	}
}

func TestTCAttachRetainedStagePreservesForeignReplacement(t *testing.T) {
	kernel := newFakeTCKernel(11)
	for id, fd := range map[uint32]int{21: 201, 22: 202, 31: 301, 32: 302, 99: 909} {
		kernel.addProgram(id, fd)
	}
	kernel.addClsact(11)
	kernel.addManagedFilter(11, canonicalTCFilterSlots()[0], 21)
	kernel.addManagedFilter(11, canonicalTCFilterSlots()[1], 22)
	plan, err := prepareTCAttachPlan(
		testTCState(11),
		tcProgramIdentity{fd: 301, id: 31},
		tcProgramIdentity{fd: 302, id: 32},
		kernel.runtime(),
	)
	if err != nil {
		t.Fatal(err)
	}
	stage, err := plan.ExecuteRetained(func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	ingress := canonicalTCFilterSlots()[0]
	key := fakeTCFilterKey{ifindex: 11, parent: ingress.parent}
	foreign := managedBpfFilter(11, ingress, 909).(*netlink.BpfFilter)
	foreign.Id = 99
	kernel.filters[key] = []netlink.Filter{foreign}
	if err := stage.Close(); err == nil || !strings.Contains(err.Error(), "refuse rollback") {
		t.Fatalf("stage Close error = %v", err)
	}
	if got := kernel.managedProgramID(t, 11, ingress); got != 99 {
		t.Fatalf("foreign replacement program = %d, want preserved 99", got)
	}
	if got := kernel.managedProgramID(t, 11, canonicalTCFilterSlots()[1]); got != 22 {
		t.Fatalf("uncontended egress program = %d, want restored 22", got)
	}
}

func TestTCAttachTransactionRollsBackPartialMultiUnderlayFailure(t *testing.T) {
	kernel := newFakeTCKernel(11, 12)
	for id, fd := range map[uint32]int{
		21: 201,
		22: 202,
		31: 301,
		32: 302,
	} {
		kernel.addProgram(id, fd)
	}
	for _, ifindex := range []int{11, 12} {
		kernel.addClsact(ifindex)
		kernel.addManagedFilter(ifindex, canonicalTCFilterSlots()[0], 21)
		kernel.addManagedFilter(ifindex, canonicalTCFilterSlots()[1], 22)
	}

	plan, err := prepareTCAttachPlan(
		testTCState(11, 12),
		tcProgramIdentity{fd: 301, id: 31},
		tcProgramIdentity{fd: 302, id: 32},
		kernel.runtime(),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Close()
	kernel.failWrite = 4
	commitCalls := 0
	err = plan.Execute(func() error {
		commitCalls++
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "injected") {
		t.Fatalf("attach error = %v, want injected failure", err)
	}
	if commitCalls != 0 {
		t.Fatalf("commit calls = %d, want 0", commitCalls)
	}
	for _, ifindex := range []int{11, 12} {
		if got := kernel.managedProgramID(t, ifindex, canonicalTCFilterSlots()[0]); got != 21 {
			t.Fatalf("ifindex %d ingress program = %d, want restored 21", ifindex, got)
		}
		if got := kernel.managedProgramID(t, ifindex, canonicalTCFilterSlots()[1]); got != 22 {
			t.Fatalf("ifindex %d egress program = %d, want restored 22", ifindex, got)
		}
	}
}

func TestTCAttachTransactionRollsBackWhenCommitFails(t *testing.T) {
	kernel := newFakeTCKernel(11)
	kernel.addProgram(31, 301)
	kernel.addProgram(32, 302)
	plan, err := prepareTCAttachPlan(
		testTCState(11),
		tcProgramIdentity{fd: 301, id: 31},
		tcProgramIdentity{fd: 302, id: 32},
		kernel.runtime(),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Close()

	err = plan.Execute(func() error { return errors.New("commit failed") })
	if err == nil || !strings.Contains(err.Error(), "commit failed") {
		t.Fatalf("attach error = %v, want commit failure", err)
	}
	for _, slot := range canonicalTCFilterSlots() {
		if got := kernel.managedProgramID(t, 11, slot); got != 0 {
			t.Fatalf("%s program remains after rollback: %d", slot.name, got)
		}
	}
	if len(kernel.qdiscs[11]) != 1 || kernel.qdiscDeletes != 0 {
		t.Fatalf("clsact count=%d delete calls=%d", len(kernel.qdiscs[11]), kernel.qdiscDeletes)
	}
}

func TestClassicTCPartialFailurePreservesEmptyClsactScaffold(t *testing.T) {
	kernel := newFakeTCKernel(11)
	kernel.addProgram(31, 301)
	kernel.addProgram(32, 302)
	plan, err := prepareTCAttachPlan(
		testTCState(11),
		tcProgramIdentity{fd: 301, id: 31},
		tcProgramIdentity{fd: 302, id: 32},
		kernel.runtime(),
	)
	if err != nil {
		t.Fatal(err)
	}
	kernel.failWrite = 2 // clsact succeeds; the first filter mutation fails.
	if err := plan.ValidatePreviousBindings(nil, true); err != nil {
		t.Fatal(err)
	}
	stage, err := plan.ExecuteRetained(func() error { return nil })
	if stage == nil || err == nil || !strings.Contains(err.Error(), "injected filter-add failure") {
		t.Fatalf("stage=%#v error=%v", stage, err)
	}
	if err := stage.Close(); err != nil {
		t.Fatalf("rollback partial attachment: %v", err)
	}
	if got := len(kernel.qdiscs[11]); got != 1 || kernel.qdiscDeletes != 0 {
		t.Fatalf("partial scaffold count=%d delete calls=%d", got, kernel.qdiscDeletes)
	}
}

func TestFakeTCQdiscDeleteModelsKernelFilterCascade(t *testing.T) {
	kernel := newFakeTCKernel(11)
	kernel.addProgram(31, 301)
	kernel.addProgram(32, 302)
	kernel.addClsact(11)
	for _, slot := range canonicalTCFilterSlots() {
		programID := uint32(31)
		if slot.parent == netlink.HANDLE_MIN_EGRESS {
			programID = 32
		}
		kernel.addManagedFilter(11, slot, programID)
	}
	if err := kernel.deleteQdisc(canonicalClsact(11)); err != nil {
		t.Fatal(err)
	}
	if len(kernel.qdiscs[11]) != 0 || len(kernel.filters) != 0 || kernel.qdiscDeletes != 1 {
		t.Fatalf("qdiscs=%v filters=%v deletes=%d", kernel.qdiscs, kernel.filters, kernel.qdiscDeletes)
	}
}

func TestTCAttachRetainedStageNeverDeletesClsactWithConcurrentForeignFilter(t *testing.T) {
	kernel := newFakeTCKernel(11)
	kernel.addProgram(31, 301)
	kernel.addProgram(32, 302)
	plan, err := prepareTCAttachPlan(
		testTCState(11),
		tcProgramIdentity{fd: 301, id: 31},
		tcProgramIdentity{fd: 302, id: 32},
		kernel.runtime(),
	)
	if err != nil {
		t.Fatal(err)
	}
	stage, err := plan.ExecuteRetained(func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	key := fakeTCFilterKey{ifindex: 11, parent: netlink.HANDLE_MIN_INGRESS}
	kernel.filters[key] = append(kernel.filters[key], &netlink.GenericFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: 11,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    0x20001,
			Priority:  99,
			Protocol:  unix.ETH_P_ALL,
		},
		FilterType: "flower",
	})
	if err := stage.Close(); err != nil {
		t.Fatalf("stage Close: %v", err)
	}
	if got := len(kernel.qdiscs[11]); got != 1 || kernel.qdiscDeletes != 0 {
		t.Fatalf("shared clsact count=%d delete calls=%d", got, kernel.qdiscDeletes)
	}
	if got := len(kernel.filters[key]); got != 1 {
		t.Fatalf("foreign filter count=%d, want preserved one", got)
	}
}

func TestTCAttachRetainedStagePreservesChangedQdiscIdentity(t *testing.T) {
	kernel := newFakeTCKernel(11)
	kernel.addProgram(31, 301)
	kernel.addProgram(32, 302)
	plan, err := prepareTCAttachPlan(
		testTCState(11),
		tcProgramIdentity{fd: 301, id: 31},
		tcProgramIdentity{fd: 302, id: 32},
		kernel.runtime(),
	)
	if err != nil {
		t.Fatal(err)
	}
	stage, err := plan.ExecuteRetained(func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	kernel.qdiscs[11] = []netlink.Qdisc{&netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: 11,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "foreign",
	}}
	if err := stage.Close(); err != nil {
		t.Fatalf("stage Close error = %v", err)
	}
	if got := kernel.qdiscs[11][0].Type(); got != "foreign" {
		t.Fatalf("foreign qdisc identity changed to %q", got)
	}
	if kernel.qdiscDeletes != 0 {
		t.Fatalf("foreign qdisc delete calls=%d", kernel.qdiscDeletes)
	}
}

func TestTCAttachPreflightRejectsForeignAndDuplicateFiltersWithoutWrites(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*fakeTCKernel)
		want  string
	}{
		{
			name: "foreign handle collision",
			setup: func(kernel *fakeTCKernel) {
				slot := canonicalTCFilterSlots()[0]
				key := fakeTCFilterKey{ifindex: 11, parent: slot.parent}
				kernel.filters[key] = append(kernel.filters[key], &netlink.GenericFilter{
					FilterAttrs: netlink.FilterAttrs{
						LinkIndex: 11,
						Parent:    slot.parent,
						Handle:    slot.handle,
						Priority:  filterPriority,
						Protocol:  unix.ETH_P_ALL,
					},
					FilterType: "flower",
				})
			},
			want: "foreign filter",
		},
		{
			name: "foreign name collision",
			setup: func(kernel *fakeTCKernel) {
				slot := canonicalTCFilterSlots()[0]
				filter := managedBpfFilter(11, slot, 301).(*netlink.BpfFilter)
				filter.Handle = 0x20001
				filter.Id = 31
				key := fakeTCFilterKey{ifindex: 11, parent: slot.parent}
				kernel.filters[key] = append(kernel.filters[key], filter)
			},
			want: "foreign filter",
		},
		{
			name: "duplicate exact filter",
			setup: func(kernel *fakeTCKernel) {
				slot := canonicalTCFilterSlots()[0]
				kernel.addManagedFilter(11, slot, 31)
				kernel.addManagedFilter(11, slot, 31)
			},
			want: "duplicate managed filters",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kernel := newFakeTCKernel(11)
			kernel.addProgram(31, 301)
			kernel.addProgram(32, 302)
			tt.setup(kernel)
			plan, err := prepareTCAttachPlan(
				testTCState(11),
				tcProgramIdentity{fd: 301, id: 31},
				tcProgramIdentity{fd: 302, id: 32},
				kernel.runtime(),
			)
			if plan != nil {
				_ = plan.Close()
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("preflight error = %v, want %q", err, tt.want)
			}
			if len(kernel.writes) != 0 {
				t.Fatalf("preflight performed writes: %v", kernel.writes)
			}
		})
	}
}

func TestTCAttachPreflightRejectsDuplicateIfindex(t *testing.T) {
	kernel := newFakeTCKernel(11)
	kernel.addProgram(31, 301)
	kernel.addProgram(32, 302)
	_, err := prepareTCAttachPlan(
		testTCState(11, 11),
		tcProgramIdentity{fd: 301, id: 31},
		tcProgramIdentity{fd: 302, id: 32},
		kernel.runtime(),
	)
	if err == nil || !strings.Contains(err.Error(), "duplicate ifindex") {
		t.Fatalf("preflight error = %v, want duplicate ifindex", err)
	}
	if len(kernel.writes) != 0 {
		t.Fatalf("preflight performed writes: %v", kernel.writes)
	}
}

func TestTCAttachTransactionRefusesRollbackAfterFilterSwap(t *testing.T) {
	kernel := newFakeTCKernel(11)
	for id, fd := range map[uint32]int{31: 301, 32: 302, 99: 909} {
		kernel.addProgram(id, fd)
	}
	plan, err := prepareTCAttachPlan(
		testTCState(11),
		tcProgramIdentity{fd: 301, id: 31},
		tcProgramIdentity{fd: 302, id: 32},
		kernel.runtime(),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Close()
	kernel.filterListHook = func(key fakeTCFilterKey, call int) {
		if key.parent != netlink.HANDLE_MIN_INGRESS || call != 4 {
			return
		}
		slot := canonicalTCFilterSlots()[0]
		filter := managedBpfFilter(11, slot, 909).(*netlink.BpfFilter)
		filter.Id = 99
		kernel.filters[key] = []netlink.Filter{filter}
	}
	err = plan.Execute(func() error { return errors.New("commit failed") })
	if err == nil || !strings.Contains(err.Error(), "refuse rollback") {
		t.Fatalf("attach error = %v, want rollback swap refusal", err)
	}
	if got := kernel.managedProgramID(t, 11, canonicalTCFilterSlots()[0]); got != 99 {
		t.Fatalf("foreign replacement program = %d, want preserved 99", got)
	}
}

func TestTCAttachTransactionIncludesOwnedStaleDeletesAndRollback(t *testing.T) {
	for _, test := range []struct {
		name       string
		failWrite  int
		commitErr  error
		wantOldIDs bool
	}{
		{
			name:       "success",
			wantOldIDs: false,
		},
		{
			name:       "second delete failure",
			failWrite:  2,
			wantOldIDs: true,
		},
		{
			name:       "commit failure",
			commitErr:  errors.New("commit failed"),
			wantOldIDs: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			kernel := newFakeTCKernel(11)
			kernel.addProgram(21, 201)
			kernel.addProgram(22, 202)
			kernel.addProgram(31, 301)
			kernel.addProgram(32, 302)
			kernel.addClsact(11)
			kernel.addManagedFilter(11, canonicalTCFilterSlots()[0], 21)
			kernel.addManagedFilter(11, canonicalTCFilterSlots()[1], 22)

			plan, err := prepareTCAttachPlan(
				testTCState(),
				tcProgramIdentity{fd: 301, id: 31},
				tcProgramIdentity{fd: 302, id: 32},
				kernel.runtime(),
			)
			if err != nil {
				t.Fatal(err)
			}
			defer plan.Close()
			active := []tcFilterBinding{
				{
					IfIndex:   11,
					Direction: "ingress",
					Parent:    netlink.HANDLE_MIN_INGRESS,
					Handle:    ingressHandle,
					Priority:  filterPriority,
					ProgramID: 21,
				},
				{
					IfIndex:   11,
					Direction: "egress",
					Parent:    netlink.HANDLE_MIN_EGRESS,
					Handle:    egressHandle,
					Priority:  filterPriority,
					ProgramID: 22,
				},
			}
			if err := plan.ValidatePreviousBindings(active, false); err != nil {
				t.Fatal(err)
			}
			if err := plan.AddOwnedStaleRemovals(active); err != nil {
				t.Fatal(err)
			}
			kernel.failWrite = test.failWrite
			err = plan.Execute(func() error { return test.commitErr })
			if test.wantOldIDs {
				if err == nil {
					t.Fatal("stale-delete transaction unexpectedly succeeded")
				}
				if got := kernel.managedProgramID(
					t,
					11,
					canonicalTCFilterSlots()[0],
				); got != 21 {
					t.Fatalf("restored ingress program = %d, want 21", got)
				}
				if got := kernel.managedProgramID(
					t,
					11,
					canonicalTCFilterSlots()[1],
				); got != 22 {
					t.Fatalf("restored egress program = %d, want 22", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, slot := range canonicalTCFilterSlots() {
				if got := kernel.managedProgramID(t, 11, slot); got != 0 {
					t.Fatalf("stale %s program remains: %d", slot.name, got)
				}
			}
		})
	}
}

func TestTCAttachFailureAtEveryFilterWriteRestoresAllOwnedSlots(t *testing.T) {
	const mutationWrites = 6 // four replacements plus two stale deletes
	for failAt := 1; failAt <= mutationWrites; failAt++ {
		t.Run(fmt.Sprintf("write-%02d", failAt), func(t *testing.T) {
			kernel := newFakeTCKernel(11, 12, 13)
			for id, fd := range map[uint32]int{
				21: 201,
				22: 202,
				31: 301,
				32: 302,
			} {
				kernel.addProgram(id, fd)
			}
			var active []tcFilterBinding
			for _, ifindex := range []int{11, 12, 13} {
				kernel.addClsact(ifindex)
				kernel.addManagedFilter(ifindex, canonicalTCFilterSlots()[0], 21)
				kernel.addManagedFilter(ifindex, canonicalTCFilterSlots()[1], 22)
				active = append(active,
					tcFilterBinding{
						IfIndex:   ifindex,
						Direction: "ingress",
						Parent:    netlink.HANDLE_MIN_INGRESS,
						Handle:    ingressHandle,
						Priority:  filterPriority,
						ProgramID: 21,
					},
					tcFilterBinding{
						IfIndex:   ifindex,
						Direction: "egress",
						Parent:    netlink.HANDLE_MIN_EGRESS,
						Handle:    egressHandle,
						Priority:  filterPriority,
						ProgramID: 22,
					},
				)
			}
			sortTCFilterBindings(active)
			plan, err := prepareTCAttachPlan(
				testTCState(11, 12),
				tcProgramIdentity{fd: 301, id: 31},
				tcProgramIdentity{fd: 302, id: 32},
				kernel.runtime(),
			)
			if err != nil {
				t.Fatal(err)
			}
			defer plan.Close()
			if err := plan.ValidatePreviousBindings(active, false); err != nil {
				t.Fatal(err)
			}
			if err := plan.AddOwnedStaleRemovals(active); err != nil {
				t.Fatal(err)
			}
			kernel.failWrite = failAt
			err = plan.Execute(func() error { return nil })
			if err == nil || !strings.Contains(err.Error(), "injected") {
				t.Fatalf("write %d error = %v", failAt, err)
			}
			for _, ifindex := range []int{11, 12, 13} {
				if got := kernel.managedProgramID(
					t,
					ifindex,
					canonicalTCFilterSlots()[0],
				); got != 21 {
					t.Fatalf("write %d ifindex %d ingress = %d, want 21", failAt, ifindex, got)
				}
				if got := kernel.managedProgramID(
					t,
					ifindex,
					canonicalTCFilterSlots()[1],
				); got != 22 {
					t.Fatalf("write %d ifindex %d egress = %d, want 22", failAt, ifindex, got)
				}
			}
		})
	}
}
