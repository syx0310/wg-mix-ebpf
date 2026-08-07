//go:build linux

package dataplane

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/control"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type fakeTCProgramRef struct {
	fd         int
	closed     bool
	closeErrs  []error
	closeCalls int
}

func (program *fakeTCProgramRef) FD() int {
	if program.closed {
		return -1
	}
	return program.fd
}

func (program *fakeTCProgramRef) Close() error {
	program.closeCalls++
	if len(program.closeErrs) != 0 {
		err := program.closeErrs[0]
		program.closeErrs = program.closeErrs[1:]
		if err != nil {
			return err
		}
	}
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

func testMutatingTCOwnerJournal(
	active []tcFilterBinding,
	desired []tcFilterBinding,
) *pinOwnerRecord {
	record := &pinOwnerRecord{
		Sequence:       7,
		ResourceKey:    "journal-test-resource",
		Token:          strings.Repeat("01", 32),
		Phase:          pinOwnerPhaseApplying,
		Step:           pinOwnerStepMutating,
		ActiveFilters:  slices.Clone(active),
		DesiredFilters: slices.Clone(desired),
	}
	token, err := tokenFromOwnerRecord(record)
	if err != nil {
		panic(err)
	}
	record.ProgramStages = buildOwnerProgramStages(
		record.ResourceKey,
		token,
		record.ActiveFilters,
		record.DesiredFilters,
	)
	return record
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
	retained, err := plan.Execute(func() error {
		committedAfterWrites = len(kernel.writes)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if retained != nil {
		t.Fatal("successful Execute returned rollback ownership")
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

func TestTCAttachRetainedStageRetriesOnlyFailedProgramReferenceClose(t *testing.T) {
	kernel := newFakeTCKernel(11)
	for id, fd := range map[uint32]int{21: 201, 22: 202, 31: 301, 32: 302} {
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
	if len(kernel.retained) != 2 {
		t.Fatalf("retained references=%d, want 2", len(kernel.retained))
	}
	closeErr := errors.New("injected retained program close failure")
	kernel.retained[0].closeErrs = []error{closeErr}
	stage, err := plan.ExecuteRetained(func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := stage.Close(); !errors.Is(err, closeErr) {
		t.Fatalf("first stage Close error=%v", err)
	}
	if !stage.rolledBack || stage.done || stage.plan != plan || plan.stage != stage {
		t.Fatalf(
			"failed reference close lost owner: rolledBack=%t done=%t stage plan=%p plan stage=%p",
			stage.rolledBack, stage.done, stage.plan, plan.stage,
		)
	}
	if kernel.retained[0].closeCalls != 1 || kernel.retained[0].closed ||
		kernel.retained[1].closeCalls != 1 || !kernel.retained[1].closed {
		t.Fatalf(
			"first close states failed=%#v successful=%#v",
			kernel.retained[0], kernel.retained[1],
		)
	}
	for index, slot := range canonicalTCFilterSlots() {
		want := uint32(21 + index)
		if got := kernel.managedProgramID(t, 11, slot); got != want {
			t.Fatalf("restored %s program=%d want=%d", slot.name, got, want)
		}
	}
	if err := stage.Close(); err != nil {
		t.Fatalf("retry stage Close error=%v", err)
	}
	if kernel.retained[0].closeCalls != 2 || !kernel.retained[0].closed ||
		kernel.retained[1].closeCalls != 1 || !stage.done || stage.plan != nil || plan.stage != nil {
		t.Fatalf(
			"retry did not converge: failed=%#v successful=%#v stage=%#v plan stage=%p",
			kernel.retained[0], kernel.retained[1], stage, plan.stage,
		)
	}
	if err := stage.Close(); err != nil || kernel.retained[0].closeCalls != 2 || kernel.retained[1].closeCalls != 1 {
		t.Fatalf(
			"converged Close error=%v calls=%d/%d",
			err, kernel.retained[0].closeCalls, kernel.retained[1].closeCalls,
		)
	}
}

func TestTCAttachPlanRetriesOnlyFailedProgramReferenceClose(t *testing.T) {
	kernel := newFakeTCKernel(11)
	for id, fd := range map[uint32]int{21: 201, 22: 202, 31: 301, 32: 302} {
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
	closeErr := errors.New("injected direct plan reference close failure")
	kernel.retained[0].closeErrs = []error{closeErr}
	if err := plan.Close(); !errors.Is(err, closeErr) {
		t.Fatalf("first plan Close error=%v", err)
	}
	if plan.closed || kernel.retained[0].closeCalls != 1 || kernel.retained[1].closeCalls != 1 {
		t.Fatalf(
			"failed plan close state closed=%t calls=%d/%d",
			plan.closed, kernel.retained[0].closeCalls, kernel.retained[1].closeCalls,
		)
	}
	if err := plan.Close(); err != nil {
		t.Fatalf("retry plan Close error=%v", err)
	}
	if !plan.closed || kernel.retained[0].closeCalls != 2 || kernel.retained[1].closeCalls != 1 {
		t.Fatalf(
			"retry plan close state closed=%t calls=%d/%d",
			plan.closed, kernel.retained[0].closeCalls, kernel.retained[1].closeCalls,
		)
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
	retained, err := plan.Execute(func() error {
		commitCalls++
		return nil
	})
	if retained != nil {
		t.Fatal("successful partial-failure rollback retained ownership")
	}
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

	retained, err := plan.Execute(func() error { return errors.New("commit failed") })
	if retained != nil {
		t.Fatal("commit failure with complete rollback retained ownership")
	}
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
	retained, err := plan.Execute(func() error { return errors.New("commit failed") })
	if err == nil || !strings.Contains(err.Error(), "refuse rollback") {
		t.Fatalf("attach error = %v, want rollback swap refusal", err)
	}
	if retained == nil || !retained.hasLiveFilterOwnership() {
		t.Fatal("rollback swap refusal lost retained filter owner")
	}
	if got := kernel.managedProgramID(t, 11, canonicalTCFilterSlots()[0]); got != 99 {
		t.Fatalf("foreign replacement program = %d, want preserved 99", got)
	}
	ingress := canonicalTCFilterSlots()[0]
	key := fakeTCFilterKey{ifindex: 11, parent: ingress.parent}
	owned := managedBpfFilter(11, ingress, 301).(*netlink.BpfFilter)
	owned.Id = 31
	kernel.filters[key] = []netlink.Filter{owned}
	if err := retained.Close(); err != nil {
		t.Fatalf("retry retained rollback: %v", err)
	}
}

func TestTCAttachExecuteReturnsRollbackOwnerForDurableJournalHandoff(t *testing.T) {
	fixture := newDurableTCOwnerJournalFixture(t)
	kernel := newFakeTCKernel(11)
	for id, fd := range map[uint32]int{21: 201, 22: 202, 31: 301, 32: 302} {
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
	defer plan.Close()
	active := fixture.active
	desired := plan.Bindings()
	if err := plan.ValidatePreviousBindings(active, false); err != nil {
		t.Fatal(err)
	}
	if err := plan.AddOwnedStaleRemovals(active); err != nil {
		t.Fatal(err)
	}
	handoff, err := prepareDurableTCOwnerJournalHandoff(
		fixture.handle,
		fixture.store,
		fixture.intent,
		active,
		desired,
		plan,
	)
	if err != nil {
		t.Fatal(err)
	}

	// The third write is the first rollback replace. Its failure leaves the
	// desired egress filter live while ingress rollback succeeds.
	kernel.failWrite = 3
	retained, err := plan.Execute(func() error { return errors.New("commit failed") })
	if retained == nil || err == nil || !strings.Contains(err.Error(), "injected filter-replace failure") {
		t.Fatalf("retained=%#v Execute error=%v", retained, err)
	}
	if !retained.hasLiveFilterOwnership() || plan.stage != retained {
		t.Fatal("Execute lost the exact partial rollback owner")
	}
	if got := kernel.managedProgramID(t, 11, canonicalTCFilterSlots()[0]); got != 21 {
		t.Fatalf("rolled-back ingress program=%d, want active 21", got)
	}
	if got := kernel.managedProgramID(t, 11, canonicalTCFilterSlots()[1]); got != 32 {
		t.Fatalf("retained egress program=%d, want desired 32", got)
	}

	if err := handoff.Transfer(retained); err != nil {
		t.Fatalf("transfer retained stage: %v", err)
	}
	if retained.hasLiveFilterOwnership() || !retained.done || plan.stage != nil {
		t.Fatal("durable journal handoff did not disarm the transient stage")
	}
	programs := &loadedOwnerPrograms{byID: map[uint32]*pinnedProgramObservation{
		31: {fd: 301, id: 31},
		32: {fd: 302, id: 32},
	}}
	kernel.failWrite = 0
	if err := rollForwardOwnerApplyFilters(
		fixture.intent.ActiveFilters,
		fixture.intent.DesiredFilters,
		programs,
		kernel.runtime(),
	); err != nil {
		t.Fatalf("journal roll-forward after handoff: %v", err)
	}
	for index, slot := range canonicalTCFilterSlots() {
		want := uint32(31 + index)
		if got := kernel.managedProgramID(t, 11, slot); got != want {
			t.Fatalf("recovered %s program=%d want=%d", slot.name, got, want)
		}
	}
}

type retainedJournalHandoffFixture struct {
	owner   *durableTCOwnerJournalFixture
	plan    *tcAttachPlan
	handoff *durableTCOwnerJournalHandoff
	stage   *tcAttachStage
}

func newRetainedJournalHandoffFixture(
	t *testing.T,
) *retainedJournalHandoffFixture {
	t.Helper()
	owner := newDurableTCOwnerJournalFixture(t)
	kernel := newFakeTCKernel(11)
	for id, fd := range map[uint32]int{21: 201, 22: 202, 31: 301, 32: 302} {
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
	t.Cleanup(func() { _ = plan.Close() })
	if err := plan.ValidatePreviousBindings(owner.active, false); err != nil {
		t.Fatal(err)
	}
	if err := plan.AddOwnedStaleRemovals(owner.active); err != nil {
		t.Fatal(err)
	}
	handoff, err := prepareDurableTCOwnerJournalHandoff(
		owner.handle,
		owner.store,
		owner.intent,
		owner.active,
		owner.desired,
		plan,
	)
	if err != nil {
		t.Fatal(err)
	}
	kernel.failWrite = 3
	stage, err := plan.Execute(func() error { return errors.New("commit failed") })
	if stage == nil || err == nil || !stage.hasLiveFilterOwnership() {
		t.Fatalf("retained stage=%#v Execute error=%v", stage, err)
	}
	return &retainedJournalHandoffFixture{
		owner:   owner,
		plan:    plan,
		handoff: handoff,
		stage:   stage,
	}
}

func TestDurableTCOwnerJournalHandoffIsExactAndOneShot(t *testing.T) {
	t.Run("wrong plan does not consume capability", func(t *testing.T) {
		first := newRetainedJournalHandoffFixture(t)
		second := newRetainedJournalHandoffFixture(t)
		if err := first.handoff.Transfer(second.stage); err == nil ||
			!strings.Contains(err.Error(), "exact stage") {
			t.Fatalf("wrong-plan transfer error = %v", err)
		}
		if err := first.handoff.Transfer(first.stage); err != nil {
			t.Fatalf("exact transfer after wrong plan: %v", err)
		}
		if err := second.stage.Close(); err != nil {
			t.Fatalf("resolve wrong-plan stage: %v", err)
		}
	})

	t.Run("stage coverage mismatch does not consume capability", func(t *testing.T) {
		fixture := newRetainedJournalHandoffFixture(t)
		if len(fixture.stage.applied) == 0 {
			t.Fatal("retained stage has no applied filter")
		}
		original := fixture.stage.applied[0].program
		fixture.stage.applied[0].program.id++
		if err := fixture.handoff.Transfer(fixture.stage); err == nil ||
			!strings.Contains(err.Error(), "outside journal desired") {
			t.Fatalf("coverage mismatch transfer error = %v", err)
		}
		fixture.stage.applied[0].program = original
		if err := fixture.handoff.Transfer(fixture.stage); err != nil {
			t.Fatalf("exact transfer after coverage mismatch: %v", err)
		}
	})

	t.Run("stale durable sequence is rejected", func(t *testing.T) {
		fixture := newRetainedJournalHandoffFixture(t)
		next := advancePinOwnerRecord(
			fixture.owner.intent,
			time.Date(2026, 8, 8, 1, 2, 4, 0, time.UTC),
			pinOwnerPhaseApplying,
			pinOwnerStepCleanup,
		)
		if err := fixture.owner.store.Persist(
			next,
			fixture.owner.intent,
			fixture.owner.handle.mountID,
		); err != nil {
			t.Fatal(err)
		}
		if err := fixture.handoff.Transfer(fixture.stage); err == nil ||
			!strings.Contains(err.Error(), "stale") {
			t.Fatalf("stale transfer error = %v", err)
		}
		if err := fixture.stage.Close(); err != nil {
			t.Fatalf("resolve stale stage: %v", err)
		}
	})

	t.Run("mount binding change is rejected", func(t *testing.T) {
		fixture := newRetainedJournalHandoffFixture(t)
		fixture.handoff.mountID++
		if err := fixture.handoff.Transfer(fixture.stage); err == nil ||
			!strings.Contains(err.Error(), "mount binding changed") {
			t.Fatalf("mount binding transfer error = %v", err)
		}
		fixture.handoff.mountID--
		if err := fixture.handoff.Transfer(fixture.stage); err != nil {
			t.Fatalf("exact transfer after mount mismatch: %v", err)
		}
	})

	t.Run("resolved and double transfer are rejected", func(t *testing.T) {
		resolved := newRetainedJournalHandoffFixture(t)
		if err := resolved.stage.Close(); err != nil {
			t.Fatal(err)
		}
		if err := resolved.handoff.Transfer(resolved.stage); err == nil ||
			!strings.Contains(err.Error(), "already resolved") {
			t.Fatalf("resolved stage transfer error = %v", err)
		}

		doubled := newRetainedJournalHandoffFixture(t)
		if err := doubled.handoff.Transfer(doubled.stage); err != nil {
			t.Fatal(err)
		}
		if err := doubled.handoff.Transfer(doubled.stage); err == nil ||
			!strings.Contains(err.Error(), "already transferred") {
			t.Fatalf("double transfer error = %v", err)
		}
	})

	t.Run("concurrent close is serialized with transfer", func(t *testing.T) {
		fixture := newRetainedJournalHandoffFixture(t)
		start := make(chan struct{})
		var wait sync.WaitGroup
		var transferErr error
		var closeErr error
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			transferErr = fixture.handoff.Transfer(fixture.stage)
		}()
		go func() {
			defer wait.Done()
			<-start
			closeErr = fixture.stage.Close()
		}()
		close(start)
		wait.Wait()
		if transferErr != nil && closeErr != nil {
			t.Fatalf("both ownership resolutions failed: transfer=%v close=%v", transferErr, closeErr)
		}
		if !fixture.stage.done || fixture.plan.stage != nil {
			t.Fatalf("concurrent resolution did not converge: transfer=%v close=%v", transferErr, closeErr)
		}
	})
}

func TestTCOwnerJournalHandoffRejectsFaultsBeforeTCMutation(t *testing.T) {
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
	active := []tcFilterBinding{}
	desired := plan.Bindings()

	tests := []struct {
		name   string
		mutate func(*pinOwnerRecord, *pinOwnerRecord)
		match  string
	}{
		{
			name: "persisted record differs",
			mutate: func(_ *pinOwnerRecord, persisted *pinOwnerRecord) {
				persisted.Sequence++
			},
			match: "differs",
		},
		{
			name: "wrong journal step",
			mutate: func(intent *pinOwnerRecord, persisted *pinOwnerRecord) {
				intent.Step = pinOwnerStepCleanup
				persisted.Step = pinOwnerStepCleanup
			},
			match: "requires applying/mutating",
		},
		{
			name: "missing desired filter coverage",
			mutate: func(intent *pinOwnerRecord, persisted *pinOwnerRecord) {
				intent.DesiredFilters = intent.DesiredFilters[:1]
				persisted.DesiredFilters = persisted.DesiredFilters[:1]
			},
			match: "desired filter set",
		},
		{
			name: "missing desired program stage",
			mutate: func(intent *pinOwnerRecord, persisted *pinOwnerRecord) {
				intent.ProgramStages = intent.ProgramStages[:1]
				persisted.ProgramStages = persisted.ProgramStages[:1]
			},
			match: "program stages",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			intent := testMutatingTCOwnerJournal(active, desired)
			persisted := clonePinOwnerRecord(intent)
			test.mutate(intent, persisted)
			handoff, err := validateTCOwnerJournalCoverage(
				intent,
				persisted,
				active,
				desired,
			)
			if handoff != nil || err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("handoff=%#v error=%v want %q", handoff, err, test.match)
			}
			if len(kernel.writes) != 0 {
				t.Fatalf("failed journal proof reached TC mutation: %v", kernel.writes)
			}
		})
	}
}

func TestTCAttachExecuteReturnsOnlyProgramReferencesToPlan(t *testing.T) {
	kernel := newFakeTCKernel(11)
	for id, fd := range map[uint32]int{21: 201, 22: 202, 31: 301, 32: 302} {
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
	closeErr := errors.New("terminal retained program close report")
	kernel.retained[0].closeErrs = []error{closeErr}
	retained, err := plan.Execute(func() error { return errors.New("commit failed") })
	if retained != nil || !errors.Is(err, closeErr) {
		t.Fatalf("retained=%#v Execute error=%v", retained, err)
	}
	if plan.stage != nil || plan.closed || kernel.retained[0].closeCalls != 1 ||
		kernel.retained[1].closeCalls != 1 {
		t.Fatalf(
			"program reference ownership was not returned to plan: stage=%p closed=%t calls=%d/%d",
			plan.stage, plan.closed, kernel.retained[0].closeCalls, kernel.retained[1].closeCalls,
		)
	}
	if err := plan.Close(); err != nil {
		t.Fatalf("plan reference retry: %v", err)
	}
	if kernel.retained[0].closeCalls != 2 || kernel.retained[1].closeCalls != 1 {
		t.Fatalf("plan retry calls=%d/%d", kernel.retained[0].closeCalls, kernel.retained[1].closeCalls)
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
			retained, err := plan.Execute(func() error { return test.commitErr })
			if test.wantOldIDs {
				if err == nil {
					t.Fatal("stale-delete transaction unexpectedly succeeded")
				}
				if retained != nil {
					t.Fatal("complete stale-delete rollback retained ownership")
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
			if retained != nil {
				t.Fatal("successful stale-delete transaction retained ownership")
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
			retained, err := plan.Execute(func() error { return nil })
			if err == nil || !strings.Contains(err.Error(), "injected") {
				t.Fatalf("write %d error = %v", failAt, err)
			}
			if retained != nil {
				t.Fatalf("write %d complete rollback retained ownership", failAt)
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
