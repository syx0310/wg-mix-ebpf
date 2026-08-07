//go:build linux

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

	if err := transferRetainedStage(handoff, retained); err != nil {
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
	kernel  *fakeTCKernel
	attach  error
}

func transferRetainedStage(
	handoff *durableTCOwnerJournalHandoff,
	stage *tcAttachStage,
) error {
	transferred, err := handoff.Transfer(stage)
	if err != nil {
		return err
	}
	if !transferred {
		return errors.New("TC owner journal transfer returned no owner")
	}
	return nil
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
		kernel:  kernel,
		attach:  err,
	}
}

func assertFailedOwnerApplyResolvedByProduction(
	t *testing.T,
	fixture *retainedJournalHandoffFixture,
	want error,
) {
	t.Helper()
	err := resolveFailedOwnerApply(
		fixture.owner.handle,
		fixture.owner.store,
		fixture.owner.intent,
		fixture.handoff,
		fixture.stage,
		fixture.kernel.runtime(),
	)
	if err == nil || (want != nil && !errors.Is(err, want)) {
		t.Fatalf("production failed-apply resolution error = %v, want %v", err, want)
	}
	if fixture.stage.hasLiveFilterOwnership() || !fixture.stage.done ||
		fixture.plan.stage != nil {
		t.Fatalf(
			"production return boundary retained an unowned stage: live=%t done=%t plan-stage=%p",
			fixture.stage.hasLiveFilterOwnership(),
			fixture.stage.done,
			fixture.plan.stage,
		)
	}
	for index, wantID := range []uint32{21, 22} {
		if got := fixture.kernel.managedProgramID(
			t,
			11,
			canonicalTCFilterSlots()[index],
		); got != wantID {
			t.Fatalf("rolled-back slot %d program=%d, want %d", index, got, wantID)
		}
	}
}

func TestFailedOwnerApplyProductionBoundaryResolvesFreshHandoffFaults(
	t *testing.T,
) {
	t.Run("owner store load", func(t *testing.T) {
		fixture := newRetainedJournalHandoffFixture(t)
		if err := fixture.owner.store.root.Close(); err != nil {
			t.Fatal(err)
		}
		assertFailedOwnerApplyResolvedByProduction(t, fixture, nil)
	})

	t.Run("owner directory coverage", func(t *testing.T) {
		fixture := newRetainedJournalHandoffFixture(t)
		wantErr := errors.New("injected owner directory entry")
		name := filepath.Join(fixture.owner.handle.pinPath, "uncovered-entry")
		if err := os.WriteFile(name, []byte(wantErr.Error()), 0o600); err != nil {
			t.Fatal(err)
		}
		assertFailedOwnerApplyResolvedByProduction(t, fixture, nil)
	})

	t.Run("owner map load", func(t *testing.T) {
		fixture := newRetainedJournalHandoffFixture(t)
		wantErr := errors.New("injected owner map load failure")
		fixture.owner.mapStore.loadErrors["control_map"] = wantErr
		assertFailedOwnerApplyResolvedByProduction(t, fixture, wantErr)
	})

	t.Run("owner program load", func(t *testing.T) {
		fixture := newRetainedJournalHandoffFixture(t)
		wantErr := errors.New("injected owner program load failure")
		stage := fixture.owner.intent.ProgramStages[0]
		fixture.owner.programLoadErrors[stage.FileName] = wantErr
		fixture.owner.programLoadErrors[stage.FileName+".handoff"] = wantErr
		assertFailedOwnerApplyResolvedByProduction(t, fixture, wantErr)
	})

	t.Run("stale durable sequence", func(t *testing.T) {
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
		assertFailedOwnerApplyResolvedByProduction(t, fixture, nil)
	})
}

func TestLinuxLoaderApplyReturnBoundaryOwnsFreshHandoffFailure(t *testing.T) {
	fixture := newRetainedJournalHandoffFixture(t)
	wantErr := errors.New("injected Apply-boundary map load failure")
	fixture.owner.mapStore.loadErrors["control_map"] = wantErr
	runtime := fixture.owner.handle.runtime
	runtime.ownerApplyFailure = func() (*ownerApplyFailureBoundary, error) {
		return &ownerApplyFailureBoundary{
			plan:      fixture.plan,
			handle:    fixture.owner.handle,
			store:     fixture.owner.store,
			record:    fixture.owner.intent,
			handoff:   fixture.handoff,
			stage:     fixture.stage,
			tcRuntime: fixture.kernel.runtime(),
			attachErr: fixture.attach,
		}, nil
	}
	err := (LinuxLoader{runtime: &runtime}).Apply(context.Background(), nil)
	if !errors.Is(err, wantErr) || !errors.Is(err, fixture.attach) {
		t.Fatalf("LinuxLoader.Apply error=%v", err)
	}
	if fixture.stage.hasLiveFilterOwnership() || !fixture.stage.done ||
		fixture.plan.stage != nil || !fixture.plan.closed {
		t.Fatalf(
			"Apply return/defer lost ownership: live=%t done=%t plan-stage=%p closed=%t",
			fixture.stage.hasLiveFilterOwnership(),
			fixture.stage.done,
			fixture.plan.stage,
			fixture.plan.closed,
		)
	}
	if fixture.owner.handle.targetFD != -1 ||
		fixture.owner.store.root != nil {
		t.Fatal("Apply return did not close its owner handle/store")
	}
	fixture.owner.assertProgramObservationsBalanced(t)
}

func TestDurableTCOwnerJournalHandoffTerminalLifecycle(t *testing.T) {
	t.Run("successful Apply return releases proof observations once", func(t *testing.T) {
		owner := newDurableTCOwnerJournalFixture(t)
		handoff, err := prepareDurableTCOwnerJournalHandoff(
			owner.handle,
			owner.store,
			owner.intent,
			owner.active,
			owner.desired,
			owner.plan,
		)
		if err != nil {
			t.Fatal(err)
		}
		opens, closes := owner.programObservationCounts()
		if opens <= closes {
			t.Fatalf("prepared handoff has no retained proof: opens=%d closes=%d", opens, closes)
		}
		if err := handoff.Close(); err != nil {
			t.Fatal(err)
		}
		owner.assertProgramObservationsBalanced(t)
		opens, closes = owner.programObservationCounts()
		if err := handoff.Close(); err != nil {
			t.Fatalf("second handoff close: %v", err)
		}
		afterOpens, afterCloses := owner.programObservationCounts()
		if opens != afterOpens || closes != afterCloses {
			t.Fatalf(
				"second close touched observations: before=%d/%d after=%d/%d",
				opens,
				closes,
				afterOpens,
				afterCloses,
			)
		}
	})

	t.Run("nil stage early return releases proof observations", func(t *testing.T) {
		owner := newDurableTCOwnerJournalFixture(t)
		handoff, err := prepareDurableTCOwnerJournalHandoff(
			owner.handle,
			owner.store,
			owner.intent,
			owner.active,
			owner.desired,
			owner.plan,
		)
		if err != nil {
			t.Fatal(err)
		}
		_ = resolveFailedOwnerApply(
			owner.handle,
			owner.store,
			owner.intent,
			handoff,
			nil,
			owner.kernel.runtime(),
		)
		owner.assertProgramObservationsBalanced(t)
	})

	t.Run("verified rollback cleanup error releases proof observations", func(t *testing.T) {
		fixture := newRetainedJournalHandoffFixture(t)
		fixture.kernel.failWrite = 0
		if err := fixture.stage.Close(); err != nil {
			t.Fatal(err)
		}
		err := resolveFailedOwnerApply(
			fixture.owner.handle,
			fixture.owner.store,
			fixture.owner.intent,
			fixture.handoff,
			fixture.stage,
			fixture.kernel.runtime(),
		)
		if err == nil || !strings.Contains(err.Error(), "clock") {
			t.Fatalf("verified rollback cleanup error=%v", err)
		}
		fixture.owner.assertProgramObservationsBalanced(t)
	})

	t.Run("successful local rollback releases proof observations", func(t *testing.T) {
		fixture := newRetainedJournalHandoffFixture(t)
		wantErr := errors.New("injected handoff validation failure")
		fixture.owner.mapStore.loadErrors["control_map"] = wantErr
		fixture.kernel.failWrite = 0
		err := resolveFailedOwnerApply(
			fixture.owner.handle,
			fixture.owner.store,
			fixture.owner.intent,
			fixture.handoff,
			fixture.stage,
			fixture.kernel.runtime(),
		)
		if !errors.Is(err, wantErr) || !fixture.stage.done {
			t.Fatalf("local rollback error=%v done=%t", err, fixture.stage.done)
		}
		fixture.owner.assertProgramObservationsBalanced(t)
	})

	t.Run("durable transfer releases proof observations", func(t *testing.T) {
		fixture := newRetainedJournalHandoffFixture(t)
		_ = resolveFailedOwnerApply(
			fixture.owner.handle,
			fixture.owner.store,
			fixture.owner.intent,
			fixture.handoff,
			fixture.stage,
			fixture.kernel.runtime(),
		)
		if !fixture.stage.done || fixture.plan.stage != nil {
			t.Fatal("durable transfer did not consume the retained stage")
		}
		fixture.owner.assertProgramObservationsBalanced(t)
	})

	t.Run("close report does not undo transfer or close twice", func(t *testing.T) {
		fixture := newRetainedJournalHandoffFixture(t)
		stageName := fixture.owner.intent.ProgramStages[0].FileName
		wantErr := errors.New("injected pinned-program close report")
		// Transfer performs one fresh validation observation before releasing
		// the independently retained proof observation.
		fixture.owner.programCloseErrors[stageName] = []error{nil, wantErr}
		transferred, err := fixture.handoff.Transfer(fixture.stage)
		if !transferred || !errors.Is(err, wantErr) {
			t.Fatalf("transfer=%t close report=%v", transferred, err)
		}
		if !fixture.stage.done || fixture.plan.stage != nil {
			t.Fatal("close report reverted durable ownership")
		}
		fixture.owner.assertProgramObservationsBalanced(t)
		opens, closes := fixture.owner.programObservationCounts()
		if err := fixture.handoff.Close(); err != nil {
			t.Fatalf("close transferred handoff: %v", err)
		}
		afterOpens, afterCloses := fixture.owner.programObservationCounts()
		if opens != afterOpens || closes != afterCloses {
			t.Fatalf(
				"post-transfer Close touched observations: before=%d/%d after=%d/%d",
				opens,
				closes,
				afterOpens,
				afterCloses,
			)
		}
		if err := fixture.plan.Close(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestFailedOwnerApplyUsesDurableHandoffProgramAcrossRestart(
	t *testing.T,
) {
	fixture := newRetainedJournalHandoffFixture(t)
	programStage := fixture.owner.intent.ProgramStages[0]
	preserved := filepath.Join(
		filepath.Dir(fixture.owner.handle.pinPath),
		"preserved-"+programStage.FileName,
	)
	if err := os.Rename(
		filepath.Join(fixture.owner.handle.pinPath, programStage.FileName),
		preserved,
	); err != nil {
		t.Fatal(err)
	}
	err := resolveFailedOwnerApply(
		fixture.owner.handle,
		fixture.owner.store,
		fixture.owner.intent,
		fixture.handoff,
		fixture.stage,
		fixture.kernel.runtime(),
	)
	if err == nil {
		t.Fatal("failed apply unexpectedly returned nil")
	}
	if fixture.stage.hasLiveFilterOwnership() || !fixture.stage.done ||
		fixture.plan.stage != nil {
		t.Fatal("durable handoff program did not accept the retained stage")
	}
	if err := validatePinnedProgramAt(
		fixture.owner.handle,
		programStage.FileName+".handoff",
		programStage.ProgramID,
	); err != nil {
		t.Fatalf("durable handoff program stage is unavailable: %v", err)
	}

	// Reopen only durable state and run the normal restart recovery path. No
	// tcAttachStage or test-side rollback participates in convergence.
	if err := fixture.owner.store.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := openPinOwnerStore(
		fixture.owner.handle.runtime,
		fixture.owner.handle.resource,
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	persisted, err := restarted.Load(fixture.owner.handle.mountID)
	if err != nil {
		t.Fatal(err)
	}
	fixture.owner.handle.runtime.now = func() time.Time {
		return time.Date(2026, 8, 8, 1, 2, 7, 0, time.UTC)
	}
	recovered, err := recoverPinOwnerTransaction(
		fixture.owner.handle,
		restarted,
		persisted,
		fixture.kernel.runtime(),
	)
	if err != nil {
		t.Fatalf("restart durable TC owner recovery: %v", err)
	}
	if recovered.record == nil || recovered.record.Phase != pinOwnerPhaseActive ||
		recovered.record.ActiveGeneration != fixture.owner.intent.NextGeneration {
		t.Fatalf("restart recovered owner=%#v", recovered.record)
	}
}

func TestDurableHandoffRecoversTCButPreservesSuspiciousPrimary(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *durableTCOwnerJournalFixture, pinOwnerProgramStage)
	}{
		{
			name: "wrong program ID",
			mutate: func(
				t *testing.T,
				owner *durableTCOwnerJournalFixture,
				stage pinOwnerProgramStage,
			) {
				t.Helper()
				owner.programIDs[stage.FileName] = stage.ProgramID + 1000
			},
		},
		{
			name: "wrong mode",
			mutate: func(
				t *testing.T,
				owner *durableTCOwnerJournalFixture,
				stage pinOwnerProgramStage,
			) {
				t.Helper()
				if err := os.Chmod(
					filepath.Join(owner.handle.pinPath, stage.FileName),
					0o640,
				); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRetainedJournalHandoffFixture(t)
			stage := fixture.owner.intent.ProgramStages[0]
			test.mutate(t, fixture.owner, stage)
			var suspiciousBefore unix.Stat_t
			if err := unix.Fstatat(
				fixture.owner.handle.targetFD,
				stage.FileName,
				&suspiciousBefore,
				unix.AT_SYMLINK_NOFOLLOW,
			); err != nil {
				t.Fatal(err)
			}
			wrongID := fixture.owner.programIDs[stage.FileName]

			err := resolveFailedOwnerApply(
				fixture.owner.handle,
				fixture.owner.store,
				fixture.owner.intent,
				fixture.handoff,
				fixture.stage,
				fixture.kernel.runtime(),
			)
			if err == nil || !fixture.stage.done || fixture.plan.stage != nil {
				t.Fatalf("durable handoff transfer error=%v done=%t", err, fixture.stage.done)
			}
			fixture.owner.assertProgramObservationsBalanced(t)

			if err := fixture.owner.store.Close(); err != nil {
				t.Fatal(err)
			}
			restarted, err := openPinOwnerStore(
				fixture.owner.handle.runtime,
				fixture.owner.handle.resource,
				true,
			)
			if err != nil {
				t.Fatal(err)
			}
			defer restarted.Close()
			persisted, err := restarted.Load(fixture.owner.handle.mountID)
			if err != nil {
				t.Fatal(err)
			}
			fixture.owner.handle.runtime.now = func() time.Time {
				return time.Date(2026, 8, 8, 1, 2, 8, 0, time.UTC)
			}
			_, recoverErr := recoverPinOwnerTransaction(
				fixture.owner.handle,
				restarted,
				persisted,
				fixture.kernel.runtime(),
			)
			if recoverErr == nil {
				t.Fatal("recovery removed or replaced a suspicious primary stage")
			}
			for index, slot := range canonicalTCFilterSlots() {
				wantID := uint32(31 + index)
				if got := fixture.kernel.managedProgramID(t, 11, slot); got != wantID {
					t.Fatalf("recovered %s program=%d want=%d", slot.name, got, wantID)
				}
			}
			cleanup, err := restarted.Load(fixture.owner.handle.mountID)
			if err != nil {
				t.Fatal(err)
			}
			if cleanup.Phase != pinOwnerPhaseApplying ||
				cleanup.Step != pinOwnerStepCleanup {
				t.Fatalf("diagnostic owner journal=%s/%s", cleanup.Phase, cleanup.Step)
			}
			if err := validatePinnedProgramAt(
				fixture.owner.handle,
				stage.FileName+".handoff",
				stage.ProgramID,
			); err != nil {
				t.Fatalf("durable handoff evidence was removed: %v", err)
			}
			var suspiciousAfter unix.Stat_t
			if err := unix.Fstatat(
				fixture.owner.handle.targetFD,
				stage.FileName,
				&suspiciousAfter,
				unix.AT_SYMLINK_NOFOLLOW,
			); err != nil {
				t.Fatal(err)
			}
			if suspiciousAfter.Ino != suspiciousBefore.Ino ||
				suspiciousAfter.Mode != suspiciousBefore.Mode ||
				suspiciousAfter.Size != suspiciousBefore.Size ||
				fixture.owner.programIDs[stage.FileName] != wrongID {
				t.Fatalf(
					"suspicious primary changed: before=%+v after=%+v id=%d want=%d",
					suspiciousBefore,
					suspiciousAfter,
					fixture.owner.programIDs[stage.FileName],
					wrongID,
				)
			}

			// A future operation sees the same durable diagnostic and remains
			// fail-closed until an operator resolves the foreign primary.
			if _, err := recoverPinOwnerTransaction(
				fixture.owner.handle,
				restarted,
				cleanup,
				fixture.kernel.runtime(),
			); err == nil {
				t.Fatal("subsequent recovery accepted the suspicious primary")
			}
		})
	}
}

func TestFailedOwnerApplyRebindsRetainedStageFromNextOperation(t *testing.T) {
	tests := []struct {
		name   string
		action string
		mode   string
	}{
		{name: "apply", action: "apply", mode: "journal"},
		{name: "detach", action: "detach", mode: "journal"},
		{name: "apply close report", action: "apply", mode: "close-report"},
		{name: "apply local rollback report", action: "apply", mode: "local-rollback"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRetainedJournalHandoffFixture(t)
			resourceKey := fixture.owner.intent.ResourceKey
			t.Cleanup(func() {
				retainedTCRollbackOwners.Lock()
				delete(retainedTCRollbackOwners.byResource, resourceKey)
				retainedTCRollbackOwners.Unlock()
			})

			wantErr := errors.New("injected persistent map validation failure")
			fixture.owner.mapStore.loadErrors["control_map"] = wantErr
			fixture.kernel.failWrite = len(fixture.kernel.writes) + 1
			pinPath := fixture.owner.handle.pinPath
			oldHandle := fixture.owner.handle
			oldStore := fixture.owner.store
			runtime := oldHandle.runtime
			runtime.ownerApplyFailure = func() (*ownerApplyFailureBoundary, error) {
				return &ownerApplyFailureBoundary{
					plan:      fixture.plan,
					handle:    oldHandle,
					store:     oldStore,
					record:    fixture.owner.intent,
					handoff:   fixture.handoff,
					stage:     fixture.stage,
					tcRuntime: fixture.kernel.runtime(),
					attachErr: fixture.attach,
				}, nil
			}
			loader := LinuxLoader{PinPath: pinPath, runtime: &runtime}
			firstErr := loader.Apply(context.Background(), nil)
			if !errors.Is(firstErr, wantErr) ||
				!errors.Is(firstErr, fixture.attach) ||
				!fixture.stage.hasLiveFilterOwnership() {
				t.Fatalf(
					"first Apply error=%v live=%t",
					firstErr,
					fixture.stage.hasLiveFilterOwnership(),
				)
			}
			if oldHandle.targetFD != -1 || oldHandle.parentPath != nil ||
				oldStore.root != nil {
				t.Fatal("first Apply retained its closed handle/store in process state")
			}
			fixture.owner.assertProgramObservationsBalanced(t)

			if test.mode != "local-rollback" {
				delete(fixture.owner.mapStore.loadErrors, "control_map")
			}
			runtime.ownerApplyFailure = nil
			runtime.ownerRetryOnly = func(got string) bool { return got == test.action }
			closeReport := errors.New("injected rebound proof close report")
			if test.mode == "close-report" {
				stageName := fixture.owner.intent.ProgramStages[0].FileName
				baseLoad := runtime.loadPinnedProgram
				loads := 0
				runtime.loadPinnedProgram = func(path string) (*pinnedProgramObservation, error) {
					observation, err := baseLoad(path)
					if err != nil || filepath.Base(path) != stageName {
						return observation, err
					}
					loads++
					// Rebind validates once, validates again before retaining,
					// then opens the independent observation released by Transfer.
					if loads == 3 {
						baseClose := observation.close
						observation.close = func() error {
							return errors.Join(baseClose(), closeReport)
						}
					}
					return observation, nil
				}
			}
			// If the fresh journal rebind is skipped, the remaining local rollback
			// still fails at its first write.
			writesBeforeRetry := len(fixture.kernel.writes)
			if test.mode == "local-rollback" {
				fixture.kernel.failWrite = 0
			} else {
				fixture.kernel.failWrite = writesBeforeRetry + 1
			}
			var retryErr error
			if test.action == "apply" {
				retryErr = loader.Apply(context.Background(), nil)
			} else {
				retryErr = loader.Detach(context.Background(), nil)
			}
			switch test.mode {
			case "journal":
				if retryErr != nil {
					t.Fatalf("fresh %s owner retry: %v", test.action, retryErr)
				}
			case "close-report":
				if !errors.Is(retryErr, closeReport) {
					t.Fatalf("fresh transfer close report=%v", retryErr)
				}
			case "local-rollback":
				if !errors.Is(retryErr, wantErr) {
					t.Fatalf("converged local rollback report=%v", retryErr)
				}
			}
			if test.mode != "local-rollback" &&
				len(fixture.kernel.writes) != writesBeforeRetry {
				t.Fatalf(
					"fresh journal retry attempted local TC rollback: writes=%v",
					fixture.kernel.writes[writesBeforeRetry:],
				)
			}
			if fixture.stage.hasLiveFilterOwnership() || !fixture.stage.done ||
				fixture.plan.stage != nil || !fixture.plan.closed {
				t.Fatalf(
					"fresh owner did not converge: live=%t done=%t plan-stage=%p closed=%t",
					fixture.stage.hasLiveFilterOwnership(),
					fixture.stage.done,
					fixture.plan.stage,
					fixture.plan.closed,
				)
			}
			fixture.owner.assertProgramObservationsBalanced(t)

			// The same real operation gate remains usable after the retained owner
			// is drained.
			if test.action == "apply" {
				retryErr = loader.Apply(context.Background(), nil)
			} else {
				retryErr = loader.Detach(context.Background(), nil)
			}
			if retryErr != nil {
				t.Fatalf("drained %s owner gate: %v", test.action, retryErr)
			}
		})
	}
}

func TestDurableTCOwnerJournalHandoffIsExactAndOneShot(t *testing.T) {
	t.Run("wrong plan does not consume capability", func(t *testing.T) {
		first := newRetainedJournalHandoffFixture(t)
		second := newRetainedJournalHandoffFixture(t)
		if err := transferRetainedStage(first.handoff, second.stage); err == nil ||
			!strings.Contains(err.Error(), "exact stage") {
			t.Fatalf("wrong-plan transfer error = %v", err)
		}
		if err := transferRetainedStage(first.handoff, first.stage); err != nil {
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
		if err := transferRetainedStage(fixture.handoff, fixture.stage); err == nil ||
			!strings.Contains(err.Error(), "outside journal desired") {
			t.Fatalf("coverage mismatch transfer error = %v", err)
		}
		fixture.stage.applied[0].program = original
		if err := transferRetainedStage(fixture.handoff, fixture.stage); err != nil {
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
		if err := transferRetainedStage(fixture.handoff, fixture.stage); err == nil ||
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
		if err := transferRetainedStage(fixture.handoff, fixture.stage); err == nil ||
			!strings.Contains(err.Error(), "mount binding changed") {
			t.Fatalf("mount binding transfer error = %v", err)
		}
		fixture.handoff.mountID--
		if err := transferRetainedStage(fixture.handoff, fixture.stage); err != nil {
			t.Fatalf("exact transfer after mount mismatch: %v", err)
		}
	})

	t.Run("resolved and double transfer are rejected", func(t *testing.T) {
		resolved := newRetainedJournalHandoffFixture(t)
		if err := resolved.stage.Close(); err != nil {
			t.Fatal(err)
		}
		if err := transferRetainedStage(resolved.handoff, resolved.stage); err == nil ||
			!strings.Contains(err.Error(), "already resolved") {
			t.Fatalf("resolved stage transfer error = %v", err)
		}

		doubled := newRetainedJournalHandoffFixture(t)
		if err := transferRetainedStage(doubled.handoff, doubled.stage); err != nil {
			t.Fatal(err)
		}
		if err := transferRetainedStage(doubled.handoff, doubled.stage); err == nil ||
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
			transferErr = transferRetainedStage(fixture.handoff, fixture.stage)
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
