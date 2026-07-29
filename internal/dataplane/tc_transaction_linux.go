//go:build linux

package dataplane

import (
	"errors"
	"fmt"
	"sort"

	"github.com/cilium/ebpf"
	"github.com/syx0310/wg-mix-ebpf/internal/control"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type tcProgramRef interface {
	FD() int
	Close() error
}

type tcProgramIdentity struct {
	fd int
	id uint32
}

type tcRuntime struct {
	linkByIndex   func(int) (netlink.Link, error)
	qdiscList     func(netlink.Link) ([]netlink.Qdisc, error)
	qdiscAdd      func(netlink.Qdisc) error
	filterList    func(netlink.Link, uint32) ([]netlink.Filter, error)
	filterAdd     func(netlink.Filter) error
	filterReplace func(netlink.Filter) error
	filterDelete  func(netlink.Filter) error
	loadProgram   func(uint32) (tcProgramRef, error)
}

var liveTCRuntime = tcRuntime{
	linkByIndex:   netlink.LinkByIndex,
	qdiscList:     netlink.QdiscList,
	qdiscAdd:      netlink.QdiscAdd,
	filterList:    netlink.FilterList,
	filterAdd:     netlink.FilterAdd,
	filterReplace: netlink.FilterReplace,
	filterDelete:  netlink.FilterDel,
	loadProgram: func(id uint32) (tcProgramRef, error) {
		return ebpf.NewProgramFromID(ebpf.ProgramID(id))
	},
}

type tcFilterSlot struct {
	parent uint32
	handle uint32
	name   string
}

type tcFilterSnapshot struct {
	slot       tcFilterSlot
	existed    bool
	programID  uint32
	oldProgram tcProgramRef
	attrs      netlink.FilterAttrs
	classID    uint32
}

type tcLinkAttachPlan struct {
	ifindex      int
	link         netlink.Link
	clsactExists bool
	filters      []tcFilterSnapshot
}

type tcAttachPlan struct {
	runtime tcRuntime
	links   []tcLinkAttachPlan
	ingress tcProgramIdentity
	egress  tcProgramIdentity
	closed  bool
}

type tcFilterBinding struct {
	IfIndex   int
	Direction string
	Parent    uint32
	Handle    uint32
	Priority  uint16
	ProgramID uint32
}

type tcAppliedFilter struct {
	link     netlink.Link
	snapshot tcFilterSnapshot
	program  tcProgramIdentity
}

func tcProgramIdentityFromProgram(program *ebpf.Program) (tcProgramIdentity, error) {
	if program == nil {
		return tcProgramIdentity{}, errors.New("TC program is nil")
	}
	info, err := program.Info()
	if err != nil {
		return tcProgramIdentity{}, fmt.Errorf("inspect TC program: %w", err)
	}
	id, ok := info.ID()
	if !ok || id == 0 {
		return tcProgramIdentity{}, errors.New("TC program has no stable kernel ID")
	}
	return tcProgramIdentity{fd: program.FD(), id: uint32(id)}, nil
}

func activeAttachIfindexes(state *control.State) ([]int, error) {
	if state == nil {
		return nil, nil
	}
	seen := make(map[int]string)
	var ifindexes []int
	for _, underlay := range state.Underlays {
		if !underlay.Resolved || underlay.Role == "parse_only" || underlay.Role == "disabled" {
			continue
		}
		if underlay.IfIndex <= 0 {
			return nil, fmt.Errorf("underlay %s has invalid ifindex %d", underlay.Name, underlay.IfIndex)
		}
		if previous, exists := seen[underlay.IfIndex]; exists {
			return nil, fmt.Errorf(
				"underlays %s and %s resolve to duplicate ifindex %d",
				previous, underlay.Name, underlay.IfIndex,
			)
		}
		seen[underlay.IfIndex] = underlay.Name
		ifindexes = append(ifindexes, underlay.IfIndex)
	}
	sort.Ints(ifindexes)
	return ifindexes, nil
}

func prepareTCAttachPlan(
	state *control.State,
	ingress tcProgramIdentity,
	egress tcProgramIdentity,
	runtime tcRuntime,
) (*tcAttachPlan, error) {
	if ingress.fd < 0 || ingress.id == 0 || egress.fd < 0 || egress.id == 0 {
		return nil, errors.New("TC attach requires non-zero program IDs and valid program FDs")
	}
	if err := validateTCRuntime(runtime); err != nil {
		return nil, err
	}
	ifindexes, err := activeAttachIfindexes(state)
	if err != nil {
		return nil, err
	}
	plan := &tcAttachPlan{
		runtime: runtime,
		ingress: ingress,
		egress:  egress,
	}
	closeOnError := func() {
		_ = plan.Close()
	}
	for _, ifindex := range ifindexes {
		link, err := runtime.linkByIndex(ifindex)
		if err != nil {
			closeOnError()
			return nil, fmt.Errorf("preflight underlay ifindex %d: %w", ifindex, err)
		}
		if link == nil || link.Attrs() == nil || link.Attrs().Index != ifindex {
			closeOnError()
			return nil, fmt.Errorf("preflight underlay ifindex %d returned a mismatched link", ifindex)
		}
		clsactExists, err := inspectClsact(link, runtime)
		if err != nil {
			closeOnError()
			return nil, fmt.Errorf("preflight clsact on ifindex %d: %w", ifindex, err)
		}
		linkPlan := tcLinkAttachPlan{
			ifindex:      ifindex,
			link:         link,
			clsactExists: clsactExists,
		}
		for _, slot := range canonicalTCFilterSlots() {
			snapshot, err := inspectTCFilterSlot(link, slot, runtime, true)
			if err != nil {
				closeOnError()
				return nil, fmt.Errorf(
					"preflight %s filter on ifindex %d: %w",
					slot.name, ifindex, err,
				)
			}
			linkPlan.filters = append(linkPlan.filters, snapshot)
		}
		plan.links = append(plan.links, linkPlan)
	}
	return plan, nil
}

func validateTCRuntime(runtime tcRuntime) error {
	if runtime.linkByIndex == nil || runtime.qdiscList == nil || runtime.qdiscAdd == nil ||
		runtime.filterList == nil || runtime.filterAdd == nil ||
		runtime.filterReplace == nil || runtime.filterDelete == nil ||
		runtime.loadProgram == nil {
		return errors.New("TC transaction runtime is incomplete")
	}
	return nil
}

func canonicalTCFilterSlots() []tcFilterSlot {
	return []tcFilterSlot{
		{
			parent: netlink.HANDLE_MIN_INGRESS,
			handle: ingressHandle,
			name:   ingressFilterName,
		},
		{
			parent: netlink.HANDLE_MIN_EGRESS,
			handle: egressHandle,
			name:   egressFilterName,
		},
	}
}

func inspectClsact(link netlink.Link, runtime tcRuntime) (bool, error) {
	qdiscs, err := runtime.qdiscList(link)
	if err != nil {
		return false, err
	}
	count := 0
	for _, qdisc := range qdiscs {
		if qdisc == nil || qdisc.Attrs() == nil {
			return false, errors.New("kernel returned a nil qdisc")
		}
		attrs := qdisc.Attrs()
		collides := attrs.Handle == netlink.MakeHandle(0xffff, 0) ||
			attrs.Parent == netlink.HANDLE_CLSACT ||
			qdisc.Type() == "clsact"
		if !collides {
			continue
		}
		if qdisc.Type() != "clsact" ||
			attrs.LinkIndex != link.Attrs().Index ||
			attrs.Handle != netlink.MakeHandle(0xffff, 0) ||
			attrs.Parent != netlink.HANDLE_CLSACT {
			return false, fmt.Errorf(
				"foreign qdisc collides with the clsact slot: type=%s link=%d handle=%#x parent=%#x",
				qdisc.Type(), attrs.LinkIndex, attrs.Handle, attrs.Parent,
			)
		}
		count++
	}
	if count > 1 {
		return false, fmt.Errorf("duplicate clsact qdiscs: found %d", count)
	}
	return count == 1, nil
}

func inspectTCFilterSlot(
	link netlink.Link,
	slot tcFilterSlot,
	runtime tcRuntime,
	retainProgram bool,
) (tcFilterSnapshot, error) {
	filters, err := runtime.filterList(link, slot.parent)
	if err != nil {
		return tcFilterSnapshot{}, err
	}
	snapshot := tcFilterSnapshot{slot: slot}
	matches := 0
	for _, filter := range filters {
		if filter == nil || filter.Attrs() == nil {
			return tcFilterSnapshot{}, errors.New("kernel returned a nil TC filter")
		}
		attrs := filter.Attrs()
		bpfFilter, isBPF := filter.(*netlink.BpfFilter)
		nameMatches := isBPF && bpfFilter.Name == slot.name
		handleMatches := attrs.Handle == slot.handle
		if !nameMatches && !handleMatches {
			continue
		}
		if !isBPF ||
			bpfFilter.Name != slot.name ||
			attrs.LinkIndex != link.Attrs().Index ||
			attrs.Parent != slot.parent ||
			attrs.Handle != slot.handle ||
			attrs.Priority != filterPriority ||
			attrs.Protocol != unix.ETH_P_ALL ||
			!bpfFilter.DirectAction ||
			bpfFilter.Id <= 0 {
			return tcFilterSnapshot{}, fmt.Errorf(
				"foreign filter collides with managed slot name=%s handle=%#x",
				slot.name, slot.handle,
			)
		}
		matches++
		snapshot.existed = true
		snapshot.programID = uint32(bpfFilter.Id)
		snapshot.attrs = *attrs
		snapshot.classID = bpfFilter.ClassId
	}
	if matches > 1 {
		return tcFilterSnapshot{}, fmt.Errorf(
			"duplicate managed filters name=%s handle=%#x: found %d",
			slot.name, slot.handle, matches,
		)
	}
	if snapshot.existed && retainProgram {
		program, err := runtime.loadProgram(snapshot.programID)
		if err != nil {
			return tcFilterSnapshot{}, fmt.Errorf(
				"retain old program ID %d for %s: %w",
				snapshot.programID, slot.name, err,
			)
		}
		if program == nil || program.FD() < 0 {
			if program != nil {
				_ = program.Close()
			}
			return tcFilterSnapshot{}, fmt.Errorf(
				"retain old program ID %d for %s returned an invalid FD",
				snapshot.programID, slot.name,
			)
		}
		snapshot.oldProgram = program
	}
	return snapshot, nil
}

func (plan *tcAttachPlan) Bindings() []tcFilterBinding {
	if plan == nil {
		return nil
	}
	bindings := make([]tcFilterBinding, 0, len(plan.links)*2)
	for _, linkPlan := range plan.links {
		for _, slot := range linkPlan.filters {
			program := plan.programForSlot(slot.slot)
			direction := "ingress"
			if slot.slot.parent == netlink.HANDLE_MIN_EGRESS {
				direction = "egress"
			}
			bindings = append(bindings, tcFilterBinding{
				IfIndex:   linkPlan.ifindex,
				Direction: direction,
				Parent:    slot.slot.parent,
				Handle:    slot.slot.handle,
				Priority:  filterPriority,
				ProgramID: program.id,
			})
		}
	}
	return bindings
}

func (plan *tcAttachPlan) Execute(commit func() error) (returnErr error) {
	if plan == nil {
		return errors.New("TC attach plan is nil")
	}
	if plan.closed {
		return errors.New("TC attach plan is closed")
	}
	if commit == nil {
		return errors.New("TC activation callback is nil")
	}
	var applied []tcAppliedFilter
	defer func() {
		if returnErr == nil {
			return
		}
		rollbackErr := plan.rollback(applied)
		if rollbackErr != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("rollback TC attachment transaction: %w", rollbackErr))
		}
	}()

	for index := range plan.links {
		linkPlan := &plan.links[index]
		currentClsact, err := inspectClsact(linkPlan.link, plan.runtime)
		if err != nil {
			return fmt.Errorf("recheck clsact on ifindex %d: %w", linkPlan.ifindex, err)
		}
		if currentClsact != linkPlan.clsactExists {
			return fmt.Errorf("clsact state changed on ifindex %d after preflight", linkPlan.ifindex)
		}
		if !linkPlan.clsactExists {
			qdisc := canonicalClsact(linkPlan.ifindex)
			if err := plan.runtime.qdiscAdd(qdisc); err != nil {
				return fmt.Errorf("add clsact on ifindex %d: %w", linkPlan.ifindex, err)
			}
			present, err := inspectClsact(linkPlan.link, plan.runtime)
			if err != nil {
				return fmt.Errorf("verify clsact on ifindex %d: %w", linkPlan.ifindex, err)
			}
			if !present {
				return fmt.Errorf("clsact did not appear on ifindex %d", linkPlan.ifindex)
			}
		}

		for _, snapshot := range linkPlan.filters {
			if err := plan.recheckFilterSnapshot(linkPlan.link, snapshot); err != nil {
				return fmt.Errorf(
					"recheck %s on ifindex %d before mutation: %w",
					snapshot.slot.name, linkPlan.ifindex, err,
				)
			}
			program := plan.programForSlot(snapshot.slot)
			filter := managedBpfFilter(linkPlan.ifindex, snapshot.slot, program.fd)
			if snapshot.existed {
				if err := plan.runtime.filterReplace(filter); err != nil {
					return fmt.Errorf(
						"replace %s on ifindex %d: %w",
						snapshot.slot.name, linkPlan.ifindex, err,
					)
				}
			} else if err := plan.runtime.filterAdd(filter); err != nil {
				return fmt.Errorf(
					"add %s on ifindex %d: %w",
					snapshot.slot.name, linkPlan.ifindex, err,
				)
			}
			applied = append(applied, tcAppliedFilter{
				link:     linkPlan.link,
				snapshot: snapshot,
				program:  program,
			})
			if err := plan.verifyManagedFilter(
				linkPlan.link,
				snapshot.slot,
				program.id,
			); err != nil {
				return fmt.Errorf(
					"verify %s on ifindex %d after mutation: %w",
					snapshot.slot.name, linkPlan.ifindex, err,
				)
			}
		}
	}
	if err := commit(); err != nil {
		return fmt.Errorf("activate attached TC programs: %w", err)
	}
	return nil
}

func canonicalClsact(ifindex int) netlink.Qdisc {
	return &netlink.Clsact{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: ifindex,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
	}
}

func managedBpfFilter(ifindex int, slot tcFilterSlot, fd int) netlink.Filter {
	return &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifindex,
			Parent:    slot.parent,
			Handle:    slot.handle,
			Protocol:  unix.ETH_P_ALL,
			Priority:  filterPriority,
		},
		Fd:           fd,
		Name:         slot.name,
		DirectAction: true,
	}
}

func (plan *tcAttachPlan) programForSlot(slot tcFilterSlot) tcProgramIdentity {
	if slot.parent == netlink.HANDLE_MIN_EGRESS {
		return plan.egress
	}
	return plan.ingress
}

func (plan *tcAttachPlan) recheckFilterSnapshot(
	link netlink.Link,
	want tcFilterSnapshot,
) error {
	current, err := inspectTCFilterSlot(link, want.slot, plan.runtime, false)
	if err != nil {
		return err
	}
	if current.existed != want.existed {
		return errors.New("filter presence changed after preflight")
	}
	if current.existed && current.programID != want.programID {
		return fmt.Errorf(
			"filter program changed from ID %d to %d after preflight",
			want.programID, current.programID,
		)
	}
	return nil
}

func (plan *tcAttachPlan) verifyManagedFilter(
	link netlink.Link,
	slot tcFilterSlot,
	programID uint32,
) error {
	current, err := inspectTCFilterSlot(link, slot, plan.runtime, false)
	if err != nil {
		return err
	}
	if !current.existed {
		return errors.New("managed filter is absent")
	}
	if current.programID != programID {
		return fmt.Errorf(
			"managed filter has program ID %d, want %d",
			current.programID, programID,
		)
	}
	return nil
}

func (plan *tcAttachPlan) rollback(applied []tcAppliedFilter) error {
	var errs []error
	for index := len(applied) - 1; index >= 0; index-- {
		change := applied[index]
		if err := plan.verifyManagedFilter(
			change.link,
			change.snapshot.slot,
			change.program.id,
		); err != nil {
			errs = append(errs, fmt.Errorf(
				"refuse rollback of %s on ifindex %d because the slot changed: %w",
				change.snapshot.slot.name, change.link.Attrs().Index, err,
			))
			continue
		}
		if change.snapshot.existed {
			filter := managedBpfFilter(
				change.link.Attrs().Index,
				change.snapshot.slot,
				change.snapshot.oldProgram.FD(),
			).(*netlink.BpfFilter)
			filter.FilterAttrs = change.snapshot.attrs
			filter.ClassId = change.snapshot.classID
			if err := plan.runtime.filterReplace(filter); err != nil {
				errs = append(errs, fmt.Errorf(
					"restore %s on ifindex %d: %w",
					change.snapshot.slot.name, change.link.Attrs().Index, err,
				))
				continue
			}
			if err := plan.verifyManagedFilter(
				change.link,
				change.snapshot.slot,
				change.snapshot.programID,
			); err != nil {
				errs = append(errs, fmt.Errorf(
					"verify restored %s on ifindex %d: %w",
					change.snapshot.slot.name, change.link.Attrs().Index, err,
				))
			}
			continue
		}
		current, err := inspectTCFilterSlot(
			change.link,
			change.snapshot.slot,
			plan.runtime,
			false,
		)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		filter := managedBpfFilter(
			change.link.Attrs().Index,
			change.snapshot.slot,
			change.program.fd,
		)
		filter.(*netlink.BpfFilter).Id = int(current.programID)
		if err := plan.runtime.filterDelete(filter); err != nil && !isNotFound(err) {
			errs = append(errs, fmt.Errorf(
				"delete newly added %s on ifindex %d: %w",
				change.snapshot.slot.name, change.link.Attrs().Index, err,
			))
			continue
		}
		after, err := inspectTCFilterSlot(
			change.link,
			change.snapshot.slot,
			plan.runtime,
			false,
		)
		if err != nil {
			errs = append(errs, err)
		} else if after.existed {
			errs = append(errs, fmt.Errorf(
				"newly added %s remains on ifindex %d after rollback",
				change.snapshot.slot.name, change.link.Attrs().Index,
			))
		}
	}
	return errors.Join(errs...)
}

func (plan *tcAttachPlan) Close() error {
	if plan == nil || plan.closed {
		return nil
	}
	plan.closed = true
	var errs []error
	for linkIndex := range plan.links {
		for filterIndex := range plan.links[linkIndex].filters {
			program := plan.links[linkIndex].filters[filterIndex].oldProgram
			if program == nil {
				continue
			}
			if err := program.Close(); err != nil {
				errs = append(errs, fmt.Errorf("close retained old TC program: %w", err))
			}
			plan.links[linkIndex].filters[filterIndex].oldProgram = nil
		}
	}
	return errors.Join(errs...)
}
