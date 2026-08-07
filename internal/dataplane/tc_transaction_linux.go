//go:build linux

package dataplane

import (
	"errors"
	"fmt"
	"sort"
	"sync"

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
	runtime  tcRuntime
	links    []tcLinkAttachPlan
	stale    []tcOwnedStaleFilter
	ingress  tcProgramIdentity
	egress   tcProgramIdentity
	closed   bool
	executed bool
	stage    *tcAttachStage
}

type tcFilterBinding struct {
	IfIndex   int    `json:"ifindex"`
	Direction string `json:"direction"`
	Parent    uint32 `json:"parent"`
	Handle    uint32 `json:"handle"`
	Priority  uint16 `json:"priority"`
	ProgramID uint32 `json:"program_id"`
}

type tcAppliedFilter struct {
	link     netlink.Link
	snapshot tcFilterSnapshot
	program  tcProgramIdentity
}

type tcOwnedStaleFilter struct {
	key      string
	link     netlink.Link
	snapshot tcFilterSnapshot
}

type tcOwnedCreatedQdisc struct {
	link    netlink.Link
	ifindex int
}

// tcAttachStage retains the exact preflight snapshots and program references
// needed to restore every filter changed by one successful attachment.  It is
// used by unpinned experimental generations whose TC ownership ends with the
// runtime, rather than being transferred to the persistent pin-owner journal.
type tcAttachStage struct {
	mu sync.Mutex

	plan    *tcAttachPlan
	applied []tcAppliedFilter
	deleted []tcOwnedStaleFilter
	created []tcOwnedCreatedQdisc
	done    bool
	err     error
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

func (plan *tcAttachPlan) ObservedBindings() []tcFilterBinding {
	if plan == nil {
		return nil
	}
	var bindings []tcFilterBinding
	for _, linkPlan := range plan.links {
		for _, snapshot := range linkPlan.filters {
			if !snapshot.existed {
				continue
			}
			direction := "ingress"
			if snapshot.slot.parent == netlink.HANDLE_MIN_EGRESS {
				direction = "egress"
			}
			bindings = append(bindings, tcFilterBinding{
				IfIndex:   linkPlan.ifindex,
				Direction: direction,
				Parent:    snapshot.slot.parent,
				Handle:    snapshot.slot.handle,
				Priority:  filterPriority,
				ProgramID: snapshot.programID,
			})
		}
	}
	sortTCFilterBindings(bindings)
	return bindings
}

func (plan *tcAttachPlan) ValidatePreviousBindings(
	active []tcFilterBinding,
	fresh bool,
) error {
	if plan == nil {
		return errors.New("TC attach plan is nil")
	}
	bySlot := make(map[string]tcFilterBinding, len(active))
	for _, binding := range active {
		key := fmt.Sprintf("%d/%s", binding.IfIndex, binding.Direction)
		if _, duplicate := bySlot[key]; duplicate {
			return fmt.Errorf("owner record repeats active TC slot %s", key)
		}
		bySlot[key] = binding
	}
	for _, linkPlan := range plan.links {
		for _, snapshot := range linkPlan.filters {
			direction := "ingress"
			if snapshot.slot.parent == netlink.HANDLE_MIN_EGRESS {
				direction = "egress"
			}
			key := fmt.Sprintf("%d/%s", linkPlan.ifindex, direction)
			binding, recorded := bySlot[key]
			if fresh {
				if snapshot.existed {
					return fmt.Errorf(
						"fresh BPF instance found a pre-existing managed-looking TC filter at %s; refusing ownership",
						key,
					)
				}
				continue
			}
			switch {
			case snapshot.existed && !recorded:
				return fmt.Errorf("TC filter at %s is not owned by the persistent record", key)
			case !snapshot.existed && recorded:
				return fmt.Errorf(
					"owned TC filter at %s with program ID %d is missing",
					key, binding.ProgramID,
				)
			case snapshot.existed && snapshot.programID != binding.ProgramID:
				return fmt.Errorf(
					"TC filter at %s has program ID %d, owner record requires %d",
					key, snapshot.programID, binding.ProgramID,
				)
			}
		}
	}
	return nil
}

func (plan *tcAttachPlan) AddOwnedStaleRemovals(
	active []tcFilterBinding,
) error {
	if plan == nil || plan.closed {
		return errors.New("TC attach plan is unavailable")
	}
	currentSlots := make(map[string]struct{}, len(plan.links)*2)
	for _, linkPlan := range plan.links {
		for _, snapshot := range linkPlan.filters {
			direction := "ingress"
			if snapshot.slot.parent == netlink.HANDLE_MIN_EGRESS {
				direction = "egress"
			}
			currentSlots[fmt.Sprintf("%d/%s", linkPlan.ifindex, direction)] = struct{}{}
		}
	}
	for _, binding := range active {
		key := fmt.Sprintf("%d/%s", binding.IfIndex, binding.Direction)
		if _, remains := currentSlots[key]; remains {
			continue
		}
		slot, err := ownerFilterSlot(binding)
		if err != nil {
			return err
		}
		link, err := plan.runtime.linkByIndex(binding.IfIndex)
		if err != nil {
			return fmt.Errorf("preflight stale owner TC slot %s: %w", key, err)
		}
		if link == nil ||
			link.Attrs() == nil ||
			link.Attrs().Index != binding.IfIndex {
			return fmt.Errorf("preflight stale owner TC slot %s returned a mismatched link", key)
		}
		clsact, err := inspectClsact(link, plan.runtime)
		if err != nil {
			return fmt.Errorf("preflight stale owner clsact %s: %w", key, err)
		}
		if !clsact {
			return fmt.Errorf("owned stale TC slot %s has no clsact", key)
		}
		snapshot, err := inspectTCFilterSlot(link, slot, plan.runtime, true)
		if err != nil {
			return fmt.Errorf("preflight stale owner filter %s: %w", key, err)
		}
		if !snapshot.existed || snapshot.programID != binding.ProgramID {
			if snapshot.oldProgram != nil {
				_ = snapshot.oldProgram.Close()
			}
			return fmt.Errorf(
				"stale owner TC slot %s has program ID %d/present=%t, want %d",
				key, snapshot.programID, snapshot.existed, binding.ProgramID,
			)
		}
		plan.stale = append(plan.stale, tcOwnedStaleFilter{
			key:      key,
			link:     link,
			snapshot: snapshot,
		})
	}
	sort.Slice(plan.stale, func(i, j int) bool {
		return plan.stale[i].key < plan.stale[j].key
	})
	return nil
}

func (plan *tcAttachPlan) Execute(commit func() error) (returnErr error) {
	stage, err := plan.ExecuteRetained(commit)
	if err != nil {
		if stage != nil {
			return errors.Join(err, stage.Close())
		}
		return errors.Join(err, plan.Close())
	}
	// Persistent loader callers transfer rollback responsibility to their
	// owner journal in commit.  Disarm leaves retained program handles with the
	// plan so its existing deferred Close keeps the post-commit path infallible.
	stage.Disarm()
	return nil
}

// ExecuteRetained performs the same preflight-fenced transaction as Execute,
// but success returns rollback ownership instead of discarding it.  On
// success callers must use only the returned stage; plan.Close refuses to
// invalidate the retained program references until the stage is resolved.
func (plan *tcAttachPlan) ExecuteRetained(
	commit func() error,
) (*tcAttachStage, error) {
	if plan == nil {
		return nil, errors.New("TC attach plan is nil")
	}
	if plan.closed {
		return nil, errors.New("TC attach plan is closed")
	}
	if plan.executed {
		return nil, errors.New("TC attach plan has already executed")
	}
	if commit == nil {
		return nil, errors.New("TC activation callback is nil")
	}
	plan.executed = true
	stage := &tcAttachStage{plan: plan}
	fail := func(err error) (*tcAttachStage, error) {
		if len(stage.applied) == 0 && len(stage.deleted) == 0 && len(stage.created) == 0 {
			return nil, err
		}
		plan.stage = stage
		return stage, err
	}

	for index := range plan.links {
		linkPlan := &plan.links[index]
		currentClsact, err := inspectClsact(linkPlan.link, plan.runtime)
		if err != nil {
			return fail(fmt.Errorf("recheck clsact on ifindex %d: %w", linkPlan.ifindex, err))
		}
		if currentClsact != linkPlan.clsactExists {
			return fail(fmt.Errorf("clsact state changed on ifindex %d after preflight", linkPlan.ifindex))
		}
		if !linkPlan.clsactExists {
			qdisc := canonicalClsact(linkPlan.ifindex)
			if err := plan.runtime.qdiscAdd(qdisc); err != nil {
				return fail(fmt.Errorf("add clsact on ifindex %d: %w", linkPlan.ifindex, err))
			}
			stage.created = append(stage.created, tcOwnedCreatedQdisc{
				link: linkPlan.link, ifindex: linkPlan.ifindex,
			})
			present, err := inspectClsact(linkPlan.link, plan.runtime)
			if err != nil {
				return fail(fmt.Errorf("verify clsact on ifindex %d: %w", linkPlan.ifindex, err))
			}
			if !present {
				return fail(fmt.Errorf("clsact did not appear on ifindex %d", linkPlan.ifindex))
			}
		}

		for _, snapshot := range linkPlan.filters {
			if err := plan.recheckFilterSnapshot(linkPlan.link, snapshot); err != nil {
				return fail(fmt.Errorf(
					"recheck %s on ifindex %d before mutation: %w",
					snapshot.slot.name, linkPlan.ifindex, err,
				))
			}
			program := plan.programForSlot(snapshot.slot)
			filter := managedBpfFilter(linkPlan.ifindex, snapshot.slot, program.fd)
			if snapshot.existed {
				if err := plan.runtime.filterReplace(filter); err != nil {
					return fail(fmt.Errorf(
						"replace %s on ifindex %d: %w",
						snapshot.slot.name, linkPlan.ifindex, err,
					))
				}
			} else if err := plan.runtime.filterAdd(filter); err != nil {
				return fail(fmt.Errorf(
					"add %s on ifindex %d: %w",
					snapshot.slot.name, linkPlan.ifindex, err,
				))
			}
			stage.applied = append(stage.applied, tcAppliedFilter{
				link:     linkPlan.link,
				snapshot: snapshot,
				program:  program,
			})
			if err := plan.verifyManagedFilter(
				linkPlan.link,
				snapshot.slot,
				program.id,
			); err != nil {
				return fail(fmt.Errorf(
					"verify %s on ifindex %d after mutation: %w",
					snapshot.slot.name, linkPlan.ifindex, err,
				))
			}
		}
	}
	for _, stale := range plan.stale {
		if err := plan.recheckFilterSnapshot(
			stale.link,
			stale.snapshot,
		); err != nil {
			return fail(fmt.Errorf(
				"recheck stale owner TC slot %s before delete: %w",
				stale.key, err,
			))
		}
		filter := managedBpfFilter(
			stale.link.Attrs().Index,
			stale.snapshot.slot,
			stale.snapshot.oldProgram.FD(),
		).(*netlink.BpfFilter)
		filter.FilterAttrs = stale.snapshot.attrs
		filter.ClassId = stale.snapshot.classID
		filter.Id = int(stale.snapshot.programID)
		if err := plan.runtime.filterDelete(filter); err != nil {
			return fail(fmt.Errorf("delete stale owner TC slot %s: %w", stale.key, err))
		}
		stage.deleted = append(stage.deleted, stale)
		after, err := inspectTCFilterSlot(
			stale.link,
			stale.snapshot.slot,
			plan.runtime,
			false,
		)
		if err != nil {
			return fail(err)
		}
		if after.existed {
			return fail(fmt.Errorf(
				"stale owner TC slot %s remains after delete",
				stale.key,
			))
		}
	}
	if err := commit(); err != nil {
		return fail(fmt.Errorf("activate attached TC programs: %w", err))
	}
	plan.stage = stage
	return stage, nil
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

func (plan *tcAttachPlan) rollbackRetained(stage *tcAttachStage) error {
	if plan == nil || stage == nil {
		return errors.New("rollback retained TC attachment: owner is nil")
	}
	var errs []error
	var remainingDeleted []tcOwnedStaleFilter
	for index := len(stage.deleted) - 1; index >= 0; index-- {
		change := stage.deleted[index]
		complete, err := plan.restoreDeletedFilter(change)
		if err != nil {
			errs = append(errs, err)
		}
		if !complete {
			remainingDeleted = append([]tcOwnedStaleFilter{change}, remainingDeleted...)
		}
	}
	stage.deleted = remainingDeleted

	var remainingApplied []tcAppliedFilter
	for index := len(stage.applied) - 1; index >= 0; index-- {
		change := stage.applied[index]
		complete, err := plan.restoreAppliedFilter(change)
		if err != nil {
			errs = append(errs, err)
		}
		if !complete {
			remainingApplied = append([]tcAppliedFilter{change}, remainingApplied...)
		}
	}
	stage.applied = remainingApplied

	// clsact is a shared, identity-less kernel scaffold. RTM_DELQDISC matches
	// only ifindex/handle/parent and atomically removes every child filter, so
	// userspace cannot prove that a canonical clsact observed before deletion
	// is still the one this transaction created. Preserve the harmless empty
	// scaffold; exact program ownership is handled separately.
	stage.created = nil
	return errors.Join(errs...)
}

func (plan *tcAttachPlan) restoreDeletedFilter(
	change tcOwnedStaleFilter,
) (bool, error) {
	current, err := inspectTCFilterSlot(
		change.link, change.snapshot.slot, plan.runtime, false,
	)
	if err != nil {
		return false, fmt.Errorf("inspect stale owner TC slot %s during restore: %w", change.key, err)
	}
	if current.existed {
		if current.programID == change.snapshot.programID {
			return true, nil
		}
		return false, fmt.Errorf(
			"refuse restore of stale owner TC slot %s because it was repopulated with program ID %d",
			change.key, current.programID,
		)
	}
	if change.snapshot.oldProgram == nil || change.snapshot.oldProgram.FD() < 0 {
		return false, fmt.Errorf("restore stale owner TC slot %s: retained program is unavailable", change.key)
	}
	filter := managedBpfFilter(
		change.link.Attrs().Index,
		change.snapshot.slot,
		change.snapshot.oldProgram.FD(),
	).(*netlink.BpfFilter)
	filter.FilterAttrs = change.snapshot.attrs
	filter.ClassId = change.snapshot.classID
	if err := plan.runtime.filterAdd(filter); err != nil {
		return false, fmt.Errorf("restore stale owner TC slot %s: %w", change.key, err)
	}
	if err := plan.verifyManagedFilter(
		change.link, change.snapshot.slot, change.snapshot.programID,
	); err != nil {
		return false, fmt.Errorf("verify restored stale owner TC slot %s: %w", change.key, err)
	}
	return true, nil
}

func (plan *tcAttachPlan) restoreAppliedFilter(
	change tcAppliedFilter,
) (bool, error) {
	ifindex := change.link.Attrs().Index
	current, err := inspectTCFilterSlot(
		change.link, change.snapshot.slot, plan.runtime, false,
	)
	if err != nil {
		return false, fmt.Errorf(
			"inspect %s on ifindex %d during rollback: %w",
			change.snapshot.slot.name, ifindex, err,
		)
	}
	if change.snapshot.existed {
		switch {
		case current.existed && current.programID == change.snapshot.programID:
			return true, nil
		case !current.existed:
			return false, fmt.Errorf(
				"refuse rollback of %s on ifindex %d because the owned slot disappeared",
				change.snapshot.slot.name, ifindex,
			)
		case current.programID != change.program.id:
			return false, fmt.Errorf(
				"refuse rollback of %s on ifindex %d because program ID changed to %d",
				change.snapshot.slot.name, ifindex, current.programID,
			)
		case change.snapshot.oldProgram == nil || change.snapshot.oldProgram.FD() < 0:
			return false, fmt.Errorf(
				"restore %s on ifindex %d: retained program is unavailable",
				change.snapshot.slot.name, ifindex,
			)
		}
		filter := managedBpfFilter(
			ifindex,
			change.snapshot.slot,
			change.snapshot.oldProgram.FD(),
		).(*netlink.BpfFilter)
		filter.FilterAttrs = change.snapshot.attrs
		filter.ClassId = change.snapshot.classID
		if err := plan.runtime.filterReplace(filter); err != nil {
			return false, fmt.Errorf(
				"restore %s on ifindex %d: %w",
				change.snapshot.slot.name, ifindex, err,
			)
		}
		if err := plan.verifyManagedFilter(
			change.link, change.snapshot.slot, change.snapshot.programID,
		); err != nil {
			return false, fmt.Errorf(
				"verify restored %s on ifindex %d: %w",
				change.snapshot.slot.name, ifindex, err,
			)
		}
		return true, nil
	}

	if !current.existed {
		return true, nil
	}
	if current.programID != change.program.id {
		return false, fmt.Errorf(
			"refuse rollback of %s on ifindex %d because program ID changed to %d",
			change.snapshot.slot.name, ifindex, current.programID,
		)
	}
	filter := managedBpfFilter(ifindex, change.snapshot.slot, change.program.fd)
	filter.(*netlink.BpfFilter).Id = int(current.programID)
	if err := plan.runtime.filterDelete(filter); err != nil && !isNotFound(err) {
		return false, fmt.Errorf(
			"delete newly added %s on ifindex %d: %w",
			change.snapshot.slot.name, ifindex, err,
		)
	}
	after, err := inspectTCFilterSlot(
		change.link, change.snapshot.slot, plan.runtime, false,
	)
	if err != nil {
		return false, fmt.Errorf(
			"verify deleted %s on ifindex %d: %w",
			change.snapshot.slot.name, ifindex, err,
		)
	}
	if after.existed {
		return false, fmt.Errorf(
			"newly added %s remains on ifindex %d after rollback",
			change.snapshot.slot.name, ifindex,
		)
	}
	return true, nil
}

func (plan *tcAttachPlan) Close() error {
	if plan == nil || plan.closed {
		return nil
	}
	if plan.stage != nil {
		return errors.New("TC attach plan is owned by a retained stage")
	}
	return plan.closeProgramReferences()
}

func (plan *tcAttachPlan) closeProgramReferences() error {
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
	for index := range plan.stale {
		program := plan.stale[index].snapshot.oldProgram
		if program == nil {
			continue
		}
		if err := program.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close retained stale TC program: %w", err))
		}
		plan.stale[index].snapshot.oldProgram = nil
	}
	return errors.Join(errs...)
}

// Close restores the exact prior filter set in reverse mutation order and
// then closes every retained prior-program reference.  A slot that no longer
// contains this stage's program is preserved and reported instead of being
// overwritten.
func (stage *tcAttachStage) Close() error {
	if stage == nil {
		return nil
	}
	stage.mu.Lock()
	defer stage.mu.Unlock()
	if stage.done {
		return stage.err
	}
	if stage.plan == nil {
		stage.err = errors.New("retained TC attach stage has no plan")
		return stage.err
	}
	plan := stage.plan
	if err := plan.rollbackRetained(stage); err != nil {
		stage.err = fmt.Errorf("rollback retained TC attachment: %w", err)
		return stage.err
	}
	stage.done = true
	plan.stage = nil
	stage.err = plan.closeProgramReferences()
	stage.plan = nil
	stage.applied = nil
	stage.deleted = nil
	stage.created = nil
	return stage.err
}

// Disarm transfers rollback responsibility out of a retained stage.  It is
// intentionally infallible and performs no close so a commit callback remains
// the final fallible operation in the persistent loader transaction.
func (stage *tcAttachStage) Disarm() {
	if stage == nil {
		return
	}
	stage.mu.Lock()
	defer stage.mu.Unlock()
	if stage.done {
		return
	}
	stage.done = true
	if stage.plan != nil && stage.plan.stage == stage {
		stage.plan.stage = nil
	}
	stage.plan = nil
	stage.applied = nil
	stage.deleted = nil
	stage.created = nil
}
