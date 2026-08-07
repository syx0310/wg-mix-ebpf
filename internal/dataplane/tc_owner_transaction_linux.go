//go:build linux

package dataplane

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"sort"

	"github.com/vishvananda/netlink"
)

type ownerTCTransition int

const (
	ownerTCApplyTransition ownerTCTransition = iota
	ownerTCDetachTransition
)

type ownerTCSlotObservation struct {
	key          string
	link         netlink.Link
	slot         tcFilterSlot
	clsactExists bool
	snapshot     tcFilterSnapshot
	active       *tcFilterBinding
	desired      *tcFilterBinding
}

type loadedOwnerPrograms struct {
	observations []*pinnedProgramObservation
	byID         map[uint32]*pinnedProgramObservation
}

func (programs *loadedOwnerPrograms) Close() error {
	if programs == nil {
		return nil
	}
	var errs []error
	for _, observation := range programs.observations {
		if err := observation.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	programs.observations = nil
	programs.byID = nil
	return errors.Join(errs...)
}

func loadOwnerPrograms(
	handle *pinPathHandle,
	record *pinOwnerRecord,
) (*loadedOwnerPrograms, error) {
	if handle == nil || record == nil {
		return nil, errors.New("load owner programs requires a handle and record")
	}
	loaded := &loadedOwnerPrograms{
		byID: make(map[uint32]*pinnedProgramObservation),
	}
	if len(record.ProgramStages) == 0 {
		return loaded, nil
	}
	if handle.runtime.loadPinnedProgram == nil {
		return nil, errors.New("pinned-program loader is unavailable")
	}
	closeOnError := func(err error) (*loadedOwnerPrograms, error) {
		return nil, errors.Join(err, loaded.Close())
	}
	for _, stage := range record.ProgramStages {
		fileName, err := validateOwnerProgramRecoveryStage(handle, record, stage)
		if err != nil {
			return closeOnError(err)
		}
		observation, err := handle.runtime.loadPinnedProgram(
			filepath.Join(handle.procPath(), fileName),
		)
		if err != nil {
			return closeOnError(fmt.Errorf(
				"load owner program stage %s: %w",
				fileName, err,
			))
		}
		loaded.observations = append(loaded.observations, observation)
		if observation == nil ||
			observation.fd < 0 ||
			observation.id != stage.ProgramID {
			return closeOnError(fmt.Errorf(
				"owner program stage %s returned invalid FD/ID",
				stage.FileName,
			))
		}
		if previous, exists := loaded.byID[stage.ProgramID]; exists {
			// The active and desired stage may intentionally reference the same
			// program. Keep one FD but retain both observations until Close.
			if previous.id != observation.id {
				return closeOnError(fmt.Errorf(
					"owner program ID %d changed between stage pins",
					stage.ProgramID,
				))
			}
			continue
		}
		loaded.byID[stage.ProgramID] = observation
	}
	return loaded, nil
}

func ownerFilterSlot(binding tcFilterBinding) (tcFilterSlot, error) {
	for _, slot := range canonicalTCFilterSlots() {
		direction := "ingress"
		if slot.parent == netlink.HANDLE_MIN_EGRESS {
			direction = "egress"
		}
		if binding.Direction != direction {
			continue
		}
		if binding.Parent != slot.parent ||
			binding.Handle != slot.handle ||
			binding.Priority != filterPriority {
			return tcFilterSlot{}, fmt.Errorf(
				"owner filter %d/%s does not use its canonical slot",
				binding.IfIndex, binding.Direction,
			)
		}
		return slot, nil
	}
	return tcFilterSlot{}, fmt.Errorf(
		"owner filter %d has invalid direction %q",
		binding.IfIndex, binding.Direction,
	)
}

func ownerFilterKey(binding tcFilterBinding) string {
	return fmt.Sprintf("%010d/%s", binding.IfIndex, binding.Direction)
}

func ownerBindingMap(
	bindings []tcFilterBinding,
) (map[string]tcFilterBinding, error) {
	out := make(map[string]tcFilterBinding, len(bindings))
	for _, binding := range bindings {
		if binding.IfIndex <= 0 || binding.ProgramID == 0 {
			return nil, errors.New("owner filter has an invalid ifindex or program ID")
		}
		if _, err := ownerFilterSlot(binding); err != nil {
			return nil, err
		}
		key := ownerFilterKey(binding)
		if _, duplicate := out[key]; duplicate {
			return nil, fmt.Errorf("owner filters repeat slot %s", key)
		}
		out[key] = binding
	}
	return out, nil
}

func inspectOwnerTCTransition(
	activeBindings []tcFilterBinding,
	desiredBindings []tcFilterBinding,
	transition ownerTCTransition,
	runtime tcRuntime,
) ([]ownerTCSlotObservation, error) {
	if err := validateTCRuntime(runtime); err != nil {
		return nil, err
	}
	active, err := ownerBindingMap(activeBindings)
	if err != nil {
		return nil, err
	}
	desired, err := ownerBindingMap(desiredBindings)
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(active)+len(desired))
	seen := make(map[string]struct{}, len(active)+len(desired))
	for key := range active {
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	for key := range desired {
		if _, ok := seen[key]; ok {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)

	links := make(map[int]netlink.Link)
	clsacts := make(map[int]bool)
	observations := make([]ownerTCSlotObservation, 0, len(keys))
	for _, key := range keys {
		activeBinding, hasActive := active[key]
		desiredBinding, hasDesired := desired[key]
		reference := activeBinding
		if !hasActive {
			reference = desiredBinding
		}
		link := links[reference.IfIndex]
		if link == nil {
			link, err = runtime.linkByIndex(reference.IfIndex)
			if err != nil {
				return nil, fmt.Errorf(
					"inspect owner TC link %d: %w",
					reference.IfIndex, err,
				)
			}
			if link == nil ||
				link.Attrs() == nil ||
				link.Attrs().Index != reference.IfIndex {
				return nil, fmt.Errorf(
					"owner TC link lookup returned a mismatch for ifindex %d",
					reference.IfIndex,
				)
			}
			links[reference.IfIndex] = link
			clsactExists, err := inspectClsact(link, runtime)
			if err != nil {
				return nil, fmt.Errorf(
					"inspect owner clsact on ifindex %d: %w",
					reference.IfIndex, err,
				)
			}
			clsacts[reference.IfIndex] = clsactExists
		}
		slot, err := ownerFilterSlot(reference)
		if err != nil {
			return nil, err
		}
		snapshot, err := inspectTCFilterSlot(link, slot, runtime, false)
		if err != nil {
			return nil, fmt.Errorf("inspect owner TC slot %s: %w", key, err)
		}
		if snapshot.existed {
			matchesActive := hasActive && snapshot.programID == activeBinding.ProgramID
			matchesDesired := hasDesired && snapshot.programID == desiredBinding.ProgramID
			if !matchesActive && !matchesDesired {
				return nil, fmt.Errorf(
					"owner TC slot %s has program ID %d outside journal old/new set",
					key, snapshot.programID,
				)
			}
		} else if hasActive &&
			hasDesired &&
			transition == ownerTCApplyTransition {
			return nil, fmt.Errorf(
				"owner TC slot %s disappeared during apply transaction",
				key,
			)
		}
		activePointer := (*tcFilterBinding)(nil)
		if hasActive {
			value := activeBinding
			activePointer = &value
		}
		desiredPointer := (*tcFilterBinding)(nil)
		if hasDesired {
			value := desiredBinding
			desiredPointer = &value
		}
		observations = append(observations, ownerTCSlotObservation{
			key:          key,
			link:         link,
			slot:         slot,
			clsactExists: clsacts[reference.IfIndex],
			snapshot:     snapshot,
			active:       activePointer,
			desired:      desiredPointer,
		})
	}
	return observations, nil
}

func validateOwnerTCExact(
	bindings []tcFilterBinding,
	covered []tcFilterBinding,
	runtime tcRuntime,
) error {
	observations, err := inspectOwnerTCTransition(
		covered,
		bindings,
		ownerTCDetachTransition,
		runtime,
	)
	if err != nil {
		return err
	}
	want, err := ownerBindingMap(bindings)
	if err != nil {
		return err
	}
	for _, observation := range observations {
		binding, expected := want[observation.key]
		switch {
		case expected && !observation.snapshot.existed:
			return fmt.Errorf("owned TC slot %s is missing", observation.key)
		case expected && observation.snapshot.programID != binding.ProgramID:
			return fmt.Errorf(
				"owned TC slot %s has program ID %d, want %d",
				observation.key, observation.snapshot.programID, binding.ProgramID,
			)
		case !expected && observation.snapshot.existed:
			return fmt.Errorf("owned TC slot %s unexpectedly remains", observation.key)
		}
	}
	return nil
}

func rollForwardOwnerApplyFilters(
	active []tcFilterBinding,
	desired []tcFilterBinding,
	programs *loadedOwnerPrograms,
	runtime tcRuntime,
) error {
	if programs == nil {
		return errors.New("owner program stages are unavailable")
	}
	observations, err := inspectOwnerTCTransition(
		active,
		desired,
		ownerTCApplyTransition,
		runtime,
	)
	if err != nil {
		return err
	}

	// Qdisc state is shared scaffold. We only add a canonical clsact when a
	// desired filter needs it; owner recovery never deletes qdiscs.
	addedClsact := make(map[int]struct{})
	for _, observation := range observations {
		if observation.desired == nil ||
			observation.clsactExists ||
			observation.snapshot.existed {
			continue
		}
		ifindex := observation.link.Attrs().Index
		if _, done := addedClsact[ifindex]; done {
			continue
		}
		present, err := inspectClsact(observation.link, runtime)
		if err != nil {
			return err
		}
		if !present {
			if err := runtime.qdiscAdd(canonicalClsact(ifindex)); err != nil {
				return fmt.Errorf("add owner clsact on ifindex %d: %w", ifindex, err)
			}
			present, err = inspectClsact(observation.link, runtime)
			if err != nil {
				return err
			}
			if !present {
				return fmt.Errorf("owner clsact did not appear on ifindex %d", ifindex)
			}
		}
		addedClsact[ifindex] = struct{}{}
	}

	for _, observation := range observations {
		if observation.desired == nil {
			if observation.active == nil {
				return fmt.Errorf("owner apply slot %s has no old/new binding", observation.key)
			}
			current, err := inspectTCFilterSlot(
				observation.link,
				observation.slot,
				runtime,
				false,
			)
			if err != nil {
				return err
			}
			if !current.existed {
				continue
			}
			if current.programID != observation.active.ProgramID {
				return fmt.Errorf(
					"stale owner TC slot %s changed immediately before delete",
					observation.key,
				)
			}
			program := programs.byID[observation.active.ProgramID]
			if program == nil || program.fd < 0 {
				return fmt.Errorf(
					"active owner program ID %d is not staged",
					observation.active.ProgramID,
				)
			}
			filter := managedBpfFilter(
				observation.link.Attrs().Index,
				observation.slot,
				program.fd,
			).(*netlink.BpfFilter)
			filter.Id = int(current.programID)
			if err := runtime.filterDelete(filter); err != nil {
				return fmt.Errorf(
					"roll forward stale owner TC delete %s: %w",
					observation.key, err,
				)
			}
			after, err := inspectTCFilterSlot(
				observation.link,
				observation.slot,
				runtime,
				false,
			)
			if err != nil {
				return err
			}
			if after.existed {
				return fmt.Errorf(
					"stale owner TC slot %s remains after recovery delete",
					observation.key,
				)
			}
			continue
		}
		desiredBinding := *observation.desired
		program := programs.byID[desiredBinding.ProgramID]
		if program == nil || program.fd < 0 {
			return fmt.Errorf(
				"desired owner program ID %d is not staged",
				desiredBinding.ProgramID,
			)
		}
		current, err := inspectTCFilterSlot(
			observation.link,
			observation.slot,
			runtime,
			false,
		)
		if err != nil {
			return err
		}
		if current.existed && current.programID == desiredBinding.ProgramID {
			continue
		}
		if current.existed &&
			(observation.active == nil ||
				current.programID != observation.active.ProgramID) {
			return fmt.Errorf(
				"owner TC slot %s changed immediately before replace",
				observation.key,
			)
		}
		filter := managedBpfFilter(
			observation.link.Attrs().Index,
			observation.slot,
			program.fd,
		)
		if current.existed {
			err = runtime.filterReplace(filter)
		} else {
			if observation.active != nil {
				return fmt.Errorf(
					"owner TC slot %s disappeared immediately before replace",
					observation.key,
				)
			}
			err = runtime.filterAdd(filter)
		}
		if err != nil {
			return fmt.Errorf("roll forward owner TC slot %s: %w", observation.key, err)
		}
		after, err := inspectTCFilterSlot(
			observation.link,
			observation.slot,
			runtime,
			false,
		)
		if err != nil {
			return err
		}
		if !after.existed || after.programID != desiredBinding.ProgramID {
			return fmt.Errorf(
				"owner TC slot %s did not converge to program ID %d",
				observation.key, desiredBinding.ProgramID,
			)
		}
	}
	return validateOwnerTCExact(
		desired,
		retainStaleOwnerFilters(desired, active),
		runtime,
	)
}

func rollForwardOwnerDetachFilters(
	active []tcFilterBinding,
	programs *loadedOwnerPrograms,
	runtime tcRuntime,
) error {
	if programs == nil {
		return errors.New("owner program stages are unavailable")
	}
	observations, err := inspectOwnerTCTransition(
		active,
		nil,
		ownerTCDetachTransition,
		runtime,
	)
	if err != nil {
		return err
	}
	for _, observation := range observations {
		if !observation.snapshot.existed {
			continue
		}
		if observation.active == nil ||
			observation.snapshot.programID != observation.active.ProgramID {
			return fmt.Errorf(
				"owner TC slot %s is not bound to the recorded active program",
				observation.key,
			)
		}
		program := programs.byID[observation.active.ProgramID]
		if program == nil || program.fd < 0 {
			return fmt.Errorf(
				"active owner program ID %d is not staged",
				observation.active.ProgramID,
			)
		}

		// Netlink has no compare-and-delete primitive. Recheck immediately
		// before and after FilterDel while the global lifecycle and resource
		// locks are held; a concurrent out-of-band writer still causes a
		// fail-closed error rather than a broad delete.
		current, err := inspectTCFilterSlot(
			observation.link,
			observation.slot,
			runtime,
			false,
		)
		if err != nil {
			return err
		}
		if !current.existed {
			continue
		}
		if current.programID != observation.active.ProgramID {
			return fmt.Errorf(
				"owner TC slot %s changed immediately before delete",
				observation.key,
			)
		}
		filter := managedBpfFilter(
			observation.link.Attrs().Index,
			observation.slot,
			program.fd,
		).(*netlink.BpfFilter)
		filter.Id = int(current.programID)
		if err := runtime.filterDelete(filter); err != nil {
			return fmt.Errorf("delete owner TC slot %s: %w", observation.key, err)
		}
		after, err := inspectTCFilterSlot(
			observation.link,
			observation.slot,
			runtime,
			false,
		)
		if err != nil {
			return err
		}
		if after.existed {
			return fmt.Errorf(
				"owner TC slot %s remains after delete with program ID %d",
				observation.key, after.programID,
			)
		}
	}
	return validateOwnerTCExact(nil, active, runtime)
}

func restoreOwnerActiveFilters(
	active []tcFilterBinding,
	programs *loadedOwnerPrograms,
	runtime tcRuntime,
) error {
	if programs == nil {
		return errors.New("owner program stages are unavailable")
	}
	observations, err := inspectOwnerTCTransition(
		active,
		active,
		ownerTCDetachTransition,
		runtime,
	)
	if err != nil {
		return err
	}
	for _, observation := range observations {
		binding := *observation.active
		if observation.snapshot.existed {
			if observation.snapshot.programID != binding.ProgramID {
				return fmt.Errorf(
					"owner TC slot %s changed before restore",
					observation.key,
				)
			}
			continue
		}
		program := programs.byID[binding.ProgramID]
		if program == nil || program.fd < 0 {
			return fmt.Errorf("active owner program ID %d is not staged", binding.ProgramID)
		}
		present, err := inspectClsact(observation.link, runtime)
		if err != nil {
			return err
		}
		if !present {
			if err := runtime.qdiscAdd(canonicalClsact(binding.IfIndex)); err != nil {
				return err
			}
		}
		if err := runtime.filterAdd(managedBpfFilter(
			binding.IfIndex,
			observation.slot,
			program.fd,
		)); err != nil {
			return fmt.Errorf("restore owner TC slot %s: %w", observation.key, err)
		}
		after, err := inspectTCFilterSlot(
			observation.link,
			observation.slot,
			runtime,
			false,
		)
		if err != nil {
			return err
		}
		if !after.existed || after.programID != binding.ProgramID {
			return fmt.Errorf(
				"owner TC slot %s did not restore program ID %d",
				observation.key, binding.ProgramID,
			)
		}
	}
	return validateOwnerTCExact(active, active, runtime)
}

func bindingSetsEqual(left, right []tcFilterBinding) bool {
	leftCopy := slices.Clone(left)
	rightCopy := slices.Clone(right)
	sortTCFilterBindings(leftCopy)
	sortTCFilterBindings(rightCopy)
	return slices.Equal(leftCopy, rightCopy)
}
