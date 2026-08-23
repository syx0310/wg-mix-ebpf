//go:build linux

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"

	"github.com/cilium/ebpf"
	"github.com/syx0310/wg-mix-ebpf/internal/control"
	"golang.org/x/sys/unix"
)

type exactTCXOwnerStore interface {
	Persist(*pinOwnerRecord, *pinOwnerRecord, uint64) error
	Remove(*pinOwnerRecord) error
}

func exactTCXBindingsForState(
	state *control.State,
	ingressProgramID uint32,
	egressProgramID uint32,
) ([]exactTCXBinding, error) {
	if ingressProgramID == 0 || egressProgramID == 0 {
		return nil, errors.New("exact TCX bindings require non-zero ingress and egress program IDs")
	}
	ifindexes, err := activeAttachIfindexes(state)
	if err != nil {
		return nil, err
	}
	bindings := make([]exactTCXBinding, 0, len(ifindexes)*2)
	for _, ifindex := range ifindexes {
		for _, desired := range []struct {
			direction exactTCXDirection
			programID uint32
		}{
			{direction: exactTCXIngress, programID: ingressProgramID},
			{direction: exactTCXEgress, programID: egressProgramID},
		} {
			attach, err := exactTCXAttachType(desired.direction)
			if err != nil {
				return nil, err
			}
			bindings = append(bindings, exactTCXBinding{
				Backend:    exactTCXBackend,
				IfIndex:    ifindex,
				Direction:  desired.direction,
				AttachType: uint32(attach),
				PinName:    exactTCXPinName(ifindex, desired.direction),
				ProgramID:  desired.programID,
			})
		}
	}
	sortExactTCXBindings(bindings)
	return bindings, nil
}

func bindDesiredExactTCXLinks(
	active []exactTCXBinding,
	desired []exactTCXBinding,
) ([]exactTCXBinding, error) {
	if err := validateOwnerLinks(active, "active", true); err != nil {
		return nil, err
	}
	out := slices.Clone(desired)
	activeBySlot := make(map[string]exactTCXBinding, len(active))
	for _, binding := range active {
		activeBySlot[exactTCXOwnerKey(binding)] = binding
	}
	for index := range out {
		if err := validateExactTCXBinding(out[index], false); err != nil {
			return nil, err
		}
		if previous, exists := activeBySlot[exactTCXOwnerKey(out[index])]; exists {
			out[index].LinkID = previous.LinkID
		}
	}
	sortExactTCXBindings(out)
	if err := validateOwnerLinks(out, "desired", false); err != nil {
		return nil, err
	}
	if err := validateOwnerLinkTransition(active, out); err != nil {
		return nil, err
	}
	return out, nil
}

func preflightExactTCXCapabilities(
	state *control.State,
	runtime exactTCXRuntime,
) error {
	if err := validateExactTCXRuntime(runtime); err != nil {
		return err
	}
	if runtime.probe == nil {
		return errors.New("exact TCX runtime has no fixed capability probe")
	}
	ifindexes, err := activeAttachIfindexes(state)
	if err != nil {
		return err
	}
	if len(ifindexes) == 0 {
		return nil
	}
	probeIfindex := ifindexes[0]
	probeQuery, err := runtime.probe(probeIfindex)
	if err != nil {
		return fmt.Errorf(
			"preflight exact TCX capability on %d/ingress before owner intent: %w",
			probeIfindex,
			err,
		)
	}
	if err := validateExactTCXQuery(probeQuery); err != nil {
		return fmt.Errorf(
			"preflight exact TCX capability on %d/ingress: %w",
			probeIfindex,
			err,
		)
	}
	for ifindexPosition, ifindex := range ifindexes {
		for _, direction := range []exactTCXDirection{exactTCXIngress, exactTCXEgress} {
			attach, err := exactTCXAttachType(direction)
			if err != nil {
				return err
			}
			query := probeQuery
			if ifindexPosition != 0 || direction != exactTCXIngress {
				query, err = runtime.query(ifindex, attach)
				if err != nil {
					return fmt.Errorf(
						"preflight exact TCX %d/%s before owner intent: %w",
						ifindex, direction, err,
					)
				}
			}
			if err := validateExactTCXQuery(query); err != nil {
				return fmt.Errorf("preflight exact TCX %d/%s: %w", ifindex, direction, err)
			}
		}
	}
	return nil
}

func validateExactTCXQuery(query exactTCXQuery) error {
	if query.Revision == 0 {
		return errors.New("TCX query has no revision fence")
	}
	seen := make(map[uint32]uint32, len(query.Programs))
	for _, program := range query.Programs {
		if program.LinkID == 0 || program.ProgramID == 0 {
			return errors.New("TCX query returned an incomplete exact identity")
		}
		if previous, duplicate := seen[program.LinkID]; duplicate {
			return fmt.Errorf(
				"TCX query repeats link ID %d for programs %d and %d",
				program.LinkID, previous, program.ProgramID,
			)
		}
		seen[program.LinkID] = program.ProgramID
	}
	return nil
}

func validatePinnedExactTCXAt(
	handle *pinPathHandle,
	binding exactTCXBinding,
	runtime exactTCXRuntime,
) (*exactTCXAttachment, error) {
	owner, observed, err := observePinnedExactTCXAt(
		handle,
		binding,
		[]uint32{binding.ProgramID},
		runtime,
	)
	if err != nil {
		return nil, err
	}
	if !observed.Attached {
		return nil, errors.Join(
			errors.New("pinned exact TCX link is detached"),
			owner.Release(),
		)
	}
	owner.committed = true
	return owner, nil
}

func observePinnedExactTCXAt(
	handle *pinPathHandle,
	binding exactTCXBinding,
	allowedProgramIDs []uint32,
	runtime exactTCXRuntime,
) (*exactTCXAttachment, *exactTCXObservation, error) {
	if handle == nil {
		return nil, nil, errors.New("observe pinned exact TCX link: pin handle is nil")
	}
	if err := validateExactTCXBinding(binding, binding.LinkID != 0); err != nil {
		return nil, nil, err
	}
	if err := handle.recheckTargetEntry(); err != nil {
		return nil, nil, err
	}
	var before unix.Stat_t
	if err := unix.Fstatat(
		handle.targetFD,
		binding.PinName,
		&before,
		unix.AT_SYMLINK_NOFOLLOW,
	); err != nil {
		return nil, nil, err
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG ||
		before.Mode&0o7777 != 0o600 ||
		before.Uid != handle.runtime.expectedUID ||
		before.Nlink != 1 {
		return nil, nil, fmt.Errorf(
			"unsafe exact TCX pin %s/%s: mode=%#o uid=%d links=%d",
			handle.pinPath, binding.PinName, before.Mode, before.Uid, before.Nlink,
		)
	}
	mountID, err := handle.runtime.mountIDAt(
		handle.targetFD,
		binding.PinName,
		unix.AT_NO_AUTOMOUNT|unix.AT_SYMLINK_NOFOLLOW,
	)
	if err != nil {
		return nil, nil, err
	}
	if mountID != handle.mountID {
		return nil, nil, fmt.Errorf("exact TCX pin %s is on another mount", binding.PinName)
	}
	owner, observed, err := observePinnedExactTCXAttachment(
		binding,
		filepath.Join(handle.procPath(), binding.PinName),
		allowedProgramIDs,
		runtime,
	)
	if err != nil {
		return nil, nil, err
	}
	var after unix.Stat_t
	if err := unix.Fstatat(
		handle.targetFD,
		binding.PinName,
		&after,
		unix.AT_SYMLINK_NOFOLLOW,
	); err != nil {
		return nil, nil, errors.Join(err, owner.Release())
	}
	beforeIdentity := pinPathInodeFromStat(&before)
	afterIdentity := pinPathInodeFromStat(&after)
	if !samePinPathInode(beforeIdentity, afterIdentity) ||
		beforeIdentity.uid != afterIdentity.uid ||
		beforeIdentity.mode&0o7777 != afterIdentity.mode&0o7777 ||
		beforeIdentity.nlink != afterIdentity.nlink {
		return nil, nil, errors.Join(
			fmt.Errorf("exact TCX pin %s changed while validating", binding.PinName),
			owner.Release(),
		)
	}
	owner.recheckPin = func() error {
		if err := handle.recheckTargetEntry(); err != nil {
			return err
		}
		var current unix.Stat_t
		if err := unix.Fstatat(
			handle.targetFD,
			binding.PinName,
			&current,
			unix.AT_SYMLINK_NOFOLLOW,
		); err != nil {
			return err
		}
		currentIdentity := pinPathInodeFromStat(&current)
		if !samePinPathInode(afterIdentity, currentIdentity) ||
			currentIdentity.uid != afterIdentity.uid ||
			currentIdentity.mode&0o7777 != afterIdentity.mode&0o7777 ||
			currentIdentity.nlink != afterIdentity.nlink {
			return fmt.Errorf("exact TCX pin %s changed before mutation", binding.PinName)
		}
		mountID, err := handle.runtime.mountIDAt(
			handle.targetFD,
			binding.PinName,
			unix.AT_NO_AUTOMOUNT|unix.AT_SYMLINK_NOFOLLOW,
		)
		if err != nil {
			return err
		}
		if mountID != handle.mountID {
			return fmt.Errorf("exact TCX pin %s moved to another mount", binding.PinName)
		}
		return nil
	}
	return owner, observed, nil
}

func validateOwnerExactTCXLinks(
	handle *pinPathHandle,
	bindings []exactTCXBinding,
	runtime exactTCXRuntime,
) error {
	for _, binding := range bindings {
		owner, err := validatePinnedExactTCXAt(handle, binding, runtime)
		if err != nil {
			return fmt.Errorf("validate owner exact TCX link %s: %w", binding.PinName, err)
		}
		if err := owner.Release(); err != nil {
			return fmt.Errorf("release owner exact TCX link %s: %w", binding.PinName, err)
		}
	}
	return nil
}

func reconcileDetachedActiveExactTCXLinks(
	handle *pinPathHandle,
	store exactTCXOwnerStore,
	record *pinOwnerRecord,
	runtime exactTCXRuntime,
) (*pinOwnerRecord, error) {
	if handle == nil || store == nil || record == nil ||
		record.Phase != pinOwnerPhaseActive ||
		(record.Step != pinOwnerStepReady && record.Step != pinOwnerStepRetiring) {
		return nil, errors.New("reconcile detached active TCX links requires an active owner record")
	}
	current := record
	for {
		restarted := false
		for index, binding := range current.ActiveLinks {
			if binding.Retiring {
				if err := removeOwnedExactTCXLink(handle, binding, runtime); err != nil {
					return current, fmt.Errorf("complete active exact TCX retirement %d: %w", binding.LinkID, err)
				}
				now, err := ownerRuntimeNow(handle.runtime)
				if err != nil {
					return current, err
				}
				next := advancePinOwnerRecord(current, now, pinOwnerPhaseActive, pinOwnerStepReady)
				next.ActiveLinks = append(
					slices.Clone(current.ActiveLinks[:index]),
					current.ActiveLinks[index+1:]...,
				)
				for _, remaining := range next.ActiveLinks {
					if remaining.Retiring {
						next.Step = pinOwnerStepRetiring
						break
					}
				}
				normalizePinOwnerRecord(next)
				if err := validatePinOwnerRecord(next, handle.resource, handle.mountID); err != nil {
					return current, err
				}
				observeOwnerMount(next, handle.mountID)
				if err := store.Persist(next, current, handle.mountID); err != nil {
					return current, err
				}
				current = next
				restarted = true
				break
			}
			owner, observed, err := observePinnedExactTCXAt(
				handle,
				binding,
				[]uint32{binding.ProgramID},
				runtime,
			)
			if err != nil {
				if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, unix.ENOENT) {
					return current, err
				}
				absent, queryErr := exactTCXLinkAbsentFromOriginalSlot(binding, runtime)
				if queryErr != nil {
					return current, queryErr
				}
				if !absent {
					return current, fmt.Errorf(
						"active exact TCX link %d lost its anchored pin but remains in the original slot",
						binding.LinkID,
					)
				}
			} else if observed.Attached {
				if err := owner.Release(); err != nil {
					return current, err
				}
				continue
			}
			now, err := ownerRuntimeNow(handle.runtime)
			if err != nil {
				if owner != nil {
					return current, errors.Join(err, owner.Release())
				}
				return current, err
			}
			retiring := advancePinOwnerRecord(
				current, now, pinOwnerPhaseActive, pinOwnerStepRetiring,
			)
			retiring.ActiveLinks[index].Retiring = true
			normalizePinOwnerRecord(retiring)
			if err := validatePinOwnerRecord(retiring, handle.resource, handle.mountID); err != nil {
				if owner != nil {
					return current, errors.Join(err, owner.Release())
				}
				return current, err
			}
			observeOwnerMount(retiring, handle.mountID)
			if err := store.Persist(retiring, current, handle.mountID); err != nil {
				if owner != nil {
					return current, errors.Join(err, owner.Release())
				}
				return current, err
			}
			current = retiring
			if owner != nil {
				if err := owner.Rollback(); err != nil {
					return current, fmt.Errorf(
						"retire detached active exact TCX link %d: %w",
						binding.LinkID,
						err,
					)
				}
			}
			restarted = true
			break
		}
		if restarted {
			continue
		}
		return current, nil
	}
}

func validateJournaledAttachedOrDetachedExactTCXLinks(
	handle *pinPathHandle,
	bindings []exactTCXBinding,
	runtime exactTCXRuntime,
) error {
	for _, binding := range bindings {
		owner, _, err := observePinnedExactTCXAt(
			handle,
			binding,
			[]uint32{binding.ProgramID},
			runtime,
		)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, unix.ENOENT) {
				return err
			}
			absent, queryErr := exactTCXLinkAbsentFromOriginalSlot(binding, runtime)
			if queryErr != nil {
				return queryErr
			}
			if !absent {
				return fmt.Errorf(
					"journaled exact TCX link %d lost its pin but remains attached",
					binding.LinkID,
				)
			}
			continue
		}
		if err := owner.Release(); err != nil {
			return err
		}
	}
	return nil
}

func exactTCXProgramFromStages(
	programs *loadedOwnerPrograms,
	id uint32,
) (exactTCXProgram, error) {
	if programs == nil || id == 0 {
		return exactTCXProgram{}, errors.New("owner exact TCX program stages are unavailable")
	}
	observation := programs.byID[id]
	if observation == nil || observation.id != id || observation.fd < 0 {
		return exactTCXProgram{}, fmt.Errorf("owner exact TCX program ID %d is not staged", id)
	}
	return exactTCXProgram{id: id, kernel: observation.program}, nil
}

func ownerExactTCXJournal(
	record **pinOwnerRecord,
	handle *pinPathHandle,
	store exactTCXOwnerStore,
) exactTCXJournal {
	return exactTCXJournal{
		persistIntent: func(intent exactTCXJournalIntent) error {
			if record == nil || *record == nil ||
				(*record).Phase != pinOwnerPhaseApplying ||
				(*record).Step != pinOwnerStepMutating {
				return errors.New("exact TCX kernel mutation is outside durable applying intent")
			}
			for _, desired := range (*record).DesiredLinks {
				if sameExactTCXSlot(desired, intent.Desired) &&
					desired.ProgramID == intent.Desired.ProgramID &&
					(desired.LinkID == 0 || desired.LinkID == intent.Desired.LinkID) {
					return nil
				}
			}
			return errors.New("exact TCX mutation is outside the owner desired-link journal")
		},
		persistIdentity: func(binding exactTCXBinding, _ exactTCXJournalIntent) error {
			current := *record
			for _, desired := range current.DesiredLinks {
				if !sameExactTCXSlot(desired, binding) || desired.ProgramID != binding.ProgramID {
					continue
				}
				if desired.LinkID == binding.LinkID && desired.PinPending == binding.PinPending {
					return nil
				}
				if desired.LinkID != 0 && desired.LinkID != binding.LinkID {
					return fmt.Errorf(
						"owner desired link %s already records link ID %d, observed %d",
						desired.PinName, desired.LinkID, binding.LinkID,
					)
				}
				next, err := ownerRecordWithDesiredLinkIdentity(current, binding, handle.runtime)
				if err != nil {
					return err
				}
				observeOwnerMount(next, handle.mountID)
				if err := store.Persist(next, current, handle.mountID); err != nil {
					return err
				}
				*record = next
				return nil
			}
			return errors.New("published exact TCX link is outside owner desired links")
		},
	}
}

func ownerRecordWithDesiredLinkIdentity(
	current *pinOwnerRecord,
	binding exactTCXBinding,
	runtime pinPathRuntime,
) (*pinOwnerRecord, error) {
	if current == nil || current.Phase != pinOwnerPhaseApplying || current.Step != pinOwnerStepMutating {
		return nil, errors.New("cannot publish exact TCX identity outside applying mutation")
	}
	now, err := ownerRuntimeNow(runtime)
	if err != nil {
		return nil, err
	}
	next := advancePinOwnerRecord(current, now, current.Phase, current.Step)
	found := false
	for index := range next.DesiredLinks {
		desired := next.DesiredLinks[index]
		if !sameExactTCXSlot(desired, binding) || desired.ProgramID != binding.ProgramID {
			continue
		}
		if desired.LinkID != 0 && desired.LinkID != binding.LinkID {
			return nil, fmt.Errorf("desired exact TCX link ID changed from %d to %d", desired.LinkID, binding.LinkID)
		}
		next.DesiredLinks[index].LinkID = binding.LinkID
		next.DesiredLinks[index].PinPending = binding.PinPending
		found = true
		break
	}
	if !found {
		return nil, errors.New("desired exact TCX link identity has no journal slot")
	}
	normalizePinOwnerRecord(next)
	if err := validatePinOwnerRecord(next, pinResourceIdentity{
		key:          next.ResourceKey,
		parentDevice: next.ParentDevice,
		parentInode:  next.ParentInode,
		base:         next.PinBaseName,
	}, 0); err != nil {
		return nil, err
	}
	return next, nil
}

func ownerRecordWithoutDesiredLinkIdentity(
	current *pinOwnerRecord,
	binding exactTCXBinding,
	handle *pinPathHandle,
	store exactTCXOwnerStore,
) (*pinOwnerRecord, error) {
	if current == nil || handle == nil || store == nil ||
		current.Phase != pinOwnerPhaseApplying || current.Step != pinOwnerStepMutating ||
		binding.LinkID == 0 {
		return nil, errors.New("cannot clear exact TCX identity outside a recorded applying mutation")
	}
	for _, active := range current.ActiveLinks {
		if sameExactTCXSlot(active, binding) {
			if binding.ReplacesLinkID != active.LinkID {
				return nil, errors.New("cannot clear the stable link ID of an active exact TCX slot")
			}
			break
		}
	}
	now, err := ownerRuntimeNow(handle.runtime)
	if err != nil {
		return nil, err
	}
	next := advancePinOwnerRecord(current, now, current.Phase, current.Step)
	found := false
	for index := range next.DesiredLinks {
		desired := next.DesiredLinks[index]
		if !sameExactTCXSlot(desired, binding) ||
			desired.ProgramID != binding.ProgramID ||
			desired.LinkID != binding.LinkID {
			continue
		}
		next.DesiredLinks[index].LinkID = 0
		next.DesiredLinks[index].PinPending = false
		next.DesiredLinks[index].Retiring = false
		found = true
		break
	}
	if !found {
		return nil, errors.New("removed exact TCX link identity has no matching desired journal entry")
	}
	normalizePinOwnerRecord(next)
	if err := validatePinOwnerRecord(next, handle.resource, handle.mountID); err != nil {
		return nil, err
	}
	observeOwnerMount(next, handle.mountID)
	if err := store.Persist(next, current, handle.mountID); err != nil {
		return nil, err
	}
	return next, nil
}

func ownerRecordRetiringDesiredLink(
	current *pinOwnerRecord,
	binding exactTCXBinding,
	handle *pinPathHandle,
	store exactTCXOwnerStore,
) (*pinOwnerRecord, error) {
	if current == nil || handle == nil || store == nil ||
		current.Phase != pinOwnerPhaseApplying || current.Step != pinOwnerStepMutating ||
		binding.LinkID == 0 || binding.PinPending {
		return nil, errors.New("cannot journal exact TCX retirement outside a published applying mutation")
	}
	if binding.Retiring {
		return current, nil
	}
	now, err := ownerRuntimeNow(handle.runtime)
	if err != nil {
		return nil, err
	}
	next := advancePinOwnerRecord(current, now, current.Phase, current.Step)
	found := false
	for index := range next.DesiredLinks {
		desired := next.DesiredLinks[index]
		if !sameExactTCXSlot(desired, binding) ||
			desired.ProgramID != binding.ProgramID ||
			desired.LinkID != binding.LinkID || desired.PinPending {
			continue
		}
		next.DesiredLinks[index].Retiring = true
		found = true
		break
	}
	if !found {
		return nil, errors.New("retiring exact TCX link has no matching desired journal entry")
	}
	normalizePinOwnerRecord(next)
	if err := validatePinOwnerRecord(next, handle.resource, handle.mountID); err != nil {
		return nil, err
	}
	observeOwnerMount(next, handle.mountID)
	if err := store.Persist(next, current, handle.mountID); err != nil {
		return nil, err
	}
	return next, nil
}

func ownerRecordReplacingDetachedLink(
	current *pinOwnerRecord,
	active exactTCXBinding,
	handle *pinPathHandle,
	store exactTCXOwnerStore,
) (*pinOwnerRecord, error) {
	if current == nil || handle == nil || store == nil ||
		current.Phase != pinOwnerPhaseApplying || current.Step != pinOwnerStepMutating ||
		active.LinkID == 0 || active.ReplacesLinkID != 0 {
		return nil, errors.New("cannot journal detached TCX replacement outside applying mutation")
	}
	now, err := ownerRuntimeNow(handle.runtime)
	if err != nil {
		return nil, err
	}
	next := advancePinOwnerRecord(current, now, current.Phase, current.Step)
	found := false
	for index := range next.DesiredLinks {
		desired := next.DesiredLinks[index]
		if !sameExactTCXSlot(desired, active) ||
			desired.LinkID != active.LinkID ||
			desired.ReplacesLinkID != 0 {
			continue
		}
		next.DesiredLinks[index].LinkID = 0
		next.DesiredLinks[index].ReplacesLinkID = active.LinkID
		next.DesiredLinks[index].PinPending = false
		found = true
		break
	}
	if !found {
		return nil, errors.New("detached active TCX link has no exact desired journal slot")
	}
	normalizePinOwnerRecord(next)
	if err := validatePinOwnerRecord(next, handle.resource, handle.mountID); err != nil {
		return nil, err
	}
	observeOwnerMount(next, handle.mountID)
	if err := store.Persist(next, current, handle.mountID); err != nil {
		return nil, err
	}
	return next, nil
}

func ownerRecordReplacingRollbackActive(
	current *pinOwnerRecord,
	active exactTCXBinding,
	handle *pinPathHandle,
	store exactTCXOwnerStore,
) (*pinOwnerRecord, error) {
	if current == nil || handle == nil || store == nil ||
		current.Phase != pinOwnerPhaseApplying || current.Step != pinOwnerStepRollingBack ||
		active.LinkID == 0 {
		return nil, errors.New("cannot journal rollback active replacement outside rolling_back")
	}
	if active.ReplacesLinkID != 0 {
		return current, nil
	}
	now, err := ownerRuntimeNow(handle.runtime)
	if err != nil {
		return nil, err
	}
	next := advancePinOwnerRecord(current, now, current.Phase, current.Step)
	found := false
	for index := range next.ActiveLinks {
		candidate := next.ActiveLinks[index]
		if !sameExactTCXSlot(candidate, active) ||
			candidate.ProgramID != active.ProgramID || candidate.LinkID != active.LinkID ||
			candidate.ReplacesLinkID != 0 {
			continue
		}
		next.ActiveLinks[index].LinkID = 0
		next.ActiveLinks[index].ReplacesLinkID = active.LinkID
		next.ActiveLinks[index].PinPending = false
		next.ActiveLinks[index].Retiring = false
		found = true
		break
	}
	if !found {
		return nil, errors.New("rollback active replacement has no exact journal slot")
	}
	normalizePinOwnerRecord(next)
	if err := validatePinOwnerRecord(next, handle.resource, handle.mountID); err != nil {
		return nil, err
	}
	observeOwnerMount(next, handle.mountID)
	if err := store.Persist(next, current, handle.mountID); err != nil {
		return nil, err
	}
	return next, nil
}

func ownerRecordResetRollbackActiveIdentity(
	current *pinOwnerRecord,
	active exactTCXBinding,
	handle *pinPathHandle,
	store exactTCXOwnerStore,
) (*pinOwnerRecord, error) {
	if current == nil || handle == nil || store == nil ||
		current.Phase != pinOwnerPhaseApplying || current.Step != pinOwnerStepRollingBack ||
		active.LinkID == 0 || active.ReplacesLinkID == 0 {
		return nil, errors.New("cannot reset rollback replacement identity outside rolling_back")
	}
	now, err := ownerRuntimeNow(handle.runtime)
	if err != nil {
		return nil, err
	}
	next := advancePinOwnerRecord(current, now, current.Phase, current.Step)
	found := false
	for index := range next.ActiveLinks {
		candidate := next.ActiveLinks[index]
		if !sameExactTCXSlot(candidate, active) ||
			candidate.ProgramID != active.ProgramID || candidate.LinkID != active.LinkID ||
			candidate.ReplacesLinkID != active.ReplacesLinkID {
			continue
		}
		next.ActiveLinks[index].LinkID = 0
		next.ActiveLinks[index].PinPending = false
		next.ActiveLinks[index].Retiring = false
		found = true
		break
	}
	if !found {
		return nil, errors.New("rollback replacement identity has no exact active journal entry")
	}
	normalizePinOwnerRecord(next)
	if err := validatePinOwnerRecord(next, handle.resource, handle.mountID); err != nil {
		return nil, err
	}
	observeOwnerMount(next, handle.mountID)
	if err := store.Persist(next, current, handle.mountID); err != nil {
		return nil, err
	}
	return next, nil
}

func rollingBackExactTCXJournal(
	record **pinOwnerRecord,
	handle *pinPathHandle,
	store exactTCXOwnerStore,
	activeIndex int,
) exactTCXJournal {
	return exactTCXJournal{
		persistIntent: func(intent exactTCXJournalIntent) error {
			if record == nil || *record == nil || handle == nil || store == nil ||
				(*record).Phase != pinOwnerPhaseApplying ||
				(*record).Step != pinOwnerStepRollingBack ||
				activeIndex < 0 || activeIndex >= len((*record).ActiveLinks) {
				return errors.New("exact TCX rollback mutation is outside durable rolling_back intent")
			}
			active := (*record).ActiveLinks[activeIndex]
			if !sameExactTCXSlot(active, intent.Desired) ||
				active.ProgramID != intent.Desired.ProgramID ||
				(active.LinkID != 0 && active.LinkID != intent.Desired.LinkID) {
				return errors.New("exact TCX rollback mutation escaped its active journal slot")
			}
			return nil
		},
		persistIdentity: func(binding exactTCXBinding, _ exactTCXJournalIntent) error {
			if record == nil || *record == nil || activeIndex < 0 ||
				activeIndex >= len((*record).ActiveLinks) {
				return errors.New("exact TCX rollback identity has no active journal slot")
			}
			current := *record
			active := current.ActiveLinks[activeIndex]
			if !sameExactTCXSlot(active, binding) ||
				active.ProgramID != binding.ProgramID ||
				active.ReplacesLinkID != binding.ReplacesLinkID || binding.LinkID == 0 {
				return errors.New("exact TCX rollback published an unexpected active identity")
			}
			if active.LinkID == binding.LinkID &&
				active.PinPending == binding.PinPending && !active.Retiring {
				return nil
			}
			if active.LinkID != 0 && active.LinkID != binding.LinkID {
				return fmt.Errorf("rollback active link ID changed from %d to %d", active.LinkID, binding.LinkID)
			}
			now, err := ownerRuntimeNow(handle.runtime)
			if err != nil {
				return err
			}
			next := advancePinOwnerRecord(current, now, current.Phase, current.Step)
			next.ActiveLinks[activeIndex].LinkID = binding.LinkID
			next.ActiveLinks[activeIndex].PinPending = binding.PinPending
			next.ActiveLinks[activeIndex].Retiring = false
			normalizePinOwnerRecord(next)
			if err := validatePinOwnerRecord(next, handle.resource, handle.mountID); err != nil {
				return err
			}
			observeOwnerMount(next, handle.mountID)
			if err := store.Persist(next, current, handle.mountID); err != nil {
				return err
			}
			*record = next
			return nil
		},
	}
}

func convergeOwnerApplyExactTCXLinks(
	ctx context.Context,
	handle *pinPathHandle,
	store exactTCXOwnerStore,
	record *pinOwnerRecord,
	programs *loadedOwnerPrograms,
	runtime exactTCXRuntime,
) (*pinOwnerRecord, error) {
	if ctx == nil {
		return nil, errors.New("converge owner exact TCX links: context is nil")
	}
	if handle == nil || store == nil || record == nil ||
		record.Phase != pinOwnerPhaseApplying || record.Step != pinOwnerStepMutating {
		return nil, errors.New("converge owner exact TCX links requires durable mutating intent")
	}
	activeBySlot := make(map[string]exactTCXBinding, len(record.ActiveLinks))
	for _, binding := range record.ActiveLinks {
		activeBySlot[exactTCXOwnerKey(binding)] = binding
	}
	current := record
	for index := 0; index < len(current.DesiredLinks); index++ {
		if err := ctx.Err(); err != nil {
			return current, err
		}
		desired := current.DesiredLinks[index]
		active, replacing := activeBySlot[exactTCXOwnerKey(desired)]
		if replacing && desired.ReplacesLinkID != 0 {
			if desired.ReplacesLinkID != active.LinkID {
				return current, errors.New("desired TCX replacement marker no longer matches the active link")
			}
			if desired.LinkID == 0 {
				if err := removeOwnedExactTCXLink(handle, active, runtime); err != nil {
					return current, fmt.Errorf("complete journaled detached active TCX retirement: %w", err)
				}
			} else {
				absent, err := exactTCXLinkAbsentFromOriginalSlot(active, runtime)
				if err != nil {
					return current, err
				}
				if !absent {
					return current, fmt.Errorf("retired active exact TCX link %d reappeared", active.LinkID)
				}
			}
			replacing = false
		}
		pinPath := filepath.Join(handle.procPath(), desired.PinName)
		if err := retryRetainedUnpinnedExactTCXOwner(pinPath); err != nil {
			return current, err
		}
		if desired.Retiring {
			if err := removeOwnedExactTCXLink(handle, desired, runtime); err != nil {
				return current, fmt.Errorf("complete journaled desired TCX retirement: %w", err)
			}
			cleared, err := ownerRecordWithoutDesiredLinkIdentity(
				current, desired, handle, store,
			)
			if err != nil {
				return current, err
			}
			current = cleared
			desired = current.DesiredLinks[index]
		}
		if replacing {
			owner, observed, err := observePinnedExactTCXAt(
				handle,
				active,
				[]uint32{active.ProgramID, desired.ProgramID},
				runtime,
			)
			if err != nil {
				return current, err
			}
			if !observed.Attached {
				replacement, err := ownerRecordReplacingDetachedLink(
					current, active, handle, store,
				)
				if err != nil {
					return current, errors.Join(err, owner.Release())
				}
				current = replacement
				if err := owner.Rollback(); err != nil {
					return current, fmt.Errorf(
						"retire detached active exact TCX link during apply: %w",
						err,
					)
				}
				desired = current.DesiredLinks[index]
				replacing = false
			}
			if !replacing {
				// The exact detached pin has been retired and the durable
				// replacement marker allows a new link ID in this slot.
			} else {
				owner.committed = true
				switch observed.Binding.ProgramID {
				case desired.ProgramID:
					if err := owner.Release(); err != nil {
						return current, err
					}
				case active.ProgramID:
					if active.ProgramID == desired.ProgramID {
						if err := owner.Release(); err != nil {
							return current, err
						}
						continue
					}
					previous, err := exactTCXProgramFromStages(programs, active.ProgramID)
					if err != nil {
						return current, errors.Join(err, owner.Release())
					}
					next, err := exactTCXProgramFromStages(programs, desired.ProgramID)
					if err != nil {
						return current, errors.Join(err, owner.Release())
					}
					journal := ownerExactTCXJournal(&current, handle, store)
					if err := owner.CompareUpdateWithOld(previous, next, journal); err != nil {
						return current, errors.Join(err, owner.Release())
					}
					if err := owner.Release(); err != nil {
						return current, err
					}
				default:
					return current, errors.Join(
						errors.New("exact TCX link program escaped owner old/new set"),
						owner.Release(),
					)
				}
				continue
			}
		}

		owner, observed, err := observePinnedExactTCXAt(
			handle,
			desired,
			[]uint32{desired.ProgramID},
			runtime,
		)
		if err == nil {
			if observed.Attached {
				journal := ownerExactTCXJournal(&current, handle, store)
				intent := exactTCXJournalIntent{Operation: exactTCXJournalAttach, Desired: desired}
				if err := journal.persistIdentity(observed.Binding, intent); err != nil {
					return current, errors.Join(err, owner.Release())
				}
				if err := owner.Release(); err != nil {
					return current, err
				}
				continue
			}
			if desired.LinkID != 0 {
				retiring, retireErr := ownerRecordRetiringDesiredLink(
					current, desired, handle, store,
				)
				if retireErr != nil {
					return current, errors.Join(retireErr, owner.Release())
				}
				current = retiring
				desired = current.DesiredLinks[index]
			}
			if err := owner.Rollback(); err != nil {
				return current, fmt.Errorf("discard detached exact TCX attach pin: %w", err)
			}
			if desired.LinkID != 0 {
				cleared, clearErr := ownerRecordWithoutDesiredLinkIdentity(
					current, desired, handle, store,
				)
				if clearErr != nil {
					return current, clearErr
				}
				current = cleared
				desired = current.DesiredLinks[index]
			}
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, unix.ENOENT) {
			return current, err
		}
		if err != nil && desired.LinkID != 0 {
			absent, queryErr := exactTCXLinkAbsentFromOriginalSlot(desired, runtime)
			if queryErr != nil {
				return current, queryErr
			}
			if !absent {
				return current, fmt.Errorf(
					"journaled exact TCX link %d lost deterministic pin %s",
					desired.LinkID, desired.PinName,
				)
			}
			cleared, clearErr := ownerRecordWithoutDesiredLinkIdentity(
				current, desired, handle, store,
			)
			if clearErr != nil {
				return current, clearErr
			}
			current = cleared
			desired = current.DesiredLinks[index]
		}
		program, err := exactTCXProgramFromStages(programs, desired.ProgramID)
		if err != nil {
			return current, err
		}
		journal := ownerExactTCXJournal(&current, handle, store)
		owner, err = stageExactTCXAttachment(
			ctx,
			desired,
			pinPath,
			program,
			journal,
			runtime,
		)
		if err != nil {
			if owner != nil {
				return current, errors.Join(err, owner.Release())
			}
			return current, err
		}
		if err := owner.Release(); err != nil {
			return current, err
		}
	}
	if err := validateOwnerExactTCXLinks(handle, current.DesiredLinks, runtime); err != nil {
		return current, err
	}
	return current, nil
}

func removeOwnedExactTCXLink(
	handle *pinPathHandle,
	binding exactTCXBinding,
	runtime exactTCXRuntime,
) error {
	owner, _, err := observePinnedExactTCXAt(
		handle,
		binding,
		[]uint32{binding.ProgramID},
		runtime,
	)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, unix.ENOENT) {
			return err
		}
		absent, queryErr := exactTCXLinkAbsentFromOriginalSlot(binding, runtime)
		if queryErr != nil {
			return queryErr
		}
		if !absent {
			return fmt.Errorf(
				"exact TCX link %d remains attached after deterministic pin disappeared",
				binding.LinkID,
			)
		}
		return nil
	}
	if err := owner.Rollback(); err != nil {
		return err
	}
	var stat unix.Stat_t
	err = unix.Fstatat(handle.targetFD, binding.PinName, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil {
		return fmt.Errorf("exact TCX pin %s remains after unpin", binding.PinName)
	}
	if !errors.Is(err, unix.ENOENT) {
		return err
	}
	absent, err := exactTCXLinkAbsentFromOriginalSlot(binding, runtime)
	if err != nil {
		return err
	}
	if !absent {
		return fmt.Errorf("exact TCX link %d remains attached after exact detach", binding.LinkID)
	}
	return nil
}

func removeStaleOwnerExactTCXLinks(
	handle *pinPathHandle,
	active []exactTCXBinding,
	desired []exactTCXBinding,
	runtime exactTCXRuntime,
) error {
	desiredSlots := make(map[string]struct{}, len(desired))
	for _, binding := range desired {
		desiredSlots[exactTCXOwnerKey(binding)] = struct{}{}
	}
	for _, binding := range active {
		if _, retained := desiredSlots[exactTCXOwnerKey(binding)]; retained {
			continue
		}
		if err := removeOwnedExactTCXLink(handle, binding, runtime); err != nil {
			return fmt.Errorf("remove stale exact TCX link %s: %w", binding.PinName, err)
		}
	}
	return nil
}

func removeAllOwnerExactTCXLinks(
	handle *pinPathHandle,
	bindings []exactTCXBinding,
	runtime exactTCXRuntime,
) error {
	ordered := slices.Clone(bindings)
	sort.Slice(ordered, func(i, j int) bool {
		return exactTCXOwnerKey(ordered[i]) < exactTCXOwnerKey(ordered[j])
	})
	for _, binding := range ordered {
		if err := removeOwnedExactTCXLink(handle, binding, runtime); err != nil {
			return fmt.Errorf("detach owner exact TCX link %s: %w", binding.PinName, err)
		}
	}
	return nil
}

func validateOwnerExactTCXLinksAbsent(
	handle *pinPathHandle,
	bindings []exactTCXBinding,
	runtime exactTCXRuntime,
) error {
	for _, binding := range bindings {
		var stat unix.Stat_t
		err := unix.Fstatat(handle.targetFD, binding.PinName, &stat, unix.AT_SYMLINK_NOFOLLOW)
		if err == nil {
			return fmt.Errorf("removed exact TCX pin %s reappeared", binding.PinName)
		}
		if !errors.Is(err, unix.ENOENT) {
			return err
		}
		absent, err := exactTCXLinkAbsentFromOriginalSlot(binding, runtime)
		if err != nil {
			return err
		}
		if !absent {
			return fmt.Errorf("removed exact TCX link %d reappeared", binding.LinkID)
		}
	}
	return nil
}

func exactTCXProgramIdentity(program *ebpf.Program) (uint32, error) {
	if program == nil {
		return 0, errors.New("TCX program is nil")
	}
	info, err := program.Info()
	if err != nil {
		return 0, fmt.Errorf("inspect TCX program: %w", err)
	}
	id, ok := info.ID()
	if !ok || id == 0 {
		return 0, errors.New("TCX program has no stable kernel ID")
	}
	return uint32(id), nil
}
