//go:build linux

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
	"golang.org/x/sys/unix"
)

func recoverExactPinOwnerTransaction(
	ctx context.Context,
	handle *pinPathHandle,
	store *pinOwnerStore,
	record *pinOwnerRecord,
	runtime exactTCXRuntime,
) (*pinOwnerRecoveryResult, error) {
	if ctx == nil {
		return nil, errors.New("exact owner recovery: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if handle == nil || store == nil || record == nil {
		return nil, errors.New("exact owner recovery requires a handle, store, and record")
	}
	if err := validatePinOwnerRecord(record, handle.resource, handle.mountID); err != nil {
		return nil, err
	}
	if record.Phase == pinOwnerPhaseActive {
		reconciled, err := reconcileDetachedActiveExactTCXLinks(
			handle, store, record, runtime,
		)
		if err != nil {
			return nil, err
		}
		record = reconciled
	}
	if err := validateOwnerDirectoryEntries(handle, record); err != nil {
		return nil, err
	}
	switch record.Phase {
	case pinOwnerPhaseActive:
		pins, err := inspectPinnedMapSet(handle, true)
		if err != nil {
			return nil, err
		}
		defer closePinnedMapPins(pins)
		if err := validateOwnerPins(handle, record, pins, true); err != nil {
			return nil, err
		}
		if err := validateOwnerControlGeneration(pins, record.ActiveGeneration); err != nil {
			return nil, err
		}
		if err := validateOwnerExactTCXLinks(handle, record.ActiveLinks, runtime); err != nil {
			return nil, err
		}
		return &pinOwnerRecoveryResult{record: record}, nil
	case pinOwnerPhaseApplying:
		return recoverExactApplyingPinOwnerTransaction(ctx, handle, store, record, runtime)
	case pinOwnerPhaseDetaching:
		return recoverExactDetachingPinOwnerTransaction(ctx, handle, store, record, runtime)
	default:
		return nil, fmt.Errorf("cannot recover exact owner phase %q", record.Phase)
	}
}

func recoverExactApplyingPinOwnerTransaction(
	ctx context.Context,
	handle *pinPathHandle,
	store *pinOwnerStore,
	record *pinOwnerRecord,
	runtime exactTCXRuntime,
) (*pinOwnerRecoveryResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	requireCompleteMaps := record.ActiveGeneration != 0 ||
		record.Step != pinOwnerStepStaging
	pins, err := inspectPinnedMapSetWithPolicy(
		handle,
		requireCompleteMaps,
		false,
		false,
	)
	if err != nil {
		return nil, err
	}
	defer closePinnedMapPins(pins)
	if err := validateOwnerPins(
		handle,
		record,
		pins,
		requireCompleteMaps,
	); err != nil {
		return nil, err
	}

	switch record.Step {
	case pinOwnerStepStaging:
		if err := validateOwnerControlGeneration(pins, record.ActiveGeneration); err != nil {
			return nil, err
		}
		if err := validateJournaledAttachedOrDetachedExactTCXLinks(handle, record.ActiveLinks, runtime); err != nil {
			return nil, err
		}
		if err := removeOwnerProgramStages(handle, record); err != nil {
			return nil, err
		}
		now, err := ownerRuntimeNow(handle.runtime)
		if err != nil {
			return nil, err
		}
		if record.ActiveGeneration == 0 {
			detaching, err := newInitialAbortDetachingPinOwnerRecord(record, now)
			if err != nil {
				return nil, err
			}
			observeOwnerMount(detaching, handle.mountID)
			if err := store.Persist(detaching, record, handle.mountID); err != nil {
				return nil, err
			}
			return recoverExactDetachingPinOwnerTransaction(
				ctx, handle, store, detaching, runtime,
			)
		}
		active, err := abortApplyingPinOwnerRecord(record, now)
		if err != nil {
			return nil, err
		}
		observeOwnerMount(active, handle.mountID)
		if err := store.Persist(active, record, handle.mountID); err != nil {
			return nil, err
		}
		return recoverExactPinOwnerTransaction(ctx, handle, store, active, runtime)

	case pinOwnerStepMutating:
		programs, err := loadOwnerPrograms(handle, record)
		if err != nil {
			return nil, err
		}
		converged, err := convergeOwnerApplyExactTCXLinks(
			ctx, handle, store, record, programs, runtime,
		)
		if err != nil {
			return nil, errors.Join(err, programs.Close())
		}
		if err := programs.Close(); err != nil {
			return nil, err
		}
		record = converged
		controlValue, err := ownerControlValue(pins)
		if err != nil {
			return nil, err
		}
		switch controlValue.ActiveGeneration {
		case record.ActiveGeneration:
			if err := commitOwnerControlGeneration(handle, record, pins); err != nil {
				return nil, err
			}
		case record.NextGeneration:
			if controlValue.ABIVersion != abi.Version {
				return nil, errors.New("recovered exact owner control ABI is invalid")
			}
		default:
			return nil, fmt.Errorf(
				"exact owner control generation %d is outside journal old/new set",
				controlValue.ActiveGeneration,
			)
		}
		now, err := ownerRuntimeNow(handle.runtime)
		if err != nil {
			return nil, err
		}
		cleanup := advancePinOwnerRecord(
			record, now, pinOwnerPhaseApplying, pinOwnerStepCleanup,
		)
		observeOwnerMount(cleanup, handle.mountID)
		if err := store.Persist(cleanup, record, handle.mountID); err != nil {
			return nil, err
		}
		return recoverExactPinOwnerTransaction(ctx, handle, store, cleanup, runtime)

	case pinOwnerStepCleanup:
		if err := validateOwnerControlGeneration(pins, record.NextGeneration); err != nil {
			return nil, err
		}
		if err := validateOwnerExactTCXLinks(handle, record.DesiredLinks, runtime); err != nil {
			return nil, err
		}
		if err := removeStaleOwnerExactTCXLinks(
			handle, record.ActiveLinks, record.DesiredLinks, runtime,
		); err != nil {
			return nil, err
		}
		stale := staleExactTCXLinks(record.ActiveLinks, record.DesiredLinks)
		if err := validateOwnerExactTCXLinksAbsent(handle, stale, runtime); err != nil {
			return nil, err
		}
		if err := removeOwnerProgramStages(handle, record); err != nil {
			return nil, err
		}
		now, err := ownerRuntimeNow(handle.runtime)
		if err != nil {
			return nil, err
		}
		active := completeApplyingPinOwnerRecord(record, now)
		observeOwnerMount(active, handle.mountID)
		if err := store.Persist(active, record, handle.mountID); err != nil {
			return nil, err
		}
		return &pinOwnerRecoveryResult{record: active}, nil

	default:
		return nil, fmt.Errorf("cannot recover exact applying step %q", record.Step)
	}
}

func staleExactTCXLinks(
	active []exactTCXBinding,
	desired []exactTCXBinding,
) []exactTCXBinding {
	desiredSlots := make(map[string]struct{}, len(desired))
	for _, binding := range desired {
		desiredSlots[exactTCXOwnerKey(binding)] = struct{}{}
	}
	var stale []exactTCXBinding
	for _, binding := range active {
		if _, retained := desiredSlots[exactTCXOwnerKey(binding)]; !retained {
			stale = append(stale, binding)
		}
	}
	sortExactTCXBindings(stale)
	return stale
}

func rollbackFailedExactOwnerApplyLinks(
	handle *pinPathHandle,
	record *pinOwnerRecord,
	programs *loadedOwnerPrograms,
	runtime exactTCXRuntime,
) error {
	activeBySlot := make(map[string]exactTCXBinding, len(record.ActiveLinks))
	for _, binding := range record.ActiveLinks {
		activeBySlot[exactTCXOwnerKey(binding)] = binding
	}
	for _, desired := range record.DesiredLinks {
		active, replacing := activeBySlot[exactTCXOwnerKey(desired)]
		if !replacing {
			owner, _, err := observePinnedExactTCXAt(
				handle, desired, []uint32{desired.ProgramID}, runtime,
			)
			if err != nil {
				if (errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ENOENT)) &&
					desired.LinkID == 0 {
					continue
				}
				if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ENOENT) {
					absent, queryErr := exactTCXLinkAbsentFromOriginalSlot(desired, runtime)
					if queryErr != nil {
						return queryErr
					}
					if absent {
						continue
					}
				}
				return err
			}
			if err := owner.Rollback(); err != nil {
				return err
			}
			continue
		}
		owner, observed, err := observePinnedExactTCXAt(
			handle,
			active,
			[]uint32{active.ProgramID, desired.ProgramID},
			runtime,
		)
		if err != nil {
			return err
		}
		if !observed.Attached {
			return errors.Join(
				errors.New("active exact TCX link detached during apply rollback"),
				owner.Release(),
			)
		}
		owner.committed = true
		switch observed.Binding.ProgramID {
		case active.ProgramID:
			if err := owner.Release(); err != nil {
				return err
			}
		case desired.ProgramID:
			if desired.ProgramID == active.ProgramID {
				if err := owner.Release(); err != nil {
					return err
				}
				continue
			}
			previous, err := exactTCXProgramFromStages(programs, desired.ProgramID)
			if err != nil {
				return errors.Join(err, owner.Release())
			}
			next, err := exactTCXProgramFromStages(programs, active.ProgramID)
			if err != nil {
				return errors.Join(err, owner.Release())
			}
			journal := exactTCXJournal{
				persistIntent: func(exactTCXJournalIntent) error {
					return nil
				},
				persistIdentity: func(binding exactTCXBinding, _ exactTCXJournalIntent) error {
					if binding.LinkID != active.LinkID ||
						binding.ProgramID != active.ProgramID ||
						!sameExactTCXSlot(binding, active) {
						return errors.New("exact TCX rollback published an unexpected active link")
					}
					return nil
				},
			}
			if err := owner.CompareUpdateWithOld(previous, next, journal); err != nil {
				return errors.Join(err, owner.Release())
			}
			if err := owner.Release(); err != nil {
				return err
			}
		default:
			return errors.Join(
				errors.New("exact TCX rollback observed a third program"),
				owner.Release(),
			)
		}
	}
	return validateOwnerExactTCXLinks(handle, record.ActiveLinks, runtime)
}

func abortFailedExactOwnerApply(
	ctx context.Context,
	handle *pinPathHandle,
	store *pinOwnerStore,
	record *pinOwnerRecord,
	runtime exactTCXRuntime,
) error {
	if ctx == nil {
		return errors.New("failed exact owner apply rollback: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if record == nil || record.Phase != pinOwnerPhaseApplying ||
		(record.Step != pinOwnerStepStaging && record.Step != pinOwnerStepMutating) {
		return errors.New("failed exact owner apply is not at a rollback-safe journal step")
	}
	if err := validateOwnerDirectoryEntries(handle, record); err != nil {
		return err
	}
	requireCompleteMaps := record.ActiveGeneration != 0 ||
		record.Step != pinOwnerStepStaging
	pins, err := inspectPinnedMapSetWithPolicy(
		handle, requireCompleteMaps, false, false,
	)
	if err != nil {
		return err
	}
	defer closePinnedMapPins(pins)
	if err := validateOwnerPins(
		handle, record, pins, requireCompleteMaps,
	); err != nil {
		return err
	}
	if err := validateOwnerControlGeneration(pins, record.ActiveGeneration); err != nil {
		return err
	}
	if record.Step == pinOwnerStepMutating {
		programs, err := loadOwnerPrograms(handle, record)
		if err != nil {
			return err
		}
		if err := rollbackFailedExactOwnerApplyLinks(handle, record, programs, runtime); err != nil {
			return errors.Join(err, programs.Close())
		}
		if err := programs.Close(); err != nil {
			return err
		}
		now, err := ownerRuntimeNow(handle.runtime)
		if err != nil {
			return err
		}
		rolledBack := advancePinOwnerRecord(
			record,
			now,
			pinOwnerPhaseApplying,
			pinOwnerStepStaging,
		)
		observeOwnerMount(rolledBack, handle.mountID)
		if err := store.Persist(rolledBack, record, handle.mountID); err != nil {
			return err
		}
		record = rolledBack
	}
	_, err = recoverExactApplyingPinOwnerTransaction(
		ctx, handle, store, record, runtime,
	)
	return err
}

func executeExactOwnerDetachTransaction(
	ctx context.Context,
	handle *pinPathHandle,
	store *pinOwnerStore,
	active *pinOwnerRecord,
	runtime exactTCXRuntime,
) error {
	if ctx == nil {
		return errors.New("exact owner detach: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	now, err := ownerRuntimeNow(handle.runtime)
	if err != nil {
		return err
	}
	detaching, err := newDetachingPinOwnerRecord(active, now)
	if err != nil {
		return err
	}
	observeOwnerMount(detaching, handle.mountID)
	if err := store.Persist(detaching, active, handle.mountID); err != nil {
		return err
	}
	_, err = recoverExactDetachingPinOwnerTransaction(
		ctx, handle, store, detaching, runtime,
	)
	return err
}

func recoverExactDetachingPinOwnerTransaction(
	ctx context.Context,
	handle *pinPathHandle,
	store *pinOwnerStore,
	record *pinOwnerRecord,
	runtime exactTCXRuntime,
) (*pinOwnerRecoveryResult, error) {
	if ctx == nil {
		return nil, errors.New("exact owner detach recovery: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	switch record.Step {
	case pinOwnerStepStaging:
		pins, err := inspectPinnedMapSetWithPolicy(
			handle,
			record.ActiveGeneration != 0,
			record.ActiveGeneration != 0,
			false,
		)
		if err != nil {
			return nil, err
		}
		defer closePinnedMapPins(pins)
		if err := validateOwnerPins(
			handle, record, pins, record.ActiveGeneration != 0,
		); err != nil {
			return nil, err
		}
		if err := validateOwnerControlGeneration(pins, record.ActiveGeneration); err != nil {
			return nil, err
		}
		if err := validateJournaledAttachedOrDetachedExactTCXLinks(handle, record.ActiveLinks, runtime); err != nil {
			return nil, err
		}
		if err := stageOwnerMaps(handle, record, pins); err != nil {
			return nil, err
		}
		now, err := ownerRuntimeNow(handle.runtime)
		if err != nil {
			return nil, err
		}
		mutating := advancePinOwnerRecord(
			record, now, pinOwnerPhaseDetaching, pinOwnerStepMutatingTC,
		)
		observeOwnerMount(mutating, handle.mountID)
		if err := store.Persist(mutating, record, handle.mountID); err != nil {
			return nil, err
		}
		return recoverExactPinOwnerTransaction(ctx, handle, store, mutating, runtime)

	case pinOwnerStepMutatingTC:
		if err := removeAllOwnerExactTCXLinks(handle, record.ActiveLinks, runtime); err != nil {
			return nil, err
		}
		if err := validateOwnerExactTCXLinksAbsent(handle, record.ActiveLinks, runtime); err != nil {
			return nil, err
		}
		now, err := ownerRuntimeNow(handle.runtime)
		if err != nil {
			return nil, err
		}
		unlinking := advancePinOwnerRecord(
			record, now, pinOwnerPhaseDetaching, pinOwnerStepUnlinkingMaps,
		)
		observeOwnerMount(unlinking, handle.mountID)
		if err := store.Persist(unlinking, record, handle.mountID); err != nil {
			return nil, err
		}
		return recoverExactPinOwnerTransaction(ctx, handle, store, unlinking, runtime)

	case pinOwnerStepUnlinkingMaps:
		if err := validateOwnerExactTCXLinksAbsent(handle, record.ActiveLinks, runtime); err != nil {
			return nil, err
		}
		mapStages, err := loadOwnerMapStages(handle, record)
		if err != nil {
			return nil, err
		}
		defer mapStages.Close()
		partial, err := inspectPinnedMapSetWithPolicy(handle, false, false, false)
		if err != nil {
			return nil, err
		}
		defer closePinnedMapPins(partial)
		if err := validateOwnerPins(handle, record, partial, false); err != nil {
			return nil, err
		}
		if err := removeCanonicalOwnerMaps(handle, record, mapStages); err != nil {
			return nil, err
		}
		now, err := ownerRuntimeNow(handle.runtime)
		if err != nil {
			return nil, err
		}
		cleanup := advancePinOwnerRecord(
			record, now, pinOwnerPhaseDetaching, pinOwnerStepCleanupStages,
		)
		observeOwnerMount(cleanup, handle.mountID)
		if err := store.Persist(cleanup, record, handle.mountID); err != nil {
			return nil, err
		}
		return recoverExactPinOwnerTransaction(ctx, handle, store, cleanup, runtime)

	case pinOwnerStepCleanupStages:
		if err := validateOwnerExactTCXLinksAbsent(handle, record.ActiveLinks, runtime); err != nil {
			return nil, err
		}
		if err := removeOwnerProgramStages(handle, record); err != nil {
			return nil, err
		}
		if err := removeOwnerMapStages(handle, record); err != nil {
			return nil, err
		}
		empty, err := pinDirectoryIsEmpty(handle.targetFD, handle.pinPath)
		if err != nil {
			return nil, err
		}
		if !empty {
			return nil, errors.New("exact owner detach left unexpected BPF pin entries")
		}
		if err := store.Remove(record); err != nil {
			return nil, err
		}
		if err := handle.recheckTargetEntry(); err != nil {
			return nil, err
		}
		if err := unix.Unlinkat(handle.parentFD, handle.base, unix.AT_REMOVEDIR); err != nil {
			return nil, fmt.Errorf("remove empty owned BPF pin path %s: %w", handle.pinPath, err)
		}
		return &pinOwnerRecoveryResult{directoryRemoved: true}, nil

	default:
		return nil, fmt.Errorf("cannot recover exact detaching step %q", record.Step)
	}
}

func bindingSetsEqualExactTCX(left, right []exactTCXBinding) bool {
	leftCopy := slices.Clone(left)
	rightCopy := slices.Clone(right)
	sortExactTCXBindings(leftCopy)
	sortExactTCXBindings(rightCopy)
	return slices.Equal(leftCopy, rightCopy)
}
