//go:build linux

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
	"golang.org/x/sys/unix"
)

func recoverExactPinOwnerTransaction(
	ctx context.Context,
	handle *pinPathHandle,
	store exactTCXOwnerStore,
	record *pinOwnerRecord,
	runtime exactTCXRuntime,
) (result *pinOwnerRecoveryResult, returnErr error) {
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
		defer func() {
			returnErr = errors.Join(returnErr, closePinnedMapPins(pins))
		}()
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
	store exactTCXOwnerStore,
	record *pinOwnerRecord,
	runtime exactTCXRuntime,
) (result *pinOwnerRecoveryResult, returnErr error) {
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
	defer func() {
		returnErr = errors.Join(returnErr, closePinnedMapPins(pins))
	}()
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
		controlValue, err := ownerControlValue(pins)
		if err != nil {
			return nil, err
		}
		switch controlValue.ActiveGeneration {
		case record.ActiveGeneration:
			if err := validateOwnerControlGeneration(pins, record.ActiveGeneration); err != nil {
				return nil, err
			}
			// The target generation was never published. A restart must abort
			// rather than silently turn an already reported apply failure into
			// a successful target configuration.
			return beginExactOwnerApplyRollback(
				ctx, handle, store, record, runtime,
			)
		case record.NextGeneration:
			if controlValue.ABIVersion != abi.Version {
				return nil, errors.New("recovered exact owner control ABI is invalid")
			}
			// The atomic control commit is the forward-recovery decision point.
		default:
			return nil, fmt.Errorf(
				"exact owner control generation %d is outside journal old/new set",
				controlValue.ActiveGeneration,
			)
		}
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

	case pinOwnerStepRollingBack:
		return recoverExactRollingBackPinOwnerTransaction(
			ctx, handle, store, record, runtime,
		)

	case pinOwnerStepRollbackCleanup:
		return recoverExactRollbackCleanupPinOwnerTransaction(
			ctx, handle, store, record, runtime,
		)

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

func rollbackAllowedProgramIDs(
	active exactTCXBinding,
	desired exactTCXBinding,
	hasDesired bool,
) []uint32 {
	ids := []uint32{active.ProgramID}
	if hasDesired && desired.ProgramID != active.ProgramID {
		ids = append(ids, desired.ProgramID)
	}
	return ids
}

func validateRollbackActiveExactTCXLinks(
	handle *pinPathHandle,
	bindings []exactTCXBinding,
	runtime exactTCXRuntime,
) error {
	for _, binding := range bindings {
		if binding.LinkID == 0 || binding.PinPending || binding.Retiring {
			return fmt.Errorf("rollback active exact TCX slot %s has an incomplete replacement identity", exactTCXOwnerKey(binding))
		}
		owner, err := validatePinnedExactTCXAt(handle, binding, runtime)
		if err != nil {
			return err
		}
		if err := owner.Release(); err != nil {
			return err
		}
	}
	return nil
}

func validateRetiredDesiredBehindRollbackReplacement(
	handle *pinPathHandle,
	active exactTCXBinding,
	desired exactTCXBinding,
	runtime exactTCXRuntime,
) error {
	if active.ReplacesLinkID == 0 || desired.LinkID == 0 ||
		desired.LinkID == active.LinkID || !sameExactTCXSlot(active, desired) {
		return errors.New("invalid rollback replacement retirement proof")
	}

	// Once a completed rollback replacement owns the deterministic path, that
	// path no longer names the failed target. Hold an exact, anchored handle to
	// the replacement while proving the target link ID absent by an independent
	// slot query. A missing replacement pin is recoverable below; any present
	// but mismatched pin is foreign and must fail closed without mutation.
	var owner *exactTCXAttachment
	var observed *exactTCXObservation
	if active.LinkID != 0 {
		var err error
		owner, observed, err = observePinnedExactTCXAt(
			handle, active, []uint32{active.ProgramID}, runtime,
		)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, unix.ENOENT) {
				return fmt.Errorf("validate rollback replacement exact TCX pin: %w", err)
			}
			owner = nil
		}
	}

	if owner != nil && !observed.Attached {
		absent, err := exactTCXLinkAbsentFromOriginalSlot(active, runtime)
		if err != nil {
			return errors.Join(err, owner.Release())
		}
		if !absent {
			return errors.Join(
				fmt.Errorf(
					"detached rollback replacement exact TCX link %d remains in its original slot",
					active.LinkID,
				),
				owner.Release(),
			)
		}
	}
	absent, err := exactTCXLinkAbsentFromOriginalSlot(desired, runtime)
	if owner != nil {
		err = errors.Join(err, owner.Release())
	}
	if err != nil {
		return err
	}
	if !absent {
		return fmt.Errorf(
			"failed-apply exact TCX target link %d remains behind rollback replacement %d",
			desired.LinkID, active.LinkID,
		)
	}
	return nil
}

func rollbackFailedExactOwnerApplyLinks(
	ctx context.Context,
	handle *pinPathHandle,
	record *pinOwnerRecord,
	programs *loadedOwnerPrograms,
	store exactTCXOwnerStore,
	runtime exactTCXRuntime,
) (*pinOwnerRecord, error) {
	if record == nil || record.Phase != pinOwnerPhaseApplying ||
		record.Step != pinOwnerStepRollingBack {
		return record, errors.New("exact TCX rollback requires durable rolling_back intent")
	}
	current := record
	desiredBySlot := make(map[string]exactTCXBinding, len(current.DesiredLinks))
	for _, desired := range current.DesiredLinks {
		desiredBySlot[exactTCXOwnerKey(desired)] = desired
	}

	// Retire target-only links first. The rolling_back record is already a
	// durable promise never to publish them as the old generation.
	activeSlots := make(map[string]struct{}, len(current.ActiveLinks))
	for _, active := range current.ActiveLinks {
		activeSlots[exactTCXOwnerKey(active)] = struct{}{}
	}
	for _, desired := range current.DesiredLinks {
		if _, existed := activeSlots[exactTCXOwnerKey(desired)]; existed || desired.LinkID == 0 {
			continue
		}
		if err := removeOwnedExactTCXLink(handle, desired, runtime); err != nil {
			return current, fmt.Errorf("retire failed-apply exact TCX link %s: %w", desired.PinName, err)
		}
	}

	for index := 0; index < len(current.ActiveLinks); index++ {
		if err := ctx.Err(); err != nil {
			return current, err
		}
		active := current.ActiveLinks[index]
		if err := retryRetainedUnpinnedExactTCXOwner(
			filepath.Join(handle.procPath(), active.PinName),
		); err != nil {
			return current, err
		}
		desired, hasDesired := desiredBySlot[exactTCXOwnerKey(active)]
		originalLinkID := active.LinkID
		if active.ReplacesLinkID != 0 {
			originalLinkID = active.ReplacesLinkID
		}
		original := active
		original.LinkID = originalLinkID
		original.ReplacesLinkID = 0
		original.PinPending = false
		original.Retiring = false

		// A forward replacement may already own the deterministic path. Retire
		// that exact new identity before recovering the old program. Once a
		// rollback replacement marker exists, however, the path belongs to the
		// rollback identity; only an exact slot query may prove the old target
		// absent, and the shared pin must never be opened as that target.
		if hasDesired && desired.LinkID != 0 && desired.LinkID != active.LinkID {
			if active.ReplacesLinkID != 0 {
				if active.LinkID == 0 {
					// The replacement lineage is durable but no rollback link
					// identity has been published yet. The shared path may still
					// hold the exact failed target from the pre-crash retirement.
					if err := removeOwnedExactTCXLink(handle, desired, runtime); err != nil {
						return current, fmt.Errorf(
							"complete rollback target retirement %s: %w",
							desired.PinName, err,
						)
					}
				} else {
					if err := validateRetiredDesiredBehindRollbackReplacement(
						handle, active, desired, runtime,
					); err != nil {
						return current, err
					}
				}
			} else if err := removeOwnedExactTCXLink(handle, desired, runtime); err != nil {
				return current, fmt.Errorf(
					"retire replacement exact TCX link %s: %w",
					desired.PinName, err,
				)
			}
		}

		if active.ReplacesLinkID == 0 {
			owner, observed, err := observePinnedExactTCXAt(
				handle,
				active,
				rollbackAllowedProgramIDs(active, desired, hasDesired),
				runtime,
			)
			if err == nil {
				if !observed.Attached {
					replacing, persistErr := ownerRecordReplacingRollbackActive(
						current, active, handle, store,
					)
					if persistErr != nil {
						return current, errors.Join(persistErr, owner.Release())
					}
					current = replacing
					if err := owner.Rollback(); err != nil {
						return current, err
					}
					active = current.ActiveLinks[index]
				} else {
					owner.committed = true
					switch observed.Binding.ProgramID {
					case active.ProgramID:
						if err := owner.Release(); err != nil {
							return current, err
						}
						continue
					case desired.ProgramID:
						if !hasDesired || desired.ProgramID == active.ProgramID {
							return current, errors.Join(
								errors.New("exact TCX rollback observed an unexplained program"),
								owner.Release(),
							)
						}
						previous, err := exactTCXProgramFromStages(programs, desired.ProgramID)
						if err != nil {
							return current, errors.Join(err, owner.Release())
						}
						next, err := exactTCXProgramFromStages(programs, active.ProgramID)
						if err != nil {
							return current, errors.Join(err, owner.Release())
						}
						journal := rollingBackExactTCXJournal(&current, handle, store, index)
						if err := owner.CompareUpdateWithOld(previous, next, journal); err != nil {
							return current, errors.Join(err, owner.Release())
						}
						if err := owner.Release(); err != nil {
							return current, err
						}
						continue
					default:
						return current, errors.Join(
							errors.New("exact TCX rollback observed a third program"),
							owner.Release(),
						)
					}
				}
			} else if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, unix.ENOENT) {
				return current, err
			} else {
				absent, queryErr := exactTCXLinkAbsentFromOriginalSlot(original, runtime)
				if queryErr != nil {
					return current, queryErr
				}
				if !absent {
					return current, fmt.Errorf("rollback active exact TCX link %d lost its pin while attached", original.LinkID)
				}
				replacing, persistErr := ownerRecordReplacingRollbackActive(
					current, active, handle, store,
				)
				if persistErr != nil {
					return current, persistErr
				}
				current = replacing
				active = current.ActiveLinks[index]
			}
		}

		if active.ReplacesLinkID == 0 {
			continue
		}
		if active.LinkID != 0 {
			owner, observed, err := observePinnedExactTCXAt(
				handle, active, []uint32{active.ProgramID}, runtime,
			)
			if err == nil && observed.Attached {
				journal := rollingBackExactTCXJournal(&current, handle, store, index)
				completed := observed.Binding
				completed.ReplacesLinkID = active.ReplacesLinkID
				completed.PinPending = false
				if err := journal.persistIdentity(
					completed,
					exactTCXJournalIntent{Operation: exactTCXJournalAttach, Desired: active},
				); err != nil {
					return current, errors.Join(err, owner.Release())
				}
				if err := owner.Release(); err != nil {
					return current, err
				}
				continue
			}
			if err == nil {
				if err := owner.Rollback(); err != nil {
					return current, err
				}
			} else if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, unix.ENOENT) {
				return current, err
			} else {
				absent, queryErr := exactTCXLinkAbsentFromOriginalSlot(active, runtime)
				if queryErr != nil {
					return current, queryErr
				}
				if !absent {
					return current, fmt.Errorf("rollback replacement exact TCX link %d lost its pin while attached", active.LinkID)
				}
			}
			reset, err := ownerRecordResetRollbackActiveIdentity(current, active, handle, store)
			if err != nil {
				return current, err
			}
			current = reset
			active = current.ActiveLinks[index]
		}

		program, err := exactTCXProgramFromStages(programs, active.ProgramID)
		if err != nil {
			return current, err
		}
		binding := active
		binding.LinkID = 0
		binding.PinPending = false
		binding.Retiring = false
		journal := rollingBackExactTCXJournal(&current, handle, store, index)
		owner, err := stageExactTCXAttachment(
			ctx,
			binding,
			filepath.Join(handle.procPath(), binding.PinName),
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
	return current, validateRollbackActiveExactTCXLinks(handle, current.ActiveLinks, runtime)
}

func beginExactOwnerApplyRollback(
	ctx context.Context,
	handle *pinPathHandle,
	store exactTCXOwnerStore,
	record *pinOwnerRecord,
	runtime exactTCXRuntime,
) (*pinOwnerRecoveryResult, error) {
	if ctx == nil {
		return nil, errors.New("begin exact owner apply rollback: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if record == nil || record.Phase != pinOwnerPhaseApplying || record.Step != pinOwnerStepMutating {
		return nil, errors.New("exact owner apply rollback can only begin from mutating")
	}
	now, err := ownerRuntimeNow(handle.runtime)
	if err != nil {
		return nil, err
	}
	rollingBack := advancePinOwnerRecord(
		record, now, pinOwnerPhaseApplying, pinOwnerStepRollingBack,
	)
	observeOwnerMount(rollingBack, handle.mountID)
	if err := store.Persist(rollingBack, record, handle.mountID); err != nil {
		return nil, fmt.Errorf("persist exact owner rollback intent: %w", err)
	}
	return recoverExactRollingBackPinOwnerTransaction(
		ctx, handle, store, rollingBack, runtime,
	)
}

func recoverExactRollingBackPinOwnerTransaction(
	ctx context.Context,
	handle *pinPathHandle,
	store exactTCXOwnerStore,
	record *pinOwnerRecord,
	runtime exactTCXRuntime,
) (result *pinOwnerRecoveryResult, returnErr error) {
	if ctx == nil {
		return nil, errors.New("recover exact owner rollback: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if record == nil || record.Phase != pinOwnerPhaseApplying ||
		record.Step != pinOwnerStepRollingBack {
		return nil, errors.New("recover exact owner rollback requires rolling_back journal state")
	}
	if err := validateOwnerDirectoryEntries(handle, record); err != nil {
		return nil, err
	}
	pins, err := inspectPinnedMapSetWithPolicy(handle, true, false, false)
	if err != nil {
		return nil, err
	}
	defer func() {
		returnErr = errors.Join(returnErr, closePinnedMapPins(pins))
	}()
	if err := validateOwnerPins(handle, record, pins, true); err != nil {
		return nil, err
	}
	if err := validateOwnerControlGeneration(pins, record.ActiveGeneration); err != nil {
		return nil, fmt.Errorf("refuse exact owner rollback after control commit: %w", err)
	}
	programs, err := loadOwnerPrograms(handle, record)
	if err != nil {
		return nil, err
	}
	current, rollbackErr := rollbackFailedExactOwnerApplyLinks(
		ctx, handle, record, programs, store, runtime,
	)
	closeErr := programs.Close()
	if rollbackErr != nil || closeErr != nil {
		return nil, errors.Join(rollbackErr, closeErr)
	}
	now, err := ownerRuntimeNow(handle.runtime)
	if err != nil {
		return nil, err
	}
	cleanup := advancePinOwnerRecord(
		current, now, pinOwnerPhaseApplying, pinOwnerStepRollbackCleanup,
	)
	observeOwnerMount(cleanup, handle.mountID)
	if err := store.Persist(cleanup, current, handle.mountID); err != nil {
		return nil, err
	}
	return recoverExactRollbackCleanupPinOwnerTransaction(
		ctx, handle, store, cleanup, runtime,
	)
}

func recoverExactRollbackCleanupPinOwnerTransaction(
	ctx context.Context,
	handle *pinPathHandle,
	store exactTCXOwnerStore,
	record *pinOwnerRecord,
	runtime exactTCXRuntime,
) (result *pinOwnerRecoveryResult, returnErr error) {
	if ctx == nil {
		return nil, errors.New("recover exact owner rollback cleanup: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if record == nil || record.Phase != pinOwnerPhaseApplying ||
		record.Step != pinOwnerStepRollbackCleanup {
		return nil, errors.New("recover exact owner rollback cleanup requires rollback_cleanup journal state")
	}
	if err := validateOwnerDirectoryEntries(handle, record); err != nil {
		return nil, err
	}
	pins, err := inspectPinnedMapSetWithPolicy(handle, true, false, false)
	if err != nil {
		return nil, err
	}
	defer func() {
		returnErr = errors.Join(returnErr, closePinnedMapPins(pins))
	}()
	if err := validateOwnerPins(handle, record, pins, true); err != nil {
		return nil, err
	}
	if err := validateOwnerControlGeneration(pins, record.ActiveGeneration); err != nil {
		return nil, fmt.Errorf("refuse exact owner rollback cleanup after control commit: %w", err)
	}
	if err := validateRollbackActiveExactTCXLinks(handle, record.ActiveLinks, runtime); err != nil {
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
	rollbackSource := clonePinOwnerRecord(record)
	for index := range rollbackSource.ActiveLinks {
		if rollbackSource.ActiveLinks[index].LinkID == 0 ||
			rollbackSource.ActiveLinks[index].PinPending ||
			rollbackSource.ActiveLinks[index].Retiring {
			return nil, fmt.Errorf("rollback active exact TCX slot %s is not publishable", rollbackSource.ActiveLinks[index].PinName)
		}
		rollbackSource.ActiveLinks[index].ReplacesLinkID = 0
	}
	active, err := abortApplyingPinOwnerRecord(rollbackSource, now)
	if err != nil {
		return nil, err
	}
	observeOwnerMount(active, handle.mountID)
	if err := store.Persist(active, record, handle.mountID); err != nil {
		return nil, err
	}
	return &pinOwnerRecoveryResult{record: active}, nil
}

func abortFailedExactOwnerApply(
	ctx context.Context,
	handle *pinPathHandle,
	store exactTCXOwnerStore,
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
		(record.Step != pinOwnerStepStaging &&
			record.Step != pinOwnerStepMutating &&
			record.Step != pinOwnerStepRollingBack &&
			record.Step != pinOwnerStepRollbackCleanup) {
		return errors.New("failed exact owner apply is not at a rollback-safe journal step")
	}
	if err := validateOwnerDirectoryEntries(handle, record); err != nil {
		return err
	}
	_, err := recoverExactApplyingPinOwnerTransaction(
		ctx, handle, store, record, runtime,
	)
	return err
}

func executeExactOwnerDetachTransaction(
	ctx context.Context,
	handle *pinPathHandle,
	store exactTCXOwnerStore,
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
	store exactTCXOwnerStore,
	record *pinOwnerRecord,
	runtime exactTCXRuntime,
) (result *pinOwnerRecoveryResult, returnErr error) {
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
		defer func() {
			returnErr = errors.Join(returnErr, closePinnedMapPins(pins))
		}()
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
		defer func() {
			returnErr = errors.Join(returnErr, mapStages.Close())
		}()
		partial, err := inspectPinnedMapSetWithPolicy(handle, false, false, false)
		if err != nil {
			return nil, err
		}
		defer func() {
			returnErr = errors.Join(returnErr, closePinnedMapPins(partial))
		}()
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
