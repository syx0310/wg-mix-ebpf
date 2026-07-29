//go:build linux

package dataplane

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
	"golang.org/x/sys/unix"
)

type pinOwnerRecoveryResult struct {
	record           *pinOwnerRecord
	directoryRemoved bool
}

func ownerRuntimeNow(runtime pinPathRuntime) (time.Time, error) {
	if runtime.now == nil {
		return time.Time{}, errors.New("pin owner clock is unavailable")
	}
	now := runtime.now().UTC()
	if now.IsZero() {
		return time.Time{}, errors.New("pin owner clock returned zero time")
	}
	return now, nil
}

func observeOwnerMount(record *pinOwnerRecord, mountID uint64) {
	if record == nil || mountID == 0 {
		return
	}
	if !slices.Contains(record.BPFFSMountIDs, mountID) {
		record.BPFFSMountIDs = append(record.BPFFSMountIDs, mountID)
	}
	normalizePinOwnerRecord(record)
}

func validateOwnerPins(
	handle *pinPathHandle,
	record *pinOwnerRecord,
	pins []pinnedMapPin,
	requireComplete bool,
) error {
	if requireComplete {
		if err := validateOwnerMapsAgainstPins(record, pins); err != nil {
			return err
		}
	} else {
		recordMaps := make(map[string]uint32, len(record.Maps))
		for _, ownerMap := range record.Maps {
			recordMaps[ownerMap.Name] = ownerMap.ID
		}
		for _, pin := range pins {
			wantID, exists := recordMaps[pin.descriptor.name]
			if !exists || pin.observation == nil || pin.observation.id != wantID {
				return fmt.Errorf(
					"partial canonical pin %s is outside the owner record",
					pin.descriptor.name,
				)
			}
		}
	}
	ownerPin, err := ownerMapPin(pins)
	if err != nil {
		if requireComplete {
			return err
		}
		return nil
	}
	return validateOwnerSentinel(
		ownerPin.observation.owner,
		ownerPin.observation.ownerSeen,
		record,
		handle.resource,
	)
}

func ownerControlValue(pins []pinnedMapPin) (abi.ControlValue, error) {
	for _, pin := range pins {
		if pin.descriptor.name != "control_map" {
			continue
		}
		if pin.observation == nil || !pin.observation.controlSeen {
			return abi.ControlValue{}, errors.New("owner control_map value is unavailable")
		}
		return pin.observation.control, nil
	}
	return abi.ControlValue{}, errors.New("owner canonical set is missing control_map")
}

func validateOwnerControlGeneration(
	pins []pinnedMapPin,
	generation uint64,
) error {
	value, err := ownerControlValue(pins)
	if err != nil {
		if generation == 0 {
			for _, pin := range pins {
				if pin.descriptor.name == "control_map" {
					return err
				}
			}
			return nil
		}
		return err
	}
	if generation == 0 {
		if value != (abi.ControlValue{}) {
			return fmt.Errorf(
				"fresh owner control value = %+v, want zero",
				value,
			)
		}
		return nil
	}
	if value.ActiveGeneration != generation ||
		value.ABIVersion != abi.Version {
		return fmt.Errorf(
			"owner control value generation/ABI = %d/%d, want %d/%d",
			value.ActiveGeneration, value.ABIVersion,
			generation, abi.Version,
		)
	}
	return nil
}

func commitOwnerControlGeneration(
	handle *pinPathHandle,
	record *pinOwnerRecord,
	pins []pinnedMapPin,
) error {
	if record == nil || record.NextGeneration == 0 {
		return errors.New("owner recovery has no next generation to commit")
	}
	for _, pin := range pins {
		if pin.descriptor.name != "control_map" {
			continue
		}
		if pin.observation == nil || pin.observation.updateControl == nil {
			return errors.New("owner control_map update is unavailable")
		}
		value := abi.ControlValue{
			ActiveGeneration: record.NextGeneration,
			ABIVersion:       abi.Version,
		}
		if err := pin.observation.updateControl(value); err != nil {
			return fmt.Errorf("commit recovered owner control generation: %w", err)
		}
		reloaded, err := validatePinnedMapAt(
			handle,
			pin.descriptor,
			pin.descriptor.name,
			pin.observation.id,
		)
		if err != nil {
			return err
		}
		defer reloaded.observation.Close()
		if !reloaded.observation.controlSeen ||
			reloaded.observation.control != value {
			return errors.New("owner control_map did not retain recovered generation")
		}
		return nil
	}
	return errors.New("owner canonical set is missing control_map")
}

func recoverPinOwnerTransaction(
	handle *pinPathHandle,
	store *pinOwnerStore,
	record *pinOwnerRecord,
	tcRuntime tcRuntime,
) (*pinOwnerRecoveryResult, error) {
	if handle == nil || store == nil || record == nil {
		return nil, errors.New("owner recovery requires a handle, store, and record")
	}
	if err := validatePinOwnerRecord(
		record,
		handle.resource,
		handle.mountID,
	); err != nil {
		return nil, err
	}
	if err := validateOwnerDirectoryEntries(handle, record); err != nil {
		return nil, err
	}
	now, err := ownerRuntimeNow(handle.runtime)
	if err != nil {
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
		if err := validateOwnerControlGeneration(
			pins,
			record.ActiveGeneration,
		); err != nil {
			return nil, err
		}
		if err := validateOwnerTCExact(
			record.ActiveFilters,
			record.ActiveFilters,
			tcRuntime,
		); err != nil {
			return nil, err
		}
		return &pinOwnerRecoveryResult{record: record}, nil

	case pinOwnerPhaseApplying:
		return recoverApplyingPinOwnerTransaction(
			handle,
			store,
			record,
			now,
			tcRuntime,
		)

	case pinOwnerPhaseDetaching:
		return recoverDetachingPinOwnerTransaction(
			handle,
			store,
			record,
			now,
			tcRuntime,
		)

	default:
		return nil, fmt.Errorf("cannot recover owner phase %q", record.Phase)
	}
}

func recoverApplyingPinOwnerTransaction(
	handle *pinPathHandle,
	store *pinOwnerStore,
	record *pinOwnerRecord,
	now time.Time,
	tcRuntime tcRuntime,
) (*pinOwnerRecoveryResult, error) {
	pins, err := inspectPinnedMapSetWithPolicy(
		handle,
		record.ActiveGeneration != 0,
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
		record.ActiveGeneration != 0,
	); err != nil {
		return nil, err
	}
	covered := retainStaleOwnerFilters(
		record.DesiredFilters,
		record.ActiveFilters,
	)

	switch record.Step {
	case pinOwnerStepStaging:
		if err := validateOwnerControlGeneration(
			pins,
			record.ActiveGeneration,
		); err != nil {
			return nil, err
		}
		if err := validateOwnerTCExact(
			record.ActiveFilters,
			covered,
			tcRuntime,
		); err != nil {
			return nil, err
		}
		if record.ActiveGeneration == 0 {
			if err := removeOwnerProgramStages(handle, record); err != nil {
				return nil, err
			}
			detaching, err := newInitialAbortDetachingPinOwnerRecord(
				record,
				now,
			)
			if err != nil {
				return nil, err
			}
			observeOwnerMount(detaching, handle.mountID)
			if err := store.Persist(detaching, record, handle.mountID); err != nil {
				return nil, err
			}
			return recoverDetachingPinOwnerTransaction(
				handle,
				store,
				detaching,
				now,
				tcRuntime,
			)
		}
		if err := removeOwnerProgramStages(handle, record); err != nil {
			return nil, err
		}
		active, err := abortApplyingPinOwnerRecord(record, now)
		if err != nil {
			return nil, err
		}
		observeOwnerMount(active, handle.mountID)
		if err := store.Persist(active, record, handle.mountID); err != nil {
			return nil, err
		}
		return &pinOwnerRecoveryResult{record: active}, nil

	case pinOwnerStepMutating:
		programs, err := loadOwnerPrograms(handle, record)
		if err != nil {
			return nil, err
		}
		defer programs.Close()
		if err := rollForwardOwnerApplyFilters(
			record.ActiveFilters,
			record.DesiredFilters,
			programs,
			tcRuntime,
		); err != nil {
			return nil, err
		}
		control, err := ownerControlValue(pins)
		if err != nil {
			return nil, err
		}
		switch control.ActiveGeneration {
		case record.ActiveGeneration:
			if err := commitOwnerControlGeneration(
				handle,
				record,
				pins,
			); err != nil {
				return nil, err
			}
		case record.NextGeneration:
			if control.ABIVersion != abi.Version {
				return nil, errors.New("recovered owner control ABI is invalid")
			}
		default:
			return nil, fmt.Errorf(
				"owner control generation %d is outside journal old/new set",
				control.ActiveGeneration,
			)
		}
		cleanup := advancePinOwnerRecord(
			record,
			now,
			pinOwnerPhaseApplying,
			pinOwnerStepCleanup,
		)
		observeOwnerMount(cleanup, handle.mountID)
		if err := store.Persist(cleanup, record, handle.mountID); err != nil {
			return nil, err
		}
		return recoverApplyingPinOwnerTransaction(
			handle,
			store,
			cleanup,
			now,
			tcRuntime,
		)

	case pinOwnerStepCleanup:
		if err := validateOwnerControlGeneration(
			pins,
			record.NextGeneration,
		); err != nil {
			return nil, err
		}
		if err := validateOwnerTCExact(
			record.DesiredFilters,
			covered,
			tcRuntime,
		); err != nil {
			return nil, err
		}
		if err := removeOwnerProgramStages(handle, record); err != nil {
			return nil, err
		}
		active := completeApplyingPinOwnerRecord(record, now)
		observeOwnerMount(active, handle.mountID)
		if err := store.Persist(active, record, handle.mountID); err != nil {
			return nil, err
		}
		return &pinOwnerRecoveryResult{record: active}, nil

	default:
		return nil, fmt.Errorf("cannot recover applying step %q", record.Step)
	}
}

func abortFailedOwnerApply(
	handle *pinPathHandle,
	store *pinOwnerStore,
	record *pinOwnerRecord,
	tcRuntime tcRuntime,
) error {
	if record == nil ||
		record.Phase != pinOwnerPhaseApplying ||
		(record.Step != pinOwnerStepStaging &&
			record.Step != pinOwnerStepMutating) {
		return errors.New("failed owner apply is not at a rollback-safe journal step")
	}
	if err := validateOwnerDirectoryEntries(handle, record); err != nil {
		return err
	}
	pins, err := inspectPinnedMapSetWithPolicy(
		handle,
		record.ActiveGeneration != 0,
		false,
		false,
	)
	if err != nil {
		return err
	}
	defer closePinnedMapPins(pins)
	if err := validateOwnerPins(
		handle,
		record,
		pins,
		record.ActiveGeneration != 0,
	); err != nil {
		return err
	}
	if err := validateOwnerControlGeneration(
		pins,
		record.ActiveGeneration,
	); err != nil {
		return err
	}
	covered := retainStaleOwnerFilters(
		record.DesiredFilters,
		record.ActiveFilters,
	)
	if err := validateOwnerTCExact(
		record.ActiveFilters,
		covered,
		tcRuntime,
	); err != nil {
		return fmt.Errorf(
			"TC rollback did not restore the owner journal's active set: %w",
			err,
		)
	}
	now, err := ownerRuntimeNow(handle.runtime)
	if err != nil {
		return err
	}
	if record.ActiveGeneration == 0 {
		if err := removeOwnerProgramStages(handle, record); err != nil {
			return err
		}
		detaching, err := newInitialAbortDetachingPinOwnerRecord(
			record,
			now,
		)
		if err != nil {
			return err
		}
		observeOwnerMount(detaching, handle.mountID)
		if err := store.Persist(
			detaching,
			record,
			handle.mountID,
		); err != nil {
			return err
		}
		_, err = recoverDetachingPinOwnerTransaction(
			handle,
			store,
			detaching,
			now,
			tcRuntime,
		)
		return err
	}
	if err := removeOwnerProgramStages(handle, record); err != nil {
		return err
	}
	active, err := abortApplyingPinOwnerRecord(record, now)
	if err != nil {
		return err
	}
	observeOwnerMount(active, handle.mountID)
	return store.Persist(active, record, handle.mountID)
}

func executeOwnerDetachTransaction(
	handle *pinPathHandle,
	store *pinOwnerStore,
	active *pinOwnerRecord,
	tcRuntime tcRuntime,
) error {
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

	pins, err := inspectPinnedMapSet(handle, true)
	if err != nil {
		return err
	}
	defer closePinnedMapPins(pins)
	if err := validateOwnerPins(handle, detaching, pins, true); err != nil {
		return err
	}
	if err := stageOwnerPrograms(handle, detaching); err != nil {
		return err
	}
	if err := stageOwnerMaps(handle, detaching, pins); err != nil {
		return err
	}
	mutating := advancePinOwnerRecord(
		detaching,
		now,
		pinOwnerPhaseDetaching,
		pinOwnerStepMutatingTC,
	)
	observeOwnerMount(mutating, handle.mountID)
	if err := store.Persist(mutating, detaching, handle.mountID); err != nil {
		return err
	}
	programs, err := loadOwnerPrograms(handle, mutating)
	if err != nil {
		return err
	}
	defer programs.Close()
	mapStages, err := loadOwnerMapStages(handle, mutating)
	if err != nil {
		return err
	}
	defer mapStages.Close()
	if err := rollForwardOwnerDetachFilters(
		mutating.ActiveFilters,
		programs,
		tcRuntime,
	); err != nil {
		rollbackErr := rollbackOwnerDetachToActive(
			handle,
			store,
			mutating,
			programs,
			mapStages,
			tcRuntime,
		)
		return errors.Join(
			err,
			wrapNonNilError("rollback failed owner detach", rollbackErr),
		)
	}
	unlinking := advancePinOwnerRecord(
		mutating,
		now,
		pinOwnerPhaseDetaching,
		pinOwnerStepUnlinkingMaps,
	)
	observeOwnerMount(unlinking, handle.mountID)
	if err := store.Persist(unlinking, mutating, handle.mountID); err != nil {
		return err
	}
	if err := removeCanonicalOwnerMaps(
		handle,
		unlinking,
		mapStages,
	); err != nil {
		rollbackErr := rollbackOwnerDetachToActive(
			handle,
			store,
			unlinking,
			programs,
			mapStages,
			tcRuntime,
		)
		return errors.Join(
			err,
			wrapNonNilError("rollback failed owner map unlink", rollbackErr),
		)
	}
	cleanup := advancePinOwnerRecord(
		unlinking,
		now,
		pinOwnerPhaseDetaching,
		pinOwnerStepCleanupStages,
	)
	observeOwnerMount(cleanup, handle.mountID)
	if err := store.Persist(cleanup, unlinking, handle.mountID); err != nil {
		return err
	}
	_, err = recoverDetachingPinOwnerTransaction(
		handle,
		store,
		cleanup,
		now,
		tcRuntime,
	)
	return err
}

func wrapNonNilError(prefix string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", prefix, err)
}

func rollbackOwnerDetachToActive(
	handle *pinPathHandle,
	store *pinOwnerStore,
	record *pinOwnerRecord,
	programs *loadedOwnerPrograms,
	mapStages *loadedOwnerMapStages,
	tcRuntime tcRuntime,
) error {
	var errs []error
	if err := restoreCanonicalOwnerMaps(
		handle,
		record,
		mapStages,
	); err != nil {
		errs = append(errs, fmt.Errorf("restore canonical owner maps: %w", err))
	}
	if err := restoreOwnerActiveFilters(
		record.ActiveFilters,
		programs,
		tcRuntime,
	); err != nil {
		errs = append(errs, fmt.Errorf("restore owner TC filters: %w", err))
	}
	if len(errs) != 0 {
		return errors.Join(errs...)
	}
	if err := removeOwnerProgramStages(handle, record); err != nil {
		return err
	}
	if err := removeOwnerMapStages(handle, record); err != nil {
		return err
	}
	now, err := ownerRuntimeNow(handle.runtime)
	if err != nil {
		return err
	}
	active, err := abortDetachingPinOwnerRecord(record, now)
	if err != nil {
		return err
	}
	observeOwnerMount(active, handle.mountID)
	return store.Persist(active, record, handle.mountID)
}

func recoverRolledBackOwnerDetach(
	handle *pinPathHandle,
	store *pinOwnerStore,
	record *pinOwnerRecord,
	now time.Time,
	tcRuntime tcRuntime,
) (*pinOwnerRecoveryResult, bool, error) {
	if record.ActiveGeneration == 0 ||
		(record.Step != pinOwnerStepMutatingTC &&
			record.Step != pinOwnerStepUnlinkingMaps) {
		return nil, false, nil
	}
	if err := validateOwnerTCExact(
		record.ActiveFilters,
		record.ActiveFilters,
		tcRuntime,
	); err != nil {
		return nil, false, nil
	}
	pins, err := inspectPinnedMapSet(handle, true)
	if err != nil {
		return nil, false, nil
	}
	defer closePinnedMapPins(pins)
	if err := validateOwnerPins(handle, record, pins, true); err != nil {
		return nil, false, nil
	}
	if err := validateOwnerControlGeneration(
		pins,
		record.ActiveGeneration,
	); err != nil {
		return nil, false, nil
	}
	if err := removeOwnerProgramStages(handle, record); err != nil {
		return nil, true, err
	}
	if err := removeOwnerMapStages(handle, record); err != nil {
		return nil, true, err
	}
	active, err := abortDetachingPinOwnerRecord(record, now)
	if err != nil {
		return nil, true, err
	}
	observeOwnerMount(active, handle.mountID)
	if err := store.Persist(active, record, handle.mountID); err != nil {
		return nil, true, err
	}
	return &pinOwnerRecoveryResult{record: active}, true, nil
}

func recoverDetachingPinOwnerTransaction(
	handle *pinPathHandle,
	store *pinOwnerStore,
	record *pinOwnerRecord,
	now time.Time,
	tcRuntime tcRuntime,
) (*pinOwnerRecoveryResult, error) {
	if recovered, handled, err := recoverRolledBackOwnerDetach(
		handle,
		store,
		record,
		now,
		tcRuntime,
	); handled {
		return recovered, err
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
			handle,
			record,
			pins,
			record.ActiveGeneration != 0,
		); err != nil {
			return nil, err
		}
		if err := validateOwnerControlGeneration(
			pins,
			record.ActiveGeneration,
		); err != nil {
			return nil, err
		}
		if err := validateOwnerTCExact(
			record.ActiveFilters,
			record.ActiveFilters,
			tcRuntime,
		); err != nil {
			return nil, err
		}
		if err := stageOwnerPrograms(handle, record); err != nil {
			return nil, err
		}
		if err := stageOwnerMaps(handle, record, pins); err != nil {
			return nil, err
		}
		mutating := advancePinOwnerRecord(
			record,
			now,
			pinOwnerPhaseDetaching,
			pinOwnerStepMutatingTC,
		)
		observeOwnerMount(mutating, handle.mountID)
		if err := store.Persist(mutating, record, handle.mountID); err != nil {
			return nil, err
		}
		return recoverDetachingPinOwnerTransaction(
			handle,
			store,
			mutating,
			now,
			tcRuntime,
		)

	case pinOwnerStepMutatingTC:
		programs, err := loadOwnerPrograms(handle, record)
		if err != nil {
			return nil, err
		}
		defer programs.Close()
		mapStages, err := loadOwnerMapStages(handle, record)
		if err != nil {
			return nil, err
		}
		defer mapStages.Close()
		if err := rollForwardOwnerDetachFilters(
			record.ActiveFilters,
			programs,
			tcRuntime,
		); err != nil {
			return nil, err
		}
		unlinking := advancePinOwnerRecord(
			record,
			now,
			pinOwnerPhaseDetaching,
			pinOwnerStepUnlinkingMaps,
		)
		observeOwnerMount(unlinking, handle.mountID)
		if err := store.Persist(unlinking, record, handle.mountID); err != nil {
			return nil, err
		}
		return recoverDetachingPinOwnerTransaction(
			handle,
			store,
			unlinking,
			now,
			tcRuntime,
		)

	case pinOwnerStepUnlinkingMaps:
		if err := validateOwnerTCExact(
			nil,
			record.ActiveFilters,
			tcRuntime,
		); err != nil {
			return nil, err
		}
		mapStages, err := loadOwnerMapStages(handle, record)
		if err != nil {
			return nil, err
		}
		defer mapStages.Close()
		partial, err := inspectPinnedMapSetWithPolicy(
			handle,
			false,
			false,
			false,
		)
		if err != nil {
			return nil, err
		}
		defer closePinnedMapPins(partial)
		if err := validateOwnerPins(
			handle,
			record,
			partial,
			false,
		); err != nil {
			return nil, err
		}
		if err := removeCanonicalOwnerMaps(
			handle,
			record,
			mapStages,
		); err != nil {
			return nil, err
		}
		cleanup := advancePinOwnerRecord(
			record,
			now,
			pinOwnerPhaseDetaching,
			pinOwnerStepCleanupStages,
		)
		observeOwnerMount(cleanup, handle.mountID)
		if err := store.Persist(cleanup, record, handle.mountID); err != nil {
			return nil, err
		}
		return recoverDetachingPinOwnerTransaction(
			handle,
			store,
			cleanup,
			now,
			tcRuntime,
		)

	case pinOwnerStepCleanupStages:
		if err := validateOwnerTCExact(
			nil,
			record.ActiveFilters,
			tcRuntime,
		); err != nil {
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
			return nil, errors.New("owner detach left unexpected BPF pin entries")
		}
		if err := store.Remove(record); err != nil {
			return nil, err
		}
		if err := handle.recheckTargetEntry(); err != nil {
			return nil, err
		}
		if err := unix.Unlinkat(
			handle.parentFD,
			handle.base,
			unix.AT_REMOVEDIR,
		); err != nil {
			return nil, fmt.Errorf(
				"remove empty owned BPF pin path %s: %w",
				handle.pinPath, err,
			)
		}
		return &pinOwnerRecoveryResult{directoryRemoved: true}, nil

	default:
		return nil, fmt.Errorf("cannot recover detaching step %q", record.Step)
	}
}
