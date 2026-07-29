//go:build linux

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/syx0310/wg-mix-ebpf/internal/lockfile"
	"golang.org/x/sys/unix"
)

func inspectPinOwnership(
	ctx context.Context,
	explicitPinPath string,
	recoverTransaction bool,
) (*PinOwnershipStatus, error) {
	loader := LinuxLoader{PinPath: explicitPinPath}
	return inspectPinOwnershipWithRuntime(
		ctx,
		pinPathFromEnv(explicitPinPath),
		recoverTransaction,
		loader.pinRuntime(ctx),
		liveTCRuntime,
	)
}

func inspectPinOwnershipWithRuntime(
	ctx context.Context,
	pinPath string,
	recoverTransaction bool,
	runtime pinPathRuntime,
	tcRuntime tcRuntime,
) (*PinOwnershipStatus, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	status := &PinOwnershipStatus{
		PinPath:   pinPath,
		OwnerRoot: runtime.ownerRoot,
		IndexPath: filepath.Join(runtime.ownerRoot, pinOwnerIndexFileName),
	}
	validated, err := validatePinPath(pinPath, runtime.validator)
	if err != nil {
		return status, err
	}
	parent, err := openPinPathParent(pinPath, validated, runtime)
	if err != nil {
		return status, err
	}
	defer parent.Close()
	status.ResourceKey = parent.resource.key
	status.RecordPath = filepath.Join(
		runtime.ownerRoot,
		parent.resource.key+".owner.json",
	)
	action := "inspect"
	if recoverTransaction {
		action = "recover"
	}
	lock, err := acquirePinPathLock(ctx, parent.resource, action, runtime)
	if err != nil {
		return status, err
	}
	defer lock.Close()
	validated, err = validatePinPath(pinPath, runtime.validator)
	if err != nil {
		return status, err
	}
	handle, _, err := openPinPathHandleFromParent(parent, validated, false)
	if err != nil {
		return status, err
	}
	if handle == nil {
		return inspectMissingPinDirectoryOwnership(
			status,
			runtime,
			parent,
			recoverTransaction,
		)
	}
	defer handle.Close()
	status.DirectoryExists = true

	store, err := openPinOwnerStoreWithPolicy(
		runtime,
		handle.resource,
		false,
		recoverTransaction,
	)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			directoryState, classifyErr := classifyCanonicalPinDirectory(handle)
			if classifyErr != nil {
				return status, classifyErr
			}
			status.LegacyPins = directoryState == canonicalPinsLegacy
			if directoryState == canonicalPinsEmpty {
				return status, nil
			}
		}
		return status, err
	}
	defer store.Close()
	descriptorPending, err := inspectPinOwnerDescriptorsReadOnly(store)
	if err != nil {
		return status, err
	}
	indexStore := indexStoreFromOwner(store)
	index, indexExists, indexPending, err :=
		indexStore.inspectOptionalReadOnly()
	if err != nil {
		return status, err
	}
	record, exists, err := store.LoadOptional(handle.mountID)
	if err != nil {
		return status, err
	}
	if exists {
		status.OwnerExists = true
		setPinOwnershipStatusRecord(status, record)
	}
	if descriptorPending || indexPending {
		status.RecoveryRequired = true
		return status, nil
	}
	if !exists {
		if indexExists {
			pointer, err := pinOwnerIndexPointerForResourceOrPath(
				index,
				handle.resource,
				filepath.Dir(handle.pinPath),
			)
			if err != nil {
				return status, err
			}
			if pointer != nil {
				indexed, err := pinOwnerIndexEntryForPointer(
					index,
					*pointer,
				)
				if err != nil {
					return status, err
				}
				historical, recordPath, err :=
					inspectIndexedOwnerEvidenceReadOnly(
						indexStore,
						*indexed,
					)
				if err != nil {
					return status, err
				}
				status.OwnerExists = true
				status.RecordPath = filepath.Join(
					runtime.ownerRoot,
					recordPath,
				)
				status.ResourceKey = historical.ResourceKey
				setPinOwnershipStatusRecord(status, historical)
				status.RecoveryRequired = true
				return status, nil
			}
		}
		directoryState, classifyErr := classifyCanonicalPinDirectory(handle)
		if classifyErr != nil {
			return status, classifyErr
		}
		status.LegacyPins = directoryState == canonicalPinsLegacy
		if directoryState == canonicalPinsEmpty {
			return status, nil
		}
		return status, errors.New(
			"BPF pins are present without a persistent owner record",
		)
	}
	if !indexExists {
		status.RecoveryRequired = true
		return status, nil
	}
	if _, err := activeIndexedOwnerForRecordInIndex(
		index,
		record,
	); err != nil {
		pointer, pointerErr := pinOwnerIndexPointerForResourceOrPath(
			index,
			handle.resource,
			record.BPFFSRootPath,
		)
		if pointerErr != nil ||
			pointer == nil ||
			pointer.Status != pinOwnerIndexRekeySource ||
			pointer.ResourceKey != record.RetiredFromResourceKey ||
			pointer.BootID != record.RetiredFromBootID {
			return status, errors.Join(err, pointerErr)
		}
		indexed, pointerErr := pinOwnerIndexEntryForPointer(
			index,
			*pointer,
		)
		if pointerErr != nil {
			return status, pointerErr
		}
		if _, _, pointerErr = inspectIndexedOwnerEvidenceReadOnly(
			indexStore,
			*indexed,
		); pointerErr != nil {
			return status, pointerErr
		}
		status.RecoveryRequired = true
		return status, nil
	}
	if recoverTransaction {
		if runtime.bootID == nil {
			return status, errors.New("pin owner boot ID runtime is unavailable")
		}
		currentBootID, err := runtime.bootID()
		if err != nil {
			return status, err
		}
		if currentBootID != record.BootID {
			return status, fmt.Errorf(
				"owner boot ID %s differs from current boot %s; use Apply for indexed reboot rekey",
				record.BootID, currentBootID,
			)
		}
		recovered, err := recoverPinOwnerTransaction(
			handle,
			store,
			record,
			tcRuntime,
		)
		if err != nil {
			return status, err
		}
		if recovered.directoryRemoved {
			status.DirectoryExists = false
			status.OwnerExists = false
			status.DirectoryRemoved = true
			status.RecoveryRequired = false
			return status, nil
		}
		record = recovered.record
		setPinOwnershipStatusRecord(status, record)
	}

	if err := validateOwnerDirectoryEntries(handle, record); err != nil {
		return status, err
	}
	if record.Phase != pinOwnerPhaseActive ||
		record.Step != pinOwnerStepReady {
		status.RecoveryRequired = true
		return status, nil
	}
	pins, err := inspectPinnedMapSet(handle, true)
	if err != nil {
		return status, err
	}
	defer closePinnedMapPins(pins)
	if err := validateOwnerPins(handle, record, pins, true); err != nil {
		return status, err
	}
	if err := validateOwnerControlGeneration(
		pins,
		record.ActiveGeneration,
	); err != nil {
		return status, err
	}
	if err := validateOwnerTCExact(
		record.ActiveFilters,
		record.ActiveFilters,
		tcRuntime,
	); err != nil {
		return status, err
	}
	return status, nil
}

func inspectMissingPinDirectoryOwnership(
	status *PinOwnershipStatus,
	runtime pinPathRuntime,
	parent *pinPathParent,
	recoverTransaction bool,
) (*PinOwnershipStatus, error) {
	store, err := openPinOwnerStoreWithPolicy(
		runtime,
		parent.resource,
		false,
		recoverTransaction,
	)
	if errors.Is(err, unix.ENOENT) {
		return status, nil
	}
	if err != nil {
		return status, err
	}
	defer store.Close()
	descriptorPending, err := inspectPinOwnerDescriptorsReadOnly(store)
	if err != nil {
		return status, err
	}
	indexStore := indexStoreFromOwner(store)
	index, indexExists, indexPending, err :=
		indexStore.inspectOptionalReadOnly()
	if err != nil {
		return status, err
	}
	record, recordExists, err := store.LoadOptional(parent.mountID)
	if err != nil {
		return status, err
	}
	if recordExists {
		status.OwnerExists = true
		setPinOwnershipStatusRecord(status, record)
	}
	if descriptorPending || indexPending {
		status.RecoveryRequired = true
		return status, nil
	}
	if recordExists {
		if !indexExists {
			status.RecoveryRequired = true
			return status, nil
		}
		if _, err := activeIndexedOwnerForRecordInIndex(
			index,
			record,
		); err != nil {
			pointer, pointerErr :=
				pinOwnerIndexPointerForResourceOrPath(
					index,
					parent.resource,
					record.BPFFSRootPath,
				)
			if pointerErr != nil ||
				pointer == nil ||
				pointer.Status != pinOwnerIndexRekeySource ||
				pointer.ResourceKey !=
					record.RetiredFromResourceKey ||
				pointer.BootID != record.RetiredFromBootID {
				return status, errors.Join(err, pointerErr)
			}
			indexed, pointerErr := pinOwnerIndexEntryForPointer(
				index,
				*pointer,
			)
			if pointerErr != nil {
				return status, pointerErr
			}
			if _, _, pointerErr =
				inspectIndexedOwnerEvidenceReadOnly(
					indexStore,
					*indexed,
				); pointerErr != nil {
				return status, pointerErr
			}
		}
		status.RecoveryRequired = true
		return status, nil
	}
	if !indexExists {
		return status, nil
	}
	pointer, err := pinOwnerIndexPointerForResourceOrPath(
		index,
		parent.resource,
		filepath.Dir(parent.pinPath),
	)
	if err != nil || pointer == nil {
		return status, err
	}
	indexed, err := pinOwnerIndexEntryForPointer(index, *pointer)
	if err != nil {
		return status, err
	}
	historical, recordPath, err := inspectIndexedOwnerEvidenceReadOnly(
		indexStore,
		*indexed,
	)
	if err != nil {
		return status, err
	}
	status.OwnerExists = true
	status.RecordPath = filepath.Join(runtime.ownerRoot, recordPath)
	status.ResourceKey = historical.ResourceKey
	setPinOwnershipStatusRecord(status, historical)
	status.RecoveryRequired = true
	return status, nil
}

func ensureMissingPinDirectoryHasNoActiveOwnership(
	runtime pinPathRuntime,
	parent *pinPathParent,
) error {
	if parent == nil {
		return errors.New(
			"missing pin directory ownership check has no parent anchor",
		)
	}
	store, err := openPinOwnerStore(
		runtime,
		parent.resource,
		false,
	)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	defer store.Close()
	if _, exists, err := store.LoadOptional(parent.mountID); err != nil {
		return err
	} else if exists {
		return errors.New(
			"BPF pin directory is missing while its persistent owner record remains",
		)
	}
	index, exists, err := indexStoreFromOwner(store).loadOptional()
	if err != nil || !exists {
		return err
	}
	pointer, err := pinOwnerIndexPointerForResourceOrPath(
		index,
		parent.resource,
		filepath.Dir(parent.pinPath),
	)
	if err != nil {
		return err
	}
	if pointer != nil {
		return fmt.Errorf(
			"BPF pin directory is missing while indexed owner %s/%s remains %s",
			pointer.ResourceKey,
			pointer.BootID,
			pointer.Status,
		)
	}
	return nil
}

func loadPinOwnerRecordNamedReadOnly(
	store *pinOwnerStore,
	name string,
) (*pinOwnerRecord, bool, error) {
	if store == nil || store.root == nil ||
		filepath.Base(name) != name {
		return nil, false, errors.New(
			"pin owner read-only target is unavailable",
		)
	}
	file, identity, err := openExistingAnchoredRegularFile(
		store.root,
		name,
		0o600,
		store.expectedUID,
	)
	if errors.Is(err, unix.ENOENT) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	record, err := readPinOwnerRecord(file)
	if err != nil {
		return nil, false, err
	}
	if err := validatePinOwnerRecord(record, store.resource, 0); err != nil {
		return nil, false, err
	}
	if _, err := validateAnchoredRegularFile(
		store.root,
		name,
		int(file.Fd()),
		0o600,
		store.expectedUID,
		&identity,
	); err != nil {
		return nil, false, err
	}
	rechecked, err := readPinOwnerRecord(file)
	if err != nil {
		return nil, false, err
	}
	if !sameExpectedOwnerRecord(rechecked, record) {
		return nil, false, errors.New(
			"pin owner record changed during read-only inspection",
		)
	}
	return record, true, nil
}

func inspectPinOwnerDescriptorsReadOnly(
	store *pinOwnerStore,
) (bool, error) {
	current, currentExists, err := loadPinOwnerRecordNamedReadOnly(
		store,
		store.fileName,
	)
	if err != nil {
		return false, err
	}
	next, nextExists, err := loadPinOwnerRecordNamedReadOnly(
		store,
		store.nextName,
	)
	if err != nil {
		return false, err
	}
	retired, retiredExists, err := loadPinOwnerRecordNamedReadOnly(
		store,
		store.retiredName,
	)
	if err != nil {
		return false, err
	}
	if nextExists && retiredExists {
		return false, errors.New(
			"next and retired pin owner records coexist",
		)
	}
	if retiredExists {
		if currentExists ||
			retired.Phase != pinOwnerPhaseDetaching ||
			retired.Step != pinOwnerStepCleanupStages {
			return false, errors.New(
				"retired pin owner record is inconsistent",
			)
		}
		return true, nil
	}
	if !nextExists {
		return false, nil
	}
	switch {
	case !currentExists && next.Sequence != 1:
		return false, errors.New(
			"initial pending pin owner sequence is not one",
		)
	case currentExists &&
		next.Sequence != current.Sequence+1 &&
		current.Sequence != next.Sequence+1:
		return false, errors.New(
			"ambiguous pin owner descriptor sequences",
		)
	case currentExists && !samePinOwnerImmutableFields(current, next):
		return false, errors.New(
			"pending pin owner immutable fields mismatch",
		)
	}
	return true, nil
}

func inspectIndexedOwnerEvidenceReadOnly(
	store *pinOwnerIndexStore,
	entry pinOwnerIndexEntry,
) (*pinOwnerRecord, string, error) {
	if entry.Status == pinOwnerIndexRekeySource {
		var archive unix.Stat_t
		err := unix.Fstatat(
			store.root.FD(),
			pinOwnerArchiveFileName(entry.ResourceKey),
			&archive,
			unix.AT_SYMLINK_NOFOLLOW,
		)
		if err == nil {
			return nil, "", errors.New(
				"durable rekey source coexists with a pin owner archive transient",
			)
		}
		if !errors.Is(err, unix.ENOENT) {
			return nil, "", err
		}
	}
	names := []string{entry.RecordFileName}
	if entry.Status == pinOwnerIndexActive {
		historical := entry
		historical.Status = pinOwnerIndexRetiredStatus
		historical.RecordFileName = pinOwnerHistoryFileName(historical)
		names = append(
			names,
			pinOwnerArchiveFileName(entry.ResourceKey),
			historical.RecordFileName,
		)
	}
	var (
		foundRecord *pinOwnerRecord
		foundName   string
	)
	for _, name := range names {
		var stat unix.Stat_t
		err := unix.Fstatat(
			store.root.FD(),
			name,
			&stat,
			unix.AT_SYMLINK_NOFOLLOW,
		)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return nil, "", err
		}
		if foundRecord != nil {
			return nil, "", errors.New(
				"multiple indexed pin owner evidence files coexist",
			)
		}
		history, err := validatePinOwnerHistoryAt(store, entry, name)
		if err != nil {
			return nil, "", err
		}
		foundRecord = clonePinOwnerRecord(history.record)
		foundName = name
		if err := history.Close(); err != nil {
			return nil, "", err
		}
	}
	if foundRecord == nil {
		return nil, "", errors.New(
			"indexed pin owner evidence is unavailable",
		)
	}
	return foundRecord, foundName, nil
}

func setPinOwnershipStatusRecord(
	status *PinOwnershipStatus,
	record *pinOwnerRecord,
) {
	if status == nil || record == nil {
		return
	}
	status.Version = record.Version
	status.Sequence = record.Sequence
	status.BootID = record.BootID
	status.Phase = record.Phase
	status.Step = record.Step
	status.ActiveGeneration = record.ActiveGeneration
	status.NextGeneration = record.NextGeneration
	status.MapCount = len(record.Maps)
	status.ActiveFilterCount = len(record.ActiveFilters)
	status.RecoveryRequired = record.Phase != pinOwnerPhaseActive ||
		record.Step != pinOwnerStepReady
}

func recoverPinOwnership(
	ctx context.Context,
	pinPath string,
	lifecycleLease *lockfile.LifecycleLease,
) (status *PinOwnershipStatus, returnErr error) {
	retained, err := retainPinOwnershipLifecycleLease(
		ctx,
		lifecycleLease,
	)
	if err != nil {
		return nil, err
	}
	defer func() {
		returnErr = errors.Join(returnErr, retained.Close())
	}()
	return inspectPinOwnership(ctx, pinPath, true)
}

func detachPinOwnership(
	ctx context.Context,
	pinPath string,
	lifecycleLease *lockfile.LifecycleLease,
) (returnErr error) {
	retained, err := retainPinOwnershipLifecycleLease(
		ctx,
		lifecycleLease,
	)
	if err != nil {
		return err
	}
	defer func() {
		returnErr = errors.Join(returnErr, retained.Close())
	}()
	return (LinuxLoader{PinPath: pinPath}).Detach(ctx, nil)
}

func retainPinOwnershipLifecycleLease(
	ctx context.Context,
	lifecycleLease *lockfile.LifecycleLease,
) (*lockfile.LifecycleLease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path := lockfile.LifecycleLeasePath(ctx)
	if lifecycleLease == nil || !lifecycleLease.HeldAt(path) {
		return nil, fmt.Errorf(
			"%w at %s",
			ErrPinOwnershipLifecycleLeaseRequired,
			path,
		)
	}
	retained, err := lifecycleLease.Retain()
	if err != nil {
		return nil, fmt.Errorf(
			"%w at %s: retain lease: %v",
			ErrPinOwnershipLifecycleLeaseRequired,
			path,
			err,
		)
	}
	if !retained.HeldAt(path) {
		_ = retained.Close()
		return nil, fmt.Errorf(
			"%w at %s: retained lease identity changed",
			ErrPinOwnershipLifecycleLeaseRequired,
			path,
		)
	}
	return retained, nil
}
