//go:build linux

package dataplane

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"golang.org/x/sys/unix"
)

func rekeyRebootedPinOwner(
	handle *pinPathHandle,
	parent *pinPathParent,
	store *pinOwnerStore,
	entry *pinOwnerIndexEntry,
	bootID string,
	now time.Time,
	_ exactTCXRuntime,
) (*pinOwnerRecord, error) {
	if handle == nil || parent == nil || store == nil || entry == nil {
		return nil, errors.New("reboot owner rekey requires anchored current and indexed old owners")
	}
	if entry.BootID == bootID {
		return nil, errors.New("same-boot owner identity change cannot be rekeyed")
	}
	oldResource := pinResourceIdentity{
		key:          entry.ResourceKey,
		parentDevice: entry.ParentDevice,
		parentInode:  entry.ParentInode,
		base:         entry.PinBaseName,
		pinPath:      filepath.Join(entry.BPFFSRootPath, entry.PinBaseName),
	}
	oldFile, oldIdentity, err := openExistingAnchoredRegularFile(
		store.root,
		entry.RecordFileName,
		0o600,
		store.expectedUID,
	)
	if err != nil {
		return nil, fmt.Errorf("open indexed prior-boot owner record: %w", err)
	}
	defer oldFile.Close()
	oldRecord, err := readPinOwnerRecord(oldFile)
	if err != nil {
		return nil, err
	}
	if err := validatePinOwnerRecord(oldRecord, oldResource, 0); err != nil {
		return nil, fmt.Errorf("validate indexed prior-boot owner record: %w", err)
	}
	if oldRecord.Phase != pinOwnerPhaseActive ||
		oldRecord.Step != pinOwnerStepReady ||
		oldRecord.BootID != entry.BootID ||
		oldRecord.BPFFSRootPath != entry.BPFFSRootPath ||
		oldRecord.PinBaseName != entry.PinBaseName ||
		!slices.Equal(oldRecord.BPFFSMountIDs, entry.BPFFSMountIDs) {
		return nil, errors.New("indexed prior-boot owner metadata does not match its active record")
	}
	if _, err := validateAnchoredRegularFile(
		store.root,
		entry.RecordFileName,
		int(oldFile.Fd()),
		0o600,
		store.expectedUID,
		&oldIdentity,
	); err != nil {
		return nil, err
	}
	if err := validateRebootedExactTCXPinsAbsent(handle, oldRecord.ActiveLinks); err != nil {
		return nil, err
	}

	pins, err := inspectPinnedMapSet(handle, true)
	if err != nil {
		return nil, err
	}
	defer closePinnedMapPins(pins)
	if err := validateOwnerMapsAgainstPins(oldRecord, pins); err != nil {
		return nil, err
	}
	if err := validateOwnerControlGeneration(
		pins,
		oldRecord.ActiveGeneration,
	); err != nil {
		return nil, err
	}
	ownerPin, err := ownerMapPin(pins)
	if err != nil {
		return nil, err
	}
	if ownerPin.observation == nil ||
		!ownerPin.observation.ownerSeen ||
		ownerPin.observation.updateOwner == nil {
		return nil, errors.New("reboot owner_map is not mutable")
	}
	if err := recheckIndexedOwnerForRekey(
		store,
		entry,
		oldFile,
		oldIdentity,
		oldRecord,
	); err != nil {
		return nil, err
	}

	oldToken, err := tokenFromOwnerRecord(oldRecord)
	if err != nil {
		return nil, err
	}
	oldSentinel, err := pinOwnerSentinelFor(oldResource, oldToken)
	if err != nil {
		return nil, err
	}
	var newToken [32]byte
	switch {
	case ownerPin.observation.owner == oldSentinel:
		newToken, err = newPinOwnerToken(handle.runtime.random)
		if err != nil {
			return nil, err
		}
		newSentinel, err := pinOwnerSentinelFor(handle.resource, newToken)
		if err != nil {
			return nil, err
		}
		if err := ownerPin.observation.updateOwner(newSentinel); err != nil {
			return nil, fmt.Errorf("rekey rebooted owner_map sentinel: %w", err)
		}
	case ownerPin.observation.owner.Version == pinOwnerSentinelVersion &&
		ownerPin.observation.owner.Flags == 0:
		newToken = ownerPin.observation.owner.Token
		if subtle.ConstantTimeCompare(
			newToken[:],
			make([]byte, len(newToken)),
		) == 1 {
			return nil, errors.New("rekeyed owner_map contains an all-zero token")
		}
		want, err := pinOwnerSentinelFor(handle.resource, newToken)
		if err != nil {
			return nil, err
		}
		if ownerPin.observation.owner != want {
			return nil, errors.New("owner_map sentinel matches neither indexed old nor anchored current resource")
		}
	default:
		return nil, errors.New("owner_map sentinel is not eligible for controlled reboot rekey")
	}

	reloadedOwner, err := validatePinnedMapAt(
		handle,
		ownerPin.descriptor,
		ownerPin.descriptor.name,
		ownerPin.observation.id,
	)
	if err != nil {
		return nil, err
	}
	defer reloadedOwner.observation.Close()
	if err := validateOwnerSentinel(
		reloadedOwner.observation.owner,
		reloadedOwner.observation.ownerSeen,
		&pinOwnerRecord{Token: fmt.Sprintf("%x", newToken)},
		handle.resource,
	); err != nil {
		return nil, fmt.Errorf("validate rekeyed owner_map sentinel: %w", err)
	}

	record, err := newActivePinOwnerRecord(
		parent,
		newToken,
		bootID,
		now,
		oldRecord.ActiveGeneration,
		slices.Clone(oldRecord.Maps),
		nil,
	)
	if err != nil {
		return nil, err
	}
	record.RetiredFromResourceKey = oldRecord.ResourceKey
	record.RetiredFromBootID = oldRecord.BootID
	normalizePinOwnerRecord(record)
	if err := validatePinOwnerRecord(
		record,
		handle.resource,
		handle.mountID,
	); err != nil {
		return nil, err
	}
	if err := store.Persist(record, nil, handle.mountID); err != nil {
		return nil, fmt.Errorf("publish rekeyed reboot owner: %w", err)
	}
	return record, nil
}

func validateRebootedExactTCXPinsAbsent(
	handle *pinPathHandle,
	bindings []exactTCXBinding,
) error {
	if handle == nil {
		return errors.New("prior-boot exact TCX pin validation has no anchored directory")
	}
	if err := handle.recheckTargetEntry(); err != nil {
		return err
	}
	for _, binding := range bindings {
		if err := validateExactTCXBinding(binding, true); err != nil {
			return err
		}
		var stat unix.Stat_t
		err := unix.Fstatat(
			handle.targetFD,
			binding.PinName,
			&stat,
			unix.AT_SYMLINK_NOFOLLOW,
		)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return err
		}
		return fmt.Errorf(
			"prior-boot exact TCX pin %s still exists; refusing cross-boot link ID trust",
			binding.PinName,
		)
	}
	return nil
}

func recheckIndexedOwnerForRekey(
	store *pinOwnerStore,
	entry *pinOwnerIndexEntry,
	oldFile *os.File,
	oldIdentity pinPathInodeIdentity,
	oldRecord *pinOwnerRecord,
) error {
	if store == nil || entry == nil || oldFile == nil || oldRecord == nil {
		return errors.New("reboot rekey owner identity recheck is incomplete")
	}
	index, exists, err := indexStoreFromOwner(store).loadOptional()
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("reboot rekey owner index disappeared before mutation")
	}
	pointer, err := pinOwnerIndexPointerForPath(
		index,
		entry.BPFFSRootPath,
		entry.PinBaseName,
	)
	if err != nil || pointer == nil ||
		*pointer != activePointerFromEntry(*entry) ||
		pointer.Status != pinOwnerIndexRekeySource {
		return errors.Join(
			err,
			errors.New("reboot rekey source is not the exact active pointer"),
		)
	}
	found := false
	for _, candidate := range index.Entries {
		if candidate.ResourceKey != entry.ResourceKey ||
			candidate.BootID != entry.BootID {
			continue
		}
		if candidate.Status != pinOwnerIndexRekeySource ||
			!samePinOwnerIndexEntries(
				[]pinOwnerIndexEntry{candidate},
				[]pinOwnerIndexEntry{*entry},
			) {
			return errors.New("reboot rekey owner index entry changed before mutation")
		}
		found = true
		break
	}
	if !found {
		return errors.New("reboot rekey owner index entry disappeared before mutation")
	}
	if _, err := validateAnchoredRegularFile(
		store.root,
		entry.RecordFileName,
		int(oldFile.Fd()),
		0o600,
		store.expectedUID,
		&oldIdentity,
	); err != nil {
		return err
	}
	rechecked, err := readPinOwnerRecord(oldFile)
	if err != nil {
		return err
	}
	if !sameExpectedOwnerRecord(rechecked, oldRecord) {
		return errors.New("indexed prior-boot owner record changed before mutation")
	}
	return nil
}

func validateRebootedFiltersAbsent(
	bindings []tcFilterBinding,
	runtime tcRuntime,
) error {
	seen := make(map[string]struct{}, len(bindings))
	for _, binding := range bindings {
		key := ownerFilterKey(binding)
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("prior-boot owner repeats TC slot %s", key)
		}
		seen[key] = struct{}{}
		link, err := runtime.linkByIndex(binding.IfIndex)
		if err != nil {
			if isNotFound(err) {
				continue
			}
			return fmt.Errorf("inspect prior-boot TC link %d: %w", binding.IfIndex, err)
		}
		if link == nil ||
			link.Attrs() == nil ||
			link.Attrs().Index != binding.IfIndex {
			return fmt.Errorf(
				"prior-boot TC link lookup returned a mismatch for ifindex %d",
				binding.IfIndex,
			)
		}
		slot, err := ownerFilterSlot(binding)
		if err != nil {
			return err
		}
		snapshot, err := inspectTCFilterSlot(link, slot, runtime, false)
		if err != nil {
			return err
		}
		if snapshot.existed {
			return fmt.Errorf(
				"prior-boot TC slot %s still contains program ID %d; refusing cross-boot ID trust",
				key, snapshot.programID,
			)
		}
	}
	return nil
}

func indexedOwnerEntryForRekey(
	store *pinOwnerStore,
	handle *pinPathHandle,
) (*pinOwnerIndexEntry, error) {
	if store == nil || handle == nil {
		return nil, errors.New("indexed owner lookup requires store and handle")
	}
	entry, err := conflictingActiveOwnerIndexEntry(
		indexStoreFromOwner(store),
		handle.resource,
		filepath.Dir(handle.pinPath),
	)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	var stat unix.Stat_t
	if err := unix.Fstatat(
		store.root.FD(),
		entry.RecordFileName,
		&stat,
		unix.AT_SYMLINK_NOFOLLOW,
	); err != nil {
		return nil, fmt.Errorf("indexed old owner record is unavailable: %w", err)
	}
	return entry, nil
}
