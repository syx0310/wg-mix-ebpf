//go:build linux

package dataplane

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"time"

	"golang.org/x/sys/unix"
)

func pinOwnerArchiveFileName(resourceKey string) string {
	return resourceKey + pinOwnerArchiveSuffix
}

func pinOwnerIndexEntryForPointer(
	index *pinOwnerIndex,
	pointer pinOwnerIndexActivePointer,
) (*pinOwnerIndexEntry, error) {
	if index == nil {
		return nil, errors.New("pin owner index is unavailable")
	}
	for entryIndex := range index.Entries {
		entry := &index.Entries[entryIndex]
		if entry.ResourceKey == pointer.ResourceKey &&
			entry.BootID == pointer.BootID {
			if activePointerFromEntry(*entry) != pointer {
				return nil, errors.New(
					"pin owner active pointer changed from its indexed entry",
				)
			}
			return entry, nil
		}
	}
	return nil, errors.New("pin owner active pointer has no indexed entry")
}

func pinOwnerIndexPointerForPath(
	index *pinOwnerIndex,
	rootPath string,
	baseName string,
) (*pinOwnerIndexActivePointer, error) {
	if index == nil {
		return nil, nil
	}
	for pointerIndex := range index.Active {
		pointer := &index.Active[pointerIndex]
		if pointer.BPFFSRootPath == rootPath &&
			pointer.PinBaseName == baseName {
			return pointer, nil
		}
	}
	return nil, nil
}

func pinOwnerIndexPointerForResourceOrPath(
	index *pinOwnerIndex,
	resource pinResourceIdentity,
	rootPath string,
) (*pinOwnerIndexActivePointer, error) {
	if index == nil {
		return nil, nil
	}
	var pathPointer *pinOwnerIndexActivePointer
	var resourcePointer *pinOwnerIndexActivePointer
	for pointerIndex := range index.Active {
		pointer := &index.Active[pointerIndex]
		if pointer.BPFFSRootPath == rootPath &&
			pointer.PinBaseName == resource.base {
			if pathPointer != nil {
				return nil, errors.New(
					"pin owner index has multiple active pointers for one path",
				)
			}
			pathPointer = pointer
		}
		entry, err := pinOwnerIndexEntryForPointer(index, *pointer)
		if err != nil {
			return nil, err
		}
		if !pinOwnerIndexEntryMatchesResource(*entry, resource) {
			continue
		}
		if resourcePointer != nil {
			return nil, errors.New(
				"pin owner index has multiple active pointers for one resource",
			)
		}
		resourcePointer = pointer
	}
	if pathPointer != nil &&
		resourcePointer != nil &&
		pinOwnerIndexEntryKey(
			pathPointer.ResourceKey,
			pathPointer.BootID,
		) != pinOwnerIndexEntryKey(
			resourcePointer.ResourceKey,
			resourcePointer.BootID,
		) {
		return nil, errors.New(
			"pin owner index path and FD-anchored resource pointers disagree",
		)
	}
	if resourcePointer != nil {
		return resourcePointer, nil
	}
	return pathPointer, nil
}

func activeIndexedOwnerForRecord(
	store *pinOwnerIndexStore,
	record *pinOwnerRecord,
) (*pinOwnerIndexEntry, error) {
	if store == nil || record == nil {
		return nil, errors.New("active indexed owner lookup is incomplete")
	}
	index, exists, err := store.loadOptional()
	if err != nil || !exists {
		return nil, errors.Join(
			err,
			errors.New("active pin owner index is unavailable"),
		)
	}
	return activeIndexedOwnerForRecordInIndex(index, record)
}

func activeIndexedOwnerForRecordInIndex(
	index *pinOwnerIndex,
	record *pinOwnerRecord,
) (*pinOwnerIndexEntry, error) {
	if index == nil || record == nil {
		return nil, errors.New(
			"active indexed owner lookup is incomplete",
		)
	}
	pointer, err := pinOwnerIndexPointerForPath(
		index,
		record.BPFFSRootPath,
		record.PinBaseName,
	)
	if err != nil || pointer == nil ||
		pointer.Status != pinOwnerIndexActive ||
		pointer.ResourceKey != record.ResourceKey ||
		pointer.BootID != record.BootID {
		return nil, errors.Join(
			err,
			errors.New("active pin owner record lacks its exact index pointer"),
		)
	}
	entry, err := pinOwnerIndexEntryForPointer(index, *pointer)
	if err != nil {
		return nil, err
	}
	digest, err := pinOwnerRecordDigest(record)
	if err != nil {
		return nil, err
	}
	if entry.OwnerDigest != digest ||
		entry.RecordFileName != record.ResourceKey+".owner.json" {
		return nil, errors.New(
			"active pin owner record digest differs from its index entry",
		)
	}
	copy := *entry
	copy.BPFFSMountIDs = slices.Clone(entry.BPFFSMountIDs)
	return &copy, nil
}

func loadIndexedPriorBootOwner(
	store *pinOwnerIndexStore,
	entry pinOwnerIndexEntry,
) (*pinOwnerRecord, error) {
	history, err := validatePinOwnerHistoryAt(
		store,
		entry,
		entry.RecordFileName,
	)
	if err != nil {
		return nil, err
	}
	record := clonePinOwnerRecord(history.record)
	if err := history.Close(); err != nil {
		return nil, err
	}
	return record, nil
}

func (store *pinOwnerIndexStore) recoverOwnerArchive(
	resource pinResourceIdentity,
) error {
	index, exists, err := store.loadOptional()
	if err != nil || !exists {
		return err
	}
	pointer, err := pinOwnerIndexPointerForResourceOrPath(
		index,
		resource,
		filepath.Dir(resource.pinPath),
	)
	if err != nil || pointer == nil {
		return err
	}
	if pointer.Status == pinOwnerIndexRekeySource {
		entry, err := pinOwnerIndexEntryForPointer(index, *pointer)
		if err != nil {
			return err
		}
		history, err := validatePinOwnerHistoryAt(
			store,
			*entry,
			entry.RecordFileName,
		)
		if err != nil {
			return err
		}
		if err := history.Close(); err != nil {
			return err
		}
		archiveName := pinOwnerArchiveFileName(entry.ResourceKey)
		var archive unix.Stat_t
		if err := unix.Fstatat(
			store.root.FD(),
			archiveName,
			&archive,
			unix.AT_SYMLINK_NOFOLLOW,
		); err == nil {
			return errors.New(
				"durable rekey source coexists with a pin owner archive transient",
			)
		} else if !errors.Is(err, unix.ENOENT) {
			return err
		}
		canonicalName := entry.ResourceKey + ".owner.json"
		canonical, canonicalIdentity, err :=
			openExistingAnchoredRegularFile(
				store.root,
				canonicalName,
				0o600,
				store.expectedUID,
			)
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		if err != nil {
			return err
		}
		defer canonical.Close()
		record, err := readPinOwnerRecord(canonical)
		if err != nil {
			return err
		}
		resource := pinResourceIdentity{
			key:          entry.ResourceKey,
			parentDevice: entry.ParentDevice,
			parentInode:  entry.ParentInode,
			base:         entry.PinBaseName,
			pinPath: filepath.Join(
				entry.BPFFSRootPath,
				entry.PinBaseName,
			),
		}
		if err := validatePinOwnerRecord(record, resource, 0); err != nil {
			return err
		}
		if record.RetiredFromResourceKey != entry.ResourceKey ||
			record.RetiredFromBootID != entry.BootID ||
			record.BootID == entry.BootID {
			return errors.New(
				"canonical owner coexisting with rekey source lacks exact reboot lineage",
			)
		}
		if _, err := validateAnchoredRegularFile(
			store.root,
			canonicalName,
			int(canonical.Fd()),
			0o600,
			store.expectedUID,
			&canonicalIdentity,
		); err != nil {
			return err
		}
		rechecked, err := readPinOwnerRecord(canonical)
		if err != nil {
			return err
		}
		if !sameExpectedOwnerRecord(rechecked, record) {
			return errors.New(
				"canonical reboot owner changed during archive recovery",
			)
		}
		return nil
	}
	if pointer.Status != pinOwnerIndexActive {
		return fmt.Errorf(
			"pin owner active pointer has unsupported archive status %q",
			pointer.Status,
		)
	}
	entry, err := pinOwnerIndexEntryForPointer(index, *pointer)
	if err != nil {
		return err
	}
	canonicalName := entry.RecordFileName
	archiveName := pinOwnerArchiveFileName(entry.ResourceKey)
	historical := *entry
	historical.Status = pinOwnerIndexRetiredStatus
	historical.RecordFileName = pinOwnerHistoryFileName(historical)
	names := []string{
		canonicalName,
		archiveName,
		historical.RecordFileName,
	}
	existsByName := make(map[string]bool, len(names))
	for _, name := range names {
		var stat unix.Stat_t
		err := unix.Fstatat(
			store.root.FD(),
			name,
			&stat,
			unix.AT_SYMLINK_NOFOLLOW,
		)
		switch {
		case err == nil:
			existsByName[name] = true
		case errors.Is(err, unix.ENOENT):
		default:
			return err
		}
	}
	if existsByName[canonicalName] {
		if existsByName[archiveName] ||
			existsByName[historical.RecordFileName] {
			return errors.New(
				"canonical and transitional pin owner archive files coexist",
			)
		}
		history, err := validatePinOwnerHistoryAt(
			store,
			*entry,
			canonicalName,
		)
		if err != nil {
			return err
		}
		return history.Close()
	}
	sourceName := ""
	switch {
	case existsByName[archiveName] &&
		!existsByName[historical.RecordFileName]:
		sourceName = archiveName
	case !existsByName[archiveName] &&
		existsByName[historical.RecordFileName]:
		sourceName = historical.RecordFileName
	default:
		return errors.New(
			"pin owner archive recovery found an ambiguous or missing transition file",
		)
	}
	history, err := validatePinOwnerHistoryAt(store, *entry, sourceName)
	if err != nil {
		return err
	}
	if err := history.Close(); err != nil {
		return err
	}
	if err := unix.Renameat2(
		store.root.FD(),
		sourceName,
		store.root.FD(),
		canonicalName,
		unix.RENAME_NOREPLACE,
	); err != nil {
		return fmt.Errorf("roll back interrupted pin owner archive: %w", err)
	}
	if err := unix.Fsync(store.root.FD()); err != nil {
		return err
	}
	recovered, err := validatePinOwnerHistoryAt(
		store,
		*entry,
		canonicalName,
	)
	if err != nil {
		return err
	}
	return recovered.Close()
}

func (store *pinOwnerIndexStore) archivePriorBootOwner(
	entry pinOwnerIndexEntry,
	record *pinOwnerRecord,
	pinsOwned bool,
	now time.Time,
) (*pinOwnerIndexEntry, error) {
	if store == nil || record == nil {
		return nil, errors.New("pin owner archive requires store and record")
	}
	if record.BootID != entry.BootID ||
		record.ResourceKey != entry.ResourceKey ||
		record.BPFFSRootPath != entry.BPFFSRootPath ||
		record.PinBaseName != entry.PinBaseName ||
		!slices.Equal(record.BPFFSMountIDs, entry.BPFFSMountIDs) {
		return nil, errors.New(
			"prior-boot owner record does not match its active index entry",
		)
	}
	if pinsOwned &&
		(record.Phase != pinOwnerPhaseActive ||
			record.Step != pinOwnerStepReady) {
		return nil, errors.New(
			"owned reboot pins require an active/ready prior-boot owner",
		)
	}
	digest, err := pinOwnerRecordDigest(record)
	if err != nil {
		return nil, err
	}
	if entry.Status != pinOwnerIndexActive ||
		entry.RecordFileName != entry.ResourceKey+".owner.json" ||
		entry.OwnerDigest != digest {
		return nil, errors.New(
			"prior-boot active owner digest or filename is inconsistent",
		)
	}
	historical := entry
	historical.Status = pinOwnerIndexRekeySource
	historical.RetiredAt = now.UTC().Format(time.RFC3339Nano)
	historical.RecordFileName = pinOwnerHistoryFileName(historical)
	archiveName := pinOwnerArchiveFileName(entry.ResourceKey)
	for _, name := range []string{archiveName, historical.RecordFileName} {
		var stat unix.Stat_t
		if err := unix.Fstatat(
			store.root.FD(),
			name,
			&stat,
			unix.AT_SYMLINK_NOFOLLOW,
		); err == nil {
			return nil, fmt.Errorf(
				"pin owner archive target %s already exists",
				name,
			)
		} else if !errors.Is(err, unix.ENOENT) {
			return nil, err
		}
	}
	pinOwnerIndexMutationMu.Lock()
	defer pinOwnerIndexMutationMu.Unlock()
	if err := store.ensureHistoryCapacityLocked(entry, now); err != nil {
		return nil, err
	}
	index, exists, err := store.loadOptionalLocked()
	if err != nil || !exists {
		return nil, errors.Join(
			err,
			errors.New("pin owner index disappeared before archive"),
		)
	}
	pointer, err := pinOwnerIndexPointerForPath(
		index,
		entry.BPFFSRootPath,
		entry.PinBaseName,
	)
	if err != nil || pointer == nil ||
		*pointer != activePointerFromEntry(entry) {
		return nil, errors.Join(
			err,
			errors.New("pin owner active pointer changed before archive"),
		)
	}
	indexed, err := pinOwnerIndexEntryForPointer(index, *pointer)
	if err != nil || indexed == nil ||
		!samePinOwnerIndexEntries(
			[]pinOwnerIndexEntry{*indexed},
			[]pinOwnerIndexEntry{entry},
		) {
		return nil, errors.Join(
			err,
			errors.New("pin owner index entry changed before archive"),
		)
	}
	canonical, err := validatePinOwnerHistoryAt(
		store,
		entry,
		entry.RecordFileName,
	)
	if err != nil {
		return nil, err
	}
	canonicalIdentity := canonical.identity
	if err := canonical.Close(); err != nil {
		return nil, err
	}
	for _, name := range []string{archiveName, historical.RecordFileName} {
		var stat unix.Stat_t
		if err := unix.Fstatat(
			store.root.FD(),
			name,
			&stat,
			unix.AT_SYMLINK_NOFOLLOW,
		); err == nil {
			return nil, fmt.Errorf(
				"pin owner archive target %s already exists",
				name,
			)
		} else if !errors.Is(err, unix.ENOENT) {
			return nil, err
		}
	}
	if store.beforeOwnerExchange != nil {
		store.beforeOwnerExchange()
	}
	canonical, err = validatePinOwnerHistoryAt(
		store,
		entry,
		entry.RecordFileName,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"prior-boot owner changed at archive hook: %w",
			err,
		)
	}
	if !samePinPathInode(canonical.identity, canonicalIdentity) {
		_ = canonical.Close()
		return nil, errors.New(
			"prior-boot owner identity changed at archive hook",
		)
	}
	if err := canonical.Close(); err != nil {
		return nil, err
	}
	if err := unix.Renameat2(
		store.root.FD(),
		entry.RecordFileName,
		store.root.FD(),
		archiveName,
		unix.RENAME_NOREPLACE,
	); err != nil {
		return nil, fmt.Errorf("quarantine prior-boot pin owner: %w", err)
	}
	if err := unix.Fsync(store.root.FD()); err != nil {
		return nil, err
	}
	quarantined, err := validatePinOwnerHistoryAt(
		store,
		entry,
		archiveName,
	)
	if err != nil {
		return nil, err
	}
	if err := quarantined.Close(); err != nil {
		return nil, err
	}
	if err := unix.Renameat2(
		store.root.FD(),
		archiveName,
		store.root.FD(),
		historical.RecordFileName,
		unix.RENAME_NOREPLACE,
	); err != nil {
		return nil, fmt.Errorf("publish historical pin owner record: %w", err)
	}
	if err := unix.Fsync(store.root.FD()); err != nil {
		return nil, err
	}
	published, err := validatePinOwnerHistoryAt(
		store,
		historical,
		historical.RecordFileName,
	)
	if err != nil {
		return nil, err
	}
	if err := published.Close(); err != nil {
		return nil, err
	}

	next := clonePinOwnerIndex(index)
	next.Sequence++
	next.UpdatedAt = now.UTC().Format(time.RFC3339Nano)
	entryIndex := -1
	for candidateIndex, candidate := range next.Entries {
		if candidate.ResourceKey == entry.ResourceKey &&
			candidate.BootID == entry.BootID {
			entryIndex = candidateIndex
			break
		}
	}
	if entryIndex < 0 {
		return nil, errors.New("prior-boot index entry disappeared during archive")
	}
	next.Entries[entryIndex] = historical
	pointerIndex := -1
	for candidateIndex, candidate := range next.Active {
		if candidate.BPFFSRootPath == entry.BPFFSRootPath &&
			candidate.PinBaseName == entry.PinBaseName {
			pointerIndex = candidateIndex
			break
		}
	}
	if pointerIndex < 0 ||
		next.Active[pointerIndex] != activePointerFromEntry(entry) {
		return nil, errors.New("prior-boot active pointer changed during archive")
	}
	next.Active[pointerIndex] = activePointerFromEntry(historical)
	normalizePinOwnerIndex(next)
	if err := store.persistLocked(next, index); err != nil {
		return nil, err
	}
	return &historical, nil
}
