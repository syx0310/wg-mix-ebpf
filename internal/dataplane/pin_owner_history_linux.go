//go:build linux

package dataplane

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"time"

	"golang.org/x/sys/unix"
)

const pinOwnerArchiveSuffix = ".owner.archive"

type validatedPinOwnerHistory struct {
	file     *os.File
	identity pinPathInodeIdentity
	record   *pinOwnerRecord
}

func (history *validatedPinOwnerHistory) Close() error {
	if history == nil || history.file == nil {
		return nil
	}
	err := history.file.Close()
	history.file = nil
	return err
}

func (store *pinOwnerIndexStore) runtimeNow() (time.Time, error) {
	now := time.Now().UTC()
	if store != nil && store.now != nil {
		now = store.now().UTC()
	}
	if now.IsZero() {
		return time.Time{}, errors.New("pin owner index clock returned zero time")
	}
	return now, nil
}

func validatePinOwnerHistoryAt(
	store *pinOwnerIndexStore,
	entry pinOwnerIndexEntry,
	fileName string,
) (*validatedPinOwnerHistory, error) {
	if store == nil || store.root == nil ||
		filepath.Base(fileName) != fileName {
		return nil, fmt.Errorf("unsafe pin owner history target %q", fileName)
	}
	file, identity, err := openExistingAnchoredRegularFile(
		store.root,
		fileName,
		0o600,
		store.expectedUID,
	)
	if err != nil {
		return nil, err
	}
	closeOnError := func(err error) (*validatedPinOwnerHistory, error) {
		return nil, errors.Join(err, file.Close())
	}
	record, err := readPinOwnerRecord(file)
	if err != nil {
		return closeOnError(err)
	}
	resource := pinResourceIdentity{
		key:          entry.ResourceKey,
		parentDevice: entry.ParentDevice,
		parentInode:  entry.ParentInode,
		base:         entry.PinBaseName,
		pinPath:      filepath.Join(entry.BPFFSRootPath, entry.PinBaseName),
	}
	if err := validatePinOwnerRecord(record, resource, 0); err != nil {
		return closeOnError(err)
	}
	digest, err := pinOwnerRecordDigest(record)
	if err != nil {
		return closeOnError(err)
	}
	if record.BootID != entry.BootID ||
		record.BPFFSRootPath != entry.BPFFSRootPath ||
		!slices.Equal(record.BPFFSMountIDs, entry.BPFFSMountIDs) ||
		digest != entry.OwnerDigest {
		return closeOnError(errors.New(
			"historical pin owner record does not match its exact index entry",
		))
	}
	if _, err := validateAnchoredRegularFile(
		store.root,
		fileName,
		int(file.Fd()),
		0o600,
		store.expectedUID,
		&identity,
	); err != nil {
		return closeOnError(err)
	}
	rechecked, err := readPinOwnerRecord(file)
	if err != nil {
		return closeOnError(err)
	}
	if !sameExpectedOwnerRecord(rechecked, record) {
		return closeOnError(errors.New(
			"historical pin owner record changed during validation",
		))
	}
	return &validatedPinOwnerHistory{
		file:     file,
		identity: identity,
		record:   record,
	}, nil
}

func (store *pinOwnerIndexStore) ensureHistoryCapacityLocked(
	active pinOwnerIndexEntry,
	now time.Time,
) error {
	if active.Status != pinOwnerIndexActive {
		return errors.New(
			"pin owner history capacity requires the active entry being archived",
		)
	}
	activePath := pinOwnerIndexPathKey(
		active.BPFFSRootPath,
		active.PinBaseName,
	)
	for {
		index, exists, err := store.loadOptionalLocked()
		if err != nil || !exists {
			return err
		}
		pathHistory := 0
		resourceHistory := 0
		for _, entry := range index.Entries {
			if entry.Status == pinOwnerIndexActive {
				continue
			}
			if pinOwnerIndexPathKey(
				entry.BPFFSRootPath,
				entry.PinBaseName,
			) == activePath {
				pathHistory++
			}
			if entry.ResourceKey == active.ResourceKey {
				resourceHistory++
			}
		}
		needPath := pathHistory >= pinOwnerIndexMaxHistory
		needResource := resourceHistory >= pinOwnerIndexMaxHistory
		needGlobal := len(index.Entries) >= pinOwnerIndexMaxEntries
		if !needPath && !needResource && !needGlobal {
			return nil
		}

		var retired []pinOwnerIndexEntry
		for _, entry := range index.Entries {
			if entry.Status != pinOwnerIndexRetiredStatus {
				continue
			}
			samePath := pinOwnerIndexPathKey(
				entry.BPFFSRootPath,
				entry.PinBaseName,
			) == activePath
			sameResource := entry.ResourceKey == active.ResourceKey
			switch {
			case needPath && needResource:
				if !samePath && !sameResource {
					continue
				}
			case needPath:
				if !samePath {
					continue
				}
			case needResource:
				if !sameResource {
					continue
				}
			case needGlobal:
			}
			retired = append(retired, entry)
		}
		if len(retired) == 0 {
			return fmt.Errorf(
				"pin owner history for %s/%s resource %s is full without an eligible retired record",
				active.BPFFSRootPath,
				active.PinBaseName,
				active.ResourceKey,
			)
		}
		sort.Slice(retired, func(i, j int) bool {
			leftPath := pinOwnerIndexPathKey(
				retired[i].BPFFSRootPath,
				retired[i].PinBaseName,
			) == activePath
			rightPath := pinOwnerIndexPathKey(
				retired[j].BPFFSRootPath,
				retired[j].PinBaseName,
			) == activePath
			leftResource := retired[i].ResourceKey == active.ResourceKey
			rightResource := retired[j].ResourceKey == active.ResourceKey
			leftCoversBoth := leftPath && leftResource
			rightCoversBoth := rightPath && rightResource
			if needPath && needResource &&
				leftCoversBoth != rightCoversBoth {
				return leftCoversBoth
			}
			if retired[i].RetiredAt != retired[j].RetiredAt {
				return retired[i].RetiredAt < retired[j].RetiredAt
			}
			return pinOwnerIndexEntryLess(retired[i], retired[j])
		})
		if err := store.startHistoryRotationLocked(
			index,
			retired[0],
			now,
		); err != nil {
			return err
		}
	}
}

func (store *pinOwnerIndexStore) startHistoryRotationLocked(
	index *pinOwnerIndex,
	victim pinOwnerIndexEntry,
	now time.Time,
) error {
	if index == nil || index.Rotation != nil ||
		victim.Status != pinOwnerIndexRetiredStatus {
		return errors.New("pin owner history rotation precondition is invalid")
	}
	history, err := validatePinOwnerHistoryAt(
		store,
		victim,
		victim.RecordFileName,
	)
	if err != nil {
		return fmt.Errorf("validate pin owner history rotation victim: %w", err)
	}
	if err := history.Close(); err != nil {
		return err
	}
	quarantineName := victim.RecordFileName + pinOwnerRotationSuffix
	var quarantine unix.Stat_t
	if err := unix.Fstatat(
		store.root.FD(),
		quarantineName,
		&quarantine,
		unix.AT_SYMLINK_NOFOLLOW,
	); err == nil {
		return errors.New("pin owner history rotation quarantine already exists")
	} else if !errors.Is(err, unix.ENOENT) {
		return err
	}
	next := clonePinOwnerIndex(index)
	next.Sequence++
	next.UpdatedAt = now.UTC().Format(time.RFC3339Nano)
	next.Rotation = &pinOwnerIndexRotation{
		ResourceKey:        victim.ResourceKey,
		BootID:             victim.BootID,
		RecordFileName:     victim.RecordFileName,
		QuarantineFileName: quarantineName,
		OwnerDigest:        victim.OwnerDigest,
	}
	normalizePinOwnerIndex(next)
	if err := store.persistLocked(next, index); err != nil {
		return err
	}
	return store.resumeHistoryRotationLocked(next)
}

func (store *pinOwnerIndexStore) resumeHistoryRotationLocked(
	index *pinOwnerIndex,
) error {
	if index == nil || index.Rotation == nil {
		return nil
	}
	rotation := index.Rotation
	victimIndex := -1
	var victim pinOwnerIndexEntry
	for entryIndex, entry := range index.Entries {
		if entry.ResourceKey == rotation.ResourceKey &&
			entry.BootID == rotation.BootID {
			victimIndex = entryIndex
			victim = entry
			break
		}
	}
	if victimIndex < 0 ||
		victim.Status != pinOwnerIndexRetiredStatus ||
		victim.RecordFileName != rotation.RecordFileName ||
		victim.OwnerDigest != rotation.OwnerDigest {
		return errors.New("pin owner history rotation victim changed")
	}
	var originalStat unix.Stat_t
	originalErr := unix.Fstatat(
		store.root.FD(),
		rotation.RecordFileName,
		&originalStat,
		unix.AT_SYMLINK_NOFOLLOW,
	)
	var quarantineStat unix.Stat_t
	quarantineErr := unix.Fstatat(
		store.root.FD(),
		rotation.QuarantineFileName,
		&quarantineStat,
		unix.AT_SYMLINK_NOFOLLOW,
	)
	if originalErr == nil && quarantineErr == nil {
		return errors.New(
			"both original and quarantine pin owner histories exist during rotation",
		)
	}
	if originalErr != nil && !errors.Is(originalErr, unix.ENOENT) {
		return originalErr
	}
	if quarantineErr != nil && !errors.Is(quarantineErr, unix.ENOENT) {
		return quarantineErr
	}
	if originalErr == nil {
		history, err := validatePinOwnerHistoryAt(
			store,
			victim,
			rotation.RecordFileName,
		)
		if err != nil {
			return err
		}
		if err := history.Close(); err != nil {
			return err
		}
		if err := unix.Renameat2(
			store.root.FD(),
			rotation.RecordFileName,
			store.root.FD(),
			rotation.QuarantineFileName,
			unix.RENAME_NOREPLACE,
		); err != nil {
			return fmt.Errorf("quarantine pin owner history for rotation: %w", err)
		}
		if err := unix.Fsync(store.root.FD()); err != nil {
			return err
		}
		quarantineErr = nil
	}
	if quarantineErr == nil {
		history, err := validatePinOwnerHistoryAt(
			store,
			victim,
			rotation.QuarantineFileName,
		)
		if err != nil {
			return err
		}
		if err := unlinkAnchoredRegularFile(
			store.root,
			rotation.QuarantineFileName,
			int(history.file.Fd()),
			history.identity,
			store.expectedUID,
		); err != nil {
			_ = history.Close()
			return fmt.Errorf("unlink rotated pin owner history: %w", err)
		}
		if err := history.Close(); err != nil {
			return err
		}
	}
	now, err := store.runtimeNow()
	if err != nil {
		return err
	}
	next := clonePinOwnerIndex(index)
	next.Sequence++
	next.UpdatedAt = now.Format(time.RFC3339Nano)
	next.Rotation = nil
	next.Entries = append(
		next.Entries[:victimIndex],
		next.Entries[victimIndex+1:]...,
	)
	normalizePinOwnerIndex(next)
	if len(next.Entries) == 0 {
		return store.removeLocked(index)
	}
	return store.persistLocked(next, index)
}

func clonePinOwnerIndex(index *pinOwnerIndex) *pinOwnerIndex {
	if index == nil {
		return nil
	}
	cloned := *index
	cloned.Active = slices.Clone(index.Active)
	cloned.Entries = make([]pinOwnerIndexEntry, len(index.Entries))
	for entryIndex, entry := range index.Entries {
		cloned.Entries[entryIndex] = entry
		cloned.Entries[entryIndex].BPFFSMountIDs = slices.Clone(
			entry.BPFFSMountIDs,
		)
	}
	if index.Rotation != nil {
		rotation := *index.Rotation
		cloned.Rotation = &rotation
	}
	return &cloned
}
