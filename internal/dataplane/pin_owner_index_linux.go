//go:build linux

package dataplane

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/pinidentity"
	"golang.org/x/sys/unix"
)

const (
	pinOwnerIndexVersion       = 2
	pinOwnerIndexMaxEntries    = 128
	pinOwnerIndexMaxHistory    = 8
	pinOwnerIndexMaxBytes      = 512 * 1024
	pinOwnerIndexFileName      = "instances.v2.json"
	pinOwnerIndexNextName      = "instances.v2.next"
	pinOwnerIndexRetired       = "instances.v2.retired"
	pinOwnerIndexActive        = "active"
	pinOwnerIndexRekeySource   = "rekey_source"
	pinOwnerIndexRetiredStatus = "retired"
	pinOwnerHistoryPrefix      = "history-"
	pinOwnerHistorySuffix      = ".owner.json"
	pinOwnerRotationSuffix     = ".rotating"
)

type pinOwnerIndexEntry struct {
	ResourceKey    string   `json:"resource_key"`
	ParentDevice   uint64   `json:"parent_device"`
	ParentInode    uint64   `json:"parent_inode"`
	PinBaseName    string   `json:"pin_basename"`
	BPFFSRootPath  string   `json:"bpffs_root_path"`
	BPFFSMountIDs  []uint64 `json:"bpffs_mount_ids"`
	BootID         string   `json:"boot_id"`
	RecordFileName string   `json:"record_filename"`
	OwnerDigest    string   `json:"owner_digest"`
	Status         string   `json:"status"`
	RetiredAt      string   `json:"retired_at"`
}

type pinOwnerIndexActivePointer struct {
	BPFFSRootPath  string `json:"bpffs_root_path"`
	PinBaseName    string `json:"pin_basename"`
	ResourceKey    string `json:"resource_key"`
	BootID         string `json:"boot_id"`
	RecordFileName string `json:"record_filename"`
	Status         string `json:"status"`
}

type pinOwnerIndexRotation struct {
	ResourceKey        string `json:"resource_key"`
	BootID             string `json:"boot_id"`
	RecordFileName     string `json:"record_filename"`
	QuarantineFileName string `json:"quarantine_filename"`
	OwnerDigest        string `json:"owner_digest"`
}

type pinOwnerIndex struct {
	Version   int                          `json:"version"`
	Sequence  uint64                       `json:"sequence"`
	UpdatedAt string                       `json:"updated_at"`
	Active    []pinOwnerIndexActivePointer `json:"active"`
	Rotation  *pinOwnerIndexRotation       `json:"rotation"`
	Entries   []pinOwnerIndexEntry         `json:"entries"`
}

type pinOwnerIndexStore struct {
	root                *anchoredDirectoryPath
	expectedUID         uint32
	beforeOwnerExchange func()
	now                 func() time.Time
}

// Production mutations already hold the cross-process lifecycle flock, but
// retained leases duplicate one open file description and therefore do not
// serialize goroutines in the owning process. Every shared-index recovery and
// read/modify/write transaction takes this mutex after its per-resource lock.
var pinOwnerIndexMutationMu sync.Mutex

func indexStoreFromOwner(store *pinOwnerStore) *pinOwnerIndexStore {
	if store == nil {
		return nil
	}
	return &pinOwnerIndexStore{
		root:                store.root,
		expectedUID:         store.expectedUID,
		beforeOwnerExchange: store.beforeOwnerExchange,
		now:                 store.now,
	}
}

func ownerIndexEntryFromRecord(
	record *pinOwnerRecord,
	status string,
	retiredAt string,
) (pinOwnerIndexEntry, error) {
	digest, err := pinOwnerRecordDigest(record)
	if err != nil {
		return pinOwnerIndexEntry{}, err
	}
	entry := pinOwnerIndexEntry{
		ResourceKey:   record.ResourceKey,
		ParentDevice:  record.ParentDevice,
		ParentInode:   record.ParentInode,
		PinBaseName:   record.PinBaseName,
		BPFFSRootPath: record.BPFFSRootPath,
		BPFFSMountIDs: slices.Clone(record.BPFFSMountIDs),
		BootID:        record.BootID,
		OwnerDigest:   digest,
		Status:        status,
		RetiredAt:     retiredAt,
	}
	switch status {
	case pinOwnerIndexActive:
		entry.RecordFileName = record.ResourceKey + ".owner.json"
	case pinOwnerIndexRekeySource, pinOwnerIndexRetiredStatus:
		entry.RecordFileName = pinOwnerHistoryFileName(entry)
	default:
		return pinOwnerIndexEntry{}, fmt.Errorf(
			"cannot build pin owner index entry with status %q",
			status,
		)
	}
	return entry, nil
}

func pinOwnerRecordDigest(record *pinOwnerRecord) (string, error) {
	data, err := marshalPinOwnerRecord(record)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return fmt.Sprintf("%x", digest), nil
}

func pinOwnerHistoryFileName(entry pinOwnerIndexEntry) string {
	return fmt.Sprintf(
		"%s%s-%s-%s%s",
		pinOwnerHistoryPrefix,
		entry.ResourceKey,
		entry.BootID,
		entry.OwnerDigest,
		pinOwnerHistorySuffix,
	)
}

func activePointerFromEntry(
	entry pinOwnerIndexEntry,
) pinOwnerIndexActivePointer {
	return pinOwnerIndexActivePointer{
		BPFFSRootPath:  entry.BPFFSRootPath,
		PinBaseName:    entry.PinBaseName,
		ResourceKey:    entry.ResourceKey,
		BootID:         entry.BootID,
		RecordFileName: entry.RecordFileName,
		Status:         entry.Status,
	}
}

func normalizePinOwnerIndex(index *pinOwnerIndex) {
	if index == nil {
		return
	}
	for entryIndex := range index.Entries {
		sort.Slice(index.Entries[entryIndex].BPFFSMountIDs, func(i, j int) bool {
			return index.Entries[entryIndex].BPFFSMountIDs[i] <
				index.Entries[entryIndex].BPFFSMountIDs[j]
		})
	}
	sort.Slice(index.Entries, func(i, j int) bool {
		if index.Entries[i].ResourceKey != index.Entries[j].ResourceKey {
			return index.Entries[i].ResourceKey < index.Entries[j].ResourceKey
		}
		return index.Entries[i].BootID < index.Entries[j].BootID
	})
	sort.Slice(index.Active, func(i, j int) bool {
		if index.Active[i].BPFFSRootPath != index.Active[j].BPFFSRootPath {
			return index.Active[i].BPFFSRootPath < index.Active[j].BPFFSRootPath
		}
		if index.Active[i].PinBaseName != index.Active[j].PinBaseName {
			return index.Active[i].PinBaseName < index.Active[j].PinBaseName
		}
		if index.Active[i].ResourceKey != index.Active[j].ResourceKey {
			return index.Active[i].ResourceKey < index.Active[j].ResourceKey
		}
		return index.Active[i].BootID < index.Active[j].BootID
	})
	if index.Active == nil {
		index.Active = []pinOwnerIndexActivePointer{}
	}
	if index.Entries == nil {
		index.Entries = []pinOwnerIndexEntry{}
	}
}

func validatePinOwnerIndex(index *pinOwnerIndex) error {
	if index == nil {
		return errors.New("pin owner index is nil")
	}
	if index.Version != pinOwnerIndexVersion ||
		index.Sequence == 0 {
		return errors.New("pin owner index has an invalid version or sequence")
	}
	updatedAt, err := time.Parse(time.RFC3339Nano, index.UpdatedAt)
	if err != nil ||
		index.UpdatedAt != updatedAt.UTC().Format(time.RFC3339Nano) {
		return errors.New("pin owner index updated_at is not canonical RFC3339Nano UTC")
	}
	if len(index.Entries) > pinOwnerIndexMaxEntries {
		return fmt.Errorf(
			"pin owner index has %d entries, maximum is %d",
			len(index.Entries), pinOwnerIndexMaxEntries,
		)
	}
	entriesByKey := make(
		map[string]pinOwnerIndexEntry,
		len(index.Entries),
	)
	historyByPath := make(map[string]int)
	historyByResource := make(map[string]int)
	for entryIndex, entry := range index.Entries {
		if !pinidentity.ValidKey(entry.ResourceKey) ||
			entry.ParentDevice == 0 ||
			entry.ParentInode == 0 ||
			!validPinPathBase(entry.PinBaseName) ||
			entry.BPFFSRootPath == "" ||
			!filepath.IsAbs(entry.BPFFSRootPath) ||
			filepath.Clean(entry.BPFFSRootPath) != entry.BPFFSRootPath ||
			entry.BPFFSRootPath == string(filepath.Separator) ||
			!bootIDPattern.MatchString(entry.BootID) ||
			!pinidentity.ValidKey(entry.OwnerDigest) {
			return fmt.Errorf("pin owner index entry %d is invalid", entryIndex)
		}
		resourceKey, err := pinidentity.Key(
			entry.ParentDevice,
			entry.ParentInode,
			entry.PinBaseName,
		)
		if err != nil || resourceKey != entry.ResourceKey {
			return fmt.Errorf(
				"pin owner index entry %d resource key does not match its FD-anchored identity",
				entryIndex,
			)
		}
		key := pinOwnerIndexEntryKey(entry.ResourceKey, entry.BootID)
		if _, duplicate := entriesByKey[key]; duplicate {
			return fmt.Errorf(
				"pin owner index repeats resource/boot %s/%s",
				entry.ResourceKey,
				entry.BootID,
			)
		}
		entriesByKey[key] = entry
		if entryIndex != 0 &&
			!pinOwnerIndexEntryLess(index.Entries[entryIndex-1], entry) {
			return errors.New(
				"pin owner index entries are not canonically sorted by resource/boot",
			)
		}
		if len(entry.BPFFSMountIDs) == 0 {
			return fmt.Errorf("pin owner index entry %s has no mount IDs", entry.ResourceKey)
		}
		mountSeen := make(map[uint64]struct{}, len(entry.BPFFSMountIDs))
		for mountIndex, mountID := range entry.BPFFSMountIDs {
			if mountID == 0 {
				return fmt.Errorf("pin owner index entry %s has a zero mount ID", entry.ResourceKey)
			}
			if _, duplicate := mountSeen[mountID]; duplicate {
				return fmt.Errorf("pin owner index entry %s repeats mount ID %d", entry.ResourceKey, mountID)
			}
			mountSeen[mountID] = struct{}{}
			if mountIndex != 0 &&
				entry.BPFFSMountIDs[mountIndex-1] >= mountID {
				return fmt.Errorf("pin owner index entry %s mount IDs are not sorted", entry.ResourceKey)
			}
		}
		switch entry.Status {
		case pinOwnerIndexActive:
			if entry.RetiredAt != "" ||
				entry.RecordFileName != entry.ResourceKey+".owner.json" {
				return fmt.Errorf(
					"active pin owner index entry %s/%s is inconsistent",
					entry.ResourceKey,
					entry.BootID,
				)
			}
		case pinOwnerIndexRekeySource, pinOwnerIndexRetiredStatus:
			retiredAt, err := time.Parse(time.RFC3339Nano, entry.RetiredAt)
			if err != nil ||
				entry.RetiredAt != retiredAt.UTC().Format(time.RFC3339Nano) ||
				entry.RecordFileName != pinOwnerHistoryFileName(entry) {
				return fmt.Errorf(
					"historical pin owner index entry %s/%s is inconsistent",
					entry.ResourceKey,
					entry.BootID,
				)
			}
			pathKey := pinOwnerIndexPathKey(
				entry.BPFFSRootPath,
				entry.PinBaseName,
			)
			historyByPath[pathKey]++
			if historyByPath[pathKey] > pinOwnerIndexMaxHistory {
				return fmt.Errorf(
					"pin owner history for %s/%s exceeds %d entries",
					entry.BPFFSRootPath,
					entry.PinBaseName,
					pinOwnerIndexMaxHistory,
				)
			}
			historyByResource[entry.ResourceKey]++
			if historyByResource[entry.ResourceKey] >
				pinOwnerIndexMaxHistory {
				return fmt.Errorf(
					"pin owner history for resource %s exceeds %d entries",
					entry.ResourceKey,
					pinOwnerIndexMaxHistory,
				)
			}
		default:
			return fmt.Errorf(
				"pin owner index entry %s/%s has status %q",
				entry.ResourceKey,
				entry.BootID,
				entry.Status,
			)
		}
	}
	activePaths := make(map[string]struct{}, len(index.Active))
	activeResources := make(map[string]struct{}, len(index.Active))
	pointedEntries := make(map[string]struct{}, len(index.Active))
	for pointerIndex, pointer := range index.Active {
		if pointer.BPFFSRootPath == "" ||
			!filepath.IsAbs(pointer.BPFFSRootPath) ||
			filepath.Clean(pointer.BPFFSRootPath) != pointer.BPFFSRootPath ||
			pointer.BPFFSRootPath == string(filepath.Separator) ||
			!validPinPathBase(pointer.PinBaseName) ||
			!pinidentity.ValidKey(pointer.ResourceKey) ||
			!bootIDPattern.MatchString(pointer.BootID) ||
			(pointer.Status != pinOwnerIndexActive &&
				pointer.Status != pinOwnerIndexRekeySource) {
			return fmt.Errorf(
				"pin owner active pointer %d is invalid",
				pointerIndex,
			)
		}
		if pointerIndex != 0 &&
			!pinOwnerIndexActiveLess(index.Active[pointerIndex-1], pointer) {
			return errors.New("pin owner active pointers are not canonically sorted")
		}
		pathKey := pinOwnerIndexPathKey(
			pointer.BPFFSRootPath,
			pointer.PinBaseName,
		)
		if _, duplicate := activePaths[pathKey]; duplicate {
			return fmt.Errorf(
				"pin owner index repeats active pointer for %s/%s",
				pointer.BPFFSRootPath,
				pointer.PinBaseName,
			)
		}
		activePaths[pathKey] = struct{}{}
		entryKey := pinOwnerIndexEntryKey(pointer.ResourceKey, pointer.BootID)
		entry, exists := entriesByKey[entryKey]
		if !exists || activePointerFromEntry(entry) != pointer {
			return fmt.Errorf(
				"pin owner active pointer %s/%s does not match its entry",
				pointer.ResourceKey,
				pointer.BootID,
			)
		}
		if _, duplicate := activeResources[entry.ResourceKey]; duplicate {
			return fmt.Errorf(
				"pin owner index repeats active pointer for resource %s",
				entry.ResourceKey,
			)
		}
		activeResources[entry.ResourceKey] = struct{}{}
		pointedEntries[entryKey] = struct{}{}
	}
	for _, entry := range index.Entries {
		entryKey := pinOwnerIndexEntryKey(entry.ResourceKey, entry.BootID)
		_, pointed := pointedEntries[entryKey]
		if (entry.Status == pinOwnerIndexActive ||
			entry.Status == pinOwnerIndexRekeySource) != pointed {
			return fmt.Errorf(
				"pin owner entry %s/%s has inconsistent active-pointer coverage",
				entry.ResourceKey,
				entry.BootID,
			)
		}
	}
	if index.Rotation != nil {
		rotation := index.Rotation
		if !pinidentity.ValidKey(rotation.ResourceKey) ||
			!bootIDPattern.MatchString(rotation.BootID) ||
			!pinidentity.ValidKey(rotation.OwnerDigest) ||
			filepath.Base(rotation.RecordFileName) != rotation.RecordFileName ||
			rotation.QuarantineFileName !=
				rotation.RecordFileName+pinOwnerRotationSuffix {
			return errors.New("pin owner history rotation descriptor is invalid")
		}
		rotationKey := pinOwnerIndexEntryKey(
			rotation.ResourceKey,
			rotation.BootID,
		)
		entry, exists := entriesByKey[rotationKey]
		if !exists ||
			entry.Status != pinOwnerIndexRetiredStatus ||
			entry.RecordFileName != rotation.RecordFileName ||
			entry.OwnerDigest != rotation.OwnerDigest {
			return errors.New(
				"pin owner history rotation does not match one retired index entry",
			)
		}
	}
	return nil
}

func pinOwnerIndexEntryKey(resourceKey, bootID string) string {
	return resourceKey + "\x00" + bootID
}

func pinOwnerIndexPathKey(rootPath, baseName string) string {
	return rootPath + "\x00" + baseName
}

func pinOwnerIndexEntryLess(
	left pinOwnerIndexEntry,
	right pinOwnerIndexEntry,
) bool {
	if left.ResourceKey != right.ResourceKey {
		return left.ResourceKey < right.ResourceKey
	}
	return left.BootID < right.BootID
}

func pinOwnerIndexActiveLess(
	left pinOwnerIndexActivePointer,
	right pinOwnerIndexActivePointer,
) bool {
	if left.BPFFSRootPath != right.BPFFSRootPath {
		return left.BPFFSRootPath < right.BPFFSRootPath
	}
	if left.PinBaseName != right.PinBaseName {
		return left.PinBaseName < right.PinBaseName
	}
	if left.ResourceKey != right.ResourceKey {
		return left.ResourceKey < right.ResourceKey
	}
	return left.BootID < right.BootID
}

func marshalPinOwnerIndex(index *pinOwnerIndex) ([]byte, error) {
	normalizePinOwnerIndex(index)
	if err := validatePinOwnerIndex(index); err != nil {
		return nil, err
	}
	data, err := json.Marshal(index)
	if err != nil {
		return nil, err
	}
	if len(data)+1 > pinOwnerIndexMaxBytes {
		return nil, errors.New("pin owner index exceeds its size bound")
	}
	return append(data, '\n'), nil
}

func readPinOwnerIndex(file *os.File) (*pinOwnerIndex, error) {
	data := make([]byte, pinOwnerIndexMaxBytes+1)
	n, err := file.ReadAt(data, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if n == 0 || n > pinOwnerIndexMaxBytes {
		return nil, fmt.Errorf("pin owner index size = %d", n)
	}
	data = data[:n]
	if data[len(data)-1] != '\n' ||
		bytes.Count(data, []byte{'\n'}) != 1 {
		return nil, errors.New("pin owner index must be exactly one JSON line terminated by LF")
	}
	var index pinOwnerIndex
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&index); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("pin owner index has trailing JSON")
	}
	if err := validatePinOwnerIndex(&index); err != nil {
		return nil, err
	}
	return &index, nil
}

func (store *pinOwnerIndexStore) loadOptional() (*pinOwnerIndex, bool, error) {
	pinOwnerIndexMutationMu.Lock()
	defer pinOwnerIndexMutationMu.Unlock()
	return store.loadOptionalLocked()
}

func (store *pinOwnerIndexStore) loadOptionalLocked() (
	*pinOwnerIndex,
	bool,
	error,
) {
	if store == nil || store.root == nil {
		return nil, false, errors.New("pin owner index store is unavailable")
	}
	for {
		if err := store.recoverLocked(); err != nil {
			return nil, false, err
		}
		file, identity, err := openExistingAnchoredRegularFile(
			store.root,
			pinOwnerIndexFileName,
			0o600,
			store.expectedUID,
		)
		if errors.Is(err, unix.ENOENT) {
			return nil, false, nil
		}
		if err != nil {
			return nil, false, err
		}
		index, err := readPinOwnerIndex(file)
		if err != nil {
			_ = file.Close()
			return nil, false, err
		}
		if _, err := validateAnchoredRegularFile(
			store.root,
			pinOwnerIndexFileName,
			int(file.Fd()),
			0o600,
			store.expectedUID,
			&identity,
		); err != nil {
			_ = file.Close()
			return nil, false, err
		}
		if err := file.Close(); err != nil {
			return nil, false, err
		}
		if index.Rotation == nil {
			return index, true, nil
		}
		if err := store.resumeHistoryRotationLocked(index); err != nil {
			return nil, false, err
		}
	}
}

func (store *pinOwnerIndexStore) loadNamedOptionalReadOnly(
	name string,
) (*pinOwnerIndex, bool, error) {
	if store == nil || store.root == nil ||
		filepath.Base(name) != name {
		return nil, false, errors.New(
			"pin owner index read-only target is unavailable",
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
	index, err := readPinOwnerIndex(file)
	if err != nil {
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
	rechecked, err := readPinOwnerIndex(file)
	if err != nil {
		return nil, false, err
	}
	if !samePinOwnerIndex(rechecked, index) {
		return nil, false, errors.New(
			"pin owner index changed during read-only inspection",
		)
	}
	return index, true, nil
}

func (store *pinOwnerIndexStore) inspectOptionalReadOnly() (
	*pinOwnerIndex,
	bool,
	bool,
	error,
) {
	current, currentExists, err := store.loadNamedOptionalReadOnly(
		pinOwnerIndexFileName,
	)
	if err != nil {
		return nil, false, false, err
	}
	next, nextExists, err := store.loadNamedOptionalReadOnly(
		pinOwnerIndexNextName,
	)
	if err != nil {
		return nil, false, false, err
	}
	_, retiredExists, err := store.loadNamedOptionalReadOnly(
		pinOwnerIndexRetired,
	)
	if err != nil {
		return nil, false, false, err
	}
	if nextExists && retiredExists {
		return nil, false, false, errors.New(
			"next and retired pin owner indexes coexist",
		)
	}
	if retiredExists {
		if currentExists {
			return nil, false, false, errors.New(
				"active and retired pin owner indexes coexist",
			)
		}
		return nil, false, true, nil
	}
	if nextExists {
		switch {
		case !currentExists && next.Sequence != 1:
			return nil, false, false, errors.New(
				"initial pending pin owner index sequence is not one",
			)
		case currentExists &&
			next.Sequence != current.Sequence+1 &&
			current.Sequence != next.Sequence+1:
			return nil, false, false, errors.New(
				"ambiguous pin owner index descriptor sequences",
			)
		}
		return current, currentExists, true, nil
	}
	return current, currentExists, currentExists && current.Rotation != nil, nil
}

func (store *pinOwnerIndexStore) persist(
	next *pinOwnerIndex,
	expected *pinOwnerIndex,
) error {
	pinOwnerIndexMutationMu.Lock()
	defer pinOwnerIndexMutationMu.Unlock()
	return store.persistLocked(next, expected)
}

func (store *pinOwnerIndexStore) persistLocked(
	next *pinOwnerIndex,
	expected *pinOwnerIndex,
) error {
	data, err := marshalPinOwnerIndex(next)
	if err != nil {
		return err
	}
	if expected == nil {
		if next.Sequence != 1 {
			return errors.New("initial pin owner index sequence must be one")
		}
	} else if next.Sequence != expected.Sequence+1 {
		return errors.New("pin owner index sequence is not monotonic")
	}
	if err := store.recoverLocked(); err != nil {
		return err
	}
	targetFile, targetIdentity, targetErr := openExistingAnchoredRegularFile(
		store.root,
		pinOwnerIndexFileName,
		0o600,
		store.expectedUID,
	)
	if expected == nil {
		if targetErr == nil {
			_ = targetFile.Close()
			return errors.New("pin owner index unexpectedly exists")
		}
		if !errors.Is(targetErr, unix.ENOENT) {
			return targetErr
		}
	} else {
		if targetErr != nil {
			return targetErr
		}
		defer targetFile.Close()
		current, err := readPinOwnerIndex(targetFile)
		if err != nil {
			return err
		}
		if !samePinOwnerIndex(current, expected) {
			return errors.New("pin owner index changed before staging next")
		}
		if _, err := validateAnchoredRegularFile(
			store.root,
			pinOwnerIndexFileName,
			int(targetFile.Fd()),
			0o600,
			store.expectedUID,
			&targetIdentity,
		); err != nil {
			return err
		}
	}
	nextFile, nextIdentity, err := createAnchoredRegularFileExclusive(
		store.root,
		pinOwnerIndexNextName,
		0o600,
		store.expectedUID,
	)
	if err != nil {
		return err
	}
	defer nextFile.Close()
	if err := writeAndSyncAnchoredFile(
		store.root,
		pinOwnerIndexNextName,
		nextFile,
		nextIdentity,
		data,
		store.expectedUID,
	); err != nil {
		return err
	}
	if expected == nil {
		if store.beforeOwnerExchange != nil {
			store.beforeOwnerExchange()
		}
		if _, err := validateAnchoredRegularFile(
			store.root,
			pinOwnerIndexNextName,
			int(nextFile.Fd()),
			0o600,
			store.expectedUID,
			&nextIdentity,
		); err != nil {
			return err
		}
		published, err := readPinOwnerIndex(nextFile)
		if err != nil {
			return err
		}
		if !samePinOwnerIndex(published, next) {
			return errors.New("next pin owner index changed before initial publish")
		}
		if err := unix.Renameat2(
			store.root.FD(),
			pinOwnerIndexNextName,
			store.root.FD(),
			pinOwnerIndexFileName,
			unix.RENAME_NOREPLACE,
		); err != nil {
			return err
		}
		if err := unix.Fsync(store.root.FD()); err != nil {
			return err
		}
		_, err = validateAnchoredRegularFile(
			store.root,
			pinOwnerIndexFileName,
			int(nextFile.Fd()),
			0o600,
			store.expectedUID,
			&nextIdentity,
		)
		return err
	}
	current, err := readPinOwnerIndex(targetFile)
	if err != nil {
		return err
	}
	if !samePinOwnerIndex(current, expected) {
		return errors.New("pin owner index changed before exchange")
	}
	if store.beforeOwnerExchange != nil {
		store.beforeOwnerExchange()
	}
	if _, err := validateAnchoredRegularFile(
		store.root,
		pinOwnerIndexFileName,
		int(targetFile.Fd()),
		0o600,
		store.expectedUID,
		&targetIdentity,
	); err != nil {
		return err
	}
	if _, err := validateAnchoredRegularFile(
		store.root,
		pinOwnerIndexNextName,
		int(nextFile.Fd()),
		0o600,
		store.expectedUID,
		&nextIdentity,
	); err != nil {
		return err
	}
	recheckedCurrent, err := readPinOwnerIndex(targetFile)
	if err != nil {
		return err
	}
	if !samePinOwnerIndex(recheckedCurrent, expected) {
		return errors.New("pin owner index changed at exchange hook")
	}
	recheckedNext, err := readPinOwnerIndex(nextFile)
	if err != nil {
		return err
	}
	if !samePinOwnerIndex(recheckedNext, next) {
		return errors.New("next pin owner index changed at exchange hook")
	}
	if err := unix.Renameat2(
		store.root.FD(),
		pinOwnerIndexNextName,
		store.root.FD(),
		pinOwnerIndexFileName,
		unix.RENAME_EXCHANGE,
	); err != nil {
		return err
	}
	if err := unix.Fsync(store.root.FD()); err != nil {
		return err
	}
	if _, err := validateAnchoredRegularFile(
		store.root,
		pinOwnerIndexFileName,
		int(nextFile.Fd()),
		0o600,
		store.expectedUID,
		&nextIdentity,
	); err != nil {
		return err
	}
	if _, err := validateAnchoredRegularFile(
		store.root,
		pinOwnerIndexNextName,
		int(targetFile.Fd()),
		0o600,
		store.expectedUID,
		&targetIdentity,
	); err != nil {
		return err
	}
	return unlinkAnchoredRegularFile(
		store.root,
		pinOwnerIndexNextName,
		int(targetFile.Fd()),
		targetIdentity,
		store.expectedUID,
	)
}

func samePinOwnerIndex(left, right *pinOwnerIndex) bool {
	leftData, leftErr := json.Marshal(left)
	rightData, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftData, rightData)
}

func (store *pinOwnerIndexStore) recover() error {
	pinOwnerIndexMutationMu.Lock()
	defer pinOwnerIndexMutationMu.Unlock()
	return store.recoverLocked()
}

func (store *pinOwnerIndexStore) recoverLocked() error {
	if err := store.recoverRetiredLocked(); err != nil {
		return err
	}
	nextFile, nextIdentity, nextErr := openExistingAnchoredRegularFile(
		store.root,
		pinOwnerIndexNextName,
		0o600,
		store.expectedUID,
	)
	if errors.Is(nextErr, unix.ENOENT) {
		return nil
	}
	if nextErr != nil {
		return nextErr
	}
	defer nextFile.Close()
	next, err := readPinOwnerIndex(nextFile)
	if err != nil {
		return err
	}
	targetFile, targetIdentity, targetErr := openExistingAnchoredRegularFile(
		store.root,
		pinOwnerIndexFileName,
		0o600,
		store.expectedUID,
	)
	if errors.Is(targetErr, unix.ENOENT) {
		if _, err := validateAnchoredRegularFile(
			store.root,
			pinOwnerIndexNextName,
			int(nextFile.Fd()),
			0o600,
			store.expectedUID,
			&nextIdentity,
		); err != nil {
			return err
		}
		recheckedNext, err := readPinOwnerIndex(nextFile)
		if err != nil {
			return err
		}
		if !samePinOwnerIndex(recheckedNext, next) {
			return errors.New("pending pin owner index changed before recovery")
		}
		if err := unix.Renameat2(
			store.root.FD(),
			pinOwnerIndexNextName,
			store.root.FD(),
			pinOwnerIndexFileName,
			unix.RENAME_NOREPLACE,
		); err != nil {
			return err
		}
		if err := unix.Fsync(store.root.FD()); err != nil {
			return err
		}
		_, err = validateAnchoredRegularFile(
			store.root,
			pinOwnerIndexFileName,
			int(nextFile.Fd()),
			0o600,
			store.expectedUID,
			&nextIdentity,
		)
		return err
	}
	if targetErr != nil {
		return targetErr
	}
	defer targetFile.Close()
	current, err := readPinOwnerIndex(targetFile)
	if err != nil {
		return err
	}
	switch {
	case next.Sequence == current.Sequence+1:
		if _, err := validateAnchoredRegularFile(
			store.root,
			pinOwnerIndexFileName,
			int(targetFile.Fd()),
			0o600,
			store.expectedUID,
			&targetIdentity,
		); err != nil {
			return err
		}
		if _, err := validateAnchoredRegularFile(
			store.root,
			pinOwnerIndexNextName,
			int(nextFile.Fd()),
			0o600,
			store.expectedUID,
			&nextIdentity,
		); err != nil {
			return err
		}
		recheckedCurrent, err := readPinOwnerIndex(targetFile)
		if err != nil {
			return err
		}
		recheckedNext, err := readPinOwnerIndex(nextFile)
		if err != nil {
			return err
		}
		if !samePinOwnerIndex(recheckedCurrent, current) ||
			!samePinOwnerIndex(recheckedNext, next) {
			return errors.New("pin owner index changed before recovery exchange")
		}
		if err := unix.Renameat2(
			store.root.FD(),
			pinOwnerIndexNextName,
			store.root.FD(),
			pinOwnerIndexFileName,
			unix.RENAME_EXCHANGE,
		); err != nil {
			return err
		}
		if err := unix.Fsync(store.root.FD()); err != nil {
			return err
		}
		if _, err := validateAnchoredRegularFile(
			store.root,
			pinOwnerIndexFileName,
			int(nextFile.Fd()),
			0o600,
			store.expectedUID,
			&nextIdentity,
		); err != nil {
			return err
		}
		if _, err := validateAnchoredRegularFile(
			store.root,
			pinOwnerIndexNextName,
			int(targetFile.Fd()),
			0o600,
			store.expectedUID,
			&targetIdentity,
		); err != nil {
			return err
		}
		return unlinkAnchoredRegularFile(
			store.root,
			pinOwnerIndexNextName,
			int(targetFile.Fd()),
			targetIdentity,
			store.expectedUID,
		)
	case current.Sequence == next.Sequence+1:
		return unlinkAnchoredRegularFile(
			store.root,
			pinOwnerIndexNextName,
			int(nextFile.Fd()),
			nextIdentity,
			store.expectedUID,
		)
	default:
		return errors.New("ambiguous pin owner index descriptor sequences")
	}
}

func (store *pinOwnerIndexStore) remove(expected *pinOwnerIndex) error {
	pinOwnerIndexMutationMu.Lock()
	defer pinOwnerIndexMutationMu.Unlock()
	return store.removeLocked(expected)
}

func (store *pinOwnerIndexStore) removeLocked(
	expected *pinOwnerIndex,
) error {
	if err := store.recoverLocked(); err != nil {
		return err
	}
	file, identity, err := openExistingAnchoredRegularFile(
		store.root,
		pinOwnerIndexFileName,
		0o600,
		store.expectedUID,
	)
	if err != nil {
		return err
	}
	defer file.Close()
	current, err := readPinOwnerIndex(file)
	if err != nil {
		return err
	}
	if !samePinOwnerIndex(current, expected) {
		return errors.New("pin owner index changed before removal")
	}
	if _, err := validateAnchoredRegularFile(
		store.root,
		pinOwnerIndexFileName,
		int(file.Fd()),
		0o600,
		store.expectedUID,
		&identity,
	); err != nil {
		return err
	}
	rechecked, err := readPinOwnerIndex(file)
	if err != nil {
		return err
	}
	if !samePinOwnerIndex(rechecked, expected) {
		return errors.New("pin owner index changed before retirement")
	}
	if err := unix.Renameat2(
		store.root.FD(),
		pinOwnerIndexFileName,
		store.root.FD(),
		pinOwnerIndexRetired,
		unix.RENAME_NOREPLACE,
	); err != nil {
		return err
	}
	if err := unix.Fsync(store.root.FD()); err != nil {
		return err
	}
	return unlinkAnchoredRegularFile(
		store.root,
		pinOwnerIndexRetired,
		int(file.Fd()),
		identity,
		store.expectedUID,
	)
}

func (store *pinOwnerIndexStore) recoverRetiredLocked() error {
	retired, identity, err := openExistingAnchoredRegularFile(
		store.root,
		pinOwnerIndexRetired,
		0o600,
		store.expectedUID,
	)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	defer retired.Close()
	if _, err := readPinOwnerIndex(retired); err != nil {
		return err
	}
	var current unix.Stat_t
	if err := unix.Fstatat(
		store.root.FD(),
		pinOwnerIndexFileName,
		&current,
		unix.AT_SYMLINK_NOFOLLOW,
	); err == nil {
		return errors.New("both active and retired pin owner indexes exist")
	} else if !errors.Is(err, unix.ENOENT) {
		return err
	}
	return unlinkAnchoredRegularFile(
		store.root,
		pinOwnerIndexRetired,
		int(retired.Fd()),
		identity,
		store.expectedUID,
	)
}

func (store *pinOwnerIndexStore) updateEntry(
	entry pinOwnerIndexEntry,
	remove bool,
	now time.Time,
) error {
	return store.updateEntries(entry, remove, "", "", now)
}

func (store *pinOwnerIndexStore) updateEntries(
	entry pinOwnerIndexEntry,
	remove bool,
	retireResourceKey string,
	retireBootID string,
	now time.Time,
) error {
	pinOwnerIndexMutationMu.Lock()
	defer pinOwnerIndexMutationMu.Unlock()
	current, exists, err := store.loadOptionalLocked()
	if err != nil {
		return err
	}
	next := &pinOwnerIndex{
		Version:   pinOwnerIndexVersion,
		Sequence:  1,
		UpdatedAt: now.UTC().Format(time.RFC3339Nano),
		Active:    []pinOwnerIndexActivePointer{},
		Entries:   []pinOwnerIndexEntry{},
	}
	if exists {
		next.Sequence = current.Sequence + 1
		next.Active = slices.Clone(current.Active)
		next.Entries = slices.Clone(current.Entries)
	}
	targetKey := pinOwnerIndexEntryKey(entry.ResourceKey, entry.BootID)
	targetIndex := -1
	for index := range next.Entries {
		if pinOwnerIndexEntryKey(
			next.Entries[index].ResourceKey,
			next.Entries[index].BootID,
		) != targetKey {
			continue
		}
		targetIndex = index
		break
	}
	pathKey := pinOwnerIndexPathKey(entry.BPFFSRootPath, entry.PinBaseName)
	pathPointerIndex := -1
	resourcePointerIndex := -1
	for index, pointer := range next.Active {
		if pinOwnerIndexPathKey(
			pointer.BPFFSRootPath,
			pointer.PinBaseName,
		) == pathKey {
			pathPointerIndex = index
		}
		if pointer.ResourceKey == entry.ResourceKey {
			resourcePointerIndex = index
		}
	}
	if pathPointerIndex >= 0 &&
		resourcePointerIndex >= 0 &&
		pathPointerIndex != resourcePointerIndex {
		return errors.New(
			"pin owner index path and FD-anchored resource pointers disagree",
		)
	}
	pointerIndex := pathPointerIndex
	if resourcePointerIndex >= 0 {
		pointerIndex = resourcePointerIndex
	}
	if remove {
		if targetIndex < 0 {
			return nil
		}
		target := next.Entries[targetIndex]
		if target.Status != pinOwnerIndexActive ||
			!samePinOwnerIndexEntryOwnershipIdentity(target, entry) ||
			target.OwnerDigest != entry.OwnerDigest ||
			pointerIndex < 0 ||
			next.Active[pointerIndex] != activePointerFromEntry(target) {
			return fmt.Errorf(
				"pin owner index identity changed before removing %s/%s",
				entry.ResourceKey,
				entry.BootID,
			)
		}
		next.Entries = append(
			next.Entries[:targetIndex],
			next.Entries[targetIndex+1:]...,
		)
		next.Active = append(
			next.Active[:pointerIndex],
			next.Active[pointerIndex+1:]...,
		)
	} else {
		if entry.Status != pinOwnerIndexActive ||
			entry.RetiredAt != "" {
			return errors.New("pin owner index updates require an active record entry")
		}
		if targetIndex < 0 {
			if len(next.Entries) == pinOwnerIndexMaxEntries {
				return fmt.Errorf(
					"pin owner index reached its %d-entry bound",
					pinOwnerIndexMaxEntries,
				)
			}
			next.Entries = append(next.Entries, entry)
		} else {
			target := next.Entries[targetIndex]
			if target.Status != pinOwnerIndexActive ||
				!samePinOwnerIndexEntryOwnershipIdentity(target, entry) {
				return fmt.Errorf(
					"pin owner index refuses to reactivate or replace identity %s/%s",
					entry.ResourceKey,
					entry.BootID,
				)
			}
			next.Entries[targetIndex] = entry
		}

		sourceKey := ""
		if retireResourceKey != "" || retireBootID != "" {
			if !pinidentity.ValidKey(retireResourceKey) ||
				!bootIDPattern.MatchString(retireBootID) ||
				retireBootID == entry.BootID {
				return errors.New("pin owner index retirement lineage is invalid")
			}
			sourceKey = pinOwnerIndexEntryKey(
				retireResourceKey,
				retireBootID,
			)
			sourceIndex := -1
			for index := range next.Entries {
				if pinOwnerIndexEntryKey(
					next.Entries[index].ResourceKey,
					next.Entries[index].BootID,
				) == sourceKey {
					sourceIndex = index
					break
				}
			}
			if sourceIndex < 0 {
				return fmt.Errorf(
					"pin owner index retirement source %s/%s is missing",
					retireResourceKey,
					retireBootID,
				)
			}
			source := &next.Entries[sourceIndex]
			sameSourcePath := pinOwnerIndexPathKey(
				source.BPFFSRootPath,
				source.PinBaseName,
			) == pathKey
			sameSourceResource := samePinOwnerIndexEntryResourceIdentity(
				*source,
				entry,
			)
			if (!sameSourcePath && !sameSourceResource) ||
				(source.Status != pinOwnerIndexRekeySource &&
					source.Status != pinOwnerIndexRetiredStatus) {
				return errors.New(
					"pin owner index retirement lineage does not match its historical source",
				)
			}
			if source.Status == pinOwnerIndexRekeySource {
				source.Status = pinOwnerIndexRetiredStatus
			}
		}

		switch {
		case pointerIndex < 0:
			next.Active = append(next.Active, activePointerFromEntry(entry))
		case pinOwnerIndexEntryKey(
			next.Active[pointerIndex].ResourceKey,
			next.Active[pointerIndex].BootID,
		) == targetKey:
			next.Active[pointerIndex] = activePointerFromEntry(entry)
		case sourceKey != "" && pinOwnerIndexEntryKey(
			next.Active[pointerIndex].ResourceKey,
			next.Active[pointerIndex].BootID,
		) == sourceKey &&
			next.Active[pointerIndex].Status == pinOwnerIndexRekeySource:
			next.Active[pointerIndex] = activePointerFromEntry(entry)
		default:
			return fmt.Errorf(
				"pin owner index path or FD-anchored resource %s/%s is owned by another active pointer",
				entry.BPFFSRootPath,
				entry.PinBaseName,
			)
		}
	}
	normalizePinOwnerIndex(next)
	if exists && samePinOwnerIndexState(current, next) {
		return nil
	}
	if len(next.Entries) == 0 {
		if !exists {
			return nil
		}
		return store.removeLocked(current)
	}
	return store.persistLocked(next, current)
}

func samePinOwnerIndexState(left, right *pinOwnerIndex) bool {
	if left == nil || right == nil {
		return left == right
	}
	leftCopy := *left
	rightCopy := *right
	leftCopy.Sequence = 1
	rightCopy.Sequence = 1
	leftCopy.UpdatedAt = "2000-01-01T00:00:00Z"
	rightCopy.UpdatedAt = leftCopy.UpdatedAt
	leftData, leftErr := json.Marshal(&leftCopy)
	rightData, rightErr := json.Marshal(&rightCopy)
	return leftErr == nil &&
		rightErr == nil &&
		bytes.Equal(leftData, rightData)
}

func samePinOwnerIndexEntryIdentity(
	left pinOwnerIndexEntry,
	right pinOwnerIndexEntry,
) bool {
	return left.ResourceKey == right.ResourceKey &&
		left.ParentDevice == right.ParentDevice &&
		left.ParentInode == right.ParentInode &&
		left.PinBaseName == right.PinBaseName &&
		left.BPFFSRootPath == right.BPFFSRootPath &&
		left.BootID == right.BootID &&
		left.RecordFileName == right.RecordFileName
}

func samePinOwnerIndexEntryOwnershipIdentity(
	left pinOwnerIndexEntry,
	right pinOwnerIndexEntry,
) bool {
	return samePinOwnerIndexEntryResourceIdentity(left, right) &&
		left.BootID == right.BootID &&
		left.RecordFileName == right.RecordFileName
}

func samePinOwnerIndexEntryResourceIdentity(
	left pinOwnerIndexEntry,
	right pinOwnerIndexEntry,
) bool {
	return left.ResourceKey == right.ResourceKey &&
		left.ParentDevice == right.ParentDevice &&
		left.ParentInode == right.ParentInode &&
		left.PinBaseName == right.PinBaseName
}

func pinOwnerIndexEntryMatchesResource(
	entry pinOwnerIndexEntry,
	resource pinResourceIdentity,
) bool {
	return entry.ResourceKey == resource.key &&
		entry.ParentDevice == resource.parentDevice &&
		entry.ParentInode == resource.parentInode &&
		entry.PinBaseName == resource.base
}

func samePinOwnerIndexEntries(left, right []pinOwnerIndexEntry) bool {
	leftData, leftErr := json.Marshal(left)
	rightData, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftData, rightData)
}

func (store *pinOwnerStore) syncIndexRecord(
	record *pinOwnerRecord,
	remove bool,
) error {
	if store == nil || record == nil {
		return errors.New("pin owner index sync requires store and record")
	}
	updatedAt, err := time.Parse(time.RFC3339Nano, record.UpdatedAt)
	if err != nil {
		return err
	}
	entry, err := ownerIndexEntryFromRecord(
		record,
		pinOwnerIndexActive,
		"",
	)
	if err != nil {
		return err
	}
	retireResourceKey := record.RetiredFromResourceKey
	retireBootID := record.RetiredFromBootID
	if remove {
		retireResourceKey = ""
		retireBootID = ""
	}
	return indexStoreFromOwner(store).updateEntries(
		entry,
		remove,
		retireResourceKey,
		retireBootID,
		updatedAt,
	)
}

func conflictingActiveOwnerIndexEntry(
	store *pinOwnerIndexStore,
	resource pinResourceIdentity,
	bpffsRootPath string,
) (*pinOwnerIndexEntry, error) {
	index, exists, err := store.loadOptional()
	if err != nil || !exists {
		return nil, err
	}
	pointer, err := pinOwnerIndexPointerForResourceOrPath(
		index,
		resource,
		bpffsRootPath,
	)
	if err != nil || pointer == nil {
		return nil, err
	}
	entry, err := pinOwnerIndexEntryForPointer(index, *pointer)
	if err != nil {
		return nil, err
	}
	copy := *entry
	copy.BPFFSMountIDs = slices.Clone(entry.BPFFSMountIDs)
	return &copy, nil
}

func (store *pinOwnerStore) repairIndexForCurrentResource() error {
	if store == nil || store.root == nil {
		return errors.New("pin owner store is unavailable")
	}
	file, _, err := openExistingAnchoredRegularFile(
		store.root,
		store.fileName,
		0o600,
		store.expectedUID,
	)
	if errors.Is(err, unix.ENOENT) {
		// A completed detach removes the exact active index entry before
		// unlinking its quarantined owner record. A prior-boot archive is
		// represented by a historical entry. Absence alone is never enough
		// authority to remove either form of durable ownership evidence.
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	record, err := readPinOwnerRecord(file)
	if err != nil {
		return err
	}
	if err := validatePinOwnerRecord(record, store.resource, 0); err != nil {
		return err
	}
	return store.syncIndexRecord(record, false)
}
