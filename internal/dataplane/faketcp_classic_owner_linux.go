//go:build linux

package dataplane

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"

	"golang.org/x/sys/unix"
)

const (
	fakeTCPClassicOwnerVersion   = 1
	fakeTCPClassicOwnerMaxBytes  = 64 << 10
	fakeTCPClassicPhaseAttaching = "attaching"
	fakeTCPClassicPhaseActive    = "active"
	fakeTCPClassicPhaseDetaching = "detaching"
)

// fakeTCPClassicOwnerRecord is deliberately separate from the baseline pin
// owner schemas. The FakeTCP collection and XDP links remain process-owned,
// while classic TC filters survive process exit. This small durable intent is
// sufficient to remove only the exact surviving filter/program identities on
// the next daemon start.
type fakeTCPClassicOwnerRecord struct {
	Version       int               `json:"version"`
	Sequence      uint64            `json:"sequence"`
	ResourceKey   string            `json:"resource_key"`
	ParentDevice  uint64            `json:"parent_device"`
	ParentInode   uint64            `json:"parent_inode"`
	PinBaseName   string            `json:"pin_basename"`
	PinPath       string            `json:"pin_path"`
	BootID        string            `json:"boot_id"`
	CreatedAt     string            `json:"created_at"`
	UpdatedAt     string            `json:"updated_at"`
	Phase         string            `json:"phase"`
	Generation    uint64            `json:"generation"`
	ObjectSHA256  string            `json:"object_sha256"`
	ActiveFilters []tcFilterBinding `json:"active_filters"`
}

type fakeTCPClassicOwnerStore struct {
	root        *anchoredDirectoryPath
	resource    pinResourceIdentity
	expectedUID uint32
	fileName    string
	nextName    string
}

func fakeTCPClassicOwnerFileName(resource pinResourceIdentity) (string, error) {
	if resource.key == "" || filepath.Base(resource.key) != resource.key {
		return "", fmt.Errorf("invalid FakeTCP classic resource key %q", resource.key)
	}
	return resource.key + ".faketcp-classic.owner.json", nil
}

func openFakeTCPClassicOwnerStore(
	runtime pinPathRuntime,
	resource pinResourceIdentity,
	createRoot bool,
) (*fakeTCPClassicOwnerStore, error) {
	fileName, err := fakeTCPClassicOwnerFileName(resource)
	if err != nil {
		return nil, err
	}
	if createRoot {
		parentPath := filepath.Dir(runtime.ownerRoot)
		parent, _, parentErr := openAnchoredDirectoryPath(
			parentPath, false, 0, runtime.expectedUID, runtime.allowUnsafeAncestors,
		)
		if errors.Is(parentErr, unix.ENOENT) {
			parent, _, parentErr = openAnchoredDirectoryPath(
				parentPath, true, 0o755, runtime.expectedUID, runtime.allowUnsafeAncestors,
			)
		}
		if parentErr != nil {
			return nil, fmt.Errorf("open FakeTCP classic owner parent %s: %w", parentPath, parentErr)
		}
		if err := parent.Close(); err != nil {
			return nil, fmt.Errorf("close FakeTCP classic owner parent %s: %w", parentPath, err)
		}
	}
	root, _, err := openAnchoredDirectoryPath(
		runtime.ownerRoot,
		createRoot,
		0o700,
		runtime.expectedUID,
		runtime.allowUnsafeAncestors,
	)
	if err != nil {
		return nil, fmt.Errorf("open FakeTCP classic owner root %s: %w", runtime.ownerRoot, err)
	}
	return &fakeTCPClassicOwnerStore{
		root:        root,
		resource:    resource,
		expectedUID: runtime.expectedUID,
		fileName:    fileName,
		nextName:    resource.key + ".faketcp-classic.owner.next",
	}, nil
}

func (store *fakeTCPClassicOwnerStore) Close() error {
	if store == nil || store.root == nil {
		return nil
	}
	err := store.root.Close()
	store.root = nil
	return err
}

func (store *fakeTCPClassicOwnerStore) LoadOptional() (
	*fakeTCPClassicOwnerRecord,
	bool,
	error,
) {
	if store == nil || store.root == nil {
		return nil, false, errors.New("FakeTCP classic owner store is unavailable")
	}
	file, identity, err := openExistingAnchoredRegularFile(
		store.root, store.fileName, 0o600, store.expectedUID,
	)
	if errors.Is(err, unix.ENOENT) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	record, err := readFakeTCPClassicOwnerRecord(file)
	if err != nil {
		return nil, false, err
	}
	if err := validateFakeTCPClassicOwnerRecord(record, store.resource); err != nil {
		return nil, false, err
	}
	if _, err := validateAnchoredRegularFile(
		store.root,
		store.fileName,
		int(file.Fd()),
		0o600,
		store.expectedUID,
		&identity,
	); err != nil {
		return nil, false, fmt.Errorf("recheck FakeTCP classic owner record: %w", err)
	}
	return record, true, nil
}

func readFakeTCPClassicOwnerRecord(file *os.File) (*fakeTCPClassicOwnerRecord, error) {
	if file == nil {
		return nil, errors.New("FakeTCP classic owner record file is nil")
	}
	data := make([]byte, fakeTCPClassicOwnerMaxBytes+1)
	n, err := file.ReadAt(data, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("read FakeTCP classic owner record: %w", err)
	}
	if n == 0 || n > fakeTCPClassicOwnerMaxBytes {
		return nil, fmt.Errorf(
			"FakeTCP classic owner record size = %d, want 1..%d",
			n, fakeTCPClassicOwnerMaxBytes,
		)
	}
	data = data[:n]
	if data[len(data)-1] != '\n' || bytes.Count(data, []byte{'\n'}) != 1 {
		return nil, errors.New("FakeTCP classic owner record must be exactly one JSON line terminated by LF")
	}
	var record fakeTCPClassicOwnerRecord
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return nil, fmt.Errorf("decode FakeTCP classic owner record: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("FakeTCP classic owner record contains trailing JSON")
	}
	return &record, nil
}

func marshalFakeTCPClassicOwnerRecord(record *fakeTCPClassicOwnerRecord) ([]byte, error) {
	data, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	if len(data)+1 > fakeTCPClassicOwnerMaxBytes {
		return nil, fmt.Errorf("FakeTCP classic owner record is too large: %d bytes", len(data)+1)
	}
	return append(data, '\n'), nil
}

func normalizeFakeTCPClassicOwnerRecord(record *fakeTCPClassicOwnerRecord) {
	if record == nil {
		return
	}
	sortTCFilterBindings(record.ActiveFilters)
}

func validateFakeTCPClassicOwnerRecord(
	record *fakeTCPClassicOwnerRecord,
	resource pinResourceIdentity,
) error {
	if record == nil {
		return errors.New("FakeTCP classic owner record is nil")
	}
	if record.Version != fakeTCPClassicOwnerVersion || record.Sequence == 0 {
		return fmt.Errorf(
			"FakeTCP classic owner version/sequence = %d/%d, want %d/non-zero",
			record.Version, record.Sequence, fakeTCPClassicOwnerVersion,
		)
	}
	if record.ResourceKey != resource.key ||
		record.ParentDevice != resource.parentDevice ||
		record.ParentInode != resource.parentInode ||
		record.PinBaseName != resource.base ||
		record.PinPath != resource.pinPath {
		return errors.New("FakeTCP classic owner resource identity does not match the bpffs scope")
	}
	if record.PinPath == "" || !filepath.IsAbs(record.PinPath) ||
		filepath.Clean(record.PinPath) != record.PinPath ||
		filepath.Base(record.PinPath) != record.PinBaseName {
		return fmt.Errorf("FakeTCP classic owner pin path %q is not canonical", record.PinPath)
	}
	if !bootIDPattern.MatchString(record.BootID) {
		return fmt.Errorf("FakeTCP classic owner boot ID %q is not canonical", record.BootID)
	}
	created, err := time.Parse(time.RFC3339Nano, record.CreatedAt)
	if err != nil || record.CreatedAt != created.UTC().Format(time.RFC3339Nano) {
		return errors.New("FakeTCP classic owner created_at is not canonical RFC3339Nano UTC")
	}
	updated, err := time.Parse(time.RFC3339Nano, record.UpdatedAt)
	if err != nil || record.UpdatedAt != updated.UTC().Format(time.RFC3339Nano) ||
		updated.Before(created) {
		return errors.New("FakeTCP classic owner updated_at is invalid")
	}
	if record.Generation == 0 {
		return errors.New("FakeTCP classic owner generation is zero")
	}
	digest, err := hex.DecodeString(record.ObjectSHA256)
	if err != nil || len(digest) != 32 {
		return errors.New("FakeTCP classic owner object SHA-256 is invalid")
	}
	switch record.Phase {
	case fakeTCPClassicPhaseAttaching, fakeTCPClassicPhaseActive, fakeTCPClassicPhaseDetaching:
	default:
		return fmt.Errorf("FakeTCP classic owner phase %q is invalid", record.Phase)
	}
	if len(record.ActiveFilters) == 0 {
		return errors.New("FakeTCP classic owner has no filter identities")
	}
	if err := validateClassicOwnerFilters(record.ActiveFilters, "FakeTCP classic active"); err != nil {
		return err
	}
	return nil
}

func sameFakeTCPClassicOwnerRecord(
	left *fakeTCPClassicOwnerRecord,
	right *fakeTCPClassicOwnerRecord,
) bool {
	if left == nil || right == nil {
		return left == right
	}
	leftCopy, rightCopy := *left, *right
	leftCopy.ActiveFilters = slices.Clone(left.ActiveFilters)
	rightCopy.ActiveFilters = slices.Clone(right.ActiveFilters)
	return leftCopy.Version == rightCopy.Version &&
		leftCopy.Sequence == rightCopy.Sequence &&
		leftCopy.ResourceKey == rightCopy.ResourceKey &&
		leftCopy.ParentDevice == rightCopy.ParentDevice &&
		leftCopy.ParentInode == rightCopy.ParentInode &&
		leftCopy.PinBaseName == rightCopy.PinBaseName &&
		leftCopy.PinPath == rightCopy.PinPath &&
		leftCopy.BootID == rightCopy.BootID &&
		leftCopy.CreatedAt == rightCopy.CreatedAt &&
		leftCopy.UpdatedAt == rightCopy.UpdatedAt &&
		leftCopy.Phase == rightCopy.Phase &&
		leftCopy.Generation == rightCopy.Generation &&
		leftCopy.ObjectSHA256 == rightCopy.ObjectSHA256 &&
		slices.Equal(leftCopy.ActiveFilters, rightCopy.ActiveFilters)
}

func (store *fakeTCPClassicOwnerStore) recoverNext() error {
	if store == nil || store.root == nil {
		return errors.New("FakeTCP classic owner store is unavailable")
	}
	file, identity, err := openExistingAnchoredRegularFile(
		store.root, store.nextName, 0o600, store.expectedUID,
	)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open interrupted FakeTCP classic owner record: %w", err)
	}
	defer file.Close()
	if _, err := validateAnchoredRegularFile(
		store.root, store.nextName, int(file.Fd()), 0o600, store.expectedUID, &identity,
	); err != nil {
		return err
	}
	if err := unix.Unlinkat(store.root.FD(), store.nextName, 0); err != nil {
		return fmt.Errorf("remove interrupted FakeTCP classic owner record: %w", err)
	}
	return unix.Fsync(store.root.FD())
}

func (store *fakeTCPClassicOwnerStore) Persist(
	record *fakeTCPClassicOwnerRecord,
	expected *fakeTCPClassicOwnerRecord,
) error {
	if store == nil || store.root == nil {
		return errors.New("FakeTCP classic owner store is unavailable")
	}
	normalizeFakeTCPClassicOwnerRecord(record)
	if err := validateFakeTCPClassicOwnerRecord(record, store.resource); err != nil {
		return err
	}
	if expected == nil {
		if record.Sequence != 1 {
			return fmt.Errorf("initial FakeTCP classic owner sequence = %d, want 1", record.Sequence)
		}
	} else {
		if record.Sequence != expected.Sequence+1 ||
			record.ResourceKey != expected.ResourceKey ||
			record.BootID != expected.BootID ||
			record.CreatedAt != expected.CreatedAt ||
			record.Generation != expected.Generation ||
			record.ObjectSHA256 != expected.ObjectSHA256 ||
			!slices.Equal(record.ActiveFilters, expected.ActiveFilters) {
			return errors.New("FakeTCP classic owner immutable fields or sequence changed")
		}
	}
	data, err := marshalFakeTCPClassicOwnerRecord(record)
	if err != nil {
		return err
	}
	if err := store.recoverNext(); err != nil {
		return err
	}
	nextFile, nextIdentity, err := createAnchoredRegularFileExclusive(
		store.root, store.nextName, 0o600, store.expectedUID,
	)
	if err != nil {
		return fmt.Errorf("create next FakeTCP classic owner record: %w", err)
	}
	defer nextFile.Close()
	if err := writeAndSyncAnchoredFile(
		store.root,
		store.nextName,
		nextFile,
		nextIdentity,
		data,
		store.expectedUID,
	); err != nil {
		return fmt.Errorf("write next FakeTCP classic owner record: %w", err)
	}
	if expected == nil {
		existingFile, _, err := openExistingAnchoredRegularFile(
			store.root, store.fileName, 0o600, store.expectedUID,
		)
		if err == nil {
			closeErr := existingFile.Close()
			if closeErr != nil {
				return fmt.Errorf("close unexpected existing FakeTCP classic owner record: %w", closeErr)
			}
			return errors.New("FakeTCP classic owner record unexpectedly already exists")
		} else if !errors.Is(err, unix.ENOENT) {
			return err
		}
		if err := unix.Renameat2(
			store.root.FD(), store.nextName,
			store.root.FD(), store.fileName,
			unix.RENAME_NOREPLACE,
		); err != nil {
			return fmt.Errorf("publish initial FakeTCP classic owner record: %w", err)
		}
		if err := unix.Fsync(store.root.FD()); err != nil {
			return fmt.Errorf("sync initial FakeTCP classic owner record: %w", err)
		}
		_, err = validateAnchoredRegularFile(
			store.root, store.fileName, int(nextFile.Fd()), 0o600,
			store.expectedUID, &nextIdentity,
		)
		return err
	}

	targetFile, targetIdentity, err := openExistingAnchoredRegularFile(
		store.root, store.fileName, 0o600, store.expectedUID,
	)
	if err != nil {
		return err
	}
	defer targetFile.Close()
	current, err := readFakeTCPClassicOwnerRecord(targetFile)
	if err != nil {
		return err
	}
	if !sameFakeTCPClassicOwnerRecord(current, expected) {
		return errors.New("FakeTCP classic owner record changed before descriptor exchange")
	}
	if err := unix.Renameat2(
		store.root.FD(), store.nextName,
		store.root.FD(), store.fileName,
		unix.RENAME_EXCHANGE,
	); err != nil {
		return fmt.Errorf("exchange FakeTCP classic owner record: %w", err)
	}
	if err := unix.Fsync(store.root.FD()); err != nil {
		return fmt.Errorf("sync exchanged FakeTCP classic owner record: %w", err)
	}
	if _, err := validateAnchoredRegularFile(
		store.root, store.fileName, int(nextFile.Fd()), 0o600,
		store.expectedUID, &nextIdentity,
	); err != nil {
		return err
	}
	if _, err := validateAnchoredRegularFile(
		store.root, store.nextName, int(targetFile.Fd()), 0o600,
		store.expectedUID, &targetIdentity,
	); err != nil {
		return err
	}
	if err := unix.Unlinkat(store.root.FD(), store.nextName, 0); err != nil {
		return fmt.Errorf("remove retired FakeTCP classic owner record: %w", err)
	}
	return unix.Fsync(store.root.FD())
}

func (store *fakeTCPClassicOwnerStore) Remove(
	expected *fakeTCPClassicOwnerRecord,
) error {
	if store == nil || store.root == nil || expected == nil {
		return errors.New("remove FakeTCP classic owner requires a store and expected record")
	}
	if err := store.recoverNext(); err != nil {
		return err
	}
	file, identity, err := openExistingAnchoredRegularFile(
		store.root, store.fileName, 0o600, store.expectedUID,
	)
	if err != nil {
		return err
	}
	defer file.Close()
	current, err := readFakeTCPClassicOwnerRecord(file)
	if err != nil {
		return err
	}
	if !sameFakeTCPClassicOwnerRecord(current, expected) {
		return errors.New("FakeTCP classic owner record changed before removal")
	}
	if _, err := validateAnchoredRegularFile(
		store.root, store.fileName, int(file.Fd()), 0o600,
		store.expectedUID, &identity,
	); err != nil {
		return err
	}
	if err := unix.Unlinkat(store.root.FD(), store.fileName, 0); err != nil {
		return fmt.Errorf("remove FakeTCP classic owner record: %w", err)
	}
	return unix.Fsync(store.root.FD())
}

func newFakeTCPClassicOwnerRecord(
	resource pinResourceIdentity,
	bootID string,
	now time.Time,
	generation uint64,
	objectSHA256 string,
	filters []tcFilterBinding,
) *fakeTCPClassicOwnerRecord {
	timestamp := now.UTC().Format(time.RFC3339Nano)
	record := &fakeTCPClassicOwnerRecord{
		Version:       fakeTCPClassicOwnerVersion,
		Sequence:      1,
		ResourceKey:   resource.key,
		ParentDevice:  resource.parentDevice,
		ParentInode:   resource.parentInode,
		PinBaseName:   resource.base,
		PinPath:       resource.pinPath,
		BootID:        bootID,
		CreatedAt:     timestamp,
		UpdatedAt:     timestamp,
		Phase:         fakeTCPClassicPhaseAttaching,
		Generation:    generation,
		ObjectSHA256:  objectSHA256,
		ActiveFilters: slices.Clone(filters),
	}
	normalizeFakeTCPClassicOwnerRecord(record)
	return record
}

func advanceFakeTCPClassicOwnerRecord(
	record *fakeTCPClassicOwnerRecord,
	phase string,
	now time.Time,
) *fakeTCPClassicOwnerRecord {
	next := *record
	next.Sequence++
	next.UpdatedAt = now.UTC().Format(time.RFC3339Nano)
	next.Phase = phase
	next.ActiveFilters = slices.Clone(record.ActiveFilters)
	return &next
}
