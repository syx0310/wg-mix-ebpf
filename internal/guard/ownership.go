package guard

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	OwnerRecordFileName        = "guard-owner.v2.json"
	legacyOwnerRecordFileName  = "guard-owner.v1.json"
	ownerRecordPendingFileName = ".guard-owner.v2.pending"
	ownerRecordVersion         = 2
	ownerMarkerPrefix          = "wg-mix-ebpf-guard-v2:"
	ownerTokenBytes            = 32
	ownedTableTokenHex         = 32
	maxOwnerRecordBytes        = 4096
)

type ownerRecord struct {
	Version        int    `json:"version"`
	InstallationID string `json:"installation_id"`
	StateDir       string `json:"state_dir"`
	StateDirDevice uint64 `json:"state_dir_device"`
	StateDirInode  uint64 `json:"state_dir_inode"`
	Table          string `json:"table"`
	Marker         string `json:"marker"`
}

func (r ownerRecord) validateSelf() error {
	if r.Version != ownerRecordVersion {
		return fmt.Errorf("unsupported guard owner record version %d", r.Version)
	}
	if len(r.InstallationID) != ownerTokenBytes*2 ||
		strings.ToLower(r.InstallationID) != r.InstallationID {
		return errors.New("guard installation_id must be lowercase 256-bit hex")
	}
	decoded, err := hex.DecodeString(r.InstallationID)
	if err != nil || len(decoded) != ownerTokenBytes {
		return errors.New("guard installation_id must be lowercase 256-bit hex")
	}
	if !filepath.IsAbs(r.StateDir) || filepath.Clean(r.StateDir) != r.StateDir ||
		r.StateDir == string(filepath.Separator) {
		return fmt.Errorf("guard owner record state_dir %q is not a safe absolute path", r.StateDir)
	}
	if r.StateDirInode == 0 {
		return errors.New("guard owner record state_dir_inode must be non-zero")
	}
	if r.Table != ownedTableName(r.InstallationID) {
		return fmt.Errorf("guard owner record table %q does not match installation identity", r.Table)
	}
	if r.Marker != ownedTableMarker(r.InstallationID) {
		return errors.New("guard owner record marker does not match installation identity")
	}
	return nil
}

func (r ownerRecord) validate(stateDir *secureStateDirectory) error {
	if err := r.validateSelf(); err != nil {
		return err
	}
	if stateDir == nil {
		return errors.New("guard state directory is unavailable")
	}
	if r.StateDir != stateDir.path {
		return fmt.Errorf("guard owner record state_dir %q does not match %q", r.StateDir, stateDir.path)
	}
	if r.StateDirDevice != stateDir.device || r.StateDirInode != stateDir.inode {
		return fmt.Errorf(
			"guard owner record state directory identity %d:%d does not match %d:%d",
			r.StateDirDevice,
			r.StateDirInode,
			stateDir.device,
			stateDir.inode,
		)
	}
	return nil
}

func ownedTableName(installationID string) string {
	return TableName + "_" + installationID[:ownedTableTokenHex]
}

func ownedTableMarker(installationID string) string {
	return ownerMarkerPrefix + installationID
}

func (e CommandExecutor) loadOrCreateOwner() (record ownerRecord, fresh bool, err error) {
	stateDir, err := openSecureStateDirectory(e.StateDir, true)
	if err != nil {
		return ownerRecord{}, false, err
	}
	defer func() {
		if closeErr := stateDir.close(); err == nil && closeErr != nil {
			err = fmt.Errorf("close guard state directory %s: %w", stateDir.path, closeErr)
		}
	}()
	if err := rejectLegacyOwnerRecord(stateDir); err != nil {
		return ownerRecord{}, false, err
	}

	record, err = loadOwnerRecord(stateDir)
	if err == nil {
		return record, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return ownerRecord{}, false, err
	}

	token := make([]byte, ownerTokenBytes)
	if _, err = io.ReadFull(rand.Reader, token); err != nil {
		return ownerRecord{}, false, fmt.Errorf("generate guard installation identity: %w", err)
	}
	installationID := hex.EncodeToString(token)
	record = ownerRecord{
		Version:        ownerRecordVersion,
		InstallationID: installationID,
		StateDir:       stateDir.path,
		StateDirDevice: stateDir.device,
		StateDirInode:  stateDir.inode,
		Table:          ownedTableName(installationID),
		Marker:         ownedTableMarker(installationID),
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return ownerRecord{}, false, fmt.Errorf("encode guard owner record: %w", err)
	}
	data = append(data, '\n')
	if err := publishOwnerRecord(stateDir, data); err != nil {
		if errors.Is(err, os.ErrExist) {
			record, loadErr := loadOwnerRecord(stateDir)
			return record, false, loadErr
		}
		return ownerRecord{}, false, err
	}
	persisted, err := loadOwnerRecord(stateDir)
	if err != nil {
		return ownerRecord{}, false, fmt.Errorf("load newly published guard owner record: %w", err)
	}
	if persisted != record {
		return ownerRecord{}, false, errors.New("newly published guard owner record changed unexpectedly")
	}
	return persisted, true, nil
}

func (e CommandExecutor) loadOwnerIfPresent() (record ownerRecord, present bool, err error) {
	stateDir, err := openSecureStateDirectory(e.StateDir, false)
	if errors.Is(err, os.ErrNotExist) {
		return ownerRecord{}, false, nil
	}
	if err != nil {
		return ownerRecord{}, false, err
	}
	defer func() {
		if closeErr := stateDir.close(); err == nil && closeErr != nil {
			err = fmt.Errorf("close guard state directory %s: %w", stateDir.path, closeErr)
		}
	}()
	if err := rejectLegacyOwnerRecord(stateDir); err != nil {
		return ownerRecord{}, false, err
	}

	record, err = loadOwnerRecord(stateDir)
	if errors.Is(err, os.ErrNotExist) {
		return ownerRecord{}, false, nil
	}
	if err != nil {
		return ownerRecord{}, false, err
	}
	return record, true, nil
}

func rejectLegacyOwnerRecord(stateDir *secureStateDirectory) error {
	if err := stateDir.validatePath(); err != nil {
		return err
	}
	path := filepath.Join(stateDir.path, legacyOwnerRecordFileName)
	file, err := guardOpenReadFileAt(stateDir.file, legacyOwnerRecordFileName)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect legacy guard owner record %s: %w", path, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect open legacy guard owner record %s: %w", path, err)
	}
	if err := validateOwnerRecordFile(path, info); err != nil {
		return err
	}
	matches, err := guardNamedFileMatches(stateDir.file, legacyOwnerRecordFileName, file)
	if err != nil {
		return fmt.Errorf("reopen legacy guard owner record %s: %w", path, err)
	}
	if !matches {
		return fmt.Errorf("legacy guard owner record %s changed while opening", path)
	}
	if err := stateDir.validatePath(); err != nil {
		return err
	}
	// A v1 record is the only durable link to its randomized v1 table name.
	// Treat any securely opened v1 record as owned-but-unmigrated even when
	// its JSON is damaged; ignoring it could make uninstall erase the last
	// ownership evidence while leaving a packet-dropping table behind.
	return fmt.Errorf(
		"legacy guard owner record %s may own a v1 nftables table; explicit ownership migration is required",
		path,
	)
}

func loadOwnerRecord(stateDir *secureStateDirectory) (ownerRecord, error) {
	if err := stateDir.validatePath(); err != nil {
		return ownerRecord{}, err
	}
	path := filepath.Join(stateDir.path, OwnerRecordFileName)
	file, err := guardOpenReadFileAt(stateDir.file, OwnerRecordFileName)
	if err != nil {
		return ownerRecord{}, fmt.Errorf("open guard owner record %s: %w", path, err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return ownerRecord{}, fmt.Errorf("inspect open guard owner record %s: %w", path, err)
	}
	if err := validateOwnerRecordFile(path, info); err != nil {
		return ownerRecord{}, err
	}
	matches, err := guardNamedFileMatches(stateDir.file, OwnerRecordFileName, file)
	if err != nil {
		return ownerRecord{}, fmt.Errorf("reopen guard owner record %s: %w", path, err)
	}
	if !matches {
		return ownerRecord{}, fmt.Errorf("guard owner record %s changed while opening", path)
	}

	limited := io.LimitReader(file, maxOwnerRecordBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return ownerRecord{}, fmt.Errorf("read guard owner record %s: %w", path, err)
	}
	if len(data) > maxOwnerRecordBytes {
		return ownerRecord{}, fmt.Errorf("guard owner record %s exceeds %d bytes", path, maxOwnerRecordBytes)
	}
	matches, err = guardNamedFileMatches(stateDir.file, OwnerRecordFileName, file)
	if err != nil {
		return ownerRecord{}, fmt.Errorf("revalidate guard owner record %s: %w", path, err)
	}
	if !matches {
		return ownerRecord{}, fmt.Errorf("guard owner record %s changed while reading", path)
	}
	if err := stateDir.validatePath(); err != nil {
		return ownerRecord{}, err
	}
	record, err := decodeOwnerRecord(data, stateDir)
	if err != nil {
		return ownerRecord{}, fmt.Errorf("parse guard owner record %s: %w", path, err)
	}
	return record, nil
}

func publishOwnerRecord(stateDir *secureStateDirectory, data []byte) error {
	if len(data) > maxOwnerRecordBytes {
		return fmt.Errorf("guard owner record exceeds %d bytes", maxOwnerRecordBytes)
	}
	if err := stateDir.validatePath(); err != nil {
		return err
	}

	pendingPath := filepath.Join(stateDir.path, ownerRecordPendingFileName)
	file, err := guardCreateFileAt(stateDir.file, ownerRecordPendingFileName, 0o600)
	if errors.Is(err, os.ErrExist) {
		file, err = guardOpenReadWriteFileAt(stateDir.file, ownerRecordPendingFileName)
	}
	if err != nil {
		return fmt.Errorf("open pending guard owner record %s: %w", pendingPath, err)
	}
	defer file.Close()

	if err := guardTryLockExclusive(file); err != nil {
		return fmt.Errorf("lock pending guard owner record %s: %w", pendingPath, err)
	}
	if _, err := loadOwnerRecord(stateDir); err == nil {
		return os.ErrExist
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("recheck final guard owner record before publication: %w", err)
	}

	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect pending guard owner record %s: %w", pendingPath, err)
	}
	if err := validateOwnerRecordFile(pendingPath, info); err != nil {
		return err
	}
	matches, err := guardNamedFileMatches(stateDir.file, ownerRecordPendingFileName, file)
	if err != nil {
		return fmt.Errorf("reopen pending guard owner record %s: %w", pendingPath, err)
	}
	if !matches {
		return fmt.Errorf("pending guard owner record %s changed while opening", pendingPath)
	}

	if err := file.Truncate(0); err != nil {
		return fmt.Errorf("truncate pending guard owner record %s: %w", pendingPath, err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind pending guard owner record %s: %w", pendingPath, err)
	}
	if err := writeAndSyncOwnerRecord(file, data); err != nil {
		return fmt.Errorf("write pending guard owner record %s: %w", pendingPath, err)
	}
	info, err = file.Stat()
	if err != nil {
		return fmt.Errorf("inspect written pending guard owner record %s: %w", pendingPath, err)
	}
	if err := validateOwnerRecordFile(pendingPath, info); err != nil {
		return err
	}
	matches, err = guardNamedFileMatches(stateDir.file, ownerRecordPendingFileName, file)
	if err != nil {
		return fmt.Errorf("revalidate pending guard owner record %s: %w", pendingPath, err)
	}
	if !matches {
		return fmt.Errorf("pending guard owner record %s changed while writing", pendingPath)
	}
	if err := stateDir.validatePath(); err != nil {
		return err
	}

	if err := guardRenameNoReplaceAt(
		stateDir.file,
		ownerRecordPendingFileName,
		OwnerRecordFileName,
	); err != nil {
		if errors.Is(err, os.ErrExist) {
			return os.ErrExist
		}
		return fmt.Errorf("publish guard owner record %s: %w", filepath.Join(stateDir.path, OwnerRecordFileName), err)
	}
	matches, err = guardNamedFileMatches(stateDir.file, OwnerRecordFileName, file)
	if err != nil {
		return fmt.Errorf("open published guard owner record: %w", err)
	}
	if !matches {
		return errors.New("published guard owner record does not match the synced pending file")
	}
	if err := stateDir.sync(); err != nil {
		return fmt.Errorf("sync guard state directory %s: %w", stateDir.path, err)
	}
	return stateDir.validatePath()
}

// ValidateOwnerRecordBytes validates the content of the one guard-owned state
// file. Install/uninstall cleanup can use this after opening the file through
// its own descriptor-anchored directory plan; it must still validate the file
// type, uid, mode, link count, and descriptor identity itself.
func ValidateOwnerRecordBytes(stateDir string, data []byte) (err error) {
	directory, err := openSecureStateDirectory(stateDir, false)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := directory.close(); err == nil && closeErr != nil {
			err = fmt.Errorf("close guard state directory %s: %w", directory.path, closeErr)
		}
	}()
	if len(data) > maxOwnerRecordBytes {
		return fmt.Errorf("guard owner record exceeds %d bytes", maxOwnerRecordBytes)
	}
	_, err = decodeOwnerRecord(data, directory)
	return err
}

func decodeOwnerRecord(data []byte, stateDir *secureStateDirectory) (ownerRecord, error) {
	var record ownerRecord
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return ownerRecord{}, err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return ownerRecord{}, errors.New("guard owner record has trailing JSON")
	}
	if err := record.validate(stateDir); err != nil {
		return ownerRecord{}, err
	}
	return record, nil
}

func validateOwnerRecordFile(path string, info os.FileInfo) error {
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("guard owner record %s is not a regular file", path)
	}
	if info.Mode().Perm() != 0o600 {
		return fmt.Errorf("guard owner record %s mode is %04o, want 0600", path, info.Mode().Perm())
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("read guard owner record ownership for %s", path)
	}
	if int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("guard owner record %s uid %d does not match effective uid %d", path, stat.Uid, os.Geteuid())
	}
	if uint64(stat.Nlink) != 1 {
		return fmt.Errorf("guard owner record %s link count is %d, want 1", path, stat.Nlink)
	}
	return nil
}

func writeAndSyncOwnerRecord(file *os.File, data []byte) error {
	written := 0
	for written < len(data) {
		n, err := file.Write(data[written:])
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		written += n
	}
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	return file.Sync()
}
