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

	"github.com/syx0310/wg-mix-ebpf/internal/attachstate"
)

const (
	OwnerRecordFileName = "guard-owner.v1.json"
	ownerRecordVersion  = 1
	ownerMarkerPrefix   = "wg-mix-ebpf-guard-v1:"
	ownerTokenBytes     = 32
	ownedTableTokenHex  = 32
	maxOwnerRecordBytes = 4096
)

type ownerRecord struct {
	Version        int    `json:"version"`
	InstallationID string `json:"installation_id"`
	StateDir       string `json:"state_dir"`
	Table          string `json:"table"`
	Marker         string `json:"marker"`
}

func (r ownerRecord) validate(stateDir string) error {
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
	if r.StateDir != stateDir {
		return fmt.Errorf("guard owner record state_dir %q does not match %q", r.StateDir, stateDir)
	}
	if r.Table != ownedTableName(r.InstallationID) {
		return fmt.Errorf("guard owner record table %q does not match installation identity", r.Table)
	}
	if r.Marker != ownedTableMarker(r.InstallationID) {
		return errors.New("guard owner record marker does not match installation identity")
	}
	return nil
}

func ownedTableName(installationID string) string {
	return TableName + "_" + installationID[:ownedTableTokenHex]
}

func ownedTableMarker(installationID string) string {
	return ownerMarkerPrefix + installationID
}

func (e CommandExecutor) loadOrCreateOwner() (ownerRecord, bool, error) {
	stateDir, err := secureStateDir(e.StateDir, true)
	if err != nil {
		return ownerRecord{}, false, err
	}
	path := filepath.Join(stateDir, OwnerRecordFileName)
	record, err := loadOwnerRecord(path, stateDir)
	if err == nil {
		return record, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return ownerRecord{}, false, err
	}

	token := make([]byte, ownerTokenBytes)
	if _, err := io.ReadFull(rand.Reader, token); err != nil {
		return ownerRecord{}, false, fmt.Errorf("generate guard installation identity: %w", err)
	}
	installationID := hex.EncodeToString(token)
	record = ownerRecord{
		Version:        ownerRecordVersion,
		InstallationID: installationID,
		StateDir:       stateDir,
		Table:          ownedTableName(installationID),
		Marker:         ownedTableMarker(installationID),
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return ownerRecord{}, false, fmt.Errorf("encode guard owner record: %w", err)
	}
	data = append(data, '\n')
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			record, loadErr := loadOwnerRecord(path, stateDir)
			return record, false, loadErr
		}
		return ownerRecord{}, false, fmt.Errorf("create guard owner record %s: %w", path, err)
	}
	writeErr := writeAndSyncOwnerRecord(file, data)
	closeErr := file.Close()
	if writeErr != nil {
		return ownerRecord{}, false, fmt.Errorf("write guard owner record %s: %w", path, writeErr)
	}
	if closeErr != nil {
		return ownerRecord{}, false, fmt.Errorf("close guard owner record %s: %w", path, closeErr)
	}
	dir, err := os.Open(stateDir)
	if err != nil {
		return ownerRecord{}, false, fmt.Errorf("open guard state directory %s for sync: %w", stateDir, err)
	}
	syncErr := dir.Sync()
	closeErr = dir.Close()
	if syncErr != nil {
		return ownerRecord{}, false, fmt.Errorf("sync guard state directory %s: %w", stateDir, syncErr)
	}
	if closeErr != nil {
		return ownerRecord{}, false, fmt.Errorf("close guard state directory %s: %w", stateDir, closeErr)
	}
	return record, true, nil
}

func (e CommandExecutor) loadOwnerIfPresent() (ownerRecord, bool, error) {
	stateDir, err := secureStateDir(e.StateDir, false)
	if errors.Is(err, os.ErrNotExist) {
		return ownerRecord{}, false, nil
	}
	if err != nil {
		return ownerRecord{}, false, err
	}
	record, err := loadOwnerRecord(filepath.Join(stateDir, OwnerRecordFileName), stateDir)
	if errors.Is(err, os.ErrNotExist) {
		return ownerRecord{}, false, nil
	}
	if err != nil {
		return ownerRecord{}, false, err
	}
	return record, true, nil
}

func secureStateDir(configured string, create bool) (string, error) {
	dir := attachstate.StateDir(configured)
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("resolve guard state directory %s: %w", dir, err)
	}
	absolute = filepath.Clean(absolute)
	if create {
		if err := os.MkdirAll(absolute, 0o755); err != nil {
			return "", fmt.Errorf("create guard state directory %s: %w", absolute, err)
		}
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", fmt.Errorf("resolve guard state directory %s: %w", absolute, err)
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return "", fmt.Errorf("inspect guard state directory %s: %w", resolved, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("guard state path %s is not a real directory", resolved)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return "", fmt.Errorf("guard state directory %s mode %04o is group/other writable", resolved, info.Mode().Perm())
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("read guard state directory ownership for %s", resolved)
	}
	if int(stat.Uid) != os.Geteuid() {
		return "", fmt.Errorf("guard state directory %s uid %d does not match effective uid %d", resolved, stat.Uid, os.Geteuid())
	}
	return resolved, nil
}

func loadOwnerRecord(path, stateDir string) (ownerRecord, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return ownerRecord{}, err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return ownerRecord{}, fmt.Errorf("guard owner record %s is not a regular file", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return ownerRecord{}, fmt.Errorf("open guard owner record %s: %w", path, err)
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil {
		return ownerRecord{}, fmt.Errorf("inspect open guard owner record %s: %w", path, err)
	}
	if !os.SameFile(before, after) {
		return ownerRecord{}, fmt.Errorf("guard owner record %s changed while opening", path)
	}
	if err := validateOwnerRecordFile(path, after); err != nil {
		return ownerRecord{}, err
	}
	limited := io.LimitReader(file, maxOwnerRecordBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return ownerRecord{}, fmt.Errorf("read guard owner record %s: %w", path, err)
	}
	if len(data) > maxOwnerRecordBytes {
		return ownerRecord{}, fmt.Errorf("guard owner record %s exceeds %d bytes", path, maxOwnerRecordBytes)
	}
	record, err := decodeOwnerRecord(data, stateDir)
	if err != nil {
		return ownerRecord{}, fmt.Errorf("parse guard owner record %s: %w", path, err)
	}
	return record, nil
}

// ValidateOwnerRecordBytes validates the content of the one guard-owned state
// file. Install/uninstall cleanup can use this after opening the file through
// its own descriptor-anchored directory plan; it must still validate the file
// type, uid, mode, link count, and descriptor identity itself.
func ValidateOwnerRecordBytes(stateDir string, data []byte) error {
	resolved, err := secureStateDir(stateDir, false)
	if err != nil {
		return err
	}
	if len(data) > maxOwnerRecordBytes {
		return fmt.Errorf("guard owner record exceeds %d bytes", maxOwnerRecordBytes)
	}
	_, err = decodeOwnerRecord(data, resolved)
	return err
}

func decodeOwnerRecord(data []byte, stateDir string) (ownerRecord, error) {
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
