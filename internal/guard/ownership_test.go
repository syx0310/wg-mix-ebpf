package guard

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOwnerRecordPersistsStableInstallationIdentity(t *testing.T) {
	stateDir := t.TempDir()
	exec := CommandExecutor{StateDir: stateDir}
	first, fresh, err := exec.loadOrCreateOwner()
	if err != nil {
		t.Fatal(err)
	}
	if !fresh {
		t.Fatal("first owner load should create the record")
	}
	second, fresh, err := exec.loadOrCreateOwner()
	if err != nil {
		t.Fatal(err)
	}
	if fresh {
		t.Fatal("second owner load should reuse the record")
	}
	if first != second {
		t.Fatalf("owner identity changed: first=%#v second=%#v", first, second)
	}
	data, err := os.ReadFile(filepath.Join(stateDir, OwnerRecordFileName))
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateOwnerRecordBytes(stateDir, data); err != nil {
		t.Fatalf("exported owner validator rejected the persisted record: %v", err)
	}
}

func TestOwnerRecordRejectsLooseMode(t *testing.T) {
	stateDir := t.TempDir()
	exec := CommandExecutor{StateDir: stateDir}
	if _, _, err := exec.loadOrCreateOwner(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(stateDir, OwnerRecordFileName)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := exec.loadOrCreateOwner(); err == nil || !strings.Contains(err.Error(), "want 0600") {
		t.Fatalf("loose owner record mode should fail closed, got %v", err)
	}
}

func TestOwnerRecordRejectsSymlink(t *testing.T) {
	stateDir := t.TempDir()
	victim := filepath.Join(stateDir, "victim.json")
	if err := os.WriteFile(victim, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(stateDir, OwnerRecordFileName)
	if err := os.Symlink(victim, path); err != nil {
		t.Fatal(err)
	}
	exec := CommandExecutor{StateDir: stateDir}
	if _, _, err := exec.loadOrCreateOwner(); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("symlink owner record should fail closed, got %v", err)
	}
	data, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "{}\n" {
		t.Fatalf("symlink victim changed: %q", data)
	}
}

func TestOwnerRecordRejectsCopyFromDifferentStateDirectory(t *testing.T) {
	firstDir := t.TempDir()
	firstExec := CommandExecutor{StateDir: firstDir}
	if _, _, err := firstExec.loadOrCreateOwner(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(firstDir, OwnerRecordFileName))
	if err != nil {
		t.Fatal(err)
	}
	secondDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(secondDir, OwnerRecordFileName), data, 0o600); err != nil {
		t.Fatal(err)
	}
	secondExec := CommandExecutor{StateDir: secondDir}
	if _, _, err := secondExec.loadOrCreateOwner(); err == nil || !strings.Contains(err.Error(), "state_dir") {
		t.Fatalf("copied owner record should fail state-dir binding, got %v", err)
	}
	if err := ValidateOwnerRecordBytes(secondDir, data); err == nil || !strings.Contains(err.Error(), "state_dir") {
		t.Fatalf("exported validator accepted a copied owner record: %v", err)
	}
}

func TestOwnerRecordRejectsGroupWritableStateDirectory(t *testing.T) {
	stateDir := t.TempDir()
	if err := os.Chmod(stateDir, 0o775); err != nil {
		t.Fatal(err)
	}
	exec := CommandExecutor{StateDir: stateDir}
	if _, _, err := exec.loadOrCreateOwner(); err == nil || !strings.Contains(err.Error(), "group/other writable") {
		t.Fatalf("group-writable state directory should fail closed, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, OwnerRecordFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsafe state directory received owner record: %v", err)
	}
}

func TestOwnerRecordRejectsHardLink(t *testing.T) {
	stateDir := t.TempDir()
	exec := CommandExecutor{StateDir: stateDir}
	if _, _, err := exec.loadOrCreateOwner(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(stateDir, OwnerRecordFileName)
	if err := os.Link(path, filepath.Join(stateDir, "owner-copy.json")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := exec.loadOrCreateOwner(); err == nil || !strings.Contains(err.Error(), "link count") {
		t.Fatalf("hard-linked owner record should fail closed, got %v", err)
	}
}
