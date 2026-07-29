package guard

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func guardTestStateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func TestOwnerRecordPersistsStableInstallationIdentity(t *testing.T) {
	stateDir := guardTestStateDir(t)
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
	stateDir := guardTestStateDir(t)
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
	stateDir := guardTestStateDir(t)
	victim := filepath.Join(stateDir, "victim.json")
	if err := os.WriteFile(victim, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(stateDir, OwnerRecordFileName)
	if err := os.Symlink(victim, path); err != nil {
		t.Fatal(err)
	}
	exec := CommandExecutor{StateDir: stateDir}
	if _, _, err := exec.loadOrCreateOwner(); err == nil {
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
	firstDir := guardTestStateDir(t)
	firstExec := CommandExecutor{StateDir: firstDir}
	if _, _, err := firstExec.loadOrCreateOwner(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(firstDir, OwnerRecordFileName))
	if err != nil {
		t.Fatal(err)
	}
	secondDir := guardTestStateDir(t)
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
	stateDir := guardTestStateDir(t)
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
	stateDir := guardTestStateDir(t)
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

func TestOwnerRecordRejectsFinalStateDirectorySymlink(t *testing.T) {
	parent := guardTestStateDir(t)
	realStateDir := filepath.Join(parent, "real-state")
	if err := os.Mkdir(realStateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(parent, "state-alias")
	if err := os.Symlink(realStateDir, alias); err != nil {
		t.Fatal(err)
	}
	exec := CommandExecutor{StateDir: alias}
	if _, _, err := exec.loadOrCreateOwner(); err == nil {
		t.Fatal("a final state-directory symlink must be rejected")
	}
	if _, err := os.Stat(filepath.Join(realStateDir, OwnerRecordFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("symlink target received an owner record: %v", err)
	}
}

func TestOwnerRecordRejectsAncestorStateDirectorySymlink(t *testing.T) {
	parent := guardTestStateDir(t)
	realParent := filepath.Join(parent, "real-parent")
	realStateDir := filepath.Join(realParent, "state")
	if err := os.MkdirAll(realStateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	aliasParent := filepath.Join(parent, "parent-alias")
	if err := os.Symlink(realParent, aliasParent); err != nil {
		t.Fatal(err)
	}
	exec := CommandExecutor{StateDir: filepath.Join(aliasParent, "state")}
	if _, _, err := exec.loadOrCreateOwner(); err == nil {
		t.Fatal("an ancestor state-directory symlink must be rejected")
	}
	if _, err := os.Stat(filepath.Join(realStateDir, OwnerRecordFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ancestor symlink target received an owner record: %v", err)
	}
}

func TestOwnerRecordRecoversPartialPendingPublish(t *testing.T) {
	stateDir := guardTestStateDir(t)
	pendingPath := filepath.Join(stateDir, ownerRecordPendingFileName)
	if err := os.WriteFile(pendingPath, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	exec := CommandExecutor{StateDir: stateDir}
	if _, fresh, err := exec.loadOrCreateOwner(); err != nil {
		t.Fatal(err)
	} else if !fresh {
		t.Fatal("recovering a partial pending publication should create the final owner record")
	}
	if _, err := os.Stat(pendingPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending publication still has a directory entry: %v", err)
	}
}

func TestOwnerRecordBindsStateDirectoryDeviceAndInode(t *testing.T) {
	firstDir := guardTestStateDir(t)
	first := CommandExecutor{StateDir: firstDir}
	if _, _, err := first.loadOrCreateOwner(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(firstDir, OwnerRecordFileName))
	if err != nil {
		t.Fatal(err)
	}
	var copied ownerRecord
	if err := json.Unmarshal(data, &copied); err != nil {
		t.Fatal(err)
	}
	secondDir := guardTestStateDir(t)
	copied.StateDir = secondDir
	copiedData, err := json.Marshal(copied)
	if err != nil {
		t.Fatal(err)
	}
	err = ValidateOwnerRecordBytes(secondDir, copiedData)
	if err == nil || !strings.Contains(err.Error(), "directory identity") {
		t.Fatalf("copied record with a rewritten path must fail inode/device binding, got %v", err)
	}
}

func TestOwnerRecordRejectsPartialFinalWithoutOverwritingIt(t *testing.T) {
	stateDir := guardTestStateDir(t)
	path := filepath.Join(stateDir, OwnerRecordFileName)
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	exec := CommandExecutor{StateDir: stateDir}
	if _, _, err := exec.loadOrCreateOwner(); err == nil {
		t.Fatal("a partial final owner record must fail closed")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "{" {
		t.Fatalf("partial final owner record was overwritten: %q", data)
	}
}

func TestOwnerRecordRejectsHardLinkedPendingFile(t *testing.T) {
	stateDir := guardTestStateDir(t)
	victim := filepath.Join(stateDir, "victim")
	if err := os.WriteFile(victim, []byte("do-not-overwrite"), 0o600); err != nil {
		t.Fatal(err)
	}
	pending := filepath.Join(stateDir, ownerRecordPendingFileName)
	if err := os.Link(victim, pending); err != nil {
		t.Fatal(err)
	}
	exec := CommandExecutor{StateDir: stateDir}
	if _, _, err := exec.loadOrCreateOwner(); err == nil || !strings.Contains(err.Error(), "link count") {
		t.Fatalf("a hard-linked pending owner record must fail closed, got %v", err)
	}
	data, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "do-not-overwrite" {
		t.Fatalf("hard-link victim was overwritten: %q", data)
	}
}

func TestGuardRenameNoReplacePreservesExistingFinal(t *testing.T) {
	stateDir := guardTestStateDir(t)
	directory, err := openSecureStateDirectory(stateDir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.close()
	if err := os.WriteFile(filepath.Join(stateDir, "pending"), []byte("pending"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "final"), []byte("final"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := guardRenameNoReplaceAt(directory.file, "pending", "final"); !errors.Is(err, os.ErrExist) {
		t.Fatalf("no-replace rename error = %v, want file exists", err)
	}
	for name, want := range map[string]string{"pending": "pending", "final": "final"} {
		data, err := os.ReadFile(filepath.Join(stateDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != want {
			t.Fatalf("%s content = %q, want %q", name, data, want)
		}
	}
}
