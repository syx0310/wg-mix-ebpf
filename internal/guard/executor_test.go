package guard

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/syx0310/wg-mix-ebpf/internal/control"
)

func TestDryRunExecutor(t *testing.T) {
	plan := BuildNftPlan(&control.State{
		WireGuards: []control.WireGuardState{
			{Name: "wg0", ConfigFwMark: 0x10000002, ConfigListenPort: 31001},
		},
	})
	exec := &DryRunExecutor{}
	if err := exec.Apply(t.Context(), plan); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(exec.AppliedScript, "meta mark 0x10000002") {
		t.Fatalf("missing apply script: %s", exec.AppliedScript)
	}
	if !strings.Contains(exec.AppliedScript, planTablePlaceholder) ||
		strings.Contains(exec.AppliedScript, "delete table inet "+TableName+"\n") {
		t.Fatalf("dry-run should be a non-executable owned-table template: %s", exec.AppliedScript)
	}
	if strings.Contains(exec.FallbackScript, "delete table") {
		t.Fatalf("fallback should be create-only: %s", exec.FallbackScript)
	}
	if err := exec.Cleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(exec.CleanupScript, "validated-handle") ||
		strings.Contains(exec.CleanupScript, "delete table inet "+TableName) {
		t.Fatalf("cleanup dry-run must not contain a name-based delete: %s", exec.CleanupScript)
	}
}

func TestMissingGuardTableErrorIsIdempotent(t *testing.T) {
	diagnostic := []byte("Error: Could not process rule: No such file or directory\nlist table inet wg_mix_ebpf_guard\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n")
	if !isMissingTableDiagnostic(diagnostic, TableName) {
		t.Fatal("expected missing guard table error to be treated as idempotent")
	}
}

func TestMissingTableClassifierRejectsWrapperOnlyTableName(t *testing.T) {
	diagnostic := []byte("libnftables.so: No such file or directory")
	if isMissingTableDiagnostic(diagnostic, TableName) {
		t.Fatal("an unrelated runtime failure must not be classified as an absent table")
	}
}

func TestParseTableIdentityJSONRequiresHandleAndComment(t *testing.T) {
	const table = "wg_mix_ebpf_guard_0123456789abcdef"
	identity, err := parseTableIdentityJSON([]byte(`{
		"nftables": [
			{"metainfo": {"json_schema_version": 1}},
			{"table": {
				"family": "inet",
				"name": "wg_mix_ebpf_guard_0123456789abcdef",
				"handle": 42,
				"comment": "wg-mix-ebpf-guard-v2:012345"
			}},
			{"chain": {
				"family": "inet",
				"table": "wg_mix_ebpf_guard_0123456789abcdef",
				"name": "input",
				"handle": 43
			}}
		]
	}`), table)
	if err != nil {
		t.Fatal(err)
	}
	if !identity.Exists || identity.Handle != 42 || identity.Comment != "wg-mix-ebpf-guard-v2:012345" {
		t.Fatalf("unexpected table identity: %#v", identity)
	}
}

func TestParseTableIdentityJSONRejectsMissingHandle(t *testing.T) {
	const table = "wg_mix_ebpf_guard_0123456789abcdef"
	_, err := parseTableIdentityJSON([]byte(`{
		"nftables": [
			{"table": {
				"family": "inet",
				"name": "wg_mix_ebpf_guard_0123456789abcdef",
				"comment": "owner"
			}}
		]
	}`), table)
	if err == nil || !strings.Contains(err.Error(), "non-zero handle") {
		t.Fatalf("missing table handle should fail closed, got %v", err)
	}
}

func TestMissingNftBinaryCleanupFails(t *testing.T) {
	stateDir := guardTestStateDir(t)
	seedOwnerRecord(t, stateDir)
	exec := CommandExecutor{
		Binary:   filepath.Join(t.TempDir(), "missing-nft"),
		StateDir: stateDir,
	}
	if err := exec.Cleanup(t.Context()); err == nil {
		t.Fatal("missing nft binary must not report successful guard cleanup")
	}
}

func TestApplyReplacesExistingTableInSingleTransaction(t *testing.T) {
	plan := BuildNftPlan(&control.State{})
	stateDir := guardTestStateDir(t)
	owner := seedOwnerRecord(t, stateDir)
	var scripts []string
	exec := CommandExecutor{
		StateDir: stateDir,
		inspectTable: func(_ context.Context, table string) (tableIdentity, error) {
			if table == TableName {
				return tableIdentity{}, nil
			}
			if table != owner.Table {
				t.Fatalf("inspected table %q, want %q", table, owner.Table)
			}
			return tableIdentity{Exists: true, Handle: 73, Comment: owner.Marker}, nil
		},
		runScript: func(_ context.Context, script string) error {
			scripts = append(scripts, script)
			return nil
		},
	}
	if err := exec.Apply(t.Context(), plan); err != nil {
		t.Fatal(err)
	}
	if len(scripts) != 1 {
		t.Fatalf("nft invocations = %d, want 1: %#v", len(scripts), scripts)
	}
	if !strings.HasPrefix(scripts[0], "delete table inet handle 73\n") ||
		!strings.Contains(scripts[0], "create table inet "+owner.Table+" { comment \""+owner.Marker+"\"; }") {
		t.Fatalf("expected handle-bound delete+create transaction, got:\n%s", scripts[0])
	}
}

func TestApplyCreatesOnlyWhenOwnedTableIsMissing(t *testing.T) {
	plan := BuildNftPlan(&control.State{})
	stateDir := guardTestStateDir(t)
	owner := seedOwnerRecord(t, stateDir)
	var scripts []string
	exec := CommandExecutor{
		StateDir: stateDir,
		inspectTable: func(_ context.Context, table string) (tableIdentity, error) {
			if table == TableName {
				return tableIdentity{}, nil
			}
			if table != owner.Table {
				t.Fatalf("inspected table %q, want %q", table, owner.Table)
			}
			return tableIdentity{}, nil
		},
		runScript: func(_ context.Context, script string) error {
			scripts = append(scripts, script)
			return nil
		},
	}
	if err := exec.Apply(t.Context(), plan); err != nil {
		t.Fatal(err)
	}
	if len(scripts) != 1 {
		t.Fatalf("nft invocations = %d, want 1: %#v", len(scripts), scripts)
	}
	if strings.Contains(scripts[0], "delete table") ||
		!strings.HasPrefix(scripts[0], "create table inet "+owner.Table+" ") {
		t.Fatalf("missing owned table should use create-only:\n%s", scripts[0])
	}
}

func TestApplyDoesNotFallbackOnInvalidReplacement(t *testing.T) {
	plan := BuildNftPlan(&control.State{})
	stateDir := guardTestStateDir(t)
	owner := seedOwnerRecord(t, stateDir)
	var scripts []string
	exec := CommandExecutor{
		StateDir: stateDir,
		inspectTable: func(_ context.Context, table string) (tableIdentity, error) {
			if table == TableName {
				return tableIdentity{}, nil
			}
			return tableIdentity{Exists: true, Handle: 91, Comment: owner.Marker}, nil
		},
		runScript: func(_ context.Context, script string) error {
			scripts = append(scripts, script)
			return errors.New("Error: syntax error, unexpected drop")
		},
	}
	err := exec.Apply(t.Context(), plan)
	if err == nil || !strings.Contains(err.Error(), "replace owned startup guard atomically by handle") {
		t.Fatalf("expected atomic replacement error, got %v", err)
	}
	if len(scripts) != 1 {
		t.Fatalf("invalid replacement must not trigger fallback; invocations=%d", len(scripts))
	}
}

func TestApplyDoesNotDeleteUnownedLegacyFixedTable(t *testing.T) {
	stateDir := guardTestStateDir(t)
	plan := BuildNftPlan(&control.State{})
	var scripts []string
	exec := CommandExecutor{
		StateDir: stateDir,
		inspectTable: func(context.Context, string) (tableIdentity, error) {
			return tableIdentity{}, nil
		},
		runScript: func(_ context.Context, script string) error {
			scripts = append(scripts, script)
			return nil
		},
	}
	if err := exec.Apply(t.Context(), plan); err != nil {
		t.Fatal(err)
	}
	for _, script := range scripts {
		if strings.Contains(script, "delete table inet "+TableName+"\n") {
			t.Fatalf("apply attempted to delete an unowned legacy table:\n%s", script)
		}
	}
}

func TestApplyRejectsLegacyTableBeforeAnyWrite(t *testing.T) {
	stateDir := guardTestStateDir(t)
	var scripts []string
	exec := CommandExecutor{
		StateDir: stateDir,
		inspectTable: func(_ context.Context, table string) (tableIdentity, error) {
			if table != TableName {
				t.Fatalf("unexpected inspection of %q", table)
			}
			return tableIdentity{Exists: true, Handle: 17, Comment: "legacy-or-foreign"}, nil
		},
		runScript: func(_ context.Context, script string) error {
			scripts = append(scripts, script)
			return nil
		},
	}
	err := exec.Apply(t.Context(), BuildNftPlan(&control.State{}))
	if err == nil || !strings.Contains(err.Error(), "refusing to replace or adopt") {
		t.Fatalf("apply should reject legacy table, got %v", err)
	}
	if len(scripts) != 0 {
		t.Fatalf("legacy table rejection issued nft writes: %#v", scripts)
	}
	if _, statErr := os.Stat(filepath.Join(stateDir, OwnerRecordFileName)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("legacy rejection created an owner record: %v", statErr)
	}
}

func TestApplyRejectsLegacyV1OwnerRecordBeforeAnyWrite(t *testing.T) {
	stateDir := guardTestStateDir(t)
	writeLegacyV1OwnerRecord(t, stateDir)
	var scripts []string
	exec := CommandExecutor{
		StateDir: stateDir,
		inspectTable: func(_ context.Context, table string) (tableIdentity, error) {
			if table != TableName {
				t.Fatalf("unexpected inspection of %q", table)
			}
			return tableIdentity{}, nil
		},
		runScript: func(_ context.Context, script string) error {
			scripts = append(scripts, script)
			return nil
		},
	}
	err := exec.Apply(t.Context(), BuildNftPlan(&control.State{}))
	if err == nil || !strings.Contains(err.Error(), "guard-owner.v1.json") ||
		!strings.Contains(err.Error(), "migration") {
		t.Fatalf("v1 owner record should require explicit migration, got %v", err)
	}
	if len(scripts) != 0 {
		t.Fatalf("v1 owner record rejection issued nft writes: %#v", scripts)
	}
	if _, statErr := os.Stat(filepath.Join(stateDir, OwnerRecordFileName)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("v1 rejection created a v2 owner record: %v", statErr)
	}
}

func TestCleanupWithoutOwnerRecordIsZeroWrite(t *testing.T) {
	stateDir := guardTestStateDir(t)
	var scripts []string
	exec := CommandExecutor{
		StateDir: stateDir,
		inspectTable: func(_ context.Context, table string) (tableIdentity, error) {
			if table != TableName {
				t.Fatalf("unexpected inspection of %q", table)
			}
			return tableIdentity{}, nil
		},
		runScript: func(_ context.Context, script string) error {
			scripts = append(scripts, script)
			return nil
		},
	}
	if err := exec.Cleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(scripts) != 0 {
		t.Fatalf("cleanup without ownership issued nft writes: %#v", scripts)
	}
}

func TestCleanupRejectsLegacyV1OwnerRecordWithZeroWrite(t *testing.T) {
	stateDir := guardTestStateDir(t)
	writeLegacyV1OwnerRecord(t, stateDir)
	var scripts []string
	exec := CommandExecutor{
		StateDir: stateDir,
		inspectTable: func(_ context.Context, table string) (tableIdentity, error) {
			if table != TableName {
				t.Fatalf("unexpected inspection of %q", table)
			}
			return tableIdentity{}, nil
		},
		runScript: func(_ context.Context, script string) error {
			scripts = append(scripts, script)
			return nil
		},
	}
	err := exec.Cleanup(t.Context())
	if err == nil || !strings.Contains(err.Error(), "guard-owner.v1.json") ||
		!strings.Contains(err.Error(), "migration") {
		t.Fatalf("v1 cleanup should fail closed, got %v", err)
	}
	if len(scripts) != 0 {
		t.Fatalf("v1 cleanup rejection issued nft writes: %#v", scripts)
	}
}

func TestCleanupWithoutOwnerRejectsLegacyTableWithZeroWrite(t *testing.T) {
	stateDir := guardTestStateDir(t)
	var scripts []string
	exec := CommandExecutor{
		StateDir: stateDir,
		inspectTable: func(_ context.Context, table string) (tableIdentity, error) {
			if table != TableName {
				t.Fatalf("unexpected inspection of %q", table)
			}
			return tableIdentity{Exists: true, Handle: 19, Comment: "legacy"}, nil
		},
		runScript: func(_ context.Context, script string) error {
			scripts = append(scripts, script)
			return nil
		},
	}
	err := exec.Cleanup(t.Context())
	if err == nil || !strings.Contains(err.Error(), "manual migration") {
		t.Fatalf("legacy table without an owner record must fail explicitly, got %v", err)
	}
	if len(scripts) != 0 {
		t.Fatalf("legacy table rejection issued nft writes: %#v", scripts)
	}
}

func TestCleanupRejectsForeignMarkerWithZeroWrite(t *testing.T) {
	stateDir := guardTestStateDir(t)
	owner := seedOwnerRecord(t, stateDir)
	var scripts []string
	exec := CommandExecutor{
		StateDir: stateDir,
		inspectTable: func(_ context.Context, table string) (tableIdentity, error) {
			if table == TableName {
				return tableIdentity{}, nil
			}
			if table != owner.Table {
				t.Fatalf("unexpected inspection of %q", table)
			}
			return tableIdentity{Exists: true, Handle: 44, Comment: "foreign-owner"}, nil
		},
		runScript: func(_ context.Context, script string) error {
			scripts = append(scripts, script)
			return nil
		},
	}
	err := exec.Cleanup(t.Context())
	if err == nil || !strings.Contains(err.Error(), owner.Table) || !strings.Contains(err.Error(), "refusing mutation") {
		t.Fatalf("cleanup should reject foreign table marker, got %v", err)
	}
	if len(scripts) != 0 {
		t.Fatalf("foreign marker cleanup issued nft writes: %#v", scripts)
	}
}

func TestApplyRejectsForeignMarkerWithZeroWrite(t *testing.T) {
	stateDir := guardTestStateDir(t)
	owner := seedOwnerRecord(t, stateDir)
	var scripts []string
	exec := CommandExecutor{
		StateDir: stateDir,
		inspectTable: func(_ context.Context, table string) (tableIdentity, error) {
			if table == TableName {
				return tableIdentity{}, nil
			}
			return tableIdentity{Exists: true, Handle: 45, Comment: "foreign-owner"}, nil
		},
		runScript: func(_ context.Context, script string) error {
			scripts = append(scripts, script)
			return nil
		},
	}
	err := exec.Apply(t.Context(), BuildNftPlan(&control.State{}))
	if err == nil || !strings.Contains(err.Error(), owner.Table) || !strings.Contains(err.Error(), "refusing mutation") {
		t.Fatalf("apply should reject foreign table marker, got %v", err)
	}
	if len(scripts) != 0 {
		t.Fatalf("foreign marker apply issued nft writes: %#v", scripts)
	}
}

func TestCleanupDeletesMatchingTableByHandleAndVerifiesAbsence(t *testing.T) {
	stateDir := guardTestStateDir(t)
	owner := seedOwnerRecord(t, stateDir)
	inspections := 0
	var scripts []string
	exec := CommandExecutor{
		StateDir: stateDir,
		inspectTable: func(_ context.Context, table string) (tableIdentity, error) {
			inspections++
			if inspections == 1 {
				if table != TableName {
					t.Fatalf("first inspection = %q, want legacy table", table)
				}
				return tableIdentity{}, nil
			}
			if table != owner.Table {
				t.Fatalf("owned inspection = %q, want %q", table, owner.Table)
			}
			if inspections == 2 {
				return tableIdentity{Exists: true, Handle: 52, Comment: owner.Marker}, nil
			}
			return tableIdentity{}, nil
		},
		runScript: func(_ context.Context, script string) error {
			scripts = append(scripts, script)
			return nil
		},
	}
	if err := exec.Cleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(scripts) != 1 || scripts[0] != "delete table inet handle 52\n" {
		t.Fatalf("cleanup scripts = %#v, want one handle-bound delete", scripts)
	}
}

func seedOwnerRecord(t *testing.T, stateDir string) ownerRecord {
	t.Helper()
	exec := CommandExecutor{StateDir: stateDir}
	record, fresh, err := exec.loadOrCreateOwner()
	if err != nil {
		t.Fatal(err)
	}
	if !fresh {
		t.Fatal("test owner record unexpectedly existed")
	}
	return record
}

func writeLegacyV1OwnerRecord(t *testing.T, stateDir string) {
	t.Helper()
	const installationID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	data := []byte(`{
  "version": 1,
  "installation_id": "` + installationID + `",
  "state_dir": "` + stateDir + `",
  "table": "wg_mix_ebpf_guard_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "marker": "wg-mix-ebpf-guard-v1:` + installationID + `"
}
`)
	if err := os.WriteFile(filepath.Join(stateDir, "guard-owner.v1.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}
