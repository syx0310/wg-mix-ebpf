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

func TestParseProjectTableInventoryJSON(t *testing.T) {
	tables, err := parseProjectTableInventoryJSON([]byte(`{
		"nftables": [
			{"metainfo": {"json_schema_version": 1}},
			{"table": {"family": "inet", "name": "unrelated"}},
			{"table": {"family": "ip", "name": "wg_mix_ebpf_guard"}},
			{"table": {"family": "inet", "name": "wg_mix_ebpf_guardrail"}},
			{"table": {"family": "inet", "name": "wg_mix_ebpf_guard_damaged-owner"}},
			{"table": {"family": "inet", "name": "wg_mix_ebpf_guard"}}
		]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"wg_mix_ebpf_guard", "wg_mix_ebpf_guard_damaged-owner"}
	if len(tables) != len(want) {
		t.Fatalf("project tables = %v, want %v", tables, want)
	}
	for index := range want {
		if tables[index] != want[index] {
			t.Fatalf("project tables = %v, want %v", tables, want)
		}
	}
}

func TestParseProjectTableInventoryJSONRejectsDuplicateMetadata(t *testing.T) {
	_, err := parseProjectTableInventoryJSON([]byte(`{
		"nftables": [
			{"table": {"family": "inet", "name": "wg_mix_ebpf_guard_orphan"}},
			{"table": {"family": "inet", "name": "wg_mix_ebpf_guard_orphan"}}
		]
	}`))
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate project table metadata was accepted: %v", err)
	}
}

func TestParseProjectTableInventoryJSONRejectsUnknownObjects(t *testing.T) {
	for _, document := range []string{
		`{"nftables": [{"metainfo": {"json_schema_version": 1}}, {"chain": {"family": "inet", "table": "unrelated", "name": "input"}}]}`,
		`{"nftables": [{"metainfo": {"json_schema_version": 1}}, {"table": {"family": "inet"}}]}`,
		`{"nftables": [{}]}`,
	} {
		if _, err := parseProjectTableInventoryJSON([]byte(document)); err == nil {
			t.Fatalf("malformed nft table inventory was accepted: %s", document)
		}
	}
}

func TestParseTableIdentityJSONRejectsMissingHandle(t *testing.T) {
	const table = "wg_mix_ebpf_guard_0123456789abcdef"
	_, err := parseTableIdentityJSON([]byte(`{
		"nftables": [
			{"metainfo": {"json_schema_version": 1}},
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

func TestParseProjectTableInventoryJSONFailsClosedOnDocumentDrift(t *testing.T) {
	documents := map[string]string{
		"missing-array":       `{}`,
		"null-array":          `{"nftables": null}`,
		"unknown-root":        `{"nftables": [], "unexpected": true}`,
		"missing-metainfo":    `{"nftables": []}`,
		"duplicate-metainfo":  `{"nftables": [{"metainfo": {"json_schema_version": 1}}, {"metainfo": {"json_schema_version": 1}}]}`,
		"unknown-table-field": `{"nftables": [{"metainfo": {"json_schema_version": 1}}, {"table": {"family": "inet", "name": "clean", "unexpected": true}}]}`,
		"unsupported-schema":  `{"nftables": [{"metainfo": {"json_schema_version": 2}}]}`,
		"duplicate-root-key":  `{"nftables": [], "nftables": []}`,
		"duplicate-table-key": `{"nftables": [{"metainfo": {"json_schema_version": 1}}, {"table": {"family": "inet", "family": "ip", "name": "clean"}}]}`,
	}
	for name, document := range documents {
		t.Run(name, func(t *testing.T) {
			if _, err := parseProjectTableInventoryJSON([]byte(document)); err == nil {
				t.Fatalf("drifted nft inventory was accepted: %s", document)
			}
		})
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
	ownedInspections := 0
	exec := CommandExecutor{
		StateDir:   stateDir,
		listTables: staticProjectTables(owner.Table),
		inspectTable: func(_ context.Context, table string) (tableIdentity, error) {
			if table == TableName {
				return tableIdentity{}, nil
			}
			if table != owner.Table {
				t.Fatalf("inspected table %q, want %q", table, owner.Table)
			}
			ownedInspections++
			handle := uint64(73)
			if ownedInspections > 1 {
				handle = 74
			}
			return tableIdentity{Exists: true, Handle: handle, Comment: owner.Marker}, nil
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
	created := false
	exec := CommandExecutor{
		StateDir: stateDir,
		listTables: func(context.Context) ([]string, error) {
			if created {
				return []string{owner.Table}, nil
			}
			return nil, nil
		},
		inspectTable: func(_ context.Context, table string) (tableIdentity, error) {
			if table == TableName {
				return tableIdentity{}, nil
			}
			if table != owner.Table {
				t.Fatalf("inspected table %q, want %q", table, owner.Table)
			}
			if created {
				return tableIdentity{Exists: true, Handle: 75, Comment: owner.Marker}, nil
			}
			return tableIdentity{}, nil
		},
		runScript: func(_ context.Context, script string) error {
			scripts = append(scripts, script)
			created = true
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
		StateDir:   stateDir,
		listTables: staticProjectTables(owner.Table),
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

func TestApplyRequiresReplacementPostcondition(t *testing.T) {
	stateDir := guardTestStateDir(t)
	owner := seedOwnerRecord(t, stateDir)
	exec := CommandExecutor{
		StateDir:   stateDir,
		listTables: staticProjectTables(owner.Table),
		inspectTable: func(_ context.Context, table string) (tableIdentity, error) {
			if table == TableName {
				return tableIdentity{}, nil
			}
			return tableIdentity{Exists: true, Handle: 92, Comment: owner.Marker}, nil
		},
		runScript: func(context.Context, string) error {
			return nil
		},
	}
	err := exec.Apply(t.Context(), BuildNftPlan(&control.State{}))
	if err == nil || !strings.Contains(err.Error(), "retained table handle 92") {
		t.Fatalf("replacement without a new handle was accepted: %v", err)
	}
}

func TestApplyRequiresCreatePostcondition(t *testing.T) {
	stateDir := guardTestStateDir(t)
	owner := seedOwnerRecord(t, stateDir)
	exec := CommandExecutor{
		StateDir:   stateDir,
		listTables: staticProjectTables(),
		inspectTable: func(_ context.Context, table string) (tableIdentity, error) {
			if table == TableName {
				return tableIdentity{}, nil
			}
			if table != owner.Table {
				t.Fatalf("unexpected inspection of %q", table)
			}
			return tableIdentity{}, nil
		},
		runScript: func(context.Context, string) error {
			return nil
		},
	}
	err := exec.Apply(t.Context(), BuildNftPlan(&control.State{}))
	if err == nil || !strings.Contains(err.Error(), "startup guard table is absent") {
		t.Fatalf("create without a visible owned table was accepted: %v", err)
	}
}

func TestApplyDoesNotDeleteUnownedLegacyFixedTable(t *testing.T) {
	stateDir := guardTestStateDir(t)
	plan := BuildNftPlan(&control.State{})
	var scripts []string
	created := false
	exec := CommandExecutor{
		StateDir: stateDir,
		inspectTable: func(_ context.Context, table string) (tableIdentity, error) {
			if table == TableName || !created {
				return tableIdentity{}, nil
			}
			owner, present, err := (CommandExecutor{StateDir: stateDir}).loadOwnerIfPresent()
			if err != nil {
				return tableIdentity{}, err
			}
			if !present || table != owner.Table {
				t.Fatalf("unexpected post-create inspection of %q with owner %#v", table, owner)
			}
			return tableIdentity{Exists: true, Handle: 76, Comment: owner.Marker}, nil
		},
		listTables: func(context.Context) ([]string, error) {
			if created {
				owner, present, err := (CommandExecutor{StateDir: stateDir}).loadOwnerIfPresent()
				if err != nil {
					return nil, err
				}
				if !present {
					return nil, errors.New("owner record missing after create")
				}
				return []string{owner.Table}, nil
			}
			return nil, nil
		},
		runScript: func(_ context.Context, script string) error {
			scripts = append(scripts, script)
			created = true
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
		listTables: func(context.Context) ([]string, error) {
			return nil, nil
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
		listTables: func(context.Context) ([]string, error) {
			return nil, nil
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

func TestOwnerlessProjectTableFailsClosedWithZeroWrite(t *testing.T) {
	for _, operation := range []struct {
		name string
		run  func(context.Context, CommandExecutor) error
	}{
		{
			name: "apply",
			run: func(ctx context.Context, executor CommandExecutor) error {
				return executor.Apply(ctx, BuildNftPlan(&control.State{}))
			},
		},
		{
			name: "cleanup",
			run: func(ctx context.Context, executor CommandExecutor) error {
				return executor.Cleanup(ctx)
			},
		},
	} {
		t.Run(operation.name, func(t *testing.T) {
			stateDir := guardTestStateDir(t)
			orphan := TableName + "_0123456789abcdef0123456789abcdef"
			writes := 0
			executor := CommandExecutor{
				StateDir: stateDir,
				inspectTable: func(_ context.Context, table string) (tableIdentity, error) {
					if table != TableName {
						t.Fatalf("unexpected exact-table inspection of %q", table)
					}
					return tableIdentity{}, nil
				},
				listTables: func(context.Context) ([]string, error) {
					return []string{orphan}, nil
				},
				runScript: func(context.Context, string) error {
					writes++
					return nil
				},
			}
			err := operation.run(t.Context(), executor)
			if err == nil || !strings.Contains(err.Error(), orphan) ||
				!strings.Contains(err.Error(), "without a v2 owner record") {
				t.Fatalf("%s accepted an ownerless project table: %v", operation.name, err)
			}
			if writes != 0 {
				t.Fatalf("%s issued %d writes for an ownerless project table", operation.name, writes)
			}
			if _, statErr := os.Lstat(filepath.Join(stateDir, OwnerRecordFileName)); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("%s created an owner record after orphan detection: %v", operation.name, statErr)
			}
		})
	}
}

func TestOwnerRecordWithUnexpectedProjectTablesFailsClosedWithZeroWrite(t *testing.T) {
	operations := []struct {
		name string
		run  func(context.Context, CommandExecutor) error
	}{
		{
			name: "apply",
			run: func(ctx context.Context, executor CommandExecutor) error {
				return executor.Apply(ctx, BuildNftPlan(&control.State{}))
			},
		},
		{
			name: "cleanup",
			run: func(ctx context.Context, executor CommandExecutor) error {
				return executor.Cleanup(ctx)
			},
		},
	}
	for _, ownerTableListed := range []bool{false, true} {
		listedState := "owner-table-missing"
		if ownerTableListed {
			listedState = "owner-table-present"
		}
		for _, operation := range operations {
			t.Run(operation.name+"/"+listedState, func(t *testing.T) {
				stateDir := guardTestStateDir(t)
				owner := seedOwnerRecord(t, stateDir)
				orphan := TableName + "_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
				tables := []string{orphan}
				if ownerTableListed {
					tables = []string{owner.Table, orphan}
				}
				inventoryCalls := 0
				ownedInspections := 0
				writes := 0
				executor := CommandExecutor{
					StateDir: stateDir,
					inspectTable: func(_ context.Context, table string) (tableIdentity, error) {
						if table == TableName {
							return tableIdentity{}, nil
						}
						ownedInspections++
						return tableIdentity{}, nil
					},
					listTables: func(context.Context) ([]string, error) {
						inventoryCalls++
						return append([]string(nil), tables...), nil
					},
					runScript: func(context.Context, string) error {
						writes++
						return nil
					},
				}

				err := operation.run(t.Context(), executor)
				if err == nil || !strings.Contains(err.Error(), orphan) ||
					!strings.Contains(err.Error(), owner.Table) ||
					!strings.Contains(err.Error(), "refusing mutation") {
					t.Fatalf("%s accepted unexpected project tables %v: %v", operation.name, tables, err)
				}
				if inventoryCalls != 1 {
					t.Fatalf("%s inventory calls = %d, want 1", operation.name, inventoryCalls)
				}
				if ownedInspections != 0 {
					t.Fatalf("%s inspected the owned table %d times after inventory mismatch", operation.name, ownedInspections)
				}
				if writes != 0 {
					t.Fatalf("%s issued %d writes for unexpected project tables", operation.name, writes)
				}
			})
		}
	}
}

func TestProjectTableInventoryErrorBeforeMutationIsZeroWrite(t *testing.T) {
	inventoryErr := errors.New("simulated inventory failure")
	operations := []struct {
		name string
		run  func(context.Context, CommandExecutor) error
	}{
		{
			name: "apply",
			run: func(ctx context.Context, executor CommandExecutor) error {
				return executor.Apply(ctx, BuildNftPlan(&control.State{}))
			},
		},
		{
			name: "cleanup",
			run: func(ctx context.Context, executor CommandExecutor) error {
				return executor.Cleanup(ctx)
			},
		},
	}
	for _, ownerPresent := range []bool{false, true} {
		ownerState := "owner-absent"
		if ownerPresent {
			ownerState = "owner-present"
		}
		for _, operation := range operations {
			t.Run(operation.name+"/"+ownerState, func(t *testing.T) {
				stateDir := guardTestStateDir(t)
				if ownerPresent {
					seedOwnerRecord(t, stateDir)
				}
				writes := 0
				executor := CommandExecutor{
					StateDir: stateDir,
					inspectTable: func(_ context.Context, table string) (tableIdentity, error) {
						if table != TableName {
							t.Fatalf("unexpected owned-table inspection of %q", table)
						}
						return tableIdentity{}, nil
					},
					listTables: func(context.Context) ([]string, error) {
						return nil, inventoryErr
					},
					runScript: func(context.Context, string) error {
						writes++
						return nil
					},
				}

				err := operation.run(t.Context(), executor)
				if !errors.Is(err, inventoryErr) ||
					!strings.Contains(err.Error(), "before mutation") {
					t.Fatalf("%s did not preserve the inventory error: %v", operation.name, err)
				}
				if writes != 0 {
					t.Fatalf("%s issued %d writes after an inventory error", operation.name, writes)
				}
				if !ownerPresent {
					if _, statErr := os.Lstat(filepath.Join(stateDir, OwnerRecordFileName)); !errors.Is(statErr, os.ErrNotExist) {
						t.Fatalf("%s created an owner record after an inventory error: %v", operation.name, statErr)
					}
				}
			})
		}
	}
}

func TestProjectTableInventoryPostconditionsFailClosed(t *testing.T) {
	inventoryErr := errors.New("simulated postcondition inventory failure")
	for _, operation := range []string{"apply", "cleanup"} {
		for _, postcondition := range []string{"unexpected-table", "inventory-error"} {
			t.Run(operation+"/"+postcondition, func(t *testing.T) {
				stateDir := guardTestStateDir(t)
				owner := seedOwnerRecord(t, stateDir)
				orphan := TableName + "_cccccccccccccccccccccccccccccccc"
				mutated := false
				inventoryCalls := 0
				writes := 0
				executor := CommandExecutor{
					StateDir: stateDir,
					inspectTable: func(_ context.Context, table string) (tableIdentity, error) {
						if table == TableName {
							return tableIdentity{}, nil
						}
						if table != owner.Table {
							t.Fatalf("inspected table %q, want %q", table, owner.Table)
						}
						if operation == "cleanup" && mutated {
							return tableIdentity{}, nil
						}
						handle := uint64(81)
						if mutated {
							handle = 82
						}
						return tableIdentity{Exists: true, Handle: handle, Comment: owner.Marker}, nil
					},
					listTables: func(context.Context) ([]string, error) {
						inventoryCalls++
						if !mutated {
							return []string{owner.Table}, nil
						}
						if postcondition == "inventory-error" {
							return nil, inventoryErr
						}
						if operation == "apply" {
							return []string{owner.Table, orphan}, nil
						}
						return []string{orphan}, nil
					},
					runScript: func(context.Context, string) error {
						writes++
						mutated = true
						return nil
					},
				}

				var err error
				if operation == "apply" {
					err = executor.Apply(t.Context(), BuildNftPlan(&control.State{}))
				} else {
					err = executor.Cleanup(t.Context())
				}
				if err == nil {
					t.Fatalf("%s accepted failed %s postcondition", operation, postcondition)
				}
				if postcondition == "inventory-error" && !errors.Is(err, inventoryErr) {
					t.Fatalf("%s did not preserve postcondition inventory error: %v", operation, err)
				}
				if postcondition == "unexpected-table" && !strings.Contains(err.Error(), orphan) {
					t.Fatalf("%s did not report unexpected postcondition table: %v", operation, err)
				}
				if !strings.Contains(err.Error(), "verify") {
					t.Fatalf("%s postcondition error lacks verification context: %v", operation, err)
				}
				if inventoryCalls != 2 {
					t.Fatalf("%s inventory calls = %d, want 2", operation, inventoryCalls)
				}
				if writes != 1 {
					t.Fatalf("%s writes = %d, want 1 completed transaction", operation, writes)
				}
			})
		}
	}
}

func TestOwnerlessCleanupRechecksEmptyPostcondition(t *testing.T) {
	stateDir := guardTestStateDir(t)
	orphan := TableName + "_dddddddddddddddddddddddddddddddd"
	inventoryCalls := 0
	executor := CommandExecutor{
		StateDir: stateDir,
		inspectTable: func(_ context.Context, table string) (tableIdentity, error) {
			if table != TableName {
				t.Fatalf("unexpected inspection of %q", table)
			}
			return tableIdentity{}, nil
		},
		listTables: func(context.Context) ([]string, error) {
			inventoryCalls++
			if inventoryCalls == 1 {
				return nil, nil
			}
			return []string{orphan}, nil
		},
		runScript: func(context.Context, string) error {
			t.Fatal("ownerless cleanup issued an nft write")
			return nil
		},
	}
	err := executor.Cleanup(t.Context())
	if err == nil || !strings.Contains(err.Error(), orphan) ||
		!strings.Contains(err.Error(), "verify ownerless") {
		t.Fatalf("ownerless cleanup accepted a non-empty postcondition: %v", err)
	}
	if inventoryCalls != 2 {
		t.Fatalf("ownerless cleanup inventory calls = %d, want 2", inventoryCalls)
	}
}

func TestCleanupAllowsMissingFinalStateDirectoryUnderTrustedParent(t *testing.T) {
	stateDir := filepath.Join(guardTestStateDir(t), "missing-final")
	exec := CommandExecutor{
		StateDir: stateDir,
		inspectTable: func(_ context.Context, table string) (tableIdentity, error) {
			if table != TableName {
				t.Fatalf("unexpected inspection of %q", table)
			}
			return tableIdentity{}, nil
		},
		listTables: func(context.Context) ([]string, error) {
			return nil, nil
		},
		runScript: func(context.Context, string) error {
			t.Fatal("cleanup with no owner issued an nft write")
			return nil
		},
	}
	if err := exec.Cleanup(t.Context()); err != nil {
		t.Fatalf("trusted missing final state directory should be an idempotent no-op: %v", err)
	}
}

func TestCleanupRejectsMissingIntermediateStateDirectory(t *testing.T) {
	stateDir := filepath.Join(guardTestStateDir(t), "missing-parent", "state")
	exec := CommandExecutor{
		StateDir: stateDir,
		inspectTable: func(_ context.Context, table string) (tableIdentity, error) {
			if table != TableName {
				t.Fatalf("unexpected inspection of %q", table)
			}
			return tableIdentity{}, nil
		},
		runScript: func(context.Context, string) error {
			t.Fatal("ambiguous missing ancestry issued an nft write")
			return nil
		},
	}
	err := exec.Cleanup(t.Context())
	if err == nil || !strings.Contains(err.Error(), "intermediate") {
		t.Fatalf("missing intermediate ancestry must fail closed, got %v", err)
	}
}

func TestCleanupRejectsOwnerHiddenThroughNewlyWritableAncestor(t *testing.T) {
	parent := guardTestStateDir(t)
	stateDir := filepath.Join(parent, "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	seedOwnerRecord(t, stateDir)
	if err := os.Rename(stateDir, filepath.Join(parent, "state-hidden")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o777); err != nil {
		t.Fatal(err)
	}
	exec := CommandExecutor{
		StateDir: stateDir,
		inspectTable: func(_ context.Context, table string) (tableIdentity, error) {
			if table != TableName {
				t.Fatalf("unexpected inspection of %q", table)
			}
			return tableIdentity{}, nil
		},
		runScript: func(context.Context, string) error {
			t.Fatal("hidden owner record issued an nft write")
			return nil
		},
	}
	err := exec.Cleanup(t.Context())
	if err == nil || !strings.Contains(err.Error(), "ancestor") {
		t.Fatalf("cleanup must not treat a hidden owner record as absent, got %v", err)
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
		StateDir:   stateDir,
		listTables: staticProjectTables(owner.Table),
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
		StateDir:   stateDir,
		listTables: staticProjectTables(owner.Table),
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
	deleted := false
	exec := CommandExecutor{
		StateDir: stateDir,
		listTables: func(context.Context) ([]string, error) {
			if deleted {
				return nil, nil
			}
			return []string{owner.Table}, nil
		},
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
			deleted = true
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

func TestCleanupReportsDeleteFailureWhenTableDisappears(t *testing.T) {
	stateDir := guardTestStateDir(t)
	owner := seedOwnerRecord(t, stateDir)
	inspections := 0
	exec := CommandExecutor{
		StateDir:   stateDir,
		listTables: staticProjectTables(owner.Table),
		inspectTable: func(_ context.Context, table string) (tableIdentity, error) {
			inspections++
			switch inspections {
			case 1:
				if table != TableName {
					t.Fatalf("first inspection = %q, want legacy table", table)
				}
				return tableIdentity{}, nil
			case 2:
				if table != owner.Table {
					t.Fatalf("second inspection = %q, want owned table %q", table, owner.Table)
				}
				return tableIdentity{Exists: true, Handle: 61, Comment: owner.Marker}, nil
			case 3:
				if table != owner.Table {
					t.Fatalf("third inspection = %q, want owned table %q", table, owner.Table)
				}
				return tableIdentity{}, nil
			default:
				t.Fatalf("unexpected inspection %d of %q", inspections, table)
				return tableIdentity{}, nil
			}
		},
		runScript: func(context.Context, string) error {
			return errors.New("simulated nft transaction failure")
		},
	}
	err := exec.Cleanup(t.Context())
	if err == nil || !strings.Contains(err.Error(), "simulated nft transaction failure") {
		t.Fatalf("cleanup hid a failed nft transaction after the table disappeared: %v", err)
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

func staticProjectTables(tables ...string) func(context.Context) ([]string, error) {
	return func(context.Context) ([]string, error) {
		return append([]string(nil), tables...), nil
	}
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
