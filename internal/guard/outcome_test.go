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

func TestObservationWireValues(t *testing.T) {
	want := map[Observation]string{
		ObservationUnchanged: "unchanged",
		ObservationActive:    "active",
		ObservationAbsent:    "absent",
		ObservationUnknown:   "unknown",
	}
	for observation, value := range want {
		if string(observation) != value {
			t.Fatalf("observation %q = %q, want %q", observation, string(observation), value)
		}
	}
}

func TestCommandExecutorObserveCrossChecksOwnerAndCompleteInventory(t *testing.T) {
	tests := []struct {
		name         string
		ownerPresent bool
		legacy       bool
		ownedState   string
		inventory    string
		want         Observation
		wantError    string
	}{
		{
			name:      "ownerless-absent",
			inventory: "empty",
			want:      ObservationAbsent,
		},
		{
			name:         "exact-owned-active",
			ownerPresent: true,
			ownedState:   "active",
			inventory:    "owner",
			want:         ObservationActive,
		},
		{
			name:         "owned-absent",
			ownerPresent: true,
			ownedState:   "absent",
			inventory:    "empty",
			want:         ObservationAbsent,
		},
		{
			name:      "ownerless-project-table",
			inventory: "orphan",
			want:      ObservationUnknown,
			wantError: "without a v2 owner record",
		},
		{
			name:      "legacy-table",
			legacy:    true,
			inventory: "legacy",
			want:      ObservationUnknown,
			wantError: "legacy startup guard table",
		},
		{
			name:         "foreign-owned-marker",
			ownerPresent: true,
			ownedState:   "foreign",
			inventory:    "owner",
			want:         ObservationUnknown,
			wantError:    "ownership marker",
		},
		{
			name:         "active-with-extra-project-table",
			ownerPresent: true,
			ownedState:   "active",
			inventory:    "owner-and-orphan",
			want:         ObservationUnknown,
			wantError:    "complete project table inventory",
		},
		{
			name:         "absent-but-inventory-lists-owner",
			ownerPresent: true,
			ownedState:   "absent",
			inventory:    "owner",
			want:         ObservationUnknown,
			wantError:    "is absent but complete project table inventory",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stateDir := guardTestStateDir(t)
			var owner ownerRecord
			if test.ownerPresent {
				owner = seedOwnerRecord(t, stateDir)
			}
			orphan := TableName + "_ffffffffffffffffffffffffffffffff"
			writes := 0
			inventoryCalls := 0
			executor := CommandExecutor{
				StateDir: stateDir,
				inspectTable: func(_ context.Context, table string) (tableIdentity, error) {
					if table == TableName {
						if test.legacy {
							return tableIdentity{Exists: true, Handle: 11, Comment: "legacy"}, nil
						}
						return tableIdentity{}, nil
					}
					if !test.ownerPresent || table != owner.Table {
						t.Fatalf("unexpected exact-table inspection of %q", table)
					}
					switch test.ownedState {
					case "active":
						return tableIdentity{Exists: true, Handle: 41, Comment: owner.Marker}, nil
					case "foreign":
						return tableIdentity{Exists: true, Handle: 41, Comment: "foreign"}, nil
					case "absent":
						return tableIdentity{}, nil
					default:
						t.Fatalf("unexpected owned state %q", test.ownedState)
						return tableIdentity{}, nil
					}
				},
				listTables: func(context.Context) ([]string, error) {
					inventoryCalls++
					switch test.inventory {
					case "empty":
						return nil, nil
					case "owner":
						return []string{owner.Table}, nil
					case "orphan":
						return []string{orphan}, nil
					case "legacy":
						return []string{TableName}, nil
					case "owner-and-orphan":
						return []string{owner.Table, orphan}, nil
					default:
						t.Fatalf("unexpected inventory %q", test.inventory)
						return nil, nil
					}
				},
				runScript: func(context.Context, string) error {
					writes++
					return nil
				},
			}

			outcome, err := executor.Observe(t.Context())
			if outcome.Observation != test.want || outcome.Mutated || outcome.Warning != nil {
				t.Fatalf("Observe outcome = %#v, want observation %q without mutation/warning", outcome, test.want)
			}
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("Observe returned error: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("Observe error = %v, want substring %q", err, test.wantError)
			}
			if inventoryCalls != 1 {
				t.Fatalf("inventory calls = %d, want 1 complete inventory", inventoryCalls)
			}
			if writes != 0 {
				t.Fatalf("Observe issued %d mutation commands", writes)
			}
		})
	}
}

func TestCommandExecutorObservePreservesIndependentEvidenceErrors(t *testing.T) {
	stateDir := guardTestStateDir(t)
	owner := seedOwnerRecord(t, stateDir)
	inspectErr := errors.New("exact table inspection failed")
	inventoryErr := errors.New("complete inventory failed")
	executor := CommandExecutor{
		StateDir: stateDir,
		inspectTable: func(_ context.Context, table string) (tableIdentity, error) {
			if table == TableName {
				return tableIdentity{}, nil
			}
			if table != owner.Table {
				t.Fatalf("inspected table %q, want %q", table, owner.Table)
			}
			return tableIdentity{}, inspectErr
		},
		listTables: func(context.Context) ([]string, error) {
			return nil, inventoryErr
		},
		runScript: func(context.Context, string) error {
			t.Fatal("Observe issued an nft mutation")
			return nil
		},
	}

	outcome, err := executor.Observe(t.Context())
	if outcome.Observation != ObservationUnknown || outcome.Mutated || outcome.Warning != nil {
		t.Fatalf("Observe outcome = %#v, want read-only unknown", outcome)
	}
	if !errors.Is(err, inspectErr) || !errors.Is(err, inventoryErr) {
		t.Fatalf("Observe did not preserve both evidence errors: %v", err)
	}
}

func TestCommandExecutorObserveDoesNotCreateMissingStateDirectory(t *testing.T) {
	stateDir := filepath.Join(guardTestStateDir(t), "missing-state")
	writes := 0
	executor := CommandExecutor{
		StateDir: stateDir,
		inspectTable: func(context.Context, string) (tableIdentity, error) {
			return tableIdentity{}, nil
		},
		listTables: func(context.Context) ([]string, error) {
			return nil, nil
		},
		runScript: func(context.Context, string) error {
			writes++
			return nil
		},
	}

	outcome, err := executor.Observe(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Observation != ObservationAbsent || outcome.Mutated || outcome.Warning != nil {
		t.Fatalf("Observe outcome = %#v, want read-only absent", outcome)
	}
	if writes != 0 {
		t.Fatalf("Observe issued %d mutation commands", writes)
	}
	if _, statErr := os.Lstat(stateDir); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("Observe created or altered missing state directory %s: %v", stateDir, statErr)
	}
}

func TestApplyTypedOutcomeAfterMutationAttempt(t *testing.T) {
	tests := []struct {
		name        string
		runFails    bool
		after       string
		want        Observation
		wantHardErr bool
	}{
		{name: "success-active", after: "active", want: ObservationActive},
		{name: "failed-command-active", runFails: true, after: "active", want: ObservationActive, wantHardErr: true},
		{name: "failed-command-absent", runFails: true, after: "absent", want: ObservationAbsent, wantHardErr: true},
		{name: "failed-command-unknown", runFails: true, after: "orphan", want: ObservationUnknown, wantHardErr: true},
		{name: "successful-command-absent", after: "absent", want: ObservationAbsent, wantHardErr: true},
		{name: "successful-command-unknown", after: "orphan", want: ObservationUnknown, wantHardErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stateDir := guardTestStateDir(t)
			owner := seedOwnerRecord(t, stateDir)
			mutationAttempted := false
			commandErr := errors.New("apply command failed")
			orphan := TableName + "_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
			executor := CommandExecutor{
				StateDir: stateDir,
				inspectTable: func(_ context.Context, table string) (tableIdentity, error) {
					if table == TableName {
						return tableIdentity{}, nil
					}
					if table != owner.Table {
						t.Fatalf("inspected table %q, want %q", table, owner.Table)
					}
					if !mutationAttempted || test.after == "absent" || test.after == "orphan" {
						return tableIdentity{}, nil
					}
					return tableIdentity{Exists: true, Handle: 71, Comment: owner.Marker}, nil
				},
				listTables: func(context.Context) ([]string, error) {
					if !mutationAttempted {
						return nil, nil
					}
					switch test.after {
					case "active":
						return []string{owner.Table}, nil
					case "absent":
						return nil, nil
					case "orphan":
						return []string{orphan}, nil
					default:
						t.Fatalf("unexpected poststate %q", test.after)
						return nil, nil
					}
				},
				runScript: func(context.Context, string) error {
					mutationAttempted = true
					if test.runFails {
						return commandErr
					}
					return nil
				},
			}

			outcome, err := executor.Apply(t.Context(), BuildNftPlan(&control.State{}))
			if outcome.Observation != test.want || !outcome.Mutated || outcome.Warning != nil {
				t.Fatalf("Apply outcome = %#v, want %q mutation without warning", outcome, test.want)
			}
			if test.wantHardErr != (err != nil) {
				t.Fatalf("Apply error = %v, wantHardErr=%t", err, test.wantHardErr)
			}
			if test.runFails && !errors.Is(err, commandErr) {
				t.Fatalf("Apply did not preserve command error: %v", err)
			}
			if test.after == "orphan" && (err == nil || !strings.Contains(err.Error(), orphan)) {
				t.Fatalf("Apply did not preserve full-inventory mismatch: %v", err)
			}
		})
	}
}

func TestApplyPreflightErrorIsTypedUnchanged(t *testing.T) {
	preflightErr := errors.New("inventory unavailable before mutation")
	writes := 0
	executor := CommandExecutor{
		StateDir: guardTestStateDir(t),
		inspectTable: func(context.Context, string) (tableIdentity, error) {
			return tableIdentity{}, nil
		},
		listTables: func(context.Context) ([]string, error) {
			return nil, preflightErr
		},
		runScript: func(context.Context, string) error {
			writes++
			return nil
		},
	}

	outcome, err := executor.Apply(t.Context(), BuildNftPlan(&control.State{}))
	if outcome.Observation != ObservationUnchanged || outcome.Mutated || outcome.Warning != nil {
		t.Fatalf("Apply outcome = %#v, want unchanged preflight failure", outcome)
	}
	if !errors.Is(err, preflightErr) || writes != 0 {
		t.Fatalf("Apply preflight result err=%v writes=%d", err, writes)
	}
}

func TestCleanupPreflightErrorIsTypedUnchanged(t *testing.T) {
	stateDir := guardTestStateDir(t)
	owner := seedOwnerRecord(t, stateDir)
	preflightErr := errors.New("cleanup inventory unavailable before mutation")
	writes := 0
	executor := CommandExecutor{
		StateDir: stateDir,
		inspectTable: func(_ context.Context, table string) (tableIdentity, error) {
			if table == TableName {
				return tableIdentity{}, nil
			}
			if table != owner.Table {
				t.Fatalf("unexpected exact table inspection %q", table)
			}
			return tableIdentity{Exists: true, Handle: 79, Comment: owner.Marker}, nil
		},
		listTables: func(context.Context) ([]string, error) {
			return nil, preflightErr
		},
		runScript: func(context.Context, string) error {
			writes++
			return nil
		},
	}

	outcome, err := executor.Cleanup(t.Context())
	if outcome.Observation != ObservationUnchanged || outcome.Mutated || outcome.Warning != nil {
		t.Fatalf("Cleanup outcome = %#v, want unchanged preflight failure", outcome)
	}
	if !errors.Is(err, preflightErr) || writes != 0 {
		t.Fatalf("Cleanup preflight result err=%v writes=%d", err, writes)
	}
}

func TestCleanupTypedOutcomeAfterMutationAttempt(t *testing.T) {
	tests := []struct {
		name        string
		runFails    bool
		after       string
		want        Observation
		wantHardErr bool
		wantWarning bool
	}{
		{name: "success-absent", after: "absent", want: ObservationAbsent},
		{name: "failed-command-but-proved-absent", runFails: true, after: "absent", want: ObservationAbsent, wantWarning: true},
		{name: "failed-command-active", runFails: true, after: "active", want: ObservationActive, wantHardErr: true},
		{name: "successful-command-active", after: "active", want: ObservationActive, wantHardErr: true},
		{name: "failed-command-owner-absent-but-orphan-remains", runFails: true, after: "orphan", want: ObservationUnknown, wantHardErr: true},
		{name: "failed-command-foreign-owner", runFails: true, after: "foreign", want: ObservationUnknown, wantHardErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stateDir := guardTestStateDir(t)
			owner := seedOwnerRecord(t, stateDir)
			mutationAttempted := false
			commandErr := errors.New("cleanup command failed")
			orphan := TableName + "_dddddddddddddddddddddddddddddddd"
			inventoryCalls := 0
			exactInspections := 0
			executor := CommandExecutor{
				StateDir: stateDir,
				inspectTable: func(_ context.Context, table string) (tableIdentity, error) {
					if table == TableName {
						return tableIdentity{}, nil
					}
					if table != owner.Table {
						t.Fatalf("inspected table %q, want %q", table, owner.Table)
					}
					exactInspections++
					if !mutationAttempted || test.after == "active" {
						return tableIdentity{Exists: true, Handle: 81, Comment: owner.Marker}, nil
					}
					if test.after == "foreign" {
						return tableIdentity{Exists: true, Handle: 82, Comment: "foreign"}, nil
					}
					return tableIdentity{}, nil
				},
				listTables: func(context.Context) ([]string, error) {
					inventoryCalls++
					if !mutationAttempted {
						return []string{owner.Table}, nil
					}
					switch test.after {
					case "absent":
						return nil, nil
					case "active", "foreign":
						return []string{owner.Table}, nil
					case "orphan":
						return []string{orphan}, nil
					default:
						t.Fatalf("unexpected poststate %q", test.after)
						return nil, nil
					}
				},
				runScript: func(context.Context, string) error {
					mutationAttempted = true
					if test.runFails {
						return commandErr
					}
					return nil
				},
			}

			outcome, err := executor.Cleanup(t.Context())
			if outcome.Observation != test.want || !outcome.Mutated {
				t.Fatalf("Cleanup outcome = %#v, want %q mutation", outcome, test.want)
			}
			if test.wantHardErr != (err != nil) {
				t.Fatalf("Cleanup error = %v, wantHardErr=%t", err, test.wantHardErr)
			}
			if test.wantWarning {
				if err != nil || !errors.Is(outcome.Warning, commandErr) {
					t.Fatalf("Cleanup warning/error = %v / %v, want preserved command warning", outcome.Warning, err)
				}
			} else {
				if outcome.Warning != nil {
					t.Fatalf("Cleanup unexpectedly returned warning: %v", outcome.Warning)
				}
				if test.runFails && !errors.Is(err, commandErr) {
					t.Fatalf("Cleanup did not preserve command error: %v", err)
				}
			}
			if test.after == "orphan" && (err == nil || !strings.Contains(err.Error(), orphan)) {
				t.Fatalf("Cleanup did not preserve full inventory mismatch: %v", err)
			}
			if test.after == "foreign" && (err == nil || !strings.Contains(err.Error(), "ownership marker")) {
				t.Fatalf("Cleanup did not preserve exact-owner mismatch: %v", err)
			}
			if inventoryCalls != 2 || exactInspections != 2 {
				t.Fatalf("Cleanup evidence calls inventory=%d exact-inspect=%d, want 2/2", inventoryCalls, exactInspections)
			}
		})
	}
}

func TestCleanupFailedCommandPreservesAllUnknownEvidenceErrors(t *testing.T) {
	stateDir := guardTestStateDir(t)
	owner := seedOwnerRecord(t, stateDir)
	commandErr := errors.New("cleanup command failed")
	inspectErr := errors.New("post-cleanup exact inspection failed")
	inventoryErr := errors.New("post-cleanup inventory failed")
	mutationAttempted := false
	executor := CommandExecutor{
		StateDir: stateDir,
		inspectTable: func(_ context.Context, table string) (tableIdentity, error) {
			if table == TableName {
				return tableIdentity{}, nil
			}
			if table != owner.Table {
				t.Fatalf("inspected table %q, want %q", table, owner.Table)
			}
			if mutationAttempted {
				return tableIdentity{}, inspectErr
			}
			return tableIdentity{Exists: true, Handle: 91, Comment: owner.Marker}, nil
		},
		listTables: func(context.Context) ([]string, error) {
			if mutationAttempted {
				return nil, inventoryErr
			}
			return []string{owner.Table}, nil
		},
		runScript: func(context.Context, string) error {
			mutationAttempted = true
			return commandErr
		},
	}

	outcome, err := executor.Cleanup(t.Context())
	if outcome.Observation != ObservationUnknown || !outcome.Mutated || outcome.Warning != nil {
		t.Fatalf("Cleanup outcome = %#v, want mutated unknown without warning", outcome)
	}
	if !errors.Is(err, commandErr) || !errors.Is(err, inspectErr) || !errors.Is(err, inventoryErr) {
		t.Fatalf("Cleanup did not preserve all independent errors: %v", err)
	}
}

func TestCleanupAlreadyAbsentDoesNotReportMutation(t *testing.T) {
	stateDir := guardTestStateDir(t)
	owner := seedOwnerRecord(t, stateDir)
	writes := 0
	executor := CommandExecutor{
		StateDir: stateDir,
		inspectTable: func(_ context.Context, table string) (tableIdentity, error) {
			if table != TableName && table != owner.Table {
				t.Fatalf("unexpected table inspection %q", table)
			}
			return tableIdentity{}, nil
		},
		listTables: func(context.Context) ([]string, error) {
			return nil, nil
		},
		runScript: func(context.Context, string) error {
			writes++
			return nil
		},
	}

	outcome, err := executor.Cleanup(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Observation != ObservationAbsent || outcome.Mutated || outcome.Warning != nil {
		t.Fatalf("Cleanup outcome = %#v, want already absent without mutation", outcome)
	}
	if writes != 0 {
		t.Fatalf("already-absent cleanup issued %d mutation commands", writes)
	}
}
