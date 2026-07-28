package guard

import (
	"context"
	"errors"
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
	if !strings.HasPrefix(exec.AppliedScript, "delete table inet "+TableName+"\n") {
		t.Fatalf("dry-run should show atomic replacement first: %s", exec.AppliedScript)
	}
	if strings.Contains(exec.FallbackScript, "delete table") {
		t.Fatalf("fallback should be create-only: %s", exec.FallbackScript)
	}
	if err := exec.Cleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(exec.CleanupScript, "delete table inet wg_mix_ebpf_guard") {
		t.Fatalf("missing cleanup script: %s", exec.CleanupScript)
	}
}

func TestMissingGuardTableErrorIsIdempotent(t *testing.T) {
	err := errors.New("nft -f - failed: Error: Could not process rule: No such file or directory; delete table inet wg_mix_ebpf_guard")
	if !isMissingGuardTable(err) {
		t.Fatal("expected missing guard table error to be treated as idempotent")
	}
}

func TestMissingNftBinaryCleanupFails(t *testing.T) {
	exec := CommandExecutor{Binary: filepath.Join(t.TempDir(), "missing-nft")}
	if err := exec.Cleanup(t.Context()); err == nil {
		t.Fatal("missing nft binary must not report successful guard cleanup")
	}
}

func TestApplyReplacesExistingTableInSingleTransaction(t *testing.T) {
	plan := BuildNftPlan(&control.State{})
	var scripts []string
	exec := CommandExecutor{
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
	if !strings.HasPrefix(scripts[0], CleanupScript()) || !strings.Contains(scripts[0], "add table inet "+TableName) {
		t.Fatalf("expected delete+add transaction, got:\n%s", scripts[0])
	}
}

func TestApplyFallsBackToCreateOnlyWhenTableIsMissing(t *testing.T) {
	plan := BuildNftPlan(&control.State{})
	var scripts []string
	exec := CommandExecutor{
		runScript: func(_ context.Context, script string) error {
			scripts = append(scripts, script)
			if len(scripts) == 1 {
				return errors.New("Error: No such file or directory; delete table inet " + TableName)
			}
			return nil
		},
	}
	if err := exec.Apply(t.Context(), plan); err != nil {
		t.Fatal(err)
	}
	if len(scripts) != 2 {
		t.Fatalf("nft invocations = %d, want 2: %#v", len(scripts), scripts)
	}
	if !strings.HasPrefix(scripts[0], CleanupScript()) {
		t.Fatalf("first script should be atomic replacement:\n%s", scripts[0])
	}
	if strings.Contains(scripts[1], "delete table") || !strings.HasPrefix(scripts[1], "add table inet "+TableName) {
		t.Fatalf("fallback should be create-only:\n%s", scripts[1])
	}
}

func TestApplyDoesNotFallbackOnInvalidReplacement(t *testing.T) {
	plan := BuildNftPlan(&control.State{})
	var scripts []string
	exec := CommandExecutor{
		runScript: func(_ context.Context, script string) error {
			scripts = append(scripts, script)
			return errors.New("Error: syntax error, unexpected drop")
		},
	}
	err := exec.Apply(t.Context(), plan)
	if err == nil || !strings.Contains(err.Error(), "replace startup guard atomically") {
		t.Fatalf("expected atomic replacement error, got %v", err)
	}
	if len(scripts) != 1 {
		t.Fatalf("invalid replacement must not trigger fallback; invocations=%d", len(scripts))
	}
}
