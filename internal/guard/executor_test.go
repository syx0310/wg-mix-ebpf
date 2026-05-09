package guard

import (
	"errors"
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
