package guard

import (
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
	if !strings.Contains(exec.CleanupScript, "destroy table inet wg_mix_ebpf_guard") {
		t.Fatalf("missing cleanup script: %s", exec.CleanupScript)
	}
}
