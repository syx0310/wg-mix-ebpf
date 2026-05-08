package guard

import (
	"strings"
	"testing"

	"github.com/syx0310/wg-mix-ebpf/internal/control"
)

func TestBuildNftPlan(t *testing.T) {
	plan := BuildNftPlan(&control.State{
		WireGuards: []control.WireGuardState{
			{Name: "wg0", ConfigFwMark: 0x10000002, ConfigListenPort: 31001},
			{Name: "wg1", ConfigFwMark: 0x10000002},
		},
	})
	if len(plan.Rules) != 2 {
		t.Fatalf("rules = %d, want 2: %#v", len(plan.Rules), plan.Rules)
	}
	joined := strings.Join(plan.Rules, "\n")
	if !strings.Contains(joined, "meta mark 0x10000002") {
		t.Fatalf("missing fwmark rule: %s", joined)
	}
	if !strings.Contains(joined, "udp dport 31001") {
		t.Fatalf("missing listen port rule: %s", joined)
	}
}

func TestNftScript(t *testing.T) {
	plan := NftPlan{
		Table: TableName,
		Rules: []string{"add rule inet wg_mix_ebpf_guard output counter drop"},
	}
	script := plan.Script()
	for _, want := range []string{
		"destroy table inet wg_mix_ebpf_guard",
		"add table inet wg_mix_ebpf_guard",
		"add chain inet wg_mix_ebpf_guard output",
		"add chain inet wg_mix_ebpf_guard input",
		"add rule inet wg_mix_ebpf_guard output counter drop",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("script missing %q:\n%s", want, script)
		}
	}
}
