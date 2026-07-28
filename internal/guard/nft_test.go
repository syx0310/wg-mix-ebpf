package guard

import (
	"strings"
	"testing"

	"github.com/syx0310/wg-mix-ebpf/internal/control"
)

func TestBuildNftPlan(t *testing.T) {
	plan := BuildNftPlan(&control.State{
		WireGuards: []control.WireGuardState{
			{Name: "wg0", ConfigFwMark: 0x10000002, RuntimeFirewallMark: 0x10000003, ConfigListenPort: 31001},
			{Name: "wg1", ConfigFwMark: 0x10000002, RuntimeFirewallMark: 0x10000003},
		},
	}, 0x10000004, 0)
	if len(plan.Rules) != 4 {
		t.Fatalf("rules = %d, want 4: %#v", len(plan.Rules), plan.Rules)
	}
	joined := strings.Join(plan.Rules, "\n")
	for _, mark := range []string{"0x10000002", "0x10000003", "0x10000004"} {
		if !strings.Contains(joined, "meta mark "+mark) {
			t.Fatalf("missing fwmark %s rule: %s", mark, joined)
		}
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

func TestReplacementScriptDeletesAndAddsInOneBatch(t *testing.T) {
	plan := NftPlan{
		Table: TableName,
		Rules: []string{"add rule inet wg_mix_ebpf_guard output counter drop"},
	}
	script := plan.ReplacementScript()
	deleteAt := strings.Index(script, "delete table inet wg_mix_ebpf_guard")
	addAt := strings.Index(script, "add table inet wg_mix_ebpf_guard")
	if deleteAt < 0 || addAt < 0 || deleteAt > addAt {
		t.Fatalf("replacement must delete then add in one script:\n%s", script)
	}
}

func TestBuildNftPlanDoesNotEmbedWireGuardNameInComment(t *testing.T) {
	const untrustedName = "wg0\"; delete table inet important; #"
	plan := BuildNftPlan(&control.State{
		WireGuards: []control.WireGuardState{
			{Name: untrustedName, ConfigFwMark: 0x10000002, ConfigListenPort: 31001},
		},
	})
	if strings.Contains(plan.Script(), untrustedName) {
		t.Fatalf("script contains untrusted WireGuard name:\n%s", plan.Script())
	}
}
