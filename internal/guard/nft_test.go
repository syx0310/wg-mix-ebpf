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
		"create table inet " + planTablePlaceholder,
		"add chain inet " + planTablePlaceholder + " output",
		"add chain inet " + planTablePlaceholder + " input",
		"add rule inet " + planTablePlaceholder + " output counter drop",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("script missing %q:\n%s", want, script)
		}
	}
}

func TestReplacementScriptIsNonExecutableOwnershipTemplate(t *testing.T) {
	plan := NftPlan{
		Table: TableName,
		Rules: []string{"add rule inet wg_mix_ebpf_guard output counter drop"},
	}
	script := plan.ReplacementScript()
	if strings.Contains(script, "delete table inet "+TableName) ||
		!strings.Contains(script, planTablePlaceholder) ||
		!strings.Contains(script, "validated table handle") {
		t.Fatalf("replacement dry-run must require runtime ownership validation:\n%s", script)
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
