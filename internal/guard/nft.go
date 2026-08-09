package guard

import (
	"fmt"
	"sort"
	"strings"

	"github.com/syx0310/wg-mix-ebpf/internal/control"
)

const (
	TableName            = "wg_mix_ebpf_guard"
	planTablePlaceholder = "wg_mix_ebpf_guard_<installation-id>"
)

type NftPlan struct {
	Table string   `json:"table"`
	Rules []string `json:"rules"`
}

func (p NftPlan) Script() string {
	lines := []string{
		"# template only: resolve the instance-owned table from " + OwnerRecordFileName,
		"# the angle-bracket placeholder intentionally makes this template non-executable",
		"create table inet " + planTablePlaceholder,
		"add chain inet " + planTablePlaceholder + " output { type filter hook output priority -300; policy accept; }",
		"add chain inet " + planTablePlaceholder + " input { type filter hook input priority -300; policy accept; }",
	}
	needle := " " + p.Table + " "
	for _, rule := range p.Rules {
		lines = append(lines, strings.ReplaceAll(rule, needle, " "+planTablePlaceholder+" "))
	}
	return strings.Join(lines, "\n") + "\n"
}

// ReplacementScript is a non-executable dry-run template. Real mutation
// resolves an instance record, validates the kernel marker, and deletes by
// table handle in CommandExecutor.Apply.
func (p NftPlan) ReplacementScript() string {
	return "# owned replacement requires a validated table handle at runtime\n" + p.Script()
}

func (p NftPlan) ownedCreateScript(owner ownerRecord) (string, error) {
	if p.Table != TableName {
		return "", fmt.Errorf("guard plan table %q is not the logical table %q", p.Table, TableName)
	}
	if err := owner.validateSelf(); err != nil {
		return "", err
	}
	lines := []string{
		fmt.Sprintf("create table inet %s { comment %q; }", owner.Table, owner.Marker),
		"add chain inet " + owner.Table + " output { type filter hook output priority -300; policy accept; }",
		"add chain inet " + owner.Table + " input { type filter hook input priority -300; policy accept; }",
	}
	for _, rule := range p.Rules {
		needle := " " + p.Table + " "
		if strings.Count(rule, needle) != 1 {
			return "", fmt.Errorf("guard rule does not contain exactly one logical table reference: %q", rule)
		}
		lines = append(lines, strings.Replace(rule, needle, " "+owner.Table+" ", 1))
	}
	return strings.Join(lines, "\n") + "\n", nil
}

func (p NftPlan) ownedReplacementScript(owner ownerRecord, handle uint64) (string, error) {
	if handle == 0 {
		return "", fmt.Errorf("guard table handle must be non-zero")
	}
	create, err := p.ownedCreateScript(owner)
	if err != nil {
		return "", err
	}
	return cleanupHandleScript(handle) + create, nil
}

func CleanupScript() string {
	return "# cleanup requires " + OwnerRecordFileName + " and a matching kernel marker\n" +
		"# delete table inet handle <validated-handle>\n"
}

func cleanupHandleScript(handle uint64) string {
	return fmt.Sprintf("delete table inet handle %d\n", handle)
}

func BuildNftPlan(state *control.State, additionalFwmarks ...uint32) NftPlan {
	plan := NftPlan{Table: TableName}
	fwmarks := uniqueFwmarks(state.WireGuards, additionalFwmarks)
	for _, mark := range fwmarks {
		plan.Rules = append(plan.Rules,
			fmt.Sprintf("add rule inet %s output meta l4proto udp meta mark 0x%08x counter drop comment \"wg-mix-ebpf startup egress guard\"", TableName, mark),
		)
	}
	for _, wg := range state.WireGuards {
		if wg.ConfigListenPort == 0 {
			continue
		}
		plan.Rules = append(plan.Rules,
			fmt.Sprintf("add rule inet %s input udp dport %d counter drop comment \"wg-mix-ebpf startup ingress guard\"", TableName, wg.ConfigListenPort),
		)
		if wg.TransportMode == "faketcp" {
			// The FakeTCP port is exclusive. Before XDP is attached, block
			// TCP so the host stack cannot emit RSTs, and retain the UDP rule
			// above so a failed startup cannot leak the original transport.
			plan.Rules = append(plan.Rules,
				fmt.Sprintf("add rule inet %s input tcp dport %d counter drop comment \"wg-mix-ebpf faketcp startup ingress guard\"", TableName, wg.ConfigListenPort),
			)
		}
	}
	sort.Strings(plan.Rules)
	return plan
}

func uniqueFwmarks(wgs []control.WireGuardState, additional []uint32) []uint32 {
	set := make(map[uint32]struct{})
	for _, wg := range wgs {
		if wg.ConfigFwMark != 0 {
			set[wg.ConfigFwMark] = struct{}{}
		}
		if wg.RuntimeFirewallMark != 0 {
			set[wg.RuntimeFirewallMark] = struct{}{}
		}
	}
	for _, mark := range additional {
		if mark != 0 {
			set[mark] = struct{}{}
		}
	}
	out := make([]uint32, 0, len(set))
	for mark := range set {
		out = append(out, mark)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
