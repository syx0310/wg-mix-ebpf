package guard

import (
	"fmt"
	"sort"
	"strings"

	"github.com/syx0310/wg-mix-ebpf/internal/control"
)

const TableName = "wg_mix_ebpf_guard"

type NftPlan struct {
	Table string   `json:"table"`
	Rules []string `json:"rules"`
}

func (p NftPlan) Script() string {
	lines := []string{
		"add table inet " + p.Table,
		"add chain inet " + p.Table + " output { type filter hook output priority -300; policy accept; }",
		"add chain inet " + p.Table + " input { type filter hook input priority -300; policy accept; }",
	}
	lines = append(lines, p.Rules...)
	return strings.Join(lines, "\n") + "\n"
}

// ReplacementScript replaces an existing guard table in one nft transaction.
// nft applies a script passed with -f atomically, so a failure while validating
// or creating the new rules leaves the old table in place.
func (p NftPlan) ReplacementScript() string {
	return cleanupScript(p.Table) + p.Script()
}

func CleanupScript() string {
	return cleanupScript(TableName)
}

func cleanupScript(table string) string {
	return "delete table inet " + table + "\n"
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
