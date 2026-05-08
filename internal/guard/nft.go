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
		"destroy table inet " + p.Table,
		"add table inet " + p.Table,
		"add chain inet " + p.Table + " output { type filter hook output priority -300; policy accept; }",
		"add chain inet " + p.Table + " input { type filter hook input priority -300; policy accept; }",
	}
	lines = append(lines, p.Rules...)
	return strings.Join(lines, "\n") + "\n"
}

func CleanupScript() string {
	return "destroy table inet " + TableName + "\n"
}

func BuildNftPlan(state *control.State) NftPlan {
	plan := NftPlan{Table: TableName}
	fwmarks := uniqueFwmarks(state.WireGuards)
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
			fmt.Sprintf("add rule inet %s input udp dport %d counter drop comment \"wg-mix-ebpf startup ingress guard %s\"", TableName, wg.ConfigListenPort, wg.Name),
		)
	}
	sort.Strings(plan.Rules)
	return plan
}

func uniqueFwmarks(wgs []control.WireGuardState) []uint32 {
	set := make(map[uint32]struct{})
	for _, wg := range wgs {
		if wg.ConfigFwMark != 0 {
			set[wg.ConfigFwMark] = struct{}{}
		}
	}
	out := make([]uint32, 0, len(set))
	for mark := range set {
		out = append(out, mark)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
