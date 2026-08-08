//go:build linux

package dataplane

import (
	"fmt"
	"sort"

	"github.com/syx0310/wg-mix-ebpf/internal/control"
)

// tcFilterBinding remains only so schema-v3 owner records can be decoded and
// rejected with an explicit migration error. No v4 production path interprets
// these fields or uses them to address a TC filter.
type tcFilterBinding struct {
	IfIndex   int    `json:"ifindex"`
	Direction string `json:"direction"`
	Parent    uint32 `json:"parent"`
	Handle    uint32 `json:"handle"`
	Priority  uint16 `json:"priority"`
	ProgramID uint32 `json:"program_id"`
}

func activeAttachIfindexes(state *control.State) ([]int, error) {
	if state == nil {
		return nil, nil
	}
	seen := make(map[int]string)
	var ifindexes []int
	for _, underlay := range state.Underlays {
		if !underlay.Resolved || underlay.Role == "parse_only" || underlay.Role == "disabled" {
			continue
		}
		if underlay.IfIndex <= 0 {
			return nil, fmt.Errorf(
				"underlay %s has invalid ifindex %d",
				underlay.Name, underlay.IfIndex,
			)
		}
		if previous, exists := seen[underlay.IfIndex]; exists {
			return nil, fmt.Errorf(
				"underlays %s and %s resolve to duplicate ifindex %d",
				previous, underlay.Name, underlay.IfIndex,
			)
		}
		seen[underlay.IfIndex] = underlay.Name
		ifindexes = append(ifindexes, underlay.IfIndex)
	}
	sort.Ints(ifindexes)
	return ifindexes, nil
}
