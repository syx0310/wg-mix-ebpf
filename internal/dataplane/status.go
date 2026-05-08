package dataplane

import (
	"context"

	"github.com/syx0310/wg-mix-ebpf/internal/control"
)

type KernelStatus struct {
	PinPath          string                 `json:"pin_path,omitempty"`
	ActiveGeneration uint64                 `json:"active_generation,omitempty"`
	ABIVersion       uint32                 `json:"abi_version,omitempty"`
	Stats            map[string]uint64      `json:"stats,omitempty"`
	MapError         string                 `json:"map_error,omitempty"`
	Underlays        []UnderlayKernelStatus `json:"underlays"`
}

type UnderlayKernelStatus struct {
	Name            string         `json:"name"`
	IfIndex         int            `json:"ifindex"`
	IfName          string         `json:"ifname,omitempty"`
	IngressAttached bool           `json:"ingress_attached"`
	EgressAttached  bool           `json:"egress_attached"`
	Filters         []FilterStatus `json:"filters,omitempty"`
	Error           string         `json:"error,omitempty"`
}

type FilterStatus struct {
	Direction string `json:"direction"`
	Name      string `json:"name"`
	Handle    uint32 `json:"handle"`
	Priority  uint16 `json:"priority"`
}

func Inspect(ctx context.Context, state *control.State) (*KernelStatus, error) {
	return inspect(ctx, state)
}
