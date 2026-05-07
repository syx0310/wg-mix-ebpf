package dataplane

import (
	"context"

	"github.com/siyixuan/wg-mix-ebpf/internal/control"
)

type KernelStatus struct {
	Underlays []UnderlayKernelStatus `json:"underlays"`
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
