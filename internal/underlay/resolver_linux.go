//go:build linux

package underlay

import (
	"context"
	"fmt"
	"net"

	"github.com/siyixuan/wg-mix-ebpf/internal/config"
)

type SystemResolver struct{}

func NewSystemResolver() Resolver {
	return SystemResolver{}
}

func (SystemResolver) Resolve(_ context.Context, u config.Underlay) (*Resolved, error) {
	if u.Type != "netdev" {
		return nil, fmt.Errorf("underlay type %q resolver is not implemented yet", u.Type)
	}
	iface, err := net.InterfaceByName(u.Name)
	if err != nil {
		return nil, err
	}
	return &Resolved{
		Name:     u.Name,
		Type:     u.Type,
		IfName:   iface.Name,
		IfIndex:  iface.Index,
		LinkType: "netdev",
		Role:     "transform",
	}, nil
}
