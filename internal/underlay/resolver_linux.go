//go:build linux

package underlay

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/syx0310/wg-mix-ebpf/internal/config"
	"github.com/vishvananda/netlink"
)

type SystemResolver struct{}

func NewSystemResolver() Resolver {
	return SystemResolver{}
}

func (SystemResolver) Resolve(ctx context.Context, u config.Underlay) (*Resolved, error) {
	switch u.Type {
	case "netdev":
		return resolveNetdev(u.Name, u.Type, u.Name, "netdev")
	case "openwrt-interface":
		ifname, err := resolveOpenWrtL3Device(ctx, u.Name)
		if err != nil {
			return nil, err
		}
		return resolveNetdev(u.Name, u.Type, ifname, "openwrt-interface")
	default:
		return nil, fmt.Errorf("underlay type %q resolver is not implemented", u.Type)
	}
}

func resolveNetdev(name string, typ string, ifname string, linkType string) (*Resolved, error) {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return nil, err
	}
	if linkType == "" || linkType == "netdev" || linkType == "openwrt-interface" {
		linkType = link.Type()
	}
	return &Resolved{
		Name:     name,
		Type:     typ,
		IfName:   link.Attrs().Name,
		IfIndex:  link.Attrs().Index,
		LinkType: linkType,
		Role:     "transform",
	}, nil
}

func resolveOpenWrtL3Device(ctx context.Context, name string) (string, error) {
	out, err := exec.CommandContext(ctx, "ifstatus", name).Output()
	if err != nil {
		return "", fmt.Errorf("resolve OpenWrt interface %q via ifstatus: %w", name, err)
	}
	var status struct {
		L3Device string `json:"l3_device"`
		Device   string `json:"device"`
	}
	if err := json.Unmarshal(out, &status); err != nil {
		return "", fmt.Errorf("parse ifstatus %q: %w", name, err)
	}
	if status.L3Device != "" {
		return status.L3Device, nil
	}
	if status.Device != "" {
		return status.Device, nil
	}
	return "", fmt.Errorf("ifstatus %q has no l3_device/device", name)
}
