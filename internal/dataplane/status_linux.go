//go:build linux

package dataplane

import (
	"context"
	"fmt"

	"github.com/siyixuan/wg-mix-ebpf/internal/control"
	"github.com/vishvananda/netlink"
)

func inspect(ctx context.Context, state *control.State) (*KernelStatus, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	status := &KernelStatus{}
	for _, u := range state.Underlays {
		if !u.Resolved || u.IfIndex == 0 || u.Role == "disabled" {
			continue
		}
		entry := UnderlayKernelStatus{
			Name:    u.Name,
			IfIndex: u.IfIndex,
			IfName:  u.IfName,
		}
		link, err := netlink.LinkByIndex(u.IfIndex)
		if err != nil {
			entry.Error = err.Error()
			status.Underlays = append(status.Underlays, entry)
			continue
		}
		ingress, err := filterStatuses(link, netlink.HANDLE_MIN_INGRESS, "ingress")
		if err != nil {
			entry.Error = fmt.Sprintf("inspect ingress filters: %v", err)
			status.Underlays = append(status.Underlays, entry)
			continue
		}
		egress, err := filterStatuses(link, netlink.HANDLE_MIN_EGRESS, "egress")
		if err != nil {
			entry.Error = fmt.Sprintf("inspect egress filters: %v", err)
			status.Underlays = append(status.Underlays, entry)
			continue
		}
		entry.Filters = append(entry.Filters, ingress...)
		entry.Filters = append(entry.Filters, egress...)
		for _, filter := range ingress {
			if filter.Name == ingressFilterName {
				entry.IngressAttached = true
			}
		}
		for _, filter := range egress {
			if filter.Name == egressFilterName {
				entry.EgressAttached = true
			}
		}
		status.Underlays = append(status.Underlays, entry)
	}
	return status, nil
}

func filterStatuses(link netlink.Link, parent uint32, direction string) ([]FilterStatus, error) {
	filters, err := netlink.FilterList(link, parent)
	if err != nil {
		return nil, err
	}
	out := make([]FilterStatus, 0, len(filters))
	for _, filter := range filters {
		bpfFilter, ok := filter.(*netlink.BpfFilter)
		if !ok {
			continue
		}
		out = append(out, FilterStatus{
			Direction: direction,
			Name:      bpfFilter.Name,
			Handle:    bpfFilter.Attrs().Handle,
			Priority:  bpfFilter.Attrs().Priority,
		})
	}
	return out, nil
}
