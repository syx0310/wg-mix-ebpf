//go:build linux

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/syx0310/wg-mix-ebpf/internal/abi"
	"github.com/syx0310/wg-mix-ebpf/internal/control"
	"github.com/vishvananda/netlink"
)

func inspect(ctx context.Context, state *control.State) (*KernelStatus, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	status := &KernelStatus{PinPath: pinPathFromEnv("")}
	if err := inspectPinnedMaps(status); err != nil {
		status.MapError = err.Error()
	}
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

func inspectPinnedMaps(status *KernelStatus) error {
	control, err := ebpf.LoadPinnedMap(filepath.Join(status.PinPath, "control_map"), nil)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("load pinned control_map: %w", err)
	}
	defer control.Close()

	var controlValue abi.ControlValue
	if err := control.Lookup(abi.ControlKeyGlobal, &controlValue); err != nil {
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("lookup control_map: %w", err)
		}
	} else {
		status.ActiveGeneration = controlValue.ActiveGeneration
		status.ABIVersion = controlValue.ABIVersion
	}

	stats, err := ebpf.LoadPinnedMap(filepath.Join(status.PinPath, "stats_map"), nil)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("load pinned stats_map: %w", err)
	}
	defer stats.Close()

	status.Stats = make(map[string]uint64, len(statNames))
	for key, name := range statNames {
		var values []uint64
		if err := stats.Lookup(uint32(key), &values); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				continue
			}
			return fmt.Errorf("lookup stats_map[%s]: %w", name, err)
		}
		var total uint64
		for _, value := range values {
			total += value
		}
		status.Stats[name] = total
	}
	return nil
}

var statNames = []string{
	"egress_rewrite_ok",
	"egress_rule_miss",
	"egress_bad_type",
	"egress_bad_length",
	"egress_fragment",
	"egress_ipv6_ext",
	"ingress_rewrite_ok",
	"ingress_rule_miss",
	"ingress_bad_type",
	"ingress_bad_length",
	"ingress_fragment",
	"ingress_ipv6_ext",
	"checksum_error",
	"skb_load_error",
	"skb_store_error",
	"gso_seen",
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
