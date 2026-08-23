//go:build linux

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/syx0310/wg-mix-ebpf/internal/control"
)

func inspect(ctx context.Context, state *control.State) (*KernelStatus, error) {
	if ctx == nil {
		return nil, errors.New("inspect context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if state == nil {
		return nil, errors.New("inspect control state is nil")
	}
	status := &KernelStatus{PinPath: pinPathFromEnv("")}
	owner, mapErr := inspectPinnedMaps(ctx, status)
	if mapErr != nil {
		status.MapError = mapErr.Error()
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
		entry.Filters = attachmentStatusesForIfindex(owner, u.IfIndex)
		for _, filter := range entry.Filters {
			if filter.Direction == string(exactTCXIngress) {
				entry.IngressAttached = true
			} else if filter.Direction == string(exactTCXEgress) {
				entry.EgressAttached = true
			}
		}
		status.Underlays = append(status.Underlays, entry)
	}
	return status, nil
}

func attachmentStatusesForIfindex(
	record *pinOwnerRecord,
	ifindex int,
) []FilterStatus {
	if record == nil || ifindex <= 0 {
		return nil
	}
	linksByDirection := make(map[exactTCXDirection]exactTCXBinding)
	for _, binding := range record.ActiveLinks {
		if binding.IfIndex == ifindex {
			linksByDirection[binding.Direction] = binding
		}
	}
	filtersByDirection := make(map[string]tcFilterBinding)
	for _, binding := range record.ActiveFilters {
		if binding.IfIndex == ifindex {
			filtersByDirection[binding.Direction] = binding
		}
	}
	var statuses []FilterStatus
	for _, direction := range []exactTCXDirection{exactTCXIngress, exactTCXEgress} {
		if binding, exists := linksByDirection[direction]; exists {
			statuses = append(statuses, FilterStatus{
				Direction:  string(direction),
				Name:       binding.PinName,
				Backend:    binding.Backend,
				AttachType: binding.AttachType,
				LinkID:     binding.LinkID,
				ProgramID:  binding.ProgramID,
			})
			continue
		}
		if binding, exists := filtersByDirection[string(direction)]; exists {
			name := ingressFilterName
			if direction == exactTCXEgress {
				name = egressFilterName
			}
			statuses = append(statuses, FilterStatus{
				Direction: string(direction),
				Name:      name,
				Handle:    binding.Handle,
				Priority:  binding.Priority,
				Backend:   classicTCBackend,
				ProgramID: binding.ProgramID,
			})
		}
	}
	return statuses
}

func inspectPinnedMaps(ctx context.Context, status *KernelStatus) (*pinOwnerRecord, error) {
	runtime := LinuxLoader{}.pinRuntime(ctx)
	validated, err := validatePinPath(status.PinPath, runtime.validator)
	if err != nil {
		return nil, err
	}
	if !validated.exists {
		return nil, nil
	}
	parent, err := openPinPathParent(status.PinPath, validated, runtime)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	lock, err := acquirePinPathLock(ctx, parent.resource, "status", runtime)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	validated, err = validatePinPath(status.PinPath, runtime.validator)
	if err != nil {
		return nil, err
	}
	handle, _, err := openPinPathHandleFromParent(parent, validated, false)
	if err != nil {
		return nil, err
	}
	if handle == nil {
		return nil, nil
	}
	defer handle.Close()

	store, err := openPinOwnerStoreWithPolicy(
		runtime,
		handle.resource,
		false,
		false,
	)
	if err != nil {
		return nil, fmt.Errorf("open persistent BPF pin owner: %w", err)
	}
	defer store.Close()
	record, exists, err := store.LoadOptional(handle.mountID)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.New("BPF pins have no persistent owner record")
	}
	if record.Phase != pinOwnerPhaseActive ||
		record.Step != pinOwnerStepReady {
		return nil, fmt.Errorf(
			"BPF owner transaction is %s/%s at sequence %d; status is not steady",
			record.Phase, record.Step, record.Sequence,
		)
	}
	if err := validateOwnerDirectoryEntries(handle, record); err != nil {
		return nil, err
	}
	pins, err := inspectPinnedMapSet(handle, true)
	if err != nil {
		return nil, err
	}
	defer closePinnedMapPins(pins)
	if err := validateOwnerPins(handle, record, pins, true); err != nil {
		return nil, err
	}
	controlValue, err := ownerControlValue(pins)
	if err != nil {
		return nil, err
	}
	if err := validateOwnerControlGeneration(
		pins,
		record.ActiveGeneration,
	); err != nil {
		return nil, err
	}
	switch record.Version {
	case pinOwnerLegacyClassicVersion:
		if err := validateOwnerTCExact(record.ActiveFilters, record.ActiveFilters, runtime.classicTC); err != nil {
			return nil, err
		}
	case pinOwnerRecordVersion:
		if err := validateOwnerExactTCXLinks(handle, record.ActiveLinks, runtime.exactTCX); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported BPF owner schema %d", record.Version)
	}
	status.ActiveGeneration = controlValue.ActiveGeneration
	status.ABIVersion = controlValue.ABIVersion

	stats, err := ebpf.LoadPinnedMap(filepath.Join(handle.procPath(), "stats_map"), nil)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return clonePinOwnerRecord(record), nil
		}
		return clonePinOwnerRecord(record), fmt.Errorf("load pinned stats_map: %w", err)
	}
	defer stats.Close()

	status.Stats = make(map[string]uint64, len(statNames))
	for key, name := range statNames {
		var values []uint64
		if err := stats.Lookup(uint32(key), &values); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				continue
			}
			return clonePinOwnerRecord(record), fmt.Errorf("lookup stats_map[%s]: %w", name, err)
		}
		var total uint64
		for _, value := range values {
			total += value
		}
		status.Stats[name] = total
	}
	return clonePinOwnerRecord(record), nil
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
	"egress_gso_seen",
	"egress_gso_managed_seen",
	"egress_gso_rewrite_ok",
	"ingress_gso_seen",
	"ingress_gso_listener_hit",
	"ingress_gso_rewrite_ok",
	"icmp_egress_rewrite_ok",
	"icmp_ingress_rewrite_ok",
	"icmp_checksum_error",
	"xor_egress_ok",
	"xor_ingress_ok",
	"xor_key_missing",
	"xor_len_overflow",
	"xor_bad_type_after_decrypt",
	"xor_load_error",
	"xor_store_error",
	"xor_csum_error",
	"ingress_bad_checksum",
	"egress_bad_checksum",
	"xor_egress_dispatch_error",
	"xor_ingress_dispatch_error",
}
