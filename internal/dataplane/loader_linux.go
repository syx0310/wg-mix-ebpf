//go:build linux

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/syx0310/wg-mix-ebpf/internal/abi"
	"github.com/syx0310/wg-mix-ebpf/internal/control"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	ingressFilterName = "wg_mix_ingress"
	egressFilterName  = "wg_mix_egress"
	filterPriority    = 49152
	ingressHandle     = 0x10001
	egressHandle      = 0x10002
)

type LinuxLoader struct {
	ObjectPath string
	PinPath    string
}

func NewLoader() Loader {
	return LinuxLoader{
		ObjectPath: objectPathFromEnv(""),
		PinPath:    pinPathFromEnv(""),
	}
}

func LoadObjectTest(ctx context.Context, objectPath string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	spec, source, err := loadCollectionSpec(objectPath)
	if err != nil {
		return err
	}
	if err := removeMemlockLimit(); err != nil {
		return err
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("create BPF collection from %s: %w", source, err)
	}
	coll.Close()
	return nil
}

func (l LinuxLoader) Apply(ctx context.Context, state *control.State) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	spec, source, err := loadCollectionSpec(l.ObjectPath)
	if err != nil {
		return err
	}
	setPinnedMaps(spec)
	if err := removeMemlockLimit(); err != nil {
		return err
	}
	pinPath := pinPathFromEnv(l.PinPath)
	if err := os.MkdirAll(pinPath, 0o700); err != nil {
		return fmt.Errorf("create BPF pin path %s: %w", pinPath, err)
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinPath},
	})
	if err != nil {
		if errors.Is(err, ebpf.ErrMapIncompatible) {
			return fmt.Errorf("create BPF collection from %s with pinned maps under %s: %w; run detach or remove stale pinned maps after stopping the agent", source, pinPath, err)
		}
		return fmt.Errorf("create BPF collection from %s: %w", source, err)
	}
	defer coll.Close()

	active, err := activeGeneration(coll)
	if err != nil {
		return err
	}
	next := active + 1
	if next == 0 {
		next = 1
	}
	snapshot, err := abi.FromStateWithGeneration(state, next)
	if err != nil {
		return err
	}
	if err := deleteGenerationMapEntries(coll, next); err != nil {
		return err
	}
	if err := populateDataMaps(coll, snapshot); err != nil {
		return err
	}
	ingress := coll.Programs[ingressFilterName]
	if ingress == nil {
		return fmt.Errorf("BPF object missing program %q", ingressFilterName)
	}
	egress := coll.Programs[egressFilterName]
	if egress == nil {
		return fmt.Errorf("BPF object missing program %q", egressFilterName)
	}

	for _, u := range state.Underlays {
		if !u.Resolved || u.Role == "parse_only" || u.Role == "disabled" {
			continue
		}
		if err := attachPrograms(u.IfIndex, ingress, egress); err != nil {
			return fmt.Errorf("attach underlay %s(%d): %w", u.Name, u.IfIndex, err)
		}
	}
	if err := commitControl(coll, snapshot.Control[abi.ControlKeyGlobal]); err != nil {
		return err
	}
	if err := deleteStaleMapEntries(coll, snapshot); err != nil {
		return err
	}
	return nil
}

func (l LinuxLoader) DetachStale(ctx context.Context, previous *control.State, current *control.State) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if previous == nil {
		return nil
	}
	currentIfindexes := make(map[int]struct{})
	if current != nil {
		for _, u := range current.Underlays {
			if !u.Resolved || u.IfIndex == 0 || u.Role == "disabled" {
				continue
			}
			currentIfindexes[u.IfIndex] = struct{}{}
		}
	}
	var errs []error
	seen := make(map[int]struct{})
	for _, u := range previous.Underlays {
		if !u.Resolved || u.IfIndex == 0 {
			continue
		}
		if _, ok := currentIfindexes[u.IfIndex]; ok {
			continue
		}
		if _, ok := seen[u.IfIndex]; ok {
			continue
		}
		seen[u.IfIndex] = struct{}{}
		if err := detachPrograms(u.IfIndex); err != nil {
			errs = append(errs, fmt.Errorf("detach stale underlay %s(%d): %w", u.Name, u.IfIndex, err))
		}
	}
	return errors.Join(errs...)
}

func (l LinuxLoader) Detach(ctx context.Context, state *control.State) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var errs []error
	for _, u := range state.Underlays {
		if !u.Resolved || u.IfIndex == 0 {
			continue
		}
		if err := detachPrograms(u.IfIndex); err != nil {
			errs = append(errs, fmt.Errorf("detach underlay %s(%d): %w", u.Name, u.IfIndex, err))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	if err := cleanupPinnedMaps(pinPathFromEnv(l.PinPath)); err != nil {
		return err
	}
	return nil
}

func pinPathFromEnv(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if path := os.Getenv(EnvPinPath); path != "" {
		return path
	}
	return DefaultPinPath
}

func removeMemlockLimit() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock rlimit: %w", err)
	}
	return nil
}

func setPinnedMaps(spec *ebpf.CollectionSpec) {
	for _, name := range pinnedMapNames() {
		if m := spec.Maps[name]; m != nil {
			m.Pinning = ebpf.PinByName
		}
	}
}

func pinnedMapNames() []string {
	return []string{
		"control_map",
		"profile_map",
		"underlay_config_map",
		"managed_fwmark_map",
		"egress_rule_map",
		"ingress_listener_map",
		"stats_map",
	}
}

func activeGeneration(coll *ebpf.Collection) (uint64, error) {
	m := coll.Maps["control_map"]
	if m == nil {
		return 0, fmt.Errorf("BPF object missing map %q", "control_map")
	}
	var value abi.ControlValue
	if err := m.Lookup(abi.ControlKeyGlobal, &value); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return 0, nil
		}
		return 0, fmt.Errorf("lookup active generation: %w", err)
	}
	if value.ABIVersion != 0 && value.ABIVersion != abi.Version {
		return 0, fmt.Errorf("pinned control_map ABI version = %d, want %d", value.ABIVersion, abi.Version)
	}
	return value.ActiveGeneration, nil
}

func populateDataMaps(coll *ebpf.Collection, snapshot *abi.Snapshot) error {
	if err := updateMap(coll, "profile_map", snapshot.Profiles); err != nil {
		return err
	}
	if err := updateMap(coll, "underlay_config_map", snapshot.Underlays); err != nil {
		return err
	}
	if err := updateMap(coll, "managed_fwmark_map", snapshot.ManagedFwmarks); err != nil {
		return err
	}
	if err := updateMap(coll, "egress_rule_map", snapshot.EgressRules); err != nil {
		return err
	}
	if err := updateMap(coll, "ingress_listener_map", snapshot.IngressListeners); err != nil {
		return err
	}
	return nil
}

func commitControl(coll *ebpf.Collection, value abi.ControlValue) error {
	m := coll.Maps["control_map"]
	if m == nil {
		return fmt.Errorf("BPF object missing map %q", "control_map")
	}
	if err := m.Update(abi.ControlKeyGlobal, value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("commit control map: %w", err)
	}
	return nil
}

func updateMap[K comparable, V any](coll *ebpf.Collection, name string, entries map[K]V) error {
	m := coll.Maps[name]
	if m == nil {
		return fmt.Errorf("BPF object missing map %q", name)
	}
	for key, value := range entries {
		if err := m.Update(key, value, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update map %s: %w", name, err)
		}
	}
	return nil
}

func deleteStaleMapEntries(coll *ebpf.Collection, snapshot *abi.Snapshot) error {
	return errors.Join(
		deleteStaleEntries(coll, "profile_map", snapshot.Profiles),
		deleteStaleEntries(coll, "underlay_config_map", snapshot.Underlays),
		deleteStaleEntries(coll, "managed_fwmark_map", snapshot.ManagedFwmarks),
		deleteStaleEntries(coll, "egress_rule_map", snapshot.EgressRules),
		deleteStaleEntries(coll, "ingress_listener_map", snapshot.IngressListeners),
	)
}

func deleteGenerationMapEntries(coll *ebpf.Collection, generation uint64) error {
	return errors.Join(
		deleteEntriesByGeneration[abi.ProfileKey, abi.ProfileValue](coll, "profile_map", generation),
		deleteEntriesByGeneration[abi.UnderlayConfigKey, abi.UnderlayConfigValue](coll, "underlay_config_map", generation),
		deleteEntriesByGeneration[abi.ManagedFwmarkKey, abi.ManagedFwmarkValue](coll, "managed_fwmark_map", generation),
		deleteEntriesByGeneration[abi.EgressRuleKey, abi.EgressRuleValue](coll, "egress_rule_map", generation),
		deleteEntriesByGeneration[abi.IngressListenerKey, abi.IngressListenerValue](coll, "ingress_listener_map", generation),
	)
}

func deleteEntriesByGeneration[K comparable, V interface{ MapGeneration() uint64 }](coll *ebpf.Collection, name string, generation uint64) error {
	m := coll.Maps[name]
	if m == nil {
		return fmt.Errorf("BPF object missing map %q", name)
	}
	var (
		key   K
		value V
		errs  []error
	)
	iter := m.Iterate()
	for iter.Next(&key, &value) {
		if value.MapGeneration() != generation {
			continue
		}
		if err := m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("delete generation %d entry from %s: %w", generation, name, err))
		}
	}
	if err := iter.Err(); err != nil {
		errs = append(errs, fmt.Errorf("iterate map %s: %w", name, err))
	}
	return errors.Join(errs...)
}

func deleteStaleEntries[K comparable, V any](coll *ebpf.Collection, name string, desired map[K]V) error {
	m := coll.Maps[name]
	if m == nil {
		return fmt.Errorf("BPF object missing map %q", name)
	}
	var (
		key   K
		value V
		errs  []error
	)
	iter := m.Iterate()
	for iter.Next(&key, &value) {
		if _, ok := desired[key]; ok {
			continue
		}
		if err := m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("delete stale entry from %s: %w", name, err))
		}
	}
	if err := iter.Err(); err != nil {
		errs = append(errs, fmt.Errorf("iterate map %s: %w", name, err))
	}
	return errors.Join(errs...)
}

func cleanupPinnedMaps(pinPath string) error {
	var errs []error
	for _, name := range pinnedMapNames() {
		path := filepath.Join(pinPath, name)
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("remove pinned map %s: %w", path, err))
		}
	}
	if err := os.Remove(pinPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		if !strings.Contains(strings.ToLower(err.Error()), "directory not empty") {
			errs = append(errs, fmt.Errorf("remove BPF pin path %s: %w", pinPath, err))
		}
	}
	return errors.Join(errs...)
}

func attachPrograms(ifindex int, ingress *ebpf.Program, egress *ebpf.Program) error {
	link, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		return err
	}
	if err := ensureClsact(link); err != nil {
		return err
	}
	if err := replaceBpfFilter(link, netlink.HANDLE_MIN_INGRESS, ingressHandle, ingressFilterName, ingress.FD()); err != nil {
		return err
	}
	if err := replaceBpfFilter(link, netlink.HANDLE_MIN_EGRESS, egressHandle, egressFilterName, egress.FD()); err != nil {
		return err
	}
	return nil
}

func ensureClsact(link netlink.Link) error {
	qdisc := &netlink.Clsact{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
	}
	if err := netlink.QdiscAdd(qdisc); err != nil && !isExists(err) {
		return err
	}
	return nil
}

func replaceBpfFilter(link netlink.Link, parent uint32, handle uint32, name string, fd int) error {
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    parent,
			Handle:    handle,
			Protocol:  unix.ETH_P_ALL,
			Priority:  filterPriority,
		},
		Fd:           fd,
		Name:         name,
		DirectAction: true,
	}
	if err := netlink.FilterReplace(filter); err != nil {
		return err
	}
	return deleteDuplicateNamedFilters(link, parent, name, handle)
}

func detachPrograms(ifindex int) error {
	link, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		if isNotFound(err) {
			return nil
		}
		return err
	}
	return errors.Join(
		deleteAgentFilter(link, netlink.HANDLE_MIN_INGRESS, ingressFilterName, ingressHandle),
		deleteAgentFilter(link, netlink.HANDLE_MIN_EGRESS, egressFilterName, egressHandle),
	)
}

func deleteAgentFilter(link netlink.Link, parent uint32, name string, handle uint32) error {
	filters, err := netlink.FilterList(link, parent)
	if err != nil {
		return err
	}
	var errs []error
	for _, f := range filters {
		bpfFilter, ok := f.(*netlink.BpfFilter)
		attrs := f.Attrs()
		if !ok || bpfFilter.Name != name || attrs.Handle != handle || attrs.Priority != filterPriority {
			continue
		}
		if err := netlink.FilterDel(f); err != nil && !isNotFound(err) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func deleteDuplicateNamedFilters(link netlink.Link, parent uint32, name string, keepHandle uint32) error {
	filters, err := netlink.FilterList(link, parent)
	if err != nil {
		return err
	}
	var errs []error
	for _, f := range filters {
		bpfFilter, ok := f.(*netlink.BpfFilter)
		attrs := f.Attrs()
		if !ok || bpfFilter.Name != name || attrs.Priority != filterPriority || attrs.Handle == keepHandle {
			continue
		}
		if err := netlink.FilterDel(f); err != nil && !isNotFound(err) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func isExists(err error) bool {
	return errors.Is(err, os.ErrExist) || strings.Contains(strings.ToLower(err.Error()), "file exists")
}

func isNotFound(err error) bool {
	lower := strings.ToLower(err.Error())
	return errors.Is(err, os.ErrNotExist) || strings.Contains(lower, "no such file") || strings.Contains(lower, "not found")
}
