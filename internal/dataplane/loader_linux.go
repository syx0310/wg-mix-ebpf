//go:build linux

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/siyixuan/wg-mix-ebpf/internal/abi"
	"github.com/siyixuan/wg-mix-ebpf/internal/control"
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
}

func NewLoader() Loader {
	return LinuxLoader{ObjectPath: objectPathFromEnv("")}
}

func LoadObjectTest(ctx context.Context, objectPath string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path := objectPathFromEnv(objectPath)
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return fmt.Errorf("load BPF object %s: %w", path, err)
	}
	if err := removeMemlockLimit(); err != nil {
		return err
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("create BPF collection: %w", err)
	}
	coll.Close()
	return nil
}

func (l LinuxLoader) Apply(ctx context.Context, state *control.State) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	spec, err := ebpf.LoadCollectionSpec(l.ObjectPath)
	if err != nil {
		return fmt.Errorf("load BPF object %s: %w", l.ObjectPath, err)
	}
	if err := removeMemlockLimit(); err != nil {
		return err
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("create BPF collection: %w", err)
	}
	defer coll.Close()

	snapshot, err := abi.FromState(state)
	if err != nil {
		return err
	}
	if err := populateMaps(coll, snapshot); err != nil {
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
	return nil
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
	return errors.Join(errs...)
}

func objectPathFromEnv(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if path := os.Getenv(EnvObjectPath); path != "" {
		return path
	}
	return DefaultObjectPath
}

func removeMemlockLimit() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock rlimit: %w", err)
	}
	return nil
}

func populateMaps(coll *ebpf.Collection, snapshot *abi.Snapshot) error {
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
	if err := updateMap(coll, "control_map", snapshot.Control); err != nil {
		return err
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
		return err
	}
	return errors.Join(
		deleteNamedFilter(link, netlink.HANDLE_MIN_INGRESS, ingressFilterName),
		deleteNamedFilter(link, netlink.HANDLE_MIN_EGRESS, egressFilterName),
	)
}

func deleteNamedFilter(link netlink.Link, parent uint32, name string) error {
	filters, err := netlink.FilterList(link, parent)
	if err != nil {
		return err
	}
	var errs []error
	for _, f := range filters {
		bpfFilter, ok := f.(*netlink.BpfFilter)
		if !ok || bpfFilter.Name != name {
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
		if !ok || bpfFilter.Name != name || bpfFilter.Attrs().Handle == keepHandle {
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
