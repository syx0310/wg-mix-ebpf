//go:build linux

package dataplane

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
)

func experimentalMapDescriptors() []pinnedMapDescriptor {
	return []pinnedMapDescriptor{
		{name: "faketcp_session_map", mapType: ebpf.Hash, keySize: 24, valueSize: 40, maxEntries: 16384},
		{name: "faketcp_managed_if_map", mapType: ebpf.Hash, keySize: 16, valueSize: 8, maxEntries: 512},
		{name: "faketcp_managed_port_map", mapType: ebpf.Hash, keySize: 16, valueSize: 16, maxEntries: 2048},
		{name: "faketcp_control_policy_map", mapType: ebpf.Hash, keySize: 16, valueSize: 32, maxEntries: 512},
		{name: "faketcp_control_flow_map", mapType: ebpf.LRUHash, keySize: 32, valueSize: 16, maxEntries: 16384},
		{name: "faketcp_events", mapType: ebpf.RingBuf, maxEntries: 1 << 20},
		{name: "faketcp_capture_scratch", mapType: ebpf.PerCPUArray, keySize: 4, valueSize: 2392, maxEntries: 1},
		{name: "faketcp_rt_id", mapType: ebpf.Array, keySize: 4, valueSize: 32, maxEntries: 1},
		{name: "faketcp_cap_seq", mapType: ebpf.PerCPUArray, keySize: 4, valueSize: 8, maxEntries: 1},
		{name: "faketcp_egress_programs", mapType: ebpf.ProgramArray, keySize: 4, valueSize: 4, maxEntries: 2},
		{name: "faketcp_stats_map", mapType: ebpf.PerCPUArray, keySize: 4, valueSize: 8, maxEntries: 13},
	}
}

func experimentalProgramDescriptors() []baselineProgramDescriptor {
	return []baselineProgramDescriptor{
		{
			name: "wg_faketcp_egress", sectionName: "classifier/faketcp_egress",
			programType: ebpf.SchedCLS, license: "MIT",
		},
		{
			name: "wg_mix_faketcp_ingress", sectionName: "xdp",
			programType: ebpf.XDP, attachType: ebpf.AttachXDP, license: "MIT",
		},
	}
}

// validateExperimentalExtensionManifest accepts exactly the independently
// built FakeTCP extension object: the unchanged baseline collection plus the
// reviewed experimental maps and TC/XDP programs below. It runs before any
// kernel resource is created.
func validateExperimentalExtensionManifest(spec *ebpf.CollectionSpec) error {
	if spec == nil {
		return errors.New("experimental BPF collection spec is nil")
	}

	core := spec.Copy()
	for _, descriptor := range experimentalMapDescriptors() {
		delete(core.Maps, descriptor.name)
	}
	for _, descriptor := range experimentalProgramDescriptors() {
		delete(core.Programs, descriptor.name)
	}
	if err := validateBaselineCollectionSpec(core); err != nil {
		return fmt.Errorf("experimental object does not preserve the exact baseline core: %w", err)
	}

	for _, descriptor := range experimentalMapDescriptors() {
		mapSpec := spec.Maps[descriptor.name]
		if mapSpec == nil {
			return fmt.Errorf("experimental BPF object missing required map %q", descriptor.name)
		}
		if err := validatePinnedMapSpec(descriptor, mapSpec); err != nil {
			return fmt.Errorf("experimental map manifest: %w", err)
		}
		if mapSpec.Pinning != ebpf.PinNone {
			return fmt.Errorf(
				"experimental BPF map %q pinning is %d, want PinNone",
				descriptor.name, mapSpec.Pinning,
			)
		}
	}
	for _, descriptor := range experimentalProgramDescriptors() {
		programSpec := spec.Programs[descriptor.name]
		if programSpec == nil {
			return fmt.Errorf("experimental BPF object missing required program %q", descriptor.name)
		}
		if err := validateProgramManifestSpec(descriptor, programSpec); err != nil {
			return fmt.Errorf("experimental program manifest: %w", err)
		}
	}
	return nil
}
