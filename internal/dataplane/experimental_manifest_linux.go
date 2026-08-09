//go:build linux

package dataplane

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/syx0310/wg-mix-ebpf/internal/faketcp"
)

const (
	experimentalFakeTCPKfuncModule = "wg_mix_faketcp_checksum"
	experimentalFakeTCPKfuncName   = "wg_mix_faketcp_skb_normalize_udp_csum"
	experimentalFakeTCPLicense     = "GPL"
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
		{name: "faketcp_stats_map", mapType: ebpf.PerCPUArray, keySize: 4, valueSize: 8, maxEntries: 17},
		{name: "faketcp_mtu_audit_map", mapType: ebpf.PerCPUArray, keySize: 4, valueSize: 8, maxEntries: faketcp.MTUAuditKeyCount},
	}
}

func experimentalProgramDescriptors() []baselineProgramDescriptor {
	return []baselineProgramDescriptor{
		{
			name: "wg_faketcp_egress", sectionName: "classifier/faketcp_egress",
			programType: ebpf.SchedCLS, license: experimentalFakeTCPLicense,
		},
		{
			name: "wg_mix_faketcp_ingress", sectionName: "xdp",
			programType: ebpf.XDP, attachType: ebpf.AttachXDP, license: experimentalFakeTCPLicense,
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
	if err := validateExperimentalKfuncManifest(spec); err != nil {
		return err
	}

	core := spec.Copy()
	for _, descriptor := range experimentalMapDescriptors() {
		delete(core.Maps, descriptor.name)
	}
	for _, descriptor := range experimentalProgramDescriptors() {
		delete(core.Programs, descriptor.name)
	}
	// The experimental ELF has one license shared by every program. Normalize
	// only this manifest-validated difference before checking the exact MIT
	// baseline schema; no baseline object or descriptor is changed.
	for _, program := range core.Programs {
		program.License = "MIT"
	}
	if err := validateBaselineCollectionSpec(core); err != nil {
		return fmt.Errorf("experimental object does not preserve the exact baseline core: %w", err)
	}

	for _, descriptor := range experimentalMapDescriptors() {
		mapSpec := spec.Maps[descriptor.name]
		if mapSpec == nil {
			return fmt.Errorf("experimental BPF object missing required map %q", descriptor.name)
		}
		if err := validateManifestMapSpec(descriptor, mapSpec); err != nil {
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

func validateExperimentalKfuncManifest(spec *ebpf.CollectionSpec) error {
	kfuncCalls := 0
	for programName, program := range spec.Programs {
		if program == nil {
			continue
		}
		if program.License != experimentalFakeTCPLicense {
			return fmt.Errorf(
				"experimental program %q license is %q, want %q for the required kfunc",
				programName, program.License, experimentalFakeTCPLicense,
			)
		}
		for _, instruction := range program.Instructions {
			if !instruction.IsKfuncCall() {
				continue
			}
			if programName != "wg_mix_egress" ||
				instruction.Reference() != experimentalFakeTCPKfuncName {
				return fmt.Errorf(
					"experimental program %q has unreviewed kfunc relocation %q",
					programName, instruction.Reference(),
				)
			}
			kfuncCalls++
		}
	}
	if kfuncCalls != 1 {
		return fmt.Errorf(
			"experimental object has %d %s relocations, want exactly one",
			kfuncCalls, experimentalFakeTCPKfuncName,
		)
	}
	return nil
}
