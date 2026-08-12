//go:build linux

package dataplane

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const (
	experimentalFakeTCPKfuncModule        = "wg_mix_faketcp_checksum"
	experimentalFakeTCPPrepareKfuncName   = "wg_mix_faketcp_skb_prepare_udp"
	experimentalFakeTCPGSOCommitKfuncName = "wg_mix_faketcp_skb_commit_udp_gso"
	experimentalFakeTCPMTUAuditKeyCount   = 15
	experimentalFakeTCPLicense            = "GPL"
)

var experimentalFakeTCPKfuncNames = [...]string{
	experimentalFakeTCPPrepareKfuncName,
	experimentalFakeTCPGSOCommitKfuncName,
}

// The unified prepare wrapper has one reviewed call site in each mutually
// exclusive non-GSO and GSO branch. The commit kfunc is GSO-only. Keep the
// exact compiled relocation cardinality explicit instead of relying on a
// compiler version to merge equivalent branch-local calls.
var experimentalFakeTCPKfuncRelocationCounts = map[string]int{
	experimentalFakeTCPPrepareKfuncName:   2,
	experimentalFakeTCPGSOCommitKfuncName: 1,
}

func experimentalMapDescriptors() []pinnedMapDescriptor {
	return []pinnedMapDescriptor{
		{name: "faketcp_session_map", mapType: ebpf.Hash, keySize: 32, valueSize: 80, maxEntries: 16384},
		{name: "faketcp_managed_if_map", mapType: ebpf.Hash, keySize: 16, valueSize: 8, maxEntries: 512},
		{name: "faketcp_managed_port_map", mapType: ebpf.Hash, keySize: 16, valueSize: 16, maxEntries: 2048},
		{name: "faketcp_control_policy_map", mapType: ebpf.Hash, keySize: 16, valueSize: 32, maxEntries: 512},
		{name: "faketcp_control_flow_map", mapType: ebpf.LRUHash, keySize: 40, valueSize: 16, maxEntries: 16384},
		{name: "faketcp_events", mapType: ebpf.RingBuf, maxEntries: 1 << 20},
		{name: "faketcp_capture_scratch", mapType: ebpf.PerCPUArray, keySize: 4, valueSize: 2416, maxEntries: 1},
		{name: "faketcp_runtime_scratch_map", mapType: ebpf.PerCPUArray, keySize: 4, valueSize: 392, maxEntries: 1},
		{name: "faketcp_rt_id", mapType: ebpf.Array, keySize: 4, valueSize: 32, maxEntries: 1},
		{name: "faketcp_gen_gt", mapType: ebpf.Array, keySize: 4, valueSize: 16, maxEntries: 1, flags: unix.BPF_F_RDONLY},
		{name: "faketcp_gen_wk", mapType: ebpf.RingBuf, maxEntries: 4096},
		{name: "faketcp_cap_seq", mapType: ebpf.PerCPUArray, keySize: 4, valueSize: 8, maxEntries: 1},
		{name: "faketcp_egress_admission_map", mapType: ebpf.PerCPUArray, keySize: 4, valueSize: 192, maxEntries: 1, flags: unix.BPF_F_RDONLY},
		{name: "faketcp_egress_programs", mapType: ebpf.ProgramArray, keySize: 4, valueSize: 4, maxEntries: 2},
		{name: "faketcp_stats_map", mapType: ebpf.PerCPUArray, keySize: 4, valueSize: 8, maxEntries: 19},
		{name: "faketcp_mtu_audit_map", mapType: ebpf.PerCPUArray, keySize: 4, valueSize: 8, maxEntries: experimentalFakeTCPMTUAuditKeyCount},
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
		{
			name: "wg_faketcp_session_claim", sectionName: "classifier/faketcp_session_claim",
			programType: ebpf.SchedCLS, license: experimentalFakeTCPLicense,
		},
		{
			name: "wg_faketcp_generation_control", sectionName: "classifier/faketcp_generation_control",
			programType: ebpf.SchedCLS, license: experimentalFakeTCPLicense,
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
	return validateFakeTCPExtensionSchema(spec, "experimental")
}

// validateFakeTCPExtensionSchema validates the common FakeTCP map/program ABI
// without conflating the modern kfunc and legacy-5.15 checksum contracts. Each
// independently built object validates its checksum/helper identity first.
func validateFakeTCPExtensionSchema(spec *ebpf.CollectionSpec, objectKind string) error {
	if spec == nil {
		return fmt.Errorf("%s BPF collection spec is nil", objectKind)
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
		return fmt.Errorf("%s object does not preserve the exact baseline core: %w", objectKind, err)
	}

	for _, descriptor := range experimentalMapDescriptors() {
		mapSpec := spec.Maps[descriptor.name]
		if mapSpec == nil {
			return fmt.Errorf("%s BPF object missing required map %q", objectKind, descriptor.name)
		}
		if err := validateManifestMapSpec(descriptor, mapSpec); err != nil {
			return fmt.Errorf("%s map manifest: %w", objectKind, err)
		}
		if mapSpec.Pinning != ebpf.PinNone {
			return fmt.Errorf(
				"%s BPF map %q pinning is %d, want PinNone",
				objectKind, descriptor.name, mapSpec.Pinning,
			)
		}
	}
	for _, descriptor := range experimentalProgramDescriptors() {
		programSpec := spec.Programs[descriptor.name]
		if programSpec == nil {
			return fmt.Errorf("%s BPF object missing required program %q", objectKind, descriptor.name)
		}
		if err := validateProgramManifestSpec(descriptor, programSpec); err != nil {
			return fmt.Errorf("%s program manifest: %w", objectKind, err)
		}
	}
	return nil
}

func validateExperimentalKfuncManifest(spec *ebpf.CollectionSpec) error {
	kfuncCalls := make(map[string]int, len(experimentalFakeTCPKfuncNames))
	for _, name := range experimentalFakeTCPKfuncNames {
		kfuncCalls[name] = 0
	}
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
			name := instruction.Reference()
			if programName != "wg_mix_egress" {
				return fmt.Errorf(
					"experimental program %q has unreviewed kfunc relocation %q",
					programName, name,
				)
			}
			if _, ok := kfuncCalls[name]; !ok {
				return fmt.Errorf(
					"experimental program %q has unreviewed kfunc relocation %q",
					programName, name,
				)
			}
			kfuncCalls[name]++
		}
	}
	for _, name := range experimentalFakeTCPKfuncNames {
		expected := experimentalFakeTCPKfuncRelocationCounts[name]
		if kfuncCalls[name] != expected {
			return fmt.Errorf(
				"experimental object has %d %s relocations, want exactly %d",
				kfuncCalls[name], name, expected,
			)
		}
	}
	return nil
}
