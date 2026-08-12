//go:build linux

package dataplane

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"golang.org/x/sys/unix"
)

const (
	legacy515FakeTCPObjectKind               = "legacy-5.15 FakeTCP"
	legacy515FakeTCPKprobeRuntimeMap         = "faketcp_kprobe_runtime_map"
	legacy515FakeTCPKprobeRuntimeMapABI      = 16
	legacy515FakeTCPIterationMap             = "faketcp_legacy_515_iteration_map"
	legacy515FakeTCPIterationMapMaxEntries   = 4097
	legacy515FakeTCPIterationHelperCallCount = 4
)

var legacy515FakeTCPTriggerHelperCounts = map[asm.BuiltinFunc]int{
	asm.FnSkbChangeType:  2,
	asm.FnSkbChangeProto: 1,
	asm.FnSkbPullData:    2,
}

var legacy515FakeTCPForbiddenHelpers = map[asm.BuiltinFunc]string{
	asm.FnLoop:          "bpf_loop",
	asm.FnXdpLoadBytes:  "bpf_xdp_load_bytes",
	asm.FnXdpStoreBytes: "bpf_xdp_store_bytes",
}

func legacy515FakeTCPKprobeRuntimeMapDescriptor() pinnedMapDescriptor {
	return pinnedMapDescriptor{
		name: legacy515FakeTCPKprobeRuntimeMap, mapType: ebpf.Array,
		keySize: 4, valueSize: legacy515FakeTCPKprobeRuntimeMapABI,
		maxEntries: 1, flags: unix.BPF_F_RDONLY_PROG,
	}
}

func legacy515FakeTCPIterationMapDescriptor() pinnedMapDescriptor {
	return pinnedMapDescriptor{
		name: legacy515FakeTCPIterationMap, mapType: ebpf.Array,
		keySize: 4, valueSize: 4,
		maxEntries: legacy515FakeTCPIterationMapMaxEntries,
		flags:      unix.BPF_F_RDONLY_PROG,
	}
}

// validateLegacy515ExtensionManifest accepts only the independently built
// Linux-5.15 FakeTCP object. In particular, it rejects both modern kfunc
// relocations and bpf_loop before any kernel resource is created. Its exact
// 5.15-compatible map iterator and the kprobe checksum bridge own separate
// helper-call contracts layered onto this manifest.
func validateLegacy515ExtensionManifest(spec *ebpf.CollectionSpec) error {
	if spec == nil {
		return errors.New("legacy-5.15 FakeTCP BPF collection spec is nil")
	}
	if err := validateLegacy515InstructionSet(spec); err != nil {
		return err
	}
	common := spec.Copy()
	for _, descriptor := range []pinnedMapDescriptor{
		legacy515FakeTCPKprobeRuntimeMapDescriptor(),
		legacy515FakeTCPIterationMapDescriptor(),
	} {
		mapSpec := spec.Maps[descriptor.name]
		if mapSpec == nil {
			return fmt.Errorf(
				"%s BPF object missing required map %q",
				legacy515FakeTCPObjectKind, descriptor.name,
			)
		}
		if err := validateManifestMapSpec(descriptor, mapSpec); err != nil {
			return fmt.Errorf("%s map manifest: %w", legacy515FakeTCPObjectKind, err)
		}
		if mapSpec.Pinning != ebpf.PinNone {
			return fmt.Errorf(
				"%s BPF map %q pinning is %d, want PinNone",
				legacy515FakeTCPObjectKind, descriptor.name, mapSpec.Pinning,
			)
		}
		delete(common.Maps, descriptor.name)
	}

	// Both maps are legacy-only. Remove only their already validated identities
	// from the copy before applying the exact common FakeTCP schema; every other
	// extra or missing map remains a hard manifest failure.
	return validateFakeTCPExtensionSchema(common, legacy515FakeTCPObjectKind)
}

func validateLegacy515InstructionSet(spec *ebpf.CollectionSpec) error {
	triggerCalls := make(map[asm.BuiltinFunc]int, len(legacy515FakeTCPTriggerHelperCounts))
	iterationCalls := 0
	for helper := range legacy515FakeTCPTriggerHelperCounts {
		triggerCalls[helper] = 0
	}
	for programName, program := range spec.Programs {
		if program == nil {
			continue
		}
		for _, instruction := range program.Instructions {
			if instruction.IsKfuncCall() {
				return fmt.Errorf(
					"legacy-5.15 FakeTCP program %q has forbidden kfunc relocation %q",
					programName, instruction.Reference(),
				)
			}
			if !instruction.IsBuiltinCall() {
				continue
			}
			helper := asm.BuiltinFunc(instruction.Constant)
			if helperName, forbidden := legacy515FakeTCPForbiddenHelpers[helper]; forbidden {
				return fmt.Errorf(
					"legacy-5.15 FakeTCP program %q depends on forbidden %s",
					programName, helperName,
				)
			}
			if helper == asm.FnForEachMapElem {
				if programName != "wg_mix_egress" {
					return fmt.Errorf(
						"legacy-5.15 FakeTCP map iterator helper is called by unreviewed program %q",
						programName,
					)
				}
				iterationCalls++
				continue
			}
			if _, ok := triggerCalls[helper]; !ok {
				continue
			}
			if programName != "wg_mix_egress" {
				return fmt.Errorf(
					"legacy-5.15 FakeTCP trigger helper %s is called by unreviewed program %q",
					helper, programName,
				)
			}
			triggerCalls[helper]++
		}
	}
	if iterationCalls != legacy515FakeTCPIterationHelperCallCount {
		return fmt.Errorf(
			"legacy-5.15 FakeTCP object has %d %s calls, want exactly %d",
			iterationCalls, asm.FnForEachMapElem,
			legacy515FakeTCPIterationHelperCallCount,
		)
	}
	for helper, expected := range legacy515FakeTCPTriggerHelperCounts {
		if triggerCalls[helper] != expected {
			return fmt.Errorf(
				"legacy-5.15 FakeTCP object has %d %s calls, want exactly %d",
				triggerCalls[helper], helper, expected,
			)
		}
	}
	return nil
}
