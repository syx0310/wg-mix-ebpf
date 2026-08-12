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
	legacy515FakeTCPObjectKind          = "legacy-5.15 FakeTCP"
	legacy515FakeTCPKprobeRuntimeMap    = "faketcp_kprobe_runtime_map"
	legacy515FakeTCPKprobeRuntimeMapABI = 16
)

var legacy515FakeTCPTriggerHelperCounts = map[asm.BuiltinFunc]int{
	asm.FnSkbChangeType:  2,
	asm.FnSkbChangeProto: 1,
	asm.FnSkbPullData:    2,
}

func legacy515FakeTCPKprobeRuntimeMapDescriptor() pinnedMapDescriptor {
	return pinnedMapDescriptor{
		name: legacy515FakeTCPKprobeRuntimeMap, mapType: ebpf.Array,
		keySize: 4, valueSize: legacy515FakeTCPKprobeRuntimeMapABI,
		maxEntries: 1, flags: unix.BPF_F_RDONLY_PROG,
	}
}

// validateLegacy515ExtensionManifest accepts only the independently built
// Linux-5.15 FakeTCP object. In particular, it rejects both modern kfunc
// relocations and bpf_loop before any kernel resource is created. The kprobe
// checksum bridge owns a separate helper-call contract layered onto this
// manifest.
func validateLegacy515ExtensionManifest(spec *ebpf.CollectionSpec) error {
	if spec == nil {
		return errors.New("legacy-5.15 FakeTCP BPF collection spec is nil")
	}
	if err := validateLegacy515InstructionSet(spec); err != nil {
		return err
	}
	descriptor := legacy515FakeTCPKprobeRuntimeMapDescriptor()
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

	// The kprobe cookie map is legacy-only. Remove only its already validated
	// identity from a copy before applying the exact common FakeTCP schema;
	// every other extra/missing map remains a hard manifest failure.
	common := spec.Copy()
	delete(common.Maps, descriptor.name)
	return validateFakeTCPExtensionSchema(common, legacy515FakeTCPObjectKind)
}

func validateLegacy515InstructionSet(spec *ebpf.CollectionSpec) error {
	triggerCalls := make(map[asm.BuiltinFunc]int, len(legacy515FakeTCPTriggerHelperCounts))
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
			if instruction.IsBuiltinCall() &&
				asm.BuiltinFunc(instruction.Constant) == asm.FnLoop {
				return fmt.Errorf(
					"legacy-5.15 FakeTCP program %q depends on forbidden bpf_loop",
					programName,
				)
			}
			if !instruction.IsBuiltinCall() {
				continue
			}
			helper := asm.BuiltinFunc(instruction.Constant)
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
