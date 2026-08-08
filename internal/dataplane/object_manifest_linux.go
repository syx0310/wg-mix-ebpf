//go:build linux

package dataplane

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
)

// baselineProgramDescriptor describes the immutable loader-facing program
// schema shared by the baseline object and the experimental extension.
// Keeping this manifest outside loader_linux.go leaves Classic TCX ownership
// and recovery untouched while giving the experimental collection an exact
// baseline-core boundary.
type baselineProgramDescriptor struct {
	name          string
	sectionName   string
	programType   ebpf.ProgramType
	ifindex       uint32
	attachType    ebpf.AttachType
	attachTo      string
	flags         uint32
	kernelVersion uint32
	license       string
}

func baselineMapDescriptors() []pinnedMapDescriptor {
	descriptors := append([]pinnedMapDescriptor(nil), pinnedMapDescriptors()...)
	return append(descriptors, pinnedMapDescriptor{
		name: "icmp_seq_map", mapType: ebpf.LRUHash,
		keySize: 24, valueSize: 16, maxEntries: 2048,
	})
}

func baselineProgramDescriptors() []baselineProgramDescriptor {
	descriptors := []baselineProgramDescriptor{
		{name: "wg_mix_egress", sectionName: "classifier/egress", programType: ebpf.SchedCLS, license: "MIT"},
		{name: "wg_mix_ingress", sectionName: "classifier/ingress", programType: ebpf.SchedCLS, license: "MIT"},
	}
	for index := 0; index < xorSegmentCount; index++ {
		descriptors = append(descriptors,
			baselineProgramDescriptor{
				name: fmt.Sprintf("wg_xor_eg_%d", index), sectionName: fmt.Sprintf("classifier/xor_egress/%d", index), programType: ebpf.SchedCLS, license: "MIT",
			},
			baselineProgramDescriptor{
				name: fmt.Sprintf("wg_xor_in_%d", index), sectionName: fmt.Sprintf("classifier/xor_ingress/%d", index), programType: ebpf.SchedCLS, license: "MIT",
			},
		)
	}
	return descriptors
}

// validateBaselineCollectionSpec is the exact schema manifest between the
// stable UDP/ICMP object and the unpinned experimental extension.
func validateBaselineCollectionSpec(spec *ebpf.CollectionSpec) error {
	if spec == nil {
		return errors.New("baseline BPF collection spec is nil")
	}
	mapManifest := baselineMapDescriptors()
	wantedMaps := make(map[string]pinnedMapDescriptor, len(mapManifest))
	for _, descriptor := range mapManifest {
		wantedMaps[descriptor.name] = descriptor
	}
	var unexpectedMaps []string
	for name := range spec.Maps {
		if _, ok := wantedMaps[name]; !ok {
			unexpectedMaps = append(unexpectedMaps, name)
		}
	}
	if len(unexpectedMaps) != 0 {
		sort.Strings(unexpectedMaps)
		return fmt.Errorf("baseline BPF object has unexpected maps outside its manifest: %s", strings.Join(unexpectedMaps, ", "))
	}
	for _, descriptor := range mapManifest {
		mapSpec := spec.Maps[descriptor.name]
		if mapSpec == nil {
			return fmt.Errorf("baseline BPF object missing required map %q", descriptor.name)
		}
		if err := validateManifestMapSpec(descriptor, mapSpec); err != nil {
			return fmt.Errorf("baseline map manifest: %w", err)
		}
		if mapSpec.Pinning != ebpf.PinNone {
			return fmt.Errorf("baseline map manifest: BPF map %q unexpectedly requests pinning mode %d", descriptor.name, mapSpec.Pinning)
		}
	}

	programManifest := baselineProgramDescriptors()
	wantedPrograms := make(map[string]baselineProgramDescriptor, len(programManifest))
	for _, descriptor := range programManifest {
		wantedPrograms[descriptor.name] = descriptor
	}
	var unexpectedPrograms []string
	for name := range spec.Programs {
		if _, ok := wantedPrograms[name]; !ok {
			unexpectedPrograms = append(unexpectedPrograms, name)
		}
	}
	if len(unexpectedPrograms) != 0 {
		sort.Strings(unexpectedPrograms)
		return fmt.Errorf("baseline BPF object has unexpected programs outside its manifest: %s", strings.Join(unexpectedPrograms, ", "))
	}
	for _, descriptor := range programManifest {
		programSpec := spec.Programs[descriptor.name]
		if programSpec == nil {
			return fmt.Errorf("baseline BPF object missing required program %q", descriptor.name)
		}
		if err := validateProgramManifestSpec(descriptor, programSpec); err != nil {
			return fmt.Errorf("baseline program manifest: %w", err)
		}
	}
	return nil
}

func validateManifestMapSpec(descriptor pinnedMapDescriptor, spec *ebpf.MapSpec) error {
	if err := validatePinnedMapSpec(descriptor, spec); err != nil {
		return err
	}
	if len(spec.Tags) != 0 {
		return fmt.Errorf("BPF map %q has unsupported creation tags", descriptor.name)
	}
	return nil
}

func validateProgramManifestSpec(descriptor baselineProgramDescriptor, spec *ebpf.ProgramSpec) error {
	if spec.Name != descriptor.name || spec.SectionName != descriptor.sectionName || spec.Type != descriptor.programType {
		return fmt.Errorf(
			"BPF program %q schema is kernel_name=%q section=%q type=%s, want kernel_name=%q section=%q type=%s",
			descriptor.name, spec.Name, spec.SectionName, spec.Type,
			descriptor.name, descriptor.sectionName, descriptor.programType,
		)
	}
	if spec.Ifindex != descriptor.ifindex || spec.AttachType != descriptor.attachType ||
		spec.AttachTo != descriptor.attachTo || spec.AttachTarget != nil ||
		spec.Flags != descriptor.flags || spec.KernelVersion != descriptor.kernelVersion ||
		spec.License != descriptor.license || spec.ByteOrder != binary.LittleEndian ||
		len(spec.Instructions) == 0 {
		return fmt.Errorf(
			"BPF program %q attach/load metadata is ifindex=%d attach_type=%d attach_to=%q target=%t flags=%#x kernel_version=%d license=%q byte_order=%T instructions=%d",
			descriptor.name, spec.Ifindex, spec.AttachType, spec.AttachTo,
			spec.AttachTarget != nil, spec.Flags, spec.KernelVersion, spec.License,
			spec.ByteOrder, len(spec.Instructions),
		)
	}
	return nil
}

func isFakeTCPObjectSymbol(name string) bool {
	return strings.Contains(strings.ToLower(name), "faketcp")
}
