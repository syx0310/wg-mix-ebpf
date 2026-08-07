//go:build linux

package dataplane

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

const (
	baselineManifestObjectEnv     = "WG_MIX_BASELINE_MANIFEST_OBJECT"
	experimentalManifestObjectEnv = "WG_MIX_FAKETCP_MANIFEST_OBJECT"
)

// TestBuiltBPFObjectManifests is opt-in so ordinary unit tests do not require
// clang. CI and the Make target provide both freshly compiled object paths.
func TestBuiltBPFObjectManifests(t *testing.T) {
	baselinePath := os.Getenv(baselineManifestObjectEnv)
	experimentalPath := os.Getenv(experimentalManifestObjectEnv)
	if baselinePath == "" && experimentalPath == "" {
		t.Skip("compiled BPF object paths are not configured")
	}
	if baselinePath == "" || experimentalPath == "" {
		t.Fatalf("both %s and %s are required", baselineManifestObjectEnv, experimentalManifestObjectEnv)
	}

	baseline, _, err := loadCollectionSpec(baselinePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateBaselineCollectionSpec(baseline); err != nil {
		t.Fatalf("fresh baseline object violates exact manifest: %v", err)
	}

	experimental, _, err := loadCollectionSpec(experimentalPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateExperimentalExtensionManifest(experimental); err != nil {
		t.Fatalf("fresh experimental object violates exact extension manifest: %v", err)
	}
}

func experimentalMapDescriptors() []pinnedMapDescriptor {
	return []pinnedMapDescriptor{
		{name: "faketcp_session_map", mapType: ebpf.Hash, keySize: 24, valueSize: 40, maxEntries: 16384},
		{name: "faketcp_managed_if_map", mapType: ebpf.Hash, keySize: 16, valueSize: 8, maxEntries: 512},
		{name: "faketcp_managed_port_map", mapType: ebpf.Hash, keySize: 16, valueSize: 16, maxEntries: 2048},
		{name: "faketcp_control_policy_map", mapType: ebpf.Hash, keySize: 16, valueSize: 32, maxEntries: 512},
		{name: "faketcp_control_flow_map", mapType: ebpf.LRUHash, keySize: 32, valueSize: 16, maxEntries: 16384},
		{name: "faketcp_events", mapType: ebpf.RingBuf, maxEntries: 1 << 20},
		{name: "faketcp_capture_scratch", mapType: ebpf.PerCPUArray, keySize: 4, valueSize: 2360, maxEntries: 1},
		{name: "faketcp_egress_programs", mapType: ebpf.ProgramArray, keySize: 4, valueSize: 4, maxEntries: 2},
		{name: "faketcp_stats_map", mapType: ebpf.PerCPUArray, keySize: 4, valueSize: 8, maxEntries: 12},
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

func TestExperimentalManifestRejectsSchemaAndMetadataDrift(t *testing.T) {
	canonical := canonicalExperimentalCollectionSpec()
	if got := canonical.Programs["wg_mix_faketcp_ingress"].AttachType; got != ebpf.AttachXDP {
		t.Fatalf("FakeTCP ingress attach type = %d, want AttachXDP", got)
	}
	if got := canonical.Programs["wg_faketcp_egress"].AttachType; got != ebpf.AttachNone {
		t.Fatalf("FakeTCP egress attach type = %d, want AttachNone", got)
	}
	if err := validateExperimentalExtensionManifest(canonical); err != nil {
		t.Fatalf("exact experimental manifest rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*ebpf.CollectionSpec)
	}{
		{
			name: "map type",
			mutate: func(spec *ebpf.CollectionSpec) {
				spec.Maps["faketcp_session_map"].Type = ebpf.LRUHash
			},
		},
		{
			name: "map key size",
			mutate: func(spec *ebpf.CollectionSpec) {
				spec.Maps["faketcp_session_map"].KeySize++
			},
		},
		{
			name: "map value size",
			mutate: func(spec *ebpf.CollectionSpec) {
				spec.Maps["faketcp_session_map"].ValueSize++
			},
		},
		{
			name: "map capacity",
			mutate: func(spec *ebpf.CollectionSpec) {
				spec.Maps["faketcp_session_map"].MaxEntries++
			},
		},
		{
			name: "map flags",
			mutate: func(spec *ebpf.CollectionSpec) {
				spec.Maps["faketcp_session_map"].Flags = 1
			},
		},
		{
			name: "map pinning",
			mutate: func(spec *ebpf.CollectionSpec) {
				spec.Maps["faketcp_session_map"].Pinning = ebpf.PinByName
			},
		},
		{
			name: "map creation metadata",
			mutate: func(spec *ebpf.CollectionSpec) {
				spec.Maps["faketcp_session_map"].Tags = []string{"unreviewed"}
			},
		},
		{
			name: "program kernel name",
			mutate: func(spec *ebpf.CollectionSpec) {
				spec.Programs["wg_faketcp_egress"].Name = "renamed"
			},
		},
		{
			name: "program section",
			mutate: func(spec *ebpf.CollectionSpec) {
				spec.Programs["wg_faketcp_egress"].SectionName = "classifier/other"
			},
		},
		{
			name: "program type",
			mutate: func(spec *ebpf.CollectionSpec) {
				spec.Programs["wg_faketcp_egress"].Type = ebpf.XDP
			},
		},
		{
			name: "program interface",
			mutate: func(spec *ebpf.CollectionSpec) {
				spec.Programs["wg_faketcp_egress"].Ifindex = 1
			},
		},
		{
			name: "egress program attach type",
			mutate: func(spec *ebpf.CollectionSpec) {
				spec.Programs["wg_faketcp_egress"].AttachType = ebpf.AttachXDP
			},
		},
		{
			name: "ingress program attach type",
			mutate: func(spec *ebpf.CollectionSpec) {
				spec.Programs["wg_mix_faketcp_ingress"].AttachType = ebpf.AttachNone
			},
		},
		{
			name: "program attach name",
			mutate: func(spec *ebpf.CollectionSpec) {
				spec.Programs["wg_faketcp_egress"].AttachTo = "unreviewed"
			},
		},
		{
			name: "program attach target",
			mutate: func(spec *ebpf.CollectionSpec) {
				spec.Programs["wg_faketcp_egress"].AttachTarget = new(ebpf.Program)
			},
		},
		{
			name: "program flags",
			mutate: func(spec *ebpf.CollectionSpec) {
				spec.Programs["wg_faketcp_egress"].Flags = 1
			},
		},
		{
			name: "program kernel version",
			mutate: func(spec *ebpf.CollectionSpec) {
				spec.Programs["wg_faketcp_egress"].KernelVersion = 1
			},
		},
		{
			name: "program license",
			mutate: func(spec *ebpf.CollectionSpec) {
				spec.Programs["wg_faketcp_egress"].License = "GPL"
			},
		},
		{
			name: "program byte order",
			mutate: func(spec *ebpf.CollectionSpec) {
				spec.Programs["wg_faketcp_egress"].ByteOrder = binary.BigEndian
			},
		},
		{
			name: "program instructions",
			mutate: func(spec *ebpf.CollectionSpec) {
				spec.Programs["wg_faketcp_egress"].Instructions = nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := canonicalExperimentalCollectionSpec()
			tt.mutate(spec)
			if err := validateExperimentalExtensionManifest(spec); err == nil {
				t.Fatal("manifest drift was accepted")
			}
		})
	}
}

func canonicalExperimentalCollectionSpec() *ebpf.CollectionSpec {
	spec := canonicalPinnedMapCollectionSpec()
	for _, descriptor := range experimentalMapDescriptors() {
		spec.Maps[descriptor.name] = &ebpf.MapSpec{
			Name:       descriptor.name,
			Type:       descriptor.mapType,
			KeySize:    descriptor.keySize,
			ValueSize:  descriptor.valueSize,
			MaxEntries: descriptor.maxEntries,
			Flags:      descriptor.flags,
			Pinning:    ebpf.PinNone,
		}
	}
	for _, descriptor := range experimentalProgramDescriptors() {
		spec.Programs[descriptor.name] = &ebpf.ProgramSpec{
			Name:          descriptor.name,
			Type:          descriptor.programType,
			Ifindex:       descriptor.ifindex,
			AttachType:    descriptor.attachType,
			AttachTo:      descriptor.attachTo,
			SectionName:   descriptor.sectionName,
			Instructions:  asm.Instructions{asm.Return()},
			Flags:         descriptor.flags,
			License:       descriptor.license,
			KernelVersion: descriptor.kernelVersion,
			ByteOrder:     binary.LittleEndian,
		}
	}
	return spec
}
