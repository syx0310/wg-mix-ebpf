//go:build linux

package dataplane

import (
	"encoding/binary"
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
			name: "unknown map",
			mutate: func(spec *ebpf.CollectionSpec) {
				spec.Maps["unreviewed_experimental_map"] = &ebpf.MapSpec{
					Name: "unreviewed_experimental_map",
				}
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
		{
			name: "unknown program",
			mutate: func(spec *ebpf.CollectionSpec) {
				spec.Programs["unreviewed_experimental_program"] = &ebpf.ProgramSpec{
					Name: "unreviewed_experimental_program",
				}
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

func TestBaselineAndExperimentalManifestsAreMutuallyExclusive(t *testing.T) {
	baseline := canonicalPinnedMapCollectionSpec()
	if err := validateBaselineCollectionSpec(baseline); err != nil {
		t.Fatalf("baseline manifest rejected its canonical object: %v", err)
	}
	if err := validateExperimentalExtensionManifest(baseline); err == nil {
		t.Fatal("experimental manifest accepted the baseline-only object")
	}

	experimental := canonicalExperimentalCollectionSpec()
	if err := validateExperimentalExtensionManifest(experimental); err != nil {
		t.Fatalf("experimental manifest rejected its canonical object: %v", err)
	}
	if err := validateBaselineCollectionSpec(experimental); err == nil {
		t.Fatal("baseline manifest accepted the experimental extension object")
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
