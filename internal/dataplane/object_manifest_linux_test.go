//go:build linux

package dataplane

import (
	"encoding/binary"
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

const (
	baselineManifestObjectEnv     = "WG_MIX_BASELINE_MANIFEST_OBJECT"
	experimentalManifestObjectEnv = "WG_MIX_FAKETCP_MANIFEST_OBJECT"
	legacy515ManifestObjectEnv    = "WG_MIX_FAKETCP_LEGACY_515_MANIFEST_OBJECT"
)

// TestBuiltBPFObjectManifests is opt-in so ordinary unit tests do not require
// clang. CI and the Make target provide both freshly compiled object paths.
func TestBuiltBPFObjectManifests(t *testing.T) {
	baselinePath := os.Getenv(baselineManifestObjectEnv)
	experimentalPath := os.Getenv(experimentalManifestObjectEnv)
	legacy515Path := os.Getenv(legacy515ManifestObjectEnv)
	if baselinePath == "" && experimentalPath == "" && legacy515Path == "" {
		t.Skip("compiled BPF object paths are not configured")
	}
	if baselinePath == "" || experimentalPath == "" || legacy515Path == "" {
		t.Fatalf(
			"%s, %s, and %s are required",
			baselineManifestObjectEnv,
			experimentalManifestObjectEnv,
			legacy515ManifestObjectEnv,
		)
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

	legacy515, _, err := loadCollectionSpec(legacy515Path)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateLegacy515ExtensionManifest(legacy515); err != nil {
		t.Fatalf("fresh legacy-5.15 object violates exact extension manifest: %v", err)
	}
}

func TestLegacy515ManifestIsIndependentAndRejectsPost515Calls(t *testing.T) {
	legacy515 := canonicalLegacy515CollectionSpec()
	if err := validateLegacy515ExtensionManifest(legacy515); err != nil {
		t.Fatalf("exact legacy-5.15 manifest rejected: %v", err)
	}
	if err := validateExperimentalExtensionManifest(legacy515); err == nil {
		t.Fatal("modern FakeTCP manifest accepted the legacy-5.15 object")
	}

	modern := canonicalExperimentalCollectionSpec()
	if err := validateLegacy515ExtensionManifest(modern); err == nil {
		t.Fatal("legacy-5.15 manifest accepted modern kfunc relocations")
	}

	loop := canonicalLegacy515CollectionSpec()
	loopCall := asm.FnLoop.Call()
	loop.Programs["wg_mix_egress"].Instructions = asm.Instructions{
		loopCall,
		asm.Return(),
	}
	if err := validateLegacy515ExtensionManifest(loop); err == nil ||
		!strings.Contains(err.Error(), "forbidden bpf_loop") {
		t.Fatalf("legacy-5.15 manifest accepted bpf_loop: %v", err)
	}
	for _, test := range []struct {
		name       string
		helper     asm.BuiltinFunc
		helperName string
	}{
		{name: "XDP load bytes", helper: asm.FnXdpLoadBytes, helperName: "bpf_xdp_load_bytes"},
		{name: "XDP store bytes", helper: asm.FnXdpStoreBytes, helperName: "bpf_xdp_store_bytes"},
	} {
		t.Run(test.name, func(t *testing.T) {
			spec := canonicalLegacy515CollectionSpec()
			spec.Programs["wg_mix_faketcp_ingress"].Instructions = asm.Instructions{
				test.helper.Call(),
				asm.Return(),
			}
			err := validateLegacy515ExtensionManifest(spec)
			if err == nil || !strings.Contains(err.Error(), "forbidden "+test.helperName) {
				t.Fatalf("legacy-5.15 manifest accepted %s: %v", test.helperName, err)
			}
		})
	}

	missingCookie := canonicalLegacy515CollectionSpec()
	delete(missingCookie.Maps, legacy515FakeTCPKprobeRuntimeMap)
	if err := validateLegacy515ExtensionManifest(missingCookie); err == nil ||
		!strings.Contains(err.Error(), legacy515FakeTCPKprobeRuntimeMap) {
		t.Fatalf("legacy-5.15 manifest accepted missing cookie map: %v", err)
	}

	mutableFromBPF := canonicalLegacy515CollectionSpec()
	mutableFromBPF.Maps[legacy515FakeTCPKprobeRuntimeMap].Flags = 0
	if err := validateLegacy515ExtensionManifest(mutableFromBPF); err == nil ||
		!strings.Contains(err.Error(), legacy515FakeTCPKprobeRuntimeMap) {
		t.Fatalf("legacy-5.15 manifest accepted BPF-writable cookie map: %v", err)
	}

	missingPrepare := canonicalLegacy515CollectionSpec()
	var withoutPrepare asm.Instructions
	removed := false
	for _, instruction := range missingPrepare.Programs["wg_mix_egress"].Instructions {
		if !removed && instruction.IsBuiltinCall() &&
			asm.BuiltinFunc(instruction.Constant) == asm.FnSkbChangeType {
			removed = true
			continue
		}
		withoutPrepare = append(withoutPrepare, instruction)
	}
	missingPrepare.Programs["wg_mix_egress"].Instructions = withoutPrepare
	if err := validateLegacy515ExtensionManifest(missingPrepare); err == nil ||
		!strings.Contains(err.Error(), "want exactly 2") {
		t.Fatalf("legacy-5.15 manifest accepted missing prepare trigger: %v", err)
	}

	missingRefresh := canonicalLegacy515CollectionSpec()
	var withoutRefresh asm.Instructions
	removed = false
	for _, instruction := range missingRefresh.Programs["wg_mix_egress"].Instructions {
		if !removed && instruction.IsBuiltinCall() &&
			asm.BuiltinFunc(instruction.Constant) == asm.FnSkbPullData {
			removed = true
			continue
		}
		withoutRefresh = append(withoutRefresh, instruction)
	}
	missingRefresh.Programs["wg_mix_egress"].Instructions = withoutRefresh
	if err := validateLegacy515ExtensionManifest(missingRefresh); err == nil ||
		!strings.Contains(err.Error(), "want exactly 2") {
		t.Fatalf("legacy-5.15 manifest accepted missing verifier refresh: %v", err)
	}

	wrongCaller := canonicalLegacy515CollectionSpec()
	wrongCaller.Programs["wg_faketcp_egress"].Instructions = asm.Instructions{
		asm.FnSkbChangeProto.Call(), asm.Return(),
	}
	if err := validateLegacy515ExtensionManifest(wrongCaller); err == nil ||
		!strings.Contains(err.Error(), "unreviewed program") {
		t.Fatalf("legacy-5.15 manifest accepted trigger on wrong program: %v", err)
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
			name: "kfunc caller program type",
			mutate: func(spec *ebpf.CollectionSpec) {
				spec.Programs["wg_mix_egress"].Type = ebpf.XDP
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
				spec.Programs["wg_faketcp_egress"].License = "MIT"
			},
		},
		{
			name: "missing required kfunc relocation",
			mutate: func(spec *ebpf.CollectionSpec) {
				spec.Programs["wg_mix_egress"].Instructions = asm.Instructions{asm.Return()}
			},
		},
		{
			name: "required kfunc on wrong program",
			mutate: func(spec *ebpf.CollectionSpec) {
				call := spec.Programs["wg_mix_egress"].Instructions[0]
				spec.Programs["wg_mix_egress"].Instructions = asm.Instructions{asm.Return()}
				spec.Programs["wg_faketcp_egress"].Instructions = asm.Instructions{call, asm.Return()}
			},
		},
		{
			name: "unreviewed kfunc relocation",
			mutate: func(spec *ebpf.CollectionSpec) {
				call := asm.Call.Label("unreviewed_kfunc")
				call.Src = asm.PseudoKfuncCall
				spec.Programs["wg_mix_egress"].Instructions = append(
					spec.Programs["wg_mix_egress"].Instructions,
					call,
				)
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
	for _, requiredName := range experimentalFakeTCPKfuncNames {
		name := requiredName
		tests = append(tests, struct {
			name   string
			mutate func(*ebpf.CollectionSpec)
		}{
			name: "missing exact kfunc " + name,
			mutate: func(spec *ebpf.CollectionSpec) {
				program := spec.Programs["wg_mix_egress"]
				filtered := make(asm.Instructions, 0, len(program.Instructions)-1)
				for _, instruction := range program.Instructions {
					if !instruction.IsKfuncCall() || instruction.Reference() != name {
						filtered = append(filtered, instruction)
					}
				}
				program.Instructions = filtered
			},
		})
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
	baseline := canonicalObjectManifestCollectionSpec()
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

func TestBaselineLoaderPreflightRejectsExperimentalObjectBeforeKernelLoad(t *testing.T) {
	baseline := canonicalObjectManifestCollectionSpec()
	if err := validateBaselineLoaderCollectionSpec(baseline, "baseline-test.o"); err != nil {
		t.Fatalf("baseline loader preflight rejected canonical object: %v", err)
	}

	experimental := canonicalExperimentalCollectionSpec()
	err := validateBaselineLoaderCollectionSpec(experimental, "experimental-test.o")
	if err == nil {
		t.Fatal("baseline loader preflight accepted the experimental object")
	}
	for _, want := range []string{
		"experimental-test.o",
		"unexpected maps outside its manifest",
		fakeTCPSessionMapName,
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("baseline loader preflight error missing %q: %v", want, err)
		}
	}
}

func canonicalExperimentalCollectionSpec() *ebpf.CollectionSpec {
	spec := canonicalObjectManifestCollectionSpec()
	for _, program := range spec.Programs {
		program.License = experimentalFakeTCPLicense
	}
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
	instructions := make(asm.Instructions, 0, 4)
	for _, name := range experimentalFakeTCPKfuncNames {
		for range experimentalFakeTCPKfuncRelocationCounts[name] {
			call := asm.Call.Label(name)
			call.Src = asm.PseudoKfuncCall
			instructions = append(instructions, call)
		}
	}
	spec.Programs["wg_mix_egress"].Instructions = append(instructions, asm.Return())
	return spec
}

func canonicalLegacy515CollectionSpec() *ebpf.CollectionSpec {
	spec := canonicalExperimentalCollectionSpec()
	descriptor := legacy515FakeTCPKprobeRuntimeMapDescriptor()
	spec.Maps[descriptor.name] = &ebpf.MapSpec{
		Name:       descriptor.name,
		Type:       descriptor.mapType,
		KeySize:    descriptor.keySize,
		ValueSize:  descriptor.valueSize,
		MaxEntries: descriptor.maxEntries,
		Flags:      descriptor.flags,
		Pinning:    ebpf.PinNone,
	}
	var instructions asm.Instructions
	for helper, count := range legacy515FakeTCPTriggerHelperCounts {
		for range count {
			instructions = append(instructions, helper.Call())
		}
	}
	spec.Programs["wg_mix_egress"].Instructions = append(instructions, asm.Return())
	return spec
}

func canonicalObjectManifestCollectionSpec() *ebpf.CollectionSpec {
	spec := &ebpf.CollectionSpec{
		Maps:     make(map[string]*ebpf.MapSpec),
		Programs: make(map[string]*ebpf.ProgramSpec),
	}
	for _, descriptor := range baselineMapDescriptors() {
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
	for _, descriptor := range baselineProgramDescriptors() {
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
