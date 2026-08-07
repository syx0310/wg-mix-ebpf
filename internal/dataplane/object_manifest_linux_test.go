//go:build linux

package dataplane

import (
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
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
	wantExtraMaps := map[string]ebpf.MapType{
		"faketcp_session_map":      ebpf.Hash,
		"faketcp_managed_if_map":   ebpf.Hash,
		"faketcp_managed_port_map": ebpf.Hash,
		"faketcp_events":           ebpf.RingBuf,
		"faketcp_capture_scratch":  ebpf.PerCPUArray,
		"faketcp_egress_programs":  ebpf.ProgramArray,
		"faketcp_stats_map":        ebpf.PerCPUArray,
	}
	wantExtraPrograms := map[string]baselineProgramDescriptor{
		"wg_faketcp_egress": {
			name: "wg_faketcp_egress", sectionName: "classifier/faketcp_egress", programType: ebpf.SchedCLS,
		},
		"wg_mix_faketcp_ingress": {
			name: "wg_mix_faketcp_ingress", sectionName: "xdp", programType: ebpf.XDP,
		},
	}
	experimentalCore := experimental.Copy()
	for name := range wantExtraMaps {
		delete(experimentalCore.Maps, name)
	}
	for name := range wantExtraPrograms {
		delete(experimentalCore.Programs, name)
	}
	if err := validateBaselineCollectionSpec(experimentalCore); err != nil {
		t.Fatalf("experimental object does not preserve the exact baseline core: %v", err)
	}
	baselineMaps := make(map[string]struct{})
	for _, descriptor := range baselineMapDescriptors() {
		baselineMaps[descriptor.name] = struct{}{}
	}
	baselinePrograms := make(map[string]struct{})
	for _, descriptor := range baselineProgramDescriptors() {
		baselinePrograms[descriptor.name] = struct{}{}
	}
	var unexpected []string
	seenMaps := make(map[string]struct{}, len(wantExtraMaps))
	for name, spec := range experimental.Maps {
		if _, core := baselineMaps[name]; core {
			continue
		}
		wantType, ok := wantExtraMaps[name]
		if !ok || spec == nil || spec.Type != wantType {
			unexpected = append(unexpected, "map:"+name)
			continue
		}
		seenMaps[name] = struct{}{}
	}
	seenPrograms := make(map[string]struct{}, len(wantExtraPrograms))
	for name, spec := range experimental.Programs {
		if _, core := baselinePrograms[name]; core {
			continue
		}
		want, ok := wantExtraPrograms[name]
		if !ok || spec == nil || spec.Name != want.name || spec.SectionName != want.sectionName || spec.Type != want.programType {
			unexpected = append(unexpected, "program:"+name)
			continue
		}
		seenPrograms[name] = struct{}{}
	}
	for name := range wantExtraMaps {
		if _, ok := seenMaps[name]; !ok {
			unexpected = append(unexpected, "missing-map:"+name)
		}
	}
	for name := range wantExtraPrograms {
		if _, ok := seenPrograms[name]; !ok {
			unexpected = append(unexpected, "missing-program:"+name)
		}
	}
	if len(unexpected) != 0 {
		sort.Strings(unexpected)
		t.Fatalf("experimental BPF object differs from reviewed extension manifest: %s", strings.Join(unexpected, ", "))
	}
}
