package dataplane

import (
	"os"
	"strings"
	"testing"
)

func TestFakeTCPLegacy515ObjectHasIndependentFullGSOBuildContract(t *testing.T) {
	bpfBytes, err := os.ReadFile("../../bpf/wg_mix_faketcp.h")
	if err != nil {
		t.Fatal(err)
	}
	makeBytes, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	manifestBytes, err := os.ReadFile("legacy_515_manifest_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	bpf := string(bpfBytes)
	makefile := string(makeBytes)
	manifest := string(manifestBytes)

	for _, required := range []string{
		"#define FAKETCP_LEGACY_515_FULL_GSO_CAPABILITY 1",
		"#define FAKETCP_LEGACY_515_GSO_MAX_SEGMENTS",
		"#define FAKETCP_LEGACY_515_GSO_MAX_XOR_CHUNKS 4096U",
		"#define FAKETCP_LEGACY_515_ITERATION_MAP_ENTRIES",
		"bpf_for_each_array_elem()",
		"faketcp_legacy_515_iteration_map SEC(\".maps\")",
		"bpf_for_each_map_elem(&faketcp_legacy_515_iteration_map",
		"context->gso_segments + 1U || context->error",
		"xor_chunks + 1U || context->error",
		"index >= FAKETCP_LEGACY_515_GSO_MAX_SEGMENTS",
		"index >= FAKETCP_LEGACY_515_GSO_MAX_XOR_CHUNKS",
		"faketcp_legacy_515_validate_gso_segments(&context)",
		"faketcp_legacy_515_rewrite_gso_types(&context)",
		"faketcp_legacy_515_xor_gso_chunks(&context, xor_chunks)",
		"bpf_loop(context.gso_segments, faketcp_gso_validate_segment",
		"bpf_loop(context.gso_segments, faketcp_gso_rewrite_type",
		"bpf_loop(xor_chunks, faketcp_gso_xor_chunk",
		"wg_mix_faketcp_checksum_kprobe_abi.h",
		"faketcp_kprobe_runtime_map SEC(\".maps\")",
		"BPF_F_RDONLY_PROG",
		"WG_MIX_FAKETCP_KPROBE_PREPARE_MAGIC",
		"WG_MIX_FAKETCP_KPROBE_COMMIT_PROTO_MAGIC",
		"bpf_skb_change_type(",
		"bpf_skb_change_proto(",
		"bpf_skb_pull_data(skb, 0)",
		"runtime->reserved != 0 || ack_window == 0",
		"mutation.window ? mutation.window : 65535",
		"faketcp_commit_udp_gso(",
	} {
		if !strings.Contains(bpf, required) {
			t.Fatalf("FakeTCP BPF source is missing legacy/modern boundary %q", required)
		}
	}
	if count := strings.Count(bpf, "#ifdef WG_MIX_FAKETCP_LEGACY_515"); count < 4 {
		t.Fatalf("legacy source gates=%d, want at least four independent gates", count)
	}

	for _, required := range []string{
		"FAKETCP_LEGACY_515_BPF_OBJECT ?= build/wg_mix_faketcp_legacy_515.o",
		"EMBEDDED_FAKETCP_LEGACY_515_BPF_OBJECT ?= internal/dataplane/embedded/wg_mix_faketcp_legacy_515.o",
		"build-faketcp-legacy-515-bpf:",
		"-DWG_MIX_EXPERIMENTAL_FAKETCP=1",
		"-DWG_MIX_FAKETCP_LEGACY_515=1",
		"WG_MIX_FAKETCP_LEGACY_515_MANIFEST_OBJECT",
	} {
		if !strings.Contains(makefile, required) {
			t.Fatalf("Makefile is missing legacy artifact contract %q", required)
		}
	}
	for _, required := range []string{
		"validateLegacy515ExtensionManifest",
		"instruction.IsKfuncCall()",
		`asm.FnLoop:          "bpf_loop"`,
		`asm.FnXdpLoadBytes:  "bpf_xdp_load_bytes"`,
		`asm.FnXdpStoreBytes: "bpf_xdp_store_bytes"`,
		"legacy515FakeTCPKprobeRuntimeMap",
		"legacy515FakeTCPIterationMap",
		"legacy515FakeTCPIterationMapMaxEntries",
		"legacy515FakeTCPIterationHelperCallCount = 6",
		"asm.FnForEachMapElem",
		"unix.BPF_F_RDONLY_PROG",
		"asm.FnSkbChangeType:  2",
		"asm.FnSkbChangeProto: 1",
		"asm.FnSkbPullData:    2",
	} {
		if !strings.Contains(manifest, required) {
			t.Fatalf("legacy object manifest is missing %q", required)
		}
	}

	legacy := fakeTCPLegacy515PreprocessorView(t, bpf, true)
	modern := fakeTCPLegacy515PreprocessorView(t, bpf, false)
	if count := strings.Count(legacy,
		"bpf_for_each_map_elem(&faketcp_legacy_515_iteration_map"); count != 3 {
		t.Fatalf("legacy-5.15 source map iterator sites=%d, want exactly three", count)
	}
	for _, required := range []string{
		"faketcp_gso_validate_segment, context, 0)",
		"faketcp_gso_rewrite_type, context, 0)",
		"faketcp_gso_xor_chunk, context, 0)",
	} {
		if !strings.Contains(legacy, required) {
			t.Fatalf("legacy-5.15 map iterator path is missing %q", required)
		}
	}
	if strings.Contains(legacy, "bpf_loop(") {
		t.Fatal("legacy-5.15 preprocessor view retains forbidden bpf_loop")
	}
	if count := strings.Count(modern, "bpf_loop("); count != 3 {
		t.Fatalf("modern bpf_loop calls=%d, want exactly three", count)
	}
	if strings.Contains(modern, "bpf_for_each_map_elem(") ||
		strings.Contains(modern, "faketcp_legacy_515_iteration_map") {
		t.Fatal("modern preprocessor view contains legacy map iteration path")
	}
}

func TestFakeTCPLegacy515XDPUsesOnlyDirectPacketAccess(t *testing.T) {
	bpfBytes, err := os.ReadFile("../../bpf/wg_mix_faketcp.h")
	if err != nil {
		t.Fatal(err)
	}
	legacy := fakeTCPLegacy515PreprocessorView(t, string(bpfBytes), true)
	modern := fakeTCPLegacy515PreprocessorView(t, string(bpfBytes), false)

	for _, forbidden := range []string{
		"bpf_xdp_load_bytes(",
		"bpf_xdp_store_bytes(",
	} {
		if strings.Contains(legacy, forbidden) {
			t.Fatalf("legacy-5.15 preprocessor view retains %q", forbidden)
		}
	}
	if count := strings.Count(modern, "bpf_xdp_load_bytes("); count != 4 {
		t.Fatalf("modern XDP load helper calls=%d, want four fixed-size calls", count)
	}
	if count := strings.Count(modern, "bpf_xdp_store_bytes("); count != 3 {
		t.Fatalf("modern XDP store helper calls=%d, want three unchanged calls", count)
	}
	for _, required := range []string{
		"#define FAKETCP_LEGACY_515_XDP_MAX_OFFSET",
		"faketcp_legacy_515_xdp_load_close_packet(",
		"faketcp_xdp_load_ipv4_tcp_snapshot(",
		"faketcp_legacy_515_xdp_load_word(",
		"faketcp_legacy_515_xdp_load_tail(",
		"faketcp_legacy_515_xdp_store_udp(",
		"faketcp_legacy_515_xdp_store_tail(",
		"faketcp_legacy_515_xdp_store_ipv4(",
		"destination[i] = source[i]",
	} {
		if !strings.Contains(legacy, required) {
			t.Fatalf("legacy-5.15 direct packet source is missing %q", required)
		}
	}
	if strings.Contains(modern, "FAKETCP_LEGACY_515_XDP_MAX_OFFSET") ||
		strings.Contains(modern, "faketcp_legacy_515_xdp_load_close_packet(") {
		t.Fatal("modern source view unexpectedly contains legacy direct-copy implementation")
	}
}

func fakeTCPLegacy515PreprocessorView(
	t *testing.T,
	source string,
	legacy bool,
) string {
	t.Helper()
	type frame struct {
		parentInclude bool
		target        bool
		condition     bool
	}
	const macro = "WG_MIX_FAKETCP_LEGACY_515"
	frames := make([]frame, 0, 8)
	include := true
	var output strings.Builder
	for lineNumber, line := range strings.Split(source, "\n") {
		trimmed := strings.TrimSpace(line)
		positive := trimmed == "#ifdef "+macro
		negative := trimmed == "#ifndef "+macro
		switch {
		case positive || negative:
			condition := legacy
			if negative {
				condition = !condition
			}
			frames = append(frames, frame{
				parentInclude: include,
				target:        true,
				condition:     condition,
			})
			include = include && condition
			continue
		case strings.HasPrefix(trimmed, "#if"):
			frames = append(frames, frame{parentInclude: include})
		case trimmed == "#else":
			if len(frames) == 0 {
				t.Fatalf("line %d has unmatched #else", lineNumber+1)
			}
			top := &frames[len(frames)-1]
			if top.target {
				include = top.parentInclude && !top.condition
				top.condition = !top.condition
				continue
			}
		case trimmed == "#endif":
			if len(frames) == 0 {
				t.Fatalf("line %d has unmatched #endif", lineNumber+1)
			}
			top := frames[len(frames)-1]
			frames = frames[:len(frames)-1]
			include = top.parentInclude
			if top.target {
				continue
			}
		}
		if include {
			output.WriteString(line)
			output.WriteByte('\n')
		}
	}
	if len(frames) != 0 {
		t.Fatalf("preprocessor view ended with %d open conditionals", len(frames))
	}
	return output.String()
}

func TestFakeTCPLegacy515PrepareRefreshesVerifierPacketPointers(t *testing.T) {
	bpfBytes, err := os.ReadFile("../../bpf/wg_mix_faketcp.h")
	if err != nil {
		t.Fatal(err)
	}
	bpf := string(bpfBytes)
	start := strings.Index(bpf, "faketcp_prepare_udp(struct __sk_buff *skb")
	if start < 0 {
		t.Fatal("cannot find FakeTCP prepare wrapper")
	}
	end := strings.Index(bpf[start:], "faketcp_commit_udp_gso(struct __sk_buff *skb")
	if end < 0 {
		t.Fatal("cannot isolate FakeTCP prepare wrapper")
	}
	prepare := bpf[start : start+end]
	trigger := strings.Index(prepare, "result = bpf_skb_change_type(")
	clear := strings.Index(prepare, "faketcp_clear_kprobe_descriptor(skb);")
	refresh := strings.Index(prepare, "if (bpf_skb_pull_data(skb, 0) < 0)")
	classify := strings.Index(prepare, "if (expect_gso)")
	if trigger < 0 || clear <= trigger || refresh <= clear || classify <= refresh {
		t.Fatalf(
			"legacy prepare order trigger=%d clear=%d refresh=%d classify=%d",
			trigger, clear, refresh, classify,
		)
	}
	if count := strings.Count(prepare, "bpf_skb_pull_data(skb, 0)"); count != 1 {
		t.Fatalf("legacy prepare source refresh calls=%d, want one in the inlined wrapper", count)
	}
	if !strings.Contains(prepare[refresh:classify],
		"result = FAKETCP_PREPARE_REJECT_WRITABLE;") {
		t.Fatal("legacy prepare refresh failure is not classified fail-closed")
	}
}

func TestFakeTCPLegacy515DescriptorCleanupUsesFreshVerifierContext(t *testing.T) {
	bpfBytes, err := os.ReadFile("../../bpf/wg_mix_faketcp.h")
	if err != nil {
		t.Fatal(err)
	}
	bpf := string(bpfBytes)
	clearStart := strings.Index(bpf,
		"static __noinline void\nfaketcp_clear_kprobe_descriptor(struct __sk_buff *skb)")
	if clearStart < 0 {
		t.Fatal("legacy descriptor cleanup is not a noinline BPF subprogram")
	}
	clearEnd := strings.Index(bpf[clearStart:], "static __always_inline int\nfaketcp_prepare_udp(")
	if clearEnd < 0 {
		t.Fatal("cannot isolate legacy descriptor cleanup subprogram")
	}
	clear := bpf[clearStart : clearStart+clearEnd]
	for _, want := range []string{
		"skb->cb[0] = 0;", "skb->cb[1] = 0;", "skb->cb[2] = 0;",
		"skb->cb[3] = 0;", "skb->cb[4] = 0;",
	} {
		if !strings.Contains(clear, want) {
			t.Fatalf("legacy descriptor cleanup is missing %q", want)
		}
	}
	if strings.Contains(clear, "for (") || strings.Contains(clear, "\tbpf_") {
		t.Fatal("legacy descriptor cleanup must remain stackless and helper-free")
	}

	commitStart := strings.Index(bpf, "faketcp_commit_udp_gso(struct __sk_buff *skb")
	if commitStart < 0 {
		t.Fatal("cannot find FakeTCP commit wrapper")
	}
	commitEnd := strings.Index(bpf[commitStart:], "static __always_inline struct faketcp_runtime_identity_value *")
	if commitEnd < 0 {
		t.Fatal("cannot isolate FakeTCP commit wrapper")
	}
	commit := bpf[commitStart : commitStart+commitEnd]
	trigger := strings.Index(commit, "result = bpf_skb_change_proto(")
	clearCall := strings.LastIndex(commit, "faketcp_clear_kprobe_descriptor(skb);")
	if trigger < 0 || clearCall <= trigger {
		t.Fatalf("legacy commit must clear through a fresh ctx boundary: trigger=%d clear=%d", trigger, clearCall)
	}
}
