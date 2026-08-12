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
		"#pragma clang loop unroll(disable)",
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
		"asm.BuiltinFunc(instruction.Constant) == asm.FnLoop",
		"legacy515FakeTCPKprobeRuntimeMap",
		"unix.BPF_F_RDONLY_PROG",
		"asm.FnSkbChangeType:  2",
		"asm.FnSkbChangeProto: 1",
		"asm.FnSkbPullData:    2",
	} {
		if !strings.Contains(manifest, required) {
			t.Fatalf("legacy object manifest is missing %q", required)
		}
	}
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
	clear := strings.Index(prepare, "index < WG_MIX_FAKETCP_KPROBE_DESCRIPTOR_SIZE / sizeof(__u32)")
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
