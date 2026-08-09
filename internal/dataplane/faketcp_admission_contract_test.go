package dataplane

import (
	"os"
	"strings"
	"testing"
)

func TestFakeTCPAdmissionCheckpointDominatesEveryTransform(t *testing.T) {
	tcBytes, err := os.ReadFile("../../bpf/wg_mix_tc.c")
	if err != nil {
		t.Fatal(err)
	}
	fakeBytes, err := os.ReadFile("../../bpf/wg_mix_faketcp.h")
	if err != nil {
		t.Fatal(err)
	}
	tc := string(tcBytes)
	fake := string(fakeBytes)

	egress := sourceSection(t, tc, "int wg_mix_egress(struct __sk_buff *skb)", "SEC(\"classifier/ingress\")")
	if !strings.Contains(egress, "if (!managed)\n\t\treturn TC_ACT_OK;") ||
		!strings.Contains(egress, "!= FAKETCP_ADMISSION_TRANSFORM)\n\t\t\treturn TC_ACT_SHOT;") {
		t.Fatal("TC egress does not state explicit unmanaged-pass and managed-reject-drop policy")
	}
	if got := strings.Count(egress, "faketcp_egress_admission_checkpoint("); got != 1 {
		t.Fatalf("TC egress checkpoint calls=%d, want exactly one", got)
	}
	checkpoint := strings.Index(egress, "faketcp_egress_admission_checkpoint(")
	checksumState := strings.Index(egress, "faketcp_inspect_and_reset_udp_checksum(")
	typeWord := strings.Index(egress, "update_type_word(skb, &info, old_wire, new_wire, 1)")
	xorDispatch := strings.Index(egress, "bpf_tail_call(skb, &xor_egress_programs")
	directEncode := strings.Index(egress, "return faketcp_encode_established(skb, &info, rule, generation,")
	if checkpoint < 0 || checksumState < 0 || typeWord < 0 || xorDispatch < 0 || directEncode < 0 ||
		!(checkpoint < checksumState && checksumState < typeWord && typeWord < xorDispatch && typeWord < directEncode) {
		t.Fatal("TC admission proof does not dominate checksum, type-word, XOR and FakeTCP transforms")
	}

	checkpointBody := sourceSection(t, fake,
		"static __always_inline int faketcp_egress_admission_checkpoint(",
		"static __always_inline __s64 faketcp_rotation_checksum")
	for _, mutation := range []string{
		"bpf_skb_store_bytes(", "bpf_skb_change_tail(", "bpf_l3_csum_replace(",
		"bpf_l4_csum_replace(", "wg_mix_faketcp_skb_normalize_udp_csum(",
	} {
		if strings.Contains(checkpointBody, mutation) {
			t.Fatalf("egress checkpoint mutates packet/checksum state through %q", mutation)
		}
	}

	xor := sourceSection(t, tc,
		"static __always_inline int run_xor_egress_segment", "static __always_inline int run_xor_ingress_segment")
	proofBranch := strings.Index(xor, "if (context.continue_faketcp)")
	tailCall := strings.Index(xor, "bpf_tail_call(skb, &faketcp_egress_programs")
	failure := strings.LastIndex(xor, "xor_dispatch_fail(skb, STAT_XOR_EGRESS_DISPATCH_ERROR)")
	if proofBranch < 0 || tailCall < 0 || failure < 0 || !(proofBranch < tailCall && tailCall < failure) {
		t.Fatal("XOR continuation must carry its existing bounded context proof through the tail call")
	}
	continuation := sourceSection(t, fake,
		"static __always_inline int faketcp_continue_egress", "SEC(\"classifier/faketcp_egress\")")
	consume := strings.Index(continuation, "load_xor_context(skb, &proof)")
	clear := strings.Index(continuation, "clear_xor_context(skb)")
	encode := strings.Index(continuation, "faketcp_encode_established(")
	if consume < 0 || clear < 0 || encode < 0 || !(consume < clear && clear < encode) {
		t.Fatal("FakeTCP tail-call program can reach the encoder without consuming its proof")
	}

	xdp := sourceSection(t, fake, "int wg_mix_faketcp_ingress(struct xdp_md *xdp)", "#endif")
	xdpCheckpoint := strings.Index(xdp, "faketcp_xdp_admission_checkpoint(")
	if xdpCheckpoint < 0 {
		t.Fatal("XDP admission checkpoint is missing")
	}
	if !strings.Contains(xdp, "if (!listener)\n\t\treturn XDP_PASS;") ||
		!strings.Contains(xdp, "admission_decision == FAKETCP_ADMISSION_DROP") {
		t.Fatal("XDP does not state explicit unmanaged-pass and managed-reject-drop policy")
	}
	for _, mutation := range []string{
		"bpf_xdp_adjust_meta(", "bpf_xdp_store_bytes(", "bpf_xdp_adjust_tail(",
	} {
		at := strings.Index(xdp, mutation)
		if at < 0 || xdpCheckpoint >= at {
			t.Fatalf("XDP checkpoint does not dominate %q", mutation)
		}
	}

	ingress := sourceSection(t, tc, "int wg_mix_ingress(struct __sk_buff *skb)", "char LICENSE[]")
	proof := strings.Index(ingress, "faketcp_consume_ingress_admission(")
	xorMetadata := strings.Index(ingress, "load_xor_ingress_metadata(")
	typeRestore := strings.Index(ingress, "update_type_word(skb, &info, encrypted_wire, new_wire, 0)")
	if proof < 0 || xorMetadata < 0 || typeRestore < 0 || !(proof < xorMetadata && xorMetadata < typeRestore) {
		t.Fatal("TC ingress can transform a packet before consuming the XDP proof")
	}
}

func TestFakeTCPAdmissionProofBindsFullIdentityAndCapabilityStaysClosed(t *testing.T) {
	source, err := os.ReadFile("../../bpf/wg_mix_faketcp.h")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, want := range []string{
		"metadata->direction = FAKETCP_DIRECTION_INGRESS",
		"metadata->generation_high = (__u32)(generation >> 32)",
		"metadata->local_ipv4 = key.local_ipv4",
		"metadata->generation_high != (__u32)(generation >> 32)",
		"load_xor_context(skb, &proof)",
		"proof.generation != generation",
		"FAKETCP_STAT_ADMISSION_BYPASS_REJECT",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("admission identity/observability contract missing %q", want)
		}
	}
	if fakeTCPImplementedCapabilities&fakeTCPCapabilityAdmissionCheckpoint != 0 {
		t.Fatal("AdmissionCheckpoint capability opened before unique review and required live evidence")
	}
}
