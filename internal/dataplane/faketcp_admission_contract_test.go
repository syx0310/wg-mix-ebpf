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
		t.Fatalf("TC non-GSO checkpoint calls=%d, want exactly one", got)
	}
	egressParse := strings.Index(egress, "faketcp_parse_tc_egress_packet(skb, generation, &faketcp_packet)")
	l3Gate := strings.Index(egress, "faketcp_tc_fixed_udp_status(&faketcp_packet)")
	prepare := strings.Index(egress, "if (faketcp_prepare_udp(")
	checkpoint := strings.Index(egress, "faketcp_egress_admission_checkpoint(")
	typeWord := strings.Index(egress, "update_type_word(skb, info, old_wire, new_wire, 1)")
	xorDispatch := strings.Index(egress, "bpf_tail_call(skb, &xor_egress_programs")
	directEncode := strings.Index(egress, "return faketcp_encode_established(")
	if egressParse < 0 || l3Gate < 0 || prepare < 0 || checkpoint < 0 || typeWord < 0 || xorDispatch < 0 || directEncode < 0 ||
		!(egressParse < l3Gate && l3Gate < prepare && prepare < checkpoint && checkpoint < typeWord && typeWord < xorDispatch && typeWord < directEncode) {
		t.Fatal("TC fixed-IPv4 and unified prepare gates must precede the proof which dominates every non-GSO transform")
	}

	checkpointBody := sourceSection(t, fake,
		"static __always_inline int faketcp_egress_admission_checkpoint(",
		"struct faketcp_gso_loop_context {")
	for _, mutation := range []string{
		"bpf_skb_store_bytes(", "bpf_skb_change_tail(", "bpf_l3_csum_replace(",
		"bpf_l4_csum_replace(", "wg_mix_faketcp_skb_prepare_udp(",
	} {
		if strings.Contains(checkpointBody, mutation) {
			t.Fatalf("egress checkpoint mutates packet/checksum state through %q", mutation)
		}
	}

	xor := sourceSection(t, tc,
		"static __always_inline int run_xor_egress_segment", "static __always_inline int run_xor_ingress_segment")
	proofLookup := strings.Index(xor, "faketcp_bind_egress_xor_progress(&context)")
	xorWrite := strings.Index(xor, "xor_segment_")
	complete := strings.Index(xor, "faketcp_complete_egress_xor(context.admission_nonce)")
	tailCall := strings.Index(xor, "bpf_tail_call(skb, &faketcp_egress_programs")
	discard := -1
	if tailCall >= 0 {
		discard = strings.Index(xor[tailCall:], "faketcp_consume_egress_admission(context.admission_nonce, 0)")
	}
	failure := strings.LastIndex(xor, "xor_dispatch_fail(skb, STAT_XOR_EGRESS_DISPATCH_ERROR)")
	if proofLookup < 0 || xorWrite < 0 || complete < 0 || tailCall < 0 || discard < 0 || failure < 0 ||
		!(proofLookup < xorWrite && xorWrite < complete && complete < tailCall && tailCall < tailCall+discard && tailCall+discard < failure) {
		t.Fatal("XOR must read the active token before mutation, CAS completion before continuation, and discard on tail miss")
	}
	continuation := sourceSection(t, fake,
		"static __always_inline int faketcp_continue_egress", "SEC(\"classifier/faketcp_egress\")")
	load := strings.Index(continuation, "load_xor_context(skb, &progress)")
	consume := strings.Index(continuation, "faketcp_consume_egress_admission(")
	clear := strings.Index(continuation, "clear_xor_context(skb)")
	parse := strings.Index(continuation, "active_generation(&generation)")
	match := strings.Index(continuation, "faketcp_egress_admission_matches(")
	encode := strings.Index(continuation, "faketcp_encode_established(")
	if load < 0 || consume < 0 || clear < 0 || parse < 0 || match < 0 || encode < 0 ||
		!(load < consume && consume < clear && clear < parse && parse < match && match < encode) {
		t.Fatal("FakeTCP continuation must consume and clear its token before exact comparison or encode")
	}

	xdp := sourceSection(t, fake, "int wg_mix_faketcp_ingress(struct xdp_md *xdp)", "#endif")
	xdpCheckpoint := strings.Index(xdp, "faketcp_xdp_admission_checkpoint(")
	if xdpCheckpoint < 0 {
		t.Fatal("XDP admission checkpoint is missing")
	}
	if !strings.Contains(xdp, "if (!managed_listener)\n\t\treturn XDP_PASS;") ||
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
	ingressConsume := sourceSection(t, fake,
		"static __always_inline int faketcp_consume_ingress_admission(",
		"static __always_inline int faketcp_xdp_managed_interface(")
	copyProof := strings.Index(ingressConsume, "consumed = *metadata")
	clearMagic := strings.Index(ingressConsume, "metadata->magic = 0")
	gsoReject := strings.Index(ingressConsume, "if (skb->gso_segs || skb->gso_size)")
	compare := strings.Index(ingressConsume, "admission->key.generation != generation")
	if copyProof < 0 || clearMagic < 0 || gsoReject < 0 || compare < 0 ||
		!(copyProof < clearMagic && clearMagic < gsoReject && gsoReject < compare) {
		t.Fatal("TC ingress must copy and invalidate metadata before the exclusive GSO gate and proof comparison")
	}
}

func TestFakeTCPAdmissionProofBindsFullIdentityAndCapabilityStaysClosed(t *testing.T) {
	source, err := os.ReadFile("../../bpf/wg_mix_faketcp.h")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, want := range []string{
		"__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY)",
		"__uint(map_flags, BPF_F_RDONLY)",
		"faketcp_egress_admission_map",
		"__u64 next_nonce",
		"FAKETCP_TOKEN_ARMED",
		"FAKETCP_TOKEN_XOR_COMPLETE",
		"__sync_val_compare_and_swap(&active->token_state",
		"__builtin_memset(&slot->active, 0, sizeof(slot->active))",
		"struct faketcp_session_authority",
		"struct faketcp_session_projection",
		"session_authority",
		"session_projection",
		"session_id",
		"runtime_incarnation[16]",
		"standard_wire",
		"mixed_wire",
		"xor_type_word_copy(current_wire, cipher)",
		"admission->mixed_wire",
		"current_wire != admission->standard_wire",
		"struct faketcp_gso_projection",
		"segment_contract",
		"logical_segments",
		"wire_total_len",
		"network_off",
		"transport_off",
		"payload_off",
		"local_isn",
		"remote_isn",
		"profile_policy_flags",
		"metadata->direction = FAKETCP_DIRECTION_INGRESS",
		"metadata->admission = admission",
		"consumed = *metadata",
		"metadata->magic = 0",
		"faketcp_runtime_incarnation_matches(",
		"FAKETCP_STAT_ADMISSION_BYPASS_REJECT",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("admission identity/observability contract missing %q", want)
		}
	}
	if fakeTCPImplementedCapabilities&fakeTCPCapabilityAdmissionCheckpoint != 0 {
		t.Fatal("AdmissionCheckpoint capability opened before unique review and required live evidence")
	}

	tcSource, err := os.ReadFile("../../bpf/wg_mix_tc.c")
	if err != nil {
		t.Fatal(err)
	}
	tc := string(tcSource)
	cbWriter := sourceSection(t, tc, "static __always_inline void set_faketcp_xor_context", "static __always_inline int load_xor_context")
	for _, want := range []string{
		"skb->cb[0] = (__u32)nonce", "skb->cb[1] = (__u32)(nonce >> 32)",
		"skb->cb[2] = 0", "skb->cb[3] = 0",
	} {
		if !strings.Contains(cbWriter, want) {
			t.Fatalf("FakeTCP cb nonce/progress contract missing %q", want)
		}
	}
	if strings.Contains(cbWriter, "generation") || strings.Contains(cbWriter, "cipher_id") ||
		strings.Contains(cbWriter, "payload_off") || strings.Contains(cbWriter, "target") {
		t.Fatal("FakeTCP cb writer regained policy/proof fields")
	}

	manifest, err := os.ReadFile("experimental_manifest_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(manifest), `{name: "faketcp_egress_admission_map", mapType: ebpf.PerCPUArray, keySize: 4, valueSize: 176, maxEntries: 1, flags: unix.BPF_F_RDONLY}`) {
		t.Fatal("fresh admission map manifest does not lock PinNone-compatible type, size and syscall-side read-only flag")
	}

	egressProof := sourceSection(t, text, "struct faketcp_egress_admission {", "struct faketcp_egress_admission_slot {")
	transformProjection := sourceSection(t, text,
		"struct faketcp_ingress_transform_projection {",
		"struct faketcp_ingress_close_projection {")
	closeProjection := sourceSection(t, text,
		"struct faketcp_ingress_close_projection {",
		"union faketcp_ingress_decision_projection {")
	ingressProof := sourceSection(t, text, "struct faketcp_ingress_admission {", "_Static_assert(sizeof(struct faketcp_session_key)")
	if strings.Contains(egressProof, "revision") || strings.Contains(transformProjection, "revision") ||
		strings.Contains(ingressProof, "revision") {
		t.Fatal("ordinary transform proof regained mutable revision equality authority")
	}
	if !strings.Contains(closeProjection, "session_revision") ||
		!strings.Contains(ingressProof, "union faketcp_ingress_decision_projection decision") {
		t.Fatal("CLOSE did not retain a distinct mutable snapshot projection")
	}
	if !strings.Contains(text, "struct faketcp_session_snapshot") ||
		!strings.Contains(text, "close decision") ||
		!strings.Contains(text, "never become ordinary admission equality") {
		t.Fatal("locked close snapshot and transform lifetime authority are no longer explicitly separated")
	}
}

func TestFakeTCPAdmissionStatisticsAreMutuallyExclusive(t *testing.T) {
	source, err := os.ReadFile("../../bpf/wg_mix_faketcp.h")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	tcSource, err := os.ReadFile("../../bpf/wg_mix_tc.c")
	if err != nil {
		t.Fatal(err)
	}
	allSource := text + string(tcSource)
	checkpoint := sourceSection(t, text,
		"static __always_inline int faketcp_egress_admission_checkpoint(",
		"struct faketcp_gso_loop_context {")
	xdpCheckpoint := sourceSection(t, text,
		"static __always_inline int faketcp_xdp_admission_checkpoint(",
		"SEC(\"xdp\")")
	if strings.Contains(checkpoint, "FAKETCP_STAT_ADMISSION_ACCEPT") ||
		strings.Contains(xdpCheckpoint, "FAKETCP_STAT_ADMISSION_ACCEPT") {
		t.Fatal("early egress/XDP checkpoints must not count final admission acceptance")
	}
	if got := strings.Count(allSource, "inc_faketcp_stat(FAKETCP_STAT_ADMISSION_ACCEPT)"); got != 3 {
		t.Fatalf("direct/GSO egress writers and TC-ingress accept sites=%d, want 3", got)
	}
	encoder := sourceSection(t, text,
		"static __always_inline int faketcp_encode_established(",
		"static __always_inline int faketcp_continue_egress")
	mutate := strings.Index(encoder, "faketcp_session_mutate(session, generation, now,")
	accept := strings.Index(encoder, "inc_faketcp_stat(FAKETCP_STAT_ADMISSION_ACCEPT)")
	if mutate < 0 || accept < 0 || mutate >= accept {
		t.Fatal("egress acceptance must be counted once after the shared final writer admits the lifetime")
	}
	gsoEncoder := sourceSection(t, text,
		"faketcp_encode_gso_segments(struct __sk_buff *skb",
		"static __always_inline __s64 faketcp_rotation_checksum")
	gsoMutate := strings.Index(gsoEncoder, "faketcp_session_mutate(session, generation, now,")
	gsoAccept := strings.Index(gsoEncoder, "inc_faketcp_stat(FAKETCP_STAT_ADMISSION_ACCEPT)")
	if gsoMutate < 0 || gsoAccept < 0 || gsoMutate >= gsoAccept ||
		strings.Count(gsoEncoder, "inc_faketcp_stat(FAKETCP_STAT_ADMISSION_ACCEPT)") != 1 {
		t.Fatal("GSO acceptance must be counted once after its stable-lifetime writer")
	}
	gso := sourceSection(t, checkpoint, "if (is_gso) {", "} else if")
	if strings.Contains(gso, "FAKETCP_STAT_BAD_PACKET") ||
		strings.Count(gso, "inc_faketcp_stat(") != 1 {
		t.Fatal("egress GSO rejection must have exactly one FakeTCP counter classification")
	}
}
