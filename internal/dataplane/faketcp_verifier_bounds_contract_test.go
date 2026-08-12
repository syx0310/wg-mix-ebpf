package dataplane

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestBPFProfileMapAccessesUseOnlyConstantOffsets(t *testing.T) {
	tcBytes, err := os.ReadFile("../../bpf/wg_mix_tc.c")
	if err != nil {
		t.Fatal(err)
	}
	fakeBytes, err := os.ReadFile("../../bpf/wg_mix_faketcp.h")
	if err != nil {
		t.Fatal(err)
	}
	source := string(tcBytes) + "\n" + string(fakeBytes)
	access := regexp.MustCompile(`profile->(?:standard_to_mixed|mixed_to_standard)\[([^]]+)\]`)
	matches := access.FindAllStringSubmatch(source, -1)
	if len(matches) == 0 {
		t.Fatal("profile type maps have no BPF access sites")
	}
	for _, match := range matches {
		switch match[1] {
		case "0", "1", "2", "3":
		default:
			t.Fatalf("profile map regained verifier-unsafe dynamic array access %q", match[0])
		}
	}
	for _, required := range []string{
		"profile_mixed_from_kind(",
		"profile_decode_mixed(",
		"faketcp_gso_mixed_from_kind(",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("constant-offset profile/GSO dispatch is missing %q", required)
		}
	}
}

func TestFakeTCPXDPPacketPointersDoNotCrossHelperBoundaries(t *testing.T) {
	fakeBytes, err := os.ReadFile("../../bpf/wg_mix_faketcp.h")
	if err != nil {
		t.Fatal(err)
	}
	fake := string(fakeBytes)
	body := sourceSection(t, fake,
		"faketcp_xdp_ingress_body(struct xdp_md *xdp, __u64 generation)",
		"SEC(\"xdp\")")

	firstBounds := strings.Index(body, "if ((void *)(wire_ports + 1) > data_end)")
	portSnapshot := strings.Index(body, "destination_port = bpf_ntohs(wire_ports->dest)")
	managedLookup := strings.Index(body, "managed_listener = faketcp_xdp_managed_port(")
	headerSnapshot := strings.Index(body, "faketcp_xdp_load_ipv4_tcp_snapshot(")
	policyLookup := strings.Index(body, "policy_listener = lookup_ingress_listener(")
	checkpoint := strings.Index(body, "admission_decision = faketcp_xdp_admission_checkpoint(")
	if firstBounds < 0 || portSnapshot < 0 || managedLookup < 0 ||
		headerSnapshot < 0 || policyLookup < 0 || checkpoint < 0 ||
		!(firstBounds < portSnapshot && portSnapshot < managedLookup &&
			managedLookup < headerSnapshot && headerSnapshot < policyLookup &&
			policyLookup < checkpoint) {
		t.Fatal("XDP packet bounds, scalar/header snapshots and helper boundaries are out of order")
	}

	afterManagedLookup := body[managedLookup:]
	for _, forbidden := range []string{
		"bpf_ntohs(tcp->dest)",
		"bpf_ntohs(tcp->source)",
		"bpf_ntohs(iph->tot_len)",
		"*old_tcp = *tcp",
		"*new_ip = *iph",
		"tcp = data + l3->l4_off",
		"iph = data + l3->l3_off",
	} {
		if strings.Contains(afterManagedLookup, forbidden) {
			t.Fatalf("XDP direct packet access %q crossed the managed-port helper boundary", forbidden)
		}
	}
	afterPolicy := body[policyLookup:]
	for _, required := range []string{
		"xdp, l3->l3_off, new_ip, old_tcp, l3, managed_listener",
		"faketcp_close_checksums_valid(new_ip, old_tcp)",
		"bpf_ntohs(old_tcp->window)",
	} {
		if !strings.Contains(afterPolicy, required) {
			t.Fatalf("XDP map-backed header use is missing %q", required)
		}
	}

	checkpointBody := sourceSection(t, fake,
		"static __always_inline int faketcp_xdp_admission_checkpoint(",
		"static __always_inline int faketcp_xdp_l3_action(")
	if strings.Contains(checkpointBody, "void *data") ||
		strings.Contains(checkpointBody, "void *data_end") ||
		strings.Contains(checkpointBody, "data + ip_off") {
		t.Fatal("XDP checkpoint regained a live packet pointer or packet-derived bounds proof")
	}
	if !strings.Contains(checkpointBody, "admission->wire_total_len != l3->l3_len") {
		t.Fatal("XDP checkpoint does not bind its header snapshot to the parsed L3 length")
	}
	snapshotLoader := sourceSection(t, fake,
		"static __always_inline int faketcp_xdp_load_ipv4_tcp_snapshot(",
		"static __always_inline int\nfaketcp_capture_close_packet(")
	for _, required := range []string{
		"transport_off - network_off != sizeof(struct iphdr)",
		"faketcp_legacy_515_xdp_load_close_packet(",
		"bpf_xdp_load_bytes(xdp, network_off, snapshot,",
		"sizeof(*snapshot)",
	} {
		if !strings.Contains(snapshotLoader, required) {
			t.Fatalf("fixed XDP header snapshot loader is missing %q", required)
		}
	}
}

func TestFakeTCPPacketHelperSizesCannotBeZero(t *testing.T) {
	fakeBytes, err := os.ReadFile("../../bpf/wg_mix_faketcp.h")
	if err != nil {
		t.Fatal(err)
	}
	fake := string(fakeBytes)
	gsoXOR := sourceSection(t, fake,
		"static __noinline long faketcp_gso_xor_chunk(",
		"#ifdef WG_MIX_FAKETCP_LEGACY_515\nstatic __always_inline int faketcp_legacy_515_rewrite_gso_types(")
	if !strings.Contains(fake, "_Static_assert(sizeof(struct faketcp_gso_loop_context) == 64") {
		t.Fatal("FakeTCP GSO loop context regained the 72-byte caller stack layout")
	}
	for _, forbidden := range []string{
		"chunk, chunk_length)",
		"chunk, chunk_length,",
		"__u8 chunk[FAKETCP_GSO_XOR_CHUNK_BYTES]",
		"old_word",
		"new_word",
		"for (int byte = 0; byte < 3; byte++)",
	} {
		if strings.Contains(gsoXOR, forbidden) {
			t.Fatalf("GSO XOR passed verifier-ambiguous dynamic helper size through %q", forbidden)
		}
	}
	for _, required := range []string{
		"if (chunk_length == 0 || chunk_length > FAKETCP_GSO_XOR_CHUNK_BYTES)",
		"struct faketcp_runtime_scratch *scratch",
		"chunk = scratch->gso_xor_chunk",
		"if (chunk_length == FAKETCP_GSO_XOR_CHUNK_BYTES)",
		"chunk,\n\t\t\t\t       FAKETCP_GSO_XOR_CHUNK_BYTES",
		"*word_buffer = 0",
		"word_buffer, sizeof(*word_buffer)",
		"for (int byte = 0; byte < 4; byte++)",
		"if (tail_length >= 2)",
		"if (tail_length == 3)",
		"tail_length == 0 || tail_length > 3",
		"xor_load_partial_word(",
		"xor_store_partial_word(",
		"processed != chunk_length",
	} {
		if !strings.Contains(gsoXOR, required) {
			t.Fatalf("fixed-size GSO XOR helper dispatch is missing %q", required)
		}
	}

	capture := sourceSection(t, fake,
		"static __always_inline int faketcp_capture_first_packet(",
		"static __always_inline struct faketcp_egress_admission *")
	if !strings.Contains(capture, "packet_len < sizeof(struct iphdr) + sizeof(struct udphdr)") ||
		!strings.Contains(capture, "record->packet, packet_len") {
		t.Fatal("variable TC capture size lost its strict positive lower bound")
	}
	checksum := sourceSection(t, fake,
		"static __always_inline int faketcp_materialize_tcp_checksum(",
		"// faketcp_encode_established is the single encoder")
	if !strings.Contains(checksum, "if (remaining == 0 || remaining > sizeof(chunk))") ||
		!strings.Contains(checksum, "chunk,\n\t\t\t\t       remaining") {
		t.Fatal("variable checksum tail load lost its explicit nonzero bound")
	}
	closeCapture := sourceSection(t, fake,
		"static __always_inline int\nfaketcp_capture_close_packet(",
		"// All managed FakeTCP wire packets reach this one bounded classifier")
	if !strings.Contains(closeCapture, "packet_len != sizeof(struct iphdr) + sizeof(struct tcphdr)") ||
		!strings.Contains(closeCapture, "sizeof(struct iphdr) + sizeof(struct tcphdr)") ||
		strings.Contains(closeCapture, "record->packet, packet_len") {
		t.Fatal("XDP close-capture helper size is not a fixed positive header length")
	}
}

func TestFakeTCPTCHeaderConsumersUseHelperSnapshots(t *testing.T) {
	fakeBytes, err := os.ReadFile("../../bpf/wg_mix_faketcp.h")
	if err != nil {
		t.Fatal(err)
	}
	fake := string(fakeBytes)
	loader := sourceSection(t, fake,
		"static __always_inline int faketcp_tc_load_ipv4_udp_snapshot(",
		"static __always_inline int faketcp_tc_key(")
	for _, required := range []string{
		"struct faketcp_tc_ipv4_udp_snapshot",
		"_Static_assert(sizeof(struct faketcp_tc_ipv4_udp_snapshot) == 28",
		"struct faketcp_tc_ipv4_udp_snapshot tc_headers",
		"_Static_assert(offsetof(struct faketcp_runtime_scratch, tc_headers) == 360",
		"_Static_assert(offsetof(struct faketcp_runtime_scratch, gso_xor_chunk) == 360",
		"_Static_assert(sizeof(struct faketcp_runtime_scratch) == 392",
		"transport_off - network_off != sizeof(struct iphdr)",
		"payload_off - transport_off != sizeof(struct udphdr)",
		"bpf_skb_load_bytes(skb, network_off, snapshot, sizeof(*snapshot))",
	} {
		if !strings.Contains(fake, required) {
			t.Fatalf("TC fixed-header snapshot contract is missing %q", required)
		}
	}
	if strings.Count(loader, "bpf_skb_load_bytes(") != 1 {
		t.Fatal("TC fixed IPv4/UDP envelope must be captured by exactly one skb helper")
	}

	sections := map[string]string{
		"flow key": sourceSection(t, fake,
			"static __always_inline int faketcp_tc_key(",
			"// One descriptor owns both the generic rule-lookup result"),
		"XOR coherence": sourceSection(t, fake,
			"static __always_inline int faketcp_tc_current_admission_coherent(",
			"static __always_inline void faketcp_tc_descriptor_from_admission("),
		"admission matcher": sourceSection(t, fake,
			"static __always_inline int faketcp_egress_admission_matches(",
			"// This is the only TC egress admission checkpoint."),
		"admission checkpoint": sourceSection(t, fake,
			"static __always_inline int faketcp_egress_admission_checkpoint(",
			"struct faketcp_gso_loop_context {"),
		"established encoder": sourceSection(t, fake,
			"static __always_inline int faketcp_encode_established(",
			"static __always_inline int faketcp_continue_egress("),
		"ingress proof": sourceSection(t, fake,
			"static __always_inline int faketcp_consume_ingress_admission(",
			"static __always_inline int faketcp_xdp_managed_interface("),
	}
	directHeader := regexp.MustCompile(`(?m)(?:struct (?:iphdr|udphdr) \*(?:iph|udp)\b|\b(?:iph|udp)->|\*(?:iph|udp)\b|data \+ (?:info|l3|admission)->(?:ip|udp|l3|transport|network)_off)`)
	for name, section := range sections {
		if match := directHeader.FindString(section); match != "" {
			t.Fatalf("%s regained direct IP/UDP packet dereference %q", name, match)
		}
		if strings.Contains(section, "struct faketcp_tc_ipv4_udp_snapshot headers = {}") {
			t.Fatalf("%s rematerialized the 28-byte header snapshot on the BPF stack", name)
		}
	}

	flowKey := sections["flow key"]
	if !strings.Contains(flowKey, "__be32 local_ipv4") ||
		!strings.Contains(flowKey, "key->local_ipv4 = local_ipv4") ||
		strings.Contains(flowKey, "faketcp_tc_ipv4_udp_snapshot") ||
		strings.Contains(flowKey, "bpf_skb_load_bytes(") {
		t.Fatal("flow-key projection does not consume only caller-projected scalars")
	}
	for _, name := range []string{
		"XOR coherence", "admission matcher", "admission checkpoint",
		"established encoder", "ingress proof",
	} {
		if !strings.Contains(sections[name], "faketcp_tc_load_ipv4_udp_snapshot(") {
			t.Fatalf("%s does not refresh its fixed header snapshot", name)
		}
	}

	matcher := sections["admission matcher"]
	matcherLoad := strings.Index(matcher, "faketcp_tc_load_ipv4_udp_snapshot(")
	matcherLastHeader := strings.LastIndex(matcher, "headers->")
	matcherScratch := strings.Index(matcher, "headers = &scratch->tc_headers")
	matcherPayload := strings.Index(matcher, "&current_wire")
	if matcherLoad < 0 || matcherLastHeader < 0 || matcherScratch < 0 || matcherPayload < 0 ||
		!(matcherScratch < matcherLoad && matcherLoad < matcherLastHeader && matcherLastHeader < matcherPayload) {
		t.Fatal("admission matcher keeps its header snapshot live across a later helper boundary")
	}
	checkpoint := sections["admission checkpoint"]
	checkpointLoad := strings.Index(checkpoint, "faketcp_tc_load_ipv4_udp_snapshot(")
	checkpointLastHeader := strings.LastIndex(checkpoint, "headers->")
	checkpointCipher := strings.Index(checkpoint, "cipher = lookup_cipher(")
	checkpointGSO := strings.Index(checkpoint, "faketcp_gso_build_projection(")
	checkpointSession := strings.Index(checkpoint, "bpf_map_lookup_elem(&faketcp_session_map")
	if checkpointLoad < 0 || checkpointLastHeader < 0 || checkpointCipher < 0 || checkpointGSO < 0 || checkpointSession < 0 ||
		!(checkpointLoad < checkpointLastHeader && checkpointLastHeader < checkpointCipher &&
			checkpointLastHeader < checkpointGSO && checkpointLastHeader < checkpointSession) {
		t.Fatal("admission checkpoint keeps its header snapshot live across a policy/GSO/session helper")
	}
	encoder := sections["established encoder"]
	if load, lastHeader, session := strings.Index(encoder, "faketcp_tc_load_ipv4_udp_snapshot("),
		strings.LastIndex(encoder, "headers->"),
		strings.Index(encoder, "bpf_map_lookup_elem(&faketcp_session_map"); load < 0 || lastHeader < 0 || session < 0 || !(load < lastHeader && lastHeader < session) {
		t.Fatal("established encoder keeps its header snapshot live across session lookup")
	}
	ingress := sections["ingress proof"]
	if load, lastHeader, payload := strings.Index(ingress, "faketcp_tc_load_ipv4_udp_snapshot("),
		strings.LastIndex(ingress, "headers->"), strings.Index(ingress, "&input_wire"); load < 0 || lastHeader < 0 || payload < 0 || !(load < lastHeader && lastHeader < payload) {
		t.Fatal("ingress proof keeps its header snapshot live across its next skb helper")
	}
}
