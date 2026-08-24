package dataplane

import (
	"os"
	"strings"
	"testing"
)

func TestFakeTCPDirectEgressAvoidsCrossProgramTokenWork(t *testing.T) {
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

	egress := sourceSection(t, tc,
		"int wg_mix_egress(struct __sk_buff *skb)",
		"SEC(\"classifier/ingress\")")
	direct := sourceSection(t, egress,
		"if (faketcp_direct_egress_admission_checkpoint(",
		"return faketcp_encode_direct_established(")
	checkpoint := strings.Index(direct, "faketcp_direct_egress_admission_checkpoint(")
	typeWord := strings.Index(direct, "update_type_word(skb, info, old_wire, new_wire, 1)")
	if checkpoint < 0 || typeWord < 0 || checkpoint >= typeWord {
		t.Fatal("direct lifetime checkpoint must dominate its first packet-byte mutation")
	}
	for _, forbidden := range []string{
		"faketcp_egress_admission_checkpoint(",
		"faketcp_consume_egress_admission(",
		"faketcp_egress_admission_matches(",
		"faketcp_egress_admission_map",
		"set_faketcp_xor_context(",
		"bpf_tail_call(",
		"nonce",
	} {
		if strings.Contains(direct, forbidden) {
			t.Fatalf("ordinary no-XOR branch regained cross-program token work %q", forbidden)
		}
	}
	directCheckpoint := sourceSection(t, fake,
		"static __always_inline int faketcp_direct_egress_admission_checkpoint(",
		"// Cross-program XOR and aggregate GSO use this complete checkpoint.")
	if got := strings.Count(directCheckpoint, "faketcp_tc_load_ipv4_udp_snapshot("); got != 1 {
		t.Fatalf("direct checkpoint header snapshots=%d, want one", got)
	}
	for _, want := range []string{
		"__builtin_memset(admission, 0, sizeof(*admission))",
		"managed->generation != generation",
		"rule->generation != generation",
		"profile->generation != generation",
		"rule->cipher_id != 0",
		"faketcp_session_snapshot_direct_established(",
		"faketcp_runtime_identity(generation)",
		"admission->session_authority.runtime_incarnation",
		"admission->rule_wg_id = rule->wg_id",
		"admission->rule_profile_id = rule->profile_id",
		"admission->profile_policy_flags = profile->policy_flags",
		"faketcp_capture_first_packet(skb, info, l3, rule",
	} {
		if !strings.Contains(directCheckpoint, want) {
			t.Fatalf("direct checkpoint lost authority %q", want)
		}
	}
	for _, forbidden := range []string{
		"faketcp_egress_admission_map",
		"faketcp_consume_egress_admission(",
		"faketcp_egress_admission_matches(",
		"next_nonce",
		"token_state",
		"slot->active",
		"faketcp_gso_build_projection(",
		"lookup_cipher(",
	} {
		if strings.Contains(directCheckpoint, forbidden) {
			t.Fatalf("direct checkpoint regained token/XOR/GSO work %q", forbidden)
		}
	}
	directMatch := sourceSection(t, fake,
		"static __always_inline int faketcp_direct_egress_admission_matches(",
		"// The packet rewrite is shared")
	if strings.Contains(directMatch, "faketcp_tc_load_ipv4_udp_snapshot(") {
		t.Fatal("direct compact replay restored the removed header snapshot")
	}
	for _, want := range []string{
		"admission->generation != generation",
		"rule->wg_id != admission->rule_wg_id",
		"rule->profile_id != admission->rule_profile_id",
		"profile->policy_flags != admission->profile_policy_flags",
		"rule->cipher_id != 0",
		"faketcp_runtime_incarnation_matches(",
		"admission->session_authority.session_id == 0",
		"admission->session_projection.state != FAKETCP_STATE_ESTABLISHED",
	} {
		if !strings.Contains(directMatch, want) {
			t.Fatalf("direct compact replay lost %q", want)
		}
	}
	for _, forbidden := range []string{
		"parse_packet(", "parse_packet_observed(", "faketcp_parse_l3(",
		"bpf_skb_load_bytes(", "faketcp_egress_admission_map",
	} {
		if strings.Contains(directMatch, forbidden) {
			t.Fatalf("direct compact replay regained packet parse/token work %q", forbidden)
		}
	}
}

func TestFakeTCPDirectAndTokenPathsRetainTheirAuthorityBoundaries(t *testing.T) {
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

	for _, want := range []string{
		"_Static_assert(sizeof(struct faketcp_direct_egress_admission) == 104",
		"_Static_assert(sizeof(struct faketcp_egress_admission_slot) == 192",
		"struct faketcp_direct_egress_admission direct_admission",
	} {
		if !strings.Contains(fake, want) {
			t.Fatalf("direct/token layout contract missing %q", want)
		}
	}

	authorized := sourceSection(t, fake,
		"static __always_inline int faketcp_encode_established_authorized(",
		"static __always_inline int faketcp_encode_direct_established(")
	lookup := strings.Index(authorized, "bpf_map_lookup_elem(&faketcp_session_map, session_key)")
	mutate := strings.Index(authorized, "faketcp_session_mutate(session, generation, now,")
	accept := strings.Index(authorized, "inc_faketcp_stat(FAKETCP_STAT_ADMISSION_ACCEPT)")
	if lookup < 0 || mutate < 0 || accept < 0 || !(lookup < mutate && mutate < accept) {
		t.Fatal("shared encoder lost its final session lookup/locked mutation/accept order")
	}
	if got := strings.Count(authorized, "faketcp_tc_load_ipv4_udp_snapshot("); got != 1 {
		t.Fatalf("shared encoder header snapshots=%d, want one", got)
	}
	for _, want := range []string{
		"session_authority,",
		"session_projection,",
		"FAKETCP_SESSION_MUTATE_TX",
	} {
		if !strings.Contains(authorized, want) {
			t.Fatalf("shared final mutation lost %q", want)
		}
	}

	egress := sourceSection(t, tc,
		"int wg_mix_egress(struct __sk_buff *skb)",
		"SEC(\"classifier/ingress\")")
	xorBranch := sourceSection(t, egress,
		"if (cipher_id != 0) {",
		"if (faketcp_direct_egress_admission_checkpoint(")
	for _, want := range []string{
		"faketcp_egress_admission_checkpoint(",
		"set_faketcp_xor_context(skb, faketcp_admission->nonce)",
		"bpf_tail_call(skb, &xor_egress_programs",
		"faketcp_consume_egress_admission(",
	} {
		if !strings.Contains(xorBranch, want) {
			t.Fatalf("XOR path no longer retains full token proof %q", want)
		}
	}

	gso := sourceSection(t, fake,
		"faketcp_encode_gso_segments(struct __sk_buff *skb",
		"static __always_inline __s64 faketcp_rotation_checksum")
	for _, want := range []string{
		"faketcp_egress_admission_checkpoint(",
		"faketcp_egress_admission_matches(",
		"admission_nonce = admission->nonce",
		"admission = faketcp_active_egress_admission(admission_nonce)",
		"faketcp_consume_egress_admission(admission_nonce, 0)",
	} {
		if !strings.Contains(gso, want) {
			t.Fatalf("GSO path no longer retains full token proof %q", want)
		}
	}
	checkpoint := strings.Index(gso, "faketcp_egress_admission_checkpoint(")
	match := strings.Index(gso, "faketcp_egress_admission_matches(")
	nonce := strings.Index(gso, "admission_nonce = admission->nonce")
	reload := strings.Index(gso, "admission = faketcp_active_egress_admission(admission_nonce)")
	commit := strings.Index(gso, "result = faketcp_commit_udp_gso(")
	consume := strings.LastIndex(gso, "faketcp_consume_egress_admission(admission_nonce, 0)")
	if checkpoint < 0 || match < checkpoint || nonce < match || reload < nonce ||
		commit < reload || consume < commit {
		t.Fatal("GSO path lost checkpoint/match/nonce reload/commit/final consume order")
	}
}
