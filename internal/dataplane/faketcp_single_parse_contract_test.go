package dataplane

import (
	"os"
	"strings"
	"testing"
)

func TestFakeTCPEgressUsesOneAuthoritativePacketDescriptor(t *testing.T) {
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
	parse := strings.Index(egress,
		"faketcp_parse_tc_egress_packet(skb, generation, faketcp_packet)")
	lookup := strings.Index(egress, "rule = bpf_map_lookup_elem(&egress_rule_map, &key)")
	fakeTCPRule := strings.Index(egress, "if (rule->transport_mode == TRANSPORT_FAKETCP)")
	fixedGate := strings.Index(egress, "faketcp_tc_fixed_udp_status(faketcp_packet)")
	prepare := strings.Index(egress, "faketcp_prepare_udp(")
	checkpoint := strings.Index(egress, "faketcp_egress_admission_checkpoint(")
	if parse < 0 || lookup < 0 || fakeTCPRule < 0 || fixedGate < 0 || prepare < 0 || checkpoint < 0 ||
		!(parse < lookup && lookup < fakeTCPRule && fakeTCPRule < fixedGate && fixedGate < prepare && prepare < checkpoint) {
		t.Fatal("generic descriptor result must reach policy lookup before the FakeTCP-only strict gate")
	}
	if got := strings.Count(egress, "faketcp_parse_tc_egress_packet("); got != 1 {
		t.Fatalf("authoritative egress descriptor parses=%d, want 1", got)
	}
	for _, want := range []string{
		"struct faketcp_tc_packet_descriptor *faketcp_packet",
		"faketcp_packet = &faketcp_scratch->tc.packet",
		"struct packet_info *info",
		"info = &faketcp_packet->info",
		"faketcp_encode_gso_segments(\n\t\t\t\tskb, info, &faketcp_packet->shape.l3",
		"skb, info, &faketcp_packet->shape.l3, managed, rule, profile",
	} {
		if !strings.Contains(egress, want) {
			t.Fatalf("egress descriptor projection missing %q", want)
		}
	}
	if strings.Contains(tc, "PARSE_FAKETCP_FAIL_CLOSED") ||
		strings.Contains(fake, "PARSE_FAKETCP_FAIL_CLOSED") {
		t.Fatal("strict FakeTCP status must not become a pre-policy generic parse result")
	}

	parser := sourceSection(t, fake,
		"faketcp_parse_tc_egress_packet(struct __sk_buff *skb",
		"static __always_inline int faketcp_tc_fixed_udp_status(")
	if got := strings.Count(parser, "parse_packet_observed("); got != 1 {
		t.Fatalf("generic superset parser calls in authoritative wrapper=%d, want 1", got)
	}
	for _, forbidden := range []string{"parse_packet(", "parse_udp_at(", "parse_link(", "faketcp_parse_l3("} {
		if strings.Contains(parser, forbidden) {
			t.Fatalf("authoritative wrapper retained parser fallback %q", forbidden)
		}
	}
	for _, want := range []string{
		"packet->generic_status = parse_packet_observed(",
		"packet->faketcp_status = faketcp_tc_project_ipv4_udp(packet)",
		"return packet->generic_status",
		"struct packet_info info",
		"int generic_status",
		"int faketcp_status",
	} {
		if !strings.Contains(fake, want) {
			t.Fatalf("descriptor does not preserve generic and strict results: %q", want)
		}
	}
	projection := sourceSection(t, fake,
		"faketcp_tc_project_ipv4_udp(struct faketcp_tc_packet_descriptor *packet)",
		"static __always_inline int\nfaketcp_parse_tc_egress_packet(")
	for _, forbidden := range []string{"faketcp_parse_l3(", "parse_packet(", "parse_udp_at(", "bpf_skb_load_bytes("} {
		if strings.Contains(projection, forbidden) {
			t.Fatalf("strict projection reloaded packet data through %q", forbidden)
		}
	}
}

func TestFakeTCPEgressConsumersNeverReparseDescriptor(t *testing.T) {
	fakeBytes, err := os.ReadFile("../../bpf/wg_mix_faketcp.h")
	if err != nil {
		t.Fatal(err)
	}
	fake := string(fakeBytes)

	matcher := sourceSection(t, fake,
		"static __always_inline int faketcp_egress_admission_matches(",
		"// This is the only TC egress admission checkpoint.")
	continuation := sourceSection(t, fake,
		"static __always_inline int faketcp_continue_egress",
		"SEC(\"classifier/faketcp_egress\")")
	for name, section := range map[string]string{
		"admission matcher": matcher,
		"XOR continuation":  continuation,
	} {
		for _, parser := range []string{"parse_packet(", "parse_packet_observed(", "parse_link(", "faketcp_parse_l3(", "faketcp_parse_tc_egress_packet("} {
			if strings.Contains(section, parser) {
				t.Fatalf("%s reparses through %q", name, parser)
			}
		}
	}
	consume := strings.Index(continuation, "faketcp_consume_egress_admission(")
	coherent := strings.Index(continuation, "faketcp_tc_current_admission_coherent(")
	project := strings.Index(continuation, "faketcp_tc_descriptor_from_admission(")
	match := strings.Index(continuation, "faketcp_egress_admission_matches(")
	encode := strings.Index(continuation, "faketcp_encode_established(")
	if consume < 0 || coherent < 0 || project < 0 || match < 0 || encode < 0 ||
		!(consume < coherent && coherent < project && project < match && match < encode) {
		t.Fatal("XOR continuation must consume, check current fixed headers, project, compare and encode in that order")
	}
	if !strings.Contains(matcher,
		"faketcp_managed_transform_status(l3, IPPROTO_UDP)") {
		t.Fatal("descriptor consumer lost the fixed IPv4/UDP gate")
	}
	coherence := sourceSection(t, fake,
		"static __always_inline int faketcp_tc_current_admission_coherent(",
		"static __always_inline void faketcp_tc_descriptor_from_admission(")
	for _, want := range []string{
		"faketcp_tc_load_ipv4_udp_snapshot(",
		"headers.ip.version != 4",
		"headers.ip.ihl != sizeof(headers.ip) / 4",
		"headers.ip.protocol != IPPROTO_UDP",
		"fragment & (IP_RESERVED | IP_MF | IP_OFFSET)",
		"bpf_ntohs(headers.ip.tot_len) != admission->ip_total_len",
		"bpf_ntohs(headers.udp.len) != admission->wire_len",
		"bpf_ntohs(headers.udp.source) != admission->key.local_port",
		"bpf_ntohs(headers.udp.dest) != admission->key.remote_port",
		"admission->xor_checksum_mode == XOR_CSUM_NONE",
	} {
		if !strings.Contains(coherence, want) {
			t.Fatalf("current-header coherence check missing %q", want)
		}
	}
	for _, forbidden := range []string{"parse_packet(", "parse_packet_observed(", "parse_link(", "faketcp_parse_l3("} {
		if strings.Contains(coherence, forbidden) {
			t.Fatalf("current-header coherence restored a full parser through %q", forbidden)
		}
	}
}

func TestFakeTCPSingleDescriptorKeepsIngressBoundaryIndependent(t *testing.T) {
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

	if strings.Count(fake, "faketcp_revalidate_tc_ingress_l3(") != 1 ||
		!strings.Contains(tc,
			"faketcp_revalidate_tc_ingress_l3(skb, &info, &faketcp_l3)") {
		t.Fatal("TC ingress must retain exactly one XDP-to-TC boundary revalidation")
	}
	if strings.Contains(tc, "faketcp_parse_tc_l3(") ||
		strings.Contains(fake, "faketcp_parse_tc_l3(") {
		t.Fatal("obsolete dual-purpose TC parser remains reachable")
	}
}
