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
		"faketcp_parse_tc_egress_packet(skb, generation, &faketcp_packet)")
	lookup := strings.Index(egress, "rule = bpf_map_lookup_elem(&egress_rule_map, &key)")
	fixedGate := strings.Index(egress, "faketcp_tc_fixed_udp_status(&faketcp_packet)")
	prepare := strings.Index(egress, "faketcp_prepare_udp(")
	checkpoint := strings.Index(egress, "faketcp_egress_admission_checkpoint(")
	if parse < 0 || lookup < 0 || fixedGate < 0 || prepare < 0 || checkpoint < 0 ||
		!(parse < lookup && lookup < fixedGate && fixedGate < prepare && prepare < checkpoint) {
		t.Fatal("one descriptor parse must precede policy lookup, fixed gate, prepare and admission")
	}
	if got := strings.Count(egress, "faketcp_parse_tc_egress_packet("); got != 1 {
		t.Fatalf("authoritative egress descriptor parses=%d, want 1", got)
	}
	for _, want := range []string{
		"struct faketcp_tc_packet_descriptor faketcp_packet = {}",
		"struct packet_info *info = &faketcp_packet.info",
		"faketcp_encode_gso_segments(\n\t\t\t\tskb, info, &faketcp_packet.l3",
		"skb, info, &faketcp_packet.l3, managed, rule, profile",
	} {
		if !strings.Contains(egress, want) {
			t.Fatalf("egress descriptor projection missing %q", want)
		}
	}
	if strings.Contains(egress, "faketcp_parse_tc_l3(") {
		t.Fatal("obsolete second FakeTCP egress parser remains")
	}

	parser := sourceSection(t, fake,
		"faketcp_parse_tc_egress_packet(struct __sk_buff *skb",
		"static __always_inline int faketcp_tc_fixed_udp_status(")
	if got := strings.Count(parser, "faketcp_parse_l3("); got != 1 {
		t.Fatalf("shared bounded parser calls in authoritative wrapper=%d, want 1", got)
	}
	for _, forbidden := range []string{"parse_packet(", "parse_udp_at("} {
		if strings.Contains(parser, forbidden) {
			t.Fatalf("authoritative wrapper retained parser fallback %q", forbidden)
		}
	}
	for _, want := range []string{
		"return faketcp_tc_derive_udp_info(data, data_end, packet)",
		"info->ip_off = l3->l3_off",
		"info->udp_off = l3->l4_off",
		"info->payload_len = l3->l4_len - sizeof(*udp)",
	} {
		if !strings.Contains(fake, want) {
			t.Fatalf("generic packet_info is not derived from the descriptor: %q", want)
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
		for _, parser := range []string{"parse_packet(", "faketcp_parse_l3(", "faketcp_parse_tc_egress_packet("} {
			if strings.Contains(section, parser) {
				t.Fatalf("%s reparses through %q", name, parser)
			}
		}
	}
	consume := strings.Index(continuation, "faketcp_consume_egress_admission(")
	project := strings.Index(continuation, "faketcp_tc_descriptor_from_admission(")
	match := strings.Index(continuation, "faketcp_egress_admission_matches(")
	encode := strings.Index(continuation, "faketcp_encode_established(")
	if consume < 0 || project < 0 || match < 0 || encode < 0 ||
		!(consume < project && project < match && match < encode) {
		t.Fatal("XOR continuation must consume, project, compare and encode in that order")
	}
	if !strings.Contains(matcher,
		"faketcp_managed_transform_status(l3, IPPROTO_UDP)") {
		t.Fatal("descriptor consumer lost the fixed IPv4/UDP gate")
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
