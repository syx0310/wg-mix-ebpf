package dataplane

import (
	"fmt"
	"os"
	"strings"
	"testing"

	faketcpmodel "github.com/syx0310/wg-mix-ebpf/internal/faketcp"
)

func TestFakeTCPL3CAndGoResultContractsStaySynchronized(t *testing.T) {
	source, err := os.ReadFile("../../bpf/wg_mix_faketcp_l3.h")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	statuses := []struct {
		name  string
		value faketcpmodel.L3ParseStatus
	}{
		{"FAKETCP_L3_OK", faketcpmodel.L3ParseOK},
		{"FAKETCP_L3_SAFE_BYPASS", faketcpmodel.L3ParseSafeBypass},
		{"FAKETCP_L3_TRUNCATED", faketcpmodel.L3ParseTruncated},
		{"FAKETCP_L3_MALFORMED", faketcpmodel.L3ParseMalformed},
		{"FAKETCP_L3_UNSUPPORTED", faketcpmodel.L3ParseUnsupported},
		{"FAKETCP_L3_FIRST_FRAGMENT", faketcpmodel.L3ParseFirstFragment},
		{"FAKETCP_L3_NONINITIAL_FRAGMENT", faketcpmodel.L3ParseNonInitialFragment},
		{"FAKETCP_L3_EXTENSION_TOO_DEEP", faketcpmodel.L3ParseExtensionTooDeep},
	}
	for _, status := range statuses {
		want := fmt.Sprintf("#define %s %d", status.name, status.value)
		if !strings.Contains(text, want) {
			t.Fatalf("C/Go L3 result ABI missing %q", want)
		}
	}
	for _, want := range []string{
		"struct faketcp_l3_info",
		"__u32 l3_len;",
		"__u32 l4_off;",
		"__u32 l4_len;",
		"__u16 l3_header_len;",
		"__u16 l4_header_len;",
		"__u16 fragment_offset_bytes;",
		"FAKETCP_L3_MAX_EXTENSION_HEADERS 8",
		"FAKETCP_L3_MAX_EXTENSION_BYTES 512",
		"iph->version != 4",
		"ihl = (__u32)iph->ihl * 4",
		"fragment & IP_RESERVED",
		"ip6->version != 6",
		"next_header == NEXTHDR_FRAGMENT",
		"next_header == NEXTHDR_AUTH",
		"depth <= FAKETCP_L3_MAX_EXTENSION_HEADERS",
		"faketcp_managed_transform_status",
		"info->l3_header_len != sizeof(struct iphdr)",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("bounded L3 parser contract missing %q", want)
		}
	}
}

func TestFakeTCPL3ParserIsSingleSharedTCAndXDPContract(t *testing.T) {
	mainSource, err := os.ReadFile("../../bpf/wg_mix_faketcp.h")
	if err != nil {
		t.Fatal(err)
	}
	parserSource, err := os.ReadFile("../../bpf/wg_mix_faketcp_l3.h")
	if err != nil {
		t.Fatal(err)
	}
	tcSource, err := os.ReadFile("../../bpf/wg_mix_tc.c")
	if err != nil {
		t.Fatal(err)
	}
	main := string(mainSource)
	parser := string(parserSource)
	tc := string(tcSource)

	if strings.Count(parser, "faketcp_parse_l3(void *data") != 1 {
		t.Fatal("FakeTCP must expose exactly one shared L3 parser entry point")
	}
	for _, want := range []string{
		"#include \"wg_mix_faketcp_l3.h\"",
		"rc = faketcp_parse_l3(data, data_end, skb->len, info->ip_off",
		"parse_rc = faketcp_parse_l3(data, data_end, frame_len, l3_off, family, &l3)",
		"parser_mode == PARSER_L3",
		"parser_mode != PARSER_ETHERNET",
		"faketcp_managed_transform_status(l3, IPPROTO_UDP)",
		"faketcp_managed_transform_status(&l3, l3.transport_protocol)",
		"sizeof(struct iphdr) + sizeof(struct udphdr)",
		"l3.l4_off + sizeof(udp)",
		"struct iphdr new_ip;",
		"bpf_xdp_store_bytes(xdp, l3.l3_off, &new_ip, sizeof(new_ip))",
	} {
		if !strings.Contains(main, want) {
			t.Fatalf("TC/XDP shared parser integration missing %q", want)
		}
	}
	for _, removed := range []string{
		"faketcp_xdp_ipv6_policy",
		"struct faketcp_ipv6_extension",
		"struct faketcp_ipv6_fragment",
		"iph->ihl != 5",
		"struct faketcp_ipv4_checksum_delta",
		"faketcp_xdp_update_ipv4_header",
		"l3->l3_header_len + sizeof(struct udphdr)",
	} {
		if strings.Contains(main, removed) {
			t.Fatalf("obsolete independent parser path remains: %q", removed)
		}
	}
	if !strings.Contains(tc, "faketcp_parse_tc_l3(skb, &info, &faketcp_l3) != FAKETCP_L3_OK") {
		t.Fatal("TC ingress did not revalidate the XDP-decoded packet with the shared L3 contract")
	}

	preflightStart := strings.Index(main, "static __always_inline int faketcp_preflight_egress")
	preflightEnd := strings.Index(main, "static __always_inline __s64 faketcp_rotation_checksum")
	if preflightStart < 0 || preflightEnd <= preflightStart {
		t.Fatal("FakeTCP preflight boundaries are missing")
	}
	preflight := main[preflightStart:preflightEnd]
	tcGate := strings.Index(preflight, "faketcp_parse_tc_l3(skb, info, &l3)")
	capture := strings.Index(preflight, "faketcp_capture_first_packet(skb, info, &l3")
	if tcGate < 0 || capture < 0 || tcGate >= capture {
		t.Fatal("fixed-header transform gate must precede first-packet capture")
	}
	tcIngressStart := strings.Index(tc, "int wg_mix_ingress(struct __sk_buff *skb)")
	if tcIngressStart < 0 {
		t.Fatal("TC ingress entry point is missing")
	}
	tcIngress := tc[tcIngressStart:]
	tcIngressGate := strings.Index(tcIngress, "faketcp_parse_tc_l3(skb, &info, &faketcp_l3)")
	tcMutation := strings.Index(tcIngress, "update_type_word(skb, &info")
	if tcIngressGate < 0 || tcMutation < 0 || tcIngressGate >= tcMutation {
		t.Fatal("fixed-header transform gate must precede TC ingress mutation")
	}

	xdpStart := strings.Index(main, "int wg_mix_faketcp_ingress(struct xdp_md *xdp)")
	if xdpStart < 0 {
		t.Fatal("FakeTCP XDP entry point is missing")
	}
	xdp := main[xdpStart:]
	parse := strings.Index(xdp, "parse_rc = faketcp_parse_l3")
	lookup := strings.Index(xdp, "listener = faketcp_xdp_managed_port")
	xdpGate := strings.Index(xdp, "faketcp_managed_transform_status(&l3, l3.transport_protocol)")
	event := strings.Index(xdp, "faketcp_emit_event(&key")
	mutation := strings.Index(xdp, "bpf_xdp_store_bytes(xdp, l3.l4_off")
	if parse < 0 || lookup < 0 || xdpGate < 0 || event < 0 || mutation < 0 ||
		parse >= lookup || lookup >= xdpGate || xdpGate >= event || xdpGate >= mutation {
		t.Fatal("ParseL3, managed-port lookup and the sole transform gate must precede XDP capture/mutation")
	}
	if fakeTCPImplementedCapabilities&fakeTCPCapabilityL3Parser != 0 {
		t.Fatal("L3 parser capability opened before verifier and real-host evidence")
	}
}
