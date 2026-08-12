package dataplane

import (
	"os"
	"strings"
	"testing"
)

func TestFakeTCPUserspaceControlEgressIsNarrowAndFailClosed(t *testing.T) {
	tcBytes, err := os.ReadFile("../../bpf/wg_mix_tc.c")
	if err != nil {
		t.Fatal(err)
	}
	controlBytes, err := os.ReadFile("../faketcp/control_packet.go")
	if err != nil {
		t.Fatal(err)
	}
	tc := string(tcBytes)
	control := string(controlBytes)

	authorize := sourceSection(t, tc,
		"static __always_inline int faketcp_authorize_userspace_control(",
		"#endif\n\nstatic __always_inline int run_xor_egress_segment(")
	if strings.Contains(tc,
		"static __noinline int faketcp_authorize_userspace_control(") {
		t.Fatal("userspace control authorization regained a BPF-to-BPF call frame")
	}
	if !strings.Contains(tc,
		"#define FAKETCP_USERSPACE_CONTROL_IPV4_ID 0x5747U") {
		t.Fatal("userspace control lost its non-zero IP_HDRINCL-stable IPv4 identification")
	}
	for _, want := range []string{
		"if (ip_protocol != IPPROTO_TCP)\n\t\treturn 0",
		"sizeof(*headers) != skb->len - network_off",
		"headers = &scratch->ingress.headers",
		"bpf_skb_load_bytes(skb, network_off, headers",
		"headers->ip.version != 4",
		"headers->ip.ihl != sizeof(headers->ip) / 4",
		"headers->ip.id != bpf_htons(FAKETCP_USERSPACE_CONTROL_IPV4_ID)",
		"headers->ip.ttl != 64",
		"fragment & (IP_RESERVED | IP_MF | IP_OFFSET)",
		"bpf_ntohs(headers->ip.tot_len) != sizeof(*headers)",
		"headers->tcp.doff != sizeof(headers->tcp) / 4",
		"headers->tcp.res1 != 0 || headers->tcp.urg_ptr != 0",
		"headers->tcp.window == 0",
		"faketcp_ipv4_tcp_control_checksums_valid(&headers->ip",
		"rule->action != ACTION_REWRITE",
		"rule->transport_mode != TRANSPORT_FAKETCP",
		".wg_id = rule->wg_id",
		"faketcp_session_key_valid(&flow_key.session)",
		"faketcp_session_snapshot_established(",
		"faketcp_runtime_identity(generation)",
		"faketcp_incarnations_equal(",
		"FAKETCP_EVENT_NEED_HANDSHAKE : FAKETCP_EVENT_SYN",
		"bpf_map_lookup_elem(&faketcp_control_flow_map, &flow_key)",
		"flow->last_event_nanos != 0 ? 1 : -1",
	} {
		if !strings.Contains(authorize, want) {
			t.Fatalf("userspace control authorization lost %q", want)
		}
	}
	for _, forbidden := range []string{
		"return TC_ACT_OK",
		"FAKETCP_FLAG_RST",
		"FAKETCP_FLAG_FIN",
		"FAKETCP_FLAG_PSH",
		"bpf_map_update_elem(",
	} {
		if strings.Contains(authorize, forbidden) {
			t.Fatalf("userspace control authorization widened through %q", forbidden)
		}
	}
	if got := strings.Count(authorize, "bpf_skb_load_bytes("); got != 1 {
		t.Fatalf("userspace control fixed-header loads=%d, want 1", got)
	}
	for _, flags := range []string{
		"controlIPv4Identification = 0x5747",
		"binary.BigEndian.PutUint16(packet[4:6], controlIPv4Identification)",
		"case FlagSYN, FlagSYN | FlagACK, FlagACK:",
		"unsupported TCP flags",
	} {
		if !strings.Contains(control, flags) {
			t.Fatalf("userspace control marshaller contract lost %q", flags)
		}
	}

	egress := sourceSection(t, tc,
		"int wg_mix_egress(struct __sk_buff *skb)",
		"SEC(\"classifier/ingress\")")
	managed := strings.Index(egress, "managed = lookup_managed_fwmark(")
	authorization := strings.Index(egress, "rc = faketcp_authorize_userspace_control(")
	accept := strings.Index(egress, "if (rc > 0)\n\t\treturn TC_ACT_OK")
	reject := strings.Index(egress, "inc_faketcp_stat(FAKETCP_STAT_ADMISSION_BYPASS_REJECT)")
	udpParser := strings.Index(egress, "rc = faketcp_parse_tc_egress_packet(")
	if managed < 0 || authorization < 0 || accept < 0 || reject < 0 || udpParser < 0 ||
		!(managed < authorization && authorization < accept && accept < reject && reject < udpParser) {
		t.Fatal("managed controls must authorize or fail closed before the ordinary UDP parser")
	}
}
