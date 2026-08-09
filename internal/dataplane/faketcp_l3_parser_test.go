package dataplane

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"testing"

	faketcpmodel "github.com/syx0310/wg-mix-ebpf/internal/faketcp"
)

func TestFakeTCPIPv4OptionsChecksumDeltaMatchesFullRecompute(t *testing.T) {
	header := make([]byte, 60)
	header[0] = 0x4f
	binary.BigEndian.PutUint16(header[2:4], 100)
	header[6] = 0x40 // DF
	header[8] = 64
	header[9] = 6 // TCP
	for i := 20; i < len(header); i++ {
		header[i] = byte(i*17 + 3)
	}
	oldOptions := append([]byte(nil), header[20:]...)
	binary.BigEndian.PutUint16(header[10:12], internetChecksum(header))

	oldFields := []byte{0, 100, 64, 6}
	newFields := []byte{0, 88, 64, 17}
	got := replaceChecksumFolded(binary.BigEndian.Uint16(header[10:12]), oldFields, newFields)
	binary.BigEndian.PutUint16(header[2:4], 88)
	header[9] = 17
	binary.BigEndian.PutUint16(header[10:12], 0)
	want := internetChecksum(header)
	if got != want {
		t.Fatalf("IPv4 options checksum delta = %#04x, full recompute = %#04x", got, want)
	}
	if !bytes.Equal(header[20:], oldOptions) {
		t.Fatal("IPv4 options changed while updating total length/protocol checksum")
	}
}

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
		"l3->l3_header_len + sizeof(struct udphdr)",
		"l3.l4_off + sizeof(udp)",
		"faketcp_xdp_update_ipv4_header",
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
	} {
		if strings.Contains(main, removed) {
			t.Fatalf("obsolete independent parser path remains: %q", removed)
		}
	}
	if !strings.Contains(tc, "faketcp_parse_tc_l3(skb, &info, &faketcp_l3) < 0") {
		t.Fatal("TC ingress did not revalidate the XDP-decoded packet with the shared L3 contract")
	}
	if fakeTCPImplementedCapabilities&fakeTCPCapabilityL3Parser != 0 {
		t.Fatal("L3 parser capability opened before verifier and real-host evidence")
	}
}
