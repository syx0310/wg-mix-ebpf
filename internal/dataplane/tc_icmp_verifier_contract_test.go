package dataplane

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestTCICMPPostParserReadsUseFixedSKBHelpers(t *testing.T) {
	sourceBytes, err := os.ReadFile("../../bpf/wg_mix_tc.c")
	if err != nil {
		t.Fatal(err)
	}
	source := string(sourceBytes)
	checksum := sourceSection(t, source,
		"static __always_inline int derive_icmp_checksum_from_udp(",
		"static __always_inline __u16 lookup_icmp_sequence(")
	sequence := sourceSection(t, source,
		"static __always_inline __u16 lookup_icmp_sequence(",
		"static __always_inline void remember_icmp_sequence(")

	directPacketRead := regexp.MustCompile(`(?m)(?:void \*data(?:_end)?\b|struct (?:iphdr|udphdr) \*(?:iph|udp)\b|\b(?:iph|udp)->|data \+ info->(?:ip|udp)_off)`)
	for name, section := range map[string]string{
		"derived ICMP checksum": checksum,
		"ICMP sequence lookup":  sequence,
	} {
		if match := directPacketRead.FindString(section); match != "" {
			t.Fatalf("%s regained verifier-unsafe direct packet read %q", name, match)
		}
	}

	for _, required := range []string{
		"offsetof(struct udphdr, check)",
		"offsetof(struct udphdr, len)",
		"offsetof(struct iphdr, saddr)",
		"offsetof(struct iphdr, daddr)",
		"&wire_word, sizeof(wire_word)",
		"&old_wire, sizeof(old_wire)",
		"csum_sub_type_word(&sum, old_wire)",
	} {
		if !strings.Contains(checksum, required) {
			t.Fatalf("derived ICMP checksum lost fixed helper read %q", required)
		}
	}
	if got := strings.Count(checksum, "bpf_skb_load_bytes("); got != 4 {
		t.Fatalf("derived ICMP checksum helper read count = %d, want 4", got)
	}
	firstPacketRead := strings.Index(checksum, "bpf_skb_load_bytes(")
	for _, consumedBeforePacketRead := range []string{
		"csum_sub_type_word(&sum, old_wire)",
		"csum_add_word(&sum, ((__u16)icmp_type) << 8)",
		"csum_add_word(&sum, icmp_id)",
		"csum_add_word(&sum, icmp_sequence)",
		"csum_add_type_word(&sum, new_wire)",
	} {
		position := strings.Index(checksum, consumedBeforePacketRead)
		if position < 0 || firstPacketRead < 0 || position > firstPacketRead {
			t.Fatalf("caller scalar %q is not consumed before packet helper reads", consumedBeforePacketRead)
		}
	}
	for _, forbiddenStackSlot := range []string{
		"ipv4_address",
		"udp_check",
		"udp_len",
	} {
		if strings.Contains(checksum, forbiddenStackSlot) {
			t.Fatalf("derived ICMP checksum regained stack slot %q", forbiddenStackSlot)
		}
	}
	for _, required := range []string{
		"offsetof(struct iphdr, daddr)",
		"&key.remote_ipv4, sizeof(key.remote_ipv4)",
	} {
		if !strings.Contains(sequence, required) {
			t.Fatalf("ICMP sequence lookup lost fixed helper read %q", required)
		}
	}
	if got := strings.Count(sequence, "bpf_skb_load_bytes("); got != 1 {
		t.Fatalf("ICMP sequence helper read count = %d, want 1", got)
	}
	if strings.Contains(sequence, "remote_ipv4 =") {
		t.Fatal("ICMP sequence lookup regained a separate remote IPv4 stack slot")
	}
}
