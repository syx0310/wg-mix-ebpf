package dataplane

import (
	"bytes"
	"encoding/binary"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestFakeTCPIncrementalTransportChecksumMatchesFullRecompute(t *testing.T) {
	for _, payloadLen := range []int{12, 13, 32, 33, 1419, 1420, 1421, 1451, 1452} {
		t.Run(strconv.Itoa(payloadLen), func(t *testing.T) {
			payload := make([]byte, payloadLen)
			for i := range payload {
				payload[i] = byte(i*29 + 7)
			}
			udp := make([]byte, 8)
			binary.BigEndian.PutUint16(udp[0:2], 31001)
			binary.BigEndian.PutUint16(udp[2:4], 443)
			binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)+len(payload)))
			udpChecksum := testTransportChecksum(17, udp, payload)

			tcp := make([]byte, 20)
			copy(tcp[0:4], udp[0:4])
			binary.BigEndian.PutUint32(tcp[4:8], 0x12345678)
			binary.BigEndian.PutUint32(tcp[8:12], 0x87654321)
			tcp[12] = 5 << 4
			tcp[13] = 0x18
			binary.BigEndian.PutUint16(tcp[14:16], 65535)
			wirePayload := append(append([]byte(nil), payload[12:]...), payload[:12]...)
			wantTCP := testTransportChecksum(6, tcp, wirePayload)

			oldWords := make([]byte, 24)
			oldWords[1] = 17
			binary.BigEndian.PutUint16(oldWords[2:4], uint16(len(udp)+len(payload)))
			copy(oldWords[4:], udp)
			newWords := make([]byte, 24)
			newWords[1] = 6
			binary.BigEndian.PutUint16(newWords[2:4], uint16(len(tcp)+len(payload)))
			copy(newWords[4:], tcp)
			gotTCP := replaceChecksumFolded(udpChecksum, oldWords, newWords)
			if payloadLen&1 != 0 {
				gotTCP = replaceChecksumFolded(gotTCP, alignedRotationHead(payload[:12]), shiftedRotationHead(payload[:12]))
			}
			if gotTCP != wantTCP {
				t.Fatalf("incremental TCP checksum = %#04x, full recompute = %#04x", gotTCP, wantTCP)
			}

			gotUDP := replaceChecksumFolded(gotTCP, newWords, oldWords)
			if payloadLen&1 != 0 {
				gotUDP = replaceChecksumFolded(gotUDP, shiftedRotationHead(payload[:12]), alignedRotationHead(payload[:12]))
			}
			if gotUDP != udpChecksum {
				t.Fatalf("incremental UDP checksum = %#04x, original = %#04x", gotUDP, udpChecksum)
			}
		})
	}
}

func testTransportChecksum(protocol byte, header, payload []byte) uint16 {
	pseudo := []byte{10, 0, 0, 1, 10, 0, 0, 2, 0, protocol, 0, 0}
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(header)+len(payload)))
	data := append(append(append([]byte(nil), pseudo...), header...), payload...)
	checksum := internetChecksum(data)
	if checksum == 0 {
		return 0xffff
	}
	return checksum
}

func alignedRotationHead(head []byte) []byte {
	out := make([]byte, 16)
	copy(out, head)
	return out
}

func shiftedRotationHead(head []byte) []byte {
	out := make([]byte, 16)
	copy(out[1:], head)
	return out
}

func replaceChecksumFolded(checksum uint16, oldData, newData []byte) uint16 {
	if len(oldData) != len(newData) || len(oldData)&1 != 0 {
		panic("checksum replacement inputs must have equal even lengths")
	}
	sum := uint64(^checksum)
	for i := 0; i < len(oldData); i += 2 {
		oldWord := binary.BigEndian.Uint16(oldData[i : i+2])
		newWord := binary.BigEndian.Uint16(newData[i : i+2])
		sum += uint64(^oldWord) + uint64(newWord)
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	result := ^uint16(sum)
	if result == 0 {
		return 0xffff
	}
	return result
}

func TestFakeTCPXORWireOrderRoundTrip(t *testing.T) {
	key := make([]byte, 256)
	for i := range key {
		key[i] = byte(i*19 + 11)
	}
	for _, payloadLen := range []int{
		12, 13, 31, 32, 33, 35, 63, 64, 65, 127, 128, 129,
		1419, 1420, 1421, 1451, 1452,
	} {
		t.Run(strconv.Itoa(payloadLen), func(t *testing.T) {
			payload := make([]byte, payloadLen)
			for i := range payload {
				payload[i] = byte(i*7 + 3)
			}
			want := append([]byte(nil), payload...)
			copy(want[:4], []byte{1, 0, 0, 0})
			copy(payload[:4], []byte{0x61, 0x62, 0x63, 0x64}) // mixed type word

			// Egress contract: type-word rewrite, XOR, then FakeTCP rotation.
			xorStoreRange(payload, key, 0, len(payload))
			beforeChecksum := internetChecksum(payload)
			wire := append(append([]byte(nil), payload[12:]...), payload[:12]...)
			adjusted := beforeChecksum
			if payloadLen&1 != 0 {
				adjusted = fakeTCPRotationChecksum(beforeChecksum, payload[:12], false)
			}
			if got := internetChecksum(wire); adjusted != got {
				t.Fatalf("egress rotation checksum = %#04x, want %#04x", adjusted, got)
			}
			if payloadLen > 12 && (bytes.Equal(wire[:4], want[:4]) || bytes.Equal(wire[:4], payload[:4])) {
				t.Fatal("FakeTCP wire prefix exposed a type-word position")
			}

			// XDP unrotates before existing TC XOR/type-word reversal.
			restored := append(append([]byte(nil), wire[len(wire)-12:]...), wire[:len(wire)-12]...)
			adjusted = internetChecksum(wire)
			if payloadLen&1 != 0 {
				adjusted = fakeTCPRotationChecksum(adjusted, wire[len(wire)-12:], true)
			}
			if got := internetChecksum(restored); adjusted != got {
				t.Fatalf("ingress rotation checksum = %#04x, want %#04x", adjusted, got)
			}
			xorStoreRange(restored, key, 0, len(restored))
			copy(restored[:4], want[:4])
			if !bytes.Equal(restored, want) {
				t.Fatal("type-word/XOR/FakeTCP composition did not round trip")
			}
		})
	}
}

func fakeTCPRotationChecksum(checksum uint16, head []byte, inverse bool) uint16 {
	if len(head) != 12 {
		panic("FakeTCP rotation head must be 12 bytes")
	}
	aligned := make([]byte, 16)
	shifted := make([]byte, 16)
	copy(aligned, head)
	copy(shifted[1:], head)
	if inverse {
		return replaceChecksumFolded(checksum, shifted, aligned)
	}
	return replaceChecksumFolded(checksum, aligned, shifted)
}

func TestFakeTCPBothEgressBranchesShareEncoderAndIngressMetadataGate(t *testing.T) {
	tcSource, err := os.ReadFile("../../bpf/wg_mix_tc.c")
	if err != nil {
		t.Fatal(err)
	}
	fakeSource, err := os.ReadFile("../../bpf/wg_mix_faketcp.h")
	if err != nil {
		t.Fatal(err)
	}
	tc := string(tcSource)
	fake := string(fakeSource)

	for _, want := range []string{
		"bpf_tail_call(skb, &faketcp_egress_programs",
		"return faketcp_encode_established(skb, &info, rule, generation);",
		"listener->transport_mode == TRANSPORT_FAKETCP",
		"!faketcp_metadata_valid(skb, generation)",
		"faketcp_capture_first_packet(skb, info, rule, &key)",
		"record_len = sizeof(record->event) + packet_len",
		"faketcp_tcp_checksum_from_materialized_udp",
	} {
		if !strings.Contains(tc, want) && !strings.Contains(fake, want) {
			t.Fatalf("FakeTCP pipeline source missing %q", want)
		}
	}
	if strings.Count(tc+fake, "faketcp_encode_established(skb, &info, rule, generation)") != 2 {
		t.Fatal("direct and tail-call branches must converge on exactly one FakeTCP encoder")
	}
	if !strings.Contains(fake, "single encoder used by both") {
		t.Fatal("shared FakeTCP encoder contract is missing")
	}
	if strings.Contains(fake, "info->payload_len & 1") || strings.Contains(fake, "(payload_len & 1))") {
		t.Fatal("odd-length FakeTCP payload rejection reappeared")
	}
	if strings.Count(fake, "FAKETCP_EVENT_NEED_HANDSHAKE") != 2 {
		t.Fatal("NEED_HANDSHAKE must only be defined and emitted with the captured pre-transform packet")
	}
	egressStart := strings.Index(tc, "int wg_mix_egress(struct __sk_buff *skb)")
	if egressStart < 0 {
		t.Fatal("egress entry point is missing")
	}
	egress := tc[egressStart:]
	preflight := strings.Index(egress, "faketcp_preflight_egress(skb, &info, rule, generation)")
	typeWord := strings.Index(egress, "update_type_word(skb, &info, old_wire, new_wire, 1)")
	if preflight < 0 || typeWord < 0 || preflight >= typeWord {
		t.Fatal("FakeTCP first-packet capture must precede type-word and XOR mutation")
	}
}

func TestFakeTCPXDPManagedPortLookupPrecedesUnsupportedHeaderExit(t *testing.T) {
	source, err := os.ReadFile("../../bpf/wg_mix_faketcp.h")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, want := range []string{
		"faketcp_managed_if_map SEC(\".maps\")",
		"faketcp_managed_port_map SEC(\".maps\")",
		"faketcp_xdp_ipv6_policy",
		"for (int vlan_depth = 0; vlan_depth < 2; vlan_depth++)",
		"return managed_interface ? XDP_DROP : XDP_PASS",
		"AH, ESP and unknown extension/transport values",
		"next_header == IPPROTO_TCP || next_header == IPPROTO_UDP",
		"A managed packet can only PASS after successful FakeTCP decoding",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("managed-port fail-closed source contract missing %q", want)
		}
	}
	xdpStart := strings.Index(text, "int wg_mix_faketcp_ingress(struct xdp_md *xdp)")
	if xdpStart < 0 {
		t.Fatal("FakeTCP XDP entry point is missing")
	}
	xdp := text[xdpStart:]
	lookup := strings.Index(xdp, "listener = faketcp_xdp_managed_port")
	unsupported := strings.Index(xdp, "if ((fragment_offset & IP_MF) || iph->ihl != 5 || tcp->doff != 5)")
	if lookup < 0 || unsupported < 0 || lookup >= unsupported {
		t.Fatal("managed-port lookup must precede IPv4 options/fragment rejection")
	}
}
