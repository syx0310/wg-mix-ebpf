package dataplane

import (
	"bytes"
	"encoding/binary"
	"math/bits"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
)

const (
	fakeTCPLivenessTX uint32 = iota + 1
	fakeTCPLivenessRX
	fakeTCPLivenessTouch
)

type fakeTCPLivenessModel struct {
	lastSeen uint64
	tx       uint32
	rx       uint32
	revision uint64
}

func (session *fakeTCPLivenessModel) mutate(operation uint32, now uint64, argument uint32) {
	if operation == fakeTCPLivenessTX {
		session.tx += argument
	} else if operation == fakeTCPLivenessRX && int32(argument-session.rx) > 0 {
		session.rx = argument
	}
	if operation != fakeTCPLivenessTX && now > session.lastSeen {
		session.lastSeen = now
	}
	session.revision++
}

func (session fakeTCPLivenessModel) idle(now, timeout uint64) bool {
	return now >= session.lastSeen && now-session.lastSeen >= timeout
}

func TestFakeTCPLastSeenTracksPeerActivityOnly(t *testing.T) {
	source, err := os.ReadFile("../../bpf/wg_mix_faketcp.h")
	if err != nil {
		t.Fatal(err)
	}
	mutation := sourceSection(t, string(source),
		"static __always_inline int faketcp_session_mutate(",
		"static __always_inline int faketcp_session_matches_expected_locked(")
	for _, want := range []string{
		"operation != FAKETCP_SESSION_MUTATE_TX &&",
		"now > session->last_seen_nanos",
		"session->last_seen_nanos = now",
	} {
		if !strings.Contains(mutation, want) {
			t.Fatalf("FakeTCP peer-liveness mutation contract missing %q", want)
		}
	}
	if strings.Count(mutation, "session->last_seen_nanos = now") != 1 {
		t.Fatal("FakeTCP session mutation must have one peer-only last_seen writer")
	}

	const (
		establishedAt = uint64(100)
		idleTimeout   = uint64(6)
	)
	t.Run("local WireGuard PersistentKeepalive cannot prevent peer expiry", func(t *testing.T) {
		session := fakeTCPLivenessModel{lastSeen: establishedAt, tx: 1001, rx: 9001, revision: 1}
		for now := establishedAt + 1; now <= establishedAt+idleTimeout; now++ {
			// Model the harness/production case where WireGuard emits one local
			// PersistentKeepalive every second while the peer is dead.
			session.mutate(fakeTCPLivenessTX, now, 32)
		}
		if session.lastSeen != establishedAt || !session.idle(establishedAt+idleTimeout, idleTimeout) {
			t.Fatalf("local egress refreshed peer liveness: session=%+v", session)
		}
		if session.tx != 1001+uint32(idleTimeout)*32 || session.revision != 1+idleTimeout {
			t.Fatalf("TX sequence/revision stopped advancing: session=%+v", session)
		}
	})

	t.Run("received FakeTCP keepalive keeps peer session alive", func(t *testing.T) {
		session := fakeTCPLivenessModel{lastSeen: establishedAt, tx: 1001, rx: 9001, revision: 1}
		for now := establishedAt + 1; now <= establishedAt+15; now++ {
			session.mutate(fakeTCPLivenessTX, now, 32)
			if (now-establishedAt)%2 == 0 {
				session.mutate(fakeTCPLivenessTouch, now, 0)
			}
			if session.idle(now, idleTimeout) {
				t.Fatalf("peer keepalive failed to refresh liveness at %d: session=%+v", now, session)
			}
		}
		if session.lastSeen != establishedAt+14 {
			t.Fatalf("last peer keepalive was not retained: session=%+v", session)
		}
	})

	t.Run("admitted peer data refreshes peer session", func(t *testing.T) {
		session := fakeTCPLivenessModel{lastSeen: establishedAt, rx: 9001, revision: 1}
		session.mutate(fakeTCPLivenessRX, establishedAt+5, 9100)
		if session.lastSeen != establishedAt+5 || session.rx != 9100 ||
			session.idle(establishedAt+idleTimeout, idleTimeout) {
			t.Fatalf("peer RX did not refresh liveness: session=%+v", session)
		}
	})
}

func TestFakeTCPFullTransportChecksumAndIngressInverseMatch(t *testing.T) {
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
			// The BPF encoder intentionally ignores the incoming UDP checksum:
			// it may be a complete value, a CHECKSUM_PARTIAL pseudo-header seed,
			// or IPv4 zero. All three states must produce the same materialized
			// TCP checksum from pseudo-header + TCP header + complete payload.
			for _, oldUDPChecksum := range []uint16{udpChecksum, 0x9a7b, 0} {
				gotTCP := materializeFakeTCPTCPChecksumModel(oldUDPChecksum, tcp, wirePayload)
				if gotTCP != wantTCP {
					t.Fatalf("old UDP checksum %#04x: materialized TCP checksum = %#04x, want %#04x", oldUDPChecksum, gotTCP, wantTCP)
				}
			}
			gotTCP := wantTCP

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

func materializeFakeTCPTCPChecksumModel(_ uint16, tcp, wirePayload []byte) uint16 {
	return testTransportChecksum(6, tcp, wirePayload)
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

func TestFakeTCPChecksumNativeBPFELWireBytes(t *testing.T) {
	// This independent two-byte fixture has the Internet checksum 0x277f,
	// matching the checksum value observed in the B82 packet oracle. A BPFEL
	// __sum16 scalar carries that network-order word as 0x7f27 so a direct
	// native store emits the correct wire bytes 27 7f.
	const wantChecksum uint16 = 0x277f
	if got := internetChecksum([]byte{0xd8, 0x80}); got != wantChecksum {
		t.Fatalf("fixture checksum = %#04x, want %#04x", got, wantChecksum)
	}

	checksumNative := bits.ReverseBytes16(wantChecksum)
	stored := make([]byte, 2)
	binary.LittleEndian.PutUint16(stored, checksumNative)
	if want := []byte{0x27, 0x7f}; !bytes.Equal(stored, want) {
		t.Fatalf("checksum-native BPFEL store = % x, want wire bytes % x", stored, want)
	}

	// Applying bpf_htons to an already checksum-native value is precisely the
	// former bug: the native scalar becomes 0x277f and the wire sees 7f 27.
	binary.LittleEndian.PutUint16(stored, bits.ReverseBytes16(checksumNative))
	if wrong := []byte{0x7f, 0x27}; !bytes.Equal(stored, wrong) {
		t.Fatalf("double-swapped BPFEL store = % x, want known bad bytes % x", stored, wrong)
	}
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
		"return faketcp_encode_established(skb, info, rule, generation,",
		"return faketcp_encode_direct_established(",
		"listener->transport_mode == TRANSPORT_FAKETCP",
		"faketcp_consume_ingress_admission(skb, &info, listener,",
		"faketcp_capture_first_packet(skb, info, l3, rule, key)",
		"record_len = sizeof(record->event) + packet_len",
		"faketcp_materialize_tcp_checksum",
		"faketcp_prepare_udp(skb, info->ip_off, info->udp_off",
		"bpf_skb_change_tail(skb, skb->len + FAKETCP_HEADER_DELTA, 0)",
	} {
		if !strings.Contains(tc, want) && !strings.Contains(fake, want) {
			t.Fatalf("FakeTCP pipeline source missing %q", want)
		}
	}
	directWrapper := sourceSection(t, fake,
		"static __always_inline int faketcp_encode_direct_established(",
		"static __always_inline int faketcp_encode_established(")
	xorWrapper := sourceSection(t, fake,
		"static __always_inline int faketcp_encode_established(",
		"static __always_inline int faketcp_continue_egress")
	if strings.Count(directWrapper, "faketcp_encode_established_authorized(") != 1 ||
		strings.Count(xorWrapper, "faketcp_encode_established_authorized(") != 1 {
		t.Fatal("direct and tail-call authority wrappers must converge on the shared packet encoder")
	}
	if !strings.Contains(fake, "The packet rewrite is shared") {
		t.Fatal("shared FakeTCP encoder contract is missing")
	}
	if strings.Contains(fake, "info->payload_len & 1") || strings.Contains(fake, "(payload_len & 1))") {
		t.Fatal("odd-length FakeTCP payload rejection reappeared")
	}
	if strings.Count(fake, "#define FAKETCP_EVENT_NEED_HANDSHAKE 1") != 1 ||
		strings.Count(fake, ".type = FAKETCP_EVENT_NEED_HANDSHAKE") != 1 {
		t.Fatal("NEED_HANDSHAKE must only be emitted with the captured pre-transform packet")
	}
	egressStart := strings.Index(tc, "int wg_mix_egress(struct __sk_buff *skb)")
	if egressStart < 0 {
		t.Fatal("egress entry point is missing")
	}
	egress := tc[egressStart:]
	xorCheckpoint := strings.Index(egress, "faketcp_egress_admission_checkpoint(")
	directCheckpoint := strings.Index(egress, "faketcp_direct_egress_admission_checkpoint(")
	xorTypeWord := strings.Index(egress, "update_type_word(skb, info, old_wire, new_wire, 1)")
	directEncode := strings.Index(egress, "return faketcp_encode_direct_established(")
	directTypeWord := -1
	if directEncode >= 0 {
		directTypeWord = strings.LastIndex(egress[:directEncode], "update_type_word(skb, info, old_wire, new_wire, 1)")
	}
	if xorCheckpoint < 0 || directCheckpoint < 0 || xorTypeWord < 0 || directTypeWord < 0 ||
		!(xorCheckpoint < xorTypeWord && directCheckpoint < directTypeWord) {
		t.Fatal("each FakeTCP admission checkpoint must precede its type-word/XOR mutation")
	}
}

func TestFakeTCPChecksumNormalizationMTUAndGSODispatchStayHardGated(t *testing.T) {
	source, err := os.ReadFile("../../bpf/wg_mix_faketcp.h")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	tcSource, err := os.ReadFile("../../bpf/wg_mix_tc.c")
	if err != nil {
		t.Fatal(err)
	}
	tc := string(tcSource)

	preflightStart := strings.Index(text, "static __always_inline int faketcp_egress_admission_checkpoint")
	gsoStart := strings.Index(text, "faketcp_encode_gso_segments(struct __sk_buff *skb")
	checksumCommentStart := strings.Index(text, "// TC's public __sk_buff ABI")
	checksumStart := strings.Index(text, "static __always_inline int faketcp_materialize_tcp_checksum")
	encoderStart := strings.Index(text, "static __always_inline int faketcp_encode_established")
	continuationStart := strings.Index(text, "static __always_inline int faketcp_continue_egress")
	if preflightStart < 0 || gsoStart < 0 || checksumCommentStart < 0 || checksumStart < 0 || encoderStart < 0 || continuationStart < 0 ||
		preflightStart >= gsoStart || gsoStart >= checksumCommentStart || checksumCommentStart >= checksumStart ||
		checksumStart >= encoderStart || encoderStart >= continuationStart {
		t.Fatal("FakeTCP checkpoint/checksum/encoder sections are missing or malformed")
	}

	preflight := text[preflightStart : strings.Index(text[preflightStart:], "struct faketcp_gso_loop_context")+preflightStart]
	gsoProjection := strings.Index(preflight, "faketcp_gso_build_projection(skb, info, profile, cipher")
	flowLookup := strings.Index(preflight, "faketcp_tc_key(skb, info, l3, local_ipv4, remote_ipv4, generation,")
	if gsoProjection < 0 || flowLookup < 0 || gsoProjection >= flowLookup {
		t.Fatal("aggregate geometry and every segment contract must be proven before flow/session admission")
	}
	for _, want := range []string{
		"feature_mask |= FAKETCP_ADMISSION_F_GSO",
		"admission->gso = *gso",
		"if (is_gso)",
		"FAKETCP_STAT_GSO_REJECT",
	} {
		if !strings.Contains(preflight, want) {
			t.Fatalf("GSO admission contract missing %q", want)
		}
	}
	egressStart := strings.Index(tc, "int wg_mix_egress(struct __sk_buff *skb)")
	if egressStart < 0 {
		t.Fatal("egress entry point is missing")
	}
	egress := tc[egressStart:]
	parse := strings.Index(egress, "faketcp_parse_tc_egress_packet(skb, generation, faketcp_packet)")
	l3Gate := strings.Index(egress, "faketcp_tc_fixed_udp_status(faketcp_packet)")
	gsoDispatch := strings.Index(egress, "return faketcp_encode_gso_segments(")
	nonGSOPrepare := strings.Index(egress, "if (faketcp_prepare_udp(")
	xorCheckpoint := strings.Index(egress, "if (faketcp_egress_admission_checkpoint(")
	directCheckpoint := strings.Index(egress, "if (faketcp_direct_egress_admission_checkpoint(")
	firstNonGSOType := strings.Index(egress, "rc = update_type_word(skb, info, old_wire, new_wire, 1)")
	directEncode := strings.Index(egress, "return faketcp_encode_direct_established(")
	directNonGSOType := -1
	if directEncode >= 0 {
		directNonGSOType = strings.LastIndex(egress[:directEncode], "rc = update_type_word(skb, info, old_wire, new_wire, 1)")
	}
	if parse < 0 || l3Gate < 0 || gsoDispatch < 0 || nonGSOPrepare < 0 || xorCheckpoint < 0 || directCheckpoint < 0 ||
		firstNonGSOType < 0 || directNonGSOType < 0 ||
		!(parse < l3Gate && l3Gate < gsoDispatch && gsoDispatch < nonGSOPrepare &&
			nonGSOPrepare < xorCheckpoint && xorCheckpoint < firstNonGSOType &&
			firstNonGSOType < directCheckpoint && directCheckpoint < directNonGSOType) {
		t.Fatal("shared L3 gate/prepare must precede the XOR token and direct authority paths")
	}
	gso := text[gsoStart:checksumCommentStart]
	gsoPrepare := strings.Index(gso, "faketcp_prepare_udp(skb, info->ip_off, info->udp_off")
	gsoCheckpoint := strings.Index(gso, "faketcp_egress_admission_checkpoint(")
	gsoConsume := strings.Index(gso, "faketcp_consume_egress_admission(")
	gsoRewrite := strings.Index(gso, "bpf_loop(context.gso_segments, faketcp_gso_rewrite_type")
	gsoMutation := strings.Index(gso, "faketcp_session_mutate(session, generation, now,")
	gsoCommit := strings.Index(gso, "faketcp_commit_udp_gso(")
	if gsoPrepare < 0 || gsoCheckpoint < 0 || gsoConsume < 0 || gsoRewrite < 0 || gsoMutation < 0 || gsoCommit < 0 ||
		!(gsoPrepare < gsoCheckpoint && gsoCheckpoint < gsoConsume && gsoConsume < gsoRewrite &&
			gsoRewrite < gsoMutation && gsoMutation < gsoCommit) {
		t.Fatal("GSO prepare/checkpoint/consume/transform/stable-writer/commit order drifted")
	}

	materialize := text[checksumCommentStart:encoderStart]
	for _, want := range []string{
		"does not expose ip_summed, csum_start or",
		"The old UDP checksum is deliberately ignored",
		"struct faketcp_ipv4_pseudo_header pseudo",
		"for (int i = 0; i < FAKETCP_CHECKSUM_CHUNK_COUNT; i++)",
		"bpf_skb_load_bytes(skb, payload_off + processed",
		"__builtin_memset(chunk, 0, sizeof(chunk))",
		"processed != payload_len",
	} {
		if !strings.Contains(materialize, want) {
			t.Fatalf("full-checksum materialization contract missing %q", want)
		}
	}
	if strings.Contains(materialize, "old_udp") {
		t.Fatal("full TCP checksum materialization must not consume the old UDP checksum or seed")
	}
	if !strings.Contains(materialize, "tcp->check = fold_csum(sum)") ||
		strings.Contains(materialize, "tcp->check = bpf_htons(fold_csum(sum))") {
		t.Fatal("bpf_csum_diff/fold_csum output must be stored as checksum-native __be16 without a second byte swap")
	}

	encoder := text[encoderStart:continuationStart]
	normalize := strings.Index(encoder, "bpf_skb_change_tail(skb, skb->len + FAKETCP_HEADER_DELTA, 0)")
	checksum := strings.Index(encoder, "faketcp_materialize_tcp_checksum(skb")
	if normalize < 0 || checksum < 0 || normalize >= checksum {
		t.Fatal("packet growth and full checksum recompute are missing or out of order")
	}
	if strings.Contains(encoder, "bpf_check_mtu") || strings.Contains(encoder, "faketcp_mtu_allows_growth") {
		t.Fatal("legacy device-only MTU fallback remains reachable after unified prepare")
	}
	for _, want := range []string{
		"old_total_len != sizeof(struct iphdr) + udp_len",
		"old_total_len > FAKETCP_MAX_IPV4_TOTAL_LEN",
		"old_total_len != skb->len - info->ip_off",
	} {
		if !strings.Contains(encoder, want) {
			t.Fatalf("bounded checksum read precondition missing %q", want)
		}
	}
}

func TestFakeTCPIngressChecksumInverseStaysChecksumNative(t *testing.T) {
	source, err := os.ReadFile("../../bpf/wg_mix_faketcp.h")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	xdp := sourceSection(t, text,
		"faketcp_xdp_ingress_body(struct xdp_md *xdp, __u64 generation)",
		"SEC(\"xdp\")")

	for _, want := range []string{
		"sum = (~old_tcp->check) & 0xffff",
		"udp->check = fold_csum(sum)",
		"new_ip->check = fold_csum(sum)",
	} {
		if !strings.Contains(xdp, want) {
			t.Fatalf("checksum-native FakeTCP ingress inverse missing %q", want)
		}
	}
	for _, forbidden := range []string{
		"(~bpf_ntohs(old_tcp->check))",
		"udp->check = bpf_htons(fold_csum(sum))",
		"new_ip->check = bpf_htons(fold_csum(sum))",
	} {
		if strings.Contains(xdp, forbidden) {
			t.Fatalf("FakeTCP ingress inverse byte-swaps checksum-native state through %q", forbidden)
		}
	}
}

func TestFakeTCPFoldedChecksumWriteSitesStayChecksumNative(t *testing.T) {
	source, err := os.ReadFile("../../bpf/wg_mix_faketcp.h")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)

	for _, write := range []string{
		"tcp->check = fold_csum(sum)",
		"udp->check = fold_csum(sum)",
		"new_ip->check = fold_csum(sum)",
	} {
		if got := strings.Count(text, write); got != 1 {
			t.Fatalf("FakeTCP checksum-native write %q count = %d, want 1", write, got)
		}
	}
	if got := strings.Count(text, "= fold_csum(sum)"); got != 3 {
		t.Fatalf("FakeTCP folded checksum write count = %d, want 3", got)
	}
	if strings.Contains(text, "= bpf_htons(fold_csum(sum))") {
		t.Fatal("FakeTCP folded checksum output regained a second byte-order conversion")
	}

	control := sourceSection(t, text,
		"faketcp_ipv4_tcp_control_checksums_valid(const struct iphdr *iph",
		"#ifdef WG_MIX_FAKETCP_LEGACY_515")
	if strings.Count(control, "fold_csum(sum)") != 2 ||
		!strings.Contains(control, "fold_csum(sum) != 0") ||
		!strings.Contains(control, "fold_csum(sum) == 0") {
		t.Fatal("control checksum validation must remain a residual-zero check, not a wire-field writer")
	}
}

func TestFakeTCPChecksumKfuncIsNarrowExplicitAndNeverAutoLoaded(t *testing.T) {
	moduleSource, err := os.ReadFile("../../kernel/faketcp_checksum/wg_mix_faketcp_checksum.c")
	if err != nil {
		t.Fatal(err)
	}
	bpfSource, err := os.ReadFile("../../bpf/wg_mix_faketcp.h")
	if err != nil {
		t.Fatal(err)
	}
	topSource, err := os.ReadFile("../../bpf/wg_mix_tc.c")
	if err != nil {
		t.Fatal(err)
	}
	makeSource, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}

	module := string(moduleSource)
	for _, want := range []string{
		"SPDX-License-Identifier: GPL-2.0-only",
		"skb_is_gso(skb)",
		"skb->protocol != htons(ETH_P_IP)",
		"ip->protocol != IPPROTO_UDP",
		"switch (skb->ip_summed)",
		"case CHECKSUM_NONE:",
		"case CHECKSUM_PARTIAL:",
		"default:",
		"skb_transport_header_was_set(skb)",
		"skb_checksum_start_offset(skb) != transport_offset",
		"skb->csum_offset != offsetof(struct udphdr, check)",
		"skb_reset_csum_not_inet(skb)",
		"skb->ip_summed = CHECKSUM_NONE",
		"register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS",
		".owner = THIS_MODULE",
	} {
		if !strings.Contains(module, want) {
			t.Fatalf("checksum kfunc hard-gate contract missing %q", want)
		}
	}
	networkIdentity := strings.Index(module, "network_offset != actual_network_offset")
	commonUDPBytes := strings.Index(module, "ntohs(udp->len) != udp_length")
	noneCase := strings.Index(module, "case CHECKSUM_NONE:")
	noneReturn := strings.Index(module, "return WG_MIX_FAKETCP_PREPARE_ACCEPT_NONE;")
	partialCase := strings.Index(module, "case CHECKSUM_PARTIAL:")
	transportHeaderRequired := strings.Index(module, "if (!skb_transport_header_was_set(skb))")
	transportIdentity := strings.Index(module, "transport_offset != actual_transport_offset")
	partialOffsets := strings.Index(module, "skb_checksum_start_offset(skb) != transport_offset")
	if networkIdentity < 0 || commonUDPBytes < 0 || noneCase < 0 || noneReturn < 0 || partialCase < 0 ||
		transportHeaderRequired < 0 || transportIdentity < 0 || partialOffsets < 0 ||
		!(networkIdentity < commonUDPBytes && commonUDPBytes < noneCase &&
			noneCase < noneReturn && noneReturn < partialCase &&
			partialCase < transportHeaderRequired && transportHeaderRequired < transportIdentity &&
			transportIdentity < partialOffsets) {
		t.Fatal("CHECKSUM_NONE must return without a transport header; CHECKSUM_PARTIAL must require exact transport/checksum metadata")
	}
	materializedReturn := strings.Index(module, "if (ret == WG_MIX_FAKETCP_PREPARE_ACCEPT_NONE)")
	partialReset := strings.Index(module, "skb_reset_csum_not_inet(skb)")
	if materializedReturn < 0 || partialReset < 0 || materializedReturn >= partialReset {
		t.Fatal("CHECKSUM_NONE must return before CHECKSUM_PARTIAL metadata normalization")
	}
	deviceGate := strings.Index(module, "if (!device)")
	deviceMTU := strings.Index(module, "device_mtu = READ_ONCE(device->mtu)")
	deviceExceeded := strings.Index(module, "planned_l3_length > device_mtu")
	validRoute := strings.Index(module, "if (!skb_valid_dst(skb))")
	routeIdentity := strings.Index(module, "if (READ_ONCE(dst->dev) != device)")
	routeMTU := strings.Index(module, "route_mtu = dst_mtu(dst)")
	if deviceGate < 0 || deviceMTU < 0 || deviceExceeded < 0 || validRoute < 0 ||
		routeIdentity < 0 || routeMTU < 0 ||
		!(deviceGate < deviceMTU && deviceMTU < deviceExceeded &&
			deviceExceeded < validRoute && validRoute < routeIdentity && routeIdentity < routeMTU) {
		t.Fatal("PMTU admission must validate current device before a live, device-identical route")
	}
	firstPMTUCall := strings.Index(module, "admission = wg_mix_faketcp_admit_pmtu")
	lastPMTUCall := strings.LastIndex(module, "admission = wg_mix_faketcp_admit_pmtu")
	firstChecksumMutation := strings.Index(module, "skb->csum = 0;")
	firstGSOMutation := strings.Index(module, "skb_shinfo(skb)->gso_segs = DIV_ROUND_UP")
	if firstPMTUCall < 0 || lastPMTUCall <= firstPMTUCall || firstChecksumMutation < 0 ||
		firstGSOMutation < 0 || firstPMTUCall >= firstChecksumMutation ||
		lastPMTUCall >= firstGSOMutation {
		t.Fatal("unified prepare must finish PMTU admission before checksum or GSO metadata mutation")
	}
	for _, forbidden := range []string{
		"BPF_PROG_TYPE_XDP",
		"BPF_PROG_TYPE_SCHED_ACT",
		"request_module(",
		"call_usermodehelper(",
	} {
		if strings.Contains(module, forbidden) {
			t.Fatalf("checksum module contains forbidden expansion %q", forbidden)
		}
	}

	bpf := string(bpfSource)
	if strings.Count(bpf, "wg_mix_faketcp_skb_prepare_udp(") != 2 {
		t.Fatal("experimental BPF source must contain one declaration and one call of the required kfunc")
	}
	top := string(topSource)
	licenseGate := strings.Index(top, "#ifdef WG_MIX_EXPERIMENTAL_FAKETCP\n// Kernel kfunc callers")
	experimentalGPL := strings.Index(top, `char LICENSE[] SEC("license") = "GPL";`)
	baselineMIT := strings.Index(top, `char LICENSE[] SEC("license") = "MIT";`)
	if licenseGate < 0 || experimentalGPL < licenseGate || baselineMIT < experimentalGPL {
		t.Fatal("experimental GPL/baseline MIT license split is missing or malformed")
	}

	makefile := string(makeSource)
	if !strings.Contains(makefile, "build-faketcp-checksum-kmod:") ||
		!strings.Contains(makefile, `MO="$(FAKETCP_CHECKSUM_KMOD_OUTPUT)" modules`) {
		t.Fatal("out-of-tree checksum module build target is missing")
	}
	for _, forbidden := range []string{"modules_install", "modprobe", "insmod", "rmmod"} {
		if strings.Contains(makefile, forbidden) {
			t.Fatalf("Makefile must not install, load, unload or clean the module: found %q", forbidden)
		}
	}
}

func TestFakeTCPChecksumMetadataAcceptanceContract(t *testing.T) {
	const (
		checksumNone        = uint8(0)
		checksumUnnecessary = uint8(1)
		checksumComplete    = uint8(2)
		checksumPartial     = uint8(3)
	)
	tests := []struct {
		name                  string
		mode                  uint8
		gso                   bool
		transportHeaderSet    bool
		transportOffset       int
		actualTransportOffset int
		checksumStart         int
		checksumOffset        int
		want                  bool
	}{
		{name: "test-run-none-without-transport-header", mode: checksumNone, transportOffset: 34, want: true},
		{name: "raw-reinject-none-ignores-transport-header", mode: checksumNone, transportHeaderSet: true, transportOffset: 34, actualTransportOffset: 33, want: true},
		{name: "wireguard-partial", mode: checksumPartial, transportHeaderSet: true, transportOffset: 34, actualTransportOffset: 34, checksumStart: 34, checksumOffset: 6, want: true},
		{name: "partial-missing-transport-header", mode: checksumPartial, transportOffset: 34, actualTransportOffset: 34, checksumStart: 34, checksumOffset: 6},
		{name: "partial-wrong-transport-header", mode: checksumPartial, transportHeaderSet: true, transportOffset: 34, actualTransportOffset: 33, checksumStart: 34, checksumOffset: 6},
		{name: "partial-wrong-start", mode: checksumPartial, transportHeaderSet: true, transportOffset: 34, actualTransportOffset: 34, checksumStart: 33, checksumOffset: 6},
		{name: "partial-wrong-offset", mode: checksumPartial, transportHeaderSet: true, transportOffset: 34, actualTransportOffset: 34, checksumStart: 34, checksumOffset: 7},
		{name: "none-gso", mode: checksumNone, gso: true, transportOffset: 34},
		{name: "partial-gso", mode: checksumPartial, gso: true, transportHeaderSet: true, transportOffset: 34, actualTransportOffset: 34, checksumStart: 34, checksumOffset: 6},
		{name: "complete", mode: checksumComplete, transportOffset: 34},
		{name: "unnecessary", mode: checksumUnnecessary, transportOffset: 34},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := fakeTCPChecksumMetadataAccepted(
				test.mode, test.gso, test.transportHeaderSet,
				test.transportOffset, test.actualTransportOffset,
				test.checksumStart, test.checksumOffset,
			)
			if got != test.want {
				t.Fatalf("accepted=%v, want %v", got, test.want)
			}
		})
	}
}

func fakeTCPChecksumMetadataAccepted(
	mode uint8,
	gso bool,
	transportHeaderSet bool,
	transportOffset int,
	actualTransportOffset int,
	checksumStart int,
	checksumOffset int,
) bool {
	if gso {
		return false
	}
	switch mode {
	case 0: // CHECKSUM_NONE: raw reinjection already materialized the packet.
		return true
	case 3: // CHECKSUM_PARTIAL: WireGuard/UDP tunnel offload metadata is exact.
		return transportHeaderSet &&
			actualTransportOffset == transportOffset &&
			checksumStart == transportOffset && checksumOffset == 6
	default:
		return false
	}
}

func TestFakeTCPXDPUsesSharedL3ParserBeforeManagedPortPolicy(t *testing.T) {
	source, err := os.ReadFile("../../bpf/wg_mix_faketcp.h")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, want := range []string{
		"faketcp_managed_if_map SEC(\".maps\")",
		"faketcp_managed_port_map SEC(\".maps\")",
		"faketcp_xdp_l3_start",
		"parser_mode != PARSER_ETHERNET",
		"parse_rc = faketcp_parse_l3",
		"parse_rc == FAKETCP_L3_SAFE_BYPASS",
		"faketcp_managed_transform_status(l3, l3->transport_protocol)",
		"before native-UDP handling, event capture or any packet mutation",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("managed-port fail-closed source contract missing %q", want)
		}
	}
	xdp := sourceSection(t, text,
		"faketcp_xdp_ingress_body(struct xdp_md *xdp, __u64 generation)",
		"SEC(\"xdp\")")
	parse := strings.Index(xdp, "parse_rc = faketcp_parse_l3")
	lookup := strings.Index(xdp, "managed_listener = faketcp_xdp_managed_port")
	unsupported := strings.Index(xdp, "faketcp_managed_transform_status(l3, l3->transport_protocol)")
	if parse < 0 || lookup < 0 || unsupported < 0 || parse >= lookup || lookup >= unsupported {
		t.Fatal("shared L3 validation must precede managed-port lookup and the single transform gate")
	}
}

func TestFakeTCPEstablishedMapCannotLRUEvictUnderSYNPressure(t *testing.T) {
	source, err := os.ReadFile("../../bpf/wg_mix_faketcp.h")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	sessionEnd := strings.Index(text, `} faketcp_session_map SEC(".maps");`)
	if sessionEnd < 0 {
		t.Fatal("FakeTCP established session map is missing")
	}
	sessionStart := strings.LastIndex(text[:sessionEnd], "struct {")
	if sessionStart < 0 {
		t.Fatal("FakeTCP established session map declaration is malformed")
	}
	sessionMap := text[sessionStart:sessionEnd]
	if strings.Contains(sessionMap, "BPF_MAP_TYPE_LRU_HASH") {
		t.Fatal("FakeTCP established sessions must not use an eviction-capable LRU map")
	}
	for _, want := range []string{
		"Only established sessions enter this map",
		"session->state == FAKETCP_STATE_ESTABLISHED",
		"struct bpf_spin_lock lock",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("established-only fast-map contract missing %q", want)
		}
	}
	if !strings.Contains(sessionMap, "__uint(type, BPF_MAP_TYPE_HASH)") {
		t.Fatal("FakeTCP established session map must remain a non-evicting HASH")
	}
}

func TestFakeTCPEstablishedClaimUsesEveryPacketPathValueLock(t *testing.T) {
	source, err := os.ReadFile("../../bpf/wg_mix_faketcp.h")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, want := range []string{
		"struct bpf_spin_lock lock",
		"SEC(\"classifier/faketcp_session_claim\")",
		"int wg_faketcp_session_claim(struct __sk_buff *skb)",
		"session->state = FAKETCP_STATE_DELETE_CLAIMED",
		"faketcp_session_matches_expected_locked(session, &request.expected, 1)",
		"expected->revision != 0",
		"expected->session_id != 0",
		"expected->runtime_incarnation",
		"session->revision != ~0ULL",
		"operation != FAKETCP_SESSION_MUTATE_TX &&",
		"now > session->last_seen_nanos",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("established compare-claim source contract missing %q", want)
		}
	}
	if strings.Contains(text, "bpf_map_update_elem(&faketcp_session_map") {
		t.Fatal("BPF must never insert or replace an established session")
	}
	if strings.Contains(text, "bpf_map_delete_elem(&faketcp_session_map") {
		t.Fatal("packet programs must never bypass the userspace exact-delete finalizer")
	}
	if got := strings.Count(text, "bpf_map_lookup_elem(&faketcp_session_map"); got != 7 {
		t.Fatalf("session-map lookup sites=%d, want claim plus checkpoint/GSO/direct/ingress/XDP paths", got)
	}

	directStart := strings.Index(text, "faketcp_direct_egress_admission_checkpoint(")
	preflightStart := strings.Index(text, "faketcp_egress_admission_checkpoint(")
	gsoStart := strings.Index(text, "faketcp_encode_gso_segments(struct __sk_buff")
	gsoEnd := strings.Index(text, "static __always_inline __s64 faketcp_rotation_checksum")
	encodeStart := strings.Index(text, "faketcp_encode_established_authorized(")
	directEncodeStart := strings.Index(text, "faketcp_encode_direct_established(")
	continueStart := strings.Index(text, "faketcp_continue_egress(struct __sk_buff")
	ingressConsumeStart := strings.Index(text, "faketcp_consume_ingress_admission(")
	xdpCheckpointStart := strings.Index(text, "faketcp_xdp_admission_checkpoint(")
	xdpBodyStart := strings.Index(text, "faketcp_xdp_ingress_body(struct xdp_md *xdp, __u64 generation)")
	if directStart < 0 || preflightStart < 0 || gsoStart < 0 || gsoEnd < 0 || encodeStart < 0 || directEncodeStart < 0 || continueStart < 0 ||
		ingressConsumeStart < 0 || xdpCheckpointStart < 0 || xdpBodyStart < 0 ||
		!(directStart < preflightStart && preflightStart < gsoStart && gsoStart < gsoEnd &&
			gsoEnd < encodeStart && encodeStart < directEncodeStart && directEncodeStart < continueStart &&
			continueStart < ingressConsumeStart && ingressConsumeStart < xdpCheckpointStart &&
			xdpCheckpointStart < xdpBodyStart) {
		t.Fatal("FakeTCP packet path functions are missing or reordered")
	}
	direct := text[directStart:preflightStart]
	preflight := text[preflightStart:gsoStart]
	gso := text[gsoStart:gsoEnd]
	encode := text[encodeStart:directEncodeStart]
	ingressConsume := text[ingressConsumeStart:xdpCheckpointStart]
	xdpCheckpoint := text[xdpCheckpointStart:xdpBodyStart]
	xdp := sourceSection(t, text,
		"faketcp_xdp_ingress_body(struct xdp_md *xdp, __u64 generation)",
		"SEC(\"xdp\")")
	if strings.Count(preflight, "faketcp_session_snapshot_established(") != 1 ||
		strings.Count(preflight, "bpf_map_lookup_elem(&faketcp_session_map") != 1 {
		t.Fatal("TC XOR/GSO checkpoint must take exactly one locked established snapshot")
	}
	if strings.Count(direct, "faketcp_session_snapshot_direct_established(") != 1 ||
		strings.Count(direct, "bpf_map_lookup_elem(&faketcp_session_map") != 1 {
		t.Fatal("TC direct checkpoint must take exactly one compact locked lifetime snapshot")
	}
	matcher := sourceSection(t, text,
		"static __always_inline int faketcp_egress_admission_matches(",
		"static __always_inline int faketcp_direct_egress_admission_checkpoint(")
	if strings.Contains(matcher, "bpf_map_lookup_elem(&faketcp_session_map") ||
		strings.Contains(matcher, "faketcp_session_authority_matches(") ||
		strings.Contains(matcher, "bpf_spin_lock(") {
		t.Fatal("egress token comparison regained a redundant session lookup/lock")
	}
	if strings.Count(encode, "FAKETCP_SESSION_MUTATE_TX") != 1 ||
		strings.Count(encode, "bpf_map_lookup_elem(&faketcp_session_map") != 1 {
		t.Fatal("TC encoder must perform one lookup and one final writer mutation")
	}
	encoderMutation := strings.Index(encode, "faketcp_session_mutate(session, generation, now,")
	if encoderMutation < 0 || strings.Contains(encode[:encoderMutation], "session->") {
		t.Fatal("TC encoder consumed a session field before its sole locked mutation snapshot")
	}
	if strings.Contains(gso, "faketcp_session_admit_established") ||
		strings.Contains(gso, "__sync_fetch_and_add") ||
		strings.Count(gso, "FAKETCP_SESSION_MUTATE_TX") != 1 ||
		strings.Count(gso, "bpf_map_lookup_elem(&faketcp_session_map") != 1 {
		t.Fatal("GSO encoder regained an unlocked/redundant session path or lost its sole mutation")
	}
	gsoMutation := strings.Index(gso, "faketcp_session_mutate(session, generation, now,")
	gsoPrepare := strings.Index(gso, "faketcp_prepare_udp(skb, info->ip_off, info->udp_off")
	gsoCheckpoint := strings.Index(gso, "faketcp_egress_admission_checkpoint(")
	gsoConsume := strings.Index(gso, "faketcp_consume_egress_admission(")
	gsoTypeRewrite := strings.Index(gso, "faketcp_gso_rewrite_type")
	gsoXOR := strings.Index(gso, "faketcp_gso_xor_chunk")
	gsoCommit := strings.Index(gso, "faketcp_commit_udp_gso(")
	if gsoMutation < 0 || gsoPrepare < 0 || gsoCheckpoint < 0 || gsoConsume < 0 ||
		gsoTypeRewrite < 0 || gsoXOR < 0 || gsoCommit < 0 ||
		strings.Contains(gso[:gsoMutation], "session->") ||
		!(gsoPrepare < gsoCheckpoint && gsoCheckpoint < gsoConsume &&
			gsoConsume < gsoTypeRewrite && gsoTypeRewrite < gsoXOR &&
			gsoXOR < gsoMutation && gsoMutation < gsoCommit) {
		t.Fatal("GSO prepare/proof/consume/type/XOR must precede one stable writer and commit")
	}
	if strings.Count(ingressConsume, "faketcp_session_compact_authority_matches(") != 1 ||
		strings.Count(ingressConsume, "bpf_map_lookup_elem(&faketcp_session_map") != 1 {
		t.Fatal("TC ingress must consume one stable-lifetime proof under one read lock")
	}
	if strings.Count(xdpCheckpoint, "faketcp_session_snapshot_established(") != 1 ||
		strings.Count(xdpCheckpoint, "bpf_map_lookup_elem(&faketcp_session_map") != 1 ||
		strings.Count(xdp, "FAKETCP_SESSION_MUTATE_TOUCH") != 1 ||
		strings.Count(xdp, "FAKETCP_SESSION_MUTATE_RX") != 1 {
		t.Fatal("XDP checkpoint reader or keepalive/payload writer lock contract drifted")
	}

	// Packet helpers and rewrite are deliberately outside the tiny writer
	// critical sections. A source-level regression that places a BPF helper
	// between lock/unlock would be rejected by the verifier and extend latency.
	mutationStart := strings.Index(text, "static __always_inline int faketcp_session_mutate(")
	if mutationStart < 0 {
		t.Fatal("shared FakeTCP session mutation helper is missing")
	}
	mutationEnd := strings.Index(text[mutationStart:], "\n}\n\nstatic __always_inline int faketcp_session_matches_expected_locked")
	if mutationEnd < 0 {
		t.Fatal("shared FakeTCP session mutation helper end is missing")
	}
	mutation := text[mutationStart : mutationStart+mutationEnd]
	if strings.Count(mutation, "bpf_spin_lock(&session->lock)") != 1 ||
		strings.Count(mutation, "bpf_spin_unlock(&session->lock)") != 1 ||
		strings.Count(mutation, "session->revision++") != 1 {
		t.Fatal("all packet writers must converge on one value-lock/revision path")
	}
	lockMutation := strings.Index(mutation, "bpf_spin_lock(&session->lock)")
	unlockMutation := strings.Index(mutation, "bpf_spin_unlock(&session->lock)")
	critical := mutation[lockMutation:unlockMutation]
	for _, forbidden := range []string{
		"bpf_ktime_get_ns", "bpf_skb_", "bpf_xdp_", "bpf_csum_diff",
		"inc_faketcp_stat", "inc_stat(",
	} {
		if strings.Contains(critical, forbidden) {
			t.Fatalf("shared mutation critical section contains helper/stat call %q", forbidden)
		}
	}

	claimStart := strings.Index(text, "int wg_faketcp_session_claim(struct __sk_buff *skb)")
	if claimStart < 0 {
		t.Fatal("FakeTCP session claim function bounds are missing")
	}
	claimEnd := strings.Index(text[claimStart:], "\n}\n\nstruct {")
	if claimEnd < 0 {
		t.Fatal("FakeTCP session claim function end is missing")
	}
	claim := text[claimStart : claimStart+claimEnd]
	lock := strings.Index(claim, "bpf_spin_lock(&session->lock)")
	compare := strings.Index(claim, "faketcp_session_matches_expected_locked")
	tombstone := strings.Index(claim, "session->state = FAKETCP_STATE_DELETE_CLAIMED")
	unlock := strings.Index(claim, "bpf_spin_unlock(&session->lock)")
	if lock < 0 || compare < 0 || tombstone < 0 || unlock < 0 ||
		!(lock < compare && compare < tombstone && tombstone < unlock) {
		t.Fatal("claim compare/tombstone linearisation is not wholly under the value lock")
	}
	if strings.Count(claim, "session->state = FAKETCP_STATE_DELETE_CLAIMED") != 1 {
		t.Fatal("claim program must have exactly one tombstone write site")
	}
}

type establishedEncoderLockModel struct {
	mu       sync.Mutex
	state    uint8
	sequence uint32
	revision uint64
	locks    uint64
}

func (model *establishedEncoderLockModel) admit() bool {
	model.mu.Lock()
	defer model.mu.Unlock()
	model.locks++
	return model.state == 3
}

func (model *establishedEncoderLockModel) mutate(payload uint32) bool {
	model.mu.Lock()
	defer model.mu.Unlock()
	model.locks++
	if model.state != 3 || model.revision == ^uint64(0) {
		return false
	}
	model.sequence += payload
	model.revision++
	return true
}

func (model *establishedEncoderLockModel) claim(expectedRevision uint64) bool {
	model.mu.Lock()
	defer model.mu.Unlock()
	model.locks++
	if model.state != 3 || model.revision != expectedRevision {
		return false
	}
	model.state = 4
	return true
}

func (model *establishedEncoderLockModel) encodeWithRedundantAdmission(payload uint32) bool {
	return model.admit() && model.mutate(payload)
}

func (model *establishedEncoderLockModel) encodeWithSingleMutation(payload uint32) bool {
	return model.mutate(payload)
}

func TestFakeTCPEncoderSingleMutationPreservesClaimOrdering(t *testing.T) {
	oldPath := &establishedEncoderLockModel{state: 3, sequence: 100}
	newPath := &establishedEncoderLockModel{state: 3, sequence: 100}
	if !oldPath.encodeWithRedundantAdmission(32) || !newPath.encodeWithSingleMutation(32) ||
		oldPath.sequence != newPath.sequence {
		t.Fatalf("established results differ: old=%#v new=%#v", oldPath, newPath)
	}
	if oldPath.locks != 2 || newPath.locks != 1 {
		t.Fatalf("value locks per packet old=%d new=%d", oldPath.locks, newPath.locks)
	}

	// A claim which wins before mutation is rejected by both paths. A claim
	// which wins after mutation is ordered after that packet in both paths;
	// the removed admission lock was never a packet-emission snapshot.
	oldClaimed := &establishedEncoderLockModel{state: 4, sequence: 100}
	newClaimed := &establishedEncoderLockModel{state: 4, sequence: 100}
	if oldClaimed.encodeWithRedundantAdmission(32) || newClaimed.encodeWithSingleMutation(32) ||
		oldClaimed.sequence != 100 || newClaimed.sequence != 100 {
		t.Fatalf("claimed session was consumed: old=%#v new=%#v", oldClaimed, newClaimed)
	}
	if oldClaimed.locks != 1 || newClaimed.locks != 1 {
		t.Fatalf("claimed value locks old=%d new=%d", oldClaimed.locks, newClaimed.locks)
	}
}

func BenchmarkFakeTCPEncoderValueLocks(b *testing.B) {
	for _, benchmark := range []struct {
		name   string
		encode func(*establishedEncoderLockModel) bool
	}{
		{"redundant-admission", func(model *establishedEncoderLockModel) bool {
			return model.encodeWithRedundantAdmission(1)
		}},
		{"single-mutation", func(model *establishedEncoderLockModel) bool {
			return model.encodeWithSingleMutation(1)
		}},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			model := &establishedEncoderLockModel{state: 3}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if !benchmark.encode(model) {
					b.Fatal("established model rejected packet")
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(model.locks)/float64(b.N), "value-locks/op")
		})
	}
}

func TestFakeTCPGSOFinalMutationHasOneLockAndSerializesDeleteClaim(t *testing.T) {
	model := &establishedEncoderLockModel{state: 3, sequence: 100, revision: 7}
	if !model.encodeWithSingleMutation(160) || model.sequence != 260 ||
		model.revision != 8 || model.locks != 1 {
		t.Fatalf("single aggregate mutation model=%#v", model)
	}

	claimed := &establishedEncoderLockModel{state: 3, sequence: 100, revision: 7}
	if !claimed.claim(7) {
		t.Fatal("fixture claim was rejected")
	}
	if claimed.encodeWithSingleMutation(160) || claimed.sequence != 100 ||
		claimed.revision != 7 || claimed.locks != 2 {
		t.Fatalf("claimed session accepted aggregate mutation: %#v", claimed)
	}

	for iteration := 0; iteration < 256; iteration++ {
		tracing := &establishedEncoderLockModel{state: 3, sequence: 100, revision: 7}
		start := make(chan struct{})
		var wait sync.WaitGroup
		var mutated, deleteClaimed bool
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			mutated = tracing.encodeWithSingleMutation(160)
		}()
		go func() {
			defer wait.Done()
			<-start
			deleteClaimed = tracing.claim(7)
		}()
		close(start)
		wait.Wait()

		if mutated == deleteClaimed || tracing.locks != 2 {
			t.Fatalf("iteration %d mutation=%v claim=%v model=%#v", iteration, mutated, deleteClaimed, tracing)
		}
		if mutated {
			if tracing.state != 3 || tracing.sequence != 260 || tracing.revision != 8 {
				t.Fatalf("iteration %d mutation-first model=%#v", iteration, tracing)
			}
		} else if tracing.state != 4 || tracing.sequence != 100 || tracing.revision != 7 {
			t.Fatalf("iteration %d claim-first model=%#v", iteration, tracing)
		}
	}
}

func TestFakeTCPBPFControlAdmissionIsPolicyScopedAndStrictlyBounded(t *testing.T) {
	source, err := os.ReadFile("../../bpf/wg_mix_faketcp.h")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, want := range []string{
		"struct faketcp_control_policy_key",
		"struct faketcp_control_policy_value",
		"struct faketcp_control_flow_key",
		"faketcp_control_policy_map SEC(\".maps\")",
		"faketcp_control_flow_map SEC(\".maps\")",
		"__uint(type, BPF_MAP_TYPE_LRU_HASH)",
		".generation = session->generation",
		".wg_id = wg_id",
		".event_type = event_type",
		"attempt < FAKETCP_CONTROL_CAS_ATTEMPTS",
		"__sync_val_compare_and_swap(&policy->virtual_time_nanos",
		"policy->interval_nanos < FAKETCP_CONTROL_MIN_INTERVAL_NANOS",
		"policy->interval_nanos > FAKETCP_CONTROL_MAX_INTERVAL_NANOS",
		"policy->burst == 0 || policy->burst > FAKETCP_CONTROL_MAX_BURST",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("FakeTCP control admission contract missing %q", want)
		}
	}

	admissionStart := strings.Index(text, "faketcp_admit_control_event_inner(const struct faketcp_session_key")
	emitStart := strings.Index(text, "static __always_inline int faketcp_emit_event")
	if admissionStart < 0 || emitStart < 0 || admissionStart >= emitStart {
		t.Fatal("FakeTCP control admission helper is missing or misplaced")
	}
	admission := sourceSection(t, text,
		"faketcp_admit_control_event_inner(const struct faketcp_session_key",
		"faketcp_admit_control_event(const struct faketcp_session_key")
	policyLookup := strings.Index(admission, "bpf_map_lookup_elem(&faketcp_control_policy_map")
	flowLookup := strings.Index(admission, "bpf_map_lookup_elem(&faketcp_control_flow_map")
	budget := strings.Index(admission, "faketcp_take_control_budget(policy, now)")
	flowUpdate := strings.Index(admission, "bpf_map_update_elem(&faketcp_control_flow_map")
	if policyLookup < 0 || flowLookup < 0 || budget < 0 || flowUpdate < 0 ||
		policyLookup >= flowLookup || flowLookup >= budget || budget >= flowUpdate {
		t.Fatal("policy lookup, duplicate lookup, budget allocation and admitted-only map update are out of order")
	}
	if strings.Count(admission, "bpf_map_update_elem(&faketcp_control_flow_map") != 1 {
		t.Fatal("attacker-keyed control map must have exactly one admitted-only write site")
	}
	for _, want := range []string{
		"bpf_map_lookup_elem(&faketcp_rt_id",
		"identity->generation != generation",
		"identity->event_abi_version != FAKETCP_EVENT_ABI_VERSION",
		"if (!nonzero)",
		"__builtin_memcpy(event->runtime_incarnation",
		"bpf_map_lookup_elem(&faketcp_cap_seq",
		"*sequence == ~0ULL",
		"event->capture_cpu = bpf_get_smp_processor_id()",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("FakeTCP capture identity contract missing %q", want)
		}
	}
	sequenceHelperStart := strings.Index(text, "faketcp_assign_capture_sequence(struct faketcp_event *event)")
	admissionHelperStart := strings.Index(text, "faketcp_take_control_budget(struct faketcp_control_policy_value")
	if sequenceHelperStart < 0 || admissionHelperStart < 0 || sequenceHelperStart >= admissionHelperStart {
		t.Fatal("FakeTCP capture sequence helper is missing or misplaced")
	}
	sequenceHelper := text[sequenceHelperStart:admissionHelperStart]
	saturation := strings.Index(sequenceHelper, "*sequence == ~0ULL")
	increment := strings.Index(sequenceHelper, "*sequence += 1")
	if saturation < 0 || increment < 0 || saturation >= increment {
		t.Fatal("FakeTCP capture sequence must reject saturation before increment and never wrap")
	}

	if got := strings.Count(text, "bpf_ringbuf_output("); got != 3 {
		t.Fatalf("FakeTCP source has %d ring-buffer output calls, want two events plus one generation wake", got)
	}
	if got := strings.Count(text, "bpf_ringbuf_output(&faketcp_events,"); got != 2 {
		t.Fatalf("FakeTCP event ring has %d output sites, want two explicitly admitted sites", got)
	}
	if got := strings.Count(text, "bpf_ringbuf_output(&faketcp_events, &event"); got != 1 {
		t.Fatalf("FakeTCP metadata ring output sites=%d, want exactly one", got)
	}
	if got := strings.Count(text, "bpf_ringbuf_output(&faketcp_events, record"); got != 1 {
		t.Fatalf("FakeTCP shared packet ring output sites=%d, want exactly one", got)
	}
	if got := strings.Count(text, "bpf_ringbuf_output(&faketcp_gen_wk, &wake"); got != 1 {
		t.Fatalf("FakeTCP generation wake output sites=%d, want exactly one", got)
	}
	for _, forbidden := range []string{"bpf_ringbuf_reserve(", "bpf_ringbuf_submit(", "bpf_ringbuf_discard("} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("un-enumerated FakeTCP ring-buffer write path %q is forbidden", forbidden)
		}
	}

	captureStart := strings.Index(text, "static __always_inline int faketcp_capture_first_packet")
	preflightStart := strings.Index(text, "static __always_inline int faketcp_egress_admission_checkpoint")
	if captureStart < 0 || preflightStart < 0 || captureStart >= preflightStart {
		t.Fatal("FakeTCP first-packet capture helper is missing or malformed")
	}
	emit := text[emitStart:captureStart]
	admitCall := strings.Index(emit, "if (!faketcp_admit_control_event(key, wg_id, type, now))")
	eventWrite := strings.Index(emit, "event = (struct faketcp_event)")
	controlIdentityBind := strings.Index(emit, "faketcp_bind_runtime_identity(key, &event)")
	ringOutput := strings.Index(emit, "bpf_ringbuf_output(&faketcp_events, &event")
	if admitCall < 0 || eventWrite < 0 || controlIdentityBind < 0 || ringOutput < 0 ||
		admitCall >= eventWrite || eventWrite >= controlIdentityBind || controlIdentityBind >= ringOutput {
		t.Fatal("control admission must dominate metadata preparation and ring-buffer output")
	}

	capture := text[captureStart:preflightStart]
	packetValidation := strings.Index(capture, "packet_len > FAKETCP_MAX_CAPTURED_PACKET")
	scratchLookup := strings.Index(capture, "bpf_map_lookup_elem(&faketcp_capture_scratch")
	packetAdmit := strings.Index(capture, "if (!faketcp_admit_control_event(key, rule->wg_id")
	scratchWrite := strings.Index(capture, "record->event = (struct faketcp_event)")
	packetCopy := strings.Index(capture, "bpf_skb_load_bytes")
	packetOutput := strings.Index(capture, "faketcp_output_packet_event(record, copy_len)")
	identityBind := strings.Index(capture, "faketcp_bind_runtime_identity(key, &record->event)")
	sequenceAssign := strings.Index(capture, "faketcp_assign_capture_sequence(&record->event)")
	if packetValidation < 0 || scratchLookup < 0 || packetAdmit < 0 || scratchWrite < 0 ||
		identityBind < 0 || sequenceAssign < 0 || packetCopy < 0 || packetOutput < 0 || packetValidation >= packetAdmit ||
		scratchLookup >= packetAdmit || packetAdmit >= scratchWrite ||
		scratchWrite >= identityBind || identityBind >= sequenceAssign ||
		sequenceAssign >= packetCopy || packetCopy >= packetOutput {
		t.Fatal("NEED_HANDSHAKE admission must follow cheap validation and dominate scratch writes, packet copy, and shared ring output")
	}
	if strings.Count(capture, "bpf_ktime_get_ns()") != 1 ||
		!strings.Contains(capture, ".timestamp_nanos = now") {
		t.Fatal("NEED_HANDSHAKE admission and event must share one monotonic timestamp")
	}
}

func TestFakeTCPControlAdmissionGCRAStartsWithConfiguredBurstAndCapsIt(t *testing.T) {
	const (
		interval = uint64(100_000_000)
		burst    = uint32(4)
		start    = uint64(1_000_000_000)
	)
	var cursor uint64
	if !takeFakeTCPControlBudgetModel(&cursor, start, interval, burst) {
		t.Fatal("fresh policy did not admit the first WireGuard handshake")
	}
	if want := start + interval; cursor != want {
		t.Fatalf("first-token cursor=%d, want %d", cursor, want)
	}
	for admitted := uint32(1); admitted < burst; admitted++ {
		if !takeFakeTCPControlBudgetModel(&cursor, start, interval, burst) {
			t.Fatalf("initial burst stopped after %d admissions", admitted)
		}
	}
	if takeFakeTCPControlBudgetModel(&cursor, start, interval, burst) {
		t.Fatalf("fresh policy admitted more than burst=%d events", burst)
	}
	if !takeFakeTCPControlBudgetModel(&cursor, start+interval, interval, burst) {
		t.Fatal("one interval did not replenish exactly one event")
	}
	if takeFakeTCPControlBudgetModel(&cursor, start+interval, interval, burst) {
		t.Fatal("one interval replenished more than one event")
	}

	// After a long idle period, exactly Burst events may be emitted; the next
	// one is rejected without relying on a flow-map insertion or ring capacity.
	now := start + 10*interval
	for admitted := uint32(0); admitted < burst; admitted++ {
		if !takeFakeTCPControlBudgetModel(&cursor, now, interval, burst) {
			t.Fatalf("idle burst stopped after %d admissions", admitted)
		}
	}
	if takeFakeTCPControlBudgetModel(&cursor, now, interval, burst) {
		t.Fatalf("policy admitted more than burst=%d events at one instant", burst)
	}
}

func TestFakeTCPControlAdmissionGCRARejectsInvalidAndOverflowingPolicy(t *testing.T) {
	maxUint64 := ^uint64(0)
	tests := []struct {
		name     string
		now      uint64
		interval uint64
		burst    uint32
	}{
		{name: "interval-zero", now: 1, interval: 0, burst: 1},
		{name: "interval-below-minimum", now: 1, interval: fakeTCPControlMinIntervalModel - 1, burst: 1},
		{name: "interval-above-maximum", now: 1, interval: fakeTCPControlMaxIntervalModel + 1, burst: 1},
		{name: "burst-zero", now: 1, interval: fakeTCPControlMinIntervalModel, burst: 0},
		{name: "burst-above-maximum", now: 1, interval: fakeTCPControlMinIntervalModel, burst: fakeTCPControlMaxBurstModel + 1},
		{name: "window-overflow", now: maxUint64, interval: fakeTCPControlMinIntervalModel, burst: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cursor := uint64(17)
			if takeFakeTCPControlBudgetModel(&cursor, test.now, test.interval, test.burst) {
				t.Fatal("invalid policy admitted an event")
			}
			if cursor != 17 {
				t.Fatalf("invalid policy changed cursor to %d", cursor)
			}
		})
	}

	window := fakeTCPControlMinIntervalModel * uint64(fakeTCPControlMaxBurstModel)
	cursor := uint64(0)
	if !takeFakeTCPControlBudgetModel(&cursor, maxUint64-window,
		fakeTCPControlMinIntervalModel, fakeTCPControlMaxBurstModel) {
		t.Fatal("largest non-overflowing first token was rejected")
	}
	if want := maxUint64 - window + fakeTCPControlMinIntervalModel; cursor != want {
		t.Fatalf("largest non-overflowing first cursor=%d, want %d", cursor, want)
	}
	cursor = maxUint64
	if takeFakeTCPControlBudgetModel(&cursor, maxUint64-window+fakeTCPControlMinIntervalModel,
		fakeTCPControlMinIntervalModel, fakeTCPControlMaxBurstModel) {
		t.Fatal("candidate overflow boundary admitted")
	}
}

const (
	fakeTCPControlMinIntervalModel = uint64(10_000_000)
	fakeTCPControlMaxIntervalModel = uint64(10_000_000_000)
	fakeTCPControlMaxBurstModel    = uint32(4096)
)

// takeFakeTCPControlBudgetModel mirrors the single-cursor arithmetic in the
// BPF helper without modelling CAS contention (contention only adds rejects).
func takeFakeTCPControlBudgetModel(cursor *uint64, now, interval uint64, burst uint32) bool {
	if interval < fakeTCPControlMinIntervalModel || interval > fakeTCPControlMaxIntervalModel ||
		burst == 0 || burst > fakeTCPControlMaxBurstModel {
		return false
	}
	window := interval * uint64(burst)
	maxUint64 := ^uint64(0)
	if now > maxUint64-window {
		return false
	}
	limit := now + window
	if *cursor == 0 {
		*cursor = now + interval
		return true
	}
	base := *cursor
	if base < now {
		base = now
	}
	if base > maxUint64-interval {
		return false
	}
	candidate := base + interval
	if candidate > limit {
		return false
	}
	*cursor = candidate
	return true
}

func TestFakeTCPCloseControlsUseOneCanonicalFailClosedPath(t *testing.T) {
	source, err := os.ReadFile("../../bpf/wg_mix_faketcp.h")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	checkpointStart := strings.Index(text, "static __always_inline int faketcp_xdp_admission_checkpoint")
	xdpBodyStart := strings.Index(text, "faketcp_xdp_ingress_body(struct xdp_md *xdp, __u64 generation)")
	if checkpointStart < 0 || xdpBodyStart < 0 || checkpointStart >= xdpBodyStart {
		t.Fatal("FakeTCP XDP admission checkpoint is missing")
	}
	checkpoint := text[checkpointStart:xdpBodyStart]
	xdp := sourceSection(t, text,
		"faketcp_xdp_ingress_body(struct xdp_md *xdp, __u64 generation)",
		"SEC(\"xdp\")")
	snapshot := strings.Index(checkpoint, "faketcp_session_snapshot_established(")
	closeDecision := strings.Index(checkpoint, "return FAKETCP_ADMISSION_CLOSE")
	fixedIPv4Gate := strings.Index(xdp, "faketcp_managed_transform_status(l3, l3->transport_protocol)")
	checkpointCall := strings.Index(xdp, "admission_decision = faketcp_xdp_admission_checkpoint(")
	closePath := strings.Index(xdp, "if (admission_decision == FAKETCP_ADMISSION_CLOSE)")
	canonical := strings.Index(xdp, "flags != (FAKETCP_FLAG_RST | FAKETCP_FLAG_ACK)")
	sequence := strings.Index(xdp, "seq != admission->decision.close.rx_sequence")
	window := strings.Index(xdp, "bpf_ntohs(old_tcp->window) != admission->session_projection.window")
	checksum := strings.Index(xdp, "faketcp_ipv4_tcp_control_checksums_valid(new_ip, old_tcp)")
	capture := strings.Index(xdp, "faketcp_capture_close_packet(")
	if snapshot < 0 || closeDecision < 0 || fixedIPv4Gate < 0 || checkpointCall < 0 ||
		closePath < 0 || canonical < 0 || sequence < 0 || window < 0 || checksum < 0 || capture < 0 ||
		snapshot >= closeDecision || fixedIPv4Gate >= checkpointCall || checkpointCall >= closePath ||
		closePath >= canonical || canonical >= sequence || sequence >= window ||
		window >= checksum || checksum >= capture {
		t.Fatal("single admission CLOSE decision and exact packet authority checks are missing or out of order")
	}
	for _, want := range []string{
		"close_control = flags & (FAKETCP_FLAG_RST | FAKETCP_FLAG_FIN)",
		"if (!close_control && admission->payload_len != 0 &&",
		"policy_listener->cipher_id != 0)",
		"return close_control ? FAKETCP_ADMISSION_DROP :",
		"admission->decision.close.session_revision = session_snapshot->revision",
		"admission->decision.close.tx_sequence = session_snapshot->tx_sequence",
		"admission->decision.close.rx_sequence = session_snapshot->rx_sequence",
	} {
		if !strings.Contains(checkpoint, want) {
			t.Fatalf("single CLOSE checkpoint is missing %q", want)
		}
	}
	keepalivePath := strings.Index(xdp, "if (admission_decision == FAKETCP_ADMISSION_KEEPALIVE)")
	if keepalivePath < 0 || closePath >= keepalivePath {
		t.Fatal("CLOSE decision does not terminate before ordinary admission decisions")
	}
	closeBlock := xdp[closePath:keepalivePath]
	for _, forbidden := range []string{"faketcp_emit_event", "faketcp_session_mutate", "xor_", "FAKETCP_ADMISSION_TRANSFORM"} {
		if strings.Contains(closeBlock, forbidden) {
			t.Fatalf("CLOSE decision leaked into ordinary control/transform path through %q", forbidden)
		}
	}
	if strings.Contains(checkpoint, "close topic") ||
		strings.Contains(text, "faketcp_session_snapshot_close") ||
		strings.Contains(text, "struct faketcp_close_snapshot") {
		t.Fatal("validated close regained a parallel snapshot or pre-admission fallback")
	}
	if strings.Contains(xdp, "old_tcp.check == 0") {
		t.Fatal("TCP checksum field zero is not independently invalid")
	}
	if strings.Contains(text, "bpf_map_delete_elem(&faketcp_session_map") {
		t.Fatal("BPF close validation must never become session-deletion authority")
	}

	checksumStart := strings.Index(text, "faketcp_ipv4_tcp_control_checksums_valid(const struct iphdr *iph")
	captureStart := strings.Index(text, "faketcp_capture_close_packet(struct xdp_md *xdp")
	if checksumStart < 0 || captureStart < 0 || checksumStart >= captureStart {
		t.Fatal("canonical close checksum and capture helpers are missing")
	}
	checksumHelper := text[checksumStart:captureStart]
	for _, want := range []string{
		"bpf_csum_diff(0, 0, (__be32 *)iph, sizeof(*iph), 0)",
		"fold_csum(sum) != 0",
		"struct faketcp_ipv4_pseudo_header pseudo",
		"bpf_csum_diff(0, 0, (__be32 *)tcp, sizeof(*tcp)",
	} {
		if !strings.Contains(checksumHelper, want) {
			t.Fatalf("close checksum helper missing %q", want)
		}
	}
	captureHelper := text[captureStart:xdpBodyStart]
	admit := strings.Index(captureHelper, "faketcp_admit_control_event(&admission->key, admission->wg_id")
	write := strings.Index(captureHelper, "record->event = (struct faketcp_event)")
	identity := strings.Index(captureHelper, "record->event.runtime_incarnation[i]")
	copyPacket := strings.Index(captureHelper, "bpf_xdp_load_bytes")
	output := strings.Index(captureHelper, "faketcp_output_packet_event(record, packet_len)")
	if admit < 0 || write < 0 || identity < 0 || copyPacket < 0 || output < 0 ||
		admit >= write || write >= identity || identity >= copyPacket || copyPacket >= output {
		t.Fatal("validated close admission must dominate event writes, identity binding, packet copy, and shared output")
	}
	for _, want := range []string{
		".session_revision = admission->decision.close.session_revision",
		".session_id = admission->session_authority.session_id",
		".sequence = admission->decision.close.rx_sequence",
		".acknowledgement = admission->decision.close.tx_sequence",
		".event_abi_version = FAKETCP_EVENT_ABI_VERSION",
	} {
		if !strings.Contains(captureHelper, want) {
			t.Fatalf("close event snapshot binding missing %q", want)
		}
	}
	if strings.Contains(captureHelper, "faketcp_bind_runtime_identity") {
		t.Fatal("close event must use the incarnation from its locked session snapshot")
	}

	copyStart := strings.Index(text, "static __always_inline void faketcp_session_snapshot_locked(")
	matchLockedStart := strings.Index(text, "static __always_inline int faketcp_session_authority_matches_locked(")
	readerStart := strings.Index(text, "static __always_inline int faketcp_session_snapshot_established(")
	authorityStart := strings.Index(text, "static __always_inline int faketcp_session_authority_matches(")
	if copyStart < 0 || matchLockedStart < 0 || readerStart < 0 || authorityStart < 0 ||
		!(copyStart < matchLockedStart && matchLockedStart < readerStart && readerStart < authorityStart) {
		t.Fatal("unified locked session snapshot helpers are missing or misplaced")
	}
	copyHelper := text[copyStart:matchLockedStart]
	for _, want := range []string{
		"snapshot->revision = session->revision",
		"faketcp_session_lifetime_snapshot_locked(session, &snapshot->authority,",
		"snapshot->tx_sequence = session->tx_sequence",
		"snapshot->rx_sequence = session->rx_sequence",
	} {
		if !strings.Contains(copyHelper, want) {
			t.Fatalf("unified session snapshot is missing close authority %q", want)
		}
	}
	if !strings.Contains(text, "authority->session_id = session->session_id") {
		t.Fatal("shared lifetime snapshot lost the session identifier authority")
	}
	reader := text[readerStart:authorityStart]
	lock := strings.Index(reader, "bpf_spin_lock(&session->lock)")
	validate := strings.Index(reader, "faketcp_session_metadata_valid_locked(session, generation)")
	copyProof := strings.Index(reader, "faketcp_session_snapshot_locked(session, snapshot)")
	unlock := strings.Index(reader, "bpf_spin_unlock(&session->lock)")
	if lock < 0 || validate < 0 || copyProof < 0 || unlock < 0 ||
		!(lock < validate && validate < copyProof && copyProof < unlock) {
		t.Fatal("close authority is not copied from the admission checkpoint's one locked snapshot")
	}
	for _, forbidden := range []string{"bpf_ktime_get_ns", "bpf_xdp_", "bpf_csum_diff", "inc_faketcp_stat"} {
		if strings.Contains(reader[lock:unlock], forbidden) {
			t.Fatalf("close snapshot critical section contains helper/stat call %q", forbidden)
		}
	}
	for _, want := range []string{
		"sizeof(struct faketcp_session_snapshot) == 56",
		"sizeof(union faketcp_ingress_decision_projection) == 16",
		"sizeof(struct faketcp_ingress_admission) == 144",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("close/admission stack contract missing %q", want)
		}
	}
	if fakeTCPImplementedCapabilities&fakeTCPCapabilityValidatedCloseControl == 0 {
		t.Fatal("production ValidatedCloseControl capability is not enabled")
	}
}
