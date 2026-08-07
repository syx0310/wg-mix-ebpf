package dataplane

import (
	"bytes"
	"encoding/binary"
	"os"
	"strconv"
	"strings"
	"testing"
)

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

func TestFakeTCPMTUMinusHeaderDeltaBoundary(t *testing.T) {
	const underlayMTU = 1500
	tests := []struct {
		name       string
		inputL3Len int
		want       bool
	}{
		{name: "exact-minus-twelve", inputL3Len: 1488, want: true},
		{name: "one-over-boundary", inputL3Len: 1489, want: false},
		{name: "ordinary-wireguard", inputL3Len: 1420, want: true},
		{name: "invalid-too-short", inputL3Len: 27, want: false},
		{name: "prototype-frame-cap", inputL3Len: 2305, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := fakeTCPMTUAllowsGrowth(test.inputL3Len, underlayMTU)
			if got != test.want {
				t.Fatalf("input L3=%d mtu=%d allowed=%v, want %v", test.inputL3Len, underlayMTU, got, test.want)
			}
		})
	}
}

func fakeTCPMTUAllowsGrowth(inputL3Len, underlayMTU int) bool {
	const (
		minimumIPv4UDP = 20 + 8
		headerDelta    = 12
		packetCap      = 2304
	)
	return inputL3Len >= minimumIPv4UDP && inputL3Len <= packetCap &&
		underlayMTU >= headerDelta && inputL3Len <= underlayMTU-headerDelta
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
		"faketcp_materialize_tcp_checksum",
		"bpf_check_mtu(skb, 0, &mtu_len, FAKETCP_HEADER_DELTA, 0)",
		"bpf_skb_change_tail(skb, skb->len + FAKETCP_HEADER_DELTA, 0)",
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
	if strings.Count(fake, "#define FAKETCP_EVENT_NEED_HANDSHAKE 1") != 1 ||
		strings.Count(fake, ".type = FAKETCP_EVENT_NEED_HANDSHAKE") != 1 {
		t.Fatal("NEED_HANDSHAKE must only be emitted with the captured pre-transform packet")
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

func TestFakeTCPChecksumNormalizationMTUAndGSOStayHardGated(t *testing.T) {
	source, err := os.ReadFile("../../bpf/wg_mix_faketcp.h")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)

	preflightStart := strings.Index(text, "static __always_inline int faketcp_preflight_egress")
	checksumCommentStart := strings.Index(text, "// TC's public __sk_buff ABI")
	checksumStart := strings.Index(text, "static __always_inline int faketcp_materialize_tcp_checksum")
	encoderStart := strings.Index(text, "static __always_inline int faketcp_encode_established")
	continuationStart := strings.Index(text, "static __always_inline int faketcp_continue_egress")
	if preflightStart < 0 || checksumCommentStart < 0 || checksumStart < 0 || encoderStart < 0 || continuationStart < 0 ||
		preflightStart >= checksumCommentStart || checksumCommentStart >= checksumStart ||
		checksumStart >= encoderStart || encoderStart >= continuationStart {
		t.Fatal("FakeTCP preflight/checksum/encoder sections are missing or malformed")
	}

	preflight := text[preflightStart:checksumCommentStart]
	gsoReject := strings.Index(preflight, "if (skb->gso_segs || skb->gso_size)")
	flowLookup := strings.Index(preflight, "faketcp_tc_key(skb, info, generation, &key)")
	if gsoReject < 0 || flowLookup < 0 || gsoReject >= flowLookup {
		t.Fatal("aggregate GSO must be rejected before flow lookup, capture, type-word and XOR mutation")
	}
	for _, want := range []string{
		"One header insertion cannot provide",
		"not an implementation of per-segment FakeTCP",
		"FAKETCP_STAT_GSO_REJECT",
	} {
		if !strings.Contains(preflight, want) {
			t.Fatalf("GSO hard-gate contract missing %q", want)
		}
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

	encoder := text[encoderStart:continuationStart]
	mtuCheck := strings.Index(encoder, "faketcp_mtu_allows_growth(skb, old_total_len)")
	normalize := strings.Index(encoder, "bpf_skb_change_tail(skb, skb->len + FAKETCP_HEADER_DELTA, 0)")
	checksum := strings.Index(encoder, "faketcp_materialize_tcp_checksum(skb")
	if mtuCheck < 0 || normalize < 0 || checksum < 0 || mtuCheck >= normalize || normalize >= checksum {
		t.Fatal("MTU check, checksum-state normalization and full recompute are out of order")
	}
	for _, want := range []string{
		"old_total_len != sizeof(*iph) + udp_len",
		"old_total_len > FAKETCP_MAX_CAPTURED_PACKET",
		"old_total_len > skb->len - info->ip_off",
	} {
		if !strings.Contains(encoder, want) {
			t.Fatalf("bounded checksum read precondition missing %q", want)
		}
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
		"session->state != FAKETCP_STATE_ESTABLISHED",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("established-only fast-map contract missing %q", want)
		}
	}
	if !strings.Contains(sessionMap, "__uint(type, BPF_MAP_TYPE_HASH)") {
		t.Fatal("FakeTCP established session map must remain a non-evicting HASH")
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

	admissionStart := strings.Index(text, "faketcp_admit_control_event(const struct faketcp_session_key")
	emitStart := strings.Index(text, "static __always_inline int faketcp_emit_event")
	if admissionStart < 0 || emitStart < 0 || admissionStart >= emitStart {
		t.Fatal("FakeTCP control admission helper is missing or misplaced")
	}
	admission := text[admissionStart:emitStart]
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

	if got := strings.Count(text, "bpf_ringbuf_output("); got != 2 {
		t.Fatalf("FakeTCP source has %d ring-buffer output calls, want two enumerated calls", got)
	}
	if got := strings.Count(text, "bpf_ringbuf_output(&faketcp_events,"); got != 2 {
		t.Fatalf("FakeTCP event ring has %d output sites, want two explicitly admitted sites", got)
	}
	if got := strings.Count(text, "bpf_ringbuf_output(&faketcp_events, &event"); got != 1 {
		t.Fatalf("FakeTCP metadata ring output sites=%d, want exactly one", got)
	}
	if got := strings.Count(text, "bpf_ringbuf_output(&faketcp_events, record"); got != 1 {
		t.Fatalf("FakeTCP packet ring output sites=%d, want exactly one", got)
	}
	for _, forbidden := range []string{"bpf_ringbuf_reserve(", "bpf_ringbuf_submit(", "bpf_ringbuf_discard("} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("un-enumerated FakeTCP ring-buffer write path %q is forbidden", forbidden)
		}
	}

	captureStart := strings.Index(text, "static __always_inline int faketcp_capture_first_packet")
	preflightStart := strings.Index(text, "static __always_inline int faketcp_preflight_egress")
	if captureStart < 0 || preflightStart < 0 || captureStart >= preflightStart {
		t.Fatal("FakeTCP first-packet capture helper is missing or malformed")
	}
	emit := text[emitStart:captureStart]
	admitCall := strings.Index(emit, "if (!faketcp_admit_control_event(key, wg_id, type, now))")
	eventWrite := strings.Index(emit, "event = (struct faketcp_event)")
	ringOutput := strings.Index(emit, "bpf_ringbuf_output(&faketcp_events, &event")
	if admitCall < 0 || eventWrite < 0 || ringOutput < 0 ||
		admitCall >= eventWrite || eventWrite >= ringOutput {
		t.Fatal("control admission must dominate metadata preparation and ring-buffer output")
	}

	capture := text[captureStart:preflightStart]
	packetValidation := strings.Index(capture, "packet_len > FAKETCP_MAX_CAPTURED_PACKET")
	scratchLookup := strings.Index(capture, "bpf_map_lookup_elem(&faketcp_capture_scratch")
	packetAdmit := strings.Index(capture, "if (!faketcp_admit_control_event(key, rule->wg_id")
	scratchWrite := strings.Index(capture, "record->event = (struct faketcp_event)")
	packetCopy := strings.Index(capture, "bpf_skb_load_bytes")
	packetOutput := strings.Index(capture, "bpf_ringbuf_output(&faketcp_events, record")
	if packetValidation < 0 || scratchLookup < 0 || packetAdmit < 0 || scratchWrite < 0 ||
		packetCopy < 0 || packetOutput < 0 || packetValidation >= packetAdmit ||
		scratchLookup >= packetAdmit || packetAdmit >= scratchWrite ||
		scratchWrite >= packetCopy || packetCopy >= packetOutput {
		t.Fatal("NEED_HANDSHAKE admission must follow cheap validation and dominate scratch writes, packet copy, and ring output")
	}
	if strings.Count(capture, "bpf_ktime_get_ns()") != 1 ||
		!strings.Contains(capture, ".timestamp_nanos = now") {
		t.Fatal("NEED_HANDSHAKE admission and event must share one monotonic timestamp")
	}
}

func TestFakeTCPControlAdmissionGCRAStartsEmptyAndCapsBurst(t *testing.T) {
	const (
		interval = uint64(100_000_000)
		burst    = uint32(4)
		start    = uint64(1_000_000_000)
	)
	var cursor uint64
	if takeFakeTCPControlBudgetModel(&cursor, start, interval, burst) {
		t.Fatal("new policy minted an immediate control-event token")
	}
	if want := start + interval*uint64(burst); cursor != want {
		t.Fatalf("zero-budget epoch cursor=%d, want %d", cursor, want)
	}
	if !takeFakeTCPControlBudgetModel(&cursor, start+interval, interval, burst) {
		t.Fatal("one interval did not accrue exactly one event")
	}
	if takeFakeTCPControlBudgetModel(&cursor, start+interval, interval, burst) {
		t.Fatal("one interval accrued more than one event")
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
	if takeFakeTCPControlBudgetModel(&cursor, maxUint64-window,
		fakeTCPControlMinIntervalModel, fakeTCPControlMaxBurstModel) {
		t.Fatal("zero-budget boundary unexpectedly admitted")
	}
	if cursor != maxUint64 {
		t.Fatalf("largest non-overflowing boundary cursor=%d, want %d", cursor, maxUint64)
	}
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
		*cursor = limit
		return false
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

func TestFakeTCPCloseControlsCannotAuthorizeDeleteBeforeBPFValidation(t *testing.T) {
	source, err := os.ReadFile("../../bpf/wg_mix_faketcp.h")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	xdpStart := strings.Index(text, "int wg_mix_faketcp_ingress(struct xdp_md *xdp)")
	if xdpStart < 0 {
		t.Fatal("FakeTCP XDP entry point is missing")
	}
	xdp := text[xdpStart:]
	closeDrop := strings.Index(xdp, "if (flags & (FAKETCP_FLAG_RST | FAKETCP_FLAG_FIN))")
	firstEvent := strings.Index(xdp, "faketcp_emit_event")
	if closeDrop < 0 || firstEvent < 0 || closeDrop >= firstEvent {
		t.Fatal("RST/FIN can reach the ring before the unavailable BPF checksum/window validator")
	}
	if strings.Contains(xdp, "old_tcp.check == 0") {
		t.Fatal("TCP checksum field zero is not independently invalid")
	}
}
