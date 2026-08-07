package dataplane

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestFakeTCPXORWireOrderRoundTrip(t *testing.T) {
	key := make([]byte, 256)
	for i := range key {
		key[i] = byte(i*19 + 11)
	}
	payload := make([]byte, 64)
	for i := range payload {
		payload[i] = byte(i*7 + 3)
	}
	want := append([]byte(nil), payload...)
	copy(want[:4], []byte{1, 0, 0, 0})
	copy(payload[:4], []byte{0x61, 0x62, 0x63, 0x64}) // mixed type word

	// Egress contract: type-word rewrite (already represented above), XOR,
	// then the FakeTCP header-growth rotation.
	xorStoreRange(payload, key, 0, len(payload))
	wire := append(append([]byte(nil), payload[12:]...), payload[:12]...)
	if bytes.Equal(wire[:4], want[:4]) || bytes.Equal(wire[:4], payload[:4]) {
		t.Fatal("FakeTCP wire prefix exposed either the standard or encrypted type-word position")
	}

	// Ingress contract: XDP removes FakeTCP and restores UDP ordering before
	// the existing TC XOR/type-word reverse path runs.
	restored := append(append([]byte(nil), wire[len(wire)-12:]...), wire[:len(wire)-12]...)
	xorStoreRange(restored, key, 0, len(restored))
	copy(restored[:4], want[:4])
	if !bytes.Equal(restored, want) {
		t.Fatal("type-word/XOR/FakeTCP composition did not round trip")
	}
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
}
