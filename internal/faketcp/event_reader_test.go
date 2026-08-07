package faketcp

import (
	"bytes"
	"testing"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

func TestCanonicalPerfEventSampleTrimsOnlyProvenKernelPadding(t *testing.T) {
	flow := testFlow(31001)
	packet := testIPv4UDPPacket(t, flow, []byte{1, 2, 3})
	compact := testEventSample(abi.FakeTCPEvent{
		Key:           flow,
		PayloadLength: 3,
		PacketLength:  uint16(len(packet)),
		Type:          abi.FakeTCPEventNeedHandshake,
	}, packet, false)
	fixed := testEventSample(abi.FakeTCPEvent{
		Key:           flow,
		PayloadLength: 3,
		PacketLength:  uint16(len(packet)),
		Type:          abi.FakeTCPEventNeedHandshake,
	}, packet, true)
	control := testEventSample(abi.FakeTCPEvent{
		Key: flow, Type: abi.FakeTCPEventACK, TCPFlags: FlagACK,
	}, nil, false)

	for _, test := range []struct {
		name  string
		input []byte
		want  []byte
	}{
		{name: "compact", input: append(append([]byte(nil), compact...), 1, 2, 3), want: compact},
		{name: "fixed", input: append(append([]byte(nil), fixed...), 1, 2, 3, 4, 5, 6, 7), want: fixed},
		{name: "control", input: append(append([]byte(nil), control...), 9), want: control},
		{name: "too much", input: append(append([]byte(nil), control...), make([]byte, 8)...), want: append(append([]byte(nil), control...), make([]byte, 8)...)},
		{name: "short", input: []byte{1, 2, 3}, want: []byte{1, 2, 3}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := canonicalPerfEventSample(test.input)
			if !bytes.Equal(got, test.want) {
				t.Fatalf("canonical sample length=%d bytes=%x, want length=%d bytes=%x", len(got), got, len(test.want), test.want)
			}
			if len(got) != 0 && len(test.input) != 0 {
				before := got[0]
				test.input[0] ^= 0xff
				if got[0] != before {
					t.Fatal("canonical sample aliases perf reader memory")
				}
			}
		})
	}
}
