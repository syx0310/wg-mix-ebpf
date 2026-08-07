package faketcp

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

func TestMaterializedIPv4UDPValidatesOddAndEvenPayloads(t *testing.T) {
	flow := packetTestFlow(t)
	for _, payload := range [][]byte{
		nil,
		{0x01},
		{0x01, 0x02},
		{0x01, 0x02, 0x03},
		{0x01, 0x02, 0x03, 0x04},
		{0x01, 0x02, 0x03, 0x04, 0x05},
	} {
		payload := payload
		t.Run(controlFlagName(uint8(len(payload))), func(t *testing.T) {
			packet := unmaterializedIPv4UDP(flow, payload)
			binary.BigEndian.PutUint16(packet[10:12], 0x1234)
			binary.BigEndian.PutUint16(packet[26:28], 0x5678)
			if err := MaterializeIPv4UDPChecksums(packet); err != nil {
				t.Fatal(err)
			}
			if got := referenceChecksumResidual(packet[:20]); got != 0xffff {
				t.Fatalf("independent IPv4 checksum residual = %#04x", got)
			}
			if got := referenceTransportResidual(packet[12:20], 17, packet[20:]); got != 0xffff {
				t.Fatalf("independent UDP checksum residual = %#04x", got)
			}
			before := append([]byte(nil), packet...)
			if err := ValidateMaterializedIPv4UDP(packet, flow); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(packet, before) {
				t.Fatal("successful validation modified the packet")
			}
		})
	}
}

func TestMaterializeIPv4UDPMapsComputedZeroToFFFF(t *testing.T) {
	flow := packetTestFlow(t)
	packet := unmaterializedIPv4UDP(flow, []byte{0, 0})
	for payloadWord := 0; payloadWord <= 0xffff; payloadWord++ {
		binary.BigEndian.PutUint16(packet[28:30], uint16(payloadWord))
		if referenceTransportChecksum(packet[12:20], 17, packet[20:]) != 0 {
			continue
		}
		if err := MaterializeIPv4UDPChecksums(packet); err != nil {
			t.Fatal(err)
		}
		if got := binary.BigEndian.Uint16(packet[26:28]); got != 0xffff {
			t.Fatalf("computed-zero UDP checksum = %#04x, want 0xffff", got)
		}
		if err := ValidateMaterializedIPv4UDP(packet, flow); err != nil {
			t.Fatalf("mapped computed-zero checksum failed validation: %v", err)
		}
		return
	}
	t.Fatal("failed to construct a computed-zero UDP checksum")
}

func TestValidateMaterializedIPv4UDPRejectsEveryHeaderMutationWithoutWriting(t *testing.T) {
	flow := packetTestFlow(t)
	valid := unmaterializedIPv4UDP(flow, []byte{1, 2, 3, 4, 5})
	if err := MaterializeIPv4UDPChecksums(valid); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{name: "truncated-packet", mutate: func(packet []byte) []byte { return packet[:27] }},
		{name: "trailing-byte", mutate: func(packet []byte) []byte { return append(packet, 0) }},
		{name: "IPv4-version", mutate: byteMutation(0, 0x65)},
		{name: "short-IHL", mutate: byteMutation(0, 0x44)},
		{name: "long-IHL", mutate: byteMutation(0, 0x46)},
		{name: "IPv4-total-length-short", mutate: uint16Mutation(2, uint16(len(valid)-1))},
		{name: "IPv4-total-length-long", mutate: uint16Mutation(2, uint16(len(valid)+1))},
		{name: "reserved-flag-with-valid-checksum", mutate: func(packet []byte) []byte {
			binary.BigEndian.PutUint16(packet[6:8], 0x8000)
			binary.BigEndian.PutUint16(packet[10:12], 0)
			binary.BigEndian.PutUint16(packet[10:12], ^referenceChecksumResidual(packet[:20]))
			return packet
		}},
		{name: "more-fragments", mutate: uint16Mutation(6, 0x2000)},
		{name: "fragment-offset", mutate: uint16Mutation(6, 0x0001)},
		{name: "protocol", mutate: byteMutation(9, 6)},
		{name: "local-address", mutate: xorByteMutation(12, 1)},
		{name: "remote-address", mutate: xorByteMutation(16, 1)},
		{name: "local-port", mutate: uint16Mutation(20, flow.LocalPort+1)},
		{name: "remote-port", mutate: uint16Mutation(22, flow.RemotePort+1)},
		{name: "UDP-length-short", mutate: uint16Mutation(24, uint16(len(valid)-20-1))},
		{name: "UDP-length-long", mutate: uint16Mutation(24, uint16(len(valid)-20+1))},
		{name: "IPv4-checksum", mutate: xorByteMutation(10, 1)},
		{name: "absent-UDP-checksum", mutate: uint16Mutation(26, 0)},
		{name: "invalid-UDP-checksum", mutate: xorByteMutation(26, 1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := test.mutate(append([]byte(nil), valid...))
			before := append([]byte(nil), candidate...)
			if err := ValidateMaterializedIPv4UDP(candidate, flow); err == nil {
				t.Fatal("mutated packet was accepted")
			}
			if !bytes.Equal(candidate, before) {
				t.Fatal("failed validation modified the packet")
			}
		})
	}
}

func TestValidateMaterializedIPv4UDPRejectsIncompleteFlowWithoutWriting(t *testing.T) {
	base := packetTestFlow(t)
	packet := unmaterializedIPv4UDP(base, []byte{1})
	if err := MaterializeIPv4UDPChecksums(packet); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*abi.FakeTCPSessionKey)
	}{
		{name: "generation", mutate: func(flow *abi.FakeTCPSessionKey) { flow.Generation = 0 }},
		{name: "local-address", mutate: func(flow *abi.FakeTCPSessionKey) { flow.LocalIPv4 = 0 }},
		{name: "remote-address", mutate: func(flow *abi.FakeTCPSessionKey) { flow.RemoteIPv4 = 0 }},
		{name: "interface-index", mutate: func(flow *abi.FakeTCPSessionKey) { flow.UnderlayIndex = 0 }},
		{name: "local-port", mutate: func(flow *abi.FakeTCPSessionKey) { flow.LocalPort = 0 }},
		{name: "remote-port", mutate: func(flow *abi.FakeTCPSessionKey) { flow.RemotePort = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			flow := base
			test.mutate(&flow)
			before := append([]byte(nil), packet...)
			if err := ValidateMaterializedIPv4UDP(packet, flow); err == nil {
				t.Fatal("incomplete flow was accepted")
			}
			if !bytes.Equal(packet, before) {
				t.Fatal("flow validation modified the packet")
			}
		})
	}
}

func TestMaterializeIPv4UDPRejectsUnsupportedHeaderWithoutPartiallyWriting(t *testing.T) {
	flow := packetTestFlow(t)
	tests := []struct {
		name   string
		mutate func([]byte)
	}{
		{name: "short-IHL", mutate: func(packet []byte) { packet[0] = 0x44 }},
		{name: "long-IHL", mutate: func(packet []byte) { packet[0] = 0x46 }},
		{name: "reserved-flag", mutate: func(packet []byte) {
			binary.BigEndian.PutUint16(packet[6:8], 0x8000)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			packet := unmaterializedIPv4UDP(flow, []byte{1})
			test.mutate(packet)
			binary.BigEndian.PutUint16(packet[10:12], 0x1234)
			binary.BigEndian.PutUint16(packet[26:28], 0x5678)
			before := append([]byte(nil), packet...)
			if err := MaterializeIPv4UDPChecksums(packet); err == nil {
				t.Fatal("unsupported header was accepted")
			}
			if !bytes.Equal(packet, before) {
				t.Fatal("rejected materialization partially modified the packet")
			}
		})
	}
}

func TestValidateMaterializedIPv4UDPAllowsDontFragment(t *testing.T) {
	flow := packetTestFlow(t)
	packet := unmaterializedIPv4UDP(flow, []byte{1, 2, 3})
	binary.BigEndian.PutUint16(packet[6:8], 0x4000)
	if err := MaterializeIPv4UDPChecksums(packet); err != nil {
		t.Fatal(err)
	}
	if err := ValidateMaterializedIPv4UDP(packet, flow); err != nil {
		t.Fatal(err)
	}
}

func unmaterializedIPv4UDP(flow abi.FakeTCPSessionKey, payload []byte) []byte {
	packet := make([]byte, 20+8+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 17
	binary.NativeEndian.PutUint32(packet[12:16], flow.LocalIPv4)
	binary.NativeEndian.PutUint32(packet[16:20], flow.RemoteIPv4)
	binary.BigEndian.PutUint16(packet[20:22], flow.LocalPort)
	binary.BigEndian.PutUint16(packet[22:24], flow.RemotePort)
	binary.BigEndian.PutUint16(packet[24:26], uint16(8+len(payload)))
	copy(packet[28:], payload)
	return packet
}

func byteMutation(offset int, value byte) func([]byte) []byte {
	return func(packet []byte) []byte {
		packet[offset] = value
		return packet
	}
}

func xorByteMutation(offset int, value byte) func([]byte) []byte {
	return func(packet []byte) []byte {
		packet[offset] ^= value
		return packet
	}
}

func uint16Mutation(offset int, value uint16) func([]byte) []byte {
	return func(packet []byte) []byte {
		binary.BigEndian.PutUint16(packet[offset:offset+2], value)
		return packet
	}
}
