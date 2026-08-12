package faketcp

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"testing"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

func TestMarshalIPv4TCPControlGoldenLayout(t *testing.T) {
	flow := packetTestFlow(t)
	control := ControlPacket{
		Flags:           FlagSYN | FlagACK,
		Sequence:        0x01020304,
		Acknowledgement: 0xa0b0c0d0,
		Window:          0x1234,
	}
	packet, err := MarshalIPv4TCPControl(flow, control)
	if err != nil {
		t.Fatal(err)
	}
	want, err := hex.DecodeString("4500002800000000400666ce0a0000010a000002791901bb01020304a0b0c0d050121234a9400000")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(packet, want) {
		t.Fatalf("control packet\n got %x\nwant %x", packet, want)
	}
	if got := referenceChecksumResidual(packet[:20]); got != 0xffff {
		t.Fatalf("independent IPv4 checksum residual = %#04x", got)
	}
	if got := referenceTransportResidual(packet[12:20], 6, packet[20:]); got != 0xffff {
		t.Fatalf("independent TCP checksum residual = %#04x", got)
	}
}

func TestMarshalIPv4TCPControlAcceptsOnlyEngineControlFlags(t *testing.T) {
	flow := packetTestFlow(t)
	for flagValue := 0; flagValue <= 0xff; flagValue++ {
		flags := uint8(flagValue)
		t.Run(controlFlagName(flags), func(t *testing.T) {
			packet, err := MarshalIPv4TCPControl(flow, ControlPacket{Flags: flags})
			valid := flags == FlagSYN || flags == FlagSYN|FlagACK || flags == FlagACK
			if valid {
				if err != nil {
					t.Fatal(err)
				}
				if len(packet) != 40 || packet[32] != 5<<4 || packet[33] != flags {
					t.Fatalf("encoded control = %x", packet)
				}
			} else if err == nil || packet != nil {
				t.Fatalf("unsupported flags %#x returned packet=%x err=%v", flags, packet, err)
			}
		})
	}
}

func TestMarshalIPv4TCPControlRejectsIncompleteFlow(t *testing.T) {
	base := packetTestFlow(t)
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
		{name: "wg-id", mutate: func(flow *abi.FakeTCPSessionKey) { flow.WGID = 0 }},
		{name: "reserved", mutate: func(flow *abi.FakeTCPSessionKey) { flow.Reserved[0] = 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			flow := base
			test.mutate(&flow)
			packet, err := MarshalIPv4TCPControl(flow, ControlPacket{Flags: FlagSYN})
			if err == nil || packet != nil {
				t.Fatalf("incomplete flow returned packet=%x err=%v", packet, err)
			}
		})
	}
}

func TestMarshalIPv4TCPControlPreservesMathematicalZeroChecksum(t *testing.T) {
	flow := packetTestFlow(t)
	control := ControlPacket{
		Flags:           FlagACK,
		Sequence:        0x10203040,
		Acknowledgement: 0x50607080,
	}
	for window := 0; window <= 0xffff; window++ {
		control.Window = uint16(window)
		packet, err := MarshalIPv4TCPControl(flow, control)
		if err != nil {
			t.Fatal(err)
		}
		if binary.BigEndian.Uint16(packet[36:38]) != 0 {
			continue
		}
		if got := referenceTransportResidual(packet[12:20], 6, packet[20:]); got != 0xffff {
			t.Fatalf("zero TCP checksum residual = %#04x", got)
		}
		if !tcpChecksumValid(packet[12:20], packet[20:]) {
			t.Fatal("mathematically valid zero TCP checksum failed validation")
		}
		return
	}
	t.Fatal("failed to construct a mathematically valid zero TCP checksum")
}

func packetTestFlow(t *testing.T) abi.FakeTCPSessionKey {
	t.Helper()
	local, err := RawIPv4BE32(netip.MustParseAddr("10.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	remote, err := RawIPv4BE32(netip.MustParseAddr("10.0.0.2"))
	if err != nil {
		t.Fatal(err)
	}
	return abi.FakeTCPSessionKey{
		Generation:    1,
		LocalIPv4:     local,
		RemoteIPv4:    remote,
		UnderlayIndex: 2,
		LocalPort:     31001,
		RemotePort:    443,
		WGID:          7,
	}
}

func controlFlagName(flags uint8) string {
	const digits = "0123456789abcdef"
	return "flags-" + string([]byte{digits[flags>>4], digits[flags&0x0f]})
}

// The reference helpers intentionally do not call production checksum code.
// They provide an independent residual check for packet codec tests.
func referenceChecksumResidual(data []byte) uint16 {
	var sum uint64
	for len(data) >= 2 {
		sum += uint64(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) != 0 {
		sum += uint64(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(sum)
}

func referenceTransportResidual(addresses []byte, protocol uint8, transport []byte) uint16 {
	pseudo := make([]byte, 12+len(transport))
	copy(pseudo[:8], addresses)
	pseudo[9] = protocol
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(transport)))
	copy(pseudo[12:], transport)
	return referenceChecksumResidual(pseudo)
}

func referenceTransportChecksum(addresses []byte, protocol uint8, transport []byte) uint16 {
	return ^referenceTransportResidualForZeroChecksum(addresses, protocol, transport)
}

func referenceTransportResidualForZeroChecksum(addresses []byte, protocol uint8, transport []byte) uint16 {
	copyTransport := append([]byte(nil), transport...)
	switch protocol {
	case 6:
		copyTransport[16], copyTransport[17] = 0, 0
	case 17:
		copyTransport[6], copyTransport[7] = 0, 0
	}
	return referenceTransportResidual(addresses, protocol, copyTransport)
}
