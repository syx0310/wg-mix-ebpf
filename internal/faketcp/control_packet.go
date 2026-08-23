package faketcp

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

const (
	controlIPv4HeaderLength = 20
	controlTCPHeaderLength  = 20
	controlPacketLength     = controlIPv4HeaderLength + controlTCPHeaderLength
	// IP_HDRINCL fills a zero IPv4 identification field before the packet
	// reaches TC egress. Use one non-zero protocol marker so the bytes written
	// by userspace remain identical to the canonical packet that BPF validates.
	controlIPv4Identification = 0x5747
)

// MarshalIPv4TCPControl encodes one Engine control action as a payload-free,
// options-free IPv4/TCP packet. FakeTCP control packets use TCP-shaped
// signalling only; this function does not provide TCP reliability or stream
// semantics and does not send the returned bytes.
func MarshalIPv4TCPControl(flow abi.FakeTCPSessionKey, control ControlPacket) ([]byte, error) {
	if err := validatePacketFlow(flow); err != nil {
		return nil, fmt.Errorf("marshal faketcp control: %w", err)
	}
	switch control.Flags {
	case FlagSYN, FlagSYN | FlagACK, FlagACK:
	default:
		return nil, fmt.Errorf("marshal faketcp control: unsupported TCP flags %#x", control.Flags)
	}

	packet := make([]byte, controlPacketLength)
	packet[0] = 4<<4 | controlIPv4HeaderLength/4
	binary.BigEndian.PutUint16(packet[2:4], controlPacketLength)
	binary.BigEndian.PutUint16(packet[4:6], controlIPv4Identification)
	packet[8] = 64
	packet[9] = 6
	binary.NativeEndian.PutUint32(packet[12:16], flow.LocalIPv4)
	binary.NativeEndian.PutUint32(packet[16:20], flow.RemoteIPv4)

	tcp := packet[controlIPv4HeaderLength:]
	binary.BigEndian.PutUint16(tcp[0:2], flow.LocalPort)
	binary.BigEndian.PutUint16(tcp[2:4], flow.RemotePort)
	binary.BigEndian.PutUint32(tcp[4:8], control.Sequence)
	binary.BigEndian.PutUint32(tcp[8:12], control.Acknowledgement)
	tcp[12] = controlTCPHeaderLength / 4 << 4
	tcp[13] = control.Flags
	binary.BigEndian.PutUint16(tcp[14:16], control.Window)
	binary.BigEndian.PutUint16(tcp[16:18], transportChecksum(packet[12:20], 6, tcp))
	binary.BigEndian.PutUint16(packet[10:12], finishChecksum(addChecksumBytes(0, packet[:controlIPv4HeaderLength])))
	return packet, nil
}

func validatePacketFlow(flow abi.FakeTCPSessionKey) error {
	switch {
	case flow.Generation == 0:
		return errors.New("flow generation must be non-zero")
	case flow.LocalIPv4 == 0:
		return errors.New("flow local IPv4 address must be non-zero")
	case flow.RemoteIPv4 == 0:
		return errors.New("flow remote IPv4 address must be non-zero")
	case flow.UnderlayIndex == 0:
		return errors.New("flow underlay interface index must be non-zero")
	case flow.LocalPort == 0:
		return errors.New("flow local port must be non-zero")
	case flow.RemotePort == 0:
		return errors.New("flow remote port must be non-zero")
	case flow.WGID == 0:
		return errors.New("flow WGID must be non-zero")
	case flow.Reserved != ([4]byte{}):
		return errors.New("flow reserved bytes must be zero")
	default:
		return nil
	}
}
