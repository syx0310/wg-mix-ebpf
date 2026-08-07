package faketcp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

const (
	materializedIPv4HeaderLength = 20
	udpHeaderLength              = 8
)

// MaterializeIPv4UDPChecksums replaces checksum-offload seeds in a captured
// packet with complete IPv4 and UDP checksums before raw reinjection. This is
// separate from the still-gated established TC path, which must handle
// CHECKSUM_PARTIAL in-kernel before FakeTCP can be activated.
func MaterializeIPv4UDPChecksums(packet []byte) error {
	udp, err := fixedIPv4UDP(packet, "materialize faketcp packet")
	if err != nil {
		return err
	}

	packet[10], packet[11] = 0, 0
	binary.BigEndian.PutUint16(packet[10:12], finishChecksum(addChecksumBytes(0, packet[:materializedIPv4HeaderLength])))

	udp[6], udp[7] = 0, 0
	checksum := transportChecksum(packet[12:20], 17, udp)
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:8], checksum)
	return nil
}

// ValidateMaterializedIPv4UDP validates a complete, non-fragmented IPv4/UDP
// packet captured for flow after checksum offload has been materialized. The
// fixed 20-byte IPv4 header is deliberate: options are not supported by the
// experimental FakeTCP reinjection path. The packet is never modified.
func ValidateMaterializedIPv4UDP(packet []byte, flow abi.FakeTCPSessionKey) error {
	udp, err := fixedIPv4UDP(packet, "validate materialized faketcp packet")
	if err != nil {
		return err
	}
	if err := validatePacketFlow(flow); err != nil {
		return fmt.Errorf("validate materialized faketcp packet: %w", err)
	}

	var localAddress, remoteAddress [4]byte
	binary.NativeEndian.PutUint32(localAddress[:], flow.LocalIPv4)
	binary.NativeEndian.PutUint32(remoteAddress[:], flow.RemoteIPv4)
	if !bytes.Equal(packet[12:16], localAddress[:]) || !bytes.Equal(packet[16:20], remoteAddress[:]) {
		return errors.New("validate materialized faketcp packet: IPv4 endpoints do not match the flow")
	}
	if binary.BigEndian.Uint16(udp[0:2]) != flow.LocalPort || binary.BigEndian.Uint16(udp[2:4]) != flow.RemotePort {
		return errors.New("validate materialized faketcp packet: UDP ports do not match the flow")
	}
	if !checksumValid(packet[:materializedIPv4HeaderLength]) {
		return errors.New("validate materialized faketcp packet: IPv4 checksum is invalid")
	}
	if binary.BigEndian.Uint16(udp[6:8]) == 0 {
		return errors.New("validate materialized faketcp packet: UDP checksum is absent")
	}
	if !transportChecksumValid(packet[12:20], 17, udp) {
		return errors.New("validate materialized faketcp packet: UDP checksum is invalid")
	}
	return nil
}

func fixedIPv4UDP(packet []byte, operation string) ([]byte, error) {
	if len(packet) < materializedIPv4HeaderLength+udpHeaderLength || packet[0]>>4 != 4 {
		return nil, fmt.Errorf("%s: not complete IPv4/UDP", operation)
	}
	headerLength := int(packet[0]&0x0f) * 4
	if headerLength != materializedIPv4HeaderLength {
		return nil, fmt.Errorf("%s: IPv4 header length %d is unsupported", operation, headerLength)
	}
	if int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) {
		return nil, fmt.Errorf("%s: IPv4 total length is inconsistent", operation)
	}
	if binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
		return nil, fmt.Errorf("%s: IPv4 fragments are unsupported", operation)
	}
	if packet[9] != 17 {
		return nil, fmt.Errorf("%s: IPv4 protocol %d is not UDP", operation, packet[9])
	}
	udp := packet[materializedIPv4HeaderLength:]
	if int(binary.BigEndian.Uint16(udp[4:6])) != len(udp) {
		return nil, fmt.Errorf("%s: UDP length is inconsistent", operation)
	}
	return udp, nil
}

func addChecksumBytes(sum uint32, data []byte) uint32 {
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) != 0 {
		sum += uint32(data[0]) << 8
	}
	return sum
}

func finishChecksum(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func checksumValid(data []byte) bool {
	return finishChecksum(addChecksumBytes(0, data)) == 0
}

func transportChecksum(addresses []byte, protocol uint8, transport []byte) uint16 {
	return finishChecksum(transportChecksumSum(addresses, protocol, transport))
}

func transportChecksumValid(addresses []byte, protocol uint8, transport []byte) bool {
	return finishChecksum(transportChecksumSum(addresses, protocol, transport)) == 0
}

func transportChecksumSum(addresses []byte, protocol uint8, transport []byte) uint32 {
	var pseudo [12]byte
	copy(pseudo[0:8], addresses)
	pseudo[9] = protocol
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(transport)))
	sum := addChecksumBytes(0, pseudo[:])
	return addChecksumBytes(sum, transport)
}
