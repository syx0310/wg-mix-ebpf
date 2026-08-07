package faketcp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// MaterializeIPv4UDPChecksums replaces checksum-offload seeds in a captured
// packet with complete IPv4 and UDP checksums before raw reinjection. This is
// separate from the still-gated established TC path, which must handle
// CHECKSUM_PARTIAL in-kernel before FakeTCP can be activated.
func MaterializeIPv4UDPChecksums(packet []byte) error {
	if len(packet) < 28 || packet[0]>>4 != 4 {
		return errors.New("materialize faketcp packet: not IPv4 UDP")
	}
	headerLength := int(packet[0]&0x0f) * 4
	if headerLength < 20 || headerLength+8 > len(packet) {
		return fmt.Errorf("materialize faketcp packet: invalid IPv4 header length %d", headerLength)
	}
	if int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) || packet[9] != 17 {
		return errors.New("materialize faketcp packet: inconsistent IPv4 length or protocol")
	}
	if binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
		return errors.New("materialize faketcp packet: IPv4 fragments are unsupported")
	}
	udp := packet[headerLength:]
	if int(binary.BigEndian.Uint16(udp[4:6])) != len(udp) {
		return errors.New("materialize faketcp packet: inconsistent UDP length")
	}

	packet[10], packet[11] = 0, 0
	binary.BigEndian.PutUint16(packet[10:12], finishChecksum(addChecksumBytes(0, packet[:headerLength])))

	udp[6], udp[7] = 0, 0
	sum := addChecksumBytes(0, packet[12:20])
	pseudoTail := [4]byte{0, 17, udp[4], udp[5]}
	sum = addChecksumBytes(sum, pseudoTail[:])
	sum = addChecksumBytes(sum, udp)
	checksum := finishChecksum(sum)
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:8], checksum)
	return nil
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
