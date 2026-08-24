//go:build linux

package dataplane

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"

	"github.com/syx0310/wg-mix-ebpf/internal/faketcp"
	"golang.org/x/sys/unix"
)

const (
	fakeTCPPacketProbeEthernetHeaderSize = 14
	fakeTCPManagedIngressFakeIngressOK   = uint32(1)
)

func fakeTCPManagedIngressEthernet(
	destination, source net.HardwareAddr,
	etherType uint16,
	l3 []byte,
) []byte {
	frame := make(
		[]byte,
		fakeTCPPacketProbeEthernetHeaderSize,
		fakeTCPPacketProbeEthernetHeaderSize+len(l3),
	)
	copy(frame[0:6], destination)
	copy(frame[6:12], source)
	binary.BigEndian.PutUint16(frame[12:14], etherType)
	return append(frame, l3...)
}

func fakeTCPManagedIngressIPv4TCP(
	t *testing.T,
	ipWords, tcpWords int,
	fragment uint16,
	sourcePort, destinationPort uint16,
	sequence, acknowledgement uint32,
	payload []byte,
) []byte {
	t.Helper()
	if ipWords < 5 || tcpWords < 5 {
		t.Fatalf("invalid packet-probe IPv4/TCP header words %d/%d", ipWords, tcpWords)
	}
	ipHeaderLength, tcpHeaderLength := ipWords*4, tcpWords*4
	tcp := make([]byte, tcpHeaderLength+len(payload))
	binary.BigEndian.PutUint16(tcp[0:2], sourcePort)
	binary.BigEndian.PutUint16(tcp[2:4], destinationPort)
	binary.BigEndian.PutUint32(tcp[4:8], sequence)
	binary.BigEndian.PutUint32(tcp[8:12], acknowledgement)
	tcp[12], tcp[13] = byte(tcpWords<<4), faketcp.FlagACK|faketcp.FlagPSH
	binary.BigEndian.PutUint16(tcp[14:16], 4096)
	copy(tcp[tcpHeaderLength:], payload)
	binary.BigEndian.PutUint16(tcp[16:18], fakeTCPRoutedTransportChecksum(
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("10.0.0.2"),
		unix.IPPROTO_TCP,
		tcp,
	))

	ipv4 := make([]byte, ipHeaderLength, ipHeaderLength+len(tcp))
	ipv4[0], ipv4[8], ipv4[9] = 0x40|byte(ipWords), 64, unix.IPPROTO_TCP
	binary.BigEndian.PutUint16(ipv4[2:4], uint16(ipHeaderLength+len(tcp)))
	binary.BigEndian.PutUint16(ipv4[4:6], uint16(sequence))
	binary.BigEndian.PutUint16(ipv4[6:8], fragment)
	copy(ipv4[12:16], []byte{10, 0, 0, 1})
	copy(ipv4[16:20], []byte{10, 0, 0, 2})
	binary.BigEndian.PutUint16(ipv4[10:12], internetChecksum(ipv4))
	return append(ipv4, tcp...)
}

func fakeTCPRoutedTransportChecksum(
	source netip.Addr,
	destination netip.Addr,
	protocol byte,
	transport []byte,
) uint16 {
	checksum := fakeTCPRoutedTransportChecksumResidual(
		source,
		destination,
		protocol,
		transport,
	)
	if checksum == 0 {
		return 0xffff
	}
	return checksum
}

func fakeTCPRoutedTransportChecksumResidual(
	source netip.Addr,
	destination netip.Addr,
	protocol byte,
	transport []byte,
) uint16 {
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], source.AsSlice())
	copy(pseudo[4:8], destination.AsSlice())
	pseudo[9] = protocol
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(transport)))
	return internetChecksum(append(pseudo, transport...))
}
