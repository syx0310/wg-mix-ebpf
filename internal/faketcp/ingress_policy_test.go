package faketcp

import (
	"encoding/binary"
	"testing"
)

func TestClassifyManagedIngressFrameFailClosedMatrix(t *testing.T) {
	managed := ManagedIngressPolicy{
		InterfaceManaged: true,
		Ports:            map[uint16]struct{}{443: {}},
	}
	tests := []struct {
		name  string
		frame []byte
		want  IngressDisposition
	}{
		{name: "IPv4 fixed", frame: testIPv4TCPFrame(0, 5, 5, 0, 443), want: IngressDecodeIPv4},
		{name: "IPv4 single VLAN", frame: testIPv4TCPFrame(1, 5, 5, 0, 443), want: IngressDecodeIPv4},
		{name: "IPv4 double VLAN", frame: testIPv4TCPFrame(2, 5, 5, 0, 443), want: IngressDecodeIPv4},
		{name: "IPv4 options", frame: testIPv4TCPFrame(0, 6, 5, 0, 443), want: IngressDrop},
		{name: "TCP options", frame: testIPv4TCPFrame(0, 5, 6, 0, 443), want: IngressDrop},
		{name: "IPv4 first fragment", frame: testIPv4TCPFrame(0, 5, 5, 0x2000, 443), want: IngressDrop},
		{name: "IPv4 non-initial fragment", frame: testIPv4TCPFrame(0, 5, 5, 1, 444), want: IngressDrop},
		{name: "IPv6 fixed", frame: testIPv6TCPFrame(0, nil, 443), want: IngressDrop},
		{name: "IPv6 double VLAN", frame: testIPv6TCPFrame(2, nil, 443), want: IngressDrop},
		{name: "IPv6 hop-by-hop", frame: testIPv6TCPFrame(0, []byte{0}, 443), want: IngressDrop},
		{name: "IPv6 first fragment", frame: testIPv6FragmentTCPFrame(0, 0, 443), want: IngressDrop},
		{name: "IPv6 non-initial fragment", frame: testIPv6FragmentTCPFrame(0, 8, 444), want: IngressDrop},
		{name: "native IPv4 UDP bypass", frame: testIPv4UDPFrame(0, 0, 443), want: IngressDrop},
		{name: "native IPv6 UDP bypass", frame: testIPv6TransportFrame(0, 17, 443), want: IngressDrop},
		{name: "IPv6 AH is ambiguous", frame: testIPv6TCPFrame(0, []byte{51}, 444), want: IngressDrop},
		{name: "IPv6 ESP is ambiguous", frame: testIPv6TCPFrame(0, []byte{50}, 444), want: IngressDrop},
		{name: "IPv6 unknown next header", frame: testIPv6TransportFrame(0, 253, 444), want: IngressDrop},
		{name: "IPv6 extension depth overflow", frame: testIPv6TCPFrame(0, []byte{0, 0, 0, 0, 0}, 444), want: IngressDrop},
		{name: "IPv6 truncated extension", frame: testIPv6TCPFrame(0, []byte{0}, 444)[:55], want: IngressDrop},
		{name: "IPv6 first fragment to UDP managed", frame: testIPv6FragmentFrame(0, 0, 17, 443), want: IngressDrop},
		{name: "IPv6 first fragment to ICMPv6", frame: testIPv6FragmentFrame(0, 0, 58, 443), want: IngressPass},
		{name: "unmanaged IPv4 port", frame: testIPv4TCPFrame(0, 5, 5, 0, 444), want: IngressPass},
		{name: "unmanaged IPv6 port", frame: testIPv6TCPFrame(0, nil, 444), want: IngressPass},
		{name: "unmanaged IPv4 UDP port", frame: testIPv4UDPFrame(0, 0, 444), want: IngressPass},
		{name: "unmanaged IPv6 UDP port", frame: testIPv6TransportFrame(0, 17, 444), want: IngressPass},
		{name: "triple VLAN is ambiguous", frame: testIPv4TCPFrame(3, 5, 5, 0, 444), want: IngressDrop},
		{name: "truncated managed interface", frame: []byte{0, 1, 2}, want: IngressDrop},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ClassifyManagedIngressFrame(tt.frame, managed); got != tt.want {
				t.Fatalf("disposition = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestClassifyManagedIngressFrameDoesNotFailClosedUnmanagedInterface(t *testing.T) {
	policy := ManagedIngressPolicy{Ports: map[uint16]struct{}{443: {}}}
	for _, frame := range [][]byte{
		{0, 1, 2},
		testIPv4TCPFrame(0, 5, 5, 1, 444),
		testIPv6FragmentTCPFrame(0, 8, 444),
	} {
		if got := ClassifyManagedIngressFrame(frame, policy); got != IngressPass {
			t.Fatalf("unmanaged interface disposition = %d, want pass", got)
		}
	}
}

func testEthernetPrefix(vlanDepth int, etherType uint16) []byte {
	frame := make([]byte, 14+vlanDepth*4)
	if vlanDepth == 0 {
		binary.BigEndian.PutUint16(frame[12:14], etherType)
		return frame
	}
	binary.BigEndian.PutUint16(frame[12:14], 0x88a8)
	for depth := 0; depth < vlanDepth; depth++ {
		offset := 14 + depth*4
		next := uint16(0x8100)
		if depth == vlanDepth-1 {
			next = etherType
		}
		binary.BigEndian.PutUint16(frame[offset+2:offset+4], next)
	}
	return frame
}

func testIPv4TCPFrame(vlanDepth, ipWords, tcpWords int, fragment uint16, port uint16) []byte {
	frame := testEthernetPrefix(vlanDepth, 0x0800)
	ipOffset := len(frame)
	ipLength := ipWords * 4
	tcpLength := tcpWords * 4
	frame = append(frame, make([]byte, ipLength+tcpLength)...)
	frame[ipOffset] = 0x40 | byte(ipWords)
	binary.BigEndian.PutUint16(frame[ipOffset+2:ipOffset+4], uint16(ipLength+tcpLength))
	binary.BigEndian.PutUint16(frame[ipOffset+6:ipOffset+8], fragment)
	frame[ipOffset+9] = 6
	tcpOffset := ipOffset + ipLength
	binary.BigEndian.PutUint16(frame[tcpOffset+2:tcpOffset+4], port)
	frame[tcpOffset+12] = byte(tcpWords << 4)
	return frame
}

func testIPv4UDPFrame(vlanDepth int, fragment uint16, port uint16) []byte {
	frame := testIPv4TCPFrame(vlanDepth, 5, 5, fragment, port)
	ipOffset := 14 + vlanDepth*4
	frame[ipOffset+9] = 17
	return frame
}

func testIPv6TCPFrame(vlanDepth int, extensionHeaders []byte, port uint16) []byte {
	frame := testEthernetPrefix(vlanDepth, 0x86dd)
	ipOffset := len(frame)
	payloadLength := len(extensionHeaders)*8 + 20
	frame = append(frame, make([]byte, 40+payloadLength)...)
	frame[ipOffset] = 0x60
	binary.BigEndian.PutUint16(frame[ipOffset+4:ipOffset+6], uint16(payloadLength))
	if len(extensionHeaders) == 0 {
		frame[ipOffset+6] = 6
	} else {
		frame[ipOffset+6] = extensionHeaders[0]
	}
	offset := ipOffset + 40
	for index := range extensionHeaders {
		next := byte(6)
		if index+1 < len(extensionHeaders) {
			next = extensionHeaders[index+1]
		}
		frame[offset] = next
		frame[offset+1] = 0
		offset += 8
	}
	binary.BigEndian.PutUint16(frame[offset+2:offset+4], port)
	frame[offset+12] = 5 << 4
	return frame
}

func testIPv6FragmentTCPFrame(vlanDepth int, fragmentOffset uint16, port uint16) []byte {
	return testIPv6FragmentFrame(vlanDepth, fragmentOffset, 6, port)
}

func testIPv6TransportFrame(vlanDepth int, protocol byte, port uint16) []byte {
	frame := testEthernetPrefix(vlanDepth, 0x86dd)
	ipOffset := len(frame)
	frame = append(frame, make([]byte, 40+20)...)
	frame[ipOffset] = 0x60
	binary.BigEndian.PutUint16(frame[ipOffset+4:ipOffset+6], 20)
	frame[ipOffset+6] = protocol
	transportOffset := ipOffset + 40
	binary.BigEndian.PutUint16(frame[transportOffset+2:transportOffset+4], port)
	return frame
}

func testIPv6FragmentFrame(vlanDepth int, fragmentOffset uint16, nextHeader byte, port uint16) []byte {
	frame := testEthernetPrefix(vlanDepth, 0x86dd)
	ipOffset := len(frame)
	frame = append(frame, make([]byte, 40+8+20)...)
	frame[ipOffset] = 0x60
	binary.BigEndian.PutUint16(frame[ipOffset+4:ipOffset+6], 28)
	frame[ipOffset+6] = 44
	fragmentOffsetIndex := ipOffset + 40
	frame[fragmentOffsetIndex] = nextHeader
	binary.BigEndian.PutUint16(frame[fragmentOffsetIndex+2:fragmentOffsetIndex+4], fragmentOffset)
	tcpOffset := fragmentOffsetIndex + 8
	binary.BigEndian.PutUint16(frame[tcpOffset+2:tcpOffset+4], port)
	frame[tcpOffset+12] = 5 << 4
	return frame
}
