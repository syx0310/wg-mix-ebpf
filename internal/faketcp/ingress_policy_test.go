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
		{name: "IPv6 eight extensions", frame: testIPv6TCPFrame(0, []byte{60, 60, 60, 60, 60, 60, 60, 60}, 443), want: IngressDrop},
		{name: "IPv6 first fragment", frame: testIPv6FragmentTCPFrame(0, 0, 443), want: IngressDrop},
		{name: "IPv6 non-initial fragment", frame: testIPv6FragmentTCPFrame(0, 8, 444), want: IngressDrop},
		{name: "native IPv4 UDP bypass", frame: testIPv4UDPFrame(0, 0, 443), want: IngressDrop},
		{name: "native IPv6 UDP bypass", frame: testIPv6TransportFrame(0, 17, 443), want: IngressDrop},
		{name: "IPv4 AH is ambiguous", frame: testIPv4ProtocolFrame(51), want: IngressDrop},
		{name: "IPv4 ESP is ambiguous", frame: testIPv4ProtocolFrame(50), want: IngressDrop},
		{name: "IPv4 IP-in-IP is ambiguous", frame: testIPv4ProtocolFrame(4), want: IngressDrop},
		{name: "IPv4 IPv6 encapsulation is ambiguous", frame: testIPv4ProtocolFrame(41), want: IngressDrop},
		{name: "IPv4 unknown protocol", frame: testIPv4ProtocolFrame(253), want: IngressDrop},
		{name: "IPv6 AH is ambiguous", frame: testIPv6TCPFrame(0, []byte{51}, 444), want: IngressDrop},
		{name: "IPv6 ESP is ambiguous", frame: testIPv6TCPFrame(0, []byte{50}, 444), want: IngressDrop},
		{name: "IPv6 IP-in-IP is ambiguous", frame: testIPv6TransportFrame(0, 4, 444), want: IngressDrop},
		{name: "IPv6 nested IPv6 is ambiguous", frame: testIPv6TransportFrame(0, 41, 444), want: IngressDrop},
		{name: "IPv6 unknown next header", frame: testIPv6TransportFrame(0, 253, 444), want: IngressDrop},
		{name: "IPv6 extension depth overflow", frame: testIPv6TCPFrame(0, []byte{60, 60, 60, 60, 60, 60, 60, 60, 60}, 444), want: IngressDrop},
		{name: "IPv6 truncated extension", frame: testIPv6TCPFrame(0, []byte{0}, 444)[:55], want: IngressDrop},
		{name: "IPv6 first fragment to UDP managed", frame: testIPv6FragmentFrame(0, 0, 17, 443), want: IngressDrop},
		{name: "IPv6 first fragment to ICMPv6", frame: testIPv6FragmentFrame(0, 0, 58, 443), want: IngressDrop},
		{name: "unfragmented IPv4 ICMP", frame: testIPv4ProtocolFrame(1), want: IngressPass},
		{name: "unfragmented IPv6 ICMPv6", frame: testIPv6TransportFrame(0, 58, 443), want: IngressPass},
		{name: "unmanaged IPv4 port", frame: testIPv4TCPFrame(0, 5, 5, 0, 444), want: IngressPass},
		{name: "unmanaged IPv4 options port", frame: testIPv4TCPFrame(0, 6, 5, 0, 444), want: IngressPass},
		{name: "unmanaged TCP options port", frame: testIPv4TCPFrame(0, 5, 6, 0, 444), want: IngressPass},
		{name: "unmanaged IPv6 port", frame: testIPv6TCPFrame(0, nil, 444), want: IngressPass},
		{name: "unmanaged IPv6 eight extensions port", frame: testIPv6TCPFrame(0, []byte{60, 60, 60, 60, 60, 60, 60, 60}, 444), want: IngressPass},
		{name: "unmanaged IPv4 UDP port", frame: testIPv4UDPFrame(0, 0, 444), want: IngressPass},
		{name: "unmanaged IPv6 UDP port", frame: testIPv6TransportFrame(0, 17, 444), want: IngressPass},
		{name: "triple VLAN is ambiguous", frame: testIPv4TCPFrame(3, 5, 5, 0, 444), want: IngressDrop},
		{name: "truncated managed interface", frame: []byte{0, 1, 2}, want: IngressDrop},
		{name: "truncated IPv4", frame: append(testEthernetPrefix(0, 0x0800), make([]byte, 10)...), want: IngressDrop},
		{name: "truncated IPv6", frame: append(testEthernetPrefix(0, 0x86dd), make([]byte, 20)...), want: IngressDrop},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ClassifyManagedIngressFrame(tt.frame, managed); got != tt.want {
				t.Fatalf("disposition = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestClassifyManagedIngressL3FailClosedMatrix(t *testing.T) {
	managed := ManagedIngressPolicy{
		InterfaceManaged: true,
		Ports:            map[uint16]struct{}{443: {}},
	}
	tests := []struct {
		name   string
		packet []byte
		policy ManagedIngressPolicy
		want   IngressDisposition
	}{
		{name: "IPv4 fixed TCP", packet: testIPv4(5, L3ProtocolTCP, 0, testTCPWithDestination(5, 443)), policy: managed, want: IngressDecodeIPv4},
		{name: "IPv4 native UDP", packet: testIPv4(5, L3ProtocolUDP, 0, testUDP(1, 443, nil)), policy: managed, want: IngressDrop},
		{name: "IPv4 options", packet: testIPv4(6, L3ProtocolTCP, 0, testTCPWithDestination(5, 443)), policy: managed, want: IngressDrop},
		{name: "IPv4 first fragment", packet: testIPv4(5, L3ProtocolTCP, 0x2000, testTCPWithDestination(5, 443)), policy: managed, want: IngressDrop},
		{name: "IPv6 fixed TCP", packet: testIPv6(L3ProtocolTCP, testTCPWithDestination(5, 443)), policy: managed, want: IngressDrop},
		{name: "IPv6 ICMP bypass", packet: testIPv6(L3ProtocolICMPv6, make([]byte, 8)), policy: managed, want: IngressPass},
		{name: "unmanaged port", packet: testIPv4(5, L3ProtocolTCP, 0, testTCPWithDestination(5, 444)), policy: managed, want: IngressPass},
		{name: "truncated managed interface", packet: []byte{0x45}, policy: managed, want: IngressDrop},
		{name: "malformed unmanaged interface", packet: []byte{0x10}, policy: ManagedIngressPolicy{}, want: IngressPass},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := ClassifyManagedIngressL3(test.packet, test.policy); got != test.want {
				t.Fatalf("disposition = %d, want %d", got, test.want)
			}
		})
	}
}

func TestManagedFakeTCPTransformStatusNarrowsGenericParser(t *testing.T) {
	tests := []struct {
		name          string
		packet        []byte
		transport     uint8
		wantL3Header  uint16
		wantL4Header  uint16
		wantTransform L3ParseStatus
	}{
		{
			name:          "fixed IPv4 TCP",
			packet:        testIPv4(5, L3ProtocolTCP, 0, testTCP(5, nil)),
			transport:     L3ProtocolTCP,
			wantL3Header:  20,
			wantL4Header:  20,
			wantTransform: L3ParseOK,
		},
		{
			name:          "IPv4 options remain parseable",
			packet:        testIPv4(6, L3ProtocolTCP, 0, testTCP(5, nil)),
			transport:     L3ProtocolTCP,
			wantL3Header:  24,
			wantL4Header:  20,
			wantTransform: L3ParseUnsupported,
		},
		{
			name:          "TCP options remain parseable",
			packet:        testIPv4(5, L3ProtocolTCP, 0, testTCP(6, nil)),
			transport:     L3ProtocolTCP,
			wantL3Header:  20,
			wantL4Header:  24,
			wantTransform: L3ParseUnsupported,
		},
		{
			name:          "IPv6 remains parseable",
			packet:        testIPv6(L3ProtocolTCP, testTCP(5, nil)),
			transport:     L3ProtocolTCP,
			wantL3Header:  40,
			wantL4Header:  20,
			wantTransform: L3ParseUnsupported,
		},
		{
			name:          "fixed IPv4 UDP",
			packet:        testIPv4(5, L3ProtocolUDP, 0, testUDP(1, 443, nil)),
			transport:     L3ProtocolUDP,
			wantL3Header:  20,
			wantL4Header:  8,
			wantTransform: L3ParseOK,
		},
		{
			name:          "IPv4 UDP options remain parseable",
			packet:        testIPv4(6, L3ProtocolUDP, 0, testUDP(1, 443, nil)),
			transport:     L3ProtocolUDP,
			wantL3Header:  24,
			wantL4Header:  8,
			wantTransform: L3ParseUnsupported,
		},
		{
			name:          "IPv6 UDP remains parseable",
			packet:        testIPv6(L3ProtocolUDP, testUDP(1, 443, nil)),
			transport:     L3ProtocolUDP,
			wantL3Header:  40,
			wantL4Header:  8,
			wantTransform: L3ParseUnsupported,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			info, status := ParseL3(test.packet)
			if status != L3ParseOK {
				t.Fatalf("generic parser status = %v, want OK; info=%#v", status, info)
			}
			if info.L3HeaderLength != test.wantL3Header || info.L4HeaderLength != test.wantL4Header {
				t.Fatalf("generic descriptor = %#v, want L3/L4 headers %d/%d", info, test.wantL3Header, test.wantL4Header)
			}
			if got := managedFakeTCPTransformStatus(info, test.transport); got != test.wantTransform {
				t.Fatalf("transform status = %v, want %v", got, test.wantTransform)
			}
		})
	}
}

func TestManagedFakeTCPDispositionMapsEveryParserStatus(t *testing.T) {
	for _, test := range []struct {
		name    string
		status  L3ParseStatus
		managed IngressDisposition
	}{
		{name: "safe bypass", status: L3ParseSafeBypass, managed: IngressPass},
		{name: "truncated", status: L3ParseTruncated, managed: IngressDrop},
		{name: "malformed", status: L3ParseMalformed, managed: IngressDrop},
		{name: "unsupported", status: L3ParseUnsupported, managed: IngressDrop},
		{name: "first fragment", status: L3ParseFirstFragment, managed: IngressDrop},
		{name: "noninitial fragment", status: L3ParseNonInitialFragment, managed: IngressDrop},
		{name: "extension too deep", status: L3ParseExtensionTooDeep, managed: IngressDrop},
	} {
		t.Run(test.name, func(t *testing.T) {
			managed := ManagedIngressPolicy{InterfaceManaged: true}
			if got := managedFakeTCPDisposition(nil, L3Info{}, test.status, managed); got != test.managed {
				t.Fatalf("managed disposition = %v, want %v", got, test.managed)
			}
			if got := managedFakeTCPDisposition(nil, L3Info{}, test.status, ManagedIngressPolicy{}); got != IngressPass {
				t.Fatalf("unmanaged disposition = %v, want pass", got)
			}
		})
	}
}

func FuzzClassifyManagedIngressFrameUsesParseL3Oracle(f *testing.F) {
	for _, seed := range [][]byte{
		testIPv4TCPFrame(0, 5, 5, 0, 443),
		testIPv4TCPFrame(0, 6, 5, 0, 443),
		testIPv4TCPFrame(0, 5, 6, 0, 443),
		testIPv4TCPFrame(0, 5, 5, 0x2000, 443),
		testIPv6TCPFrame(0, nil, 443),
		testIPv6TCPFrame(0, []byte{60, 60, 60, 60, 60, 60, 60, 60}, 443),
		testIPv6FragmentTCPFrame(0, 0, 443),
		{0, 1, 2},
	} {
		f.Add(seed, true, uint16(443))
	}
	f.Fuzz(func(t *testing.T, frame []byte, interfaceManaged bool, managedPort uint16) {
		policy := ManagedIngressPolicy{
			InterfaceManaged: interfaceManaged,
			Ports:            map[uint16]struct{}{managedPort: {}},
		}
		got := ClassifyManagedIngressFrame(frame, policy)
		l3, info, status := testManagedIngressParseOracle(frame)
		want := IngressPass
		switch {
		case status == L3ParseSafeBypass:
			want = IngressPass
		case status != L3ParseOK:
			if interfaceManaged {
				want = IngressDrop
			}
		case int(info.L4Offset)+4 > len(l3):
			if interfaceManaged {
				want = IngressDrop
			}
		case binary.BigEndian.Uint16(l3[int(info.L4Offset)+2:int(info.L4Offset)+4]) != managedPort:
			want = IngressPass
		case managedFakeTCPTransformStatus(info, info.TransportProtocol) != L3ParseOK:
			want = IngressDrop
		case info.TransportProtocol == L3ProtocolUDP:
			want = IngressDrop
		default:
			want = IngressDecodeIPv4
		}
		if got != want {
			t.Fatalf("classifier=%v oracle=%v status=%v info=%#v frame_len=%d", got, want, status, info, len(frame))
		}
		if got == IngressDecodeIPv4 &&
			(status != L3ParseOK || managedFakeTCPTransformStatus(info, L3ProtocolTCP) != L3ParseOK) {
			t.Fatalf("decode escaped parser/transform gates: status=%v info=%#v", status, info)
		}
	})
}

func TestClassifyManagedIngressFrameDoesNotFailClosedUnmanagedInterface(t *testing.T) {
	policy := ManagedIngressPolicy{Ports: map[uint16]struct{}{443: {}}}
	for _, frame := range [][]byte{
		{0, 1, 2},
		testIPv4TCPFrame(0, 5, 5, 1, 444),
		testIPv6FragmentTCPFrame(0, 8, 444),
		testIPv4ProtocolFrame(4),
		testIPv6TransportFrame(0, 41, 444),
	} {
		if got := ClassifyManagedIngressFrame(frame, policy); got != IngressPass {
			t.Fatalf("unmanaged interface disposition = %d, want pass", got)
		}
	}
}

func testIPv4ProtocolFrame(protocol byte) []byte {
	frame := testIPv4TCPFrame(0, 5, 5, 0, 444)
	frame[14+9] = protocol
	return frame
}

func testTCPWithDestination(dataOffsetWords byte, destination uint16) []byte {
	packet := testTCP(dataOffsetWords, nil)
	binary.BigEndian.PutUint16(packet[2:4], destination)
	return packet
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
	frame := testEthernetPrefix(vlanDepth, 0x0800)
	ipOffset := len(frame)
	frame = append(frame, make([]byte, 20+8)...)
	frame[ipOffset] = 0x45
	binary.BigEndian.PutUint16(frame[ipOffset+2:ipOffset+4], 28)
	binary.BigEndian.PutUint16(frame[ipOffset+6:ipOffset+8], fragment)
	frame[ipOffset+9] = 17
	udpOffset := ipOffset + 20
	binary.BigEndian.PutUint16(frame[udpOffset+2:udpOffset+4], port)
	binary.BigEndian.PutUint16(frame[udpOffset+4:udpOffset+6], 8)
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
	transportLength := 20
	if protocol == L3ProtocolUDP {
		transportLength = 8
	}
	frame = append(frame, make([]byte, 40+transportLength)...)
	frame[ipOffset] = 0x60
	binary.BigEndian.PutUint16(frame[ipOffset+4:ipOffset+6], uint16(transportLength))
	frame[ipOffset+6] = protocol
	transportOffset := ipOffset + 40
	binary.BigEndian.PutUint16(frame[transportOffset+2:transportOffset+4], port)
	if protocol == L3ProtocolUDP {
		binary.BigEndian.PutUint16(frame[transportOffset+4:transportOffset+6], uint16(transportLength))
	}
	if protocol == L3ProtocolTCP {
		frame[transportOffset+12] = 5 << 4
	}
	return frame
}

func testManagedIngressParseOracle(frame []byte) ([]byte, L3Info, L3ParseStatus) {
	const (
		etherTypeIPv4 = 0x0800
		etherTypeIPv6 = 0x86dd
		etherTypeVLAN = 0x8100
		etherTypeQinQ = 0x88a8
	)
	if len(frame) < 14 {
		return nil, L3Info{}, L3ParseTruncated
	}
	offset := 14
	etherType := binary.BigEndian.Uint16(frame[12:14])
	for depth := 0; depth < 2 && (etherType == etherTypeVLAN || etherType == etherTypeQinQ); depth++ {
		if len(frame) < offset+4 {
			return nil, L3Info{}, L3ParseTruncated
		}
		etherType = binary.BigEndian.Uint16(frame[offset+2 : offset+4])
		offset += 4
	}
	if etherType == etherTypeVLAN || etherType == etherTypeQinQ {
		return nil, L3Info{}, L3ParseUnsupported
	}
	if etherType != etherTypeIPv4 && etherType != etherTypeIPv6 {
		return nil, L3Info{}, L3ParseSafeBypass
	}
	l3 := frame[offset:]
	info, status := ParseL3(l3)
	return l3, info, status
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
