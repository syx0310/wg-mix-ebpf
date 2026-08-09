package faketcp

import (
	"encoding/binary"
	"testing"
)

func TestParseL3IPv4Boundaries(t *testing.T) {
	validUDP := testUDP(31001, 443, []byte{1, 2, 3, 4})
	validTCP := testTCP(5, []byte{1, 2, 3, 4})
	tests := []struct {
		name       string
		packet     []byte
		wantStatus L3ParseStatus
		check      func(*testing.T, L3Info)
	}{
		{
			name:       "udp-minimum-header",
			packet:     testIPv4(5, L3ProtocolUDP, 0, validUDP),
			wantStatus: L3ParseOK,
			check: func(t *testing.T, got L3Info) {
				if got.Family != L3FamilyIPv4 || got.L3HeaderLength != 20 ||
					got.L4Offset != 20 || got.L4Length != uint32(len(validUDP)) ||
					got.L4HeaderLength != 8 || got.TransportProtocol != L3ProtocolUDP {
					t.Fatalf("IPv4 UDP descriptor = %#v", got)
				}
			},
		},
		{
			name:       "tcp-maximum-ip-options",
			packet:     testIPv4(15, L3ProtocolTCP, 0x4000, validTCP),
			wantStatus: L3ParseOK,
			check: func(t *testing.T, got L3Info) {
				if got.L3HeaderLength != 60 || got.L4Offset != 60 ||
					got.L4HeaderLength != 20 || got.Flags&L3FlagIPv4Options == 0 ||
					got.Flags&L3FlagIPv4DontFragment == 0 {
					t.Fatalf("IPv4 options descriptor = %#v", got)
				}
			},
		},
		{name: "empty", packet: nil, wantStatus: L3ParseTruncated},
		{name: "short-base", packet: []byte{0x45}, wantStatus: L3ParseTruncated},
		{name: "ihl-below-five", packet: testIPv4(5, L3ProtocolUDP, 0, validUDP), wantStatus: L3ParseMalformed,
			check: func(_ *testing.T, _ L3Info) {}},
		{name: "ihl-truncated", packet: testIPv4HeaderOnly(15, 40), wantStatus: L3ParseTruncated},
		{name: "declared-smaller-than-header", packet: testIPv4DeclaredLength(6, 20), wantStatus: L3ParseMalformed},
		{name: "declared-longer-than-frame", packet: testIPv4DeclaredLength(5, 80), wantStatus: L3ParseTruncated},
		{name: "reserved-fragment-bit", packet: testIPv4(5, L3ProtocolUDP, 0x8000, validUDP), wantStatus: L3ParseMalformed},
		{name: "dont-fragment-with-fragment", packet: testIPv4(5, L3ProtocolUDP, 0x6000, validUDP), wantStatus: L3ParseMalformed},
		{
			name:       "first-fragment",
			packet:     testIPv4(6, L3ProtocolUDP, 0x2000, validUDP),
			wantStatus: L3ParseFirstFragment,
			check: func(t *testing.T, got L3Info) {
				if got.Flags&(L3FlagFragment|L3FlagMoreFragments) !=
					L3FlagFragment|L3FlagMoreFragments || got.FragmentOffsetBytes != 0 {
					t.Fatalf("first fragment descriptor = %#v", got)
				}
			},
		},
		{
			name:       "noninitial-fragment",
			packet:     testIPv4(5, L3ProtocolUDP, 3, []byte{1, 2, 3, 4, 5, 6, 7, 8}),
			wantStatus: L3ParseNonInitialFragment,
			check: func(t *testing.T, got L3Info) {
				if got.FragmentOffsetBytes != 24 || got.Flags&L3FlagFragment == 0 {
					t.Fatalf("non-initial fragment descriptor = %#v", got)
				}
			},
		},
		{name: "udp-declared-length-mismatch", packet: testIPv4(5, L3ProtocolUDP, 0, testUDPWithLength(9, 12)), wantStatus: L3ParseMalformed},
		{name: "tcp-data-offset-small", packet: testIPv4(5, L3ProtocolTCP, 0, testTCP(4, nil)), wantStatus: L3ParseMalformed},
		{name: "tcp-data-offset-past-packet", packet: testIPv4(5, L3ProtocolTCP, 0, testTCPTruncatedDataOffset(15)), wantStatus: L3ParseMalformed},
		{name: "icmp-safe-bypass", packet: testIPv4(5, L3ProtocolICMP, 0, make([]byte, 8)), wantStatus: L3ParseSafeBypass},
		{name: "unknown-protocol", packet: testIPv4(5, 99, 0, make([]byte, 8)), wantStatus: L3ParseUnsupported},
	}

	// Corrupt only the IHL field after constructing an otherwise valid frame.
	tests[4].packet[0] = 0x44
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, status := ParseL3(test.packet)
			if status != test.wantStatus {
				t.Fatalf("status = %v, want %v; info=%#v", status, test.wantStatus, got)
			}
			if test.check != nil {
				test.check(t, got)
			}
		})
	}
}

func TestParseL3IPv6ExtensionAndFragmentBoundaries(t *testing.T) {
	udp := testUDP(31001, 443, []byte{1, 2, 3, 4})
	tcp := testTCP(6, []byte{9, 8, 7, 6})
	hop := testIPv6Option(l3IPv6Destination, 0)
	destination := testIPv6Option(L3ProtocolTCP, 0)
	validExtensions := append(append(append([]byte(nil), hop...), destination...), tcp...)

	tests := []struct {
		name       string
		packet     []byte
		wantStatus L3ParseStatus
		check      func(*testing.T, L3Info)
	}{
		{
			name:       "udp",
			packet:     testIPv6(L3ProtocolUDP, udp),
			wantStatus: L3ParseOK,
			check: func(t *testing.T, got L3Info) {
				if got.Family != L3FamilyIPv6 || got.L3HeaderLength != 40 ||
					got.L4Offset != 40 || got.L4HeaderLength != 8 ||
					got.L4Length != uint32(len(udp)) {
					t.Fatalf("IPv6 UDP descriptor = %#v", got)
				}
			},
		},
		{
			name:       "bounded-extension-chain",
			packet:     testIPv6(l3IPv6HopByHop, validExtensions),
			wantStatus: L3ParseOK,
			check: func(t *testing.T, got L3Info) {
				if got.ExtensionCount != 2 || got.L4Offset != 56 ||
					got.L4HeaderLength != 24 || got.Flags&L3FlagIPv6Extensions == 0 {
					t.Fatalf("IPv6 extension descriptor = %#v", got)
				}
			},
		},
		{name: "short-base", packet: []byte{0x60}, wantStatus: L3ParseTruncated},
		{name: "payload-truncated", packet: testIPv6DeclaredLength(L3ProtocolUDP, 64), wantStatus: L3ParseTruncated},
		{name: "jumbogram", packet: testIPv6ZeroPayload(l3IPv6HopByHop), wantStatus: L3ParseUnsupported},
		{name: "zero-payload-no-next", packet: testIPv6ZeroPayload(L3ProtocolNone), wantStatus: L3ParseSafeBypass},
		{name: "zero-payload-no-next-with-link-padding", packet: append(testIPv6ZeroPayload(L3ProtocolNone), make([]byte, 16)...), wantStatus: L3ParseSafeBypass},
		{name: "icmpv6-safe-bypass", packet: testIPv6(L3ProtocolICMPv6, make([]byte, 8)), wantStatus: L3ParseSafeBypass},
		{name: "hop-not-first", packet: testIPv6(l3IPv6Destination, append(testIPv6Option(l3IPv6HopByHop, 0), testIPv6Option(L3ProtocolUDP, 0)...)), wantStatus: L3ParseMalformed},
		{name: "malformed-option-length", packet: testIPv6(l3IPv6Destination, []byte{L3ProtocolUDP, 4, 0, 0, 0, 0, 0, 0}), wantStatus: L3ParseMalformed},
		{name: "extension-bytes-over-cap", packet: testIPv6(l3IPv6Destination, testIPv6Option(L3ProtocolUDP, 64)), wantStatus: L3ParseExtensionTooDeep},
		{name: "extension-count-over-cap", packet: testIPv6(l3IPv6Destination, testIPv6OptionChain(9, L3ProtocolUDP)), wantStatus: L3ParseExtensionTooDeep},
		{name: "fragment-header-short", packet: testIPv6(l3IPv6Fragment, []byte{L3ProtocolTCP, 0, 0, 0}), wantStatus: L3ParseMalformed},
		{
			name:       "atomic-fragment-still-fragment",
			packet:     testIPv6(l3IPv6Fragment, append(testIPv6Fragment(L3ProtocolTCP, 0), tcp...)),
			wantStatus: L3ParseFirstFragment,
			check: func(t *testing.T, got L3Info) {
				if got.Flags&L3FlagFragment == 0 || got.ExtensionCount != 1 {
					t.Fatalf("atomic fragment descriptor = %#v", got)
				}
			},
		},
		{
			name:       "first-fragment",
			packet:     testIPv6(l3IPv6Fragment, append(testIPv6Fragment(L3ProtocolTCP, 1), tcp...)),
			wantStatus: L3ParseFirstFragment,
			check: func(t *testing.T, got L3Info) {
				if got.FragmentOffsetBytes != 0 || got.Flags&L3FlagMoreFragments == 0 {
					t.Fatalf("IPv6 first fragment descriptor = %#v", got)
				}
			},
		},
		{
			name:       "noninitial-fragment",
			packet:     testIPv6(l3IPv6Fragment, append(testIPv6Fragment(L3ProtocolTCP, 0x0019), make([]byte, 8)...)),
			wantStatus: L3ParseNonInitialFragment,
			check: func(t *testing.T, got L3Info) {
				if got.FragmentOffsetBytes != 24 || got.Flags&L3FlagMoreFragments == 0 {
					t.Fatalf("IPv6 non-initial fragment descriptor = %#v", got)
				}
			},
		},
		{name: "fragment-reserved-bits", packet: testIPv6(l3IPv6Fragment, testIPv6Fragment(L3ProtocolTCP, 0x0002)), wantStatus: L3ParseMalformed},
		{name: "ah-structurally-valid-but-unsupported", packet: testIPv6(L3ProtocolAH, append([]byte{L3ProtocolTCP, 1}, make([]byte, 10)...)), wantStatus: L3ParseUnsupported},
		{name: "ah-malformed", packet: testIPv6(L3ProtocolAH, []byte{L3ProtocolTCP, 0, 0, 0, 0, 0, 0, 0}), wantStatus: L3ParseMalformed},
		{name: "esp-unsupported", packet: testIPv6(L3ProtocolESP, make([]byte, 16)), wantStatus: L3ParseUnsupported},
		{name: "encapsulated-ipv6-unsupported", packet: testIPv6(L3ProtocolIPv6, make([]byte, 40)), wantStatus: L3ParseUnsupported},
		{name: "unknown-next-header", packet: testIPv6(253, make([]byte, 8)), wantStatus: L3ParseUnsupported},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, status := ParseL3(test.packet)
			if status != test.wantStatus {
				t.Fatalf("status = %v, want %v; info=%#v", status, test.wantStatus, got)
			}
			if test.check != nil {
				test.check(t, got)
			}
		})
	}
}

func FuzzParseL3(f *testing.F) {
	for _, seed := range [][]byte{
		testIPv4(5, L3ProtocolUDP, 0, testUDP(1, 2, []byte{1, 2, 3, 4})),
		testIPv4(15, L3ProtocolTCP, 0, testTCP(15, nil)),
		testIPv4(5, L3ProtocolUDP, 0x2000, make([]byte, 8)),
		testIPv6(L3ProtocolUDP, testUDP(1, 2, []byte{1, 2, 3, 4})),
		testIPv6(l3IPv6Destination, testIPv6OptionChain(8, L3ProtocolTCP)),
		testIPv6(l3IPv6Fragment, testIPv6Fragment(L3ProtocolTCP, 0x0019)),
		{},
		{0xff},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, packet []byte) {
		info, status := ParseL3(packet)
		if status != L3ParseOK {
			return
		}
		if info.Family != L3FamilyIPv4 && info.Family != L3FamilyIPv6 {
			t.Fatalf("successful parse has family %d", info.Family)
		}
		if info.TransportProtocol != L3ProtocolUDP && info.TransportProtocol != L3ProtocolTCP {
			t.Fatalf("successful parse has transport %d", info.TransportProtocol)
		}
		if info.L3Length > uint32(len(packet)) || info.L4Offset > info.L3Length ||
			info.L4Length > info.L3Length-info.L4Offset || info.L4HeaderLength == 0 ||
			uint32(info.L4HeaderLength) > info.L4Length {
			t.Fatalf("successful parse escaped bounds: len=%d info=%#v", len(packet), info)
		}
	})
}

func BenchmarkParseL3(b *testing.B) {
	cases := map[string][]byte{
		"ipv4-minimum":          testIPv4(5, L3ProtocolUDP, 0, testUDP(31001, 443, make([]byte, 64))),
		"ipv4-options":          testIPv4(15, L3ProtocolTCP, 0, testTCP(15, make([]byte, 64))),
		"ipv6-eight-extensions": testIPv6(l3IPv6Destination, append(testIPv6OptionChain(8, L3ProtocolTCP), testTCP(5, make([]byte, 64))...)),
	}
	for name, packet := range cases {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, _ = ParseL3(packet)
			}
		})
	}
}

func testIPv4(ihlWords byte, protocol byte, fragment uint16, payload []byte) []byte {
	headerLength := int(ihlWords) * 4
	packet := make([]byte, headerLength+len(payload))
	packet[0] = 0x40 | ihlWords
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	binary.BigEndian.PutUint16(packet[6:8], fragment)
	packet[8] = 64
	packet[9] = protocol
	copy(packet[headerLength:], payload)
	return packet
}

func testIPv4HeaderOnly(ihlWords byte, actualLength int) []byte {
	packet := make([]byte, actualLength)
	packet[0] = 0x40 | ihlWords
	binary.BigEndian.PutUint16(packet[2:4], uint16(actualLength))
	return packet
}

func testIPv4DeclaredLength(ihlWords byte, declared int) []byte {
	actual := int(ihlWords) * 4
	if actual < 20 {
		actual = 20
	}
	packet := make([]byte, actual)
	packet[0] = 0x40 | ihlWords
	binary.BigEndian.PutUint16(packet[2:4], uint16(declared))
	packet[9] = L3ProtocolUDP
	return packet
}

func testIPv6(nextHeader byte, payload []byte) []byte {
	packet := make([]byte, 40+len(payload))
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(payload)))
	packet[6] = nextHeader
	packet[7] = 64
	copy(packet[40:], payload)
	return packet
}

func testIPv6DeclaredLength(nextHeader byte, declared int) []byte {
	packet := make([]byte, 40)
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(declared))
	packet[6] = nextHeader
	return packet
}

func testIPv6ZeroPayload(nextHeader byte) []byte {
	packet := make([]byte, 40)
	packet[0] = 0x60
	packet[6] = nextHeader
	return packet
}

func testIPv6Option(nextHeader byte, headerLengthByte byte) []byte {
	length := (int(headerLengthByte) + 1) * 8
	header := make([]byte, length)
	header[0] = nextHeader
	header[1] = headerLengthByte
	return header
}

func testIPv6OptionChain(count int, finalHeader byte) []byte {
	chain := make([]byte, count*8)
	for i := 0; i < count; i++ {
		chain[i*8] = l3IPv6Destination
		if i == count-1 {
			chain[i*8] = finalHeader
		}
	}
	return chain
}

func testIPv6Fragment(nextHeader byte, fragment uint16) []byte {
	header := make([]byte, 8)
	header[0] = nextHeader
	binary.BigEndian.PutUint16(header[2:4], fragment)
	return header
}

func testUDP(source, destination uint16, payload []byte) []byte {
	packet := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(packet[0:2], source)
	binary.BigEndian.PutUint16(packet[2:4], destination)
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(packet)))
	copy(packet[8:], payload)
	return packet
}

func testUDPWithLength(actual, declared int) []byte {
	packet := make([]byte, actual)
	binary.BigEndian.PutUint16(packet[4:6], uint16(declared))
	return packet
}

func testTCP(dataOffsetWords byte, payload []byte) []byte {
	actualHeaderLength := 20
	if int(dataOffsetWords)*4 > actualHeaderLength && dataOffsetWords <= 15 {
		// Most callers asking for an options header want a structurally valid
		// packet; the explicit past-packet test truncates it below.
		actualHeaderLength = int(dataOffsetWords) * 4
	}
	packet := make([]byte, actualHeaderLength+len(payload))
	packet[12] = dataOffsetWords << 4
	copy(packet[actualHeaderLength:], payload)
	return packet
}

func testTCPTruncatedDataOffset(dataOffsetWords byte) []byte {
	packet := make([]byte, 20)
	packet[12] = dataOffsetWords << 4
	return packet
}
