package faketcp

import (
	"encoding/binary"
	"testing"
)

type tcPacketParseResult uint8

const (
	tcPacketParseOK tcPacketParseResult = iota
	tcPacketParseShort
	tcPacketParseNotUDP
	tcPacketParseFragment
	tcPacketParseIPv6Extension
	tcPacketParseIPv4FirstFragment
	tcPacketParseIPv4NonInitialFragment
	tcPacketParseIPv6ExtensionUDP
	tcPacketParseIPv6FirstFragment
	tcPacketParseIPv6NonInitialFragment
	tcPacketParseBadChecksum
	tcPacketParseIPv6ExtensionTooDeep
)

type tcUDPProjection struct {
	IPOffset         uint32
	UDPOffset        uint32
	PayloadOffset    uint32
	PayloadLength    uint32
	SourcePort       uint16
	DestinationPort  uint16
	Family           uint8
	IPv4ChecksumZero bool
}

func projectTCUDPPacket(packet []byte) (L3Info, tcUDPProjection, tcPacketParseResult) {
	l3, status := ParseL3(packet)
	if status != L3ParseOK {
		return l3, tcUDPProjection{}, tcResultFromL3Status(l3, status)
	}
	if l3.TransportProtocol != L3ProtocolUDP {
		return l3, tcUDPProjection{}, tcPacketParseNotUDP
	}
	offset := int(l3.L4Offset)
	if l3.L4Length < 8 || offset < 0 || offset > len(packet) || len(packet)-offset < 8 {
		return l3, tcUDPProjection{}, tcPacketParseShort
	}
	udp := packet[offset : offset+8]
	projection := tcUDPProjection{
		IPOffset:         l3.L3Offset,
		UDPOffset:        l3.L4Offset,
		PayloadOffset:    l3.L4Offset + 8,
		PayloadLength:    l3.L4Length - 8,
		SourcePort:       binary.BigEndian.Uint16(udp[0:2]),
		DestinationPort:  binary.BigEndian.Uint16(udp[2:4]),
		Family:           l3.Family,
		IPv4ChecksumZero: l3.Family == L3FamilyIPv4 && binary.BigEndian.Uint16(udp[6:8]) == 0,
	}
	if l3.Family == L3FamilyIPv6 && binary.BigEndian.Uint16(udp[6:8]) == 0 {
		return l3, projection, tcPacketParseBadChecksum
	}
	if l3.Flags&L3FlagIPv6Extensions == 0 && projection.PayloadLength < 4 {
		return l3, projection, tcPacketParseShort
	}
	if l3.Flags&L3FlagIPv6Extensions != 0 {
		return l3, projection, tcPacketParseIPv6ExtensionUDP
	}
	return l3, projection, tcPacketParseOK
}

func tcResultFromL3Status(info L3Info, status L3ParseStatus) tcPacketParseResult {
	switch status {
	case L3ParseSafeBypass:
		return tcPacketParseNotUDP
	case L3ParseFirstFragment:
		if info.Family == L3FamilyIPv6 {
			return tcPacketParseIPv6FirstFragment
		}
		return tcPacketParseIPv4FirstFragment
	case L3ParseNonInitialFragment:
		if info.Family == L3FamilyIPv6 {
			return tcPacketParseIPv6NonInitialFragment
		}
		return tcPacketParseIPv4NonInitialFragment
	case L3ParseExtensionTooDeep:
		if info.Family == L3FamilyIPv6 {
			return tcPacketParseIPv6ExtensionTooDeep
		}
		return tcPacketParseShort
	case L3ParseUnsupported:
		if info.Family == L3FamilyIPv6 {
			return tcPacketParseIPv6Extension
		}
		return tcPacketParseNotUDP
	default:
		return tcPacketParseShort
	}
}

func fixedIPv4UDPGate(info L3Info) bool {
	return info.Family == L3FamilyIPv4 &&
		info.L3HeaderLength == 20 &&
		info.TransportProtocol == L3ProtocolUDP &&
		info.L4HeaderLength == 8
}

func TestSingleTCDescriptorBoundaryModel(t *testing.T) {
	validUDP := testUDP(31001, 443, []byte{1, 2, 3, 4})
	v6UDP := append([]byte(nil), validUDP...)
	binary.BigEndian.PutUint16(v6UDP[6:8], 1)
	v6ExtensionUDP := append(testIPv6Option(L3ProtocolUDP, 0), v6UDP...)

	tests := []struct {
		name       string
		packet     []byte
		wantResult tcPacketParseResult
		wantGate   bool
		check      func(*testing.T, tcUDPProjection)
	}{
		{
			name:       "fixed-ipv4-udp",
			packet:     testIPv4(5, L3ProtocolUDP, 0, validUDP),
			wantResult: tcPacketParseOK,
			wantGate:   true,
			check: func(t *testing.T, got tcUDPProjection) {
				if got.UDPOffset != 20 || got.PayloadOffset != 28 || got.PayloadLength != 4 ||
					got.SourcePort != 31001 || got.DestinationPort != 443 || !got.IPv4ChecksumZero {
					t.Fatalf("UDP projection = %#v", got)
				}
			},
		},
		{name: "ipv4-options-stay-outside-faketcp-gate", packet: testIPv4(6, L3ProtocolUDP, 0, validUDP), wantResult: tcPacketParseOK},
		{name: "ipv6-udp-stays-outside-faketcp-gate", packet: testIPv6(L3ProtocolUDP, v6UDP), wantResult: tcPacketParseOK},
		{name: "ipv6-zero-checksum", packet: testIPv6(L3ProtocolUDP, validUDP), wantResult: tcPacketParseBadChecksum},
		{name: "ipv6-extension-udp", packet: testIPv6(l3IPv6Destination, v6ExtensionUDP), wantResult: tcPacketParseIPv6ExtensionUDP},
		{name: "ipv4-first-fragment", packet: testIPv4(5, L3ProtocolUDP, 0x2000, validUDP), wantResult: tcPacketParseIPv4FirstFragment},
		{name: "ipv4-noninitial-fragment", packet: testIPv4(5, L3ProtocolUDP, 3, make([]byte, 8)), wantResult: tcPacketParseIPv4NonInitialFragment},
		{name: "ipv6-first-fragment", packet: testIPv6(l3IPv6Fragment, append(testIPv6Fragment(L3ProtocolUDP, 1), v6UDP...)), wantResult: tcPacketParseIPv6FirstFragment},
		{name: "ipv6-noninitial-fragment", packet: testIPv6(l3IPv6Fragment, append(testIPv6Fragment(L3ProtocolUDP, 0x0019), make([]byte, 8)...)), wantResult: tcPacketParseIPv6NonInitialFragment},
		{name: "truncated-ipv4", packet: []byte{0x45}, wantResult: tcPacketParseShort},
		{name: "malformed-udp-length", packet: testIPv4(5, L3ProtocolUDP, 0, testUDPWithLength(9, 12)), wantResult: tcPacketParseShort},
		{name: "short-udp-payload", packet: testIPv4(5, L3ProtocolUDP, 0, testUDP(1, 2, []byte{1, 2, 3})), wantResult: tcPacketParseShort},
		{name: "tcp-is-not-udp", packet: testIPv4(5, L3ProtocolTCP, 0, testTCP(5, nil)), wantResult: tcPacketParseNotUDP},
		{name: "ipv6-extension-too-deep", packet: testIPv6(l3IPv6Destination, testIPv6Option(L3ProtocolUDP, 64)), wantResult: tcPacketParseIPv6ExtensionTooDeep},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			l3, projection, result := projectTCUDPPacket(test.packet)
			if result != test.wantResult {
				t.Fatalf("parse result=%d, want=%d; l3=%#v projection=%#v", result, test.wantResult, l3, projection)
			}
			if got := result == tcPacketParseOK && fixedIPv4UDPGate(l3); got != test.wantGate {
				t.Fatalf("fixed IPv4/UDP gate=%v, want=%v; l3=%#v", got, test.wantGate, l3)
			}
			if test.check != nil {
				test.check(t, projection)
			}
		})
	}
}

func legacyGenericIPv4UDP(packet []byte) (tcUDPProjection, tcPacketParseResult) {
	if len(packet) < 20 {
		return tcUDPProjection{}, tcPacketParseShort
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || ihl > len(packet) || packet[9] != L3ProtocolUDP {
		return tcUDPProjection{}, tcPacketParseNotUDP
	}
	if len(packet)-ihl < 8 {
		return tcUDPProjection{}, tcPacketParseShort
	}
	udp := packet[ihl : ihl+8]
	udpLength := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLength < 8 || udpLength > len(packet)-ihl {
		return tcUDPProjection{}, tcPacketParseShort
	}
	return tcUDPProjection{
		UDPOffset:        uint32(ihl),
		PayloadOffset:    uint32(ihl + 8),
		PayloadLength:    uint32(udpLength - 8),
		SourcePort:       binary.BigEndian.Uint16(udp[0:2]),
		DestinationPort:  binary.BigEndian.Uint16(udp[2:4]),
		Family:           L3FamilyIPv4,
		IPv4ChecksumZero: binary.BigEndian.Uint16(udp[6:8]) == 0,
	}, tcPacketParseOK
}

func legacyTwoParserModel(packet []byte) (L3Info, tcUDPProjection, tcPacketParseResult) {
	projection, result := legacyGenericIPv4UDP(packet)
	if result != tcPacketParseOK {
		return L3Info{}, projection, result
	}
	l3, status := ParseL3(packet)
	if status != L3ParseOK || !fixedIPv4UDPGate(l3) {
		return l3, projection, tcPacketParseShort
	}
	return l3, projection, result
}

var (
	benchmarkSingleL3         L3Info
	benchmarkSingleProjection tcUDPProjection
	benchmarkSingleResult     tcPacketParseResult
)

func BenchmarkTCFakeTCPSingleAuthoritativeParseModel(b *testing.B) {
	packet := testIPv4(5, L3ProtocolUDP, 0,
		testUDP(31001, 443, make([]byte, 148)))
	benchmarks := []struct {
		name   string
		parses float64
		parse  func([]byte) (L3Info, tcUDPProjection, tcPacketParseResult)
	}{
		{name: "legacy-generic-plus-shared", parses: 2, parse: legacyTwoParserModel},
		{name: "single-authoritative-descriptor", parses: 1, parse: projectTCUDPPacket},
	}
	for _, benchmark := range benchmarks {
		b.Run(benchmark.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ReportMetric(benchmark.parses, "l3-l4-parses/op")
			for i := 0; i < b.N; i++ {
				benchmarkSingleL3, benchmarkSingleProjection, benchmarkSingleResult = benchmark.parse(packet)
			}
		})
	}
}
