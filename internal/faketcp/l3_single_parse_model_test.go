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

type tcIPv4ParseObservation struct {
	FrameLength  uint32
	TotalLength  uint32
	HeaderLength uint16
	Fragment     uint16
	UDPLength    uint16
	Version      uint8
	Protocol     uint8
}

type tcPacketDescriptorModel struct {
	L3            L3Info
	Info          tcUDPProjection
	GenericStatus tcPacketParseResult
	FakeTCPStatus L3ParseStatus
}

// genericIPv4UDPModel mirrors the ordinary TC parser. In particular, it does
// not validate the IPv4 total length, reserved fragment bit, or equality of
// the UDP and IPv4 lengths; those are stricter FakeTCP-only checks.
func genericIPv4UDPModel(packet []byte) (tcUDPProjection, tcIPv4ParseObservation, tcPacketParseResult) {
	observation := tcIPv4ParseObservation{FrameLength: uint32(len(packet))}
	if len(packet) < 20 {
		return tcUDPProjection{}, observation, tcPacketParseShort
	}
	headerLength := int(packet[0]&0x0f) * 4
	if headerLength < 20 || headerLength > len(packet) {
		return tcUDPProjection{}, observation, tcPacketParseShort
	}
	observation.TotalLength = uint32(binary.BigEndian.Uint16(packet[2:4]))
	observation.HeaderLength = uint16(headerLength)
	observation.Fragment = binary.BigEndian.Uint16(packet[6:8])
	observation.Version = packet[0] >> 4
	observation.Protocol = packet[9]
	if observation.Protocol != L3ProtocolUDP {
		return tcUDPProjection{}, observation, tcPacketParseNotUDP
	}
	if observation.Fragment&0x1fff != 0 {
		return tcUDPProjection{}, observation, tcPacketParseIPv4NonInitialFragment
	}
	if len(packet)-headerLength < 8 {
		return tcUDPProjection{}, observation, tcPacketParseShort
	}
	udp := packet[headerLength : headerLength+8]
	observation.UDPLength = binary.BigEndian.Uint16(udp[4:6])
	if observation.UDPLength < 8 {
		return tcUDPProjection{}, observation, tcPacketParseShort
	}
	projection := tcUDPProjection{
		IPOffset:         0,
		UDPOffset:        uint32(headerLength),
		PayloadOffset:    uint32(headerLength + 8),
		PayloadLength:    uint32(observation.UDPLength - 8),
		SourcePort:       binary.BigEndian.Uint16(udp[0:2]),
		DestinationPort:  binary.BigEndian.Uint16(udp[2:4]),
		Family:           L3FamilyIPv4,
		IPv4ChecksumZero: binary.BigEndian.Uint16(udp[6:8]) == 0,
	}
	if observation.Fragment&0x2000 != 0 {
		return projection, observation, tcPacketParseIPv4FirstFragment
	}
	if projection.PayloadLength < 4 {
		return projection, observation, tcPacketParseShort
	}
	return projection, observation, tcPacketParseOK
}

func strictStatusFromGeneric(status tcPacketParseResult) L3ParseStatus {
	switch status {
	case tcPacketParseShort:
		return L3ParseTruncated
	case tcPacketParseIPv4FirstFragment, tcPacketParseIPv6FirstFragment:
		return L3ParseFirstFragment
	case tcPacketParseIPv4NonInitialFragment, tcPacketParseIPv6NonInitialFragment:
		return L3ParseNonInitialFragment
	case tcPacketParseIPv6ExtensionTooDeep:
		return L3ParseExtensionTooDeep
	case tcPacketParseBadChecksum:
		return L3ParseMalformed
	default:
		return L3ParseUnsupported
	}
}

func projectStrictIPv4UDP(info tcUDPProjection, observed tcIPv4ParseObservation) (L3Info, L3ParseStatus) {
	l3 := L3Info{Family: info.Family, L3Offset: info.IPOffset}
	if info.Family != L3FamilyIPv4 {
		return l3, L3ParseUnsupported
	}
	if observed.Version != 4 || observed.HeaderLength < 20 {
		return l3, L3ParseMalformed
	}
	if info.IPOffset > observed.FrameLength ||
		observed.TotalLength > observed.FrameLength-info.IPOffset {
		return l3, L3ParseTruncated
	}
	if observed.TotalLength < uint32(observed.HeaderLength) {
		return l3, L3ParseMalformed
	}
	l3.L3Length = observed.TotalLength
	l3.L3HeaderLength = observed.HeaderLength
	l3.L4Offset = info.IPOffset + uint32(observed.HeaderLength)
	l3.L4Length = observed.TotalLength - uint32(observed.HeaderLength)
	l3.TransportProtocol = observed.Protocol
	if observed.HeaderLength > 20 {
		l3.Flags |= L3FlagIPv4Options
	}
	if observed.Fragment&0x8000 != 0 {
		return l3, L3ParseMalformed
	}
	if observed.Fragment&0x4000 != 0 {
		l3.Flags |= L3FlagIPv4DontFragment
	}
	if observed.Fragment&0x4000 != 0 && observed.Fragment&0x3fff != 0 {
		return l3, L3ParseMalformed
	}
	if observed.Fragment&0x1fff != 0 {
		return l3, L3ParseNonInitialFragment
	}
	if observed.Fragment&0x2000 != 0 {
		return l3, L3ParseFirstFragment
	}
	if observed.Protocol != L3ProtocolUDP {
		return l3, L3ParseUnsupported
	}
	if observed.UDPLength < 8 || uint32(observed.UDPLength) != l3.L4Length {
		return l3, L3ParseMalformed
	}
	l3.L4HeaderLength = 8
	return l3, L3ParseOK
}

func singleTCDescriptorIPv4UDP(packet []byte) tcPacketDescriptorModel {
	info, observed, genericStatus := genericIPv4UDPModel(packet)
	descriptor := tcPacketDescriptorModel{Info: info, GenericStatus: genericStatus}
	if genericStatus != tcPacketParseOK {
		descriptor.FakeTCPStatus = strictStatusFromGeneric(genericStatus)
		return descriptor
	}
	descriptor.L3, descriptor.FakeTCPStatus = projectStrictIPv4UDP(info, observed)
	return descriptor
}

func fixedIPv4UDPGate(info L3Info) bool {
	return info.Family == L3FamilyIPv4 &&
		info.L3HeaderLength == 20 &&
		info.TransportProtocol == L3ProtocolUDP &&
		info.L4HeaderLength == 8
}

func TestSingleTCDescriptorKeepsGenericAndStrictStatus(t *testing.T) {
	validUDP := testUDP(31001, 443, []byte{1, 2, 3, 4})
	lengthMismatch := testIPv4(5, L3ProtocolUDP, 0, testUDPWithLength(16, 12))
	truncatedDeclaredIP := testIPv4(5, L3ProtocolUDP, 0, validUDP)
	binary.BigEndian.PutUint16(truncatedDeclaredIP[2:4], uint16(len(truncatedDeclaredIP)+4))
	tests := []struct {
		name        string
		packet      []byte
		wantGeneric tcPacketParseResult
		wantStrict  L3ParseStatus
		wantGate    bool
	}{
		{name: "fixed-ipv4-udp", packet: testIPv4(5, L3ProtocolUDP, 0, validUDP), wantGeneric: tcPacketParseOK, wantStrict: L3ParseOK, wantGate: true},
		{name: "ipv4-options", packet: testIPv4(6, L3ProtocolUDP, 0, validUDP), wantGeneric: tcPacketParseOK, wantStrict: L3ParseOK},
		{name: "reserved-fragment-bit", packet: testIPv4(5, L3ProtocolUDP, 0x8000, validUDP), wantGeneric: tcPacketParseOK, wantStrict: L3ParseMalformed},
		{name: "udp-ip-length-mismatch", packet: lengthMismatch, wantGeneric: tcPacketParseOK, wantStrict: L3ParseMalformed},
		{name: "declared-ip-truncated", packet: truncatedDeclaredIP, wantGeneric: tcPacketParseOK, wantStrict: L3ParseTruncated},
		{name: "first-fragment", packet: testIPv4(5, L3ProtocolUDP, 0x2000, validUDP), wantGeneric: tcPacketParseIPv4FirstFragment, wantStrict: L3ParseFirstFragment},
		{name: "noninitial-fragment", packet: testIPv4(5, L3ProtocolUDP, 3, make([]byte, 8)), wantGeneric: tcPacketParseIPv4NonInitialFragment, wantStrict: L3ParseNonInitialFragment},
		{name: "short-udp-payload", packet: testIPv4(5, L3ProtocolUDP, 0, testUDP(1, 2, []byte{1, 2, 3})), wantGeneric: tcPacketParseShort, wantStrict: L3ParseTruncated},
		{name: "tcp-is-not-udp", packet: testIPv4(5, L3ProtocolTCP, 0, testTCP(5, nil)), wantGeneric: tcPacketParseNotUDP, wantStrict: L3ParseUnsupported},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := singleTCDescriptorIPv4UDP(test.packet)
			if got.GenericStatus != test.wantGeneric || got.FakeTCPStatus != test.wantStrict {
				t.Fatalf("descriptor statuses generic=%d strict=%d, want %d/%d; descriptor=%#v", got.GenericStatus, got.FakeTCPStatus, test.wantGeneric, test.wantStrict, got)
			}
			if gate := got.FakeTCPStatus == L3ParseOK && fixedIPv4UDPGate(got.L3); gate != test.wantGate {
				t.Fatalf("fixed gate=%v, want %v; descriptor=%#v", gate, test.wantGate, got)
			}
		})
	}
}

type tcRuleTransport uint8

const (
	tcRuleUDP tcRuleTransport = iota
	tcRuleICMP
	tcRuleFakeTCP
)

type tcEgressDecision uint8

const (
	tcDecisionPass tcEgressDecision = iota
	tcDecisionRewrite
	tcDecisionDrop
)

func decideTCDescriptor(descriptor tcPacketDescriptorModel, matched bool, transport tcRuleTransport) tcEgressDecision {
	if descriptor.GenericStatus != tcPacketParseOK || !matched {
		return tcDecisionPass
	}
	if transport == tcRuleFakeTCP &&
		(descriptor.FakeTCPStatus != L3ParseOK || !fixedIPv4UDPGate(descriptor.L3)) {
		return tcDecisionDrop
	}
	return tcDecisionRewrite
}

func TestStrictFailureIsScopedToMatchedFakeTCPRule(t *testing.T) {
	validUDP := testUDP(31001, 443, []byte{1, 2, 3, 4})
	lengthMismatch := testIPv4(5, L3ProtocolUDP, 0, testUDPWithLength(16, 12))
	truncatedDeclaredIP := testIPv4(5, L3ProtocolUDP, 0, validUDP)
	binary.BigEndian.PutUint16(truncatedDeclaredIP[2:4], uint16(len(truncatedDeclaredIP)+4))
	fixtures := map[string][]byte{
		"reserved-fragment":      testIPv4(5, L3ProtocolUDP, 0x8000, validUDP),
		"udp-ip-length-mismatch": lengthMismatch,
		"declared-ip-truncated":  truncatedDeclaredIP,
	}
	for name, packet := range fixtures {
		t.Run(name, func(t *testing.T) {
			descriptor := singleTCDescriptorIPv4UDP(packet)
			if descriptor.GenericStatus != tcPacketParseOK || descriptor.FakeTCPStatus == L3ParseOK {
				t.Fatalf("fixture must be generic-OK and strict-rejected: %#v", descriptor)
			}
			cases := []struct {
				name      string
				matched   bool
				transport tcRuleTransport
				want      tcEgressDecision
			}{
				{name: "miss-pass", matched: false, transport: tcRuleFakeTCP, want: tcDecisionPass},
				{name: "udp-rule", matched: true, transport: tcRuleUDP, want: tcDecisionRewrite},
				{name: "icmp-rule", matched: true, transport: tcRuleICMP, want: tcDecisionRewrite},
				{name: "faketcp-rule", matched: true, transport: tcRuleFakeTCP, want: tcDecisionDrop},
			}
			for _, test := range cases {
				t.Run(test.name, func(t *testing.T) {
					if got := decideTCDescriptor(descriptor, test.matched, test.transport); got != test.want {
						t.Fatalf("decision=%d, want=%d", got, test.want)
					}
				})
			}
		})
	}
}

const (
	tcXORChecksumNone uint8 = iota
	tcXORChecksumRecompute
)

type tcXORAdmissionModel struct {
	NetworkOffset   uint32
	TransportOffset uint32
	PayloadOffset   uint32
	PayloadLength   uint32
	IPTotalLength   uint32
	WireLength      uint32
	SKBLength       uint32
	SourcePort      uint16
	DestinationPort uint16
	CipherID        uint32
	ChecksumMode    uint8
}

func fixedXORAdmissionModel(packet []byte, checksumMode uint8) tcXORAdmissionModel {
	return tcXORAdmissionModel{
		NetworkOffset:   0,
		TransportOffset: 20,
		PayloadOffset:   28,
		PayloadLength:   uint32(len(packet) - 28),
		IPTotalLength:   uint32(len(packet)),
		WireLength:      uint32(len(packet) - 20),
		SKBLength:       uint32(len(packet)),
		SourcePort:      binary.BigEndian.Uint16(packet[20:22]),
		DestinationPort: binary.BigEndian.Uint16(packet[22:24]),
		CipherID:        1,
		ChecksumMode:    checksumMode,
	}
}

func currentXORAdmissionCoherent(packet []byte, admission tcXORAdmissionModel) bool {
	packetLength := uint32(len(packet))
	if admission.NetworkOffset > packetLength ||
		admission.TransportOffset < admission.NetworkOffset ||
		admission.PayloadOffset < admission.TransportOffset ||
		admission.TransportOffset-admission.NetworkOffset != 20 ||
		admission.PayloadOffset-admission.TransportOffset != 8 ||
		admission.WireLength < 8 || admission.WireLength-8 != admission.PayloadLength ||
		admission.IPTotalLength < 20 || admission.IPTotalLength-20 != admission.WireLength ||
		admission.SKBLength != packetLength ||
		admission.IPTotalLength != packetLength-admission.NetworkOffset ||
		admission.CipherID == 0 || admission.ChecksumMode > tcXORChecksumRecompute ||
		admission.NetworkOffset > packetLength-20 ||
		admission.TransportOffset > packetLength-8 {
		return false
	}
	ip := packet[admission.NetworkOffset : admission.NetworkOffset+20]
	udp := packet[admission.TransportOffset : admission.TransportOffset+8]
	fragment := binary.BigEndian.Uint16(ip[6:8])
	return ip[0]>>4 == 4 && ip[0]&0x0f == 5 && ip[9] == L3ProtocolUDP &&
		fragment&0xbfff == 0 &&
		uint32(binary.BigEndian.Uint16(ip[2:4])) == admission.IPTotalLength &&
		uint32(binary.BigEndian.Uint16(udp[4:6])) == admission.WireLength &&
		binary.BigEndian.Uint16(udp[0:2]) == admission.SourcePort &&
		binary.BigEndian.Uint16(udp[2:4]) == admission.DestinationPort &&
		(binary.BigEndian.Uint16(udp[6:8]) == 0) == (admission.ChecksumMode == tcXORChecksumNone)
}

func TestXORContinuationRejectsCurrentHeaderBitFlips(t *testing.T) {
	packet := testIPv4(5, L3ProtocolUDP, 0, testUDP(31001, 443, []byte{1, 2, 3, 4}))
	admission := fixedXORAdmissionModel(packet, tcXORChecksumNone)
	if !currentXORAdmissionCoherent(packet, admission) {
		t.Fatal("valid fixed IPv4/UDP continuation rejected")
	}
	dfPacket := append([]byte(nil), packet...)
	binary.BigEndian.PutUint16(dfPacket[6:8], 0x4000)
	if !currentXORAdmissionCoherent(dfPacket, admission) {
		t.Fatal("DF-only admitted shape must remain coherent")
	}
	recomputed := append([]byte(nil), packet...)
	binary.BigEndian.PutUint16(recomputed[26:28], 1)
	recomputedAdmission := fixedXORAdmissionModel(recomputed, tcXORChecksumRecompute)
	if !currentXORAdmissionCoherent(recomputed, recomputedAdmission) {
		t.Fatal("non-zero recomputed checksum mode rejected")
	}

	mutations := []struct {
		name   string
		mutate func([]byte, *tcXORAdmissionModel)
	}{
		{name: "version", mutate: func(p []byte, _ *tcXORAdmissionModel) { p[0] ^= 0x10 }},
		{name: "ihl", mutate: func(p []byte, _ *tcXORAdmissionModel) { p[0] ^= 0x01 }},
		{name: "protocol", mutate: func(p []byte, _ *tcXORAdmissionModel) { p[9] ^= 0x01 }},
		{name: "reserved-fragment", mutate: func(p []byte, _ *tcXORAdmissionModel) { p[6] ^= 0x80 }},
		{name: "more-fragments", mutate: func(p []byte, _ *tcXORAdmissionModel) { p[6] ^= 0x20 }},
		{name: "fragment-offset", mutate: func(p []byte, _ *tcXORAdmissionModel) { p[7] ^= 0x01 }},
		{name: "ip-total-length", mutate: func(p []byte, _ *tcXORAdmissionModel) { p[3] ^= 0x01 }},
		{name: "udp-length", mutate: func(p []byte, _ *tcXORAdmissionModel) { p[25] ^= 0x01 }},
		{name: "source-port", mutate: func(p []byte, _ *tcXORAdmissionModel) { p[21] ^= 0x01 }},
		{name: "destination-port", mutate: func(p []byte, _ *tcXORAdmissionModel) { p[23] ^= 0x01 }},
		{name: "checksum-zero-mode", mutate: func(p []byte, _ *tcXORAdmissionModel) { p[27] ^= 0x01 }},
		{name: "admission-checksum-mode", mutate: func(_ []byte, a *tcXORAdmissionModel) { a.ChecksumMode ^= 0x01 }},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			mutated := append([]byte(nil), packet...)
			mutatedAdmission := admission
			test.mutate(mutated, &mutatedAdmission)
			if currentXORAdmissionCoherent(mutated, mutatedAdmission) {
				t.Fatal("bit-flipped continuation remained coherent")
			}
		})
	}
}

func legacyTwoParserModel(packet []byte) (L3Info, tcUDPProjection, tcPacketParseResult) {
	projection, _, result := genericIPv4UDPModel(packet)
	if result != tcPacketParseOK {
		return L3Info{}, projection, result
	}
	l3, status := ParseL3(packet)
	if status != L3ParseOK || !fixedIPv4UDPGate(l3) {
		return l3, projection, tcPacketParseShort
	}
	return l3, projection, result
}

func singleDescriptorBenchmarkModel(packet []byte) (L3Info, tcUDPProjection, tcPacketParseResult) {
	descriptor := singleTCDescriptorIPv4UDP(packet)
	if descriptor.FakeTCPStatus != L3ParseOK || !fixedIPv4UDPGate(descriptor.L3) {
		return descriptor.L3, descriptor.Info, tcPacketParseShort
	}
	return descriptor.L3, descriptor.Info, descriptor.GenericStatus
}

var (
	benchmarkSingleL3         L3Info
	benchmarkSingleProjection tcUDPProjection
	benchmarkSingleResult     tcPacketParseResult
)

func BenchmarkTCFakeTCPSingleAuthoritativeParseModel(b *testing.B) {
	packet := testIPv4(5, L3ProtocolUDP, 0, testUDP(31001, 443, make([]byte, 148)))
	benchmarks := []struct {
		name   string
		parses float64
		parse  func([]byte) (L3Info, tcUDPProjection, tcPacketParseResult)
	}{
		{name: "legacy-generic-plus-shared", parses: 2, parse: legacyTwoParserModel},
		{name: "single-authoritative-descriptor", parses: 1, parse: singleDescriptorBenchmarkModel},
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
