package faketcp

import "encoding/binary"

// L3ParseStatus mirrors the bounded BPF parser contract. Only L3ParseOK
// authorizes transport-port access or mutation. SafeBypass proves a
// non-TCP/UDP protocol; every error result fails closed.
type L3ParseStatus uint8

const (
	L3ParseOK L3ParseStatus = iota
	L3ParseSafeBypass
	L3ParseTruncated
	L3ParseMalformed
	L3ParseUnsupported
	L3ParseFirstFragment
	L3ParseNonInitialFragment
	L3ParseExtensionTooDeep
)

const (
	L3FamilyIPv4 = 4
	L3FamilyIPv6 = 6

	L3ProtocolICMP   = 1
	L3ProtocolTCP    = 6
	L3ProtocolUDP    = 17
	L3ProtocolIPv6   = 41
	L3ProtocolESP    = 50
	L3ProtocolAH     = 51
	L3ProtocolICMPv6 = 58
	L3ProtocolNone   = 59

	l3IPv6HopByHop    = 0
	l3IPv6Routing     = 43
	l3IPv6Fragment    = 44
	l3IPv6Destination = 60

	L3MaxIPv6ExtensionHeaders = 8
	L3MaxIPv6ExtensionBytes   = 512
)

const (
	L3FlagIPv4Options uint8 = 1 << iota
	L3FlagIPv4DontFragment
	L3FlagMoreFragments
	L3FlagIPv6Extensions
	L3FlagFragment
)

// L3Info contains only offsets and lengths proven against the declared L3
// length and the supplied frame. Offsets are relative to the beginning of the
// supplied L3 packet. Transport fields are authoritative only for L3ParseOK.
type L3Info struct {
	L3Offset            uint32
	L3Length            uint32
	L4Offset            uint32
	L4Length            uint32
	L3HeaderLength      uint16
	L4HeaderLength      uint16
	FragmentOffsetBytes uint16
	Family              uint8
	TransportProtocol   uint8
	ExtensionCount      uint8
	Flags               uint8
}

// ParseL3 models the verifier-bounded FakeTCP parser. It deliberately does not
// scan for an inner IP header: an unknown protocol is unsupported rather than
// being guessed as UDP or TCP.
func ParseL3(packet []byte) (L3Info, L3ParseStatus) {
	if len(packet) == 0 {
		return L3Info{}, L3ParseTruncated
	}
	switch packet[0] >> 4 {
	case L3FamilyIPv4:
		return parseIPv4L3(packet)
	case L3FamilyIPv6:
		return parseIPv6L3(packet)
	default:
		return L3Info{}, L3ParseMalformed
	}
}

func parseIPv4L3(packet []byte) (L3Info, L3ParseStatus) {
	info := L3Info{Family: L3FamilyIPv4}
	if len(packet) < 20 {
		return info, L3ParseTruncated
	}
	headerLength := int(packet[0]&0x0f) * 4
	if headerLength < 20 {
		return info, L3ParseMalformed
	}
	if headerLength > len(packet) {
		return info, L3ParseTruncated
	}
	totalLength := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLength < headerLength {
		return info, L3ParseMalformed
	}
	if totalLength > len(packet) {
		return info, L3ParseTruncated
	}

	info.L3Length = uint32(totalLength)
	info.L3HeaderLength = uint16(headerLength)
	info.L4Offset = uint32(headerLength)
	info.L4Length = uint32(totalLength - headerLength)
	info.TransportProtocol = packet[9]
	if headerLength > 20 {
		info.Flags |= L3FlagIPv4Options
	}

	fragment := binary.BigEndian.Uint16(packet[6:8])
	if fragment&0x8000 != 0 {
		return info, L3ParseMalformed
	}
	if fragment&0x4000 != 0 {
		info.Flags |= L3FlagIPv4DontFragment
	}
	if fragment&0x4000 != 0 && fragment&0x3fff != 0 {
		return info, L3ParseMalformed
	}
	if fragment&0x2000 != 0 {
		info.Flags |= L3FlagMoreFragments | L3FlagFragment
	}
	fragmentOffset := fragment & 0x1fff
	info.FragmentOffsetBytes = fragmentOffset * 8
	if fragmentOffset != 0 {
		info.Flags |= L3FlagFragment
		return info, L3ParseNonInitialFragment
	}
	if fragment&0x2000 != 0 {
		return info, L3ParseFirstFragment
	}

	if info.TransportProtocol == L3ProtocolICMP {
		return info, L3ParseSafeBypass
	}
	if info.TransportProtocol != L3ProtocolTCP && info.TransportProtocol != L3ProtocolUDP {
		return info, L3ParseUnsupported
	}
	return validateL4(packet[:totalLength], &info)
}

func parseIPv6L3(packet []byte) (L3Info, L3ParseStatus) {
	info := L3Info{Family: L3FamilyIPv6}
	if len(packet) < 40 {
		return info, L3ParseTruncated
	}
	payloadLength := int(binary.BigEndian.Uint16(packet[4:6]))
	totalLength := 40 + payloadLength
	if totalLength > len(packet) {
		return info, L3ParseTruncated
	}
	info.L3Length = uint32(totalLength)
	info.L3HeaderLength = 40

	nextHeader := packet[6]
	if payloadLength == 0 {
		if nextHeader == L3ProtocolNone {
			info.TransportProtocol = nextHeader
			return info, L3ParseSafeBypass
		}
		// IPv6 jumbograms require option parsing and 32-bit transport length
		// handling which FakeTCP deliberately does not implement.
		return info, L3ParseUnsupported
	}

	offset := 40
	extensionBytes := 0
	for depth := 0; depth <= L3MaxIPv6ExtensionHeaders; depth++ {
		switch nextHeader {
		case L3ProtocolTCP, L3ProtocolUDP:
			info.L4Offset = uint32(offset)
			info.L4Length = uint32(totalLength - offset)
			info.TransportProtocol = nextHeader
			return validateL4(packet[:totalLength], &info)
		case L3ProtocolICMPv6, L3ProtocolNone:
			info.L4Offset = uint32(offset)
			info.L4Length = uint32(totalLength - offset)
			info.TransportProtocol = nextHeader
			return info, L3ParseSafeBypass
		case l3IPv6Fragment:
			if depth == L3MaxIPv6ExtensionHeaders {
				return info, L3ParseExtensionTooDeep
			}
			if totalLength-offset < 8 {
				return info, L3ParseMalformed
			}
			fragment := binary.BigEndian.Uint16(packet[offset+2 : offset+4])
			if packet[offset+1] != 0 || fragment&0x0006 != 0 {
				return info, L3ParseMalformed
			}
			info.Flags |= L3FlagIPv6Extensions | L3FlagFragment
			info.ExtensionCount++
			info.TransportProtocol = packet[offset]
			info.FragmentOffsetBytes = ((fragment & 0xfff8) >> 3) * 8
			if fragment&1 != 0 {
				info.Flags |= L3FlagMoreFragments
			}
			if info.FragmentOffsetBytes != 0 {
				return info, L3ParseNonInitialFragment
			}
			return info, L3ParseFirstFragment
		case l3IPv6HopByHop, l3IPv6Routing, l3IPv6Destination:
			if depth == L3MaxIPv6ExtensionHeaders {
				return info, L3ParseExtensionTooDeep
			}
			if nextHeader == l3IPv6HopByHop && depth != 0 {
				return info, L3ParseMalformed
			}
			if totalLength-offset < 2 {
				return info, L3ParseMalformed
			}
			extensionLength := (int(packet[offset+1]) + 1) * 8
			if extensionLength < 8 || extensionLength > totalLength-offset {
				return info, L3ParseMalformed
			}
			extensionBytes += extensionLength
			if extensionBytes > L3MaxIPv6ExtensionBytes {
				return info, L3ParseExtensionTooDeep
			}
			info.Flags |= L3FlagIPv6Extensions
			info.ExtensionCount++
			nextHeader = packet[offset]
			offset += extensionLength
		case L3ProtocolAH:
			if depth == L3MaxIPv6ExtensionHeaders {
				return info, L3ParseExtensionTooDeep
			}
			if totalLength-offset < 2 {
				return info, L3ParseMalformed
			}
			extensionLength := (int(packet[offset+1]) + 2) * 4
			if extensionLength < 12 || extensionLength > totalLength-offset {
				return info, L3ParseMalformed
			}
			info.Flags |= L3FlagIPv6Extensions
			info.ExtensionCount++
			info.TransportProtocol = nextHeader
			return info, L3ParseUnsupported
		case L3ProtocolESP, L3ProtocolIPv6:
			info.TransportProtocol = nextHeader
			return info, L3ParseUnsupported
		default:
			info.TransportProtocol = nextHeader
			return info, L3ParseUnsupported
		}
	}
	return info, L3ParseExtensionTooDeep
}

func validateL4(packet []byte, info *L3Info) (L3Info, L3ParseStatus) {
	offset := int(info.L4Offset)
	length := int(info.L4Length)
	if offset < 0 || length < 0 || offset > len(packet) || length > len(packet)-offset {
		return *info, L3ParseTruncated
	}
	switch info.TransportProtocol {
	case L3ProtocolUDP:
		if length < 8 {
			return *info, L3ParseMalformed
		}
		udpLength := int(binary.BigEndian.Uint16(packet[offset+4 : offset+6]))
		if udpLength < 8 || udpLength != length {
			return *info, L3ParseMalformed
		}
		info.L4HeaderLength = 8
	case L3ProtocolTCP:
		if length < 20 {
			return *info, L3ParseMalformed
		}
		headerLength := int(packet[offset+12]>>4) * 4
		if headerLength < 20 || headerLength > length {
			return *info, L3ParseMalformed
		}
		info.L4HeaderLength = uint16(headerLength)
	default:
		return *info, L3ParseUnsupported
	}
	return *info, L3ParseOK
}
