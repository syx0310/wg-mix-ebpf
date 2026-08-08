package faketcp

import "encoding/binary"

// IngressDisposition is the userspace oracle used by packet-level tests for
// the experimental XDP managed-port policy. DecodeIPv4 means the frame is the
// one supported shape that may proceed to FakeTCP decoding; Drop prevents an
// unsupported managed frame from reaching the host TCP stack.
type IngressDisposition uint8

const (
	IngressPass IngressDisposition = iota
	IngressDecodeIPv4
	IngressDrop
)

// ManagedIngressPolicy is an exact projection of one XDP attachment's policy.
// InterfaceManaged covers ambiguous fragments and truncated headers where the
// destination port is unavailable. Ports contains every FakeTCP listener that
// must remain fail-closed on this concrete interface.
type ManagedIngressPolicy struct {
	InterfaceManaged bool
	Ports            map[uint16]struct{}
}

// ClassifyManagedIngressFrame mirrors the bounded parser contract in
// wg_mix_faketcp.h. It intentionally supports only fixed-header IPv4 TCP for
// decoding. IPv6 and option/fragment variants can still be classified by port,
// but a managed match is dropped until the wire decoder supports that shape.
func ClassifyManagedIngressFrame(frame []byte, policy ManagedIngressPolicy) IngressDisposition {
	const (
		ethernetHeaderLength = 14
		vlanHeaderLength     = 4
		etherTypeIPv4        = 0x0800
		etherTypeIPv6        = 0x86dd
		etherTypeVLAN        = 0x8100
		etherTypeQinQ        = 0x88a8
		protocolTCP          = 6
		protocolUDP          = 17
	)

	failClosed := func() IngressDisposition {
		if policy.InterfaceManaged {
			return IngressDrop
		}
		return IngressPass
	}
	if len(frame) < ethernetHeaderLength {
		return failClosed()
	}
	offset := ethernetHeaderLength
	etherType := binary.BigEndian.Uint16(frame[12:14])
	for depth := 0; depth < 2 && (etherType == etherTypeVLAN || etherType == etherTypeQinQ); depth++ {
		if len(frame) < offset+vlanHeaderLength {
			return failClosed()
		}
		etherType = binary.BigEndian.Uint16(frame[offset+2 : offset+4])
		offset += vlanHeaderLength
	}
	if etherType == etherTypeVLAN || etherType == etherTypeQinQ {
		return failClosed()
	}

	switch etherType {
	case etherTypeIPv4:
		if len(frame) < offset+20 || frame[offset]>>4 != 4 {
			return failClosed()
		}
		headerLength := int(frame[offset]&0x0f) * 4
		if headerLength < 20 || len(frame) < offset+headerLength {
			return failClosed()
		}
		protocol := frame[offset+9]
		if protocol != protocolTCP && protocol != protocolUDP {
			if protocol == 1 { // ICMP has no transport port to bypass.
				return IngressPass
			}
			// AH, ESP, IP-in-IP, IPv6 encapsulation and unknown protocols
			// cannot prove the absence of a managed inner destination.
			return failClosed()
		}
		fragmentOffset := binary.BigEndian.Uint16(frame[offset+6 : offset+8])
		if fragmentOffset&0x1fff != 0 {
			return failClosed()
		}
		tcpOffset := offset + headerLength
		if len(frame) < tcpOffset+8 {
			return failClosed()
		}
		destinationPort := binary.BigEndian.Uint16(frame[tcpOffset+2 : tcpOffset+4])
		if !managedIngressPort(policy, destinationPort) {
			return IngressPass
		}
		if protocol == protocolUDP {
			return IngressDrop
		}
		if len(frame) < tcpOffset+20 {
			return IngressDrop
		}
		tcpHeaderLength := int(frame[tcpOffset+12]>>4) * 4
		if fragmentOffset&0x2000 != 0 || headerLength != 20 || tcpHeaderLength != 20 {
			return IngressDrop
		}
		return IngressDecodeIPv4

	case etherTypeIPv6:
		if len(frame) < offset+40 || frame[offset]>>4 != 6 {
			return failClosed()
		}
		nextHeader := frame[offset+6]
		offset += 40
		for depth := 0; depth < 4; depth++ {
			switch nextHeader {
			case protocolTCP, protocolUDP:
				if len(frame) < offset+8 {
					return failClosed()
				}
				port := binary.BigEndian.Uint16(frame[offset+2 : offset+4])
				if managedIngressPort(policy, port) {
					return IngressDrop
				}
				return IngressPass
			case 44: // fragment
				if len(frame) < offset+8 {
					return failClosed()
				}
				if binary.BigEndian.Uint16(frame[offset+2:offset+4])&0xfff8 != 0 {
					return failClosed()
				}
				nextHeader = frame[offset]
				offset += 8
			case 0, 43, 60: // hop-by-hop, routing, destination options
				if len(frame) < offset+2 {
					return failClosed()
				}
				extensionLength := (int(frame[offset+1]) + 1) * 8
				if extensionLength < 8 || len(frame) < offset+extensionLength {
					return failClosed()
				}
				nextHeader = frame[offset]
				offset += extensionLength
			case 58, 59: // ICMPv6, no next header
				return IngressPass
			default:
				return failClosed()
			}
		}
		return failClosed()
	default:
		return IngressPass
	}
}

func managedIngressPort(policy ManagedIngressPolicy, port uint16) bool {
	_, ok := policy.Ports[port]
	return ok
}
