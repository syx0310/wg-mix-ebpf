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

// ClassifyManagedIngressFrame extracts only the bounded Ethernet/VLAN prefix,
// then delegates all IPv4/IPv6 work to ParseL3. The parser can classify valid
// IPv4 options and IPv6 chains; fragments and malformed/unsupported shapes do
// not authorize a port read and therefore fail closed on a managed interface.
func ClassifyManagedIngressFrame(frame []byte, policy ManagedIngressPolicy) IngressDisposition {
	const (
		ethernetHeaderLength = 14
		vlanHeaderLength     = 4
		etherTypeIPv4        = 0x0800
		etherTypeIPv6        = 0x86dd
		etherTypeVLAN        = 0x8100
		etherTypeQinQ        = 0x88a8
	)
	if len(frame) < ethernetHeaderLength {
		return managedFakeTCPDisposition(nil, L3Info{}, L3ParseTruncated, policy)
	}
	offset := ethernetHeaderLength
	etherType := binary.BigEndian.Uint16(frame[12:14])
	for depth := 0; depth < 2 && (etherType == etherTypeVLAN || etherType == etherTypeQinQ); depth++ {
		if len(frame) < offset+vlanHeaderLength {
			return managedFakeTCPDisposition(nil, L3Info{}, L3ParseTruncated, policy)
		}
		etherType = binary.BigEndian.Uint16(frame[offset+2 : offset+4])
		offset += vlanHeaderLength
	}
	if etherType == etherTypeVLAN || etherType == etherTypeQinQ {
		return managedFakeTCPDisposition(nil, L3Info{}, L3ParseUnsupported, policy)
	}
	if etherType != etherTypeIPv4 && etherType != etherTypeIPv6 {
		return IngressPass
	}
	l3 := frame[offset:]
	info, status := ParseL3(l3)
	return managedFakeTCPDisposition(l3, info, status, policy)
}

// managedFakeTCPDisposition is the sole status-to-policy mapper. The parser
// may describe more packet shapes than the current IPv4/fixed-header FakeTCP
// transform supports; a managed match only decodes after the narrower mapper
// below succeeds.
func managedFakeTCPDisposition(l3 []byte, info L3Info, status L3ParseStatus, policy ManagedIngressPolicy) IngressDisposition {
	if status == L3ParseSafeBypass {
		return IngressPass
	}
	if status != L3ParseOK {
		if policy.InterfaceManaged {
			return IngressDrop
		}
		return IngressPass
	}
	l4Offset := int(info.L4Offset)
	if l4Offset > len(l3)-4 {
		if policy.InterfaceManaged {
			return IngressDrop
		}
		return IngressPass
	}
	if !managedIngressPort(policy, binary.BigEndian.Uint16(l3[l4Offset+2:l4Offset+4])) {
		return IngressPass
	}
	if managedFakeTCPTransformStatus(info, info.TransportProtocol) != L3ParseOK {
		return IngressDrop
	}
	if info.TransportProtocol == L3ProtocolUDP {
		return IngressDrop
	}
	return IngressDecodeIPv4
}

func managedFakeTCPTransformStatus(info L3Info, transport uint8) L3ParseStatus {
	if info.Family != L3FamilyIPv4 || info.L3HeaderLength != 20 ||
		info.TransportProtocol != transport {
		return L3ParseUnsupported
	}
	if transport == L3ProtocolUDP && info.L4HeaderLength == 8 ||
		transport == L3ProtocolTCP && info.L4HeaderLength == 20 {
		return L3ParseOK
	}
	return L3ParseUnsupported
}

func managedIngressPort(policy ManagedIngressPolicy, port uint16) bool {
	_, ok := policy.Ports[port]
	return ok
}
