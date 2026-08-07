package faketcp

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// WireHeaderOverhead is the additional outer-packet size when an 8-byte UDP
// header becomes a 20-byte TCP header. A deployment must lower the MTU used by
// the otherwise-equivalent UDP transport by this amount before activation.
const WireHeaderOverhead = 12

func AdjustTransportMTU(udpTransportMTU int) (int, error) {
	if udpTransportMTU <= WireHeaderOverhead {
		return 0, fmt.Errorf("faketcp base transport MTU %d must exceed %d-byte wire overhead", udpTransportMTU, WireHeaderOverhead)
	}
	return udpTransportMTU - WireHeaderOverhead, nil
}

// RawIPv4BE32 returns the native uint32 whose in-memory bytes are the IPv4
// network-order bytes expected by the BPF __be32 map key. It must not be
// replaced with addr.As4() interpreted as a big-endian numeric value on a
// little-endian host.
func RawIPv4BE32(addr netip.Addr) (uint32, error) {
	if !addr.Is4() {
		return 0, fmt.Errorf("faketcp address %s is not IPv4", addr)
	}
	bytes := addr.As4()
	return binary.NativeEndian.Uint32(bytes[:]), nil
}
