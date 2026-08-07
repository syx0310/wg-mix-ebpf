package faketcp

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

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
