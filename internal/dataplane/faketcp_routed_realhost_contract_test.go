package dataplane

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
)

const (
	fakeTCPRoutedLocalIPv4Env  = "WG_MIX_FAKETCP_ROUTED_LOCAL_IPV4"
	fakeTCPRoutedRemoteIPv4Env = "WG_MIX_FAKETCP_ROUTED_REMOTE_IPV4"
	fakeTCPRoutedPrefixBitsEnv = "WG_MIX_FAKETCP_ROUTED_PREFIX_BITS"
	fakeTCPRoutedRouteMTUEnv   = "WG_MIX_FAKETCP_ROUTED_ROUTE_MTU"

	fakeTCPRoutedLocalIPv4       = "198.18.82.1"
	fakeTCPRoutedRemoteIPv4      = "198.18.82.2"
	fakeTCPRoutedPrefixBits      = 32
	fakeTCPRoutedRouteMTU        = 1500
	fakeTCPRoutedSourcePort      = uint16(31101)
	fakeTCPRoutedDestinationPort = uint16(31102)
	fakeTCPRoutedSegmentBytes    = 64
	fakeTCPRoutedGSOSegments     = 3
	fakeTCPRoutedRotationBytes   = 12
)

type fakeTCPRoutedRealHostContract struct {
	localIPv4  netip.Addr
	remoteIPv4 netip.Addr
	prefixBits int
	routeMTU   int
}

func fakeTCPRoutedWireImage(
	original []byte,
	mixedType uint32,
	key []byte,
	keyMask uint32,
	maxBytes int,
) ([]byte, error) {
	if len(original) < fakeTCPRoutedRotationBytes {
		return nil, fmt.Errorf("FakeTCP routed segment is too short: %d", len(original))
	}
	if binary.LittleEndian.Uint32(original[:4]) != 4 {
		return nil, fmt.Errorf("FakeTCP routed segment typeword is not data")
	}
	if len(key) == 0 || keyMask >= uint32(len(key)) || maxBytes <= 0 {
		return nil, fmt.Errorf("FakeTCP routed XOR contract is invalid")
	}

	encrypted := append([]byte(nil), original...)
	binary.LittleEndian.PutUint32(encrypted[:4], mixedType)
	target := min(len(encrypted), maxBytes)
	for offset := range target {
		encrypted[offset] ^= key[uint32(offset)&keyMask]
	}
	wire := make([]byte, 0, len(encrypted))
	wire = append(wire, encrypted[fakeTCPRoutedRotationBytes:]...)
	wire = append(wire, encrypted[:fakeTCPRoutedRotationBytes]...)
	return wire, nil
}

func parseFakeTCPRoutedRealHostContract(
	lookup fakeTCPRealHostEnvLookup,
) (fakeTCPRoutedRealHostContract, error) {
	if lookup == nil {
		return fakeTCPRoutedRealHostContract{}, fmt.Errorf(
			"parse FakeTCP routed real-host contract: environment lookup is nil",
		)
	}
	require := func(name string) (string, error) {
		value, ok := lookup(name)
		if !ok || value == "" {
			return "", fmt.Errorf("%s is required", name)
		}
		if strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\x00") {
			return "", fmt.Errorf("%s contains whitespace or control characters", name)
		}
		return value, nil
	}
	requireExact := func(name, expected string) error {
		value, err := require(name)
		if err != nil {
			return err
		}
		if value != expected {
			return fmt.Errorf("%s must be exactly %s", name, expected)
		}
		return nil
	}
	if err := requireExact(fakeTCPRoutedLocalIPv4Env, fakeTCPRoutedLocalIPv4); err != nil {
		return fakeTCPRoutedRealHostContract{}, err
	}
	if err := requireExact(fakeTCPRoutedRemoteIPv4Env, fakeTCPRoutedRemoteIPv4); err != nil {
		return fakeTCPRoutedRealHostContract{}, err
	}
	if err := requireExact(
		fakeTCPRoutedPrefixBitsEnv,
		strconv.Itoa(fakeTCPRoutedPrefixBits),
	); err != nil {
		return fakeTCPRoutedRealHostContract{}, err
	}
	if err := requireExact(
		fakeTCPRoutedRouteMTUEnv,
		strconv.Itoa(fakeTCPRoutedRouteMTU),
	); err != nil {
		return fakeTCPRoutedRealHostContract{}, err
	}

	local := netip.MustParseAddr(fakeTCPRoutedLocalIPv4)
	remote := netip.MustParseAddr(fakeTCPRoutedRemoteIPv4)
	if !local.Is4() || !remote.Is4() || local == remote {
		return fakeTCPRoutedRealHostContract{}, fmt.Errorf(
			"invalid compiled FakeTCP routed IPv4 contract",
		)
	}
	return fakeTCPRoutedRealHostContract{
		localIPv4: local, remoteIPv4: remote,
		prefixBits: fakeTCPRoutedPrefixBits, routeMTU: fakeTCPRoutedRouteMTU,
	}, nil
}

func TestParseFakeTCPRoutedRealHostContract(t *testing.T) {
	values := validFakeTCPRoutedRealHostEnvironment()
	contract, err := parseFakeTCPRoutedRealHostContract(mapFakeTCPRealHostEnvironment(values))
	if err != nil {
		t.Fatal(err)
	}
	if contract.localIPv4.String() != fakeTCPRoutedLocalIPv4 ||
		contract.remoteIPv4.String() != fakeTCPRoutedRemoteIPv4 ||
		contract.prefixBits != fakeTCPRoutedPrefixBits ||
		contract.routeMTU != fakeTCPRoutedRouteMTU {
		t.Fatalf("parsed routed contract = %#v", contract)
	}

	for _, test := range []struct {
		name   string
		mutate func(map[string]string)
		match  string
	}{
		{
			name: "missing local",
			mutate: func(values map[string]string) {
				delete(values, fakeTCPRoutedLocalIPv4Env)
			},
			match: "is required",
		},
		{
			name: "different local",
			mutate: func(values map[string]string) {
				values[fakeTCPRoutedLocalIPv4Env] = "198.18.82.9"
			},
			match: "must be exactly",
		},
		{
			name: "different remote",
			mutate: func(values map[string]string) {
				values[fakeTCPRoutedRemoteIPv4Env] = "198.18.82.10"
			},
			match: "must be exactly",
		},
		{
			name: "noncanonical prefix",
			mutate: func(values map[string]string) {
				values[fakeTCPRoutedPrefixBitsEnv] = "032"
			},
			match: "must be exactly",
		},
		{
			name: "different route MTU",
			mutate: func(values map[string]string) {
				values[fakeTCPRoutedRouteMTUEnv] = "1492"
			},
			match: "must be exactly",
		},
		{
			name: "newline",
			mutate: func(values map[string]string) {
				values[fakeTCPRoutedRouteMTUEnv] = "1500\n1492"
			},
			match: "whitespace or control characters",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := validFakeTCPRoutedRealHostEnvironment()
			test.mutate(candidate)
			contract, err := parseFakeTCPRoutedRealHostContract(
				mapFakeTCPRealHostEnvironment(candidate),
			)
			if err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("contract=%#v error=%v, want error containing %q", contract, err, test.match)
			}
		})
	}

	if _, err := parseFakeTCPRoutedRealHostContract(nil); err == nil {
		t.Fatal("nil environment lookup was accepted")
	}
}

func TestFakeTCPRoutedWireImageBindsTypewordXORAndRotation(t *testing.T) {
	original := make([]byte, fakeTCPRoutedSegmentBytes)
	binary.LittleEndian.PutUint32(original[:4], 4)
	for offset := 4; offset < len(original); offset++ {
		original[offset] = byte(offset*29 + 7)
	}
	key := make([]byte, 256)
	for offset := range key {
		key[offset] = byte(offset*17 + 5)
	}

	wire, err := fakeTCPRoutedWireImage(original, 0x13dff06b, key, 255, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) != len(original) || bytes.Equal(wire, original) {
		t.Fatalf("FakeTCP routed wire image length/content=%d/%x", len(wire), wire)
	}
	encrypted := append(append([]byte(nil), wire[len(wire)-fakeTCPRoutedRotationBytes:]...),
		wire[:len(wire)-fakeTCPRoutedRotationBytes]...)
	for offset := range encrypted {
		encrypted[offset] ^= key[offset&255]
	}
	if binary.LittleEndian.Uint32(encrypted[:4]) != 0x13dff06b {
		t.Fatalf("FakeTCP routed mixed typeword=%#x", binary.LittleEndian.Uint32(encrypted[:4]))
	}
	binary.LittleEndian.PutUint32(encrypted[:4], 4)
	if !bytes.Equal(encrypted, original) {
		t.Fatal("FakeTCP routed typeword/XOR/rotation oracle did not recover the source segment")
	}

	for _, test := range []struct {
		name     string
		original []byte
		key      []byte
		mask     uint32
		maxBytes int
	}{
		{name: "short", original: original[:fakeTCPRoutedRotationBytes-1], key: key, mask: 255, maxBytes: 2048},
		{name: "non-data", original: append([]byte(nil), original...), key: key, mask: 255, maxBytes: 2048},
		{name: "empty-key", original: original, key: nil, mask: 0, maxBytes: 2048},
		{name: "mask-outside-key", original: original, key: key[:16], mask: 255, maxBytes: 2048},
		{name: "zero-max", original: original, key: key, mask: 255, maxBytes: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.name == "non-data" {
				binary.LittleEndian.PutUint32(test.original[:4], 3)
			}
			if _, err := fakeTCPRoutedWireImage(
				test.original, 0x13dff06b, test.key, test.mask, test.maxBytes,
			); err == nil {
				t.Fatal("invalid FakeTCP routed wire-image input was accepted")
			}
		})
	}
}

func validFakeTCPRoutedRealHostEnvironment() map[string]string {
	return map[string]string{
		fakeTCPRoutedLocalIPv4Env:  fakeTCPRoutedLocalIPv4,
		fakeTCPRoutedRemoteIPv4Env: fakeTCPRoutedRemoteIPv4,
		fakeTCPRoutedPrefixBitsEnv: strconv.Itoa(fakeTCPRoutedPrefixBits),
		fakeTCPRoutedRouteMTUEnv:   strconv.Itoa(fakeTCPRoutedRouteMTU),
	}
}

func TestFakeTCPRoutedRealHostLinuxStaticContract(t *testing.T) {
	contents, err := os.ReadFile("faketcp_routed_realhost_linux_test.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(contents)
	for _, required := range []string{
		"func TestFakeTCPRealHostRoutedIPHdrInclNone(t *testing.T)",
		"func TestFakeTCPRealHostRoutedUDPSocketPartial(t *testing.T)",
		"func TestFakeTCPRealHostRoutedUDPSegmentGSO(t *testing.T)",
		"validateFakeTCPRoutedTopology(t, prepared.contract, routed)",
		"installFakeTCPRoutedSession(t, handles, runtime.Generation()",
		"unix.BindToDevice(fd, device)",
		"unix.IP_HDRINCL",
		"unix.IP_MTU_DISCOVER",
		"unix.IP_PMTUDISC_DO",
		"unix.UDP_SEGMENT",
		"faketcp_mtu_audit_map",
		"fakeTCPRoutedMTUAuditStatCount",
		"fakeTCPRealHostStatChecksumNoneAccepted",
		"fakeTCPRealHostStatChecksumPartialReset",
		"fakeTCPRoutedCoreStatGSORewriteOK",
		"wireImages := fakeTCPRoutedExpectedWireSegments(",
		"rule.SourcePort != fakeTCPRoutedSourcePort",
		"rule.ProfileID != profile.ID || rule.CipherID != cipher.ID",
		"payload[offset:offset+fakeTCPRoutedSegmentBytes]",
		"bytes.Equal(segment.payload, wantPayload)",
		"internetChecksum",
		"assertFakeTCPRealHostKernelEmpty(t, prepared.contract)",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("FakeTCP routed real-host Linux source is missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"os.Remove(",
		"os.RemoveAll(",
		"exec.Command(",
		"netlink.LinkAdd(",
		"netlink.LinkDel(",
		"netlink.AddrAdd(",
		"netlink.AddrDel(",
		"netlink.RouteAdd(",
		"netlink.RouteDel(",
		"netlink.NeighAdd(",
		"netlink.NeighDel(",
		"t.Parallel()",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("FakeTCP routed real-host Linux source contains forbidden operation %q", forbidden)
		}
	}
}
