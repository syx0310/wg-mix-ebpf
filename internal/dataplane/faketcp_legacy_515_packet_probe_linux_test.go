//go:build linux

package dataplane

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/syx0310/wg-mix-ebpf/internal/abi"
	"github.com/syx0310/wg-mix-ebpf/internal/faketcp"
	"golang.org/x/sys/unix"
)

const fakeTCPLegacy515PacketProbeObjectEnv = "WG_MIX_FAKETCP_LEGACY_515_PACKET_TEST_OBJECT"

// TestFakeTCPLegacy515XDPIngressDecodeProbe is the small Linux-5.15 regression
// in front of the full WireGuard real-host cell. It verifier-loads the exact
// legacy object, creates only unpinned in-memory maps, installs one established
// session, and test-runs one TCP-shaped data packet through the production XDP
// ingress program. In particular, BPF_PROG_TEST_RUN applies the target
// kernel's bpf_xdp_adjust_meta limit, so an XDP-to-TC handoff that is too large
// for Linux 5.15 fails here before a daemon, interface, TC filter, or WireGuard
// endpoint is created.
//
// Run on the Linux 5.15 target as:
//
//	WG_MIX_FAKETCP_LEGACY_515_PACKET_TEST_OBJECT=/absolute/wg_mix_faketcp_legacy_515.o \
//	  go test ./internal/dataplane -run '^TestFakeTCPLegacy515XDPIngressDecodeProbe$' -v
func TestFakeTCPLegacy515XDPIngressDecodeProbe(t *testing.T) {
	objectPath := os.Getenv(fakeTCPLegacy515PacketProbeObjectEnv)
	if objectPath == "" {
		t.Skipf("set %s to an absolute legacy-5.15 BPF object path", fakeTCPLegacy515PacketProbeObjectEnv)
	}
	if objectPath[0] != '/' {
		t.Fatalf("%s must be an absolute path", fakeTCPLegacy515PacketProbeObjectEnv)
	}

	spec, identity, err := loadFakeTCPLegacy515CollectionSpecFromResolvedPath(objectPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateLegacy515ExtensionManifest(spec); err != nil {
		t.Fatalf("validate legacy-5.15 object %s (%s): %v", identity.Source, identity.SHA256, err)
	}
	if err := removeMemlockLimit(); err != nil {
		t.Fatalf("remove BPF memlock limit: %v", err)
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("load legacy-5.15 object %s (%s): %v", identity.Source, identity.SHA256, err)
	}
	t.Cleanup(collection.Close)

	const (
		generation      = uint64(515)
		profileID       = uint32(7)
		wgID            = uint32(11)
		ifindex         = uint32(1)
		sourcePort      = uint16(31001)
		destinationPort = uint16(31155)
		sequence        = uint32(0x01020304)
		acknowledgement = uint32(0x11223344)
		mixedType       = uint32(0x13dff06b)
	)
	incarnation := faketcp.RuntimeIncarnation{1}
	openFakeTCPPacketProbeGenerationGate(
		t, collection, generation, incarnation, ifindex, destinationPort,
	)

	localIPv4, err := faketcp.RawIPv4BE32(netip.MustParseAddr("10.0.0.2"))
	if err != nil {
		t.Fatal(err)
	}
	remoteIPv4, err := faketcp.RawIPv4BE32(netip.MustParseAddr("10.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	updates := []struct {
		mapName string
		key     any
		value   any
	}{
		{
			mapName: "underlay_config_map",
			key: abi.UnderlayConfigKey{
				Generation: generation, UnderlayIndex: ifindex,
			},
			value: abi.UnderlayConfigValue{
				Generation: generation, ParserMode: abi.ParserEthernet,
			},
		},
		{
			mapName: "profile_map",
			key:     abi.ProfileKey{Generation: generation, ProfileID: profileID},
			value: abi.ProfileValue{
				Generation:      generation,
				StandardToMixed: [4]uint32{0xa1b2c3d4, 0xb2c3d4e5, 0xc3d4e5f6, mixedType},
				MixedToStandard: [4]uint32{1, 2, 3, 4},
			},
		},
		{
			mapName: "ingress_listener_map",
			key: abi.IngressListenerKey{
				Generation: generation, UnderlayIndex: ifindex,
				DestinationPort: destinationPort, Family: abi.FamilyIPv4,
			},
			value: abi.IngressListenerValue{
				Generation: generation, ProfileID: profileID, WGID: wgID,
				Action: abi.ActionRewrite, TransportMode: abi.TransportFakeTCP,
			},
		},
		{
			mapName: "faketcp_managed_if_map",
			key: abi.FakeTCPManagedIfKey{
				Generation: generation, UnderlayIndex: ifindex,
			},
			value: abi.FakeTCPManagedIfValue{Generation: generation},
		},
		{
			mapName: "faketcp_managed_port_map",
			key: abi.FakeTCPManagedPortKey{
				Generation: generation, UnderlayIndex: ifindex,
				DestinationPort: destinationPort,
			},
			value: abi.FakeTCPManagedPortValue{
				Generation: generation, WGID: wgID, Action: abi.ActionRewrite,
			},
		},
		{
			mapName: "faketcp_session_map",
			key: abi.FakeTCPSessionKey{
				Generation: generation, LocalIPv4: localIPv4, RemoteIPv4: remoteIPv4,
				UnderlayIndex: ifindex, LocalPort: destinationPort,
				RemotePort: sourcePort, WGID: wgID,
			},
			value: abi.FakeTCPSessionValue{
				Generation: generation, TXSequence: acknowledgement, RXSequence: sequence,
				Window: 4096, State: abi.FakeTCPStateEstablished, Revision: 1,
				SessionID: 1, RuntimeIncarnation: [16]byte(incarnation),
			},
		},
	}
	for _, update := range updates {
		m := collection.Maps[update.mapName]
		if m == nil {
			t.Fatalf("legacy-5.15 object has no %s map", update.mapName)
		}
		if err := m.Update(update.key, update.value, ebpf.UpdateAny); err != nil {
			t.Fatalf("populate %s: %v", update.mapName, err)
		}
	}

	payload := make([]byte, 32)
	for index := range payload {
		payload[index] = byte(index*29 + 7)
	}
	binary.LittleEndian.PutUint32(payload[:4], mixedType)
	// FakeTCP moves the first twelve UDP payload bytes to the wire tail.
	wirePayload := append(append([]byte(nil), payload[12:]...), payload[:12]...)
	packet := fakeTCPManagedIngressEthernet(
		net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		unix.ETH_P_IP,
		fakeTCPManagedIngressIPv4TCP(
			t, 5, 5, 0, sourcePort, destinationPort,
			sequence, acknowledgement, wirePayload,
		),
	)
	program := collection.Programs[fakeTCPXDPProgramName]
	if program == nil {
		t.Fatal("legacy-5.15 object has no FakeTCP XDP ingress program")
	}
	before := readFakeTCPPacketProbeStat(t, collection, fakeTCPManagedIngressFakeIngressOK)
	result, output, err := runFakeTCPPacketProbe(
		program, packet, fakeTCPXDPContext{IngressIfindex: ifindex}, len(packet)+64,
	)
	if err != nil {
		t.Fatalf("BPF_PROG_TEST_RUN legacy-5.15 ingress decode: %v", err)
	}
	if result != uint32(2) {
		t.Fatalf("legacy-5.15 ingress action=%d, want XDP_PASS; check the target kernel's XDP metadata limit", result)
	}
	assertFakeTCPLegacy515DecodedPacket(
		t, output, payload, sourcePort, destinationPort,
	)
	after := readFakeTCPPacketProbeStat(t, collection, fakeTCPManagedIngressFakeIngressOK)
	if after != before+1 {
		t.Fatalf("legacy-5.15 ingress-ok delta=%d, want 1", after-before)
	}
}

func assertFakeTCPLegacy515DecodedPacket(
	t *testing.T,
	frame []byte,
	payload []byte,
	sourcePort uint16,
	destinationPort uint16,
) {
	t.Helper()
	const ethernetLength = 14
	if len(frame) != ethernetLength+20+8+len(payload) ||
		binary.BigEndian.Uint16(frame[12:14]) != unix.ETH_P_IP {
		t.Fatalf("decoded legacy-5.15 frame has invalid length/link shape: bytes=%d", len(frame))
	}
	ipv4 := frame[ethernetLength:]
	if ipv4[0] != 0x45 || ipv4[9] != unix.IPPROTO_UDP ||
		int(binary.BigEndian.Uint16(ipv4[2:4])) != len(ipv4) ||
		internetChecksum(ipv4[:20]) != 0 {
		t.Fatalf("decoded legacy-5.15 IPv4 header is invalid: %x", ipv4[:20])
	}
	udp := ipv4[20:]
	if binary.BigEndian.Uint16(udp[0:2]) != sourcePort ||
		binary.BigEndian.Uint16(udp[2:4]) != destinationPort ||
		int(binary.BigEndian.Uint16(udp[4:6])) != len(udp) ||
		!bytes.Equal(udp[8:], payload) {
		t.Fatalf("decoded legacy-5.15 UDP image is invalid: %x", udp)
	}
	if fakeTCPRoutedTransportChecksumResidual(
		netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"),
		unix.IPPROTO_UDP, udp,
	) != 0 {
		t.Fatalf("decoded legacy-5.15 UDP checksum is invalid: %x", udp)
	}
}
