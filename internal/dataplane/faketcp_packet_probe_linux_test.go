//go:build linux

package dataplane

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/syx0310/wg-mix-ebpf/internal/abi"
	"github.com/syx0310/wg-mix-ebpf/internal/faketcp"
	"golang.org/x/sys/unix"
)

const fakeTCPPacketProbeObjectEnv = "WG_MIX_FAKETCP_PACKET_TEST_OBJECT"

// fakeTCPSKBContext mirrors the 192-byte Linux UAPI struct __sk_buff through
// hwtstamp. Keeping gso_segs and gso_size in an explicit context makes the
// BPF_PROG_TEST_RUN cell an executable feature probe instead of a source-text
// assertion. The kernel may reject synthetic GSO context on a release that
// cannot model it; that result is reported as unsupported, never as a pass.
type fakeTCPSKBContext struct {
	Len            uint32
	PacketType     uint32
	Mark           uint32
	QueueMapping   uint32
	Protocol       uint32
	VLANPresent    uint32
	VLANTCI        uint32
	VLANProtocol   uint32
	Priority       uint32
	IngressIfindex uint32
	Ifindex        uint32
	TCIndex        uint32
	CB             [5]uint32
	Hash           uint32
	TCClassID      uint32
	Data           uint32
	DataEnd        uint32
	NAPIID         uint32
	Family         uint32
	RemoteIPv4     uint32
	LocalIPv4      uint32
	RemoteIPv6     [4]uint32
	LocalIPv6      [4]uint32
	RemotePort     uint32
	LocalPort      uint32
	DataMeta       uint32
	FlowKeys       uint64
	Timestamp      uint64
	WireLength     uint32
	GSOSegments    uint32
	Socket         uint64
	GSOSize        uint32
	TimestampType  uint8
	_              [3]byte
	HardwareStamp  uint64
}

func TestFakeTCPSKBContextLayout(t *testing.T) {
	if got, want := binary.Size(fakeTCPSKBContext{}), 192; got != want {
		t.Fatalf("serialized __sk_buff context size=%d, want %d", got, want)
	}
}

// TestFakeTCPBPFPacketProbe verifier-loads the separately built experimental
// object, populates only in-memory maps, and invokes the TC egress program with
// BPF_PROG_TEST_RUN. It never attaches or pins a program. The test-run ABI
// cannot synthesize ip_summed/csum_start/csum_offset, so its default skb covers
// only the CHECKSUM_NONE path used after raw/IP_HDRINCL reinjection has already
// materialized the UDP checksum. A successful cell is never evidence that the
// real-TC CHECKSUM_PARTIAL path works. This probe covers verifier loading,
// CHECKSUM_NONE transformation, GSO rejection and frame boundaries. Run
// explicitly on a Linux test host as:
//
//	WG_MIX_FAKETCP_PACKET_TEST_OBJECT=/absolute/wg_mix_faketcp_experimental.o \
//	  go test ./internal/dataplane -run '^TestFakeTCPBPFPacketProbe$' -v
//
// CHECKSUM_PARTIAL normalization remains a separately reviewed real-TC/NIC
// acceptance requirement.
func TestFakeTCPBPFPacketProbe(t *testing.T) {
	objectPath := os.Getenv(fakeTCPPacketProbeObjectEnv)
	if objectPath == "" {
		t.Skipf("set %s to an absolute experimental BPF object path", fakeTCPPacketProbeObjectEnv)
	}
	if objectPath[0] != '/' {
		t.Fatalf("%s must be an absolute path", fakeTCPPacketProbeObjectEnv)
	}

	spec, identity, err := loadCollectionSpec(objectPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateExperimentalExtensionManifest(spec); err != nil {
		t.Fatalf("validate experimental object %s (%s): %v", identity.Source, identity.SHA256, err)
	}
	if err := probeExperimentalFakeTCPKernelDependency(); err != nil {
		t.Fatalf("probe required FakeTCP checksum kfunc module: %v", err)
	}
	if err := removeMemlockLimit(); err != nil {
		t.Fatalf("remove BPF memlock limit: %v", err)
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("load experimental object %s (%s): %v", identity.Source, identity.SHA256, err)
	}
	defer collection.Close()

	const (
		generation = uint64(91)
		profileID  = uint32(7)
		wgID       = uint32(11)
		ifindex    = uint32(1) // loopback in the dedicated Linux probe host
		sourcePort = uint16(31001)
		remotePort = uint16(443)
	)
	localIPv4, err := faketcp.RawIPv4BE32(netip.MustParseAddr("10.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	remoteIPv4, err := faketcp.RawIPv4BE32(netip.MustParseAddr("10.0.0.2"))
	if err != nil {
		t.Fatal(err)
	}
	program := collection.Programs["wg_mix_egress"]
	if program == nil {
		t.Fatal("experimental object has no wg_mix_egress program")
	}
	populateFakeTCPPacketProbeTailCalls(t, collection, generation)

	const (
		fakeTCPStatBadPacket = uint32(4)
		fakeTCPStatGSOReject = uint32(5)
	)
	for _, xorEnabled := range []bool{false, true} {
		for _, payloadLength := range []int{32, 33, 1459, 1460} {
			name := fmt.Sprintf("checksum-none-materialized-payload-%d", payloadLength)
			if xorEnabled {
				name += "-xor"
			}
			t.Run(name, func(t *testing.T) {
				xorKey := populateFakeTCPPacketProbeMaps(t, collection, generation, profileID, wgID,
					ifindex, sourcePort, remotePort, localIPv4, remoteIPv4, xorEnabled)
				packet, originalPayload := buildFakeTCPProbeUDPPacket(
					t, sourcePort, remotePort, payloadLength,
				)
				context := fakeTCPSKBContext{Ifindex: ifindex}
				result, output, err := runFakeTCPPacketProbe(
					program, packet, context, len(packet)+64,
				)
				if err != nil {
					t.Fatalf("BPF_PROG_TEST_RUN materialized packet: %v", err)
				}
				if result != 0 {
					t.Fatalf("CHECKSUM_NONE packet action=%d, want TC_ACT_OK", result)
				}
				verifyFakeTCPProbeOutput(
					t, output, packet, originalPayload, sourcePort, remotePort, xorKey,
				)
			})
		}
	}

	t.Run("frame-cap-exact-materialized", func(t *testing.T) {
		populateFakeTCPPacketProbeMaps(t, collection, generation, profileID, wgID,
			ifindex, sourcePort, remotePort, localIPv4, remoteIPv4, false)
		packet, originalPayload := buildFakeTCPProbeUDPPacket(t, sourcePort, remotePort, 2276)
		result, output, err := runFakeTCPPacketProbe(
			program, packet, fakeTCPSKBContext{Ifindex: ifindex}, len(packet)+64,
		)
		if err != nil {
			t.Fatalf("BPF_PROG_TEST_RUN exact frame boundary: %v", err)
		}
		if result != 0 {
			t.Fatalf("exact frame-boundary packet action=%d, want TC_ACT_OK", result)
		}
		verifyFakeTCPProbeOutput(
			t, output, packet, originalPayload, sourcePort, remotePort, nil,
		)
	})

	t.Run("frame-cap-one-over-hard-reject", func(t *testing.T) {
		populateFakeTCPPacketProbeMaps(t, collection, generation, profileID, wgID,
			ifindex, sourcePort, remotePort, localIPv4, remoteIPv4, false)
		packet, _ := buildFakeTCPProbeUDPPacket(t, sourcePort, remotePort, 2277)
		before := readFakeTCPPacketProbeStat(t, collection, fakeTCPStatBadPacket)
		result, output, err := runFakeTCPPacketProbe(
			program, packet, fakeTCPSKBContext{Ifindex: ifindex}, len(packet)+64,
		)
		if err != nil {
			t.Fatalf("BPF_PROG_TEST_RUN frame boundary: %v", err)
		}
		if result != 2 {
			t.Fatalf("frame-boundary packet action=%d, want TC_ACT_SHOT", result)
		}
		if !bytes.Equal(output, packet) {
			t.Fatal("frame-boundary packet was mutated before the hard reject")
		}
		after := readFakeTCPPacketProbeStat(t, collection, fakeTCPStatBadPacket)
		if after != before+1 {
			t.Fatalf("bad-packet stat delta=%d, want 1", after-before)
		}
	})

	t.Run("aggregate-gso-hard-reject", func(t *testing.T) {
		populateFakeTCPPacketProbeMaps(t, collection, generation, profileID, wgID,
			ifindex, sourcePort, remotePort, localIPv4, remoteIPv4, true)
		packet, _ := buildFakeTCPProbeUDPPacket(t, sourcePort, remotePort, 33)
		before := readFakeTCPPacketProbeStat(t, collection, fakeTCPStatGSOReject)
		context := fakeTCPSKBContext{
			Ifindex:     ifindex,
			GSOSegments: 2,
			GSOSize:     16,
		}
		result, output, err := runFakeTCPPacketProbe(
			program, packet, context, len(packet)+64,
		)
		if err != nil {
			if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EOPNOTSUPP) {
				t.Skipf("kernel cannot synthesize an skb GSO context for BPF_PROG_TEST_RUN: %v", err)
			}
			t.Fatalf("BPF_PROG_TEST_RUN aggregate GSO probe: %v", err)
		}
		if result != 2 {
			t.Fatalf("aggregate GSO action=%d, want TC_ACT_SHOT", result)
		}
		if !bytes.Equal(output, packet) {
			t.Fatal("aggregate GSO packet was mutated before the hard reject")
		}
		after := readFakeTCPPacketProbeStat(t, collection, fakeTCPStatGSOReject)
		if after != before+1 {
			t.Fatalf("GSO-reject stat delta=%d, want 1", after-before)
		}
	})
}

func readFakeTCPPacketProbeStat(
	t *testing.T,
	collection *ebpf.Collection,
	key uint32,
) uint64 {
	t.Helper()
	stats := collection.Maps["faketcp_stats_map"]
	if stats == nil {
		t.Fatal("experimental object has no faketcp_stats_map")
	}
	possibleCPUs, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatalf("read possible CPU count: %v", err)
	}
	values := make([]uint64, possibleCPUs)
	if err := stats.Lookup(&key, &values); err != nil {
		t.Fatalf("read faketcp_stats_map[%d]: %v", key, err)
	}
	var total uint64
	for _, value := range values {
		total += value
	}
	return total
}

func populateFakeTCPPacketProbeMaps(
	t *testing.T,
	collection *ebpf.Collection,
	generation uint64,
	profileID uint32,
	wgID uint32,
	ifindex uint32,
	sourcePort uint16,
	remotePort uint16,
	localIPv4 uint32,
	remoteIPv4 uint32,
	xorEnabled bool,
) []byte {
	t.Helper()
	const cipherID = uint32(19)
	var xorKey []byte
	ruleCipherID := uint32(0)
	if xorEnabled {
		ruleCipherID = cipherID
		xorKey = make([]byte, 256)
		for i := range xorKey {
			xorKey[i] = byte(i*17 + 5)
		}
	}
	updates := []struct {
		mapName string
		key     any
		value   any
	}{
		{
			mapName: "control_map",
			key:     abi.ControlKeyGlobal,
			value: abi.ControlValue{
				ActiveGeneration: generation,
				ABIVersion:       abi.Version,
			},
		},
		{
			mapName: "profile_map",
			key:     abi.ProfileKey{Generation: generation, ProfileID: profileID},
			value: abi.ProfileValue{
				Generation:      generation,
				StandardToMixed: [4]uint32{0xa1b2c3d4, 0xb2c3d4e5, 0xc3d4e5f6, 0x13dff06b},
				MixedToStandard: [4]uint32{1, 2, 3, 4},
			},
		},
		{
			mapName: "managed_fwmark_map",
			key: abi.ManagedFwmarkKey{
				Generation: generation,
			},
			value: abi.ManagedFwmarkValue{
				Generation:   generation,
				ActionOnMiss: abi.ActionDrop,
			},
		},
		{
			mapName: "egress_rule_map",
			key: abi.EgressRuleKey{
				Generation: generation,
				SourcePort: sourcePort,
				Family:     abi.FamilyIPv4,
			},
			value: abi.EgressRuleValue{
				Generation:    generation,
				ProfileID:     profileID,
				WGID:          wgID,
				CipherID:      ruleCipherID,
				Action:        abi.ActionRewrite,
				TransportMode: abi.TransportFakeTCP,
			},
		},
		{
			mapName: "faketcp_session_map",
			key: abi.FakeTCPSessionKey{
				Generation:    generation,
				LocalIPv4:     localIPv4,
				RemoteIPv4:    remoteIPv4,
				UnderlayIndex: ifindex,
				LocalPort:     sourcePort,
				RemotePort:    remotePort,
			},
			value: abi.FakeTCPSessionValue{
				Generation: generation,
				TXSequence: 0x01020304,
				RXSequence: 0x11223344,
				Window:     4096,
				State:      abi.FakeTCPStateEstablished,
			},
		},
	}
	if xorEnabled {
		var key [256]byte
		copy(key[:], xorKey)
		updates = append(updates, struct {
			mapName string
			key     any
			value   any
		}{
			mapName: "cipher_map",
			key:     abi.CipherKey{Generation: generation, CipherID: cipherID},
			value: abi.CipherValue{
				Generation: generation,
				Key:        key,
				KeyLen:     256,
				KeyMask:    255,
				MaxBytes:   2048,
				Mode:       abi.CipherModeXOR,
			},
		})
	}
	for _, update := range updates {
		m := collection.Maps[update.mapName]
		if m == nil {
			t.Fatalf("experimental object has no %s map", update.mapName)
		}
		if err := m.Update(update.key, update.value, ebpf.UpdateAny); err != nil {
			t.Fatalf("populate %s: %v", update.mapName, err)
		}
	}
	return xorKey
}

func populateFakeTCPPacketProbeTailCalls(
	t *testing.T,
	collection *ebpf.Collection,
	generation uint64,
) {
	t.Helper()
	if err := populateXORTailCalls(collection, generation); err != nil {
		t.Fatalf("populate XOR packet-probe tail calls: %v", err)
	}
	m := collection.Maps["faketcp_egress_programs"]
	program := collection.Programs["wg_faketcp_egress"]
	if m == nil || program == nil {
		t.Fatal("experimental object has no FakeTCP egress tail-call map/program")
	}
	index := uint32(generation & 1)
	fd := uint32(program.FD())
	if err := m.Update(index, fd, ebpf.UpdateAny); err != nil {
		t.Fatalf("populate faketcp_egress_programs[%d]: %v", index, err)
	}
}

func buildFakeTCPProbeUDPPacket(
	t *testing.T,
	sourcePort uint16,
	destinationPort uint16,
	payloadLength int,
) ([]byte, []byte) {
	t.Helper()
	if payloadLength < 32 {
		t.Fatal("probe payload must be a WireGuard transport-data shape")
	}
	payload := make([]byte, payloadLength)
	for i := range payload {
		payload[i] = byte(i*29 + 7)
	}
	binary.LittleEndian.PutUint32(payload[:4], 4)

	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], sourcePort)
	binary.BigEndian.PutUint16(udp[2:4], destinationPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)+len(payload)))
	binary.BigEndian.PutUint16(udp[6:8], testTransportChecksum(17, udp, payload))

	ipv4 := make([]byte, 20)
	ipv4[0] = 0x45
	ipv4[8] = 64
	ipv4[9] = 17
	binary.BigEndian.PutUint16(ipv4[2:4], uint16(len(ipv4)+len(udp)+len(payload)))
	copy(ipv4[12:16], []byte{10, 0, 0, 1})
	copy(ipv4[16:20], []byte{10, 0, 0, 2})
	binary.BigEndian.PutUint16(ipv4[10:12], internetChecksum(ipv4))

	ethernet := make([]byte, 14)
	copy(ethernet[0:6], []byte{2, 0, 0, 0, 0, 2})
	copy(ethernet[6:12], []byte{2, 0, 0, 0, 0, 1})
	binary.BigEndian.PutUint16(ethernet[12:14], 0x0800)
	packet := append(append(append(ethernet, ipv4...), udp...), payload...)
	return packet, payload
}

func verifyFakeTCPProbeOutput(
	t *testing.T,
	output []byte,
	input []byte,
	originalPayload []byte,
	sourcePort uint16,
	destinationPort uint16,
	xorKey []byte,
) {
	t.Helper()
	const (
		ethernetLength = 14
		ipv4Length     = 20
		tcpLength      = 20
		headerDelta    = 12
	)
	if got, want := len(output), len(input)+headerDelta; got != want {
		t.Fatalf("FakeTCP output length=%d, want %d", got, want)
	}
	ipv4 := output[ethernetLength : ethernetLength+ipv4Length]
	if ipv4[0] != 0x45 || ipv4[9] != 6 {
		t.Fatalf("FakeTCP IPv4 header version/IHL=%#x protocol=%d", ipv4[0], ipv4[9])
	}
	if got, want := int(binary.BigEndian.Uint16(ipv4[2:4])), len(output)-ethernetLength; got != want {
		t.Fatalf("FakeTCP IPv4 total length=%d, want %d", got, want)
	}
	if internetChecksum(ipv4) != 0 {
		t.Fatalf("FakeTCP IPv4 checksum is invalid: header=%x", ipv4)
	}

	tcpOffset := ethernetLength + ipv4Length
	tcp := output[tcpOffset : tcpOffset+tcpLength]
	if got := binary.BigEndian.Uint16(tcp[0:2]); got != sourcePort {
		t.Fatalf("FakeTCP source port=%d, want %d", got, sourcePort)
	}
	if got := binary.BigEndian.Uint16(tcp[2:4]); got != destinationPort {
		t.Fatalf("FakeTCP destination port=%d, want %d", got, destinationPort)
	}
	if got := binary.BigEndian.Uint32(tcp[4:8]); got != 0x01020304 {
		t.Fatalf("FakeTCP sequence=%#x, want %#x", got, uint32(0x01020304))
	}
	if got := binary.BigEndian.Uint32(tcp[8:12]); got != 0x11223344 {
		t.Fatalf("FakeTCP acknowledgement=%#x, want %#x", got, uint32(0x11223344))
	}
	if tcp[12] != 5<<4 || tcp[13] != 0x18 {
		t.Fatalf("FakeTCP data offset/flags=%#x/%#x", tcp[12], tcp[13])
	}

	transformed := append([]byte(nil), originalPayload...)
	binary.LittleEndian.PutUint32(transformed[:4], 0x13dff06b)
	for i := range transformed {
		if len(xorKey) != 0 {
			transformed[i] ^= xorKey[i&255]
		}
	}
	wantWirePayload := append(append([]byte(nil), transformed[headerDelta:]...), transformed[:headerDelta]...)
	wirePayload := output[tcpOffset+tcpLength:]
	if !bytes.Equal(wirePayload, wantWirePayload) {
		t.Fatalf("FakeTCP type-word/rotation order mismatch:\n got %x\nwant %x", wirePayload, wantWirePayload)
	}
	tcpForChecksum := append([]byte(nil), tcp...)
	gotChecksum := binary.BigEndian.Uint16(tcpForChecksum[16:18])
	tcpForChecksum[16], tcpForChecksum[17] = 0, 0
	wantChecksum := testTransportChecksum(6, tcpForChecksum, wirePayload)
	if gotChecksum != wantChecksum {
		t.Fatalf("FakeTCP TCP checksum=%#04x, full recompute=%#04x", gotChecksum, wantChecksum)
	}
	if gotChecksum == 0 {
		t.Fatal("FakeTCP materialized TCP checksum is zero")
	}
}
