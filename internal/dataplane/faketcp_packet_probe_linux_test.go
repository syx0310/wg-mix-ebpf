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

type fakeTCPXDPContext struct {
	Data           uint32
	DataEnd        uint32
	DataMeta       uint32
	IngressIfindex uint32
	RXQueueIndex   uint32
	EgressIfindex  uint32
}

func TestFakeTCPSKBContextLayout(t *testing.T) {
	if got, want := binary.Size(fakeTCPSKBContext{}), 192; got != want {
		t.Fatalf("serialized __sk_buff context size=%d, want %d", got, want)
	}
}

func TestFakeTCPXDPContextLayout(t *testing.T) {
	if got, want := binary.Size(fakeTCPXDPContext{}), 24; got != want {
		t.Fatalf("serialized xdp_md context size=%d, want %d", got, want)
	}
}

// TestFakeTCPBPFPacketProbe verifier-loads the separately built experimental
// object, populates only in-memory maps, and invokes the TC egress and XDP
// ingress programs with BPF_PROG_TEST_RUN. It never attaches or pins a program.
// The test-run ABI cannot synthesize ip_summed/csum_start/csum_offset or skb_dst. The unified
// prepare contract must therefore reject its otherwise materialized
// CHECKSUM_NONE skb as route-PMTU-unknown before mutation. Success belongs only
// to routed real-TC evidence. This probe covers verifier loading, the no-route
// fail-closed boundary, synthetic unsupported-GSO metadata and frame caps. Run
// explicitly on a Linux test host as:
//
//	WG_MIX_FAKETCP_PACKET_TEST_OBJECT=/absolute/wg_mix_faketcp_experimental.o \
//	  go test ./internal/dataplane -run '^TestFakeTCPBPFPacketProbe$' -v
//
// CHECKSUM_PARTIAL normalization and successful PMTU admission remain
// separately reviewed real-TC/NIC acceptance requirements.
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
	t.Cleanup(collection.Close)

	const (
		generation = uint64(91)
		profileID  = uint32(7)
		wgID       = uint32(11)
		ifindex    = uint32(1) // loopback in the dedicated Linux probe host
		sourcePort = uint16(31001)
		remotePort = uint16(443)
	)
	incarnation := faketcp.RuntimeIncarnation{1}
	openFakeTCPPacketProbeGenerationGate(
		t, collection, generation, incarnation, ifindex, remotePort,
	)
	t.Run("generation poison fails closed", func(t *testing.T) {
		probeFakeTCPPacketProbePoisonFailClosed(
			t, spec.Copy(), generation, incarnation, ifindex, remotePort,
		)
	})
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
	probeFakeTCPXDPParserModes(t, collection, generation, wgID, ifindex, remotePort)
	// The following TC matrix retains its original Ethernet-first parser:auto
	// contract. A leaked ParserL3 entry changes its first action and fails it.
	requireFakeTCPPacketProbeUnderlayAbsent(t, collection, generation, ifindex)

	const (
		fakeTCPStatBadPacket           = uint32(4)
		fakeTCPStatGSOReject           = uint32(5)
		fakeTCPMTURouteUnknownAuditKey = uint32(3*3 + 2)
	)
	for _, xorEnabled := range []bool{false, true} {
		for _, payloadLength := range []int{32, 33, 1459, 1460} {
			name := fmt.Sprintf("checksum-none-materialized-payload-%d", payloadLength)
			if xorEnabled {
				name += "-xor"
			}
			t.Run(name, func(t *testing.T) {
				populateFakeTCPPacketProbeMaps(t, collection, generation, profileID, wgID,
					ifindex, sourcePort, remotePort, localIPv4, remoteIPv4, xorEnabled)
				packet, _ := buildFakeTCPProbeUDPPacket(
					t, sourcePort, remotePort, payloadLength,
				)
				before := readFakeTCPPacketProbeMapCounter(
					t, collection, "faketcp_mtu_audit_map", fakeTCPMTURouteUnknownAuditKey,
				)
				context := fakeTCPSKBContext{Ifindex: ifindex}
				result, output, err := runFakeTCPPacketProbe(
					program, packet, context, len(packet)+64,
				)
				if err != nil {
					t.Fatalf("BPF_PROG_TEST_RUN materialized packet: %v", err)
				}
				if result != 2 {
					t.Fatalf("no-route CHECKSUM_NONE packet action=%d, want TC_ACT_SHOT", result)
				}
				if !bytes.Equal(output, packet) {
					t.Fatal("no-route CHECKSUM_NONE packet mutated before PMTU rejection")
				}
				after := readFakeTCPPacketProbeMapCounter(
					t, collection, "faketcp_mtu_audit_map", fakeTCPMTURouteUnknownAuditKey,
				)
				if after != before+1 {
					t.Fatalf("route-unknown audit delta=%d, want 1", after-before)
				}
			})
		}
	}

	t.Run("frame-cap-exact-materialized", func(t *testing.T) {
		populateFakeTCPPacketProbeMaps(t, collection, generation, profileID, wgID,
			ifindex, sourcePort, remotePort, localIPv4, remoteIPv4, false)
		packet, _ := buildFakeTCPProbeUDPPacket(t, sourcePort, remotePort, 2276)
		before := readFakeTCPPacketProbeMapCounter(
			t, collection, "faketcp_mtu_audit_map", fakeTCPMTURouteUnknownAuditKey,
		)
		result, output, err := runFakeTCPPacketProbe(
			program, packet, fakeTCPSKBContext{Ifindex: ifindex}, len(packet)+64,
		)
		if err != nil {
			t.Fatalf("BPF_PROG_TEST_RUN exact frame boundary: %v", err)
		}
		if result != 2 {
			t.Fatalf("no-route exact frame-boundary action=%d, want TC_ACT_SHOT", result)
		}
		if !bytes.Equal(output, packet) {
			t.Fatal("no-route exact frame-boundary packet mutated before PMTU rejection")
		}
		after := readFakeTCPPacketProbeMapCounter(
			t, collection, "faketcp_mtu_audit_map", fakeTCPMTURouteUnknownAuditKey,
		)
		if after != before+1 {
			t.Fatalf("route-unknown audit delta=%d, want 1", after-before)
		}
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

func openFakeTCPPacketProbeGenerationGate(
	t *testing.T,
	collection *ebpf.Collection,
	generation uint64,
	incarnation faketcp.RuntimeIncarnation,
	ifindex uint32,
	destinationPort uint16,
) {
	t.Helper()
	gate := collection.Maps[fakeTCPGenerationGateMapName]
	wake := collection.Maps[fakeTCPGenerationWakeMapName]
	runtimeIdentity := collection.Maps[fakeTCPRuntimeIDMapName]
	control := collection.Programs[fakeTCPGenerationControlProgramName]
	xdp := collection.Programs[fakeTCPXDPProgramName]
	if gate == nil || wake == nil || runtimeIdentity == nil || control == nil || xdp == nil {
		t.Fatal("experimental object has an incomplete generation barrier")
	}
	if err := validateLiveFakeTCPGenerationControl(gate, wake, runtimeIdentity, control); err != nil {
		t.Fatalf("validate packet-probe generation control identity: %v", err)
	}
	if err := gate.Update(uint32(0), abi.FakeTCPGenerationGateValue{
		Generation: generation,
		State:      abi.FakeTCPGenerationStateOpen,
	}, ebpf.UpdateAny); !errors.Is(err, unix.EPERM) {
		t.Fatalf("syscall write to BPF_F_RDONLY generation gate error=%v, want EPERM", err)
	}
	updateFakeTCPPacketProbeRuntimeIdentity(t, runtimeIdentity, generation, incarnation)
	if result, err := runFakeTCPPacketProbeGenerationControl(
		control, generation, incarnation, abi.FakeTCPGenerationControlAssertClosed,
	); err != nil || result != abi.FakeTCPGenerationResultIdle {
		t.Fatalf("ASSERT_CLOSED result=%d error=%v", result, err)
	}

	controlMap := collection.Maps["control_map"]
	if controlMap == nil {
		t.Fatal("experimental object has no control_map")
	}
	if err := controlMap.Update(abi.ControlKeyGlobal, abi.ControlValue{
		ActiveGeneration: generation,
		ABIVersion:       abi.Version,
	}, ebpf.UpdateAny); err != nil {
		t.Fatalf("publish unopened packet-probe selector: %v", err)
	}
	packet, _ := buildFakeTCPProbeUDPPacket(t, 31001, destinationPort, 32)
	result, output, err := runFakeTCPPacketProbe(
		xdp, packet, fakeTCPXDPContext{IngressIfindex: ifindex}, len(packet)+64,
	)
	if err != nil || result != uint32(1) || !bytes.Equal(output, packet) {
		t.Fatalf("unopened generation action=%d error=%v mutated=%t",
			result, err, !bytes.Equal(output, packet))
	}

	if result, err := runFakeTCPPacketProbeGenerationControl(
		control, generation, incarnation, abi.FakeTCPGenerationControlOpen,
	); err != nil || result != abi.FakeTCPGenerationResultOpen {
		t.Fatalf("OPEN result=%d error=%v", result, err)
	}
	t.Cleanup(func() {
		result, err := runFakeTCPPacketProbeGenerationControl(
			control, generation, incarnation, abi.FakeTCPGenerationControlClose,
		)
		if err != nil || result != abi.FakeTCPGenerationResultIdle {
			t.Errorf("CLOSE result=%d error=%v", result, err)
			return
		}
		var observed abi.FakeTCPGenerationGateValue
		if err := gate.Lookup(uint32(0), &observed); err != nil {
			t.Errorf("reread closed generation gate: %v", err)
		} else if observed.Generation != generation ||
			observed.State != abi.FakeTCPGenerationStateSealed {
			t.Errorf("closed generation gate=%#v, want sealed idle", observed)
		}
	})
}

func probeFakeTCPPacketProbePoisonFailClosed(
	t *testing.T,
	spec *ebpf.CollectionSpec,
	generation uint64,
	incarnation faketcp.RuntimeIncarnation,
	ifindex uint32,
	destinationPort uint16,
) {
	t.Helper()
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("load poison-negative experimental collection: %v", err)
	}
	defer collection.Close()
	gate := collection.Maps[fakeTCPGenerationGateMapName]
	runtimeIdentity := collection.Maps[fakeTCPRuntimeIDMapName]
	control := collection.Programs[fakeTCPGenerationControlProgramName]
	xdp := collection.Programs[fakeTCPXDPProgramName]
	if gate == nil || runtimeIdentity == nil || control == nil || xdp == nil {
		t.Fatal("poison-negative collection has an incomplete generation barrier")
	}
	updateFakeTCPPacketProbeRuntimeIdentity(t, runtimeIdentity, generation, incarnation)
	wrongIncarnation := incarnation
	wrongIncarnation[1] = 1
	if result, err := runFakeTCPPacketProbeGenerationControl(
		control, generation, wrongIncarnation, abi.FakeTCPGenerationControlAssertClosed,
	); err != nil || result != abi.FakeTCPGenerationResultMalformed {
		t.Fatalf("wrong-incarnation result=%d error=%v", result, err)
	}
	var observed abi.FakeTCPGenerationGateValue
	if err := gate.Lookup(uint32(0), &observed); err != nil || observed != (abi.FakeTCPGenerationGateValue{}) {
		t.Fatalf("wrong incarnation changed fresh gate=%#v error=%v", observed, err)
	}
	if result, err := runFakeTCPPacketProbeGenerationControl(
		control, generation, incarnation, abi.FakeTCPGenerationControlClose,
	); err != nil || result != abi.FakeTCPGenerationResultIdle {
		t.Fatalf("terminal CLOSE-before-OPEN result=%d error=%v", result, err)
	}

	wrongGeneration := generation + 1
	wrongGenerationIncarnation := faketcp.RuntimeIncarnation{2}
	updateFakeTCPPacketProbeRuntimeIdentity(
		t, runtimeIdentity, wrongGeneration, wrongGenerationIncarnation,
	)
	if result, err := runFakeTCPPacketProbeGenerationControl(
		control, wrongGeneration, wrongGenerationIncarnation, abi.FakeTCPGenerationControlOpen,
	); err != nil || result != abi.FakeTCPGenerationResultPoison {
		t.Fatalf("wrong-generation OPEN result=%d error=%v", result, err)
	}
	if err := gate.Lookup(uint32(0), &observed); err != nil ||
		observed.Generation != generation ||
		observed.State&abi.FakeTCPGenerationStatePoison == 0 {
		t.Fatalf("wrong generation did not stick poison: gate=%#v error=%v", observed, err)
	}

	controlMap := collection.Maps["control_map"]
	if controlMap == nil {
		t.Fatal("poison-negative collection has no control_map")
	}
	if err := controlMap.Update(abi.ControlKeyGlobal, abi.ControlValue{
		ActiveGeneration: generation,
		ABIVersion:       abi.Version,
	}, ebpf.UpdateAny); err != nil {
		t.Fatalf("publish poison-negative selector: %v", err)
	}
	packet, _ := buildFakeTCPProbeUDPPacket(t, 31001, destinationPort, 32)
	result, output, err := runFakeTCPPacketProbe(
		xdp, packet, fakeTCPXDPContext{IngressIfindex: ifindex}, len(packet)+64,
	)
	if err != nil || result != uint32(1) || !bytes.Equal(output, packet) {
		t.Fatalf("poisoned generation action=%d error=%v mutated=%t",
			result, err, !bytes.Equal(output, packet))
	}
}

func updateFakeTCPPacketProbeRuntimeIdentity(
	t *testing.T,
	runtimeIdentity *ebpf.Map,
	generation uint64,
	incarnation faketcp.RuntimeIncarnation,
) {
	t.Helper()
	value := abi.FakeTCPRuntimeIdentityValue{
		Generation:      generation,
		Incarnation:     [16]byte(incarnation),
		EventABIVersion: abi.FakeTCPEventABIVersion,
	}
	if err := runtimeIdentity.Update(uint32(0), value, ebpf.UpdateAny); err != nil {
		t.Fatalf("populate packet-probe runtime identity: %v", err)
	}
}

func runFakeTCPPacketProbeGenerationControl(
	control *ebpf.Program,
	generation uint64,
	incarnation faketcp.RuntimeIncarnation,
	operation uint32,
) (uint32, error) {
	request := make([]byte, 32)
	binary.NativeEndian.PutUint64(request[0:8], generation)
	copy(request[8:24], incarnation[:])
	binary.NativeEndian.PutUint32(request[24:28], operation)
	return control.Run(&ebpf.RunOptions{Data: request})
}

func probeFakeTCPXDPParserModes(
	t *testing.T,
	collection *ebpf.Collection,
	generation uint64,
	wgID uint32,
	ifindex uint32,
	destinationPort uint16,
) {
	t.Helper()
	program := collection.Programs["wg_mix_faketcp_ingress"]
	if program == nil {
		t.Fatal("experimental object has no wg_mix_faketcp_ingress program")
	}
	for _, update := range []struct {
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
	} {
		m := collection.Maps[update.mapName]
		if m == nil {
			t.Fatalf("experimental object has no %s map", update.mapName)
		}
		if err := m.Update(update.key, update.value, ebpf.UpdateAny); err != nil {
			t.Fatalf("populate %s: %v", update.mapName, err)
		}
	}
	underlayMap := collection.Maps["underlay_config_map"]
	if underlayMap == nil {
		t.Fatal("experimental object has no underlay_config_map")
	}
	underlayKey := abi.UnderlayConfigKey{
		Generation: generation, UnderlayIndex: ifindex,
	}
	requireFakeTCPPacketProbeUnderlayAbsent(t, collection, generation, ifindex)
	defer func() {
		if err := underlayMap.Delete(underlayKey); err != nil &&
			!errors.Is(err, ebpf.ErrKeyNotExist) {
			t.Errorf("delete XDP parser probe underlay: %v", err)
		}
		requireFakeTCPPacketProbeUnderlayAbsent(t, collection, generation, ifindex)
	}()

	ethernet, _ := buildFakeTCPProbeUDPPacket(t, 31001, destinationPort, 32)
	rawL3 := append([]byte(nil), ethernet[14:]...)
	const (
		xdpDrop = uint32(1)
		xdpPass = uint32(2)
	)
	for _, test := range []struct {
		name   string
		parser uint8
		packet []byte
		want   uint32
	}{
		{name: "ethernet/ethernet", parser: abi.ParserEthernet, packet: ethernet, want: xdpDrop},
		{name: "ethernet/raw-l3", parser: abi.ParserEthernet, packet: rawL3, want: xdpPass},
		{name: "l3/raw-l3", parser: abi.ParserL3, packet: rawL3, want: xdpDrop},
		{name: "l3/ethernet", parser: abi.ParserL3, packet: ethernet, want: xdpDrop},
	} {
		t.Run("XDP parser "+test.name, func(t *testing.T) {
			value := abi.UnderlayConfigValue{Generation: generation, ParserMode: test.parser}
			if err := underlayMap.Update(underlayKey, value, ebpf.UpdateAny); err != nil {
				t.Fatalf("select parser mode %d: %v", test.parser, err)
			}
			result, output, err := runFakeTCPPacketProbe(
				program,
				test.packet,
				fakeTCPXDPContext{IngressIfindex: ifindex},
				len(test.packet)+64,
			)
			if err != nil {
				t.Fatalf("BPF_PROG_TEST_RUN parser mode %d: %v", test.parser, err)
			}
			if result != test.want {
				t.Fatalf("XDP action=%d, want %d", result, test.want)
			}
			if !bytes.Equal(output, test.packet) {
				t.Fatal("parser-policy probe mutated the packet")
			}
		})
	}
}

func requireFakeTCPPacketProbeUnderlayAbsent(
	t *testing.T,
	collection *ebpf.Collection,
	generation uint64,
	ifindex uint32,
) {
	t.Helper()
	underlayMap := collection.Maps["underlay_config_map"]
	if underlayMap == nil {
		t.Fatal("experimental object has no underlay_config_map")
	}
	key := abi.UnderlayConfigKey{Generation: generation, UnderlayIndex: ifindex}
	var value abi.UnderlayConfigValue
	err := underlayMap.Lookup(key, &value)
	if err == nil {
		t.Fatalf("unexpected retained underlay parser policy: key=%#v value=%#v", key, value)
	}
	if !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("check underlay parser policy absence: %v", err)
	}
}

func readFakeTCPPacketProbeStat(
	t *testing.T,
	collection *ebpf.Collection,
	key uint32,
) uint64 {
	t.Helper()
	return readFakeTCPPacketProbeMapCounter(t, collection, "faketcp_stats_map", key)
}

func readFakeTCPPacketProbeMapCounter(
	t *testing.T,
	collection *ebpf.Collection,
	mapName string,
	key uint32,
) uint64 {
	t.Helper()
	counters := collection.Maps[mapName]
	if counters == nil {
		t.Fatalf("experimental object has no %s", mapName)
	}
	possibleCPUs, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatalf("read possible CPU count: %v", err)
	}
	values := make([]uint64, possibleCPUs)
	if err := counters.Lookup(&key, &values); err != nil {
		t.Fatalf("read %s[%d]: %v", mapName, key, err)
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
				Generation:         generation,
				TXSequence:         0x01020304,
				RXSequence:         0x11223344,
				Window:             4096,
				State:              abi.FakeTCPStateEstablished,
				Revision:           1,
				SessionID:          1,
				RuntimeIncarnation: [16]byte{1},
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
