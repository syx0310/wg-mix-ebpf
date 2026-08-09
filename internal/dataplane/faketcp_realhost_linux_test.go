//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	ciliumlink "github.com/cilium/ebpf/link"
	"github.com/syx0310/wg-mix-ebpf/internal/abi"
	"github.com/syx0310/wg-mix-ebpf/internal/config"
	"github.com/syx0310/wg-mix-ebpf/internal/control"
	"github.com/syx0310/wg-mix-ebpf/internal/faketcp"
	"github.com/syx0310/wg-mix-ebpf/internal/lockfile"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	fakeTCPRealHostObjectSizeLimit              = 128 << 20
	fakeTCPRealHostStatCount                    = 19
	fakeTCPRealHostStatMTUReject                = uint32(16)
	fakeTCPRealHostMTURouteUnknownAuditKey      = uint32(3*3 + 2)
	fakeTCPRealHostCoreStatEgressGSOSeen        = uint32(15)
	fakeTCPRealHostCoreStatEgressGSOManagedSeen = uint32(16)
	fakeTCPRealHostVirtioNetHeaderSize          = 10
	fakeTCPRealHostEthernetHeaderSize           = 14
	fakeTCPRealHostIPv4HeaderSize               = 20
	fakeTCPRealHostUDPHeaderSize                = 8
	fakeTCPRealHostVirtioChecksumStart          = fakeTCPRealHostEthernetHeaderSize + fakeTCPRealHostIPv4HeaderSize
	fakeTCPRealHostVirtioChecksumOffset         = 6
	// Linux packet_snd requires hdr_len to cover the checksum field when
	// NEEDS_CSUM is set: csum_start + csum_offset + sizeof(__sum16) = 42.
	fakeTCPRealHostVirtioHeaderLength        = fakeTCPRealHostVirtioChecksumStart + fakeTCPRealHostUDPHeaderSize
	fakeTCPRealHostVirtioGSOSize      uint16 = 64
	fakeTCPRealHostGSOSourcePort      uint16 = 31101
	fakeTCPRealHostGSODestinationPort uint16 = 31102
)

type fakeTCPRealHostPrepared struct {
	contract         fakeTCPRealHostContract
	experimentalSpec *ebpf.CollectionSpec
	baselineSpec     *ebpf.CollectionSpec
}

type fakeTCPRealHostTCXProgram struct {
	programID uint32
	linkID    uint32
}

type fakeTCPRealHostTCXSlot struct {
	ifindex int
	attach  ebpf.AttachType
}

type fakeTCPRealHostKernelSnapshot struct {
	xdp map[int]fakeTCPXDPProbe
	tcx map[fakeTCPRealHostTCXSlot][]fakeTCPRealHostTCXProgram
}

type fakeTCPRealHostSlowPath struct {
	started   chan struct{}
	stop      chan struct{}
	startOnce sync.Once
	stopOnce  sync.Once
}

func TestFakeTCPRealHostVirtioNetHeaderEncoding(t *testing.T) {
	packet := make([]byte, 128)
	partial := prependFakeTCPRealHostVirtioNetHeader(
		t, packet, unix.VIRTIO_NET_HDR_GSO_NONE, 0,
	)
	if got, want := partial[:fakeTCPRealHostVirtioNetHeaderSize], []byte{
		unix.VIRTIO_NET_HDR_F_NEEDS_CSUM,
		unix.VIRTIO_NET_HDR_GSO_NONE,
		42, 0,
		0, 0,
		34, 0,
		6, 0,
	}; !bytes.Equal(got, want) {
		t.Fatalf("CHECKSUM_PARTIAL virtio header=%v, want %v", got, want)
	}
	if !bytes.Equal(partial[fakeTCPRealHostVirtioNetHeaderSize:], packet) {
		t.Fatal("CHECKSUM_PARTIAL virtio header changed frame bytes")
	}

	gso := prependFakeTCPRealHostVirtioNetHeader(
		t, packet, unix.VIRTIO_NET_HDR_GSO_UDP_L4, fakeTCPRealHostVirtioGSOSize,
	)
	if got, want := gso[:fakeTCPRealHostVirtioNetHeaderSize], []byte{
		unix.VIRTIO_NET_HDR_F_NEEDS_CSUM,
		unix.VIRTIO_NET_HDR_GSO_UDP_L4,
		42, 0,
		64, 0,
		34, 0,
		6, 0,
	}; !bytes.Equal(got, want) {
		t.Fatalf("UDP_L4 GSO virtio header=%v, want %v", got, want)
	}
	if !bytes.Equal(gso[fakeTCPRealHostVirtioNetHeaderSize:], packet) {
		t.Fatal("UDP_L4 GSO virtio header changed frame bytes")
	}

}

func TestFakeTCPRealHostGSOOutputMatcher(t *testing.T) {
	for _, protocol := range []byte{17, 6} {
		for _, payloadLength := range []int{67, 32, 3} {
			frame := buildFakeTCPRealHostFlowMatcherFrame(t, protocol, payloadLength)
			if !fakeTCPRealHostFlowFrameMatches(
				frame, fakeTCPRealHostGSOSourcePort, fakeTCPRealHostGSODestinationPort,
			) {
				t.Fatalf("protocol=%d payload=%d valid flow did not match", protocol, payloadLength)
			}
		}
	}
	wrongFlow := buildFakeTCPRealHostFlowMatcherFrame(t, 17, 67)
	binary.BigEndian.PutUint16(
		wrongFlow[fakeTCPRealHostEthernetHeaderSize+fakeTCPRealHostIPv4HeaderSize:],
		fakeTCPRealHostGSOSourcePort+1,
	)
	if fakeTCPRealHostFlowFrameMatches(
		wrongFlow, fakeTCPRealHostGSOSourcePort, fakeTCPRealHostGSODestinationPort,
	) {
		t.Fatal("wrong GSO flow matched")
	}
	truncated := buildFakeTCPRealHostFlowMatcherFrame(t, 17, 32)
	if fakeTCPRealHostFlowFrameMatches(
		truncated[:len(truncated)-1], fakeTCPRealHostGSOSourcePort, fakeTCPRealHostGSODestinationPort,
	) {
		t.Fatal("truncated UDP segment matched")
	}
	for _, totalLength := range []uint16{20, 23} {
		shortTotal := buildFakeTCPRealHostFlowMatcherFrame(t, 17, 32)
		binary.BigEndian.PutUint16(
			shortTotal[fakeTCPRealHostEthernetHeaderSize+2:], totalLength,
		)
		if fakeTCPRealHostFlowFrameMatches(
			shortTotal, fakeTCPRealHostGSOSourcePort, fakeTCPRealHostGSODestinationPort,
		) {
			t.Fatalf("short IPv4 total length %d matched", totalLength)
		}
	}
	badUDP := buildFakeTCPRealHostFlowMatcherFrame(t, 17, 32)
	udp := badUDP[fakeTCPRealHostEthernetHeaderSize+fakeTCPRealHostIPv4HeaderSize:]
	binary.BigEndian.PutUint16(udp[4:6], uint16(fakeTCPRealHostUDPHeaderSize+31))
	if fakeTCPRealHostFlowFrameMatches(
		badUDP, fakeTCPRealHostGSOSourcePort, fakeTCPRealHostGSODestinationPort,
	) {
		t.Fatal("UDP segment with inconsistent length matched")
	}
	badTCP := buildFakeTCPRealHostFlowMatcherFrame(t, 6, 32)
	badTCP[fakeTCPRealHostEthernetHeaderSize+fakeTCPRealHostIPv4HeaderSize+12] = 4 << 4
	if fakeTCPRealHostFlowFrameMatches(
		badTCP, fakeTCPRealHostGSOSourcePort, fakeTCPRealHostGSODestinationPort,
	) {
		t.Fatal("TCP segment with short data offset matched")
	}
}

func TestFakeTCPRealHostGSOProbeIsolationContract(t *testing.T) {
	contract := fakeTCPRealHostContract{
		ifindex: 101, peerIfindex: 102, vethName: "wgc8e41a", peerVethName: "wgc8e41b",
	}
	state := fakeTCPRealHostState(contract, 77, true)
	localRules := 0
	for _, rule := range state.EgressRules {
		if rule.SourcePort != fakeTCPRealHostGSOSourcePort {
			continue
		}
		if rule.UnderlayIfIndex != contract.ifindex || rule.TransportMode != "faketcp" {
			t.Fatalf("GSO probe egress rule=%#v", rule)
		}
		localRules++
	}
	if localRules != 1 {
		t.Fatalf("GSO probe local egress rules=%d, want 1", localRules)
	}
	for _, listener := range state.IngressListeners {
		if listener.DestinationPort == fakeTCPRealHostGSODestinationPort {
			t.Fatalf("GSO probe unexpectedly installed peer ingress listener %#v", listener)
		}
	}
}

func buildFakeTCPRealHostFlowMatcherFrame(t *testing.T, protocol byte, payloadLength int) []byte {
	t.Helper()
	if payloadLength < 0 {
		t.Fatalf("negative matcher payload length %d", payloadLength)
	}
	transportHeaderLength := fakeTCPRealHostUDPHeaderSize
	if protocol == 6 {
		transportHeaderLength = 20
	} else if protocol != 17 {
		t.Fatalf("unsupported matcher protocol=%d", protocol)
	}
	ipv4Length := fakeTCPRealHostIPv4HeaderSize + transportHeaderLength + payloadLength
	frame := make([]byte, fakeTCPRealHostEthernetHeaderSize+ipv4Length)
	frame[12], frame[13] = 0x08, 0x00
	ip := frame[fakeTCPRealHostEthernetHeaderSize:]
	ip[0], ip[8], ip[9] = 0x45, 64, protocol
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipv4Length))
	copy(ip[12:16], []byte{10, 0, 0, 1})
	copy(ip[16:20], []byte{10, 0, 0, 2})
	binary.BigEndian.PutUint16(ip[10:12], internetChecksum(ip[:fakeTCPRealHostIPv4HeaderSize]))
	transport := ip[fakeTCPRealHostIPv4HeaderSize:]
	binary.BigEndian.PutUint16(transport[0:2], fakeTCPRealHostGSOSourcePort)
	binary.BigEndian.PutUint16(transport[2:4], fakeTCPRealHostGSODestinationPort)
	if protocol == 17 {
		binary.BigEndian.PutUint16(transport[4:6], uint16(transportHeaderLength+payloadLength))
	} else {
		transport[12] = 5 << 4
	}
	return frame
}

func newFakeTCPRealHostSlowPath() *fakeTCPRealHostSlowPath {
	return &fakeTCPRealHostSlowPath{
		started: make(chan struct{}),
		stop:    make(chan struct{}),
	}
}

func (slowPath *fakeTCPRealHostSlowPath) Run(ctx context.Context) error {
	if slowPath == nil || ctx == nil {
		return errors.New("FakeTCP real-host slow path is unavailable")
	}
	slowPath.startOnce.Do(func() { close(slowPath.started) })
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-slowPath.stop:
		return nil
	}
}

func (slowPath *fakeTCPRealHostSlowPath) RequestStop() error {
	if slowPath == nil {
		return errors.New("FakeTCP real-host slow path is unavailable")
	}
	slowPath.stopOnce.Do(func() { close(slowPath.stop) })
	return nil
}

func (slowPath *fakeTCPRealHostSlowPath) Close() error {
	return slowPath.RequestStop()
}

type fakeTCPRealHostGenerationIsolation struct {
	mu         sync.Mutex
	owner      *experimentalCollectionOwner
	generation uint64
	ifindexes  []int
}

func (isolation *fakeTCPRealHostGenerationIsolation) bind(owner *experimentalCollectionOwner) error {
	if isolation == nil || owner == nil {
		return errors.New("bind FakeTCP real-host generation isolation: owner is nil")
	}
	isolation.mu.Lock()
	defer isolation.mu.Unlock()
	if isolation.owner != nil && isolation.owner != owner {
		return errors.New("bind FakeTCP real-host generation isolation: owner already bound")
	}
	isolation.owner = owner
	return nil
}

func (isolation *fakeTCPRealHostGenerationIsolation) AssertInactive(
	ctx context.Context,
	generation uint64,
) error {
	if ctx == nil {
		return errors.New("prove FakeTCP real-host generation inactive: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if isolation == nil || generation == 0 || generation != isolation.generation {
		return errors.New("prove FakeTCP real-host generation inactive: generation identity mismatch")
	}
	owner := isolation.boundOwner()
	if owner == nil {
		return errors.New("prove FakeTCP real-host generation inactive: collection owner is unbound")
	}
	controlMap, err := owner.mapResource("control_map")
	if err != nil {
		return err
	}
	var observed abi.ControlValue
	if err := controlMap.Lookup(abi.ControlKeyGlobal, &observed); err != nil {
		return fmt.Errorf("prove FakeTCP real-host generation inactive: read selector: %w", err)
	}
	if observed != (abi.ControlValue{}) {
		return fmt.Errorf("prove FakeTCP real-host generation inactive: selector is %#v", observed)
	}
	return nil
}

func (isolation *fakeTCPRealHostGenerationIsolation) Quiesce(
	ctx context.Context,
	generation uint64,
) error {
	if err := isolation.AssertInactive(ctx, generation); err != nil {
		return err
	}
	for _, ifindex := range isolation.ifindexes {
		probe, err := probeLiveFakeTCPXDP(ifindex)
		if err != nil {
			return fmt.Errorf("quiesce FakeTCP real-host generation: probe XDP ifindex %d: %w", ifindex, err)
		}
		if probe.Attached || probe.ProgramID != 0 {
			return fmt.Errorf("quiesce FakeTCP real-host generation: XDP remains on ifindex %d", ifindex)
		}
		for _, attach := range []ebpf.AttachType{ebpf.AttachTCXIngress, ebpf.AttachTCXEgress} {
			programs, err := queryFakeTCPRealHostTCX(ifindex, attach)
			if err != nil {
				return err
			}
			if len(programs) != 0 {
				return fmt.Errorf(
					"quiesce FakeTCP real-host generation: TCX %s remains on ifindex %d",
					attach,
					ifindex,
				)
			}
		}
	}
	return nil
}

func (isolation *fakeTCPRealHostGenerationIsolation) boundOwner() *experimentalCollectionOwner {
	if isolation == nil {
		return nil
	}
	isolation.mu.Lock()
	defer isolation.mu.Unlock()
	return isolation.owner
}

// TestExperimentalFakeTCPRealHostLifecycleIntegration is an explicitly gated
// kernel test. It owns no persistent pins: the only mutations are exact XDP
// and TCX links on the controller-created veth pair, and Close acts only on
// the link FDs returned by this runtime.
func TestExperimentalFakeTCPRealHostLifecycleIntegration(t *testing.T) {
	prepared := requireFakeTCPRealHostPrepared(t)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()

	runtime, slowPath := buildFakeTCPRealHostRuntime(ctx, t, prepared, false, "lifecycle")
	closed := false
	defer func() {
		if !closed {
			if err := runtime.Close(); err != nil {
				t.Errorf("close exact FakeTCP real-host runtime after failure: %v", err)
			}
		}
	}()
	assertFakeTCPRealHostRuntimeAttached(t, prepared.contract)

	handles, err := runtime.Handles()
	if err != nil {
		t.Fatal(err)
	}
	if runtime.Generation() == 0 || handles.Generation() != runtime.Generation() ||
		handles.Identity() != runtime.Identity() || handles.SessionStore() == nil {
		t.Fatalf("runtime identity=%#v generation=%d handles identity=%#v generation=%d store=%v",
			runtime.Identity(), runtime.Generation(), handles.Identity(), handles.Generation(), handles.SessionStore())
	}
	runErr := make(chan error, 1)
	go func() { runErr <- runtime.Run(ctx) }()
	select {
	case <-slowPath.started:
	case <-time.After(5 * time.Second):
		t.Fatal("FakeTCP real-host runtime slow path did not start")
	}
	if err := runtime.RequestStop(); err != nil {
		t.Fatalf("request FakeTCP real-host runtime stop: %v", err)
	}
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("run FakeTCP real-host runtime: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("FakeTCP real-host runtime did not stop")
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("close FakeTCP real-host runtime: %v", err)
	}
	closed = true
	assertFakeTCPRealHostKernelEmpty(t, prepared.contract)
	t.Logf("FAKETCP_REALHOST_LIFECYCLE_COMPLETE run_id=%s restored=1", prepared.contract.runID)
}

// TestFakeTCPRealHostXORTypewordHeaderCompositionIntegration keeps the legacy
// AF_PACKET fixture as negative evidence only. Packet sockets select a device
// but do not publish a route dst, so unified PMTU admission must reject
// CHECKSUM_NONE, CHECKSUM_PARTIAL and a shape-valid UDP_L4 GSO aggregate before
// any FakeTCP, type-word or XOR mutation. Positive evidence is intentionally
// deferred to the separately reviewed routed-veth harness.
func TestFakeTCPRealHostXORTypewordHeaderCompositionIntegration(t *testing.T) {
	prepared := requireFakeTCPRealHostPrepared(t)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()

	runtime, _ := buildFakeTCPRealHostRuntime(ctx, t, prepared, true, "composition")
	closed := false
	defer func() {
		if !closed {
			if err := runtime.Close(); err != nil {
				t.Errorf("close exact FakeTCP composition runtime after failure: %v", err)
			}
		}
	}()
	assertFakeTCPRealHostRuntimeAttached(t, prepared.contract)

	handles, err := runtime.Handles()
	if err != nil {
		t.Fatal(err)
	}
	installFakeTCPRealHostSessions(t, handles, runtime.Generation(), prepared.contract)
	fakeStatsBefore := readFakeTCPRealHostStats(
		t, runtime, "faketcp_stats_map", fakeTCPRealHostStatCount,
	)
	mtuAuditBefore := readFakeTCPRealHostStats(t, runtime, "faketcp_mtu_audit_map", 15)
	coreStatsBefore := readFakeTCPRealHostStats(t, runtime, "stats_map", 36)

	local, err := netlink.LinkByIndex(prepared.contract.ifindex)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := netlink.LinkByIndex(prepared.contract.peerIfindex)
	if err != nil {
		t.Fatal(err)
	}
	receiver := openFakeTCPRealHostPacketSocket(t, prepared.contract.peerIfindex)
	defer closeFakeTCPRealHostFD(t, receiver, "peer packet socket")
	sender := openFakeTCPRealHostPacketSocket(t, prepared.contract.ifindex)
	defer closeFakeTCPRealHostFD(t, sender, "sender packet socket")
	vnetSender := openFakeTCPRealHostVNetPacketSocket(t, prepared.contract.ifindex)
	defer closeFakeTCPRealHostFD(t, vnetSender, "vnet sender packet socket")
	destinationMAC := peer.Attrs().HardwareAddr
	sourceMAC := local.Attrs().HardwareAddr

	packetNone, _ := buildFakeTCPRealHostProbePacket(
		t, destinationMAC, sourceMAC, 65,
	)
	sendFakeTCPRealHostDropProbe(t, sender, prepared.contract.ifindex, packetNone)
	waitForFakeTCPRealHostStat(
		t,
		runtime,
		"faketcp_mtu_audit_map",
		fakeTCPRealHostMTURouteUnknownAuditKey,
		mtuAuditBefore[fakeTCPRealHostMTURouteUnknownAuditKey]+1,
	)
	assertNoFakeTCPRealHostFlowPacket(
		t, ctx, receiver, 31001, 31002,
	)

	packetPartial, _ := buildFakeTCPRealHostProbePacket(
		t, destinationMAC, sourceMAC, 66,
	)
	sendFakeTCPRealHostDropProbe(
		t,
		vnetSender,
		prepared.contract.ifindex,
		prependFakeTCPRealHostVirtioNetHeader(t, packetPartial, unix.VIRTIO_NET_HDR_GSO_NONE, 0),
	)
	waitForFakeTCPRealHostStat(
		t,
		runtime,
		"faketcp_mtu_audit_map",
		fakeTCPRealHostMTURouteUnknownAuditKey,
		mtuAuditBefore[fakeTCPRealHostMTURouteUnknownAuditKey]+2,
	)
	assertNoFakeTCPRealHostFlowPacket(
		t, ctx, receiver, 31001, 31002,
	)

	packetGSO := buildFakeTCPRealHostGSOProbePacket(
		t, destinationMAC, sourceMAC,
	)
	sendFakeTCPRealHostDropProbe(
		t,
		vnetSender,
		prepared.contract.ifindex,
		prependFakeTCPRealHostVirtioNetHeader(
			t, packetGSO, unix.VIRTIO_NET_HDR_GSO_UDP_L4, fakeTCPRealHostVirtioGSOSize,
		),
	)
	waitForFakeTCPRealHostStat(
		t,
		runtime,
		"faketcp_mtu_audit_map",
		fakeTCPRealHostMTURouteUnknownAuditKey,
		mtuAuditBefore[fakeTCPRealHostMTURouteUnknownAuditKey]+3,
	)
	assertNoFakeTCPRealHostFlowPacket(
		t, ctx, receiver,
		fakeTCPRealHostGSOSourcePort, fakeTCPRealHostGSODestinationPort,
	)

	fakeStatsAfter := readFakeTCPRealHostStats(
		t, runtime, "faketcp_stats_map", fakeTCPRealHostStatCount,
	)
	assertFakeTCPRealHostStatDeltas(t, "FakeTCP", fakeStatsBefore, fakeStatsAfter, map[uint32]uint64{
		fakeTCPRealHostStatMTUReject: 3,
	})
	mtuAuditAfter := readFakeTCPRealHostStats(t, runtime, "faketcp_mtu_audit_map", 15)
	assertFakeTCPRealHostStatDeltas(t, "PMTU audit", mtuAuditBefore, mtuAuditAfter, map[uint32]uint64{
		fakeTCPRealHostMTURouteUnknownAuditKey: 3,
	})
	coreStatsAfter := readFakeTCPRealHostStats(t, runtime, "stats_map", 36)
	assertFakeTCPRealHostStatDeltas(t, "core", coreStatsBefore, coreStatsAfter, map[uint32]uint64{
		fakeTCPRealHostCoreStatEgressGSOSeen:        1,
		fakeTCPRealHostCoreStatEgressGSOManagedSeen: 1,
	})

	if err := runtime.Close(); err != nil {
		t.Fatalf("close FakeTCP composition runtime: %v", err)
	}
	closed = true
	assertFakeTCPRealHostKernelEmpty(t, prepared.contract)
	t.Logf("FAKETCP_REALHOST_COMPOSITION_COMPLETE run_id=%s restored=1", prepared.contract.runID)
}

// TestBaselineExperimentalRealHostMutualExclusionIntegration proves that an
// active experimental owner cannot be competed with through the production
// baseline loader. The baseline loader must reject FakeTCP at its hard gate
// before it opens an object, validates a pin path, or changes the exact XDP and
// TCX identities already owned by the experimental runtime.
func TestBaselineExperimentalRealHostMutualExclusionIntegration(t *testing.T) {
	prepared := requireFakeTCPRealHostPrepared(t)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()

	if err := validateBaselineCollectionSpec(prepared.experimentalSpec); err == nil {
		t.Fatal("experimental object unexpectedly passed the baseline manifest")
	}
	if err := validateExperimentalExtensionManifest(prepared.baselineSpec); err == nil {
		t.Fatal("baseline object unexpectedly passed the experimental manifest")
	}

	runtime, _ := buildFakeTCPRealHostRuntime(ctx, t, prepared, false, "mutual-exclusion")
	closed := false
	defer func() {
		if !closed {
			if err := runtime.Close(); err != nil {
				t.Errorf("close exact FakeTCP mutual-exclusion runtime after failure: %v", err)
			}
		}
	}()
	active := assertFakeTCPRealHostRuntimeAttached(t, prepared.contract)

	forbiddenPin := filepath.Join(
		prepared.contract.tempRoot,
		"faketcp-"+prepared.contract.runID+"-baseline-gate-pin",
	)
	if _, err := os.Lstat(forbiddenPin); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("refuse baseline mutual-exclusion probe because path exists: %s: %v", forbiddenPin, err)
	}
	state := fakeTCPRealHostState(prepared.contract, runtime.Generation(), false)
	err := (LinuxLoader{
		ObjectPath: prepared.contract.baselineObject,
		PinPath:    forbiddenPin,
	}).Apply(ctx, state)
	if !errors.Is(err, ErrFakeTCPKernelGate) {
		t.Fatalf("baseline loader did not reject FakeTCP before mutation: %v", err)
	}
	if _, err := os.Lstat(forbiddenPin); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("baseline gate touched forbidden run-owned pin candidate: %s: %v", forbiddenPin, err)
	}
	after := snapshotFakeTCPRealHostKernel(t, prepared.contract)
	if !reflect.DeepEqual(after, active) {
		t.Fatalf("baseline gate changed experimental link identity: before=%#v after=%#v", active, after)
	}

	if err := runtime.Close(); err != nil {
		t.Fatalf("close FakeTCP mutual-exclusion runtime: %v", err)
	}
	closed = true
	assertFakeTCPRealHostKernelEmpty(t, prepared.contract)
	t.Logf("FAKETCP_REALHOST_MUTUAL_EXCLUSION_COMPLETE run_id=%s restored=1", prepared.contract.runID)
}

func requireFakeTCPRealHostPrepared(t *testing.T) fakeTCPRealHostPrepared {
	t.Helper()
	enabled, err := fakeTCPRealHostGateEnabled(os.LookupEnv)
	if err != nil {
		t.Fatal(err)
	}
	if !enabled {
		t.Skipf("set %s=1 only through the reviewed real-host controller", fakeTCPRealHostGateEnv)
	}
	if os.Geteuid() != 0 {
		t.Fatal("explicit FakeTCP real-host integration requires root")
	}
	contract, err := parseFakeTCPRealHostContract(os.LookupEnv)
	if err != nil {
		t.Fatal(err)
	}
	validateFakeTCPRealHostTempRootIdentity(t, contract)
	experimentalSpec, experimentalIdentity, err := loadFakeTCPRealHostObject(contract.experimentalObject)
	if err != nil {
		t.Fatal(err)
	}
	if experimentalIdentity.Embedded || experimentalIdentity.Source != contract.experimentalObject {
		t.Fatalf("experimental object identity = %#v", experimentalIdentity)
	}
	if err := validateExperimentalExtensionManifest(experimentalSpec); err != nil {
		t.Fatalf("validate experimental object %s (%s): %v",
			experimentalIdentity.Source, experimentalIdentity.SHA256, err)
	}
	baselineSpec, baselineIdentity, err := loadFakeTCPRealHostObject(contract.baselineObject)
	if err != nil {
		t.Fatal(err)
	}
	if baselineIdentity.Embedded || baselineIdentity.Source != contract.baselineObject {
		t.Fatalf("baseline object identity = %#v", baselineIdentity)
	}
	if err := validateBaselineCollectionSpec(baselineSpec); err != nil {
		t.Fatalf("validate baseline object %s (%s): %v", baselineIdentity.Source, baselineIdentity.SHA256, err)
	}
	validateFakeTCPRealHostOwnedVethPair(t, contract)
	assertFakeTCPRealHostKernelEmpty(t, contract)
	return fakeTCPRealHostPrepared{
		contract: contract, experimentalSpec: experimentalSpec, baselineSpec: baselineSpec,
	}
}

func loadFakeTCPRealHostObject(path string) (*ebpf.CollectionSpec, ObjectIdentity, error) {
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, ObjectIdentity{}, fmt.Errorf("resolve reviewed BPF object %s: %w", path, err)
	}
	if canonical != path {
		return nil, ObjectIdentity{}, fmt.Errorf("reviewed BPF object path %s resolves to %s", path, canonical)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ObjectIdentity{}, fmt.Errorf("open reviewed BPF object %s: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, ObjectIdentity{}, fmt.Errorf("own reviewed BPF object descriptor %s", path)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		closeErr := file.Close()
		return nil, ObjectIdentity{}, errors.Join(
			fmt.Errorf("inspect reviewed BPF object %s: %w", path, err),
			closeErr,
		)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != 0 || stat.Nlink != 1 ||
		stat.Mode&0o022 != 0 || stat.Size <= 0 || stat.Size > fakeTCPRealHostObjectSizeLimit {
		closeErr := file.Close()
		return nil, ObjectIdentity{}, errors.Join(
			fmt.Errorf(
				"reviewed BPF object %s has unsafe identity mode=%#o uid=%d nlink=%d size=%d",
				path, stat.Mode, stat.Uid, stat.Nlink, stat.Size,
			),
			closeErr,
		)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, fakeTCPRealHostObjectSizeLimit+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return nil, ObjectIdentity{}, errors.Join(
			wrapNonNilError("read reviewed BPF object "+path, readErr),
			wrapNonNilError("close reviewed BPF object "+path, closeErr),
		)
	}
	if len(data) == 0 || len(data) > fakeTCPRealHostObjectSizeLimit {
		return nil, ObjectIdentity{}, fmt.Errorf("reviewed BPF object %s has invalid size %d", path, len(data))
	}
	identity := objectIdentity(path, false, data)
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(data))
	if err != nil {
		return nil, identity, fmt.Errorf("parse reviewed BPF object %s: %w", path, err)
	}
	return spec, identity, nil
}

func validateFakeTCPRealHostTempRootIdentity(t *testing.T, contract fakeTCPRealHostContract) {
	t.Helper()
	canonical, err := filepath.EvalSymlinks(contract.tempRoot)
	if err != nil {
		t.Fatalf("resolve reviewed FakeTCP real-host temp root: %v", err)
	}
	if canonical != contract.tempRoot {
		t.Fatalf("reviewed FakeTCP real-host temp root resolves to %s", canonical)
	}
	var stat unix.Stat_t
	if err := unix.Lstat(contract.tempRoot, &stat); err != nil {
		t.Fatalf("inspect reviewed FakeTCP real-host temp root: %v", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != 0 || stat.Nlink < 2 || stat.Mode&0o077 != 0 {
		t.Fatalf("reviewed FakeTCP real-host temp root has unsafe identity mode=%#o uid=%d nlink=%d",
			stat.Mode, stat.Uid, stat.Nlink)
	}
}

func validateFakeTCPRealHostOwnedVethPair(t *testing.T, contract fakeTCPRealHostContract) {
	t.Helper()
	selfNetNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	initialNetNS, err := os.Readlink("/proc/1/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	if selfNetNS != initialNetNS || !strings.HasPrefix(selfNetNS, "net:[") {
		t.Fatalf("FakeTCP real-host test is not in the initial network namespace: self=%s pid1=%s",
			selfNetNS, initialNetNS)
	}
	for _, endpoint := range []struct {
		ifindex     int
		name        string
		alias       string
		peerIfindex int
	}{
		{contract.ifindex, contract.vethName, contract.vethAlias, contract.peerIfindex},
		{contract.peerIfindex, contract.peerVethName, contract.peerVethAlias, contract.ifindex},
	} {
		link, err := netlink.LinkByIndex(endpoint.ifindex)
		if err != nil {
			t.Fatalf("resolve reviewed veth ifindex %d: %v", endpoint.ifindex, err)
		}
		attrs := link.Attrs()
		if attrs == nil || attrs.Index != endpoint.ifindex || attrs.Name != endpoint.name ||
			attrs.Alias != endpoint.alias || link.Type() != "veth" || attrs.Flags&net.FlagUp == 0 ||
			len(attrs.HardwareAddr) != 6 {
			t.Fatalf("reviewed veth identity mismatch: link=%T attrs=%#v want ifindex=%d name=%s alias=%s",
				link, attrs, endpoint.ifindex, endpoint.name, endpoint.alias)
		}
		iflinkPath := filepath.Join("/sys/class/net", endpoint.name, "iflink")
		iflinkBytes, err := os.ReadFile(iflinkPath)
		if err != nil {
			t.Fatalf("read reviewed veth peer identity %s: %v", iflinkPath, err)
		}
		iflink := strings.TrimSuffix(string(iflinkBytes), "\n")
		parsed, err := parseFakeTCPRealHostIfindex("veth iflink", iflink)
		if err != nil || parsed != endpoint.peerIfindex {
			t.Fatalf("reviewed veth %s iflink=%q error=%v, want %d",
				endpoint.name, iflink, err, endpoint.peerIfindex)
		}
	}
}

func buildFakeTCPRealHostRuntime(
	ctx context.Context,
	t *testing.T,
	prepared fakeTCPRealHostPrepared,
	withXOR bool,
	leaseSuffix string,
) (*ExperimentalFakeTCPRuntime, *fakeTCPRealHostSlowPath) {
	t.Helper()
	generationText := prepared.contract.resourceID
	generation, err := strconv.ParseUint(generationText, 16, 32)
	if err != nil || generation == 0 {
		t.Fatalf("derive FakeTCP real-host generation from %s: %v", generationText, err)
	}
	generation++
	state := fakeTCPRealHostState(prepared.contract, generation, withXOR)
	baselineSnapshot, err := abi.FromStateWithGeneration(state, generation)
	if err != nil {
		t.Fatal(err)
	}
	policyPlan, err := buildFakeTCPPolicyGenerationPlan(state, generation)
	if err != nil {
		t.Fatal(err)
	}

	leaseBase := "faketcp-" + prepared.contract.resourceID + "-" + leaseSuffix
	leasePath := filepath.Join(prepared.contract.tempRoot, leaseBase+".lease")
	maintenancePath := filepath.Join(prepared.contract.tempRoot, leaseBase+".maintenance")
	leaseCtx := lockfile.WithLifecyclePathsForTest(ctx, leasePath, maintenancePath)
	lease, err := lockfile.AcquireLifecycle(leaseCtx, lockfile.LifecycleOwner{
		PID: os.Getpid(), Action: "faketcp-realhost-" + leaseSuffix, RunDir: prepared.contract.tempRoot,
	})
	if err != nil {
		t.Fatalf("acquire run-owned FakeTCP lifecycle lease: %v", err)
	}
	isolation := &fakeTCPRealHostGenerationIsolation{
		generation: generation,
		ifindexes:  []int{prepared.contract.ifindex, prepared.contract.peerIfindex},
	}
	transaction, err := newFakeTCPPolicyGenerationTransaction(leaseCtx, policyPlan, lease, isolation)
	if err != nil {
		closeErr := lease.Close()
		t.Fatalf("create FakeTCP real-host generation transaction: %v", errors.Join(err, closeErr))
	}
	if err := lease.Close(); err != nil {
		transactionErr := transaction.Close()
		t.Fatalf("release caller copy of FakeTCP lifecycle lease: %v", errors.Join(err, transactionErr))
	}

	dependencies := liveExperimentalCollectionAcquisitionDependencies()
	newOwner := dependencies.newOwner
	dependencies.newOwner = func(collection *ebpf.Collection) (*experimentalCollectionOwner, error) {
		owner, ownerErr := newOwner(collection)
		if owner != nil {
			ownerErr = errors.Join(ownerErr, isolation.bind(owner))
		}
		return owner, ownerErr
	}
	slowPath := newFakeTCPRealHostSlowPath()
	runtime, err := acquireAndBuildExperimentalFakeTCPRuntime(
		leaseCtx,
		prepared.experimentalSpec.Copy(),
		prepared.contract.experimentalObject,
		dependencies,
		experimentalFakeTCPRuntimeBuildOptions{
			transaction:      transaction,
			baselineSnapshot: baselineSnapshot,
			attachState:      state,
			xdpRequests: []fakeTCPXDPAttachRequest{
				{IfIndex: prepared.contract.ifindex, Mode: fakeTCPXDPAttachGeneric},
				{IfIndex: prepared.contract.peerIfindex, Mode: fakeTCPXDPAttachGeneric},
			},
			xdpRuntime:     liveFakeTCPXDPRuntime,
			xdpRequirement: fakeTCPXDPAllowSelectedModeTestOnly,
			engineOptions:  fakeTCPRealHostEngineOptions(generation),
			slowPathFactory: func(_ *faketcp.Engine, events *ebpf.Map) (experimentalSlowPath, error) {
				if events == nil {
					return nil, errors.New("FakeTCP real-host events map is nil")
				}
				info, err := events.Info()
				if err != nil {
					return nil, fmt.Errorf("inspect FakeTCP real-host events map: %w", err)
				}
				if info.Name != "faketcp_events" {
					return nil, fmt.Errorf("FakeTCP real-host events map name=%q", info.Name)
				}
				return slowPath, nil
			},
		},
	)
	if err != nil {
		if runtime != nil {
			err = errors.Join(err, runtime.Close())
		}
		t.Fatalf("build FakeTCP real-host runtime: %v", err)
	}
	if runtime == nil {
		t.Fatal("build FakeTCP real-host runtime returned nil")
	}
	return runtime, slowPath
}

func fakeTCPRealHostState(
	contract fakeTCPRealHostContract,
	generation uint64,
	withXOR bool,
) *control.State {
	const (
		profileID = uint32(1)
		cipherID  = uint32(1)
		wgID      = uint32(1)
	)
	state := &control.State{
		Generation: generation,
		Profiles: []control.ProfileState{{
			ID: profileID, Name: "realhost",
			StandardToMixed: [4]uint32{0xa1b2c3d4, 0xb2c3d4e5, 0xc3d4e5f6, 0x13dff06b},
			MixedToStandard: [4]uint32{1, 2, 3, 4},
		}},
		WireGuards: []control.WireGuardState{{
			ID: wgID, Name: "realhost", ProfileID: profileID,
			TransportMode: "faketcp", FakeTCPExperimental: true,
			FakeTCPChecksumMode: config.FakeTCPChecksumModePartialCompleteReset,
			FakeTCPIngressMode:  "xdp-required", FakeTCPSYNRateIntervalNanos: int64(20 * time.Millisecond),
			FakeTCPSYNBurst: 4,
		}},
		Underlays: []control.UnderlayState{
			{ID: 1, Name: contract.vethName, IfName: contract.vethName, LinkType: "veth", Parser: "ethernet", IfIndex: contract.ifindex, Role: "transform", Resolved: true},
			{ID: 2, Name: contract.peerVethName, IfName: contract.peerVethName, LinkType: "veth", Parser: "ethernet", IfIndex: contract.peerIfindex, Role: "transform", Resolved: true},
		},
	}
	selectedCipher := uint32(0)
	if withXOR {
		selectedCipher = cipherID
		var key [256]byte
		for index := range key {
			key[index] = byte(index*17 + 5)
		}
		state.Ciphers = []control.CipherState{{
			ID: cipherID, Name: "realhost-xor", Mode: "xor", Auth: "none",
			Scope: "wg-payload-full", KeyDerivation: "wgmx-hkdf256-v1",
			KeyLen: 256, KeyMask: 255, MaxBytes: 2048, Key: key,
		}}
		state.WireGuards[0].CipherID = cipherID
	}
	for _, endpoint := range []struct {
		ifindex         int
		sourcePort      uint16
		destinationPort uint16
	}{
		{contract.ifindex, 31001, 31001},
		{contract.peerIfindex, 31002, 31002},
	} {
		state.EgressRules = append(state.EgressRules, control.EgressRule{
			Generation: generation, Family: "ipv4", SourcePort: endpoint.sourcePort,
			UnderlayIfIndex: endpoint.ifindex, ProfileID: profileID, CipherID: selectedCipher,
			WGID: wgID, Action: "rewrite", TransportMode: "faketcp",
		})
		state.IngressListeners = append(state.IngressListeners, control.IngressListener{
			Generation: generation, Family: "ipv4", DestinationPort: endpoint.destinationPort,
			UnderlayIfIndex: endpoint.ifindex, ProfileID: profileID, CipherID: selectedCipher,
			WGID: wgID, Action: "rewrite", TransportMode: "faketcp",
		})
	}
	if withXOR {
		// The shape-valid GSO rejection probe is deliberately one-way. There is
		// no peer listener for 31102, so any accidental AF_PACKET no-route pass
		// remains directly observable before an inverse transform can hide it.
		state.EgressRules = append(state.EgressRules, control.EgressRule{
			Generation: generation, Family: "ipv4", SourcePort: fakeTCPRealHostGSOSourcePort,
			UnderlayIfIndex: contract.ifindex, ProfileID: profileID, CipherID: selectedCipher,
			WGID: wgID, Action: "rewrite", TransportMode: "faketcp",
		})
	}
	return state
}

func fakeTCPRealHostEngineOptions(generation uint64) faketcp.Options {
	return faketcp.Options{
		Generation: generation, SessionCapacity: 32,
		MaxHalfOpenSessions: 16, MaxHalfOpenPerSource: 4,
		SYNRateInterval: 20 * time.Millisecond, SYNBurst: 4, SYNBurstPerSource: 2,
		SYNSourceLedgerCapacity: 32, SYNSourceLedgerTTL: time.Second,
		MaxPendingFlows: 8, MaxPendingPacketsPerFlow: 4, MaxPendingBytes: 64 * 1024,
		HandshakeTimeout: time.Second, HandshakeRetries: 2,
		KeepaliveInterval: 5 * time.Second, IdleTimeout: 20 * time.Second,
		Window: 4096, Now: time.Now, MonotonicClock: faketcp.LinuxMonotonicClock{},
		InitialSequence: func() uint32 { return 0x01020304 },
	}
}

func snapshotFakeTCPRealHostKernel(
	t *testing.T,
	contract fakeTCPRealHostContract,
) fakeTCPRealHostKernelSnapshot {
	t.Helper()
	snapshot := fakeTCPRealHostKernelSnapshot{
		xdp: make(map[int]fakeTCPXDPProbe, 2),
		tcx: make(map[fakeTCPRealHostTCXSlot][]fakeTCPRealHostTCXProgram, 4),
	}
	for _, ifindex := range []int{contract.ifindex, contract.peerIfindex} {
		probe, err := probeLiveFakeTCPXDP(ifindex)
		if err != nil {
			t.Fatalf("probe FakeTCP real-host XDP ifindex %d: %v", ifindex, err)
		}
		snapshot.xdp[ifindex] = probe
		for _, attach := range []ebpf.AttachType{ebpf.AttachTCXIngress, ebpf.AttachTCXEgress} {
			programs, err := queryFakeTCPRealHostTCX(ifindex, attach)
			if err != nil {
				t.Fatal(err)
			}
			snapshot.tcx[fakeTCPRealHostTCXSlot{ifindex: ifindex, attach: attach}] = programs
		}
	}
	return snapshot
}

func queryFakeTCPRealHostTCX(
	ifindex int,
	attach ebpf.AttachType,
) ([]fakeTCPRealHostTCXProgram, error) {
	result, err := ciliumlink.QueryPrograms(ciliumlink.QueryOptions{Target: ifindex, Attach: attach})
	if err != nil {
		return nil, fmt.Errorf("query FakeTCP real-host TCX %s ifindex %d: %w", attach, ifindex, err)
	}
	if result == nil || result.Revision == 0 {
		return nil, fmt.Errorf("query FakeTCP real-host TCX %s ifindex %d returned no revision fence", attach, ifindex)
	}
	programs := make([]fakeTCPRealHostTCXProgram, 0, len(result.Programs))
	for _, attached := range result.Programs {
		linkID, ok := attached.LinkID()
		if !ok || linkID == 0 || attached.ID == 0 {
			return nil, fmt.Errorf("query FakeTCP real-host TCX %s ifindex %d returned incomplete identity", attach, ifindex)
		}
		programs = append(programs, fakeTCPRealHostTCXProgram{
			programID: uint32(attached.ID), linkID: uint32(linkID),
		})
	}
	return programs, nil
}

func assertFakeTCPRealHostKernelEmpty(t *testing.T, contract fakeTCPRealHostContract) {
	t.Helper()
	snapshot := snapshotFakeTCPRealHostKernel(t, contract)
	for ifindex, probe := range snapshot.xdp {
		if probe.Attached || probe.ProgramID != 0 {
			t.Fatalf("run-owned veth ifindex %d already has XDP identity %#v", ifindex, probe)
		}
	}
	for slot, programs := range snapshot.tcx {
		if len(programs) != 0 {
			t.Fatalf("run-owned veth TCX slot %#v already has programs %#v", slot, programs)
		}
	}
}

func assertFakeTCPRealHostRuntimeAttached(
	t *testing.T,
	contract fakeTCPRealHostContract,
) fakeTCPRealHostKernelSnapshot {
	t.Helper()
	snapshot := snapshotFakeTCPRealHostKernel(t, contract)
	for ifindex, probe := range snapshot.xdp {
		if !probe.Attached || probe.ProgramID == 0 {
			t.Fatalf("FakeTCP runtime has no exact XDP identity on ifindex %d: %#v", ifindex, probe)
		}
	}
	for slot, programs := range snapshot.tcx {
		if len(programs) != 1 || programs[0].programID == 0 || programs[0].linkID == 0 {
			t.Fatalf("FakeTCP runtime TCX slot %#v identities=%#v, want exactly one", slot, programs)
		}
	}
	return snapshot
}

func installFakeTCPRealHostSessions(
	t *testing.T,
	handles ExperimentalFakeTCPRuntimeHandles,
	generation uint64,
	contract fakeTCPRealHostContract,
) {
	t.Helper()
	runtimeIncarnation := [16]byte(handles.Identity().Incarnation)
	localA, err := faketcp.RawIPv4BE32(netip.MustParseAddr("10.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	localB, err := faketcp.RawIPv4BE32(netip.MustParseAddr("10.0.0.2"))
	if err != nil {
		t.Fatal(err)
	}
	for index, session := range []struct {
		key   abi.FakeTCPSessionKey
		value abi.FakeTCPSessionValue
	}{
		{
			key: abi.FakeTCPSessionKey{
				Generation: generation, LocalIPv4: localA, RemoteIPv4: localB,
				UnderlayIndex: uint32(contract.ifindex), LocalPort: 31001, RemotePort: 31002,
			},
			value: abi.FakeTCPSessionValue{
				Generation: generation, TXSequence: 0x01020304, RXSequence: 0x11223344,
				Window: 4096, State: abi.FakeTCPStateEstablished, Revision: 1,
				RuntimeIncarnation: runtimeIncarnation,
			},
		},
		{
			key: abi.FakeTCPSessionKey{
				Generation: generation, LocalIPv4: localB, RemoteIPv4: localA,
				UnderlayIndex: uint32(contract.peerIfindex), LocalPort: 31002, RemotePort: 31001,
			},
			value: abi.FakeTCPSessionValue{
				Generation: generation, TXSequence: 0x11223344, RXSequence: 0x01020304,
				Window: 4096, State: abi.FakeTCPStateEstablished, Revision: 1,
				RuntimeIncarnation: runtimeIncarnation,
			},
		},
		{
			// One-way local session only: never install the peer reverse session.
			key: abi.FakeTCPSessionKey{
				Generation: generation, LocalIPv4: localA, RemoteIPv4: localB,
				UnderlayIndex: uint32(contract.ifindex),
				LocalPort:     fakeTCPRealHostGSOSourcePort,
				RemotePort:    fakeTCPRealHostGSODestinationPort,
			},
			value: abi.FakeTCPSessionValue{
				Generation: generation, TXSequence: 0x55667788, RXSequence: 0x99aabbcc,
				Window: 4096, State: abi.FakeTCPStateEstablished, Revision: 1,
				RuntimeIncarnation: runtimeIncarnation,
			},
		},
	} {
		session.value.SessionID = uint64(index + 1)
		if err := handles.SessionStore().InsertEstablished(session.key, session.value); err != nil {
			t.Fatalf("insert FakeTCP real-host established session %#v: %v", session.key, err)
		}
	}
}

func buildFakeTCPRealHostProbePacket(
	t *testing.T,
	destinationMAC net.HardwareAddr,
	sourceMAC net.HardwareAddr,
	payloadLength int,
) ([]byte, []byte) {
	t.Helper()
	if len(destinationMAC) != 6 || len(sourceMAC) != 6 {
		t.Fatalf("FakeTCP real-host probe requires exact Ethernet addresses: destination=%x source=%x",
			destinationMAC, sourceMAC)
	}
	packet, payload := buildFakeTCPProbeUDPPacket(t, 31001, 31002, payloadLength)
	copy(packet[0:6], destinationMAC)
	copy(packet[6:12], sourceMAC)
	return packet, payload
}

func buildFakeTCPRealHostGSOProbePacket(
	t *testing.T,
	destinationMAC net.HardwareAddr,
	sourceMAC net.HardwareAddr,
) []byte {
	t.Helper()
	if len(destinationMAC) != 6 || len(sourceMAC) != 6 {
		t.Fatalf("FakeTCP real-host GSO probe requires exact Ethernet addresses: destination=%x source=%x",
			destinationMAC, sourceMAC)
	}
	payloadLength := int(fakeTCPRealHostVirtioGSOSize) * 2
	packet, payload := buildFakeTCPProbeUDPPacket(
		t, fakeTCPRealHostGSOSourcePort, fakeTCPRealHostGSODestinationPort,
		payloadLength,
	)
	for offset := 0; offset < payloadLength; offset += int(fakeTCPRealHostVirtioGSOSize) {
		binary.LittleEndian.PutUint32(payload[offset:offset+4], 3)
	}
	copy(packet[len(packet)-payloadLength:], payload)
	copy(packet[0:6], destinationMAC)
	copy(packet[6:12], sourceMAC)
	return packet
}

func assertFakeTCPRealHostStatDeltas(
	t *testing.T,
	label string,
	before []uint64,
	after []uint64,
	want map[uint32]uint64,
) {
	t.Helper()
	if len(before) != len(after) {
		t.Fatalf("%s stat snapshot lengths differ: before=%d after=%d", label, len(before), len(after))
	}
	for key := range want {
		if int(key) >= len(before) {
			t.Fatalf("%s expected stat key %d is outside snapshot length %d", label, key, len(before))
		}
	}
	for key := range before {
		expected := before[key] + want[uint32(key)]
		if after[key] != expected {
			t.Fatalf("%s stat %d=%d, want %d (delta %d)",
				label, key, after[key], expected, want[uint32(key)])
		}
	}
}

func readFakeTCPRealHostStats(
	t *testing.T,
	runtime *ExperimentalFakeTCPRuntime,
	mapName string,
	count int,
) []uint64 {
	t.Helper()
	if runtime == nil || runtime.state == nil || runtime.state.collection == nil {
		t.Fatal("FakeTCP real-host runtime collection is unavailable")
	}
	if count <= 0 {
		t.Fatalf("invalid FakeTCP real-host stat count %d", count)
	}
	stats, err := runtime.state.collection.mapResource(mapName)
	if err != nil {
		t.Fatal(err)
	}
	possibleCPUs, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatal(err)
	}
	totals := make([]uint64, count)
	for index := range count {
		key := uint32(index)
		values := make([]uint64, possibleCPUs)
		if err := stats.Lookup(&key, &values); err != nil {
			t.Fatalf("read FakeTCP real-host map %s stat %d: %v", mapName, key, err)
		}
		for _, value := range values {
			totals[index] += value
		}
	}
	return totals
}

func waitForFakeTCPRealHostStat(
	t *testing.T,
	runtime *ExperimentalFakeTCPRuntime,
	mapName string,
	key uint32,
	want uint64,
) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		values := readFakeTCPRealHostStats(t, runtime, mapName, int(key)+1)
		if values[key] == want {
			return
		}
		if values[key] > want || time.Now().After(deadline) {
			t.Fatalf("FakeTCP real-host map %s stat %d=%d, want %d", mapName, key, values[key], want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func openFakeTCPRealHostPacketSocket(t *testing.T, ifindex int) int {
	t.Helper()
	protocol := fakeTCPRealHostHTONS(unix.ETH_P_ALL)
	fd, err := unix.Socket(
		unix.AF_PACKET,
		unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK,
		int(protocol),
	)
	if err != nil {
		t.Fatalf("open run-owned veth packet socket: %v", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: protocol, Ifindex: ifindex}); err != nil {
		closeErr := unix.Close(fd)
		t.Fatalf("bind run-owned veth packet socket: %v", errors.Join(err, closeErr))
	}
	return fd
}

func openFakeTCPRealHostVNetPacketSocket(t *testing.T, ifindex int) int {
	t.Helper()
	fd := openFakeTCPRealHostPacketSocket(t, ifindex)
	if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_VNET_HDR, 1); err != nil {
		closeErr := unix.Close(fd)
		t.Fatalf("enable PACKET_VNET_HDR on run-owned veth socket: %v", errors.Join(err, closeErr))
	}
	enabled, err := unix.GetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_VNET_HDR)
	if err != nil {
		closeErr := unix.Close(fd)
		t.Fatalf("verify PACKET_VNET_HDR on run-owned veth socket: %v", errors.Join(err, closeErr))
	}
	headerSize, err := unix.GetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_VNET_HDR_SZ)
	if err != nil {
		closeErr := unix.Close(fd)
		t.Fatalf("read PACKET_VNET_HDR_SZ on run-owned veth socket: %v", errors.Join(err, closeErr))
	}
	if enabled != 1 || headerSize != fakeTCPRealHostVirtioNetHeaderSize {
		closeErr := unix.Close(fd)
		t.Fatalf("PACKET_VNET_HDR contract enabled=%d size=%d, want enabled=1 size=%d: %v",
			enabled, headerSize, fakeTCPRealHostVirtioNetHeaderSize, closeErr)
	}
	return fd
}

func prependFakeTCPRealHostVirtioNetHeader(
	t *testing.T,
	packet []byte,
	gsoType uint8,
	gsoSize uint16,
) []byte {
	t.Helper()
	if len(packet) <= fakeTCPRealHostVirtioHeaderLength {
		t.Fatalf("FakeTCP real-host virtio frame is too short: %d", len(packet))
	}
	switch gsoType {
	case unix.VIRTIO_NET_HDR_GSO_NONE:
		if gsoSize != 0 {
			t.Fatalf("non-GSO virtio frame has GSO size %d", gsoSize)
		}
	case unix.VIRTIO_NET_HDR_GSO_UDP_L4:
		if gsoSize == 0 || len(packet)-fakeTCPRealHostVirtioHeaderLength <= int(gsoSize) {
			t.Fatalf("UDP L4 GSO frame payload=%d size=%d does not represent multiple segments",
				len(packet)-fakeTCPRealHostVirtioHeaderLength, gsoSize)
		}
	default:
		t.Fatalf("unsupported FakeTCP real-host virtio GSO type %d", gsoType)
	}
	header := make([]byte, fakeTCPRealHostVirtioNetHeaderSize)
	header[0] = unix.VIRTIO_NET_HDR_F_NEEDS_CSUM
	header[1] = gsoType
	binary.LittleEndian.PutUint16(header[2:4], uint16(fakeTCPRealHostVirtioHeaderLength))
	binary.LittleEndian.PutUint16(header[4:6], gsoSize)
	binary.LittleEndian.PutUint16(header[6:8], uint16(fakeTCPRealHostVirtioChecksumStart))
	binary.LittleEndian.PutUint16(header[8:10], fakeTCPRealHostVirtioChecksumOffset)
	return append(header, packet...)
}

func sendFakeTCPRealHostDropProbe(t *testing.T, fd, ifindex int, packet []byte) {
	t.Helper()
	err := unix.Sendto(fd, packet, 0, &unix.SockaddrLinklayer{
		Protocol: fakeTCPRealHostHTONS(unix.ETH_P_IP),
		Ifindex:  ifindex,
	})
	switch {
	case err == nil:
		t.Log("FAKETCP_REALHOST_AF_PACKET_DROP_SEND result=nil")
	case errors.Is(err, unix.ENOBUFS):
		t.Log("FAKETCP_REALHOST_AF_PACKET_DROP_SEND result=ENOBUFS")
	default:
		t.Fatalf("send run-owned veth no-route probe: %v", err)
	}
}

func closeFakeTCPRealHostFD(t *testing.T, fd int, label string) {
	t.Helper()
	if fd >= 0 {
		if err := unix.Close(fd); err != nil {
			t.Errorf("close %s: %v", label, err)
		}
	}
}

func receiveFakeTCPRealHostFlowPacket(
	ctx context.Context,
	fd int,
	sourcePort uint16,
	destinationPort uint16,
) ([]byte, error) {
	return receiveFakeTCPRealHostPacket(ctx, fd, func(frame []byte) bool {
		return fakeTCPRealHostFlowFrameMatches(frame, sourcePort, destinationPort)
	})
}

func receiveFakeTCPRealHostPacket(
	ctx context.Context,
	fd int,
	match func([]byte) bool,
) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("receive FakeTCP real-host packet: context is nil")
	}
	if match == nil {
		return nil, errors.New("receive FakeTCP real-host packet: matcher is nil")
	}
	buffer := make([]byte, 4096)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		deadline, ok := ctx.Deadline()
		if !ok {
			return nil, errors.New("receive FakeTCP real-host packet: context has no deadline")
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, context.DeadlineExceeded
		}
		timeout := int(remaining / time.Millisecond)
		if timeout < 1 {
			timeout = 1
		}
		if timeout > 1000 {
			timeout = 1000
		}
		pollFDs := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		count, err := unix.Poll(pollFDs, timeout)
		if errors.Is(err, unix.EINTR) || count == 0 {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("poll FakeTCP real-host packet socket: %w", err)
		}
		if pollFDs[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return nil, fmt.Errorf("poll FakeTCP real-host packet socket returned events %#x", pollFDs[0].Revents)
		}
		length, _, err := unix.Recvfrom(fd, buffer, unix.MSG_DONTWAIT)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("receive FakeTCP real-host packet: %w", err)
		}
		frame := buffer[:length]
		if match(frame) {
			return append([]byte(nil), frame...), nil
		}
	}
}

func assertNoFakeTCPRealHostFlowPacket(
	t *testing.T,
	parent context.Context,
	fd int,
	sourcePort uint16,
	destinationPort uint16,
) {
	t.Helper()
	receiveCtx, stopReceive := context.WithTimeout(parent, 750*time.Millisecond)
	defer stopReceive()
	received, err := receiveFakeTCPRealHostFlowPacket(
		receiveCtx, fd, sourcePort, destinationPort,
	)
	if err == nil {
		t.Fatalf("no-route FakeTCP flow reached peer: %x", received)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("observe no-route FakeTCP flow: %v", err)
	}
}

func fakeTCPRealHostFlowFrameMatches(
	frame []byte,
	sourcePort uint16,
	destinationPort uint16,
) bool {
	if len(frame) < fakeTCPRealHostEthernetHeaderSize+fakeTCPRealHostIPv4HeaderSize ||
		frame[12] != 0x08 || frame[13] != 0x00 {
		return false
	}
	ip := frame[fakeTCPRealHostEthernetHeaderSize:]
	if ip[0] != 0x45 || (ip[9] != 6 && ip[9] != 17) ||
		!bytes.Equal(ip[12:16], []byte{10, 0, 0, 1}) ||
		!bytes.Equal(ip[16:20], []byte{10, 0, 0, 2}) {
		return false
	}
	ipv4Length := int(binary.BigEndian.Uint16(ip[2:4]))
	if ipv4Length < fakeTCPRealHostIPv4HeaderSize+4 ||
		len(frame) < fakeTCPRealHostEthernetHeaderSize+ipv4Length {
		return false
	}
	transport := ip[fakeTCPRealHostIPv4HeaderSize:]
	if binary.BigEndian.Uint16(transport[0:2]) != sourcePort ||
		binary.BigEndian.Uint16(transport[2:4]) != destinationPort {
		return false
	}
	if ip[9] == 17 {
		if ipv4Length < fakeTCPRealHostIPv4HeaderSize+fakeTCPRealHostUDPHeaderSize {
			return false
		}
		udpLength := int(binary.BigEndian.Uint16(transport[4:6]))
		return udpLength >= fakeTCPRealHostUDPHeaderSize &&
			udpLength == ipv4Length-fakeTCPRealHostIPv4HeaderSize
	}
	if ipv4Length < fakeTCPRealHostIPv4HeaderSize+20 {
		return false
	}
	tcpHeaderLength := int(transport[12]>>4) * 4
	return tcpHeaderLength >= 20 &&
		tcpHeaderLength <= ipv4Length-fakeTCPRealHostIPv4HeaderSize
}

func fakeTCPRealHostUDPFrameMatches(
	frame []byte,
	sourcePort uint16,
	destinationPort uint16,
	payloadLength int,
) bool {
	if len(frame) < 14+20+8 || frame[12] != 0x08 || frame[13] != 0x00 {
		return false
	}
	ip := frame[14:]
	if ip[0] != 0x45 || ip[9] != 17 || !bytes.Equal(ip[12:16], []byte{10, 0, 0, 1}) ||
		!bytes.Equal(ip[16:20], []byte{10, 0, 0, 2}) {
		return false
	}
	udp := ip[20:]
	return payloadLength >= 0 &&
		int(binary.BigEndian.Uint16(ip[2:4])) == 20+8+payloadLength &&
		int(binary.BigEndian.Uint16(udp[4:6])) == 8+payloadLength &&
		uint16(udp[0])<<8|uint16(udp[1]) == sourcePort &&
		uint16(udp[2])<<8|uint16(udp[3]) == destinationPort
}

func fakeTCPRealHostHTONS(value uint16) uint16 {
	return value<<8 | value>>8
}
