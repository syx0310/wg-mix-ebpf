//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/syx0310/wg-mix-ebpf/internal/abi"
	"github.com/syx0310/wg-mix-ebpf/internal/faketcp"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	fakeTCPManagedIngressPort             = uint16(31002)
	fakeTCPManagedIngressUnmanagedPort    = uint16(32002)
	fakeTCPManagedIngressInvalidWireWord  = uint32(0xfeedface)
	fakeTCPManagedIngressFakeStatCount    = 19
	fakeTCPManagedIngressCoreStatCount    = 36
	fakeTCPManagedIngressFakeBadPacket    = uint32(4)
	fakeTCPManagedIngressFakeIngressOK    = uint32(1)
	fakeTCPManagedIngressFakeAdmissionOK  = uint32(17)
	fakeTCPManagedIngressFakeBypassReject = uint32(18)
	fakeTCPManagedIngressCoreIngressOK    = uint32(6)
	fakeTCPManagedIngressCoreRuleMiss     = uint32(7)
	fakeTCPManagedIngressCoreIPv6Ext      = uint32(11)
)

type fakeTCPManagedIngressWireExpectation uint8

const (
	fakeTCPManagedIngressWireDrop fakeTCPManagedIngressWireExpectation = iota
	fakeTCPManagedIngressWireUnchanged
	fakeTCPManagedIngressWireDecoded
	fakeTCPManagedIngressWireTestRun
)

type fakeTCPManagedIngressCell struct {
	name             string
	frame            []byte
	interfaceManaged bool
	wantDisposition  faketcp.IngressDisposition
	wantParse        faketcp.L3ParseStatus
	wire             fakeTCPManagedIngressWireExpectation
	wantFake         map[uint32]uint64
	wantCore         map[uint32]uint64
	decodedPayload   []byte
}

// TestFakeTCPRealHostManagedIngressAcceptance keeps one experimental runtime
// on the already-owned veth pair. Live cells enter the peer XDP hook from the
// wire; ambiguous unmanaged-interface cells invoke the same loaded program
// with one temporary parser key and no managed-interface latch. The Go oracle
// predicts XDP disposition; wantFake/wantCore are exact end-to-end XDP+TC
// deltas. Every cell is serial and accounts for all 19 plus all 36 counters.
func TestFakeTCPRealHostManagedIngressAcceptance(t *testing.T) {
	prepared := requireFakeTCPRealHostPrepared(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	runtime, _ := buildFakeTCPRealHostRuntime(ctx, t, prepared, false, "managed-ingress")
	closed := false
	defer func() {
		if !closed {
			if err := runtime.Close(); err != nil {
				t.Errorf("close managed-ingress FakeTCP runtime after failure: %v", err)
			}
		}
	}()
	assertFakeTCPRealHostRuntimeAttached(t, prepared.contract)

	handles, err := runtime.Handles()
	if err != nil {
		t.Fatal(err)
	}
	installFakeTCPRealHostSessions(t, handles, runtime.Generation(), prepared.contract)

	local, err := netlink.LinkByIndex(prepared.contract.ifindex)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := netlink.LinkByIndex(prepared.contract.peerIfindex)
	if err != nil {
		t.Fatal(err)
	}
	if local.Attrs() == nil || peer.Attrs() == nil {
		t.Fatal("managed-ingress veth attributes are unavailable")
	}
	sender := openFakeTCPRealHostPacketSocket(t, prepared.contract.ifindex)
	defer closeFakeTCPRealHostFD(t, sender, "managed-ingress sender")
	receiver := openFakeTCPRealHostPacketSocket(t, prepared.contract.peerIfindex)
	defer closeFakeTCPRealHostFD(t, receiver, "managed-ingress receiver")

	xdpProgram, probeIfindex, releaseParser := prepareFakeTCPManagedIngressUnmanagedProbe(
		t, runtime,
	)
	defer releaseParser()

	cells := buildFakeTCPManagedIngressCells(
		t,
		local.Attrs().HardwareAddr,
		peer.Attrs().HardwareAddr,
		fakeTCPRealHostState(prepared.contract, runtime.Generation(), false).Profiles[0].StandardToMixed[3],
	)
	for _, cell := range cells {
		t.Run(cell.name, func(t *testing.T) {
			runFakeTCPManagedIngressCell(
				t, ctx, runtime, xdpProgram, probeIfindex, sender, prepared.contract.ifindex,
				receiver, cell,
			)
		})
	}

	releaseParser()
	if err := runtime.Close(); err != nil {
		t.Fatalf("close managed-ingress FakeTCP runtime: %v", err)
	}
	closed = true
	assertFakeTCPRealHostKernelEmpty(t, prepared.contract)
	t.Logf(
		"FAKETCP_MANAGED_INGRESS_COMPLETE run_id=%s cells=%d fake_stats=19 core_stats=36 restored=1 capability_opened=1",
		prepared.contract.runID, len(cells),
	)
}

func prepareFakeTCPManagedIngressUnmanagedProbe(
	t *testing.T,
	runtime *ExperimentalFakeTCPRuntime,
) (*ebpf.Program, uint32, func()) {
	t.Helper()
	if runtime == nil || runtime.state == nil || runtime.state.collection == nil {
		t.Fatal("managed-ingress runtime collection is unavailable")
	}
	programResource, err := runtime.state.collection.programResource(fakeTCPXDPProgramName)
	if err != nil {
		t.Fatal(err)
	}
	program := programResource.kernelProgram()
	if program == nil {
		t.Fatal("managed-ingress XDP program is unavailable")
	}
	parserMap, err := runtime.state.collection.mapResource("underlay_config_map")
	if err != nil {
		t.Fatal(err)
	}
	managedInterfaces, err := runtime.state.collection.mapResource(fakeTCPManagedIfMapName)
	if err != nil {
		t.Fatal(err)
	}
	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatalf("resolve loopback for unmanaged XDP test-run context: %v", err)
	}
	if loopback.Attrs() == nil || loopback.Attrs().Index <= 0 || loopback.Attrs().Name != "lo" ||
		loopback.Attrs().Flags&net.FlagLoopback == 0 || loopback.Attrs().Flags&net.FlagUp == 0 {
		t.Fatalf("invalid loopback XDP test-run identity: link=%T attrs=%#v", loopback, loopback.Attrs())
	}
	probeIfindex := uint32(loopback.Attrs().Index)
	key := abi.UnderlayConfigKey{
		Generation: runtime.Generation(), UnderlayIndex: probeIfindex,
	}
	var existing abi.UnderlayConfigValue
	if err := parserMap.Lookup(key, &existing); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("managed-ingress probe parser key preexists: value=%#v error=%v", existing, err)
	}
	managedKey := abi.FakeTCPManagedIfKey{
		Generation: runtime.Generation(), UnderlayIndex: probeIfindex,
	}
	var managed abi.FakeTCPManagedIfValue
	if err := managedInterfaces.Lookup(managedKey, &managed); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("managed-ingress probe interface is unexpectedly managed: value=%#v error=%v", managed, err)
	}
	if err := parserMap.Update(key, abi.UnderlayConfigValue{
		Generation: runtime.Generation(), ParserMode: abi.ParserEthernet,
	}, ebpf.UpdateNoExist); err != nil {
		t.Fatalf("install unmanaged probe Ethernet parser key: %v", err)
	}
	released := false
	release := func() {
		if released {
			return
		}
		released = true
		if err := parserMap.Delete(key); err != nil {
			t.Errorf("delete unmanaged probe Ethernet parser key: %v", err)
			return
		}
		if err := parserMap.Lookup(key, &existing); !errors.Is(err, ebpf.ErrKeyNotExist) {
			t.Errorf("unmanaged probe Ethernet parser key remains: value=%#v error=%v", existing, err)
		}
	}
	return program, probeIfindex, release
}

func runFakeTCPManagedIngressCell(
	t *testing.T,
	ctx context.Context,
	runtime *ExperimentalFakeTCPRuntime,
	xdpProgram *ebpf.Program,
	probeIfindex uint32,
	sender int,
	senderIfindex int,
	receiver int,
	cell fakeTCPManagedIngressCell,
) {
	t.Helper()
	assertFakeTCPManagedIngressOracle(t, cell)
	fakeBefore := readFakeTCPRealHostStats(
		t, runtime, "faketcp_stats_map", fakeTCPManagedIngressFakeStatCount,
	)
	coreBefore := readFakeTCPRealHostStats(
		t, runtime, "stats_map", fakeTCPManagedIngressCoreStatCount,
	)

	if cell.wire == fakeTCPManagedIngressWireTestRun {
		result, output, err := runFakeTCPPacketProbe(
			xdpProgram,
			cell.frame,
			fakeTCPXDPContext{IngressIfindex: probeIfindex},
			len(cell.frame)+64,
		)
		if err != nil {
			t.Fatalf("run unmanaged managed-ingress XDP cell: %v", err)
		}
		if result != uint32(2) || !bytes.Equal(output, cell.frame) {
			t.Fatalf("unmanaged XDP result=%d output=%x, want XDP_PASS and exact wire=%x",
				result, output, cell.frame)
		}
	} else {
		sendFakeTCPManagedIngressFrame(t, sender, senderIfindex, cell.frame)
		observed := observeFakeTCPManagedIngressFrame(t, ctx, receiver, cell.frame[6:12], cell.wire)
		switch cell.wire {
		case fakeTCPManagedIngressWireDrop:
			if observed != nil {
				t.Fatalf("managed frame leaked to host packet tap: %x", observed)
			}
		case fakeTCPManagedIngressWireUnchanged:
			if !bytes.Equal(observed, cell.frame) {
				t.Fatalf("unmanaged wire changed: got=%x want=%x", observed, cell.frame)
			}
		case fakeTCPManagedIngressWireDecoded:
			assertFakeTCPManagedIngressDecoded(t, observed, cell.decodedPayload)
		default:
			t.Fatalf("unsupported managed-ingress wire expectation %d", cell.wire)
		}
	}

	fakeAfter, coreAfter := waitFakeTCPManagedIngressStatDeltas(
		t, runtime, fakeBefore, coreBefore, cell.wantFake, cell.wantCore,
	)
	assertFakeTCPRealHostStatDeltas(t, "managed-ingress FakeTCP", fakeBefore, fakeAfter, cell.wantFake)
	assertFakeTCPRealHostStatDeltas(t, "managed-ingress core", coreBefore, coreAfter, cell.wantCore)
}

func waitFakeTCPManagedIngressStatDeltas(
	t *testing.T,
	runtime *ExperimentalFakeTCPRuntime,
	fakeBefore, coreBefore []uint64,
	wantFake, wantCore map[uint32]uint64,
) ([]uint64, []uint64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	settledAt := time.Now().Add(20 * time.Millisecond)
	for {
		fakeAfter := readFakeTCPRealHostStats(
			t, runtime, "faketcp_stats_map", fakeTCPManagedIngressFakeStatCount,
		)
		coreAfter := readFakeTCPRealHostStats(
			t, runtime, "stats_map", fakeTCPManagedIngressCoreStatCount,
		)
		fakePending, err := fakeTCPRoutedExactStatDeltas(fakeBefore, fakeAfter, wantFake)
		if err != nil {
			t.Fatalf("managed-ingress FakeTCP stats: %v", err)
		}
		corePending, err := fakeTCPRoutedExactStatDeltas(coreBefore, coreAfter, wantCore)
		if err != nil {
			t.Fatalf("managed-ingress core stats: %v", err)
		}
		if !fakePending && !corePending && time.Now().After(settledAt) {
			return fakeAfter, coreAfter
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for exact managed-ingress stat deltas")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func assertFakeTCPManagedIngressOracle(t *testing.T, cell fakeTCPManagedIngressCell) {
	t.Helper()
	policy := faketcp.ManagedIngressPolicy{
		InterfaceManaged: cell.interfaceManaged,
		Ports:            map[uint16]struct{}{fakeTCPManagedIngressPort: {}},
	}
	if got := faketcp.ClassifyManagedIngressFrame(cell.frame, policy); got != cell.wantDisposition {
		t.Fatalf("ClassifyManagedIngressFrame=%d, want %d", got, cell.wantDisposition)
	}
	if len(cell.frame) < fakeTCPRealHostEthernetHeaderSize {
		t.Fatalf("managed-ingress oracle frame is shorter than Ethernet: %d", len(cell.frame))
	}
	_, status := faketcp.ParseL3(cell.frame[fakeTCPRealHostEthernetHeaderSize:])
	if status != cell.wantParse {
		t.Fatalf("ParseL3=%d, want %d", status, cell.wantParse)
	}
}

func sendFakeTCPManagedIngressFrame(t *testing.T, fd, ifindex int, frame []byte) {
	t.Helper()
	if len(frame) < fakeTCPRealHostEthernetHeaderSize {
		t.Fatalf("managed-ingress frame is shorter than Ethernet: %d", len(frame))
	}
	protocol := fakeTCPRealHostHTONS(binary.BigEndian.Uint16(frame[12:14]))
	err := unix.Sendto(fd, frame, 0, &unix.SockaddrLinklayer{
		Protocol: protocol,
		Ifindex:  ifindex,
	})
	if err != nil && !errors.Is(err, unix.ENOBUFS) {
		t.Fatalf("send managed-ingress frame: %v", err)
	}
}

func observeFakeTCPManagedIngressFrame(
	t *testing.T,
	parent context.Context,
	fd int,
	sourceMAC []byte,
	want fakeTCPManagedIngressWireExpectation,
) []byte {
	t.Helper()
	timeout := 2 * time.Second
	if want == fakeTCPManagedIngressWireDrop {
		timeout = 150 * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	frame, err := receiveFakeTCPRealHostPacket(ctx, fd, func(candidate []byte) bool {
		return len(candidate) >= fakeTCPRealHostEthernetHeaderSize &&
			bytes.Equal(candidate[6:12], sourceMAC)
	})
	if want == fakeTCPManagedIngressWireDrop {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil
		}
		if err != nil {
			t.Fatalf("observe managed-ingress drop: %v", err)
		}
		return frame
	}
	if err != nil {
		t.Fatalf("observe managed-ingress pass: %v", err)
	}
	return frame
}

func assertFakeTCPManagedIngressDecoded(t *testing.T, frame, originalPayload []byte) {
	t.Helper()
	if len(frame) < 14+20+8 || binary.BigEndian.Uint16(frame[12:14]) != unix.ETH_P_IP {
		t.Fatalf("decoded managed-ingress frame has invalid Ethernet/IPv4 shape: %x", frame)
	}
	ipv4 := frame[14:]
	totalLength := int(binary.BigEndian.Uint16(ipv4[2:4]))
	if ipv4[0] != 0x45 || ipv4[9] != unix.IPPROTO_UDP ||
		totalLength != 20+8+len(originalPayload) || len(ipv4) != totalLength ||
		internetChecksum(ipv4[:20]) != 0 {
		t.Fatalf("decoded managed-ingress IPv4 header=%x total=%d frame=%d", ipv4[:20], totalLength, len(ipv4))
	}
	info, status := faketcp.ParseL3(ipv4)
	if status != faketcp.L3ParseOK || info.Family != faketcp.L3FamilyIPv4 ||
		info.TransportProtocol != faketcp.L3ProtocolUDP || info.L3HeaderLength != 20 ||
		info.L4HeaderLength != 8 {
		t.Fatalf("decoded ParseL3 status=%d info=%#v", status, info)
	}
	udp := ipv4[20:]
	if binary.BigEndian.Uint16(udp[0:2]) != 31001 ||
		binary.BigEndian.Uint16(udp[2:4]) != fakeTCPManagedIngressPort ||
		int(binary.BigEndian.Uint16(udp[4:6])) != 8+len(originalPayload) {
		t.Fatalf("decoded managed-ingress UDP header=%x", udp[:8])
	}
	// AF_PACKET ptype taps run after generic XDP and before TCX ingress. The
	// exact mixed payload is therefore the XDP wire boundary; AdmissionAccept
	// plus the core ingress-rewrite counter prove the later standard rewrite.
	if !bytes.Equal(udp[8:], originalPayload) {
		t.Fatalf("decoded managed-ingress payload=%x, want=%x", udp[8:], originalPayload)
	}
	if fakeTCPRoutedTransportChecksumResidual(
		netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"),
		unix.IPPROTO_UDP, udp,
	) != 0 {
		t.Fatalf("decoded managed-ingress UDP checksum is invalid: %x", udp)
	}
}

func buildFakeTCPManagedIngressCells(
	t *testing.T,
	senderMAC net.HardwareAddr,
	receiverMAC net.HardwareAddr,
	mixedType uint32,
) []fakeTCPManagedIngressCell {
	t.Helper()
	if len(senderMAC) != 6 || len(receiverMAC) != 6 || mixedType == 0 {
		t.Fatalf("invalid managed-ingress link/profile identity: sender=%x receiver=%x mixed=%#x",
			senderMAC, receiverMAC, mixedType)
	}
	cellSource := func(index byte) net.HardwareAddr {
		mac := append(net.HardwareAddr(nil), senderMAC...)
		mac[0], mac[1], mac[5] = 0x02, 0xfa, index
		return mac
	}
	frame := func(index byte, etherType uint16, l3 []byte) []byte {
		return fakeTCPManagedIngressEthernet(receiverMAC, cellSource(index), etherType, l3)
	}
	tcpPayload := func(index byte) []byte {
		payload := make([]byte, 32)
		for offset := range payload {
			payload[offset] = byte(int(index)*17 + offset*29 + 7)
		}
		return payload
	}

	canonicalPayload := tcpPayload(1)
	binary.LittleEndian.PutUint32(canonicalPayload[:4], mixedType)
	// The old admission bug read the rotated wire prefix. Keep that word
	// deliberately invalid so only the tail-restored typeword can admit.
	binary.LittleEndian.PutUint32(canonicalPayload[12:16], fakeTCPManagedIngressInvalidWireWord)
	canonicalWire := append(append([]byte(nil), canonicalPayload[12:]...), canonicalPayload[:12]...)
	canonical := frame(1, unix.ETH_P_IP, fakeTCPManagedIngressIPv4TCP(
		t, 5, 5, 0, 31001, fakeTCPManagedIngressPort,
		0x01020304, 0x11223344, canonicalWire,
	))

	makeTCPv4 := func(index byte, ipWords, tcpWords int, fragment uint16, port uint16) []byte {
		return frame(index, unix.ETH_P_IP, fakeTCPManagedIngressIPv4TCP(
			t, ipWords, tcpWords, fragment, 32001, port,
			uint32(0x20000000)+uint32(index), 0x30000000, tcpPayload(index),
		))
	}
	makeTCPv6 := func(index byte, extensions int, fragment uint16, port uint16) []byte {
		return frame(index, unix.ETH_P_IPV6, fakeTCPManagedIngressIPv6TCP(
			t, extensions, fragment, 32001, port, tcpPayload(index),
		))
	}
	makeUDPv4 := func(index byte, port uint16) []byte {
		return frame(index, unix.ETH_P_IP, fakeTCPManagedIngressIPv4UDP(
			t, 32001, port, tcpPayload(index),
		))
	}
	makeTruncated := func(index byte) []byte {
		// Keep the frame at Ethernet's minimum wire size, but declare more L3
		// bytes than are present so veth padding cannot change TRUNCATED.
		l3 := make([]byte, 46)
		l3[0], l3[8], l3[9] = 0x45, 64, unix.IPPROTO_TCP
		binary.BigEndian.PutUint16(l3[2:4], 64)
		copy(l3[12:16], []byte{10, 0, 0, 1})
		copy(l3[16:20], []byte{10, 0, 0, 2})
		binary.BigEndian.PutUint16(l3[10:12], internetChecksum(l3[:20]))
		return frame(index, unix.ETH_P_IP, l3)
	}

	return []fakeTCPManagedIngressCell{
		{
			name: "managed canonical decode", frame: canonical, interfaceManaged: true,
			wantDisposition: faketcp.IngressDecodeIPv4, wantParse: faketcp.L3ParseOK,
			wire: fakeTCPManagedIngressWireDecoded, decodedPayload: canonicalPayload,
			wantFake: map[uint32]uint64{
				fakeTCPManagedIngressFakeIngressOK: 1, fakeTCPManagedIngressFakeAdmissionOK: 1,
			},
			wantCore: map[uint32]uint64{fakeTCPManagedIngressCoreIngressOK: 1},
		},
		{
			name: "unmanaged native UDP pass", frame: makeUDPv4(2, fakeTCPManagedIngressUnmanagedPort),
			interfaceManaged: true, wantDisposition: faketcp.IngressPass, wantParse: faketcp.L3ParseOK,
			wire:     fakeTCPManagedIngressWireUnchanged,
			wantCore: map[uint32]uint64{fakeTCPManagedIngressCoreRuleMiss: 1},
		},
		{
			name: "managed native UDP drop", frame: makeUDPv4(3, fakeTCPManagedIngressPort),
			interfaceManaged: true, wantDisposition: faketcp.IngressDrop, wantParse: faketcp.L3ParseOK,
			wire:     fakeTCPManagedIngressWireDrop,
			wantFake: map[uint32]uint64{fakeTCPManagedIngressFakeBypassReject: 1},
		},
		{
			name: "managed IPv4 options drop", frame: makeTCPv4(4, 6, 5, 0, fakeTCPManagedIngressPort),
			interfaceManaged: true, wantDisposition: faketcp.IngressDrop, wantParse: faketcp.L3ParseOK,
			wire:     fakeTCPManagedIngressWireDrop,
			wantFake: map[uint32]uint64{fakeTCPManagedIngressFakeBypassReject: 1},
		},
		{
			name: "unmanaged IPv4 options pass", frame: makeTCPv4(5, 6, 5, 0, fakeTCPManagedIngressUnmanagedPort),
			interfaceManaged: true, wantDisposition: faketcp.IngressPass, wantParse: faketcp.L3ParseOK,
			wire: fakeTCPManagedIngressWireUnchanged,
		},
		{
			name: "managed TCP options drop", frame: makeTCPv4(6, 5, 6, 0, fakeTCPManagedIngressPort),
			interfaceManaged: true, wantDisposition: faketcp.IngressDrop, wantParse: faketcp.L3ParseOK,
			wire:     fakeTCPManagedIngressWireDrop,
			wantFake: map[uint32]uint64{fakeTCPManagedIngressFakeBypassReject: 1},
		},
		{
			name: "unmanaged TCP options pass", frame: makeTCPv4(7, 5, 6, 0, fakeTCPManagedIngressUnmanagedPort),
			interfaceManaged: true, wantDisposition: faketcp.IngressPass, wantParse: faketcp.L3ParseOK,
			wire: fakeTCPManagedIngressWireUnchanged,
		},
		{
			name: "managed IPv6 fixed drop", frame: makeTCPv6(8, 0, 0, fakeTCPManagedIngressPort),
			interfaceManaged: true, wantDisposition: faketcp.IngressDrop, wantParse: faketcp.L3ParseOK,
			wire:     fakeTCPManagedIngressWireDrop,
			wantFake: map[uint32]uint64{fakeTCPManagedIngressFakeBypassReject: 1},
		},
		{
			name: "unmanaged IPv6 fixed pass", frame: makeTCPv6(9, 0, 0, fakeTCPManagedIngressUnmanagedPort),
			interfaceManaged: true, wantDisposition: faketcp.IngressPass, wantParse: faketcp.L3ParseOK,
			wire:     fakeTCPManagedIngressWireUnchanged,
			wantCore: map[uint32]uint64{fakeTCPManagedIngressCoreIPv6Ext: 1},
		},
		{
			name: "managed IPv6 extension drop", frame: makeTCPv6(10, 1, 0, fakeTCPManagedIngressPort),
			interfaceManaged: true, wantDisposition: faketcp.IngressDrop, wantParse: faketcp.L3ParseOK,
			wire:     fakeTCPManagedIngressWireDrop,
			wantFake: map[uint32]uint64{fakeTCPManagedIngressFakeBypassReject: 1},
		},
		{
			name: "unmanaged IPv6 extension pass", frame: makeTCPv6(11, 1, 0, fakeTCPManagedIngressUnmanagedPort),
			interfaceManaged: true, wantDisposition: faketcp.IngressPass, wantParse: faketcp.L3ParseOK,
			wire:     fakeTCPManagedIngressWireUnchanged,
			wantCore: map[uint32]uint64{fakeTCPManagedIngressCoreIPv6Ext: 1},
		},
		{
			name: "managed IPv4 first fragment drop", frame: makeTCPv4(12, 5, 5, 0x2000, fakeTCPManagedIngressPort),
			interfaceManaged: true, wantDisposition: faketcp.IngressDrop, wantParse: faketcp.L3ParseFirstFragment,
			wire:     fakeTCPManagedIngressWireDrop,
			wantFake: map[uint32]uint64{fakeTCPManagedIngressFakeBypassReject: 1},
		},
		{
			name: "unmanaged IPv4 first fragment pass", frame: makeTCPv4(13, 5, 5, 0x2000, fakeTCPManagedIngressPort),
			wantDisposition: faketcp.IngressPass, wantParse: faketcp.L3ParseFirstFragment,
			wire: fakeTCPManagedIngressWireTestRun,
		},
		{
			name: "managed IPv4 noninitial fragment drop", frame: makeTCPv4(14, 5, 5, 1, fakeTCPManagedIngressPort),
			interfaceManaged: true, wantDisposition: faketcp.IngressDrop, wantParse: faketcp.L3ParseNonInitialFragment,
			wire:     fakeTCPManagedIngressWireDrop,
			wantFake: map[uint32]uint64{fakeTCPManagedIngressFakeBypassReject: 1},
		},
		{
			name: "unmanaged IPv4 noninitial fragment pass", frame: makeTCPv4(15, 5, 5, 1, fakeTCPManagedIngressPort),
			wantDisposition: faketcp.IngressPass, wantParse: faketcp.L3ParseNonInitialFragment,
			wire: fakeTCPManagedIngressWireTestRun,
		},
		{
			name: "managed IPv6 first fragment drop", frame: makeTCPv6(16, 0, 1, fakeTCPManagedIngressPort),
			interfaceManaged: true, wantDisposition: faketcp.IngressDrop, wantParse: faketcp.L3ParseFirstFragment,
			wire:     fakeTCPManagedIngressWireDrop,
			wantFake: map[uint32]uint64{fakeTCPManagedIngressFakeBypassReject: 1},
		},
		{
			name: "managed IPv6 noninitial fragment drop", frame: makeTCPv6(21, 0, 8, fakeTCPManagedIngressPort),
			interfaceManaged: true, wantDisposition: faketcp.IngressDrop, wantParse: faketcp.L3ParseNonInitialFragment,
			wire:     fakeTCPManagedIngressWireDrop,
			wantFake: map[uint32]uint64{fakeTCPManagedIngressFakeBypassReject: 1},
		},
		{
			name: "unmanaged IPv6 noninitial fragment pass", frame: makeTCPv6(17, 0, 8, fakeTCPManagedIngressPort),
			wantDisposition: faketcp.IngressPass, wantParse: faketcp.L3ParseNonInitialFragment,
			wire: fakeTCPManagedIngressWireTestRun,
		},
		{
			name: "managed truncation drop", frame: makeTruncated(18),
			interfaceManaged: true, wantDisposition: faketcp.IngressDrop, wantParse: faketcp.L3ParseTruncated,
			wire:     fakeTCPManagedIngressWireDrop,
			wantFake: map[uint32]uint64{fakeTCPManagedIngressFakeBadPacket: 1},
		},
		{
			name: "unmanaged truncation pass", frame: makeTruncated(19),
			wantDisposition: faketcp.IngressPass, wantParse: faketcp.L3ParseTruncated,
			wire: fakeTCPManagedIngressWireTestRun,
		},
		{
			name: "ICMP safe bypass", frame: frame(20, unix.ETH_P_IP, fakeTCPManagedIngressIPv4ICMP(tcpPayload(20))),
			interfaceManaged: true, wantDisposition: faketcp.IngressPass, wantParse: faketcp.L3ParseSafeBypass,
			wire: fakeTCPManagedIngressWireUnchanged,
		},
		{
			name: "ICMPv6 safe bypass", frame: frame(22, unix.ETH_P_IPV6, fakeTCPManagedIngressIPv6ICMP(tcpPayload(22))),
			interfaceManaged: true, wantDisposition: faketcp.IngressPass, wantParse: faketcp.L3ParseSafeBypass,
			wire:     fakeTCPManagedIngressWireUnchanged,
			wantCore: map[uint32]uint64{fakeTCPManagedIngressCoreIPv6Ext: 1},
		},
	}
}

func fakeTCPManagedIngressEthernet(
	destination, source net.HardwareAddr,
	etherType uint16,
	l3 []byte,
) []byte {
	frame := make([]byte, fakeTCPRealHostEthernetHeaderSize, fakeTCPRealHostEthernetHeaderSize+len(l3))
	copy(frame[0:6], destination)
	copy(frame[6:12], source)
	binary.BigEndian.PutUint16(frame[12:14], etherType)
	return append(frame, l3...)
}

func fakeTCPManagedIngressIPv4TCP(
	t *testing.T,
	ipWords, tcpWords int,
	fragment uint16,
	sourcePort, destinationPort uint16,
	sequence, acknowledgement uint32,
	payload []byte,
) []byte {
	t.Helper()
	if ipWords < 5 || tcpWords < 5 {
		t.Fatalf("invalid managed-ingress IPv4/TCP header words %d/%d", ipWords, tcpWords)
	}
	ipHeaderLength, tcpHeaderLength := ipWords*4, tcpWords*4
	tcp := make([]byte, tcpHeaderLength+len(payload))
	binary.BigEndian.PutUint16(tcp[0:2], sourcePort)
	binary.BigEndian.PutUint16(tcp[2:4], destinationPort)
	binary.BigEndian.PutUint32(tcp[4:8], sequence)
	binary.BigEndian.PutUint32(tcp[8:12], acknowledgement)
	tcp[12], tcp[13] = byte(tcpWords<<4), faketcp.FlagACK|faketcp.FlagPSH
	binary.BigEndian.PutUint16(tcp[14:16], 4096)
	copy(tcp[tcpHeaderLength:], payload)
	binary.BigEndian.PutUint16(tcp[16:18], fakeTCPRoutedTransportChecksum(
		netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), unix.IPPROTO_TCP, tcp,
	))

	ipv4 := make([]byte, ipHeaderLength, ipHeaderLength+len(tcp))
	ipv4[0], ipv4[8], ipv4[9] = 0x40|byte(ipWords), 64, unix.IPPROTO_TCP
	binary.BigEndian.PutUint16(ipv4[2:4], uint16(ipHeaderLength+len(tcp)))
	binary.BigEndian.PutUint16(ipv4[4:6], uint16(sequence))
	binary.BigEndian.PutUint16(ipv4[6:8], fragment)
	copy(ipv4[12:16], []byte{10, 0, 0, 1})
	copy(ipv4[16:20], []byte{10, 0, 0, 2})
	binary.BigEndian.PutUint16(ipv4[10:12], internetChecksum(ipv4))
	return append(ipv4, tcp...)
}

func fakeTCPManagedIngressIPv4UDP(
	t *testing.T,
	sourcePort, destinationPort uint16,
	payload []byte,
) []byte {
	t.Helper()
	udp := make([]byte, 8, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:2], sourcePort)
	binary.BigEndian.PutUint16(udp[2:4], destinationPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))
	udp = append(udp, payload...)
	ipv4 := make([]byte, 20, 20+len(udp))
	ipv4[0], ipv4[8], ipv4[9] = 0x45, 64, unix.IPPROTO_UDP
	binary.BigEndian.PutUint16(ipv4[2:4], uint16(20+len(udp)))
	copy(ipv4[12:16], []byte{10, 0, 0, 1})
	copy(ipv4[16:20], []byte{10, 0, 0, 2})
	binary.BigEndian.PutUint16(ipv4[10:12], internetChecksum(ipv4))
	return append(ipv4, udp...)
}

func fakeTCPManagedIngressIPv6TCP(
	t *testing.T,
	extensions int,
	fragment uint16,
	sourcePort, destinationPort uint16,
	payload []byte,
) []byte {
	t.Helper()
	if extensions < 0 || extensions > 1 {
		t.Fatalf("invalid managed-ingress IPv6 extension count %d", extensions)
	}
	tcp := make([]byte, 20, 20+len(payload))
	binary.BigEndian.PutUint16(tcp[0:2], sourcePort)
	binary.BigEndian.PutUint16(tcp[2:4], destinationPort)
	tcp[12], tcp[13] = 5<<4, faketcp.FlagACK|faketcp.FlagPSH
	tcp = append(tcp, payload...)
	source := netip.MustParseAddr("2001:db8::1")
	destination := netip.MustParseAddr("2001:db8::2")
	binary.BigEndian.PutUint16(tcp[16:18], fakeTCPManagedIngressIPv6Checksum(
		source, destination, unix.IPPROTO_TCP, tcp,
	))
	nextHeader := byte(unix.IPPROTO_TCP)
	prefix := make([]byte, 0, extensions*8+8)
	if fragment != 0 {
		fragmentHeader := make([]byte, 8)
		fragmentHeader[0] = unix.IPPROTO_TCP
		binary.BigEndian.PutUint16(fragmentHeader[2:4], fragment)
		binary.BigEndian.PutUint32(fragmentHeader[4:8], 0x01020304)
		prefix = append(prefix, fragmentHeader...)
		nextHeader = 44
	} else if extensions == 1 {
		extension := make([]byte, 8)
		extension[0] = unix.IPPROTO_TCP
		prefix = append(prefix, extension...)
		nextHeader = 0
	}
	ipv6 := make([]byte, 40, 40+len(prefix)+len(tcp))
	ipv6[0], ipv6[6], ipv6[7] = 0x60, nextHeader, 64
	binary.BigEndian.PutUint16(ipv6[4:6], uint16(len(prefix)+len(tcp)))
	copy(ipv6[8:24], source.AsSlice())
	copy(ipv6[24:40], destination.AsSlice())
	ipv6 = append(ipv6, prefix...)
	return append(ipv6, tcp...)
}

func fakeTCPManagedIngressIPv4ICMP(payload []byte) []byte {
	icmp := make([]byte, 8, 8+len(payload))
	icmp[0] = 8
	binary.BigEndian.PutUint16(icmp[4:6], 0x4242)
	binary.BigEndian.PutUint16(icmp[6:8], 1)
	icmp = append(icmp, payload...)
	binary.BigEndian.PutUint16(icmp[2:4], internetChecksum(icmp))
	ipv4 := make([]byte, 20, 20+len(icmp))
	ipv4[0], ipv4[8], ipv4[9] = 0x45, 64, unix.IPPROTO_ICMP
	binary.BigEndian.PutUint16(ipv4[2:4], uint16(20+len(icmp)))
	copy(ipv4[12:16], []byte{10, 0, 0, 1})
	copy(ipv4[16:20], []byte{10, 0, 0, 2})
	binary.BigEndian.PutUint16(ipv4[10:12], internetChecksum(ipv4))
	return append(ipv4, icmp...)
}

func fakeTCPManagedIngressIPv6ICMP(payload []byte) []byte {
	source := netip.MustParseAddr("2001:db8::1")
	destination := netip.MustParseAddr("2001:db8::2")
	icmp := make([]byte, 8, 8+len(payload))
	icmp[0] = 128
	binary.BigEndian.PutUint16(icmp[4:6], 0x4242)
	binary.BigEndian.PutUint16(icmp[6:8], 1)
	icmp = append(icmp, payload...)
	binary.BigEndian.PutUint16(icmp[2:4], fakeTCPManagedIngressIPv6Checksum(
		source, destination, unix.IPPROTO_ICMPV6, icmp,
	))
	ipv6 := make([]byte, 40, 40+len(icmp))
	ipv6[0], ipv6[6], ipv6[7] = 0x60, unix.IPPROTO_ICMPV6, 64
	binary.BigEndian.PutUint16(ipv6[4:6], uint16(len(icmp)))
	copy(ipv6[8:24], source.AsSlice())
	copy(ipv6[24:40], destination.AsSlice())
	return append(ipv6, icmp...)
}

func fakeTCPManagedIngressIPv6Checksum(
	source, destination netip.Addr,
	protocol byte,
	transport []byte,
) uint16 {
	pseudo := make([]byte, 40, 40+len(transport))
	copy(pseudo[0:16], source.AsSlice())
	copy(pseudo[16:32], destination.AsSlice())
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(transport)))
	pseudo[39] = protocol
	checksum := internetChecksum(append(pseudo, transport...))
	if checksum == 0 {
		return 0xffff
	}
	return checksum
}
