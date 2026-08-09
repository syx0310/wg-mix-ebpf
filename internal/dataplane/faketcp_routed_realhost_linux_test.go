//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
	"github.com/syx0310/wg-mix-ebpf/internal/faketcp"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	fakeTCPRoutedCoreStatIngressRuleMiss = uint32(7)
	fakeTCPRoutedCoreStatGSORewriteOK    = uint32(17)
	fakeTCPRoutedFakeStatCount           = 19
	fakeTCPRoutedCoreStatCount           = 36
	fakeTCPRoutedMTUAuditStatCount       = 15
	fakeTCPRoutedInitialSequence         = uint32(0x55667788)
	fakeTCPRoutedAcknowledgement         = uint32(0x99aabbcc)
	fakeTCPRoutedWindow                  = uint16(4096)
)

type fakeTCPRoutedSocketMode uint8

const (
	fakeTCPRoutedSocketIPHdrIncl fakeTCPRoutedSocketMode = iota + 1
	fakeTCPRoutedSocketUDP
	fakeTCPRoutedSocketUDPSegment
)

type fakeTCPRoutedTCPSegment struct {
	sequence uint32
	flags    byte
	payload  []byte
}

// TestFakeTCPRealHostRoutedIPHdrInclNone proves the route-backed raw IPv4
// source reaches FakeTCP egress as CHECKSUM_NONE and is transformed before the
// run-owned veth peer. It is deliberately separate from the AF_PACKET
// route-unknown negative fixture.
func TestFakeTCPRealHostRoutedIPHdrInclNone(t *testing.T) {
	runFakeTCPRoutedSocketAcceptance(t, fakeTCPRoutedSocketIPHdrIncl)
}

// TestFakeTCPRealHostRoutedUDPSocketPartial requires the reviewed veth feature
// snapshot to preserve CHECKSUM_PARTIAL through TC egress. A host that has
// already completed the checksum in software fails this coverage cell instead
// of being reported as PARTIAL evidence.
func TestFakeTCPRealHostRoutedUDPSocketPartial(t *testing.T) {
	runFakeTCPRoutedSocketAcceptance(t, fakeTCPRoutedSocketUDP)
}

// TestFakeTCPRealHostRoutedUDPSegmentGSO sends one UDP_SEGMENT aggregate and
// requires three independently checksummed TCP wire segments. The reviewed
// runner disables only TCP segmentation on the owned sender veth so the
// aggregate must be software-segmented after FakeTCP commit.
func TestFakeTCPRealHostRoutedUDPSegmentGSO(t *testing.T) {
	runFakeTCPRoutedSocketAcceptance(t, fakeTCPRoutedSocketUDPSegment)
}

func runFakeTCPRoutedSocketAcceptance(t *testing.T, mode fakeTCPRoutedSocketMode) {
	t.Helper()
	prepared := requireFakeTCPRealHostPrepared(t)
	routed, err := parseFakeTCPRoutedRealHostContract(os.LookupEnv)
	if err != nil {
		t.Fatal(err)
	}
	validateFakeTCPRoutedTopology(t, prepared.contract, routed)

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	runtime, _ := buildFakeTCPRealHostRuntime(ctx, t, prepared, true, routedLeaseSuffix(mode))
	closed := false
	defer func() {
		if !closed {
			if err := runtime.Close(); err != nil {
				t.Errorf("close routed FakeTCP runtime after failure: %v", err)
			}
		}
	}()
	assertFakeTCPRealHostRuntimeAttached(t, prepared.contract)

	handles, err := runtime.Handles()
	if err != nil {
		t.Fatal(err)
	}
	installFakeTCPRoutedSession(t, handles, runtime.Generation(), prepared.contract, routed)

	fakeBefore := readFakeTCPRoutedStats(
		t, runtime, "faketcp_stats_map", fakeTCPRoutedFakeStatCount,
	)
	coreBefore := readFakeTCPRoutedStats(
		t, runtime, "stats_map", fakeTCPRoutedCoreStatCount,
	)
	mtuBefore := readFakeTCPRoutedStats(
		t, runtime, "faketcp_mtu_audit_map", fakeTCPRoutedMTUAuditStatCount,
	)

	receiver := openFakeTCPRealHostPacketSocket(t, prepared.contract.peerIfindex)
	defer closeFakeTCPRealHostFD(t, receiver, "routed peer packet socket")
	payload := buildFakeTCPRoutedPayload(mode)
	sendFakeTCPRoutedPayload(t, mode, prepared.contract.vethName, routed, payload)

	wantSegments := 1
	if mode == fakeTCPRoutedSocketUDPSegment {
		wantSegments = fakeTCPRoutedGSOSegments
	}
	segments := receiveFakeTCPRoutedSegments(
		t, ctx, receiver, routed, wantSegments,
	)
	wireImages := fakeTCPRoutedExpectedWireSegments(
		t, prepared.contract, runtime.Generation(), payload, wantSegments,
	)
	assertFakeTCPRoutedSegments(t, mode, segments, wireImages)

	fakeWant := map[uint32]uint64{fakeTCPRealHostStatEgressOK: 1}
	coreWant := map[uint32]uint64{
		fakeTCPRealHostCoreStatEgressRewriteOK: 1,
		fakeTCPRoutedCoreStatIngressRuleMiss:   uint64(wantSegments),
		fakeTCPRealHostCoreStatXOREgressOK:     1,
	}
	switch mode {
	case fakeTCPRoutedSocketIPHdrIncl:
		fakeWant[fakeTCPRealHostStatChecksumNoneAccepted] = 1
	case fakeTCPRoutedSocketUDP:
		fakeWant[fakeTCPRealHostStatChecksumPartialReset] = 1
	case fakeTCPRoutedSocketUDPSegment:
		coreWant[fakeTCPRealHostCoreStatEgressGSOSeen] = 1
		coreWant[fakeTCPRealHostCoreStatEgressGSOManagedSeen] = 1
		coreWant[fakeTCPRoutedCoreStatGSORewriteOK] = 1
	default:
		t.Fatalf("unsupported routed socket mode %d", mode)
	}
	waitForFakeTCPRoutedStatDeltas(
		t,
		runtime,
		[]fakeTCPRoutedStatExpectation{
			{name: "faketcp_stats_map", before: fakeBefore, want: fakeWant},
			{name: "stats_map", before: coreBefore, want: coreWant},
			{name: "faketcp_mtu_audit_map", before: mtuBefore, want: nil},
		},
	)

	if err := runtime.Close(); err != nil {
		t.Fatalf("close routed FakeTCP runtime: %v", err)
	}
	closed = true
	assertFakeTCPRealHostKernelEmpty(t, prepared.contract)
	t.Logf(
		"FAKETCP_ROUTED_SOCKET_COMPLETE run_id=%s mode=%s route_mtu=%d segments=%d restored=1",
		prepared.contract.runID, routedModeName(mode), routed.routeMTU, wantSegments,
	)
}

func routedLeaseSuffix(mode fakeTCPRoutedSocketMode) string {
	return "routed-" + routedModeName(mode)
}

func routedModeName(mode fakeTCPRoutedSocketMode) string {
	switch mode {
	case fakeTCPRoutedSocketIPHdrIncl:
		return "iphdrincl-none"
	case fakeTCPRoutedSocketUDP:
		return "udp-partial"
	case fakeTCPRoutedSocketUDPSegment:
		return "udp-segment-gso"
	default:
		return fmt.Sprintf("unknown-%d", mode)
	}
}

func validateFakeTCPRoutedTopology(
	t *testing.T,
	base fakeTCPRealHostContract,
	routed fakeTCPRoutedRealHostContract,
) {
	t.Helper()
	local, err := netlink.LinkByIndex(base.ifindex)
	if err != nil {
		t.Fatalf("resolve routed sender veth: %v", err)
	}
	peer, err := netlink.LinkByIndex(base.peerIfindex)
	if err != nil {
		t.Fatalf("resolve routed peer veth: %v", err)
	}
	localAddresses, err := netlink.AddrList(local, netlink.FAMILY_V4)
	if err != nil {
		t.Fatalf("list routed sender IPv4 addresses: %v", err)
	}
	wantPrefix := netip.PrefixFrom(routed.localIPv4, routed.prefixBits).String()
	if len(localAddresses) != 1 || localAddresses[0].IPNet == nil ||
		localAddresses[0].IPNet.String() != wantPrefix {
		t.Fatalf("routed sender IPv4 addresses=%v, want exactly %s", localAddresses, wantPrefix)
	}
	peerAddresses, err := netlink.AddrList(peer, netlink.FAMILY_V4)
	if err != nil {
		t.Fatalf("list routed peer IPv4 addresses: %v", err)
	}
	if len(peerAddresses) != 0 {
		t.Fatalf("routed peer must remain unnumbered, got IPv4 addresses %v", peerAddresses)
	}

	remoteNetwork := &net.IPNet{
		IP:   net.IP(routed.remoteIPv4.AsSlice()),
		Mask: net.CIDRMask(routed.prefixBits, 32),
	}
	routes, err := netlink.RouteListFiltered(
		netlink.FAMILY_V4,
		&netlink.Route{LinkIndex: base.ifindex, Dst: remoteNetwork},
		netlink.RT_FILTER_OIF|netlink.RT_FILTER_DST,
	)
	if err != nil {
		t.Fatalf("list exact routed-veth route: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("exact routed-veth route count=%d, want 1: %v", len(routes), routes)
	}
	route := routes[0]
	if route.LinkIndex != base.ifindex || route.Dst == nil ||
		route.Dst.String() != remoteNetwork.String() ||
		!route.Src.Equal(net.IP(routed.localIPv4.AsSlice())) ||
		len(route.Gw) != 0 || route.Table != unix.RT_TABLE_MAIN ||
		route.Scope != netlink.SCOPE_LINK ||
		route.Protocol != netlink.RouteProtocol(unix.RTPROT_STATIC) ||
		route.MTU != routed.routeMTU {
		t.Fatalf("routed-veth route=%#v, want exact device/source/static/link/MTU contract", route)
	}

	neighbors, err := netlink.NeighList(base.ifindex, netlink.FAMILY_V4)
	if err != nil {
		t.Fatalf("list routed-veth neighbors: %v", err)
	}
	var matches []netlink.Neigh
	for _, neighbor := range neighbors {
		if neighbor.IP.Equal(net.IP(routed.remoteIPv4.AsSlice())) {
			matches = append(matches, neighbor)
		}
	}
	if len(matches) != 1 || matches[0].LinkIndex != base.ifindex ||
		matches[0].State != netlink.NUD_PERMANENT ||
		!bytes.Equal(matches[0].HardwareAddr, peer.Attrs().HardwareAddr) {
		t.Fatalf("routed-veth neighbor=%#v, want one permanent peer-MAC entry", matches)
	}
}

func installFakeTCPRoutedSession(
	t *testing.T,
	handles ExperimentalFakeTCPRuntimeHandles,
	generation uint64,
	base fakeTCPRealHostContract,
	routed fakeTCPRoutedRealHostContract,
) {
	t.Helper()
	local, err := faketcp.RawIPv4BE32(routed.localIPv4)
	if err != nil {
		t.Fatal(err)
	}
	remote, err := faketcp.RawIPv4BE32(routed.remoteIPv4)
	if err != nil {
		t.Fatal(err)
	}
	value := abi.FakeTCPSessionValue{
		Generation: generation, TXSequence: fakeTCPRoutedInitialSequence,
		RXSequence: fakeTCPRoutedAcknowledgement, Window: fakeTCPRoutedWindow,
		State: abi.FakeTCPStateEstablished, Revision: 1, SessionID: 0x7e42a19c,
		RuntimeIncarnation: [16]byte(handles.Identity().Incarnation),
	}
	key := abi.FakeTCPSessionKey{
		Generation: generation, LocalIPv4: local, RemoteIPv4: remote,
		UnderlayIndex: uint32(base.ifindex), LocalPort: fakeTCPRoutedSourcePort,
		RemotePort: fakeTCPRoutedDestinationPort,
	}
	if err := handles.SessionStore().InsertEstablished(key, value); err != nil {
		t.Fatalf("insert routed FakeTCP established session: %v", err)
	}
}

func buildFakeTCPRoutedPayload(mode fakeTCPRoutedSocketMode) []byte {
	segments := 1
	if mode == fakeTCPRoutedSocketUDPSegment {
		segments = fakeTCPRoutedGSOSegments
	}
	payload := make([]byte, segments*fakeTCPRoutedSegmentBytes)
	for segment := range segments {
		start := segment * fakeTCPRoutedSegmentBytes
		binary.LittleEndian.PutUint32(payload[start:start+4], 4)
		for offset := 4; offset < fakeTCPRoutedSegmentBytes; offset++ {
			payload[start+offset] = byte(segment*53 + offset*29 + 7)
		}
	}
	return payload
}

func sendFakeTCPRoutedPayload(
	t *testing.T,
	mode fakeTCPRoutedSocketMode,
	device string,
	contract fakeTCPRoutedRealHostContract,
	payload []byte,
) {
	t.Helper()
	if mode == fakeTCPRoutedSocketIPHdrIncl {
		sendFakeTCPRoutedIPHdrIncl(t, device, contract, payload)
		return
	}
	fd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM|unix.SOCK_CLOEXEC,
		unix.IPPROTO_UDP,
	)
	if err != nil {
		t.Fatalf("open routed UDP socket: %v", err)
	}
	defer closeFakeTCPRealHostFD(t, fd, "routed UDP socket")
	if err := unix.BindToDevice(fd, device); err != nil {
		t.Fatalf("bind routed UDP socket to %s: %v", device, err)
	}
	if err := unix.SetsockoptInt(
		fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO,
	); err != nil {
		t.Fatalf("enable routed UDP PMTU discovery: %v", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrInet4{
		Port: int(fakeTCPRoutedSourcePort), Addr: contract.localIPv4.As4(),
	}); err != nil {
		t.Fatalf("bind routed UDP source: %v", err)
	}
	if mode == fakeTCPRoutedSocketUDPSegment {
		if err := unix.SetsockoptInt(
			fd, unix.SOL_UDP, unix.UDP_SEGMENT, fakeTCPRoutedSegmentBytes,
		); err != nil {
			t.Fatalf("enable routed UDP_SEGMENT: %v", err)
		}
		segmentSize, err := unix.GetsockoptInt(fd, unix.SOL_UDP, unix.UDP_SEGMENT)
		if err != nil || segmentSize != fakeTCPRoutedSegmentBytes {
			t.Fatalf("verify routed UDP_SEGMENT=%d: got=%d error=%v",
				fakeTCPRoutedSegmentBytes, segmentSize, err)
		}
	}
	if err := unix.Sendto(fd, payload, 0, &unix.SockaddrInet4{
		Port: int(fakeTCPRoutedDestinationPort), Addr: contract.remoteIPv4.As4(),
	}); err != nil {
		t.Fatalf("send routed %s payload: %v", routedModeName(mode), err)
	}
}

func sendFakeTCPRoutedIPHdrIncl(
	t *testing.T,
	device string,
	contract fakeTCPRoutedRealHostContract,
	payload []byte,
) {
	t.Helper()
	fd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_RAW|unix.SOCK_CLOEXEC,
		unix.IPPROTO_RAW,
	)
	if err != nil {
		t.Fatalf("open routed raw IPv4 socket: %v", err)
	}
	defer closeFakeTCPRealHostFD(t, fd, "routed raw IPv4 socket")
	if err := unix.BindToDevice(fd, device); err != nil {
		t.Fatalf("bind routed raw IPv4 socket to %s: %v", device, err)
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		t.Fatalf("enable routed IP_HDRINCL: %v", err)
	}
	if enabled, err := unix.GetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL); err != nil || enabled != 1 {
		t.Fatalf("verify routed IP_HDRINCL: enabled=%d error=%v", enabled, err)
	}
	if err := unix.SetsockoptInt(
		fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO,
	); err != nil {
		t.Fatalf("enable routed raw IPv4 PMTU discovery: %v", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: contract.localIPv4.As4()}); err != nil {
		t.Fatalf("bind routed raw IPv4 source: %v", err)
	}
	packet := buildFakeTCPRoutedIPv4UDP(contract, payload)
	if err := unix.Sendto(fd, packet, 0, &unix.SockaddrInet4{
		Addr: contract.remoteIPv4.As4(),
	}); err != nil {
		t.Fatalf("send routed raw IPv4/IP_HDRINCL payload: %v", err)
	}
}

func buildFakeTCPRoutedIPv4UDP(
	contract fakeTCPRoutedRealHostContract,
	payload []byte,
) []byte {
	udp := make([]byte, fakeTCPRealHostUDPHeaderSize)
	binary.BigEndian.PutUint16(udp[0:2], fakeTCPRoutedSourcePort)
	binary.BigEndian.PutUint16(udp[2:4], fakeTCPRoutedDestinationPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)+len(payload)))
	checksum := fakeTCPRoutedTransportChecksum(
		contract.localIPv4, contract.remoteIPv4, unix.IPPROTO_UDP,
		append(append([]byte(nil), udp...), payload...),
	)
	binary.BigEndian.PutUint16(udp[6:8], checksum)

	ipv4 := make([]byte, fakeTCPRealHostIPv4HeaderSize)
	ipv4[0] = 0x45
	ipv4[8] = 64
	ipv4[9] = unix.IPPROTO_UDP
	binary.BigEndian.PutUint16(ipv4[2:4], uint16(len(ipv4)+len(udp)+len(payload)))
	binary.BigEndian.PutUint16(ipv4[4:6], 0x4219)
	binary.BigEndian.PutUint16(ipv4[6:8], 0x4000)
	copy(ipv4[12:16], contract.localIPv4.AsSlice())
	copy(ipv4[16:20], contract.remoteIPv4.AsSlice())
	binary.BigEndian.PutUint16(ipv4[10:12], internetChecksum(ipv4))
	return append(append(ipv4, udp...), payload...)
}

func fakeTCPRoutedTransportChecksum(
	source netip.Addr,
	destination netip.Addr,
	protocol byte,
	transport []byte,
) uint16 {
	checksum := fakeTCPRoutedTransportChecksumResidual(
		source, destination, protocol, transport,
	)
	if checksum == 0 {
		return 0xffff
	}
	return checksum
}

func fakeTCPRoutedTransportChecksumResidual(
	source netip.Addr,
	destination netip.Addr,
	protocol byte,
	transport []byte,
) uint16 {
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], source.AsSlice())
	copy(pseudo[4:8], destination.AsSlice())
	pseudo[9] = protocol
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(transport)))
	return internetChecksum(append(pseudo, transport...))
}

func receiveFakeTCPRoutedSegments(
	t *testing.T,
	ctx context.Context,
	fd int,
	contract fakeTCPRoutedRealHostContract,
	want int,
) []fakeTCPRoutedTCPSegment {
	t.Helper()
	segments := make([]fakeTCPRoutedTCPSegment, 0, want)
	buffer := make([]byte, 65535)
	for len(segments) < want {
		if err := ctx.Err(); err != nil {
			t.Fatalf("receive routed FakeTCP wire segments %d/%d: %v", len(segments), want, err)
		}
		n, _, err := unix.Recvfrom(fd, buffer, unix.MSG_DONTWAIT)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			time.Sleep(5 * time.Millisecond)
			continue
		}
		if err != nil {
			t.Fatalf("receive routed FakeTCP wire frame: %v", err)
		}
		segment, matched, err := parseFakeTCPRoutedTCPSegment(buffer[:n], contract)
		if err != nil {
			t.Fatal(err)
		}
		if matched {
			segments = append(segments, segment)
		}
	}
	return segments
}

func parseFakeTCPRoutedTCPSegment(
	frame []byte,
	contract fakeTCPRoutedRealHostContract,
) (fakeTCPRoutedTCPSegment, bool, error) {
	const ethernetSize = fakeTCPRealHostEthernetHeaderSize
	if len(frame) < ethernetSize+fakeTCPRealHostIPv4HeaderSize ||
		binary.BigEndian.Uint16(frame[12:14]) != unix.ETH_P_IP {
		return fakeTCPRoutedTCPSegment{}, false, nil
	}
	ipv4 := frame[ethernetSize:]
	if ipv4[0] != 0x45 || ipv4[9] != unix.IPPROTO_TCP {
		return fakeTCPRoutedTCPSegment{}, false, nil
	}
	if !bytes.Equal(ipv4[12:16], contract.localIPv4.AsSlice()) ||
		!bytes.Equal(ipv4[16:20], contract.remoteIPv4.AsSlice()) {
		return fakeTCPRoutedTCPSegment{}, false, nil
	}
	totalLength := int(binary.BigEndian.Uint16(ipv4[2:4]))
	if totalLength < fakeTCPRealHostIPv4HeaderSize+20 || totalLength > len(ipv4) {
		return fakeTCPRoutedTCPSegment{}, false, fmt.Errorf(
			"routed FakeTCP IPv4 total length=%d frame=%d", totalLength, len(ipv4),
		)
	}
	if binary.BigEndian.Uint16(ipv4[6:8])&0x3fff != 0 ||
		internetChecksum(ipv4[:fakeTCPRealHostIPv4HeaderSize]) != 0 {
		return fakeTCPRoutedTCPSegment{}, false, fmt.Errorf(
			"routed FakeTCP IPv4 fragment/checksum contract failed",
		)
	}
	tcp := ipv4[fakeTCPRealHostIPv4HeaderSize:totalLength]
	if len(tcp) < 20 {
		return fakeTCPRoutedTCPSegment{}, false, fmt.Errorf("short routed FakeTCP TCP header")
	}
	if binary.BigEndian.Uint16(tcp[0:2]) != fakeTCPRoutedSourcePort ||
		binary.BigEndian.Uint16(tcp[2:4]) != fakeTCPRoutedDestinationPort {
		return fakeTCPRoutedTCPSegment{}, false, nil
	}
	tcpHeaderLength := int(tcp[12]>>4) * 4
	if tcpHeaderLength != 20 || tcpHeaderLength > len(tcp) {
		return fakeTCPRoutedTCPSegment{}, false, fmt.Errorf(
			"routed FakeTCP TCP header length=%d", tcpHeaderLength,
		)
	}
	if fakeTCPRoutedTransportChecksumResidual(
		contract.localIPv4, contract.remoteIPv4, unix.IPPROTO_TCP, tcp,
	) != 0 {
		return fakeTCPRoutedTCPSegment{}, false, fmt.Errorf("invalid routed FakeTCP TCP checksum")
	}
	if binary.BigEndian.Uint32(tcp[8:12]) != fakeTCPRoutedAcknowledgement ||
		binary.BigEndian.Uint16(tcp[14:16]) != fakeTCPRoutedWindow {
		return fakeTCPRoutedTCPSegment{}, false, fmt.Errorf(
			"routed FakeTCP acknowledgment/window drift",
		)
	}
	return fakeTCPRoutedTCPSegment{
		sequence: binary.BigEndian.Uint32(tcp[4:8]),
		flags:    tcp[13],
		payload:  append([]byte(nil), tcp[tcpHeaderLength:]...),
	}, true, nil
}

func assertFakeTCPRoutedSegments(
	t *testing.T,
	mode fakeTCPRoutedSocketMode,
	segments []fakeTCPRoutedTCPSegment,
	wireImages [][]byte,
) {
	t.Helper()
	want := 1
	if mode == fakeTCPRoutedSocketUDPSegment {
		want = fakeTCPRoutedGSOSegments
	}
	if len(segments) != want || len(wireImages) != want {
		t.Fatalf("routed TCP segment/oracle count=%d/%d, want %d",
			len(segments), len(wireImages), want)
	}
	for index, segment := range segments {
		payloadOffset := index * fakeTCPRoutedSegmentBytes
		if segment.sequence != fakeTCPRoutedInitialSequence+uint32(payloadOffset) {
			t.Fatalf("routed TCP segment %d source offset=%d sequence=%#x",
				index, payloadOffset, segment.sequence)
		}
		wantFlags := byte(0x10)
		if index == len(segments)-1 {
			wantFlags = 0x18
		}
		wantPayload := wireImages[index]
		if segment.flags != wantFlags || len(segment.payload) != fakeTCPRoutedSegmentBytes {
			t.Fatalf("routed TCP segment %d flags=%#x payload=%d, want flags=%#x payload=%d",
				index, segment.flags, len(segment.payload), wantFlags, fakeTCPRoutedSegmentBytes)
		}
		if !bytes.Equal(segment.payload, wantPayload) {
			t.Fatalf("routed TCP segment %d source offset=%d wire image mismatch: got=%x want=%x",
				index, payloadOffset, segment.payload, wantPayload)
		}
	}
}

func fakeTCPRoutedExpectedWireSegments(
	t *testing.T,
	contract fakeTCPRealHostContract,
	generation uint64,
	payload []byte,
	segments int,
) [][]byte {
	t.Helper()
	state := fakeTCPRealHostState(contract, generation, true)
	if len(state.Profiles) != 1 || len(state.WireGuards) != 1 || len(state.Ciphers) != 1 {
		t.Fatalf("routed wire oracle profile/wg/cipher cardinality=%d/%d/%d",
			len(state.Profiles), len(state.WireGuards), len(state.Ciphers))
	}
	profile := state.Profiles[0]
	wireGuard := state.WireGuards[0]
	cipher := state.Ciphers[0]
	matchedRules := 0
	for _, rule := range state.EgressRules {
		if rule.SourcePort != fakeTCPRoutedSourcePort ||
			rule.UnderlayIfIndex != contract.ifindex {
			continue
		}
		matchedRules++
		if rule.ProfileID != profile.ID || rule.CipherID != cipher.ID ||
			rule.WGID != wireGuard.ID || rule.TransportMode != "faketcp" ||
			rule.Action != "rewrite" {
			t.Fatalf("routed wire oracle egress rule is not bound to the active FakeTCP/XOR profile: %#v", rule)
		}
	}
	if wireGuard.ProfileID != profile.ID || wireGuard.CipherID != cipher.ID ||
		cipher.Mode != "xor" || cipher.Scope != "wg-payload-full" ||
		cipher.KeyLen == 0 || cipher.KeyLen > uint32(len(cipher.Key)) ||
		cipher.MaxBytes < fakeTCPRoutedSegmentBytes || matchedRules != 1 {
		t.Fatalf("routed wire oracle is not bound to the active full-payload XOR profile")
	}
	if len(payload) != segments*fakeTCPRoutedSegmentBytes {
		t.Fatalf("routed wire oracle payload=%d, want %d segments x %d",
			len(payload), segments, fakeTCPRoutedSegmentBytes)
	}

	wireImages := make([][]byte, segments)
	for index := range segments {
		offset := index * fakeTCPRoutedSegmentBytes
		wire, err := fakeTCPRoutedWireImage(
			payload[offset:offset+fakeTCPRoutedSegmentBytes],
			profile.StandardToMixed[3], cipher.Key[:cipher.KeyLen],
			cipher.KeyMask, int(cipher.MaxBytes),
		)
		if err != nil {
			t.Fatalf("build routed wire oracle segment %d source offset=%d: %v", index, offset, err)
		}
		wireImages[index] = wire
	}
	return wireImages
}

type fakeTCPRoutedStatExpectation struct {
	name   string
	before []uint64
	want   map[uint32]uint64
}

func readFakeTCPRoutedStats(
	t *testing.T,
	runtime *ExperimentalFakeTCPRuntime,
	mapName string,
	count int,
) []uint64 {
	t.Helper()
	if runtime == nil || runtime.state == nil || runtime.state.collection == nil {
		t.Fatal("routed FakeTCP runtime collection is unavailable")
	}
	if count <= 0 || count > 4096 {
		t.Fatalf("routed FakeTCP stat map %s requested entries=%d", mapName, count)
	}
	return readFakeTCPRealHostStats(t, runtime, mapName, count)
}

func waitForFakeTCPRoutedStatDeltas(
	t *testing.T,
	runtime *ExperimentalFakeTCPRuntime,
	expectations []fakeTCPRoutedStatExpectation,
) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		pending := false
		for _, expectation := range expectations {
			after := readFakeTCPRoutedStats(
				t, runtime, expectation.name, len(expectation.before),
			)
			if len(after) != len(expectation.before) {
				t.Fatalf("routed FakeTCP stat map %s resized: before=%d after=%d",
					expectation.name, len(expectation.before), len(after))
			}
			for index := range after {
				if after[index] < expectation.before[index] {
					t.Fatalf("routed FakeTCP stat map %s counter %d decreased",
						expectation.name, index)
				}
				delta := after[index] - expectation.before[index]
				want := expectation.want[uint32(index)]
				if delta > want {
					t.Fatalf("routed FakeTCP stat map %s counter %d delta=%d, want %d",
						expectation.name, index, delta, want)
				}
				if delta < want {
					pending = true
				}
			}
		}
		if !pending {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for exact routed FakeTCP stat deltas")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
