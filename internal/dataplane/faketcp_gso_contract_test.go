package dataplane

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"testing"
)

const (
	fakeTCPGSOTypeUDPL4    = uint32(1 << 0)
	fakeTCPGSOTypeDodgy    = uint32(1 << 1)
	fakeTCPGSOTypeFragList = uint32(1 << 2)
	fakeTCPGSOTypeTunnel   = uint32(1 << 3)
	fakeTCPGSOMaxPayload   = 0xffff - 20 - 8 - 12
)

var (
	errFakeTCPGSOType              = errors.New("unsupported GSO type")
	errFakeTCPGSOMetadata          = errors.New("unsafe GSO metadata")
	errFakeTCPGSOGeometry          = errors.New("invalid GSO geometry")
	errFakeTCPGSOSegment           = errors.New("invalid GSO segment")
	errFakeTCPGSOMTUDeviceUnknown  = errors.New("GSO device MTU unknown")
	errFakeTCPGSOMTUDeviceExceeded = errors.New("GSO device MTU exceeded")
	errFakeTCPGSOMTURouteUnknown   = errors.New("GSO route MTU unknown")
	errFakeTCPGSOMTURouteExceeded  = errors.New("GSO route MTU exceeded")
)

// fakeTCPGSODescriptor mirrors the single kernel transform contract without
// pretending that a portable Go test can observe struct sk_buff internals.
// Kernel verifier and real-host evidence remain mandatory before activation.
type fakeTCPGSODescriptor struct {
	GSOType                uint32
	IPv4FixedHeader        bool
	ChecksumPartial        bool
	ExactHeaderOffsets     bool
	ExactChecksumOffsets   bool
	Encapsulated           bool
	HasFragList            bool
	WritableLinearPrepared bool
	PayloadLength          int
	GSOSize                int
	GSOSegments            int
	DevicePresent          bool
	DeviceMTU              int
	RoutePresent           bool
	RouteMetadata          bool
	RouteDeviceMatches     bool
	RouteMTU               int
}

func validateFakeTCPGSODescriptor(descriptor fakeTCPGSODescriptor) error {
	const allowedTypes = fakeTCPGSOTypeUDPL4 | fakeTCPGSOTypeDodgy
	if descriptor.GSOType&fakeTCPGSOTypeUDPL4 == 0 ||
		descriptor.GSOType & ^uint32(allowedTypes) != 0 ||
		descriptor.Encapsulated || descriptor.HasFragList {
		return errFakeTCPGSOType
	}
	if !descriptor.IPv4FixedHeader || !descriptor.ChecksumPartial ||
		!descriptor.ExactHeaderOffsets || !descriptor.ExactChecksumOffsets ||
		!descriptor.WritableLinearPrepared {
		return errFakeTCPGSOMetadata
	}
	if descriptor.PayloadLength > fakeTCPGSOMaxPayload ||
		descriptor.GSOSize < 32 || descriptor.PayloadLength <= descriptor.GSOSize {
		return errFakeTCPGSOGeometry
	}
	expectedSegments := (descriptor.PayloadLength + descriptor.GSOSize - 1) / descriptor.GSOSize
	allowDodgyZero := descriptor.GSOType&fakeTCPGSOTypeDodgy != 0 && descriptor.GSOSegments == 0
	if expectedSegments < 2 ||
		(!allowDodgyZero && expectedSegments != descriptor.GSOSegments) ||
		descriptor.PayloadLength-(expectedSegments-1)*descriptor.GSOSize < 32 {
		return errFakeTCPGSOGeometry
	}
	plannedL3Length := 20 + 20 + descriptor.GSOSize
	if !descriptor.DevicePresent || descriptor.DeviceMTU <= 0 {
		return errFakeTCPGSOMTUDeviceUnknown
	}
	if plannedL3Length > descriptor.DeviceMTU {
		return errFakeTCPGSOMTUDeviceExceeded
	}
	if !descriptor.RoutePresent || descriptor.RouteMetadata ||
		!descriptor.RouteDeviceMatches || descriptor.RouteMTU <= 0 {
		return errFakeTCPGSOMTURouteUnknown
	}
	if plannedL3Length > descriptor.RouteMTU {
		return errFakeTCPGSOMTURouteExceeded
	}
	return nil
}

type fakeTCPGSOModelCipher struct {
	key      []byte
	maxBytes int
	prefix   bool
}

type fakeTCPGSOWireSegment struct {
	sequence uint32
	payload  []byte
	tcp      []byte
}

func transformFakeTCPGSOSegments(
	descriptor fakeTCPGSODescriptor,
	aggregate []byte,
	profile [4]uint32,
	cipher *fakeTCPGSOModelCipher,
	sequence uint32,
	acknowledgement uint32,
) ([]fakeTCPGSOWireSegment, error) {
	if err := validateFakeTCPGSODescriptor(descriptor); err != nil {
		return nil, err
	}
	if len(aggregate) != descriptor.PayloadLength {
		return nil, errFakeTCPGSOGeometry
	}
	if cipher != nil && (len(cipher.key) != 256 || cipher.maxBytes < 1 || cipher.maxBytes > 2048) {
		return nil, errFakeTCPGSOSegment
	}

	segmentCount := (descriptor.PayloadLength + descriptor.GSOSize - 1) / descriptor.GSOSize
	segments := make([]fakeTCPGSOWireSegment, 0, segmentCount)
	processed := 0
	for processed < len(aggregate) {
		length := min(descriptor.GSOSize, len(aggregate)-processed)
		plain := append([]byte(nil), aggregate[processed:processed+length]...)
		kind := fakeTCPWireGuardKind(binary.LittleEndian.Uint32(plain[:4]))
		if kind < 0 || !fakeTCPWireGuardLengthValid(kind, length) {
			return nil, errFakeTCPGSOSegment
		}
		binary.LittleEndian.PutUint32(plain[:4], profile[kind])
		if cipher != nil {
			target := length
			if target > cipher.maxBytes {
				if !cipher.prefix {
					return nil, errFakeTCPGSOSegment
				}
				target = cipher.maxBytes
			}
			for index := 0; index < target; index++ {
				plain[index] ^= cipher.key[index&255]
			}
		}
		rotated := append(append([]byte(nil), plain[12:]...), plain[:12]...)
		tcp := make([]byte, 20)
		binary.BigEndian.PutUint16(tcp[0:2], 31001)
		binary.BigEndian.PutUint16(tcp[2:4], 443)
		binary.BigEndian.PutUint32(tcp[4:8], sequence+uint32(processed))
		binary.BigEndian.PutUint32(tcp[8:12], acknowledgement)
		tcp[12] = 5 << 4
		tcp[13] = 0x10
		if processed+length == len(aggregate) {
			tcp[13] |= 0x08
		}
		binary.BigEndian.PutUint16(tcp[14:16], 4096)
		binary.BigEndian.PutUint16(tcp[16:18], testTransportChecksum(6, tcp, rotated))
		segments = append(segments, fakeTCPGSOWireSegment{
			sequence: sequence + uint32(processed),
			payload:  rotated,
			tcp:      tcp,
		})
		processed += length
	}
	return segments, nil
}

func fakeTCPWireGuardKind(value uint32) int {
	switch value {
	case 1:
		return 0
	case 2:
		return 1
	case 3:
		return 2
	case 4:
		return 3
	default:
		return -1
	}
}

func fakeTCPWireGuardLengthValid(kind, length int) bool {
	switch kind {
	case 0:
		return length == 148
	case 1:
		return length == 92
	case 2:
		return length == 64
	case 3:
		return length >= 32
	default:
		return false
	}
}

func validFakeTCPGSODescriptor() fakeTCPGSODescriptor {
	return fakeTCPGSODescriptor{
		GSOType:                fakeTCPGSOTypeUDPL4,
		IPv4FixedHeader:        true,
		ChecksumPartial:        true,
		ExactHeaderOffsets:     true,
		ExactChecksumOffsets:   true,
		WritableLinearPrepared: true,
		PayloadLength:          160,
		GSOSize:                64,
		GSOSegments:            3,
		DevicePresent:          true,
		DeviceMTU:              1500,
		RoutePresent:           true,
		RouteDeviceMatches:     true,
		RouteMTU:               1500,
	}
}

func TestFakeTCPGSOSupportMatrixHasOneAcceptedFamily(t *testing.T) {
	valid := validFakeTCPGSODescriptor()
	if err := validateFakeTCPGSODescriptor(valid); err != nil {
		t.Fatalf("exact UDP_L4 contract rejected: %v", err)
	}
	valid.GSOType |= fakeTCPGSOTypeDodgy
	if err := validateFakeTCPGSODescriptor(valid); err != nil {
		t.Fatalf("validated DODGY UDP_L4 contract rejected: %v", err)
	}
	valid.GSOSegments = 0
	if err := validateFakeTCPGSODescriptor(valid); err != nil {
		t.Fatalf("DODGY zero segment count was not normalized: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*fakeTCPGSODescriptor)
		want   error
	}{
		{name: "not-udp-l4", mutate: func(d *fakeTCPGSODescriptor) { d.GSOType = 0 }, want: errFakeTCPGSOType},
		{name: "tunnel", mutate: func(d *fakeTCPGSODescriptor) { d.GSOType |= fakeTCPGSOTypeTunnel }, want: errFakeTCPGSOType},
		{name: "gro-fraglist", mutate: func(d *fakeTCPGSODescriptor) { d.GSOType |= fakeTCPGSOTypeFragList; d.HasFragList = true }, want: errFakeTCPGSOType},
		{name: "encapsulated", mutate: func(d *fakeTCPGSODescriptor) { d.Encapsulated = true }, want: errFakeTCPGSOType},
		{name: "ipv6-or-options", mutate: func(d *fakeTCPGSODescriptor) { d.IPv4FixedHeader = false }, want: errFakeTCPGSOMetadata},
		{name: "checksum-none", mutate: func(d *fakeTCPGSODescriptor) { d.ChecksumPartial = false }, want: errFakeTCPGSOMetadata},
		{name: "checksum-offset", mutate: func(d *fakeTCPGSODescriptor) { d.ExactChecksumOffsets = false }, want: errFakeTCPGSOMetadata},
		{name: "nonlinear-not-prepared", mutate: func(d *fakeTCPGSODescriptor) { d.WritableLinearPrepared = false }, want: errFakeTCPGSOMetadata},
		{name: "one-segment", mutate: func(d *fakeTCPGSODescriptor) { d.PayloadLength = 64; d.GSOSegments = 1 }, want: errFakeTCPGSOGeometry},
		{name: "trusted-zero-segments", mutate: func(d *fakeTCPGSODescriptor) { d.GSOSegments = 0 }, want: errFakeTCPGSOGeometry},
		{name: "segment-count", mutate: func(d *fakeTCPGSODescriptor) { d.GSOSegments = 4 }, want: errFakeTCPGSOGeometry},
		{name: "short-last", mutate: func(d *fakeTCPGSODescriptor) { d.PayloadLength = 129 }, want: errFakeTCPGSOGeometry},
		{name: "device-missing", mutate: func(d *fakeTCPGSODescriptor) { d.DevicePresent = false }, want: errFakeTCPGSOMTUDeviceUnknown},
		{name: "device-mtu-unknown", mutate: func(d *fakeTCPGSODescriptor) { d.DeviceMTU = 0 }, want: errFakeTCPGSOMTUDeviceUnknown},
		{name: "device-mtu-exceeded", mutate: func(d *fakeTCPGSODescriptor) { d.DeviceMTU = 103 }, want: errFakeTCPGSOMTUDeviceExceeded},
		{name: "route-missing", mutate: func(d *fakeTCPGSODescriptor) { d.RoutePresent = false }, want: errFakeTCPGSOMTURouteUnknown},
		{name: "metadata-dst", mutate: func(d *fakeTCPGSODescriptor) { d.RouteMetadata = true }, want: errFakeTCPGSOMTURouteUnknown},
		{name: "route-device-mismatch", mutate: func(d *fakeTCPGSODescriptor) { d.RouteDeviceMatches = false }, want: errFakeTCPGSOMTURouteUnknown},
		{name: "route-mtu-unknown", mutate: func(d *fakeTCPGSODescriptor) { d.RouteMTU = 0 }, want: errFakeTCPGSOMTURouteUnknown},
		{name: "route-mtu-exceeded", mutate: func(d *fakeTCPGSODescriptor) { d.RouteMTU = 103 }, want: errFakeTCPGSOMTURouteExceeded},
		{name: "aggregate-over-ipv4", mutate: func(d *fakeTCPGSODescriptor) {
			d.PayloadLength = fakeTCPGSOMaxPayload + 1
			d.GSOSize = 64
			d.GSOSegments = (d.PayloadLength + 63) / 64
		}, want: errFakeTCPGSOGeometry},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			descriptor := validFakeTCPGSODescriptor()
			test.mutate(&descriptor)
			if err := validateFakeTCPGSODescriptor(descriptor); !errors.Is(err, test.want) {
				t.Fatalf("error=%v, want %v", err, test.want)
			}
		})
	}

	deviceFirst := validFakeTCPGSODescriptor()
	deviceFirst.DeviceMTU = 103
	deviceFirst.RoutePresent = false
	if err := validateFakeTCPGSODescriptor(deviceFirst); !errors.Is(err, errFakeTCPGSOMTUDeviceExceeded) {
		t.Fatalf("device/route precedence error=%v, want device exceeded", err)
	}
}

func TestFakeTCPGSOPMTUUsesLargestUDPPayloadSegmentAndChecksLastSegment(t *testing.T) {
	descriptor := validFakeTCPGSODescriptor()
	descriptor.PayloadLength = 4096
	descriptor.GSOSize = 1400
	descriptor.GSOSegments = 3
	descriptor.DeviceMTU = 1440
	descriptor.RouteMTU = 1440
	if err := validateFakeTCPGSODescriptor(descriptor); err != nil {
		t.Fatalf("exact TCP wire L3 boundary rejected: %v", err)
	}
	if got := 20 + 20 + descriptor.GSOSize; got != 1440 {
		t.Fatalf("planned maximum wire L3=%d, want 1440", got)
	}
	if last := descriptor.PayloadLength - (descriptor.GSOSegments-1)*descriptor.GSOSize; last != 1296 {
		t.Fatalf("last segment=%d, want 1296", last)
	}

	descriptor.RouteMTU = 1439
	if err := validateFakeTCPGSODescriptor(descriptor); !errors.Is(err, errFakeTCPGSOMTURouteExceeded) {
		t.Fatalf("one-over route PMTU error=%v, want exceeded", err)
	}
	descriptor.RouteMTU = 1440
	descriptor.PayloadLength = 2831
	descriptor.GSOSegments = 3
	if err := validateFakeTCPGSODescriptor(descriptor); !errors.Is(err, errFakeTCPGSOGeometry) {
		t.Fatalf("31-byte last segment error=%v, want geometry rejection", err)
	}
}

func TestFakeTCPGSOPerSegmentTypeXORRotationSequenceAndChecksum(t *testing.T) {
	descriptor := validFakeTCPGSODescriptor()
	aggregate := make([]byte, descriptor.PayloadLength)
	for index := range aggregate {
		aggregate[index] = byte(index*13 + 9)
	}
	binary.LittleEndian.PutUint32(aggregate[0:4], 3)
	binary.LittleEndian.PutUint32(aggregate[64:68], 3)
	binary.LittleEndian.PutUint32(aggregate[128:132], 4)
	profile := [4]uint32{0xa1b2c3d4, 0xb2c3d4e5, 0xc3d4e5f6, 0x13dff06b}
	key := make([]byte, 256)
	for index := range key {
		key[index] = byte(index*17 + 5)
	}
	cipher := &fakeTCPGSOModelCipher{key: key, maxBytes: 48, prefix: true}

	segments, err := transformFakeTCPGSOSegments(
		descriptor, aggregate, profile, cipher, 0x01020304, 0x11223344,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(segments) != 3 {
		t.Fatalf("segments=%d, want 3", len(segments))
	}
	for index, segment := range segments {
		start := index * descriptor.GSOSize
		length := min(descriptor.GSOSize, descriptor.PayloadLength-start)
		want := append([]byte(nil), aggregate[start:start+length]...)
		kind := fakeTCPWireGuardKind(binary.LittleEndian.Uint32(want[:4]))
		binary.LittleEndian.PutUint32(want[:4], profile[kind])
		for byteIndex := 0; byteIndex < min(length, cipher.maxBytes); byteIndex++ {
			want[byteIndex] ^= key[byteIndex&255]
		}
		want = append(append([]byte(nil), want[12:]...), want[:12]...)
		if !bytes.Equal(segment.payload, want) {
			t.Fatalf("segment %d payload mismatch\n got %x\nwant %x", index, segment.payload, want)
		}
		wantSequence := uint32(0x01020304 + start)
		if segment.sequence != wantSequence || binary.BigEndian.Uint32(segment.tcp[4:8]) != wantSequence {
			t.Fatalf("segment %d sequence=%#x header=%#x want=%#x", index, segment.sequence, binary.BigEndian.Uint32(segment.tcp[4:8]), wantSequence)
		}
		wantFlags := byte(0x10)
		if index == len(segments)-1 {
			wantFlags = 0x18
		}
		if segment.tcp[13] != wantFlags {
			t.Fatalf("segment %d flags=%#x, want %#x", index, segment.tcp[13], wantFlags)
		}
		tcp := append([]byte(nil), segment.tcp...)
		gotChecksum := binary.BigEndian.Uint16(tcp[16:18])
		tcp[16], tcp[17] = 0, 0
		if wantChecksum := testTransportChecksum(6, tcp, segment.payload); gotChecksum != wantChecksum {
			t.Fatalf("segment %d checksum=%#x, want %#x", index, gotChecksum, wantChecksum)
		}
	}
	if bytes.Equal(segments[0].payload, segments[1].payload) {
		t.Fatal("test fixture failed to distinguish segment payloads")
	}
	// Both full-size segments restart XOR at key byte zero; aggregate-global
	// key position 64 must never leak into the second logical datagram.
	secondPreRotationType := append([]byte(nil), segments[1].payload[len(segments[1].payload)-12:]...)
	wantSecondType := make([]byte, 4)
	binary.LittleEndian.PutUint32(wantSecondType, profile[2])
	for index := range wantSecondType {
		wantSecondType[index] ^= key[index]
	}
	if !bytes.Equal(secondPreRotationType[:4], wantSecondType) {
		t.Fatalf("second segment did not reset XOR stream: got %x want %x", secondPreRotationType[:4], wantSecondType)
	}
}

func TestFakeTCPGSODirectCommitRejectsNonExclusiveStorage(t *testing.T) {
	commitWritable := func(shared, cloned, headerCloned, nonlinear bool, headroom int) bool {
		return !shared && !cloned && !headerCloned && !nonlinear && headroom >= 12
	}
	if !commitWritable(false, false, false, false, 12) {
		t.Fatal("exclusive prepared skb was rejected")
	}
	for _, test := range []struct {
		name         string
		shared       bool
		cloned       bool
		headerCloned bool
		nonlinear    bool
		headroom     int
	}{
		{name: "shared-skb", shared: true, headroom: 12},
		{name: "linear-but-cloned", cloned: true, headroom: 12},
		{name: "header-cloned", headerCloned: true, headroom: 12},
		{name: "nonlinear", nonlinear: true, headroom: 12},
		{name: "missing-headroom", headroom: 11},
	} {
		t.Run(test.name, func(t *testing.T) {
			if commitWritable(test.shared, test.cloned, test.headerCloned, test.nonlinear, test.headroom) {
				t.Fatal("direct commit accepted storage that prepare did not make exclusive")
			}
		})
	}
}

func TestFakeTCPGSOContractIsBuildAndEvidenceGated(t *testing.T) {
	bpfSource, err := os.ReadFile("../../bpf/wg_mix_faketcp.h")
	if err != nil {
		t.Fatal(err)
	}
	kernelSource, err := os.ReadFile("../../kernel/faketcp_checksum/wg_mix_faketcp_checksum.c")
	if err != nil {
		t.Fatal(err)
	}
	bpf := string(bpfSource)
	kernel := string(kernelSource)
	for _, required := range []string{
		"wg_mix_faketcp_skb_prepare_udp(",
		"wg_mix_faketcp_skb_commit_udp_gso(",
		"Non-fraglist aggregates are source-neutral",
		"bpf_loop(context.gso_segments, faketcp_gso_validate_segment",
		"segment_index = index / context->xor_chunks_per_segment",
		"target_length = segment_length < context->cipher->max_bytes",
		"__sync_fetch_and_add(&session->tx_sequence",
	} {
		if !strings.Contains(bpf, required) {
			t.Fatalf("BPF GSO contract missing %q", required)
		}
	}
	for _, required := range []string{
		"const unsigned int allowed_gso_type = SKB_GSO_UDP_L4 | SKB_GSO_DODGY",
		"shinfo->gso_type & ~allowed_gso_type",
		"if (skb_shared(skb))",
		"skb_linearize_cow(skb)",
		"skb_cow_head(skb, WG_MIX_FAKETCP_HEADER_DELTA)",
		"skb_shared(skb) || skb_cloned(skb) || skb_header_cloned(skb)",
		"#include <net/dst_metadata.h>",
		"struct net_device *device = READ_ONCE(skb->dev)",
		"device_mtu = READ_ONCE(device->mtu)",
		"if (!skb_valid_dst(skb))",
		"if (READ_ONCE(dst->dev) != device)",
		"route_mtu = dst_mtu(dst)",
		"sizeof(struct iphdr) + sizeof(struct tcphdr) +",
		"gso_modifier = shinfo->gso_type & SKB_GSO_DODGY",
		"shinfo->gso_type = SKB_GSO_TCPV4 | gso_modifier",
		"tcp->check = ~tcp_v4_check",
	} {
		if !strings.Contains(kernel, required) {
			t.Fatalf("kernel GSO contract missing %q", required)
		}
	}
	gsoStart := strings.Index(bpf, "faketcp_encode_gso_segments(struct __sk_buff *skb")
	gsoEnd := strings.Index(bpf, "static __always_inline __s64 faketcp_rotation_checksum")
	if gsoStart < 0 || gsoEnd <= gsoStart {
		t.Fatal("GSO encoder boundaries are missing")
	}
	gso := bpf[gsoStart:gsoEnd]
	parseGate := strings.Index(gso, "faketcp_parse_tc_l3(skb, info, &l3) != FAKETCP_L3_OK")
	prepare := strings.Index(gso, "faketcp_prepare_udp(skb, info->ip_off, info->udp_off")
	rewrite := strings.Index(gso, "bpf_loop(context.gso_segments, faketcp_gso_rewrite_type")
	if parseGate < 0 || prepare < 0 || rewrite < 0 || !(parseGate < prepare && prepare < rewrite) {
		t.Fatal("shared fixed-IPv4 gate and unified prepare must precede every GSO mutation")
	}
	commitStart := strings.Index(kernel, "wg_mix_faketcp_skb_commit_udp_gso(struct __sk_buff *ctx")
	if commitStart < 0 {
		t.Fatal("GSO commit boundary is missing")
	}
	commit := kernel[commitStart:]
	geometry := strings.Index(commit, "wg_mix_faketcp_validate_udp_gso(skb, transport_offset")
	writable := strings.Index(commit, "skb_shared(skb) || skb_cloned(skb) || skb_header_cloned(skb)")
	mutation := strings.Index(commit, "wg_mix_faketcp_rotate_gso_payload(skb")
	if geometry < 0 || writable < 0 || mutation < 0 || !(geometry < writable && writable < mutation) {
		t.Fatal("direct GSO commit must revalidate geometry and reject shared storage before its first write")
	}
	if fakeTCPImplementedCapabilities&fakeTCPCapabilityGSOPerSegmentTransform != 0 {
		t.Fatal("GSO capability opened before verifier and .82 wire evidence")
	}
}

func BenchmarkFakeTCPGSOPerSegmentTransformModel(b *testing.B) {
	const (
		segmentSize  = 1420
		segmentCount = 32
	)
	descriptor := validFakeTCPGSODescriptor()
	descriptor.PayloadLength = segmentSize * segmentCount
	descriptor.GSOSize = segmentSize
	descriptor.GSOSegments = segmentCount
	aggregate := make([]byte, descriptor.PayloadLength)
	for segment := 0; segment < segmentCount; segment++ {
		binary.LittleEndian.PutUint32(aggregate[segment*segmentSize:], 4)
	}
	profile := [4]uint32{0xa1b2c3d4, 0xb2c3d4e5, 0xc3d4e5f6, 0x13dff06b}
	key := make([]byte, 256)
	for index := range key {
		key[index] = byte(index*17 + 5)
	}
	b.SetBytes(int64(len(aggregate)))
	for _, benchmark := range []struct {
		name   string
		cipher fakeTCPGSOModelCipher
	}{
		{name: "prefix-128", cipher: fakeTCPGSOModelCipher{key: key, maxBytes: 128, prefix: true}},
		{name: "full", cipher: fakeTCPGSOModelCipher{key: key, maxBytes: 2048}},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			b.SetBytes(int64(len(aggregate)))
			b.ReportAllocs()
			for iteration := 0; iteration < b.N; iteration++ {
				if _, err := transformFakeTCPGSOSegments(
					descriptor, aggregate, profile, &benchmark.cipher,
					0x01020304, 0x11223344,
				); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
