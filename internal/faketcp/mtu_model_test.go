package faketcp

import (
	"fmt"
	"math"
)

// MTUFamily is the on-wire IP family used by the reference admission model.
type MTUFamily uint8

const (
	MTUFamilyIPv4 MTUFamily = 4
	MTUFamilyIPv6 MTUFamily = 6

	maximumIPPacketLength uint64 = math.MaxUint16
	ipv4MinimumHeader     uint64 = 20
	ipv4MaximumHeader     uint64 = 60
	ipv6MinimumHeader     uint64 = 40
	mtuUDPHeaderLength    uint64 = 8
)

// MTURequest describes the pre-transform packet for the test oracle.
type MTURequest struct {
	Family                 MTUFamily
	L3Length               uint64
	L3HeaderLength         uint64
	TransportPayloadLength uint64
	DeviceMTU              uint64
	RouteMTU               uint64

	IPv4DF              bool
	IPv4MoreFragments   bool
	FragmentOffsetBytes uint64
	IPv6FragmentHeader  bool

	GSOSize     uint64
	GSOSegments uint64
}

type MTUDecision struct {
	InputSegmentL3Length   uint64
	OutputSegmentL3Length  uint64
	EffectiveMTU           uint64
	GSO                    bool
	IPv4DF                 bool
	FragmentationForbidden bool
}

type MTUError struct {
	Code                  MTUErrorCode
	Boundary              MTUBoundary
	Family                MTUFamily
	InputL3Length         uint64
	InputSegmentL3Length  uint64
	OutputSegmentL3Length uint64
	DeviceMTU             uint64
	RouteMTU              uint64
	IPv4DF                bool
	GSO                   bool
	Detail                string
}

func (err *MTUError) Error() string {
	if err == nil {
		return "<nil>"
	}
	return fmt.Sprintf(
		"faketcp mtu admission %s: boundary=%s family=%d input_l3=%d input_segment_l3=%d output_segment_l3=%d device_mtu=%d route_mtu=%d ipv4_df=%t gso=%t: %s",
		err.Code,
		err.Boundary,
		err.Family,
		err.InputL3Length,
		err.InputSegmentL3Length,
		err.OutputSegmentL3Length,
		err.DeviceMTU,
		err.RouteMTU,
		err.IPv4DF,
		err.GSO,
		err.Detail,
	)
}

// AdmitMTU is the only reference model. Production admission lives solely in
// bpf/wg_mix_faketcp_mtu.h; keeping this oracle test-only prevents a second
// userspace policy implementation from becoming reachable.
func AdmitMTU(request MTURequest) (MTUDecision, error) {
	gso := request.GSOSize != 0 || request.GSOSegments != 0
	reject := func(code MTUErrorCode, boundary MTUBoundary, inputSegment, outputSegment uint64, detail string) (MTUDecision, error) {
		return MTUDecision{}, &MTUError{
			Code:                  code,
			Boundary:              boundary,
			Family:                request.Family,
			InputL3Length:         request.L3Length,
			InputSegmentL3Length:  inputSegment,
			OutputSegmentL3Length: outputSegment,
			DeviceMTU:             request.DeviceMTU,
			RouteMTU:              request.RouteMTU,
			IPv4DF:                request.IPv4DF,
			GSO:                   gso,
			Detail:                detail,
		}
	}

	switch request.Family {
	case MTUFamilyIPv4:
		if request.L3HeaderLength < ipv4MinimumHeader ||
			request.L3HeaderLength > ipv4MaximumHeader ||
			request.L3HeaderLength%4 != 0 {
			return reject(MTUErrorInvalidInput, MTUBoundaryInput, 0, 0, "IPv4 header length is outside the 20..60-byte aligned range")
		}
		if request.IPv6FragmentHeader {
			return reject(MTUErrorInvalidInput, MTUBoundaryInput, 0, 0, "IPv4 request carries IPv6 fragment metadata")
		}
		if request.IPv4MoreFragments || request.FragmentOffsetBytes != 0 {
			return reject(MTUErrorFragmentationRejected, MTUBoundaryInput, 0, 0, "IPv4 fragments are not a FakeTCP transform input")
		}
	case MTUFamilyIPv6:
		if request.L3HeaderLength < ipv6MinimumHeader ||
			request.L3HeaderLength > maximumIPPacketLength ||
			request.L3HeaderLength%8 != 0 {
			return reject(MTUErrorInvalidInput, MTUBoundaryInput, 0, 0, "IPv6 header chain is shorter than 40 bytes or not 8-byte aligned")
		}
		if request.IPv4DF || request.IPv4MoreFragments || request.FragmentOffsetBytes != 0 {
			return reject(MTUErrorInvalidInput, MTUBoundaryInput, 0, 0, "IPv6 request carries IPv4 fragmentation metadata")
		}
		if request.IPv6FragmentHeader {
			return reject(MTUErrorFragmentationRejected, MTUBoundaryInput, 0, 0, "IPv6 fragment headers are not a FakeTCP transform input")
		}
	default:
		return reject(MTUErrorInvalidInput, MTUBoundaryInput, 0, 0, "only IPv4 and IPv6 are supported")
	}

	baseLength, overflow := checkedAddUint64(request.L3HeaderLength, mtuUDPHeaderLength)
	if overflow {
		return reject(MTUErrorArithmeticOverflow, MTUBoundaryInput, 0, 0, "L3 and UDP header length addition overflowed")
	}
	wantL3Length, overflow := checkedAddUint64(baseLength, request.TransportPayloadLength)
	if overflow {
		return reject(MTUErrorArithmeticOverflow, MTUBoundaryInput, 0, 0, "aggregate L3 length addition overflowed")
	}
	if request.L3Length != wantL3Length || request.L3Length > maximumIPPacketLength {
		return reject(MTUErrorInvalidInput, MTUBoundaryInput, 0, 0, "L3 length does not exactly match headers plus transport payload, or is a jumbogram")
	}

	inputSegment := request.L3Length
	if gso {
		if request.GSOSize == 0 || request.GSOSegments == 0 || request.TransportPayloadLength == 0 {
			return reject(MTUErrorInvalidInput, MTUBoundaryInput, 0, 0, "GSO size, segment count, and transport payload must all be nonzero")
		}
		expectedSegments := request.TransportPayloadLength / request.GSOSize
		if request.TransportPayloadLength%request.GSOSize != 0 {
			expectedSegments++
		}
		if request.GSOSegments != expectedSegments {
			return reject(MTUErrorInvalidInput, MTUBoundaryInput, 0, 0, "GSO segment count is not the exact payload/size ceiling")
		}
		segmentPayload := min(request.GSOSize, request.TransportPayloadLength)
		inputSegment, overflow = checkedAddUint64(baseLength, segmentPayload)
		if overflow {
			return reject(MTUErrorArithmeticOverflow, MTUBoundaryInput, 0, 0, "GSO segment L3 length addition overflowed")
		}
	}
	outputSegment, overflow := checkedAddUint64(inputSegment, FakeTCPHeaderDelta)
	if overflow {
		return reject(MTUErrorArithmeticOverflow, MTUBoundaryInput, inputSegment, 0, "FakeTCP header growth overflowed")
	}
	if outputSegment > maximumIPPacketLength {
		return reject(MTUErrorInvalidInput, MTUBoundaryInput, inputSegment, outputSegment, "post-transform segment exceeds the non-jumbogram IP length limit")
	}
	if request.DeviceMTU == 0 || request.DeviceMTU > math.MaxUint32 {
		return reject(MTUErrorUnknown, MTUBoundaryDevice, inputSegment, outputSegment, "device MTU is absent or outside the kernel helper ABI")
	}
	if outputSegment > request.DeviceMTU {
		return reject(MTUErrorExceeded, MTUBoundaryDevice, inputSegment, outputSegment, "FakeTCP never fragments an oversized output segment")
	}
	if request.RouteMTU == 0 || request.RouteMTU > math.MaxUint32 {
		return reject(MTUErrorUnknown, MTUBoundaryRoute, inputSegment, outputSegment, "route MTU is absent or outside the kernel helper ABI")
	}
	if outputSegment > request.RouteMTU {
		return reject(MTUErrorExceeded, MTUBoundaryRoute, inputSegment, outputSegment, "FakeTCP never fragments an oversized output segment")
	}

	return MTUDecision{
		InputSegmentL3Length:   inputSegment,
		OutputSegmentL3Length:  outputSegment,
		EffectiveMTU:           min(request.DeviceMTU, request.RouteMTU),
		GSO:                    gso,
		IPv4DF:                 request.IPv4DF,
		FragmentationForbidden: true,
	}, nil
}

func checkedAddUint64(left, right uint64) (uint64, bool) {
	if left > math.MaxUint64-right {
		return 0, true
	}
	return left + right, false
}
