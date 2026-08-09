package faketcp

import (
	"errors"
	"math"
	"strings"
	"testing"
)

func TestAdmitMTUBoundaryTable(t *testing.T) {
	baseIPv4 := MTURequest{
		Family:                 MTUFamilyIPv4,
		L3Length:               1488,
		L3HeaderLength:         20,
		TransportPayloadLength: 1460,
		DeviceMTU:              1500,
		RouteMTU:               1500,
		IPv4DF:                 true,
	}
	baseIPv6 := MTURequest{
		Family:                 MTUFamilyIPv6,
		L3Length:               1488,
		L3HeaderLength:         40,
		TransportPayloadLength: 1440,
		DeviceMTU:              1500,
		RouteMTU:               1500,
	}

	tests := []struct {
		name         string
		request      MTURequest
		wantOutput   uint64
		wantCode     MTUErrorCode
		wantBoundary MTUBoundary
	}{
		{name: "ipv4 exact mtu minus delta with DF", request: baseIPv4, wantOutput: 1500},
		{name: "ipv6 exact mtu minus delta", request: baseIPv6, wantOutput: 1500},
		{
			name: "ipv4 one over device with DF",
			request: mutateMTURequest(baseIPv4, func(request *MTURequest) {
				request.L3Length++
				request.TransportPayloadLength++
			}),
			wantCode: MTUErrorExceeded, wantBoundary: MTUBoundaryDevice,
		},
		{
			name: "ipv4 one over device without DF still cannot fragment",
			request: mutateMTURequest(baseIPv4, func(request *MTURequest) {
				request.L3Length++
				request.TransportPayloadLength++
				request.IPv4DF = false
			}),
			wantCode: MTUErrorExceeded, wantBoundary: MTUBoundaryDevice,
		},
		{
			name: "ipv6 one over device",
			request: mutateMTURequest(baseIPv6, func(request *MTURequest) {
				request.L3Length++
				request.TransportPayloadLength++
			}),
			wantCode: MTUErrorExceeded, wantBoundary: MTUBoundaryDevice,
		},
		{
			name: "route pmtu exact",
			request: mutateMTURequest(baseIPv4, func(request *MTURequest) {
				request.L3Length = 1480
				request.TransportPayloadLength = 1452
				request.RouteMTU = 1492
			}),
			wantOutput: 1492,
		},
		{
			name: "route pmtu one over",
			request: mutateMTURequest(baseIPv4, func(request *MTURequest) {
				request.L3Length = 1481
				request.TransportPayloadLength = 1453
				request.RouteMTU = 1492
			}),
			wantCode: MTUErrorExceeded, wantBoundary: MTUBoundaryRoute,
		},
		{
			name:     "device unknown",
			request:  mutateMTURequest(baseIPv4, func(request *MTURequest) { request.DeviceMTU = 0 }),
			wantCode: MTUErrorUnknown, wantBoundary: MTUBoundaryDevice,
		},
		{
			name:     "route unknown",
			request:  mutateMTURequest(baseIPv4, func(request *MTURequest) { request.RouteMTU = 0 }),
			wantCode: MTUErrorUnknown, wantBoundary: MTUBoundaryRoute,
		},
		{
			name:     "IPv4 first fragment",
			request:  mutateMTURequest(baseIPv4, func(request *MTURequest) { request.IPv4MoreFragments = true }),
			wantCode: MTUErrorFragmentationRejected, wantBoundary: MTUBoundaryInput,
		},
		{
			name:     "IPv4 non-initial fragment",
			request:  mutateMTURequest(baseIPv4, func(request *MTURequest) { request.FragmentOffsetBytes = 8 }),
			wantCode: MTUErrorFragmentationRejected, wantBoundary: MTUBoundaryInput,
		},
		{
			name:     "IPv6 fragment header",
			request:  mutateMTURequest(baseIPv6, func(request *MTURequest) { request.IPv6FragmentHeader = true }),
			wantCode: MTUErrorFragmentationRejected, wantBoundary: MTUBoundaryInput,
		},
		{
			name:     "unknown family",
			request:  mutateMTURequest(baseIPv4, func(request *MTURequest) { request.Family = 5 }),
			wantCode: MTUErrorInvalidInput, wantBoundary: MTUBoundaryInput,
		},
		{
			name:     "L3 length mismatch",
			request:  mutateMTURequest(baseIPv4, func(request *MTURequest) { request.L3Length-- }),
			wantCode: MTUErrorInvalidInput, wantBoundary: MTUBoundaryInput,
		},
		{
			name: "aggregate arithmetic overflow",
			request: mutateMTURequest(baseIPv6, func(request *MTURequest) {
				request.L3HeaderLength = 40
				request.TransportPayloadLength = math.MaxUint64
				request.L3Length = 1
			}),
			wantCode: MTUErrorArithmeticOverflow, wantBoundary: MTUBoundaryInput,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision, err := AdmitMTU(test.request)
			if test.wantCode == "" {
				if err != nil {
					t.Fatalf("AdmitMTU() error = %v", err)
				}
				if decision.OutputSegmentL3Length != test.wantOutput {
					t.Fatalf("output segment L3 = %d, want %d", decision.OutputSegmentL3Length, test.wantOutput)
				}
				if !decision.FragmentationForbidden {
					t.Fatal("accepted decision permits fragmentation")
				}
				return
			}
			if err == nil {
				t.Fatalf("AdmitMTU() accepted %+v, want %s", decision, test.wantCode)
			}
			var mtuErr *MTUError
			if !errors.As(err, &mtuErr) {
				t.Fatalf("error type = %T, want *MTUError", err)
			}
			if mtuErr.Code != test.wantCode {
				t.Fatalf("error code = %q, want %q; error=%v", mtuErr.Code, test.wantCode, err)
			}
			if mtuErr.Boundary != test.wantBoundary {
				t.Fatalf("error boundary = %q, want %q; error=%v", mtuErr.Boundary, test.wantBoundary, err)
			}
			for _, field := range []string{"boundary=", "family=", "input_l3=", "output_segment_l3=", "device_mtu=", "route_mtu=", "ipv4_df=", "gso="} {
				if !strings.Contains(err.Error(), field) {
					t.Fatalf("auditable error %q missing %q", err, field)
				}
			}
		})
	}
}

func TestAdmitMTUGSOMaximumWireSegment(t *testing.T) {
	base := MTURequest{
		Family:                 MTUFamilyIPv4,
		L3Length:               20 + 8 + 4096,
		L3HeaderLength:         20,
		TransportPayloadLength: 4096,
		DeviceMTU:              1500,
		RouteMTU:               1500,
		IPv4DF:                 true,
		GSOSize:                1400,
		GSOSegments:            3,
	}
	decision, err := AdmitMTU(base)
	if err != nil {
		t.Fatalf("AdmitMTU(GSO) error = %v", err)
	}
	if !decision.GSO || decision.InputSegmentL3Length != 1428 || decision.OutputSegmentL3Length != 1440 {
		t.Fatalf("GSO decision = %+v, want input/output 1428/1440", decision)
	}

	tests := []struct {
		name         string
		mutate       func(*MTURequest)
		wantCode     MTUErrorCode
		wantBoundary MTUBoundary
	}{
		{name: "missing segment count", mutate: func(request *MTURequest) { request.GSOSegments = 0 }, wantCode: MTUErrorInvalidInput, wantBoundary: MTUBoundaryInput},
		{name: "missing segment size", mutate: func(request *MTURequest) { request.GSOSize = 0 }, wantCode: MTUErrorInvalidInput, wantBoundary: MTUBoundaryInput},
		{name: "wrong segment count", mutate: func(request *MTURequest) { request.GSOSegments = 4 }, wantCode: MTUErrorInvalidInput, wantBoundary: MTUBoundaryInput},
		{name: "per-segment route exceed", mutate: func(request *MTURequest) { request.RouteMTU = 1439 }, wantCode: MTUErrorExceeded, wantBoundary: MTUBoundaryRoute},
		{name: "per-segment device exceed", mutate: func(request *MTURequest) { request.DeviceMTU = 1439 }, wantCode: MTUErrorExceeded, wantBoundary: MTUBoundaryDevice},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := mutateMTURequest(base, test.mutate)
			_, err := AdmitMTU(request)
			var mtuErr *MTUError
			if !errors.As(err, &mtuErr) || mtuErr.Code != test.wantCode || mtuErr.Boundary != test.wantBoundary {
				t.Fatalf("AdmitMTU() error = %v, want %s/%s", err, test.wantCode, test.wantBoundary)
			}
		})
	}
}

func TestDecodeMTUAuditKey(t *testing.T) {
	wantReasons := []MTUErrorCode{
		MTUErrorInvalidInput,
		MTUErrorArithmeticOverflow,
		MTUErrorFragmentationRejected,
		MTUErrorUnknown,
		MTUErrorExceeded,
	}
	wantBoundaries := []MTUBoundary{
		MTUBoundaryInput,
		MTUBoundaryDevice,
		MTUBoundaryRoute,
	}
	for reasonIndex, wantReason := range wantReasons {
		for boundaryIndex, wantBoundary := range wantBoundaries {
			key := uint32(reasonIndex*len(wantBoundaries) + boundaryIndex)
			encoded, err := EncodeMTUAuditKey(wantReason, wantBoundary)
			if err != nil || encoded != key {
				t.Fatalf("classification %q/%q = key %d, %v; want %d", wantReason, wantBoundary, encoded, err, key)
			}
			gotReason, gotBoundary, err := DecodeMTUAuditKey(key)
			if err != nil || gotReason != wantReason || gotBoundary != wantBoundary {
				t.Fatalf("key %d = %q/%q, %v; want %q/%q", key, gotReason, gotBoundary, err, wantReason, wantBoundary)
			}
		}
	}
	if _, _, err := DecodeMTUAuditKey(MTUAuditKeyCount); err == nil {
		t.Fatal("out-of-range MTU audit key was accepted")
	}
	if _, err := EncodeMTUAuditKey("not-a-reason", MTUBoundaryInput); err == nil {
		t.Fatal("unknown MTU audit reason was accepted")
	}
	if _, err := EncodeMTUAuditKey(MTUErrorExceeded, "not-a-boundary"); err == nil {
		t.Fatal("unknown MTU audit boundary was accepted")
	}
}

func TestAdmitMTURejectPrecedenceMatchesDataplaneBoundaries(t *testing.T) {
	request := MTURequest{
		Family:                 MTUFamilyIPv4,
		L3Length:               1489,
		L3HeaderLength:         20,
		TransportPayloadLength: 1461,
		DeviceMTU:              1500,
		RouteMTU:               0,
	}
	_, err := AdmitMTU(request)
	var mtuErr *MTUError
	if !errors.As(err, &mtuErr) || mtuErr.Code != MTUErrorExceeded || mtuErr.Boundary != MTUBoundaryDevice {
		t.Fatalf("AdmitMTU() error = %v, want device/exceeded before route/unknown", err)
	}
}

func TestAdmitMTUBoundaryProperty(t *testing.T) {
	for _, family := range []MTUFamily{MTUFamilyIPv4, MTUFamilyIPv6} {
		headerLength := uint64(20)
		if family == MTUFamilyIPv6 {
			headerLength = 40
		}
		for mtu := uint64(576); mtu <= 9000; mtu += 137 {
			for offset := int64(-2); offset <= 2; offset++ {
				input := int64(mtu-FakeTCPHeaderDelta) + offset
				if input < int64(headerLength+mtuUDPHeaderLength) {
					continue
				}
				request := MTURequest{
					Family:                 family,
					L3Length:               uint64(input),
					L3HeaderLength:         headerLength,
					TransportPayloadLength: uint64(input) - headerLength - mtuUDPHeaderLength,
					DeviceMTU:              mtu,
					RouteMTU:               mtu,
					IPv4DF:                 family == MTUFamilyIPv4,
				}
				decision, err := AdmitMTU(request)
				wantAccept := offset <= 0
				if wantAccept != (err == nil) {
					t.Fatalf("family=%d mtu=%d offset=%d decision=%+v error=%v", family, mtu, offset, decision, err)
				}
				if err == nil && decision.OutputSegmentL3Length > decision.EffectiveMTU {
					t.Fatalf("accepted output %d above effective MTU %d", decision.OutputSegmentL3Length, decision.EffectiveMTU)
				}
			}
		}
	}
}

func FuzzAdmitMTUNeverAcceptsOversizedSegment(f *testing.F) {
	f.Add(uint8(4), uint64(20), uint64(1200), uint64(0), uint64(1500), uint64(1500), false)
	f.Add(uint8(6), uint64(40), uint64(4096), uint64(1400), uint64(1500), uint64(1492), false)
	f.Fuzz(func(t *testing.T, familyRaw uint8, headerLength, payloadLength, gsoSize, deviceMTU, routeMTU uint64, fragmented bool) {
		family := MTUFamily(familyRaw)
		l3Length, overflow := checkedAddUint64(headerLength, mtuUDPHeaderLength)
		if !overflow {
			l3Length, overflow = checkedAddUint64(l3Length, payloadLength)
		}
		if overflow {
			l3Length = 0
		}
		segments := uint64(0)
		if gsoSize != 0 && payloadLength != 0 {
			segments = payloadLength / gsoSize
			if payloadLength%gsoSize != 0 && segments != math.MaxUint64 {
				segments++
			}
		}
		request := MTURequest{
			Family:                 family,
			L3Length:               l3Length,
			L3HeaderLength:         headerLength,
			TransportPayloadLength: payloadLength,
			DeviceMTU:              deviceMTU,
			RouteMTU:               routeMTU,
			IPv4DF:                 family == MTUFamilyIPv4,
			IPv4MoreFragments:      fragmented && family == MTUFamilyIPv4,
			IPv6FragmentHeader:     fragmented && family == MTUFamilyIPv6,
			GSOSize:                gsoSize,
			GSOSegments:            segments,
		}
		decision, err := AdmitMTU(request)
		if err != nil {
			return
		}
		if decision.OutputSegmentL3Length > request.DeviceMTU ||
			decision.OutputSegmentL3Length > request.RouteMTU ||
			fragmented || !decision.FragmentationForbidden {
			t.Fatalf("unsafe admission: request=%+v decision=%+v", request, decision)
		}
	})
}

func BenchmarkAdmitMTU(b *testing.B) {
	requests := map[string]MTURequest{
		"ipv4/non-gso": {
			Family: MTUFamilyIPv4, L3Length: 1420, L3HeaderLength: 20,
			TransportPayloadLength: 1392,
			DeviceMTU:              1500, RouteMTU: 1492, IPv4DF: true,
		},
		"ipv6/non-gso": {
			Family: MTUFamilyIPv6, L3Length: 1420, L3HeaderLength: 40,
			TransportPayloadLength: 1372,
			DeviceMTU:              1500, RouteMTU: 1492,
		},
		"ipv4/gso": {
			Family: MTUFamilyIPv4, L3Length: 20 + 8 + 4096, L3HeaderLength: 20,
			TransportPayloadLength: 4096,
			DeviceMTU:              1500, RouteMTU: 1492, IPv4DF: true,
			GSOSize: 1400, GSOSegments: 3,
		},
	}
	for name, request := range requests {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				decision, err := AdmitMTU(request)
				if err != nil || decision.OutputSegmentL3Length == 0 {
					b.Fatalf("AdmitMTU() = %+v, %v", decision, err)
				}
			}
		})
	}
}

func mutateMTURequest(request MTURequest, mutate func(*MTURequest)) MTURequest {
	mutate(&request)
	return request
}
