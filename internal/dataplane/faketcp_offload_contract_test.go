package dataplane

import (
	"os"
	"strings"
	"testing"
)

const (
	testChecksumNone        = uint8(0)
	testChecksumUnnecessary = uint8(1)
	testChecksumComplete    = uint8(2)
	testChecksumPartial     = uint8(3)

	testFakeTCPCSumAcceptNone           = 0
	testFakeTCPCSumAcceptPartialReset   = 1
	testFakeTCPCSumRejectPacket         = -1
	testFakeTCPCSumRejectState          = -2
	testFakeTCPCSumRejectMetadata       = -3
	testFakeTCPCSumRejectGSO            = -4
	testFakeTCPStatGSOReject            = 5
	testFakeTCPStatChecksumError        = 6
	testFakeTCPStatMetadataError        = 7
	testFakeTCPStatBadPacket            = 4
	testFakeTCPStatChecksumNone         = 13
	testFakeTCPStatChecksumPartialReset = 14
	testFakeTCPStatChecksumStateReject  = 15
)

// fakeTCPChecksumSKBModel contains only fields observed or reset by the narrow
// checksum kfunc. CSum aliases csum_start/csum_offset in struct sk_buff; the
// explicit alias fields make the required post-reset state executable here.
type fakeTCPChecksumSKBModel struct {
	PacketShapeValid   bool
	GSOSegments        uint32
	GSOSize            uint32
	IPSummed           uint8
	TransportHeaderSet bool
	TransportOffset    int
	ActualTransport    int
	CSumStart          int
	CSumOffset         int
	CSum               uint32
	CSumValid          bool
	CSumCompleteSW     bool
	CSumLevel          uint8
	CSumNotInet        bool
}

func normalizeFakeTCPChecksumModel(skb fakeTCPChecksumSKBModel) (fakeTCPChecksumSKBModel, int) {
	if skb.GSOSegments != 0 || skb.GSOSize != 0 {
		return skb, testFakeTCPCSumRejectGSO
	}
	if !skb.PacketShapeValid {
		return skb, testFakeTCPCSumRejectPacket
	}
	switch skb.IPSummed {
	case testChecksumNone:
		return skb, testFakeTCPCSumAcceptNone
	case testChecksumPartial:
	default:
		return skb, testFakeTCPCSumRejectState
	}
	if !skb.TransportHeaderSet || skb.ActualTransport != skb.TransportOffset ||
		skb.CSumStart != skb.TransportOffset || skb.CSumOffset != 6 {
		return skb, testFakeTCPCSumRejectMetadata
	}
	skb.CSum = 0
	skb.CSumStart = 0
	skb.CSumOffset = 0
	skb.CSumValid = false
	skb.CSumCompleteSW = false
	skb.CSumLevel = 0
	skb.CSumNotInet = false
	skb.IPSummed = testChecksumNone
	return skb, testFakeTCPCSumAcceptPartialReset
}

func TestFakeTCPChecksumStateAndMetadataResetContract(t *testing.T) {
	exactPartial := fakeTCPChecksumSKBModel{
		PacketShapeValid:   true,
		IPSummed:           testChecksumPartial,
		TransportHeaderSet: true,
		TransportOffset:    34,
		ActualTransport:    34,
		CSumStart:          34,
		CSumOffset:         6,
		CSum:               0xdeadbeef,
		CSumValid:          true,
		CSumCompleteSW:     true,
		CSumLevel:          2,
		CSumNotInet:        true,
	}
	tests := []struct {
		name       string
		mutate     func(*fakeTCPChecksumSKBModel)
		wantResult int
		wantReset  bool
	}{
		{name: "checksum-none", mutate: func(s *fakeTCPChecksumSKBModel) { s.IPSummed = testChecksumNone }, wantResult: testFakeTCPCSumAcceptNone},
		{name: "checksum-partial-exact", wantResult: testFakeTCPCSumAcceptPartialReset, wantReset: true},
		{name: "checksum-unnecessary", mutate: func(s *fakeTCPChecksumSKBModel) { s.IPSummed = testChecksumUnnecessary }, wantResult: testFakeTCPCSumRejectState},
		{name: "checksum-complete", mutate: func(s *fakeTCPChecksumSKBModel) { s.IPSummed = testChecksumComplete }, wantResult: testFakeTCPCSumRejectState},
		{name: "packet-shape", mutate: func(s *fakeTCPChecksumSKBModel) { s.PacketShapeValid = false }, wantResult: testFakeTCPCSumRejectPacket},
		{name: "partial-no-transport-header", mutate: func(s *fakeTCPChecksumSKBModel) { s.TransportHeaderSet = false }, wantResult: testFakeTCPCSumRejectMetadata},
		{name: "partial-transport-offset", mutate: func(s *fakeTCPChecksumSKBModel) { s.ActualTransport-- }, wantResult: testFakeTCPCSumRejectMetadata},
		{name: "partial-checksum-start", mutate: func(s *fakeTCPChecksumSKBModel) { s.CSumStart-- }, wantResult: testFakeTCPCSumRejectMetadata},
		{name: "partial-checksum-offset", mutate: func(s *fakeTCPChecksumSKBModel) { s.CSumOffset++ }, wantResult: testFakeTCPCSumRejectMetadata},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := exactPartial
			if test.mutate != nil {
				test.mutate(&input)
			}
			got, result := normalizeFakeTCPChecksumModel(input)
			if result != test.wantResult {
				t.Fatalf("result=%d, want %d", result, test.wantResult)
			}
			if !test.wantReset {
				if got != input {
					t.Fatalf("rejected/CHECKSUM_NONE state mutated: got %+v, want %+v", got, input)
				}
				return
			}
			if got.IPSummed != testChecksumNone || got.CSum != 0 || got.CSumStart != 0 ||
				got.CSumOffset != 0 || got.CSumValid || got.CSumCompleteSW ||
				got.CSumLevel != 0 || got.CSumNotInet {
				t.Fatalf("CHECKSUM_PARTIAL reset state = %+v", got)
			}
		})
	}
}

func TestFakeTCPGSOFailClosedBeforeChecksumMutation(t *testing.T) {
	base := fakeTCPChecksumSKBModel{
		PacketShapeValid:   true,
		IPSummed:           testChecksumPartial,
		TransportHeaderSet: true,
		TransportOffset:    34,
		ActualTransport:    34,
		CSumStart:          34,
		CSumOffset:         6,
		CSum:               0x12345678,
		CSumValid:          true,
	}
	for _, test := range []struct {
		name string
		segs uint32
		size uint32
	}{
		{name: "gso-segments-only", segs: 2},
		{name: "gso-size-only", size: 1420},
		{name: "both-gso-fields", segs: 2, size: 1420},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := base
			input.GSOSegments = test.segs
			input.GSOSize = test.size
			got, result := normalizeFakeTCPChecksumModel(input)
			if result != testFakeTCPCSumRejectGSO {
				t.Fatalf("result=%d, want GSO reject %d", result, testFakeTCPCSumRejectGSO)
			}
			if got != input {
				t.Fatalf("GSO rejection mutated checksum metadata: got %+v, want %+v", got, input)
			}
		})
	}
}

func TestFakeTCPChecksumResultToBPFActionAndStatContract(t *testing.T) {
	tests := []struct {
		result         int
		continuePacket bool
		stat           int
	}{
		{result: testFakeTCPCSumAcceptNone, continuePacket: true, stat: testFakeTCPStatChecksumNone},
		{result: testFakeTCPCSumAcceptPartialReset, continuePacket: true, stat: testFakeTCPStatChecksumPartialReset},
		{result: testFakeTCPCSumRejectPacket, stat: testFakeTCPStatBadPacket},
		{result: testFakeTCPCSumRejectState, stat: testFakeTCPStatChecksumStateReject},
		{result: testFakeTCPCSumRejectMetadata, stat: testFakeTCPStatMetadataError},
		{result: testFakeTCPCSumRejectGSO, stat: testFakeTCPStatGSOReject},
		{result: -99, stat: testFakeTCPStatChecksumError},
	}
	for _, test := range tests {
		continuePacket, stat := fakeTCPChecksumBPFDecisionModel(test.result)
		if continuePacket != test.continuePacket || stat != test.stat {
			t.Fatalf("result %d => continue=%v stat=%d, want %v/%d", test.result, continuePacket, stat, test.continuePacket, test.stat)
		}
	}
}

func fakeTCPChecksumBPFDecisionModel(result int) (bool, int) {
	switch result {
	case testFakeTCPCSumAcceptNone:
		return true, testFakeTCPStatChecksumNone
	case testFakeTCPCSumAcceptPartialReset:
		return true, testFakeTCPStatChecksumPartialReset
	case testFakeTCPCSumRejectGSO:
		return false, testFakeTCPStatGSOReject
	case testFakeTCPCSumRejectPacket:
		return false, testFakeTCPStatBadPacket
	case testFakeTCPCSumRejectState:
		return false, testFakeTCPStatChecksumStateReject
	case testFakeTCPCSumRejectMetadata:
		return false, testFakeTCPStatMetadataError
	default:
		return false, testFakeTCPStatChecksumError
	}
}

func TestFakeTCPOffloadCapabilitiesRemainEvidenceGated(t *testing.T) {
	requiresUnmetKernelOrRealHostEvidence := fakeTCPCapabilityChecksumStateInspection |
		fakeTCPCapabilityChecksumPartialCompletion |
		fakeTCPCapabilityChecksumMetadataReset |
		fakeTCPCapabilityGSOPerSegmentTransform |
		fakeTCPCapabilityMTUEnforcement |
		fakeTCPCapabilityRealNICOffloadAcceptance
	if got := fakeTCPImplementedCapabilities & requiresUnmetKernelOrRealHostEvidence; got != requiresUnmetKernelOrRealHostEvidence {
		t.Fatalf("production offload/MTU capability bits are incomplete: got %#x want %#x", got, requiresUnmetKernelOrRealHostEvidence)
	}
}

func TestFakeTCPChecksumKfuncAndBPFReturnABIStayIdentical(t *testing.T) {
	kernelSource, err := os.ReadFile("../../kernel/faketcp_checksum/wg_mix_faketcp_checksum.c")
	if err != nil {
		t.Fatal(err)
	}
	bpfSource, err := os.ReadFile("../../bpf/wg_mix_faketcp.h")
	if err != nil {
		t.Fatal(err)
	}
	kernel := string(kernelSource)
	bpf := string(bpfSource)
	contracts := []struct {
		name  string
		value string
		stat  string
	}{
		{name: "ACCEPT_NONE", value: "0", stat: "FAKETCP_STAT_CHECKSUM_NONE_ACCEPTED"},
		{name: "ACCEPT_PARTIAL_RESET", value: "1", stat: "FAKETCP_STAT_CHECKSUM_PARTIAL_RESET"},
		{name: "REJECT_PACKET", value: "-1", stat: "FAKETCP_STAT_BAD_PACKET"},
		{name: "REJECT_STATE", value: "-2", stat: "FAKETCP_STAT_CHECKSUM_STATE_REJECT"},
		{name: "REJECT_METADATA", value: "-3", stat: "FAKETCP_STAT_METADATA_ERROR"},
		{name: "REJECT_GSO_TYPE", value: "-4", stat: "FAKETCP_STAT_GSO_REJECT"},
	}
	for _, contract := range contracts {
		if !strings.Contains(kernel, "WG_MIX_FAKETCP_PREPARE_"+contract.name+" = "+contract.value) {
			t.Fatalf("kernel checksum result ABI missing %s=%s", contract.name, contract.value)
		}
		if !strings.Contains(bpf, "FAKETCP_PREPARE_"+contract.name) || !strings.Contains(bpf, contract.stat) {
			t.Fatalf("BPF checksum result/stat mapping missing %s -> %s", contract.name, contract.stat)
		}
	}
	for _, required := range []string{
		"faketcp_mtu_audit_map SEC(\".maps\")",
		"reason * FAKETCP_MTU_BOUNDARY_MAX + boundary",
		"inc_faketcp_stat(FAKETCP_STAT_MTU_REJECT)",
	} {
		if !strings.Contains(bpf, required) {
			t.Fatalf("BPF PMTU audit contract missing %q", required)
		}
	}
	for _, required := range []string{
		"#include <net/dst_metadata.h>",
		"struct net_device *device = READ_ONCE(skb->dev)",
		"device_mtu = READ_ONCE(device->mtu)",
		"if (!skb_valid_dst(skb))",
		"if (READ_ONCE(dst->dev) != device)",
		"route_mtu = dst_mtu(dst)",
	} {
		if !strings.Contains(kernel, required) {
			t.Fatalf("kernel PMTU admission contract missing %q", required)
		}
	}
	resetOrder := []string{
		"skb->csum = 0;",
		"skb->csum_valid = 0;",
		"skb->csum_complete_sw = 0;",
		"skb->csum_level = 0;",
		"skb_reset_csum_not_inet(skb);",
		"skb->ip_summed = CHECKSUM_NONE;",
		"return WG_MIX_FAKETCP_PREPARE_ACCEPT_PARTIAL_RESET;",
	}
	position := -1
	for _, fragment := range resetOrder {
		next := strings.Index(kernel[position+1:], fragment)
		if next < 0 {
			t.Fatalf("kernel PARTIAL reset contract missing %q", fragment)
		}
		position += next + 1
	}
}
