package dataplane

import (
	"os"
	"strings"
	"testing"
)

func TestFakeTCPMTUIntegrationUsesUnifiedPrepareOnly(t *testing.T) {
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
	for _, forbidden := range []string{
		"faketcp_mtu_admit",
		"faketcp_mtu_allows_growth",
		"bpf_check_mtu(",
		"bpf_fib_lookup(",
		"BPF_FIB_LOOKUP_OUTPUT",
	} {
		if strings.Contains(bpf, forbidden) {
			t.Fatalf("legacy standalone MTU admission remains reachable: %q", forbidden)
		}
	}
	for _, required := range []string{
		"wg_mix_faketcp_skb_prepare_udp(",
		"faketcp_mtu_audit_map SEC(\".maps\")",
		"inc_faketcp_stat(FAKETCP_STAT_MTU_REJECT)",
	} {
		if !strings.Contains(bpf, required) {
			t.Fatalf("unified BPF MTU contract is missing %q", required)
		}
	}
	for _, required := range []string{
		"static int wg_mix_faketcp_admit_pmtu(struct sk_buff *skb",
		"struct net_device *device = READ_ONCE(skb->dev)",
		"if (!skb_valid_dst(skb))",
		"if (READ_ONCE(dst->dev) != device)",
		"route_mtu = dst_mtu(dst)",
	} {
		if !strings.Contains(kernel, required) {
			t.Fatalf("unified kernel MTU contract is missing %q", required)
		}
	}
	if strings.Count(bpf, "wg_mix_faketcp_skb_prepare_udp(") != 2 {
		t.Fatal("unified prepare must have one declaration and one BPF call")
	}
	if fakeTCPImplementedCapabilities&fakeTCPCapabilityMTUEnforcement != 0 {
		t.Fatal("a model or static contract must not claim live MTU enforcement")
	}
}

func TestFakeTCPMTUOracleIsTestOnlyAndUsesStableAuditSchema(t *testing.T) {
	production, err := os.ReadFile("../faketcp/mtu.go")
	if err != nil {
		t.Fatal(err)
	}
	oracle, err := os.ReadFile("../faketcp/mtu_model_test.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, testOnly := range []string{
		"func AdmitMTU(",
		"type MTUErrorCode",
		"type MTUBoundary",
		"MTUAuditKeyCount",
		"func EncodeMTUAuditKey(",
		"func DecodeMTUAuditKey(",
	} {
		if strings.Contains(string(production), testOnly) {
			t.Fatalf("test-only MTU oracle schema became production API: %q", testOnly)
		}
	}
	for _, required := range []string{
		"func AdmitMTU(",
		"type MTUErrorCode",
		"type MTUBoundary",
		"mtuAuditReasonCount   uint32 = 5",
		"mtuAuditBoundaryCount uint32 = 3",
		"MTUAuditKeyCount",
		"func EncodeMTUAuditKey(",
		"func DecodeMTUAuditKey(",
		"unified skb prepare kfunc",
	} {
		if !strings.Contains(string(oracle), required) {
			t.Fatalf("test-only MTU oracle/schema is missing %q", required)
		}
	}
	if !strings.Contains(string(production), "FakeTCPHeaderDelta uint64 = 12") {
		t.Fatal("the production key-length contract lost its exact 12-byte header delta")
	}
}
