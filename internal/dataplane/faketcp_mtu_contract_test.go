package dataplane

import (
	"os"
	"strings"
	"testing"
)

func TestFakeTCPMTUIntegrationRejectsLegacyStandaloneAdmission(t *testing.T) {
	source, err := os.ReadFile("../../bpf/wg_mix_faketcp.h")
	if err != nil {
		t.Fatal(err)
	}
	bpf := string(source)
	for _, forbidden := range []string{
		"faketcp_mtu_admit",
		"bpf_fib_lookup(",
		"BPF_FIB_LOOKUP_OUTPUT",
	} {
		if strings.Contains(bpf, forbidden) {
			t.Fatalf("legacy standalone MTU admission remains reachable: %q", forbidden)
		}
	}
	for _, required := range []string{
		"faketcp_mtu_allows_growth(struct __sk_buff *skb",
		"bpf_check_mtu(skb, 0, &mtu_len, FAKETCP_HEADER_DELTA, 0)",
		"old_total_len > mtu_len - FAKETCP_HEADER_DELTA",
		"inc_faketcp_stat(FAKETCP_STAT_MTU_REJECT)",
	} {
		if !strings.Contains(bpf, required) {
			t.Fatalf("non-GSO device MTU fail-closed contract is missing %q", required)
		}
	}
	if strings.Count(bpf, "bpf_check_mtu(") != 1 ||
		strings.Count(bpf, "faketcp_mtu_allows_growth(skb, old_total_len)") != 1 {
		t.Fatal("device MTU admission must have one helper call and one encoder call")
	}
	admit := strings.Index(bpf, "faketcp_mtu_allows_growth(skb, old_total_len)")
	mutation := strings.Index(bpf, "bpf_skb_change_tail(skb, skb->len + FAKETCP_HEADER_DELTA")
	if admit < 0 || mutation < 0 || admit >= mutation {
		t.Fatal("device MTU rejection must precede the first packet-size mutation")
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
