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
	tcSource, err := os.ReadFile("../../bpf/wg_mix_tc.c")
	if err != nil {
		t.Fatal(err)
	}
	tc := string(tcSource)
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
	if strings.Count(bpf+tc, "bpf_check_mtu(") != 1 ||
		strings.Count(bpf+tc, "faketcp_mtu_allows_growth(skb, faketcp_l3.l3_len)") != 1 {
		t.Fatal("device MTU admission must have one helper and one pre-checkpoint call")
	}
	egress := sourceSection(t, tc, "int wg_mix_egress(struct __sk_buff *skb)", "SEC(\"classifier/ingress\")")
	l3Gate := strings.Index(egress, "faketcp_parse_tc_l3(skb, &info, &faketcp_l3)")
	fixedGate := strings.Index(egress, "faketcp_managed_transform_status(&faketcp_l3, IPPROTO_UDP)")
	admit := strings.Index(egress, "faketcp_mtu_allows_growth(skb, faketcp_l3.l3_len)")
	checkpoint := strings.Index(egress, "faketcp_egress_admission_checkpoint(")
	if l3Gate < 0 || fixedGate < 0 || admit < 0 || checkpoint < 0 ||
		!(l3Gate < fixedGate && fixedGate < admit && admit < checkpoint) {
		t.Fatal("device MTU rejection must run once after fixed-IPv4 parsing and before proof formation")
	}
	encoder := sourceSection(t, bpf, "static __always_inline int faketcp_encode_established(", "static __always_inline int faketcp_continue_egress")
	if strings.Contains(encoder, "faketcp_mtu_allows_growth(") {
		t.Fatal("encoder retained the late MTU check after proof formation")
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
