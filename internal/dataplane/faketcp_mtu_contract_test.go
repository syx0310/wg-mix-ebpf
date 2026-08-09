package dataplane

import (
	"os"
	"strings"
	"testing"

	"github.com/syx0310/wg-mix-ebpf/internal/faketcp"
)

func TestFakeTCPMTUIntegrationRejectsLegacyStandaloneAdmission(t *testing.T) {
	source, err := os.ReadFile("../../bpf/wg_mix_faketcp.h")
	if err != nil {
		t.Fatal(err)
	}
	bpf := string(source)
	for _, forbidden := range []string{
		"faketcp_mtu_allows_growth",
		"faketcp_mtu_admit",
		"bpf_check_mtu(",
		"bpf_fib_lookup(",
		"BPF_FIB_LOOKUP_OUTPUT",
	} {
		if strings.Contains(bpf, forbidden) {
			t.Fatalf("legacy standalone MTU admission remains reachable: %q", forbidden)
		}
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
	if strings.Contains(string(production), "func AdmitMTU(") {
		t.Fatal("the reference admission model became reachable production code")
	}
	if !strings.Contains(string(oracle), "func AdmitMTU(") ||
		!strings.Contains(string(oracle), "unified skb prepare kfunc") {
		t.Fatal("the test-only oracle is absent or no longer names its production integration owner")
	}
	if faketcp.MTUAuditKeyCount != 15 {
		t.Fatalf("MTU reason-by-boundary audit cardinality=%d, want 15", faketcp.MTUAuditKeyCount)
	}
}
