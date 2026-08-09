package dataplane

import (
	"os"
	"strings"
	"testing"

	"github.com/syx0310/wg-mix-ebpf/internal/faketcp"
)

func TestFakeTCPMTUAdmissionIsSingleFailClosedProductionBoundary(t *testing.T) {
	mtuBytes, err := os.ReadFile("../../bpf/wg_mix_faketcp_mtu.h")
	if err != nil {
		t.Fatal(err)
	}
	mainBytes, err := os.ReadFile("../../bpf/wg_mix_faketcp.h")
	if err != nil {
		t.Fatal(err)
	}
	manifestBytes, err := os.ReadFile("experimental_manifest_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	mtu := string(mtuBytes)
	main := string(mainBytes)
	manifest := string(manifestBytes)

	for _, want := range []string{
		"FAKETCP_MTU_INVALID_INPUT",
		"FAKETCP_MTU_ARITHMETIC_OVERFLOW",
		"FAKETCP_MTU_FRAGMENTATION_REJECTED",
		"FAKETCP_MTU_UNKNOWN",
		"FAKETCP_MTU_EXCEEDED",
		"FAKETCP_MTU_BOUNDARY_INPUT",
		"FAKETCP_MTU_BOUNDARY_DEVICE",
		"FAKETCP_MTU_BOUNDARY_ROUTE",
		"reason * FAKETCP_MTU_BOUNDARY_MAX + boundary",
		"faketcp_mtu_audit_map SEC(\".maps\")",
		"static __always_inline int\nfaketcp_mtu_admit(",
	} {
		if !strings.Contains(mtu, want) {
			t.Fatalf("MTU admission contract missing %q", want)
		}
	}
	if got := strings.Count(mtu, "enum faketcp_mtu_reason"); got != 1 {
		t.Fatalf("MTU reason taxonomies=%d, want one", got)
	}
	if got := strings.Count(mtu, "faketcp_mtu_admit(struct __sk_buff"); got != 1 {
		t.Fatalf("MTU admission implementations=%d, want one", got)
	}
	if strings.Contains(main, "faketcp_mtu_allows_growth") {
		t.Fatal("legacy device-only MTU fallback remains reachable")
	}

	device := strings.Index(mtu, "bpf_check_mtu(skb, request->ifindex")
	route := strings.Index(mtu, "bpf_fib_lookup(skb, &fib")
	if device < 0 || route < 0 || device >= route {
		t.Fatal("device and route admission are absent or out of order")
	}
	for _, want := range []string{
		"device_mtu == 0",
		"BPF_FIB_LKUP_RET_FRAG_NEEDED",
		"fib.tot_len = (__u16)planned_l3_len",
		"BPF_FIB_LOOKUP_OUTPUT | BPF_FIB_LOOKUP_SKIP_NEIGH",
		"fib_flags |= BPF_FIB_LOOKUP_MARK",
		"FAKETCP_FIB_AF_INET : FAKETCP_FIB_AF_INET6",
		"request->input_segment_l3_len != request->input_l3_len",
		"FAKETCP_MTU_F_GSO",
	} {
		if !strings.Contains(mtu, want) {
			t.Fatalf("fail-closed MTU boundary missing %q", want)
		}
	}

	request := strings.Index(main, "struct faketcp_mtu_request mtu_request")
	admit := strings.Index(main, "faketcp_mtu_admit(skb, &mtu_request)")
	mutation := strings.Index(main, "bpf_skb_change_tail(skb, skb->len + FAKETCP_HEADER_DELTA")
	if request < 0 || admit < 0 || mutation < 0 || request >= admit || admit >= mutation {
		t.Fatal("MTU request/admission must precede the first packet-size mutation")
	}
	if !strings.Contains(manifest, `{name: "faketcp_mtu_audit_map", mapType: ebpf.PerCPUArray, keySize: 4, valueSize: 8, maxEntries: faketcp.MTUAuditKeyCount}`) || faketcp.MTUAuditKeyCount != 15 {
		t.Fatal("MTU audit map is absent from the exact experimental manifest")
	}
	if fakeTCPImplementedCapabilities&fakeTCPCapabilityMTUEnforcement != 0 {
		t.Fatal("local/model MTU tests must not open the real-host evidence gate")
	}
}

func TestFakeTCPMTUAuditEncodingMatchesCEnumOrder(t *testing.T) {
	mtuBytes, err := os.ReadFile("../../bpf/wg_mix_faketcp_mtu.h")
	if err != nil {
		t.Fatal(err)
	}
	mainBytes, err := os.ReadFile("../../bpf/wg_mix_faketcp.h")
	if err != nil {
		t.Fatal(err)
	}
	mtu := string(mtuBytes)

	reasons := []struct {
		code  faketcp.MTUErrorCode
		token string
	}{
		{faketcp.MTUErrorInvalidInput, "FAKETCP_MTU_INVALID_INPUT"},
		{faketcp.MTUErrorArithmeticOverflow, "FAKETCP_MTU_ARITHMETIC_OVERFLOW"},
		{faketcp.MTUErrorFragmentationRejected, "FAKETCP_MTU_FRAGMENTATION_REJECTED"},
		{faketcp.MTUErrorUnknown, "FAKETCP_MTU_UNKNOWN"},
		{faketcp.MTUErrorExceeded, "FAKETCP_MTU_EXCEEDED"},
	}
	boundaries := []struct {
		boundary faketcp.MTUBoundary
		token    string
	}{
		{faketcp.MTUBoundaryInput, "FAKETCP_MTU_BOUNDARY_INPUT"},
		{faketcp.MTUBoundaryDevice, "FAKETCP_MTU_BOUNDARY_DEVICE"},
		{faketcp.MTUBoundaryRoute, "FAKETCP_MTU_BOUNDARY_ROUTE"},
	}
	previous := -1
	for _, reason := range reasons {
		index := strings.Index(mtu, reason.token)
		if index <= previous {
			t.Fatalf("C MTU reason %s is absent or out of stable order", reason.token)
		}
		previous = index
	}
	previous = -1
	for _, boundary := range boundaries {
		index := strings.Index(mtu, boundary.token)
		if index <= previous {
			t.Fatalf("C MTU boundary %s is absent or out of stable order", boundary.token)
		}
		previous = index
	}
	for reasonIndex, reason := range reasons {
		for boundaryIndex, boundary := range boundaries {
			got, err := faketcp.EncodeMTUAuditKey(reason.code, boundary.boundary)
			want := uint32(reasonIndex*len(boundaries) + boundaryIndex)
			if err != nil || got != want {
				t.Fatalf("Go audit key %s/%s=%d, %v; C enum layout requires %d", reason.code, boundary.boundary, got, err, want)
			}
		}
	}
	if faketcp.FakeTCPHeaderDelta != 12 || !strings.Contains(string(mainBytes), "#define FAKETCP_HEADER_DELTA 12") {
		t.Fatal("Go/C FakeTCP header delta contract drifted from 12 bytes")
	}
}
