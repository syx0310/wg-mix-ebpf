package dataplane

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestBPFProfileMapAccessesUseOnlyConstantOffsets(t *testing.T) {
	tcBytes, err := os.ReadFile("../../bpf/wg_mix_tc.c")
	if err != nil {
		t.Fatal(err)
	}
	fakeBytes, err := os.ReadFile("../../bpf/wg_mix_faketcp.h")
	if err != nil {
		t.Fatal(err)
	}
	source := string(tcBytes) + "\n" + string(fakeBytes)
	access := regexp.MustCompile(`profile->(?:standard_to_mixed|mixed_to_standard)\[([^]]+)\]`)
	matches := access.FindAllStringSubmatch(source, -1)
	if len(matches) == 0 {
		t.Fatal("profile type maps have no BPF access sites")
	}
	for _, match := range matches {
		switch match[1] {
		case "0", "1", "2", "3":
		default:
			t.Fatalf("profile map regained verifier-unsafe dynamic array access %q", match[0])
		}
	}
	for _, required := range []string{
		"profile_mixed_from_kind(",
		"profile_decode_mixed(",
		"faketcp_gso_mixed_from_kind(",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("constant-offset profile/GSO dispatch is missing %q", required)
		}
	}
}

func TestFakeTCPXDPPacketPointersDoNotCrossHelperBoundaries(t *testing.T) {
	fakeBytes, err := os.ReadFile("../../bpf/wg_mix_faketcp.h")
	if err != nil {
		t.Fatal(err)
	}
	fake := string(fakeBytes)
	body := sourceSection(t, fake,
		"faketcp_xdp_ingress_body(struct xdp_md *xdp, __u64 generation)",
		"SEC(\"xdp\")")

	firstBounds := strings.Index(body, "if ((void *)(wire_ports + 1) > data_end)")
	portSnapshot := strings.Index(body, "destination_port = bpf_ntohs(wire_ports->dest)")
	managedLookup := strings.Index(body, "managed_listener = faketcp_xdp_managed_port(")
	packetReload := -1
	if managedLookup >= 0 {
		if relative := strings.Index(body[managedLookup:], "data = (void *)(long)xdp->data"); relative >= 0 {
			packetReload = managedLookup + relative
		}
	}
	tcpSnapshot := strings.Index(body, "*old_tcp = *tcp")
	ipSnapshot := strings.Index(body, "*new_ip = *iph")
	policyLookup := strings.Index(body, "policy_listener = lookup_ingress_listener(")
	checkpoint := strings.Index(body, "admission_decision = faketcp_xdp_admission_checkpoint(")
	if firstBounds < 0 || portSnapshot < 0 || managedLookup < 0 || packetReload < 0 ||
		tcpSnapshot < 0 || ipSnapshot < 0 || policyLookup < 0 || checkpoint < 0 ||
		!(firstBounds < portSnapshot && portSnapshot < managedLookup &&
			managedLookup < packetReload && packetReload < tcpSnapshot && tcpSnapshot < policyLookup &&
			ipSnapshot < policyLookup && policyLookup < checkpoint) {
		t.Fatal("XDP packet bounds, scalar/header snapshots and helper boundaries are out of order")
	}

	afterPolicy := body[policyLookup:]
	for _, forbidden := range []string{
		"bpf_ntohs(tcp->dest)",
		"bpf_ntohs(tcp->source)",
		"bpf_ntohs(iph->tot_len)",
		"*old_tcp = *tcp",
		"*new_ip = *iph",
		"iph = data + l3->l3_off",
	} {
		if strings.Contains(afterPolicy, forbidden) {
			t.Fatalf("XDP direct packet access %q crossed the policy helper boundary", forbidden)
		}
	}
	for _, required := range []string{
		"xdp, l3->l3_off, new_ip, old_tcp, l3, managed_listener",
		"faketcp_close_checksums_valid(new_ip, old_tcp)",
		"bpf_ntohs(old_tcp->window)",
	} {
		if !strings.Contains(afterPolicy, required) {
			t.Fatalf("XDP map-backed header use is missing %q", required)
		}
	}

	checkpointBody := sourceSection(t, fake,
		"static __always_inline int faketcp_xdp_admission_checkpoint(",
		"static __always_inline int faketcp_xdp_l3_action(")
	if strings.Contains(checkpointBody, "void *data") ||
		strings.Contains(checkpointBody, "void *data_end") ||
		strings.Contains(checkpointBody, "data + ip_off") {
		t.Fatal("XDP checkpoint regained a live packet pointer or packet-derived bounds proof")
	}
	if !strings.Contains(checkpointBody, "admission->wire_total_len != l3->l3_len") {
		t.Fatal("XDP checkpoint does not bind its header snapshot to the parsed L3 length")
	}
}
