package dataplane

import (
	"strings"
	"testing"
)

func TestFakeTCPActivationCannotBeEnabledWithoutEveryAcceptanceCapability(t *testing.T) {
	if fakeTCPActivationReady() {
		t.Fatal("experimental FakeTCP object became attachable without the missing acceptance capabilities")
	}
	missing := strings.Join(missingFakeTCPCapabilities(), "\n")
	const halfOpenRequirement = "bounded and rate-limited userspace half-open quota with zero-credit restart"
	if strings.Contains(missing, halfOpenRequirement) ||
		fakeTCPImplementedCapabilities&fakeTCPCapabilityHalfOpenProtection == 0 {
		t.Fatalf("implemented zero-credit half-open protection is still reported missing: %q", missing)
	}
	if strings.Contains(missing, "BPF control-event admission/coalescing") ||
		fakeTCPImplementedCapabilities&fakeTCPCapabilityBPFControlAdmission == 0 {
		t.Fatalf("implemented BPF control-event admission is still reported missing: %q", missing)
	}

	const packetProofRequirement = "single-use packet admission proof with stable-lifetime binding"
	if fakeTCPImplementedCapabilities&fakeTCPCapabilitySingleUsePacketAdmissionProof != 0 ||
		!strings.Contains(missing, packetProofRequirement) {
		t.Fatalf("closed packet-proof capability is not reported missing: %q", missing)
	}
	for _, capability := range []string{
		"XDP link ownership/rollback and libxdp chaining",
		"atomic managed-interface/port policy population",
		"ip_summed/CHECKSUM_PARTIAL identification",
		"CHECKSUM_PARTIAL materialize/complete",
		"checksum offset and skb metadata reset",
		"per-segment GSO transform",
		"established-state compare-delete backend",
		"real-NIC GSO/GRO/checksum-offload acceptance",
	} {
		if !strings.Contains(missing, capability) {
			t.Fatalf("hard gate no longer requires %q; missing=%q", capability, missing)
		}
	}
	if strings.Contains(missing, "persistent/reload-safe SYN admission checkpoint") {
		t.Fatalf("packet-local proof still claims durable SYN recovery: %q", missing)
	}
}

func TestFakeTCPImplementedCapabilityMaskRemainsEvidenceBound(t *testing.T) {
	if fakeTCPCapabilityHalfOpenProtection != 0x8 ||
		fakeTCPCapabilitySingleUsePacketAdmissionProof != 0x10 {
		t.Fatalf("admission capability bits drifted: half-open=%#x packet-proof=%#x",
			fakeTCPCapabilityHalfOpenProtection,
			fakeTCPCapabilitySingleUsePacketAdmissionProof)
	}
	const want fakeTCPCapability = 0x2d
	if got := fakeTCPImplementedCapabilities; got != want {
		t.Fatalf("implemented capability mask=%#x, want %#x", got, want)
	}
}
