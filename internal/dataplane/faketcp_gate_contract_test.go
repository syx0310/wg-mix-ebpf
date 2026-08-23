package dataplane

import (
	"errors"
	"testing"

	"github.com/syx0310/wg-mix-ebpf/internal/control"
)

func TestFakeTCPResidentRuntimeGate(t *testing.T) {
	fakeTCPState := &control.State{
		WireGuards: []control.WireGuardState{{Name: "wg0", TransportMode: "faketcp"}},
	}
	if err := ValidateFakeTCPResidentRuntime(fakeTCPState, false); !errors.Is(
		err,
		ErrFakeTCPResidentRuntimeRequired,
	) {
		t.Fatalf("one-shot FakeTCP runtime error = %v", err)
	}
	if err := ValidateFakeTCPResidentRuntime(fakeTCPState, true); err != nil {
		t.Fatalf("resident FakeTCP runtime rejected: %v", err)
	}
	if err := ValidateFakeTCPResidentRuntime(&control.State{}, false); err != nil {
		t.Fatalf("baseline one-shot runtime rejected: %v", err)
	}
}

func TestFakeTCPActivationRequiresAndImplementsEveryProductionCapability(t *testing.T) {
	if !fakeTCPActivationReady() {
		t.Fatalf("production FakeTCP capability set is incomplete: %v", missingFakeTCPCapabilities())
	}
	if got := missingFakeTCPCapabilities(); len(got) != 0 {
		t.Fatalf("production FakeTCP reports missing capabilities: %v", got)
	}
	state := &control.State{
		WireGuards: []control.WireGuardState{{Name: "wg0", TransportMode: "faketcp"}},
	}
	if err := ValidateFakeTCPActivation(state); err != nil {
		t.Fatalf("production FakeTCP activation rejected: %v", err)
	}
}

func TestFakeTCPImplementedCapabilityMaskRemainsEvidenceBound(t *testing.T) {
	if fakeTCPCapabilityHalfOpenProtection != 0x8 ||
		fakeTCPCapabilitySingleUsePacketAdmissionProof != 0x10 {
		t.Fatalf("admission capability bits drifted: half-open=%#x packet-proof=%#x",
			fakeTCPCapabilityHalfOpenProtection,
			fakeTCPCapabilitySingleUsePacketAdmissionProof)
	}
	const want = fakeTCPRequiredCapabilities
	if got := fakeTCPImplementedCapabilities; got != want {
		t.Fatalf("implemented capability mask=%#x, want %#x", got, want)
	}
}
