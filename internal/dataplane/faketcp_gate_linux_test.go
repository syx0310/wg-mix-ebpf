//go:build linux

package dataplane

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
	"github.com/syx0310/wg-mix-ebpf/internal/control"
)

func TestFakeTCPKernelGateRejectsBeforeActivation(t *testing.T) {
	state := &control.State{
		WireGuards: []control.WireGuardState{{Name: "wg0", TransportMode: "faketcp"}},
	}
	err := preflightFakeTCPKernelRequirements(state)
	if !errors.Is(err, ErrFakeTCPKernelGate) {
		t.Fatalf("expected FakeTCP kernel gate, got %v", err)
	}
	for _, want := range []string{"XDP link ownership/rollback", "CHECKSUM_PARTIAL", "MTU-minus-12", "once-only reinjector", "before mutation"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("gate error missing %q: %v", want, err)
		}
	}
	// Apply must return the same capability error before it even validates an
	// intentionally invalid pin path, proving no pin/TC/XDP mutation starts.
	err = (LinuxLoader{PinPath: "relative-path-must-not-be-touched"}).Apply(context.Background(), state)
	if !errors.Is(err, ErrFakeTCPKernelGate) {
		t.Fatalf("Apply did not fail at the pre-mutation gate: %v", err)
	}
}

func TestFakeTCPKernelGateDoesNotBlockExistingTransports(t *testing.T) {
	err := preflightFakeTCPKernelRequirements(&control.State{
		WireGuards: []control.WireGuardState{{Name: "wg0", TransportMode: "udp"}},
	})
	if err != nil || isFakeTCPKernelGate(err) {
		t.Fatalf("existing transport blocked: %v", err)
	}
}

func TestFakeTCPKernelGateCannotBeBypassedByRuleOnlyState(t *testing.T) {
	for _, state := range []*control.State{
		{EgressRules: []control.EgressRule{{TransportMode: "faketcp", WGID: 7}}},
		{IngressListeners: []control.IngressListener{{TransportMode: "faketcp", WGID: 8}}},
	} {
		if err := preflightFakeTCPKernelRequirements(state); !errors.Is(err, ErrFakeTCPKernelGate) {
			t.Fatalf("rule-only FakeTCP state bypassed gate: %v", err)
		}
	}
}

func TestFakeTCPPrototypePreservesCanonicalOwnerAndInactiveMemory(t *testing.T) {
	if abi.Version != 10 {
		t.Fatalf("ABI version = %d, want the existing compatible version 10", abi.Version)
	}
	descriptors := pinnedMapDescriptors()
	if len(descriptors) != 12 {
		t.Fatalf("canonical pinned map count = %d, want existing 12-map owner set", len(descriptors))
	}
	for _, descriptor := range descriptors {
		if strings.HasPrefix(descriptor.name, "faketcp_") {
			t.Fatalf("experimental map %q entered canonical owner set", descriptor.name)
		}
		if descriptor.name == "stats_map" && descriptor.maxEntries != 36 {
			t.Fatalf("canonical stats map entries = %d, want ABI-v10 size 36", descriptor.maxEntries)
		}
	}

	spec := canonicalPinnedMapCollectionSpec()
	if err := validateAndSetPinnedMaps(spec); err != nil {
		t.Fatal(err)
	}
	if err := configureFakeTCPMapCapacity(spec, false); err != nil {
		t.Fatal(err)
	}
	if got := spec.Maps["faketcp_session_map"].MaxEntries; got != 1 {
		t.Fatalf("inactive FakeTCP LRU entries = %d, want 1", got)
	}
	if got := spec.Maps["faketcp_events"].MaxEntries; got != inactiveFakeTCPRingCapacity() {
		t.Fatalf("inactive FakeTCP ringbuf bytes = %d, want one page", got)
	}
	if inactiveFakeTCPRingCapacity() < abi.FakeTCPPacketEventSize+8 {
		t.Fatal("inactive ringbuf cannot hold one maximum compact event")
	}
	for _, descriptor := range fakeTCPUnpinnedMapDescriptors() {
		if got := spec.Maps[descriptor.name].Pinning; got != 0 {
			t.Fatalf("experimental map %q pinning = %d, want unpinned", descriptor.name, got)
		}
	}
}
