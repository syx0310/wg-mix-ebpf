//go:build linux

package dataplane

import (
	"context"
	"errors"
	"os"
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
	for _, want := range []string{
		"XDP link ownership/rollback and libxdp chaining",
		"ip_summed/CHECKSUM_PARTIAL identification",
		"CHECKSUM_PARTIAL materialize/complete",
		"checksum offset and skb metadata reset",
		"per-segment GSO transform",
		"MTU-minus-12",
		"once-only reinjector",
		"real-NIC GSO/GRO/checksum-offload acceptance",
		"before mutation",
	} {
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

func TestFakeTCPActivationCannotBeEnabledWithoutEveryAcceptanceCapability(t *testing.T) {
	if fakeTCPActivationReady() {
		t.Fatal("experimental FakeTCP object became attachable without the missing acceptance capabilities")
	}
	missing := strings.Join(missingFakeTCPCapabilities(), "\n")
	if strings.Contains(missing, "BPF control-event admission/coalescing") ||
		fakeTCPImplementedCapabilities&fakeTCPCapabilityBPFControlAdmission == 0 {
		t.Fatalf("implemented BPF control-event admission is still reported missing: %q", missing)
	}
	for _, capability := range []string{
		"XDP link ownership/rollback and libxdp chaining",
		"atomic managed-interface/port policy population",
		"persistent/reload-safe SYN admission checkpoint backend",
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
}

func TestFakeTCPImplementedCapabilityMaskRemainsEvidenceBound(t *testing.T) {
	const want fakeTCPCapability = 0x2d
	if got := fakeTCPImplementedCapabilities; got != want {
		t.Fatalf("implemented capability mask=%#x, want %#x", got, want)
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

func TestFakeTCPPrototypeIsAbsentFromBaselineCollection(t *testing.T) {
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

	spec := canonicalObjectManifestCollectionSpec()
	if err := validateBaselineCollectionSpec(spec); err != nil {
		t.Fatal(err)
	}
	if err := validateAndSetPinnedMaps(spec); err != nil {
		t.Fatal(err)
	}
	for name := range spec.Maps {
		if isFakeTCPObjectSymbol(name) {
			t.Fatalf("experimental map %q is present in baseline spec", name)
		}
	}
}

func TestFakeTCPBPFSourceRequiresExplicitExperimentalBuild(t *testing.T) {
	source, err := os.ReadFile("../../bpf/wg_mix_tc.c")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	guardedInclude := "#ifdef WG_MIX_EXPERIMENTAL_FAKETCP\n#include \"wg_mix_faketcp.h\"\n#endif"
	if !strings.Contains(text, guardedInclude) {
		t.Fatal("FakeTCP BPF include is not behind the explicit experimental build guard")
	}
}
