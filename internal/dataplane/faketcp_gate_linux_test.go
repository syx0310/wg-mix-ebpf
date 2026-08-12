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

func TestFakeTCPProductionCapabilitiesPermitActivation(t *testing.T) {
	state := &control.State{
		WireGuards: []control.WireGuardState{{Name: "wg0", TransportMode: "faketcp"}},
	}
	err := preflightFakeTCPKernelRequirements(state)
	if err != nil {
		t.Fatalf("production FakeTCP capability gate rejected activation: %v", err)
	}
	// The baseline-only loader still stops before it validates an intentionally
	// invalid pin path; only the production coordinator may install FakeTCP.
	err = (LinuxLoader{PinPath: "relative-path-must-not-be-touched"}).Apply(context.Background(), state)
	if !errors.Is(err, ErrFakeTCPProductionCoordinatorRequired) {
		t.Fatalf("Apply did not fail at the coordinator pre-mutation gate: %v", err)
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

func TestFakeTCPProductionCapabilitiesCoverRuleOnlyReferences(t *testing.T) {
	for _, state := range []*control.State{
		{EgressRules: []control.EgressRule{{TransportMode: "faketcp", WGID: 7}}},
		{IngressListeners: []control.IngressListener{{TransportMode: "faketcp", WGID: 8}}},
	} {
		if err := preflightFakeTCPKernelRequirements(state); err != nil {
			t.Fatalf("rule-only FakeTCP production reference rejected: %v", err)
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
