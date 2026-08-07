//go:build linux

package dataplane

import (
	"context"
	"errors"
	"strings"
	"testing"

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
	for _, want := range []string{"XDP link ownership/rollback", "CHECKSUM_PARTIAL", "before mutation"} {
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
