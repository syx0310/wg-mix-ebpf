//go:build linux

package dataplane

import (
	"errors"
	"fmt"
	"strings"

	"github.com/syx0310/wg-mix-ebpf/internal/control"
)

// preflightFakeTCPKernelRequirements runs before any pin, map, TC, XDP or
// network mutation. The established packet programs are present for verifier
// and packet-level development, but production activation remains fail-closed
// until ownership, checksum-offset, MTU and userspace-I/O requirements are
// implemented and accepted on the kernel-7.0 real-NIC matrix.
func preflightFakeTCPKernelRequirements(state *control.State) error {
	references := fakeTCPStateReferences(state)
	if len(references) == 0 {
		return nil
	}
	return fmt.Errorf(
		"%w for configuration references %s: XDP link ownership/rollback, the reviewed CHECKSUM_PARTIAL csum_offset kfunc, MTU-minus-12 enforcement, and daemon-owned ring reader/control sender/once-only reinjector backends are not enabled; activation is refused before mutation",
		ErrFakeTCPKernelGate,
		strings.Join(references, ","),
	)
}

func stateUsesFakeTCP(state *control.State) bool {
	return len(fakeTCPStateReferences(state)) != 0
}

func fakeTCPStateReferences(state *control.State) []string {
	if state == nil {
		return nil
	}
	var references []string
	for _, wg := range state.WireGuards {
		if wg.TransportMode == "faketcp" {
			references = append(references, "wireguard:"+wg.Name)
		}
	}
	for index, rule := range state.EgressRules {
		if rule.TransportMode == "faketcp" {
			references = append(references, fmt.Sprintf("egress[%d]:wg_id=%d", index, rule.WGID))
		}
	}
	for index, listener := range state.IngressListeners {
		if listener.TransportMode == "faketcp" {
			references = append(references, fmt.Sprintf("ingress[%d]:wg_id=%d", index, listener.WGID))
		}
	}
	return references
}

func isFakeTCPKernelGate(err error) bool {
	return errors.Is(err, ErrFakeTCPKernelGate)
}
