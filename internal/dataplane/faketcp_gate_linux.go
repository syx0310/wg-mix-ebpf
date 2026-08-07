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
// until both ownership and checksum-offset requirements are implemented and
// accepted on the kernel-7.0 real-NIC matrix.
func preflightFakeTCPKernelRequirements(state *control.State) error {
	var names []string
	for _, wg := range state.WireGuards {
		if wg.TransportMode == "faketcp" {
			names = append(names, wg.Name)
		}
	}
	if len(names) == 0 {
		return nil
	}
	return fmt.Errorf(
		"%w for WireGuard interfaces %s: XDP link ownership/rollback and the reviewed CHECKSUM_PARTIAL csum_offset kfunc are not enabled; activation is refused before mutation",
		ErrFakeTCPKernelGate,
		strings.Join(names, ","),
	)
}

func isFakeTCPKernelGate(err error) bool {
	return errors.Is(err, ErrFakeTCPKernelGate)
}
