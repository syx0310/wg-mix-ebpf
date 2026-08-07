//go:build linux

package dataplane

import (
	"errors"
	"fmt"
	"strings"

	"github.com/syx0310/wg-mix-ebpf/internal/control"
)

type fakeTCPCapability uint64

const (
	fakeTCPCapabilityBaselineIsolation fakeTCPCapability = 1 << iota
	fakeTCPCapabilityManagedIngressParser
	fakeTCPCapabilitySingleWriterState
	fakeTCPCapabilityHalfOpenProtection
	fakeTCPCapabilityXDPOwnership
	fakeTCPCapabilityManagedPolicyPopulation
	fakeTCPCapabilityChecksumStateInspection
	fakeTCPCapabilityChecksumPartialCompletion
	fakeTCPCapabilityChecksumMetadataReset
	fakeTCPCapabilityGSOPerSegmentTransform
	fakeTCPCapabilityMTUEnforcement
	fakeTCPCapabilityEstablishedStoreBackend
	fakeTCPCapabilityControllerBackends
	fakeTCPCapabilityRealNICOffloadAcceptance
)

const fakeTCPRequiredCapabilities = fakeTCPCapabilityBaselineIsolation |
	fakeTCPCapabilityManagedIngressParser |
	fakeTCPCapabilitySingleWriterState |
	fakeTCPCapabilityHalfOpenProtection |
	fakeTCPCapabilityXDPOwnership |
	fakeTCPCapabilityManagedPolicyPopulation |
	fakeTCPCapabilityChecksumStateInspection |
	fakeTCPCapabilityChecksumPartialCompletion |
	fakeTCPCapabilityChecksumMetadataReset |
	fakeTCPCapabilityGSOPerSegmentTransform |
	fakeTCPCapabilityMTUEnforcement |
	fakeTCPCapabilityEstablishedStoreBackend |
	fakeTCPCapabilityControllerBackends |
	fakeTCPCapabilityRealNICOffloadAcceptance

// This constant is intentionally not configurable. A YAML flag or object-path
// override cannot claim kernel readiness. Each bit moves here only with its
// implementation and packet/real-NIC acceptance tests in the same change.
const fakeTCPImplementedCapabilities = fakeTCPCapabilityBaselineIsolation |
	fakeTCPCapabilityManagedIngressParser |
	fakeTCPCapabilitySingleWriterState |
	fakeTCPCapabilityHalfOpenProtection

var fakeTCPRequirements = []struct {
	capability fakeTCPCapability
	name       string
}{
	{fakeTCPCapabilityBaselineIsolation, "baseline/experimental BPF object isolation"},
	{fakeTCPCapabilityManagedIngressParser, "managed-port IPv4/IPv6 fail-closed parser"},
	{fakeTCPCapabilitySingleWriterState, "single-writer established session state"},
	{fakeTCPCapabilityHalfOpenProtection, "bounded and rate-limited half-open state"},
	{fakeTCPCapabilityXDPOwnership, "XDP link ownership/rollback and libxdp chaining"},
	{fakeTCPCapabilityManagedPolicyPopulation, "atomic managed-interface/port policy population"},
	{fakeTCPCapabilityChecksumStateInspection, "ip_summed/CHECKSUM_PARTIAL identification"},
	{fakeTCPCapabilityChecksumPartialCompletion, "CHECKSUM_PARTIAL materialize/complete"},
	{fakeTCPCapabilityChecksumMetadataReset, "checksum offset and skb metadata reset"},
	{fakeTCPCapabilityGSOPerSegmentTransform, "per-segment GSO transform"},
	{fakeTCPCapabilityMTUEnforcement, "WireGuard MTU-minus-12 enforcement"},
	{fakeTCPCapabilityEstablishedStoreBackend, "established-state compare-delete backend"},
	{fakeTCPCapabilityControllerBackends, "daemon ring reader/control sender/once-only reinjector"},
	{fakeTCPCapabilityRealNICOffloadAcceptance, "real-NIC GSO/GRO/checksum-offload acceptance"},
}

// preflightFakeTCPKernelRequirements runs before any pin, map, TC, XDP or
// network mutation. The established packet programs are present for verifier
// and packet-level development, but production activation remains fail-closed
// until ownership, complete offload handling, MTU and userspace-I/O
// requirements are implemented and accepted on the kernel-7.0 real-NIC
// matrix.
func preflightFakeTCPKernelRequirements(state *control.State) error {
	references := fakeTCPStateReferences(state)
	if len(references) == 0 {
		return nil
	}
	return fmt.Errorf(
		"%w for configuration references %s; missing capabilities: %s; activation is refused before mutation",
		ErrFakeTCPKernelGate,
		strings.Join(references, ","),
		strings.Join(missingFakeTCPCapabilities(), "; "),
	)
}

func missingFakeTCPCapabilities() []string {
	missing := make([]string, 0, len(fakeTCPRequirements))
	for _, requirement := range fakeTCPRequirements {
		if fakeTCPImplementedCapabilities&requirement.capability == 0 {
			missing = append(missing, requirement.name)
		}
	}
	return missing
}

func fakeTCPActivationReady() bool {
	return fakeTCPImplementedCapabilities&fakeTCPRequiredCapabilities == fakeTCPRequiredCapabilities
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
