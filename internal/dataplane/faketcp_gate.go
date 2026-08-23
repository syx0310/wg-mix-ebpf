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
	// This capability is packet-local: the proof is single-use and binds the
	// packet to one established session lifetime. It promises no durable SYN
	// state and no reload recovery.
	fakeTCPCapabilitySingleUsePacketAdmissionProof
	fakeTCPCapabilityBPFControlAdmission
	fakeTCPCapabilityValidatedCloseControl
	fakeTCPCapabilityL3Parser
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
	fakeTCPCapabilitySingleUsePacketAdmissionProof |
	fakeTCPCapabilityBPFControlAdmission |
	fakeTCPCapabilityValidatedCloseControl |
	fakeTCPCapabilityL3Parser |
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
const fakeTCPImplementedCapabilities = fakeTCPRequiredCapabilities

var fakeTCPRequirements = []struct {
	capability fakeTCPCapability
	name       string
}{
	{fakeTCPCapabilityBaselineIsolation, "baseline/FakeTCP BPF object isolation"},
	{fakeTCPCapabilityManagedIngressParser, "managed-port IPv4 fail-closed parser"},
	{fakeTCPCapabilitySingleWriterState, "single-writer established session state"},
	{fakeTCPCapabilityHalfOpenProtection, "bounded and rate-limited userspace half-open quota with zero-credit restart"},
	{fakeTCPCapabilitySingleUsePacketAdmissionProof, "single-use packet admission proof with stable-lifetime binding"},
	{fakeTCPCapabilityBPFControlAdmission, "BPF control-event admission/coalescing under SYN flood"},
	{fakeTCPCapabilityValidatedCloseControl, "RST/FIN full IPv4/TCP checksum and receive-window validation"},
	{fakeTCPCapabilityL3Parser, "parser:l3 FakeTCP policy and attachment support"},
	{fakeTCPCapabilityXDPOwnership, "direct generic XDP exact-selected-mode ownership and rollback"},
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

// ValidateFakeTCPActivation is deliberately platform-independent so command
// orchestration, including dry-run, cannot defer this gate to LinuxLoader.
// Callers must invoke it after loading state and before any guard, pin, map,
// TC, XDP, route, or other network mutation.
func ValidateFakeTCPActivation(state *control.State) error {
	references := fakeTCPStateReferences(state)
	if len(references) == 0 {
		return nil
	}
	if fakeTCPActivationReady() {
		return nil
	}
	return fmt.Errorf(
		"%w for configuration references %s; missing capabilities: %s; activation is refused before mutation",
		ErrFakeTCPKernelGate,
		strings.Join(references, ","),
		strings.Join(missingFakeTCPCapabilities(), "; "),
	)
}

// ValidateFakeTCPResidentRuntime prevents a process-owned FakeTCP collection
// from being installed by a one-shot command. The check is intentionally
// platform-independent and must run before startup-guard or dataplane writes.
// Dry-run callers may skip it because they never acquire runtime ownership.
func ValidateFakeTCPResidentRuntime(state *control.State, resident bool) error {
	if len(fakeTCPStateReferences(state)) == 0 || resident {
		return nil
	}
	return fmt.Errorf(
		"%w; use the long-running daemon instead of one-shot reload or run --once",
		ErrFakeTCPResidentRuntimeRequired,
	)
}

// preflightFakeTCPKernelRequirements remains a loader-local defence in depth.
func preflightFakeTCPKernelRequirements(state *control.State) error {
	return ValidateFakeTCPActivation(state)
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
