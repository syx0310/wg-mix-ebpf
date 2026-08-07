package dataplane

import (
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
	"github.com/syx0310/wg-mix-ebpf/internal/config"
	"github.com/syx0310/wg-mix-ebpf/internal/control"
)

const (
	// The experimental maps retain two generations during a staged reload.
	// These per-generation limits are therefore half of the exact ELF map
	// capacities asserted by object_manifest_linux_test.go.
	fakeTCPManagedInterfacesPerGeneration = 256
	fakeTCPManagedPortsPerGeneration      = 1024
	fakeTCPControlPoliciesPerGeneration   = 256

	fakeTCPControlMinInterval = 10 * time.Millisecond
	fakeTCPControlMaxInterval = 10 * time.Second
)

// fakeTCPPolicySnapshot is deliberately separate from abi.Snapshot. It is an
// unpinned experimental extension and must not silently enlarge the canonical
// ABI-v10 owner set.
type fakeTCPPolicySnapshot struct {
	Generation        uint64
	ControlPolicies   map[abi.FakeTCPControlPolicyKey]abi.FakeTCPControlPolicyValue
	ManagedPorts      map[abi.FakeTCPManagedPortKey]abi.FakeTCPManagedPortValue
	ManagedInterfaces map[abi.FakeTCPManagedIfKey]abi.FakeTCPManagedIfValue
}

func buildFakeTCPPolicySnapshot(
	state *control.State,
	generation uint64,
) (*fakeTCPPolicySnapshot, error) {
	if state == nil {
		return nil, errors.New("build FakeTCP policy: state is nil")
	}
	if state.Generation == 0 {
		return nil, errors.New("build FakeTCP policy: source state generation must be nonzero")
	}
	if generation == 0 {
		return nil, errors.New("build FakeTCP policy: target generation must be nonzero")
	}

	snapshot := &fakeTCPPolicySnapshot{
		Generation:        generation,
		ControlPolicies:   make(map[abi.FakeTCPControlPolicyKey]abi.FakeTCPControlPolicyValue),
		ManagedPorts:      make(map[abi.FakeTCPManagedPortKey]abi.FakeTCPManagedPortValue),
		ManagedInterfaces: make(map[abi.FakeTCPManagedIfKey]abi.FakeTCPManagedIfValue),
	}

	wireGuards := make(map[uint32]control.WireGuardState, len(state.WireGuards))
	for _, wg := range state.WireGuards {
		if wg.ID == 0 {
			if wg.TransportMode == "faketcp" {
				return nil, fmt.Errorf("build FakeTCP policy: WireGuard %q has zero ID", wg.Name)
			}
			continue
		}
		if previous, exists := wireGuards[wg.ID]; exists {
			return nil, fmt.Errorf(
				"build FakeTCP policy: WireGuard ID %d is duplicated by %q and %q",
				wg.ID, previous.Name, wg.Name,
			)
		}
		wireGuards[wg.ID] = wg
	}

	underlays := make(map[int]control.UnderlayState, len(state.Underlays))
	for _, underlay := range state.Underlays {
		if underlay.IfIndex <= 0 {
			continue
		}
		if previous, exists := underlays[underlay.IfIndex]; exists {
			return nil, fmt.Errorf(
				"build FakeTCP policy: underlay ifindex %d is duplicated by %q and %q",
				underlay.IfIndex, previous.Name, underlay.Name,
			)
		}
		underlays[underlay.IfIndex] = underlay
	}

	for index, listener := range state.IngressListeners {
		if listener.TransportMode != "faketcp" {
			continue
		}
		if listener.Generation != state.Generation {
			return nil, fmt.Errorf(
				"build FakeTCP policy: ingress[%d] source generation %d does not match state generation %d",
				index, listener.Generation, state.Generation,
			)
		}
		if listener.Family != "ipv4" {
			return nil, fmt.Errorf(
				"build FakeTCP policy: ingress[%d] family %q is unsupported; only ipv4 is implemented",
				index, listener.Family,
			)
		}
		if listener.DestinationPort == 0 {
			return nil, fmt.Errorf("build FakeTCP policy: ingress[%d] has zero destination port", index)
		}
		if listener.Action != "rewrite" {
			return nil, fmt.Errorf(
				"build FakeTCP policy: ingress[%d] action %q is unsupported; want rewrite",
				index, listener.Action,
			)
		}
		if listener.UnderlayIfIndex <= 0 || uint64(listener.UnderlayIfIndex) > math.MaxUint32 {
			return nil, fmt.Errorf(
				"build FakeTCP policy: ingress[%d] underlay ifindex %d is invalid",
				index, listener.UnderlayIfIndex,
			)
		}
		underlay, exists := underlays[listener.UnderlayIfIndex]
		if !exists {
			return nil, fmt.Errorf(
				"build FakeTCP policy: ingress[%d] references unknown underlay ifindex %d",
				index, listener.UnderlayIfIndex,
			)
		}
		if !underlay.Resolved || underlay.Role != "transform" {
			return nil, fmt.Errorf(
				"build FakeTCP policy: ingress[%d] underlay %q is not a resolved transform attachment",
				index, underlay.Name,
			)
		}
		if underlay.Parser != "ethernet" {
			return nil, fmt.Errorf(
				"build FakeTCP policy: ingress[%d] underlay %q parser is %q; want ethernet",
				index, underlay.Name, underlay.Parser,
			)
		}

		wg, exists := wireGuards[listener.WGID]
		if !exists {
			return nil, fmt.Errorf(
				"build FakeTCP policy: ingress[%d] references unknown WireGuard ID %d",
				index, listener.WGID,
			)
		}
		if wg.TransportMode != "faketcp" {
			return nil, fmt.Errorf(
				"build FakeTCP policy: ingress[%d] references WireGuard %q with transport %q",
				index, wg.Name, wg.TransportMode,
			)
		}
		if err := validateFakeTCPPolicyWireGuard(wg); err != nil {
			return nil, err
		}

		ifKey := abi.FakeTCPManagedIfKey{
			Generation:    generation,
			UnderlayIndex: uint32(listener.UnderlayIfIndex),
		}
		snapshot.ManagedInterfaces[ifKey] = abi.FakeTCPManagedIfValue{Generation: generation}

		portKey := abi.FakeTCPManagedPortKey{
			Generation:      generation,
			UnderlayIndex:   uint32(listener.UnderlayIfIndex),
			DestinationPort: listener.DestinationPort,
		}
		if _, duplicate := snapshot.ManagedPorts[portKey]; duplicate {
			return nil, fmt.Errorf(
				"build FakeTCP policy: duplicate managed listener for ifindex %d port %d",
				listener.UnderlayIfIndex, listener.DestinationPort,
			)
		}
		snapshot.ManagedPorts[portKey] = abi.FakeTCPManagedPortValue{
			Generation: generation,
			WGID:       listener.WGID,
			Action:     abi.ActionRewrite,
		}

		policyKey := abi.FakeTCPControlPolicyKey{Generation: generation, WGID: wg.ID}
		if _, exists := snapshot.ControlPolicies[policyKey]; !exists {
			snapshot.ControlPolicies[policyKey] = abi.FakeTCPControlPolicyValue{
				Generation:       generation,
				VirtualTimeNanos: 0,
				IntervalNanos:    uint64(wg.FakeTCPSYNRateIntervalNanos),
				Burst:            wg.FakeTCPSYNBurst,
			}
		}
	}

	if err := validateFakeTCPPolicySnapshot(snapshot); err != nil {
		return nil, fmt.Errorf("build FakeTCP policy: %w", err)
	}
	return snapshot, nil
}

func validateFakeTCPPolicyWireGuard(wg control.WireGuardState) error {
	if !wg.FakeTCPExperimental {
		return fmt.Errorf("build FakeTCP policy: WireGuard %q has not acknowledged the experiment", wg.Name)
	}
	if wg.FakeTCPChecksumMode != config.FakeTCPChecksumModePartialCompleteReset {
		return fmt.Errorf(
			"build FakeTCP policy: WireGuard %q checksum mode is %q",
			wg.Name, wg.FakeTCPChecksumMode,
		)
	}
	if wg.FakeTCPIngressMode != "xdp-required" {
		return fmt.Errorf(
			"build FakeTCP policy: WireGuard %q ingress mode is %q; want xdp-required",
			wg.Name, wg.FakeTCPIngressMode,
		)
	}
	interval := time.Duration(wg.FakeTCPSYNRateIntervalNanos)
	if interval < fakeTCPControlMinInterval || interval > fakeTCPControlMaxInterval {
		return fmt.Errorf(
			"build FakeTCP policy: WireGuard %q control interval %s is outside [%s,%s]",
			wg.Name, interval, fakeTCPControlMinInterval, fakeTCPControlMaxInterval,
		)
	}
	if wg.FakeTCPSYNBurst == 0 || wg.FakeTCPSYNBurst > config.MaxFakeTCPSYNBurst {
		return fmt.Errorf(
			"build FakeTCP policy: WireGuard %q control burst %d is outside [1,%d]",
			wg.Name, wg.FakeTCPSYNBurst, config.MaxFakeTCPSYNBurst,
		)
	}
	return nil
}

func validateFakeTCPPolicySnapshot(snapshot *fakeTCPPolicySnapshot) error {
	if snapshot == nil {
		return errors.New("snapshot is nil")
	}
	if snapshot.Generation == 0 {
		return errors.New("snapshot generation must be nonzero")
	}
	if len(snapshot.ManagedInterfaces) == 0 || len(snapshot.ManagedPorts) == 0 ||
		len(snapshot.ControlPolicies) == 0 {
		return errors.New("snapshot contains no complete managed FakeTCP policy")
	}
	if len(snapshot.ManagedInterfaces) > fakeTCPManagedInterfacesPerGeneration {
		return fmt.Errorf(
			"managed interfaces %d exceed per-generation capacity %d",
			len(snapshot.ManagedInterfaces), fakeTCPManagedInterfacesPerGeneration,
		)
	}
	if len(snapshot.ManagedPorts) > fakeTCPManagedPortsPerGeneration {
		return fmt.Errorf(
			"managed ports %d exceed per-generation capacity %d",
			len(snapshot.ManagedPorts), fakeTCPManagedPortsPerGeneration,
		)
	}
	if len(snapshot.ControlPolicies) > fakeTCPControlPoliciesPerGeneration {
		return fmt.Errorf(
			"control policies %d exceed per-generation capacity %d",
			len(snapshot.ControlPolicies), fakeTCPControlPoliciesPerGeneration,
		)
	}

	referencedInterfaces := make(map[abi.FakeTCPManagedIfKey]struct{}, len(snapshot.ManagedPorts))
	referencedPolicies := make(map[abi.FakeTCPControlPolicyKey]struct{}, len(snapshot.ManagedPorts))
	for key, value := range snapshot.ManagedInterfaces {
		if key.Generation != snapshot.Generation || value.Generation != snapshot.Generation {
			return errors.New("managed interface generation does not match snapshot generation")
		}
		if key.UnderlayIndex == 0 {
			return errors.New("managed interface has zero underlay index")
		}
	}
	for key, value := range snapshot.ControlPolicies {
		if key.Generation != snapshot.Generation || value.Generation != snapshot.Generation {
			return errors.New("control policy generation does not match snapshot generation")
		}
		if key.WGID == 0 {
			return errors.New("control policy has zero WireGuard ID")
		}
		if value.VirtualTimeNanos != 0 {
			return fmt.Errorf(
				"control policy for WireGuard ID %d has nonzero BPF-owned virtual time",
				key.WGID,
			)
		}
		if value.IntervalNanos < uint64(fakeTCPControlMinInterval) ||
			value.IntervalNanos > uint64(fakeTCPControlMaxInterval) {
			return fmt.Errorf("control policy for WireGuard ID %d has invalid interval", key.WGID)
		}
		if value.Burst == 0 || value.Burst > config.MaxFakeTCPSYNBurst {
			return fmt.Errorf("control policy for WireGuard ID %d has invalid burst", key.WGID)
		}
	}
	for key, value := range snapshot.ManagedPorts {
		if key.Generation != snapshot.Generation || value.Generation != snapshot.Generation {
			return errors.New("managed port generation does not match snapshot generation")
		}
		if key.UnderlayIndex == 0 || key.DestinationPort == 0 {
			return errors.New("managed port has zero interface or destination port")
		}
		if value.WGID == 0 || value.Action != abi.ActionRewrite {
			return errors.New("managed port has invalid WireGuard ID or action")
		}
		ifKey := abi.FakeTCPManagedIfKey{
			Generation:    snapshot.Generation,
			UnderlayIndex: key.UnderlayIndex,
		}
		if _, exists := snapshot.ManagedInterfaces[ifKey]; !exists {
			return fmt.Errorf(
				"managed port ifindex %d port %d has no interface latch",
				key.UnderlayIndex, key.DestinationPort,
			)
		}
		policyKey := abi.FakeTCPControlPolicyKey{
			Generation: snapshot.Generation,
			WGID:       value.WGID,
		}
		if _, exists := snapshot.ControlPolicies[policyKey]; !exists {
			return fmt.Errorf(
				"managed port ifindex %d port %d has no WireGuard control policy",
				key.UnderlayIndex, key.DestinationPort,
			)
		}
		referencedInterfaces[ifKey] = struct{}{}
		referencedPolicies[policyKey] = struct{}{}
	}
	for key := range snapshot.ManagedInterfaces {
		if _, referenced := referencedInterfaces[key]; !referenced {
			return fmt.Errorf("managed interface ifindex %d has no managed port", key.UnderlayIndex)
		}
	}
	for key := range snapshot.ControlPolicies {
		if _, referenced := referencedPolicies[key]; !referenced {
			return fmt.Errorf("control policy for WireGuard ID %d has no managed port", key.WGID)
		}
	}
	return nil
}
