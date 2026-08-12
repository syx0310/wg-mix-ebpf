//go:build linux

package dataplane

import (
	"context"
	"errors"
	"fmt"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
	"github.com/syx0310/wg-mix-ebpf/internal/faketcp"
)

// fakeTCPRetainedRuntimeHealth keeps the exact borrowed collection handles and
// immutable values which made one FakeTCP generation reachable. The outer
// runtime lock prevents collection Close from racing these read-only checks.
// None of these handles may outlive the collection owner.
type fakeTCPRetainedRuntimeHealth struct {
	policyPlan          *fakeTCPPolicyGenerationPlan
	policyMaps          fakeTCPPolicyMaps
	programStage        *fakeTCPProgramArrayStage
	egressProgram       experimentalProgramResource
	runtimeIdentityMap  fakeTCPPolicyMap
	runtimeIdentityWant abi.FakeTCPRuntimeIdentityValue
}

func retainFakeTCPRuntimeHealth(
	plan *fakeTCPPolicyGenerationPlan,
	policyMaps fakeTCPPolicyMaps,
	programStage *fakeTCPProgramArrayStage,
	egressProgram experimentalProgramResource,
	runtimeIdentityMap fakeTCPPolicyMap,
	identity faketcp.RuntimeIdentity,
) *fakeTCPRetainedRuntimeHealth {
	return &fakeTCPRetainedRuntimeHealth{
		policyPlan:         plan.clone(),
		policyMaps:         policyMaps,
		programStage:       programStage,
		egressProgram:      egressProgram,
		runtimeIdentityMap: runtimeIdentityMap,
		runtimeIdentityWant: abi.FakeTCPRuntimeIdentityValue{
			Generation:      identity.Generation,
			Incarnation:     [16]byte(identity.Incarnation),
			EventABIVersion: abi.FakeTCPEventABIVersion,
		},
	}
}

func (health *fakeTCPRetainedRuntimeHealth) Healthy(ctx context.Context) error {
	if health == nil {
		return errors.New("retained FakeTCP runtime owner is nil")
	}
	if ctx == nil {
		return errors.New("inspect retained FakeTCP runtime: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateFakeTCPPolicyGenerationPlan(health.policyPlan); err != nil {
		return fmt.Errorf("inspect retained FakeTCP policy plan: %w", err)
	}
	if health.policyMaps.ControlPolicies == nil ||
		health.policyMaps.ManagedPorts == nil ||
		health.policyMaps.ManagedInterfaces == nil {
		return errors.New("inspect retained FakeTCP policy maps: owner set is incomplete")
	}

	for _, entry := range health.policyPlan.controlPolicies {
		if err := ctx.Err(); err != nil {
			return err
		}
		var actual abi.FakeTCPControlPolicyValue
		if err := health.policyMaps.ControlPolicies.Lookup(entry.Key, &actual); err != nil {
			return fmt.Errorf(
				"inspect %s key=%#v: %w",
				fakeTCPControlPolicyMapName, entry.Key, err,
			)
		}
		// virtual_time_nanos is the only BPF-owned mutable field. Normalize it
		// before strict struct comparison so generation, rate, burst, and all
		// reserved ABI bytes remain exact.
		actual.VirtualTimeNanos = entry.Value.VirtualTimeNanos
		if actual != entry.Value {
			return fmt.Errorf(
				"inspect %s key=%#v: value %#v differs from retained value %#v",
				fakeTCPControlPolicyMapName, entry.Key, actual, entry.Value,
			)
		}
	}
	for _, entry := range health.policyPlan.managedPorts {
		if err := ctx.Err(); err != nil {
			return err
		}
		var actual abi.FakeTCPManagedPortValue
		if err := health.policyMaps.ManagedPorts.Lookup(entry.Key, &actual); err != nil {
			return fmt.Errorf(
				"inspect %s key=%#v: %w",
				fakeTCPManagedPortMapName, entry.Key, err,
			)
		}
		if actual != entry.Value {
			return fmt.Errorf(
				"inspect %s key=%#v: value %#v differs from retained value %#v",
				fakeTCPManagedPortMapName, entry.Key, actual, entry.Value,
			)
		}
	}
	for _, entry := range health.policyPlan.managedInterfaces {
		if err := ctx.Err(); err != nil {
			return err
		}
		var actual abi.FakeTCPManagedIfValue
		if err := health.policyMaps.ManagedInterfaces.Lookup(entry.Key, &actual); err != nil {
			return fmt.Errorf(
				"inspect %s key=%#v: %w",
				fakeTCPManagedIfMapName, entry.Key, err,
			)
		}
		if actual != entry.Value {
			return fmt.Errorf(
				"inspect %s key=%#v: value %#v differs from retained value %#v",
				fakeTCPManagedIfMapName, entry.Key, actual, entry.Value,
			)
		}
	}

	if health.programStage == nil || health.programStage.programs == nil ||
		health.egressProgram == nil {
		return errors.New("inspect retained FakeTCP egress program: owner is incomplete")
	}
	if health.programStage.state != fakeTCPProgramArrayStageDisarmed {
		return fmt.Errorf(
			"inspect retained FakeTCP egress program: stage state %d is not committed",
			health.programStage.state,
		)
	}
	wantSlot := uint32(health.policyPlan.generation & 1)
	if health.programStage.slot != wantSlot || health.programStage.programID == 0 {
		return fmt.Errorf(
			"inspect retained %s: slot=%d program=%d, want generation slot=%d",
			fakeTCPEgressProgramArrayMapName,
			health.programStage.slot,
			health.programStage.programID,
			wantSlot,
		)
	}
	programID, err := health.egressProgram.ID()
	if err != nil {
		return fmt.Errorf("inspect retained FakeTCP egress program FD: %w", err)
	}
	if programID != health.programStage.programID {
		return fmt.Errorf(
			"inspect retained FakeTCP egress program FD: ID %d differs from retained ID %d",
			programID,
			health.programStage.programID,
		)
	}
	actualProgramID, err := health.programStage.programs.LookupProgramID(
		health.programStage.slot,
	)
	if err != nil {
		return fmt.Errorf(
			"inspect retained %s slot=%d: %w",
			fakeTCPEgressProgramArrayMapName, health.programStage.slot, err,
		)
	}
	if actualProgramID != health.programStage.programID {
		return fmt.Errorf(
			"inspect retained %s slot=%d: program ID %d differs from retained ID %d",
			fakeTCPEgressProgramArrayMapName,
			health.programStage.slot,
			actualProgramID,
			health.programStage.programID,
		)
	}

	if health.runtimeIdentityMap == nil ||
		health.runtimeIdentityWant.Generation != health.policyPlan.generation ||
		health.runtimeIdentityWant.Incarnation == ([16]byte{}) {
		return errors.New("inspect retained faketcp_rt_id: owner identity is incomplete")
	}
	key := uint32(0)
	var actualIdentity abi.FakeTCPRuntimeIdentityValue
	if err := health.runtimeIdentityMap.Lookup(key, &actualIdentity); err != nil {
		return fmt.Errorf("inspect %s key=0: %w", fakeTCPRuntimeIDMapName, err)
	}
	if actualIdentity != health.runtimeIdentityWant {
		return fmt.Errorf(
			"inspect %s key=0: identity %#v differs from retained identity %#v",
			fakeTCPRuntimeIDMapName,
			actualIdentity,
			health.runtimeIdentityWant,
		)
	}
	return nil
}
