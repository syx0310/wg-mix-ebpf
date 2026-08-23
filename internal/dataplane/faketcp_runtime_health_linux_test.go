//go:build linux

package dataplane

import (
	"strings"
	"testing"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

func TestExperimentalFakeTCPRuntimeHealthIgnoresOnlyControlVirtualTime(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	runtime, _, err := fixture.build(t, 91)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := runtime.Close(); err != nil {
			t.Errorf("close runtime: %v", err)
		}
	})

	controlMap := fixture.policyMaps.ControlPolicies.(*memoryFakeTCPPolicyMap)
	for key, untyped := range controlMap.entries {
		value := untyped.(abi.FakeTCPControlPolicyValue)
		value.VirtualTimeNanos += 987654321
		controlMap.entries[key] = value
	}
	if err := runtime.Healthy(t.Context()); err != nil {
		t.Fatalf("BPF-owned virtual time made runtime unhealthy: %v", err)
	}
}

func TestExperimentalFakeTCPRuntimeHealthDetectsRetainedKernelDrift(t *testing.T) {
	tests := []struct {
		name   string
		want   string
		mutate func(*runtimeTestFixture, *ExperimentalFakeTCPRuntime)
	}{
		{
			name: "control policy",
			want: fakeTCPControlPolicyMapName,
			mutate: func(fixture *runtimeTestFixture, _ *ExperimentalFakeTCPRuntime) {
				entries := fixture.policyMaps.ControlPolicies.(*memoryFakeTCPPolicyMap).entries
				for key, untyped := range entries {
					value := untyped.(abi.FakeTCPControlPolicyValue)
					value.IntervalNanos++
					entries[key] = value
					break
				}
			},
		},
		{
			name: "managed port",
			want: fakeTCPManagedPortMapName,
			mutate: func(fixture *runtimeTestFixture, _ *ExperimentalFakeTCPRuntime) {
				entries := fixture.policyMaps.ManagedPorts.(*memoryFakeTCPPolicyMap).entries
				for key, untyped := range entries {
					value := untyped.(abi.FakeTCPManagedPortValue)
					value.WGID++
					entries[key] = value
					break
				}
			},
		},
		{
			name: "managed interface",
			want: fakeTCPManagedIfMapName,
			mutate: func(fixture *runtimeTestFixture, _ *ExperimentalFakeTCPRuntime) {
				entries := fixture.policyMaps.ManagedInterfaces.(*memoryFakeTCPPolicyMap).entries
				for key, untyped := range entries {
					value := untyped.(abi.FakeTCPManagedIfValue)
					value.Generation++
					entries[key] = value
					break
				}
			},
		},
		{
			name: "egress program array slot",
			want: fakeTCPEgressProgramArrayMapName,
			mutate: func(fixture *runtimeTestFixture, runtime *ExperimentalFakeTCPRuntime) {
				slot := runtime.state.retained.programStage.slot
				fixture.programArray.entries[slot]++
			},
		},
		{
			name: "egress program FD identity",
			want: "egress program FD",
			mutate: func(fixture *runtimeTestFixture, _ *ExperimentalFakeTCPRuntime) {
				fixture.programs[fakeTCPEgressProgramName].id++
			},
		},
		{
			name: "runtime identity",
			want: fakeTCPRuntimeIDMapName,
			mutate: func(fixture *runtimeTestFixture, _ *ExperimentalFakeTCPRuntime) {
				backend := fixture.mapResources[fakeTCPRuntimeIDMapName].fakeTCPPolicyMap.(*memoryFakeTCPPolicyMap)
				value := backend.entries[uint32(0)].(abi.FakeTCPRuntimeIdentityValue)
				value.EventABIVersion++
				backend.entries[uint32(0)] = value
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRuntimeTestFixture(t)
			runtime, _, err := fixture.build(t, 91)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := runtime.Close(); err != nil {
					t.Errorf("close runtime: %v", err)
				}
			})
			if err := runtime.Healthy(t.Context()); err != nil {
				t.Fatalf("initial retained health: %v", err)
			}
			test.mutate(fixture, runtime)
			err = runtime.Healthy(t.Context())
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("drift health error=%v, want %q", err, test.want)
			}
		})
	}
}
