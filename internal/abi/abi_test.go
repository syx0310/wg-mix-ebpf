package abi

import (
	"testing"
	"unsafe"

	"github.com/siyixuan/wg-mix-ebpf/internal/control"
)

func TestStructSizesAreStable(t *testing.T) {
	checks := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"ControlValue", unsafe.Sizeof(ControlValue{}), 16},
		{"ProfileValue", unsafe.Sizeof(ProfileValue{}), 48},
		{"ManagedFwmarkKey", unsafe.Sizeof(ManagedFwmarkKey{}), 8},
		{"ManagedFwmarkValue", unsafe.Sizeof(ManagedFwmarkValue{}), 16},
		{"EgressRuleKey", unsafe.Sizeof(EgressRuleKey{}), 12},
		{"EgressRuleValue", unsafe.Sizeof(EgressRuleValue{}), 24},
		{"IngressListenerKey", unsafe.Sizeof(IngressListenerKey{}), 8},
		{"IngressListenerValue", unsafe.Sizeof(IngressListenerValue{}), 24},
	}
	for _, check := range checks {
		if check.got != check.want {
			t.Fatalf("%s size = %d, want %d", check.name, check.got, check.want)
		}
	}
}

func TestFromState(t *testing.T) {
	state := &control.State{
		Generation: 7,
		Profiles: []control.ProfileState{
			{
				ID:              1,
				Name:            "default",
				StandardToMixed: [4]uint32{10, 11, 12, 13},
				MixedToStandard: [4]uint32{1, 2, 3, 4},
			},
		},
		ManagedFwmarks: []control.ManagedFwmarkRule{
			{Generation: 7, FwMark: 0x10000001, UnderlayIfIndex: 2, ActionOnMiss: "drop"},
		},
		EgressRules: []control.EgressRule{
			{Generation: 7, Family: "ipv4", FwMark: 0x10000001, SourcePort: 31001, UnderlayIfIndex: 2, ProfileID: 1, WGID: 1, Action: "rewrite"},
		},
		IngressListeners: []control.IngressListener{
			{Generation: 7, Family: "ipv6", DestinationPort: 31001, UnderlayIfIndex: 2, ProfileID: 1, WGID: 1, Action: "rewrite"},
		},
	}
	snapshot, err := FromState(state)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Control[ControlKeyGlobal].ActiveGeneration != 7 {
		t.Fatalf("generation = %d", snapshot.Control[ControlKeyGlobal].ActiveGeneration)
	}
	if snapshot.EgressRules[EgressRuleKey{FwMark: 0x10000001, UnderlayIndex: 2, SourcePort: 31001, Family: FamilyIPv4}].Action != ActionRewrite {
		t.Fatal("missing egress rewrite rule")
	}
	if snapshot.ManagedFwmarks[ManagedFwmarkKey{FwMark: 0x10000001, UnderlayIndex: 2}].ActionOnMiss != ActionDrop {
		t.Fatal("missing managed fwmark drop rule")
	}
	if snapshot.IngressListeners[IngressListenerKey{UnderlayIndex: 2, DestinationPort: 31001, Family: FamilyIPv6}].Action != ActionRewrite {
		t.Fatal("missing ingress rewrite rule")
	}
}
