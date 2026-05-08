package abi

import (
	"testing"
	"unsafe"

	"github.com/syx0310/wg-mix-ebpf/internal/control"
)

func TestStructSizesAreStable(t *testing.T) {
	checks := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"ControlValue", unsafe.Sizeof(ControlValue{}), 16},
		{"ProfileKey", unsafe.Sizeof(ProfileKey{}), 16},
		{"ProfileValue", unsafe.Sizeof(ProfileValue{}), 48},
		{"UnderlayConfigKey", unsafe.Sizeof(UnderlayConfigKey{}), 16},
		{"UnderlayConfigValue", unsafe.Sizeof(UnderlayConfigValue{}), 16},
		{"ManagedFwmarkKey", unsafe.Sizeof(ManagedFwmarkKey{}), 16},
		{"ManagedFwmarkValue", unsafe.Sizeof(ManagedFwmarkValue{}), 16},
		{"EgressRuleKey", unsafe.Sizeof(EgressRuleKey{}), 24},
		{"EgressRuleValue", unsafe.Sizeof(EgressRuleValue{}), 24},
		{"IngressListenerKey", unsafe.Sizeof(IngressListenerKey{}), 16},
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
		Underlays: []control.UnderlayState{
			{IfIndex: 2, Parser: "ethernet", Role: "transform", Resolved: true},
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
	if snapshot.Underlays[UnderlayConfigKey{Generation: 7, UnderlayIndex: 2}].ParserMode != ParserEthernet {
		t.Fatal("missing underlay parser mode")
	}
	if snapshot.EgressRules[EgressRuleKey{Generation: 7, FwMark: 0x10000001, UnderlayIndex: 2, SourcePort: 31001, Family: FamilyIPv4}].Action != ActionRewrite {
		t.Fatal("missing egress rewrite rule")
	}
	if snapshot.ManagedFwmarks[ManagedFwmarkKey{Generation: 7, FwMark: 0x10000001, UnderlayIndex: 2}].ActionOnMiss != ActionDrop {
		t.Fatal("missing managed fwmark drop rule")
	}
	if snapshot.IngressListeners[IngressListenerKey{Generation: 7, UnderlayIndex: 2, DestinationPort: 31001, Family: FamilyIPv6}].Action != ActionRewrite {
		t.Fatal("missing ingress rewrite rule")
	}
}

func TestFromStateWithGenerationOverridesRuleGeneration(t *testing.T) {
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
		Underlays: []control.UnderlayState{
			{IfIndex: 2, Parser: "ethernet", Role: "transform", Resolved: true},
		},
		ManagedFwmarks: []control.ManagedFwmarkRule{
			{Generation: 7, FwMark: 0x10000001, UnderlayIfIndex: 2, ActionOnMiss: "drop"},
		},
		EgressRules: []control.EgressRule{
			{Generation: 7, Family: "ipv4", FwMark: 0x10000001, SourcePort: 31001, UnderlayIfIndex: 2, ProfileID: 1, WGID: 1, Action: "rewrite"},
		},
		IngressListeners: []control.IngressListener{
			{Generation: 7, Family: "ipv4", DestinationPort: 31001, UnderlayIfIndex: 2, ProfileID: 1, WGID: 1, Action: "rewrite"},
		},
	}
	snapshot, err := FromStateWithGeneration(state, 42)
	if err != nil {
		t.Fatal(err)
	}
	if got := snapshot.Control[ControlKeyGlobal].ActiveGeneration; got != 42 {
		t.Fatalf("control generation = %d, want 42", got)
	}
	if got := snapshot.Profiles[ProfileKey{Generation: 42, ProfileID: 1}].Generation; got != 42 {
		t.Fatalf("profile generation = %d, want 42", got)
	}
	if got := snapshot.ManagedFwmarks[ManagedFwmarkKey{Generation: 42, FwMark: 0x10000001, UnderlayIndex: 2}].Generation; got != 42 {
		t.Fatalf("managed fwmark generation = %d, want 42", got)
	}
	if got := snapshot.EgressRules[EgressRuleKey{Generation: 42, FwMark: 0x10000001, UnderlayIndex: 2, SourcePort: 31001, Family: FamilyIPv4}].Generation; got != 42 {
		t.Fatalf("egress generation = %d, want 42", got)
	}
	if got := snapshot.IngressListeners[IngressListenerKey{Generation: 42, UnderlayIndex: 2, DestinationPort: 31001, Family: FamilyIPv4}].Generation; got != 42 {
		t.Fatalf("ingress generation = %d, want 42", got)
	}
}

func TestGenerationIsPartOfDataplaneKeys(t *testing.T) {
	state := &control.State{
		Generation: 1,
		Profiles: []control.ProfileState{
			{
				ID:              1,
				Name:            "default",
				StandardToMixed: [4]uint32{10, 11, 12, 13},
				MixedToStandard: [4]uint32{1, 2, 3, 4},
			},
		},
		Underlays: []control.UnderlayState{
			{IfIndex: 2, Parser: "ethernet", Role: "transform", Resolved: true},
		},
		ManagedFwmarks: []control.ManagedFwmarkRule{
			{FwMark: 0x10000001, UnderlayIfIndex: 2, ActionOnMiss: "drop"},
		},
		EgressRules: []control.EgressRule{
			{Family: "ipv4", FwMark: 0x10000001, SourcePort: 31001, UnderlayIfIndex: 2, ProfileID: 1, WGID: 1, Action: "rewrite"},
		},
		IngressListeners: []control.IngressListener{
			{Family: "ipv4", DestinationPort: 31001, UnderlayIfIndex: 2, ProfileID: 1, WGID: 1, Action: "rewrite"},
		},
	}
	oldSnapshot, err := FromStateWithGeneration(state, 1)
	if err != nil {
		t.Fatal(err)
	}
	newSnapshot, err := FromStateWithGeneration(state, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := oldSnapshot.EgressRules[EgressRuleKey{Generation: 1, FwMark: 0x10000001, UnderlayIndex: 2, SourcePort: 31001, Family: FamilyIPv4}]; !ok {
		t.Fatal("missing old generation egress rule")
	}
	if _, ok := newSnapshot.EgressRules[EgressRuleKey{Generation: 2, FwMark: 0x10000001, UnderlayIndex: 2, SourcePort: 31001, Family: FamilyIPv4}]; !ok {
		t.Fatal("missing new generation egress rule")
	}
	if _, ok := newSnapshot.EgressRules[EgressRuleKey{Generation: 1, FwMark: 0x10000001, UnderlayIndex: 2, SourcePort: 31001, Family: FamilyIPv4}]; ok {
		t.Fatal("new snapshot unexpectedly overwrites old generation key")
	}
	if _, ok := oldSnapshot.ManagedFwmarks[ManagedFwmarkKey{Generation: 1, FwMark: 0x10000001, UnderlayIndex: 2}]; !ok {
		t.Fatal("missing old generation managed fwmark")
	}
	if _, ok := newSnapshot.ManagedFwmarks[ManagedFwmarkKey{Generation: 2, FwMark: 0x10000001, UnderlayIndex: 2}]; !ok {
		t.Fatal("missing new generation managed fwmark")
	}
}
