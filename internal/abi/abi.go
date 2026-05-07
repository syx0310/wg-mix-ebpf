package abi

import (
	"encoding/json"
	"fmt"

	"github.com/siyixuan/wg-mix-ebpf/internal/control"
)

const (
	Version uint32 = 1

	FamilyAny  uint8 = 0
	FamilyIPv4 uint8 = 4
	FamilyIPv6 uint8 = 6

	ActionPass    uint8 = 1
	ActionDrop    uint8 = 2
	ActionRewrite uint8 = 3

	UnderlayWildcard uint32 = 0
)

type ControlKey uint32

const (
	ControlKeyGlobal ControlKey = 0
)

type ControlValue struct {
	ActiveGeneration uint64
	ABIVersion       uint32
	Flags            uint32
}

type ProfileKey uint32

type ProfileValue struct {
	Generation      uint64
	StandardToMixed [4]uint32
	MixedToStandard [4]uint32
	PolicyFlags     uint32
	_               uint32
}

type ManagedFwmarkKey struct {
	FwMark        uint32
	UnderlayIndex uint32
}

type ManagedFwmarkValue struct {
	Generation   uint64
	ActionOnMiss uint8
	_            [7]byte
}

type EgressRuleKey struct {
	FwMark        uint32
	UnderlayIndex uint32
	SourcePort    uint16
	Family        uint8
	_             uint8
}

type EgressRuleValue struct {
	Generation uint64
	ProfileID  uint32
	WGID       uint32
	Action     uint8
	_          [7]byte
}

type IngressListenerKey struct {
	UnderlayIndex   uint32
	DestinationPort uint16
	Family          uint8
	_               uint8
}

type IngressListenerValue struct {
	Generation uint64
	ProfileID  uint32
	WGID       uint32
	Action     uint8
	_          [7]byte
}

type Snapshot struct {
	Control          map[ControlKey]ControlValue
	Profiles         map[ProfileKey]ProfileValue
	ManagedFwmarks   map[ManagedFwmarkKey]ManagedFwmarkValue
	EgressRules      map[EgressRuleKey]EgressRuleValue
	IngressListeners map[IngressListenerKey]IngressListenerValue
}

type MapEntry[K comparable, V any] struct {
	Key   K `json:"key"`
	Value V `json:"value"`
}

func (s Snapshot) MarshalJSON() ([]byte, error) {
	type view struct {
		Control          []MapEntry[ControlKey, ControlValue]                 `json:"control"`
		Profiles         []MapEntry[ProfileKey, ProfileValue]                 `json:"profiles"`
		ManagedFwmarks   []MapEntry[ManagedFwmarkKey, ManagedFwmarkValue]     `json:"managed_fwmarks"`
		EgressRules      []MapEntry[EgressRuleKey, EgressRuleValue]           `json:"egress_rules"`
		IngressListeners []MapEntry[IngressListenerKey, IngressListenerValue] `json:"ingress_listeners"`
	}
	return json.Marshal(view{
		Control:          mapEntries(s.Control),
		Profiles:         mapEntries(s.Profiles),
		ManagedFwmarks:   mapEntries(s.ManagedFwmarks),
		EgressRules:      mapEntries(s.EgressRules),
		IngressListeners: mapEntries(s.IngressListeners),
	})
}

func mapEntries[K comparable, V any](m map[K]V) []MapEntry[K, V] {
	out := make([]MapEntry[K, V], 0, len(m))
	for k, v := range m {
		out = append(out, MapEntry[K, V]{Key: k, Value: v})
	}
	return out
}

func FromState(state *control.State) (*Snapshot, error) {
	out := &Snapshot{
		Control: map[ControlKey]ControlValue{
			ControlKeyGlobal: {
				ActiveGeneration: state.Generation,
				ABIVersion:       Version,
			},
		},
		Profiles:         make(map[ProfileKey]ProfileValue, len(state.Profiles)),
		ManagedFwmarks:   make(map[ManagedFwmarkKey]ManagedFwmarkValue, len(state.ManagedFwmarks)),
		EgressRules:      make(map[EgressRuleKey]EgressRuleValue, len(state.EgressRules)),
		IngressListeners: make(map[IngressListenerKey]IngressListenerValue, len(state.IngressListeners)),
	}
	for _, p := range state.Profiles {
		out.Profiles[ProfileKey(p.ID)] = ProfileValue{
			Generation:      state.Generation,
			StandardToMixed: p.StandardToMixed,
			MixedToStandard: p.MixedToStandard,
		}
	}
	for _, r := range state.ManagedFwmarks {
		action, err := parseAction(r.ActionOnMiss)
		if err != nil {
			return nil, err
		}
		out.ManagedFwmarks[ManagedFwmarkKey{
			FwMark:        r.FwMark,
			UnderlayIndex: uint32(r.UnderlayIfIndex),
		}] = ManagedFwmarkValue{
			Generation:   r.Generation,
			ActionOnMiss: action,
		}
	}
	for _, r := range state.EgressRules {
		family, err := parseFamily(r.Family)
		if err != nil {
			return nil, err
		}
		action, err := parseAction(r.Action)
		if err != nil {
			return nil, err
		}
		out.EgressRules[EgressRuleKey{
			FwMark:        r.FwMark,
			UnderlayIndex: uint32(r.UnderlayIfIndex),
			SourcePort:    r.SourcePort,
			Family:        family,
		}] = EgressRuleValue{
			Generation: r.Generation,
			ProfileID:  r.ProfileID,
			WGID:       r.WGID,
			Action:     action,
		}
	}
	for _, r := range state.IngressListeners {
		family, err := parseFamily(r.Family)
		if err != nil {
			return nil, err
		}
		action, err := parseAction(r.Action)
		if err != nil {
			return nil, err
		}
		out.IngressListeners[IngressListenerKey{
			UnderlayIndex:   uint32(r.UnderlayIfIndex),
			DestinationPort: r.DestinationPort,
			Family:          family,
		}] = IngressListenerValue{
			Generation: r.Generation,
			ProfileID:  r.ProfileID,
			WGID:       r.WGID,
			Action:     action,
		}
	}
	return out, nil
}

func parseFamily(family string) (uint8, error) {
	switch family {
	case "", "any":
		return FamilyAny, nil
	case "ipv4":
		return FamilyIPv4, nil
	case "ipv6":
		return FamilyIPv6, nil
	default:
		return 0, fmt.Errorf("unsupported family %q", family)
	}
}

func parseAction(action string) (uint8, error) {
	switch action {
	case "pass":
		return ActionPass, nil
	case "drop":
		return ActionDrop, nil
	case "rewrite":
		return ActionRewrite, nil
	default:
		return 0, fmt.Errorf("unsupported action %q", action)
	}
}
