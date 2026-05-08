package abi

import (
	"encoding/json"
	"fmt"

	"github.com/syx0310/wg-mix-ebpf/internal/control"
)

const (
	Version uint32 = 4

	FamilyAny  uint8 = 0
	FamilyIPv4 uint8 = 4
	FamilyIPv6 uint8 = 6

	ActionPass    uint8 = 1
	ActionDrop    uint8 = 2
	ActionRewrite uint8 = 3

	UnderlayWildcard uint32 = 0

	ParserAuto     uint8 = 0
	ParserEthernet uint8 = 1
	ParserL3       uint8 = 2
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

type ProfileKey struct {
	Generation uint64
	ProfileID  uint32
	_          uint32
}

type ProfileValue struct {
	Generation      uint64
	StandardToMixed [4]uint32
	MixedToStandard [4]uint32
	PolicyFlags     uint32
	_               uint32
}

func (v ProfileValue) MapGeneration() uint64 { return v.Generation }

type ManagedFwmarkKey struct {
	Generation    uint64
	FwMark        uint32
	UnderlayIndex uint32
}

type UnderlayConfigKey struct {
	Generation    uint64
	UnderlayIndex uint32
	_             uint32
}

type UnderlayConfigValue struct {
	Generation uint64
	ParserMode uint8
	_          [7]byte
}

func (v UnderlayConfigValue) MapGeneration() uint64 { return v.Generation }

type ManagedFwmarkValue struct {
	Generation   uint64
	ActionOnMiss uint8
	_            [7]byte
}

func (v ManagedFwmarkValue) MapGeneration() uint64 { return v.Generation }

type EgressRuleKey struct {
	Generation    uint64
	FwMark        uint32
	UnderlayIndex uint32
	SourcePort    uint16
	Family        uint8
	_             [5]byte
}

type EgressRuleValue struct {
	Generation uint64
	ProfileID  uint32
	WGID       uint32
	Action     uint8
	_          [7]byte
}

func (v EgressRuleValue) MapGeneration() uint64 { return v.Generation }

type IngressListenerKey struct {
	Generation      uint64
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

func (v IngressListenerValue) MapGeneration() uint64 { return v.Generation }

type Snapshot struct {
	Control          map[ControlKey]ControlValue
	Profiles         map[ProfileKey]ProfileValue
	Underlays        map[UnderlayConfigKey]UnderlayConfigValue
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
		Underlays        []MapEntry[UnderlayConfigKey, UnderlayConfigValue]   `json:"underlays"`
		ManagedFwmarks   []MapEntry[ManagedFwmarkKey, ManagedFwmarkValue]     `json:"managed_fwmarks"`
		EgressRules      []MapEntry[EgressRuleKey, EgressRuleValue]           `json:"egress_rules"`
		IngressListeners []MapEntry[IngressListenerKey, IngressListenerValue] `json:"ingress_listeners"`
	}
	return json.Marshal(view{
		Control:          mapEntries(s.Control),
		Profiles:         mapEntries(s.Profiles),
		Underlays:        mapEntries(s.Underlays),
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
	return FromStateWithGeneration(state, state.Generation)
}

func FromStateWithGeneration(state *control.State, generation uint64) (*Snapshot, error) {
	out := &Snapshot{
		Control: map[ControlKey]ControlValue{
			ControlKeyGlobal: {
				ActiveGeneration: generation,
				ABIVersion:       Version,
			},
		},
		Profiles:         make(map[ProfileKey]ProfileValue, len(state.Profiles)),
		Underlays:        make(map[UnderlayConfigKey]UnderlayConfigValue, len(state.Underlays)),
		ManagedFwmarks:   make(map[ManagedFwmarkKey]ManagedFwmarkValue, len(state.ManagedFwmarks)),
		EgressRules:      make(map[EgressRuleKey]EgressRuleValue, len(state.EgressRules)),
		IngressListeners: make(map[IngressListenerKey]IngressListenerValue, len(state.IngressListeners)),
	}
	for _, p := range state.Profiles {
		out.Profiles[ProfileKey{Generation: generation, ProfileID: p.ID}] = ProfileValue{
			Generation:      generation,
			StandardToMixed: p.StandardToMixed,
			MixedToStandard: p.MixedToStandard,
		}
	}
	for _, u := range state.Underlays {
		if !u.Resolved || u.IfIndex == 0 || u.Role == "parse_only" || u.Role == "disabled" {
			continue
		}
		parser, err := parseParser(u.Parser)
		if err != nil {
			return nil, err
		}
		out.Underlays[UnderlayConfigKey{
			Generation:    generation,
			UnderlayIndex: uint32(u.IfIndex),
		}] = UnderlayConfigValue{
			Generation: generation,
			ParserMode: parser,
		}
	}
	for _, r := range state.ManagedFwmarks {
		action, err := parseAction(r.ActionOnMiss)
		if err != nil {
			return nil, err
		}
		out.ManagedFwmarks[ManagedFwmarkKey{
			Generation:    generation,
			FwMark:        r.FwMark,
			UnderlayIndex: uint32(r.UnderlayIfIndex),
		}] = ManagedFwmarkValue{
			Generation:   generation,
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
			Generation:    generation,
			FwMark:        r.FwMark,
			UnderlayIndex: uint32(r.UnderlayIfIndex),
			SourcePort:    r.SourcePort,
			Family:        family,
		}] = EgressRuleValue{
			Generation: generation,
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
			Generation:      generation,
			UnderlayIndex:   uint32(r.UnderlayIfIndex),
			DestinationPort: r.DestinationPort,
			Family:          family,
		}] = IngressListenerValue{
			Generation: generation,
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

func parseParser(parser string) (uint8, error) {
	switch parser {
	case "", "auto":
		return ParserAuto, nil
	case "ethernet":
		return ParserEthernet, nil
	case "l3":
		return ParserL3, nil
	default:
		return 0, fmt.Errorf("unsupported underlay parser %q", parser)
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
