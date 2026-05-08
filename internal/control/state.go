package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/syx0310/wg-mix-ebpf/internal/config"
	"github.com/syx0310/wg-mix-ebpf/internal/profile"
	"github.com/syx0310/wg-mix-ebpf/internal/runtime"
	"github.com/syx0310/wg-mix-ebpf/internal/underlay"
	"github.com/syx0310/wg-mix-ebpf/internal/wgconfig"
)

type BuildOptions struct {
	Offline bool
}

type WGConfigLoader func(path string) (*wgconfig.Interface, error)

type State struct {
	Generation       uint64              `json:"generation"`
	Profiles         []ProfileState      `json:"profiles"`
	WireGuards       []WireGuardState    `json:"wireguards"`
	Underlays        []UnderlayState     `json:"underlays"`
	ManagedFwmarks   []ManagedFwmarkRule `json:"managed_fwmarks"`
	EgressRules      []EgressRule        `json:"egress_rules"`
	IngressListeners []IngressListener   `json:"ingress_listeners"`
	Warnings         []string            `json:"warnings,omitempty"`
}

type ProfileState struct {
	ID              uint32    `json:"id"`
	Name            string    `json:"name"`
	StandardToMixed [4]uint32 `json:"standard_to_mixed"`
	MixedToStandard [4]uint32 `json:"mixed_to_standard"`
}

type WireGuardState struct {
	ID                    uint32 `json:"id"`
	Name                  string `json:"name"`
	ConfigPath            string `json:"config_path"`
	Profile               string `json:"profile"`
	ProfileID             uint32 `json:"profile_id"`
	ConfigFwMark          uint32 `json:"config_fwmark"`
	ConfigListenPort      uint16 `json:"config_listen_port,omitempty"`
	RuntimeFirewallMark   uint32 `json:"runtime_firewall_mark,omitempty"`
	RuntimeListenPort     uint16 `json:"runtime_listen_port,omitempty"`
	RuntimeIfIndex        int    `json:"runtime_ifindex,omitempty"`
	RuntimeStateAvailable bool   `json:"runtime_state_available"`
}

type UnderlayState struct {
	ID       uint32 `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Parser   string `json:"parser"`
	IfName   string `json:"ifname,omitempty"`
	IfIndex  int    `json:"ifindex,omitempty"`
	LinkType string `json:"link_type,omitempty"`
	Role     string `json:"role,omitempty"`
	Resolved bool   `json:"resolved"`
}

type ManagedFwmarkRule struct {
	Generation      uint64 `json:"generation"`
	FwMark          uint32 `json:"fwmark"`
	UnderlayIfIndex int    `json:"underlay_ifindex"`
	ActionOnMiss    string `json:"action_on_miss"`
}

type EgressRule struct {
	Generation      uint64 `json:"generation"`
	Family          string `json:"family"`
	FwMark          uint32 `json:"fwmark"`
	SourcePort      uint16 `json:"source_port"`
	UnderlayIfIndex int    `json:"underlay_ifindex"`
	ProfileID       uint32 `json:"profile_id"`
	WGID            uint32 `json:"wg_id"`
	Action          string `json:"action"`
}

type IngressListener struct {
	Generation      uint64 `json:"generation"`
	Family          string `json:"family"`
	DestinationPort uint16 `json:"destination_port"`
	UnderlayIfIndex int    `json:"underlay_ifindex"`
	ProfileID       uint32 `json:"profile_id"`
	WGID            uint32 `json:"wg_id"`
	Action          string `json:"action"`
}

func (s *State) JSON() ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}

func BuildState(ctx context.Context, cfg *config.Config, rt runtime.Provider, resolver underlay.Resolver, loadWG WGConfigLoader, opts BuildOptions) (*State, error) {
	if loadWG == nil {
		loadWG = wgconfig.ParseFile
	}
	compiledProfiles, err := profile.CompileAll(cfg.Profiles)
	if err != nil {
		return nil, err
	}

	state := &State{Generation: 1}
	profileIDs := assignProfileIDs(compiledProfiles)
	for _, name := range sortedProfileNames(compiledProfiles) {
		compiled := compiledProfiles[name]
		state.Profiles = append(state.Profiles, ProfileState{
			ID:              profileIDs[name],
			Name:            name,
			StandardToMixed: compiled.StandardToMixed,
			MixedToStandard: compiled.MixedToStandard,
		})
	}

	underlayStates, err := buildUnderlayStates(ctx, cfg, resolver, opts)
	if err != nil {
		return nil, err
	}
	state.Underlays = underlayStates

	for i, wg := range cfg.WireGuards {
		wgID := uint32(i + 1)
		wgState, err := buildWireGuardState(ctx, cfg, wg, wgID, profileIDs[wg.Profile], rt, loadWG, opts)
		if err != nil {
			return nil, err
		}
		state.WireGuards = append(state.WireGuards, *wgState)
	}
	if !opts.Offline {
		state.buildRules(cfg)
		if err := state.validateRuleUniqueness(); err != nil {
			return nil, err
		}
	}
	return state, nil
}

func buildUnderlayStates(ctx context.Context, cfg *config.Config, resolver underlay.Resolver, opts BuildOptions) ([]UnderlayState, error) {
	out := make([]UnderlayState, 0, len(cfg.Underlays))
	seenIfIndex := make(map[int]string)
	for i, u := range cfg.Underlays {
		state := UnderlayState{
			ID:     uint32(i + 1),
			Name:   u.Name,
			Type:   u.Type,
			Parser: normalizeParser(u.Parser),
		}
		if !opts.Offline {
			resolved, err := resolver.Resolve(ctx, u)
			if err != nil {
				return nil, fmt.Errorf("resolve underlay %q: %w", u.Name, err)
			}
			state.IfName = resolved.IfName
			state.IfIndex = resolved.IfIndex
			state.LinkType = resolved.LinkType
			state.Role = resolved.Role
			state.Resolved = true
			if u.Parser == "" || u.Parser == "auto" {
				state.Parser = inferParser(resolved)
			}
			if state.IfIndex != 0 {
				if other, ok := seenIfIndex[state.IfIndex]; ok && cfg.UnderlayOverlapPolicy == "reject" {
					return nil, fmt.Errorf("underlay %q overlaps with %q on ifindex %d", u.Name, other, state.IfIndex)
				}
				seenIfIndex[state.IfIndex] = u.Name
			}
		}
		out = append(out, state)
	}
	return out, nil
}

func normalizeParser(parser string) string {
	if parser == "" {
		return "auto"
	}
	return parser
}

func inferParser(resolved *underlay.Resolved) string {
	switch resolved.LinkType {
	case "ppp", "tun", "ipip", "sit", "gre", "ip6gre", "xfrm":
		return "l3"
	case "ethernet", "device", "veth", "bridge", "vlan", "macvlan", "macvtap", "bond", "team", "dummy":
		return "ethernet"
	default:
		if resolved.IfName != "" && (hasPrefix(resolved.IfName, "ppp") || hasPrefix(resolved.IfName, "pppoe-")) {
			return "l3"
		}
		return "auto"
	}
}

func hasPrefix(value string, prefix string) bool {
	return len(value) >= len(prefix) && value[:len(prefix)] == prefix
}

func buildWireGuardState(ctx context.Context, cfg *config.Config, wg config.WireGuard, wgID uint32, profileID uint32, rt runtime.Provider, loadWG WGConfigLoader, opts BuildOptions) (*WireGuardState, error) {
	parsed, err := loadWG(wg.Config)
	if err != nil {
		return nil, fmt.Errorf("read wg config for %s: %w", wg.Name, err)
	}
	if parsed.FwMark == nil {
		if cfg.FwmarkPolicy.Mode == "config-required" {
			return nil, fmt.Errorf("wg %s config %s missing required FwMark", wg.Name, wg.Config)
		}
		return nil, fmt.Errorf("wg %s fwmark policy %q is unsupported in MVP", wg.Name, cfg.FwmarkPolicy.Mode)
	}
	if *parsed.FwMark == 0 && cfg.Runtime.RequireNonzeroFwmark {
		return nil, fmt.Errorf("wg %s config FwMark is zero/off", wg.Name)
	}

	state := &WireGuardState{
		ID:           wgID,
		Name:         wg.Name,
		ConfigPath:   wg.Config,
		Profile:      wg.Profile,
		ProfileID:    profileID,
		ConfigFwMark: *parsed.FwMark,
	}
	if parsed.ListenPort != nil {
		state.ConfigListenPort = *parsed.ListenPort
	}
	if opts.Offline {
		return state, nil
	}

	dev, err := rt.Device(ctx, wg.Name)
	if err != nil {
		return nil, fmt.Errorf("read runtime wg device %s: %w", wg.Name, err)
	}
	state.RuntimeStateAvailable = true
	state.RuntimeFirewallMark = dev.FirewallMark
	state.RuntimeListenPort = dev.ListenPort
	state.RuntimeIfIndex = dev.IfIndex
	if dev.FirewallMark == 0 && cfg.Runtime.RequireNonzeroFwmark {
		return nil, fmt.Errorf("wg %s runtime FirewallMark is zero/off", wg.Name)
	}
	if cfg.Runtime.StrictRuntimeFwmark && dev.FirewallMark != *parsed.FwMark {
		return nil, fmt.Errorf("wg %s config FwMark 0x%08x does not match runtime FirewallMark 0x%08x", wg.Name, *parsed.FwMark, dev.FirewallMark)
	}
	if dev.ListenPort == 0 {
		return nil, fmt.Errorf("wg %s runtime ListenPort is zero", wg.Name)
	}
	return state, nil
}

func (s *State) buildRules(cfg *config.Config) {
	for _, wg := range s.WireGuards {
		if !wg.RuntimeStateAvailable {
			continue
		}
		for _, u := range s.Underlays {
			if !u.Resolved || u.Role == "parse_only" || u.Role == "disabled" {
				continue
			}
			s.ManagedFwmarks = append(s.ManagedFwmarks, ManagedFwmarkRule{
				Generation:      s.Generation,
				FwMark:          wg.RuntimeFirewallMark,
				UnderlayIfIndex: u.IfIndex,
				ActionOnMiss:    cfg.Policy.ManagedEgressMapMiss,
			})
			for _, family := range []string{"ipv4", "ipv6"} {
				s.EgressRules = append(s.EgressRules, EgressRule{
					Generation:      s.Generation,
					Family:          family,
					FwMark:          wg.RuntimeFirewallMark,
					SourcePort:      wg.RuntimeListenPort,
					UnderlayIfIndex: u.IfIndex,
					ProfileID:       wg.ProfileID,
					WGID:            wg.ID,
					Action:          "rewrite",
				})
				s.IngressListeners = append(s.IngressListeners, IngressListener{
					Generation:      s.Generation,
					Family:          family,
					DestinationPort: wg.RuntimeListenPort,
					UnderlayIfIndex: u.IfIndex,
					ProfileID:       wg.ProfileID,
					WGID:            wg.ID,
					Action:          "rewrite",
				})
			}
		}
	}
}

func (s *State) validateRuleUniqueness() error {
	type egressKey struct {
		family     string
		fwmark     uint32
		sourcePort uint16
		underlay   int
	}
	egressSeen := make(map[egressKey]EgressRule, len(s.EgressRules))
	for _, r := range s.EgressRules {
		key := egressKey{family: r.Family, fwmark: r.FwMark, sourcePort: r.SourcePort, underlay: r.UnderlayIfIndex}
		if existing, ok := egressSeen[key]; ok {
			return fmt.Errorf("duplicate egress rule for family=%s fwmark=0x%08x source_port=%d underlay_ifindex=%d between wg_id=%d and wg_id=%d", r.Family, r.FwMark, r.SourcePort, r.UnderlayIfIndex, existing.WGID, r.WGID)
		}
		egressSeen[key] = r
	}

	type ingressKey struct {
		family   string
		port     uint16
		underlay int
	}
	ingressSeen := make(map[ingressKey]IngressListener, len(s.IngressListeners))
	for _, r := range s.IngressListeners {
		key := ingressKey{family: r.Family, port: r.DestinationPort, underlay: r.UnderlayIfIndex}
		if existing, ok := ingressSeen[key]; ok {
			return fmt.Errorf("duplicate ingress listener for family=%s destination_port=%d underlay_ifindex=%d between wg_id=%d and wg_id=%d", r.Family, r.DestinationPort, r.UnderlayIfIndex, existing.WGID, r.WGID)
		}
		ingressSeen[key] = r
	}

	type fwmarkKey struct {
		fwmark   uint32
		underlay int
	}
	managedSeen := make(map[fwmarkKey]ManagedFwmarkRule, len(s.ManagedFwmarks))
	for _, r := range s.ManagedFwmarks {
		key := fwmarkKey{fwmark: r.FwMark, underlay: r.UnderlayIfIndex}
		if existing, ok := managedSeen[key]; ok && existing.ActionOnMiss != r.ActionOnMiss {
			return fmt.Errorf("conflicting managed fwmark rule for fwmark=0x%08x underlay_ifindex=%d", r.FwMark, r.UnderlayIfIndex)
		}
		managedSeen[key] = r
	}
	return nil
}

func assignProfileIDs(profiles map[string]profile.Compiled) map[string]uint32 {
	names := sortedProfileNames(profiles)
	ids := make(map[string]uint32, len(names))
	for i, name := range names {
		ids[name] = uint32(i + 1)
	}
	return ids
}

func sortedProfileNames(profiles map[string]profile.Compiled) []string {
	names := make([]string, 0, len(profiles))
	for name := range profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func IsUnsupportedRuntime(err error) bool {
	return errors.Is(err, runtime.ErrUnsupported) || errors.Is(err, underlay.ErrUnsupported)
}
