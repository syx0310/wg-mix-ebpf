package control

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/syx0310/wg-mix-ebpf/internal/config"
	"github.com/syx0310/wg-mix-ebpf/internal/profile"
	"github.com/syx0310/wg-mix-ebpf/internal/runtime"
	"github.com/syx0310/wg-mix-ebpf/internal/underlay"
	"github.com/syx0310/wg-mix-ebpf/internal/wgconfig"
	"golang.org/x/crypto/hkdf"
)

type BuildOptions struct {
	Offline bool
}

type WGConfigLoader func(path string) (*wgconfig.Interface, error)

type State struct {
	Generation       uint64              `json:"generation"`
	Profiles         []ProfileState      `json:"profiles"`
	Ciphers          []CipherState       `json:"ciphers,omitempty"`
	WireGuards       []WireGuardState    `json:"wireguards"`
	Underlays        []UnderlayState     `json:"underlays"`
	ManagedFwmarks   []ManagedFwmarkRule `json:"managed_fwmarks"`
	EgressRules      []EgressRule        `json:"egress_rules"`
	IngressListeners []IngressListener   `json:"ingress_listeners"`
	ICMPListeners    []ICMPListener      `json:"icmp_listeners,omitempty"`
	Warnings         []string            `json:"warnings,omitempty"`
}

type ProfileState struct {
	ID              uint32    `json:"id"`
	Name            string    `json:"name"`
	StandardToMixed [4]uint32 `json:"standard_to_mixed"`
	MixedToStandard [4]uint32 `json:"mixed_to_standard"`
}

type CipherState struct {
	ID            uint32    `json:"id"`
	Name          string    `json:"name"`
	Mode          string    `json:"mode"`
	Auth          string    `json:"auth"`
	Scope         string    `json:"scope"`
	KeyDerivation string    `json:"key_derivation"`
	KeyLen        uint32    `json:"key_len"`
	KeyMask       uint32    `json:"key_mask"`
	MaxBytes      uint32    `json:"max_bytes"`
	Flags         uint32    `json:"flags"`
	Key           [256]byte `json:"-"`
}

type WireGuardState struct {
	ID                              uint32 `json:"id"`
	Name                            string `json:"name"`
	ConfigPath                      string `json:"config_path"`
	Profile                         string `json:"profile"`
	ProfileID                       uint32 `json:"profile_id"`
	Cipher                          string `json:"cipher,omitempty"`
	CipherID                        uint32 `json:"cipher_id,omitempty"`
	ConfigFwMark                    uint32 `json:"config_fwmark"`
	ConfigListenPort                uint16 `json:"config_listen_port,omitempty"`
	RuntimeFirewallMark             uint32 `json:"runtime_firewall_mark,omitempty"`
	RuntimeListenPort               uint16 `json:"runtime_listen_port,omitempty"`
	RuntimeIfIndex                  int    `json:"runtime_ifindex,omitempty"`
	RuntimeStateAvailable           bool   `json:"runtime_state_available"`
	TransportMode                   string `json:"transport_mode"`
	ICMPRole                        string `json:"icmp_role,omitempty"`
	ICMPID                          uint16 `json:"icmp_id,omitempty"`
	FakeTCPExperimental             bool   `json:"faketcp_experimental,omitempty"`
	FakeTCPChecksumMode             string `json:"faketcp_checksum_mode,omitempty"`
	FakeTCPIngressMode              string `json:"faketcp_ingress_mode,omitempty"`
	FakeTCPSessionCapacity          uint32 `json:"faketcp_session_capacity,omitempty"`
	FakeTCPMaxPendingFlows          uint32 `json:"faketcp_max_pending_flows,omitempty"`
	FakeTCPMaxPendingPacketsPerFlow uint32 `json:"faketcp_max_pending_packets_per_flow,omitempty"`
	FakeTCPMaxPendingBytes          uint32 `json:"faketcp_max_pending_bytes,omitempty"`
	FakeTCPHandshakeTimeoutNanos    int64  `json:"faketcp_handshake_timeout_nanos,omitempty"`
	FakeTCPKeepaliveIntervalNanos   int64  `json:"faketcp_keepalive_interval_nanos,omitempty"`
	FakeTCPIdleTimeoutNanos         int64  `json:"faketcp_idle_timeout_nanos,omitempty"`
}

type FwmarkMismatchError struct {
	WireGuard    string
	ConfigFwMark uint32
	RuntimeMark  uint32
}

func (e *FwmarkMismatchError) Error() string {
	return fmt.Sprintf(
		"wg %s config FwMark 0x%08x does not match runtime FirewallMark 0x%08x",
		e.WireGuard,
		e.ConfigFwMark,
		e.RuntimeMark,
	)
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
	CipherID        uint32 `json:"cipher_id,omitempty"`
	WGID            uint32 `json:"wg_id"`
	Action          string `json:"action"`
	TransportMode   string `json:"transport_mode,omitempty"`
	ICMPRole        string `json:"icmp_role,omitempty"`
	ICMPID          uint16 `json:"icmp_id,omitempty"`
}

type IngressListener struct {
	Generation      uint64 `json:"generation"`
	Family          string `json:"family"`
	DestinationPort uint16 `json:"destination_port"`
	UnderlayIfIndex int    `json:"underlay_ifindex"`
	ProfileID       uint32 `json:"profile_id"`
	CipherID        uint32 `json:"cipher_id,omitempty"`
	WGID            uint32 `json:"wg_id"`
	Action          string `json:"action"`
	TransportMode   string `json:"transport_mode,omitempty"`
}

type ICMPListener struct {
	Generation      uint64 `json:"generation"`
	Family          string `json:"family"`
	UnderlayIfIndex int    `json:"underlay_ifindex"`
	ICMPType        uint8  `json:"icmp_type"`
	ICMPID          uint16 `json:"icmp_id"`
	ListenPort      uint16 `json:"listen_port"`
	ProfileID       uint32 `json:"profile_id"`
	WGID            uint32 `json:"wg_id"`
	Action          string `json:"action"`
	Role            string `json:"role"`
	Flags           uint32 `json:"flags,omitempty"`
}

const (
	ICMPListenerFlagWildcardID uint32 = 1 << 0
	CipherFlagPrefix           uint32 = 1 << 0
)

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
	compiledCiphers, err := compileCiphers(cfg.Ciphers)
	if err != nil {
		return nil, err
	}
	cipherIDs := assignCipherIDs(compiledCiphers)
	for _, name := range sortedCipherNames(compiledCiphers) {
		compiled := compiledCiphers[name]
		compiled.ID = cipherIDs[name]
		state.Ciphers = append(state.Ciphers, compiled)
	}

	underlayStates, err := buildUnderlayStates(ctx, cfg, resolver, opts)
	if err != nil {
		return nil, err
	}
	state.Underlays = underlayStates

	for i, wg := range cfg.WireGuards {
		wgID := uint32(i + 1)
		wgState, err := buildWireGuardState(ctx, cfg, wg, wgID, profileIDs[wg.Profile], cipherIDs[wg.Cipher], rt, loadWG, opts)
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

func buildWireGuardState(ctx context.Context, cfg *config.Config, wg config.WireGuard, wgID uint32, profileID uint32, cipherID uint32, rt runtime.Provider, loadWG WGConfigLoader, opts BuildOptions) (*WireGuardState, error) {
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
	if *parsed.FwMark == 0 {
		return nil, fmt.Errorf("wg %s config FwMark is zero/off", wg.Name)
	}

	state := &WireGuardState{
		ID:                              wgID,
		Name:                            wg.Name,
		ConfigPath:                      wg.Config,
		Profile:                         wg.Profile,
		ProfileID:                       profileID,
		Cipher:                          wg.Cipher,
		CipherID:                        cipherID,
		ConfigFwMark:                    *parsed.FwMark,
		TransportMode:                   wg.Transport.Mode,
		ICMPRole:                        wg.Transport.ICMP.Role,
		ICMPID:                          wg.Transport.ICMP.ID,
		FakeTCPExperimental:             wg.Transport.FakeTCP.Experimental,
		FakeTCPChecksumMode:             wg.Transport.FakeTCP.ChecksumMode,
		FakeTCPIngressMode:              wg.Transport.FakeTCP.IngressMode,
		FakeTCPSessionCapacity:          wg.Transport.FakeTCP.SessionCapacity,
		FakeTCPMaxPendingFlows:          wg.Transport.FakeTCP.MaxPendingFlows,
		FakeTCPMaxPendingPacketsPerFlow: wg.Transport.FakeTCP.MaxPendingPacketsPerFlow,
		FakeTCPMaxPendingBytes:          wg.Transport.FakeTCP.MaxPendingBytes,
		FakeTCPHandshakeTimeoutNanos:    wg.Transport.FakeTCP.HandshakeTimeout.Duration.Nanoseconds(),
		FakeTCPKeepaliveIntervalNanos:   wg.Transport.FakeTCP.KeepaliveInterval.Duration.Nanoseconds(),
		FakeTCPIdleTimeoutNanos:         wg.Transport.FakeTCP.IdleTimeout.Duration.Nanoseconds(),
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
	if dev.FirewallMark == 0 {
		return nil, fmt.Errorf("wg %s runtime FirewallMark is zero/off", wg.Name)
	}
	if cfg.Runtime.StrictRuntimeFwmark && dev.FirewallMark != *parsed.FwMark {
		return nil, &FwmarkMismatchError{
			WireGuard:    wg.Name,
			ConfigFwMark: *parsed.FwMark,
			RuntimeMark:  dev.FirewallMark,
		}
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
			families := []string{"ipv4", "ipv6"}
			if wg.TransportMode == "faketcp" {
				// The first FakeTCP slice is deliberately IPv4-only. Managed
				// IPv6 WireGuard packets still hit the fwmark miss policy and
				// fail closed instead of leaking as UDP.
				families = []string{"ipv4"}
			}
			for _, family := range families {
				if wg.TransportMode == "icmp" {
					s.IngressListeners = append(s.IngressListeners, IngressListener{
						Generation:      s.Generation,
						Family:          family,
						DestinationPort: wg.RuntimeListenPort,
						UnderlayIfIndex: u.IfIndex,
						ProfileID:       wg.ProfileID,
						CipherID:        wg.CipherID,
						WGID:            wg.ID,
						Action:          "drop",
						TransportMode:   wg.TransportMode,
					})
					if family == "ipv6" {
						continue
					}
					s.EgressRules = append(s.EgressRules, EgressRule{
						Generation:      s.Generation,
						Family:          family,
						FwMark:          wg.RuntimeFirewallMark,
						SourcePort:      wg.RuntimeListenPort,
						UnderlayIfIndex: u.IfIndex,
						ProfileID:       wg.ProfileID,
						CipherID:        wg.CipherID,
						WGID:            wg.ID,
						Action:          "rewrite",
						TransportMode:   wg.TransportMode,
						ICMPRole:        wg.ICMPRole,
						ICMPID:          wg.ICMPID,
					})
					icmpType := uint8(8)
					icmpID := wg.ICMPID
					icmpFlags := uint32(0)
					if wg.ICMPRole == "client" {
						icmpType = 0
					}
					if wg.ICMPRole == "server" {
						icmpID = 0
						icmpFlags = ICMPListenerFlagWildcardID
					}
					s.ICMPListeners = append(s.ICMPListeners, ICMPListener{
						Generation:      s.Generation,
						Family:          family,
						UnderlayIfIndex: u.IfIndex,
						ICMPType:        icmpType,
						ICMPID:          icmpID,
						ListenPort:      wg.RuntimeListenPort,
						ProfileID:       wg.ProfileID,
						WGID:            wg.ID,
						Action:          "rewrite",
						Role:            wg.ICMPRole,
						Flags:           icmpFlags,
					})
					continue
				}
				s.EgressRules = append(s.EgressRules, EgressRule{
					Generation:      s.Generation,
					Family:          family,
					FwMark:          wg.RuntimeFirewallMark,
					SourcePort:      wg.RuntimeListenPort,
					UnderlayIfIndex: u.IfIndex,
					ProfileID:       wg.ProfileID,
					CipherID:        wg.CipherID,
					WGID:            wg.ID,
					Action:          "rewrite",
					TransportMode:   wg.TransportMode,
					ICMPRole:        wg.ICMPRole,
					ICMPID:          wg.ICMPID,
				})
				s.IngressListeners = append(s.IngressListeners, IngressListener{
					Generation:      s.Generation,
					Family:          family,
					DestinationPort: wg.RuntimeListenPort,
					UnderlayIfIndex: u.IfIndex,
					ProfileID:       wg.ProfileID,
					CipherID:        wg.CipherID,
					WGID:            wg.ID,
					Action:          "rewrite",
					TransportMode:   wg.TransportMode,
				})
			}
		}
	}
}

func compileCiphers(ciphers map[string]config.Cipher) (map[string]CipherState, error) {
	out := make(map[string]CipherState, len(ciphers))
	for name, cipher := range ciphers {
		key, err := deriveCipherKey(name, cipher)
		if err != nil {
			return nil, err
		}
		flags := uint32(0)
		if cipher.Scope == "wg-payload-prefix" {
			flags |= CipherFlagPrefix
		}
		out[name] = CipherState{
			Name:          name,
			Mode:          cipher.Mode,
			Auth:          cipher.Auth,
			Scope:         cipher.Scope,
			KeyDerivation: cipher.KeyDerivation,
			KeyLen:        cipher.KeyLen,
			KeyMask:       cipher.KeyLen - 1,
			MaxBytes:      cipher.MaxBytes,
			Flags:         flags,
			Key:           key,
		}
	}
	return out, nil
}

func deriveCipherKey(name string, cipher config.Cipher) ([256]byte, error) {
	var out [256]byte
	switch cipher.KeyLen {
	case 16, 32, 64, 256:
	default:
		return out, fmt.Errorf("derive cipher %q: unsupported key_len %d", name,
			cipher.KeyLen)
	}
	secret, err := cipherSecretBytes(cipher)
	if err != nil {
		return out, fmt.Errorf("derive cipher %q: %w", name, err)
	}
	switch cipher.KeyDerivation {
	case "wgmx-hkdf256-v1":
		reader := hkdf.New(sha256.New, secret, nil, []byte("wg-mix-ebpf xor symmetric v1"))
		if _, err := io.ReadFull(reader, out[:cipher.KeyLen]); err != nil {
			return out, err
		}
	case "udp2raw-md5-key1":
		sum := md5.Sum(append(secret, []byte("key1")...))
		for i := uint32(0); i < cipher.KeyLen; i++ {
			out[i] = sum[i%uint32(len(sum))]
		}
	default:
		return out, fmt.Errorf("unsupported key_derivation %q", cipher.KeyDerivation)
	}
	for i := cipher.KeyLen; i < uint32(len(out)); i++ {
		out[i] = out[i%cipher.KeyLen]
	}
	return out, nil
}

func cipherSecretBytes(cipher config.Cipher) ([]byte, error) {
	var secret []byte
	var err error
	switch {
	case cipher.SecretFile != "":
		secret, err = os.ReadFile(cipher.SecretFile)
		if err != nil {
			return nil, err
		}
		secret = []byte(strings.TrimSpace(string(secret)))
	case cipher.Secret != "":
		if strings.HasPrefix(cipher.Secret, "base64:") {
			secret, err = base64.StdEncoding.DecodeString(strings.TrimPrefix(cipher.Secret, "base64:"))
			if err != nil {
				return nil, err
			}
		} else {
			secret = []byte(cipher.Secret)
		}
	case cipher.Password != "":
		secret = []byte(cipher.Password)
	default:
		return nil, errors.New("missing secret material")
	}
	if len(secret) == 0 {
		return nil, errors.New("secret material is empty")
	}
	return secret, nil
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

	type icmpKey struct {
		family   string
		underlay int
		icmpType uint8
		icmpID   uint16
	}
	icmpSeen := make(map[icmpKey]ICMPListener, len(s.ICMPListeners))
	for _, r := range s.ICMPListeners {
		key := icmpKey{family: r.Family, underlay: r.UnderlayIfIndex, icmpType: r.ICMPType, icmpID: r.ICMPID}
		if existing, ok := icmpSeen[key]; ok {
			return fmt.Errorf("duplicate icmp listener for family=%s type=%d id=%d underlay_ifindex=%d between wg_id=%d and wg_id=%d", r.Family, r.ICMPType, r.ICMPID, r.UnderlayIfIndex, existing.WGID, r.WGID)
		}
		icmpSeen[key] = r
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

func assignCipherIDs(ciphers map[string]CipherState) map[string]uint32 {
	names := sortedCipherNames(ciphers)
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

func sortedCipherNames(ciphers map[string]CipherState) []string {
	names := make([]string, 0, len(ciphers))
	for name := range ciphers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func IsUnsupportedRuntime(err error) bool {
	return errors.Is(err, runtime.ErrUnsupported) || errors.Is(err, underlay.ErrUnsupported)
}
