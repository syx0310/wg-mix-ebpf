package config

import (
	"errors"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	DefaultConfigPath = "/etc/wg-mix-ebpf/config.yaml"
	DefaultWGDir      = "/etc/wireguard"
)

type Config struct {
	Version               int                `yaml:"version"`
	Mode                  string             `yaml:"mode"`
	Underlays             []Underlay         `yaml:"underlays"`
	WireGuards            []WireGuard        `yaml:"wireguards"`
	Profiles              map[string]Profile `yaml:"profiles"`
	FwmarkPolicy          FwmarkPolicy       `yaml:"fwmark_policy"`
	Runtime               Runtime            `yaml:"runtime"`
	StartupGuard          StartupGuard       `yaml:"startup_guard"`
	UnderlayOverlapPolicy string             `yaml:"underlay_overlap_policy"`
	Policy                Policy             `yaml:"policy"`
}

type Underlay struct {
	Name   string `yaml:"name"`
	Type   string `yaml:"type"`
	Parser string `yaml:"parser"`
}

type WireGuard struct {
	Name    string `yaml:"name"`
	Config  string `yaml:"config"`
	Profile string `yaml:"profile"`
	NetNS   string `yaml:"netns"`
}

type Profile struct {
	Preset           string          `yaml:"preset"`
	TypeWord         TypeWordProfile `yaml:"type_word"`
	Index            IndexProfile    `yaml:"index"`
	AllowPassthrough bool            `yaml:"allow_passthrough"`
}

type TypeWordProfile struct {
	Initiation    uint32 `yaml:"initiation"`
	Response      uint32 `yaml:"response"`
	CookieReply   uint32 `yaml:"cookie_reply"`
	TransportData uint32 `yaml:"transport_data"`
}

type IndexProfile struct {
	Mode string `yaml:"mode"`
}

type FwmarkPolicy struct {
	Mode string `yaml:"mode"`
}

type Runtime struct {
	PollInterval            Duration `yaml:"poll_interval"`
	RequireNonzeroFwmark    bool     `yaml:"require_nonzero_fwmark"`
	StrictRuntimeFwmark     bool     `yaml:"strict_runtime_fwmark"`
	AllowZeroFwmarkFallback bool     `yaml:"allow_zero_fwmark_fallback"`

	requireNonzeroFwmarkSet bool
	strictRuntimeFwmarkSet  bool
}

func (r *Runtime) UnmarshalYAML(value *yaml.Node) error {
	type runtime Runtime
	var out runtime
	if err := value.Decode(&out); err != nil {
		return err
	}
	for i := 0; i+1 < len(value.Content); i += 2 {
		switch value.Content[i].Value {
		case "require_nonzero_fwmark":
			out.requireNonzeroFwmarkSet = true
		case "strict_runtime_fwmark":
			out.strictRuntimeFwmarkSet = true
		}
	}
	*r = Runtime(out)
	return nil
}

type StartupGuard struct {
	Mode    string       `yaml:"mode"`
	Egress  GuardEgress  `yaml:"egress"`
	Ingress GuardIngress `yaml:"ingress"`
}

type GuardEgress struct {
	Match string `yaml:"match"`
}

type GuardIngress struct {
	Match                    string `yaml:"match"`
	RandomListenPortBehavior string `yaml:"random_listen_port_behavior"`
}

type Policy struct {
	NonManagedUDP               string               `yaml:"non_managed_udp"`
	ManagedEgressMapMiss        string               `yaml:"managed_egress_map_miss"`
	ManagedEgressBadType        string               `yaml:"managed_egress_bad_type"`
	ManagedEgressBadLength      string               `yaml:"managed_egress_bad_length"`
	EgressManagedIPv6ExtHeader  string               `yaml:"egress_managed_ipv6_ext_header"`
	ManagedIngressMapMiss       string               `yaml:"managed_ingress_map_miss"`
	ManagedIngressBadType       string               `yaml:"managed_ingress_bad_type"`
	ManagedIngressBadLength     string               `yaml:"managed_ingress_bad_length"`
	IngressManagedIPv6ExtHeader string               `yaml:"ingress_managed_ipv6_ext_header"`
	IPv4FirstFragment           string               `yaml:"ipv4_first_fragment"`
	IPv4NonFirstFragment        IPv4NonFirstFragment `yaml:"ipv4_non_first_fragment"`
	IPv6Fragment                string               `yaml:"ipv6_fragment"`
	StartupFailMode             string               `yaml:"startup_fail_mode"`
}

type IPv4NonFirstFragment struct {
	Ingress                   string `yaml:"ingress"`
	EgressIfManagedFwmark     string `yaml:"egress_if_managed_fwmark"`
	OptionalDropAllOnUnderlay bool   `yaml:"optional_drop_all_on_underlay"`
}

type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var raw string
	if err := value.Decode(&raw); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil {
		return fmt.Errorf("parse duration %q: %w", raw, err)
	}
	d.Duration = parsed
	return nil
}

func (d Duration) MarshalYAML() (any, error) {
	return d.Duration.String(), nil
}

func LoadFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := Load(data)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

func Load(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	cfg.ApplyDefaults()
	if err := cfg.ValidateStatic(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) ApplyDefaults() {
	if c.Version == 0 {
		c.Version = 1
	}
	if c.Mode == "" {
		c.Mode = "transparent-typeword"
	}
	if c.FwmarkPolicy.Mode == "" {
		c.FwmarkPolicy.Mode = "config-required"
	}
	if c.Runtime.PollInterval.Duration == 0 {
		c.Runtime.PollInterval.Duration = 5 * time.Second
	}
	if !c.Runtime.AllowZeroFwmarkFallback && !c.Runtime.requireNonzeroFwmarkSet {
		c.Runtime.RequireNonzeroFwmark = true
	}
	if !c.Runtime.strictRuntimeFwmarkSet {
		c.Runtime.StrictRuntimeFwmark = true
	}
	if c.StartupGuard.Mode == "" {
		c.StartupGuard.Mode = "nft-temporary-drop"
	}
	if c.StartupGuard.Egress.Match == "" {
		c.StartupGuard.Egress.Match = "fwmark"
	}
	if c.StartupGuard.Ingress.Match == "" {
		c.StartupGuard.Ingress.Match = "config-listen-port-if-present"
	}
	if c.StartupGuard.Ingress.RandomListenPortBehavior == "" {
		c.StartupGuard.Ingress.RandomListenPortBehavior = "best-effort"
	}
	if c.UnderlayOverlapPolicy == "" {
		c.UnderlayOverlapPolicy = "reject"
	}
	c.Policy.applyDefaults()
	for i := range c.WireGuards {
		if c.WireGuards[i].Config == "" && c.WireGuards[i].Name != "" {
			c.WireGuards[i].Config = DefaultWGDir + "/" + c.WireGuards[i].Name + ".conf"
		}
		if c.WireGuards[i].NetNS == "" {
			c.WireGuards[i].NetNS = "root"
		}
	}
}

func (p *Policy) applyDefaults() {
	defaultString(&p.NonManagedUDP, "pass")
	defaultString(&p.ManagedEgressMapMiss, "drop")
	defaultString(&p.ManagedEgressBadType, "drop")
	defaultString(&p.ManagedEgressBadLength, "drop")
	defaultString(&p.EgressManagedIPv6ExtHeader, "drop")
	defaultString(&p.ManagedIngressMapMiss, "pass")
	defaultString(&p.ManagedIngressBadType, "drop")
	defaultString(&p.ManagedIngressBadLength, "drop")
	defaultString(&p.IngressManagedIPv6ExtHeader, "drop")
	defaultString(&p.IPv4FirstFragment, "drop")
	defaultString(&p.IPv4NonFirstFragment.Ingress, "pass")
	defaultString(&p.IPv4NonFirstFragment.EgressIfManagedFwmark, "drop")
	defaultString(&p.IPv6Fragment, "drop")
	defaultString(&p.StartupFailMode, "fail_closed_for_managed_flows")
}

func defaultString(s *string, value string) {
	if *s == "" {
		*s = value
	}
}

func (c *Config) ValidateStatic() error {
	if c.Version != 1 {
		return fmt.Errorf("unsupported config version %d", c.Version)
	}
	if c.Mode != "transparent-typeword" {
		return fmt.Errorf("unsupported mode %q", c.Mode)
	}
	if len(c.Underlays) == 0 {
		return errors.New("at least one underlay is required")
	}
	if len(c.WireGuards) == 0 {
		return errors.New("at least one wireguard interface is required")
	}
	if len(c.Profiles) == 0 {
		return errors.New("at least one profile is required")
	}
	switch c.FwmarkPolicy.Mode {
	case "config-required":
	case "runtime-accepted", "openwrt-uci":
		return fmt.Errorf("fwmark_policy.mode %q is reserved but not implemented in MVP", c.FwmarkPolicy.Mode)
	default:
		return fmt.Errorf("fwmark_policy.mode %q is unsupported", c.FwmarkPolicy.Mode)
	}
	if c.Runtime.AllowZeroFwmarkFallback {
		return errors.New("runtime.allow_zero_fwmark_fallback is reserved but not implemented in MVP")
	}
	if err := validateUniqueUnderlays(c.Underlays); err != nil {
		return err
	}
	if err := validatePolicy(c.Policy); err != nil {
		return err
	}
	switch c.StartupGuard.Mode {
	case "nft-temporary-drop", "none":
	default:
		return fmt.Errorf("startup_guard.mode %q is unsupported", c.StartupGuard.Mode)
	}
	for i, wg := range c.WireGuards {
		if wg.Name == "" {
			return fmt.Errorf("wireguards[%d].name is required", i)
		}
		if wg.Profile == "" {
			return fmt.Errorf("wireguards[%d].profile is required", i)
		}
		if _, ok := c.Profiles[wg.Profile]; !ok {
			return fmt.Errorf("wireguards[%d].profile %q is not defined", i, wg.Profile)
		}
	}
	return nil
}

func validateUniqueUnderlays(underlays []Underlay) error {
	seen := make(map[string]struct{}, len(underlays))
	for i, u := range underlays {
		if u.Name == "" {
			return fmt.Errorf("underlays[%d].name is required", i)
		}
		if u.Type == "" {
			return fmt.Errorf("underlays[%d].type is required", i)
		}
		switch u.Type {
		case "netdev", "openwrt-interface":
		default:
			return fmt.Errorf("underlays[%d].type %q is unsupported", i, u.Type)
		}
		switch u.Parser {
		case "", "auto", "ethernet", "l3":
		default:
			return fmt.Errorf("underlays[%d].parser %q is unsupported", i, u.Parser)
		}
		if _, exists := seen[u.Name]; exists {
			return fmt.Errorf("duplicate underlay %q", u.Name)
		}
		seen[u.Name] = struct{}{}
	}
	return nil
}

func validatePolicy(p Policy) error {
	checks := []struct {
		name  string
		value string
		allow map[string]struct{}
	}{
		{"policy.non_managed_udp", p.NonManagedUDP, set("pass")},
		{"policy.managed_egress_map_miss", p.ManagedEgressMapMiss, set("pass", "drop")},
		{"policy.managed_egress_bad_type", p.ManagedEgressBadType, set("drop")},
		{"policy.managed_egress_bad_length", p.ManagedEgressBadLength, set("drop")},
		{"policy.egress_managed_ipv6_ext_header", p.EgressManagedIPv6ExtHeader, set("drop")},
		{"policy.managed_ingress_map_miss", p.ManagedIngressMapMiss, set("pass")},
		{"policy.managed_ingress_bad_type", p.ManagedIngressBadType, set("drop")},
		{"policy.managed_ingress_bad_length", p.ManagedIngressBadLength, set("drop")},
		{"policy.ingress_managed_ipv6_ext_header", p.IngressManagedIPv6ExtHeader, set("drop")},
		{"policy.ipv4_first_fragment", p.IPv4FirstFragment, set("drop")},
		{"policy.ipv4_non_first_fragment.ingress", p.IPv4NonFirstFragment.Ingress, set("pass")},
		{"policy.ipv4_non_first_fragment.egress_if_managed_fwmark", p.IPv4NonFirstFragment.EgressIfManagedFwmark, set("drop")},
		{"policy.ipv6_fragment", p.IPv6Fragment, set("drop")},
		{"policy.startup_fail_mode", p.StartupFailMode, set("fail_closed_for_managed_flows", "best_effort")},
	}
	for _, check := range checks {
		if _, ok := check.allow[check.value]; !ok {
			return fmt.Errorf("%s=%q is not implemented by the MVP dataplane", check.name, check.value)
		}
	}
	if p.IPv4NonFirstFragment.OptionalDropAllOnUnderlay {
		return errors.New("policy.ipv4_non_first_fragment.optional_drop_all_on_underlay is not implemented by the MVP dataplane")
	}
	return nil
}

func set(values ...string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		out[value] = struct{}{}
	}
	return out
}
