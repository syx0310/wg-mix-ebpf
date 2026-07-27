package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	DefaultConfigPath   = "/etc/wg-mix-ebpf/config.yaml"
	DefaultWGDir        = "/etc/wireguard"
	MinimumPollInterval = 100 * time.Millisecond

	// Reload stages a second generation before deleting the active one. These
	// limits are therefore half of the corresponding BPF map capacities.
	MaxProfilesPerGeneration         = 64
	MaxCiphersPerGeneration          = 64
	MaxUnderlaysPerGeneration        = 256
	MaxManagedRulesPerGeneration     = 256
	MaxDirectionalRulesPerGeneration = 1024
)

type Config struct {
	Version               int                `yaml:"version"`
	Mode                  string             `yaml:"mode"`
	Underlays             []Underlay         `yaml:"underlays"`
	WireGuards            []WireGuard        `yaml:"wireguards"`
	Profiles              map[string]Profile `yaml:"profiles"`
	Ciphers               map[string]Cipher  `yaml:"ciphers"`
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
	Name      string    `yaml:"name"`
	Config    string    `yaml:"config"`
	Profile   string    `yaml:"profile"`
	Cipher    string    `yaml:"cipher"`
	NetNS     string    `yaml:"netns"`
	Transport Transport `yaml:"transport"`
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

type Transport struct {
	Mode string        `yaml:"mode"`
	ICMP ICMPTransport `yaml:"icmp"`
}

type ICMPTransport struct {
	Role string `yaml:"role"`
	ID   uint16 `yaml:"id"`
}

type Cipher struct {
	Mode          string `yaml:"mode"`
	Auth          string `yaml:"auth"`
	Scope         string `yaml:"scope"`
	KeyDerivation string `yaml:"key_derivation"`
	Secret        string `yaml:"secret"`
	SecretFile    string `yaml:"secret_file"`
	Password      string `yaml:"password"`
	KeyLen        uint32 `yaml:"key_len"`
	MaxBytes      uint32 `yaml:"max_bytes"`
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
		case "poll_interval", "allow_zero_fwmark_fallback":
		default:
			return fmt.Errorf("field %q not found in type config.Runtime", value.Content[i].Value)
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

func LoadFileLenient(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return LoadLenient(data)
}

func Load(data []byte) (*Config, error) {
	cfg, err := decode(data)
	if err != nil {
		return nil, err
	}
	cfg.ApplyDefaults()
	if err := cfg.ValidateStatic(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func LoadLenient(data []byte) (*Config, error) {
	cfg, err := decode(data)
	if err != nil {
		return nil, err
	}
	cfg.ApplyDefaults()
	return cfg, nil
}

func decode(data []byte) (*Config, error) {
	var cfg Config
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("config must contain exactly one YAML document")
		}
		return nil, err
	}
	return &cfg, nil
}

func SaveFile(path string, cfg *Config) error {
	cfg.ApplyDefaults()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return fmt.Errorf("create temporary config: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("set temporary config permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temporary config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temporary config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary config: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace config %s: %w", path, err)
	}
	return nil
}

func SafeTemplate() *Config {
	cfg := &Config{
		Version: 1,
		Mode:    "transparent-typeword",
		Profiles: map[string]Profile{
			"default": {
				Preset: "wireguard-mix-wire-values-v1",
				Index:  IndexProfile{Mode: "none"},
			},
		},
		FwmarkPolicy: FwmarkPolicy{Mode: "config-required"},
		Runtime: Runtime{
			PollInterval:            Duration{Duration: 5 * time.Second},
			RequireNonzeroFwmark:    true,
			StrictRuntimeFwmark:     true,
			AllowZeroFwmarkFallback: false,
			requireNonzeroFwmarkSet: true,
			strictRuntimeFwmarkSet:  true,
		},
		StartupGuard: StartupGuard{
			Mode: "nft-temporary-drop",
			Egress: GuardEgress{
				Match: "fwmark",
			},
			Ingress: GuardIngress{
				Match:                    "config-listen-port-if-present",
				RandomListenPortBehavior: "best-effort",
			},
		},
		UnderlayOverlapPolicy: "reject",
	}
	cfg.Policy.applyDefaults()
	return cfg
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
		if c.WireGuards[i].Transport.Mode == "" {
			c.WireGuards[i].Transport.Mode = "udp"
		}
	}
	for name, cipher := range c.Ciphers {
		if cipher.Mode == "" {
			cipher.Mode = "xor"
		}
		if cipher.Auth == "" {
			cipher.Auth = "none"
		}
		if cipher.Scope == "" {
			cipher.Scope = "wg-payload-prefix"
		}
		if cipher.KeyDerivation == "" {
			cipher.KeyDerivation = "wgmx-hkdf256-v1"
		}
		if cipher.KeyLen == 0 {
			if cipher.KeyDerivation == "udp2raw-md5-key1" {
				cipher.KeyLen = 16
			} else {
				cipher.KeyLen = 256
			}
		}
		if cipher.MaxBytes == 0 {
			cipher.MaxBytes = 128
		}
		c.Ciphers[name] = cipher
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
	if len(c.WireGuards) > 0 && len(c.Underlays) == 0 {
		return errors.New("at least one underlay is required when wireguard interfaces are configured")
	}
	if len(c.WireGuards) > 0 && len(c.Profiles) == 0 {
		return errors.New("at least one profile is required when wireguard interfaces are configured")
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
	if !c.Runtime.RequireNonzeroFwmark {
		return errors.New("runtime.require_nonzero_fwmark=false is reserved but not implemented in MVP")
	}
	if c.Runtime.PollInterval.Duration < MinimumPollInterval {
		return fmt.Errorf("runtime.poll_interval must be at least %s", MinimumPollInterval)
	}
	if err := validateUniqueUnderlays(c.Underlays); err != nil {
		return err
	}
	if c.UnderlayOverlapPolicy != "reject" {
		return fmt.Errorf("underlay_overlap_policy %q is reserved but not implemented", c.UnderlayOverlapPolicy)
	}
	if err := validatePolicy(c.Policy); err != nil {
		return err
	}
	switch c.StartupGuard.Mode {
	case "nft-temporary-drop", "none":
	default:
		return fmt.Errorf("startup_guard.mode %q is unsupported", c.StartupGuard.Mode)
	}
	if c.StartupGuard.Egress.Match != "fwmark" {
		return fmt.Errorf("startup_guard.egress.match %q is unsupported", c.StartupGuard.Egress.Match)
	}
	if c.StartupGuard.Ingress.Match != "config-listen-port-if-present" {
		return fmt.Errorf("startup_guard.ingress.match %q is unsupported", c.StartupGuard.Ingress.Match)
	}
	if c.StartupGuard.Ingress.RandomListenPortBehavior != "best-effort" {
		return fmt.Errorf("startup_guard.ingress.random_listen_port_behavior %q is unsupported", c.StartupGuard.Ingress.RandomListenPortBehavior)
	}
	for name, cipher := range c.Ciphers {
		if name == "" {
			return errors.New("cipher name is required")
		}
		if err := validateCipher(fmt.Sprintf("ciphers.%s", name), cipher); err != nil {
			return err
		}
	}
	seenWireGuards := make(map[string]struct{}, len(c.WireGuards))
	for i, wg := range c.WireGuards {
		if wg.Name == "" {
			return fmt.Errorf("wireguards[%d].name is required", i)
		}
		if _, exists := seenWireGuards[wg.Name]; exists {
			return fmt.Errorf("duplicate wireguard %q", wg.Name)
		}
		seenWireGuards[wg.Name] = struct{}{}
		if wg.NetNS != "root" {
			return fmt.Errorf("wireguards[%d].netns %q is reserved but not implemented; only root is supported", i, wg.NetNS)
		}
		if wg.Profile == "" {
			return fmt.Errorf("wireguards[%d].profile is required", i)
		}
		if _, ok := c.Profiles[wg.Profile]; !ok {
			return fmt.Errorf("wireguards[%d].profile %q is not defined", i, wg.Profile)
		}
		if wg.Cipher != "" {
			_, ok := c.Ciphers[wg.Cipher]
			if !ok {
				return fmt.Errorf("wireguards[%d].cipher %q is not defined", i, wg.Cipher)
			}
			if wg.Transport.Mode != "" && wg.Transport.Mode != "udp" {
				return fmt.Errorf("wireguards[%d].cipher is only implemented for udp transport in MVP", i)
			}
		}
		switch wg.Transport.Mode {
		case "", "udp":
		case "icmp":
			switch wg.Transport.ICMP.Role {
			case "client":
				if wg.Transport.ICMP.ID == 0 {
					return fmt.Errorf("wireguards[%d].transport.icmp.id is required for client role", i)
				}
			case "server":
				if wg.Transport.ICMP.ID != 0 {
					return fmt.Errorf("wireguards[%d].transport.icmp.id must be omitted or zero for server role", i)
				}
			default:
				return fmt.Errorf("wireguards[%d].transport.icmp.role must be client or server", i)
			}
		case "faketcp", "faketcp-lite":
			return fmt.Errorf("wireguards[%d].transport.mode %q is reserved but not implemented", i, wg.Transport.Mode)
		default:
			return fmt.Errorf("wireguards[%d].transport.mode %q is unsupported", i, wg.Transport.Mode)
		}
	}
	return validateDataplaneCapacity(c)
}

func validateCipher(prefix string, c Cipher) error {
	switch c.Mode {
	case "xor":
	default:
		return fmt.Errorf("%s.mode %q is unsupported", prefix, c.Mode)
	}
	switch c.Auth {
	case "", "none":
	default:
		return fmt.Errorf("%s.auth %q is unsupported; only auth=none is implemented", prefix, c.Auth)
	}
	switch c.Scope {
	case "wg-payload-full", "wg-payload-prefix":
	default:
		return fmt.Errorf("%s.scope %q is unsupported", prefix, c.Scope)
	}
	secretSources := 0
	for _, present := range []bool{c.Secret != "", c.SecretFile != "", c.Password != ""} {
		if present {
			secretSources++
		}
	}
	if secretSources != 1 {
		return fmt.Errorf("%s must configure exactly one of secret, secret_file, or password", prefix)
	}
	switch c.KeyDerivation {
	case "wgmx-hkdf256-v1":
		if c.Secret == "" && c.SecretFile == "" {
			return fmt.Errorf("%s requires secret or secret_file", prefix)
		}
		if c.Password != "" {
			return fmt.Errorf("%s.password is only valid with key_derivation=udp2raw-md5-key1", prefix)
		}
	case "udp2raw-md5-key1":
		if c.Password == "" && c.Secret == "" && c.SecretFile == "" {
			return fmt.Errorf("%s requires password, secret, or secret_file", prefix)
		}
	default:
		return fmt.Errorf("%s.key_derivation %q is unsupported", prefix, c.KeyDerivation)
	}
	switch c.KeyLen {
	case 16, 32, 64, 256:
	default:
		return fmt.Errorf("%s.key_len must be one of 16, 32, 64, 256", prefix)
	}
	if c.MaxBytes == 0 || c.MaxBytes > 2048 || c.MaxBytes%4 != 0 {
		return fmt.Errorf("%s.max_bytes must be a non-zero multiple of 4 up to 2048", prefix)
	}
	return nil
}

func validateDataplaneCapacity(c *Config) error {
	if len(c.Profiles) > MaxProfilesPerGeneration {
		return fmt.Errorf("profiles has %d entries, maximum is %d so reload can stage two generations", len(c.Profiles), MaxProfilesPerGeneration)
	}
	if len(c.Ciphers) > MaxCiphersPerGeneration {
		return fmt.Errorf("ciphers has %d entries, maximum is %d so reload can stage two generations", len(c.Ciphers), MaxCiphersPerGeneration)
	}
	if len(c.Underlays) > MaxUnderlaysPerGeneration {
		return fmt.Errorf("underlays has %d entries, maximum is %d so reload can stage two generations", len(c.Underlays), MaxUnderlaysPerGeneration)
	}
	underlays := uint64(len(c.Underlays))
	wireguards := uint64(len(c.WireGuards))
	if managed := underlays * wireguards; managed > MaxManagedRulesPerGeneration {
		return fmt.Errorf("configuration may create %d managed fwmark rules, maximum is %d per generation", managed, MaxManagedRulesPerGeneration)
	}
	ingress := underlays * wireguards * 2
	if ingress > MaxDirectionalRulesPerGeneration {
		return fmt.Errorf("configuration may create %d ingress rules, maximum is %d per generation", ingress, MaxDirectionalRulesPerGeneration)
	}
	var egressPerUnderlay uint64
	var icmpWireGuards uint64
	for _, wg := range c.WireGuards {
		if wg.Transport.Mode == "icmp" {
			egressPerUnderlay++
			icmpWireGuards++
		} else {
			egressPerUnderlay += 2
		}
	}
	if egress := underlays * egressPerUnderlay; egress > MaxDirectionalRulesPerGeneration {
		return fmt.Errorf("configuration may create %d egress rules, maximum is %d per generation", egress, MaxDirectionalRulesPerGeneration)
	}
	if icmp := underlays * icmpWireGuards; icmp > MaxDirectionalRulesPerGeneration {
		return fmt.Errorf("configuration may create %d ICMP listeners, maximum is %d per generation", icmp, MaxDirectionalRulesPerGeneration)
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
