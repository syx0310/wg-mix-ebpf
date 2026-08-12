package control

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/config"
	"github.com/syx0310/wg-mix-ebpf/internal/runtime"
	"github.com/syx0310/wg-mix-ebpf/internal/underlay"
	"github.com/syx0310/wg-mix-ebpf/internal/wgconfig"
)

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Load([]byte(`
version: 1
underlays:
  - name: eth0
    type: netdev
wireguards:
  - name: wg0
    config: /tmp/wg0.conf
    profile: mix-default
profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
`))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestBuildStateRejectsEmptyDecodedCipherSecret(t *testing.T) {
	cfg, err := config.Load([]byte(`
version: 1
underlays: []
wireguards: []
profiles: {}
ciphers:
  xor:
    mode: xor
    key_derivation: wgmx-hkdf256-v1
    secret: "base64:"
`))
	if err != nil {
		t.Fatal(err)
	}
	_, err = BuildState(t.Context(), cfg, runtime.StaticProvider{}, underlay.StaticResolver{}, nil, BuildOptions{Offline: true})
	if err == nil || !strings.Contains(err.Error(), "secret material is empty") {
		t.Fatalf("expected empty secret rejection, got %v", err)
	}
}

func TestDeriveCipherKeyExpandsConfiguredPeriod(t *testing.T) {
	derivations := []config.Cipher{
		{
			KeyDerivation: "wgmx-hkdf256-v1",
			Secret:        "test-secret",
		},
		{
			KeyDerivation: "udp2raw-md5-key1",
			Password:      "test-password",
		},
	}
	for _, derivation := range derivations {
		for _, keyLen := range []uint32{16, 32, 64, 256} {
			cipher := derivation
			cipher.KeyLen = keyLen
			key, err := deriveCipherKey("test", cipher)
			if err != nil {
				t.Fatalf("derive %s key_len=%d: %v",
					cipher.KeyDerivation, keyLen, err)
			}
			for i := keyLen; i < uint32(len(key)); i++ {
				if key[i] != key[i%keyLen] {
					t.Fatalf("%s key_len=%d byte %d = %d, want period byte %d",
						cipher.KeyDerivation, keyLen, i, key[i],
						key[i%keyLen])
				}
			}
			for offset := uint32(0); offset < 2048; offset++ {
				oldIndex := offset & (keyLen - 1)
				newIndex := offset & 255
				if key[oldIndex] != key[newIndex] {
					t.Fatalf("%s key_len=%d offset %d changed keystream",
						cipher.KeyDerivation, keyLen, offset)
				}
			}
		}
	}
}

func TestStateFingerprintIncludesRedactedCipherBytes(t *testing.T) {
	state := &State{
		Generation: 1,
		Ciphers:    []CipherState{{ID: 7, Name: "secret", KeyLen: 4, Key: [256]byte{1, 2, 3, 4}}},
	}
	first, err := state.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	public, err := state.JSON()
	if err != nil {
		t.Fatal(err)
	}
	state.Ciphers[0].Key[0] = 9
	second, err := state.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	publicAfter, err := state.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("secret-only cipher rotation did not change state fingerprint")
	}
	if string(public) != string(publicAfter) {
		t.Fatal("redacted public state changed after secret-only cipher rotation")
	}
	if len(first) != sha256.Size*2 || strings.Contains(first, "01020304") {
		t.Fatalf("unsafe or malformed fingerprint %q", first)
	}
}

func TestDeriveCipherKeyRejectsUnsupportedLength(t *testing.T) {
	_, err := deriveCipherKey("test", config.Cipher{
		KeyDerivation: "wgmx-hkdf256-v1",
		Secret:        "test-secret",
		KeyLen:        8,
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported key_len 8") {
		t.Fatalf("expected key length error, got %v", err)
	}
}

func requireIngressListener(t *testing.T, state *State, family string, port uint16, action string) IngressListener {
	t.Helper()
	for _, listener := range state.IngressListeners {
		if listener.Family == family && listener.DestinationPort == port && listener.Action == action {
			return listener
		}
	}
	t.Fatalf("missing ingress listener family=%s port=%d action=%s", family, port, action)
	return IngressListener{}
}

func TestBuildStateOfflineParsesConfigFwMark(t *testing.T) {
	cfg := testConfig(t)
	cfg.Runtime.AttachmentBackend = "classic_tc"
	state, err := BuildState(context.Background(), cfg, runtime.StaticProvider{}, underlay.StaticResolver{}, func(string) (*wgconfig.Interface, error) {
		mark := uint32(0x10000002)
		return &wgconfig.Interface{FwMark: &mark}, nil
	}, BuildOptions{Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(state.WireGuards) != 1 {
		t.Fatalf("wireguards = %d", len(state.WireGuards))
	}
	if state.AttachmentBackend != "classic_tc" {
		t.Fatalf("attachment backend = %q", state.AttachmentBackend)
	}
	if state.WireGuards[0].ConfigFwMark != 0x10000002 {
		t.Fatalf("config fwmark = 0x%x", state.WireGuards[0].ConfigFwMark)
	}
	if len(state.EgressRules) != 0 {
		t.Fatalf("offline egress rules = %d", len(state.EgressRules))
	}
}

func TestBuildStateRejectsMissingFwMark(t *testing.T) {
	cfg := testConfig(t)
	_, err := BuildState(context.Background(), cfg, runtime.StaticProvider{}, underlay.StaticResolver{}, func(string) (*wgconfig.Interface, error) {
		return &wgconfig.Interface{}, nil
	}, BuildOptions{Offline: true})
	if err == nil {
		t.Fatal("expected missing fwmark error")
	}
}

func TestBuildStateRuntimeRules(t *testing.T) {
	cfg := testConfig(t)
	mark := uint32(0x10000002)
	state, err := BuildState(
		context.Background(),
		cfg,
		runtime.StaticProvider{Devices: map[string]*runtime.Device{
			"wg0": {
				Name:         "wg0",
				ListenPort:   31001,
				FirewallMark: mark,
				Up:           true,
			},
		}},
		underlay.StaticResolver{Underlays: map[string]*underlay.Resolved{
			"eth0": {
				Name:     "eth0",
				Type:     "netdev",
				IfName:   "eth0",
				IfIndex:  2,
				LinkType: "ethernet",
				Role:     "transform",
			},
		}},
		func(string) (*wgconfig.Interface, error) {
			return &wgconfig.Interface{FwMark: &mark}, nil
		},
		BuildOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.ManagedFwmarks) != 1 {
		t.Fatalf("managed fwmark rules = %d", len(state.ManagedFwmarks))
	}
	if len(state.EgressRules) != 2 {
		t.Fatalf("egress rules = %d", len(state.EgressRules))
	}
	if len(state.IngressListeners) != 2 {
		t.Fatalf("ingress listeners = %d", len(state.IngressListeners))
	}
	requireIngressListener(t, state, "ipv4", 31001, "rewrite")
	requireIngressListener(t, state, "ipv6", 31001, "rewrite")
	if state.EgressRules[0].SourcePort != 31001 {
		t.Fatalf("egress source port = %d", state.EgressRules[0].SourcePort)
	}
	if state.Underlays[0].Parser != "ethernet" {
		t.Fatalf("underlay parser = %q", state.Underlays[0].Parser)
	}
}

func TestBuildStateUDPXORCipherRules(t *testing.T) {
	cfg, err := config.Load([]byte(`
version: 1
underlays:
  - name: eth0
    type: netdev
wireguards:
  - name: wg0
    config: /tmp/wg0.conf
    profile: mix-default
    cipher: xor-home
profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
ciphers:
  xor-home:
    mode: xor
    auth: none
    scope: wg-payload-full
    key_derivation: udp2raw-md5-key1
    password: test-pass
    max_bytes: 256
`))
	if err != nil {
		t.Fatal(err)
	}
	mark := uint32(0x10000002)
	state, err := BuildState(
		context.Background(),
		cfg,
		runtime.StaticProvider{Devices: map[string]*runtime.Device{
			"wg0": {Name: "wg0", ListenPort: 31001, FirewallMark: mark, Up: true},
		}},
		underlay.StaticResolver{Underlays: map[string]*underlay.Resolved{
			"eth0": {IfName: "eth0", IfIndex: 2, LinkType: "ethernet", Role: "transform"},
		}},
		func(string) (*wgconfig.Interface, error) {
			return &wgconfig.Interface{FwMark: &mark}, nil
		},
		BuildOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Ciphers) != 1 {
		t.Fatalf("ciphers = %d", len(state.Ciphers))
	}
	if state.Ciphers[0].KeyLen != 16 || state.Ciphers[0].MaxBytes != 256 {
		t.Fatalf("cipher state = key_len %d max_bytes %d", state.Ciphers[0].KeyLen, state.Ciphers[0].MaxBytes)
	}
	if state.WireGuards[0].CipherID == 0 {
		t.Fatal("wireguard missing cipher id")
	}
	for _, rule := range state.EgressRules {
		if rule.CipherID != state.WireGuards[0].CipherID {
			t.Fatalf("egress cipher id = %d want %d", rule.CipherID, state.WireGuards[0].CipherID)
		}
	}
	for _, listener := range state.IngressListeners {
		if listener.CipherID != state.WireGuards[0].CipherID {
			t.Fatalf("ingress cipher id = %d want %d", listener.CipherID, state.WireGuards[0].CipherID)
		}
	}
}

func TestBuildStateICMPTransportRules(t *testing.T) {
	cfg, err := config.Load([]byte(`
version: 1
underlays:
  - name: eth0
    type: netdev
wireguards:
  - name: wg0
    config: /tmp/wg0.conf
    profile: mix-default
    transport:
      mode: icmp
      icmp:
        role: client
        id: 0x5303
profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
`))
	if err != nil {
		t.Fatal(err)
	}
	mark := uint32(0x10000002)
	state, err := BuildState(
		context.Background(),
		cfg,
		runtime.StaticProvider{Devices: map[string]*runtime.Device{
			"wg0": {Name: "wg0", ListenPort: 31001, FirewallMark: mark, Up: true},
		}},
		underlay.StaticResolver{Underlays: map[string]*underlay.Resolved{
			"eth0": {IfName: "eth0", IfIndex: 2, LinkType: "ethernet", Role: "transform"},
		}},
		func(string) (*wgconfig.Interface, error) {
			return &wgconfig.Interface{FwMark: &mark}, nil
		},
		BuildOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.EgressRules) != 1 {
		t.Fatalf("icmp egress rules = %d", len(state.EgressRules))
	}
	if got := state.EgressRules[0].TransportMode; got != "icmp" {
		t.Fatalf("transport mode = %q", got)
	}
	if state.EgressRules[0].ICMPRole != "client" || state.EgressRules[0].ICMPID != 0x5303 {
		t.Fatalf("icmp egress = role %q id %d", state.EgressRules[0].ICMPRole, state.EgressRules[0].ICMPID)
	}
	if len(state.IngressListeners) != 2 {
		t.Fatalf("udp ingress listeners = %d", len(state.IngressListeners))
	}
	udpDrop := requireIngressListener(t, state, "ipv4", 31001, "drop")
	if udpDrop.UnderlayIfIndex != 2 {
		t.Fatalf("udp drop underlay = %d", udpDrop.UnderlayIfIndex)
	}
	requireIngressListener(t, state, "ipv6", 31001, "drop")
	if len(state.ICMPListeners) != 1 {
		t.Fatalf("icmp listeners = %d", len(state.ICMPListeners))
	}
	listener := state.ICMPListeners[0]
	if listener.ICMPType != 0 || listener.ICMPID != 0x5303 || listener.ListenPort != 31001 {
		t.Fatalf("icmp listener = type %d id %d listen %d", listener.ICMPType, listener.ICMPID, listener.ListenPort)
	}
	if listener.Flags != 0 {
		t.Fatalf("client icmp listener flags = 0x%x", listener.Flags)
	}
}

func TestBuildStateFakeTCPIsIPv4OnlyKeepsCipherAndUsesCanonicalIngress(t *testing.T) {
	cfg, err := config.Load([]byte(`
version: 1
underlays:
  - name: eth0
    type: netdev
wireguards:
  - name: wg0
    config: /tmp/wg0.conf
    profile: mix-default
    cipher: xor-home
    transport:
      mode: faketcp
      faketcp:
        experimental: true
        ingress_mode: xdp-required
profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
ciphers:
  xor-home:
    mode: xor
    secret: "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
`))
	if err != nil {
		t.Fatal(err)
	}
	mark := uint32(0x10000002)
	state, err := BuildState(
		context.Background(),
		cfg,
		runtime.StaticProvider{Devices: map[string]*runtime.Device{
			"wg0": {Name: "wg0", ListenPort: 31001, FirewallMark: mark, Up: true},
		}},
		underlay.StaticResolver{Underlays: map[string]*underlay.Resolved{
			"eth0": {IfName: "eth0", IfIndex: 2, LinkType: "ethernet", Role: "transform"},
		}},
		func(string) (*wgconfig.Interface, error) {
			return &wgconfig.Interface{FwMark: &mark}, nil
		},
		BuildOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.EgressRules) != 1 || len(state.IngressListeners) != 1 {
		t.Fatalf("faketcp rules = egress %d ingress %d", len(state.EgressRules), len(state.IngressListeners))
	}
	egress := state.EgressRules[0]
	ingress := state.IngressListeners[0]
	if egress.Family != "ipv4" || ingress.Family != "ipv4" ||
		egress.TransportMode != "faketcp" || ingress.TransportMode != "faketcp" {
		t.Fatalf("faketcp rules = %#v %#v", egress, ingress)
	}
	if egress.CipherID == 0 || ingress.CipherID != egress.CipherID {
		t.Fatalf("faketcp cipher IDs = egress %d ingress %d", egress.CipherID, ingress.CipherID)
	}
	wg := state.WireGuards[0]
	if wg.FakeTCPChecksumMode != config.FakeTCPChecksumModePartialCompleteReset ||
		wg.FakeTCPIngressMode != config.FakeTCPIngressModeXDPGenericExact || wg.FakeTCPSessionCapacity != 4096 ||
		wg.FakeTCPMaxHalfOpenSessions != 1024 || wg.FakeTCPMaxHalfOpenPerSource != 16 ||
		wg.FakeTCPSYNRateIntervalNanos != int64(100*time.Millisecond) ||
		wg.FakeTCPSYNBurst != 256 || wg.FakeTCPSYNBurstPerSource != 8 ||
		wg.FakeTCPSYNSourceLedgerCapacity != 4096 ||
		wg.FakeTCPSYNSourceLedgerTTLNanos != int64(5*time.Minute) {
		t.Fatalf("faketcp state = %#v", wg)
	}
	encoded, err := state.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "faketcp_experimental") {
		t.Fatalf("deprecated experimental acknowledgement leaked into state: %s", encoded)
	}
	if !strings.Contains(string(encoded), `"faketcp_ingress_mode": "xdp-generic-exact"`) {
		t.Fatalf("state lacks canonical FakeTCP ingress mode: %s", encoded)
	}
}

func TestBuildStateICMPServerUsesWildcardRequestID(t *testing.T) {
	cfg, err := config.Load([]byte(`
version: 1
underlays:
  - name: eth0
    type: netdev
wireguards:
  - name: wg0
    config: /tmp/wg0.conf
    profile: mix-default
    transport:
      mode: icmp
      icmp:
        role: server
profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
`))
	if err != nil {
		t.Fatal(err)
	}
	mark := uint32(0x10000002)
	state, err := BuildState(
		context.Background(),
		cfg,
		runtime.StaticProvider{Devices: map[string]*runtime.Device{
			"wg0": {Name: "wg0", ListenPort: 52000, FirewallMark: mark, Up: true},
		}},
		underlay.StaticResolver{Underlays: map[string]*underlay.Resolved{
			"eth0": {IfName: "eth0", IfIndex: 2, LinkType: "ethernet", Role: "transform"},
		}},
		func(string) (*wgconfig.Interface, error) {
			return &wgconfig.Interface{FwMark: &mark}, nil
		},
		BuildOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.ICMPListeners) != 1 {
		t.Fatalf("icmp listeners = %d", len(state.ICMPListeners))
	}
	if state.ICMPListeners[0].ICMPType != 8 || state.ICMPListeners[0].ICMPID != 0 {
		t.Fatalf("server icmp listener = type %d id %d", state.ICMPListeners[0].ICMPType, state.ICMPListeners[0].ICMPID)
	}
	if len(state.IngressListeners) != 2 {
		t.Fatalf("udp ingress listeners = %d", len(state.IngressListeners))
	}
	requireIngressListener(t, state, "ipv4", 52000, "drop")
	requireIngressListener(t, state, "ipv6", 52000, "drop")
	if state.ICMPListeners[0].Flags&ICMPListenerFlagWildcardID == 0 {
		t.Fatalf("server icmp listener flags = 0x%x, missing wildcard-id flag", state.ICMPListeners[0].Flags)
	}
}

func TestBuildStateHonorsConfiguredUnderlayParser(t *testing.T) {
	cfg, err := config.Load([]byte(`
version: 1
underlays:
  - name: pppoe-wan
    type: netdev
    parser: l3
wireguards:
  - name: wg0
    config: /tmp/wg0.conf
    profile: mix-default
profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
`))
	if err != nil {
		t.Fatal(err)
	}
	mark := uint32(0x10000002)
	state, err := BuildState(
		context.Background(),
		cfg,
		runtime.StaticProvider{Devices: map[string]*runtime.Device{
			"wg0": {Name: "wg0", ListenPort: 31001, FirewallMark: mark, Up: true},
		}},
		underlay.StaticResolver{Underlays: map[string]*underlay.Resolved{
			"pppoe-wan": {IfName: "pppoe-wan", IfIndex: 7, LinkType: "device", Role: "transform"},
		}},
		func(string) (*wgconfig.Interface, error) {
			return &wgconfig.Interface{FwMark: &mark}, nil
		},
		BuildOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if state.Underlays[0].Parser != "l3" {
		t.Fatalf("underlay parser = %q", state.Underlays[0].Parser)
	}
}

func TestBuildStateAcceptsExplicitFakeTCPOnL3Parser(t *testing.T) {
	cfg, err := config.Load([]byte(`
version: 1
underlays:
  - name: pppoe-wan
    type: netdev
    parser: l3
wireguards:
  - name: wg0
    config: /tmp/wg0.conf
    profile: mix-default
    transport:
      mode: faketcp
      faketcp:
        experimental: true
profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
`))
	if err != nil {
		t.Fatal(err)
	}
	mark := uint32(0x10000002)
	state, err := BuildState(
		context.Background(),
		cfg,
		runtime.StaticProvider{Devices: map[string]*runtime.Device{
			"wg0": {Name: "wg0", ListenPort: 31001, FirewallMark: mark, Up: true},
		}},
		underlay.StaticResolver{Underlays: map[string]*underlay.Resolved{
			"pppoe-wan": {IfName: "pppoe-wan", IfIndex: 7, LinkType: "device", Role: "transform"},
		}},
		func(string) (*wgconfig.Interface, error) {
			return &wgconfig.Interface{FwMark: &mark}, nil
		},
		BuildOptions{},
	)
	if err != nil {
		t.Fatalf("FakeTCP parser:l3 state: %v", err)
	}
	if got := state.Underlays[0].Parser; got != "l3" {
		t.Fatalf("FakeTCP underlay parser = %q, want l3", got)
	}
}

func TestFakeTCPResolvedUnderlayParserMustBeUnambiguous(t *testing.T) {
	state := &State{
		WireGuards: []WireGuardState{{TransportMode: "faketcp"}},
		Underlays: []UnderlayState{{
			Name: "mystery0", Role: "transform", Resolved: true, Parser: "auto",
		}},
	}
	if err := validateFakeTCPUnderlayParsers(state); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("FakeTCP parser:auto error = %v", err)
	}
	for _, parser := range []string{"ethernet", "l3"} {
		state.Underlays[0].Parser = parser
		if err := validateFakeTCPUnderlayParsers(state); err != nil {
			t.Fatalf("FakeTCP parser:%s rejected: %v", parser, err)
		}
	}
}

func TestBuildStateRuntimeFwMarkMismatch(t *testing.T) {
	cfg := testConfig(t)
	configMark := uint32(0x10000002)
	runtimeMark := uint32(0x10000003)
	_, err := BuildState(
		context.Background(),
		cfg,
		runtime.StaticProvider{Devices: map[string]*runtime.Device{
			"wg0": {
				Name:         "wg0",
				ListenPort:   31001,
				FirewallMark: runtimeMark,
				Up:           true,
			},
		}},
		underlay.StaticResolver{Underlays: map[string]*underlay.Resolved{
			"eth0": {IfName: "eth0", IfIndex: 2, Role: "transform"},
		}},
		func(string) (*wgconfig.Interface, error) {
			return &wgconfig.Interface{FwMark: &configMark}, nil
		},
		BuildOptions{},
	)
	if err == nil {
		t.Fatal("expected runtime fwmark mismatch")
	}
	var mismatch *FwmarkMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("expected typed mismatch error, got %T: %v", err, err)
	}
	if mismatch.WireGuard != "wg0" || mismatch.ConfigFwMark != configMark || mismatch.RuntimeMark != runtimeMark {
		t.Fatalf("unexpected mismatch details: %#v", mismatch)
	}
}

func TestBuildStateRejectsDuplicateIngressListener(t *testing.T) {
	cfg, err := config.Load([]byte(`
version: 1
underlays:
  - name: eth0
    type: netdev
wireguards:
  - name: wg0
    config: /tmp/wg0.conf
    profile: mix-default
  - name: wg1
    config: /tmp/wg1.conf
    profile: mix-default
profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
`))
	if err != nil {
		t.Fatal(err)
	}
	mark0 := uint32(0x10000002)
	mark1 := uint32(0x10000003)
	_, err = BuildState(
		context.Background(),
		cfg,
		runtime.StaticProvider{Devices: map[string]*runtime.Device{
			"wg0": {Name: "wg0", ListenPort: 31001, FirewallMark: mark0, Up: true},
			"wg1": {Name: "wg1", ListenPort: 31001, FirewallMark: mark1, Up: true},
		}},
		underlay.StaticResolver{Underlays: map[string]*underlay.Resolved{
			"eth0": {IfName: "eth0", IfIndex: 2, Role: "transform"},
		}},
		func(path string) (*wgconfig.Interface, error) {
			switch path {
			case "/tmp/wg0.conf":
				return &wgconfig.Interface{FwMark: &mark0}, nil
			case "/tmp/wg1.conf":
				return &wgconfig.Interface{FwMark: &mark1}, nil
			default:
				t.Fatalf("unexpected path %s", path)
				return nil, nil
			}
		},
		BuildOptions{},
	)
	if err == nil {
		t.Fatal("expected duplicate ingress listener error")
	}
}
