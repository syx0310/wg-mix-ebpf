package config

import "testing"

func TestLoadAppliesDefaults(t *testing.T) {
	cfg, err := Load([]byte(`
version: 1
underlays:
  - name: eth0
    type: netdev
wireguards:
  - name: wg0
    profile: mix-default
profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != "transparent-typeword" {
		t.Fatalf("mode = %q", cfg.Mode)
	}
	if cfg.WireGuards[0].Config != "/etc/wireguard/wg0.conf" {
		t.Fatalf("default config = %q", cfg.WireGuards[0].Config)
	}
	if cfg.FwmarkPolicy.Mode != "config-required" {
		t.Fatalf("fwmark policy = %q", cfg.FwmarkPolicy.Mode)
	}
	if !cfg.Runtime.RequireNonzeroFwmark {
		t.Fatal("require nonzero fwmark default not enabled")
	}
}

func TestRejectUnknownUnderlayType(t *testing.T) {
	_, err := Load([]byte(`
version: 1
underlays:
  - name: eth0
    type: invalid
wireguards:
  - name: wg0
    profile: mix-default
profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
`))
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestRejectRequireNonzeroFwmarkFalse(t *testing.T) {
	_, err := Load([]byte(`
version: 1
underlays:
  - name: eth0
    type: netdev
wireguards:
  - name: wg0
    profile: mix-default
profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
runtime:
  require_nonzero_fwmark: false
`))
	if err == nil {
		t.Fatal("expected require_nonzero_fwmark=false to be rejected")
	}
}

func TestRuntimeStrictFalseIsPreserved(t *testing.T) {
	cfg, err := Load([]byte(`
version: 1
underlays:
  - name: eth0
    type: netdev
wireguards:
  - name: wg0
    profile: mix-default
profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
runtime:
  strict_runtime_fwmark: false
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Runtime.StrictRuntimeFwmark {
		t.Fatal("explicit strict_runtime_fwmark=false was overwritten")
	}
}

func TestRejectReservedFwmarkPolicyModes(t *testing.T) {
	_, err := Load([]byte(`
version: 1
underlays:
  - name: eth0
    type: netdev
wireguards:
  - name: wg0
    profile: mix-default
profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
fwmark_policy:
  mode: runtime-accepted
`))
	if err == nil {
		t.Fatal("expected reserved fwmark policy error")
	}
}

func TestRejectZeroFwmarkFallback(t *testing.T) {
	_, err := Load([]byte(`
version: 1
underlays:
  - name: eth0
    type: netdev
wireguards:
  - name: wg0
    profile: mix-default
profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
runtime:
  allow_zero_fwmark_fallback: true
`))
	if err == nil {
		t.Fatal("expected zero fwmark fallback error")
	}
}

func TestAcceptICMPClientTransport(t *testing.T) {
	cfg, err := Load([]byte(`
version: 1
underlays:
  - name: eth0
    type: netdev
wireguards:
  - name: wg0
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
	if cfg.WireGuards[0].Transport.Mode != "icmp" {
		t.Fatalf("transport mode = %q", cfg.WireGuards[0].Transport.Mode)
	}
}

func TestAcceptUDPXORCipher(t *testing.T) {
	cfg, err := Load([]byte(`
version: 1
underlays:
  - name: eth0
    type: netdev
wireguards:
  - name: wg0
    profile: mix-default
    cipher: xor-home
profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
ciphers:
  xor-home:
    mode: xor
    auth: none
    key_derivation: wgmx-hkdf256-v1
    secret: "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.WireGuards[0].Cipher != "xor-home" {
		t.Fatalf("cipher = %q", cfg.WireGuards[0].Cipher)
	}
	if cfg.Ciphers["xor-home"].KeyLen != 256 {
		t.Fatalf("default key_len = %d", cfg.Ciphers["xor-home"].KeyLen)
	}
	if cfg.Ciphers["xor-home"].Scope != "wg-payload-prefix" {
		t.Fatalf("default scope = %q", cfg.Ciphers["xor-home"].Scope)
	}
	if cfg.Ciphers["xor-home"].MaxBytes != 128 {
		t.Fatalf("default max_bytes = %d", cfg.Ciphers["xor-home"].MaxBytes)
	}
}

func TestRejectCipherWithICMPTransport(t *testing.T) {
	_, err := Load([]byte(`
version: 1
underlays:
  - name: eth0
    type: netdev
wireguards:
  - name: wg0
    profile: mix-default
    cipher: xor-home
    transport:
      mode: icmp
      icmp:
        role: client
        id: 0x5303
profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
ciphers:
  xor-home:
    mode: xor
    secret: "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
`))
	if err == nil {
		t.Fatal("expected cipher with icmp transport to be rejected")
	}
}

func TestRejectXORCipherWithoutSecret(t *testing.T) {
	_, err := Load([]byte(`
version: 1
underlays:
  - name: eth0
    type: netdev
wireguards:
  - name: wg0
    profile: mix-default
    cipher: xor-home
profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
ciphers:
  xor-home:
    mode: xor
`))
	if err == nil {
		t.Fatal("expected missing XOR secret to be rejected")
	}
}

func TestRejectICMPClientWithoutID(t *testing.T) {
	_, err := Load([]byte(`
version: 1
underlays:
  - name: eth0
    type: netdev
wireguards:
  - name: wg0
    profile: mix-default
    transport:
      mode: icmp
      icmp:
        role: client
profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
`))
	if err == nil {
		t.Fatal("expected missing icmp id error")
	}
}

func TestRejectICMPServerWithID(t *testing.T) {
	_, err := Load([]byte(`
version: 1
underlays:
  - name: eth0
    type: netdev
wireguards:
  - name: wg0
    profile: mix-default
    transport:
      mode: icmp
      icmp:
        role: server
        id: 0x5303
profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
`))
	if err == nil {
		t.Fatal("expected server icmp id error")
	}
}

func TestRejectFakeTCPTransport(t *testing.T) {
	_, err := Load([]byte(`
version: 1
underlays:
  - name: eth0
    type: netdev
wireguards:
  - name: wg0
    profile: mix-default
    transport:
      mode: faketcp
profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
`))
	if err == nil {
		t.Fatal("expected faketcp to be rejected")
	}
}

func TestRejectUnsupportedUnderlayParser(t *testing.T) {
	_, err := Load([]byte(`
version: 1
underlays:
  - name: eth0
    type: netdev
    parser: pppoe
wireguards:
  - name: wg0
    profile: mix-default
profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
`))
	if err == nil {
		t.Fatal("expected unsupported parser error")
	}
}

func TestRejectPolicyNotImplementedByDataplane(t *testing.T) {
	_, err := Load([]byte(`
version: 1
underlays:
  - name: eth0
    type: netdev
wireguards:
  - name: wg0
    profile: mix-default
profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
policy:
  ingress_managed_ipv6_ext_header: pass
`))
	if err == nil {
		t.Fatal("expected unsupported policy error")
	}
}

func TestSafeTemplateValidatesAsIdleConfig(t *testing.T) {
	cfg := SafeTemplate()
	if err := cfg.ValidateStatic(); err != nil {
		t.Fatalf("safe template should validate: %v", err)
	}
}
