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

func TestRuntimeBoolFalseIsPreserved(t *testing.T) {
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
  require_nonzero_fwmark: false
  strict_runtime_fwmark: false
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Runtime.RequireNonzeroFwmark {
		t.Fatal("explicit require_nonzero_fwmark=false was overwritten")
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
