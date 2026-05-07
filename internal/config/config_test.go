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
