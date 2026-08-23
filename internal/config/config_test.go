package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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
	if cfg.Runtime.AttachmentBackend != "auto" {
		t.Fatalf("attachment backend default = %q", cfg.Runtime.AttachmentBackend)
	}
	if cfg.Runtime.ChecksumBackend != FakeTCPChecksumBackendAuto {
		t.Fatalf("checksum backend default = %q", cfg.Runtime.ChecksumBackend)
	}
}

func TestRuntimeAttachmentBackends(t *testing.T) {
	for _, backend := range []string{"auto", "tcx", "classic_tc"} {
		cfg, err := Load([]byte("version: 1\nunderlays: []\nwireguards: []\nprofiles: {}\nruntime:\n  attachment_backend: " + backend + "\n"))
		if err != nil {
			t.Fatalf("load backend %s: %v", backend, err)
		}
		if cfg.Runtime.AttachmentBackend != backend {
			t.Fatalf("attachment backend = %q, want %q", cfg.Runtime.AttachmentBackend, backend)
		}
	}
	if _, err := Load([]byte("version: 1\nunderlays: []\nwireguards: []\nprofiles: {}\nruntime:\n  attachment_backend: legacy\n")); err == nil {
		t.Fatal("expected unsupported attachment backend rejection")
	}
}

func TestRuntimeChecksumBackends(t *testing.T) {
	for _, backend := range []string{
		FakeTCPChecksumBackendAuto,
		FakeTCPChecksumBackendKfunc,
		FakeTCPChecksumBackendKprobe,
	} {
		cfg, err := Load([]byte("version: 1\nunderlays: []\nwireguards: []\nprofiles: {}\nruntime:\n  checksum_backend: " + backend + "\n"))
		if err != nil {
			t.Fatalf("load backend %s: %v", backend, err)
		}
		if cfg.Runtime.ChecksumBackend != backend {
			t.Fatalf("checksum backend = %q, want %q", cfg.Runtime.ChecksumBackend, backend)
		}
	}
	if _, err := Load([]byte("version: 1\nunderlays: []\nwireguards: []\nprofiles: {}\nruntime:\n  checksum_backend: magic\n")); err == nil {
		t.Fatal("expected unsupported checksum backend rejection")
	}
}

func TestStartupGuardModeIsExplicitAndDoesNotHaveAutoFallback(t *testing.T) {
	base := "version: 1\nunderlays: []\nwireguards: []\nprofiles: {}\n"
	defaultConfig, err := Load([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	if defaultConfig.StartupGuard.Mode != StartupGuardModeNFTTemporaryDrop {
		t.Fatalf("default startup guard mode = %q", defaultConfig.StartupGuard.Mode)
	}
	disabledConfig, err := Load([]byte(base + "startup_guard:\n  mode: none\n"))
	if err != nil {
		t.Fatal(err)
	}
	if disabledConfig.StartupGuard.Mode != StartupGuardModeNone {
		t.Fatalf("disabled startup guard mode = %q", disabledConfig.StartupGuard.Mode)
	}
	for _, unsupported := range []string{"auto", "optional", "best-effort"} {
		_, err := Load([]byte(base + "startup_guard:\n  mode: " + unsupported + "\n"))
		if err == nil || !strings.Contains(err.Error(), "startup_guard.mode") {
			t.Fatalf("implicit fallback mode %q was accepted: %v", unsupported, err)
		}
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

func TestAcceptProductionFakeTCPTransportWithXOR(t *testing.T) {
	cfg, err := Load([]byte(`
version: 1
underlays:
  - name: eth0
    type: netdev
wireguards:
  - name: wg0
    profile: mix-default
    cipher: xor-home
    transport:
      mode: faketcp
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
	fake := cfg.WireGuards[0].Transport.FakeTCP
	if fake.ChecksumMode != FakeTCPChecksumModePartialCompleteReset || fake.IngressMode != FakeTCPIngressModeXDPGenericExact {
		t.Fatalf("faketcp capability defaults = checksum %q ingress %q", fake.ChecksumMode, fake.IngressMode)
	}
	if fake.SessionCapacity != 4096 || fake.MaxHalfOpenSessions != 1024 ||
		fake.MaxHalfOpenPerSource != 16 || fake.SYNRateInterval.Duration != 100*time.Millisecond ||
		fake.SYNBurst != 256 || fake.SYNBurstPerSource != 8 ||
		fake.SYNSourceLedgerCapacity != 4096 || fake.SYNSourceLedgerTTL.Duration != 5*time.Minute ||
		fake.MaxPendingPacketsPerFlow != 1 {
		t.Fatalf("faketcp bounds = %#v", fake)
	}
}

func TestFakeTCPStartupGuardProfiles(t *testing.T) {
	base := `
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
`
	guarded, err := Load([]byte(base))
	if err != nil {
		t.Fatalf("load default guarded FakeTCP profile: %v", err)
	}
	if guarded.StartupGuard.Mode != StartupGuardModeNFTTemporaryDrop {
		t.Fatalf("default startup guard mode = %q", guarded.StartupGuard.Mode)
	}

	disabled, err := Load([]byte(base + "startup_guard:\n  mode: none\n"))
	if err != nil {
		t.Fatalf("explicit no-nft FakeTCP profile was rejected: %v", err)
	}
	if disabled.StartupGuard.Mode != StartupGuardModeNone {
		t.Fatalf("explicit startup guard mode = %q", disabled.StartupGuard.Mode)
	}

	_, err = Load([]byte(base + "policy:\n  startup_fail_mode: best_effort\n"))
	if err == nil || !strings.Contains(err.Error(), "faketcp requires") {
		t.Fatalf("expected FakeTCP startup fail policy rejection, got %v", err)
	}
}

func TestRejectLegacyFakeTCPChecksumOffsetMode(t *testing.T) {
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
      faketcp:
        experimental: true
        checksum_mode: kfunc-required
profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
`))
	if err == nil || !strings.Contains(err.Error(), "ip_summed identification") ||
		!strings.Contains(err.Error(), "materialize/complete") ||
		!strings.Contains(err.Error(), "metadata reset") {
		t.Fatalf("legacy checksum-offset mode error = %v", err)
	}
}

func TestDeprecatedFakeTCPExperimentalFieldIsIgnored(t *testing.T) {
	for _, value := range []string{"true", "false"} {
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
      faketcp:
        experimental: ` + value + `
profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
`))
		if err != nil {
			t.Fatalf("deprecated experimental=%s was not accepted: %v", value, err)
		}
	}
}

func TestDeprecatedFakeTCPIngressModeIsNormalized(t *testing.T) {
	cfg, err := Load([]byte(`
version: 1
underlays:
  - name: eth0
    type: netdev
wireguards:
  - name: wg0
    profile: mix-default
    transport:
      mode: faketcp
      faketcp:
        ingress_mode: xdp-required
profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.WireGuards[0].Transport.FakeTCP.IngressMode; got != FakeTCPIngressModeXDPGenericExact {
		t.Fatalf("normalized ingress mode = %q, want %q", got, FakeTCPIngressModeXDPGenericExact)
	}
}

func TestRejectUnsupportedFakeTCPIngressMode(t *testing.T) {
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
      faketcp:
        ingress_mode: xdp-native
profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
`))
	if err == nil || !strings.Contains(err.Error(), FakeTCPIngressModeXDPGenericExact) {
		t.Fatalf("unsupported FakeTCP ingress error = %v", err)
	}
}

func TestRejectUnboundedFakeTCPSettings(t *testing.T) {
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
      faketcp:
        experimental: true
        session_capacity: 16385
profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
`))
	if err == nil || !strings.Contains(err.Error(), "session_capacity") {
		t.Fatalf("expected bounded session error, got %v", err)
	}
}

func TestRejectFakeTCPHalfOpenCapacityThatCanFillEstablishedTable(t *testing.T) {
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
      faketcp:
        experimental: true
        session_capacity: 64
        max_half_open_sessions: 64
profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
`))
	if err == nil || !strings.Contains(err.Error(), "max_half_open_sessions") {
		t.Fatalf("expected established-capacity reservation error, got %v", err)
	}
}

func TestAcceptMultipleFakeTCPWireGuards(t *testing.T) {
	cfg, err := Load([]byte(`
version: 1
underlays:
  - name: eth0
    type: netdev
wireguards:
  - name: wg0
    profile: mix-default
    transport:
      mode: faketcp
  - name: wg1
    profile: mix-default
    transport:
      mode: faketcp
profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
`))
	if err != nil {
		t.Fatalf("multiple FakeTCP rejected: %v", err)
	}
	if len(cfg.WireGuards) != 2 {
		t.Fatalf("wireguards = %d, want 2", len(cfg.WireGuards))
	}
}

func TestAllowOneFakeTCPAlongsideUDPWireGuard(t *testing.T) {
	_, err := Load([]byte(`
version: 1
underlays:
  - name: eth0
    type: netdev
wireguards:
  - name: wg-faketcp
    profile: mix-default
    transport:
      mode: faketcp
  - name: wg-udp
    profile: mix-default
    transport:
      mode: udp
profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
runtime:
  attachment_backend: tcx
`))
	if err != nil {
		t.Fatalf("one FakeTCP plus UDP rejected: %v", err)
	}
}

func TestFakeTCPPolicyParametersApplyToSingleWireGuard(t *testing.T) {
	cfg, err := Load([]byte(`
version: 1
underlays:
  - name: eth0
    type: netdev
wireguards:
  - name: wg0
    profile: mix-default
    transport:
      mode: faketcp
      faketcp:
        experimental: true
        syn_rate_interval: 100ms
        syn_source_ledger_ttl: 1m
        handshake_timeout: 2s
profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
`))
	if err != nil {
		t.Fatal(err)
	}
	fake := cfg.WireGuards[0].Transport.FakeTCP
	if fake.SYNRateInterval.Duration != 100*time.Millisecond ||
		fake.SYNSourceLedgerTTL.Duration != time.Minute ||
		fake.HandshakeTimeout.Duration != 2*time.Second {
		t.Fatalf("FakeTCP policy = %#v", fake)
	}
}

func TestAcceptFakeTCPWithClassicTCAttachmentBackend(t *testing.T) {
	cfg, err := Load([]byte(`
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
runtime:
  attachment_backend: classic_tc
`))
	if err != nil {
		t.Fatalf("FakeTCP classic_tc rejected: %v", err)
	}
	if cfg.Runtime.AttachmentBackend != "classic_tc" {
		t.Fatalf("attachment backend = %q", cfg.Runtime.AttachmentBackend)
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

func TestRejectUnknownConfigField(t *testing.T) {
	for location, data := range map[string][]byte{
		"top-level": []byte("version: 1\nunderlays: []\nwireguards: []\nprofiles: {}\npoll_intervl: 1s\n"),
		"runtime":   []byte("version: 1\nunderlays: []\nwireguards: []\nprofiles: {}\nruntime:\n  poll_intervl: 1s\n"),
	} {
		for mode, load := range map[string]func([]byte) (*Config, error){
			"strict":  Load,
			"lenient": LoadLenient,
		} {
			t.Run(location+"/"+mode, func(t *testing.T) {
				if _, err := load(data); err == nil || !strings.Contains(err.Error(), "poll_intervl") {
					t.Fatalf("expected unknown field error, got %v", err)
				}
			})
		}
	}
}

func TestRejectMultipleYAMLDocuments(t *testing.T) {
	_, err := Load([]byte("version: 1\n---\nversion: 1\n"))
	if err == nil {
		t.Fatal("expected multiple YAML documents to be rejected")
	}
}

func TestRejectUnsafePollIntervals(t *testing.T) {
	for _, interval := range []string{"-1s", "1ns"} {
		t.Run(interval, func(t *testing.T) {
			_, err := Load([]byte("version: 1\nunderlays: []\nwireguards: []\nprofiles: {}\nruntime:\n  poll_interval: " + interval + "\n"))
			if err == nil || !strings.Contains(err.Error(), "poll_interval") {
				t.Fatalf("expected poll interval error, got %v", err)
			}
		})
	}
}

func TestRejectDuplicateWireGuardNames(t *testing.T) {
	_, err := Load([]byte(`
version: 1
underlays:
  - name: eth0
    type: netdev
wireguards:
  - name: wg0
    profile: p
  - name: wg0
    profile: p
profiles:
  p:
    preset: wireguard-mix-wire-values-v1
`))
	if err == nil || !strings.Contains(err.Error(), "duplicate wireguard") {
		t.Fatalf("expected duplicate wireguard error, got %v", err)
	}
}

func TestRejectNonRootNetNS(t *testing.T) {
	_, err := Load([]byte(`
version: 1
underlays:
  - name: eth0
    type: netdev
wireguards:
  - name: wg0
    netns: testns
    profile: p
profiles:
  p:
    preset: wireguard-mix-wire-values-v1
`))
	if err == nil || !strings.Contains(err.Error(), "only root is supported") {
		t.Fatalf("expected netns error, got %v", err)
	}
}

func TestRejectIgnoredSafetySelectors(t *testing.T) {
	tests := map[string]string{
		"overlap": "underlay_overlap_policy: allow\n",
		"egress":  "startup_guard:\n  egress:\n    match: anything\n",
		"ingress": "startup_guard:\n  ingress:\n    match: anything\n",
	}
	for name, extra := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Load([]byte("version: 1\nunderlays: []\nwireguards: []\nprofiles: {}\n" + extra))
			if err == nil {
				t.Fatal("expected ignored safety selector to be rejected")
			}
		})
	}
}

func TestRejectAmbiguousCipherSecretSources(t *testing.T) {
	_, err := Load([]byte(`
version: 1
underlays: []
wireguards: []
profiles: {}
ciphers:
  xor:
    mode: xor
    key_derivation: udp2raw-md5-key1
    secret: one
    password: two
`))
	if err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("expected ambiguous secret error, got %v", err)
	}
}

func TestRejectConfigBeyondGenerationCapacity(t *testing.T) {
	cfg := SafeTemplate()
	for i := len(cfg.Profiles); i < MaxProfilesPerGeneration+1; i++ {
		cfg.Profiles[fmt.Sprintf("profile-%03d", i)] = Profile{Preset: "wireguard-mix-wire-values-v1"}
	}
	if err := cfg.ValidateStatic(); err == nil || !strings.Contains(err.Error(), "stage two generations") {
		t.Fatalf("expected generation capacity error, got %v", err)
	}
}

func TestSaveFileUsesAtomicPrivateReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	initialInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := initialInfo.Mode().Perm(); got != 0o644 {
		t.Fatalf("initial config mode = %o, want 644", got)
	}
	if err := SaveFile(path, SafeTemplate()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("config mode = %o, want 600", got)
	}
	if _, err := LoadFile(path); err != nil {
		t.Fatalf("replacement config is invalid: %v", err)
	}
	leftovers, err := filepath.Glob(filepath.Join(dir, ".config.yaml.tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(leftovers) != 0 {
		t.Fatalf("temporary configs left behind: %v", leftovers)
	}
}
