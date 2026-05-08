package app

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

func TestValidateOffline(t *testing.T) {
	dir := t.TempDir()
	wgPath := filepath.Join(dir, "wg0.conf")
	if err := os.WriteFile(wgPath, []byte("[Interface]\nFwMark = 0x10000002\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(`
version: 1
underlays:
  - name: eth0
    type: netdev
wireguards:
  - name: wg0
    config: `+wgPath+`
    profile: mix-default
profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := Run(t.Context(), []string{"validate", "--config", cfgPath, "--offline"}, &stdout, &stderr); err != nil {
		t.Fatalf("Run returned error: %v stderr=%s", err, stderr.String())
	}
	if stdout.String() != "ok\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestFeatures(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := Run(t.Context(), []string{"features"}, &stdout, &stderr); err != nil {
		t.Fatalf("Run returned error: %v stderr=%s", err, stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte(`"goos"`)) {
		t.Fatalf("unexpected features output: %s", stdout.String())
	}
}

func TestGuardPlanOffline(t *testing.T) {
	cfgPath := writeTestConfig(t, "[Interface]\nFwMark = 0x10000002\nListenPort = 31001\n")
	var stdout, stderr bytes.Buffer
	if err := Run(t.Context(), []string{"guard-plan", "--config", cfgPath, "--offline"}, &stdout, &stderr); err != nil {
		t.Fatalf("Run returned error: %v stderr=%s", err, stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("meta mark 0x10000002")) {
		t.Fatalf("guard plan missing mark rule: %s", stdout.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("udp dport 31001")) {
		t.Fatalf("guard plan missing listen port rule: %s", stdout.String())
	}
}

func TestGuardApplyDryRunOffline(t *testing.T) {
	cfgPath := writeTestConfig(t, "[Interface]\nFwMark = 0x10000002\nListenPort = 31001\n")
	var stdout, stderr bytes.Buffer
	if err := Run(t.Context(), []string{"guard-apply", "--config", cfgPath, "--offline", "--dry-run"}, &stdout, &stderr); err != nil {
		t.Fatalf("Run returned error: %v stderr=%s", err, stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("meta mark 0x10000002")) {
		t.Fatalf("guard apply dry-run missing mark rule: %s", stdout.String())
	}
}

func TestDumpABIOffline(t *testing.T) {
	cfgPath := writeTestConfig(t, "[Interface]\nFwMark = 0x10000002\nListenPort = 31001\n")
	var stdout, stderr bytes.Buffer
	if err := Run(t.Context(), []string{"dump-abi", "--config", cfgPath, "--offline"}, &stdout, &stderr); err != nil {
		t.Fatalf("Run returned error: %v stderr=%s", err, stderr.String())
	}
	want := []byte(`"ABIVersion": ` + strconv.FormatUint(uint64(abi.Version), 10))
	if !bytes.Contains(stdout.Bytes(), want) {
		t.Fatalf("dump-abi missing ABI version: %s", stdout.String())
	}
}

func TestGuardCleanupDryRun(t *testing.T) {
	cfgPath := writeTestConfig(t, "[Interface]\nFwMark = 0x10000002\n")
	var stdout, stderr bytes.Buffer
	if err := Run(t.Context(), []string{"guard-cleanup", "--config", cfgPath, "--offline", "--dry-run"}, &stdout, &stderr); err != nil {
		t.Fatalf("Run returned error: %v stderr=%s", err, stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("destroy table inet wg_mix_ebpf_guard")) {
		t.Fatalf("guard cleanup dry-run missing cleanup script: %s", stdout.String())
	}
}

func writeTestConfig(t *testing.T, wgConfig string) string {
	t.Helper()
	dir := t.TempDir()
	wgPath := filepath.Join(dir, "wg0.conf")
	if err := os.WriteFile(wgPath, []byte(wgConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(`
version: 1
underlays:
  - name: eth0
    type: netdev
wireguards:
  - name: wg0
    config: `+wgPath+`
    profile: mix-default
profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
`), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}
