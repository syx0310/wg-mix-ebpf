package install

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/attachstate"
)

func TestUninstallPurgeRejectsNonOwnedConfigDir(t *testing.T) {
	t.Setenv(EnvEtcDir, filepath.Join(t.TempDir(), "etc", "wg-mix-ebpf"))
	_, err := Uninstall(t.Context(), Options{
		ConfigPath: filepath.Join(t.TempDir(), "config.yaml"),
		System:     "unknown",
		DryRun:     true,
		Purge:      true,
	})
	if err == nil {
		t.Fatal("expected purge with non-owned config dir to fail")
	}
}

func TestUninstallPurgeAllowsOwnedConfigDir(t *testing.T) {
	dir := t.TempDir()
	etcDir := filepath.Join(dir, "etc", "wg-mix-ebpf")
	t.Setenv(EnvEtcDir, etcDir)
	plan, err := Uninstall(t.Context(), Options{
		ConfigPath: filepath.Join(etcDir, "config.yaml"),
		System:     "unknown",
		DryRun:     true,
		Purge:      true,
	})
	if err != nil {
		t.Fatalf("expected owned purge dry-run to pass: %v", err)
	}
	if !containsAction(plan.Actions, "purge owned config dir "+etcDir) {
		t.Fatalf("missing owned purge action: %#v", plan.Actions)
	}
}

func TestRenderedServicesUseStopCommand(t *testing.T) {
	unit := systemdUnit("/etc/wg-mix-ebpf/config.yaml", "/usr/sbin/wg-mix-ebpf")
	if !strings.Contains(unit, "ExecStop=/usr/sbin/wg-mix-ebpf stop --config /etc/wg-mix-ebpf/config.yaml") {
		t.Fatalf("systemd unit should stop via daemon stop command:\n%s", unit)
	}
	init := openWrtInit("/etc/wg-mix-ebpf/config.yaml", "/usr/sbin/wg-mix-ebpf")
	if !strings.Contains(init, "/usr/sbin/wg-mix-ebpf stop --config \"$CONF\"") {
		t.Fatalf("OpenWrt init should stop via daemon stop command:\n%s", init)
	}
}

func TestOpenWrtHotplugDoesNotUseNanosecondDate(t *testing.T) {
	script := openWrtHotplug()
	if strings.Contains(script, "%N") {
		t.Fatalf("hotplug script should not depend on BusyBox date %%N:\n%s", script)
	}
	if !strings.Contains(script, "/proc/uptime") {
		t.Fatalf("hotplug script should use portable changing content:\n%s", script)
	}
}

func TestUninstallKeepsBinaryHint(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(EnvEtcDir, filepath.Join(dir, "etc", "wg-mix-ebpf"))
	t.Setenv(EnvBinaryPath, filepath.Join(dir, "sbin", "wg-mix-ebpf"))
	plan, err := Uninstall(t.Context(), Options{System: "unknown", DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if !containsAction(plan.Actions, "binary removal hint") {
		t.Fatalf("missing binary removal hint: %#v", plan.Actions)
	}
}

func TestUninstallDoesNotDeadlockWhenConfigExists(t *testing.T) {
	dir := t.TempDir()
	fakeBin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fakeBin, "nft"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	etcDir := filepath.Join(dir, "etc", "wg-mix-ebpf")
	runDir := filepath.Join(dir, "run")
	stateDir := filepath.Join(dir, "state")
	pinDir := filepath.Join(dir, "pins")
	binaryPath := filepath.Join(dir, "sbin", "wg-mix-ebpf")
	for _, d := range []string{etcDir, runDir, stateDir, pinDir, filepath.Dir(binaryPath)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	configPath := filepath.Join(etcDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(`version: 1
underlays: []
wireguards: []
profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
startup_guard:
  mode: none
`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvEtcDir, etcDir)
	t.Setenv(daemonEnvRunDirForTest, runDir)
	t.Setenv(EnvVarLibDir, stateDir)
	t.Setenv(dataplaneEnvPinPathForTest, pinDir)
	t.Setenv(EnvBinaryPath, binaryPath)

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if _, err := Uninstall(ctx, Options{ConfigPath: configPath, System: "unknown", Yes: true}); err != nil {
		t.Fatalf("uninstall should complete without nested lock deadlock: %v", err)
	}
}

func TestUninstallStopsWhenOnlyAttachStateExists(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	if err := attachstate.Save(stateDir, &attachstate.State{Version: 1}); err != nil {
		t.Fatal(err)
	}
	p := paths{ConfigPath: filepath.Join(dir, "missing.yaml"), VarLibDir: stateDir}
	if !shouldStopForUninstall(p) {
		t.Fatal("uninstall should run stop cleanup when attach-state exists even if config is missing")
	}
}

func containsAction(actions []string, substr string) bool {
	for _, action := range actions {
		if strings.Contains(action, substr) {
			return true
		}
	}
	return false
}

const (
	daemonEnvRunDirForTest     = "WG_MIX_EBPF_RUN_DIR"
	dataplaneEnvPinPathForTest = "WG_MIX_EBPF_PIN_PATH"
)

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
