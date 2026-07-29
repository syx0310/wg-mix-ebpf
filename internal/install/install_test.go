package install

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/attachstate"
	"github.com/syx0310/wg-mix-ebpf/internal/lockfile"
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
	if !strings.Contains(script, "/run/wg-mix-ebpf/runtime.request") || strings.Contains(script, "/run/wg-mix-ebpf/reload.request") {
		t.Fatalf("hotplug must not overwrite acknowledged CLI request files:\n%s", script)
	}
}

func TestInstallRejectsHeldGlobalLifecycleLeaseBeforeWrites(t *testing.T) {
	dir := t.TempDir()
	etcDir := filepath.Join(dir, "etc", "wg-mix-ebpf")
	runDir := filepath.Join(dir, "run")
	binaryPath := filepath.Join(dir, "sbin", "wg-mix-ebpf")
	t.Setenv(EnvEtcDir, etcDir)
	t.Setenv(EnvBinaryPath, binaryPath)
	t.Setenv(EnvVarLibDir, filepath.Join(dir, "state"))
	t.Setenv(daemonEnvRunDirForTest, runDir)

	ctx := lockfile.WithLifecyclePathForTest(t.Context(), filepath.Join(dir, "daemon.lease"))
	lease, err := lockfile.AcquireLifecycle(ctx, lockfile.LifecycleOwner{
		PID:    os.Getpid(),
		Action: "daemon",
		RunDir: "/run/real-daemon",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()

	_, err = Install(ctx, Options{System: "unknown"})
	if !errors.Is(err, lockfile.ErrLifecycleLeaseHeld) {
		t.Fatalf("install error = %v, want held lifecycle lease", err)
	}
	for _, path := range []string{filepath.Join(etcDir, "config.yaml"), binaryPath, runDir} {
		if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("install wrote %s before acquiring lifecycle ownership: %v", path, statErr)
		}
	}
}

func TestUninstallRejectsHeldGlobalLifecycleLeaseBeforeCleanup(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(dir, "run")
	stateDir := filepath.Join(dir, "state")
	marker := filepath.Join(stateDir, "keep")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvEtcDir, filepath.Join(dir, "etc", "wg-mix-ebpf"))
	t.Setenv(EnvBinaryPath, filepath.Join(dir, "sbin", "wg-mix-ebpf"))
	t.Setenv(EnvVarLibDir, stateDir)
	t.Setenv(daemonEnvRunDirForTest, runDir)
	t.Setenv(dataplaneEnvPinPathForTest, filepath.Join(dir, "pins"))

	ctx := lockfile.WithLifecyclePathForTest(t.Context(), filepath.Join(dir, "daemon.lease"))
	lease, err := lockfile.AcquireLifecycle(ctx, lockfile.LifecycleOwner{
		PID:    os.Getpid(),
		Action: "daemon",
		RunDir: "/run/real-daemon",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()

	_, err = Uninstall(ctx, Options{System: "unknown", Yes: true})
	if !errors.Is(err, lockfile.ErrLifecycleLeaseHeld) {
		t.Fatalf("uninstall error = %v, want held lifecycle lease", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("uninstall cleaned state before acquiring lifecycle ownership: %v", err)
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
	dir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", dir)
	fakeBin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fakeBin, "nft"), []byte(
		"#!/bin/sh\nprintf '%s\\n' 'Error: No such file or directory' 'list table inet wg_mix_ebpf_guard' >&2\nexit 1\n",
	), 0o755); err != nil {
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

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	ctx = lockfile.WithLifecyclePathForTest(ctx, filepath.Join(dir, "daemon.lease"))
	if _, err := Uninstall(ctx, Options{ConfigPath: configPath, System: "unknown", Yes: true}); err != nil {
		t.Fatalf("uninstall should complete without nested lock deadlock: %v", err)
	}
}

func TestUninstallRejectsDangerousCleanupPaths(t *testing.T) {
	t.Setenv(dataplaneEnvPinPathForTest, "/sys/fs/bpf")
	_, err := Uninstall(t.Context(), Options{System: "unknown", DryRun: true})
	if err == nil || !strings.Contains(err.Error(), "unsafe BPF pin path") {
		t.Fatalf("expected dangerous pin path rejection, got %v", err)
	}
}

func TestInstallBinaryReplacesModeAtomically(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "wg-mix-ebpf")
	if err := os.WriteFile(target, []byte("stale"), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o777); err != nil {
		t.Fatal(err)
	}
	initialInfo, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if got := initialInfo.Mode().Perm(); got != 0o777 {
		t.Fatalf("initial binary mode = %o, want 777", got)
	}
	if err := installBinary(target); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o755 {
		t.Fatalf("installed binary mode = %o, want 755", got)
	}
	if info.Size() <= int64(len("stale")) {
		t.Fatalf("installed binary was not replaced: size=%d", info.Size())
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

func TestCleanupRuntimeDirPreservesLifecycleInode(t *testing.T) {
	runDir := t.TempDir()
	leasePath := filepath.Join(runDir, "daemon.lease")
	if err := os.WriteFile(leasePath, []byte("owner\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "status.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(runDir, "requests"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := cleanupRuntimeDir(runDir, leasePath); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(leasePath); err != nil {
		t.Fatalf("lifecycle lease inode was removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(runDir, "status.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("runtime status was not removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(runDir, "requests")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("runtime request directory was not removed: %v", err)
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
