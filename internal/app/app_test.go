package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
	"github.com/syx0310/wg-mix-ebpf/internal/config"
	"github.com/syx0310/wg-mix-ebpf/internal/daemon"
	"github.com/syx0310/wg-mix-ebpf/internal/lockfile"
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
	if !bytes.Contains(stdout.Bytes(), []byte("delete table inet wg_mix_ebpf_guard")) {
		t.Fatalf("guard cleanup dry-run missing cleanup script: %s", stdout.String())
	}
}

func TestStopFallbackDetachDryRunOffline(t *testing.T) {
	cfgPath := writeTestConfig(t, "[Interface]\nFwMark = 0x10000002\n")
	dir := t.TempDir()
	fakeBin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fakeBin, "nft"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	runDir := filepath.Join(dir, "run")
	stateDir := filepath.Join(dir, "state")
	ctx := lockfile.WithLifecyclePathForTest(t.Context(), filepath.Join(dir, "daemon.lease"))
	var stdout, stderr bytes.Buffer
	if err := Run(ctx, []string{"stop", "--config", cfgPath, "--run-dir", runDir, "--state-dir", stateDir}, &stdout, &stderr); err != nil {
		t.Fatalf("stop fallback should tolerate missing runtime when there is no attach-state to detach: %v stderr=%s", err, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if err := Run(t.Context(), []string{"detach", "--config", cfgPath, "--offline", "--dry-run", "--run-dir", runDir, "--state-dir", stateDir}, &stdout, &stderr); err != nil {
		t.Fatalf("detach dry-run offline failed: %v stderr=%s", err, stderr.String())
	}
}

func TestWrongRunDirOneShotStopCannotRaceDaemon(t *testing.T) {
	dir := t.TempDir()
	leasePath := filepath.Join(dir, "daemon.lease")
	ctx := lockfile.WithLifecyclePathForTest(t.Context(), leasePath)
	lease, err := lockfile.AcquireLifecycle(ctx, lockfile.LifecycleOwner{
		PID:        os.Getpid(),
		Action:     "daemon",
		ConfigPath: "/etc/wg-mix-ebpf/config.yaml",
		RunDir:     "/run/real-daemon",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()

	var stdout, stderr bytes.Buffer
	err = Run(ctx, []string{
		"stop",
		"--config", filepath.Join(dir, "wrong.yaml"),
		"--run-dir", filepath.Join(dir, "wrong-run-dir"),
		"--state-dir", filepath.Join(dir, "wrong-state-dir"),
	}, &stdout, &stderr)
	if !errors.Is(err, lockfile.ErrLifecycleLeaseHeld) {
		t.Fatalf("wrong-run-dir stop error = %v, want held lifecycle lease", err)
	}
	if !strings.Contains(err.Error(), "/run/real-daemon") {
		t.Fatalf("wrong-run-dir stop error lacks real owner: %v", err)
	}
}

func TestStopExitRaceFallsBackThroughGlobalLifecycleLease(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(dir, "run")
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.yaml")
	status := daemon.Status{
		PID:             os.Getpid(),
		ConfigPath:      configPath,
		State:           "active",
		RequestProtocol: 1,
		InstanceID:      "0123456789abcdef0123456789abcdef",
	}
	writeStatus := func(status daemon.Status) error {
		data, err := json.Marshal(status)
		if err != nil {
			return err
		}
		tmp := filepath.Join(runDir, "status.json.next")
		if err := os.WriteFile(tmp, data, 0o644); err != nil {
			return err
		}
		return os.Rename(tmp, filepath.Join(runDir, "status.json"))
	}
	if err := writeStatus(status); err != nil {
		t.Fatal(err)
	}

	leasePath := filepath.Join(dir, "daemon.lease")
	ctx := lockfile.WithLifecyclePathForTest(t.Context(), leasePath)
	lease, err := lockfile.AcquireLifecycle(ctx, lockfile.LifecycleOwner{
		PID:        os.Getpid(),
		Action:     "daemon-cleanup",
		ConfigPath: configPath,
		RunDir:     runDir,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()

	statusUpdated := make(chan error, 1)
	go func() {
		deadline := time.Now().Add(time.Second)
		requestDir := filepath.Join(runDir, "requests")
		for time.Now().Before(deadline) {
			entries, err := os.ReadDir(requestDir)
			if err == nil {
				for _, entry := range entries {
					if strings.HasSuffix(entry.Name(), ".json") {
						status.PID = 1 << 30
						statusUpdated <- writeStatus(status)
						return
					}
				}
			}
			time.Sleep(5 * time.Millisecond)
		}
		statusUpdated <- errors.New("stop request was not enqueued")
	}()

	var stdout, stderr bytes.Buffer
	err = Run(ctx, []string{
		"stop",
		"--config", configPath,
		"--run-dir", runDir,
		"--state-dir", filepath.Join(dir, "state"),
		"--timeout", "1s",
	}, &stdout, &stderr)
	if updateErr := <-statusUpdated; updateErr != nil {
		t.Fatal(updateErr)
	}
	if !errors.Is(err, lockfile.ErrLifecycleLeaseHeld) {
		t.Fatalf("exit-race fallback error = %v, want global lifecycle ownership rejection", err)
	}
	if errors.Is(err, daemon.ErrDaemonNotRunning) {
		t.Fatalf("CLI returned request race instead of using safe one-shot fallback: %v", err)
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

func TestProfileAddTokenCheckAndRemoveForce(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	wgPath := filepath.Join(dir, "wg0.conf")
	if err := os.WriteFile(wgPath, []byte("[Interface]\nFwMark = 0x10000002\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte(`
version: 1
underlays:
  - name: eth0
    type: netdev
wireguards:
  - name: wg0
    config: `+wgPath+`
    profile: home
profiles:
  home:
    preset: wireguard-mix-wire-values-v1
`), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if err := Run(t.Context(), []string{"profile", "token", "home", "--config", cfgPath}, &stdout, &stderr); err != nil {
		t.Fatalf("token failed: %v", err)
	}
	token := strings.TrimSpace(stdout.String())
	stdout.Reset()
	if err := Run(t.Context(), []string{"profile", "check", token}, &stdout, &stderr); err != nil {
		t.Fatalf("check failed: %v", err)
	}
	stdout.Reset()
	if err := Run(t.Context(), []string{"profile", "add", "imported", "--config", cfgPath, "--token", token}, &stdout, &stderr); err != nil {
		t.Fatalf("add token failed: %v", err)
	}
	stdout.Reset()
	if err := Run(t.Context(), []string{"profile", "remove", "home", "--config", cfgPath}, &stdout, &stderr); err == nil {
		t.Fatal("expected referenced profile remove to require --force")
	}
	if err := Run(t.Context(), []string{"profile", "remove", "home", "--config", cfgPath, "--force"}, &stdout, &stderr); err != nil {
		t.Fatalf("remove force failed: %v", err)
	}
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("name: wg0")) {
		t.Fatalf("force remove should stop managing referenced wg: %s", data)
	}
}

func TestInitNonInteractiveCreatesConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	wgPath := filepath.Join(dir, "wg0.conf")
	if err := os.WriteFile(wgPath, []byte("[Interface]\nFwMark = 0x10000002\nListenPort = 31001\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	args := []string{"init", "--config", cfgPath, "--wg", "wg0", "--wg-config", wgPath, "--underlay", "eth0:netdev", "--profile", "home", "--profile-preset", "wireguard-mix-wire-values-v1"}
	if err := Run(t.Context(), args, &stdout, &stderr); err != nil {
		t.Fatalf("init failed: %v stderr=%s", err, stderr.String())
	}
	if err := Run(t.Context(), []string{"validate", "--config", cfgPath, "--offline"}, &stdout, &stderr); err != nil {
		t.Fatalf("validate initialized config failed: %v", err)
	}
}

func TestInstallDryRunUsesOverrides(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WG_MIX_EBPF_ETC_DIR", filepath.Join(dir, "etc"))
	t.Setenv("WG_MIX_EBPF_BINARY_PATH", filepath.Join(dir, "sbin", "wg-mix-ebpf"))
	t.Setenv("WG_MIX_EBPF_VAR_LIB_DIR", filepath.Join(dir, "varlib"))
	t.Setenv("WG_MIX_EBPF_RUN_DIR", filepath.Join(dir, "run"))
	t.Setenv("WG_MIX_EBPF_SYSTEMD_DIR", filepath.Join(dir, "systemd"))
	var stdout, stderr bytes.Buffer
	if err := Run(t.Context(), []string{"install", "--system", "systemd", "--dry-run", "--enable"}, &stdout, &stderr); err != nil {
		t.Fatalf("install dry-run failed: %v", err)
	}
	if !bytes.Contains(stdout.Bytes(), []byte("enable systemd service")) {
		t.Fatalf("install dry-run missing enable action: %s", stdout.String())
	}
}

func TestRunOnceDryOfflineWritesStatus(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeTestConfig(t, "[Interface]\nFwMark = 0x10000002\nListenPort = 31001\n")
	runDir := filepath.Join(dir, "run")
	var stdout, stderr bytes.Buffer
	if err := Run(t.Context(), []string{"run", "--config", cfgPath, "--run-dir", runDir, "--offline", "--dry-run", "--once"}, &stdout, &stderr); err != nil {
		t.Fatalf("run once failed: %v stderr=%s", err, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(runDir, "status.json")); err != nil {
		t.Fatalf("status not written: %v", err)
	}
}

func TestRunOfflineWithoutDryRunIsRejected(t *testing.T) {
	cfgPath := writeTestConfig(t, "[Interface]\nFwMark = 0x10000002\n")
	var stdout, stderr bytes.Buffer
	err := Run(t.Context(), []string{"run", "--config", cfgPath, "--offline", "--once"}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "requires --dry-run") {
		t.Fatalf("expected offline daemon rejection, got %v", err)
	}
}

func TestRunRejectsNegativeShutdownTimeout(t *testing.T) {
	cfgPath := writeTestConfig(t, "[Interface]\nFwMark = 0x10000002\n")
	var stdout, stderr bytes.Buffer
	err := Run(t.Context(), []string{
		"run",
		"--config", cfgPath,
		"--run-dir", t.TempDir(),
		"--offline",
		"--dry-run",
		"--once",
		"--shutdown-timeout=-1s",
	}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "shutdown timeout must not be negative") {
		t.Fatalf("expected shutdown timeout rejection, got %v", err)
	}
}

func TestReloadOfflineWithoutDryRunIsRejected(t *testing.T) {
	cfgPath := writeTestConfig(t, "[Interface]\nFwMark = 0x10000002\n")
	var stdout, stderr bytes.Buffer
	err := Run(t.Context(), []string{"reload", "--config", cfgPath, "--offline"}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "requires --dry-run") {
		t.Fatalf("expected offline reload rejection, got %v", err)
	}
}

func TestInitPreservesExistingTransportCipherAndParser(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	wgPath := filepath.Join(dir, "wg0.conf")
	if err := os.WriteFile(wgPath, []byte("[Interface]\nFwMark = 0x10000002\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte(`
version: 1
underlays:
  - name: eth0
    type: netdev
    parser: l3
wireguards:
  - name: wg0
    config: `+wgPath+`
    profile: home
    cipher: xor-home
    transport:
      mode: udp
profiles:
  home:
    preset: wireguard-mix-wire-values-v1
ciphers:
  xor-home:
    mode: xor
    key_derivation: udp2raw-md5-key1
    password: test-password
`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	args := []string{"init", "--config", cfgPath, "--wg", "wg0", "--wg-config", wgPath, "--underlay", "eth0:netdev", "--profile", "home"}
	if err := Run(t.Context(), args, &stdout, &stderr); err != nil {
		t.Fatalf("init failed: %v stderr=%s", err, stderr.String())
	}
	cfg, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Underlays[0].Parser; got != "l3" {
		t.Fatalf("underlay parser was overwritten: %q", got)
	}
	if got := cfg.WireGuards[0].Cipher; got != "xor-home" {
		t.Fatalf("cipher was overwritten: %q", got)
	}
	if got := cfg.WireGuards[0].Transport.Mode; got != "udp" {
		t.Fatalf("transport was overwritten: %q", got)
	}
}

func TestDumpABIRedactsCipherKey(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(`
version: 1
underlays: []
wireguards: []
profiles: {}
ciphers:
  xor:
    mode: xor
    key_derivation: udp2raw-md5-key1
    password: highly-sensitive
`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := Run(t.Context(), []string{"dump-abi", "--config", cfgPath, "--offline"}, &stdout, &stderr); err != nil {
		t.Fatalf("dump-abi failed: %v", err)
	}
	if strings.Contains(stdout.String(), `"Key":`) || !strings.Contains(stdout.String(), `"KeyRedacted": true`) {
		t.Fatalf("dump-abi did not redact cipher key: %s", stdout.String())
	}
}

func TestInitRefusesToOverwriteExistingProfile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	wgPath := filepath.Join(dir, "wg0.conf")
	if err := os.WriteFile(wgPath, []byte("[Interface]\nFwMark = 0x10000002\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte(`
version: 1
underlays: []
wireguards: []
profiles:
  home:
    preset: wireguard-mix-wire-values-v1
`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	args := []string{"init", "--config", cfgPath, "--wg", "wg0", "--wg-config", wgPath, "--underlay", "eth0:netdev", "--profile", "home", "--profile-random"}
	if err := Run(t.Context(), args, &stdout, &stderr); err == nil {
		t.Fatal("expected init to refuse overwriting existing profile")
	}
}
