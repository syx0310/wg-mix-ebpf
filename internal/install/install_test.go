package install

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
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
	readyPath := filepath.Join(dir, "nft-ready")
	releasePath := filepath.Join(dir, "nft-release")
	for _, path := range []string{readyPath, releasePath} {
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			t.Fatalf("create fake nft control FIFO %s: %v", path, err)
		}
	}
	readyFIFO, err := os.OpenFile(readyPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open fake nft readiness FIFO: %v", err)
	}
	t.Cleanup(func() {
		if err := readyFIFO.Close(); err != nil {
			t.Errorf("close fake nft readiness FIFO: %v", err)
		}
	})
	releaseFIFO, err := os.OpenFile(releasePath, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open fake nft release FIFO: %v", err)
	}
	t.Cleanup(func() {
		if err := releaseFIFO.Close(); err != nil {
			t.Errorf("close fake nft release FIFO: %v", err)
		}
	})
	if err := os.WriteFile(filepath.Join(fakeBin, "nft"), []byte(
		"#!/bin/sh\n"+
			"set -eu\n"+
			"printf '%s\\000' \"$#\" \"$@\" >\"$WG_MIX_EBPF_TEST_NFT_READY_FIFO\"\n"+
			"IFS= read -r control <\"$WG_MIX_EBPF_TEST_NFT_RELEASE_FIFO\"\n"+
			"[ \"$control\" = continue ] || exit 70\n"+
			"printf '%s\\n' 'Error: No such file or directory' 'list table inet wg_mix_ebpf_guard' >&2\n"+
			"exit 1\n",
	), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("WG_MIX_EBPF_TEST_NFT_READY_FIFO", readyPath)
	t.Setenv("WG_MIX_EBPF_TEST_NFT_RELEASE_FIFO", releasePath)
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

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ctx = lockfile.WithLifecyclePathForTest(ctx, filepath.Join(dir, "daemon.lease"))

	uninstallDone := make(chan error, 1)
	go func() {
		_, err := Uninstall(ctx, Options{ConfigPath: configPath, System: "unknown", Yes: true})
		uninstallDone <- err
	}()

	wantArgs := []string{"-j", "-a", "list", "table", "inet", "wg_mix_ebpf_guard"}
	type readyResult struct {
		args []string
		err  error
	}
	nftReady := make(chan readyResult, 1)
	go func() {
		const (
			maxNftArgs     = 16
			maxNftArgBytes = 256
		)
		reader := bufio.NewReaderSize(readyFIFO, maxNftArgBytes+1)
		readField := func() (string, error) {
			field, err := reader.ReadSlice(0)
			if errors.Is(err, bufio.ErrBufferFull) {
				return "", fmt.Errorf("fake nft protocol field exceeds %d bytes", maxNftArgBytes)
			}
			if err != nil {
				return "", fmt.Errorf("read fake nft protocol field: %w", err)
			}
			field = field[:len(field)-1]
			if len(field) > maxNftArgBytes {
				return "", fmt.Errorf("fake nft protocol field is %d bytes, maximum is %d", len(field), maxNftArgBytes)
			}
			return string(field), nil
		}

		argcField, err := readField()
		if err != nil {
			nftReady <- readyResult{err: err}
			return
		}
		argc, err := strconv.Atoi(argcField)
		if err != nil || argc < 0 || argc > maxNftArgs {
			nftReady <- readyResult{err: fmt.Errorf("fake nft argc %q is outside 0..%d", argcField, maxNftArgs)}
			return
		}
		if argc != len(wantArgs) {
			nftReady <- readyResult{err: fmt.Errorf("fake nft argc = %d, want %d", argc, len(wantArgs))}
			return
		}
		args := make([]string, argc)
		for i := range args {
			args[i], err = readField()
			if err != nil {
				nftReady <- readyResult{err: fmt.Errorf("read fake nft argv[%d]: %w", i, err)}
				return
			}
		}
		nftReady <- readyResult{args: args}
	}()

	// Keep the watchdog outside ctx: a deadline on ctx also kills the fake nft
	// subprocess and turns slow process scheduling into a false deadlock result.
	// The FIFO handshake proves that uninstall crossed the nested-lock boundary.
	const deadlockWatchdog = 30 * time.Second
	readyWatchdog := time.NewTimer(deadlockWatchdog)
	select {
	case result := <-nftReady:
		readyWatchdog.Stop()
		if result.err != nil {
			t.Fatalf("read fake nft readiness: %v", result.err)
		}
		for i := range wantArgs {
			if result.args[i] != wantArgs[i] {
				t.Fatalf("fake nft argv[%d] = %q, want %q", i, result.args[i], wantArgs[i])
			}
		}
	case err := <-uninstallDone:
		readyWatchdog.Stop()
		t.Fatalf("uninstall returned before fake nft inspection: %v", err)
	case <-readyWatchdog.C:
		cancel()
		t.Fatal("uninstall did not reach fake nft inspection; possible nested lock deadlock")
	}

	if _, err := releaseFIFO.WriteString("continue\n"); err != nil {
		t.Fatalf("release fake nft inspection: %v", err)
	}
	completionWatchdog := time.NewTimer(deadlockWatchdog)
	select {
	case err := <-uninstallDone:
		completionWatchdog.Stop()
		if err != nil {
			t.Fatalf("uninstall should complete without nested lock deadlock: %v", err)
		}
	case <-completionWatchdog.C:
		cancel()
		t.Fatal("uninstall did not complete after fake nft inspection was released")
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
