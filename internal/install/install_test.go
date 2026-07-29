package install

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/attachstate"
	"github.com/syx0310/wg-mix-ebpf/internal/config"
	"github.com/syx0310/wg-mix-ebpf/internal/daemon"
	"github.com/syx0310/wg-mix-ebpf/internal/lockfile"
)

func TestUninstallPurgeRejectsNonOwnedConfigDir(t *testing.T) {
	t.Setenv(EnvEtcDir, filepath.Join(t.TempDir(), "wg-mix-ebpf-owned"))
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

func TestUninstallPurgeAllowsOwnedEmptyConfigDir(t *testing.T) {
	root := t.TempDir()
	etcDir := filepath.Join(root, "wg-mix-ebpf-owned")
	t.Setenv(EnvEtcDir, etcDir)
	plan, err := Uninstall(t.Context(), Options{
		ConfigPath: filepath.Join(etcDir, "config.yaml"),
		System:     "unknown",
		DryRun:     true,
		Purge:      true,
	})
	if err != nil {
		t.Fatalf("expected owned empty purge dry-run to pass: %v", err)
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
	if !strings.Contains(script, "/run/wg-mix-ebpf/runtime.request") ||
		strings.Contains(script, "/run/wg-mix-ebpf/reload.request") {
		t.Fatalf("hotplug must not overwrite acknowledged CLI request files:\n%s", script)
	}
}

func TestInstallRejectsHeldGlobalLifecycleLeaseBeforeWrites(t *testing.T) {
	root := t.TempDir()
	layout := cleanupTestPaths(root, "install-held")
	setCleanupTestEnvironment(t, layout)
	ctx := lockfile.WithLifecyclePathsForTest(
		t.Context(),
		filepath.Join(root, "daemon.lease"),
		filepath.Join(root, "maintenance.gate"),
	)
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
	for _, path := range []string{layout.ConfigPath, layout.BinaryPath, layout.RunDir} {
		if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("install wrote %s before acquiring lifecycle ownership: %v", path, statErr)
		}
	}
}

func TestUninstallRejectsHeldGlobalLifecycleLeaseBeforeCleanup(t *testing.T) {
	layout := newCleanupTestLayout(t, "uninstall-held")
	attachStatePath := attachstate.Path(layout.VarLibDir)
	if err := attachstate.Save(layout.VarLibDir, &attachstate.State{
		Version:    1,
		ConfigPath: layout.ConfigPath,
	}); err != nil {
		t.Fatal(err)
	}
	setCleanupTestEnvironment(t, layout)

	lifecycleRoot := t.TempDir()
	ctx := lockfile.WithLifecyclePathsForTest(
		t.Context(),
		filepath.Join(lifecycleRoot, "daemon.lease"),
		filepath.Join(lifecycleRoot, "maintenance.gate"),
	)
	lease, err := lockfile.AcquireLifecycle(ctx, lockfile.LifecycleOwner{
		PID:    os.Getpid(),
		Action: "daemon",
		RunDir: "/run/real-daemon",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()

	_, err = Uninstall(ctx, Options{
		ConfigPath: layout.ConfigPath,
		System:     "unknown",
		Yes:        true,
	})
	if !errors.Is(err, lockfile.ErrLifecycleLeaseHeld) {
		t.Fatalf("uninstall error = %v, want held lifecycle lease", err)
	}
	if _, err := os.Stat(attachStatePath); err != nil {
		t.Fatalf("uninstall cleaned state before acquiring lifecycle ownership: %v", err)
	}
}

func TestUninstallKeepsBinaryHint(t *testing.T) {
	root := t.TempDir()
	layout := cleanupTestPaths(root, "hint")
	setCleanupTestEnvironment(t, layout)
	plan, err := Uninstall(t.Context(), Options{
		ConfigPath: layout.ConfigPath,
		System:     "unknown",
		DryRun:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !containsAction(plan.Actions, "binary removal hint") {
		t.Fatalf("missing binary removal hint: %#v", plan.Actions)
	}
}

func TestUninstallDoesNotDeadlockWhenConfigExists(t *testing.T) {
	layout := newCleanupTestLayout(t, "deadlock")
	setCleanupTestEnvironment(t, layout)
	controlDir := t.TempDir()
	fakeBin := filepath.Join(controlDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatal(err)
	}
	readyPath := filepath.Join(controlDir, "nft-ready")
	releasePath := filepath.Join(controlDir, "nft-release")
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

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	lifecycleRoot := t.TempDir()
	ctx = lockfile.WithLifecyclePathsForTest(
		ctx,
		filepath.Join(lifecycleRoot, "daemon.lease"),
		filepath.Join(lifecycleRoot, "maintenance.gate"),
	)

	uninstallDone := make(chan error, 1)
	go func() {
		_, err := Uninstall(ctx, Options{ConfigPath: layout.ConfigPath, System: "unknown", Yes: true})
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

func TestRepeatedUninstallDoesNotLeaveRecreatedRuntime(t *testing.T) {
	layout := newCleanupTestLayout(t, "repeat")
	setCleanupTestEnvironment(t, layout)
	installFakeNft(t, "")
	lifecycleRoot := t.TempDir()
	ctx := lockfile.WithLifecyclePathsForTest(
		t.Context(),
		filepath.Join(lifecycleRoot, "daemon.lease"),
		filepath.Join(lifecycleRoot, "maintenance.gate"),
	)

	for attempt := 1; attempt <= 2; attempt++ {
		if _, err := Uninstall(ctx, Options{
			ConfigPath: layout.ConfigPath,
			System:     "unknown",
			Yes:        true,
		}); err != nil {
			t.Fatalf("uninstall attempt %d: %v", attempt, err)
		}
		if _, err := os.Stat(layout.RunDir); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("uninstall attempt %d left or recreated runtime dir: %v", attempt, err)
		}
		if _, err := os.Stat(cleanupManifestPath(layout)); err != nil {
			t.Fatalf("uninstall attempt %d removed retained ownership manifest: %v", attempt, err)
		}
	}
}

func TestUninstallPurgeRemovesOwnedConfigAndIsIdempotent(t *testing.T) {
	layout := newCleanupTestLayout(t, "purge-success")
	setCleanupTestEnvironment(t, layout)
	installFakeNft(t, "")
	lifecycleRoot := t.TempDir()
	ctx := lockfile.WithLifecyclePathsForTest(
		t.Context(),
		filepath.Join(lifecycleRoot, "daemon.lease"),
		filepath.Join(lifecycleRoot, "maintenance.gate"),
	)
	opts := Options{
		ConfigPath: layout.ConfigPath,
		System:     "unknown",
		Yes:        true,
		Purge:      true,
	}

	for attempt := 1; attempt <= 2; attempt++ {
		if _, err := Uninstall(ctx, opts); err != nil {
			t.Fatalf("purge attempt %d: %v", attempt, err)
		}
		if _, err := os.Stat(filepath.Dir(layout.ConfigPath)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("purge attempt %d retained owned config dir: %v", attempt, err)
		}
	}
}

func TestUninstallPurgeIsIdempotentWithRetainedLifecycleLease(t *testing.T) {
	layout := newCleanupTestLayout(t, "purge-retained-lease")
	setCleanupTestEnvironment(t, layout)
	installFakeNft(t, "")
	lifecyclePath := filepath.Join(layout.RunDir, "daemon.lease")
	ctx := lockfile.WithLifecyclePathForTest(t.Context(), lifecyclePath)
	opts := Options{
		ConfigPath: layout.ConfigPath,
		System:     "unknown",
		Yes:        true,
		Purge:      true,
	}

	if _, err := Uninstall(ctx, opts); err != nil {
		t.Fatal(err)
	}
	leaseBefore, err := os.Stat(lifecyclePath)
	if err != nil {
		t.Fatalf("purge removed retained lifecycle lease: %v", err)
	}
	entries, err := os.ReadDir(layout.RunDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "daemon.lease" {
		t.Fatalf("purge retained unexpected runtime entries: %#v", entries)
	}
	if _, err := os.Stat(filepath.Dir(layout.ConfigPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("purge retained config ownership directory: %v", err)
	}

	if _, err := Uninstall(ctx, opts); err != nil {
		t.Fatalf("second purge with retained lifecycle lease: %v", err)
	}
	leaseAfter, err := os.Stat(lifecyclePath)
	if err != nil {
		t.Fatalf("second purge changed retained lifecycle lease: %v", err)
	}
	if !os.SameFile(leaseBefore, leaseAfter) {
		t.Fatal("second purge replaced the retained lifecycle lease")
	}
}

func TestUninstallPurgeRetainsOwnershipUntilDaemonReloadSucceeds(t *testing.T) {
	layout := newCleanupTestLayoutForSystem(t, "purge-reload-retry", "systemd")
	setCleanupTestEnvironment(t, layout)
	installFakeNft(t, "")
	commandLog := filepath.Join(t.TempDir(), "systemctl.log")
	installFakeSystemctl(t, commandLog, "daemon-reload")
	ctx := lockfile.WithLifecyclePathForTest(
		t.Context(),
		filepath.Join(t.TempDir(), "daemon.lease"),
	)
	opts := Options{
		ConfigPath: layout.ConfigPath,
		System:     "systemd",
		Yes:        true,
		Purge:      true,
	}

	_, err := Uninstall(ctx, opts)
	if err == nil || !strings.Contains(err.Error(), "daemon-reload") {
		t.Fatalf("first purge error = %v, want daemon-reload failure", err)
	}
	unitPath := filepath.Join(layout.SystemdDir, "wg-mix-ebpf.service")
	if _, err := os.Stat(unitPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed daemon-reload retained systemd unit: %v", err)
	}
	for _, path := range []string{
		cleanupManifestPath(layout),
		layout.ConfigPath,
		layout.RunDir,
		layout.VarLibDir,
		layout.PinPath,
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("failed daemon-reload removed retry ownership target %s: %v", path, err)
		}
	}

	t.Setenv("WG_MIX_EBPF_TEST_SYSTEMCTL_FAIL", "")
	if _, err := Uninstall(ctx, opts); err != nil {
		t.Fatalf("retry purge after daemon-reload recovery: %v", err)
	}
	for _, path := range []string{
		filepath.Dir(layout.ConfigPath),
		layout.RunDir,
		layout.VarLibDir,
		layout.PinPath,
	} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("retry purge retained %s: %v", path, err)
		}
	}
	logData, err := os.ReadFile(commandLog)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(logData), "daemon-reload\n") != 2 {
		t.Fatalf("systemctl log = %q, want two daemon-reload attempts", logData)
	}
}

func TestUninstallRejectsDangerousCleanupPaths(t *testing.T) {
	t.Setenv(dataplaneEnvPinPathForTest, "/sys/fs/bpf")
	_, err := Uninstall(t.Context(), Options{System: "unknown", DryRun: true})
	if err == nil || !strings.Contains(err.Error(), "unsafe BPF pin path") {
		t.Fatalf("expected dangerous pin path rejection, got %v", err)
	}
}

func TestValidateCleanupPathsRejectsBroadAndNonProjectPaths(t *testing.T) {
	root := t.TempDir()
	safe := cleanupTestPaths(root, "safe")
	tests := []struct {
		name   string
		mutate func(*paths)
		want   string
	}{
		{
			name:   "runtime service directory",
			mutate: func(p *paths) { p.RunDir = "/run/systemd" },
			want:   "unsafe runtime dir",
		},
		{
			name:   "state service directory",
			mutate: func(p *paths) { p.VarLibDir = "/var/lib/systemd" },
			want:   "unsafe state dir",
		},
		{
			name:   "unrelated BPF subtree",
			mutate: func(p *paths) { p.PinPath = "/sys/fs/bpf/cilium" },
			want:   "unsafe BPF pin path",
		},
		{
			name:   "wide runtime root",
			mutate: func(p *paths) { p.RunDir = "/run" },
			want:   "unsafe runtime dir",
		},
		{
			name:   "relative state path",
			mutate: func(p *paths) { p.VarLibDir = "wg-mix-ebpf-state" },
			want:   "unsafe state dir",
		},
		{
			name:   "non-clean pin path",
			mutate: func(p *paths) { p.PinPath = "/sys/fs/bpf/../bpf/wg-mix-ebpf-test" },
			want:   "non-clean BPF pin path",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := safe
			test.mutate(&candidate)
			err := validateCleanupPaths(candidate)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validateCleanupPaths error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestOpenManagedCleanupDirRejectsFileAndSymlinkTargets(t *testing.T) {
	root := t.TempDir()
	fileTarget := filepath.Join(root, "wg-mix-ebpf-run-file")
	if err := os.WriteFile(fileTarget, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := openManagedCleanupDir(runtimeCleanupPath(fileTarget)); err == nil {
		t.Fatal("ordinary-file target should be rejected")
	}
	if data, err := os.ReadFile(fileTarget); err != nil || string(data) != "keep\n" {
		t.Fatalf("ordinary-file target changed: data=%q err=%v", data, err)
	}

	realTarget := filepath.Join(t.TempDir(), "real")
	if err := os.Mkdir(realTarget, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(realTarget, "keep")
	if err := os.WriteFile(marker, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlinkTarget := filepath.Join(root, "wg-mix-ebpf-run-link")
	if err := os.Symlink(realTarget, symlinkTarget); err != nil {
		t.Fatal(err)
	}
	if _, _, err := openManagedCleanupDir(runtimeCleanupPath(symlinkTarget)); err == nil {
		t.Fatal("symlink target should be rejected")
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("symlink target contents changed: %v", err)
	}
}

func TestOpenManagedCleanupDirRejectsSymlinkedParent(t *testing.T) {
	root := t.TempDir()
	realParent := filepath.Join(t.TempDir(), "real-parent")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	linkParent := filepath.Join(root, "parent")
	if err := os.Symlink(realParent, linkParent); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(linkParent, "wg-mix-ebpf-run-parent-link")
	if _, _, err := openManagedCleanupDir(runtimeCleanupPath(target)); err == nil {
		t.Fatal("symlinked parent should be rejected")
	}
}

func TestOpenManagedCleanupDirRejectsMountIdentityChange(t *testing.T) {
	target := filepath.Join(t.TempDir(), "wg-mix-ebpf-run-other-fs")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	_, _, err := openManagedCleanupDirWithOptions(
		runtimeCleanupPath(target),
		managedDirOpenOptions{identityHook: func(path string, identity *cleanupIdentity) {
			if filepath.Clean(path) == filepath.Clean(target) {
				identity.MountKnown = true
				identity.MountID++
			}
		}},
	)
	if err == nil || !strings.Contains(err.Error(), "crosses a mount boundary") {
		t.Fatalf("mount-boundary error = %v, want rejection", err)
	}
}

func TestInstallBinaryReplacesModeAtomically(t *testing.T) {
	target := filepath.Join(t.TempDir(), "wg-mix-ebpf")
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
	stateDir := filepath.Join(t.TempDir(), "state")
	if err := attachstate.Save(stateDir, &attachstate.State{Version: 1}); err != nil {
		t.Fatal(err)
	}
	candidate := paths{ConfigPath: filepath.Join(t.TempDir(), "missing.yaml"), VarLibDir: stateDir}
	if !shouldStopForUninstall(candidate) {
		t.Fatal("uninstall should run stop cleanup when attach-state exists even if config is missing")
	}
}

func TestInstallWritesCleanupOwnershipManifest(t *testing.T) {
	root := t.TempDir()
	layout := cleanupTestPaths(root, "install")
	setCleanupTestEnvironment(t, layout)
	ctx := lockfile.WithLifecyclePathsForTest(
		t.Context(),
		filepath.Join(root, "daemon.lease"),
		filepath.Join(root, "maintenance.gate"),
	)
	if _, err := Install(ctx, Options{System: "unknown"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(cleanupManifestPath(layout))
	if err != nil {
		t.Fatal(err)
	}
	var manifest cleanupManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if err := manifest.validateAgainst(layout, "unknown"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(cleanupManifestPath(layout))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("manifest mode = %#o, want 0600", info.Mode().Perm())
	}
}

func TestInstallRequiresExplicitAdoptionBeforeWrites(t *testing.T) {
	layout := newUnmarkedCleanupTestLayout(t, "adoption-required", "unknown")
	setCleanupTestEnvironment(t, layout)
	configBefore, err := os.ReadFile(layout.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(layout.RunDir, "lock")
	lockBefore, err := os.Stat(lockPath)
	if err != nil {
		t.Fatal(err)
	}

	lifecycleRoot := t.TempDir()
	_, err = Install(
		lockfile.WithLifecyclePathsForTest(
			t.Context(),
			filepath.Join(lifecycleRoot, "daemon.lease"),
			filepath.Join(lifecycleRoot, "maintenance.gate"),
		),
		Options{System: "unknown"},
	)
	if err == nil || !strings.Contains(err.Error(), "--adopt-existing") {
		t.Fatalf("install error = %v, want explicit-adoption rejection", err)
	}
	for _, path := range []string{cleanupManifestPath(layout), layout.BinaryPath} {
		if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("install wrote %s before explicit adoption: %v", path, statErr)
		}
	}
	configAfter, err := os.ReadFile(layout.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(configAfter) != string(configBefore) {
		t.Fatal("rejected adoption changed the existing config")
	}
	lockAfter, err := os.Stat(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(lockBefore, lockAfter) {
		t.Fatal("rejected adoption replaced the existing runtime lock")
	}
}

func TestInstallExplicitlyAdoptsValidatedResources(t *testing.T) {
	layout := newUnmarkedCleanupTestLayout(t, "adoption-approved", "unknown")
	setCleanupTestEnvironment(t, layout)

	lifecycleRoot := t.TempDir()
	plan, err := Install(
		lockfile.WithLifecyclePathsForTest(
			t.Context(),
			filepath.Join(lifecycleRoot, "daemon.lease"),
			filepath.Join(lifecycleRoot, "maintenance.gate"),
		),
		Options{System: "unknown", AdoptExisting: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !containsAction(plan.Actions, "adopt strictly validated existing resources") {
		t.Fatalf("install plan omitted explicit adoption: %#v", plan.Actions)
	}
	data, err := os.ReadFile(cleanupManifestPath(layout))
	if err != nil {
		t.Fatal(err)
	}
	var manifest cleanupManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if err := manifest.validateAgainst(layout, "unknown"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(layout.BinaryPath); err != nil {
		t.Fatalf("explicit adoption did not finish installation: %v", err)
	}
}

func TestInstallDryRunValidatesExplicitAdoptionWithoutWrites(t *testing.T) {
	layout := newUnmarkedCleanupTestLayout(t, "adoption-dry-run", "unknown")
	setCleanupTestEnvironment(t, layout)

	if _, err := Install(t.Context(), Options{
		System: "unknown",
		DryRun: true,
	}); err == nil || !strings.Contains(err.Error(), "--adopt-existing") {
		t.Fatalf("dry-run error = %v, want explicit-adoption rejection", err)
	}
	plan, err := Install(t.Context(), Options{
		System:        "unknown",
		DryRun:        true,
		AdoptExisting: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !containsAction(plan.Actions, "adopt strictly validated existing resources") {
		t.Fatalf("dry-run plan omitted explicit adoption: %#v", plan.Actions)
	}
	for _, path := range []string{cleanupManifestPath(layout), layout.BinaryPath} {
		if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("dry-run adoption wrote %s: %v", path, statErr)
		}
	}
}

func TestInstallFreshRecheckRejectsUnmarkedLayoutInjectedAfterPreflight(t *testing.T) {
	layout := cleanupTestPaths(t.TempDir(), "fresh-recheck-race")
	setCleanupTestEnvironment(t, layout)
	var configBefore []byte
	var configIdentity os.FileInfo
	var lockIdentity os.FileInfo
	hookRan := false
	hook := func() error {
		hookRan = true
		if err := populateUnmarkedCleanupTestLayout(layout, "unknown"); err != nil {
			return err
		}
		var err error
		configBefore, err = os.ReadFile(layout.ConfigPath)
		if err != nil {
			return err
		}
		configIdentity, err = os.Stat(layout.ConfigPath)
		if err != nil {
			return err
		}
		lockIdentity, err = os.Stat(filepath.Join(layout.RunDir, "lock"))
		return err
	}
	lifecycleRoot := t.TempDir()
	ctx := context.WithValue(
		lockfile.WithLifecyclePathsForTest(
			t.Context(),
			filepath.Join(lifecycleRoot, "daemon.lease"),
			filepath.Join(lifecycleRoot, "maintenance.gate"),
		),
		installAfterInspectHookContextKey{},
		hook,
	)

	_, err := Install(ctx, Options{System: "unknown"})
	if err == nil || !strings.Contains(err.Error(), "resources appeared") {
		t.Fatalf("install error = %v, want locked fresh-resource rejection", err)
	}
	if !hookRan {
		t.Fatal("post-inspection injection hook did not run")
	}
	for _, path := range []string{cleanupManifestPath(layout), layout.BinaryPath} {
		if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("fresh-race rejection wrote %s: %v", path, statErr)
		}
	}
	configAfter, err := os.ReadFile(layout.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(configAfter) != string(configBefore) {
		t.Fatal("fresh-race rejection changed the injected config")
	}
	configAfterIdentity, err := os.Stat(layout.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(configIdentity, configAfterIdentity) {
		t.Fatal("fresh-race rejection replaced the injected config")
	}
	lockAfterIdentity, err := os.Stat(filepath.Join(layout.RunDir, "lock"))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(lockIdentity, lockAfterIdentity) {
		t.Fatal("fresh-race rejection replaced the injected operation lock")
	}
	for _, path := range []string{layout.VarLibDir, layout.PinPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("fresh-race rejection changed injected directory %s: %v", path, err)
		}
	}
}

func TestWriteCleanupManifestPreservesValidatedMarkerIdentity(t *testing.T) {
	layout := newCleanupTestLayout(t, "marker-idempotent")
	markerPath := cleanupManifestPath(layout)
	before, err := os.Stat(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeCleanupManifest(layout, "unknown", cleanupManifestWriteOptions{}); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("idempotent manifest write replaced the validated marker inode")
	}
}

func TestWriteCleanupManifestRefusesUnknownUnmarkedResource(t *testing.T) {
	layout := cleanupTestPaths(t.TempDir(), "marker-bootstrap")
	for _, dir := range []string{
		filepath.Dir(layout.ConfigPath),
		layout.RunDir,
		layout.VarLibDir,
		layout.PinPath,
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := config.SaveFile(layout.ConfigPath, config.SafeTemplate()); err != nil {
		t.Fatal(err)
	}
	foreignPath := filepath.Join(layout.RunDir, "foreign")
	if err := os.WriteFile(foreignPath, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := writeCleanupManifest(
		layout,
		"unknown",
		cleanupManifestWriteOptions{AdoptExisting: true},
	)
	if err == nil || !strings.Contains(err.Error(), "unmarked runtime") {
		t.Fatalf("manifest bootstrap error = %v, want foreign-resource rejection", err)
	}
	if _, statErr := os.Stat(cleanupManifestPath(layout)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed bootstrap installed ownership marker: %v", statErr)
	}
	if data, readErr := os.ReadFile(foreignPath); readErr != nil || string(data) != "keep\n" {
		t.Fatalf("failed bootstrap changed foreign resource: data=%q err=%v", data, readErr)
	}
}

func TestPrepareCleanupRejectsForeignSameNameWithoutManifest(t *testing.T) {
	layout := cleanupTestPaths(t.TempDir(), "foreign-no-marker")
	for _, dir := range []string{
		filepath.Dir(layout.ConfigPath),
		layout.RunDir,
		layout.VarLibDir,
		layout.PinPath,
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	statusPath := filepath.Join(layout.RunDir, "status.json")
	if err := os.WriteFile(statusPath, []byte("foreign\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := prepareUninstallCleanup(
		layout,
		"unknown",
		false,
		filepath.Join(t.TempDir(), "daemon.lease"),
	)
	if err == nil || !strings.Contains(err.Error(), "ownership manifest") {
		t.Fatalf("prepare error = %v, want ownership-manifest rejection", err)
	}
	if data, readErr := os.ReadFile(statusPath); readErr != nil || string(data) != "foreign\n" {
		t.Fatalf("foreign same-name file changed: data=%q err=%v", data, readErr)
	}
}

func TestPrepareCleanupRejectsForeignSameNameContent(t *testing.T) {
	layout := newCleanupTestLayout(t, "foreign-content")
	statusPath := filepath.Join(layout.RunDir, "status.json")
	if err := os.WriteFile(statusPath, []byte("not project json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := prepareUninstallCleanup(
		layout,
		"unknown",
		false,
		filepath.Join(t.TempDir(), "daemon.lease"),
	)
	if err == nil || !strings.Contains(err.Error(), "validate managed file") {
		t.Fatalf("prepare error = %v, want content-identity rejection", err)
	}
	if data, readErr := os.ReadFile(statusPath); readErr != nil || string(data) != "not project json\n" {
		t.Fatalf("foreign same-name file changed: data=%q err=%v", data, readErr)
	}
}

func TestPrepareCleanupRejectsSymlinkedRetainedConfig(t *testing.T) {
	layout := newCleanupTestLayout(t, "config-link")
	foreignConfig := filepath.Join(t.TempDir(), "config.yaml")
	if err := config.SaveFile(foreignConfig, config.SafeTemplate()); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(layout.ConfigPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(foreignConfig, layout.ConfigPath); err != nil {
		t.Fatal(err)
	}
	_, err := prepareUninstallCleanup(
		layout,
		"unknown",
		false,
		filepath.Join(t.TempDir(), "daemon.lease"),
	)
	if err == nil {
		t.Fatal("retained config symlink should be rejected before stop")
	}
	if _, statErr := os.Stat(foreignConfig); statErr != nil {
		t.Fatalf("foreign config behind symlink changed: %v", statErr)
	}
}

func TestGlobalPreflightLateFailureLeavesEarlierTargetsUntouched(t *testing.T) {
	layout := newCleanupTestLayout(t, "global-preflight")
	statusPath := writeCleanupTestStatus(t, layout)
	statePath := attachstate.Path(layout.VarLibDir)
	if err := attachstate.Save(layout.VarLibDir, &attachstate.State{
		Version:    1,
		ConfigPath: layout.ConfigPath,
	}); err != nil {
		t.Fatal(err)
	}
	unknownPath := filepath.Join(layout.VarLibDir, "foreign")
	if err := os.WriteFile(unknownPath, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	setCleanupTestEnvironment(t, layout)
	commandLog := filepath.Join(t.TempDir(), "nft-invoked")
	installFakeNft(t, commandLog)
	lifecycleRoot := t.TempDir()
	ctx := lockfile.WithLifecyclePathsForTest(
		t.Context(),
		filepath.Join(lifecycleRoot, "daemon.lease"),
		filepath.Join(lifecycleRoot, "maintenance.gate"),
	)
	_, err := Uninstall(ctx, Options{
		ConfigPath: layout.ConfigPath,
		System:     "unknown",
		Yes:        true,
	})
	if err == nil || !strings.Contains(err.Error(), "unknown state entry") {
		t.Fatalf("uninstall error = %v, want late state rejection", err)
	}
	for _, path := range []string{statusPath, statePath, unknownPath} {
		if _, statErr := os.Stat(path); statErr != nil {
			t.Fatalf("global preflight removed %s: %v", path, statErr)
		}
	}
	if _, statErr := os.Stat(commandLog); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("global preflight invoked reconcile/guard command before rejecting late target: %v", statErr)
	}
}

func TestCleanupPlanRejectsManagedDirectoryReplacement(t *testing.T) {
	layout := newCleanupTestLayout(t, "dir-swap")
	statusPath := writeCleanupTestStatus(t, layout)
	plan, err := prepareUninstallCleanup(
		layout,
		"unknown",
		false,
		filepath.Join(t.TempDir(), "daemon.lease"),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.close()
	originalRunDir := layout.RunDir + "-original"
	foreignDir := filepath.Join(t.TempDir(), "foreign")
	if err := os.Mkdir(foreignDir, 0o700); err != nil {
		t.Fatal(err)
	}
	foreignStatus := filepath.Join(foreignDir, "status.json")
	if err := os.WriteFile(foreignStatus, []byte("foreign\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan.beforeExecute = func() error {
		if err := os.Rename(layout.RunDir, originalRunDir); err != nil {
			return err
		}
		return os.Symlink(foreignDir, layout.RunDir)
	}
	err = plan.execute()
	if err == nil {
		t.Fatal("directory replacement should be rejected")
	}
	if data, readErr := os.ReadFile(foreignStatus); readErr != nil || string(data) != "foreign\n" {
		t.Fatalf("foreign target changed: data=%q err=%v", data, readErr)
	}
	if _, statErr := os.Stat(filepath.Join(originalRunDir, filepath.Base(statusPath))); statErr != nil {
		t.Fatalf("original managed file was removed: %v", statErr)
	}
}

func TestCleanupPlanRejectsFileInodeReplacement(t *testing.T) {
	layout := newCleanupTestLayout(t, "file-swap")
	statusPath := writeCleanupTestStatus(t, layout)
	plan, err := prepareUninstallCleanup(
		layout,
		"unknown",
		false,
		filepath.Join(t.TempDir(), "daemon.lease"),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.close()
	originalStatus := filepath.Join(t.TempDir(), "status.original")
	plan.beforeExecute = func() error {
		if err := os.Rename(statusPath, originalStatus); err != nil {
			return err
		}
		return os.WriteFile(statusPath, []byte("{}\n"), 0o600)
	}
	err = plan.execute()
	if err == nil || !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("execute error = %v, want inode replacement rejection", err)
	}
	for _, path := range []string{statusPath, originalStatus} {
		if _, statErr := os.Stat(path); statErr != nil {
			t.Fatalf("replacement preflight removed %s: %v", path, statErr)
		}
	}
}

func TestCleanupPlanRejectsSameInodeContentReplacement(t *testing.T) {
	layout := newCleanupTestLayout(t, "file-rewrite")
	statusPath := writeCleanupTestStatus(t, layout)
	before, err := os.Stat(statusPath)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := prepareUninstallCleanup(
		layout,
		"unknown",
		false,
		filepath.Join(t.TempDir(), "daemon.lease"),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.close()
	plan.beforeExecute = func() error {
		file, err := os.OpenFile(statusPath, os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		if _, err := file.WriteAt([]byte{'['}, 0); err != nil {
			_ = file.Close()
			return err
		}
		return file.Close()
	}
	err = plan.execute()
	if err == nil {
		t.Fatal("same-inode content replacement should be rejected")
	}
	after, statErr := os.Stat(statusPath)
	if statErr != nil {
		t.Fatalf("rewritten managed file was removed: %v", statErr)
	}
	if !os.SameFile(before, after) {
		t.Fatal("test did not preserve the managed file inode")
	}
	if _, statErr := os.Stat(filepath.Join(layout.RunDir, "lock")); statErr != nil {
		t.Fatalf("content rejection mutated an earlier cleanup target: %v", statErr)
	}
}

func TestCleanupQuarantineRestoresForeignFileSwappedAtFinalHook(t *testing.T) {
	layout := cleanupTestPaths(t.TempDir(), "final-file-swap")
	for _, dir := range []string{filepath.Dir(layout.ConfigPath), layout.SystemdDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := config.SaveFile(layout.ConfigPath, config.SafeTemplate()); err != nil {
		t.Fatal(err)
	}
	unitPath := filepath.Join(layout.SystemdDir, "wg-mix-ebpf.service")
	expectedUnit := systemdUnit(layout.ConfigPath, layout.BinaryPath)
	if err := os.WriteFile(unitPath, []byte(expectedUnit), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeCleanupManifest(
		layout,
		"systemd",
		cleanupManifestWriteOptions{AdoptExisting: true},
	); err != nil {
		t.Fatal(err)
	}
	plan, err := prepareUninstallCleanup(
		layout,
		"systemd",
		false,
		filepath.Join(t.TempDir(), "daemon.lease"),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.close()

	originalUnit := filepath.Join(t.TempDir(), "unit.original")
	hookRan := false
	plan.beforeQuarantine = func(path string) error {
		if path != unitPath || hookRan {
			return nil
		}
		hookRan = true
		if err := os.Rename(unitPath, originalUnit); err != nil {
			return err
		}
		return os.WriteFile(unitPath, []byte("foreign unit\n"), 0o600)
	}
	err = plan.execute()
	if err == nil || !strings.Contains(err.Error(), "moved object identity") {
		t.Fatalf("execute error = %v, want quarantined identity rejection", err)
	}
	if !hookRan {
		t.Fatal("final quarantine hook did not run")
	}
	if data, readErr := os.ReadFile(unitPath); readErr != nil || string(data) != "foreign unit\n" {
		t.Fatalf("foreign replacement was not restored: data=%q err=%v", data, readErr)
	}
	if data, readErr := os.ReadFile(originalUnit); readErr != nil || string(data) != expectedUnit {
		t.Fatalf("original managed unit changed: data=%q err=%v", data, readErr)
	}
	if _, statErr := os.Stat(cleanupManifestPath(layout)); statErr != nil {
		t.Fatalf("final swap removed ownership marker: %v", statErr)
	}
}

func TestCleanupQuarantineRestoresForeignRootSwappedAtFinalHook(t *testing.T) {
	layout := cleanupTestPaths(t.TempDir(), "final-root-swap")
	for _, dir := range []string{filepath.Dir(layout.ConfigPath), layout.VarLibDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := config.SaveFile(layout.ConfigPath, config.SafeTemplate()); err != nil {
		t.Fatal(err)
	}
	if err := writeCleanupManifest(
		layout,
		"unknown",
		cleanupManifestWriteOptions{AdoptExisting: true},
	); err != nil {
		t.Fatal(err)
	}
	plan, err := prepareUninstallCleanup(
		layout,
		"unknown",
		false,
		filepath.Join(t.TempDir(), "daemon.lease"),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.close()

	originalStateDir := layout.VarLibDir + "-original"
	foreignStateDir := filepath.Join(filepath.Dir(layout.VarLibDir), "foreign-state")
	if err := os.Mkdir(foreignStateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	foreignMarker := filepath.Join(foreignStateDir, "keep")
	if err := os.WriteFile(foreignMarker, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hookRan := false
	plan.beforeQuarantine = func(path string) error {
		if path != layout.VarLibDir || hookRan {
			return nil
		}
		hookRan = true
		if err := os.Rename(layout.VarLibDir, originalStateDir); err != nil {
			return err
		}
		return os.Rename(foreignStateDir, layout.VarLibDir)
	}
	err = plan.execute()
	if err == nil || !strings.Contains(err.Error(), "directory identity changed") {
		t.Fatalf("execute error = %v, want quarantined root rejection", err)
	}
	if !hookRan {
		t.Fatal("final root quarantine hook did not run")
	}
	if data, readErr := os.ReadFile(filepath.Join(layout.VarLibDir, "keep")); readErr != nil || string(data) != "keep\n" {
		t.Fatalf("foreign root was not restored: data=%q err=%v", data, readErr)
	}
	if _, statErr := os.Stat(originalStateDir); statErr != nil {
		t.Fatalf("original managed root changed: %v", statErr)
	}
	if _, statErr := os.Stat(cleanupManifestPath(layout)); statErr != nil {
		t.Fatalf("root swap removed ownership marker: %v", statErr)
	}
}

func TestCleanupPlanRevalidatesAllTargetsBeforeFirstUnlink(t *testing.T) {
	layout := newCleanupTestLayout(t, "late-swap")
	statusPath := writeCleanupTestStatus(t, layout)
	plan, err := prepareUninstallCleanup(
		layout,
		"unknown",
		false,
		filepath.Join(t.TempDir(), "daemon.lease"),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.close()
	lateUnknown := filepath.Join(layout.VarLibDir, "late-foreign")
	plan.beforeExecute = func() error {
		return os.WriteFile(lateUnknown, []byte("keep\n"), 0o600)
	}
	err = plan.execute()
	if err == nil || !strings.Contains(err.Error(), "unplanned entries") {
		t.Fatalf("execute error = %v, want late-target rejection", err)
	}
	for _, path := range []string{statusPath, lateUnknown} {
		if _, statErr := os.Stat(path); statErr != nil {
			t.Fatalf("global revalidation removed %s: %v", path, statErr)
		}
	}
}

func TestCleanupPlanPreservesLifecycleAndRemovesExactManifestEntries(t *testing.T) {
	layout := newCleanupTestLayout(t, "success")
	statusPath := writeCleanupTestStatus(t, layout)
	leasePath := filepath.Join(layout.RunDir, "daemon.lease")
	leaseData, err := json.Marshal(lockfile.LifecycleOwner{
		PID:        os.Getpid(),
		Action:     "uninstall",
		ConfigPath: layout.ConfigPath,
		RunDir:     layout.RunDir,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(leasePath, append(leaseData, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	requestID := strings.Repeat("a", 32)
	for _, dir := range []string{
		filepath.Join(layout.RunDir, "requests"),
		filepath.Join(layout.RunDir, "acks"),
	} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		payload, err := json.Marshal(map[string]any{"id": requestID})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, requestID+".json"), payload, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(layout.RunDir, "requests", "lock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := attachstate.Save(layout.VarLibDir, &attachstate.State{
		Version:    1,
		ConfigPath: layout.ConfigPath,
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(layout.PinPath, "control_map"), []byte("opaque pin\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err := prepareUninstallCleanup(layout, "unknown", false, leasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.close()
	if err := plan.execute(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(leasePath); err != nil {
		t.Fatalf("lifecycle lease was removed: %v", err)
	}
	if _, err := os.Stat(statusPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("runtime status was not removed: %v", err)
	}
	for _, removedDir := range []string{layout.VarLibDir, layout.PinPath} {
		if _, err := os.Stat(removedDir); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("managed directory %s was not removed: %v", removedDir, err)
		}
	}
	if _, err := os.Stat(cleanupManifestPath(layout)); err != nil {
		t.Fatalf("non-purge cleanup removed ownership manifest: %v", err)
	}
}

func TestPrepareCleanupRejectsUnknownBPFPinBeforeMutation(t *testing.T) {
	layout := newCleanupTestLayout(t, "unknown-pin")
	statusPath := writeCleanupTestStatus(t, layout)
	unknownPin := filepath.Join(layout.PinPath, "foreign_map")
	if err := os.WriteFile(unknownPin, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := prepareUninstallCleanup(
		layout,
		"unknown",
		false,
		filepath.Join(t.TempDir(), "daemon.lease"),
	)
	if err == nil || !strings.Contains(err.Error(), "unknown BPF pin") {
		t.Fatalf("prepare error = %v, want unknown-pin rejection", err)
	}
	for _, path := range []string{statusPath, unknownPin} {
		if _, statErr := os.Stat(path); statErr != nil {
			t.Fatalf("unknown-pin preflight removed %s: %v", path, statErr)
		}
	}
}

func TestCleanupPlanRemovesOnlyExactDeclaredServiceArtifact(t *testing.T) {
	layout := newCleanupTestLayoutForSystem(t, "artifact-success", "systemd")
	unitPath := filepath.Join(layout.SystemdDir, "wg-mix-ebpf.service")
	foreignPath := filepath.Join(layout.SystemdDir, "foreign.service")
	if err := os.WriteFile(foreignPath, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err := prepareUninstallCleanup(
		layout,
		"systemd",
		false,
		filepath.Join(t.TempDir(), "daemon.lease"),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.close()
	if err := plan.execute(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(unitPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("declared service artifact was not removed: %v", err)
	}
	if data, err := os.ReadFile(foreignPath); err != nil || string(data) != "keep\n" {
		t.Fatalf("foreign service artifact changed: data=%q err=%v", data, err)
	}
}

func TestPrepareCleanupRejectsChangedDeclaredServiceArtifact(t *testing.T) {
	layout := newCleanupTestLayoutForSystem(t, "artifact-changed", "systemd")
	unitPath := filepath.Join(layout.SystemdDir, "wg-mix-ebpf.service")
	if err := os.WriteFile(unitPath, []byte("foreign unit\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(layout.RunDir, "lock")
	_, err := prepareUninstallCleanup(
		layout,
		"systemd",
		false,
		filepath.Join(t.TempDir(), "daemon.lease"),
	)
	if err == nil || !strings.Contains(err.Error(), "content hash") {
		t.Fatalf("prepare error = %v, want service content rejection", err)
	}
	for _, path := range []string{unitPath, lockPath} {
		if _, statErr := os.Stat(path); statErr != nil {
			t.Fatalf("artifact preflight removed %s: %v", path, statErr)
		}
	}
}

func TestInstallServiceArtifactsRejectSymlinksWithoutChangingVictims(t *testing.T) {
	tests := []struct {
		name   string
		system string
		path   func(paths) string
	}{
		{
			name:   "systemd-unit",
			system: "systemd",
			path: func(layout paths) string {
				return filepath.Join(layout.SystemdDir, "wg-mix-ebpf.service")
			},
		},
		{
			name:   "openwrt-init",
			system: "openwrt",
			path: func(layout paths) string {
				return filepath.Join(layout.OpenWrtInitDir, "wg-mix-ebpf")
			},
		},
		{
			name:   "openwrt-hotplug",
			system: "openwrt",
			path: func(layout paths) string {
				return filepath.Join(layout.OpenWrtHotplugDir, "90-wg-mix-ebpf")
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			layout := newCleanupTestLayoutForSystem(
				t,
				"install-artifact-symlink-"+test.name,
				test.system,
			)
			setCleanupTestEnvironment(t, layout)
			artifactPath := test.path(layout)
			ownedBackup := artifactPath + ".owned-backup"
			if err := os.Rename(artifactPath, ownedBackup); err != nil {
				t.Fatal(err)
			}
			victimPath := filepath.Join(t.TempDir(), "victim")
			if err := os.WriteFile(victimPath, []byte("victim\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			victimBefore, err := os.Stat(victimPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(victimPath, artifactPath); err != nil {
				t.Fatal(err)
			}
			commandLog := filepath.Join(t.TempDir(), "systemctl.log")
			if test.system == "systemd" {
				installFakeSystemctl(t, commandLog, "")
			}

			lifecycleRoot := t.TempDir()
			_, err = Install(
				lockfile.WithLifecyclePathsForTest(
					t.Context(),
					filepath.Join(lifecycleRoot, "daemon.lease"),
					filepath.Join(lifecycleRoot, "maintenance.gate"),
				),
				Options{System: test.system},
			)
			if err == nil || !strings.Contains(err.Error(), "service artifact") {
				t.Fatalf("install error = %v, want symlink artifact rejection", err)
			}
			victimAfter, err := os.Stat(victimPath)
			if err != nil {
				t.Fatal(err)
			}
			if !os.SameFile(victimBefore, victimAfter) {
				t.Fatal("service artifact install replaced the symlink victim")
			}
			if data, err := os.ReadFile(victimPath); err != nil || string(data) != "victim\n" {
				t.Fatalf("service artifact install changed victim: data=%q err=%v", data, err)
			}
			linkInfo, err := os.Lstat(artifactPath)
			if err != nil {
				t.Fatal(err)
			}
			if linkInfo.Mode()&os.ModeSymlink == 0 {
				t.Fatal("service artifact install replaced the foreign symlink")
			}
			if _, err := os.Stat(layout.BinaryPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("service artifact rejection installed binary first: %v", err)
			}
			if test.system == "systemd" {
				if _, err := os.Stat(commandLog); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("service artifact rejection invoked systemctl: %v", err)
				}
			}
		})
	}
}

func TestInstallServiceArtifactReusesValidatedInode(t *testing.T) {
	layout := newCleanupTestLayoutForSystem(t, "install-artifact-idempotent", "systemd")
	setCleanupTestEnvironment(t, layout)
	unitPath := filepath.Join(layout.SystemdDir, "wg-mix-ebpf.service")
	before, err := os.Stat(unitPath)
	if err != nil {
		t.Fatal(err)
	}
	commandLog := filepath.Join(t.TempDir(), "systemctl.log")
	installFakeSystemctl(t, commandLog, "")

	lifecycleRoot := t.TempDir()
	if _, err := Install(
		lockfile.WithLifecyclePathsForTest(
			t.Context(),
			filepath.Join(lifecycleRoot, "daemon.lease"),
			filepath.Join(lifecycleRoot, "maintenance.gate"),
		),
		Options{System: "systemd"},
	); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(unitPath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("reinstall replaced the validated systemd unit inode")
	}
	if after.Mode().Perm() != 0o644 {
		t.Fatalf("reinstalled systemd unit mode = %#o, want 0644", after.Mode().Perm())
	}
	if data, err := os.ReadFile(unitPath); err != nil ||
		string(data) != systemdUnit(layout.ConfigPath, layout.BinaryPath) {
		t.Fatalf("reinstalled systemd unit changed: data=%q err=%v", data, err)
	}
}

func TestInstallCreatesServiceArtifactThroughDeclaredDirectory(t *testing.T) {
	root := t.TempDir()
	layout := cleanupTestPaths(root, "install-artifact-fresh")
	setCleanupTestEnvironment(t, layout)
	commandLog := filepath.Join(t.TempDir(), "systemctl.log")
	installFakeSystemctl(t, commandLog, "")

	lifecycleRoot := t.TempDir()
	if _, err := Install(
		lockfile.WithLifecyclePathsForTest(
			t.Context(),
			filepath.Join(lifecycleRoot, "daemon.lease"),
			filepath.Join(lifecycleRoot, "maintenance.gate"),
		),
		Options{System: "systemd"},
	); err != nil {
		t.Fatal(err)
	}
	unitPath := filepath.Join(layout.SystemdDir, "wg-mix-ebpf.service")
	info, err := os.Lstat(unitPath)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o644 {
		t.Fatalf("installed systemd unit mode = %v, want regular 0644", info.Mode())
	}
	if data, err := os.ReadFile(unitPath); err != nil ||
		string(data) != systemdUnit(layout.ConfigPath, layout.BinaryPath) {
		t.Fatalf("installed systemd unit data=%q err=%v", data, err)
	}
	entries, err := os.ReadDir(layout.SystemdDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp-") {
			t.Fatalf("atomic service artifact install left temporary entry %s", entry.Name())
		}
	}
}

func TestRunCommandFromVerifiedFile(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("verified OpenWrt file execution is Linux-specific")
	}
	scriptPath := filepath.Join(t.TempDir(), "verified-script")
	outputPath := filepath.Join(t.TempDir(), "verified-script.log")
	t.Setenv("WG_MIX_EBPF_TEST_VERIFIED_SCRIPT_LOG", outputPath)
	script := "#!/bin/sh\nprintf '%s' \"$1\" > \"$WG_MIX_EBPF_TEST_VERIFIED_SCRIPT_LOG\"\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(scriptPath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := runCommandFromVerifiedFile(t.Context(), file, "verified"); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(outputPath); err != nil || string(data) != "verified" {
		t.Fatalf("verified FD execution output = %q err=%v", data, err)
	}
}

func TestOpenWrtServiceActionRejectsFinalPathSwapWithoutExecutingForeign(t *testing.T) {
	layout := newCleanupTestLayoutForSystem(t, "openwrt-final-exec-swap", "openwrt")
	initPath := filepath.Join(layout.OpenWrtInitDir, "wg-mix-ebpf")
	plan, err := prepareUninstallCleanup(
		layout,
		"openwrt",
		false,
		filepath.Join(t.TempDir(), "daemon.lease"),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.close()

	originalPath := initPath + ".owned-original"
	foreignLog := filepath.Join(t.TempDir(), "foreign-executed")
	t.Setenv("WG_MIX_EBPF_TEST_FOREIGN_INIT_LOG", foreignLog)
	hookRan := false
	plan.beforeServiceExec = func(path string) error {
		if path != initPath {
			return fmt.Errorf("unexpected service exec hook path %s", path)
		}
		hookRan = true
		if err := os.Rename(initPath, originalPath); err != nil {
			return err
		}
		return os.WriteFile(
			initPath,
			[]byte("#!/bin/sh\nprintf foreign > \"$WG_MIX_EBPF_TEST_FOREIGN_INIT_LOG\"\n"),
			0o700,
		)
	}
	err = runOpenWrtServiceAction(t.Context(), plan, "stop")
	if err == nil || !strings.Contains(err.Error(), "service artifact execution") {
		t.Fatalf("OpenWrt service action error = %v, want final identity rejection", err)
	}
	if !hookRan {
		t.Fatal("OpenWrt final service exec hook did not run")
	}
	if _, err := os.Stat(foreignLog); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("foreign OpenWrt script executed: %v", err)
	}
	if data, err := os.ReadFile(initPath); err != nil ||
		!strings.Contains(string(data), "WG_MIX_EBPF_TEST_FOREIGN_INIT_LOG") {
		t.Fatalf("foreign replacement changed unexpectedly: data=%q err=%v", data, err)
	}
	if data, err := os.ReadFile(originalPath); err != nil ||
		string(data) != openWrtInit(layout.ConfigPath, layout.BinaryPath) {
		t.Fatalf("held owned init script changed: data=%q err=%v", data, err)
	}
}

func TestCleanupPlanRejectsHardLinkedKnownFile(t *testing.T) {
	layout := newCleanupTestLayout(t, "hardlink")
	externalPath := filepath.Join(t.TempDir(), "external")
	if err := os.WriteFile(externalPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	statusPath := filepath.Join(layout.RunDir, "status.json")
	if err := os.Link(externalPath, statusPath); err != nil {
		t.Fatal(err)
	}
	_, err := prepareUninstallCleanup(
		layout,
		"unknown",
		false,
		filepath.Join(t.TempDir(), "daemon.lease"),
	)
	if err == nil || !strings.Contains(err.Error(), "links") {
		t.Fatalf("prepare error = %v, want hard-link rejection", err)
	}
	for _, path := range []string{externalPath, statusPath} {
		if _, statErr := os.Stat(path); statErr != nil {
			t.Fatalf("hard-link preflight removed %s: %v", path, statErr)
		}
	}
}

func TestCleanupPlanRejectsGroupWritableKnownFile(t *testing.T) {
	layout := newCleanupTestLayout(t, "writable")
	lockPath := filepath.Join(layout.RunDir, "lock")
	if err := os.Chmod(lockPath, 0o660); err != nil {
		t.Fatal(err)
	}
	_, err := prepareUninstallCleanup(
		layout,
		"unknown",
		false,
		filepath.Join(t.TempDir(), "daemon.lease"),
	)
	if err == nil || !strings.Contains(err.Error(), "group/other writable") {
		t.Fatalf("prepare error = %v, want writable-file rejection", err)
	}
	if _, statErr := os.Stat(lockPath); statErr != nil {
		t.Fatalf("writable-file preflight removed target: %v", statErr)
	}
}

func cleanupTestPaths(root string, suffix string) paths {
	if physicalRoot, err := filepath.EvalSymlinks(root); err == nil {
		root = physicalRoot
	}
	configDir := filepath.Join(root, "wg-mix-ebpf-config-"+suffix)
	return paths{
		ConfigPath:        filepath.Join(configDir, "config.yaml"),
		BinaryPath:        filepath.Join(root, "sbin", "wg-mix-ebpf"),
		VarLibDir:         filepath.Join(root, "wg-mix-ebpf-state-"+suffix),
		RunDir:            filepath.Join(root, "wg-mix-ebpf-run-"+suffix),
		PinPath:           filepath.Join(root, "wg-mix-ebpf-pins-"+suffix),
		SystemdDir:        filepath.Join(root, "systemd"),
		OpenWrtInitDir:    filepath.Join(root, "init.d"),
		OpenWrtHotplugDir: filepath.Join(root, "hotplug"),
	}
}

func newCleanupTestLayout(t *testing.T, suffix string) paths {
	return newCleanupTestLayoutForSystem(t, suffix, "unknown")
}

func newCleanupTestLayoutForSystem(t *testing.T, suffix string, system string) paths {
	t.Helper()
	layout := newUnmarkedCleanupTestLayout(t, suffix, system)
	if err := writeCleanupManifest(
		layout,
		system,
		cleanupManifestWriteOptions{AdoptExisting: true},
	); err != nil {
		t.Fatal(err)
	}
	return layout
}

func newUnmarkedCleanupTestLayout(t *testing.T, suffix string, system string) paths {
	t.Helper()
	layout := cleanupTestPaths(t.TempDir(), suffix)
	if err := populateUnmarkedCleanupTestLayout(layout, system); err != nil {
		t.Fatal(err)
	}
	return layout
}

func populateUnmarkedCleanupTestLayout(layout paths, system string) error {
	for _, dir := range []string{
		filepath.Dir(layout.ConfigPath),
		layout.RunDir,
		layout.VarLibDir,
		layout.PinPath,
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	if err := config.SaveFile(layout.ConfigPath, config.SafeTemplate()); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(layout.RunDir, "lock"), nil, 0o600); err != nil {
		return err
	}
	switch system {
	case "systemd":
		if err := os.MkdirAll(layout.SystemdDir, 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(
			filepath.Join(layout.SystemdDir, "wg-mix-ebpf.service"),
			[]byte(systemdUnit(layout.ConfigPath, layout.BinaryPath)),
			0o600,
		); err != nil {
			return err
		}
	case "openwrt":
		for _, dir := range []string{layout.OpenWrtInitDir, layout.OpenWrtHotplugDir} {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return err
			}
		}
		if err := os.WriteFile(
			filepath.Join(layout.OpenWrtInitDir, "wg-mix-ebpf"),
			[]byte(openWrtInit(layout.ConfigPath, layout.BinaryPath)),
			0o700,
		); err != nil {
			return err
		}
		if err := os.WriteFile(
			filepath.Join(layout.OpenWrtHotplugDir, "90-wg-mix-ebpf"),
			[]byte(openWrtHotplug()),
			0o700,
		); err != nil {
			return err
		}
	}
	return nil
}

func setCleanupTestEnvironment(t *testing.T, layout paths) {
	t.Helper()
	t.Setenv(EnvEtcDir, filepath.Dir(layout.ConfigPath))
	t.Setenv(EnvBinaryPath, layout.BinaryPath)
	t.Setenv(EnvVarLibDir, layout.VarLibDir)
	t.Setenv(daemonEnvRunDirForTest, layout.RunDir)
	t.Setenv(dataplaneEnvPinPathForTest, layout.PinPath)
	t.Setenv(EnvSystemdDir, layout.SystemdDir)
	t.Setenv(EnvOpenWrtInit, layout.OpenWrtInitDir)
	t.Setenv(EnvOpenWrtHotplug, layout.OpenWrtHotplugDir)
}

func writeCleanupTestStatus(t *testing.T, layout paths) string {
	t.Helper()
	data, err := json.Marshal(daemon.Status{
		PID:        os.Getpid(),
		ConfigPath: layout.ConfigPath,
		State:      "active",
		InstanceID: "0123456789abcdef0123456789abcdef",
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(layout.RunDir, "status.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func containsAction(actions []string, substr string) bool {
	for _, action := range actions {
		if strings.Contains(action, substr) {
			return true
		}
	}
	return false
}

func installFakeNft(t *testing.T, commandLog string) {
	t.Helper()
	fakeBin := filepath.Join(t.TempDir(), "bin")
	if err := os.Mkdir(fakeBin, 0o755); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\n" +
		"printf '%s\\n' 'Error: No such file or directory' 'list table inet wg_mix_ebpf_guard' >&2\n" +
		"exit 1\n"
	if commandLog != "" {
		t.Setenv("WG_MIX_EBPF_TEST_NFT_LOG", commandLog)
		script = "#!/bin/sh\n" +
			"printf invoked > \"$WG_MIX_EBPF_TEST_NFT_LOG\"\n" +
			"printf '%s\\n' 'Error: No such file or directory' 'list table inet wg_mix_ebpf_guard' >&2\n" +
			"exit 1\n"
	}
	if err := os.WriteFile(filepath.Join(fakeBin, "nft"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func installFakeSystemctl(t *testing.T, commandLog string, failAction string) {
	t.Helper()
	fakeBin := filepath.Join(t.TempDir(), "bin")
	if err := os.Mkdir(fakeBin, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WG_MIX_EBPF_TEST_SYSTEMCTL_LOG", commandLog)
	t.Setenv("WG_MIX_EBPF_TEST_SYSTEMCTL_FAIL", failAction)
	script := `#!/bin/sh
printf '%s\n' "$*" >> "$WG_MIX_EBPF_TEST_SYSTEMCTL_LOG"
[ "$1" != "$WG_MIX_EBPF_TEST_SYSTEMCTL_FAIL" ]
`
	if err := os.WriteFile(
		filepath.Join(fakeBin, "systemctl"),
		[]byte(script),
		0o755,
	); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

const (
	daemonEnvRunDirForTest     = "WG_MIX_EBPF_RUN_DIR"
	dataplaneEnvPinPathForTest = "WG_MIX_EBPF_PIN_PATH"
)

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
