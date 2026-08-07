package install

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
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
	"github.com/syx0310/wg-mix-ebpf/internal/testutil"
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
	if !strings.Contains(
		unit,
		`ExecStop="/usr/sbin/wg-mix-ebpf" stop --config "/etc/wg-mix-ebpf/config.yaml"`,
	) {
		t.Fatalf("systemd unit should stop via daemon stop command:\n%s", unit)
	}
	init := openWrtInit(
		"/etc/wg-mix-ebpf/config.yaml",
		"/usr/sbin/wg-mix-ebpf",
		"/etc/init.d/wg-mix-ebpf",
	)
	if !strings.Contains(init, `'/usr/sbin/wg-mix-ebpf' stop --config "$CONF"`) {
		t.Fatalf("OpenWrt init should stop via daemon stop command:\n%s", init)
	}
}

func TestRenderedServicesEncodeTemplateArguments(t *testing.T) {
	configPath := `/etc/wg-mix-ebpf/config "quoted" 'single'.yaml`
	binaryPath := `/opt/wg mix/"bin"/wg-mix-ebpf`

	unit := systemdUnit(configPath, binaryPath)
	for _, want := range []string{
		`ExecStart="/opt/wg mix/\"bin\"/wg-mix-ebpf" run --config "/etc/wg-mix-ebpf/config \"quoted\" 'single'.yaml"`,
		`ExecReload="/opt/wg mix/\"bin\"/wg-mix-ebpf" reload --config "/etc/wg-mix-ebpf/config \"quoted\" 'single'.yaml"`,
		`ExecStop="/opt/wg mix/\"bin\"/wg-mix-ebpf" stop --config "/etc/wg-mix-ebpf/config \"quoted\" 'single'.yaml"`,
	} {
		if !strings.Contains(unit, want) {
			t.Fatalf("systemd unit omitted encoded argument %q:\n%s", want, unit)
		}
	}

	init := openWrtInit(configPath, binaryPath, "/etc/init.d/wg-mix-ebpf")
	for _, want := range []string{
		`CONF='/etc/wg-mix-ebpf/config "quoted" '"'"'single'"'"'.yaml'`,
		`'/opt/wg mix/"bin"/wg-mix-ebpf' run --config "$CONF" --openwrt`,
		`'/opt/wg mix/"bin"/wg-mix-ebpf' reload --config "$CONF"`,
		`'/opt/wg mix/"bin"/wg-mix-ebpf' stop --config "$CONF"`,
	} {
		if !strings.Contains(init, want) {
			t.Fatalf("OpenWrt init omitted encoded argument %q:\n%s", want, init)
		}
	}
}

func TestValidateCleanupPathsRejectsServiceTemplateInjection(t *testing.T) {
	safe := cleanupTestPaths(t.TempDir(), "template-path")
	tests := []struct {
		name   string
		suffix string
	}{
		{name: "newline", suffix: "\nExecStart=/bin/false"},
		{name: "carriage return", suffix: "\rExecStart=/bin/false"},
		{name: "escape", suffix: "\x1b[Service]"},
		{name: "systemd specifier", suffix: "%N"},
		{name: "systemd variable", suffix: "${PATH}"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := safe
			candidate.ConfigPath = filepath.Join(
				filepath.Dir(safe.ConfigPath),
				"config"+test.suffix+".yaml",
			)
			err := validateCleanupPaths(candidate)
			if err == nil || !strings.Contains(err.Error(), "unsafe config path") {
				t.Fatalf("validateCleanupPaths error = %v, want unsafe config path", err)
			}
		})
	}
}

func TestInstallAndUninstallRejectNonCleanServiceDirectoryInputs(t *testing.T) {
	tests := []struct {
		name       string
		system     string
		env        string
		selectPath func(paths) string
	}{
		{
			name:       "systemd",
			system:     "systemd",
			env:        EnvSystemdDir,
			selectPath: func(layout paths) string { return layout.SystemdDir },
		},
		{
			name:       "OpenWrt init",
			system:     "openwrt",
			env:        EnvOpenWrtInit,
			selectPath: func(layout paths) string { return layout.OpenWrtInitDir },
		},
		{
			name:       "OpenWrt hotplug",
			system:     "openwrt",
			env:        EnvOpenWrtHotplug,
			selectPath: func(layout paths) string { return layout.OpenWrtHotplugDir },
		},
	}
	for _, test := range tests {
		for _, operation := range []struct {
			name string
			run  func(context.Context, Options) (*Plan, error)
		}{
			{name: "install", run: Install},
			{name: "uninstall", run: Uninstall},
		} {
			t.Run(test.name+"/"+operation.name, func(t *testing.T) {
				root := t.TempDir()
				layout := cleanupTestPaths(root, "non-clean-service-dir")
				setCleanupTestEnvironment(t, layout)
				cleanPath := test.selectPath(layout)
				rawPath := filepath.Join(filepath.Dir(cleanPath), "detour") +
					string(os.PathSeparator) + ".." +
					string(os.PathSeparator) + filepath.Base(cleanPath)
				t.Setenv(test.env, rawPath)

				_, err := operation.run(t.Context(), Options{
					System: test.system,
					DryRun: true,
				})
				if err == nil ||
					!strings.Contains(err.Error(), "non-clean declared artifact path") {
					t.Fatalf(
						"%s error = %v, want raw non-clean path rejection",
						operation.name,
						err,
					)
				}
				if _, statErr := os.Lstat(cleanPath); !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf(
						"rejected %s created normalized directory %s: %v",
						operation.name,
						cleanPath,
						statErr,
					)
				}
			})
		}
	}
}

func TestInstallAndUninstallRejectNonCleanDefaultConfigDirectory(t *testing.T) {
	for _, operation := range []struct {
		name string
		run  func(context.Context, Options) (*Plan, error)
	}{
		{name: "install", run: Install},
		{name: "uninstall", run: Uninstall},
	} {
		t.Run(operation.name, func(t *testing.T) {
			root := t.TempDir()
			layout := cleanupTestPaths(root, "non-clean-default-config")
			setCleanupTestEnvironment(t, layout)
			cleanEtcDir := filepath.Dir(layout.ConfigPath)
			rawEtcDir := filepath.Join(filepath.Dir(cleanEtcDir), "detour") +
				string(os.PathSeparator) + ".." +
				string(os.PathSeparator) + filepath.Base(cleanEtcDir)
			t.Setenv(EnvEtcDir, rawEtcDir)

			_, err := operation.run(t.Context(), Options{
				System: "unknown",
				DryRun: true,
			})
			if err == nil ||
				!strings.Contains(err.Error(), "non-clean default config directory") {
				t.Fatalf(
					"%s error = %v, want raw default config directory rejection",
					operation.name,
					err,
				)
			}
			if _, statErr := os.Lstat(cleanEtcDir); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf(
					"rejected %s created normalized config directory %s: %v",
					operation.name,
					cleanEtcDir,
					statErr,
				)
			}
		})
	}
}

func TestApplyInstallPreservesRequestedServiceModes(t *testing.T) {
	t.Run("systemd", func(t *testing.T) {
		root := t.TempDir()
		prepareServiceModeTestAnchors(t, root, "systemd")
		installPaths := serviceModeTestPaths(root)
		setCleanupTestEnvironment(t, installPaths)
		installFakeSystemctl(t, filepath.Join(t.TempDir(), "systemctl.log"), "")
		if _, err := Install(
			systemdEnableTestContext(t),
			Options{System: "systemd"},
		); err != nil {
			t.Fatalf("apply systemd install: %v", err)
		}

		for _, dir := range []string{
			filepath.Dir(installPaths.ConfigPath),
			filepath.Dir(installPaths.BinaryPath),
			installPaths.VarLibDir,
			installPaths.RunDir,
			installPaths.SystemdDir,
		} {
			requireInstallMode(t, dir, 0o755)
		}
		requireInstallMode(t, installPaths.BinaryPath, 0o755)
		requireInstallMode(
			t,
			filepath.Join(installPaths.SystemdDir, "wg-mix-ebpf.service"),
			0o644,
		)
	})

	t.Run("openwrt", func(t *testing.T) {
		root := t.TempDir()
		prepareServiceModeTestAnchors(t, root, "openwrt")
		installPaths := serviceModeTestPaths(root)
		setCleanupTestEnvironment(t, installPaths)
		if _, err := Install(
			systemdEnableTestContext(t),
			Options{System: "openwrt"},
		); err != nil {
			t.Fatalf("apply OpenWrt install: %v", err)
		}

		for _, dir := range []string{
			filepath.Dir(installPaths.ConfigPath),
			filepath.Dir(installPaths.BinaryPath),
			installPaths.VarLibDir,
			installPaths.RunDir,
			installPaths.OpenWrtInitDir,
			installPaths.OpenWrtHotplugDir,
		} {
			requireInstallMode(t, dir, 0o755)
		}
		requireInstallMode(t, installPaths.BinaryPath, 0o755)
		requireInstallMode(
			t,
			filepath.Join(installPaths.OpenWrtInitDir, "wg-mix-ebpf"),
			0o755,
		)
		requireInstallMode(
			t,
			filepath.Join(installPaths.OpenWrtHotplugDir, "90-wg-mix-ebpf"),
			0o755,
		)
	})
}

func prepareServiceModeTestAnchors(t *testing.T, root string, system string) {
	t.Helper()
	directories := []string{
		filepath.Join(root, "etc"),
		filepath.Join(root, "usr"),
		filepath.Join(root, "var", "lib"),
		filepath.Join(root, "run"),
	}
	switch system {
	case "systemd":
		directories = append(directories, filepath.Join(root, "etc", "systemd"))
	case "openwrt":
		directories = append(
			directories,
			filepath.Join(root, "etc", "init.d"),
			filepath.Join(root, "etc", "hotplug.d"),
		)
	}
	for _, directory := range directories {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatalf("create service mode test anchor %s: %v", directory, err)
		}
	}
}

func serviceModeTestPaths(root string) paths {
	return paths{
		ConfigPath:        filepath.Join(root, "etc", "wg-mix-ebpf", "config.yaml"),
		BinaryPath:        filepath.Join(root, "usr", "sbin", "wg-mix-ebpf"),
		VarLibDir:         filepath.Join(root, "var", "lib", "wg-mix-ebpf"),
		RunDir:            filepath.Join(root, "run", "wg-mix-ebpf"),
		SystemdDir:        filepath.Join(root, "etc", "systemd", "system"),
		OpenWrtInitDir:    filepath.Join(root, "etc", "init.d"),
		OpenWrtHotplugDir: filepath.Join(root, "etc", "hotplug.d", "iface"),
		PinPath:           filepath.Join(root, "sys", "fs", "bpf", "wg-mix-ebpf"),
	}
}

func requireInstallMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("inspect mode for %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("mode for %s = %#o, want %#o", path, got, want)
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

func TestInstallRetainsMaintenanceGateWithLifecycleLease(t *testing.T) {
	root := t.TempDir()
	layout := cleanupTestPaths(root, "install-gate-held")
	setCleanupTestEnvironment(t, layout)
	lifecyclePath := filepath.Join(root, "daemon.lease")
	maintenancePath := filepath.Join(root, "maintenance.gate")
	hookRan := false
	ctx := lockfile.WithLifecyclePathsForTest(
		t.Context(),
		lifecyclePath,
		maintenancePath,
	)
	ctx = context.WithValue(
		ctx,
		installAfterLifecycleHookContextKey{},
		func() error {
			hookRan = true
			other, err := lockfile.BeginLifecycleMaintenanceAt(
				lifecyclePath,
				maintenancePath,
				lockfile.LifecycleOwner{
					PID:    os.Getpid(),
					Action: "concurrent-maintenance",
				},
			)
			if err == nil {
				_ = other.Close()
				return errors.New("concurrent maintenance acquired install gate")
			}
			if !errors.Is(err, lockfile.ErrLifecycleMaintenanceHeld) {
				return fmt.Errorf("concurrent maintenance error = %w", err)
			}
			return nil
		},
	)

	if _, err := Install(ctx, Options{System: "unknown"}); err != nil {
		t.Fatal(err)
	}
	if !hookRan {
		t.Fatal("install lifecycle hook did not run")
	}
}

func TestUninstallRejectsHeldMaintenanceGateBeforeCleanup(t *testing.T) {
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
	lifecyclePath := filepath.Join(lifecycleRoot, "daemon.lease")
	maintenancePath := filepath.Join(lifecycleRoot, "maintenance.gate")
	held, err := lockfile.BeginLifecycleMaintenanceAt(
		lifecyclePath,
		maintenancePath,
		lockfile.LifecycleOwner{PID: os.Getpid(), Action: "other-maintenance"},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	waitCtx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
	defer cancel()
	ctx := lockfile.WithLifecyclePathsForTest(
		waitCtx,
		lifecyclePath,
		maintenancePath,
	)

	_, err = Uninstall(ctx, Options{
		ConfigPath: layout.ConfigPath,
		System:     "unknown",
		Yes:        true,
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("uninstall error = %v, want bounded maintenance wait", err)
	}
	if _, err := os.Stat(attachStatePath); err != nil {
		t.Fatalf("uninstall cleaned state before acquiring lifecycle ownership: %v", err)
	}
}

func TestUninstallHoldsMaintenanceAcrossDaemonLeaseHandoff(t *testing.T) {
	layout := newCleanupTestLayoutForSystem(t, "uninstall-handoff", "systemd")
	if err := attachstate.Save(layout.VarLibDir, &attachstate.State{
		Version:    1,
		ConfigPath: layout.ConfigPath,
	}); err != nil {
		t.Fatal(err)
	}
	setCleanupTestEnvironment(t, layout)
	installFakeNft(t, "")
	commandLog := filepath.Join(t.TempDir(), "systemctl.log")
	installFakeSystemctl(t, commandLog, "")

	lifecycleRoot := t.TempDir()
	waitCtx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	ctx := lockfile.WithLifecyclePathsForTest(
		waitCtx,
		filepath.Join(lifecycleRoot, "daemon.lease"),
		filepath.Join(lifecycleRoot, "maintenance.gate"),
	)
	lease, err := lockfile.AcquireLifecycle(ctx, lockfile.LifecycleOwner{
		PID:    os.Getpid(),
		Action: "daemon",
		RunDir: layout.RunDir,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()

	releaseDone := make(chan struct{})
	go func() {
		defer close(releaseDone)
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-waitCtx.Done():
				return
			case <-ticker.C:
				data, readErr := os.ReadFile(commandLog)
				if readErr == nil &&
					strings.Contains(string(data), "stop wg-mix-ebpf.service") {
					_ = lease.Close()
					return
				}
			}
		}
	}()

	_, err = Uninstall(ctx, Options{
		ConfigPath: layout.ConfigPath,
		System:     "systemd",
		Yes:        true,
	})
	<-releaseDone
	if err != nil {
		t.Fatalf("uninstall failed daemon lease handoff: %v", err)
	}
	if _, err := os.Stat(attachstate.Path(layout.VarLibDir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("uninstall retained attach state after handoff: %v", err)
	}
	if _, err := os.Stat(
		filepath.Join(layout.SystemdDir, "wg-mix-ebpf.service"),
	); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("uninstall retained service artifact after handoff: %v", err)
	}
}

func TestUninstallRejectsSystemdFragmentMismatchBeforeStop(t *testing.T) {
	layout := newCleanupTestLayoutForSystem(
		t,
		"systemd-fragment-mismatch",
		"systemd",
	)
	setCleanupTestEnvironment(t, layout)
	installFakeNft(t, "")
	commandLog := filepath.Join(t.TempDir(), "systemctl.log")
	installFakeSystemctl(t, commandLog, "")
	t.Setenv(
		"WG_MIX_EBPF_TEST_SYSTEMCTL_FRAGMENT",
		filepath.Join(t.TempDir(), "foreign.service"),
	)
	lifecycleRoot := t.TempDir()
	ctx := lockfile.WithLifecyclePathsForTest(
		t.Context(),
		filepath.Join(lifecycleRoot, "daemon.lease"),
		filepath.Join(lifecycleRoot, "maintenance.gate"),
	)

	_, err := Uninstall(ctx, Options{
		ConfigPath: layout.ConfigPath,
		System:     "systemd",
		Yes:        true,
	})
	if err == nil || !strings.Contains(err.Error(), "FragmentPath") {
		t.Fatalf("uninstall error = %v, want FragmentPath rejection", err)
	}
	data, readErr := os.ReadFile(commandLog)
	if readErr == nil && strings.Contains(string(data), "stop wg-mix-ebpf.service") {
		t.Fatalf("fragment mismatch stopped foreign service: %q", data)
	}
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		t.Fatal(readErr)
	}
	if _, statErr := os.Stat(
		filepath.Join(layout.SystemdDir, "wg-mix-ebpf.service"),
	); statErr != nil {
		t.Fatalf("fragment rejection changed owned unit: %v", statErr)
	}
}

func TestUninstallRejectsUnverifiedSystemdManagerStateBeforeStop(t *testing.T) {
	tests := []struct {
		name  string
		env   string
		value string
		want  string
	}{
		{
			name:  "drop-in",
			env:   "WG_MIX_EBPF_TEST_SYSTEMCTL_DROP_INS",
			value: "/etc/systemd/system/wg-mix-ebpf.service.d/override.conf",
			want:  "DropInPaths",
		},
		{
			name:  "reload still needed",
			env:   "WG_MIX_EBPF_TEST_SYSTEMCTL_NEEDS_RELOAD",
			value: "yes",
			want:  "NeedDaemonReload",
		},
		{
			name:  "not loaded",
			env:   "WG_MIX_EBPF_TEST_SYSTEMCTL_LOAD_STATE",
			value: "not-found",
			want:  "LoadState",
		},
		{
			name:  "transient",
			env:   "WG_MIX_EBPF_TEST_SYSTEMCTL_TRANSIENT",
			value: "yes",
			want:  "Transient",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			layout := newCleanupTestLayoutForSystem(
				t,
				"systemd-manager-"+strings.ReplaceAll(test.name, " ", "-"),
				"systemd",
			)
			setCleanupTestEnvironment(t, layout)
			installFakeNft(t, "")
			commandLog := filepath.Join(t.TempDir(), "systemctl.log")
			installFakeSystemctl(t, commandLog, "")
			t.Setenv(test.env, test.value)
			lifecycleRoot := t.TempDir()

			_, err := Uninstall(
				lockfile.WithLifecyclePathsForTest(
					t.Context(),
					filepath.Join(lifecycleRoot, "daemon.lease"),
					filepath.Join(lifecycleRoot, "maintenance.gate"),
				),
				Options{
					ConfigPath: layout.ConfigPath,
					System:     "systemd",
					Yes:        true,
				},
			)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("uninstall error = %v, want %s rejection", err, test.want)
			}
			logData, readErr := os.ReadFile(commandLog)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if !strings.Contains(string(logData), "daemon-reload\n") {
				t.Fatalf("manager state was not synchronized first: %q", logData)
			}
			if strings.Contains(string(logData), "stop wg-mix-ebpf.service") ||
				strings.Contains(string(logData), "disable wg-mix-ebpf.service") {
				t.Fatalf("unverified manager state mutated service: %q", logData)
			}
			if _, statErr := os.Stat(
				filepath.Join(layout.SystemdDir, "wg-mix-ebpf.service"),
			); statErr != nil {
				t.Fatalf("manager rejection changed owned unit: %v", statErr)
			}
		})
	}
}

func TestParseSystemdUnitPropertiesRejectsAmbiguousOutput(t *testing.T) {
	valid := "" +
		"FragmentPath=/etc/systemd/system/wg-mix-ebpf.service\n" +
		"DropInPaths=\n" +
		"NeedDaemonReload=no\n" +
		"LoadState=loaded\n" +
		"Transient=no\n"
	tests := []struct {
		name string
		data string
	}{
		{name: "empty"},
		{name: "missing", data: strings.Replace(valid, "Transient=no\n", "", 1)},
		{name: "duplicate", data: valid + "Transient=no\n"},
		{name: "unknown", data: strings.Replace(valid, "Transient=no", "Other=no", 1)},
		{name: "malformed", data: strings.Replace(valid, "Transient=no", "Transient", 1)},
		{name: "NUL", data: valid + "\x00"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseSystemdUnitProperties([]byte(test.data)); err == nil {
				t.Fatalf("ambiguous manager output %q unexpectedly accepted", test.data)
			}
		})
	}
	if properties, err := parseSystemdUnitProperties([]byte(valid)); err != nil {
		t.Fatal(err)
	} else if properties["FragmentPath"] != "/etc/systemd/system/wg-mix-ebpf.service" {
		t.Fatalf("parsed FragmentPath = %q", properties["FragmentPath"])
	}
}

func TestSystemdServiceActionRejectsFinalPathSwapBeforeManagerReload(t *testing.T) {
	layout := newCleanupTestLayoutForSystem(t, "systemd-final-exec-swap", "systemd")
	unitPath := filepath.Join(layout.SystemdDir, "wg-mix-ebpf.service")
	commandLog := filepath.Join(t.TempDir(), "systemctl.log")
	lifecyclePath := filepath.Join(t.TempDir(), "daemon.lease")
	setCleanupTestEnvironment(t, layout)
	installFakeSystemctl(t, commandLog, "")
	plan, err := prepareUninstallCleanup(
		layout,
		"systemd",
		false,
		lifecyclePath,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.close()

	originalPath := unitPath + ".owned-original"
	hookRan := false
	plan.beforeServiceExec = func(path string) error {
		if path != unitPath {
			return fmt.Errorf("unexpected service exec hook path %s", path)
		}
		hookRan = true
		if err := os.Rename(unitPath, originalPath); err != nil {
			return err
		}
		return os.WriteFile(unitPath, []byte("[Service]\nExecStart=/bin/false\n"), 0o644)
	}
	err = runSystemdServiceActions(t.Context(), layout, plan, "stop")
	if err == nil || !strings.Contains(err.Error(), "service artifact execution") {
		t.Fatalf("systemd service action error = %v, want final identity rejection", err)
	}
	if !hookRan {
		t.Fatal("systemd final service hook did not run")
	}
	if _, readErr := os.ReadFile(commandLog); !errors.Is(readErr, os.ErrNotExist) {
		t.Fatalf("unit swap invoked systemctl before rejection: %v", readErr)
	}
	if data, readErr := os.ReadFile(unitPath); readErr != nil ||
		string(data) != "[Service]\nExecStart=/bin/false\n" {
		t.Fatalf("foreign unit replacement changed: data=%q err=%v", data, readErr)
	}
	if data, readErr := os.ReadFile(originalPath); readErr != nil ||
		string(data) != systemdUnit(layout.ConfigPath, layout.BinaryPath) {
		t.Fatalf("held owned unit changed: data=%q err=%v", data, readErr)
	}
}

func TestUninstallRemovesValidatedSystemdEnableLink(t *testing.T) {
	layout := newCleanupTestLayoutForSystem(t, "systemd-disable", "systemd")
	enableLink := systemdEnableLinkPath(layout)
	if err := os.MkdirAll(filepath.Dir(enableLink), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../wg-mix-ebpf.service", enableLink); err != nil {
		t.Fatal(err)
	}
	setCleanupTestEnvironment(t, layout)
	installFakeNft(t, "")
	commandLog := filepath.Join(t.TempDir(), "systemctl.log")
	installFakeSystemctl(t, commandLog, "")
	lifecycleRoot := t.TempDir()
	ctx := lockfile.WithLifecyclePathsForTest(
		t.Context(),
		filepath.Join(lifecycleRoot, "daemon.lease"),
		filepath.Join(lifecycleRoot, "maintenance.gate"),
	)

	_, err := Uninstall(ctx, Options{
		ConfigPath: layout.ConfigPath,
		System:     "systemd",
		Yes:        true,
	})
	if err != nil {
		t.Fatalf("uninstall enabled systemd installation: %v", err)
	}
	if _, err := os.Stat(filepath.Join(layout.SystemdDir, "wg-mix-ebpf.service")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("uninstall retained systemd unit: %v", err)
	}
	if _, err := os.Lstat(enableLink); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("uninstall retained validated systemd enable link: %v", err)
	}
	if _, err := os.Stat(cleanupManifestPath(layout)); err != nil {
		t.Fatalf("non-purge uninstall removed ownership marker: %v", err)
	}
}

func TestSystemdEnableLinkCleanupRejectsPostPreflightReplacement(t *testing.T) {
	for _, test := range []struct {
		name              string
		replacementTarget string
	}{
		{name: "same target new inode", replacementTarget: systemdEnableLinkTarget},
		{name: "different target", replacementTarget: "../foreign.service"},
	} {
		t.Run(test.name, func(t *testing.T) {
			layout := newCleanupTestLayoutForSystem(
				t,
				"systemd-link-replacement-"+strings.ReplaceAll(test.name, " ", "-"),
				"systemd",
			)
			linkPath := systemdEnableLinkPath(layout)
			if err := os.Symlink(systemdEnableLinkTarget, linkPath); err != nil {
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

			var linkDirectory *cleanupDirectoryPlan
			for _, directory := range plan.directories {
				if directory.root.spec.path == filepath.Dir(linkPath) {
					linkDirectory = directory
					break
				}
			}
			if linkDirectory == nil {
				t.Fatal("cleanup plan omitted the exact systemd wants directory")
			}
			ownedBackup := linkPath + ".owned-before-replacement"
			hookRan := false
			err = linkDirectory.remove(func(path string) error {
				if path != linkPath || hookRan {
					return nil
				}
				hookRan = true
				if err := os.Rename(linkPath, ownedBackup); err != nil {
					return err
				}
				return os.Symlink(test.replacementTarget, linkPath)
			}, nil)
			if err == nil {
				t.Fatal("post-preflight systemd enable link replacement was removed")
			}
			if !hookRan {
				t.Fatal("systemd enable link replacement hook did not run")
			}
			assertSymlinkTarget(t, linkPath, test.replacementTarget)
			assertSymlinkTarget(t, ownedBackup, systemdEnableLinkTarget)
		})
	}
}

func TestUninstallPreservesForeignSystemdEnableLink(t *testing.T) {
	layout := newCleanupTestLayoutForSystem(
		t,
		"systemd-foreign-enable-uninstall",
		"systemd",
	)
	enableLink := systemdEnableLinkPath(layout)
	if err := os.MkdirAll(filepath.Dir(enableLink), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../foreign.service", enableLink); err != nil {
		t.Fatal(err)
	}
	setCleanupTestEnvironment(t, layout)
	commandLog := filepath.Join(t.TempDir(), "systemctl.log")
	installFakeSystemctl(t, commandLog, "")
	lifecycleRoot := t.TempDir()

	_, err := Uninstall(
		lockfile.WithLifecyclePathsForTest(
			t.Context(),
			filepath.Join(lifecycleRoot, "daemon.lease"),
			filepath.Join(lifecycleRoot, "maintenance.gate"),
		),
		Options{
			ConfigPath: layout.ConfigPath,
			System:     "systemd",
			Yes:        true,
		},
	)
	if err == nil || !strings.Contains(err.Error(), "target") {
		t.Fatalf("uninstall error = %v, want foreign enable link rejection", err)
	}
	if target, readErr := os.Readlink(enableLink); readErr != nil ||
		target != "../foreign.service" {
		t.Fatalf("foreign enable link target = %q err=%v", target, readErr)
	}
	if _, statErr := os.Stat(
		filepath.Join(layout.SystemdDir, "wg-mix-ebpf.service"),
	); statErr != nil {
		t.Fatalf("foreign link rejection changed owned unit: %v", statErr)
	}
	if _, statErr := os.Stat(commandLog); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("foreign link rejection invoked systemctl: %v", statErr)
	}
}

func TestUninstallWithoutSystemdEnableLinkCompletes(t *testing.T) {
	layout := newCleanupTestLayoutForSystem(t, "systemd-never-enabled", "systemd")
	setCleanupTestEnvironment(t, layout)
	installFakeNft(t, "")
	commandLog := filepath.Join(t.TempDir(), "systemctl.log")
	installFakeSystemctl(t, commandLog, "")

	lifecycleRoot := t.TempDir()
	plan, err := Uninstall(
		lockfile.WithLifecyclePathsForTest(
			t.Context(),
			filepath.Join(lifecycleRoot, "daemon.lease"),
			filepath.Join(lifecycleRoot, "maintenance.gate"),
		),
		Options{
			ConfigPath: layout.ConfigPath,
			System:     "systemd",
			Yes:        true,
		},
	)
	if err != nil {
		t.Fatalf("uninstall never-enabled systemd install: %v", err)
	}
	if !containsAction(
		plan.Actions,
		"remove the exact validated systemd enable link if present",
	) {
		t.Fatalf("uninstall plan omits enable-link cleanup policy: %#v", plan.Actions)
	}
	if _, statErr := os.Stat(
		filepath.Join(layout.SystemdDir, "wg-mix-ebpf.service"),
	); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("uninstall retained never-enabled unit: %v", statErr)
	}
	logData, err := os.ReadFile(commandLog)
	if err != nil {
		t.Fatal(err)
	}
	want := "daemon-reload\nstop wg-mix-ebpf.service\ndaemon-reload\n"
	if string(logData) != want {
		t.Fatalf("systemctl log = %q, want %q", logData, want)
	}
}

func TestUninstallDoesNotMutateSystemdWhenOwnedUnitIsAlreadyAbsent(t *testing.T) {
	layout := newCleanupTestLayoutForSystem(t, "systemd-disable-absent", "systemd")
	unitPath := filepath.Join(layout.SystemdDir, "wg-mix-ebpf.service")
	if err := os.Rename(unitPath, unitPath+".already-absent"); err != nil {
		t.Fatal(err)
	}
	setCleanupTestEnvironment(t, layout)
	installFakeNft(t, "")
	commandLog := filepath.Join(t.TempDir(), "systemctl.log")
	installFakeSystemctl(t, commandLog, "")

	lifecycleRoot := t.TempDir()
	if _, err := Uninstall(
		lockfile.WithLifecyclePathsForTest(
			t.Context(),
			filepath.Join(lifecycleRoot, "daemon.lease"),
			filepath.Join(lifecycleRoot, "maintenance.gate"),
		),
		Options{
			ConfigPath: layout.ConfigPath,
			System:     "systemd",
			Yes:        true,
		},
	); err != nil {
		t.Fatal(err)
	}
	logData, err := os.ReadFile(commandLog)
	if err != nil {
		t.Fatal(err)
	}
	want := "daemon-reload\n"
	if string(logData) != want {
		t.Fatalf("systemctl log = %q, want only manager reload %q", logData, want)
	}
}

func TestUninstallOwnedResourceAbsenceHasAlignedDryRunAndRealNoOpPlans(t *testing.T) {
	layout := cleanupTestPaths(t.TempDir(), "uninstall-noop")
	setCleanupTestEnvironment(t, layout)
	opts := Options{
		ConfigPath: layout.ConfigPath,
		System:     "unknown",
	}
	dryOpts := opts
	dryOpts.DryRun = true
	dryPlan, err := Uninstall(t.Context(), dryOpts)
	if err != nil {
		t.Fatal(err)
	}
	realPlan, err := Uninstall(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(dryPlan.Actions, "\n") != strings.Join(realPlan.Actions, "\n") {
		t.Fatalf("dry-run actions %#v differ from real no-op %#v", dryPlan.Actions, realPlan.Actions)
	}
	if !containsAction(dryPlan.Actions, "no owned installation resources found; no changes") {
		t.Fatalf("no-op plan missing ownership result: %#v", dryPlan.Actions)
	}
	for _, mutation := range []string{
		"stop wg-mix-ebpf",
		"disable systemd",
		"disable OpenWrt",
		"remove BPF",
		"remove nft",
		"remove runtime",
		"remove state",
		"detach dataplane",
	} {
		if containsAction(dryPlan.Actions, mutation) {
			t.Fatalf("no-op plan claims mutation %q: %#v", mutation, dryPlan.Actions)
		}
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
			"if [ \"$*\" = '-j list tables' ]; then\n"+
			"  printf '%s\\n' '{\"nftables\":[{\"metainfo\":{\"json_schema_version\":1}}]}'\n"+
			"  exit 0\n"+
			"fi\n"+
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
	ctx := lockfile.WithLifecyclePathsForTest(
		t.Context(),
		lifecyclePath,
		filepath.Join(t.TempDir(), "maintenance.gate"),
	)
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
	t.Setenv("WG_MIX_EBPF_TEST_SYSTEMCTL_FAIL_OCCURRENCE", "2")
	lifecycleRoot := t.TempDir()
	ctx := lockfile.WithLifecyclePathsForTest(
		t.Context(),
		filepath.Join(lifecycleRoot, "daemon.lease"),
		filepath.Join(lifecycleRoot, "maintenance.gate"),
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
	if strings.Count(string(logData), "daemon-reload\n") != 3 {
		t.Fatalf("systemctl log = %q, want three daemon-reload attempts", logData)
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

func TestInstallBinaryReplacesValidatedTargetAtomically(t *testing.T) {
	target := filepath.Join(t.TempDir(), "wg-mix-ebpf")
	if err := os.WriteFile(target, []byte("stale"), 0o755); err != nil {
		t.Fatal(err)
	}
	initialInfo, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
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
	if os.SameFile(initialInfo, info) {
		t.Fatal("installed binary reused the stale target inode")
	}
}

func TestInstallBinaryRejectsWritableTargetWithoutMutation(t *testing.T) {
	target := filepath.Join(t.TempDir(), "wg-mix-ebpf")
	if err := os.WriteFile(target, []byte("foreign"), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o777); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	err = installBinary(target)
	if err == nil || !strings.Contains(err.Error(), "group/other writable") {
		t.Fatalf("install binary error = %v, want writable-target rejection", err)
	}
	after, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("rejected binary install replaced the foreign inode")
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "foreign" {
		t.Fatalf("rejected binary install changed target: data=%q err=%v", data, err)
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

func TestInstallPublishesOwnershipOnlyAfterServiceCommit(t *testing.T) {
	root := t.TempDir()
	layout := cleanupTestPaths(root, "manifest-last")
	setCleanupTestEnvironment(t, layout)
	commandLog := filepath.Join(t.TempDir(), "systemctl.log")
	installFakeSystemctl(t, commandLog, "daemon-reload")
	ctx := lockfile.WithLifecyclePathsForTest(
		t.Context(),
		filepath.Join(root, "daemon.lease"),
		filepath.Join(root, "maintenance.gate"),
	)

	_, err := Install(ctx, Options{System: "systemd"})
	if err == nil || !strings.Contains(err.Error(), "daemon-reload") {
		t.Fatalf("install error = %v, want service commit failure", err)
	}
	if _, statErr := os.Lstat(cleanupManifestPath(layout)); !errors.Is(
		statErr,
		os.ErrNotExist,
	) {
		t.Fatalf("failed install published cleanup ownership: %v", statErr)
	}
	unitPath := filepath.Join(layout.SystemdDir, "wg-mix-ebpf.service")
	if _, statErr := os.Stat(unitPath); statErr != nil {
		t.Fatalf("failed install did not retain its exact partial artifact: %v", statErr)
	}

	_, err = Install(ctx, Options{System: "systemd"})
	if err == nil || !strings.Contains(err.Error(), "--adopt-existing") {
		t.Fatalf("retry error = %v, want explicit partial-install adoption", err)
	}
	if _, statErr := os.Lstat(cleanupManifestPath(layout)); !errors.Is(
		statErr,
		os.ErrNotExist,
	) {
		t.Fatalf("rejected retry published cleanup ownership: %v", statErr)
	}

	t.Setenv("WG_MIX_EBPF_TEST_SYSTEMCTL_FAIL", "")
	plan, err := Install(ctx, Options{
		System:        "systemd",
		AdoptExisting: true,
	})
	if err != nil {
		t.Fatalf("explicit partial-install adoption failed: %v", err)
	}
	if !containsAction(plan.Actions, "adopt strictly validated existing resources") {
		t.Fatalf("adoption plan omitted ownership transition: %#v", plan.Actions)
	}
	data, err := os.ReadFile(cleanupManifestPath(layout))
	if err != nil {
		t.Fatal(err)
	}
	var manifest cleanupManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if err := manifest.validateAgainst(layout, "systemd"); err != nil {
		t.Fatal(err)
	}
}

func TestInstallRejectsForeignSystemdFragmentBeforeEnable(t *testing.T) {
	root := t.TempDir()
	layout := cleanupTestPaths(root, "install-fragment-mismatch")
	setCleanupTestEnvironment(t, layout)
	commandLog := filepath.Join(t.TempDir(), "systemctl.log")
	installFakeSystemctl(t, commandLog, "")
	t.Setenv(
		"WG_MIX_EBPF_TEST_SYSTEMCTL_FRAGMENT",
		filepath.Join(t.TempDir(), "foreign.service"),
	)
	ctx := lockfile.WithLifecyclePathsForTest(
		t.Context(),
		filepath.Join(root, "daemon.lease"),
		filepath.Join(root, "maintenance.gate"),
	)

	_, err := Install(ctx, Options{System: "systemd", Enable: true})
	if err == nil || !strings.Contains(err.Error(), "FragmentPath") {
		t.Fatalf("install error = %v, want FragmentPath rejection", err)
	}
	logData, readErr := os.ReadFile(commandLog)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if strings.Contains(string(logData), "enable wg-mix-ebpf.service") {
		t.Fatalf("fragment mismatch enabled foreign service: %q", logData)
	}
	if _, statErr := os.Lstat(cleanupManifestPath(layout)); !errors.Is(
		statErr,
		os.ErrNotExist,
	) {
		t.Fatalf("fragment mismatch published cleanup ownership: %v", statErr)
	}
}

func TestInstallRejectsSystemdUnitSamePathSwapBeforeEnable(t *testing.T) {
	tests := []struct {
		name       string
		marked     bool
		swapAction string
	}{
		{
			name:       "fresh during daemon reload",
			swapAction: "daemon-reload",
		},
		{
			name:       "marked during manager inspection",
			marked:     true,
			swapAction: "show",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var layout paths
			if test.marked {
				layout = newCleanupTestLayoutForSystem(
					t,
					"systemd-swap-marked",
					"systemd",
				)
			} else {
				layout = cleanupTestPaths(t.TempDir(), "systemd-swap-fresh")
			}
			setCleanupTestEnvironment(t, layout)

			markerPath := cleanupManifestPath(layout)
			var markerData []byte
			var markerInfo os.FileInfo
			if test.marked {
				var err error
				markerData, err = os.ReadFile(markerPath)
				if err != nil {
					t.Fatal(err)
				}
				markerInfo, err = os.Stat(markerPath)
				if err != nil {
					t.Fatal(err)
				}
			}

			commandLog := filepath.Join(t.TempDir(), "systemctl.log")
			installFakeSystemctl(t, commandLog, "")
			unitPath := filepath.Join(layout.SystemdDir, "wg-mix-ebpf.service")
			foreignContent := []byte(
				"[Service]\nExecStart=/bin/false\nExecStop=/bin/false\n",
			)
			foreignSource := filepath.Join(t.TempDir(), "foreign.service")
			if err := os.WriteFile(foreignSource, foreignContent, 0o644); err != nil {
				t.Fatal(err)
			}
			t.Setenv(
				"WG_MIX_EBPF_TEST_SYSTEMCTL_SWAP_ACTION",
				test.swapAction,
			)
			t.Setenv("WG_MIX_EBPF_TEST_SYSTEMCTL_SWAP_PATH", unitPath)
			t.Setenv(
				"WG_MIX_EBPF_TEST_SYSTEMCTL_SWAP_CONTENT",
				foreignSource,
			)

			lifecycleRoot := t.TempDir()
			_, err := Install(
				lockfile.WithLifecyclePathsForTest(
					t.Context(),
					filepath.Join(lifecycleRoot, "daemon.lease"),
					filepath.Join(lifecycleRoot, "maintenance.gate"),
				),
				Options{
					System: "systemd",
					Enable: true,
				},
			)
			if err == nil ||
				!strings.Contains(err.Error(), "revalidate installed systemd unit") {
				t.Fatalf(
					"install error = %v, want verified unit identity rejection",
					err,
				)
			}
			logData, readErr := os.ReadFile(commandLog)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if strings.Contains(
				string(logData),
				"enable wg-mix-ebpf.service",
			) {
				t.Fatalf("same-path foreign unit was enabled: %q", logData)
			}
			if data, readErr := os.ReadFile(unitPath); readErr != nil ||
				string(data) != string(foreignContent) {
				t.Fatalf(
					"foreign unit replacement changed: data=%q err=%v",
					data,
					readErr,
				)
			}
			ownedPath := unitPath + ".owned-original"
			if data, readErr := os.ReadFile(ownedPath); readErr != nil ||
				string(data) != systemdUnit(layout.ConfigPath, layout.BinaryPath) {
				t.Fatalf(
					"held owned unit changed: data=%q err=%v",
					data,
					readErr,
				)
			}
			if test.marked {
				afterInfo, statErr := os.Stat(markerPath)
				if statErr != nil {
					t.Fatalf("marked reinstall lost ownership marker: %v", statErr)
				}
				if !os.SameFile(markerInfo, afterInfo) {
					t.Fatal("marked reinstall replaced ownership marker")
				}
				if data, readErr := os.ReadFile(markerPath); readErr != nil ||
					string(data) != string(markerData) {
					t.Fatalf(
						"marked reinstall changed ownership marker: data=%q err=%v",
						data,
						readErr,
					)
				}
			} else if _, statErr := os.Lstat(markerPath); !errors.Is(
				statErr,
				os.ErrNotExist,
			) {
				t.Fatalf("fresh rejected install published ownership: %v", statErr)
			}
		})
	}
}

func TestMarkedInstallRejectsManifestSamePathSwapBeforeEnable(t *testing.T) {
	layout := newCleanupTestLayoutForSystem(
		t,
		"systemd-manifest-swap",
		"systemd",
	)
	setCleanupTestEnvironment(t, layout)
	markerPath := cleanupManifestPath(layout)
	markerData, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	markerInfo, err := os.Stat(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	replacementSource := filepath.Join(t.TempDir(), "replacement-manifest.json")
	if err := os.WriteFile(replacementSource, markerData, 0o600); err != nil {
		t.Fatal(err)
	}

	commandLog := filepath.Join(t.TempDir(), "systemctl.log")
	installFakeSystemctl(t, commandLog, "")
	t.Setenv("WG_MIX_EBPF_TEST_SYSTEMCTL_SWAP_ACTION", "show")
	t.Setenv("WG_MIX_EBPF_TEST_SYSTEMCTL_SWAP_PATH", markerPath)
	t.Setenv(
		"WG_MIX_EBPF_TEST_SYSTEMCTL_SWAP_CONTENT",
		replacementSource,
	)

	lifecycleRoot := t.TempDir()
	_, err = Install(
		lockfile.WithLifecyclePathsForTest(
			t.Context(),
			filepath.Join(lifecycleRoot, "daemon.lease"),
			filepath.Join(lifecycleRoot, "maintenance.gate"),
		),
		Options{
			System: "systemd",
			Enable: true,
		},
	)
	if err == nil ||
		!strings.Contains(err.Error(), "marked install manifest") {
		t.Fatalf("install error = %v, want held manifest rejection", err)
	}
	logData, readErr := os.ReadFile(commandLog)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if strings.Contains(string(logData), "enable wg-mix-ebpf.service") {
		t.Fatalf("manifest swap was authorized to enable service: %q", logData)
	}
	originalPath := markerPath + ".owned-original"
	originalInfo, statErr := os.Stat(originalPath)
	if statErr != nil {
		t.Fatalf("held original ownership marker is missing: %v", statErr)
	}
	if !os.SameFile(markerInfo, originalInfo) {
		t.Fatal("held original ownership marker identity changed")
	}
	if data, readErr := os.ReadFile(originalPath); readErr != nil ||
		string(data) != string(markerData) {
		t.Fatalf(
			"held original ownership marker changed: data=%q err=%v",
			data,
			readErr,
		)
	}
	replacementInfo, statErr := os.Stat(markerPath)
	if statErr != nil {
		t.Fatalf("foreign marker replacement is missing: %v", statErr)
	}
	if os.SameFile(markerInfo, replacementInfo) {
		t.Fatal("foreign marker replacement unexpectedly reused held identity")
	}
	if data, readErr := os.ReadFile(markerPath); readErr != nil ||
		string(data) != string(markerData) {
		t.Fatalf(
			"installer changed foreign marker replacement: data=%q err=%v",
			data,
			readErr,
		)
	}
}

func TestInstallCreatesExactSystemdEnableLinkWithoutSystemctlEnable(t *testing.T) {
	layout := cleanupTestPaths(t.TempDir(), "systemd-exact-enable")
	prepareSystemdWantsDirectory(t, layout)
	setCleanupTestEnvironment(t, layout)
	commandLog := filepath.Join(t.TempDir(), "systemctl.log")
	installFakeSystemctl(t, commandLog, "")
	lifecycleRoot := t.TempDir()
	ctx := lockfile.WithLifecyclePathsForTest(
		t.Context(),
		filepath.Join(lifecycleRoot, "daemon.lease"),
		filepath.Join(lifecycleRoot, "maintenance.gate"),
	)

	if _, err := Install(ctx, Options{System: "systemd", Enable: true}); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{
		filepath.Dir(layout.ConfigPath),
		filepath.Dir(layout.BinaryPath),
		layout.SystemdDir,
	} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if strings.Contains(entry.Name(), ".tmp-") {
				t.Fatalf("successful install retained temporary name %s", filepath.Join(dir, entry.Name()))
			}
		}
	}
	linkPath := systemdEnableLinkPath(layout)
	target, err := os.Readlink(linkPath)
	if err != nil {
		t.Fatal(err)
	}
	if target != "../wg-mix-ebpf.service" {
		t.Fatalf("systemd enable link target = %q", target)
	}
	entries, err := os.ReadDir(filepath.Dir(linkPath))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "wg-mix-ebpf.service" {
		t.Fatalf("enable transaction created unexpected Wants/Alias entries: %#v", entries)
	}
	logData, err := os.ReadFile(commandLog)
	if err != nil {
		t.Fatal(err)
	}
	if string(logData) != "daemon-reload\n" {
		t.Fatalf("systemctl log = %q, want only descriptor-verified manager reload", logData)
	}
	manifestData, err := os.ReadFile(cleanupManifestPath(layout))
	if err != nil {
		t.Fatal(err)
	}
	var manifest cleanupManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		t.Fatal(err)
	}
	if err := manifest.validateAgainst(layout, "systemd"); err != nil {
		t.Fatal(err)
	}
}

func TestInstallRetainsCreatedSystemdEnableLinkAfterPartialFailure(t *testing.T) {
	layout := cleanupTestPaths(t.TempDir(), "systemd-enable-partial")
	linkPath := prepareSystemdWantsDirectory(t, layout)
	setCleanupTestEnvironment(t, layout)
	commandLog := filepath.Join(t.TempDir(), "systemctl.log")
	installFakeSystemctl(t, commandLog, "")
	lifecycleRoot := t.TempDir()
	baseContext := lockfile.WithLifecyclePathsForTest(
		t.Context(),
		filepath.Join(lifecycleRoot, "daemon.lease"),
		filepath.Join(lifecycleRoot, "maintenance.gate"),
	)
	injected := errors.New("injected failure after exact enable link creation")
	hookRan := false
	ctx := context.WithValue(
		baseContext,
		installAfterSystemdEnableLinkHookContextKey{},
		func(path string) error {
			hookRan = true
			if path != systemdEnableLinkPath(layout) {
				return fmt.Errorf("unexpected enable link hook path %s", path)
			}
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			if target != "../wg-mix-ebpf.service" {
				return fmt.Errorf("unexpected enable link target %q", target)
			}
			return injected
		},
	)

	_, err := Install(ctx, Options{System: "systemd", Enable: true})
	if !errors.Is(err, injected) {
		t.Fatalf("install error = %v, want injected post-create failure", err)
	}
	if !hookRan {
		t.Fatal("post-systemd-enable-link hook did not run")
	}
	assertNonDestructiveRetentionError(t, err, linkPath)
	assertSymlinkTarget(t, linkPath, systemdEnableLinkTarget)
	entries, readErr := os.ReadDir(filepath.Dir(linkPath))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(linkPath) {
		t.Fatalf("failure retention created or removed names: %#v", entries)
	}
	if _, statErr := os.Stat(cleanupManifestPath(layout)); statErr != nil {
		t.Fatalf("failed enable transaction lost recoverable ownership: %v", statErr)
	}
}

func TestInstallRetainsSystemdEnableLinkOnDuringEnableIdentitySwap(t *testing.T) {
	tests := []struct {
		name      string
		swap      func(t *testing.T, layout paths)
		wantError string
	}{
		{
			name: "unit",
			swap: func(t *testing.T, layout paths) {
				t.Helper()
				unitPath := filepath.Join(layout.SystemdDir, "wg-mix-ebpf.service")
				if err := os.Rename(unitPath, unitPath+".owned-original"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(
					unitPath,
					[]byte("[Service]\nExecStart=/bin/false\n"),
					0o644,
				); err != nil {
					t.Fatal(err)
				}
			},
			wantError: "revalidate installed systemd unit",
		},
		{
			name: "ownership manifest",
			swap: func(t *testing.T, layout paths) {
				t.Helper()
				markerPath := cleanupManifestPath(layout)
				data, err := os.ReadFile(markerPath)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(markerPath, markerPath+".owned-original"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(markerPath, data, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wantError: "marked install manifest",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			layout := cleanupTestPaths(
				t.TempDir(),
				"during-enable-"+strings.ReplaceAll(test.name, " ", "-"),
			)
			linkPath := prepareSystemdWantsDirectory(t, layout)
			setCleanupTestEnvironment(t, layout)
			commandLog := filepath.Join(t.TempDir(), "systemctl.log")
			installFakeSystemctl(t, commandLog, "")
			lifecycleRoot := t.TempDir()
			ctx := lockfile.WithLifecyclePathsForTest(
				t.Context(),
				filepath.Join(lifecycleRoot, "daemon.lease"),
				filepath.Join(lifecycleRoot, "maintenance.gate"),
			)
			ctx = context.WithValue(
				ctx,
				installAfterSystemdEnableLinkHookContextKey{},
				func(path string) error {
					if target, err := os.Readlink(path); err != nil ||
						target != "../wg-mix-ebpf.service" {
						return fmt.Errorf(
							"enable link was not committed before race injection: target=%q err=%v",
							target,
							err,
						)
					}
					test.swap(t, layout)
					return nil
				},
			)

			_, err := Install(ctx, Options{System: "systemd", Enable: true})
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("install error = %v, want %q", err, test.wantError)
			}
			assertNonDestructiveRetentionError(t, err, linkPath)
			assertSymlinkTarget(t, linkPath, systemdEnableLinkTarget)
			logData, readErr := os.ReadFile(commandLog)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if strings.Contains(string(logData), "enable ") {
				t.Fatalf("identity race invoked name-based systemctl enable: %q", logData)
			}
		})
	}
}

func TestMarkedInstallPreservesForeignExistingSystemdEnableLink(t *testing.T) {
	layout := newCleanupTestLayoutForSystem(
		t,
		"systemd-foreign-enable-link",
		"systemd",
	)
	linkPath := systemdEnableLinkPath(layout)
	if err := os.MkdirAll(filepath.Dir(linkPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../foreign.service", linkPath); err != nil {
		t.Fatal(err)
	}
	setCleanupTestEnvironment(t, layout)
	commandLog := filepath.Join(t.TempDir(), "systemctl.log")
	installFakeSystemctl(t, commandLog, "")
	lifecycleRoot := t.TempDir()

	_, err := Install(
		lockfile.WithLifecyclePathsForTest(
			t.Context(),
			filepath.Join(lifecycleRoot, "daemon.lease"),
			filepath.Join(lifecycleRoot, "maintenance.gate"),
		),
		Options{System: "systemd", Enable: true},
	)
	if err == nil || !strings.Contains(err.Error(), "target") {
		t.Fatalf("install error = %v, want foreign enable link rejection", err)
	}
	if target, readErr := os.Readlink(linkPath); readErr != nil ||
		target != "../foreign.service" {
		t.Fatalf("foreign enable link target = %q err=%v", target, readErr)
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

func TestInstallTreatsStandaloneBinaryAsUnmarkedResource(t *testing.T) {
	root := t.TempDir()
	layout := cleanupTestPaths(root, "binary-only")
	if err := os.MkdirAll(filepath.Dir(layout.BinaryPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(layout.BinaryPath, []byte("foreign"), 0o755); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(layout.BinaryPath)
	if err != nil {
		t.Fatal(err)
	}
	setCleanupTestEnvironment(t, layout)
	ctx := lockfile.WithLifecyclePathsForTest(
		t.Context(),
		filepath.Join(root, "daemon.lease"),
		filepath.Join(root, "maintenance.gate"),
	)

	_, err = Install(ctx, Options{System: "unknown"})
	if err == nil || !strings.Contains(err.Error(), "--adopt-existing") {
		t.Fatalf("install error = %v, want standalone-binary adoption rejection", err)
	}
	after, err := os.Stat(layout.BinaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("rejected install replaced the standalone binary")
	}
	if data, err := os.ReadFile(layout.BinaryPath); err != nil ||
		string(data) != "foreign" {
		t.Fatalf("rejected install changed standalone binary: data=%q err=%v", data, err)
	}
	for _, path := range []string{
		filepath.Dir(layout.ConfigPath),
		layout.RunDir,
		layout.VarLibDir,
	} {
		if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("rejected standalone-binary adoption created %s: %v", path, statErr)
		}
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

func TestInstallAdoptionRecreatesMissingStateSiblingAfterConfigBaseline(
	t *testing.T,
) {
	layout := cleanupTestPaths(t.TempDir(), "adoption-missing-state")
	if err := os.MkdirAll(filepath.Dir(layout.ConfigPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := config.SaveFile(layout.ConfigPath, config.SafeTemplate()); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(layout.RunDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(layout.RunDir, "lock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	setCleanupTestEnvironment(t, layout)
	lifecycleRoot := t.TempDir()

	if _, err := Install(
		lockfile.WithLifecyclePathsForTest(
			t.Context(),
			filepath.Join(lifecycleRoot, "daemon.lease"),
			filepath.Join(lifecycleRoot, "maintenance.gate"),
		),
		Options{System: "unknown", AdoptExisting: true},
	); err != nil {
		t.Fatalf("adopt install with missing state sibling: %v", err)
	}
	if info, err := os.Stat(layout.VarLibDir); err != nil || !info.IsDir() {
		t.Fatalf("recreated state directory info=%v err=%v", info, err)
	}
	if _, err := os.Stat(cleanupManifestPath(layout)); err != nil {
		t.Fatalf("adoption did not publish ownership manifest: %v", err)
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

func TestMarkedReinstallRejectsSymlinkedConfigBeforeWrites(t *testing.T) {
	layout := newCleanupTestLayout(t, "marked-config-link")
	setCleanupTestEnvironment(t, layout)
	foreignConfig := filepath.Join(t.TempDir(), "foreign-config.yaml")
	if err := config.SaveFile(foreignConfig, config.SafeTemplate()); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(layout.ConfigPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(foreignConfig, layout.ConfigPath); err != nil {
		t.Fatal(err)
	}
	lifecycleRoot := t.TempDir()
	_, err := Install(
		lockfile.WithLifecyclePathsForTest(
			t.Context(),
			filepath.Join(lifecycleRoot, "daemon.lease"),
			filepath.Join(lifecycleRoot, "maintenance.gate"),
		),
		Options{System: "unknown"},
	)
	if err == nil || !strings.Contains(err.Error(), "marked install config") {
		t.Fatalf("marked reinstall error = %v, want config ownership rejection", err)
	}
	if _, statErr := os.Lstat(layout.BinaryPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("config rejection installed binary first: %v", statErr)
	}
	if info, statErr := os.Lstat(layout.ConfigPath); statErr != nil ||
		info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf(
			"config rejection replaced the foreign symlink: info=%v err=%v",
			info,
			statErr,
		)
	}
	if _, statErr := os.Stat(foreignConfig); statErr != nil {
		t.Fatalf("config rejection changed the symlink target: %v", statErr)
	}
	if _, statErr := os.Stat(cleanupManifestPath(layout)); statErr != nil {
		t.Fatalf("config rejection changed the ownership manifest: %v", statErr)
	}
}

func TestMarkedReinstallRetainsConfigDescriptorIdentity(t *testing.T) {
	layout := newCleanupTestLayout(t, "marked-config-identity")
	publication, err := prepareCleanupManifestPublication(
		layout,
		"unknown",
		cleanupManifestWriteOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer publication.close()

	originalConfig := layout.ConfigPath + ".original"
	if err := os.Rename(layout.ConfigPath, originalConfig); err != nil {
		t.Fatal(err)
	}
	if err := config.SaveFile(layout.ConfigPath, config.SafeTemplate()); err != nil {
		t.Fatal(err)
	}
	if err := publication.publish(); err == nil ||
		(!strings.Contains(err.Error(), "marked install config") &&
			!strings.Contains(err.Error(), "directory generation changed")) {
		t.Fatalf("publication error = %v, want held config identity rejection", err)
	}
	if _, statErr := os.Stat(originalConfig); statErr != nil {
		t.Fatalf("held original config changed: %v", statErr)
	}
	if _, statErr := os.Stat(layout.ConfigPath); statErr != nil {
		t.Fatalf("foreign config replacement changed: %v", statErr)
	}
}

func TestMarkedReinstallRetainsManifestDescriptorIdentity(t *testing.T) {
	layout := newCleanupTestLayout(t, "marked-manifest-identity")
	publication, err := prepareCleanupManifestPublication(
		layout,
		"unknown",
		cleanupManifestWriteOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer publication.close()

	markerPath := cleanupManifestPath(layout)
	markerData, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	originalMarker := markerPath + ".original"
	if err := os.Rename(markerPath, originalMarker); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(markerPath, markerData, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := publication.publish(); err == nil ||
		!strings.Contains(err.Error(), "marked install manifest") {
		t.Fatalf("publication error = %v, want held manifest identity rejection", err)
	}
	if data, readErr := os.ReadFile(originalMarker); readErr != nil ||
		string(data) != string(markerData) {
		t.Fatalf("held original manifest changed: data=%q err=%v", data, readErr)
	}
	if data, readErr := os.ReadFile(markerPath); readErr != nil ||
		string(data) != string(markerData) {
		t.Fatalf("foreign manifest replacement changed: data=%q err=%v", data, readErr)
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
	originalStatus := filepath.Join(t.TempDir(), "status.original")
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
		if err := os.Rename(statusPath, originalStatus); err != nil {
			return err
		}
		return os.WriteFile(statusPath, []byte("{}\n"), 0o600)
	}
	err = plan.execute()
	if err == nil ||
		(!strings.Contains(err.Error(), "identity changed") &&
			!strings.Contains(err.Error(), "directory generation changed")) {
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
	for _, dir := range []string{
		filepath.Dir(layout.ConfigPath),
		layout.SystemdDir,
		filepath.Dir(systemdEnableLinkPath(layout)),
	} {
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
	originalUnit := filepath.Join(t.TempDir(), "unit.original")
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
	if err == nil ||
		(!strings.Contains(err.Error(), "moved object identity") &&
			!strings.Contains(err.Error(), "component generation changed")) {
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
	originalStateDir := layout.VarLibDir + "-original"
	foreignStateDir := filepath.Join(filepath.Dir(layout.VarLibDir), "foreign-state")
	if err := os.Mkdir(foreignStateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	foreignMarker := filepath.Join(foreignStateDir, "keep")
	if err := os.WriteFile(foreignMarker, []byte("keep\n"), 0o600); err != nil {
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
	if err == nil ||
		(!strings.Contains(err.Error(), "directory identity changed") &&
			!strings.Contains(err.Error(), "held parent generation changed") &&
			!strings.Contains(err.Error(), "pathname no longer names")) {
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
	if err == nil ||
		(!strings.Contains(err.Error(), "unplanned entries") &&
			!strings.Contains(err.Error(), "directory generation changed")) {
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

func TestInstalledServiceArtifactRejectsParentPathSwap(t *testing.T) {
	layout := newCleanupTestLayoutForSystem(
		t,
		"install-artifact-parent-swap",
		"systemd",
	)
	if err := installServiceArtifacts(layout, "systemd", nil, nil); err != nil {
		t.Fatal(err)
	}
	artifact, err := openInstalledServiceArtifact(
		layout,
		"systemd",
		"systemd-unit",
	)
	if err != nil {
		t.Fatal(err)
	}
	defer artifact.close()

	originalDir := layout.SystemdDir + ".owned-original"
	if err := os.Rename(layout.SystemdDir, originalDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(layout.SystemdDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(layout.SystemdDir, "wg-mix-ebpf.service"),
		[]byte(systemdUnit(layout.ConfigPath, layout.BinaryPath)),
		0o644,
	); err != nil {
		t.Fatal(err)
	}
	if err := artifact.revalidateForExecution(); err == nil ||
		!strings.Contains(err.Error(), "parent identity changed") {
		t.Fatalf("artifact revalidation error = %v, want parent rejection", err)
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

func TestVerifiedOpenWrtInitRestoresInstalledServiceIdentity(t *testing.T) {
	descriptorPath := "/proc/self/fd/3"
	if runtime.GOOS == "darwin" {
		descriptorPath = "/dev/fd/3"
	} else if runtime.GOOS != "linux" {
		t.Skip("verified OpenWrt descriptor sourcing requires a procfs or devfs FD path")
	}
	initPath := "/etc/init.d/wg-mix-ebpf"
	configPath := "/etc/wg-mix-ebpf/config.yaml"
	scriptPath := filepath.Join(t.TempDir(), "held-init")
	if err := os.WriteFile(
		scriptPath,
		[]byte(openWrtInit(configPath, "/usr/sbin/wg-mix-ebpf", initPath)),
		0o700,
	); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(scriptPath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	resultPath := filepath.Join(t.TempDir(), "identity.log")
	harnessPath := filepath.Join(t.TempDir(), "rc.common-harness")
	harness := `#!/bin/sh
initscript=$1
verified_source=$1
. "$initscript"
printf '%s\n%s\n%s\n%s\n' \
    "$verified_source" \
    "$initscript" \
    "${initscript##*/}" \
    "$CONF" > "$2"
`
	if err := os.WriteFile(harnessPath, []byte(harness), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(
		t.Context(),
		"/bin/sh",
		harnessPath,
		descriptorPath,
		resultPath,
	)
	cmd.ExtraFiles = []*os.File{file}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("source verified OpenWrt init through descriptor: %v: %s", err, out)
	}
	data, err := os.ReadFile(resultPath)
	if err != nil {
		t.Fatal(err)
	}
	want := descriptorPath + "\n" +
		initPath + "\n" +
		"wg-mix-ebpf\n" +
		configPath + "\n"
	if string(data) != want {
		t.Fatalf("rc.common identity result = %q, want %q", data, want)
	}
}

func TestOpenWrtServiceActionRejectsFinalPathSwapWithoutExecutingForeign(t *testing.T) {
	layout := newCleanupTestLayoutForSystem(t, "openwrt-final-exec-swap", "openwrt")
	initPath := filepath.Join(layout.OpenWrtInitDir, "wg-mix-ebpf")
	lifecyclePath := filepath.Join(t.TempDir(), "daemon.lease")
	foreignLog := filepath.Join(t.TempDir(), "foreign-executed")
	plan, err := prepareUninstallCleanup(
		layout,
		"openwrt",
		false,
		lifecyclePath,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.close()

	originalPath := initPath + ".owned-original"
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
	err = runOpenWrtServiceActions(t.Context(), plan, "stop")
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
		string(data) != openWrtInit(layout.ConfigPath, layout.BinaryPath, initPath) {
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
		for _, dir := range []string{
			layout.SystemdDir,
			filepath.Dir(systemdEnableLinkPath(layout)),
		} {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return err
			}
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
			[]byte(openWrtInit(
				layout.ConfigPath,
				layout.BinaryPath,
				filepath.Join(layout.OpenWrtInitDir, "wg-mix-ebpf"),
			)),
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
	t.Setenv(
		"WG_MIX_EBPF_TEST_SYSTEMCTL_FRAGMENT",
		filepath.Join(layout.SystemdDir, "wg-mix-ebpf.service"),
	)
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
	logCommand := ""
	if commandLog != "" {
		t.Setenv("WG_MIX_EBPF_TEST_NFT_LOG", commandLog)
		logCommand = `printf '%s\n' "$*" >> "$WG_MIX_EBPF_TEST_NFT_LOG"` + "\n"
	}
	script := "#!/bin/sh\n" + logCommand + `if [ "$1" = "-j" ] &&
	[ "$2" = "list" ] && [ "$3" = "tables" ]; then
	printf '%s\n' '{"nftables":[{"metainfo":{"json_schema_version":1}}]}'
	exit 0
fi
printf '%s\n' 'Error: No such file or directory' 'list table inet wg_mix_ebpf_guard' >&2
exit 1
`
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
	t.Setenv("WG_MIX_EBPF_TEST_SYSTEMCTL_FAIL_OCCURRENCE", "1")
	t.Setenv("WG_MIX_EBPF_TEST_SYSTEMCTL_DROP_INS", "")
	t.Setenv("WG_MIX_EBPF_TEST_SYSTEMCTL_NEEDS_RELOAD", "no")
	t.Setenv("WG_MIX_EBPF_TEST_SYSTEMCTL_LOAD_STATE", "loaded")
	t.Setenv("WG_MIX_EBPF_TEST_SYSTEMCTL_TRANSIENT", "no")
	t.Setenv("WG_MIX_EBPF_TEST_SYSTEMCTL_SWAP_ACTION", "")
	t.Setenv("WG_MIX_EBPF_TEST_SYSTEMCTL_SWAP_PATH", "")
	t.Setenv("WG_MIX_EBPF_TEST_SYSTEMCTL_SWAP_CONTENT", "")
	t.Setenv("WG_MIX_EBPF_TEST_SYSTEMCTL_CHAIN_MUTATE_ACTION", "")
	t.Setenv("WG_MIX_EBPF_TEST_SYSTEMCTL_CHAIN_MUTATE_PATH", "")
	script := `#!/bin/sh
if [ -n "$WG_MIX_EBPF_TEST_SYSTEMCTL_CHAIN_MUTATE_ACTION" ] &&
	[ "$1" = "$WG_MIX_EBPF_TEST_SYSTEMCTL_CHAIN_MUTATE_ACTION" ]; then
	mv "$WG_MIX_EBPF_TEST_SYSTEMCTL_CHAIN_MUTATE_PATH" \
		"$WG_MIX_EBPF_TEST_SYSTEMCTL_CHAIN_MUTATE_PATH.chain-away" || exit
	mv "$WG_MIX_EBPF_TEST_SYSTEMCTL_CHAIN_MUTATE_PATH.chain-away" \
		"$WG_MIX_EBPF_TEST_SYSTEMCTL_CHAIN_MUTATE_PATH" || exit
fi
if [ -n "$WG_MIX_EBPF_TEST_SYSTEMCTL_SWAP_ACTION" ] &&
	[ "$1" = "$WG_MIX_EBPF_TEST_SYSTEMCTL_SWAP_ACTION" ]; then
	mv "$WG_MIX_EBPF_TEST_SYSTEMCTL_SWAP_PATH" \
		"$WG_MIX_EBPF_TEST_SYSTEMCTL_SWAP_PATH.owned-original" || exit
	cp "$WG_MIX_EBPF_TEST_SYSTEMCTL_SWAP_CONTENT" \
		"$WG_MIX_EBPF_TEST_SYSTEMCTL_SWAP_PATH" || exit
fi
if [ "$1" = "show" ]; then
	printf 'FragmentPath=%s\n' "$WG_MIX_EBPF_TEST_SYSTEMCTL_FRAGMENT"
	printf 'DropInPaths=%s\n' "$WG_MIX_EBPF_TEST_SYSTEMCTL_DROP_INS"
	printf 'NeedDaemonReload=%s\n' "$WG_MIX_EBPF_TEST_SYSTEMCTL_NEEDS_RELOAD"
	printf 'LoadState=%s\n' "$WG_MIX_EBPF_TEST_SYSTEMCTL_LOAD_STATE"
	printf 'Transient=%s\n' "$WG_MIX_EBPF_TEST_SYSTEMCTL_TRANSIENT"
	exit 0
fi
printf '%s\n' "$*" >> "$WG_MIX_EBPF_TEST_SYSTEMCTL_LOG"
if [ "$1" = "$WG_MIX_EBPF_TEST_SYSTEMCTL_FAIL" ]; then
	seen=0
	while IFS= read -r logged; do
		case "$logged" in
			"$1"|"$1 "*) seen=$((seen + 1)) ;;
		esac
	done < "$WG_MIX_EBPF_TEST_SYSTEMCTL_LOG"
	[ "$seen" -ne "$WG_MIX_EBPF_TEST_SYSTEMCTL_FAIL_OCCURRENCE" ]
	exit
fi
exit 0
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
	os.Exit(testutil.RunWithStandardUmask(func() int {
		const testTempPrefix = ".wg-mix-ebpf-install-tests-"
		workingDir, err := os.Getwd()
		if err != nil {
			fmt.Fprintf(os.Stderr, "resolve install package test directory: %v\n", err)
			return 1
		}
		workingDir = filepath.Clean(workingDir)
		testTempRoot, err := os.MkdirTemp(
			workingDir,
			testTempPrefix,
		)
		if err != nil {
			fmt.Fprintf(os.Stderr, "create isolated install test root: %v\n", err)
			return 1
		}
		removeTestTempRoot := func() error {
			if testTempRoot == "" ||
				!filepath.IsAbs(testTempRoot) ||
				filepath.Clean(testTempRoot) != testTempRoot ||
				filepath.Dir(testTempRoot) != workingDir ||
				!strings.HasPrefix(filepath.Base(testTempRoot), testTempPrefix) {
				return fmt.Errorf(
					"refuse unsafe isolated install test root cleanup %q",
					testTempRoot,
				)
			}
			entries, err := os.ReadDir(testTempRoot)
			if err != nil {
				return err
			}
			if len(entries) != 0 {
				return fmt.Errorf(
					"isolated install test root %s retained %d entries",
					testTempRoot,
					len(entries),
				)
			}
			return os.Remove(testTempRoot)
		}
		if err := os.Setenv("TMPDIR", testTempRoot); err != nil {
			fmt.Fprintf(os.Stderr, "set isolated install test root: %v\n", err)
			if removeErr := removeTestTempRoot(); removeErr != nil {
				fmt.Fprintf(
					os.Stderr,
					"remove isolated install test root %s: %v\n",
					testTempRoot,
					removeErr,
				)
			}
			return 1
		}

		code := m.Run()
		if err := removeTestTempRoot(); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"remove isolated install test root %s: %v\n",
				testTempRoot,
				err,
			)
			if code == 0 {
				code = 1
			}
		}
		return code
	}))
}
