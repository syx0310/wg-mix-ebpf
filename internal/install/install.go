package install

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/syx0310/wg-mix-ebpf/internal/attachstate"
	"github.com/syx0310/wg-mix-ebpf/internal/config"
	"github.com/syx0310/wg-mix-ebpf/internal/daemon"
	"github.com/syx0310/wg-mix-ebpf/internal/dataplane"
	"github.com/syx0310/wg-mix-ebpf/internal/guard"
	"github.com/syx0310/wg-mix-ebpf/internal/lockfile"
	"github.com/syx0310/wg-mix-ebpf/internal/reconcile"
	"github.com/syx0310/wg-mix-ebpf/internal/runtime"
)

const (
	EnvEtcDir         = "WG_MIX_EBPF_ETC_DIR"
	EnvBinaryPath     = "WG_MIX_EBPF_BINARY_PATH"
	EnvVarLibDir      = "WG_MIX_EBPF_VAR_LIB_DIR"
	EnvSystemdDir     = "WG_MIX_EBPF_SYSTEMD_DIR"
	EnvOpenWrtInit    = "WG_MIX_EBPF_OPENWRT_INIT_DIR"
	EnvOpenWrtHotplug = "WG_MIX_EBPF_OPENWRT_HOTPLUG_DIR"
)

type Options struct {
	ConfigPath string
	System     string
	Enable     bool
	DryRun     bool
	Yes        bool
	Purge      bool
}

type Plan struct {
	System     string   `json:"system"`
	Actions    []string `json:"actions"`
	ConfigPath string   `json:"config_path"`
	BinaryPath string   `json:"binary_path"`
}

func Install(ctx context.Context, opts Options) (*Plan, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	system := detectSystem(opts.System)
	paths := resolvedPaths(opts.ConfigPath)
	plan := &Plan{System: system, ConfigPath: paths.ConfigPath, BinaryPath: paths.BinaryPath}
	add := func(format string, args ...any) { plan.Actions = append(plan.Actions, fmt.Sprintf(format, args...)) }

	add("ensure directory %s", filepath.Dir(paths.ConfigPath))
	add("ensure directory %s", paths.VarLibDir)
	add("ensure directory %s", paths.RunDir)
	add("install binary to %s", paths.BinaryPath)
	add("write safe template if %s is missing", paths.ConfigPath)
	switch system {
	case "systemd":
		add("write systemd unit %s", filepath.Join(paths.SystemdDir, "wg-mix-ebpf.service"))
		if opts.Enable {
			add("enable systemd service")
		}
	case "openwrt":
		add("write OpenWrt init script %s", filepath.Join(paths.OpenWrtInitDir, "wg-mix-ebpf"))
		add("write OpenWrt hotplug script %s", filepath.Join(paths.OpenWrtHotplugDir, "90-wg-mix-ebpf"))
		if opts.Enable {
			add("enable OpenWrt service")
		}
	default:
		add("skip service registration for unknown init system")
	}
	if opts.DryRun {
		return plan, nil
	}

	owner := lockfile.LifecycleOwner{
		PID:        os.Getpid(),
		Action:     "install",
		ConfigPath: paths.ConfigPath,
		RunDir:     paths.RunDir,
	}
	if err := lockfile.WithLifecycle(ctx, nil, owner, func(*lockfile.LifecycleLease) error {
		return lockfile.WithLock(ctx, paths.RunDir, func() error {
			return applyInstall(ctx, opts, system, paths)
		})
	}); err != nil {
		return nil, err
	}
	return plan, nil
}

func applyInstall(ctx context.Context, opts Options, system string, paths paths) error {
	for _, dir := range []string{filepath.Dir(paths.ConfigPath), paths.VarLibDir, paths.RunDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}
	if err := installBinary(paths.BinaryPath); err != nil {
		return err
	}
	if _, err := os.Stat(paths.ConfigPath); errors.Is(err, os.ErrNotExist) {
		if err := config.SaveFile(paths.ConfigPath, config.SafeTemplate()); err != nil {
			return err
		}
	} else if err != nil {
		return fmt.Errorf("stat config %s: %w", paths.ConfigPath, err)
	}
	switch system {
	case "systemd":
		if err := os.MkdirAll(paths.SystemdDir, 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(paths.SystemdDir, "wg-mix-ebpf.service"), []byte(systemdUnit(paths.ConfigPath, paths.BinaryPath)), 0o644); err != nil {
			return err
		}
		if err := runCommand(ctx, "systemctl", "daemon-reload"); err != nil {
			return err
		}
		if opts.Enable {
			if err := runCommand(ctx, "systemctl", "enable", "wg-mix-ebpf.service"); err != nil {
				return err
			}
		}
	case "openwrt":
		if err := os.MkdirAll(paths.OpenWrtInitDir, 0o755); err != nil {
			return err
		}
		if err := os.MkdirAll(paths.OpenWrtHotplugDir, 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(paths.OpenWrtInitDir, "wg-mix-ebpf"), []byte(openWrtInit(paths.ConfigPath, paths.BinaryPath)), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(paths.OpenWrtHotplugDir, "90-wg-mix-ebpf"), []byte(openWrtHotplug()), 0o755); err != nil {
			return err
		}
		if opts.Enable {
			if err := runCommand(ctx, filepath.Join(paths.OpenWrtInitDir, "wg-mix-ebpf"), "enable"); err != nil {
				return err
			}
		}
	}
	return nil
}

func Uninstall(ctx context.Context, opts Options) (*Plan, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	system := detectSystem(opts.System)
	paths := resolvedPaths(opts.ConfigPath)
	if err := validateCleanupPaths(paths); err != nil {
		return nil, err
	}
	plan := &Plan{System: system, ConfigPath: paths.ConfigPath, BinaryPath: paths.BinaryPath}
	add := func(format string, args ...any) { plan.Actions = append(plan.Actions, fmt.Sprintf(format, args...)) }
	add("stop wg-mix-ebpf service if present")
	add("detach dataplane using attach-state when available, with config fallback")
	add("remove BPF pins under %s", paths.PinPath)
	add("remove nft startup guard table")
	add("remove runtime state under %s while preserving the global lifecycle lease", paths.RunDir)
	add("remove state dir %s", paths.VarLibDir)
	switch system {
	case "systemd":
		add("remove systemd unit %s", filepath.Join(paths.SystemdDir, "wg-mix-ebpf.service"))
	case "openwrt":
		add("remove OpenWrt init/hotplug scripts")
	}
	if opts.Purge {
		if err := validatePurgeDir(paths); err != nil {
			return nil, err
		}
		add("purge owned config dir %s", filepath.Dir(paths.ConfigPath))
	} else {
		add("keep config %s", paths.ConfigPath)
	}
	add("keep binary %s", paths.BinaryPath)
	add("binary removal hint: remove %s manually or with the package manager that installed it", paths.BinaryPath)
	if opts.DryRun {
		return plan, nil
	}
	if !opts.Yes && wireGuardAppearsRunning(ctx, paths.ConfigPath) {
		return nil, errors.New("managed WireGuard runtime appears active; rerun uninstall with --yes to detach transform and continue")
	}
	switch system {
	case "systemd":
		unitPath := filepath.Join(paths.SystemdDir, "wg-mix-ebpf.service")
		if exists(unitPath) {
			if err := runCommand(ctx, "systemctl", "stop", "wg-mix-ebpf.service"); err != nil {
				return nil, err
			}
		}
	case "openwrt":
		initPath := filepath.Join(paths.OpenWrtInitDir, "wg-mix-ebpf")
		if exists(initPath) {
			if err := runCommand(ctx, initPath, "stop"); err != nil {
				return nil, err
			}
		}
	}
	owner := lockfile.LifecycleOwner{
		PID:        os.Getpid(),
		Action:     "uninstall",
		ConfigPath: paths.ConfigPath,
		RunDir:     paths.RunDir,
	}
	if err := lockfile.WithLifecycle(ctx, nil, owner, func(lease *lockfile.LifecycleLease) error {
		stopped := false
		if shouldStopForUninstall(paths) {
			if _, err := reconcile.Stop(ctx, reconcile.Options{
				ConfigPath:     paths.ConfigPath,
				RunDir:         paths.RunDir,
				StateDir:       paths.VarLibDir,
				LifecycleLease: lease,
			}); err != nil {
				return fmt.Errorf("detach dataplane: %w", err)
			}
			stopped = true
		}
		if err := lockfile.WithLock(ctx, paths.RunDir, func() error {
			if !stopped {
				if err := guard.NewCommandExecutor().Cleanup(ctx); err != nil {
					return fmt.Errorf("cleanup startup guard: %w", err)
				}
			}
			if err := os.RemoveAll(paths.PinPath); err != nil {
				return fmt.Errorf("remove BPF pins %s: %w", paths.PinPath, err)
			}
			if err := os.RemoveAll(paths.VarLibDir); err != nil {
				return fmt.Errorf("remove state dir %s: %w", paths.VarLibDir, err)
			}
			switch system {
			case "systemd":
				if err := removeIfExists(filepath.Join(paths.SystemdDir, "wg-mix-ebpf.service")); err != nil {
					return err
				}
				if err := runCommand(ctx, "systemctl", "daemon-reload"); err != nil {
					return err
				}
			case "openwrt":
				if err := removeIfExists(filepath.Join(paths.OpenWrtInitDir, "wg-mix-ebpf")); err != nil {
					return err
				}
				if err := removeIfExists(filepath.Join(paths.OpenWrtHotplugDir, "90-wg-mix-ebpf")); err != nil {
					return err
				}
			}
			if opts.Purge {
				if err := os.RemoveAll(filepath.Dir(paths.ConfigPath)); err != nil {
					return fmt.Errorf("purge config dir %s: %w", filepath.Dir(paths.ConfigPath), err)
				}
			}
			return nil
		}); err != nil {
			return err
		}
		return cleanupRuntimeDir(paths.RunDir, lockfile.LifecycleLeasePath(ctx))
	}); err != nil {
		return nil, err
	}
	return plan, nil
}

func cleanupRuntimeDir(runDir string, lifecyclePath string) error {
	if filepath.Clean(runDir) != filepath.Clean(filepath.Dir(lifecyclePath)) {
		if err := os.RemoveAll(runDir); err != nil {
			return fmt.Errorf("remove runtime dir %s: %w", runDir, err)
		}
		return nil
	}
	entries, err := os.ReadDir(runDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read runtime dir %s: %w", runDir, err)
	}
	for _, entry := range entries {
		path := filepath.Join(runDir, entry.Name())
		if filepath.Clean(path) == filepath.Clean(lifecyclePath) {
			continue
		}
		if err := os.RemoveAll(path); err != nil {
			return fmt.Errorf("remove runtime entry %s: %w", path, err)
		}
	}
	return nil
}

func shouldStopForUninstall(paths paths) bool {
	return exists(paths.ConfigPath) || exists(attachstate.Path(paths.VarLibDir))
}

type paths struct {
	ConfigPath        string
	BinaryPath        string
	VarLibDir         string
	RunDir            string
	SystemdDir        string
	OpenWrtInitDir    string
	OpenWrtHotplugDir string
	PinPath           string
}

func resolvedPaths(configPath string) paths {
	etcDir := envOr(EnvEtcDir, "/etc/wg-mix-ebpf")
	if configPath == "" {
		configPath = filepath.Join(etcDir, "config.yaml")
	}
	return paths{
		ConfigPath:        configPath,
		BinaryPath:        envOr(EnvBinaryPath, "/usr/sbin/wg-mix-ebpf"),
		VarLibDir:         envOr(EnvVarLibDir, "/var/lib/wg-mix-ebpf"),
		RunDir:            envOr(daemon.EnvRunDir, daemon.DefaultRunDir),
		SystemdDir:        envOr(EnvSystemdDir, "/etc/systemd/system"),
		OpenWrtInitDir:    envOr(EnvOpenWrtInit, "/etc/init.d"),
		OpenWrtHotplugDir: envOr(EnvOpenWrtHotplug, "/etc/hotplug.d/iface"),
		PinPath:           envOr(dataplane.EnvPinPath, dataplane.DefaultPinPath),
	}
}

func installBinary(target string) error {
	src, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve current executable: %w", err)
	}
	srcAbs, _ := filepath.Abs(src)
	dstAbs, _ := filepath.Abs(target)
	if srcAbs == dstAbs {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.CreateTemp(filepath.Dir(target), "."+filepath.Base(target)+".tmp-")
	if err != nil {
		return err
	}
	tmpPath := out.Name()
	defer os.Remove(tmpPath)
	if err := out.Chmod(0o755); err != nil {
		_ = out.Close()
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, target); err != nil {
		return err
	}
	return nil
}

func wireGuardAppearsRunning(ctx context.Context, configPath string) bool {
	cfg, err := config.LoadFileLenient(configPath)
	if err != nil {
		return false
	}
	provider := runtime.NewSystemProvider()
	for _, wg := range cfg.WireGuards {
		if _, err := provider.Device(ctx, wg.Name); err == nil {
			return true
		}
	}
	return false
}

func validatePurgeDir(paths paths) error {
	configDir := filepath.Clean(filepath.Dir(paths.ConfigPath))
	ownedDir := filepath.Clean(envOr(EnvEtcDir, "/etc/wg-mix-ebpf"))
	if configDir != ownedDir {
		return fmt.Errorf("refuse to purge non-owned config directory %s; only %s is managed by uninstall --purge", configDir, ownedDir)
	}
	switch configDir {
	case "/", "/etc", "/tmp", "/var", "/usr", "/usr/sbin", "/run", "/var/lib":
		return fmt.Errorf("refuse to purge unsafe config directory %s", configDir)
	}
	if configDir == "." || configDir == "" {
		return fmt.Errorf("refuse to purge invalid config directory %q", configDir)
	}
	return nil
}

func validateCleanupPaths(paths paths) error {
	cleanup := []struct {
		name string
		path string
	}{
		{name: "runtime dir", path: paths.RunDir},
		{name: "state dir", path: paths.VarLibDir},
		{name: "BPF pin path", path: paths.PinPath},
	}
	protected := map[string]struct{}{
		"/": {}, "/bin": {}, "/boot": {}, "/dev": {}, "/etc": {}, "/home": {},
		"/lib": {}, "/lib64": {}, "/opt": {}, "/proc": {}, "/root": {}, "/run": {},
		"/sbin": {}, "/srv": {}, "/sys": {}, "/sys/fs": {}, "/sys/fs/bpf": {},
		"/tmp": {}, "/usr": {}, "/var": {}, "/var/lib": {},
		"/Library": {}, "/System": {}, "/Users": {}, "/private": {},
		"/private/tmp": {}, "/private/var": {},
	}
	configDir := filepath.Clean(filepath.Dir(paths.ConfigPath))
	allowedRoots := map[string][]string{
		"runtime dir":  {"/run", "/var/run", os.TempDir()},
		"state dir":    {"/var/lib", os.TempDir()},
		"BPF pin path": {"/sys/fs/bpf", os.TempDir()},
	}
	for i := range cleanup {
		cleanup[i].path = filepath.Clean(cleanup[i].path)
		if !filepath.IsAbs(cleanup[i].path) {
			return fmt.Errorf("refuse unsafe relative %s %q", cleanup[i].name, cleanup[i].path)
		}
		if _, denied := protected[cleanup[i].path]; denied {
			return fmt.Errorf("refuse unsafe %s %s", cleanup[i].name, cleanup[i].path)
		}
		allowed := false
		for _, root := range allowedRoots[cleanup[i].name] {
			root = filepath.Clean(root)
			if cleanup[i].path != root && pathContains(root, cleanup[i].path) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("refuse %s outside its managed roots: %s", cleanup[i].name, cleanup[i].path)
		}
		if pathContains(cleanup[i].path, configDir) {
			return fmt.Errorf("refuse %s %s because it contains config directory %s", cleanup[i].name, cleanup[i].path, configDir)
		}
	}
	for i := 0; i < len(cleanup); i++ {
		for j := i + 1; j < len(cleanup); j++ {
			if pathContains(cleanup[i].path, cleanup[j].path) || pathContains(cleanup[j].path, cleanup[i].path) {
				return fmt.Errorf("refuse overlapping cleanup paths %s and %s", cleanup[i].path, cleanup[j].path)
			}
		}
	}
	return nil
}

func pathContains(parent string, child string) bool {
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)))
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", path, err)
	}
	return nil
}

func detectSystem(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if _, err := os.Stat("/etc/openwrt_release"); err == nil {
		return "openwrt"
	}
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		return "systemd"
	}
	if _, err := exec.LookPath("systemctl"); err == nil {
		return "systemd"
	}
	return "unknown"
}

func runCommand(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s failed: %w: %s", name, strings.Join(args, " "), err, string(out))
	}
	return nil
}

func envOr(name string, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func systemdUnit(configPath string, binaryPath string) string {
	return fmt.Sprintf(`[Unit]
Description=wg-mix-ebpf transparent WireGuard type-word transform
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s run --config %s
ExecReload=%s reload --config %s
ExecStop=%s stop --config %s
Restart=on-failure
RestartSec=3s

[Install]
WantedBy=multi-user.target
`, binaryPath, configPath, binaryPath, configPath, binaryPath, configPath)
}

func openWrtInit(configPath string, binaryPath string) string {
	return fmt.Sprintf(`#!/bin/sh /etc/rc.common

USE_PROCD=1
START=99
STOP=10

CONF="%s"

start_service() {
    procd_open_instance
    procd_set_param command %s run --config "$CONF" --openwrt
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_set_param respawn
    procd_close_instance
}

reload_service() {
    %s reload --config "$CONF"
}

stop_service() {
    %s stop --config "$CONF"
}
`, configPath, binaryPath, binaryPath, binaryPath)
}

func openWrtHotplug() string {
	return `#!/bin/sh

[ "$ACTION" = "ifup" ] || [ "$ACTION" = "ifupdate" ] || [ "$ACTION" = "ifdown" ] || exit 0
mkdir -p /run/wg-mix-ebpf
{
    cat /proc/uptime 2>/dev/null
    echo "$$"
    echo "$ACTION"
    echo "$INTERFACE"
    echo "$DEVICE"
} > /run/wg-mix-ebpf/runtime.request
`
}
