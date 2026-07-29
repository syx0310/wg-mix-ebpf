package install

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

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
	ConfigPath    string
	System        string
	Enable        bool
	DryRun        bool
	Yes           bool
	Purge         bool
	AdoptExisting bool
}

type Plan struct {
	System     string   `json:"system"`
	Actions    []string `json:"actions"`
	ConfigPath string   `json:"config_path"`
	BinaryPath string   `json:"binary_path"`
}

type installAfterInspectHookContextKey struct{}
type installAfterLifecycleHookContextKey struct{}

func Install(ctx context.Context, opts Options) (*Plan, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	system := detectSystem(opts.System)
	paths := resolvedPaths(opts.ConfigPath)
	if err := validateInstallOwnershipPaths(paths); err != nil {
		return nil, err
	}
	ownership, err := inspectInstallCleanupOwnership(paths, system)
	if err != nil {
		return nil, err
	}
	if ownership == cleanupOwnershipUnmarked && !opts.AdoptExisting {
		return nil, errors.New(
			"refuse to adopt unmarked installation resources without explicit authorization; " +
				"review the resolved paths and rerun install with --adopt-existing",
		)
	}
	if ownership == cleanupOwnershipUnmarked {
		if err := validateUnmarkedCleanupResources(paths, system); err != nil {
			return nil, fmt.Errorf("validate explicitly adopted installation resources: %w", err)
		}
	}
	plan := &Plan{System: system, ConfigPath: paths.ConfigPath, BinaryPath: paths.BinaryPath}
	add := func(format string, args ...any) { plan.Actions = append(plan.Actions, fmt.Sprintf(format, args...)) }

	add("ensure directory %s", filepath.Dir(paths.ConfigPath))
	add("ensure directory %s", paths.VarLibDir)
	add("ensure directory %s", paths.RunDir)
	add("install binary to %s", paths.BinaryPath)
	add("write safe template if %s is missing", paths.ConfigPath)
	if ownership == cleanupOwnershipUnmarked {
		add("adopt strictly validated existing resources under installation ownership")
	}
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
	if hook, ok := ctx.Value(installAfterInspectHookContextKey{}).(func() error); ok && hook != nil {
		if err := hook(); err != nil {
			return nil, fmt.Errorf("run install post-inspection hook: %w", err)
		}
	}

	owner := lockfile.LifecycleOwner{
		PID:        os.Getpid(),
		Action:     "install",
		ConfigPath: paths.ConfigPath,
		RunDir:     paths.RunDir,
	}
	maintenance, err := lockfile.BeginLifecycleMaintenance(ctx, owner)
	if err != nil {
		return nil, err
	}
	lease, err := maintenance.TryAcquireLifecycle(owner)
	if err != nil {
		return nil, errors.Join(err, maintenance.Close())
	}
	installErr := lockfile.WithLifecycle(ctx, lease, owner, func(
		lease *lockfile.LifecycleLease,
	) error {
		if hook, ok := ctx.Value(installAfterLifecycleHookContextKey{}).(func() error); ok &&
			hook != nil {
			if err := hook(); err != nil {
				return fmt.Errorf("run install lifecycle hook: %w", err)
			}
		}
		return lockfile.WithLock(ctx, paths.RunDir, func() error {
			lockedOwnership, err := inspectLockedInstallOwnership(
				paths,
				system,
				ownership,
				opts.AdoptExisting,
				lockfile.LifecycleLeasePath(ctx),
				lease,
			)
			if err != nil {
				return err
			}
			return applyInstall(ctx, opts, system, paths, lockedOwnership)
		})
	})
	closeErr := errors.Join(lease.Close(), maintenance.Close())
	if err := errors.Join(installErr, closeErr); err != nil {
		return nil, err
	}
	return plan, nil
}

func applyInstall(
	ctx context.Context,
	opts Options,
	system string,
	paths paths,
	ownership cleanupOwnershipState,
) (retErr error) {
	configDir := filepath.Dir(paths.ConfigPath)
	if ownership == cleanupOwnershipAbsent {
		freshConfig, err := createFreshManagedCleanupDir(configCleanupPath(configDir))
		if err != nil {
			return err
		}
		if err := freshConfig.close(); err != nil {
			return fmt.Errorf("close fresh config directory handles: %w", err)
		}
	} else if err := os.MkdirAll(configDir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", configDir, err)
	}
	var stateDir *managedCleanupDir
	defer func() {
		if stateDir != nil {
			retErr = errors.Join(retErr, stateDir.close())
		}
	}()
	publication, err := prepareCleanupManifestPublication(
		paths,
		system,
		cleanupManifestWriteOptions{
			Fresh:         ownership == cleanupOwnershipAbsent,
			AdoptExisting: ownership == cleanupOwnershipUnmarked && opts.AdoptExisting,
			LifecyclePath: lockfile.LifecycleLeasePath(ctx),
			createState: func() (*managedCleanupDir, error) {
				var err error
				stateDir, err = createFreshManagedCleanupDir(stateCleanupPath(paths.VarLibDir))
				return stateDir, err
			},
		},
	)
	if err != nil {
		return err
	}
	defer func() {
		retErr = errors.Join(retErr, publication.close())
	}()
	if stateDir == nil {
		var exists bool
		var err error
		stateDir, exists, err = openManagedCleanupDir(stateCleanupPath(paths.VarLibDir))
		if err != nil {
			return err
		}
		if !exists {
			stateDir, err = createFreshManagedCleanupDir(stateCleanupPath(paths.VarLibDir))
			if err != nil {
				return err
			}
		}
	}
	if err := revalidateManagedCleanupDir(stateDir); err != nil {
		return err
	}
	runDir, exists, err := openManagedCleanupDir(runtimeCleanupPath(paths.RunDir))
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("runtime dir %s disappeared while holding its operation lock", paths.RunDir)
	}
	if err := revalidateManagedCleanupDir(runDir); err != nil {
		_ = runDir.close()
		return err
	}
	if err := runDir.close(); err != nil {
		return fmt.Errorf("close runtime directory handles: %w", err)
	}
	if err := installServiceArtifacts(paths, system); err != nil {
		return err
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
		if err := runCommand(ctx, "systemctl", "daemon-reload"); err != nil {
			return err
		}
		if err := verifySystemdServiceFragment(ctx, paths); err != nil {
			return err
		}
		if opts.Enable {
			if err := runCommand(ctx, "systemctl", "enable", "wg-mix-ebpf.service"); err != nil {
				return err
			}
		}
	case "openwrt":
		if opts.Enable {
			if err := runInstalledOpenWrtServiceAction(ctx, paths, "enable"); err != nil {
				return err
			}
		}
	}
	if err := publication.publish(); err != nil {
		return fmt.Errorf("commit cleanup ownership after completed install: %w", err)
	}
	return nil
}

func Uninstall(ctx context.Context, opts Options) (_ *Plan, retErr error) {
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
		add("disable systemd service wg-mix-ebpf.service to remove derived enablement links")
		add("remove systemd unit %s", filepath.Join(paths.SystemdDir, "wg-mix-ebpf.service"))
		add("reload systemd manager after removing the owned unit")
	case "openwrt":
		add("disable OpenWrt service to remove derived rc.d links")
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

	initialCleanup, err := prepareUninstallCleanup(
		paths,
		system,
		opts.Purge,
		lockfile.LifecycleLeasePath(ctx),
	)
	if err != nil {
		return nil, err
	}
	defer func() {
		if initialCleanup != nil {
			if err := initialCleanup.close(); err != nil {
				retErr = errors.Join(
					retErr,
					fmt.Errorf("close initial uninstall preflight handles: %w", err),
				)
			}
		}
	}()
	ownsResources := initialCleanup.manifest.Product == cleanupManifestProduct
	if !ownsResources {
		plan.Actions = []string{
			"no owned installation resources found; no changes",
		}
		if opts.Purge {
			plan.Actions = append(
				plan.Actions,
				fmt.Sprintf(
					"purge owned config dir %s: already absent; no-op",
					filepath.Dir(paths.ConfigPath),
				),
			)
		}
		plan.Actions = append(
			plan.Actions,
			fmt.Sprintf("keep binary %s", paths.BinaryPath),
			fmt.Sprintf(
				"binary removal hint: remove %s manually or with the package manager that installed it",
				paths.BinaryPath,
			),
		)
		return plan, nil
	}
	if !opts.Yes && wireGuardAppearsRunning(ctx, paths.ConfigPath) {
		return nil, errors.New("managed WireGuard runtime appears active; rerun uninstall with --yes to detach transform and continue")
	}
	if opts.DryRun {
		return plan, nil
	}
	if err := initialCleanup.close(); err != nil {
		return nil, fmt.Errorf("close initial uninstall preflight handles: %w", err)
	}
	initialCleanup = nil
	owner := lockfile.LifecycleOwner{
		PID:        os.Getpid(),
		Action:     "uninstall",
		ConfigPath: paths.ConfigPath,
		RunDir:     paths.RunDir,
	}
	maintenance, err := lockfile.BeginLifecycleMaintenance(ctx, owner)
	if err != nil {
		return nil, err
	}
	defer func() {
		if maintenance != nil {
			retErr = errors.Join(retErr, maintenance.Close())
		}
	}()

	serviceStopPlan, err := prepareUninstallCleanup(
		paths,
		system,
		opts.Purge,
		lockfile.LifecycleLeasePath(ctx),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"repeat uninstall preflight after maintenance acquisition: %w",
			err,
		)
	}
	defer func() {
		if serviceStopPlan != nil {
			if err := serviceStopPlan.close(); err != nil {
				retErr = errors.Join(
					retErr,
					fmt.Errorf("close service-stop cleanup handles: %w", err),
				)
			}
		}
	}()
	if err := serviceStopPlan.revalidate(); err != nil {
		return nil, fmt.Errorf(
			"revalidate all uninstall targets before service stop: %w",
			err,
		)
	}
	switch system {
	case "systemd":
		_, _, unitExists, err := serviceStopPlan.serviceArtifactEntry("systemd-unit")
		if err != nil {
			return nil, err
		}
		if unitExists {
			if err := verifySystemdServiceFragment(ctx, paths); err != nil {
				return nil, err
			}
			if err := runCommand(ctx, "systemctl", "stop", "wg-mix-ebpf.service"); err != nil {
				return nil, err
			}
			if err := runCommand(ctx, "systemctl", "disable", "wg-mix-ebpf.service"); err != nil {
				return nil, err
			}
		}
	case "openwrt":
		if err := runOpenWrtServiceActions(
			ctx,
			serviceStopPlan,
			"stop",
			"disable",
		); err != nil {
			return nil, err
		}
	}
	if err := serviceStopPlan.close(); err != nil {
		return nil, fmt.Errorf("close service-stop cleanup handles: %w", err)
	}
	serviceStopPlan = nil

	lease, err := maintenance.WaitAcquireLifecycle(ctx, owner)
	if err != nil {
		return nil, fmt.Errorf(
			"wait for daemon lifecycle handoff after verified service stop: %w",
			err,
		)
	}
	defer func() {
		if lease != nil {
			retErr = errors.Join(retErr, lease.Close())
		}
	}()

	if err := func() (retErr error) {
		preStopPlan, err := prepareUninstallCleanup(
			paths,
			system,
			opts.Purge,
			lockfile.LifecycleLeasePath(ctx),
		)
		if err != nil {
			return fmt.Errorf("repeat uninstall preflight after service stop: %w", err)
		}
		defer func() {
			if preStopPlan != nil {
				if err := preStopPlan.close(); err != nil {
					retErr = errors.Join(retErr, fmt.Errorf("close pre-stop cleanup handles: %w", err))
				}
			}
		}()

		stopped := false
		if shouldStopForUninstall(paths) {
			if err := preStopPlan.revalidate(); err != nil {
				return fmt.Errorf("revalidate all uninstall targets before detach: %w", err)
			}
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
		if err := preStopPlan.close(); err != nil {
			return fmt.Errorf("close pre-stop cleanup handles: %w", err)
		}
		preStopPlan = nil

		cleanupPlan, err := prepareUninstallCleanup(
			paths,
			system,
			opts.Purge,
			lockfile.LifecycleLeasePath(ctx),
		)
		if err != nil {
			return fmt.Errorf("final uninstall preflight after detach: %w", err)
		}
		defer func() {
			if cleanupPlan != nil {
				if err := cleanupPlan.close(); err != nil {
					retErr = errors.Join(retErr, fmt.Errorf("close final cleanup handles: %w", err))
				}
			}
		}()

		if !stopped {
			if err := cleanupPlan.revalidate(); err != nil {
				return fmt.Errorf("revalidate all uninstall targets before guard cleanup: %w", err)
			}
			if err := guard.NewCommandExecutor(paths.VarLibDir).Cleanup(ctx); err != nil {
				return fmt.Errorf("cleanup startup guard: %w", err)
			}
		}
		if err := cleanupPlan.executeServiceArtifacts(); err != nil {
			return fmt.Errorf("remove descriptor-anchored service artifacts: %w", err)
		}
		if err := cleanupPlan.close(); err != nil {
			return fmt.Errorf("close service-artifact cleanup handles: %w", err)
		}
		cleanupPlan = nil
		if system == "systemd" {
			if err := runCommand(ctx, "systemctl", "daemon-reload"); err != nil {
				return err
			}
		}

		cleanupPlan, err = prepareUninstallCleanup(
			paths,
			system,
			opts.Purge,
			lockfile.LifecycleLeasePath(ctx),
		)
		if err != nil {
			return fmt.Errorf("repeat uninstall preflight after service reload: %w", err)
		}
		// The global lifecycle lease serializes every mutating entrypoint. Do
		// not acquire the per-run lock here: WithLock creates a lock file, which
		// would mutate the fully preflighted target set before revalidation.
		if err := cleanupPlan.execute(); err != nil {
			return fmt.Errorf("execute descriptor-anchored uninstall cleanup: %w", err)
		}
		return nil
	}(); err != nil {
		return nil, err
	}
	return plan, nil
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

func validateInstallOwnershipPaths(paths paths) error {
	if err := validateCleanupPaths(paths); err != nil {
		return err
	}
	if err := validateInstallBinaryPath(paths.BinaryPath); err != nil {
		return err
	}
	if paths.ConfigPath == "" || !filepath.IsAbs(paths.ConfigPath) ||
		filepath.Clean(paths.ConfigPath) != paths.ConfigPath {
		return fmt.Errorf("refuse unsafe install config path %q", paths.ConfigPath)
	}
	if _, err := managedCleanupAnchor(configCleanupPath(filepath.Dir(paths.ConfigPath))); err != nil {
		return err
	}
	for _, spec := range []cleanupPathSpec{
		configCleanupPath(filepath.Dir(paths.ConfigPath)),
		runtimeCleanupPath(paths.RunDir),
		stateCleanupPath(paths.VarLibDir),
		bpfPinCleanupPath(paths.PinPath),
	} {
		dir, exists, err := openManagedCleanupDir(spec)
		if err != nil {
			return fmt.Errorf("validate existing install ownership path: %w", err)
		}
		if exists {
			if err := dir.close(); err != nil {
				return fmt.Errorf("close validated install ownership path: %w", err)
			}
		}
	}
	return nil
}

func validatePurgeDir(paths paths) error {
	if paths.ConfigPath == "" || filepath.Clean(paths.ConfigPath) != paths.ConfigPath {
		return fmt.Errorf("refuse to purge config with non-clean path %q", paths.ConfigPath)
	}
	configDir := filepath.Dir(paths.ConfigPath)
	ownedDir := envOr(EnvEtcDir, "/etc/wg-mix-ebpf")
	if filepath.Clean(ownedDir) != ownedDir {
		return fmt.Errorf("refuse to purge non-clean owned config directory %q", ownedDir)
	}
	if configDir != ownedDir {
		return fmt.Errorf("refuse to purge non-owned config directory %s; only %s is managed by uninstall --purge", configDir, ownedDir)
	}
	if err := validateManagedCleanupPath(configCleanupPath(configDir)); err != nil {
		return err
	}
	return nil
}

func validateCleanupPaths(paths paths) error {
	if err := validateServiceTemplatePath("config path", paths.ConfigPath); err != nil {
		return err
	}
	cleanup := []cleanupPathSpec{
		runtimeCleanupPath(paths.RunDir),
		stateCleanupPath(paths.VarLibDir),
		bpfPinCleanupPath(paths.PinPath),
	}
	configDir := filepath.Clean(filepath.Dir(paths.ConfigPath))
	for _, candidate := range cleanup {
		if err := validateManagedCleanupPath(candidate); err != nil {
			return err
		}
		if pathContains(candidate.path, configDir) {
			return fmt.Errorf("refuse %s %s because it contains config directory %s", candidate.name, candidate.path, configDir)
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

func validateServiceTemplatePath(name string, path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("refuse unsafe %s %q: path must be absolute and clean", name, path)
	}
	if !utf8.ValidString(path) {
		return fmt.Errorf("refuse unsafe %s %q: path is not valid UTF-8", name, path)
	}
	for _, character := range path {
		if unicode.IsControl(character) {
			return fmt.Errorf(
				"refuse unsafe %s %q: path contains a control character",
				name,
				path,
			)
		}
	}
	if strings.ContainsAny(path, "%$") {
		return fmt.Errorf(
			"refuse unsafe %s %q: path contains a service-template expansion character",
			name,
			path,
		)
	}
	return nil
}

const (
	managedCleanupBase      = "wg-mix-ebpf"
	maxCleanupPathSuffixLen = 64
)

type cleanupPathSpec struct {
	name        string
	path        string
	defaultPath string
	systemRoot  string
}

func runtimeCleanupPath(path string) cleanupPathSpec {
	return cleanupPathSpec{name: "runtime dir", path: path, defaultPath: daemon.DefaultRunDir, systemRoot: "/run"}
}

func stateCleanupPath(path string) cleanupPathSpec {
	return cleanupPathSpec{name: "state dir", path: path, defaultPath: attachstate.DefaultStateDir, systemRoot: "/var/lib"}
}

func bpfPinCleanupPath(path string) cleanupPathSpec {
	return cleanupPathSpec{name: "BPF pin path", path: path, defaultPath: dataplane.DefaultPinPath, systemRoot: "/sys/fs/bpf"}
}

func configCleanupPath(path string) cleanupPathSpec {
	return cleanupPathSpec{name: "config dir", path: path, defaultPath: "/etc/wg-mix-ebpf", systemRoot: "/etc"}
}

func validateManagedCleanupPath(spec cleanupPathSpec) error {
	_, err := managedCleanupAnchor(spec)
	return err
}

func validManagedCleanupBase(base string) bool {
	if base == managedCleanupBase {
		return true
	}
	prefix := managedCleanupBase + "-"
	if !strings.HasPrefix(base, prefix) {
		return false
	}
	suffix := strings.TrimPrefix(base, prefix)
	if len(suffix) == 0 || len(suffix) > maxCleanupPathSuffixLen {
		return false
	}
	for index := range len(suffix) {
		character := suffix[index]
		alphaNumeric := character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9'
		if alphaNumeric {
			continue
		}
		if character != '-' || index == 0 || index == len(suffix)-1 {
			return false
		}
	}
	return true
}

func validRuntimeQueueFile(name string) bool {
	if !strings.HasSuffix(name, ".json") {
		return false
	}
	id := strings.TrimSuffix(name, ".json")
	if len(id) != 32 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
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

func verifySystemdServiceFragment(ctx context.Context, paths paths) error {
	expected := filepath.Join(paths.SystemdDir, "wg-mix-ebpf.service")
	if !filepath.IsAbs(expected) || filepath.Clean(expected) != expected {
		return fmt.Errorf(
			"refuse systemd service verification for non-clean unit path %q",
			expected,
		)
	}
	args := []string{
		"show",
		"--property=FragmentPath",
		"--value",
		"wg-mix-ebpf.service",
	}
	cmd := exec.CommandContext(ctx, "systemctl", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf(
			"systemctl %s failed while verifying owned service: %w: %s",
			strings.Join(args, " "),
			err,
			string(out),
		)
	}
	actual := strings.TrimSpace(string(out))
	if actual != expected {
		return fmt.Errorf(
			"refuse to stop systemd service: FragmentPath %q does not match owned unit %q",
			actual,
			expected,
		)
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
`,
		systemdExecArgument(binaryPath),
		systemdExecArgument(configPath),
		systemdExecArgument(binaryPath),
		systemdExecArgument(configPath),
		systemdExecArgument(binaryPath),
		systemdExecArgument(configPath),
	)
}

func openWrtInit(configPath string, binaryPath string) string {
	return fmt.Sprintf(`#!/bin/sh /etc/rc.common

USE_PROCD=1
START=99
STOP=10

CONF=%s

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
`,
		shellSingleQuote(configPath),
		shellSingleQuote(binaryPath),
		shellSingleQuote(binaryPath),
		shellSingleQuote(binaryPath),
	)
}

func systemdExecArgument(value string) string {
	replacer := strings.NewReplacer(
		`\`, `\\`,
		`"`, `\"`,
		`%`, `%%`,
		`$`, `$$`,
	)
	return `"` + replacer.Replace(value) + `"`
}

func shellSingleQuote(value string) string {
	return `'` + strings.ReplaceAll(value, `'`, `'"'"'`) + `'`
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
