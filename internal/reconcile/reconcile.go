package reconcile

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/attachstate"
	"github.com/syx0310/wg-mix-ebpf/internal/config"
	"github.com/syx0310/wg-mix-ebpf/internal/control"
	"github.com/syx0310/wg-mix-ebpf/internal/dataplane"
	"github.com/syx0310/wg-mix-ebpf/internal/guard"
	"github.com/syx0310/wg-mix-ebpf/internal/lockfile"
	"github.com/syx0310/wg-mix-ebpf/internal/runtime"
	"github.com/syx0310/wg-mix-ebpf/internal/underlay"
	"github.com/syx0310/wg-mix-ebpf/internal/wgconfig"
)

type Options struct {
	ConfigPath     string
	RunDir         string
	StateDir       string
	Offline        bool
	DryRun         bool
	LifecycleLease *lockfile.LifecycleLease

	deps *dependencies
}

type dependencies struct {
	loadConfigFile   func(string) (*config.Config, error)
	loadWGConfig     control.WGConfigLoader
	runtimeProvider  runtime.Provider
	underlayResolver underlay.Resolver
	guardExecutor    guard.Executor
	dataplaneLoader  dataplane.Loader
}

type Result struct {
	ConfigPath      string                  `json:"config_path"`
	Time            time.Time               `json:"time"`
	Action          string                  `json:"action"`
	State           *control.State          `json:"state,omitempty"`
	Dataplane       *dataplane.KernelStatus `json:"dataplane,omitempty"`
	DataplaneError  string                  `json:"dataplane_error,omitempty"`
	AttachStatePath string                  `json:"attach_state_path,omitempty"`
	GuardApplied    bool                    `json:"guard_applied,omitempty"`
	GuardCleaned    bool                    `json:"guard_cleaned,omitempty"`
	GuardScript     string                  `json:"guard_script,omitempty"`
	GuardCleanup    string                  `json:"guard_cleanup,omitempty"`
	DryRun          bool                    `json:"dry_run,omitempty"`
	OneShotFallback bool                    `json:"one_shot_fallback,omitempty"`
}

func BuildState(ctx context.Context, opts Options) (*config.Config, *control.State, error) {
	cfg, err := loadConfig(opts)
	if err != nil {
		return nil, nil, err
	}
	state, err := buildStateFromConfig(ctx, cfg, opts)
	if err != nil {
		return nil, nil, err
	}
	return cfg, state, nil
}

func BuildGuardState(ctx context.Context, opts Options) (*config.Config, *control.State, error) {
	cfg, err := loadConfig(opts)
	if err != nil {
		return nil, nil, err
	}
	state, err := buildGuardStateFromConfig(ctx, cfg, opts, configuredWGConfigLoader(opts))
	if err != nil {
		return nil, nil, err
	}
	return cfg, state, nil
}

func loadConfig(opts Options) (*config.Config, error) {
	path := opts.ConfigPath
	if path == "" {
		path = config.DefaultConfigPath
	}
	loader := config.LoadFile
	if opts.deps != nil && opts.deps.loadConfigFile != nil {
		loader = opts.deps.loadConfigFile
	}
	cfg, err := loader(path)
	if err != nil {
		return nil, fmt.Errorf("load config %s: %w", path, err)
	}
	return cfg, nil
}

func buildStateFromConfig(ctx context.Context, cfg *config.Config, opts Options) (*control.State, error) {
	return buildStateFromConfigWithLoader(ctx, cfg, opts, configuredWGConfigLoader(opts), opts.Offline)
}

func buildGuardStateFromConfig(ctx context.Context, cfg *config.Config, opts Options, loadWG control.WGConfigLoader) (*control.State, error) {
	return buildStateFromConfigWithLoader(ctx, cfg, opts, loadWG, true)
}

func buildStateFromConfigWithLoader(ctx context.Context, cfg *config.Config, opts Options, loadWG control.WGConfigLoader, offline bool) (*control.State, error) {
	return buildStateFromConfigWithSources(
		ctx,
		cfg,
		loadWG,
		configuredRuntimeProvider(opts),
		configuredUnderlayResolver(opts),
		offline,
	)
}

func buildStateFromConfigWithSources(
	ctx context.Context,
	cfg *config.Config,
	loadWG control.WGConfigLoader,
	runtimeProvider runtime.Provider,
	underlayResolver underlay.Resolver,
	offline bool,
) (*control.State, error) {
	state, err := control.BuildState(
		ctx,
		cfg,
		runtimeProvider,
		underlayResolver,
		loadWG,
		control.BuildOptions{Offline: offline},
	)
	if err != nil {
		if control.IsUnsupportedRuntime(err) && !offline {
			return nil, fmt.Errorf("%w (use --offline for static validation on this platform)", err)
		}
		return nil, err
	}
	return state, nil
}

func configuredWGConfigLoader(opts Options) control.WGConfigLoader {
	if opts.deps != nil && opts.deps.loadWGConfig != nil {
		return opts.deps.loadWGConfig
	}
	return wgconfig.ParseFile
}

func configuredRuntimeProvider(opts Options) runtime.Provider {
	if opts.deps != nil && opts.deps.runtimeProvider != nil {
		return opts.deps.runtimeProvider
	}
	return runtime.NewSystemProvider()
}

func configuredUnderlayResolver(opts Options) underlay.Resolver {
	if opts.deps != nil && opts.deps.underlayResolver != nil {
		return opts.deps.underlayResolver
	}
	return underlay.NewSystemResolver()
}

func configuredGuardExecutor(opts Options) guard.Executor {
	if opts.deps != nil && opts.deps.guardExecutor != nil {
		return opts.deps.guardExecutor
	}
	return guard.NewCommandExecutor()
}

func configuredDataplaneLoader(opts Options) dataplane.Loader {
	if opts.deps != nil && opts.deps.dataplaneLoader != nil {
		return opts.deps.dataplaneLoader
	}
	return dataplane.NewLoader()
}

type wgConfigSnapshotEntry struct {
	value *wgconfig.Interface
	err   error
}

// snapshotWGConfigLoader keeps guard construction and runtime state
// construction on the same immutable view of every WireGuard config file.
func snapshotWGConfigLoader(load control.WGConfigLoader) control.WGConfigLoader {
	var mu sync.Mutex
	cache := make(map[string]wgConfigSnapshotEntry)
	return func(path string) (*wgconfig.Interface, error) {
		mu.Lock()
		defer mu.Unlock()
		if cached, ok := cache[path]; ok {
			return cloneWGConfig(cached.value), cached.err
		}
		value, err := load(path)
		cache[path] = wgConfigSnapshotEntry{value: cloneWGConfig(value), err: err}
		return cloneWGConfig(value), err
	}
}

func cloneWGConfig(value *wgconfig.Interface) *wgconfig.Interface {
	if value == nil {
		return nil
	}
	out := *value
	if value.FwMark != nil {
		mark := *value.FwMark
		out.FwMark = &mark
	}
	if value.ListenPort != nil {
		port := *value.ListenPort
		out.ListenPort = &port
	}
	return &out
}

type runtimeSnapshotEntry struct {
	value *runtime.Device
	err   error
}

type runtimeSnapshotProvider struct {
	mu       sync.Mutex
	upstream runtime.Provider
	cache    map[string]runtimeSnapshotEntry
}

func snapshotRuntimeProvider(upstream runtime.Provider) runtime.Provider {
	return &runtimeSnapshotProvider{
		upstream: upstream,
		cache:    make(map[string]runtimeSnapshotEntry),
	}
}

func (p *runtimeSnapshotProvider) Device(ctx context.Context, name string) (*runtime.Device, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if cached, ok := p.cache[name]; ok {
		return cloneRuntimeDevice(cached.value), cached.err
	}
	value, err := p.upstream.Device(ctx, name)
	p.cache[name] = runtimeSnapshotEntry{value: cloneRuntimeDevice(value), err: err}
	return cloneRuntimeDevice(value), err
}

func cloneRuntimeDevice(value *runtime.Device) *runtime.Device {
	if value == nil {
		return nil
	}
	out := *value
	out.Peers = append([]runtime.Peer(nil), value.Peers...)
	return &out
}

func observedRuntimeFwmarks(ctx context.Context, cfg *config.Config, provider runtime.Provider) []uint32 {
	var marks []uint32
	for _, wg := range cfg.WireGuards {
		if ctx.Err() != nil {
			break
		}
		device, err := provider.Device(ctx, wg.Name)
		if err == nil && device.FirewallMark != 0 {
			marks = append(marks, device.FirewallMark)
		}
	}
	return marks
}

func Validate(ctx context.Context, opts Options) (*Result, error) {
	_, state, err := BuildState(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &Result{ConfigPath: configPath(opts), Time: time.Now(), Action: "validate", State: state, DryRun: opts.DryRun}, nil
}

func Status(ctx context.Context, opts Options) (*Result, error) {
	_, state, err := BuildState(ctx, opts)
	if err != nil {
		return nil, err
	}
	result := &Result{ConfigPath: configPath(opts), Time: time.Now(), Action: "status", State: state}
	if kernelStatus, err := dataplane.Inspect(ctx, state); err == nil {
		result.Dataplane = kernelStatus
	} else if !errors.Is(err, dataplane.ErrUnsupported) {
		result.DataplaneError = err.Error()
	}
	return result, nil
}

func Reload(ctx context.Context, opts Options) (*Result, error) {
	if opts.Offline && !opts.DryRun {
		return nil, errors.New("offline reload requires --dry-run; refusing to apply an empty runtime-derived dataplane")
	}
	if opts.DryRun {
		return reloadUnlocked(ctx, opts)
	}
	var result *Result
	err := withMutationOwnership(ctx, opts, "reload", func() error {
		var err error
		result, err = reloadUnlocked(ctx, opts)
		return err
	})
	return result, err
}

func reloadUnlocked(ctx context.Context, opts Options) (*Result, error) {
	cfg, err := loadConfig(opts)
	if err != nil {
		return nil, err
	}
	loadWG := snapshotWGConfigLoader(configuredWGConfigLoader(opts))
	guardState, err := buildGuardStateFromConfig(ctx, cfg, opts, loadWG)
	if err != nil {
		return nil, err
	}
	guardExecutor := configuredGuardExecutor(opts)
	initialGuardPlan := guard.BuildNftPlan(guardState)
	activeGuardPlan := initialGuardPlan
	guardApplied := false
	if !opts.DryRun && shouldApplyStartupGuard(cfg) {
		if err := guardExecutor.Apply(ctx, initialGuardPlan); err != nil {
			return nil, fmt.Errorf("apply startup guard: %w", err)
		}
		guardApplied = true
	}

	runtimeProvider := configuredRuntimeProvider(opts)
	if !opts.Offline {
		runtimeProvider = snapshotRuntimeProvider(runtimeProvider)
	}
	if guardApplied && !opts.Offline {
		observedMarks := observedRuntimeFwmarks(ctx, cfg, runtimeProvider)
		expandedPlan := guard.BuildNftPlan(guardState, observedMarks...)
		if !sameNftPlan(activeGuardPlan, expandedPlan) {
			if err := guardExecutor.Apply(ctx, expandedPlan); err != nil {
				return nil, fmt.Errorf("expand startup guard for observed runtime fwmarks: %w", err)
			}
			activeGuardPlan = expandedPlan
		}
	}

	state, err := buildStateFromConfigWithSources(
		ctx,
		cfg,
		loadWG,
		runtimeProvider,
		configuredUnderlayResolver(opts),
		opts.Offline,
	)
	if err != nil {
		return nil, err
	}
	result := &Result{ConfigPath: configPath(opts), Time: time.Now(), Action: "reload", State: state, DryRun: opts.DryRun, AttachStatePath: attachstate.Path(opts.StateDir)}
	if opts.DryRun {
		if shouldApplyStartupGuard(cfg) {
			result.GuardScript = guard.BuildNftPlan(state).Script()
		}
		return result, nil
	}
	result.GuardApplied = guardApplied
	if guardApplied {
		runtimeGuardPlan := guard.BuildNftPlan(state)
		if !sameNftPlan(activeGuardPlan, runtimeGuardPlan) {
			if err := guardExecutor.Apply(ctx, runtimeGuardPlan); err != nil {
				return nil, fmt.Errorf("expand startup guard for runtime fwmarks: %w", err)
			}
		}
	}
	loader := configuredDataplaneLoader(opts)
	if err := loader.Apply(ctx, state); err != nil {
		return nil, err
	}
	if previous, err := attachstate.Load(opts.StateDir); err == nil {
		if staleLoader, ok := loader.(dataplane.AttachStateLoader); ok {
			if err := staleLoader.DetachStale(ctx, attachstate.ToControlState(previous), state); err != nil {
				return nil, fmt.Errorf("detach stale underlays: %w", err)
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := attachstate.Save(opts.StateDir, attachstate.FromControlState(configPath(opts), state)); err != nil {
		return nil, err
	}
	if guardApplied {
		if err := guardExecutor.Cleanup(ctx); err != nil {
			return nil, fmt.Errorf("cleanup startup guard after reload: %w", err)
		}
		result.GuardCleaned = true
	}
	return result, nil
}

func sameNftPlan(left, right guard.NftPlan) bool {
	if left.Table != right.Table || len(left.Rules) != len(right.Rules) {
		return false
	}
	for i := range left.Rules {
		if left.Rules[i] != right.Rules[i] {
			return false
		}
	}
	return true
}

func Detach(ctx context.Context, opts Options) (*Result, error) {
	if opts.DryRun {
		return detachUnlocked(ctx, opts)
	}
	var result *Result
	err := withMutationOwnership(ctx, opts, "detach", func() error {
		var err error
		result, err = detachUnlocked(ctx, opts)
		return err
	})
	return result, err
}

func detachUnlocked(ctx context.Context, opts Options) (*Result, error) {
	state, stateErr := detachState(ctx, opts)
	if stateErr != nil {
		if opts.DryRun && errors.Is(stateErr, errNoDetachUnderlays) {
			state = &control.State{}
		} else {
			return nil, stateErr
		}
	}
	result := &Result{ConfigPath: configPath(opts), Time: time.Now(), Action: "detach", State: state, DryRun: opts.DryRun, AttachStatePath: attachstate.Path(opts.StateDir)}
	if opts.DryRun {
		return result, nil
	}
	if err := configuredDataplaneLoader(opts).Detach(ctx, state); err != nil {
		return nil, err
	}
	if err := attachstate.Remove(opts.StateDir); err != nil {
		return nil, err
	}
	return result, nil
}

func Stop(ctx context.Context, opts Options) (*Result, error) {
	if opts.DryRun {
		return stopUnlocked(ctx, opts)
	}
	var result *Result
	err := withMutationOwnership(ctx, opts, "stop", func() error {
		var err error
		result, err = stopUnlocked(ctx, opts)
		return err
	})
	return result, err
}

func stopUnlocked(ctx context.Context, opts Options) (*Result, error) {
	result, err := detachUnlocked(ctx, opts)
	if err != nil && !errors.Is(err, errNoDetachUnderlays) {
		return nil, err
	}
	if result == nil {
		result = &Result{ConfigPath: configPath(opts), Time: time.Now(), State: &control.State{}, DryRun: opts.DryRun, AttachStatePath: attachstate.Path(opts.StateDir)}
	}
	result.Action = "stop"
	if opts.DryRun {
		result.GuardCleanup = guard.CleanupScript()
		return result, nil
	}
	if err := cleanupGuardForStop(ctx, opts); err != nil {
		return nil, fmt.Errorf("cleanup startup guard during stop: %w", err)
	}
	result.GuardCleaned = true
	return result, nil
}

func cleanupGuardForStop(ctx context.Context, opts Options) error {
	// The guard table name is fixed and may have been left by an earlier config
	// generation. The current config mode therefore cannot prove it is absent.
	return configuredGuardExecutor(opts).Cleanup(ctx)
}

func detachState(ctx context.Context, opts Options) (*control.State, error) {
	var states []*control.State
	if saved, err := attachstate.Load(opts.StateDir); err == nil {
		states = append(states, attachstate.ToControlState(saved))
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	cfg, configErr := loadConfig(opts)
	if configErr == nil {
		loadWG := snapshotWGConfigLoader(configuredWGConfigLoader(opts))
		current, runtimeErr := buildStateFromConfigWithLoader(ctx, cfg, opts, loadWG, opts.Offline)
		if runtimeErr == nil {
			states = append(states, current)
		} else if len(states) == 0 {
			offline, offlineErr := buildGuardStateFromConfig(ctx, cfg, opts, loadWG)
			if offlineErr != nil {
				return nil, fmt.Errorf("build detach state failed: runtime=%v offline=%v", runtimeErr, offlineErr)
			}
			states = append(states, offline)
		}
	} else if len(states) == 0 {
		return nil, fmt.Errorf("build detach state failed: runtime=%v offline=%v", configErr, configErr)
	}
	merged := attachstate.MergeControlStates(states...)
	if len(merged.Underlays) == 0 {
		return nil, errNoDetachUnderlays
	}
	return merged, nil
}

var errNoDetachUnderlays = errors.New("no underlays available for detach")

func GuardPlan(ctx context.Context, opts Options) (*Result, error) {
	_, state, err := BuildGuardState(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &Result{
		ConfigPath:  configPath(opts),
		Time:        time.Now(),
		Action:      "guard-plan",
		State:       state,
		GuardScript: guard.BuildNftPlan(state).Script(),
		DryRun:      true,
	}, nil
}

func GuardApply(ctx context.Context, opts Options) (*Result, error) {
	_, state, err := BuildGuardState(ctx, opts)
	if err != nil {
		return nil, err
	}
	plan := guard.BuildNftPlan(state)
	result := &Result{ConfigPath: configPath(opts), Time: time.Now(), Action: "guard-apply", State: state, GuardScript: plan.Script(), DryRun: opts.DryRun}
	if opts.DryRun {
		return result, nil
	}
	if err := withMutationOwnership(ctx, opts, "guard-apply", func() error {
		return configuredGuardExecutor(opts).Apply(ctx, plan)
	}); err != nil {
		return nil, err
	}
	result.GuardApplied = true
	return result, nil
}

func GuardCleanup(ctx context.Context, opts Options) (*Result, error) {
	result := &Result{ConfigPath: configPath(opts), Time: time.Now(), Action: "guard-cleanup", GuardCleanup: guard.CleanupScript(), DryRun: opts.DryRun}
	if opts.DryRun {
		return result, nil
	}
	if err := withMutationOwnership(ctx, opts, "guard-cleanup", func() error {
		return configuredGuardExecutor(opts).Cleanup(ctx)
	}); err != nil {
		return nil, err
	}
	result.GuardCleaned = true
	return result, nil
}

func shouldApplyStartupGuard(cfg *config.Config) bool {
	return cfg.StartupGuard.Mode == "nft-temporary-drop" &&
		cfg.Policy.StartupFailMode == "fail_closed_for_managed_flows"
}

func configPath(opts Options) string {
	if opts.ConfigPath != "" {
		return opts.ConfigPath
	}
	return config.DefaultConfigPath
}

func withMutationOwnership(ctx context.Context, opts Options, action string, fn func() error) error {
	owner := lockfile.LifecycleOwner{
		PID:        os.Getpid(),
		Action:     action,
		ConfigPath: configPath(opts),
		RunDir:     opts.RunDir,
	}
	return lockfile.WithLifecycle(ctx, opts.LifecycleLease, owner, func(*lockfile.LifecycleLease) error {
		if opts.RunDir == "" {
			return fn()
		}
		return lockfile.WithLock(ctx, opts.RunDir, fn)
	})
}
