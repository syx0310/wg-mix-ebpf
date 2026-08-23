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
	"github.com/syx0310/wg-mix-ebpf/internal/diagnostic"
	"github.com/syx0310/wg-mix-ebpf/internal/guard"
	"github.com/syx0310/wg-mix-ebpf/internal/lockfile"
	"github.com/syx0310/wg-mix-ebpf/internal/runtime"
	"github.com/syx0310/wg-mix-ebpf/internal/underlay"
	"github.com/syx0310/wg-mix-ebpf/internal/wgconfig"
)

type Options struct {
	ConfigPath      string
	RunDir          string
	StateDir        string
	Offline         bool
	DryRun          bool
	AdoptLegacyPins bool
	LifecycleLease  *lockfile.LifecycleLease
	// ResidentRuntime is set only by the non-once daemon. It is forwarded to
	// the dataplane so process-owned FakeTCP links cannot be installed by a
	// command that exits immediately after reload.
	ResidentRuntime bool
	// Progress receives immutable, non-secret live observations while a reload
	// is in flight. The daemon uses it to publish runtime pause and guard
	// transitions before the operation has completed.
	Progress ProgressFunc

	deps *dependencies
}

type dependencies struct {
	loadConfigFile          func(string) (*config.Config, error)
	loadConfigFileLenient   func(string) (*config.Config, error)
	loadWGConfig            control.WGConfigLoader
	runtimeProvider         runtime.Provider
	underlayResolver        underlay.Resolver
	guardExecutor           guard.Executor
	noNFTGuardPreflight     func(context.Context, string) error
	dataplaneLoader         dataplane.Loader
	newDataplaneLoader      func(dataplane.LoaderOptions) dataplane.Loader
	productionFakeTCPStatus func(context.Context, *control.State) (bool, *dataplane.KernelStatus, error)
}

type Result struct {
	ConfigPath      string                  `json:"config_path"`
	Time            time.Time               `json:"time"`
	Action          string                  `json:"action"`
	State           *control.State          `json:"state,omitempty"`
	Dataplane       *dataplane.KernelStatus `json:"dataplane,omitempty"`
	DataplaneError  string                  `json:"dataplane_error,omitempty"`
	StateError      string                  `json:"state_error,omitempty"`
	Observation     *Observation            `json:"observation,omitempty"`
	AttachStatePath string                  `json:"attach_state_path,omitempty"`
	GuardApplied    bool                    `json:"guard_applied,omitempty"`
	GuardCleaned    bool                    `json:"guard_cleaned,omitempty"`
	GuardWarning    string                  `json:"guard_warning,omitempty"`
	GuardScript     string                  `json:"guard_script,omitempty"`
	GuardCleanup    string                  `json:"guard_cleanup,omitempty"`
	DryRun          bool                    `json:"dry_run,omitempty"`
	OneShotFallback bool                    `json:"one_shot_fallback,omitempty"`
	Timings         *ReloadTimings          `json:"timings,omitempty"`
}

// ReloadTimings records monotonic durations for the reload critical section.
// BarrierHeld covers quiesce-start through successful runtime resume, while
// GuardActive covers the interval after the first authoritative Active guard
// result through authoritative Absent cleanup. Apply and Cleanup measure the
// exact dataplane Apply and normal guard Cleanup calls. The structure contains
// durations only: it deliberately carries no wall-clock timestamps, paths, or
// configuration data.
type ReloadTimings struct {
	BarrierHeldNanoseconds int64 `json:"barrier_held_nanoseconds"`
	GuardActiveNanoseconds int64 `json:"guard_active_nanoseconds"`
	ApplyNanoseconds       int64 `json:"apply_nanoseconds"`
	CleanupNanoseconds     int64 `json:"cleanup_nanoseconds"`
	TotalNanoseconds       int64 `json:"total_nanoseconds"`
	Completed              bool  `json:"completed"`
}

func BuildState(ctx context.Context, opts Options) (*config.Config, *control.State, error) {
	cfg, err := loadConfig(opts)
	if err != nil {
		return nil, nil, err
	}
	state, err := buildStateFromConfig(ctx, cfg, opts)
	if err != nil {
		return cfg, nil, err
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
		return cfg, nil, err
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

func loadConfigLenient(opts Options) (*config.Config, error) {
	path := opts.ConfigPath
	if path == "" {
		path = config.DefaultConfigPath
	}
	loader := config.LoadFileLenient
	if opts.deps != nil && opts.deps.loadConfigFileLenient != nil {
		loader = opts.deps.loadConfigFileLenient
	}
	cfg, err := loader(path)
	if err != nil {
		return nil, fmt.Errorf("load config %s for status: %w", path, err)
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
	return guard.NewCommandExecutor(opts.StateDir)
}

func configuredGuardExecutorForMode(opts Options, mode string) guard.Executor {
	if mode == config.StartupGuardModeNone {
		return guard.NewDisabledExecutor()
	}
	if opts.deps != nil && opts.deps.guardExecutor != nil {
		return opts.deps.guardExecutor
	}
	return guard.NewCommandExecutor(opts.StateDir)
}

func configuredNoNFTGuardPreflight(opts Options) func(context.Context, string) error {
	if opts.deps != nil && opts.deps.noNFTGuardPreflight != nil {
		return opts.deps.noNFTGuardPreflight
	}
	return preflightNoNFTStartupGuard
}

func configuredDataplaneLoader(opts Options) dataplane.Loader {
	if opts.deps != nil && opts.deps.dataplaneLoader != nil {
		return opts.deps.dataplaneLoader
	}
	constructor := dataplane.NewLoaderWithOptions
	if opts.deps != nil && opts.deps.newDataplaneLoader != nil {
		constructor = opts.deps.newDataplaneLoader
	}
	return constructor(dataplane.LoaderOptions{
		AdoptLegacyPins: opts.AdoptLegacyPins,
		LifecycleLease:  opts.LifecycleLease,
		ResidentRuntime: opts.ResidentRuntime,
	})
}

func configuredProductionFakeTCPStatus(
	opts Options,
) func(context.Context, *control.State) (bool, *dataplane.KernelStatus, error) {
	if opts.deps != nil && opts.deps.productionFakeTCPStatus != nil {
		return opts.deps.productionFakeTCPStatus
	}
	return dataplane.ProductionFakeTCPStatus
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
	if ctx == nil {
		return nil, errors.New("status context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	now := time.Now()
	result := &Result{
		ConfigPath: configPath(opts), Time: now, Action: "status",
	}

	cfg, state, stateErr := BuildState(ctx, opts)
	statusConfig := cfg
	if stateErr != nil {
		result.StateError = stateErr.Error()
		if statusConfig == nil {
			if lenient, err := loadConfigLenient(opts); err == nil {
				statusConfig = lenient
			}
		}
	} else {
		result.State = state
	}
	guardStatus := observeStartupGuard(ctx, opts, statusConfig)
	loader := configuredDataplaneLoader(opts)
	guardStatus.RuntimePause = startupGuardPauseStatus(loader, guardStatus.ObservationTime)

	kernelStatus, dataplaneError := inspectCurrentDataplane(ctx, opts, state, loader)
	observation := &Observation{
		ObservationTime: time.Now(),
		Reconcile: ReconcileStatus{
			Phase: ReconcilePhaseIdle, Since: now, ObservationTime: time.Now(),
		},
		StartupGuard:   guardStatus,
		Dataplane:      kernelStatus,
		DataplaneError: dataplaneError,
	}
	result.Dataplane = kernelStatus
	result.DataplaneError = dataplaneError
	result.Observation = observation
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
	err := withMutationOwnership(ctx, opts, "reload", func(lease *lockfile.LifecycleLease) error {
		ownedOpts := opts
		ownedOpts.LifecycleLease = lease
		var err error
		result, err = reloadUnlocked(ctx, ownedOpts)
		return err
	})
	return result, err
}

// startupGuardTxn keeps immutable runtime-barrier ownership separate from
// guard postconditions. In particular, an Apply observation must never erase
// whether this reload acquired or borrowed the barrier. A fresh lease may use
// a pre-dataplane Absent proof; a borrowed lease additionally requires this
// retry's dataplane validation and normal cleanup to complete.
type startupGuardTxn struct {
	runtime dataplane.StartupGuardRuntime
	lease   dataplane.StartupGuardLease

	barrierFresh       bool
	initialObservation guard.Observation
	observation        guard.Observation
	guardCreated       bool

	dataplaneMutationStarted bool
	dataplaneValidated       bool
	cleanupAttempted         bool
	cleanupProvedAbsent      bool
	normalCleanup            bool
	resumed                  bool
}

func newStartupGuardTxn(status StartupGuardStatus) *startupGuardTxn {
	observation := guardObservationFromStatus(status)
	return &startupGuardTxn{
		initialObservation: observation,
		observation:        observation,
	}
}

func guardObservationFromStatus(status StartupGuardStatus) guard.Observation {
	switch status.KernelState {
	case StartupGuardKernelActive:
		return guard.ObservationActive
	case StartupGuardKernelAbsent:
		return guard.ObservationAbsent
	default:
		return guard.ObservationUnknown
	}
}

func (txn *startupGuardTxn) recordLease(
	runtime dataplane.StartupGuardRuntime,
	lease dataplane.StartupGuardLease,
) error {
	if runtime == nil {
		return errors.New("startup guard runtime is nil")
	}
	if lease.Token.IsZero() {
		return errors.New("startup guard runtime returned an empty lease token")
	}
	txn.runtime = runtime
	txn.lease = lease
	// Immutable transaction-origin fact. Guard observations below deliberately
	// cannot overwrite it.
	txn.barrierFresh = lease.Acquired
	return nil
}

func (txn *startupGuardTxn) recordApply(outcome guard.Outcome) {
	txn.observation = effectiveGuardObservation(txn.observation, outcome.Observation)
	if outcome.Observation == guard.ObservationActive &&
		outcome.Mutated &&
		txn.initialObservation == guard.ObservationAbsent {
		txn.guardCreated = true
	}
}

func effectiveGuardObservation(
	previous guard.Observation,
	next guard.Observation,
) guard.Observation {
	if next == guard.ObservationUnchanged {
		return previous
	}
	return next
}

func (txn *startupGuardTxn) apply(
	ctx context.Context,
	executor guard.Executor,
	plan guard.NftPlan,
) (guard.Outcome, error) {
	outcome, err := executor.Apply(ctx, plan)
	txn.recordApply(outcome)
	return outcome, err
}

func (txn *startupGuardTxn) recordCleanupOutcome(outcome guard.Outcome) {
	txn.cleanupAttempted = true
	txn.observation = effectiveGuardObservation(txn.observation, outcome.Observation)
	txn.cleanupProvedAbsent = outcome.Observation == guard.ObservationAbsent
}

func (txn *startupGuardTxn) recordRollbackCleanup(outcome guard.Outcome) {
	txn.recordCleanupOutcome(outcome)
}

func (txn *startupGuardTxn) recordNormalCleanup(outcome guard.Outcome) {
	txn.normalCleanup = true
	txn.recordCleanupOutcome(outcome)
}

func (txn *startupGuardTxn) shouldRollbackGuardOnFailure() bool {
	return !txn.dataplaneMutationStarted &&
		txn.guardCreated &&
		!txn.cleanupAttempted &&
		txn.observation == guard.ObservationActive
}

func (txn *startupGuardTxn) shouldResumeAfterFailure() bool {
	if txn.runtime == nil || txn.resumed {
		return false
	}
	if txn.dataplaneValidated && txn.normalCleanup && txn.cleanupProvedAbsent {
		return true
	}
	// A borrowed lease may represent a previous reload whose dataplane
	// mutation was never validated. No pre-dataplane failure or rollback in
	// this retry may start that retained runtime, even if it proves the nft
	// guard absent.
	if !txn.barrierFresh {
		return false
	}
	if txn.dataplaneMutationStarted {
		return false
	}
	if txn.observation == guard.ObservationAbsent {
		// Only a barrier acquired by this transaction can be restored from a
		// pre-dataplane Absent proof.
		return true
	}
	return false
}

func (txn *startupGuardTxn) resume(ctx context.Context) error {
	if err := txn.runtime.ResumeAfterStartupGuard(ctx, txn.lease); err != nil {
		return err
	}
	txn.resumed = true
	return nil
}

func reloadUnlocked(ctx context.Context, opts Options) (result *Result, retErr error) {
	reloadStarted := time.Now()
	timings := &ReloadTimings{}
	var barrierHeldStarted time.Time
	var guardActiveStarted time.Time
	defer func() {
		if result == nil {
			return
		}
		timings.TotalNanoseconds = time.Since(reloadStarted).Nanoseconds()
		timings.Completed = retErr == nil
		result.Timings = timings
	}()
	cfg, err := loadConfig(opts)
	if err != nil {
		return nil, err
	}
	loadWG := snapshotWGConfigLoader(configuredWGConfigLoader(opts))
	loader := configuredDataplaneLoader(opts)
	guardExecutor := configuredGuardExecutorForMode(opts, cfg.StartupGuard.Mode)
	guardStatus := unobservedStartupGuard(cfg)
	if !opts.DryRun && cfg.StartupGuard.Mode != config.StartupGuardModeNone {
		guardStatus = observeStartupGuard(ctx, opts, cfg)
	}
	phaseSince := time.Now()
	guardTxn := newStartupGuardTxn(guardStatus)
	if !opts.DryRun {
		publishProgress(
			ctx, opts, ReconcilePhasePreparing, phaseSince,
			nil, guardStatus, loader, nil,
		)
		defer func() {
			if retErr == nil {
				return
			}
			if guardTxn.shouldRollbackGuardOnFailure() {
				cleanupCtx, cancel := startupGuardFinalizationContext(ctx)
				outcome, cleanupErr := guardExecutor.Cleanup(cleanupCtx)
				cancel()
				guardStatus = projectGuardOutcome(
					cfg.StartupGuard.Mode, guardStatus, outcome, cleanupErr,
				)
				guardTxn.recordRollbackCleanup(outcome)
				if cleanupErr != nil {
					retErr = errors.Join(
						retErr,
						fmt.Errorf("rollback startup guard after failed reload: %w", cleanupErr),
					)
				} else if !guardTxn.cleanupProvedAbsent {
					retErr = errors.Join(
						retErr,
						fmt.Errorf(
							"rollback startup guard after failed reload returned kernel state %q, want %q",
							guardStatus.KernelState,
							StartupGuardKernelAbsent,
						),
					)
				}
			}
			if guardTxn.shouldResumeAfterFailure() {
				recoveryCtx, cancel := startupGuardFinalizationContext(ctx)
				resumeErr := guardTxn.resume(recoveryCtx)
				cancel()
				if resumeErr == nil && !barrierHeldStarted.IsZero() {
					timings.BarrierHeldNanoseconds = time.Since(barrierHeldStarted).Nanoseconds()
				}
				if resumeErr != nil {
					retErr = errors.Join(
						retErr,
						fmt.Errorf("resume resident dataplane after failed startup guard transaction: %w", resumeErr),
					)
				}
			}
			observationCtx, cancel := startupGuardFinalizationContext(ctx)
			observation := publishProgress(
				observationCtx, opts, ReconcilePhaseFailed, time.Now(),
				nil, guardStatus, loader, retErr,
			)
			cancel()
			if result != nil {
				result.Observation = cloneObservation(observation)
			}
		}()
		if cfg.StartupGuard.Mode == config.StartupGuardModeNone {
			if err := configuredNoNFTGuardPreflight(opts)(ctx, opts.StateDir); err != nil {
				guardStatus.Error = joinStatusText(guardStatus.Error, err.Error())
				guardStatus.ObservationTime = time.Now()
				return nil, fmt.Errorf("preflight disabled startup guard: %w", err)
			}
		}
	}
	guardState, err := buildGuardStateFromConfig(ctx, cfg, opts, loadWG)
	if err != nil {
		return nil, err
	}
	if err := validateFakeTCPStartupIsolation(cfg, guardState); err != nil {
		return nil, err
	}
	// FakeTCP activation is gated here, after configuration/state loading but
	// before even the temporary nft startup guard can mutate the host. Keep the
	// loader gate as defence in depth, but do not rely on reaching it.
	if err := dataplane.ValidateFakeTCPActivation(guardState); err != nil {
		return nil, err
	}
	if !opts.DryRun {
		if err := dataplane.ValidateFakeTCPResidentRuntime(
			guardState,
			opts.ResidentRuntime,
		); err != nil {
			return nil, err
		}
	}
	initialGuardPlan := guard.BuildNftPlan(guardState)
	activeGuardPlan := initialGuardPlan
	guardApplied := false
	if !opts.DryRun && shouldApplyStartupGuard(cfg) {
		phaseSince = time.Now()
		publishProgress(
			ctx, opts, ReconcilePhaseQuiescing, phaseSince,
			guardState, guardStatus, loader, nil,
		)
		if runtime, ok := loader.(dataplane.StartupGuardRuntime); ok {
			barrierHeldStarted = time.Now()
			lease, err := runtime.QuiesceForStartupGuard(ctx)
			if err != nil {
				return nil, fmt.Errorf("quiesce resident dataplane before startup guard: %w", err)
			}
			if err := guardTxn.recordLease(runtime, lease); err != nil {
				return nil, fmt.Errorf("quiesce resident dataplane before startup guard: %w", err)
			}
			publishProgress(
				ctx, opts, ReconcilePhaseQuiescing, phaseSince,
				guardState, guardStatus, loader, nil,
			)
		}
		outcome, err := guardTxn.apply(ctx, guardExecutor, initialGuardPlan)
		guardStatus = projectGuardOutcome(cfg.StartupGuard.Mode, guardStatus, outcome, err)
		if err != nil {
			return nil, fmt.Errorf("apply startup guard: %w", err)
		}
		if guardStatus.KernelState != StartupGuardKernelActive {
			return nil, fmt.Errorf(
				"apply startup guard returned kernel state %q, want %q",
				guardStatus.KernelState, StartupGuardKernelActive,
			)
		}
		guardActiveStarted = time.Now()
		guardApplied = true
		phaseSince = time.Now()
		publishProgress(
			ctx, opts, ReconcilePhaseGuarded, phaseSince,
			guardState, guardStatus, loader, nil,
		)
	}

	runtimeProvider := configuredRuntimeProvider(opts)
	if !opts.Offline {
		runtimeProvider = snapshotRuntimeProvider(runtimeProvider)
	}
	if guardApplied && !opts.Offline {
		observedMarks := observedRuntimeFwmarks(ctx, cfg, runtimeProvider)
		expandedPlan := guard.BuildNftPlan(guardState, observedMarks...)
		if !sameNftPlan(activeGuardPlan, expandedPlan) {
			outcome, err := guardTxn.apply(ctx, guardExecutor, expandedPlan)
			guardStatus = projectGuardOutcome(cfg.StartupGuard.Mode, guardStatus, outcome, err)
			if err != nil {
				return nil, fmt.Errorf("expand startup guard for observed runtime fwmarks: %w", err)
			}
			if guardStatus.KernelState != StartupGuardKernelActive {
				return nil, fmt.Errorf(
					"expand startup guard for observed runtime fwmarks returned kernel state %q",
					guardStatus.KernelState,
				)
			}
			activeGuardPlan = expandedPlan
			publishProgress(
				ctx, opts, ReconcilePhaseGuarded, phaseSince,
				guardState, guardStatus, loader, nil,
			)
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
	// The startup guard is built from the configured WireGuard listen port,
	// while the live FakeTCP policy uses the kernel-observed listen port. Keep
	// those two views identical before the loader can detach the baseline or
	// attach any process-owned FakeTCP program.
	if err := validateFakeTCPStartupIsolation(cfg, state); err != nil {
		return nil, err
	}
	result = &Result{ConfigPath: configPath(opts), Time: time.Now(), Action: "reload", State: state, DryRun: opts.DryRun, AttachStatePath: attachstate.Path(opts.StateDir)}
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
			outcome, err := guardTxn.apply(ctx, guardExecutor, runtimeGuardPlan)
			guardStatus = projectGuardOutcome(cfg.StartupGuard.Mode, guardStatus, outcome, err)
			if err != nil {
				return nil, fmt.Errorf("expand startup guard for runtime fwmarks: %w", err)
			}
			if guardStatus.KernelState != StartupGuardKernelActive {
				return nil, fmt.Errorf(
					"expand startup guard for runtime fwmarks returned kernel state %q",
					guardStatus.KernelState,
				)
			}
		}
	}
	phaseSince = time.Now()
	publishProgress(
		ctx, opts, ReconcilePhaseApplying, phaseSince,
		state, guardStatus, loader, nil,
	)
	if cfg.StartupGuard.Mode == config.StartupGuardModeNone {
		if err := configuredNoNFTGuardPreflight(opts)(ctx, opts.StateDir); err != nil {
			guardStatus.Error = joinStatusText(guardStatus.Error, err.Error())
			guardStatus.ObservationTime = time.Now()
			return nil, fmt.Errorf("revalidate disabled startup guard immediately before dataplane apply: %w", err)
		}
	}
	guardTxn.dataplaneMutationStarted = true
	applyStarted := time.Now()
	if err := loader.Apply(ctx, state); err != nil {
		timings.ApplyNanoseconds = time.Since(applyStarted).Nanoseconds()
		return nil, err
	}
	timings.ApplyNanoseconds = time.Since(applyStarted).Nanoseconds()
	if handled, kernelStatus, statusErr := configuredProductionFakeTCPStatus(opts)(ctx, state); handled {
		result.Dataplane = kernelStatus
		if statusErr != nil {
			// The startup guard must remain installed until every process-owned
			// FakeTCP map and attachment has passed its final retained-owner
			// health check. Returning here deliberately precedes attach-state
			// publication and guard cleanup.
			return nil, fmt.Errorf("verify production FakeTCP runtime health after apply: %w", statusErr)
		}
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
	guardTxn.dataplaneValidated = true
	if guardApplied {
		phaseSince = time.Now()
		publishProgress(
			ctx, opts, ReconcilePhaseFinalizing, phaseSince,
			state, guardStatus, loader, nil,
		)
		cleanupStarted := time.Now()
		outcome, err := guardExecutor.Cleanup(ctx)
		timings.CleanupNanoseconds = time.Since(cleanupStarted).Nanoseconds()
		guardTxn.recordNormalCleanup(outcome)
		guardStatus = projectGuardOutcome(cfg.StartupGuard.Mode, guardStatus, outcome, err)
		if err != nil {
			return nil, fmt.Errorf("cleanup startup guard after reload: %w", err)
		}
		if !guardTxn.cleanupProvedAbsent {
			return nil, fmt.Errorf(
				"cleanup startup guard returned kernel state %q, want %q",
				guardStatus.KernelState, StartupGuardKernelAbsent,
			)
		}
		if !guardActiveStarted.IsZero() {
			timings.GuardActiveNanoseconds = time.Since(guardActiveStarted).Nanoseconds()
		}
		result.GuardCleaned = true
		if guardTxn.runtime != nil {
			recoveryCtx, cancel := startupGuardFinalizationContext(ctx)
			err := guardTxn.resume(recoveryCtx)
			cancel()
			if err != nil {
				return nil, fmt.Errorf("resume resident dataplane after startup guard: %w", err)
			}
			if !barrierHeldStarted.IsZero() {
				timings.BarrierHeldNanoseconds = time.Since(barrierHeldStarted).Nanoseconds()
			}
		}
	}
	phaseSince = time.Now()
	result.Observation = publishFinalProgress(
		ctx, opts, ReconcilePhaseActive, phaseSince,
		state, guardStatus, loader, nil,
	)
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
	err := withMutationOwnership(ctx, opts, "detach", func(lease *lockfile.LifecycleLease) error {
		ownedOpts := opts
		ownedOpts.LifecycleLease = lease
		var err error
		result, err = detachUnlocked(ctx, ownedOpts)
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
	err := withMutationOwnership(ctx, opts, "stop", func(lease *lockfile.LifecycleLease) error {
		ownedOpts := opts
		ownedOpts.LifecycleLease = lease
		var err error
		result, err = stopUnlocked(ctx, ownedOpts)
		return err
	})
	return result, err
}

func stopUnlocked(ctx context.Context, opts Options) (*Result, error) {
	guardMode, guardModeKnown := configuredStartupGuardMode(opts)
	if !opts.DryRun && guardModeKnown && guardMode == config.StartupGuardModeNone {
		if err := configuredNoNFTGuardPreflight(opts)(ctx, opts.StateDir); err != nil {
			return nil, fmt.Errorf("preflight disabled startup guard during stop: %w", err)
		}
	}
	result, err := detachUnlocked(ctx, opts)
	if err != nil && !errors.Is(err, errNoDetachUnderlays) {
		return nil, err
	}
	if result == nil {
		result = &Result{ConfigPath: configPath(opts), Time: time.Now(), State: &control.State{}, DryRun: opts.DryRun, AttachStatePath: attachstate.Path(opts.StateDir)}
	}
	result.Action = "stop"
	if opts.DryRun {
		if !guardModeKnown || guardMode != config.StartupGuardModeNone {
			result.GuardCleanup = guard.CleanupScript()
		}
		return result, nil
	}
	cleaned, warning, err := cleanupGuardForStop(ctx, opts, guardMode, guardModeKnown)
	if err != nil {
		return nil, fmt.Errorf("cleanup startup guard during stop: %w", err)
	}
	result.GuardCleaned = cleaned
	result.GuardWarning = warning
	return result, nil
}

func cleanupGuardForStop(
	ctx context.Context,
	opts Options,
	mode string,
	modeKnown bool,
) (bool, string, error) {
	if modeKnown && mode == config.StartupGuardModeNone {
		// The disabled executor's read-only preflight already proved absence
		// before detach. Do not repeat the netlink dump and do not claim that
		// stop performed a guard cleanup mutation. Explicit guard-cleanup remains
		// the recovery command for an installation with ownership evidence.
		return false, "", nil
	}
	outcome, err := configuredGuardExecutor(opts).Cleanup(ctx)
	if err != nil {
		return false, outcomeWarning(outcome), err
	}
	status := projectGuardOutcome(startupGuardModeUnknown, StartupGuardStatus{}, outcome, nil)
	if status.KernelState != StartupGuardKernelAbsent {
		return false, status.Warning, fmt.Errorf(
			"cleanup startup guard during stop returned kernel state %q, want %q",
			status.KernelState, StartupGuardKernelAbsent,
		)
	}
	return true, status.Warning, nil
}

func configuredStartupGuardMode(opts Options) (string, bool) {
	cfg, err := loadConfig(opts)
	if err != nil || cfg == nil {
		return startupGuardModeUnknown, false
	}
	return cfg.StartupGuard.Mode, true
}

func outcomeWarning(outcome guard.Outcome) string {
	if outcome.Warning == nil {
		return ""
	}
	return diagnostic.Redact(outcome.Warning.Error())
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
	if err := dataplane.ValidateFakeTCPActivation(state); err != nil {
		return nil, err
	}
	plan := guard.BuildNftPlan(state)
	result := &Result{ConfigPath: configPath(opts), Time: time.Now(), Action: "guard-apply", State: state, GuardScript: plan.Script(), DryRun: opts.DryRun}
	if opts.DryRun {
		return result, nil
	}
	if err := withMutationOwnership(ctx, opts, "guard-apply", func(*lockfile.LifecycleLease) error {
		outcome, err := configuredGuardExecutor(opts).Apply(ctx, plan)
		result.GuardWarning = outcomeWarning(outcome)
		if err != nil {
			return err
		}
		status := projectGuardOutcome("nft-temporary-drop", StartupGuardStatus{}, outcome, nil)
		if status.KernelState != StartupGuardKernelActive {
			return fmt.Errorf("guard apply returned kernel state %q", status.KernelState)
		}
		return nil
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
	if err := withMutationOwnership(ctx, opts, "guard-cleanup", func(*lockfile.LifecycleLease) error {
		outcome, err := configuredGuardExecutor(opts).Cleanup(ctx)
		result.GuardWarning = outcomeWarning(outcome)
		if err != nil {
			return err
		}
		status := projectGuardOutcome(startupGuardModeUnknown, StartupGuardStatus{}, outcome, nil)
		if status.KernelState != StartupGuardKernelAbsent {
			return fmt.Errorf("guard cleanup returned kernel state %q", status.KernelState)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	result.GuardCleaned = true
	return result, nil
}

func shouldApplyStartupGuard(cfg *config.Config) bool {
	return cfg.StartupGuard.Mode == config.StartupGuardModeNFTTemporaryDrop &&
		cfg.Policy.StartupFailMode == "fail_closed_for_managed_flows"
}

func validateFakeTCPStartupIsolation(cfg *config.Config, state *control.State) error {
	if cfg == nil || state == nil {
		return errors.New("validate FakeTCP startup isolation: config and state are required")
	}
	for _, wg := range state.WireGuards {
		if wg.TransportMode != "faketcp" {
			continue
		}
		if wg.ConfigListenPort == 0 {
			return fmt.Errorf(
				"faketcp WireGuard %q requires a fixed non-zero ListenPort in its WireGuard config so the startup guard covers both UDP and TCP wire traffic",
				wg.Name,
			)
		}
		if wg.RuntimeStateAvailable && wg.RuntimeListenPort != wg.ConfigListenPort {
			return fmt.Errorf(
				"faketcp WireGuard %q runtime ListenPort %d does not equal configured ListenPort %d protected by the startup guard",
				wg.Name,
				wg.RuntimeListenPort,
				wg.ConfigListenPort,
			)
		}
	}
	return nil
}

func configPath(opts Options) string {
	if opts.ConfigPath != "" {
		return opts.ConfigPath
	}
	return config.DefaultConfigPath
}

func withMutationOwnership(
	ctx context.Context,
	opts Options,
	action string,
	fn func(*lockfile.LifecycleLease) error,
) error {
	owner := lockfile.LifecycleOwner{
		PID:        os.Getpid(),
		Action:     action,
		ConfigPath: configPath(opts),
		RunDir:     opts.RunDir,
	}
	return lockfile.WithLifecycle(ctx, opts.LifecycleLease, owner, func(lease *lockfile.LifecycleLease) error {
		mutate := func() error { return fn(lease) }
		if opts.RunDir == "" {
			return mutate()
		}
		return lockfile.WithLock(ctx, opts.RunDir, mutate)
	})
}
