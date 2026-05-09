package reconcile

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/config"
	"github.com/syx0310/wg-mix-ebpf/internal/control"
	"github.com/syx0310/wg-mix-ebpf/internal/dataplane"
	"github.com/syx0310/wg-mix-ebpf/internal/guard"
	"github.com/syx0310/wg-mix-ebpf/internal/runtime"
	"github.com/syx0310/wg-mix-ebpf/internal/underlay"
)

type Options struct {
	ConfigPath string
	Offline    bool
	DryRun     bool
}

type Result struct {
	ConfigPath      string                  `json:"config_path"`
	Time            time.Time               `json:"time"`
	Action          string                  `json:"action"`
	State           *control.State          `json:"state,omitempty"`
	Dataplane       *dataplane.KernelStatus `json:"dataplane,omitempty"`
	DataplaneError  string                  `json:"dataplane_error,omitempty"`
	GuardApplied    bool                    `json:"guard_applied,omitempty"`
	GuardCleaned    bool                    `json:"guard_cleaned,omitempty"`
	GuardScript     string                  `json:"guard_script,omitempty"`
	GuardCleanup    string                  `json:"guard_cleanup,omitempty"`
	DryRun          bool                    `json:"dry_run,omitempty"`
	OneShotFallback bool                    `json:"one_shot_fallback,omitempty"`
}

func BuildState(ctx context.Context, opts Options) (*config.Config, *control.State, error) {
	path := opts.ConfigPath
	if path == "" {
		path = config.DefaultConfigPath
	}
	cfg, err := config.LoadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("load config %s: %w", path, err)
	}
	state, err := control.BuildState(ctx, cfg, runtime.NewSystemProvider(), underlay.NewSystemResolver(), nil, control.BuildOptions{Offline: opts.Offline})
	if err != nil {
		if control.IsUnsupportedRuntime(err) && !opts.Offline {
			return nil, nil, fmt.Errorf("%w (use --offline for static validation on this platform)", err)
		}
		return nil, nil, err
	}
	return cfg, state, nil
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
	cfg, state, err := BuildState(ctx, opts)
	if err != nil {
		return nil, err
	}
	result := &Result{ConfigPath: configPath(opts), Time: time.Now(), Action: "reload", State: state, DryRun: opts.DryRun}
	if opts.DryRun {
		if shouldApplyStartupGuard(cfg) {
			result.GuardScript = guard.BuildNftPlan(state).Script()
		}
		return result, nil
	}
	guardApplied := false
	if shouldApplyStartupGuard(cfg) {
		plan := guard.BuildNftPlan(state)
		if err := guard.NewCommandExecutor().Apply(ctx, plan); err != nil {
			return nil, fmt.Errorf("apply startup guard: %w", err)
		}
		guardApplied = true
		result.GuardApplied = true
	}
	if err := dataplane.NewLoader().Apply(ctx, state); err != nil {
		return nil, err
	}
	if guardApplied {
		if err := guard.NewCommandExecutor().Cleanup(ctx); err != nil {
			return nil, fmt.Errorf("cleanup startup guard after reload: %w", err)
		}
		result.GuardCleaned = true
	}
	return result, nil
}

func Detach(ctx context.Context, opts Options) (*Result, error) {
	_, state, err := BuildState(ctx, opts)
	if err != nil {
		return nil, err
	}
	result := &Result{ConfigPath: configPath(opts), Time: time.Now(), Action: "detach", State: state, DryRun: opts.DryRun}
	if opts.DryRun {
		return result, nil
	}
	if err := dataplane.NewLoader().Detach(ctx, state); err != nil {
		return nil, err
	}
	return result, nil
}

func GuardPlan(ctx context.Context, opts Options) (*Result, error) {
	_, state, err := BuildState(ctx, opts)
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
	_, state, err := BuildState(ctx, opts)
	if err != nil {
		return nil, err
	}
	plan := guard.BuildNftPlan(state)
	result := &Result{ConfigPath: configPath(opts), Time: time.Now(), Action: "guard-apply", State: state, GuardScript: plan.Script(), DryRun: opts.DryRun}
	if opts.DryRun {
		return result, nil
	}
	if err := guard.NewCommandExecutor().Apply(ctx, plan); err != nil {
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
	if err := guard.NewCommandExecutor().Cleanup(ctx); err != nil {
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
