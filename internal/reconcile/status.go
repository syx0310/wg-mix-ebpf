package reconcile

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/config"
	"github.com/syx0310/wg-mix-ebpf/internal/control"
	"github.com/syx0310/wg-mix-ebpf/internal/dataplane"
	"github.com/syx0310/wg-mix-ebpf/internal/diagnostic"
	"github.com/syx0310/wg-mix-ebpf/internal/faketcp"
	"github.com/syx0310/wg-mix-ebpf/internal/guard"
)

const (
	ReconcilePhaseIdle         = "idle"
	StartupGuardKernelActive   = "active"
	StartupGuardKernelAbsent   = "absent"
	StartupGuardKernelDisabled = "disabled"
	StartupGuardKernelUnknown  = "unknown"
)

const startupGuardModeUnknown = "unknown"

const noNFTStartupGuardRisk = "startup_guard.mode=none does not prevent standard UDP leakage or host-stack FakeTCP RST during startup and reload"

const startupGuardFinalizationTimeout = 5 * time.Second

const (
	ReconcilePhasePreparing  = "preparing"
	ReconcilePhaseQuiescing  = "quiescing"
	ReconcilePhaseGuarded    = "guarded"
	ReconcilePhaseApplying   = "applying"
	ReconcilePhaseFinalizing = "finalizing"
	ReconcilePhaseActive     = "active"
	ReconcilePhaseFailed     = "failed"
)

// StartupGuardStatus deliberately combines a fresh kernel observation with
// the resident process's pause snapshot. The two observation clocks are kept
// separate because the kernel can be inspected by a status client while only
// the daemon that owns the runtime can inspect its in-memory barrier.
type StartupGuardStatus struct {
	Mode            string                             `json:"mode"`
	KernelState     string                             `json:"kernel_state"`
	ObservationTime time.Time                          `json:"observation_time"`
	Warning         string                             `json:"warning,omitempty"`
	Error           string                             `json:"error,omitempty"`
	Risk            string                             `json:"risk,omitempty"`
	RuntimePause    *dataplane.StartupGuardPauseStatus `json:"runtime_pause,omitempty"`
}

type ReconcileStatus struct {
	Phase           string    `json:"phase"`
	Since           time.Time `json:"since"`
	ObservationTime time.Time `json:"observation_time"`
	Error           string    `json:"error,omitempty"`
}

// Observation is the current read-only status projection. Unlike Result it
// is not a record of a completed operation and must be refreshed whenever it
// is presented as current daemon state.
type Observation struct {
	ObservationTime time.Time               `json:"observation_time"`
	Reconcile       ReconcileStatus         `json:"reconcile"`
	StartupGuard    StartupGuardStatus      `json:"startup_guard"`
	Dataplane       *dataplane.KernelStatus `json:"dataplane,omitempty"`
	DataplaneError  string                  `json:"dataplane_error,omitempty"`
}

type ProgressFunc func(Observation)

func observeStartupGuard(
	ctx context.Context,
	opts Options,
	cfg *config.Config,
) StartupGuardStatus {
	mode := startupGuardModeUnknown
	if cfg != nil && cfg.StartupGuard.Mode != "" {
		mode = cfg.StartupGuard.Mode
	}
	if mode == config.StartupGuardModeNone {
		status := StartupGuardStatus{
			Mode: mode, KernelState: StartupGuardKernelDisabled,
			ObservationTime: time.Now(), Risk: noNFTStartupGuardRisk,
		}
		if err := configuredNoNFTGuardPreflight(opts)(ctx, opts.StateDir); err != nil {
			status.Error = diagnostic.Redact(err.Error())
			status.ObservationTime = time.Now()
		}
		return status
	}
	outcome, err := configuredGuardExecutor(opts).Observe(ctx)
	return projectGuardOutcome(mode, StartupGuardStatus{}, outcome, err)
}

func unobservedStartupGuard(cfg *config.Config) StartupGuardStatus {
	mode := startupGuardModeUnknown
	state := StartupGuardKernelUnknown
	if cfg != nil && cfg.StartupGuard.Mode != "" {
		mode = cfg.StartupGuard.Mode
	}
	if mode == config.StartupGuardModeNone {
		state = StartupGuardKernelDisabled
	}
	return StartupGuardStatus{
		Mode: mode, KernelState: state, ObservationTime: time.Now(),
		Risk: func() string {
			if mode == config.StartupGuardModeNone {
				return noNFTStartupGuardRisk
			}
			return ""
		}(),
	}
}

// preflightNoNFTStartupGuard combines durable ownership evidence with the
// disabled executor's read-only NETLINK_NETFILTER project-table inventory.
// A securely validated stable v2 owner record is compatible with no-nft only
// when the following fresh kernel inventory proves every project table absent.
// Neither half invokes the nft binary or mutates nf_tables.
func preflightNoNFTStartupGuard(ctx context.Context, configuredStateDir string) error {
	return preflightNoNFTStartupGuardWith(
		ctx,
		configuredStateDir,
		guard.NewDisabledExecutor(),
	)
}

type disabledGuardPreflight interface {
	Preflight(context.Context) (guard.Outcome, error)
}

func preflightNoNFTStartupGuardWith(
	ctx context.Context,
	configuredStateDir string,
	preflight disabledGuardPreflight,
) error {
	if err := guard.ValidateNoNFTOwnerState(configuredStateDir); err != nil {
		return err
	}
	if preflight == nil {
		return errors.New("preflight disabled startup guard: kernel inventory is nil")
	}
	outcome, err := preflight.Preflight(ctx)
	if err != nil {
		return err
	}
	if outcome.Observation != guard.ObservationAbsent || outcome.Mutated {
		return fmt.Errorf(
			"inventory disabled startup guard returned observation %q mutated=%t, want absent without mutation",
			outcome.Observation,
			outcome.Mutated,
		)
	}
	return nil
}

func projectGuardOutcome(
	mode string,
	previous StartupGuardStatus,
	outcome guard.Outcome,
	err error,
) StartupGuardStatus {
	if mode == "" {
		mode = startupGuardModeUnknown
	}
	status := StartupGuardStatus{
		Mode: mode, KernelState: StartupGuardKernelUnknown,
		ObservationTime: time.Now(),
		RuntimePause:    clonePauseStatus(previous.RuntimePause),
	}
	switch outcome.Observation {
	case guard.ObservationActive:
		status.KernelState = StartupGuardKernelActive
	case guard.ObservationAbsent:
		status.KernelState = StartupGuardKernelAbsent
	case guard.ObservationUnchanged:
		if previous.KernelState != "" {
			status.KernelState = previous.KernelState
		}
		status.Warning = previous.Warning
	case guard.ObservationUnknown:
		status.KernelState = StartupGuardKernelUnknown
	default:
		status.Error = "guard observer returned an invalid kernel state"
	}
	if outcome.Warning != nil {
		status.Warning = joinStatusText(status.Warning, diagnostic.Redact(outcome.Warning.Error()))
	}
	if err != nil {
		status.Error = joinStatusText(status.Error, diagnostic.Redact(err.Error()))
	}
	return status
}

func joinStatusText(existing, next string) string {
	existing = strings.TrimSpace(existing)
	next = strings.TrimSpace(next)
	if existing == "" {
		return next
	}
	if next == "" || next == existing {
		return existing
	}
	return existing + "; " + next
}

func startupGuardFinalizationContext(ctx context.Context) (context.Context, context.CancelFunc) {
	base := context.Background()
	if ctx != nil {
		base = context.WithoutCancel(ctx)
	}
	return context.WithTimeout(base, startupGuardFinalizationTimeout)
}

func pauseWasOpen(status *dataplane.StartupGuardPauseStatus) bool {
	return status == nil || status.Phase == "" || status.Phase == "open"
}

func publishProgress(
	_ context.Context,
	opts Options,
	phase string,
	since time.Time,
	_ *control.State,
	guardStatus StartupGuardStatus,
	loader dataplane.Loader,
	operationErr error,
) *Observation {
	observation := newPhaseObservation(phase, since, guardStatus, loader, operationErr)
	publishObservation(opts, observation)
	return observation
}

// publishFinalProgress is reserved for a terminal safe point. Unlike
// publishProgress it may enumerate pins, maps, links, filters, and stats in
// order to attach a deep dataplane snapshot to the final observation.
func publishFinalProgress(
	ctx context.Context,
	opts Options,
	phase string,
	since time.Time,
	state *control.State,
	guardStatus StartupGuardStatus,
	loader dataplane.Loader,
	operationErr error,
) *Observation {
	observation := newPhaseObservation(phase, since, guardStatus, loader, operationErr)
	refreshDeepObservation(ctx, opts, state, loader, observation)
	publishObservation(opts, observation)
	return observation
}

// newPhaseObservation is intentionally a pure userspace projection. Reload
// can call it while the startup guard is active or the resident runtime is
// paused without opening BPF pins/maps/links, enumerating TC filters, or
// collecting counters. Deep status snapshots belong to explicit Status calls
// and publishFinalProgress only; this does not replace the loader's mandatory
// post-apply health gate.
func newPhaseObservation(
	phase string,
	since time.Time,
	guardStatus StartupGuardStatus,
	loader dataplane.Loader,
	operationErr error,
) *Observation {
	observedAt := time.Now()
	guardStatus.RuntimePause = startupGuardPauseStatus(loader, observedAt)
	observation := &Observation{
		ObservationTime: observedAt,
		Reconcile: ReconcileStatus{
			Phase: phase, Since: since, ObservationTime: observedAt,
		},
		StartupGuard: guardStatus,
	}
	if operationErr != nil {
		observation.Reconcile.Error = diagnostic.Redact(operationErr.Error())
	}
	return observation
}

func refreshDeepObservation(
	ctx context.Context,
	opts Options,
	state *control.State,
	loader dataplane.Loader,
	observation *Observation,
) {
	if observation == nil {
		return
	}
	observation.Dataplane, observation.DataplaneError = inspectCurrentDataplane(
		ctx,
		opts,
		state,
		loader,
	)
}

func publishObservation(opts Options, observation *Observation) {
	if opts.Progress != nil {
		clone := cloneObservation(observation)
		opts.Progress(*clone)
	}
}

func cloneObservation(observation *Observation) *Observation {
	if observation == nil {
		return nil
	}
	clone := *observation
	clone.StartupGuard.RuntimePause = clonePauseStatus(observation.StartupGuard.RuntimePause)
	clone.Dataplane = cloneKernelStatus(observation.Dataplane)
	return &clone
}

func clonePauseStatus(status *dataplane.StartupGuardPauseStatus) *dataplane.StartupGuardPauseStatus {
	if status == nil {
		return nil
	}
	clone := *status
	return &clone
}

func cloneKernelStatus(status *dataplane.KernelStatus) *dataplane.KernelStatus {
	if status == nil {
		return nil
	}
	clone := *status
	if status.Stats != nil {
		clone.Stats = make(map[string]uint64, len(status.Stats))
		for key, value := range status.Stats {
			clone.Stats[key] = value
		}
	}
	clone.Underlays = append([]dataplane.UnderlayKernelStatus(nil), status.Underlays...)
	for index := range clone.Underlays {
		clone.Underlays[index].Filters = append(
			[]dataplane.FilterStatus(nil),
			status.Underlays[index].Filters...,
		)
	}
	if status.FakeTCP != nil {
		runtime := *status.FakeTCP
		runtime.ChecksumBackend.Capabilities = append(
			[]string(nil), status.FakeTCP.ChecksumBackend.Capabilities...,
		)
		runtime.StartupGuardPause = clonePauseStatus(status.FakeTCP.StartupGuardPause)
		runtime.XDP = append([]dataplane.FakeTCPXDPStatus(nil), status.FakeTCP.XDP...)
		runtime.TCX = append([]dataplane.FakeTCPTCXStatus(nil), status.FakeTCP.TCX...)
		runtime.ClassicTC = append(
			[]dataplane.FakeTCPClassicTCStatus(nil), status.FakeTCP.ClassicTC...,
		)
		runtime.Ownership = nil
		clone.FakeTCP = &runtime
		dataplane.ProjectFakeTCPOwnership(&clone)
	}
	return &clone
}

func inspectDataplane(
	ctx context.Context,
	opts Options,
	state *control.State,
) (*dataplane.KernelStatus, string) {
	if state == nil {
		return nil, ""
	}
	if handled, status, err := configuredProductionFakeTCPStatus(opts)(ctx, state); handled {
		dataplane.ProjectFakeTCPOwnership(status)
		if err != nil {
			return status, diagnostic.Redact(err.Error())
		}
		return status, ""
	}
	status, err := dataplane.Inspect(ctx, state)
	if err == nil {
		return status, ""
	}
	if errors.Is(err, dataplane.ErrUnsupported) {
		return nil, ""
	}
	return status, diagnostic.Redact(err.Error())
}

func inspectCurrentDataplane(
	ctx context.Context,
	opts Options,
	state *control.State,
	loader dataplane.Loader,
) (*dataplane.KernelStatus, string) {
	// Always ask for the resident FakeTCP owner first. A failed config load or
	// a changed desired mode must not hide the process-owned generation that is
	// still serving (or deliberately paused inside) the daemon.
	residentProbe := &control.State{WireGuards: []control.WireGuardState{{
		Name: "resident-status-probe", TransportMode: "faketcp",
	}}}
	if handled, status, err := configuredProductionFakeTCPStatus(opts)(ctx, residentProbe); handled &&
		status != nil && status.FakeTCP != nil {
		status.FakeTCP.StartupGuardPause = startupGuardPauseStatus(loader, time.Now())
		dataplane.ProjectFakeTCPOwnership(status)
		if err != nil {
			return status, diagnostic.Redact(err.Error())
		}
		return status, ""
	}
	status, statusErr := inspectDataplane(ctx, opts, state)
	if status != nil && status.FakeTCP != nil {
		status.FakeTCP.StartupGuardPause = startupGuardPauseStatus(loader, time.Now())
		dataplane.ProjectFakeTCPOwnership(status)
	}
	return status, statusErr
}

type startupGuardPauseStatusProvider interface {
	StartupGuardPauseStatus() faketcp.StartupGuardPauseStatus
}

// startupGuardPauseStatus is the sole A2 adapter. Reconcile stores only the
// stable JSON projection and does not depend on the concrete runtime or
// supervisor implementation.
func startupGuardPauseStatus(
	loader dataplane.Loader,
	observedAt time.Time,
) *dataplane.StartupGuardPauseStatus {
	provider, ok := loader.(startupGuardPauseStatusProvider)
	if !ok {
		return nil
	}
	status := provider.StartupGuardPauseStatus()
	return &dataplane.StartupGuardPauseStatus{
		Phase:           string(status.Phase),
		Reason:          string(status.Reason),
		Since:           status.Since,
		ObservationTime: observedAt,
	}
}
