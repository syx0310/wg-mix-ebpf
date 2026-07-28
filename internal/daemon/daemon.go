package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/config"
	"github.com/syx0310/wg-mix-ebpf/internal/control"
	"github.com/syx0310/wg-mix-ebpf/internal/dataplane"
	"github.com/syx0310/wg-mix-ebpf/internal/lockfile"
	"github.com/syx0310/wg-mix-ebpf/internal/reconcile"
)

const (
	DefaultRunDir          = "/run/wg-mix-ebpf"
	EnvRunDir              = "WG_MIX_EBPF_RUN_DIR"
	DefaultShutdownTimeout = 10 * time.Second
	DefaultRequestTimeout  = 15 * time.Second
	cleanupCompletionGrace = 25 * time.Millisecond
)

var ErrDaemonNotRunning = errors.New("wg-mix-ebpf daemon is not running")

type Options struct {
	ConfigPath      string
	RunDir          string
	StateDir        string
	PollInterval    time.Duration
	ShutdownTimeout time.Duration
	Once            bool
	Offline         bool
	DryRun          bool

	hooks          *runHooks
	lifecycleLease *lockfile.LifecycleLease
}

type Status struct {
	PID             int               `json:"pid"`
	ConfigPath      string            `json:"config_path"`
	State           string            `json:"state"`
	LastReason      string            `json:"last_reason,omitempty"`
	LastSuccess     time.Time         `json:"last_success,omitempty"`
	LastErrorTime   time.Time         `json:"last_error_time,omitempty"`
	LastError       string            `json:"last_error,omitempty"`
	LastResult      *reconcile.Result `json:"last_result,omitempty"`
	NeedReload      bool              `json:"need_reload,omitempty"`
	RequestProtocol int               `json:"request_protocol"`
	InstanceID      string            `json:"instance_id"`
	LastRequestID   string            `json:"last_request_id,omitempty"`
	LastRequestKind string            `json:"last_request_kind,omitempty"`
}

type runHooks struct {
	lifecycleLeasePath string
	instanceID         string
	acquireLease       func(string, leaseOwner) (*lifecycleLeaseHandle, error)
	reload             func(context.Context, reconcile.Options) (*reconcile.Result, error)
	validate           func(context.Context, reconcile.Options) (*reconcile.Result, error)
	healthy            func(context.Context, *control.State) bool
	stop               func(context.Context, Options, string) (*reconcile.Result, error)
	writeStatus        func(string, Status) error
}

func Run(parentCtx context.Context, opts Options) (retErr error) {
	if opts.Offline && !opts.DryRun {
		return errors.New("offline daemon mode requires --dry-run")
	}
	if opts.PollInterval < 0 {
		return errors.New("poll interval must not be negative")
	}
	if opts.ShutdownTimeout < 0 {
		return errors.New("shutdown timeout must not be negative")
	}
	if err := parentCtx.Err(); err != nil {
		return err
	}

	runDir := runDir(opts.RunDir)
	hooks := hooksFor(opts)
	leasePath := lifecycleLeasePath(opts, runDir, hooks.lifecycleLeasePath)
	lease, err := hooks.acquireLease(leasePath, leaseOwner{
		PID:        os.Getpid(),
		Action:     "daemon",
		ConfigPath: configPath(opts.ConfigPath),
		RunDir:     runDir,
	})
	if err != nil {
		return err
	}
	opts.lifecycleLease = lease
	defer func() {
		if err := lease.Close(); err != nil {
			retErr = errors.Join(retErr, err)
		}
	}()

	ctx, stopSignals := signal.NotifyContext(parentCtx, syscall.SIGINT, syscall.SIGTERM)
	restoreSignalsOnDone := context.AfterFunc(ctx, stopSignals)
	defer func() {
		restoreSignalsOnDone()
		stopSignals()
	}()

	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return fmt.Errorf("create run dir: %w", err)
	}
	if err := ensureRequestDirs(runDir); err != nil {
		return err
	}
	instanceID := hooks.instanceID
	if instanceID == "" {
		instanceID, err = newRequestID()
		if err != nil {
			return err
		}
	}
	if !validRequestID(instanceID) {
		return fmt.Errorf("invalid daemon instance id %q", instanceID)
	}
	lastLegacyRequest := requestStamp(runDir)
	status := Status{
		PID:             os.Getpid(),
		ConfigPath:      configPath(opts.ConfigPath),
		State:           "starting",
		RequestProtocol: requestProtocolVersion,
		InstanceID:      instanceID,
	}
	if err := hooks.writeStatus(runDir, status); err != nil {
		return fmt.Errorf("write starting daemon status: %w", err)
	}

	interval := opts.PollInterval
	if interval == 0 {
		interval = pollIntervalFromConfig(opts.ConfigPath)
	}
	if interval == 0 {
		interval = 5 * time.Second
	}
	if interval < config.MinimumPollInterval {
		return fmt.Errorf("poll interval must be at least %s", config.MinimumPollInterval)
	}
	shutdownTimeout := opts.ShutdownTimeout
	if shutdownTimeout == 0 {
		shutdownTimeout = DefaultShutdownTimeout
	}

	lastFingerprint := ""
	lastConfigHash := ""
	shutdown := func(reason string, triggerErr error) error {
		status.PID = os.Getpid()
		status.ConfigPath = configPath(opts.ConfigPath)
		status.LastReason = reason
		status.NeedReload = false

		var cleanupErr error
		if !opts.DryRun {
			result, err := runStopBounded(ctx, shutdownTimeout, lease, func(cleanupCtx context.Context, workerLease *lockfile.LifecycleLease) (*reconcile.Result, error) {
				cleanupOpts := opts
				cleanupOpts.lifecycleLease = workerLease
				return hooks.stop(cleanupCtx, cleanupOpts, runDir)
			})
			if result != nil {
				status.LastResult = result
			}
			if err != nil {
				cleanupErr = fmt.Errorf("daemon stop cleanup: %w", err)
			}
		}

		finalErr := errors.Join(triggerErr, cleanupErr)
		if finalErr != nil {
			status.State = "degraded"
			status.LastError = finalErr.Error()
			status.LastErrorTime = time.Now()
		} else {
			status.State = "stopped"
			status.LastError = ""
			status.LastSuccess = time.Now()
		}

		var statusErr error
		if err := hooks.writeStatus(runDir, status); err != nil {
			statusErr = fmt.Errorf("write final daemon status: %w", err)
		}
		return errors.Join(finalErr, statusErr)
	}
	recordLegacyWarnings := func(warnings []string) error {
		if len(warnings) == 0 {
			return nil
		}
		warning := "ignored legacy request notification: " + strings.Join(warnings, "; ")
		if status.LastError != "" {
			status.LastError += "\n" + warning
		} else {
			status.State = "degraded"
			status.LastReason = "legacy-request-ignored"
			status.LastError = warning
		}
		status.LastErrorTime = time.Now()
		if err := hooks.writeStatus(runDir, status); err != nil {
			return fmt.Errorf("write ignored legacy request status: %w", err)
		}
		return nil
	}

	runOnce := func(reason string) error {
		currentConfigHash := fileHash(configPath(opts.ConfigPath))
		if (reason == "poll" || reason == "runtime-event") && lastConfigHash != "" && currentConfigHash != "" && currentConfigHash != lastConfigHash {
			status.PID = os.Getpid()
			status.ConfigPath = configPath(opts.ConfigPath)
			status.State = "config_changed"
			status.NeedReload = true
			status.LastReason = reason
			status.LastError = "config file changed; run wg-mix-ebpf reload or systemctl reload wg-mix-ebpf to apply"
			status.LastErrorTime = time.Now()
			if err := hooks.writeStatus(runDir, status); err != nil {
				return fmt.Errorf("write config-changed daemon status: %w", err)
			}
			return nil
		}
		if reason == "poll" && lastFingerprint != "" {
			result, err := hooks.validate(ctx, reconcile.Options{ConfigPath: opts.ConfigPath, RunDir: runDir, StateDir: opts.StateDir, Offline: opts.Offline})
			if err == nil {
				fp := stateFingerprint(result)
				if fp == lastFingerprint {
					if !opts.Offline && !opts.DryRun && !hooks.healthy(ctx, result.State) {
						goto forceReload
					}
					status.PID = os.Getpid()
					status.ConfigPath = configPath(opts.ConfigPath)
					status.State = "active"
					status.LastReason = "poll-noop"
					status.LastError = ""
					status.NeedReload = false
					status.LastResult = result
					if err := hooks.writeStatus(runDir, status); err != nil {
						return fmt.Errorf("write poll-noop daemon status: %w", err)
					}
					return nil
				}
			}
		}
	forceReload:
		result, err := hooks.reload(ctx, reconcile.Options{
			ConfigPath:     opts.ConfigPath,
			RunDir:         runDir,
			StateDir:       opts.StateDir,
			Offline:        opts.Offline,
			DryRun:         opts.DryRun,
			LifecycleLease: lease,
		})
		status.PID = os.Getpid()
		status.ConfigPath = configPath(opts.ConfigPath)
		status.LastReason = reason
		if err != nil {
			status.State = "degraded"
			status.LastError = err.Error()
			status.LastErrorTime = time.Now()
		} else {
			status.State = "active"
			status.LastError = ""
			status.NeedReload = false
			status.LastSuccess = time.Now()
			status.LastResult = result
			lastFingerprint = stateFingerprint(result)
			lastConfigHash = currentConfigHash
		}
		if err := hooks.writeStatus(runDir, status); err != nil {
			return fmt.Errorf("write %s daemon status: %w", reason, err)
		}
		return nil
	}

	startupStatusErr := runOnce("startup")
	if opts.Once {
		var reconcileErr error
		if status.LastError != "" {
			reconcileErr = errors.New(status.LastError)
		}
		return errors.Join(reconcileErr, startupStatusErr)
	}
	if startupStatusErr != nil {
		return shutdown("startup-status-error", startupStatusErr)
	}
	if err := recordLegacyWarnings(legacyRequestWarnings(lastLegacyRequest)); err != nil {
		return shutdown("status-write-error", err)
	}

	ackHistoryChecked := false
	processRequests := func() (bool, error) {
		pending, err := pendingRequests(runDir)
		if err != nil {
			return false, err
		}
		pruneAckHistory := func() error {
			if ackHistoryChecked && len(pending) == 0 {
				return nil
			}
			ackHistoryChecked = true
			return pruneAcknowledgements(runDir)
		}
		valid := make([]pendingRequest, 0, len(pending))
		for _, request := range pending {
			if request.request.ExpectedInstanceID != status.InstanceID {
				requestErr := fmt.Errorf(
					"%w: request %s targets daemon instance %s, active instance is %s",
					ErrDaemonNotRunning,
					request.request.ID,
					request.request.ExpectedInstanceID,
					status.InstanceID,
				)
				if ackErr := acknowledgeRequest(runDir, request, status, requestErr); ackErr != nil {
					return false, errors.Join(requestErr, ackErr)
				}
				continue
			}
			if err := ValidateConfigPathForRequest(&status, request.request.ExpectedConfigPath, request.request.Kind); err != nil {
				if ackErr := acknowledgeRequest(runDir, request, status, err); ackErr != nil {
					return false, errors.Join(err, ackErr)
				}
				continue
			}
			valid = append(valid, request)
		}

		var stops []pendingRequest
		var reloads []pendingRequest
		for _, request := range valid {
			if request.request.Kind == "stop" {
				stops = append(stops, request)
			} else {
				reloads = append(reloads, request)
			}
		}
		if len(stops) > 0 {
			status.LastRequestID = stops[0].request.ID
			status.LastRequestKind = "stop"
			shutdownErr := shutdown("stop-request", nil)
			var ackErrs []error
			supersededErr := fmt.Errorf("reload request superseded by stop request %s", stops[0].request.ID)
			for _, request := range reloads {
				ackErrs = append(ackErrs, acknowledgeRequest(runDir, request, status, supersededErr))
			}
			for _, request := range stops {
				ackErrs = append(ackErrs, acknowledgeRequest(runDir, request, status, shutdownErr))
			}
			return true, errors.Join(shutdownErr, errors.Join(ackErrs...), pruneAckHistory())
		}

		for _, request := range reloads {
			status.LastRequestID = request.request.ID
			status.LastRequestKind = "reload"
			runErr := runOnce("reload-request")
			if runErr != nil {
				shutdownErr := shutdown("status-write-error", runErr)
				ackErr := acknowledgeRequest(runDir, request, status, shutdownErr)
				return true, errors.Join(shutdownErr, ackErr, pruneAckHistory())
			}
			var requestErr error
			if status.LastError != "" {
				requestErr = errors.New(status.LastError)
			}
			if err := acknowledgeRequest(runDir, request, status, requestErr); err != nil {
				return false, err
			}
		}
		return false, pruneAckHistory()
	}

	if shouldExit, err := processRequests(); shouldExit {
		return err
	} else if err != nil {
		return shutdown("request-processing-error", err)
	}

	ticker := time.NewTicker(interval)
	requestTicker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	defer requestTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return shutdown("signal", nil)
		case <-requestTicker.C:
			if shouldExit, err := processRequests(); shouldExit {
				return err
			} else if err != nil {
				return shutdown("request-processing-error", err)
			}
			stamp := requestStamp(runDir)
			if stamp != lastLegacyRequest {
				reloadChanged := stamp.Reload != lastLegacyRequest.Reload
				runtimeChanged := stamp.Runtime != lastLegacyRequest.Runtime
				lastLegacyRequest = stamp
				reloadEvent := reloadChanged &&
					stamp.Reload.ReadError == "" &&
					strings.HasPrefix(stamp.Reload.Value, "reload:")
				runtimeEvent := runtimeChanged &&
					stamp.Runtime.ReadError == "" &&
					stamp.Runtime.Value != ""
				if reloadEvent {
					if err := runOnce("reload-request"); err != nil {
						return shutdown("status-write-error", err)
					}
				} else if runtimeEvent {
					if err := runOnce("runtime-event"); err != nil {
						return shutdown("status-write-error", err)
					}
				}
				changed := legacyRequestStamp{}
				if reloadChanged {
					changed.Reload = stamp.Reload
				}
				if runtimeChanged {
					changed.Runtime = stamp.Runtime
				}
				if err := recordLegacyWarnings(legacyRequestWarnings(changed)); err != nil {
					return shutdown("status-write-error", err)
				}
			}
		case <-ticker.C:
			if err := runOnce("poll"); err != nil {
				return shutdown("status-write-error", err)
			}
		}
	}
}

type stopOutcome struct {
	result *reconcile.Result
	err    error
}

func runStopBounded(
	baseCtx context.Context,
	timeout time.Duration,
	lease *lockfile.LifecycleLease,
	stop func(context.Context, *lockfile.LifecycleLease) (*reconcile.Result, error),
) (*reconcile.Result, error) {
	retainedLease, err := lease.Retain()
	if err != nil {
		return nil, err
	}
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(baseCtx), timeout)
	done := make(chan stopOutcome, 1)
	go func() {
		result, stopErr := stop(cleanupCtx, retainedLease)
		done <- stopOutcome{result: result, err: errors.Join(stopErr, retainedLease.Close())}
	}()

	select {
	case outcome := <-done:
		deadlineErr := cleanupCtx.Err()
		cancel()
		return outcome.result, errors.Join(outcome.err, deadlineErr)
	case <-cleanupCtx.Done():
		deadlineErr := cleanupCtx.Err()
		grace := time.NewTimer(cleanupCompletionGrace)
		defer grace.Stop()
		select {
		case outcome := <-done:
			cancel()
			return outcome.result, errors.Join(outcome.err, deadlineErr)
		case <-grace.C:
			cancel()
			return nil, deadlineErr
		}
	}
}

func dataplaneHealthy(ctx context.Context, state *control.State) bool {
	if state == nil {
		return false
	}
	status, err := dataplane.Inspect(ctx, state)
	if err != nil || status == nil || status.MapError != "" || status.ActiveGeneration == 0 {
		return false
	}
	byIndex := make(map[int]dataplane.UnderlayKernelStatus, len(status.Underlays))
	for _, u := range status.Underlays {
		byIndex[u.IfIndex] = u
	}
	for _, desired := range state.Underlays {
		if !desired.Resolved || desired.Role == "parse_only" || desired.Role == "disabled" {
			continue
		}
		actual, ok := byIndex[desired.IfIndex]
		if !ok || actual.Error != "" || !actual.IngressAttached || !actual.EgressAttached {
			return false
		}
	}
	return true
}

func RequestReload(ctx context.Context, runDir string, expectedConfigPath string, timeout time.Duration) (*Status, error) {
	return writeRequestAndWait(ctx, runDir, "reload", expectedConfigPath, timeout)
}

func RequestStop(ctx context.Context, runDir string, expectedConfigPath string, timeout time.Duration) (*Status, error) {
	status, err := writeRequestAndWait(ctx, runDir, "stop", expectedConfigPath, timeout)
	if err != nil {
		return status, err
	}
	if status.State != "stopped" {
		return status, fmt.Errorf("daemon stop request ended in state %q", status.State)
	}
	return status, nil
}

func writeRequestAndWait(ctx context.Context, runDir string, kind string, expectedConfigPath string, timeout time.Duration) (*Status, error) {
	dir := runDirOrDefault(runDir)
	current, statusErr := ReadStatus(dir)
	if statusErr != nil {
		return nil, fmt.Errorf("%w: read daemon status in %s: %v", ErrDaemonNotRunning, dir, statusErr)
	}
	if !IsRunning(current) {
		return current, fmt.Errorf("%w: last recorded pid is %d", ErrDaemonNotRunning, current.PID)
	}
	if current.RequestProtocol != requestProtocolVersion {
		return current, fmt.Errorf(
			"running daemon request protocol is %d, want %d; restart the daemon before %s",
			current.RequestProtocol,
			requestProtocolVersion,
			kind,
		)
	}
	if !validRequestID(current.InstanceID) {
		return current, fmt.Errorf("running daemon has invalid instance id %q; restart the daemon before %s", current.InstanceID, kind)
	}
	if err := ValidateConfigPathForRequest(current, expectedConfigPath, kind); err != nil {
		return current, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create run dir: %w", err)
	}
	expected := ""
	if expectedConfigPath != "" {
		expected = configPath(expectedConfigPath)
	}
	if timeout == 0 {
		timeout = DefaultRequestTimeout
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	request, err := enqueueRequest(waitCtx, dir, kind, expected, current.InstanceID)
	if err != nil {
		return nil, err
	}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-waitCtx.Done():
			if errors.Is(waitCtx.Err(), context.DeadlineExceeded) {
				return nil, fmt.Errorf("daemon %s request %s timed out; it may still complete", kind, request.ID)
			}
			return nil, fmt.Errorf("wait for daemon %s request %s: %w", kind, request.ID, waitCtx.Err())
		case <-ticker.C:
			ack, err := readRequestAck(dir, request.ID)
			if errors.Is(err, os.ErrNotExist) {
				active, activeErr := daemonInstanceIsRunning(dir, current.InstanceID)
				if activeErr != nil {
					return nil, activeErr
				}
				if !active {
					if err := os.Remove(requestPath(dir, request.ID)); err == nil {
						return nil, fmt.Errorf("%w: daemon instance %s exited before accepting request %s", ErrDaemonNotRunning, current.InstanceID, request.ID)
					} else if !errors.Is(err, os.ErrNotExist) {
						return nil, fmt.Errorf("withdraw daemon request %s after owner exit: %w", request.ID, err)
					}
				}
				continue
			}
			if err != nil {
				return nil, fmt.Errorf("read daemon %s request ack %s: %w", kind, request.ID, err)
			}
			if err := validateAckForRequest(ack, request); err != nil {
				return nil, fmt.Errorf("validate daemon %s request ack %s: %w", kind, request.ID, err)
			}
			status := ack.Status
			_, err = consumeAckIfRequestRemoved(dir, request.ID)
			if err != nil {
				return nil, fmt.Errorf("consume daemon request ack %s: %w", request.ID, err)
			}
			if ack.Error != "" {
				if ack.ErrorCode == ackErrorDaemonChanged {
					return &status, fmt.Errorf("%w: %s", ErrDaemonNotRunning, ack.Error)
				}
				return &status, errors.New(ack.Error)
			}
			return &status, nil
		}
	}
}

func daemonInstanceIsRunning(runDir string, instanceID string) (bool, error) {
	status, err := ReadStatus(runDir)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read daemon status while waiting for request: %w", err)
	}
	return status.InstanceID == instanceID && IsRunning(status), nil
}

func ValidateConfigPathForRequest(status *Status, expectedConfigPath string, kind string) error {
	if status == nil || expectedConfigPath == "" {
		return nil
	}
	if filepath.Clean(status.ConfigPath) != filepath.Clean(configPath(expectedConfigPath)) {
		return fmt.Errorf("daemon is running with config %s, refusing %s request for %s", status.ConfigPath, kind, configPath(expectedConfigPath))
	}
	return nil
}

func detachForStop(ctx context.Context, opts Options, runDir string) (*reconcile.Result, error) {
	return reconcile.Stop(ctx, reconcile.Options{
		ConfigPath:     opts.ConfigPath,
		RunDir:         runDir,
		StateDir:       opts.StateDir,
		Offline:        opts.Offline,
		DryRun:         opts.DryRun,
		LifecycleLease: opts.lifecycleLease,
	})
}

func hooksFor(opts Options) runHooks {
	hooks := runHooks{
		acquireLease: acquireLifecycleLease,
		reload:       reconcile.Reload,
		validate:     reconcile.Validate,
		healthy:      dataplaneHealthy,
		stop:         detachForStop,
		writeStatus:  writeStatus,
	}
	if opts.hooks == nil {
		return hooks
	}
	if opts.hooks.lifecycleLeasePath != "" {
		hooks.lifecycleLeasePath = opts.hooks.lifecycleLeasePath
	}
	if opts.hooks.instanceID != "" {
		hooks.instanceID = opts.hooks.instanceID
	}
	if opts.hooks.acquireLease != nil {
		hooks.acquireLease = opts.hooks.acquireLease
	}
	if opts.hooks.reload != nil {
		hooks.reload = opts.hooks.reload
	}
	if opts.hooks.validate != nil {
		hooks.validate = opts.hooks.validate
	}
	if opts.hooks.healthy != nil {
		hooks.healthy = opts.hooks.healthy
	}
	if opts.hooks.stop != nil {
		hooks.stop = opts.hooks.stop
	}
	if opts.hooks.writeStatus != nil {
		hooks.writeStatus = opts.hooks.writeStatus
	}
	return hooks
}

func lifecycleLeasePath(opts Options, runDir string, override string) string {
	if override != "" {
		return override
	}
	if opts.DryRun {
		return filepath.Join(runDir, "daemon.lease")
	}
	return DefaultLifecycleLeasePath
}

func ReadStatus(runDir string) (*Status, error) {
	data, err := readRegularControlFile(filepath.Join(runDirOrDefault(runDir), "status.json"))
	if err != nil {
		return nil, err
	}
	var status Status
	if err := json.Unmarshal(data, &status); err != nil {
		return nil, err
	}
	return &status, nil
}

func IsRunning(status *Status) bool {
	if status == nil || status.PID <= 0 {
		return false
	}
	if runtime.GOOS != "linux" {
		err := syscall.Kill(status.PID, 0)
		return err == nil
	}
	if _, err := os.Stat(filepath.Join("/proc", strconv.Itoa(status.PID))); err == nil {
		return true
	}
	return false
}

func writeStatus(runDir string, status Status) error {
	return writeJSONAtomicMode(runDir, "status.json", status, 0o644)
}

type legacyRequestValue struct {
	Value     string
	ReadError string
}

type legacyRequestStamp struct {
	Reload  legacyRequestValue
	Runtime legacyRequestValue
}

func readLegacyRequestValue(runDir string, name string) legacyRequestValue {
	data, err := readRegularControlFile(filepath.Join(runDir, name))
	if errors.Is(err, os.ErrNotExist) {
		return legacyRequestValue{}
	}
	if err != nil {
		return legacyRequestValue{ReadError: fmt.Sprintf("%s: %v", name, err)}
	}
	return legacyRequestValue{Value: strings.TrimSpace(string(data))}
}

func requestStamp(runDir string) legacyRequestStamp {
	return legacyRequestStamp{
		Reload:  readLegacyRequestValue(runDir, "reload.request"),
		Runtime: readLegacyRequestValue(runDir, "runtime.request"),
	}
}

func legacyRequestWarnings(stamp legacyRequestStamp) []string {
	var warnings []string
	if stamp.Reload.ReadError != "" {
		warnings = append(warnings, stamp.Reload.ReadError)
	} else if stamp.Reload.Value != "" && !strings.HasPrefix(stamp.Reload.Value, "reload:") {
		if strings.HasPrefix(stamp.Reload.Value, "stop:") {
			warnings = append(warnings, "legacy stop request is disabled; use the versioned request protocol")
		} else {
			warnings = append(warnings, "reload.request has an unsupported notification")
		}
	}
	if stamp.Runtime.ReadError != "" {
		warnings = append(warnings, stamp.Runtime.ReadError)
	}
	return warnings
}

func stateFingerprint(result *reconcile.Result) string {
	if result == nil || result.State == nil {
		return ""
	}
	data, err := result.State.JSON()
	if err != nil {
		return ""
	}
	return string(data)
}

func fileHash(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum[:])
}

func pollIntervalFromConfig(path string) time.Duration {
	cfg, err := config.LoadFileLenient(configPath(path))
	if err != nil {
		return 0
	}
	return cfg.Runtime.PollInterval.Duration
}

func runDir(path string) string {
	return runDirOrDefault(path)
}

func runDirOrDefault(path string) string {
	if path != "" {
		return path
	}
	if env := os.Getenv(EnvRunDir); env != "" {
		return env
	}
	return DefaultRunDir
}

func configPath(path string) string {
	if path != "" {
		return path
	}
	return config.DefaultConfigPath
}
