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
	"github.com/syx0310/wg-mix-ebpf/internal/reconcile"
)

const (
	DefaultRunDir = "/run/wg-mix-ebpf"
	EnvRunDir     = "WG_MIX_EBPF_RUN_DIR"
)

type Options struct {
	ConfigPath   string
	RunDir       string
	StateDir     string
	PollInterval time.Duration
	Once         bool
	Offline      bool
	DryRun       bool
}

type Status struct {
	PID           int               `json:"pid"`
	ConfigPath    string            `json:"config_path"`
	State         string            `json:"state"`
	LastReason    string            `json:"last_reason,omitempty"`
	LastSuccess   time.Time         `json:"last_success,omitempty"`
	LastErrorTime time.Time         `json:"last_error_time,omitempty"`
	LastError     string            `json:"last_error,omitempty"`
	LastResult    *reconcile.Result `json:"last_result,omitempty"`
	NeedReload    bool              `json:"need_reload,omitempty"`
}

func Run(ctx context.Context, opts Options) error {
	ctx, stopSignals := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()

	runDir := runDir(opts.RunDir)
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return fmt.Errorf("create run dir: %w", err)
	}
	status := Status{
		PID:        os.Getpid(),
		ConfigPath: configPath(opts.ConfigPath),
		State:      "starting",
	}
	if err := writeStatus(runDir, status); err != nil {
		return err
	}

	interval := opts.PollInterval
	if interval == 0 {
		interval = pollIntervalFromConfig(opts.ConfigPath)
	}
	if interval == 0 {
		interval = 5 * time.Second
	}

	lastRequest := requestStamp(runDir)
	lastFingerprint := ""
	lastConfigHash := ""
	runOnce := func(reason string) {
		currentConfigHash := fileHash(configPath(opts.ConfigPath))
		if (reason == "poll" || reason == "runtime-event") && lastConfigHash != "" && currentConfigHash != "" && currentConfigHash != lastConfigHash {
			status.PID = os.Getpid()
			status.ConfigPath = configPath(opts.ConfigPath)
			status.State = "config_changed"
			status.NeedReload = true
			status.LastReason = reason
			status.LastError = "config file changed; run wg-mix-ebpf reload or systemctl reload wg-mix-ebpf to apply"
			status.LastErrorTime = time.Now()
			_ = writeStatus(runDir, status)
			return
		}
		if reason == "poll" && lastFingerprint != "" {
			result, err := reconcile.Validate(ctx, reconcile.Options{ConfigPath: opts.ConfigPath, RunDir: runDir, StateDir: opts.StateDir, Offline: opts.Offline})
			if err == nil {
				fp := stateFingerprint(result)
				if fp == lastFingerprint {
					if !opts.Offline && !opts.DryRun && !dataplaneHealthy(ctx, result.State) {
						goto forceReload
					}
					status.PID = os.Getpid()
					status.ConfigPath = configPath(opts.ConfigPath)
					status.State = "active"
					status.LastReason = "poll-noop"
					status.LastError = ""
					status.NeedReload = false
					status.LastResult = result
					_ = writeStatus(runDir, status)
					return
				}
			}
		}
	forceReload:
		result, err := reconcile.Reload(ctx, reconcile.Options{ConfigPath: opts.ConfigPath, RunDir: runDir, StateDir: opts.StateDir, Offline: opts.Offline, DryRun: opts.DryRun})
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
		_ = writeStatus(runDir, status)
	}

	runOnce("startup")
	if opts.Once {
		if status.LastError != "" {
			return errors.New(status.LastError)
		}
		return nil
	}

	ticker := time.NewTicker(interval)
	requestTicker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	defer requestTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			status.LastReason = "signal"
			if !opts.DryRun {
				if result, err := detachForStop(context.Background(), opts, runDir); err != nil {
					status.State = "degraded"
					status.LastError = err.Error()
					status.LastErrorTime = time.Now()
				} else {
					status.State = "stopped"
					status.LastError = ""
					status.LastSuccess = time.Now()
					status.LastResult = result
				}
			} else {
				status.State = "stopped"
			}
			_ = writeStatus(runDir, status)
			return nil
		case <-requestTicker.C:
			stamp := requestStamp(runDir)
			if stamp != lastRequest {
				lastRequest = stamp
				if strings.HasPrefix(stamp, "stop:") {
					status.LastReason = "stop-request"
					if result, err := detachForStop(context.Background(), opts, runDir); err != nil {
						status.State = "degraded"
						status.LastError = err.Error()
						status.LastErrorTime = time.Now()
						_ = writeStatus(runDir, status)
						return err
					} else {
						status.State = "stopped"
						status.LastError = ""
						status.LastSuccess = time.Now()
						status.LastResult = result
						_ = writeStatus(runDir, status)
						return nil
					}
				}
				if strings.HasPrefix(stamp, "reload:") {
					runOnce("reload-request")
				} else {
					runOnce("runtime-event")
				}
			}
		case <-ticker.C:
			runOnce("poll")
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
	before, _ := ReadStatus(dir)
	if err := ValidateConfigPathForRequest(before, expectedConfigPath, kind); err != nil {
		return before, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create run dir: %w", err)
	}
	requestPath := filepath.Join(dir, "reload.request")
	if err := os.WriteFile(requestPath, []byte(kind+":"+strconv.FormatInt(time.Now().UnixNano(), 10)+"\n"), 0o644); err != nil {
		return nil, fmt.Errorf("write reload request: %w", err)
	}
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			return nil, fmt.Errorf("daemon reload request timed out")
		case <-ticker.C:
			status, err := ReadStatus(dir)
			if err != nil {
				continue
			}
			if before == nil || status.LastSuccess.After(before.LastSuccess) || status.LastErrorTime.After(before.LastErrorTime) {
				if status.LastError != "" {
					return status, errors.New(status.LastError)
				}
				return status, nil
			}
		}
	}
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
	return reconcile.Stop(ctx, reconcile.Options{ConfigPath: opts.ConfigPath, RunDir: runDir, StateDir: opts.StateDir, Offline: opts.Offline, DryRun: opts.DryRun})
}

func ReadStatus(runDir string) (*Status, error) {
	data, err := os.ReadFile(filepath.Join(runDirOrDefault(runDir), "status.json"))
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
	data, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(runDir, "status.json.tmp")
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(runDir, "status.json"))
}

func requestStamp(runDir string) string {
	data, err := os.ReadFile(filepath.Join(runDir, "reload.request"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
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
