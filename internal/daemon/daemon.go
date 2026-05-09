package daemon

import (
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
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/config"
	"github.com/syx0310/wg-mix-ebpf/internal/reconcile"
)

const (
	DefaultRunDir = "/run/wg-mix-ebpf"
	EnvRunDir     = "WG_MIX_EBPF_RUN_DIR"
)

type Options struct {
	ConfigPath   string
	RunDir       string
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
}

func Run(ctx context.Context, opts Options) error {
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
	runOnce := func(reason string) {
		if reason == "poll" && lastFingerprint != "" {
			result, err := reconcile.Validate(ctx, reconcile.Options{ConfigPath: opts.ConfigPath, Offline: opts.Offline})
			if err == nil {
				fp := stateFingerprint(result)
				if fp == lastFingerprint {
					status.PID = os.Getpid()
					status.ConfigPath = configPath(opts.ConfigPath)
					status.State = "active"
					status.LastReason = "poll-noop"
					status.LastError = ""
					status.LastResult = result
					_ = writeStatus(runDir, status)
					return
				}
			}
		}
		result, err := reconcile.Reload(ctx, reconcile.Options{ConfigPath: opts.ConfigPath, Offline: opts.Offline, DryRun: opts.DryRun})
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
			status.LastSuccess = time.Now()
			status.LastResult = result
			lastFingerprint = stateFingerprint(result)
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
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			status.State = "stopped"
			_ = writeStatus(runDir, status)
			return ctx.Err()
		case <-ticker.C:
			stamp := requestStamp(runDir)
			if stamp != lastRequest {
				lastRequest = stamp
				runOnce("reload-request")
				continue
			}
			runOnce("poll")
		}
	}
}

func RequestReload(ctx context.Context, runDir string, timeout time.Duration) (*Status, error) {
	dir := runDirOrDefault(runDir)
	before, _ := ReadStatus(dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create run dir: %w", err)
	}
	requestPath := filepath.Join(dir, "reload.request")
	if err := os.WriteFile(requestPath, []byte(strconv.FormatInt(time.Now().UnixNano(), 10)+"\n"), 0o644); err != nil {
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
