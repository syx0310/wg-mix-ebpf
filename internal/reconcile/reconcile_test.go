package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/attachstate"
	"github.com/syx0310/wg-mix-ebpf/internal/config"
	"github.com/syx0310/wg-mix-ebpf/internal/control"
	"github.com/syx0310/wg-mix-ebpf/internal/dataplane"
	"github.com/syx0310/wg-mix-ebpf/internal/faketcp"
	"github.com/syx0310/wg-mix-ebpf/internal/guard"
	"github.com/syx0310/wg-mix-ebpf/internal/lockfile"
	"github.com/syx0310/wg-mix-ebpf/internal/runtime"
	"github.com/syx0310/wg-mix-ebpf/internal/underlay"
	"github.com/syx0310/wg-mix-ebpf/internal/wgconfig"
)

func TestReloadRejectsOfflineApply(t *testing.T) {
	_, err := Reload(t.Context(), Options{Offline: true})
	if err == nil || !strings.Contains(err.Error(), "requires --dry-run") {
		t.Fatalf("expected offline apply rejection, got %v", err)
	}
}

func TestReloadFakeTCPGatePrecedesGuardAndLoaderInApplyAndDryRun(t *testing.T) {
	for _, dryRun := range []bool{false, true} {
		t.Run(fmt.Sprintf("dry-run=%t", dryRun), func(t *testing.T) {
			cfg := mustFakeTCPReconcileConfig(t)
			guardExec := &recordingGuardExecutor{}
			loader := &recordingDataplaneLoader{}
			mark := uint32(0x10000002)
			lifecycleRoot := t.TempDir()
			ctx := lockfile.WithLifecyclePathsForTest(
				t.Context(),
				filepath.Join(lifecycleRoot, "daemon.lease"),
				filepath.Join(lifecycleRoot, "maintenance.gate"),
			)
			_, err := Reload(ctx, Options{
				ConfigPath: "/ignored/by-test-loader.yaml",
				RunDir:     t.TempDir(),
				DryRun:     dryRun,
				Offline:    dryRun,
				deps: &dependencies{
					loadConfigFile: func(string) (*config.Config, error) { return cfg, nil },
					loadWGConfig: func(string) (*wgconfig.Interface, error) {
						return &wgconfig.Interface{FwMark: &mark, ListenPort: func() *uint16 { value := uint16(31001); return &value }()}, nil
					},
					guardExecutor:   guardExec,
					dataplaneLoader: loader,
				},
			})
			if dryRun {
				if err != nil {
					t.Fatalf("production FakeTCP dry-run rejected: %v", err)
				}
			} else if !errors.Is(err, dataplane.ErrFakeTCPResidentRuntimeRequired) {
				t.Fatalf("expected resident FakeTCP runtime gate, got %v", err)
			}
			if len(guardExec.plans) != 0 || guardExec.cleanupCalls != 0 || loader.applyCalls != 0 {
				t.Fatalf("gate ran after mutation: guard apply=%d cleanup=%d loader=%d", len(guardExec.plans), guardExec.cleanupCalls, loader.applyCalls)
			}
		})
	}
}

func mustFakeTCPReconcileConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Load([]byte(`
version: 1
underlays:
  - name: eth0
    type: netdev
wireguards:
  - name: wg0
    config: /tmp/wg0.conf
    profile: mix-default
    transport:
      mode: faketcp
      faketcp:
        experimental: true
profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
`))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestValidateFakeTCPStartupIsolationRequiresFixedListenPortBeforeMutation(t *testing.T) {
	cfg := mustFakeTCPReconcileConfig(t)
	state := &control.State{WireGuards: []control.WireGuardState{{
		Name: "wg0", TransportMode: "faketcp",
	}}}
	if err := validateFakeTCPStartupIsolation(cfg, state); err == nil ||
		!strings.Contains(err.Error(), "fixed non-zero ListenPort") {
		t.Fatalf("missing fixed FakeTCP listen port error = %v", err)
	}
	state.WireGuards[0].ConfigListenPort = 31001
	if err := validateFakeTCPStartupIsolation(cfg, state); err != nil {
		t.Fatalf("fixed FakeTCP listen port rejected: %v", err)
	}
	state.WireGuards[0].RuntimeStateAvailable = true
	state.WireGuards[0].RuntimeListenPort = 31002
	if err := validateFakeTCPStartupIsolation(cfg, state); err == nil ||
		!strings.Contains(err.Error(), "does not equal configured ListenPort") {
		t.Fatalf("mismatched live FakeTCP listen port error = %v", err)
	}
	state.WireGuards[0].RuntimeListenPort = state.WireGuards[0].ConfigListenPort
	if err := validateFakeTCPStartupIsolation(cfg, state); err != nil {
		t.Fatalf("matching live FakeTCP listen port rejected: %v", err)
	}
	cfg.StartupGuard.Mode = "none"
	if err := validateFakeTCPStartupIsolation(cfg, state); err != nil {
		t.Fatalf("explicit no-nft FakeTCP profile rejected: %v", err)
	}
}

func TestStopDoesNotInvokeOrMisreportGuardCleanupWhenCurrentConfigDisablesGuard(t *testing.T) {
	cfgPath := writeReconcileConfig(t, "[Interface]\nFwMark = 0x10000002\n")
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, []byte("\nstartup_guard:\n  mode: none\n")...)
	if err := os.WriteFile(cfgPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	guardExec := &recordingGuardExecutor{}
	events := make([]string, 0, 2)
	loader := &recordingDataplaneLoader{events: &events}
	configLoads := 0
	preflightCalls := 0
	stateDir := t.TempDir()
	if err := attachstate.Save(stateDir, attachstate.FromControlState(cfgPath, &control.State{
		Underlays: []control.UnderlayState{{
			Name: "wan", IfName: "eth0", IfIndex: 123, Resolved: true, Role: "transform",
		}},
	})); err != nil {
		t.Fatal(err)
	}
	lifecycleRoot := t.TempDir()
	ctx := lockfile.WithLifecyclePathsForTest(
		t.Context(),
		filepath.Join(lifecycleRoot, "daemon.lease"),
		filepath.Join(lifecycleRoot, "maintenance.gate"),
	)
	lease, err := lockfile.AcquireLifecycle(ctx, lockfile.LifecycleOwner{PID: os.Getpid(), Action: "daemon"})
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	result, err := Stop(ctx, Options{
		ConfigPath:     cfgPath,
		RunDir:         t.TempDir(),
		StateDir:       stateDir,
		Offline:        true,
		LifecycleLease: lease,
		deps: &dependencies{
			loadConfigFile: func(path string) (*config.Config, error) {
				configLoads++
				return config.LoadFile(path)
			},
			guardExecutor:   guardExec,
			dataplaneLoader: loader,
			noNFTGuardPreflight: func(context.Context, string) error {
				preflightCalls++
				events = append(events, "preflight")
				return nil
			},
		},
	})
	if err != nil {
		t.Fatalf("no-nft stop failed: %v", err)
	}
	if result.GuardCleaned {
		t.Fatal("disabled guard stop must not claim it removed a guard")
	}
	if guardExec.cleanupCalls != 0 {
		t.Fatalf("disabled guard stop executed cleanup %d times", guardExec.cleanupCalls)
	}
	if preflightCalls != 1 || loader.detachCalls != 1 {
		t.Fatalf("no-nft stop calls: preflight=%d detach=%d", preflightCalls, loader.detachCalls)
	}
	if got, want := fmt.Sprint(events), fmt.Sprint([]string{"preflight", "detach"}); got != want {
		t.Fatalf("no-nft stop order = %s, want %s", got, want)
	}
	if configLoads != 2 {
		t.Fatalf("main config loads = %d, want mode probe plus detach snapshot", configLoads)
	}
}

func TestOneShotMutationsRejectHeldGlobalLifecycleLease(t *testing.T) {
	leasePath := filepath.Join(t.TempDir(), "daemon.lease")
	maintenancePath := filepath.Join(filepath.Dir(leasePath), "maintenance.gate")
	ctx := lockfile.WithLifecyclePathsForTest(
		t.Context(),
		leasePath,
		maintenancePath,
	)
	lease, err := lockfile.AcquireLifecycle(ctx, lockfile.LifecycleOwner{
		PID:        os.Getpid(),
		Action:     "daemon",
		ConfigPath: "/etc/wg-mix-ebpf/config.yaml",
		RunDir:     "/run/real-daemon",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()

	for name, mutate := range map[string]func() error{
		"reload": func() error {
			_, err := Reload(ctx, Options{ConfigPath: "/missing/config.yaml", RunDir: t.TempDir()})
			return err
		},
		"detach": func() error {
			_, err := Detach(ctx, Options{ConfigPath: "/missing/config.yaml", RunDir: t.TempDir()})
			return err
		},
		"stop": func() error {
			_, err := Stop(ctx, Options{ConfigPath: "/missing/config.yaml", RunDir: t.TempDir()})
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := mutate()
			if !errors.Is(err, lockfile.ErrLifecycleLeaseHeld) {
				t.Fatalf("%s error = %v, want held lifecycle lease", name, err)
			}
			if !strings.Contains(err.Error(), "/run/real-daemon") {
				t.Fatalf("%s error lacks owner run-dir: %v", name, err)
			}
		})
	}
}

func TestStopDryRunSucceedsWithoutRuntimeState(t *testing.T) {
	result, err := Stop(t.Context(), Options{
		ConfigPath: "/nonexistent/wg-mix-ebpf.yaml",
		RunDir:     t.TempDir(),
		StateDir:   t.TempDir(),
		DryRun:     true,
	})
	if err == nil {
		t.Fatalf("expected missing config to fail before stop dry-run can clean guard: result=%#v", result)
	}

	cfgPath := writeReconcileConfig(t, "[Interface]\nFwMark = 0x10000002\n")
	result, err = Stop(t.Context(), Options{
		ConfigPath: cfgPath,
		RunDir:     t.TempDir(),
		StateDir:   t.TempDir(),
		DryRun:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Action != "stop" {
		t.Fatalf("action = %q", result.Action)
	}
	if result.GuardCleanup == "" {
		t.Fatal("stop dry-run should include guard cleanup script")
	}
}

func writeReconcileConfig(t *testing.T, wgConfig string) string {
	t.Helper()
	dir := t.TempDir()
	wgPath := filepath.Join(dir, "wg0.conf")
	if err := os.WriteFile(wgPath, []byte(wgConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(`
version: 1
underlays:
  - name: eth0
    type: netdev
wireguards:
  - name: wg0
    config: `+wgPath+`
    profile: mix-default
profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
`), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}

func TestDetachStateReportsNoUnderlays(t *testing.T) {
	cfgPath := writeReconcileConfig(t, "[Interface]\nFwMark = 0x10000002\n")
	_, err := detachState(t.Context(), Options{
		ConfigPath: cfgPath,
		StateDir:   t.TempDir(),
		Offline:    true,
	})
	if !errors.Is(err, errNoDetachUnderlays) {
		t.Fatalf("expected errNoDetachUnderlays, got %v", err)
	}
}

func TestDetachDryRunUsesAttachStateWithoutConfig(t *testing.T) {
	stateDir := t.TempDir()
	if err := attachstate.Save(stateDir, attachstate.FromControlState("/missing/config.yaml", &control.State{
		Underlays: []control.UnderlayState{
			{Name: "wan", IfName: "eth0", IfIndex: 123, Resolved: true, Role: "transform"},
		},
	})); err != nil {
		t.Fatal(err)
	}
	result, err := Detach(t.Context(), Options{
		ConfigPath: filepath.Join(t.TempDir(), "missing.yaml"),
		StateDir:   stateDir,
		DryRun:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.State.Underlays) != 1 || result.State.Underlays[0].IfIndex != 123 {
		t.Fatalf("detach dry-run should use attach-state underlay, got %#v", result.State.Underlays)
	}
}

func TestReloadUsesSingleConfigSnapshotAndExpandsGuardForRuntimeMark(t *testing.T) {
	const (
		configMark  = uint32(0x10000002)
		runtimeMark = uint32(0x10000003)
	)
	cfgPath := writeReconcileConfig(t, "[Interface]\nListenPort = 31001\nFwMark = 0x10000002\n")
	appendConfig(t, cfgPath, "\nruntime:\n  strict_runtime_fwmark: false\n")

	guardExec := &recordingGuardExecutor{}
	loader := &recordingDataplaneLoader{}
	configLoads := 0
	wgConfigLoads := 0
	runtimeProvider := &countingRuntimeProvider{upstream: runtime.StaticProvider{Devices: map[string]*runtime.Device{
		"wg0": {Name: "wg0", ListenPort: 31001, FirewallMark: runtimeMark, Up: true},
	}}}
	lifecycleRoot := t.TempDir()
	ctx := lockfile.WithLifecyclePathsForTest(
		t.Context(),
		filepath.Join(lifecycleRoot, "daemon.lease"),
		filepath.Join(lifecycleRoot, "maintenance.gate"),
	)
	result, err := Reload(ctx, Options{
		ConfigPath: cfgPath,
		StateDir:   t.TempDir(),
		deps: &dependencies{
			loadConfigFile: func(path string) (*config.Config, error) {
				configLoads++
				return config.LoadFile(path)
			},
			loadWGConfig: func(path string) (*wgconfig.Interface, error) {
				wgConfigLoads++
				return wgconfig.ParseFile(path)
			},
			runtimeProvider: runtimeProvider,
			underlayResolver: underlay.StaticResolver{Underlays: map[string]*underlay.Resolved{
				"eth0": {Name: "eth0", IfName: "eth0", IfIndex: 2, LinkType: "ethernet", Role: "transform"},
			}},
			guardExecutor:   guardExec,
			dataplaneLoader: loader,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if configLoads != 1 || wgConfigLoads != 1 {
		t.Fatalf("snapshot loads: main=%d wg=%d, want main=1 wg=1", configLoads, wgConfigLoads)
	}
	if runtimeProvider.calls["wg0"] != 1 {
		t.Fatalf("runtime device loads = %d, want 1", runtimeProvider.calls["wg0"])
	}
	if len(guardExec.plans) != 2 {
		t.Fatalf("guard apply calls = %d, want config plan plus runtime-union plan", len(guardExec.plans))
	}
	if !planHasMark(guardExec.plans[0], configMark) || planHasMark(guardExec.plans[0], runtimeMark) {
		t.Fatalf("initial guard must contain config mark only: %#v", guardExec.plans[0].Rules)
	}
	if !planHasMark(guardExec.plans[1], configMark) || !planHasMark(guardExec.plans[1], runtimeMark) {
		t.Fatalf("expanded guard must contain config/runtime union: %#v", guardExec.plans[1].Rules)
	}
	if loader.applyCalls != 1 {
		t.Fatalf("dataplane apply calls = %d, want 1", loader.applyCalls)
	}
	if guardExec.cleanupCalls != 1 || !result.GuardApplied || !result.GuardCleaned {
		t.Fatalf("unexpected guard completion: cleanup=%d result=%#v", guardExec.cleanupCalls, result)
	}
}

func TestReloadFencesResidentRuntimeAcrossStartupGuard(t *testing.T) {
	const mark = uint32(0x10000002)
	cfgPath := writeReconcileConfig(t, "[Interface]\nListenPort = 31001\nFwMark = 0x10000002\n")
	events := make([]string, 0, 5)
	loader := &guardAwareRecordingDataplaneLoader{events: &events}
	guardExec := &orderedGuardExecutor{events: &events}
	lifecycleRoot := t.TempDir()
	ctx := lockfile.WithLifecyclePathsForTest(
		t.Context(),
		filepath.Join(lifecycleRoot, "daemon.lease"),
		filepath.Join(lifecycleRoot, "maintenance.gate"),
	)
	result, err := Reload(ctx, Options{
		ConfigPath: cfgPath,
		StateDir:   t.TempDir(),
		deps: &dependencies{
			runtimeProvider: runtime.StaticProvider{Devices: map[string]*runtime.Device{
				"wg0": {Name: "wg0", ListenPort: 31001, FirewallMark: mark, Up: true},
			}},
			underlayResolver: underlay.StaticResolver{Underlays: map[string]*underlay.Resolved{
				"eth0": {Name: "eth0", IfName: "eth0", IfIndex: 2, LinkType: "ethernet", Role: "transform"},
			}},
			guardExecutor:   guardExec,
			dataplaneLoader: loader,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"quiesce", "guard-apply", "loader-apply", "guard-cleanup", "resume"}
	if fmt.Sprint(events) != fmt.Sprint(want) {
		t.Fatalf("startup guard/runtime order = %v, want %v", events, want)
	}
	if !result.GuardApplied || !result.GuardCleaned {
		t.Fatalf("guard result = %#v", result)
	}
}

func TestReloadTimingsAreCompleteWithProgressOnAndOff(t *testing.T) {
	for _, test := range []struct {
		name     string
		progress ProgressFunc
	}{
		{name: "progress-off"},
		{name: "progress-on", progress: func(Observation) {}},
	} {
		t.Run(test.name, func(t *testing.T) {
			loader := &pauseAwareDataplaneLoader{pause: openPauseStatus()}
			result, err := reloadUnlocked(
				t.Context(),
				successfulReloadOptions(t, loader, &recordingGuardExecutor{}, test.progress),
			)
			if err != nil {
				t.Fatal(err)
			}
			got := result.Timings
			// The in-memory loader and guard can complete within one monotonic
			// clock tick, so their individual duration may legitimately be zero.
			if got == nil || !got.Completed || got.BarrierHeldNanoseconds <= 0 ||
				got.GuardActiveNanoseconds <= 0 || got.ApplyNanoseconds < 0 ||
				got.CleanupNanoseconds < 0 || got.TotalNanoseconds <= 0 {
				t.Fatalf("incomplete reload timings: %#v", got)
			}
			for label, duration := range map[string]int64{
				"barrier": got.BarrierHeldNanoseconds,
				"guard":   got.GuardActiveNanoseconds,
				"apply":   got.ApplyNanoseconds,
				"cleanup": got.CleanupNanoseconds,
			} {
				if duration > got.TotalNanoseconds {
					t.Fatalf("%s duration %d exceeds total %d", label, duration, got.TotalNanoseconds)
				}
			}

			encoded, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			var document map[string]any
			if err := json.Unmarshal(encoded, &document); err != nil {
				t.Fatal(err)
			}
			wantKeys := map[string]bool{
				"barrier_held_nanoseconds": true,
				"guard_active_nanoseconds": true,
				"apply_nanoseconds":        true,
				"cleanup_nanoseconds":      true,
				"total_nanoseconds":        true,
				"completed":                true,
			}
			if len(document) != len(wantKeys) {
				t.Fatalf("timing JSON keys = %v", document)
			}
			for key, value := range document {
				if !wantKeys[key] {
					t.Fatalf("unexpected timing JSON field %q", key)
				}
				if _, isString := value.(string); isString {
					t.Fatalf("timing JSON field %q exposed string data", key)
				}
			}
		})
	}
}

func TestReloadPassesExactHeldLifecycleLeaseToConstructedLoader(t *testing.T) {
	const mark = uint32(0x10000002)
	cfgPath := writeReconcileConfig(t, "[Interface]\nListenPort = 31001\nFwMark = 0x10000002\n")
	lifecycleRoot := t.TempDir()
	ctx := lockfile.WithLifecyclePathsForTest(
		t.Context(),
		filepath.Join(lifecycleRoot, "daemon.lease"),
		filepath.Join(lifecycleRoot, "maintenance.gate"),
	)
	lease, err := lockfile.AcquireLifecycle(ctx, lockfile.LifecycleOwner{
		PID: os.Getpid(), Action: "daemon", ConfigPath: cfgPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()

	loader := &recordingDataplaneLoader{}
	var constructed dataplane.LoaderOptions
	_, err = Reload(ctx, Options{
		ConfigPath:      cfgPath,
		RunDir:          t.TempDir(),
		StateDir:        t.TempDir(),
		LifecycleLease:  lease,
		ResidentRuntime: true,
		deps: &dependencies{
			runtimeProvider: runtime.StaticProvider{Devices: map[string]*runtime.Device{
				"wg0": {Name: "wg0", ListenPort: 31001, FirewallMark: mark, Up: true},
			}},
			underlayResolver: underlay.StaticResolver{Underlays: map[string]*underlay.Resolved{
				"eth0": {Name: "eth0", IfName: "eth0", IfIndex: 2, LinkType: "ethernet", Role: "transform"},
			}},
			guardExecutor: &recordingGuardExecutor{},
			newDataplaneLoader: func(options dataplane.LoaderOptions) dataplane.Loader {
				constructed = options
				return loader
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if constructed.LifecycleLease != lease {
		t.Fatal("reload constructor did not receive the exact already-held lifecycle lease")
	}
	if !constructed.ResidentRuntime {
		t.Fatal("reload constructor did not receive the resident-runtime capability")
	}
	if loader.applyCalls != 1 {
		t.Fatalf("dataplane apply calls = %d, want 1", loader.applyCalls)
	}
}

func TestReloadKeepsFakeTCPStartupGuardWhenInitialRuntimeHealthFails(t *testing.T) {
	const mark = uint32(0x10000002)
	healthErr := errors.New("initial FakeTCP XDP aggregate identity drifted")
	guardExec := &recordingGuardExecutor{}
	loader := &recordingDataplaneLoader{}
	stateDir := t.TempDir()
	lifecycleRoot := t.TempDir()
	ctx := lockfile.WithLifecyclePathsForTest(
		t.Context(),
		filepath.Join(lifecycleRoot, "daemon.lease"),
		filepath.Join(lifecycleRoot, "maintenance.gate"),
	)

	result, err := Reload(ctx, Options{
		ConfigPath:      "/ignored/by-test-loader.yaml",
		RunDir:          t.TempDir(),
		StateDir:        stateDir,
		ResidentRuntime: true,
		deps: &dependencies{
			loadConfigFile: func(string) (*config.Config, error) {
				return mustFakeTCPReconcileConfig(t), nil
			},
			loadWGConfig: func(string) (*wgconfig.Interface, error) {
				port := uint16(31001)
				value := mark
				return &wgconfig.Interface{FwMark: &value, ListenPort: &port}, nil
			},
			runtimeProvider: runtime.StaticProvider{Devices: map[string]*runtime.Device{
				"wg0": {Name: "wg0", ListenPort: 31001, FirewallMark: mark, Up: true},
			}},
			underlayResolver: underlay.StaticResolver{Underlays: map[string]*underlay.Resolved{
				"eth0": {Name: "eth0", IfName: "eth0", IfIndex: 2, LinkType: "ethernet", Role: "transform"},
			}},
			guardExecutor:   guardExec,
			dataplaneLoader: loader,
			productionFakeTCPStatus: func(context.Context, *control.State) (bool, *dataplane.KernelStatus, error) {
				return true, &dataplane.KernelStatus{Mode: "faketcp"}, healthErr
			},
		},
	})
	if result != nil || !errors.Is(err, healthErr) ||
		!strings.Contains(err.Error(), "verify production FakeTCP runtime health after apply") {
		t.Fatalf("result=%#v error=%v, want complete initial health failure", result, err)
	}
	if loader.applyCalls != 1 || guardExec.cleanupCalls != 0 || len(guardExec.plans) == 0 {
		t.Fatalf(
			"initial health failure boundary: apply=%d guard-plans=%d cleanup=%d",
			loader.applyCalls, len(guardExec.plans), guardExec.cleanupCalls,
		)
	}
	if _, loadErr := attachstate.Load(stateDir); !errors.Is(loadErr, os.ErrNotExist) {
		t.Fatalf("initial health failure published attach-state: %v", loadErr)
	}
}

func TestReloadKeepsRuntimeMarkGuardedOnStrictMismatch(t *testing.T) {
	const (
		configMark0  = uint32(0x10000002)
		runtimeMark0 = uint32(0x10000003)
		configMark1  = uint32(0x10000004)
		runtimeMark1 = uint32(0x10000005)
	)
	cfgPath := writeTwoWireGuardReconcileConfig(
		t,
		"[Interface]\nListenPort = 31001\nFwMark = 0x10000002\n",
		"[Interface]\nListenPort = 31002\nFwMark = 0x10000004\n",
	)
	guardExec := &recordingGuardExecutor{}
	loader := &recordingDataplaneLoader{}
	runtimeProvider := &countingRuntimeProvider{upstream: runtime.StaticProvider{Devices: map[string]*runtime.Device{
		"wg0": {Name: "wg0", ListenPort: 31001, FirewallMark: runtimeMark0, Up: true},
		"wg1": {Name: "wg1", ListenPort: 31002, FirewallMark: runtimeMark1, Up: true},
	}}}
	lifecycleRoot := t.TempDir()
	ctx := lockfile.WithLifecyclePathsForTest(
		t.Context(),
		filepath.Join(lifecycleRoot, "daemon.lease"),
		filepath.Join(lifecycleRoot, "maintenance.gate"),
	)
	_, err := Reload(ctx, Options{
		ConfigPath: cfgPath,
		StateDir:   t.TempDir(),
		deps: &dependencies{
			runtimeProvider: runtimeProvider,
			underlayResolver: underlay.StaticResolver{Underlays: map[string]*underlay.Resolved{
				"eth0": {Name: "eth0", IfName: "eth0", IfIndex: 2, LinkType: "ethernet", Role: "transform"},
			}},
			guardExecutor:   guardExec,
			dataplaneLoader: loader,
		},
	})
	var mismatch *control.FwmarkMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("expected strict fwmark mismatch, got %v", err)
	}
	if len(guardExec.plans) != 2 {
		t.Fatalf("guard apply calls = %d, want initial plus fail-closed expansion", len(guardExec.plans))
	}
	if runtimeProvider.calls["wg0"] != 1 || runtimeProvider.calls["wg1"] != 1 {
		t.Fatalf("runtime snapshot loads = %#v, want one per WireGuard", runtimeProvider.calls)
	}
	for _, mark := range []uint32{configMark0, runtimeMark0, configMark1, runtimeMark1} {
		if !planHasMark(guardExec.plans[1], mark) {
			t.Fatalf("failed reload must leave every configured/observed mark guarded; missing=0x%08x rules=%#v", mark, guardExec.plans[1].Rules)
		}
	}
	if loader.applyCalls != 0 || guardExec.cleanupCalls != 0 {
		t.Fatalf("failed reload should not apply dataplane or clean guard: loader=%d cleanup=%d", loader.applyCalls, guardExec.cleanupCalls)
	}
}

func TestStopUsesAttachStateAndCleansGuardWhenConfigIsMissing(t *testing.T) {
	stateDir := t.TempDir()
	if err := attachstate.Save(stateDir, attachstate.FromControlState("/missing/config.yaml", &control.State{
		Underlays: []control.UnderlayState{
			{Name: "wan", IfName: "eth0", IfIndex: 123, Resolved: true, Role: "transform"},
		},
	})); err != nil {
		t.Fatal(err)
	}
	warning := errors.New("cleanup command exited after absence was proven")
	guardExec := &scriptedGuardExecutor{cleanupOutcome: guard.Outcome{
		Observation: guard.ObservationAbsent,
		Mutated:     true,
		Warning:     warning,
	}}
	loader := &recordingDataplaneLoader{}
	lifecycleRoot := t.TempDir()
	ctx := lockfile.WithLifecyclePathsForTest(
		t.Context(),
		filepath.Join(lifecycleRoot, "daemon.lease"),
		filepath.Join(lifecycleRoot, "maintenance.gate"),
	)
	result, err := Stop(ctx, Options{
		ConfigPath: filepath.Join(t.TempDir(), "missing.yaml"),
		StateDir:   stateDir,
		deps: &dependencies{
			guardExecutor:   guardExec,
			dataplaneLoader: loader,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if loader.detachCalls != 1 || guardExec.cleanupCalls != 1 || !result.GuardCleaned {
		t.Fatalf("stop did not complete saved-state cleanup: detach=%d guard=%d result=%#v", loader.detachCalls, guardExec.cleanupCalls, result)
	}
	if !strings.Contains(result.GuardWarning, warning.Error()) {
		t.Fatalf("stop discarded cleanup warning: %#v", result)
	}
	if _, err := attachstate.Load(stateDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("attach-state should be removed, got %v", err)
	}
}

func TestGuardCleanupPreservesNonFatalOutcomeWarning(t *testing.T) {
	warning := errors.New("cleanup command exited after absence was proven")
	guardExec := &scriptedGuardExecutor{cleanupOutcome: guard.Outcome{
		Observation: guard.ObservationAbsent,
		Mutated:     true,
		Warning:     warning,
	}}
	lifecycleRoot := t.TempDir()
	ctx := lockfile.WithLifecyclePathsForTest(
		t.Context(),
		filepath.Join(lifecycleRoot, "daemon.lease"),
		filepath.Join(lifecycleRoot, "maintenance.gate"),
	)

	result, err := GuardCleanup(ctx, Options{
		RunDir: t.TempDir(),
		deps:   &dependencies{guardExecutor: guardExec},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.GuardCleaned || guardExec.cleanupCalls != 1 ||
		!strings.Contains(result.GuardWarning, warning.Error()) {
		t.Fatalf("guard cleanup result = %#v calls=%d", result, guardExec.cleanupCalls)
	}
}

func TestStatusKeepsFreshGuardAndResidentOwnershipWhenBuildStateFails(t *testing.T) {
	cfgPath := writeReconcileConfig(t, "[Interface]\nListenPort = 31001\nFwMark = 0x10000002\n")
	guardExec := &recordingGuardExecutor{observation: guard.ObservationActive}
	pauseSince := time.Unix(100, 0).UTC()
	loader := &pauseAwareDataplaneLoader{pause: faketcp.StartupGuardPauseStatus{
		Phase:  faketcp.StartupGuardPausePhaseHeld,
		Reason: faketcp.StartupGuardPauseReasonStartupGuard,
		Since:  pauseSince,
	}}
	result, err := Status(t.Context(), Options{
		ConfigPath: cfgPath,
		deps: &dependencies{
			runtimeProvider: runtime.StaticProvider{},
			guardExecutor:   guardExec,
			dataplaneLoader: loader,
			productionFakeTCPStatus: func(context.Context, *control.State) (bool, *dataplane.KernelStatus, error) {
				return true, &dataplane.KernelStatus{
					Mode: "faketcp",
					FakeTCP: &dataplane.FakeTCPRuntimeStatus{
						Generation: 7, Incarnation: "00112233445566778899aabbccddeeff",
						OwnerKind: "process-owned", AttachmentBackend: "tcx", Healthy: true,
						XDP: []dataplane.FakeTCPXDPStatus{{IfIndex: 2, LinkID: 11, ProgramID: 13}},
						TCX: []dataplane.FakeTCPTCXStatus{{IfIndex: 2, Direction: "ingress", LinkID: 17, ProgramID: 19}},
					},
				}, nil
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.State != nil || result.StateError == "" {
		t.Fatalf("failed desired state was not preserved as a diagnostic: %#v", result)
	}
	if result.Observation == nil ||
		result.Observation.StartupGuard.KernelState != StartupGuardKernelActive ||
		result.Observation.StartupGuard.ObservationTime.IsZero() {
		t.Fatalf("guard observation = %#v", result.Observation)
	}
	pause := result.Observation.StartupGuard.RuntimePause
	if pause == nil || pause.Phase != "held" || pause.Reason != "startup_guard" ||
		!pause.Since.Equal(pauseSince) || pause.ObservationTime.IsZero() {
		t.Fatalf("runtime pause = %#v", pause)
	}
	if result.Dataplane == nil || result.Dataplane.FakeTCP == nil ||
		result.Dataplane.FakeTCP.Ownership == nil ||
		len(result.Dataplane.FakeTCP.Ownership.XDP) != 1 ||
		len(result.Dataplane.FakeTCP.Ownership.TC.TCX) != 1 {
		t.Fatalf("resident ownership = %#v", result.Dataplane)
	}
}

func TestStatusProjectsExplicitNoNFTModeAsDisabledWithoutNFTSubprocess(t *testing.T) {
	cfgPath := writeReconcileConfig(t, "[Interface]\nFwMark = 0x10000002\n")
	appendConfig(t, cfgPath, "\nstartup_guard:\n  mode: none\n")
	guardExec := &recordingGuardExecutor{observation: guard.ObservationActive}
	preflightCalls := 0
	result, err := Status(t.Context(), Options{
		ConfigPath: cfgPath,
		Offline:    true,
		deps: &dependencies{
			guardExecutor: guardExec,
			noNFTGuardPreflight: func(context.Context, string) error {
				preflightCalls++
				return nil
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	guardStatus := result.Observation.StartupGuard
	if guardStatus.Mode != "none" || guardStatus.KernelState != StartupGuardKernelDisabled ||
		guardStatus.Error != "" || !strings.Contains(guardStatus.Risk, "does not prevent") {
		t.Fatalf("disabled guard status = %#v", guardStatus)
	}
	if guardExec.observeCalls != 0 || preflightCalls != 1 {
		t.Fatalf(
			"disabled status calls: nft observer=%d netlink preflight=%d",
			guardExec.observeCalls,
			preflightCalls,
		)
	}
}

func TestStatusKeepsNoNFTInventoryFailureUnderDisabledKernelState(t *testing.T) {
	cfgPath := writeReconcileConfig(t, "[Interface]\nFwMark = 0x10000002\n")
	appendConfig(t, cfgPath, "\nstartup_guard:\n  mode: none\n")
	guardExec := &recordingGuardExecutor{observation: guard.ObservationActive}
	inventoryErr := errors.New("inet project guard table still exists")
	preflightCalls := 0
	result, err := Status(t.Context(), Options{
		ConfigPath: cfgPath,
		Offline:    true,
		deps: &dependencies{
			guardExecutor: guardExec,
			noNFTGuardPreflight: func(context.Context, string) error {
				preflightCalls++
				return inventoryErr
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	guardStatus := result.Observation.StartupGuard
	if guardStatus.KernelState != StartupGuardKernelDisabled ||
		!strings.Contains(guardStatus.Error, inventoryErr.Error()) ||
		guardStatus.Risk == "" || preflightCalls != 1 || guardExec.observeCalls != 0 {
		t.Fatalf(
			"disabled conflict status=%#v preflight=%d nft-observe=%d",
			guardStatus,
			preflightCalls,
			guardExec.observeCalls,
		)
	}
}

func TestGuardStatusRedactsOwnershipProofMaterial(t *testing.T) {
	marker := "wg-mix-ebpf-guard-v2:" + strings.Repeat("b", 64)
	status := projectGuardOutcome(
		config.StartupGuardModeNFTTemporaryDrop,
		StartupGuardStatus{},
		guard.Outcome{Observation: guard.ObservationUnknown, Warning: fmt.Errorf("warning %s", marker)},
		fmt.Errorf("failure %s", marker),
	)
	if strings.Contains(status.Warning, marker) || strings.Contains(status.Error, marker) ||
		!strings.Contains(status.Warning, "<redacted>") || !strings.Contains(status.Error, "<redacted>") {
		t.Fatalf("guard status exposed ownership proof: %#v", status)
	}
}

func TestStatusReportsGuardWhenConfigCannotBeLoaded(t *testing.T) {
	configErr := errors.New("config file is unreadable")
	guardExec := &recordingGuardExecutor{observation: guard.ObservationActive}
	result, err := Status(t.Context(), Options{
		ConfigPath: "/ignored/status-config.yaml",
		deps: &dependencies{
			loadConfigFile: func(string) (*config.Config, error) { return nil, configErr },
			loadConfigFileLenient: func(string) (*config.Config, error) {
				return nil, configErr
			},
			guardExecutor:   guardExec,
			dataplaneLoader: &recordingDataplaneLoader{},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.StateError == "" || result.Observation == nil ||
		result.Observation.StartupGuard.Mode != startupGuardModeUnknown ||
		result.Observation.StartupGuard.KernelState != StartupGuardKernelActive ||
		guardExec.observeCalls != 1 {
		t.Fatalf("config-independent guard status = %#v", result)
	}
}

func TestReloadApplyPreflightFailureReleasesOnlyNewBarrier(t *testing.T) {
	applyErr := errors.New("nft preflight failed before mutation")
	loader := &pauseAwareDataplaneLoader{pause: openPauseStatus()}
	guardExec := &scriptedGuardExecutor{
		observeOutcome: guard.Outcome{Observation: guard.ObservationAbsent},
		applyOutcomes:  []guard.Outcome{{Observation: guard.ObservationUnchanged}},
		applyErrors:    []error{applyErr},
	}
	var progress []Observation
	_, err := reloadUnlocked(t.Context(), successfulReloadOptions(t, loader, guardExec, func(status Observation) {
		progress = append(progress, status)
	}))
	if !errors.Is(err, applyErr) {
		t.Fatalf("reload error = %v", err)
	}
	if loader.quiesceCalls != 1 || loader.resumeCalls != 1 || loader.applyCalls != 0 {
		t.Fatalf("barrier rollback: quiesce=%d resume=%d apply=%d", loader.quiesceCalls, loader.resumeCalls, loader.applyCalls)
	}
	if loader.pause.Phase != faketcp.StartupGuardPausePhaseOpen {
		t.Fatalf("barrier remained held: %#v", loader.pause)
	}
	if len(progress) == 0 || progress[len(progress)-1].Reconcile.Phase != ReconcilePhaseFailed ||
		progress[len(progress)-1].StartupGuard.KernelState != StartupGuardKernelAbsent {
		t.Fatalf("final progress = %#v", progress)
	}
}

func TestReloadApplyPreflightFailureDoesNotReleasePriorBarrier(t *testing.T) {
	applyErr := errors.New("nft preflight failed before mutation")
	loader := &pauseAwareDataplaneLoader{pause: faketcp.StartupGuardPauseStatus{
		Phase:  faketcp.StartupGuardPausePhaseHeld,
		Reason: faketcp.StartupGuardPauseReasonStartupGuard,
		Since:  time.Unix(10, 0).UTC(),
	}}
	guardExec := &scriptedGuardExecutor{
		observeOutcome: guard.Outcome{Observation: guard.ObservationActive},
		applyOutcomes:  []guard.Outcome{{Observation: guard.ObservationUnchanged}},
		applyErrors:    []error{applyErr},
	}
	_, err := reloadUnlocked(t.Context(), successfulReloadOptions(t, loader, guardExec, nil))
	if !errors.Is(err, applyErr) {
		t.Fatalf("reload error = %v", err)
	}
	if loader.quiesceCalls != 1 || loader.resumeCalls != 0 ||
		loader.pause.Phase != faketcp.StartupGuardPausePhaseHeld {
		t.Fatalf("prior barrier was released: %#v", loader)
	}
}

func TestReloadFailureAfterActiveGuardKeepsRuntimePaused(t *testing.T) {
	applyErr := errors.New("dataplane apply failed")
	loader := &pauseAwareDataplaneLoader{pause: openPauseStatus(), applyErr: applyErr}
	guardExec := &scriptedGuardExecutor{
		observeOutcome: guard.Outcome{Observation: guard.ObservationAbsent},
		applyOutcomes:  []guard.Outcome{{Observation: guard.ObservationActive, Mutated: true}},
	}
	var progress []Observation
	_, err := reloadUnlocked(t.Context(), successfulReloadOptions(t, loader, guardExec, func(status Observation) {
		progress = append(progress, status)
	}))
	if !errors.Is(err, applyErr) {
		t.Fatalf("reload error = %v", err)
	}
	if loader.resumeCalls != 0 || guardExec.cleanupCalls != 0 ||
		loader.pause.Phase != faketcp.StartupGuardPausePhaseHeld {
		t.Fatalf("fail-closed state: resume=%d cleanup=%d pause=%#v", loader.resumeCalls, guardExec.cleanupCalls, loader.pause)
	}
	last := progress[len(progress)-1]
	if last.Reconcile.Phase != ReconcilePhaseFailed ||
		last.StartupGuard.KernelState != StartupGuardKernelActive ||
		last.StartupGuard.RuntimePause == nil || last.StartupGuard.RuntimePause.Phase != "held" {
		t.Fatalf("failed live projection = %#v", last)
	}
}

func TestReloadCleanupWarningAbsentResumesWithNonCancelledContext(t *testing.T) {
	requestCtx, cancelRequest := context.WithCancel(t.Context())
	warning := errors.New("nft delete returned non-zero after table disappeared")
	loader := &pauseAwareDataplaneLoader{pause: openPauseStatus()}
	guardExec := &scriptedGuardExecutor{
		observeOutcome: guard.Outcome{Observation: guard.ObservationAbsent},
		applyOutcomes:  []guard.Outcome{{Observation: guard.ObservationActive, Mutated: true}},
		cleanupOutcome: guard.Outcome{Observation: guard.ObservationAbsent, Mutated: true, Warning: warning},
		cleanupHook:    cancelRequest,
	}
	result, err := reloadUnlocked(requestCtx, successfulReloadOptions(t, loader, guardExec, nil))
	if err != nil {
		t.Fatalf("cleanup warning should not fail reload: %v", err)
	}
	if !result.GuardCleaned || loader.resumeCalls != 1 || loader.resumeContextErr != nil ||
		loader.pause.Phase != faketcp.StartupGuardPausePhaseOpen {
		t.Fatalf("finalization result=%#v loader=%#v", result, loader)
	}
	if result.Observation == nil || result.Observation.StartupGuard.KernelState != StartupGuardKernelAbsent ||
		!strings.Contains(result.Observation.StartupGuard.Warning, warning.Error()) {
		t.Fatalf("warning projection = %#v", result.Observation)
	}
}

func TestReloadNoNFTUsesDisabledProjectionWithoutGuardOperations(t *testing.T) {
	loader := &pauseAwareDataplaneLoader{pause: openPauseStatus()}
	guardExec := &recordingGuardExecutor{observation: guard.ObservationActive}
	preflightCalls := 0
	opts := successfulReloadOptions(t, loader, guardExec, nil)
	appendConfig(t, opts.ConfigPath, "\nstartup_guard:\n  mode: none\n")
	opts.deps.noNFTGuardPreflight = func(context.Context, string) error {
		preflightCalls++
		return nil
	}
	result, err := reloadUnlocked(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if preflightCalls != 2 || guardExec.observeCalls != 0 || len(guardExec.plans) != 0 ||
		guardExec.cleanupCalls != 0 || loader.quiesceCalls != 0 || loader.resumeCalls != 0 ||
		loader.applyCalls != 1 {
		t.Fatalf(
			"no-nft calls: preflight=%d observe=%d apply-guard=%d cleanup=%d quiesce=%d resume=%d dataplane=%d",
			preflightCalls, guardExec.observeCalls, len(guardExec.plans), guardExec.cleanupCalls,
			loader.quiesceCalls, loader.resumeCalls, loader.applyCalls,
		)
	}
	if result.GuardApplied || result.GuardCleaned || result.Observation == nil ||
		result.Observation.StartupGuard.KernelState != StartupGuardKernelDisabled ||
		result.Observation.StartupGuard.Risk == "" {
		t.Fatalf("no-nft result = %#v", result)
	}
}

func TestReloadNoNFTRejectsMalformedGuardOwnerBeforeDataplaneMutation(t *testing.T) {
	loader := &pauseAwareDataplaneLoader{pause: openPauseStatus()}
	stateDir := noNFTGuardTestStateDir(t)
	ownerPath := filepath.Join(stateDir, guard.OwnerRecordFileName)
	if err := os.WriteFile(ownerPath, []byte("owned\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := successfulReloadOptions(t, loader, nil, nil)
	opts.StateDir = stateDir
	appendConfig(t, opts.ConfigPath, "\nstartup_guard:\n  mode: none\n")
	_, err := reloadUnlocked(t.Context(), opts)
	if err == nil || !strings.Contains(err.Error(), "validate no-nft guard owner record") ||
		!strings.Contains(err.Error(), guard.OwnerRecordFileName) {
		t.Fatalf("owner preflight error = %v", err)
	}
	if loader.applyCalls != 0 || loader.quiesceCalls != 0 {
		t.Fatalf("owner preflight ran after mutation: %#v", loader)
	}
}

func TestNoNFTPreflightCombinesOwnerEvidenceAndKernelInventory(t *testing.T) {
	t.Run("absent", func(t *testing.T) {
		listCalls := 0
		disabled := guard.NewDisabledExecutorWithLister(nfTableListerFunc(
			func(context.Context) ([]guard.NFTable, error) {
				listCalls++
				return []guard.NFTable{{Family: "ip", Name: "unrelated"}}, nil
			},
		))
		if err := preflightNoNFTStartupGuardWith(t.Context(), noNFTGuardTestStateDir(t), disabled); err != nil {
			t.Fatal(err)
		}
		if listCalls != 1 {
			t.Fatalf("kernel inventory calls = %d, want 1", listCalls)
		}
	})

	t.Run("stable-v2-owner-with-empty-inventory", func(t *testing.T) {
		stateDir := validNoNFTGuardOwnerStateDir(t)
		listCalls := 0
		disabled := guard.NewDisabledExecutorWithLister(nfTableListerFunc(
			func(context.Context) ([]guard.NFTable, error) {
				listCalls++
				return []guard.NFTable{{Family: "ip", Name: "unrelated"}}, nil
			},
		))
		if err := preflightNoNFTStartupGuardWith(t.Context(), stateDir, disabled); err != nil {
			t.Fatalf("validated stable owner with empty project inventory rejected: %v", err)
		}
		if listCalls != 1 {
			t.Fatalf("kernel inventory calls = %d, want 1", listCalls)
		}
	})

	t.Run("stable-v2-owner-with-project-table", func(t *testing.T) {
		stateDir := validNoNFTGuardOwnerStateDir(t)
		listCalls := 0
		disabled := guard.NewDisabledExecutorWithLister(nfTableListerFunc(
			func(context.Context) ([]guard.NFTable, error) {
				listCalls++
				return []guard.NFTable{{Family: "inet", Name: guard.TableName}}, nil
			},
		))
		err := preflightNoNFTStartupGuardWith(t.Context(), stateDir, disabled)
		if err == nil || !strings.Contains(err.Error(), guard.TableName) || listCalls != 1 {
			t.Fatalf("stable-owner table preflight: calls=%d err=%v", listCalls, err)
		}
	})

	t.Run("project-table", func(t *testing.T) {
		listCalls := 0
		disabled := guard.NewDisabledExecutorWithLister(nfTableListerFunc(
			func(context.Context) ([]guard.NFTable, error) {
				listCalls++
				return []guard.NFTable{{Family: "inet", Name: guard.TableName}}, nil
			},
		))
		err := preflightNoNFTStartupGuardWith(t.Context(), noNFTGuardTestStateDir(t), disabled)
		if err == nil || !strings.Contains(err.Error(), guard.TableName) || listCalls != 1 {
			t.Fatalf("project-table preflight: calls=%d err=%v", listCalls, err)
		}
	})

	t.Run("malformed-owner-record-precedes-kernel", func(t *testing.T) {
		stateDir := noNFTGuardTestStateDir(t)
		if err := os.WriteFile(
			filepath.Join(stateDir, guard.OwnerRecordFileName),
			[]byte("owned\n"),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
		listCalls := 0
		disabled := guard.NewDisabledExecutorWithLister(nfTableListerFunc(
			func(context.Context) ([]guard.NFTable, error) {
				listCalls++
				return nil, nil
			},
		))
		err := preflightNoNFTStartupGuardWith(t.Context(), stateDir, disabled)
		if err == nil || !strings.Contains(err.Error(), guard.OwnerRecordFileName) || listCalls != 0 {
			t.Fatalf("owner-first preflight: calls=%d err=%v", listCalls, err)
		}
	})
}

func validNoNFTGuardOwnerStateDir(t *testing.T) string {
	t.Helper()
	stateDir := noNFTGuardTestStateDir(t)
	info, err := os.Stat(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("test state directory has no syscall identity")
	}
	installationID := strings.Repeat("ab", 32)
	record := struct {
		Version        int    `json:"version"`
		InstallationID string `json:"installation_id"`
		StateDir       string `json:"state_dir"`
		StateDirDevice uint64 `json:"state_dir_device"`
		StateDirInode  uint64 `json:"state_dir_inode"`
		Table          string `json:"table"`
		Marker         string `json:"marker"`
	}{
		Version:        2,
		InstallationID: installationID,
		StateDir:       stateDir,
		StateDirDevice: uint64(stat.Dev),
		StateDirInode:  uint64(stat.Ino),
		Table:          guard.TableName + "_" + installationID[:32],
		Marker:         "wg-mix-ebpf-guard-v2:" + installationID,
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(filepath.Join(stateDir, guard.OwnerRecordFileName), data, 0o600); err != nil {
		t.Fatal(err)
	}
	return stateDir
}

func noNFTGuardTestStateDir(t *testing.T) string {
	t.Helper()
	stateDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return stateDir
}

func successfulReloadOptions(
	t *testing.T,
	loader dataplane.Loader,
	guardExec guard.Executor,
	progress ProgressFunc,
) Options {
	t.Helper()
	const mark = uint32(0x10000002)
	return Options{
		ConfigPath: writeReconcileConfig(t, "[Interface]\nListenPort = 31001\nFwMark = 0x10000002\n"),
		StateDir:   t.TempDir(),
		Progress:   progress,
		deps: &dependencies{
			runtimeProvider: runtime.StaticProvider{Devices: map[string]*runtime.Device{
				"wg0": {Name: "wg0", ListenPort: 31001, FirewallMark: mark, Up: true},
			}},
			underlayResolver: underlay.StaticResolver{Underlays: map[string]*underlay.Resolved{
				"eth0": {Name: "eth0", IfName: "eth0", IfIndex: 2, LinkType: "ethernet", Role: "transform"},
			}},
			guardExecutor:   guardExec,
			dataplaneLoader: loader,
		},
	}
}

func openPauseStatus() faketcp.StartupGuardPauseStatus {
	return faketcp.StartupGuardPauseStatus{
		Phase:  faketcp.StartupGuardPausePhaseOpen,
		Reason: faketcp.StartupGuardPauseReasonNone,
		Since:  time.Now(),
	}
}

type recordingGuardExecutor struct {
	plans        []guard.NftPlan
	cleanupCalls int
	observeCalls int
	observation  guard.Observation
}

func (e *recordingGuardExecutor) Apply(_ context.Context, plan guard.NftPlan) (guard.Outcome, error) {
	plan.Rules = append([]string(nil), plan.Rules...)
	e.plans = append(e.plans, plan)
	e.observation = guard.ObservationActive
	return guard.Outcome{Observation: guard.ObservationActive, Mutated: true}, nil
}

func (e *recordingGuardExecutor) Cleanup(context.Context) (guard.Outcome, error) {
	e.cleanupCalls++
	e.observation = guard.ObservationAbsent
	return guard.Outcome{Observation: guard.ObservationAbsent, Mutated: true}, nil
}

func (e *recordingGuardExecutor) Observe(context.Context) (guard.Outcome, error) {
	e.observeCalls++
	observation := e.observation
	if observation == guard.ObservationUnknown || observation == guard.ObservationUnchanged {
		observation = guard.ObservationAbsent
	}
	return guard.Outcome{Observation: observation}, nil
}

type scriptedGuardExecutor struct {
	observeOutcome guard.Outcome
	observeErr     error
	applyOutcomes  []guard.Outcome
	applyErrors    []error
	applyCalls     int
	cleanupOutcome guard.Outcome
	cleanupErr     error
	cleanupHook    func()
	cleanupCalls   int
}

func (e *scriptedGuardExecutor) Observe(context.Context) (guard.Outcome, error) {
	return e.observeOutcome, e.observeErr
}

func (e *scriptedGuardExecutor) Apply(context.Context, guard.NftPlan) (guard.Outcome, error) {
	index := e.applyCalls
	e.applyCalls++
	var outcome guard.Outcome
	if index < len(e.applyOutcomes) {
		outcome = e.applyOutcomes[index]
	}
	var err error
	if index < len(e.applyErrors) {
		err = e.applyErrors[index]
	}
	return outcome, err
}

func (e *scriptedGuardExecutor) Cleanup(context.Context) (guard.Outcome, error) {
	e.cleanupCalls++
	if e.cleanupHook != nil {
		e.cleanupHook()
	}
	return e.cleanupOutcome, e.cleanupErr
}

type recordingDataplaneLoader struct {
	applyCalls  int
	detachCalls int
	events      *[]string
}

type orderedGuardExecutor struct {
	events *[]string
}

func (e *orderedGuardExecutor) Apply(context.Context, guard.NftPlan) (guard.Outcome, error) {
	*e.events = append(*e.events, "guard-apply")
	return guard.Outcome{Observation: guard.ObservationActive, Mutated: true}, nil
}

func (e *orderedGuardExecutor) Cleanup(context.Context) (guard.Outcome, error) {
	*e.events = append(*e.events, "guard-cleanup")
	return guard.Outcome{Observation: guard.ObservationAbsent, Mutated: true}, nil
}

func (e *orderedGuardExecutor) Observe(context.Context) (guard.Outcome, error) {
	return guard.Outcome{Observation: guard.ObservationAbsent}, nil
}

type guardAwareRecordingDataplaneLoader struct {
	events *[]string
	token  dataplane.StartupGuardLeaseToken
}

type pauseAwareDataplaneLoader struct {
	pause            faketcp.StartupGuardPauseStatus
	quiesceCalls     int
	resumeCalls      int
	applyCalls       int
	applyErr         error
	resumeContextErr error
	token            dataplane.StartupGuardLeaseToken
}

func (l *pauseAwareDataplaneLoader) StartupGuardPauseStatus() faketcp.StartupGuardPauseStatus {
	return l.pause
}

func (l *pauseAwareDataplaneLoader) QuiesceForStartupGuard(context.Context) (dataplane.StartupGuardLease, error) {
	l.quiesceCalls++
	acquired := l.pause.Phase != faketcp.StartupGuardPausePhaseHeld
	if l.token.IsZero() {
		l.token = dataplane.NewStartupGuardLease().Token
	}
	l.pause = faketcp.StartupGuardPauseStatus{
		Phase:  faketcp.StartupGuardPausePhaseHeld,
		Reason: faketcp.StartupGuardPauseReasonStartupGuard,
		Since:  time.Now(),
	}
	return dataplane.StartupGuardLease{Acquired: acquired, Token: l.token}, nil
}

func (l *pauseAwareDataplaneLoader) ResumeAfterStartupGuard(
	ctx context.Context,
	lease dataplane.StartupGuardLease,
) error {
	l.resumeCalls++
	l.resumeContextErr = ctx.Err()
	if l.resumeContextErr != nil {
		return l.resumeContextErr
	}
	if l.token.IsZero() || lease.Token.IsZero() || l.token != lease.Token {
		return dataplane.ErrStartupGuardLeaseMismatch
	}
	l.pause = faketcp.StartupGuardPauseStatus{
		Phase:  faketcp.StartupGuardPausePhaseOpen,
		Reason: faketcp.StartupGuardPauseReasonNone,
		Since:  time.Now(),
	}
	l.token = dataplane.StartupGuardLeaseToken{}
	return nil
}

func (l *pauseAwareDataplaneLoader) Apply(context.Context, *control.State) error {
	l.applyCalls++
	return l.applyErr
}

func (*pauseAwareDataplaneLoader) Detach(context.Context, *control.State) error {
	return nil
}

func (l *guardAwareRecordingDataplaneLoader) QuiesceForStartupGuard(context.Context) (dataplane.StartupGuardLease, error) {
	*l.events = append(*l.events, "quiesce")
	lease := dataplane.NewStartupGuardLease()
	l.token = lease.Token
	return lease, nil
}

func (l *guardAwareRecordingDataplaneLoader) ResumeAfterStartupGuard(
	_ context.Context,
	lease dataplane.StartupGuardLease,
) error {
	*l.events = append(*l.events, "resume")
	if l.token.IsZero() || lease.Token.IsZero() || l.token != lease.Token {
		return dataplane.ErrStartupGuardLeaseMismatch
	}
	l.token = dataplane.StartupGuardLeaseToken{}
	return nil
}

func (l *guardAwareRecordingDataplaneLoader) Apply(context.Context, *control.State) error {
	*l.events = append(*l.events, "loader-apply")
	return nil
}

func (l *guardAwareRecordingDataplaneLoader) Detach(context.Context, *control.State) error {
	return nil
}

func (l *recordingDataplaneLoader) Apply(context.Context, *control.State) error {
	l.applyCalls++
	if l.events != nil {
		*l.events = append(*l.events, "apply")
	}
	return nil
}

func (l *recordingDataplaneLoader) Detach(context.Context, *control.State) error {
	l.detachCalls++
	if l.events != nil {
		*l.events = append(*l.events, "detach")
	}
	return nil
}

type countingRuntimeProvider struct {
	upstream runtime.Provider
	calls    map[string]int
}

type nfTableListerFunc func(context.Context) ([]guard.NFTable, error)

func (fn nfTableListerFunc) ListTables(ctx context.Context) ([]guard.NFTable, error) {
	return fn(ctx)
}

func (p *countingRuntimeProvider) Device(ctx context.Context, name string) (*runtime.Device, error) {
	if p.calls == nil {
		p.calls = make(map[string]int)
	}
	p.calls[name]++
	return p.upstream.Device(ctx, name)
}

func appendConfig(t *testing.T, path, extra string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, extra...)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeTwoWireGuardReconcileConfig(t *testing.T, wg0Config, wg1Config string) string {
	t.Helper()
	dir := t.TempDir()
	wg0Path := filepath.Join(dir, "wg0.conf")
	wg1Path := filepath.Join(dir, "wg1.conf")
	if err := os.WriteFile(wg0Path, []byte(wg0Config), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wg1Path, []byte(wg1Config), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.yaml")
	data := fmt.Sprintf(`
version: 1
underlays:
  - name: eth0
    type: netdev
wireguards:
  - name: wg0
    config: %s
    profile: mix-default
  - name: wg1
    config: %s
    profile: mix-default
profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
`, wg0Path, wg1Path)
	if err := os.WriteFile(cfgPath, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}

func planHasMark(plan guard.NftPlan, mark uint32) bool {
	needle := fmt.Sprintf("meta mark 0x%08x", mark)
	for _, rule := range plan.Rules {
		if strings.Contains(rule, needle) {
			return true
		}
	}
	return false
}
