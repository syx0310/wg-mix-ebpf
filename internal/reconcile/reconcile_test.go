package reconcile

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	if err := validateFakeTCPStartupIsolation(cfg, state); err == nil ||
		!strings.Contains(err.Error(), "nft-temporary-drop") {
		t.Fatalf("disabled FakeTCP guard error = %v", err)
	}
}

func TestStopCleansFixedGuardTableWhenCurrentConfigDisablesGuard(t *testing.T) {
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
	configLoads := 0
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
		StateDir:       t.TempDir(),
		Offline:        true,
		LifecycleLease: lease,
		deps: &dependencies{
			loadConfigFile: func(path string) (*config.Config, error) {
				configLoads++
				return config.LoadFile(path)
			},
			guardExecutor: guardExec,
		},
	})
	if err != nil {
		t.Fatalf("stop should clean the fixed guard table: %v", err)
	}
	if !result.GuardCleaned {
		t.Fatal("guard should only be reported clean after cleanup succeeds")
	}
	if guardExec.cleanupCalls != 1 {
		t.Fatalf("guard cleanup calls = %d, want 1", guardExec.cleanupCalls)
	}
	if configLoads != 1 {
		t.Fatalf("main config loads = %d, want 1", configLoads)
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
	guardExec := &recordingGuardExecutor{}
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
	if _, err := attachstate.Load(stateDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("attach-state should be removed, got %v", err)
	}
}

type recordingGuardExecutor struct {
	plans        []guard.NftPlan
	cleanupCalls int
}

func (e *recordingGuardExecutor) Apply(_ context.Context, plan guard.NftPlan) error {
	plan.Rules = append([]string(nil), plan.Rules...)
	e.plans = append(e.plans, plan)
	return nil
}

func (e *recordingGuardExecutor) Cleanup(context.Context) error {
	e.cleanupCalls++
	return nil
}

type recordingDataplaneLoader struct {
	applyCalls  int
	detachCalls int
}

type orderedGuardExecutor struct {
	events *[]string
}

func (e *orderedGuardExecutor) Apply(context.Context, guard.NftPlan) error {
	*e.events = append(*e.events, "guard-apply")
	return nil
}

func (e *orderedGuardExecutor) Cleanup(context.Context) error {
	*e.events = append(*e.events, "guard-cleanup")
	return nil
}

type guardAwareRecordingDataplaneLoader struct {
	events *[]string
}

func (l *guardAwareRecordingDataplaneLoader) QuiesceForStartupGuard(context.Context) error {
	*l.events = append(*l.events, "quiesce")
	return nil
}

func (l *guardAwareRecordingDataplaneLoader) ResumeAfterStartupGuard(context.Context) error {
	*l.events = append(*l.events, "resume")
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
	return nil
}

func (l *recordingDataplaneLoader) Detach(context.Context, *control.State) error {
	l.detachCalls++
	return nil
}

type countingRuntimeProvider struct {
	upstream runtime.Provider
	calls    map[string]int
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
