package reconcile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/syx0310/wg-mix-ebpf/internal/attachstate"
	"github.com/syx0310/wg-mix-ebpf/internal/control"
)

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
