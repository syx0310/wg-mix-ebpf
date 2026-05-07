package control

import (
	"context"
	"testing"

	"github.com/siyixuan/wg-mix-ebpf/internal/config"
	"github.com/siyixuan/wg-mix-ebpf/internal/runtime"
	"github.com/siyixuan/wg-mix-ebpf/internal/underlay"
	"github.com/siyixuan/wg-mix-ebpf/internal/wgconfig"
)

func testConfig(t *testing.T) *config.Config {
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
profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
`))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestBuildStateOfflineParsesConfigFwMark(t *testing.T) {
	cfg := testConfig(t)
	state, err := BuildState(context.Background(), cfg, runtime.StaticProvider{}, underlay.StaticResolver{}, func(string) (*wgconfig.Interface, error) {
		mark := uint32(0x10000002)
		return &wgconfig.Interface{FwMark: &mark}, nil
	}, BuildOptions{Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(state.WireGuards) != 1 {
		t.Fatalf("wireguards = %d", len(state.WireGuards))
	}
	if state.WireGuards[0].ConfigFwMark != 0x10000002 {
		t.Fatalf("config fwmark = 0x%x", state.WireGuards[0].ConfigFwMark)
	}
	if len(state.EgressRules) != 0 {
		t.Fatalf("offline egress rules = %d", len(state.EgressRules))
	}
}

func TestBuildStateRejectsMissingFwMark(t *testing.T) {
	cfg := testConfig(t)
	_, err := BuildState(context.Background(), cfg, runtime.StaticProvider{}, underlay.StaticResolver{}, func(string) (*wgconfig.Interface, error) {
		return &wgconfig.Interface{}, nil
	}, BuildOptions{Offline: true})
	if err == nil {
		t.Fatal("expected missing fwmark error")
	}
}

func TestBuildStateRuntimeRules(t *testing.T) {
	cfg := testConfig(t)
	mark := uint32(0x10000002)
	state, err := BuildState(
		context.Background(),
		cfg,
		runtime.StaticProvider{Devices: map[string]*runtime.Device{
			"wg0": {
				Name:         "wg0",
				ListenPort:   31001,
				FirewallMark: mark,
				Up:           true,
			},
		}},
		underlay.StaticResolver{Underlays: map[string]*underlay.Resolved{
			"eth0": {
				Name:     "eth0",
				Type:     "netdev",
				IfName:   "eth0",
				IfIndex:  2,
				LinkType: "ethernet",
				Role:     "transform",
			},
		}},
		func(string) (*wgconfig.Interface, error) {
			return &wgconfig.Interface{FwMark: &mark}, nil
		},
		BuildOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.ManagedFwmarks) != 1 {
		t.Fatalf("managed fwmark rules = %d", len(state.ManagedFwmarks))
	}
	if len(state.EgressRules) != 2 {
		t.Fatalf("egress rules = %d", len(state.EgressRules))
	}
	if len(state.IngressListeners) != 2 {
		t.Fatalf("ingress listeners = %d", len(state.IngressListeners))
	}
	if state.EgressRules[0].SourcePort != 31001 {
		t.Fatalf("egress source port = %d", state.EgressRules[0].SourcePort)
	}
}

func TestBuildStateRuntimeFwMarkMismatch(t *testing.T) {
	cfg := testConfig(t)
	configMark := uint32(0x10000002)
	runtimeMark := uint32(0x10000003)
	_, err := BuildState(
		context.Background(),
		cfg,
		runtime.StaticProvider{Devices: map[string]*runtime.Device{
			"wg0": {
				Name:         "wg0",
				ListenPort:   31001,
				FirewallMark: runtimeMark,
				Up:           true,
			},
		}},
		underlay.StaticResolver{Underlays: map[string]*underlay.Resolved{
			"eth0": {IfName: "eth0", IfIndex: 2, Role: "transform"},
		}},
		func(string) (*wgconfig.Interface, error) {
			return &wgconfig.Interface{FwMark: &configMark}, nil
		},
		BuildOptions{},
	)
	if err == nil {
		t.Fatal("expected runtime fwmark mismatch")
	}
}
