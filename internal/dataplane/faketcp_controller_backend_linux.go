//go:build linux

package dataplane

import (
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	"github.com/syx0310/wg-mix-ebpf/internal/control"
	"github.com/syx0310/wg-mix-ebpf/internal/faketcp"
)

const (
	liveFakeTCPEventPollInterval = 100 * time.Millisecond
	liveFakeTCPControllerTick    = 100 * time.Millisecond
	liveFakeTCPRawSendTimeout    = time.Second
)

// newLiveExperimentalFakeTCPSlowPathFactory freezes the exact state and pin
// scope selected by production planning into a single-use factory. The
// returned closure has one backend only: ringbuf events plus a raw IPv4
// sender. It cannot construct a second consumer after any valid build attempt.
func newLiveExperimentalFakeTCPSlowPathFactory(
	state *control.State,
	snapshot *fakeTCPPolicySnapshot,
	scope fakeTCPProductionScopeIdentity,
) (experimentalSlowPathFactory, error) {
	factory, err := newLiveFakeTCPControllerRuntimeFactory(state, snapshot, scope)
	if err != nil {
		return nil, err
	}
	return func(
		engine *faketcp.Engine,
		events *ebpf.Map,
		stats *ebpf.Map,
	) (experimentalSlowPath, error) {
		return factory.NewLinuxRuntime(engine, events, stats)
	}, nil
}

// newLiveExperimentalFakeTCPRoutedSlowPathFactory owns the same single-use
// controller capability as the single-Engine factory, but connects its one
// ring reader and one raw backend to an immutable multi-WireGuard router.
func newLiveExperimentalFakeTCPRoutedSlowPathFactory(
	state *control.State,
	snapshot *fakeTCPPolicySnapshot,
	scope fakeTCPProductionScopeIdentity,
) (experimentalRoutedSlowPathFactory, error) {
	factory, err := newLiveFakeTCPControllerRuntimeFactory(state, snapshot, scope)
	if err != nil {
		return nil, err
	}
	return func(
		router *faketcp.EngineRouter,
		events *ebpf.Map,
		stats *ebpf.Map,
	) (experimentalSlowPath, error) {
		return factory.NewLinuxRoutedRuntime(router, events, stats)
	}, nil
}

func newLiveFakeTCPControllerRuntimeFactory(
	state *control.State,
	snapshot *fakeTCPPolicySnapshot,
	scope fakeTCPProductionScopeIdentity,
) (faketcp.ControllerRuntimeFactory, error) {
	if state == nil {
		return faketcp.ControllerRuntimeFactory{}, errors.New("build live FakeTCP slow-path factory: state is nil")
	}
	if err := validateFakeTCPPolicySnapshot(snapshot); err != nil {
		return faketcp.ControllerRuntimeFactory{}, fmt.Errorf("build live FakeTCP slow-path factory snapshot: %w", err)
	}
	if err := scope.validate(); err != nil {
		return faketcp.ControllerRuntimeFactory{}, fmt.Errorf("build live FakeTCP slow-path factory scope: %w", err)
	}
	marks, err := buildFakeTCPControllerMarks(state, snapshot)
	if err != nil {
		return faketcp.ControllerRuntimeFactory{}, err
	}
	factory, err := faketcp.NewControllerRuntimeFactory(
		faketcp.ControllerRuntimeFactoryOptions{
			Scope: faketcp.ControllerRuntimeScope{
				Generation: snapshot.Generation,
				PinPath:    scope.pinPath,
			},
			ControlMarks:   marks,
			PollInterval:   liveFakeTCPEventPollInterval,
			TickInterval:   liveFakeTCPControllerTick,
			RawSendTimeout: liveFakeTCPRawSendTimeout,
		},
	)
	if err != nil {
		return faketcp.ControllerRuntimeFactory{}, fmt.Errorf("build live FakeTCP controller runtime factory: %w", err)
	}
	return factory, nil
}
