//go:build linux

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/syx0310/wg-mix-ebpf/internal/config"
)

const fakeTCPKprobeRuntimeMapName = "faketcp_kprobe_runtime_map"

// fakeTCPKprobeRuntimeValue is the frozen shared legacy BPF/module bridge ABI:
// cookie@0, abi_version@8, reserved@12, sizeof 16. It is deliberately private
// so neither status nor desired-key serialization can expose the cookie.
type fakeTCPKprobeRuntimeValue struct {
	Cookie     uint64
	ABIVersion uint32
	Reserved   uint32
}

// FakeTCPChecksumStageFactory binds an immutable checksum selection to the
// collection-lifetime stage seam. The returned factory must run after the
// collection is created and before its first program can become reachable.
// The selection itself remains owned by the outer production runtime.
func FakeTCPChecksumStageFactory(
	selection *FakeTCPChecksumSelection,
) (experimentalChecksumStageFactory, error) {
	if selection == nil {
		return nil, errors.New("build FakeTCP checksum stage factory: selection is nil")
	}
	status := selection.RuntimeStatus()
	if status.Backend != selection.Backend || status.ObjectVariant != selection.ObjectVariant {
		return nil, errors.New("build FakeTCP checksum stage factory: selection identity is inconsistent")
	}
	switch selection.Backend {
	case config.FakeTCPChecksumBackendKfunc:
		if selection.ObjectVariant != FakeTCPObjectVariantModernKfunc {
			return nil, errors.New("build FakeTCP checksum stage factory: kfunc selection has a non-modern object")
		}
		return func(
			ctx context.Context,
			_ *experimentalCollectionOwner,
		) (experimentalChecksumStageOwner, error) {
			if err := selection.Healthy(ctx); err != nil {
				return nil, fmt.Errorf("validate kfunc checksum selection: %w", err)
			}
			return &fakeTCPChecksumSelectionStage{selection: selection}, nil
		}, nil
	case config.FakeTCPChecksumBackendKprobe:
		if selection.ObjectVariant != FakeTCPObjectVariantLegacy515 {
			return nil, errors.New("build FakeTCP checksum stage factory: kprobe selection has a non-legacy object")
		}
		if _, ok := selection.KprobeCookie(); !ok {
			return nil, errors.New("build FakeTCP checksum stage factory: kprobe lease cookie is unavailable")
		}
		return func(
			ctx context.Context,
			collection *experimentalCollectionOwner,
		) (experimentalChecksumStageOwner, error) {
			return seedFakeTCPKprobeChecksumStage(ctx, collection, selection)
		}, nil
	default:
		return nil, fmt.Errorf(
			"build FakeTCP checksum stage factory: backend %q is not resolved",
			selection.Backend,
		)
	}
}

// fakeTCPChecksumSelectionStage gives the generic runtime a uniform checksum
// health owner for kfunc without taking ownership of the selection.
type fakeTCPChecksumSelectionStage struct {
	mu        sync.Mutex
	selection *FakeTCPChecksumSelection
	closed    bool
}

func (stage *fakeTCPChecksumSelectionStage) Healthy(ctx context.Context) error {
	if stage == nil {
		return errors.New("FakeTCP checksum stage is nil")
	}
	stage.mu.Lock()
	defer stage.mu.Unlock()
	if stage.closed || stage.selection == nil {
		return errors.New("FakeTCP checksum stage is closed")
	}
	return stage.selection.Healthy(ctx)
}

func (stage *fakeTCPChecksumSelectionStage) Close() error {
	if stage == nil {
		return nil
	}
	stage.mu.Lock()
	defer stage.mu.Unlock()
	stage.closed = true
	stage.selection = nil
	return nil
}

type fakeTCPKprobeChecksumStage struct {
	mu        sync.Mutex
	selection *FakeTCPChecksumSelection
	runtime   fakeTCPPolicyMap
	want      fakeTCPKprobeRuntimeValue
	closed    bool
}

func seedFakeTCPKprobeChecksumStage(
	ctx context.Context,
	collection *experimentalCollectionOwner,
	selection *FakeTCPChecksumSelection,
) (*fakeTCPKprobeChecksumStage, error) {
	if ctx == nil {
		return nil, errors.New("seed FakeTCP kprobe checksum stage: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, errors.New("seed FakeTCP kprobe checksum stage: collection is nil")
	}
	if selection == nil || selection.Backend != config.FakeTCPChecksumBackendKprobe ||
		selection.ObjectVariant != FakeTCPObjectVariantLegacy515 {
		return nil, errors.New("seed FakeTCP kprobe checksum stage: selection is not legacy kprobe")
	}
	if err := selection.Healthy(ctx); err != nil {
		return nil, fmt.Errorf("seed FakeTCP kprobe checksum stage: lease is unhealthy: %w", err)
	}
	cookie, ok := selection.KprobeCookie()
	if !ok {
		return nil, errors.New("seed FakeTCP kprobe checksum stage: lease cookie is unavailable")
	}
	runtimeMap, err := collection.mapResource(fakeTCPKprobeRuntimeMapName)
	if err != nil {
		return nil, fmt.Errorf("seed FakeTCP kprobe checksum stage: %w", err)
	}
	want := fakeTCPKprobeRuntimeValue{
		Cookie:     cookie,
		ABIVersion: fakeTCPKprobeBridgeABIVersion,
	}
	const key = uint32(0)
	if err := runtimeMap.Update(key, want, ebpf.UpdateAny); err != nil {
		return nil, fmt.Errorf("seed FakeTCP kprobe runtime map: %w", err)
	}
	stage := &fakeTCPKprobeChecksumStage{
		selection: selection,
		runtime:   runtimeMap,
		want:      want,
	}
	if err := stage.Healthy(ctx); err != nil {
		return stage, fmt.Errorf("verify FakeTCP kprobe checksum stage: %w", err)
	}
	return stage, nil
}

func (stage *fakeTCPKprobeChecksumStage) Healthy(ctx context.Context) error {
	if stage == nil {
		return errors.New("FakeTCP kprobe checksum stage is nil")
	}
	if ctx == nil {
		return errors.New("inspect FakeTCP kprobe checksum stage: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	stage.mu.Lock()
	defer stage.mu.Unlock()
	if stage.closed || stage.selection == nil || stage.runtime == nil {
		return errors.New("FakeTCP kprobe checksum stage is closed")
	}
	if err := stage.selection.Healthy(ctx); err != nil {
		return fmt.Errorf("inspect FakeTCP kprobe module lease: %w", err)
	}
	cookie, ok := stage.selection.KprobeCookie()
	if !ok || cookie != stage.want.Cookie {
		return errors.New("inspect FakeTCP kprobe runtime map: lease identity changed")
	}
	var actual fakeTCPKprobeRuntimeValue
	const key = uint32(0)
	if err := stage.runtime.Lookup(key, &actual); err != nil {
		return fmt.Errorf("inspect FakeTCP kprobe runtime map: %w", err)
	}
	if actual != stage.want {
		return errors.New("inspect FakeTCP kprobe runtime map: value differs from retained lease identity")
	}
	return ctx.Err()
}

func (stage *fakeTCPKprobeChecksumStage) Close() error {
	if stage == nil {
		return nil
	}
	stage.mu.Lock()
	defer stage.mu.Unlock()
	stage.closed = true
	stage.selection = nil
	stage.runtime = nil
	stage.want = fakeTCPKprobeRuntimeValue{}
	return nil
}
