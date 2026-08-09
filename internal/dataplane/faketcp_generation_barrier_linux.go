//go:build linux

package dataplane

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/syx0310/wg-mix-ebpf/internal/abi"
	"github.com/syx0310/wg-mix-ebpf/internal/faketcp"
)

const (
	fakeTCPGenerationGateMapName        = "faketcp_gen_gt"
	fakeTCPGenerationWakeMapName        = "faketcp_gen_wk"
	fakeTCPGenerationControlProgramName = "wg_faketcp_generation_control"
	fakeTCPGenerationWakeWait           = 5 * time.Second
)

type liveFakeTCPGenerationBarrier struct {
	mu sync.Mutex

	generation uint64
	identity   faketcp.RuntimeIdentity
	gate       *ebpf.Map
	wake       *ebpf.Map
	control    *ebpf.Program
}

var _ fakeTCPPolicyGenerationIsolationBackend = (*liveFakeTCPGenerationBarrier)(nil)

func newLiveFakeTCPGenerationBarrier(generation uint64) (*liveFakeTCPGenerationBarrier, error) {
	if generation == 0 {
		return nil, errors.New("create FakeTCP generation barrier: generation is zero")
	}
	return &liveFakeTCPGenerationBarrier{generation: generation}, nil
}

func (barrier *liveFakeTCPGenerationBarrier) BindCollection(
	ctx context.Context,
	owner *experimentalCollectionOwner,
	identity faketcp.RuntimeIdentity,
) error {
	if ctx == nil || barrier == nil || owner == nil {
		return errors.New("bind FakeTCP generation barrier: incomplete owner")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if identity.Generation != barrier.generation ||
		identity.Incarnation == (faketcp.RuntimeIncarnation{}) {
		return errors.New("bind FakeTCP generation barrier: runtime identity mismatch")
	}

	barrier.mu.Lock()
	defer barrier.mu.Unlock()
	if barrier.gate != nil {
		return errors.New("bind FakeTCP generation barrier: already bound")
	}
	gate, err := liveFakeTCPGenerationMap(owner, fakeTCPGenerationGateMapName)
	if err != nil {
		return err
	}
	wake, err := liveFakeTCPGenerationMap(owner, fakeTCPGenerationWakeMapName)
	if err != nil {
		return err
	}
	runtimeIdentity, err := liveFakeTCPGenerationMap(owner, fakeTCPRuntimeIDMapName)
	if err != nil {
		return err
	}
	resource, err := owner.programResource(fakeTCPGenerationControlProgramName)
	if err != nil {
		return err
	}
	control := resource.kernelProgram()
	if control == nil {
		return errors.New("bind FakeTCP generation barrier: control program is not live")
	}
	if err := validateLiveFakeTCPGenerationControl(gate, wake, runtimeIdentity, control); err != nil {
		return err
	}
	var initial abi.FakeTCPGenerationGateValue
	if err := gate.Lookup(uint32(0), &initial); err != nil {
		return fmt.Errorf("bind FakeTCP generation barrier: read fresh gate: %w", err)
	}
	if initial != (abi.FakeTCPGenerationGateValue{}) {
		return fmt.Errorf("bind FakeTCP generation barrier: fresh gate is %#v", initial)
	}
	barrier.identity, barrier.gate, barrier.wake, barrier.control = identity, gate, wake, control
	return nil
}

func liveFakeTCPGenerationMap(
	owner *experimentalCollectionOwner,
	name string,
) (*ebpf.Map, error) {
	resource, err := owner.mapResource(name)
	if err != nil {
		return nil, err
	}
	bpfMap, ok := linuxMapFromExperimentalResource(resource)
	if !ok {
		return nil, fmt.Errorf("bind FakeTCP generation barrier: map %s is not live", name)
	}
	return bpfMap, nil
}

func validateLiveFakeTCPGenerationControl(
	gate, wake, runtimeIdentity *ebpf.Map,
	control *ebpf.Program,
) error {
	expected := make(map[ebpf.MapID]struct{}, 3)
	for _, bpfMap := range []*ebpf.Map{gate, wake, runtimeIdentity} {
		info, err := bpfMap.Info()
		if err != nil {
			return fmt.Errorf("bind FakeTCP generation barrier: inspect map: %w", err)
		}
		id, ok := info.ID()
		if !ok || id == 0 {
			return errors.New("bind FakeTCP generation barrier: map ID is unavailable")
		}
		expected[id] = struct{}{}
	}
	info, err := control.Info()
	if err != nil {
		return fmt.Errorf("bind FakeTCP generation barrier: inspect control program: %w", err)
	}
	ids, ok := info.MapIDs()
	if info.Type != ebpf.SchedCLS || !ok || len(ids) != 3 || len(expected) != 3 {
		return errors.New("bind FakeTCP generation barrier: control program identity is invalid")
	}
	for _, id := range ids {
		if _, ok := expected[id]; !ok {
			return errors.New("bind FakeTCP generation barrier: control program map binding differs")
		}
		delete(expected, id)
	}
	if len(expected) != 0 {
		return errors.New("bind FakeTCP generation barrier: control program map binding is incomplete")
	}
	return nil
}

func (barrier *liveFakeTCPGenerationBarrier) AssertInactive(
	ctx context.Context,
	generation uint64,
) error {
	if err := barrier.lock(ctx, generation); err != nil {
		return fmt.Errorf("prove FakeTCP generation inactive: %w", err)
	}
	defer barrier.mu.Unlock()
	return barrier.expectLocked("ASSERT_CLOSED", abi.FakeTCPGenerationControlAssertClosed,
		abi.FakeTCPGenerationResultIdle)
}

func (barrier *liveFakeTCPGenerationBarrier) Activate(
	ctx context.Context,
	generation uint64,
) error {
	if err := barrier.lock(ctx, generation); err != nil {
		return fmt.Errorf("activate FakeTCP generation barrier: %w", err)
	}
	defer barrier.mu.Unlock()
	return barrier.expectLocked("OPEN", abi.FakeTCPGenerationControlOpen,
		abi.FakeTCPGenerationResultOpen)
}

func (barrier *liveFakeTCPGenerationBarrier) Quiesce(
	ctx context.Context,
	generation uint64,
) error {
	if err := barrier.lock(ctx, generation); err != nil {
		return fmt.Errorf("quiesce FakeTCP generation barrier: %w", err)
	}
	defer barrier.mu.Unlock()
	result, err := barrier.runLocked(abi.FakeTCPGenerationControlClose)
	if err != nil {
		return fmt.Errorf("quiesce FakeTCP generation barrier: CLOSE: %w", err)
	}
	if result == abi.FakeTCPGenerationResultIdle {
		return barrier.verifyIdleLocked()
	}
	if result != abi.FakeTCPGenerationResultWait {
		return fmt.Errorf("FakeTCP generation CLOSE returned state %d", result)
	}
	wake, err := barrier.readWakeLocked(ctx)
	if err != nil {
		return fmt.Errorf("quiesce FakeTCP generation barrier: wait for last exit: %w", err)
	}
	if wake.Generation != barrier.identity.Generation ||
		wake.Incarnation != [16]byte(barrier.identity.Incarnation) ||
		wake.State != abi.FakeTCPGenerationStateSealed|abi.FakeTCPGenerationStateWakeArmed {
		return errors.New("quiesce FakeTCP generation barrier: wake identity or state mismatch")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := barrier.expectLocked("confirm CLOSE", abi.FakeTCPGenerationControlClose,
		abi.FakeTCPGenerationResultIdle); err != nil {
		return err
	}
	return barrier.verifyIdleLocked()
}

func (barrier *liveFakeTCPGenerationBarrier) lock(ctx context.Context, generation uint64) error {
	if ctx == nil || barrier == nil || generation == 0 || generation != barrier.generation {
		return errors.New("generation identity mismatch")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	barrier.mu.Lock()
	if err := ctx.Err(); err != nil {
		barrier.mu.Unlock()
		return err
	}
	if barrier.gate == nil || barrier.wake == nil || barrier.control == nil {
		barrier.mu.Unlock()
		return errors.New("exact fresh collection is not bound")
	}
	return nil
}

func (barrier *liveFakeTCPGenerationBarrier) expectLocked(
	label string,
	operation, expected uint32,
) error {
	result, err := barrier.runLocked(operation)
	if err != nil {
		return fmt.Errorf("FakeTCP generation %s: %w", label, err)
	}
	if result != expected {
		return fmt.Errorf("FakeTCP generation %s returned state %d", label, result)
	}
	return nil
}

func (barrier *liveFakeTCPGenerationBarrier) runLocked(operation uint32) (uint32, error) {
	request := make([]byte, 32)
	binary.NativeEndian.PutUint64(request[0:8], barrier.identity.Generation)
	copy(request[8:24], barrier.identity.Incarnation[:])
	binary.NativeEndian.PutUint32(request[24:28], operation)
	return barrier.control.Run(&ebpf.RunOptions{Data: request})
}

func (barrier *liveFakeTCPGenerationBarrier) verifyIdleLocked() error {
	var gate abi.FakeTCPGenerationGateValue
	if err := barrier.gate.Lookup(uint32(0), &gate); err != nil {
		return fmt.Errorf("quiesce FakeTCP generation barrier: reread gate: %w", err)
	}
	if gate.Generation != barrier.identity.Generation ||
		gate.State != abi.FakeTCPGenerationStateSealed {
		return fmt.Errorf("quiesce FakeTCP generation barrier: gate is %#v, want sealed idle", gate)
	}
	return nil
}

func (barrier *liveFakeTCPGenerationBarrier) readWakeLocked(
	ctx context.Context,
) (abi.FakeTCPGenerationWake, error) {
	reader, err := ringbuf.NewReader(barrier.wake)
	if err != nil {
		return abi.FakeTCPGenerationWake{}, err
	}
	deadline := time.Now().Add(fakeTCPGenerationWakeWait)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	reader.SetDeadline(deadline)
	cancelDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = reader.Close()
		close(cancelDone)
	})
	record, readErr := reader.Read()
	if stop() {
		close(cancelDone)
	}
	<-cancelDone
	closeErr := reader.Close()
	if err := ctx.Err(); err != nil {
		return abi.FakeTCPGenerationWake{}, errors.Join(err, closeErr)
	}
	if readErr != nil || closeErr != nil {
		return abi.FakeTCPGenerationWake{}, errors.Join(readErr, closeErr)
	}
	if len(record.RawSample) != 32 {
		return abi.FakeTCPGenerationWake{}, fmt.Errorf("generation wake has %d bytes", len(record.RawSample))
	}
	return abi.FakeTCPGenerationWake{
		Generation:  binary.NativeEndian.Uint64(record.RawSample[0:8]),
		Incarnation: [16]byte(record.RawSample[8:24]),
		State:       binary.NativeEndian.Uint64(record.RawSample[24:32]),
	}, nil
}
