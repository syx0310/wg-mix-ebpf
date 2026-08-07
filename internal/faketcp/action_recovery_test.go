package faketcp

import (
	"context"
	"errors"
	"math"
	"slices"
	"testing"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

func TestMemoryActionCheckpointStoreCopiesAndComparesRevision(t *testing.T) {
	store := NewMemoryActionCheckpointStore()
	checkpoint := recoveryCheckpoint(t, 1, ActionCheckpointPrepared, 0, []ActionStep{
		recoveryPacketStep(t, testFlow(31001), 11),
	})
	created, err := store.CreateActionCheckpoint(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint.Steps[0].Packet.Data[0] ^= 0xff
	loaded, found, err := store.LoadActionCheckpoint()
	if err != nil || !found {
		t.Fatalf("LoadActionCheckpoint found=%t err=%v", found, err)
	}
	if loaded.Steps[0].Packet.Data[0] == checkpoint.Steps[0].Packet.Data[0] {
		t.Fatal("store retained caller packet backing array")
	}
	loaded.Steps[0].Packet.Data[0] ^= 0xff
	reloaded, _, err := store.LoadActionCheckpoint()
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Steps[0].Packet.Data[0] == loaded.Steps[0].Packet.Data[0] {
		t.Fatal("load exposed stored packet backing array")
	}

	stale := created
	stale.Revision++
	if _, err := store.UpdateActionCheckpoint(created.Revision, stale); !errors.Is(err, ErrActionCheckpointCorrupt) {
		t.Fatalf("mismatched update revision error = %v", err)
	}
	updated := created
	updated.NextStep = 1
	updated, err = store.UpdateActionCheckpoint(created.Revision, updated)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateActionCheckpoint(created.Revision, created); !errors.Is(err, ErrActionCheckpointConflict) {
		t.Fatalf("stale update error = %v", err)
	}
	if err := store.DeleteActionCheckpoint(created.Revision); !errors.Is(err, ErrActionCheckpointConflict) {
		t.Fatalf("stale delete error = %v", err)
	}
	if err := store.DeleteActionCheckpoint(updated.Revision); err != nil {
		t.Fatal(err)
	}
}

func TestMemoryActionCheckpointStoreFailsClosedOnRevisionExhaustion(t *testing.T) {
	store := NewMemoryActionCheckpointStore()
	store.nextRevision = math.MaxUint64
	checkpoint := recoveryCheckpoint(t, 1, ActionCheckpointPrepared, 0, []ActionStep{
		recoveryControlStep(testFlow(31001), FlagSYN),
	})
	created, err := store.CreateActionCheckpoint(checkpoint)
	if err != nil || created.Revision != math.MaxUint64 {
		t.Fatalf("create revision=%d err=%v", created.Revision, err)
	}
	if _, err := store.UpdateActionCheckpoint(created.Revision, created); !errors.Is(err, ErrActionCheckpointRevisionExhausted) {
		t.Fatalf("revision exhaustion error = %v", err)
	}
	loaded, found, err := store.LoadActionCheckpoint()
	if err != nil || !found || loaded.Revision != created.Revision {
		t.Fatalf("checkpoint mutated on exhaustion: found=%t checkpoint=%#v err=%v", found, loaded, err)
	}
}

func TestActionRecoveryExecutesAndClearsCheckpointInOrder(t *testing.T) {
	backend := &fakeControllerBackend{}
	store := NewMemoryActionCheckpointStore()
	recovery, err := NewActionRecovery(backend, store)
	if err != nil {
		t.Fatal(err)
	}
	flow := testFlow(31001)
	actions := []Action{
		{Kind: ActionSendControl, Flow: flow, WGID: 7, Control: ControlPacket{Flags: FlagSYN}, Reason: "start"},
		{Kind: ActionReleasePending, Flow: flow, Packets: []PendingPacket{recoveryPacket(t, flow, 11)}},
		{Kind: ActionSendControl, Flow: flow, WGID: 7, Control: ControlPacket{Flags: FlagACK}, Reason: "finish"},
	}
	if err := recovery.Execute(context.Background(), actions); err != nil {
		t.Fatal(err)
	}
	if got, want := backend.operations, []string{"send:0x2", "reinject", "send:0x10"}; !slices.Equal(got, want) {
		t.Fatalf("operations=%v want=%v", got, want)
	}
	if pending, err := recovery.Pending(); err != nil || pending {
		t.Fatalf("pending=%t err=%v", pending, err)
	}
}

func TestActionRecoveryReplaysAmbiguousControl(t *testing.T) {
	wantErr := errors.New("ambiguous control send")
	backend := &fakeControllerBackend{sendErr: wantErr}
	store := NewMemoryActionCheckpointStore()
	recovery, err := NewActionRecovery(backend, store)
	if err != nil {
		t.Fatal(err)
	}
	flow := testFlow(31001)
	actions := []Action{
		{Kind: ActionSendControl, Flow: flow, WGID: 7, Control: ControlPacket{Flags: FlagSYN}, Reason: "start"},
		{Kind: ActionReleasePending, Flow: flow, Packets: []PendingPacket{recoveryPacket(t, flow, 11)}},
	}
	if err := recovery.Execute(context.Background(), actions); !errors.Is(err, ErrActionRecoveryRequired) || !errors.Is(err, wantErr) {
		t.Fatalf("Execute error = %v", err)
	}
	backend.sendErr = nil
	recovery, err = NewActionRecovery(backend, store)
	if err != nil {
		t.Fatal(err)
	}
	report, err := recovery.Recover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.ReplayedControls != 1 || report.SkippedAmbiguousReinjections != 0 || report.CompletedSteps != 2 {
		t.Fatalf("recovery report=%#v", report)
	}
	if len(backend.sent) != 2 || len(backend.packets) != 1 {
		t.Fatalf("sent=%d reinjected=%d", len(backend.sent), len(backend.packets))
	}
}

func TestActionRecoverySkipsAmbiguousReinjectionAndContinues(t *testing.T) {
	wantErr := errors.New("ambiguous reinjection")
	backend := &fakeControllerBackend{reinjectErr: wantErr}
	store := NewMemoryActionCheckpointStore()
	recovery, err := NewActionRecovery(backend, store)
	if err != nil {
		t.Fatal(err)
	}
	flow := testFlow(31001)
	actions := []Action{
		{Kind: ActionSendControl, Flow: flow, WGID: 7, Control: ControlPacket{Flags: FlagSYN}, Reason: "start"},
		{Kind: ActionReleasePending, Flow: flow, Packets: []PendingPacket{recoveryPacket(t, flow, 11)}},
		{Kind: ActionSendControl, Flow: flow, WGID: 7, Control: ControlPacket{Flags: FlagACK}, Reason: "finish"},
	}
	if err := recovery.Execute(context.Background(), actions); !errors.Is(err, ErrActionRecoveryRequired) || !errors.Is(err, wantErr) {
		t.Fatalf("Execute error = %v", err)
	}
	backend.reinjectErr = nil
	recovery, err = NewActionRecovery(backend, store)
	if err != nil {
		t.Fatal(err)
	}
	report, err := recovery.Recover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.ReplayedControls != 0 || report.SkippedAmbiguousReinjections != 1 || report.CompletedSteps != 1 {
		t.Fatalf("recovery report=%#v", report)
	}
	if len(backend.packets) != 1 || len(backend.sent) != 2 {
		t.Fatalf("sent=%d reinjection attempts=%d", len(backend.sent), len(backend.packets))
	}
}

func TestActionRecoveryFlattensReleaseAndSkipsOnlyAttemptedPacket(t *testing.T) {
	wantErr := errors.New("first reinjection failed")
	backend := &fakeControllerBackend{reinjectErr: wantErr}
	store := NewMemoryActionCheckpointStore()
	recovery, err := NewActionRecovery(backend, store)
	if err != nil {
		t.Fatal(err)
	}
	flow := testFlow(31001)
	actions := []Action{{
		Kind: ActionReleasePending,
		Flow: flow,
		Packets: []PendingPacket{
			recoveryPacket(t, flow, 11),
			recoveryPacket(t, flow, 12),
		},
	}}
	if err := recovery.Execute(context.Background(), actions); !errors.Is(err, wantErr) {
		t.Fatalf("Execute error = %v", err)
	}
	backend.reinjectErr = nil
	recovery, err = NewActionRecovery(backend, store)
	if err != nil {
		t.Fatal(err)
	}
	report, err := recovery.Recover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.SkippedAmbiguousReinjections != 1 || report.CompletedSteps != 1 {
		t.Fatalf("recovery report=%#v", report)
	}
	if len(backend.packets) != 2 || backend.packets[0].packet.CaptureNanos != 11 || backend.packets[1].packet.CaptureNanos != 12 {
		t.Fatalf("reinjection attempts=%#v", backend.packets)
	}
}

type cancelOnCreateCheckpointStore struct {
	*MemoryActionCheckpointStore
	cancel context.CancelFunc
}

func (store *cancelOnCreateCheckpointStore) CreateActionCheckpoint(checkpoint ActionCheckpoint) (ActionCheckpoint, error) {
	created, err := store.MemoryActionCheckpointStore.CreateActionCheckpoint(checkpoint)
	store.cancel()
	return created, err
}

func TestActionRecoveryRetainsPreparedCheckpointOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	store := &cancelOnCreateCheckpointStore{MemoryActionCheckpointStore: NewMemoryActionCheckpointStore(), cancel: cancel}
	backend := &fakeControllerBackend{}
	recovery, err := NewActionRecovery(backend, store)
	if err != nil {
		t.Fatal(err)
	}
	flow := testFlow(31001)
	err = recovery.Execute(ctx, []Action{{
		Kind: ActionSendControl, Flow: flow, WGID: 7,
		Control: ControlPacket{Flags: FlagSYN}, Reason: "cancelled",
	}})
	if !errors.Is(err, ErrActionRecoveryRequired) || !errors.Is(err, context.Canceled) {
		t.Fatalf("Execute error = %v", err)
	}
	if len(backend.sent) != 0 {
		t.Fatal("backend was called after checkpoint-time cancellation")
	}
	recovery, err = NewActionRecovery(backend, store)
	if err != nil {
		t.Fatal(err)
	}
	report, err := recovery.Recover(context.Background())
	if err != nil || report.CompletedSteps != 1 || len(backend.sent) != 1 {
		t.Fatalf("report=%#v sent=%d err=%v", report, len(backend.sent), err)
	}
}

type staticCheckpointStore struct {
	checkpoint ActionCheckpoint
	found      bool
}

func (store *staticCheckpointStore) LoadActionCheckpoint() (ActionCheckpoint, bool, error) {
	return cloneActionCheckpoint(store.checkpoint), store.found, nil
}
func (*staticCheckpointStore) CreateActionCheckpoint(ActionCheckpoint) (ActionCheckpoint, error) {
	return ActionCheckpoint{}, errors.New("unexpected create")
}
func (*staticCheckpointStore) UpdateActionCheckpoint(uint64, ActionCheckpoint) (ActionCheckpoint, error) {
	return ActionCheckpoint{}, errors.New("unexpected update")
}
func (*staticCheckpointStore) DeleteActionCheckpoint(uint64) error {
	return errors.New("unexpected delete")
}

func TestNewActionRecoveryRejectsCorruptStoredCheckpoint(t *testing.T) {
	checkpoint := recoveryCheckpoint(t, 1, ActionCheckpointPrepared, 0, []ActionStep{
		recoveryControlStep(testFlow(31001), FlagSYN),
	})
	checkpoint.Revision = 0
	if recovery, err := NewActionRecovery(&fakeControllerBackend{}, &staticCheckpointStore{
		checkpoint: checkpoint, found: true,
	}); err == nil || recovery != nil || !errors.Is(err, ErrActionCheckpointCorrupt) {
		t.Fatalf("recovery=%#v err=%v", recovery, err)
	}
}

func TestActionRecoveryCompletesMaxOperationThenExhausts(t *testing.T) {
	store := NewMemoryActionCheckpointStore()
	checkpoint := recoveryCheckpoint(t, math.MaxUint64, ActionCheckpointPrepared, 0, []ActionStep{
		recoveryControlStep(testFlow(31001), FlagSYN),
	})
	if _, err := store.CreateActionCheckpoint(checkpoint); err != nil {
		t.Fatal(err)
	}
	backend := &fakeControllerBackend{}
	recovery, err := NewActionRecovery(backend, store)
	if err != nil {
		t.Fatal(err)
	}
	if report, err := recovery.Recover(context.Background()); err != nil || report.CompletedSteps != 1 {
		t.Fatalf("report=%#v err=%v", report, err)
	}
	if err := recovery.Execute(context.Background(), []Action{{
		Kind: ActionSendControl, Flow: testFlow(31002), WGID: 7,
		Control: ControlPacket{Flags: FlagSYN}, Reason: "exhausted",
	}}); err == nil {
		t.Fatal("exhausted operation counter was reused")
	}
}

func TestRecoverableControllerGatesAfterControlFailureUntilRecover(t *testing.T) {
	engine, _ := testEngine(t, nil)
	wantErr := errors.New("ambiguous initial SYN")
	backend := &fakeControllerBackend{sendErr: wantErr}
	store := NewMemoryActionCheckpointStore()
	controller, err := NewRecoverableController(engine, backend, store)
	if err != nil {
		t.Fatal(err)
	}
	flow := testFlow(31001)
	packet := testIPv4UDPPacket(t, flow, []byte{1, 2})
	sample := testEventSample(abi.FakeTCPEvent{
		Key: flow, TimestampNanos: 11, PayloadLength: 2, FWMark: 3, WGID: 7,
		PacketLength: uint16(len(packet)), Type: abi.FakeTCPEventNeedHandshake,
	}, packet, false)
	if _, err := controller.HandleSample(context.Background(), sample); !errors.Is(err, ErrActionRecoveryRequired) ||
		!errors.Is(err, wantErr) || errors.Is(err, ErrControllerFailed) {
		t.Fatalf("HandleSample error = %v", err)
	}
	if len(backend.sent) != 1 {
		t.Fatalf("control attempts=%d", len(backend.sent))
	}
	if _, err := controller.Tick(context.Background()); !errors.Is(err, ErrActionRecoveryRequired) {
		t.Fatalf("Tick while recovery required error = %v", err)
	}
	if len(backend.sent) != 1 {
		t.Fatal("gated operation touched backend")
	}
	backend.sendErr = nil
	report, err := controller.Recover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.ReplayedControls != 1 || report.CompletedSteps != 1 || len(backend.sent) != 2 {
		t.Fatalf("report=%#v control attempts=%d", report, len(backend.sent))
	}
	if _, err := controller.Tick(context.Background()); err != nil {
		t.Fatalf("Tick after recovery error = %v", err)
	}
}

func TestRecoverableControllerNeverRetriesAmbiguousReleasedPacket(t *testing.T) {
	engine, _ := testEngine(t, nil)
	wantErr := errors.New("ambiguous first-packet send")
	backend := &fakeControllerBackend{reinjectErr: wantErr}
	controller, err := NewRecoverableController(engine, backend, NewMemoryActionCheckpointStore())
	if err != nil {
		t.Fatal(err)
	}
	flow := testFlow(31001)
	packet := testIPv4UDPPacket(t, flow, []byte{1, 2})
	first := testEventSample(abi.FakeTCPEvent{
		Key: flow, TimestampNanos: 11, PayloadLength: 2, FWMark: 3, WGID: 7,
		PacketLength: uint16(len(packet)), Type: abi.FakeTCPEventNeedHandshake,
	}, packet, false)
	if _, err := controller.HandleSample(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	synACK := testEventSample(abi.FakeTCPEvent{
		Key: flow, Sequence: 9000, Acknowledgement: 1001, WGID: 7,
		Type: abi.FakeTCPEventSYNACK, TCPFlags: FlagSYN | FlagACK,
	}, nil, false)
	if _, err := controller.HandleSample(context.Background(), synACK); !errors.Is(err, ErrActionRecoveryRequired) || !errors.Is(err, wantErr) {
		t.Fatalf("SYNACK error = %v", err)
	}
	if len(backend.packets) != 1 {
		t.Fatalf("reinjection attempts=%d", len(backend.packets))
	}
	backend.reinjectErr = nil
	report, err := controller.Recover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.SkippedAmbiguousReinjections != 1 || len(backend.packets) != 1 {
		t.Fatalf("report=%#v reinjection attempts=%d", report, len(backend.packets))
	}
	if _, err := controller.HandleSample(context.Background(), synACK); err != nil {
		t.Fatal(err)
	}
	if len(backend.packets) != 1 {
		t.Fatalf("duplicate handshake retried packet %d times", len(backend.packets))
	}
}

func TestRecoverableControllerStartsFencedByRetainedCheckpoint(t *testing.T) {
	flow := testFlow(31001)
	store := NewMemoryActionCheckpointStore()
	checkpoint := recoveryCheckpoint(t, 9, ActionCheckpointPrepared, 0, []ActionStep{
		recoveryControlStep(flow, FlagSYN),
	})
	if _, err := store.CreateActionCheckpoint(checkpoint); err != nil {
		t.Fatal(err)
	}
	engine, _ := testEngine(t, nil)
	backend := &fakeControllerBackend{}
	controller, err := NewRecoverableController(engine, backend, store)
	if err != nil {
		t.Fatal(err)
	}
	packet := testIPv4UDPPacket(t, flow, []byte{1})
	sample := testEventSample(abi.FakeTCPEvent{
		Key: flow, TimestampNanos: 11, PayloadLength: 1, WGID: 7,
		PacketLength: uint16(len(packet)), Type: abi.FakeTCPEventNeedHandshake,
	}, packet, false)
	if _, err := controller.HandleSample(context.Background(), sample); !errors.Is(err, ErrActionRecoveryRequired) {
		t.Fatalf("HandleSample before recovery error = %v", err)
	}
	if _, found, err := engine.Snapshot(flow); err != nil || found {
		t.Fatalf("engine touched before recovery: found=%t err=%v", found, err)
	}
	if report, err := controller.Recover(context.Background()); err != nil || report.CompletedSteps != 1 {
		t.Fatalf("report=%#v err=%v", report, err)
	}
	if len(backend.sent) != 1 {
		t.Fatalf("recovered controls=%d", len(backend.sent))
	}
}

func TestRecoverableControllerClosePreservesPendingCheckpoint(t *testing.T) {
	flow := testFlow(31001)
	store := NewMemoryActionCheckpointStore()
	if _, err := store.CreateActionCheckpoint(recoveryCheckpoint(t, 9, ActionCheckpointAttempting, 0, []ActionStep{
		recoveryPacketStep(t, flow, 11),
	})); err != nil {
		t.Fatal(err)
	}
	engine, _ := testEngine(t, nil)
	backend := &fakeControllerBackend{}
	controller, err := NewRecoverableController(engine, backend, store)
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.Close(); err != nil {
		t.Fatal(err)
	}
	if backend.closeCalls != 1 {
		t.Fatalf("backend close calls=%d", backend.closeCalls)
	}
	if _, found, err := store.LoadActionCheckpoint(); err != nil || !found {
		t.Fatalf("pending checkpoint after Close found=%t err=%v", found, err)
	}
	if _, err := controller.Recover(context.Background()); !errors.Is(err, ErrControllerClosed) {
		t.Fatalf("Recover after Close error = %v", err)
	}
}

func TestControllerRecoverRequiresConfiguredStore(t *testing.T) {
	engine, _ := testEngine(t, nil)
	controller, err := NewController(engine, &fakeControllerBackend{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Recover(context.Background()); !errors.Is(err, ErrControllerRecoveryUnavailable) {
		t.Fatalf("legacy Recover error = %v", err)
	}
	var typedNil *MemoryActionCheckpointStore
	if controller, err := NewRecoverableController(engine, &fakeControllerBackend{}, typedNil); err == nil || controller != nil {
		t.Fatalf("typed-nil checkpoint store accepted: controller=%#v err=%v", controller, err)
	}
}

func recoveryCheckpoint(
	t *testing.T,
	operation uint64,
	phase ActionCheckpointPhase,
	next int,
	steps []ActionStep,
) ActionCheckpoint {
	t.Helper()
	checkpoint := ActionCheckpoint{Operation: operation, Phase: phase, NextStep: next, Steps: steps}
	if err := validateActionCheckpoint(checkpoint); err != nil {
		t.Fatal(err)
	}
	return checkpoint
}

func recoveryControlStep(flow abi.FakeTCPSessionKey, flags uint8) ActionStep {
	return ActionStep{
		Kind: ActionStepSendControl, Flow: flow, WGID: 7,
		Control: ControlPacket{Flags: flags}, Reason: "test",
	}
}

func recoveryPacketStep(t *testing.T, flow abi.FakeTCPSessionKey, capture uint64) ActionStep {
	t.Helper()
	return ActionStep{Kind: ActionStepReinject, Flow: flow, Packet: recoveryPacket(t, flow, capture)}
}

func recoveryPacket(t *testing.T, flow abi.FakeTCPSessionKey, capture uint64) PendingPacket {
	t.Helper()
	return testPendingPacket(t, flow, capture)
}
