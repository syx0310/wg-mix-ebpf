package faketcp

import (
	"context"
	"errors"
	"math"
	"reflect"
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

func TestMemoryActionCheckpointTransitionPreservesImmutableCheckpoint(t *testing.T) {
	store := NewMemoryActionCheckpointStore()
	flow := testFlow(31001)
	checkpoint := recoveryCheckpoint(t, 1, ActionCheckpointPrepared, 0, []ActionStep{
		recoveryPacketStep(t, flow, 11),
		recoveryPacketStep(t, flow, 12),
	})
	created, err := store.CreateActionCheckpoint(checkpoint)
	if err != nil {
		t.Fatal(err)
	}

	attemptingRevision, err := store.TransitionActionCheckpoint(
		created.Revision,
		ActionCheckpointAttempting,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	if attemptingRevision == created.Revision {
		t.Fatal("transition did not advance the checkpoint revision")
	}
	if _, err := store.TransitionActionCheckpoint(
		created.Revision,
		ActionCheckpointPrepared,
		1,
	); !errors.Is(err, ErrActionCheckpointConflict) {
		t.Fatalf("stale transition error = %v", err)
	}

	beforeInvalidRevision := store.nextRevision
	if _, err := store.TransitionActionCheckpoint(
		attemptingRevision,
		ActionCheckpointAttempting,
		len(checkpoint.Steps),
	); !errors.Is(err, ErrActionCheckpointCorrupt) {
		t.Fatalf("invalid transition error = %v", err)
	}
	if store.nextRevision != beforeInvalidRevision {
		t.Fatal("invalid transition consumed a revision")
	}

	loaded, found, err := store.LoadActionCheckpoint()
	if err != nil || !found {
		t.Fatalf("load after transition found=%t err=%v", found, err)
	}
	if loaded.Revision != attemptingRevision || loaded.Phase != ActionCheckpointAttempting || loaded.NextStep != 0 {
		t.Fatalf("transitioned checkpoint = %#v", loaded)
	}
	if loaded.Operation != created.Operation || loaded.Identity != created.Identity ||
		!reflect.DeepEqual(loaded.Steps, created.Steps) {
		t.Fatal("transition changed immutable checkpoint fields")
	}
	loaded.Steps[0].Packet.Data[0] ^= 0xff
	reloaded, _, err := store.LoadActionCheckpoint()
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Steps[0].Packet.Data[0] == loaded.Steps[0].Packet.Data[0] {
		t.Fatal("transition load exposed the store packet backing array")
	}
	store.nextRevision = 0
	if _, err := store.TransitionActionCheckpoint(
		attemptingRevision,
		ActionCheckpointPrepared,
		1,
	); !errors.Is(err, ErrActionCheckpointRevisionExhausted) {
		t.Fatalf("transition revision exhaustion error = %v", err)
	}
	exhausted, _, err := store.LoadActionCheckpoint()
	if err != nil || exhausted.Revision != attemptingRevision || exhausted.NextStep != 0 {
		t.Fatalf("transition mutated checkpoint on revision exhaustion: %#v err=%v", exhausted, err)
	}
}

type actionCheckpointUpdateOnlyStore struct {
	ActionCheckpointStore
	updates int
}

func (store *actionCheckpointUpdateOnlyStore) UpdateActionCheckpoint(
	expectedRevision uint64,
	checkpoint ActionCheckpoint,
) (ActionCheckpoint, error) {
	store.updates++
	return store.ActionCheckpointStore.UpdateActionCheckpoint(expectedRevision, checkpoint)
}

func TestActionRecoveryRetainsBaseStoreUpdateContract(t *testing.T) {
	store := &actionCheckpointUpdateOnlyStore{ActionCheckpointStore: NewMemoryActionCheckpointStore()}
	recovery, err := NewActionRecovery(testRecoveryIdentity(), &fakeControllerBackend{}, store)
	if err != nil {
		t.Fatal(err)
	}
	actions := []Action{{
		Kind:    ActionSendControl,
		Flow:    testFlow(31001),
		WGID:    7,
		Control: ControlPacket{Flags: FlagSYN},
		Reason:  "base-store",
	}}
	if err := recovery.Execute(context.Background(), actions); err != nil {
		t.Fatal(err)
	}
	if store.updates != 2 {
		t.Fatalf("base store update calls=%d, want 2", store.updates)
	}
}

type failingActionCheckpointTransitionStore struct {
	ActionCheckpointStore
	err         error
	transitions int
	updates     int
}

func (store *failingActionCheckpointTransitionStore) TransitionActionCheckpoint(
	uint64,
	ActionCheckpointPhase,
	int,
) (uint64, error) {
	store.transitions++
	return 0, store.err
}

func (store *failingActionCheckpointTransitionStore) UpdateActionCheckpoint(
	expectedRevision uint64,
	checkpoint ActionCheckpoint,
) (ActionCheckpoint, error) {
	store.updates++
	return store.ActionCheckpointStore.UpdateActionCheckpoint(expectedRevision, checkpoint)
}

func TestActionRecoveryDoesNotFallBackAfterTransitionFailure(t *testing.T) {
	wantErr := errors.New("transition unavailable")
	store := &failingActionCheckpointTransitionStore{
		ActionCheckpointStore: NewMemoryActionCheckpointStore(),
		err:                   wantErr,
	}
	recovery, err := NewActionRecovery(testRecoveryIdentity(), &fakeControllerBackend{}, store)
	if err != nil {
		t.Fatal(err)
	}
	actions := []Action{{
		Kind:    ActionSendControl,
		Flow:    testFlow(31001),
		WGID:    7,
		Control: ControlPacket{Flags: FlagSYN},
		Reason:  "transition-failure",
	}}
	if err := recovery.Execute(context.Background(), actions); !errors.Is(err, wantErr) {
		t.Fatalf("Execute error = %v", err)
	}
	if store.transitions != 1 || store.updates != 0 {
		t.Fatalf("transition calls=%d update calls=%d", store.transitions, store.updates)
	}
}

func TestActionRecoveryExecutesAndClearsCheckpointInOrder(t *testing.T) {
	backend := &fakeControllerBackend{}
	store := NewMemoryActionCheckpointStore()
	recovery, err := NewActionRecovery(testRecoveryIdentity(), backend, store)
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
	recovery, err := NewActionRecovery(testRecoveryIdentity(), backend, store)
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
	recovery, err = NewActionRecovery(testRecoveryIdentity(), backend, store)
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
	recovery, err := NewActionRecovery(testRecoveryIdentity(), backend, store)
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
	recovery, err = NewActionRecovery(testRecoveryIdentity(), backend, store)
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
	recovery, err := NewActionRecovery(testRecoveryIdentity(), backend, store)
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
	recovery, err = NewActionRecovery(testRecoveryIdentity(), backend, store)
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
	recovery, err := NewActionRecovery(testRecoveryIdentity(), backend, store)
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
	recovery, err = NewActionRecovery(testRecoveryIdentity(), backend, store)
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
	if recovery, err := NewActionRecovery(testRecoveryIdentity(), &fakeControllerBackend{}, &staticCheckpointStore{
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
	recovery, err := NewActionRecovery(testRecoveryIdentity(), backend, store)
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
	sample := testBoundEventSample(abi.FakeTCPEvent{
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
	first := testBoundEventSample(abi.FakeTCPEvent{
		Key: flow, TimestampNanos: 11, PayloadLength: 2, FWMark: 3, WGID: 7,
		PacketLength: uint16(len(packet)), Type: abi.FakeTCPEventNeedHandshake,
	}, packet, false)
	if _, err := controller.HandleSample(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	synACK := testBoundEventSample(abi.FakeTCPEvent{
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
	engine, _ := testEngine(t, nil)
	store := NewMemoryActionCheckpointStore()
	checkpoint := recoveryCheckpoint(t, 9, ActionCheckpointPrepared, 0, []ActionStep{
		recoveryControlStep(flow, FlagSYN),
	})
	checkpoint.Identity = engine.Identity()
	if _, err := store.CreateActionCheckpoint(checkpoint); err != nil {
		t.Fatal(err)
	}
	backend := &fakeControllerBackend{}
	controller, err := NewRecoverableController(engine, backend, store)
	if err != nil {
		t.Fatal(err)
	}
	packet := testIPv4UDPPacket(t, flow, []byte{1})
	sample := testBoundEventSample(abi.FakeTCPEvent{
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

func TestRecoverableControllerRejectsCheckpointFromDifferentEngineIdentity(t *testing.T) {
	for _, test := range []struct {
		name       string
		generation uint64
	}{
		{name: "same-generation-new-incarnation", generation: 1},
		{name: "different-generation", generation: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			sourceEngine, _ := testEngine(t, nil)
			flow := testFlow(31001)
			store := NewMemoryActionCheckpointStore()
			checkpoint := recoveryCheckpoint(t, 9, ActionCheckpointPrepared, 0, []ActionStep{
				recoveryControlStep(flow, FlagSYN),
			})
			checkpoint.Identity = sourceEngine.Identity()
			created, err := store.CreateActionCheckpoint(checkpoint)
			if err != nil {
				t.Fatal(err)
			}
			candidate, _ := testEngine(t, func(options *Options) {
				options.Generation = test.generation
			})
			candidate.identity.Incarnation[0] = 2
			if candidate.Identity() == sourceEngine.Identity() {
				t.Fatal("new Engine reused source identity")
			}
			backend := &fakeControllerBackend{}
			controller, err := NewRecoverableController(candidate, backend, store)
			if err != nil {
				t.Fatal(err)
			}
			report, err := controller.Recover(context.Background())
			if !errors.Is(err, ErrActionRecoveryRequired) || !errors.Is(err, ErrActionCheckpointIdentityMismatch) {
				t.Fatalf("Recover report=%#v error=%v", report, err)
			}
			if len(backend.operations) != 0 {
				t.Fatalf("identity mismatch reached backend: %v", backend.operations)
			}
			retained, found, err := store.LoadActionCheckpoint()
			if err != nil || !found || retained.Revision != created.Revision || retained.Identity != created.Identity {
				t.Fatalf("checkpoint evidence changed: found=%t checkpoint=%#v err=%v", found, retained, err)
			}
			if _, err := controller.Tick(context.Background()); !errors.Is(err, ErrActionCheckpointIdentityMismatch) {
				t.Fatalf("ordinary work was not fenced by identity mismatch: %v", err)
			}
		})
	}
}

func TestNewEngineAlwaysCreatesFreshRuntimeIncarnation(t *testing.T) {
	first, _ := testEngine(t, nil)
	second, err := New(first.opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRuntimeIdentity(first.Identity()); err != nil {
		t.Fatal(err)
	}
	if first.Identity().Generation != second.Identity().Generation {
		t.Fatalf("test generations differ: first=%d second=%d", first.Identity().Generation, second.Identity().Generation)
	}
	if first.Identity().Incarnation == second.Identity().Incarnation {
		t.Fatal("new empty Engine reused a prior incarnation")
	}
}

func TestRecoverableControllerClosePreservesPendingCheckpoint(t *testing.T) {
	flow := testFlow(31001)
	engine, _ := testEngine(t, nil)
	store := NewMemoryActionCheckpointStore()
	checkpoint := recoveryCheckpoint(t, 9, ActionCheckpointAttempting, 0, []ActionStep{
		recoveryPacketStep(t, flow, 11),
	})
	checkpoint.Identity = engine.Identity()
	if _, err := store.CreateActionCheckpoint(checkpoint); err != nil {
		t.Fatal(err)
	}
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
	checkpoint := ActionCheckpoint{
		Operation: operation, Identity: testRecoveryIdentity(), Phase: phase, NextStep: next, Steps: steps,
	}
	if err := validateActionCheckpoint(checkpoint); err != nil {
		t.Fatal(err)
	}
	return checkpoint
}

func testRecoveryIdentity() RuntimeIdentity {
	return RuntimeIdentity{Generation: 1, Incarnation: RuntimeIncarnation{1}}
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
