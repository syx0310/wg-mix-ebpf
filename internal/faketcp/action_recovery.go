package faketcp

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

var (
	ErrActionRecoveryRequired            = errors.New("faketcp action recovery is required")
	ErrActionCheckpointConflict          = errors.New("faketcp action checkpoint compare-and-swap conflict")
	ErrActionCheckpointCorrupt           = errors.New("faketcp action checkpoint is invalid")
	ErrActionCheckpointRevisionExhausted = errors.New("faketcp action checkpoint revision is exhausted")
	ErrActionCheckpointIdentityMismatch  = errors.New("faketcp action checkpoint belongs to a different engine identity")
)

type ActionCheckpointPhase uint8

const (
	ActionCheckpointPrepared ActionCheckpointPhase = iota + 1
	ActionCheckpointAttempting
)

type ActionStepKind uint8

const (
	ActionStepSendControl ActionStepKind = iota + 1
	ActionStepReinject
)

// ActionStep is one externally visible side effect. ReleasePending actions are
// split into one step per datagram so recovery never has to guess which packet
// in a batch was attempted.
type ActionStep struct {
	Kind    ActionStepKind
	Flow    abi.FakeTCPSessionKey
	WGID    uint32
	Control ControlPacket
	Packet  PendingPacket
	Reason  string
}

// ActionCheckpoint is a single-controller write-ahead checkpoint. Revision is
// assigned by ActionCheckpointStore and must be used for every update/delete.
// NextStep identifies the prepared or currently attempting step.
type ActionCheckpoint struct {
	Revision  uint64
	Operation uint64
	Identity  RuntimeIdentity
	Phase     ActionCheckpointPhase
	NextStep  int
	Steps     []ActionStep
}

// ActionCheckpointStore is a one-slot atomic CAS store. A daemon may back it
// with durable state; the in-memory implementation is suitable for one
// process lifetime. Implementations must deep-copy packet bytes on ingress and
// egress and preserve each reinjection step's CaptureFingerprint exactly across
// create, load, update, and transition operations. The fingerprint covers the
// pre-materialization capture sample and must never be reconstructed from the
// stored packet bytes. Implementations must never report a successful CAS
// before the new value is recoverable. A returned conflict must mean no mutation
// occurred; any other write error is treated as an unrecoverable store fault by
// Controller because its commit outcome cannot be inferred safely.
type ActionCheckpointStore interface {
	LoadActionCheckpoint() (ActionCheckpoint, bool, error)
	CreateActionCheckpoint(ActionCheckpoint) (ActionCheckpoint, error)
	UpdateActionCheckpoint(uint64, ActionCheckpoint) (ActionCheckpoint, error)
	DeleteActionCheckpoint(uint64) error
}

// ActionCheckpointTransitionStore optionally advances only checkpoint
// execution progress. It must durably CAS Phase, NextStep, and Revision while
// leaving Identity, Operation, Steps, and every CaptureFingerprint unchanged.
// NewActionRecovery binds this contract or the base update contract once for
// its entire lifetime.
type ActionCheckpointTransitionStore interface {
	ActionCheckpointStore
	TransitionActionCheckpoint(
		expectedRevision uint64,
		phase ActionCheckpointPhase,
		nextStep int,
	) (newRevision uint64, err error)
}

// MemoryActionCheckpointStore provides the exact CAS semantics used by tests
// and non-durable embedding. It deliberately retains no history after delete.
type MemoryActionCheckpointStore struct {
	mu sync.Mutex

	checkpoint   *ActionCheckpoint
	nextRevision uint64
}

func NewMemoryActionCheckpointStore() *MemoryActionCheckpointStore {
	return &MemoryActionCheckpointStore{nextRevision: 1}
}

func (store *MemoryActionCheckpointStore) LoadActionCheckpoint() (ActionCheckpoint, bool, error) {
	if store == nil {
		return ActionCheckpoint{}, false, errors.New("faketcp action checkpoint store is nil")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.checkpoint == nil {
		return ActionCheckpoint{}, false, nil
	}
	return cloneActionCheckpoint(*store.checkpoint), true, nil
}

func (store *MemoryActionCheckpointStore) CreateActionCheckpoint(
	checkpoint ActionCheckpoint,
) (ActionCheckpoint, error) {
	if store == nil {
		return ActionCheckpoint{}, errors.New("faketcp action checkpoint store is nil")
	}
	if checkpoint.Revision != 0 {
		return ActionCheckpoint{}, fmt.Errorf("%w: create revision is %d", ErrActionCheckpointCorrupt, checkpoint.Revision)
	}
	if err := validateActionCheckpoint(checkpoint); err != nil {
		return ActionCheckpoint{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.checkpoint != nil {
		return ActionCheckpoint{}, ErrActionCheckpointConflict
	}
	revision, err := store.allocateRevisionLocked()
	if err != nil {
		return ActionCheckpoint{}, err
	}
	checkpoint.Revision = revision
	copyCheckpoint := cloneActionCheckpoint(checkpoint)
	store.checkpoint = &copyCheckpoint
	return cloneActionCheckpoint(copyCheckpoint), nil
}

func (store *MemoryActionCheckpointStore) UpdateActionCheckpoint(
	expectedRevision uint64,
	checkpoint ActionCheckpoint,
) (ActionCheckpoint, error) {
	if store == nil {
		return ActionCheckpoint{}, errors.New("faketcp action checkpoint store is nil")
	}
	if expectedRevision == 0 {
		return ActionCheckpoint{}, fmt.Errorf("%w: expected revision is zero", ErrActionCheckpointCorrupt)
	}
	if checkpoint.Revision != expectedRevision {
		return ActionCheckpoint{}, fmt.Errorf(
			"%w: update revision %d does not match expected %d",
			ErrActionCheckpointCorrupt, checkpoint.Revision, expectedRevision,
		)
	}
	if err := validateActionCheckpoint(checkpoint); err != nil {
		return ActionCheckpoint{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.checkpoint == nil || store.checkpoint.Revision != expectedRevision {
		return ActionCheckpoint{}, ErrActionCheckpointConflict
	}
	revision, err := store.allocateRevisionLocked()
	if err != nil {
		return ActionCheckpoint{}, err
	}
	checkpoint.Revision = revision
	copyCheckpoint := cloneActionCheckpoint(checkpoint)
	store.checkpoint = &copyCheckpoint
	return cloneActionCheckpoint(copyCheckpoint), nil
}

func (store *MemoryActionCheckpointStore) TransitionActionCheckpoint(
	expectedRevision uint64,
	phase ActionCheckpointPhase,
	nextStep int,
) (uint64, error) {
	if store == nil {
		return 0, errors.New("faketcp action checkpoint store is nil")
	}
	if expectedRevision == 0 {
		return 0, fmt.Errorf("%w: expected revision is zero", ErrActionCheckpointCorrupt)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.checkpoint == nil || store.checkpoint.Revision != expectedRevision {
		return 0, ErrActionCheckpointConflict
	}
	if err := validateActionCheckpointPosition(phase, nextStep, len(store.checkpoint.Steps)); err != nil {
		return 0, err
	}
	revision, err := store.allocateRevisionLocked()
	if err != nil {
		return 0, err
	}
	store.checkpoint.Phase = phase
	store.checkpoint.NextStep = nextStep
	store.checkpoint.Revision = revision
	return revision, nil
}

func (store *MemoryActionCheckpointStore) DeleteActionCheckpoint(expectedRevision uint64) error {
	if store == nil {
		return errors.New("faketcp action checkpoint store is nil")
	}
	if expectedRevision == 0 {
		return fmt.Errorf("%w: expected revision is zero", ErrActionCheckpointCorrupt)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.checkpoint == nil || store.checkpoint.Revision != expectedRevision {
		return ErrActionCheckpointConflict
	}
	store.checkpoint = nil
	return nil
}

func (store *MemoryActionCheckpointStore) allocateRevisionLocked() (uint64, error) {
	if store.nextRevision == 0 {
		return 0, ErrActionCheckpointRevisionExhausted
	}
	revision := store.nextRevision
	store.nextRevision++
	return revision, nil
}

type RecoveryReport struct {
	ReplayedControls             int
	SkippedAmbiguousReinjections int
	CompletedSteps               int
}

// ActionRecovery owns no external resource. It serialises checkpoint changes
// and backend calls, allowing a new controller instance to resume a retained
// checkpoint. An attempting control step is safe to replay because FakeTCP
// handshakes accept duplicate SYN/SYNACK/ACK. An attempting reinjection is
// never replayed: its send outcome is ambiguous and WireGuard/QUIC remains
// responsible for retransmitting the dropped datagram.
type ActionRecovery struct {
	mu sync.Mutex

	backend          ControllerBackend
	store            ActionCheckpointStore
	updateCheckpoint func(ActionCheckpoint) (ActionCheckpoint, error)
	identity         RuntimeIdentity
	nextOperation    uint64
}

func NewActionRecovery(
	identity RuntimeIdentity,
	backend ControllerBackend,
	store ActionCheckpointStore,
) (*ActionRecovery, error) {
	if err := validateRuntimeIdentity(identity); err != nil {
		return nil, err
	}
	if controllerBackendIsNil(backend) {
		return nil, errors.New("faketcp action recovery backend is nil")
	}
	if actionCheckpointStoreIsNil(store) {
		return nil, errors.New("faketcp action checkpoint store is nil")
	}
	checkpoint, found, err := store.LoadActionCheckpoint()
	if err != nil {
		return nil, fmt.Errorf("load faketcp action checkpoint: %w", err)
	}
	nextOperation := uint64(1)
	if found {
		if err := validateStoredActionCheckpoint(checkpoint); err != nil {
			return nil, err
		}
		nextOperation = checkpoint.Operation + 1
	}
	return &ActionRecovery{
		backend: backend, store: store, updateCheckpoint: bindActionCheckpointUpdate(store),
		identity: identity, nextOperation: nextOperation,
	}, nil
}

func bindActionCheckpointUpdate(
	store ActionCheckpointStore,
) func(ActionCheckpoint) (ActionCheckpoint, error) {
	if transitionStore, ok := store.(ActionCheckpointTransitionStore); ok {
		return func(checkpoint ActionCheckpoint) (ActionCheckpoint, error) {
			revision, err := transitionStore.TransitionActionCheckpoint(
				checkpoint.Revision,
				checkpoint.Phase,
				checkpoint.NextStep,
			)
			checkpoint.Revision = revision
			return checkpoint, err
		}
	}
	return func(checkpoint ActionCheckpoint) (ActionCheckpoint, error) {
		return store.UpdateActionCheckpoint(checkpoint.Revision, checkpoint)
	}
}

func (recovery *ActionRecovery) Execute(ctx context.Context, actions []Action) error {
	if recovery == nil {
		return errors.New("faketcp action recovery is nil")
	}
	if ctx == nil {
		return errors.New("faketcp action execution context is nil")
	}
	steps, err := actionSteps(actions)
	if err != nil {
		return err
	}
	if len(steps) == 0 {
		return nil
	}
	recovery.mu.Lock()
	defer recovery.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, found, err := recovery.store.LoadActionCheckpoint(); err != nil {
		return fmt.Errorf("load faketcp action checkpoint before execute: %w", err)
	} else if found {
		return ErrActionRecoveryRequired
	}
	if recovery.nextOperation == 0 {
		return errors.New("faketcp action operation counter is exhausted")
	}
	checkpoint, err := recovery.store.CreateActionCheckpoint(ActionCheckpoint{
		Operation: recovery.nextOperation,
		Identity:  recovery.identity,
		Phase:     ActionCheckpointPrepared,
		Steps:     steps,
	})
	if err != nil {
		checkpointErr := fmt.Errorf("create faketcp action checkpoint: %w", err)
		if errors.Is(err, ErrActionCheckpointConflict) {
			return errors.Join(ErrActionRecoveryRequired, checkpointErr)
		}
		return checkpointErr
	}
	recovery.nextOperation++
	_, err = recovery.continueLocked(ctx, checkpoint, false)
	return err
}

func (recovery *ActionRecovery) Recover(ctx context.Context) (RecoveryReport, error) {
	if recovery == nil {
		return RecoveryReport{}, errors.New("faketcp action recovery is nil")
	}
	if ctx == nil {
		return RecoveryReport{}, errors.New("faketcp action recovery context is nil")
	}
	recovery.mu.Lock()
	defer recovery.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return RecoveryReport{}, err
	}
	checkpoint, found, err := recovery.store.LoadActionCheckpoint()
	if err != nil {
		return RecoveryReport{}, fmt.Errorf("load faketcp action checkpoint for recovery: %w", err)
	}
	if !found {
		return RecoveryReport{}, nil
	}
	if err := validateStoredActionCheckpoint(checkpoint); err != nil {
		return RecoveryReport{}, err
	}
	if checkpoint.Identity != recovery.identity {
		return RecoveryReport{}, fmt.Errorf(
			"%w: checkpoint generation %d incarnation %x, engine generation %d incarnation %x",
			ErrActionCheckpointIdentityMismatch,
			checkpoint.Identity.Generation, checkpoint.Identity.Incarnation,
			recovery.identity.Generation, recovery.identity.Incarnation,
		)
	}
	return recovery.continueLocked(ctx, checkpoint, true)
}

func (recovery *ActionRecovery) Pending() (bool, error) {
	if recovery == nil {
		return false, errors.New("faketcp action recovery is nil")
	}
	recovery.mu.Lock()
	defer recovery.mu.Unlock()
	checkpoint, found, err := recovery.store.LoadActionCheckpoint()
	if err != nil {
		return false, fmt.Errorf("load faketcp action checkpoint status: %w", err)
	}
	if found {
		if err := validateStoredActionCheckpoint(checkpoint); err != nil {
			return false, err
		}
	}
	return found, nil
}

func (recovery *ActionRecovery) continueLocked(
	ctx context.Context,
	checkpoint ActionCheckpoint,
	recovering bool,
) (RecoveryReport, error) {
	var report RecoveryReport
	if checkpoint.Phase == ActionCheckpointAttempting {
		step := checkpoint.Steps[checkpoint.NextStep]
		if !recovering {
			return report, ErrActionRecoveryRequired
		}
		if step.Kind == ActionStepReinject {
			checkpoint.Phase = ActionCheckpointPrepared
			checkpoint.NextStep++
			updated, err := recovery.updateCheckpoint(checkpoint)
			if err != nil {
				return report, fmt.Errorf("%w: checkpoint ambiguous faketcp reinjection as skipped: %w", ErrActionRecoveryRequired, err)
			}
			checkpoint = updated
			report.SkippedAmbiguousReinjections++
		} else {
			checkpoint.Phase = ActionCheckpointPrepared
			updated, err := recovery.updateCheckpoint(checkpoint)
			if err != nil {
				return report, fmt.Errorf("%w: checkpoint faketcp control replay: %w", ErrActionRecoveryRequired, err)
			}
			checkpoint = updated
			report.ReplayedControls++
		}
	}

	for checkpoint.NextStep < len(checkpoint.Steps) {
		if err := ctx.Err(); err != nil {
			return report, fmt.Errorf("%w: %w", ErrActionRecoveryRequired, err)
		}
		checkpoint.Phase = ActionCheckpointAttempting
		updated, err := recovery.updateCheckpoint(checkpoint)
		if err != nil {
			return report, fmt.Errorf("%w: mark faketcp action step attempting: %w", ErrActionRecoveryRequired, err)
		}
		checkpoint = updated
		step := checkpoint.Steps[checkpoint.NextStep]
		if err := executeActionStep(ctx, recovery.backend, step); err != nil {
			return report, fmt.Errorf("%w: %w", ErrActionRecoveryRequired, err)
		}
		checkpoint.Phase = ActionCheckpointPrepared
		checkpoint.NextStep++
		updated, err = recovery.updateCheckpoint(checkpoint)
		if err != nil {
			return report, fmt.Errorf("%w: checkpoint completed faketcp action step: %w", ErrActionRecoveryRequired, err)
		}
		checkpoint = updated
		report.CompletedSteps++
	}
	if err := recovery.store.DeleteActionCheckpoint(checkpoint.Revision); err != nil {
		return report, fmt.Errorf("%w: delete completed faketcp action checkpoint: %w", ErrActionRecoveryRequired, err)
	}
	return report, nil
}

func actionSteps(actions []Action) ([]ActionStep, error) {
	steps := make([]ActionStep, 0, len(actions))
	var captureBindings map[CaptureIdentity]capturedPacketBinding
	for _, action := range actions {
		switch action.Kind {
		case ActionDrop, ActionForward, ActionClose:
		case ActionSendControl:
			step := ActionStep{
				Kind: ActionStepSendControl, Flow: action.Flow, WGID: action.WGID,
				Control: action.Control, Reason: action.Reason,
			}
			if err := validateActionStep(step); err != nil {
				return nil, err
			}
			steps = append(steps, step)
		case ActionReleasePending:
			for _, packet := range action.Packets {
				step := ActionStep{
					Kind: ActionStepReinject, Flow: action.Flow, Packet: packet,
					Reason: action.Reason,
				}
				if err := validateActionStep(step); err != nil {
					return nil, err
				}
				if captureBindings == nil {
					captureBindings = make(map[CaptureIdentity]capturedPacketBinding)
				}
				duplicate, err := observeCapturedPacket(captureBindings, action.Flow, packet)
				if err != nil {
					return nil, fmt.Errorf("canonicalize faketcp captured packet: %w", err)
				}
				if duplicate {
					continue
				}
				step.Packet.Data = append([]byte(nil), packet.Data...)
				steps = append(steps, step)
			}
		default:
			return nil, fmt.Errorf("unknown faketcp action kind %d", action.Kind)
		}
	}
	return steps, nil
}

func executeActionStep(ctx context.Context, backend ControllerBackend, step ActionStep) error {
	switch step.Kind {
	case ActionStepSendControl:
		if err := backend.SendControl(ctx, step.Flow, step.WGID, step.Control); err != nil {
			return fmt.Errorf("send faketcp control packet (%s): %w", step.Reason, err)
		}
	case ActionStepReinject:
		if err := backend.Reinject(ctx, step.Flow, step.Packet); err != nil {
			return fmt.Errorf("reinject faketcp first packet: %w", err)
		}
	default:
		return fmt.Errorf("unknown faketcp action step kind %d", step.Kind)
	}
	return nil
}

func validateActionCheckpoint(checkpoint ActionCheckpoint) error {
	if checkpoint.Operation == 0 || len(checkpoint.Steps) == 0 {
		return fmt.Errorf("%w: zero operation or empty steps", ErrActionCheckpointCorrupt)
	}
	if err := validateActionCheckpointPosition(checkpoint.Phase, checkpoint.NextStep, len(checkpoint.Steps)); err != nil {
		return err
	}
	if err := validateRuntimeIdentity(checkpoint.Identity); err != nil {
		return fmt.Errorf("%w: %v", ErrActionCheckpointCorrupt, err)
	}
	for _, step := range checkpoint.Steps {
		if err := validateActionStep(step); err != nil {
			return fmt.Errorf("%w: %v", ErrActionCheckpointCorrupt, err)
		}
		if step.Flow.Generation != checkpoint.Identity.Generation {
			return fmt.Errorf(
				"%w: action generation %d does not match identity generation %d",
				ErrActionCheckpointCorrupt, step.Flow.Generation, checkpoint.Identity.Generation,
			)
		}
		if step.Kind == ActionStepReinject && step.Packet.CaptureID.Runtime != checkpoint.Identity {
			return fmt.Errorf(
				"%w: captured packet identity does not match checkpoint Engine identity",
				ErrActionCheckpointCorrupt,
			)
		}
	}
	if err := validateCheckpointCaptureBindings(checkpoint); err != nil {
		return err
	}
	return nil
}

func validateCheckpointCaptureBindings(checkpoint ActionCheckpoint) error {
	var bindings map[CaptureIdentity]capturedPacketBinding
	for index, step := range checkpoint.Steps {
		if step.Kind != ActionStepReinject {
			continue
		}
		if bindings == nil {
			bindings = make(map[CaptureIdentity]capturedPacketBinding)
		}
		duplicate, err := observeCapturedPacket(bindings, step.Flow, step.Packet)
		if err != nil {
			return fmt.Errorf(
				"%w: capture binding at step %d: %w",
				ErrActionCheckpointCorrupt,
				index,
				err,
			)
		}
		if duplicate {
			return fmt.Errorf(
				"%w: duplicate capture identity at step %d",
				ErrActionCheckpointCorrupt,
				index,
			)
		}
	}
	return nil
}

func validateActionCheckpointPosition(phase ActionCheckpointPhase, nextStep, stepCount int) error {
	if nextStep < 0 || nextStep > stepCount {
		return fmt.Errorf("%w: next step %d of %d", ErrActionCheckpointCorrupt, nextStep, stepCount)
	}
	if phase != ActionCheckpointPrepared && phase != ActionCheckpointAttempting {
		return fmt.Errorf("%w: phase %d", ErrActionCheckpointCorrupt, phase)
	}
	if phase == ActionCheckpointAttempting && nextStep == stepCount {
		return fmt.Errorf("%w: attempting after final step", ErrActionCheckpointCorrupt)
	}
	return nil
}

func validateStoredActionCheckpoint(checkpoint ActionCheckpoint) error {
	if checkpoint.Revision == 0 {
		return fmt.Errorf("%w: stored revision is zero", ErrActionCheckpointCorrupt)
	}
	return validateActionCheckpoint(checkpoint)
}

func validateActionStep(step ActionStep) error {
	if err := validatePacketFlow(step.Flow); err != nil {
		return fmt.Errorf("invalid faketcp action step flow: %w", err)
	}
	switch step.Kind {
	case ActionStepSendControl:
		if len(step.Packet.Data) != 0 {
			return errors.New("faketcp control action step contains packet data")
		}
		switch step.Control.Flags {
		case FlagSYN, FlagSYN | FlagACK, FlagACK:
		default:
			return fmt.Errorf("faketcp control action step has unsupported flags %#x", step.Control.Flags)
		}
	case ActionStepReinject:
		if len(step.Packet.Data) == 0 {
			return errors.New("faketcp reinjection action step has no packet or capture identity")
		}
		if err := validateCaptureIdentity(step.Packet.CaptureID, step.Flow.Generation); err != nil {
			return fmt.Errorf("faketcp reinjection action step identity: %w", err)
		}
		if step.Packet.CaptureFingerprint == ([32]byte{}) {
			return errors.New("faketcp reinjection action step has no capture fingerprint")
		}
	default:
		return fmt.Errorf("unknown faketcp action step kind %d", step.Kind)
	}
	return nil
}

func cloneActionCheckpoint(checkpoint ActionCheckpoint) ActionCheckpoint {
	clone := checkpoint
	clone.Steps = make([]ActionStep, len(checkpoint.Steps))
	for index, step := range checkpoint.Steps {
		clone.Steps[index] = step
		clone.Steps[index].Packet.Data = append([]byte(nil), step.Packet.Data...)
	}
	return clone
}

func actionCheckpointStoreIsNil(store ActionCheckpointStore) bool {
	return interfaceValueIsNil(store)
}
