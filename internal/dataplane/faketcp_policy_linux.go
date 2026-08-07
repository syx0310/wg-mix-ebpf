//go:build linux

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/syx0310/wg-mix-ebpf/internal/abi"
	"github.com/syx0310/wg-mix-ebpf/internal/lockfile"
)

const (
	fakeTCPControlPolicyMapName = "faketcp_control_policy_map"
	fakeTCPManagedPortMapName   = "faketcp_managed_port_map"
	fakeTCPManagedIfMapName     = "faketcp_managed_if_map"
)

type fakeTCPPolicyMap interface {
	Lookup(key, valueOut any) error
	Update(key, value any, flags ebpf.MapUpdateFlags) error
	Delete(key any) error
}

type fakeTCPPolicyMaps struct {
	ControlPolicies   fakeTCPPolicyMap
	ManagedPorts      fakeTCPPolicyMap
	ManagedInterfaces fakeTCPPolicyMap
}

var errFakeTCPPolicyGenerationLeaseRequired = errors.New(
	"FakeTCP policy mutation requires a held generation transaction lease",
)

// fakeTCPPolicyGenerationIsolationBackend proves both sides of the generation
// lifecycle. AssertInactive must prove that no dataplane selector currently
// reaches the target generation before Stage performs its first map lookup.
// The retained lifecycle lease then prevents cooperating userspace from
// selecting it during staging. Quiesce is called only after every interface
// reachability latch has been confirmed absent; a successful return must also
// guarantee that all BPF executions which could have observed those latches
// have exited.
type fakeTCPPolicyGenerationIsolationBackend interface {
	AssertInactive(context.Context, uint64) error
	Quiesce(context.Context, uint64) error
}

type fakeTCPPolicyGenerationIdentity struct {
	nonce byte
}

// fakeTCPPolicyGenerationTransaction binds one policy generation to a retained
// global lifecycle lease and a mandatory BPF quiescence barrier. The retained
// lease excludes every cooperating userspace map mutator for the complete
// stage/rollback lifetime, even if the caller closes its original lease.
//
// The transaction is intentionally single-use. A future owner integration
// must either Rollback or Disarm its stage before Close can release the lease.
type fakeTCPPolicyGenerationTransaction struct {
	mu             sync.Mutex
	generation     uint64
	lifecyclePath  string
	lifecycleLease *lockfile.LifecycleLease
	isolation      fakeTCPPolicyGenerationIsolationBackend
	identity       *fakeTCPPolicyGenerationIdentity
	stage          *fakeTCPPolicyStage
	closed         bool
}

func newFakeTCPPolicyGenerationTransaction(
	ctx context.Context,
	generation uint64,
	lifecycleLease *lockfile.LifecycleLease,
	isolation fakeTCPPolicyGenerationIsolationBackend,
) (*fakeTCPPolicyGenerationTransaction, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context is nil", errFakeTCPPolicyGenerationLeaseRequired)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if generation == 0 {
		return nil, fmt.Errorf("%w: generation is zero", errFakeTCPPolicyGenerationLeaseRequired)
	}
	if fakeTCPPolicyGenerationIsolationBackendIsNil(isolation) {
		return nil, fmt.Errorf("%w: generation isolation backend is nil", errFakeTCPPolicyGenerationLeaseRequired)
	}
	lifecyclePath := lockfile.LifecycleLeasePath(ctx)
	if lifecycleLease == nil || !lifecycleLease.HeldAt(lifecyclePath) {
		return nil, fmt.Errorf(
			"%w at %s",
			errFakeTCPPolicyGenerationLeaseRequired,
			lifecyclePath,
		)
	}
	retained, err := lifecycleLease.Retain()
	if err != nil {
		return nil, fmt.Errorf(
			"%w at %s: retain lifecycle lease: %v",
			errFakeTCPPolicyGenerationLeaseRequired,
			lifecyclePath,
			err,
		)
	}
	if !retained.HeldAt(lifecyclePath) {
		_ = retained.Close()
		return nil, fmt.Errorf(
			"%w at %s: retained lifecycle lease identity changed",
			errFakeTCPPolicyGenerationLeaseRequired,
			lifecyclePath,
		)
	}
	return &fakeTCPPolicyGenerationTransaction{
		generation:     generation,
		lifecyclePath:  lifecyclePath,
		lifecycleLease: retained,
		isolation:      isolation,
		identity:       &fakeTCPPolicyGenerationIdentity{nonce: 1},
	}, nil
}

func fakeTCPPolicyGenerationIsolationBackendIsNil(
	isolation fakeTCPPolicyGenerationIsolationBackend,
) bool {
	if isolation == nil {
		return true
	}
	value := reflect.ValueOf(isolation)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (transaction *fakeTCPPolicyGenerationTransaction) assertHeldLocked(ctx context.Context) error {
	if transaction == nil {
		return fmt.Errorf("%w: transaction is nil", errFakeTCPPolicyGenerationLeaseRequired)
	}
	if ctx == nil {
		return fmt.Errorf("%w: context is nil", errFakeTCPPolicyGenerationLeaseRequired)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	contextLifecyclePath := lockfile.LifecycleLeasePath(ctx)
	if contextLifecyclePath != transaction.lifecyclePath {
		return fmt.Errorf(
			"%w: context lifecycle path %s does not match transaction path %s",
			errFakeTCPPolicyGenerationLeaseRequired,
			contextLifecyclePath,
			transaction.lifecyclePath,
		)
	}
	if transaction.closed || transaction.lifecycleLease == nil ||
		!transaction.lifecycleLease.HeldAt(transaction.lifecyclePath) {
		return fmt.Errorf(
			"%w at %s: transaction is closed or no longer owns the lease",
			errFakeTCPPolicyGenerationLeaseRequired,
			transaction.lifecyclePath,
		)
	}
	if transaction.identity == nil ||
		fakeTCPPolicyGenerationIsolationBackendIsNil(transaction.isolation) ||
		transaction.generation == 0 {
		return fmt.Errorf("%w: transaction identity is incomplete", errFakeTCPPolicyGenerationLeaseRequired)
	}
	return nil
}

func (transaction *fakeTCPPolicyGenerationTransaction) assertHeld(ctx context.Context) error {
	if transaction == nil {
		return fmt.Errorf("%w: transaction is nil", errFakeTCPPolicyGenerationLeaseRequired)
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	return transaction.assertHeldLocked(ctx)
}

// Close releases the transaction's retained lifecycle lease. It refuses to
// release ownership while a stage can still require rollback.
func (transaction *fakeTCPPolicyGenerationTransaction) Close() error {
	if transaction == nil {
		return nil
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.closed {
		return nil
	}
	if transaction.stage != nil &&
		(transaction.stage.state == fakeTCPPolicyStageActive ||
			transaction.stage.state == fakeTCPPolicyStageRollbackPending) {
		return errors.New("cannot close FakeTCP generation transaction with a live policy stage")
	}
	transaction.closed = true
	lease := transaction.lifecycleLease
	transaction.lifecycleLease = nil
	return lease.Close()
}

// Stage stages one previously absent generation while retaining the generation
// transaction lease. The interface marker is the XDP reachability latch and is
// therefore always written last. This helper deliberately does not commit
// control_map or attach a program; those remain responsibilities of a future
// owner transaction.
func (transaction *fakeTCPPolicyGenerationTransaction) Stage(
	ctx context.Context,
	maps fakeTCPPolicyMaps,
	snapshot *fakeTCPPolicySnapshot,
) (*fakeTCPPolicyStage, error) {
	if transaction == nil {
		return nil, fmt.Errorf("stage FakeTCP policy: %w", errFakeTCPPolicyGenerationLeaseRequired)
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if err := transaction.assertHeldLocked(ctx); err != nil {
		return nil, fmt.Errorf("stage FakeTCP policy: %w", err)
	}
	if err := validateFakeTCPPolicySnapshot(snapshot); err != nil {
		return nil, fmt.Errorf("stage FakeTCP policy: %w", err)
	}
	if snapshot.Generation != transaction.generation {
		return nil, fmt.Errorf(
			"stage FakeTCP policy: snapshot generation %d does not match transaction generation %d",
			snapshot.Generation,
			transaction.generation,
		)
	}
	if transaction.stage != nil {
		return nil, errors.New("stage FakeTCP policy: generation transaction is single-use")
	}
	if maps.ControlPolicies == nil || maps.ManagedPorts == nil || maps.ManagedInterfaces == nil {
		return nil, errors.New("stage FakeTCP policy: all three experimental policy maps are required")
	}
	if err := transaction.isolation.AssertInactive(ctx, transaction.generation); err != nil {
		return nil, fmt.Errorf(
			"stage FakeTCP policy: prove generation %d is inactive: %w",
			transaction.generation,
			err,
		)
	}

	operations := fakeTCPPolicyOperations(maps, snapshot)
	// Reject the whole target generation before the first write if any exact
	// key already exists. In particular, this prevents a reload from resetting
	// the BPF-owned virtual_time_nanos cursor.
	for _, operation := range operations {
		if err := operation.requireAbsent(); err != nil {
			return nil, fmt.Errorf("stage FakeTCP policy preflight %s: %w", operation.label, err)
		}
	}

	applied := make([]fakeTCPPolicyOperation, 0, len(operations))
	for _, operation := range operations {
		if err := operation.insert(); err != nil {
			return transaction.failStageLocked(
				ctx,
				fmt.Errorf("stage FakeTCP policy insert %s: %w", operation.label, err),
				applied,
			)
		}
		applied = append(applied, operation)
		if err := operation.verify(); err != nil {
			return transaction.failStageLocked(
				ctx,
				fmt.Errorf("stage FakeTCP policy verify %s: %w", operation.label, err),
				applied,
			)
		}
	}
	stage := &fakeTCPPolicyStage{
		operations: applied,
		owner:      transaction.identity,
	}
	transaction.stage = stage
	return stage, nil
}

const (
	fakeTCPPolicyStageActive uint8 = iota
	fakeTCPPolicyStageRollbackPending
	fakeTCPPolicyStageRolledBack
	fakeTCPPolicyStageDisarmed
)

// fakeTCPPolicyStage lets the future collection/XDP owner transaction undo a
// successful stage if a later attachment or owner-record commit fails. It owns
// only the exact keys and immutable values inserted by its generation
// transaction; virtual_time_nanos is explicitly BPF-owned. It has no Rollback
// method: mutation is possible only through the exact transaction which holds
// the retained lifecycle lease and generation-isolation backend.
type fakeTCPPolicyStage struct {
	operations      []fakeTCPPolicyOperation
	state           uint8
	owner           *fakeTCPPolicyGenerationIdentity
	collectionOwner *experimentalCollectionOwner
}

// Rollback is idempotent after a complete rollback or Disarm. It first removes
// every interface latch, then executes the mandatory BPF quiescence barrier,
// then removes ports, and only then removes control policies. A failure in any
// layer stops before its dependencies and leaves the same handle retryable.
func (transaction *fakeTCPPolicyGenerationTransaction) Rollback(
	ctx context.Context,
	stage *fakeTCPPolicyStage,
) error {
	if transaction == nil {
		return errFakeTCPPolicyGenerationLeaseRequired
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if err := transaction.assertStageLocked(ctx, stage); err != nil {
		return err
	}
	if stage.state == fakeTCPPolicyStageRolledBack || stage.state == fakeTCPPolicyStageDisarmed {
		return nil
	}
	stage.state = fakeTCPPolicyStageRollbackPending
	if err := rollbackFakeTCPPolicyOperationsLocked(ctx, transaction, stage.operations); err != nil {
		return err
	}
	stage.operations = nil
	stage.state = fakeTCPPolicyStageRolledBack
	return nil
}

// Disarm transfers responsibility for the staged entries to the successful
// outer transaction. It refuses to hide a partially failed rollback.
func (transaction *fakeTCPPolicyGenerationTransaction) Disarm(
	ctx context.Context,
	stage *fakeTCPPolicyStage,
) error {
	if transaction == nil {
		return errFakeTCPPolicyGenerationLeaseRequired
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if err := transaction.assertStageLocked(ctx, stage); err != nil {
		return err
	}
	switch stage.state {
	case fakeTCPPolicyStageActive:
		stage.operations = nil
		stage.state = fakeTCPPolicyStageDisarmed
		return nil
	case fakeTCPPolicyStageDisarmed:
		return nil
	case fakeTCPPolicyStageRollbackPending:
		return errors.New("cannot disarm FakeTCP policy stage after an incomplete rollback")
	default:
		return errors.New("cannot disarm a rolled-back FakeTCP policy stage")
	}
}

func (transaction *fakeTCPPolicyGenerationTransaction) bindStageCollectionOwner(
	ctx context.Context,
	stage *fakeTCPPolicyStage,
	owner *experimentalCollectionOwner,
) error {
	if transaction == nil {
		return errFakeTCPPolicyGenerationLeaseRequired
	}
	if owner == nil {
		return errors.New("bind FakeTCP policy stage: collection owner is nil")
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if err := transaction.assertStageLocked(ctx, stage); err != nil {
		return err
	}
	if stage.collectionOwner != nil && stage.collectionOwner != owner {
		return errors.New("bind FakeTCP policy stage: collection owner changed")
	}
	stage.collectionOwner = owner
	return nil
}

// releaseStageAfterCollectionClose is the terminal construction-failure path
// for an unpinned experimental collection. Ordinary policy owners must use
// Rollback or Disarm. This path is permitted only after the exact collection
// owner has attempted every map/program close and relinquished all handles;
// at that point retrying map rollback is both impossible and unnecessary for
// lifecycle-lease safety.
func (transaction *fakeTCPPolicyGenerationTransaction) releaseStageAfterCollectionClose(
	ctx context.Context,
	stage *fakeTCPPolicyStage,
	proof *experimentalCollectionReleaseProof,
) error {
	if transaction == nil {
		return errFakeTCPPolicyGenerationLeaseRequired
	}
	if proof == nil || proof.owner == nil {
		return errors.New("release FakeTCP policy stage requires collection close proof")
	}
	proof.owner.mu.Lock()
	collectionClosed := proof.owner.closed
	proof.owner.mu.Unlock()
	if !collectionClosed {
		return errors.New("release FakeTCP policy stage requires a closed collection owner")
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if err := transaction.assertStageLocked(ctx, stage); err != nil {
		return err
	}
	if stage.collectionOwner == nil || stage.collectionOwner != proof.owner {
		return errors.New("release FakeTCP policy stage collection proof does not match its bound owner")
	}
	stage.operations = nil
	stage.state = fakeTCPPolicyStageRolledBack
	return nil
}

func (transaction *fakeTCPPolicyGenerationTransaction) assertStageLocked(
	ctx context.Context,
	stage *fakeTCPPolicyStage,
) error {
	if err := transaction.assertHeldLocked(ctx); err != nil {
		return err
	}
	if stage == nil || transaction.stage != stage || stage.owner != transaction.identity {
		return errors.New("FakeTCP policy stage is not owned by this generation transaction")
	}
	return nil
}

type fakeTCPPolicyPhase uint8

const (
	fakeTCPPolicyPhaseControl fakeTCPPolicyPhase = iota
	fakeTCPPolicyPhasePort
	fakeTCPPolicyPhaseInterface
)

type fakeTCPPolicyRollbackMode uint8

const (
	fakeTCPPolicyRollbackExact fakeTCPPolicyRollbackMode = iota
	fakeTCPPolicyRollbackQuiescedControl
)

type fakeTCPPolicyOperation struct {
	label         string
	phase         fakeTCPPolicyPhase
	requireAbsent func() error
	insert        func() error
	verify        func() error
	rollback      func(fakeTCPPolicyRollbackMode) error
}

func fakeTCPPolicyOperations(
	maps fakeTCPPolicyMaps,
	snapshot *fakeTCPPolicySnapshot,
) []fakeTCPPolicyOperation {
	operations := make([]fakeTCPPolicyOperation, 0,
		len(snapshot.ControlPolicies)+len(snapshot.ManagedPorts)+len(snapshot.ManagedInterfaces))

	policyKeys := make([]abi.FakeTCPControlPolicyKey, 0, len(snapshot.ControlPolicies))
	for key := range snapshot.ControlPolicies {
		policyKeys = append(policyKeys, key)
	}
	sort.Slice(policyKeys, func(i, j int) bool {
		return policyKeys[i].WGID < policyKeys[j].WGID
	})
	for _, key := range policyKeys {
		operations = append(operations, newFakeTCPPolicyOperationWithComparator(
			maps.ControlPolicies,
			fakeTCPControlPolicyMapName,
			fakeTCPPolicyPhaseControl,
			key,
			snapshot.ControlPolicies[key],
			fakeTCPControlPolicyRollbackMatches,
		))
	}

	portKeys := make([]abi.FakeTCPManagedPortKey, 0, len(snapshot.ManagedPorts))
	for key := range snapshot.ManagedPorts {
		portKeys = append(portKeys, key)
	}
	sort.Slice(portKeys, func(i, j int) bool {
		if portKeys[i].UnderlayIndex != portKeys[j].UnderlayIndex {
			return portKeys[i].UnderlayIndex < portKeys[j].UnderlayIndex
		}
		return portKeys[i].DestinationPort < portKeys[j].DestinationPort
	})
	for _, key := range portKeys {
		operations = append(operations, newFakeTCPPolicyOperation(
			maps.ManagedPorts,
			fakeTCPManagedPortMapName,
			fakeTCPPolicyPhasePort,
			key,
			snapshot.ManagedPorts[key],
		))
	}

	interfaceKeys := make([]abi.FakeTCPManagedIfKey, 0, len(snapshot.ManagedInterfaces))
	for key := range snapshot.ManagedInterfaces {
		interfaceKeys = append(interfaceKeys, key)
	}
	sort.Slice(interfaceKeys, func(i, j int) bool {
		return interfaceKeys[i].UnderlayIndex < interfaceKeys[j].UnderlayIndex
	})
	for _, key := range interfaceKeys {
		operations = append(operations, newFakeTCPPolicyOperation(
			maps.ManagedInterfaces,
			fakeTCPManagedIfMapName,
			fakeTCPPolicyPhaseInterface,
			key,
			snapshot.ManagedInterfaces[key],
		))
	}
	return operations
}

func newFakeTCPPolicyOperation[K comparable, V comparable](
	m fakeTCPPolicyMap,
	mapName string,
	phase fakeTCPPolicyPhase,
	key K,
	value V,
) fakeTCPPolicyOperation {
	return newFakeTCPPolicyOperationWithComparator(
		m,
		mapName,
		phase,
		key,
		value,
		nil,
	)
}

func newFakeTCPPolicyOperationWithComparator[K comparable, V comparable](
	m fakeTCPPolicyMap,
	mapName string,
	phase fakeTCPPolicyPhase,
	key K,
	value V,
	quiescedRollbackMatches func(V, V) bool,
) fakeTCPPolicyOperation {
	label := fmt.Sprintf("%s key=%#v", mapName, key)
	lookup := func() (V, error) {
		var actual V
		err := m.Lookup(key, &actual)
		return actual, err
	}
	return fakeTCPPolicyOperation{
		label: label,
		phase: phase,
		requireAbsent: func() error {
			_, err := lookup()
			switch {
			case err == nil:
				return errors.New("exact key already exists")
			case errors.Is(err, ebpf.ErrKeyNotExist):
				return nil
			default:
				return fmt.Errorf("lookup existing key: %w", err)
			}
		},
		insert: func() error {
			if err := m.Update(key, value, ebpf.UpdateNoExist); err != nil {
				return err
			}
			return nil
		},
		verify: func() error {
			actual, err := lookup()
			if err != nil {
				return fmt.Errorf("read back inserted value: %w", err)
			}
			if actual != value {
				return errors.New("read back value differs from inserted value")
			}
			return nil
		},
		rollback: func(mode fakeTCPPolicyRollbackMode) error {
			actual, err := lookup()
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return nil
			}
			if err != nil {
				return fmt.Errorf("read back before rollback: %w", err)
			}
			matches := actual == value
			if !matches &&
				mode == fakeTCPPolicyRollbackQuiescedControl &&
				quiescedRollbackMatches != nil {
				matches = quiescedRollbackMatches(actual, value)
			}
			if !matches {
				return errors.New("refusing rollback because inserted value changed")
			}
			// Lookup+Delete is not an atomic kernel operation. Safety comes
			// from the retained lifecycle lease excluding userspace writers;
			// control policies are reached only after interface latches are
			// absent and the BPF quiescence barrier has succeeded.
			if err := m.Delete(key); err != nil {
				if errors.Is(err, ebpf.ErrKeyNotExist) {
					return nil
				}
				return fmt.Errorf("delete exact inserted key: %w", err)
			}
			_, err = lookup()
			switch {
			case errors.Is(err, ebpf.ErrKeyNotExist):
				return nil
			case err != nil:
				return fmt.Errorf("confirm deleted key is absent: %w", err)
			default:
				return errors.New("deleted key is still present")
			}
		},
	}
}

// fakeTCPControlPolicyRollbackMatches accepts only the cursor drift owned by
// BPF. Struct equality after normalizing virtual_time_nanos keeps generation,
// interval, burst, and all reserved bytes strict. The caller enables this
// comparator only after interface latches are absent and Quiesce succeeds.
func fakeTCPControlPolicyRollbackMatches(
	actual abi.FakeTCPControlPolicyValue,
	inserted abi.FakeTCPControlPolicyValue,
) bool {
	actual.VirtualTimeNanos = inserted.VirtualTimeNanos
	return actual == inserted
}

func (transaction *fakeTCPPolicyGenerationTransaction) failStageLocked(
	ctx context.Context,
	cause error,
	applied []fakeTCPPolicyOperation,
) (*fakeTCPPolicyStage, error) {
	rollbackErr := rollbackFakeTCPPolicyOperationsLocked(ctx, transaction, applied)
	if rollbackErr != nil {
		stage := &fakeTCPPolicyStage{
			operations: applied,
			state:      fakeTCPPolicyStageRollbackPending,
			owner:      transaction.identity,
		}
		transaction.stage = stage
		return stage, errors.Join(cause, fmt.Errorf("FakeTCP policy rollback incomplete: %w", rollbackErr))
	}
	return nil, cause
}

func rollbackFakeTCPPolicyOperationsLocked(
	ctx context.Context,
	transaction *fakeTCPPolicyGenerationTransaction,
	applied []fakeTCPPolicyOperation,
) error {
	if err := rollbackFakeTCPPolicyPhase(
		applied,
		fakeTCPPolicyPhaseInterface,
		fakeTCPPolicyRollbackExact,
	); err != nil {
		return fmt.Errorf("remove FakeTCP interface reachability latches: %w", err)
	}
	if err := transaction.assertHeldLocked(ctx); err != nil {
		return err
	}
	if err := transaction.isolation.Quiesce(ctx, transaction.generation); err != nil {
		return fmt.Errorf(
			"quiesce FakeTCP policy generation %d after removing interface latches: %w",
			transaction.generation,
			err,
		)
	}
	if err := transaction.assertHeldLocked(ctx); err != nil {
		return err
	}
	if err := rollbackFakeTCPPolicyPhase(
		applied,
		fakeTCPPolicyPhasePort,
		fakeTCPPolicyRollbackExact,
	); err != nil {
		return fmt.Errorf("remove FakeTCP managed ports: %w", err)
	}
	if err := transaction.assertHeldLocked(ctx); err != nil {
		return err
	}
	if err := rollbackFakeTCPPolicyPhase(
		applied,
		fakeTCPPolicyPhaseControl,
		fakeTCPPolicyRollbackQuiescedControl,
	); err != nil {
		return fmt.Errorf("remove FakeTCP control policies: %w", err)
	}
	return nil
}

func rollbackFakeTCPPolicyPhase(
	applied []fakeTCPPolicyOperation,
	phase fakeTCPPolicyPhase,
	mode fakeTCPPolicyRollbackMode,
) error {
	var rollbackErrors []error
	for index := len(applied) - 1; index >= 0; index-- {
		if applied[index].phase != phase {
			continue
		}
		if err := applied[index].rollback(mode); err != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf(
				"rollback %s: %w", applied[index].label, err,
			))
		}
	}
	return errors.Join(rollbackErrors...)
}
