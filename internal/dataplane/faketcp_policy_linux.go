//go:build linux

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"reflect"
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
// lifecycle: Stage requires a closed gate, Activate precedes selector commit,
// and Quiesce seals and drains before policy removal.
type fakeTCPPolicyGenerationIsolationBackend interface {
	AssertInactive(context.Context, uint64) error
	Activate(context.Context, uint64) error
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
	mu                  sync.Mutex
	plan                *fakeTCPPolicyGenerationPlan
	lifecyclePath       string
	lifecycleLease      *lockfile.LifecycleLease
	closeLifecycleLease func(*lockfile.LifecycleLease) error
	isolation           fakeTCPPolicyGenerationIsolationBackend
	identity            *fakeTCPPolicyGenerationIdentity
	stage               *fakeTCPPolicyStage
	runtimeClaim        *fakeTCPPolicyRuntimeBuildClaim
	activated           bool
	closed              bool
}

// fakeTCPPolicyRuntimeBuildClaim is an exclusive, single-use ownership token
// for composing one fresh generation transaction into a complete runtime. A
// successful claim transfers transaction ownership to the runtime builder;
// a failed claim changes no transaction state and leaves ownership with the
// caller. While the token is live, ordinary transaction entrypoints reject
// access so no second builder or caller can interleave generation mutations.
type fakeTCPPolicyRuntimeBuildClaim struct {
	transaction *fakeTCPPolicyGenerationTransaction
}

func newFakeTCPPolicyGenerationTransaction(
	ctx context.Context,
	plan *fakeTCPPolicyGenerationPlan,
	lifecycleLease *lockfile.LifecycleLease,
	isolation fakeTCPPolicyGenerationIsolationBackend,
) (*fakeTCPPolicyGenerationTransaction, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context is nil", errFakeTCPPolicyGenerationLeaseRequired)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ownedPlan := plan.clone()
	if err := validateFakeTCPPolicyGenerationPlan(ownedPlan); err != nil {
		return nil, fmt.Errorf("%w: invalid generation plan: %v", errFakeTCPPolicyGenerationLeaseRequired, err)
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
		plan:           ownedPlan,
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
		transaction.plan == nil || transaction.plan.generation == 0 {
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
	return transaction.assertAccessLocked(ctx, nil)
}

func (transaction *fakeTCPPolicyGenerationTransaction) assertAccessLocked(
	ctx context.Context,
	claim *fakeTCPPolicyRuntimeBuildClaim,
) error {
	if err := transaction.assertHeldLocked(ctx); err != nil {
		return err
	}
	if claim == nil {
		if transaction.runtimeClaim != nil {
			return errors.New("FakeTCP generation transaction is exclusively claimed by a runtime build")
		}
		return nil
	}
	if claim.transaction != transaction || transaction.runtimeClaim != claim {
		return errors.New("FakeTCP runtime build claim does not own this generation transaction")
	}
	return nil
}

// claimRuntimeBuild atomically verifies that the transaction is held, open,
// fresh, and unclaimed before installing the exclusive build token. No
// collection or dataplane ownership may move to a builder before this returns
// successfully.
func (transaction *fakeTCPPolicyGenerationTransaction) claimRuntimeBuild(
	ctx context.Context,
) (*fakeTCPPolicyRuntimeBuildClaim, error) {
	if transaction == nil {
		return nil, fmt.Errorf("claim FakeTCP runtime build: %w", errFakeTCPPolicyGenerationLeaseRequired)
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if err := transaction.assertHeldLocked(ctx); err != nil {
		return nil, fmt.Errorf("claim FakeTCP runtime build: %w", err)
	}
	if transaction.stage != nil {
		return nil, errors.New("claim FakeTCP runtime build: generation transaction is not fresh")
	}
	if transaction.runtimeClaim != nil {
		return nil, errors.New("claim FakeTCP runtime build: generation transaction is already claimed")
	}
	claim := &fakeTCPPolicyRuntimeBuildClaim{transaction: transaction}
	transaction.runtimeClaim = claim
	return claim, nil
}

func (claim *fakeTCPPolicyRuntimeBuildClaim) assertHeld(ctx context.Context) error {
	if claim == nil || claim.transaction == nil {
		return fmt.Errorf("%w: runtime build claim is nil", errFakeTCPPolicyGenerationLeaseRequired)
	}
	claim.transaction.mu.Lock()
	defer claim.transaction.mu.Unlock()
	return claim.transaction.assertAccessLocked(ctx, claim)
}

func (claim *fakeTCPPolicyRuntimeBuildClaim) policyGeneration() uint64 {
	if claim == nil || claim.transaction == nil || claim.transaction.plan == nil {
		return 0
	}
	return claim.transaction.plan.generation
}

func (transaction *fakeTCPPolicyGenerationTransaction) policyGeneration() uint64 {
	if transaction == nil || transaction.plan == nil {
		return 0
	}
	return transaction.plan.generation
}

func (claim *fakeTCPPolicyRuntimeBuildClaim) policyPlan() *fakeTCPPolicyGenerationPlan {
	if claim == nil || claim.transaction == nil {
		return nil
	}
	claim.transaction.mu.Lock()
	defer claim.transaction.mu.Unlock()
	return claim.transaction.plan.clone()
}

// Close releases the transaction's retained lifecycle lease. It refuses to
// release ownership while a stage can still require rollback.
func (transaction *fakeTCPPolicyGenerationTransaction) Close() error {
	return transaction.closeForRuntimeClaim(nil)
}

// isClosed reports whether the transaction has irreversibly consumed its
// retained lifecycle lease. Factory cleanup uses this only to distinguish a
// builder-owned terminal path from a pre-claim path which it must close.
func (transaction *fakeTCPPolicyGenerationTransaction) isClosed() bool {
	if transaction == nil {
		return true
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	return transaction.closed
}

func (claim *fakeTCPPolicyRuntimeBuildClaim) Close() error {
	if claim == nil || claim.transaction == nil {
		return nil
	}
	return claim.transaction.closeForRuntimeClaim(claim)
}

// commitRuntimeBuild validates and transfers the program-array and policy
// stages in one transaction-lock critical section. A validation error leaves
// both stages rollback-owned. Once committed is true, the transaction and its
// lease handle are irreversibly closed even if closing the underlying file
// descriptor reports an error; callers must tear down the now-reachable
// runtime instead of attempting rollback through a consumed claim.
func (claim *fakeTCPPolicyRuntimeBuildClaim) commitRuntimeBuild(
	ctx context.Context,
	policyStage *fakeTCPPolicyStage,
	programStage *fakeTCPProgramArrayStage,
) (committed bool, returnErr error) {
	if claim == nil || claim.transaction == nil {
		return false, errFakeTCPPolicyGenerationLeaseRequired
	}
	transaction := claim.transaction
	transaction.mu.Lock()
	if err := transaction.assertAccessLocked(ctx, claim); err != nil {
		transaction.mu.Unlock()
		return false, err
	}
	if policyStage == nil || transaction.stage != policyStage ||
		policyStage.owner != transaction.identity {
		transaction.mu.Unlock()
		return false, errors.New("commit FakeTCP runtime: policy stage is not owned by the generation transaction")
	}
	if policyStage.state != fakeTCPPolicyStageActive {
		transaction.mu.Unlock()
		return false, errors.New("commit FakeTCP runtime: policy stage is not rollback-owned")
	}
	if policyStage.collectionOwner == nil {
		transaction.mu.Unlock()
		return false, errors.New("commit FakeTCP runtime: policy stage has no collection owner")
	}
	if programStage == nil || programStage.state != fakeTCPProgramArrayStageActive {
		transaction.mu.Unlock()
		return false, errors.New("commit FakeTCP runtime: program-array stage is not rollback-owned")
	}
	if !transaction.activated {
		transaction.mu.Unlock()
		return false, errors.New("commit FakeTCP runtime: generation barrier is not active")
	}

	policyStage.operations = nil
	policyStage.state = fakeTCPPolicyStageDisarmed
	programStage.state = fakeTCPProgramArrayStageDisarmed
	transaction.closed = true
	transaction.runtimeClaim = nil
	lease := transaction.lifecycleLease
	transaction.lifecycleLease = nil
	closeLease := transaction.closeLifecycleLease
	transaction.mu.Unlock()

	if lease == nil {
		return true, nil
	}
	if closeLease == nil {
		closeLease = (*lockfile.LifecycleLease).Close
	}
	if err := closeLease(lease); err != nil {
		return true, fmt.Errorf("close committed FakeTCP generation lifecycle lease: %w", err)
	}
	return true, nil
}

func (transaction *fakeTCPPolicyGenerationTransaction) closeForRuntimeClaim(
	claim *fakeTCPPolicyRuntimeBuildClaim,
) error {
	if transaction == nil {
		return nil
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.closed {
		return nil
	}
	if claim == nil && transaction.runtimeClaim != nil {
		return errors.New("cannot close FakeTCP generation transaction claimed by a runtime build")
	}
	if claim != nil &&
		(claim.transaction != transaction || transaction.runtimeClaim != claim) {
		return errors.New("cannot close FakeTCP generation transaction through a foreign runtime build claim")
	}
	if transaction.stage != nil &&
		(transaction.stage.state == fakeTCPPolicyStageActive ||
			transaction.stage.state == fakeTCPPolicyStageRollbackPending) {
		return errors.New("cannot close FakeTCP generation transaction with a live policy stage")
	}
	if transaction.activated {
		return errors.New("cannot close FakeTCP generation transaction with an active barrier")
	}
	transaction.closed = true
	transaction.runtimeClaim = nil
	lease := transaction.lifecycleLease
	transaction.lifecycleLease = nil
	if lease == nil {
		return nil
	}
	closeLease := transaction.closeLifecycleLease
	if closeLease == nil {
		closeLease = (*lockfile.LifecycleLease).Close
	}
	return closeLease(lease)
}

// Stage stages one previously absent generation while retaining the generation
// transaction lease. The interface marker is the XDP reachability latch and is
// therefore always written last. This helper deliberately does not commit
// control_map or attach a program; the outer runtime transaction publishes the
// fully staged generation once through experimentalCoreStage.CommitControl.
func (transaction *fakeTCPPolicyGenerationTransaction) Stage(
	ctx context.Context,
	maps fakeTCPPolicyMaps,
) (*fakeTCPPolicyStage, error) {
	return transaction.stageForRuntimeClaim(ctx, nil, maps)
}

func (claim *fakeTCPPolicyRuntimeBuildClaim) Stage(
	ctx context.Context,
	maps fakeTCPPolicyMaps,
) (*fakeTCPPolicyStage, error) {
	if claim == nil || claim.transaction == nil {
		return nil, fmt.Errorf("stage FakeTCP policy: %w", errFakeTCPPolicyGenerationLeaseRequired)
	}
	return claim.transaction.stageForRuntimeClaim(ctx, claim, maps)
}

func (transaction *fakeTCPPolicyGenerationTransaction) stageForRuntimeClaim(
	ctx context.Context,
	claim *fakeTCPPolicyRuntimeBuildClaim,
	maps fakeTCPPolicyMaps,
) (*fakeTCPPolicyStage, error) {
	if transaction == nil {
		return nil, fmt.Errorf("stage FakeTCP policy: %w", errFakeTCPPolicyGenerationLeaseRequired)
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if err := transaction.assertAccessLocked(ctx, claim); err != nil {
		return nil, fmt.Errorf("stage FakeTCP policy: %w", err)
	}
	if transaction.stage != nil {
		return nil, errors.New("stage FakeTCP policy: generation transaction is single-use")
	}
	if maps.ControlPolicies == nil || maps.ManagedPorts == nil || maps.ManagedInterfaces == nil {
		return nil, errors.New("stage FakeTCP policy: all three experimental policy maps are required")
	}
	generation := transaction.plan.generation
	if err := transaction.isolation.AssertInactive(ctx, generation); err != nil {
		return nil, fmt.Errorf(
			"stage FakeTCP policy: prove generation %d is inactive: %w",
			generation,
			err,
		)
	}

	operations := fakeTCPPolicyOperations(maps, transaction.plan)
	// Reject the whole target generation before the first write if any exact
	// key already exists. In particular, this prevents a reload from resetting
	// the BPF-owned virtual_time_nanos cursor.
	for _, operation := range operations {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := operation.requireAbsent(); err != nil {
			return nil, fmt.Errorf("stage FakeTCP policy preflight %s: %w", operation.label, err)
		}
	}

	applied := make([]fakeTCPPolicyOperation, 0, len(operations))
	for _, operation := range operations {
		if err := ctx.Err(); err != nil {
			return transaction.failStageLocked(ctx, err, applied)
		}
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
	if err := ctx.Err(); err != nil {
		return transaction.failStageLocked(ctx, err, applied)
	}
	stage := &fakeTCPPolicyStage{
		operations: applied,
		owner:      transaction.identity,
	}
	transaction.stage = stage
	return stage, nil
}

// Activate opens a complete stage while the selector is still zero.
func (claim *fakeTCPPolicyRuntimeBuildClaim) Activate(
	ctx context.Context,
	stage *fakeTCPPolicyStage,
) error {
	if claim == nil || claim.transaction == nil {
		return fmt.Errorf("activate FakeTCP policy generation: %w", errFakeTCPPolicyGenerationLeaseRequired)
	}
	transaction := claim.transaction
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if err := transaction.assertStageLocked(ctx, claim, stage); err != nil {
		return fmt.Errorf("activate FakeTCP policy generation: %w", err)
	}
	if stage.state != fakeTCPPolicyStageActive {
		return errors.New("activate FakeTCP policy generation: policy stage is not rollback-owned")
	}
	if transaction.activated {
		return errors.New("activate FakeTCP policy generation: barrier is already active")
	}
	if err := transaction.isolation.Activate(ctx, transaction.plan.generation); err != nil {
		return fmt.Errorf(
			"activate FakeTCP policy generation %d: %w",
			transaction.plan.generation,
			err,
		)
	}
	transaction.activated = true
	return nil
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

// Rollback seals and drains before removing interface, port, and control keys.
// Failure leaves the same stage and isolation owner retryable.
func (transaction *fakeTCPPolicyGenerationTransaction) Rollback(
	ctx context.Context,
	stage *fakeTCPPolicyStage,
) error {
	return transaction.rollbackForRuntimeClaim(ctx, nil, stage)
}

func (claim *fakeTCPPolicyRuntimeBuildClaim) Rollback(
	ctx context.Context,
	stage *fakeTCPPolicyStage,
) error {
	if claim == nil || claim.transaction == nil {
		return errFakeTCPPolicyGenerationLeaseRequired
	}
	return claim.transaction.rollbackForRuntimeClaim(ctx, claim, stage)
}

func (transaction *fakeTCPPolicyGenerationTransaction) rollbackForRuntimeClaim(
	ctx context.Context,
	claim *fakeTCPPolicyRuntimeBuildClaim,
	stage *fakeTCPPolicyStage,
) error {
	if transaction == nil {
		return errFakeTCPPolicyGenerationLeaseRequired
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if err := transaction.assertStageLocked(ctx, claim, stage); err != nil {
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
	transaction.activated = false
	return nil
}

// Disarm transfers responsibility for the staged entries to the successful
// outer transaction. It refuses to hide a partially failed rollback.
func (transaction *fakeTCPPolicyGenerationTransaction) Disarm(
	ctx context.Context,
	stage *fakeTCPPolicyStage,
) error {
	return transaction.disarmForRuntimeClaim(ctx, nil, stage)
}

func (claim *fakeTCPPolicyRuntimeBuildClaim) Disarm(
	ctx context.Context,
	stage *fakeTCPPolicyStage,
) error {
	if claim == nil || claim.transaction == nil {
		return errFakeTCPPolicyGenerationLeaseRequired
	}
	return claim.transaction.disarmForRuntimeClaim(ctx, claim, stage)
}

func (transaction *fakeTCPPolicyGenerationTransaction) disarmForRuntimeClaim(
	ctx context.Context,
	claim *fakeTCPPolicyRuntimeBuildClaim,
	stage *fakeTCPPolicyStage,
) error {
	if transaction == nil {
		return errFakeTCPPolicyGenerationLeaseRequired
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if err := transaction.assertStageLocked(ctx, claim, stage); err != nil {
		return err
	}
	switch stage.state {
	case fakeTCPPolicyStageActive:
		if transaction.activated {
			return errors.New("cannot disarm FakeTCP policy stage outside the combined runtime commit")
		}
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
	return transaction.bindStageCollectionOwnerForRuntimeClaim(ctx, nil, stage, owner)
}

func (claim *fakeTCPPolicyRuntimeBuildClaim) bindStageCollectionOwner(
	ctx context.Context,
	stage *fakeTCPPolicyStage,
	owner *experimentalCollectionOwner,
) error {
	if claim == nil || claim.transaction == nil {
		return errFakeTCPPolicyGenerationLeaseRequired
	}
	return claim.transaction.bindStageCollectionOwnerForRuntimeClaim(ctx, claim, stage, owner)
}

func (transaction *fakeTCPPolicyGenerationTransaction) bindStageCollectionOwnerForRuntimeClaim(
	ctx context.Context,
	claim *fakeTCPPolicyRuntimeBuildClaim,
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
	if err := transaction.assertStageLocked(ctx, claim, stage); err != nil {
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
	return transaction.releaseStageAfterCollectionCloseForRuntimeClaim(ctx, nil, stage, proof)
}

func (claim *fakeTCPPolicyRuntimeBuildClaim) releaseStageAfterCollectionClose(
	ctx context.Context,
	stage *fakeTCPPolicyStage,
	proof *experimentalCollectionReleaseProof,
) error {
	if claim == nil || claim.transaction == nil {
		return errFakeTCPPolicyGenerationLeaseRequired
	}
	return claim.transaction.releaseStageAfterCollectionCloseForRuntimeClaim(
		ctx, claim, stage, proof,
	)
}

func (transaction *fakeTCPPolicyGenerationTransaction) releaseStageAfterCollectionCloseForRuntimeClaim(
	ctx context.Context,
	claim *fakeTCPPolicyRuntimeBuildClaim,
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
	if err := transaction.assertStageLocked(ctx, claim, stage); err != nil {
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
	claim *fakeTCPPolicyRuntimeBuildClaim,
	stage *fakeTCPPolicyStage,
) error {
	if err := transaction.assertAccessLocked(ctx, claim); err != nil {
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
	plan *fakeTCPPolicyGenerationPlan,
) []fakeTCPPolicyOperation {
	operations := make([]fakeTCPPolicyOperation, 0,
		len(plan.controlPolicies)+len(plan.managedPorts)+len(plan.managedInterfaces))

	for _, entry := range plan.controlPolicies {
		operations = append(operations, newFakeTCPPolicyOperationWithComparator(
			maps.ControlPolicies,
			fakeTCPControlPolicyMapName,
			fakeTCPPolicyPhaseControl,
			entry.Key,
			entry.Value,
			fakeTCPControlPolicyRollbackMatches,
		))
	}

	for _, entry := range plan.managedPorts {
		operations = append(operations, newFakeTCPPolicyOperation(
			maps.ManagedPorts,
			fakeTCPManagedPortMapName,
			fakeTCPPolicyPhasePort,
			entry.Key,
			entry.Value,
		))
	}

	for _, entry := range plan.managedInterfaces {
		operations = append(operations, newFakeTCPPolicyOperation(
			maps.ManagedInterfaces,
			fakeTCPManagedIfMapName,
			fakeTCPPolicyPhaseInterface,
			entry.Key,
			entry.Value,
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
			// rollback begins only after the gate is sealed and drained.
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
// comparator only after Quiesce succeeds.
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
	if err := transaction.assertHeldLocked(ctx); err != nil {
		return err
	}
	if err := transaction.isolation.Quiesce(ctx, transaction.plan.generation); err != nil {
		return fmt.Errorf(
			"quiesce FakeTCP policy generation %d before removing policy: %w",
			transaction.plan.generation,
			err,
		)
	}
	if err := transaction.assertHeldLocked(ctx); err != nil {
		return err
	}
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
