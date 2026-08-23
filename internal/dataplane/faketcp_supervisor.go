package dataplane

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/faketcp"
)

var (
	errFakeTCPRuntimeExited = errors.New(
		"FakeTCP userspace runtime exited without a stop request",
	)
	errFakeTCPRuntimeStopping = errors.New(
		"FakeTCP userspace runtime stop is already in progress",
	)
)

// fakeTCPRuntimeDesiredKey is an opaque digest of every input that affects one
// FakeTCP runtime generation. It is deliberately comparable so an
// identical daemon reconcile is a no-op without exposing cipher material.
type fakeTCPRuntimeDesiredKey [32]byte

type fakeTCPRuntimeService interface {
	faketcp.RuntimeService
	faketcp.RuntimeStopRequester
	Healthy(context.Context) error
}

type fakeTCPRuntimeBuild func(context.Context) (fakeTCPRuntimeService, error)

type fakeTCPRuntimeStatusProvider interface {
	ProductionStatus(context.Context) (*FakeTCPRuntimeStatus, error)
}

// fakeTCPRuntimeSupervisor is the single userspace ownership boundary for an
// activated FakeTCP generation, including its half-open and SYN quota.
// Ensure and Stop are serialised because collection, TC, XDP, and quota
// ownership must never be split between two runtimes. A successful Ensure
// transfers exactly one runtime to the supervisor; a replacement is not built
// until the prior Run has returned and Close has released its complete owner.
type fakeTCPRuntimeSupervisor struct {
	operationMu sync.Mutex
	mu          sync.Mutex
	current     *supervisedFakeTCPRuntime
	// startupGuardPause prevents a newly built runtime from starting its raw
	// reinjection loop while the temporary nft output guard is installed. The
	// revision permits failure rollback to touch only the transition acquired
	// by that operation. operationMu serialises lifecycle transitions while mu
	// permits status readers to observe draining/held/resuming in real time.
	startupGuardPause         faketcp.StartupGuardPauseStatus
	startupGuardRevision      uint64
	startupGuardLease         StartupGuardLease
	startupGuardReleased      StartupGuardLeaseToken
	startupGuardInnerLease    faketcp.StartupGuardLease
	startupGuardPausedRuntime *supervisedFakeTCPRuntime
}

var _ faketcp.RuntimeStartupGuardPauseStatusProvider = (*fakeTCPRuntimeSupervisor)(nil)

type supervisedFakeTCPRuntime struct {
	key      fakeTCPRuntimeDesiredKey
	runtime  fakeTCPRuntimeService
	runCtx   context.Context
	cancel   context.CancelFunc
	done     chan struct{}
	doneOnce sync.Once

	mu            sync.Mutex
	runErr        error
	runStarted    bool
	stopRequested bool
}

func (supervisor *fakeTCPRuntimeSupervisor) Ensure(
	ctx context.Context,
	key fakeTCPRuntimeDesiredKey,
	build fakeTCPRuntimeBuild,
) error {
	if supervisor == nil {
		return errors.New("FakeTCP runtime supervisor is nil")
	}
	if ctx == nil {
		return errors.New("ensure FakeTCP runtime: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if key == (fakeTCPRuntimeDesiredKey{}) {
		return errors.New("ensure FakeTCP runtime: desired key is empty")
	}
	if build == nil {
		return errors.New("ensure FakeTCP runtime: builder is nil")
	}

	supervisor.operationMu.Lock()
	defer supervisor.operationMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}

	current := supervisor.loadCurrent()
	if current != nil && !current.finished() {
		if current.key == key {
			if current.stopWasRequested() {
				return errFakeTCPRuntimeStopping
			}
			if current.ownerHealthy(ctx) {
				return nil
			}
			// The userspace goroutine can remain alive after an interface or
			// process-owned link disappears. Retire the unhealthy exact owner
			// before rebuilding the same desired generation.
			if err := supervisor.stopAndRetire(ctx, current); err != nil {
				return fmt.Errorf("retire unhealthy FakeTCP generation: %w", err)
			}
			current = nil
		} else {
			// FakeTCP resources are FD-owned and cannot overlap generations.
			// Replace them serially under operationMu: request the old runtime to
			// stop, wait for Run to exit, then close its complete owner before
			// building the new generation. A failed stop/close keeps the old entry
			// quarantined and prevents the replacement build.
			if err := supervisor.stopAndRetire(ctx, current); err != nil {
				return fmt.Errorf("retire changed FakeTCP generation: %w", err)
			}
			current = nil
		}
	}
	if current != nil {
		// A terminal runtime no longer protects traffic.  Retire its complete
		// ownership graph before a same-key restart or a changed generation.
		retireErr := supervisor.retireFinished(current)
		if retireErr != nil {
			return retireErr
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	runtime, err := build(ctx)
	if err != nil {
		if !fakeTCPRuntimeServiceIsNil(runtime) {
			closeErr := closeUnstartedFakeTCPRuntime(runtime)
			err = errors.Join(err, closeErr)
			if closeErr != nil {
				supervisor.storeCurrent(newQuarantinedFakeTCPRuntime(key, runtime))
			}
		}
		return fmt.Errorf("build FakeTCP runtime: %w", err)
	}
	if fakeTCPRuntimeServiceIsNil(runtime) {
		return errors.New("build FakeTCP runtime: builder returned nil")
	}
	if err := ctx.Err(); err != nil {
		closeErr := closeUnstartedFakeTCPRuntime(runtime)
		if closeErr != nil {
			supervisor.storeCurrent(newQuarantinedFakeTCPRuntime(key, runtime))
		}
		return errors.Join(err, closeErr)
	}

	runCtx, cancel := context.WithCancel(context.Background())
	entry := &supervisedFakeTCPRuntime{
		key:     key,
		runtime: runtime,
		runCtx:  runCtx,
		cancel:  cancel,
		done:    make(chan struct{}),
	}
	supervisor.storeCurrent(entry)
	if !supervisor.startupGuardBarrierHeld() {
		if err := entry.start(); err != nil {
			return fmt.Errorf("start FakeTCP runtime: %w", err)
		}
	}
	return nil
}

// QuiesceForStartupGuard drains the sole userspace event loop before nft can
// reject its raw reinjection packets. It deliberately retains the runtime's
// TC/XDP/map owner so managed traffic remains fail-closed. Ensure may replace
// that owner while the barrier is held, but it will stage the replacement
// without starting Run.
func (supervisor *fakeTCPRuntimeSupervisor) QuiesceForStartupGuard(
	ctx context.Context,
) (StartupGuardLease, error) {
	if supervisor == nil {
		return StartupGuardLease{}, errors.New("quiesce FakeTCP runtime for startup guard: supervisor is nil")
	}
	if ctx == nil {
		return StartupGuardLease{}, errors.New("quiesce FakeTCP runtime for startup guard: context is nil")
	}
	supervisor.operationMu.Lock()
	defer supervisor.operationMu.Unlock()
	status := supervisor.StartupGuardPauseStatus()
	if status.Phase == faketcp.StartupGuardPausePhaseHeld {
		return supervisor.borrowHeldStartupGuardLease()
	}
	if err := ctx.Err(); err != nil {
		return StartupGuardLease{}, err
	}
	if status.Phase != faketcp.StartupGuardPausePhaseOpen {
		return StartupGuardLease{}, fmt.Errorf(
			"quiesce FakeTCP runtime for startup guard: invalid pause phase %q",
			status.Phase,
		)
	}
	lease := NewStartupGuardLease()
	acquiredRevision := supervisor.acquireStartupGuardPause(
		lease,
		faketcp.StartupGuardPauseStatus{
			Phase:  faketcp.StartupGuardPausePhaseDraining,
			Reason: faketcp.StartupGuardPauseReasonStartupGuard,
			Since:  time.Now().UTC(),
		},
	)
	rollback := func() {
		supervisor.rollbackNewStartupGuardPause(acquiredRevision, lease)
	}
	current := supervisor.loadCurrent()
	if current == nil || !current.wasStarted() || current.finished() {
		supervisor.holdStartupGuardPause()
		return lease, nil
	}
	pauser, ok := current.runtime.(faketcp.RuntimeStartupGuardPauser)
	if !ok {
		rollback()
		return StartupGuardLease{}, errors.New("quiesce FakeTCP runtime for startup guard: runtime has no pause contract")
	}
	innerLease, err := pauser.PauseForStartupGuard(ctx)
	if err != nil {
		rollback()
		return StartupGuardLease{}, err
	}
	if innerLease.Token.IsZero() {
		// Pause reported success, so admission may already be closed. Keep the
		// outer barrier held even though the leaf violated its lease contract;
		// a later replacement can retire this owner without leaking traffic.
		supervisor.holdStartupGuardPause()
		return StartupGuardLease{}, errors.New("quiesce FakeTCP runtime for startup guard: runtime returned an empty lease")
	}
	supervisor.storeStartupGuardInnerLease(current, innerLease)
	supervisor.holdStartupGuardPause()
	return lease, nil
}

// ResumeAfterStartupGuard starts the staged runtime only after nft cleanup has
// completed. A failed reload intentionally leaves this barrier held: a later
// lifecycle-serialised retry can reuse or replace the staged exact owner and
// then release it after its own guard cleanup.
func (supervisor *fakeTCPRuntimeSupervisor) ResumeAfterStartupGuard(
	ctx context.Context,
	lease StartupGuardLease,
) error {
	if supervisor == nil {
		return errors.New("resume FakeTCP runtime after startup guard: supervisor is nil")
	}
	if ctx == nil {
		return errors.New("resume FakeTCP runtime after startup guard: context is nil")
	}
	supervisor.operationMu.Lock()
	defer supervisor.operationMu.Unlock()
	heldStatus := supervisor.StartupGuardPauseStatus()
	if heldStatus.Phase == faketcp.StartupGuardPausePhaseOpen {
		if supervisor.releasedStartupGuardLeaseMatches(lease) {
			return nil
		}
		return ErrStartupGuardLeaseMismatch
	}
	if heldStatus.Phase != faketcp.StartupGuardPausePhaseHeld {
		return fmt.Errorf(
			"resume FakeTCP runtime after startup guard: invalid pause phase %q",
			heldStatus.Phase,
		)
	}
	if !supervisor.activeStartupGuardLeaseMatches(lease) {
		return ErrStartupGuardLeaseMismatch
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	resumeRevision := supervisor.setStartupGuardPauseState(
		faketcp.StartupGuardPauseStatus{
			Phase:  faketcp.StartupGuardPausePhaseResuming,
			Reason: faketcp.StartupGuardPauseReasonStartupGuard,
			Since:  time.Now().UTC(),
		},
	)
	rollback := func() {
		supervisor.restoreStartupGuardPause(resumeRevision, heldStatus)
	}
	current := supervisor.loadCurrent()
	if current != nil {
		if current.finished() || current.stopWasRequested() {
			rollback()
			return errors.Join(
				errors.New("resume FakeTCP runtime after startup guard: runtime is not startable"),
				wrapFakeTCPRunError(current.terminalError()),
			)
		}
		if current.wasStarted() {
			pauser, ok := current.runtime.(faketcp.RuntimeStartupGuardPauser)
			if !ok {
				rollback()
				return errors.New("resume FakeTCP runtime after startup guard: runtime has no pause contract")
			}
			innerLease, ok := supervisor.loadStartupGuardInnerLease(current)
			if !ok {
				rollback()
				return errors.New("resume FakeTCP runtime after startup guard: runtime has no retained inner lease")
			}
			if err := pauser.ResumeAfterStartupGuard(ctx, innerLease); err != nil {
				rollback()
				return fmt.Errorf("resume FakeTCP runtime after startup guard: %w", err)
			}
			supervisor.clearStartupGuardInnerLease(current)
		} else {
			if err := current.start(); err != nil {
				rollback()
				return fmt.Errorf("resume FakeTCP runtime after startup guard: %w", err)
			}
		}
	}
	supervisor.releaseStartupGuardPause(faketcp.StartupGuardPauseStatus{
		Phase:  faketcp.StartupGuardPausePhaseOpen,
		Reason: faketcp.StartupGuardPauseReasonNone,
		Since:  time.Now().UTC(),
	})
	return nil
}

// StartupGuardPauseStatus returns the supervisor barrier even when there is no
// current runtime owner. That makes initial startup and a held empty barrier
// observable without borrowing status from a staged generation.
func (supervisor *fakeTCPRuntimeSupervisor) StartupGuardPauseStatus() faketcp.StartupGuardPauseStatus {
	if supervisor == nil {
		return faketcp.StartupGuardPauseStatus{
			Phase:  faketcp.StartupGuardPausePhaseStopped,
			Reason: faketcp.StartupGuardPauseReasonRuntimeClosed,
		}
	}
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	status := supervisor.startupGuardPause
	if status.Phase == "" {
		status = faketcp.StartupGuardPauseStatus{
			Phase:  faketcp.StartupGuardPausePhaseOpen,
			Reason: faketcp.StartupGuardPauseReasonNone,
			Since:  time.Now().UTC(),
		}
		supervisor.startupGuardPause = status
		supervisor.startupGuardRevision++
	}
	return status
}

func (supervisor *fakeTCPRuntimeSupervisor) startupGuardBarrierHeld() bool {
	status := supervisor.StartupGuardPauseStatus()
	switch status.Phase {
	case faketcp.StartupGuardPausePhaseDraining,
		faketcp.StartupGuardPausePhaseHeld,
		faketcp.StartupGuardPausePhaseResuming:
		return true
	default:
		return false
	}
}

func (supervisor *fakeTCPRuntimeSupervisor) setStartupGuardPauseState(
	status faketcp.StartupGuardPauseStatus,
) uint64 {
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	if supervisor.startupGuardPause == status {
		return supervisor.startupGuardRevision
	}
	supervisor.startupGuardPause = status
	supervisor.startupGuardRevision++
	return supervisor.startupGuardRevision
}

func (supervisor *fakeTCPRuntimeSupervisor) acquireStartupGuardPause(
	lease StartupGuardLease,
	status faketcp.StartupGuardPauseStatus,
) uint64 {
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	// Quiesce holds operationMu, has observed Open, and minted this valid lease.
	// Status readers cannot mutate these fields, so acquisition is one
	// infallible state commit rather than a check-then-act transition.
	supervisor.startupGuardLease = lease
	supervisor.startupGuardReleased = StartupGuardLeaseToken{}
	supervisor.startupGuardInnerLease = faketcp.StartupGuardLease{}
	supervisor.startupGuardPausedRuntime = nil
	supervisor.startupGuardPause = status
	supervisor.startupGuardRevision++
	return supervisor.startupGuardRevision
}

func (supervisor *fakeTCPRuntimeSupervisor) borrowHeldStartupGuardLease() (
	StartupGuardLease,
	error,
) {
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	if supervisor.startupGuardPause.Phase != faketcp.StartupGuardPausePhaseHeld ||
		!supervisor.startupGuardLease.valid() {
		return StartupGuardLease{}, errors.New("held startup guard barrier has no active lease")
	}
	return borrowedStartupGuardLease(supervisor.startupGuardLease.Token), nil
}

func (supervisor *fakeTCPRuntimeSupervisor) activeStartupGuardLeaseMatches(
	lease StartupGuardLease,
) bool {
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	return lease.valid() && supervisor.startupGuardLease.valid() &&
		supervisor.startupGuardLease.Token == lease.Token
}

func (supervisor *fakeTCPRuntimeSupervisor) releasedStartupGuardLeaseMatches(
	lease StartupGuardLease,
) bool {
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	return lease.valid() && !supervisor.startupGuardReleased.IsZero() &&
		supervisor.startupGuardReleased == lease.Token
}

func (supervisor *fakeTCPRuntimeSupervisor) holdStartupGuardPause() {
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	// operationMu spans acquisition, leaf drain, and this transition. No other
	// lifecycle mutator can change the phase, revision, or token in between;
	// status readers only observe these fields. Keeping this transition
	// infallible avoids a post-leaf validation point that could strand the
	// inner runtime paused.
	supervisor.startupGuardPause = faketcp.StartupGuardPauseStatus{
		Phase:  faketcp.StartupGuardPausePhaseHeld,
		Reason: faketcp.StartupGuardPauseReasonStartupGuard,
		Since:  time.Now().UTC(),
	}
	supervisor.startupGuardRevision++
}

func (supervisor *fakeTCPRuntimeSupervisor) rollbackNewStartupGuardPause(
	expectedRevision uint64,
	lease StartupGuardLease,
) {
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	if expectedRevision == 0 || supervisor.startupGuardRevision != expectedRevision ||
		supervisor.startupGuardPause.Phase != faketcp.StartupGuardPausePhaseDraining ||
		!lease.valid() || !supervisor.startupGuardLease.valid() ||
		supervisor.startupGuardLease.Token != lease.Token {
		return
	}
	supervisor.startupGuardLease = StartupGuardLease{}
	supervisor.startupGuardInnerLease = faketcp.StartupGuardLease{}
	supervisor.startupGuardPausedRuntime = nil
	supervisor.startupGuardPause = faketcp.StartupGuardPauseStatus{
		Phase:  faketcp.StartupGuardPausePhaseOpen,
		Reason: faketcp.StartupGuardPauseReasonNone,
		Since:  time.Now().UTC(),
	}
	supervisor.startupGuardRevision++
}

func (supervisor *fakeTCPRuntimeSupervisor) releaseStartupGuardPause(
	status faketcp.StartupGuardPauseStatus,
) {
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	// Resume pre-validates the active token and retains operationMu through the
	// leaf resume/start and this commit. Therefore the outer release is an
	// infallible commit, not a second validation point after userspace traffic
	// has already resumed.
	supervisor.startupGuardReleased = supervisor.startupGuardLease.Token
	supervisor.startupGuardLease = StartupGuardLease{}
	supervisor.startupGuardInnerLease = faketcp.StartupGuardLease{}
	supervisor.startupGuardPausedRuntime = nil
	supervisor.startupGuardPause = status
	supervisor.startupGuardRevision++
}

func (supervisor *fakeTCPRuntimeSupervisor) storeStartupGuardInnerLease(
	runtime *supervisedFakeTCPRuntime,
	lease faketcp.StartupGuardLease,
) {
	supervisor.mu.Lock()
	supervisor.startupGuardPausedRuntime = runtime
	supervisor.startupGuardInnerLease = lease
	supervisor.mu.Unlock()
}

func (supervisor *fakeTCPRuntimeSupervisor) loadStartupGuardInnerLease(
	runtime *supervisedFakeTCPRuntime,
) (faketcp.StartupGuardLease, bool) {
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	lease := supervisor.startupGuardInnerLease
	return lease, supervisor.startupGuardPausedRuntime == runtime && !lease.Token.IsZero()
}

func (supervisor *fakeTCPRuntimeSupervisor) clearStartupGuardInnerLease(
	runtime *supervisedFakeTCPRuntime,
) {
	supervisor.mu.Lock()
	if supervisor.startupGuardPausedRuntime == runtime {
		supervisor.startupGuardPausedRuntime = nil
		supervisor.startupGuardInnerLease = faketcp.StartupGuardLease{}
	}
	supervisor.mu.Unlock()
}

func (supervisor *fakeTCPRuntimeSupervisor) restoreStartupGuardPause(
	expectedRevision uint64,
	status faketcp.StartupGuardPauseStatus,
) {
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	if supervisor.startupGuardRevision != expectedRevision ||
		supervisor.startupGuardPause.Phase != faketcp.StartupGuardPausePhaseResuming {
		return
	}
	supervisor.startupGuardPause = status
	supervisor.startupGuardRevision++
}

func (supervisor *fakeTCPRuntimeSupervisor) stopAndRetire(
	ctx context.Context,
	current *supervisedFakeTCPRuntime,
) error {
	if current == nil {
		return nil
	}
	stopErr := current.requestStop()
	select {
	case <-current.done:
	case <-ctx.Done():
		return errors.Join(wrapFakeTCPStopError(stopErr), ctx.Err())
	}
	closeErr := current.runtime.Close()
	if closeErr == nil {
		supervisor.clearCurrent(current)
	}
	return errors.Join(
		wrapFakeTCPRunError(current.terminalError()),
		wrapFakeTCPStopError(stopErr),
		wrapFakeTCPCloseError(closeErr),
	)
}

func (supervisor *fakeTCPRuntimeSupervisor) Healthy(
	key fakeTCPRuntimeDesiredKey,
) bool {
	if supervisor == nil || key == (fakeTCPRuntimeDesiredKey{}) {
		return false
	}
	current := supervisor.loadCurrent()
	return current != nil && current.key == key && current.ownerHealthy(context.Background())
}

// HealthyCurrent reports whether the sole process-owned runtime is still
// running. Callers use this only after their unchanged control-state
// fingerprint has selected FakeTCP; desired-key equality remains the stronger
// check used by Ensure itself.
func (supervisor *fakeTCPRuntimeSupervisor) HealthyCurrent(ctx context.Context) bool {
	if supervisor == nil {
		return false
	}
	if ctx == nil || ctx.Err() != nil {
		return false
	}
	current := supervisor.loadCurrent()
	return current != nil && current.ownerHealthy(ctx)
}

func (supervisor *fakeTCPRuntimeSupervisor) CurrentProductionStatus(
	ctx context.Context,
) (*FakeTCPRuntimeStatus, error) {
	if supervisor == nil || ctx == nil {
		return nil, errors.New("inspect FakeTCP runtime status: incomplete input")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	current := supervisor.loadCurrent()
	if current == nil {
		return nil, errors.New("inspect FakeTCP runtime status: no runtime owner")
	}
	provider, ok := current.runtime.(fakeTCPRuntimeStatusProvider)
	if !ok {
		return nil, errors.New("inspect FakeTCP runtime status: owner has no production status contract")
	}
	status, err := provider.ProductionStatus(ctx)
	if status == nil {
		return nil, errors.Join(err, errors.New("inspect FakeTCP runtime status: owner returned nil status"))
	}
	var lifecycleErr error
	if current.stopWasRequested() {
		lifecycleErr = errors.Join(lifecycleErr, errFakeTCPRuntimeStopping)
	}
	if current.finished() {
		lifecycleErr = errors.Join(lifecycleErr, current.terminalError())
		if lifecycleErr == nil {
			lifecycleErr = errFakeTCPRuntimeExited
		}
	}
	if lifecycleErr != nil {
		status.Healthy = false
		if status.Error == "" {
			status.Error = lifecycleErr.Error()
		} else {
			status.Error = errors.Join(errors.New(status.Error), lifecycleErr).Error()
		}
	}
	return status, err
}

func (supervisor *fakeTCPRuntimeSupervisor) RuntimeError() error {
	if supervisor == nil {
		return nil
	}
	current := supervisor.loadCurrent()
	if current == nil || !current.finished() {
		return nil
	}
	return current.terminalError()
}

func (supervisor *fakeTCPRuntimeSupervisor) Stop(ctx context.Context) error {
	if supervisor == nil {
		return nil
	}
	if ctx == nil {
		return errors.New("stop FakeTCP runtime: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	supervisor.operationMu.Lock()
	defer supervisor.operationMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	current := supervisor.loadCurrent()
	if current == nil {
		return nil
	}

	// RuntimeStopRequester is explicitly the callback-safe, non-blocking stop
	// contract.  Implementations must only interrupt Run here; the bounded
	// completion wait and all potentially blocking Close work remain below.
	stopErr := current.requestStop()
	select {
	case <-current.done:
	case <-ctx.Done():
		// The runtime remains owned by the supervisor.  In particular, Close is
		// not called while Run may still be using the collection.
		return errors.Join(stopErr, ctx.Err())
	}
	closeErr := current.runtime.Close()
	if closeErr == nil {
		supervisor.clearCurrent(current)
	}
	return errors.Join(
		wrapFakeTCPRunError(current.terminalError()),
		wrapFakeTCPStopError(stopErr),
		wrapFakeTCPCloseError(closeErr),
	)
}

func (supervisor *fakeTCPRuntimeSupervisor) retireFinished(
	current *supervisedFakeTCPRuntime,
) error {
	if current == nil || !current.finished() {
		return errors.New("retire FakeTCP runtime: runtime is not finished")
	}
	closeErr := current.runtime.Close()
	if closeErr == nil {
		supervisor.clearCurrent(current)
	}
	return errors.Join(
		wrapFakeTCPRunError(current.terminalError()),
		wrapFakeTCPCloseError(closeErr),
	)
}

func newQuarantinedFakeTCPRuntime(
	key fakeTCPRuntimeDesiredKey,
	runtime fakeTCPRuntimeService,
) *supervisedFakeTCPRuntime {
	done := make(chan struct{})
	close(done)
	return &supervisedFakeTCPRuntime{
		key: key, runtime: runtime, done: done, stopRequested: true,
		cancel: func() {},
	}
}

func (supervisor *fakeTCPRuntimeSupervisor) loadCurrent() *supervisedFakeTCPRuntime {
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	return supervisor.current
}

func (supervisor *fakeTCPRuntimeSupervisor) storeCurrent(current *supervisedFakeTCPRuntime) {
	supervisor.mu.Lock()
	supervisor.current = current
	supervisor.mu.Unlock()
}

func (supervisor *fakeTCPRuntimeSupervisor) clearCurrent(current *supervisedFakeTCPRuntime) {
	supervisor.mu.Lock()
	if supervisor.current == current {
		supervisor.current = nil
	}
	// The outer lease deliberately survives runtime replacement so a later
	// lifecycle retry can release the resident barrier. The leaf runtime's
	// private token does not: RequestStop/Close invalidates it, and a staged
	// replacement has not acquired an inner admission lease.
	if supervisor.startupGuardPausedRuntime == current {
		supervisor.startupGuardPausedRuntime = nil
		supervisor.startupGuardInnerLease = faketcp.StartupGuardLease{}
	}
	supervisor.mu.Unlock()
}

func (runtime *supervisedFakeTCPRuntime) run(ctx context.Context) {
	err := runtime.runtime.Run(ctx)
	runtime.mu.Lock()
	if err == nil && !runtime.stopRequested {
		err = errFakeTCPRuntimeExited
	}
	runtime.runErr = err
	runtime.mu.Unlock()
	runtime.doneOnce.Do(func() { close(runtime.done) })
}

func (runtime *supervisedFakeTCPRuntime) start() error {
	if runtime == nil {
		return errors.New("runtime is nil")
	}
	runtime.mu.Lock()
	if runtime.runStarted {
		runtime.mu.Unlock()
		return nil
	}
	if runtime.stopRequested {
		runtime.mu.Unlock()
		return errFakeTCPRuntimeStopping
	}
	if runtime.runCtx == nil {
		runtime.mu.Unlock()
		return errors.New("runtime context is nil")
	}
	runtime.runStarted = true
	ctx := runtime.runCtx
	runtime.mu.Unlock()
	go runtime.run(ctx)
	return nil
}

func (runtime *supervisedFakeTCPRuntime) wasStarted() bool {
	if runtime == nil {
		return false
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.runStarted
}

func (runtime *supervisedFakeTCPRuntime) requestStop() error {
	runtime.mu.Lock()
	if runtime.stopRequested {
		runtime.mu.Unlock()
		return nil
	}
	runtime.stopRequested = true
	stopper := runtime.runtime
	cancel := runtime.cancel
	started := runtime.runStarted
	runtime.mu.Unlock()

	err := stopper.RequestStop()
	cancel()
	if !started {
		runtime.doneOnce.Do(func() { close(runtime.done) })
	}
	return err
}

func (runtime *supervisedFakeTCPRuntime) finished() bool {
	if runtime == nil {
		return true
	}
	select {
	case <-runtime.done:
		return true
	default:
		return false
	}
}

func (runtime *supervisedFakeTCPRuntime) stopWasRequested() bool {
	if runtime == nil {
		return false
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.stopRequested
}

func (runtime *supervisedFakeTCPRuntime) ownerHealthy(ctx context.Context) bool {
	if runtime == nil || ctx == nil || ctx.Err() != nil ||
		runtime.stopWasRequested() || runtime.finished() {
		return false
	}
	return runtime.runtime.Healthy(ctx) == nil
}

func (runtime *supervisedFakeTCPRuntime) terminalError() error {
	if runtime == nil || !runtime.finished() {
		return nil
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.runErr
}

func closeUnstartedFakeTCPRuntime(runtime fakeTCPRuntimeService) error {
	if fakeTCPRuntimeServiceIsNil(runtime) {
		return nil
	}
	if err := runtime.Close(); err != nil {
		return fmt.Errorf("close unstarted FakeTCP runtime: %w", err)
	}
	return nil
}

func wrapFakeTCPRunError(err error) error {
	if err == nil || errors.Is(err, context.Canceled) {
		return nil
	}
	return fmt.Errorf("FakeTCP runtime stopped: %w", err)
}

func wrapFakeTCPStopError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("request FakeTCP runtime stop: %w", err)
}

func wrapFakeTCPCloseError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("close FakeTCP runtime owner: %w", err)
}

func fakeTCPRuntimeServiceIsNil(runtime fakeTCPRuntimeService) bool {
	if runtime == nil {
		return true
	}
	value := reflect.ValueOf(runtime)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
