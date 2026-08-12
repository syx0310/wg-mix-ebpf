package dataplane

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"

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
}

type supervisedFakeTCPRuntime struct {
	key     fakeTCPRuntimeDesiredKey
	runtime fakeTCPRuntimeService
	cancel  context.CancelFunc
	done    chan struct{}

	mu            sync.Mutex
	runErr        error
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
		cancel:  cancel,
		done:    make(chan struct{}),
	}
	supervisor.storeCurrent(entry)
	go entry.run(runCtx)
	return nil
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
	supervisor.mu.Unlock()
}

func (runtime *supervisedFakeTCPRuntime) run(ctx context.Context) {
	err := runtime.runtime.Run(ctx)
	runtime.mu.Lock()
	if err == nil && !runtime.stopRequested {
		err = errFakeTCPRuntimeExited
	}
	runtime.runErr = err
	close(runtime.done)
	runtime.mu.Unlock()
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
	runtime.mu.Unlock()

	err := stopper.RequestStop()
	cancel()
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
