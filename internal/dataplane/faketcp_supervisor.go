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
	errFakeTCPRuntimeReplacementUnsafe = errors.New(
		"live experimental FakeTCP generation replacement is not yet atomic",
	)
	errFakeTCPRuntimeExited = errors.New(
		"experimental FakeTCP userspace runtime exited without a stop request",
	)
)

// fakeTCPRuntimeDesiredKey is an opaque digest of every input that affects one
// experimental runtime generation.  It is deliberately comparable so an
// identical daemon reconcile is a no-op without exposing cipher material.
type fakeTCPRuntimeDesiredKey [32]byte

type fakeTCPRuntimeService interface {
	faketcp.RuntimeService
	faketcp.RuntimeStopRequester
}

type fakeTCPRuntimeBuild func(context.Context) (fakeTCPRuntimeService, error)

// fakeTCPRuntimeSupervisor is the single userspace ownership boundary for an
// activated experimental generation.  Ensure and Stop are serialised because
// collection, TC, and XDP ownership must never be split between two callers.
// A successful Ensure transfers exactly one runtime to the supervisor; Close
// is only called after its Run method has returned.
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
		return errors.New("experimental FakeTCP runtime supervisor is nil")
	}
	if ctx == nil {
		return errors.New("ensure experimental FakeTCP runtime: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if key == (fakeTCPRuntimeDesiredKey{}) {
		return errors.New("ensure experimental FakeTCP runtime: desired key is empty")
	}
	if build == nil {
		return errors.New("ensure experimental FakeTCP runtime: builder is nil")
	}

	supervisor.operationMu.Lock()
	defer supervisor.operationMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}

	current := supervisor.loadCurrent()
	if current != nil && !current.finished() {
		if current.key == key {
			return nil
		}
		return fmt.Errorf(
			"%w: stop the active generation before applying changed FakeTCP state",
			errFakeTCPRuntimeReplacementUnsafe,
		)
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
			err = errors.Join(err, closeUnstartedFakeTCPRuntime(runtime))
		}
		return fmt.Errorf("build experimental FakeTCP runtime: %w", err)
	}
	if fakeTCPRuntimeServiceIsNil(runtime) {
		return errors.New("build experimental FakeTCP runtime: builder returned nil")
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(err, closeUnstartedFakeTCPRuntime(runtime))
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

func (supervisor *fakeTCPRuntimeSupervisor) Healthy(
	key fakeTCPRuntimeDesiredKey,
) bool {
	if supervisor == nil || key == (fakeTCPRuntimeDesiredKey{}) {
		return false
	}
	current := supervisor.loadCurrent()
	return current != nil && current.key == key && !current.finished()
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
		return errors.New("stop experimental FakeTCP runtime: context is nil")
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
	supervisor.clearCurrent(current)
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
		return errors.New("retire experimental FakeTCP runtime: runtime is not finished")
	}
	closeErr := current.runtime.Close()
	supervisor.clearCurrent(current)
	return errors.Join(
		wrapFakeTCPRunError(current.terminalError()),
		wrapFakeTCPCloseError(closeErr),
	)
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
		return fmt.Errorf("close unstarted experimental FakeTCP runtime: %w", err)
	}
	return nil
}

func wrapFakeTCPRunError(err error) error {
	if err == nil || errors.Is(err, context.Canceled) {
		return nil
	}
	return fmt.Errorf("experimental FakeTCP runtime stopped: %w", err)
}

func wrapFakeTCPStopError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("request experimental FakeTCP runtime stop: %w", err)
}

func wrapFakeTCPCloseError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("close experimental FakeTCP runtime owner: %w", err)
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
