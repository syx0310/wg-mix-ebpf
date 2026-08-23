package faketcp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sync"
	"time"
)

var (
	ErrEventRuntimeClosed     = errors.New("faketcp event runtime is closed")
	ErrEventRuntimeAlreadyRun = errors.New("faketcp event runtime has already run")
	ErrEventSamplesLost       = errors.New("faketcp event samples were lost")
)

// EventRecord is one owned event sample. LostSamples may come from a perf
// reader, the production ring error counter, or a capture-sequence gap.
// Losing a control or first-packet event makes userspace handshake state
// unknowable, so EventRuntime treats any loss as a terminal, fail-closed
// error.
type EventRecord struct {
	RawSample   []byte
	LostSamples uint64

	ownedSample    ownedDecodedEvent
	hasOwnedSample bool
}

// EventReader is the common boundary for BPF ring-buffer and perf-event-array
// readers. Read must return a RawSample that remains owned by the caller.
// SetDeadline must interrupt Read with an error matching
// os.ErrDeadlineExceeded. Close must interrupt Read with os.ErrClosed and be
// idempotent.
type EventReader interface {
	Read() (EventRecord, error)
	SetDeadline(time.Time)
	Close() error
}

// EventController is the subset of Controller used by the daemon-facing event
// runtime. Keeping this interface in faketcp avoids importing dataplane or
// daemon packages into the slow path.
type EventController interface {
	HandleSample(context.Context, []byte) ([]Action, error)
	Tick(context.Context) ([]Action, error)
	Close() error
}

type eventRecordHandler func(context.Context, EventRecord) ([]Action, error)

// RuntimeService is the lifecycle contract a daemon or generation owner may
// retain without depending on the concrete event-loop implementation.
type RuntimeService interface {
	Run(context.Context) error
	Close() error
}

// RuntimeStopRequester is the non-blocking-shutdown boundary that callbacks
// running on a RuntimeService goroutine may use. A callback must not invoke
// RuntimeService.Close synchronously because Close is a completion fence over
// Run; it requests a stop and lets the owner call Close after Run returns.
type RuntimeStopRequester interface {
	RequestStop() error
}

// RuntimeStartupGuardPauser temporarily fences event delivery without ending
// the one-shot Run lifecycle. Reconcile uses it to drain raw reinjection before
// installing the temporary nft startup guard, then resumes the identical
// runtime after that guard has been removed. Pause is failure-atomic: an error
// may release only the barrier acquired by that call and must preserve a
// barrier that was already held when the call began. A held barrier returns
// its existing opaque token with Acquired false so a lifecycle-serialised
// retry can release it after proving the kernel guard absent. Resume is also
// failure-atomic: an error or token mismatch leaves the established barrier
// held.
type RuntimeStartupGuardPauser interface {
	PauseForStartupGuard(context.Context) (StartupGuardLease, error)
	ResumeAfterStartupGuard(context.Context, StartupGuardLease) error
}

type EventRuntimeOptions struct {
	// PollInterval bounds cancellation latency while Read is idle.
	PollInterval time.Duration
	// TickInterval controls handshake retries, keepalives, and idle expiry.
	TickInterval time.Duration
	Now          func() time.Time
}

// EventRuntime serialises event delivery and timer ticks through one
// Controller. It owns both Reader and Controller on successful construction.
// Run is deliberately one-shot: replaying a consumed ring record against the
// same Engine is not a supported recovery mechanism.
type EventRuntime struct {
	mu sync.Mutex

	reader        EventReader
	controller    EventController
	handleRecord  eventRecordHandler
	opts          EventRuntimeOptions
	runDone       chan struct{}
	closeDone     chan struct{}
	readerDone    chan struct{}
	runStarted    bool
	running       bool
	stopAsked     bool
	shutdown      bool
	closing       bool
	closed        bool
	readerClosing bool
	readerErr     error
	closeErr      error
	guardPhase    StartupGuardPausePhase
	guardReason   StartupGuardPauseReason
	guardSince    time.Time
	guardRevision uint64
	guardLease    StartupGuardLease
	guardReleased StartupGuardLeaseToken
	activeWork    int
	stateChanged  chan struct{}
}

var _ RuntimeService = (*EventRuntime)(nil)
var _ RuntimeStopRequester = (*EventRuntime)(nil)
var _ RuntimeStartupGuardPauser = (*EventRuntime)(nil)
var _ RuntimeStartupGuardPauseStatusProvider = (*EventRuntime)(nil)

func NewEventRuntime(
	reader EventReader,
	controller EventController,
	options EventRuntimeOptions,
) (*EventRuntime, error) {
	return newEventRuntime(
		reader,
		controller,
		options,
		func(ctx context.Context, record EventRecord) ([]Action, error) {
			if len(record.RawSample) == 0 {
				return nil, errors.New("faketcp event reader returned an empty sample")
			}
			return controller.HandleSample(ctx, record.RawSample)
		},
	)
}

// newOwnedEventRuntime selects the production-only decoded event boundary at
// construction. Its loop never falls back to the public raw-sample decoder.
func newOwnedEventRuntime(
	reader EventReader,
	controller *Controller,
	options EventRuntimeOptions,
) (*EventRuntime, error) {
	return newEventRuntime(
		reader,
		controller,
		options,
		func(ctx context.Context, record EventRecord) ([]Action, error) {
			if !record.hasOwnedSample {
				return nil, errors.New("faketcp production event reader returned no owned sample")
			}
			return controller.handleOwnedEvent(ctx, record.ownedSample)
		},
	)
}

func newEventRuntime(
	reader EventReader,
	controller EventController,
	options EventRuntimeOptions,
	handleRecord eventRecordHandler,
) (*EventRuntime, error) {
	if eventReaderIsNil(reader) {
		return nil, errors.New("faketcp event reader is nil")
	}
	if eventControllerIsNil(controller) {
		return nil, errors.New("faketcp event controller is nil")
	}
	if handleRecord == nil {
		return nil, errors.New("faketcp event record handler is nil")
	}
	if options.PollInterval <= 0 || options.TickInterval <= 0 {
		return nil, errors.New("faketcp event runtime intervals must be positive")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	now := options.Now()
	return &EventRuntime{
		reader:       reader,
		controller:   controller,
		handleRecord: handleRecord,
		opts:         options,
		runDone:      make(chan struct{}),
		closeDone:    make(chan struct{}),
		readerDone:   make(chan struct{}),
		guardPhase:   StartupGuardPausePhaseOpen,
		guardReason:  StartupGuardPauseReasonNone,
		guardSince:   now,
		stateChanged: make(chan struct{}),
	}, nil
}

func (runtime *EventRuntime) Run(ctx context.Context) error {
	if runtime == nil {
		return ErrEventRuntimeClosed
	}
	if ctx == nil {
		return errors.New("faketcp event runtime context is nil")
	}
	runtime.mu.Lock()
	switch {
	case runtime.shutdown || runtime.closing || runtime.closed:
		runtime.mu.Unlock()
		return ErrEventRuntimeClosed
	case runtime.runStarted:
		runtime.mu.Unlock()
		return ErrEventRuntimeAlreadyRun
	default:
		runtime.runStarted = true
		runtime.running = true
		reader := runtime.reader
		controller := runtime.controller
		handleRecord := runtime.handleRecord
		stopAsked := runtime.stopAsked
		runtime.mu.Unlock()
		defer runtime.finishRun()
		if stopAsked || eventReaderIsNil(reader) || eventControllerIsNil(controller) || handleRecord == nil {
			return nil
		}

		nextTick := runtime.opts.Now().Add(runtime.opts.TickInterval)
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			now := runtime.opts.Now()
			deadline := now.Add(runtime.opts.PollInterval)
			if nextTick.Before(deadline) {
				deadline = nextTick
			}
			reader.SetDeadline(deadline)
			record, err := reader.Read()
			switch {
			case err == nil:
				if record.LostSamples != 0 {
					return fmt.Errorf("%w: %d", ErrEventSamplesLost, record.LostSamples)
				}
				if err := runtime.beginGuardableWork(ctx); err != nil {
					if runtime.stopRequested() && errors.Is(err, ErrEventRuntimeClosed) {
						return nil
					}
					return err
				}
				_, handleErr := handleRecord(ctx, record)
				runtime.finishGuardableWork()
				if handleErr != nil {
					return fmt.Errorf("handle faketcp event sample: %w", handleErr)
				}
			case errors.Is(err, os.ErrDeadlineExceeded):
				// Deadline wakeups exist only to service ctx and Tick below.
			case errors.Is(err, os.ErrClosed):
				runtime.mu.Lock()
				closing := runtime.stopAsked || runtime.shutdown || runtime.closing || runtime.closed
				runtime.mu.Unlock()
				if closing {
					return nil
				}
				return fmt.Errorf("read faketcp event sample: %w", err)
			default:
				return fmt.Errorf("read faketcp event sample: %w", err)
			}
			if runtime.stopRequested() {
				return nil
			}

			now = runtime.opts.Now()
			if !now.Before(nextTick) {
				if err := runtime.beginGuardableWork(ctx); err != nil {
					if runtime.stopRequested() && errors.Is(err, ErrEventRuntimeClosed) {
						return nil
					}
					return err
				}
				_, tickErr := controller.Tick(ctx)
				runtime.finishGuardableWork()
				if tickErr != nil {
					return fmt.Errorf("tick faketcp controller: %w", tickErr)
				}
				nextTick = now.Add(runtime.opts.TickInterval)
			}
		}
	}
}

// PauseForStartupGuard closes event admission and waits for every already
// admitted HandleSample/Tick operation (including raw reinjection) to finish.
// The reader and Run goroutine stay owned and can resume with the same Engine,
// session map, links, and generation identity.
func (runtime *EventRuntime) PauseForStartupGuard(ctx context.Context) (StartupGuardLease, error) {
	if runtime == nil {
		return StartupGuardLease{}, ErrEventRuntimeClosed
	}
	if ctx == nil {
		return StartupGuardLease{}, errors.New("pause faketcp event runtime: context is nil")
	}

	// acquiredRevision is non-zero only for the caller that changed open to
	// draining. If that caller is cancelled, it may roll back only that exact
	// transition. A caller that joined an older draining/held barrier must
	// never release it.
	var acquiredRevision uint64
	var acquiredLease StartupGuardLease
	for {
		runtime.mu.Lock()
		if runtime.shutdown || runtime.closing || runtime.closed || runtime.stopAsked {
			runtime.mu.Unlock()
			return StartupGuardLease{}, ErrEventRuntimeClosed
		}
		switch runtime.guardPhase {
		case StartupGuardPausePhaseHeld:
			lease, err := runtime.startupGuardLeaseForCallerLocked(acquiredLease)
			runtime.mu.Unlock()
			return lease, err
		case StartupGuardPausePhaseOpen:
			if err := ctx.Err(); err != nil {
				runtime.mu.Unlock()
				return StartupGuardLease{}, err
			}
			acquiredLease = NewStartupGuardLease()
			runtime.guardLease = acquiredLease
			runtime.guardReleased = StartupGuardLeaseToken{}
			runtime.setStartupGuardPauseStateLocked(
				StartupGuardPausePhaseDraining,
				StartupGuardPauseReasonStartupGuard,
			)
			acquiredRevision = runtime.guardRevision
		case StartupGuardPausePhaseDraining:
			// A concurrent Pause may wait on the same transition, but it does
			// not own that transition and therefore cannot roll it back.
		case StartupGuardPausePhaseResuming:
			// Resume is synchronous, but retaining this branch makes the state
			// machine explicit if a future implementation has an async resume.
		case StartupGuardPausePhaseStopped:
			runtime.mu.Unlock()
			return StartupGuardLease{}, ErrEventRuntimeClosed
		default:
			phase := runtime.guardPhase
			runtime.mu.Unlock()
			return StartupGuardLease{}, fmt.Errorf("pause faketcp event runtime: invalid startup guard phase %q", phase)
		}

		if runtime.guardPhase == StartupGuardPausePhaseDraining && runtime.activeWork == 0 {
			runtime.setStartupGuardPauseStateLocked(
				StartupGuardPausePhaseHeld,
				StartupGuardPauseReasonStartupGuard,
			)
			lease, err := runtime.startupGuardLeaseForCallerLocked(acquiredLease)
			runtime.mu.Unlock()
			return lease, err
		}
		changed := runtime.stateChanged
		runtime.mu.Unlock()

		select {
		case <-ctx.Done():
			runtime.mu.Lock()
			// Completion wins a cancellation race: the requested barrier is
			// already safely held, so returning success is idempotent.
			if runtime.guardPhase == StartupGuardPausePhaseHeld {
				lease, err := runtime.startupGuardLeaseForCallerLocked(acquiredLease)
				runtime.mu.Unlock()
				return lease, err
			}
			if acquiredRevision != 0 &&
				runtime.guardPhase == StartupGuardPausePhaseDraining &&
				runtime.guardRevision == acquiredRevision &&
				runtime.guardLease.Token == acquiredLease.Token {
				runtime.guardLease = StartupGuardLease{}
				runtime.setStartupGuardPauseStateLocked(
					StartupGuardPausePhaseOpen,
					StartupGuardPauseReasonNone,
				)
			}
			runtime.mu.Unlock()
			return StartupGuardLease{}, ctx.Err()
		case <-changed:
		}
	}
}

func (runtime *EventRuntime) ResumeAfterStartupGuard(
	ctx context.Context,
	lease StartupGuardLease,
) error {
	if runtime == nil {
		return ErrEventRuntimeClosed
	}
	if ctx == nil {
		return errors.New("resume faketcp event runtime: context is nil")
	}
	for {
		runtime.mu.Lock()
		if runtime.shutdown || runtime.closing || runtime.closed || runtime.stopAsked {
			runtime.mu.Unlock()
			return ErrEventRuntimeClosed
		}
		switch runtime.guardPhase {
		case StartupGuardPausePhaseOpen:
			// Releasing the exact same completed lease is an idempotent no-op,
			// even if the caller's finalization context has just expired.
			if !lease.valid() || runtime.guardReleased != lease.Token {
				runtime.mu.Unlock()
				return ErrStartupGuardLeaseMismatch
			}
			runtime.mu.Unlock()
			return nil
		case StartupGuardPausePhaseHeld:
			if !lease.valid() || !runtime.guardLease.valid() ||
				runtime.guardLease.Token != lease.Token {
				runtime.mu.Unlock()
				return ErrStartupGuardLeaseMismatch
			}
			if err := ctx.Err(); err != nil {
				runtime.mu.Unlock()
				return err
			}
			runtime.setStartupGuardPauseStateLocked(
				StartupGuardPausePhaseResuming,
				StartupGuardPauseReasonStartupGuard,
			)
			runtime.setStartupGuardPauseStateLocked(
				StartupGuardPausePhaseOpen,
				StartupGuardPauseReasonNone,
			)
			runtime.guardReleased = runtime.guardLease.Token
			runtime.guardLease = StartupGuardLease{}
			runtime.mu.Unlock()
			return nil
		case StartupGuardPausePhaseDraining, StartupGuardPausePhaseResuming:
			if !lease.valid() || !runtime.guardLease.valid() ||
				runtime.guardLease.Token != lease.Token {
				runtime.mu.Unlock()
				return ErrStartupGuardLeaseMismatch
			}
			if err := ctx.Err(); err != nil {
				runtime.mu.Unlock()
				return err
			}
			changed := runtime.stateChanged
			runtime.mu.Unlock()
			select {
			case <-ctx.Done():
				// Re-check the phase so an already completed concurrent resume
				// still wins the cancellation race.
			case <-changed:
			}
		case StartupGuardPausePhaseStopped:
			runtime.mu.Unlock()
			return ErrEventRuntimeClosed
		default:
			phase := runtime.guardPhase
			runtime.mu.Unlock()
			return fmt.Errorf("resume faketcp event runtime: invalid startup guard phase %q", phase)
		}
	}
}

func (runtime *EventRuntime) startupGuardLeaseForCallerLocked(
	acquired StartupGuardLease,
) (StartupGuardLease, error) {
	if !runtime.guardLease.valid() {
		return StartupGuardLease{}, errors.New("startup guard barrier has no active lease")
	}
	if acquired.valid() && acquired.Token == runtime.guardLease.Token {
		return acquired, nil
	}
	return borrowedStartupGuardLease(runtime.guardLease.Token), nil
}

// StartupGuardPauseStatus returns a typed, race-free snapshot suitable for
// daemon status projection.
func (runtime *EventRuntime) StartupGuardPauseStatus() StartupGuardPauseStatus {
	if runtime == nil {
		return StartupGuardPauseStatus{
			Phase:  StartupGuardPausePhaseStopped,
			Reason: StartupGuardPauseReasonRuntimeClosed,
		}
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return StartupGuardPauseStatus{
		Phase:  runtime.guardPhase,
		Reason: runtime.guardReason,
		Since:  runtime.guardSince,
	}
}

func (runtime *EventRuntime) beginGuardableWork(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		runtime.mu.Lock()
		if runtime.shutdown || runtime.closing || runtime.closed || runtime.stopAsked {
			runtime.mu.Unlock()
			return ErrEventRuntimeClosed
		}
		if runtime.guardPhase == StartupGuardPausePhaseOpen {
			runtime.activeWork++
			runtime.mu.Unlock()
			return nil
		}
		if runtime.guardPhase == StartupGuardPausePhaseStopped {
			runtime.mu.Unlock()
			return ErrEventRuntimeClosed
		}
		changed := runtime.stateChanged
		runtime.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
	}
}

func (runtime *EventRuntime) finishGuardableWork() {
	runtime.mu.Lock()
	if runtime.activeWork > 0 {
		runtime.activeWork--
	}
	runtime.signalStateChangedLocked()
	runtime.mu.Unlock()
}

func (runtime *EventRuntime) signalStateChangedLocked() {
	if runtime.stateChanged == nil {
		runtime.stateChanged = make(chan struct{})
		return
	}
	close(runtime.stateChanged)
	runtime.stateChanged = make(chan struct{})
}

func (runtime *EventRuntime) setStartupGuardPauseStateLocked(
	phase StartupGuardPausePhase,
	reason StartupGuardPauseReason,
) {
	if runtime.guardPhase == phase && runtime.guardReason == reason {
		return
	}
	runtime.guardPhase = phase
	runtime.guardReason = reason
	runtime.guardSince = runtime.opts.Now()
	runtime.guardRevision++
	runtime.signalStateChangedLocked()
}

func (runtime *EventRuntime) invalidateStartupGuardLeasesLocked() {
	runtime.guardLease = StartupGuardLease{}
	runtime.guardReleased = StartupGuardLeaseToken{}
}

// RequestStop is safe from HandleSample and Tick callbacks. It interrupts the
// reader exactly once but deliberately does not wait for Run or close the
// controller. The generation owner must call Close after Run has returned.
func (runtime *EventRuntime) RequestStop() error {
	if runtime == nil {
		return ErrEventRuntimeClosed
	}
	runtime.mu.Lock()
	if runtime.shutdown || runtime.closed {
		runtime.mu.Unlock()
		return ErrEventRuntimeClosed
	}
	if !runtime.stopAsked {
		runtime.stopAsked = true
		runtime.invalidateStartupGuardLeasesLocked()
		runtime.setStartupGuardPauseStateLocked(
			StartupGuardPausePhaseStopped,
			StartupGuardPauseReasonRuntimeStopping,
		)
	}
	runtime.mu.Unlock()
	return runtime.closeReader()
}

func (runtime *EventRuntime) stopRequested() bool {
	runtime.mu.Lock()
	requested := runtime.stopAsked || runtime.shutdown || runtime.closing || runtime.closed
	runtime.mu.Unlock()
	return requested
}

func (runtime *EventRuntime) finishRun() {
	runtime.mu.Lock()
	if runtime.running {
		runtime.running = false
		close(runtime.runDone)
	}
	if runtime.guardPhase != StartupGuardPausePhaseStopped {
		runtime.invalidateStartupGuardLeasesLocked()
		runtime.setStartupGuardPauseStateLocked(
			StartupGuardPausePhaseStopped,
			StartupGuardPauseReasonRuntimeStopped,
		)
	} else {
		runtime.signalStateChangedLocked()
	}
	runtime.mu.Unlock()
}

// Close permanently fences new work, interrupts an admitted reader, waits for
// Run to leave the controller, and then closes the controller. Failed owners
// are retained for a later Close attempt; successfully closed owners are
// pruned so an outer lifecycle owner can eventually converge.
func (runtime *EventRuntime) Close() error {
	if runtime == nil {
		return nil
	}
	runtime.mu.Lock()
	if runtime.closed {
		runtime.mu.Unlock()
		return nil
	}
	if runtime.closing {
		done := runtime.closeDone
		runtime.mu.Unlock()
		<-done
		runtime.mu.Lock()
		err := runtime.closeErr
		runtime.mu.Unlock()
		return err
	}
	runtime.shutdown = true
	runtime.stopAsked = true
	runtime.closing = true
	runtime.invalidateStartupGuardLeasesLocked()
	runtime.setStartupGuardPauseStateLocked(
		StartupGuardPausePhaseStopped,
		StartupGuardPauseReasonRuntimeClosed,
	)
	runtime.closeDone = make(chan struct{})
	running := runtime.running
	runDone := runtime.runDone
	controller := runtime.controller
	runtime.mu.Unlock()

	readerErr := runtime.closeReader()
	if running {
		<-runDone
	}
	var controllerErr error
	if !eventControllerIsNil(controller) {
		controllerErr = controller.Close()
	}
	closeErr := errors.Join(
		wrapEventRuntimeCloseError("reader", readerErr),
		wrapEventRuntimeCloseError("controller", controllerErr),
	)

	runtime.mu.Lock()
	if controllerErr == nil {
		runtime.controller = nil
		runtime.handleRecord = nil
	}
	runtime.closeErr = closeErr
	runtime.closed = eventReaderIsNil(runtime.reader) && eventControllerIsNil(runtime.controller)
	runtime.closing = false
	close(runtime.closeDone)
	runtime.mu.Unlock()
	return closeErr
}

func (runtime *EventRuntime) closeReader() error {
	runtime.mu.Lock()
	if eventReaderIsNil(runtime.reader) {
		runtime.mu.Unlock()
		return nil
	}
	if runtime.readerClosing {
		done := runtime.readerDone
		runtime.mu.Unlock()
		<-done
		runtime.mu.Lock()
		err := runtime.readerErr
		runtime.mu.Unlock()
		return err
	}
	runtime.readerClosing = true
	runtime.readerDone = make(chan struct{})
	reader := runtime.reader
	runtime.mu.Unlock()

	err := reader.Close()

	runtime.mu.Lock()
	runtime.readerErr = err
	if err == nil {
		runtime.reader = nil
	}
	runtime.readerClosing = false
	close(runtime.readerDone)
	runtime.mu.Unlock()
	return err
}

func wrapEventRuntimeCloseError(resource string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("close faketcp event runtime %s: %w", resource, err)
}

func eventReaderIsNil(reader EventReader) bool {
	return interfaceValueIsNil(reader)
}

func eventControllerIsNil(controller EventController) bool {
	return interfaceValueIsNil(controller)
}

func interfaceValueIsNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
