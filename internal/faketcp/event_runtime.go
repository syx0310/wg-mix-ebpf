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

// EventRecord is one owned event sample. LostSamples is non-zero only for a
// perf-event-array reader. Losing a control or first-packet event makes the
// userspace handshake state unknowable, so EventRuntime treats any loss as a
// terminal, fail-closed error.
type EventRecord struct {
	RawSample   []byte
	LostSamples uint64
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

	reader     EventReader
	controller EventController
	opts       EventRuntimeOptions
	runDone    chan struct{}
	closeDone  chan struct{}
	readerDone chan struct{}
	readerOnce sync.Once
	runStarted bool
	running    bool
	stopAsked  bool
	closing    bool
	closed     bool
	readerErr  error
	closeErr   error
}

var _ RuntimeService = (*EventRuntime)(nil)
var _ RuntimeStopRequester = (*EventRuntime)(nil)

func NewEventRuntime(
	reader EventReader,
	controller EventController,
	options EventRuntimeOptions,
) (*EventRuntime, error) {
	if eventReaderIsNil(reader) {
		return nil, errors.New("faketcp event reader is nil")
	}
	if eventControllerIsNil(controller) {
		return nil, errors.New("faketcp event controller is nil")
	}
	if options.PollInterval <= 0 || options.TickInterval <= 0 {
		return nil, errors.New("faketcp event runtime intervals must be positive")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &EventRuntime{
		reader:     reader,
		controller: controller,
		opts:       options,
		runDone:    make(chan struct{}),
		closeDone:  make(chan struct{}),
		readerDone: make(chan struct{}),
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
	case runtime.closing || runtime.closed:
		runtime.mu.Unlock()
		return ErrEventRuntimeClosed
	case runtime.runStarted:
		runtime.mu.Unlock()
		return ErrEventRuntimeAlreadyRun
	default:
		runtime.runStarted = true
		runtime.running = true
		runtime.mu.Unlock()
	}
	defer runtime.finishRun()

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
		runtime.reader.SetDeadline(deadline)
		record, err := runtime.reader.Read()
		switch {
		case err == nil:
			if record.LostSamples != 0 {
				return fmt.Errorf("%w: %d", ErrEventSamplesLost, record.LostSamples)
			}
			if len(record.RawSample) == 0 {
				return errors.New("faketcp event reader returned an empty sample")
			}
			if _, err := runtime.controller.HandleSample(ctx, record.RawSample); err != nil {
				return fmt.Errorf("handle faketcp event sample: %w", err)
			}
		case errors.Is(err, os.ErrDeadlineExceeded):
			// Deadline wakeups exist only to service ctx and Tick below.
		case errors.Is(err, os.ErrClosed):
			runtime.mu.Lock()
			closing := runtime.stopAsked || runtime.closing || runtime.closed
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
			if _, err := runtime.controller.Tick(ctx); err != nil {
				return fmt.Errorf("tick faketcp controller: %w", err)
			}
			nextTick = now.Add(runtime.opts.TickInterval)
		}
	}
}

// RequestStop is safe from HandleSample and Tick callbacks. It interrupts the
// reader exactly once but deliberately does not wait for Run or close the
// controller. The generation owner must call Close after Run has returned.
func (runtime *EventRuntime) RequestStop() error {
	if runtime == nil {
		return ErrEventRuntimeClosed
	}
	runtime.mu.Lock()
	if runtime.closed {
		err := runtime.readerErr
		runtime.mu.Unlock()
		return err
	}
	runtime.stopAsked = true
	runtime.mu.Unlock()
	return runtime.closeReader()
}

func (runtime *EventRuntime) stopRequested() bool {
	runtime.mu.Lock()
	requested := runtime.stopAsked || runtime.closing || runtime.closed
	runtime.mu.Unlock()
	return requested
}

func (runtime *EventRuntime) finishRun() {
	runtime.mu.Lock()
	if runtime.running {
		runtime.running = false
		close(runtime.runDone)
	}
	runtime.mu.Unlock()
}

// Close fences new Run calls, interrupts an admitted reader, waits for Run to
// leave the controller, and then closes the controller. It never holds the
// lifecycle mutex while invoking either owned resource.
func (runtime *EventRuntime) Close() error {
	if runtime == nil {
		return nil
	}
	runtime.mu.Lock()
	if runtime.closed {
		err := runtime.closeErr
		runtime.mu.Unlock()
		return err
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
	runtime.closing = true
	running := runtime.running
	runDone := runtime.runDone
	controller := runtime.controller
	runtime.mu.Unlock()

	readerErr := runtime.closeReader()
	if running {
		<-runDone
	}
	controllerErr := controller.Close()
	closeErr := errors.Join(
		wrapEventRuntimeCloseError("reader", readerErr),
		wrapEventRuntimeCloseError("controller", controllerErr),
	)

	runtime.mu.Lock()
	runtime.closeErr = closeErr
	runtime.closed = true
	runtime.closing = false
	close(runtime.closeDone)
	runtime.mu.Unlock()
	return closeErr
}

func (runtime *EventRuntime) closeReader() error {
	runtime.readerOnce.Do(func() {
		runtime.readerErr = runtime.reader.Close()
		close(runtime.readerDone)
	})
	<-runtime.readerDone
	return runtime.readerErr
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
