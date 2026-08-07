package faketcp

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"
)

type fakeEventReader struct {
	mu sync.Mutex

	records    []EventRecord
	errors     []error
	deadlines  []time.Time
	readHook   func()
	readCalls  int
	closeCalls int
	closeErr   error
	closed     bool
}

func (reader *fakeEventReader) Read() (EventRecord, error) {
	reader.mu.Lock()
	reader.readCalls++
	hook := reader.readHook
	if len(reader.records) != 0 {
		record := reader.records[0]
		reader.records = reader.records[1:]
		reader.mu.Unlock()
		if hook != nil {
			hook()
		}
		return record, nil
	}
	if len(reader.errors) != 0 {
		err := reader.errors[0]
		reader.errors = reader.errors[1:]
		reader.mu.Unlock()
		if hook != nil {
			hook()
		}
		return EventRecord{}, err
	}
	closed := reader.closed
	reader.mu.Unlock()
	if hook != nil {
		hook()
	}
	if closed {
		return EventRecord{}, os.ErrClosed
	}
	return EventRecord{}, os.ErrDeadlineExceeded
}

func (reader *fakeEventReader) SetDeadline(deadline time.Time) {
	reader.mu.Lock()
	reader.deadlines = append(reader.deadlines, deadline)
	reader.mu.Unlock()
}

func (reader *fakeEventReader) Close() error {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	reader.closeCalls++
	reader.closed = true
	return reader.closeErr
}

type blockingEventReader struct {
	started   chan struct{}
	release   chan struct{}
	startOnce sync.Once
	closeOnce sync.Once
	mu        sync.Mutex
	closes    int
	closeErr  error
}

func newBlockingEventReader() *blockingEventReader {
	return &blockingEventReader{started: make(chan struct{}), release: make(chan struct{})}
}

func (reader *blockingEventReader) Read() (EventRecord, error) {
	reader.startOnce.Do(func() { close(reader.started) })
	<-reader.release
	return EventRecord{}, os.ErrClosed
}

func (*blockingEventReader) SetDeadline(time.Time) {}

func (reader *blockingEventReader) Close() error {
	reader.mu.Lock()
	reader.closes++
	reader.mu.Unlock()
	reader.closeOnce.Do(func() { close(reader.release) })
	return reader.closeErr
}

type fakeEventController struct {
	mu sync.Mutex

	samples    [][]byte
	handleErr  error
	handleHook func()
	ticks      int
	tickErr    error
	tickHook   func()
	closeCalls int
	closeErr   error
	closed     bool
	operations []string
}

func (controller *fakeEventController) HandleSample(_ context.Context, sample []byte) ([]Action, error) {
	controller.mu.Lock()
	controller.samples = append(controller.samples, append([]byte(nil), sample...))
	controller.operations = append(controller.operations, "sample")
	hook := controller.handleHook
	err := controller.handleErr
	controller.mu.Unlock()
	if hook != nil {
		hook()
	}
	return nil, err
}

func (controller *fakeEventController) Tick(context.Context) ([]Action, error) {
	controller.mu.Lock()
	controller.ticks++
	controller.operations = append(controller.operations, "tick")
	hook := controller.tickHook
	err := controller.tickErr
	controller.mu.Unlock()
	if hook != nil {
		hook()
	}
	return nil, err
}

func (controller *fakeEventController) Close() error {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	controller.closeCalls++
	controller.closed = true
	controller.operations = append(controller.operations, "close")
	return controller.closeErr
}

func newTestEventRuntime(t *testing.T, reader EventReader, controller EventController, options EventRuntimeOptions) *EventRuntime {
	t.Helper()
	if options.PollInterval == 0 {
		options.PollInterval = time.Millisecond
	}
	if options.TickInterval == 0 {
		options.TickInterval = time.Second
	}
	runtime, err := NewEventRuntime(reader, controller, options)
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

func TestEventRuntimeDeliversOwnedSamplesAndHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	reader := &fakeEventReader{records: []EventRecord{{RawSample: []byte{1, 2, 3}}}}
	controller := &fakeEventController{handleHook: cancel}
	runtime := newTestEventRuntime(t, reader, controller, EventRuntimeOptions{})
	if err := runtime.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v", err)
	}
	reader.records = nil
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if len(controller.samples) != 1 || string(controller.samples[0]) != string([]byte{1, 2, 3}) {
		t.Fatalf("samples = %v", controller.samples)
	}
}

func TestEventRuntimeFailsClosedOnLostOrEmptySamples(t *testing.T) {
	for _, test := range []struct {
		name   string
		record EventRecord
		want   error
	}{
		{name: "lost", record: EventRecord{LostSamples: 3}, want: ErrEventSamplesLost},
		{name: "empty", record: EventRecord{}, want: nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader := &fakeEventReader{records: []EventRecord{test.record}}
			controller := &fakeEventController{}
			runtime := newTestEventRuntime(t, reader, controller, EventRuntimeOptions{})
			err := runtime.Run(context.Background())
			if test.want != nil {
				if !errors.Is(err, test.want) {
					t.Fatalf("Run error = %v", err)
				}
			} else if err == nil {
				t.Fatal("empty sample was accepted")
			}
			if len(controller.samples) != 0 {
				t.Fatal("invalid record reached controller")
			}
		})
	}
}

func TestEventRuntimeServicesTickAfterReadDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	now := time.Unix(100, 0)
	reader := &fakeEventReader{errors: []error{os.ErrDeadlineExceeded}}
	reader.readHook = func() { now = now.Add(2 * time.Second) }
	controller := &fakeEventController{tickHook: cancel}
	runtime := newTestEventRuntime(t, reader, controller, EventRuntimeOptions{
		PollInterval: time.Second,
		TickInterval: time.Second,
		Now:          func() time.Time { return now },
	})
	if err := runtime.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v", err)
	}
	if controller.ticks != 1 {
		t.Fatalf("ticks = %d", controller.ticks)
	}
}

func TestEventRuntimePropagatesReaderAndControllerErrors(t *testing.T) {
	readErr := errors.New("reader failure")
	runtime := newTestEventRuntime(t,
		&fakeEventReader{errors: []error{readErr}},
		&fakeEventController{},
		EventRuntimeOptions{},
	)
	if err := runtime.Run(context.Background()); !errors.Is(err, readErr) {
		t.Fatalf("reader Run error = %v", err)
	}

	handleErr := errors.New("controller failure")
	runtime = newTestEventRuntime(t,
		&fakeEventReader{records: []EventRecord{{RawSample: []byte{1}}}},
		&fakeEventController{handleErr: handleErr},
		EventRuntimeOptions{},
	)
	if err := runtime.Run(context.Background()); !errors.Is(err, handleErr) {
		t.Fatalf("controller Run error = %v", err)
	}
}

func TestEventRuntimeCloseInterruptsRunThenClosesController(t *testing.T) {
	reader := newBlockingEventReader()
	controller := &fakeEventController{}
	runtime := newTestEventRuntime(t, reader, controller, EventRuntimeOptions{})
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(context.Background()) }()
	select {
	case <-reader.started:
	case <-time.After(time.Second):
		t.Fatal("Run did not enter reader")
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-runDone; err != nil {
		t.Fatalf("interrupted Run error = %v", err)
	}
	reader.mu.Lock()
	closes := reader.closes
	reader.mu.Unlock()
	if closes != 1 || controller.closeCalls != 1 {
		t.Fatalf("close calls reader=%d controller=%d", closes, controller.closeCalls)
	}
	if err := runtime.Run(context.Background()); !errors.Is(err, ErrEventRuntimeClosed) {
		t.Fatalf("Run after Close error = %v", err)
	}
}

func TestEventRuntimeCallbackRequestsStopThenOwnerCloses(t *testing.T) {
	reader := &fakeEventReader{records: []EventRecord{{RawSample: []byte{1}}}}
	controller := &fakeEventController{}
	var runtime *EventRuntime
	controller.handleHook = func() {
		if err := runtime.RequestStop(); err != nil {
			t.Errorf("RequestStop error = %v", err)
		}
	}
	runtime = newTestEventRuntime(t, reader, controller, EventRuntimeOptions{})
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(context.Background()) }()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Run error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("callback stop request deadlocked Run")
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if reader.closeCalls != 1 || controller.closeCalls != 1 {
		t.Fatalf("close calls reader=%d controller=%d", reader.closeCalls, controller.closeCalls)
	}
}

func TestEventRuntimeRequestStopAndCloseShareReaderClose(t *testing.T) {
	readerErr := errors.New("reader close failure")
	reader := &fakeEventReader{closeErr: readerErr}
	controller := &fakeEventController{}
	runtime := newTestEventRuntime(t, reader, controller, EventRuntimeOptions{})
	if err := runtime.RequestStop(); !errors.Is(err, readerErr) {
		t.Fatalf("RequestStop error = %v", err)
	}
	if err := runtime.Run(context.Background()); err != nil {
		t.Fatalf("Run after RequestStop error = %v", err)
	}
	if err := runtime.Close(); !errors.Is(err, readerErr) {
		t.Fatalf("Close error = %v", err)
	}
	if reader.closeCalls != 1 || controller.closeCalls != 1 {
		t.Fatalf("close calls reader=%d controller=%d", reader.closeCalls, controller.closeCalls)
	}
}

func TestEventRuntimeConcurrentCloseIsOnceOnlyAndRetainsErrors(t *testing.T) {
	readerErr := errors.New("reader close failure")
	controllerErr := errors.New("controller close failure")
	reader := &fakeEventReader{closeErr: readerErr}
	controller := &fakeEventController{closeErr: controllerErr}
	runtime := newTestEventRuntime(t, reader, controller, EventRuntimeOptions{})

	const callers = 16
	start := make(chan struct{})
	errs := make(chan error, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			errs <- runtime.Close()
		}()
	}
	close(start)
	wait.Wait()
	close(errs)
	for err := range errs {
		if !errors.Is(err, readerErr) || !errors.Is(err, controllerErr) {
			t.Fatalf("Close error = %v", err)
		}
	}
	if reader.closeCalls != 1 || controller.closeCalls != 1 {
		t.Fatalf("close calls reader=%d controller=%d", reader.closeCalls, controller.closeCalls)
	}
}

func TestEventRuntimeRunIsOneShot(t *testing.T) {
	reader := &fakeEventReader{}
	controller := &fakeEventController{}
	runtime := newTestEventRuntime(t, reader, controller, EventRuntimeOptions{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runtime.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("first Run error = %v", err)
	}
	if err := runtime.Run(context.Background()); !errors.Is(err, ErrEventRuntimeAlreadyRun) {
		t.Fatalf("second Run error = %v", err)
	}
}

func TestNewEventRuntimeRejectsInvalidResourcesAndIntervals(t *testing.T) {
	reader := &fakeEventReader{}
	controller := &fakeEventController{}
	if _, err := NewEventRuntime(nil, controller, EventRuntimeOptions{PollInterval: 1, TickInterval: 1}); err == nil {
		t.Fatal("nil reader accepted")
	}
	var typedNilReader *fakeEventReader
	if _, err := NewEventRuntime(typedNilReader, controller, EventRuntimeOptions{PollInterval: 1, TickInterval: 1}); err == nil {
		t.Fatal("typed-nil reader accepted")
	}
	if _, err := NewEventRuntime(reader, nil, EventRuntimeOptions{PollInterval: 1, TickInterval: 1}); err == nil {
		t.Fatal("nil controller accepted")
	}
	if _, err := NewEventRuntime(reader, controller, EventRuntimeOptions{}); err == nil {
		t.Fatal("zero intervals accepted")
	}
}
