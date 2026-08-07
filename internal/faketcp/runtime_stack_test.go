package faketcp

import (
	"context"
	"errors"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

type orderedCloseLog struct {
	mu         sync.Mutex
	operations []string
}

func (log *orderedCloseLog) append(operation string) {
	log.mu.Lock()
	log.operations = append(log.operations, operation)
	log.mu.Unlock()
}

func (log *orderedCloseLog) snapshot() []string {
	log.mu.Lock()
	defer log.mu.Unlock()
	return append([]string(nil), log.operations...)
}

type orderedEventReader struct {
	log              *orderedCloseLog
	started          chan struct{}
	release          chan struct{}
	startOnce        sync.Once
	closeOnce        sync.Once
	mu               sync.Mutex
	closeErr         error
	closeCall        int
	closeStarted     chan struct{}
	closeRelease     <-chan struct{}
	closeStartedOnce sync.Once
}

func (reader *orderedEventReader) Read() (EventRecord, error) {
	reader.startOnce.Do(func() { close(reader.started) })
	<-reader.release
	return EventRecord{}, os.ErrClosed
}

func (*orderedEventReader) SetDeadline(time.Time) {}

func (reader *orderedEventReader) Close() error {
	reader.log.append("reader")
	if reader.closeStarted != nil {
		reader.closeStartedOnce.Do(func() { close(reader.closeStarted) })
	}
	if reader.closeRelease != nil {
		<-reader.closeRelease
	}
	reader.closeOnce.Do(func() {
		close(reader.release)
	})
	reader.mu.Lock()
	defer reader.mu.Unlock()
	reader.closeCall++
	return reader.closeErr
}

type orderedControllerBackend struct {
	log      *orderedCloseLog
	closeErr error
}

func (*orderedControllerBackend) SendControl(context.Context, abi.FakeTCPSessionKey, uint32, ControlPacket) error {
	return nil
}
func (*orderedControllerBackend) Reinject(context.Context, abi.FakeTCPSessionKey, PendingPacket) error {
	return nil
}
func (backend *orderedControllerBackend) Close() error {
	backend.log.append("backend")
	return backend.closeErr
}

type orderedController struct {
	*Controller
	log *orderedCloseLog
}

func (controller *orderedController) Close() error {
	controller.log.append("controller")
	return controller.Controller.Close()
}

func newOrderedController(t *testing.T, log *orderedCloseLog, backendErr error) *orderedController {
	t.Helper()
	engine, _ := testEngine(t, nil)
	controller, err := NewController(engine, &orderedControllerBackend{log: log, closeErr: backendErr})
	if err != nil {
		t.Fatal(err)
	}
	return &orderedController{Controller: controller, log: log}
}

type orderedGenerationCloser struct {
	log       *orderedCloseLog
	mu        sync.Mutex
	closeErr  error
	closeCall int
}

func (generation *orderedGenerationCloser) Close() error {
	generation.mu.Lock()
	generation.closeCall++
	generation.mu.Unlock()
	generation.log.append("generation")
	return generation.closeErr
}

func TestRuntimeStackClosesSlowPathBeforeGeneration(t *testing.T) {
	log := &orderedCloseLog{}
	reader := &orderedEventReader{log: log, started: make(chan struct{}), release: make(chan struct{})}
	controller := newOrderedController(t, log, nil)
	events, err := NewEventRuntime(reader, controller, EventRuntimeOptions{
		PollInterval: time.Millisecond, TickInterval: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	generation := &orderedGenerationCloser{log: log}
	stack, err := NewRuntimeStack(events, generation)
	if err != nil {
		t.Fatal(err)
	}
	runDone := make(chan error, 1)
	go func() { runDone <- stack.Run(context.Background()) }()
	select {
	case <-reader.started:
	case <-time.After(time.Second):
		t.Fatal("runtime did not enter event reader")
	}
	if err := stack.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-runDone; err != nil {
		t.Fatalf("Run error = %v", err)
	}
	if got, want := log.snapshot(), []string{"reader", "controller", "backend", "generation"}; !slices.Equal(got, want) {
		t.Fatalf("close order=%v want=%v", got, want)
	}
	if err := stack.Run(context.Background()); !errors.Is(err, ErrRuntimeStackClosed) {
		t.Fatalf("Run after Close error = %v", err)
	}
}

func TestRuntimeStackConcurrentCloseCoalescesAndRetriesInDependencyOrder(t *testing.T) {
	log := &orderedCloseLog{}
	readerErr := errors.New("reader close failed")
	backendErr := errors.New("controller backend close failed")
	generationErr := errors.New("generation close failed")
	closeStarted := make(chan struct{})
	closeRelease := make(chan struct{})
	reader := &orderedEventReader{
		log: log, started: make(chan struct{}), release: make(chan struct{}), closeErr: readerErr,
		closeStarted: closeStarted, closeRelease: closeRelease,
	}
	controller := newOrderedController(t, log, backendErr)
	events, err := NewEventRuntime(reader, controller, EventRuntimeOptions{
		PollInterval: time.Millisecond, TickInterval: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	generation := &orderedGenerationCloser{log: log, closeErr: generationErr}
	stack, err := NewRuntimeStack(events, generation)
	if err != nil {
		t.Fatal(err)
	}
	runDone := make(chan error, 1)
	go func() { runDone <- stack.Run(context.Background()) }()
	select {
	case <-reader.started:
	case <-time.After(time.Second):
		t.Fatal("runtime did not enter event reader")
	}
	const callers = 16
	start := make(chan struct{})
	errs := make(chan error, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			errs <- stack.Close()
		}()
	}
	close(start)
	select {
	case <-closeStarted:
	case <-time.After(time.Second):
		t.Fatal("Close did not reach event reader")
	}
	time.Sleep(10 * time.Millisecond)
	close(closeRelease)
	wait.Wait()
	close(errs)
	for err := range errs {
		if !errors.Is(err, readerErr) || !errors.Is(err, backendErr) || errors.Is(err, generationErr) {
			t.Fatalf("Close error = %v", err)
		}
	}
	if err := <-runDone; err != nil {
		t.Fatalf("Run error = %v", err)
	}
	if got, want := log.snapshot(), []string{"reader", "controller", "backend"}; !slices.Equal(got, want) {
		t.Fatalf("first close order=%v want=%v", got, want)
	}
	generation.mu.Lock()
	closeCalls := generation.closeCall
	generation.mu.Unlock()
	if closeCalls != 0 {
		t.Fatalf("generation closed before slow path converged: calls=%d", closeCalls)
	}

	reader.mu.Lock()
	reader.closeErr = nil
	reader.mu.Unlock()
	controller.Controller.stateMu.Lock()
	backend := controller.Controller.backend.(*orderedControllerBackend)
	backend.closeErr = nil
	controller.Controller.stateMu.Unlock()
	if err := stack.Close(); !errors.Is(err, generationErr) || errors.Is(err, readerErr) || errors.Is(err, backendErr) {
		t.Fatalf("generation retry error=%v", err)
	}
	if got, want := log.snapshot(), []string{
		"reader", "controller", "backend",
		"reader", "controller", "backend", "generation",
	}; !slices.Equal(got, want) {
		t.Fatalf("retry close order=%v want=%v", got, want)
	}
	generation.mu.Lock()
	generation.closeErr = nil
	generation.mu.Unlock()
	if err := stack.Close(); err != nil {
		t.Fatalf("final generation retry error=%v", err)
	}
	if err := stack.Close(); err != nil {
		t.Fatalf("converged Close error=%v", err)
	}
	generation.mu.Lock()
	closeCalls = generation.closeCall
	generation.mu.Unlock()
	if closeCalls != 2 {
		t.Fatalf("generation close calls=%d, want 2", closeCalls)
	}
}

func TestRuntimeStackRequestStopDelegatesWithoutClosingGeneration(t *testing.T) {
	log := &orderedCloseLog{}
	reader := &orderedEventReader{log: log, started: make(chan struct{}), release: make(chan struct{})}
	events, err := NewEventRuntime(reader, newOrderedController(t, log, nil), EventRuntimeOptions{
		PollInterval: time.Millisecond, TickInterval: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	generation := &orderedGenerationCloser{log: log}
	stack, err := NewRuntimeStack(events, generation)
	if err != nil {
		t.Fatal(err)
	}
	runDone := make(chan error, 1)
	go func() { runDone <- stack.Run(context.Background()) }()
	select {
	case <-reader.started:
	case <-time.After(time.Second):
		t.Fatal("runtime did not enter event reader")
	}
	if err := stack.RequestStop(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Run error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("RequestStop did not release Run")
	}
	if got, want := log.snapshot(), []string{"reader"}; !slices.Equal(got, want) {
		t.Fatalf("operations before owner Close=%v want=%v", got, want)
	}
	if err := stack.Close(); err != nil {
		t.Fatal(err)
	}
	if got, want := log.snapshot(), []string{"reader", "controller", "backend", "generation"}; !slices.Equal(got, want) {
		t.Fatalf("close order=%v want=%v", got, want)
	}
}

func TestRuntimeStackCallbackUsesRequestStopAndOwnerClosesAfterRun(t *testing.T) {
	reader := &fakeEventReader{records: []EventRecord{{RawSample: []byte{1}}}}
	controller := &fakeEventController{}
	events, err := NewEventRuntime(reader, controller, EventRuntimeOptions{
		PollInterval: time.Millisecond, TickInterval: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	log := &orderedCloseLog{}
	generation := &orderedGenerationCloser{log: log}
	stack, err := NewRuntimeStack(events, generation)
	if err != nil {
		t.Fatal(err)
	}
	controller.handleHook = func() {
		if err := stack.RequestStop(); err != nil {
			t.Errorf("callback RequestStop error = %v", err)
		}
	}
	runDone := make(chan error, 1)
	go func() { runDone <- stack.Run(context.Background()) }()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Run error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("callback RequestStop deadlocked Run")
	}
	generation.mu.Lock()
	closeCalls := generation.closeCall
	generation.mu.Unlock()
	if closeCalls != 0 {
		t.Fatal("callback stop request closed generation")
	}
	if err := stack.Close(); err != nil {
		t.Fatal(err)
	}
	if reader.closeCalls != 1 || controller.closeCalls != 1 {
		t.Fatalf("close calls reader=%d controller=%d", reader.closeCalls, controller.closeCalls)
	}
	generation.mu.Lock()
	closeCalls = generation.closeCall
	generation.mu.Unlock()
	if closeCalls != 1 {
		t.Fatalf("generation close calls=%d", closeCalls)
	}
}

type closeOnlyRuntime struct{}

func (*closeOnlyRuntime) Run(context.Context) error { return nil }
func (*closeOnlyRuntime) Close() error              { return nil }

func TestNewRuntimeStackRejectsInvalidOwnersAndMissingStopBoundary(t *testing.T) {
	slowPath := &closeOnlyRuntime{}
	generation := &orderedGenerationCloser{log: &orderedCloseLog{}}
	if stack, err := NewRuntimeStack(nil, generation); err == nil || stack != nil {
		t.Fatalf("nil slow path accepted: stack=%#v err=%v", stack, err)
	}
	var typedNil *orderedGenerationCloser
	if stack, err := NewRuntimeStack(slowPath, typedNil); err == nil || stack != nil {
		t.Fatalf("typed-nil generation accepted: stack=%#v err=%v", stack, err)
	}
	stack, err := NewRuntimeStack(slowPath, generation)
	if err != nil {
		t.Fatal(err)
	}
	if err := stack.RequestStop(); !errors.Is(err, ErrRuntimeStopUnavailable) {
		t.Fatalf("missing stop boundary error = %v", err)
	}
}
