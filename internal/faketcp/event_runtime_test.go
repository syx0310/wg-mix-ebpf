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

	records          []EventRecord
	errors           []error
	deadlines        []time.Time
	readHook         func()
	readCalls        int
	closeCalls       int
	closeErr         error
	closed           bool
	closeStarted     chan struct{}
	closeRelease     <-chan struct{}
	closeStartedOnce sync.Once
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
	reader.closeCalls++
	reader.closed = true
	if reader.closeStarted != nil {
		reader.closeStartedOnce.Do(func() { close(reader.closeStarted) })
	}
	closeRelease := reader.closeRelease
	reader.mu.Unlock()
	if closeRelease != nil {
		<-closeRelease
	}
	reader.mu.Lock()
	err := reader.closeErr
	reader.mu.Unlock()
	return err
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

type startupGuardPauseResult struct {
	lease StartupGuardLease
	err   error
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

func TestEventRuntimeStartupGuardPauseDrainsAndBlocksDeliveryUntilResume(t *testing.T) {
	reader := &fakeEventReader{records: []EventRecord{
		{RawSample: []byte{1}},
		{RawSample: []byte{2}},
	}}
	firstStarted := make(chan struct{})
	firstRelease := make(chan struct{})
	secondStarted := make(chan struct{})
	var firstOnce sync.Once
	var secondOnce sync.Once
	controller := &fakeEventController{}
	controller.handleHook = func() {
		controller.mu.Lock()
		count := len(controller.samples)
		controller.mu.Unlock()
		switch count {
		case 1:
			firstOnce.Do(func() { close(firstStarted) })
			<-firstRelease
		case 2:
			secondOnce.Do(func() { close(secondStarted) })
		}
	}
	runtime := newTestEventRuntime(t, reader, controller, EventRuntimeOptions{})
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(context.Background()) }()
	<-firstStarted
	pauseDone := make(chan startupGuardPauseResult, 1)
	go func() {
		lease, err := runtime.PauseForStartupGuard(t.Context())
		pauseDone <- startupGuardPauseResult{lease: lease, err: err}
	}()
	deadline := time.After(time.Second)
	for {
		if runtime.StartupGuardPauseStatus().Phase == StartupGuardPausePhaseDraining {
			break
		}
		select {
		case result := <-pauseDone:
			t.Fatalf("pause returned before admitted event drained: %v", result.err)
		case <-deadline:
			t.Fatal("pause did not close event admission")
		default:
		}
	}
	close(firstRelease)
	pauseResult := <-pauseDone
	if pauseResult.err != nil {
		t.Fatal(pauseResult.err)
	}
	if !pauseResult.lease.Acquired || pauseResult.lease.Token.IsZero() {
		t.Fatalf("pause lease = %#v, want acquired non-zero token", pauseResult.lease)
	}
	held := runtime.StartupGuardPauseStatus()
	if held.Phase != StartupGuardPausePhaseHeld ||
		held.Reason != StartupGuardPauseReasonStartupGuard || held.Since.IsZero() {
		t.Fatalf("held pause status = %#v", held)
	}
	controller.mu.Lock()
	samplesWhilePaused := len(controller.samples)
	controller.mu.Unlock()
	if samplesWhilePaused != 1 {
		t.Fatalf("samples while paused = %d, want 1", samplesWhilePaused)
	}
	if err := runtime.ResumeAfterStartupGuard(t.Context(), pauseResult.lease); err != nil {
		t.Fatal(err)
	}
	open := runtime.StartupGuardPauseStatus()
	if open.Phase != StartupGuardPausePhaseOpen ||
		open.Reason != StartupGuardPauseReasonNone || open.Since.IsZero() {
		t.Fatalf("resumed pause status = %#v", open)
	}
	select {
	case <-secondStarted:
	case <-time.After(time.Second):
		t.Fatal("queued event was not delivered after resume")
	}
	if err := runtime.RequestStop(); err != nil {
		t.Fatal(err)
	}
	if err := <-runDone; err != nil {
		t.Fatalf("Run after guard pause = %v", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestEventRuntimeStartupGuardPauseCancellationRollsBackNewAdmissionBarrier(t *testing.T) {
	runtime := newTestEventRuntime(t, &fakeEventReader{}, &fakeEventController{}, EventRuntimeOptions{})
	if err := runtime.beginGuardableWork(t.Context()); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	pauseDone := make(chan startupGuardPauseResult, 1)
	go func() {
		lease, err := runtime.PauseForStartupGuard(ctx)
		pauseDone <- startupGuardPauseResult{lease: lease, err: err}
	}()
	waitForEventRuntimePausePhase(t, runtime, StartupGuardPausePhaseDraining)
	cancel()
	if result := <-pauseDone; !errors.Is(result.err, context.Canceled) ||
		result.lease != (StartupGuardLease{}) {
		t.Fatalf("Pause result = %#v, error %v", result.lease, result.err)
	}
	status := runtime.StartupGuardPauseStatus()
	if status.Phase != StartupGuardPausePhaseOpen ||
		status.Reason != StartupGuardPauseReasonNone {
		t.Fatalf("pause status after cancellation = %#v", status)
	}

	// The cancelled call released only the admission barrier it acquired, so
	// fresh work can enter while the earlier admitted operation is still owned.
	if err := runtime.beginGuardableWork(t.Context()); err != nil {
		t.Fatalf("begin work after pause rollback: %v", err)
	}
	runtime.finishGuardableWork()
	runtime.finishGuardableWork()
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestEventRuntimeStartupGuardPauseAndResumeAreIdempotent(t *testing.T) {
	runtime := newTestEventRuntime(t, &fakeEventReader{}, &fakeEventController{}, EventRuntimeOptions{})
	lease, err := runtime.PauseForStartupGuard(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	held := runtime.StartupGuardPauseStatus()
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	borrowed, err := runtime.PauseForStartupGuard(cancelled)
	if err != nil {
		t.Fatalf("repeated Pause on held barrier: %v", err)
	}
	if borrowed.Acquired || borrowed.Token != lease.Token || borrowed.Token.IsZero() {
		t.Fatalf("repeated Pause lease = %#v, want borrowed original token", borrowed)
	}
	if got := runtime.StartupGuardPauseStatus(); got != held {
		t.Fatalf("repeated Pause changed old held barrier: got %#v want %#v", got, held)
	}

	if err := runtime.ResumeAfterStartupGuard(t.Context(), borrowed); err != nil {
		t.Fatal(err)
	}
	open := runtime.StartupGuardPauseStatus()
	if err := runtime.ResumeAfterStartupGuard(cancelled, lease); err != nil {
		t.Fatalf("repeated Resume on open barrier: %v", err)
	}
	if got := runtime.StartupGuardPauseStatus(); got != open {
		t.Fatalf("repeated Resume changed open barrier: got %#v want %#v", got, open)
	}
	if err := runtime.RequestStop(); err != nil {
		t.Fatal(err)
	}
	if err := runtime.RequestStop(); err != nil {
		t.Fatalf("repeated RequestStop: %v", err)
	}
	stopping := runtime.StartupGuardPauseStatus()
	if stopping.Phase != StartupGuardPausePhaseStopped ||
		stopping.Reason != StartupGuardPauseReasonRuntimeStopping {
		t.Fatalf("stopping pause status = %#v", stopping)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	closed := runtime.StartupGuardPauseStatus()
	if closed.Phase != StartupGuardPausePhaseStopped ||
		closed.Reason != StartupGuardPauseReasonRuntimeClosed {
		t.Fatalf("closed pause status = %#v", closed)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("repeated Close: %v", err)
	}
}

func TestStartupGuardLeaseTokensAreUniqueSequentiallyAndConcurrently(t *testing.T) {
	const leases = 256
	sequential := make(map[StartupGuardLeaseToken]struct{}, leases)
	for range leases {
		lease := NewStartupGuardLease()
		if !lease.Acquired || lease.Token.IsZero() {
			t.Fatalf("minted lease = %#v, want acquired non-zero token", lease)
		}
		if _, exists := sequential[lease.Token]; exists {
			t.Fatal("sequential lease token was reused")
		}
		sequential[lease.Token] = struct{}{}
	}

	results := make(chan StartupGuardLeaseToken, leases)
	var group sync.WaitGroup
	group.Add(leases)
	for range leases {
		go func() {
			defer group.Done()
			results <- NewStartupGuardLease().Token
		}()
	}
	group.Wait()
	close(results)
	concurrent := make(map[StartupGuardLeaseToken]struct{}, leases)
	for token := range results {
		if token.IsZero() {
			t.Fatal("concurrent mint returned zero token")
		}
		if _, exists := sequential[token]; exists {
			t.Fatal("concurrent token reused a sequential token")
		}
		if _, exists := concurrent[token]; exists {
			t.Fatal("concurrent lease token was reused")
		}
		concurrent[token] = struct{}{}
	}
}

func TestEventRuntimeStartupGuardLeaseMismatchFailsClosed(t *testing.T) {
	runtime := newTestEventRuntime(t, &fakeEventReader{}, &fakeEventController{}, EventRuntimeOptions{})
	first, err := runtime.PauseForStartupGuard(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	wrong := NewStartupGuardLease()
	if err := runtime.ResumeAfterStartupGuard(t.Context(), wrong); !errors.Is(err, ErrStartupGuardLeaseMismatch) {
		t.Fatalf("wrong-token Resume error = %v", err)
	}
	if got := runtime.StartupGuardPauseStatus().Phase; got != StartupGuardPausePhaseHeld {
		t.Fatalf("wrong-token Resume phase = %q, want held", got)
	}
	if err := runtime.ResumeAfterStartupGuard(t.Context(), StartupGuardLease{}); !errors.Is(err, ErrStartupGuardLeaseMismatch) {
		t.Fatalf("zero-token Resume error = %v", err)
	}
	if err := runtime.ResumeAfterStartupGuard(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	if err := runtime.ResumeAfterStartupGuard(t.Context(), first); err != nil {
		t.Fatalf("idempotent Resume: %v", err)
	}

	second, err := runtime.PauseForStartupGuard(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if second.Token == first.Token {
		t.Fatal("successive barrier acquisitions reused a token")
	}
	if err := runtime.ResumeAfterStartupGuard(t.Context(), first); !errors.Is(err, ErrStartupGuardLeaseMismatch) {
		t.Fatalf("stale-token Resume error = %v", err)
	}
	if got := runtime.StartupGuardPauseStatus().Phase; got != StartupGuardPausePhaseHeld {
		t.Fatalf("stale-token Resume phase = %q, want held", got)
	}
	if err := runtime.ResumeAfterStartupGuard(t.Context(), second); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestEventRuntimeStopInvalidatesLeaseAndWakesDrainingPause(t *testing.T) {
	runtime := newTestEventRuntime(t, &fakeEventReader{}, &fakeEventController{}, EventRuntimeOptions{})
	lease, err := runtime.PauseForStartupGuard(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.RequestStop(); err != nil {
		t.Fatal(err)
	}
	if err := runtime.ResumeAfterStartupGuard(t.Context(), lease); !errors.Is(err, ErrEventRuntimeClosed) {
		t.Fatalf("Resume after stop error = %v", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}

	draining := newTestEventRuntime(t, &fakeEventReader{}, &fakeEventController{}, EventRuntimeOptions{})
	if err := draining.beginGuardableWork(t.Context()); err != nil {
		t.Fatal(err)
	}
	pauseDone := make(chan startupGuardPauseResult, 1)
	go func() {
		lease, err := draining.PauseForStartupGuard(t.Context())
		pauseDone <- startupGuardPauseResult{lease: lease, err: err}
	}()
	waitForEventRuntimePausePhase(t, draining, StartupGuardPausePhaseDraining)
	if err := draining.RequestStop(); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-pauseDone:
		if !errors.Is(result.err, ErrEventRuntimeClosed) || result.lease != (StartupGuardLease{}) {
			t.Fatalf("draining Pause after stop = %#v, %v", result.lease, result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("RequestStop did not wake draining Pause")
	}
	draining.finishGuardableWork()
	if err := draining.Close(); err != nil {
		t.Fatal(err)
	}
}

func waitForEventRuntimePausePhase(
	t *testing.T,
	runtime *EventRuntime,
	want StartupGuardPausePhase,
) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if got := runtime.StartupGuardPauseStatus().Phase; got == want {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("pause phase = %q, want %q", runtime.StartupGuardPauseStatus().Phase, want)
		case <-ticker.C:
		}
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
	reader.mu.Lock()
	reader.closeErr = nil
	reader.mu.Unlock()
	if err := runtime.Close(); err != nil {
		t.Fatalf("Close retry error = %v", err)
	}
	if reader.closeCalls != 2 || controller.closeCalls != 1 {
		t.Fatalf("close calls reader=%d controller=%d", reader.closeCalls, controller.closeCalls)
	}
}

func TestEventRuntimeConcurrentCloseCoalescesErrorsAndLaterRetries(t *testing.T) {
	readerErr := errors.New("reader close failure")
	controllerErr := errors.New("controller close failure")
	closeStarted := make(chan struct{})
	closeRelease := make(chan struct{})
	reader := &fakeEventReader{
		closeErr: readerErr, closeStarted: closeStarted, closeRelease: closeRelease,
	}
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
	select {
	case <-closeStarted:
	case <-time.After(time.Second):
		t.Fatal("Close did not reach reader")
	}
	time.Sleep(10 * time.Millisecond)
	close(closeRelease)
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
	reader.mu.Lock()
	reader.closeErr = nil
	reader.mu.Unlock()
	controller.mu.Lock()
	controller.closeErr = nil
	controller.mu.Unlock()
	if err := runtime.Close(); err != nil {
		t.Fatalf("retry Close error=%v", err)
	}
	if reader.closeCalls != 2 || controller.closeCalls != 2 {
		t.Fatalf("retry close calls reader=%d controller=%d", reader.closeCalls, controller.closeCalls)
	}
	if err := runtime.Close(); err != nil || reader.closeCalls != 2 || controller.closeCalls != 2 {
		t.Fatalf(
			"converged Close error=%v reader calls=%d controller calls=%d",
			err, reader.closeCalls, controller.closeCalls,
		)
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
