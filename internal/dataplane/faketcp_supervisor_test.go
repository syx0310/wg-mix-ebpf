package dataplane

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/faketcp"
)

type controlledFakeTCPRuntime struct {
	mu sync.Mutex

	runStarted      chan struct{}
	stop            chan struct{}
	runErr          error
	stopErr         error
	closeErr        error
	healthErr       error
	pauseErr        error
	resumeErr       error
	healthCalls     int
	stopCalls       int
	closeCalls      int
	pauseCalls      int
	resumeCalls     int
	paused          bool
	closeEarly      bool
	wakeOnStop      bool
	ignoreCancel    bool
	status          *FakeTCPRuntimeStatus
	pauseStarted    chan struct{}
	pauseRelease    <-chan struct{}
	pauseOnce       sync.Once
	pauseLease      faketcp.StartupGuardLease
	pauseReleased   faketcp.StartupGuardLeaseToken
	emptyPauseLease bool
}

type supervisorPauseResult struct {
	lease StartupGuardLease
	err   error
}

// firstNilErrContext makes the pre-serialization Err observation visible. The
// first call always reports an active context and closes prechecked; later
// calls delegate to the cancellable parent.
type firstNilErrContext struct {
	context.Context
	prechecked chan struct{}
	once       sync.Once
}

func newFirstNilErrContext(parent context.Context) *firstNilErrContext {
	return &firstNilErrContext{
		Context:    parent,
		prechecked: make(chan struct{}),
	}
}

func (ctx *firstNilErrContext) Err() error {
	first := false
	ctx.once.Do(func() {
		first = true
		close(ctx.prechecked)
	})
	if first {
		return nil
	}
	return ctx.Context.Err()
}

func newControlledFakeTCPRuntime() *controlledFakeTCPRuntime {
	return &controlledFakeTCPRuntime{
		runStarted: make(chan struct{}),
		stop:       make(chan struct{}),
		wakeOnStop: true,
	}
}

func (runtime *controlledFakeTCPRuntime) Run(ctx context.Context) error {
	close(runtime.runStarted)
	if runtime.ignoreCancel {
		<-runtime.stop
		return runtime.runErr
	}
	select {
	case <-runtime.stop:
	case <-ctx.Done():
	}
	return runtime.runErr
}

func (runtime *controlledFakeTCPRuntime) RequestStop() error {
	runtime.mu.Lock()
	runtime.stopCalls++
	if runtime.stopCalls == 1 && runtime.wakeOnStop {
		close(runtime.stop)
	}
	err := runtime.stopErr
	runtime.mu.Unlock()
	return err
}

func (runtime *controlledFakeTCPRuntime) Close() error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	select {
	case <-runtime.stop:
	default:
		runtime.closeEarly = true
	}
	runtime.closeCalls++
	return runtime.closeErr
}

func (runtime *controlledFakeTCPRuntime) PauseForStartupGuard(
	ctx context.Context,
) (faketcp.StartupGuardLease, error) {
	if ctx == nil {
		return faketcp.StartupGuardLease{}, errors.New("pause context is nil")
	}
	if err := ctx.Err(); err != nil {
		return faketcp.StartupGuardLease{}, err
	}
	runtime.mu.Lock()
	runtime.pauseCalls++
	if runtime.pauseErr != nil {
		err := runtime.pauseErr
		runtime.mu.Unlock()
		return faketcp.StartupGuardLease{}, err
	}
	if runtime.paused {
		lease := faketcp.StartupGuardLease{Token: runtime.pauseLease.Token}
		runtime.mu.Unlock()
		return lease, nil
	}
	pauseStarted := runtime.pauseStarted
	pauseRelease := runtime.pauseRelease
	runtime.mu.Unlock()
	if pauseStarted != nil {
		runtime.pauseOnce.Do(func() { close(pauseStarted) })
	}
	if pauseRelease != nil {
		select {
		case <-ctx.Done():
			return faketcp.StartupGuardLease{}, ctx.Err()
		case <-pauseRelease:
		}
	}
	runtime.mu.Lock()
	lease := faketcp.NewStartupGuardLease()
	runtime.paused = true
	runtime.pauseLease = lease
	runtime.pauseReleased = faketcp.StartupGuardLeaseToken{}
	if runtime.emptyPauseLease {
		lease = faketcp.StartupGuardLease{}
	}
	runtime.mu.Unlock()
	return lease, nil
}

func (runtime *controlledFakeTCPRuntime) ResumeAfterStartupGuard(
	ctx context.Context,
	lease faketcp.StartupGuardLease,
) error {
	if ctx == nil {
		return errors.New("resume context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	runtime.mu.Lock()
	runtime.resumeCalls++
	if lease.Token.IsZero() || (!runtime.paused && runtime.pauseReleased != lease.Token) ||
		(runtime.paused && runtime.pauseLease.Token != lease.Token) {
		runtime.mu.Unlock()
		return faketcp.ErrStartupGuardLeaseMismatch
	}
	if runtime.resumeErr != nil {
		err := runtime.resumeErr
		runtime.mu.Unlock()
		return err
	}
	runtime.paused = false
	runtime.pauseReleased = lease.Token
	runtime.pauseLease = faketcp.StartupGuardLease{}
	runtime.mu.Unlock()
	return nil
}

func (runtime *controlledFakeTCPRuntime) ProductionStatus(
	ctx context.Context,
) (*FakeTCPRuntimeStatus, error) {
	if ctx == nil {
		return nil, errors.New("status context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.status == nil {
		return &FakeTCPRuntimeStatus{Healthy: true}, nil
	}
	status := *runtime.status
	status.XDP = append([]FakeTCPXDPStatus(nil), runtime.status.XDP...)
	status.TCX = append([]FakeTCPTCXStatus(nil), runtime.status.TCX...)
	status.ClassicTC = append([]FakeTCPClassicTCStatus(nil), runtime.status.ClassicTC...)
	return &status, nil
}

func (runtime *controlledFakeTCPRuntime) Healthy(ctx context.Context) error {
	if ctx == nil {
		return errors.New("health context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.healthCalls++
	return runtime.healthErr
}

func (runtime *controlledFakeTCPRuntime) counts() (int, int, bool) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.stopCalls, runtime.closeCalls, runtime.closeEarly
}

func (runtime *controlledFakeTCPRuntime) setCloseError(err error) {
	runtime.mu.Lock()
	runtime.closeErr = err
	runtime.mu.Unlock()
}

func (runtime *controlledFakeTCPRuntime) setHealthError(err error) {
	runtime.mu.Lock()
	runtime.healthErr = err
	runtime.mu.Unlock()
}

func (runtime *controlledFakeTCPRuntime) setPauseError(err error) {
	runtime.mu.Lock()
	runtime.pauseErr = err
	runtime.mu.Unlock()
}

func (runtime *controlledFakeTCPRuntime) setResumeError(err error) {
	runtime.mu.Lock()
	runtime.resumeErr = err
	runtime.mu.Unlock()
}

func TestFakeTCPRuntimeSupervisorRepeatedEnsureOwnsOneRuntime(t *testing.T) {
	supervisor := &fakeTCPRuntimeSupervisor{}
	runtime := newControlledFakeTCPRuntime()
	key := fakeTCPRuntimeDesiredKey{1}
	buildCalls := 0
	build := func(context.Context) (fakeTCPRuntimeService, error) {
		buildCalls++
		return runtime, nil
	}
	if err := supervisor.Ensure(t.Context(), key, build); err != nil {
		t.Fatalf("first Ensure: %v", err)
	}
	<-runtime.runStarted
	if err := supervisor.Ensure(t.Context(), key, build); err != nil {
		t.Fatalf("repeated Ensure: %v", err)
	}
	if buildCalls != 1 {
		t.Fatalf("build calls = %d, want 1", buildCalls)
	}
	if !supervisor.Healthy(key) {
		t.Fatal("supervisor is not healthy for active key")
	}
	if err := supervisor.Stop(t.Context()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	stopCalls, closeCalls, closeEarly := runtime.counts()
	if stopCalls != 1 || closeCalls != 1 || closeEarly {
		t.Fatalf("runtime lifecycle = stop %d close %d early %t", stopCalls, closeCalls, closeEarly)
	}
}

func TestStartupGuardOuterLeaseTokensAreUniqueSequentiallyAndConcurrently(t *testing.T) {
	const leases = 256
	sequential := make(map[StartupGuardLeaseToken]struct{}, leases)
	for range leases {
		lease := NewStartupGuardLease()
		if !lease.Acquired || lease.Token.IsZero() {
			t.Fatalf("minted lease = %#v, want acquired non-zero token", lease)
		}
		if _, exists := sequential[lease.Token]; exists {
			t.Fatal("sequential outer lease token was reused")
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
			t.Fatal("concurrent outer token reused a sequential token")
		}
		if _, exists := concurrent[token]; exists {
			t.Fatal("concurrent outer lease token was reused")
		}
		concurrent[token] = struct{}{}
	}
}

func TestFakeTCPRuntimeSupervisorStartupGuardDrainsOldAndStagesReplacement(t *testing.T) {
	supervisor := &fakeTCPRuntimeSupervisor{}
	first := newControlledFakeTCPRuntime()
	if err := supervisor.Ensure(
		t.Context(), fakeTCPRuntimeDesiredKey{1},
		func(context.Context) (fakeTCPRuntimeService, error) { return first, nil },
	); err != nil {
		t.Fatalf("start first runtime: %v", err)
	}
	<-first.runStarted

	lease, err := supervisor.QuiesceForStartupGuard(t.Context())
	if err != nil {
		t.Fatalf("quiesce for startup guard: %v", err)
	}
	stopCalls, closeCalls, closeEarly := first.counts()
	if stopCalls != 0 || closeCalls != 0 || closeEarly {
		t.Fatalf("quiesced runtime lifecycle = stop %d close %d early %t", stopCalls, closeCalls, closeEarly)
	}

	second := newControlledFakeTCPRuntime()
	if err := supervisor.Ensure(
		t.Context(), fakeTCPRuntimeDesiredKey{2},
		func(context.Context) (fakeTCPRuntimeService, error) { return second, nil },
	); err != nil {
		t.Fatalf("stage replacement runtime: %v", err)
	}
	select {
	case <-second.runStarted:
		t.Fatal("replacement userspace runtime started while startup guard was held")
	default:
	}
	_, closeCalls, closeEarly = first.counts()
	if closeCalls != 1 || closeEarly {
		t.Fatalf("retired runtime close = %d early %t", closeCalls, closeEarly)
	}
	if !supervisor.Healthy(fakeTCPRuntimeDesiredKey{2}) {
		t.Fatal("staged replacement did not retain a healthy kernel owner")
	}

	if err := supervisor.ResumeAfterStartupGuard(t.Context(), lease); err != nil {
		t.Fatalf("resume after startup guard: %v", err)
	}
	select {
	case <-second.runStarted:
	case <-time.After(time.Second):
		t.Fatal("replacement runtime did not start after startup guard cleanup")
	}
	if err := supervisor.Stop(t.Context()); err != nil {
		t.Fatalf("stop replacement: %v", err)
	}
}

func TestFakeTCPRuntimeSupervisorStartupGuardReusesHealthySameKeyRuntime(t *testing.T) {
	supervisor := &fakeTCPRuntimeSupervisor{}
	runtime := newControlledFakeTCPRuntime()
	runtime.status = &FakeTCPRuntimeStatus{
		Generation:  91,
		Incarnation: "same-runtime-incarnation",
		Healthy:     true,
		XDP: []FakeTCPXDPStatus{{
			IfIndex: 11, Mode: "generic", LinkID: 701, ProgramID: 601,
		}},
		TCX: []FakeTCPTCXStatus{{
			IfIndex: 11, Direction: "egress", LinkID: 702, ProgramID: 602,
		}},
	}
	key := fakeTCPRuntimeDesiredKey{1}
	builds := 0
	build := func(context.Context) (fakeTCPRuntimeService, error) {
		builds++
		return runtime, nil
	}
	if err := supervisor.Ensure(t.Context(), key, build); err != nil {
		t.Fatal(err)
	}
	<-runtime.runStarted
	lease, err := supervisor.QuiesceForStartupGuard(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	before, err := supervisor.CurrentProductionStatus(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Ensure(t.Context(), key, build); err != nil {
		t.Fatal(err)
	}
	if err := supervisor.ResumeAfterStartupGuard(t.Context(), lease); err != nil {
		t.Fatal(err)
	}
	if builds != 1 || supervisor.loadCurrent().runtime != runtime {
		t.Fatalf("same-key reload replaced runtime: builds=%d current=%T", builds, supervisor.loadCurrent().runtime)
	}
	after, err := supervisor.CurrentProductionStatus(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after.XDP, before.XDP) || !reflect.DeepEqual(after.TCX, before.TCX) ||
		after.Incarnation != before.Incarnation {
		t.Fatalf("same-key reload changed exact runtime identity: before=%#v after=%#v", before, after)
	}
	runtime.mu.Lock()
	pauseCalls, resumeCalls, paused := runtime.pauseCalls, runtime.resumeCalls, runtime.paused
	runtime.mu.Unlock()
	if pauseCalls != 1 || resumeCalls != 1 || paused {
		t.Fatalf("guard pause lifecycle = pause %d resume %d paused %t", pauseCalls, resumeCalls, paused)
	}
	if err := supervisor.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestFakeTCPRuntimeSupervisorStartupGuardFailureRollbackIsOwnershipScoped(t *testing.T) {
	supervisor := &fakeTCPRuntimeSupervisor{}
	initial := supervisor.StartupGuardPauseStatus()
	if initial.Phase != faketcp.StartupGuardPausePhaseOpen ||
		initial.Reason != faketcp.StartupGuardPauseReasonNone || initial.Since.IsZero() {
		t.Fatalf("initial barrier status = %#v", initial)
	}
	runtime := newControlledFakeTCPRuntime()
	if err := supervisor.Ensure(
		t.Context(), fakeTCPRuntimeDesiredKey{1},
		func(context.Context) (fakeTCPRuntimeService, error) { return runtime, nil },
	); err != nil {
		t.Fatal(err)
	}
	<-runtime.runStarted

	pauseErr := errors.New("pause failed before drain")
	runtime.setPauseError(pauseErr)
	if lease, err := supervisor.QuiesceForStartupGuard(t.Context()); !errors.Is(err, pauseErr) ||
		lease != (StartupGuardLease{}) {
		t.Fatalf("Quiesce error = %v", err)
	}
	rolledBack := supervisor.StartupGuardPauseStatus()
	if rolledBack.Phase != faketcp.StartupGuardPausePhaseOpen ||
		rolledBack.Reason != faketcp.StartupGuardPauseReasonNone {
		t.Fatalf("new barrier was not rolled back = %#v", rolledBack)
	}

	runtime.setPauseError(nil)
	lease, err := supervisor.QuiesceForStartupGuard(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	held := supervisor.StartupGuardPauseStatus()
	if held.Phase != faketcp.StartupGuardPausePhaseHeld ||
		held.Reason != faketcp.StartupGuardPauseReasonStartupGuard || held.Since.IsZero() {
		t.Fatalf("held barrier status = %#v", held)
	}
	runtime.mu.Lock()
	pauseCalls := runtime.pauseCalls
	runtime.mu.Unlock()
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	borrowed, err := supervisor.QuiesceForStartupGuard(cancelled)
	if err != nil {
		t.Fatalf("repeated Quiesce on old held barrier: %v", err)
	}
	if borrowed.Acquired || borrowed.Token.IsZero() || borrowed.Token != lease.Token {
		t.Fatalf("repeated Quiesce lease = %#v, want borrowed original token", borrowed)
	}
	if got := supervisor.StartupGuardPauseStatus(); got != held {
		t.Fatalf("failed/repeated Quiesce released old barrier: got %#v want %#v", got, held)
	}
	runtime.mu.Lock()
	if runtime.pauseCalls != pauseCalls {
		t.Fatalf("repeated Quiesce called runtime Pause: got %d want %d", runtime.pauseCalls, pauseCalls)
	}
	runtime.mu.Unlock()

	resumeErr := errors.New("resume failed")
	runtime.setResumeError(resumeErr)
	if err := supervisor.ResumeAfterStartupGuard(t.Context(), borrowed); !errors.Is(err, resumeErr) {
		t.Fatalf("Resume error = %v", err)
	}
	if got := supervisor.StartupGuardPauseStatus(); got != held {
		t.Fatalf("failed Resume released old barrier: got %#v want %#v", got, held)
	}
	runtime.setResumeError(nil)
	if err := supervisor.ResumeAfterStartupGuard(t.Context(), lease); err != nil {
		t.Fatal(err)
	}
	if got := supervisor.StartupGuardPauseStatus(); got.Phase != faketcp.StartupGuardPausePhaseOpen ||
		got.Reason != faketcp.StartupGuardPauseReasonNone {
		t.Fatalf("resumed barrier status = %#v", got)
	}
	if err := supervisor.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Stop(t.Context()); err != nil {
		t.Fatalf("repeated Stop: %v", err)
	}
}

func TestFakeTCPRuntimeSupervisorStartupGuardLeaseRetryAndMismatchFailClosed(t *testing.T) {
	supervisor := &fakeTCPRuntimeSupervisor{}
	first, err := supervisor.QuiesceForStartupGuard(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !first.Acquired || first.Token.IsZero() {
		t.Fatalf("first lease = %#v, want acquired non-zero token", first)
	}

	// Model an attempt that failed after installing the guard: it intentionally
	// returns without releasing its outer barrier. The next lifecycle-serialised
	// attempt borrows the same token and can release it only after its own guard
	// cleanup has proved Absent.
	retry, err := supervisor.QuiesceForStartupGuard(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if retry.Acquired || retry.Token.IsZero() || retry.Token != first.Token {
		t.Fatalf("retry lease = %#v, want borrowed first token", retry)
	}
	wrong := NewStartupGuardLease()
	if err := supervisor.ResumeAfterStartupGuard(t.Context(), wrong); !errors.Is(err, ErrStartupGuardLeaseMismatch) {
		t.Fatalf("wrong-token Resume error = %v", err)
	}
	if got := supervisor.StartupGuardPauseStatus().Phase; got != faketcp.StartupGuardPausePhaseHeld {
		t.Fatalf("wrong-token Resume phase = %q, want held", got)
	}
	if err := supervisor.ResumeAfterStartupGuard(t.Context(), StartupGuardLease{}); !errors.Is(err, ErrStartupGuardLeaseMismatch) {
		t.Fatalf("zero-token Resume error = %v", err)
	}
	if err := supervisor.ResumeAfterStartupGuard(t.Context(), retry); err != nil {
		t.Fatal(err)
	}
	if err := supervisor.ResumeAfterStartupGuard(t.Context(), first); err != nil {
		t.Fatalf("idempotent Resume with acquired lease: %v", err)
	}

	second, err := supervisor.QuiesceForStartupGuard(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !second.Acquired || second.Token.IsZero() || second.Token == first.Token {
		t.Fatalf("second lease = %#v, want fresh acquired token", second)
	}
	if err := supervisor.ResumeAfterStartupGuard(t.Context(), first); !errors.Is(err, ErrStartupGuardLeaseMismatch) {
		t.Fatalf("stale-token Resume error = %v", err)
	}
	if got := supervisor.StartupGuardPauseStatus().Phase; got != faketcp.StartupGuardPausePhaseHeld {
		t.Fatalf("stale-token Resume phase = %q, want held", got)
	}
	if err := supervisor.ResumeAfterStartupGuard(t.Context(), second); err != nil {
		t.Fatal(err)
	}
}

func TestFakeTCPRuntimeSupervisorLeafLeaseContractFailureStaysHeldAndCanReplace(t *testing.T) {
	supervisor := &fakeTCPRuntimeSupervisor{}
	broken := newControlledFakeTCPRuntime()
	broken.emptyPauseLease = true
	if err := supervisor.Ensure(
		t.Context(), fakeTCPRuntimeDesiredKey{1},
		func(context.Context) (fakeTCPRuntimeService, error) { return broken, nil },
	); err != nil {
		t.Fatal(err)
	}
	<-broken.runStarted
	if lease, err := supervisor.QuiesceForStartupGuard(t.Context()); err == nil ||
		lease != (StartupGuardLease{}) {
		t.Fatalf("Quiesce with empty leaf lease = %#v, %v", lease, err)
	}
	if got := supervisor.StartupGuardPauseStatus().Phase; got != faketcp.StartupGuardPausePhaseHeld {
		t.Fatalf("empty leaf lease phase = %q, want held", got)
	}
	retry, err := supervisor.QuiesceForStartupGuard(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if retry.Acquired || retry.Token.IsZero() {
		t.Fatalf("retry lease = %#v, want borrowed outer token", retry)
	}

	replacement := newControlledFakeTCPRuntime()
	if err := supervisor.Ensure(
		t.Context(), fakeTCPRuntimeDesiredKey{2},
		func(context.Context) (fakeTCPRuntimeService, error) { return replacement, nil },
	); err != nil {
		t.Fatal(err)
	}
	select {
	case <-replacement.runStarted:
		t.Fatal("replacement started before outer lease release")
	default:
	}
	if err := supervisor.ResumeAfterStartupGuard(t.Context(), retry); err != nil {
		t.Fatal(err)
	}
	select {
	case <-replacement.runStarted:
	case <-time.After(time.Second):
		t.Fatal("replacement did not start after outer lease release")
	}
	if err := supervisor.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestFakeTCPRuntimeSupervisorExposesDrainingBeforeHeld(t *testing.T) {
	supervisor := &fakeTCPRuntimeSupervisor{}
	runtime := newControlledFakeTCPRuntime()
	runtime.pauseStarted = make(chan struct{})
	pauseRelease := make(chan struct{})
	runtime.pauseRelease = pauseRelease
	if err := supervisor.Ensure(
		t.Context(), fakeTCPRuntimeDesiredKey{1},
		func(context.Context) (fakeTCPRuntimeService, error) { return runtime, nil },
	); err != nil {
		t.Fatal(err)
	}
	<-runtime.runStarted

	pauseDone := make(chan supervisorPauseResult, 1)
	go func() {
		lease, err := supervisor.QuiesceForStartupGuard(t.Context())
		pauseDone <- supervisorPauseResult{lease: lease, err: err}
	}()
	select {
	case <-runtime.pauseStarted:
	case <-time.After(time.Second):
		t.Fatal("runtime Pause was not called")
	}
	draining := supervisor.StartupGuardPauseStatus()
	if draining.Phase != faketcp.StartupGuardPausePhaseDraining ||
		draining.Reason != faketcp.StartupGuardPauseReasonStartupGuard ||
		draining.Since.IsZero() {
		t.Fatalf("draining barrier status = %#v", draining)
	}
	close(pauseRelease)
	pauseResult := <-pauseDone
	if pauseResult.err != nil {
		t.Fatal(pauseResult.err)
	}
	if got := supervisor.StartupGuardPauseStatus(); got.Phase != faketcp.StartupGuardPausePhaseHeld ||
		got.Reason != faketcp.StartupGuardPauseReasonStartupGuard ||
		got.Since.Before(draining.Since) {
		t.Fatalf("held barrier status = %#v after draining %#v", got, draining)
	}
	if err := supervisor.ResumeAfterStartupGuard(t.Context(), pauseResult.lease); err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestFakeTCPRuntimeSupervisorStartupGuardRetryAndPendingStopAreBounded(t *testing.T) {
	supervisor := &fakeTCPRuntimeSupervisor{}
	lease, err := supervisor.QuiesceForStartupGuard(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	runtime := newControlledFakeTCPRuntime()
	builds := 0
	build := func(context.Context) (fakeTCPRuntimeService, error) {
		builds++
		return runtime, nil
	}
	key := fakeTCPRuntimeDesiredKey{1}
	if err := supervisor.Ensure(t.Context(), key, build); err != nil {
		t.Fatal(err)
	}
	// A failed reload leaves the barrier held. Its lifecycle-serialised retry
	// reuses the same staged owner instead of building an overlapping runtime.
	borrowed, err := supervisor.QuiesceForStartupGuard(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if borrowed.Acquired || borrowed.Token != lease.Token {
		t.Fatalf("retry lease = %#v, want borrowed token", borrowed)
	}
	if err := supervisor.Ensure(t.Context(), key, build); err != nil {
		t.Fatal(err)
	}
	if builds != 1 {
		t.Fatalf("staged retry builds = %d, want 1", builds)
	}
	select {
	case <-runtime.runStarted:
		t.Fatal("staged retry started before guard cleanup")
	default:
	}

	// Stop must not wait forever for a Run goroutine that was deliberately not
	// started while the guard barrier was held.
	if err := supervisor.Stop(t.Context()); err != nil {
		t.Fatalf("stop staged runtime: %v", err)
	}
	if supervisor.loadCurrent() != nil {
		t.Fatal("stop retained a staged runtime after successful close")
	}
	if err := supervisor.ResumeAfterStartupGuard(t.Context(), borrowed); err != nil {
		t.Fatalf("release empty startup guard barrier: %v", err)
	}
}

func TestFakeTCPRuntimeSupervisorSeriallyReplacesChangedLiveGeneration(t *testing.T) {
	supervisor := &fakeTCPRuntimeSupervisor{}
	firstRuntime := newControlledFakeTCPRuntime()
	if err := supervisor.Ensure(
		t.Context(), fakeTCPRuntimeDesiredKey{1},
		func(context.Context) (fakeTCPRuntimeService, error) { return firstRuntime, nil },
	); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	<-firstRuntime.runStarted
	secondRuntime := newControlledFakeTCPRuntime()
	replacementBuilds := 0
	oldRetiredBeforeBuild := false
	err := supervisor.Ensure(
		t.Context(), fakeTCPRuntimeDesiredKey{2},
		func(context.Context) (fakeTCPRuntimeService, error) {
			replacementBuilds++
			stopCalls, closeCalls, closeEarly := firstRuntime.counts()
			oldRetiredBeforeBuild = stopCalls == 1 && closeCalls == 1 && !closeEarly &&
				supervisor.loadCurrent() == nil
			return secondRuntime, nil
		},
	)
	if err != nil {
		t.Fatalf("changed generation replacement: %v", err)
	}
	<-secondRuntime.runStarted
	if replacementBuilds != 1 || !oldRetiredBeforeBuild ||
		supervisor.Healthy(fakeTCPRuntimeDesiredKey{1}) ||
		!supervisor.Healthy(fakeTCPRuntimeDesiredKey{2}) {
		t.Fatalf(
			"replacement builds = %d, old retired before build = %t, old healthy = %t, new healthy = %t",
			replacementBuilds,
			oldRetiredBeforeBuild,
			supervisor.Healthy(fakeTCPRuntimeDesiredKey{1}),
			supervisor.Healthy(fakeTCPRuntimeDesiredKey{2}),
		)
	}
	stopCalls, closeCalls, closeEarly := firstRuntime.counts()
	if stopCalls != 1 || closeCalls != 1 || closeEarly {
		t.Fatalf("old runtime lifecycle = stop %d close %d early %t", stopCalls, closeCalls, closeEarly)
	}
	if err := supervisor.Stop(t.Context()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestFakeTCPRuntimeSupervisorRebuildsUnhealthySameGeneration(t *testing.T) {
	supervisor := &fakeTCPRuntimeSupervisor{}
	key := fakeTCPRuntimeDesiredKey{1}
	firstRuntime := newControlledFakeTCPRuntime()
	if err := supervisor.Ensure(
		t.Context(), key,
		func(context.Context) (fakeTCPRuntimeService, error) { return firstRuntime, nil },
	); err != nil {
		t.Fatalf("first Ensure: %v", err)
	}
	<-firstRuntime.runStarted
	firstRuntime.setHealthError(errors.New("owned link disappeared"))
	secondRuntime := newControlledFakeTCPRuntime()
	builds := 0
	if err := supervisor.Ensure(
		t.Context(), key,
		func(context.Context) (fakeTCPRuntimeService, error) {
			builds++
			return secondRuntime, nil
		},
	); err != nil {
		t.Fatalf("unhealthy same-key Ensure: %v", err)
	}
	<-secondRuntime.runStarted
	if builds != 1 || !supervisor.Healthy(key) {
		t.Fatalf("replacement builds=%d healthy=%t", builds, supervisor.Healthy(key))
	}
	stopCalls, closeCalls, closeEarly := firstRuntime.counts()
	if stopCalls != 1 || closeCalls != 1 || closeEarly {
		t.Fatalf("old runtime lifecycle = stop %d close %d early %t", stopCalls, closeCalls, closeEarly)
	}
	if err := supervisor.Stop(t.Context()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestFakeTCPRuntimeSupervisorBuildFailureLeavesNoOwner(t *testing.T) {
	supervisor := &fakeTCPRuntimeSupervisor{}
	buildErr := errors.New("build failed")
	err := supervisor.Ensure(
		t.Context(), fakeTCPRuntimeDesiredKey{1},
		func(context.Context) (fakeTCPRuntimeService, error) { return nil, buildErr },
	)
	if !errors.Is(err, buildErr) {
		t.Fatalf("Ensure error = %v", err)
	}
	if supervisor.loadCurrent() != nil {
		t.Fatal("failed build left a supervised runtime")
	}
}

func TestFakeTCPRuntimeSupervisorCancellationClosesUnstartedOwner(t *testing.T) {
	supervisor := &fakeTCPRuntimeSupervisor{}
	runtime := newControlledFakeTCPRuntime()
	ctx, cancel := context.WithCancel(t.Context())
	err := supervisor.Ensure(ctx, fakeTCPRuntimeDesiredKey{1}, func(context.Context) (fakeTCPRuntimeService, error) {
		cancel()
		return runtime, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Ensure error = %v", err)
	}
	_, closeCalls, _ := runtime.counts()
	if closeCalls != 1 || supervisor.loadCurrent() != nil {
		t.Fatalf("close calls = %d, current = %#v", closeCalls, supervisor.loadCurrent())
	}
}

func TestFakeTCPRuntimeSupervisorReportsUnexpectedRunExit(t *testing.T) {
	supervisor := &fakeTCPRuntimeSupervisor{}
	runtime := newControlledFakeTCPRuntime()
	close(runtime.stop)
	if err := supervisor.Ensure(
		t.Context(), fakeTCPRuntimeDesiredKey{1},
		func(context.Context) (fakeTCPRuntimeService, error) { return runtime, nil },
	); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	select {
	case <-supervisor.loadCurrent().done:
	case <-time.After(time.Second):
		t.Fatal("runtime did not exit")
	}
	if supervisor.Healthy(fakeTCPRuntimeDesiredKey{1}) {
		t.Fatal("exited runtime reported healthy")
	}
	if !errors.Is(supervisor.RuntimeError(), errFakeTCPRuntimeExited) {
		t.Fatalf("RuntimeError = %v", supervisor.RuntimeError())
	}
	err := supervisor.Ensure(
		t.Context(), fakeTCPRuntimeDesiredKey{1},
		func(context.Context) (fakeTCPRuntimeService, error) {
			t.Fatal("replacement build ran before terminal error was reported")
			return nil, nil
		},
	)
	if !errors.Is(err, errFakeTCPRuntimeExited) {
		t.Fatalf("retire error = %v", err)
	}
	_, closeCalls, _ := runtime.counts()
	if closeCalls != 1 || supervisor.loadCurrent() != nil {
		t.Fatalf("close calls = %d, current = %#v", closeCalls, supervisor.loadCurrent())
	}
}

func TestFakeTCPRuntimeSupervisorStopTimeoutRetainsOwnership(t *testing.T) {
	supervisor := &fakeTCPRuntimeSupervisor{}
	runtime := newControlledFakeTCPRuntime()
	// Model a broken stop implementation: count the request without waking Run.
	runtime.wakeOnStop = false
	runtime.ignoreCancel = true
	runtime.stopErr = errors.New("stop unavailable")
	if err := supervisor.Ensure(
		t.Context(), fakeTCPRuntimeDesiredKey{1},
		func(context.Context) (fakeTCPRuntimeService, error) { return runtime, nil },
	); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	<-runtime.runStarted
	ctx, cancel := context.WithTimeout(t.Context(), time.Millisecond)
	defer cancel()
	if err := supervisor.Stop(ctx); !errors.Is(err, context.DeadlineExceeded) ||
		!errors.Is(err, runtime.stopErr) {
		t.Fatalf("Stop error = %v", err)
	}
	if supervisor.loadCurrent() == nil {
		t.Fatal("timed-out stop discarded runtime ownership")
	}
	key := fakeTCPRuntimeDesiredKey{1}
	if supervisor.Healthy(key) {
		t.Fatal("stop-requested runtime reported healthy after timeout")
	}
	replacementBuilds := 0
	if err := supervisor.Ensure(
		t.Context(), key,
		func(context.Context) (fakeTCPRuntimeService, error) {
			replacementBuilds++
			return newControlledFakeTCPRuntime(), nil
		},
	); !errors.Is(err, errFakeTCPRuntimeStopping) {
		t.Fatalf("same-key Ensure during timed-out stop error = %v", err)
	}
	if replacementBuilds != 0 {
		t.Fatalf("same-key Ensure built %d overlapping runtimes", replacementBuilds)
	}
	_, closeCalls, _ := runtime.counts()
	if closeCalls != 0 {
		t.Fatalf("close calls = %d before Run exit", closeCalls)
	}
	close(runtime.stop)
	if err := supervisor.Stop(t.Context()); err != nil {
		t.Fatalf("retry Stop: %v", err)
	}
}

func TestFakeTCPRuntimeSupervisorKeepsSYNQuotaOwnerUntilCloseCompletes(t *testing.T) {
	supervisor := &fakeTCPRuntimeSupervisor{}
	runtime := newControlledFakeTCPRuntime()
	closeErr := errors.New("injected runtime close failure")
	runtime.setCloseError(closeErr)
	key := fakeTCPRuntimeDesiredKey{1}
	if err := supervisor.Ensure(
		t.Context(), key,
		func(context.Context) (fakeTCPRuntimeService, error) { return runtime, nil },
	); err != nil {
		t.Fatal(err)
	}
	<-runtime.runStarted
	if err := supervisor.Stop(t.Context()); !errors.Is(err, closeErr) {
		t.Fatalf("first Stop error = %v", err)
	}
	if supervisor.loadCurrent() == nil {
		t.Fatal("failed Close discarded the only runtime owner")
	}
	replacementBuilds := 0
	restartKeys := []fakeTCPRuntimeDesiredKey{{1}, {2}, {3}, {255}}
	for attempt, restartKey := range restartKeys {
		if err := supervisor.Ensure(
			t.Context(), restartKey,
			func(context.Context) (fakeTCPRuntimeService, error) {
				replacementBuilds++
				return newControlledFakeTCPRuntime(), nil
			},
		); !errors.Is(err, closeErr) {
			t.Fatalf("restart attempt %d during quota-owner quarantine error = %v", attempt, err)
		}
		if replacementBuilds != 0 || supervisor.loadCurrent() == nil {
			t.Fatalf("restart attempt %d built overlapping quota owner: builds=%d current=%#v",
				attempt, replacementBuilds, supervisor.loadCurrent())
		}
	}
	runtime.setCloseError(nil)
	if err := supervisor.Stop(t.Context()); err != nil {
		t.Fatalf("retry Stop: %v", err)
	}
	if supervisor.loadCurrent() != nil {
		t.Fatal("successful retry retained quarantine owner")
	}
	_, closeCalls, _ := runtime.counts()
	wantCloseCalls := 2 + len(restartKeys)
	if closeCalls != wantCloseCalls {
		t.Fatalf("Close calls = %d, want initial Stop + %d restart attempts + final Stop",
			closeCalls, len(restartKeys))
	}

	replacement := newControlledFakeTCPRuntime()
	if err := supervisor.Ensure(
		t.Context(), fakeTCPRuntimeDesiredKey{2},
		func(context.Context) (fakeTCPRuntimeService, error) {
			replacementBuilds++
			return replacement, nil
		},
	); err != nil {
		t.Fatalf("Ensure after old quota owner closed: %v", err)
	}
	<-replacement.runStarted
	if replacementBuilds != 1 || !supervisor.Healthy(fakeTCPRuntimeDesiredKey{2}) {
		t.Fatalf("replacement quota owner builds=%d healthy=%t",
			replacementBuilds, supervisor.Healthy(fakeTCPRuntimeDesiredKey{2}))
	}
	if err := supervisor.Stop(t.Context()); err != nil {
		t.Fatalf("replacement Stop: %v", err)
	}
}

func TestFakeTCPRuntimeSupervisorQuarantinesUnstartedCloseFailure(t *testing.T) {
	supervisor := &fakeTCPRuntimeSupervisor{}
	runtime := newControlledFakeTCPRuntime()
	closeErr := errors.New("injected unstarted close failure")
	runtime.setCloseError(closeErr)
	ctx, cancel := context.WithCancel(t.Context())
	err := supervisor.Ensure(
		ctx,
		fakeTCPRuntimeDesiredKey{1},
		func(context.Context) (fakeTCPRuntimeService, error) {
			cancel()
			return runtime, nil
		},
	)
	if !errors.Is(err, context.Canceled) || !errors.Is(err, closeErr) {
		t.Fatalf("Ensure error = %v", err)
	}
	if supervisor.loadCurrent() == nil {
		t.Fatal("unstarted Close failure discarded runtime owner")
	}
	runtime.setCloseError(nil)
	if err := supervisor.Stop(t.Context()); err != nil {
		t.Fatalf("retry quarantined Close: %v", err)
	}
	if supervisor.loadCurrent() != nil {
		t.Fatal("quarantined unstarted owner remains after retry")
	}
}

func TestFakeTCPRuntimeSupervisorRechecksEnsureCancellationAfterSerialization(t *testing.T) {
	supervisor := &fakeTCPRuntimeSupervisor{}
	supervisor.operationMu.Lock()
	parent, cancel := context.WithCancel(t.Context())
	ctx := newFirstNilErrContext(parent)
	done := make(chan error, 1)
	buildCalls := 0
	go func() {
		done <- supervisor.Ensure(
			ctx,
			fakeTCPRuntimeDesiredKey{1},
			func(context.Context) (fakeTCPRuntimeService, error) {
				buildCalls++
				return newControlledFakeTCPRuntime(), nil
			},
		)
	}()
	<-ctx.prechecked
	cancel()
	supervisor.operationMu.Unlock()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Ensure error = %v", err)
	}
	if buildCalls != 0 || supervisor.loadCurrent() != nil {
		t.Fatalf("build calls = %d, current = %#v", buildCalls, supervisor.loadCurrent())
	}
}

func TestFakeTCPRuntimeSupervisorRechecksStopCancellationAfterSerialization(t *testing.T) {
	supervisor := &fakeTCPRuntimeSupervisor{}
	runtime := newControlledFakeTCPRuntime()
	if err := supervisor.Ensure(
		t.Context(),
		fakeTCPRuntimeDesiredKey{1},
		func(context.Context) (fakeTCPRuntimeService, error) { return runtime, nil },
	); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	<-runtime.runStarted

	supervisor.operationMu.Lock()
	parent, cancel := context.WithCancel(t.Context())
	ctx := newFirstNilErrContext(parent)
	done := make(chan error, 1)
	go func() { done <- supervisor.Stop(ctx) }()
	<-ctx.prechecked
	cancel()
	supervisor.operationMu.Unlock()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Stop error = %v", err)
	}
	stopCalls, closeCalls, _ := runtime.counts()
	if stopCalls != 0 || closeCalls != 0 || !supervisor.Healthy(fakeTCPRuntimeDesiredKey{1}) {
		t.Fatalf("runtime lifecycle = stop %d close %d healthy %t", stopCalls, closeCalls, supervisor.Healthy(fakeTCPRuntimeDesiredKey{1}))
	}
	if err := supervisor.Stop(t.Context()); err != nil {
		t.Fatalf("cleanup Stop: %v", err)
	}
}
