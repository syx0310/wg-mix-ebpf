//go:build linux

package faketcp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

type runtimeIdentityTestTrace struct {
	mu         sync.Mutex
	operations []string
}

func (trace *runtimeIdentityTestTrace) add(operation string) {
	trace.mu.Lock()
	trace.operations = append(trace.operations, operation)
	trace.mu.Unlock()
}

func (trace *runtimeIdentityTestTrace) snapshot() []string {
	trace.mu.Lock()
	defer trace.mu.Unlock()
	return append([]string(nil), trace.operations...)
}

type fakeRuntimeIdentityMap struct {
	mu sync.Mutex

	info              ebpf.MapInfo
	kind              string
	identity          [32]byte
	sequences         []uint64
	failUpdate        int
	updateCalls       int
	successfulUpdates int
	trace             *runtimeIdentityTestTrace
}

func (m *fakeRuntimeIdentityMap) Info() (*ebpf.MapInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	info := m.info
	return &info, nil
}

func (m *fakeRuntimeIdentityMap) Lookup(_ any, valueOut any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch m.kind {
	case "identity":
		value, ok := valueOut.(*[32]byte)
		if !ok {
			return fmt.Errorf("identity lookup output is %T", valueOut)
		}
		*value = m.identity
		m.trace.add("lookup-identity")
	case "sequence":
		value, ok := valueOut.([]uint64)
		if !ok {
			return fmt.Errorf("sequence lookup output is %T", valueOut)
		}
		if len(value) != len(m.sequences) {
			return fmt.Errorf("sequence lookup slots=%d want=%d", len(value), len(m.sequences))
		}
		copy(value, m.sequences)
		m.trace.add("lookup-sequence")
	default:
		return fmt.Errorf("unknown fake runtime map kind %q", m.kind)
	}
	return nil
}

func (m *fakeRuntimeIdentityMap) Update(_ any, value any, _ ebpf.MapUpdateFlags) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updateCalls++
	if m.failUpdate == m.updateCalls {
		return errors.New("injected map update failure")
	}
	switch m.kind {
	case "identity":
		typed, ok := value.(*abi.FakeTCPRuntimeIdentityValue)
		if !ok {
			return fmt.Errorf("identity update value is %T", value)
		}
		m.identity = encodeRuntimeIdentityValue(*typed)
		if *typed == (abi.FakeTCPRuntimeIdentityValue{}) {
			m.trace.add("disable")
		} else {
			m.trace.add(fmt.Sprintf("commit:%d:%d", typed.Generation, typed.EventABIVersion))
		}
	case "sequence":
		typed, ok := value.([]uint64)
		if !ok {
			return fmt.Errorf("sequence update value is %T", value)
		}
		if len(typed) != len(m.sequences) {
			return fmt.Errorf("sequence update slots=%d want=%d", len(typed), len(m.sequences))
		}
		m.sequences = append(m.sequences[:0], typed...)
		m.trace.add(fmt.Sprintf("reset:%d", len(typed)))
	default:
		return fmt.Errorf("unknown fake runtime map kind %q", m.kind)
	}
	m.successfulUpdates++
	return nil
}

func (m *fakeRuntimeIdentityMap) setFailUpdate(call int) {
	m.mu.Lock()
	m.failUpdate = call
	m.mu.Unlock()
}

func (m *fakeRuntimeIdentityMap) setIdentityByte(index int, value byte) {
	m.mu.Lock()
	m.identity[index] = value
	m.mu.Unlock()
}

func (m *fakeRuntimeIdentityMap) setSequence(cpu int, value uint64) {
	m.mu.Lock()
	m.sequences[cpu] = value
	m.mu.Unlock()
}

func (m *fakeRuntimeIdentityMap) mutateInfo(mutate func(*ebpf.MapInfo)) {
	m.mu.Lock()
	mutate(&m.info)
	m.mu.Unlock()
}

func (m *fakeRuntimeIdentityMap) counts() (calls, successful int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.updateCalls, m.successfulUpdates
}

func (m *fakeRuntimeIdentityMap) identityValue() [32]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.identity
}

func encodeRuntimeIdentityValue(value abi.FakeTCPRuntimeIdentityValue) [32]byte {
	var encoded [32]byte
	binary.NativeEndian.PutUint64(encoded[0:8], value.Generation)
	copy(encoded[8:24], value.Incarnation[:])
	binary.NativeEndian.PutUint16(encoded[24:26], value.EventABIVersion)
	return encoded
}

func fakeRuntimeMaps(possibleCPUs int) (
	*fakeRuntimeIdentityMap,
	*fakeRuntimeIdentityMap,
	*runtimeIdentityTestTrace,
) {
	trace := &runtimeIdentityTestTrace{}
	return &fakeRuntimeIdentityMap{
			info: ebpf.MapInfo{
				Name: fakeTCPRuntimeIdentityMapName, Type: ebpf.Array,
				KeySize: 4, ValueSize: 32, MaxEntries: 1,
			},
			kind: "identity", trace: trace,
		}, &fakeRuntimeIdentityMap{
			info: ebpf.MapInfo{
				Name: fakeTCPCaptureSequenceMapName, Type: ebpf.PerCPUArray,
				KeySize: 4, ValueSize: 8, MaxEntries: 1,
			},
			kind: "sequence", sequences: make([]uint64, possibleCPUs), trace: trace,
		}, trace
}

func testLinuxRuntimeIdentity() RuntimeIdentity {
	return RuntimeIdentity{Generation: 7, Incarnation: RuntimeIncarnation{1, 2, 3}}
}

func newFakeRuntimeIdentityHook(
	t *testing.T,
	identityMap linuxRuntimeIdentityMap,
	sequenceMap linuxRuntimeIdentityMap,
	identity RuntimeIdentity,
	possibleCPUs int,
) *linuxRuntimeIdentityPreCommit {
	t.Helper()
	hook, err := newLinuxRuntimeIdentityPreCommit(func() error {
		return seedLinuxRuntimeIdentity(identityMap, sequenceMap, identity, possibleCPUs)
	})
	if err != nil {
		t.Fatal(err)
	}
	return hook
}

func TestSeedLinuxRuntimeIdentityReadsFreshGuardThenCommitsIdentityLast(t *testing.T) {
	identityMap, sequenceMap, trace := fakeRuntimeMaps(4)
	if err := seedLinuxRuntimeIdentity(
		identityMap, sequenceMap, testLinuxRuntimeIdentity(), 4,
	); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"lookup-identity", "lookup-sequence", "disable", "reset:4", "commit:7:1",
	}
	if got := trace.snapshot(); !slices.Equal(got, want) {
		t.Fatalf("seed operations=%v want=%v", got, want)
	}
	if identityMap.identityValue() == ([32]byte{}) {
		t.Fatal("successful seed did not persist the runtime identity guard")
	}
}

func TestSeedLinuxRuntimeIdentityRejectsEveryNonFreshStateBeforeWrites(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*fakeRuntimeIdentityMap, *fakeRuntimeIdentityMap)
	}{
		{
			name: "identity field nonzero",
			mutate: func(identityMap, _ *fakeRuntimeIdentityMap) {
				identityMap.setIdentityByte(0, 1)
			},
		},
		{
			name: "identity padding nonzero",
			mutate: func(identityMap, _ *fakeRuntimeIdentityMap) {
				identityMap.setIdentityByte(31, 1)
			},
		},
		{
			name: "identity contract",
			mutate: func(identityMap, _ *fakeRuntimeIdentityMap) {
				identityMap.mutateInfo(func(info *ebpf.MapInfo) { info.ValueSize-- })
			},
		},
		{
			name: "sequence contract",
			mutate: func(_ *fakeRuntimeIdentityMap, sequenceMap *fakeRuntimeIdentityMap) {
				sequenceMap.mutateInfo(func(info *ebpf.MapInfo) { info.MaxEntries++ })
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			identityMap, sequenceMap, _ := fakeRuntimeMaps(4)
			test.mutate(identityMap, sequenceMap)
			err := seedLinuxRuntimeIdentity(
				identityMap, sequenceMap, testLinuxRuntimeIdentity(), 4,
			)
			if err == nil {
				t.Fatal("non-fresh or invalid runtime namespace was accepted")
			}
			if writes, _ := identityMap.counts(); writes != 0 {
				t.Fatalf("identity map write calls=%d want=0", writes)
			}
			if writes, _ := sequenceMap.counts(); writes != 0 {
				t.Fatalf("sequence map write calls=%d want=0", writes)
			}
		})
	}

	for cpu := range 4 {
		t.Run(fmt.Sprintf("sequence slot %d nonzero", cpu), func(t *testing.T) {
			identityMap, sequenceMap, _ := fakeRuntimeMaps(4)
			sequenceMap.setSequence(cpu, 99)
			err := seedLinuxRuntimeIdentity(
				identityMap, sequenceMap, testLinuxRuntimeIdentity(), 4,
			)
			if !errors.Is(err, ErrLinuxRuntimeIdentityNamespaceNotFresh) {
				t.Fatalf("nonzero sequence error=%v", err)
			}
			if writes, _ := identityMap.counts(); writes != 0 {
				t.Fatalf("identity map write calls=%d want=0", writes)
			}
			if writes, _ := sequenceMap.counts(); writes != 0 {
				t.Fatalf("sequence map write calls=%d want=0", writes)
			}
		})
	}
}

func TestInternalLinuxRuntimeIdentityHookFailureIsStickyButFreshNewHookCanRetry(t *testing.T) {
	for _, test := range []struct {
		name             string
		failIdentityCall int
		failSequenceCall int
	}{
		{name: "disable", failIdentityCall: 1},
		{name: "sequence", failSequenceCall: 1},
		{name: "commit", failIdentityCall: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			identityMap, sequenceMap, _ := fakeRuntimeMaps(4)
			identityMap.setFailUpdate(test.failIdentityCall)
			sequenceMap.setFailUpdate(test.failSequenceCall)
			hook := newFakeRuntimeIdentityHook(
				t, identityMap, sequenceMap, testLinuxRuntimeIdentity(), 4,
			)
			firstErr := hook.PrepareUnreachableGeneration()
			if firstErr == nil {
				t.Fatal("injected seed failure was ignored")
			}
			identityCalls, _ := identityMap.counts()
			sequenceCalls, _ := sequenceMap.counts()
			if err := hook.PrepareUnreachableGeneration(); err == nil || err.Error() != firstErr.Error() {
				t.Fatalf("same hook retry error=%v want retained %v", err, firstErr)
			}
			if got, _ := identityMap.counts(); got != identityCalls {
				t.Fatalf("same hook retried identity writes: got=%d want=%d", got, identityCalls)
			}
			if got, _ := sequenceMap.counts(); got != sequenceCalls {
				t.Fatalf("same hook retried sequence writes: got=%d want=%d", got, sequenceCalls)
			}

			// At the internal seed layer every failed syscall above leaves the
			// never-published namespace fully zero. Only a newly issued hook may
			// make a fresh attempt; the exported Engine path is stricter and
			// consumes its Engine identity on the first attempt.
			identityMap.setFailUpdate(0)
			sequenceMap.setFailUpdate(0)
			freshHook := newFakeRuntimeIdentityHook(
				t, identityMap, sequenceMap, testLinuxRuntimeIdentity(), 4,
			)
			if err := freshHook.PrepareUnreachableGeneration(); err != nil {
				t.Fatalf("fresh hook could not retry all-zero namespace: %v", err)
			}
		})
	}
}

func TestSecondLinuxRuntimeIdentityHookCannotReseedSameMaps(t *testing.T) {
	identityMap, sequenceMap, trace := fakeRuntimeMaps(4)
	first := newFakeRuntimeIdentityHook(
		t, identityMap, sequenceMap, testLinuxRuntimeIdentity(), 4,
	)
	if err := first.PrepareUnreachableGeneration(); err != nil {
		t.Fatal(err)
	}
	identityCalls, _ := identityMap.counts()
	sequenceCalls, _ := sequenceMap.counts()
	second := newFakeRuntimeIdentityHook(
		t, identityMap, sequenceMap, testLinuxRuntimeIdentity(), 4,
	)
	if err := second.PrepareUnreachableGeneration(); !errors.Is(err, ErrLinuxRuntimeIdentityNamespaceNotFresh) {
		t.Fatalf("second hook error=%v", err)
	}
	if got, _ := identityMap.counts(); got != identityCalls {
		t.Fatalf("second hook wrote identity map: calls=%d want=%d", got, identityCalls)
	}
	if got, _ := sequenceMap.counts(); got != sequenceCalls {
		t.Fatalf("second hook wrote sequence map: calls=%d want=%d", got, sequenceCalls)
	}
	afterFailure := trace.snapshot()
	if err := second.PrepareUnreachableGeneration(); !errors.Is(err, ErrLinuxRuntimeIdentityNamespaceNotFresh) {
		t.Fatalf("repeated second hook error=%v", err)
	}
	if got := trace.snapshot(); !slices.Equal(got, afterFailure) {
		t.Fatalf("failed hook retried map access: before=%v after=%v", afterFailure, got)
	}
}

func TestConcurrentLinuxRuntimeIdentityHooksAllowExactlyOneSeed(t *testing.T) {
	identityMap, sequenceMap, _ := fakeRuntimeMaps(4)
	hooks := []*linuxRuntimeIdentityPreCommit{
		newFakeRuntimeIdentityHook(t, identityMap, sequenceMap, testLinuxRuntimeIdentity(), 4),
		newFakeRuntimeIdentityHook(t, identityMap, sequenceMap, testLinuxRuntimeIdentity(), 4),
	}
	start := make(chan struct{})
	results := make(chan error, len(hooks))
	var group sync.WaitGroup
	for _, hook := range hooks {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			results <- hook.PrepareUnreachableGeneration()
		}()
	}
	close(start)
	group.Wait()
	close(results)

	successes, rejected := 0, 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrLinuxRuntimeIdentityNamespaceNotFresh):
			rejected++
		default:
			t.Fatalf("unexpected concurrent seed error: %v", err)
		}
	}
	if successes != 1 || rejected != 1 {
		t.Fatalf("concurrent seeds: successes=%d rejected=%d", successes, rejected)
	}
	_, identityWrites := identityMap.counts()
	_, sequenceWrites := sequenceMap.counts()
	if identityWrites != 2 || sequenceWrites != 1 {
		t.Fatalf("successful writes: identity=%d sequence=%d want=2/1", identityWrites, sequenceWrites)
	}
}

type fakeLinuxFreshCollectionClaim struct {
	trace      *runtimeIdentityTestTrace
	callbacks  int
	held       atomic.Bool
	entries    atomic.Int32
	releases   atomic.Int32
	releaseErr error
}

type linuxFreshCollectionClaimFunc func(
	func(*ebpf.Map, *ebpf.Map, LinuxFreshCollectionRelease) error,
) error

func (function linuxFreshCollectionClaimFunc) WithExclusiveFreshFakeTCPCollection(
	callback func(*ebpf.Map, *ebpf.Map, LinuxFreshCollectionRelease) error,
) error {
	return function(callback)
}

func (claim *fakeLinuxFreshCollectionClaim) WithExclusiveFreshFakeTCPCollection(
	callback func(*ebpf.Map, *ebpf.Map, LinuxFreshCollectionRelease) error,
) error {
	claim.entries.Add(1)
	claim.held.Store(true)
	claim.trace.add("claim-fresh-collection")
	released := false
	release := func() error {
		if released {
			return errors.New("test fresh collection release called more than once")
		}
		released = true
		claim.releases.Add(1)
		claim.trace.add("release-fresh-collection")
		if claim.releaseErr != nil {
			return claim.releaseErr
		}
		claim.held.Store(false)
		return nil
	}
	for range claim.callbacks {
		if err := callback(nil, nil, release); err != nil {
			return err
		}
	}
	return nil
}

func successfulTestLinuxCommit(
	engine *Engine,
	claim LinuxFreshCollectionClaim,
	seedCalls *atomic.Int32,
	reachabilityCalls *atomic.Int32,
) error {
	return commitLinuxGenerationReachability(
		engine,
		claim,
		func(release LinuxFreshCollectionRelease) error {
			reachabilityCalls.Add(1)
			return release()
		},
		func() (int, error) { return 4, nil },
		func(*ebpf.Map, *ebpf.Map, RuntimeIdentity, int) error {
			seedCalls.Add(1)
			return nil
		},
	)
}

func TestCommitLinuxGenerationReachabilityKeepsFreshClaimAcrossCommit(t *testing.T) {
	engine, _ := testEngine(t, nil)
	trace := &runtimeIdentityTestTrace{}
	claim := &fakeLinuxFreshCollectionClaim{trace: trace, callbacks: 1}
	err := commitLinuxGenerationReachability(
		engine,
		claim,
		func(release LinuxFreshCollectionRelease) error {
			if !claim.held.Load() {
				t.Fatal("fresh collection claim was released before reachability commit")
			}
			trace.add("populate-prog-array")
			trace.add("publish-policy-reachability")
			trace.add("attach-xdp-tc")
			return release()
		},
		func() (int, error) { return 4, nil },
		func(*ebpf.Map, *ebpf.Map, RuntimeIdentity, int) error {
			if !claim.held.Load() {
				t.Fatal("fresh collection claim was not held during seed")
			}
			trace.add("seed-runtime-identity")
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"claim-fresh-collection",
		"seed-runtime-identity",
		"populate-prog-array",
		"publish-policy-reachability",
		"attach-xdp-tc",
		"release-fresh-collection",
	}
	if got := trace.snapshot(); !slices.Equal(got, want) {
		t.Fatalf("Linux generation commit trace=%v want=%v", got, want)
	}
}

func TestCommitLinuxGenerationReachabilityRejectsMissingClaimCallback(t *testing.T) {
	engine, _ := testEngine(t, nil)
	trace := &runtimeIdentityTestTrace{}
	claim := &fakeLinuxFreshCollectionClaim{trace: trace, callbacks: 0}
	err := commitLinuxGenerationReachability(
		engine,
		claim,
		func(LinuxFreshCollectionRelease) error {
			trace.add("reachable")
			return nil
		},
		func() (int, error) { return 4, nil },
		func(*ebpf.Map, *ebpf.Map, RuntimeIdentity, int) error {
			trace.add("seed")
			return nil
		},
	)
	if err == nil {
		t.Fatal("claim which did not expose its maps was accepted")
	}
	if got := trace.snapshot(); slices.Contains(got, "seed") || slices.Contains(got, "reachable") {
		t.Fatalf("missing claim callback caused side effects: %v", got)
	}
}

func TestCommitLinuxGenerationReachabilityPreservesCallbackErrorSwallowedByClaim(t *testing.T) {
	engine, _ := testEngine(t, nil)
	wantErr := errors.New("injected seed failure swallowed by claim")
	claim := linuxFreshCollectionClaimFunc(func(
		callback func(*ebpf.Map, *ebpf.Map, LinuxFreshCollectionRelease) error,
	) error {
		_ = callback(nil, nil, func() error { return nil })
		return nil
	})
	err := commitLinuxGenerationReachability(
		engine,
		claim,
		func(LinuxFreshCollectionRelease) error {
			t.Fatal("swallowed seed failure reached makeReachable")
			return nil
		},
		func() (int, error) { return 4, nil },
		func(*ebpf.Map, *ebpf.Map, RuntimeIdentity, int) error { return wantErr },
	)
	if !errors.Is(err, wantErr) {
		t.Fatalf("swallowed callback error = %v", err)
	}
}

func TestCommitLinuxGenerationReachabilityRejectsLateClaimCallbackWithoutSideEffects(t *testing.T) {
	engine, _ := testEngine(t, nil)
	allowCallback := make(chan struct{})
	callbackDone := make(chan error, 1)
	claim := linuxFreshCollectionClaimFunc(func(
		callback func(*ebpf.Map, *ebpf.Map, LinuxFreshCollectionRelease) error,
	) error {
		go func() {
			<-allowCallback
			callbackDone <- callback(nil, nil, func() error { return nil })
		}()
		return nil
	})
	var seedCalls, reachabilityCalls atomic.Int32
	err := commitLinuxGenerationReachability(
		engine,
		claim,
		func(LinuxFreshCollectionRelease) error {
			reachabilityCalls.Add(1)
			return nil
		},
		func() (int, error) { return 4, nil },
		func(*ebpf.Map, *ebpf.Map, RuntimeIdentity, int) error {
			seedCalls.Add(1)
			return nil
		},
	)
	if err == nil {
		t.Fatal("claim returning before its callback was accepted")
	}
	close(allowCallback)
	if lateErr := <-callbackDone; lateErr == nil ||
		!strings.Contains(lateErr.Error(), "after the claim returned") {
		t.Fatalf("late callback error = %v", lateErr)
	}
	if seedCalls.Load() != 0 || reachabilityCalls.Load() != 0 {
		t.Fatalf("late callback side effects seed=%d reachability=%d",
			seedCalls.Load(), reachabilityCalls.Load())
	}
}

func TestCommitLinuxGenerationReachabilityRejectsMissingReleaseAndSealsCapability(t *testing.T) {
	engine, _ := testEngine(t, nil)
	trace := &runtimeIdentityTestTrace{}
	claim := &fakeLinuxFreshCollectionClaim{trace: trace, callbacks: 1}
	var retained LinuxFreshCollectionRelease
	err := commitLinuxGenerationReachability(
		engine,
		claim,
		func(release LinuxFreshCollectionRelease) error {
			retained = release
			trace.add("reachable-callback-return")
			return nil
		},
		func() (int, error) { return 4, nil },
		func(*ebpf.Map, *ebpf.Map, RuntimeIdentity, int) error {
			trace.add("seed")
			return nil
		},
	)
	if !errors.Is(err, ErrLinuxFreshCollectionReleaseNotCalled) {
		t.Fatalf("missing release error = %v", err)
	}
	if retained == nil {
		t.Fatal("reachability callback did not receive release capability")
	}
	if lateErr := retained(); !errors.Is(lateErr, ErrLinuxFreshCollectionReleaseConsumed) {
		t.Fatalf("late release error = %v", lateErr)
	}
	if claim.releases.Load() != 0 || !claim.held.Load() {
		t.Fatalf("late release side effects=%d held=%t", claim.releases.Load(), claim.held.Load())
	}
}

func TestCommitLinuxGenerationReachabilityRejectsDoubleReleaseWithoutSecondSideEffect(t *testing.T) {
	engine, _ := testEngine(t, nil)
	claim := &fakeLinuxFreshCollectionClaim{
		trace: &runtimeIdentityTestTrace{}, callbacks: 1,
	}
	err := commitLinuxGenerationReachability(
		engine,
		claim,
		func(release LinuxFreshCollectionRelease) error {
			firstErr := release()
			secondErr := release()
			return errors.Join(firstErr, secondErr)
		},
		func() (int, error) { return 4, nil },
		func(*ebpf.Map, *ebpf.Map, RuntimeIdentity, int) error { return nil },
	)
	if !errors.Is(err, ErrLinuxFreshCollectionReleaseConsumed) ||
		!errors.Is(err, ErrLinuxFreshCollectionReleaseNotCalled) {
		t.Fatalf("double release error = %v", err)
	}
	if claim.releases.Load() != 1 {
		t.Fatalf("underlying release calls = %d", claim.releases.Load())
	}
}

func TestCommitLinuxGenerationReachabilityRejectsRetainedReleaseAfterSuccess(t *testing.T) {
	engine, _ := testEngine(t, nil)
	claim := &fakeLinuxFreshCollectionClaim{
		trace: &runtimeIdentityTestTrace{}, callbacks: 1,
	}
	var retained LinuxFreshCollectionRelease
	err := commitLinuxGenerationReachability(
		engine,
		claim,
		func(release LinuxFreshCollectionRelease) error {
			retained = release
			return release()
		},
		func() (int, error) { return 4, nil },
		func(*ebpf.Map, *ebpf.Map, RuntimeIdentity, int) error { return nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	if lateErr := retained(); !errors.Is(lateErr, ErrLinuxFreshCollectionReleaseConsumed) {
		t.Fatalf("retained release error = %v", lateErr)
	}
	if claim.releases.Load() != 1 {
		t.Fatalf("underlying release calls = %d", claim.releases.Load())
	}
}

func TestCommitLinuxGenerationReachabilityPreservesReleaseFailure(t *testing.T) {
	engine, _ := testEngine(t, nil)
	wantErr := errors.New("injected fresh collection release failure")
	claim := &fakeLinuxFreshCollectionClaim{
		trace: &runtimeIdentityTestTrace{}, callbacks: 1, releaseErr: wantErr,
	}
	err := commitLinuxGenerationReachability(
		engine,
		claim,
		func(release LinuxFreshCollectionRelease) error { return release() },
		func() (int, error) { return 4, nil },
		func(*ebpf.Map, *ebpf.Map, RuntimeIdentity, int) error { return nil },
	)
	if !errors.Is(err, wantErr) || claim.releases.Load() != 1 {
		t.Fatalf("release failure=%v calls=%d", err, claim.releases.Load())
	}
}

func TestCommitLinuxGenerationReachabilityRejectsPossibleCPUFailureBeforeClaim(t *testing.T) {
	for _, test := range []struct {
		name  string
		count int
		err   error
	}{
		{name: "source error", err: errors.New("possible CPU failure")},
		{name: "zero CPUs"},
	} {
		t.Run(test.name, func(t *testing.T) {
			engine, _ := testEngine(t, nil)
			claim := &fakeLinuxFreshCollectionClaim{
				trace: &runtimeIdentityTestTrace{}, callbacks: 1,
			}
			seedCalls := 0
			err := commitLinuxGenerationReachability(
				engine,
				claim,
				func(release LinuxFreshCollectionRelease) error { return release() },
				func() (int, error) { return test.count, test.err },
				func(*ebpf.Map, *ebpf.Map, RuntimeIdentity, int) error {
					seedCalls++
					return nil
				},
			)
			if err == nil || claim.entries.Load() != 0 || seedCalls != 0 {
				t.Fatalf("possible CPU error=%v claims=%d seeds=%d", err, claim.entries.Load(), seedCalls)
			}
		})
	}
}

func TestCommitLinuxGenerationReachabilityRejectsNilAndZeroEngineBeforeClaim(t *testing.T) {
	for _, engine := range []*Engine{nil, &Engine{}} {
		trace := &runtimeIdentityTestTrace{}
		claim := &fakeLinuxFreshCollectionClaim{trace: trace, callbacks: 1}
		err := commitLinuxGenerationReachability(
			engine,
			claim,
			func(LinuxFreshCollectionRelease) error {
				trace.add("reachable")
				return nil
			},
			func() (int, error) { return 4, nil },
			func(*ebpf.Map, *ebpf.Map, RuntimeIdentity, int) error {
				trace.add("seed")
				return nil
			},
		)
		if err == nil {
			t.Fatal("nil or zero Engine was accepted")
		}
		if claim.entries.Load() != 0 || len(trace.snapshot()) != 0 {
			t.Fatalf("nil or zero Engine entered collection claim: %v", trace.snapshot())
		}
	}
}

func TestEngineValueCopyCannotCommitSecondFreshLinuxCollection(t *testing.T) {
	engine, _ := testEngine(t, nil)
	engineCopy := copyEngineValue(t, engine)
	firstTrace := &runtimeIdentityTestTrace{}
	firstClaim := &fakeLinuxFreshCollectionClaim{trace: firstTrace, callbacks: 1}
	var seedCalls atomic.Int32
	var reachabilityCalls atomic.Int32
	if err := successfulTestLinuxCommit(
		engine, firstClaim, &seedCalls, &reachabilityCalls,
	); err != nil {
		t.Fatal(err)
	}

	secondTrace := &runtimeIdentityTestTrace{}
	secondClaim := &fakeLinuxFreshCollectionClaim{trace: secondTrace, callbacks: 1}
	if err := successfulTestLinuxCommit(
		engineCopy, secondClaim, &seedCalls, &reachabilityCalls,
	); !errors.Is(err, ErrLinuxRuntimeIdentityCommitConsumed) {
		t.Fatalf("second fresh collection commit error=%v", err)
	}
	if secondClaim.entries.Load() != 0 || len(secondTrace.snapshot()) != 0 {
		t.Fatalf("consumed Engine entered second fresh collection claim: %v", secondTrace.snapshot())
	}
	if seedCalls.Load() != 1 || reachabilityCalls.Load() != 1 {
		t.Fatalf(
			"same Engine side effects: seed=%d reachability=%d want=1/1",
			seedCalls.Load(), reachabilityCalls.Load(),
		)
	}
}

func TestConcurrentLinuxCollectionCommitsConsumeEngineExactlyOnce(t *testing.T) {
	engine, _ := testEngine(t, nil)
	engines := []*Engine{copyEngineValue(t, engine), copyEngineValue(t, engine)}
	claims := []*fakeLinuxFreshCollectionClaim{
		{trace: &runtimeIdentityTestTrace{}, callbacks: 1},
		{trace: &runtimeIdentityTestTrace{}, callbacks: 1},
	}
	var seedCalls atomic.Int32
	var reachabilityCalls atomic.Int32
	start := make(chan struct{})
	results := make(chan error, len(claims))
	var group sync.WaitGroup
	for index, claim := range claims {
		candidate := engines[index]
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			results <- successfulTestLinuxCommit(
				candidate, claim, &seedCalls, &reachabilityCalls,
			)
		}()
	}
	close(start)
	group.Wait()
	close(results)

	successes, consumed := 0, 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrLinuxRuntimeIdentityCommitConsumed):
			consumed++
		default:
			t.Fatalf("unexpected concurrent collection commit error: %v", err)
		}
	}
	if successes != 1 || consumed != 1 {
		t.Fatalf("concurrent collection commits: success=%d consumed=%d", successes, consumed)
	}
	claimEntries := claims[0].entries.Load() + claims[1].entries.Load()
	if claimEntries != 1 || seedCalls.Load() != 1 || reachabilityCalls.Load() != 1 {
		t.Fatalf(
			"concurrent commit side effects: claims=%d seed=%d reachability=%d",
			claimEntries, seedCalls.Load(), reachabilityCalls.Load(),
		)
	}
}

func TestFailedLinuxCollectionCommitConsumesEngineAndRequiresNewEngine(t *testing.T) {
	engine, _ := testEngine(t, nil)
	firstFailure := errors.New("injected first collection seed failure")
	firstClaim := &fakeLinuxFreshCollectionClaim{
		trace: &runtimeIdentityTestTrace{}, callbacks: 1,
	}
	err := commitLinuxGenerationReachability(
		engine,
		firstClaim,
		func(LinuxFreshCollectionRelease) error { return nil },
		func() (int, error) { return 4, nil },
		func(*ebpf.Map, *ebpf.Map, RuntimeIdentity, int) error { return firstFailure },
	)
	if !errors.Is(err, firstFailure) {
		t.Fatalf("first collection commit error=%v want=%v", err, firstFailure)
	}

	secondClaim := &fakeLinuxFreshCollectionClaim{
		trace: &runtimeIdentityTestTrace{}, callbacks: 1,
	}
	var seedCalls atomic.Int32
	var reachabilityCalls atomic.Int32
	err = successfulTestLinuxCommit(engine, secondClaim, &seedCalls, &reachabilityCalls)
	if !errors.Is(err, ErrLinuxRuntimeIdentityCommitConsumed) || !errors.Is(err, firstFailure) {
		t.Fatalf("failed Engine retry error=%v", err)
	}
	if secondClaim.entries.Load() != 0 || seedCalls.Load() != 0 || reachabilityCalls.Load() != 0 {
		t.Fatalf(
			"failed Engine retry touched fresh collection: claims=%d seed=%d reachability=%d",
			secondClaim.entries.Load(), seedCalls.Load(), reachabilityCalls.Load(),
		)
	}

	freshEngine, err := New(engine.opts)
	if err != nil {
		t.Fatal(err)
	}
	if freshEngine.Identity() == engine.Identity() {
		t.Fatal("fresh Engine reused consumed runtime identity")
	}
	freshClaim := &fakeLinuxFreshCollectionClaim{
		trace: &runtimeIdentityTestTrace{}, callbacks: 1,
	}
	if err := successfulTestLinuxCommit(
		freshEngine, freshClaim, &seedCalls, &reachabilityCalls,
	); err != nil {
		t.Fatalf("new Engine and fresh collection could not commit: %v", err)
	}
	if freshClaim.entries.Load() != 1 || seedCalls.Load() != 1 || reachabilityCalls.Load() != 1 {
		t.Fatalf(
			"fresh Engine side effects: claims=%d seed=%d reachability=%d",
			freshClaim.entries.Load(), seedCalls.Load(), reachabilityCalls.Load(),
		)
	}
}
