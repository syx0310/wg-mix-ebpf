package faketcp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

type fakeClock struct {
	now       time.Time
	monotonic uint64
	clockErr  error
	domain    string
}

func (c *fakeClock) Now() time.Time { return c.now }
func (c *fakeClock) Domain() string {
	if c.domain != "" {
		return c.domain
	}
	return BPFMonotonicClockDomain
}
func (c *fakeClock) NowNanos() (uint64, error) { return c.monotonic, c.clockErr }
func (c *fakeClock) Add(d time.Duration) {
	c.now = c.now.Add(d)
	c.monotonic += uint64(d)
}

func testFlow(port uint16) abi.FakeTCPSessionKey {
	local, err := RawIPv4BE32(netip.MustParseAddr("10.0.0.1"))
	if err != nil {
		panic(err)
	}
	remote, err := RawIPv4BE32(netip.MustParseAddr("10.0.0.2"))
	if err != nil {
		panic(err)
	}
	return abi.FakeTCPSessionKey{
		Generation: 1, LocalIPv4: local, RemoteIPv4: remote,
		UnderlayIndex: 2, LocalPort: port, RemotePort: 443,
	}
}

type fakeSessionStore struct {
	values         map[abi.FakeTCPSessionKey]abi.FakeTCPSessionValue
	insertErr      error
	lookupErr      error
	deleteErr      error
	inserts        int
	lookups        int
	deleteAttempts int
	beforeDelete   func(abi.FakeTCPSessionKey)
}

// modelClaimSessionStore embeds the production LinuxSessionStore. Only its
// kernel compare-claim primitive is modeled, so these tests exercise the real
// Engine/store integration rather than calling a deleter in isolation.
type modelClaimSessionStore struct {
	*LinuxSessionStore
	backend *memorySessionMap
	deleter *modelClaimCompareDeleter
}

type modelClaimCompareDeleter struct {
	backend        *memorySessionMap
	deleteFailures []modelClaimDeleteFailure
	deleteAttempts int
}

type modelClaimDeleteFailure struct {
	err               error
	deleteBeforeError bool
}

func newModelClaimSessionStore(
	t *testing.T,
	failures ...modelClaimDeleteFailure,
) *modelClaimSessionStore {
	t.Helper()
	backend := newMemorySessionMap()
	deleter := &modelClaimCompareDeleter{
		backend:        backend,
		deleteFailures: append([]modelClaimDeleteFailure(nil), failures...),
	}
	store, err := newLinuxSessionStoreWithAtomicCompareDelete(
		backend, 1, backend.identity, deleter,
	)
	if err != nil {
		t.Fatal(err)
	}
	return &modelClaimSessionStore{
		LinuxSessionStore: store,
		backend:           backend,
		deleter:           deleter,
	}
}

func (deleter *modelClaimCompareDeleter) CompareDeleteEstablished(
	identity SessionMapIdentity,
	key abi.FakeTCPSessionKey,
	expected abi.FakeTCPSessionValue,
) (SessionDeleteResult, error) {
	deleter.backend.mu.Lock()
	defer deleter.backend.mu.Unlock()
	deleter.deleteAttempts++
	if identity != deleter.backend.identity {
		return SessionDeleteDifferent, ErrSessionMapIdentityChanged
	}
	actual, found := deleter.backend.values[key]
	if !found {
		return SessionDeleteAbsent, nil
	}
	comparable := actual
	if comparable.State == abi.FakeTCPStateDeleteClaimed {
		comparable.State = abi.FakeTCPStateEstablished
	}
	if comparable != expected ||
		(actual.State != abi.FakeTCPStateEstablished && actual.State != abi.FakeTCPStateDeleteClaimed) {
		return SessionDeleteDifferent, nil
	}
	actual.State = abi.FakeTCPStateDeleteClaimed
	deleter.backend.values[key] = actual
	if len(deleter.deleteFailures) != 0 {
		failure := deleter.deleteFailures[0]
		deleter.deleteFailures = deleter.deleteFailures[1:]
		if failure.deleteBeforeError {
			delete(deleter.backend.values, key)
		}
		return SessionDeleteDifferent, failure.err
	}
	delete(deleter.backend.values, key)
	return SessionDeleteRemoved, nil
}

func (s *modelClaimSessionStore) value(
	key abi.FakeTCPSessionKey,
) (abi.FakeTCPSessionValue, bool) {
	return s.backend.value(key)
}

func (s *modelClaimSessionStore) put(
	key abi.FakeTCPSessionKey,
	value abi.FakeTCPSessionValue,
) {
	s.backend.putFromBPF(key, value)
}

func (s *modelClaimSessionStore) counts() (int, int) {
	s.backend.mu.Lock()
	defer s.backend.mu.Unlock()
	return s.backend.lookupCalls, s.deleter.deleteAttempts
}

func newFakeSessionStore() *fakeSessionStore {
	return &fakeSessionStore{values: make(map[abi.FakeTCPSessionKey]abi.FakeTCPSessionValue)}
}

func (s *fakeSessionStore) InsertEstablished(key abi.FakeTCPSessionKey, value abi.FakeTCPSessionValue) error {
	s.inserts++
	if s.insertErr != nil {
		return s.insertErr
	}
	if value.State != abi.FakeTCPStateEstablished {
		return errors.New("test store rejected non-established session")
	}
	if _, exists := s.values[key]; exists {
		return errors.New("test store rejected whole-value overwrite")
	}
	s.values[key] = value
	return nil
}

func (s *fakeSessionStore) LookupEstablished(key abi.FakeTCPSessionKey) (abi.FakeTCPSessionValue, bool, error) {
	s.lookups++
	if s.lookupErr != nil {
		return abi.FakeTCPSessionValue{}, false, s.lookupErr
	}
	value, found := s.values[key]
	return value, found, nil
}

func (s *fakeSessionStore) DeleteEstablishedIfUnchanged(key abi.FakeTCPSessionKey, expected abi.FakeTCPSessionValue) (SessionDeleteResult, error) {
	s.deleteAttempts++
	if s.deleteErr != nil {
		return SessionDeleteDifferent, s.deleteErr
	}
	if s.beforeDelete != nil {
		s.beforeDelete(key)
	}
	value, found := s.values[key]
	if !found {
		return SessionDeleteAbsent, nil
	}
	if value != expected {
		return SessionDeleteDifferent, nil
	}
	delete(s.values, key)
	return SessionDeleteRemoved, nil
}

func testEngine(t *testing.T, mutate func(*Options)) (*Engine, *fakeClock) {
	t.Helper()
	clock := &fakeClock{now: time.Unix(100, 0), monotonic: uint64(100 * time.Second)}
	nextISN := uint32(1000)
	opts := Options{
		Generation: 1, SessionCapacity: 8,
		MaxHalfOpenSessions: 4, MaxHalfOpenPerSource: 2,
		SYNRateInterval: time.Second, SYNBurst: 4, SYNBurstPerSource: 2,
		SYNSourceLedgerCapacity: 8, SYNSourceLedgerTTL: 10 * time.Second,
		MaxPendingFlows:          4,
		MaxPendingPacketsPerFlow: 2, MaxPendingBytes: 64,
		HandshakeTimeout: time.Second, HandshakeRetries: 2,
		KeepaliveInterval: 5 * time.Second, IdleTimeout: 20 * time.Second,
		Now:             clock.Now,
		MonotonicClock:  clock,
		Store:           newFakeSessionStore(),
		InitialSequence: func() uint32 { value := nextISN; nextISN += 1000; return value },
	}
	if mutate != nil {
		mutate(&opts)
	}
	engine, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	engine.identity = testRuntimeIdentity(opts.Generation)
	// Ordinary state-machine tests start after one full global refill horizon.
	// Dedicated restart tests below exercise New's zero-budget fail-safe edge.
	clock.Add(opts.SYNRateInterval * time.Duration(opts.SYNBurst))
	return engine, clock
}

func establishedModelClaimTestEngine(
	t *testing.T,
	store *modelClaimSessionStore,
) (*Engine, *fakeClock, abi.FakeTCPSessionKey, abi.FakeTCPSessionValue) {
	t.Helper()
	engine, clock := testEngine(t, func(options *Options) { options.Store = store })
	flow := testFlow(31001)
	if _, err := engine.Outbound(flow, []byte{1}); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Inbound(flow, Segment{
		Flags: FlagSYN | FlagACK, Sequence: 9000, Acknowledgement: 1001,
	}); err != nil {
		t.Fatal(err)
	}
	expected, found := store.value(flow)
	if !found {
		t.Fatal("model claim store did not receive established session")
	}
	return engine, clock, flow, expected
}

func TestEnginePendingDeleteRecoveryPrecedesEstablishedLookup(t *testing.T) {
	t.Run("claim then delete failure retries on Tick", func(t *testing.T) {
		failure := errors.New("exact delete failed after claim")
		store := newModelClaimSessionStore(t, modelClaimDeleteFailure{err: failure})
		engine, clock, flow, expected := establishedModelClaimTestEngine(t, store)
		clock.Add(engine.opts.IdleTimeout)

		actions, err := engine.Tick()
		if !errors.Is(err, failure) || len(actions) != 1 || actions[0].Reason != "session-store-unavailable" {
			t.Fatalf("first Tick actions=%#v err=%v", actions, err)
		}
		claimed, _ := store.value(flow)
		if claimed.State != abi.FakeTCPStateDeleteClaimed ||
			engine.sessions[flow].pendingDelete == nil ||
			engine.sessions[flow].pendingDelete.expected != expected {
			t.Fatalf("claim recovery state=%#v pending=%#v", claimed, engine.sessions[flow].pendingDelete)
		}
		lookupsAfterClaim, _ := store.counts()

		actions, err = engine.Tick()
		if err != nil || len(actions) != 1 || actions[0].Kind != ActionClose || actions[0].Reason != "idle-timeout" {
			t.Fatalf("retry Tick actions=%#v err=%v", actions, err)
		}
		lookups, _ := store.counts()
		if lookups != lookupsAfterClaim || engine.sessions[flow] != nil {
			t.Fatalf("retry performed ordinary lookup=%d/%d or kept slow state", lookups, lookupsAfterClaim)
		}
	})

	t.Run("outbound resolves absent after uncertain delete", func(t *testing.T) {
		failure := errors.New("delete completed but completion was uncertain")
		store := newModelClaimSessionStore(t, modelClaimDeleteFailure{
			err: failure, deleteBeforeError: true,
		})
		engine, clock, flow, expected := establishedModelClaimTestEngine(t, store)
		clock.Add(engine.opts.IdleTimeout)

		if actions, err := engine.Tick(); !errors.Is(err, failure) || len(actions) != 1 || actions[0].Reason != "session-store-unavailable" {
			t.Fatalf("uncertain Tick actions=%#v err=%v", actions, err)
		}
		if _, found := store.value(flow); found || engine.sessions[flow].pendingDelete.expected != expected {
			t.Fatalf("uncertain delete found=%t pending=%#v", found, engine.sessions[flow].pendingDelete)
		}
		lookupsAfterDelete, _ := store.counts()
		actions, err := engine.Outbound(flow, []byte{9})
		if err != nil || len(actions) != 1 || actions[0].Kind != ActionClose || actions[0].Reason != "idle-timeout" {
			t.Fatalf("absent outbound retry actions=%#v err=%v", actions, err)
		}
		lookups, _ := store.counts()
		if lookups != lookupsAfterDelete || engine.sessions[flow] != nil {
			t.Fatalf("absent retry performed lookup=%d/%d or kept slow state", lookups, lookupsAfterDelete)
		}
	})

	t.Run("persistent failure retains one immutable request", func(t *testing.T) {
		failure := errors.New("persistent exact delete failure")
		store := newModelClaimSessionStore(t,
			modelClaimDeleteFailure{err: failure},
			modelClaimDeleteFailure{err: failure},
			modelClaimDeleteFailure{err: failure},
		)
		engine, clock, flow, expected := establishedModelClaimTestEngine(t, store)
		clock.Add(engine.opts.IdleTimeout)

		for attempt := 0; attempt < 3; attempt++ {
			var actions []Action
			var err error
			if attempt == 1 {
				actions, err = engine.Outbound(flow, []byte{9})
			} else {
				actions, err = engine.Tick()
			}
			if !errors.Is(err, failure) || len(actions) != 1 || actions[0].Reason != "session-store-unavailable" {
				t.Fatalf("attempt %d actions=%#v err=%v", attempt, actions, err)
			}
			pending := engine.sessions[flow].pendingDelete
			if pending == nil || pending.expected != expected || pending.reason != "idle-timeout" {
				t.Fatalf("attempt %d pending=%#v", attempt, pending)
			}
			if got, _ := store.value(flow); got.State != abi.FakeTCPStateDeleteClaimed {
				t.Fatalf("attempt %d lost tombstone: %#v", attempt, got)
			}
		}
		lookups, deletes := store.counts()
		if lookups != 1 || deletes != 3 {
			t.Fatalf("persistent failure lookups=%d deletes=%d", lookups, deletes)
		}
	})

	t.Run("different ABA value is preserved and authority is dropped", func(t *testing.T) {
		failure := errors.New("claim completed before delete failure")
		store := newModelClaimSessionStore(t, modelClaimDeleteFailure{err: failure})
		engine, clock, flow, expected := establishedModelClaimTestEngine(t, store)
		clock.Add(engine.opts.IdleTimeout)
		if _, err := engine.Tick(); !errors.Is(err, failure) {
			t.Fatalf("initial claim error=%v", err)
		}

		replacement := expected
		replacement.SessionID++
		replacement.Revision++
		store.put(flow, replacement)
		lookupsAfterClaim, _ := store.counts()
		actions, err := engine.Outbound(flow, []byte{9})
		if err != nil || len(actions) != 1 || actions[0].Reason != "fast-session-raced" {
			t.Fatalf("different outbound retry actions=%#v err=%v", actions, err)
		}
		actual, _ := store.value(flow)
		lookups, _ := store.counts()
		if actual != replacement || engine.sessions[flow] == nil ||
			engine.sessions[flow].pendingDelete != nil || lookups != lookupsAfterClaim {
			t.Fatalf("different retry value=%#v session=%#v lookups=%d/%d",
				actual, engine.sessions[flow], lookups, lookupsAfterClaim)
		}
	})

	t.Run("same-flow Inbound retries peer close before lookup", func(t *testing.T) {
		failure := errors.New("peer-close delete failed after claim")
		store := newModelClaimSessionStore(t, modelClaimDeleteFailure{err: failure})
		engine, _, flow, expected := establishedModelClaimTestEngine(t, store)
		packet := buildIPv4TCPControl(flow, expected, FlagRST|FlagACK, 0)
		validated, err := ValidateIPv4TCPControl(packet, flow, expected)
		if err != nil {
			t.Fatal(err)
		}

		actions, err := engine.InboundValidatedControl(validated, 0)
		if !errors.Is(err, failure) || len(actions) != 1 || actions[0].Reason != "session-store-unavailable" {
			t.Fatalf("first Inbound actions=%#v err=%v", actions, err)
		}
		lookupsAfterClaim, _ := store.counts()
		actions, err = engine.Inbound(flow, Segment{Flags: FlagACK})
		if err != nil || len(actions) != 1 || actions[0].Kind != ActionClose || actions[0].Reason != "peer-close" {
			t.Fatalf("retry Inbound actions=%#v err=%v", actions, err)
		}
		lookups, _ := store.counts()
		if lookups != lookupsAfterClaim || engine.sessions[flow] != nil {
			t.Fatalf("Inbound retry performed lookup=%d/%d or kept slow state", lookups, lookupsAfterClaim)
		}
	})
}

func TestNewAndRepeatedRestartNeverGrantImmediateSYNBurst(t *testing.T) {
	seed, clock := testEngine(t, nil)
	options := seed.opts
	for restart := 0; restart < 3; restart++ {
		engine, err := New(options)
		if err != nil {
			t.Fatal(err)
		}
		flow := testFlow(uint16(31000 + restart))
		actions, err := engine.Inbound(flow, Segment{Flags: FlagSYN, Sequence: uint32(restart + 1)})
		if err != nil || len(actions) != 1 || actions[0].Reason != "syn-rate-global" {
			t.Fatalf("restart %d minted admission budget: actions=%#v err=%v", restart, actions, err)
		}
		if len(engine.synSources) != 0 || engine.synSourceLRU.Len() != 0 {
			t.Fatalf("restart %d populated source ledger while globally empty", restart)
		}
	}

	engine, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	clock.Add(options.SYNRateInterval)
	flow := testFlow(32000)
	if actions, err := engine.Inbound(flow, Segment{Flags: FlagSYN, Sequence: 10}); err != nil || actions[0].Reason != "accept-syn" {
		t.Fatalf("same engine did not accrue one interval: actions=%#v err=%v", actions, err)
	}
	restarted, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	flow = testFlow(32001)
	if actions, err := restarted.Inbound(flow, Segment{Flags: FlagSYN, Sequence: 11}); err != nil || actions[0].Reason != "syn-rate-global" {
		t.Fatalf("restart restored consumed/full burst: actions=%#v err=%v", actions, err)
	}
}

func TestMonotonicClockContractRejectsDomainMismatchAndFallback(t *testing.T) {
	engine, _ := testEngine(t, nil)
	options := engine.opts
	options.MonotonicClock = &fakeClock{domain: "CLOCK_BOOTTIME"}
	if _, err := New(options); err == nil || !strings.Contains(err.Error(), "does not match BPF domain") {
		t.Fatalf("domain mismatch error=%v", err)
	}

	store := newFakeSessionStore()
	engine, clock := testEngine(t, func(options *Options) { options.Store = store })
	flow := testFlow(31001)
	if _, err := engine.Outbound(flow, []byte{1}); err != nil {
		t.Fatal(err)
	}
	clock.clockErr = errors.New("clock unavailable")
	actions, err := engine.Inbound(flow, Segment{Flags: FlagSYN | FlagACK, Sequence: 9000, Acknowledgement: 1001})
	if err == nil || !strings.Contains(err.Error(), "clock unavailable") || len(actions) != 1 || actions[0].Reason != "session-store-unavailable" {
		t.Fatalf("clock insert failure actions=%#v err=%v", actions, err)
	}
	if len(store.values) != 0 {
		t.Fatal("clock failure fell back and inserted an incomparable timestamp")
	}
}

func TestMonotonicClockFailureAndUintBoundariesNeverFalseDelete(t *testing.T) {
	store := newFakeSessionStore()
	engine, clock := testEngine(t, func(options *Options) { options.Store = store })
	flow := testFlow(31001)
	if _, err := engine.Outbound(flow, []byte{1}); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Inbound(flow, Segment{Flags: FlagSYN | FlagACK, Sequence: 9000, Acknowledgement: 1001}); err != nil {
		t.Fatal(err)
	}

	clock.clockErr = errors.New("clock unavailable")
	if actions, err := engine.Tick(); err == nil || len(actions) != 0 || store.deleteAttempts != 0 {
		t.Fatalf("clock failure actions=%#v err=%v deleteAttempts=%d", actions, err, store.deleteAttempts)
	}
	clock.clockErr = nil
	value := store.values[flow]
	value.LastSeenNanos = math.MaxUint64 - 10
	store.values[flow] = value
	clock.monotonic = 5
	if actions, err := engine.Tick(); err != nil || len(actions) != 0 || store.deleteAttempts != 0 {
		t.Fatalf("future timestamp underflow actions=%#v err=%v deleteAttempts=%d", actions, err, store.deleteAttempts)
	}

	value.LastSeenNanos = math.MaxUint64 - uint64(engine.opts.IdleTimeout)
	store.values[flow] = value
	clock.monotonic = math.MaxUint64
	actions, err := engine.Tick()
	if err != nil || len(actions) != 1 || actions[0].Reason != "idle-timeout" || store.deleteAttempts != 1 {
		t.Fatalf("max-uint idle actions=%#v err=%v deleteAttempts=%d", actions, err, store.deleteAttempts)
	}
}

func TestMonotonicTimespecConversionBounds(t *testing.T) {
	maxSeconds := int64(math.MaxUint64 / 1_000_000_000)
	maxNanoseconds := int64(math.MaxUint64 - uint64(maxSeconds)*1_000_000_000)
	if got, err := monotonicNanosFromParts(maxSeconds, maxNanoseconds); err != nil || got != math.MaxUint64 {
		t.Fatalf("boundary conversion=%d err=%v want=%d", got, err, uint64(math.MaxUint64))
	}
	for _, parts := range [][2]int64{{-1, 0}, {0, -1}, {0, 1_000_000_000}, {maxSeconds, maxNanoseconds + 1}, {maxSeconds + 1, 0}} {
		if _, err := monotonicNanosFromParts(parts[0], parts[1]); err == nil {
			t.Fatalf("invalid timespec (%d,%d) accepted", parts[0], parts[1])
		}
	}
}

func TestClientHandshakeReleasesBoundedFirstPacket(t *testing.T) {
	engine, _ := testEngine(t, nil)
	flow := testFlow(31001)
	packet := []byte{1, 2, 3, 4}
	actions, err := engine.Outbound(flow, packet)
	if err != nil || len(actions) != 1 || actions[0].Control.Flags != FlagSYN {
		t.Fatalf("outbound actions=%#v err=%v", actions, err)
	}
	packet[0] = 9
	actions, err = engine.Inbound(flow, Segment{Flags: FlagSYN | FlagACK, Sequence: 9000, Acknowledgement: 1001})
	if err != nil || len(actions) != 2 || actions[0].Control.Flags != FlagACK ||
		actions[1].Kind != ActionReleasePending || actions[1].Packets[0].Data[0] != 1 {
		t.Fatalf("handshake actions=%#v err=%v", actions, err)
	}
	state, ok, _ := engine.Snapshot(flow)
	if !ok || state.State != abi.FakeTCPStateEstablished || state.PendingPackets != 0 {
		t.Fatalf("state=%#v ok=%t", state, ok)
	}
}

func TestServerDuplicateSYNAndACKTransitions(t *testing.T) {
	engine, _ := testEngine(t, nil)
	flow := testFlow(31001)
	actions, err := engine.Inbound(flow, Segment{Flags: FlagSYN, Sequence: 7000})
	if err != nil || len(actions) != 1 || actions[0].Control.Flags != FlagSYN|FlagACK {
		t.Fatalf("syn actions=%#v err=%v", actions, err)
	}
	actions, err = engine.Inbound(flow, Segment{Flags: FlagSYN, Sequence: 7000})
	if err != nil || len(actions) != 1 || actions[0].Reason != "duplicate-syn" {
		t.Fatalf("duplicate actions=%#v err=%v", actions, err)
	}
	actions, err = engine.Inbound(flow, Segment{Flags: FlagACK, Acknowledgement: 1001})
	if err != nil || len(actions) != 0 {
		t.Fatalf("ack actions=%#v err=%v", actions, err)
	}
	state, _, _ := engine.Snapshot(flow)
	if state.State != abi.FakeTCPStateEstablished {
		t.Fatalf("state=%d", state.State)
	}
	// A duplicate ACK after establishment is harmless and remains forwardable.
	actions, err = engine.Inbound(flow, Segment{Flags: FlagACK, Acknowledgement: 1001})
	if err != nil || len(actions) != 1 || actions[0].Kind != ActionForward {
		t.Fatalf("duplicate ack actions=%#v err=%v", actions, err)
	}
}

func TestDuplicateSYNConsumesSourceAndGlobalTokens(t *testing.T) {
	engine, _ := testEngine(t, func(o *Options) {
		o.SYNBurst = 4
		o.SYNBurstPerSource = 2
	})
	flow := testFlow(31001)
	for attempt := 1; attempt <= 2; attempt++ {
		actions, err := engine.Inbound(flow, Segment{Flags: FlagSYN, Sequence: 7000})
		if err != nil || len(actions) != 1 || (actions[0].Reason != "accept-syn" && actions[0].Reason != "duplicate-syn") {
			t.Fatalf("attempt %d actions=%#v err=%v", attempt, actions, err)
		}
	}
	actions, err := engine.Inbound(flow, Segment{Flags: FlagSYN, Sequence: 7000})
	if err != nil || len(actions) != 1 || actions[0].Reason != "syn-rate-source" {
		t.Fatalf("third duplicate actions=%#v err=%v", actions, err)
	}
}

func TestSYNResetLoopCannotResetSourceTokenHistory(t *testing.T) {
	engine, _ := testEngine(t, func(o *Options) {
		o.SYNBurst = 4
		o.SYNBurstPerSource = 1
	})
	first := testFlow(31001)
	if actions, err := engine.Inbound(first, Segment{Flags: FlagSYN, Sequence: 100}); err != nil || actions[0].Reason != "accept-syn" {
		t.Fatalf("first SYN actions=%#v err=%v", actions, err)
	}
	if actions, err := engine.Inbound(first, Segment{Flags: FlagRST}); err != nil || actions[0].Kind != ActionClose {
		t.Fatalf("RST actions=%#v err=%v", actions, err)
	}
	second := testFlow(31002)
	actions, err := engine.Inbound(second, Segment{Flags: FlagSYN, Sequence: 200})
	if err != nil || len(actions) != 1 || actions[0].Reason != "syn-rate-source" {
		t.Fatalf("post-RST SYN reset source history: actions=%#v err=%v", actions, err)
	}
}

func TestSuccessfulAndRejectedSYNsDoNotRefundSourceTokens(t *testing.T) {
	t.Run("successful-handshake", func(t *testing.T) {
		engine, _ := testEngine(t, func(o *Options) {
			o.SYNBurst = 4
			o.SYNBurstPerSource = 1
		})
		first := testFlow(31001)
		if _, err := engine.Inbound(first, Segment{Flags: FlagSYN, Sequence: 100}); err != nil {
			t.Fatal(err)
		}
		if _, err := engine.Inbound(first, Segment{Flags: FlagACK, Acknowledgement: 1001}); err != nil {
			t.Fatal(err)
		}
		second := testFlow(31002)
		if actions, err := engine.Inbound(second, Segment{Flags: FlagSYN, Sequence: 200}); err != nil || actions[0].Reason != "syn-rate-source" {
			t.Fatalf("successful handshake refunded token: actions=%#v err=%v", actions, err)
		}
	})

	t.Run("half-open-rejection", func(t *testing.T) {
		engine, _ := testEngine(t, func(o *Options) {
			o.MaxHalfOpenSessions = 1
			o.MaxHalfOpenPerSource = 1
			o.SYNBurst = 8
			o.SYNBurstPerSource = 1
		})
		blocking := testFlow(31001)
		blocking.RemoteIPv4++
		if _, err := engine.Inbound(blocking, Segment{Flags: FlagSYN, Sequence: 100}); err != nil {
			t.Fatal(err)
		}
		rejected := testFlow(31002)
		if actions, err := engine.Inbound(rejected, Segment{Flags: FlagSYN, Sequence: 200}); err != nil || actions[0].Reason != "half-open-capacity" {
			t.Fatalf("capacity rejection actions=%#v err=%v", actions, err)
		}
		if _, err := engine.Inbound(blocking, Segment{Flags: FlagRST}); err != nil {
			t.Fatal(err)
		}
		retry := testFlow(31003)
		if actions, err := engine.Inbound(retry, Segment{Flags: FlagSYN, Sequence: 201}); err != nil || actions[0].Reason != "syn-rate-source" {
			t.Fatalf("rejected SYN refunded token: actions=%#v err=%v", actions, err)
		}
	})
}

func TestBoundedSYNSourceLedgerPreservesKnownLegitimateSource(t *testing.T) {
	engine, clock := testEngine(t, func(o *Options) {
		o.SYNBurst = 16
		o.SYNBurstPerSource = 1
		o.SYNSourceLedgerCapacity = 4
		o.SYNSourceLedgerTTL = 10 * time.Second
	})
	legitimate := testFlow(31001)
	if _, err := engine.Inbound(legitimate, Segment{Flags: FlagSYN, Sequence: 100}); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Inbound(legitimate, Segment{Flags: FlagRST}); err != nil {
		t.Fatal(err)
	}
	for source := uint32(1); source <= 3; source++ {
		flow := testFlow(uint16(32000 + source))
		flow.RemoteIPv4 += source
		if actions, err := engine.Inbound(flow, Segment{Flags: FlagSYN, Sequence: source}); err != nil || actions[0].Reason != "accept-syn" {
			t.Fatalf("flood source %d actions=%#v err=%v", source, actions, err)
		}
	}
	overflow := testFlow(33000)
	overflow.RemoteIPv4 += 100
	if actions, err := engine.Inbound(overflow, Segment{Flags: FlagSYN, Sequence: 1}); err != nil || actions[0].Reason != "syn-source-ledger-capacity" {
		t.Fatalf("overflow actions=%#v err=%v", actions, err)
	}
	if len(engine.synSources) != 4 {
		t.Fatalf("ledger size=%d, want hard bound 4", len(engine.synSources))
	}
	clock.Add(time.Second)
	if actions, err := engine.Inbound(legitimate, Segment{Flags: FlagSYN, Sequence: 101}); err != nil || actions[0].Reason != "accept-syn" {
		t.Fatalf("known legitimate source starved by flood: actions=%#v err=%v", actions, err)
	}
}

func TestGlobalSYNRejectionDoesNotTouchOrAllocateSourceLedger(t *testing.T) {
	engine, clock := testEngine(t, func(options *Options) {
		options.SYNBurst = 1
		options.SYNBurstPerSource = 1
		options.SYNSourceLedgerCapacity = 16384
	})
	first := testFlow(31001)
	if actions, err := engine.Inbound(first, Segment{Flags: FlagSYN, Sequence: 1}); err != nil || actions[0].Reason != "accept-syn" {
		t.Fatalf("first SYN actions=%#v err=%v", actions, err)
	}
	populateExpiredSYNSourceLedger(engine, clock.now, engine.opts.SYNSourceLedgerCapacity)
	beforeSize := len(engine.synSources)
	beforeLRU := engine.synSourceLRU.Len()
	beforeVisits := engine.synSourcePruneVisits
	rejected := testFlow(65000)
	rejected.RemoteIPv4 += 1 << 24
	actions, err := engine.Inbound(rejected, Segment{Flags: FlagSYN, Sequence: 2})
	if err != nil || len(actions) != 1 || actions[0].Reason != "syn-rate-global" {
		t.Fatalf("exhausted global limiter actions=%#v err=%v", actions, err)
	}
	key := synSourceKey{remoteIPv4: rejected.RemoteIPv4, underlayIndex: rejected.UnderlayIndex}
	if _, created := engine.synSources[key]; created || len(engine.synSources) != beforeSize ||
		engine.synSourceLRU.Len() != beforeLRU || engine.synSourcePruneVisits != beforeVisits {
		t.Fatalf("global rejection touched ledger: created=%t size=%d/%d lru=%d/%d visits=%d/%d",
			created, len(engine.synSources), beforeSize, engine.synSourceLRU.Len(), beforeLRU,
			engine.synSourcePruneVisits, beforeVisits)
	}
}

func TestSYNSourceExpiryWorkIsConstantForFullLedger(t *testing.T) {
	engine, clock := testEngine(t, func(options *Options) {
		options.SYNBurst = 1
		options.SYNBurstPerSource = 1
		options.SYNSourceLedgerCapacity = 16384
	})
	populateExpiredSYNSourceLedger(engine, clock.now, engine.opts.SYNSourceLedgerCapacity)
	beforeVisits := engine.synSourcePruneVisits
	flow := testFlow(65001)
	flow.RemoteIPv4 += 1 << 24
	actions, err := engine.Inbound(flow, Segment{Flags: FlagSYN, Sequence: 1})
	if err != nil || len(actions) != 1 || actions[0].Reason != "accept-syn" {
		t.Fatalf("bounded prune admission actions=%#v err=%v", actions, err)
	}
	visits := engine.synSourcePruneVisits - beforeVisits
	if visits != synSourcePruneBudget {
		t.Fatalf("full 16K ledger expiry visits=%d, want fixed budget %d", visits, synSourcePruneBudget)
	}
	wantSize := engine.opts.SYNSourceLedgerCapacity - synSourcePruneBudget + 1
	if len(engine.synSources) != wantSize {
		t.Fatalf("ledger size after bounded cleanup=%d, want %d", len(engine.synSources), wantSize)
	}
}

func populateExpiredSYNSourceLedger(engine *Engine, now time.Time, target int) {
	for candidate := uint32(1); len(engine.synSources) < target; candidate++ {
		key := synSourceKey{remoteIPv4: candidate, underlayIndex: 99}
		if _, exists := engine.synSources[key]; exists {
			continue
		}
		source := &synSourceState{lastActivity: now.Add(-engine.opts.SYNSourceLedgerTTL - time.Second)}
		source.lruElement = engine.synSourceLRU.PushBack(key)
		engine.synSources[key] = source
	}
}

func TestSimultaneousOpen(t *testing.T) {
	engine, _ := testEngine(t, nil)
	flow := testFlow(31001)
	if _, err := engine.Outbound(flow, []byte{1}); err != nil {
		t.Fatal(err)
	}
	actions, err := engine.Inbound(flow, Segment{Flags: FlagSYN, Sequence: 8000})
	if err != nil || len(actions) != 1 || actions[0].Reason != "simultaneous-open" ||
		actions[0].Control.Flags != FlagSYN|FlagACK {
		t.Fatalf("actions=%#v err=%v", actions, err)
	}
	actions, err = engine.Inbound(flow, Segment{Flags: FlagACK, Acknowledgement: 1001})
	if err != nil || len(actions) != 1 || actions[0].Kind != ActionReleasePending {
		t.Fatalf("complete actions=%#v err=%v", actions, err)
	}
}

func TestRSTClosesAndDropsPendingAccounting(t *testing.T) {
	engine, _ := testEngine(t, nil)
	flow := testFlow(31001)
	if _, err := engine.Outbound(flow, []byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	actions, err := engine.Inbound(flow, Segment{Flags: FlagRST})
	if err != nil || len(actions) != 1 || actions[0].Kind != ActionClose {
		t.Fatalf("actions=%#v err=%v", actions, err)
	}
	if _, ok, _ := engine.Snapshot(flow); ok {
		t.Fatal("RST did not remove session")
	}
}

func TestHandshakeTimeoutRetriesThenCloses(t *testing.T) {
	engine, clock := testEngine(t, nil)
	flow := testFlow(31001)
	if _, err := engine.Outbound(flow, []byte{1}); err != nil {
		t.Fatal(err)
	}
	clock.Add(time.Second)
	actions, err := engine.Tick()
	if err != nil || len(actions) != 1 || actions[0].Reason != "handshake-retry" {
		t.Fatalf("retry actions=%#v err=%v", actions, err)
	}
	clock.Add(time.Second)
	actions, err = engine.Tick()
	if err != nil || len(actions) != 1 || actions[0].Reason != "handshake-timeout" {
		t.Fatalf("timeout actions=%#v err=%v", actions, err)
	}
}

func TestPendingQueueEnforcesFlowPacketAndByteLimits(t *testing.T) {
	engine, _ := testEngine(t, func(o *Options) {
		o.MaxPendingFlows = 1
		o.MaxPendingPacketsPerFlow = 1
		o.MaxPendingBytes = 4
	})
	flow1 := testFlow(31001)
	flow2 := testFlow(31002)
	if actions, _ := engine.Outbound(flow1, []byte{1, 2, 3, 4}); len(actions) != 1 {
		t.Fatalf("first actions=%#v", actions)
	}
	if actions, _ := engine.Outbound(flow1, []byte{5}); len(actions) != 1 || actions[0].Reason != "pending-capacity" {
		t.Fatalf("packet bound actions=%#v", actions)
	}
	if actions, _ := engine.Outbound(flow2, []byte{6}); len(actions) != 2 || actions[1].Reason != "pending-capacity" {
		t.Fatalf("flow/byte bound actions=%#v", actions)
	}
	state, ok, _ := engine.Snapshot(flow2)
	if !ok || state.PendingPackets != 0 {
		t.Fatalf("flow2 state=%#v ok=%t", state, ok)
	}
}

func TestUnknownProbeDoesNotAllocate(t *testing.T) {
	engine, _ := testEngine(t, nil)
	flow := testFlow(31001)
	actions, err := engine.Inbound(flow, Segment{Flags: FlagACK, Sequence: 42})
	if err != nil || len(actions) != 1 || actions[0].Reason != "unknown-flow" {
		t.Fatalf("actions=%#v err=%v", actions, err)
	}
	if _, ok, _ := engine.Snapshot(flow); ok {
		t.Fatal("probe allocated a session")
	}
}

func TestAdvanceGenerationRequiresNewEngineWithoutStateChange(t *testing.T) {
	engine, _ := testEngine(t, nil)
	flow := testFlow(31001)
	if _, err := engine.Outbound(flow, []byte{1}); err != nil {
		t.Fatal(err)
	}
	beforeIdentity := engine.Identity()
	beforeGeneration := engine.opts.Generation
	beforeCommitState := engine.runtimeIdentityCommit
	actions, err := engine.AdvanceGeneration(2)
	if !errors.Is(err, ErrEngineGenerationImmutable) || len(actions) != 0 {
		t.Fatalf("actions=%#v err=%v", actions, err)
	}
	if engine.opts.Generation != beforeGeneration || engine.Identity() != beforeIdentity ||
		engine.runtimeIdentityCommit != beforeCommitState {
		t.Fatalf(
			"generation rejection changed Engine: opts=%d identity=%#v commit=%p",
			engine.opts.Generation, engine.Identity(), engine.runtimeIdentityCommit,
		)
	}
	if snapshot, found, snapshotErr := engine.Snapshot(flow); snapshotErr != nil || !found || snapshot.PendingPackets != 1 {
		t.Fatalf("old generation session changed: snapshot=%#v found=%t err=%v", snapshot, found, snapshotErr)
	}
	newFlow := flow
	newFlow.Generation = 2
	if _, err := engine.Outbound(newFlow, []byte{2}); err == nil {
		t.Fatal("rejected generation became active")
	}
	if _, err := engine.Outbound(flow, []byte{2}); err != nil {
		t.Fatal(err)
	}
	freshOptions := engine.opts
	freshOptions.Generation = 2
	freshEngine, err := New(freshOptions)
	if err != nil {
		t.Fatal(err)
	}
	if freshEngine.Identity().Generation != 2 {
		t.Fatalf("fresh Engine identity generation=%d want=2", freshEngine.Identity().Generation)
	}
	if _, err := freshEngine.Outbound(newFlow, []byte{3}); err != nil {
		t.Fatalf("fresh Engine rejected its generation: %v", err)
	}
}

func TestAdvanceGenerationNeverDrainsEstablishedStore(t *testing.T) {
	store := newFakeSessionStore()
	engine, _ := testEngine(t, func(options *Options) { options.Store = store })
	flow := testFlow(31001)
	if _, err := engine.Outbound(flow, []byte{1}); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Inbound(flow, Segment{
		Flags: FlagSYN | FlagACK, Sequence: 9000, Acknowledgement: 1001,
	}); err != nil {
		t.Fatal(err)
	}
	beforeValue, found := store.values[flow]
	if !found {
		t.Fatal("established session was not inserted")
	}
	beforeDeletes := store.deleteAttempts
	actions, err := engine.AdvanceGeneration(2)
	if len(actions) != 0 || !errors.Is(err, ErrEngineGenerationImmutable) {
		t.Fatalf("actions=%#v err=%v", actions, err)
	}
	if store.deleteAttempts != beforeDeletes || store.values[flow] != beforeValue {
		t.Fatalf(
			"generation rejection changed established store: deletes=%d value=%#v",
			store.deleteAttempts, store.values[flow],
		)
	}
	if snapshot, found, snapshotErr := engine.Snapshot(flow); snapshotErr != nil || !found || snapshot.State != abi.FakeTCPStateEstablished {
		t.Fatalf("established session changed: snapshot=%#v found=%t err=%v", snapshot, found, snapshotErr)
	}
}

func TestRejectedGenerationAdvanceKeepsPacketEventIdentityConsistent(t *testing.T) {
	engine, _ := testEngine(t, nil)
	if _, err := engine.AdvanceGeneration(2); !errors.Is(err, ErrEngineGenerationImmutable) {
		t.Fatalf("AdvanceGeneration error=%v", err)
	}
	flow := testFlow(31001)
	event := abi.FakeTCPPacketEvent{Event: abi.FakeTCPEvent{
		Key: flow, Type: abi.FakeTCPEventNeedHandshake, PacketLength: 1,
	}}
	bindTestEvent(&event.Event, engine.Identity(), 1)
	event.Packet[0] = 1
	if actions, err := engine.HandlePacketEvent(event); err != nil || len(actions) != 1 {
		t.Fatalf("original generation packet event actions=%#v err=%v", actions, err)
	}

	newFlow := flow
	newFlow.Generation = 2
	newEvent := abi.FakeTCPPacketEvent{Event: abi.FakeTCPEvent{
		Key: newFlow, Type: abi.FakeTCPEventNeedHandshake, PacketLength: 1,
	}}
	bindTestEvent(&newEvent.Event, RuntimeIdentity{
		Generation: 2, Incarnation: engine.Identity().Incarnation,
	}, 1)
	newEvent.Packet[0] = 1
	if _, err := engine.HandlePacketEvent(newEvent); err == nil {
		t.Fatal("rejected generation packet event was accepted")
	}
	if _, found, err := engine.Snapshot(newFlow); err != nil || found {
		t.Fatalf("rejected generation touched Engine: found=%t err=%v", found, err)
	}
}

func TestAdvanceGenerationDoesNotConsumeOrResetRuntimeIdentityCommit(t *testing.T) {
	consumed := errors.New("consumed")

	t.Run("not yet consumed", func(t *testing.T) {
		engine, _ := testEngine(t, nil)
		if _, err := engine.AdvanceGeneration(2); !errors.Is(err, ErrEngineGenerationImmutable) {
			t.Fatalf("AdvanceGeneration error=%v", err)
		}
		var calls atomic.Int32
		if err := engine.commitRuntimeIdentityOnce(consumed, func() error {
			calls.Add(1)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if calls.Load() != 1 {
			t.Fatalf("generation rejection consumed commit capability: calls=%d", calls.Load())
		}
	})

	t.Run("already consumed", func(t *testing.T) {
		engine, _ := testEngine(t, nil)
		if err := engine.commitRuntimeIdentityOnce(consumed, func() error { return nil }); err != nil {
			t.Fatal(err)
		}
		beforeIdentity := engine.Identity()
		beforeCommitState := engine.runtimeIdentityCommit
		if _, err := engine.AdvanceGeneration(2); !errors.Is(err, ErrEngineGenerationImmutable) {
			t.Fatalf("AdvanceGeneration error=%v", err)
		}
		called := false
		if err := engine.commitRuntimeIdentityOnce(consumed, func() error {
			called = true
			return nil
		}); !errors.Is(err, consumed) {
			t.Fatalf("consumed commit error=%v", err)
		}
		if called || engine.Identity() != beforeIdentity || engine.runtimeIdentityCommit != beforeCommitState {
			t.Fatal("generation rejection reset consumed identity state")
		}
	})
}

func TestAdvanceGenerationCannotRaceRuntimeIdentityCommit(t *testing.T) {
	engine, _ := testEngine(t, nil)
	flow := testFlow(31001)
	if _, err := engine.Outbound(flow, []byte{1}); err != nil {
		t.Fatal(err)
	}
	beforeIdentity := engine.Identity()
	beforeGeneration := engine.opts.Generation
	beforeCommitState := engine.runtimeIdentityCommit
	consumed := errors.New("consumed")
	var commitCalls atomic.Int32
	start := make(chan struct{})
	results := make(chan error, 33)
	var group sync.WaitGroup
	group.Add(1)
	go func() {
		defer group.Done()
		<-start
		results <- engine.commitRuntimeIdentityOnce(consumed, func() error {
			commitCalls.Add(1)
			return nil
		})
	}()
	for range 32 {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			actions, err := engine.AdvanceGeneration(2)
			if len(actions) != 0 || !errors.Is(err, ErrEngineGenerationImmutable) {
				results <- fmt.Errorf("advance actions=%#v error=%w", actions, err)
				return
			}
			results <- nil
		}()
	}
	close(start)
	group.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	if commitCalls.Load() != 1 {
		t.Fatalf("commit callbacks=%d want=1", commitCalls.Load())
	}
	if engine.opts.Generation != beforeGeneration || engine.Identity() != beforeIdentity ||
		engine.runtimeIdentityCommit != beforeCommitState {
		t.Fatal("concurrent generation rejection changed Engine identity state")
	}
	if snapshot, found, err := engine.Snapshot(flow); err != nil || !found || snapshot.PendingPackets != 1 {
		t.Fatalf("concurrent generation rejection changed session: snapshot=%#v found=%t err=%v", snapshot, found, err)
	}
}

func TestAdvanceGenerationNilAndZeroEngineFailClosed(t *testing.T) {
	for _, engine := range []*Engine{nil, &Engine{}} {
		if actions, err := engine.AdvanceGeneration(2); len(actions) != 0 || !errors.Is(err, ErrEngineGenerationImmutable) {
			t.Fatalf("actions=%#v err=%v", actions, err)
		}
	}
}

func TestStoreFailureRollsBackEstablishmentAndPendingRelease(t *testing.T) {
	store := newFakeSessionStore()
	store.insertErr = errors.New("map unavailable")
	engine, _ := testEngine(t, func(o *Options) {
		o.Store = store
	})
	flow := testFlow(31001)
	actions, err := engine.Outbound(flow, []byte{1, 2, 3, 4})
	if err != nil || len(actions) != 1 || actions[0].Reason != "initial-handshake" {
		t.Fatalf("half-open actions=%#v err=%v", actions, err)
	}
	if store.inserts != 0 || len(store.values) != 0 {
		t.Fatal("half-open session was written into the established fast map")
	}
	actions, err = engine.Inbound(flow, Segment{
		Flags: FlagSYN | FlagACK, Sequence: 9000, Acknowledgement: 1001,
	})
	if err == nil || len(actions) != 1 || actions[0].Reason != "session-store-unavailable" {
		t.Fatalf("actions=%#v err=%v", actions, err)
	}
	state, ok, snapshotErr := engine.Snapshot(flow)
	if snapshotErr != nil || !ok || state.State != abi.FakeTCPStateSynSent ||
		state.PendingPackets != 1 {
		t.Fatalf("failed insert state=%#v ok=%t err=%v", state, ok, snapshotErr)
	}
}

func TestEstablishedStateReadsBPFAdvanceAndNeverOverwritesOrRacyDeletes(t *testing.T) {
	store := newFakeSessionStore()
	engine, clock := testEngine(t, func(o *Options) { o.Store = store })
	flow := testFlow(31001)
	if _, err := engine.Outbound(flow, []byte{1, 2, 3, 4}); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Inbound(flow, Segment{
		Flags: FlagSYN | FlagACK, Sequence: 9000, Acknowledgement: 1001,
	}); err != nil {
		t.Fatal(err)
	}
	if store.inserts != 1 {
		t.Fatalf("established inserts = %d, want exactly one", store.inserts)
	}

	// Simulate TC/XDP advancing the authoritative value between userspace
	// turns. Tick must build keepalive from these current sequences and must
	// not write its stale in-memory copy back over them.
	value := store.values[flow]
	if value.Revision != 1 || value.SessionID != 1 ||
		value.RuntimeIncarnation != [16]byte(engine.Identity().Incarnation) {
		t.Fatalf("established value lacks ABA identity: %#v", value)
	}
	value.TXSequence += 4096
	value.RXSequence += 2048
	value.LastSeenNanos = clock.monotonic
	value.Revision++
	store.values[flow] = value
	clock.Add(5 * time.Second)
	actions, err := engine.Tick()
	if err != nil || len(actions) != 1 || actions[0].Reason != "keepalive" {
		t.Fatalf("keepalive actions=%#v err=%v", actions, err)
	}
	if actions[0].Control.Sequence != value.TXSequence-1 ||
		actions[0].Control.Acknowledgement != value.RXSequence {
		t.Fatalf("keepalive used stale fast state: %#v, want tx=%d rx=%d",
			actions[0].Control, value.TXSequence, value.RXSequence)
	}
	if store.inserts != 1 || store.values[flow] != value {
		t.Fatal("userspace overwrote BPF-owned established fields")
	}

	// Make the observed value idle, then advance it inside the conditional
	// delete operation exactly as BPF could. Compare-and-delete must fail and
	// the active session must remain alive with the newer state.
	clock.Add(21 * time.Second)
	advanced := value
	advanced.TXSequence += 128
	advanced.RXSequence += 64
	advanced.LastSeenNanos = clock.monotonic
	advanced.Revision++
	store.beforeDelete = func(key abi.FakeTCPSessionKey) {
		store.values[key] = advanced
		store.beforeDelete = nil
	}
	actions, err = engine.Tick()
	if err != nil || len(actions) != 0 {
		t.Fatalf("raced idle actions=%#v err=%v", actions, err)
	}
	if store.deleteAttempts != 1 || store.values[flow] != advanced {
		t.Fatalf("conditional delete ignored BPF advance: attempts=%d value=%#v",
			store.deleteAttempts, store.values[flow])
	}
	snapshot, ok, err := engine.Snapshot(flow)
	if err != nil || !ok || snapshot.TXSequence != advanced.TXSequence ||
		snapshot.RXSequence != advanced.RXSequence ||
		snapshot.LastSeenNanos != advanced.LastSeenNanos {
		t.Fatalf("snapshot=%#v ok=%t err=%v, want current BPF state", snapshot, ok, err)
	}
	if store.inserts != 1 {
		t.Fatalf("established state was reinserted %d times", store.inserts)
	}
}

func TestSYNFloodCannotEnterOrEvictEstablishedFastState(t *testing.T) {
	store := newFakeSessionStore()
	engine, clock := testEngine(t, func(o *Options) {
		o.Store = store
		o.MaxHalfOpenSessions = 3
		o.MaxHalfOpenPerSource = 1
		o.SYNBurst = 32
		o.SYNBurstPerSource = 1
		o.SYNSourceLedgerCapacity = 16
		o.HandshakeRetries = 1
	})
	established := testFlow(31001)
	if _, err := engine.Outbound(established, []byte{1}); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Inbound(established, Segment{
		Flags: FlagSYN | FlagACK, Sequence: 9000, Acknowledgement: 1001,
	}); err != nil {
		t.Fatal(err)
	}
	wantEstablished := store.values[established]

	accepted := 0
	rejected := 0
	for source := uint32(1); source <= 12; source++ {
		flow := testFlow(uint16(32000 + source))
		flow.RemoteIPv4 += source
		actions, err := engine.Inbound(flow, Segment{Flags: FlagSYN, Sequence: source * 100})
		if err != nil || len(actions) != 1 {
			t.Fatalf("source %d actions=%#v err=%v", source, actions, err)
		}
		if actions[0].Reason == "accept-syn" {
			accepted++
		} else if actions[0].Reason == "half-open-capacity" {
			rejected++
		} else {
			t.Fatalf("source %d unexpected reason %q", source, actions[0].Reason)
		}
	}
	if accepted != 3 || rejected != 9 {
		t.Fatalf("SYN budget accepted=%d rejected=%d, want 3/9", accepted, rejected)
	}
	if store.inserts != 1 || len(store.values) != 1 || store.values[established] != wantEstablished {
		t.Fatal("half-open flood entered or changed the established fast map")
	}

	clock.Add(time.Second)
	if _, err := engine.Tick(); err != nil {
		t.Fatal(err)
	}
	snapshot, ok, err := engine.Snapshot(established)
	if err != nil || !ok || snapshot.State != abi.FakeTCPStateEstablished ||
		store.values[established] != wantEstablished {
		t.Fatalf("established session after flood=%#v ok=%t err=%v", snapshot, ok, err)
	}
}

func TestInboundSYNRateAndPerSourceBudgets(t *testing.T) {
	tests := []struct {
		name          string
		mutate        func(*Options)
		secondSource  bool
		wantRejection string
	}{
		{
			name: "global rate",
			mutate: func(o *Options) {
				o.SYNBurst = 1
				o.SYNBurstPerSource = 1
			},
			secondSource:  true,
			wantRejection: "syn-rate-global",
		},
		{
			name: "source rate",
			mutate: func(o *Options) {
				o.SYNBurst = 4
				o.SYNBurstPerSource = 1
				o.MaxHalfOpenPerSource = 4
			},
			wantRejection: "syn-rate-source",
		},
		{
			name: "source half-open",
			mutate: func(o *Options) {
				o.SYNBurst = 4
				o.SYNBurstPerSource = 4
				o.MaxHalfOpenPerSource = 1
			},
			wantRejection: "half-open-source-capacity",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine, _ := testEngine(t, tt.mutate)
			first := testFlow(31001)
			actions, err := engine.Inbound(first, Segment{Flags: FlagSYN, Sequence: 100})
			if err != nil || len(actions) != 1 || actions[0].Reason != "accept-syn" {
				t.Fatalf("first actions=%#v err=%v", actions, err)
			}
			second := testFlow(31002)
			if tt.secondSource {
				second.RemoteIPv4++
			}
			actions, err = engine.Inbound(second, Segment{Flags: FlagSYN, Sequence: 200})
			if err != nil || len(actions) != 1 || actions[0].Reason != tt.wantRejection {
				t.Fatalf("second actions=%#v err=%v, want %q", actions, err, tt.wantRejection)
			}
		})
	}
}

func TestRawIPv4BE32MatchesBPFMemoryLayout(t *testing.T) {
	raw, err := RawIPv4BE32(netip.MustParseAddr("10.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	var bytes [4]byte
	binary.NativeEndian.PutUint32(bytes[:], raw)
	if bytes != [4]byte{10, 0, 0, 1} {
		t.Fatalf("raw __be32 memory = %v", bytes)
	}
}

func TestAdjustTransportMTUAccountsForTCPHeaderDelta(t *testing.T) {
	got, err := AdjustTransportMTU(1500)
	if err != nil || got != 1488 {
		t.Fatalf("adjusted MTU = %d, err=%v, want 1488", got, err)
	}
	if _, err := AdjustTransportMTU(WireHeaderOverhead); err == nil {
		t.Fatal("non-positive post-encapsulation MTU was accepted")
	}
}

func TestPacketEventFeedsRealBoundedQueueAndReleaseMetadata(t *testing.T) {
	engine, _ := testEngine(t, nil)
	flow := testFlow(31001)
	event := abi.FakeTCPPacketEvent{Event: abi.FakeTCPEvent{
		Key: flow, Type: abi.FakeTCPEventNeedHandshake,
		PacketLength: 4, FWMark: 0x10000002, WGID: 7,
	}}
	bindTestEvent(&event.Event, engine.Identity(), 1)
	copy(event.Packet[:], []byte{0x45, 1, 2, 3})
	actions, err := engine.HandlePacketEvent(event)
	if err != nil || len(actions) != 1 || actions[0].Control.Flags != FlagSYN {
		t.Fatalf("capture actions=%#v err=%v", actions, err)
	}
	event.Packet[0] = 0xff
	actions, err = engine.Inbound(flow, Segment{
		Flags: FlagSYN | FlagACK, Sequence: 9000, Acknowledgement: 1001,
	})
	if err != nil || len(actions) != 2 || actions[1].Kind != ActionReleasePending {
		t.Fatalf("release actions=%#v err=%v", actions, err)
	}
	packet := actions[1].Packets[0]
	if packet.Data[0] != 0x45 || packet.FWMark != 0x10000002 || packet.WGID != 7 {
		t.Fatalf("released packet=%#v", packet)
	}
}

func TestPacketEventRejectsMissingPacketBody(t *testing.T) {
	engine, _ := testEngine(t, nil)
	event := abi.FakeTCPPacketEvent{Event: abi.FakeTCPEvent{
		Key: testFlow(31001), Type: abi.FakeTCPEventNeedHandshake,
	}}
	bindTestEvent(&event.Event, engine.Identity(), 1)
	_, err := engine.HandlePacketEvent(event)
	if err == nil {
		t.Fatal("metadata-only NEED_HANDSHAKE event was accepted")
	}
}

func TestEngineRejectsPacketEventFromDifferentIncarnation(t *testing.T) {
	engine, _ := testEngine(t, nil)
	flow := testFlow(31001)
	event := abi.FakeTCPPacketEvent{Event: abi.FakeTCPEvent{
		Key: flow, Type: abi.FakeTCPEventNeedHandshake, PacketLength: 1,
	}}
	wrong := engine.Identity()
	wrong.Incarnation[0] = 2
	bindTestEvent(&event.Event, wrong, 1)
	event.Packet[0] = 1
	if _, err := engine.HandlePacketEvent(event); err == nil {
		t.Fatal("packet event from another Engine incarnation was accepted")
	}
	if _, found, err := engine.Snapshot(flow); err != nil || found {
		t.Fatalf("mismatched packet event touched Engine: found=%t err=%v", found, err)
	}
}

func TestWGIDMismatchCannotDriveOrCloseExistingSession(t *testing.T) {
	engine, _ := testEngine(t, nil)
	flow := testFlow(31001)
	event := abi.FakeTCPPacketEvent{Event: abi.FakeTCPEvent{
		Key: flow, Type: abi.FakeTCPEventNeedHandshake,
		PacketLength: 1, WGID: 7,
	}}
	bindTestEvent(&event.Event, engine.Identity(), 1)
	event.Packet[0] = 1
	actions, err := engine.HandlePacketEvent(event)
	if err != nil || len(actions) != 1 || actions[0].WGID != 7 {
		t.Fatalf("initial actions=%#v err=%v", actions, err)
	}
	for _, segment := range []Segment{
		{Flags: FlagSYN | FlagACK, Sequence: 9000, Acknowledgement: 1001},
		{Flags: FlagRST},
	} {
		actions, err = engine.InboundWithWGID(flow, segment, 8)
		if err != nil || len(actions) != 1 || actions[0].Reason != "wg-id-mismatch" {
			t.Fatalf("mismatched actions=%#v err=%v", actions, err)
		}
	}
	state, ok, _ := engine.Snapshot(flow)
	if !ok || state.State != abi.FakeTCPStateSynSent {
		t.Fatalf("mismatched event changed state=%#v ok=%t", state, ok)
	}
}

func TestLatePacketEventAfterEstablishmentIsReinjected(t *testing.T) {
	engine, _ := testEngine(t, nil)
	flow := testFlow(31001)
	if _, err := engine.Outbound(flow, []byte{1}); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Inbound(flow, Segment{
		Flags: FlagSYN | FlagACK, Sequence: 9000, Acknowledgement: 1001,
	}); err != nil {
		t.Fatal(err)
	}
	event := abi.FakeTCPPacketEvent{Event: abi.FakeTCPEvent{
		Key: flow, Type: abi.FakeTCPEventNeedHandshake,
		PacketLength: 2, FWMark: 3, WGID: 7,
	}}
	bindTestEvent(&event.Event, engine.Identity(), 2)
	copy(event.Packet[:], []byte{4, 5})
	actions, err := engine.HandlePacketEvent(event)
	if err != nil || len(actions) != 1 || actions[0].Kind != ActionReleasePending ||
		len(actions[0].Packets) != 1 || actions[0].Packets[0].Data[1] != 5 {
		t.Fatalf("late packet actions=%#v err=%v", actions, err)
	}
}
