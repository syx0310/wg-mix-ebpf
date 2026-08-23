package faketcp

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestRuntimeDomainSharesIdentitySessionIDsAndCommit(t *testing.T) {
	firstOptions := runtimeDomainTestOptions(t)
	secondOptions := runtimeDomainTestOptions(t)
	domain, err := NewRuntimeDomain(firstOptions.Generation)
	if err != nil {
		t.Fatal(err)
	}
	first, err := domain.NewEngine(firstOptions)
	if err != nil {
		t.Fatal(err)
	}
	second, err := domain.NewEngine(secondOptions)
	if err != nil {
		t.Fatal(err)
	}
	if first.Identity() != domain.Identity() || second.Identity() != domain.Identity() {
		t.Fatal("runtime domain Engines did not share one identity")
	}
	firstID, err := first.sessionIDs.allocate()
	if err != nil {
		t.Fatal(err)
	}
	secondID, err := second.sessionIDs.allocate()
	if err != nil {
		t.Fatal(err)
	}
	if firstID != 1 || secondID != 2 {
		t.Fatalf("shared session IDs=(%d,%d), want (1,2)", firstID, secondID)
	}

	consumed := errors.New("consumed")
	var calls atomic.Int32
	if err := first.commitRuntimeIdentityOnce(consumed, func() error {
		calls.Add(1)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := second.commitRuntimeIdentityOnce(consumed, func() error {
		calls.Add(1)
		return nil
	}); !errors.Is(err, consumed) {
		t.Fatalf("second domain commit error=%v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("domain commit callbacks=%d want=1", calls.Load())
	}
}

func TestRuntimeDomainRejectsGenerationMismatch(t *testing.T) {
	domain, err := NewRuntimeDomain(1)
	if err != nil {
		t.Fatal(err)
	}
	options := runtimeDomainTestOptions(t)
	options.Generation = 2
	if _, err := domain.NewEngine(options); err == nil {
		t.Fatal("runtime domain accepted a different Engine generation")
	}
}

func runtimeDomainTestOptions(t testing.TB) Options {
	t.Helper()
	clock := &fakeClock{now: time.Unix(100, 0), monotonic: uint64(100 * time.Second)}
	nextISN := uint32(1000)
	return Options{
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
}
