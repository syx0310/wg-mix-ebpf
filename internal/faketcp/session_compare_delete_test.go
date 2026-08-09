package faketcp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

type modelClaimEntry struct {
	mu    sync.Mutex
	value abi.FakeTCPSessionValue
}

type modelSessionClaimKernel struct {
	mu sync.Mutex

	identity    SessionMapIdentity
	programType ebpf.ProgramType
	programMaps []uint32
	entries     map[abi.FakeTCPSessionKey]*modelClaimEntry
	runCalls    int
	deleteCalls int
	deleteErr   error
	afterLock   func(abi.FakeTCPSessionKey)
	afterClaim  func(abi.FakeTCPSessionKey)
}

func newModelSessionClaimKernel() *modelSessionClaimKernel {
	identity := validSessionMapIdentity()
	return &modelSessionClaimKernel{
		identity: identity, programType: ebpf.SchedCLS,
		programMaps: []uint32{identity.ID},
		entries:     make(map[abi.FakeTCPSessionKey]*modelClaimEntry),
	}
}

func (kernel *modelSessionClaimKernel) SessionMapIdentity() (SessionMapIdentity, error) {
	kernel.mu.Lock()
	defer kernel.mu.Unlock()
	return kernel.identity, nil
}

func (kernel *modelSessionClaimKernel) ClaimProgramBinding() (ebpf.ProgramType, []uint32, error) {
	kernel.mu.Lock()
	defer kernel.mu.Unlock()
	return kernel.programType, append([]uint32(nil), kernel.programMaps...), nil
}

func (kernel *modelSessionClaimKernel) RunClaim(request []byte) (uint32, error) {
	if len(request) != int(fakeTCPSessionClaimRequestSize) {
		return fakeTCPSessionClaimMalformed, nil
	}
	reader := bytes.NewReader(request)
	var key abi.FakeTCPSessionKey
	var expected abi.FakeTCPSessionValue
	if err := binary.Read(reader, binary.NativeEndian, &key); err != nil {
		return 0, err
	}
	if err := binary.Read(reader, binary.NativeEndian, &expected); err != nil {
		return 0, err
	}

	kernel.mu.Lock()
	kernel.runCalls++
	entry := kernel.entries[key]
	afterLock := kernel.afterLock
	afterClaim := kernel.afterClaim
	kernel.mu.Unlock()
	if entry == nil {
		return fakeTCPSessionClaimAbsent, nil
	}

	entry.mu.Lock()
	if afterLock != nil {
		afterLock(key)
	}
	actual := entry.value
	normalized := actual
	if normalized.State == abi.FakeTCPStateDeleteClaimed {
		normalized.State = abi.FakeTCPStateEstablished
	}
	if normalized != expected ||
		(actual.State != abi.FakeTCPStateEstablished &&
			actual.State != abi.FakeTCPStateDeleteClaimed) {
		entry.mu.Unlock()
		return fakeTCPSessionClaimDifferent, nil
	}
	entry.value.State = abi.FakeTCPStateDeleteClaimed
	entry.mu.Unlock()
	if afterClaim != nil {
		afterClaim(key)
	}
	return fakeTCPSessionClaimed, nil
}

func (kernel *modelSessionClaimKernel) DeleteSession(key abi.FakeTCPSessionKey) error {
	kernel.mu.Lock()
	defer kernel.mu.Unlock()
	kernel.deleteCalls++
	if kernel.deleteErr != nil {
		return kernel.deleteErr
	}
	delete(kernel.entries, key)
	return nil
}

func (kernel *modelSessionClaimKernel) put(
	key abi.FakeTCPSessionKey,
	value abi.FakeTCPSessionValue,
) {
	kernel.mu.Lock()
	defer kernel.mu.Unlock()
	kernel.entries[key] = &modelClaimEntry{value: value}
}

func (kernel *modelSessionClaimKernel) value(
	key abi.FakeTCPSessionKey,
) (abi.FakeTCPSessionValue, bool) {
	kernel.mu.Lock()
	entry := kernel.entries[key]
	kernel.mu.Unlock()
	if entry == nil {
		return abi.FakeTCPSessionValue{}, false
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	return entry.value, true
}

// write models every TC/XDP mutable site: lookup may happen before claim, but
// admission and mutation share the value's lock and recheck the tombstone.
func (kernel *modelSessionClaimKernel) write(
	key abi.FakeTCPSessionKey,
	mutate func(*abi.FakeTCPSessionValue),
) bool {
	kernel.mu.Lock()
	entry := kernel.entries[key]
	kernel.mu.Unlock()
	if entry == nil {
		return false
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.value.State != abi.FakeTCPStateEstablished ||
		entry.value.Generation != key.Generation || entry.value.Revision == ^uint64(0) {
		return false
	}
	mutate(&entry.value)
	entry.value.Revision++
	return true
}

func newModelSessionDeleter(t *testing.T) (*LinuxAtomicSessionCompareDeleter, *modelSessionClaimKernel) {
	t.Helper()
	kernel := newModelSessionClaimKernel()
	deleter, err := newLinuxAtomicSessionCompareDeleter(kernel, kernel.identity)
	if err != nil {
		t.Fatal(err)
	}
	return deleter, kernel
}

func TestLinuxAtomicSessionCompareDeleteLinearization(t *testing.T) {
	key := sessionStoreTestKey(7)
	expected := sessionStoreTestValue(7)

	t.Run("equal value claims then deletes", func(t *testing.T) {
		deleter, kernel := newModelSessionDeleter(t)
		kernel.put(key, expected)
		deleted, err := deleter.CompareDeleteEstablished(kernel.identity, key, expected)
		if err != nil || !deleted {
			t.Fatalf("deleted=%t err=%v", deleted, err)
		}
		if _, found := kernel.value(key); found {
			t.Fatal("claimed value survived exact delete")
		}
		if kernel.runCalls != 1 || kernel.deleteCalls != 1 {
			t.Fatalf("run calls=%d delete calls=%d", kernel.runCalls, kernel.deleteCalls)
		}
	})

	t.Run("absent and different never delete", func(t *testing.T) {
		deleter, kernel := newModelSessionDeleter(t)
		if deleted, err := deleter.CompareDeleteEstablished(kernel.identity, key, expected); err != nil || deleted {
			t.Fatalf("absent deleted=%t err=%v", deleted, err)
		}
		advanced := expected
		advanced.TXSequence++
		advanced.Revision++
		kernel.put(key, advanced)
		if deleted, err := deleter.CompareDeleteEstablished(kernel.identity, key, expected); err != nil || deleted {
			t.Fatalf("different deleted=%t err=%v", deleted, err)
		}
		if got, found := kernel.value(key); !found || got != advanced {
			t.Fatalf("different value changed: got=%#v found=%t", got, found)
		}
		if kernel.deleteCalls != 0 {
			t.Fatalf("different/absent reached delete %d times", kernel.deleteCalls)
		}
	})

	t.Run("writer before claim is preserved", func(t *testing.T) {
		deleter, kernel := newModelSessionDeleter(t)
		kernel.put(key, expected)
		if !kernel.write(key, func(value *abi.FakeTCPSessionValue) {
			value.LastSeenNanos++
			value.TXSequence += 32
		}) {
			t.Fatal("model writer was not admitted")
		}
		advanced, _ := kernel.value(key)
		if deleted, err := deleter.CompareDeleteEstablished(kernel.identity, key, expected); err != nil || deleted {
			t.Fatalf("advanced deleted=%t err=%v", deleted, err)
		}
		if got, found := kernel.value(key); !found || got != advanced {
			t.Fatalf("writer update lost: got=%#v found=%t", got, found)
		}
	})

	t.Run("writer during claim waits then rejects tombstone", func(t *testing.T) {
		deleter, kernel := newModelSessionDeleter(t)
		kernel.put(key, expected)
		claimLocked := make(chan struct{})
		releaseClaim := make(chan struct{})
		kernel.afterLock = func(abi.FakeTCPSessionKey) {
			close(claimLocked)
			<-releaseClaim
		}
		deleteResult := make(chan error, 1)
		go func() {
			deleted, err := deleter.CompareDeleteEstablished(kernel.identity, key, expected)
			if err == nil && !deleted {
				err = errors.New("compare-delete returned false")
			}
			deleteResult <- err
		}()
		<-claimLocked
		writerResult := make(chan bool, 1)
		go func() {
			writerResult <- kernel.write(key, func(value *abi.FakeTCPSessionValue) {
				value.TXSequence++
			})
		}()
		select {
		case <-writerResult:
			t.Fatal("writer bypassed held per-session claim lock")
		case <-time.After(20 * time.Millisecond):
		}
		close(releaseClaim)
		if err := <-deleteResult; err != nil {
			t.Fatal(err)
		}
		if admitted := <-writerResult; admitted {
			t.Fatal("writer was admitted after tombstone")
		}
	})

	t.Run("writer after claim before delete rejects tombstone", func(t *testing.T) {
		deleter, kernel := newModelSessionDeleter(t)
		kernel.put(key, expected)
		claimed := make(chan struct{})
		finishRun := make(chan struct{})
		kernel.afterClaim = func(abi.FakeTCPSessionKey) {
			close(claimed)
			<-finishRun
		}
		result := make(chan error, 1)
		go func() {
			deleted, err := deleter.CompareDeleteEstablished(kernel.identity, key, expected)
			if err == nil && !deleted {
				err = errors.New("compare-delete returned false")
			}
			result <- err
		}()
		<-claimed
		if kernel.write(key, func(value *abi.FakeTCPSessionValue) { value.RXSequence++ }) {
			t.Fatal("post-claim writer mutated tombstone")
		}
		close(finishRun)
		if err := <-result; err != nil {
			t.Fatal(err)
		}
	})
}

func TestLinuxAtomicSessionCompareDeleteCrashRecoveryAndABA(t *testing.T) {
	key := sessionStoreTestKey(7)
	expected := sessionStoreTestValue(7)
	deleter, kernel := newModelSessionDeleter(t)
	kernel.put(key, expected)
	crash := errors.New("simulated crash before exact delete")
	kernel.deleteErr = crash
	if deleted, err := deleter.CompareDeleteEstablished(kernel.identity, key, expected); deleted || !errors.Is(err, crash) {
		t.Fatalf("first delete deleted=%t err=%v", deleted, err)
	}
	claimed, found := kernel.value(key)
	if !found || claimed.State != abi.FakeTCPStateDeleteClaimed {
		t.Fatalf("crash did not preserve tombstone: value=%#v found=%t", claimed, found)
	}

	different := expected
	different.SessionID++
	if deleted, err := deleter.CompareDeleteEstablished(kernel.identity, key, different); err != nil || deleted {
		t.Fatalf("different tombstone claimant deleted=%t err=%v", deleted, err)
	}
	if got, found := kernel.value(key); !found || got != claimed {
		t.Fatalf("different claimant changed tombstone: got=%#v found=%t", got, found)
	}

	kernel.deleteErr = nil
	if deleted, err := deleter.CompareDeleteEstablished(kernel.identity, key, expected); err != nil || !deleted {
		t.Fatalf("idempotent crash retry deleted=%t err=%v", deleted, err)
	}

	// A reinsert with otherwise identical transport fields has a fresh
	// SessionID/revision and cannot inherit the old snapshot's authority.
	reinserted := expected
	reinserted.SessionID++
	reinserted.Revision++
	kernel.put(key, reinserted)
	if deleted, err := deleter.CompareDeleteEstablished(kernel.identity, key, expected); err != nil || deleted {
		t.Fatalf("ABA reinsert deleted=%t err=%v", deleted, err)
	}
	if got, found := kernel.value(key); !found || got != reinserted {
		t.Fatalf("ABA reinsert changed: got=%#v found=%t", got, found)
	}
}

func TestLinuxAtomicSessionCompareDeleteIdentityDriftPreservesState(t *testing.T) {
	key := sessionStoreTestKey(7)
	expected := sessionStoreTestValue(7)

	t.Run("map replacement before claim", func(t *testing.T) {
		deleter, kernel := newModelSessionDeleter(t)
		kernel.put(key, expected)
		kernel.identity.ID++
		if deleted, err := deleter.CompareDeleteEstablished(deleter.identity, key, expected); deleted ||
			!errors.Is(err, ErrSessionMapIdentityChanged) {
			t.Fatalf("deleted=%t err=%v", deleted, err)
		}
		if kernel.runCalls != 0 || kernel.deleteCalls != 0 {
			t.Fatalf("identity drift reached run/delete: %d/%d", kernel.runCalls, kernel.deleteCalls)
		}
	})

	t.Run("map replacement after claim preserves tombstone", func(t *testing.T) {
		deleter, kernel := newModelSessionDeleter(t)
		kernel.put(key, expected)
		kernel.afterClaim = func(abi.FakeTCPSessionKey) {
			kernel.mu.Lock()
			kernel.identity.ID++
			kernel.mu.Unlock()
		}
		if deleted, err := deleter.CompareDeleteEstablished(kernel.identity, key, expected); deleted ||
			!errors.Is(err, ErrSessionMapIdentityChanged) {
			t.Fatalf("deleted=%t err=%v", deleted, err)
		}
		if got, found := kernel.value(key); !found || got.State != abi.FakeTCPStateDeleteClaimed {
			t.Fatalf("post-claim drift erased tombstone: got=%#v found=%t", got, found)
		}
		if kernel.deleteCalls != 0 {
			t.Fatalf("post-claim drift reached delete %d times", kernel.deleteCalls)
		}
	})

	t.Run("claim program map binding drift", func(t *testing.T) {
		deleter, kernel := newModelSessionDeleter(t)
		kernel.put(key, expected)
		kernel.programMaps = []uint32{kernel.identity.ID + 1}
		if deleted, err := deleter.CompareDeleteEstablished(kernel.identity, key, expected); err == nil || deleted {
			t.Fatalf("deleted=%t err=%v", deleted, err)
		}
		if kernel.runCalls != 0 || kernel.deleteCalls != 0 {
			t.Fatalf("program drift reached run/delete: %d/%d", kernel.runCalls, kernel.deleteCalls)
		}
	})
}

func TestLinuxAtomicSessionPerEntryLocksDoNotSerializeOtherSessions(t *testing.T) {
	keyA := sessionStoreTestKey(7)
	keyB := keyA
	keyB.RemotePort++
	valueA := sessionStoreTestValue(7)
	valueB := valueA
	valueB.SessionID++
	deleter, kernel := newModelSessionDeleter(t)
	kernel.put(keyA, valueA)
	kernel.put(keyB, valueB)
	lockedA := make(chan struct{})
	releaseA := make(chan struct{})
	kernel.afterLock = func(key abi.FakeTCPSessionKey) {
		if key == keyA {
			close(lockedA)
			<-releaseA
		}
	}
	claimDone := make(chan error, 1)
	go func() {
		_, err := deleter.CompareDeleteEstablished(kernel.identity, keyA, valueA)
		claimDone <- err
	}()
	<-lockedA
	writerDone := make(chan bool, 1)
	go func() {
		writerDone <- kernel.write(keyB, func(value *abi.FakeTCPSessionValue) {
			value.LastSeenNanos++
		})
	}()
	select {
	case admitted := <-writerDone:
		if !admitted {
			t.Fatal("independent session writer was rejected")
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("session B serialized behind session A claim")
	}
	close(releaseA)
	if err := <-claimDone; err != nil {
		t.Fatal(err)
	}
}

func TestLinuxSessionStoreCloseWaitsForAdmittedAtomicDelete(t *testing.T) {
	key := sessionStoreTestKey(7)
	expected := sessionStoreTestValue(7)
	deleter, kernel := newModelSessionDeleter(t)
	kernel.put(key, expected)
	backend := newMemorySessionMap()
	store, err := newLinuxSessionStoreWithAtomicCompareDelete(
		backend, key.Generation, backend.identity, deleter,
	)
	if err != nil {
		t.Fatal(err)
	}
	claimLocked := make(chan struct{})
	releaseClaim := make(chan struct{})
	kernel.afterLock = func(abi.FakeTCPSessionKey) {
		close(claimLocked)
		<-releaseClaim
	}
	deleteDone := make(chan error, 1)
	go func() {
		_, err := store.DeleteEstablishedIfUnchanged(key, expected)
		deleteDone <- err
	}()
	<-claimLocked
	closeDone := make(chan error, 1)
	go func() { closeDone <- store.Close() }()
	select {
	case err := <-closeDone:
		t.Fatalf("Close bypassed admitted compare-delete: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(releaseClaim)
	if err := <-deleteDone; err != nil {
		t.Fatal(err)
	}
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	if deleted, err := store.DeleteEstablishedIfUnchanged(key, expected); deleted ||
		!errors.Is(err, ErrSessionStoreClosed) {
		t.Fatalf("post-close deleted=%t err=%v", deleted, err)
	}
}

func TestMarshalFakeTCPSessionClaimExactABI(t *testing.T) {
	key := sessionStoreTestKey(7)
	value := sessionStoreTestValue(7)
	request, err := marshalFakeTCPSessionClaim(key, value)
	if err != nil {
		t.Fatal(err)
	}
	if len(request) != 104 {
		t.Fatalf("claim request size=%d, want 104", len(request))
	}
	var decodedKey abi.FakeTCPSessionKey
	var decodedValue abi.FakeTCPSessionValue
	reader := bytes.NewReader(request)
	if err := binary.Read(reader, binary.NativeEndian, &decodedKey); err != nil {
		t.Fatal(err)
	}
	if err := binary.Read(reader, binary.NativeEndian, &decodedValue); err != nil {
		t.Fatal(err)
	}
	if decodedKey != key || decodedValue != value || reader.Len() != 0 {
		t.Fatalf("claim roundtrip key=%#v value=%#v remaining=%d", decodedKey, decodedValue, reader.Len())
	}
}

func BenchmarkFakeTCPSessionClaimModelIndependentSessions(b *testing.B) {
	kernel := newModelSessionClaimKernel()
	baseKey := sessionStoreTestKey(7)
	baseValue := sessionStoreTestValue(7)
	const sessions = 64
	for index := 0; index < sessions; index++ {
		key := baseKey
		key.RemotePort += uint16(index)
		value := baseValue
		value.SessionID += uint64(index)
		kernel.put(key, value)
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		index := 0
		for pb.Next() {
			key := baseKey
			key.RemotePort += uint16(index % sessions)
			kernel.write(key, func(value *abi.FakeTCPSessionValue) {
				value.LastSeenNanos++
			})
			index++
		}
	})
}
