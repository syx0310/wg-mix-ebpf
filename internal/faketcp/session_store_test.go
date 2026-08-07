package faketcp

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

var (
	errMemorySessionMapClosed  = errors.New("memory session map is closed")
	errMemorySessionKeyExists  = errors.New("memory session key already exists")
	errMemorySessionMapInspect = errors.New("memory session map inspect failed")
	errMemorySessionMapUpdate  = errors.New("memory session map update failed")
	errMemorySessionMapLookup  = errors.New("memory session map lookup failed")
	errMemorySessionMapClone   = errors.New("memory session map clone failed")
	errMemorySessionMapClose   = errors.New("memory session map close failed")
)

type memorySessionMap struct {
	mu sync.Mutex

	identity      SessionMapIdentity
	values        map[abi.FakeTCPSessionKey]abi.FakeTCPSessionValue
	identityErr   error
	insertErr     error
	lookupErr     error
	closed        bool
	closeErr      error
	cloneErr      error
	cloneWithErr  bool
	cloneCloseErr error
	cloneIdentity *SessionMapIdentity
	cloneTypedNil bool

	identityCalls int
	insertCalls   int
	lookupCalls   int
	cloneCalls    int
	closeCalls    int
	beforeLookup  func(*memorySessionMap, abi.FakeTCPSessionKey)
	lastClone     *clonedMemorySessionMap
}

// clonedMemorySessionMap is a handle with lifecycle independent from the
// caller-owned memorySessionMap. Both handles intentionally share map data and
// operation counters, just like dup(2) descriptors for one kernel eBPF map.
type clonedMemorySessionMap struct {
	mu sync.Mutex

	state            *memorySessionMap
	closed           bool
	closeErr         error
	closeCalls       int
	identityOverride *SessionMapIdentity
}

func newMemorySessionMap() *memorySessionMap {
	return &memorySessionMap{
		identity: validSessionMapIdentity(),
		values:   make(map[abi.FakeTCPSessionKey]abi.FakeTCPSessionValue),
	}
}

func (sessionMap *memorySessionMap) Clone() (sessionMapBackend, error) {
	sessionMap.mu.Lock()
	defer sessionMap.mu.Unlock()
	sessionMap.cloneCalls++
	if sessionMap.closed {
		return nil, errMemorySessionMapClosed
	}
	if sessionMap.cloneErr != nil && !sessionMap.cloneWithErr {
		return nil, sessionMap.cloneErr
	}
	if sessionMap.cloneTypedNil {
		var cloned *clonedMemorySessionMap
		return cloned, nil
	}
	cloned := &clonedMemorySessionMap{
		state:            sessionMap,
		closeErr:         sessionMap.cloneCloseErr,
		identityOverride: sessionMap.cloneIdentity,
	}
	sessionMap.lastClone = cloned
	if sessionMap.cloneErr != nil {
		return cloned, sessionMap.cloneErr
	}
	return cloned, nil
}

func (sessionMap *memorySessionMap) Close() error {
	sessionMap.mu.Lock()
	defer sessionMap.mu.Unlock()
	sessionMap.closeCalls++
	if sessionMap.closed {
		return sessionMap.closeErr
	}
	sessionMap.closed = true
	return sessionMap.closeErr
}

func (sessionMap *memorySessionMap) Identity() (SessionMapIdentity, error) {
	sessionMap.mu.Lock()
	defer sessionMap.mu.Unlock()
	sessionMap.identityCalls++
	if sessionMap.closed {
		return SessionMapIdentity{}, errMemorySessionMapClosed
	}
	if sessionMap.identityErr != nil {
		return SessionMapIdentity{}, sessionMap.identityErr
	}
	return sessionMap.identity, nil
}

func (sessionMap *memorySessionMap) InsertNoExist(
	key abi.FakeTCPSessionKey,
	value abi.FakeTCPSessionValue,
) error {
	sessionMap.mu.Lock()
	defer sessionMap.mu.Unlock()
	sessionMap.insertCalls++
	if sessionMap.closed {
		return errMemorySessionMapClosed
	}
	if sessionMap.insertErr != nil {
		return sessionMap.insertErr
	}
	if _, exists := sessionMap.values[key]; exists {
		return errMemorySessionKeyExists
	}
	sessionMap.values[key] = value
	return nil
}

func (sessionMap *memorySessionMap) Lookup(
	key abi.FakeTCPSessionKey,
	value *abi.FakeTCPSessionValue,
) error {
	sessionMap.mu.Lock()
	defer sessionMap.mu.Unlock()
	sessionMap.lookupCalls++
	if sessionMap.closed {
		return errMemorySessionMapClosed
	}
	if sessionMap.lookupErr != nil {
		return sessionMap.lookupErr
	}
	if hook := sessionMap.beforeLookup; hook != nil {
		sessionMap.beforeLookup = nil
		hook(sessionMap, key)
	}
	actual, found := sessionMap.values[key]
	if !found {
		return errSessionMapKeyNotExist
	}
	*value = actual
	return nil
}

func (sessionMap *memorySessionMap) putFromBPF(
	key abi.FakeTCPSessionKey,
	value abi.FakeTCPSessionValue,
) {
	sessionMap.mu.Lock()
	defer sessionMap.mu.Unlock()
	sessionMap.values[key] = value
}

func (sessionMap *memorySessionMap) value(
	key abi.FakeTCPSessionKey,
) (abi.FakeTCPSessionValue, bool) {
	sessionMap.mu.Lock()
	defer sessionMap.mu.Unlock()
	value, found := sessionMap.values[key]
	return value, found
}

func (sessionMap *memorySessionMap) setIdentity(identity SessionMapIdentity) {
	sessionMap.mu.Lock()
	defer sessionMap.mu.Unlock()
	sessionMap.identity = identity
}

func (sessionMap *memorySessionMap) close() {
	_ = sessionMap.Close()
}

func (sessionMap *memorySessionMap) clonedHandle() *clonedMemorySessionMap {
	sessionMap.mu.Lock()
	defer sessionMap.mu.Unlock()
	return sessionMap.lastClone
}

func (cloned *clonedMemorySessionMap) Clone() (sessionMapBackend, error) {
	return nil, errors.New("test cloned session map cannot be cloned again")
}

func (cloned *clonedMemorySessionMap) Close() error {
	if cloned == nil {
		return nil
	}
	cloned.mu.Lock()
	defer cloned.mu.Unlock()
	cloned.closeCalls++
	if cloned.closed {
		return cloned.closeErr
	}
	cloned.closed = true
	return cloned.closeErr
}

func (cloned *clonedMemorySessionMap) Identity() (SessionMapIdentity, error) {
	cloned.mu.Lock()
	defer cloned.mu.Unlock()
	if cloned.closed {
		return SessionMapIdentity{}, errMemorySessionMapClosed
	}
	if cloned.identityOverride != nil {
		return *cloned.identityOverride, nil
	}
	cloned.state.mu.Lock()
	defer cloned.state.mu.Unlock()
	cloned.state.identityCalls++
	if cloned.state.identityErr != nil {
		return SessionMapIdentity{}, cloned.state.identityErr
	}
	return cloned.state.identity, nil
}

func (cloned *clonedMemorySessionMap) InsertNoExist(
	key abi.FakeTCPSessionKey,
	value abi.FakeTCPSessionValue,
) error {
	cloned.mu.Lock()
	defer cloned.mu.Unlock()
	if cloned.closed {
		return errMemorySessionMapClosed
	}
	cloned.state.mu.Lock()
	defer cloned.state.mu.Unlock()
	cloned.state.insertCalls++
	if cloned.state.insertErr != nil {
		return cloned.state.insertErr
	}
	if _, exists := cloned.state.values[key]; exists {
		return errMemorySessionKeyExists
	}
	cloned.state.values[key] = value
	return nil
}

func (cloned *clonedMemorySessionMap) Lookup(
	key abi.FakeTCPSessionKey,
	value *abi.FakeTCPSessionValue,
) error {
	cloned.mu.Lock()
	defer cloned.mu.Unlock()
	if cloned.closed {
		return errMemorySessionMapClosed
	}
	cloned.state.mu.Lock()
	defer cloned.state.mu.Unlock()
	cloned.state.lookupCalls++
	if cloned.state.lookupErr != nil {
		return cloned.state.lookupErr
	}
	if hook := cloned.state.beforeLookup; hook != nil {
		cloned.state.beforeLookup = nil
		hook(cloned.state, key)
	}
	actual, found := cloned.state.values[key]
	if !found {
		return errSessionMapKeyNotExist
	}
	*value = actual
	return nil
}

func validSessionMapIdentity() SessionMapIdentity {
	return SessionMapIdentity{
		ID:         41,
		Name:       fakeTCPSessionKernelMapName,
		MapType:    fakeTCPSessionMapTypeHash,
		KeySize:    fakeTCPSessionMapKeySize,
		ValueSize:  fakeTCPSessionMapValueSize,
		MaxEntries: fakeTCPSessionMapMaxEntries,
	}
}

func sessionStoreTestKey(generation uint64) abi.FakeTCPSessionKey {
	return abi.FakeTCPSessionKey{
		Generation:    generation,
		LocalIPv4:     0x0100000a,
		RemoteIPv4:    0x0200000a,
		UnderlayIndex: 2,
		LocalPort:     31001,
		RemotePort:    443,
	}
}

func sessionStoreTestValue(generation uint64) abi.FakeTCPSessionValue {
	return abi.FakeTCPSessionValue{
		Generation:    generation,
		LastSeenNanos: 123456,
		TXSequence:    1001,
		RXSequence:    9001,
		LocalISN:      1000,
		RemoteISN:     9000,
		Window:        65535,
		State:         abi.FakeTCPStateEstablished,
	}
}

func newTestLinuxSessionStore(t *testing.T) (*LinuxSessionStore, *memorySessionMap) {
	t.Helper()
	backend := newMemorySessionMap()
	store, err := newLinuxSessionStore(backend, 7, backend.identity)
	if err != nil {
		t.Fatal(err)
	}
	return store, backend
}

func TestSessionMapIdentityRequiresExactLinuxABI(t *testing.T) {
	valid := validSessionMapIdentity()
	if err := validateSessionMapIdentity(valid); err != nil {
		t.Fatalf("valid identity rejected: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*SessionMapIdentity)
	}{
		{name: "zero ID", mutate: func(identity *SessionMapIdentity) { identity.ID = 0 }},
		{name: "name", mutate: func(identity *SessionMapIdentity) { identity.Name = "foreign_map" }},
		{name: "type", mutate: func(identity *SessionMapIdentity) { identity.MapType++ }},
		{name: "key size", mutate: func(identity *SessionMapIdentity) { identity.KeySize++ }},
		{name: "value size", mutate: func(identity *SessionMapIdentity) { identity.ValueSize++ }},
		{name: "capacity", mutate: func(identity *SessionMapIdentity) { identity.MaxEntries++ }},
		{name: "flags", mutate: func(identity *SessionMapIdentity) { identity.Flags = 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			identity := valid
			test.mutate(&identity)
			if err := validateSessionMapIdentity(identity); err == nil {
				t.Fatalf("invalid identity accepted: %#v", identity)
			}
		})
	}
}

func TestNewLinuxSessionStoreBindsGenerationAndMapIdentity(t *testing.T) {
	identity := validSessionMapIdentity()
	t.Run("success owns only clone", func(t *testing.T) {
		backend := newMemorySessionMap()
		store, err := newLinuxSessionStore(backend, 7, identity)
		if err != nil || store.generation != 7 || store.identity != identity {
			t.Fatalf("store=%#v err=%v", store, err)
		}
		if backend.cloneCalls != 1 || backend.clonedHandle() == nil ||
			store.backend != backend.clonedHandle() || backend.closeCalls != 0 {
			t.Fatalf(
				"clone calls=%d clone=%p store backend=%p source close calls=%d",
				backend.cloneCalls,
				backend.clonedHandle(),
				store.backend,
				backend.closeCalls,
			)
		}
	})

	t.Run("nil and typed nil", func(t *testing.T) {
		if _, err := newLinuxSessionStore(nil, 7, identity); err == nil {
			t.Fatal("nil backend accepted")
		}
		var typedNil *memorySessionMap
		if _, err := newLinuxSessionStore(typedNil, 7, identity); err == nil {
			t.Fatal("typed-nil backend accepted")
		}
	})

	t.Run("pre-clone validation", func(t *testing.T) {
		backend := newMemorySessionMap()
		if _, err := newLinuxSessionStore(backend, 0, identity); err == nil {
			t.Fatal("zero generation accepted")
		}
		invalidExpected := identity
		invalidExpected.KeySize++
		if _, err := newLinuxSessionStore(backend, 7, invalidExpected); err == nil {
			t.Fatal("invalid expected ABI accepted")
		}
		if backend.cloneCalls != 0 {
			t.Fatalf("pre-clone validation cloned map %d times", backend.cloneCalls)
		}
	})

	t.Run("clone failure", func(t *testing.T) {
		backend := newMemorySessionMap()
		backend.cloneErr = errMemorySessionMapClone
		if _, err := newLinuxSessionStore(backend, 7, identity); !errors.Is(err, errMemorySessionMapClone) {
			t.Fatalf("clone error = %v", err)
		}
		if backend.lastClone != nil || backend.closeCalls != 0 {
			t.Fatal("clone failure closed the caller or produced an owned handle")
		}
	})

	t.Run("partial clone failure closes returned handle", func(t *testing.T) {
		backend := newMemorySessionMap()
		backend.cloneErr = errMemorySessionMapClone
		backend.cloneWithErr = true
		backend.cloneCloseErr = errMemorySessionMapClose
		_, err := newLinuxSessionStore(backend, 7, identity)
		if !errors.Is(err, errMemorySessionMapClone) ||
			!errors.Is(err, errMemorySessionMapClose) {
			t.Fatalf("partial clone joined error = %v", err)
		}
		clone := backend.clonedHandle()
		if clone == nil || clone.closeCalls != 1 {
			t.Fatalf("partial clone was not closed exactly once: clone=%p", clone)
		}
		if backend.closeCalls != 0 {
			t.Fatal("partial clone failure closed caller handle")
		}
	})

	t.Run("typed nil clone", func(t *testing.T) {
		backend := newMemorySessionMap()
		backend.cloneTypedNil = true
		if _, err := newLinuxSessionStore(backend, 7, identity); err == nil {
			t.Fatal("typed-nil clone accepted")
		}
		if backend.closeCalls != 0 {
			t.Fatal("typed-nil clone closed the caller handle")
		}
	})

	t.Run("cloned identity drift closes clone", func(t *testing.T) {
		backend := newMemorySessionMap()
		drifted := identity
		drifted.ID++
		backend.cloneIdentity = &drifted
		if _, err := newLinuxSessionStore(backend, 7, identity); !errors.Is(err, ErrSessionMapIdentityChanged) {
			t.Fatalf("identity drift error = %v", err)
		}
		clone := backend.clonedHandle()
		if clone == nil {
			t.Fatal("identity drift did not retain cloned-handle evidence")
		}
		if clone.closeCalls != 1 {
			t.Fatalf("failed construction clone close calls=%d", clone.closeCalls)
		}
		if backend.closeCalls != 0 {
			t.Fatal("identity drift closed caller handle")
		}
	})

	t.Run("invalid cloned ABI closes clone", func(t *testing.T) {
		backend := newMemorySessionMap()
		invalid := identity
		invalid.ValueSize++
		backend.cloneIdentity = &invalid
		if _, err := newLinuxSessionStore(backend, 7, identity); err == nil {
			t.Fatal("invalid cloned ABI accepted")
		}
		clone := backend.clonedHandle()
		if clone == nil || clone.closeCalls != 1 {
			t.Fatalf("invalid ABI clone was not closed exactly once: clone=%p", clone)
		}
		if backend.closeCalls != 0 {
			t.Fatal("invalid cloned ABI closed caller handle")
		}
	})

	t.Run("identity failure joins clone close failure", func(t *testing.T) {
		backend := newMemorySessionMap()
		backend.identityErr = errMemorySessionMapInspect
		backend.cloneCloseErr = errMemorySessionMapClose
		_, err := newLinuxSessionStore(backend, 7, identity)
		if !errors.Is(err, errMemorySessionMapInspect) ||
			!errors.Is(err, errMemorySessionMapClose) {
			t.Fatalf("joined construction error = %v", err)
		}
		clone := backend.clonedHandle()
		if clone == nil {
			t.Fatal("identity failure did not retain cloned-handle evidence")
		}
		if clone.closeCalls != 1 {
			t.Fatalf("failed construction clone close calls=%d", clone.closeCalls)
		}
		if backend.closeCalls != 0 {
			t.Fatal("construction failure closed caller handle")
		}
	})
}

func TestLinuxSessionStoreInsertsOnceAndReadsValidatedValue(t *testing.T) {
	store, backend := newTestLinuxSessionStore(t)
	key := sessionStoreTestKey(7)
	value := sessionStoreTestValue(7)
	if err := store.InsertEstablished(key, value); err != nil {
		t.Fatal(err)
	}
	got, found, err := store.LookupEstablished(key)
	if err != nil || !found || got != value {
		t.Fatalf("lookup got=%#v found=%t err=%v", got, found, err)
	}

	replacement := value
	replacement.TXSequence++
	if err := store.InsertEstablished(key, replacement); !errors.Is(err, errMemorySessionKeyExists) {
		t.Fatalf("duplicate insert error = %v", err)
	}
	if got, found := backend.value(key); !found || got != value {
		t.Fatalf("duplicate insert overwrote map: got=%#v found=%t", got, found)
	}
	if backend.insertCalls != 2 {
		t.Fatalf("insert calls = %d, want 2", backend.insertCalls)
	}

	missing := key
	missing.LocalPort++
	got, found, err = store.LookupEstablished(missing)
	if err != nil || found || got != (abi.FakeTCPSessionValue{}) {
		t.Fatalf("missing lookup got=%#v found=%t err=%v", got, found, err)
	}
}

func TestLinuxSessionStoreTransfersCompletedHandshakeToFastMap(t *testing.T) {
	backend := newMemorySessionMap()
	store, err := newLinuxSessionStore(backend, 1, backend.identity)
	if err != nil {
		t.Fatal(err)
	}
	engine, _ := testEngine(t, func(options *Options) {
		options.Store = store
	})
	flow := testFlow(31001)
	if _, err := engine.Outbound(flow, []byte{1, 2, 3, 4}); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Inbound(flow, Segment{
		Flags: FlagSYN | FlagACK, Sequence: 9000, Acknowledgement: 1001,
	}); err != nil {
		t.Fatal(err)
	}
	value, found, err := store.LookupEstablished(flow)
	if err != nil || !found || value.Generation != 1 ||
		value.State != abi.FakeTCPStateEstablished ||
		value.LocalISN != 1000 || value.RemoteISN != 9000 ||
		value.Reserved != ([4]byte{}) {
		t.Fatalf("established map value=%#v found=%t err=%v", value, found, err)
	}
	if backend.insertCalls != 1 {
		t.Fatalf("handshake inserted established state %d times, want 1", backend.insertCalls)
	}
}

func TestLinuxSessionStoreRejectsInvalidInsertBeforeMapAccess(t *testing.T) {
	validKey := sessionStoreTestKey(7)
	validValue := sessionStoreTestValue(7)
	tests := []struct {
		name   string
		mutate func(*abi.FakeTCPSessionKey, *abi.FakeTCPSessionValue)
	}{
		{name: "key generation", mutate: func(key *abi.FakeTCPSessionKey, _ *abi.FakeTCPSessionValue) { key.Generation++ }},
		{name: "local address", mutate: func(key *abi.FakeTCPSessionKey, _ *abi.FakeTCPSessionValue) { key.LocalIPv4 = 0 }},
		{name: "remote address", mutate: func(key *abi.FakeTCPSessionKey, _ *abi.FakeTCPSessionValue) { key.RemoteIPv4 = 0 }},
		{name: "interface", mutate: func(key *abi.FakeTCPSessionKey, _ *abi.FakeTCPSessionValue) { key.UnderlayIndex = 0 }},
		{name: "local port", mutate: func(key *abi.FakeTCPSessionKey, _ *abi.FakeTCPSessionValue) { key.LocalPort = 0 }},
		{name: "remote port", mutate: func(key *abi.FakeTCPSessionKey, _ *abi.FakeTCPSessionValue) { key.RemotePort = 0 }},
		{name: "value generation", mutate: func(_ *abi.FakeTCPSessionKey, value *abi.FakeTCPSessionValue) { value.Generation++ }},
		{name: "state", mutate: func(_ *abi.FakeTCPSessionKey, value *abi.FakeTCPSessionValue) { value.State = abi.FakeTCPStateSynSent }},
		{name: "flags", mutate: func(_ *abi.FakeTCPSessionKey, value *abi.FakeTCPSessionValue) { value.Flags = 1 }},
		{name: "reserved", mutate: func(_ *abi.FakeTCPSessionKey, value *abi.FakeTCPSessionValue) { value.Reserved[2] = 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, backend := newTestLinuxSessionStore(t)
			key, value := validKey, validValue
			test.mutate(&key, &value)
			if err := store.InsertEstablished(key, value); err == nil {
				t.Fatal("invalid insert accepted")
			}
			if backend.insertCalls != 0 {
				t.Fatalf("invalid insert reached map %d times", backend.insertCalls)
			}
		})
	}
}

func TestLinuxSessionStoreRejectsInvalidValuesReadFromMap(t *testing.T) {
	key := sessionStoreTestKey(7)
	valid := sessionStoreTestValue(7)
	tests := []struct {
		name   string
		mutate func(*abi.FakeTCPSessionValue)
	}{
		{name: "generation", mutate: func(value *abi.FakeTCPSessionValue) { value.Generation++ }},
		{name: "state", mutate: func(value *abi.FakeTCPSessionValue) { value.State = abi.FakeTCPStateClosing }},
		{name: "flags", mutate: func(value *abi.FakeTCPSessionValue) { value.Flags = 1 }},
		{name: "reserved", mutate: func(value *abi.FakeTCPSessionValue) { value.Reserved[0] = 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, backend := newTestLinuxSessionStore(t)
			value := valid
			test.mutate(&value)
			backend.putFromBPF(key, value)
			if _, found, err := store.LookupEstablished(key); err == nil || found {
				t.Fatalf("invalid map value found=%t err=%v", found, err)
			}
		})
	}
}

func TestLinuxSessionStoreRevalidatesIdentityAndPropagatesMapFailures(t *testing.T) {
	t.Run("identity drift", func(t *testing.T) {
		store, backend := newTestLinuxSessionStore(t)
		changed := backend.identity
		changed.ID++
		backend.setIdentity(changed)
		err := store.InsertEstablished(sessionStoreTestKey(7), sessionStoreTestValue(7))
		if !errors.Is(err, ErrSessionMapIdentityChanged) {
			t.Fatalf("identity drift error = %v", err)
		}
		if backend.insertCalls != 0 {
			t.Fatal("identity drift reached map update")
		}
	})

	t.Run("caller close does not affect owned clone", func(t *testing.T) {
		store, backend := newTestLinuxSessionStore(t)
		key := sessionStoreTestKey(7)
		value := sessionStoreTestValue(7)
		if err := store.InsertEstablished(key, value); err != nil {
			t.Fatal(err)
		}
		backend.close()
		got, found, err := store.LookupEstablished(key)
		if err != nil || !found || got != value {
			t.Fatalf("lookup after caller close got=%#v found=%t err=%v", got, found, err)
		}
		clone := backend.clonedHandle()
		if backend.closeCalls != 1 || clone == nil || clone.closeCalls != 0 {
			t.Fatalf("source close calls=%d clone=%p", backend.closeCalls, clone)
		}
	})

	t.Run("unexpected owned handle close is detected", func(t *testing.T) {
		store, backend := newTestLinuxSessionStore(t)
		clone := backend.clonedHandle()
		if clone == nil {
			t.Fatal("store did not own a cloned handle")
		}
		if err := clone.Close(); err != nil {
			t.Fatal(err)
		}
		_, _, err := store.LookupEstablished(sessionStoreTestKey(7))
		if !errors.Is(err, errMemorySessionMapClosed) {
			t.Fatalf("externally closed owned handle error = %v", err)
		}
		if backend.lookupCalls != 0 {
			t.Fatal("closed owned handle reached map lookup")
		}
	})

	t.Run("insert", func(t *testing.T) {
		store, backend := newTestLinuxSessionStore(t)
		backend.insertErr = errMemorySessionMapUpdate
		err := store.InsertEstablished(sessionStoreTestKey(7), sessionStoreTestValue(7))
		if !errors.Is(err, errMemorySessionMapUpdate) {
			t.Fatalf("insert error = %v", err)
		}
	})

	t.Run("lookup", func(t *testing.T) {
		store, backend := newTestLinuxSessionStore(t)
		backend.lookupErr = errMemorySessionMapLookup
		_, _, err := store.LookupEstablished(sessionStoreTestKey(7))
		if !errors.Is(err, errMemorySessionMapLookup) {
			t.Fatalf("lookup error = %v", err)
		}
	})
}

func TestLinuxSessionStoreCompareDeleteFailsClosedWithoutTOCTOU(t *testing.T) {
	key := sessionStoreTestKey(7)
	expected := sessionStoreTestValue(7)

	t.Run("equal value is preserved", func(t *testing.T) {
		store, backend := newTestLinuxSessionStore(t)
		backend.putFromBPF(key, expected)
		deleted, err := store.DeleteEstablishedIfUnchanged(key, expected)
		if deleted || !errors.Is(err, ErrSessionCompareDeleteUnavailable) {
			t.Fatalf("deleted=%t err=%v", deleted, err)
		}
		if got, found := backend.value(key); !found || got != expected {
			t.Fatalf("equal value was removed or changed: got=%#v found=%t", got, found)
		}
	})

	t.Run("BPF advance before comparison", func(t *testing.T) {
		store, backend := newTestLinuxSessionStore(t)
		backend.putFromBPF(key, expected)
		advanced := expected
		advanced.TXSequence += 4096
		advanced.RXSequence += 2048
		advanced.LastSeenNanos++
		backend.beforeLookup = func(locked *memorySessionMap, lookupKey abi.FakeTCPSessionKey) {
			locked.values[lookupKey] = advanced
		}
		deleted, err := store.DeleteEstablishedIfUnchanged(key, expected)
		if err != nil || deleted {
			t.Fatalf("deleted=%t err=%v", deleted, err)
		}
		if got, found := backend.value(key); !found || got != advanced {
			t.Fatalf("BPF advance was lost: got=%#v found=%t", got, found)
		}
	})

	t.Run("already absent", func(t *testing.T) {
		store, _ := newTestLinuxSessionStore(t)
		deleted, err := store.DeleteEstablishedIfUnchanged(key, expected)
		if err != nil || deleted {
			t.Fatalf("deleted=%t err=%v", deleted, err)
		}
	})

	t.Run("lookup failure", func(t *testing.T) {
		store, backend := newTestLinuxSessionStore(t)
		backend.lookupErr = errMemorySessionMapLookup
		deleted, err := store.DeleteEstablishedIfUnchanged(key, expected)
		if deleted || !errors.Is(err, errMemorySessionMapLookup) {
			t.Fatalf("deleted=%t err=%v", deleted, err)
		}
	})
}

func TestLinuxSessionStoreCloseOwnsOnlyCloneAndFailsOperationsClosed(t *testing.T) {
	t.Run("idempotent close leaves caller open", func(t *testing.T) {
		store, backend := newTestLinuxSessionStore(t)
		clone := backend.clonedHandle()
		if clone == nil {
			t.Fatal("store did not retain cloned handle")
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatalf("second close error = %v", err)
		}
		if clone.closeCalls != 1 || backend.closeCalls != 0 {
			t.Fatalf("clone close calls=%d caller close calls=%d", clone.closeCalls, backend.closeCalls)
		}

		identityCalls := backend.identityCalls
		insertCalls := backend.insertCalls
		lookupCalls := backend.lookupCalls
		key := sessionStoreTestKey(7)
		value := sessionStoreTestValue(7)
		if err := store.InsertEstablished(key, value); !errors.Is(err, ErrSessionStoreClosed) {
			t.Fatalf("closed insert error = %v", err)
		}
		if _, found, err := store.LookupEstablished(key); !errors.Is(err, ErrSessionStoreClosed) || found {
			t.Fatalf("closed lookup found=%t err=%v", found, err)
		}
		if deleted, err := store.DeleteEstablishedIfUnchanged(key, value); !errors.Is(err, ErrSessionStoreClosed) || deleted {
			t.Fatalf("closed delete deleted=%t err=%v", deleted, err)
		}
		if backend.identityCalls != identityCalls || backend.insertCalls != insertCalls ||
			backend.lookupCalls != lookupCalls {
			t.Fatalf(
				"closed operations touched backend: identity=%d/%d insert=%d/%d lookup=%d/%d",
				backend.identityCalls,
				identityCalls,
				backend.insertCalls,
				insertCalls,
				backend.lookupCalls,
				lookupCalls,
			)
		}
		if _, err := backend.Identity(); err != nil {
			t.Fatalf("store close closed caller handle: %v", err)
		}
	})

	t.Run("close error is retained without retry", func(t *testing.T) {
		backend := newMemorySessionMap()
		backend.cloneCloseErr = errMemorySessionMapClose
		store, err := newLinuxSessionStore(backend, 7, backend.identity)
		if err != nil {
			t.Fatal(err)
		}
		firstErr := store.Close()
		secondErr := store.Close()
		if !errors.Is(firstErr, errMemorySessionMapClose) ||
			!errors.Is(secondErr, errMemorySessionMapClose) {
			t.Fatalf("close errors first=%v second=%v", firstErr, secondErr)
		}
		clone := backend.clonedHandle()
		if clone == nil || clone.closeCalls != 1 {
			t.Fatalf("close failure retried or lost clone: clone=%p", clone)
		}
		if _, _, err := store.LookupEstablished(sessionStoreTestKey(7)); !errors.Is(err, ErrSessionStoreClosed) {
			t.Fatalf("store remained usable after close failure: %v", err)
		}
	})

	var nilStore *LinuxSessionStore
	if err := nilStore.Close(); err != nil {
		t.Fatalf("nil store close error = %v", err)
	}
}

func TestLinuxSessionStoreConcurrentInsertAndBPFReads(t *testing.T) {
	t.Run("no-exist insert has one winner", func(t *testing.T) {
		store, backend := newTestLinuxSessionStore(t)
		key := sessionStoreTestKey(7)
		value := sessionStoreTestValue(7)
		const workers = 32
		start := make(chan struct{})
		errorsByWorker := make(chan error, workers)
		var wait sync.WaitGroup
		for index := 0; index < workers; index++ {
			wait.Add(1)
			go func() {
				defer wait.Done()
				<-start
				errorsByWorker <- store.InsertEstablished(key, value)
			}()
		}
		close(start)
		wait.Wait()
		close(errorsByWorker)

		succeeded, existed := 0, 0
		for err := range errorsByWorker {
			switch {
			case err == nil:
				succeeded++
			case errors.Is(err, errMemorySessionKeyExists):
				existed++
			default:
				t.Fatalf("unexpected insert error: %v", err)
			}
		}
		if succeeded != 1 || existed != workers-1 || backend.insertCalls != workers {
			t.Fatalf("success=%d exists=%d insert calls=%d", succeeded, existed, backend.insertCalls)
		}
	})

	t.Run("concurrent BPF updates remain whole and validated", func(t *testing.T) {
		store, backend := newTestLinuxSessionStore(t)
		key := sessionStoreTestKey(7)
		base := sessionStoreTestValue(7)
		backend.putFromBPF(key, base)

		const iterations = 1000
		start := make(chan struct{})
		errCh := make(chan error, 3)
		var wait sync.WaitGroup
		wait.Add(3)
		go func() {
			defer wait.Done()
			<-start
			for index := 0; index < iterations; index++ {
				value := base
				value.TXSequence += uint32(index)
				value.RXSequence += uint32(index * 2)
				value.LastSeenNanos += uint64(index)
				backend.putFromBPF(key, value)
			}
		}()
		for reader := 0; reader < 2; reader++ {
			go func() {
				defer wait.Done()
				<-start
				for index := 0; index < iterations; index++ {
					value, found, err := store.LookupEstablished(key)
					if err != nil || !found || value.Generation != 7 ||
						value.State != abi.FakeTCPStateEstablished ||
						value.Reserved != ([4]byte{}) {
						errCh <- fmt.Errorf("value=%#v found=%t err=%v", value, found, err)
						return
					}
				}
			}()
		}
		close(start)
		wait.Wait()
		close(errCh)
		for err := range errCh {
			t.Fatal(err)
		}
	})

	t.Run("store close serializes with lookups", func(t *testing.T) {
		store, backend := newTestLinuxSessionStore(t)
		key := sessionStoreTestKey(7)
		backend.putFromBPF(key, sessionStoreTestValue(7))
		start := make(chan struct{})
		errCh := make(chan error, 2)
		var wait sync.WaitGroup
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			for index := 0; index < 1000; index++ {
				_, _, err := store.LookupEstablished(key)
				if err != nil && !errors.Is(err, ErrSessionStoreClosed) {
					errCh <- err
					return
				}
			}
		}()
		go func() {
			defer wait.Done()
			<-start
			if err := store.Close(); err != nil {
				errCh <- err
			}
		}()
		close(start)
		wait.Wait()
		close(errCh)
		for err := range errCh {
			t.Fatal(err)
		}
		if _, _, err := store.LookupEstablished(key); !errors.Is(err, ErrSessionStoreClosed) {
			t.Fatalf("post-close lookup error = %v", err)
		}
		clone := backend.clonedHandle()
		if clone == nil || clone.closeCalls != 1 || backend.closeCalls != 0 {
			t.Fatalf("clone=%p caller close calls=%d", clone, backend.closeCalls)
		}
	})
}

func TestNilLinuxSessionStoreFailsClosed(t *testing.T) {
	var store *LinuxSessionStore
	key := sessionStoreTestKey(7)
	value := sessionStoreTestValue(7)
	if err := store.InsertEstablished(key, value); err == nil {
		t.Fatal("nil store insert did not fail")
	}
	if _, found, err := store.LookupEstablished(key); err == nil || found {
		t.Fatalf("nil store lookup found=%t err=%v", found, err)
	}
	if deleted, err := store.DeleteEstablishedIfUnchanged(key, value); err == nil || deleted {
		t.Fatalf("nil store delete deleted=%t err=%v", deleted, err)
	}
}
