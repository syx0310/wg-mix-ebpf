//go:build linux

package faketcp

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

type fakeCiliumSessionMap struct {
	updateFlags ebpf.MapUpdateFlags
	lookupFlags ebpf.MapLookupFlags
	updateErr   error
	lookupErr   error
	lookupValue abi.FakeTCPSessionValue
	closeErr    error
	closeCalls  int
}

func (sessionMap *fakeCiliumSessionMap) Info() (*ebpf.MapInfo, error) {
	return nil, errors.New("Info is not used by this adapter test")
}

func (sessionMap *fakeCiliumSessionMap) Update(
	_, value any,
	flags ebpf.MapUpdateFlags,
) error {
	sessionMap.updateFlags = flags
	if session, ok := value.(abi.FakeTCPSessionValue); ok {
		sessionMap.lookupValue = session
	}
	return sessionMap.updateErr
}

func (sessionMap *fakeCiliumSessionMap) LookupWithFlags(
	_, valueOut any,
	flags ebpf.MapLookupFlags,
) error {
	sessionMap.lookupFlags = flags
	if sessionMap.lookupErr != nil {
		return sessionMap.lookupErr
	}
	value := valueOut.(*abi.FakeTCPSessionValue)
	*value = sessionMap.lookupValue
	return nil
}

func (sessionMap *fakeCiliumSessionMap) Close() error {
	sessionMap.closeCalls++
	return sessionMap.closeErr
}

func TestCiliumSessionMapUsesNoExistAndMapsOnlyNotFound(t *testing.T) {
	if uint32(ebpf.Hash) != fakeTCPSessionMapTypeHash {
		t.Fatalf("ebpf.Hash = %d, ABI expects %d", ebpf.Hash, fakeTCPSessionMapTypeHash)
	}
	raw := &fakeCiliumSessionMap{lookupValue: sessionStoreTestValue(7)}
	adapter := &ciliumSessionMap{bpfMap: raw}
	key := sessionStoreTestKey(7)
	value := sessionStoreTestValue(7)
	if err := adapter.InsertNoExist(key, value); err != nil {
		t.Fatal(err)
	}
	if raw.updateFlags != ebpf.UpdateNoExist|ebpf.UpdateLock {
		t.Fatalf("update flags = %d, want BPF_NOEXIST|BPF_F_LOCK", raw.updateFlags)
	}

	var got abi.FakeTCPSessionValue
	if err := adapter.Lookup(key, &got); err != nil || got != value {
		t.Fatalf("lookup got=%#v err=%v", got, err)
	}
	if raw.lookupFlags != ebpf.LookupLock {
		t.Fatalf("lookup flags = %d, want BPF_F_LOCK", raw.lookupFlags)
	}
	raw.lookupErr = ebpf.ErrKeyNotExist
	if err := adapter.Lookup(key, &got); !errors.Is(err, errSessionMapKeyNotExist) ||
		!errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("not-found translation error = %v", err)
	}
	raw.lookupErr = errMemorySessionMapLookup
	if err := adapter.Lookup(key, &got); !errors.Is(err, errMemorySessionMapLookup) {
		t.Fatalf("lookup error propagation = %v", err)
	}
}

func TestCiliumSessionMapCloneAndCloseUseIndependentHandles(t *testing.T) {
	sourceRaw := &fakeCiliumSessionMap{}
	cloneRaw := &fakeCiliumSessionMap{}
	cloneAdapter := &ciliumSessionMap{bpfMap: cloneRaw}
	source := &ciliumSessionMap{
		bpfMap: sourceRaw,
		cloneMap: func() (*ciliumSessionMap, error) {
			return cloneAdapter, nil
		},
	}
	owned, err := source.Clone()
	if err != nil || owned != cloneAdapter {
		t.Fatalf("owned=%#v err=%v", owned, err)
	}
	if err := owned.Close(); err != nil {
		t.Fatal(err)
	}
	if cloneRaw.closeCalls != 1 || sourceRaw.closeCalls != 0 {
		t.Fatalf("clone close calls=%d source close calls=%d", cloneRaw.closeCalls, sourceRaw.closeCalls)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	if sourceRaw.closeCalls != 1 {
		t.Fatalf("source close calls=%d", sourceRaw.closeCalls)
	}

	cloneErr := errors.New("cilium clone failed")
	failing := &ciliumSessionMap{
		bpfMap: &fakeCiliumSessionMap{},
		cloneMap: func() (*ciliumSessionMap, error) {
			return nil, cloneErr
		},
	}
	if _, err := failing.Clone(); !errors.Is(err, cloneErr) {
		t.Fatalf("clone failure = %v", err)
	}

	returningNil := &ciliumSessionMap{
		bpfMap: &fakeCiliumSessionMap{},
		cloneMap: func() (*ciliumSessionMap, error) {
			return nil, nil
		},
	}
	if _, err := returningNil.Clone(); err == nil {
		t.Fatal("nil cilium clone accepted")
	}

	closeErr := errors.New("cilium close failed")
	closeFailingRaw := &fakeCiliumSessionMap{closeErr: closeErr}
	if err := (&ciliumSessionMap{bpfMap: closeFailingRaw}).Close(); !errors.Is(err, closeErr) {
		t.Fatalf("cilium close failure = %v", err)
	}
	if closeFailingRaw.closeCalls != 1 {
		t.Fatalf("cilium close calls=%d", closeFailingRaw.closeCalls)
	}
}

func TestCiliumSessionStoreConstructionOwnsAndCleansClone(t *testing.T) {
	identity := validSessionMapIdentity()
	newAdapter := func(raw *fakeCiliumSessionMap, observed SessionMapIdentity) *ciliumSessionMap {
		return &ciliumSessionMap{
			bpfMap: raw,
			inspectMap: func() (SessionMapIdentity, error) {
				return observed, nil
			},
		}
	}

	t.Run("caller close cannot affect store clone", func(t *testing.T) {
		sourceRaw := &fakeCiliumSessionMap{}
		cloneRaw := &fakeCiliumSessionMap{}
		cloneAdapter := newAdapter(cloneRaw, identity)
		source := &ciliumSessionMap{
			bpfMap: sourceRaw,
			cloneMap: func() (*ciliumSessionMap, error) {
				return cloneAdapter, nil
			},
		}
		store, err := newLinuxSessionStore(source, 7, identity)
		if err != nil {
			t.Fatal(err)
		}
		if store.backend != cloneAdapter {
			t.Fatal("store retained caller adapter instead of clone")
		}
		if err := source.Close(); err != nil {
			t.Fatal(err)
		}
		key := sessionStoreTestKey(7)
		value := sessionStoreTestValue(7)
		if err := store.InsertEstablished(key, value); err != nil {
			t.Fatal(err)
		}
		got, found, err := store.LookupEstablished(key)
		if err != nil || !found || got != value {
			t.Fatalf("lookup after caller close got=%#v found=%t err=%v", got, found, err)
		}
		if sourceRaw.closeCalls != 1 || cloneRaw.closeCalls != 0 {
			t.Fatalf("source close calls=%d clone close calls=%d", sourceRaw.closeCalls, cloneRaw.closeCalls)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		if cloneRaw.closeCalls != 1 {
			t.Fatalf("store clone close calls=%d", cloneRaw.closeCalls)
		}
	})

	t.Run("clone failure preserves caller", func(t *testing.T) {
		cloneErr := errors.New("constructor clone failed")
		sourceRaw := &fakeCiliumSessionMap{}
		source := &ciliumSessionMap{
			bpfMap: sourceRaw,
			cloneMap: func() (*ciliumSessionMap, error) {
				return nil, cloneErr
			},
		}
		if _, err := newLinuxSessionStore(source, 7, identity); !errors.Is(err, cloneErr) {
			t.Fatalf("constructor clone error = %v", err)
		}
		if sourceRaw.closeCalls != 0 {
			t.Fatal("clone failure closed caller handle")
		}
	})

	t.Run("identity drift closes clone", func(t *testing.T) {
		sourceRaw := &fakeCiliumSessionMap{}
		cloneRaw := &fakeCiliumSessionMap{}
		drifted := identity
		drifted.ID++
		cloneAdapter := newAdapter(cloneRaw, drifted)
		source := &ciliumSessionMap{
			bpfMap: sourceRaw,
			cloneMap: func() (*ciliumSessionMap, error) {
				return cloneAdapter, nil
			},
		}
		if _, err := newLinuxSessionStore(source, 7, identity); !errors.Is(err, ErrSessionMapIdentityChanged) {
			t.Fatalf("cloned identity drift error = %v", err)
		}
		if cloneRaw.closeCalls != 1 || sourceRaw.closeCalls != 0 {
			t.Fatalf("clone close calls=%d source close calls=%d", cloneRaw.closeCalls, sourceRaw.closeCalls)
		}
	})

	t.Run("construction failure joins clone close error", func(t *testing.T) {
		inspectErr := errors.New("cloned identity inspect failed")
		closeErr := errors.New("cloned handle close failed")
		sourceRaw := &fakeCiliumSessionMap{}
		cloneRaw := &fakeCiliumSessionMap{closeErr: closeErr}
		cloneAdapter := &ciliumSessionMap{
			bpfMap: cloneRaw,
			inspectMap: func() (SessionMapIdentity, error) {
				return SessionMapIdentity{}, inspectErr
			},
		}
		source := &ciliumSessionMap{
			bpfMap: sourceRaw,
			cloneMap: func() (*ciliumSessionMap, error) {
				return cloneAdapter, nil
			},
		}
		_, err := newLinuxSessionStore(source, 7, identity)
		if !errors.Is(err, inspectErr) || !errors.Is(err, closeErr) {
			t.Fatalf("joined construction error = %v", err)
		}
		if cloneRaw.closeCalls != 1 || sourceRaw.closeCalls != 0 {
			t.Fatalf("clone close calls=%d source close calls=%d", cloneRaw.closeCalls, sourceRaw.closeCalls)
		}
	})
}

func TestLinuxSessionMapConstructorsRejectNilAndTypedNil(t *testing.T) {
	if _, err := InspectLinuxSessionMapIdentity(nil); err == nil {
		t.Fatal("nil map inspection succeeded")
	}
	if _, err := NewLinuxSessionStore(nil, 7, validSessionMapIdentity()); err == nil {
		t.Fatal("nil map constructor succeeded")
	}
	var typedNil *fakeCiliumSessionMap
	typedNilAdapter := &ciliumSessionMap{bpfMap: typedNil}
	if _, err := typedNilAdapter.Identity(); err == nil {
		t.Fatal("typed-nil cilium map identity succeeded")
	}
	if _, err := typedNilAdapter.Clone(); err == nil {
		t.Fatal("typed-nil cilium map clone succeeded")
	}
}
