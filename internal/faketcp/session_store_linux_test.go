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
	updateErr   error
	lookupErr   error
	lookupValue abi.FakeTCPSessionValue
}

func (sessionMap *fakeCiliumSessionMap) Info() (*ebpf.MapInfo, error) {
	return nil, errors.New("Info is not used by this adapter test")
}

func (sessionMap *fakeCiliumSessionMap) Update(
	_, _ any,
	flags ebpf.MapUpdateFlags,
) error {
	sessionMap.updateFlags = flags
	return sessionMap.updateErr
}

func (sessionMap *fakeCiliumSessionMap) Lookup(_, valueOut any) error {
	if sessionMap.lookupErr != nil {
		return sessionMap.lookupErr
	}
	value := valueOut.(*abi.FakeTCPSessionValue)
	*value = sessionMap.lookupValue
	return nil
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
	if raw.updateFlags != ebpf.UpdateNoExist {
		t.Fatalf("update flags = %d, want BPF_NOEXIST", raw.updateFlags)
	}

	var got abi.FakeTCPSessionValue
	if err := adapter.Lookup(key, &got); err != nil || got != value {
		t.Fatalf("lookup got=%#v err=%v", got, err)
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

func TestLinuxSessionMapConstructorsRejectNilAndTypedNil(t *testing.T) {
	if _, err := InspectLinuxSessionMapIdentity(nil); err == nil {
		t.Fatal("nil map inspection succeeded")
	}
	if _, err := NewLinuxSessionStore(nil, 7, validSessionMapIdentity()); err == nil {
		t.Fatal("nil map constructor succeeded")
	}
	var typedNil *fakeCiliumSessionMap
	if _, err := (&ciliumSessionMap{bpfMap: typedNil}).Identity(); err == nil {
		t.Fatal("typed-nil cilium map identity succeeded")
	}
}
