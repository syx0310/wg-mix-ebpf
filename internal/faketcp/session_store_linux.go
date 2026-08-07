//go:build linux

package faketcp

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/cilium/ebpf"
	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

type ciliumSessionMapAPI interface {
	Info() (*ebpf.MapInfo, error)
	Update(key, value any, flags ebpf.MapUpdateFlags) error
	Lookup(key, valueOut any) error
	Close() error
}

type ciliumSessionMap struct {
	bpfMap     ciliumSessionMapAPI
	cloneMap   func() (*ciliumSessionMap, error)
	inspectMap func() (SessionMapIdentity, error)
}

func wrapCiliumSessionMap(bpfMap *ebpf.Map) *ciliumSessionMap {
	sessionMap := &ciliumSessionMap{
		bpfMap: bpfMap,
		inspectMap: func() (SessionMapIdentity, error) {
			return inspectCiliumSessionMapIdentity(bpfMap)
		},
	}
	sessionMap.cloneMap = func() (*ciliumSessionMap, error) {
		cloned, err := bpfMap.Clone()
		if err != nil {
			return nil, err
		}
		if cloned == nil {
			return nil, errors.New("cilium eBPF map clone returned nil without error")
		}
		return wrapCiliumSessionMap(cloned), nil
	}
	return sessionMap
}

// InspectLinuxSessionMapIdentity returns the complete identity a caller must
// retain and pass to NewLinuxSessionStore. The constructor observes it again,
// so a different or replaced map is rejected before any map mutation.
func InspectLinuxSessionMapIdentity(bpfMap *ebpf.Map) (SessionMapIdentity, error) {
	if bpfMap == nil {
		return SessionMapIdentity{}, errors.New("faketcp session eBPF map is nil")
	}
	identity, err := wrapCiliumSessionMap(bpfMap).Identity()
	if err != nil {
		return SessionMapIdentity{}, err
	}
	if err := validateSessionMapIdentity(identity); err != nil {
		return SessionMapIdentity{}, err
	}
	return identity, nil
}

// NewLinuxSessionStore binds one generation to one exact eBPF hash map. The
// expected identity must come from the loader's admitted collection (or from
// InspectLinuxSessionMapIdentity) rather than from configuration text. As
// required by cilium/ebpf's Map contract, the caller must not race Close with
// this constructor itself. Once this function returns successfully, the
// caller may close its handle without affecting the store-owned clone.
func NewLinuxSessionStore(
	bpfMap *ebpf.Map,
	generation uint64,
	expected SessionMapIdentity,
) (*LinuxSessionStore, error) {
	if bpfMap == nil {
		return nil, errors.New("faketcp session eBPF map is nil")
	}
	return newLinuxSessionStore(wrapCiliumSessionMap(bpfMap), generation, expected)
}

func (sessionMap *ciliumSessionMap) Clone() (sessionMapBackend, error) {
	if sessionMap == nil || ciliumSessionMapAPIIsNil(sessionMap.bpfMap) {
		return nil, errors.New("clone faketcp session eBPF map: source map is nil")
	}
	if sessionMap.cloneMap == nil {
		return nil, errors.New("clone faketcp session eBPF map: clone operation is unavailable")
	}
	cloned, err := sessionMap.cloneMap()
	if err != nil {
		return nil, err
	}
	if cloned == nil || ciliumSessionMapAPIIsNil(cloned.bpfMap) {
		return nil, errors.New("clone faketcp session eBPF map: clone operation returned nil")
	}
	return cloned, nil
}

func (sessionMap *ciliumSessionMap) Close() error {
	if sessionMap == nil || ciliumSessionMapAPIIsNil(sessionMap.bpfMap) {
		return nil
	}
	return sessionMap.bpfMap.Close()
}

func (sessionMap *ciliumSessionMap) Identity() (SessionMapIdentity, error) {
	if sessionMap == nil || ciliumSessionMapAPIIsNil(sessionMap.bpfMap) {
		return SessionMapIdentity{}, errors.New("faketcp session eBPF map is nil")
	}
	if sessionMap.inspectMap != nil {
		return sessionMap.inspectMap()
	}
	return inspectCiliumSessionMapIdentity(sessionMap.bpfMap)
}

func inspectCiliumSessionMapIdentity(bpfMap ciliumSessionMapAPI) (SessionMapIdentity, error) {
	info, err := bpfMap.Info()
	if err != nil {
		return SessionMapIdentity{}, fmt.Errorf("read eBPF map info: %w", err)
	}
	id, available := info.ID()
	if !available || id == 0 {
		return SessionMapIdentity{}, errors.New("eBPF map ID is unavailable")
	}
	return SessionMapIdentity{
		ID:         uint32(id),
		Name:       info.Name,
		MapType:    uint32(info.Type),
		KeySize:    info.KeySize,
		ValueSize:  info.ValueSize,
		MaxEntries: info.MaxEntries,
		Flags:      info.Flags,
	}, nil
}

func ciliumSessionMapAPIIsNil(bpfMap ciliumSessionMapAPI) bool {
	if bpfMap == nil {
		return true
	}
	value := reflect.ValueOf(bpfMap)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (sessionMap *ciliumSessionMap) InsertNoExist(
	key abi.FakeTCPSessionKey,
	value abi.FakeTCPSessionValue,
) error {
	return sessionMap.bpfMap.Update(key, value, ebpf.UpdateNoExist)
}

func (sessionMap *ciliumSessionMap) Lookup(
	key abi.FakeTCPSessionKey,
	value *abi.FakeTCPSessionValue,
) error {
	err := sessionMap.bpfMap.Lookup(key, value)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("%w: %w", errSessionMapKeyNotExist, err)
	}
	return err
}
