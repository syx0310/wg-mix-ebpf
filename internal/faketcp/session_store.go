package faketcp

import (
	"errors"
	"fmt"
	"reflect"
	"sync"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

const (
	// Linux exposes at most the first 15 bytes of the ELF map name through
	// BPF_OBJ_GET_INFO_BY_FD.
	fakeTCPSessionKernelMapName = "faketcp_session"
	fakeTCPSessionMapTypeHash   = uint32(1)
	fakeTCPSessionMapKeySize    = uint32(24)
	fakeTCPSessionMapValueSize  = uint32(40)
	fakeTCPSessionMapMaxEntries = uint32(16384)
)

var (
	// ErrSessionMapIdentityChanged means the file descriptor no longer names
	// the exact map which was admitted when the store was constructed.
	ErrSessionMapIdentityChanged = errors.New("faketcp session map identity changed")

	// ErrSessionCompareDeleteUnavailable is returned when the observed value
	// still equals the delete candidate. Linux BPF_MAP_DELETE_ELEM has no
	// compare operand, while BPF_MAP_LOOKUP_AND_DELETE_ELEM removes the value
	// before userspace can compare it. Deleting in either case could erase a
	// concurrent TC/XDP sequence or activity update, so this backend keeps the
	// entry and leaves the activation capability disabled.
	ErrSessionCompareDeleteUnavailable = errors.New("atomic faketcp session compare-delete is unavailable")

	errSessionMapKeyNotExist = errors.New("faketcp session map key does not exist")
)

// SessionMapIdentity is the immutable kernel identity and complete map ABI to
// which a LinuxSessionStore is bound. MapType is the raw BPF map type number.
type SessionMapIdentity struct {
	ID         uint32
	Name       string
	MapType    uint32
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	Flags      uint32
}

// sessionMapBackend is deliberately narrower than ebpf.Map. In particular it
// exposes no delete primitive, making an unsafe lookup-then-delete impossible
// in this slice while the kernel lacks atomic compare-delete.
type sessionMapBackend interface {
	Identity() (SessionMapIdentity, error)
	InsertNoExist(abi.FakeTCPSessionKey, abi.FakeTCPSessionValue) error
	Lookup(abi.FakeTCPSessionKey, *abi.FakeTCPSessionValue) error
}

// LinuxSessionStore transfers an established session to the eBPF fast path
// exactly once. All later writes belong to TC/XDP. Userspace serialisation
// protects this store's calls, while the immutable map ID and ABI checks bind
// every call to the originally admitted kernel map.
type LinuxSessionStore struct {
	mu         sync.Mutex
	backend    sessionMapBackend
	generation uint64
	identity   SessionMapIdentity
}

var _ SessionStore = (*LinuxSessionStore)(nil)

func newLinuxSessionStore(
	backend sessionMapBackend,
	generation uint64,
	expected SessionMapIdentity,
) (*LinuxSessionStore, error) {
	if sessionMapBackendIsNil(backend) {
		return nil, errors.New("faketcp session map backend is nil")
	}
	if generation == 0 {
		return nil, errors.New("faketcp session store generation must be non-zero")
	}
	if err := validateSessionMapIdentity(expected); err != nil {
		return nil, fmt.Errorf("invalid expected faketcp session map identity: %w", err)
	}
	actual, err := backend.Identity()
	if err != nil {
		return nil, fmt.Errorf("inspect faketcp session map identity: %w", err)
	}
	if err := validateSessionMapIdentity(actual); err != nil {
		return nil, fmt.Errorf("invalid actual faketcp session map identity: %w", err)
	}
	if actual != expected {
		return nil, fmt.Errorf(
			"%w during construction: expected %#v, got %#v",
			ErrSessionMapIdentityChanged,
			expected,
			actual,
		)
	}
	return &LinuxSessionStore{
		backend:    backend,
		generation: generation,
		identity:   expected,
	}, nil
}

func sessionMapBackendIsNil(backend sessionMapBackend) bool {
	if backend == nil {
		return true
	}
	value := reflect.ValueOf(backend)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func validateSessionMapIdentity(identity SessionMapIdentity) error {
	if identity.ID == 0 {
		return errors.New("map ID is unavailable or zero")
	}
	if identity.Name != fakeTCPSessionKernelMapName {
		return fmt.Errorf("kernel map name is %q, want %q", identity.Name, fakeTCPSessionKernelMapName)
	}
	if identity.MapType != fakeTCPSessionMapTypeHash {
		return fmt.Errorf("map type is %d, want BPF_MAP_TYPE_HASH", identity.MapType)
	}
	if identity.KeySize != fakeTCPSessionMapKeySize ||
		identity.ValueSize != fakeTCPSessionMapValueSize ||
		identity.MaxEntries != fakeTCPSessionMapMaxEntries ||
		identity.Flags != 0 {
		return fmt.Errorf(
			"map ABI is key=%d value=%d max=%d flags=%d, want key=%d value=%d max=%d flags=0",
			identity.KeySize,
			identity.ValueSize,
			identity.MaxEntries,
			identity.Flags,
			fakeTCPSessionMapKeySize,
			fakeTCPSessionMapValueSize,
			fakeTCPSessionMapMaxEntries,
		)
	}
	return nil
}

func (store *LinuxSessionStore) InsertEstablished(
	key abi.FakeTCPSessionKey,
	value abi.FakeTCPSessionValue,
) error {
	if store == nil {
		return errors.New("faketcp session store is nil")
	}
	if err := validateBoundSessionKey(key, store.generation); err != nil {
		return err
	}
	if err := validateEstablishedSessionValue(value, store.generation); err != nil {
		return err
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.validateMapBindingLocked(); err != nil {
		return err
	}
	if err := store.backend.InsertNoExist(key, value); err != nil {
		return fmt.Errorf("insert established faketcp session without overwrite: %w", err)
	}
	return nil
}

func (store *LinuxSessionStore) LookupEstablished(
	key abi.FakeTCPSessionKey,
) (abi.FakeTCPSessionValue, bool, error) {
	if store == nil {
		return abi.FakeTCPSessionValue{}, false, errors.New("faketcp session store is nil")
	}
	if err := validateBoundSessionKey(key, store.generation); err != nil {
		return abi.FakeTCPSessionValue{}, false, err
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.validateMapBindingLocked(); err != nil {
		return abi.FakeTCPSessionValue{}, false, err
	}
	return store.lookupEstablishedLocked(key)
}

func (store *LinuxSessionStore) DeleteEstablishedIfUnchanged(
	key abi.FakeTCPSessionKey,
	expected abi.FakeTCPSessionValue,
) (bool, error) {
	if store == nil {
		return false, errors.New("faketcp session store is nil")
	}
	if err := validateBoundSessionKey(key, store.generation); err != nil {
		return false, err
	}
	if err := validateEstablishedSessionValue(expected, store.generation); err != nil {
		return false, err
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.validateMapBindingLocked(); err != nil {
		return false, err
	}
	actual, found, err := store.lookupEstablishedLocked(key)
	if err != nil || !found {
		return false, err
	}
	if actual != expected {
		return false, nil
	}

	// Do not add backend.Delete here. The comparison above cannot exclude a
	// BPF write between lookup and deletion, and LookupAndDelete would remove
	// the entry before comparison. A future implementation needs a concrete
	// quiescence/ownership primitive or a kernel-side atomic operation.
	return false, fmt.Errorf(
		"%w for map ID %d generation %d; entry was preserved",
		ErrSessionCompareDeleteUnavailable,
		store.identity.ID,
		store.generation,
	)
}

func (store *LinuxSessionStore) validateMapBindingLocked() error {
	actual, err := store.backend.Identity()
	if err != nil {
		return fmt.Errorf("inspect bound faketcp session map identity: %w", err)
	}
	if actual != store.identity {
		return fmt.Errorf(
			"%w: expected %#v, got %#v",
			ErrSessionMapIdentityChanged,
			store.identity,
			actual,
		)
	}
	if err := validateSessionMapIdentity(actual); err != nil {
		return fmt.Errorf("bound faketcp session map failed ABI validation: %w", err)
	}
	return nil
}

func (store *LinuxSessionStore) lookupEstablishedLocked(
	key abi.FakeTCPSessionKey,
) (abi.FakeTCPSessionValue, bool, error) {
	var value abi.FakeTCPSessionValue
	if err := store.backend.Lookup(key, &value); err != nil {
		if errors.Is(err, errSessionMapKeyNotExist) {
			return abi.FakeTCPSessionValue{}, false, nil
		}
		return abi.FakeTCPSessionValue{}, false, fmt.Errorf("lookup established faketcp session: %w", err)
	}
	if err := validateEstablishedSessionValue(value, store.generation); err != nil {
		return abi.FakeTCPSessionValue{}, false, fmt.Errorf("invalid established faketcp session from map: %w", err)
	}
	return value, true, nil
}

func validateBoundSessionKey(key abi.FakeTCPSessionKey, generation uint64) error {
	if key.Generation != generation {
		return fmt.Errorf(
			"faketcp session key generation %d does not match store generation %d",
			key.Generation,
			generation,
		)
	}
	if key.LocalIPv4 == 0 || key.RemoteIPv4 == 0 || key.UnderlayIndex == 0 ||
		key.LocalPort == 0 || key.RemotePort == 0 {
		return errors.New("faketcp session key has a zero address, interface, or port")
	}
	return nil
}

func validateEstablishedSessionValue(value abi.FakeTCPSessionValue, generation uint64) error {
	if value.Generation != generation {
		return fmt.Errorf(
			"faketcp session value generation %d does not match store generation %d",
			value.Generation,
			generation,
		)
	}
	if value.State != abi.FakeTCPStateEstablished {
		return fmt.Errorf("faketcp session state %d is not established", value.State)
	}
	if value.Flags != 0 {
		return fmt.Errorf("faketcp session has unsupported flags %#x", value.Flags)
	}
	if value.Reserved != ([4]byte{}) {
		return errors.New("faketcp session has nonzero reserved bytes")
	}
	return nil
}
