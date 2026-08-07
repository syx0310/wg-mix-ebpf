package faketcp

import (
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

const (
	fakeTCPRuntimeIdentityMapName = "faketcp_rt_id"
	fakeTCPCaptureSequenceMapName = "faketcp_cap_seq"
)

var (
	// ErrLinuxRuntimeIdentityNamespaceNotFresh means at least one persisted
	// byte or per-CPU sequence shows that this map namespace has already been
	// seeded or used. It must be replaced, never reset and reused.
	ErrLinuxRuntimeIdentityNamespaceNotFresh = errors.New("faketcp Linux runtime identity namespace is not fresh")

	// Seed is a generation-load operation, so serializing it process-wide is
	// deliberately preferable to allowing two hooks to observe the same fresh
	// maps and both perform an ABA reset. The persisted map checks below are the
	// guard after this mutex is acquired.
	linuxRuntimeIdentitySeedMu sync.Mutex
)

type linuxRuntimeIdentityMap interface {
	Info() (*ebpf.MapInfo, error)
	Lookup(key, valueOut any) error
	Update(key, value any, flags ebpf.MapUpdateFlags) error
}

type linuxRuntimeIdentityPreCommit struct {
	once sync.Once
	seed func() error
	err  error
}

var _ GenerationPreCommit = (*linuxRuntimeIdentityPreCommit)(nil)

func newLinuxRuntimeIdentityPreCommit(seed func() error) (*linuxRuntimeIdentityPreCommit, error) {
	if seed == nil {
		return nil, errors.New("faketcp runtime identity seed capability is nil")
	}
	return &linuxRuntimeIdentityPreCommit{seed: seed}, nil
}

func (hook *linuxRuntimeIdentityPreCommit) PrepareUnreachableGeneration() error {
	if hook == nil {
		return errors.New("faketcp runtime identity pre-commit hook is nil")
	}
	hook.once.Do(func() {
		hook.err = hook.seed()
	})
	return hook.err
}

// seedLinuxRuntimeIdentity is intentionally unexported and is reachable from
// production only through CommitLinuxGenerationReachability's once-only hook.
func seedLinuxRuntimeIdentity(
	identityMap linuxRuntimeIdentityMap,
	sequenceMap linuxRuntimeIdentityMap,
	identity RuntimeIdentity,
	possibleCPUs int,
) error {
	linuxRuntimeIdentitySeedMu.Lock()
	defer linuxRuntimeIdentitySeedMu.Unlock()

	if err := validateRuntimeIdentity(identity); err != nil {
		return err
	}
	if interfaceValueIsNil(identityMap) || interfaceValueIsNil(sequenceMap) {
		return errors.New("faketcp runtime identity maps are nil")
	}
	if possibleCPUs <= 0 {
		return errors.New("faketcp possible CPU count must be positive")
	}
	if err := validateRuntimeIdentityMap(
		identityMap, fakeTCPRuntimeIdentityMapName, ebpf.Array, 32,
	); err != nil {
		return err
	}
	if err := validateRuntimeIdentityMap(
		sequenceMap, fakeTCPCaptureSequenceMapName, ebpf.PerCPUArray, 8,
	); err != nil {
		return err
	}

	key := uint32(0)
	var persistedIdentity [32]byte
	if err := identityMap.Lookup(&key, &persistedIdentity); err != nil {
		return fmt.Errorf("read persisted faketcp runtime identity: %w", err)
	}
	if persistedIdentity != ([32]byte{}) {
		return fmt.Errorf("%w: identity map contains non-zero data", ErrLinuxRuntimeIdentityNamespaceNotFresh)
	}
	persistedSequences := make([]uint64, possibleCPUs)
	if err := sequenceMap.Lookup(&key, persistedSequences); err != nil {
		return fmt.Errorf("read persisted faketcp per-CPU capture sequences: %w", err)
	}
	for cpu, sequence := range persistedSequences {
		if sequence != 0 {
			return fmt.Errorf(
				"%w: capture sequence for possible CPU slot %d is %d",
				ErrLinuxRuntimeIdentityNamespaceNotFresh, cpu, sequence,
			)
		}
	}

	// The all-zero reads above prove this namespace has never published an
	// identity through this API. Keep emission disabled, reset every possible
	// CPU slot, then publish the non-zero identity as the final commit point.
	disabled := abi.FakeTCPRuntimeIdentityValue{}
	if err := identityMap.Update(&key, &disabled, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("disable faketcp event emission before identity seed: %w", err)
	}
	sequences := make([]uint64, possibleCPUs)
	if err := sequenceMap.Update(&key, sequences, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("reset faketcp per-CPU capture sequences while emission is disabled: %w", err)
	}
	committed := abi.FakeTCPRuntimeIdentityValue{
		Generation:      identity.Generation,
		Incarnation:     [16]byte(identity.Incarnation),
		EventABIVersion: abi.FakeTCPEventABIVersion,
	}
	if err := identityMap.Update(&key, &committed, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("commit faketcp runtime identity while emission is disabled: %w", err)
	}
	return nil
}

func validateRuntimeIdentityMap(
	m linuxRuntimeIdentityMap,
	wantName string,
	wantType ebpf.MapType,
	wantValueSize uint32,
) error {
	info, err := m.Info()
	if err != nil {
		return fmt.Errorf("inspect faketcp runtime map %q: %w", wantName, err)
	}
	if info.Name != wantName || info.Type != wantType || info.KeySize != 4 ||
		info.ValueSize != wantValueSize || info.MaxEntries != 1 {
		return fmt.Errorf(
			"faketcp runtime map contract mismatch: got name=%q type=%s key=%d value=%d max=%d; want name=%q type=%s key=4 value=%d max=1",
			info.Name, info.Type, info.KeySize, info.ValueSize, info.MaxEntries,
			wantName, wantType, wantValueSize,
		)
	}
	return nil
}
