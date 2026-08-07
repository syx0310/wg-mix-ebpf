//go:build linux

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

type linuxRuntimeIdentityMap interface {
	Info() (*ebpf.MapInfo, error)
	Update(key, value any, flags ebpf.MapUpdateFlags) error
}

// LinuxRuntimeIdentityMapBorrower is implemented by the kernel generation
// owner. Both handles are borrowed only for the synchronous callback; the hook
// never retains a raw map. The owner must provide the exact maps belonging to
// the still-unreachable generation.
type LinuxRuntimeIdentityMapBorrower interface {
	WithRuntimeIdentityMaps(func(identityMap, sequenceMap *ebpf.Map) error) error
}

type linuxRuntimeIdentityPreCommit struct {
	once sync.Once

	engine   *Engine
	borrower LinuxRuntimeIdentityMapBorrower
	seed     func(*ebpf.Map, *ebpf.Map, *Engine) error
	err      error
}

var _ GenerationPreCommit = (*linuxRuntimeIdentityPreCommit)(nil)

// NewLinuxRuntimeIdentityPreCommit returns the hook a generation transaction
// passes to CommitGenerationReachability. Preparation is once-only; a failed
// attempt is retained and can never later turn into a successful commit.
func NewLinuxRuntimeIdentityPreCommit(
	engine *Engine,
	borrower LinuxRuntimeIdentityMapBorrower,
) (GenerationPreCommit, error) {
	return newLinuxRuntimeIdentityPreCommit(engine, borrower, SeedLinuxRuntimeIdentity)
}

func newLinuxRuntimeIdentityPreCommit(
	engine *Engine,
	borrower LinuxRuntimeIdentityMapBorrower,
	seed func(*ebpf.Map, *ebpf.Map, *Engine) error,
) (GenerationPreCommit, error) {
	if engine == nil {
		return nil, errors.New("faketcp Engine is nil")
	}
	if interfaceValueIsNil(borrower) {
		return nil, errors.New("faketcp runtime identity map borrower is nil")
	}
	if seed == nil {
		return nil, errors.New("faketcp runtime identity seed function is nil")
	}
	return &linuxRuntimeIdentityPreCommit{engine: engine, borrower: borrower, seed: seed}, nil
}

func (hook *linuxRuntimeIdentityPreCommit) PrepareUnreachableGeneration() error {
	if hook == nil {
		return errors.New("faketcp runtime identity pre-commit hook is nil")
	}
	hook.once.Do(func() {
		callbacks := 0
		hook.err = hook.borrower.WithRuntimeIdentityMaps(func(identityMap, sequenceMap *ebpf.Map) error {
			callbacks++
			if callbacks != 1 {
				return errors.New("faketcp runtime identity maps callback invoked more than once")
			}
			return hook.seed(identityMap, sequenceMap, hook.engine)
		})
		if hook.err == nil && callbacks != 1 {
			hook.err = errors.New("faketcp runtime identity maps callback was not invoked exactly once")
		}
	})
	return hook.err
}

// SeedLinuxRuntimeIdentity publishes the Engine identity used by BPF events.
// The generation owner must call it while both maps are unreachable or fully
// quiesced, before attach/commit makes any FakeTCP program reachable.
//
// The identity map is first zeroed (disabling emit), every per-CPU sequence is
// reset, and the non-zero identity is written last as the single commit point.
// A failure after disable leaves emit fail-closed; this function never restores
// a prior identity whose sequence namespace may already have been reset.
func SeedLinuxRuntimeIdentity(
	identityMap *ebpf.Map,
	sequenceMap *ebpf.Map,
	engine *Engine,
) error {
	if engine == nil {
		return errors.New("faketcp Engine is nil")
	}
	possibleCPUs, err := ebpf.PossibleCPU()
	if err != nil {
		return fmt.Errorf("read possible CPUs for faketcp capture sequence: %w", err)
	}
	return seedLinuxRuntimeIdentity(identityMap, sequenceMap, engine.Identity(), possibleCPUs)
}

func seedLinuxRuntimeIdentity(
	identityMap linuxRuntimeIdentityMap,
	sequenceMap linuxRuntimeIdentityMap,
	identity RuntimeIdentity,
	possibleCPUs int,
) error {
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
