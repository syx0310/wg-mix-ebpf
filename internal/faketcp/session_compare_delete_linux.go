//go:build linux

package faketcp

import (
	"errors"

	"github.com/cilium/ebpf"
	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

type ciliumLinuxSessionClaimKernel struct {
	sessionMap   *ebpf.Map
	claimProgram *ebpf.Program
}

// NewLinuxAtomicSessionCompareDeleter proves that claimProgram references
// exactly bpfMap by immutable kernel map ID before returning a usable backend.
// The caller retains ownership and must keep both resources live until its
// LinuxSessionStore has closed.
func NewLinuxAtomicSessionCompareDeleter(
	bpfMap *ebpf.Map,
	claimProgram *ebpf.Program,
	expected SessionMapIdentity,
) (*LinuxAtomicSessionCompareDeleter, error) {
	if bpfMap == nil {
		return nil, errors.New("faketcp compare-delete session map is nil")
	}
	if claimProgram == nil {
		return nil, errors.New("faketcp compare-delete claim program is nil")
	}
	return newLinuxAtomicSessionCompareDeleter(
		&ciliumLinuxSessionClaimKernel{sessionMap: bpfMap, claimProgram: claimProgram},
		expected,
	)
}

func (kernel *ciliumLinuxSessionClaimKernel) SessionMapIdentity() (SessionMapIdentity, error) {
	if kernel == nil || kernel.sessionMap == nil {
		return SessionMapIdentity{}, errors.New("faketcp compare-delete session map is nil")
	}
	return inspectCiliumSessionMapIdentity(kernel.sessionMap)
}

func (kernel *ciliumLinuxSessionClaimKernel) ClaimProgramBinding() (ebpf.ProgramType, []uint32, error) {
	if kernel == nil || kernel.claimProgram == nil {
		return ebpf.UnspecifiedProgram, nil, errors.New("faketcp compare-claim program is nil")
	}
	info, err := kernel.claimProgram.Info()
	if err != nil {
		return ebpf.UnspecifiedProgram, nil, err
	}
	ids, available := info.MapIDs()
	if !available {
		return info.Type, nil, errors.New("faketcp compare-claim program map IDs are unavailable")
	}
	result := make([]uint32, len(ids))
	for index, id := range ids {
		result[index] = uint32(id)
	}
	return info.Type, result, nil
}

func (kernel *ciliumLinuxSessionClaimKernel) RunClaim(request []byte) (uint32, error) {
	if kernel == nil || kernel.claimProgram == nil {
		return 0, errors.New("faketcp compare-claim program is nil")
	}
	return kernel.claimProgram.Run(&ebpf.RunOptions{Data: request})
}

func (kernel *ciliumLinuxSessionClaimKernel) DeleteSession(key abi.FakeTCPSessionKey) error {
	if kernel == nil || kernel.sessionMap == nil {
		return errors.New("faketcp compare-delete session map is nil")
	}
	return kernel.sessionMap.Delete(key)
}
