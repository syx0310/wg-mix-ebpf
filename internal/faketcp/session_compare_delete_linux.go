//go:build linux

package faketcp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

const (
	fakeTCPSessionClaimMalformed uint32 = iota
	fakeTCPSessionClaimAbsent
	fakeTCPSessionClaimDifferent
	fakeTCPSessionClaimed

	fakeTCPSessionClaimRequestSize = fakeTCPSessionMapKeySize + fakeTCPSessionMapValueSize
)

type linuxSessionClaimKernel interface {
	SessionMapIdentity() (SessionMapIdentity, error)
	ClaimProgramBinding() (ebpf.ProgramType, []uint32, error)
	RunClaim([]byte) (uint32, error)
	DeleteSession(abi.FakeTCPSessionKey) error
}

type ciliumLinuxSessionClaimKernel struct {
	sessionMap   *ebpf.Map
	claimProgram *ebpf.Program
}

// LinuxAtomicSessionCompareDeleter borrows one map and one claim program from
// the same experimental collection. The runtime's generation fence closes the
// store before it closes that collection, so no admitted operation can race
// either borrowed FD's Close. The store serialises Insert and compare-delete;
// production creates exactly one store for the collection, and BPF has no
// session-map insertion site. Consequently no same-key Insert can occur
// between a successful claim and its exact delete in the supported lifecycle.
type LinuxAtomicSessionCompareDeleter struct {
	kernel   linuxSessionClaimKernel
	identity SessionMapIdentity
}

var _ AtomicSessionCompareDeleter = (*LinuxAtomicSessionCompareDeleter)(nil)

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

func newLinuxAtomicSessionCompareDeleter(
	kernel linuxSessionClaimKernel,
	expected SessionMapIdentity,
) (*LinuxAtomicSessionCompareDeleter, error) {
	if kernel == nil {
		return nil, errors.New("faketcp compare-delete kernel backend is nil")
	}
	if err := validateSessionMapIdentity(expected); err != nil {
		return nil, fmt.Errorf("invalid compare-delete map identity: %w", err)
	}
	deleter := &LinuxAtomicSessionCompareDeleter{kernel: kernel, identity: expected}
	if err := deleter.validateBinding(); err != nil {
		return nil, err
	}
	return deleter, nil
}

func (deleter *LinuxAtomicSessionCompareDeleter) CompareDeleteEstablished(
	identity SessionMapIdentity,
	key abi.FakeTCPSessionKey,
	expected abi.FakeTCPSessionValue,
) (bool, error) {
	if deleter == nil || deleter.kernel == nil {
		return false, errors.New("faketcp compare-delete backend is nil")
	}
	if identity != deleter.identity {
		return false, fmt.Errorf(
			"%w for compare-delete: bound %#v, requested %#v",
			ErrSessionMapIdentityChanged, deleter.identity, identity,
		)
	}
	if err := validateBoundSessionKey(key, expected.Generation); err != nil {
		return false, err
	}
	if err := validateEstablishedSessionValue(expected, key.Generation); err != nil {
		return false, err
	}
	if err := deleter.validateBinding(); err != nil {
		return false, err
	}

	request, err := marshalFakeTCPSessionClaim(key, expected)
	if err != nil {
		return false, err
	}
	result, err := deleter.kernel.RunClaim(request)
	if err != nil {
		return false, fmt.Errorf("run faketcp kernel compare-claim: %w", err)
	}
	switch result {
	case fakeTCPSessionClaimAbsent, fakeTCPSessionClaimDifferent:
		return false, nil
	case fakeTCPSessionClaimMalformed:
		return false, errors.New("faketcp kernel rejected a locally validated compare-claim")
	case fakeTCPSessionClaimed:
		// The ESTABLISHED -> DELETE_CLAIMED transition already linearised the
		// operation. Revalidate both FDs before the non-conditional reclaim;
		// any drift preserves the tombstone and fails closed.
		if err := deleter.validateBinding(); err != nil {
			return false, err
		}
		if err := deleter.kernel.DeleteSession(key); err != nil {
			return false, fmt.Errorf("delete claimed faketcp session: %w", err)
		}
		return true, nil
	default:
		return false, fmt.Errorf("faketcp kernel compare-claim returned unknown status %d", result)
	}
}

func (deleter *LinuxAtomicSessionCompareDeleter) validateBinding() error {
	actual, err := deleter.kernel.SessionMapIdentity()
	if err != nil {
		return fmt.Errorf("inspect compare-delete session map: %w", err)
	}
	if actual != deleter.identity {
		return fmt.Errorf(
			"%w for compare-delete: expected %#v, got %#v",
			ErrSessionMapIdentityChanged, deleter.identity, actual,
		)
	}
	programType, mapIDs, err := deleter.kernel.ClaimProgramBinding()
	if err != nil {
		return fmt.Errorf("inspect faketcp compare-claim program: %w", err)
	}
	if programType != ebpf.SchedCLS {
		return fmt.Errorf("faketcp compare-claim program type is %s, want SchedCLS", programType)
	}
	if len(mapIDs) != 1 || mapIDs[0] != deleter.identity.ID {
		return fmt.Errorf(
			"faketcp compare-claim program map IDs are %v, want only %d",
			mapIDs, deleter.identity.ID,
		)
	}
	return nil
}

func marshalFakeTCPSessionClaim(
	key abi.FakeTCPSessionKey,
	expected abi.FakeTCPSessionValue,
) ([]byte, error) {
	var request bytes.Buffer
	request.Grow(int(fakeTCPSessionClaimRequestSize))
	if err := binary.Write(&request, binary.NativeEndian, key); err != nil {
		return nil, fmt.Errorf("encode faketcp compare-claim key: %w", err)
	}
	if err := binary.Write(&request, binary.NativeEndian, expected); err != nil {
		return nil, fmt.Errorf("encode faketcp compare-claim expected value: %w", err)
	}
	if request.Len() != int(fakeTCPSessionClaimRequestSize) {
		return nil, fmt.Errorf(
			"encoded faketcp compare-claim has %d bytes, want %d",
			request.Len(), fakeTCPSessionClaimRequestSize,
		)
	}
	return request.Bytes(), nil
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
