//go:build linux

package faketcp

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
)

var (
	// ErrLinuxRuntimeIdentityCommitConsumed means this Engine identity has
	// already attempted its one permitted kernel collection commit. A new
	// Engine identity and a new collection are required even if that first
	// attempt failed before publishing an identity.
	ErrLinuxRuntimeIdentityCommitConsumed = errors.New("faketcp Linux runtime identity commit capability is consumed")
)

// LinuxFreshCollectionClaim is the kernel generation owner's exclusive
// lifecycle claim for one newly created, still-unreachable collection. The
// implementation must hold its cross-process ownership claim for the entire
// callback, invoke the callback synchronously exactly once, and expose only
// the two maps from that claimed fresh collection.
type LinuxFreshCollectionClaim interface {
	WithExclusiveFreshFakeTCPCollection(
		func(identityMap, sequenceMap *ebpf.Map) error,
	) error
}

type linuxRuntimeIdentitySeedFunc func(
	identityMap *ebpf.Map,
	sequenceMap *ebpf.Map,
	identity RuntimeIdentity,
	possibleCPUs int,
) error

type linuxPossibleCPUFunc func() (int, error)

// CommitLinuxGenerationReachability is the only exported path which seeds the
// experimental Linux maps. The kernel generation owner supplies an exclusive
// fresh-collection claim; that claim stays held across both the once-only seed
// and every mutation which makes the generation reachable.
func CommitLinuxGenerationReachability(
	engine *Engine,
	claim LinuxFreshCollectionClaim,
	makeReachable func() error,
) error {
	return commitLinuxGenerationReachability(
		engine,
		claim,
		makeReachable,
		ebpf.PossibleCPU,
		func(identityMap, sequenceMap *ebpf.Map, identity RuntimeIdentity, possibleCPUs int) error {
			return seedLinuxRuntimeIdentity(identityMap, sequenceMap, identity, possibleCPUs)
		},
	)
}

func commitLinuxGenerationReachability(
	engine *Engine,
	claim LinuxFreshCollectionClaim,
	makeReachable func() error,
	possibleCPUs linuxPossibleCPUFunc,
	seed linuxRuntimeIdentitySeedFunc,
) error {
	if engine == nil {
		return errors.New("faketcp Engine is nil")
	}
	if err := validateRuntimeIdentity(engine.Identity()); err != nil {
		return err
	}
	if interfaceValueIsNil(claim) {
		return errors.New("faketcp Linux fresh collection claim is nil")
	}
	if makeReachable == nil {
		return errors.New("faketcp generation reachability callback is nil")
	}
	if possibleCPUs == nil {
		return errors.New("faketcp possible CPU source is nil")
	}
	if seed == nil {
		return errors.New("faketcp runtime identity seed capability is nil")
	}

	return engine.commitRuntimeIdentityOnce(ErrLinuxRuntimeIdentityCommitConsumed, func() error {
		cpuCount, err := possibleCPUs()
		if err != nil {
			return fmt.Errorf("read possible CPUs for faketcp capture sequence: %w", err)
		}
		if cpuCount <= 0 {
			return errors.New("faketcp possible CPU count must be positive")
		}

		callbacks := 0
		var callbackErr error
		claimErr := claim.WithExclusiveFreshFakeTCPCollection(
			func(identityMap, sequenceMap *ebpf.Map) error {
				callbacks++
				if callbacks != 1 {
					callbackErr = errors.New("faketcp fresh collection claim callback invoked more than once")
					return callbackErr
				}
				hook, err := newLinuxRuntimeIdentityPreCommit(func() error {
					return seed(identityMap, sequenceMap, engine.Identity(), cpuCount)
				})
				if err != nil {
					callbackErr = err
					return err
				}
				callbackErr = CommitGenerationReachability(hook, makeReachable)
				return callbackErr
			},
		)
		if callbacks != 1 && callbackErr == nil {
			callbackErr = errors.New("faketcp fresh collection claim callback was not invoked exactly once")
		}
		if claimErr != nil && callbackErr != nil && !errors.Is(claimErr, callbackErr) {
			return errors.Join(claimErr, callbackErr)
		}
		if claimErr != nil {
			return claimErr
		}
		return callbackErr
	})
}
