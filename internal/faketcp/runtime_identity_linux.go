//go:build linux

package faketcp

import (
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
)

var (
	// ErrLinuxRuntimeIdentityCommitConsumed means this Engine identity has
	// already attempted its one permitted kernel collection commit. A new
	// Engine identity and a new collection are required even if that first
	// attempt failed before publishing an identity.
	ErrLinuxRuntimeIdentityCommitConsumed = errors.New("faketcp Linux runtime identity commit capability is consumed")

	ErrLinuxFreshCollectionReleaseNotCalled = errors.New("faketcp Linux fresh collection release was not called exactly once")
	ErrLinuxFreshCollectionReleaseConsumed  = errors.New("faketcp Linux fresh collection release capability is consumed")
)

// LinuxFreshCollectionClaim is the kernel generation owner's exclusive
// lifecycle claim for one newly created, still-unreachable collection. The
// implementation must hold its cross-process ownership claim for the entire
// callback, invoke the callback synchronously exactly once, and expose only
// the two maps from that claimed fresh collection. release is a single-use
// capability: makeReachable must invoke it as its final operation. The claim
// wrapper must return the callback result directly and perform no fallible
// release or other work after a successful callback.
type LinuxFreshCollectionRelease func() error

type LinuxFreshCollectionClaim interface {
	WithExclusiveFreshFakeTCPCollection(
		func(
			identityMap, sequenceMap *ebpf.Map,
			release LinuxFreshCollectionRelease,
		) error,
	) error
}

type linuxRuntimeIdentitySeedFunc func(
	identityMap *ebpf.Map,
	sequenceMap *ebpf.Map,
	identity RuntimeIdentity,
	possibleCPUs int,
) error

type linuxPossibleCPUFunc func() (int, error)

type linuxFreshCollectionReleaseGuard struct {
	mu sync.Mutex

	release   LinuxFreshCollectionRelease
	calls     int
	sealed    bool
	running   bool
	completed bool
	done      chan struct{}
	err       error
}

type linuxFreshCollectionCallbackGuard struct {
	mu sync.Mutex

	sealed  bool
	calls   int
	running bool
	done    chan struct{}
	err     error
}

func (guard *linuxFreshCollectionCallbackGuard) run(callback func() error) error {
	guard.mu.Lock()
	guard.calls++
	if guard.sealed {
		guard.mu.Unlock()
		return errors.New("faketcp fresh collection claim callback invoked after the claim returned")
	}
	if guard.calls != 1 {
		guard.mu.Unlock()
		return errors.New("faketcp fresh collection claim callback invoked more than once")
	}
	guard.running = true
	guard.done = make(chan struct{})
	done := guard.done
	guard.mu.Unlock()

	err := callback()
	guard.mu.Lock()
	guard.err = err
	guard.running = false
	close(done)
	guard.mu.Unlock()
	return err
}

func (guard *linuxFreshCollectionCallbackGuard) seal() (int, error) {
	guard.mu.Lock()
	guard.sealed = true
	calls := guard.calls
	done := guard.done
	running := guard.running
	guard.mu.Unlock()
	if running {
		<-done
	}
	guard.mu.Lock()
	err := guard.err
	guard.mu.Unlock()
	return calls, err
}

func (guard *linuxFreshCollectionReleaseGuard) call() error {
	guard.mu.Lock()
	guard.calls++
	if guard.sealed || guard.calls != 1 {
		err := guard.err
		guard.mu.Unlock()
		return errors.Join(ErrLinuxFreshCollectionReleaseConsumed, err)
	}
	guard.running = true
	guard.done = make(chan struct{})
	done := guard.done
	guard.mu.Unlock()

	err := guard.release()
	guard.mu.Lock()
	guard.err = err
	guard.running = false
	guard.completed = true
	close(done)
	guard.mu.Unlock()
	return err
}

func (guard *linuxFreshCollectionReleaseGuard) validate() error {
	guard.mu.Lock()
	guard.sealed = true
	calls := guard.calls
	done := guard.done
	running := guard.running
	guard.mu.Unlock()
	if running {
		<-done
	}
	guard.mu.Lock()
	err := guard.err
	completed := guard.completed
	guard.mu.Unlock()
	if calls != 1 || !completed {
		return errors.Join(
			fmt.Errorf("%w: calls=%d", ErrLinuxFreshCollectionReleaseNotCalled, calls),
			err,
		)
	}
	return err
}

// CommitLinuxGenerationReachability is the only exported path which seeds the
// experimental Linux maps. The kernel generation owner supplies an exclusive
// fresh-collection claim; that claim stays held across both the once-only seed
// and every mutation which makes the generation reachable.
func CommitLinuxGenerationReachability(
	engine *Engine,
	claim LinuxFreshCollectionClaim,
	makeReachable func(LinuxFreshCollectionRelease) error,
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
	makeReachable func(LinuxFreshCollectionRelease) error,
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

		callbackGuard := &linuxFreshCollectionCallbackGuard{}
		claimErr := claim.WithExclusiveFreshFakeTCPCollection(
			func(
				identityMap, sequenceMap *ebpf.Map,
				release LinuxFreshCollectionRelease,
			) error {
				return callbackGuard.run(func() error {
					if release == nil {
						return errors.New("faketcp fresh collection release capability is nil")
					}
					releaseGuard := &linuxFreshCollectionReleaseGuard{release: release}
					hook, err := newLinuxRuntimeIdentityPreCommit(func() error {
						return seed(identityMap, sequenceMap, engine.Identity(), cpuCount)
					})
					if err != nil {
						return err
					}
					commitErr := CommitGenerationReachability(hook, func() error {
						return makeReachable(releaseGuard.call)
					})
					return errors.Join(commitErr, releaseGuard.validate())
				})
			},
		)
		callbacks, callbackErr := callbackGuard.seal()
		if callbacks == 0 && claimErr == nil {
			callbackErr = errors.New("faketcp fresh collection claim callback was not invoked exactly once")
		} else if callbacks > 1 {
			callbackErr = errors.Join(
				callbackErr,
				fmt.Errorf("faketcp fresh collection claim callback was invoked %d times", callbacks),
			)
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
