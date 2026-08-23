package faketcp

import (
	"errors"
	"sync"
)

// RuntimeDomain is the immutable identity and allocation domain shared by the
// Engines in one kernel generation. Its fields are deliberately opaque: a
// caller may create per-WireGuard Engines, but cannot split their incarnation,
// session-ID sequence, or once-only kernel collection commit capability.
type RuntimeDomain struct {
	state *runtimeDomainState
}

type runtimeDomainState struct {
	identity              RuntimeIdentity
	runtimeIdentityCommit *runtimeIdentityCommitState
	sessionIDs            *sessionIDAllocator
}

type sessionIDAllocator struct {
	mu   sync.Mutex
	next uint64
}

// NewRuntimeDomain creates one fresh userspace lifetime for generation.
func NewRuntimeDomain(generation uint64) (*RuntimeDomain, error) {
	if generation == 0 {
		return nil, errors.New("faketcp runtime domain generation must be non-zero")
	}
	incarnation, err := newRuntimeIncarnation()
	if err != nil {
		return nil, err
	}
	return &RuntimeDomain{state: &runtimeDomainState{
		identity: RuntimeIdentity{
			Generation:  generation,
			Incarnation: incarnation,
		},
		runtimeIdentityCommit: &runtimeIdentityCommitState{},
		sessionIDs:            &sessionIDAllocator{},
	}}, nil
}

// Identity returns the single generation/incarnation pair owned by domain.
func (domain *RuntimeDomain) Identity() RuntimeIdentity {
	if domain == nil || domain.state == nil {
		return RuntimeIdentity{}
	}
	return domain.state.identity
}

// NewEngine creates an independent quota, ledger, queue, and session owner in
// domain. Options.Generation must name the domain generation exactly.
func (domain *RuntimeDomain) NewEngine(options Options) (*Engine, error) {
	if domain == nil || domain.state == nil {
		return nil, errors.New("faketcp runtime domain is nil")
	}
	return newEngine(options, domain.state)
}

func (allocator *sessionIDAllocator) allocate() (uint64, error) {
	if allocator == nil {
		return 0, errors.New("faketcp session ID allocator is unavailable")
	}
	allocator.mu.Lock()
	defer allocator.mu.Unlock()
	if allocator.next == ^uint64(0) {
		return 0, errors.New("faketcp session ID space is exhausted")
	}
	allocator.next++
	return allocator.next, nil
}
