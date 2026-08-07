//go:build linux

package dataplane

import (
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/cilium/ebpf"
)

var errExperimentalCollectionClosed = errors.New("experimental FakeTCP collection is closed")

type experimentalMapResource interface {
	fakeTCPPolicyMap
	Close() error
}

type experimentalProgramResource interface {
	ID() (uint32, error)
	Close() error
	kernelProgram() *ebpf.Program
}

type liveExperimentalProgram struct {
	program *ebpf.Program
}

func (program *liveExperimentalProgram) ID() (uint32, error) {
	if program == nil || program.program == nil {
		return 0, errors.New("experimental FakeTCP program is nil")
	}
	info, err := program.program.Info()
	if err != nil {
		return 0, fmt.Errorf("inspect experimental FakeTCP program: %w", err)
	}
	id, ok := info.ID()
	if !ok || id == 0 {
		return 0, errors.New("experimental FakeTCP program has no stable kernel ID")
	}
	return uint32(id), nil
}

func (program *liveExperimentalProgram) Close() error {
	if program == nil || program.program == nil {
		return nil
	}
	return program.program.Close()
}

func (program *liveExperimentalProgram) kernelProgram() *ebpf.Program {
	if program == nil {
		return nil
	}
	return program.program
}

// experimentalCollectionOwner is the only owner of every map and program in
// one unpinned experimental collection. Accessors return borrowed resources:
// callers must not close them and must not use them after Close starts.
//
// The owner closes each resource itself instead of calling Collection.Close,
// whose error-less API would hide FD close failures. A first Close permanently
// fences borrowed access, but a failed resource remains owned and can be
// retried. Successfully closed siblings are removed before the next attempt.
type experimentalCollectionOwner struct {
	mu sync.Mutex

	maps                      map[string]experimentalMapResource
	programs                  map[string]experimentalProgramResource
	shutdown                  bool
	closing                   bool
	closed                    bool
	freshRuntimeClaimConsumed bool
	closeErr                  error
	closeDone                 chan struct{}
}

type experimentalCollectionReleaseProof struct {
	owner *experimentalCollectionOwner
}

func newExperimentalCollectionOwner(collection *ebpf.Collection) (*experimentalCollectionOwner, error) {
	if collection == nil {
		return nil, errors.New("experimental FakeTCP collection is nil")
	}
	owner := &experimentalCollectionOwner{
		maps:      make(map[string]experimentalMapResource, len(collection.Maps)),
		programs:  make(map[string]experimentalProgramResource, len(collection.Programs)),
		closeDone: make(chan struct{}),
	}
	for name, bpfMap := range collection.Maps {
		if bpfMap == nil {
			return nil, fmt.Errorf("experimental FakeTCP collection map %q is nil", name)
		}
	}
	for name, program := range collection.Programs {
		if program == nil {
			return nil, fmt.Errorf("experimental FakeTCP collection program %q is nil", name)
		}
	}
	for name, bpfMap := range collection.Maps {
		owner.maps[name] = bpfMap
	}
	for name, program := range collection.Programs {
		owner.programs[name] = &liveExperimentalProgram{program: program}
	}
	// Ownership moved out of ebpf.Collection. Leaving these maps empty makes a
	// later accidental Collection.Close harmless instead of a double-close.
	collection.Maps = nil
	collection.Programs = nil
	return owner, nil
}

func (owner *experimentalCollectionOwner) mapResource(name string) (experimentalMapResource, error) {
	if owner == nil {
		return nil, errExperimentalCollectionClosed
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.shutdown || owner.closing || owner.closed {
		return nil, errExperimentalCollectionClosed
	}
	resource := owner.maps[name]
	if resource == nil {
		return nil, fmt.Errorf("experimental FakeTCP collection is missing map %q", name)
	}
	return resource, nil
}

func (owner *experimentalCollectionOwner) programResource(name string) (experimentalProgramResource, error) {
	if owner == nil {
		return nil, errExperimentalCollectionClosed
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.shutdown || owner.closing || owner.closed {
		return nil, errExperimentalCollectionClosed
	}
	resource := owner.programs[name]
	if resource == nil {
		return nil, fmt.Errorf("experimental FakeTCP collection is missing program %q", name)
	}
	return resource, nil
}

func (owner *experimentalCollectionOwner) Close() error {
	if owner == nil {
		return nil
	}
	owner.mu.Lock()
	if owner.closed {
		owner.mu.Unlock()
		return nil
	}
	if owner.closing {
		done := owner.closeDone
		owner.mu.Unlock()
		<-done
		owner.mu.Lock()
		err := owner.closeErr
		owner.mu.Unlock()
		return err
	}
	owner.shutdown = true
	owner.closing = true
	owner.closeDone = make(chan struct{})
	done := owner.closeDone
	maps := owner.maps
	programs := owner.programs
	owner.maps = nil
	owner.programs = nil
	owner.mu.Unlock()

	remainingMaps, remainingPrograms, err := closeExperimentalResources(maps, programs)

	owner.mu.Lock()
	owner.maps = remainingMaps
	owner.programs = remainingPrograms
	owner.closeErr = err
	owner.closed = len(remainingMaps) == 0 && len(remainingPrograms) == 0
	owner.closing = false
	close(done)
	owner.mu.Unlock()
	return err
}

// isClosed reports whether every exact resource has completed Close. A failed
// attempt leaves this false so the unique owner remains a retry capability.
func (owner *experimentalCollectionOwner) isClosed() bool {
	if owner == nil {
		return true
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	return owner.closed
}

func (owner *experimentalCollectionOwner) closeAndReleaseProof() (
	*experimentalCollectionReleaseProof,
	error,
) {
	if owner == nil {
		return nil, errExperimentalCollectionClosed
	}
	err := owner.Close()
	owner.mu.Lock()
	closed := owner.closed
	owner.mu.Unlock()
	if !closed {
		return nil, errors.Join(err, errors.New("experimental FakeTCP collection did not finish closing"))
	}
	return &experimentalCollectionReleaseProof{owner: owner}, err
}

func closeExperimentalResources(
	maps map[string]experimentalMapResource,
	programs map[string]experimentalProgramResource,
) (
	map[string]experimentalMapResource,
	map[string]experimentalProgramResource,
	error,
) {
	mapNames := make([]string, 0, len(maps))
	for name := range maps {
		mapNames = append(mapNames, name)
	}
	sort.Strings(mapNames)
	programNames := make([]string, 0, len(programs))
	for name := range programs {
		programNames = append(programNames, name)
	}
	sort.Strings(programNames)

	remainingMaps := make(map[string]experimentalMapResource)
	remainingPrograms := make(map[string]experimentalProgramResource)
	var errs []error
	for _, name := range programNames {
		if err := programs[name].Close(); err != nil {
			remainingPrograms[name] = programs[name]
			errs = append(errs, fmt.Errorf("close experimental FakeTCP program %s: %w", name, err))
		}
	}
	for _, name := range mapNames {
		if err := maps[name].Close(); err != nil {
			remainingMaps[name] = maps[name]
			errs = append(errs, fmt.Errorf("close experimental FakeTCP map %s: %w", name, err))
		}
	}
	return remainingMaps, remainingPrograms, errors.Join(errs...)
}
