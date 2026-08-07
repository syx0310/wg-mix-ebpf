//go:build linux

package dataplane

import (
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/cilium/ebpf"
)

type fakeExperimentalOwnedMap struct {
	name     string
	mu       sync.Mutex
	closeLog *[]string
	closeErr error
	closes   int
}

func (*fakeExperimentalOwnedMap) Lookup(any, any) error                      { return ebpf.ErrKeyNotExist }
func (*fakeExperimentalOwnedMap) Update(any, any, ebpf.MapUpdateFlags) error { return nil }
func (*fakeExperimentalOwnedMap) Delete(any) error                           { return nil }

func (resource *fakeExperimentalOwnedMap) Close() error {
	resource.mu.Lock()
	defer resource.mu.Unlock()
	resource.closes++
	*resource.closeLog = append(*resource.closeLog, "map:"+resource.name)
	return resource.closeErr
}

type fakeExperimentalOwnedProgram struct {
	name     string
	id       uint32
	mu       sync.Mutex
	closeLog *[]string
	closeErr error
	closes   int
}

func (resource *fakeExperimentalOwnedProgram) ID() (uint32, error) { return resource.id, nil }
func (*fakeExperimentalOwnedProgram) kernelProgram() *ebpf.Program { return nil }

func (resource *fakeExperimentalOwnedProgram) Close() error {
	resource.mu.Lock()
	defer resource.mu.Unlock()
	resource.closes++
	*resource.closeLog = append(*resource.closeLog, "program:"+resource.name)
	return resource.closeErr
}

func TestExperimentalCollectionOwnerConcurrentCloseRetainsOnlyFailedResources(t *testing.T) {
	var closeLog []string
	mapA := &fakeExperimentalOwnedMap{name: "a", closeLog: &closeLog}
	mapBErr := errors.New("injected map close failure")
	mapB := &fakeExperimentalOwnedMap{name: "b", closeLog: &closeLog, closeErr: mapBErr}
	programA := &fakeExperimentalOwnedProgram{name: "a", id: 1, closeLog: &closeLog}
	programBErr := errors.New("injected program close failure")
	programB := &fakeExperimentalOwnedProgram{name: "b", id: 2, closeLog: &closeLog, closeErr: programBErr}
	owner := &experimentalCollectionOwner{
		maps: map[string]experimentalMapResource{
			"b": mapB,
			"a": mapA,
		},
		programs: map[string]experimentalProgramResource{
			"b": programB,
			"a": programA,
		},
		closeDone: make(chan struct{}),
	}

	const callers = 24
	errs := make(chan error, callers)
	start := make(chan struct{})
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			errs <- owner.Close()
		}()
	}
	close(start)
	wait.Wait()
	close(errs)
	for err := range errs {
		if !errors.Is(err, mapBErr) || !errors.Is(err, programBErr) {
			t.Fatalf("concurrent close error = %v, want both injected errors", err)
		}
	}

	if len(closeLog) < 4 || !slices.Equal(
		closeLog[:4], []string{"program:a", "program:b", "map:a", "map:b"},
	) {
		t.Fatalf("close order = %v", closeLog)
	}
	for name, closes := range map[string]int{
		"map-a": mapA.closes, "program-a": programA.closes,
	} {
		if closes != 1 {
			t.Fatalf("successful sibling %s close count = %d, want 1", name, closes)
		}
	}
	if mapB.closes == 0 || programB.closes == 0 {
		t.Fatalf("failed resources were not attempted: map=%d program=%d", mapB.closes, programB.closes)
	}
	mapBAttempts := mapB.closes
	programBAttempts := programB.closes
	if owner.isClosed() {
		t.Fatal("owner with failed resources reported closed")
	}
	if _, err := owner.mapResource("a"); !errors.Is(err, errExperimentalCollectionClosed) {
		t.Fatalf("map accessor after close error = %v", err)
	}
	if _, err := owner.programResource("a"); !errors.Is(err, errExperimentalCollectionClosed) {
		t.Fatalf("program accessor after close error = %v", err)
	}

	mapB.closeErr = nil
	programB.closeErr = nil
	if err := owner.Close(); err != nil {
		t.Fatalf("retry Close: %v", err)
	}
	if !owner.isClosed() {
		t.Fatal("owner did not close after failed resources converged")
	}
	for name, closes := range map[string]int{
		"map-a": mapA.closes, "program-a": programA.closes,
	} {
		if closes != 1 {
			t.Fatalf("successful sibling %s was closed again: %d", name, closes)
		}
	}
	if mapB.closes != mapBAttempts+1 || programB.closes != programBAttempts+1 {
		t.Fatalf(
			"failed resource retries map=%d/%d program=%d/%d",
			mapB.closes, mapBAttempts+1, programB.closes, programBAttempts+1,
		)
	}
}

func TestExperimentalCollectionOwnerRejectsMissingResourceWithoutClosing(t *testing.T) {
	owner := &experimentalCollectionOwner{
		maps:      map[string]experimentalMapResource{},
		programs:  map[string]experimentalProgramResource{},
		closeDone: make(chan struct{}),
	}
	if _, err := owner.mapResource("missing"); err == nil {
		t.Fatal("missing map was accepted")
	}
	if _, err := owner.programResource("missing"); err == nil {
		t.Fatal("missing program was accepted")
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
}
