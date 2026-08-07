//go:build linux

package dataplane

import (
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

type fakeRuntimeMapResource struct {
	fakeTCPPolicyMap
	name     string
	closeLog *[]string
	closeErr error
	closes   int
}

func (resource *fakeRuntimeMapResource) Close() error {
	resource.closes++
	if resource.closeLog != nil {
		*resource.closeLog = append(*resource.closeLog, "map:"+resource.name)
	}
	return resource.closeErr
}

type fakeOwnedSessionStore struct {
	mu       sync.Mutex
	entries  map[abi.FakeTCPSessionKey]abi.FakeTCPSessionValue
	closed   bool
	closes   int
	closeErr error
	entered  chan struct{}
	release  chan struct{}
}

type fakeRuntimeEventMapSource struct {
	mu       sync.Mutex
	bpfMap   *ebpf.Map
	cloneErr error
	closeErr error
	clones   int
	closes   int
}

type fakeRuntimeEventMapSourceFunc func() (*experimentalEventMapClone, error)

func (function fakeRuntimeEventMapSourceFunc) Clone() (*experimentalEventMapClone, error) {
	return function()
}

func (source *fakeRuntimeEventMapSource) Clone() (*experimentalEventMapClone, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.clones++
	if source.cloneErr != nil {
		return nil, source.cloneErr
	}
	return &experimentalEventMapClone{
		bpfMap: source.bpfMap,
		close: func() error {
			source.mu.Lock()
			defer source.mu.Unlock()
			source.closes++
			return source.closeErr
		},
	}, nil
}

func (source *fakeRuntimeEventMapSource) counts() (int, int) {
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.clones, source.closes
}

func (store *fakeOwnedSessionStore) InsertEstablished(
	key abi.FakeTCPSessionKey,
	value abi.FakeTCPSessionValue,
) error {
	store.waitIfBlocked()
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return errors.New("fake session backend closed")
	}
	store.entries[key] = value
	return nil
}

func (store *fakeOwnedSessionStore) LookupEstablished(
	key abi.FakeTCPSessionKey,
) (abi.FakeTCPSessionValue, bool, error) {
	store.waitIfBlocked()
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return abi.FakeTCPSessionValue{}, false, errors.New("fake session backend closed")
	}
	value, exists := store.entries[key]
	return value, exists, nil
}

func (store *fakeOwnedSessionStore) DeleteEstablishedIfUnchanged(
	key abi.FakeTCPSessionKey,
	value abi.FakeTCPSessionValue,
) (bool, error) {
	store.waitIfBlocked()
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return false, errors.New("fake session backend closed")
	}
	actual, exists := store.entries[key]
	if !exists || actual != value {
		return false, nil
	}
	delete(store.entries, key)
	return true, nil
}

func (store *fakeOwnedSessionStore) waitIfBlocked() {
	if store.entered == nil {
		return
	}
	select {
	case store.entered <- struct{}{}:
	default:
	}
	<-store.release
}

func (store *fakeOwnedSessionStore) Close() error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.closes++
	store.closed = true
	return store.closeErr
}

type runtimeTestFixture struct {
	collection   *experimentalCollectionOwner
	policyMaps   fakeTCPPolicyMaps
	programArray *memoryFakeTCPProgramArray
	xdpRuntime   *memoryFakeTCPXDPRuntime
	sessionStore *fakeOwnedSessionStore
	eventSource  *fakeRuntimeEventMapSource
	mapResources map[string]*fakeRuntimeMapResource
	programs     map[string]*fakeExperimentalOwnedProgram
	closeLog     []string
}

func newRuntimeTestFixture(t *testing.T) *runtimeTestFixture {
	t.Helper()
	policyMaps, _ := newMemoryFakeTCPPolicyMaps()
	fixture := &runtimeTestFixture{
		policyMaps:   policyMaps,
		programArray: &memoryFakeTCPProgramArray{entries: make(map[uint32]uint32)},
		xdpRuntime:   newMemoryFakeTCPXDPRuntime(),
		sessionStore: &fakeOwnedSessionStore{entries: make(map[abi.FakeTCPSessionKey]abi.FakeTCPSessionValue)},
		eventSource:  &fakeRuntimeEventMapSource{bpfMap: &ebpf.Map{}},
		mapResources: make(map[string]*fakeRuntimeMapResource),
		programs:     make(map[string]*fakeExperimentalOwnedProgram),
	}
	addMap := func(name string, backend fakeTCPPolicyMap) {
		resource := &fakeRuntimeMapResource{
			fakeTCPPolicyMap: backend, name: name, closeLog: &fixture.closeLog,
		}
		fixture.mapResources[name] = resource
	}
	addMap(fakeTCPControlPolicyMapName, policyMaps.ControlPolicies)
	addMap(fakeTCPManagedPortMapName, policyMaps.ManagedPorts)
	addMap(fakeTCPManagedIfMapName, policyMaps.ManagedInterfaces)
	dummyMap := &memoryFakeTCPPolicyMap{
		name: "dummy", entries: make(map[any]any), trace: &memoryFakeTCPPolicyTrace{},
	}
	addMap(fakeTCPSessionMapName, dummyMap)
	addMap(fakeTCPEventsMapName, dummyMap)
	addMap(fakeTCPEgressProgramArrayMapName, dummyMap)
	collectionMaps := make(map[string]experimentalMapResource, len(fixture.mapResources))
	for name, resource := range fixture.mapResources {
		collectionMaps[name] = resource
	}
	for name, id := range map[string]uint32{
		fakeTCPEgressProgramName: 8001,
		fakeTCPXDPProgramName:    8002,
	} {
		program := &fakeExperimentalOwnedProgram{
			name: name, id: id, closeLog: &fixture.closeLog,
		}
		fixture.programs[name] = program
	}
	fixture.collection = &experimentalCollectionOwner{
		maps: collectionMaps,
		programs: map[string]experimentalProgramResource{
			fakeTCPEgressProgramName: fixture.programs[fakeTCPEgressProgramName],
			fakeTCPXDPProgramName:    fixture.programs[fakeTCPXDPProgramName],
		},
		closeDone: make(chan struct{}),
	}
	return fixture
}

func (fixture *runtimeTestFixture) build(
	t *testing.T,
	generation uint64,
) (*ExperimentalFakeTCPRuntime, ExperimentalFakeTCPRuntimeHandles, error) {
	t.Helper()
	snapshot := mustFakeTCPPolicySnapshot(t, generation)
	ctx, transaction, _ := newTestFakeTCPPolicyGenerationTransaction(t, generation)
	runtime, err := buildExperimentalFakeTCPRuntime(
		ctx,
		experimentalFakeTCPRuntimeBuildOptions{
			collection:  fixture.collection,
			transaction: transaction,
			snapshot:    snapshot,
			xdpRequests: []fakeTCPXDPAttachRequest{
				{IfIndex: 3, Mode: fakeTCPXDPAttachNative},
				{IfIndex: 9, Mode: fakeTCPXDPAttachGeneric},
			},
			xdpRuntime: fixture.xdpRuntime.backend(),
			sessionFactory: func(experimentalMapResource, uint64) (ownedFakeTCPSessionStore, error) {
				return fixture.sessionStore, nil
			},
			eventSource:  fixture.eventSource,
			programArray: fixture.programArray,
		},
	)
	if err != nil {
		return nil, ExperimentalFakeTCPRuntimeHandles{}, err
	}
	handles, err := runtime.Handles()
	return runtime, handles, err
}

func TestExperimentalFakeTCPRuntimeBuildsPolicyTailCallsXDPAndHandles(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	runtime, handles, err := fixture.build(t, 91)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.Generation() != 91 || handles.Generation() != 91 || handles.SessionStore() == nil {
		t.Fatalf("runtime generation=%d handles=%d store=%v",
			runtime.Generation(), handles.Generation(), handles.SessionStore())
	}
	callbackMap := (*ebpf.Map)(nil)
	if err := handles.WithEventsMap(func(bpfMap *ebpf.Map) error {
		callbackMap = bpfMap
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	clones, closes := fixture.eventSource.counts()
	if callbackMap != fixture.eventSource.bpfMap || clones != 1 || closes != 1 {
		t.Fatalf("event constructor map=%p clones=%d closes=%d", callbackMap, clones, closes)
	}
	if fixture.programArray.entries[1] != 8001 {
		t.Fatalf("tail-call bank = %v", fixture.programArray.entries)
	}
	assertMemoryPolicyMapMatches(t, fixture.policyMaps.ControlPolicies,
		mustFakeTCPPolicySnapshot(t, 91).ControlPolicies)
	if len(fixture.xdpRuntime.attachCalls) != 2 {
		t.Fatalf("XDP attaches = %v", fixture.xdpRuntime.attachCalls)
	}

	key := sessionStoreTestKey(91)
	value := sessionStoreTestValue(91)
	if err := handles.SessionStore().InsertEstablished(key, value); err != nil {
		t.Fatal(err)
	}
	if got, exists, err := handles.SessionStore().LookupEstablished(key); err != nil || !exists || got != value {
		t.Fatalf("lookup got=%#v exists=%t error=%v", got, exists, err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if fixture.sessionStore.closes != 1 || fixture.xdpRuntime.links[3].closes != 1 ||
		fixture.xdpRuntime.links[9].closes != 1 {
		t.Fatalf("close counts session=%d xdp3=%d xdp9=%d",
			fixture.sessionStore.closes, fixture.xdpRuntime.links[3].closes,
			fixture.xdpRuntime.links[9].closes)
	}
	for name, resource := range fixture.mapResources {
		if resource.closes != 1 {
			t.Fatalf("map %s closes=%d", name, resource.closes)
		}
	}
	for name, program := range fixture.programs {
		if program.closes != 1 {
			t.Fatalf("program %s closes=%d", name, program.closes)
		}
	}
	if _, _, err := handles.SessionStore().LookupEstablished(key); !errors.Is(err, ErrExperimentalFakeTCPRuntimeClosed) {
		t.Fatalf("retained handle after runtime close error = %v", err)
	}
	if _, err := runtime.Handles(); !errors.Is(err, ErrExperimentalFakeTCPRuntimeClosed) {
		t.Fatalf("handles after close error = %v", err)
	}
	if err := handles.WithEventsMap(func(*ebpf.Map) error { return nil }); !errors.Is(err, ErrExperimentalFakeTCPRuntimeClosed) {
		t.Fatalf("retained event constructor after close error = %v", err)
	}
}

func TestGenerationFencedSessionStoreRejectsCrossGenerationWithoutBackendCall(t *testing.T) {
	backend := &fakeOwnedSessionStore{entries: make(map[abi.FakeTCPSessionKey]abi.FakeTCPSessionValue)}
	store, err := newGenerationFencedSessionStore(91, backend)
	if err != nil {
		t.Fatal(err)
	}
	key := sessionStoreTestKey(92)
	value := sessionStoreTestValue(92)
	if err := store.InsertEstablished(key, value); !errors.Is(err, ErrExperimentalFakeTCPGenerationMismatch) {
		t.Fatalf("cross-generation insert error = %v", err)
	}
	if _, _, err := store.LookupEstablished(key); !errors.Is(err, ErrExperimentalFakeTCPGenerationMismatch) {
		t.Fatalf("cross-generation lookup error = %v", err)
	}
	if deleted, err := store.DeleteEstablishedIfUnchanged(key, value); deleted ||
		!errors.Is(err, ErrExperimentalFakeTCPGenerationMismatch) {
		t.Fatalf("cross-generation delete=%t error=%v", deleted, err)
	}
	if len(backend.entries) != 0 {
		t.Fatalf("generation fence touched backend: %v", backend.entries)
	}
}

func TestGenerationFencedSessionStoreCloseWaitsForAdmittedOperation(t *testing.T) {
	backend := &fakeOwnedSessionStore{
		entries: make(map[abi.FakeTCPSessionKey]abi.FakeTCPSessionValue),
		entered: make(chan struct{}, 1), release: make(chan struct{}),
	}
	store, err := newGenerationFencedSessionStore(91, backend)
	if err != nil {
		t.Fatal(err)
	}
	operationDone := make(chan error, 1)
	go func() {
		_, _, err := store.LookupEstablished(sessionStoreTestKey(91))
		operationDone <- err
	}()
	select {
	case <-backend.entered:
	case <-time.After(time.Second):
		t.Fatal("operation did not enter backend")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- store.Close() }()
	select {
	case err := <-closeDone:
		t.Fatalf("close returned before admitted operation: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(backend.release)
	if err := <-operationDone; err != nil {
		t.Fatal(err)
	}
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	if backend.closes != 1 {
		t.Fatalf("backend close count = %d", backend.closes)
	}
}

func TestExperimentalFakeTCPRuntimeConcurrentCloseIsOnceOnly(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	wantErr := errors.New("injected session close failure")
	fixture.sessionStore.closeErr = wantErr
	runtime, _, err := fixture.build(t, 91)
	if err != nil {
		t.Fatal(err)
	}
	const callers = 24
	start := make(chan struct{})
	errs := make(chan error, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			errs <- runtime.Close()
		}()
	}
	close(start)
	wait.Wait()
	close(errs)
	for err := range errs {
		if !errors.Is(err, wantErr) {
			t.Fatalf("concurrent close error = %v", err)
		}
	}
	if fixture.sessionStore.closes != 1 {
		t.Fatalf("session close count = %d", fixture.sessionStore.closes)
	}
	for name, resource := range fixture.mapResources {
		if resource.closes != 1 {
			t.Fatalf("map %s close count = %d", name, resource.closes)
		}
	}
}

func TestExperimentalFakeTCPGenerationReloadFencesRetainedOldHandles(t *testing.T) {
	oldFixture := newRuntimeTestFixture(t)
	oldRuntime, oldHandles, err := oldFixture.build(t, 91)
	if err != nil {
		t.Fatal(err)
	}
	newFixture := newRuntimeTestFixture(t)
	newRuntime, newHandles, err := newFixture.build(t, 92)
	if err != nil {
		t.Fatal(err)
	}
	if err := oldRuntime.Close(); err != nil {
		t.Fatal(err)
	}
	if err := oldHandles.SessionStore().InsertEstablished(
		sessionStoreTestKey(91), sessionStoreTestValue(91),
	); !errors.Is(err, ErrExperimentalFakeTCPRuntimeClosed) {
		t.Fatalf("old retained handle error = %v", err)
	}
	if err := newHandles.SessionStore().InsertEstablished(
		sessionStoreTestKey(92), sessionStoreTestValue(92),
	); err != nil {
		t.Fatalf("new generation handle: %v", err)
	}
	if err := newHandles.SessionStore().InsertEstablished(
		sessionStoreTestKey(91), sessionStoreTestValue(91),
	); !errors.Is(err, ErrExperimentalFakeTCPGenerationMismatch) {
		t.Fatalf("new handle accepted old generation: %v", err)
	}
	if err := newRuntime.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestExperimentalFakeTCPRuntimeFailureRollsBackOwnedPrefixAndClosesAll(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	wantErr := errors.New("injected second XDP attach failure")
	fixture.xdpRuntime.attachErrs[9] = wantErr
	runtime, _, err := fixture.build(t, 91)
	if runtime != nil || !errors.Is(err, wantErr) {
		t.Fatalf("runtime=%#v error=%v", runtime, err)
	}
	if fixture.xdpRuntime.links[3].closes != 1 {
		t.Fatalf("first XDP link close count = %d", fixture.xdpRuntime.links[3].closes)
	}
	if len(fixture.programArray.entries) != 0 ||
		!slices.Equal(fixture.programArray.deletes, []uint32{1}) {
		t.Fatalf("program-array rollback entries=%v deletes=%v",
			fixture.programArray.entries, fixture.programArray.deletes)
	}
	if fixture.sessionStore.closes != 1 {
		t.Fatalf("session close count = %d", fixture.sessionStore.closes)
	}
	for name, resource := range fixture.mapResources {
		if resource.closes != 1 {
			t.Fatalf("map %s close count = %d", name, resource.closes)
		}
	}
}

func TestExperimentalFakeTCPRuntimeValidatesXDPPolicySetBeforeMutation(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	snapshot := mustFakeTCPPolicySnapshot(t, 91)
	ctx, transaction, _ := newTestFakeTCPPolicyGenerationTransaction(t, 91)
	runtime, err := buildExperimentalFakeTCPRuntime(
		ctx,
		experimentalFakeTCPRuntimeBuildOptions{
			collection: fixture.collection, transaction: transaction, snapshot: snapshot,
			xdpRequests: []fakeTCPXDPAttachRequest{{IfIndex: 3, Mode: fakeTCPXDPAttachNative}},
			xdpRuntime:  fixture.xdpRuntime.backend(), programArray: fixture.programArray,
			sessionFactory: func(experimentalMapResource, uint64) (ownedFakeTCPSessionStore, error) {
				return fixture.sessionStore, nil
			},
			eventSource: fixture.eventSource,
		},
	)
	if runtime != nil || err == nil || !strings.Contains(err.Error(), "do not match managed interfaces") {
		t.Fatalf("runtime=%#v error=%v", runtime, err)
	}
	if len(fixture.xdpRuntime.probeCalls) != 0 || len(fixture.programArray.inserts) != 0 ||
		fixture.sessionStore.closes != 0 {
		t.Fatalf("preflight reached mutation: probes=%v programs=%v session closes=%d",
			fixture.xdpRuntime.probeCalls, fixture.programArray.inserts, fixture.sessionStore.closes)
	}
	for name, resource := range fixture.mapResources {
		if resource.closes != 1 {
			t.Fatalf("owned map %s was not closed on preflight failure", name)
		}
	}
}

func TestExperimentalRuntimeClosePreservesAllResourceErrors(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	sessionErr := errors.New("session close")
	xdpErr := errors.New("XDP close")
	mapErr := errors.New("map close")
	fixture.sessionStore.closeErr = sessionErr
	fixture.xdpRuntime.links[3] = &fakeOwnedXDPLink{
		ifindex: 3, programID: 8002, closeErrs: []error{xdpErr},
	}
	fixture.mapResources[fakeTCPSessionMapName].closeErr = mapErr
	runtime, _, err := fixture.build(t, 91)
	if err != nil {
		t.Fatal(err)
	}
	err = runtime.Close()
	for _, want := range []error{sessionErr, xdpErr, mapErr} {
		if !errors.Is(err, want) {
			t.Fatalf("close error %v does not contain %v", err, want)
		}
	}
	if retryErr := runtime.Close(); retryErr == nil || retryErr.Error() != err.Error() {
		t.Fatalf("retained close error = %v, want %v", retryErr, err)
	}
}

func TestExperimentalEventsMapConstructorClosesCloneAndPreservesBothErrors(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	runtime, handles, err := fixture.build(t, 91)
	if err != nil {
		t.Fatal(err)
	}
	callbackErr := errors.New("reader constructor failure")
	cloneCloseErr := errors.New("events clone close failure")
	fixture.eventSource.closeErr = cloneCloseErr
	err = handles.WithEventsMap(func(*ebpf.Map) error { return callbackErr })
	if !errors.Is(err, callbackErr) || !errors.Is(err, cloneCloseErr) {
		t.Fatalf("event constructor error = %v", err)
	}
	clones, closes := fixture.eventSource.counts()
	if clones != 1 || closes != 1 {
		t.Fatalf("event clone counts clones=%d closes=%d", clones, closes)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestExperimentalEventsMapConstructorClosesPartialCloneOnSourceFailure(t *testing.T) {
	wantErr := errors.New("injected event-map clone failure")
	closes := 0
	source := fakeRuntimeEventMapSourceFunc(func() (*experimentalEventMapClone, error) {
		return &experimentalEventMapClone{
			bpfMap: &ebpf.Map{},
			close: func() error {
				closes++
				return nil
			},
		}, wantErr
	})
	events, err := newGenerationFencedEventMap(91, source)
	if err != nil {
		t.Fatal(err)
	}
	err = events.withMap(func(*ebpf.Map) error {
		t.Fatal("clone failure reached callback")
		return nil
	})
	if !errors.Is(err, wantErr) || closes != 1 {
		t.Fatalf("partial clone error=%v closes=%d", err, closes)
	}
}

func TestExperimentalEventsMapConstructorClosesIncompleteClone(t *testing.T) {
	closes := 0
	source := fakeRuntimeEventMapSourceFunc(func() (*experimentalEventMapClone, error) {
		return &experimentalEventMapClone{
			close: func() error {
				closes++
				return nil
			},
		}, nil
	})
	events, err := newGenerationFencedEventMap(91, source)
	if err != nil {
		t.Fatal(err)
	}
	err = events.withMap(func(*ebpf.Map) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "incomplete clone") || closes != 1 {
		t.Fatalf("incomplete clone error=%v closes=%d", err, closes)
	}
}

func TestExperimentalRuntimeCloseWaitsForEventMapConstructor(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	runtime, handles, err := fixture.build(t, 91)
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	callbackDone := make(chan error, 1)
	go func() {
		callbackDone <- handles.WithEventsMap(func(*ebpf.Map) error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered
	closeDone := make(chan error, 1)
	go func() { closeDone <- runtime.Close() }()
	select {
	case err := <-closeDone:
		t.Fatalf("runtime close returned during event constructor: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if fixture.mapResources[fakeTCPEventsMapName].closes != 0 {
		t.Fatal("collection closed events map during admitted constructor")
	}
	close(release)
	if err := <-callbackDone; err != nil {
		t.Fatal(err)
	}
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	if fixture.mapResources[fakeTCPEventsMapName].closes != 1 {
		t.Fatalf("events map close count = %d", fixture.mapResources[fakeTCPEventsMapName].closes)
	}
}

func TestFakeTCPPolicyFailureReleaseRequiresExactClosedCollectionOwner(t *testing.T) {
	snapshot := mustFakeTCPPolicySnapshot(t, 91)
	ctx, transaction, _ := newTestFakeTCPPolicyGenerationTransaction(t, 91)
	policyMaps, _ := newMemoryFakeTCPPolicyMaps()
	stage, err := transaction.Stage(ctx, policyMaps, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	owner := &experimentalCollectionOwner{
		maps:      make(map[string]experimentalMapResource),
		programs:  make(map[string]experimentalProgramResource),
		closeDone: make(chan struct{}),
	}
	otherOwner := &experimentalCollectionOwner{
		maps:      make(map[string]experimentalMapResource),
		programs:  make(map[string]experimentalProgramResource),
		closeDone: make(chan struct{}),
	}
	if err := transaction.bindStageCollectionOwner(ctx, stage, owner); err != nil {
		t.Fatal(err)
	}
	policyMaps.ManagedInterfaces.(*memoryFakeTCPPolicyMap).failNextDelete =
		errors.New("injected terminal map rollback failure")
	if err := transaction.Rollback(ctx, stage); err == nil {
		t.Fatal("injected policy rollback unexpectedly succeeded")
	}
	otherProof, err := otherOwner.closeAndReleaseProof()
	if err != nil {
		t.Fatal(err)
	}
	if err := transaction.releaseStageAfterCollectionClose(ctx, stage, otherProof); err == nil ||
		!strings.Contains(err.Error(), "does not match") {
		t.Fatalf("unrelated collection proof error = %v", err)
	}
	proof, err := owner.closeAndReleaseProof()
	if err != nil {
		t.Fatal(err)
	}
	if err := transaction.releaseStageAfterCollectionClose(ctx, stage, proof); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Close(); err != nil {
		t.Fatal(err)
	}
}

var _ fakeTCPPolicyMap = (*fakeRuntimeMapResource)(nil)
var _ experimentalMapResource = (*fakeRuntimeMapResource)(nil)
var _ ownedFakeTCPSessionStore = (*fakeOwnedSessionStore)(nil)
var _ experimentalEventMapSource = (*fakeRuntimeEventMapSource)(nil)

func sessionStoreTestKey(generation uint64) abi.FakeTCPSessionKey {
	return abi.FakeTCPSessionKey{Generation: generation}
}

func sessionStoreTestValue(generation uint64) abi.FakeTCPSessionValue {
	return abi.FakeTCPSessionValue{Generation: generation}
}
