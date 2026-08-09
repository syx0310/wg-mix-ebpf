//go:build linux

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/syx0310/wg-mix-ebpf/internal/abi"
	"github.com/syx0310/wg-mix-ebpf/internal/control"
	"github.com/syx0310/wg-mix-ebpf/internal/faketcp"
	"github.com/syx0310/wg-mix-ebpf/internal/lockfile"
)

type fakeRuntimeMapResource struct {
	fakeTCPPolicyMap
	name     string
	closeLog *[]string
	closeErr error
	closes   int
	bpfMap   *ebpf.Map
}

func (resource *fakeRuntimeMapResource) Close() error {
	resource.closes++
	if resource.closeLog != nil {
		*resource.closeLog = append(*resource.closeLog, "map:"+resource.name)
	}
	return resource.closeErr
}

func (resource *fakeRuntimeMapResource) linuxMap() *ebpf.Map {
	if resource == nil {
		return nil
	}
	return resource.bpfMap
}

type fakeOwnedSessionStore struct {
	mu       sync.Mutex
	entries  map[abi.FakeTCPSessionKey]abi.FakeTCPSessionValue
	closed   bool
	closes   int
	closeErr error
	entered  chan struct{}
	release  chan struct{}
	closeLog *[]string
}

type fakeExperimentalSlowPath struct {
	mu sync.Mutex

	engine         *faketcp.Engine
	runErr         error
	stopErr        error
	closeErr       error
	runs           int
	stops          int
	closes         int
	closeLog       *[]string
	lifecycleTrace *[]string
	// closeRelease models ControllerRuntime.Close waiting for an admitted raw
	// writer before the outer runtime may detach any dataplane owner.
	closeStarted   chan struct{}
	closeRelease   <-chan struct{}
	closeStartOnce sync.Once
}

func (slowPath *fakeExperimentalSlowPath) Run(context.Context) error {
	slowPath.mu.Lock()
	defer slowPath.mu.Unlock()
	slowPath.runs++
	return slowPath.runErr
}

func (slowPath *fakeExperimentalSlowPath) RequestStop() error {
	slowPath.mu.Lock()
	defer slowPath.mu.Unlock()
	slowPath.stops++
	return slowPath.stopErr
}

func (slowPath *fakeExperimentalSlowPath) Close() error {
	slowPath.mu.Lock()
	defer slowPath.mu.Unlock()
	slowPath.closes++
	if slowPath.closeLog != nil {
		*slowPath.closeLog = append(*slowPath.closeLog, "slow-path")
	}
	if slowPath.lifecycleTrace != nil {
		*slowPath.lifecycleTrace = append(*slowPath.lifecycleTrace, "slow-close")
	}
	if slowPath.closeStarted != nil {
		slowPath.closeStartOnce.Do(func() { close(slowPath.closeStarted) })
	}
	if slowPath.closeRelease != nil {
		<-slowPath.closeRelease
	}
	return slowPath.closeErr
}

func (slowPath *fakeExperimentalSlowPath) counts() (runs, stops, closes int) {
	slowPath.mu.Lock()
	defer slowPath.mu.Unlock()
	return slowPath.runs, slowPath.stops, slowPath.closes
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
) (faketcp.SessionDeleteResult, error) {
	store.waitIfBlocked()
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return faketcp.SessionDeleteDifferent, errors.New("fake session backend closed")
	}
	actual, exists := store.entries[key]
	if !exists {
		return faketcp.SessionDeleteAbsent, nil
	}
	if actual != value {
		return faketcp.SessionDeleteDifferent, nil
	}
	delete(store.entries, key)
	return faketcp.SessionDeleteRemoved, nil
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
	if store.closeLog != nil {
		*store.closeLog = append(*store.closeLog, "session")
	}
	return store.closeErr
}

type runtimeTestFixture struct {
	collection      *experimentalCollectionOwner
	policyMaps      fakeTCPPolicyMaps
	policyTrace     *memoryFakeTCPPolicyTrace
	programArray    *memoryFakeTCPProgramArray
	xdpRuntime      *memoryFakeTCPXDPRuntime
	sessionStore    *fakeOwnedSessionStore
	slowPath        *fakeExperimentalSlowPath
	eventSource     *fakeRuntimeEventMapSource
	mapResources    map[string]*fakeRuntimeMapResource
	programs        map[string]*fakeExperimentalOwnedProgram
	closeLog        []string
	activationTrace []string
	commitEngine    *faketcp.Engine
	commitCalls     int
	retainedRelease faketcp.LinuxFreshCollectionRelease
	lastCoreStage   *fakeExperimentalCoreStage
	lastTCStage     *fakeExperimentalTCStage
	sessionMapArg   experimentalMapResource
	sessionClaimArg experimentalProgramResource
	sessionGenArg   uint64
}

type fakeExperimentalCoreStage struct {
	trace             *[]string
	commitErr         error
	deactivateErr     error
	closeErr          error
	commits           int
	deactivates       int
	closes            int
	active            bool
	deactivateStarted chan struct{}
	deactivateOnce    sync.Once
}

func (stage *fakeExperimentalCoreStage) Deactivate() error {
	if !stage.active {
		return nil
	}
	if stage.deactivateStarted != nil {
		stage.deactivateOnce.Do(func() { close(stage.deactivateStarted) })
	}
	stage.deactivates++
	*stage.trace = append(*stage.trace, "core-deactivate")
	if stage.deactivateErr == nil {
		stage.active = false
	}
	return stage.deactivateErr
}

func (stage *fakeExperimentalCoreStage) CommitControl() error {
	stage.commits++
	*stage.trace = append(*stage.trace, "core-commit")
	if stage.commitErr == nil {
		stage.active = true
	}
	return stage.commitErr
}

func (stage *fakeExperimentalCoreStage) Close() error {
	stage.closes++
	*stage.trace = append(*stage.trace, "core-close")
	return stage.closeErr
}

type fakeExperimentalTCStage struct {
	trace    *[]string
	closeErr error
	closes   int
}

func (stage *fakeExperimentalTCStage) Close() error {
	stage.closes++
	*stage.trace = append(*stage.trace, "tc-close")
	return stage.closeErr
}

func newRuntimeTestFixture(t *testing.T) *runtimeTestFixture {
	t.Helper()
	policyMaps, policyTrace := newMemoryFakeTCPPolicyMaps()
	fixture := &runtimeTestFixture{
		policyMaps:   policyMaps,
		policyTrace:  policyTrace,
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
	addMap(fakeTCPStatsMapName, dummyMap)
	addMap(fakeTCPEgressProgramArrayMapName, dummyMap)
	addMap(fakeTCPRuntimeIDMapName, dummyMap)
	addMap(fakeTCPCaptureSeqMapName, dummyMap)
	for _, name := range []string{
		"control_map", "profile_map", "cipher_map", "underlay_config_map",
		"managed_fwmark_map", "egress_rule_map", "ingress_listener_map",
		"icmp_listener_map", "xor_egress_programs", "xor_ingress_programs",
	} {
		addMap(name, dummyMap)
	}
	fixture.mapResources[fakeTCPRuntimeIDMapName].bpfMap = &ebpf.Map{}
	fixture.mapResources[fakeTCPCaptureSeqMapName].bpfMap = &ebpf.Map{}
	fixture.mapResources[fakeTCPStatsMapName].bpfMap = &ebpf.Map{}
	collectionMaps := make(map[string]experimentalMapResource, len(fixture.mapResources))
	for name, resource := range fixture.mapResources {
		collectionMaps[name] = resource
	}
	for name, id := range map[string]uint32{
		fakeTCPEgressProgramName:       8001,
		fakeTCPXDPProgramName:          8002,
		fakeTCPSessionClaimProgramName: 8005,
		ingressFilterName:              8003,
		egressFilterName:               8004,
	} {
		program := &fakeExperimentalOwnedProgram{
			name: name, id: id, closeLog: &fixture.closeLog,
		}
		fixture.programs[name] = program
	}
	nextProgramID := uint32(8100)
	for _, binding := range xorTailCallBindings {
		for _, name := range binding.programNames {
			program := &fakeExperimentalOwnedProgram{
				name: name, id: nextProgramID, closeLog: &fixture.closeLog,
			}
			fixture.programs[name] = program
			nextProgramID++
		}
	}
	collectionPrograms := make(map[string]experimentalProgramResource, len(fixture.programs))
	for name, program := range fixture.programs {
		collectionPrograms[name] = program
	}
	fixture.collection = &experimentalCollectionOwner{
		maps:      collectionMaps,
		programs:  collectionPrograms,
		closeDone: make(chan struct{}),
	}
	fixture.sessionStore.closeLog = &fixture.closeLog
	fixture.slowPath = &fakeExperimentalSlowPath{
		closeLog: &fixture.closeLog, lifecycleTrace: &fixture.activationTrace,
	}
	fixture.programArray.events = &fixture.activationTrace
	fixture.xdpRuntime.events = &fixture.activationTrace
	fixture.policyTrace.externalEvents = &fixture.activationTrace
	return fixture
}

func runtimeTestEngineOptions(generation uint64) faketcp.Options {
	return faketcp.Options{
		Generation: generation, SessionCapacity: 8,
		MaxHalfOpenSessions: 4, MaxHalfOpenPerSource: 2,
		SYNRateInterval: time.Second, SYNBurst: 4, SYNBurstPerSource: 2,
		SYNSourceLedgerCapacity: 8, SYNSourceLedgerTTL: 10 * time.Second,
		MaxPendingFlows: 4, MaxPendingPacketsPerFlow: 2, MaxPendingBytes: 64,
		HandshakeTimeout: time.Second, HandshakeRetries: 2,
		KeepaliveInterval: 5 * time.Second, IdleTimeout: 20 * time.Second,
		Now: time.Now, MonotonicClock: faketcp.LinuxMonotonicClock{},
		InitialSequence: func() uint32 { return 1000 },
	}
}

func (fixture *runtimeTestFixture) slowPathFactory(
	engine *faketcp.Engine,
	eventsMap *ebpf.Map,
	statsMap *ebpf.Map,
) (experimentalSlowPath, error) {
	if eventsMap != fixture.eventSource.bpfMap {
		return nil, errors.New("slow-path factory received unrelated events map")
	}
	if statsMap != fixture.mapResources[fakeTCPStatsMapName].bpfMap {
		return nil, errors.New("slow-path factory received unrelated stats map")
	}
	fixture.slowPath.engine = engine
	return fixture.slowPath, nil
}

func (fixture *runtimeTestFixture) commitGeneration(
	engine *faketcp.Engine,
	claim faketcp.LinuxFreshCollectionClaim,
	makeReachable func(faketcp.LinuxFreshCollectionRelease) error,
) error {
	fixture.commitCalls++
	fixture.commitEngine = engine
	return claim.WithExclusiveFreshFakeTCPCollection(func(
		identityMap, sequenceMap *ebpf.Map,
		release faketcp.LinuxFreshCollectionRelease,
	) error {
		if identityMap != fixture.mapResources[fakeTCPRuntimeIDMapName].bpfMap ||
			sequenceMap != fixture.mapResources[fakeTCPCaptureSeqMapName].bpfMap {
			return errors.New("fresh collection exposed unrelated runtime maps")
		}
		fixture.retainedRelease = release
		fixture.activationTrace = append(fixture.activationTrace, "seed")
		return makeReachable(func() error {
			fixture.activationTrace = append(fixture.activationTrace, "release")
			return release()
		})
	})
}

func (fixture *runtimeTestFixture) buildOptions(
	transaction *fakeTCPPolicyGenerationTransaction,
) experimentalFakeTCPRuntimeBuildOptions {
	generation := transaction.policyGeneration()
	attachState := fakeTCPPolicyTestState()
	baseline, err := abi.FromStateWithGeneration(attachState, generation)
	if err != nil {
		panic(fmt.Sprintf("build runtime test baseline: %v", err))
	}
	return experimentalFakeTCPRuntimeBuildOptions{
		collection: fixture.collection, transaction: transaction,
		baselineSnapshot: baseline,
		attachState:      attachState,
		xdpRequests: []fakeTCPXDPAttachRequest{
			{IfIndex: 3, Mode: fakeTCPXDPAttachNative},
			{IfIndex: 9, Mode: fakeTCPXDPAttachGeneric},
		},
		xdpRuntime:     fixture.xdpRuntime.backend(),
		xdpRequirement: fakeTCPXDPAllowSelectedModeTestOnly,
		sessionFactory: func(sessionMap experimentalMapResource, claimProgram experimentalProgramResource, generation uint64) (ownedFakeTCPSessionStore, error) {
			fixture.sessionMapArg = sessionMap
			fixture.sessionClaimArg = claimProgram
			fixture.sessionGenArg = generation
			return fixture.sessionStore, nil
		},
		eventSource:      fixture.eventSource,
		programArray:     fixture.programArray,
		engineOptions:    runtimeTestEngineOptions(generation),
		slowPathFactory:  fixture.slowPathFactory,
		commitGeneration: fixture.commitGeneration,
		coreStageFactory: func(
			context.Context,
			experimentalCoreResources,
			*abi.Snapshot,
		) (experimentalCoreStageOwner, error) {
			fixture.activationTrace = append(fixture.activationTrace, "core-stage")
			stage := &fakeExperimentalCoreStage{trace: &fixture.activationTrace}
			fixture.lastCoreStage = stage
			return stage, nil
		},
		tcStageFactory: func(
			_ context.Context,
			_ *control.State,
			_, _ experimentalProgramResource,
			commit func() error,
		) (experimentalTCStageOwner, error) {
			fixture.activationTrace = append(fixture.activationTrace, "tc-stage")
			stage := &fakeExperimentalTCStage{trace: &fixture.activationTrace}
			fixture.lastTCStage = stage
			if err := commit(); err != nil {
				return stage, err
			}
			return stage, nil
		},
	}
}

func (fixture *runtimeTestFixture) build(
	t *testing.T,
	generation uint64,
) (*ExperimentalFakeTCPRuntime, ExperimentalFakeTCPRuntimeHandles, error) {
	t.Helper()
	ctx, transaction, _ := newTestFakeTCPPolicyGenerationTransaction(t, generation)
	runtime, err := buildExperimentalFakeTCPRuntime(
		ctx,
		fixture.buildOptions(transaction),
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
	if fixture.sessionMapArg != fixture.mapResources[fakeTCPSessionMapName] ||
		fixture.sessionClaimArg != fixture.programs[fakeTCPSessionClaimProgramName] ||
		fixture.sessionGenArg != 91 {
		t.Fatalf("session factory map=%v claim=%v generation=%d",
			fixture.sessionMapArg, fixture.sessionClaimArg, fixture.sessionGenArg)
	}
	if runtime.Identity() != handles.Identity() || runtime.Identity().Generation != 91 {
		t.Fatalf("runtime identity=%#v handles identity=%#v", runtime.Identity(), handles.Identity())
	}
	if fixture.commitCalls != 1 || fixture.commitEngine == nil ||
		fixture.commitEngine != fixture.slowPath.engine ||
		fixture.commitEngine != runtime.state.engine ||
		fixture.commitEngine.Identity() != runtime.Identity() {
		t.Fatalf("commit Engine=%p slow-path Engine=%p calls=%d identity=%#v",
			fixture.commitEngine, fixture.slowPath.engine, fixture.commitCalls, runtime.Identity())
	}
	coreStageIndex := slices.Index(fixture.activationTrace, "core-stage")
	programInsertIndex := slices.Index(fixture.activationTrace, "program-insert")
	xdpAttachIndex := slices.Index(fixture.activationTrace, "xdp-attach")
	tcStageIndex := slices.Index(fixture.activationTrace, "tc-stage")
	policyUpdateIndex := slices.Index(fixture.activationTrace, "policy:update:faketcp_control_policy_map")
	coreCommitIndex := slices.Index(fixture.activationTrace, "core-commit")
	releaseIndex := slices.Index(fixture.activationTrace, "release")
	coreCommitCount := 0
	for _, event := range fixture.activationTrace {
		if event == "core-commit" {
			coreCommitCount++
		}
	}
	if len(fixture.activationTrace) < 2 || fixture.activationTrace[0] != "seed" ||
		coreStageIndex <= 0 || programInsertIndex <= coreStageIndex ||
		xdpAttachIndex <= programInsertIndex || tcStageIndex <= xdpAttachIndex ||
		policyUpdateIndex <= tcStageIndex || coreCommitIndex <= policyUpdateIndex ||
		releaseIndex <= coreCommitIndex || releaseIndex != len(fixture.activationTrace)-1 ||
		coreCommitCount != 1 {
		t.Fatalf("activation order = %v", fixture.activationTrace)
	}
	if lateErr := fixture.retainedRelease(); !errors.Is(lateErr, errExperimentalFreshCollectionReleaseConsumed) {
		t.Fatalf("retained collection release error = %v", lateErr)
	}
	if fixture.commitCalls != 1 {
		t.Fatalf("retained release repeated commit: calls=%d", fixture.commitCalls)
	}
	if err := runtime.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := runtime.RequestStop(); err != nil {
		t.Fatal(err)
	}
	callbackMap := (*ebpf.Map)(nil)
	if err := handles.WithEventsMap(func(bpfMap *ebpf.Map) error {
		callbackMap = bpfMap
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	clones, closes := fixture.eventSource.counts()
	if callbackMap != fixture.eventSource.bpfMap || clones != 2 || closes != 2 {
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
	if runs, stops, closes := fixture.slowPath.counts(); runs != 1 || stops != 1 || closes != 1 {
		t.Fatalf("slow-path runs=%d stops=%d closes=%d", runs, stops, closes)
	}
	if len(fixture.closeLog) == 0 || fixture.closeLog[0] != "slow-path" {
		t.Fatalf("runtime close order = %v", fixture.closeLog)
	}
	sessionClose := slices.Index(fixture.closeLog, "session")
	claimClose := slices.Index(fixture.closeLog, "program:"+fakeTCPSessionClaimProgramName)
	if sessionClose < 0 || claimClose < 0 || sessionClose >= claimClose {
		t.Fatalf("session store must close before borrowed claim program: %v", fixture.closeLog)
	}
	if runtime.state.engine != nil || runtime.state.slowPath != nil {
		t.Fatalf("closed runtime retained Engine=%p slowPath=%v",
			runtime.state.engine, runtime.state.slowPath)
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
	if err := runtime.Run(t.Context()); !errors.Is(err, ErrExperimentalFakeTCPRuntimeClosed) {
		t.Fatalf("Run after close error = %v", err)
	}
	if err := runtime.RequestStop(); !errors.Is(err, ErrExperimentalFakeTCPRuntimeClosed) {
		t.Fatalf("RequestStop after close error = %v", err)
	}
	if err := handles.WithEventsMap(func(*ebpf.Map) error { return nil }); !errors.Is(err, ErrExperimentalFakeTCPRuntimeClosed) {
		t.Fatalf("retained event constructor after close error = %v", err)
	}
}

func TestExperimentalFakeTCPFreshClaimUsesPreResolvedCoreResourcesWithoutOwnerReentry(
	t *testing.T,
) {
	fixture := newRuntimeTestFixture(t)
	ctx, transaction, _ := newTestFakeTCPPolicyGenerationTransaction(t, 91)
	options := fixture.buildOptions(transaction)
	options.coreStageFactory = func(
		_ context.Context,
		resources experimentalCoreResources,
		_ *abi.Snapshot,
	) (experimentalCoreStageOwner, error) {
		if resources.control == nil || len(resources.dataMaps) != 7 ||
			len(resources.tailCalls) != len(xorTailCallBindings) {
			return nil, errors.New("pre-resolved core resource bundle is incomplete")
		}
		if fixture.collection.mu.TryLock() {
			fixture.collection.mu.Unlock()
			return nil, errors.New("fresh claim callback does not hold collection ownership lock")
		}
		return &fakeExperimentalCoreStage{trace: &fixture.activationTrace}, nil
	}
	type result struct {
		runtime *ExperimentalFakeTCPRuntime
		err     error
	}
	done := make(chan result, 1)
	go func() {
		runtime, err := buildExperimentalFakeTCPRuntime(ctx, options)
		done <- result{runtime: runtime, err: err}
	}()
	var built result
	select {
	case built = <-done:
	case <-time.After(time.Second):
		t.Fatal("fresh collection callback deadlocked on collection owner reentry")
	}
	if built.err != nil {
		t.Fatal(built.err)
	}
	if !fixture.collection.mu.TryLock() {
		t.Fatal("collection owner remained locked after fresh callback")
	}
	fixture.collection.mu.Unlock()
	if err := built.runtime.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestExperimentalRuntimeCloseBlocksReachabilityBeforeDependentTeardown(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	runtime, _, err := fixture.build(t, 91)
	if err != nil {
		t.Fatal(err)
	}
	closeStart := len(fixture.activationTrace)
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	got := fixture.activationTrace[closeStart:]
	want := []string{
		"slow-close",
		"core-deactivate",
		"xdp-close",
		"xdp-close",
		"tc-close",
		"core-close",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("runtime dependency close order = %v, want %v", got, want)
	}
}

func TestExperimentalRuntimeCloseWaitsForBlockedSlowPathWriterFence(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	slowCloseStarted := make(chan struct{})
	slowCloseRelease := make(chan struct{})
	fixture.slowPath.closeStarted = slowCloseStarted
	fixture.slowPath.closeRelease = slowCloseRelease
	runtime, _, err := fixture.build(t, 91)
	if err != nil {
		t.Fatal(err)
	}
	deactivateStarted := make(chan struct{})
	fixture.lastCoreStage.deactivateStarted = deactivateStarted
	closeStart := len(fixture.activationTrace)
	closeDone := make(chan error, 1)
	go func() { closeDone <- runtime.Close() }()
	select {
	case <-slowCloseStarted:
	case <-time.After(time.Second):
		t.Fatal("runtime Close did not enter the slow-path writer fence")
	}
	select {
	case <-deactivateStarted:
		t.Fatal("baseline core deactivated while the slow-path writer was still admitted")
	case err := <-closeDone:
		t.Fatalf("runtime Close returned before the slow-path writer fence: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(slowCloseRelease)
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	want := []string{
		"slow-close",
		"core-deactivate",
		"xdp-close",
		"xdp-close",
		"tc-close",
		"core-close",
	}
	if got := fixture.activationTrace[closeStart:]; !slices.Equal(got, want) {
		t.Fatalf("blocked writer teardown order = %v, want %v", got, want)
	}
}

func TestExperimentalRuntimeSlowPathCloseFailureRetainsDataplaneForExactRetry(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	wantErr := errors.New("injected slow-path writer close failure")
	fixture.slowPath.closeErr = wantErr
	runtime, _, err := fixture.build(t, 91)
	if err != nil {
		t.Fatal(err)
	}
	ownedSlowPath := runtime.state.slowPath
	ownedCore := runtime.state.core
	ownedXDP := runtime.state.xdp
	ownedTC := runtime.state.tc
	closeStart := len(fixture.activationTrace)
	if err := runtime.Close(); !errors.Is(err, wantErr) {
		t.Fatalf("runtime Close error = %v", err)
	}
	if runtime.state.closed || runtime.state.slowPath != ownedSlowPath ||
		runtime.state.core != ownedCore || runtime.state.xdp != ownedXDP ||
		runtime.state.tc != ownedTC || runtime.state.collection == nil {
		t.Fatalf(
			"failed slow-path fence lost ownership closed=%t slow=%#v core=%#v xdp=%#v tc=%#v collection=%#v",
			runtime.state.closed,
			runtime.state.slowPath,
			runtime.state.core,
			runtime.state.xdp,
			runtime.state.tc,
			runtime.state.collection,
		)
	}
	if fixture.lastCoreStage.deactivates != 0 || fixture.lastTCStage.closes != 0 ||
		fixture.xdpRuntime.links[3].closes != 0 || fixture.xdpRuntime.links[9].closes != 0 {
		t.Fatalf(
			"failed slow-path fence reached teardown core=%d tc=%d xdp3=%d xdp9=%d",
			fixture.lastCoreStage.deactivates,
			fixture.lastTCStage.closes,
			fixture.xdpRuntime.links[3].closes,
			fixture.xdpRuntime.links[9].closes,
		)
	}
	for name, resource := range fixture.mapResources {
		if resource.closes != 0 {
			t.Fatalf("failed slow-path fence closed retained map %s %d times", name, resource.closes)
		}
	}
	for name, program := range fixture.programs {
		if program.closes != 0 {
			t.Fatalf("failed slow-path fence closed retained program %s %d times", name, program.closes)
		}
	}
	wantPolicy := mustFakeTCPPolicySnapshot(t, 91)
	assertMemoryPolicyMapMatches(t, fixture.policyMaps.ControlPolicies, wantPolicy.ControlPolicies)
	assertMemoryPolicyMapMatches(t, fixture.policyMaps.ManagedPorts, wantPolicy.ManagedPorts)
	assertMemoryPolicyMapMatches(t, fixture.policyMaps.ManagedInterfaces, wantPolicy.ManagedInterfaces)
	if fixture.sessionClaimArg != fixture.programs[fakeTCPSessionClaimProgramName] {
		t.Fatal("runtime did not retain the exact session claim program")
	}
	if got := fixture.activationTrace[closeStart:]; !slices.Equal(got, []string{"slow-close"}) {
		t.Fatalf("failed slow-path fence trace = %v", got)
	}

	fixture.slowPath.closeErr = nil
	if err := runtime.Close(); err != nil {
		t.Fatalf("retry exact slow-path owner: %v", err)
	}
	want := []string{
		"slow-close",
		"slow-close",
		"core-deactivate",
		"xdp-close",
		"xdp-close",
		"tc-close",
		"core-close",
	}
	if got := fixture.activationTrace[closeStart:]; !slices.Equal(got, want) {
		t.Fatalf("slow-path retry teardown order = %v, want %v", got, want)
	}
	if !runtime.state.closed {
		t.Fatal("retry did not converge the retained runtime owner")
	}
}

func TestExperimentalRuntimeDeactivateFailureStillDetachesXDPAndTC(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	runtime, _, err := fixture.build(t, 91)
	if err != nil {
		t.Fatal(err)
	}
	deactivateErr := errors.New("injected runtime deactivate failure")
	fixture.lastCoreStage.deactivateErr = deactivateErr
	if err := runtime.Close(); !errors.Is(err, deactivateErr) {
		t.Fatalf("runtime Close error = %v", err)
	}
	if fixture.lastTCStage.closes != 1 ||
		fixture.xdpRuntime.links[3].closes != 1 ||
		fixture.xdpRuntime.links[9].closes != 1 {
		t.Fatalf(
			"deactivate failure teardown tc=%d xdp3=%d xdp9=%d",
			fixture.lastTCStage.closes,
			fixture.xdpRuntime.links[3].closes,
			fixture.xdpRuntime.links[9].closes,
		)
	}
	slowIndex := slices.Index(fixture.activationTrace, "slow-close")
	deactivateIndex := slices.Index(fixture.activationTrace, "core-deactivate")
	xdpIndex := slices.Index(fixture.activationTrace, "xdp-close")
	tcIndex := slices.Index(fixture.activationTrace, "tc-close")
	if slowIndex < 0 || deactivateIndex <= slowIndex || xdpIndex <= deactivateIndex || tcIndex <= xdpIndex {
		t.Fatalf("deactivate failure dependency order = %v", fixture.activationTrace)
	}
	fixture.lastCoreStage.deactivateErr = nil
	if err := runtime.Close(); err != nil {
		t.Fatalf("retry runtime Close: %v", err)
	}
	if !runtime.state.closed || runtime.state.collection != nil {
		t.Fatalf("retry closed=%t collection=%#v", runtime.state.closed, runtime.state.collection)
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
	if result, err := store.DeleteEstablishedIfUnchanged(key, value); result != faketcp.SessionDeleteDifferent ||
		!errors.Is(err, ErrExperimentalFakeTCPGenerationMismatch) {
		t.Fatalf("cross-generation result=%v error=%v", result, err)
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

func TestExperimentalFakeTCPRuntimeCopiesShareRetryableCloseQuarantine(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	wantErr := errors.New("injected session close failure")
	fixture.sessionStore.closeErr = wantErr
	runtime, _, err := fixture.build(t, 91)
	if err != nil {
		t.Fatal(err)
	}
	runtimeCopy := *runtime
	const callers = 24
	start := make(chan struct{})
	errs := make(chan error, callers)
	var wait sync.WaitGroup
	for index := range callers {
		target := runtime
		if index%2 != 0 {
			target = &runtimeCopy
		}
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			errs <- target.Close()
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
	if runtime.state.closed || fixture.sessionStore.closes == 0 {
		t.Fatalf(
			"failed session owner closed=%t close attempts=%d",
			runtime.state.closed, fixture.sessionStore.closes,
		)
	}
	for name, target := range map[string]*ExperimentalFakeTCPRuntime{
		"original": runtime, "copy": &runtimeCopy,
	} {
		if _, err := target.Handles(); !errors.Is(err, ErrExperimentalFakeTCPRuntimeClosed) {
			t.Fatalf("handles through quarantined %s error = %v", name, err)
		}
	}
	for name, resource := range fixture.mapResources {
		if resource.closes != 0 {
			t.Fatalf("unsafe collection close reached map %s: %d", name, resource.closes)
		}
	}
	priorAttempts := fixture.sessionStore.closes
	fixture.sessionStore.closeErr = nil
	if err := runtimeCopy.Close(); err != nil {
		t.Fatalf("retry through copied owner: %v", err)
	}
	if !runtime.state.closed || fixture.sessionStore.closes != priorAttempts+1 {
		t.Fatalf(
			"retry closed=%t session attempts=%d, want %d",
			runtime.state.closed, fixture.sessionStore.closes, priorAttempts+1,
		)
	}
	for name, resource := range fixture.mapResources {
		if resource.closes != 1 {
			t.Fatalf("map %s close count after convergence = %d", name, resource.closes)
		}
	}
}

func TestExperimentalFakeTCPRuntimeZeroValueIsClosed(t *testing.T) {
	var runtime ExperimentalFakeTCPRuntime
	if runtime.Generation() != 0 {
		t.Fatalf("zero runtime generation = %d", runtime.Generation())
	}
	if runtime.Identity() != (faketcp.RuntimeIdentity{}) {
		t.Fatalf("zero runtime identity = %#v", runtime.Identity())
	}
	if err := runtime.Run(t.Context()); !errors.Is(err, ErrExperimentalFakeTCPRuntimeClosed) {
		t.Fatalf("zero runtime Run error = %v", err)
	}
	if err := runtime.RequestStop(); !errors.Is(err, ErrExperimentalFakeTCPRuntimeClosed) {
		t.Fatalf("zero runtime RequestStop error = %v", err)
	}
	handles, err := runtime.Handles()
	if !errors.Is(err, ErrExperimentalFakeTCPRuntimeClosed) ||
		handles.Generation() != 0 || handles.SessionStore() != nil {
		t.Fatalf("zero runtime handles=%#v error=%v", handles, err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("zero runtime close: %v", err)
	}
	runtimeCopy := runtime
	if err := runtimeCopy.Close(); err != nil {
		t.Fatalf("zero runtime copy close: %v", err)
	}
}

func TestExperimentalFakeTCPRuntimeCopySharesHandlesCloseFence(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	fixture.sessionStore.entered = make(chan struct{}, 1)
	fixture.sessionStore.release = make(chan struct{})
	runtime, handles, err := fixture.build(t, 91)
	if err != nil {
		t.Fatal(err)
	}
	runtimeCopy := *runtime
	operationDone := make(chan error, 1)
	go func() {
		_, _, err := handles.SessionStore().LookupEstablished(sessionStoreTestKey(91))
		operationDone <- err
	}()
	select {
	case <-fixture.sessionStore.entered:
	case <-time.After(time.Second):
		t.Fatal("session operation did not enter backend")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- runtimeCopy.Close() }()
	deadline := time.After(time.Second)
	for {
		_, err := runtime.Handles()
		if errors.Is(err, ErrExperimentalFakeTCPRuntimeClosed) {
			break
		}
		if err != nil {
			t.Fatalf("unexpected handles fence error: %v", err)
		}
		select {
		case <-deadline:
			t.Fatal("runtime close did not fence handles")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if _, err := runtimeCopy.Handles(); !errors.Is(err, ErrExperimentalFakeTCPRuntimeClosed) {
		t.Fatalf("copied runtime handles during close error = %v", err)
	}
	select {
	case err := <-closeDone:
		t.Fatalf("close returned before admitted operation: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(fixture.sessionStore.release)
	if err := <-operationDone; err != nil {
		t.Fatal(err)
	}
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	if _, _, err := handles.SessionStore().LookupEstablished(
		sessionStoreTestKey(91),
	); !errors.Is(err, ErrExperimentalFakeTCPRuntimeClosed) {
		t.Fatalf("retained handles after copied close error = %v", err)
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
	if len(fixture.activationTrace) == 0 || fixture.activationTrace[0] != "seed" ||
		slices.Index(fixture.activationTrace, "xdp-attach") <= 0 ||
		slices.Contains(fixture.activationTrace, "release") {
		t.Fatalf("failed attach activation order = %v", fixture.activationTrace)
	}
	if _, _, closes := fixture.slowPath.counts(); closes != 1 ||
		len(fixture.closeLog) == 0 || fixture.closeLog[0] != "slow-path" {
		t.Fatalf("failed build slow-path closes=%d close order=%v", closes, fixture.closeLog)
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

func TestExperimentalFakeTCPRuntimeRejectsEngineMismatchAndPrebuiltStoreBeforeFreshClaim(
	t *testing.T,
) {
	for _, test := range []struct {
		name   string
		mutate func(*runtimeTestFixture, *experimentalFakeTCPRuntimeBuildOptions)
		match  string
	}{
		{
			name: "generation mismatch",
			mutate: func(_ *runtimeTestFixture, options *experimentalFakeTCPRuntimeBuildOptions) {
				options.engineOptions.Generation++
			},
			match: "does not match policy plan generation",
		},
		{
			name: "prebuilt store",
			mutate: func(fixture *runtimeTestFixture, options *experimentalFakeTCPRuntimeBuildOptions) {
				options.engineOptions.Store = fixture.sessionStore
			},
			match: "Store must come from the claimed collection",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRuntimeTestFixture(t)
			ctx, transaction, _ := newTestFakeTCPPolicyGenerationTransaction(t, 91)
			options := fixture.buildOptions(transaction)
			test.mutate(fixture, &options)
			runtime, err := buildExperimentalFakeTCPRuntime(ctx, options)
			if runtime != nil || err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("runtime=%#v error=%v", runtime, err)
			}
			if fixture.commitCalls != 0 || fixture.collection.freshRuntimeClaimConsumed ||
				len(fixture.programArray.inserts) != 0 || len(fixture.xdpRuntime.probeCalls) != 0 ||
				fixture.sessionStore.closes != 0 {
				t.Fatalf(
					"preflight claim=%d consumed=%t programs=%v probes=%v session closes=%d",
					fixture.commitCalls, fixture.collection.freshRuntimeClaimConsumed,
					fixture.programArray.inserts, fixture.xdpRuntime.probeCalls,
					fixture.sessionStore.closes,
				)
			}
		})
	}
}

func TestExperimentalFakeTCPRuntimeMapMismatchConsumesFreshCollectionWithoutReachability(
	t *testing.T,
) {
	fixture := newRuntimeTestFixture(t)
	fixture.mapResources[fakeTCPRuntimeIDMapName].bpfMap = nil
	ctx, transaction, _ := newTestFakeTCPPolicyGenerationTransaction(t, 91)
	runtime, err := buildExperimentalFakeTCPRuntime(
		ctx,
		fixture.buildOptions(transaction),
	)
	if runtime != nil || err == nil || !strings.Contains(err.Error(), "identity resource") {
		t.Fatalf("runtime=%#v error=%v", runtime, err)
	}
	if !fixture.collection.freshRuntimeClaimConsumed || fixture.commitCalls != 1 ||
		len(fixture.programArray.inserts) != 0 || len(fixture.xdpRuntime.probeCalls) != 0 ||
		len(fixture.policyTrace.updateAttempts) != 0 {
		t.Fatalf("consumed=%t commits=%d programs=%v probes=%v policy=%v",
			fixture.collection.freshRuntimeClaimConsumed, fixture.commitCalls,
			fixture.programArray.inserts, fixture.xdpRuntime.probeCalls,
			fixture.policyTrace.updateAttempts)
	}
	if _, _, closes := fixture.slowPath.counts(); closes != 1 {
		t.Fatalf("slow-path close count = %d", closes)
	}
}

func TestExperimentalFakeTCPRuntimeReleaseFailureBeforeCommitRollsBack(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	ctx, transaction, _ := newTestFakeTCPPolicyGenerationTransaction(t, 91)
	wantErr := errors.New("injected release-before-commit failure")
	var retainedRelease faketcp.LinuxFreshCollectionRelease
	options := fixture.buildOptions(transaction)
	options.commitGeneration = func(
		_ *faketcp.Engine,
		claim faketcp.LinuxFreshCollectionClaim,
		makeReachable func(faketcp.LinuxFreshCollectionRelease) error,
	) error {
		return claim.WithExclusiveFreshFakeTCPCollection(func(
			_, _ *ebpf.Map,
			release faketcp.LinuxFreshCollectionRelease,
		) error {
			retainedRelease = release
			fixture.activationTrace = append(fixture.activationTrace, "seed")
			return makeReachable(func() error {
				fixture.activationTrace = append(fixture.activationTrace, "release-failure")
				return wantErr
			})
		})
	}
	runtime, err := buildExperimentalFakeTCPRuntime(ctx, options)
	if runtime != nil || !errors.Is(err, wantErr) {
		t.Fatalf("runtime=%#v error=%v", runtime, err)
	}
	if lateErr := retainedRelease(); !errors.Is(lateErr, errExperimentalFreshCollectionReleaseConsumed) {
		t.Fatalf("late uncalled release error = %v", lateErr)
	}
	releaseIndex := slices.Index(fixture.activationTrace, "release-failure")
	xdpIndex := slices.Index(fixture.activationTrace, "xdp-attach")
	deactivateIndex := slices.Index(fixture.activationTrace, "core-deactivate")
	xdpCloseIndex := slices.Index(fixture.activationTrace, "xdp-close")
	tcCloseIndex := slices.Index(fixture.activationTrace, "tc-close")
	slowCloseIndex := slices.Index(fixture.activationTrace, "slow-close")
	policyDeleteIndex := slices.Index(
		fixture.activationTrace,
		"policy:delete:faketcp_managed_if_map",
	)
	programDeleteIndex := slices.Index(fixture.activationTrace, "program-delete")
	coreCloseIndex := slices.Index(fixture.activationTrace, "core-close")
	if len(fixture.activationTrace) == 0 || fixture.activationTrace[0] != "seed" ||
		xdpIndex <= 0 || releaseIndex <= xdpIndex ||
		slowCloseIndex <= releaseIndex || deactivateIndex <= slowCloseIndex ||
		xdpCloseIndex <= deactivateIndex || tcCloseIndex <= xdpCloseIndex ||
		policyDeleteIndex <= tcCloseIndex || programDeleteIndex <= policyDeleteIndex ||
		coreCloseIndex <= programDeleteIndex {
		t.Fatalf("release failure order = %v", fixture.activationTrace)
	}
	if len(fixture.programArray.entries) != 0 || len(fixture.programArray.deletes) != 1 {
		t.Fatalf("program rollback entries=%v deletes=%v",
			fixture.programArray.entries, fixture.programArray.deletes)
	}
	if slices.Contains(fixture.activationTrace, "core-commit") {
		t.Fatalf("canceled build published a partial generation: %v", fixture.activationTrace)
	}
	assertNoMemoryPolicyGeneration(t, fixture.policyMaps, 91)
	if fixture.xdpRuntime.links[3].closes != 1 || fixture.xdpRuntime.links[9].closes != 1 {
		t.Fatalf("XDP closes 3=%d 9=%d",
			fixture.xdpRuntime.links[3].closes, fixture.xdpRuntime.links[9].closes)
	}
}

func TestExperimentalBuildCleanupRetainsDataplaneUntilSlowPathRetry(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	ctx, transaction, _ := newTestFakeTCPPolicyGenerationTransaction(t, 91)
	releaseErr := errors.New("injected pre-commit release failure")
	slowCloseErr := errors.New("injected failed-build slow-path close failure")
	fixture.slowPath.closeErr = slowCloseErr
	options := fixture.buildOptions(transaction)
	options.commitGeneration = func(
		_ *faketcp.Engine,
		claim faketcp.LinuxFreshCollectionClaim,
		makeReachable func(faketcp.LinuxFreshCollectionRelease) error,
	) error {
		return claim.WithExclusiveFreshFakeTCPCollection(func(
			_, _ *ebpf.Map,
			_ faketcp.LinuxFreshCollectionRelease,
		) error {
			fixture.activationTrace = append(fixture.activationTrace, "seed")
			return makeReachable(func() error {
				fixture.activationTrace = append(fixture.activationTrace, "release-failure")
				return releaseErr
			})
		})
	}
	runtime, err := buildExperimentalFakeTCPRuntime(ctx, options)
	if runtime == nil || !errors.Is(err, releaseErr) || !errors.Is(err, slowCloseErr) {
		t.Fatalf("failed-build runtime=%#v error=%v", runtime, err)
	}
	if runtime.state.failedBuild == nil || runtime.state.closed ||
		!fixture.lastCoreStage.active || fixture.lastCoreStage.deactivates != 0 ||
		fixture.lastTCStage.closes != 0 || fixture.xdpRuntime.links[3].closes != 0 ||
		fixture.xdpRuntime.links[9].closes != 0 {
		t.Fatalf(
			"failed cleanup ownership failedBuild=%#v closed=%t coreActive=%t coreDeactivates=%d tc=%d xdp3=%d xdp9=%d",
			runtime.state.failedBuild,
			runtime.state.closed,
			fixture.lastCoreStage.active,
			fixture.lastCoreStage.deactivates,
			fixture.lastTCStage.closes,
			fixture.xdpRuntime.links[3].closes,
			fixture.xdpRuntime.links[9].closes,
		)
	}
	releaseIndex := slices.Index(fixture.activationTrace, "release-failure")
	if releaseIndex < 0 || !slices.Equal(
		fixture.activationTrace[releaseIndex+1:],
		[]string{"slow-close"},
	) {
		t.Fatalf("failed cleanup crossed the slow-path fence: %v", fixture.activationTrace)
	}
	for name, resource := range fixture.mapResources {
		if resource.closes != 0 {
			t.Fatalf("failed slow-path cleanup reached map %s close=%d", name, resource.closes)
		}
	}

	fixture.slowPath.closeErr = nil
	retryStart := len(fixture.activationTrace)
	if err := runtime.Close(); err != nil {
		t.Fatalf("retry failed-build owner: %v", err)
	}
	wantRetryPrefix := []string{
		"slow-close",
		"core-deactivate",
		"xdp-close",
		"xdp-close",
		"tc-close",
	}
	retryTrace := fixture.activationTrace[retryStart:]
	if len(retryTrace) < len(wantRetryPrefix) ||
		!slices.Equal(retryTrace[:len(wantRetryPrefix)], wantRetryPrefix) {
		t.Fatalf("failed-build retry teardown order = %v", retryTrace)
	}
	if !runtime.state.closed || runtime.state.failedBuild != nil || !transaction.isClosed() {
		t.Fatalf(
			"failed-build retry closed=%t retained=%#v transactionClosed=%t",
			runtime.state.closed,
			runtime.state.failedBuild,
			transaction.isClosed(),
		)
	}
}

func TestExperimentalFakeTCPRuntimeCommittedLeaseCloseFailureTearsDownWithoutRollback(
	t *testing.T,
) {
	fixture := newRuntimeTestFixture(t)
	ctx, transaction, _ := newTestFakeTCPPolicyGenerationTransaction(t, 91)
	wantErr := errors.New("injected committed lifecycle close failure")
	closeCalls := 0
	transaction.closeLifecycleLease = func(lease *lockfile.LifecycleLease) error {
		closeCalls++
		return errors.Join(lease.Close(), wantErr)
	}
	runtime, err := buildExperimentalFakeTCPRuntime(
		ctx,
		fixture.buildOptions(transaction),
	)
	if runtime != nil || !errors.Is(err, wantErr) {
		t.Fatalf("runtime=%#v error=%v", runtime, err)
	}
	if closeCalls != 1 || !transaction.closed || transaction.runtimeClaim != nil {
		t.Fatalf("lease closes=%d transaction closed=%t claim=%p",
			closeCalls, transaction.closed, transaction.runtimeClaim)
	}
	if len(fixture.programArray.deletes) != 0 || len(fixture.policyTrace.deleteAttempts) != 0 {
		t.Fatalf("committed failure attempted rollback: programs=%v policy=%v",
			fixture.programArray.deletes, fixture.policyTrace.deleteAttempts)
	}
	if fixture.xdpRuntime.links[3].closes != 1 || fixture.xdpRuntime.links[9].closes != 1 ||
		fixture.sessionStore.closes != 1 {
		t.Fatalf("committed teardown xdp3=%d xdp9=%d session=%d",
			fixture.xdpRuntime.links[3].closes, fixture.xdpRuntime.links[9].closes,
			fixture.sessionStore.closes)
	}
	if _, _, closes := fixture.slowPath.counts(); closes != 1 ||
		len(fixture.closeLog) == 0 || fixture.closeLog[0] != "slow-path" {
		t.Fatalf("committed teardown slow-path=%d order=%v", closes, fixture.closeLog)
	}
	for name, resource := range fixture.mapResources {
		if resource.closes != 1 {
			t.Fatalf("committed teardown map %s closes=%d", name, resource.closes)
		}
	}
}

func TestExperimentalFakeTCPRuntimeDoubleReleaseCommitsOnceThenTearsDown(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	ctx, transaction, _ := newTestFakeTCPPolicyGenerationTransaction(t, 91)
	options := fixture.buildOptions(transaction)
	options.commitGeneration = func(
		_ *faketcp.Engine,
		claim faketcp.LinuxFreshCollectionClaim,
		makeReachable func(faketcp.LinuxFreshCollectionRelease) error,
	) error {
		return claim.WithExclusiveFreshFakeTCPCollection(func(
			_, _ *ebpf.Map,
			release faketcp.LinuxFreshCollectionRelease,
		) error {
			return makeReachable(func() error {
				firstErr := release()
				secondErr := release()
				return errors.Join(firstErr, secondErr)
			})
		})
	}
	runtime, err := buildExperimentalFakeTCPRuntime(ctx, options)
	if runtime != nil || !errors.Is(err, errExperimentalFreshCollectionReleaseConsumed) {
		t.Fatalf("runtime=%#v error=%v", runtime, err)
	}
	if !transaction.closed || len(fixture.programArray.deletes) != 0 ||
		len(fixture.policyTrace.deleteAttempts) != 0 {
		t.Fatalf("double release closed=%t program deletes=%v policy deletes=%v",
			transaction.closed, fixture.programArray.deletes, fixture.policyTrace.deleteAttempts)
	}
	if _, _, closes := fixture.slowPath.counts(); closes != 1 {
		t.Fatalf("slow-path closes = %d", closes)
	}
}

func TestExperimentalFakeTCPRuntimeRejectsPreStagedTransactionWithoutOwnershipTransfer(
	t *testing.T,
) {
	fixture := newRuntimeTestFixture(t)
	wantSnapshot := mustFakeTCPPolicySnapshot(t, 91)
	ctx, transaction, _ := newTestFakeTCPPolicyGenerationTransaction(t, wantSnapshot.Generation)
	stage, err := transaction.Stage(ctx, fixture.policyMaps)
	if err != nil {
		t.Fatal(err)
	}
	updatesBefore := len(fixture.policyTrace.updateAttempts)
	deletesBefore := len(fixture.policyTrace.deleteAttempts)
	options := fixture.buildOptions(transaction)
	runtime, err := buildExperimentalFakeTCPRuntime(ctx, options)
	if runtime != nil || err == nil || !strings.Contains(err.Error(), "not fresh") {
		t.Fatalf("pre-staged runtime=%#v error=%v", runtime, err)
	}
	if len(fixture.policyTrace.updateAttempts) != updatesBefore ||
		len(fixture.policyTrace.deleteAttempts) != deletesBefore ||
		len(fixture.programArray.inserts) != 0 || len(fixture.xdpRuntime.probeCalls) != 0 ||
		fixture.sessionStore.closes != 0 {
		t.Fatalf(
			"rejected build mutated resources: policy updates=%d/%d deletes=%d/%d programs=%v probes=%v session closes=%d",
			len(fixture.policyTrace.updateAttempts), updatesBefore,
			len(fixture.policyTrace.deleteAttempts), deletesBefore,
			fixture.programArray.inserts, fixture.xdpRuntime.probeCalls,
			fixture.sessionStore.closes,
		)
	}
	for name, resource := range fixture.mapResources {
		if resource.closes != 0 {
			t.Fatalf("rejected build closed caller-owned map %s %d times", name, resource.closes)
		}
	}
	for name, program := range fixture.programs {
		if program.closes != 0 {
			t.Fatalf("rejected build closed caller-owned program %s %d times", name, program.closes)
		}
	}
	assertMemoryPolicyMapMatches(t, fixture.policyMaps.ControlPolicies, wantSnapshot.ControlPolicies)
	assertMemoryPolicyMapMatches(t, fixture.policyMaps.ManagedPorts, wantSnapshot.ManagedPorts)
	assertMemoryPolicyMapMatches(t, fixture.policyMaps.ManagedInterfaces, wantSnapshot.ManagedInterfaces)

	if err := transaction.Rollback(ctx, stage); err != nil {
		t.Fatalf("caller rollback after rejected build: %v", err)
	}
	if err := transaction.Close(); err != nil {
		t.Fatalf("caller close after rejected build: %v", err)
	}
	reacquired, err := lockfile.AcquireLifecycle(
		ctx,
		lockfile.LifecycleOwner{PID: os.Getpid(), Action: "test-faketcp-after-rejected-runtime-build"},
	)
	if err != nil {
		t.Fatalf("reacquire lifecycle lease after caller cleanup: %v", err)
	}
	if err := reacquired.Close(); err != nil {
		t.Fatal(err)
	}
	if err := fixture.collection.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestExperimentalLinuxFreshCollectionClaimCopiesAreConcurrentSingleUse(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	ctx, transaction, _ := newTestFakeTCPPolicyGenerationTransaction(t, 91)
	buildClaim, err := transaction.claimRuntimeBuild(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var releaseCalls atomic.Int32
	claim := experimentalLinuxFreshCollectionClaim{
		state: &experimentalLinuxFreshCollectionClaimState{
			transaction: buildClaim,
			claimCtx:    context.WithoutCancel(ctx),
			collection:  fixture.collection,
			release: func() error {
				releaseCalls.Add(1)
				return nil
			},
		},
	}
	const contenders = 24
	start := make(chan struct{})
	results := make(chan error, contenders)
	var callbacks atomic.Int32
	var retained atomic.Pointer[func() error]
	var wait sync.WaitGroup
	for range contenders {
		candidate := claim
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			results <- candidate.WithExclusiveFreshFakeTCPCollection(func(
				_, _ *ebpf.Map,
				release faketcp.LinuxFreshCollectionRelease,
			) error {
				callbacks.Add(1)
				retainedRelease := func() error { return release() }
				retained.Store(&retainedRelease)
				return release()
			})
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else if !strings.Contains(err.Error(), "single-use") {
			t.Fatalf("competing fresh claim error = %v", err)
		}
	}
	if successes != 1 || callbacks.Load() != 1 || releaseCalls.Load() != 1 {
		t.Fatalf("successes=%d callbacks=%d releases=%d",
			successes, callbacks.Load(), releaseCalls.Load())
	}
	if retainedRelease := retained.Load(); retainedRelease == nil {
		t.Fatal("winning callback did not retain a release capability")
	} else if err := (*retainedRelease)(); !errors.Is(err, errExperimentalFreshCollectionReleaseConsumed) {
		t.Fatalf("retained release error = %v", err)
	}
	if releaseCalls.Load() != 1 {
		t.Fatalf("retained release repeated side effect: %d", releaseCalls.Load())
	}
	if err := buildClaim.Close(); err != nil {
		t.Fatal(err)
	}
	if err := fixture.collection.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestExperimentalLinuxFreshCollectionClaimBlocksCollectionCloseAcrossCallback(
	t *testing.T,
) {
	fixture := newRuntimeTestFixture(t)
	ctx, transaction, _ := newTestFakeTCPPolicyGenerationTransaction(t, 91)
	buildClaim, err := transaction.claimRuntimeBuild(ctx)
	if err != nil {
		t.Fatal(err)
	}
	claim := experimentalLinuxFreshCollectionClaim{
		state: &experimentalLinuxFreshCollectionClaimState{
			transaction: buildClaim,
			claimCtx:    context.WithoutCancel(ctx),
			collection:  fixture.collection,
			release:     func() error { return nil },
		},
	}
	entered := make(chan struct{})
	allowReturn := make(chan struct{})
	callbackDone := make(chan error, 1)
	go func() {
		callbackDone <- claim.WithExclusiveFreshFakeTCPCollection(func(
			_, _ *ebpf.Map,
			release faketcp.LinuxFreshCollectionRelease,
		) error {
			close(entered)
			<-allowReturn
			return release()
		})
	}()
	<-entered
	closeDone := make(chan error, 1)
	go func() { closeDone <- fixture.collection.Close() }()
	select {
	case err := <-closeDone:
		t.Fatalf("collection Close escaped fresh callback: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if err := transaction.Close(); err == nil || !strings.Contains(err.Error(), "claimed") {
		t.Fatalf("ordinary transaction Close during callback = %v", err)
	}
	close(allowReturn)
	if err := <-callbackDone; err != nil {
		t.Fatal(err)
	}
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	if err := buildClaim.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestFakeTCPRuntimeBuildClaimIsExclusiveAndFencesCallerMutation(t *testing.T) {
	ctx, transaction, _ := newTestFakeTCPPolicyGenerationTransaction(t, 91)
	const contenders = 16
	start := make(chan struct{})
	claims := make(chan *fakeTCPPolicyRuntimeBuildClaim, contenders)
	errs := make(chan error, contenders)
	var wait sync.WaitGroup
	for range contenders {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			claim, err := transaction.claimRuntimeBuild(ctx)
			claims <- claim
			errs <- err
		}()
	}
	close(start)
	wait.Wait()
	close(claims)
	close(errs)

	var owner *fakeTCPPolicyRuntimeBuildClaim
	successes := 0
	for claim := range claims {
		if claim != nil {
			owner = claim
			successes++
		}
	}
	failures := 0
	for err := range errs {
		if err != nil {
			if !strings.Contains(err.Error(), "already claimed") {
				t.Fatalf("competing claim error = %v", err)
			}
			failures++
		}
	}
	if successes != 1 || failures != contenders-1 {
		t.Fatalf("claim successes=%d failures=%d", successes, failures)
	}
	policyMaps, trace := newMemoryFakeTCPPolicyMaps()
	stage, err := transaction.Stage(ctx, policyMaps)
	if stage != nil || err == nil || !strings.Contains(err.Error(), "exclusively claimed") {
		t.Fatalf("caller stage during build claim=%#v error=%v", stage, err)
	}
	if len(trace.updateAttempts) != 0 || len(trace.deleteAttempts) != 0 {
		t.Fatalf("fenced caller mutation touched maps: %#v", trace)
	}
	if err := transaction.Close(); err == nil || !strings.Contains(err.Error(), "claimed") {
		t.Fatalf("caller close during build claim error = %v", err)
	}
	if err := owner.Close(); err != nil {
		t.Fatalf("close winning runtime claim: %v", err)
	}
	reacquired, err := lockfile.AcquireLifecycle(
		ctx,
		lockfile.LifecycleOwner{PID: os.Getpid(), Action: "test-faketcp-after-runtime-claim"},
	)
	if err != nil {
		t.Fatalf("reacquire lifecycle lease after claim close: %v", err)
	}
	if err := reacquired.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestExperimentalFakeTCPRuntimeCancellationAfterMutationUsesCleanupContext(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	baseCtx, transaction, _ := newTestFakeTCPPolicyGenerationTransaction(t, 91)
	activeCtx, cancel := context.WithCancel(baseCtx)
	xdpRuntime := fixture.xdpRuntime.backend()
	attach := xdpRuntime.attach
	xdpRuntime.attach = func(
		request fakeTCPXDPAttachRequest,
		expected fakeTCPXDPProbe,
		program experimentalProgramResource,
	) (fakeTCPXDPLink, error) {
		owned, err := attach(request, expected, program)
		if err == nil {
			cancel()
		}
		return owned, err
	}

	options := fixture.buildOptions(transaction)
	options.xdpRuntime = xdpRuntime
	runtime, err := buildExperimentalFakeTCPRuntime(activeCtx, options)
	if runtime != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled runtime=%#v error=%v", runtime, err)
	}
	if len(fixture.xdpRuntime.attachCalls) != 1 || fixture.xdpRuntime.links[3].closes != 1 {
		t.Fatalf("XDP attach calls=%v first-link closes=%d",
			fixture.xdpRuntime.attachCalls, fixture.xdpRuntime.links[3].closes)
	}
	if _, exists := fixture.xdpRuntime.links[9]; exists {
		t.Fatal("cancellation after first attach did not stop the second attach")
	}
	if len(fixture.programArray.entries) != 0 ||
		!slices.Equal(fixture.programArray.deletes, []uint32{1}) {
		t.Fatalf("program rollback entries=%v deletes=%v",
			fixture.programArray.entries, fixture.programArray.deletes)
	}
	assertNoMemoryPolicyGeneration(t, fixture.policyMaps, 91)
	if fixture.sessionStore.closes != 1 {
		t.Fatalf("session close count = %d", fixture.sessionStore.closes)
	}
	for name, resource := range fixture.mapResources {
		if resource.closes != 1 {
			t.Fatalf("map %s close count = %d", name, resource.closes)
		}
	}
}

func TestExperimentalFakeTCPRuntimeCommitBoundaryIgnoresLaterCancellation(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	activeCtx, transaction, _ := newTestFakeTCPPolicyGenerationTransaction(t, 91)
	claim, err := transaction.claimRuntimeBuild(activeCtx)
	if err != nil {
		t.Fatal(err)
	}
	options := fixture.buildOptions(transaction)
	build := &experimentalRuntimeBuild{
		options:    options,
		claim:      claim,
		activeCtx:  activeCtx,
		cleanupCtx: context.WithoutCancel(activeCtx),
	}
	if err := build.prepare(); err != nil {
		t.Fatal(err)
	}
	boundaryCtx, cancel := context.WithCancel(activeCtx)
	build.activeCtx = boundaryCtx
	build.cleanupCtx = context.WithoutCancel(boundaryCtx)
	build.freshClaim.state.claimCtx = build.cleanupCtx
	build.options.commitGeneration = func(
		_ *faketcp.Engine,
		fresh faketcp.LinuxFreshCollectionClaim,
		makeReachable func(faketcp.LinuxFreshCollectionRelease) error,
	) error {
		return fresh.WithExclusiveFreshFakeTCPCollection(func(
			_, _ *ebpf.Map,
			release faketcp.LinuxFreshCollectionRelease,
		) error {
			return makeReachable(func() error {
				cancel()
				return release()
			})
		})
	}
	if err := build.activate(); err != nil {
		t.Fatalf("uninterruptible commit after boundary: %v", err)
	}
	if !errors.Is(boundaryCtx.Err(), context.Canceled) || !build.committed.Load() {
		t.Fatalf("commit boundary context error=%v committed=%t",
			boundaryCtx.Err(), build.committed.Load())
	}
	if build.programStage.state != fakeTCPProgramArrayStageDisarmed ||
		build.policyStage.state != fakeTCPPolicyStageDisarmed {
		t.Fatalf("commit states program=%d policy=%d",
			build.programStage.state, build.policyStage.state)
	}
	runtime := &ExperimentalFakeTCPRuntime{
		state: &experimentalFakeTCPRuntimeState{
			generation: build.policyPlan.generation,
			identity:   build.engine.Identity(),
			engine:     build.engine,
			collection: fixture.collection,
			core:       build.coreStage,
			tc:         build.tcStage,
			xdp:        build.xdpStage,
			slowPath:   build.slowPath,
			handles: ExperimentalFakeTCPRuntimeHandles{
				generation: build.policyPlan.generation,
				identity:   build.engine.Identity(),
				sessions:   build.sessions,
				events:     build.events,
			},
			closeDone: make(chan struct{}),
		},
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestExperimentalFakeTCPRuntimeValidatesXDPPolicySetBeforeMutation(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	ctx, transaction, _ := newTestFakeTCPPolicyGenerationTransaction(t, 91)
	options := fixture.buildOptions(transaction)
	options.xdpRequests = []fakeTCPXDPAttachRequest{{IfIndex: 3, Mode: fakeTCPXDPAttachNative}}
	runtime, err := buildExperimentalFakeTCPRuntime(ctx, options)
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

func TestExperimentalRuntimeCanonicalInterfacesBindL3UnderlayAuthority(t *testing.T) {
	const generation = uint64(91)
	canonical := func(t *testing.T) (
		*control.State,
		*abi.Snapshot,
		*fakeTCPPolicyGenerationPlan,
		[]fakeTCPXDPAttachRequest,
	) {
		t.Helper()
		state := fakeTCPPolicyTestState()
		state.Underlays[0].Parser = "l3"
		baseline, err := abi.FromStateWithGeneration(state, generation)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := buildFakeTCPPolicyGenerationPlan(state, generation)
		if err != nil {
			t.Fatal(err)
		}
		return state, baseline, plan, []fakeTCPXDPAttachRequest{
			{IfIndex: 3, Mode: fakeTCPXDPAttachNative},
			{IfIndex: 9, Mode: fakeTCPXDPAttachGeneric},
		}
	}

	state, baseline, plan, requests := canonical(t)
	for _, want := range []struct {
		ifindex uint32
		parser  uint8
	}{
		{ifindex: 3, parser: abi.ParserL3},
		{ifindex: 9, parser: abi.ParserEthernet},
	} {
		key := abi.UnderlayConfigKey{Generation: generation, UnderlayIndex: want.ifindex}
		if got := baseline.Underlays[key].ParserMode; got != want.parser {
			t.Fatalf("underlay %d parser=%d, want %d", want.ifindex, got, want.parser)
		}
	}
	if got := []uint32{
		plan.managedInterfaces[0].Key.UnderlayIndex,
		plan.managedInterfaces[1].Key.UnderlayIndex,
	}; !slices.Equal(got, []uint32{3, 9}) {
		t.Fatalf("managed interfaces = %v, want [3 9]", got)
	}
	if err := validateExperimentalRuntimeCanonicalInterfaces(
		baseline, plan, state, requests,
	); err != nil {
		t.Fatalf("canonical parser:l3 runtime inputs: %v", err)
	}

	t.Run("baseline parser fork", func(t *testing.T) {
		state, baseline, plan, requests := canonical(t)
		key := abi.UnderlayConfigKey{Generation: generation, UnderlayIndex: 3}
		value := baseline.Underlays[key]
		value.ParserMode = abi.ParserEthernet
		baseline.Underlays[key] = value
		err := validateExperimentalRuntimeCanonicalInterfaces(baseline, plan, state, requests)
		if err == nil || !strings.Contains(err.Error(), "baseline underlays are stale") {
			t.Fatalf("baseline parser fork error = %v", err)
		}
	})

	t.Run("managed interface fork", func(t *testing.T) {
		state, baseline, plan, requests := canonical(t)
		plan.managedInterfaces[0].Key.UnderlayIndex = 7
		err := validateExperimentalRuntimeCanonicalInterfaces(baseline, plan, state, requests)
		if err == nil || !strings.Contains(err.Error(), "managed interfaces are stale") {
			t.Fatalf("managed-interface fork error = %v", err)
		}
	})

	t.Run("XDP request fork", func(t *testing.T) {
		state, baseline, plan, requests := canonical(t)
		requests[0].IfIndex = 7
		err := validateExperimentalRuntimeCanonicalInterfaces(baseline, plan, state, requests)
		if err == nil || !strings.Contains(err.Error(), "has no managed-interface policy") {
			t.Fatalf("XDP request fork error = %v", err)
		}
	})
}

func TestExperimentalFakeTCPRuntimeRejectsXDPBackendModeMismatchBeforeMutation(
	t *testing.T,
) {
	fixture := newRuntimeTestFixture(t)
	ctx, transaction, _ := newTestFakeTCPPolicyGenerationTransaction(t, 91)
	options := fixture.buildOptions(transaction)
	for index := range options.xdpRequests {
		options.xdpRequests[index].Mode = fakeTCPXDPAttachLibXDP
	}
	runtime, err := buildExperimentalFakeTCPRuntime(ctx, options)
	if runtime != nil || err == nil || !strings.Contains(err.Error(), "does not match constructed") {
		t.Fatalf("runtime=%#v error=%v", runtime, err)
	}
	if fixture.commitCalls != 0 || len(fixture.xdpRuntime.probeCalls) != 0 ||
		len(fixture.programArray.inserts) != 0 || fixture.sessionStore.closes != 0 {
		t.Fatalf(
			"backend mismatch commits=%d probes=%v programs=%v session closes=%d",
			fixture.commitCalls, fixture.xdpRuntime.probeCalls,
			fixture.programArray.inserts, fixture.sessionStore.closes,
		)
	}
}

func TestExperimentalFakeTCPRuntimeRefusesDirectAllHooksRequirementBeforeMutation(
	t *testing.T,
) {
	fixture := newRuntimeTestFixture(t)
	ctx, transaction, _ := newTestFakeTCPPolicyGenerationTransaction(t, 91)
	options := fixture.buildOptions(transaction)
	options.xdpRequirement = fakeTCPXDPRequireAllHooksExclusive
	runtime, err := buildExperimentalFakeTCPRuntime(ctx, options)
	if runtime != nil || err == nil || !strings.Contains(err.Error(), "all-hooks exclusive activation") {
		t.Fatalf("runtime=%#v error=%v", runtime, err)
	}
	if fixture.commitCalls != 0 || len(fixture.xdpRuntime.probeCalls) != 0 ||
		len(fixture.xdpRuntime.attachCalls) != 0 || len(fixture.programArray.inserts) != 0 ||
		fixture.sessionStore.closes != 0 {
		t.Fatalf(
			"strict refusal commits=%d probes=%v attaches=%v programs=%v session closes=%d",
			fixture.commitCalls, fixture.xdpRuntime.probeCalls,
			fixture.xdpRuntime.attachCalls, fixture.programArray.inserts,
			fixture.sessionStore.closes,
		)
	}
}

func TestExperimentalFakeTCPRuntimeBindsCanonicalInterfacesBeforeMutation(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *experimentalFakeTCPRuntimeBuildOptions)
		match  string
	}{
		{
			name: "empty canonical state",
			mutate: func(_ *testing.T, options *experimentalFakeTCPRuntimeBuildOptions) {
				options.attachState = &control.State{Generation: 7}
				options.baselineSnapshot.Underlays = map[abi.UnderlayConfigKey]abi.UnderlayConfigValue{}
			},
			match: "contains no attachable underlay",
		},
		{
			name: "stale baseline generation",
			mutate: func(_ *testing.T, options *experimentalFakeTCPRuntimeBuildOptions) {
				for key, value := range options.baselineSnapshot.Underlays {
					delete(options.baselineSnapshot.Underlays, key)
					key.Generation--
					value.Generation--
					options.baselineSnapshot.Underlays[key] = value
					break
				}
			},
			match: "baseline underlays are stale or unrelated",
		},
		{
			name: "stale baseline control",
			mutate: func(_ *testing.T, options *experimentalFakeTCPRuntimeBuildOptions) {
				value := options.baselineSnapshot.Control[abi.ControlKeyGlobal]
				value.ABIVersion++
				options.baselineSnapshot.Control[abi.ControlKeyGlobal] = value
			},
			match: "baseline control are stale or unrelated",
		},
		{
			name: "unrelated baseline profile",
			mutate: func(_ *testing.T, options *experimentalFakeTCPRuntimeBuildOptions) {
				generation := options.transaction.policyGeneration()
				options.baselineSnapshot.Profiles[abi.ProfileKey{
					Generation: generation, ProfileID: 99,
				}] = abi.ProfileValue{Generation: generation}
			},
			match: "baseline profiles are stale or unrelated",
		},
		{
			name: "unrelated baseline cipher",
			mutate: func(_ *testing.T, options *experimentalFakeTCPRuntimeBuildOptions) {
				generation := options.transaction.policyGeneration()
				options.baselineSnapshot.Ciphers[abi.CipherKey{
					Generation: generation, CipherID: 99,
				}] = abi.CipherValue{Generation: generation}
			},
			match: "baseline ciphers are stale or unrelated",
		},
		{
			name: "unrelated baseline managed fwmark",
			mutate: func(_ *testing.T, options *experimentalFakeTCPRuntimeBuildOptions) {
				generation := options.transaction.policyGeneration()
				options.baselineSnapshot.ManagedFwmarks[abi.ManagedFwmarkKey{
					Generation: generation, FwMark: 99, UnderlayIndex: 3,
				}] = abi.ManagedFwmarkValue{Generation: generation}
			},
			match: "baseline managed fwmarks are stale or unrelated",
		},
		{
			name: "unrelated baseline egress rule",
			mutate: func(_ *testing.T, options *experimentalFakeTCPRuntimeBuildOptions) {
				generation := options.transaction.policyGeneration()
				options.baselineSnapshot.EgressRules[abi.EgressRuleKey{
					Generation: generation, FwMark: 99, UnderlayIndex: 3,
				}] = abi.EgressRuleValue{Generation: generation}
			},
			match: "baseline egress rules are stale or unrelated",
		},
		{
			name: "stale baseline ingress listener",
			mutate: func(_ *testing.T, options *experimentalFakeTCPRuntimeBuildOptions) {
				for key, value := range options.baselineSnapshot.IngressListeners {
					value.WGID++
					options.baselineSnapshot.IngressListeners[key] = value
					break
				}
			},
			match: "baseline ingress listeners are stale or unrelated",
		},
		{
			name: "unrelated baseline ICMP listener",
			mutate: func(_ *testing.T, options *experimentalFakeTCPRuntimeBuildOptions) {
				generation := options.transaction.policyGeneration()
				options.baselineSnapshot.ICMPListeners[abi.ICMPListenerKey{
					Generation: generation, UnderlayIndex: 3, ICMPID: 99,
				}] = abi.ICMPListenerValue{Generation: generation}
			},
			match: "baseline ICMP listeners are stale or unrelated",
		},
		{
			name: "stale FakeTCP managed port",
			mutate: func(_ *testing.T, options *experimentalFakeTCPRuntimeBuildOptions) {
				options.transaction.plan.managedPorts[0].Key.DestinationPort++
			},
			match: "managed ports are stale or unrelated",
		},
		{
			name: "stale FakeTCP control policy",
			mutate: func(_ *testing.T, options *experimentalFakeTCPRuntimeBuildOptions) {
				options.transaction.plan.controlPolicies[0].Value.Burst++
			},
			match: "control policies are stale or unrelated",
		},
		{
			name: "unrelated FakeTCP interface",
			mutate: func(t *testing.T, options *experimentalFakeTCPRuntimeBuildOptions) {
				state := fakeTCPPolicyTestState()
				state.Underlays[1].IfIndex = 11
				state.IngressListeners[1].UnderlayIfIndex = 11
				baseline, err := abi.FromStateWithGeneration(
					state,
					options.transaction.policyGeneration(),
				)
				if err != nil {
					t.Fatal(err)
				}
				options.attachState = state
				options.baselineSnapshot = baseline
			},
			match: "managed interfaces are stale or unrelated",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRuntimeTestFixture(t)
			ctx, transaction, _ := newTestFakeTCPPolicyGenerationTransaction(t, 91)
			options := fixture.buildOptions(transaction)
			test.mutate(t, &options)
			runtime, err := buildExperimentalFakeTCPRuntime(ctx, options)
			if runtime != nil || err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("runtime=%#v error=%v", runtime, err)
			}
			if fixture.commitCalls != 0 || fixture.collection.freshRuntimeClaimConsumed ||
				len(fixture.xdpRuntime.probeCalls) != 0 || len(fixture.programArray.inserts) != 0 ||
				fixture.sessionStore.closes != 0 {
				t.Fatalf(
					"canonical preflight commits=%d consumed=%t probes=%v programs=%v session closes=%d",
					fixture.commitCalls, fixture.collection.freshRuntimeClaimConsumed,
					fixture.xdpRuntime.probeCalls, fixture.programArray.inserts,
					fixture.sessionStore.closes,
				)
			}
		})
	}
}

func TestExperimentalRuntimeCloseQuarantinesFailedDetachesUntilRetry(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	xdpErr := errors.New("XDP close")
	tcErr := errors.New("TC close")
	fixture.xdpRuntime.links[3] = &fakeOwnedXDPLink{
		identity: fakeTCPXDPLinkIdentity{
			Family: fakeTCPXDPBackendDirect, Mode: fakeTCPXDPAttachNative,
			IfIndex: 3, ProgramID: 8002, OwnerID: 100003,
		},
		releaseErrs: []error{xdpErr}, retainOnError: []bool{true},
	}
	runtime, _, err := fixture.build(t, 91)
	if err != nil {
		t.Fatal(err)
	}
	fixture.lastTCStage.closeErr = tcErr
	err = runtime.Close()
	for _, want := range []error{xdpErr, tcErr} {
		if !errors.Is(err, want) {
			t.Fatalf("close error %v does not contain %v", err, want)
		}
	}
	if runtime.state.closed || runtime.state.xdp == nil || runtime.state.tc == nil ||
		runtime.state.core == nil || runtime.state.collection == nil {
		t.Fatalf(
			"failed detach owner closed=%t xdp=%#v tc=%#v core=%#v collection=%#v",
			runtime.state.closed, runtime.state.xdp, runtime.state.tc,
			runtime.state.core, runtime.state.collection,
		)
	}
	if _, err := runtime.Handles(); !errors.Is(err, ErrExperimentalFakeTCPRuntimeClosed) {
		t.Fatalf("quarantined Handles error = %v", err)
	}
	for name, resource := range fixture.mapResources {
		if resource.closes != 0 {
			t.Fatalf("unsafe dependency close reached map %s: %d", name, resource.closes)
		}
	}
	fixture.lastTCStage.closeErr = nil
	if err := runtime.Close(); err != nil {
		t.Fatalf("retry Close: %v", err)
	}
	if !runtime.state.closed || runtime.state.collection != nil ||
		fixture.xdpRuntime.links[3].closes != 2 || fixture.lastTCStage.closes != 2 {
		t.Fatalf(
			"retry closed=%t collection=%#v xdp closes=%d tc closes=%d",
			runtime.state.closed, runtime.state.collection,
			fixture.xdpRuntime.links[3].closes, fixture.lastTCStage.closes,
		)
	}
}

func TestFakeTCPDaemonLifecycleRetainsRuntimeOnStaleXDPOwner(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	runtime, _, err := fixture.build(t, 91)
	if err != nil {
		t.Fatal(err)
	}
	owned := fixture.xdpRuntime.links[3]
	stale := owned.identity
	stale.OwnerID++
	owned.setIdentity(stale)

	supervisor := &fakeTCPRuntimeSupervisor{}
	key := fakeTCPRuntimeDesiredKey{91}
	if err := supervisor.Ensure(
		t.Context(), key,
		func(context.Context) (fakeTCPRuntimeService, error) { return runtime, nil },
	); err != nil {
		t.Fatal(err)
	}
	select {
	case <-supervisor.loadCurrent().done:
	case <-time.After(time.Second):
		t.Fatal("test runtime did not reach its daemon lifecycle boundary")
	}
	if err := supervisor.Stop(t.Context()); err == nil ||
		!strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("daemon Stop stale-owner error = %v", err)
	}
	if supervisor.loadCurrent() == nil || runtime.state.xdp == nil ||
		runtime.state.collection == nil {
		t.Fatal("daemon discarded the only stale XDP ownership capability")
	}
	if owned.closes != 0 {
		t.Fatalf("stale daemon owner triggered %d destructive closes", owned.closes)
	}
	for name, resource := range fixture.mapResources {
		if resource.closes != 0 {
			t.Fatalf("stale XDP owner released dependent map %s", name)
		}
	}
}

func TestExperimentalRuntimeBuildFailureQuarantinesRetainedTCRollback(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	ctx, transaction, _ := newTestFakeTCPPolicyGenerationTransaction(t, 91)
	commitErr := errors.New("injected core commit failure")
	tcCloseErr := errors.New("injected retained TC rollback failure")
	options := fixture.buildOptions(transaction)
	options.coreStageFactory = func(
		context.Context,
		experimentalCoreResources,
		*abi.Snapshot,
	) (experimentalCoreStageOwner, error) {
		stage := &fakeExperimentalCoreStage{
			trace: &fixture.activationTrace, commitErr: commitErr,
		}
		fixture.lastCoreStage = stage
		return stage, nil
	}
	options.tcStageFactory = func(
		_ context.Context,
		_ *control.State,
		_, _ experimentalProgramResource,
		commit func() error,
	) (experimentalTCStageOwner, error) {
		stage := &fakeExperimentalTCStage{
			trace: &fixture.activationTrace, closeErr: tcCloseErr,
		}
		fixture.lastTCStage = stage
		return stage, commit()
	}

	runtime, err := buildExperimentalFakeTCPRuntime(ctx, options)
	if runtime == nil || !errors.Is(err, commitErr) || !errors.Is(err, tcCloseErr) {
		t.Fatalf("runtime=%#v error=%v", runtime, err)
	}
	if runtime.state.failedBuild == nil || runtime.state.closed || fixture.lastTCStage.closes != 1 {
		t.Fatalf(
			"failed build=%#v closed=%t TC closes=%d",
			runtime.state.failedBuild, runtime.state.closed, fixture.lastTCStage.closes,
		)
	}
	if transaction.isClosed() || len(fixture.programArray.deletes) != 0 ||
		len(fixture.policyTrace.deleteAttempts) != 0 {
		t.Fatalf(
			"quarantine transaction closed=%t programs=%v policy deletes=%v",
			transaction.isClosed(), fixture.programArray.deletes,
			fixture.policyTrace.deleteAttempts,
		)
	}
	for name, resource := range fixture.mapResources {
		if resource.closes != 0 {
			t.Fatalf("live rollback dependency map %s closed=%d", name, resource.closes)
		}
	}
	if _, handlesErr := runtime.Handles(); !errors.Is(
		handlesErr, ErrExperimentalFakeTCPRuntimeClosed,
	) {
		t.Fatalf("quarantined Handles error = %v", handlesErr)
	}

	fixture.lastTCStage.closeErr = nil
	if closeErr := runtime.Close(); closeErr != nil {
		t.Fatalf("retry failed-build Close: %v", closeErr)
	}
	if !runtime.state.closed || runtime.state.failedBuild != nil ||
		!transaction.isClosed() || fixture.lastTCStage.closes != 2 {
		t.Fatalf(
			"retry closed=%t failed build=%#v transaction closed=%t TC closes=%d",
			runtime.state.closed, runtime.state.failedBuild,
			transaction.isClosed(), fixture.lastTCStage.closes,
		)
	}
	if len(fixture.programArray.deletes) == 0 || len(fixture.policyTrace.deleteAttempts) == 0 {
		t.Fatalf(
			"retry did not roll back programs=%v policy deletes=%v",
			fixture.programArray.deletes, fixture.policyTrace.deleteAttempts,
		)
	}
}

func TestExperimentalSlowPathConstructionFailureQuarantinesPartialOwner(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	ctx, transaction, _ := newTestFakeTCPPolicyGenerationTransaction(t, 91)
	factoryErr := errors.New("injected slow-path factory failure")
	closeErr := errors.New("injected partial slow-path close failure")
	fixture.slowPath.closeErr = closeErr
	options := fixture.buildOptions(transaction)
	options.slowPathFactory = func(*faketcp.Engine, *ebpf.Map, *ebpf.Map) (experimentalSlowPath, error) {
		return fixture.slowPath, factoryErr
	}
	runtime, err := buildExperimentalFakeTCPRuntime(ctx, options)
	if runtime == nil || !errors.Is(err, factoryErr) || !errors.Is(err, closeErr) {
		t.Fatalf("runtime=%#v error=%v", runtime, err)
	}
	if _, _, closes := fixture.slowPath.counts(); closes != 2 {
		t.Fatalf("partial slow-path closes = %d, want constructor plus cleanup", closes)
	}
	if _, handlesErr := runtime.Handles(); !errors.Is(
		handlesErr, ErrExperimentalFakeTCPRuntimeClosed,
	) {
		t.Fatalf("quarantined Handles error = %v", handlesErr)
	}
	for name, resource := range fixture.mapResources {
		if resource.closes != 0 {
			t.Fatalf("partial slow path failure reached map %s close=%d", name, resource.closes)
		}
	}
	fixture.slowPath.closeErr = nil
	if err := runtime.Close(); err != nil {
		t.Fatalf("retry partial owner Close: %v", err)
	}
	if !runtime.state.closed {
		t.Fatal("partial owner quarantine did not converge")
	}
}

func TestExperimentalSlowPathTypedNilFailsClosed(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	ctx, transaction, _ := newTestFakeTCPPolicyGenerationTransaction(t, 91)
	options := fixture.buildOptions(transaction)
	options.slowPathFactory = func(*faketcp.Engine, *ebpf.Map, *ebpf.Map) (experimentalSlowPath, error) {
		var typedNil *fakeExperimentalSlowPath
		return typedNil, nil
	}
	runtime, err := buildExperimentalFakeTCPRuntime(ctx, options)
	if runtime != nil || err == nil || !strings.Contains(err.Error(), "returned nil") {
		t.Fatalf("runtime=%#v error=%v", runtime, err)
	}
}

func TestExperimentalEventCloneCloseFailureClosesConstructedSlowPath(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	ctx, transaction, _ := newTestFakeTCPPolicyGenerationTransaction(t, 91)
	wantErr := errors.New("injected slow-path constructor clone close failure")
	fixture.eventSource.closeErr = wantErr
	runtime, err := buildExperimentalFakeTCPRuntime(
		ctx,
		fixture.buildOptions(transaction),
	)
	if runtime != nil || !errors.Is(err, wantErr) {
		t.Fatalf("runtime=%#v error=%v", runtime, err)
	}
	if _, _, closes := fixture.slowPath.counts(); closes != 1 {
		t.Fatalf("constructed slow-path closes = %d", closes)
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
	if clones != 2 || closes != 2 {
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
	ctx, transaction, _ := newTestFakeTCPPolicyGenerationTransaction(t, 91)
	policyMaps, _ := newMemoryFakeTCPPolicyMaps()
	stage, err := transaction.Stage(ctx, policyMaps)
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
