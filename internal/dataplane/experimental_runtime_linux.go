//go:build linux

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/syx0310/wg-mix-ebpf/internal/abi"
	"github.com/syx0310/wg-mix-ebpf/internal/control"
	"github.com/syx0310/wg-mix-ebpf/internal/faketcp"
)

const (
	fakeTCPSessionMapName          = "faketcp_session_map"
	fakeTCPEventsMapName           = "faketcp_events"
	fakeTCPStatsMapName            = "faketcp_stats_map"
	fakeTCPRuntimeIDMapName        = "faketcp_rt_id"
	fakeTCPCaptureSeqMapName       = "faketcp_cap_seq"
	fakeTCPEgressProgramName       = "wg_faketcp_egress"
	fakeTCPXDPProgramName          = "wg_mix_faketcp_ingress"
	fakeTCPSessionClaimProgramName = "wg_faketcp_session_claim"
)

var (
	ErrExperimentalFakeTCPRuntimeClosed      = errors.New("experimental FakeTCP runtime is closed")
	ErrExperimentalFakeTCPGenerationMismatch = errors.New("experimental FakeTCP runtime generation mismatch")
)

type ownedFakeTCPSessionStore interface {
	faketcp.SessionStore
	Close() error
}

type experimentalSessionStoreFactory func(
	experimentalMapResource,
	experimentalProgramResource,
	uint64,
) (ownedFakeTCPSessionStore, error)

type experimentalSlowPath interface {
	faketcp.RuntimeService
	faketcp.RuntimeStopRequester
}

type experimentalSlowPathFactory func(
	*faketcp.Engine,
	*ebpf.Map,
	*ebpf.Map,
) (experimentalSlowPath, error)

type experimentalLinuxGenerationCommit func(
	*faketcp.Engine,
	faketcp.LinuxFreshCollectionClaim,
	func(faketcp.LinuxFreshCollectionRelease) error,
) error

type experimentalCoreStageOwner interface {
	CommitControl() error
	Deactivate() error
	Close() error
}

type experimentalCoreStageFactory func(
	context.Context,
	experimentalCoreResources,
	*abi.Snapshot,
) (experimentalCoreStageOwner, error)

type experimentalTCStageOwner interface {
	Close() error
}

type experimentalTCStageFactory func(
	context.Context,
	*control.State,
	experimentalProgramResource,
	experimentalProgramResource,
	func() error,
) (experimentalTCStageOwner, error)

type fakeTCPPolicyGenerationCollectionBinder interface {
	BindCollection(context.Context, *experimentalCollectionOwner, faketcp.RuntimeIdentity) error
}

type experimentalEventMapClone struct {
	bpfMap *ebpf.Map
	close  func() error
}

type experimentalEventMapSource interface {
	Clone() (*experimentalEventMapClone, error)
}

type liveExperimentalEventMapSource struct {
	bpfMap *ebpf.Map
}

func (source liveExperimentalEventMapSource) Clone() (*experimentalEventMapClone, error) {
	if source.bpfMap == nil {
		return nil, errors.New("experimental FakeTCP events map is nil")
	}
	cloned, err := source.bpfMap.Clone()
	if err != nil {
		return nil, fmt.Errorf("clone experimental FakeTCP events map: %w", err)
	}
	if cloned == nil {
		return nil, errors.New("clone experimental FakeTCP events map returned nil")
	}
	return &experimentalEventMapClone{bpfMap: cloned, close: cloned.Close}, nil
}

func newLiveExperimentalSessionStore(
	resource experimentalMapResource,
	claimResource experimentalProgramResource,
	generation uint64,
) (ownedFakeTCPSessionStore, error) {
	bpfMap, ok := resource.(*ebpf.Map)
	if !ok || bpfMap == nil {
		return nil, errors.New("experimental FakeTCP session resource is not a live eBPF map")
	}
	if claimResource == nil || claimResource.kernelProgram() == nil {
		return nil, errors.New("experimental FakeTCP session claim resource is not a live eBPF program")
	}
	identity, err := faketcp.InspectLinuxSessionMapIdentity(bpfMap)
	if err != nil {
		return nil, fmt.Errorf("inspect experimental FakeTCP session map: %w", err)
	}
	compareDelete, err := faketcp.NewLinuxAtomicSessionCompareDeleter(
		bpfMap, claimResource.kernelProgram(), identity,
	)
	if err != nil {
		return nil, fmt.Errorf("bind experimental FakeTCP session claim program: %w", err)
	}
	store, err := faketcp.NewLinuxSessionStoreWithAtomicCompareDelete(
		bpfMap, generation, identity, compareDelete,
	)
	if err != nil {
		return nil, fmt.Errorf("own experimental FakeTCP session map: %w", err)
	}
	return store, nil
}

// generationFencedSessionStore is retained for the complete userspace
// backend lifetime. The only per-operation work is a generation/closed check;
// packets themselves stay entirely in BPF maps and programs with no
// userspace lookup or copy. Its lock also prevents a concurrent runtime Close
// from closing the private map clone under an admitted operation.
type generationFencedSessionStore struct {
	mu         sync.RWMutex
	generation uint64
	backend    ownedFakeTCPSessionStore
	shutdown   bool
	closed     bool
	closeErr   error
}

// generationFencedEventMap exposes the collection map only through a
// short-lived clone used to construct a ring/perf reader. The callback may
// retain the reader it constructs, but must not retain the raw *ebpf.Map: the
// clone is closed before WithEventsMap returns. Close waits for an admitted
// constructor callback before allowing the collection to be destroyed.
type generationFencedEventMap struct {
	mu         sync.RWMutex
	generation uint64
	source     experimentalEventMapSource
	closed     bool
}

func newGenerationFencedEventMap(
	generation uint64,
	source experimentalEventMapSource,
) (*generationFencedEventMap, error) {
	if generation == 0 {
		return nil, errors.New("experimental FakeTCP event-map fence generation is zero")
	}
	if experimentalEventMapSourceIsNil(source) {
		return nil, errors.New("experimental FakeTCP event-map source is nil")
	}
	return &generationFencedEventMap{generation: generation, source: source}, nil
}

func experimentalEventMapSourceIsNil(source experimentalEventMapSource) bool {
	if source == nil {
		return true
	}
	value := reflect.ValueOf(source)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (events *generationFencedEventMap) withMap(
	callback func(*ebpf.Map) error,
) (returnErr error) {
	if events == nil {
		return ErrExperimentalFakeTCPRuntimeClosed
	}
	if callback == nil {
		return errors.New("experimental FakeTCP events-map callback is nil")
	}
	events.mu.RLock()
	defer events.mu.RUnlock()
	if events.closed || events.source == nil {
		return ErrExperimentalFakeTCPRuntimeClosed
	}
	cloned, err := events.source.Clone()
	if err != nil {
		return errors.Join(err, closeExperimentalEventMapClone(cloned))
	}
	if cloned == nil || cloned.bpfMap == nil || cloned.close == nil {
		return errors.Join(
			errors.New("experimental FakeTCP events-map source returned an incomplete clone"),
			closeExperimentalEventMapClone(cloned),
		)
	}
	defer func() {
		returnErr = errors.Join(returnErr, closeExperimentalEventMapClone(cloned))
	}()
	return callback(cloned.bpfMap)
}

func closeExperimentalEventMapClone(cloned *experimentalEventMapClone) error {
	if cloned == nil || cloned.close == nil {
		return nil
	}
	closeFn := cloned.close
	cloned.close = nil
	return wrapNonNilError(
		"close experimental FakeTCP events-map constructor clone",
		closeFn(),
	)
}

func (events *generationFencedEventMap) Close() error {
	if events == nil {
		return nil
	}
	events.mu.Lock()
	defer events.mu.Unlock()
	events.closed = true
	events.source = nil
	return nil
}

func newGenerationFencedSessionStore(
	generation uint64,
	backend ownedFakeTCPSessionStore,
) (*generationFencedSessionStore, error) {
	if generation == 0 {
		return nil, errors.New("experimental FakeTCP session fence generation is zero")
	}
	if ownedFakeTCPSessionStoreIsNil(backend) {
		return nil, errors.New("experimental FakeTCP session fence backend is nil")
	}
	return &generationFencedSessionStore{generation: generation, backend: backend}, nil
}

func ownedFakeTCPSessionStoreIsNil(store ownedFakeTCPSessionStore) bool {
	if store == nil {
		return true
	}
	value := reflect.ValueOf(store)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func experimentalSlowPathIsNil(slowPath experimentalSlowPath) bool {
	if slowPath == nil {
		return true
	}
	value := reflect.ValueOf(slowPath)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (store *generationFencedSessionStore) InsertEstablished(
	key abi.FakeTCPSessionKey,
	value abi.FakeTCPSessionValue,
) error {
	if store == nil {
		return ErrExperimentalFakeTCPRuntimeClosed
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if err := store.validateLocked(key.Generation, value.Generation); err != nil {
		return err
	}
	return store.backend.InsertEstablished(key, value)
}

func (store *generationFencedSessionStore) LookupEstablished(
	key abi.FakeTCPSessionKey,
) (abi.FakeTCPSessionValue, bool, error) {
	if store == nil {
		return abi.FakeTCPSessionValue{}, false, ErrExperimentalFakeTCPRuntimeClosed
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if err := store.validateLocked(key.Generation); err != nil {
		return abi.FakeTCPSessionValue{}, false, err
	}
	return store.backend.LookupEstablished(key)
}

func (store *generationFencedSessionStore) DeleteEstablishedIfUnchanged(
	key abi.FakeTCPSessionKey,
	value abi.FakeTCPSessionValue,
) (faketcp.SessionDeleteResult, error) {
	if store == nil {
		return faketcp.SessionDeleteDifferent, ErrExperimentalFakeTCPRuntimeClosed
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if err := store.validateLocked(key.Generation, value.Generation); err != nil {
		return faketcp.SessionDeleteDifferent, err
	}
	return store.backend.DeleteEstablishedIfUnchanged(key, value)
}

func (store *generationFencedSessionStore) validateLocked(generations ...uint64) error {
	if store == nil || store.shutdown || store.closed || store.backend == nil {
		return ErrExperimentalFakeTCPRuntimeClosed
	}
	for _, generation := range generations {
		if generation != store.generation {
			return fmt.Errorf(
				"%w: handle generation %d, operation generation %d",
				ErrExperimentalFakeTCPGenerationMismatch,
				store.generation,
				generation,
			)
		}
	}
	return nil
}

func (store *generationFencedSessionStore) Close() error {
	if store == nil {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return nil
	}
	store.shutdown = true
	backend := store.backend
	store.closeErr = backend.Close()
	if store.closeErr == nil {
		store.backend = nil
		store.closed = true
	}
	return store.closeErr
}

// ExperimentalFakeTCPRuntimeHandles are borrowed from one runtime generation
// and may be retained by its userspace controller. SessionStore remains the
// same fenced object for the generation lifetime; it never clones a map or
// copies packet payloads per operation.
type ExperimentalFakeTCPRuntimeHandles struct {
	generation uint64
	identity   faketcp.RuntimeIdentity
	sessions   *generationFencedSessionStore
	events     *generationFencedEventMap
}

func (handles ExperimentalFakeTCPRuntimeHandles) Generation() uint64 {
	return handles.generation
}

func (handles ExperimentalFakeTCPRuntimeHandles) Identity() faketcp.RuntimeIdentity {
	return handles.identity
}

func (handles ExperimentalFakeTCPRuntimeHandles) SessionStore() faketcp.SessionStore {
	if handles.sessions == nil {
		return nil
	}
	return handles.sessions
}

// WithEventsMap lends a short-lived clone of the generation's exact events
// map to a reader constructor. The callback may retain the constructed reader,
// but it must not retain the raw map pointer. The clone is always closed before
// this method returns, and runtime Close waits for the callback to finish. The
// callback must not synchronously call Close on its owning runtime.
func (handles ExperimentalFakeTCPRuntimeHandles) WithEventsMap(
	callback func(*ebpf.Map) error,
) error {
	if handles.events == nil {
		return ErrExperimentalFakeTCPRuntimeClosed
	}
	return handles.events.withMap(callback)
}

// ExperimentalFakeTCPRuntime owns one complete unpinned collection, its XDP
// links, and the userspace session-map clone. Runtime values may be copied:
// every copy shares one close state and the same exactly-once resource owner.
// The zero value is closed.
type ExperimentalFakeTCPRuntime struct {
	state *experimentalFakeTCPRuntimeState
}

var (
	_ faketcp.RuntimeService       = (*ExperimentalFakeTCPRuntime)(nil)
	_ faketcp.RuntimeStopRequester = (*ExperimentalFakeTCPRuntime)(nil)
)

type experimentalFakeTCPRuntimeState struct {
	mu sync.Mutex

	generation  uint64
	identity    faketcp.RuntimeIdentity
	engine      *faketcp.Engine
	collection  *experimentalCollectionOwner
	isolation   fakeTCPPolicyGenerationIsolationBackend
	core        experimentalCoreStageOwner
	tc          experimentalTCStageOwner
	xdp         *fakeTCPXDPStage
	slowPath    experimentalSlowPath
	handles     ExperimentalFakeTCPRuntimeHandles
	closing     bool
	closed      bool
	shutdown    bool
	closeErr    error
	closeDone   chan struct{}
	failedBuild *experimentalRuntimeBuild
}

var errExperimentalFreshCollectionReleaseConsumed = errors.New(
	"experimental FakeTCP fresh collection release capability is consumed",
)

// experimentalLinuxFreshCollectionClaim binds the userspace seed API to the
// exact collection and retained lifecycle/runtime-build claim owned by one
// builder. Copies share a single callback and release state. The callback is
// synchronous and release performs the builder's final commit from inside
// makeReachable; WithExclusiveFreshFakeTCPCollection does no work afterwards.
type experimentalLinuxFreshCollectionClaim struct {
	state *experimentalLinuxFreshCollectionClaimState
}

type experimentalLinuxFreshCollectionClaimState struct {
	mu sync.Mutex

	transaction      *fakeTCPPolicyRuntimeBuildClaim
	claimCtx         context.Context
	collection       *experimentalCollectionOwner
	release          func() error
	entered          bool
	callbackReturned bool
	releaseCalls     int
	releaseStarted   bool
	releaseCompleted bool
	releaseDone      chan struct{}
	releaseErr       error
}

var _ faketcp.LinuxFreshCollectionClaim = experimentalLinuxFreshCollectionClaim{}

type experimentalLinuxMapProvider interface {
	linuxMap() *ebpf.Map
}

func linuxMapFromExperimentalResource(resource experimentalMapResource) (*ebpf.Map, bool) {
	switch resource := resource.(type) {
	case *ebpf.Map:
		return resource, resource != nil
	case experimentalLinuxMapProvider:
		bpfMap := resource.linuxMap()
		return bpfMap, bpfMap != nil
	default:
		return nil, false
	}
}

func (claim *fakeTCPPolicyRuntimeBuildClaim) bindIsolationCollection(
	ctx context.Context,
	owner *experimentalCollectionOwner,
	identity faketcp.RuntimeIdentity,
) (fakeTCPPolicyGenerationIsolationBackend, error) {
	if claim == nil || claim.transaction == nil {
		return nil, errFakeTCPPolicyGenerationLeaseRequired
	}
	transaction := claim.transaction
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if err := transaction.assertAccessLocked(ctx, claim); err != nil {
		return nil, err
	}
	if identity.Generation != transaction.plan.generation {
		return nil, errors.New("bind FakeTCP generation isolation: runtime identity generation mismatch")
	}
	isolation := transaction.isolation
	if binder, ok := isolation.(fakeTCPPolicyGenerationCollectionBinder); ok {
		if err := binder.BindCollection(ctx, owner, identity); err != nil {
			return nil, err
		}
	}
	return isolation, nil
}

func (claim experimentalLinuxFreshCollectionClaim) WithExclusiveFreshFakeTCPCollection(
	callback func(
		identityMap, sequenceMap *ebpf.Map,
		release faketcp.LinuxFreshCollectionRelease,
	) error,
) error {
	state := claim.state
	if state == nil {
		return errors.New("experimental FakeTCP fresh collection claim is nil")
	}
	if callback == nil {
		return errors.New("experimental FakeTCP fresh collection callback is nil")
	}
	state.mu.Lock()
	if state.entered {
		state.mu.Unlock()
		return errors.New("experimental FakeTCP fresh collection claim is single-use")
	}
	if state.transaction == nil || state.claimCtx == nil ||
		state.collection == nil || state.release == nil {
		state.mu.Unlock()
		return errors.New("experimental FakeTCP fresh collection claim is incomplete")
	}
	if err := state.transaction.assertHeld(state.claimCtx); err != nil {
		state.mu.Unlock()
		return fmt.Errorf("validate experimental FakeTCP fresh collection ownership: %w", err)
	}
	state.entered = true
	collection := state.collection
	state.mu.Unlock()

	// Hold the exact collection owner across the complete callback. This
	// prevents concurrent Close from invalidating either borrowed map while
	// seed and all reachability mutations execute. Consumption is sticky even
	// when map validation, seed, or reachability later fails.
	collection.mu.Lock()
	defer collection.mu.Unlock()
	if collection.closing || collection.closed {
		return errExperimentalCollectionClosed
	}
	if collection.freshRuntimeClaimConsumed {
		return errors.New("experimental FakeTCP collection fresh claim is consumed")
	}
	collection.freshRuntimeClaimConsumed = true
	identityMap, ok := linuxMapFromExperimentalResource(collection.maps[fakeTCPRuntimeIDMapName])
	if !ok {
		return errors.New("experimental FakeTCP runtime identity resource is not a live eBPF map")
	}
	sequenceMap, ok := linuxMapFromExperimentalResource(collection.maps[fakeTCPCaptureSeqMapName])
	if !ok {
		return errors.New("experimental FakeTCP capture sequence resource is not a live eBPF map")
	}
	callbackErr := callback(identityMap, sequenceMap, state.releaseOnceOnly)
	state.finishCallback()
	return callbackErr
}

func (state *experimentalLinuxFreshCollectionClaimState) releaseOnceOnly() error {
	if state == nil {
		return errors.New("experimental FakeTCP fresh collection release is nil")
	}
	state.mu.Lock()
	state.releaseCalls++
	if state.callbackReturned || state.releaseStarted {
		err := state.releaseErr
		state.mu.Unlock()
		return errors.Join(errExperimentalFreshCollectionReleaseConsumed, err)
	}
	state.releaseStarted = true
	state.releaseDone = make(chan struct{})
	done := state.releaseDone
	transaction := state.transaction
	claimCtx := state.claimCtx
	release := state.release
	state.mu.Unlock()

	var err error
	if err = transaction.assertHeld(claimCtx); err != nil {
		err = fmt.Errorf("validate experimental FakeTCP ownership before release: %w", err)
	} else {
		err = release()
	}
	state.mu.Lock()
	state.releaseErr = err
	state.releaseCompleted = true
	close(done)
	state.mu.Unlock()
	return err
}

func (state *experimentalLinuxFreshCollectionClaimState) finishCallback() {
	state.mu.Lock()
	state.callbackReturned = true
	done := state.releaseDone
	wait := state.releaseStarted && !state.releaseCompleted
	state.mu.Unlock()
	if wait {
		<-done
	}
}

type experimentalFakeTCPRuntimeBuildOptions struct {
	collection       *experimentalCollectionOwner
	transaction      *fakeTCPPolicyGenerationTransaction
	baselineSnapshot *abi.Snapshot
	attachState      *control.State
	xdpRequests      []fakeTCPXDPAttachRequest
	xdpRuntime       fakeTCPXDPRuntime
	xdpRequirement   fakeTCPXDPActivationRequirement
	sessionFactory   experimentalSessionStoreFactory
	eventSource      experimentalEventMapSource
	programArray     fakeTCPProgramArray
	engineOptions    faketcp.Options
	slowPathFactory  experimentalSlowPathFactory
	commitGeneration experimentalLinuxGenerationCommit
	coreStageFactory experimentalCoreStageFactory
	tcStageFactory   experimentalTCStageFactory
}

// buildExperimentalFakeTCPRuntime transfers ownership of both collection and
// transaction only after atomically claiming a fresh transaction. Errors
// before that handoff leave both resources with the caller. Once the claim
// succeeds, every success or failure path consumes the transaction and closes
// its retained lifecycle lease; success transfers collection ownership onward
// to the returned runtime.
func buildExperimentalFakeTCPRuntime(
	ctx context.Context,
	options experimentalFakeTCPRuntimeBuildOptions,
) (*ExperimentalFakeTCPRuntime, error) {
	if ctx == nil {
		return nil, errors.New("build experimental FakeTCP runtime: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if options.transaction == nil {
		return nil, fmt.Errorf(
			"build experimental FakeTCP runtime: %w",
			errFakeTCPPolicyGenerationLeaseRequired,
		)
	}
	claim, err := options.transaction.claimRuntimeBuild(ctx)
	if err != nil {
		return nil, fmt.Errorf("build experimental FakeTCP runtime: %w", err)
	}
	cleanupCtx := context.WithoutCancel(ctx)
	build := &experimentalRuntimeBuild{
		options:    options,
		claim:      claim,
		activeCtx:  ctx,
		cleanupCtx: cleanupCtx,
	}
	if err := build.prepare(); err != nil {
		return build.fail(err)
	}
	if err := build.activate(); err != nil {
		if build.committed.Load() {
			return build.failCommitted(err)
		}
		return build.fail(err)
	}
	return build.runtimeOwner(), nil
}

func (build *experimentalRuntimeBuild) runtimeOwner() *ExperimentalFakeTCPRuntime {
	generation := build.policyPlan.generation
	return &ExperimentalFakeTCPRuntime{
		state: &experimentalFakeTCPRuntimeState{
			generation: generation,
			identity:   build.engine.Identity(),
			engine:     build.engine,
			collection: build.options.collection,
			isolation:  build.isolation,
			core:       build.coreStage,
			tc:         build.tcStage,
			xdp:        build.xdpStage,
			slowPath:   build.slowPath,
			handles: ExperimentalFakeTCPRuntimeHandles{
				generation: generation,
				identity:   build.engine.Identity(),
				sessions:   build.sessions,
				events:     build.events,
			},
			closeDone: make(chan struct{}),
		},
	}
}

func (build *experimentalRuntimeBuild) failedBuildOwner() *ExperimentalFakeTCPRuntime {
	var generation uint64
	if build != nil && build.policyPlan != nil {
		generation = build.policyPlan.generation
	}
	var identity faketcp.RuntimeIdentity
	if build != nil && build.engine != nil {
		identity = build.engine.Identity()
	}
	return &ExperimentalFakeTCPRuntime{state: &experimentalFakeTCPRuntimeState{
		generation:  generation,
		identity:    identity,
		shutdown:    true,
		failedBuild: build,
		closeDone:   make(chan struct{}),
	}}
}

type experimentalRuntimeBuild struct {
	options    experimentalFakeTCPRuntimeBuildOptions
	claim      *fakeTCPPolicyRuntimeBuildClaim
	activeCtx  context.Context
	cleanupCtx context.Context
	policyPlan *fakeTCPPolicyGenerationPlan

	sessions          *generationFencedSessionStore
	events            *generationFencedEventMap
	engine            *faketcp.Engine
	isolation         fakeTCPPolicyGenerationIsolationBackend
	slowPath          experimentalSlowPath
	freshClaim        experimentalLinuxFreshCollectionClaim
	policyMaps        fakeTCPPolicyMaps
	programArray      fakeTCPProgramArray
	egressProgram     experimentalProgramResource
	xdpProgram        experimentalProgramResource
	ingressProgram    experimentalProgramResource
	coreEgressProgram experimentalProgramResource
	coreResources     experimentalCoreResources
	coreStage         experimentalCoreStageOwner
	tcStage           experimentalTCStageOwner
	programStage      *fakeTCPProgramArrayStage
	xdpStage          *fakeTCPXDPStage
	policyStage       *fakeTCPPolicyStage
	committed         atomic.Bool
}

func (build *experimentalRuntimeBuild) prepare() error {
	options := build.options
	if err := build.activeContextError(); err != nil {
		return err
	}
	if options.collection == nil {
		return errors.New("build experimental FakeTCP runtime: collection owner is nil")
	}
	if build.claim == nil {
		return fmt.Errorf("build experimental FakeTCP runtime: %w", errFakeTCPPolicyGenerationLeaseRequired)
	}
	if err := build.claim.assertHeld(build.activeCtx); err != nil {
		return fmt.Errorf("build experimental FakeTCP runtime: %w", err)
	}
	build.policyPlan = build.claim.policyPlan()
	if err := validateFakeTCPPolicyGenerationPlan(build.policyPlan); err != nil {
		return fmt.Errorf("build experimental FakeTCP runtime policy plan: %w", err)
	}
	generation := build.policyPlan.generation
	if options.baselineSnapshot == nil {
		return errors.New("build experimental FakeTCP runtime: baseline snapshot is nil")
	}
	baselineControl, ok := options.baselineSnapshot.Control[abi.ControlKeyGlobal]
	if !ok || baselineControl.ActiveGeneration != generation {
		return fmt.Errorf(
			"build experimental FakeTCP runtime: baseline generation %d does not match FakeTCP generation %d",
			baselineControl.ActiveGeneration,
			generation,
		)
	}
	if options.attachState == nil {
		return errors.New("build experimental FakeTCP runtime: TC attach state is nil")
	}
	if err := validateExperimentalRuntimeCanonicalInterfaces(
		options.baselineSnapshot,
		build.policyPlan,
		options.attachState,
		options.xdpRequests,
	); err != nil {
		return err
	}
	if options.xdpRuntime.probe == nil || options.xdpRuntime.attach == nil {
		return errors.New("build experimental FakeTCP runtime: XDP backend is incomplete")
	}
	if err := validateFakeTCPXDPActivationRequirement(
		options.xdpRuntime.capabilities,
		options.xdpRequirement,
	); err != nil {
		return fmt.Errorf("build experimental FakeTCP runtime: %w", err)
	}
	if _, err := canonicalFakeTCPXDPRequests(
		options.xdpRequests, options.xdpRuntime.capabilities.Family,
	); err != nil {
		return fmt.Errorf("build experimental FakeTCP runtime: %w", err)
	}
	if options.engineOptions.Generation != generation {
		return fmt.Errorf(
			"build experimental FakeTCP runtime: Engine generation %d does not match policy plan generation %d",
			options.engineOptions.Generation, generation,
		)
	}
	if options.engineOptions.Store != nil {
		return errors.New("build experimental FakeTCP runtime: Engine Store must come from the claimed collection")
	}
	if options.slowPathFactory == nil {
		return errors.New("build experimental FakeTCP runtime: slow-path factory is nil")
	}
	if options.commitGeneration == nil {
		options.commitGeneration = faketcp.CommitLinuxGenerationReachability
	}
	build.options.commitGeneration = options.commitGeneration
	if options.coreStageFactory == nil {
		options.coreStageFactory = func(
			ctx context.Context,
			resources experimentalCoreResources,
			snapshot *abi.Snapshot,
		) (experimentalCoreStageOwner, error) {
			return stageExperimentalCoreCollection(
				ctx,
				resources,
				snapshot,
				experimentalCoreStageDependencies{},
			)
		}
	}
	build.options.coreStageFactory = options.coreStageFactory
	if options.tcStageFactory == nil {
		options.tcStageFactory = stageLiveExperimentalTC
	}
	build.options.tcStageFactory = options.tcStageFactory
	if options.sessionFactory == nil {
		options.sessionFactory = newLiveExperimentalSessionStore
	}
	build.options.sessionFactory = options.sessionFactory

	controlPolicies, err := options.collection.mapResource(fakeTCPControlPolicyMapName)
	if err != nil {
		return err
	}
	managedPorts, err := options.collection.mapResource(fakeTCPManagedPortMapName)
	if err != nil {
		return err
	}
	managedInterfaces, err := options.collection.mapResource(fakeTCPManagedIfMapName)
	if err != nil {
		return err
	}
	sessionMap, err := options.collection.mapResource(fakeTCPSessionMapName)
	if err != nil {
		return err
	}
	sessionClaimProgram, err := options.collection.programResource(fakeTCPSessionClaimProgramName)
	if err != nil {
		return err
	}
	eventsMap, err := options.collection.mapResource(fakeTCPEventsMapName)
	if err != nil {
		return err
	}
	statsResource, err := options.collection.mapResource(fakeTCPStatsMapName)
	if err != nil {
		return err
	}
	statsMap, ok := linuxMapFromExperimentalResource(statsResource)
	if !ok {
		return errors.New("experimental FakeTCP stats resource is not a live eBPF map")
	}
	programArrayResource, err := options.collection.mapResource(fakeTCPEgressProgramArrayMapName)
	if err != nil {
		return err
	}
	egressProgram, err := options.collection.programResource(fakeTCPEgressProgramName)
	if err != nil {
		return err
	}
	xdpProgram, err := options.collection.programResource(fakeTCPXDPProgramName)
	if err != nil {
		return err
	}
	ingressProgram, err := options.collection.programResource(ingressFilterName)
	if err != nil {
		return err
	}
	coreEgressProgram, err := options.collection.programResource(egressFilterName)
	if err != nil {
		return err
	}
	coreResources, err := resolveExperimentalCoreResources(options.collection)
	if err != nil {
		return err
	}

	ownedStore, err := options.sessionFactory(
		sessionMap, sessionClaimProgram, generation,
	)
	if err != nil {
		return build.prepareError(fmt.Errorf("build experimental FakeTCP runtime session handle: %w", err))
	}
	build.sessions, err = newGenerationFencedSessionStore(generation, ownedStore)
	if err != nil {
		if ownedFakeTCPSessionStoreIsNil(ownedStore) {
			return err
		}
		return errors.Join(err, ownedStore.Close())
	}
	engineOptions := options.engineOptions
	engineOptions.Store = build.sessions
	build.engine, err = faketcp.New(engineOptions)
	if err != nil {
		return fmt.Errorf("build experimental FakeTCP runtime Engine: %w", err)
	}
	build.isolation, err = build.claim.bindIsolationCollection(
		build.activeCtx,
		options.collection,
		build.engine.Identity(),
	)
	if err != nil {
		return fmt.Errorf("bind experimental FakeTCP generation isolation: %w", err)
	}
	eventSource := options.eventSource
	if eventSource == nil {
		bpfMap, ok := eventsMap.(*ebpf.Map)
		if !ok || bpfMap == nil {
			return errors.New("experimental FakeTCP events resource is not a live eBPF map")
		}
		eventSource = liveExperimentalEventMapSource{bpfMap: bpfMap}
	}
	build.events, err = newGenerationFencedEventMap(generation, eventSource)
	if err != nil {
		return err
	}
	err = build.events.withMap(func(eventsMap *ebpf.Map) error {
		constructed, constructErr := options.slowPathFactory(build.engine, eventsMap, statsMap)
		if constructErr != nil {
			if !experimentalSlowPathIsNil(constructed) {
				if closeErr := constructed.Close(); closeErr != nil {
					// A failed constructor still transferred this partial owner.
					// Retain it so failed-build quarantine can retry the exact
					// teardown instead of losing a possibly live userspace path.
					build.slowPath = constructed
					constructErr = errors.Join(constructErr, closeErr)
				}
			}
			return constructErr
		}
		if experimentalSlowPathIsNil(constructed) {
			return errors.New("experimental FakeTCP slow-path factory returned nil")
		}
		// Record ownership before WithMap closes its constructor clone. A clone
		// close failure must still close the fully constructed slow path.
		build.slowPath = constructed
		return nil
	})
	if err != nil {
		return fmt.Errorf("build experimental FakeTCP userspace slow path: %w", err)
	}
	if err := build.activeContextError(); err != nil {
		return err
	}
	programArray := options.programArray
	if programArray == nil {
		programArray = liveFakeTCPProgramArray{resource: programArrayResource}
	}
	build.policyMaps = fakeTCPPolicyMaps{
		ControlPolicies: controlPolicies, ManagedPorts: managedPorts,
		ManagedInterfaces: managedInterfaces,
	}
	build.programArray = programArray
	build.egressProgram = egressProgram
	build.xdpProgram = xdpProgram
	build.ingressProgram = ingressProgram
	build.coreEgressProgram = coreEgressProgram
	build.coreResources = coreResources
	build.freshClaim = experimentalLinuxFreshCollectionClaim{
		state: &experimentalLinuxFreshCollectionClaimState{
			transaction: build.claim,
			claimCtx:    build.cleanupCtx,
			collection:  options.collection,
			release:     build.commit,
		},
	}
	return build.activeContextError()
}

func (build *experimentalRuntimeBuild) activate() error {
	if build == nil || build.engine == nil || build.freshClaim.state == nil ||
		build.options.commitGeneration == nil {
		return errors.New("activate experimental FakeTCP runtime: build is incomplete")
	}
	err := build.options.commitGeneration(
		build.engine,
		build.freshClaim,
		build.makeReachable,
	)
	if err == nil && !build.committed.Load() {
		return errors.New("activate experimental FakeTCP runtime: generation commit returned without releasing ownership")
	}
	return err
}

func (build *experimentalRuntimeBuild) makeReachable(
	release faketcp.LinuxFreshCollectionRelease,
) error {
	if release == nil {
		return errors.New("activate experimental FakeTCP runtime: release capability is nil")
	}
	if err := build.activeContextError(); err != nil {
		return err
	}
	var err error
	build.coreStage, err = build.options.coreStageFactory(
		build.activeCtx,
		build.coreResources,
		build.options.baselineSnapshot,
	)
	if err != nil {
		return build.prepareError(err)
	}
	if err := build.activeContextError(); err != nil {
		return err
	}
	build.programStage, err = stageFakeTCPEgressProgram(
		build.activeCtx, build.claim, build.programArray, build.egressProgram,
	)
	if err != nil {
		return build.prepareError(err)
	}
	if err := build.activeContextError(); err != nil {
		return err
	}
	build.xdpStage, err = stageFakeTCPXDPAttachments(
		build.activeCtx, build.options.xdpRequests, build.xdpProgram,
		build.options.xdpRuntime,
	)
	if err != nil {
		return build.prepareError(err)
	}
	if err := build.activeContextError(); err != nil {
		return err
	}
	build.tcStage, err = build.options.tcStageFactory(
		build.activeCtx,
		build.options.attachState,
		build.ingressProgram,
		build.coreEgressProgram,
		func() error { return build.commitAttachedCore(release) },
	)
	if err != nil {
		return build.prepareError(err)
	}
	return nil
}

func (build *experimentalRuntimeBuild) commitAttachedCore(
	release faketcp.LinuxFreshCollectionRelease,
) error {
	var err error
	build.policyStage, err = build.claim.Stage(
		build.activeCtx,
		build.policyMaps,
	)
	if build.policyStage != nil {
		bindErr := build.claim.bindStageCollectionOwner(
			build.cleanupCtx, build.policyStage, build.options.collection,
		)
		if bindErr != nil {
			err = errors.Join(err, fmt.Errorf(
				"bind FakeTCP policy stage to collection owner: %w", bindErr,
			))
		}
	}
	if err != nil {
		return build.prepareError(err)
	}
	if err := build.activeContextError(); err != nil {
		return err
	}
	if err := build.claim.Activate(build.activeCtx, build.policyStage); err != nil {
		return err
	}
	if err := build.activeContextError(); err != nil {
		return err
	}
	if err := build.coreStage.CommitControl(); err != nil {
		return err
	}
	// release is deliberately the final fallible operation. It commits local rollback
	// ownership and releases the retained lifecycle claim without leaving any
	// fallible wrapper work after the TC transaction callback succeeds.
	if err := release(); err != nil {
		return err
	}
	return nil
}

func (build *experimentalRuntimeBuild) commit() error {
	// This is the single cancellation boundary. Before it, every mutation is
	// rollback-owned and cancellation aborts the build. Once Err observes an
	// active caller, commit is deliberately uninterruptible: both disarms and
	// lease release use cleanupCtx so cancellation cannot split ownership
	// between the program-array and policy stages.
	committed, err := build.claim.commitRuntimeBuild(
		build.cleanupCtx,
		build.policyStage,
		build.programStage,
	)
	if committed {
		build.committed.Store(true)
	}
	if err != nil {
		return fmt.Errorf("release FakeTCP generation transaction: %w", err)
	}
	return nil
}

func (build *experimentalRuntimeBuild) activeContextError() error {
	if build == nil || build.activeCtx == nil {
		return errors.New("build experimental FakeTCP runtime: active context is nil")
	}
	return build.activeCtx.Err()
}

func (build *experimentalRuntimeBuild) prepareError(err error) error {
	return errors.Join(err, build.activeContextError())
}

func (build *experimentalRuntimeBuild) fail(
	cause error,
) (*ExperimentalFakeTCPRuntime, error) {
	complete, cleanupErr := build.cleanupUncommitted()
	err := errors.Join(cause, cleanupErr)
	if complete {
		return nil, err
	}
	return build.failedBuildOwner(), err
}

func (build *experimentalRuntimeBuild) cleanupUncommitted() (bool, error) {
	var cleanupErrors []error
	// The slow path owns the reader, controller/backend, and raw writer. Fence
	// all of them before making the generation or any TC/XDP attachment
	// unreachable. A failed fence retains every later owner for an exact retry.
	if !experimentalSlowPathIsNil(build.slowPath) {
		if err := build.slowPath.Close(); err != nil {
			return false, fmt.Errorf("close FakeTCP slow path: %w", err)
		}
		build.slowPath = nil
	}
	coreInactive := true
	if build.coreStage != nil {
		if err := build.coreStage.Deactivate(); err != nil {
			coreInactive = false
			cleanupErrors = append(cleanupErrors, fmt.Errorf("deactivate FakeTCP baseline core: %w", err))
		}
	}
	if coreInactive && build.policyStage != nil {
		if err := build.claim.Rollback(build.cleanupCtx, build.policyStage); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("rollback FakeTCP policy stage: %w", err))
		} else {
			build.policyStage = nil
		}
	}
	policyClosed := coreInactive && build.policyStage == nil
	if policyClosed {
		if build.xdpStage != nil {
			if err := build.xdpStage.Close(); err != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("rollback FakeTCP XDP stage: %w", err))
			} else {
				build.xdpStage = nil
			}
		}
		if build.tcStage != nil {
			if err := build.tcStage.Close(); err != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("rollback FakeTCP TC stage: %w", err))
			} else {
				build.tcStage = nil
			}
		}
	}
	externalDetached := policyClosed && build.xdpStage == nil && build.tcStage == nil &&
		experimentalSlowPathIsNil(build.slowPath)
	if externalDetached {
		if build.programStage != nil {
			if err := build.programStage.Rollback(build.cleanupCtx, build.claim); err != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("rollback FakeTCP program array stage: %w", err))
			} else {
				build.programStage = nil
			}
		}
		if build.policyStage == nil && build.programStage == nil && build.coreStage != nil {
			if err := build.coreStage.Close(); err != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("rollback FakeTCP baseline core: %w", err))
			} else {
				build.coreStage = nil
			}
		}
		if build.policyStage == nil && build.programStage == nil && build.coreStage == nil {
			if build.sessions != nil {
				if err := build.sessions.Close(); err != nil {
					cleanupErrors = append(cleanupErrors, fmt.Errorf("close FakeTCP session handle: %w", err))
				} else {
					build.sessions = nil
				}
			}
			if build.events != nil {
				if err := build.events.Close(); err != nil {
					cleanupErrors = append(cleanupErrors, fmt.Errorf("close FakeTCP event-map handle: %w", err))
				} else {
					build.events = nil
				}
			}
		}
	}
	internalClosed := externalDetached && build.policyStage == nil &&
		build.programStage == nil && build.coreStage == nil &&
		build.sessions == nil && build.events == nil
	if internalClosed && build.options.collection != nil {
		if err := build.options.collection.Close(); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("close experimental FakeTCP collection: %w", err))
		} else {
			build.options.collection = nil
		}
	}
	if internalClosed && build.options.collection == nil && build.claim != nil {
		if err := build.claim.Close(); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("close FakeTCP generation transaction: %w", err))
		} else {
			build.claim = nil
		}
	}
	complete := internalClosed && build.options.collection == nil && build.claim == nil
	if complete {
		build.engine = nil
		build.isolation = nil
		build.freshClaim = experimentalLinuxFreshCollectionClaim{}
	}
	return complete, errors.Join(cleanupErrors...)
}

// failCommitted is the only error path after the combined transaction commit
// consumed rollback ownership. It closes every live owner in dependency order
// and deliberately never calls Rollback or Close through the spent claim.
func (build *experimentalRuntimeBuild) failCommitted(
	cause error,
) (*ExperimentalFakeTCPRuntime, error) {
	runtime := build.runtimeOwner()
	closeErr := runtime.Close()
	if closeErr == nil {
		return nil, cause
	}
	return runtime, errors.Join(cause, closeErr)
}

func validateFakeTCPXDPRequests(
	plan *fakeTCPPolicyGenerationPlan,
	requests []fakeTCPXDPAttachRequest,
) error {
	if plan == nil {
		return errors.New("build experimental FakeTCP runtime: policy plan is nil")
	}
	want := make(map[uint32]struct{}, len(plan.managedInterfaces))
	for _, entry := range plan.managedInterfaces {
		want[entry.Key.UnderlayIndex] = struct{}{}
	}
	if len(requests) != len(want) {
		return fmt.Errorf(
			"build experimental FakeTCP runtime: XDP requests %d do not match managed interfaces %d",
			len(requests), len(want),
		)
	}
	seen := make(map[int]struct{}, len(requests))
	for _, request := range requests {
		if request.IfIndex <= 0 || uint64(request.IfIndex) > math.MaxUint32 {
			return fmt.Errorf("build experimental FakeTCP runtime: invalid XDP ifindex %d", request.IfIndex)
		}
		if _, duplicate := seen[request.IfIndex]; duplicate {
			return fmt.Errorf("build experimental FakeTCP runtime: duplicate XDP ifindex %d", request.IfIndex)
		}
		seen[request.IfIndex] = struct{}{}
		if request.Mode != fakeTCPXDPAttachNative && request.Mode != fakeTCPXDPAttachGeneric &&
			request.Mode != fakeTCPXDPAttachLibXDP {
			return fmt.Errorf(
				"build experimental FakeTCP runtime: unsupported XDP mode %s for ifindex %d",
				request.Mode, request.IfIndex,
			)
		}
		if _, exists := want[uint32(request.IfIndex)]; !exists {
			return fmt.Errorf(
				"build experimental FakeTCP runtime: XDP ifindex %d has no managed-interface policy",
				request.IfIndex,
			)
		}
	}
	return nil
}

// validateExperimentalRuntimeCanonicalInterfaces binds every independently
// supplied projection before the first map, TCX, or XDP mutation. Baseline TCX
// may cover more underlays than FakeTCP, but every baseline map and every
// FakeTCP policy map must be an exact projection of the same control.State.
func validateExperimentalRuntimeCanonicalInterfaces(
	baseline *abi.Snapshot,
	fakePlan *fakeTCPPolicyGenerationPlan,
	attachState *control.State,
	xdpRequests []fakeTCPXDPAttachRequest,
) error {
	if baseline == nil || fakePlan == nil || attachState == nil {
		return errors.New("build experimental FakeTCP runtime: canonical interface inputs are incomplete")
	}
	generation := fakePlan.generation
	projectedBaseline, err := abi.FromStateWithGeneration(attachState, generation)
	if err != nil {
		return fmt.Errorf("build experimental FakeTCP runtime: project canonical baseline state: %w", err)
	}
	if len(projectedBaseline.Underlays) == 0 {
		return errors.New("build experimental FakeTCP runtime: canonical baseline contains no attachable underlay")
	}
	if !reflect.DeepEqual(baseline.Underlays, projectedBaseline.Underlays) {
		return errors.New("build experimental FakeTCP runtime: baseline underlays are stale or unrelated to TC attach state")
	}
	for _, projection := range []struct {
		label     string
		supplied  any
		canonical any
	}{
		{"control", baseline.Control, projectedBaseline.Control},
		{"profiles", baseline.Profiles, projectedBaseline.Profiles},
		{"ciphers", baseline.Ciphers, projectedBaseline.Ciphers},
		{"managed fwmarks", baseline.ManagedFwmarks, projectedBaseline.ManagedFwmarks},
		{"egress rules", baseline.EgressRules, projectedBaseline.EgressRules},
		{"ingress listeners", baseline.IngressListeners, projectedBaseline.IngressListeners},
		{"ICMP listeners", baseline.ICMPListeners, projectedBaseline.ICMPListeners},
	} {
		if !reflect.DeepEqual(projection.supplied, projection.canonical) {
			return fmt.Errorf(
				"build experimental FakeTCP runtime: baseline %s are stale or unrelated to TC attach state",
				projection.label,
			)
		}
	}
	tcIfindexes, err := activeAttachIfindexes(attachState)
	if err != nil {
		return fmt.Errorf("build experimental FakeTCP runtime: derive canonical TC interfaces: %w", err)
	}
	if len(tcIfindexes) == 0 {
		return errors.New("build experimental FakeTCP runtime: canonical TC interface set is empty")
	}
	if len(tcIfindexes) != len(projectedBaseline.Underlays) {
		return errors.New("build experimental FakeTCP runtime: TC interfaces differ from baseline underlays")
	}
	for _, ifindex := range tcIfindexes {
		if uint64(ifindex) > math.MaxUint32 {
			return fmt.Errorf("build experimental FakeTCP runtime: TC ifindex %d exceeds the BPF ABI", ifindex)
		}
		key := abi.UnderlayConfigKey{
			Generation: generation, UnderlayIndex: uint32(ifindex),
		}
		if _, exists := projectedBaseline.Underlays[key]; !exists {
			return fmt.Errorf(
				"build experimental FakeTCP runtime: TC ifindex %d has no canonical baseline underlay",
				ifindex,
			)
		}
	}
	projectedFake, err := buildFakeTCPPolicyGenerationPlan(attachState, generation)
	if err != nil {
		return fmt.Errorf("build experimental FakeTCP runtime: project canonical FakeTCP policy: %w", err)
	}
	if !reflect.DeepEqual(fakePlan.managedInterfaces, projectedFake.managedInterfaces) {
		return errors.New("build experimental FakeTCP runtime: FakeTCP managed interfaces are stale or unrelated to TC attach state")
	}
	if !reflect.DeepEqual(fakePlan.managedPorts, projectedFake.managedPorts) {
		return errors.New("build experimental FakeTCP runtime: FakeTCP managed ports are stale or unrelated to TC attach state")
	}
	if !reflect.DeepEqual(fakePlan.controlPolicies, projectedFake.controlPolicies) {
		return errors.New("build experimental FakeTCP runtime: FakeTCP control policies are stale or unrelated to TC attach state")
	}
	if err := validateFakeTCPXDPRequests(fakePlan, xdpRequests); err != nil {
		return err
	}
	return nil
}

func (runtime *ExperimentalFakeTCPRuntime) Handles() (ExperimentalFakeTCPRuntimeHandles, error) {
	if runtime == nil || runtime.state == nil {
		return ExperimentalFakeTCPRuntimeHandles{}, ErrExperimentalFakeTCPRuntimeClosed
	}
	state := runtime.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.shutdown || state.closing || state.closed {
		return ExperimentalFakeTCPRuntimeHandles{}, ErrExperimentalFakeTCPRuntimeClosed
	}
	return state.handles, nil
}

func (runtime *ExperimentalFakeTCPRuntime) Generation() uint64 {
	if runtime == nil || runtime.state == nil {
		return 0
	}
	return runtime.state.generation
}

func (runtime *ExperimentalFakeTCPRuntime) Identity() faketcp.RuntimeIdentity {
	if runtime == nil || runtime.state == nil {
		return faketcp.RuntimeIdentity{}
	}
	return runtime.state.identity
}

func (runtime *ExperimentalFakeTCPRuntime) Run(ctx context.Context) error {
	if runtime == nil || runtime.state == nil {
		return ErrExperimentalFakeTCPRuntimeClosed
	}
	state := runtime.state
	state.mu.Lock()
	if state.shutdown || state.closing || state.closed || experimentalSlowPathIsNil(state.slowPath) {
		state.mu.Unlock()
		return ErrExperimentalFakeTCPRuntimeClosed
	}
	slowPath := state.slowPath
	state.mu.Unlock()
	return slowPath.Run(ctx)
}

func (runtime *ExperimentalFakeTCPRuntime) RequestStop() error {
	if runtime == nil || runtime.state == nil {
		return ErrExperimentalFakeTCPRuntimeClosed
	}
	state := runtime.state
	state.mu.Lock()
	if state.shutdown || state.closing || state.closed || experimentalSlowPathIsNil(state.slowPath) {
		state.mu.Unlock()
		return ErrExperimentalFakeTCPRuntimeClosed
	}
	slowPath := state.slowPath
	state.mu.Unlock()
	return slowPath.RequestStop()
}

func (runtime *ExperimentalFakeTCPRuntime) Close() error {
	if runtime == nil || runtime.state == nil {
		return nil
	}
	state := runtime.state
	state.mu.Lock()
	if state.closed {
		err := state.closeErr
		state.mu.Unlock()
		return err
	}
	if state.closing {
		done := state.closeDone
		state.mu.Unlock()
		<-done
		state.mu.Lock()
		err := state.closeErr
		state.mu.Unlock()
		return err
	}
	state.closeDone = make(chan struct{})
	state.closing = true
	state.shutdown = true
	done := state.closeDone
	failedBuild := state.failedBuild
	if failedBuild != nil {
		state.mu.Unlock()
		complete, err := failedBuild.cleanupUncommitted()
		state.mu.Lock()
		state.closeErr = err
		state.closing = false
		if complete {
			state.failedBuild = nil
			state.closed = true
			state.engine = nil
			state.handles = ExperimentalFakeTCPRuntimeHandles{}
		}
		close(done)
		state.mu.Unlock()
		return err
	}
	core := state.core
	slowPath := state.slowPath
	sessions := state.handles.sessions
	events := state.handles.events
	tc := state.tc
	xdp := state.xdp
	isolation := state.isolation
	generation := state.generation
	collection := state.collection
	state.mu.Unlock()

	// Closing the slow path synchronously fences its ring reader, controller,
	// backend and raw writer. No dataplane owner may be detached while a write
	// could still complete against that generation.
	slowPathErr := wrapExperimentalRuntimeClose("slow path", slowPath)
	if slowPathErr != nil {
		state.mu.Lock()
		state.closeErr = slowPathErr
		state.closing = false
		close(done)
		state.mu.Unlock()
		return slowPathErr
	}

	var closeErrors []error
	coreInactive := true
	if core != nil {
		if err := core.Deactivate(); err != nil {
			coreInactive = false
			closeErrors = append(closeErrors, fmt.Errorf("deactivate experimental FakeTCP runtime baseline core: %w", err))
		}
	}
	var isolationErr error
	if coreInactive {
		if fakeTCPPolicyGenerationIsolationBackendIsNil(isolation) {
			isolationErr = errors.New("quiesce experimental FakeTCP runtime: generation isolation owner is nil")
		} else {
			isolationErr = isolation.Quiesce(context.Background(), generation)
			if isolationErr != nil {
				isolationErr = fmt.Errorf("quiesce experimental FakeTCP runtime generation %d: %w", generation, isolationErr)
			}
		}
		closeErrors = append(closeErrors, isolationErr)
	}
	quiesced := coreInactive && isolationErr == nil
	var xdpErr, tcErr error
	if quiesced {
		xdpErr = wrapExperimentalRuntimeClose("XDP links", xdp)
		tcErr = wrapExperimentalRuntimeClose("TC filters", tc)
		closeErrors = append(closeErrors, xdpErr, tcErr)
	}

	var coreErr, sessionErr, eventErr, collectionErr error
	if quiesced && xdpErr == nil && tcErr == nil {
		coreErr = wrapExperimentalRuntimeClose("baseline core", core)
		closeErrors = append(closeErrors, coreErr)
		if coreErr == nil {
			sessionErr = wrapExperimentalRuntimeClose("session handle", sessions)
			eventErr = wrapExperimentalRuntimeClose("event-map constructors", events)
			closeErrors = append(closeErrors, sessionErr, eventErr)
			if sessionErr == nil && eventErr == nil {
				collectionErr = wrapExperimentalRuntimeClose("collection", collection)
				closeErrors = append(closeErrors, collectionErr)
			}
		}
	}
	err := errors.Join(closeErrors...)

	state.mu.Lock()
	state.closeErr = err
	state.closing = false
	if quiesced && xdpErr == nil {
		state.xdp = nil
	}
	if quiesced && tcErr == nil {
		state.tc = nil
	}
	state.slowPath = nil
	if quiesced && coreErr == nil && xdpErr == nil && tcErr == nil {
		state.core = nil
		if sessionErr == nil {
			state.handles.sessions = nil
		}
		if eventErr == nil {
			state.handles.events = nil
		}
	}
	complete := quiesced && xdpErr == nil && tcErr == nil &&
		coreErr == nil && sessionErr == nil && eventErr == nil && collectionErr == nil
	if complete {
		state.closed = true
		state.handles = ExperimentalFakeTCPRuntimeHandles{}
		state.engine = nil
		state.collection = nil
		state.isolation = nil
	}
	close(done)
	state.mu.Unlock()
	return err
}

type experimentalRuntimeCloser interface {
	Close() error
}

func wrapExperimentalRuntimeClose(label string, closer experimentalRuntimeCloser) error {
	if closer == nil {
		return nil
	}
	if err := closer.Close(); err != nil {
		return fmt.Errorf("close experimental FakeTCP runtime %s: %w", label, err)
	}
	return nil
}
