//go:build linux

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/syx0310/wg-mix-ebpf/internal/abi"
	"github.com/syx0310/wg-mix-ebpf/internal/faketcp"
)

const (
	fakeTCPSessionMapName    = "faketcp_session_map"
	fakeTCPEventsMapName     = "faketcp_events"
	fakeTCPEgressProgramName = "wg_faketcp_egress"
	fakeTCPXDPProgramName    = "wg_mix_faketcp_ingress"
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
	uint64,
) (ownedFakeTCPSessionStore, error)

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
	generation uint64,
) (ownedFakeTCPSessionStore, error) {
	bpfMap, ok := resource.(*ebpf.Map)
	if !ok || bpfMap == nil {
		return nil, errors.New("experimental FakeTCP session resource is not a live eBPF map")
	}
	identity, err := faketcp.InspectLinuxSessionMapIdentity(bpfMap)
	if err != nil {
		return nil, fmt.Errorf("inspect experimental FakeTCP session map: %w", err)
	}
	store, err := faketcp.NewLinuxSessionStore(bpfMap, generation, identity)
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
) (bool, error) {
	if store == nil {
		return false, ErrExperimentalFakeTCPRuntimeClosed
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if err := store.validateLocked(key.Generation, value.Generation); err != nil {
		return false, err
	}
	return store.backend.DeleteEstablishedIfUnchanged(key, value)
}

func (store *generationFencedSessionStore) validateLocked(generations ...uint64) error {
	if store == nil || store.closed || store.backend == nil {
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
		return store.closeErr
	}
	store.closed = true
	backend := store.backend
	store.backend = nil
	store.closeErr = backend.Close()
	return store.closeErr
}

// ExperimentalFakeTCPRuntimeHandles are borrowed from one runtime generation
// and may be retained by its userspace controller. SessionStore remains the
// same fenced object for the generation lifetime; it never clones a map or
// copies packet payloads per operation.
type ExperimentalFakeTCPRuntimeHandles struct {
	generation uint64
	sessions   *generationFencedSessionStore
	events     *generationFencedEventMap
}

func (handles ExperimentalFakeTCPRuntimeHandles) Generation() uint64 {
	return handles.generation
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
// links, and the userspace session-map clone. It must not be copied.
type ExperimentalFakeTCPRuntime struct {
	mu sync.Mutex

	generation uint64
	collection *experimentalCollectionOwner
	xdp        *fakeTCPXDPStage
	handles    ExperimentalFakeTCPRuntimeHandles
	closing    bool
	closed     bool
	closeErr   error
	closeDone  chan struct{}
}

type experimentalFakeTCPRuntimeBuildOptions struct {
	collection     *experimentalCollectionOwner
	transaction    *fakeTCPPolicyGenerationTransaction
	snapshot       *fakeTCPPolicySnapshot
	xdpRequests    []fakeTCPXDPAttachRequest
	xdpRuntime     fakeTCPXDPRuntime
	sessionFactory experimentalSessionStoreFactory
	eventSource    experimentalEventMapSource
	programArray   fakeTCPProgramArray
}

// buildExperimentalFakeTCPRuntime takes collection ownership immediately,
// including on error. The caller retains ownership of transaction only until
// this function returns; every path closes its retained lifecycle lease.
func buildExperimentalFakeTCPRuntime(
	ctx context.Context,
	options experimentalFakeTCPRuntimeBuildOptions,
) (*ExperimentalFakeTCPRuntime, error) {
	if ctx == nil {
		var cleanupErr error
		if options.collection != nil {
			cleanupErr = errors.Join(cleanupErr, options.collection.Close())
		}
		if options.transaction != nil {
			cleanupErr = errors.Join(cleanupErr, options.transaction.Close())
		}
		return nil, errors.Join(
			errors.New("build experimental FakeTCP runtime: context is nil"),
			cleanupErr,
		)
	}
	cleanupCtx := context.WithoutCancel(ctx)
	if err := ctx.Err(); err != nil {
		if options.collection != nil {
			err = errors.Join(err, options.collection.Close())
		}
		if options.transaction != nil {
			err = errors.Join(err, options.transaction.Close())
		}
		return nil, err
	}
	build := &experimentalRuntimeBuild{
		options:    options,
		activeCtx:  ctx,
		cleanupCtx: cleanupCtx,
	}
	if err := build.prepare(); err != nil {
		return nil, build.fail(err)
	}
	if err := build.commit(); err != nil {
		return nil, build.fail(err)
	}
	return &ExperimentalFakeTCPRuntime{
		generation: options.snapshot.Generation,
		collection: options.collection,
		xdp:        build.xdpStage,
		handles: ExperimentalFakeTCPRuntimeHandles{
			generation: options.snapshot.Generation,
			sessions:   build.sessions,
			events:     build.events,
		},
		closeDone: make(chan struct{}),
	}, nil
}

type experimentalRuntimeBuild struct {
	options    experimentalFakeTCPRuntimeBuildOptions
	activeCtx  context.Context
	cleanupCtx context.Context

	sessions     *generationFencedSessionStore
	events       *generationFencedEventMap
	programStage *fakeTCPProgramArrayStage
	xdpStage     *fakeTCPXDPStage
	policyStage  *fakeTCPPolicyStage
}

func (build *experimentalRuntimeBuild) prepare() error {
	options := build.options
	if err := build.activeContextError(); err != nil {
		return err
	}
	if options.collection == nil {
		return errors.New("build experimental FakeTCP runtime: collection owner is nil")
	}
	if options.transaction == nil {
		return fmt.Errorf("build experimental FakeTCP runtime: %w", errFakeTCPPolicyGenerationLeaseRequired)
	}
	if err := options.transaction.assertHeld(build.activeCtx); err != nil {
		return fmt.Errorf("build experimental FakeTCP runtime: %w", err)
	}
	if err := validateFakeTCPPolicySnapshot(options.snapshot); err != nil {
		return fmt.Errorf("build experimental FakeTCP runtime snapshot: %w", err)
	}
	if options.snapshot.Generation != options.transaction.generation {
		return fmt.Errorf(
			"build experimental FakeTCP runtime: snapshot generation %d does not match transaction generation %d",
			options.snapshot.Generation, options.transaction.generation,
		)
	}
	if err := validateFakeTCPXDPRequests(options.snapshot, options.xdpRequests); err != nil {
		return err
	}
	if options.xdpRuntime.probe == nil || options.xdpRuntime.attach == nil {
		return errors.New("build experimental FakeTCP runtime: XDP probe and attach backends are required")
	}
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
	eventsMap, err := options.collection.mapResource(fakeTCPEventsMapName)
	if err != nil {
		return err
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

	ownedStore, err := options.sessionFactory(sessionMap, options.snapshot.Generation)
	if err != nil {
		return build.prepareError(fmt.Errorf("build experimental FakeTCP runtime session handle: %w", err))
	}
	build.sessions, err = newGenerationFencedSessionStore(options.snapshot.Generation, ownedStore)
	if err != nil {
		if ownedFakeTCPSessionStoreIsNil(ownedStore) {
			return err
		}
		return errors.Join(err, ownedStore.Close())
	}
	eventSource := options.eventSource
	if eventSource == nil {
		bpfMap, ok := eventsMap.(*ebpf.Map)
		if !ok || bpfMap == nil {
			return errors.New("experimental FakeTCP events resource is not a live eBPF map")
		}
		eventSource = liveExperimentalEventMapSource{bpfMap: bpfMap}
	}
	build.events, err = newGenerationFencedEventMap(options.snapshot.Generation, eventSource)
	if err != nil {
		return err
	}
	if err := build.activeContextError(); err != nil {
		return err
	}
	programArray := options.programArray
	if programArray == nil {
		programArray = liveFakeTCPProgramArray{resource: programArrayResource}
	}
	build.programStage, err = stageFakeTCPEgressProgram(
		build.activeCtx, options.transaction, programArray, egressProgram,
	)
	if err != nil {
		return build.prepareError(err)
	}
	if err := build.activeContextError(); err != nil {
		return err
	}
	build.xdpStage, err = stageFakeTCPXDPAttachments(
		build.activeCtx, options.xdpRequests, xdpProgram, options.xdpRuntime,
	)
	if err != nil {
		return build.prepareError(err)
	}
	if err := build.activeContextError(); err != nil {
		return err
	}
	build.policyStage, err = options.transaction.Stage(
		build.activeCtx,
		fakeTCPPolicyMaps{
			ControlPolicies: controlPolicies, ManagedPorts: managedPorts,
			ManagedInterfaces: managedInterfaces,
		},
		options.snapshot,
	)
	if build.policyStage != nil {
		bindErr := options.transaction.bindStageCollectionOwner(
			build.cleanupCtx, build.policyStage, options.collection,
		)
		if bindErr != nil {
			err = errors.Join(err, fmt.Errorf("bind FakeTCP policy stage to collection owner: %w", bindErr))
		}
	}
	if err != nil {
		return build.prepareError(err)
	}
	return build.activeContextError()
}

func (build *experimentalRuntimeBuild) commit() error {
	// This is the single cancellation boundary. Before it, every mutation is
	// rollback-owned and cancellation aborts the build. Once Err observes an
	// active caller, commit is deliberately uninterruptible: both disarms and
	// lease release use cleanupCtx so cancellation cannot split ownership
	// between the program-array and policy stages.
	if err := build.activeContextError(); err != nil {
		return err
	}
	if err := build.programStage.Disarm(); err != nil {
		return fmt.Errorf("commit FakeTCP egress program stage: %w", err)
	}
	if err := build.options.transaction.Disarm(build.cleanupCtx, build.policyStage); err != nil {
		return fmt.Errorf("commit FakeTCP policy stage: %w", err)
	}
	if err := build.options.transaction.Close(); err != nil {
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

func (build *experimentalRuntimeBuild) fail(cause error) error {
	var cleanupErrors []error
	policyRollbackFailed := false
	if build.policyStage != nil {
		if err := build.options.transaction.Rollback(build.cleanupCtx, build.policyStage); err != nil {
			policyRollbackFailed = true
			cleanupErrors = append(cleanupErrors, fmt.Errorf("rollback FakeTCP policy stage: %w", err))
		}
	}
	if build.xdpStage != nil {
		if err := build.xdpStage.Close(); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("rollback FakeTCP XDP stage: %w", err))
		}
	}
	if build.programStage != nil {
		if err := build.programStage.Rollback(build.cleanupCtx, build.options.transaction); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("rollback FakeTCP program array stage: %w", err))
		}
	}
	if build.sessions != nil {
		if err := build.sessions.Close(); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("close FakeTCP session handle: %w", err))
		}
	}
	if build.events != nil {
		if err := build.events.Close(); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("close FakeTCP event-map handle: %w", err))
		}
	}
	proof, collectionErr := build.options.collection.closeAndReleaseProof()
	if collectionErr != nil {
		cleanupErrors = append(cleanupErrors, fmt.Errorf("close experimental FakeTCP collection: %w", collectionErr))
	}
	if policyRollbackFailed && proof != nil {
		if err := build.options.transaction.releaseStageAfterCollectionClose(
			build.cleanupCtx, build.policyStage, proof,
		); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("release destroyed FakeTCP policy stage: %w", err))
		}
	}
	if build.options.transaction != nil {
		if err := build.options.transaction.Close(); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("close FakeTCP generation transaction: %w", err))
		}
	}
	return errors.Join(append([]error{cause}, cleanupErrors...)...)
}

func validateFakeTCPXDPRequests(
	snapshot *fakeTCPPolicySnapshot,
	requests []fakeTCPXDPAttachRequest,
) error {
	if snapshot == nil {
		return errors.New("build experimental FakeTCP runtime: snapshot is nil")
	}
	want := make(map[uint32]struct{}, len(snapshot.ManagedInterfaces))
	for key := range snapshot.ManagedInterfaces {
		want[key.UnderlayIndex] = struct{}{}
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

func (runtime *ExperimentalFakeTCPRuntime) Handles() (ExperimentalFakeTCPRuntimeHandles, error) {
	if runtime == nil {
		return ExperimentalFakeTCPRuntimeHandles{}, ErrExperimentalFakeTCPRuntimeClosed
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.closing || runtime.closed {
		return ExperimentalFakeTCPRuntimeHandles{}, ErrExperimentalFakeTCPRuntimeClosed
	}
	return runtime.handles, nil
}

func (runtime *ExperimentalFakeTCPRuntime) Generation() uint64 {
	if runtime == nil {
		return 0
	}
	return runtime.generation
}

func (runtime *ExperimentalFakeTCPRuntime) Close() error {
	if runtime == nil {
		return nil
	}
	runtime.mu.Lock()
	if runtime.closed {
		err := runtime.closeErr
		runtime.mu.Unlock()
		return err
	}
	if runtime.closing {
		done := runtime.closeDone
		runtime.mu.Unlock()
		<-done
		runtime.mu.Lock()
		err := runtime.closeErr
		runtime.mu.Unlock()
		return err
	}
	runtime.closing = true
	sessions := runtime.handles.sessions
	events := runtime.handles.events
	xdp := runtime.xdp
	collection := runtime.collection
	runtime.mu.Unlock()

	err := errors.Join(
		wrapExperimentalRuntimeClose("session handle", sessions),
		wrapExperimentalRuntimeClose("event-map constructors", events),
		wrapExperimentalRuntimeClose("XDP links", xdp),
		wrapExperimentalRuntimeClose("collection", collection),
	)

	runtime.mu.Lock()
	runtime.closeErr = err
	runtime.closed = true
	runtime.closing = false
	runtime.handles = ExperimentalFakeTCPRuntimeHandles{}
	runtime.xdp = nil
	runtime.collection = nil
	close(runtime.closeDone)
	runtime.mu.Unlock()
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
