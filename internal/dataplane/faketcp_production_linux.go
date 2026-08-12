//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/syx0310/wg-mix-ebpf/internal/abi"
	"github.com/syx0310/wg-mix-ebpf/internal/control"
	"github.com/syx0310/wg-mix-ebpf/internal/faketcp"
	"github.com/syx0310/wg-mix-ebpf/internal/lockfile"
)

const (
	fakeTCPProductionHandshakeRetries = 2
	fakeTCPProductionWindow           = math.MaxUint16
)

// experimentalFakeTCPProductionRequest is the complete, still-unclaimed input
// to the acquisition/runtime factory. The coordinator owns rollback until it
// invokes factory; factory then consumes buildOptions.transaction at entry.
type experimentalFakeTCPProductionRequest struct {
	key          fakeTCPRuntimeDesiredKey
	spec         *ebpf.CollectionSpec
	source       string
	object       ObjectIdentity
	dependencies experimentalCollectionAcquisitionDependencies
	buildOptions experimentalFakeTCPRuntimeBuildOptions
	rollback     func() error
}

type experimentalFakeTCPProductionRequestBuilder func(
	context.Context,
	*control.State,
	LinuxLoader,
) (*experimentalFakeTCPProductionRequest, error)

type experimentalFakeTCPProductionFactory func(
	context.Context,
	*experimentalFakeTCPProductionRequest,
) (fakeTCPRuntimeService, error)

var liveFakeTCPProductionCoordinatorState = &fakeTCPProductionCoordinatorState{
	supervisor: &fakeTCPRuntimeSupervisor{},
	owner:      dataplaneCoreOwnerUnknown,
}

// ProductionFakeTCPHealthy handles only states that select FakeTCP. The live
// runtime is intentionally process-owned rather than pinned, so baseline map
// inspection cannot determine its health. The daemon calls this only after it
// has proved that the control-state fingerprint is unchanged.
func ProductionFakeTCPHealthy(ctx context.Context, state *control.State) (handled bool, healthy bool) {
	handled, status, err := ProductionFakeTCPStatus(ctx, state)
	return handled, err == nil && status != nil && status.FakeTCP != nil && status.FakeTCP.Healthy
}

// ProductionFakeTCPStatus projects the exact process-owned runtime instead of
// inspecting baseline pins, which are deliberately absent in FakeTCP mode.
func ProductionFakeTCPStatus(
	ctx context.Context,
	state *control.State,
) (handled bool, status *KernelStatus, err error) {
	if len(fakeTCPStateReferences(state)) == 0 {
		return false, nil, nil
	}
	status = &KernelStatus{
		Mode: "faketcp", Underlays: make([]UnderlayKernelStatus, 0, len(state.Underlays)),
	}
	shared := liveFakeTCPProductionCoordinatorState
	if shared == nil {
		return true, status, errors.New("inspect production FakeTCP status: coordinator is nil")
	}
	shared.operationMu.Lock()
	defer shared.operationMu.Unlock()
	if shared.owner != dataplaneCoreOwnerExperimental || shared.supervisor == nil {
		return true, status, errors.New("inspect production FakeTCP status: runtime owner is not active")
	}
	provider, ok := shared.supervisor.(interface {
		CurrentProductionStatus(context.Context) (*FakeTCPRuntimeStatus, error)
	})
	if !ok {
		return true, status, errors.New("inspect production FakeTCP status: supervisor has no status contract")
	}
	runtimeStatus, statusErr := provider.CurrentProductionStatus(ctx)
	if runtimeStatus == nil {
		return true, status, statusErr
	}
	status.ActiveGeneration = runtimeStatus.Generation
	status.ABIVersion = abi.Version
	status.FakeTCP = runtimeStatus
	underlays := make(map[int]int)
	for _, underlay := range state.Underlays {
		if !underlay.Resolved || underlay.IfIndex <= 0 ||
			underlay.Role == "disabled" || underlay.Role == "parse_only" {
			continue
		}
		status.Underlays = append(status.Underlays, UnderlayKernelStatus{
			Name: underlay.Name, IfIndex: underlay.IfIndex, IfName: underlay.IfName,
		})
		underlays[underlay.IfIndex] = len(status.Underlays) - 1
	}
	for _, attachment := range runtimeStatus.TCX {
		index, exists := underlays[attachment.IfIndex]
		if !exists {
			continue
		}
		underlay := &status.Underlays[index]
		underlay.Filters = append(underlay.Filters, FilterStatus{
			Direction: attachment.Direction, Name: "faketcp-" + attachment.Direction,
			Backend: exactTCXBackend, AttachType: attachment.AttachType,
			LinkID: attachment.LinkID, ProgramID: attachment.ProgramID,
		})
		if attachment.Direction == string(exactTCXIngress) {
			underlay.IngressAttached = true
		} else if attachment.Direction == string(exactTCXEgress) {
			underlay.EgressAttached = true
		}
	}
	for _, attachment := range runtimeStatus.XDP {
		index, exists := underlays[attachment.IfIndex]
		if !exists {
			continue
		}
		underlay := &status.Underlays[index]
		underlay.XDPAttached = true
		underlay.XDPMode = attachment.Mode
		underlay.XDPLinkID = attachment.LinkID
		underlay.XDPProgramID = attachment.ProgramID
	}
	return true, status, statusErr
}

func newFakeTCPProductionLoader(baseline LinuxLoader) Loader {
	// Freeze both environment-backed selectors in the handle. Scope resolution
	// and every later baseline operation now use these exact values even if a
	// process mutates its environment between reconcile phases.
	baseline.ObjectPath = baseline.effectiveObjectPath()
	baseline.objectPathFrozen = true
	baseline.FakeTCPObjectPath = baseline.effectiveFakeTCPObjectPath()
	baseline.fakeTCPObjectPathFrozen = true
	baseline.PinPath = pinPathFromEnv(baseline.PinPath)
	return &fakeTCPProductionCoordinator{
		baseline:           baseline,
		shared:             liveFakeTCPProductionCoordinatorState,
		validateActivation: ValidateFakeTCPActivation,
		resolveScope: func(ctx context.Context) (fakeTCPProductionScopeIdentity, error) {
			return resolveLinuxFakeTCPProductionScope(ctx, baseline)
		},
		planExperimental: composeExperimentalFakeTCPProductionPlanner(
			baseline,
			buildLiveExperimentalFakeTCPProductionRequest,
			acquireExperimentalFakeTCPProductionRuntime,
		),
	}
}

func resolveLinuxFakeTCPProductionScope(
	ctx context.Context,
	baseline LinuxLoader,
) (fakeTCPProductionScopeIdentity, error) {
	if ctx == nil {
		return fakeTCPProductionScopeIdentity{}, errors.New(
			"resolve Linux production dataplane scope: context is nil",
		)
	}
	objectPath := baseline.effectiveObjectPath()
	objectKind := fakeTCPProductionObjectScopeFilesystem
	var err error
	if objectPath == "" {
		objectKind = fakeTCPProductionObjectScopeEmbedded
		objectPath = EmbeddedObjectSource
	} else {
		objectPath, err = canonicalFakeTCPProductionPath("object", objectPath)
		if err != nil {
			return fakeTCPProductionScopeIdentity{}, err
		}
	}
	fakeTCPObjectPath := baseline.effectiveFakeTCPObjectPath()
	if fakeTCPObjectPath == "" {
		fakeTCPObjectPath = EmbeddedFakeTCPObjectSource
	} else {
		fakeTCPObjectPath, err = canonicalFakeTCPProductionPath(
			"FakeTCP object", fakeTCPObjectPath,
		)
		if err != nil {
			return fakeTCPProductionScopeIdentity{}, err
		}
	}
	pinPath, err := canonicalFakeTCPProductionPath(
		"pin",
		pinPathFromEnv(baseline.PinPath),
	)
	if err != nil {
		return fakeTCPProductionScopeIdentity{}, err
	}
	lifecyclePath, err := canonicalFakeTCPProductionPath(
		"lifecycle lease",
		lockfile.LifecycleLeasePath(ctx),
	)
	if err != nil {
		return fakeTCPProductionScopeIdentity{}, err
	}
	return fakeTCPProductionScopeIdentity{
		objectKind:        objectKind,
		objectPath:        objectPath,
		fakeTCPObjectPath: fakeTCPObjectPath,
		pinPath:           pinPath,
		lifecyclePath:     lifecyclePath,
		adoptLegacyPins:   baseline.AdoptLegacyPins,
	}, nil
}

// composeExperimentalFakeTCPProductionPlanner keeps request construction and
// the ownership-consuming factory injectable. Production NewLoader supplies
// the live request builder and the sole adapter that may call
// acquireAndBuildExperimentalFakeTCPRuntime; unit tests can replace both
// without loading BPF or changing network state.
func composeExperimentalFakeTCPProductionPlanner(
	baseline LinuxLoader,
	buildRequest experimentalFakeTCPProductionRequestBuilder,
	factory experimentalFakeTCPProductionFactory,
) fakeTCPProductionPlanner {
	return func(
		ctx context.Context,
		state *control.State,
	) (*fakeTCPProductionPlan, error) {
		if buildRequest == nil {
			return nil, errors.New("production experimental FakeTCP request builder is nil")
		}
		if factory == nil {
			return nil, errors.New("production experimental FakeTCP runtime factory is nil")
		}
		request, err := buildRequest(ctx, state, baseline)
		if err != nil {
			return nil, err
		}
		if request == nil {
			return nil, errors.New("production experimental FakeTCP request builder returned nil")
		}
		return &fakeTCPProductionPlan{
			key: request.key,
			build: func(buildCtx context.Context) (fakeTCPRuntimeService, error) {
				return factory(buildCtx, request)
			},
			rollback: request.rollbackUnclaimed,
		}, nil
	}
}

// acquireExperimentalFakeTCPProductionRuntime is the sole production adapter
// to the ownership-consuming factory. Keeping this call out of LinuxLoader and
// daemon/reconcile code makes the coordinator's gate and mutual-exclusion
// protocol mandatory for production activation.
func acquireExperimentalFakeTCPProductionRuntime(
	ctx context.Context,
	request *experimentalFakeTCPProductionRequest,
) (fakeTCPRuntimeService, error) {
	if request == nil {
		return nil, errors.New("acquire production experimental FakeTCP runtime: request is nil")
	}
	runtime, err := acquireAndBuildExperimentalFakeTCPRuntime(
		ctx,
		request.spec,
		request.source,
		request.dependencies,
		request.buildOptions,
	)
	if runtime == nil {
		return nil, err
	}
	return &productionFakeTCPRuntime{
		ExperimentalFakeTCPRuntime: runtime,
		object:                     request.object,
	}, err
}

// productionFakeTCPRuntime adds immutable deployment identity and a status
// projection to the raw runtime owner without weakening the latter's exact
// lifecycle. A non-nil failed build is wrapped too, preserving the sole Close
// capability for supervisor quarantine/retry.
type productionFakeTCPRuntime struct {
	*ExperimentalFakeTCPRuntime
	object ObjectIdentity
}

func (runtime *productionFakeTCPRuntime) ProductionStatus(
	ctx context.Context,
) (*FakeTCPRuntimeStatus, error) {
	if runtime == nil || runtime.ExperimentalFakeTCPRuntime == nil {
		return nil, ErrExperimentalFakeTCPRuntimeClosed
	}
	identity := runtime.Identity()
	status := &FakeTCPRuntimeStatus{
		Generation:   identity.Generation,
		Incarnation:  hex.EncodeToString(identity.Incarnation[:]),
		OwnerKind:    "process-owned",
		ObjectSource: runtime.object.Source,
		ObjectSHA256: runtime.object.SHA256,
		Barrier:      "unknown",
	}
	healthErr := runtime.Healthy(ctx)
	status.Healthy = healthErr == nil
	if healthErr != nil {
		status.Error = healthErr.Error()
	}
	state := runtime.state
	if state == nil {
		return status, errors.Join(healthErr, ErrExperimentalFakeTCPRuntimeClosed)
	}
	state.mu.Lock()
	tc, xdp, isolation := state.tc, state.xdp, state.isolation
	if barrier, ok := isolation.(experimentalRuntimeHealthOwner); ok && barrier.Healthy(ctx) == nil {
		status.Barrier = "open"
	} else {
		status.Barrier = "unhealthy"
	}
	state.mu.Unlock()
	if productionTC, ok := tc.(*productionFakeTCPTCXStage); ok {
		status.TCX = productionTC.status()
	} else if tc != nil {
		healthErr = errors.Join(healthErr, errors.New("production FakeTCP TCX status owner is unavailable"))
	}
	if xdp != nil {
		status.XDP = xdp.productionStatus()
	} else {
		healthErr = errors.Join(healthErr, errors.New("production FakeTCP XDP status owner is unavailable"))
	}
	if healthErr != nil {
		status.Healthy = false
		status.Error = healthErr.Error()
	}
	return status, healthErr
}

func (request *experimentalFakeTCPProductionRequest) rollbackUnclaimed() error {
	if request == nil {
		return nil
	}
	var rollbackErr error
	if request.rollback != nil {
		rollback := request.rollback
		request.rollback = nil
		rollbackErr = rollback()
	}
	transaction := request.buildOptions.transaction
	request.buildOptions.transaction = nil
	if transaction != nil && !transaction.isClosed() {
		rollbackErr = errors.Join(
			rollbackErr,
			wrapNonNilError(
				"close unclaimed experimental FakeTCP generation transaction",
				transaction.Close(),
			),
		)
	}
	return rollbackErr
}

// buildLiveExperimentalFakeTCPProductionRequest performs every fallible
// userspace-only planning step before the coordinator detaches the baseline.
// It loads and validates bytes but does not create a collection, mutate a map,
// attach a link, or acquire a second lifecycle lease.
func buildLiveExperimentalFakeTCPProductionRequest(
	ctx context.Context,
	state *control.State,
	baseline LinuxLoader,
) (*experimentalFakeTCPProductionRequest, error) {
	if ctx == nil {
		return nil, errors.New("plan live experimental FakeTCP runtime: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if state == nil {
		return nil, errors.New("plan live experimental FakeTCP runtime: state is nil")
	}
	if len(fakeTCPStateReferences(state)) == 0 {
		return nil, errors.New("plan live experimental FakeTCP runtime: state has no FakeTCP reference")
	}
	if !baseline.ResidentRuntime {
		return nil, ErrFakeTCPResidentRuntimeRequired
	}
	if !baseline.objectPathFrozen || !baseline.fakeTCPObjectPathFrozen {
		return nil, errors.New("plan live experimental FakeTCP runtime: object selectors are not frozen")
	}
	frozen := cloneFakeTCPProductionState(state)
	wg, err := validateFakeTCPProductionReferences(frozen)
	if err != nil {
		return nil, err
	}
	scope, err := resolveLinuxFakeTCPProductionScope(ctx, baseline)
	if err != nil {
		return nil, fmt.Errorf("plan live experimental FakeTCP runtime scope: %w", err)
	}
	if err := scope.validate(); err != nil {
		return nil, fmt.Errorf("plan live experimental FakeTCP runtime scope: %w", err)
	}
	if baseline.LifecycleLease == nil ||
		!baseline.LifecycleLease.HeldAt(scope.lifecyclePath) {
		return nil, fmt.Errorf(
			"plan live experimental FakeTCP runtime: %w at %s",
			errFakeTCPPolicyGenerationLeaseRequired,
			scope.lifecyclePath,
		)
	}
	backend, err := resolveAttachmentBackend(frozen, baseline.pinRuntime(ctx).exactTCX)
	if err != nil {
		return nil, fmt.Errorf("plan live experimental FakeTCP runtime attachment backend: %w", err)
	}
	if backend != exactTCXBackend {
		return nil, fmt.Errorf(
			"plan live experimental FakeTCP runtime attachment backend %q; want %q",
			backend, exactTCXBackend,
		)
	}
	// The factory repeats this immediately before collection load. Keeping the
	// same read-only module/kfunc probe here ensures an absent or incompatible
	// administrator-provisioned dependency cannot detach a working baseline.
	if err := probeExperimentalFakeTCPKernelDependency(); err != nil {
		return nil, fmt.Errorf(
			"plan live experimental FakeTCP runtime kernel dependency: %w", err,
		)
	}

	spec, identity, err := loadFakeTCPCollectionSpecFromResolvedPath(
		baseline.effectiveFakeTCPObjectPath(),
	)
	if err != nil {
		return nil, err
	}
	if err := validateFakeTCPProductionObjectIdentity(scope, identity); err != nil {
		return nil, err
	}
	if err := validateExperimentalExtensionManifest(spec); err != nil {
		return nil, fmt.Errorf(
			"validate production FakeTCP BPF object %s: %w", identity.Source, err,
		)
	}

	generation := frozen.Generation
	baselineSnapshot, err := abi.FromStateWithGeneration(frozen, generation)
	if err != nil {
		return nil, fmt.Errorf("project production FakeTCP baseline snapshot: %w", err)
	}
	policyPlan, err := buildFakeTCPPolicyGenerationPlan(frozen, generation)
	if err != nil {
		return nil, err
	}
	tcxRequests, err := fakeTCPProductionTCXRequests(frozen)
	if err != nil {
		return nil, err
	}
	xdpRequests := fakeTCPProductionXDPRequests(policyPlan)
	engineOptions, err := fakeTCPProductionEngineOptions(wg, generation)
	if err != nil {
		return nil, err
	}
	slowPathFactory, err := newLiveExperimentalFakeTCPSlowPathFactory(
		frozen, policyPlan.snapshot(), scope,
	)
	if err != nil {
		return nil, err
	}
	desiredKey, err := fakeTCPProductionDesiredKey(
		frozen, identity, scope, baselineSnapshot, policyPlan,
		engineOptions, tcxRequests, xdpRequests,
	)
	if err != nil {
		return nil, err
	}
	barrier, err := newLiveFakeTCPGenerationBarrier(generation)
	if err != nil {
		return nil, err
	}
	transaction, err := newFakeTCPPolicyGenerationTransaction(
		ctx, policyPlan, baseline.LifecycleLease, barrier,
	)
	if err != nil {
		return nil, err
	}
	tcxRuntime := baseline.pinRuntime(ctx).exactTCX

	return &experimentalFakeTCPProductionRequest{
		key:          desiredKey,
		spec:         spec,
		source:       identity.Source,
		object:       identity,
		dependencies: liveExperimentalCollectionAcquisitionDependencies(),
		buildOptions: experimentalFakeTCPRuntimeBuildOptions{
			transaction:      transaction,
			baselineSnapshot: baselineSnapshot,
			attachState:      frozen,
			xdpRequests:      xdpRequests,
			xdpRuntime:       liveFakeTCPXDPRuntime,
			xdpRequirement:   fakeTCPXDPRequireExactSelectedMode,
			engineOptions:    engineOptions,
			slowPathFactory:  slowPathFactory,
			tcStageFactory: func(
				stageCtx context.Context,
				attachState *control.State,
				ingress experimentalProgramResource,
				egress experimentalProgramResource,
				commit func() error,
			) (experimentalTCStageOwner, error) {
				return stageProductionFakeTCPTCX(
					stageCtx, attachState, ingress, egress, commit, tcxRuntime,
				)
			},
		},
	}, nil
}

func cloneFakeTCPProductionState(state *control.State) *control.State {
	if state == nil {
		return nil
	}
	frozen := *state
	frozen.Profiles = append([]control.ProfileState(nil), state.Profiles...)
	frozen.Ciphers = append([]control.CipherState(nil), state.Ciphers...)
	frozen.WireGuards = append([]control.WireGuardState(nil), state.WireGuards...)
	frozen.Underlays = append([]control.UnderlayState(nil), state.Underlays...)
	frozen.ManagedFwmarks = append([]control.ManagedFwmarkRule(nil), state.ManagedFwmarks...)
	frozen.EgressRules = append([]control.EgressRule(nil), state.EgressRules...)
	frozen.IngressListeners = append([]control.IngressListener(nil), state.IngressListeners...)
	frozen.ICMPListeners = append([]control.ICMPListener(nil), state.ICMPListeners...)
	frozen.Warnings = append([]string(nil), state.Warnings...)
	return &frozen
}

func validateFakeTCPProductionReferences(state *control.State) (control.WireGuardState, error) {
	if state == nil || state.Generation == 0 {
		return control.WireGuardState{}, errors.New(
			"plan live experimental FakeTCP runtime: state generation is zero",
		)
	}
	ids := make(map[uint32]control.WireGuardState, len(state.WireGuards))
	var selected control.WireGuardState
	count := 0
	for _, wg := range state.WireGuards {
		if wg.ID == 0 {
			return selected, fmt.Errorf("production WireGuard %q has zero ID", wg.Name)
		}
		if previous, exists := ids[wg.ID]; exists {
			return selected, fmt.Errorf(
				"production WireGuard ID %d is duplicated by %q and %q", wg.ID, previous.Name, wg.Name,
			)
		}
		ids[wg.ID] = wg
		if wg.TransportMode == "faketcp" {
			selected = wg
			count++
		}
	}
	if count != 1 {
		return selected, fmt.Errorf("production requires exactly one FakeTCP WireGuard; got %d", count)
	}
	check := func(kind string, index int, wgID uint32, mode string) error {
		wg, exists := ids[wgID]
		if !exists {
			return fmt.Errorf("production %s[%d] references unknown WireGuard ID %d", kind, index, wgID)
		}
		if mode != wg.TransportMode {
			return fmt.Errorf(
				"production %s[%d] transport %q does not match WireGuard ID %d transport %q",
				kind, index, mode, wgID, wg.TransportMode,
			)
		}
		if mode == "faketcp" && wgID != selected.ID {
			return fmt.Errorf(
				"production %s[%d] FakeTCP WGID %d does not match sole FakeTCP WireGuard ID %d",
				kind, index, wgID, selected.ID,
			)
		}
		if wgID == selected.ID && mode != "faketcp" {
			return fmt.Errorf(
				"production %s[%d] references FakeTCP WireGuard ID %d with transport %q",
				kind, index, wgID, mode,
			)
		}
		return nil
	}
	for index, rule := range state.EgressRules {
		if err := check("egress", index, rule.WGID, rule.TransportMode); err != nil {
			return selected, err
		}
	}
	for index, listener := range state.IngressListeners {
		if err := check("ingress", index, listener.WGID, listener.TransportMode); err != nil {
			return selected, err
		}
	}
	return selected, nil
}

func validateFakeTCPProductionObjectIdentity(
	scope fakeTCPProductionScopeIdentity,
	identity ObjectIdentity,
) error {
	if identity.Source != scope.fakeTCPObjectPath {
		return fmt.Errorf(
			"production FakeTCP object source %q differs from scope %q",
			identity.Source, scope.fakeTCPObjectPath,
		)
	}
	if identity.Embedded != (scope.fakeTCPObjectPath == EmbeddedFakeTCPObjectSource) {
		return errors.New("production FakeTCP object embedded identity differs from scope")
	}
	digest, err := hex.DecodeString(identity.SHA256)
	if err != nil || len(digest) != sha256.Size {
		return fmt.Errorf("production FakeTCP object %s has invalid SHA-256 identity", identity.Source)
	}
	return nil
}

func fakeTCPProductionXDPRequests(
	plan *fakeTCPPolicyGenerationPlan,
) []fakeTCPXDPAttachRequest {
	requests := make([]fakeTCPXDPAttachRequest, 0, len(plan.managedInterfaces))
	for _, entry := range plan.managedInterfaces {
		requests = append(requests, fakeTCPXDPAttachRequest{
			IfIndex: int(entry.Key.UnderlayIndex),
			Mode:    fakeTCPXDPAttachGeneric,
		})
	}
	return requests
}

type fakeTCPProductionTCXAttachRequest struct {
	ifIndex int
	attach  ebpf.AttachType
}

func fakeTCPProductionTCXRequests(
	state *control.State,
) ([]fakeTCPProductionTCXAttachRequest, error) {
	ifindexes, err := activeAttachIfindexes(state)
	if err != nil {
		return nil, fmt.Errorf("derive production FakeTCP TCX interfaces: %w", err)
	}
	if len(ifindexes) == 0 {
		return nil, errors.New("derive production FakeTCP TCX interfaces: no attachable interfaces")
	}
	requests := make([]fakeTCPProductionTCXAttachRequest, 0, len(ifindexes)*2)
	for _, ifindex := range ifindexes {
		requests = append(requests,
			fakeTCPProductionTCXAttachRequest{ifIndex: ifindex, attach: ebpf.AttachTCXIngress},
			fakeTCPProductionTCXAttachRequest{ifIndex: ifindex, attach: ebpf.AttachTCXEgress},
		)
	}
	return requests, nil
}

func fakeTCPProductionEngineOptions(
	wg control.WireGuardState,
	generation uint64,
) (faketcp.Options, error) {
	seed := make([]byte, sha256.Size)
	if _, err := rand.Read(seed); err != nil {
		return faketcp.Options{}, fmt.Errorf("seed production FakeTCP initial sequence: %w", err)
	}
	var sequence atomic.Uint64
	initialSequence := func() uint32 {
		counter := sequence.Add(1)
		input := make([]byte, 0, len(seed)+8)
		input = append(input, seed...)
		input = binary.BigEndian.AppendUint64(input, counter)
		digest := sha256.Sum256(input)
		value := binary.BigEndian.Uint32(digest[:4])
		if value == 0 {
			return 1
		}
		return value
	}
	options := faketcp.Options{
		Generation:               generation,
		SessionCapacity:          int(wg.FakeTCPSessionCapacity),
		MaxHalfOpenSessions:      int(wg.FakeTCPMaxHalfOpenSessions),
		MaxHalfOpenPerSource:     int(wg.FakeTCPMaxHalfOpenPerSource),
		SYNRateInterval:          time.Duration(wg.FakeTCPSYNRateIntervalNanos),
		SYNBurst:                 int(wg.FakeTCPSYNBurst),
		SYNBurstPerSource:        int(wg.FakeTCPSYNBurstPerSource),
		SYNSourceLedgerCapacity:  int(wg.FakeTCPSYNSourceLedgerCapacity),
		SYNSourceLedgerTTL:       time.Duration(wg.FakeTCPSYNSourceLedgerTTLNanos),
		MaxPendingFlows:          int(wg.FakeTCPMaxPendingFlows),
		MaxPendingPacketsPerFlow: int(wg.FakeTCPMaxPendingPacketsPerFlow),
		MaxPendingBytes:          int(wg.FakeTCPMaxPendingBytes),
		HandshakeTimeout:         time.Duration(wg.FakeTCPHandshakeTimeoutNanos),
		HandshakeRetries:         fakeTCPProductionHandshakeRetries,
		KeepaliveInterval:        time.Duration(wg.FakeTCPKeepaliveIntervalNanos),
		IdleTimeout:              time.Duration(wg.FakeTCPIdleTimeoutNanos),
		Window:                   fakeTCPProductionWindow,
		Now:                      time.Now,
		MonotonicClock:           faketcp.LinuxMonotonicClock{},
		InitialSequence:          initialSequence,
	}
	if err := validateFakeTCPProductionEngineOptions(options); err != nil {
		return faketcp.Options{}, err
	}
	return options, nil
}

func validateFakeTCPProductionEngineOptions(options faketcp.Options) error {
	if options.Generation == 0 {
		return errors.New("validate production FakeTCP Engine: generation is zero")
	}
	if options.SessionCapacity <= 0 || options.MaxPendingFlows <= 0 ||
		options.MaxPendingFlows > options.SessionCapacity ||
		options.MaxPendingPacketsPerFlow <= 0 || options.MaxPendingBytes <= 0 {
		return errors.New("validate production FakeTCP Engine: session and pending limits are invalid")
	}
	if options.MaxHalfOpenSessions <= 0 ||
		options.MaxHalfOpenSessions >= options.SessionCapacity ||
		options.MaxHalfOpenPerSource <= 0 ||
		options.MaxHalfOpenPerSource > options.MaxHalfOpenSessions ||
		options.SYNRateInterval <= 0 || options.SYNBurst <= 0 ||
		options.SYNBurstPerSource <= 0 || options.SYNBurstPerSource > options.SYNBurst ||
		options.SYNSourceLedgerCapacity < options.MaxHalfOpenSessions ||
		options.SYNSourceLedgerTTL < options.SYNRateInterval {
		return errors.New("validate production FakeTCP Engine: half-open and SYN limits are invalid")
	}
	if options.HandshakeTimeout <= 0 || options.HandshakeRetries <= 0 ||
		options.KeepaliveInterval <= 0 || options.IdleTimeout <= options.KeepaliveInterval {
		return errors.New("validate production FakeTCP Engine: timeout and retry limits are invalid")
	}
	if options.Window == 0 || options.Now == nil || options.InitialSequence == nil ||
		options.MonotonicClock == nil ||
		options.MonotonicClock.Domain() != faketcp.BPFMonotonicClockDomain {
		return errors.New("validate production FakeTCP Engine: runtime sources are incomplete")
	}
	if options.Store != nil {
		return errors.New("validate production FakeTCP Engine: Store must be injected by the collection")
	}
	return nil
}

func fakeTCPProductionDesiredKey(
	state *control.State,
	identity ObjectIdentity,
	scope fakeTCPProductionScopeIdentity,
	baseline *abi.Snapshot,
	plan *fakeTCPPolicyGenerationPlan,
	engine faketcp.Options,
	tcx []fakeTCPProductionTCXAttachRequest,
	xdp []fakeTCPXDPAttachRequest,
) (fakeTCPRuntimeDesiredKey, error) {
	if state == nil || baseline == nil || plan == nil {
		return fakeTCPRuntimeDesiredKey{}, errors.New("build production FakeTCP desired key: incomplete input")
	}
	engine.Generation = state.Generation
	h := sha256.New()
	fakeTCPDesiredKeyString(h, "wg-mix-ebpf/faketcp-production-key/v1")
	fakeTCPDesiredKeyString(h, exactTCXBackend)
	fakeTCPDesiredKeyString(h, fakeTCPXDPBackendDirect.String())
	fakeTCPDesiredKeyString(h, identity.Source)
	fakeTCPDesiredKeyString(h, identity.SHA256)
	if identity.Embedded {
		fakeTCPDesiredKeyUint64(h, 1)
	} else {
		fakeTCPDesiredKeyUint64(h, 0)
	}
	fakeTCPDesiredKeyString(h, scope.String())
	// Hash the canonical ABI projections in deterministic binary order. In
	// particular, abi.CipherValue is written directly, including all 256 key
	// bytes; neither control.State.JSON nor abi.CipherValue.MarshalJSON is used.
	for _, encode := range []func() error{
		func() error { return fakeTCPDesiredKeyCanonicalMap(h, baseline.Control) },
		func() error { return fakeTCPDesiredKeyCanonicalMap(h, baseline.Profiles) },
		func() error { return fakeTCPDesiredKeyCanonicalMap(h, baseline.Ciphers) },
		func() error { return fakeTCPDesiredKeyCanonicalMap(h, baseline.Underlays) },
		func() error { return fakeTCPDesiredKeyCanonicalMap(h, baseline.ManagedFwmarks) },
		func() error { return fakeTCPDesiredKeyCanonicalMap(h, baseline.EgressRules) },
		func() error { return fakeTCPDesiredKeyCanonicalMap(h, baseline.IngressListeners) },
		func() error { return fakeTCPDesiredKeyCanonicalMap(h, baseline.ICMPListeners) },
		func() error { return fakeTCPDesiredKeyCanonicalMap(h, plan.snapshot().ControlPolicies) },
		func() error { return fakeTCPDesiredKeyCanonicalMap(h, plan.snapshot().ManagedPorts) },
		func() error { return fakeTCPDesiredKeyCanonicalMap(h, plan.snapshot().ManagedInterfaces) },
	} {
		if err := encode(); err != nil {
			return fakeTCPRuntimeDesiredKey{}, fmt.Errorf(
				"build production FakeTCP desired key projection: %w", err,
			)
		}
	}
	marks, err := buildFakeTCPControllerMarks(state, plan.snapshot())
	if err != nil {
		return fakeTCPRuntimeDesiredKey{}, err
	}
	if err := fakeTCPDesiredKeyCanonicalMap(h, marks); err != nil {
		return fakeTCPRuntimeDesiredKey{}, fmt.Errorf(
			"build production FakeTCP desired key controller marks: %w", err,
		)
	}
	for _, value := range []uint64{
		engine.Generation, uint64(engine.SessionCapacity), uint64(engine.MaxHalfOpenSessions),
		uint64(engine.MaxHalfOpenPerSource), uint64(engine.SYNRateInterval), uint64(engine.SYNBurst),
		uint64(engine.SYNBurstPerSource), uint64(engine.SYNSourceLedgerCapacity),
		uint64(engine.SYNSourceLedgerTTL), uint64(engine.MaxPendingFlows),
		uint64(engine.MaxPendingPacketsPerFlow), uint64(engine.MaxPendingBytes),
		uint64(engine.HandshakeTimeout), uint64(engine.HandshakeRetries),
		uint64(engine.KeepaliveInterval), uint64(engine.IdleTimeout), uint64(engine.Window),
		uint64(fakeTCPXDPRequireExactSelectedMode),
	} {
		fakeTCPDesiredKeyUint64(h, value)
	}
	for _, request := range tcx {
		fakeTCPDesiredKeyUint64(h, uint64(request.ifIndex))
		fakeTCPDesiredKeyUint64(h, uint64(request.attach))
	}
	for _, request := range xdp {
		fakeTCPDesiredKeyUint64(h, uint64(request.IfIndex))
		fakeTCPDesiredKeyUint64(h, uint64(request.Mode))
	}
	var key fakeTCPRuntimeDesiredKey
	copy(key[:], h.Sum(nil))
	if key == (fakeTCPRuntimeDesiredKey{}) {
		return key, errors.New("build production FakeTCP desired key: digest is zero")
	}
	return key, nil
}

func fakeTCPDesiredKeyBytes(h hash.Hash, value []byte) {
	fakeTCPDesiredKeyUint64(h, uint64(len(value)))
	_, _ = h.Write(value)
}

func fakeTCPDesiredKeyString(h hash.Hash, value string) {
	fakeTCPDesiredKeyBytes(h, []byte(value))
}

func fakeTCPDesiredKeyUint64(h hash.Hash, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	_, _ = h.Write(encoded[:])
}

func fakeTCPDesiredKeyCanonicalMap[K comparable, V any](
	h hash.Hash,
	values map[K]V,
) error {
	type encodedEntry struct {
		key   []byte
		value []byte
	}
	entries := make([]encodedEntry, 0, len(values))
	for key, value := range values {
		var encodedKey bytes.Buffer
		if err := binary.Write(&encodedKey, binary.BigEndian, key); err != nil {
			return fmt.Errorf("encode key: %w", err)
		}
		var encodedValue bytes.Buffer
		if err := binary.Write(&encodedValue, binary.BigEndian, value); err != nil {
			return fmt.Errorf("encode value: %w", err)
		}
		entries = append(entries, encodedEntry{
			key: encodedKey.Bytes(), value: encodedValue.Bytes(),
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		return bytes.Compare(entries[i].key, entries[j].key) < 0
	})
	fakeTCPDesiredKeyUint64(h, uint64(len(entries)))
	for _, entry := range entries {
		fakeTCPDesiredKeyBytes(h, entry.key)
		fakeTCPDesiredKeyBytes(h, entry.value)
	}
	return nil
}

type productionFakeTCPTCXPlannedAttachment struct {
	request  fakeTCPProductionTCXAttachRequest
	revision uint64
	program  exactTCXProgram
}

type productionFakeTCPTCXAttachment struct {
	request  fakeTCPProductionTCXAttachRequest
	identity exactTCXLinkIdentity
	link     exactTCXKernelLink
}

// productionFakeTCPTCXStage is an FD-owned, resident-runtime TCX owner. It
// differs from the durable baseline owner: every slot must be empty, every
// attach is fenced by the aggregate revision and anchored at head, and the
// exact link/program identity is re-read before activation.
type productionFakeTCPTCXStage struct {
	mu          sync.Mutex
	runtime     exactTCXRuntime
	attachments []productionFakeTCPTCXAttachment
}

func stageProductionFakeTCPTCX(
	ctx context.Context,
	state *control.State,
	ingress experimentalProgramResource,
	egress experimentalProgramResource,
	commit func() error,
	runtime exactTCXRuntime,
) (*productionFakeTCPTCXStage, error) {
	if ctx == nil {
		return nil, errors.New("stage production FakeTCP TCX: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if state == nil || ingress == nil || egress == nil || commit == nil {
		return nil, errors.New("stage production FakeTCP TCX: inputs are incomplete")
	}
	if err := validateExactTCXRuntime(runtime); err != nil {
		return nil, fmt.Errorf("stage production FakeTCP TCX: %w", err)
	}
	requests, err := fakeTCPProductionTCXRequests(state)
	if err != nil {
		return nil, err
	}
	ingressID, err := ingress.ID()
	if err != nil {
		return nil, fmt.Errorf("stage production FakeTCP TCX ingress identity: %w", err)
	}
	egressID, err := egress.ID()
	if err != nil {
		return nil, fmt.Errorf("stage production FakeTCP TCX egress identity: %w", err)
	}
	programs := map[ebpf.AttachType]exactTCXProgram{
		ebpf.AttachTCXIngress: {id: ingressID, kernel: ingress.kernelProgram()},
		ebpf.AttachTCXEgress:  {id: egressID, kernel: egress.kernelProgram()},
	}
	planned := make([]productionFakeTCPTCXPlannedAttachment, 0, len(requests))
	// Probe every aggregate before the first write. A baseline detach precedes
	// this builder, so any remaining program is foreign or stale and must not be
	// reordered, replaced, or chained by the production FakeTCP owner.
	for _, request := range requests {
		query, err := runtime.query(request.ifIndex, request.attach)
		if err != nil {
			return nil, fmt.Errorf(
				"stage production FakeTCP TCX query %d/%s: %w",
				request.ifIndex, request.attach, err,
			)
		}
		if err := validateExactTCXQuery(query); err != nil {
			return nil, fmt.Errorf(
				"stage production FakeTCP TCX validate %d/%s: %w",
				request.ifIndex, request.attach, err,
			)
		}
		if len(query.Programs) != 0 {
			return nil, fmt.Errorf(
				"stage production FakeTCP TCX %d/%s: aggregate has %d unowned programs",
				request.ifIndex, request.attach, len(query.Programs),
			)
		}
		planned = append(planned, productionFakeTCPTCXPlannedAttachment{
			request: request, revision: query.Revision, program: programs[request.attach],
		})
	}

	stage := &productionFakeTCPTCXStage{runtime: runtime}
	fail := func(cause error) (*productionFakeTCPTCXStage, error) {
		if len(stage.attachments) == 0 {
			return nil, cause
		}
		return stage, cause
	}
	for _, plan := range planned {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		owned, err := runtime.attach(
			plan.request.ifIndex, plan.request.attach, plan.revision, plan.program,
		)
		if err != nil {
			return fail(fmt.Errorf(
				"stage production FakeTCP TCX attach %d/%s: %w",
				plan.request.ifIndex, plan.request.attach, err,
			))
		}
		if owned == nil {
			return fail(fmt.Errorf(
				"stage production FakeTCP TCX attach %d/%s returned nil owner",
				plan.request.ifIndex, plan.request.attach,
			))
		}
		stage.attachments = append(stage.attachments, productionFakeTCPTCXAttachment{
			request: plan.request, link: owned,
		})
		attachment := &stage.attachments[len(stage.attachments)-1]
		identity, err := owned.Identity()
		if err != nil {
			return stage, fmt.Errorf(
				"stage production FakeTCP TCX inspect %d/%s: %w",
				plan.request.ifIndex, plan.request.attach, err,
			)
		}
		if err := validateProductionFakeTCPTCXIdentity(plan, identity); err != nil {
			return stage, err
		}
		attachment.identity = identity
		post, err := runtime.query(plan.request.ifIndex, plan.request.attach)
		if err != nil {
			return stage, fmt.Errorf(
				"stage production FakeTCP TCX post-query %d/%s: %w",
				plan.request.ifIndex, plan.request.attach, err,
			)
		}
		if err := validateProductionFakeTCPTCXPostQuery(post, identity); err != nil {
			return stage, fmt.Errorf(
				"stage production FakeTCP TCX post-query %d/%s: %w",
				plan.request.ifIndex, plan.request.attach, err,
			)
		}
	}
	// A foreign writer may alter an earlier aggregate while later hooks are
	// being attached. Re-prove the complete exact owner set immediately before
	// the policy/control commit; no hook that passed an earlier post-check is
	// trusted without this final all-hooks observation.
	for _, attachment := range stage.attachments {
		if err := ctx.Err(); err != nil {
			return stage, err
		}
		query, err := runtime.query(
			attachment.request.ifIndex, attachment.request.attach,
		)
		if err != nil {
			return stage, fmt.Errorf(
				"stage production FakeTCP TCX final query %d/%s: %w",
				attachment.request.ifIndex, attachment.request.attach, err,
			)
		}
		if err := validateProductionFakeTCPTCXPostQuery(query, attachment.identity); err != nil {
			return stage, fmt.Errorf(
				"stage production FakeTCP TCX final query %d/%s: %w",
				attachment.request.ifIndex, attachment.request.attach, err,
			)
		}
	}
	if err := ctx.Err(); err != nil {
		return stage, err
	}
	if err := commit(); err != nil {
		return stage, fmt.Errorf("activate production FakeTCP TCX owner: %w", err)
	}
	return stage, nil
}

func validateProductionFakeTCPTCXIdentity(
	plan productionFakeTCPTCXPlannedAttachment,
	identity exactTCXLinkIdentity,
) error {
	if identity.IfIndex != plan.request.ifIndex || identity.Attach != plan.request.attach ||
		identity.LinkID == 0 || identity.ProgramID != plan.program.id {
		return fmt.Errorf(
			"production FakeTCP TCX identity %+v differs from request ifindex=%d attach=%s program=%d",
			identity, plan.request.ifIndex, plan.request.attach, plan.program.id,
		)
	}
	return nil
}

func validateProductionFakeTCPTCXPostQuery(
	query exactTCXQuery,
	identity exactTCXLinkIdentity,
) error {
	if err := validateExactTCXQuery(query); err != nil {
		return err
	}
	if len(query.Programs) != 1 || query.Programs[0].LinkID != identity.LinkID ||
		query.Programs[0].ProgramID != identity.ProgramID {
		return fmt.Errorf(
			"aggregate identity %+v does not contain only link/program %d/%d",
			query.Programs, identity.LinkID, identity.ProgramID,
		)
	}
	return nil
}

func (stage *productionFakeTCPTCXStage) Close() error {
	if stage == nil {
		return nil
	}
	stage.mu.Lock()
	defer stage.mu.Unlock()
	var errs []error
	remaining := make([]productionFakeTCPTCXAttachment, 0, len(stage.attachments))
	for index := len(stage.attachments) - 1; index >= 0; index-- {
		attachment := stage.attachments[index]
		if attachment.link == nil {
			continue
		}
		if err := attachment.link.Close(); err != nil {
			errs = append(errs, fmt.Errorf(
				"close production FakeTCP TCX %d/%s link %d: %w",
				attachment.request.ifIndex, attachment.request.attach,
				attachment.identity.LinkID, err,
			))
			remaining = append([]productionFakeTCPTCXAttachment{attachment}, remaining...)
		}
	}
	stage.attachments = remaining
	return errors.Join(errs...)
}

// Healthy re-proves both the retained FD identity and the aggregate identity
// for every production attachment. It serializes with Close so status cannot
// report a partially retired owner as healthy.
func (stage *productionFakeTCPTCXStage) Healthy(ctx context.Context) error {
	if ctx == nil {
		return errors.New("inspect production FakeTCP TCX health: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if stage == nil {
		return errors.New("inspect production FakeTCP TCX health: stage is nil")
	}
	stage.mu.Lock()
	defer stage.mu.Unlock()
	if len(stage.attachments) == 0 {
		return errors.New("inspect production FakeTCP TCX health: owner has no attachments")
	}
	if err := validateExactTCXRuntime(stage.runtime); err != nil {
		return fmt.Errorf("inspect production FakeTCP TCX health: %w", err)
	}
	for _, attachment := range stage.attachments {
		if err := ctx.Err(); err != nil {
			return err
		}
		if attachment.link == nil || attachment.identity.LinkID == 0 {
			return errors.New("inspect production FakeTCP TCX health: attachment owner is incomplete")
		}
		identity, err := attachment.link.Identity()
		if err != nil {
			return fmt.Errorf(
				"inspect production FakeTCP TCX health %d/%s link: %w",
				attachment.request.ifIndex, attachment.request.attach, err,
			)
		}
		if identity != attachment.identity {
			return fmt.Errorf(
				"inspect production FakeTCP TCX health %d/%s: identity %+v changed from %+v",
				attachment.request.ifIndex, attachment.request.attach,
				identity, attachment.identity,
			)
		}
		query, err := stage.runtime.query(
			attachment.request.ifIndex, attachment.request.attach,
		)
		if err != nil {
			return fmt.Errorf(
				"inspect production FakeTCP TCX health %d/%s aggregate: %w",
				attachment.request.ifIndex, attachment.request.attach, err,
			)
		}
		if err := validateProductionFakeTCPTCXPostQuery(query, attachment.identity); err != nil {
			return fmt.Errorf(
				"inspect production FakeTCP TCX health %d/%s aggregate: %w",
				attachment.request.ifIndex, attachment.request.attach, err,
			)
		}
	}
	return nil
}

func (stage *productionFakeTCPTCXStage) status() []FakeTCPTCXStatus {
	if stage == nil {
		return nil
	}
	stage.mu.Lock()
	defer stage.mu.Unlock()
	result := make([]FakeTCPTCXStatus, 0, len(stage.attachments))
	for _, attachment := range stage.attachments {
		direction := "unknown"
		switch attachment.identity.Attach {
		case ebpf.AttachTCXIngress:
			direction = string(exactTCXIngress)
		case ebpf.AttachTCXEgress:
			direction = string(exactTCXEgress)
		}
		result = append(result, FakeTCPTCXStatus{
			IfIndex: attachment.identity.IfIndex, Direction: direction,
			AttachType: uint32(attachment.identity.Attach),
			LinkID:     attachment.identity.LinkID, ProgramID: attachment.identity.ProgramID,
		})
	}
	return result
}
