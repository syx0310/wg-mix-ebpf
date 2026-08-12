package faketcp

import (
	"context"
	"errors"
	"fmt"
	"path"
	"sync"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

var ErrControllerRuntimeFactoryConsumed = errors.New(
	"faketcp controller runtime factory capability is consumed",
)

// ControllerRuntimeScope is the immutable userspace ownership domain for one
// production slow path. PinPath names the already-canonical production pin
// scope; the slow path never discovers or follows an alternate path.
type ControllerRuntimeScope struct {
	Generation uint64
	PinPath    string
}

type ControllerRuntimeFactoryOptions struct {
	Scope          ControllerRuntimeScope
	ControlMarks   map[uint32]uint32
	PollInterval   time.Duration
	TickInterval   time.Duration
	RawSendTimeout time.Duration
}

// ControllerRuntimeFactory is a single-use capability. Copies share one
// state, so copying the Go value cannot create a second ring consumer, raw
// sender, or once-only reinjection ledger. Construction selects the sole
// production backend (Linux ring buffer plus raw IPv4) up front; Run has no
// fallback branch.
type ControllerRuntimeFactory struct {
	state *controllerRuntimeFactoryState
}

type controllerRuntimeFactoryState struct {
	mu sync.Mutex

	scope          ControllerRuntimeScope
	controlMarks   *fixedControlMarks
	pollInterval   time.Duration
	tickInterval   time.Duration
	rawSendTimeout time.Duration
	consumed       bool
}

type fixedControlMarks struct {
	generation uint64
	marks      map[uint32]uint32
}

func NewControllerRuntimeFactory(
	options ControllerRuntimeFactoryOptions,
) (ControllerRuntimeFactory, error) {
	if err := validateControllerRuntimeScope(options.Scope); err != nil {
		return ControllerRuntimeFactory{}, err
	}
	marks, err := newFixedControlMarks(options.Scope.Generation, options.ControlMarks)
	if err != nil {
		return ControllerRuntimeFactory{}, err
	}
	if options.PollInterval <= 0 || options.TickInterval <= 0 || options.RawSendTimeout <= 0 {
		return ControllerRuntimeFactory{}, errors.New(
			"faketcp controller runtime intervals and raw send timeout must be positive",
		)
	}
	return ControllerRuntimeFactory{state: &controllerRuntimeFactoryState{
		scope:          options.Scope,
		controlMarks:   marks,
		pollInterval:   options.PollInterval,
		tickInterval:   options.TickInterval,
		rawSendTimeout: options.RawSendTimeout,
	}}, nil
}

func validateControllerRuntimeScope(scope ControllerRuntimeScope) error {
	if scope.Generation == 0 {
		return errors.New("faketcp controller runtime scope generation is zero")
	}
	if scope.PinPath == "" || !path.IsAbs(scope.PinPath) {
		return fmt.Errorf("faketcp controller runtime pin scope %q is not absolute", scope.PinPath)
	}
	if cleaned := path.Clean(scope.PinPath); cleaned != scope.PinPath {
		return fmt.Errorf(
			"faketcp controller runtime pin scope %q is not canonical (clean spelling %q)",
			scope.PinPath,
			cleaned,
		)
	}
	if path.Dir(scope.PinPath) == scope.PinPath {
		return errors.New("faketcp controller runtime pin scope must not be a filesystem root")
	}
	return nil
}

func newFixedControlMarks(
	generation uint64,
	controlMarks map[uint32]uint32,
) (*fixedControlMarks, error) {
	if generation == 0 {
		return nil, errors.New("faketcp control mark generation is zero")
	}
	if len(controlMarks) == 0 {
		return nil, errors.New("faketcp control mark table is empty")
	}
	marks := make(map[uint32]uint32, len(controlMarks))
	for wgID, mark := range controlMarks {
		if wgID == 0 || mark == 0 {
			return nil, fmt.Errorf(
				"faketcp control mark entry has invalid WireGuard ID %d or mark %#x",
				wgID,
				mark,
			)
		}
		marks[wgID] = mark
	}
	return &fixedControlMarks{generation: generation, marks: marks}, nil
}

func (marks *fixedControlMarks) ControlMark(
	ctx context.Context,
	flow abi.FakeTCPSessionKey,
	wgID uint32,
) (uint32, error) {
	if marks == nil || marks.generation == 0 || len(marks.marks) == 0 {
		return 0, errors.New("faketcp fixed control mark table is unavailable")
	}
	if ctx == nil {
		return 0, errors.New("resolve faketcp fixed control mark: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if err := validatePacketFlow(flow); err != nil {
		return 0, fmt.Errorf("faketcp control flow is invalid: %w", err)
	}
	if flow.Generation != marks.generation {
		return 0, fmt.Errorf(
			"faketcp control flow generation %d does not match fixed generation %d",
			flow.Generation,
			marks.generation,
		)
	}
	if wgID != flow.WGID {
		return 0, fmt.Errorf(
			"faketcp control WireGuard ID %d does not match flow WGID %d",
			wgID,
			flow.WGID,
		)
	}
	mark, ok := marks.marks[wgID]
	if !ok {
		return 0, fmt.Errorf("faketcp control mark for WireGuard ID %d is not configured", wgID)
	}
	return mark, nil
}

type controllerRuntimeClaim struct {
	binding        ControllerRuntimeBinding
	controlMarks   *fixedControlMarks
	pollInterval   time.Duration
	tickInterval   time.Duration
	rawSendTimeout time.Duration
	possibleCPUs   int
}

func (factory ControllerRuntimeFactory) claim(
	identity RuntimeIdentity,
	eventMapID uint32,
	statsMapID uint32,
	possibleCPUs int,
) (controllerRuntimeClaim, error) {
	state := factory.state
	if state == nil {
		return controllerRuntimeClaim{}, errors.New("faketcp controller runtime factory is nil")
	}
	if err := validateRuntimeIdentity(identity); err != nil {
		return controllerRuntimeClaim{}, err
	}
	if eventMapID == 0 || statsMapID == 0 || eventMapID == statsMapID {
		return controllerRuntimeClaim{}, errors.New("faketcp controller runtime map identities are invalid")
	}
	if possibleCPUs <= 0 {
		return controllerRuntimeClaim{}, errors.New("faketcp controller runtime possible CPU count must be positive")
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.consumed {
		return controllerRuntimeClaim{}, ErrControllerRuntimeFactoryConsumed
	}
	if identity.Generation != state.scope.Generation {
		return controllerRuntimeClaim{}, fmt.Errorf(
			"faketcp controller runtime identity generation %d does not match scope generation %d",
			identity.Generation,
			state.scope.Generation,
		)
	}
	state.consumed = true
	return controllerRuntimeClaim{
		binding: ControllerRuntimeBinding{
			Scope: state.scope, RuntimeIdentity: identity,
			EventMapID: eventMapID, StatsMapID: statsMapID,
		},
		controlMarks:   state.controlMarks,
		pollInterval:   state.pollInterval,
		tickInterval:   state.tickInterval,
		rawSendTimeout: state.rawSendTimeout,
		possibleCPUs:   possibleCPUs,
	}, nil
}

type ControllerRuntimeBinding struct {
	Scope           ControllerRuntimeScope
	RuntimeIdentity RuntimeIdentity
	EventMapID      uint32
	StatsMapID      uint32
}

// ControllerRuntime owns exactly one EventRuntime. Copies share this pointer
// and therefore the same reader/controller/backend lifecycle.
type ControllerRuntime struct {
	events  *EventRuntime
	binding ControllerRuntimeBinding
}

var _ RuntimeService = (*ControllerRuntime)(nil)
var _ RuntimeStopRequester = (*ControllerRuntime)(nil)

func newOwnedControllerRuntime(
	engine *Engine,
	reader EventReader,
	writer RawIPv4Writer,
	claim controllerRuntimeClaim,
) (*ControllerRuntime, error) {
	if engine == nil || engine.Identity() != claim.binding.RuntimeIdentity {
		return nil, errors.Join(
			errors.New("faketcp controller runtime Engine identity does not match claimed binding"),
			closeControllerRuntimeResource("event reader", reader),
			closeControllerRuntimeResource("raw writer", writer),
		)
	}
	return newOwnedControllerRuntimeWithDispatcher(
		reader,
		writer,
		claim,
		func(backend ControllerBackend) (*Controller, error) {
			return NewController(engine, backend)
		},
	)
}

// newOwnedRoutedControllerRuntime is the multi-WireGuard counterpart of
// newOwnedControllerRuntime. The EngineRouter retains every per-WG Engine,
// while the surrounding ControllerRuntime still owns exactly one reader,
// backend, raw writer, and event loop for the shared kernel collection.
func newOwnedRoutedControllerRuntime(
	router *EngineRouter,
	reader EventReader,
	writer RawIPv4Writer,
	claim controllerRuntimeClaim,
) (*ControllerRuntime, error) {
	if router == nil || router.Identity() != claim.binding.RuntimeIdentity {
		return nil, errors.Join(
			errors.New("faketcp controller runtime EngineRouter identity does not match claimed binding"),
			closeControllerRuntimeResource("event reader", reader),
			closeControllerRuntimeResource("raw writer", writer),
		)
	}
	return newOwnedControllerRuntimeWithDispatcher(
		reader,
		writer,
		claim,
		func(backend ControllerBackend) (*Controller, error) {
			return NewRoutedController(router, backend)
		},
	)
}

func newOwnedControllerRuntimeWithDispatcher(
	reader EventReader,
	writer RawIPv4Writer,
	claim controllerRuntimeClaim,
	newController func(ControllerBackend) (*Controller, error),
) (*ControllerRuntime, error) {
	if newController == nil {
		return nil, errors.Join(
			errors.New("faketcp controller runtime dispatcher constructor is nil"),
			closeControllerRuntimeResource("event reader", reader),
			closeControllerRuntimeResource("raw writer", writer),
		)
	}
	backend, err := NewRawControllerBackend(RawControllerBackendOptions{
		Writer:             writer,
		ControlMarks:       claim.controlMarks,
		RuntimeIdentity:    claim.binding.RuntimeIdentity,
		MaxReinjectStreams: claim.possibleCPUs,
	})
	if err != nil {
		return nil, errors.Join(
			err,
			closeControllerRuntimeResource("event reader", reader),
			closeControllerRuntimeResource("raw writer", writer),
		)
	}
	controller, err := newController(backend)
	if err != nil {
		return nil, errors.Join(
			err,
			closeControllerRuntimeResource("event reader", reader),
			closeControllerRuntimeResource("controller backend", backend),
		)
	}
	events, err := newOwnedEventRuntime(reader, controller, EventRuntimeOptions{
		PollInterval: claim.pollInterval,
		TickInterval: claim.tickInterval,
	})
	if err != nil {
		return nil, errors.Join(
			err,
			closeControllerRuntimeResource("event reader", reader),
			closeControllerRuntimeResource("controller", controller),
		)
	}
	return &ControllerRuntime{events: events, binding: claim.binding}, nil
}

func closeControllerRuntimeResource(resource string, closer interface{ Close() error }) error {
	if interfaceValueIsNil(closer) {
		return nil
	}
	if err := closer.Close(); err != nil {
		return fmt.Errorf("close faketcp controller runtime %s: %w", resource, err)
	}
	return nil
}

func (runtime *ControllerRuntime) Binding() ControllerRuntimeBinding {
	if runtime == nil {
		return ControllerRuntimeBinding{}
	}
	return runtime.binding
}

func (runtime *ControllerRuntime) Run(ctx context.Context) error {
	if runtime == nil || runtime.events == nil {
		return ErrEventRuntimeClosed
	}
	return runtime.events.Run(ctx)
}

func (runtime *ControllerRuntime) RequestStop() error {
	if runtime == nil || runtime.events == nil {
		return ErrEventRuntimeClosed
	}
	return runtime.events.RequestStop()
}

func (runtime *ControllerRuntime) Close() error {
	if runtime == nil || runtime.events == nil {
		return nil
	}
	return runtime.events.Close()
}
