package faketcp

import (
	"errors"
	"fmt"
	"sort"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

var (
	ErrEngineRouteInvalid  = errors.New("faketcp engine route is invalid")
	ErrEngineRouteConflict = errors.New("faketcp engine route conflicts with another route")
	ErrEngineRouteRejected = errors.New("faketcp event or action has no exact engine route")
)

// WGEngineBinding assigns exactly one independently-owned Engine to one
// WireGuard identity. All bindings in a router must belong to its one
// RuntimeDomain.
type WGEngineBinding struct {
	WGID   uint32
	Engine *Engine
}

// EngineRoute is the complete userspace projection of one managed FakeTCP
// listener. Action must be abi.ActionRewrite. FWMark is the exact captured
// egress mark accepted for NEED_HANDSHAKE events on this route.
type EngineRoute struct {
	Generation    uint64
	UnderlayIndex uint32
	LocalPort     uint16
	WGID          uint32
	FWMark        uint32
	Action        uint8
}

type engineRouteKey struct {
	generation    uint64
	underlayIndex uint32
	localPort     uint16
}

type engineRouteTarget struct {
	wgID   uint32
	fwmark uint32
}

// EngineRouter is an immutable exact dispatcher for one runtime generation.
// Its route and ordering tables are private copies of constructor input.
type EngineRouter struct {
	identity RuntimeIdentity
	engines  map[uint32]*Engine
	routes   map[engineRouteKey]engineRouteTarget
	wgIDs    []uint32
}

// NewEngineRouter freezes a strict multi-WireGuard dispatch table. Duplicate
// route keys are conflicts even when their values are equal: accepting equal
// duplicates would hide multiple configuration authorities.
func NewEngineRouter(
	domain *RuntimeDomain,
	bindings []WGEngineBinding,
	routes []EngineRoute,
) (*EngineRouter, error) {
	if domain == nil || domain.state == nil {
		return nil, fmt.Errorf("%w: runtime domain is nil", ErrEngineRouteInvalid)
	}
	if len(bindings) == 0 || len(routes) == 0 {
		return nil, fmt.Errorf("%w: bindings and routes must be non-empty", ErrEngineRouteInvalid)
	}

	engines := make(map[uint32]*Engine, len(bindings))
	owners := make(map[*Engine]uint32, len(bindings))
	for index, binding := range bindings {
		if binding.WGID == 0 || binding.Engine == nil {
			return nil, fmt.Errorf("%w: binding[%d] has zero WGID or nil Engine", ErrEngineRouteInvalid, index)
		}
		if _, exists := engines[binding.WGID]; exists {
			return nil, fmt.Errorf("%w: duplicate binding for WGID %d", ErrEngineRouteConflict, binding.WGID)
		}
		if owner, exists := owners[binding.Engine]; exists {
			return nil, fmt.Errorf(
				"%w: one Engine is assigned to WGIDs %d and %d",
				ErrEngineRouteConflict,
				owner,
				binding.WGID,
			)
		}
		engine := binding.Engine
		if engine.domain != domain.state || engine.Identity() != domain.Identity() ||
			engine.runtimeIdentityCommit != domain.state.runtimeIdentityCommit ||
			engine.sessionIDs != domain.state.sessionIDs {
			return nil, fmt.Errorf(
				"%w: Engine for WGID %d does not belong to the router RuntimeDomain",
				ErrEngineRouteInvalid,
				binding.WGID,
			)
		}
		engines[binding.WGID] = engine
		owners[engine] = binding.WGID
	}

	frozenRoutes := make(map[engineRouteKey]engineRouteTarget, len(routes))
	referenced := make(map[uint32]struct{}, len(bindings))
	marks := make(map[uint32]uint32, len(bindings))
	identity := domain.Identity()
	for index, route := range routes {
		if route.Generation != identity.Generation || route.UnderlayIndex == 0 ||
			route.LocalPort == 0 || route.WGID == 0 || route.FWMark == 0 {
			return nil, fmt.Errorf("%w: route[%d] has incomplete identity", ErrEngineRouteInvalid, index)
		}
		if route.Action != abi.ActionRewrite {
			return nil, fmt.Errorf(
				"%w: route[%d] action %d is not rewrite",
				ErrEngineRouteInvalid,
				index,
				route.Action,
			)
		}
		if _, exists := engines[route.WGID]; !exists {
			return nil, fmt.Errorf(
				"%w: route[%d] references unknown WGID %d",
				ErrEngineRouteInvalid,
				index,
				route.WGID,
			)
		}
		if mark, exists := marks[route.WGID]; exists && mark != route.FWMark {
			return nil, fmt.Errorf(
				"%w: WGID %d has marks %#x and %#x",
				ErrEngineRouteConflict,
				route.WGID,
				mark,
				route.FWMark,
			)
		}
		key := engineRouteKey{
			generation: route.Generation, underlayIndex: route.UnderlayIndex, localPort: route.LocalPort,
		}
		if _, exists := frozenRoutes[key]; exists {
			return nil, fmt.Errorf(
				"%w: duplicate generation=%d underlay=%d local-port=%d",
				ErrEngineRouteConflict,
				key.generation,
				key.underlayIndex,
				key.localPort,
			)
		}
		frozenRoutes[key] = engineRouteTarget{wgID: route.WGID, fwmark: route.FWMark}
		marks[route.WGID] = route.FWMark
		referenced[route.WGID] = struct{}{}
	}

	wgIDs := make([]uint32, 0, len(engines))
	for wgID := range engines {
		if _, exists := referenced[wgID]; !exists {
			return nil, fmt.Errorf("%w: WGID %d has no route", ErrEngineRouteInvalid, wgID)
		}
		wgIDs = append(wgIDs, wgID)
	}
	sort.Slice(wgIDs, func(left, right int) bool { return wgIDs[left] < wgIDs[right] })
	return &EngineRouter{
		identity: identity,
		engines:  engines,
		routes:   frozenRoutes,
		wgIDs:    wgIDs,
	}, nil
}

func (router *EngineRouter) Identity() RuntimeIdentity {
	if router == nil {
		return RuntimeIdentity{}
	}
	return router.identity
}

func (router *EngineRouter) selectEngine(event abi.FakeTCPEvent) (dispatchedEngine, error) {
	if router == nil || len(router.engines) == 0 || len(router.routes) == 0 {
		return dispatchedEngine{}, fmt.Errorf("%w: router is unavailable", ErrEngineRouteRejected)
	}
	key := engineRouteKey{
		generation: event.Key.Generation, underlayIndex: event.Key.UnderlayIndex, localPort: event.Key.LocalPort,
	}
	target, exists := router.routes[key]
	if !exists {
		return dispatchedEngine{}, fmt.Errorf(
			"%w: generation=%d underlay=%d local-port=%d is unknown",
			ErrEngineRouteRejected,
			key.generation,
			key.underlayIndex,
			key.localPort,
		)
	}
	if event.WGID != target.wgID {
		return dispatchedEngine{}, fmt.Errorf(
			"%w: event WGID %d does not match route WGID %d",
			ErrEngineRouteRejected,
			event.WGID,
			target.wgID,
		)
	}
	if event.Type == abi.FakeTCPEventNeedHandshake {
		if event.FWMark != target.fwmark {
			return dispatchedEngine{}, fmt.Errorf(
				"%w: event mark %#x does not match route mark %#x",
				ErrEngineRouteRejected,
				event.FWMark,
				target.fwmark,
			)
		}
	} else if event.FWMark != 0 {
		return dispatchedEngine{}, fmt.Errorf(
			"%w: inbound control event has mark %#x",
			ErrEngineRouteRejected,
			event.FWMark,
		)
	}
	return dispatchedEngine{engine: router.engines[target.wgID], wgID: target.wgID}, nil
}

func (router *EngineRouter) Tick() ([]Action, error) {
	if router == nil || len(router.wgIDs) == 0 {
		return nil, fmt.Errorf("%w: router is unavailable", ErrEngineRouteRejected)
	}
	var actions []Action
	var errs []error
	for _, wgID := range router.wgIDs {
		engineActions, err := router.engines[wgID].Tick()
		if err != nil {
			errs = append(errs, fmt.Errorf("tick faketcp WGID %d: %w", wgID, err))
		}
		if err := router.validateActions(wgID, engineActions); err != nil {
			errs = append(errs, fmt.Errorf("validate faketcp WGID %d tick actions: %w", wgID, err))
			continue
		}
		actions = append(actions, engineActions...)
	}
	return actions, errors.Join(errs...)
}

// validateActions fences every backend-visible action behind the same exact
// immutable route that admitted its event or Tick owner.
func (router *EngineRouter) validateActions(ownerWGID uint32, actions []Action) error {
	for index, action := range actions {
		key := engineRouteKey{
			generation:    action.Flow.Generation,
			underlayIndex: action.Flow.UnderlayIndex,
			localPort:     action.Flow.LocalPort,
		}
		target, exists := router.routes[key]
		if !exists {
			return fmt.Errorf("%w: action[%d] flow is unknown", ErrEngineRouteRejected, index)
		}
		if target.wgID != ownerWGID {
			return fmt.Errorf(
				"%w: action[%d] route WGID %d does not match owner WGID %d",
				ErrEngineRouteRejected,
				index,
				target.wgID,
				ownerWGID,
			)
		}
		switch action.Kind {
		case ActionDrop, ActionForward, ActionClose:
		case ActionSendControl:
			if action.WGID != target.wgID {
				return fmt.Errorf(
					"%w: action[%d] WGID %d does not match route WGID %d",
					ErrEngineRouteRejected,
					index,
					action.WGID,
					target.wgID,
				)
			}
		case ActionReleasePending:
			if action.WGID != target.wgID || len(action.Packets) == 0 {
				return fmt.Errorf("%w: action[%d] has no canonical pending WGID", ErrEngineRouteRejected, index)
			}
			for packetIndex, packet := range action.Packets {
				if packet.WGID != target.wgID || packet.FWMark != target.fwmark {
					return fmt.Errorf(
						"%w: action[%d] packet[%d] does not match WGID/mark route",
						ErrEngineRouteRejected,
						index,
						packetIndex,
					)
				}
			}
		default:
			return fmt.Errorf("%w: action[%d] kind %d is unknown", ErrEngineRouteRejected, index, action.Kind)
		}
	}
	return nil
}

type dispatchedEngine struct {
	engine *Engine
	wgID   uint32
}

type controllerEngineDispatcher interface {
	Identity() RuntimeIdentity
	selectEngine(abi.FakeTCPEvent) (dispatchedEngine, error)
	Tick() ([]Action, error)
	validateActions(uint32, []Action) error
}

type singleEngineDispatcher struct {
	engine *Engine
}

func (dispatcher *singleEngineDispatcher) Identity() RuntimeIdentity {
	if dispatcher == nil || dispatcher.engine == nil {
		return RuntimeIdentity{}
	}
	return dispatcher.engine.Identity()
}

func (dispatcher *singleEngineDispatcher) selectEngine(abi.FakeTCPEvent) (dispatchedEngine, error) {
	if dispatcher == nil || dispatcher.engine == nil {
		return dispatchedEngine{}, errors.New("faketcp single-engine dispatcher is unavailable")
	}
	return dispatchedEngine{engine: dispatcher.engine}, nil
}

func (dispatcher *singleEngineDispatcher) Tick() ([]Action, error) {
	if dispatcher == nil || dispatcher.engine == nil {
		return nil, errors.New("faketcp single-engine dispatcher is unavailable")
	}
	return dispatcher.engine.Tick()
}

func (*singleEngineDispatcher) validateActions(uint32, []Action) error { return nil }
