package faketcp

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

type routerTestFixture struct {
	domain     *RuntimeDomain
	router     *EngineRouter
	controller *Controller
	backend    *fakeControllerBackend
	bindings   []WGEngineBinding
	routes     map[uint32]EngineRoute
	engines    map[uint32]*Engine
	stores     map[uint32]*fakeSessionStore
	clocks     map[uint32]*fakeClock
}

func newRouterTestFixture(
	t *testing.T,
	wgIDs []uint32,
	mutate func(uint32, *Options),
) *routerTestFixture {
	t.Helper()
	domain, bindings, routeList, engines, stores, clocks := routerTestParts(t, wgIDs, mutate)
	router, err := NewEngineRouter(domain, bindings, routeList)
	if err != nil {
		t.Fatal(err)
	}
	backend := &fakeControllerBackend{}
	controller, err := NewRoutedController(router, backend)
	if err != nil {
		t.Fatal(err)
	}
	routes := make(map[uint32]EngineRoute, len(routeList))
	for _, route := range routeList {
		routes[route.WGID] = route
	}
	return &routerTestFixture{
		domain: domain, router: router, controller: controller, backend: backend,
		bindings: bindings, routes: routes, engines: engines, stores: stores, clocks: clocks,
	}
}

func routerTestParts(
	t *testing.T,
	wgIDs []uint32,
	mutate func(uint32, *Options),
) (
	*RuntimeDomain,
	[]WGEngineBinding,
	[]EngineRoute,
	map[uint32]*Engine,
	map[uint32]*fakeSessionStore,
	map[uint32]*fakeClock,
) {
	t.Helper()
	domain, err := NewRuntimeDomain(1)
	if err != nil {
		t.Fatal(err)
	}
	bindings := make([]WGEngineBinding, 0, len(wgIDs))
	routes := make([]EngineRoute, 0, len(wgIDs))
	engines := make(map[uint32]*Engine, len(wgIDs))
	stores := make(map[uint32]*fakeSessionStore, len(wgIDs))
	clocks := make(map[uint32]*fakeClock, len(wgIDs))
	for index, wgID := range wgIDs {
		clock := &fakeClock{now: time.Unix(100, 0), monotonic: uint64(100 * time.Second)}
		store := newFakeSessionStore()
		options := runtimeDomainTestOptions(t)
		options.Now = clock.Now
		options.MonotonicClock = clock
		options.Store = store
		if mutate != nil {
			mutate(wgID, &options)
		}
		engine, err := domain.NewEngine(options)
		if err != nil {
			t.Fatalf("WGID %d Engine: %v", wgID, err)
		}
		clock.Add(options.SYNRateInterval * time.Duration(options.SYNBurst))
		bindings = append(bindings, WGEngineBinding{WGID: wgID, Engine: engine})
		routes = append(routes, EngineRoute{
			Generation: 1, UnderlayIndex: 2, LocalPort: uint16(31001 + index),
			WGID: wgID, FWMark: 0xa1230000 + wgID, Action: abi.ActionRewrite,
		})
		engines[wgID], stores[wgID], clocks[wgID] = engine, store, clock
	}
	return domain, bindings, routes, engines, stores, clocks
}

func routedFlow(route EngineRoute) abi.FakeTCPSessionKey {
	flow := testFlow(route.LocalPort)
	flow.Generation = route.Generation
	flow.UnderlayIndex = route.UnderlayIndex
	return flow
}

func routedNeedHandshakeSample(
	t testing.TB,
	identity RuntimeIdentity,
	flow abi.FakeTCPSessionKey,
	wgID uint32,
	mark uint32,
	captureSequence uint64,
) []byte {
	t.Helper()
	packet := testIPv4UDPPacket(t, flow, []byte{1, 2, 3, 4, 5})
	event := abi.FakeTCPEvent{
		Key: flow, TimestampNanos: captureSequence, PayloadLength: 5,
		FWMark: mark, WGID: wgID, PacketLength: uint16(len(packet)),
		Type: abi.FakeTCPEventNeedHandshake,
	}
	bindTestEvent(&event, identity, captureSequence)
	return testEventSample(event, packet, false)
}

func establishRoutedSession(
	t *testing.T,
	fixture *routerTestFixture,
	wgID uint32,
	captureSequence uint64,
) abi.FakeTCPSessionKey {
	t.Helper()
	route := fixture.routes[wgID]
	flow := routedFlow(route)
	if actions, err := fixture.controller.HandleSample(
		context.Background(),
		routedNeedHandshakeSample(t, fixture.domain.Identity(), flow, wgID, route.FWMark, captureSequence),
	); err != nil || len(actions) != 1 || actions[0].Kind != ActionSendControl {
		t.Fatalf("WGID %d initial actions=%#v err=%v", wgID, actions, err)
	}
	event := abi.FakeTCPEvent{
		Key: flow, Sequence: 9000, Acknowledgement: 1001, WGID: wgID,
		Type: abi.FakeTCPEventSYNACK, TCPFlags: FlagSYN | FlagACK,
	}
	bindTestEvent(&event, fixture.domain.Identity(), 0)
	if actions, err := fixture.controller.HandleSample(
		context.Background(), testEventSample(event, nil, false),
	); err != nil || len(actions) != 2 || actions[0].Kind != ActionSendControl ||
		actions[1].Kind != ActionReleasePending || actions[1].WGID != wgID {
		t.Fatalf("WGID %d completion actions=%#v err=%v", wgID, actions, err)
	}
	return flow
}

func TestEngineRouterKeepsEqualAndDifferentPoliciesIndependent(t *testing.T) {
	t.Run("equal policies", func(t *testing.T) {
		fixture := newRouterTestFixture(t, []uint32{7, 9}, nil)
		if len(fixture.router.engines) != 2 || fixture.engines[7] == fixture.engines[9] {
			t.Fatal("equal per-WG policies were merged into one Engine")
		}
	})

	t.Run("different policies", func(t *testing.T) {
		fixture := newRouterTestFixture(t, []uint32{7, 9}, func(wgID uint32, options *Options) {
			if wgID == 9 {
				options.HandshakeRetries++
				options.MaxPendingBytes++
			}
		})
		if fixture.engines[7].opts.HandshakeRetries == fixture.engines[9].opts.HandshakeRetries ||
			fixture.engines[7].opts.MaxPendingBytes == fixture.engines[9].opts.MaxPendingBytes {
			t.Fatal("different per-WG policies were not retained")
		}
	})
}

func TestEngineRouterRejectsAmbiguousConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*RuntimeDomain, *[]WGEngineBinding, *[]EngineRoute)
		want   error
	}{
		{
			name: "equal duplicate route",
			mutate: func(_ *RuntimeDomain, _ *[]WGEngineBinding, routes *[]EngineRoute) {
				*routes = append(*routes, (*routes)[0])
			},
			want: ErrEngineRouteConflict,
		},
		{
			name: "same Engine for two WGIDs",
			mutate: func(_ *RuntimeDomain, bindings *[]WGEngineBinding, _ *[]EngineRoute) {
				(*bindings)[1].Engine = (*bindings)[0].Engine
			},
			want: ErrEngineRouteConflict,
		},
		{
			name: "duplicate WG binding",
			mutate: func(_ *RuntimeDomain, bindings *[]WGEngineBinding, _ *[]EngineRoute) {
				(*bindings)[1].WGID = (*bindings)[0].WGID
			},
			want: ErrEngineRouteConflict,
		},
		{
			name: "unknown WG route",
			mutate: func(_ *RuntimeDomain, _ *[]WGEngineBinding, routes *[]EngineRoute) {
				(*routes)[0].WGID = 99
			},
			want: ErrEngineRouteInvalid,
		},
		{
			name: "non-rewrite action",
			mutate: func(_ *RuntimeDomain, _ *[]WGEngineBinding, routes *[]EngineRoute) {
				(*routes)[0].Action = abi.ActionPass
			},
			want: ErrEngineRouteInvalid,
		},
		{
			name: "different marks for one WG",
			mutate: func(_ *RuntimeDomain, _ *[]WGEngineBinding, routes *[]EngineRoute) {
				extra := (*routes)[0]
				extra.LocalPort = 32001
				extra.FWMark++
				*routes = append(*routes, extra)
			},
			want: ErrEngineRouteConflict,
		},
		{
			name: "unreferenced Engine",
			mutate: func(_ *RuntimeDomain, _ *[]WGEngineBinding, routes *[]EngineRoute) {
				*routes = (*routes)[:1]
			},
			want: ErrEngineRouteInvalid,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			domain, bindings, routes, _, _, _ := routerTestParts(t, []uint32{7, 9}, nil)
			test.mutate(domain, &bindings, &routes)
			if router, err := NewEngineRouter(domain, bindings, routes); router != nil || !errors.Is(err, test.want) {
				t.Fatalf("router=%#v err=%v", router, err)
			}
		})
	}

	t.Run("foreign RuntimeDomain", func(t *testing.T) {
		domain, bindings, routes, _, _, _ := routerTestParts(t, []uint32{7, 9}, nil)
		foreign, foreignBindings, _, _, _, _ := routerTestParts(t, []uint32{11}, nil)
		if foreign == domain {
			t.Fatal("test RuntimeDomains unexpectedly alias")
		}
		bindings[0].Engine = foreignBindings[0].Engine
		if router, err := NewEngineRouter(domain, bindings, routes); router != nil ||
			!errors.Is(err, ErrEngineRouteInvalid) {
			t.Fatalf("router=%#v err=%v", router, err)
		}
	})
}

func TestEngineRouterFreezesCallerTables(t *testing.T) {
	domain, bindings, routes, engines, _, _ := routerTestParts(t, []uint32{7, 9}, nil)
	router, err := NewEngineRouter(domain, bindings, routes)
	if err != nil {
		t.Fatal(err)
	}
	original := routes[0]
	bindings[0].Engine = engines[9]
	routes[0].WGID = 9
	routes[0].FWMark++
	selection, err := router.selectEngine(abi.FakeTCPEvent{
		Key: routedFlow(original), WGID: original.WGID, FWMark: original.FWMark,
		Type: abi.FakeTCPEventNeedHandshake,
	})
	if err != nil || selection.engine != engines[7] || selection.wgID != 7 {
		t.Fatalf("selection=%#v err=%v", selection, err)
	}
}

func TestRoutedControllerRejectsBeforeEngineStoreOrBackend(t *testing.T) {
	fixture := newRouterTestFixture(t, []uint32{7, 9}, nil)
	route := fixture.routes[7]
	baseFlow := routedFlow(route)
	tests := []struct {
		name string
		flow abi.FakeTCPSessionKey
		wgID uint32
		mark uint32
	}{
		{name: "unknown route", flow: func() abi.FakeTCPSessionKey {
			flow := baseFlow
			flow.LocalPort = 39999
			return flow
		}(), wgID: 7, mark: route.FWMark},
		{name: "wrong WGID", flow: baseFlow, wgID: 9, mark: route.FWMark},
		{name: "wrong mark", flow: baseFlow, wgID: 7, mark: route.FWMark + 1},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if actions, err := fixture.controller.HandleSample(
				context.Background(),
				routedNeedHandshakeSample(
					t, fixture.domain.Identity(), test.flow, test.wgID, test.mark, uint64(index+1),
				),
			); len(actions) != 0 || !errors.Is(err, ErrEngineRouteRejected) {
				t.Fatalf("actions=%#v err=%v", actions, err)
			}
		})
	}
	for wgID, engine := range fixture.engines {
		store := fixture.stores[wgID]
		if len(engine.sessions) != 0 || store.inserts != 0 || store.lookups != 0 || store.deleteAttempts != 0 {
			t.Fatalf("WGID %d touched engine/store: sessions=%d store=%#v", wgID, len(engine.sessions), store)
		}
	}
	if len(fixture.backend.operations) != 0 {
		t.Fatalf("rejected routes reached backend: %v", fixture.backend.operations)
	}
}

func TestRoutedControllerKeepsPerWGQuotaAndPendingStateIndependent(t *testing.T) {
	fixture := newRouterTestFixture(t, []uint32{7, 9}, func(_ uint32, options *Options) {
		options.MaxPendingFlows = 1
	})
	for index, wgID := range []uint32{7, 9} {
		route := fixture.routes[wgID]
		flow := routedFlow(route)
		actions, err := fixture.controller.HandleSample(
			context.Background(),
			routedNeedHandshakeSample(t, fixture.domain.Identity(), flow, wgID, route.FWMark, uint64(index+1)),
		)
		if err != nil || len(actions) != 1 || actions[0].Kind != ActionSendControl {
			t.Fatalf("WGID %d actions=%#v err=%v", wgID, actions, err)
		}
	}
	secondFlow := routedFlow(fixture.routes[7])
	secondFlow.RemotePort++
	actions, err := fixture.controller.HandleSample(
		context.Background(),
		routedNeedHandshakeSample(
			t, fixture.domain.Identity(), secondFlow, 7, fixture.routes[7].FWMark, 3,
		),
	)
	if err != nil || len(actions) != 2 || actions[1].Reason != "pending-capacity" {
		t.Fatalf("second WGID 7 flow actions=%#v err=%v", actions, err)
	}
	if fixture.engines[7].pendingFlows != 1 || fixture.engines[9].pendingFlows != 1 {
		t.Fatalf(
			"pending flows WG7=%d WG9=%d want independent 1/1",
			fixture.engines[7].pendingFlows,
			fixture.engines[9].pendingFlows,
		)
	}
}

func TestRuntimeDomainAllocatesSessionIDsGloballyAcrossRoutedEngines(t *testing.T) {
	fixture := newRouterTestFixture(t, []uint32{7, 9}, nil)
	flow9 := establishRoutedSession(t, fixture, 9, 1)
	flow7 := establishRoutedSession(t, fixture, 7, 2)
	value9, found9 := fixture.stores[9].values[flow9]
	value7, found7 := fixture.stores[7].values[flow7]
	if !found9 || !found7 || value9.SessionID != 1 || value7.SessionID != 2 ||
		value9.SessionID == value7.SessionID {
		t.Fatalf("WG9=%#v found=%t WG7=%#v found=%t", value9, found9, value7, found7)
	}
	if value9.RuntimeIncarnation != [16]byte(fixture.domain.Identity().Incarnation) ||
		value7.RuntimeIncarnation != [16]byte(fixture.domain.Identity().Incarnation) {
		t.Fatal("routed sessions did not retain the shared RuntimeDomain identity")
	}
}

func TestRoutedWrongWGCloseAndPendingDoNotLookup(t *testing.T) {
	fixture := newRouterTestFixture(t, []uint32{7, 9}, nil)
	flow := establishRoutedSession(t, fixture, 7, 1)
	store := fixture.stores[7]
	state := store.values[flow]
	lookups, deletes, operations := store.lookups, store.deleteAttempts, len(fixture.backend.operations)

	if actions, err := fixture.controller.HandleSample(
		context.Background(),
		routedNeedHandshakeSample(
			t, fixture.domain.Identity(), flow, 9, fixture.routes[7].FWMark, 2,
		),
	); len(actions) != 0 || !errors.Is(err, ErrEngineRouteRejected) {
		t.Fatalf("wrong-WG pending actions=%#v err=%v", actions, err)
	}
	closeEvent := closeValidationEvent(flow, state, FlagRST|FlagACK, 9, fixture.domain.Identity())
	closePacket := buildIPv4TCPControl(flow, state, FlagRST|FlagACK)
	if actions, err := fixture.controller.HandleSample(
		context.Background(), testEventSample(closeEvent, closePacket, false),
	); len(actions) != 0 || !errors.Is(err, ErrEngineRouteRejected) {
		t.Fatalf("wrong-WG close actions=%#v err=%v", actions, err)
	}
	if store.lookups != lookups || store.deleteAttempts != deletes ||
		len(fixture.backend.operations) != operations || fixture.engines[7].sessions[flow] == nil {
		t.Fatalf(
			"wrong-WG event touched state: lookups=%d/%d deletes=%d/%d operations=%d/%d",
			store.lookups, lookups, store.deleteAttempts, deletes,
			len(fixture.backend.operations), operations,
		)
	}
}

func TestEngineRouterTicksInSortedWGIDOrder(t *testing.T) {
	fixture := newRouterTestFixture(t, []uint32{22, 7}, nil)
	for index, wgID := range []uint32{22, 7} {
		route := fixture.routes[wgID]
		flow := routedFlow(route)
		if _, err := fixture.controller.HandleSample(
			context.Background(),
			routedNeedHandshakeSample(t, fixture.domain.Identity(), flow, wgID, route.FWMark, uint64(index+1)),
		); err != nil {
			t.Fatal(err)
		}
	}
	fixture.backend.sent = nil
	fixture.backend.operations = nil
	fixture.clocks[22].Add(time.Second)
	fixture.clocks[7].Add(time.Second)
	actions, err := fixture.controller.Tick(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	gotActions := make([]uint32, 0, len(actions))
	for _, action := range actions {
		gotActions = append(gotActions, action.WGID)
	}
	gotBackend := make([]uint32, 0, len(fixture.backend.sent))
	for _, sent := range fixture.backend.sent {
		gotBackend = append(gotBackend, sent.wgID)
	}
	if !slices.Equal(gotActions, []uint32{7, 22}) || !slices.Equal(gotBackend, []uint32{7, 22}) {
		t.Fatalf("actions=%v backend=%v", gotActions, gotBackend)
	}
}

func TestEngineRouterRejectsWrongActionProvenanceBeforeBackend(t *testing.T) {
	fixture := newRouterTestFixture(t, []uint32{7, 9}, nil)
	wrongFlow := routedFlow(fixture.routes[7])
	if _, err := fixture.engines[7].outbound(
		wrongFlow,
		PendingPacket{Data: []byte{1}, WGID: 7, FWMark: fixture.routes[7].FWMark},
		false,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.engines[9].outbound(
		wrongFlow,
		PendingPacket{Data: []byte{1}, WGID: 9, FWMark: fixture.routes[9].FWMark},
		false,
	); err != nil {
		t.Fatal(err)
	}
	fixture.clocks[7].Add(time.Second)
	fixture.clocks[9].Add(time.Second)
	fixture.backend.operations = nil
	actions, err := fixture.controller.Tick(context.Background())
	if len(actions) != 0 || !errors.Is(err, ErrEngineRouteRejected) {
		t.Fatalf("actions=%#v err=%v", actions, err)
	}
	if len(fixture.backend.operations) != 0 {
		t.Fatalf("wrong-owner Tick reached backend: %v", fixture.backend.operations)
	}
	if _, retryErr := fixture.controller.Tick(context.Background()); !errors.Is(retryErr, ErrControllerFailed) || len(fixture.backend.operations) != 0 {
		t.Fatalf("route fault was not terminal: err=%v backend=%v", retryErr, fixture.backend.operations)
	}
	for _, kind := range []ActionKind{ActionDrop, ActionForward, ActionClose} {
		if err := fixture.router.validateActions(9, []Action{{Kind: kind, Flow: wrongFlow}}); !errors.Is(err, ErrEngineRouteRejected) {
			t.Fatalf("kind=%d error=%v", kind, err)
		}
	}
}
