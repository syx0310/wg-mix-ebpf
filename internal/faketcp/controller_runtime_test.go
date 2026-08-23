package faketcp

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

func testControllerRuntimeFactory(
	t *testing.T,
	generation uint64,
	marks map[uint32]uint32,
) ControllerRuntimeFactory {
	t.Helper()
	factory, err := NewControllerRuntimeFactory(ControllerRuntimeFactoryOptions{
		Scope: ControllerRuntimeScope{
			Generation: generation,
			PinPath:    "/run/wg-mix-ebpf/controller-runtime-test",
		},
		ControlMarks:   marks,
		PollInterval:   time.Millisecond,
		TickInterval:   time.Second,
		RawSendTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return factory
}

func TestControllerRuntimeFactoryFreezesMarksAndCopiesShareOneClaim(t *testing.T) {
	marks := map[uint32]uint32{77: 0xa1230007}
	factory := testControllerRuntimeFactory(t, 1, marks)
	copyFactory := factory
	marks[77] = 0xffffffff
	marks[88] = 9
	identity := testRuntimeIdentity(1)
	claim, err := factory.claim(identity, 101, 102, 8)
	if err != nil {
		t.Fatal(err)
	}
	if claim.binding != (ControllerRuntimeBinding{
		Scope: ControllerRuntimeScope{
			Generation: 1,
			PinPath:    "/run/wg-mix-ebpf/controller-runtime-test",
		},
		RuntimeIdentity: identity,
		EventMapID:      101,
		StatsMapID:      102,
	}) {
		t.Fatalf("binding=%#v", claim.binding)
	}
	mark, err := claim.controlMarks.ControlMark(context.Background(), testFlowWithWGID(31001, 77), 77)
	if err != nil || mark != 0xa1230007 {
		t.Fatalf("frozen mark=%#x err=%v", mark, err)
	}
	if _, err := claim.controlMarks.ControlMark(context.Background(), testFlowWithWGID(31001, 88), 88); err == nil {
		t.Fatal("post-construction mark mutation became visible")
	}
	if _, err := copyFactory.claim(identity, 103, 104, 8); !errors.Is(err, ErrControllerRuntimeFactoryConsumed) {
		t.Fatalf("copied factory claim error=%v", err)
	}
}

func TestControllerRuntimeFactoryRejectsScopeIdentityAndMarkAmbiguity(t *testing.T) {
	valid := ControllerRuntimeFactoryOptions{
		Scope: ControllerRuntimeScope{
			Generation: 1,
			PinPath:    "/run/wg-mix-ebpf/controller-runtime-test",
		},
		ControlMarks:   map[uint32]uint32{77: 9},
		PollInterval:   time.Millisecond,
		TickInterval:   time.Second,
		RawSendTimeout: time.Second,
	}
	for _, test := range []struct {
		name   string
		mutate func(*ControllerRuntimeFactoryOptions)
	}{
		{name: "generation", mutate: func(options *ControllerRuntimeFactoryOptions) { options.Scope.Generation = 0 }},
		{name: "relative pin", mutate: func(options *ControllerRuntimeFactoryOptions) { options.Scope.PinPath = "pins" }},
		{name: "unclean pin", mutate: func(options *ControllerRuntimeFactoryOptions) { options.Scope.PinPath += "/../test" }},
		{name: "root pin", mutate: func(options *ControllerRuntimeFactoryOptions) { options.Scope.PinPath = "/" }},
		{name: "empty marks", mutate: func(options *ControllerRuntimeFactoryOptions) { options.ControlMarks = nil }},
		{name: "zero WG ID", mutate: func(options *ControllerRuntimeFactoryOptions) { options.ControlMarks = map[uint32]uint32{0: 9} }},
		{name: "zero mark", mutate: func(options *ControllerRuntimeFactoryOptions) { options.ControlMarks = map[uint32]uint32{77: 0} }},
		{name: "interval", mutate: func(options *ControllerRuntimeFactoryOptions) { options.PollInterval = 0 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := valid
			test.mutate(&options)
			if _, err := NewControllerRuntimeFactory(options); err == nil {
				t.Fatal("invalid factory options were accepted")
			}
		})
	}
	factory := testControllerRuntimeFactory(t, 1, map[uint32]uint32{77: 9})
	if _, err := factory.claim(testRuntimeIdentity(2), 1, 2, 4); err == nil {
		t.Fatal("wrong generation identity was accepted")
	}
	if _, err := factory.claim(testRuntimeIdentity(1), 1, 1, 4); err == nil {
		t.Fatal("aliased map identities were accepted")
	}
	if _, err := factory.claim(testRuntimeIdentity(1), 1, 2, 0); err == nil {
		t.Fatal("zero possible CPUs were accepted")
	}
	if _, err := factory.claim(testRuntimeIdentity(1), 1, 2, 4); err != nil {
		t.Fatalf("pre-claim validation consumed factory: %v", err)
	}
}

func TestFixedControlMarksFailClosedOutsideFrozenGeneration(t *testing.T) {
	marks, err := newFixedControlMarks(1, map[uint32]uint32{77: 9})
	if err != nil {
		t.Fatal(err)
	}
	wrongGeneration := testFlow(31001)
	wrongGeneration.Generation++
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, test := range []struct {
		name string
		ctx  context.Context
		flow abi.FakeTCPSessionKey
		wgID uint32
	}{
		{name: "nil context", flow: testFlowWithWGID(31001, 77), wgID: 77},
		{name: "cancelled", ctx: cancelled, flow: testFlowWithWGID(31001, 77), wgID: 77},
		{name: "generation", ctx: context.Background(), flow: wrongGeneration, wgID: wrongGeneration.WGID},
		{name: "unknown WG", ctx: context.Background(), flow: testFlow(31001), wgID: 88},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := marks.ControlMark(test.ctx, test.flow, test.wgID); err == nil {
				t.Fatal("ambiguous control mark lookup was accepted")
			}
		})
	}
}

func TestControllerRuntimeModelCombinesV3CloseOrderingAndOnceOnlyReinjection(t *testing.T) {
	store := newFakeSessionStore()
	engine, _ := testEngine(t, func(options *Options) { options.Store = store })
	identity := engine.Identity()
	closeFlow := testFlowWithWGID(31002, 77)
	if _, err := engine.outbound(
		closeFlow,
		PendingPacket{Data: []byte{9}, WGID: 77},
		false,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.InboundWithWGID(
		closeFlow,
		Segment{Flags: FlagSYN | FlagACK, Sequence: 9000, Acknowledgement: 1001},
		77,
	); err != nil {
		t.Fatal(err)
	}
	closeState, found := store.values[closeFlow]
	if !found {
		t.Fatal("close integration fixture did not establish a session")
	}
	closeEvent, closePacket := capturedCloseEvent(
		engine,
		closeFlow,
		closeState,
		FlagRST|FlagACK,
		77,
	)
	closeSample := testBoundEventSample(closeEvent, closePacket, false)
	decodedClose, err := DecodeEventSample(closeSample)
	if err != nil {
		t.Fatal(err)
	}
	if len(closeSample) != abi.FakeTCPEventSize+len(closePacket) ||
		decodedClose.Event.EventABIVersion != abi.FakeTCPEventABIVersion ||
		decodedClose.Event.SessionID != closeState.SessionID ||
		decodedClose.Event.SessionRevision != closeState.Revision {
		t.Fatalf("v3 close decode=%#v sample-size=%d", decodedClose.Event, len(closeSample))
	}

	flow := testFlowWithWGID(31001, 77)
	packet := testIPv4UDPPacket(t, flow, []byte{1, 2, 3})
	packetEvent := abi.FakeTCPEvent{
		Key: flow, PayloadLength: 3, FWMark: 0xa1230007, WGID: 77,
		PacketLength: uint16(len(packet)), Type: abi.FakeTCPEventNeedHandshake,
	}
	bindTestEvent(&packetEvent, identity, 1)
	packetEvent.CaptureCPU = 1
	packetSample := testBoundEventSample(packetEvent, packet, false)
	outOfOrderACK := abi.FakeTCPEvent{
		Key: flow, WGID: 77, Type: abi.FakeTCPEventACK, TCPFlags: FlagACK,
		Acknowledgement: 999,
	}
	bindTestEvent(&outOfOrderACK, identity, 0)
	synACK := abi.FakeTCPEvent{
		Key: flow, WGID: 77, Type: abi.FakeTCPEventSYNACK,
		TCPFlags: FlagSYN | FlagACK, Sequence: 10000, Acknowledgement: 2001,
	}
	bindTestEvent(&synACK, identity, 0)
	source := &fakeEventReader{records: []EventRecord{
		{RawSample: packetSample},
		{RawSample: testBoundEventSample(outOfOrderACK, nil, false)},
		{RawSample: packetSample},
		{RawSample: testBoundEventSample(synACK, nil, false)},
		{RawSample: closeSample},
		{LostSamples: 1},
	}}
	ordered, err := newProductionEventReader(
		source,
		identity,
		4,
		&memoryEventLossCounter{},
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	factory := testControllerRuntimeFactory(t, flow.Generation, map[uint32]uint32{77: 9})
	claim, err := factory.claim(identity, 101, 102, 4)
	if err != nil {
		t.Fatal(err)
	}
	writer := &memoryRawIPv4Writer{}
	runtime, err := newOwnedControllerRuntime(engine, ordered, writer, claim)
	if err != nil {
		t.Fatal(err)
	}
	if got := runtime.Binding(); got != claim.binding {
		t.Fatalf("runtime binding=%#v want=%#v", got, claim.binding)
	}
	if err := runtime.Run(context.Background()); !errors.Is(err, ErrEventSamplesLost) {
		t.Fatalf("model Run error=%v", err)
	}
	writes, closes := writer.snapshot()
	if closes != 0 {
		t.Fatalf("writer closed during Run %d times", closes)
	}
	var tcpWrites, udpWrites int
	for _, write := range writes {
		switch write.Data[9] {
		case 6:
			tcpWrites++
			if write.FWMark != 9 {
				t.Fatalf("control write mark=%#x", write.FWMark)
			}
		case 17:
			udpWrites++
			if write.FWMark != packetEvent.FWMark {
				t.Fatalf("reinject write mark=%#x", write.FWMark)
			}
		default:
			t.Fatalf("unexpected raw protocol %d", write.Data[9])
		}
	}
	if tcpWrites != 2 || udpWrites != 1 {
		t.Fatalf("raw writes TCP=%d UDP=%d total=%d", tcpWrites, udpWrites, len(writes))
	}
	if _, found := store.values[closeFlow]; found || store.deleteAttempts != 1 {
		t.Fatalf(
			"v3 close retained session=%t compare-delete attempts=%d",
			found,
			store.deleteAttempts,
		)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	_, closes = writer.snapshot()
	if closes != 1 {
		t.Fatalf("writer Close calls=%d", closes)
	}
	if err := runtime.Run(context.Background()); !errors.Is(err, ErrEventRuntimeClosed) {
		t.Fatalf("post-close Run error=%v", err)
	}
}

func TestControllerRuntimeConstructionFailureClosesExactOwnedResources(t *testing.T) {
	engine, _ := testEngine(t, nil)
	factory := testControllerRuntimeFactory(t, 1, map[uint32]uint32{77: 9})
	wrongIdentity := testRuntimeIdentity(1)
	wrongIdentity.Incarnation[0]++
	claim, err := factory.claim(wrongIdentity, 101, 102, 4)
	if err != nil {
		t.Fatal(err)
	}
	reader := &fakeEventReader{}
	writer := &memoryRawIPv4Writer{}
	if runtime, err := newOwnedControllerRuntime(engine, reader, writer, claim); err == nil || runtime != nil {
		t.Fatalf("mismatched Engine identity accepted: runtime=%#v err=%v", runtime, err)
	}
	reader.mu.Lock()
	readerCloses := reader.closeCalls
	reader.mu.Unlock()
	_, writerCloses := writer.snapshot()
	if readerCloses != 1 || writerCloses != 1 {
		t.Fatalf("construction cleanup reader=%d writer=%d", readerCloses, writerCloses)
	}
}

func TestRoutedControllerRuntimeDispatchesSameTupleByWGIDWithOneBackend(t *testing.T) {
	domain, err := NewRuntimeDomain(1)
	if err != nil {
		t.Fatal(err)
	}
	const (
		firstWGID  = uint32(77)
		secondWGID = uint32(88)
		firstMark  = uint32(0xa123004d)
		secondMark = uint32(0xa1230058)
	)
	stores := map[uint32]*fakeSessionStore{}
	plans := make([]WGEnginePlan, 0, 2)
	for _, binding := range []struct {
		wgID uint32
		mark uint32
	}{
		{wgID: firstWGID, mark: firstMark},
		{wgID: secondWGID, mark: secondMark},
	} {
		options := runtimeDomainTestOptions(t)
		store := newFakeSessionStore()
		options.Store = store
		stores[binding.wgID] = store
		plans = append(plans, WGEnginePlan{
			WGID: binding.wgID, Options: options,
			Routes: []EngineRoute{{
				Generation: 1, UnderlayIndex: 2, LocalPort: 31001,
				WGID: binding.wgID, FWMark: binding.mark, Action: abi.ActionRewrite,
			}},
		})
	}
	router, err := NewEngineRouterFromPlans(domain, plans)
	if err != nil {
		t.Fatal(err)
	}

	records := make([]EventRecord, 0, 5)
	for index, binding := range []struct {
		wgID uint32
		mark uint32
	}{
		{wgID: firstWGID, mark: firstMark},
		{wgID: secondWGID, mark: secondMark},
	} {
		flow := testFlowWithWGID(31001, binding.wgID)
		packet := testIPv4UDPPacket(t, flow, []byte{byte(binding.wgID)})
		event := abi.FakeTCPEvent{
			Key: flow, PayloadLength: 1, FWMark: binding.mark, WGID: binding.wgID,
			PacketLength: uint16(len(packet)), Type: abi.FakeTCPEventNeedHandshake,
		}
		bindTestEvent(&event, router.Identity(), uint64(index+1))
		records = append(records, EventRecord{RawSample: testBoundEventSample(event, packet, false)})
	}
	for _, wgID := range []uint32{firstWGID, secondWGID} {
		flow := testFlowWithWGID(31001, wgID)
		event := abi.FakeTCPEvent{
			Key: flow, WGID: wgID, Type: abi.FakeTCPEventSYNACK,
			TCPFlags: FlagSYN | FlagACK, Sequence: 9000 + wgID, Acknowledgement: 1001,
		}
		bindTestEvent(&event, router.Identity(), 0)
		records = append(records, EventRecord{RawSample: testBoundEventSample(event, nil, false)})
	}
	records = append(records, EventRecord{LostSamples: 1})
	source := &fakeEventReader{records: records}
	ordered, err := newProductionEventReader(
		source,
		router.Identity(),
		4,
		&memoryEventLossCounter{},
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	factory := testControllerRuntimeFactory(t, 1, map[uint32]uint32{
		firstWGID: firstMark, secondWGID: secondMark,
	})
	claim, err := factory.claim(router.Identity(), 101, 102, 4)
	if err != nil {
		t.Fatal(err)
	}
	writer := &memoryRawIPv4Writer{}
	runtime, err := newOwnedRoutedControllerRuntime(router, ordered, writer, claim)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Run(context.Background()); !errors.Is(err, ErrEventSamplesLost) {
		t.Fatalf("routed runtime Run error=%v", err)
	}
	for _, wgID := range []uint32{firstWGID, secondWGID} {
		flow := testFlowWithWGID(31001, wgID)
		if _, exists := stores[wgID].values[flow]; !exists {
			t.Fatalf("WGID %d same-tuple event reached the wrong Engine", wgID)
		}
	}
	if writes, closes := writer.snapshot(); len(writes) != 6 || closes != 0 {
		t.Fatalf("shared raw backend writes=%d closes=%d", len(writes), closes)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	source.mu.Lock()
	readerCloses := source.closeCalls
	source.mu.Unlock()
	_, writerCloses := writer.snapshot()
	if readerCloses != 1 || writerCloses != 1 {
		t.Fatalf("shared routed resources reader closes=%d writer closes=%d", readerCloses, writerCloses)
	}
}

func TestRoutedControllerRuntimeConstructionFailureClosesOneWriter(t *testing.T) {
	domain, err := NewRuntimeDomain(1)
	if err != nil {
		t.Fatal(err)
	}
	options := runtimeDomainTestOptions(t)
	router, err := NewEngineRouterFromPlans(domain, []WGEnginePlan{{
		WGID: 77, Options: options,
		Routes: []EngineRoute{{
			Generation: 1, UnderlayIndex: 2, LocalPort: 31001,
			WGID: 77, FWMark: 9, Action: abi.ActionRewrite,
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	factory := testControllerRuntimeFactory(t, 1, map[uint32]uint32{77: 9})
	claim, err := factory.claim(router.Identity(), 101, 102, 1)
	if err != nil {
		t.Fatal(err)
	}
	writer := &memoryRawIPv4Writer{}
	if runtime, err := newOwnedRoutedControllerRuntime(router, nil, writer, claim); err == nil || runtime != nil {
		t.Fatalf("nil routed event reader accepted: runtime=%#v err=%v", runtime, err)
	}
	if _, writerCloses := writer.snapshot(); writerCloses != 1 {
		t.Fatalf("routed construction failure writer closes=%d", writerCloses)
	}
}

func TestControllerRuntimeRequestStopInterruptsReaderBeforeClose(t *testing.T) {
	engine, _ := testEngine(t, nil)
	factory := testControllerRuntimeFactory(t, 1, map[uint32]uint32{77: 9})
	claim, err := factory.claim(engine.Identity(), 101, 102, 4)
	if err != nil {
		t.Fatal(err)
	}
	reader := newBlockingEventReader()
	writer := &memoryRawIPv4Writer{}
	runtime, err := newOwnedControllerRuntime(engine, reader, writer, claim)
	if err != nil {
		t.Fatal(err)
	}
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(context.Background()) }()
	select {
	case <-reader.started:
	case <-time.After(time.Second):
		t.Fatal("runtime did not enter reader")
	}
	if err := runtime.RequestStop(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("stopped Run error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("RequestStop did not interrupt reader")
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if _, writerCloses := writer.snapshot(); writerCloses != 1 {
		t.Fatalf("writer Close calls=%d", writerCloses)
	}
}

func TestControllerRuntimeCancellationDoesNotTouchReaderOrWriter(t *testing.T) {
	engine, _ := testEngine(t, nil)
	factory := testControllerRuntimeFactory(t, 1, map[uint32]uint32{77: 9})
	claim, err := factory.claim(engine.Identity(), 101, 102, 4)
	if err != nil {
		t.Fatal(err)
	}
	reader := &fakeEventReader{}
	writer := &memoryRawIPv4Writer{}
	runtime, err := newOwnedControllerRuntime(engine, reader, writer, claim)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runtime.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Run error=%v", err)
	}
	reader.mu.Lock()
	readCalls := reader.readCalls
	reader.mu.Unlock()
	writes, _ := writer.snapshot()
	if readCalls != 0 || len(writes) != 0 {
		t.Fatalf("cancelled Run touched reader=%d writer=%d", readCalls, len(writes))
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestProductionModelSamplesRemainCompleteIPv4(t *testing.T) {
	// Guard the model fixture itself: the backend tests above distinguish
	// control and reinjection by this materialized IPv4 protocol byte.
	sample := testProductionPacketSample(t, 1, 1)
	decoded, err := DecodeEventSample(sample)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.Packet) < 28 || binary.BigEndian.Uint16(decoded.Packet[2:4]) != uint16(len(decoded.Packet)) {
		t.Fatal("production model packet is not a complete IPv4 datagram")
	}
}
