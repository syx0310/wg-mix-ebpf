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
	mark, err := claim.controlMarks.ControlMark(context.Background(), testFlow(31001), 77)
	if err != nil || mark != 0xa1230007 {
		t.Fatalf("frozen mark=%#x err=%v", mark, err)
	}
	if _, err := claim.controlMarks.ControlMark(context.Background(), testFlow(31001), 88); err == nil {
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
		{name: "nil context", flow: testFlow(31001), wgID: 77},
		{name: "cancelled", ctx: cancelled, flow: testFlow(31001), wgID: 77},
		{name: "generation", ctx: context.Background(), flow: wrongGeneration, wgID: 77},
		{name: "unknown WG", ctx: context.Background(), flow: testFlow(31001), wgID: 88},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := marks.ControlMark(test.ctx, test.flow, test.wgID); err == nil {
				t.Fatal("ambiguous control mark lookup was accepted")
			}
		})
	}
}

func TestControllerRuntimeModelDropsProtocolReorderingAndReinjectsDuplicateCaptureOnce(t *testing.T) {
	engine, _ := testEngine(t, nil)
	identity := engine.Identity()
	flow := testFlow(31001)
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
		TCPFlags: FlagSYN | FlagACK, Sequence: 9000, Acknowledgement: 1001,
	}
	bindTestEvent(&synACK, identity, 0)
	source := &fakeEventReader{records: []EventRecord{
		{RawSample: packetSample},
		{RawSample: testBoundEventSample(outOfOrderACK, nil, false)},
		{RawSample: packetSample},
		{RawSample: testBoundEventSample(synACK, nil, false)},
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
