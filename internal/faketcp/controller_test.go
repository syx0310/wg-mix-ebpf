package faketcp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

type sentControl struct {
	flow    abi.FakeTCPSessionKey
	wgID    uint32
	control ControlPacket
}

type reinjectedPacket struct {
	flow   abi.FakeTCPSessionKey
	packet PendingPacket
}

type fakeControllerBackend struct {
	sent        []sentControl
	packets     []reinjectedPacket
	operations  []string
	sendErr     error
	reinjectErr error
	closeErr    error
	closeCalls  int
}

func (b *fakeControllerBackend) SendControl(_ context.Context, flow abi.FakeTCPSessionKey, wgID uint32, control ControlPacket) error {
	b.sent = append(b.sent, sentControl{flow: flow, wgID: wgID, control: control})
	b.operations = append(b.operations, fmt.Sprintf("send:%#x", control.Flags))
	return b.sendErr
}

func (b *fakeControllerBackend) Reinject(_ context.Context, flow abi.FakeTCPSessionKey, packet PendingPacket) error {
	copyPacket := packet
	copyPacket.Data = append([]byte(nil), packet.Data...)
	b.packets = append(b.packets, reinjectedPacket{flow: flow, packet: copyPacket})
	b.operations = append(b.operations, "reinject")
	return b.reinjectErr
}

func (b *fakeControllerBackend) Close() error {
	b.closeCalls++
	b.operations = append(b.operations, "close")
	return b.closeErr
}

func TestControllerHandshakeSendsControlAndReinjectsFirstPacketOnce(t *testing.T) {
	engine, _ := testEngine(t, nil)
	backend := &fakeControllerBackend{}
	controller, err := NewController(engine, backend)
	if err != nil {
		t.Fatal(err)
	}
	flow := testFlow(31001)
	packet := testIPv4UDPPacket(t, flow, []byte{1, 2, 3, 4, 5})
	binary.BigEndian.PutUint16(packet[10:12], 0x1234)
	binary.BigEndian.PutUint16(packet[26:28], 0x5678)
	wantPacket := append([]byte(nil), packet...)
	if err := MaterializeIPv4UDPChecksums(wantPacket); err != nil {
		t.Fatal(err)
	}
	packetEvent := testEventSample(abi.FakeTCPEvent{
		Key: flow, PayloadLength: 5, FWMark: 0x1234, WGID: 77,
		PacketLength: uint16(len(packet)), Type: abi.FakeTCPEventNeedHandshake,
	}, packet, false)

	actions, err := controller.HandleSample(context.Background(), packetEvent)
	if err != nil || len(actions) != 1 || actions[0].Kind != ActionSendControl {
		t.Fatalf("first packet actions=%#v err=%v", actions, err)
	}
	if len(backend.sent) != 1 || backend.sent[0].wgID != 77 || backend.sent[0].control.Flags != FlagSYN {
		t.Fatalf("sent control=%#v", backend.sent)
	}
	if len(backend.packets) != 0 {
		t.Fatal("packet was reinjected before the handshake completed")
	}

	synACK := testEventSample(abi.FakeTCPEvent{
		Key: flow, Sequence: 9000, Acknowledgement: 1001, WGID: 77,
		Type: abi.FakeTCPEventSYNACK, TCPFlags: FlagSYN | FlagACK,
	}, nil, false)
	actions, err = controller.HandleSample(context.Background(), synACK)
	if err != nil || len(actions) != 2 || actions[0].Kind != ActionSendControl || actions[1].Kind != ActionReleasePending {
		t.Fatalf("synack actions=%#v err=%v", actions, err)
	}
	if len(backend.sent) != 2 || backend.sent[1].wgID != 77 || backend.sent[1].control.Flags != FlagACK {
		t.Fatalf("sent control=%#v", backend.sent)
	}
	if len(backend.packets) != 1 {
		t.Fatalf("reinjected packets=%#v", backend.packets)
	}
	got := backend.packets[0]
	if got.flow != flow || got.packet.FWMark != 0x1234 || got.packet.WGID != 77 || !bytes.Equal(got.packet.Data, wantPacket) {
		t.Fatalf("reinjected packet=%#v", got)
	}

	// A duplicate completion cannot release the packet a second time.
	if _, err := controller.HandleSample(context.Background(), synACK); err != nil {
		t.Fatal(err)
	}
	if len(backend.packets) != 1 {
		t.Fatalf("first packet was reinjected %d times", len(backend.packets))
	}
	if got, want := backend.operations, []string{"send:0x2", "send:0x10", "reinject"}; !slices.Equal(got, want) {
		t.Fatalf("backend operation order=%v, want %v", got, want)
	}
}

func TestDecodeEventSampleAcceptsCompactAndFixedPacketRecords(t *testing.T) {
	flow := testFlow(31001)
	packet := testIPv4UDPPacket(t, flow, []byte{9, 8, 7})
	event := abi.FakeTCPEvent{
		Key: flow, PayloadLength: 3, FWMark: 9, WGID: 5,
		PacketLength: uint16(len(packet)), Type: abi.FakeTCPEventNeedHandshake,
	}
	for _, fixed := range []bool{false, true} {
		decoded, err := DecodeEventSample(testEventSample(event, packet, fixed))
		if err != nil {
			t.Fatalf("fixed=%t: %v", fixed, err)
		}
		if decoded.Event != event || !bytes.Equal(decoded.Packet, packet) {
			t.Fatalf("fixed=%t decoded=%#v", fixed, decoded)
		}
	}
}

func TestDecodeEventSampleRejectsMetadataOnlyAndMismatchedPackets(t *testing.T) {
	flow := testFlow(31001)
	packet := testIPv4UDPPacket(t, flow, []byte{1})
	base := abi.FakeTCPEvent{
		Key: flow, PayloadLength: 1, WGID: 1,
		PacketLength: uint16(len(packet)), Type: abi.FakeTCPEventNeedHandshake,
	}
	tests := []struct {
		name   string
		event  abi.FakeTCPEvent
		packet []byte
		fixed  bool
	}{
		{name: "metadata-only", event: abi.FakeTCPEvent{Key: flow, Type: abi.FakeTCPEventNeedHandshake}},
		{name: "wrong-size", event: base, packet: packet[:len(packet)-1]},
		{name: "wrong-address", event: func() abi.FakeTCPEvent { value := base; value.Key.LocalIPv4++; return value }(), packet: packet},
		{name: "wrong-flags", event: func() abi.FakeTCPEvent { value := base; value.TCPFlags = FlagACK; return value }(), packet: packet},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := DecodeEventSample(testEventSample(test.event, test.packet, test.fixed))
			if err == nil {
				t.Fatal("malformed event was accepted")
			}
		})
	}
}

func TestMaterializeIPv4UDPChecksumsReplacesOffloadSeeds(t *testing.T) {
	flow := testFlow(31001)
	packet := testIPv4UDPPacket(t, flow, []byte{1, 2, 3, 4, 5})
	binary.BigEndian.PutUint16(packet[10:12], 0x1234)
	binary.BigEndian.PutUint16(packet[26:28], 0x5678)
	if err := MaterializeIPv4UDPChecksums(packet); err != nil {
		t.Fatal(err)
	}
	if got := finishChecksum(addChecksumBytes(0, packet[:20])); got != 0 {
		t.Fatalf("materialized IPv4 checksum residual = %#04x", got)
	}
	sum := addChecksumBytes(0, packet[12:20])
	pseudoTail := [4]byte{0, 17, packet[24], packet[25]}
	sum = addChecksumBytes(sum, pseudoTail[:])
	sum = addChecksumBytes(sum, packet[20:])
	if got := finishChecksum(sum); got != 0 {
		t.Fatalf("materialized UDP checksum residual = %#04x", got)
	}
}

func TestControllerDoesNotRepeatFailedReinjection(t *testing.T) {
	engine, _ := testEngine(t, nil)
	backend := &fakeControllerBackend{reinjectErr: errors.New("injected failure")}
	controller, err := NewController(engine, backend)
	if err != nil {
		t.Fatal(err)
	}
	flow := testFlow(31001)
	packet := testIPv4UDPPacket(t, flow, []byte{1, 2})
	first := testEventSample(abi.FakeTCPEvent{
		Key: flow, PayloadLength: 2, FWMark: 3, WGID: 4,
		PacketLength: uint16(len(packet)), Type: abi.FakeTCPEventNeedHandshake,
	}, packet, false)
	if _, err := controller.HandleSample(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	synACK := testEventSample(abi.FakeTCPEvent{
		Key: flow, Sequence: 99, Acknowledgement: 1001, WGID: 4,
		Type: abi.FakeTCPEventSYNACK, TCPFlags: FlagSYN | FlagACK,
	}, nil, false)
	if _, err := controller.HandleSample(context.Background(), synACK); err == nil {
		t.Fatal("reinjection error was not propagated")
	}
	if len(backend.packets) != 1 {
		t.Fatalf("reinjection attempts=%d, want 1", len(backend.packets))
	}
	if _, err := controller.HandleSample(context.Background(), synACK); err != nil {
		t.Fatal(err)
	}
	if len(backend.packets) != 1 {
		t.Fatalf("failed packet was retried, attempts=%d", len(backend.packets))
	}
}

func TestControllerAttemptsEveryReleasedPacketOnce(t *testing.T) {
	engine, _ := testEngine(t, nil)
	backend := &fakeControllerBackend{reinjectErr: errors.New("injected failure")}
	controller, err := NewController(engine, backend)
	if err != nil {
		t.Fatal(err)
	}
	flow := testFlow(31001)
	for index, payload := range [][]byte{{1}, {2}} {
		packet := testIPv4UDPPacket(t, flow, payload)
		sample := testEventSample(abi.FakeTCPEvent{
			Key: flow, PayloadLength: 1, FWMark: uint32(index + 1), WGID: 4,
			PacketLength: uint16(len(packet)), Type: abi.FakeTCPEventNeedHandshake,
		}, packet, false)
		if _, err := controller.HandleSample(context.Background(), sample); err != nil {
			t.Fatal(err)
		}
	}
	synACK := testEventSample(abi.FakeTCPEvent{
		Key: flow, Sequence: 99, Acknowledgement: 1001, WGID: 4,
		Type: abi.FakeTCPEventSYNACK, TCPFlags: FlagSYN | FlagACK,
	}, nil, false)
	if _, err := controller.HandleSample(context.Background(), synACK); err == nil {
		t.Fatal("aggregate reinjection error was not propagated")
	}
	if len(backend.packets) != 2 || backend.packets[0].packet.FWMark != 1 || backend.packets[1].packet.FWMark != 2 {
		t.Fatalf("reinjection attempts=%#v", backend.packets)
	}
}

func TestControllerStopsReleaseWhenControlSendFails(t *testing.T) {
	engine, _ := testEngine(t, nil)
	backend := &fakeControllerBackend{}
	controller, err := NewController(engine, backend)
	if err != nil {
		t.Fatal(err)
	}
	flow := testFlow(31001)
	packet := testIPv4UDPPacket(t, flow, []byte{1})
	first := testEventSample(abi.FakeTCPEvent{
		Key: flow, PayloadLength: 1, WGID: 4,
		PacketLength: uint16(len(packet)), Type: abi.FakeTCPEventNeedHandshake,
	}, packet, false)
	if _, err := controller.HandleSample(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	backend.sendErr = errors.New("send failure")
	synACK := testEventSample(abi.FakeTCPEvent{
		Key: flow, Sequence: 99, Acknowledgement: 1001, WGID: 4,
		Type: abi.FakeTCPEventSYNACK, TCPFlags: FlagSYN | FlagACK,
	}, nil, false)
	if _, err := controller.HandleSample(context.Background(), synACK); err == nil {
		t.Fatal("control send error was not propagated")
	}
	if len(backend.packets) != 0 {
		t.Fatal("packet was released after the prerequisite ACK send failed")
	}
	if _, err := controller.HandleSample(context.Background(), synACK); err != nil {
		t.Fatal(err)
	}
	if len(backend.sent) != 2 {
		t.Fatalf("terminal send failure was retried, send attempts=%d", len(backend.sent))
	}
}

func TestNewControllerRejectsNilAndTypedNilBackend(t *testing.T) {
	engine, _ := testEngine(t, nil)
	backend := &fakeControllerBackend{}
	if controller, err := NewController(nil, backend); err == nil || controller != nil {
		t.Fatalf("nil engine controller=%v err=%v", controller, err)
	}
	if controller, err := NewController(engine, nil); err == nil || controller != nil {
		t.Fatalf("nil backend controller=%v err=%v", controller, err)
	}
	var typedNil *fakeControllerBackend
	if controller, err := NewController(engine, typedNil); err == nil || controller != nil {
		t.Fatalf("typed-nil backend controller=%v err=%v", controller, err)
	}
}

func TestControllerNilReceiverAndNilContextAreFailClosed(t *testing.T) {
	var nilController *Controller
	if _, err := nilController.HandleSample(context.Background(), nil); !errors.Is(err, ErrControllerClosed) {
		t.Fatalf("nil HandleSample error=%v", err)
	}
	if _, err := nilController.Tick(context.Background()); !errors.Is(err, ErrControllerClosed) {
		t.Fatalf("nil Tick error=%v", err)
	}
	if err := nilController.Close(); err != nil {
		t.Fatalf("nil Close error=%v", err)
	}

	engine, _ := testEngine(t, nil)
	backend := &fakeControllerBackend{}
	controller, err := NewController(engine, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.HandleSample(nil, nil); !errors.Is(err, errControllerContextNil) {
		t.Fatalf("nil-context HandleSample error=%v", err)
	}
	if _, err := controller.Tick(nil); !errors.Is(err, errControllerContextNil) {
		t.Fatalf("nil-context Tick error=%v", err)
	}
	if len(backend.operations) != 0 {
		t.Fatalf("nil context touched backend: %v", backend.operations)
	}
}

type gatedControllerBackend struct {
	entered       chan string
	release       chan struct{}
	releaseOnce   sync.Once
	active        atomic.Int32
	maximumActive atomic.Int32
	sendCalls     atomic.Int32
	reinjectCalls atomic.Int32
	closeCalls    atomic.Int32
}

func newGatedControllerBackend() *gatedControllerBackend {
	return &gatedControllerBackend{
		entered: make(chan string, 16),
		release: make(chan struct{}),
	}
}

func (b *gatedControllerBackend) SendControl(context.Context, abi.FakeTCPSessionKey, uint32, ControlPacket) error {
	b.sendCalls.Add(1)
	b.block("send")
	return nil
}

func (b *gatedControllerBackend) Reinject(context.Context, abi.FakeTCPSessionKey, PendingPacket) error {
	b.reinjectCalls.Add(1)
	b.block("reinject")
	return nil
}

func (b *gatedControllerBackend) Close() error {
	b.closeCalls.Add(1)
	b.entered <- "close"
	return nil
}

func (b *gatedControllerBackend) block(operation string) {
	active := b.active.Add(1)
	for {
		maximum := b.maximumActive.Load()
		if active <= maximum || b.maximumActive.CompareAndSwap(maximum, active) {
			break
		}
	}
	b.entered <- operation
	<-b.release
	b.active.Add(-1)
}

func (b *gatedControllerBackend) unblock() {
	b.releaseOnce.Do(func() { close(b.release) })
}

func TestControllerSerializesHandleSampleAndTickSideEffects(t *testing.T) {
	engine, clock := testEngine(t, nil)
	retryFlow := testFlow(31001)
	if _, err := engine.Outbound(retryFlow, []byte{1}); err != nil {
		t.Fatal(err)
	}
	clock.Add(engine.opts.HandshakeTimeout)

	backend := newGatedControllerBackend()
	defer backend.unblock()
	controller, err := NewController(engine, backend)
	if err != nil {
		t.Fatal(err)
	}

	tickResult := make(chan error, 1)
	go func() {
		_, err := controller.Tick(context.Background())
		tickResult <- err
	}()
	if operation := awaitControllerOperation(t, backend.entered); operation != "send" {
		t.Fatalf("first backend operation=%q, want send", operation)
	}

	handleFlow := testFlow(31002)
	packet := testIPv4UDPPacket(t, handleFlow, []byte{2})
	sample := testEventSample(abi.FakeTCPEvent{
		Key: handleFlow, PayloadLength: 1, WGID: 9,
		PacketLength: uint16(len(packet)), Type: abi.FakeTCPEventNeedHandshake,
	}, packet, false)
	handleStarted := make(chan struct{})
	handleResult := make(chan error, 1)
	go func() {
		close(handleStarted)
		_, err := controller.HandleSample(context.Background(), sample)
		handleResult <- err
	}()
	<-handleStarted

	concurrentEntry := ""
	select {
	case concurrentEntry = <-backend.entered:
	case <-time.After(100 * time.Millisecond):
	}
	backend.unblock()
	if err := awaitControllerResult(t, tickResult); err != nil {
		t.Fatalf("Tick error=%v", err)
	}
	if err := awaitControllerResult(t, handleResult); err != nil {
		t.Fatalf("HandleSample error=%v", err)
	}
	if concurrentEntry != "" {
		t.Errorf("HandleSample entered backend concurrently with Tick: %q", concurrentEntry)
	}
	if got := backend.maximumActive.Load(); got != 1 {
		t.Fatalf("maximum concurrent backend calls=%d, want 1", got)
	}
	if got := backend.sendCalls.Load(); got != 2 {
		t.Fatalf("send calls=%d, want one Tick send and one HandleSample send", got)
	}
}

func TestControllerCloseWaitsForInFlightAndClosedOperationsDoNotTouchState(t *testing.T) {
	engine, clock := testEngine(t, nil)
	backend := newGatedControllerBackend()
	defer backend.unblock()
	controller, err := NewController(engine, backend)
	if err != nil {
		t.Fatal(err)
	}

	flow := testFlow(31001)
	packet := testIPv4UDPPacket(t, flow, []byte{1})
	sample := testEventSample(abi.FakeTCPEvent{
		Key: flow, PayloadLength: 1, WGID: 3,
		PacketLength: uint16(len(packet)), Type: abi.FakeTCPEventNeedHandshake,
	}, packet, false)
	handleResult := make(chan error, 1)
	go func() {
		_, err := controller.HandleSample(context.Background(), sample)
		handleResult <- err
	}()
	if operation := awaitControllerOperation(t, backend.entered); operation != "send" {
		t.Fatalf("in-flight backend operation=%q, want send", operation)
	}

	closeStarted := make(chan struct{})
	closeResult := make(chan error, 1)
	go func() {
		close(closeStarted)
		closeResult <- controller.Close()
	}()
	<-closeStarted
	select {
	case err := <-closeResult:
		t.Fatalf("Close returned before in-flight HandleSample: %v", err)
	case operation := <-backend.entered:
		t.Fatalf("Close touched backend before in-flight HandleSample completed: %q", operation)
	case <-time.After(100 * time.Millisecond):
	}

	backend.unblock()
	if err := awaitControllerResult(t, handleResult); err != nil {
		t.Fatalf("HandleSample error=%v", err)
	}
	if err := awaitControllerResult(t, closeResult); err != nil {
		t.Fatalf("Close error=%v", err)
	}
	if operation := awaitControllerOperation(t, backend.entered); operation != "close" {
		t.Fatalf("post-flight backend operation=%q, want close", operation)
	}

	closedFlow := testFlow(31002)
	closedPacket := testIPv4UDPPacket(t, closedFlow, []byte{2})
	closedSample := testEventSample(abi.FakeTCPEvent{
		Key: closedFlow, PayloadLength: 1, WGID: 4,
		PacketLength: uint16(len(closedPacket)), Type: abi.FakeTCPEventNeedHandshake,
	}, closedPacket, false)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := controller.HandleSample(canceled, closedSample); !errors.Is(err, ErrControllerClosed) {
		t.Fatalf("closed HandleSample error=%v", err)
	}
	clock.Add(2 * engine.opts.HandshakeTimeout)
	if _, err := controller.Tick(canceled); !errors.Is(err, ErrControllerClosed) {
		t.Fatalf("closed Tick error=%v", err)
	}
	if _, found, err := engine.Snapshot(closedFlow); err != nil || found {
		t.Fatalf("closed HandleSample touched engine: found=%t err=%v", found, err)
	}
	if got := backend.sendCalls.Load(); got != 1 {
		t.Fatalf("closed operations touched backend: send calls=%d", got)
	}
	if got := backend.closeCalls.Load(); got != 1 {
		t.Fatalf("backend close calls=%d, want 1", got)
	}
}

func TestControllerConcurrentCloseIsIdempotentAndRetainsFirstError(t *testing.T) {
	engine, _ := testEngine(t, nil)
	closeFailure := errors.New("injected close failure")
	backend := &fakeControllerBackend{closeErr: closeFailure}
	controller, err := NewController(engine, backend)
	if err != nil {
		t.Fatal(err)
	}

	const closers = 16
	start := make(chan struct{})
	errs := make([]error, closers)
	var wait sync.WaitGroup
	wait.Add(closers)
	for index := range errs {
		go func() {
			defer wait.Done()
			<-start
			errs[index] = controller.Close()
		}()
	}
	close(start)
	wait.Wait()

	if backend.closeCalls != 1 {
		t.Fatalf("backend Close calls=%d, want 1", backend.closeCalls)
	}
	for index, err := range errs {
		if !errors.Is(err, closeFailure) {
			t.Fatalf("Close[%d] error=%v, want retained failure", index, err)
		}
		if err != errs[0] {
			t.Fatalf("Close[%d] did not return the retained first error", index)
		}
	}
	if err := controller.Close(); err != errs[0] {
		t.Fatal("later Close did not return the retained first error")
	}
	if _, err := controller.Tick(context.Background()); !errors.Is(err, ErrControllerClosed) {
		t.Fatalf("operation after failed Close error=%v", err)
	}
}

func awaitControllerOperation(t *testing.T, operations <-chan string) string {
	t.Helper()
	select {
	case operation := <-operations:
		return operation
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for controller backend operation")
		return ""
	}
}

func awaitControllerResult(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for controller operation")
		return nil
	}
}

func testEventSample(event abi.FakeTCPEvent, packet []byte, fixed bool) []byte {
	size := fakeTCPEventSize + len(packet)
	if fixed && event.Type == abi.FakeTCPEventNeedHandshake {
		size = fakeTCPPacketEventSize
	}
	sample := make([]byte, size)
	native := binary.NativeEndian
	native.PutUint64(sample[0:8], event.Key.Generation)
	native.PutUint32(sample[8:12], event.Key.LocalIPv4)
	native.PutUint32(sample[12:16], event.Key.RemoteIPv4)
	native.PutUint32(sample[16:20], event.Key.UnderlayIndex)
	native.PutUint16(sample[20:22], event.Key.LocalPort)
	native.PutUint16(sample[22:24], event.Key.RemotePort)
	native.PutUint64(sample[24:32], event.TimestampNanos)
	native.PutUint32(sample[32:36], event.Sequence)
	native.PutUint32(sample[36:40], event.Acknowledgement)
	native.PutUint32(sample[40:44], event.PayloadLength)
	native.PutUint32(sample[44:48], event.FWMark)
	native.PutUint32(sample[48:52], event.WGID)
	native.PutUint16(sample[52:54], event.PacketLength)
	sample[54] = event.Type
	sample[55] = event.TCPFlags
	copy(sample[fakeTCPEventSize:], packet)
	return sample
}

func testIPv4UDPPacket(t *testing.T, flow abi.FakeTCPSessionKey, payload []byte) []byte {
	t.Helper()
	packet := make([]byte, 20+8+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 17
	binary.NativeEndian.PutUint32(packet[12:16], flow.LocalIPv4)
	binary.NativeEndian.PutUint32(packet[16:20], flow.RemoteIPv4)
	binary.BigEndian.PutUint16(packet[20:22], flow.LocalPort)
	binary.BigEndian.PutUint16(packet[22:24], flow.RemotePort)
	binary.BigEndian.PutUint16(packet[24:26], uint16(8+len(payload)))
	copy(packet[28:], payload)
	if err := MaterializeIPv4UDPChecksums(packet); err != nil {
		t.Fatal(err)
	}
	return packet
}
