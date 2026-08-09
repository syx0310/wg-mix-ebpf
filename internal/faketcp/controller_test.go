package faketcp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
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
	sent             []sentControl
	packets          []reinjectedPacket
	operations       []string
	sendErr          error
	reinjectErr      error
	closeErr         error
	closeCalls       int
	reinjectHook     func(int)
	closeStarted     chan struct{}
	closeRelease     <-chan struct{}
	closeStartedOnce sync.Once
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
	if b.reinjectHook != nil {
		b.reinjectHook(len(b.packets))
	}
	return b.reinjectErr
}

func (b *fakeControllerBackend) Close() error {
	b.closeCalls++
	b.operations = append(b.operations, "close")
	if b.closeStarted != nil {
		b.closeStartedOnce.Do(func() { close(b.closeStarted) })
	}
	if b.closeRelease != nil {
		<-b.closeRelease
	}
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
	packetEvent := testBoundEventSample(abi.FakeTCPEvent{
		Key: flow, TimestampNanos: 123456, PayloadLength: 5, FWMark: 0x1234, WGID: 77,
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

	synACK := testBoundEventSample(abi.FakeTCPEvent{
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
	if got.flow != flow || got.packet.FWMark != 0x1234 || got.packet.WGID != 77 ||
		got.packet.CaptureNanos != 123456 || got.packet.CaptureID.Runtime != engine.Identity() ||
		got.packet.CaptureID.CPU != 3 || got.packet.CaptureID.Sequence != 1 ||
		!bytes.Equal(got.packet.Data, wantPacket) {
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

func TestDecodeEventSampleRejectsUnversionedOrAmbiguousIdentity(t *testing.T) {
	flow := testFlow(31001)
	packet := testIPv4UDPPacket(t, flow, []byte{1})
	base := abi.FakeTCPEvent{
		Key: flow, PayloadLength: 1, PacketLength: uint16(len(packet)),
		Type: abi.FakeTCPEventNeedHandshake,
	}
	if _, err := DecodeEventSample(testEventSample(base, packet, false)); err == nil {
		t.Fatal("uninitialized producer event was implicitly assigned an identity")
	}
	bindTestEvent(&base, testRuntimeIdentity(flow.Generation), 1)
	for _, test := range []struct {
		name   string
		mutate func(*abi.FakeTCPEvent)
	}{
		{name: "event ABI", mutate: func(event *abi.FakeTCPEvent) { event.EventABIVersion++ }},
		{name: "zero incarnation", mutate: func(event *abi.FakeTCPEvent) { event.RuntimeIncarnation = [16]byte{} }},
		{name: "zero sequence", mutate: func(event *abi.FakeTCPEvent) { event.CaptureSequence = 0 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			event := base
			test.mutate(&event)
			if _, err := DecodeEventSample(testBoundEventSample(event, packet, false)); err == nil {
				t.Fatal("ambiguous event identity was accepted")
			}
		})
	}
	if _, err := DecodeEventSample(make([]byte, 56)); err == nil {
		t.Fatal("legacy unversioned event header was accepted")
	}
	control := abi.FakeTCPEvent{Key: flow, Type: abi.FakeTCPEventACK, TCPFlags: FlagACK}
	bindTestEvent(&control, testRuntimeIdentity(flow.Generation), 0)
	control.CaptureCPU, control.CaptureSequence = 3, 1
	if _, err := DecodeEventSample(testBoundEventSample(control, nil, false)); err == nil {
		t.Fatal("control event with capture identity was accepted")
	}
}

func TestControllerRejectsEventFromDifferentRuntimeIncarnationBeforeEngine(t *testing.T) {
	engine, _ := testEngine(t, nil)
	backend := &fakeControllerBackend{}
	controller, err := NewController(engine, backend)
	if err != nil {
		t.Fatal(err)
	}
	flow := testFlow(31001)
	packet := testIPv4UDPPacket(t, flow, []byte{1})
	event := abi.FakeTCPEvent{
		Key: flow, PayloadLength: 1, PacketLength: uint16(len(packet)),
		Type: abi.FakeTCPEventNeedHandshake,
	}
	wrong := engine.Identity()
	wrong.Incarnation[0] = 2
	bindTestEvent(&event, wrong, 1)
	if _, err := controller.HandleSample(context.Background(), testBoundEventSample(event, packet, false)); err == nil {
		t.Fatal("event from another runtime incarnation was accepted")
	}
	if _, found, err := engine.Snapshot(flow); err != nil || found {
		t.Fatalf("mismatched event touched Engine: found=%t err=%v", found, err)
	}
	if len(backend.operations) != 0 {
		t.Fatalf("mismatched event reached backend: %v", backend.operations)
	}
}

func TestDecodeEventSampleAcceptsCompactAndFixedPacketRecords(t *testing.T) {
	flow := testFlow(31001)
	packet := testIPv4UDPPacket(t, flow, []byte{9, 8, 7})
	event := abi.FakeTCPEvent{
		Key: flow, PayloadLength: 3, FWMark: 9, WGID: 5,
		PacketLength: uint16(len(packet)), Type: abi.FakeTCPEventNeedHandshake,
	}
	bindTestEvent(&event, testRuntimeIdentity(flow.Generation), 1)
	for _, fixed := range []bool{false, true} {
		decoded, err := DecodeEventSample(testBoundEventSample(event, packet, fixed))
		if err != nil {
			t.Fatalf("fixed=%t: %v", fixed, err)
		}
		if decoded.Event != event || !bytes.Equal(decoded.Packet, packet) {
			t.Fatalf("fixed=%t decoded=%#v", fixed, decoded)
		}
	}
}

func TestDecodeEventSampleAcceptsCompactAndFixedCloseRecords(t *testing.T) {
	engine, _, flow, state := establishedControlTestSession(t)
	for _, flags := range []uint8{FlagRST | FlagACK, FlagFIN | FlagACK} {
		event, packet := capturedCloseEvent(engine, flow, state, flags, 7)
		for _, fixed := range []bool{false, true} {
			decoded, err := DecodeEventSample(testBoundEventSample(event, packet, fixed))
			if err != nil {
				t.Fatalf("flags=%#x fixed=%t: %v", flags, fixed, err)
			}
			if decoded.Event != event || !bytes.Equal(decoded.Packet, packet) {
				t.Fatalf("flags=%#x fixed=%t decoded=%#v", flags, fixed, decoded)
			}
		}
	}
}

func TestControllerCloseValidationDropsForgeryThenAcceptsExactPacket(t *testing.T) {
	engine, store, flow, state := establishedControlTestSession(t)
	backend := &fakeControllerBackend{}
	controller, err := NewController(engine, backend)
	if err != nil {
		t.Fatal(err)
	}
	event, packet := capturedCloseEvent(engine, flow, state, FlagRST|FlagACK, 7)
	mismatched := event
	mismatched.Sequence++
	actions, err := controller.HandleSample(
		context.Background(), testBoundEventSample(mismatched, packet, false),
	)
	if err != nil || len(actions) != 1 || actions[0].Reason != "invalid-close-control" {
		t.Fatalf("mismatched close actions=%#v err=%v", actions, err)
	}
	forged := append([]byte(nil), packet...)
	forged[36] ^= 1
	actions, err = controller.HandleSample(
		context.Background(), testBoundEventSample(event, forged, false),
	)
	if err != nil || len(actions) != 1 || actions[0].Reason != "invalid-close-control" {
		t.Fatalf("forged close actions=%#v err=%v", actions, err)
	}
	if _, found := store.values[flow]; !found || store.deleteAttempts != 0 {
		t.Fatalf("forged close touched session: found=%t attempts=%d", found, store.deleteAttempts)
	}

	actions, err = controller.HandleSample(
		context.Background(), testBoundEventSample(event, packet, false),
	)
	if err != nil || len(actions) != 1 || actions[0].Reason != "peer-close" {
		t.Fatalf("exact close actions=%#v err=%v", actions, err)
	}
	if _, found := store.values[flow]; found || store.deleteAttempts != 1 {
		t.Fatalf("exact close result: found=%t attempts=%d", found, store.deleteAttempts)
	}
	if len(backend.operations) != 0 {
		t.Fatalf("peer close unexpectedly reached packet/control backend: %v", backend.operations)
	}

	actions, err = controller.HandleSample(
		context.Background(), testBoundEventSample(event, packet, false),
	)
	if err != nil || len(actions) != 1 || actions[0].Reason != "unknown-close" {
		t.Fatalf("replayed close actions=%#v err=%v", actions, err)
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
			_, err := DecodeEventSample(testBoundEventSample(test.event, test.packet, test.fixed))
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
	reinjectFailure := errors.New("injected failure")
	backend := &fakeControllerBackend{reinjectErr: reinjectFailure}
	controller, err := NewController(engine, backend)
	if err != nil {
		t.Fatal(err)
	}
	flow := testFlow(31001)
	packet := testIPv4UDPPacket(t, flow, []byte{1, 2})
	first := testBoundEventSample(abi.FakeTCPEvent{
		Key: flow, PayloadLength: 2, FWMark: 3, WGID: 4,
		PacketLength: uint16(len(packet)), Type: abi.FakeTCPEventNeedHandshake,
	}, packet, false)
	if _, err := controller.HandleSample(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	synACK := testBoundEventSample(abi.FakeTCPEvent{
		Key: flow, Sequence: 99, Acknowledgement: 1001, WGID: 4,
		Type: abi.FakeTCPEventSYNACK, TCPFlags: FlagSYN | FlagACK,
	}, nil, false)
	_, terminalErr := controller.HandleSample(context.Background(), synACK)
	if !errors.Is(terminalErr, ErrControllerFailed) || !errors.Is(terminalErr, reinjectFailure) {
		t.Fatalf("reinjection terminal error=%v", terminalErr)
	}
	if len(backend.packets) != 1 {
		t.Fatalf("reinjection attempts=%d, want 1", len(backend.packets))
	}
	if _, err := controller.HandleSample(context.Background(), synACK); err != terminalErr {
		t.Fatalf("failed controller error=%v, want retained %v", err, terminalErr)
	}
	if len(backend.packets) != 1 {
		t.Fatalf("failed packet was retried, attempts=%d", len(backend.packets))
	}
}

func TestControllerAttemptsEveryReleasedPacketOnce(t *testing.T) {
	engine, _ := testEngine(t, nil)
	reinjectFailure := errors.New("injected failure")
	backend := &fakeControllerBackend{reinjectErr: reinjectFailure}
	controller, err := NewController(engine, backend)
	if err != nil {
		t.Fatal(err)
	}
	flow := testFlow(31001)
	for index, payload := range [][]byte{{1}, {2}} {
		packet := testIPv4UDPPacket(t, flow, payload)
		sample := testBoundEventSample(abi.FakeTCPEvent{
			Key: flow, PayloadLength: 1, FWMark: uint32(index + 1), WGID: 4,
			PacketLength: uint16(len(packet)), Type: abi.FakeTCPEventNeedHandshake,
		}, packet, false)
		if _, err := controller.HandleSample(context.Background(), sample); err != nil {
			t.Fatal(err)
		}
	}
	synACK := testBoundEventSample(abi.FakeTCPEvent{
		Key: flow, Sequence: 99, Acknowledgement: 1001, WGID: 4,
		Type: abi.FakeTCPEventSYNACK, TCPFlags: FlagSYN | FlagACK,
	}, nil, false)
	if _, err := controller.HandleSample(context.Background(), synACK); !errors.Is(err, ErrControllerFailed) || !errors.Is(err, reinjectFailure) {
		t.Fatalf("aggregate terminal reinjection error=%v", err)
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
	first := testBoundEventSample(abi.FakeTCPEvent{
		Key: flow, PayloadLength: 1, WGID: 4,
		PacketLength: uint16(len(packet)), Type: abi.FakeTCPEventNeedHandshake,
	}, packet, false)
	if _, err := controller.HandleSample(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	sendFailure := errors.New("send failure")
	backend.sendErr = sendFailure
	synACK := testBoundEventSample(abi.FakeTCPEvent{
		Key: flow, Sequence: 99, Acknowledgement: 1001, WGID: 4,
		Type: abi.FakeTCPEventSYNACK, TCPFlags: FlagSYN | FlagACK,
	}, nil, false)
	_, terminalErr := controller.HandleSample(context.Background(), synACK)
	if !errors.Is(terminalErr, ErrControllerFailed) || !errors.Is(terminalErr, sendFailure) {
		t.Fatalf("control send terminal error=%v", terminalErr)
	}
	if len(backend.packets) != 0 {
		t.Fatal("packet was released after the prerequisite ACK send failed")
	}
	if _, err := controller.HandleSample(context.Background(), synACK); err != terminalErr {
		t.Fatalf("failed controller error=%v, want retained %v", err, terminalErr)
	}
	if len(backend.sent) != 2 {
		t.Fatalf("terminal send failure was retried, send attempts=%d", len(backend.sent))
	}
}

func TestControllerInitialSendFailurePreventsTickRetry(t *testing.T) {
	engine, clock := testEngine(t, nil)
	sendFailure := errors.New("initial SYN send failed")
	backend := &fakeControllerBackend{sendErr: sendFailure}
	controller, err := NewController(engine, backend)
	if err != nil {
		t.Fatal(err)
	}

	flow := testFlow(31001)
	packet := testIPv4UDPPacket(t, flow, []byte{1})
	sample := testBoundEventSample(abi.FakeTCPEvent{
		Key: flow, PayloadLength: 1, WGID: 4,
		PacketLength: uint16(len(packet)), Type: abi.FakeTCPEventNeedHandshake,
	}, packet, false)
	_, terminalErr := controller.HandleSample(context.Background(), sample)
	if !errors.Is(terminalErr, ErrControllerFailed) || !errors.Is(terminalErr, sendFailure) {
		t.Fatalf("initial send terminal error=%v", terminalErr)
	}
	if len(backend.sent) != 1 {
		t.Fatalf("initial send attempts=%d, want 1", len(backend.sent))
	}
	engine.mu.Lock()
	session := engine.sessions[flow]
	if session == nil {
		engine.mu.Unlock()
		t.Fatal("initial Engine transition did not create a session")
	}
	retriesBefore := session.retries
	engine.mu.Unlock()

	clock.Add(2 * engine.opts.HandshakeTimeout)
	if actions, err := controller.Tick(context.Background()); err != terminalErr || actions != nil {
		t.Fatalf("failed Tick actions=%#v err=%v, want retained %v", actions, err, terminalErr)
	}
	engine.mu.Lock()
	retriesAfter := engine.sessions[flow].retries
	engine.mu.Unlock()
	if retriesAfter != retriesBefore {
		t.Fatalf("failed Tick touched Engine retries: before=%d after=%d", retriesBefore, retriesAfter)
	}
	if len(backend.sent) != 1 {
		t.Fatalf("failed Tick retried backend send, attempts=%d", len(backend.sent))
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := controller.HandleSample(canceled, nil); err != terminalErr {
		t.Fatalf("failed HandleSample validated context/sample first: error=%v", err)
	}
	if err := controller.Close(); err != nil {
		t.Fatal(err)
	}
	if backend.closeCalls != 1 {
		t.Fatalf("failed controller backend Close calls=%d, want 1", backend.closeCalls)
	}
	if _, err := controller.Tick(context.Background()); !errors.Is(err, ErrControllerClosed) {
		t.Fatalf("closed failed controller Tick error=%v", err)
	}
}

func TestControllerPartialReinjectionCancellationIsTerminal(t *testing.T) {
	engine, _ := testEngine(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	backend := &fakeControllerBackend{}
	backend.reinjectHook = func(attempt int) {
		if attempt == 1 {
			cancel()
		}
	}
	controller, err := NewController(engine, backend)
	if err != nil {
		t.Fatal(err)
	}

	flow := testFlow(31001)
	for index, payload := range [][]byte{{1}, {2}} {
		packet := testIPv4UDPPacket(t, flow, payload)
		sample := testBoundEventSample(abi.FakeTCPEvent{
			Key: flow, PayloadLength: 1, FWMark: uint32(index + 1), WGID: 4,
			PacketLength: uint16(len(packet)), Type: abi.FakeTCPEventNeedHandshake,
		}, packet, false)
		if _, err := controller.HandleSample(context.Background(), sample); err != nil {
			t.Fatal(err)
		}
	}
	synACK := testBoundEventSample(abi.FakeTCPEvent{
		Key: flow, Sequence: 99, Acknowledgement: 1001, WGID: 4,
		Type: abi.FakeTCPEventSYNACK, TCPFlags: FlagSYN | FlagACK,
	}, nil, false)
	_, terminalErr := controller.HandleSample(ctx, synACK)
	if !errors.Is(terminalErr, ErrControllerFailed) || !errors.Is(terminalErr, context.Canceled) {
		t.Fatalf("partial reinjection terminal error=%v", terminalErr)
	}
	if len(backend.packets) != 1 || backend.packets[0].packet.FWMark != 1 {
		t.Fatalf("partial reinjection attempts=%#v", backend.packets)
	}
	if _, err := controller.Tick(context.Background()); err != terminalErr {
		t.Fatalf("failed Tick error=%v, want retained %v", err, terminalErr)
	}
	if len(backend.packets) != 1 {
		t.Fatalf("partial reinjection was retried, attempts=%d", len(backend.packets))
	}
}

func TestControllerPreExecutionErrorsDoNotBecomeTerminal(t *testing.T) {
	engine, _ := testEngine(t, nil)
	backend := &fakeControllerBackend{}
	controller, err := NewController(engine, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.HandleSample(context.Background(), []byte{1}); err == nil || errors.Is(err, ErrControllerFailed) {
		t.Fatalf("decode error=%v", err)
	}

	flow := testFlow(31001)
	packet := testIPv4UDPPacket(t, flow, []byte{1})
	sample := testBoundEventSample(abi.FakeTCPEvent{
		Key: flow, PayloadLength: 1, WGID: 4,
		PacketLength: uint16(len(packet)), Type: abi.FakeTCPEventNeedHandshake,
	}, packet, false)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := controller.HandleSample(canceled, sample); !errors.Is(err, context.Canceled) || errors.Is(err, ErrControllerFailed) {
		t.Fatalf("pre-Engine context error=%v", err)
	}

	wrongGeneration := testFlow(31002)
	wrongGeneration.Generation++
	wrongPacket := testIPv4UDPPacket(t, wrongGeneration, []byte{2})
	wrongSample := testBoundEventSample(abi.FakeTCPEvent{
		Key: wrongGeneration, PayloadLength: 1, WGID: 4,
		PacketLength: uint16(len(wrongPacket)), Type: abi.FakeTCPEventNeedHandshake,
	}, wrongPacket, false)
	if _, err := controller.HandleSample(context.Background(), wrongSample); err == nil || errors.Is(err, ErrControllerFailed) {
		t.Fatalf("Engine validation error=%v", err)
	}

	if _, err := controller.HandleSample(context.Background(), sample); err != nil {
		t.Fatalf("controller became terminal after pre-execution errors: %v", err)
	}
	if len(backend.sent) != 1 {
		t.Fatalf("valid operation backend sends=%d, want 1", len(backend.sent))
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
	if err := nilController.Close(); !errors.Is(err, ErrControllerClosed) {
		t.Fatalf("nil Close error=%v", err)
	}
	zeroController := &Controller{}
	if _, err := zeroController.HandleSample(context.Background(), nil); !errors.Is(err, ErrControllerClosed) {
		t.Fatalf("zero-value HandleSample error=%v", err)
	}
	if _, err := zeroController.Tick(context.Background()); !errors.Is(err, ErrControllerClosed) {
		t.Fatalf("zero-value Tick error=%v", err)
	}
	if err := zeroController.Close(); !errors.Is(err, ErrControllerClosed) {
		t.Fatalf("zero-value Close error=%v", err)
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
	sendErr       error
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
	return b.sendErr
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
	sample := testBoundEventSample(abi.FakeTCPEvent{
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
	awaitControllerInflight(t, controller, 2)
	if controller.opMu.TryLock() {
		controller.opMu.Unlock()
		t.Fatal("first operation did not retain the action serialisation lock")
	}
	select {
	case operation := <-backend.entered:
		t.Fatalf("HandleSample entered backend concurrently with Tick: %q", operation)
	default:
	}
	backend.unblock()
	if err := awaitControllerResult(t, tickResult); err != nil {
		t.Fatalf("Tick error=%v", err)
	}
	if err := awaitControllerResult(t, handleResult); err != nil {
		t.Fatalf("HandleSample error=%v", err)
	}
	if got := backend.maximumActive.Load(); got != 1 {
		t.Fatalf("maximum concurrent backend calls=%d, want 1", got)
	}
	if got := backend.sendCalls.Load(); got != 2 {
		t.Fatalf("send calls=%d, want one Tick send and one HandleSample send", got)
	}
}

func TestControllerAdmittedWaiterObservesPriorTerminalFailureBeforeEngine(t *testing.T) {
	engine, _ := testEngine(t, nil)
	sendFailure := errors.New("blocked send failed")
	backend := newGatedControllerBackend()
	backend.sendErr = sendFailure
	defer backend.unblock()
	controller, err := NewController(engine, backend)
	if err != nil {
		t.Fatal(err)
	}

	makeSample := func(port uint16) []byte {
		flow := testFlow(port)
		packet := testIPv4UDPPacket(t, flow, []byte{1})
		return testBoundEventSample(abi.FakeTCPEvent{
			Key: flow, PayloadLength: 1, WGID: 3,
			PacketLength: uint16(len(packet)), Type: abi.FakeTCPEventNeedHandshake,
		}, packet, false)
	}
	firstSample := makeSample(31001)
	secondSample := makeSample(31002)
	firstResult := make(chan error, 1)
	go func() {
		_, err := controller.HandleSample(context.Background(), firstSample)
		firstResult <- err
	}()
	if operation := awaitControllerOperation(t, backend.entered); operation != "send" {
		t.Fatalf("first backend operation=%q, want send", operation)
	}

	secondResult := make(chan error, 1)
	go func() {
		_, err := controller.HandleSample(context.Background(), secondSample)
		secondResult <- err
	}()
	awaitControllerInflight(t, controller, 2)
	backend.unblock()
	terminalErr := awaitControllerResult(t, firstResult)
	if !errors.Is(terminalErr, ErrControllerFailed) || !errors.Is(terminalErr, sendFailure) {
		t.Fatalf("first terminal error=%v", terminalErr)
	}
	if err := awaitControllerResult(t, secondResult); err != terminalErr {
		t.Fatalf("admitted waiter error=%v, want retained %v", err, terminalErr)
	}
	if got := backend.sendCalls.Load(); got != 1 {
		t.Fatalf("admitted waiter touched backend, send calls=%d", got)
	}
	if _, found, err := engine.Snapshot(testFlow(31002)); err != nil || found {
		t.Fatalf("admitted waiter touched Engine: found=%t err=%v", found, err)
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
	sample := testBoundEventSample(abi.FakeTCPEvent{
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
	awaitControllerClosing(t, controller)
	closingOperation := make(chan error, 1)
	go func() {
		_, err := controller.Tick(context.Background())
		closingOperation <- err
	}()
	if err := awaitControllerResult(t, closingOperation); !errors.Is(err, ErrControllerClosed) {
		t.Fatalf("operation admitted after closing began: %v", err)
	}
	select {
	case err := <-closeResult:
		t.Fatalf("Close returned before in-flight HandleSample: %v", err)
	case operation := <-backend.entered:
		t.Fatalf("Close touched backend before in-flight HandleSample completed: %q", operation)
	default:
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
	closedSample := testBoundEventSample(abi.FakeTCPEvent{
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

type closingCallbackBackend struct {
	controller  *Controller
	entered     chan struct{}
	invoke      chan struct{}
	callbackErr chan error
	enteredOnce sync.Once
	closeCalls  atomic.Int32
}

func newClosingCallbackBackend() *closingCallbackBackend {
	return &closingCallbackBackend{
		entered:     make(chan struct{}),
		invoke:      make(chan struct{}),
		callbackErr: make(chan error, 1),
	}
}

func (b *closingCallbackBackend) SendControl(context.Context, abi.FakeTCPSessionKey, uint32, ControlPacket) error {
	b.enteredOnce.Do(func() { close(b.entered) })
	<-b.invoke
	_, err := b.controller.Tick(context.Background())
	b.callbackErr <- err
	return nil
}

func (*closingCallbackBackend) Reinject(context.Context, abi.FakeTCPSessionKey, PendingPacket) error {
	return nil
}

func (b *closingCallbackBackend) Close() error {
	b.closeCalls.Add(1)
	return nil
}

func TestControllerClosingRejectsCallbackFromInflightBackendWithoutDeadlock(t *testing.T) {
	engine, _ := testEngine(t, nil)
	backend := newClosingCallbackBackend()
	controller, err := NewController(engine, backend)
	if err != nil {
		t.Fatal(err)
	}
	backend.controller = controller

	flow := testFlow(31001)
	packet := testIPv4UDPPacket(t, flow, []byte{1})
	sample := testBoundEventSample(abi.FakeTCPEvent{
		Key: flow, PayloadLength: 1, WGID: 3,
		PacketLength: uint16(len(packet)), Type: abi.FakeTCPEventNeedHandshake,
	}, packet, false)
	handleResult := make(chan error, 1)
	go func() {
		_, err := controller.HandleSample(context.Background(), sample)
		handleResult <- err
	}()
	awaitControllerSignal(t, backend.entered, "backend SendControl entry")

	closeResult := make(chan error, 1)
	go func() { closeResult <- controller.Close() }()
	awaitControllerClosing(t, controller)
	close(backend.invoke)
	if err := awaitControllerResult(t, backend.callbackErr); !errors.Is(err, ErrControllerClosed) {
		t.Fatalf("in-flight backend callback error=%v, want ErrControllerClosed", err)
	}
	if err := awaitControllerResult(t, handleResult); err != nil {
		t.Fatalf("HandleSample error=%v", err)
	}
	if err := awaitControllerResult(t, closeResult); err != nil {
		t.Fatalf("Close error=%v", err)
	}
	if got := backend.closeCalls.Load(); got != 1 {
		t.Fatalf("backend Close calls=%d, want 1", got)
	}
}

type closeInspectionBackend struct {
	controller    *Controller
	callbackErr   error
	stateUnlocked bool
	opUnlocked    bool
	closeCalls    int
}

func (*closeInspectionBackend) SendControl(context.Context, abi.FakeTCPSessionKey, uint32, ControlPacket) error {
	return nil
}

func (*closeInspectionBackend) Reinject(context.Context, abi.FakeTCPSessionKey, PendingPacket) error {
	return nil
}

func (b *closeInspectionBackend) Close() error {
	b.closeCalls++
	b.stateUnlocked = b.controller.stateMu.TryLock()
	if b.stateUnlocked {
		b.controller.stateMu.Unlock()
	}
	b.opUnlocked = b.controller.opMu.TryLock()
	if b.opUnlocked {
		b.controller.opMu.Unlock()
	}
	_, b.callbackErr = b.controller.Tick(context.Background())
	return nil
}

func TestControllerBackendCloseRunsOutsideLocksAndCallbackFailsClosed(t *testing.T) {
	engine, _ := testEngine(t, nil)
	backend := &closeInspectionBackend{}
	controller, err := NewController(engine, backend)
	if err != nil {
		t.Fatal(err)
	}
	backend.controller = controller
	closeResult := make(chan error, 1)
	go func() { closeResult <- controller.Close() }()
	if err := awaitControllerResult(t, closeResult); err != nil {
		t.Fatal(err)
	}
	if !backend.stateUnlocked || !backend.opUnlocked {
		t.Fatalf("backend Close lock state: stateMu unlocked=%t opMu unlocked=%t", backend.stateUnlocked, backend.opUnlocked)
	}
	if !errors.Is(backend.callbackErr, ErrControllerClosed) {
		t.Fatalf("backend Close Tick callback error=%v", backend.callbackErr)
	}
	if backend.closeCalls != 1 {
		t.Fatalf("backend Close calls=%d, want 1", backend.closeCalls)
	}
}

func TestControllerConcurrentCloseCoalescesFailureAndLaterRetries(t *testing.T) {
	engine, _ := testEngine(t, nil)
	closeFailure := errors.New("injected close failure")
	closeStarted := make(chan struct{})
	closeRelease := make(chan struct{})
	backend := &fakeControllerBackend{
		closeErr:     closeFailure,
		closeStarted: closeStarted,
		closeRelease: closeRelease,
	}
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
	awaitControllerSignal(t, closeStarted, "backend Close entry")
	awaitControllerClosing(t, controller)
	time.Sleep(10 * time.Millisecond)
	close(closeRelease)
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
	backend.closeErr = nil
	if err := controller.Close(); err != nil {
		t.Fatalf("retry Close error=%v", err)
	}
	if backend.closeCalls != 2 {
		t.Fatalf("backend retry Close calls=%d, want 2", backend.closeCalls)
	}
	if err := controller.Close(); err != nil || backend.closeCalls != 2 {
		t.Fatalf("converged Close error=%v calls=%d", err, backend.closeCalls)
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

func awaitControllerSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func awaitControllerInflight(t *testing.T, controller *Controller, want uint64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		controller.stateMu.Lock()
		got := controller.inflight
		controller.stateMu.Unlock()
		if got == want {
			return
		}
		if got > want || time.Now().After(deadline) {
			t.Fatalf("controller in-flight operations=%d, want %d", got, want)
		}
		runtime.Gosched()
	}
}

func awaitControllerClosing(t *testing.T, controller *Controller) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		controller.stateMu.Lock()
		closing := controller.closing
		controller.stateMu.Unlock()
		if closing {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for controller closing state")
		}
		runtime.Gosched()
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

func testBoundEventSample(event abi.FakeTCPEvent, packet []byte, fixed bool) []byte {
	if event.EventABIVersion == 0 {
		bindTestEvent(&event, testRuntimeIdentity(event.Key.Generation), 1)
	}
	return testEventSample(event, packet, fixed)
}

// testEventSample encodes exactly the supplied event. It deliberately does not
// repair missing producer identity so malformed-producer tests cannot be
// hidden by a shared helper.
func testEventSample(event abi.FakeTCPEvent, packet []byte, fixed bool) []byte {
	size := fakeTCPEventSize + len(packet)
	if fixed && fakeTCPEventCarriesPacket(event.Type) {
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
	copy(sample[32:48], event.RuntimeIncarnation[:])
	native.PutUint64(sample[48:56], event.CaptureSequence)
	native.PutUint32(sample[56:60], event.CaptureCPU)
	native.PutUint32(sample[60:64], event.Sequence)
	native.PutUint32(sample[64:68], event.Acknowledgement)
	native.PutUint32(sample[68:72], event.PayloadLength)
	native.PutUint32(sample[72:76], event.FWMark)
	native.PutUint32(sample[76:80], event.WGID)
	native.PutUint16(sample[80:82], event.PacketLength)
	native.PutUint16(sample[82:84], event.EventABIVersion)
	sample[84] = event.Type
	sample[85] = event.TCPFlags
	copy(sample[fakeTCPEventSize:], packet)
	return sample
}

func testRuntimeIdentity(generation uint64) RuntimeIdentity {
	return RuntimeIdentity{Generation: generation, Incarnation: RuntimeIncarnation{1}}
}

func bindTestEvent(event *abi.FakeTCPEvent, identity RuntimeIdentity, captureSequence uint64) {
	event.EventABIVersion = abi.FakeTCPEventABIVersion
	event.RuntimeIncarnation = [16]byte(identity.Incarnation)
	if event.Type == abi.FakeTCPEventNeedHandshake {
		event.CaptureSequence = captureSequence
		event.CaptureCPU = 3
	}
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
