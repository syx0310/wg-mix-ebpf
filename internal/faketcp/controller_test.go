package faketcp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

type sentControl struct {
	flow    abi.FakeTCPSessionKey
	wgID    uint32
	control ControlPacket
}

type fakeControlSender struct {
	sent []sentControl
	err  error
}

func (s *fakeControlSender) SendControl(_ context.Context, flow abi.FakeTCPSessionKey, wgID uint32, control ControlPacket) error {
	s.sent = append(s.sent, sentControl{flow: flow, wgID: wgID, control: control})
	return s.err
}

type reinjectedPacket struct {
	flow   abi.FakeTCPSessionKey
	packet PendingPacket
}

type fakePacketReinjector struct {
	packets []reinjectedPacket
	err     error
}

func (r *fakePacketReinjector) Reinject(_ context.Context, flow abi.FakeTCPSessionKey, packet PendingPacket) error {
	copyPacket := packet
	copyPacket.Data = append([]byte(nil), packet.Data...)
	r.packets = append(r.packets, reinjectedPacket{flow: flow, packet: copyPacket})
	return r.err
}

func TestControllerHandshakeSendsControlAndReinjectsFirstPacketOnce(t *testing.T) {
	engine, _ := testEngine(t, nil)
	sender := &fakeControlSender{}
	reinjector := &fakePacketReinjector{}
	controller, err := NewController(engine, sender, reinjector)
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
	if len(sender.sent) != 1 || sender.sent[0].wgID != 77 || sender.sent[0].control.Flags != FlagSYN {
		t.Fatalf("sent control=%#v", sender.sent)
	}
	if len(reinjector.packets) != 0 {
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
	if len(sender.sent) != 2 || sender.sent[1].wgID != 77 || sender.sent[1].control.Flags != FlagACK {
		t.Fatalf("sent control=%#v", sender.sent)
	}
	if len(reinjector.packets) != 1 {
		t.Fatalf("reinjected packets=%#v", reinjector.packets)
	}
	got := reinjector.packets[0]
	if got.flow != flow || got.packet.FWMark != 0x1234 || got.packet.WGID != 77 || !bytes.Equal(got.packet.Data, wantPacket) {
		t.Fatalf("reinjected packet=%#v", got)
	}

	// A duplicate completion cannot release the packet a second time.
	if _, err := controller.HandleSample(context.Background(), synACK); err != nil {
		t.Fatal(err)
	}
	if len(reinjector.packets) != 1 {
		t.Fatalf("first packet was reinjected %d times", len(reinjector.packets))
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
	sender := &fakeControlSender{}
	reinjector := &fakePacketReinjector{err: errors.New("injected failure")}
	controller, err := NewController(engine, sender, reinjector)
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
	if len(reinjector.packets) != 1 {
		t.Fatalf("reinjection attempts=%d, want 1", len(reinjector.packets))
	}
	if _, err := controller.HandleSample(context.Background(), synACK); err != nil {
		t.Fatal(err)
	}
	if len(reinjector.packets) != 1 {
		t.Fatalf("failed packet was retried, attempts=%d", len(reinjector.packets))
	}
}

func TestControllerAttemptsEveryReleasedPacketOnce(t *testing.T) {
	engine, _ := testEngine(t, nil)
	sender := &fakeControlSender{}
	reinjector := &fakePacketReinjector{err: errors.New("injected failure")}
	controller, err := NewController(engine, sender, reinjector)
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
	if len(reinjector.packets) != 2 || reinjector.packets[0].packet.FWMark != 1 || reinjector.packets[1].packet.FWMark != 2 {
		t.Fatalf("reinjection attempts=%#v", reinjector.packets)
	}
}

func TestControllerStopsReleaseWhenControlSendFails(t *testing.T) {
	engine, _ := testEngine(t, nil)
	sender := &fakeControlSender{}
	reinjector := &fakePacketReinjector{}
	controller, err := NewController(engine, sender, reinjector)
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
	sender.err = errors.New("send failure")
	synACK := testEventSample(abi.FakeTCPEvent{
		Key: flow, Sequence: 99, Acknowledgement: 1001, WGID: 4,
		Type: abi.FakeTCPEventSYNACK, TCPFlags: FlagSYN | FlagACK,
	}, nil, false)
	if _, err := controller.HandleSample(context.Background(), synACK); err == nil {
		t.Fatal("control send error was not propagated")
	}
	if len(reinjector.packets) != 0 {
		t.Fatal("packet was released after the prerequisite ACK send failed")
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
