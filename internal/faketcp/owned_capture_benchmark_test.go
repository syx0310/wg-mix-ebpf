package faketcp

import (
	"context"
	"testing"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

func BenchmarkControllerCapturedEstablishedDuplicate(b *testing.B) {
	_, controller, sample := benchmarkEstablishedCaptureController(b)
	if _, err := controller.HandleSample(context.Background(), sample); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(sample)))
	b.ResetTimer()
	for range b.N {
		if _, err := controller.HandleSample(context.Background(), sample); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkProductionOwnedCaptureEstablishedDuplicate(b *testing.B) {
	engine, controller, sample := benchmarkEstablishedCaptureController(b)
	reader, err := newProductionEventReader(
		repeatingEventReader{sample: sample},
		engine.Identity(),
		4,
		&memoryEventLossCounter{},
		0,
	)
	if err != nil {
		b.Fatal(err)
	}
	first, err := reader.Read()
	if err != nil {
		b.Fatal(err)
	}
	if _, err := controller.handleOwnedEvent(context.Background(), first.ownedSample); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(sample)))
	b.ResetTimer()
	for range b.N {
		record, err := reader.Read()
		if err != nil {
			b.Fatal(err)
		}
		if _, err := controller.handleOwnedEvent(context.Background(), record.ownedSample); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEngineRetainPendingPacket(b *testing.B) {
	for _, test := range []struct {
		name  string
		owned bool
	}{
		{name: "borrowed", owned: false},
		{name: "owned", owned: true},
	} {
		b.Run(test.name, func(b *testing.B) {
			engine := &Engine{opts: Options{
				MaxPendingFlows: 1, MaxPendingPacketsPerFlow: 1, MaxPendingBytes: 2048,
			}}
			s := &session{pending: make([]PendingPacket, 0, 1)}
			packet := PendingPacket{Data: make([]byte, 1280), dataOwned: test.owned}
			b.ReportAllocs()
			b.SetBytes(int64(len(packet.Data)))
			b.ResetTimer()
			for range b.N {
				engine.pendingFlows = 0
				engine.pendingBytes = 0
				s.pending = s.pending[:0]
				s.pendingBytes = 0
				if !engine.enqueue(s, packet) {
					b.Fatal("packet rejected")
				}
			}
		})
	}
}

func BenchmarkOnceReinjectorExactDuplicate(b *testing.B) {
	flow := testFlow(31001)
	packet := testPendingPacket(b, flow, 1)
	writer := &memoryRawIPv4Writer{}
	reinjector, err := newOnceReinjector(writer, packet.CaptureID.Runtime, 4)
	if err != nil {
		b.Fatal(err)
	}
	if err := reinjector.Reinject(context.Background(), flow, packet); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(packet.Data)))
	b.ResetTimer()
	for range b.N {
		if err := reinjector.Reinject(context.Background(), flow, packet); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkEstablishedCaptureController(b *testing.B) (*Engine, *Controller, []byte) {
	b.Helper()
	engine, _ := testEngine(b, nil)
	flow := testFlow(31001)
	if _, err := engine.outbound(flow, PendingPacket{Data: []byte{9}, WGID: 77}, false); err != nil {
		b.Fatal(err)
	}
	if _, err := engine.InboundWithWGID(
		flow,
		Segment{Flags: FlagSYN | FlagACK, Sequence: 9000, Acknowledgement: 1001},
		77,
	); err != nil {
		b.Fatal(err)
	}

	packet := testIPv4UDPPacket(b, flow, []byte{1, 2, 3, 4, 5})
	event := abi.FakeTCPEvent{
		Key: flow, PayloadLength: 5, FWMark: 0xa1230007, WGID: 77,
		PacketLength: uint16(len(packet)), Type: abi.FakeTCPEventNeedHandshake,
	}
	bindTestEvent(&event, engine.Identity(), 1)
	sample := testBoundEventSample(event, packet, false)

	writer := &memoryRawIPv4Writer{}
	backend, err := NewRawControllerBackend(RawControllerBackendOptions{
		Writer: writer,
		ControlMarks: ControlMarkResolverFunc(func(
			context.Context,
			abi.FakeTCPSessionKey,
			uint32,
		) (uint32, error) {
			return 9, nil
		}),
		RuntimeIdentity: engine.Identity(), MaxReinjectStreams: 4,
	})
	if err != nil {
		b.Fatal(err)
	}
	controller, err := NewController(engine, backend)
	if err != nil {
		b.Fatal(err)
	}
	return engine, controller, sample
}
