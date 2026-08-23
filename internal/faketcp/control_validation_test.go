package faketcp

import (
	"encoding/binary"
	"strings"
	"sync"
	"testing"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

func TestEstablishedCloseRequiresFullPacketValidation(t *testing.T) {
	engine, store, flow, state := establishedControlTestSession(t)
	segment := Segment{
		Flags:           FlagRST | FlagACK,
		Sequence:        state.RXSequence,
		Acknowledgement: state.TXSequence,
	}
	actions, err := engine.Inbound(flow, segment)
	if err != nil || len(actions) != 1 || actions[0].Reason != "unvalidated-close" {
		t.Fatalf("unvalidated close actions=%#v err=%v", actions, err)
	}
	if _, found := store.values[flow]; !found || store.deleteAttempts != 0 {
		t.Fatalf("unvalidated close reached established delete: found=%t attempts=%d", found, store.deleteAttempts)
	}
}

func TestValidateIPv4TCPControlRejectsEveryDestructiveFieldMismatch(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]byte, abi.FakeTCPSessionValue)
		want   string
	}{
		{
			name: "bad IPv4 checksum",
			mutate: func(packet []byte, _ abi.FakeTCPSessionValue) {
				packet[8]++
			},
			want: "IPv4 checksum",
		},
		{
			name: "bad TCP checksum",
			mutate: func(packet []byte, _ abi.FakeTCPSessionValue) {
				packet[36] ^= 1
			},
			want: "TCP checksum",
		},
		{
			name: "reverse address mismatch",
			mutate: func(packet []byte, _ abi.FakeTCPSessionValue) {
				packet[12] ^= 1
				setTCPChecksum(packet)
				setIPv4Checksum(packet)
			},
			want: "endpoints",
		},
		{
			name: "reverse port mismatch",
			mutate: func(packet []byte, _ abi.FakeTCPSessionValue) {
				binary.BigEndian.PutUint16(packet[20:22], binary.BigEndian.Uint16(packet[20:22])+1)
				setTCPChecksum(packet)
			},
			want: "ports",
		},
		{
			name: "RST without ACK",
			mutate: func(packet []byte, _ abi.FakeTCPSessionValue) {
				packet[33] = FlagRST
				setTCPChecksum(packet)
			},
			want: "flags",
		},
		{
			name: "RST and FIN",
			mutate: func(packet []byte, _ abi.FakeTCPSessionValue) {
				packet[33] = FlagRST | FlagFIN | FlagACK
				setTCPChecksum(packet)
			},
			want: "flags",
		},
		{
			name: "unexpected PSH",
			mutate: func(packet []byte, _ abi.FakeTCPSessionValue) {
				packet[33] = FlagFIN | FlagACK | FlagPSH
				setTCPChecksum(packet)
			},
			want: "flags",
		},
		{
			name: "non-exact sequence",
			mutate: func(packet []byte, state abi.FakeTCPSessionValue) {
				binary.BigEndian.PutUint32(packet[24:28], state.RXSequence+1)
				setTCPChecksum(packet)
			},
			want: "sequence",
		},
		{
			name: "non-exact acknowledgement",
			mutate: func(packet []byte, state abi.FakeTCPSessionValue) {
				binary.BigEndian.PutUint32(packet[28:32], state.TXSequence-1)
				setTCPChecksum(packet)
			},
			want: "acknowledgement",
		},
		{
			name: "non-exact window",
			mutate: func(packet []byte, state abi.FakeTCPSessionValue) {
				binary.BigEndian.PutUint16(packet[34:36], state.Window-1)
				setTCPChecksum(packet)
			},
			want: "window",
		},
		{
			name: "TCP reserved bit",
			mutate: func(packet []byte, _ abi.FakeTCPSessionValue) {
				packet[32] |= 1
				setTCPChecksum(packet)
			},
			want: "header length",
		},
		{
			name: "urgent pointer",
			mutate: func(packet []byte, _ abi.FakeTCPSessionValue) {
				binary.BigEndian.PutUint16(packet[38:40], 1)
				setTCPChecksum(packet)
			},
			want: "urgent",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			engine, store, flow, state := establishedControlTestSession(t)
			packet := buildIPv4TCPControl(flow, state, FlagRST|FlagACK)
			test.mutate(packet, state)
			event := closeValidationEvent(flow, state, FlagRST|FlagACK, 7, engine.Identity())
			validationErr := validateIPv4TCPControl(packet, event, state)
			if validationErr == nil || !strings.Contains(validationErr.Error(), test.want) {
				t.Fatalf("validation error=%v, want %q", validationErr, test.want)
			}
			if _, found := store.values[flow]; !found || store.deleteAttempts != 0 {
				t.Fatalf("invalid close touched session: found=%t attempts=%d", found, store.deleteAttempts)
			}
		})
	}
}

func TestValidatedRSTAndFINDeleteOnlyExactSession(t *testing.T) {
	for _, flags := range []uint8{FlagRST | FlagACK, FlagFIN | FlagACK} {
		t.Run(controlFlagName(flags), func(t *testing.T) {
			engine, store, flow, state := establishedControlTestSession(t)
			event, packet := capturedCloseEvent(engine, flow, state, flags, 7)
			actions, err := engine.InboundCapturedControl(event, packet)
			if err != nil || len(actions) != 1 || actions[0].Reason != "peer-close" {
				t.Fatalf("validated close actions=%#v err=%v", actions, err)
			}
			if _, found := store.values[flow]; found || store.deleteAttempts != 1 {
				t.Fatalf("validated close result: found=%t attempts=%d", found, store.deleteAttempts)
			}
		})
	}
}

func TestValidZeroTCPChecksumFieldIsAcceptedByResidual(t *testing.T) {
	flow := testFlow(31001)
	identity := testRuntimeIdentity(flow.Generation)
	state := abi.FakeTCPSessionValue{
		Generation:         flow.Generation,
		TXSequence:         1001,
		RXSequence:         9001,
		LocalISN:           1000,
		RemoteISN:          9000,
		Window:             65535,
		State:              abi.FakeTCPStateEstablished,
		Revision:           1,
		SessionID:          1,
		RuntimeIncarnation: [16]byte{1},
	}
	for attempts := 0; attempts <= 0xffff; attempts++ {
		packet := buildIPv4TCPControl(flow, state, FlagRST|FlagACK)
		if packet[36] == 0 && packet[37] == 0 {
			event := closeValidationEvent(flow, state, FlagRST|FlagACK, 7, identity)
			if err := validateIPv4TCPControl(packet, event, state); err != nil {
				t.Fatalf("valid zero TCP checksum field rejected: %v", err)
			}
			return
		}
		state.RXSequence++
	}
	t.Fatal("failed to construct a mathematically valid TCP checksum value zero")
}

func TestCapturedCloseIsBoundToRuntimeIncarnation(t *testing.T) {
	first, _, flow, state := establishedControlTestSession(t)
	event, packet := capturedCloseEvent(first, flow, state, FlagRST|FlagACK, 7)
	second, secondStore, secondFlow, secondState := establishedControlTestSession(t)
	second.identity.Incarnation[0] = 2
	if secondFlow != flow || secondState != state {
		t.Fatal("test engines did not create the same generation/flow/session state")
	}
	actions, err := second.InboundCapturedControl(event, packet)
	if err == nil || len(actions) != 0 {
		t.Fatalf("cross-incarnation close actions=%#v err=%v", actions, err)
	}
	if _, found := secondStore.values[flow]; !found || secondStore.deleteAttempts != 0 {
		t.Fatalf("cross-incarnation token touched session: found=%t attempts=%d", found, secondStore.deleteAttempts)
	}
}

func TestCapturedCloseRequiresExistingFastSession(t *testing.T) {
	engine, store, flow, state := establishedControlTestSession(t)
	event, packet := capturedCloseEvent(engine, flow, state, FlagRST|FlagACK, 7)
	delete(store.values, flow)
	actions, err := engine.InboundCapturedControl(event, packet)
	if err != nil || len(actions) != 1 || actions[0].Kind != ActionDrop ||
		actions[0].Reason != "fast-session-missing" {
		t.Fatalf("missing fast session actions=%#v err=%v", actions, err)
	}
	if engine.sessions[flow] == nil {
		t.Fatal("missing fast session tore down slow state")
	}
	if store.deleteAttempts != 0 {
		t.Fatalf("missing fast session attempted delete %d times", store.deleteAttempts)
	}
}

func TestCapturedCloseCannotTearDownAnotherFlow(t *testing.T) {
	engine, store, flow, state := establishedControlTestSession(t)
	otherFlow := testFlow(31002)
	otherFlow.WGID = 8
	if _, err := engine.outbound(otherFlow, PendingPacket{Data: []byte{2}, WGID: 8}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.InboundWithWGID(
		otherFlow,
		Segment{Flags: FlagSYN | FlagACK, Sequence: 9000, Acknowledgement: 2001},
		8,
	); err != nil {
		t.Fatal(err)
	}
	event, packet := capturedCloseEvent(engine, flow, state, FlagRST|FlagACK, 7)
	event.Key, event.WGID = otherFlow, 8
	actions, err := engine.InboundCapturedControl(event, packet)
	if err != nil || len(actions) != 1 || actions[0].Reason != "invalid-close-control" {
		t.Fatalf("cross-flow close actions=%#v err=%v", actions, err)
	}
	if _, found := store.values[flow]; !found {
		t.Fatal("cross-flow close removed its source session")
	}
	if _, found := store.values[otherFlow]; !found || store.deleteAttempts != 0 {
		t.Fatalf("cross-flow close touched target: found=%t attempts=%d", found, store.deleteAttempts)
	}
}

func TestCapturedCloseRejectsEventFromOlderRevision(t *testing.T) {
	engine, store, flow, state := establishedControlTestSession(t)
	event, packet := capturedCloseEvent(engine, flow, state, FlagRST|FlagACK, 7)
	advanced := state
	advanced.LastSeenNanos++
	advanced.Revision++
	store.values[flow] = advanced

	actions, err := engine.InboundCapturedControl(event, packet)
	if err != nil || len(actions) != 1 || actions[0].Reason != "invalid-close-control" {
		t.Fatalf("stale-revision close actions=%#v err=%v", actions, err)
	}
	if got, found := store.values[flow]; !found || got != advanced || store.deleteAttempts != 0 {
		t.Fatalf("stale-revision close changed current state: found=%t value=%#v attempts=%d", found, got, store.deleteAttempts)
	}
}

func TestCapturedCloseRejectsEventFromReplacedSession(t *testing.T) {
	engine, store, flow, old := establishedControlTestSession(t)
	event, packet := capturedCloseEvent(engine, flow, old, FlagFIN|FlagACK, 7)
	delete(store.values, flow)
	engine.remove(flow, engine.sessions[flow])
	engine.opts.InitialSequence = func() uint32 { return old.LocalISN }
	if _, err := engine.outbound(flow, PendingPacket{Data: []byte{2}, WGID: 7}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.InboundWithWGID(
		flow,
		Segment{Flags: FlagSYN | FlagACK, Sequence: old.RemoteISN, Acknowledgement: old.LocalISN + 1},
		7,
	); err != nil {
		t.Fatal(err)
	}
	replacement := store.values[flow]
	if replacement.SessionID == old.SessionID || replacement.TXSequence != old.TXSequence ||
		replacement.RXSequence != old.RXSequence || replacement.Window != old.Window {
		t.Fatalf("replacement session did not isolate only its identity: old=%#v new=%#v", old, replacement)
	}

	actions, err := engine.InboundCapturedControl(event, packet)
	if err != nil || len(actions) != 1 || actions[0].Reason != "invalid-close-control" {
		t.Fatalf("replaced-session close actions=%#v err=%v", actions, err)
	}
	if got, found := store.values[flow]; !found || got != replacement || store.deleteAttempts != 0 {
		t.Fatalf("replaced-session close changed current state: found=%t value=%#v attempts=%d", found, got, store.deleteAttempts)
	}
}

func TestValidatedCloseCannotDeleteAdvancedBPFState(t *testing.T) {
	engine, store, flow, state := establishedControlTestSession(t)
	event, packet := capturedCloseEvent(engine, flow, state, FlagRST|FlagACK, 7)
	advanced := state
	advanced.RXSequence++
	store.beforeDelete = func(key abi.FakeTCPSessionKey) { store.values[key] = advanced }
	actions, err := engine.InboundCapturedControl(event, packet)
	if err != nil || len(actions) != 1 || actions[0].Reason != "fast-session-raced" {
		t.Fatalf("raced close actions=%#v err=%v", actions, err)
	}
	if store.values[flow] != advanced || store.deleteAttempts != 1 {
		t.Fatal("validated close deleted state that advanced after validation")
	}
}

func TestValidatedCloseReplayAndConcurrencyDeleteAtMostOnce(t *testing.T) {
	engine, store, flow, state := establishedControlTestSession(t)
	event, packet := capturedCloseEvent(engine, flow, state, FlagFIN|FlagACK, 7)
	const workers = 32
	var wait sync.WaitGroup
	results := make(chan []Action, workers)
	errorsSeen := make(chan error, workers)
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			actions, inboundErr := engine.InboundCapturedControl(event, packet)
			results <- actions
			errorsSeen <- inboundErr
		}()
	}
	wait.Wait()
	close(results)
	close(errorsSeen)
	for inboundErr := range errorsSeen {
		if inboundErr != nil {
			t.Fatal(inboundErr)
		}
	}
	closed := 0
	for actions := range results {
		if len(actions) != 1 {
			t.Fatalf("concurrent close actions=%#v", actions)
		}
		if actions[0].Reason == "peer-close" {
			closed++
		} else if actions[0].Reason != "unknown-close" {
			t.Fatalf("unexpected concurrent close reason %q", actions[0].Reason)
		}
	}
	if closed != 1 || store.deleteAttempts != 1 {
		t.Fatalf("peer closes=%d compare-delete attempts=%d, want one each", closed, store.deleteAttempts)
	}
}

func TestCloseValidationBitFlipCorpusFailsClosed(t *testing.T) {
	engine, _, flow, state := establishedControlTestSession(t)
	valid := buildIPv4TCPControl(flow, state, FlagRST|FlagACK)
	for byteIndex := range valid {
		for bit := uint8(1); bit != 0; bit <<= 1 {
			candidate := append([]byte(nil), valid...)
			candidate[byteIndex] ^= bit
			event := closeValidationEvent(flow, state, FlagRST|FlagACK, 7, engine.Identity())
			if err := validateIPv4TCPControl(candidate, event, state); err == nil {
				t.Fatalf("single bit mutation accepted at byte=%d bit=%#x", byteIndex, bit)
			}
		}
	}
}

func BenchmarkValidateIPv4TCPControl(b *testing.B) {
	flow := testFlow(31001)
	state := abi.FakeTCPSessionValue{
		Generation:         flow.Generation,
		TXSequence:         1001,
		RXSequence:         9001,
		LocalISN:           1000,
		RemoteISN:          9000,
		Window:             65535,
		State:              abi.FakeTCPStateEstablished,
		Revision:           1,
		SessionID:          1,
		RuntimeIncarnation: [16]byte{1},
	}
	identity := testRuntimeIdentity(flow.Generation)
	packet := buildIPv4TCPControl(flow, state, FlagRST|FlagACK)
	event := closeValidationEvent(flow, state, FlagRST|FlagACK, 7, identity)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if err := validateIPv4TCPControl(packet, event, state); err != nil {
			b.Fatal(err)
		}
	}
}

func establishedControlTestSession(t *testing.T) (*Engine, *fakeSessionStore, abi.FakeTCPSessionKey, abi.FakeTCPSessionValue) {
	t.Helper()
	store := newFakeSessionStore()
	engine, _ := testEngine(t, func(options *Options) { options.Store = store })
	flow := testFlow(31001)
	if _, err := engine.outbound(flow, PendingPacket{Data: []byte{1}, WGID: 7}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.InboundWithWGID(
		flow,
		Segment{Flags: FlagSYN | FlagACK, Sequence: 9000, Acknowledgement: 1001},
		7,
	); err != nil {
		t.Fatal(err)
	}
	state, found := store.values[flow]
	if !found {
		t.Fatal("test handshake did not establish BPF state")
	}
	return engine, store, flow, state
}

func buildIPv4TCPControl(flow abi.FakeTCPSessionKey, state abi.FakeTCPSessionValue, flags uint8) []byte {
	packet := make([]byte, controlPacketLength)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 6
	binary.NativeEndian.PutUint32(packet[12:16], flow.RemoteIPv4)
	binary.NativeEndian.PutUint32(packet[16:20], flow.LocalIPv4)
	binary.BigEndian.PutUint16(packet[20:22], flow.RemotePort)
	binary.BigEndian.PutUint16(packet[22:24], flow.LocalPort)
	binary.BigEndian.PutUint32(packet[24:28], state.RXSequence)
	binary.BigEndian.PutUint32(packet[28:32], state.TXSequence)
	packet[32] = 5 << 4
	packet[33] = flags
	binary.BigEndian.PutUint16(packet[34:36], state.Window)
	setTCPChecksum(packet)
	setIPv4Checksum(packet)
	return packet
}

func capturedCloseEvent(
	engine *Engine,
	flow abi.FakeTCPSessionKey,
	state abi.FakeTCPSessionValue,
	flags uint8,
	wgID uint32,
) (abi.FakeTCPEvent, []byte) {
	packet := buildIPv4TCPControl(flow, state, flags)
	event := closeValidationEvent(flow, state, flags, wgID, engine.Identity())
	return event, packet
}

func closeValidationEvent(
	flow abi.FakeTCPSessionKey,
	state abi.FakeTCPSessionValue,
	flags uint8,
	wgID uint32,
	identity RuntimeIdentity,
) abi.FakeTCPEvent {
	eventType := abi.FakeTCPEventRST
	if flags == FlagFIN|FlagACK {
		eventType = abi.FakeTCPEventFIN
	}
	event := abi.FakeTCPEvent{
		Key:             flow,
		SessionRevision: state.Revision,
		SessionID:       state.SessionID,
		Sequence:        state.RXSequence,
		Acknowledgement: state.TXSequence,
		WGID:            wgID,
		PacketLength:    controlPacketLength,
		Type:            eventType,
		TCPFlags:        flags,
	}
	bindTestEvent(&event, identity, 0)
	return event
}

func setIPv4Checksum(packet []byte) {
	packet[10], packet[11] = 0, 0
	binary.BigEndian.PutUint16(packet[10:12], finishChecksum(addChecksumBytes(0, packet[:20])))
}

func setTCPChecksum(packet []byte) {
	packet[36], packet[37] = 0, 0
	var pseudo [12]byte
	copy(pseudo[:8], packet[12:20])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(packet)-20))
	sum := addChecksumBytes(0, pseudo[:])
	sum = addChecksumBytes(sum, packet[20:])
	binary.BigEndian.PutUint16(packet[36:38], finishChecksum(sum))
}
