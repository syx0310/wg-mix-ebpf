package faketcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"strings"
	"testing"
	"time"
)

func TestProductionOwnedCaptureTransfersOneDecodedPacketToEngine(t *testing.T) {
	engine, _ := testEngine(t, nil)
	firstSample := testProductionPacketSample(t, 1, 1)
	secondSample := testProductionPacketSample(t, 1, 2)
	secondSample[len(secondSample)-1] ^= 0x5a
	reader, err := newProductionEventReader(
		&fakeEventReader{records: []EventRecord{
			{RawSample: firstSample},
			{RawSample: secondSample},
		}},
		engine.Identity(),
		4,
		&memoryEventLossCounter{},
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	backend := &fakeControllerBackend{}
	controller, err := NewController(engine, backend)
	if err != nil {
		t.Fatal(err)
	}

	first, err := reader.Read()
	if err != nil {
		t.Fatal(err)
	}
	assertOwnedCaptureRecord(t, first, firstSample)
	firstPacket := append([]byte(nil), first.ownedSample.Packet...)
	firstPointer := &first.ownedSample.Packet[0]
	if _, err := controller.handleOwnedEvent(context.Background(), first.ownedSample); err != nil {
		t.Fatal(err)
	}
	s := engine.sessions[first.ownedSample.Event.Key]
	if s == nil || len(s.pending) != 1 || &s.pending[0].Data[0] != firstPointer ||
		s.pending[0].CaptureFingerprint != first.ownedSample.Fingerprint {
		t.Fatalf("first owned packet was copied or not queued: session=%#v", s)
	}

	second, err := reader.Read()
	if err != nil {
		t.Fatal(err)
	}
	assertOwnedCaptureRecord(t, second, secondSample)
	secondPointer := &second.ownedSample.Packet[0]
	if secondPointer == firstPointer {
		t.Fatal("successive owned records alias one sample allocation")
	}
	if _, err := controller.handleOwnedEvent(context.Background(), second.ownedSample); err != nil {
		t.Fatal(err)
	}
	if len(s.pending) != 2 || &s.pending[1].Data[0] != secondPointer {
		t.Fatalf("second owned packet was copied or not queued: pending=%d", len(s.pending))
	}
	if !bytes.Equal(s.pending[0].Data, firstPacket) {
		t.Fatal("a later Read or checksum materialization changed the first owned packet")
	}
}

func TestOwnedEventRuntimeDoesNotFallbackToRawSampleDecoder(t *testing.T) {
	engine, _ := testEngine(t, nil)
	backend := &fakeControllerBackend{}
	controller, err := NewController(engine, backend)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := newOwnedEventRuntime(
		&fakeEventReader{records: []EventRecord{{
			RawSample: testProductionPacketSample(t, 1, 1),
		}}},
		controller,
		EventRuntimeOptions{PollInterval: time.Millisecond, TickInterval: time.Second},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := runtime.Close(); err != nil {
			t.Errorf("Close error: %v", err)
		}
	})
	err = runtime.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "returned no owned sample") {
		t.Fatalf("owned runtime raw fallback error=%v", err)
	}
	if len(backend.sent) != 0 || len(backend.packets) != 0 {
		t.Fatalf("raw-only record reached controller: backend=%#v", backend)
	}
}

func TestProductionEventReaderRestartFailsClosedOnMidstreamCapture(t *testing.T) {
	reader, err := newProductionEventReader(
		&fakeEventReader{records: []EventRecord{{
			RawSample: testProductionPacketSample(t, 1, 2),
		}}},
		testRuntimeIdentity(1),
		4,
		&memoryEventLossCounter{},
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	record, err := reader.Read()
	if err != nil {
		t.Fatal(err)
	}
	if record.LostSamples != 1 || record.hasOwnedSample || len(record.RawSample) != 0 {
		t.Fatalf("fresh reader adopted midstream capture: record=%#v", record)
	}
}

func TestOwnedCaptureFingerprintSurvivesCheckpointReload(t *testing.T) {
	engine, _ := testEngine(t, nil)
	sample := testProductionPacketSample(t, 1, 1)
	reader, err := newProductionEventReader(
		&fakeEventReader{records: []EventRecord{{RawSample: sample}}},
		engine.Identity(),
		4,
		&memoryEventLossCounter{},
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	controller, err := NewController(engine, &fakeControllerBackend{})
	if err != nil {
		t.Fatal(err)
	}
	record, err := reader.Read()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.handleOwnedEvent(context.Background(), record.ownedSample); err != nil {
		t.Fatal(err)
	}
	flow := record.ownedSample.Event.Key
	packet := engine.sessions[flow].pending[0]
	want := sha256.Sum256(sample)
	if packet.CaptureFingerprint != want {
		t.Fatalf("checkpoint input fingerprint=%x want exact sample digest=%x", packet.CaptureFingerprint, want)
	}
	steps, err := actionSteps([]Action{{
		Kind: ActionReleasePending, Flow: flow,
		Packets: []PendingPacket{packet}, Reason: "fingerprint-reload",
	}})
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemoryActionCheckpointStore()
	created, err := store.CreateActionCheckpoint(ActionCheckpoint{
		Operation: 1, Identity: testRuntimeIdentity(1),
		Phase: ActionCheckpointPrepared, Steps: steps,
	})
	if err != nil {
		t.Fatal(err)
	}
	transitionedRevision, err := store.TransitionActionCheckpoint(
		created.Revision,
		ActionCheckpointAttempting,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	packet.CaptureFingerprint[0] ^= 0xff
	loaded, found, err := store.LoadActionCheckpoint()
	if err != nil || !found {
		t.Fatalf("checkpoint reload found=%t err=%v", found, err)
	}
	if loaded.Revision != transitionedRevision || loaded.Steps[0].Packet.CaptureFingerprint != want {
		t.Fatalf("checkpoint fingerprint=%x want=%x", loaded.Steps[0].Packet.CaptureFingerprint, want)
	}
}

func assertOwnedCaptureRecord(t *testing.T, record EventRecord, sample []byte) {
	t.Helper()
	if record.LostSamples != 0 || !record.hasOwnedSample {
		t.Fatalf("record has no owned sample: %#v", record)
	}
	packet := record.ownedSample.Packet
	if len(packet) == 0 || cap(packet) != len(packet) {
		t.Fatalf("owned packet length/capacity=%d/%d", len(packet), cap(packet))
	}
	if &packet[0] != &record.RawSample[fakeTCPEventSize] {
		t.Fatal("decoded packet does not use the record-owned sample allocation")
	}
	if record.ownedSample.Fingerprint != sha256.Sum256(sample) {
		t.Fatalf("owned fingerprint=%x want=%x", record.ownedSample.Fingerprint, sha256.Sum256(sample))
	}
}
