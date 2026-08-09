package faketcp

import (
	"encoding/binary"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

type memoryEventLossCounter struct {
	mu    sync.Mutex
	count uint64
	err   error
}

func (counter *memoryEventLossCounter) Count() (uint64, error) {
	counter.mu.Lock()
	defer counter.mu.Unlock()
	return counter.count, counter.err
}

func (counter *memoryEventLossCounter) set(count uint64) {
	counter.mu.Lock()
	counter.count = count
	counter.mu.Unlock()
}

func testProductionPacketSample(t testing.TB, cpu uint32, sequence uint64) []byte {
	t.Helper()
	flow := testFlow(31001)
	packet := make([]byte, 20+8+3)
	packet[0], packet[8], packet[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	binary.NativeEndian.PutUint32(packet[12:16], flow.LocalIPv4)
	binary.NativeEndian.PutUint32(packet[16:20], flow.RemoteIPv4)
	binary.BigEndian.PutUint16(packet[20:22], flow.LocalPort)
	binary.BigEndian.PutUint16(packet[22:24], flow.RemotePort)
	binary.BigEndian.PutUint16(packet[24:26], uint16(8+3))
	copy(packet[28:], []byte{1, 2, 3})
	if err := MaterializeIPv4UDPChecksums(packet); err != nil {
		t.Fatal(err)
	}
	event := abi.FakeTCPEvent{
		Key: flow, PayloadLength: 3, PacketLength: uint16(len(packet)),
		Type: abi.FakeTCPEventNeedHandshake, FWMark: 7, WGID: 9,
	}
	bindTestEvent(&event, testRuntimeIdentity(flow.Generation), sequence)
	event.CaptureCPU = cpu
	return testBoundEventSample(event, packet, false)
}

func TestProductionEventReaderMakesDuplicatesGapsAndReorderingExplicit(t *testing.T) {
	sequence1 := testProductionPacketSample(t, 1, 1)
	sequence2 := testProductionPacketSample(t, 1, 2)
	sequence3 := testProductionPacketSample(t, 1, 3)
	reader := &fakeEventReader{records: []EventRecord{
		{RawSample: sequence1},
		{RawSample: sequence1},
		{RawSample: sequence3},
		{RawSample: sequence2},
		{RawSample: sequence1},
	}}
	ordered, err := newProductionEventReader(
		reader,
		testRuntimeIdentity(1),
		4,
		&memoryEventLossCounter{},
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	for index := range 2 {
		record, err := ordered.Read()
		if err != nil || string(record.RawSample) != string(sequence1) {
			t.Fatalf("sequence-1 delivery %d record=%#v err=%v", index, record, err)
		}
	}
	record, err := ordered.Read()
	if err != nil || record.LostSamples != 1 || len(record.RawSample) != 0 {
		t.Fatalf("sequence gap record=%#v err=%v", record, err)
	}
	record, err = ordered.Read()
	if err != nil || string(record.RawSample) != string(sequence2) {
		t.Fatalf("gap did not leave sequence-2 admissible record=%#v err=%v", record, err)
	}
	if _, err := ordered.Read(); !errors.Is(err, ErrEventCaptureOutOfOrder) {
		t.Fatalf("out-of-order error=%v", err)
	}
}

func TestProductionEventReaderRejectsChangedDuplicateFingerprint(t *testing.T) {
	sample := testProductionPacketSample(t, 1, 1)
	changed := append([]byte(nil), sample...)
	changed[len(changed)-1] ^= 1
	reader := &fakeEventReader{records: []EventRecord{
		{RawSample: sample},
		{RawSample: changed},
	}}
	ordered, err := newProductionEventReader(
		reader,
		testRuntimeIdentity(1),
		4,
		&memoryEventLossCounter{},
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ordered.Read(); err != nil {
		t.Fatal(err)
	}
	if _, err := ordered.Read(); !errors.Is(err, ErrCaptureIdentityConflict) {
		t.Fatalf("changed duplicate error=%v", err)
	}
}

func TestProductionEventReaderReportsKernelLossOnIdleDeadline(t *testing.T) {
	losses := &memoryEventLossCounter{}
	reader := &fakeEventReader{errors: []error{os.ErrDeadlineExceeded}}
	ordered, err := newProductionEventReader(
		reader,
		testRuntimeIdentity(1),
		4,
		losses,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	losses.set(3)
	record, err := ordered.Read()
	if err != nil || record.LostSamples != 3 {
		t.Fatalf("kernel loss record=%#v err=%v", record, err)
	}
	reader.errors = []error{os.ErrDeadlineExceeded}
	record, err = ordered.Read()
	if !errors.Is(err, os.ErrDeadlineExceeded) || len(record.RawSample) != 0 || record.LostSamples != 0 {
		t.Fatalf("stable loss counter record=%#v err=%v", record, err)
	}
	losses.set(2)
	reader.errors = []error{os.ErrDeadlineExceeded}
	if _, err := ordered.Read(); err == nil {
		t.Fatal("decreasing kernel loss counter was accepted")
	}
}

func TestProductionEventReaderBindsRuntimeAndPossibleCPUs(t *testing.T) {
	wrongIdentity := testProductionPacketSample(t, 1, 1)
	wrongIdentity[32] ^= 0xff
	outOfRangeCPU := testProductionPacketSample(t, 4, 1)
	for _, test := range []struct {
		name   string
		sample []byte
	}{
		{name: "identity", sample: wrongIdentity},
		{name: "CPU", sample: outOfRangeCPU},
	} {
		t.Run(test.name, func(t *testing.T) {
			ordered, err := newProductionEventReader(
				&fakeEventReader{records: []EventRecord{{RawSample: test.sample}}},
				testRuntimeIdentity(1),
				4,
				&memoryEventLossCounter{},
				0,
			)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ordered.Read(); err == nil {
				t.Fatal("unbound event was accepted")
			}
		})
	}
}

type repeatingEventReader struct {
	sample []byte
}

func (reader repeatingEventReader) Read() (EventRecord, error) {
	return EventRecord{RawSample: reader.sample}, nil
}

func (repeatingEventReader) SetDeadline(time.Time) {}
func (repeatingEventReader) Close() error          { return nil }

func BenchmarkProductionEventReaderExactDuplicate(b *testing.B) {
	sample := testProductionPacketSample(b, 1, 1)
	reader, err := newProductionEventReader(
		repeatingEventReader{sample: sample},
		testRuntimeIdentity(1),
		4,
		&memoryEventLossCounter{},
		0,
	)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(sample)))
	for range b.N {
		if _, err := reader.Read(); err != nil {
			b.Fatal(err)
		}
	}
}
