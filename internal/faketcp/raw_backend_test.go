package faketcp

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

type memoryRawIPv4Writer struct {
	mu sync.Mutex

	writes      []RawIPv4Write
	writeErr    error
	closeErr    error
	closeCalls  int
	entered     chan struct{}
	release     <-chan struct{}
	enteredOnce sync.Once
	writeHook   func()
}

func (writer *memoryRawIPv4Writer) WriteIPv4(ctx context.Context, write RawIPv4Write) error {
	copyWrite := write
	copyWrite.Data = append([]byte(nil), write.Data...)
	writer.mu.Lock()
	writer.writes = append(writer.writes, copyWrite)
	hook := writer.writeHook
	writer.mu.Unlock()
	if hook != nil {
		hook()
	}
	if writer.entered != nil {
		writer.enteredOnce.Do(func() { close(writer.entered) })
	}
	if writer.release != nil {
		select {
		case <-writer.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return writer.writeErr
}

func (writer *memoryRawIPv4Writer) Close() error {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	writer.closeCalls++
	return writer.closeErr
}

func (writer *memoryRawIPv4Writer) snapshot() ([]RawIPv4Write, int) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	writes := make([]RawIPv4Write, len(writer.writes))
	for index, write := range writer.writes {
		writes[index] = write
		writes[index].Data = append([]byte(nil), write.Data...)
	}
	return writes, writer.closeCalls
}

func testPendingPacket(t *testing.T, flow abi.FakeTCPSessionKey, capture uint64) PendingPacket {
	t.Helper()
	data := testIPv4UDPPacket(t, flow, []byte{1, 2, 3, 4, 5})
	if err := MaterializeIPv4UDPChecksums(data); err != nil {
		t.Fatal(err)
	}
	return PendingPacket{
		Data: data, FWMark: 0xa1230007, WGID: 77, CaptureNanos: capture,
		CaptureID: CaptureIdentity{Runtime: testRuntimeIdentity(flow.Generation), CPU: 3, Sequence: capture},
	}
}

func TestRawControllerBackendSendsControlWithExplicitRouteMark(t *testing.T) {
	writer := &memoryRawIPv4Writer{}
	flow := testFlow(31001)
	var resolvedFlow abi.FakeTCPSessionKey
	var resolvedWGID uint32
	backend, err := NewRawControllerBackend(RawControllerBackendOptions{
		Writer: writer,
		ControlMarks: ControlMarkResolverFunc(func(_ context.Context, gotFlow abi.FakeTCPSessionKey, wgID uint32) (uint32, error) {
			resolvedFlow, resolvedWGID = gotFlow, wgID
			return 0xa1230009, nil
		}),
		MaxRememberedReinjections: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	control := ControlPacket{
		Flags: FlagSYN | FlagACK, Sequence: 100, Acknowledgement: 200, Window: 4096,
	}
	if err := backend.SendControl(context.Background(), flow, 77, control); err != nil {
		t.Fatal(err)
	}
	writes, _ := writer.snapshot()
	if resolvedFlow != flow || resolvedWGID != 77 {
		t.Fatalf("resolved flow=%#v wgID=%d", resolvedFlow, resolvedWGID)
	}
	if len(writes) != 1 || writes[0].UnderlayIndex != flow.UnderlayIndex || writes[0].FWMark != 0xa1230009 {
		t.Fatalf("raw writes=%#v", writes)
	}
	want, err := MarshalIPv4TCPControl(flow, control)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(writes[0].Data, want) || writes[0].Data[9] != 6 {
		t.Fatalf("control packet=%x want=%x", writes[0].Data, want)
	}
	if err := validateRawIPv4Write(writes[0]); err != nil {
		t.Fatalf("raw control write validation: %v", err)
	}
}

func TestRawControllerBackendReinjectsMaterializedPacketThroughOriginalMark(t *testing.T) {
	writer := &memoryRawIPv4Writer{}
	backend, err := NewRawControllerBackend(RawControllerBackendOptions{
		Writer: writer,
		ControlMarks: ControlMarkResolverFunc(func(context.Context, abi.FakeTCPSessionKey, uint32) (uint32, error) {
			return 0, nil
		}),
		MaxRememberedReinjections: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	flow := testFlow(31001)
	packet := testPendingPacket(t, flow, 123)
	if err := backend.Reinject(context.Background(), flow, packet); err != nil {
		t.Fatal(err)
	}
	writes, _ := writer.snapshot()
	if len(writes) != 1 || writes[0].UnderlayIndex != flow.UnderlayIndex ||
		writes[0].FWMark != packet.FWMark || !bytes.Equal(writes[0].Data, packet.Data) {
		t.Fatalf("raw writes=%#v", writes)
	}
	if err := validateRawIPv4Write(writes[0]); err != nil {
		t.Fatalf("raw reinjection validation: %v", err)
	}
}

func TestOnceReinjectorAttemptsExactIdentityOnlyOnce(t *testing.T) {
	wantErr := errors.New("ambiguous raw send failure")
	writer := &memoryRawIPv4Writer{writeErr: wantErr}
	reinjector, err := NewOnceReinjector(writer, 8)
	if err != nil {
		t.Fatal(err)
	}
	flow := testFlow(31001)
	packet := testPendingPacket(t, flow, 123)
	firstErr := reinjector.Reinject(context.Background(), flow, packet)
	secondErr := reinjector.Reinject(context.Background(), flow, packet)
	if !errors.Is(firstErr, wantErr) || !errors.Is(secondErr, wantErr) {
		t.Fatalf("attempt errors first=%v second=%v", firstErr, secondErr)
	}
	writes, _ := writer.snapshot()
	if len(writes) != 1 {
		t.Fatalf("raw attempts=%d, want one", len(writes))
	}
}

func TestOnceReinjectorUsesCaptureSequenceAndIncarnationNotTimestamp(t *testing.T) {
	writer := &memoryRawIPv4Writer{}
	reinjector, err := NewOnceReinjector(writer, 8)
	if err != nil {
		t.Fatal(err)
	}
	flow := testFlow(31001)
	first := testPendingPacket(t, flow, 1)
	first.CaptureNanos = 999
	second := first
	second.Data = append([]byte(nil), first.Data...)
	second.CaptureID.Sequence = 2
	third := first
	third.Data = append([]byte(nil), first.Data...)
	third.CaptureID.Runtime.Incarnation[0] = 2
	fourth := first
	fourth.Data = append([]byte(nil), first.Data...)
	fourth.CaptureID.CPU = 4
	for _, packet := range []PendingPacket{first, second, third, fourth} {
		if err := reinjector.Reinject(context.Background(), flow, packet); err != nil {
			t.Fatal(err)
		}
	}
	// Exact replay of each identity is coalesced independently.
	for _, packet := range []PendingPacket{first, second, third, fourth} {
		if err := reinjector.Reinject(context.Background(), flow, packet); err != nil {
			t.Fatal(err)
		}
	}
	writes, _ := writer.snapshot()
	if len(writes) != 4 {
		t.Fatalf("raw attempts=%d, want one per capture identity", len(writes))
	}
}

func TestOnceReinjectorRejectsCaptureIdentityReuseWithDifferentMetadata(t *testing.T) {
	writer := &memoryRawIPv4Writer{}
	reinjector, err := NewOnceReinjector(writer, 8)
	if err != nil {
		t.Fatal(err)
	}
	flow := testFlow(31001)
	packet := testPendingPacket(t, flow, 1)
	if err := reinjector.Reinject(context.Background(), flow, packet); err != nil {
		t.Fatal(err)
	}
	conflict := packet
	conflict.FWMark++
	if err := reinjector.Reinject(context.Background(), flow, conflict); !errors.Is(err, ErrCaptureIdentityConflict) {
		t.Fatalf("capture identity conflict error=%v", err)
	}
	writes, _ := writer.snapshot()
	if len(writes) != 1 {
		t.Fatalf("conflicting capture identity wrote %d packets", len(writes))
	}
}

func TestOnceReinjectorCoalescesConcurrentDuplicate(t *testing.T) {
	release := make(chan struct{})
	writer := &memoryRawIPv4Writer{entered: make(chan struct{}), release: release}
	reinjector, err := NewOnceReinjector(writer, 8)
	if err != nil {
		t.Fatal(err)
	}
	flow := testFlow(31001)
	packet := testPendingPacket(t, flow, 123)
	const callers = 16
	start := make(chan struct{})
	errs := make(chan error, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			errs <- reinjector.Reinject(context.Background(), flow, packet)
		}()
	}
	close(start)
	select {
	case <-writer.entered:
	case <-time.After(time.Second):
		t.Fatal("raw write did not start")
	}
	close(release)
	wait.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("coalesced error=%v", err)
		}
	}
	writes, _ := writer.snapshot()
	if len(writes) != 1 {
		t.Fatalf("concurrent raw attempts=%d, want one", len(writes))
	}
}

func TestOnceReinjectorBoundsLedgerAndValidatesBeforeClaim(t *testing.T) {
	writer := &memoryRawIPv4Writer{}
	reinjector, err := NewOnceReinjector(writer, 1)
	if err != nil {
		t.Fatal(err)
	}
	flow := testFlow(31001)
	missingIdentity := testPendingPacket(t, flow, 0)
	if err := reinjector.Reinject(context.Background(), flow, missingIdentity); err == nil {
		t.Fatal("zero capture identity was accepted")
	}
	invalid := testPendingPacket(t, flow, 1)
	invalid.Data[10] ^= 0xff
	if err := reinjector.Reinject(context.Background(), flow, invalid); err == nil {
		t.Fatal("invalid materialized packet was accepted")
	}
	if err := reinjector.Reinject(context.Background(), flow, testPendingPacket(t, flow, 1)); err != nil {
		t.Fatal(err)
	}
	if err := reinjector.Reinject(context.Background(), flow, testPendingPacket(t, flow, 2)); !errors.Is(err, ErrReinjectLedgerCapacity) {
		t.Fatalf("capacity error=%v", err)
	}
	writes, _ := writer.snapshot()
	if len(writes) != 1 {
		t.Fatalf("raw attempts=%d, want one", len(writes))
	}
}

func TestRawControllerBackendCloseWaitsForReinjectionAndClosesWriterOnce(t *testing.T) {
	release := make(chan struct{})
	writer := &memoryRawIPv4Writer{entered: make(chan struct{}), release: release}
	backend, err := NewRawControllerBackend(RawControllerBackendOptions{
		Writer: writer,
		ControlMarks: ControlMarkResolverFunc(func(context.Context, abi.FakeTCPSessionKey, uint32) (uint32, error) {
			return 0, nil
		}),
		MaxRememberedReinjections: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	flow := testFlow(31001)
	packet := testPendingPacket(t, flow, 123)
	reinjectDone := make(chan error, 1)
	go func() {
		reinjectDone <- backend.Reinject(context.Background(), flow, packet)
	}()
	select {
	case <-writer.entered:
	case <-time.After(time.Second):
		t.Fatal("reinjection did not enter writer")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- backend.Close() }()
	deadline := time.Now().Add(time.Second)
	for {
		backend.mu.Lock()
		closing := backend.closing
		backend.mu.Unlock()
		if closing {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("backend did not enter closing state")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case err := <-closeDone:
		t.Fatalf("Close returned before reinjection: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-reinjectDone; err != nil {
		t.Fatal(err)
	}
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	if err := backend.Close(); err != nil {
		t.Fatal(err)
	}
	_, closes := writer.snapshot()
	if closes != 1 {
		t.Fatalf("writer Close calls=%d", closes)
	}
	if err := backend.Reinject(context.Background(), flow, testPendingPacket(t, flow, 124)); !errors.Is(err, ErrRawBackendClosed) {
		t.Fatalf("post-close reinjection error=%v", err)
	}
}

func TestRawControllerBackendExternalCallsRunOutsideStateLock(t *testing.T) {
	writer := &memoryRawIPv4Writer{}
	var backend *RawControllerBackend
	assertUnlocked := func(stage string) {
		t.Helper()
		if !backend.mu.TryLock() {
			t.Fatalf("backend state lock held during %s", stage)
		}
		backend.mu.Unlock()
	}
	writer.writeHook = func() { assertUnlocked("raw write") }
	var err error
	backend, err = NewRawControllerBackend(RawControllerBackendOptions{
		Writer: writer,
		ControlMarks: ControlMarkResolverFunc(func(context.Context, abi.FakeTCPSessionKey, uint32) (uint32, error) {
			assertUnlocked("control mark resolution")
			return 9, nil
		}),
		MaxRememberedReinjections: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.SendControl(context.Background(), testFlow(31001), 77, ControlPacket{Flags: FlagSYN}); err != nil {
		t.Fatal(err)
	}
	if err := backend.Reinject(context.Background(), testFlow(31001), testPendingPacket(t, testFlow(31001), 1)); err != nil {
		t.Fatal(err)
	}
}

func TestRawControllerBackendCloseFencesAdmittedResolver(t *testing.T) {
	resolverEntered := make(chan struct{})
	resolverRelease := make(chan struct{})
	backend, err := NewRawControllerBackend(RawControllerBackendOptions{
		Writer: &memoryRawIPv4Writer{},
		ControlMarks: ControlMarkResolverFunc(func(context.Context, abi.FakeTCPSessionKey, uint32) (uint32, error) {
			close(resolverEntered)
			<-resolverRelease
			return 9, nil
		}),
		MaxRememberedReinjections: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	sendDone := make(chan error, 1)
	go func() {
		sendDone <- backend.SendControl(context.Background(), testFlow(31001), 77, ControlPacket{Flags: FlagSYN})
	}()
	select {
	case <-resolverEntered:
	case <-time.After(time.Second):
		t.Fatal("control mark resolver did not start")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- backend.Close() }()
	deadline := time.Now().Add(time.Second)
	for {
		backend.mu.Lock()
		closing := backend.closing
		backend.mu.Unlock()
		if closing {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("backend did not enter closing state")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case err := <-closeDone:
		t.Fatalf("Close returned before resolver: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if err := backend.SendControl(context.Background(), testFlow(31002), 77, ControlPacket{Flags: FlagSYN}); !errors.Is(err, ErrRawBackendClosed) {
		t.Fatalf("operation admitted while closing: %v", err)
	}
	close(resolverRelease)
	if err := <-sendDone; err != nil {
		t.Fatal(err)
	}
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
}

func TestRawControllerBackendFailsBeforeWriterOnMarkError(t *testing.T) {
	wantErr := errors.New("mark lookup failed")
	writer := &memoryRawIPv4Writer{}
	backend, err := NewRawControllerBackend(RawControllerBackendOptions{
		Writer: writer,
		ControlMarks: ControlMarkResolverFunc(func(context.Context, abi.FakeTCPSessionKey, uint32) (uint32, error) {
			return 0, wantErr
		}),
		MaxRememberedReinjections: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = backend.SendControl(context.Background(), testFlow(31001), 77, ControlPacket{Flags: FlagSYN})
	if !errors.Is(err, wantErr) {
		t.Fatalf("control error=%v", err)
	}
	writes, _ := writer.snapshot()
	if len(writes) != 0 {
		t.Fatal("mark failure reached writer")
	}
}

func TestRawControllerBackendConcurrentCloseRetainsWriterError(t *testing.T) {
	wantErr := errors.New("raw writer close failed")
	writer := &memoryRawIPv4Writer{closeErr: wantErr}
	backend, err := NewRawControllerBackend(RawControllerBackendOptions{
		Writer: writer,
		ControlMarks: ControlMarkResolverFunc(func(context.Context, abi.FakeTCPSessionKey, uint32) (uint32, error) {
			return 0, nil
		}),
		MaxRememberedReinjections: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	const callers = 16
	start := make(chan struct{})
	errs := make(chan error, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			errs <- backend.Close()
		}()
	}
	close(start)
	wait.Wait()
	close(errs)
	for err := range errs {
		if !errors.Is(err, wantErr) {
			t.Fatalf("Close error=%v", err)
		}
	}
	_, closes := writer.snapshot()
	if closes != 1 {
		t.Fatalf("writer Close calls=%d", closes)
	}
}

func TestNewRawControllerBackendRejectsNilResourcesAndCapacity(t *testing.T) {
	resolver := ControlMarkResolverFunc(func(context.Context, abi.FakeTCPSessionKey, uint32) (uint32, error) {
		return 0, nil
	})
	if _, err := NewRawControllerBackend(RawControllerBackendOptions{ControlMarks: resolver, MaxRememberedReinjections: 1}); err == nil {
		t.Fatal("nil writer accepted")
	}
	writer := &memoryRawIPv4Writer{}
	if _, err := NewRawControllerBackend(RawControllerBackendOptions{Writer: writer, MaxRememberedReinjections: 1}); err == nil {
		t.Fatal("nil resolver accepted")
	}
	if _, err := NewRawControllerBackend(RawControllerBackendOptions{Writer: writer, ControlMarks: resolver}); err == nil {
		t.Fatal("zero capacity accepted")
	}
	var typedNilWriter *memoryRawIPv4Writer
	if _, err := NewOnceReinjector(typedNilWriter, 1); err == nil {
		t.Fatal("typed-nil writer accepted")
	}
}

func TestValidateRawIPv4WriteRejectsCorruptionAndUnsupportedShape(t *testing.T) {
	flow := testFlow(31001)
	packet := testPendingPacket(t, flow, 1)
	valid := RawIPv4Write{Data: packet.Data, UnderlayIndex: flow.UnderlayIndex, FWMark: packet.FWMark}
	if err := validateRawIPv4Write(valid); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*RawIPv4Write)
	}{
		{name: "interface", mutate: func(write *RawIPv4Write) { write.UnderlayIndex = 0 }},
		{name: "ip checksum", mutate: func(write *RawIPv4Write) { write.Data[10] ^= 0xff }},
		{name: "transport checksum", mutate: func(write *RawIPv4Write) { write.Data[len(write.Data)-1] ^= 0xff }},
		{name: "protocol", mutate: func(write *RawIPv4Write) { write.Data[9] = 1 }},
		{name: "fragment", mutate: func(write *RawIPv4Write) { write.Data[6] = 0x20 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			write := valid
			write.Data = append([]byte(nil), valid.Data...)
			test.mutate(&write)
			if err := validateRawIPv4Write(write); err == nil {
				t.Fatal("invalid raw write was accepted")
			}
		})
	}
}
