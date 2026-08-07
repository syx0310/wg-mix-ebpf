package faketcp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

var (
	ErrRawBackendClosed        = errors.New("faketcp raw controller backend is closed")
	ErrReinjectorClosed        = errors.New("faketcp once-only reinjector is closed")
	ErrReinjectLedgerCapacity  = errors.New("faketcp once-only reinjection ledger is full")
	ErrCaptureIdentityConflict = errors.New("faketcp capture identity was reused with different packet metadata")
)

// RawIPv4Write is one complete IPv4 packet and the exact routing metadata
// required to send it. Data ownership remains with the caller for the duration
// of WriteIPv4 only.
type RawIPv4Write struct {
	Data          []byte
	UnderlayIndex uint32
	FWMark        uint32
}

// RawIPv4Writer is the capability-bearing boundary around a raw IPv4 socket.
// Implementations must send one complete datagram or return an error; partial
// success is not allowed. Close must fence admitted writes and be idempotent.
// WriteIPv4 must not synchronously call Close on an owning
// RawControllerBackend; the owner waits for admitted calls before closing it.
type RawIPv4Writer interface {
	WriteIPv4(context.Context, RawIPv4Write) error
	Close() error
}

func validateRawIPv4Write(write RawIPv4Write) error {
	if write.UnderlayIndex == 0 {
		return errors.New("raw faketcp IPv4 write has zero underlay interface index")
	}
	if write.UnderlayIndex > 1<<31-1 {
		return fmt.Errorf("raw faketcp IPv4 write has out-of-range underlay interface index %d", write.UnderlayIndex)
	}
	packet := write.Data
	if len(packet) < materializedIPv4HeaderLength || packet[0]>>4 != 4 {
		return errors.New("raw faketcp IPv4 write is not a complete IPv4 packet")
	}
	headerLength := int(packet[0]&0x0f) * 4
	if headerLength != materializedIPv4HeaderLength || len(packet) < headerLength {
		return fmt.Errorf("raw faketcp IPv4 write has unsupported header length %d", headerLength)
	}
	if int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) || len(packet) > 0xffff {
		return errors.New("raw faketcp IPv4 write has inconsistent total length")
	}
	if binary.BigEndian.Uint16(packet[6:8])&0xbfff != 0 {
		return errors.New("raw faketcp IPv4 write has reserved flags or fragmentation")
	}
	if packet[9] != 6 && packet[9] != 17 {
		return fmt.Errorf("raw faketcp IPv4 write has unsupported protocol %d", packet[9])
	}
	if packet[12] == 0 && packet[13] == 0 && packet[14] == 0 && packet[15] == 0 {
		return errors.New("raw faketcp IPv4 write has zero source address")
	}
	if packet[16] == 0 && packet[17] == 0 && packet[18] == 0 && packet[19] == 0 {
		return errors.New("raw faketcp IPv4 write has zero destination address")
	}
	if !checksumValid(packet[:headerLength]) {
		return errors.New("raw faketcp IPv4 write has invalid IPv4 checksum")
	}
	transport := packet[headerLength:]
	if len(transport) < controlTCPHeaderLength {
		if packet[9] == 6 || len(transport) < udpHeaderLength {
			return errors.New("raw faketcp IPv4 write has a truncated transport header")
		}
	}
	if !transportChecksumValid(packet[12:20], packet[9], transport) {
		return errors.New("raw faketcp IPv4 write has invalid transport checksum")
	}
	if packet[9] == 17 && binary.BigEndian.Uint16(transport[6:8]) == 0 {
		return errors.New("raw faketcp IPv4 write has an absent UDP checksum")
	}
	return nil
}

// ControlMarkResolver binds one userspace handshake packet to the configured
// routing mark for its WireGuard identity. It is intentionally explicit: a
// backend must not guess a mark from WGID or reuse the captured data mark.
// ControlMark must not synchronously call Close on its owning
// RawControllerBackend. It is invoked without backend locks, but Close is a
// synchronous fence over admitted calls.
type ControlMarkResolver interface {
	ControlMark(context.Context, abi.FakeTCPSessionKey, uint32) (uint32, error)
}

type ControlMarkResolverFunc func(context.Context, abi.FakeTCPSessionKey, uint32) (uint32, error)

func (resolve ControlMarkResolverFunc) ControlMark(
	ctx context.Context,
	flow abi.FakeTCPSessionKey,
	wgID uint32,
) (uint32, error) {
	return resolve(ctx, flow, wgID)
}

type RawControllerBackendOptions struct {
	Writer                    RawIPv4Writer
	ControlMarks              ControlMarkResolver
	MaxRememberedReinjections int
}

// RawControllerBackend implements ControllerBackend without owning any BPF
// resource. Control packets are marshalled as TCP-shaped IPv4 datagrams;
// captured UDP packets are validated and re-injected through the ordinary
// type-word/XOR/FakeTCP egress pipeline. The same writer serialises SO_MARK and
// interface selection for both paths.
type RawControllerBackend struct {
	mu sync.Mutex

	writer       RawIPv4Writer
	controlMarks ControlMarkResolver
	reinjector   *OnceReinjector
	inflightDone *sync.Cond
	closeDone    chan struct{}
	inflight     uint64
	closing      bool
	closed       bool
	closeErr     error
}

var _ ControllerBackend = (*RawControllerBackend)(nil)

func NewRawControllerBackend(options RawControllerBackendOptions) (*RawControllerBackend, error) {
	if rawIPv4WriterIsNil(options.Writer) {
		return nil, errors.New("faketcp raw IPv4 writer is nil")
	}
	if controlMarkResolverIsNil(options.ControlMarks) {
		return nil, errors.New("faketcp control mark resolver is nil")
	}
	reinjector, err := NewOnceReinjector(options.Writer, options.MaxRememberedReinjections)
	if err != nil {
		return nil, err
	}
	backend := &RawControllerBackend{
		writer:       options.Writer,
		controlMarks: options.ControlMarks,
		reinjector:   reinjector,
		closeDone:    make(chan struct{}),
	}
	backend.inflightDone = sync.NewCond(&backend.mu)
	return backend, nil
}

func (backend *RawControllerBackend) SendControl(
	ctx context.Context,
	flow abi.FakeTCPSessionKey,
	wgID uint32,
	control ControlPacket,
) error {
	if backend == nil {
		return ErrRawBackendClosed
	}
	if ctx == nil {
		return errors.New("send faketcp control: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	writer, controlMarks, _, err := backend.beginOperation()
	if err != nil {
		return err
	}
	defer backend.endOperation()

	// Resolver and writer are deliberately invoked without holding backend.mu.
	// They must not synchronously call Close on this backend: Close waits for
	// admitted calls so ownership has a conventional, synchronous fence.
	mark, err := controlMarks.ControlMark(ctx, flow, wgID)
	if err != nil {
		return fmt.Errorf("resolve faketcp control mark for wg id %d: %w", wgID, err)
	}
	packet, err := MarshalIPv4TCPControl(flow, control)
	if err != nil {
		return err
	}
	if err := writer.WriteIPv4(ctx, RawIPv4Write{
		Data:          packet,
		UnderlayIndex: flow.UnderlayIndex,
		FWMark:        mark,
	}); err != nil {
		return fmt.Errorf("write faketcp control packet: %w", err)
	}
	return nil
}

func (backend *RawControllerBackend) Reinject(
	ctx context.Context,
	flow abi.FakeTCPSessionKey,
	packet PendingPacket,
) error {
	if backend == nil {
		return ErrRawBackendClosed
	}
	if ctx == nil {
		return errors.New("reinject faketcp packet: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	_, _, reinjector, err := backend.beginOperation()
	if err != nil {
		return err
	}
	defer backend.endOperation()
	return reinjector.Reinject(ctx, flow, packet)
}

func (backend *RawControllerBackend) Close() error {
	if backend == nil {
		return nil
	}
	backend.mu.Lock()
	if !backend.initializedLocked() {
		backend.mu.Unlock()
		return ErrRawBackendClosed
	}
	if backend.closed {
		closeErr := backend.closeErr
		backend.mu.Unlock()
		return closeErr
	}
	if backend.closing {
		closeDone := backend.closeDone
		backend.mu.Unlock()
		<-closeDone
		backend.mu.Lock()
		closeErr := backend.closeErr
		backend.mu.Unlock()
		return closeErr
	}
	backend.closing = true
	for backend.inflight != 0 {
		backend.inflightDone.Wait()
	}
	reinjector := backend.reinjector
	writer := backend.writer
	backend.mu.Unlock()

	closeErr := errors.Join(
		reinjector.Close(),
		writer.Close(),
	)

	backend.mu.Lock()
	backend.closeErr = closeErr
	backend.closed = true
	backend.closing = false
	close(backend.closeDone)
	backend.mu.Unlock()
	return closeErr
}

func (backend *RawControllerBackend) beginOperation() (
	RawIPv4Writer,
	ControlMarkResolver,
	*OnceReinjector,
	error,
) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if !backend.initializedLocked() || backend.closing || backend.closed {
		return nil, nil, nil, ErrRawBackendClosed
	}
	backend.inflight++
	return backend.writer, backend.controlMarks, backend.reinjector, nil
}

func (backend *RawControllerBackend) endOperation() {
	backend.mu.Lock()
	if backend.inflight > 0 {
		backend.inflight--
	}
	if backend.inflight == 0 {
		backend.inflightDone.Broadcast()
	}
	backend.mu.Unlock()
}

func (backend *RawControllerBackend) initializedLocked() bool {
	return !rawIPv4WriterIsNil(backend.writer) &&
		!controlMarkResolverIsNil(backend.controlMarks) &&
		backend.reinjector != nil &&
		backend.inflightDone != nil &&
		backend.closeDone != nil
}

type reinjectIdentity struct {
	capture CaptureIdentity
}

type reinjectFingerprint struct {
	flow   abi.FakeTCPSessionKey
	fwmark uint32
	wgID   uint32
	packet string
}

type reinjectAttempt struct {
	fingerprint reinjectFingerprint
	done        chan struct{}
	err         error
}

// OnceReinjector retains an exact identity for every attempted captured
// packet. It claims an identity before calling the writer, so an error with an
// ambiguous send outcome is never retried. Concurrent duplicate callers wait
// for and receive the first attempt's result. Reusing an identity with changed
// flow/mark/WGID/bytes fails closed without a write. The ledger never evicts:
// reaching the configured bound requires a generation/runtime reload.
type OnceReinjector struct {
	mu sync.Mutex

	writer      RawIPv4Writer
	maxAttempts int
	attempts    map[reinjectIdentity]*reinjectAttempt
	closed      bool
}

func NewOnceReinjector(writer RawIPv4Writer, maxAttempts int) (*OnceReinjector, error) {
	if rawIPv4WriterIsNil(writer) {
		return nil, errors.New("faketcp once-only reinjector writer is nil")
	}
	if ready, ok := writer.(interface{ rawIPv4WriterReady() error }); ok {
		if err := ready.rawIPv4WriterReady(); err != nil {
			return nil, fmt.Errorf("faketcp once-only reinjector writer is not ready: %w", err)
		}
	}
	if maxAttempts <= 0 {
		return nil, errors.New("faketcp once-only reinjector capacity must be positive")
	}
	return &OnceReinjector{
		writer:      writer,
		maxAttempts: maxAttempts,
		attempts:    make(map[reinjectIdentity]*reinjectAttempt),
	}, nil
}

func (reinjector *OnceReinjector) Reinject(
	ctx context.Context,
	flow abi.FakeTCPSessionKey,
	packet PendingPacket,
) error {
	if reinjector == nil {
		return ErrReinjectorClosed
	}
	if ctx == nil {
		return errors.New("faketcp once-only reinjection context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateCaptureIdentity(packet.CaptureID, flow.Generation); err != nil {
		return fmt.Errorf("validate faketcp captured packet identity: %w", err)
	}
	if err := ValidateMaterializedIPv4UDP(packet.Data, flow); err != nil {
		return err
	}
	identity := reinjectIdentity{capture: packet.CaptureID}
	fingerprint := reinjectFingerprint{
		flow:   flow,
		fwmark: packet.FWMark,
		wgID:   packet.WGID,
		packet: string(packet.Data),
	}

	reinjector.mu.Lock()
	if reinjector.closed {
		reinjector.mu.Unlock()
		return ErrReinjectorClosed
	}
	if previous := reinjector.attempts[identity]; previous != nil {
		if previous.fingerprint != fingerprint {
			reinjector.mu.Unlock()
			return ErrCaptureIdentityConflict
		}
		done := previous.done
		reinjector.mu.Unlock()
		select {
		case <-done:
			return previous.err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if len(reinjector.attempts) >= reinjector.maxAttempts {
		reinjector.mu.Unlock()
		return fmt.Errorf("%w: maximum %d", ErrReinjectLedgerCapacity, reinjector.maxAttempts)
	}
	attempt := &reinjectAttempt{fingerprint: fingerprint, done: make(chan struct{})}
	reinjector.attempts[identity] = attempt
	reinjector.mu.Unlock()

	err := reinjector.writer.WriteIPv4(ctx, RawIPv4Write{
		Data:          packet.Data,
		UnderlayIndex: flow.UnderlayIndex,
		FWMark:        packet.FWMark,
	})
	if err != nil {
		err = fmt.Errorf("write captured faketcp packet once: %w", err)
	}
	reinjector.mu.Lock()
	attempt.err = err
	close(attempt.done)
	reinjector.mu.Unlock()
	return err
}

func (reinjector *OnceReinjector) Close() error {
	if reinjector == nil {
		return nil
	}
	reinjector.mu.Lock()
	reinjector.closed = true
	pending := make([]<-chan struct{}, 0)
	for _, attempt := range reinjector.attempts {
		select {
		case <-attempt.done:
		default:
			pending = append(pending, attempt.done)
		}
	}
	reinjector.mu.Unlock()
	for _, done := range pending {
		<-done
	}
	return nil
}

func rawIPv4WriterIsNil(writer RawIPv4Writer) bool {
	return interfaceValueIsNil(writer)
}

func controlMarkResolverIsNil(resolver ControlMarkResolver) bool {
	return interfaceValueIsNil(resolver)
}
