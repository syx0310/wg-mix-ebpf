package faketcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"sync"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

const (
	fakeTCPEventSize       = abi.FakeTCPEventSize
	fakeTCPPacketEventSize = abi.FakeTCPPacketEventSize
)

// DecodedEvent owns its Packet copy; a ring-buffer reader may reuse the input
// sample as soon as DecodeEventSample returns.
type DecodedEvent struct {
	Event  abi.FakeTCPEvent
	Packet []byte
}

// borrowedDecodedEvent is valid only while its input sample remains owned by
// the caller. Keeping this type private prevents the borrowed packet from
// weakening DecodeEventSample's ownership contract.
type borrowedDecodedEvent struct {
	Event  abi.FakeTCPEvent
	packet []byte
}

// ownedDecodedEvent transfers one validated event to the production
// controller. Packet is either empty or an owned, capacity-bounded view into
// the sample allocation. Fingerprint binds the exact pre-materialization
// sample and remains valid after checksum materialization mutates Packet.
type ownedDecodedEvent struct {
	Event       abi.FakeTCPEvent
	Packet      []byte
	Fingerprint [sha256.Size]byte
}

// DecodeEventSample accepts compact variable-size packet events and the
// original fixed-size record for safe rolling upgrades. NEED_HANDSHAKE and
// destructive RST/FIN events must carry their complete L3 packet: metadata is
// never sufficient to release a packet or authorize session teardown.
func DecodeEventSample(sample []byte) (DecodedEvent, error) {
	decoded, err := decodeBorrowedEventSample(sample)
	if err != nil {
		return DecodedEvent{}, err
	}
	return DecodedEvent{
		Event:  decoded.Event,
		Packet: append([]byte(nil), decoded.packet...),
	}, nil
}

// decodeBorrowedEventSample applies the same validation as DecodeEventSample
// without copying the packet. Callers must not retain packet after the input
// sample's ownership ends.
func decodeBorrowedEventSample(sample []byte) (borrowedDecodedEvent, error) {
	if len(sample) < fakeTCPEventSize {
		return borrowedDecodedEvent{}, fmt.Errorf("faketcp event sample has %d bytes, need at least %d", len(sample), fakeTCPEventSize)
	}
	event := decodeEventHeader(sample[:fakeTCPEventSize])
	if err := validateEventType(event); err != nil {
		return borrowedDecodedEvent{}, err
	}

	if !fakeTCPEventCarriesPacket(event.Type) {
		if event.PacketLength != 0 || len(sample) != fakeTCPEventSize {
			return borrowedDecodedEvent{}, fmt.Errorf("faketcp control event type %d has packet length %d and sample size %d", event.Type, event.PacketLength, len(sample))
		}
		return borrowedDecodedEvent{Event: event}, nil
	}

	packetLength := int(event.PacketLength)
	if packetLength <= 0 || packetLength > abi.FakeTCPMaxCapturedPacket {
		return borrowedDecodedEvent{}, fmt.Errorf("faketcp captured packet length %d is invalid", packetLength)
	}
	compactSize := fakeTCPEventSize + packetLength
	if len(sample) != compactSize && len(sample) != fakeTCPPacketEventSize {
		return borrowedDecodedEvent{}, fmt.Errorf("faketcp packet event sample has %d bytes, want compact %d or fixed %d", len(sample), compactSize, fakeTCPPacketEventSize)
	}
	packet := sample[fakeTCPEventSize:compactSize:compactSize]
	if event.Type == abi.FakeTCPEventNeedHandshake {
		if err := validateCapturedIPv4UDP(event, packet); err != nil {
			return borrowedDecodedEvent{}, err
		}
	}
	return borrowedDecodedEvent{Event: event, packet: packet}, nil
}

func fakeTCPEventCarriesPacket(eventType uint8) bool {
	return eventType == abi.FakeTCPEventNeedHandshake ||
		eventType == abi.FakeTCPEventRST || eventType == abi.FakeTCPEventFIN
}

func decodeEventHeader(header []byte) abi.FakeTCPEvent {
	native := binary.NativeEndian
	return abi.FakeTCPEvent{
		Key: abi.FakeTCPSessionKey{
			Generation:    native.Uint64(header[0:8]),
			LocalIPv4:     native.Uint32(header[8:12]),
			RemoteIPv4:    native.Uint32(header[12:16]),
			UnderlayIndex: native.Uint32(header[16:20]),
			LocalPort:     native.Uint16(header[20:22]),
			RemotePort:    native.Uint16(header[22:24]),
		},
		TimestampNanos:     native.Uint64(header[24:32]),
		RuntimeIncarnation: [16]byte(header[32:48]),
		CaptureSequence:    native.Uint64(header[48:56]),
		SessionRevision:    native.Uint64(header[56:64]),
		SessionID:          native.Uint64(header[64:72]),
		CaptureCPU:         native.Uint32(header[72:76]),
		Sequence:           native.Uint32(header[76:80]),
		Acknowledgement:    native.Uint32(header[80:84]),
		PayloadLength:      native.Uint32(header[84:88]),
		FWMark:             native.Uint32(header[88:92]),
		WGID:               native.Uint32(header[92:96]),
		PacketLength:       native.Uint16(header[96:98]),
		EventABIVersion:    native.Uint16(header[98:100]),
		Type:               header[100],
		TCPFlags:           header[101],
	}
}

func validateEventType(event abi.FakeTCPEvent) error {
	if event.EventABIVersion != abi.FakeTCPEventABIVersion {
		return fmt.Errorf(
			"faketcp event ABI version %d does not match %d",
			event.EventABIVersion, abi.FakeTCPEventABIVersion,
		)
	}
	if err := validateRuntimeIdentity(runtimeIdentityFromEvent(event)); err != nil {
		return fmt.Errorf("invalid faketcp event runtime identity: %w", err)
	}
	flags := event.TCPFlags
	switch event.Type {
	case abi.FakeTCPEventNeedHandshake:
		if flags != 0 {
			return fmt.Errorf("faketcp NEED_HANDSHAKE event has TCP flags %#x", flags)
		}
		if err := validateCaptureIdentity(captureIdentityFromEvent(event), event.Key.Generation); err != nil {
			return fmt.Errorf("invalid faketcp event capture identity: %w", err)
		}
	case abi.FakeTCPEventSYN:
		if flags&FlagSYN == 0 || flags&(FlagACK|FlagRST|FlagFIN) != 0 {
			return fmt.Errorf("faketcp SYN event has inconsistent flags %#x", flags)
		}
	case abi.FakeTCPEventSYNACK:
		if flags&(FlagSYN|FlagACK) != FlagSYN|FlagACK || flags&(FlagRST|FlagFIN) != 0 {
			return fmt.Errorf("faketcp SYNACK event has inconsistent flags %#x", flags)
		}
	case abi.FakeTCPEventACK:
		if flags&FlagACK == 0 || flags&(FlagSYN|FlagRST|FlagFIN) != 0 {
			return fmt.Errorf("faketcp ACK event has inconsistent flags %#x", flags)
		}
	case abi.FakeTCPEventRST:
		if flags != FlagRST|FlagACK {
			return fmt.Errorf("faketcp RST event has inconsistent flags %#x", flags)
		}
	case abi.FakeTCPEventFIN:
		if flags != FlagFIN|FlagACK {
			return fmt.Errorf("faketcp FIN event has inconsistent flags %#x", flags)
		}
	default:
		return fmt.Errorf("unknown faketcp event type %d", event.Type)
	}
	closeEvent := event.Type == abi.FakeTCPEventRST || event.Type == abi.FakeTCPEventFIN
	if closeEvent {
		if event.SessionRevision == 0 || event.SessionID == 0 {
			return errors.New("faketcp close event has no session identity")
		}
	} else if event.SessionRevision != 0 || event.SessionID != 0 {
		return errors.New("faketcp non-close event contains a session identity")
	}
	if event.Type != abi.FakeTCPEventNeedHandshake &&
		(event.CaptureSequence != 0 || event.CaptureCPU != 0) {
		return errors.New("faketcp control event contains a capture sequence")
	}
	return nil
}

func validateCapturedIPv4UDP(event abi.FakeTCPEvent, packet []byte) error {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return errors.New("faketcp captured packet is not IPv4")
	}
	headerLength := int(packet[0]&0x0f) * 4
	if headerLength != 20 || headerLength+8 > len(packet) {
		return fmt.Errorf("faketcp captured IPv4 header length %d is invalid", headerLength)
	}
	if int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) {
		return fmt.Errorf("faketcp captured IPv4 total length does not match %d-byte record", len(packet))
	}
	if binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
		return errors.New("faketcp captured packet must not be an IPv4 fragment")
	}
	if packet[9] != 17 {
		return fmt.Errorf("faketcp captured IPv4 protocol %d is not UDP", packet[9])
	}
	var localAddress, remoteAddress [4]byte
	binary.NativeEndian.PutUint32(localAddress[:], event.Key.LocalIPv4)
	binary.NativeEndian.PutUint32(remoteAddress[:], event.Key.RemoteIPv4)
	if !bytes.Equal(packet[12:16], localAddress[:]) || !bytes.Equal(packet[16:20], remoteAddress[:]) {
		return errors.New("faketcp captured IPv4 endpoints do not match event key")
	}
	udp := packet[headerLength : headerLength+8]
	if binary.BigEndian.Uint16(udp[0:2]) != event.Key.LocalPort || binary.BigEndian.Uint16(udp[2:4]) != event.Key.RemotePort {
		return errors.New("faketcp captured UDP ports do not match event key")
	}
	if int(binary.BigEndian.Uint16(udp[4:6])) != len(packet)-headerLength {
		return errors.New("faketcp captured UDP length does not match IPv4 payload")
	}
	if event.PayloadLength != uint32(len(packet)-headerLength-8) {
		return errors.New("faketcp captured payload length does not match event metadata")
	}
	return nil
}

type ControlSender interface {
	SendControl(context.Context, abi.FakeTCPSessionKey, uint32, ControlPacket) error
}

type PacketReinjector interface {
	Reinject(context.Context, abi.FakeTCPSessionKey, PendingPacket) error
}

// ControllerBackend owns every external resource used by Controller.
// NewController takes ownership on success. Combining both side-effect paths
// under one Close contract prevents two wrappers from closing the same
// underlying file descriptor independently.
//
// SendControl and Reinject must not synchronously call HandleSample, Tick, or
// Close on their owning Controller: action execution is deliberately
// serialised, so such re-entry cannot preserve the ordering contract. Close is
// called after admitted operations drain and without either controller lock.
// It may call HandleSample or Tick, which immediately return
// ErrControllerClosed, but it must not recursively call Close.
type ControllerBackend interface {
	ControlSender
	PacketReinjector
	Close() error
}

var (
	// ErrControllerClosed means the controller has begun or completed closing.
	// An operation returning this error has not touched Engine or the backend.
	ErrControllerClosed = errors.New("faketcp controller is closed")

	// ErrControllerFailed means action execution failed after Engine had
	// already committed its transition. The first execution error is retained,
	// and later operations return it without touching Engine or the backend.
	ErrControllerFailed = errors.New("faketcp controller action execution failed")

	// ErrControllerRecoveryUnavailable means this controller was constructed
	// without a write-ahead ActionCheckpointStore.
	ErrControllerRecoveryUnavailable = errors.New("faketcp controller action recovery is unavailable")

	errControllerContextNil = errors.New("faketcp controller context is nil")
)

// Controller executes the userspace side effects selected by Engine. Engine
// state transitions and all resulting side effects are serialised with each
// other. Close rejects new work, waits for admitted operations to drain, and
// then closes the backend without holding either controller lock.
// NewController does not retry side effects: a captured packet leaves the
// engine queue once and is passed to Reinject exactly once after preceding
// control sends succeed. NewRecoverableController instead checkpoints each
// side effect and gates ordinary work behind Recover after an ambiguous
// result.
//
// Engine currently commits a transition before its actions are executed. The
// legacy constructor therefore treats execution failure as terminal. The
// recoverable constructor makes side-effect ambiguity explicit, but it does
// not persist Engine state; the experimental activation gate must remain
// closed until daemon-level generation recovery binds both pieces together. A
// Controller must not be copied after construction.
type Controller struct {
	stateMu sync.Mutex
	opMu    sync.Mutex

	dispatcher   controllerEngineDispatcher
	backend      ControllerBackend
	recovery     *ActionRecovery
	inflightDone *sync.Cond
	closeDone    chan struct{}
	inflight     uint64
	shutdown     bool
	closing      bool
	closed       bool
	failureErr   error
	recoveryErr  error
	closeErr     error
}

func NewController(engine *Engine, backend ControllerBackend) (*Controller, error) {
	if engine == nil {
		return nil, errors.New("faketcp controller requires an engine")
	}
	return newController(&singleEngineDispatcher{engine: engine}, backend)
}

// NewRoutedController selects one independently-owned Engine through router's
// immutable exact WGID table. It does not alter production runtime selection;
// callers must opt into this pure-Go multi-WireGuard boundary explicitly.
func NewRoutedController(router *EngineRouter, backend ControllerBackend) (*Controller, error) {
	if router == nil || validateRuntimeIdentity(router.Identity()) != nil ||
		len(router.engines) == 0 || len(router.routes) == 0 || len(router.wgIDs) == 0 {
		return nil, errors.New("faketcp routed controller requires an engine router")
	}
	return newController(router, backend)
}

// NewRecoverableController adds a one-slot write-ahead checkpoint around
// Controller side effects. It takes ownership of backend only on successful
// construction; the checkpoint store remains borrowed and may be durable.
// A retained checkpoint blocks HandleSample and Tick until Recover completes.
func NewRecoverableController(
	engine *Engine,
	backend ControllerBackend,
	store ActionCheckpointStore,
) (*Controller, error) {
	if engine == nil {
		return nil, errors.New("faketcp controller requires an engine")
	}
	return newRecoverableController(&singleEngineDispatcher{engine: engine}, backend, store)
}

// NewRecoverableRoutedController applies the same one-slot recovery protocol
// to the immutable multi-WireGuard dispatcher. Durable store implementations
// remain outside this slice; the Controller depends only on the existing store
// contract.
func NewRecoverableRoutedController(
	router *EngineRouter,
	backend ControllerBackend,
	store ActionCheckpointStore,
) (*Controller, error) {
	if router == nil || validateRuntimeIdentity(router.Identity()) != nil ||
		len(router.engines) == 0 || len(router.routes) == 0 || len(router.wgIDs) == 0 {
		return nil, errors.New("faketcp recoverable routed controller requires an engine router")
	}
	return newRecoverableController(router, backend, store)
}

func newRecoverableController(
	dispatcher controllerEngineDispatcher,
	backend ControllerBackend,
	store ActionCheckpointStore,
) (*Controller, error) {
	controller, err := newController(dispatcher, backend)
	if err != nil {
		return nil, err
	}
	recovery, err := NewActionRecovery(dispatcher.Identity(), backend, store)
	if err != nil {
		return nil, err
	}
	pending, err := recovery.Pending()
	if err != nil {
		return nil, err
	}
	controller.recovery = recovery
	if pending {
		controller.recoveryErr = ErrActionRecoveryRequired
	}
	return controller, nil
}

func newController(dispatcher controllerEngineDispatcher, backend ControllerBackend) (*Controller, error) {
	if interfaceValueIsNil(dispatcher) {
		return nil, errors.New("faketcp controller engine dispatcher is nil")
	}
	if controllerBackendIsNil(backend) {
		return nil, errors.New("faketcp controller backend is nil")
	}
	controller := &Controller{
		dispatcher: dispatcher,
		backend:    backend,
		closeDone:  make(chan struct{}),
	}
	controller.inflightDone = sync.NewCond(&controller.stateMu)
	return controller, nil
}

func controllerBackendIsNil(backend ControllerBackend) bool {
	if backend == nil {
		return true
	}
	value := reflect.ValueOf(backend)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (c *Controller) HandleSample(ctx context.Context, sample []byte) ([]Action, error) {
	if err := c.beginSerializedOperation(); err != nil {
		return nil, err
	}
	defer c.endSerializedOperation()
	if ctx == nil {
		return nil, errControllerContextNil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	decoded, err := DecodeEventSample(sample)
	if err != nil {
		return nil, err
	}
	owned := ownedDecodedEvent{Event: decoded.Event, Packet: decoded.Packet}
	if decoded.Event.Type == abi.FakeTCPEventNeedHandshake {
		owned.Fingerprint = sha256.Sum256(sample)
	}
	return c.handleOwnedDecodedEvent(ctx, owned)
}

// handleOwnedEvent is the private production boundary selected when the
// controller runtime is constructed. The reader has already decoded and
// validated the sample, and transfers Packet ownership with this call.
func (c *Controller) handleOwnedEvent(
	ctx context.Context,
	decoded ownedDecodedEvent,
) ([]Action, error) {
	if err := c.beginSerializedOperation(); err != nil {
		return nil, err
	}
	defer c.endSerializedOperation()
	if ctx == nil {
		return nil, errControllerContextNil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return c.handleOwnedDecodedEvent(ctx, decoded)
}

// handleOwnedDecodedEvent runs with opMu held. Every packet reaching this
// helper is owned by the call, so Engine may retain it without another copy.
func (c *Controller) handleOwnedDecodedEvent(
	ctx context.Context,
	decoded ownedDecodedEvent,
) ([]Action, error) {
	if identity := runtimeIdentityFromEvent(decoded.Event); identity != c.dispatcher.Identity() {
		return nil, fmt.Errorf(
			"faketcp event runtime identity does not match controller dispatcher: event=%x dispatcher=%x",
			identity.Incarnation, c.dispatcher.Identity().Incarnation,
		)
	}
	engine, err := c.dispatcher.selectEngine(decoded.Event)
	if err != nil {
		return nil, err
	}
	var (
		actions   []Action
		engineErr error
	)
	switch decoded.Event.Type {
	case abi.FakeTCPEventNeedHandshake:
		if err := MaterializeIPv4UDPChecksums(decoded.Packet); err != nil {
			return nil, err
		}
		actions, engineErr = engine.handleOwnedCapturedPacket(
			decoded.Event,
			decoded.Packet,
			decoded.Fingerprint,
		)
	case abi.FakeTCPEventRST, abi.FakeTCPEventFIN:
		actions, engineErr = engine.InboundCapturedControl(decoded.Event, decoded.Packet)
	default:
		actions, engineErr = engine.InboundWithWGID(decoded.Event.Key, Segment{
			Flags:           decoded.Event.TCPFlags,
			Sequence:        decoded.Event.Sequence,
			Acknowledgement: decoded.Event.Acknowledgement,
			PayloadLength:   decoded.Event.PayloadLength,
		}, decoded.Event.WGID)
	}
	if engineErr != nil {
		return actions, engineErr
	}
	if err := c.dispatcher.validateActions(actions); err != nil {
		return actions, err
	}
	if err := c.executeActions(ctx, actions); err != nil {
		return actions, c.handleActionExecutionError(err)
	}
	return actions, nil
}

func (c *Controller) Tick(ctx context.Context) ([]Action, error) {
	if err := c.beginSerializedOperation(); err != nil {
		return nil, err
	}
	defer c.endSerializedOperation()
	if ctx == nil {
		return nil, errControllerContextNil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	actions, engineErr := c.dispatcher.Tick()
	if routeErr := c.dispatcher.validateActions(actions); routeErr != nil {
		return actions, errors.Join(engineErr, routeErr)
	}
	if executeErr := c.executeActions(ctx, actions); executeErr != nil {
		return actions, errors.Join(engineErr, c.handleActionExecutionError(executeErr))
	}
	return actions, engineErr
}

// Recover resumes a retained action checkpoint. Ambiguous controls are
// replayed, while an ambiguous reinjection is permanently skipped. Ordinary
// operations remain fenced until no checkpoint remains. Recover itself is
// serialised with HandleSample, Tick, and Close.
func (c *Controller) Recover(ctx context.Context) (RecoveryReport, error) {
	if err := c.beginRecoveryOperation(); err != nil {
		return RecoveryReport{}, err
	}
	defer c.endSerializedOperation()
	if ctx == nil {
		return RecoveryReport{}, errControllerContextNil
	}
	report, recoveryErr := c.recovery.Recover(ctx)
	pending, pendingErr := c.recovery.Pending()
	if pendingErr != nil {
		return report, c.markRecoveryRequired(errors.Join(recoveryErr, pendingErr))
	}
	if pending {
		return report, c.markRecoveryRequired(recoveryErr)
	}
	c.clearRecoveryRequired()
	return report, recoveryErr
}

// Close first rejects new operations, waits for admitted HandleSample and Tick
// calls, and then closes the single owned backend without holding stateMu or
// opMu. A failed close retains that exact backend for a later Close retry while
// the first attempt permanently fences operations. A nil or zero-value
// receiver fails closed with ErrControllerClosed.
func (c *Controller) Close() error {
	if c == nil {
		return ErrControllerClosed
	}

	c.stateMu.Lock()
	if c.closed {
		c.stateMu.Unlock()
		return nil
	}
	if c.closing {
		closeDone := c.closeDone
		c.stateMu.Unlock()
		<-closeDone
		c.stateMu.Lock()
		closeErr := c.closeErr
		c.stateMu.Unlock()
		return closeErr
	}
	if !c.initializedLocked() {
		c.stateMu.Unlock()
		return ErrControllerClosed
	}

	c.shutdown = true
	c.closing = true
	c.closeDone = make(chan struct{})
	for c.inflight != 0 {
		c.inflightDone.Wait()
	}
	backend := c.backend
	c.stateMu.Unlock()

	var closeErr error
	if err := backend.Close(); err != nil {
		closeErr = fmt.Errorf("close faketcp controller backend: %w", err)
	}

	c.stateMu.Lock()
	if closeErr == nil {
		c.backend = nil
	}
	c.closeErr = closeErr
	c.closed = controllerBackendIsNil(c.backend)
	c.closing = false
	close(c.closeDone)
	c.inflightDone.Broadcast()
	c.stateMu.Unlock()
	return closeErr
}

func (c *Controller) beginSerializedOperation() error {
	if c == nil {
		return ErrControllerClosed
	}

	c.stateMu.Lock()
	if !c.initializedLocked() || c.shutdown || c.closing || c.closed {
		c.stateMu.Unlock()
		return ErrControllerClosed
	}
	if c.failureErr != nil {
		failureErr := c.failureErr
		c.stateMu.Unlock()
		return failureErr
	}
	if c.recoveryErr != nil {
		recoveryErr := c.recoveryErr
		c.stateMu.Unlock()
		return recoveryErr
	}
	c.inflight++
	c.stateMu.Unlock()

	c.opMu.Lock()
	c.stateMu.Lock()
	failureErr := c.failureErr
	recoveryErr := c.recoveryErr
	initialized := c.initializedLocked()
	c.stateMu.Unlock()
	if failureErr != nil {
		c.opMu.Unlock()
		c.finishOperation()
		return failureErr
	}
	if recoveryErr != nil {
		c.opMu.Unlock()
		c.finishOperation()
		return recoveryErr
	}
	if !initialized {
		c.opMu.Unlock()
		c.finishOperation()
		return ErrControllerClosed
	}
	return nil
}

func (c *Controller) beginRecoveryOperation() error {
	if c == nil {
		return ErrControllerClosed
	}
	c.stateMu.Lock()
	if !c.initializedLocked() || c.shutdown || c.closing || c.closed {
		c.stateMu.Unlock()
		return ErrControllerClosed
	}
	if c.failureErr != nil {
		failureErr := c.failureErr
		c.stateMu.Unlock()
		return failureErr
	}
	if c.recovery == nil {
		c.stateMu.Unlock()
		return ErrControllerRecoveryUnavailable
	}
	c.inflight++
	c.stateMu.Unlock()

	c.opMu.Lock()
	c.stateMu.Lock()
	failureErr := c.failureErr
	initialized := c.initializedLocked()
	recoveryAvailable := c.recovery != nil
	c.stateMu.Unlock()
	if failureErr != nil {
		c.opMu.Unlock()
		c.finishOperation()
		return failureErr
	}
	if !initialized {
		c.opMu.Unlock()
		c.finishOperation()
		return ErrControllerClosed
	}
	if !recoveryAvailable {
		c.opMu.Unlock()
		c.finishOperation()
		return ErrControllerRecoveryUnavailable
	}
	return nil
}

func (c *Controller) endSerializedOperation() {
	c.opMu.Unlock()
	c.finishOperation()
}

func (c *Controller) finishOperation() {
	c.stateMu.Lock()
	if c.inflight > 0 {
		c.inflight--
	}
	if c.inflight == 0 && c.inflightDone != nil {
		c.inflightDone.Broadcast()
	}
	c.stateMu.Unlock()
}

func (c *Controller) initializedLocked() bool {
	return !interfaceValueIsNil(c.dispatcher) &&
		!controllerBackendIsNil(c.backend) &&
		c.inflightDone != nil &&
		c.closeDone != nil
}

func (c *Controller) markFailed(cause error) error {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if c.failureErr == nil {
		c.failureErr = fmt.Errorf("%w: %w", ErrControllerFailed, cause)
	}
	return c.failureErr
}

func (c *Controller) markRecoveryRequired(cause error) error {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if cause == nil {
		if c.recoveryErr == nil {
			c.recoveryErr = ErrActionRecoveryRequired
		}
	} else {
		c.recoveryErr = errors.Join(ErrActionRecoveryRequired, cause)
	}
	return c.recoveryErr
}

func (c *Controller) clearRecoveryRequired() {
	c.stateMu.Lock()
	c.recoveryErr = nil
	c.stateMu.Unlock()
}

func (c *Controller) handleActionExecutionError(cause error) error {
	if c.recovery != nil && errors.Is(cause, ErrActionRecoveryRequired) {
		return c.markRecoveryRequired(cause)
	}
	return c.markFailed(cause)
}

// executeActions is called only while opMu is held. Its caller promotes a
// legacy execution error to permanent failure, or fences a recoverable
// controller while a write-ahead checkpoint remains.
func (c *Controller) executeActions(ctx context.Context, actions []Action) error {
	if c.recovery != nil {
		return c.recovery.Execute(ctx, actions)
	}
	for _, action := range actions {
		if err := ctx.Err(); err != nil {
			return err
		}
		switch action.Kind {
		case ActionSendControl:
			if err := c.backend.SendControl(ctx, action.Flow, action.WGID, action.Control); err != nil {
				return fmt.Errorf("send faketcp control packet (%s): %w", action.Reason, err)
			}
		case ActionReleasePending:
			var errs []error
			for _, packet := range action.Packets {
				if err := ctx.Err(); err != nil {
					errs = append(errs, fmt.Errorf("reinject faketcp first packet: %w", err))
					break
				}
				if err := c.backend.Reinject(ctx, action.Flow, packet); err != nil {
					errs = append(errs, fmt.Errorf("reinject faketcp first packet: %w", err))
				}
			}
			if err := errors.Join(errs...); err != nil {
				return err
			}
		}
	}
	return nil
}
