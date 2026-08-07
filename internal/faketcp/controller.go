package faketcp

import (
	"bytes"
	"context"
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

// DecodeEventSample accepts the compact variable-size packet event emitted by
// the current BPF program and the original fixed-size record for safe rolling
// upgrades. Metadata-only NEED_HANDSHAKE events are rejected because they
// cannot release a real first packet after the handshake.
func DecodeEventSample(sample []byte) (DecodedEvent, error) {
	if len(sample) < fakeTCPEventSize {
		return DecodedEvent{}, fmt.Errorf("faketcp event sample has %d bytes, need at least %d", len(sample), fakeTCPEventSize)
	}
	event := decodeEventHeader(sample[:fakeTCPEventSize])
	if err := validateEventType(event); err != nil {
		return DecodedEvent{}, err
	}

	if event.Type != abi.FakeTCPEventNeedHandshake {
		if event.PacketLength != 0 || len(sample) != fakeTCPEventSize {
			return DecodedEvent{}, fmt.Errorf("faketcp control event type %d has packet length %d and sample size %d", event.Type, event.PacketLength, len(sample))
		}
		return DecodedEvent{Event: event}, nil
	}

	packetLength := int(event.PacketLength)
	if packetLength <= 0 || packetLength > abi.FakeTCPMaxCapturedPacket {
		return DecodedEvent{}, fmt.Errorf("faketcp captured packet length %d is invalid", packetLength)
	}
	compactSize := fakeTCPEventSize + packetLength
	if len(sample) != compactSize && len(sample) != fakeTCPPacketEventSize {
		return DecodedEvent{}, fmt.Errorf("faketcp packet event sample has %d bytes, want compact %d or fixed %d", len(sample), compactSize, fakeTCPPacketEventSize)
	}
	packet := append([]byte(nil), sample[fakeTCPEventSize:compactSize]...)
	if err := validateCapturedIPv4UDP(event, packet); err != nil {
		return DecodedEvent{}, err
	}
	return DecodedEvent{Event: event, Packet: packet}, nil
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
		TimestampNanos:  native.Uint64(header[24:32]),
		Sequence:        native.Uint32(header[32:36]),
		Acknowledgement: native.Uint32(header[36:40]),
		PayloadLength:   native.Uint32(header[40:44]),
		FWMark:          native.Uint32(header[44:48]),
		WGID:            native.Uint32(header[48:52]),
		PacketLength:    native.Uint16(header[52:54]),
		Type:            header[54],
		TCPFlags:        header[55],
	}
}

func validateEventType(event abi.FakeTCPEvent) error {
	flags := event.TCPFlags
	switch event.Type {
	case abi.FakeTCPEventNeedHandshake:
		if flags != 0 {
			return fmt.Errorf("faketcp NEED_HANDSHAKE event has TCP flags %#x", flags)
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
		if flags&FlagRST == 0 {
			return fmt.Errorf("faketcp RST event has inconsistent flags %#x", flags)
		}
	case abi.FakeTCPEventFIN:
		if flags&FlagFIN == 0 || flags&FlagRST != 0 {
			return fmt.Errorf("faketcp FIN event has inconsistent flags %#x", flags)
		}
	default:
		return fmt.Errorf("unknown faketcp event type %d", event.Type)
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

	errControllerContextNil = errors.New("faketcp controller context is nil")
)

// Controller executes the userspace side effects selected by Engine. Engine
// state transitions and all resulting side effects are serialised with each
// other. Close rejects new work, waits for admitted operations to drain, and
// then closes the backend without holding either controller lock.
// It does not retry side effects: a captured packet leaves the engine queue
// once and is passed to Reinject exactly once after preceding control sends
// succeed.
//
// Engine currently commits a transition before its actions are executed. Any
// action-execution failure, including a backend error or side-effect-stage
// context cancellation, is therefore terminal and is never rolled back or
// retried. The experimental activation gate must remain closed until this
// two-phase action/rollback gap has a concrete solution. A Controller must not
// be copied after NewController returns.
type Controller struct {
	stateMu sync.Mutex
	opMu    sync.Mutex

	engine       *Engine
	backend      ControllerBackend
	inflightDone *sync.Cond
	closeDone    chan struct{}
	inflight     uint64
	closing      bool
	closed       bool
	failureErr   error
	closeErr     error
}

func NewController(engine *Engine, backend ControllerBackend) (*Controller, error) {
	if engine == nil {
		return nil, errors.New("faketcp controller requires an engine")
	}
	if controllerBackendIsNil(backend) {
		return nil, errors.New("faketcp controller backend is nil")
	}
	controller := &Controller{
		engine:    engine,
		backend:   backend,
		closeDone: make(chan struct{}),
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
	var actions []Action
	if decoded.Event.Type == abi.FakeTCPEventNeedHandshake {
		if err := MaterializeIPv4UDPChecksums(decoded.Packet); err != nil {
			return nil, err
		}
		actions, err = c.engine.handleCapturedPacket(decoded.Event, decoded.Packet)
	} else {
		actions, err = c.engine.InboundWithWGID(decoded.Event.Key, Segment{
			Flags:           decoded.Event.TCPFlags,
			Sequence:        decoded.Event.Sequence,
			Acknowledgement: decoded.Event.Acknowledgement,
			PayloadLength:   decoded.Event.PayloadLength,
		}, decoded.Event.WGID)
	}
	if err != nil {
		return actions, err
	}
	if err := c.executeActions(ctx, actions); err != nil {
		return actions, c.markFailed(err)
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
	actions, engineErr := c.engine.Tick()
	if executeErr := c.executeActions(ctx, actions); executeErr != nil {
		return actions, errors.Join(engineErr, c.markFailed(executeErr))
	}
	return actions, engineErr
}

// Close first rejects new operations, waits for admitted HandleSample and Tick
// calls, and then closes the single owned backend exactly once without holding
// stateMu or opMu. A first close error is retained and returned by every later
// Close call. A nil or zero-value receiver fails closed with
// ErrControllerClosed.
func (c *Controller) Close() error {
	if c == nil {
		return ErrControllerClosed
	}

	c.stateMu.Lock()
	if !c.initializedLocked() {
		c.stateMu.Unlock()
		return ErrControllerClosed
	}
	if c.closed {
		closeErr := c.closeErr
		c.stateMu.Unlock()
		return closeErr
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

	c.closing = true
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
	c.closeErr = closeErr
	c.closed = true
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
	if !c.initializedLocked() || c.closing || c.closed {
		c.stateMu.Unlock()
		return ErrControllerClosed
	}
	if c.failureErr != nil {
		failureErr := c.failureErr
		c.stateMu.Unlock()
		return failureErr
	}
	c.inflight++
	c.stateMu.Unlock()

	c.opMu.Lock()
	c.stateMu.Lock()
	failureErr := c.failureErr
	initialized := c.initializedLocked()
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
	return c.engine != nil &&
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

// executeActions is called only while opMu is held. A non-nil error after an
// Engine transition is promoted by the caller to the permanent failed state.
func (c *Controller) executeActions(ctx context.Context, actions []Action) error {
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
