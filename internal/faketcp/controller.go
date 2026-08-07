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

// ControllerBackend owns every external resource used by Controller. Combining
// both side-effect paths under one Close contract prevents two wrappers from
// closing the same underlying file descriptor independently.
type ControllerBackend interface {
	ControlSender
	PacketReinjector
	Close() error
}

var (
	// ErrControllerClosed means the controller has begun or completed closing.
	// An operation returning this error has not touched Engine or the backend.
	ErrControllerClosed = errors.New("faketcp controller is closed")

	errControllerContextNil = errors.New("faketcp controller context is nil")
)

// Controller executes the userspace side effects selected by Engine. Engine
// state transitions and all resulting side effects are serialised with Close.
// It does not retry side effects: a captured packet leaves the engine queue
// once and is passed to Reinject exactly once after preceding control sends
// succeed.
//
// Engine currently commits a transition before its actions are executed. A
// backend failure is therefore terminal and is never rolled back or retried.
// The experimental activation gate must remain closed until this two-phase
// action/rollback gap has a concrete solution.
type Controller struct {
	mu       sync.Mutex
	engine   *Engine
	backend  ControllerBackend
	closed   bool
	closeErr error
}

func NewController(engine *Engine, backend ControllerBackend) (*Controller, error) {
	if engine == nil {
		return nil, errors.New("faketcp controller requires an engine")
	}
	if controllerBackendIsNil(backend) {
		return nil, errors.New("faketcp controller backend is nil")
	}
	return &Controller{engine: engine, backend: backend}, nil
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
	if c == nil {
		return nil, ErrControllerClosed
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.requireOpenLocked(); err != nil {
		return nil, err
	}
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
	if err := c.executeLocked(ctx, actions); err != nil {
		return actions, err
	}
	return actions, nil
}

func (c *Controller) Tick(ctx context.Context) ([]Action, error) {
	if c == nil {
		return nil, ErrControllerClosed
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.requireOpenLocked(); err != nil {
		return nil, err
	}
	if ctx == nil {
		return nil, errControllerContextNil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	actions, engineErr := c.engine.Tick()
	executeErr := c.executeLocked(ctx, actions)
	return actions, errors.Join(engineErr, executeErr)
}

// Close waits for an in-flight HandleSample or Tick, then closes the single
// owned backend exactly once. A first close error is retained and returned by
// every later Close call. Closing a nil receiver is an explicit no-op.
func (c *Controller) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return c.closeErr
	}
	c.closed = true
	if controllerBackendIsNil(c.backend) {
		c.closeErr = errors.New("close faketcp controller: backend is nil")
		return c.closeErr
	}
	if err := c.backend.Close(); err != nil {
		c.closeErr = fmt.Errorf("close faketcp controller backend: %w", err)
	}
	return c.closeErr
}

func (c *Controller) requireOpenLocked() error {
	if c.closed {
		return ErrControllerClosed
	}
	if c.engine == nil {
		return errors.New("faketcp controller has no engine")
	}
	if controllerBackendIsNil(c.backend) {
		return errors.New("faketcp controller has no backend")
	}
	return nil
}

// executeLocked is called only while c.mu is held, keeping action order and
// resource ownership serialised with every other operation and Close.
func (c *Controller) executeLocked(ctx context.Context, actions []Action) error {
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
