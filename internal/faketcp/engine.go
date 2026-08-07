// Package faketcp contains the userspace slow-path state machine for the
// experimental FakeTCP transport. It intentionally implements TCP-shaped
// signalling, not TCP reliability or byte-stream semantics: the UDP payload
// remains independently recoverable by WireGuard or QUIC.
package faketcp

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

const (
	FlagFIN uint8 = 1 << 0
	FlagSYN uint8 = 1 << 1
	FlagRST uint8 = 1 << 2
	FlagPSH uint8 = 1 << 3
	FlagACK uint8 = 1 << 4
)

type Options struct {
	Generation               uint64
	SessionCapacity          int
	MaxPendingFlows          int
	MaxPendingPacketsPerFlow int
	MaxPendingBytes          int
	HandshakeTimeout         time.Duration
	HandshakeRetries         int
	KeepaliveInterval        time.Duration
	IdleTimeout              time.Duration
	Window                   uint16
	Now                      func() time.Time
	InitialSequence          func() uint32
	Store                    SessionStore
}

type SessionStore interface {
	Upsert(abi.FakeTCPSessionKey, abi.FakeTCPSessionValue) error
	Delete(abi.FakeTCPSessionKey) error
}

type Segment struct {
	Flags           uint8
	Sequence        uint32
	Acknowledgement uint32
	PayloadLength   uint32
}

type ControlPacket struct {
	Flags           uint8
	Sequence        uint32
	Acknowledgement uint32
	Window          uint16
}

type ActionKind uint8

const (
	ActionDrop ActionKind = iota
	ActionForward
	ActionSendControl
	ActionReleasePending
	ActionClose
)

type Action struct {
	Kind    ActionKind
	Flow    abi.FakeTCPSessionKey
	Control ControlPacket
	Packets [][]byte
	Reason  string
}

type SessionSnapshot struct {
	State          uint8
	TXSequence     uint32
	RXSequence     uint32
	PendingPackets int
	PendingBytes   int
	LastActivity   time.Time
}

type session struct {
	state         uint8
	localISN      uint32
	remoteISN     uint32
	txSequence    uint32
	rxSequence    uint32
	lastActivity  time.Time
	nextRetry     time.Time
	nextKeepalive time.Time
	retries       int
	pending       [][]byte
	pendingBytes  int
}

type Engine struct {
	mu           sync.Mutex
	opts         Options
	sessions     map[abi.FakeTCPSessionKey]*session
	pendingFlows int
	pendingBytes int
}

type engineCheckpoint struct {
	existed      bool
	session      *session
	pendingFlows int
	pendingBytes int
}

func New(options Options) (*Engine, error) {
	if options.Generation == 0 {
		return nil, errors.New("faketcp generation must be non-zero")
	}
	if options.SessionCapacity <= 0 || options.MaxPendingFlows <= 0 ||
		options.MaxPendingFlows > options.SessionCapacity ||
		options.MaxPendingPacketsPerFlow <= 0 || options.MaxPendingBytes <= 0 {
		return nil, errors.New("faketcp session and pending limits must be positive and bounded")
	}
	if options.HandshakeTimeout <= 0 || options.HandshakeRetries <= 0 ||
		options.KeepaliveInterval <= 0 || options.IdleTimeout <= options.KeepaliveInterval {
		return nil, errors.New("faketcp timeouts and retry limit are invalid")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.InitialSequence == nil {
		return nil, errors.New("faketcp initial sequence source is required")
	}
	if options.Window == 0 {
		options.Window = 65535
	}
	return &Engine{opts: options, sessions: make(map[abi.FakeTCPSessionKey]*session)}, nil
}

// Outbound observes a UDP datagram before the BPF established path can encode
// it. The packet copy is retained only within all three configured limits.
func (e *Engine) Outbound(flow abi.FakeTCPSessionKey, packet []byte) ([]Action, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.validateFlow(flow); err != nil {
		return nil, err
	}
	now := e.opts.Now()
	s := e.sessions[flow]
	checkpoint := e.checkpoint(s)
	if s != nil && s.state == abi.FakeTCPStateEstablished {
		s.lastActivity = now
		s.nextKeepalive = now.Add(e.opts.KeepaliveInterval)
		if err := e.sync(flow, s); err != nil {
			e.restore(flow, checkpoint)
			return []Action{{Kind: ActionDrop, Flow: flow, Reason: "session-store-unavailable"}}, err
		}
		return []Action{{Kind: ActionForward, Flow: flow}}, nil
	}
	created := false
	if s == nil {
		if len(e.sessions) >= e.opts.SessionCapacity {
			return []Action{{Kind: ActionDrop, Flow: flow, Reason: "session-capacity"}}, nil
		}
		isn := e.opts.InitialSequence()
		s = &session{
			state:        abi.FakeTCPStateSynSent,
			localISN:     isn,
			txSequence:   isn + 1,
			lastActivity: now,
			nextRetry:    now.Add(e.opts.HandshakeTimeout),
			retries:      1,
		}
		e.sessions[flow] = s
		created = true
	}
	queued := e.enqueue(s, packet)
	if err := e.sync(flow, s); err != nil {
		e.restore(flow, checkpoint)
		return []Action{{Kind: ActionDrop, Flow: flow, Reason: "session-store-unavailable"}}, err
	}
	actions := make([]Action, 0, 2)
	if created {
		actions = append(actions, e.control(flow, s, FlagSYN, s.localISN, 0, "initial-handshake"))
	}
	if !queued {
		actions = append(actions, Action{Kind: ActionDrop, Flow: flow, Reason: "pending-capacity"})
	}
	return actions, nil
}

func (e *Engine) Inbound(flow abi.FakeTCPSessionKey, seg Segment) ([]Action, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.validateFlow(flow); err != nil {
		return nil, err
	}
	now := e.opts.Now()
	s := e.sessions[flow]
	checkpoint := e.checkpoint(s)
	if seg.Flags&(FlagRST|FlagFIN) != 0 {
		if s == nil {
			return []Action{{Kind: ActionDrop, Flow: flow, Reason: "unknown-close"}}, nil
		}
		if err := e.deleteStore(flow); err != nil {
			return []Action{{Kind: ActionDrop, Flow: flow, Reason: "session-store-unavailable"}}, err
		}
		e.remove(flow, s)
		return []Action{{Kind: ActionClose, Flow: flow, Reason: "peer-close"}}, nil
	}
	if s == nil {
		if seg.Flags != FlagSYN {
			// Silent drop resists unauthenticated active probes and avoids
			// allocating state for arbitrary ACK/data packets.
			return []Action{{Kind: ActionDrop, Flow: flow, Reason: "unknown-flow"}}, nil
		}
		if len(e.sessions) >= e.opts.SessionCapacity {
			return []Action{{Kind: ActionDrop, Flow: flow, Reason: "session-capacity"}}, nil
		}
		isn := e.opts.InitialSequence()
		s = &session{
			state:        abi.FakeTCPStateSynReceived,
			localISN:     isn,
			remoteISN:    seg.Sequence,
			txSequence:   isn + 1,
			rxSequence:   seg.Sequence + 1,
			lastActivity: now,
			nextRetry:    now.Add(e.opts.HandshakeTimeout),
			retries:      1,
		}
		e.sessions[flow] = s
		if err := e.sync(flow, s); err != nil {
			e.restore(flow, checkpoint)
			return []Action{{Kind: ActionDrop, Flow: flow, Reason: "session-store-unavailable"}}, err
		}
		return []Action{e.control(flow, s, FlagSYN|FlagACK, s.localISN, s.rxSequence, "accept-syn")}, nil
	}

	s.lastActivity = now
	s.nextKeepalive = now.Add(e.opts.KeepaliveInterval)
	var actions []Action
	switch s.state {
	case abi.FakeTCPStateSynSent:
		switch {
		case seg.Flags&(FlagSYN|FlagACK) == FlagSYN|FlagACK && seg.Acknowledgement == s.txSequence:
			s.remoteISN = seg.Sequence
			s.rxSequence = seg.Sequence + 1
			s.state = abi.FakeTCPStateEstablished
			actions = append(actions, e.control(flow, s, FlagACK, s.txSequence, s.rxSequence, "complete-handshake"))
			actions = append(actions, e.release(flow, s)...)
		case seg.Flags == FlagSYN:
			// Simultaneous open: retain our ISN and acknowledge the peer.
			s.remoteISN = seg.Sequence
			s.rxSequence = seg.Sequence + 1
			s.state = abi.FakeTCPStateSynReceived
			actions = append(actions, e.control(flow, s, FlagSYN|FlagACK, s.localISN, s.rxSequence, "simultaneous-open"))
		default:
			actions = append(actions, Action{Kind: ActionDrop, Flow: flow, Reason: "invalid-syn-sent-segment"})
		}
	case abi.FakeTCPStateSynReceived:
		switch {
		case seg.Flags == FlagSYN && seg.Sequence == s.remoteISN:
			actions = append(actions, e.control(flow, s, FlagSYN|FlagACK, s.localISN, s.rxSequence, "duplicate-syn"))
		case seg.Flags&FlagACK != 0 && seg.Acknowledgement == s.txSequence:
			s.state = abi.FakeTCPStateEstablished
			actions = append(actions, e.release(flow, s)...)
		default:
			actions = append(actions, Action{Kind: ActionDrop, Flow: flow, Reason: "invalid-syn-received-segment"})
		}
	case abi.FakeTCPStateEstablished:
		if seg.Flags&FlagSYN != 0 {
			actions = append(actions, Action{Kind: ActionDrop, Flow: flow, Reason: "syn-on-established"})
		} else {
			if end := seg.Sequence + seg.PayloadLength; int32(end-s.rxSequence) > 0 {
				s.rxSequence = end
			}
			actions = append(actions, Action{Kind: ActionForward, Flow: flow})
		}
	default:
		actions = append(actions, Action{Kind: ActionDrop, Flow: flow, Reason: "invalid-state"})
	}
	if err := e.sync(flow, s); err != nil {
		e.restore(flow, checkpoint)
		return []Action{{Kind: ActionDrop, Flow: flow, Reason: "session-store-unavailable"}}, err
	}
	return actions, nil
}

func (e *Engine) Tick() ([]Action, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.opts.Now()
	var actions []Action
	var errs []error
	for flow, s := range e.sessions {
		switch s.state {
		case abi.FakeTCPStateSynSent, abi.FakeTCPStateSynReceived:
			if now.Before(s.nextRetry) {
				continue
			}
			if s.retries >= e.opts.HandshakeRetries {
				if err := e.deleteStore(flow); err != nil {
					errs = append(errs, err)
					actions = append(actions, Action{Kind: ActionDrop, Flow: flow, Reason: "session-store-unavailable"})
					continue
				}
				e.remove(flow, s)
				actions = append(actions, Action{Kind: ActionClose, Flow: flow, Reason: "handshake-timeout"})
				continue
			}
			checkpoint := e.checkpoint(s)
			s.retries++
			s.nextRetry = now.Add(e.opts.HandshakeTimeout)
			flags, ack := uint8(FlagSYN), uint32(0)
			if s.state == abi.FakeTCPStateSynReceived {
				flags, ack = FlagSYN|FlagACK, s.rxSequence
			}
			if err := e.sync(flow, s); err != nil {
				e.restore(flow, checkpoint)
				errs = append(errs, err)
				actions = append(actions, Action{Kind: ActionDrop, Flow: flow, Reason: "session-store-unavailable"})
				continue
			}
			actions = append(actions, e.control(flow, s, flags, s.localISN, ack, "handshake-retry"))
		case abi.FakeTCPStateEstablished:
			if now.Sub(s.lastActivity) >= e.opts.IdleTimeout {
				if err := e.deleteStore(flow); err != nil {
					errs = append(errs, err)
					actions = append(actions, Action{Kind: ActionDrop, Flow: flow, Reason: "session-store-unavailable"})
					continue
				}
				e.remove(flow, s)
				actions = append(actions, Action{Kind: ActionClose, Flow: flow, Reason: "idle-timeout"})
				continue
			}
			if !now.Before(s.nextKeepalive) {
				checkpoint := e.checkpoint(s)
				s.nextKeepalive = now.Add(e.opts.KeepaliveInterval)
				if err := e.sync(flow, s); err != nil {
					e.restore(flow, checkpoint)
					errs = append(errs, err)
					actions = append(actions, Action{Kind: ActionDrop, Flow: flow, Reason: "session-store-unavailable"})
					continue
				}
				actions = append(actions, e.control(flow, s, FlagACK, s.txSequence-1, s.rxSequence, "keepalive"))
			}
		}
	}
	return actions, errors.Join(errs...)
}

// AdvanceGeneration explicitly drains all live sessions. The loader cannot
// silently carry keys across generation changes because rules, profiles and
// peers may have changed; callers must observe the returned close actions and
// allow WireGuard/QUIC to re-handshake under the new generation.
func (e *Engine) AdvanceGeneration(generation uint64) ([]Action, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if generation == 0 || generation == e.opts.Generation {
		return nil, fmt.Errorf("new faketcp generation must be non-zero and differ from %d", e.opts.Generation)
	}
	actions := make([]Action, 0, len(e.sessions))
	var errs []error
	for flow, s := range e.sessions {
		if err := e.deleteStore(flow); err != nil {
			errs = append(errs, err)
			continue
		}
		e.remove(flow, s)
		actions = append(actions, Action{Kind: ActionClose, Flow: flow, Reason: "generation-drain-rehandshake"})
	}
	if len(e.sessions) == 0 {
		e.opts.Generation = generation
	}
	return actions, errors.Join(errs...)
}

func (e *Engine) Snapshot(flow abi.FakeTCPSessionKey) (SessionSnapshot, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.sessions[flow]
	if s == nil {
		return SessionSnapshot{}, false
	}
	return SessionSnapshot{
		State:          s.state,
		TXSequence:     s.txSequence,
		RXSequence:     s.rxSequence,
		PendingPackets: len(s.pending),
		PendingBytes:   s.pendingBytes,
		LastActivity:   s.lastActivity,
	}, true
}

func (e *Engine) validateFlow(flow abi.FakeTCPSessionKey) error {
	if flow.Generation != e.opts.Generation || flow.LocalIPv4 == 0 || flow.RemoteIPv4 == 0 ||
		flow.UnderlayIndex == 0 || flow.LocalPort == 0 || flow.RemotePort == 0 {
		return errors.New("faketcp flow must use the active generation and non-zero IPv4/port/underlay fields")
	}
	return nil
}

func (e *Engine) checkpoint(s *session) engineCheckpoint {
	checkpoint := engineCheckpoint{
		existed:      s != nil,
		pendingFlows: e.pendingFlows,
		pendingBytes: e.pendingBytes,
	}
	if s != nil {
		copySession := *s
		copySession.pending = append([][]byte(nil), s.pending...)
		checkpoint.session = &copySession
	}
	return checkpoint
}

func (e *Engine) restore(flow abi.FakeTCPSessionKey, checkpoint engineCheckpoint) {
	e.pendingFlows = checkpoint.pendingFlows
	e.pendingBytes = checkpoint.pendingBytes
	if !checkpoint.existed {
		delete(e.sessions, flow)
		return
	}
	e.sessions[flow] = checkpoint.session
}

func (e *Engine) enqueue(s *session, packet []byte) bool {
	if len(packet) == 0 || len(s.pending) >= e.opts.MaxPendingPacketsPerFlow ||
		e.pendingBytes+len(packet) > e.opts.MaxPendingBytes {
		return false
	}
	if len(s.pending) == 0 {
		if e.pendingFlows >= e.opts.MaxPendingFlows {
			return false
		}
		e.pendingFlows++
	}
	copyPacket := append([]byte(nil), packet...)
	s.pending = append(s.pending, copyPacket)
	s.pendingBytes += len(copyPacket)
	e.pendingBytes += len(copyPacket)
	return true
}

func (e *Engine) release(flow abi.FakeTCPSessionKey, s *session) []Action {
	if len(s.pending) == 0 {
		return nil
	}
	packets := s.pending
	e.pendingFlows--
	e.pendingBytes -= s.pendingBytes
	s.pending = nil
	s.pendingBytes = 0
	return []Action{{Kind: ActionReleasePending, Flow: flow, Packets: packets}}
}

func (e *Engine) remove(flow abi.FakeTCPSessionKey, s *session) {
	if len(s.pending) != 0 {
		e.pendingFlows--
		e.pendingBytes -= s.pendingBytes
	}
	delete(e.sessions, flow)
}

func (e *Engine) control(flow abi.FakeTCPSessionKey, s *session, flags uint8, seq, ack uint32, reason string) Action {
	return Action{
		Kind:    ActionSendControl,
		Flow:    flow,
		Control: ControlPacket{Flags: flags, Sequence: seq, Acknowledgement: ack, Window: e.opts.Window},
		Reason:  reason,
	}
}

func (e *Engine) sync(flow abi.FakeTCPSessionKey, s *session) error {
	if e.opts.Store == nil {
		return nil
	}
	return e.opts.Store.Upsert(flow, abi.FakeTCPSessionValue{
		Generation: flow.Generation,
		// BPF uses monotonic bpf_ktime_get_ns(). Userspace cannot safely
		// synthesize that clock domain, so zero means "not yet observed by
		// the fast path" and the first packet replaces it.
		LastSeenNanos: 0,
		TXSequence:    s.txSequence,
		RXSequence:    s.rxSequence,
		LocalISN:      s.localISN,
		RemoteISN:     s.remoteISN,
		Window:        e.opts.Window,
		State:         s.state,
	})
}

func (e *Engine) deleteStore(flow abi.FakeTCPSessionKey) error {
	if e.opts.Store == nil {
		return nil
	}
	return e.opts.Store.Delete(flow)
}
