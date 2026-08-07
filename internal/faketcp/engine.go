// Package faketcp contains the userspace slow-path state machine for the
// experimental FakeTCP transport. It intentionally implements TCP-shaped
// signalling, not TCP reliability or byte-stream semantics: the UDP payload
// remains independently recoverable by WireGuard or QUIC.
package faketcp

import (
	"container/list"
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

	// Each admitted SYN performs at most this many expiry visits. This keeps
	// attacker-controlled ingress work independent of the 16K ledger size.
	synSourcePruneBudget = 4
)

type Options struct {
	Generation               uint64
	SessionCapacity          int
	MaxHalfOpenSessions      int
	MaxHalfOpenPerSource     int
	SYNRateInterval          time.Duration
	SYNBurst                 int
	SYNBurstPerSource        int
	SYNSourceLedgerCapacity  int
	SYNSourceLedgerTTL       time.Duration
	MaxPendingFlows          int
	MaxPendingPacketsPerFlow int
	MaxPendingBytes          int
	HandshakeTimeout         time.Duration
	HandshakeRetries         int
	KeepaliveInterval        time.Duration
	IdleTimeout              time.Duration
	Window                   uint16
	Now                      func() time.Time
	MonotonicClock           MonotonicClock
	InitialSequence          func() uint32
	Store                    SessionStore
}

// SessionStore exposes the established fast-path state without granting the
// userspace engine an overwrite operation. InsertEstablished is used exactly
// once at handshake completion. From that point BPF owns sequence/activity
// fields; userspace may only read them or request a compare-and-delete.
type SessionStore interface {
	InsertEstablished(abi.FakeTCPSessionKey, abi.FakeTCPSessionValue) error
	LookupEstablished(abi.FakeTCPSessionKey) (abi.FakeTCPSessionValue, bool, error)
	DeleteEstablishedIfUnchanged(abi.FakeTCPSessionKey, abi.FakeTCPSessionValue) (bool, error)
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
	WGID    uint32
	Control ControlPacket
	Packets []PendingPacket
	Reason  string
}

// PendingPacket is a pre-transform IPv4 packet captured by BPF, with complete
// checksums materialized by Controller. A raw sender must re-inject it with
// FWMark on Flow.UnderlayIndex so it traverses the ordinary
// type-word/XOR/FakeTCP egress pipeline exactly once.
type PendingPacket struct {
	Data         []byte
	FWMark       uint32
	WGID         uint32
	CaptureNanos uint64
}

type SessionSnapshot struct {
	State          uint8
	TXSequence     uint32
	RXSequence     uint32
	LastSeenNanos  uint64
	PendingPackets int
	PendingBytes   int
	LastActivity   time.Time
}

type session struct {
	state         uint8
	wgID          uint32
	localISN      uint32
	remoteISN     uint32
	txSequence    uint32
	rxSequence    uint32
	lastActivity  time.Time
	nextRetry     time.Time
	nextKeepalive time.Time
	retries       int
	pending       []PendingPacket
	pendingBytes  int
	halfOpenHeld  bool
	synSource     synSourceKey
}

type synSourceKey struct {
	remoteIPv4    uint32
	underlayIndex uint32
}

type synSourceState struct {
	bucket       tokenBucket
	halfOpen     int
	lastActivity time.Time
	lruElement   *list.Element
}

type tokenBucket struct {
	tokens      int
	lastRefill  time.Time
	initialized bool
}

type Engine struct {
	mu           sync.Mutex
	opts         Options
	sessions     map[abi.FakeTCPSessionKey]*session
	pendingFlows int
	pendingBytes int
	halfOpen     int
	globalSYNs   tokenBucket
	// admissionEpoch is local to one Engine lifetime. New engines begin with
	// zero tokens at this epoch; recreation can only discard accumulated
	// budget and can never mint a fresh burst.
	admissionEpoch time.Time
	synSources     map[synSourceKey]*synSourceState
	synSourceLRU   *list.List
	// Counted under mu and used by complexity-contract tests. It also makes
	// accidental replacement of bounded pruning with a full scan observable.
	synSourcePruneVisits uint64
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
	if options.MaxHalfOpenSessions <= 0 || options.MaxHalfOpenSessions >= options.SessionCapacity ||
		options.MaxHalfOpenPerSource <= 0 || options.MaxHalfOpenPerSource > options.MaxHalfOpenSessions ||
		options.SYNRateInterval <= 0 || options.SYNBurst <= 0 ||
		options.SYNBurstPerSource <= 0 || options.SYNBurstPerSource > options.SYNBurst ||
		options.SYNSourceLedgerCapacity < options.MaxHalfOpenSessions ||
		options.SYNSourceLedgerTTL < options.SYNRateInterval {
		return nil, errors.New("faketcp half-open and SYN-rate limits are invalid")
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
	if options.MonotonicClock == nil {
		return nil, errors.New("faketcp CLOCK_MONOTONIC source is required")
	}
	if domain := options.MonotonicClock.Domain(); domain != BPFMonotonicClockDomain {
		return nil, fmt.Errorf("faketcp monotonic clock domain %q does not match BPF domain %q", domain, BPFMonotonicClockDomain)
	}
	if options.Store == nil {
		return nil, errors.New("faketcp established session store is required")
	}
	if options.Window == 0 {
		options.Window = 65535
	}
	admissionEpoch := options.Now()
	return &Engine{
		opts:           options,
		sessions:       make(map[abi.FakeTCPSessionKey]*session),
		globalSYNs:     tokenBucket{lastRefill: admissionEpoch, initialized: true},
		admissionEpoch: admissionEpoch,
		synSources:     make(map[synSourceKey]*synSourceState),
		synSourceLRU:   list.New(),
	}, nil
}

// Outbound observes a UDP datagram before the BPF established path can encode
// it. The packet copy is retained only within all three configured limits.
func (e *Engine) Outbound(flow abi.FakeTCPSessionKey, packet []byte) ([]Action, error) {
	return e.outbound(flow, PendingPacket{Data: packet}, false)
}

// HandlePacketEvent accepts the fixed upper-bound ABI form used by low-level
// tests. Production ring-buffer input goes through Controller so packet shape
// and offload checksums are validated before reaching the state machine.
func (e *Engine) HandlePacketEvent(event abi.FakeTCPPacketEvent) ([]Action, error) {
	length := int(event.Event.PacketLength)
	if length <= 0 || length > len(event.Packet) {
		return nil, fmt.Errorf("faketcp captured packet length %d is invalid", length)
	}
	return e.handleCapturedPacket(event.Event, event.Packet[:length])
}

// handleCapturedPacket avoids materializing the fixed maximum-size ABI record
// when a ring-buffer reader already owns the compact packet sample.
func (e *Engine) handleCapturedPacket(event abi.FakeTCPEvent, packet []byte) ([]Action, error) {
	if event.Type != abi.FakeTCPEventNeedHandshake {
		return nil, fmt.Errorf("faketcp packet event type %d is not NEED_HANDSHAKE", event.Type)
	}
	if len(packet) == 0 || len(packet) != int(event.PacketLength) || len(packet) > abi.FakeTCPMaxCapturedPacket {
		return nil, fmt.Errorf("faketcp captured packet body has %d bytes for declared length %d", len(packet), event.PacketLength)
	}
	return e.outbound(event.Key, PendingPacket{
		Data:         packet,
		FWMark:       event.FWMark,
		WGID:         event.WGID,
		CaptureNanos: event.TimestampNanos,
	}, true)
}

func (e *Engine) outbound(flow abi.FakeTCPSessionKey, packet PendingPacket, alreadyDropped bool) ([]Action, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.validateFlow(flow); err != nil {
		return nil, err
	}
	now := e.opts.Now()
	s := e.sessions[flow]
	if s != nil && s.state == abi.FakeTCPStateEstablished {
		if packet.WGID != 0 && s.wgID != 0 && packet.WGID != s.wgID {
			return []Action{{Kind: ActionDrop, Flow: flow, Reason: "wg-id-mismatch"}}, nil
		}
		if s.wgID == 0 {
			s.wgID = packet.WGID
		}
		_, found, err := e.lookupEstablished(flow, s)
		if err != nil {
			return []Action{{Kind: ActionDrop, Flow: flow, Reason: "session-store-unavailable"}}, err
		}
		if !found {
			e.remove(flow, s)
			return []Action{{Kind: ActionClose, Flow: flow, Reason: "fast-session-missing"}}, nil
		}
		s.nextKeepalive = now.Add(e.opts.KeepaliveInterval)
		if alreadyDropped {
			copyPacket := packet
			copyPacket.Data = append([]byte(nil), packet.Data...)
			return []Action{{Kind: ActionReleasePending, Flow: flow, Packets: []PendingPacket{copyPacket}}}, nil
		}
		return []Action{{Kind: ActionForward, Flow: flow}}, nil
	}
	created := false
	if s == nil {
		if len(e.sessions) >= e.opts.SessionCapacity {
			return []Action{{Kind: ActionDrop, Flow: flow, Reason: "session-capacity"}}, nil
		}
		if e.halfOpen >= e.opts.MaxHalfOpenSessions {
			return []Action{{Kind: ActionDrop, Flow: flow, Reason: "half-open-capacity"}}, nil
		}
		isn := e.opts.InitialSequence()
		s = &session{
			state:        abi.FakeTCPStateSynSent,
			wgID:         packet.WGID,
			localISN:     isn,
			txSequence:   isn + 1,
			lastActivity: now,
			nextRetry:    now.Add(e.opts.HandshakeTimeout),
			retries:      1,
			halfOpenHeld: true,
		}
		e.halfOpen++
		e.sessions[flow] = s
		created = true
	}
	if s.wgID == 0 {
		s.wgID = packet.WGID
	} else if packet.WGID != 0 && packet.WGID != s.wgID {
		return []Action{{Kind: ActionDrop, Flow: flow, Reason: "wg-id-mismatch"}}, nil
	}
	queued := e.enqueue(s, packet)
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
	return e.inbound(flow, seg, 0, nil)
}

// InboundWithWGID preserves the listener identity carried by the BPF event so
// retries and replies are sent through the same configured WireGuard path.
func (e *Engine) InboundWithWGID(flow abi.FakeTCPSessionKey, seg Segment, wgID uint32) ([]Action, error) {
	return e.inbound(flow, seg, wgID, nil)
}

// InboundValidatedControl is the only path that may remove an established
// session in response to peer RST/FIN. The opaque value can only be produced
// by ValidateIPv4TCPControl from the complete packet and the exact BPF-owned
// session snapshot used for its sequence/window checks.
func (e *Engine) InboundValidatedControl(control ValidatedControl, wgID uint32) ([]Action, error) {
	return e.inbound(control.flow, control.segment, wgID, &control)
}

func (e *Engine) inbound(flow abi.FakeTCPSessionKey, seg Segment, wgID uint32, validated *ValidatedControl) ([]Action, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.validateFlow(flow); err != nil {
		return nil, err
	}
	now := e.opts.Now()
	s := e.sessions[flow]
	checkpoint := e.checkpoint(s)
	var synSource synSourceKey
	if seg.Flags&FlagSYN != 0 {
		var rejection string
		synSource, rejection = e.observeSYN(flow, now)
		if rejection != "" {
			return []Action{{Kind: ActionDrop, Flow: flow, Reason: rejection}}, nil
		}
	}
	if s != nil && wgID != 0 && s.wgID != 0 && wgID != s.wgID {
		return []Action{{Kind: ActionDrop, Flow: flow, Reason: "wg-id-mismatch"}}, nil
	}
	if seg.Flags&(FlagRST|FlagFIN) != 0 {
		if s == nil {
			return []Action{{Kind: ActionDrop, Flow: flow, Reason: "unknown-close"}}, nil
		}
		if s.state == abi.FakeTCPStateEstablished {
			if validated == nil || validated.flow != flow || validated.segment != seg {
				return []Action{{Kind: ActionDrop, Flow: flow, Reason: "unvalidated-close"}}, nil
			}
			value, found, err := e.lookupEstablished(flow, s)
			if err != nil {
				return []Action{{Kind: ActionDrop, Flow: flow, Reason: "session-store-unavailable"}}, err
			}
			if found {
				if value != validated.session {
					return []Action{{Kind: ActionDrop, Flow: flow, Reason: "fast-session-raced"}}, nil
				}
				deleted, err := e.opts.Store.DeleteEstablishedIfUnchanged(flow, validated.session)
				if err != nil {
					return []Action{{Kind: ActionDrop, Flow: flow, Reason: "session-store-unavailable"}}, err
				}
				if !deleted {
					return []Action{{Kind: ActionDrop, Flow: flow, Reason: "fast-session-raced"}}, nil
				}
			}
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
		rejection := e.reserveInboundHalfOpen(synSource)
		if rejection != "" {
			return []Action{{Kind: ActionDrop, Flow: flow, Reason: rejection}}, nil
		}
		isn := e.opts.InitialSequence()
		s = &session{
			state:        abi.FakeTCPStateSynReceived,
			wgID:         wgID,
			localISN:     isn,
			remoteISN:    seg.Sequence,
			txSequence:   isn + 1,
			rxSequence:   seg.Sequence + 1,
			lastActivity: now,
			nextRetry:    now.Add(e.opts.HandshakeTimeout),
			retries:      1,
			halfOpenHeld: true,
			synSource:    synSource,
		}
		e.sessions[flow] = s
		return []Action{e.control(flow, s, FlagSYN|FlagACK, s.localISN, s.rxSequence, "accept-syn")}, nil
	}
	if s.wgID == 0 {
		s.wgID = wgID
	}

	s.lastActivity = now
	s.nextKeepalive = now.Add(e.opts.KeepaliveInterval)
	var actions []Action
	becameEstablished := false
	switch s.state {
	case abi.FakeTCPStateSynSent:
		switch {
		case seg.Flags&(FlagSYN|FlagACK) == FlagSYN|FlagACK && seg.Acknowledgement == s.txSequence:
			s.remoteISN = seg.Sequence
			s.rxSequence = seg.Sequence + 1
			s.state = abi.FakeTCPStateEstablished
			becameEstablished = true
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
			becameEstablished = true
			actions = append(actions, e.release(flow, s)...)
		default:
			actions = append(actions, Action{Kind: ActionDrop, Flow: flow, Reason: "invalid-syn-received-segment"})
		}
	case abi.FakeTCPStateEstablished:
		if seg.Flags&FlagSYN != 0 {
			actions = append(actions, Action{Kind: ActionDrop, Flow: flow, Reason: "syn-on-established"})
		} else {
			_, found, err := e.lookupEstablished(flow, s)
			if err != nil {
				e.restore(flow, checkpoint)
				return []Action{{Kind: ActionDrop, Flow: flow, Reason: "session-store-unavailable"}}, err
			}
			if !found {
				e.remove(flow, s)
				return []Action{{Kind: ActionClose, Flow: flow, Reason: "fast-session-missing"}}, nil
			}
			actions = append(actions, Action{Kind: ActionForward, Flow: flow})
		}
	default:
		actions = append(actions, Action{Kind: ActionDrop, Flow: flow, Reason: "invalid-state"})
	}
	if becameEstablished {
		if err := e.insertEstablished(flow, s); err != nil {
			e.restore(flow, checkpoint)
			return []Action{{Kind: ActionDrop, Flow: flow, Reason: "session-store-unavailable"}}, err
		}
		e.releaseHalfOpen(s)
	}
	return actions, nil
}

func (e *Engine) Tick() ([]Action, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.opts.Now()
	nowMonotonic, err := e.opts.MonotonicClock.NowNanos()
	if err != nil {
		return nil, fmt.Errorf("read faketcp %s clock: %w", BPFMonotonicClockDomain, err)
	}
	var actions []Action
	var errs []error
	for flow, s := range e.sessions {
		switch s.state {
		case abi.FakeTCPStateSynSent, abi.FakeTCPStateSynReceived:
			if now.Before(s.nextRetry) {
				continue
			}
			if s.retries >= e.opts.HandshakeRetries {
				e.remove(flow, s)
				actions = append(actions, Action{Kind: ActionClose, Flow: flow, Reason: "handshake-timeout"})
				continue
			}
			s.retries++
			s.nextRetry = now.Add(e.opts.HandshakeTimeout)
			flags, ack := uint8(FlagSYN), uint32(0)
			if s.state == abi.FakeTCPStateSynReceived {
				flags, ack = FlagSYN|FlagACK, s.rxSequence
			}
			actions = append(actions, e.control(flow, s, flags, s.localISN, ack, "handshake-retry"))
		case abi.FakeTCPStateEstablished:
			value, found, err := e.lookupEstablished(flow, s)
			if err != nil {
				errs = append(errs, err)
				actions = append(actions, Action{Kind: ActionDrop, Flow: flow, Reason: "session-store-unavailable"})
				continue
			}
			if !found {
				e.remove(flow, s)
				actions = append(actions, Action{Kind: ActionClose, Flow: flow, Reason: "fast-session-missing"})
				continue
			}
			idle := nowMonotonic >= value.LastSeenNanos &&
				nowMonotonic-value.LastSeenNanos >= uint64(e.opts.IdleTimeout)
			if idle {
				deleted, err := e.opts.Store.DeleteEstablishedIfUnchanged(flow, value)
				if err != nil {
					errs = append(errs, err)
					actions = append(actions, Action{Kind: ActionDrop, Flow: flow, Reason: "session-store-unavailable"})
					continue
				}
				if !deleted {
					// BPF advanced the fast state after our lookup. A later tick
					// re-reads LastSeenNanos; this session is demonstrably active.
					continue
				}
				e.remove(flow, s)
				actions = append(actions, Action{Kind: ActionClose, Flow: flow, Reason: "idle-timeout"})
				continue
			}
			if !now.Before(s.nextKeepalive) {
				s.nextKeepalive = now.Add(e.opts.KeepaliveInterval)
				actions = append(actions, e.controlEstablished(flow, s, value,
					FlagACK, value.TXSequence-1, value.RXSequence, "keepalive"))
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
		if s.state == abi.FakeTCPStateEstablished {
			value, found, err := e.lookupEstablished(flow, s)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if found {
				deleted, err := e.opts.Store.DeleteEstablishedIfUnchanged(flow, value)
				if err != nil {
					errs = append(errs, err)
					continue
				}
				if !deleted {
					continue
				}
			}
		}
		e.remove(flow, s)
		actions = append(actions, Action{Kind: ActionClose, Flow: flow, Reason: "generation-drain-rehandshake"})
	}
	if len(e.sessions) == 0 {
		e.opts.Generation = generation
	}
	return actions, errors.Join(errs...)
}

func (e *Engine) Snapshot(flow abi.FakeTCPSessionKey) (SessionSnapshot, bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.sessions[flow]
	if s == nil {
		return SessionSnapshot{}, false, nil
	}
	lastSeenNanos := uint64(0)
	if s.state == abi.FakeTCPStateEstablished {
		value, found, err := e.lookupEstablished(flow, s)
		if err != nil {
			return SessionSnapshot{}, true, err
		}
		if !found {
			return SessionSnapshot{}, false, nil
		}
		lastSeenNanos = value.LastSeenNanos
	}
	return SessionSnapshot{
		State:          s.state,
		TXSequence:     s.txSequence,
		RXSequence:     s.rxSequence,
		LastSeenNanos:  lastSeenNanos,
		PendingPackets: len(s.pending),
		PendingBytes:   s.pendingBytes,
		LastActivity:   s.lastActivity,
	}, true, nil
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
		copySession.pending = append([]PendingPacket(nil), s.pending...)
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

func (e *Engine) enqueue(s *session, packet PendingPacket) bool {
	if len(packet.Data) == 0 || len(s.pending) >= e.opts.MaxPendingPacketsPerFlow ||
		e.pendingBytes+len(packet.Data) > e.opts.MaxPendingBytes {
		return false
	}
	if len(s.pending) == 0 {
		if e.pendingFlows >= e.opts.MaxPendingFlows {
			return false
		}
		e.pendingFlows++
	}
	copyPacket := packet
	copyPacket.Data = append([]byte(nil), packet.Data...)
	s.pending = append(s.pending, copyPacket)
	s.pendingBytes += len(copyPacket.Data)
	e.pendingBytes += len(copyPacket.Data)
	return true
}

// observeSYN applies the O(1) global limiter before any source-ledger lookup,
// expiry work or allocation. A globally rejected flood therefore cannot
// consume source memory or turn the bounded ledger into a CPU multiplier.
func (e *Engine) observeSYN(flow abi.FakeTCPSessionKey, now time.Time) (synSourceKey, string) {
	refillTokenBucket(&e.globalSYNs, now, e.opts.SYNRateInterval, e.opts.SYNBurst)
	if e.globalSYNs.tokens == 0 {
		return synSourceKey{}, "syn-rate-global"
	}
	// Never refund this token after a per-source, ledger or half-open failure.
	e.globalSYNs.tokens--

	key := synSourceKey{remoteIPv4: flow.RemoteIPv4, underlayIndex: flow.UnderlayIndex}
	source, rejection := e.lookupOrCreateSYNSource(key, now)
	if rejection != "" {
		return synSourceKey{}, rejection
	}
	refillTokenBucket(&source.bucket, now, e.opts.SYNRateInterval, e.opts.SYNBurstPerSource)
	if source.bucket.tokens == 0 {
		return synSourceKey{}, "syn-rate-source"
	}
	source.bucket.tokens--
	return key, ""
}

func (e *Engine) reserveInboundHalfOpen(key synSourceKey) string {
	if e.halfOpen >= e.opts.MaxHalfOpenSessions {
		return "half-open-capacity"
	}
	source := e.synSources[key]
	if source == nil {
		return "syn-source-ledger-missing"
	}
	if source.halfOpen >= e.opts.MaxHalfOpenPerSource {
		return "half-open-source-capacity"
	}
	source.halfOpen++
	e.halfOpen++
	return ""
}

func (e *Engine) lookupOrCreateSYNSource(key synSourceKey, now time.Time) (*synSourceState, string) {
	e.pruneExpiredSYNSources(now, synSourcePruneBudget)
	if source := e.synSources[key]; source != nil {
		e.touchSYNSource(source, now)
		return source, ""
	}
	if len(e.synSources) >= e.opts.SYNSourceLedgerCapacity {
		return nil, "syn-source-ledger-capacity"
	}
	// New sources share the engine admission epoch. A source first observed
	// after sufficient uptime may use accrued budget, but recreating Engine
	// resets that epoch and never grants an immediate burst.
	source := &synSourceState{
		bucket:       tokenBucket{lastRefill: e.admissionEpoch, initialized: true},
		lastActivity: now,
	}
	source.lruElement = e.synSourceLRU.PushFront(key)
	e.synSources[key] = source
	return source, ""
}

func (e *Engine) touchSYNSource(source *synSourceState, now time.Time) {
	source.lastActivity = now
	if source.lruElement != nil {
		e.synSourceLRU.MoveToFront(source.lruElement)
	}
}

func (e *Engine) pruneExpiredSYNSources(now time.Time, budget int) {
	for visited := 0; visited < budget; visited++ {
		element := e.synSourceLRU.Back()
		if element == nil {
			return
		}
		e.synSourcePruneVisits++
		key := element.Value.(synSourceKey)
		source := e.synSources[key]
		if source == nil {
			e.synSourceLRU.Remove(element)
			continue
		}
		if now.Before(source.lastActivity.Add(e.opts.SYNSourceLedgerTTL)) {
			// LRU order is also last-activity order, so every newer entry is
			// necessarily unexpired.
			return
		}
		if source.halfOpen == 0 {
			delete(e.synSources, key)
			e.synSourceLRU.Remove(element)
			continue
		}
		// Active state cannot be evicted. Refresh/move it so one expired active
		// tail cannot permanently obstruct amortized cleanup behind it.
		e.touchSYNSource(source, now)
	}
}

func refillTokenBucket(bucket *tokenBucket, now time.Time, interval time.Duration, burst int) {
	if !bucket.initialized {
		// Fail safe for zero-value buckets restored without a checkpoint. The
		// first observation starts time accounting at zero budget.
		bucket.initialized = true
		bucket.lastRefill = now
		return
	}
	if now.Before(bucket.lastRefill.Add(interval)) {
		return
	}
	steps := int(now.Sub(bucket.lastRefill) / interval)
	if steps >= burst {
		bucket.tokens = burst
		bucket.lastRefill = now
		return
	}
	bucket.tokens = min(burst, bucket.tokens+steps)
	bucket.lastRefill = bucket.lastRefill.Add(time.Duration(steps) * interval)
}

func (e *Engine) releaseHalfOpen(s *session) {
	if !s.halfOpenHeld {
		return
	}
	s.halfOpenHeld = false
	if e.halfOpen > 0 {
		e.halfOpen--
	}
	if s.synSource.remoteIPv4 == 0 {
		return
	}
	source := e.synSources[s.synSource]
	if source == nil {
		return
	}
	if source.halfOpen > 0 {
		source.halfOpen--
	}
	// Releasing half-open state never returns tokens or deletes history. Keep
	// the ledger entry for a full TTL from release so SYN->RST/success loops
	// cannot reset the source bucket.
	e.touchSYNSource(source, e.opts.Now())
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
	e.releaseHalfOpen(s)
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
		WGID:    s.wgID,
		Control: ControlPacket{Flags: flags, Sequence: seq, Acknowledgement: ack, Window: e.opts.Window},
		Reason:  reason,
	}
}

func (e *Engine) controlEstablished(flow abi.FakeTCPSessionKey, s *session,
	value abi.FakeTCPSessionValue, flags uint8, seq, ack uint32, reason string) Action {
	window := value.Window
	if window == 0 {
		window = e.opts.Window
	}
	return Action{
		Kind:    ActionSendControl,
		Flow:    flow,
		WGID:    s.wgID,
		Control: ControlPacket{Flags: flags, Sequence: seq, Acknowledgement: ack, Window: window},
		Reason:  reason,
	}
}

func (e *Engine) insertEstablished(flow abi.FakeTCPSessionKey, s *session) error {
	nowMonotonic, err := e.opts.MonotonicClock.NowNanos()
	if err != nil {
		return fmt.Errorf("read faketcp %s clock for established insert: %w", BPFMonotonicClockDomain, err)
	}
	return e.opts.Store.InsertEstablished(flow, abi.FakeTCPSessionValue{
		Generation:    flow.Generation,
		LastSeenNanos: nowMonotonic,
		TXSequence:    s.txSequence,
		RXSequence:    s.rxSequence,
		LocalISN:      s.localISN,
		RemoteISN:     s.remoteISN,
		Window:        e.opts.Window,
		State:         s.state,
	})
}

func (e *Engine) lookupEstablished(flow abi.FakeTCPSessionKey, s *session) (abi.FakeTCPSessionValue, bool, error) {
	value, found, err := e.opts.Store.LookupEstablished(flow)
	if err != nil || !found {
		return value, found, err
	}
	if value.Generation != flow.Generation || value.State != abi.FakeTCPStateEstablished {
		return abi.FakeTCPSessionValue{}, false, errors.New("faketcp fast session has invalid generation or state")
	}
	if value.LocalISN != s.localISN || value.RemoteISN != s.remoteISN {
		return abi.FakeTCPSessionValue{}, false, errors.New("faketcp fast session identity changed")
	}
	// BPF is the sole writer after insertion. These assignments only refresh
	// the userspace snapshot used for observability; no whole-value write API
	// exists on SessionStore.
	s.txSequence = value.TXSequence
	s.rxSequence = value.RXSequence
	return value, true, nil
}
