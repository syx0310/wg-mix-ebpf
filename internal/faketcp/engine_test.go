package faketcp

import (
	"testing"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time      { return c.now }
func (c *fakeClock) Add(d time.Duration) { c.now = c.now.Add(d) }

func testFlow(port uint16) abi.FakeTCPSessionKey {
	// IPv4 fields use network byte order, matching the BPF map contract.
	return abi.FakeTCPSessionKey{
		Generation: 1, LocalIPv4: 0x0a000001, RemoteIPv4: 0x0a000002,
		UnderlayIndex: 2, LocalPort: port, RemotePort: 443,
	}
}

func testEngine(t *testing.T, mutate func(*Options)) (*Engine, *fakeClock) {
	t.Helper()
	clock := &fakeClock{now: time.Unix(100, 0)}
	nextISN := uint32(1000)
	opts := Options{
		Generation: 1, SessionCapacity: 8, MaxPendingFlows: 4,
		MaxPendingPacketsPerFlow: 2, MaxPendingBytes: 64,
		HandshakeTimeout: time.Second, HandshakeRetries: 2,
		KeepaliveInterval: 5 * time.Second, IdleTimeout: 20 * time.Second,
		Now:             clock.Now,
		InitialSequence: func() uint32 { value := nextISN; nextISN += 1000; return value },
	}
	if mutate != nil {
		mutate(&opts)
	}
	engine, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return engine, clock
}

func TestClientHandshakeReleasesBoundedFirstPacket(t *testing.T) {
	engine, _ := testEngine(t, nil)
	flow := testFlow(31001)
	packet := []byte{1, 2, 3, 4}
	actions, err := engine.Outbound(flow, packet)
	if err != nil || len(actions) != 1 || actions[0].Control.Flags != FlagSYN {
		t.Fatalf("outbound actions=%#v err=%v", actions, err)
	}
	packet[0] = 9
	actions, err = engine.Inbound(flow, Segment{Flags: FlagSYN | FlagACK, Sequence: 9000, Acknowledgement: 1001})
	if err != nil || len(actions) != 2 || actions[0].Control.Flags != FlagACK ||
		actions[1].Kind != ActionReleasePending || actions[1].Packets[0][0] != 1 {
		t.Fatalf("handshake actions=%#v err=%v", actions, err)
	}
	state, ok := engine.Snapshot(flow)
	if !ok || state.State != abi.FakeTCPStateEstablished || state.PendingPackets != 0 {
		t.Fatalf("state=%#v ok=%t", state, ok)
	}
}

func TestServerDuplicateSYNAndACKTransitions(t *testing.T) {
	engine, _ := testEngine(t, nil)
	flow := testFlow(31001)
	actions, err := engine.Inbound(flow, Segment{Flags: FlagSYN, Sequence: 7000})
	if err != nil || len(actions) != 1 || actions[0].Control.Flags != FlagSYN|FlagACK {
		t.Fatalf("syn actions=%#v err=%v", actions, err)
	}
	actions, err = engine.Inbound(flow, Segment{Flags: FlagSYN, Sequence: 7000})
	if err != nil || len(actions) != 1 || actions[0].Reason != "duplicate-syn" {
		t.Fatalf("duplicate actions=%#v err=%v", actions, err)
	}
	actions, err = engine.Inbound(flow, Segment{Flags: FlagACK, Acknowledgement: 1001})
	if err != nil || len(actions) != 0 {
		t.Fatalf("ack actions=%#v err=%v", actions, err)
	}
	state, _ := engine.Snapshot(flow)
	if state.State != abi.FakeTCPStateEstablished {
		t.Fatalf("state=%d", state.State)
	}
	// A duplicate ACK after establishment is harmless and remains forwardable.
	actions, err = engine.Inbound(flow, Segment{Flags: FlagACK, Acknowledgement: 1001})
	if err != nil || len(actions) != 1 || actions[0].Kind != ActionForward {
		t.Fatalf("duplicate ack actions=%#v err=%v", actions, err)
	}
}

func TestSimultaneousOpen(t *testing.T) {
	engine, _ := testEngine(t, nil)
	flow := testFlow(31001)
	if _, err := engine.Outbound(flow, []byte{1}); err != nil {
		t.Fatal(err)
	}
	actions, err := engine.Inbound(flow, Segment{Flags: FlagSYN, Sequence: 8000})
	if err != nil || len(actions) != 1 || actions[0].Reason != "simultaneous-open" ||
		actions[0].Control.Flags != FlagSYN|FlagACK {
		t.Fatalf("actions=%#v err=%v", actions, err)
	}
	actions, err = engine.Inbound(flow, Segment{Flags: FlagACK, Acknowledgement: 1001})
	if err != nil || len(actions) != 1 || actions[0].Kind != ActionReleasePending {
		t.Fatalf("complete actions=%#v err=%v", actions, err)
	}
}

func TestRSTClosesAndDropsPendingAccounting(t *testing.T) {
	engine, _ := testEngine(t, nil)
	flow := testFlow(31001)
	if _, err := engine.Outbound(flow, []byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	actions, err := engine.Inbound(flow, Segment{Flags: FlagRST})
	if err != nil || len(actions) != 1 || actions[0].Kind != ActionClose {
		t.Fatalf("actions=%#v err=%v", actions, err)
	}
	if _, ok := engine.Snapshot(flow); ok {
		t.Fatal("RST did not remove session")
	}
}

func TestHandshakeTimeoutRetriesThenCloses(t *testing.T) {
	engine, clock := testEngine(t, nil)
	flow := testFlow(31001)
	if _, err := engine.Outbound(flow, []byte{1}); err != nil {
		t.Fatal(err)
	}
	clock.Add(time.Second)
	actions, err := engine.Tick()
	if err != nil || len(actions) != 1 || actions[0].Reason != "handshake-retry" {
		t.Fatalf("retry actions=%#v err=%v", actions, err)
	}
	clock.Add(time.Second)
	actions, err = engine.Tick()
	if err != nil || len(actions) != 1 || actions[0].Reason != "handshake-timeout" {
		t.Fatalf("timeout actions=%#v err=%v", actions, err)
	}
}

func TestPendingQueueEnforcesFlowPacketAndByteLimits(t *testing.T) {
	engine, _ := testEngine(t, func(o *Options) {
		o.MaxPendingFlows = 1
		o.MaxPendingPacketsPerFlow = 1
		o.MaxPendingBytes = 4
	})
	flow1 := testFlow(31001)
	flow2 := testFlow(31002)
	if actions, _ := engine.Outbound(flow1, []byte{1, 2, 3, 4}); len(actions) != 1 {
		t.Fatalf("first actions=%#v", actions)
	}
	if actions, _ := engine.Outbound(flow1, []byte{5}); len(actions) != 1 || actions[0].Reason != "pending-capacity" {
		t.Fatalf("packet bound actions=%#v", actions)
	}
	if actions, _ := engine.Outbound(flow2, []byte{6}); len(actions) != 2 || actions[1].Reason != "pending-capacity" {
		t.Fatalf("flow/byte bound actions=%#v", actions)
	}
	state, ok := engine.Snapshot(flow2)
	if !ok || state.PendingPackets != 0 {
		t.Fatalf("flow2 state=%#v ok=%t", state, ok)
	}
}

func TestUnknownProbeDoesNotAllocate(t *testing.T) {
	engine, _ := testEngine(t, nil)
	flow := testFlow(31001)
	actions, err := engine.Inbound(flow, Segment{Flags: FlagACK, Sequence: 42})
	if err != nil || len(actions) != 1 || actions[0].Reason != "unknown-flow" {
		t.Fatalf("actions=%#v err=%v", actions, err)
	}
	if _, ok := engine.Snapshot(flow); ok {
		t.Fatal("probe allocated a session")
	}
}

func TestGenerationAdvanceIsExplicitDrain(t *testing.T) {
	engine, _ := testEngine(t, nil)
	flow := testFlow(31001)
	if _, err := engine.Outbound(flow, []byte{1}); err != nil {
		t.Fatal(err)
	}
	actions, err := engine.AdvanceGeneration(2)
	if err != nil || len(actions) != 1 || actions[0].Reason != "generation-drain-rehandshake" {
		t.Fatalf("actions=%#v err=%v", actions, err)
	}
	if _, ok := engine.Snapshot(flow); ok {
		t.Fatal("old generation session survived drain")
	}
	flow.Generation = 2
	if _, err := engine.Outbound(flow, []byte{2}); err != nil {
		t.Fatal(err)
	}
}
