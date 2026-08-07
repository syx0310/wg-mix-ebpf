package faketcp

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

func TestEstablishedCloseRequiresFullPacketValidation(t *testing.T) {
	engine, store, flow, state := establishedControlTestSession(t)
	segment := Segment{
		Flags:           FlagRST | FlagACK,
		Sequence:        state.RXSequence,
		Acknowledgement: state.TXSequence,
	}
	actions, err := engine.Inbound(flow, segment)
	if err != nil || len(actions) != 1 || actions[0].Reason != "unvalidated-close" {
		t.Fatalf("unvalidated close actions=%#v err=%v", actions, err)
	}
	if _, found := store.values[flow]; !found || store.deleteAttempts != 0 {
		t.Fatalf("unvalidated close reached established delete: found=%t attempts=%d", found, store.deleteAttempts)
	}
}

func TestValidateIPv4TCPControlRejectsBadChecksumAndWindowWithoutDelete(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]byte, abi.FakeTCPSessionValue)
		want   string
	}{
		{
			name: "bad IPv4 checksum",
			mutate: func(packet []byte, _ abi.FakeTCPSessionValue) {
				packet[8]++
			},
			want: "IPv4 checksum",
		},
		{
			name: "bad TCP checksum",
			mutate: func(packet []byte, _ abi.FakeTCPSessionValue) {
				packet[36], packet[37] = 0, 0
			},
			want: "TCP checksum",
		},
		{
			name: "non-exact RST sequence inside receive window",
			mutate: func(packet []byte, state abi.FakeTCPSessionValue) {
				binary.BigEndian.PutUint32(packet[24:28], state.RXSequence+1)
				setTCPChecksum(packet)
			},
			want: "exactly match",
		},
		{
			name: "out-of-window RST sequence",
			mutate: func(packet []byte, state abi.FakeTCPSessionValue) {
				binary.BigEndian.PutUint32(packet[24:28], state.RXSequence+uint32(state.Window)+1)
				setTCPChecksum(packet)
			},
			want: "exactly match",
		},
		{
			name: "non-exact RST acknowledgement",
			mutate: func(packet []byte, state abi.FakeTCPSessionValue) {
				binary.BigEndian.PutUint32(packet[28:32], state.TXSequence-1)
				setTCPChecksum(packet)
			},
			want: "exactly match",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			engine, store, flow, state := establishedControlTestSession(t)
			packet := buildIPv4TCPControl(flow, state, FlagRST|FlagACK, 0)
			test.mutate(packet, state)
			_, validationErr := ValidateIPv4TCPControl(packet, flow, state)
			if validationErr == nil || !strings.Contains(validationErr.Error(), test.want) {
				t.Fatalf("validation error=%v, want %q", validationErr, test.want)
			}
			actions, err := engine.Inbound(flow, Segment{
				Flags:           packet[33],
				Sequence:        binary.BigEndian.Uint32(packet[24:28]),
				Acknowledgement: binary.BigEndian.Uint32(packet[28:32]),
			})
			if err != nil || len(actions) != 1 || actions[0].Reason != "unvalidated-close" {
				t.Fatalf("invalid close actions=%#v err=%v", actions, err)
			}
			if _, found := store.values[flow]; !found || store.deleteAttempts != 0 {
				t.Fatalf("invalid close deleted session: found=%t attempts=%d", found, store.deleteAttempts)
			}
		})
	}
}

func TestValidZeroTCPChecksumFieldIsNotRejectedByFieldValue(t *testing.T) {
	engine, store, flow, state := establishedControlTestSession(t)
	var packet []byte
	for window := 0; window <= 0xffff; window++ {
		candidate := buildIPv4TCPControl(flow, state, FlagRST|FlagACK, uint16(window))
		if candidate[36] == 0 && candidate[37] == 0 {
			packet = candidate
			break
		}
	}
	if packet == nil {
		t.Fatal("failed to construct mathematically valid TCP checksum value zero")
	}
	validated, err := ValidateIPv4TCPControl(packet, flow, state)
	if err != nil {
		t.Fatalf("valid zero TCP checksum field rejected: %v", err)
	}
	actions, err := engine.InboundValidatedControl(validated, 0)
	if err != nil || len(actions) != 1 || actions[0].Kind != ActionClose {
		t.Fatalf("validated close actions=%#v err=%v", actions, err)
	}
	if _, found := store.values[flow]; found || store.deleteAttempts != 1 {
		t.Fatalf("validated close delete result: found=%t attempts=%d", found, store.deleteAttempts)
	}
}

func TestFINUsesReceiveWindowAndRequiresAcknowledgement(t *testing.T) {
	_, _, flow, state := establishedControlTestSession(t)
	packet := buildIPv4TCPControl(flow, state, FlagFIN|FlagACK, 1234)
	binary.BigEndian.PutUint32(packet[24:28], state.RXSequence+1)
	setTCPChecksum(packet)
	if _, err := ValidateIPv4TCPControl(packet, flow, state); err != nil {
		t.Fatalf("in-window acknowledged FIN rejected: %v", err)
	}
	packet[33] = FlagFIN
	setTCPChecksum(packet)
	if _, err := ValidateIPv4TCPControl(packet, flow, state); err == nil || !strings.Contains(err.Error(), "must acknowledge") {
		t.Fatalf("unacknowledged FIN error=%v", err)
	}
}

func TestValidatedCloseCannotDeleteAdvancedBPFState(t *testing.T) {
	engine, store, flow, state := establishedControlTestSession(t)
	packet := buildIPv4TCPControl(flow, state, FlagRST|FlagACK, 1234)
	validated, err := ValidateIPv4TCPControl(packet, flow, state)
	if err != nil {
		t.Fatal(err)
	}
	advanced := state
	advanced.RXSequence++
	store.values[flow] = advanced
	actions, err := engine.InboundValidatedControl(validated, 0)
	if err != nil || len(actions) != 1 || actions[0].Reason != "fast-session-raced" {
		t.Fatalf("raced close actions=%#v err=%v", actions, err)
	}
	if store.values[flow] != advanced || store.deleteAttempts != 0 {
		t.Fatal("validated close deleted state that advanced after validation")
	}
}

func establishedControlTestSession(t *testing.T) (*Engine, *fakeSessionStore, abi.FakeTCPSessionKey, abi.FakeTCPSessionValue) {
	t.Helper()
	store := newFakeSessionStore()
	engine, _ := testEngine(t, func(options *Options) { options.Store = store })
	flow := testFlow(31001)
	if _, err := engine.Outbound(flow, []byte{1}); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Inbound(flow, Segment{Flags: FlagSYN | FlagACK, Sequence: 9000, Acknowledgement: 1001}); err != nil {
		t.Fatal(err)
	}
	state, found := store.values[flow]
	if !found {
		t.Fatal("test handshake did not establish BPF state")
	}
	return engine, store, flow, state
}

func buildIPv4TCPControl(flow abi.FakeTCPSessionKey, state abi.FakeTCPSessionValue, flags uint8, window uint16) []byte {
	packet := make([]byte, 40)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 6
	binary.NativeEndian.PutUint32(packet[12:16], flow.RemoteIPv4)
	binary.NativeEndian.PutUint32(packet[16:20], flow.LocalIPv4)
	binary.BigEndian.PutUint16(packet[20:22], flow.RemotePort)
	binary.BigEndian.PutUint16(packet[22:24], flow.LocalPort)
	binary.BigEndian.PutUint32(packet[24:28], state.RXSequence)
	binary.BigEndian.PutUint32(packet[28:32], state.TXSequence)
	packet[32] = 5 << 4
	packet[33] = flags
	binary.BigEndian.PutUint16(packet[34:36], window)
	setTCPChecksum(packet)
	setIPv4Checksum(packet)
	return packet
}

func setIPv4Checksum(packet []byte) {
	packet[10], packet[11] = 0, 0
	binary.BigEndian.PutUint16(packet[10:12], ^foldChecksumSum(checksumSum(0, packet[:20])))
}

func setTCPChecksum(packet []byte) {
	packet[36], packet[37] = 0, 0
	var pseudo [12]byte
	copy(pseudo[:8], packet[12:20])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(packet)-20))
	sum := checksumSum(0, pseudo[:])
	sum = checksumSum(sum, packet[20:])
	binary.BigEndian.PutUint16(packet[36:38], ^foldChecksumSum(sum))
}
