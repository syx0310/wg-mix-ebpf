package dataplane

import (
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
	"github.com/syx0310/wg-mix-ebpf/internal/config"
	"github.com/syx0310/wg-mix-ebpf/internal/control"
)

func TestBuildFakeTCPPolicySnapshotProjectsExactManagedPolicy(t *testing.T) {
	state := fakeTCPPolicyTestState()
	snapshot, err := buildFakeTCPPolicySnapshot(state, 91)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Generation != 91 || len(snapshot.ManagedInterfaces) != 2 ||
		len(snapshot.ManagedPorts) != 2 || len(snapshot.ControlPolicies) != 2 {
		t.Fatalf("unexpected FakeTCP snapshot: %#v", snapshot)
	}

	for _, want := range []struct {
		ifindex  uint32
		port     uint16
		wgID     uint32
		interval uint64
		burst    uint32
	}{
		{ifindex: 3, port: 31001, wgID: 1, interval: uint64(20 * time.Millisecond), burst: 17},
		{ifindex: 9, port: 31002, wgID: 2, interval: uint64(30 * time.Millisecond), burst: 23},
	} {
		ifValue, ok := snapshot.ManagedInterfaces[abi.FakeTCPManagedIfKey{
			Generation: 91, UnderlayIndex: want.ifindex,
		}]
		if !ok || ifValue.Generation != 91 {
			t.Fatalf("missing managed interface %d: %#v", want.ifindex, ifValue)
		}
		portValue, ok := snapshot.ManagedPorts[abi.FakeTCPManagedPortKey{
			Generation: 91, UnderlayIndex: want.ifindex, DestinationPort: want.port,
		}]
		if !ok || portValue != (abi.FakeTCPManagedPortValue{
			Generation: 91, WGID: want.wgID, Action: abi.ActionRewrite,
		}) {
			t.Fatalf("managed port %d/%d = %#v", want.ifindex, want.port, portValue)
		}
		policy, ok := snapshot.ControlPolicies[abi.FakeTCPControlPolicyKey{
			Generation: 91, WGID: want.wgID,
		}]
		if !ok || policy != (abi.FakeTCPControlPolicyValue{
			Generation: 91, IntervalNanos: want.interval, Burst: want.burst,
		}) {
			t.Fatalf("control policy %d = %#v", want.wgID, policy)
		}
		if policy.VirtualTimeNanos != 0 {
			t.Fatalf("control policy %d minted reload budget: %#v", want.wgID, policy)
		}
	}
}

func TestValidateFakeTCPPolicySnapshotRejectsReservedFields(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*fakeTCPPolicySnapshot)
		wantErr string
	}{
		{
			name: "managed port",
			mutate: func(snapshot *fakeTCPPolicySnapshot) {
				for key, value := range snapshot.ManagedPorts {
					value.Reserved[1] = 1
					snapshot.ManagedPorts[key] = value
					break
				}
			},
			wantErr: "managed port has nonzero reserved bytes",
		},
		{
			name: "control policy",
			mutate: func(snapshot *fakeTCPPolicySnapshot) {
				for key, value := range snapshot.ControlPolicies {
					value.Reserved = 1
					snapshot.ControlPolicies[key] = value
					break
				}
			},
			wantErr: "control policy for WireGuard ID",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot, err := buildFakeTCPPolicySnapshot(fakeTCPPolicyTestState(), 91)
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(snapshot)
			err = validateFakeTCPPolicySnapshot(snapshot)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) ||
				!strings.Contains(err.Error(), "reserved") {
				t.Fatalf("reserved validation error = %v, want %q and reserved", err, test.wantErr)
			}
		})
	}
}

func TestBuildFakeTCPPolicySnapshotIsInputOrderIndependentAndGenerationIsolated(t *testing.T) {
	state := fakeTCPPolicyTestState()
	first, err := buildFakeTCPPolicySnapshot(state, 101)
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(state.WireGuards)
	slices.Reverse(state.Underlays)
	slices.Reverse(state.IngressListeners)
	reversed, err := buildFakeTCPPolicySnapshot(state, 101)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, reversed) {
		t.Fatalf("policy projection depends on state slice order:\nfirst=%#v\nreversed=%#v", first, reversed)
	}

	next, err := buildFakeTCPPolicySnapshot(state, 102)
	if err != nil {
		t.Fatal(err)
	}
	for key := range first.ManagedPorts {
		if _, collision := next.ManagedPorts[key]; collision {
			t.Fatalf("target generations share managed-port key %#v", key)
		}
	}
	for key := range first.ControlPolicies {
		if _, collision := next.ControlPolicies[key]; collision {
			t.Fatalf("target generations share control-policy key %#v", key)
		}
	}
}

func TestBuildFakeTCPPolicySnapshotSharesOneInterfaceLatchAcrossDistinctPorts(t *testing.T) {
	state := fakeTCPPolicyTestState()
	state.IngressListeners[1].UnderlayIfIndex = state.IngressListeners[0].UnderlayIfIndex
	snapshot, err := buildFakeTCPPolicySnapshot(state, 91)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.ManagedInterfaces) != 1 || len(snapshot.ManagedPorts) != 2 {
		t.Fatalf(
			"same-interface listeners projected as interfaces=%d ports=%d, want 1/2",
			len(snapshot.ManagedInterfaces), len(snapshot.ManagedPorts),
		)
	}
}

func TestBuildFakeTCPPolicySnapshotRejectsInvalidSourceState(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*control.State)
		wantErr string
	}{
		{
			name: "zero source generation",
			mutate: func(state *control.State) {
				state.Generation = 0
			},
			wantErr: "source state generation",
		},
		{
			name: "listener generation mismatch",
			mutate: func(state *control.State) {
				state.IngressListeners[0].Generation++
			},
			wantErr: "does not match state generation",
		},
		{
			name: "ipv6 listener",
			mutate: func(state *control.State) {
				state.IngressListeners[0].Family = "ipv6"
			},
			wantErr: "only ipv4",
		},
		{
			name: "zero port",
			mutate: func(state *control.State) {
				state.IngressListeners[0].DestinationPort = 0
			},
			wantErr: "zero destination port",
		},
		{
			name: "non rewrite",
			mutate: func(state *control.State) {
				state.IngressListeners[0].Action = "drop"
			},
			wantErr: "want rewrite",
		},
		{
			name: "unknown underlay",
			mutate: func(state *control.State) {
				state.IngressListeners[0].UnderlayIfIndex = 77
			},
			wantErr: "unknown underlay",
		},
		{
			name: "unresolved underlay",
			mutate: func(state *control.State) {
				state.Underlays[0].Resolved = false
			},
			wantErr: "not a resolved transform attachment",
		},
		{
			name: "parse only underlay",
			mutate: func(state *control.State) {
				state.Underlays[0].Role = "parse_only"
			},
			wantErr: "not a resolved transform attachment",
		},
		{
			name: "empty underlay role",
			mutate: func(state *control.State) {
				state.Underlays[0].Role = ""
			},
			wantErr: "not a resolved transform attachment",
		},
		{
			name: "unknown underlay role",
			mutate: func(state *control.State) {
				state.Underlays[0].Role = "unexpected"
			},
			wantErr: "not a resolved transform attachment",
		},
		{
			name: "l3 parser",
			mutate: func(state *control.State) {
				state.Underlays[0].Parser = "l3"
			},
			wantErr: "want ethernet",
		},
		{
			name: "unknown WireGuard",
			mutate: func(state *control.State) {
				state.IngressListeners[0].WGID = 77
			},
			wantErr: "unknown WireGuard",
		},
		{
			name: "wrong transport",
			mutate: func(state *control.State) {
				state.WireGuards[0].TransportMode = "udp"
			},
			wantErr: "with transport",
		},
		{
			name: "experiment not acknowledged",
			mutate: func(state *control.State) {
				state.WireGuards[0].FakeTCPExperimental = false
			},
			wantErr: "has not acknowledged",
		},
		{
			name: "wrong checksum mode",
			mutate: func(state *control.State) {
				state.WireGuards[0].FakeTCPChecksumMode = "legacy"
			},
			wantErr: "checksum mode",
		},
		{
			name: "wrong ingress mode",
			mutate: func(state *control.State) {
				state.WireGuards[0].FakeTCPIngressMode = "tc"
			},
			wantErr: "want xdp-required",
		},
		{
			name: "interval below minimum",
			mutate: func(state *control.State) {
				state.WireGuards[0].FakeTCPSYNRateIntervalNanos = int64(fakeTCPControlMinInterval - 1)
			},
			wantErr: "control interval",
		},
		{
			name: "interval above maximum",
			mutate: func(state *control.State) {
				state.WireGuards[0].FakeTCPSYNRateIntervalNanos = int64(fakeTCPControlMaxInterval + 1)
			},
			wantErr: "control interval",
		},
		{
			name: "zero burst",
			mutate: func(state *control.State) {
				state.WireGuards[0].FakeTCPSYNBurst = 0
			},
			wantErr: "control burst",
		},
		{
			name: "burst above maximum",
			mutate: func(state *control.State) {
				state.WireGuards[0].FakeTCPSYNBurst = config.MaxFakeTCPSYNBurst + 1
			},
			wantErr: "control burst",
		},
		{
			name: "duplicate listener",
			mutate: func(state *control.State) {
				state.IngressListeners = append(state.IngressListeners, state.IngressListeners[0])
			},
			wantErr: "duplicate managed listener",
		},
		{
			name: "same port conflicting WireGuard",
			mutate: func(state *control.State) {
				state.IngressListeners[1].UnderlayIfIndex = state.IngressListeners[0].UnderlayIfIndex
				state.IngressListeners[1].DestinationPort = state.IngressListeners[0].DestinationPort
			},
			wantErr: "duplicate managed listener",
		},
		{
			name: "duplicate WireGuard ID",
			mutate: func(state *control.State) {
				duplicate := state.WireGuards[0]
				duplicate.Name = "duplicate"
				state.WireGuards = append(state.WireGuards, duplicate)
			},
			wantErr: "WireGuard ID 1 is duplicated",
		},
		{
			name: "duplicate underlay ifindex",
			mutate: func(state *control.State) {
				duplicate := state.Underlays[0]
				duplicate.Name = "duplicate"
				state.Underlays = append(state.Underlays, duplicate)
			},
			wantErr: "underlay ifindex 3 is duplicated",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := fakeTCPPolicyTestState()
			test.mutate(state)
			_, err := buildFakeTCPPolicySnapshot(state, 91)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, test.wantErr)
			}
		})
	}

	if _, err := buildFakeTCPPolicySnapshot(nil, 91); err == nil || !strings.Contains(err.Error(), "state is nil") {
		t.Fatalf("nil state error = %v", err)
	}
	if _, err := buildFakeTCPPolicySnapshot(fakeTCPPolicyTestState(), 0); err == nil || !strings.Contains(err.Error(), "target generation") {
		t.Fatalf("zero target generation error = %v", err)
	}
}

func TestBuildFakeTCPPolicySnapshotEnforcesTwoGenerationCapacity(t *testing.T) {
	tests := []struct {
		name    string
		state   func(int) *control.State
		limit   int
		wantErr string
	}{
		{
			name: "interfaces", state: fakeTCPPolicyStateWithInterfaces,
			limit: fakeTCPManagedInterfacesPerGeneration, wantErr: "managed interfaces",
		},
		{
			name: "ports", state: fakeTCPPolicyStateWithPorts,
			limit: fakeTCPManagedPortsPerGeneration, wantErr: "managed ports",
		},
		{
			name: "policies", state: fakeTCPPolicyStateWithWireGuards,
			limit: fakeTCPControlPoliciesPerGeneration, wantErr: "control policies",
		},
	}
	for _, test := range tests {
		t.Run(test.name+" at limit", func(t *testing.T) {
			if _, err := buildFakeTCPPolicySnapshot(test.state(test.limit), 91); err != nil {
				t.Fatalf("capacity limit rejected: %v", err)
			}
		})
		t.Run(test.name+" over limit", func(t *testing.T) {
			_, err := buildFakeTCPPolicySnapshot(test.state(test.limit+1), 91)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("capacity overflow error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

func TestBuildFakeTCPPolicySnapshotRejectsEmptyUnmanagedState(t *testing.T) {
	_, err := buildFakeTCPPolicySnapshot(&control.State{
		Generation:       1,
		WireGuards:       []control.WireGuardState{{ID: 1, Name: "wg0", TransportMode: "udp"}},
		IngressListeners: []control.IngressListener{{TransportMode: "udp"}},
	}, 91)
	if err == nil || !strings.Contains(err.Error(), "no complete managed FakeTCP policy") {
		t.Fatalf("empty policy error = %v", err)
	}
}

func TestFakeTCPMimicTransformCompositionOrderContract(t *testing.T) {
	tcBytes, err := os.ReadFile("../../bpf/wg_mix_tc.c")
	if err != nil {
		t.Fatal(err)
	}
	fakeBytes, err := os.ReadFile("../../bpf/wg_mix_faketcp.h")
	if err != nil {
		t.Fatal(err)
	}
	tc := string(tcBytes)
	fake := string(fakeBytes)

	egress := sourceSection(t, tc, "int wg_mix_egress(struct __sk_buff *skb)", "SEC(\"classifier/ingress\")")
	checkpoint := strings.Index(egress, "faketcp_egress_admission_checkpoint(")
	typeWord := strings.Index(egress, "update_type_word(skb, &info, old_wire, new_wire, 1)")
	xorDispatch := strings.Index(egress, "bpf_tail_call(skb, &xor_egress_programs")
	directFakeTCP := strings.Index(egress, "return faketcp_encode_established(skb, &info, rule, generation,")
	if checkpoint < 0 || typeWord < 0 || xorDispatch < 0 || directFakeTCP < 0 ||
		!(checkpoint < typeWord && typeWord < xorDispatch && typeWord < directFakeTCP) {
		t.Fatal("egress must capture original UDP, rewrite type-word, apply XOR when configured, then encode FakeTCP")
	}
	xorContinuation := sourceSection(t, tc,
		"static __always_inline int run_xor_egress_segment", "static __always_inline int run_xor_ingress_segment")
	if xorWrite, fakeTCPDispatch := strings.Index(xorContinuation, "xor_segment_"),
		strings.Index(xorContinuation, "bpf_tail_call(skb, &faketcp_egress_programs"); xorWrite < 0 || fakeTCPDispatch < 0 || xorWrite >= fakeTCPDispatch {
		t.Fatal("XOR egress completion must precede the FakeTCP encoder tail call")
	}

	xdp := sourceSection(t, fake, "int wg_mix_faketcp_ingress(struct xdp_md *xdp)", "#endif")
	udpRestore := strings.Index(xdp, "bpf_xdp_store_bytes(xdp, l3.l4_off, &udp")
	tailShrink := strings.Index(xdp, "bpf_xdp_adjust_tail(xdp, -FAKETCP_HEADER_DELTA)")
	xdpPass := strings.LastIndex(xdp, "return XDP_PASS")
	if udpRestore < 0 || tailShrink < 0 || xdpPass < 0 || !(udpRestore < tailShrink && tailShrink < xdpPass) {
		t.Fatal("XDP must decode the FakeTCP header back to UDP before passing to TC ingress")
	}
	ingress := sourceSection(t, tc, "int wg_mix_ingress(struct __sk_buff *skb)", "char LICENSE[]")
	metadataGate := strings.Index(ingress, "faketcp_consume_ingress_admission(skb, &info, listener,")
	xorMetadata := strings.Index(ingress, "load_xor_ingress_metadata")
	restoreTypeWord := strings.Index(ingress, "update_type_word(skb, &info, encrypted_wire, new_wire, 0)")
	xorRestore := strings.Index(ingress, "bpf_tail_call(skb, &xor_ingress_programs")
	if metadataGate < 0 || xorMetadata < 0 || restoreTypeWord < 0 || xorRestore < 0 ||
		!(metadataGate < xorMetadata && xorMetadata < restoreTypeWord && restoreTypeWord < xorRestore) {
		t.Fatal("TC ingress must accept only XDP-decoded UDP, restore type-word, then restore XOR payload")
	}
}

func sourceSection(t *testing.T, source, startMarker, endMarker string) string {
	t.Helper()
	start := strings.Index(source, startMarker)
	if start < 0 {
		t.Fatalf("source marker %q is missing", startMarker)
	}
	end := strings.Index(source[start:], endMarker)
	if end < 0 {
		t.Fatalf("source marker %q after %q is missing", endMarker, startMarker)
	}
	return source[start : start+end]
}

func fakeTCPPolicyTestState() *control.State {
	return &control.State{
		Generation: 7,
		WireGuards: []control.WireGuardState{
			fakeTCPPolicyTestWireGuard(1, "wg-one", 20*time.Millisecond, 17),
			fakeTCPPolicyTestWireGuard(2, "wg-two", 30*time.Millisecond, 23),
			fakeTCPPolicyTestWireGuard(3, "wg-unused", 40*time.Millisecond, 29),
		},
		Underlays: []control.UnderlayState{
			{ID: 1, Name: "eth-three", Parser: "ethernet", IfIndex: 3, Role: "transform", Resolved: true},
			{ID: 2, Name: "eth-nine", Parser: "ethernet", IfIndex: 9, Role: "transform", Resolved: true},
		},
		IngressListeners: []control.IngressListener{
			{Generation: 7, Family: "ipv4", DestinationPort: 31001, UnderlayIfIndex: 3, WGID: 1, Action: "rewrite", TransportMode: "faketcp"},
			{Generation: 7, Family: "ipv4", DestinationPort: 31002, UnderlayIfIndex: 9, WGID: 2, Action: "rewrite", TransportMode: "faketcp"},
		},
	}
}

func fakeTCPPolicyTestWireGuard(
	id uint32,
	name string,
	interval time.Duration,
	burst uint32,
) control.WireGuardState {
	return control.WireGuardState{
		ID:                          id,
		Name:                        name,
		TransportMode:               "faketcp",
		FakeTCPExperimental:         true,
		FakeTCPChecksumMode:         config.FakeTCPChecksumModePartialCompleteReset,
		FakeTCPIngressMode:          "xdp-required",
		FakeTCPSYNRateIntervalNanos: int64(interval),
		FakeTCPSYNBurst:             burst,
	}
}

func fakeTCPPolicyStateWithInterfaces(count int) *control.State {
	state := &control.State{
		Generation: 1,
		WireGuards: []control.WireGuardState{
			fakeTCPPolicyTestWireGuard(1, "wg", 20*time.Millisecond, 1),
		},
	}
	for index := 0; index < count; index++ {
		ifindex := index + 1
		state.Underlays = append(state.Underlays, control.UnderlayState{
			Name: "underlay", Parser: "ethernet", IfIndex: ifindex, Role: "transform", Resolved: true,
		})
		state.IngressListeners = append(state.IngressListeners, control.IngressListener{
			Generation: 1, Family: "ipv4", DestinationPort: 31001,
			UnderlayIfIndex: ifindex, WGID: 1, Action: "rewrite", TransportMode: "faketcp",
		})
	}
	return state
}

func fakeTCPPolicyStateWithPorts(count int) *control.State {
	state := &control.State{
		Generation: 1,
		WireGuards: []control.WireGuardState{
			fakeTCPPolicyTestWireGuard(1, "wg", 20*time.Millisecond, 1),
		},
		Underlays: []control.UnderlayState{
			{Name: "underlay", Parser: "ethernet", IfIndex: 1, Role: "transform", Resolved: true},
		},
	}
	for index := 0; index < count; index++ {
		state.IngressListeners = append(state.IngressListeners, control.IngressListener{
			Generation: 1, Family: "ipv4", DestinationPort: uint16(10000 + index),
			UnderlayIfIndex: 1, WGID: 1, Action: "rewrite", TransportMode: "faketcp",
		})
	}
	return state
}

func fakeTCPPolicyStateWithWireGuards(count int) *control.State {
	state := &control.State{
		Generation: 1,
		Underlays: []control.UnderlayState{
			{Name: "underlay", Parser: "ethernet", IfIndex: 1, Role: "transform", Resolved: true},
		},
	}
	for index := 0; index < count; index++ {
		wgID := uint32(index + 1)
		state.WireGuards = append(state.WireGuards,
			fakeTCPPolicyTestWireGuard(wgID, "wg", 20*time.Millisecond, 1))
		state.IngressListeners = append(state.IngressListeners, control.IngressListener{
			Generation: 1, Family: "ipv4", DestinationPort: uint16(10000 + index),
			UnderlayIfIndex: 1, WGID: wgID, Action: "rewrite", TransportMode: "faketcp",
		})
	}
	return state
}
