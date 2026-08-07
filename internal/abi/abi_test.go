package abi

import (
	"bytes"
	"encoding/json"
	"testing"
	"unsafe"

	"github.com/syx0310/wg-mix-ebpf/internal/control"
)

func TestABIVersion(t *testing.T) {
	if Version != 10 {
		t.Fatalf("ABI version = %d, want backward-compatible 10", Version)
	}
}

func TestCipherValueJSONRedactsKey(t *testing.T) {
	value := CipherValue{Generation: 3, Key: [256]byte{0xde, 0xad, 0xbe, 0xef}, KeyLen: 16, KeyMask: 15, Mode: CipherModeXOR}
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(`"Key":`)) || bytes.Contains(data, []byte("222,173,190,239")) {
		t.Fatalf("cipher key leaked in JSON: %s", data)
	}
	if !bytes.Contains(data, []byte(`"KeyRedacted":true`)) {
		t.Fatalf("redaction marker missing: %s", data)
	}
}

func TestStructSizesAreStable(t *testing.T) {
	checks := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"ControlValue", unsafe.Sizeof(ControlValue{}), 16},
		{"ProfileKey", unsafe.Sizeof(ProfileKey{}), 16},
		{"ProfileValue", unsafe.Sizeof(ProfileValue{}), 48},
		{"CipherKey", unsafe.Sizeof(CipherKey{}), 16},
		{"CipherValue", unsafe.Sizeof(CipherValue{}), 288},
		{"UnderlayConfigKey", unsafe.Sizeof(UnderlayConfigKey{}), 16},
		{"UnderlayConfigValue", unsafe.Sizeof(UnderlayConfigValue{}), 16},
		{"ManagedFwmarkKey", unsafe.Sizeof(ManagedFwmarkKey{}), 16},
		{"ManagedFwmarkValue", unsafe.Sizeof(ManagedFwmarkValue{}), 16},
		{"EgressRuleKey", unsafe.Sizeof(EgressRuleKey{}), 24},
		{"EgressRuleValue", unsafe.Sizeof(EgressRuleValue{}), 32},
		{"IngressListenerKey", unsafe.Sizeof(IngressListenerKey{}), 16},
		{"IngressListenerValue", unsafe.Sizeof(IngressListenerValue{}), 24},
		{"ICMPListenerKey", unsafe.Sizeof(ICMPListenerKey{}), 16},
		{"ICMPListenerValue", unsafe.Sizeof(ICMPListenerValue{}), 24},
		{"FakeTCPSessionKey", unsafe.Sizeof(FakeTCPSessionKey{}), 24},
		{"FakeTCPSessionValue", unsafe.Sizeof(FakeTCPSessionValue{}), 40},
		{"FakeTCPManagedIfKey", unsafe.Sizeof(FakeTCPManagedIfKey{}), 16},
		{"FakeTCPManagedIfValue", unsafe.Sizeof(FakeTCPManagedIfValue{}), 8},
		{"FakeTCPManagedPortKey", unsafe.Sizeof(FakeTCPManagedPortKey{}), 16},
		{"FakeTCPManagedPortValue", unsafe.Sizeof(FakeTCPManagedPortValue{}), 16},
		{"FakeTCPControlPolicyKey", unsafe.Sizeof(FakeTCPControlPolicyKey{}), 16},
		{"FakeTCPControlPolicyValue", unsafe.Sizeof(FakeTCPControlPolicyValue{}), 32},
		{"FakeTCPControlFlowKey", unsafe.Sizeof(FakeTCPControlFlowKey{}), 32},
		{"FakeTCPControlFlowValue", unsafe.Sizeof(FakeTCPControlFlowValue{}), 16},
		{"FakeTCPEvent", unsafe.Sizeof(FakeTCPEvent{}), FakeTCPEventSize},
		{"FakeTCPPacketEvent", unsafe.Sizeof(FakeTCPPacketEvent{}), FakeTCPPacketEventSize},
	}
	for _, check := range checks {
		if check.got != check.want {
			t.Fatalf("%s size = %d, want %d", check.name, check.got, check.want)
		}
	}
	if got, want := unsafe.Offsetof(ICMPListenerValue{}.Flags), uintptr(20); got != want {
		t.Fatalf("ICMPListenerValue.Flags offset = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(CipherValue{}.Mode), uintptr(280); got != want {
		t.Fatalf("CipherValue.Mode offset = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(FakeTCPManagedIfKey{}.UnderlayIndex), uintptr(8); got != want {
		t.Fatalf("FakeTCPManagedIfKey.UnderlayIndex offset = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(FakeTCPSessionValue{}.Generation), uintptr(0); got != want {
		t.Fatalf("FakeTCPSessionValue.Generation offset = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(FakeTCPSessionValue{}.LastSeenNanos), uintptr(8); got != want {
		t.Fatalf("FakeTCPSessionValue.LastSeenNanos offset = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(FakeTCPSessionValue{}.TXSequence), uintptr(16); got != want {
		t.Fatalf("FakeTCPSessionValue.TXSequence offset = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(FakeTCPSessionValue{}.RXSequence), uintptr(20); got != want {
		t.Fatalf("FakeTCPSessionValue.RXSequence offset = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(FakeTCPSessionValue{}.LocalISN), uintptr(24); got != want {
		t.Fatalf("FakeTCPSessionValue.LocalISN offset = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(FakeTCPSessionValue{}.RemoteISN), uintptr(28); got != want {
		t.Fatalf("FakeTCPSessionValue.RemoteISN offset = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(FakeTCPSessionValue{}.Window), uintptr(32); got != want {
		t.Fatalf("FakeTCPSessionValue.Window offset = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(FakeTCPSessionValue{}.State), uintptr(34); got != want {
		t.Fatalf("FakeTCPSessionValue.State offset = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(FakeTCPSessionValue{}.Flags), uintptr(35); got != want {
		t.Fatalf("FakeTCPSessionValue.Flags offset = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(FakeTCPSessionValue{}.Reserved), uintptr(36); got != want {
		t.Fatalf("FakeTCPSessionValue.Reserved offset = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(FakeTCPManagedPortKey{}.DestinationPort), uintptr(12); got != want {
		t.Fatalf("FakeTCPManagedPortKey.DestinationPort offset = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(FakeTCPManagedPortValue{}.Generation), uintptr(0); got != want {
		t.Fatalf("FakeTCPManagedPortValue.Generation offset = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(FakeTCPManagedPortValue{}.WGID), uintptr(8); got != want {
		t.Fatalf("FakeTCPManagedPortValue.WGID offset = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(FakeTCPManagedPortValue{}.Action), uintptr(12); got != want {
		t.Fatalf("FakeTCPManagedPortValue.Action offset = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(FakeTCPManagedPortValue{}.Reserved), uintptr(13); got != want {
		t.Fatalf("FakeTCPManagedPortValue.Reserved offset = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(FakeTCPControlPolicyValue{}.Generation), uintptr(0); got != want {
		t.Fatalf("FakeTCPControlPolicyValue.Generation offset = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(FakeTCPControlPolicyValue{}.VirtualTimeNanos), uintptr(8); got != want {
		t.Fatalf("FakeTCPControlPolicyValue.VirtualTimeNanos offset = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(FakeTCPControlPolicyValue{}.IntervalNanos), uintptr(16); got != want {
		t.Fatalf("FakeTCPControlPolicyValue.IntervalNanos offset = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(FakeTCPControlPolicyValue{}.Burst), uintptr(24); got != want {
		t.Fatalf("FakeTCPControlPolicyValue.Burst offset = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(FakeTCPControlPolicyValue{}.Reserved), uintptr(28); got != want {
		t.Fatalf("FakeTCPControlPolicyValue.Reserved offset = %d, want %d", got, want)
	}
}

func TestFromState(t *testing.T) {
	state := &control.State{
		Generation: 7,
		Profiles: []control.ProfileState{
			{
				ID:              1,
				Name:            "default",
				StandardToMixed: [4]uint32{10, 11, 12, 13},
				MixedToStandard: [4]uint32{1, 2, 3, 4},
			},
		},
		Ciphers: []control.CipherState{
			{
				ID:            1,
				Name:          "xor",
				Mode:          "xor",
				Auth:          "none",
				Scope:         "wg-payload-full",
				KeyDerivation: "wgmx-hkdf256-v1",
				KeyLen:        16,
				KeyMask:       15,
				MaxBytes:      2048,
				Key:           [256]byte{1, 2, 3, 4},
			},
		},
		Underlays: []control.UnderlayState{
			{IfIndex: 2, Parser: "ethernet", Role: "transform", Resolved: true},
		},
		ManagedFwmarks: []control.ManagedFwmarkRule{
			{Generation: 7, FwMark: 0x10000001, UnderlayIfIndex: 2, ActionOnMiss: "drop"},
		},
		EgressRules: []control.EgressRule{
			{Generation: 7, Family: "ipv4", FwMark: 0x10000001, SourcePort: 31001, UnderlayIfIndex: 2, ProfileID: 1, CipherID: 1, WGID: 1, Action: "rewrite", TransportMode: "icmp", ICMPRole: "client", ICMPID: 0x5303},
		},
		IngressListeners: []control.IngressListener{
			{Generation: 7, Family: "ipv4", DestinationPort: 31001, UnderlayIfIndex: 2, ProfileID: 1, WGID: 1, Action: "drop"},
			{Generation: 7, Family: "ipv6", DestinationPort: 31001, UnderlayIfIndex: 2, ProfileID: 1, CipherID: 1, WGID: 1, Action: "rewrite", TransportMode: "faketcp"},
		},
		ICMPListeners: []control.ICMPListener{
			{Generation: 7, Family: "ipv4", UnderlayIfIndex: 2, ICMPType: 0, ICMPID: 0x5303, ListenPort: 31001, ProfileID: 1, WGID: 1, Action: "rewrite", Role: "client"},
			{Generation: 7, Family: "ipv4", UnderlayIfIndex: 2, ICMPType: 8, ICMPID: 0, ListenPort: 31001, ProfileID: 1, WGID: 1, Action: "rewrite", Role: "server", Flags: control.ICMPListenerFlagWildcardID},
		},
	}
	snapshot, err := FromState(state)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Control[ControlKeyGlobal].ActiveGeneration != 7 {
		t.Fatalf("generation = %d", snapshot.Control[ControlKeyGlobal].ActiveGeneration)
	}
	if snapshot.Underlays[UnderlayConfigKey{Generation: 7, UnderlayIndex: 2}].ParserMode != ParserEthernet {
		t.Fatal("missing underlay parser mode")
	}
	cipher := snapshot.Ciphers[CipherKey{Generation: 7, CipherID: 1}]
	if cipher.Mode != CipherModeXOR || cipher.KeyLen != 16 || cipher.Key[0] != 1 {
		t.Fatal("missing xor cipher")
	}
	if cipher.Key[16] != 1 || cipher.Key[17] != 2 ||
		cipher.Key[18] != 3 || cipher.Key[19] != 4 {
		t.Fatalf("cipher key period was not expanded: %v", cipher.Key[16:20])
	}
	egress := snapshot.EgressRules[EgressRuleKey{Generation: 7, FwMark: 0x10000001, UnderlayIndex: 2, SourcePort: 31001, Family: FamilyIPv4}]
	if egress.Action != ActionRewrite || egress.TransportMode != TransportICMP || egress.ICMPRole != ICMPRoleClient || egress.ICMPID != 0x5303 || egress.CipherID != 1 {
		t.Fatal("missing egress rewrite rule")
	}
	if snapshot.ManagedFwmarks[ManagedFwmarkKey{Generation: 7, FwMark: 0x10000001, UnderlayIndex: 2}].ActionOnMiss != ActionDrop {
		t.Fatal("missing managed fwmark drop rule")
	}
	if snapshot.IngressListeners[IngressListenerKey{Generation: 7, UnderlayIndex: 2, DestinationPort: 31001, Family: FamilyIPv4}].Action != ActionDrop {
		t.Fatal("missing ingress drop rule")
	}
	if ingress := snapshot.IngressListeners[IngressListenerKey{Generation: 7, UnderlayIndex: 2, DestinationPort: 31001, Family: FamilyIPv6}]; ingress.Action != ActionRewrite || ingress.CipherID != 1 || ingress.TransportMode != TransportFakeTCP {
		t.Fatal("missing ingress rewrite rule")
	}
	icmp := snapshot.ICMPListeners[ICMPListenerKey{Generation: 7, UnderlayIndex: 2, ICMPID: 0x5303, Family: FamilyIPv4, ICMPType: 0}]
	if icmp.Action != ActionRewrite || icmp.ListenPort != 31001 || icmp.Role != ICMPRoleClient || icmp.Flags != 0 {
		t.Fatal("missing icmp listener")
	}
	wildcard := snapshot.ICMPListeners[ICMPListenerKey{Generation: 7, UnderlayIndex: 2, ICMPID: 0, Family: FamilyIPv4, ICMPType: 8}]
	if wildcard.Action != ActionRewrite || wildcard.ListenPort != 31001 || wildcard.Role != ICMPRoleServer || wildcard.Flags != ICMPListenerFWildcardID {
		t.Fatal("missing icmp wildcard listener")
	}
}

func TestFromStateRejectsInvalidCipherLayout(t *testing.T) {
	tests := []struct {
		name    string
		keyLen  uint32
		keyMask uint32
		want    string
	}{
		{name: "length", keyLen: 8, keyMask: 7, want: "unsupported key length 8"},
		{name: "mask", keyLen: 16, keyMask: 31, want: "key mask 31, want 15"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := FromState(&control.State{
				Generation: 1,
				Ciphers: []control.CipherState{{
					ID:      1,
					Name:    "xor",
					Mode:    "xor",
					KeyLen:  test.keyLen,
					KeyMask: test.keyMask,
				}},
			})
			if err == nil || !bytes.Contains([]byte(err.Error()), []byte(test.want)) {
				t.Fatalf("expected %q, got %v", test.want, err)
			}
		})
	}
}

func TestFromStateWithGenerationOverridesRuleGeneration(t *testing.T) {
	state := &control.State{
		Generation: 7,
		Profiles: []control.ProfileState{
			{
				ID:              1,
				Name:            "default",
				StandardToMixed: [4]uint32{10, 11, 12, 13},
				MixedToStandard: [4]uint32{1, 2, 3, 4},
			},
		},
		Underlays: []control.UnderlayState{
			{IfIndex: 2, Parser: "ethernet", Role: "transform", Resolved: true},
		},
		ManagedFwmarks: []control.ManagedFwmarkRule{
			{Generation: 7, FwMark: 0x10000001, UnderlayIfIndex: 2, ActionOnMiss: "drop"},
		},
		EgressRules: []control.EgressRule{
			{Generation: 7, Family: "ipv4", FwMark: 0x10000001, SourcePort: 31001, UnderlayIfIndex: 2, ProfileID: 1, WGID: 1, Action: "rewrite"},
		},
		IngressListeners: []control.IngressListener{
			{Generation: 7, Family: "ipv4", DestinationPort: 31001, UnderlayIfIndex: 2, ProfileID: 1, WGID: 1, Action: "rewrite"},
		},
	}
	snapshot, err := FromStateWithGeneration(state, 42)
	if err != nil {
		t.Fatal(err)
	}
	if got := snapshot.Control[ControlKeyGlobal].ActiveGeneration; got != 42 {
		t.Fatalf("control generation = %d, want 42", got)
	}
	if got := snapshot.Profiles[ProfileKey{Generation: 42, ProfileID: 1}].Generation; got != 42 {
		t.Fatalf("profile generation = %d, want 42", got)
	}
	if got := snapshot.ManagedFwmarks[ManagedFwmarkKey{Generation: 42, FwMark: 0x10000001, UnderlayIndex: 2}].Generation; got != 42 {
		t.Fatalf("managed fwmark generation = %d, want 42", got)
	}
	if got := snapshot.EgressRules[EgressRuleKey{Generation: 42, FwMark: 0x10000001, UnderlayIndex: 2, SourcePort: 31001, Family: FamilyIPv4}].Generation; got != 42 {
		t.Fatalf("egress generation = %d, want 42", got)
	}
	if got := snapshot.IngressListeners[IngressListenerKey{Generation: 42, UnderlayIndex: 2, DestinationPort: 31001, Family: FamilyIPv4}].Generation; got != 42 {
		t.Fatalf("ingress generation = %d, want 42", got)
	}
}

func TestGenerationIsPartOfDataplaneKeys(t *testing.T) {
	state := &control.State{
		Generation: 1,
		Profiles: []control.ProfileState{
			{
				ID:              1,
				Name:            "default",
				StandardToMixed: [4]uint32{10, 11, 12, 13},
				MixedToStandard: [4]uint32{1, 2, 3, 4},
			},
		},
		Underlays: []control.UnderlayState{
			{IfIndex: 2, Parser: "ethernet", Role: "transform", Resolved: true},
		},
		ManagedFwmarks: []control.ManagedFwmarkRule{
			{FwMark: 0x10000001, UnderlayIfIndex: 2, ActionOnMiss: "drop"},
		},
		EgressRules: []control.EgressRule{
			{Family: "ipv4", FwMark: 0x10000001, SourcePort: 31001, UnderlayIfIndex: 2, ProfileID: 1, WGID: 1, Action: "rewrite"},
		},
		IngressListeners: []control.IngressListener{
			{Family: "ipv4", DestinationPort: 31001, UnderlayIfIndex: 2, ProfileID: 1, WGID: 1, Action: "rewrite"},
		},
		ICMPListeners: []control.ICMPListener{
			{Family: "ipv4", UnderlayIfIndex: 2, ICMPType: 0, ICMPID: 0x5303, ListenPort: 31001, ProfileID: 1, WGID: 1, Action: "rewrite", Role: "client"},
		},
	}
	oldSnapshot, err := FromStateWithGeneration(state, 1)
	if err != nil {
		t.Fatal(err)
	}
	newSnapshot, err := FromStateWithGeneration(state, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := oldSnapshot.EgressRules[EgressRuleKey{Generation: 1, FwMark: 0x10000001, UnderlayIndex: 2, SourcePort: 31001, Family: FamilyIPv4}]; !ok {
		t.Fatal("missing old generation egress rule")
	}
	if _, ok := newSnapshot.EgressRules[EgressRuleKey{Generation: 2, FwMark: 0x10000001, UnderlayIndex: 2, SourcePort: 31001, Family: FamilyIPv4}]; !ok {
		t.Fatal("missing new generation egress rule")
	}
	if _, ok := newSnapshot.EgressRules[EgressRuleKey{Generation: 1, FwMark: 0x10000001, UnderlayIndex: 2, SourcePort: 31001, Family: FamilyIPv4}]; ok {
		t.Fatal("new snapshot unexpectedly overwrites old generation key")
	}
	if _, ok := oldSnapshot.ManagedFwmarks[ManagedFwmarkKey{Generation: 1, FwMark: 0x10000001, UnderlayIndex: 2}]; !ok {
		t.Fatal("missing old generation managed fwmark")
	}
	if _, ok := newSnapshot.ManagedFwmarks[ManagedFwmarkKey{Generation: 2, FwMark: 0x10000001, UnderlayIndex: 2}]; !ok {
		t.Fatal("missing new generation managed fwmark")
	}
	if _, ok := oldSnapshot.ICMPListeners[ICMPListenerKey{Generation: 1, UnderlayIndex: 2, ICMPID: 0x5303, Family: FamilyIPv4, ICMPType: 0}]; !ok {
		t.Fatal("missing old generation icmp listener")
	}
	if _, ok := newSnapshot.ICMPListeners[ICMPListenerKey{Generation: 2, UnderlayIndex: 2, ICMPID: 0x5303, Family: FamilyIPv4, ICMPType: 0}]; !ok {
		t.Fatal("missing new generation icmp listener")
	}
}
