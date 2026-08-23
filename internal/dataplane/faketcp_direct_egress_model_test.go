package dataplane

import (
	"testing"
	"unsafe"
)

type fakeTCPDirectPolicyModel struct {
	generation        uint64
	managedGeneration uint64
	ruleGeneration    uint64
	profileGeneration uint64
	wgID              uint32
	profileID         uint32
	profileFlags      uint32
	payloadLen        uint32
	standardWire      uint32
	mixedWire         uint32
	cipherID          uint32
	action            uint8
	transport         uint8
	typeKind          uint8
	runtime           [16]byte
}

type fakeTCPDirectAdmissionModel struct {
	policy  fakeTCPDirectPolicyModel
	session fakeTCPAdmissionSessionProof
}

func validFakeTCPDirectPolicyModel() fakeTCPDirectPolicyModel {
	return fakeTCPDirectPolicyModel{
		generation: 7, managedGeneration: 7, ruleGeneration: 7, profileGeneration: 7,
		wgID: 9, profileID: 11, profileFlags: 0x21, payloadLen: 128,
		standardWire: 4, mixedWire: 0x13dff06b,
		action: 3, transport: 2, typeKind: 3,
		runtime: [16]byte{1, 2, 3, 4},
	}
}

func fakeTCPDirectAdmissionCheckpointModel(
	policy fakeTCPDirectPolicyModel,
	snapshot fakeTCPAdmissionLockedSnapshot,
) (fakeTCPDirectAdmissionModel, bool) {
	if policy.generation == 0 || policy.managedGeneration != policy.generation ||
		policy.ruleGeneration != policy.generation || policy.profileGeneration != policy.generation ||
		policy.wgID == 0 || policy.cipherID != 0 ||
		policy.action != 3 || policy.transport != 2 || policy.typeKind >= 4 ||
		policy.payloadLen == 0 || policy.standardWire != uint32(policy.typeKind)+1 ||
		snapshot.proof.key.generation != policy.generation ||
		snapshot.proof.key.wgID != policy.wgID || snapshot.proof.lifetime.sessionID == 0 ||
		snapshot.proof.lifetime.incarnation != policy.runtime ||
		snapshot.proof.projection.state != fakeTCPAdmissionSessionEstablished ||
		snapshot.proof.projection.flags != 0 {
		return fakeTCPDirectAdmissionModel{}, false
	}
	return fakeTCPDirectAdmissionModel{policy: policy, session: snapshot.proof}, true
}

func fakeTCPDirectAdmissionMatchesModel(
	admission fakeTCPDirectAdmissionModel,
	current fakeTCPDirectPolicyModel,
) bool {
	return admission.policy == current && current.generation != 0 &&
		current.managedGeneration == current.generation &&
		current.ruleGeneration == current.generation &&
		current.profileGeneration == current.generation && current.cipherID == 0 &&
		admission.session.key.generation == current.generation &&
		admission.session.key.wgID == current.wgID &&
		admission.session.lifetime.incarnation == current.runtime &&
		admission.session.projection.state == fakeTCPAdmissionSessionEstablished &&
		admission.session.projection.flags == 0
}

func validFakeTCPDirectAdmissionFixture(t testing.TB) (
	*fakeTCPAdmissionSessionStore,
	fakeTCPDirectPolicyModel,
	fakeTCPDirectAdmissionModel,
) {
	t.Helper()
	store := validFakeTCPAdmissionSessionStore()
	store.key.wgID = 9
	store.value.lifetime.incarnation = [16]byte{1, 2, 3, 4}
	snapshot, ok := store.snapshot()
	if !ok {
		t.Fatal("valid direct session snapshot failed")
	}
	policy := validFakeTCPDirectPolicyModel()
	admission, ok := fakeTCPDirectAdmissionCheckpointModel(policy, snapshot)
	if !ok {
		t.Fatal("valid direct checkpoint failed")
	}
	return store, policy, admission
}

func TestFakeTCPDirectAdmissionBindsGenerationRuleProfileAndRuntime(t *testing.T) {
	_, current, admission := validFakeTCPDirectAdmissionFixture(t)
	mutations := []struct {
		name   string
		mutate func(*fakeTCPDirectPolicyModel)
	}{
		{"generation", func(v *fakeTCPDirectPolicyModel) { v.generation++ }},
		{"managed generation", func(v *fakeTCPDirectPolicyModel) { v.managedGeneration++ }},
		{"rule generation", func(v *fakeTCPDirectPolicyModel) { v.ruleGeneration++ }},
		{"profile generation", func(v *fakeTCPDirectPolicyModel) { v.profileGeneration++ }},
		{"WireGuard rule", func(v *fakeTCPDirectPolicyModel) { v.wgID++ }},
		{"profile rule", func(v *fakeTCPDirectPolicyModel) { v.profileID++ }},
		{"profile flags", func(v *fakeTCPDirectPolicyModel) { v.profileFlags++ }},
		{"payload", func(v *fakeTCPDirectPolicyModel) { v.payloadLen++ }},
		{"standard type", func(v *fakeTCPDirectPolicyModel) { v.standardWire++ }},
		{"mixed type", func(v *fakeTCPDirectPolicyModel) { v.mixedWire++ }},
		{"cipher", func(v *fakeTCPDirectPolicyModel) { v.cipherID = 1 }},
		{"action", func(v *fakeTCPDirectPolicyModel) { v.action++ }},
		{"transport", func(v *fakeTCPDirectPolicyModel) { v.transport++ }},
		{"type kind", func(v *fakeTCPDirectPolicyModel) { v.typeKind-- }},
		{"runtime incarnation", func(v *fakeTCPDirectPolicyModel) { v.runtime[0]++ }},
	}
	if !fakeTCPDirectAdmissionMatchesModel(admission, current) {
		t.Fatal("fresh direct authority was rejected")
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			changed := current
			test.mutate(&changed)
			if fakeTCPDirectAdmissionMatchesModel(admission, changed) {
				t.Fatal("changed direct authority was accepted")
			}
		})
	}
}

func TestFakeTCPDirectAdmissionFinalWriterRejectsSessionReplacement(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*fakeTCPAdmissionSessionStore)
	}{
		{"session id", func(store *fakeTCPAdmissionSessionStore) { store.value.lifetime.sessionID++ }},
		{"runtime incarnation", func(store *fakeTCPAdmissionSessionStore) { store.value.lifetime.incarnation[0]++ }},
		{"delete claim", func(store *fakeTCPAdmissionSessionStore) {
			store.value.projection.state = fakeTCPAdmissionSessionClaimed
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, current, admission := validFakeTCPDirectAdmissionFixture(t)
			if !fakeTCPDirectAdmissionMatchesModel(admission, current) {
				t.Fatal("fresh direct authority was rejected")
			}
			store.mu.Lock()
			test.mutate(store)
			store.mu.Unlock()
			if _, admitted := store.mutateTX(admission.session, admission.policy.payloadLen); admitted {
				t.Fatal("final locked writer accepted a replaced/claimed session")
			}
		})
	}
}

type fakeTCPDirectProjectionBytes [104]byte
type fakeTCPFullProjectionBytes [184]byte
type fakeTCPFullSlotBytes struct {
	next   uint64
	active fakeTCPFullProjectionBytes
}

var fakeTCPDirectProjectionSink fakeTCPDirectProjectionBytes
var fakeTCPFullProjectionSink fakeTCPFullProjectionBytes
var fakeTCPFullClearedProjectionSink fakeTCPFullProjectionBytes
var fakeTCPFullNonceSink uint64

func TestFakeTCPDirectProjectionModelSizes(t *testing.T) {
	if got := unsafe.Sizeof(fakeTCPDirectProjectionBytes{}); got != 104 {
		t.Fatalf("direct projection model size=%d, want 104", got)
	}
	if got := unsafe.Sizeof(fakeTCPFullSlotBytes{}); got != 192 {
		t.Fatalf("full token slot model size=%d, want 192", got)
	}
}

// This benchmark compares only the modeled projection mechanics. Controlled
// target-host profiling remains authoritative for BPF cycles and acceptance.
func BenchmarkFakeTCPDirectVsTokenProjectionModel(b *testing.B) {
	var directSource fakeTCPDirectProjectionBytes
	var fullSource fakeTCPFullProjectionBytes
	directSource[0], directSource[103] = 1, 2
	fullSource[0], fullSource[183] = 1, 2

	b.Run("direct-compact-authority", func(b *testing.B) {
		var admission fakeTCPDirectProjectionBytes
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			admission = directSource
			if admission[0] != 1 || admission[103] != 2 {
				b.Fatal("direct authority mismatch")
			}
		}
		fakeTCPDirectProjectionSink = admission
	})

	b.Run("legacy-token-copy-consume-replay", func(b *testing.B) {
		var slot fakeTCPFullSlotBytes
		var consumed fakeTCPFullProjectionBytes
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			slot.next++
			slot.active = fullSource
			consumed = slot.active
			slot.active = fakeTCPFullProjectionBytes{}
			if consumed != fullSource {
				b.Fatal("full token replay mismatch")
			}
		}
		fakeTCPFullProjectionSink = consumed
		fakeTCPFullClearedProjectionSink = slot.active
		fakeTCPFullNonceSink = slot.next
	})
}
