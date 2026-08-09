package dataplane

import (
	"math"
	"testing"
)

type fakeTCPAdmissionModelInput struct {
	managed            bool
	policyGeneration   bool
	parserOK           bool
	directionOK        bool
	keyGenerationOK    bool
	lengthOK           bool
	flagsOK            bool
	typeWord           bool
	headerRewrite      bool
	wireFakeTCP        bool
	xor                bool
	xorPolicyOK        bool
	sessionEstablished bool
	gso                bool
}

type fakeTCPAdmissionModelResult struct {
	transform bool
	features  uint8
}

const (
	fakeTCPAdmissionModelTypeWord uint8 = 1 << iota
	fakeTCPAdmissionModelXOR
	fakeTCPAdmissionModelHeader
	fakeTCPAdmissionModelWire
)

func fakeTCPAdmissionCheckpointModel(input fakeTCPAdmissionModelInput) fakeTCPAdmissionModelResult {
	required := input.managed && input.policyGeneration && input.parserOK &&
		input.directionOK && input.keyGenerationOK && input.lengthOK &&
		input.flagsOK && input.typeWord && input.headerRewrite &&
		input.wireFakeTCP && input.sessionEstablished && !input.gso
	if !required || (input.xor && !input.xorPolicyOK) {
		return fakeTCPAdmissionModelResult{}
	}
	features := fakeTCPAdmissionModelTypeWord |
		fakeTCPAdmissionModelHeader | fakeTCPAdmissionModelWire
	if input.xor {
		features |= fakeTCPAdmissionModelXOR
	}
	return fakeTCPAdmissionModelResult{transform: true, features: features}
}

func validFakeTCPAdmissionModelInput() fakeTCPAdmissionModelInput {
	return fakeTCPAdmissionModelInput{
		managed: true, policyGeneration: true, parserOK: true,
		directionOK: true, keyGenerationOK: true, lengthOK: true,
		flagsOK: true, typeWord: true, headerRewrite: true,
		wireFakeTCP: true, xorPolicyOK: true, sessionEstablished: true,
	}
}

func TestFakeTCPAdmissionCheckpointModelRejectsBeforeMutation(t *testing.T) {
	base := validFakeTCPAdmissionModelInput()
	reject := []struct {
		name   string
		mutate func(*fakeTCPAdmissionModelInput)
	}{
		{"unmanaged", func(v *fakeTCPAdmissionModelInput) { v.managed = false }},
		{"policy generation", func(v *fakeTCPAdmissionModelInput) { v.policyGeneration = false }},
		{"parser", func(v *fakeTCPAdmissionModelInput) { v.parserOK = false }},
		{"direction", func(v *fakeTCPAdmissionModelInput) { v.directionOK = false }},
		{"key generation", func(v *fakeTCPAdmissionModelInput) { v.keyGenerationOK = false }},
		{"length", func(v *fakeTCPAdmissionModelInput) { v.lengthOK = false }},
		{"flags", func(v *fakeTCPAdmissionModelInput) { v.flagsOK = false }},
		{"type-word", func(v *fakeTCPAdmissionModelInput) { v.typeWord = false }},
		{"header rewrite", func(v *fakeTCPAdmissionModelInput) { v.headerRewrite = false }},
		{"wire FakeTCP", func(v *fakeTCPAdmissionModelInput) { v.wireFakeTCP = false }},
		{"session", func(v *fakeTCPAdmissionModelInput) { v.sessionEstablished = false }},
		{"GSO/GRO", func(v *fakeTCPAdmissionModelInput) { v.gso = true }},
		{"XOR policy", func(v *fakeTCPAdmissionModelInput) { v.xor = true; v.xorPolicyOK = false }},
	}
	for _, test := range reject {
		t.Run(test.name, func(t *testing.T) {
			input := base
			test.mutate(&input)
			got := fakeTCPAdmissionCheckpointModel(input)
			if got.transform || got.features != 0 {
				t.Fatalf("rejected input leaked a transform: %+v", got)
			}
		})
	}
}

func TestFakeTCPAdmissionCheckpointModelFeatureProperty(t *testing.T) {
	for mask := uint16(0); mask < 1<<13; mask++ {
		input := fakeTCPAdmissionModelInput{
			managed: mask&(1<<0) != 0, policyGeneration: mask&(1<<1) != 0,
			parserOK: mask&(1<<2) != 0, directionOK: mask&(1<<3) != 0,
			keyGenerationOK: mask&(1<<4) != 0, lengthOK: mask&(1<<5) != 0,
			flagsOK: mask&(1<<6) != 0, typeWord: mask&(1<<7) != 0,
			headerRewrite: mask&(1<<8) != 0, wireFakeTCP: mask&(1<<9) != 0,
			xor: mask&(1<<10) != 0, sessionEstablished: mask&(1<<11) != 0,
			gso:         mask&(1<<12) != 0,
			xorPolicyOK: true,
		}
		got := fakeTCPAdmissionCheckpointModel(input)
		want := input.managed && input.policyGeneration && input.parserOK &&
			input.directionOK && input.keyGenerationOK && input.lengthOK &&
			input.flagsOK && input.typeWord && input.headerRewrite &&
			input.wireFakeTCP && input.sessionEstablished && !input.gso
		if got.transform != want || (!want && got.features != 0) {
			t.Fatalf("mask=%013b result=%+v want transform=%v", mask, got, want)
		}
		if got.transform && got.features&fakeTCPAdmissionModelXOR != 0 != input.xor {
			t.Fatalf("mask=%013b feature projection=%04b xor=%v", mask, got.features, input.xor)
		}
	}
}

func BenchmarkFakeTCPAdmissionCheckpointHotPath(b *testing.B) {
	input := validFakeTCPAdmissionModelInput()
	input.xor = true
	var result fakeTCPAdmissionModelResult
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result = fakeTCPAdmissionCheckpointModel(input)
	}
	if !result.transform {
		b.Fatal("valid hot path rejected")
	}
}

type fakeTCPTokenState uint8

const (
	fakeTCPTokenFree fakeTCPTokenState = iota
	fakeTCPTokenArmed
	fakeTCPTokenXORComplete
)

type fakeTCPTokenProjection struct {
	flowPolicySession uint64
	features          uint8
}

type fakeTCPTokenSlot struct {
	counter    uint64
	nonce      uint64
	state      fakeTCPTokenState
	projection fakeTCPTokenProjection
}

func (slot *fakeTCPTokenSlot) arm(projection fakeTCPTokenProjection) (uint64, bool) {
	if slot.nonce != 0 || slot.state != fakeTCPTokenFree || slot.counter == math.MaxUint64 ||
		projection.flowPolicySession == 0 || projection.features == 0 {
		// Production discards a stale active projection and rejects this packet;
		// the monotonic counter is deliberately retained.
		slot.nonce = 0
		slot.state = fakeTCPTokenFree
		slot.projection = fakeTCPTokenProjection{}
		return 0, false
	}
	slot.counter++
	if slot.counter == 0 {
		return 0, false
	}
	slot.nonce = slot.counter
	slot.state = fakeTCPTokenArmed
	slot.projection = projection
	return slot.nonce, true
}

func (slot *fakeTCPTokenSlot) completeXOR(nonce uint64) bool {
	if nonce == 0 || nonce != slot.nonce || slot.state != fakeTCPTokenArmed {
		return false
	}
	slot.state = fakeTCPTokenXORComplete
	return true
}

func (slot *fakeTCPTokenSlot) consume(
	nonce uint64,
	required fakeTCPTokenState,
	want fakeTCPTokenProjection,
) bool {
	activeNonce, activeState, activeProjection := slot.nonce, slot.state, slot.projection
	// Consume always clears active before comparing and never clears counter.
	slot.nonce = 0
	slot.state = fakeTCPTokenFree
	slot.projection = fakeTCPTokenProjection{}
	return nonce != 0 && nonce == activeNonce && required == activeState &&
		want == activeProjection
}

func TestFakeTCPAdmissionTokenIsSingleUseAndStateBound(t *testing.T) {
	projection := fakeTCPTokenProjection{flowPolicySession: 0x1020304050607080, features: 0xf}
	var direct fakeTCPTokenSlot
	directNonce, ok := direct.arm(projection)
	if !ok || directNonce == 0 || !direct.consume(directNonce, fakeTCPTokenArmed, projection) {
		t.Fatal("valid direct ARMED token was rejected")
	}
	if direct.consume(directNonce, fakeTCPTokenArmed, projection) {
		t.Fatal("consumed direct token replayed")
	}
	if direct.counter != directNonce {
		t.Fatal("consume moved the monotonic counter backwards")
	}

	var xor fakeTCPTokenSlot
	xorNonce, ok := xor.arm(projection)
	if !ok || !xor.completeXOR(xorNonce) ||
		!xor.consume(xorNonce, fakeTCPTokenXORComplete, projection) {
		t.Fatal("valid XOR_COMPLETE token was rejected")
	}
	if xor.completeXOR(xorNonce) || xor.consume(xorNonce, fakeTCPTokenXORComplete, projection) {
		t.Fatal("completed XOR token replayed")
	}
}

func TestFakeTCPAdmissionTokenMismatchConsumesFailClosed(t *testing.T) {
	projection := fakeTCPTokenProjection{flowPolicySession: 7, features: 0xd}
	for _, test := range []struct {
		name       string
		nonce      func(uint64) uint64
		state      fakeTCPTokenState
		projection fakeTCPTokenProjection
	}{
		{name: "zero nonce", nonce: func(uint64) uint64 { return 0 }, state: fakeTCPTokenArmed, projection: projection},
		{name: "stale nonce", nonce: func(n uint64) uint64 { return n + 1 }, state: fakeTCPTokenArmed, projection: projection},
		{name: "wrong state", nonce: func(n uint64) uint64 { return n }, state: fakeTCPTokenXORComplete, projection: projection},
		{name: "projection drift", nonce: func(n uint64) uint64 { return n }, state: fakeTCPTokenArmed, projection: fakeTCPTokenProjection{flowPolicySession: 8, features: 0xd}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var slot fakeTCPTokenSlot
			nonce, ok := slot.arm(projection)
			if !ok {
				t.Fatal("arm failed")
			}
			if slot.consume(test.nonce(nonce), test.state, test.projection) {
				t.Fatal("mismatched token admitted")
			}
			if slot.nonce != 0 || slot.state != fakeTCPTokenFree ||
				slot.projection != (fakeTCPTokenProjection{}) || slot.counter != nonce {
				t.Fatalf("mismatch did not clear only active: %+v", slot)
			}
		})
	}
}

func TestFakeTCPAdmissionTokenConsumeProperty(t *testing.T) {
	projection := fakeTCPTokenProjection{flowPolicySession: 0xa5, features: 0xf}
	for mask := uint8(0); mask < 1<<4; mask++ {
		slot := fakeTCPTokenSlot{
			counter: 7, nonce: 7, state: fakeTCPTokenArmed,
			projection: projection,
		}
		nonce := uint64(7)
		required := fakeTCPTokenArmed
		wantProjection := projection
		if mask&(1<<0) != 0 {
			nonce++
		}
		if mask&(1<<1) != 0 {
			required = fakeTCPTokenXORComplete
		}
		if mask&(1<<2) != 0 {
			wantProjection.flowPolicySession++
		}
		if mask&(1<<3) != 0 {
			wantProjection.features ^= 1
		}
		accepted := slot.consume(nonce, required, wantProjection)
		if accepted != (mask == 0) {
			t.Fatalf("mask=%04b accepted=%v", mask, accepted)
		}
		if slot.counter != 7 || slot.nonce != 0 || slot.state != fakeTCPTokenFree ||
			slot.projection != (fakeTCPTokenProjection{}) {
			t.Fatalf("mask=%04b consume did not clear only active: %+v", mask, slot)
		}
	}
}

func TestFakeTCPAdmissionTokenNonceNeverWrapsOrReuses(t *testing.T) {
	projection := fakeTCPTokenProjection{flowPolicySession: 1, features: 0xf}
	slot := fakeTCPTokenSlot{counter: math.MaxUint64}
	if nonce, ok := slot.arm(projection); ok || nonce != 0 || slot.counter != math.MaxUint64 {
		t.Fatalf("saturated counter armed or moved: nonce=%d slot=%+v", nonce, slot)
	}

	var fresh fakeTCPTokenSlot
	first, ok := fresh.arm(projection)
	if !ok || !fresh.consume(first, fakeTCPTokenArmed, projection) {
		t.Fatal("first token failed")
	}
	second, ok := fresh.arm(projection)
	if !ok || second <= first {
		t.Fatalf("nonce was reused: first=%d second=%d", first, second)
	}
	if fresh.consume(first, fakeTCPTokenArmed, projection) {
		t.Fatal("residual cb nonce consumed a newer token")
	}
}

func TestFakeTCPAdmissionTokenPerCPUTailChainInvariant(t *testing.T) {
	// Networking BPF and its synchronous tail calls cannot migrate CPUs. Each
	// CPU therefore owns one independent slot from checkpoint through consume.
	projectionA := fakeTCPTokenProjection{flowPolicySession: 1, features: 0xf}
	projectionB := fakeTCPTokenProjection{flowPolicySession: 2, features: 0xf}
	var perCPU [2]fakeTCPTokenSlot
	nonceA, _ := perCPU[0].arm(projectionA)
	nonceB, _ := perCPU[1].arm(projectionB)
	if nonceA != nonceB {
		t.Fatal("fixture should demonstrate that nonce uniqueness is per CPU")
	}
	if perCPU[1].consume(nonceA, fakeTCPTokenArmed, projectionA) {
		t.Fatal("a different CPU/projection admitted the token")
	}
	if !perCPU[0].consume(nonceA, fakeTCPTokenArmed, projectionA) {
		t.Fatal("same-CPU synchronous chain did not admit its token")
	}
}

func BenchmarkFakeTCPAdmissionTokenConsumeHotPath(b *testing.B) {
	projection := fakeTCPTokenProjection{flowPolicySession: 1, features: 0xf}
	var slot fakeTCPTokenSlot
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		nonce, ok := slot.arm(projection)
		if !ok || !slot.completeXOR(nonce) ||
			!slot.consume(nonce, fakeTCPTokenXORComplete, projection) {
			b.Fatal("valid hot-path token rejected")
		}
	}
}
