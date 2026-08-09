package dataplane

import "testing"

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
		input.wireFakeTCP && input.sessionEstablished
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
	for mask := uint16(0); mask < 1<<12; mask++ {
		input := fakeTCPAdmissionModelInput{
			managed: mask&(1<<0) != 0, policyGeneration: mask&(1<<1) != 0,
			parserOK: mask&(1<<2) != 0, directionOK: mask&(1<<3) != 0,
			keyGenerationOK: mask&(1<<4) != 0, lengthOK: mask&(1<<5) != 0,
			flagsOK: mask&(1<<6) != 0, typeWord: mask&(1<<7) != 0,
			headerRewrite: mask&(1<<8) != 0, wireFakeTCP: mask&(1<<9) != 0,
			xor: mask&(1<<10) != 0, sessionEstablished: mask&(1<<11) != 0,
			xorPolicyOK: true,
		}
		got := fakeTCPAdmissionCheckpointModel(input)
		want := input.managed && input.policyGeneration && input.parserOK &&
			input.directionOK && input.keyGenerationOK && input.lengthOK &&
			input.flagsOK && input.typeWord && input.headerRewrite &&
			input.wireFakeTCP && input.sessionEstablished
		if got.transform != want || (!want && got.features != 0) {
			t.Fatalf("mask=%012b result=%+v want transform=%v", mask, got, want)
		}
		if got.transform && got.features&fakeTCPAdmissionModelXOR != 0 != input.xor {
			t.Fatalf("mask=%012b feature projection=%04b xor=%v", mask, got.features, input.xor)
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
