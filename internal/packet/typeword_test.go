package packet

import "testing"

func TestWireRoundTrip(t *testing.T) {
	wire := ToWire(0xf658c2e6)
	want := [4]byte{0xe6, 0xc2, 0x58, 0xf6}
	if wire != want {
		t.Fatalf("wire = % x, want % x", wire, want)
	}
	got, err := FromWire(wire[:])
	if err != nil {
		t.Fatal(err)
	}
	if got != 0xf658c2e6 {
		t.Fatalf("type word = 0x%08x", got)
	}
}

func TestValidatePayloadLength(t *testing.T) {
	cases := []struct {
		kind MessageKind
		size int
		ok   bool
	}{
		{MessageInitiation, 148, true},
		{MessageInitiation, 147, false},
		{MessageResponse, 92, true},
		{MessageCookieReply, 64, true},
		{MessageTransportData, 32, true},
		{MessageTransportData, 48, true},
		{MessageTransportData, 33, false},
		{MessageTransportData, 31, false},
	}
	for _, tc := range cases {
		err := ValidatePayloadLength(tc.kind, tc.size)
		if tc.ok && err != nil {
			t.Fatalf("%s/%d expected ok: %v", tc.kind, tc.size, err)
		}
		if !tc.ok && err == nil {
			t.Fatalf("%s/%d expected error", tc.kind, tc.size)
		}
	}
}

func TestContainsStandardTypeWord(t *testing.T) {
	wire := ToWire(StandardResponse)
	if !ContainsStandardTypeWord(wire[:]) {
		t.Fatal("expected standard type word")
	}
	mixed := ToWire(0xf658c2e6)
	if ContainsStandardTypeWord(mixed[:]) {
		t.Fatal("mixed value detected as standard")
	}
}
