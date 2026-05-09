package profile

import (
	"encoding/binary"
	"testing"

	"github.com/syx0310/wg-mix-ebpf/internal/config"
)

func TestCompilePreset(t *testing.T) {
	compiled, err := Compile("default", config.Profile{
		Preset: "wireguard-mix-wire-values-v1",
		Index:  config.IndexProfile{Mode: "none"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if compiled.StandardToMixed != WireguardMixWireValuesV1 {
		t.Fatalf("unexpected preset values: %#v", compiled.StandardToMixed)
	}
}

func TestRejectDuplicateMixedValues(t *testing.T) {
	_, err := Compile("bad", config.Profile{
		TypeWord: config.TypeWordProfile{
			Initiation:    10,
			Response:      10,
			CookieReply:   11,
			TransportData: 12,
		},
		Index: config.IndexProfile{Mode: "none"},
	})
	if err == nil {
		t.Fatal("expected duplicate mixed value error")
	}
}

func TestRejectStandardMixedValue(t *testing.T) {
	_, err := Compile("bad", config.Profile{
		TypeWord: config.TypeWordProfile{
			Initiation:    1,
			Response:      10,
			CookieReply:   11,
			TransportData: 12,
		},
		Index: config.IndexProfile{Mode: "none"},
	})
	if err == nil {
		t.Fatal("expected standard passthrough error")
	}
}

func TestWireLittleEndianValue(t *testing.T) {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], 0xf658c2e6)
	want := [4]byte{0xe6, 0xc2, 0x58, 0xf6}
	if buf != want {
		t.Fatalf("wire bytes = % x, want % x", buf, want)
	}
}

func TestTokenRoundTrip(t *testing.T) {
	cfg := config.Profile{
		TypeWord: config.TypeWordProfile{
			Initiation:    0x11111111,
			Response:      0x22222222,
			CookieReply:   0x33333333,
			TransportData: 0x44444444,
		},
		Index: config.IndexProfile{Mode: "none"},
	}
	token, err := EncodeToken(cfg)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeToken(token)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := Compile("decoded", decoded)
	if err != nil {
		t.Fatal(err)
	}
	want := [4]uint32{0x11111111, 0x22222222, 0x33333333, 0x44444444}
	if compiled.StandardToMixed != want {
		t.Fatalf("decoded values = %#v, want %#v", compiled.StandardToMixed, want)
	}
}

func TestTokenRejectsChecksumMismatch(t *testing.T) {
	cfg, err := Preset("wireguard-mix-wire-values-v1")
	if err != nil {
		t.Fatal(err)
	}
	token, err := EncodeToken(cfg)
	if err != nil {
		t.Fatal(err)
	}
	bad := token[:len(token)-1] + "0"
	if bad == token {
		bad = token[:len(token)-1] + "1"
	}
	if _, err := DecodeToken(bad); err == nil {
		t.Fatal("expected checksum mismatch")
	}
}

func TestGenerateRandomCompiles(t *testing.T) {
	cfg, err := GenerateRandom()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Compile("random", cfg); err != nil {
		t.Fatal(err)
	}
}
