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
