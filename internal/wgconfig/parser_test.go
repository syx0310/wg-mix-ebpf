package wgconfig

import (
	"strings"
	"testing"
)

func TestParseInterfaceFwMarkAndListenPort(t *testing.T) {
	cfg, err := Parse(strings.NewReader(`
[Interface]
PrivateKey = should-not-matter
ListenPort = 31001
FwMark = 0x10000002

[Peer]
PublicKey = ignored
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FwMark == nil || *cfg.FwMark != 0x10000002 {
		t.Fatalf("unexpected fwmark: %#v", cfg.FwMark)
	}
	if cfg.ListenPort == nil || *cfg.ListenPort != 31001 {
		t.Fatalf("unexpected listen port: %#v", cfg.ListenPort)
	}
}

func TestParseFwMarkOff(t *testing.T) {
	mark, err := ParseFwMark("off")
	if err != nil {
		t.Fatal(err)
	}
	if mark != 0 {
		t.Fatalf("off parsed to %d", mark)
	}
}

func TestParseMissingFwMark(t *testing.T) {
	cfg, err := Parse(strings.NewReader(`
[Interface]
ListenPort = 31001
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FwMark != nil {
		t.Fatalf("expected nil fwmark, got %#v", *cfg.FwMark)
	}
}
