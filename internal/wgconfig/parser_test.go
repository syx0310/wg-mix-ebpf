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

func TestParseFwMarkFromPostUp(t *testing.T) {
	cfg, err := Parse(strings.NewReader(`
[Interface]
ListenPort = 21000
PostUp = /sbin/ip addr add dev %i 10.191.65.2/32 peer 10.191.65.1/32
PostUp = wg set %i fwmark 0x46
Table = off
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FwMark == nil || *cfg.FwMark != 0x46 {
		t.Fatalf("unexpected fwmark: %#v", cfg.FwMark)
	}
}

func TestParseFwMarkFromPostUpAbsoluteWGPath(t *testing.T) {
	cfg, err := Parse(strings.NewReader(`
[Interface]
PostUp = /usr/bin/wg set %i fwmark "0x10005303"
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FwMark == nil || *cfg.FwMark != 0x10005303 {
		t.Fatalf("unexpected fwmark: %#v", cfg.FwMark)
	}
}

func TestParseFwMarkFromPostUpCommandChain(t *testing.T) {
	cfg, err := Parse(strings.NewReader(`
[Interface]
PostUp = /sbin/ip addr add dev %i 10.191.65.2/32 peer 10.191.65.1/32 && wg set %i fwmark 70
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FwMark == nil || *cfg.FwMark != 70 {
		t.Fatalf("unexpected fwmark: %#v", cfg.FwMark)
	}
}

func TestParseCommentedPostUpFwMarkIsIgnored(t *testing.T) {
	cfg, err := Parse(strings.NewReader(`
[Interface]
#PostUp = wg set %i fwmark 0x46
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FwMark != nil {
		t.Fatalf("expected commented postup to be ignored, got %#v", *cfg.FwMark)
	}
}

func TestExplicitFwMarkWinsOverPostUp(t *testing.T) {
	cfg, err := Parse(strings.NewReader(`
[Interface]
FwMark = 0x10000002
PostUp = wg set %i fwmark 0x46
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FwMark == nil || *cfg.FwMark != 0x10000002 {
		t.Fatalf("unexpected fwmark: %#v", cfg.FwMark)
	}
}
