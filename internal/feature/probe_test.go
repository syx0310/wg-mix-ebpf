package feature

import "testing"

func TestRunProbe(t *testing.T) {
	p := Run()
	if p.GOOS == "" || p.GOARCH == "" {
		t.Fatalf("missing platform: %#v", p)
	}
	if p.Commands == nil {
		t.Fatal("commands map is nil")
	}
	if _, err := p.JSON(); err != nil {
		t.Fatal(err)
	}
}

func TestSupportedArch(t *testing.T) {
	if !supportedArch("amd64") || !supportedArch("arm64") {
		t.Fatal("tier1 arch not supported")
	}
	if supportedArch("386") {
		t.Fatal("32-bit arch should not be MVP supported")
	}
}
