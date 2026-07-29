package buildinfo

import (
	"regexp"
	"testing"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

func TestNormalizeSourceCommit(t *testing.T) {
	valid := "0123456789abcdef0123456789abcdef01234567"
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "valid", value: valid, want: valid},
		{name: "default", value: UnknownCommit, want: UnknownCommit},
		{name: "empty", value: "", want: UnknownCommit},
		{name: "short", value: valid[:12], want: UnknownCommit},
		{name: "uppercase", value: "0123456789ABCDEF0123456789ABCDEF01234567", want: UnknownCommit},
		{name: "shell syntax", value: "$(touch injected)0123456789abcdef01234567", want: UnknownCommit},
		{name: "newline", value: valid[:39] + "\n", want: UnknownCommit},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeSourceCommit(tt.value); got != tt.want {
				t.Fatalf("normalizeSourceCommit(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestCurrentHasDeterministicDefaults(t *testing.T) {
	info := Current()
	if info.Version != Version {
		t.Fatalf("version = %q, want %q", info.Version, Version)
	}
	if info.SourceCommit != UnknownCommit {
		t.Fatalf("source commit = %q, want %q", info.SourceCommit, UnknownCommit)
	}
	if info.BPFABIVersion != abi.Version {
		t.Fatalf("BPF ABI version = %d, want %d", info.BPFABIVersion, abi.Version)
	}
	if info.EmbeddedBPFObjectSHA256 != UnknownSHA256 &&
		!regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(info.EmbeddedBPFObjectSHA256) {
		t.Fatalf("embedded BPF SHA-256 = %q", info.EmbeddedBPFObjectSHA256)
	}
}
