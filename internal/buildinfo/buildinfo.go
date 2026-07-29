package buildinfo

import (
	"strings"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
	"github.com/syx0310/wg-mix-ebpf/internal/dataplane"
)

const (
	Version       = "dev"
	UnknownCommit = "unknown"
	UnknownSHA256 = "unknown"
)

// sourceCommit is intentionally unknown unless an audited build entrypoint
// supplies a clean Git commit with -ldflags -X.
var sourceCommit = UnknownCommit

// Info identifies the userspace source and the exact BPF bytes embedded in the
// same executable.
type Info struct {
	Version                 string `json:"version"`
	SourceCommit            string `json:"source_commit"`
	EmbeddedBPFObjectSHA256 string `json:"embedded_bpf_object_sha256"`
	BPFABIVersion           uint32 `json:"bpf_abi_version"`
}

func Current() Info {
	objectSHA256 := UnknownSHA256
	if object, err := dataplane.EmbeddedObjectIdentity(); err == nil {
		objectSHA256 = object.SHA256
	}
	return Info{
		Version:                 Version,
		SourceCommit:            SourceCommit(),
		EmbeddedBPFObjectSHA256: objectSHA256,
		BPFABIVersion:           abi.Version,
	}
}

func SourceCommit() string {
	return normalizeSourceCommit(sourceCommit)
}

func normalizeSourceCommit(value string) string {
	if len(value) != 40 || strings.IndexFunc(value, func(r rune) bool {
		return (r < '0' || r > '9') && (r < 'a' || r > 'f')
	}) >= 0 {
		return UnknownCommit
	}
	return value
}
