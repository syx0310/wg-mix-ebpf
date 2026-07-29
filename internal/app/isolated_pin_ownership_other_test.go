//go:build !linux

package app

import (
	"bytes"
	"strings"
	"testing"
)

func TestIsolatedOwnershipBridgeExplicitlyRejectsNonLinux(t *testing.T) {
	t.Setenv(
		"WG_MIX_EBPF_PIN_PATH",
		"/run/wg-mix-ebpf-tests/0123456789abcdef/bpffs/wg-mix-ebpf-a",
	)
	var stdout bytes.Buffer
	err := runIsolatedPinOwnershipCommand(
		t.Context(),
		[]string{
			"--operation", "inspect",
			"--isolated-netns-test",
			"--config", "/run/wg-mix-ebpf-tests/0123456789abcdef/secrets/agent-a.yaml",
			"--run-dir", "/run/wg-mix-ebpf-tests/0123456789abcdef/run-a",
			"--state-dir", "/run/wg-mix-ebpf-tests/0123456789abcdef/state-a",
		},
		&stdout,
	)
	if err == nil || !strings.Contains(err.Error(), "only supported on Linux") {
		t.Fatalf("non-Linux isolated ownership bridge error = %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("non-Linux bridge wrote output: %q", stdout.String())
	}
}
