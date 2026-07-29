package app

import (
	"path/filepath"
	"testing"
)

func TestIsolatedNetNSTestPaths(t *testing.T) {
	base := filepath.Join(isolatedNetNSTestRoot, "0123456789abcdef")
	layout, err := isolatedNetNSTestPaths(
		"reload",
		filepath.Join(base, "secrets", "agent-a.yaml"),
		filepath.Join(base, "run-a"),
		filepath.Join(base, "state-a"),
		filepath.Join(base, "bpffs", "wg-mix-ebpf-a"),
	)
	if err != nil {
		t.Fatalf("isolatedNetNSTestPaths() error = %v", err)
	}
	if layout.runBase != base {
		t.Fatalf("run base = %q, want %q", layout.runBase, base)
	}
	if layout.lease != filepath.Join(base, "run-a", "daemon.lease") {
		t.Fatalf("lease = %q", layout.lease)
	}
}

func TestIsolatedNetNSTestPathsRejectsEscapesAndMismatches(t *testing.T) {
	base := filepath.Join(isolatedNetNSTestRoot, "01234567")
	validConfig := filepath.Join(base, "secrets", "agent-client.yaml")
	validRun := filepath.Join(base, "run-client")
	validState := filepath.Join(base, "state-client")
	validPin := filepath.Join(base, "bpffs", "wg-mix-ebpf-client")

	tests := []struct {
		name   string
		cmd    string
		config string
		run    string
		state  string
		pin    string
	}{
		{name: "read-only command", cmd: "status", config: validConfig, run: validRun, state: validState, pin: validPin},
		{name: "short run id", cmd: "reload", config: validConfig, run: filepath.Join(isolatedNetNSTestRoot, "1234", "run-client"), state: validState, pin: validPin},
		{name: "state role mismatch", cmd: "reload", config: validConfig, run: validRun, state: filepath.Join(base, "state-server"), pin: validPin},
		{name: "config outside secrets", cmd: "reload", config: filepath.Join(base, "agent.yaml"), run: validRun, state: validState, pin: validPin},
		{name: "pin outside bpffs", cmd: "detach", config: validConfig, run: validRun, state: validState, pin: filepath.Join(base, "wg-mix-ebpf-client")},
		{name: "noncanonical run", cmd: "reload", config: validConfig, run: base + "/evidence/../run-client", state: validState, pin: validPin},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := isolatedNetNSTestPaths(
				tt.cmd,
				tt.config,
				tt.run,
				tt.state,
				tt.pin,
			); err == nil {
				t.Fatal("isolatedNetNSTestPaths() unexpectedly succeeded")
			}
		})
	}
}
