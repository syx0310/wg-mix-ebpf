package daemon

import (
	"strings"
	"testing"
)

func TestValidateConfigPathForRequest(t *testing.T) {
	status := &Status{ConfigPath: "/etc/wg-mix-ebpf/config.yaml"}
	if err := ValidateConfigPathForRequest(status, "/etc/wg-mix-ebpf/config.yaml", "reload"); err != nil {
		t.Fatalf("same config rejected: %v", err)
	}
	err := ValidateConfigPathForRequest(status, "/tmp/other.yaml", "reload")
	if err == nil {
		t.Fatal("expected mismatched config to be rejected")
	}
	if !strings.Contains(err.Error(), "refusing reload request") {
		t.Fatalf("unexpected error: %v", err)
	}
}
