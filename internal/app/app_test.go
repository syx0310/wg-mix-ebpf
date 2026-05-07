package app

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestValidateOffline(t *testing.T) {
	dir := t.TempDir()
	wgPath := filepath.Join(dir, "wg0.conf")
	if err := os.WriteFile(wgPath, []byte("[Interface]\nFwMark = 0x10000002\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(`
version: 1
underlays:
  - name: eth0
    type: netdev
wireguards:
  - name: wg0
    config: `+wgPath+`
    profile: mix-default
profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := Run(t.Context(), []string{"validate", "--config", cfgPath, "--offline"}, &stdout, &stderr); err != nil {
		t.Fatalf("Run returned error: %v stderr=%s", err, stderr.String())
	}
	if stdout.String() != "ok\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
}
