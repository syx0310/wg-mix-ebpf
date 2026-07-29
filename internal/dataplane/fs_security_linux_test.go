//go:build linux

package dataplane

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAnchoredBPFFSRootAcceptsSafeObservedModeAndRejectsWritableMode(t *testing.T) {
	tests := []struct {
		name    string
		mode    os.FileMode
		wantErr string
	}{
		{name: "private 0700", mode: 0o700},
		{name: "system 0755", mode: 0o755},
		{name: "group writable", mode: 0o775, wantErr: "group/other writable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parent := t.TempDir()
			path := filepath.Join(parent, "bpffs")
			if err := os.Mkdir(path, tt.mode); err != nil {
				t.Fatal(err)
			}
			anchor, _, err := openAnchoredDirectoryPath(
				path,
				false,
				0,
				uint32(os.Getuid()),
				true,
			)
			if anchor != nil {
				defer anchor.Close()
			}
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("open safe mode %#o: %v", tt.mode, err)
				}
				if err := anchor.Recheck(); err != nil {
					t.Fatalf("recheck safe mode %#o: %v", tt.mode, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("mode %#o error = %v, want %q", tt.mode, err, tt.wantErr)
			}
		})
	}
}

func TestAnchoredBPFFSRootRejectsOwnerMismatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bpffs")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	anchor, _, err := openAnchoredDirectoryPath(
		path,
		false,
		0,
		uint32(os.Getuid())+1,
		true,
	)
	if anchor != nil {
		defer anchor.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "uid=") {
		t.Fatalf("owner mismatch error = %v", err)
	}
}
