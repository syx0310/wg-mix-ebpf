//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package testutil

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestRunWithStandardUmaskNormalizesModesAndRestoresCaller(t *testing.T) {
	original := syscall.Umask(0o002)
	defer syscall.Umask(original)

	const wantResult = 37
	result := RunWithStandardUmask(func() int {
		current := syscall.Umask(standardTestUmask)
		if current != standardTestUmask {
			t.Errorf("umask inside test run = %#03o, want %#03o", current, standardTestUmask)
		}

		tempDir := t.TempDir()
		requireTestMode(t, tempDir, 0o755)
		if info, err := os.Stat(tempDir); err != nil {
			t.Fatalf("inspect TempDir %s: %v", tempDir, err)
		} else if info.Mode().Perm()&0o022 != 0 {
			t.Fatalf("TempDir %s remains group/other writable: mode=%#o", tempDir, info.Mode().Perm())
		}

		publicDir := filepath.Join(tempDir, "requested-0755")
		if err := os.Mkdir(publicDir, 0o755); err != nil {
			t.Fatalf("create requested 0755 directory: %v", err)
		}
		requireTestMode(t, publicDir, 0o755)

		unitPath := filepath.Join(tempDir, "requested-0644.service")
		if err := os.WriteFile(unitPath, []byte("[Unit]\n"), 0o644); err != nil {
			t.Fatalf("create requested 0644 unit: %v", err)
		}
		requireTestMode(t, unitPath, 0o644)

		scriptPath := filepath.Join(tempDir, "requested-0755-script")
		if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatalf("create requested 0755 script: %v", err)
		}
		requireTestMode(t, scriptPath, 0o755)
		return wantResult
	})
	if result != wantResult {
		t.Fatalf("run result = %d, want %d", result, wantResult)
	}

	after := syscall.Umask(0o002)
	if after != 0o002 {
		t.Fatalf("umask after test run = %#03o, want restored caller mask 002", after)
	}
}

func requireTestMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("inspect mode for %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("mode for %s = %#o, want %#o", path, got, want)
	}
}
