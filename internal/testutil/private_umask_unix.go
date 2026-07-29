//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

// Package testutil contains process-wide helpers used only by test binaries.
package testutil

import (
	"syscall"
	"testing"
)

// RunWithPrivateUmask makes testing.T.TempDir children deterministic for
// security-sensitive tests. Go 1.26 creates numbered TempDir children with
// mode 0777 filtered by the process umask; a caller umask such as 0002 would
// otherwise make those children group-writable.
func RunWithPrivateUmask(m *testing.M) int {
	previous := syscall.Umask(0o077)
	result := m.Run()
	syscall.Umask(previous)
	return result
}
