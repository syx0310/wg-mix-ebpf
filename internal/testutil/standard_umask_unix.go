//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

// Package testutil contains process-wide helpers used only by test binaries.
package testutil

import "syscall"

const standardTestUmask = 0o022

// RunWithStandardUmask makes testing.T.TempDir children deterministic without
// changing requested 0755 and 0644 modes in the production code under test.
// A caller umask such as 0002 would otherwise make TempDir's numbered
// directories group-writable. The caller's original umask is restored after
// run returns, panics, or exits its goroutine.
func RunWithStandardUmask(run func() int) int {
	previous := syscall.Umask(standardTestUmask)
	defer syscall.Umask(previous)
	return run()
}
