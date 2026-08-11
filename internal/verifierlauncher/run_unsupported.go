//go:build !linux

package verifierlauncher

import "fmt"

// Run rejects non-Linux execution. Linux cross-compilation remains available
// from any supported development host.
func Run(_ []string) error {
	return fmt.Errorf("FakeTCP verifier launcher requires Linux")
}
