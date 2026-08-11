//go:build !linux

package netnsanchor

import "errors"

// Run reports the platform constraint without attempting a substitute
// implementation. Anonymous network namespace anchors are Linux-only.
func Run(_ []string) error {
	return errors.New("anonymous network namespace anchors require Linux")
}
