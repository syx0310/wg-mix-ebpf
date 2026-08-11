//go:build linux

package dataplane

import "fmt"

// wrapNonNilError preserves errors.Join's nil-elision while adding operation
// context. Experimental resource owners use it independently of the Classic
// TCX recovery implementation where this helper was originally introduced.
func wrapNonNilError(prefix string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", prefix, err)
}
