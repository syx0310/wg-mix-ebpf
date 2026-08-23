//go:build !linux

package guard

import (
	"errors"
	"testing"
)

func TestDefaultProjectTablePreflightIsExplicitlyUnsupportedOffLinux(t *testing.T) {
	outcome, err := NewProjectTablePreflight().Check(t.Context())
	if !errors.Is(err, ErrNFTableInventoryUnsupported) {
		t.Fatalf("default off-Linux preflight error = %v, want unsupported", err)
	}
	if outcome.Observation != ObservationUnknown || outcome.Mutated || outcome.Warning != nil {
		t.Fatalf("default off-Linux preflight outcome = %#v, want unknown and non-mutating", outcome)
	}
}
