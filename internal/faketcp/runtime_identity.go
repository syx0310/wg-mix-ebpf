package faketcp

import (
	"crypto/rand"
	"errors"
	"fmt"
)

const RuntimeIncarnationSize = 16

// RuntimeIncarnation is a cryptographically random identity for exactly one
// in-memory Engine lifetime. New always creates a fresh value and there is
// intentionally no API for assigning an old value to a new empty Engine.
// Reusing an incarnation is only safe after the daemon can atomically restore
// the complete Engine state, which is not implemented while activation is
// gated.
type RuntimeIncarnation [RuntimeIncarnationSize]byte

// RuntimeIdentity binds an Engine lifetime to its kernel generation. The same
// value must seed the experimental BPF runtime-identity map before events from
// that generation are accepted.
type RuntimeIdentity struct {
	Generation  uint64
	Incarnation RuntimeIncarnation
}

func newRuntimeIncarnation() (RuntimeIncarnation, error) {
	var incarnation RuntimeIncarnation
	if _, err := rand.Read(incarnation[:]); err != nil {
		return RuntimeIncarnation{}, fmt.Errorf("generate faketcp runtime incarnation: %w", err)
	}
	if incarnation == (RuntimeIncarnation{}) {
		return RuntimeIncarnation{}, errors.New("generated zero faketcp runtime incarnation")
	}
	return incarnation, nil
}

func validateRuntimeIdentity(identity RuntimeIdentity) error {
	if identity.Generation == 0 {
		return errors.New("faketcp runtime identity generation is zero")
	}
	if identity.Incarnation == (RuntimeIncarnation{}) {
		return errors.New("faketcp runtime identity incarnation is zero")
	}
	return nil
}
