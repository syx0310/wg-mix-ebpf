package faketcp

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
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

// CaptureIdentity is globally scoped by one Engine incarnation and kernel
// generation, then uniquely allocated by CPU and a non-zero per-CPU sequence.
// Timestamp is deliberately excluded: ktime is diagnostic, not identity.
type CaptureIdentity struct {
	Runtime  RuntimeIdentity
	CPU      uint32
	Sequence uint64
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

func validateCaptureIdentity(identity CaptureIdentity, generation uint64) error {
	if err := validateRuntimeIdentity(identity.Runtime); err != nil {
		return err
	}
	if identity.Runtime.Generation != generation {
		return fmt.Errorf(
			"faketcp capture identity generation %d does not match flow generation %d",
			identity.Runtime.Generation, generation,
		)
	}
	if identity.Sequence == 0 {
		return errors.New("faketcp capture identity sequence is zero")
	}
	return nil
}

func runtimeIdentityFromEvent(event abi.FakeTCPEvent) RuntimeIdentity {
	return RuntimeIdentity{
		Generation:  event.Key.Generation,
		Incarnation: RuntimeIncarnation(event.RuntimeIncarnation),
	}
}

func captureIdentityFromEvent(event abi.FakeTCPEvent) CaptureIdentity {
	return CaptureIdentity{
		Runtime: runtimeIdentityFromEvent(event),
		CPU:     event.CaptureCPU, Sequence: event.CaptureSequence,
	}
}
