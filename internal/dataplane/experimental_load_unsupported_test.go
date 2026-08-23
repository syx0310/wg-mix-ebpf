//go:build !linux

package dataplane

import (
	"errors"
	"testing"
)

func TestExperimentalVerifierLoadFailsClosedOnUnsupportedPlatforms(t *testing.T) {
	identity, err := LoadExperimentalFakeTCPObjectTestIdentity(
		t.Context(),
		"/explicit/experimental.o",
	)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("error = %v, want ErrUnsupported", err)
	}
	if identity != (ObjectIdentity{}) {
		t.Fatalf("unsupported loader returned identity %#v", identity)
	}
}

func TestLegacy515VerifierLoadFailsClosedOnUnsupportedPlatforms(t *testing.T) {
	identity, err := LoadLegacy515FakeTCPObjectTestIdentity(
		t.Context(),
		"/explicit/legacy-515.o",
	)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("error = %v, want ErrUnsupported", err)
	}
	if identity != (ObjectIdentity{}) {
		t.Fatalf("unsupported loader returned identity %#v", identity)
	}
}
