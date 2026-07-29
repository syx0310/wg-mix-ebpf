//go:build !linux

package dataplane

import (
	"context"

	"github.com/syx0310/wg-mix-ebpf/internal/lockfile"
)

func inspectPinOwnership(
	context.Context,
	string,
	bool,
) (*PinOwnershipStatus, error) {
	return nil, ErrUnsupported
}

func recoverPinOwnership(
	context.Context,
	string,
	*lockfile.LifecycleLease,
) (*PinOwnershipStatus, error) {
	return nil, ErrUnsupported
}

func detachPinOwnership(
	context.Context,
	string,
	*lockfile.LifecycleLease,
) error {
	return ErrUnsupported
}
