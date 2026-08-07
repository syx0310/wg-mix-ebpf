package dataplane

import (
	"context"
	"errors"

	"github.com/syx0310/wg-mix-ebpf/internal/control"
	"github.com/syx0310/wg-mix-ebpf/internal/lockfile"
)

var ErrUnsupported = errors.New("dataplane is unsupported on this platform")
var ErrFakeTCPKernelGate = errors.New("experimental faketcp kernel gate is not satisfied")
var ErrPinOwnershipLifecycleLeaseRequired = errors.New(
	"pin ownership mutation requires the held global lifecycle lease",
)

const (
	DefaultObjectPath = "build/wg_mix_tc.o"
	EnvObjectPath     = "WG_MIX_EBPF_OBJECT"
	DefaultPinPath    = "/sys/fs/bpf/wg-mix-ebpf"
	EnvPinPath        = "WG_MIX_EBPF_PIN_PATH"
)

type Loader interface {
	Apply(ctx context.Context, state *control.State) error
	Detach(ctx context.Context, state *control.State) error
}

type AttachStateLoader interface {
	Loader
	DetachStale(ctx context.Context, previous *control.State, current *control.State) error
}

type LoaderOptions struct {
	AdoptLegacyPins bool
}

type PinOwnershipStatus struct {
	PinPath           string `json:"pin_path"`
	OwnerRoot         string `json:"owner_root"`
	RecordPath        string `json:"record_path,omitempty"`
	IndexPath         string `json:"index_path"`
	ResourceKey       string `json:"resource_key,omitempty"`
	DirectoryExists   bool   `json:"directory_exists"`
	OwnerExists       bool   `json:"owner_exists"`
	LegacyPins        bool   `json:"legacy_pins"`
	RecoveryRequired  bool   `json:"recovery_required"`
	DirectoryRemoved  bool   `json:"directory_removed"`
	Version           int    `json:"version,omitempty"`
	Sequence          uint64 `json:"sequence,omitempty"`
	BootID            string `json:"boot_id,omitempty"`
	Phase             string `json:"phase,omitempty"`
	Step              string `json:"step,omitempty"`
	ActiveGeneration  uint64 `json:"active_generation,omitempty"`
	NextGeneration    uint64 `json:"next_generation,omitempty"`
	MapCount          int    `json:"map_count,omitempty"`
	ActiveFilterCount int    `json:"active_filter_count,omitempty"`
}

// InspectPinOwnership validates owner metadata and steady-state kernel
// identities without repairing or mutating owner, index, pin, map, or TC
// state. It still acquires the per-resource lease, whose lock file records the
// inspection while excluding concurrent mutation.
func InspectPinOwnership(
	ctx context.Context,
	pinPath string,
) (*PinOwnershipStatus, error) {
	return inspectPinOwnership(ctx, pinPath, false)
}

// RecoverPinOwnership explicitly completes or rolls back a journaled owner
// transaction. The caller must pass the global lifecycle lease it already
// holds; this function verifies that lease before acquiring the FD-anchored
// resource lock.
func RecoverPinOwnership(
	ctx context.Context,
	pinPath string,
	lifecycleLease *lockfile.LifecycleLease,
) (*PinOwnershipStatus, error) {
	return recoverPinOwnership(ctx, pinPath, lifecycleLease)
}

// DetachPinOwnership removes only resources proven by the owner
// sentinel/record/map/filter identities. The caller must pass the global
// lifecycle lease it already holds; this function verifies that lease before
// acquiring the FD-anchored resource lock.
func DetachPinOwnership(
	ctx context.Context,
	pinPath string,
	lifecycleLease *lockfile.LifecycleLease,
) error {
	return detachPinOwnership(ctx, pinPath, lifecycleLease)
}
