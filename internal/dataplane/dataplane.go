package dataplane

import (
	"context"
	"errors"

	"github.com/syx0310/wg-mix-ebpf/internal/control"
)

var ErrUnsupported = errors.New("dataplane is unsupported on this platform")

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
