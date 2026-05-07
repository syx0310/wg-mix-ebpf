package dataplane

import (
	"context"
	"errors"

	"github.com/siyixuan/wg-mix-ebpf/internal/control"
)

var ErrUnsupported = errors.New("dataplane is unsupported on this platform")

const (
	DefaultObjectPath = "build/wg_mix_tc.o"
	EnvObjectPath     = "WG_MIX_EBPF_OBJECT"
)

type Loader interface {
	Apply(ctx context.Context, state *control.State) error
	Detach(ctx context.Context, state *control.State) error
}
