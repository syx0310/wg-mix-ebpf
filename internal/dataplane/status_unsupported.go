//go:build !linux

package dataplane

import (
	"context"

	"github.com/siyixuan/wg-mix-ebpf/internal/control"
)

func inspect(context.Context, *control.State) (*KernelStatus, error) {
	return nil, ErrUnsupported
}
