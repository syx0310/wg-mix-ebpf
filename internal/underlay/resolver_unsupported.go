//go:build !linux

package underlay

import (
	"context"

	"github.com/syx0310/wg-mix-ebpf/internal/config"
)

type SystemResolver struct{}

func NewSystemResolver() Resolver {
	return SystemResolver{}
}

func (SystemResolver) Resolve(context.Context, config.Underlay) (*Resolved, error) {
	return nil, ErrUnsupported
}
