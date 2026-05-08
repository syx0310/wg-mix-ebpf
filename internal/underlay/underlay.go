package underlay

import (
	"context"
	"errors"
	"fmt"

	"github.com/syx0310/wg-mix-ebpf/internal/config"
)

var ErrUnsupported = errors.New("underlay resolver is unsupported on this platform")

type Resolved struct {
	ID       uint32
	Name     string
	Type     string
	IfName   string
	IfIndex  int
	LinkType string
	Role     string
}

type Resolver interface {
	Resolve(ctx context.Context, underlay config.Underlay) (*Resolved, error)
}

type StaticResolver struct {
	Underlays map[string]*Resolved
}

func (r StaticResolver) Resolve(_ context.Context, underlay config.Underlay) (*Resolved, error) {
	if r.Underlays == nil {
		return nil, ErrUnsupported
	}
	resolved, ok := r.Underlays[underlay.Name]
	if !ok {
		return nil, fmt.Errorf("underlay %q not found", underlay.Name)
	}
	copied := *resolved
	if copied.Name == "" {
		copied.Name = underlay.Name
	}
	if copied.Type == "" {
		copied.Type = underlay.Type
	}
	return &copied, nil
}
