//go:build !linux

package dataplane

import (
	"context"

	"github.com/syx0310/wg-mix-ebpf/internal/control"
)

type UnsupportedLoader struct{}

func NewLoader() Loader {
	return NewLoaderWithOptions(LoaderOptions{})
}

func NewLoaderWithOptions(LoaderOptions) Loader {
	return UnsupportedLoader{}
}

func (UnsupportedLoader) Apply(context.Context, *control.State) error {
	return ErrUnsupported
}

func (UnsupportedLoader) Detach(context.Context, *control.State) error {
	return ErrUnsupported
}

func (UnsupportedLoader) DetachStale(context.Context, *control.State, *control.State) error {
	return ErrUnsupported
}

func LoadObjectTest(context.Context, string) error {
	return ErrUnsupported
}

func LoadObjectTestIdentity(context.Context, string) (ObjectIdentity, error) {
	return ObjectIdentity{}, ErrUnsupported
}

func LoadExperimentalFakeTCPObjectTestIdentity(context.Context, string) (ObjectIdentity, error) {
	return ObjectIdentity{}, ErrUnsupported
}
