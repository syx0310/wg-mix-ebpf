//go:build !linux

package dataplane

import (
	"context"

	"github.com/syx0310/wg-mix-ebpf/internal/control"
)

func ProductionFakeTCPHealthy(_ context.Context, state *control.State) (handled bool, healthy bool) {
	if len(fakeTCPStateReferences(state)) == 0 {
		return false, false
	}
	return true, false
}

func ProductionFakeTCPStatus(
	_ context.Context,
	state *control.State,
) (handled bool, status *KernelStatus, err error) {
	if len(fakeTCPStateReferences(state)) == 0 {
		return false, nil, nil
	}
	return true, &KernelStatus{Mode: "faketcp"}, ErrUnsupported
}

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

func LoadLegacy515FakeTCPObjectTestIdentity(context.Context, string) (ObjectIdentity, error) {
	return ObjectIdentity{}, ErrUnsupported
}

func ProbeFakeTCPKernelDependency() error {
	return ErrUnsupported
}
