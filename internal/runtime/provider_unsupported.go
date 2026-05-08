//go:build !linux

package runtime

import "context"

type SystemProvider struct{}

func NewSystemProvider() Provider {
	return SystemProvider{}
}

func (SystemProvider) Device(context.Context, string) (*Device, error) {
	return nil, ErrUnsupported
}
