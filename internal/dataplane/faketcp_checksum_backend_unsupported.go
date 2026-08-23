//go:build !linux

package dataplane

import (
	"context"
	"fmt"
)

func resolveFakeTCPChecksumBackend(
	context.Context,
	string,
) (*FakeTCPChecksumSelection, error) {
	return nil, ErrUnsupported
}

func probeFakeTCPChecksumBackends(context.Context) []FakeTCPChecksumBackendProbe {
	return []FakeTCPChecksumBackendProbe{
		{
			Backend:     configFakeTCPChecksumBackendKfunc,
			Unsupported: true,
			Error:       fmt.Sprintf("%v: Linux is required", ErrUnsupported),
		},
		{
			Backend:     configFakeTCPChecksumBackendKprobe,
			Unsupported: true,
			Error:       fmt.Sprintf("%v: Linux is required", ErrUnsupported),
		},
	}
}

const (
	configFakeTCPChecksumBackendKfunc  = "kfunc"
	configFakeTCPChecksumBackendKprobe = "kprobe"
)
