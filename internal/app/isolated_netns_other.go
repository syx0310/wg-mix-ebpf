//go:build !linux

package app

import (
	"context"
	"errors"
)

func isolatedNetNSTestContext(
	context.Context,
	string,
	string,
	string,
	string,
	string,
) (context.Context, error) {
	return nil, errors.New("--isolated-netns-test is only supported on Linux")
}
