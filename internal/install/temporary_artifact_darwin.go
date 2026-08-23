//go:build darwin

package install

import (
	"errors"
	"os"
)

func cleanupCreateObjectBoundFileAt(
	*cleanupDirFD,
	uint32,
) (*os.File, error) {
	return nil, errors.Join(
		errObjectBoundFreshFileUnsupported,
		errors.New("Darwin has no supported held-FD anonymous publication primitive"),
	)
}

func cleanupPublishObjectBoundFileAt(
	*cleanupDirFD,
	*os.File,
	string,
) error {
	return errObjectBoundFreshFileUnsupported
}
