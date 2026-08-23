//go:build !linux && !darwin

package install

import "os"

func cleanupCreateObjectBoundFileAt(
	*cleanupDirFD,
	uint32,
) (*os.File, error) {
	return nil, errObjectBoundFreshFileUnsupported
}

func cleanupPublishObjectBoundFileAt(
	*cleanupDirFD,
	*os.File,
	string,
) error {
	return errObjectBoundFreshFileUnsupported
}
