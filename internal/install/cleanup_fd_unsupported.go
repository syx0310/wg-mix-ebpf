//go:build !linux && !darwin

package install

import (
	"errors"
	"os"
)

var errSecureCleanupUnsupported = errors.New("secure descriptor-anchored cleanup is unsupported on this platform")

func cleanupOpenAnchor(string) (*cleanupDirFD, error) {
	return nil, errSecureCleanupUnsupported
}

func cleanupOpenDirAt(*cleanupDirFD, string) (*cleanupDirFD, error) {
	return nil, errSecureCleanupUnsupported
}

func cleanupIdentityForFD(int) (cleanupIdentity, error) {
	return cleanupIdentity{}, errSecureCleanupUnsupported
}

func cleanupIdentityAt(*cleanupDirFD, string) (cleanupIdentity, error) {
	return cleanupIdentity{}, errSecureCleanupUnsupported
}

func cleanupSymlinkIdentityAt(*cleanupDirFD, string) (cleanupIdentity, error) {
	return cleanupIdentity{}, errSecureCleanupUnsupported
}

func cleanupOpenFileAt(*cleanupDirFD, string) (*os.File, cleanupIdentity, error) {
	return nil, cleanupIdentity{}, errSecureCleanupUnsupported
}

func cleanupReadDir(*cleanupDirFD) ([]os.DirEntry, error) {
	return nil, errSecureCleanupUnsupported
}

func cleanupUnlinkAt(*cleanupDirFD, string, bool) error {
	return errSecureCleanupUnsupported
}

func cleanupReadlinkAt(*cleanupDirFD, string) (string, error) {
	return "", errSecureCleanupUnsupported
}

func cleanupSymlinkAt(*cleanupDirFD, string, string) error {
	return errSecureCleanupUnsupported
}

func cleanupCreateFileAt(*cleanupDirFD, string, uint32) (*os.File, error) {
	return nil, errSecureCleanupUnsupported
}

func cleanupMkdirAt(*cleanupDirFD, string, uint32) error {
	return errSecureCleanupUnsupported
}

func cleanupRenameNoReplaceAt(*cleanupDirFD, string, string) error {
	return errSecureCleanupUnsupported
}

func cleanupRenameReplaceAt(*cleanupDirFD, string, string) error {
	return errSecureCleanupUnsupported
}
