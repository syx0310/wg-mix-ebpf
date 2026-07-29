//go:build linux

package install

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func cleanupCreateObjectBoundFileAt(
	parent *cleanupDirFD,
	mode uint32,
) (*os.File, error) {
	fd, err := unix.Openat(
		int(parent.file.Fd()),
		".",
		unix.O_RDWR|unix.O_TMPFILE|unix.O_CLOEXEC,
		mode,
	)
	if err != nil {
		return nil, errors.Join(errObjectBoundFreshFileUnsupported, err)
	}
	file := os.NewFile(uintptr(fd), "object-bound-install-stage")
	identity, err := cleanupIdentityForFD(fd)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !identity.sameMount(parent.identity) {
		_ = file.Close()
		return nil, fmt.Errorf(
			"refuse unnamed publication stage: object crosses the held parent mount",
		)
	}
	return file, nil
}

func cleanupPublishObjectBoundFileAt(
	parent *cleanupDirFD,
	file *os.File,
	name string,
) error {
	sourceFD := int(file.Fd())
	err := unix.Linkat(
		sourceFD,
		"",
		int(parent.file.Fd()),
		name,
		unix.AT_EMPTY_PATH,
	)
	if err == nil {
		return nil
	}
	if !errors.Is(err, unix.EPERM) &&
		!errors.Is(err, unix.ENOENT) &&
		!errors.Is(err, unix.EINVAL) &&
		!errors.Is(err, unix.EOPNOTSUPP) {
		return err
	}

	procPath := fmt.Sprintf("/proc/self/fd/%d", sourceFD)
	procFile, openErr := os.Open(procPath)
	if openErr != nil {
		return errors.Join(
			errObjectBoundFreshFileUnsupported,
			fmt.Errorf(
				"AT_EMPTY_PATH publication failed (%v) and descriptor-bound proc fallback "+
					"could not be opened: %w",
				err,
				openErr,
			),
		)
	}
	procIdentity, identityErr := cleanupIdentityForFD(int(procFile.Fd()))
	closeErr := procFile.Close()
	if identityErr != nil || closeErr != nil {
		return errors.Join(identityErr, closeErr)
	}
	heldIdentity, identityErr := cleanupIdentityForFD(sourceFD)
	if identityErr != nil {
		return identityErr
	}
	if !heldIdentity.sameRegularFile(procIdentity) {
		return errors.New(
			"refuse /proc/self/fd publication fallback: proc path is not bound to held object",
		)
	}
	if err := unix.Linkat(
		unix.AT_FDCWD,
		procPath,
		int(parent.file.Fd()),
		name,
		unix.AT_SYMLINK_FOLLOW,
	); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return err
		}
		return errors.Join(
			errObjectBoundFreshFileUnsupported,
			fmt.Errorf("descriptor-bound /proc/self/fd publication fallback: %w", err),
		)
	}
	return nil
}
