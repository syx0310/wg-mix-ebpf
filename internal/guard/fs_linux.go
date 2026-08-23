//go:build linux

package guard

import (
	"os"

	"golang.org/x/sys/unix"
)

func guardOpenDirectoryPath(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func guardOpenDirectoryAt(parent *os.File, name string) (*os.File, error) {
	how := &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
	}
	fd, err := unix.Openat2(int(parent.Fd()), name, how)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func guardMkdirDirectoryAt(parent *os.File, name string, mode uint32) error {
	return unix.Mkdirat(int(parent.Fd()), name, mode)
}

func guardOpenReadFileAt(parent *os.File, name string) (*os.File, error) {
	how := &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
	}
	fd, err := unix.Openat2(int(parent.Fd()), name, how)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func guardOpenReadWriteFileAt(parent *os.File, name string) (*os.File, error) {
	how := &unix.OpenHow{
		Flags:   unix.O_RDWR | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
	}
	fd, err := unix.Openat2(int(parent.Fd()), name, how)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func guardCreateFileAt(parent *os.File, name string, mode uint32) (*os.File, error) {
	fd, err := unix.Openat(
		int(parent.Fd()),
		name,
		unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK,
		mode,
	)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func guardRenameNoReplaceAt(parent *os.File, oldName string, newName string) error {
	return unix.Renameat2(
		int(parent.Fd()),
		oldName,
		int(parent.Fd()),
		newName,
		unix.RENAME_NOREPLACE,
	)
}

func guardTryLockExclusive(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
}
