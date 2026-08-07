//go:build linux

package install

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func cleanupOpenAnchor(path string) (*cleanupDirFD, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	identity, err := cleanupIdentityForFD(fd)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	return &cleanupDirFD{file: file, identity: identity, path: path}, nil
}

func cleanupOpenDirAt(parent *cleanupDirFD, name string) (*cleanupDirFD, error) {
	how := &unix.OpenHow{
		Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS |
			unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV,
	}
	fd, err := unix.Openat2(int(parent.file.Fd()), name, how)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	identity, err := cleanupIdentityForFD(fd)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !identity.sameMount(parent.identity) {
		_ = file.Close()
		return nil, fmt.Errorf("refuse cleanup directory %s/%s: path crosses a mount boundary", parent.path, name)
	}
	return &cleanupDirFD{file: file, identity: identity, path: parent.path + "/" + name}, nil
}

func cleanupOpenDirAtAllowMount(parent *cleanupDirFD, name string) (*cleanupDirFD, error) {
	how := &unix.OpenHow{
		Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS |
			unix.RESOLVE_NO_SYMLINKS,
	}
	fd, err := unix.Openat2(int(parent.file.Fd()), name, how)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	identity, err := cleanupIdentityForFD(fd)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	return &cleanupDirFD{file: file, identity: identity, path: parent.path + "/" + name}, nil
}

func cleanupIdentityForFD(fd int) (cleanupIdentity, error) {
	var stat unix.Statx_t
	if err := cleanupStatx(
		fd,
		"",
		unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW,
		&stat,
	); err != nil {
		return cleanupIdentity{}, err
	}
	mountKnown := stat.Mask&(unix.STATX_MNT_ID|unix.STATX_MNT_ID_UNIQUE) != 0
	if !mountKnown {
		return cleanupIdentity{}, errors.New("statx did not return a mount identity")
	}
	device := uint64(stat.Dev_major)<<32 | uint64(stat.Dev_minor)
	return cleanupIdentity{
		Device:     device,
		Inode:      stat.Ino,
		MountID:    stat.Mnt_id,
		MountKnown: true,
		Mode:       uint32(stat.Mode),
		Links:      uint64(stat.Nlink),
		UID:        stat.Uid,
		GID:        stat.Gid,
		Size:       stat.Size,
		ChangeSec:  stat.Ctime.Sec,
		ChangeNsec: int64(stat.Ctime.Nsec),
		ModifySec:  stat.Mtime.Sec,
		ModifyNsec: int64(stat.Mtime.Nsec),
	}, nil
}

func cleanupIdentityAt(parent *cleanupDirFD, name string) (cleanupIdentity, error) {
	var stat unix.Statx_t
	err := cleanupStatx(
		int(parent.file.Fd()),
		name,
		unix.AT_SYMLINK_NOFOLLOW,
		&stat,
	)
	if err != nil {
		return cleanupIdentity{}, err
	}
	if stat.Mask&(unix.STATX_MNT_ID|unix.STATX_MNT_ID_UNIQUE) == 0 {
		return cleanupIdentity{}, errors.New("statx did not return a mount identity")
	}
	device := uint64(stat.Dev_major)<<32 | uint64(stat.Dev_minor)
	return cleanupIdentity{
		Device:     device,
		Inode:      stat.Ino,
		MountID:    stat.Mnt_id,
		MountKnown: true,
		Mode:       uint32(stat.Mode),
		Links:      uint64(stat.Nlink),
		UID:        stat.Uid,
		GID:        stat.Gid,
		Size:       stat.Size,
		ChangeSec:  stat.Ctime.Sec,
		ChangeNsec: int64(stat.Ctime.Nsec),
		ModifySec:  stat.Mtime.Sec,
		ModifyNsec: int64(stat.Mtime.Nsec),
	}, nil
}

func cleanupSymlinkIdentityAt(parent *cleanupDirFD, name string) (cleanupIdentity, error) {
	return cleanupIdentityAt(parent, name)
}

func cleanupStatx(dirFD int, path string, flags int, stat *unix.Statx_t) error {
	mask := unix.STATX_BASIC_STATS | unix.STATX_MNT_ID | unix.STATX_MNT_ID_UNIQUE
	err := unix.Statx(dirFD, path, flags, mask, stat)
	if !errors.Is(err, unix.EINVAL) {
		return err
	}
	*stat = unix.Statx_t{}
	return unix.Statx(
		dirFD,
		path,
		flags,
		unix.STATX_BASIC_STATS|unix.STATX_MNT_ID,
		stat,
	)
}

func cleanupOpenFileAt(parent *cleanupDirFD, name string) (*os.File, cleanupIdentity, error) {
	how := &unix.OpenHow{
		Flags: unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS |
			unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV,
	}
	fd, err := unix.Openat2(int(parent.file.Fd()), name, how)
	if err != nil {
		return nil, cleanupIdentity{}, err
	}
	file := os.NewFile(uintptr(fd), name)
	identity, err := cleanupIdentityForFD(fd)
	if err != nil {
		_ = file.Close()
		return nil, cleanupIdentity{}, err
	}
	if !identity.sameMount(parent.identity) {
		_ = file.Close()
		return nil, cleanupIdentity{}, fmt.Errorf("refuse managed file %s/%s: path crosses a mount boundary", parent.path, name)
	}
	return file, identity, nil
}

func cleanupReadDir(parent *cleanupDirFD) ([]os.DirEntry, error) {
	how := &unix.OpenHow{
		Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS |
			unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV,
	}
	fd, err := unix.Openat2(int(parent.file.Fd()), ".", how)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), parent.path)
	defer file.Close()
	return file.ReadDir(-1)
}

func cleanupUnlinkAt(parent *cleanupDirFD, name string, directory bool) error {
	flags := 0
	if directory {
		flags = unix.AT_REMOVEDIR
	}
	return unix.Unlinkat(int(parent.file.Fd()), name, flags)
}

func cleanupReadlinkAt(parent *cleanupDirFD, name string) (string, error) {
	buffer := make([]byte, 4096)
	n, err := unix.Readlinkat(int(parent.file.Fd()), name, buffer)
	if err != nil {
		return "", err
	}
	if n == len(buffer) {
		return "", errors.New("managed symlink target exceeds the size limit")
	}
	return string(buffer[:n]), nil
}

func cleanupSymlinkAt(parent *cleanupDirFD, target string, name string) error {
	return unix.Symlinkat(target, int(parent.file.Fd()), name)
}

func cleanupCreateFileAt(parent *cleanupDirFD, name string, mode uint32) (*os.File, error) {
	fd, err := unix.Openat(
		int(parent.file.Fd()),
		name,
		unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		mode,
	)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func cleanupMkdirAt(parent *cleanupDirFD, name string, mode uint32) error {
	return unix.Mkdirat(int(parent.file.Fd()), name, mode)
}

func cleanupRenameNoReplaceAt(parent *cleanupDirFD, oldName string, newName string) error {
	return unix.Renameat2(
		int(parent.file.Fd()),
		oldName,
		int(parent.file.Fd()),
		newName,
		unix.RENAME_NOREPLACE,
	)
}

func cleanupRenameReplaceAt(parent *cleanupDirFD, oldName string, newName string) error {
	return unix.Renameat(
		int(parent.file.Fd()),
		oldName,
		int(parent.file.Fd()),
		newName,
	)
}
