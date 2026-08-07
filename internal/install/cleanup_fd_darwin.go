//go:build darwin

package install

import (
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
	fd, err := unix.Openat(
		int(parent.file.Fd()),
		name,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
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
	fd, err := unix.Openat(
		int(parent.file.Fd()),
		name,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
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
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return cleanupIdentity{}, err
	}
	var statfs unix.Statfs_t
	if err := unix.Fstatfs(fd, &statfs); err != nil {
		return cleanupIdentity{}, err
	}
	mountID := uint64(uint32(statfs.Fsid.Val[0]))<<32 | uint64(uint32(statfs.Fsid.Val[1]))
	return cleanupIdentity{
		Device:     uint64(uint32(stat.Dev)),
		Inode:      stat.Ino,
		MountID:    mountID,
		MountKnown: true,
		Mode:       uint32(stat.Mode),
		Links:      uint64(stat.Nlink),
		UID:        stat.Uid,
		GID:        stat.Gid,
		Size:       uint64(stat.Size),
		ChangeSec:  stat.Ctim.Sec,
		ChangeNsec: stat.Ctim.Nsec,
		ModifySec:  stat.Mtim.Sec,
		ModifyNsec: stat.Mtim.Nsec,
	}, nil
}

func cleanupIdentityAt(parent *cleanupDirFD, name string) (cleanupIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Fstatat(int(parent.file.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return cleanupIdentity{}, err
	}
	file, identity, err := cleanupOpenFileAt(parent, name)
	if err != nil {
		return cleanupIdentity{}, err
	}
	_ = file.Close()
	if identity.Device != uint64(uint32(stat.Dev)) || identity.Inode != stat.Ino {
		return cleanupIdentity{}, fmt.Errorf("managed entry %s/%s changed while inspecting", parent.path, name)
	}
	return identity, nil
}

func cleanupSymlinkIdentityAt(parent *cleanupDirFD, name string) (cleanupIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Fstatat(int(parent.file.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return cleanupIdentity{}, err
	}
	device := uint64(uint32(stat.Dev))
	if device != parent.identity.Device {
		return cleanupIdentity{}, fmt.Errorf(
			"refuse managed symlink %s/%s: path crosses a mount boundary",
			parent.path,
			name,
		)
	}
	return cleanupIdentity{
		Device:     device,
		Inode:      stat.Ino,
		MountID:    parent.identity.MountID,
		MountKnown: parent.identity.MountKnown,
		Mode:       uint32(stat.Mode),
		Links:      uint64(stat.Nlink),
		UID:        stat.Uid,
		GID:        stat.Gid,
		Size:       uint64(stat.Size),
		ChangeSec:  stat.Ctim.Sec,
		ChangeNsec: stat.Ctim.Nsec,
		ModifySec:  stat.Mtim.Sec,
		ModifyNsec: stat.Mtim.Nsec,
	}, nil
}

func cleanupOpenFileAt(parent *cleanupDirFD, name string) (*os.File, cleanupIdentity, error) {
	fd, err := unix.Openat(
		int(parent.file.Fd()),
		name,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
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
	fd, err := unix.Openat(
		int(parent.file.Fd()),
		".",
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
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
		return "", fmt.Errorf("managed symlink target exceeds the size limit")
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
	return unix.RenameatxNp(
		int(parent.file.Fd()),
		oldName,
		int(parent.file.Fd()),
		newName,
		unix.RENAME_EXCL,
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
