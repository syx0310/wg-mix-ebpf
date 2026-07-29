//go:build linux

package lockfile

import (
	"errors"

	"golang.org/x/sys/unix"
)

const lifecycleStatxMask = unix.STATX_BASIC_STATS | unix.STATX_MNT_ID

func lifecycleLockIdentityForFD(fd int) (lifecycleLockIdentity, error) {
	var stat unix.Statx_t
	if err := unix.Statx(
		fd,
		"",
		unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW,
		lifecycleStatxMask,
		&stat,
	); err != nil {
		return lifecycleLockIdentity{}, err
	}
	return lifecycleLockIdentityFromStatx(stat)
}

func lifecycleLockIdentityAt(parentFD int, name string) (lifecycleLockIdentity, error) {
	var stat unix.Statx_t
	if err := unix.Statx(
		parentFD,
		name,
		unix.AT_SYMLINK_NOFOLLOW,
		lifecycleStatxMask,
		&stat,
	); err != nil {
		return lifecycleLockIdentity{}, err
	}
	return lifecycleLockIdentityFromStatx(stat)
}

func lifecycleLockIdentityFromStatx(stat unix.Statx_t) (lifecycleLockIdentity, error) {
	if stat.Mask&unix.STATX_MNT_ID == 0 {
		return lifecycleLockIdentity{}, errors.New("statx did not return a mount identity")
	}
	return lifecycleLockIdentity{
		device:  uint64(stat.Dev_major)<<32 | uint64(stat.Dev_minor),
		inode:   stat.Ino,
		mountID: stat.Mnt_id,
		mode:    uint32(stat.Mode),
		uid:     stat.Uid,
		gid:     stat.Gid,
		links:   uint64(stat.Nlink),
	}, nil
}
