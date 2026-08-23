//go:build darwin

package lockfile

import "golang.org/x/sys/unix"

func lifecycleLockIdentityForFD(fd int) (lifecycleLockIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return lifecycleLockIdentity{}, err
	}
	return lifecycleLockIdentityFromStat(stat), nil
}

func lifecycleLockIdentityAt(parentFD int, name string) (lifecycleLockIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return lifecycleLockIdentity{}, err
	}
	return lifecycleLockIdentityFromStat(stat), nil
}

func lifecycleLockIdentityFromStat(stat unix.Stat_t) lifecycleLockIdentity {
	return lifecycleLockIdentity{
		device:  uint64(stat.Dev),
		inode:   uint64(stat.Ino),
		mountID: uint64(stat.Dev),
		mode:    uint32(stat.Mode),
		uid:     stat.Uid,
		gid:     stat.Gid,
		links:   uint64(stat.Nlink),
	}
}
