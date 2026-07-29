package lockfile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type lifecycleLockIdentity struct {
	device  uint64
	inode   uint64
	mountID uint64
	mode    uint32
	uid     uint32
	gid     uint32
	links   uint64
}

func (identity lifecycleLockIdentity) sameObject(other lifecycleLockIdentity) bool {
	return identity.device == other.device &&
		identity.inode == other.inode &&
		identity.mountID == other.mountID &&
		identity.mode&unix.S_IFMT == other.mode&unix.S_IFMT
}

func (identity lifecycleLockIdentity) sameSecuredFile(other lifecycleLockIdentity) bool {
	return identity.sameObject(other) &&
		identity.uid == other.uid &&
		identity.gid == other.gid &&
		identity.mode&0o7777 == other.mode&0o7777 &&
		identity.links == other.links
}

func (identity lifecycleLockIdentity) sameSecuredDirectory(other lifecycleLockIdentity) bool {
	return identity.sameObject(other) &&
		identity.uid == other.uid &&
		identity.gid == other.gid &&
		identity.mode&0o7777 == other.mode&0o7777
}

func (identity lifecycleLockIdentity) validateFile(path string) error {
	if identity.mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("lock path %s is not a regular file", path)
	}
	if identity.uid != uint32(os.Geteuid()) {
		return fmt.Errorf(
			"lock path %s owner uid is %d, want %d",
			path,
			identity.uid,
			os.Geteuid(),
		)
	}
	if identity.mode&0o7777 != 0o600 {
		return fmt.Errorf(
			"lock path %s mode is %#o, want 0600",
			path,
			identity.mode&0o7777,
		)
	}
	if identity.links != 1 {
		return fmt.Errorf("refuse lock file %s with %d links", path, identity.links)
	}
	return nil
}

func (identity lifecycleLockIdentity) validateDirectory(path string) error {
	if identity.mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("lock parent %s is not a directory", path)
	}
	if identity.uid != uint32(os.Geteuid()) {
		return fmt.Errorf(
			"lock parent %s owner uid is %d, want %d",
			path,
			identity.uid,
			os.Geteuid(),
		)
	}
	if identity.mode&0o022 != 0 {
		return fmt.Errorf(
			"lock parent %s has group/other writable mode %#o",
			path,
			identity.mode&0o7777,
		)
	}
	return nil
}

type anchoredLifecycleLock struct {
	path           string
	parentPath     string
	name           string
	parent         *os.File
	file           *os.File
	parentIdentity lifecycleLockIdentity
	fileIdentity   lifecycleLockIdentity
}

func openAnchoredLifecycleLock(path string) (*anchoredLifecycleLock, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("lock path must be a clean absolute path: %q", path)
	}
	parentPath := filepath.Dir(path)
	name := filepath.Base(path)
	if name == "." || name == string(os.PathSeparator) {
		return nil, fmt.Errorf("lock path has invalid basename: %q", path)
	}
	if err := os.MkdirAll(parentPath, 0o755); err != nil {
		return nil, fmt.Errorf("create lock parent %s: %w", parentPath, err)
	}
	parentFD, err := unix.Open(
		parentPath,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("open lock parent %s: %w", parentPath, err)
	}
	parent := os.NewFile(uintptr(parentFD), parentPath)
	parentIdentity, err := lifecycleLockIdentityForFD(parentFD)
	if err != nil {
		_ = parent.Close()
		return nil, fmt.Errorf("inspect lock parent %s: %w", parentPath, err)
	}
	if err := parentIdentity.validateDirectory(parentPath); err != nil {
		_ = parent.Close()
		return nil, err
	}

	flags := unix.O_RDWR | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
	fileFD, err := unix.Openat(parentFD, name, flags|unix.O_CREAT|unix.O_EXCL, 0o600)
	created := err == nil
	if errors.Is(err, unix.EEXIST) {
		fileFD, err = unix.Openat(parentFD, name, flags, 0)
	}
	if err != nil {
		_ = parent.Close()
		if errors.Is(err, unix.ELOOP) {
			return nil, fmt.Errorf("refuse symbolic-link lock file %s: %w", path, err)
		}
		return nil, fmt.Errorf("open lock file %s: %w", path, err)
	}
	file := os.NewFile(uintptr(fileFD), path)
	if created {
		if err := file.Chmod(0o600); err != nil {
			_ = file.Close()
			_ = parent.Close()
			return nil, fmt.Errorf("secure new lock file %s: %w", path, err)
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			_ = parent.Close()
			return nil, fmt.Errorf("sync new lock file %s: %w", path, err)
		}
		if err := parent.Sync(); err != nil {
			_ = file.Close()
			_ = parent.Close()
			return nil, fmt.Errorf("sync lock parent %s: %w", parentPath, err)
		}
	}
	fileIdentity, err := lifecycleLockIdentityForFD(fileFD)
	if err != nil {
		_ = file.Close()
		_ = parent.Close()
		return nil, fmt.Errorf("inspect lock file %s: %w", path, err)
	}
	if err := fileIdentity.validateFile(path); err != nil {
		_ = file.Close()
		_ = parent.Close()
		return nil, err
	}
	namedIdentity, err := lifecycleLockIdentityAt(parentFD, name)
	if err != nil {
		_ = file.Close()
		_ = parent.Close()
		return nil, fmt.Errorf("inspect named lock file %s: %w", path, err)
	}
	if !fileIdentity.sameSecuredFile(namedIdentity) {
		_ = file.Close()
		_ = parent.Close()
		return nil, fmt.Errorf("lock pathname %s does not name the opened file", path)
	}
	lock := &anchoredLifecycleLock{
		path:           path,
		parentPath:     parentPath,
		name:           name,
		parent:         parent,
		file:           file,
		parentIdentity: parentIdentity,
		fileIdentity:   fileIdentity,
	}
	if err := lock.validate(); err != nil {
		_ = lock.close()
		return nil, err
	}
	return lock, nil
}

func (lock *anchoredLifecycleLock) validate() error {
	if lock == nil || lock.parent == nil || lock.file == nil {
		return errors.New("anchored lifecycle lock is closed")
	}
	parentIdentity, err := lifecycleLockIdentityForFD(int(lock.parent.Fd()))
	if err != nil {
		return fmt.Errorf("inspect held lock parent %s: %w", lock.parentPath, err)
	}
	if err := parentIdentity.validateDirectory(lock.parentPath); err != nil {
		return err
	}
	if !lock.parentIdentity.sameSecuredDirectory(parentIdentity) {
		return fmt.Errorf("lock parent identity changed for %s", lock.parentPath)
	}
	namedParentFD, err := unix.Open(
		lock.parentPath,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return fmt.Errorf("reopen lock parent %s: %w", lock.parentPath, err)
	}
	namedParent := os.NewFile(uintptr(namedParentFD), lock.parentPath)
	namedParentIdentity, identityErr := lifecycleLockIdentityForFD(namedParentFD)
	closeErr := namedParent.Close()
	if identityErr != nil {
		return fmt.Errorf("inspect reopened lock parent %s: %w", lock.parentPath, identityErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close reopened lock parent %s: %w", lock.parentPath, closeErr)
	}
	if !parentIdentity.sameSecuredDirectory(namedParentIdentity) {
		return fmt.Errorf("lock parent pathname identity changed for %s", lock.parentPath)
	}

	fileIdentity, err := lifecycleLockIdentityForFD(int(lock.file.Fd()))
	if err != nil {
		return fmt.Errorf("inspect held lock file %s: %w", lock.path, err)
	}
	if err := fileIdentity.validateFile(lock.path); err != nil {
		return err
	}
	if !lock.fileIdentity.sameSecuredFile(fileIdentity) {
		return fmt.Errorf("held lock file identity changed for %s", lock.path)
	}
	namedIdentity, err := lifecycleLockIdentityAt(int(lock.parent.Fd()), lock.name)
	if err != nil {
		return fmt.Errorf("revalidate lock pathname %s: %w", lock.path, err)
	}
	if !fileIdentity.sameSecuredFile(namedIdentity) {
		return fmt.Errorf("lock pathname identity changed for %s", lock.path)
	}
	return nil
}

func (lock *anchoredLifecycleLock) duplicate() (*anchoredLifecycleLock, error) {
	if err := lock.validate(); err != nil {
		return nil, err
	}
	parentFD, err := unix.FcntlInt(lock.parent.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("duplicate lock parent %s: %w", lock.parentPath, err)
	}
	fileFD, err := unix.FcntlInt(lock.file.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		_ = unix.Close(parentFD)
		return nil, fmt.Errorf("duplicate lock file %s: %w", lock.path, err)
	}
	duplicate := &anchoredLifecycleLock{
		path:           lock.path,
		parentPath:     lock.parentPath,
		name:           lock.name,
		parent:         os.NewFile(uintptr(parentFD), lock.parentPath),
		file:           os.NewFile(uintptr(fileFD), lock.path),
		parentIdentity: lock.parentIdentity,
		fileIdentity:   lock.fileIdentity,
	}
	if err := duplicate.validate(); err != nil {
		_ = duplicate.close()
		return nil, err
	}
	return duplicate, nil
}

func (lock *anchoredLifecycleLock) close() error {
	if lock == nil {
		return nil
	}
	var errs []error
	if lock.file != nil {
		errs = append(errs, lock.file.Close())
		lock.file = nil
	}
	if lock.parent != nil {
		errs = append(errs, lock.parent.Close())
		lock.parent = nil
	}
	return errors.Join(errs...)
}
