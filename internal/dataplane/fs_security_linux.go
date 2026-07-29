//go:build linux

package dataplane

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type anchoredDirectoryEntry struct {
	name     string
	fd       int
	identity pinPathInodeIdentity
	leaf     bool
	leafMode uint32
}

type anchoredDirectoryPath struct {
	path                 string
	entries              []anchoredDirectoryEntry
	expectedUID          uint32
	allowUnsafeAncestors bool
}

func openAnchoredDirectoryPath(
	path string,
	createLeaf bool,
	leafMode uint32,
	expectedUID uint32,
	allowUnsafeAncestors bool,
) (*anchoredDirectoryPath, bool, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path ||
		path == string(filepath.Separator) {
		return nil, false, fmt.Errorf(
			"directory path %q must be absolute, clean, and below the filesystem root",
			path,
		)
	}
	if createLeaf && leafMode == 0 {
		return nil, false, fmt.Errorf("creation mode for directory %s is unavailable", path)
	}
	rootFD, err := unix.Open(
		string(filepath.Separator),
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return nil, false, err
	}
	rootIdentity, err := inspectDirectoryFD(rootFD)
	if err != nil {
		_ = unix.Close(rootFD)
		return nil, false, err
	}
	anchored := &anchoredDirectoryPath{
		path:                 path,
		expectedUID:          expectedUID,
		allowUnsafeAncestors: allowUnsafeAncestors,
		entries: []anchoredDirectoryEntry{{
			name:     string(filepath.Separator),
			fd:       rootFD,
			identity: rootIdentity,
		}},
	}
	closeOnError := func(err error) (*anchoredDirectoryPath, bool, error) {
		_ = anchored.Close()
		return nil, false, err
	}
	if err := anchored.validateEntry(0); err != nil {
		return closeOnError(err)
	}

	components := strings.Split(
		strings.TrimPrefix(path, string(filepath.Separator)),
		string(filepath.Separator),
	)
	created := false
	for index, component := range components {
		isLeaf := index == len(components)-1
		parentFD := anchored.entries[len(anchored.entries)-1].fd
		nextFD, openErr := unix.Openat(
			parentFD,
			component,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
			0,
		)
		if errors.Is(openErr, unix.ENOENT) && isLeaf && createLeaf {
			if err := anchored.Recheck(); err != nil {
				return closeOnError(fmt.Errorf("recheck directory boundary before creating %s: %w", path, err))
			}
			if err := unix.Mkdirat(parentFD, component, leafMode); err != nil {
				if !errors.Is(err, unix.EEXIST) {
					return closeOnError(fmt.Errorf("create directory %s: %w", path, err))
				}
			} else {
				created = true
			}
			nextFD, openErr = unix.Openat(
				parentFD,
				component,
				unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
				0,
			)
		}
		if openErr != nil {
			return closeOnError(fmt.Errorf("open directory component %s: %w", component, openErr))
		}
		identity, err := inspectDirectoryFD(nextFD)
		if err != nil {
			_ = unix.Close(nextFD)
			return closeOnError(fmt.Errorf("inspect directory component %s: %w", component, err))
		}
		anchored.entries = append(anchored.entries, anchoredDirectoryEntry{
			name:     component,
			fd:       nextFD,
			identity: identity,
			leaf:     isLeaf,
			leafMode: leafMode,
		})
		if err := anchored.validateEntry(len(anchored.entries) - 1); err != nil {
			return closeOnError(err)
		}
		if err := anchored.recheckEntry(len(anchored.entries) - 1); err != nil {
			return closeOnError(err)
		}
	}
	return anchored, created, nil
}

func inspectDirectoryFD(fd int) (pinPathInodeIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return pinPathInodeIdentity{}, err
	}
	identity := pinPathInodeFromStat(&stat)
	if identity.mode&unix.S_IFMT != unix.S_IFDIR {
		return pinPathInodeIdentity{}, fmt.Errorf("mode %#o is not a directory", identity.mode)
	}
	return identity, nil
}

func (path *anchoredDirectoryPath) validateEntry(index int) error {
	entry := path.entries[index]
	identity := entry.identity
	if identity.mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("refuse unsafe directory %s: mode %#o is not a directory", path.path, identity.mode)
	}
	if identity.nlink == 0 {
		return fmt.Errorf("refuse unsafe directory %s: link count is zero", path.path)
	}
	if !entry.leaf && path.allowUnsafeAncestors {
		return nil
	}
	if identity.uid != path.expectedUID {
		return fmt.Errorf(
			"refuse unsafe directory %s: uid=%d, want %d",
			path.path, identity.uid, path.expectedUID,
		)
	}
	permissions := identity.mode & 0o7777
	if entry.leaf {
		if entry.leafMode != 0 && permissions != entry.leafMode {
			return fmt.Errorf(
				"refuse unsafe directory %s: mode=%#o, want %#o",
				path.path, permissions, entry.leafMode,
			)
		}
		if entry.leafMode != 0 {
			return nil
		}
		if permissions&0o022 != 0 || permissions&0o700 != 0o700 {
			return fmt.Errorf(
				"refuse unsafe directory %s: mode=%#o must be owner-rwx and not group/other writable",
				path.path, permissions,
			)
		}
		return nil
	}
	if permissions&0o022 != 0 {
		return fmt.Errorf(
			"refuse writable directory boundary for %s: component %s has mode %#o",
			path.path, entry.name, permissions,
		)
	}
	return nil
}

func (path *anchoredDirectoryPath) recheckEntry(index int) error {
	entry := path.entries[index]
	var heldStat unix.Stat_t
	if err := unix.Fstat(entry.fd, &heldStat); err != nil {
		return fmt.Errorf("recheck held directory %s: %w", path.path, err)
	}
	held := pinPathInodeFromStat(&heldStat)
	if !samePinPathInode(held, entry.identity) ||
		held.uid != entry.identity.uid ||
		held.mode&0o7777 != entry.identity.mode&0o7777 ||
		held.nlink == 0 {
		return fmt.Errorf("held directory identity or metadata changed for %s", path.path)
	}
	if index == 0 {
		return nil
	}
	parent := path.entries[index-1]
	var pathStat unix.Stat_t
	if err := unix.Fstatat(
		parent.fd,
		entry.name,
		&pathStat,
		unix.AT_SYMLINK_NOFOLLOW,
	); err != nil {
		return fmt.Errorf("recheck directory entry %s for %s: %w", entry.name, path.path, err)
	}
	observed := pinPathInodeFromStat(&pathStat)
	if !samePinPathInode(observed, entry.identity) ||
		observed.uid != entry.identity.uid ||
		observed.mode&0o7777 != entry.identity.mode&0o7777 ||
		observed.nlink == 0 {
		return fmt.Errorf("directory entry %s changed for %s", entry.name, path.path)
	}
	return nil
}

func (path *anchoredDirectoryPath) Recheck() error {
	if path == nil {
		return errors.New("anchored directory path is nil")
	}
	for index := range path.entries {
		if err := path.recheckEntry(index); err != nil {
			return err
		}
		if err := path.validateCurrentEntry(index); err != nil {
			return err
		}
	}
	return nil
}

func (path *anchoredDirectoryPath) validateCurrentEntry(index int) error {
	entry := path.entries[index]
	var stat unix.Stat_t
	if err := unix.Fstat(entry.fd, &stat); err != nil {
		return err
	}
	current := entry
	current.identity = pinPathInodeFromStat(&stat)
	original := path.entries[index]
	path.entries[index] = current
	err := path.validateEntry(index)
	path.entries[index] = original
	return err
}

func (path *anchoredDirectoryPath) FD() int {
	if path == nil || len(path.entries) == 0 {
		return -1
	}
	return path.entries[len(path.entries)-1].fd
}

func (path *anchoredDirectoryPath) Identity() pinPathInodeIdentity {
	if path == nil || len(path.entries) == 0 {
		return pinPathInodeIdentity{}
	}
	return path.entries[len(path.entries)-1].identity
}

func (path *anchoredDirectoryPath) Close() error {
	if path == nil {
		return nil
	}
	var errs []error
	for index := len(path.entries) - 1; index >= 0; index-- {
		if path.entries[index].fd < 0 {
			continue
		}
		if err := unix.Close(path.entries[index].fd); err != nil {
			errs = append(errs, fmt.Errorf("close directory boundary %s: %w", path.path, err))
		}
		path.entries[index].fd = -1
	}
	return errors.Join(errs...)
}

func openAnchoredRegularFile(
	root *anchoredDirectoryPath,
	name string,
	mode uint32,
	expectedUID uint32,
) (*os.File, pinPathInodeIdentity, bool, error) {
	if root == nil || root.FD() < 0 {
		return nil, pinPathInodeIdentity{}, false, errors.New("regular-file root is unavailable")
	}
	if name == "" || filepath.Base(name) != name || name == "." || name == ".." {
		return nil, pinPathInodeIdentity{}, false, fmt.Errorf("unsafe regular-file name %q", name)
	}
	if err := root.Recheck(); err != nil {
		return nil, pinPathInodeIdentity{}, false, err
	}
	var existing unix.Stat_t
	statErr := unix.Fstatat(root.FD(), name, &existing, unix.AT_SYMLINK_NOFOLLOW)
	created := false
	flags := unix.O_RDWR | unix.O_CLOEXEC | unix.O_NOFOLLOW
	var fd int
	var err error
	switch {
	case statErr == nil:
		fd, err = unix.Openat(root.FD(), name, flags, 0)
	case errors.Is(statErr, unix.ENOENT):
		fd, err = unix.Openat(root.FD(), name, flags|unix.O_CREAT|unix.O_EXCL, mode)
		if err == nil {
			created = true
		}
	default:
		return nil, pinPathInodeIdentity{}, false, statErr
	}
	if err != nil {
		return nil, pinPathInodeIdentity{}, false, err
	}
	file := os.NewFile(uintptr(fd), filepath.Join(root.path, name))
	identity, err := validateAnchoredRegularFile(root, name, fd, mode, expectedUID, nil)
	if err != nil {
		_ = file.Close()
		return nil, pinPathInodeIdentity{}, created, err
	}
	return file, identity, created, nil
}

func validateAnchoredRegularFile(
	root *anchoredDirectoryPath,
	name string,
	fd int,
	mode uint32,
	expectedUID uint32,
	expected *pinPathInodeIdentity,
) (pinPathInodeIdentity, error) {
	if err := root.Recheck(); err != nil {
		return pinPathInodeIdentity{}, err
	}
	var heldStat unix.Stat_t
	if err := unix.Fstat(fd, &heldStat); err != nil {
		return pinPathInodeIdentity{}, err
	}
	held := pinPathInodeFromStat(&heldStat)
	if held.mode&unix.S_IFMT != unix.S_IFREG ||
		held.mode&0o7777 != mode ||
		held.uid != expectedUID ||
		held.nlink != 1 {
		return pinPathInodeIdentity{}, fmt.Errorf(
			"refuse unsafe regular file %s/%s: mode=%#o uid=%d links=%d; want regular %#o uid=%d links=1",
			root.path, name, held.mode, held.uid, held.nlink, mode, expectedUID,
		)
	}
	if expected != nil && (!samePinPathInode(held, *expected) ||
		held.uid != expected.uid ||
		held.mode&0o7777 != expected.mode&0o7777 ||
		held.nlink != expected.nlink) {
		return pinPathInodeIdentity{}, fmt.Errorf("regular file %s/%s changed identity", root.path, name)
	}
	var pathStat unix.Stat_t
	if err := unix.Fstatat(root.FD(), name, &pathStat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return pinPathInodeIdentity{}, err
	}
	atPath := pinPathInodeFromStat(&pathStat)
	if !samePinPathInode(held, atPath) ||
		atPath.uid != held.uid ||
		atPath.mode&0o7777 != held.mode&0o7777 ||
		atPath.nlink != held.nlink {
		return pinPathInodeIdentity{}, fmt.Errorf("regular file %s/%s changed after open", root.path, name)
	}
	return held, nil
}
