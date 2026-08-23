package install

import (
	"errors"
	"fmt"
	"os"
)

const (
	cleanupTypeMask    = 0o170000
	cleanupTypeDir     = 0o040000
	cleanupTypeFile    = 0o100000
	cleanupTypeSymlink = 0o120000
)

type cleanupIdentity struct {
	Device     uint64
	Inode      uint64
	MountID    uint64
	MountKnown bool
	Mode       uint32
	Links      uint64
	UID        uint32
	GID        uint32
	Size       uint64
	ChangeSec  int64
	ChangeNsec int64
	ModifySec  int64
	ModifyNsec int64
}

func (id cleanupIdentity) sameObject(other cleanupIdentity) bool {
	if id.Device != other.Device || id.Inode != other.Inode {
		return false
	}
	if id.MountKnown != other.MountKnown {
		return false
	}
	if id.MountKnown && id.MountID != other.MountID {
		return false
	}
	return id.Mode&cleanupTypeMask == other.Mode&cleanupTypeMask
}

func (id cleanupIdentity) sameMount(other cleanupIdentity) bool {
	if id.MountKnown && other.MountKnown {
		return id.MountID == other.MountID
	}
	return id.Device == other.Device
}

func (id cleanupIdentity) sameDirectory(other cleanupIdentity) bool {
	return id.sameObject(other) &&
		id.UID == other.UID &&
		id.GID == other.GID &&
		id.Mode&0o7777 == other.Mode&0o7777
}

func (id cleanupIdentity) sameRegularFile(other cleanupIdentity) bool {
	return id.sameRegularFileObject(other) &&
		id.ChangeSec == other.ChangeSec &&
		id.ChangeNsec == other.ChangeNsec &&
		id.ModifySec == other.ModifySec &&
		id.ModifyNsec == other.ModifyNsec
}

func (id cleanupIdentity) sameRegularFileObject(other cleanupIdentity) bool {
	return id.sameObject(other) &&
		id.UID == other.UID &&
		id.GID == other.GID &&
		id.Mode&0o7777 == other.Mode&0o7777 &&
		id.Links == other.Links &&
		id.Size == other.Size
}

func (id cleanupIdentity) sameSymlink(other cleanupIdentity) bool {
	return id.sameSymlinkObject(other) &&
		id.ChangeSec == other.ChangeSec &&
		id.ChangeNsec == other.ChangeNsec &&
		id.ModifySec == other.ModifySec &&
		id.ModifyNsec == other.ModifyNsec
}

func (id cleanupIdentity) sameSymlinkObject(other cleanupIdentity) bool {
	return id.sameObject(other) &&
		id.UID == other.UID &&
		id.GID == other.GID &&
		id.Mode&0o7777 == other.Mode&0o7777 &&
		id.Links == other.Links &&
		id.Size == other.Size
}

func (id cleanupIdentity) validateDirectory(path string, owner uint32) error {
	if id.Mode&cleanupTypeMask != cleanupTypeDir {
		return fmt.Errorf("refuse cleanup directory %s: path is not a directory", path)
	}
	if id.UID != owner {
		return fmt.Errorf("refuse cleanup directory %s: owner uid is %d, want %d", path, id.UID, owner)
	}
	if id.Mode&0o022 != 0 {
		return fmt.Errorf("refuse cleanup directory %s: group/other writable mode %#o", path, id.Mode&0o7777)
	}
	return nil
}

func (id cleanupIdentity) validateRegularFile(path string, owner uint32) error {
	if id.Mode&cleanupTypeMask != cleanupTypeFile {
		return fmt.Errorf("refuse managed file %s: path is not a regular file", path)
	}
	if id.UID != owner {
		return fmt.Errorf("refuse managed file %s: owner uid is %d, want %d", path, id.UID, owner)
	}
	if id.Links != 1 {
		return fmt.Errorf("refuse managed file %s: file has %d links", path, id.Links)
	}
	if id.Mode&0o022 != 0 {
		return fmt.Errorf("refuse managed file %s: group/other writable mode %#o", path, id.Mode&0o7777)
	}
	return nil
}

func (id cleanupIdentity) validateSymlink(path string, owner uint32) error {
	if id.Mode&cleanupTypeMask != cleanupTypeSymlink {
		return fmt.Errorf("refuse managed symlink %s: path is not a symbolic link", path)
	}
	if id.UID != owner {
		return fmt.Errorf("refuse managed symlink %s: owner uid is %d, want %d", path, id.UID, owner)
	}
	if id.Links != 1 {
		return fmt.Errorf("refuse managed symlink %s: link inode has %d names", path, id.Links)
	}
	return nil
}

type cleanupDirFD struct {
	file     *os.File
	identity cleanupIdentity
	path     string
}

func (d *cleanupDirFD) close() error {
	if d == nil || d.file == nil {
		return nil
	}
	err := d.file.Close()
	d.file = nil
	return err
}

func cleanupIsNotExist(err error) bool {
	return errors.Is(err, os.ErrNotExist)
}
