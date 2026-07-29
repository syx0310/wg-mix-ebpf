package pinidentity

import (
	"crypto/sha256"
	"fmt"
	"regexp"
)

const CanonicalVersion = "wg-mix-ebpf-pin-v1"

var (
	baseNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$`)
	keyPattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Canonical returns the stable identity for a pin basename within a specific
// parent directory. Device and inode identify the directory rather than its
// potentially aliased path.
func Canonical(parentDevice uint64, parentInode uint64, baseName string) (string, error) {
	if parentDevice == 0 {
		return "", fmt.Errorf("pin parent device must be non-zero")
	}
	if parentInode == 0 {
		return "", fmt.Errorf("pin parent inode must be non-zero")
	}
	if !baseNamePattern.MatchString(baseName) || baseName == "." || baseName == ".." {
		return "", fmt.Errorf("pin basename %q is not a canonical ASCII path component", baseName)
	}
	return fmt.Sprintf(
		"%s:%d:%d:%s",
		CanonicalVersion,
		parentDevice,
		parentInode,
		baseName,
	), nil
}

// Key returns the lowercase hexadecimal SHA-256 digest of Canonical.
func Key(parentDevice uint64, parentInode uint64, baseName string) (string, error) {
	canonical, err := Canonical(parentDevice, parentInode, baseName)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(canonical))
	return fmt.Sprintf("%x", sum), nil
}

func LockFileName(parentDevice uint64, parentInode uint64, baseName string) (string, error) {
	key, err := Key(parentDevice, parentInode, baseName)
	if err != nil {
		return "", err
	}
	return key + ".lock", nil
}

func OwnerFileName(parentDevice uint64, parentInode uint64, baseName string) (string, error) {
	key, err := Key(parentDevice, parentInode, baseName)
	if err != nil {
		return "", err
	}
	return key + ".owner.json", nil
}

func ValidKey(key string) bool {
	return keyPattern.MatchString(key)
}
