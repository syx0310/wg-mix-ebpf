package dataplane

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

var (
	errFakeTCPProductionScopeMismatch = errors.New(
		"production dataplane scope does not match the retained owner",
	)
	errFakeTCPProductionScopeUnboundOwner = errors.New(
		"production dataplane owner has no bound scope identity",
	)
)

type fakeTCPProductionObjectScopeKind uint8

const (
	fakeTCPProductionObjectScopeInvalid fakeTCPProductionObjectScopeKind = iota
	fakeTCPProductionObjectScopeEmbedded
	fakeTCPProductionObjectScopeFilesystem
)

// fakeTCPProductionScopeIdentity is a comparable, non-concatenated ownership
// domain identity. ObjectPath intentionally identifies the canonical source
// path, not its inode or content. An object replaced at the same path remains
// in the same ownership scope; the experimental production planner must fold
// the loaded ObjectIdentity (including SHA-256) into fakeTCPRuntimeDesiredKey,
// so the supervisor rejects an in-place content change as a live generation
// replacement rather than confusing it with the current runtime.
type fakeTCPProductionScopeIdentity struct {
	objectKind        fakeTCPProductionObjectScopeKind
	objectPath        string
	fakeTCPObjectPath string
	pinPath           string
	lifecyclePath     string
	adoptLegacyPins   bool
}

func (scope fakeTCPProductionScopeIdentity) validate() error {
	switch scope.objectKind {
	case fakeTCPProductionObjectScopeEmbedded:
		if scope.objectPath != EmbeddedObjectSource {
			return errors.New("production embedded object scope has an invalid source")
		}
	case fakeTCPProductionObjectScopeFilesystem:
		if err := validateCanonicalFakeTCPProductionPath("object", scope.objectPath); err != nil {
			return err
		}
	default:
		return errors.New("production object scope kind is invalid")
	}
	// FakeTCP always has an independent object source. The packaged default is
	// a second embedded object; an override must use the same canonical,
	// symlink-free spelling as every other production scope path.
	if scope.fakeTCPObjectPath != EmbeddedFakeTCPObjectSource {
		if err := validateCanonicalFakeTCPProductionPath(
			"FakeTCP object", scope.fakeTCPObjectPath,
		); err != nil {
			return err
		}
	}
	if err := validateCanonicalFakeTCPProductionPath("pin", scope.pinPath); err != nil {
		return err
	}
	if err := validateCanonicalFakeTCPProductionPath("lifecycle lease", scope.lifecyclePath); err != nil {
		return err
	}
	return nil
}

func (scope fakeTCPProductionScopeIdentity) String() string {
	objectKind := "invalid"
	switch scope.objectKind {
	case fakeTCPProductionObjectScopeEmbedded:
		objectKind = "embedded"
	case fakeTCPProductionObjectScopeFilesystem:
		objectKind = "filesystem"
	}
	return fmt.Sprintf(
		"object_kind=%q object_path=%q faketcp_object_path=%q pin=%q lifecycle=%q adopt_legacy_pins=%t",
		objectKind,
		scope.objectPath,
		scope.fakeTCPObjectPath,
		scope.pinPath,
		scope.lifecyclePath,
		scope.adoptLegacyPins,
	)
}

func validateCanonicalFakeTCPProductionPath(label, path string) error {
	if path == "" {
		return fmt.Errorf("production %s path is empty", label)
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("production %s path %q is not absolute", label, path)
	}
	if cleaned := filepath.Clean(path); cleaned != path {
		return fmt.Errorf(
			"production %s path %q is not canonical (clean spelling %q)",
			label,
			path,
			cleaned,
		)
	}
	if filepath.Dir(path) == path {
		return fmt.Errorf("production %s path must not be a filesystem root", label)
	}
	return nil
}

// canonicalFakeTCPProductionPath rejects relative/non-clean spellings and any
// symlink in the existing path prefix. Missing suffixes are allowed because a
// first Apply may create the pin leaf, while Detach must remain able to name a
// scope after its object file has disappeared. Rejecting symlinks instead of
// following them avoids a resolution-to-use alias race in the coordinator;
// the lower-level baseline loader still performs its FD/inode checks.
func canonicalFakeTCPProductionPath(label, path string) (string, error) {
	if err := validateCanonicalFakeTCPProductionPath(label, path); err != nil {
		return "", err
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		switch {
		case err == nil && info.Mode()&os.ModeSymlink != 0:
			return "", fmt.Errorf(
				"production %s path %q contains symbolic-link component %q",
				label,
				path,
				current,
			)
		case err != nil && !errors.Is(err, os.ErrNotExist):
			return "", fmt.Errorf(
				"inspect production %s path component %q: %w",
				label,
				current,
				err,
			)
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}
	return path, nil
}
