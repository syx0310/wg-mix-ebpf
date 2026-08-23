package install

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const defaultBinaryParent = "/usr/sbin"

func validateInstallBinaryPath(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("refuse non-clean install binary path %q", path)
	}
	if err := validateServiceTemplatePath("install binary path", path); err != nil {
		return err
	}
	if filepath.Base(path) != "wg-mix-ebpf" {
		return fmt.Errorf(
			"refuse install binary path %s: basename must be wg-mix-ebpf",
			path,
		)
	}
	if _, err := declaredArtifactPathSpec(
		filepath.Dir(path),
		defaultBinaryParent,
	); err != nil {
		return fmt.Errorf("refuse install binary parent: %w", err)
	}
	return nil
}

func validateInstallBinaryTarget(path string, requirePresent bool) (bool, error) {
	if err := validateInstallBinaryPath(path); err != nil {
		return false, err
	}
	parent, exists, err := openDeclaredArtifactParent(
		filepath.Dir(path),
		defaultBinaryParent,
	)
	if err != nil {
		return false, err
	}
	if !exists {
		if requirePresent {
			return false, fmt.Errorf("install binary parent %s is missing", filepath.Dir(path))
		}
		return false, nil
	}
	defer parent.close()

	file, identity, err := cleanupOpenFileAt(parent.dir, filepath.Base(path))
	if cleanupIsNotExist(err) {
		if requirePresent {
			return false, fmt.Errorf("install binary %s is missing", path)
		}
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("open install binary %s: %w", path, err)
	}
	defer file.Close()
	if err := identity.validateRegularFile(path, uint32(os.Geteuid())); err != nil {
		return false, err
	}
	if identity.Mode&0o7777 != 0o755 {
		return false, fmt.Errorf(
			"refuse install binary %s: mode %#o does not match 0755",
			path,
			identity.Mode&0o7777,
		)
	}
	finalIdentity, err := cleanupIdentityForFD(int(file.Fd()))
	if err != nil {
		return false, err
	}
	if !identity.sameRegularFile(finalIdentity) {
		return false, fmt.Errorf(
			"refuse install binary %s: identity changed during validation",
			path,
		)
	}
	return true, nil
}

func installBinary(target string) (retErr error) {
	if err := validateInstallBinaryPath(target); err != nil {
		return err
	}
	src, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve current executable: %w", err)
	}
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open current executable %s: %w", src, err)
	}
	defer in.Close()
	sourceInfo, err := in.Stat()
	if err != nil {
		return fmt.Errorf("inspect current executable %s: %w", src, err)
	}
	if !sourceInfo.Mode().IsRegular() {
		return fmt.Errorf("current executable %s is not a regular file", src)
	}

	parent, _, err := openOrCreateDeclaredArtifactParent(
		filepath.Dir(target),
		defaultBinaryParent,
		nil,
	)
	if err != nil {
		return fmt.Errorf("open install binary parent: %w", err)
	}
	defer func() {
		retErr = errors.Join(retErr, parent.close())
	}()

	name := filepath.Base(target)
	var prior cleanupIdentity
	existing, existingIdentity, openErr := cleanupOpenFileAt(parent.dir, name)
	switch {
	case openErr == nil:
		prior = existingIdentity
		if err := prior.validateRegularFile(target, uint32(os.Geteuid())); err != nil {
			_ = existing.Close()
			return err
		}
		if prior.Mode&0o7777 != 0o755 {
			_ = existing.Close()
			return fmt.Errorf(
				"refuse to replace install binary %s with unexpected mode %#o",
				target,
				prior.Mode&0o7777,
			)
		}
		srcAbs, _ := filepath.Abs(src)
		dstAbs, _ := filepath.Abs(target)
		if srcAbs == dstAbs {
			return existing.Close()
		}
		if err := existing.Close(); err != nil {
			return fmt.Errorf("close existing install binary %s: %w", target, err)
		}
	case cleanupIsNotExist(openErr):
		existing = nil
	default:
		return fmt.Errorf("inspect existing install binary %s: %w", target, openErr)
	}

	randomSuffix, err := newCleanupInstallationID()
	if err != nil {
		return err
	}
	tempName := "." + name + ".tmp-" + randomSuffix
	out, err := cleanupCreateFileAt(parent.dir, tempName, 0o755)
	if err != nil {
		return fmt.Errorf("create temporary install binary: %w", err)
	}
	tempPresent := true
	defer func() {
		if !tempPresent {
			return
		}
		if err := cleanupUnlinkAt(parent.dir, tempName, false); err != nil &&
			!cleanupIsNotExist(err) {
			retErr = errors.Join(
				retErr,
				fmt.Errorf("remove temporary install binary %s: %w", tempName, err),
			)
		}
	}()
	if err := out.Chmod(0o755); err != nil {
		_ = out.Close()
		return fmt.Errorf("set temporary install binary mode: %w", err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return fmt.Errorf("copy install binary: %w", err)
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return fmt.Errorf("sync temporary install binary: %w", err)
	}
	tempIdentity, err := cleanupIdentityForFD(int(out.Fd()))
	if err != nil {
		_ = out.Close()
		return fmt.Errorf("inspect temporary install binary: %w", err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close temporary install binary: %w", err)
	}

	if existing != nil {
		current, err := cleanupIdentityAt(parent.dir, name)
		if err != nil {
			return fmt.Errorf("revalidate existing install binary %s: %w", target, err)
		}
		if !prior.sameRegularFile(current) {
			return fmt.Errorf(
				"refuse to replace install binary %s: target identity changed",
				target,
			)
		}
		if err := cleanupRenameReplaceAt(parent.dir, tempName, name); err != nil {
			return fmt.Errorf("atomically replace install binary %s: %w", target, err)
		}
	} else if err := cleanupRenameNoReplaceAt(parent.dir, tempName, name); err != nil {
		return fmt.Errorf("atomically install new binary %s: %w", target, err)
	}
	tempPresent = false
	if err := parent.dir.file.Sync(); err != nil {
		return fmt.Errorf("sync install binary directory %s: %w", parent.spec.path, err)
	}

	installed, identity, err := cleanupOpenFileAt(parent.dir, name)
	if err != nil {
		return fmt.Errorf("open installed binary %s: %w", target, err)
	}
	defer installed.Close()
	if !tempIdentity.sameRegularFileObject(identity) {
		return fmt.Errorf(
			"installed binary %s does not match the published temporary inode",
			target,
		)
	}
	if err := identity.validateRegularFile(target, uint32(os.Geteuid())); err != nil {
		return err
	}
	if identity.Mode&0o7777 != 0o755 {
		return fmt.Errorf(
			"installed binary %s has mode %#o, want 0755",
			target,
			identity.Mode&0o7777,
		)
	}
	return nil
}
