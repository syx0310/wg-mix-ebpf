package install

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/syx0310/wg-mix-ebpf/internal/config"
	"gopkg.in/yaml.v3"
)

func ensureInstallConfigArtifact(
	configDir *managedCleanupDir,
	path string,
	allowExisting bool,
) (retErr error) {
	if configDir == nil || configDir.dir == nil || configDir.dir.file == nil {
		return errors.New("install config requires a held config directory")
	}
	if filepath.Clean(filepath.Dir(path)) != filepath.Clean(configDir.spec.path) {
		return fmt.Errorf(
			"refuse install config %s outside held directory %s",
			path,
			configDir.spec.path,
		)
	}
	if err := revalidateManagedCleanupDir(configDir); err != nil {
		return fmt.Errorf("revalidate install config directory: %w", err)
	}

	name := filepath.Base(path)
	existing, identity, err := cleanupOpenFileAt(configDir.dir, name)
	switch {
	case err == nil:
		defer existing.Close()
		if !allowExisting {
			return fmt.Errorf(
				"refuse install config %s that appeared during a fresh install",
				path,
			)
		}
		return validateExistingInstallConfig(configDir, name, path, existing, identity)
	case !cleanupIsNotExist(err):
		return fmt.Errorf("inspect install config %s: %w", path, err)
	}

	template := config.SafeTemplate()
	template.ApplyDefaults()
	data, err := yaml.Marshal(template)
	if err != nil {
		return fmt.Errorf("marshal safe install config template: %w", err)
	}
	tempPrefix := "." + name + ".tmp-"
	if err := refuseRetainedInstallTemporary(
		configDir.dir,
		tempPrefix,
		"install config",
	); err != nil {
		return err
	}
	randomSuffix, err := newCleanupInstallationID()
	if err != nil {
		return err
	}
	tempName := tempPrefix + randomSuffix
	tempPath := filepath.Join(configDir.spec.path, tempName)
	temp, err := cleanupCreateFileAt(configDir.dir, tempName, 0o600)
	if err != nil {
		return fmt.Errorf("create temporary install config %s: %w", tempPath, err)
	}
	tempPresent := true
	defer func() {
		if !tempPresent {
			return
		}
		retErr = errors.Join(
			retErr,
			fmt.Errorf(
				"temporary install config retained without name-based cleanup at %s; "+
					"manually inspect its identity before removal",
				tempPath,
			),
		)
	}()
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return fmt.Errorf("set temporary install config permissions: %w", err)
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return fmt.Errorf("write temporary install config: %w", err)
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return fmt.Errorf("sync temporary install config: %w", err)
	}
	tempIdentity, err := cleanupIdentityForFD(int(temp.Fd()))
	if err != nil {
		_ = temp.Close()
		return fmt.Errorf("inspect temporary install config: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close temporary install config: %w", err)
	}
	if err := revalidateManagedCleanupDir(configDir); err != nil {
		return fmt.Errorf("revalidate install config directory before commit: %w", err)
	}
	if _, err := cleanupIdentityAt(configDir.dir, name); !cleanupIsNotExist(err) {
		if err == nil {
			return fmt.Errorf("refuse install config %s that appeared before commit", path)
		}
		return fmt.Errorf("recheck absent install config %s: %w", path, err)
	}
	if err := cleanupRenameNoReplaceAt(configDir.dir, tempName, name); err != nil {
		return fmt.Errorf(
			"atomically install config %s without replacement: %w",
			path,
			err,
		)
	}
	tempPresent = false
	if err := configDir.dir.file.Sync(); err != nil {
		return fmt.Errorf("sync install config directory %s: %w", configDir.spec.path, err)
	}

	installed, installedIdentity, err := cleanupOpenFileAt(configDir.dir, name)
	if err != nil {
		return fmt.Errorf("open installed config %s: %w", path, err)
	}
	defer installed.Close()
	if !tempIdentity.sameRegularFileObject(installedIdentity) {
		return fmt.Errorf(
			"installed config %s does not match the published temporary inode",
			path,
		)
	}
	return validateExistingInstallConfig(
		configDir,
		name,
		path,
		installed,
		installedIdentity,
	)
}

func validateExistingInstallConfig(
	configDir *managedCleanupDir,
	name string,
	path string,
	file *os.File,
	identity cleanupIdentity,
) error {
	if err := identity.validateRegularFile(path, uint32(os.Geteuid())); err != nil {
		return err
	}
	if identity.Mode&0o7777 != 0o600 {
		return fmt.Errorf(
			"refuse install config %s: mode %#o does not match 0600",
			path,
			identity.Mode&0o7777,
		)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxManagedCleanupFileSize+1))
	if err != nil {
		return fmt.Errorf("read install config %s: %w", path, err)
	}
	if len(data) > maxManagedCleanupFileSize {
		return fmt.Errorf("refuse install config %s: content exceeds size limit", path)
	}
	if _, err := config.Load(data); err != nil {
		return fmt.Errorf("validate install config %s: %w", path, err)
	}
	finalIdentity, err := cleanupIdentityForFD(int(file.Fd()))
	if err != nil {
		return fmt.Errorf("recheck held install config %s: %w", path, err)
	}
	if !identity.sameRegularFile(finalIdentity) {
		return fmt.Errorf("refuse install config %s: held identity changed", path)
	}
	namedIdentity, err := cleanupIdentityAt(configDir.dir, name)
	if err != nil {
		return fmt.Errorf("revalidate install config name %s: %w", path, err)
	}
	if !finalIdentity.sameRegularFile(namedIdentity) {
		return fmt.Errorf("refuse install config %s: pathname changed", path)
	}
	return nil
}
