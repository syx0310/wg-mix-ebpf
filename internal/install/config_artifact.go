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
	beforeFreshPublish func(objectBoundFreshFileHookState) error,
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
	result, err := publishObjectBoundFreshFile(objectBoundFreshFileSpec{
		parent:        configDir,
		name:          name,
		path:          path,
		kind:          "install config",
		mode:          0o600,
		content:       data,
		beforePublish: beforeFreshPublish,
	})
	if err != nil {
		return err
	}
	defer func() {
		closeErr := result.file.Close()
		if retErr != nil || closeErr != nil {
			retErr = errors.Join(
				retErr,
				closeErr,
				objectBoundPublishedFinalAudit(
					"install config",
					path,
					result.identity,
				),
			)
		}
	}()
	if _, err := result.file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind published install config %s: %w", path, err)
	}
	return validateExistingInstallConfig(
		configDir,
		name,
		path,
		result.file,
		result.identity,
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
