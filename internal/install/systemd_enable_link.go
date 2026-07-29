package install

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

const (
	systemdEnableLinkKind   = "systemd-enable-link"
	systemdEnableLinkTarget = "../wg-mix-ebpf.service"
)

type systemdEnableLinkTransaction struct {
	artifact      cleanupManifestArtifact
	parent        *managedCleanupDir
	entry         *cleanupEntryPlan
	created       bool
	parentCreated bool
	committed     bool
}

func declaredSystemdEnableLink(paths paths) (cleanupManifestArtifact, error) {
	manifest := expectedCleanupManifest(paths, "systemd", strings.Repeat("0", 32))
	var selected *cleanupManifestArtifact
	for index := range manifest.Artifacts {
		if manifest.Artifacts[index].Kind != systemdEnableLinkKind {
			continue
		}
		if selected != nil {
			return cleanupManifestArtifact{}, errors.New(
				"systemd install manifest declares duplicate enable links",
			)
		}
		selected = &manifest.Artifacts[index]
	}
	if selected == nil || selected.Target == "" || selected.SHA256 != "" {
		return cleanupManifestArtifact{}, errors.New(
			"systemd install manifest lacks its exact enable symlink",
		)
	}
	return *selected, nil
}

func beginSystemdEnableLinkTransaction(
	paths paths,
	allowExisting bool,
) (_ *systemdEnableLinkTransaction, retErr error) {
	artifact, err := declaredSystemdEnableLink(paths)
	if err != nil {
		return nil, err
	}
	defaultParent := "/etc/systemd/system/multi-user.target.wants"
	parent, exists, err := openDeclaredArtifactParent(
		filepath.Dir(artifact.Path),
		defaultParent,
	)
	parentCreated := false
	if err != nil {
		return nil, err
	}
	if !exists {
		parent, err = openOrCreateDeclaredArtifactParent(
			filepath.Dir(artifact.Path),
			defaultParent,
		)
		if err != nil {
			return nil, err
		}
		parentCreated = true
	}
	transaction := &systemdEnableLinkTransaction{
		artifact:      artifact,
		parent:        parent,
		parentCreated: parentCreated,
	}
	defer func() {
		if retErr == nil {
			return
		}
		retErr = errors.Join(retErr, transaction.rollback(), transaction.close())
	}()

	if err := revalidateManagedCleanupDir(parent); err != nil {
		return nil, err
	}
	name := filepath.Base(artifact.Path)
	_, err = cleanupSymlinkIdentityAt(parent.dir, name)
	switch {
	case err == nil:
		if !allowExisting {
			return nil, fmt.Errorf(
				"refuse pre-existing systemd enable link %s for a fresh install",
				artifact.Path,
			)
		}
		entry, err := snapshotManagedSymlink(parent.dir, name, false, artifact.Target)
		if err != nil {
			return nil, err
		}
		transaction.entry = entry
		return transaction, nil
	case !cleanupIsNotExist(err):
		return nil, fmt.Errorf("inspect systemd enable link %s: %w", artifact.Path, err)
	}

	if err := cleanupSymlinkAt(parent.dir, artifact.Target, name); err != nil {
		return nil, fmt.Errorf("create exact systemd enable link %s: %w", artifact.Path, err)
	}
	transaction.created = true
	entry, err := snapshotManagedSymlink(parent.dir, name, false, artifact.Target)
	if err != nil {
		return nil, fmt.Errorf("validate newly created systemd enable link: %w", err)
	}
	entry.remove = true
	transaction.entry = entry
	if err := parent.dir.file.Sync(); err != nil {
		return nil, fmt.Errorf("sync systemd enable link directory %s: %w", parent.spec.path, err)
	}
	if err := revalidateManagedCleanupDir(parent); err != nil {
		return nil, err
	}
	return transaction, nil
}

func (transaction *systemdEnableLinkTransaction) commit() {
	if transaction != nil {
		transaction.committed = true
	}
}

func (transaction *systemdEnableLinkTransaction) rollback() error {
	if transaction == nil || transaction.committed {
		return nil
	}
	var errs []error
	if transaction.created {
		switch {
		case transaction.entry == nil:
			errs = append(errs, fmt.Errorf(
				"cannot safely roll back unverified systemd enable link %s; "+
					"the published ownership manifest retains its exact path and target",
				transaction.artifact.Path,
			))
		default:
			if err := revalidateManagedCleanupDir(transaction.parent); err != nil {
				errs = append(errs, err)
			} else if err := transaction.entry.unlink(nil); err != nil {
				errs = append(errs, fmt.Errorf(
					"roll back exact systemd enable link %s: %w",
					transaction.artifact.Path,
					err,
				))
			} else {
				transaction.created = false
				if err := transaction.parent.dir.file.Sync(); err != nil {
					errs = append(errs, fmt.Errorf(
						"sync systemd enable link rollback directory %s: %w",
						transaction.parent.spec.path,
						err,
					))
				}
			}
		}
	}
	if transaction.parentCreated && !transaction.created {
		entries, err := cleanupReadDir(transaction.parent.dir)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf(
				"inspect created systemd enable directory before rollback: %w",
				err,
			))
		case len(entries) != 0:
			errs = append(errs, fmt.Errorf(
				"refuse to remove created systemd enable directory %s: directory is no longer empty",
				transaction.parent.spec.path,
			))
		default:
			if err := revalidateManagedCleanupDir(transaction.parent); err != nil {
				errs = append(errs, fmt.Errorf(
					"refuse to remove created systemd enable directory %s: %w",
					transaction.parent.spec.path,
					err,
				))
			} else if err := cleanupUnlinkAt(
				transaction.parent.parent,
				transaction.parent.name,
				true,
			); err != nil {
				errs = append(errs, fmt.Errorf(
					"remove empty created systemd enable directory %s: %w",
					transaction.parent.spec.path,
					err,
				))
			} else if err := transaction.parent.parent.file.Sync(); err != nil {
				errs = append(errs, fmt.Errorf(
					"sync parent after systemd enable directory rollback: %w",
					err,
				))
			} else {
				transaction.parentCreated = false
			}
		}
	}
	return errors.Join(errs...)
}

func (transaction *systemdEnableLinkTransaction) close() error {
	if transaction == nil || transaction.parent == nil {
		return nil
	}
	err := transaction.parent.close()
	transaction.parent = nil
	return err
}

func systemdEnableLinkPath(paths paths) string {
	return filepath.Join(
		paths.SystemdDir,
		"multi-user.target.wants",
		"wg-mix-ebpf.service",
	)
}
