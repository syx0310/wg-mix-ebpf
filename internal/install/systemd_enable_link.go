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

func (transaction *systemdEnableLinkTransaction) commit() error {
	if transaction == nil || transaction.parent == nil || transaction.entry == nil {
		return errors.New(
			"cannot commit systemd enable link without held directory and link identities",
		)
	}
	if transaction.committed {
		return errors.New("systemd enable link transaction is already committed")
	}
	if transaction.entry.path != transaction.artifact.Path ||
		transaction.entry.symlinkTarget != transaction.artifact.Target ||
		!transaction.entry.symlink {
		return errors.New(
			"systemd enable link transaction lost its declared link identity",
		)
	}
	if err := revalidateManagedCleanupDir(transaction.parent); err != nil {
		return fmt.Errorf(
			"revalidate held systemd wants directory at commit: %w",
			err,
		)
	}
	if err := transaction.entry.revalidate(); err != nil {
		return fmt.Errorf(
			"revalidate exact systemd enable link inode, UID, and target at commit: %w",
			err,
		)
	}
	if err := revalidateManagedCleanupDir(transaction.parent); err != nil {
		return fmt.Errorf(
			"revalidate held systemd wants directory after exact link inspection: %w",
			err,
		)
	}
	transaction.committed = true
	return nil
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
			// The entry plan is bound to the held wants-directory descriptor.
			// Do not resolve the wants pathname again before rolling back the
			// exact link: a replaced pathname must neither redirect cleanup to
			// a foreign directory nor prevent descriptor-bound cleanup of the
			// transaction-owned link in a displaced directory.
			if err := transaction.entry.unlink(nil); err != nil {
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
		directory := &cleanupDirectoryPlan{
			root:          transaction.parent,
			strictEntries: true,
			removeRoot:    true,
		}
		if err := directory.remove(nil); err != nil {
			errs = append(errs, fmt.Errorf(
				"roll back exact created systemd enable directory %s: %w",
				transaction.parent.spec.path,
				err,
			))
		} else {
			transaction.parentCreated = false
			if err := transaction.parent.parent.file.Sync(); err != nil {
				errs = append(errs, fmt.Errorf(
					"sync parent after systemd enable directory rollback: %w",
					err,
				))
			}
		}
	}
	rollbackErr := errors.Join(errs...)
	if rollbackErr == nil {
		return nil
	}
	return errors.Join(
		rollbackErr,
		fmt.Errorf(
			"systemd enable rollback is incomplete; the published ownership "+
				"manifest retains path %s and target %q, and any object that "+
				"could not be restored from cleanup quarantine remains at the "+
				"exact quarantine path reported above",
			transaction.artifact.Path,
			transaction.artifact.Target,
		),
	)
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
