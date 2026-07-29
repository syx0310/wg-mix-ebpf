package install

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

const (
	systemdEnableLinkKind          = "systemd-enable-link"
	systemdEnableLinkTarget        = "../wg-mix-ebpf.service"
	systemdEnableLinkDefaultParent = "/etc/systemd/system/multi-user.target.wants"
)

type systemdEnableLinkTransactionHooks struct {
	afterCommitWalkOpen func(string) error
	afterRetentionCheck func(string) error
}

type systemdEnableLinkTransaction struct {
	artifact            cleanupManifestArtifact
	parent              *managedCleanupDir
	entry               *cleanupEntryPlan
	afterCommitWalkOpen func(string) error
	afterRetentionCheck func(string) error
	created             bool
	committed           bool
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
	hooks systemdEnableLinkTransactionHooks,
) (_ *systemdEnableLinkTransaction, retErr error) {
	artifact, err := declaredSystemdEnableLink(paths)
	if err != nil {
		return nil, err
	}
	parent, exists, err := openDeclaredArtifactParent(
		filepath.Dir(artifact.Path),
		systemdEnableLinkDefaultParent,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"open existing declared systemd wants directory %s: %w",
			filepath.Dir(artifact.Path),
			err,
		)
	}
	if !exists {
		return nil, fmt.Errorf(
			"refuse systemd enablement: declared wants directory %s does not exist; "+
				"create and validate it outside this transaction before retrying",
			filepath.Dir(artifact.Path),
		)
	}
	transaction := &systemdEnableLinkTransaction{
		artifact:            artifact,
		parent:              parent,
		afterCommitWalkOpen: hooks.afterCommitWalkOpen,
		afterRetentionCheck: hooks.afterRetentionCheck,
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
		if err := revalidateManagedCleanupDir(parent); err != nil {
			return nil, err
		}
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
	expectedHeldPath := filepath.Join(
		transaction.parent.declaredCanonicalPath,
		filepath.Base(transaction.artifact.Path),
	)
	if transaction.entry.path != expectedHeldPath ||
		transaction.entry.symlinkTarget != transaction.artifact.Target ||
		!transaction.entry.symlink {
		return errors.New(
			"systemd enable link transaction lost its declared link identity",
		)
	}
	if err := transaction.revalidateParentFromDeclaredRoot(
		"before exact link inspection",
	); err != nil {
		return fmt.Errorf(
			"revalidate held systemd wants directory from declared root at commit: %w",
			err,
		)
	}
	if err := transaction.entry.revalidate(); err != nil {
		return fmt.Errorf(
			"revalidate exact systemd enable link inode, UID, and target at commit: %w",
			err,
		)
	}
	if err := transaction.revalidateParentFromDeclaredRoot(
		"after exact link inspection",
	); err != nil {
		return fmt.Errorf(
			"revalidate held systemd wants directory from declared root at commit: %w",
			err,
		)
	}
	transaction.committed = true
	return nil
}

func (transaction *systemdEnableLinkTransaction) revalidateParentFromDeclaredRoot(
	boundary string,
) (retErr error) {
	if transaction == nil || transaction.parent == nil ||
		transaction.parent.dir == nil || transaction.parent.dir.file == nil {
		return errors.New("cannot revalidate an unheld systemd wants directory")
	}
	if err := revalidateManagedCleanupDir(transaction.parent); err != nil {
		return fmt.Errorf("%s: %w", boundary, err)
	}
	reopened, exists, err := openDeclaredArtifactParentWithOptions(
		filepath.Dir(transaction.artifact.Path),
		systemdEnableLinkDefaultParent,
		exactDeclaredDirectoryOpenOptions{
			afterOpen: transaction.afterCommitWalkOpen,
		},
	)
	if err != nil {
		return fmt.Errorf("%s: reopen declared systemd wants directory: %w", boundary, err)
	}
	if !exists {
		return fmt.Errorf(
			"%s: declared systemd wants directory disappeared",
			boundary,
		)
	}
	defer func() {
		if err := reopened.close(); err != nil {
			retErr = errors.Join(
				retErr,
				fmt.Errorf(
					"%s: close reopened systemd wants directory: %w",
					boundary,
					err,
				),
			)
		}
	}()
	if err := revalidateManagedCleanupDir(reopened); err != nil {
		return fmt.Errorf(
			"%s: revalidate reopened systemd wants directory: %w",
			boundary,
			err,
		)
	}
	if err := compareDeclaredDirectoryChains(transaction.parent, reopened); err != nil {
		return fmt.Errorf("%s: compare complete declared directory chains: %w", boundary, err)
	}
	return nil
}

func (transaction *systemdEnableLinkTransaction) rollback() error {
	if transaction == nil || transaction.committed {
		return nil
	}

	beforeStatus := transaction.retentionStatus()
	var hookErr error
	if transaction.afterRetentionCheck != nil {
		if err := transaction.afterRetentionCheck(transaction.artifact.Path); err != nil {
			hookErr = fmt.Errorf(
				"run systemd enable retention post-check hook for %s: %w",
				transaction.artifact.Path,
				err,
			)
		}
	}
	afterStatus := transaction.retentionStatus()
	heldIdentity := "unavailable"
	if transaction.entry != nil {
		heldIdentity = systemdEnableIdentitySummary(transaction.entry.identity)
	}

	retentionErr := fmt.Errorf(
		"systemd enable failure retained evidence without rename, unlink, restore, or rmdir: "+
			"original declared path %s, declared target %q, created_by_transaction=%t, "+
			"held identity [%s], status before final retention hook [%s], "+
			"current status [%s]; ownership was published before enablement, but the "+
			"manifest does not durably bind this symlink inode, so automatic cleanup "+
			"is not authorized after this error; manually inspect and resolve the "+
			"declared path before using validated uninstall",
		transaction.artifact.Path,
		transaction.artifact.Target,
		transaction.created,
		heldIdentity,
		beforeStatus,
		afterStatus,
	)
	return errors.Join(hookErr, retentionErr)
}

func (transaction *systemdEnableLinkTransaction) retentionStatus() string {
	if transaction == nil || transaction.parent == nil ||
		transaction.parent.dir == nil || transaction.parent.dir.file == nil {
		return "held wants-directory descriptor unavailable"
	}
	chainStatus := "declared parent chain still reaches every held component"
	if err := revalidateManagedCleanupDir(transaction.parent); err != nil {
		chainStatus = "declared parent chain mismatch: " + err.Error()
	}

	name := filepath.Base(transaction.artifact.Path)
	identity, err := cleanupSymlinkIdentityAt(transaction.parent.dir, name)
	if cleanupIsNotExist(err) {
		return chainStatus + "; held-directory entry is absent"
	}
	if err != nil {
		return chainStatus + "; held-directory entry inspection failed: " + err.Error()
	}
	target, err := cleanupReadlinkAt(transaction.parent.dir, name)
	if err != nil {
		return chainStatus + "; held-directory entry target inspection failed: " + err.Error()
	}
	current := fmt.Sprintf(
		"%s; held-directory entry identity [%s], target %q",
		chainStatus,
		systemdEnableIdentitySummary(identity),
		target,
	)
	if transaction.entry == nil {
		return current + "; no transaction-held link identity was established"
	}
	return fmt.Sprintf(
		"%s; matches held identity=%t, matches declared target=%t",
		current,
		transaction.entry.identity.sameSymlink(identity),
		target == transaction.artifact.Target,
	)
}

func systemdEnableIdentitySummary(identity cleanupIdentity) string {
	mount := "unknown"
	if identity.MountKnown {
		mount = fmt.Sprintf("%d", identity.MountID)
	}
	return fmt.Sprintf(
		"device=%d inode=%d mount=%s uid=%d gid=%d mode=%#o links=%d",
		identity.Device,
		identity.Inode,
		mount,
		identity.UID,
		identity.GID,
		identity.Mode,
		identity.Links,
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
