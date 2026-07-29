package install

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

type serviceArtifactInstallSpec struct {
	artifact           cleanupManifestArtifact
	content            []byte
	mode               os.FileMode
	defaultParent      string
	beforeFreshPublish func(objectBoundFreshFileHookState) error
}

func serviceArtifactInstallSpecs(paths paths, system string) ([]serviceArtifactInstallSpec, error) {
	if err := validateRawServiceArtifactParentPaths(paths, system); err != nil {
		return nil, err
	}
	manifest := expectedCleanupManifest(paths, system, strings.Repeat("0", 32))
	specs := make([]serviceArtifactInstallSpec, 0, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		if artifact.Kind == systemdEnableLinkKind {
			continue
		}
		spec := serviceArtifactInstallSpec{artifact: artifact}
		switch artifact.Kind {
		case "systemd-unit":
			spec.content = []byte(systemdUnit(paths.ConfigPath, paths.BinaryPath))
			spec.mode = 0o644
			spec.defaultParent = "/etc/systemd/system"
		case "openwrt-init":
			spec.content = []byte(openWrtInit(
				paths.ConfigPath,
				paths.BinaryPath,
				artifact.Path,
			))
			spec.mode = 0o755
			spec.defaultParent = "/etc/init.d"
		case "openwrt-hotplug":
			spec.content = []byte(openWrtHotplug())
			spec.mode = 0o755
			spec.defaultParent = "/etc/hotplug.d/iface"
		default:
			return nil, fmt.Errorf("unknown service artifact kind %q", artifact.Kind)
		}
		sum := sha256.Sum256(spec.content)
		if artifact.SHA256 != hex.EncodeToString(sum[:]) {
			return nil, fmt.Errorf(
				"service artifact %s content does not match its ownership digest",
				artifact.Path,
			)
		}
		specs = append(specs, spec)
	}
	return specs, nil
}

func installServiceArtifacts(
	paths paths,
	system string,
	revalidateInstallMetadata func() error,
	beforeFreshPublish func(objectBoundFreshFileHookState) error,
) error {
	specs, err := serviceArtifactInstallSpecs(paths, system)
	if err != nil {
		return err
	}
	for _, spec := range specs {
		spec.beforeFreshPublish = beforeFreshPublish
		if revalidateInstallMetadata != nil {
			if err := revalidateInstallMetadata(); err != nil {
				return fmt.Errorf(
					"revalidate install ownership before service artifact %s: %w",
					spec.artifact.Path,
					err,
				)
			}
		}
		if err := installServiceArtifact(spec); err != nil {
			return err
		}
	}
	return nil
}

func installServiceArtifact(spec serviceArtifactInstallSpec) (retErr error) {
	parent, _, err := openOrCreateDeclaredArtifactParent(
		filepath.Dir(spec.artifact.Path),
		spec.defaultParent,
		nil,
	)
	if err != nil {
		return err
	}
	defer func() {
		if err := parent.close(); err != nil {
			retErr = errors.Join(
				retErr,
				fmt.Errorf("close service artifact directory %s: %w", parent.spec.path, err),
			)
		}
	}()

	name := filepath.Base(spec.artifact.Path)
	file, identity, err := cleanupOpenFileAt(parent.dir, name)
	switch {
	case err == nil:
		defer file.Close()
		if _, err := validateServiceArtifactFile(
			parent.dir,
			name,
			file,
			identity,
			spec,
			true,
		); err != nil {
			return err
		}
		return nil
	case !cleanupIsNotExist(err):
		return fmt.Errorf(
			"refuse existing service artifact %s: %w",
			spec.artifact.Path,
			err,
		)
	}

	result, err := publishObjectBoundFreshFile(objectBoundFreshFileSpec{
		parent:        parent,
		name:          name,
		path:          spec.artifact.Path,
		kind:          "service artifact",
		mode:          spec.mode,
		content:       spec.content,
		beforePublish: spec.beforeFreshPublish,
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
					"service artifact",
					spec.artifact.Path,
					result.identity,
				),
			)
		}
	}()
	if _, err := result.file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind published service artifact %s: %w", spec.artifact.Path, err)
	}
	if _, err := validateServiceArtifactFile(
		parent.dir,
		name,
		result.file,
		result.identity,
		spec,
		false,
	); err != nil {
		return err
	}
	return nil
}

func validateServiceArtifactFile(
	parent *cleanupDirFD,
	name string,
	file *os.File,
	identity cleanupIdentity,
	spec serviceArtifactInstallSpec,
	repairMode bool,
) (cleanupIdentity, error) {
	path := spec.artifact.Path
	if err := identity.validateRegularFile(path, uint32(os.Geteuid())); err != nil {
		return cleanupIdentity{}, err
	}
	data, err := io.ReadAll(io.LimitReader(file, maxManagedCleanupFileSize+1))
	if err != nil {
		return cleanupIdentity{}, fmt.Errorf("read service artifact %s: %w", path, err)
	}
	if len(data) > maxManagedCleanupFileSize || !bytes.Equal(data, spec.content) {
		return cleanupIdentity{}, fmt.Errorf(
			"refuse service artifact %s: content does not match the ownership manifest",
			path,
		)
	}
	afterRead, err := cleanupIdentityForFD(int(file.Fd()))
	if err != nil {
		return cleanupIdentity{}, err
	}
	if !identity.sameRegularFile(afterRead) {
		return cleanupIdentity{}, fmt.Errorf(
			"refuse service artifact %s: identity changed while validating content",
			path,
		)
	}
	if afterRead.Mode&0o7777 != uint32(spec.mode.Perm()) {
		if !repairMode {
			return cleanupIdentity{}, fmt.Errorf(
				"refuse service artifact %s: mode %#o does not match %#o",
				path,
				afterRead.Mode&0o7777,
				spec.mode.Perm(),
			)
		}
		if err := file.Chmod(spec.mode.Perm()); err != nil {
			return cleanupIdentity{}, fmt.Errorf("set service artifact mode %s: %w", path, err)
		}
		if err := file.Sync(); err != nil {
			return cleanupIdentity{}, fmt.Errorf("sync service artifact mode %s: %w", path, err)
		}
	}
	finalIdentity, err := cleanupIdentityForFD(int(file.Fd()))
	if err != nil {
		return cleanupIdentity{}, err
	}
	if afterRead.Mode&0o7777 == uint32(spec.mode.Perm()) &&
		!afterRead.sameRegularFile(finalIdentity) {
		return cleanupIdentity{}, fmt.Errorf(
			"refuse service artifact %s: identity changed after content validation",
			path,
		)
	}
	if err := finalIdentity.validateRegularFile(path, uint32(os.Geteuid())); err != nil {
		return cleanupIdentity{}, err
	}
	if !identity.sameObject(finalIdentity) ||
		identity.UID != finalIdentity.UID ||
		identity.GID != finalIdentity.GID ||
		identity.Links != finalIdentity.Links ||
		identity.Size != finalIdentity.Size ||
		finalIdentity.Mode&0o7777 != uint32(spec.mode.Perm()) {
		return cleanupIdentity{}, fmt.Errorf(
			"refuse service artifact %s: object identity changed during validation",
			path,
		)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return cleanupIdentity{}, err
	}
	finalData, err := io.ReadAll(io.LimitReader(file, maxManagedCleanupFileSize+1))
	if err != nil {
		return cleanupIdentity{}, fmt.Errorf("re-read service artifact %s: %w", path, err)
	}
	if len(finalData) > maxManagedCleanupFileSize || !bytes.Equal(finalData, spec.content) {
		return cleanupIdentity{}, fmt.Errorf(
			"refuse service artifact %s: content changed during final validation",
			path,
		)
	}
	afterFinalRead, err := cleanupIdentityForFD(int(file.Fd()))
	if err != nil {
		return cleanupIdentity{}, err
	}
	if !finalIdentity.sameRegularFile(afterFinalRead) {
		return cleanupIdentity{}, fmt.Errorf(
			"refuse service artifact %s: identity changed during final content validation",
			path,
		)
	}
	finalIdentity = afterFinalRead
	namedIdentity, err := cleanupIdentityAt(parent, name)
	if err != nil {
		return cleanupIdentity{}, fmt.Errorf("revalidate service artifact name %s: %w", path, err)
	}
	if !finalIdentity.sameRegularFile(namedIdentity) {
		return cleanupIdentity{}, fmt.Errorf(
			"refuse service artifact %s: pathname changed during validation",
			path,
		)
	}
	return finalIdentity, nil
}

type verifiedServiceArtifact struct {
	file                        *os.File
	entry                       *cleanupEntryPlan
	ownedParent                 *managedCleanupDir
	borrowedParent              *managedCleanupDir
	beforeFinalParentRevalidate func() error
}

type verifiedServiceArtifactAbsence struct {
	parent *managedCleanupDir
	path   string
	name   string
}

func (absence *verifiedServiceArtifactAbsence) close() error {
	if absence == nil {
		return nil
	}
	// The cleanup plan owns the retained parent chain. Absence verification
	// borrows it across the manager boundary and must not close it.
	absence.parent = nil
	return nil
}

func (absence *verifiedServiceArtifactAbsence) revalidate() error {
	if absence == nil || absence.parent == nil || absence.name == "" {
		return errors.New("cannot revalidate an unheld service artifact absence")
	}
	if err := revalidateManagedCleanupDir(absence.parent); err != nil {
		return fmt.Errorf(
			"revalidate service artifact absence parent chain for %s: %w",
			absence.path,
			err,
		)
	}
	if _, err := cleanupIdentityAt(absence.parent.dir, absence.name); !cleanupIsNotExist(err) {
		if err == nil {
			return fmt.Errorf(
				"refuse systemd manager reload: service artifact reappeared at %s",
				absence.path,
			)
		}
		return fmt.Errorf(
			"inspect removed service artifact %s: %w",
			absence.path,
			err,
		)
	}
	if err := revalidateManagedCleanupDir(absence.parent); err != nil {
		return fmt.Errorf(
			"revalidate service artifact absence parent chain after name inspection for %s: %w",
			absence.path,
			err,
		)
	}
	return nil
}

func (artifact *verifiedServiceArtifact) close() error {
	if artifact == nil {
		return nil
	}
	var errs []error
	if artifact.file != nil {
		errs = append(errs, artifact.file.Close())
		artifact.file = nil
	}
	if artifact.ownedParent != nil {
		errs = append(errs, artifact.ownedParent.close())
		artifact.ownedParent = nil
	}
	// borrowedParent belongs to the uninstall cleanup plan. The artifact only
	// borrows it for execution-boundary revalidation and must never close it.
	artifact.borrowedParent = nil
	return errors.Join(errs...)
}

func (artifact *verifiedServiceArtifact) revalidateForExecution() error {
	if artifact == nil || artifact.file == nil || artifact.entry == nil {
		return errors.New("cannot execute an unverified service artifact")
	}
	if (artifact.ownedParent == nil) == (artifact.borrowedParent == nil) {
		return errors.New(
			"service artifact must hold exactly one owned or borrowed parent chain",
		)
	}
	parent := artifact.ownedParent
	if parent == nil {
		parent = artifact.borrowedParent
	}
	if artifact.entry.parent != parent.dir {
		return fmt.Errorf(
			"service artifact entry parent is not the held final directory for %s",
			artifact.entry.path,
		)
	}
	if err := revalidateManagedCleanupDir(parent); err != nil {
		return fmt.Errorf(
			"refuse service artifact execution: parent identity changed for %s: %w",
			artifact.entry.path,
			err,
		)
	}
	entry := artifact.entry
	if _, err := artifact.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	data, err := io.ReadAll(io.LimitReader(artifact.file, maxManagedCleanupFileSize+1))
	if err != nil {
		return err
	}
	if len(data) > maxManagedCleanupFileSize || sha256.Sum256(data) != entry.digest {
		return fmt.Errorf("refuse service artifact execution: content changed for %s", entry.path)
	}
	fdIdentity, err := cleanupIdentityForFD(int(artifact.file.Fd()))
	if err != nil {
		return err
	}
	if !entry.identity.sameRegularFile(fdIdentity) {
		return fmt.Errorf("refuse service artifact execution: held identity changed for %s", entry.path)
	}
	namedIdentity, err := cleanupIdentityAt(entry.parent, entry.name)
	if err != nil {
		return fmt.Errorf("revalidate service artifact execution name %s: %w", entry.path, err)
	}
	if !fdIdentity.sameRegularFile(namedIdentity) {
		return fmt.Errorf("refuse service artifact execution: pathname changed for %s", entry.path)
	}
	if _, err := artifact.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if artifact.beforeFinalParentRevalidate != nil {
		if err := artifact.beforeFinalParentRevalidate(); err != nil {
			return fmt.Errorf(
				"run service artifact pre-final-chain test hook: %w",
				err,
			)
		}
	}
	if err := revalidateManagedCleanupDir(parent); err != nil {
		return fmt.Errorf(
			"refuse service artifact execution: parent identity changed "+
				"after file and name inspection for %s: %w",
			artifact.entry.path,
			err,
		)
	}
	return nil
}

func (plan *uninstallCleanupPlan) serviceArtifactEntry(
	kind string,
) (*cleanupManifestArtifact, *cleanupDirectoryPlan, *cleanupEntryPlan, bool, error) {
	if plan == nil {
		return nil, nil, nil, false, nil
	}
	var declared *cleanupManifestArtifact
	for index := range plan.manifest.Artifacts {
		artifact := &plan.manifest.Artifacts[index]
		if artifact.Kind != kind {
			continue
		}
		if declared != nil {
			return nil, nil, nil, false, fmt.Errorf(
				"duplicate service artifact kind %q",
				kind,
			)
		}
		declared = artifact
	}
	if declared == nil {
		return nil, nil, nil, false, nil
	}
	var matchedDirectory *cleanupDirectoryPlan
	var absenceDirectory *cleanupDirectoryPlan
	var matched *cleanupEntryPlan
	for _, directory := range plan.directories {
		if directory == nil {
			continue
		}
		if directory.absentServiceArtifactPath == declared.Path {
			if absenceDirectory != nil {
				return nil, nil, nil, false, fmt.Errorf(
					"duplicate held absence for service artifact %s",
					declared.Path,
				)
			}
			absenceDirectory = directory
		}
		for _, entry := range directory.entries {
			if filepath.Clean(entry.path) != filepath.Clean(declared.Path) {
				continue
			}
			if matched != nil {
				return nil, nil, nil, false, fmt.Errorf(
					"duplicate planned service artifact %s",
					declared.Path,
				)
			}
			matchedDirectory = directory
			matched = entry
		}
	}
	if matched == nil {
		return declared, absenceDirectory, nil, false, nil
	}
	if absenceDirectory != nil {
		return nil, nil, nil, false, fmt.Errorf(
			"service artifact %s is both present and held absent",
			declared.Path,
		)
	}
	if !matched.digestKnown || hex.EncodeToString(matched.digest[:]) != declared.SHA256 {
		return nil, nil, nil, false, fmt.Errorf(
			"planned service artifact %s lacks its declared digest",
			declared.Path,
		)
	}
	if matchedDirectory == nil || matchedDirectory.root == nil ||
		matched.parent != matchedDirectory.root.dir {
		return nil, nil, nil, false, fmt.Errorf(
			"planned service artifact %s lost its held parent directory",
			declared.Path,
		)
	}
	return declared, matchedDirectory, matched, true, nil
}

func (plan *uninstallCleanupPlan) openServiceArtifactForExecution(
	kind string,
) (*verifiedServiceArtifact, bool, error) {
	_, directory, entry, exists, err := plan.serviceArtifactEntry(kind)
	if err != nil || !exists {
		return nil, exists, err
	}
	file, identity, err := cleanupOpenFileAt(entry.parent, entry.name)
	if err != nil {
		return nil, false, err
	}
	if !entry.identity.sameRegularFile(identity) {
		_ = file.Close()
		return nil, false, fmt.Errorf(
			"refuse service artifact execution: identity changed while opening %s",
			entry.path,
		)
	}
	return &verifiedServiceArtifact{
		file:                        file,
		entry:                       entry,
		borrowedParent:              directory.root,
		beforeFinalParentRevalidate: plan.beforeServiceFinalChainCheck,
	}, true, nil
}

func (plan *uninstallCleanupPlan) openServiceArtifactAbsence(
	kind string,
) (*verifiedServiceArtifactAbsence, error) {
	declared, directory, _, exists, err := plan.serviceArtifactEntry(kind)
	if err != nil {
		return nil, err
	}
	if declared == nil {
		return nil, nil
	}
	absence := &verifiedServiceArtifactAbsence{
		path: declared.Path,
		name: filepath.Base(declared.Path),
	}
	if directory == nil || directory.root == nil {
		return nil, fmt.Errorf(
			"cleanup plan did not retain the parent chain for service artifact %s",
			declared.Path,
		)
	}
	if exists || directory.absentServiceArtifactPath == declared.Path {
		absence.parent = directory.root
		return absence, nil
	}
	return nil, fmt.Errorf(
		"cleanup plan retained an inconsistent absence for service artifact %s",
		declared.Path,
	)
}

func runSystemdManagerReloadAfterServiceArtifactRemoval(
	ctx context.Context,
	plan *uninstallCleanupPlan,
) (retErr error) {
	absence, err := plan.openServiceArtifactAbsence("systemd-unit")
	if err != nil {
		return err
	}
	if absence == nil {
		return nil
	}
	defer func() {
		if err := absence.close(); err != nil {
			retErr = errors.Join(
				retErr,
				fmt.Errorf("close verified systemd unit absence handles: %w", err),
			)
		}
	}()
	if err := absence.revalidate(); err != nil {
		return fmt.Errorf(
			"revalidate removed systemd unit before manager reload: %w",
			err,
		)
	}
	if err := runCommand(ctx, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := absence.revalidate(); err != nil {
		return fmt.Errorf(
			"revalidate removed systemd unit after manager reload: %w",
			err,
		)
	}
	return nil
}

func revalidateServiceArtifactBoundary(
	artifact *verifiedServiceArtifact,
	boundary string,
) error {
	if err := artifact.revalidateForExecution(); err != nil {
		return fmt.Errorf(
			"revalidate verified service artifact %s: %w",
			boundary,
			err,
		)
	}
	return nil
}

func runOpenWrtServiceActions(
	ctx context.Context,
	plan *uninstallCleanupPlan,
	actions ...string,
) (retErr error) {
	if err := plan.revalidate(); err != nil {
		return err
	}
	artifact, exists, err := plan.openServiceArtifactForExecution("openwrt-init")
	if err != nil || !exists {
		return err
	}
	defer func() {
		if err := artifact.close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close verified OpenWrt init script: %w", err))
		}
	}()
	for _, action := range actions {
		switch action {
		case "stop", "disable":
		default:
			return fmt.Errorf("refuse unsupported OpenWrt uninstall action %q", action)
		}
		if plan.beforeServiceExec != nil {
			if err := plan.beforeServiceExec(artifact.entry.path); err != nil {
				return err
			}
		}
		if err := revalidateServiceArtifactBoundary(
			artifact,
			fmt.Sprintf("after test hook and before OpenWrt %s", action),
		); err != nil {
			return err
		}
		var execErr error
		if plan.serviceActionExec != nil {
			execErr = plan.serviceActionExec(artifact.file, action)
		} else {
			execErr = runCommandFromVerifiedFile(ctx, artifact.file, action)
		}
		if execErr != nil {
			return execErr
		}
		if err := revalidateServiceArtifactBoundary(
			artifact,
			fmt.Sprintf("after OpenWrt %s", action),
		); err != nil {
			return err
		}
	}
	return nil
}

func runSystemdServiceActions(
	ctx context.Context,
	paths paths,
	plan *uninstallCleanupPlan,
	actions ...string,
) (retErr error) {
	for _, action := range actions {
		switch action {
		case "stop":
		default:
			return fmt.Errorf("refuse unsupported systemd uninstall action %q", action)
		}
	}
	if err := plan.revalidate(); err != nil {
		return err
	}
	artifact, exists, err := plan.openServiceArtifactForExecution("systemd-unit")
	if err != nil || !exists {
		return err
	}
	defer func() {
		if err := artifact.close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close verified systemd unit: %w", err))
		}
	}()
	for index, action := range actions {
		if plan.beforeServiceExec != nil {
			if err := plan.beforeServiceExec(artifact.entry.path); err != nil {
				return err
			}
		}
		if err := revalidateServiceArtifactBoundary(
			artifact,
			fmt.Sprintf("after test hook for systemd %s", action),
		); err != nil {
			return err
		}
		if index == 0 {
			if err := revalidateServiceArtifactBoundary(
				artifact,
				"before systemd manager reload",
			); err != nil {
				return err
			}
			if err := runCommand(ctx, "systemctl", "daemon-reload"); err != nil {
				return fmt.Errorf(
					"synchronize systemd manager with verified owned unit: %w",
					err,
				)
			}
			if err := revalidateServiceArtifactBoundary(
				artifact,
				"after systemd manager reload",
			); err != nil {
				return err
			}
		}
		if err := revalidateServiceArtifactBoundary(
			artifact,
			"before systemd manager inspection",
		); err != nil {
			return err
		}
		if err := verifySystemdServiceFragment(ctx, paths); err != nil {
			return err
		}
		if err := revalidateServiceArtifactBoundary(
			artifact,
			"after systemd manager inspection",
		); err != nil {
			return err
		}
		if err := revalidateServiceArtifactBoundary(
			artifact,
			fmt.Sprintf("before systemd %s", action),
		); err != nil {
			return err
		}
		if err := runCommand(ctx, "systemctl", action, "wg-mix-ebpf.service"); err != nil {
			return err
		}
		if err := revalidateServiceArtifactBoundary(
			artifact,
			fmt.Sprintf("after systemd %s", action),
		); err != nil {
			return err
		}
	}
	return nil
}

func openInstalledServiceArtifact(
	paths paths,
	system string,
	kind string,
) (*verifiedServiceArtifact, error) {
	specs, err := serviceArtifactInstallSpecs(paths, system)
	if err != nil {
		return nil, err
	}
	var selected *serviceArtifactInstallSpec
	for index := range specs {
		if specs[index].artifact.Kind == kind {
			selected = &specs[index]
			break
		}
	}
	if selected == nil {
		return nil, fmt.Errorf(
			"%s install manifest does not declare service artifact kind %q",
			system,
			kind,
		)
	}
	parent, exists, err := openDeclaredArtifactParent(
		filepath.Dir(selected.artifact.Path),
		selected.defaultParent,
	)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.Join(
			fmt.Errorf(
				"service artifact directory %s is missing",
				filepath.Dir(selected.artifact.Path),
			),
			parent.close(),
		)
	}
	file, identity, err := cleanupOpenFileAt(
		parent.dir,
		filepath.Base(selected.artifact.Path),
	)
	if err != nil {
		return nil, errors.Join(err, parent.close())
	}
	finalIdentity, err := validateServiceArtifactFile(
		parent.dir,
		filepath.Base(selected.artifact.Path),
		file,
		identity,
		*selected,
		false,
	)
	if err != nil {
		return nil, errors.Join(err, file.Close(), parent.close())
	}
	return &verifiedServiceArtifact{
		file: file,
		entry: &cleanupEntryPlan{
			parent:      parent.dir,
			path:        selected.artifact.Path,
			name:        filepath.Base(selected.artifact.Path),
			identity:    finalIdentity,
			digest:      sha256.Sum256(selected.content),
			digestKnown: true,
		},
		ownedParent: parent,
	}, nil
}

func runInstalledSystemdServiceCommit(
	ctx context.Context,
	paths paths,
	enable bool,
	allowExistingEnableLink bool,
	revalidateInstallMetadata func() error,
	publishInstallOwnership func() error,
) (retErr error) {
	artifact, err := openInstalledServiceArtifact(
		paths,
		"systemd",
		"systemd-unit",
	)
	if err != nil {
		return err
	}
	defer func() {
		if err := artifact.close(); err != nil {
			retErr = errors.Join(retErr, err)
		}
	}()
	revalidate := func(boundary string) error {
		if err := artifact.revalidateForExecution(); err != nil {
			return fmt.Errorf(
				"revalidate installed systemd unit %s: %w",
				boundary,
				err,
			)
		}
		return nil
	}
	revalidateMetadata := func(boundary string) error {
		if revalidateInstallMetadata == nil {
			return nil
		}
		if err := revalidateInstallMetadata(); err != nil {
			return fmt.Errorf(
				"revalidate install ownership %s: %w",
				boundary,
				err,
			)
		}
		return nil
	}
	if err := revalidate("before manager reload"); err != nil {
		return err
	}
	if err := revalidateMetadata("before manager reload"); err != nil {
		return err
	}
	if err := revalidate("immediately before manager reload"); err != nil {
		return err
	}
	if err := runCommand(ctx, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := revalidate("after manager reload"); err != nil {
		return err
	}
	if err := revalidateMetadata("after manager reload"); err != nil {
		return err
	}
	if err := revalidate("before manager inspection"); err != nil {
		return err
	}
	if err := verifySystemdServiceFragment(ctx, paths); err != nil {
		return err
	}
	if err := revalidate("after manager inspection"); err != nil {
		return err
	}
	if err := revalidateMetadata("after manager inspection"); err != nil {
		return err
	}
	if publishInstallOwnership == nil {
		return errors.New("systemd service commit requires an ownership publication callback")
	}
	if err := publishInstallOwnership(); err != nil {
		return fmt.Errorf("commit cleanup ownership before systemd enablement: %w", err)
	}
	if err := revalidate("after ownership publication"); err != nil {
		return err
	}
	if err := revalidateMetadata("after ownership publication"); err != nil {
		return err
	}
	if !enable {
		return nil
	}
	if err := revalidate("before enable"); err != nil {
		return err
	}
	if err := revalidateMetadata("before enable"); err != nil {
		return err
	}
	if err := revalidate("immediately before enable link transaction"); err != nil {
		return err
	}
	transactionHooks := systemdEnableLinkTransactionHooks{}
	if hook, ok := ctx.Value(
		installAfterSystemdEnableCommitWalkOpenHookContextKey{},
	).(func(string) error); ok && hook != nil {
		transactionHooks.afterCommitWalkOpen = hook
	}
	if hook, ok := ctx.Value(
		installAfterSystemdEnableRetentionCheckHookContextKey{},
	).(func(string) error); ok && hook != nil {
		transactionHooks.afterRetentionCheck = hook
	}
	transaction, err := beginSystemdEnableLinkTransaction(
		paths,
		allowExistingEnableLink,
		transactionHooks,
	)
	if err != nil {
		return err
	}
	defer func() {
		if retErr != nil {
			retErr = errors.Join(retErr, transaction.rollback())
		}
		retErr = errors.Join(retErr, transaction.close())
	}()
	if hook, ok := ctx.Value(installAfterSystemdEnableLinkHookContextKey{}).(func(string) error); ok && hook != nil {
		if err := hook(transaction.artifact.Path); err != nil {
			return fmt.Errorf("run post-systemd-enable-link hook: %w", err)
		}
	}
	if err := revalidate("after enable link creation"); err != nil {
		return err
	}
	if err := revalidateMetadata("after enable link creation"); err != nil {
		return err
	}
	if err := revalidate("immediately before enable link commit"); err != nil {
		return err
	}
	if err := transaction.commit(); err != nil {
		return fmt.Errorf("commit exact systemd enable link: %w", err)
	}
	return nil
}

func runInstalledOpenWrtServiceAction(
	ctx context.Context,
	paths paths,
	action string,
	revalidateInstallMetadata func() error,
) (retErr error) {
	artifact, err := openInstalledServiceArtifact(
		paths,
		"openwrt",
		"openwrt-init",
	)
	if err != nil {
		return err
	}
	defer func() {
		if err := artifact.close(); err != nil {
			retErr = errors.Join(retErr, err)
		}
	}()
	if err := artifact.revalidateForExecution(); err != nil {
		return err
	}
	if revalidateInstallMetadata != nil {
		if err := revalidateInstallMetadata(); err != nil {
			return fmt.Errorf(
				"revalidate install ownership before OpenWrt %s: %w",
				action,
				err,
			)
		}
	}
	if err := artifact.revalidateForExecution(); err != nil {
		return fmt.Errorf(
			"revalidate installed OpenWrt service immediately before %s: %w",
			action,
			err,
		)
	}
	if err := runCommandFromVerifiedFile(ctx, artifact.file, action); err != nil {
		return err
	}
	if err := artifact.revalidateForExecution(); err != nil {
		return fmt.Errorf(
			"revalidate installed OpenWrt service after %s: %w",
			action,
			err,
		)
	}
	if revalidateInstallMetadata != nil {
		if err := revalidateInstallMetadata(); err != nil {
			return fmt.Errorf(
				"revalidate install ownership after OpenWrt %s: %w",
				action,
				err,
			)
		}
	}
	return nil
}

func runCommandFromVerifiedFile(ctx context.Context, file *os.File, args ...string) error {
	executablePath := ""
	switch runtime.GOOS {
	case "linux":
		executablePath = "/proc/self/fd/3"
	default:
		return fmt.Errorf("verified file execution is unsupported on %s", runtime.GOOS)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, executablePath, args...)
	cmd.ExtraFiles = []*os.File{file}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf(
			"verified service artifact %s failed: %w: %s",
			strings.Join(args, " "),
			err,
			string(out),
		)
	}
	return nil
}
