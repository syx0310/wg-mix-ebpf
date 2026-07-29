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
	artifact      cleanupManifestArtifact
	content       []byte
	mode          os.FileMode
	defaultParent string
}

func serviceArtifactInstallSpecs(paths paths, system string) ([]serviceArtifactInstallSpec, error) {
	manifest := expectedCleanupManifest(paths, system, strings.Repeat("0", 32))
	specs := make([]serviceArtifactInstallSpec, 0, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
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

func installServiceArtifacts(paths paths, system string) error {
	specs, err := serviceArtifactInstallSpecs(paths, system)
	if err != nil {
		return err
	}
	for _, spec := range specs {
		if err := installServiceArtifact(spec); err != nil {
			return err
		}
	}
	return nil
}

func installServiceArtifact(spec serviceArtifactInstallSpec) (retErr error) {
	parent, err := openOrCreateDeclaredArtifactParent(
		filepath.Dir(spec.artifact.Path),
		spec.defaultParent,
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

	randomSuffix, err := newCleanupInstallationID()
	if err != nil {
		return err
	}
	tempName := "." + name + ".tmp-" + randomSuffix
	temp, err := cleanupCreateFileAt(parent.dir, tempName, uint32(spec.mode.Perm()))
	if err != nil {
		return fmt.Errorf("create temporary service artifact %s: %w", spec.artifact.Path, err)
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
				fmt.Errorf(
					"remove temporary service artifact %s/%s: %w",
					parent.spec.path,
					tempName,
					err,
				),
			)
		}
	}()
	if err := temp.Chmod(spec.mode.Perm()); err != nil {
		_ = temp.Close()
		return fmt.Errorf("set temporary service artifact mode: %w", err)
	}
	if _, err := temp.Write(spec.content); err != nil {
		_ = temp.Close()
		return fmt.Errorf("write temporary service artifact: %w", err)
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return fmt.Errorf("sync temporary service artifact: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close temporary service artifact: %w", err)
	}
	if err := cleanupRenameNoReplaceAt(parent.dir, tempName, name); err != nil {
		return fmt.Errorf(
			"atomically install service artifact %s without replacement: %w",
			spec.artifact.Path,
			err,
		)
	}
	tempPresent = false
	if err := parent.dir.file.Sync(); err != nil {
		return fmt.Errorf("sync service artifact directory %s: %w", parent.spec.path, err)
	}

	file, identity, err = cleanupOpenFileAt(parent.dir, name)
	if err != nil {
		return fmt.Errorf("open installed service artifact %s: %w", spec.artifact.Path, err)
	}
	defer file.Close()
	if _, err := validateServiceArtifactFile(
		parent.dir,
		name,
		file,
		identity,
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
	file        *os.File
	entry       *cleanupEntryPlan
	ownedParent *managedCleanupDir
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
	return errors.Join(errs...)
}

func (artifact *verifiedServiceArtifact) revalidateForExecution() error {
	if artifact == nil || artifact.file == nil || artifact.entry == nil {
		return errors.New("cannot execute an unverified service artifact")
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
	_, err = artifact.file.Seek(0, io.SeekStart)
	return err
}

func (plan *uninstallCleanupPlan) serviceArtifactEntry(
	kind string,
) (*cleanupManifestArtifact, *cleanupEntryPlan, bool, error) {
	if plan == nil {
		return nil, nil, false, nil
	}
	var declared *cleanupManifestArtifact
	for index := range plan.manifest.Artifacts {
		artifact := &plan.manifest.Artifacts[index]
		if artifact.Kind != kind {
			continue
		}
		if declared != nil {
			return nil, nil, false, fmt.Errorf("duplicate service artifact kind %q", kind)
		}
		declared = artifact
	}
	if declared == nil {
		return nil, nil, false, nil
	}
	var matched *cleanupEntryPlan
	for _, directory := range plan.directories {
		for _, entry := range directory.entries {
			if filepath.Clean(entry.path) != filepath.Clean(declared.Path) {
				continue
			}
			if matched != nil {
				return nil, nil, false, fmt.Errorf(
					"duplicate planned service artifact %s",
					declared.Path,
				)
			}
			matched = entry
		}
	}
	if matched == nil {
		return declared, nil, false, nil
	}
	if !matched.digestKnown || hex.EncodeToString(matched.digest[:]) != declared.SHA256 {
		return nil, nil, false, fmt.Errorf(
			"planned service artifact %s lacks its declared digest",
			declared.Path,
		)
	}
	return declared, matched, true, nil
}

func (plan *uninstallCleanupPlan) openServiceArtifactForExecution(
	kind string,
) (*verifiedServiceArtifact, bool, error) {
	_, entry, exists, err := plan.serviceArtifactEntry(kind)
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
	return &verifiedServiceArtifact{file: file, entry: entry}, true, nil
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
		if err := artifact.revalidateForExecution(); err != nil {
			return err
		}
		if err := runCommandFromVerifiedFile(ctx, artifact.file, action); err != nil {
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
		case "stop", "disable":
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
		if err := artifact.revalidateForExecution(); err != nil {
			return err
		}
		if index == 0 {
			if err := runCommand(ctx, "systemctl", "daemon-reload"); err != nil {
				return fmt.Errorf(
					"synchronize systemd manager with verified owned unit: %w",
					err,
				)
			}
			if err := artifact.revalidateForExecution(); err != nil {
				return fmt.Errorf(
					"revalidate owned systemd unit after manager reload: %w",
					err,
				)
			}
		}
		if err := verifySystemdServiceFragment(ctx, paths); err != nil {
			return err
		}
		if err := artifact.revalidateForExecution(); err != nil {
			return fmt.Errorf(
				"revalidate owned systemd unit after manager inspection: %w",
				err,
			)
		}
		if err := runCommand(ctx, "systemctl", action, "wg-mix-ebpf.service"); err != nil {
			return err
		}
	}
	return nil
}

func runInstalledOpenWrtServiceAction(
	ctx context.Context,
	paths paths,
	action string,
) (retErr error) {
	specs, err := serviceArtifactInstallSpecs(paths, "openwrt")
	if err != nil {
		return err
	}
	var initSpec *serviceArtifactInstallSpec
	for index := range specs {
		if specs[index].artifact.Kind == "openwrt-init" {
			initSpec = &specs[index]
			break
		}
	}
	if initSpec == nil {
		return errors.New("OpenWrt install manifest does not declare its init script")
	}
	parent, exists, err := openDeclaredArtifactParent(
		filepath.Dir(initSpec.artifact.Path),
		initSpec.defaultParent,
	)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("OpenWrt init script directory %s is missing", filepath.Dir(initSpec.artifact.Path))
	}
	file, identity, err := cleanupOpenFileAt(parent.dir, filepath.Base(initSpec.artifact.Path))
	if err != nil {
		_ = parent.close()
		return err
	}
	finalIdentity, err := validateServiceArtifactFile(
		parent.dir,
		filepath.Base(initSpec.artifact.Path),
		file,
		identity,
		*initSpec,
		false,
	)
	if err != nil {
		_ = file.Close()
		_ = parent.close()
		return err
	}
	artifact := &verifiedServiceArtifact{
		file: file,
		entry: &cleanupEntryPlan{
			parent:      parent.dir,
			path:        initSpec.artifact.Path,
			name:        filepath.Base(initSpec.artifact.Path),
			identity:    finalIdentity,
			digest:      sha256.Sum256(initSpec.content),
			digestKnown: true,
		},
		ownedParent: parent,
	}
	defer func() {
		if err := artifact.close(); err != nil {
			retErr = errors.Join(retErr, err)
		}
	}()
	if err := artifact.revalidateForExecution(); err != nil {
		return err
	}
	return runCommandFromVerifiedFile(ctx, artifact.file, action)
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
