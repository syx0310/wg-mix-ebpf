package install

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/syx0310/wg-mix-ebpf/internal/attachstate"
	"github.com/syx0310/wg-mix-ebpf/internal/config"
	"github.com/syx0310/wg-mix-ebpf/internal/daemon"
	"github.com/syx0310/wg-mix-ebpf/internal/lockfile"
)

const maxManagedCleanupFileSize = 4 << 20

type managedCleanupDir struct {
	spec                  cleanupPathSpec
	parent                *cleanupDirFD
	dir                   *cleanupDirFD
	name                  string
	identity              cleanupIdentity
	declaredChain         []*cleanupDirFD
	declaredEdges         []string
	declaredCanonicalRoot string
	declaredCanonicalPath string
	declaredRootDepth     int
}

func (dir *managedCleanupDir) close() error {
	if dir == nil {
		return nil
	}
	if len(dir.declaredChain) != 0 {
		err := closeCleanupDirFDChain(dir.declaredChain)
		dir.declaredChain = nil
		dir.declaredEdges = nil
		dir.declaredCanonicalRoot = ""
		dir.declaredCanonicalPath = ""
		dir.declaredRootDepth = 0
		dir.parent = nil
		dir.dir = nil
		return err
	}
	return errors.Join(dir.dir.close(), dir.parent.close())
}

func closeCleanupDirFDChain(chain []*cleanupDirFD) error {
	var errs []error
	for index := len(chain) - 1; index >= 0; index-- {
		errs = append(errs, chain[index].close())
	}
	return errors.Join(errs...)
}

type managedDirOpenOptions struct {
	identityHook func(string, *cleanupIdentity)
}

func openManagedCleanupDir(spec cleanupPathSpec) (*managedCleanupDir, bool, error) {
	return openManagedCleanupDirWithOptions(spec, managedDirOpenOptions{})
}

func createFreshManagedCleanupDir(spec cleanupPathSpec) (*managedCleanupDir, error) {
	anchor, err := managedCleanupAnchor(spec)
	if err != nil {
		return nil, err
	}
	relative, err := filepath.Rel(anchor, spec.path)
	if err != nil || relative == "." || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return nil, fmt.Errorf("refuse %s %s outside managed root %s", spec.name, spec.path, anchor)
	}
	components := strings.Split(relative, string(os.PathSeparator))
	current, err := cleanupOpenAnchor(anchor)
	if err != nil {
		return nil, fmt.Errorf("open managed root %s for fresh %s: %w", anchor, spec.name, err)
	}
	anchorIdentity := current.identity
	owner := uint32(os.Geteuid())
	if filepath.Clean(anchor) != filepath.Clean(os.TempDir()) {
		if err := anchorIdentity.validateDirectory(anchor, owner); err != nil {
			_ = current.close()
			return nil, err
		}
	}

	for index, component := range components {
		final := index == len(components)-1
		child, openErr := cleanupOpenDirAt(current, component)
		if final && openErr == nil {
			_ = child.close()
			_ = current.close()
			return nil, fmt.Errorf("refuse pre-existing fresh %s %s", spec.name, spec.path)
		}
		if final && cleanupIsNotExist(openErr) {
			if err := cleanupMkdirAt(current, component, 0o755); err != nil {
				_ = current.close()
				return nil, fmt.Errorf("exclusively create fresh %s %s: %w", spec.name, spec.path, err)
			}
			if err := current.file.Sync(); err != nil {
				_ = current.close()
				return nil, fmt.Errorf(
					"sync parent after creating fresh %s %s: %w",
					spec.name,
					spec.path,
					err,
				)
			}
			child, openErr = cleanupOpenDirAt(current, component)
		}
		if openErr != nil {
			_ = current.close()
			if final {
				return nil, fmt.Errorf("refuse pre-existing or unsafe fresh %s %s: %w", spec.name, spec.path, openErr)
			}
			return nil, fmt.Errorf("open fresh %s component %s: %w", spec.name, component, openErr)
		}
		if !child.identity.sameMount(anchorIdentity) {
			_ = child.close()
			_ = current.close()
			return nil, fmt.Errorf(
				"refuse fresh %s %s: component %s crosses a mount boundary",
				spec.name,
				spec.path,
				child.path,
			)
		}
		if err := child.identity.validateDirectory(child.path, owner); err != nil {
			_ = child.close()
			_ = current.close()
			return nil, err
		}
		if final {
			return &managedCleanupDir{
				spec:     spec,
				parent:   current,
				dir:      child,
				name:     component,
				identity: child.identity,
			}, nil
		}
		_ = current.close()
		current = child
	}
	_ = current.close()
	return nil, fmt.Errorf("refuse empty relative path for fresh %s %s", spec.name, spec.path)
}

func revalidateManagedCleanupDir(dir *managedCleanupDir) error {
	if dir == nil || dir.parent == nil || dir.dir == nil || dir.dir.file == nil {
		return errors.New("cannot revalidate an unheld managed directory")
	}
	if len(dir.declaredChain) != 0 {
		return revalidateDeclaredDirectoryChain(dir)
	}
	heldIdentity, err := cleanupIdentityForFD(int(dir.dir.file.Fd()))
	if err != nil {
		return fmt.Errorf("inspect held %s %s: %w", dir.spec.name, dir.spec.path, err)
	}
	if !dir.identity.sameDirectory(heldIdentity) {
		return fmt.Errorf("refuse %s %s: held directory identity changed", dir.spec.name, dir.spec.path)
	}
	namedIdentity, err := cleanupIdentityAt(dir.parent, dir.name)
	if err != nil {
		return fmt.Errorf("revalidate %s pathname %s: %w", dir.spec.name, dir.spec.path, err)
	}
	if !heldIdentity.sameDirectory(namedIdentity) {
		return fmt.Errorf("refuse %s %s: pathname no longer names the held directory", dir.spec.name, dir.spec.path)
	}
	return nil
}

func revalidateDeclaredDirectoryChain(dir *managedCleanupDir) (retErr error) {
	if dir == nil || len(dir.declaredChain) < 2 ||
		len(dir.declaredEdges)+1 != len(dir.declaredChain) ||
		dir.declaredRootDepth < 0 ||
		dir.declaredRootDepth > len(dir.declaredEdges) ||
		dir.declaredCanonicalRoot == "" ||
		dir.declaredCanonicalPath == "" {
		return errors.New("cannot revalidate an incomplete declared directory chain")
	}
	last := len(dir.declaredChain) - 1
	if dir.parent != dir.declaredChain[last-1] ||
		dir.dir != dir.declaredChain[last] ||
		dir.name != dir.declaredEdges[last-1] {
		return errors.New("declared directory chain lost its final parent edge")
	}
	if err := revalidateDeclaredCanonicalRoot(dir); err != nil {
		return err
	}

	kernelRoot := string(os.PathSeparator)
	reopenedAnchor, err := cleanupOpenAnchor(kernelRoot)
	if err != nil {
		return fmt.Errorf(
			"reopen kernel root for declared directory %s: %w",
			dir.spec.path,
			err,
		)
	}
	defer func() {
		if err := reopenedAnchor.close(); err != nil {
			retErr = errors.Join(
				retErr,
				fmt.Errorf("close reopened kernel root for %s: %w", dir.spec.path, err),
			)
		}
	}()
	if !dir.declaredChain[0].identity.sameDirectory(reopenedAnchor.identity) {
		return fmt.Errorf(
			"refuse declared directory %s: kernel root identity changed",
			dir.spec.path,
		)
	}

	for index, held := range dir.declaredChain {
		if held == nil || held.file == nil {
			return fmt.Errorf(
				"refuse declared directory %s: component %d is no longer held",
				dir.spec.path,
				index,
			)
		}
		heldIdentity, err := cleanupIdentityForFD(int(held.file.Fd()))
		if err != nil {
			return fmt.Errorf(
				"inspect held declared directory component %s: %w",
				held.path,
				err,
			)
		}
		if !held.identity.sameDirectory(heldIdentity) {
			return fmt.Errorf(
				"refuse declared directory %s: held component identity changed at %s",
				dir.spec.path,
				held.path,
			)
		}
		if index == 0 {
			continue
		}
		namedIdentity, err := declaredDirectoryEdgeIdentity(dir, index-1)
		if err != nil {
			return fmt.Errorf(
				"revalidate declared directory edge %s: %w",
				held.path,
				err,
			)
		}
		if !heldIdentity.sameDirectory(namedIdentity) {
			return fmt.Errorf(
				"refuse declared directory %s: parent edge no longer names held component %s",
				dir.spec.path,
				held.path,
			)
		}
	}
	if err := revalidateDeclaredCanonicalRoot(dir); err != nil {
		return err
	}
	return nil
}

func declaredDirectoryEdgeIdentity(
	dir *managedCleanupDir,
	edgeIndex int,
) (cleanupIdentity, error) {
	parent := dir.declaredChain[edgeIndex]
	name := dir.declaredEdges[edgeIndex]
	if !declaredDirectoryEdgeMayCrossMount(edgeIndex, dir.declaredRootDepth) {
		return cleanupIdentityAt(parent, name)
	}
	child, err := cleanupOpenDirAtAllowMount(parent, name)
	if err != nil {
		return cleanupIdentity{}, err
	}
	identity := child.identity
	if err := child.close(); err != nil {
		return cleanupIdentity{}, err
	}
	return identity, nil
}

func declaredDirectoryEdgeMayCrossMount(edgeIndex int, rootDepth int) bool {
	// The canonical walk from the kernel root through systemRoot may contain
	// ordinary system mount transitions such as a separate /usr or /etc.
	// Once systemRoot is reached, the artifact-relative subtree remains on
	// that fixed mount.
	return edgeIndex >= 0 && edgeIndex < rootDepth
}

func revalidateDeclaredCanonicalRoot(dir *managedCleanupDir) error {
	canonicalRoot, err := filepath.EvalSymlinks(dir.spec.systemRoot)
	if err != nil {
		return fmt.Errorf(
			"resolve declared root %s during revalidation: %w",
			dir.spec.systemRoot,
			err,
		)
	}
	canonicalRoot = filepath.Clean(canonicalRoot)
	if canonicalRoot != dir.declaredCanonicalRoot {
		return fmt.Errorf(
			"refuse declared directory %s: canonical root changed from %s to %s",
			dir.spec.path,
			dir.declaredCanonicalRoot,
			canonicalRoot,
		)
	}
	relative, err := filepath.Rel(dir.spec.systemRoot, dir.spec.path)
	if err != nil {
		return fmt.Errorf("recompute declared path relative to canonical root: %w", err)
	}
	if filepath.Clean(filepath.Join(canonicalRoot, relative)) !=
		dir.declaredCanonicalPath {
		return fmt.Errorf(
			"refuse declared directory %s: canonical target path changed",
			dir.spec.path,
		)
	}
	return nil
}

func compareDeclaredDirectoryChains(
	held *managedCleanupDir,
	reopened *managedCleanupDir,
) error {
	if held == nil || reopened == nil ||
		len(held.declaredChain) == 0 ||
		len(held.declaredChain) != len(reopened.declaredChain) ||
		len(held.declaredEdges) != len(reopened.declaredEdges) {
		return errors.New("declared directory walks produced different chain lengths")
	}
	if held.spec.path != reopened.spec.path ||
		held.spec.systemRoot != reopened.spec.systemRoot ||
		held.declaredCanonicalRoot != reopened.declaredCanonicalRoot ||
		held.declaredCanonicalPath != reopened.declaredCanonicalPath ||
		held.declaredRootDepth != reopened.declaredRootDepth {
		return errors.New("declared directory walks used different roots")
	}
	for index := range held.declaredChain {
		if index > 0 &&
			held.declaredEdges[index-1] != reopened.declaredEdges[index-1] {
			return fmt.Errorf(
				"declared directory walks used different edge %d",
				index,
			)
		}
		heldIdentity, err := cleanupIdentityForFD(
			int(held.declaredChain[index].file.Fd()),
		)
		if err != nil {
			return fmt.Errorf(
				"inspect held declared chain component %s: %w",
				held.declaredChain[index].path,
				err,
			)
		}
		reopenedIdentity, err := cleanupIdentityForFD(
			int(reopened.declaredChain[index].file.Fd()),
		)
		if err != nil {
			return fmt.Errorf(
				"inspect reopened declared chain component %s: %w",
				reopened.declaredChain[index].path,
				err,
			)
		}
		if !held.declaredChain[index].identity.sameDirectory(heldIdentity) ||
			!reopened.declaredChain[index].identity.sameDirectory(reopenedIdentity) ||
			!heldIdentity.sameDirectory(reopenedIdentity) {
			return fmt.Errorf(
				"declared path no longer reaches the held component %s",
				held.declaredChain[index].path,
			)
		}
	}
	return nil
}

func openManagedCleanupDirWithOptions(
	spec cleanupPathSpec,
	options managedDirOpenOptions,
) (*managedCleanupDir, bool, error) {
	anchor, err := managedCleanupAnchor(spec)
	if err != nil {
		return nil, false, err
	}
	relative, err := filepath.Rel(anchor, spec.path)
	if err != nil || relative == "." || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return nil, false, fmt.Errorf("refuse %s %s outside managed root %s", spec.name, spec.path, anchor)
	}
	components := strings.Split(relative, string(os.PathSeparator))
	current, err := cleanupOpenAnchor(anchor)
	if err != nil {
		return nil, false, fmt.Errorf("open managed root %s for %s: %w", anchor, spec.name, err)
	}
	anchorIdentity := current.identity
	owner := uint32(os.Geteuid())
	if filepath.Clean(anchor) != filepath.Clean(os.TempDir()) {
		if err := anchorIdentity.validateDirectory(anchor, owner); err != nil {
			_ = current.close()
			return nil, false, err
		}
	}

	for index, component := range components {
		child, err := cleanupOpenDirAt(current, component)
		if cleanupIsNotExist(err) {
			_ = current.close()
			return nil, false, nil
		}
		if err != nil {
			_ = current.close()
			return nil, false, fmt.Errorf("open %s component %s: %w", spec.name, component, err)
		}
		if options.identityHook != nil {
			options.identityHook(child.path, &child.identity)
		}
		if !child.identity.sameMount(anchorIdentity) {
			_ = child.close()
			_ = current.close()
			return nil, false, fmt.Errorf(
				"refuse %s %s: component %s crosses a mount boundary",
				spec.name,
				spec.path,
				child.path,
			)
		}
		if err := child.identity.validateDirectory(child.path, owner); err != nil {
			_ = child.close()
			_ = current.close()
			return nil, false, err
		}
		if index == len(components)-1 {
			return &managedCleanupDir{
				spec:     spec,
				parent:   current,
				dir:      child,
				name:     component,
				identity: child.identity,
			}, true, nil
		}
		_ = current.close()
		current = child
	}
	_ = current.close()
	return nil, false, fmt.Errorf("refuse empty relative path for %s %s", spec.name, spec.path)
}

func managedCleanupAnchor(spec cleanupPathSpec) (string, error) {
	if spec.path == "" || !filepath.IsAbs(spec.path) {
		return "", fmt.Errorf("refuse unsafe %s %q", spec.name, spec.path)
	}
	if cleaned := filepath.Clean(spec.path); cleaned != spec.path {
		return "", fmt.Errorf("refuse non-clean %s %q", spec.name, spec.path)
	}
	if !validManagedCleanupBase(filepath.Base(spec.path)) {
		return "", fmt.Errorf(
			"refuse unsafe %s %s: basename must be %q or its bounded suffix form",
			spec.name,
			spec.path,
			managedCleanupBase,
		)
	}
	systemRoot := filepath.Clean(spec.systemRoot)
	tempRoot := filepath.Clean(os.TempDir())
	switch {
	case spec.path == filepath.Clean(spec.defaultPath):
		return systemRoot, nil
	case filepath.Dir(spec.path) == systemRoot:
		return systemRoot, nil
	case spec.path != tempRoot && pathContains(tempRoot, spec.path):
		return tempRoot, nil
	}
	if physicalTempRoot, err := filepath.EvalSymlinks(tempRoot); err == nil {
		physicalTempRoot = filepath.Clean(physicalTempRoot)
		if spec.path != physicalTempRoot && pathContains(physicalTempRoot, spec.path) {
			return physicalTempRoot, nil
		}
	}
	return "", fmt.Errorf("refuse %s outside its project-managed roots: %s", spec.name, spec.path)
}

type cleanupEntryPlan struct {
	parent        *cleanupDirFD
	dir           *cleanupDirFD
	path          string
	name          string
	identity      cleanupIdentity
	directory     bool
	symlink       bool
	symlinkTarget string
	digest        [sha256.Size]byte
	digestKnown   bool
	mayDisappear  bool
	remove        bool
	children      []*cleanupEntryPlan
}

func (entry *cleanupEntryPlan) close() error {
	if entry == nil {
		return nil
	}
	var errs []error
	for _, child := range entry.children {
		errs = append(errs, child.close())
	}
	if entry.dir != nil {
		errs = append(errs, entry.dir.close())
		entry.dir = nil
	}
	return errors.Join(errs...)
}

type cleanupDirectoryPlan struct {
	root             *managedCleanupDir
	entries          []*cleanupEntryPlan
	strictEntries    bool
	removeRoot       bool
	rootMayDisappear bool
}

func (directory *cleanupDirectoryPlan) close() error {
	if directory == nil {
		return nil
	}
	var errs []error
	for _, entry := range directory.entries {
		errs = append(errs, entry.close())
	}
	errs = append(errs, directory.root.close())
	return errors.Join(errs...)
}

type uninstallCleanupPlan struct {
	directories       []*cleanupDirectoryPlan
	manifest          cleanupManifest
	beforeExecute     func() error
	beforeQuarantine  func(string) error
	beforeServiceExec func(string) error
}

func (plan *uninstallCleanupPlan) close() error {
	if plan == nil {
		return nil
	}
	var errs []error
	for _, directory := range plan.directories {
		errs = append(errs, directory.close())
	}
	return errors.Join(errs...)
}

func prepareUninstallCleanup(
	paths paths,
	system string,
	purge bool,
	lifecyclePath string,
) (*uninstallCleanupPlan, error) {
	if err := validateCleanupPaths(paths); err != nil {
		return nil, err
	}
	if purge {
		if err := validatePurgeDir(paths); err != nil {
			return nil, err
		}
	}

	configRoot, exists, err := openManagedCleanupDir(configCleanupPath(filepath.Dir(paths.ConfigPath)))
	if err != nil {
		return nil, err
	}
	if !exists {
		if cleanupResourcesExist(paths, system) {
			return nil, errors.New(
				"refuse uninstall cleanup without an ownership manifest; rerun install to establish ownership",
			)
		}
		return &uninstallCleanupPlan{}, nil
	}

	manifest, _, err := readCleanupManifestFromDir(configRoot.dir)
	if err != nil {
		_ = configRoot.close()
		if cleanupIsNotExist(err) {
			return nil, errors.New(
				"refuse uninstall cleanup without an ownership manifest; rerun install to establish ownership",
			)
		}
		return nil, err
	}
	if err := manifest.validateAgainst(paths, system); err != nil {
		_ = configRoot.close()
		return nil, err
	}
	plan := &uninstallCleanupPlan{manifest: *manifest}
	fail := func(err error) (*uninstallCleanupPlan, error) {
		_ = configRoot.close()
		_ = plan.close()
		return nil, err
	}

	configPlan, err := prepareConfigDirectoryPlan(configRoot, *manifest, purge)
	if err != nil {
		return fail(err)
	}
	plan.directories = append(plan.directories, configPlan)

	runtimePlan, err := prepareRuntimeDirectoryPlan(paths.RunDir, *manifest, lifecyclePath)
	if err != nil {
		return fail(err)
	}
	if runtimePlan != nil {
		plan.directories = append(plan.directories, runtimePlan)
	}

	statePlan, err := prepareStateDirectoryPlan(paths.VarLibDir, *manifest)
	if err != nil {
		return fail(err)
	}
	if statePlan != nil {
		plan.directories = append(plan.directories, statePlan)
	}

	pinPlan, err := preparePinDirectoryPlan(paths.PinPath)
	if err != nil {
		return fail(err)
	}
	if pinPlan != nil {
		plan.directories = append(plan.directories, pinPlan)
	}

	artifactPlans, err := prepareArtifactPlans(*manifest)
	if err != nil {
		return fail(err)
	}
	plan.directories = append(plan.directories, artifactPlans...)

	// Keep the config directory, which owns the manifest, until every other
	// target has completed. This also keeps repeated non-purge uninstall safe.
	sort.SliceStable(plan.directories, func(i, j int) bool {
		leftConfig := plan.directories[i].root.spec.name == "config dir"
		rightConfig := plan.directories[j].root.spec.name == "config dir"
		return !leftConfig && rightConfig
	})
	return plan, nil
}

func cleanupResourcesExist(paths paths, system string) bool {
	candidates := []string{
		paths.VarLibDir,
		paths.PinPath,
		paths.ConfigPath,
	}
	switch system {
	case "systemd":
		candidates = append(
			candidates,
			filepath.Join(paths.SystemdDir, "wg-mix-ebpf.service"),
			systemdEnableLinkPath(paths),
		)
	case "openwrt":
		candidates = append(
			candidates,
			filepath.Join(paths.OpenWrtInitDir, "wg-mix-ebpf"),
			filepath.Join(paths.OpenWrtHotplugDir, "90-wg-mix-ebpf"),
		)
	}
	for _, candidate := range candidates {
		if _, err := os.Lstat(candidate); err == nil || !cleanupIsNotExist(err) {
			return true
		}
	}
	return runtimeCleanupResourcesExist(paths.RunDir)
}

func installOwnershipResourcesExist(paths paths, system string) bool {
	if _, err := os.Lstat(paths.BinaryPath); err == nil || !cleanupIsNotExist(err) {
		return true
	}
	return cleanupResourcesExist(paths, system)
}

func runtimeCleanupResourcesExist(runDir string) bool {
	if _, err := os.Lstat(runDir); cleanupIsNotExist(err) {
		return false
	} else if err != nil {
		return true
	}
	root, exists, err := openManagedCleanupDir(runtimeCleanupPath(runDir))
	if err != nil {
		return true
	}
	if !exists {
		return false
	}
	entries, err := cleanupReadDir(root.dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "daemon.lease" {
		_ = root.close()
		return true
	}
	node, err := snapshotManagedFile(
		root.dir,
		"daemon.lease",
		false,
		false,
		validateLifecycleLeaseBytes(cleanupManifest{RunDir: runDir}),
	)
	if err != nil {
		_ = root.close()
		return true
	}
	if node.identity.Mode&0o7777 != 0o600 {
		_ = node.close()
		_ = root.close()
		return true
	}
	return errors.Join(node.close(), root.close()) != nil
}

func prepareConfigDirectoryPlan(
	root *managedCleanupDir,
	manifest cleanupManifest,
	purge bool,
) (*cleanupDirectoryPlan, error) {
	plan := &cleanupDirectoryPlan{
		root:          root,
		strictEntries: purge,
		removeRoot:    purge,
	}
	entries, err := cleanupReadDir(root.dir)
	if err != nil {
		return nil, fmt.Errorf("read config directory %s: %w", root.spec.path, err)
	}
	for _, entry := range entries {
		switch entry.Name() {
		case cleanupManifestName:
			node, err := snapshotManagedFile(root.dir, entry.Name(), false, false, validateManifestBytes(manifest))
			if err != nil {
				return nil, err
			}
			node.remove = purge
			plan.entries = append(plan.entries, node)
		case filepath.Base(manifest.ConfigPath):
			node, err := snapshotManagedFile(root.dir, entry.Name(), false, false, validateConfigBytes)
			if err != nil {
				return nil, err
			}
			// Stop/detach consumes the retained config even without --purge,
			// so it remains part of the globally validated target set.
			node.remove = purge
			plan.entries = append(plan.entries, node)
		default:
			if purge {
				return nil, fmt.Errorf("refuse to remove unknown config entry %s", filepath.Join(root.spec.path, entry.Name()))
			}
		}
	}
	if !containsCleanupEntry(plan.entries, cleanupManifestName) {
		return nil, errors.New("cleanup ownership manifest disappeared during preflight")
	}
	sort.SliceStable(plan.entries, func(i, j int) bool {
		return plan.entries[i].name != cleanupManifestName &&
			plan.entries[j].name == cleanupManifestName
	})
	return plan, nil
}

func validateCleanupManifestBootstrap(
	configRoot *managedCleanupDir,
	paths paths,
	system string,
	installationID string,
) error {
	manifest := expectedCleanupManifest(paths, system, installationID)
	if _, err := validateInstallBinaryTarget(paths.BinaryPath, false); err != nil {
		return fmt.Errorf("refuse install binary ownership: %w", err)
	}
	if configRoot != nil {
		entries, err := cleanupReadDir(configRoot.dir)
		if err != nil {
			return fmt.Errorf("read unmarked config directory before ownership adoption: %w", err)
		}
		for _, entry := range entries {
			if entry.Name() != filepath.Base(paths.ConfigPath) {
				return fmt.Errorf(
					"refuse to adopt unmarked config directory with unknown entry %s",
					filepath.Join(configRoot.spec.path, entry.Name()),
				)
			}
			node, err := snapshotManagedFile(
				configRoot.dir,
				entry.Name(),
				false,
				false,
				validateConfigBytes,
			)
			if err != nil {
				return fmt.Errorf("refuse to adopt unmarked config file: %w", err)
			}
			_ = node.close()
		}
	}

	var plans []*cleanupDirectoryPlan
	closePlans := func() {
		closeCleanupDirectoryPlans(plans)
	}
	defer closePlans()

	runtimePlan, err := prepareRuntimeDirectoryPlan(
		paths.RunDir,
		manifest,
		lockfile.DefaultLifecycleLeasePath,
	)
	if err != nil {
		return fmt.Errorf("refuse to adopt unmarked runtime directory: %w", err)
	}
	if runtimePlan != nil {
		plans = append(plans, runtimePlan)
	}
	statePlan, err := prepareStateDirectoryPlan(paths.VarLibDir, manifest)
	if err != nil {
		return fmt.Errorf("refuse to adopt unmarked state directory: %w", err)
	}
	if statePlan != nil {
		plans = append(plans, statePlan)
	}
	pinPlan, err := preparePinDirectoryPlan(paths.PinPath)
	if err != nil {
		return fmt.Errorf("refuse to adopt unmarked BPF pin directory: %w", err)
	}
	if pinPlan != nil {
		plans = append(plans, pinPlan)
	}
	artifactPlans, err := prepareArtifactPlans(manifest)
	if err != nil {
		return fmt.Errorf("refuse to adopt unmarked service artifact: %w", err)
	}
	plans = append(plans, artifactPlans...)
	return nil
}

func validateUnmarkedCleanupResources(paths paths, system string) (retErr error) {
	configRoot, exists, err := openManagedCleanupDir(
		configCleanupPath(filepath.Dir(paths.ConfigPath)),
	)
	if err != nil {
		return err
	}
	if exists {
		defer func() {
			if err := configRoot.close(); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("close unmarked config validation handles: %w", err))
			}
		}()
	} else {
		configRoot = nil
	}
	return validateCleanupManifestBootstrap(
		configRoot,
		paths,
		system,
		strings.Repeat("0", 32),
	)
}

func inspectLockedInstallOwnership(
	paths paths,
	system string,
	initial cleanupOwnershipState,
	adoptExisting bool,
	lifecyclePath string,
	lease *lockfile.LifecycleLease,
) (cleanupOwnershipState, error) {
	if lease == nil || !lease.HeldAt(lifecyclePath) {
		return cleanupOwnershipAbsent, errors.New(
			"refuse install ownership decision without the held global lifecycle lease",
		)
	}
	current, err := inspectInstallCleanupOwnership(paths, system)
	if err != nil {
		return cleanupOwnershipAbsent, err
	}
	switch initial {
	case cleanupOwnershipAbsent:
		if err := validateFreshLockedInstallResources(
			paths,
			system,
			lifecyclePath,
		); err != nil {
			return cleanupOwnershipAbsent, fmt.Errorf(
				"refuse fresh install after resources appeared between preflight and lifecycle lock: %w",
				err,
			)
		}
		return cleanupOwnershipAbsent, nil
	case cleanupOwnershipMarked:
		if current != cleanupOwnershipMarked {
			return cleanupOwnershipAbsent, errors.New(
				"refuse install because cleanup ownership changed after lifecycle preflight",
			)
		}
		return cleanupOwnershipMarked, nil
	case cleanupOwnershipUnmarked:
		if !adoptExisting {
			return cleanupOwnershipAbsent, errors.New(
				"refuse to adopt unmarked installation resources without explicit authorization",
			)
		}
		if current != cleanupOwnershipUnmarked {
			return cleanupOwnershipAbsent, errors.New(
				"refuse adoption because cleanup ownership changed after lifecycle preflight",
			)
		}
		if err := validateUnmarkedCleanupResources(paths, system); err != nil {
			return cleanupOwnershipAbsent, fmt.Errorf(
				"revalidate explicitly adopted installation resources under lifecycle lock: %w",
				err,
			)
		}
		return cleanupOwnershipUnmarked, nil
	default:
		return cleanupOwnershipAbsent, fmt.Errorf(
			"refuse unknown install ownership state %d",
			initial,
		)
	}
}

func validateFreshLockedInstallResources(
	paths paths,
	system string,
	lifecyclePath string,
) error {
	configRoot, exists, err := openManagedCleanupDir(
		configCleanupPath(filepath.Dir(paths.ConfigPath)),
	)
	if err != nil {
		return err
	}
	if exists {
		closeErr := configRoot.close()
		return errors.Join(
			fmt.Errorf(
				"config directory %s already exists",
				filepath.Dir(paths.ConfigPath),
			),
			closeErr,
		)
	}
	return validateFreshCleanupManifestBootstrap(
		nil,
		paths,
		system,
		strings.Repeat("0", 32),
		lifecyclePath,
	)
}

func validateFreshCleanupManifestBootstrap(
	configRoot *managedCleanupDir,
	paths paths,
	system string,
	installationID string,
	lifecyclePath string,
) error {
	manifest := expectedCleanupManifest(paths, system, installationID)
	if exists, err := validateInstallBinaryTarget(paths.BinaryPath, false); err != nil {
		return fmt.Errorf("validate fresh install binary target: %w", err)
	} else if exists {
		return fmt.Errorf("fresh install binary %s already exists", paths.BinaryPath)
	}
	if configRoot != nil {
		entries, err := cleanupReadDir(configRoot.dir)
		if err != nil {
			return fmt.Errorf("read fresh config directory before ownership creation: %w", err)
		}
		if len(entries) != 0 {
			return fmt.Errorf(
				"fresh config directory %s is not empty",
				configRoot.spec.path,
			)
		}
	}
	for _, spec := range []cleanupPathSpec{
		stateCleanupPath(paths.VarLibDir),
		bpfPinCleanupPath(paths.PinPath),
	} {
		root, exists, err := openManagedCleanupDir(spec)
		if err != nil {
			return err
		}
		if !exists {
			continue
		}
		closeErr := root.close()
		return errors.Join(
			fmt.Errorf("fresh %s %s already exists", spec.name, spec.path),
			closeErr,
		)
	}
	if err := validateFreshRuntimeDirectory(paths.RunDir, manifest, lifecyclePath); err != nil {
		return err
	}
	if err := validateFreshServiceArtifactsAbsent(manifest); err != nil {
		return err
	}
	return nil
}

func validateFreshRuntimeDirectory(
	runDir string,
	manifest cleanupManifest,
	lifecyclePath string,
) (retErr error) {
	root, exists, err := openManagedCleanupDir(runtimeCleanupPath(runDir))
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("fresh runtime directory %s is missing its held operation lock", runDir)
	}
	defer func() {
		if err := root.close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close fresh runtime validation handles: %w", err))
		}
	}()

	entries, err := cleanupReadDir(root.dir)
	if err != nil {
		return err
	}
	expectedLifecyclePath := filepath.Join(runDir, "daemon.lease")
	lifecycleInRunDir := filepath.Clean(lifecyclePath) == filepath.Clean(expectedLifecyclePath)
	sawLock := false
	sawLifecycle := false
	for _, entry := range entries {
		switch entry.Name() {
		case "lock":
			if sawLock {
				return errors.New("fresh runtime directory contains a duplicate lock entry")
			}
			sawLock = true
			node, err := snapshotManagedFile(
				root.dir,
				entry.Name(),
				false,
				false,
				func(data []byte) error {
					if len(data) != 0 {
						return errors.New("fresh operation lock is not empty")
					}
					return nil
				},
			)
			if err != nil {
				return fmt.Errorf("validate fresh operation lock: %w", err)
			}
			if err := node.close(); err != nil {
				return err
			}
		case "daemon.lease":
			if !lifecycleInRunDir {
				return fmt.Errorf(
					"fresh runtime directory contains an unexpected lifecycle lease %s",
					filepath.Join(runDir, entry.Name()),
				)
			}
			if sawLifecycle {
				return errors.New("fresh runtime directory contains a duplicate lifecycle lease entry")
			}
			sawLifecycle = true
			node, err := snapshotManagedFile(
				root.dir,
				entry.Name(),
				false,
				false,
				validateLifecycleLeaseBytes(manifest),
			)
			if err != nil {
				return fmt.Errorf("validate fresh lifecycle lease: %w", err)
			}
			if err := node.close(); err != nil {
				return err
			}
		default:
			return fmt.Errorf(
				"fresh runtime directory contains pre-existing entry %s",
				filepath.Join(runDir, entry.Name()),
			)
		}
	}
	if !sawLock {
		return errors.New("fresh runtime directory is missing the held operation lock")
	}
	if lifecycleInRunDir && !sawLifecycle {
		return errors.New("fresh runtime directory is missing the held lifecycle lease")
	}
	return nil
}

func validateFreshServiceArtifactsAbsent(manifest cleanupManifest) (retErr error) {
	for _, artifact := range manifest.Artifacts {
		defaultParent := ""
		switch artifact.Kind {
		case "systemd-unit":
			defaultParent = "/etc/systemd/system"
		case systemdEnableLinkKind:
			defaultParent = "/etc/systemd/system/multi-user.target.wants"
		case "openwrt-init":
			defaultParent = "/etc/init.d"
		case "openwrt-hotplug":
			defaultParent = "/etc/hotplug.d/iface"
		default:
			return fmt.Errorf("unknown cleanup manifest artifact kind %q", artifact.Kind)
		}
		parent, exists, err := openDeclaredArtifactParent(
			filepath.Dir(artifact.Path),
			defaultParent,
		)
		if err != nil {
			return err
		}
		if !exists {
			continue
		}
		_, identityErr := cleanupIdentityAt(parent.dir, filepath.Base(artifact.Path))
		closeErr := parent.close()
		switch {
		case cleanupIsNotExist(identityErr):
			if closeErr != nil {
				return closeErr
			}
		case identityErr != nil:
			return errors.Join(
				fmt.Errorf(
					"inspect fresh service artifact %s: %w",
					artifact.Path,
					identityErr,
				),
				closeErr,
			)
		default:
			return errors.Join(
				fmt.Errorf("fresh service artifact %s already exists", artifact.Path),
				closeErr,
			)
		}
	}
	return nil
}

func prepareRuntimeDirectoryPlan(
	runDir string,
	manifest cleanupManifest,
	lifecyclePath string,
) (*cleanupDirectoryPlan, error) {
	root, exists, err := openManagedCleanupDir(runtimeCleanupPath(runDir))
	if err != nil || !exists {
		return nil, err
	}
	plan := &cleanupDirectoryPlan{
		root:          root,
		strictEntries: true,
		removeRoot:    filepath.Clean(runDir) != filepath.Clean(filepath.Dir(lifecyclePath)),
	}
	entries, err := cleanupReadDir(root.dir)
	if err != nil {
		_ = root.close()
		return nil, err
	}
	for _, entry := range entries {
		name := entry.Name()
		switch name {
		case "lock":
			node, err := snapshotManagedFile(root.dir, name, false, false, validateSmallControlFile)
			if err != nil {
				_ = root.close()
				return nil, err
			}
			node.remove = true
			plan.entries = append(plan.entries, node)
		case "daemon.lease":
			if filepath.Clean(filepath.Join(runDir, name)) != filepath.Clean(lifecyclePath) {
				_ = root.close()
				return nil, fmt.Errorf("refuse unexpected lifecycle lease %s", filepath.Join(runDir, name))
			}
			node, err := snapshotManagedFile(root.dir, name, false, false, validateLifecycleLeaseBytes(manifest))
			if err != nil {
				_ = root.close()
				return nil, err
			}
			node.remove = false
			plan.entries = append(plan.entries, node)
		case "status.json":
			node, err := snapshotManagedFile(root.dir, name, false, false, validateStatusBytes(manifest))
			if err != nil {
				_ = root.close()
				return nil, err
			}
			node.remove = true
			plan.entries = append(plan.entries, node)
		case "reload.request", "runtime.request":
			node, err := snapshotManagedFile(root.dir, name, false, false, validateSmallControlFile)
			if err != nil {
				_ = root.close()
				return nil, err
			}
			node.remove = true
			plan.entries = append(plan.entries, node)
		case "requests", "acks":
			node, err := snapshotRuntimeQueue(root.dir, name)
			if err != nil {
				_ = root.close()
				return nil, err
			}
			node.remove = true
			plan.entries = append(plan.entries, node)
		default:
			_ = root.close()
			return nil, fmt.Errorf("refuse to remove unknown runtime entry %s", filepath.Join(runDir, name))
		}
	}
	return plan, nil
}

func prepareStateDirectoryPlan(
	stateDir string,
	manifest cleanupManifest,
) (*cleanupDirectoryPlan, error) {
	root, exists, err := openManagedCleanupDir(stateCleanupPath(stateDir))
	if err != nil || !exists {
		return nil, err
	}
	plan := &cleanupDirectoryPlan{root: root, strictEntries: true, removeRoot: true}
	entries, err := cleanupReadDir(root.dir)
	if err != nil {
		_ = root.close()
		return nil, err
	}
	for _, entry := range entries {
		switch entry.Name() {
		case attachstate.FileName, attachstate.FileName + ".tmp":
			node, err := snapshotManagedFile(
				root.dir,
				entry.Name(),
				true,
				false,
				validateAttachStateBytes(manifest),
			)
			if err != nil {
				_ = root.close()
				return nil, err
			}
			node.remove = true
			plan.entries = append(plan.entries, node)
		default:
			_ = root.close()
			return nil, fmt.Errorf("refuse to remove unknown state entry %s", filepath.Join(stateDir, entry.Name()))
		}
	}
	return plan, nil
}

var uninstallPinnedMapNames = map[string]struct{}{
	"control_map":          {},
	"profile_map":          {},
	"cipher_map":           {},
	"underlay_config_map":  {},
	"managed_fwmark_map":   {},
	"egress_rule_map":      {},
	"ingress_listener_map": {},
	"icmp_listener_map":    {},
	"stats_map":            {},
	"xor_egress_programs":  {},
	"xor_ingress_programs": {},
}

func preparePinDirectoryPlan(pinPath string) (*cleanupDirectoryPlan, error) {
	root, exists, err := openManagedCleanupDir(bpfPinCleanupPath(pinPath))
	if err != nil || !exists {
		return nil, err
	}
	plan := &cleanupDirectoryPlan{
		root:             root,
		strictEntries:    true,
		removeRoot:       true,
		rootMayDisappear: true,
	}
	entries, err := cleanupReadDir(root.dir)
	if err != nil {
		_ = root.close()
		return nil, err
	}
	for _, entry := range entries {
		if _, ok := uninstallPinnedMapNames[entry.Name()]; !ok {
			_ = root.close()
			return nil, fmt.Errorf("refuse to remove unknown BPF pin %s", filepath.Join(pinPath, entry.Name()))
		}
		node, err := snapshotManagedFile(root.dir, entry.Name(), true, true, nil)
		if err != nil {
			_ = root.close()
			return nil, err
		}
		node.remove = true
		plan.entries = append(plan.entries, node)
	}
	return plan, nil
}

func prepareArtifactPlans(manifest cleanupManifest) ([]*cleanupDirectoryPlan, error) {
	var plans []*cleanupDirectoryPlan
	for _, artifact := range manifest.Artifacts {
		defaultParent := ""
		switch artifact.Kind {
		case "systemd-unit":
			defaultParent = "/etc/systemd/system"
		case systemdEnableLinkKind:
			defaultParent = "/etc/systemd/system/multi-user.target.wants"
		case "openwrt-init":
			defaultParent = "/etc/init.d"
		case "openwrt-hotplug":
			defaultParent = "/etc/hotplug.d/iface"
		default:
			return nil, fmt.Errorf("unknown cleanup manifest artifact kind %q", artifact.Kind)
		}
		parent, exists, err := openDeclaredArtifactParent(filepath.Dir(artifact.Path), defaultParent)
		if err != nil {
			closeCleanupDirectoryPlans(plans)
			return nil, err
		}
		if !exists {
			continue
		}
		var node *cleanupEntryPlan
		if artifact.Kind == systemdEnableLinkKind {
			node, err = snapshotManagedSymlink(
				parent.dir,
				filepath.Base(artifact.Path),
				false,
				artifact.Target,
			)
		} else {
			node, err = snapshotManagedFile(
				parent.dir,
				filepath.Base(artifact.Path),
				false,
				false,
				validateDigest(artifact.SHA256),
			)
		}
		if cleanupIsNotExist(err) {
			_ = parent.close()
			continue
		}
		if err != nil {
			_ = parent.close()
			closeCleanupDirectoryPlans(plans)
			return nil, err
		}
		if artifact.Kind == systemdEnableLinkKind {
			closeErr := errors.Join(node.close(), parent.close())
			closeCleanupDirectoryPlans(plans)
			return nil, errors.Join(
				fmt.Errorf(
					"refuse automatic cleanup of systemd enable link %s: "+
						"the published manifest records path and target but not a durable "+
						"symlink inode identity; manually inspect and remove or retain the "+
						"exact link, then retry validated uninstall",
					artifact.Path,
				),
				closeErr,
			)
		}
		node.remove = true
		plan := &cleanupDirectoryPlan{
			root:          parent,
			entries:       []*cleanupEntryPlan{node},
			strictEntries: false,
			removeRoot:    false,
		}
		plans = append(plans, plan)
	}
	return plans, nil
}

func openDeclaredArtifactParent(path string, defaultPath string) (*managedCleanupDir, bool, error) {
	return openDeclaredArtifactParentWithOptions(
		path,
		defaultPath,
		exactDeclaredDirectoryOpenOptions{},
	)
}

func openDeclaredArtifactParentWithOptions(
	path string,
	defaultPath string,
	options exactDeclaredDirectoryOpenOptions,
) (*managedCleanupDir, bool, error) {
	spec, err := declaredArtifactPathSpec(path, defaultPath)
	if err != nil {
		return nil, false, err
	}
	dir, exists, _, err := openExactDeclaredDirectoryWithOptions(spec, options)
	return dir, exists, err
}

func openOrCreateDeclaredArtifactParent(
	path string,
	defaultPath string,
	beforeFinalCreate func(string) error,
) (*managedCleanupDir, bool, error) {
	spec, err := declaredArtifactPathSpec(path, defaultPath)
	if err != nil {
		return nil, false, err
	}
	dir, exists, created, err := openExactDeclaredDirectoryWithOptions(
		spec,
		exactDeclaredDirectoryOpenOptions{
			createFinal:       true,
			beforeFinalCreate: beforeFinalCreate,
		},
	)
	if err != nil {
		return nil, false, err
	}
	if !exists {
		return nil, false, fmt.Errorf(
			"service artifact directory %s could not be created",
			path,
		)
	}
	return dir, created, nil
}

func declaredArtifactPathSpec(path string, defaultPath string) (cleanupPathSpec, error) {
	path = filepath.Clean(path)
	tempRoot := filepath.Clean(os.TempDir())
	physicalTempRoot, _ := filepath.EvalSymlinks(tempRoot)
	physicalTempRoot = filepath.Clean(physicalTempRoot)
	spec := cleanupPathSpec{
		name:        "service artifact directory",
		path:        path,
		defaultPath: defaultPath,
	}
	switch {
	case path == filepath.Clean(defaultPath):
		spec.systemRoot = filepath.Dir(filepath.Clean(defaultPath))
		spec.defaultPath = path
		spec.path = path
		return spec, nil
	case path != tempRoot && pathContains(tempRoot, path):
		return cleanupPathSpec{
			name:        spec.name,
			path:        path,
			defaultPath: path,
			systemRoot:  tempRoot,
		}, nil
	case physicalTempRoot != "." &&
		path != physicalTempRoot &&
		pathContains(physicalTempRoot, path):
		return cleanupPathSpec{
			name:        spec.name,
			path:        path,
			defaultPath: path,
			systemRoot:  physicalTempRoot,
		}, nil
	default:
		return cleanupPathSpec{}, fmt.Errorf(
			"refuse service artifact directory outside its declared roots: %s",
			path,
		)
	}
}

func openExactDeclaredDirectory(spec cleanupPathSpec) (*managedCleanupDir, bool, error) {
	dir, exists, _, err := openExactDeclaredDirectoryWithOptions(
		spec,
		exactDeclaredDirectoryOpenOptions{},
	)
	return dir, exists, err
}

type exactDeclaredDirectoryOpenOptions struct {
	createFinal       bool
	beforeFinalCreate func(string) error
	afterOpen         func(string) error
}

func openExactDeclaredDirectoryWithOptions(
	spec cleanupPathSpec,
	options exactDeclaredDirectoryOpenOptions,
) (*managedCleanupDir, bool, bool, error) {
	canonicalRoot, canonicalPath, rootComponents, relativeComponents, err :=
		canonicalDeclaredDirectoryComponents(spec)
	if err != nil {
		return nil, false, false, err
	}
	components := append(
		append([]string(nil), rootComponents...),
		relativeComponents...,
	)
	kernelRoot := string(os.PathSeparator)
	anchor, err := cleanupOpenAnchor(kernelRoot)
	if err != nil {
		return nil, false, false, fmt.Errorf(
			"open kernel root for declared directory %s: %w",
			spec.path,
			err,
		)
	}
	chain := []*cleanupDirFD{anchor}
	current := anchor
	owner := uint32(os.Geteuid())
	canonicalTempRoot, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		_ = closeCleanupDirFDChain(chain)
		return nil, false, false, fmt.Errorf(
			"resolve canonical temporary root for declared directory %s: %w",
			spec.path,
			err,
		)
	}
	canonicalTempRoot = filepath.Clean(canonicalTempRoot)
	for index, component := range components {
		final := index == len(components)-1
		var child *cleanupDirFD
		var openErr error
		if declaredDirectoryEdgeMayCrossMount(index, len(rootComponents)) {
			child, openErr = cleanupOpenDirAtAllowMount(current, component)
		} else {
			child, openErr = cleanupOpenDirAt(current, component)
		}
		created := false
		if cleanupIsNotExist(openErr) && options.createFinal && final {
			if options.beforeFinalCreate != nil {
				if err := options.beforeFinalCreate(spec.path); err != nil {
					_ = closeCleanupDirFDChain(chain)
					return nil, false, false, fmt.Errorf(
						"run service artifact directory pre-create hook: %w",
						err,
					)
				}
			}
			createErr := cleanupMkdirAt(current, component, 0o755)
			switch {
			case createErr == nil:
				created = true
				if err := current.file.Sync(); err != nil {
					_ = closeCleanupDirFDChain(chain)
					return nil, false, false, fmt.Errorf(
						"sync parent after creating declared artifact directory %s: %w",
						spec.path,
						err,
					)
				}
			case errors.Is(createErr, os.ErrExist):
				// A concurrent creator won the exclusive mkdirat. Open its
				// directory, but never report it as transaction-created.
			default:
				_ = closeCleanupDirFDChain(chain)
				return nil, false, false, fmt.Errorf(
					"create service artifact directory %s: %w",
					spec.path,
					createErr,
				)
			}
			child, openErr = cleanupOpenDirAt(current, component)
		}
		if cleanupIsNotExist(openErr) {
			_ = closeCleanupDirFDChain(chain)
			return nil, false, false, nil
		}
		if openErr != nil {
			_ = closeCleanupDirFDChain(chain)
			return nil, false, false, openErr
		}
		child.path = filepath.Join(current.path, component)
		var validateErr error
		if declaredDirectoryEdgeMayCrossMount(index, len(rootComponents)) {
			validateErr = validateDeclaredCanonicalPrefix(
				child.identity,
				child.path,
				canonicalTempRoot,
				owner,
			)
		} else {
			validateErr = child.identity.validateDirectory(child.path, owner)
		}
		if validateErr != nil {
			_ = child.close()
			_ = closeCleanupDirFDChain(chain)
			return nil, false, false, validateErr
		}
		chain = append(chain, child)
		if options.afterOpen != nil {
			if err := options.afterOpen(child.path); err != nil {
				_ = closeCleanupDirFDChain(chain)
				return nil, false, false, fmt.Errorf(
					"run declared directory post-open hook for %s: %w",
					child.path,
					err,
				)
			}
		}
		if final {
			dir := &managedCleanupDir{
				spec:                  spec,
				parent:                current,
				dir:                   child,
				name:                  component,
				identity:              child.identity,
				declaredChain:         chain,
				declaredEdges:         append([]string(nil), components...),
				declaredCanonicalRoot: canonicalRoot,
				declaredCanonicalPath: canonicalPath,
				declaredRootDepth:     len(rootComponents),
			}
			if err := revalidateManagedCleanupDir(dir); err != nil {
				return nil, false, false, errors.Join(err, dir.close())
			}
			return dir, true, created, nil
		}
		current = child
	}
	_ = closeCleanupDirFDChain(chain)
	return nil, false, false, errors.New("empty declared directory path")
}

func canonicalDeclaredDirectoryComponents(
	spec cleanupPathSpec,
) (
	canonicalRoot string,
	canonicalPath string,
	rootComponents []string,
	relativeComponents []string,
	err error,
) {
	relative, err := filepath.Rel(spec.systemRoot, spec.path)
	if err != nil || relative == "." || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return "", "", nil, nil, fmt.Errorf(
			"refuse declared directory %s outside root %s",
			spec.path,
			spec.systemRoot,
		)
	}
	canonicalRoot, err = filepath.EvalSymlinks(spec.systemRoot)
	if err != nil {
		return "", "", nil, nil, fmt.Errorf(
			"resolve declared root %s: %w",
			spec.systemRoot,
			err,
		)
	}
	canonicalRoot = filepath.Clean(canonicalRoot)
	if !filepath.IsAbs(canonicalRoot) {
		return "", "", nil, nil, fmt.Errorf(
			"refuse non-absolute canonical declared root %s",
			canonicalRoot,
		)
	}
	kernelRoot := string(os.PathSeparator)
	rootRelative, err := filepath.Rel(kernelRoot, canonicalRoot)
	if err != nil || rootRelative == ".." ||
		strings.HasPrefix(rootRelative, ".."+string(os.PathSeparator)) {
		return "", "", nil, nil, fmt.Errorf(
			"refuse canonical declared root outside kernel root: %s",
			canonicalRoot,
		)
	}
	if rootRelative != "." {
		rootComponents = strings.Split(rootRelative, string(os.PathSeparator))
	}
	relativeComponents = strings.Split(relative, string(os.PathSeparator))
	for _, component := range append(
		append([]string(nil), rootComponents...),
		relativeComponents...,
	) {
		if component == "" || component == "." || component == ".." {
			return "", "", nil, nil, fmt.Errorf(
				"refuse unsafe declared directory component %q in %s",
				component,
				spec.path,
			)
		}
	}
	canonicalPath = filepath.Clean(filepath.Join(canonicalRoot, relative))
	if canonicalPath == canonicalRoot || !pathContains(canonicalRoot, canonicalPath) {
		return "", "", nil, nil, fmt.Errorf(
			"refuse canonical declared directory %s outside root %s",
			canonicalPath,
			canonicalRoot,
		)
	}
	return canonicalRoot, canonicalPath, rootComponents, relativeComponents, nil
}

func validateDeclaredCanonicalPrefix(
	identity cleanupIdentity,
	path string,
	canonicalTempRoot string,
	owner uint32,
) error {
	if identity.Mode&cleanupTypeMask != cleanupTypeDir {
		return fmt.Errorf("refuse canonical declared prefix %s: not a directory", path)
	}
	if identity.UID != 0 && identity.UID != owner {
		return fmt.Errorf(
			"refuse canonical declared prefix %s: owner uid is %d, want root or %d",
			path,
			identity.UID,
			owner,
		)
	}
	if identity.Mode&0o022 == 0 {
		return nil
	}
	if filepath.Clean(path) == canonicalTempRoot && identity.Mode&0o1000 != 0 {
		return nil
	}
	return fmt.Errorf(
		"refuse canonical declared prefix %s: group/other writable mode %#o",
		path,
		identity.Mode&0o7777,
	)
}

func snapshotRuntimeQueue(parent *cleanupDirFD, name string) (*cleanupEntryPlan, error) {
	dir, err := cleanupOpenDirAt(parent, name)
	if err != nil {
		return nil, err
	}
	if err := dir.identity.validateDirectory(dir.path, uint32(os.Geteuid())); err != nil {
		_ = dir.close()
		return nil, err
	}
	node := &cleanupEntryPlan{
		parent:    parent,
		dir:       dir,
		path:      dir.path,
		name:      name,
		identity:  dir.identity,
		directory: true,
	}
	entries, err := cleanupReadDir(dir)
	if err != nil {
		_ = node.close()
		return nil, err
	}
	for _, entry := range entries {
		validName := validRuntimeQueueFile(entry.Name()) || name == "requests" && entry.Name() == "lock"
		if !validName {
			_ = node.close()
			return nil, fmt.Errorf("refuse unknown runtime queue entry %s", filepath.Join(dir.path, entry.Name()))
		}
		validator := validateQueueFileBytes(entry.Name())
		if entry.Name() == "lock" {
			validator = validateSmallControlFile
		}
		child, err := snapshotManagedFile(dir, entry.Name(), false, false, validator)
		if err != nil {
			_ = node.close()
			return nil, err
		}
		child.remove = true
		node.children = append(node.children, child)
	}
	return node, nil
}

type cleanupContentValidator func([]byte) error

func snapshotManagedFile(
	parent *cleanupDirFD,
	name string,
	mayDisappear bool,
	opaque bool,
	validator cleanupContentValidator,
) (*cleanupEntryPlan, error) {
	path := filepath.Join(parent.path, name)
	if opaque {
		identity, err := cleanupIdentityAt(parent, name)
		if err != nil {
			return nil, err
		}
		if !identity.sameMount(parent.identity) {
			return nil, fmt.Errorf("refuse managed file %s: path crosses a mount boundary", path)
		}
		if err := identity.validateRegularFile(path, uint32(os.Geteuid())); err != nil {
			return nil, err
		}
		return &cleanupEntryPlan{
			parent:       parent,
			path:         path,
			name:         name,
			identity:     identity,
			mayDisappear: mayDisappear,
		}, nil
	}
	file, identity, err := cleanupOpenFileAt(parent, name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if err := identity.validateRegularFile(path, uint32(os.Geteuid())); err != nil {
		return nil, err
	}
	node := &cleanupEntryPlan{
		parent:       parent,
		path:         path,
		name:         name,
		identity:     identity,
		mayDisappear: mayDisappear,
	}
	data, err := io.ReadAll(io.LimitReader(file, maxManagedCleanupFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read managed file %s: %w", path, err)
	}
	if len(data) > maxManagedCleanupFileSize {
		return nil, fmt.Errorf("refuse managed file %s: content exceeds size limit", path)
	}
	if validator != nil {
		if err := validator(data); err != nil {
			return nil, fmt.Errorf("validate managed file %s: %w", path, err)
		}
	}
	finalIdentity, err := cleanupIdentityForFD(int(file.Fd()))
	if err != nil {
		return nil, fmt.Errorf("recheck managed file %s after reading: %w", path, err)
	}
	if !identity.sameRegularFile(finalIdentity) {
		return nil, fmt.Errorf("refuse managed file %s: identity changed while reading", path)
	}
	node.digest = sha256.Sum256(data)
	node.digestKnown = true
	return node, nil
}

func snapshotManagedSymlink(
	parent *cleanupDirFD,
	name string,
	mayDisappear bool,
	expectedTarget string,
) (*cleanupEntryPlan, error) {
	path := filepath.Join(parent.path, name)
	identity, err := cleanupSymlinkIdentityAt(parent, name)
	if err != nil {
		return nil, err
	}
	if !identity.sameMount(parent.identity) {
		return nil, fmt.Errorf("refuse managed symlink %s: path crosses a mount boundary", path)
	}
	if err := identity.validateSymlink(path, uint32(os.Geteuid())); err != nil {
		return nil, err
	}
	target, err := cleanupReadlinkAt(parent, name)
	if err != nil {
		return nil, fmt.Errorf("read managed symlink %s: %w", path, err)
	}
	if target != expectedTarget {
		return nil, fmt.Errorf(
			"refuse managed symlink %s: target %q does not match owned target %q",
			path,
			target,
			expectedTarget,
		)
	}
	finalIdentity, err := cleanupSymlinkIdentityAt(parent, name)
	if err != nil {
		return nil, fmt.Errorf("recheck managed symlink %s after reading: %w", path, err)
	}
	if !identity.sameSymlink(finalIdentity) {
		return nil, fmt.Errorf("refuse managed symlink %s: identity changed while reading", path)
	}
	return &cleanupEntryPlan{
		parent:        parent,
		path:          path,
		name:          name,
		identity:      finalIdentity,
		symlink:       true,
		symlinkTarget: expectedTarget,
		mayDisappear:  mayDisappear,
	}, nil
}

func (plan *uninstallCleanupPlan) execute() error {
	if plan == nil {
		return nil
	}
	if plan.beforeExecute != nil {
		if err := plan.beforeExecute(); err != nil {
			return err
		}
	}
	if err := plan.revalidate(); err != nil {
		return err
	}
	for _, directory := range plan.directories {
		if err := directory.remove(plan.beforeQuarantine); err != nil {
			return err
		}
	}
	return nil
}

func (plan *uninstallCleanupPlan) executeServiceArtifacts() error {
	if plan == nil {
		return nil
	}
	if plan.beforeExecute != nil {
		if err := plan.beforeExecute(); err != nil {
			return err
		}
	}
	if err := plan.revalidate(); err != nil {
		return err
	}
	for _, directory := range plan.directories {
		if directory.root.spec.name != "service artifact directory" {
			continue
		}
		if err := directory.remove(plan.beforeQuarantine); err != nil {
			return err
		}
	}
	return nil
}

func (plan *uninstallCleanupPlan) revalidate() error {
	for _, directory := range plan.directories {
		if err := directory.revalidate(); err != nil {
			return err
		}
	}
	return nil
}

func (directory *cleanupDirectoryPlan) revalidate() error {
	return directory.revalidateRootName(directory.root.name, true)
}

func (directory *cleanupDirectoryPlan) revalidateRootName(
	rootName string,
	allowDisappear bool,
) error {
	rootIdentity, err := cleanupIdentityAt(directory.root.parent, rootName)
	if cleanupIsNotExist(err) && directory.rootMayDisappear && allowDisappear {
		return nil
	}
	if err != nil {
		return fmt.Errorf("revalidate cleanup directory %s: %w", directory.root.spec.path, err)
	}
	if !directory.root.identity.sameDirectory(rootIdentity) {
		return fmt.Errorf("refuse cleanup directory %s: directory identity changed", directory.root.spec.path)
	}
	if directory.strictEntries {
		if err := revalidateEntryNames(directory.root.dir, directory.entries); err != nil {
			return err
		}
	}
	for _, entry := range directory.entries {
		if err := entry.revalidate(); err != nil {
			return err
		}
	}
	return nil
}

func revalidateEntryNames(dir *cleanupDirFD, expected []*cleanupEntryPlan) error {
	entries, err := cleanupReadDir(dir)
	if err != nil {
		return err
	}
	actual := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		actual[entry.Name()] = struct{}{}
	}
	for _, entry := range expected {
		if _, ok := actual[entry.name]; ok {
			delete(actual, entry.name)
			continue
		}
		if !entry.mayDisappear {
			return fmt.Errorf("managed cleanup entry %s disappeared before execution", entry.path)
		}
	}
	if len(actual) != 0 {
		names := make([]string, 0, len(actual))
		for name := range actual {
			names = append(names, name)
		}
		sort.Strings(names)
		return fmt.Errorf("refuse cleanup: unplanned entries appeared in %s: %s", dir.path, strings.Join(names, ", "))
	}
	return nil
}

func (entry *cleanupEntryPlan) revalidate() error {
	return entry.revalidateName(entry.name, true)
}

func (entry *cleanupEntryPlan) revalidateName(name string, allowDisappear bool) error {
	var identity cleanupIdentity
	var err error
	if entry.symlink {
		identity, err = cleanupSymlinkIdentityAt(entry.parent, name)
	} else {
		identity, err = cleanupIdentityAt(entry.parent, name)
	}
	if cleanupIsNotExist(err) && entry.mayDisappear && allowDisappear {
		return nil
	}
	if err != nil {
		return fmt.Errorf("revalidate managed entry %s: %w", entry.path, err)
	}
	sameIdentity := entry.identity.sameRegularFile(identity)
	if entry.directory {
		sameIdentity = entry.identity.sameDirectory(identity)
	} else if entry.symlink {
		sameIdentity = entry.identity.sameSymlink(identity)
	}
	if !sameIdentity {
		return fmt.Errorf("refuse managed entry %s: inode or mount identity changed", entry.path)
	}
	if entry.directory {
		if err := revalidateEntryNames(entry.dir, entry.children); err != nil {
			return err
		}
		for _, child := range entry.children {
			if err := child.revalidate(); err != nil {
				return err
			}
		}
		return nil
	}
	if entry.symlink {
		target, err := cleanupReadlinkAt(entry.parent, name)
		if err != nil {
			return fmt.Errorf("read managed symlink %s during revalidation: %w", entry.path, err)
		}
		if target != entry.symlinkTarget {
			return fmt.Errorf(
				"refuse managed symlink %s: target changed to %q",
				entry.path,
				target,
			)
		}
		finalIdentity, err := cleanupSymlinkIdentityAt(entry.parent, name)
		if err != nil {
			return fmt.Errorf("recheck managed symlink %s: %w", entry.path, err)
		}
		if !entry.identity.sameSymlink(finalIdentity) {
			return fmt.Errorf(
				"refuse managed symlink %s: identity changed while re-reading",
				entry.path,
			)
		}
		return nil
	}
	if !entry.digestKnown {
		return nil
	}
	file, openedIdentity, err := cleanupOpenFileAt(entry.parent, name)
	if err != nil {
		return err
	}
	defer file.Close()
	if !entry.identity.sameRegularFile(openedIdentity) {
		return fmt.Errorf("refuse managed entry %s: identity changed while opening", entry.path)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxManagedCleanupFileSize+1))
	if err != nil {
		return err
	}
	if len(data) > maxManagedCleanupFileSize || sha256.Sum256(data) != entry.digest {
		return fmt.Errorf("refuse managed entry %s: content changed after preflight", entry.path)
	}
	finalIdentity, err := cleanupIdentityForFD(int(file.Fd()))
	if err != nil {
		return err
	}
	if !entry.identity.sameRegularFile(finalIdentity) {
		return fmt.Errorf("refuse managed entry %s: identity changed while re-reading", entry.path)
	}
	return nil
}

func (directory *cleanupDirectoryPlan) remove(beforeQuarantine func(string) error) error {
	if err := directory.revalidate(); err != nil {
		return err
	}

	rootName := directory.root.name
	rootMoved := false
	if directory.removeRoot {
		quarantineName, moved, err := directory.moveRootToQuarantine(beforeQuarantine)
		if err != nil {
			return err
		}
		if !moved {
			return nil
		}
		rootName = quarantineName
		rootMoved = true
	}

	restoreRoot := func(cause error) error {
		if !rootMoved {
			return cause
		}
		rootMoved = false
		return errors.Join(
			cause,
			restoreCleanupQuarantine(
				directory.root.parent,
				rootName,
				directory.root.name,
				directory.root.spec.path,
			),
		)
	}

	for _, entry := range directory.entries {
		if err := entry.unlink(beforeQuarantine); err != nil {
			return restoreRoot(err)
		}
	}
	if !directory.removeRoot {
		return nil
	}
	entries, err := cleanupReadDir(directory.root.dir)
	if err != nil {
		return restoreRoot(err)
	}
	if len(entries) != 0 {
		return restoreRoot(fmt.Errorf("refuse to remove non-empty managed directory %s", directory.root.spec.path))
	}
	identity, err := cleanupIdentityAt(directory.root.parent, rootName)
	if err != nil {
		return restoreRoot(err)
	}
	if !directory.root.identity.sameDirectory(identity) {
		return restoreRoot(fmt.Errorf(
			"refuse cleanup directory %s: quarantined identity changed before unlinkat",
			directory.root.spec.path,
		))
	}
	if err := cleanupUnlinkAt(directory.root.parent, rootName, true); err != nil {
		return restoreRoot(fmt.Errorf("remove empty managed directory %s: %w", directory.root.spec.path, err))
	}
	rootMoved = false
	return nil
}

func (directory *cleanupDirectoryPlan) moveRootToQuarantine(
	beforeQuarantine func(string) error,
) (string, bool, error) {
	quarantineName, err := newCleanupQuarantineName()
	if err != nil {
		return "", false, err
	}
	if beforeQuarantine != nil {
		if err := beforeQuarantine(directory.root.spec.path); err != nil {
			return "", false, err
		}
	}
	err = cleanupRenameNoReplaceAt(
		directory.root.parent,
		directory.root.name,
		quarantineName,
	)
	if cleanupIsNotExist(err) && directory.rootMayDisappear {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf(
			"move cleanup directory %s to unique quarantine: %w",
			directory.root.spec.path,
			err,
		)
	}
	if err := directory.revalidateRootName(quarantineName, false); err != nil {
		return "", false, errors.Join(
			fmt.Errorf(
				"refuse quarantined cleanup directory %s: %w",
				directory.root.spec.path,
				err,
			),
			restoreCleanupQuarantine(
				directory.root.parent,
				quarantineName,
				directory.root.name,
				directory.root.spec.path,
			),
		)
	}
	return quarantineName, true, nil
}

func (entry *cleanupEntryPlan) unlink(beforeQuarantine func(string) error) error {
	if !entry.remove {
		return nil
	}
	quarantineName, moved, err := entry.moveToQuarantine(beforeQuarantine)
	if err != nil || !moved {
		return err
	}

	restoreEntry := func(cause error) error {
		return errors.Join(
			cause,
			restoreCleanupQuarantine(
				entry.parent,
				quarantineName,
				entry.name,
				entry.path,
			),
		)
	}

	if entry.directory {
		for _, child := range entry.children {
			if err := child.unlink(beforeQuarantine); err != nil {
				return restoreEntry(err)
			}
		}
		entries, err := cleanupReadDir(entry.dir)
		if err != nil {
			return restoreEntry(err)
		}
		if len(entries) != 0 {
			return restoreEntry(fmt.Errorf("refuse to remove non-empty managed directory %s", entry.path))
		}
	}

	var identity cleanupIdentity
	if entry.symlink {
		identity, err = cleanupSymlinkIdentityAt(entry.parent, quarantineName)
	} else {
		identity, err = cleanupIdentityAt(entry.parent, quarantineName)
	}
	if err != nil {
		return restoreEntry(err)
	}
	sameIdentity := entry.identity.sameRegularFile(identity)
	if entry.directory {
		sameIdentity = entry.identity.sameDirectory(identity)
	} else if entry.symlink {
		sameIdentity = entry.identity.sameSymlink(identity)
	}
	if !sameIdentity {
		return restoreEntry(fmt.Errorf(
			"refuse managed entry %s: quarantined identity changed before unlinkat",
			entry.path,
		))
	}
	if err := cleanupUnlinkAt(entry.parent, quarantineName, entry.directory); err != nil {
		return restoreEntry(fmt.Errorf("remove quarantined managed entry %s: %w", entry.path, err))
	}
	return nil
}

func (entry *cleanupEntryPlan) moveToQuarantine(
	beforeQuarantine func(string) error,
) (string, bool, error) {
	quarantineName, err := newCleanupQuarantineName()
	if err != nil {
		return "", false, err
	}
	if beforeQuarantine != nil {
		if err := beforeQuarantine(entry.path); err != nil {
			return "", false, err
		}
	}
	err = cleanupRenameNoReplaceAt(entry.parent, entry.name, quarantineName)
	if cleanupIsNotExist(err) && entry.mayDisappear {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf(
			"move managed entry %s to unique quarantine: %w",
			entry.path,
			err,
		)
	}
	var movedIdentity cleanupIdentity
	if entry.symlink {
		movedIdentity, err = cleanupSymlinkIdentityAt(entry.parent, quarantineName)
	} else {
		movedIdentity, err = cleanupIdentityAt(entry.parent, quarantineName)
	}
	if err != nil {
		return "", false, errors.Join(
			fmt.Errorf("inspect quarantined managed entry %s: %w", entry.path, err),
			restoreCleanupQuarantine(
				entry.parent,
				quarantineName,
				entry.name,
				entry.path,
			),
		)
	}
	sameMovedObject := entry.identity.sameRegularFileObject(movedIdentity)
	if entry.directory {
		sameMovedObject = entry.identity.sameDirectory(movedIdentity)
	} else if entry.symlink {
		sameMovedObject = entry.identity.sameSymlinkObject(movedIdentity)
	}
	if !sameMovedObject {
		return "", false, errors.Join(
			fmt.Errorf(
				"refuse quarantined managed entry %s: moved object identity does not match preflight",
				entry.path,
			),
			restoreCleanupQuarantine(
				entry.parent,
				quarantineName,
				entry.name,
				entry.path,
			),
		)
	}
	// rename changes ctime on regular files. Adopt only the post-rename
	// timestamp after stable inode/mount/owner/mode/link/size comparison.
	entry.identity = movedIdentity
	if err := entry.revalidateName(quarantineName, false); err != nil {
		return "", false, errors.Join(
			fmt.Errorf("refuse quarantined managed entry %s: %w", entry.path, err),
			restoreCleanupQuarantine(
				entry.parent,
				quarantineName,
				entry.name,
				entry.path,
			),
		)
	}
	return quarantineName, true, nil
}

func newCleanupQuarantineName() (string, error) {
	suffix, err := newCleanupInstallationID()
	if err != nil {
		return "", err
	}
	return ".wg-mix-ebpf-quarantine-" + suffix, nil
}

func restoreCleanupQuarantine(
	parent *cleanupDirFD,
	quarantineName string,
	originalName string,
	originalPath string,
) error {
	if err := cleanupRenameNoReplaceAt(parent, quarantineName, originalName); err != nil {
		return fmt.Errorf(
			"restore quarantined object for %s without overwriting; object retained at %s: %w",
			originalPath,
			filepath.Join(parent.path, quarantineName),
			err,
		)
	}
	return nil
}

func validateManifestBytes(expected cleanupManifest) cleanupContentValidator {
	return func(data []byte) error {
		actual, err := decodeCleanupManifest(data)
		if err != nil {
			return err
		}
		actualJSON, _ := json.Marshal(actual)
		expectedJSON, _ := json.Marshal(expected)
		if string(actualJSON) != string(expectedJSON) {
			return errors.New("manifest content does not match the validated ownership record")
		}
		return nil
	}
}

func validateConfigBytes(data []byte) error {
	_, err := config.Load(data)
	return err
}

func validateAttachStateBytes(manifest cleanupManifest) cleanupContentValidator {
	return func(data []byte) error {
		var state attachstate.State
		if err := json.Unmarshal(data, &state); err != nil {
			return err
		}
		if state.Version != 1 {
			return fmt.Errorf("unsupported attach-state version %d", state.Version)
		}
		if state.ConfigPath != manifest.ConfigPath {
			return fmt.Errorf("attach-state config path %s does not match %s", state.ConfigPath, manifest.ConfigPath)
		}
		return nil
	}
}

func validateLifecycleLeaseBytes(manifest cleanupManifest) cleanupContentValidator {
	return func(data []byte) error {
		var owner lockfile.LifecycleOwner
		if err := json.Unmarshal(data, &owner); err != nil {
			return err
		}
		if owner.PID <= 0 || owner.Action == "" {
			return errors.New("lifecycle owner is missing pid or action identity")
		}
		if owner.RunDir != manifest.RunDir {
			return fmt.Errorf("lifecycle owner run dir %s does not match %s", owner.RunDir, manifest.RunDir)
		}
		return nil
	}
}

func validateStatusBytes(manifest cleanupManifest) cleanupContentValidator {
	return func(data []byte) error {
		var status daemon.Status
		if err := json.Unmarshal(data, &status); err != nil {
			return err
		}
		if status.PID <= 0 || !validCleanupInstallationID(status.InstanceID) {
			return errors.New("status is missing pid or daemon instance identity")
		}
		switch status.State {
		case "starting", "active", "degraded", "stopped", "config_changed":
		default:
			return fmt.Errorf("status has invalid state %q", status.State)
		}
		if status.ConfigPath != manifest.ConfigPath {
			return fmt.Errorf("status config path %s does not match %s", status.ConfigPath, manifest.ConfigPath)
		}
		return nil
	}
}

func validateSmallControlFile(data []byte) error {
	if len(data) > 4096 {
		return errors.New("control file exceeds 4096 bytes")
	}
	return nil
}

func validateQueueFileBytes(name string) cleanupContentValidator {
	return func(data []byte) error {
		var envelope struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(data, &envelope); err != nil {
			return err
		}
		expectedID := strings.TrimSuffix(name, ".json")
		if envelope.ID != expectedID {
			return fmt.Errorf("payload id %s does not match filename id %s", envelope.ID, expectedID)
		}
		return nil
	}
}

func validateDigest(expected string) cleanupContentValidator {
	return func(data []byte) error {
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != expected {
			return errors.New("file content hash does not match ownership manifest")
		}
		return nil
	}
}

func containsCleanupEntry(entries []*cleanupEntryPlan, name string) bool {
	for _, entry := range entries {
		if entry.name == name {
			return true
		}
	}
	return false
}

func closeCleanupDirectoryPlans(plans []*cleanupDirectoryPlan) {
	for _, plan := range plans {
		_ = plan.close()
	}
}
