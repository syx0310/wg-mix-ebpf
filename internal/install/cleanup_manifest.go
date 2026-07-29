package install

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	cleanupManifestName    = ".wg-mix-ebpf-cleanup.json"
	cleanupManifestProduct = "wg-mix-ebpf"
	cleanupManifestVersion = 1
	maxCleanupManifestSize = 64 << 10
)

type cleanupManifest struct {
	Version        int                       `json:"version"`
	Product        string                    `json:"product"`
	InstallationID string                    `json:"installation_id"`
	ConfigPath     string                    `json:"config_path"`
	BinaryPath     string                    `json:"binary_path"`
	RunDir         string                    `json:"run_dir"`
	StateDir       string                    `json:"state_dir"`
	PinPath        string                    `json:"pin_path"`
	System         string                    `json:"system"`
	Artifacts      []cleanupManifestArtifact `json:"artifacts,omitempty"`
}

type cleanupManifestArtifact struct {
	Kind   string `json:"kind"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256,omitempty"`
	Target string `json:"target,omitempty"`
}

type cleanupOwnershipState uint8

const (
	cleanupOwnershipAbsent cleanupOwnershipState = iota
	cleanupOwnershipMarked
	cleanupOwnershipUnmarked
)

type cleanupManifestWriteOptions struct {
	Fresh         bool
	AdoptExisting bool
	LifecyclePath string
	createState   func() (*managedCleanupDir, error)
}

func expectedCleanupManifest(paths paths, system string, installationID string) cleanupManifest {
	manifest := cleanupManifest{
		Version:        cleanupManifestVersion,
		Product:        cleanupManifestProduct,
		InstallationID: installationID,
		ConfigPath:     paths.ConfigPath,
		BinaryPath:     paths.BinaryPath,
		RunDir:         paths.RunDir,
		StateDir:       paths.VarLibDir,
		PinPath:        paths.PinPath,
		System:         system,
	}
	addArtifact := func(kind string, path string, content string) {
		sum := sha256.Sum256([]byte(content))
		manifest.Artifacts = append(manifest.Artifacts, cleanupManifestArtifact{
			Kind:   kind,
			Path:   path,
			SHA256: hex.EncodeToString(sum[:]),
		})
	}
	addSymlink := func(kind string, path string, target string) {
		manifest.Artifacts = append(manifest.Artifacts, cleanupManifestArtifact{
			Kind:   kind,
			Path:   path,
			Target: target,
		})
	}
	switch system {
	case "systemd":
		addArtifact(
			"systemd-unit",
			filepath.Join(paths.SystemdDir, "wg-mix-ebpf.service"),
			systemdUnit(paths.ConfigPath, paths.BinaryPath),
		)
		addSymlink(
			systemdEnableLinkKind,
			systemdEnableLinkPath(paths),
			systemdEnableLinkTarget,
		)
	case "openwrt":
		addArtifact(
			"openwrt-init",
			filepath.Join(paths.OpenWrtInitDir, "wg-mix-ebpf"),
			openWrtInit(
				paths.ConfigPath,
				paths.BinaryPath,
				filepath.Join(paths.OpenWrtInitDir, "wg-mix-ebpf"),
			),
		)
		addArtifact(
			"openwrt-hotplug",
			filepath.Join(paths.OpenWrtHotplugDir, "90-wg-mix-ebpf"),
			openWrtHotplug(),
		)
	}
	return manifest
}

func newCleanupInstallationID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate cleanup ownership id: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

func validCleanupInstallationID(id string) bool {
	if len(id) != 32 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

func (manifest cleanupManifest) validateAgainst(paths paths, system string) error {
	if manifest.Version != cleanupManifestVersion || manifest.Product != cleanupManifestProduct {
		return fmt.Errorf(
			"cleanup ownership manifest has unsupported identity %q version %d",
			manifest.Product,
			manifest.Version,
		)
	}
	if !validCleanupInstallationID(manifest.InstallationID) {
		return errors.New("cleanup ownership manifest has an invalid installation id")
	}
	expected := expectedCleanupManifest(paths, system, manifest.InstallationID)
	actualJSON, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	expectedJSON, err := json.Marshal(expected)
	if err != nil {
		return err
	}
	if string(actualJSON) != string(expectedJSON) {
		return errors.New("cleanup ownership manifest does not match the resolved install paths and artifacts")
	}
	return nil
}

func cleanupManifestPath(paths paths) string {
	return filepath.Join(filepath.Dir(paths.ConfigPath), cleanupManifestName)
}

func inspectInstallCleanupOwnership(
	paths paths,
	system string,
) (state cleanupOwnershipState, retErr error) {
	configDir, exists, err := openManagedCleanupDir(
		configCleanupPath(filepath.Dir(paths.ConfigPath)),
	)
	if err != nil {
		return cleanupOwnershipAbsent, err
	}
	if !exists {
		if installOwnershipResourcesExist(paths, system) {
			return cleanupOwnershipUnmarked, nil
		}
		return cleanupOwnershipAbsent, nil
	}
	defer func() {
		if err := configDir.close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close cleanup ownership inspection handles: %w", err))
		}
	}()

	manifest, _, err := readCleanupManifestFromDir(configDir.dir)
	if cleanupIsNotExist(err) {
		return cleanupOwnershipUnmarked, nil
	}
	if err != nil {
		return cleanupOwnershipAbsent, err
	}
	if err := manifest.validateAgainst(paths, system); err != nil {
		return cleanupOwnershipAbsent, err
	}
	return cleanupOwnershipMarked, nil
}

func readCleanupManifestFromDir(dir *cleanupDirFD) (*cleanupManifest, cleanupIdentity, error) {
	manifest, file, identity, _, err := openCleanupManifestFromDir(dir)
	if err != nil {
		return nil, cleanupIdentity{}, err
	}
	if err := file.Close(); err != nil {
		return nil, cleanupIdentity{}, fmt.Errorf("close cleanup ownership manifest: %w", err)
	}
	return manifest, identity, nil
}

func openCleanupManifestFromDir(
	dir *cleanupDirFD,
) (
	manifest *cleanupManifest,
	file *os.File,
	identity cleanupIdentity,
	digest [sha256.Size]byte,
	retErr error,
) {
	openedFile, identity, err := cleanupOpenFileAt(dir, cleanupManifestName)
	if err != nil {
		return nil, nil, cleanupIdentity{}, digest, err
	}
	defer func() {
		if retErr != nil {
			retErr = errors.Join(retErr, openedFile.Close())
		}
	}()
	if err := identity.validateRegularFile(filepath.Join(dir.path, cleanupManifestName), uint32(os.Geteuid())); err != nil {
		return nil, nil, cleanupIdentity{}, digest, err
	}
	if identity.Mode&0o077 != 0 {
		return nil, nil, cleanupIdentity{}, digest, fmt.Errorf(
			"refuse cleanup ownership manifest %s: mode %#o is not private",
			filepath.Join(dir.path, cleanupManifestName),
			identity.Mode&0o7777,
		)
	}
	data, err := io.ReadAll(io.LimitReader(openedFile, maxCleanupManifestSize+1))
	if err != nil {
		return nil, nil, cleanupIdentity{}, digest, fmt.Errorf(
			"read cleanup ownership manifest: %w",
			err,
		)
	}
	if len(data) > maxCleanupManifestSize {
		return nil, nil, cleanupIdentity{}, digest, errors.New(
			"cleanup ownership manifest exceeds the size limit",
		)
	}
	fdIdentity, err := cleanupIdentityForFD(int(openedFile.Fd()))
	if err != nil {
		return nil, nil, cleanupIdentity{}, digest, fmt.Errorf(
			"revalidate held cleanup ownership manifest: %w",
			err,
		)
	}
	if !identity.sameRegularFile(fdIdentity) {
		return nil, nil, cleanupIdentity{}, digest, errors.New(
			"refuse cleanup ownership manifest: identity changed while reading",
		)
	}
	namedIdentity, err := cleanupIdentityAt(dir, cleanupManifestName)
	if err != nil {
		return nil, nil, cleanupIdentity{}, digest, fmt.Errorf(
			"revalidate cleanup ownership manifest name: %w",
			err,
		)
	}
	if !fdIdentity.sameRegularFile(namedIdentity) {
		return nil, nil, cleanupIdentity{}, digest, errors.New(
			"refuse cleanup ownership manifest: pathname changed while reading",
		)
	}
	manifest, err = decodeCleanupManifest(data)
	if err != nil {
		return nil, nil, cleanupIdentity{}, digest, fmt.Errorf(
			"parse cleanup ownership manifest: %w",
			err,
		)
	}
	return manifest, openedFile, fdIdentity, sha256.Sum256(data), nil
}

func decodeCleanupManifest(data []byte) (*cleanupManifest, error) {
	var manifest cleanupManifest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("cleanup ownership manifest must contain one JSON value")
		}
		return nil, err
	}
	return &manifest, nil
}

type cleanupManifestPublication struct {
	paths            paths
	system           string
	configDir        *managedCleanupDir
	configFile       *os.File
	configIdentity   cleanupIdentity
	configName       string
	manifestFile     *os.File
	manifestIdentity cleanupIdentity
	manifestDigest   [sha256.Size]byte
	manifestName     string
	stateDir         *managedCleanupDir
	desired          cleanupManifest
	alreadyPublished bool
}

func (publication *cleanupManifestPublication) close() error {
	if publication == nil {
		return nil
	}
	var errs []error
	if publication.configFile != nil {
		errs = append(errs, publication.configFile.Close())
		publication.configFile = nil
	}
	if publication.manifestFile != nil {
		errs = append(errs, publication.manifestFile.Close())
		publication.manifestFile = nil
	}
	if publication.configDir != nil {
		errs = append(errs, publication.configDir.close())
		publication.configDir = nil
	}
	return errors.Join(errs...)
}

func prepareCleanupManifestPublication(
	paths paths,
	system string,
	options cleanupManifestWriteOptions,
) (_ *cleanupManifestPublication, retErr error) {
	configDir, exists, err := openManagedCleanupDir(configCleanupPath(filepath.Dir(paths.ConfigPath)))
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf(
			"prepare cleanup ownership manifest: config directory %s does not exist",
			filepath.Dir(paths.ConfigPath),
		)
	}
	defer func() {
		if configDir != nil {
			retErr = errors.Join(retErr, configDir.close())
		}
	}()

	installationID := ""
	var freshStateDir *managedCleanupDir
	manifest, manifestFile, manifestIdentity, manifestDigest, err :=
		openCleanupManifestFromDir(configDir.dir)
	switch {
	case err == nil:
		if err := manifest.validateAgainst(paths, system); err != nil {
			return nil, errors.Join(err, manifestFile.Close())
		}
		configFile, configIdentity, err := openOwnedConfigForReinstall(
			configDir,
			paths.ConfigPath,
		)
		if err != nil {
			return nil, errors.Join(err, manifestFile.Close())
		}
		publication := &cleanupManifestPublication{
			paths:            paths,
			system:           system,
			configDir:        configDir,
			configFile:       configFile,
			configIdentity:   configIdentity,
			configName:       filepath.Base(paths.ConfigPath),
			manifestFile:     manifestFile,
			manifestIdentity: manifestIdentity,
			manifestDigest:   manifestDigest,
			manifestName:     cleanupManifestName,
			alreadyPublished: true,
		}
		configDir = nil
		return publication, nil
	case cleanupIsNotExist(err):
		if !options.Fresh && !options.AdoptExisting {
			return nil, errors.New(
				"refuse to create cleanup ownership marker for unmarked resources " +
					"without explicit adoption authorization",
			)
		}
		installationID, err = newCleanupInstallationID()
		if err != nil {
			return nil, err
		}
		if options.Fresh {
			if err := validateFreshCleanupManifestBootstrap(
				configDir,
				paths,
				system,
				installationID,
				options.LifecyclePath,
			); err != nil {
				return nil, err
			}
			if options.createState == nil {
				return nil, errors.New(
					"fresh ownership bootstrap requires descriptor-anchored state creation",
				)
			}
			freshStateDir, err = options.createState()
			if err != nil {
				return nil, fmt.Errorf(
					"create fresh state dir before ownership publication: %w",
					err,
				)
			}
			if err := revalidateManagedCleanupDir(freshStateDir); err != nil {
				return nil, fmt.Errorf(
					"revalidate fresh state dir before ownership publication: %w",
					err,
				)
			}
		} else {
			if err := validateCleanupManifestBootstrap(configDir, paths, system, installationID); err != nil {
				return nil, err
			}
		}
	default:
		return nil, err
	}

	publication := &cleanupManifestPublication{
		paths:     paths,
		system:    system,
		configDir: configDir,
		stateDir:  freshStateDir,
		desired:   expectedCleanupManifest(paths, system, installationID),
	}
	configDir = nil
	return publication, nil
}

func (publication *cleanupManifestPublication) publish() (retErr error) {
	if publication == nil {
		return errors.New("cannot publish a nil cleanup ownership manifest")
	}
	if publication.alreadyPublished {
		return publication.revalidateOwnedInstallMetadata()
	}
	if publication.configDir == nil {
		return errors.New("cleanup ownership publication has no held config directory")
	}
	if err := revalidateManagedCleanupDir(publication.configDir); err != nil {
		return fmt.Errorf(
			"revalidate config directory before cleanup ownership publication: %w",
			err,
		)
	}
	if err := validateCleanupManifestBootstrap(
		publication.configDir,
		publication.paths,
		publication.system,
		publication.desired.InstallationID,
	); err != nil {
		return fmt.Errorf(
			"validate completed install before cleanup ownership publication: %w",
			err,
		)
	}
	if publication.stateDir != nil {
		if err := revalidateManagedCleanupDir(publication.stateDir); err != nil {
			return fmt.Errorf(
				"revalidate state directory before cleanup ownership publication: %w",
				err,
			)
		}
	}

	data, err := json.MarshalIndent(publication.desired, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal cleanup ownership manifest: %w", err)
	}
	data = append(data, '\n')

	tempPrefix := "." + cleanupManifestName + ".tmp-"
	if err := refuseRetainedInstallTemporary(
		publication.configDir.dir,
		tempPrefix,
		"cleanup ownership manifest",
	); err != nil {
		return err
	}
	randomSuffix, err := newCleanupInstallationID()
	if err != nil {
		return err
	}
	tempName := tempPrefix + randomSuffix
	file, err := cleanupCreateFileAt(publication.configDir.dir, tempName, 0o600)
	if err != nil {
		return fmt.Errorf("create temporary cleanup ownership manifest: %w", err)
	}
	tempPresent := true
	defer func() {
		if tempPresent {
			retErr = errors.Join(
				retErr,
				fmt.Errorf(
					"temporary cleanup ownership manifest retained without name-based cleanup "+
						"at %s; manually inspect its identity before removal",
					filepath.Join(publication.configDir.spec.path, tempName),
				),
			)
		}
	}()
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("write temporary cleanup ownership manifest: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync temporary cleanup ownership manifest: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temporary cleanup ownership manifest: %w", err)
	}
	if err := cleanupRenameNoReplaceAt(
		publication.configDir.dir,
		tempName,
		cleanupManifestName,
	); err != nil {
		return fmt.Errorf("install cleanup ownership manifest: %w", err)
	}
	tempPresent = false
	if err := publication.configDir.dir.file.Sync(); err != nil {
		return fmt.Errorf("sync cleanup ownership directory: %w", err)
	}
	if publication.stateDir != nil {
		if err := revalidateManagedCleanupDir(publication.stateDir); err != nil {
			return fmt.Errorf("revalidate fresh state dir after ownership publication: %w", err)
		}
	}
	if err := publication.holdNewlyPublishedInstallMetadata(); err != nil {
		return err
	}
	publication.alreadyPublished = true
	return nil
}

func (publication *cleanupManifestPublication) holdNewlyPublishedInstallMetadata() error {
	if publication == nil || publication.configDir == nil {
		return errors.New("cannot hold published install metadata without its config directory")
	}
	if publication.manifestFile != nil || publication.configFile != nil {
		return errors.New("new ownership publication unexpectedly already holds install metadata")
	}
	manifest, manifestFile, manifestIdentity, manifestDigest, err :=
		openCleanupManifestFromDir(publication.configDir.dir)
	if err != nil {
		return fmt.Errorf("open newly published cleanup ownership manifest: %w", err)
	}
	if err := manifest.validateAgainst(publication.paths, publication.system); err != nil {
		return errors.Join(
			fmt.Errorf("validate newly published cleanup ownership manifest: %w", err),
			manifestFile.Close(),
		)
	}
	configFile, configIdentity, err := openOwnedConfigForReinstall(
		publication.configDir,
		publication.paths.ConfigPath,
	)
	if err != nil {
		return errors.Join(err, manifestFile.Close())
	}
	publication.manifestFile = manifestFile
	publication.manifestIdentity = manifestIdentity
	publication.manifestDigest = manifestDigest
	publication.manifestName = cleanupManifestName
	publication.configFile = configFile
	publication.configIdentity = configIdentity
	publication.configName = filepath.Base(publication.paths.ConfigPath)
	return nil
}

func openOwnedConfigForReinstall(
	configDir *managedCleanupDir,
	path string,
) (*os.File, cleanupIdentity, error) {
	name := filepath.Base(path)
	file, identity, err := cleanupOpenFileAt(configDir.dir, name)
	if err != nil {
		return nil, cleanupIdentity{}, fmt.Errorf(
			"open marked install config %s without following links: %w",
			path,
			err,
		)
	}
	if err := identity.validateRegularFile(path, uint32(os.Geteuid())); err != nil {
		_ = file.Close()
		return nil, cleanupIdentity{}, fmt.Errorf("validate marked install config: %w", err)
	}
	fdIdentity, err := cleanupIdentityForFD(int(file.Fd()))
	if err != nil {
		_ = file.Close()
		return nil, cleanupIdentity{}, err
	}
	if !identity.sameRegularFile(fdIdentity) {
		_ = file.Close()
		return nil, cleanupIdentity{}, fmt.Errorf(
			"refuse marked install config %s: held identity changed during validation",
			path,
		)
	}
	namedIdentity, err := cleanupIdentityAt(configDir.dir, name)
	if err != nil {
		_ = file.Close()
		return nil, cleanupIdentity{}, fmt.Errorf(
			"revalidate marked install config name %s: %w",
			path,
			err,
		)
	}
	if !fdIdentity.sameRegularFile(namedIdentity) {
		_ = file.Close()
		return nil, cleanupIdentity{}, fmt.Errorf(
			"refuse marked install config %s: pathname changed during validation",
			path,
		)
	}
	return file, fdIdentity, nil
}

func (publication *cleanupManifestPublication) revalidateOwnedConfig() error {
	if publication == nil || publication.configFile == nil {
		return nil
	}
	if publication.configDir == nil {
		return errors.New("marked install config lost its held parent directory")
	}
	if err := revalidateManagedCleanupDir(publication.configDir); err != nil {
		return fmt.Errorf("revalidate marked install config directory: %w", err)
	}
	fdIdentity, err := cleanupIdentityForFD(int(publication.configFile.Fd()))
	if err != nil {
		return fmt.Errorf("revalidate held marked install config: %w", err)
	}
	if !publication.configIdentity.sameRegularFile(fdIdentity) {
		return fmt.Errorf(
			"refuse marked install config %s: held identity changed",
			publication.paths.ConfigPath,
		)
	}
	namedIdentity, err := cleanupIdentityAt(publication.configDir.dir, publication.configName)
	if err != nil {
		return fmt.Errorf(
			"revalidate marked install config name %s: %w",
			publication.paths.ConfigPath,
			err,
		)
	}
	if !fdIdentity.sameRegularFile(namedIdentity) {
		return fmt.Errorf(
			"refuse marked install config %s: pathname changed",
			publication.paths.ConfigPath,
		)
	}
	return nil
}

func (publication *cleanupManifestPublication) revalidateOwnedManifest() error {
	if publication == nil || publication.manifestFile == nil {
		return nil
	}
	if publication.configDir == nil {
		return errors.New("marked install manifest lost its held parent directory")
	}
	if err := revalidateManagedCleanupDir(publication.configDir); err != nil {
		return fmt.Errorf("revalidate marked install manifest directory: %w", err)
	}
	if _, err := publication.manifestFile.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind held marked install manifest: %w", err)
	}
	data, err := io.ReadAll(
		io.LimitReader(publication.manifestFile, maxCleanupManifestSize+1),
	)
	if err != nil {
		return fmt.Errorf("re-read held marked install manifest: %w", err)
	}
	if len(data) > maxCleanupManifestSize ||
		sha256.Sum256(data) != publication.manifestDigest {
		return errors.New("refuse marked install manifest: content changed")
	}
	fdIdentity, err := cleanupIdentityForFD(int(publication.manifestFile.Fd()))
	if err != nil {
		return fmt.Errorf("revalidate held marked install manifest: %w", err)
	}
	if !publication.manifestIdentity.sameRegularFile(fdIdentity) {
		return errors.New("refuse marked install manifest: held identity changed")
	}
	namedIdentity, err := cleanupIdentityAt(
		publication.configDir.dir,
		publication.manifestName,
	)
	if err != nil {
		return fmt.Errorf("revalidate marked install manifest name: %w", err)
	}
	if !fdIdentity.sameRegularFile(namedIdentity) {
		return errors.New("refuse marked install manifest: pathname changed")
	}
	return nil
}

func (publication *cleanupManifestPublication) revalidateOwnedInstallMetadata() error {
	if err := publication.revalidateOwnedManifest(); err != nil {
		return err
	}
	return publication.revalidateOwnedConfig()
}

func writeCleanupManifest(
	paths paths,
	system string,
	options cleanupManifestWriteOptions,
) (retErr error) {
	publication, err := prepareCleanupManifestPublication(paths, system, options)
	if err != nil {
		return err
	}
	defer func() {
		retErr = errors.Join(retErr, publication.close())
	}()
	return publication.publish()
}
