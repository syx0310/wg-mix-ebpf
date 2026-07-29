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
	SHA256 string `json:"sha256"`
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
	switch system {
	case "systemd":
		addArtifact(
			"systemd-unit",
			filepath.Join(paths.SystemdDir, "wg-mix-ebpf.service"),
			systemdUnit(paths.ConfigPath, paths.BinaryPath),
		)
	case "openwrt":
		addArtifact(
			"openwrt-init",
			filepath.Join(paths.OpenWrtInitDir, "wg-mix-ebpf"),
			openWrtInit(paths.ConfigPath, paths.BinaryPath),
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
	file, identity, err := cleanupOpenFileAt(dir, cleanupManifestName)
	if err != nil {
		return nil, cleanupIdentity{}, err
	}
	defer file.Close()
	if err := identity.validateRegularFile(filepath.Join(dir.path, cleanupManifestName), uint32(os.Geteuid())); err != nil {
		return nil, cleanupIdentity{}, err
	}
	if identity.Mode&0o077 != 0 {
		return nil, cleanupIdentity{}, fmt.Errorf(
			"refuse cleanup ownership manifest %s: mode %#o is not private",
			filepath.Join(dir.path, cleanupManifestName),
			identity.Mode&0o7777,
		)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxCleanupManifestSize+1))
	if err != nil {
		return nil, cleanupIdentity{}, fmt.Errorf("read cleanup ownership manifest: %w", err)
	}
	if len(data) > maxCleanupManifestSize {
		return nil, cleanupIdentity{}, errors.New("cleanup ownership manifest exceeds the size limit")
	}
	manifest, err := decodeCleanupManifest(data)
	if err != nil {
		return nil, cleanupIdentity{}, fmt.Errorf("parse cleanup ownership manifest: %w", err)
	}
	return manifest, identity, nil
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
	stateDir         *managedCleanupDir
	desired          cleanupManifest
	alreadyPublished bool
}

func (publication *cleanupManifestPublication) close() error {
	if publication == nil || publication.configDir == nil {
		return nil
	}
	err := publication.configDir.close()
	publication.configDir = nil
	return err
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
	manifest, _, err := readCleanupManifestFromDir(configDir.dir)
	switch {
	case err == nil:
		if err := manifest.validateAgainst(paths, system); err != nil {
			return nil, err
		}
		publication := &cleanupManifestPublication{
			paths:            paths,
			system:           system,
			alreadyPublished: true,
		}
		if err := configDir.close(); err != nil {
			return nil, fmt.Errorf(
				"close existing cleanup ownership directory: %w",
				err,
			)
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
		return nil
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

	randomSuffix, err := newCleanupInstallationID()
	if err != nil {
		return err
	}
	tempName := "." + cleanupManifestName + ".tmp-" + randomSuffix
	file, err := cleanupCreateFileAt(publication.configDir.dir, tempName, 0o600)
	if err != nil {
		return fmt.Errorf("create temporary cleanup ownership manifest: %w", err)
	}
	tempPresent := true
	defer func() {
		if tempPresent {
			if err := cleanupUnlinkAt(
				publication.configDir.dir,
				tempName,
				false,
			); err != nil &&
				!cleanupIsNotExist(err) {
				retErr = errors.Join(
					retErr,
					fmt.Errorf("remove temporary cleanup ownership manifest %s: %w", tempName, err),
				)
			}
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
	publication.alreadyPublished = true
	return nil
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
