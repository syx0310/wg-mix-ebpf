//go:build linux

package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/syx0310/wg-mix-ebpf/internal/config"
	"github.com/syx0310/wg-mix-ebpf/internal/lockfile"
)

func isolatedNetNSTestContext(
	ctx context.Context,
	cmd string,
	configPath string,
	runDir string,
	stateDir string,
	pinPath string,
) (context.Context, error) {
	layout, err := isolatedNetNSTestPaths(cmd, configPath, runDir, stateDir, pinPath)
	if err != nil {
		return nil, err
	}

	initialNetNS, err := os.Stat("/proc/1/ns/net")
	if err != nil {
		return nil, fmt.Errorf("inspect initial network namespace: %w", err)
	}
	currentNetNS, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		return nil, fmt.Errorf("inspect current network namespace: %w", err)
	}
	if os.SameFile(initialNetNS, currentNetNS) {
		return nil, fmt.Errorf(
			"--isolated-netns-test is forbidden in the initial network namespace",
		)
	}
	currentNetNSStat, ok := currentNetNS.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, errors.New("inspect current network namespace identity: unsupported stat data")
	}

	for _, dir := range []string{
		isolatedNetNSTestRoot,
		layout.runBase,
		runDir,
		stateDir,
		filepath.Dir(configPath),
		layout.bpffsDir,
		filepath.Join(layout.runBase, "pin-locks"),
		filepath.Join(layout.runBase, "pin-owners"),
	} {
		if err := requireRootOwnedPrivateDirectory(dir); err != nil {
			return nil, err
		}
	}
	if err := requireRootOwnedPrivateFile(configPath); err != nil {
		return nil, err
	}

	manifestData, err := readRootOwnedPrivateFile(layout.manifest, 64*1024)
	if err != nil {
		return nil, err
	}
	manifest, err := parseIsolatedNetNSTestManifest(manifestData)
	if err != nil {
		return nil, err
	}
	if err := validateIsolatedNetNSTestManifestLayout(
		manifest,
		layout,
		configPath,
		runDir,
		stateDir,
		pinPath,
	); err != nil {
		return nil, err
	}
	endpoint, err := manifestEndpointForRole(manifest, layout.role)
	if err != nil {
		return nil, err
	}
	bootIDData, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nil, fmt.Errorf("read current boot ID: %w", err)
	}
	if currentBootID := strings.TrimSpace(string(bootIDData)); currentBootID != manifest.values["boot_id"] {
		return nil, fmt.Errorf(
			"isolated test manifest boot_id=%q, current boot_id=%q",
			manifest.values["boot_id"],
			currentBootID,
		)
	}
	host, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("read current hostname: %w", err)
	}
	if host == "" || host != manifest.values["host"] {
		return nil, fmt.Errorf(
			"isolated test manifest host=%q, current host=%q",
			manifest.values["host"],
			host,
		)
	}
	if err := validateManifestNetworkNamespaces(
		manifest,
		endpoint,
		uint64(currentNetNSStat.Dev),
		currentNetNSStat.Ino,
	); err != nil {
		return nil, err
	}

	markers := []struct {
		path string
		role string
	}{
		{filepath.Join(layout.runBase, isolatedNetNSOwnerMarker), "root"},
		{filepath.Join(runDir, isolatedNetNSOwnerMarker), "run-" + layout.role},
		{filepath.Join(stateDir, isolatedNetNSOwnerMarker), "state-" + layout.role},
		{filepath.Join(filepath.Dir(configPath), isolatedNetNSOwnerMarker), "secrets"},
		{
			filepath.Join(layout.runBase, "pin-locks", isolatedNetNSOwnerMarker),
			"pin-locks",
		},
		{
			filepath.Join(layout.runBase, "pin-owners", isolatedNetNSOwnerMarker),
			"pin-owners",
		},
	}
	for _, marker := range markers {
		data, err := readRootOwnedPrivateFile(marker.path, 16*1024)
		if err != nil {
			return nil, err
		}
		if err := validateIsolatedNetNSTestOwner(data, manifest, marker.role); err != nil {
			return nil, fmt.Errorf("validate owner marker %s: %w", marker.path, err)
		}
	}

	if err := validateIsolatedNetNSTestConfig(
		configPath,
		manifest,
		layout.role,
		endpoint,
	); err != nil {
		return nil, err
	}

	var fs unix.Statfs_t
	if err := unix.Statfs(layout.bpffsDir, &fs); err != nil {
		return nil, fmt.Errorf("inspect isolated bpffs %s: %w", layout.bpffsDir, err)
	}
	if uint64(fs.Type) != uint64(unix.BPF_FS_MAGIC) {
		return nil, fmt.Errorf(
			"--isolated-netns-test bpffs path is not on bpf filesystem: %s",
			layout.bpffsDir,
		)
	}
	bpffsInfo, err := os.Lstat(layout.bpffsDir)
	if err != nil {
		return nil, fmt.Errorf("inspect isolated bpffs identity: %w", err)
	}
	bpffsStat, ok := bpffsInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, errors.New("inspect isolated bpffs identity: unsupported stat data")
	}
	if err := validateBPFFSParentIdentity(
		manifest,
		uint64(bpffsStat.Dev),
		bpffsStat.Ino,
	); err != nil {
		return nil, err
	}
	mountInfoData, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil, fmt.Errorf("read mountinfo for isolated bpffs: %w", err)
	}
	mountInfo, err := parseMountInfo(mountInfoData)
	if err != nil {
		return nil, fmt.Errorf("parse mountinfo for isolated bpffs: %w", err)
	}
	bpffsMountID, err := statxMountID(layout.bpffsDir)
	if err != nil {
		return nil, fmt.Errorf("inspect isolated bpffs mount ID: %w", err)
	}
	var pinMountID *uint64
	pinInfo, err := os.Lstat(pinPath)
	switch {
	case err == nil:
		if !pinInfo.IsDir() || pinInfo.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("isolated pin target is not a real directory: %s", pinPath)
		}
		id, statErr := statxMountID(pinPath)
		if statErr != nil {
			return nil, fmt.Errorf("inspect isolated pin target mount ID: %w", statErr)
		}
		pinMountID = &id
	case errors.Is(err, os.ErrNotExist):
	default:
		return nil, fmt.Errorf("inspect isolated pin target %s: %w", pinPath, err)
	}
	if err := validatePrivateBPFFSMountInfo(
		mountInfo,
		layout,
		manifest,
		bpffsMountID,
		pinMountID,
	); err != nil {
		return nil, err
	}

	return lockfile.WithIsolatedNetNSTestLifecyclePath(ctx, layout.lease), nil
}

func validateIsolatedNetNSTestConfig(
	configPath string,
	manifest isolatedNetNSTestManifest,
	role string,
	endpoint string,
) error {
	cfg, err := config.LoadFile(configPath)
	if err != nil {
		return fmt.Errorf("load isolated test config %s: %w", configPath, err)
	}
	if len(cfg.Underlays) != 1 ||
		cfg.Underlays[0].Name != manifest.values["underlay_"+endpoint] ||
		cfg.Underlays[0].Type != "netdev" {
		return fmt.Errorf(
			"isolated test config must contain exactly the manifest netdev underlay %q",
			manifest.values["underlay_"+endpoint],
		)
	}
	if len(cfg.WireGuards) != 1 ||
		cfg.WireGuards[0].Name != "wg0" ||
		cfg.WireGuards[0].Config != manifest.values["wg_config_"+endpoint] {
		return fmt.Errorf(
			"isolated test config must contain exactly wg0 with role %s config %s",
			role,
			manifest.values["wg_config_"+endpoint],
		)
	}
	if err := requireRootOwnedPrivateFile(manifest.values["wg_config_"+endpoint]); err != nil {
		return err
	}
	for name, cipher := range cfg.Ciphers {
		if cipher.Secret != "" || cipher.Password != "" {
			return fmt.Errorf("isolated test cipher %q must not contain an inline secret", name)
		}
		if cipher.SecretFile == "" {
			continue
		}
		want := filepath.Join(manifest.values["secrets"], "xor-password")
		if cipher.SecretFile != want {
			return fmt.Errorf(
				"isolated test cipher %q secret_file=%q, want %q",
				name,
				cipher.SecretFile,
				want,
			)
		}
		if err := requireRootOwnedPrivateFile(cipher.SecretFile); err != nil {
			return err
		}
	}
	return nil
}

func statxMountID(path string) (uint64, error) {
	var stat unix.Statx_t
	if err := unix.Statx(
		unix.AT_FDCWD,
		path,
		unix.AT_SYMLINK_NOFOLLOW,
		unix.STATX_TYPE|unix.STATX_MNT_ID,
		&stat,
	); err != nil {
		return 0, err
	}
	if stat.Mask&unix.STATX_MNT_ID == 0 || stat.Mnt_id == 0 {
		return 0, errors.New("kernel did not return STATX_MNT_ID")
	}
	return stat.Mnt_id, nil
}

func requireRootOwnedPrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect isolated test directory %s: %w", path, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("isolated test path is not a real directory: %s", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || info.Mode().Perm() != 0o700 {
		return fmt.Errorf(
			"isolated test directory must be root-owned mode 0700: %s",
			path,
		)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("resolve isolated test directory %s: %w", path, err)
	}
	if resolved != path {
		return fmt.Errorf("isolated test directory contains a symlink: %s", path)
	}
	return nil
}

func requireRootOwnedPrivateFile(path string) error {
	file, err := openRootOwnedPrivateFile(path)
	if err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close isolated test file %s: %w", path, err)
	}
	return nil
}

func readRootOwnedPrivateFile(path string, maximum int64) ([]byte, error) {
	file, err := openRootOwnedPrivateFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, fmt.Errorf("read isolated test file %s: %w", path, err)
	}
	if int64(len(data)) > maximum {
		return nil, fmt.Errorf("isolated test file exceeds %d bytes: %s", maximum, path)
	}
	return data, nil
}

func openRootOwnedPrivateFile(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open isolated test file %s: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("inspect isolated test file %s: %w", path, err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = file.Close()
		return nil, fmt.Errorf("isolated test path is not a regular file: %s", path)
	}
	if stat.Uid != 0 || stat.Mode&0o7777 != 0o600 || stat.Nlink != 1 {
		_ = file.Close()
		return nil, fmt.Errorf(
			"isolated test file must be root-owned mode 0600 with one link: %s",
			path,
		)
	}
	return file, nil
}
