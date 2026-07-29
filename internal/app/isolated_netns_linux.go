//go:build linux

package app

import (
	"context"
	"crypto/sha256"
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

type isolatedNetNSRevalidationKey struct{}

type isolatedNetNSTestFileSnapshot struct {
	path   string
	device uint64
	inode  uint64
	size   int64
	digest [sha256.Size]byte
	data   []byte
}

type isolatedNetNSTestContractSnapshot struct {
	files map[string]isolatedNetNSTestFileSnapshot
	bpffs isolatedNetNSTestBPFFSSnapshot
}

type isolatedNetNSTestBPFFSSnapshot struct {
	mountChain []mountInfoEntry
	mountID    uint64
	device     uint64
	inode      uint64
}

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

	manifestFile, err := snapshotRootOwnedPrivateFile(layout.manifest, 64*1024)
	if err != nil {
		return nil, err
	}
	manifest, err := parseIsolatedNetNSTestManifest(manifestFile.data)
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
	for _, dir := range []string{
		manifest.values["run_dir_a"],
		manifest.values["run_dir_b"],
		manifest.values["state_dir_a"],
		manifest.values["state_dir_b"],
		manifest.values["evidence"],
	} {
		if err := requireRootOwnedPrivateDirectory(dir); err != nil {
			return nil, err
		}
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
		{filepath.Join(filepath.Dir(configPath), isolatedNetNSOwnerMarker), "secrets"},
		{
			filepath.Join(manifest.values["evidence"], isolatedNetNSOwnerMarker),
			"evidence",
		},
		{
			filepath.Join(layout.runBase, "pin-locks", isolatedNetNSOwnerMarker),
			"pin-locks",
		},
		{
			filepath.Join(layout.runBase, "pin-owners", isolatedNetNSOwnerMarker),
			"pin-owners",
		},
	}
	for _, endpoint := range []string{"a", "b"} {
		role := manifest.values["role_"+endpoint]
		markers = append(markers,
			struct {
				path string
				role string
			}{
				filepath.Join(
					manifest.values["run_dir_"+endpoint],
					isolatedNetNSOwnerMarker,
				),
				"run-" + role,
			},
			struct {
				path string
				role string
			}{
				filepath.Join(
					manifest.values["state_dir_"+endpoint],
					isolatedNetNSOwnerMarker,
				),
				"state-" + role,
			},
		)
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

	contractSnapshot, err := snapshotIsolatedNetNSTestContract(
		manifest,
		layout,
		manifestFile,
	)
	if err != nil {
		return nil, err
	}
	configFile, ok := contractSnapshot.files[configPath]
	if !ok {
		return nil, fmt.Errorf("isolated test contract does not snapshot config %s", configPath)
	}
	if err := validateIsolatedNetNSTestConfig(
		configPath,
		configFile.data,
		manifest,
		layout.role,
		endpoint,
	); err != nil {
		return nil, err
	}

	if revalidating, _ := ctx.Value(isolatedNetNSRevalidationKey{}).(bool); revalidating {
		return lockfile.WithIsolatedNetNSTestLifecyclePath(ctx, layout.lease), nil
	}
	revalidate := func() error {
		if err := revalidateIsolatedNetNSTestSnapshot(
			contractSnapshot,
			manifest,
			layout,
		); err != nil {
			return err
		}
		revalidationContext := context.WithValue(
			context.Background(),
			isolatedNetNSRevalidationKey{},
			true,
		)
		if _, err := isolatedNetNSTestContext(
			revalidationContext,
			cmd,
			configPath,
			runDir,
			stateDir,
			pinPath,
		); err != nil {
			return err
		}
		return revalidateIsolatedNetNSTestSnapshot(
			contractSnapshot,
			manifest,
			layout,
		)
	}
	validatedContext := lockfile.WithIsolatedNetNSTestLifecycleValidation(
		ctx,
		layout.lease,
		revalidate,
	)
	return withIsolatedOwnershipContract(
		validatedContext,
		isolatedOwnershipContract{
			layout:     layout,
			manifest:   manifest,
			endpoint:   endpoint,
			pinPath:    pinPath,
			revalidate: revalidate,
		},
	), nil
}

func validateIsolatedNetNSTestConfig(
	configPath string,
	configData []byte,
	manifest isolatedNetNSTestManifest,
	role string,
	endpoint string,
) error {
	cfg, err := config.Load(configData)
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

func snapshotIsolatedNetNSTestContract(
	manifest isolatedNetNSTestManifest,
	layout isolatedNetNSTestLayout,
	manifestFile isolatedNetNSTestFileSnapshot,
) (isolatedNetNSTestContractSnapshot, error) {
	snapshot := isolatedNetNSTestContractSnapshot{
		files: map[string]isolatedNetNSTestFileSnapshot{
			manifestFile.path: manifestFile,
		},
	}
	files := map[string]int64{
		manifest.values["config_a"]:    1024 * 1024,
		manifest.values["config_b"]:    1024 * 1024,
		manifest.values["wg_config_a"]: 256 * 1024,
		manifest.values["wg_config_b"]: 256 * 1024,
		layout.ledger:                  64 * 1024,
		filepath.Join(
			layout.runBase,
			isolatedNetNSOwnerMarker,
		): 16 * 1024,
		filepath.Join(
			manifest.values["run_dir_a"],
			isolatedNetNSOwnerMarker,
		): 16 * 1024,
		filepath.Join(
			manifest.values["run_dir_b"],
			isolatedNetNSOwnerMarker,
		): 16 * 1024,
		filepath.Join(
			manifest.values["state_dir_a"],
			isolatedNetNSOwnerMarker,
		): 16 * 1024,
		filepath.Join(
			manifest.values["state_dir_b"],
			isolatedNetNSOwnerMarker,
		): 16 * 1024,
		filepath.Join(
			manifest.values["secrets"],
			isolatedNetNSOwnerMarker,
		): 16 * 1024,
		filepath.Join(
			manifest.values["evidence"],
			isolatedNetNSOwnerMarker,
		): 16 * 1024,
		filepath.Join(
			manifest.values["pin_lock_root"],
			isolatedNetNSOwnerMarker,
		): 16 * 1024,
		filepath.Join(
			manifest.values["pin_owner_root"],
			isolatedNetNSOwnerMarker,
		): 16 * 1024,
	}
	xorSecret := filepath.Join(manifest.values["secrets"], "xor-password")
	if _, err := os.Lstat(xorSecret); err == nil {
		files[xorSecret] = 4 * 1024
	} else if !errors.Is(err, os.ErrNotExist) {
		return isolatedNetNSTestContractSnapshot{}, fmt.Errorf(
			"inspect isolated XOR secret %s: %w",
			xorSecret,
			err,
		)
	}
	for path, maximum := range files {
		file, err := snapshotRootOwnedPrivateFile(path, maximum)
		if err != nil {
			return isolatedNetNSTestContractSnapshot{}, err
		}
		snapshot.files[path] = file
	}
	ledgerFile, ok := snapshot.files[layout.ledger]
	if !ok {
		return isolatedNetNSTestContractSnapshot{}, fmt.Errorf(
			"isolated test contract does not snapshot bpffs creation ledger %s",
			layout.ledger,
		)
	}
	ledger, err := parseIsolatedNetNSTestBPFFSLedger(ledgerFile.data)
	if err != nil {
		return isolatedNetNSTestContractSnapshot{}, err
	}
	endpoint, err := manifestEndpointForRole(manifest, layout.role)
	if err != nil {
		return isolatedNetNSTestContractSnapshot{}, err
	}
	bpffs, err := snapshotIsolatedNetNSTestBPFFS(
		manifest,
		ledger,
		layout,
		manifest.values["pin_"+endpoint],
	)
	if err != nil {
		return isolatedNetNSTestContractSnapshot{}, err
	}
	snapshot.bpffs = bpffs
	return snapshot, nil
}

func snapshotIsolatedNetNSTestBPFFS(
	manifest isolatedNetNSTestManifest,
	ledger isolatedNetNSTestBPFFSLedger,
	layout isolatedNetNSTestLayout,
	pinPath string,
) (isolatedNetNSTestBPFFSSnapshot, error) {
	var fs unix.Statfs_t
	if err := unix.Statfs(layout.bpffsDir, &fs); err != nil {
		return isolatedNetNSTestBPFFSSnapshot{}, fmt.Errorf(
			"inspect isolated bpffs %s: %w",
			layout.bpffsDir,
			err,
		)
	}
	if uint64(fs.Type) != uint64(unix.BPF_FS_MAGIC) {
		return isolatedNetNSTestBPFFSSnapshot{}, fmt.Errorf(
			"--isolated-netns-test bpffs path is not on bpf filesystem: %s",
			layout.bpffsDir,
		)
	}
	bpffsInfo, err := os.Lstat(layout.bpffsDir)
	if err != nil {
		return isolatedNetNSTestBPFFSSnapshot{}, fmt.Errorf(
			"inspect isolated bpffs identity: %w",
			err,
		)
	}
	if !bpffsInfo.IsDir() || bpffsInfo.Mode()&os.ModeSymlink != 0 {
		return isolatedNetNSTestBPFFSSnapshot{}, fmt.Errorf(
			"isolated bpffs is not a real directory: %s",
			layout.bpffsDir,
		)
	}
	bpffsStat, ok := bpffsInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return isolatedNetNSTestBPFFSSnapshot{}, errors.New(
			"inspect isolated bpffs identity: unsupported stat data",
		)
	}
	if bpffsStat.Uid != 0 ||
		bpffsInfo.Mode().Perm() != 0o700 ||
		bpffsStat.Nlink == 0 {
		return isolatedNetNSTestBPFFSSnapshot{}, fmt.Errorf(
			"isolated bpffs must remain root-owned mode 0700 with a live directory link: %s",
			layout.bpffsDir,
		)
	}
	device := uint64(bpffsStat.Dev)
	if err := validateBPFFSParentIdentity(
		manifest,
		device,
		bpffsStat.Ino,
	); err != nil {
		return isolatedNetNSTestBPFFSSnapshot{}, err
	}
	mountInfoData, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return isolatedNetNSTestBPFFSSnapshot{}, fmt.Errorf(
			"read mountinfo for isolated bpffs: %w",
			err,
		)
	}
	mountInfo, err := parseMountInfo(mountInfoData)
	if err != nil {
		return isolatedNetNSTestBPFFSSnapshot{}, fmt.Errorf(
			"parse mountinfo for isolated bpffs: %w",
			err,
		)
	}
	bpffsMountID, err := statxMountID(layout.bpffsDir)
	if err != nil {
		return isolatedNetNSTestBPFFSSnapshot{}, fmt.Errorf(
			"inspect isolated bpffs mount ID: %w",
			err,
		)
	}
	var pinMountID *uint64
	pinInfo, err := os.Lstat(pinPath)
	switch {
	case err == nil:
		if !pinInfo.IsDir() || pinInfo.Mode()&os.ModeSymlink != 0 {
			return isolatedNetNSTestBPFFSSnapshot{}, fmt.Errorf(
				"isolated pin target is not a real directory: %s",
				pinPath,
			)
		}
		id, statErr := statxMountID(pinPath)
		if statErr != nil {
			return isolatedNetNSTestBPFFSSnapshot{}, fmt.Errorf(
				"inspect isolated pin target mount ID: %w",
				statErr,
			)
		}
		pinMountID = &id
	case errors.Is(err, os.ErrNotExist):
	default:
		return isolatedNetNSTestBPFFSSnapshot{}, fmt.Errorf(
			"inspect isolated pin target %s: %w",
			pinPath,
			err,
		)
	}
	if err := validatePrivateBPFFSMountInfo(
		mountInfo,
		layout,
		manifest,
		bpffsMountID,
		pinMountID,
	); err != nil {
		return isolatedNetNSTestBPFFSSnapshot{}, err
	}
	mountChain, err := privateBPFFSMountChain(mountInfo, layout)
	if err != nil {
		return isolatedNetNSTestBPFFSSnapshot{}, err
	}
	target := mountChain[0]
	statDevice := fmt.Sprintf("%d:%d", unix.Major(device), unix.Minor(device))
	if target.device != statDevice {
		return isolatedNetNSTestBPFFSSnapshot{}, fmt.Errorf(
			"isolated bpffs mountinfo device=%s does not match stat dev=%d (%s)",
			target.device,
			device,
			statDevice,
		)
	}
	if err := validateIsolatedNetNSTestBPFFSLedger(
		ledger,
		mountInfo,
		mountChain,
		layout,
		manifest,
		statDevice,
		bpffsStat.Ino,
	); err != nil {
		return isolatedNetNSTestBPFFSSnapshot{}, err
	}
	return isolatedNetNSTestBPFFSSnapshot{
		mountChain: mountChain,
		mountID:    bpffsMountID,
		device:     device,
		inode:      bpffsStat.Ino,
	}, nil
}

func snapshotRootOwnedPrivateFile(
	path string,
	maximum int64,
) (isolatedNetNSTestFileSnapshot, error) {
	file, err := openRootOwnedPrivateFile(path)
	if err != nil {
		return isolatedNetNSTestFileSnapshot{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return isolatedNetNSTestFileSnapshot{}, fmt.Errorf(
			"inspect isolated test file %s: %w",
			path,
			err,
		)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return isolatedNetNSTestFileSnapshot{}, fmt.Errorf(
			"inspect isolated test file %s: unsupported stat data",
			path,
		)
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return isolatedNetNSTestFileSnapshot{}, fmt.Errorf(
			"read isolated test file %s: %w",
			path,
			err,
		)
	}
	if int64(len(data)) > maximum {
		return isolatedNetNSTestFileSnapshot{}, fmt.Errorf(
			"isolated test file exceeds %d bytes: %s",
			maximum,
			path,
		)
	}
	return isolatedNetNSTestFileSnapshot{
		path:   path,
		device: uint64(stat.Dev),
		inode:  stat.Ino,
		size:   int64(len(data)),
		digest: sha256.Sum256(data),
		data:   data,
	}, nil
}

func revalidateIsolatedNetNSTestSnapshot(
	expected isolatedNetNSTestContractSnapshot,
	manifest isolatedNetNSTestManifest,
	layout isolatedNetNSTestLayout,
) error {
	manifestFile, err := snapshotRootOwnedPrivateFile(layout.manifest, 64*1024)
	if err != nil {
		return err
	}
	current, err := snapshotIsolatedNetNSTestContract(
		manifest,
		layout,
		manifestFile,
	)
	if err != nil {
		return err
	}
	if len(current.files) != len(expected.files) {
		return fmt.Errorf(
			"isolated test contract file set changed: current=%d expected=%d",
			len(current.files),
			len(expected.files),
		)
	}
	for path, expectedFile := range expected.files {
		currentFile, ok := current.files[path]
		if !ok {
			return fmt.Errorf("isolated test contract file disappeared: %s", path)
		}
		if currentFile.device != expectedFile.device ||
			currentFile.inode != expectedFile.inode ||
			currentFile.size != expectedFile.size ||
			currentFile.digest != expectedFile.digest {
			return fmt.Errorf(
				"isolated test contract file identity or digest changed: %s",
				path,
			)
		}
	}
	if current.bpffs.mountID != expected.bpffs.mountID ||
		current.bpffs.device != expected.bpffs.device ||
		current.bpffs.inode != expected.bpffs.inode ||
		!sameMountInfoChain(current.bpffs.mountChain, expected.bpffs.mountChain) {
		return fmt.Errorf(
			"isolated bpffs mount identity, topology, or options changed after validation",
		)
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
