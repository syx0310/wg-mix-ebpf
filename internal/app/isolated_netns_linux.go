//go:build linux

package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"

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

	for _, dir := range []string{
		isolatedNetNSTestRoot,
		layout.runBase,
		runDir,
		stateDir,
		filepath.Dir(configPath),
		layout.bpffsDir,
	} {
		if err := requireRootOwnedPrivateDirectory(dir); err != nil {
			return nil, err
		}
	}
	if err := requireRootOwnedPrivateFile(configPath); err != nil {
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

	return lockfile.WithIsolatedNetNSTestLifecyclePath(ctx, layout.lease), nil
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
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect isolated test file %s: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("isolated test path is not a regular file: %s", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || info.Mode().Perm() != 0o600 || stat.Nlink != 1 {
		return fmt.Errorf(
			"isolated test file must be root-owned mode 0600 with one link: %s",
			path,
		)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("resolve isolated test file %s: %w", path, err)
	}
	if resolved != path {
		return fmt.Errorf("isolated test file contains a symlink: %s", path)
	}
	return nil
}
