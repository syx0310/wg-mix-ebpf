package install

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newServiceExecutionChainLayout(
	t *testing.T,
	suffix string,
	system string,
) (paths, string) {
	t.Helper()
	outer := t.TempDir()
	serviceTree := filepath.Join(outer, "service-tree")
	layout := cleanupTestPaths(serviceTree, suffix)
	layout.SystemdDir = filepath.Join(serviceTree, "manager", "systemd")
	layout.OpenWrtInitDir = filepath.Join(serviceTree, "manager", "init.d")
	layout.OpenWrtHotplugDir = filepath.Join(
		serviceTree,
		"manager",
		"hotplug.d",
		"iface",
	)
	if err := populateUnmarkedCleanupTestLayout(layout, system); err != nil {
		t.Fatal(err)
	}
	if err := writeCleanupManifest(
		layout,
		system,
		cleanupManifestWriteOptions{AdoptExisting: true},
	); err != nil {
		t.Fatal(err)
	}
	return layout, serviceTree
}

func TestUninstallServiceArtifactBorrowsCleanupParentLifecycle(t *testing.T) {
	layout, _ := newServiceExecutionChainLayout(
		t,
		"borrowed-parent",
		"systemd",
	)
	lifecyclePath := filepath.Join(t.TempDir(), "daemon.lease")
	plan, err := prepareUninstallCleanup(
		layout,
		"systemd",
		false,
		lifecyclePath,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.close()

	artifact, exists, err := plan.openServiceArtifactForExecution("systemd-unit")
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("owned systemd unit was not available for verified execution")
	}
	borrowed := artifact.borrowedParent
	if borrowed == nil || artifact.ownedParent != nil {
		t.Fatal("uninstall artifact did not borrow exactly the cleanup-plan parent")
	}
	if err := artifact.close(); err != nil {
		t.Fatal(err)
	}
	if borrowed.dir == nil || borrowed.dir.file == nil {
		t.Fatal("closing verified artifact closed its borrowed cleanup-plan root")
	}
	if err := plan.revalidate(); err != nil {
		t.Fatalf("borrowed parent was unusable after artifact close: %v", err)
	}
}

func TestSystemdServiceActionRevalidatesFullChainAfterBeforeExecHook(
	t *testing.T,
) {
	tests := []struct {
		name   string
		mutate func(paths, string) error
	}{
		{
			name: "high ancestor away and back",
			mutate: func(_ paths, serviceTree string) error {
				away := serviceTree + ".away"
				if err := os.Rename(serviceTree, away); err != nil {
					return err
				}
				return os.Rename(away, serviceTree)
			},
		},
		{
			name: "final parent replacement",
			mutate: func(layout paths, _ string) error {
				away := layout.SystemdDir + ".away"
				if err := os.Rename(layout.SystemdDir, away); err != nil {
					return err
				}
				if err := os.MkdirAll(layout.SystemdDir, 0o700); err != nil {
					return err
				}
				return os.WriteFile(
					filepath.Join(layout.SystemdDir, "wg-mix-ebpf.service"),
					[]byte("[Service]\nExecStart=/bin/false\n"),
					0o600,
				)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			layout, serviceTree := newServiceExecutionChainLayout(
				t,
				"before-exec-"+strings.ReplaceAll(test.name, " ", "-"),
				"systemd",
			)
			commandLog := filepath.Join(t.TempDir(), "systemctl.log")
			lifecyclePath := filepath.Join(t.TempDir(), "daemon.lease")
			setCleanupTestEnvironment(t, layout)
			installFakeSystemctl(t, commandLog, "")
			plan, err := prepareUninstallCleanup(
				layout,
				"systemd",
				false,
				lifecyclePath,
			)
			if err != nil {
				t.Fatal(err)
			}
			defer plan.close()

			hookRan := false
			plan.beforeServiceExec = func(path string) error {
				if path != filepath.Join(
					layout.SystemdDir,
					"wg-mix-ebpf.service",
				) {
					return fmt.Errorf("unexpected systemd unit path %s", path)
				}
				hookRan = true
				return test.mutate(layout, serviceTree)
			}
			err = runSystemdServiceActions(t.Context(), layout, plan, "stop")
			if err == nil ||
				(!strings.Contains(err.Error(), "component generation changed") &&
					!strings.Contains(err.Error(), "parent edge no longer names") &&
					!strings.Contains(err.Error(), "canonical root changed")) {
				t.Fatalf(
					"systemd action error = %v, want full-chain rejection",
					err,
				)
			}
			if !hookRan {
				t.Fatal("beforeServiceExec hook did not run")
			}
			if _, statErr := os.Stat(commandLog); !errors.Is(
				statErr,
				os.ErrNotExist,
			) {
				t.Fatalf(
					"full-chain rejection invoked systemctl: %v",
					statErr,
				)
			}
		})
	}
}

func TestSystemdServiceActionFinalChainCheckRejectsInternalAwayBack(
	t *testing.T,
) {
	layout, serviceTree := newServiceExecutionChainLayout(
		t,
		"systemd-final-chain-check",
		"systemd",
	)
	commandLog := filepath.Join(t.TempDir(), "systemctl.log")
	lifecyclePath := filepath.Join(t.TempDir(), "daemon.lease")
	setCleanupTestEnvironment(t, layout)
	installFakeSystemctl(t, commandLog, "")
	plan, err := prepareUninstallCleanup(
		layout,
		"systemd",
		false,
		lifecyclePath,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.close()

	hookRan := false
	plan.beforeServiceFinalChainCheck = func() error {
		if hookRan {
			return nil
		}
		hookRan = true
		away := serviceTree + ".away"
		if err := os.Rename(serviceTree, away); err != nil {
			return err
		}
		return os.Rename(away, serviceTree)
	}
	err = runSystemdServiceActions(t.Context(), layout, plan, "stop")
	if err == nil ||
		(!strings.Contains(err.Error(), "component generation changed") &&
			!strings.Contains(err.Error(), "parent edge no longer names")) {
		t.Fatalf("final chain-check error = %v, want full-chain rejection", err)
	}
	if !hookRan {
		t.Fatal("pre-final-chain test hook did not run")
	}
	if _, statErr := os.Stat(commandLog); !errors.Is(
		statErr,
		os.ErrNotExist,
	) {
		t.Fatalf("internal chain race crossed manager boundary: %v", statErr)
	}
}

func TestServiceActionFinalObjectClosureRejectsPostHookMutation(t *testing.T) {
	tests := []struct {
		name       string
		system     string
		artifact   func(paths) string
		parent     func(paths) string
		mutate     func(string, string) error
		wantSafety string
		hookError  bool
	}{
		{
			name:   "systemd in-place rewrite",
			system: "systemd",
			artifact: func(layout paths) string {
				return filepath.Join(layout.SystemdDir, "wg-mix-ebpf.service")
			},
			parent: func(layout paths) string { return layout.SystemdDir },
			mutate: func(path, _ string) error {
				file, err := os.OpenFile(path, os.O_WRONLY, 0)
				if err != nil {
					return err
				}
				if _, err := file.WriteAt([]byte{'X'}, 0); err != nil {
					_ = file.Close()
					return err
				}
				return file.Close()
			},
			wantSafety: "held identity changed",
		},
		{
			name:   "OpenWrt in-place rewrite",
			system: "openwrt",
			artifact: func(layout paths) string {
				return filepath.Join(layout.OpenWrtInitDir, "wg-mix-ebpf")
			},
			parent: func(layout paths) string { return layout.OpenWrtInitDir },
			mutate: func(path, _ string) error {
				file, err := os.OpenFile(path, os.O_WRONLY, 0)
				if err != nil {
					return err
				}
				if _, err := file.WriteAt([]byte{'X'}, 0); err != nil {
					_ = file.Close()
					return err
				}
				return file.Close()
			},
			wantSafety: "held identity changed",
		},
		{
			name:   "systemd mutation and restore",
			system: "systemd",
			artifact: func(layout paths) string {
				return filepath.Join(layout.SystemdDir, "wg-mix-ebpf.service")
			},
			parent: func(layout paths) string { return layout.SystemdDir },
			mutate: func(path, _ string) error {
				info, err := os.Stat(path)
				if err != nil {
					return err
				}
				if err := os.Chmod(path, info.Mode().Perm()^0o200); err != nil {
					return err
				}
				return os.Chmod(path, info.Mode().Perm())
			},
			wantSafety: "held identity changed",
		},
		{
			name:   "OpenWrt mutation and restore with hook error",
			system: "openwrt",
			artifact: func(layout paths) string {
				return filepath.Join(layout.OpenWrtInitDir, "wg-mix-ebpf")
			},
			parent: func(layout paths) string { return layout.OpenWrtInitDir },
			mutate: func(path, _ string) error {
				info, err := os.Stat(path)
				if err != nil {
					return err
				}
				if err := os.Chmod(path, info.Mode().Perm()^0o200); err != nil {
					return err
				}
				return os.Chmod(path, info.Mode().Perm())
			},
			wantSafety: "held identity changed",
			hookError:  true,
		},
		{
			name:   "systemd final parent away and back",
			system: "systemd",
			artifact: func(layout paths) string {
				return filepath.Join(layout.SystemdDir, "wg-mix-ebpf.service")
			},
			parent: func(layout paths) string { return layout.SystemdDir },
			mutate: func(_, parent string) error {
				away := parent + ".away"
				if err := os.Rename(parent, away); err != nil {
					return err
				}
				return os.Rename(away, parent)
			},
			wantSafety: "component generation changed",
		},
		{
			name:   "OpenWrt final parent away and back",
			system: "openwrt",
			artifact: func(layout paths) string {
				return filepath.Join(layout.OpenWrtInitDir, "wg-mix-ebpf")
			},
			parent: func(layout paths) string { return layout.OpenWrtInitDir },
			mutate: func(_, parent string) error {
				away := parent + ".away"
				if err := os.Rename(parent, away); err != nil {
					return err
				}
				return os.Rename(away, parent)
			},
			wantSafety: "component generation changed",
		},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			layout, _ := newServiceExecutionChainLayout(
				t,
				fmt.Sprintf("post-hook-%d", index),
				test.system,
			)
			lifecyclePath := filepath.Join(t.TempDir(), "daemon.lease")
			commandLog := filepath.Join(t.TempDir(), "manager.log")
			if test.system == "systemd" {
				setCleanupTestEnvironment(t, layout)
				installFakeSystemctl(t, commandLog, "")
			}
			plan, err := prepareUninstallCleanup(
				layout,
				test.system,
				false,
				lifecyclePath,
			)
			if err != nil {
				t.Fatal(err)
			}
			defer plan.close()

			injected := errors.New("injected final object hook error")
			hookRan := false
			plan.beforeServiceFinalChainCheck = func() error {
				if hookRan {
					return nil
				}
				hookRan = true
				if err := test.mutate(
					test.artifact(layout),
					test.parent(layout),
				); err != nil {
					return err
				}
				if test.hookError {
					return injected
				}
				return nil
			}
			var actions []string
			plan.serviceActionExec = func(_ *os.File, action string) error {
				actions = append(actions, action)
				return nil
			}
			if test.system == "systemd" {
				err = runSystemdServiceActions(
					t.Context(),
					layout,
					plan,
					"stop",
				)
			} else {
				err = runOpenWrtServiceActions(
					t.Context(),
					plan,
					"stop",
				)
			}
			if err == nil || !strings.Contains(err.Error(), test.wantSafety) {
				t.Fatalf(
					"service action error = %v, want post-hook safety rejection %q",
					err,
					test.wantSafety,
				)
			}
			if test.hookError && !errors.Is(err, injected) {
				t.Fatalf("service action error = %v, want joined hook error", err)
			}
			if !hookRan {
				t.Fatal("final object hook did not run")
			}
			if len(actions) != 0 {
				t.Fatalf("post-hook mutation executed actions %#v", actions)
			}
			if test.system == "systemd" {
				if _, statErr := os.Stat(commandLog); !errors.Is(
					statErr,
					os.ErrNotExist,
				) {
					t.Fatalf(
						"post-hook mutation invoked systemctl: %v",
						statErr,
					)
				}
			}
		})
	}
}

func TestPrepareCleanupRejectsInitiallyMissingServiceArtifactParent(
	t *testing.T,
) {
	tests := []struct {
		name   string
		system string
		parent func(paths) string
	}{
		{
			name:   "systemd unit parent",
			system: "systemd",
			parent: func(layout paths) string { return layout.SystemdDir },
		},
		{
			name:   "OpenWrt init parent",
			system: "openwrt",
			parent: func(layout paths) string { return layout.OpenWrtInitDir },
		},
		{
			name:   "OpenWrt hotplug parent",
			system: "openwrt",
			parent: func(layout paths) string { return layout.OpenWrtHotplugDir },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			layout, _ := newServiceExecutionChainLayout(
				t,
				"missing-parent-"+strings.ReplaceAll(test.name, " ", "-"),
				test.system,
			)
			parent := test.parent(layout)
			if err := os.Rename(parent, parent+".initially-missing"); err != nil {
				t.Fatal(err)
			}
			commandLog := filepath.Join(t.TempDir(), "manager.log")
			setCleanupTestEnvironment(t, layout)
			if test.system == "systemd" {
				installFakeSystemctl(t, commandLog, "")
			}
			plan, err := prepareUninstallCleanup(
				layout,
				test.system,
				false,
				filepath.Join(t.TempDir(), "daemon.lease"),
			)
			if plan != nil {
				_ = plan.close()
			}
			if err == nil || !strings.Contains(err.Error(), "parent") ||
				!strings.Contains(err.Error(), "missing") {
				t.Fatalf(
					"prepare error = %v, want initially-missing parent rejection",
					err,
				)
			}
			if _, statErr := os.Stat(commandLog); !errors.Is(
				statErr,
				os.ErrNotExist,
			) {
				t.Fatalf("missing parent invoked a manager/action: %v", statErr)
			}
		})
	}
}

func TestServiceActionBoundaryRevalidatesAllDeclaredArtifacts(t *testing.T) {
	t.Run("OpenWrt hotplug reappears after stop", func(t *testing.T) {
		layout, _ := newServiceExecutionChainLayout(
			t,
			"openwrt-sibling-reappears",
			"openwrt",
		)
		hotplugPath := filepath.Join(
			layout.OpenWrtHotplugDir,
			"90-wg-mix-ebpf",
		)
		if err := os.Rename(
			hotplugPath,
			hotplugPath+".initially-absent",
		); err != nil {
			t.Fatal(err)
		}
		plan, err := prepareUninstallCleanup(
			layout,
			"openwrt",
			false,
			filepath.Join(t.TempDir(), "daemon.lease"),
		)
		if err != nil {
			t.Fatal(err)
		}
		defer plan.close()
		var actions []string
		plan.serviceActionExec = func(_ *os.File, action string) error {
			actions = append(actions, action)
			if action == "stop" {
				return os.WriteFile(
					hotplugPath,
					[]byte("foreign hotplug\n"),
					0o700,
				)
			}
			return nil
		}
		err = runOpenWrtServiceActions(
			t.Context(),
			plan,
			"stop",
			"disable",
		)
		if err == nil ||
			(!strings.Contains(err.Error(), "reappeared") &&
				!strings.Contains(err.Error(), "component generation changed") &&
				!strings.Contains(err.Error(), "directory generation changed")) {
			t.Fatalf("OpenWrt sibling boundary error = %v, want rejection", err)
		}
		if strings.Join(actions, ",") != "stop" {
			t.Fatalf("OpenWrt sibling race executed actions %#v", actions)
		}
	})

	t.Run("systemd enable-link reappears before manager", func(t *testing.T) {
		layout, _ := newServiceExecutionChainLayout(
			t,
			"systemd-sibling-reappears",
			"systemd",
		)
		commandLog := filepath.Join(t.TempDir(), "systemctl.log")
		setCleanupTestEnvironment(t, layout)
		installFakeSystemctl(t, commandLog, "")
		plan, err := prepareUninstallCleanup(
			layout,
			"systemd",
			false,
			filepath.Join(t.TempDir(), "daemon.lease"),
		)
		if err != nil {
			t.Fatal(err)
		}
		defer plan.close()
		linkPath := systemdEnableLinkPath(layout)
		hookRan := false
		plan.beforeServiceFinalChainCheck = func() error {
			if hookRan {
				return nil
			}
			hookRan = true
			return os.Symlink(systemdEnableLinkTarget, linkPath)
		}
		err = runSystemdServiceActions(
			t.Context(),
			layout,
			plan,
			"stop",
		)
		if err == nil ||
			(!strings.Contains(err.Error(), "reappeared") &&
				!strings.Contains(err.Error(), "component generation changed") &&
				!strings.Contains(err.Error(), "directory generation changed")) {
			t.Fatalf("systemd sibling boundary error = %v, want rejection", err)
		}
		if !hookRan {
			t.Fatal("systemd sibling injection hook did not run")
		}
		if _, statErr := os.Stat(commandLog); !errors.Is(
			statErr,
			os.ErrNotExist,
		) {
			t.Fatalf("systemd sibling race invoked manager/action: %v", statErr)
		}
	})
}

func TestServiceActionBoundaryAcceptsStableDeclaredArtifactSet(t *testing.T) {
	t.Run("systemd", func(t *testing.T) {
		layout, _ := newServiceExecutionChainLayout(
			t,
			"systemd-stable-set",
			"systemd",
		)
		commandLog := filepath.Join(t.TempDir(), "systemctl.log")
		setCleanupTestEnvironment(t, layout)
		installFakeSystemctl(t, commandLog, "")
		plan, err := prepareUninstallCleanup(
			layout,
			"systemd",
			false,
			filepath.Join(t.TempDir(), "daemon.lease"),
		)
		if err != nil {
			t.Fatal(err)
		}
		defer plan.close()
		if err := runSystemdServiceActions(
			t.Context(),
			layout,
			plan,
			"stop",
		); err != nil {
			t.Fatal(err)
		}
		logData, err := os.ReadFile(commandLog)
		if err != nil {
			t.Fatal(err)
		}
		if string(logData) != "daemon-reload\nstop wg-mix-ebpf.service\n" {
			t.Fatalf("systemd stable-set actions = %q", logData)
		}
	})

	t.Run("OpenWrt", func(t *testing.T) {
		layout, _ := newServiceExecutionChainLayout(
			t,
			"openwrt-stable-set",
			"openwrt",
		)
		plan, err := prepareUninstallCleanup(
			layout,
			"openwrt",
			false,
			filepath.Join(t.TempDir(), "daemon.lease"),
		)
		if err != nil {
			t.Fatal(err)
		}
		defer plan.close()
		var actions []string
		plan.serviceActionExec = func(_ *os.File, action string) error {
			actions = append(actions, action)
			return nil
		}
		if err := runOpenWrtServiceActions(
			t.Context(),
			plan,
			"stop",
			"disable",
		); err != nil {
			t.Fatal(err)
		}
		if strings.Join(actions, ",") != "stop,disable" {
			t.Fatalf("OpenWrt stable-set actions = %#v", actions)
		}
	})
}

func TestServiceActionFailureStillRevalidatesDeclaredArtifactSet(t *testing.T) {
	t.Run("OpenWrt action error and hotplug reappearance", func(t *testing.T) {
		layout, _ := newServiceExecutionChainLayout(
			t,
			"openwrt-error-set",
			"openwrt",
		)
		hotplugPath := filepath.Join(
			layout.OpenWrtHotplugDir,
			"90-wg-mix-ebpf",
		)
		if err := os.Rename(hotplugPath, hotplugPath+".initially-absent"); err != nil {
			t.Fatal(err)
		}
		plan, err := prepareUninstallCleanup(
			layout,
			"openwrt",
			false,
			filepath.Join(t.TempDir(), "daemon.lease"),
		)
		if err != nil {
			t.Fatal(err)
		}
		defer plan.close()
		injected := errors.New("injected OpenWrt action error")
		var actions []string
		plan.serviceActionExec = func(_ *os.File, action string) error {
			actions = append(actions, action)
			if err := os.WriteFile(
				hotplugPath,
				[]byte("foreign hotplug\n"),
				0o700,
			); err != nil {
				return err
			}
			return injected
		}
		err = runOpenWrtServiceActions(
			t.Context(),
			plan,
			"stop",
			"disable",
		)
		if !errors.Is(err, injected) ||
			(!strings.Contains(err.Error(), "reappeared") &&
				!strings.Contains(err.Error(), "component generation changed") &&
				!strings.Contains(err.Error(), "directory generation changed")) {
			t.Fatalf(
				"OpenWrt action error = %v, want joined action and set rejection",
				err,
			)
		}
		if strings.Join(actions, ",") != "stop" {
			t.Fatalf("OpenWrt failed action crossed boundary: %#v", actions)
		}
	})

	t.Run("systemd manager error and unit mutation", func(t *testing.T) {
		layout, _ := newServiceExecutionChainLayout(
			t,
			"systemd-error-object",
			"systemd",
		)
		commandLog := filepath.Join(t.TempDir(), "systemctl.log")
		setCleanupTestEnvironment(t, layout)
		installFakeSystemctl(t, commandLog, "daemon-reload")
		replacement := filepath.Join(t.TempDir(), "foreign-unit")
		if err := os.WriteFile(
			replacement,
			[]byte("[Service]\nExecStart=/bin/false\n"),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
		t.Setenv("WG_MIX_EBPF_TEST_SYSTEMCTL_SWAP_ACTION", "daemon-reload")
		t.Setenv(
			"WG_MIX_EBPF_TEST_SYSTEMCTL_SWAP_PATH",
			filepath.Join(layout.SystemdDir, "wg-mix-ebpf.service"),
		)
		t.Setenv("WG_MIX_EBPF_TEST_SYSTEMCTL_SWAP_CONTENT", replacement)
		plan, err := prepareUninstallCleanup(
			layout,
			"systemd",
			false,
			filepath.Join(t.TempDir(), "daemon.lease"),
		)
		if err != nil {
			t.Fatal(err)
		}
		defer plan.close()
		err = runSystemdServiceActions(
			t.Context(),
			layout,
			plan,
			"stop",
		)
		if err == nil ||
			!strings.Contains(err.Error(), "systemctl daemon-reload") ||
			(!strings.Contains(err.Error(), "held identity changed") &&
				!strings.Contains(err.Error(), "inode or mount identity changed") &&
				!strings.Contains(err.Error(), "component generation changed")) {
			t.Fatalf(
				"systemd manager error = %v, want joined manager and object rejection",
				err,
			)
		}
		logData, readErr := os.ReadFile(commandLog)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if string(logData) != "daemon-reload\n" {
			t.Fatalf("systemd failed manager crossed boundary: %q", logData)
		}
	})

	t.Run("before-exec hook error and object mutation", func(t *testing.T) {
		layout, _ := newServiceExecutionChainLayout(
			t,
			"openwrt-hook-error",
			"openwrt",
		)
		plan, err := prepareUninstallCleanup(
			layout,
			"openwrt",
			false,
			filepath.Join(t.TempDir(), "daemon.lease"),
		)
		if err != nil {
			t.Fatal(err)
		}
		defer plan.close()
		injected := errors.New("injected before-exec hook error")
		plan.beforeServiceExec = func(path string) error {
			file, err := os.OpenFile(path, os.O_WRONLY, 0)
			if err != nil {
				return err
			}
			if _, err := file.WriteAt([]byte{'X'}, 0); err != nil {
				_ = file.Close()
				return err
			}
			if err := file.Close(); err != nil {
				return err
			}
			return injected
		}
		var actions []string
		plan.serviceActionExec = func(_ *os.File, action string) error {
			actions = append(actions, action)
			return nil
		}
		err = runOpenWrtServiceActions(t.Context(), plan, "stop")
		if !errors.Is(err, injected) ||
			(!strings.Contains(err.Error(), "held identity changed") &&
				!strings.Contains(err.Error(), "inode or mount identity changed")) {
			t.Fatalf(
				"before-exec hook error = %v, want joined hook and object rejection",
				err,
			)
		}
		if len(actions) != 0 {
			t.Fatalf("failed before-exec hook executed actions %#v", actions)
		}
	})
}

func TestVerifiedServiceArtifactRejectsCanonicalSystemRootAliasSwap(
	t *testing.T,
) {
	outer := t.TempDir()
	realRoot := filepath.Join(outer, "real-root")
	replacementRoot := filepath.Join(outer, "replacement-root")
	for _, root := range []string{realRoot, replacementRoot} {
		if err := os.MkdirAll(filepath.Join(root, "artifact-parent"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	unitName := "wg-mix-ebpf.service"
	content := []byte("[Service]\nExecStart=/bin/true\n")
	if err := os.WriteFile(
		filepath.Join(realRoot, "artifact-parent", unitName),
		content,
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(replacementRoot, "artifact-parent", unitName),
		content,
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	aliasRoot := filepath.Join(outer, "system-root")
	if err := os.Symlink(realRoot, aliasRoot); err != nil {
		t.Fatal(err)
	}
	parentPath := filepath.Join(aliasRoot, "artifact-parent")
	parent, exists, err := openExactDeclaredDirectory(cleanupPathSpec{
		name:        "service artifact directory",
		path:        parentPath,
		defaultPath: parentPath,
		systemRoot:  aliasRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("declared artifact parent unexpectedly missing")
	}
	defer parent.close()
	entry, err := snapshotManagedFile(
		parent.dir,
		unitName,
		false,
		false,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	file, identity, err := cleanupOpenFileAt(parent.dir, unitName)
	if err != nil {
		t.Fatal(err)
	}
	if !entry.identity.sameRegularFile(identity) {
		_ = file.Close()
		t.Fatal("opened service unit does not match its cleanup entry")
	}
	artifact := &verifiedServiceArtifact{
		file:           file,
		entry:          entry,
		borrowedParent: parent,
	}
	defer artifact.close()

	heldAlias := aliasRoot + ".held"
	if err := os.Rename(aliasRoot, heldAlias); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(replacementRoot, aliasRoot); err != nil {
		t.Fatal(err)
	}
	if err := artifact.revalidateForExecution(); err == nil ||
		(!strings.Contains(err.Error(), "canonical root changed") &&
			!strings.Contains(err.Error(), "component generation changed")) {
		t.Fatalf(
			"artifact alias-swap revalidation error = %v, want canonical-chain rejection",
			err,
		)
	}
}

func TestSystemdServiceActionRevalidatesEveryManagerBoundary(t *testing.T) {
	tests := []struct {
		action      string
		wantLog     string
		forbidInLog string
	}{
		{
			action:      "daemon-reload",
			wantLog:     "daemon-reload\n",
			forbidInLog: "stop wg-mix-ebpf.service",
		},
		{
			action:      "show",
			wantLog:     "daemon-reload\n",
			forbidInLog: "stop wg-mix-ebpf.service",
		},
		{
			action:  "stop",
			wantLog: "daemon-reload\nstop wg-mix-ebpf.service\n",
		},
	}
	for _, test := range tests {
		t.Run(test.action, func(t *testing.T) {
			layout, serviceTree := newServiceExecutionChainLayout(
				t,
				"systemd-boundary-"+test.action,
				"systemd",
			)
			commandLog := filepath.Join(t.TempDir(), "systemctl.log")
			lifecyclePath := filepath.Join(t.TempDir(), "daemon.lease")
			setCleanupTestEnvironment(t, layout)
			installFakeSystemctl(t, commandLog, "")
			plan, err := prepareUninstallCleanup(
				layout,
				"systemd",
				false,
				lifecyclePath,
			)
			if err != nil {
				t.Fatal(err)
			}
			defer plan.close()
			t.Setenv(
				"WG_MIX_EBPF_TEST_SYSTEMCTL_CHAIN_MUTATE_ACTION",
				test.action,
			)
			t.Setenv(
				"WG_MIX_EBPF_TEST_SYSTEMCTL_CHAIN_MUTATE_PATH",
				serviceTree,
			)

			err = runSystemdServiceActions(t.Context(), layout, plan, "stop")
			if err == nil ||
				(!strings.Contains(err.Error(), "component generation changed") &&
					!strings.Contains(err.Error(), "parent edge no longer names")) {
				t.Fatalf(
					"systemd %s boundary error = %v, want full-chain rejection",
					test.action,
					err,
				)
			}
			logData, readErr := os.ReadFile(commandLog)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if string(logData) != test.wantLog {
				t.Fatalf(
					"systemctl log = %q, want %q",
					logData,
					test.wantLog,
				)
			}
			if test.forbidInLog != "" &&
				strings.Contains(string(logData), test.forbidInLog) {
				t.Fatalf(
					"systemctl crossed rejected boundary: %q",
					logData,
				)
			}
		})
	}
}

func TestOpenWrtServiceActionsRevalidateBetweenStopAndDisable(t *testing.T) {
	layout, serviceTree := newServiceExecutionChainLayout(
		t,
		"openwrt-boundaries",
		"openwrt",
	)
	lifecyclePath := filepath.Join(t.TempDir(), "daemon.lease")
	plan, err := prepareUninstallCleanup(
		layout,
		"openwrt",
		false,
		lifecyclePath,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.close()

	var actions []string
	plan.serviceActionExec = func(_ *os.File, action string) error {
		actions = append(actions, action)
		if action != "stop" {
			return nil
		}
		away := serviceTree + ".away"
		if err := os.Rename(serviceTree, away); err != nil {
			return err
		}
		return os.Rename(away, serviceTree)
	}
	err = runOpenWrtServiceActions(
		t.Context(),
		plan,
		"stop",
		"disable",
	)
	if err == nil ||
		(!strings.Contains(err.Error(), "component generation changed") &&
			!strings.Contains(err.Error(), "parent edge no longer names")) {
		t.Fatalf("OpenWrt boundary error = %v, want full-chain rejection", err)
	}
	if strings.Join(actions, ",") != "stop" {
		t.Fatalf(
			"OpenWrt actions crossed rejected stop boundary: %#v",
			actions,
		)
	}
}

func TestInitialServiceArtifactAbsenceRejectsReappearanceBeforeAction(
	t *testing.T,
) {
	tests := []struct {
		name       string
		system     string
		artifact   func(paths) string
		runActions func(*uninstallCleanupPlan, paths) error
	}{
		{
			name:   "systemd unit",
			system: "systemd",
			artifact: func(layout paths) string {
				return filepath.Join(
					layout.SystemdDir,
					"wg-mix-ebpf.service",
				)
			},
			runActions: func(plan *uninstallCleanupPlan, layout paths) error {
				return runSystemdServiceActions(
					t.Context(),
					layout,
					plan,
					"stop",
				)
			},
		},
		{
			name:   "OpenWrt init",
			system: "openwrt",
			artifact: func(layout paths) string {
				return filepath.Join(layout.OpenWrtInitDir, "wg-mix-ebpf")
			},
			runActions: func(plan *uninstallCleanupPlan, _ paths) error {
				return runOpenWrtServiceActions(
					t.Context(),
					plan,
					"stop",
					"disable",
				)
			},
		},
		{
			name:   "OpenWrt hotplug",
			system: "openwrt",
			artifact: func(layout paths) string {
				return filepath.Join(
					layout.OpenWrtHotplugDir,
					"90-wg-mix-ebpf",
				)
			},
			runActions: func(plan *uninstallCleanupPlan, _ paths) error {
				return runOpenWrtServiceActions(
					t.Context(),
					plan,
					"stop",
					"disable",
				)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			layout, _ := newServiceExecutionChainLayout(
				t,
				"absence-reappearance-"+
					strings.ReplaceAll(test.name, " ", "-"),
				test.system,
			)
			artifactPath := test.artifact(layout)
			displacedPath := filepath.Join(
				t.TempDir(),
				filepath.Base(artifactPath),
			)
			if err := os.Rename(artifactPath, displacedPath); err != nil {
				t.Fatal(err)
			}
			commandLog := filepath.Join(t.TempDir(), "manager.log")
			lifecyclePath := filepath.Join(t.TempDir(), "daemon.lease")
			setCleanupTestEnvironment(t, layout)
			if test.system == "systemd" {
				installFakeSystemctl(t, commandLog, "")
			}
			plan, err := prepareUninstallCleanup(
				layout,
				test.system,
				false,
				lifecyclePath,
			)
			if err != nil {
				t.Fatal(err)
			}
			defer plan.close()
			var actions []string
			plan.serviceActionExec = func(_ *os.File, action string) error {
				actions = append(actions, action)
				return nil
			}
			if err := os.WriteFile(
				artifactPath,
				[]byte("foreign service artifact\n"),
				0o700,
			); err != nil {
				t.Fatal(err)
			}

			err = test.runActions(plan, layout)
			if err == nil ||
				(!strings.Contains(err.Error(), "reappeared") &&
					!strings.Contains(err.Error(), "component generation changed") &&
					!strings.Contains(err.Error(), "directory generation changed")) {
				t.Fatalf(
					"service absence reappearance error = %v, want rejection",
					err,
				)
			}
			if len(actions) != 0 {
				t.Fatalf(
					"service absence reappearance executed actions %#v",
					actions,
				)
			}
			if test.system == "systemd" {
				if _, statErr := os.Stat(commandLog); !errors.Is(
					statErr,
					os.ErrNotExist,
				) {
					t.Fatalf(
						"service absence reappearance invoked systemctl: %v",
						statErr,
					)
				}
			}
		})
	}
}

func TestPostRemovalSystemdReloadRevalidatesHeldAbsenceChain(t *testing.T) {
	layout, serviceTree := newServiceExecutionChainLayout(
		t,
		"post-removal-reload",
		"systemd",
	)
	commandLog := filepath.Join(t.TempDir(), "systemctl.log")
	lifecyclePath := filepath.Join(t.TempDir(), "daemon.lease")
	setCleanupTestEnvironment(t, layout)
	installFakeSystemctl(t, commandLog, "")
	plan, err := prepareUninstallCleanup(
		layout,
		"systemd",
		false,
		lifecyclePath,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.close()
	if err := plan.executeServiceArtifacts(); err != nil {
		t.Fatal(err)
	}
	t.Setenv(
		"WG_MIX_EBPF_TEST_SYSTEMCTL_CHAIN_MUTATE_ACTION",
		"daemon-reload",
	)
	t.Setenv(
		"WG_MIX_EBPF_TEST_SYSTEMCTL_CHAIN_MUTATE_PATH",
		serviceTree,
	)

	err = runSystemdManagerReloadAfterServiceArtifactRemoval(
		t.Context(),
		plan,
	)
	if err == nil ||
		(!strings.Contains(err.Error(), "component generation changed") &&
			!strings.Contains(err.Error(), "parent edge no longer names")) {
		t.Fatalf(
			"post-removal manager reload error = %v, want absence-chain rejection",
			err,
		)
	}
	logData, readErr := os.ReadFile(commandLog)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(logData) != "daemon-reload\n" {
		t.Fatalf("post-removal systemctl log = %q", logData)
	}
	if _, statErr := os.Stat(
		filepath.Join(layout.SystemdDir, "wg-mix-ebpf.service"),
	); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("removed systemd unit reappeared: %v", statErr)
	}
}

func TestPostRemovalSystemdReloadSkipsWithoutDeclaredUnit(t *testing.T) {
	commandLog := filepath.Join(t.TempDir(), "systemctl.log")
	installFakeSystemctl(t, commandLog, "")

	if err := runSystemdManagerReloadAfterServiceArtifactRemoval(
		t.Context(),
		&uninstallCleanupPlan{},
	); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(commandLog); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("undeclared unit invoked systemctl: %v", err)
	}
}

func TestPostRemovalSystemdReloadUsesPreflightChainForAlreadyAbsentUnit(
	t *testing.T,
) {
	layout, serviceTree := newServiceExecutionChainLayout(
		t,
		"preflight-absence-chain",
		"systemd",
	)
	unitPath := filepath.Join(layout.SystemdDir, "wg-mix-ebpf.service")
	if err := os.Rename(unitPath, unitPath+".already-absent"); err != nil {
		t.Fatal(err)
	}
	commandLog := filepath.Join(t.TempDir(), "systemctl.log")
	lifecyclePath := filepath.Join(t.TempDir(), "daemon.lease")
	setCleanupTestEnvironment(t, layout)
	installFakeSystemctl(t, commandLog, "")
	plan, err := prepareUninstallCleanup(
		layout,
		"systemd",
		false,
		lifecyclePath,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.close()

	away := serviceTree + ".away"
	if err := os.Rename(serviceTree, away); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(away, serviceTree); err != nil {
		t.Fatal(err)
	}
	err = runSystemdManagerReloadAfterServiceArtifactRemoval(
		t.Context(),
		plan,
	)
	if err == nil ||
		(!strings.Contains(err.Error(), "component generation changed") &&
			!strings.Contains(err.Error(), "parent edge no longer names")) {
		t.Fatalf(
			"preflight absence-chain error = %v, want full-chain rejection",
			err,
		)
	}
	if _, statErr := os.Stat(commandLog); !errors.Is(
		statErr,
		os.ErrNotExist,
	) {
		t.Fatalf("changed preflight absence chain invoked systemctl: %v", statErr)
	}
}

func TestInstalledSystemdRevalidatesAfterMetadataBeforeEachAction(
	t *testing.T,
) {
	tests := []struct {
		name             string
		mutateAtCall     int
		enable           bool
		wantRetainedLink bool
	}{
		{name: "manager reload", mutateAtCall: 1},
		{name: "manager inspection", mutateAtCall: 2},
		{name: "enable link transaction", mutateAtCall: 5, enable: true},
		{
			name:             "enable link commit",
			mutateAtCall:     6,
			enable:           true,
			wantRetainedLink: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			layout, serviceTree := newServiceExecutionChainLayout(
				t,
				"installed-systemd-"+
					strings.ReplaceAll(test.name, " ", "-"),
				"systemd",
			)
			if err := os.Chmod(
				filepath.Join(
					layout.SystemdDir,
					"wg-mix-ebpf.service",
				),
				0o644,
			); err != nil {
				t.Fatal(err)
			}
			if test.enable {
				if err := os.MkdirAll(
					filepath.Join(
						layout.SystemdDir,
						"multi-user.target.wants",
					),
					0o755,
				); err != nil {
					t.Fatal(err)
				}
			}
			commandLog := filepath.Join(t.TempDir(), "systemctl.log")
			setCleanupTestEnvironment(t, layout)
			installFakeSystemctl(t, commandLog, "")
			metadataCalls := 0
			err := runInstalledSystemdServiceCommit(
				t.Context(),
				layout,
				test.enable,
				false,
				func() error {
					metadataCalls++
					if metadataCalls != test.mutateAtCall {
						return nil
					}
					away := serviceTree + ".away"
					if err := os.Rename(serviceTree, away); err != nil {
						return err
					}
					return os.Rename(away, serviceTree)
				},
				func() error { return nil },
			)
			if err == nil ||
				(!strings.Contains(err.Error(), "component generation changed") &&
					!strings.Contains(err.Error(), "parent edge no longer names")) {
				t.Fatalf(
					"installed systemd %s error = %v, want full-chain rejection",
					test.name,
					err,
				)
			}
			if metadataCalls != test.mutateAtCall {
				t.Fatalf(
					"metadata calls = %d, want %d",
					metadataCalls,
					test.mutateAtCall,
				)
			}
			enableLink := filepath.Join(
				layout.SystemdDir,
				"multi-user.target.wants",
				"wg-mix-ebpf.service",
			)
			_, statErr := os.Lstat(enableLink)
			if test.wantRetainedLink && statErr != nil {
				t.Fatalf(
					"post-publication failure did not retain enable evidence: %v",
					statErr,
				)
			}
			if !test.wantRetainedLink && !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf(
					"rejected installed action created enable link: %v",
					statErr,
				)
			}
		})
	}
}

func TestInstalledOpenWrtRevalidatesAfterMetadataBeforeExecution(
	t *testing.T,
) {
	layout, serviceTree := newServiceExecutionChainLayout(
		t,
		"installed-openwrt-metadata",
		"openwrt",
	)
	if err := os.Chmod(
		filepath.Join(layout.OpenWrtInitDir, "wg-mix-ebpf"),
		0o755,
	); err != nil {
		t.Fatal(err)
	}
	metadataCalls := 0
	err := runInstalledOpenWrtServiceAction(
		t.Context(),
		layout,
		"enable",
		func() error {
			metadataCalls++
			away := serviceTree + ".away"
			if err := os.Rename(serviceTree, away); err != nil {
				return err
			}
			return os.Rename(away, serviceTree)
		},
	)
	if err == nil ||
		(!strings.Contains(err.Error(), "component generation changed") &&
			!strings.Contains(err.Error(), "parent edge no longer names")) {
		t.Fatalf(
			"installed OpenWrt metadata-boundary error = %v, "+
				"want full-chain rejection",
			err,
		)
	}
	if metadataCalls != 1 {
		t.Fatalf("metadata calls = %d, want 1", metadataCalls)
	}
}

func TestCleanupOwnMutationsRefreshSharedParentGenerations(t *testing.T) {
	layout := newCleanupTestLayout(t, "shared-parent-success")
	lifecyclePath := filepath.Join(t.TempDir(), "daemon.lease")
	plan, err := prepareUninstallCleanup(
		layout,
		"unknown",
		false,
		lifecyclePath,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.close()
	if err := plan.execute(); err != nil {
		t.Fatalf("owned shared-parent cleanup self-rejected: %v", err)
	}
	for _, path := range []string{layout.RunDir, layout.VarLibDir, layout.PinPath} {
		if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("owned cleanup retained %s: %v", path, statErr)
		}
	}
}

func TestCleanupSharedGenerationRefreshRejectsConcurrentPeerMutation(
	t *testing.T,
) {
	layout := newCleanupTestLayout(t, "shared-parent-concurrent")
	lifecyclePath := filepath.Join(t.TempDir(), "daemon.lease")
	plan, err := prepareUninstallCleanup(
		layout,
		"unknown",
		false,
		lifecyclePath,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.close()
	var runtimePlan, statePlan *cleanupDirectoryPlan
	for _, directory := range plan.directories {
		switch directory.root.spec.name {
		case "runtime dir":
			runtimePlan = directory
		case "state dir":
			statePlan = directory
		}
	}
	if runtimePlan == nil || statePlan == nil {
		t.Fatal("cleanup plan omitted runtime or state directory")
	}
	coordinator := &cleanupDirectoryMutationCoordinator{
		peers: []*cleanupDirectoryPlan{statePlan},
	}
	sharedParent := runtimePlan.root.parent
	if err := coordinator.prepare(sharedParent); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(layout.VarLibDir, "concurrent"),
		[]byte("foreign\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	proof, err := performCleanupDirectoryMutation(
		sharedParent,
		func() error {
			file, err := cleanupCreateFileAt(
				sharedParent,
				"owned-shared-parent-mutation",
				0o600,
			)
			if err != nil {
				return err
			}
			return file.Close()
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.refresh(proof); err == nil ||
		(!strings.Contains(err.Error(), "exact held-parent generation refresh") &&
			!strings.Contains(err.Error(), "directory generation changed")) {
		t.Fatalf(
			"shared generation refresh error = %v, want concurrent peer rejection",
			err,
		)
	}
}

func TestCleanupGenerationRefreshDoesNotAdoptDifferentDirectory(
	t *testing.T,
) {
	layout := newCleanupTestLayout(t, "different-parent")
	lifecyclePath := filepath.Join(t.TempDir(), "daemon.lease")
	plan, err := prepareUninstallCleanup(
		layout,
		"unknown",
		false,
		lifecyclePath,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.close()
	var runtimePlan, statePlan *cleanupDirectoryPlan
	for _, directory := range plan.directories {
		switch directory.root.spec.name {
		case "runtime dir":
			runtimePlan = directory
		case "state dir":
			statePlan = directory
		}
	}
	if runtimePlan == nil || statePlan == nil {
		t.Fatal("cleanup plan omitted runtime or state directory")
	}
	proof, err := performCleanupDirectoryMutation(
		runtimePlan.root.dir,
		func() error {
			file, err := cleanupCreateFileAt(
				runtimePlan.root.dir,
				"owned-runtime-mutation",
				0o600,
			)
			if err != nil {
				return err
			}
			return file.Close()
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	matched, err := refreshManagedCleanupDirGenerationAfterOwnedMutationAtName(
		statePlan.root,
		statePlan.root.name,
		proof,
	)
	if err != nil {
		t.Fatal(err)
	}
	if matched {
		t.Fatal("generation refresh adopted a different held directory object")
	}
	if err := revalidateManagedCleanupDir(statePlan.root); err != nil {
		t.Fatalf("different-directory proof changed peer baseline: %v", err)
	}
}
