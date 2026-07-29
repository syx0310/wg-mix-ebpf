package install

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/syx0310/wg-mix-ebpf/internal/lockfile"
)

func TestInstallPreservesSwappedSystemdEnableLinkAcrossOwnershipAndHookResults(
	t *testing.T,
) {
	ownershipCases := []struct {
		name   string
		marked bool
	}{
		{name: "fresh", marked: false},
		{name: "marked", marked: true},
	}
	hookCases := []struct {
		name        string
		returnError bool
	}{
		{name: "hook-nil", returnError: false},
		{name: "hook-error", returnError: true},
	}

	for _, ownershipCase := range ownershipCases {
		for _, hookCase := range hookCases {
			t.Run(ownershipCase.name+"/"+hookCase.name, func(t *testing.T) {
				var layout paths
				if ownershipCase.marked {
					layout = newCleanupTestLayoutForSystem(
						t,
						"enable-final-"+ownershipCase.name+"-"+hookCase.name,
						"systemd",
					)
					linkPath := systemdEnableLinkPath(layout)
					if err := os.MkdirAll(filepath.Dir(linkPath), 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(systemdEnableLinkTarget, linkPath); err != nil {
						t.Fatal(err)
					}
				} else {
					layout = cleanupTestPaths(
						t.TempDir(),
						"enable-final-"+ownershipCase.name+"-"+hookCase.name,
					)
				}
				setCleanupTestEnvironment(t, layout)
				commandLog := filepath.Join(t.TempDir(), "systemctl.log")
				installFakeSystemctl(t, commandLog, "")
				lifecycleRoot := t.TempDir()
				baseContext := lockfile.WithLifecyclePathsForTest(
					t.Context(),
					filepath.Join(lifecycleRoot, "daemon.lease"),
					filepath.Join(lifecycleRoot, "maintenance.gate"),
				)
				injected := errors.New("injected post-enable-link hook failure")
				linkPath := systemdEnableLinkPath(layout)
				ownedBackup := linkPath + ".owned-before-swap"
				replacementTarget := "../foreign.service"
				var replacementIdentity os.FileInfo
				ctx := context.WithValue(
					baseContext,
					installAfterSystemdEnableLinkHookContextKey{},
					func(path string) error {
						if path != linkPath {
							return fmt.Errorf("unexpected enable link hook path %s", path)
						}
						if target, err := os.Readlink(path); err != nil ||
							target != systemdEnableLinkTarget {
							return fmt.Errorf(
								"pre-swap enable link target=%q err=%v",
								target,
								err,
							)
						}
						if err := os.Rename(path, ownedBackup); err != nil {
							return err
						}
						if err := os.Symlink(replacementTarget, path); err != nil {
							return err
						}
						var err error
						replacementIdentity, err = os.Lstat(path)
						if err != nil {
							return err
						}
						if hookCase.returnError {
							return injected
						}
						return nil
					},
				)

				_, err := Install(ctx, Options{System: "systemd", Enable: true})
				if err == nil {
					t.Fatal("install accepted a swapped systemd enable link")
				}
				if hookCase.returnError {
					if !errors.Is(err, injected) {
						t.Fatalf("install error = %v, want injected hook error", err)
					}
				} else if !strings.Contains(
					err.Error(),
					"revalidate exact systemd enable link inode, UID, and target at commit",
				) {
					t.Fatalf("install error = %v, want final link revalidation", err)
				}

				target, readErr := os.Readlink(linkPath)
				if readErr != nil || target != replacementTarget {
					t.Fatalf(
						"foreign replacement target=%q err=%v",
						target,
						readErr,
					)
				}
				finalReplacementIdentity, statErr := os.Lstat(linkPath)
				if statErr != nil {
					t.Fatal(statErr)
				}
				if replacementIdentity == nil ||
					!os.SameFile(replacementIdentity, finalReplacementIdentity) {
					t.Fatal("rollback deleted or overwrote the foreign replacement link")
				}
				if target, readErr := os.Readlink(ownedBackup); readErr != nil ||
					target != systemdEnableLinkTarget {
					t.Fatalf(
						"displaced owned link target=%q err=%v",
						target,
						readErr,
					)
				}
				assertPublishedSystemdEnableOwnership(t, layout)

				logData, readErr := os.ReadFile(commandLog)
				if readErr != nil {
					t.Fatal(readErr)
				}
				if strings.Contains(string(logData), "enable ") {
					t.Fatalf(
						"link swap invoked name-based systemctl enable: %q",
						logData,
					)
				}
			})
		}
	}
}

func TestInstallRejectsSystemdWantsDirectoryPathReplacementAtCommit(t *testing.T) {
	layout := cleanupTestPaths(t.TempDir(), "enable-wants-path-swap")
	setCleanupTestEnvironment(t, layout)
	commandLog := filepath.Join(t.TempDir(), "systemctl.log")
	installFakeSystemctl(t, commandLog, "")
	lifecycleRoot := t.TempDir()
	baseContext := lockfile.WithLifecyclePathsForTest(
		t.Context(),
		filepath.Join(lifecycleRoot, "daemon.lease"),
		filepath.Join(lifecycleRoot, "maintenance.gate"),
	)
	linkPath := systemdEnableLinkPath(layout)
	wantsDir := filepath.Dir(linkPath)
	displacedWantsDir := wantsDir + ".owned-before-swap"
	foreignTarget := "../foreign.service"
	var replacementIdentity os.FileInfo
	ctx := context.WithValue(
		baseContext,
		installAfterSystemdEnableLinkHookContextKey{},
		func(path string) error {
			if path != linkPath {
				return fmt.Errorf("unexpected enable link hook path %s", path)
			}
			if err := os.Rename(wantsDir, displacedWantsDir); err != nil {
				return err
			}
			if err := os.Mkdir(wantsDir, 0o700); err != nil {
				return err
			}
			if err := os.Symlink(foreignTarget, linkPath); err != nil {
				return err
			}
			var err error
			replacementIdentity, err = os.Lstat(linkPath)
			return err
		},
	)

	_, err := Install(ctx, Options{System: "systemd", Enable: true})
	if err == nil || !strings.Contains(
		err.Error(),
		"revalidate held systemd wants directory at commit",
	) {
		t.Fatalf("install error = %v, want final wants-directory rejection", err)
	}
	if !strings.Contains(err.Error(), "published ownership manifest retains path") {
		t.Fatalf("install error lacks incomplete rollback audit record: %v", err)
	}
	target, readErr := os.Readlink(linkPath)
	if readErr != nil || target != foreignTarget {
		t.Fatalf("foreign replacement target=%q err=%v", target, readErr)
	}
	finalReplacementIdentity, statErr := os.Lstat(linkPath)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if replacementIdentity == nil ||
		!os.SameFile(replacementIdentity, finalReplacementIdentity) {
		t.Fatal("rollback deleted or overwrote the foreign wants-directory link")
	}
	if _, statErr := os.Lstat(
		filepath.Join(displacedWantsDir, filepath.Base(linkPath)),
	); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("descriptor-bound rollback retained its exact created link: %v", statErr)
	}
	entries, readDirErr := os.ReadDir(displacedWantsDir)
	if readDirErr != nil {
		t.Fatal(readDirErr)
	}
	if len(entries) != 0 {
		t.Fatalf("displaced wants directory retained unexpected entries: %#v", entries)
	}
	assertPublishedSystemdEnableOwnership(t, layout)
}

func TestSystemdEnableRollbackRestoreFailureRetainsForeignAndQuarantine(
	t *testing.T,
) {
	layout := newCleanupTestLayoutForSystem(
		t,
		"enable-restore-quarantine",
		"systemd",
	)
	linkPath := systemdEnableLinkPath(layout)
	wantsDir := filepath.Dir(linkPath)
	if err := os.MkdirAll(wantsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	foreignTarget := "../foreign.service"
	if err := os.Symlink(foreignTarget, linkPath); err != nil {
		t.Fatal(err)
	}
	quarantineName := ".wg-mix-ebpf-quarantine-auditable"
	quarantinePath := filepath.Join(wantsDir, quarantineName)
	if err := os.Symlink(systemdEnableLinkTarget, quarantinePath); err != nil {
		t.Fatal(err)
	}
	parent, exists, err := openDeclaredArtifactParent(
		wantsDir,
		"/etc/systemd/system/multi-user.target.wants",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("wants directory unexpectedly absent")
	}
	defer parent.close()

	err = restoreCleanupQuarantine(
		parent.dir,
		quarantineName,
		filepath.Base(linkPath),
		linkPath,
	)
	if err == nil || !strings.Contains(err.Error(), quarantinePath) {
		t.Fatalf("restore error = %v, want exact retained quarantine path", err)
	}
	if target, readErr := os.Readlink(linkPath); readErr != nil ||
		target != foreignTarget {
		t.Fatalf("foreign link target=%q err=%v", target, readErr)
	}
	if target, readErr := os.Readlink(quarantinePath); readErr != nil ||
		target != systemdEnableLinkTarget {
		t.Fatalf("quarantined owned link target=%q err=%v", target, readErr)
	}
	assertPublishedSystemdEnableOwnership(t, layout)
}

func assertPublishedSystemdEnableOwnership(t *testing.T, layout paths) {
	t.Helper()
	data, err := os.ReadFile(cleanupManifestPath(layout))
	if err != nil {
		t.Fatalf("read published cleanup ownership: %v", err)
	}
	manifest, err := decodeCleanupManifest(data)
	if err != nil {
		t.Fatalf("decode published cleanup ownership: %v", err)
	}
	if err := manifest.validateAgainst(layout, "systemd"); err != nil {
		t.Fatalf("validate published cleanup ownership: %v", err)
	}
	for _, artifact := range manifest.Artifacts {
		if artifact.Kind == systemdEnableLinkKind {
			if artifact.Path != systemdEnableLinkPath(layout) ||
				artifact.Target != systemdEnableLinkTarget {
				t.Fatalf("published enable ownership = %#v", artifact)
			}
			return
		}
	}
	t.Fatal("published cleanup ownership lacks the systemd enable link")
}
