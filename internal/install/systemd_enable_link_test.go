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

func TestInstallRejectsMissingSystemdWantsDirectoryWithoutCreatingIt(t *testing.T) {
	layout := cleanupTestPaths(t.TempDir(), "enable-missing-wants")
	setCleanupTestEnvironment(t, layout)
	installFakeSystemctl(t, filepath.Join(t.TempDir(), "systemctl.log"), "")

	wantsDir := filepath.Dir(systemdEnableLinkPath(layout))
	_, err := Install(
		systemdEnableTestContext(t),
		Options{System: "systemd", Enable: true},
	)
	if err == nil || !strings.Contains(
		err.Error(),
		"declared wants directory",
	) || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("install error = %v, want missing wants-directory rejection", err)
	}
	if _, statErr := os.Stat(wantsDir); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("enable transaction created missing wants directory: %v", statErr)
	}
	assertPublishedSystemdEnableOwnership(t, layout)
}

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
				} else {
					layout = cleanupTestPaths(
						t.TempDir(),
						"enable-final-"+ownershipCase.name+"-"+hookCase.name,
					)
				}
				linkPath := prepareSystemdWantsDirectory(t, layout)
				if ownershipCase.marked {
					if err := os.Symlink(systemdEnableLinkTarget, linkPath); err != nil {
						t.Fatal(err)
					}
				}
				setCleanupTestEnvironment(t, layout)
				commandLog := filepath.Join(t.TempDir(), "systemctl.log")
				installFakeSystemctl(t, commandLog, "")

				injected := errors.New("injected post-enable-link hook failure")
				ownedBackup := linkPath + ".owned-before-swap"
				replacementTarget := "../foreign.service"
				var replacementIdentity os.FileInfo
				ctx := context.WithValue(
					systemdEnableTestContext(t),
					installAfterSystemdEnableLinkHookContextKey{},
					func(path string) error {
						if path != linkPath {
							return fmt.Errorf("unexpected enable link hook path %s", path)
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
				if hookCase.returnError && !errors.Is(err, injected) {
					t.Fatalf("install error = %v, want injected hook error", err)
				}
				assertNonDestructiveRetentionError(t, err, linkPath)
				assertSameSymlink(
					t,
					linkPath,
					replacementTarget,
					replacementIdentity,
					"foreign replacement",
				)
				assertSymlinkTarget(t, ownedBackup, systemdEnableLinkTarget)
				assertPublishedSystemdEnableOwnership(t, layout)

				logData, readErr := os.ReadFile(commandLog)
				if readErr != nil {
					t.Fatal(readErr)
				}
				if strings.Contains(string(logData), "enable ") {
					t.Fatalf("link swap invoked name-based systemctl enable: %q", logData)
				}
			})
		}
	}
}

func TestInstallRejectsSystemdWantsDirectoryPathReplacementAtCommit(t *testing.T) {
	layout := cleanupTestPaths(t.TempDir(), "enable-wants-path-swap")
	linkPath := prepareSystemdWantsDirectory(t, layout)
	setCleanupTestEnvironment(t, layout)
	installFakeSystemctl(t, filepath.Join(t.TempDir(), "systemctl.log"), "")

	wantsDir := filepath.Dir(linkPath)
	displacedWantsDir := wantsDir + ".owned-before-swap"
	foreignTarget := "../foreign.service"
	var replacementIdentity os.FileInfo
	ctx := context.WithValue(
		systemdEnableTestContext(t),
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
		"revalidate held systemd wants directory from declared root at commit",
	) {
		t.Fatalf("install error = %v, want wants-directory edge rejection", err)
	}
	assertNonDestructiveRetentionError(t, err, linkPath)
	assertSameSymlink(t, linkPath, foreignTarget, replacementIdentity, "foreign replacement")
	assertSymlinkTarget(
		t,
		filepath.Join(displacedWantsDir, filepath.Base(linkPath)),
		systemdEnableLinkTarget,
	)
	assertPublishedSystemdEnableOwnership(t, layout)
}

func TestInstallRejectsPersistentHighAncestorSystemdTreeReplacementAtCommit(
	t *testing.T,
) {
	root := t.TempDir()
	layout := cleanupTestPaths(root, "enable-high-ancestor-swap")
	serviceTree := filepath.Join(root, "service-tree")
	layout.SystemdDir = filepath.Join(serviceTree, "systemd")
	linkPath := prepareSystemdWantsDirectory(t, layout)
	setCleanupTestEnvironment(t, layout)
	installFakeSystemctl(t, filepath.Join(t.TempDir(), "systemctl.log"), "")

	displacedTree := serviceTree + ".owned-before-swap"
	foreignTarget := "../foreign.service"
	var replacementIdentity os.FileInfo
	ctx := context.WithValue(
		systemdEnableTestContext(t),
		installAfterSystemdEnableLinkHookContextKey{},
		func(path string) error {
			if path != linkPath {
				return fmt.Errorf("unexpected enable link hook path %s", path)
			}
			if err := os.Rename(serviceTree, displacedTree); err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(linkPath), 0o700); err != nil {
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
	if err == nil || !strings.Contains(err.Error(), "parent edge no longer names held component") {
		t.Fatalf("install error = %v, want high-ancestor edge rejection", err)
	}
	assertNonDestructiveRetentionError(t, err, linkPath)
	assertSameSymlink(t, linkPath, foreignTarget, replacementIdentity, "foreign replacement")
	assertSymlinkTarget(
		t,
		filepath.Join(
			displacedTree,
			"systemd",
			"multi-user.target.wants",
			filepath.Base(linkPath),
		),
		systemdEnableLinkTarget,
	)
	assertPublishedSystemdEnableOwnership(t, layout)
}

func TestInstallRejectsHighAncestorSwapInsideSecondDeclaredWalk(t *testing.T) {
	root := t.TempDir()
	layout := cleanupTestPaths(root, "enable-second-walk-swap")
	serviceTree := filepath.Join(root, "service-tree")
	layout.SystemdDir = filepath.Join(serviceTree, "systemd")
	linkPath := prepareSystemdWantsDirectory(t, layout)
	canonicalServiceTree, err := filepath.EvalSymlinks(serviceTree)
	if err != nil {
		t.Fatal(err)
	}
	setCleanupTestEnvironment(t, layout)
	installFakeSystemctl(t, filepath.Join(t.TempDir(), "systemctl.log"), "")

	displacedTree := serviceTree + ".opened-before-swap"
	foreignTarget := "../foreign.service"
	var replacementIdentity os.FileInfo
	hookRan := false
	var openedPaths []string
	ctx := context.WithValue(
		systemdEnableTestContext(t),
		installAfterSystemdEnableCommitWalkOpenHookContextKey{},
		func(openedPath string) error {
			openedPaths = append(openedPaths, openedPath)
			if hookRan || filepath.Clean(openedPath) != filepath.Clean(canonicalServiceTree) {
				return nil
			}
			hookRan = true
			if err := os.Rename(serviceTree, displacedTree); err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(linkPath), 0o700); err != nil {
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

	_, err = Install(ctx, Options{System: "systemd", Enable: true})
	if !hookRan {
		t.Fatalf(
			"second declared walk did not expose the high-ancestor hook; err=%v opened=%v want=%s",
			err,
			openedPaths,
			canonicalServiceTree,
		)
	}
	if err == nil || !strings.Contains(err.Error(), "parent edge no longer names held component") {
		t.Fatalf("install error = %v, want complete edge-chain rejection", err)
	}
	assertNonDestructiveRetentionError(t, err, linkPath)
	assertSameSymlink(t, linkPath, foreignTarget, replacementIdentity, "foreign replacement")
	assertSymlinkTarget(
		t,
		filepath.Join(
			displacedTree,
			"systemd",
			"multi-user.target.wants",
			filepath.Base(linkPath),
		),
		systemdEnableLinkTarget,
	)
}

func TestSystemdEnableFailureRetentionHasNoCheckThenUnlinkOrBlindRestore(
	t *testing.T,
) {
	tests := []struct {
		name       string
		ownedPath  func(string) string
		errorLabel string
	}{
		{
			name: "check-to-unlink-race",
			ownedPath: func(linkPath string) string {
				return linkPath + ".owned-after-check"
			},
			errorLabel: "check-to-unlink",
		},
		{
			name: "quarantine-name-swap",
			ownedPath: func(linkPath string) string {
				return filepath.Join(
					filepath.Dir(linkPath),
					".wg-mix-ebpf-quarantine-retention-test",
				)
			},
			errorLabel: "quarantine-name",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			layout := cleanupTestPaths(t.TempDir(), "enable-retain-"+test.name)
			linkPath := prepareSystemdWantsDirectory(t, layout)
			setCleanupTestEnvironment(t, layout)
			installFakeSystemctl(t, filepath.Join(t.TempDir(), "systemctl.log"), "")

			rollbackCause := errors.New("force non-destructive retention")
			foreignTarget := "../foreign.service"
			ownedPath := test.ownedPath(linkPath)
			var ownedIdentity os.FileInfo
			var foreignIdentity os.FileInfo
			retentionHookRan := false
			ctx := context.WithValue(
				systemdEnableTestContext(t),
				installAfterSystemdEnableLinkHookContextKey{},
				func(path string) error {
					if path != linkPath {
						return fmt.Errorf("unexpected enable link hook path %s", path)
					}
					var err error
					ownedIdentity, err = os.Lstat(path)
					if err != nil {
						return err
					}
					return rollbackCause
				},
			)
			ctx = context.WithValue(
				ctx,
				installAfterSystemdEnableRetentionCheckHookContextKey{},
				func(path string) error {
					retentionHookRan = true
					if path != linkPath {
						return fmt.Errorf("unexpected retention hook path %s", path)
					}
					if err := os.Rename(path, ownedPath); err != nil {
						return err
					}
					if err := os.Symlink(foreignTarget, path); err != nil {
						return err
					}
					var err error
					foreignIdentity, err = os.Lstat(path)
					return err
				},
			)

			_, err := Install(ctx, Options{System: "systemd", Enable: true})
			if !errors.Is(err, rollbackCause) {
				t.Fatalf("install error = %v, want retention cause", err)
			}
			if !retentionHookRan {
				t.Fatalf("%s retention hook did not run", test.errorLabel)
			}
			assertNonDestructiveRetentionError(t, err, linkPath)
			assertSameSymlink(
				t,
				linkPath,
				foreignTarget,
				foreignIdentity,
				"foreign replacement",
			)
			assertSameSymlink(
				t,
				ownedPath,
				systemdEnableLinkTarget,
				ownedIdentity,
				"transaction-owned retained link",
			)
			assertPublishedSystemdEnableOwnership(t, layout)
		})
	}
}

func TestOpenOrCreateDeclaredArtifactParentConcurrentEEXISTIsNotOwned(
	t *testing.T,
) {
	parentPath := filepath.Join(t.TempDir(), "artifact-parent")
	foreignPath := filepath.Join(parentPath, "foreign.keep")
	var parentIdentity os.FileInfo
	parent, created, err := openOrCreateDeclaredArtifactParent(
		parentPath,
		parentPath,
		func(path string) error {
			if path != parentPath {
				return fmt.Errorf("unexpected pre-create path %s", path)
			}
			if err := os.Mkdir(path, 0o700); err != nil {
				return err
			}
			if err := os.WriteFile(foreignPath, []byte("foreign\n"), 0o600); err != nil {
				return err
			}
			var err error
			parentIdentity, err = os.Stat(path)
			return err
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.close()
	if created {
		t.Fatal("concurrent EEXIST directory was reported transaction-created")
	}
	finalIdentity, err := os.Stat(parentPath)
	if err != nil {
		t.Fatal(err)
	}
	if parentIdentity == nil || !os.SameFile(parentIdentity, finalIdentity) {
		t.Fatal("descriptor walk did not retain the concurrent directory")
	}
	if data, err := os.ReadFile(foreignPath); err != nil || string(data) != "foreign\n" {
		t.Fatalf("foreign content=%q err=%v", data, err)
	}
	if err := revalidateManagedCleanupDir(parent); err != nil {
		t.Fatalf("revalidate concurrent directory chain: %v", err)
	}
}

func TestDeclaredWalkRejectsSystemRootSwapAfterOpeningIt(t *testing.T) {
	outer := t.TempDir()
	systemRoot := filepath.Join(outer, "declared-system-root")
	artifactParent := filepath.Join(systemRoot, "artifact-parent")
	if err := os.MkdirAll(artifactParent, 0o700); err != nil {
		t.Fatal(err)
	}
	canonicalRoot, err := filepath.EvalSymlinks(systemRoot)
	if err != nil {
		t.Fatal(err)
	}
	displacedRoot := systemRoot + ".opened-before-swap"
	hookRan := false
	dir, exists, _, err := openExactDeclaredDirectoryWithOptions(
		cleanupPathSpec{
			name:        "service artifact directory",
			path:        artifactParent,
			defaultPath: artifactParent,
			systemRoot:  systemRoot,
		},
		exactDeclaredDirectoryOpenOptions{
			afterOpen: func(openedPath string) error {
				if hookRan || filepath.Clean(openedPath) != filepath.Clean(canonicalRoot) {
					return nil
				}
				hookRan = true
				if err := os.Rename(systemRoot, displacedRoot); err != nil {
					return err
				}
				return os.MkdirAll(artifactParent, 0o700)
			},
		},
	)
	if dir != nil {
		_ = dir.close()
	}
	if exists {
		t.Fatal("declared walk accepted a swapped systemRoot")
	}
	if !hookRan {
		t.Fatal("declared walk did not expose systemRoot after-open boundary")
	}
	if err == nil || !strings.Contains(err.Error(), "parent edge no longer names held component") {
		t.Fatalf("declared walk error = %v, want systemRoot parent-edge rejection", err)
	}
	for _, path := range []string{
		filepath.Join(displacedRoot, "artifact-parent"),
		artifactParent,
	} {
		if info, statErr := os.Stat(path); statErr != nil || !info.IsDir() {
			t.Fatalf("systemRoot swap evidence missing at %s: %v", path, statErr)
		}
	}
}

func TestDeclaredWalkBindsCanonicalSystemRootAlias(t *testing.T) {
	outer := t.TempDir()
	realRoot := filepath.Join(outer, "real-root")
	replacementRoot := filepath.Join(outer, "replacement-root")
	for _, root := range []string{realRoot, replacementRoot} {
		if err := os.MkdirAll(filepath.Join(root, "artifact-parent"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	canonicalRealRoot, err := filepath.EvalSymlinks(realRoot)
	if err != nil {
		t.Fatal(err)
	}
	aliasRoot := filepath.Join(outer, "declared-root-alias")
	if err := os.Symlink(realRoot, aliasRoot); err != nil {
		t.Fatal(err)
	}
	originalAlias := aliasRoot + ".opened-before-swap"
	hookRan := false
	dir, exists, _, err := openExactDeclaredDirectoryWithOptions(
		cleanupPathSpec{
			name:        "service artifact directory",
			path:        filepath.Join(aliasRoot, "artifact-parent"),
			defaultPath: filepath.Join(aliasRoot, "artifact-parent"),
			systemRoot:  aliasRoot,
		},
		exactDeclaredDirectoryOpenOptions{
			afterOpen: func(openedPath string) error {
				if hookRan || filepath.Clean(openedPath) != filepath.Clean(canonicalRealRoot) {
					return nil
				}
				hookRan = true
				if err := os.Rename(aliasRoot, originalAlias); err != nil {
					return err
				}
				return os.Symlink(replacementRoot, aliasRoot)
			},
		},
	)
	if dir != nil {
		_ = dir.close()
	}
	if exists {
		t.Fatal("declared walk accepted a replaced canonical root alias")
	}
	if !hookRan {
		t.Fatal("declared walk did not open the canonical root component")
	}
	if err == nil || !strings.Contains(err.Error(), "canonical root changed") {
		t.Fatalf("declared walk error = %v, want canonical-root rejection", err)
	}
	for path, want := range map[string]string{
		aliasRoot:     replacementRoot,
		originalAlias: realRoot,
	} {
		target, readErr := os.Readlink(path)
		if readErr != nil || target != want {
			t.Fatalf("alias %s target=%q err=%v, want %q", path, target, readErr, want)
		}
	}
}

func TestDeclaredRootWalkAllowsPinnedMountTransitionsThroughSystemRoot(t *testing.T) {
	parentIdentity := cleanupIdentity{MountKnown: true, MountID: 101}
	childIdentity := cleanupIdentity{MountKnown: true, MountID: 202}
	if parentIdentity.sameMount(childIdentity) {
		t.Fatal("test identities unexpectedly share a mount")
	}

	const rootDepth = 3
	for edgeIndex := 0; edgeIndex < rootDepth; edgeIndex++ {
		if !declaredDirectoryEdgeMayCrossMount(edgeIndex, rootDepth) {
			t.Fatalf(
				"canonical root edge %d/%d rejected an ordinary mount transition",
				edgeIndex,
				rootDepth,
			)
		}
	}
	if declaredDirectoryEdgeMayCrossMount(rootDepth, rootDepth) {
		t.Fatal("artifact-relative edge unexpectedly permits a mount transition")
	}
}

func TestSystemdEnableDefaultParentUsesDeclaredSystemRoot(t *testing.T) {
	spec, err := declaredArtifactPathSpec(
		systemdEnableLinkDefaultParent,
		systemdEnableLinkDefaultParent,
	)
	if err != nil {
		t.Fatal(err)
	}
	if spec.path != systemdEnableLinkDefaultParent ||
		spec.defaultPath != systemdEnableLinkDefaultParent ||
		spec.systemRoot != filepath.Dir(systemdEnableLinkDefaultParent) {
		t.Fatalf("default systemd wants spec = %#v", spec)
	}
}

func systemdEnableTestContext(t *testing.T) context.Context {
	t.Helper()
	lifecycleRoot := t.TempDir()
	return lockfile.WithLifecyclePathsForTest(
		t.Context(),
		filepath.Join(lifecycleRoot, "daemon.lease"),
		filepath.Join(lifecycleRoot, "maintenance.gate"),
	)
}

func prepareSystemdWantsDirectory(t *testing.T, layout paths) string {
	t.Helper()
	linkPath := systemdEnableLinkPath(layout)
	if err := os.MkdirAll(filepath.Dir(linkPath), 0o700); err != nil {
		t.Fatal(err)
	}
	return linkPath
}

func assertNonDestructiveRetentionError(t *testing.T, err error, path string) {
	t.Helper()
	for _, want := range []string{
		"retained evidence without rename, unlink, restore, or rmdir",
		"original declared path " + path,
		"current status",
		"automatic cleanup is not authorized",
		"manually inspect and resolve",
	} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("retention error = %v, want %q", err, want)
		}
	}
}

func assertSymlinkTarget(t *testing.T, path string, want string) {
	t.Helper()
	target, err := os.Readlink(path)
	if err != nil || target != want {
		t.Fatalf("symlink %s target=%q err=%v, want %q", path, target, err, want)
	}
}

func assertSameSymlink(
	t *testing.T,
	path string,
	wantTarget string,
	wantIdentity os.FileInfo,
	label string,
) {
	t.Helper()
	assertSymlinkTarget(t, path, wantTarget)
	finalIdentity, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if wantIdentity == nil || !os.SameFile(wantIdentity, finalIdentity) {
		t.Fatalf("%s identity changed", label)
	}
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
