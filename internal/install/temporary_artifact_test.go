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

func forceExclusiveNamedObjectBoundStages(t *testing.T) *uint32 {
	t.Helper()
	originalAnonymous := createAnonymousObjectBoundFileAt
	originalExclusive := createExclusiveObjectBoundFileAt
	var creationMode uint32
	createAnonymousObjectBoundFileAt = func(
		*cleanupDirFD,
		uint32,
	) (*os.File, error) {
		return nil, errObjectBoundFreshFileUnsupported
	}
	createExclusiveObjectBoundFileAt = func(
		parent *cleanupDirFD,
		name string,
		mode uint32,
	) (*os.File, error) {
		creationMode = mode
		return cleanupCreateFileAt(parent, name, mode)
	}
	t.Cleanup(func() {
		createAnonymousObjectBoundFileAt = originalAnonymous
		createExclusiveObjectBoundFileAt = originalExclusive
	})
	return &creationMode
}

func TestObjectBoundFreshPublicationFallsBackToExclusiveNamedStage(
	t *testing.T,
) {
	creationMode := forceExclusiveNamedObjectBoundStages(t)
	parentPath := filepath.Join(t.TempDir(), "publication-parent")
	if err := os.Mkdir(parentPath, 0o700); err != nil {
		t.Fatal(err)
	}
	parent, exists, err := openDeclaredArtifactParent(parentPath, parentPath)
	if err != nil || !exists {
		t.Fatalf("open publication parent: exists=%t err=%v", exists, err)
	}
	defer parent.close()

	finalPath := filepath.Join(parentPath, "artifact")
	var stagePath string
	result, err := publishObjectBoundFreshFile(objectBoundFreshFileSpec{
		parent:  parent,
		name:    filepath.Base(finalPath),
		path:    finalPath,
		kind:    "test artifact",
		mode:    0o644,
		content: []byte("owned\n"),
		beforePublish: func(state objectBoundFreshFileHookState) error {
			stagePath = state.NamedStage
			if filepath.Dir(stagePath) != parentPath ||
				!strings.HasPrefix(
					filepath.Base(stagePath),
					objectBoundNamedStagePrefix,
				) {
				return fmt.Errorf("unsafe fallback stage path %q", stagePath)
			}
			info, err := os.Stat(stagePath)
			if err != nil {
				return err
			}
			if info.Mode().Perm() != 0o644 || state.HeldIdentity.Links != 1 {
				return fmt.Errorf(
					"fallback stage mode=%#o links=%d, want 0644 and 1",
					info.Mode().Perm(),
					state.HeldIdentity.Links,
				)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := result.file.Close(); err != nil {
		t.Fatal(err)
	}
	if *creationMode != 0o600 {
		t.Fatalf("exclusive stage creation mode = %#o, want 0600", *creationMode)
	}
	if stagePath == "" {
		t.Fatal("exclusive fallback did not expose its reviewed stage path")
	}
	if _, err := os.Lstat(stagePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("published fallback retained its stage name: %v", err)
	}
	data, err := os.ReadFile(finalPath)
	if err != nil || string(data) != "owned\n" {
		t.Fatalf("fallback final data=%q err=%v", data, err)
	}
	info, err := os.Stat(finalPath)
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("fallback final mode=%v err=%v, want 0644", info, err)
	}
	if err := revalidateManagedCleanupDir(parent); err != nil {
		t.Fatalf("fallback did not refresh held parent: %v", err)
	}
}

func TestExclusiveNamedStageReplacementIsNeverPublishedOrDeleted(
	t *testing.T,
) {
	forceExclusiveNamedObjectBoundStages(t)
	parentPath := filepath.Join(t.TempDir(), "publication-parent")
	if err := os.Mkdir(parentPath, 0o700); err != nil {
		t.Fatal(err)
	}
	parent, exists, err := openDeclaredArtifactParent(parentPath, parentPath)
	if err != nil || !exists {
		t.Fatalf("open publication parent: exists=%t err=%v", exists, err)
	}
	defer parent.close()

	finalPath := filepath.Join(parentPath, "artifact")
	var stagePath string
	var ownedAway string
	_, err = publishObjectBoundFreshFile(objectBoundFreshFileSpec{
		parent:  parent,
		name:    filepath.Base(finalPath),
		path:    finalPath,
		kind:    "test artifact",
		mode:    0o600,
		content: []byte("owned\n"),
		beforePublish: func(state objectBoundFreshFileHookState) error {
			stagePath = state.NamedStage
			ownedAway = stagePath + ".owned-away"
			if err := os.Rename(stagePath, ownedAway); err != nil {
				return err
			}
			return os.WriteFile(stagePath, []byte("foreign\n"), 0o600)
		},
	})
	if err == nil || !strings.Contains(err.Error(), "retained at") {
		t.Fatalf("stage replacement error = %v, want fail-closed retention", err)
	}
	if _, statErr := os.Lstat(finalPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("stage replacement reached final path: %v", statErr)
	}
	for path, want := range map[string]string{
		stagePath: "foreign\n",
		ownedAway: "owned\n",
	} {
		data, readErr := os.ReadFile(path)
		if readErr != nil || string(data) != want {
			t.Fatalf("retained evidence %s data=%q err=%v, want %q", path, data, readErr, want)
		}
	}
}

func TestObjectBoundFreshPublicationRejectsUnsafeNameAndDisplayPath(t *testing.T) {
	parentPath := filepath.Join(t.TempDir(), "publication-parent")
	if err := os.Mkdir(parentPath, 0o700); err != nil {
		t.Fatal(err)
	}
	parent, exists, err := openDeclaredArtifactParent(parentPath, parentPath)
	if err != nil || !exists {
		t.Fatalf("open publication parent: exists=%t err=%v", exists, err)
	}
	defer parent.close()

	for _, test := range []struct {
		name         string
		artifactName string
		displayPath  string
	}{
		{
			name:         "parent traversal",
			artifactName: "../artifact",
			displayPath:  filepath.Join(parentPath, "..", "artifact"),
		},
		{
			name:         "nested component",
			artifactName: filepath.Join("nested", "artifact"),
			displayPath:  filepath.Join(parentPath, "nested", "artifact"),
		},
		{
			name:         "different basename",
			artifactName: "artifact",
			displayPath:  filepath.Join(parentPath, "other"),
		},
		{
			name:         "non-clean display",
			artifactName: "artifact",
			displayPath:  parentPath + string(os.PathSeparator) + "nested/../artifact",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			hookCalled := false
			_, err := publishObjectBoundFreshFile(objectBoundFreshFileSpec{
				parent:  parent,
				name:    test.artifactName,
				path:    test.displayPath,
				kind:    "test artifact",
				mode:    0o600,
				content: []byte("owned\n"),
				beforePublish: func(objectBoundFreshFileHookState) error {
					hookCalled = true
					return nil
				},
			})
			if err == nil {
				t.Fatal("unsafe publication spec was accepted")
			}
			if hookCalled {
				t.Fatal("unsafe publication spec reached the publication hook")
			}
		})
	}
	entries, err := os.ReadDir(parentPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("unsafe publication specs created entries: %v", entries)
	}
}

func TestObjectBoundFreshPublicationPreservesForeignNamedObjects(t *testing.T) {
	parentPath := filepath.Join(t.TempDir(), "publication-parent")
	if err := os.Mkdir(parentPath, 0o700); err != nil {
		t.Fatal(err)
	}
	openParent := func() *managedCleanupDir {
		t.Helper()
		parent, exists, err := openDeclaredArtifactParent(parentPath, parentPath)
		if err != nil {
			t.Fatal(err)
		}
		if !exists {
			t.Fatal("publication parent is missing")
		}
		return parent
	}

	finalPath := filepath.Join(parentPath, "artifact")
	foreignStage := filepath.Join(parentPath, ".artifact.foreign-stage")
	parent := openParent()
	_, err := publishObjectBoundFreshFile(objectBoundFreshFileSpec{
		parent:  parent,
		name:    filepath.Base(finalPath),
		path:    finalPath,
		kind:    "test artifact",
		mode:    0o600,
		content: []byte("owned\n"),
		beforePublish: func(state objectBoundFreshFileHookState) error {
			if state.NamedStage == foreignStage {
				return errors.New("publisher reused a foreign stage name")
			}
			return os.WriteFile(foreignStage, []byte("foreign\n"), 0o600)
		},
	})
	if err == nil || !strings.Contains(err.Error(), "component generation changed") {
		t.Fatalf("publication error = %v, want foreign-stage generation rejection", err)
	}
	if closeErr := parent.close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if _, statErr := os.Lstat(finalPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed publication created final path: %v", statErr)
	}
	if data, readErr := os.ReadFile(foreignStage); readErr != nil ||
		string(data) != "foreign\n" {
		t.Fatalf("foreign stage changed: data=%q err=%v", data, readErr)
	}

	parent = openParent()
	result, err := publishObjectBoundFreshFile(objectBoundFreshFileSpec{
		parent:  parent,
		name:    filepath.Base(finalPath),
		path:    finalPath,
		kind:    "test artifact",
		mode:    0o600,
		content: []byte("owned\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := result.file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := parent.close(); err != nil {
		t.Fatal(err)
	}
	if data, readErr := os.ReadFile(finalPath); readErr != nil ||
		string(data) != "owned\n" {
		t.Fatalf("published artifact data=%q err=%v", data, readErr)
	}
	if data, readErr := os.ReadFile(foreignStage); readErr != nil ||
		string(data) != "foreign\n" {
		t.Fatalf("retry changed foreign stage: data=%q err=%v", data, readErr)
	}
}

func TestObjectBoundFreshPublicationNeverOverwritesHookInsertedFinal(t *testing.T) {
	parentPath := filepath.Join(t.TempDir(), "publication-parent")
	if err := os.Mkdir(parentPath, 0o700); err != nil {
		t.Fatal(err)
	}
	parent, exists, err := openDeclaredArtifactParent(parentPath, parentPath)
	if err != nil || !exists {
		t.Fatalf("open publication parent: exists=%t err=%v", exists, err)
	}
	defer parent.close()

	finalPath := filepath.Join(parentPath, "artifact")
	_, err = publishObjectBoundFreshFile(objectBoundFreshFileSpec{
		parent:  parent,
		name:    filepath.Base(finalPath),
		path:    finalPath,
		kind:    "test artifact",
		mode:    0o600,
		content: []byte("owned\n"),
		beforePublish: func(objectBoundFreshFileHookState) error {
			return os.WriteFile(finalPath, []byte("foreign\n"), 0o600)
		},
	})
	if err == nil {
		t.Fatal("publication overwrote a hook-inserted final")
	}
	if data, readErr := os.ReadFile(finalPath); readErr != nil ||
		string(data) != "foreign\n" {
		t.Fatalf("hook-inserted final changed: data=%q err=%v", data, readErr)
	}
}

func TestObjectBoundPostLinkFailureRetainsPublishedFinalWithAudit(t *testing.T) {
	parentPath := filepath.Join(t.TempDir(), "publication-parent")
	if err := os.Mkdir(parentPath, 0o700); err != nil {
		t.Fatal(err)
	}
	parent, exists, err := openDeclaredArtifactParent(parentPath, parentPath)
	if err != nil || !exists {
		t.Fatalf("open publication parent: exists=%t err=%v", exists, err)
	}
	defer parent.close()

	finalPath := filepath.Join(parentPath, "artifact")
	injected := errors.New("fail after object-bound link")
	_, err = publishObjectBoundFreshFile(objectBoundFreshFileSpec{
		parent:  parent,
		name:    filepath.Base(finalPath),
		path:    finalPath,
		kind:    "test artifact",
		mode:    0o600,
		content: []byte("owned\n"),
		afterPublish: func(objectBoundFreshFileHookState) error {
			return injected
		},
	})
	if !errors.Is(err, injected) ||
		!strings.Contains(err.Error(), "final "+finalPath+" was published") ||
		!strings.Contains(err.Error(), "no automatic unlink, rollback") {
		t.Fatalf("post-link error = %v, want non-destructive published-final audit", err)
	}
	if data, readErr := os.ReadFile(finalPath); readErr != nil ||
		string(data) != "owned\n" {
		t.Fatalf("published final data=%q err=%v", data, readErr)
	}
}

func TestObjectBoundPostLinkMutationAndErrorStillValidatesFinal(t *testing.T) {
	parentPath := filepath.Join(t.TempDir(), "publication-parent")
	if err := os.Mkdir(parentPath, 0o700); err != nil {
		t.Fatal(err)
	}
	parent, exists, err := openDeclaredArtifactParent(parentPath, parentPath)
	if err != nil || !exists {
		t.Fatalf("open publication parent: exists=%t err=%v", exists, err)
	}
	defer parent.close()

	finalPath := filepath.Join(parentPath, "artifact")
	injected := errors.New("fail after mutating object-bound final")
	_, err = publishObjectBoundFreshFile(objectBoundFreshFileSpec{
		parent:  parent,
		name:    filepath.Base(finalPath),
		path:    finalPath,
		kind:    "test artifact",
		mode:    0o600,
		content: []byte("owned\n"),
		afterPublish: func(objectBoundFreshFileHookState) error {
			if err := os.WriteFile(finalPath, []byte("other\n"), 0o600); err != nil {
				return err
			}
			return injected
		},
	})
	if !errors.Is(err, injected) ||
		!strings.Contains(err.Error(), "bytes or content hash changed") ||
		!strings.Contains(err.Error(), "no automatic unlink, rollback") {
		t.Fatalf(
			"post-link mutation error = %v, want hook, content, and retention errors",
			err,
		)
	}
	if data, readErr := os.ReadFile(finalPath); readErr != nil ||
		string(data) != "other\n" {
		t.Fatalf("tampered final data=%q err=%v", data, readErr)
	}
}

func TestObjectBoundPostLinkGenerationMutationsFailClosed(t *testing.T) {
	for _, parentKind := range []string{"declared", "managed-config"} {
		for _, mutation := range []string{"final-away-and-back", "sibling-create-and-remove"} {
			t.Run(parentKind+"/"+mutation, func(t *testing.T) {
				parent, parentPath, evidenceDir :=
					openObjectBoundGenerationTestParent(t, parentKind, true)
				defer parent.close()

				finalPath := filepath.Join(parentPath, "artifact")
				var publishedIdentity os.FileInfo
				var foreignIdentity os.FileInfo
				hookRan := false
				_, err := publishObjectBoundFreshFile(objectBoundFreshFileSpec{
					parent:  parent,
					name:    filepath.Base(finalPath),
					path:    finalPath,
					kind:    "test artifact",
					mode:    0o600,
					content: []byte("owned\n"),
					afterPublish: func(objectBoundFreshFileHookState) error {
						hookRan = true
						var err error
						publishedIdentity, err = os.Stat(finalPath)
						if err != nil {
							return err
						}
						switch mutation {
						case "final-away-and-back":
							awayPath := filepath.Join(evidenceDir, "owned-away")
							if err := os.Rename(finalPath, awayPath); err != nil {
								return err
							}
							return os.Rename(awayPath, finalPath)
						case "sibling-create-and-remove":
							siblingPath := filepath.Join(parentPath, "foreign-sibling")
							evidencePath := filepath.Join(evidenceDir, "foreign-sibling")
							if err := os.WriteFile(
								siblingPath,
								[]byte("foreign\n"),
								0o600,
							); err != nil {
								return err
							}
							foreignIdentity, err = os.Stat(siblingPath)
							if err != nil {
								return err
							}
							return os.Rename(siblingPath, evidencePath)
						default:
							return fmt.Errorf("unknown mutation %q", mutation)
						}
					},
				})
				if !hookRan {
					t.Fatalf("post-link mutation hook did not run: %v", err)
				}
				if err == nil ||
					!strings.Contains(err.Error(), "generation changed") ||
					!strings.Contains(err.Error(), "no automatic unlink, rollback") {
					t.Fatalf(
						"post-link mutation error = %v, want generation rejection and retention audit",
						err,
					)
				}
				finalIdentity, statErr := os.Stat(finalPath)
				if statErr != nil || !os.SameFile(publishedIdentity, finalIdentity) {
					t.Fatalf(
						"published final identity changed: identity=%v err=%v",
						finalIdentity,
						statErr,
					)
				}
				if data, readErr := os.ReadFile(finalPath); readErr != nil ||
					string(data) != "owned\n" {
					t.Fatalf("published final data=%q err=%v", data, readErr)
				}
				if mutation == "sibling-create-and-remove" {
					evidencePath := filepath.Join(evidenceDir, "foreign-sibling")
					evidenceIdentity, statErr := os.Stat(evidencePath)
					if statErr != nil ||
						!os.SameFile(foreignIdentity, evidenceIdentity) {
						t.Fatalf(
							"foreign sibling evidence changed: identity=%v err=%v",
							evidenceIdentity,
							statErr,
						)
					}
					if data, readErr := os.ReadFile(evidencePath); readErr != nil ||
						string(data) != "foreign\n" {
						t.Fatalf("foreign sibling evidence=%q err=%v", data, readErr)
					}
				}
			})
		}
	}
}

func TestObjectBoundFreshPublicationSucceedsWithParentGenerationBaselines(
	t *testing.T,
) {
	for _, parentKind := range []string{"declared", "managed-config"} {
		t.Run(parentKind, func(t *testing.T) {
			parent, parentPath, _ :=
				openObjectBoundGenerationTestParent(t, parentKind, false)
			defer parent.close()

			finalPath := filepath.Join(parentPath, "artifact")
			result, err := publishObjectBoundFreshFile(objectBoundFreshFileSpec{
				parent:  parent,
				name:    filepath.Base(finalPath),
				path:    finalPath,
				kind:    "test artifact",
				mode:    0o600,
				content: []byte("owned\n"),
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := result.file.Close(); err != nil {
				t.Fatal(err)
			}
			if data, err := os.ReadFile(finalPath); err != nil ||
				string(data) != "owned\n" {
				t.Fatalf("published final data=%q err=%v", data, err)
			}
			if err := revalidateManagedCleanupDir(parent); err != nil {
				t.Fatalf("revalidate published parent generation: %v", err)
			}
		})
	}
}

func TestManagedCleanupDirRejectsParentEntryAwayAndBack(t *testing.T) {
	root := t.TempDir()
	parentPath := filepath.Join(root, "wg-mix-ebpf-generation-parent")
	parent, err := createFreshManagedCleanupDir(configCleanupPath(parentPath))
	if err != nil {
		t.Fatal(err)
	}
	defer parent.close()
	before, err := os.Stat(parentPath)
	if err != nil {
		t.Fatal(err)
	}
	awayPath := parentPath + ".held-away"
	if err := os.Rename(parentPath, awayPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(awayPath, parentPath); err != nil {
		t.Fatal(err)
	}
	if err := revalidateManagedCleanupDir(parent); err == nil ||
		!strings.Contains(err.Error(), "generation changed") {
		t.Fatalf("managed parent revalidation error = %v, want generation rejection", err)
	}
	after, err := os.Stat(parentPath)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("reattached managed directory identity changed: info=%v err=%v", after, err)
	}
}

func openObjectBoundGenerationTestParent(
	t *testing.T,
	parentKind string,
	withEvidence bool,
) (*managedCleanupDir, string, string) {
	t.Helper()
	root := t.TempDir()
	var parentPath string
	switch parentKind {
	case "declared":
		parentPath = filepath.Join(root, "declared-parent")
		if err := os.Mkdir(parentPath, 0o700); err != nil {
			t.Fatal(err)
		}
	case "managed-config":
		parentPath = filepath.Join(root, "wg-mix-ebpf-object-parent")
		parent, err := createFreshManagedCleanupDir(configCleanupPath(parentPath))
		if err != nil {
			t.Fatal(err)
		}
		if !withEvidence {
			return parent, parentPath, ""
		}
		if err := parent.close(); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unknown object-bound test parent kind %q", parentKind)
	}

	evidenceDir := ""
	if withEvidence {
		evidenceDir = filepath.Join(parentPath, "retained-evidence")
		if err := os.Mkdir(evidenceDir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if parentKind == "managed-config" {
		parent, exists, err := openManagedCleanupDir(configCleanupPath(parentPath))
		if err != nil || !exists {
			t.Fatalf("reopen managed publication parent: exists=%t err=%v", exists, err)
		}
		return parent, parentPath, evidenceDir
	}
	parent, exists, err := openDeclaredArtifactParent(parentPath, parentPath)
	if err != nil || !exists {
		t.Fatalf("open declared publication parent: exists=%t err=%v", exists, err)
	}
	return parent, parentPath, evidenceDir
}

func TestInstallRetryAfterUnpublishedManifestAddsNoTemporaryNames(t *testing.T) {
	layout := cleanupTestPaths(t.TempDir(), "object-bound-retry")
	setCleanupTestEnvironment(t, layout)
	lifecycleRoot := t.TempDir()
	injected := errors.New("stop before ownership publication")
	failedOnce := false
	ctx := lockfile.WithLifecyclePathsForTest(
		context.WithValue(
			t.Context(),
			installBeforeObjectBoundFreshPublishHookContextKey{},
			func(state objectBoundFreshFileHookState) error {
				if state.Kind != "cleanup ownership manifest" || failedOnce {
					return nil
				}
				failedOnce = true
				return injected
			},
		),
		filepath.Join(lifecycleRoot, "daemon.lease"),
		filepath.Join(lifecycleRoot, "maintenance.gate"),
	)
	options := Options{System: "unknown", AdoptExisting: true}

	if _, err := Install(ctx, options); !errors.Is(err, injected) {
		t.Fatalf("first install error = %v, want injected publication failure", err)
	}
	if !failedOnce {
		t.Fatal("manifest publication hook did not run")
	}
	assertNoInstallTemporaryNames(t, layout)
	if _, err := os.Lstat(cleanupManifestPath(layout)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed publication created ownership manifest: %v", err)
	}

	if _, err := Install(ctx, options); err != nil {
		t.Fatalf("in-place install retry: %v", err)
	}
	assertNoInstallTemporaryNames(t, layout)
	if _, err := os.Stat(cleanupManifestPath(layout)); err != nil {
		t.Fatalf("retry did not publish ownership manifest: %v", err)
	}
}

func assertNoInstallTemporaryNames(t *testing.T, layout paths) {
	t.Helper()
	for _, dir := range []string{
		filepath.Dir(layout.ConfigPath),
		filepath.Dir(layout.BinaryPath),
		layout.SystemdDir,
		layout.OpenWrtInitDir,
		layout.OpenWrtHotplugDir,
	} {
		entries, err := os.ReadDir(dir)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if strings.Contains(entry.Name(), ".tmp-") ||
				strings.HasPrefix(entry.Name(), objectBoundNamedStagePrefix) {
				t.Fatalf("install retained temporary name %s", filepath.Join(dir, entry.Name()))
			}
		}
	}
}
