//go:build darwin

package install

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func init() {
	objectBoundFreshFilePublisherForTest =
		publishObjectBoundFreshFileByExclusiveDestinationForDarwinTest
}

func TestDarwinProductionObjectBoundPublicationFailsClosed(t *testing.T) {
	parentPath := filepath.Join(t.TempDir(), "publication-parent")
	if err := os.Mkdir(parentPath, 0o700); err != nil {
		t.Fatal(err)
	}
	parent, exists, err := openDeclaredArtifactParent(parentPath, parentPath)
	if err != nil || !exists {
		t.Fatalf("open publication parent: exists=%t err=%v", exists, err)
	}
	defer parent.close()

	injected := objectBoundFreshFilePublisherForTest
	objectBoundFreshFilePublisherForTest = nil
	defer func() {
		objectBoundFreshFilePublisherForTest = injected
	}()
	finalPath := filepath.Join(parentPath, "artifact")
	_, err = publishObjectBoundFreshFile(objectBoundFreshFileSpec{
		parent:  parent,
		name:    filepath.Base(finalPath),
		path:    finalPath,
		kind:    "test artifact",
		mode:    0o600,
		content: []byte("owned\n"),
	})
	if !errors.Is(err, errObjectBoundFreshFileUnsupported) {
		t.Fatalf("Darwin production publication error = %v, want unsupported", err)
	}
	if _, statErr := os.Lstat(finalPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("Darwin production fail-closed path exists: %v", statErr)
	}
}

// Darwin production deliberately fails closed. Tests inject this narrower
// backend: it creates the final descriptor with O_EXCL after the hook and
// copies only from caller-owned bytes. It never renames, replaces, or deletes
// any named object.
func publishObjectBoundFreshFileByExclusiveDestinationForDarwinTest(
	spec objectBoundFreshFileSpec,
) (_ objectBoundFreshFileResult, retErr error) {
	if err := validateObjectBoundFreshFileSpec(spec); err != nil {
		return objectBoundFreshFileResult{}, err
	}
	if err := revalidateManagedCleanupDir(spec.parent); err != nil {
		return objectBoundFreshFileResult{}, err
	}
	if err := requireAbsentObjectBoundDestination(spec); err != nil {
		return objectBoundFreshFileResult{}, err
	}
	expectedDigest := sha256.Sum256(spec.content)
	beforeHookParentGeneration, err := objectBoundParentDirectoryGeneration(
		spec.parent,
	)
	if err != nil {
		return objectBoundFreshFileResult{}, err
	}
	var beforePublishErr error
	if spec.beforePublish != nil {
		if err := spec.beforePublish(objectBoundFreshFileHookState{
			Kind:          spec.kind,
			FinalPath:     spec.path,
			NamedStage:    "",
			ExpectedBytes: len(spec.content),
			ExpectedHash:  expectedDigest,
		}); err != nil {
			beforePublishErr = fmt.Errorf(
				"run Darwin test pre-publication hook for %s: %w",
				spec.path,
				err,
			)
		}
	}
	var parentRevalidationErr error
	if err := revalidateManagedCleanupDir(spec.parent); err != nil {
		parentRevalidationErr = err
	}
	var parentGenerationErr error
	if err := requireObjectBoundParentDirectoryGeneration(
		spec.parent,
		beforeHookParentGeneration,
		"after Darwin test pre-publication hook",
	); err != nil {
		parentGenerationErr = err
	}
	if err := errors.Join(
		beforePublishErr,
		parentRevalidationErr,
		parentGenerationErr,
	); err != nil {
		return objectBoundFreshFileResult{}, err
	}
	if err := requireAbsentObjectBoundDestination(spec); err != nil {
		return objectBoundFreshFileResult{}, err
	}

	file, err := cleanupCreateFileAt(
		spec.parent.dir,
		spec.name,
		uint32(spec.mode.Perm()),
	)
	if err != nil {
		return objectBoundFreshFileResult{}, err
	}
	var heldIdentity cleanupIdentity
	defer func() {
		if retErr != nil {
			if file != nil {
				if identity, err := cleanupIdentityForFD(int(file.Fd())); err == nil {
					heldIdentity = identity
				}
			}
			retErr = errors.Join(
				retErr,
				objectBoundPublishedFinalAudit(
					spec.kind,
					spec.path,
					heldIdentity,
				),
			)
			if file != nil {
				retErr = errors.Join(retErr, file.Close())
			}
		}
	}()
	if err := file.Chmod(spec.mode.Perm()); err != nil {
		return objectBoundFreshFileResult{}, err
	}
	written, err := io.Copy(file, bytes.NewReader(spec.content))
	if err != nil {
		return objectBoundFreshFileResult{}, err
	}
	if written != int64(len(spec.content)) {
		return objectBoundFreshFileResult{}, fmt.Errorf(
			"Darwin test publication wrote %d bytes, want %d",
			written,
			len(spec.content),
		)
	}
	if err := file.Sync(); err != nil {
		return objectBoundFreshFileResult{}, err
	}
	writeIdentity, err := cleanupIdentityForFD(int(file.Fd()))
	if err != nil {
		return objectBoundFreshFileResult{}, err
	}
	heldIdentity = writeIdentity
	if err := file.Close(); err != nil {
		return objectBoundFreshFileResult{}, err
	}
	file = nil
	opened, openedIdentity, err := cleanupOpenFileAt(spec.parent.dir, spec.name)
	if err != nil {
		return objectBoundFreshFileResult{}, err
	}
	file = opened
	if !writeIdentity.sameRegularFile(openedIdentity) {
		return objectBoundFreshFileResult{}, errors.New(
			"Darwin test final pathname changed after exclusive creation",
		)
	}
	heldIdentity, err = validateHeldObjectBoundFreshFile(
		file,
		spec,
		1,
		expectedDigest,
	)
	if err != nil {
		return objectBoundFreshFileResult{}, err
	}
	if err := spec.parent.dir.file.Sync(); err != nil {
		return objectBoundFreshFileResult{}, err
	}
	if err := refreshManagedFinalDirectoryGenerationAfterOwnedMutation(
		spec.parent,
	); err != nil {
		return objectBoundFreshFileResult{}, err
	}
	publishedParentGeneration, err := objectBoundParentDirectoryGeneration(
		spec.parent,
	)
	if err != nil {
		return objectBoundFreshFileResult{}, err
	}
	var afterPublishErr error
	if spec.afterPublish != nil {
		if err := spec.afterPublish(objectBoundFreshFileHookState{
			Kind:          spec.kind,
			FinalPath:     spec.path,
			NamedStage:    "",
			HeldIdentity:  heldIdentity,
			ExpectedBytes: len(spec.content),
			ExpectedHash:  expectedDigest,
		}); err != nil {
			afterPublishErr = err
		}
	}
	parentRevalidationErr = nil
	if err := revalidateManagedCleanupDir(spec.parent); err != nil {
		parentRevalidationErr = err
	}
	parentGenerationErr = nil
	if err := requireObjectBoundParentDirectoryGeneration(
		spec.parent,
		publishedParentGeneration,
		"after Darwin test post-link publication hook",
	); err != nil {
		parentGenerationErr = err
	}
	heldIdentity, publishedValidationErr :=
		validateHeldAndNamedObjectBoundFreshFile(
			file,
			spec,
			expectedDigest,
		)
	var finalParentRevalidationErr error
	if err := revalidateManagedCleanupDir(spec.parent); err != nil {
		finalParentRevalidationErr = err
	}
	var finalParentGenerationErr error
	if err := requireObjectBoundParentDirectoryGeneration(
		spec.parent,
		publishedParentGeneration,
		"after Darwin test final pathname and held-object validation",
	); err != nil {
		finalParentGenerationErr = err
	}
	if err := errors.Join(
		afterPublishErr,
		parentRevalidationErr,
		parentGenerationErr,
		publishedValidationErr,
		finalParentRevalidationErr,
		finalParentGenerationErr,
	); err != nil {
		return objectBoundFreshFileResult{}, err
	}
	return objectBoundFreshFileResult{
		file:     file,
		identity: heldIdentity,
		digest:   expectedDigest,
	}, nil
}
