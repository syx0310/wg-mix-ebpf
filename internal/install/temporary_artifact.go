package install

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

var errObjectBoundFreshFileUnsupported = errors.New(
	"object-bound fresh-file publication is unsupported on this platform or filesystem",
)

type objectBoundFreshFileHookState struct {
	Kind          string
	FinalPath     string
	NamedStage    string
	HeldIdentity  cleanupIdentity
	ExpectedBytes int
	ExpectedHash  [sha256.Size]byte
}

type objectBoundFreshFileSpec struct {
	parent        *managedCleanupDir
	name          string
	path          string
	kind          string
	mode          os.FileMode
	content       []byte
	beforePublish func(objectBoundFreshFileHookState) error
	afterPublish  func(objectBoundFreshFileHookState) error
}

type objectBoundFreshFileResult struct {
	file     *os.File
	identity cleanupIdentity
	digest   [sha256.Size]byte
}

type objectBoundFreshFileTestPublisher func(
	objectBoundFreshFileSpec,
) (objectBoundFreshFileResult, error)

// Tests on platforms without a production object-bound primitive explicitly
// install a no-replace-only backend from a platform-specific _test.go file.
// Production builds leave this nil and fail closed.
var objectBoundFreshFilePublisherForTest objectBoundFreshFileTestPublisher

func publishObjectBoundFreshFile(
	spec objectBoundFreshFileSpec,
) (objectBoundFreshFileResult, error) {
	if objectBoundFreshFilePublisherForTest != nil {
		return objectBoundFreshFilePublisherForTest(spec)
	}
	return publishObjectBoundFreshFileProduction(spec)
}

func publishObjectBoundFreshFileProduction(
	spec objectBoundFreshFileSpec,
) (_ objectBoundFreshFileResult, retErr error) {
	if err := validateObjectBoundFreshFileSpec(spec); err != nil {
		return objectBoundFreshFileResult{}, err
	}
	if err := revalidateManagedCleanupDir(spec.parent); err != nil {
		return objectBoundFreshFileResult{}, fmt.Errorf(
			"revalidate %s parent before object-bound publication: %w",
			spec.kind,
			err,
		)
	}
	if err := requireAbsentObjectBoundDestination(spec); err != nil {
		return objectBoundFreshFileResult{}, err
	}

	file, err := cleanupCreateObjectBoundFileAt(
		spec.parent.dir,
		uint32(spec.mode.Perm()),
	)
	if err != nil {
		return objectBoundFreshFileResult{}, fmt.Errorf(
			"create unnamed object-bound %s stage: %w",
			spec.kind,
			err,
		)
	}
	published := false
	var heldIdentity cleanupIdentity
	defer func() {
		if retErr != nil {
			if file != nil {
				if identity, err := cleanupIdentityForFD(int(file.Fd())); err == nil {
					heldIdentity = identity
				}
			}
			if published {
				retErr = errors.Join(
					retErr,
					objectBoundPublishedFinalAudit(
						spec.kind,
						spec.path,
						heldIdentity,
					),
				)
			} else {
				retErr = errors.Join(
					retErr,
					fmt.Errorf(
						"unpublished object-bound %s retained only held identity [%s]; "+
							"no named stage existed and no pathname-based cleanup was attempted",
						spec.kind,
						cleanupIdentityAuditSummary(heldIdentity),
					),
				)
			}
		}
		if file != nil {
			retErr = errors.Join(retErr, file.Close())
		}
	}()

	if err := file.Chmod(spec.mode.Perm()); err != nil {
		return objectBoundFreshFileResult{}, fmt.Errorf(
			"set unnamed %s stage mode: %w",
			spec.kind,
			err,
		)
	}
	written, err := io.Copy(file, bytes.NewReader(spec.content))
	if err != nil {
		return objectBoundFreshFileResult{}, fmt.Errorf(
			"write unnamed %s stage: %w",
			spec.kind,
			err,
		)
	}
	if written != int64(len(spec.content)) {
		return objectBoundFreshFileResult{}, fmt.Errorf(
			"write unnamed %s stage: wrote %d bytes, want %d",
			spec.kind,
			written,
			len(spec.content),
		)
	}
	if err := file.Sync(); err != nil {
		return objectBoundFreshFileResult{}, fmt.Errorf(
			"sync unnamed %s stage: %w",
			spec.kind,
			err,
		)
	}
	expectedDigest := sha256.Sum256(spec.content)
	heldIdentity, err = validateHeldObjectBoundFreshFile(
		file,
		spec,
		0,
		expectedDigest,
	)
	if err != nil {
		return objectBoundFreshFileResult{}, fmt.Errorf(
			"validate unnamed %s stage before publication: %w",
			spec.kind,
			err,
		)
	}
	beforeHookIdentity := heldIdentity
	beforeHookParentGeneration, err := objectBoundParentDirectoryGeneration(
		spec.parent,
	)
	if err != nil {
		return objectBoundFreshFileResult{}, fmt.Errorf(
			"record %s parent generation before pre-publication hook: %w",
			spec.kind,
			err,
		)
	}
	var beforePublishErr error
	if spec.beforePublish != nil {
		if err := spec.beforePublish(objectBoundFreshFileHookState{
			Kind:          spec.kind,
			FinalPath:     spec.path,
			NamedStage:    "",
			HeldIdentity:  heldIdentity,
			ExpectedBytes: len(spec.content),
			ExpectedHash:  expectedDigest,
		}); err != nil {
			beforePublishErr = fmt.Errorf(
				"run pre-publication hook for %s: %w",
				spec.path,
				err,
			)
		}
	}
	var parentRevalidationErr error
	if err := revalidateManagedCleanupDir(spec.parent); err != nil {
		parentRevalidationErr = fmt.Errorf(
			"revalidate %s parent after pre-publication hook: %w",
			spec.kind,
			err,
		)
	}
	var parentGenerationErr error
	if err := requireObjectBoundParentDirectoryGeneration(
		spec.parent,
		beforeHookParentGeneration,
		"after pre-publication hook",
	); err != nil {
		parentGenerationErr = err
	}
	revalidatedHeldIdentity, heldRevalidationErr := validateHeldObjectBoundFreshFile(
		file,
		spec,
		0,
		expectedDigest,
	)
	if heldRevalidationErr != nil {
		heldRevalidationErr = fmt.Errorf(
			"revalidate unnamed %s stage after pre-publication hook: %w",
			spec.kind,
			heldRevalidationErr,
		)
	}
	var heldIdentityErr error
	if heldRevalidationErr == nil &&
		!beforeHookIdentity.sameRegularFile(revalidatedHeldIdentity) {
		heldIdentityErr = fmt.Errorf(
			"refuse %s publication: held unnamed stage identity changed",
			spec.kind,
		)
	}
	if err := errors.Join(
		beforePublishErr,
		parentRevalidationErr,
		parentGenerationErr,
		heldRevalidationErr,
		heldIdentityErr,
	); err != nil {
		return objectBoundFreshFileResult{}, err
	}
	heldIdentity = revalidatedHeldIdentity
	if err := requireAbsentObjectBoundDestination(spec); err != nil {
		return objectBoundFreshFileResult{}, err
	}
	if err := cleanupPublishObjectBoundFileAt(
		spec.parent.dir,
		file,
		spec.name,
	); err != nil {
		return objectBoundFreshFileResult{}, fmt.Errorf(
			"publish held %s object directly at %s without replacement: %w",
			spec.kind,
			spec.path,
			err,
		)
	}
	published = true
	heldIdentity, err = validateHeldObjectBoundFreshFile(
		file,
		spec,
		1,
		expectedDigest,
	)
	if err != nil {
		return objectBoundFreshFileResult{}, fmt.Errorf(
			"validate held %s immediately after publication: %w",
			spec.kind,
			err,
		)
	}
	if !sameObjectBoundPublicationObject(beforeHookIdentity, heldIdentity) {
		return objectBoundFreshFileResult{}, fmt.Errorf(
			"refuse %s publication: linked held object differs from staged object",
			spec.kind,
		)
	}
	if err := spec.parent.dir.file.Sync(); err != nil {
		return objectBoundFreshFileResult{}, fmt.Errorf(
			"sync %s parent after object-bound publication: %w",
			spec.kind,
			err,
		)
	}
	if err := refreshManagedFinalDirectoryGenerationAfterOwnedMutation(
		spec.parent,
	); err != nil {
		return objectBoundFreshFileResult{}, fmt.Errorf(
			"refresh held parent generation after publishing %s: %w",
			spec.kind,
			err,
		)
	}
	publishedParentGeneration, err := objectBoundParentDirectoryGeneration(
		spec.parent,
	)
	if err != nil {
		return objectBoundFreshFileResult{}, fmt.Errorf(
			"record %s parent generation after owned publication: %w",
			spec.kind,
			err,
		)
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
			afterPublishErr = fmt.Errorf(
				"run post-link publication hook for %s: %w",
				spec.path,
				err,
			)
		}
	}
	parentRevalidationErr = nil
	if err := revalidateManagedCleanupDir(spec.parent); err != nil {
		parentRevalidationErr = fmt.Errorf(
			"revalidate %s parent after post-link publication hook: %w",
			spec.kind,
			err,
		)
	}
	parentGenerationErr = nil
	if err := requireObjectBoundParentDirectoryGeneration(
		spec.parent,
		publishedParentGeneration,
		"after post-link publication hook",
	); err != nil {
		parentGenerationErr = err
	}
	publishedIdentity, publishedValidationErr :=
		validateHeldAndNamedObjectBoundFreshFile(
			file,
			spec,
			expectedDigest,
		)
	var stagedObjectErr error
	if publishedValidationErr == nil &&
		!sameObjectBoundPublicationObject(beforeHookIdentity, publishedIdentity) {
		stagedObjectErr = fmt.Errorf(
			"refuse %s publication: published held object differs from staged object",
			spec.kind,
		)
	}
	var finalParentRevalidationErr error
	if err := revalidateManagedCleanupDir(spec.parent); err != nil {
		finalParentRevalidationErr = fmt.Errorf(
			"revalidate %s parent after object-bound publication: %w",
			spec.kind,
			err,
		)
	}
	var finalParentGenerationErr error
	if err := requireObjectBoundParentDirectoryGeneration(
		spec.parent,
		publishedParentGeneration,
		"after final pathname and held-object validation",
	); err != nil {
		finalParentGenerationErr = err
	}
	if err := errors.Join(
		afterPublishErr,
		parentRevalidationErr,
		parentGenerationErr,
		publishedValidationErr,
		stagedObjectErr,
		finalParentRevalidationErr,
		finalParentGenerationErr,
	); err != nil {
		return objectBoundFreshFileResult{}, err
	}
	result := objectBoundFreshFileResult{
		file:     file,
		identity: publishedIdentity,
		digest:   expectedDigest,
	}
	file = nil
	return result, nil
}

func validateObjectBoundFreshFileSpec(spec objectBoundFreshFileSpec) error {
	if spec.parent == nil || spec.parent.dir == nil || spec.parent.dir.file == nil {
		return errors.New("object-bound publication requires a held parent directory")
	}
	if spec.name == "" || spec.name == "." || spec.name == ".." ||
		filepath.Base(spec.name) != spec.name {
		return fmt.Errorf("refuse unsafe object-bound publication name %q", spec.name)
	}
	if spec.kind == "" || spec.path == "" {
		return errors.New("object-bound publication requires kind and display path")
	}
	if filepath.Clean(spec.path) != spec.path ||
		spec.path != filepath.Join(spec.parent.spec.path, spec.name) {
		return fmt.Errorf(
			"refuse object-bound publication path %s outside held parent %s",
			spec.path,
			spec.parent.spec.path,
		)
	}
	if spec.mode.Perm() == 0 || spec.mode&^os.ModePerm != 0 {
		return fmt.Errorf(
			"refuse invalid object-bound publication mode %#o",
			spec.mode,
		)
	}
	return nil
}

func objectBoundPublishedFinalAudit(
	kind string,
	path string,
	identity cleanupIdentity,
) error {
	return fmt.Errorf(
		"object-bound %s final %s was published from held identity [%s] "+
			"before a later failure; no automatic unlink, rollback, or "+
			"pathname-based cleanup is authorized",
		kind,
		path,
		cleanupIdentityAuditSummary(identity),
	)
}

func objectBoundParentDirectoryGeneration(
	parent *managedCleanupDir,
) (cleanupDirectoryGeneration, error) {
	if parent == nil || parent.dir == nil || parent.dir.file == nil {
		return cleanupDirectoryGeneration{}, errors.New(
			"object-bound publication parent is not held",
		)
	}
	identity, err := cleanupIdentityForFD(int(parent.dir.file.Fd()))
	if err != nil {
		return cleanupDirectoryGeneration{}, err
	}
	if !parent.dir.identity.sameDirectory(identity) {
		return cleanupDirectoryGeneration{}, errors.New(
			"object-bound publication parent identity changed",
		)
	}
	return directoryGeneration(identity), nil
}

func requireObjectBoundParentDirectoryGeneration(
	parent *managedCleanupDir,
	expected cleanupDirectoryGeneration,
	boundary string,
) error {
	actual, err := objectBoundParentDirectoryGeneration(parent)
	if err != nil {
		return fmt.Errorf(
			"revalidate object-bound publication parent %s: %w",
			boundary,
			err,
		)
	}
	if !expected.same(actual) {
		return fmt.Errorf(
			"refuse object-bound publication: parent directory generation changed %s",
			boundary,
		)
	}
	return nil
}

func requireAbsentObjectBoundDestination(spec objectBoundFreshFileSpec) error {
	_, err := cleanupIdentityAt(spec.parent.dir, spec.name)
	switch {
	case cleanupIsNotExist(err):
		return nil
	case err == nil:
		return fmt.Errorf(
			"refuse object-bound %s publication: destination %s already exists",
			spec.kind,
			spec.path,
		)
	default:
		return fmt.Errorf(
			"inspect object-bound %s destination %s: %w",
			spec.kind,
			spec.path,
			err,
		)
	}
}

func validateHeldAndNamedObjectBoundFreshFile(
	file *os.File,
	spec objectBoundFreshFileSpec,
	expectedDigest [sha256.Size]byte,
) (cleanupIdentity, error) {
	heldIdentity, heldErr := validateHeldObjectBoundFreshFile(
		file,
		spec,
		1,
		expectedDigest,
	)
	if heldErr != nil {
		heldErr = fmt.Errorf(
			"validate held %s object after publication: %w",
			spec.kind,
			heldErr,
		)
	}

	var namedIdentity cleanupIdentity
	var namedErr error
	named, _, err := cleanupOpenFileAt(spec.parent.dir, spec.name)
	if err != nil {
		namedErr = fmt.Errorf(
			"open published %s final pathname %s: %w",
			spec.kind,
			spec.path,
			err,
		)
	} else {
		var validateErr error
		namedIdentity, validateErr = validateHeldObjectBoundFreshFile(
			named,
			spec,
			1,
			expectedDigest,
		)
		closeErr := named.Close()
		if err := errors.Join(validateErr, closeErr); err != nil {
			namedErr = fmt.Errorf(
				"validate published %s final pathname %s: %w",
				spec.kind,
				spec.path,
				err,
			)
		}
	}

	var bindingErr error
	if heldErr == nil && namedErr == nil &&
		!heldIdentity.sameRegularFile(namedIdentity) {
		bindingErr = fmt.Errorf(
			"refuse %s publication: final pathname does not bind the held object",
			spec.kind,
		)
	}
	return heldIdentity, errors.Join(heldErr, namedErr, bindingErr)
}

func validateHeldObjectBoundFreshFile(
	file *os.File,
	spec objectBoundFreshFileSpec,
	expectedLinks uint64,
	expectedDigest [sha256.Size]byte,
) (cleanupIdentity, error) {
	if file == nil {
		return cleanupIdentity{}, errors.New("held publication file is nil")
	}
	before, err := cleanupIdentityForFD(int(file.Fd()))
	if err != nil {
		return cleanupIdentity{}, err
	}
	if before.Mode&cleanupTypeMask != cleanupTypeFile ||
		before.UID != uint32(os.Geteuid()) ||
		before.Mode&0o7777 != uint32(spec.mode.Perm()) ||
		before.Links != expectedLinks ||
		before.Size != uint64(len(spec.content)) {
		return cleanupIdentity{}, fmt.Errorf(
			"held identity [%s] does not match mode %#o, links %d, and size %d",
			cleanupIdentityAuditSummary(before),
			spec.mode.Perm(),
			expectedLinks,
			len(spec.content),
		)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return cleanupIdentity{}, err
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(len(spec.content))+1))
	if err != nil {
		return cleanupIdentity{}, err
	}
	if len(data) != len(spec.content) ||
		!bytes.Equal(data, spec.content) ||
		sha256.Sum256(data) != expectedDigest {
		return cleanupIdentity{}, errors.New(
			"held publication bytes or content hash changed",
		)
	}
	after, err := cleanupIdentityForFD(int(file.Fd()))
	if err != nil {
		return cleanupIdentity{}, err
	}
	if !before.sameRegularFile(after) {
		return cleanupIdentity{}, errors.New(
			"held publication identity changed while validating bytes",
		)
	}
	return after, nil
}

func sameObjectBoundPublicationObject(before cleanupIdentity, after cleanupIdentity) bool {
	return before.sameObject(after) &&
		before.UID == after.UID &&
		before.GID == after.GID &&
		before.Mode&0o7777 == after.Mode&0o7777 &&
		before.Size == after.Size &&
		before.Links == 0 &&
		after.Links == 1
}

func cleanupIdentityAuditSummary(identity cleanupIdentity) string {
	mount := "unknown"
	if identity.MountKnown {
		mount = fmt.Sprintf("%d", identity.MountID)
	}
	return fmt.Sprintf(
		"device=%d inode=%d mount=%s uid=%d gid=%d mode=%#o links=%d size=%d "+
			"ctime=%d.%09d",
		identity.Device,
		identity.Inode,
		mount,
		identity.UID,
		identity.GID,
		identity.Mode,
		identity.Links,
		identity.Size,
		identity.ChangeSec,
		identity.ChangeNsec,
	)
}
