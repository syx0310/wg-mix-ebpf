package install

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var errObjectBoundFreshFileUnsupported = errors.New(
	"object-bound fresh-file publication is unsupported on this platform or filesystem",
)

const objectBoundNamedStagePrefix = ".wg-mix-ebpf-stage-"

type objectBoundFreshFileHookState struct {
	Kind          string
	FinalPath     string
	NamedStage    string
	HeldIdentity  cleanupIdentity
	ExpectedBytes int
	ExpectedHash  [sha256.Size]byte
}

type objectBoundFreshFileSpec struct {
	parent                *managedCleanupDir
	name                  string
	path                  string
	kind                  string
	mode                  os.FileMode
	content               []byte
	beforePublish         func(objectBoundFreshFileHookState) error
	afterPublish          func(objectBoundFreshFileHookState) error
	afterFailedStageCheck func(objectBoundFreshFileHookState) error
}

type objectBoundFreshFileResult struct {
	file     *os.File
	identity cleanupIdentity
	digest   [sha256.Size]byte
}

type objectBoundFreshFileStage struct {
	file         *os.File
	name         string
	initialLinks uint64
}

// These indirections let unit tests force the portable path without depending
// on the filesystem backing the test directory.
var createAnonymousObjectBoundFileAt = cleanupCreateObjectBoundFileAt
var createExclusiveObjectBoundFileAt = cleanupCreateFileAt

func publishObjectBoundFreshFile(
	spec objectBoundFreshFileSpec,
) (objectBoundFreshFileResult, error) {
	return publishObjectBoundFreshFileProduction(spec)
}

func createObjectBoundFreshFileStage(
	spec objectBoundFreshFileSpec,
) (objectBoundFreshFileStage, error) {
	file, anonymousErr := createAnonymousObjectBoundFileAt(
		spec.parent.dir,
		uint32(spec.mode.Perm()),
	)
	if anonymousErr == nil {
		return objectBoundFreshFileStage{file: file}, nil
	}
	if !errors.Is(anonymousErr, errObjectBoundFreshFileUnsupported) {
		return objectBoundFreshFileStage{}, anonymousErr
	}

	const maxNameAttempts = 4
	for attempt := 0; attempt < maxNameAttempts; attempt++ {
		suffix, err := newCleanupInstallationID()
		if err != nil {
			return objectBoundFreshFileStage{}, fmt.Errorf(
				"generate exclusive object-bound stage name: %w",
				err,
			)
		}
		name := objectBoundNamedStagePrefix + suffix
		var namedFile *os.File
		proof, err := performCleanupDirectoryMutation(
			spec.parent.dir,
			func() error {
				var createErr error
				namedFile, createErr = createExclusiveObjectBoundFileAt(
					spec.parent.dir,
					name,
					0o600,
				)
				return createErr
			},
		)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return objectBoundFreshFileStage{}, errors.Join(
				fmt.Errorf("create exclusive named object-bound stage: %w", err),
				fmt.Errorf("anonymous stage was unavailable: %w", anonymousErr),
			)
		}
		stage := objectBoundFreshFileStage{
			file:         namedFile,
			name:         name,
			initialLinks: 1,
		}
		if err := refreshObjectBoundParentAfterMutation(spec.parent, proof); err != nil {
			return stage, fmt.Errorf(
				"refresh parent after creating exclusive named stage %s: %w",
				filepath.Join(spec.parent.spec.path, name),
				err,
			)
		}
		return stage, nil
	}
	return objectBoundFreshFileStage{}, errors.New(
		"could not allocate a unique exclusive object-bound stage name",
	)
}

func refreshObjectBoundParentAfterMutation(
	parent *managedCleanupDir,
	proof cleanupDirectoryMutationProof,
) error {
	if parent == nil {
		return errors.New("cannot refresh a nil object-bound publication parent")
	}
	matched, err := refreshManagedCleanupDirGenerationAfterOwnedMutationAtName(
		parent,
		parent.name,
		proof,
	)
	if err != nil {
		return err
	}
	if !matched {
		return errors.New(
			"object-bound mutation did not match the held publication parent",
		)
	}
	return nil
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

	stage, stageErr := createObjectBoundFreshFileStage(spec)
	file := stage.file
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
			} else if stage.name == "" {
				retErr = errors.Join(
					retErr,
					fmt.Errorf(
						"unpublished object-bound %s retained only held identity [%s]; "+
							"no named stage existed and no pathname-based cleanup was attempted",
						spec.kind,
						cleanupIdentityAuditSummary(heldIdentity),
					),
				)
			} else if cleanupErr := cleanupExclusiveObjectBoundStage(
				spec,
				stage.name,
				file,
			); cleanupErr != nil {
				retErr = errors.Join(retErr, cleanupErr)
			}
		}
		if file != nil {
			retErr = errors.Join(retErr, file.Close())
		}
	}()
	if stageErr != nil {
		return objectBoundFreshFileResult{}, fmt.Errorf(
			"create object-bound %s stage: %w",
			spec.kind,
			stageErr,
		)
	}
	stageDescription := "unnamed"
	if stage.name != "" {
		stageDescription = "exclusive named"
	}

	if err := file.Chmod(spec.mode.Perm()); err != nil {
		return objectBoundFreshFileResult{}, fmt.Errorf(
			"set %s %s stage mode: %w",
			stageDescription,
			spec.kind,
			err,
		)
	}
	written, err := io.Copy(file, bytes.NewReader(spec.content))
	if err != nil {
		return objectBoundFreshFileResult{}, fmt.Errorf(
			"write %s %s stage: %w",
			stageDescription,
			spec.kind,
			err,
		)
	}
	if written != int64(len(spec.content)) {
		return objectBoundFreshFileResult{}, fmt.Errorf(
			"write %s %s stage: wrote %d bytes, want %d",
			stageDescription,
			spec.kind,
			written,
			len(spec.content),
		)
	}
	if err := file.Sync(); err != nil {
		return objectBoundFreshFileResult{}, fmt.Errorf(
			"sync %s %s stage: %w",
			stageDescription,
			spec.kind,
			err,
		)
	}
	expectedDigest := sha256.Sum256(spec.content)
	heldIdentity, err = validateHeldObjectBoundFreshFile(
		file,
		spec,
		stage.initialLinks,
		expectedDigest,
	)
	if err != nil {
		return objectBoundFreshFileResult{}, fmt.Errorf(
			"validate %s %s stage before publication: %w",
			stageDescription,
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
		namedStage := ""
		if stage.name != "" {
			namedStage = filepath.Join(spec.parent.spec.path, stage.name)
		}
		if err := spec.beforePublish(objectBoundFreshFileHookState{
			Kind:          spec.kind,
			FinalPath:     spec.path,
			NamedStage:    namedStage,
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
	var revalidatedHeldIdentity cleanupIdentity
	var heldRevalidationErr error
	if stage.name == "" {
		revalidatedHeldIdentity, heldRevalidationErr =
			validateHeldObjectBoundFreshFile(
				file,
				spec,
				stage.initialLinks,
				expectedDigest,
			)
	} else {
		revalidatedHeldIdentity, heldRevalidationErr =
			validateHeldAndNamedObjectBoundStage(
				file,
				spec,
				stage.name,
				expectedDigest,
			)
	}
	if heldRevalidationErr != nil {
		heldRevalidationErr = fmt.Errorf(
			"revalidate %s %s stage after pre-publication hook: %w",
			stageDescription,
			spec.kind,
			heldRevalidationErr,
		)
	}
	var heldIdentityErr error
	if heldRevalidationErr == nil &&
		!beforeHookIdentity.sameRegularFile(revalidatedHeldIdentity) {
		heldIdentityErr = fmt.Errorf(
			"refuse %s publication: held %s stage identity changed",
			spec.kind,
			stageDescription,
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
	parentProof, err := performCleanupDirectoryMutation(
		spec.parent.dir,
		func() error {
			if stage.name == "" {
				return cleanupPublishObjectBoundFileAt(
					spec.parent.dir,
					file,
					spec.name,
				)
			}
			return cleanupRenameNoReplaceAt(
				spec.parent.dir,
				stage.name,
				spec.name,
			)
		},
	)
	if err != nil {
		return objectBoundFreshFileResult{}, fmt.Errorf(
			"publish held %s object at %s without replacement: %w",
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
	if !sameObjectBoundPublicationObject(
		beforeHookIdentity,
		heldIdentity,
		stage.initialLinks,
	) {
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
	if err := refreshObjectBoundParentAfterMutation(spec.parent, parentProof); err != nil {
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
		!sameObjectBoundPublicationObject(
			beforeHookIdentity,
			publishedIdentity,
			stage.initialLinks,
		) {
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

func validateHeldAndNamedObjectBoundStage(
	file *os.File,
	spec objectBoundFreshFileSpec,
	stageName string,
	expectedDigest [sha256.Size]byte,
) (cleanupIdentity, error) {
	heldIdentity, heldErr := validateHeldObjectBoundFreshFile(
		file,
		spec,
		1,
		expectedDigest,
	)
	if heldErr != nil {
		heldErr = fmt.Errorf("validate held named stage: %w", heldErr)
	}

	var namedIdentity cleanupIdentity
	var namedErr error
	named, _, err := cleanupOpenFileAt(spec.parent.dir, stageName)
	if err != nil {
		namedErr = fmt.Errorf(
			"open exclusive named stage %s: %w",
			filepath.Join(spec.parent.spec.path, stageName),
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
			namedErr = fmt.Errorf("validate exclusive named stage: %w", err)
		}
	}
	var bindingErr error
	if heldErr == nil && namedErr == nil &&
		!heldIdentity.sameRegularFile(namedIdentity) {
		bindingErr = errors.New(
			"exclusive named stage does not bind the held publication object",
		)
	}
	return heldIdentity, errors.Join(heldErr, namedErr, bindingErr)
}

func cleanupExclusiveObjectBoundStage(
	spec objectBoundFreshFileSpec,
	stageName string,
	file *os.File,
) error {
	stagePath := filepath.Join(spec.parent.spec.path, stageName)
	retained := func(cause error) error {
		return fmt.Errorf(
			"exclusive named %s stage retained at %s because exact cleanup could not be proven: %w",
			spec.kind,
			stagePath,
			cause,
		)
	}
	if file == nil || stageName == "" ||
		!strings.HasPrefix(stageName, objectBoundNamedStagePrefix) ||
		filepath.Base(stageName) != stageName {
		return retained(errors.New("stage handle or generated name is incomplete"))
	}
	if err := revalidateManagedCleanupDir(spec.parent); err != nil {
		return retained(fmt.Errorf("revalidate held stage parent: %w", err))
	}
	heldIdentity, err := cleanupIdentityForFD(int(file.Fd()))
	if err != nil {
		return retained(fmt.Errorf("inspect held stage object: %w", err))
	}
	if heldIdentity.Mode&cleanupTypeMask != cleanupTypeFile ||
		heldIdentity.UID != uint32(os.Geteuid()) || heldIdentity.Links != 1 {
		return retained(fmt.Errorf(
			"held stage identity [%s] is not an exclusively named owned regular file",
			cleanupIdentityAuditSummary(heldIdentity),
		))
	}
	named, namedIdentity, err := cleanupOpenFileAt(spec.parent.dir, stageName)
	if err != nil {
		return retained(fmt.Errorf("open exact named stage: %w", err))
	}
	if err := named.Close(); err != nil {
		return retained(fmt.Errorf("close exact named stage check: %w", err))
	}
	if !heldIdentity.sameRegularFile(namedIdentity) {
		return retained(errors.New(
			"named stage no longer binds the held publication object",
		))
	}
	// A pathname unlink after this check could delete a replacement. There is
	// no portable descriptor-bound unlink for this held regular file, so every
	// failed exclusive publication keeps its named stage for explicit audit.
	var hookErr error
	if spec.afterFailedStageCheck != nil {
		if err := spec.afterFailedStageCheck(objectBoundFreshFileHookState{
			Kind:          spec.kind,
			FinalPath:     spec.path,
			NamedStage:    stagePath,
			HeldIdentity:  heldIdentity,
			ExpectedBytes: len(spec.content),
			ExpectedHash:  sha256.Sum256(spec.content),
		}); err != nil {
			hookErr = fmt.Errorf(
				"run post-final-check failed-stage hook for %s: %w",
				stagePath,
				err,
			)
		}
	}
	_, postHookErr := validateHeldAndNamedObjectBoundStage(
		file,
		spec,
		stageName,
		sha256.Sum256(spec.content),
	)
	if postHookErr != nil {
		postHookErr = fmt.Errorf(
			"audit retained named stage after final-check boundary: %w",
			postHookErr,
		)
	}
	return retained(errors.Join(
		errors.New(
			"descriptor-bound unlink is unavailable; no pathname-based cleanup was attempted",
		),
		hookErr,
		postHookErr,
	))
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

func sameObjectBoundPublicationObject(
	before cleanupIdentity,
	after cleanupIdentity,
	beforeLinks uint64,
) bool {
	return before.sameObject(after) &&
		before.UID == after.UID &&
		before.GID == after.GID &&
		before.Mode&0o7777 == after.Mode&0o7777 &&
		before.Size == after.Size &&
		before.Links == beforeLinks &&
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
