//go:build linux

package dataplane

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"time"

	"golang.org/x/sys/unix"
)

const (
	tcHandoffWitnessVersion  = 1
	tcHandoffWitnessPending  = "pending"
	tcHandoffWitnessComplete = "complete"
	tcHandoffWitnessMaxBytes = pinOwnerRecordMaxBytes
)

// tcHandoffWitnessSource is the immutable identity of one applying/mutating
// owner transaction. It deliberately excludes UpdatedAt and BPFFSMountIDs:
// recovery may run later or through a bind-mount alias. Every field that can
// identify the owner lineage, resource, generation transition, maps, or TC
// coverage remains part of the digest and the persisted witness.
type tcHandoffWitnessSource struct {
	Version                int                    `json:"version"`
	ResourceKey            string                 `json:"resource_key"`
	ParentDevice           uint64                 `json:"parent_device"`
	ParentInode            uint64                 `json:"parent_inode"`
	PinBaseName            string                 `json:"pin_basename"`
	PinPath                string                 `json:"pin_path"`
	BPFFSRootPath          string                 `json:"bpffs_root_path"`
	BootID                 string                 `json:"boot_id"`
	Token                  string                 `json:"token"`
	OwnerCreatedAt         string                 `json:"owner_created_at"`
	RetiredFromResourceKey string                 `json:"retired_from_resource_key"`
	RetiredFromBootID      string                 `json:"retired_from_boot_id"`
	Sequence               uint64                 `json:"sequence"`
	ActiveGeneration       uint64                 `json:"active_generation"`
	NextGeneration         uint64                 `json:"next_generation"`
	Maps                   []pinOwnerMapIdentity  `json:"maps"`
	ActiveFilters          []tcFilterBinding      `json:"active_filters"`
	DesiredFilters         []tcFilterBinding      `json:"desired_filters"`
	ProgramStages          []pinOwnerProgramStage `json:"program_stages"`
	MapStages              []pinOwnerMapStage     `json:"map_stages"`
	Coverage               string                 `json:"coverage_sha256"`
}

type tcHandoffWitnessCompletion struct {
	Sequence         uint64            `json:"sequence"`
	ActiveGeneration uint64            `json:"active_generation"`
	ActiveFilters    []tcFilterBinding `json:"active_filters"`
	Coverage         string            `json:"coverage_sha256"`
	CompletedAt      string            `json:"completed_at"`
}

type tcHandoffWitness struct {
	Version      int                         `json:"version"`
	Revision     uint64                      `json:"revision"`
	State        string                      `json:"state"`
	SourceDigest string                      `json:"source_sha256"`
	Source       tcHandoffWitnessSource      `json:"source"`
	Completion   *tcHandoffWitnessCompletion `json:"completion,omitempty"`
}

type tcHandoffCompletionCoverage struct {
	ActiveGeneration uint64            `json:"active_generation"`
	ActiveFilters    []tcFilterBinding `json:"active_filters"`
}

func tcHandoffWitnessSourceFromMutating(
	record *pinOwnerRecord,
) (tcHandoffWitnessSource, [sha256.Size]byte, error) {
	if record == nil || record.Phase != pinOwnerPhaseApplying ||
		record.Step != pinOwnerStepMutating {
		return tcHandoffWitnessSource{}, [sha256.Size]byte{},
			errors.New("TC handoff witness requires an applying/mutating owner record")
	}
	return tcHandoffWitnessSourceFor(record, record.Sequence)
}

func tcHandoffWitnessSourceFromCleanup(
	record *pinOwnerRecord,
) (tcHandoffWitnessSource, [sha256.Size]byte, error) {
	if record == nil || record.Phase != pinOwnerPhaseApplying ||
		record.Step != pinOwnerStepCleanup || record.Sequence <= 1 {
		return tcHandoffWitnessSource{}, [sha256.Size]byte{},
			errors.New("TC handoff completion requires an applying/cleanup owner record")
	}
	return tcHandoffWitnessSourceFor(record, record.Sequence-1)
}

func tcHandoffWitnessSourceFor(
	record *pinOwnerRecord,
	sourceSequence uint64,
) (tcHandoffWitnessSource, [sha256.Size]byte, error) {
	if record == nil || sourceSequence == 0 {
		return tcHandoffWitnessSource{}, [sha256.Size]byte{},
			errors.New("TC handoff witness source is incomplete")
	}
	resource := pinResourceIdentity{
		key:          record.ResourceKey,
		parentDevice: record.ParentDevice,
		parentInode:  record.ParentInode,
		base:         record.PinBaseName,
		pinPath:      record.PinPath,
	}
	if err := validatePinOwnerRecord(record, resource, 0); err != nil {
		return tcHandoffWitnessSource{}, [sha256.Size]byte{}, err
	}
	coverage, err := tcOwnerJournalCoverageDigest(record)
	if err != nil {
		return tcHandoffWitnessSource{}, [sha256.Size]byte{}, err
	}
	source := tcHandoffWitnessSource{
		Version:                pinOwnerRecordVersion,
		ResourceKey:            record.ResourceKey,
		ParentDevice:           record.ParentDevice,
		ParentInode:            record.ParentInode,
		PinBaseName:            record.PinBaseName,
		PinPath:                record.PinPath,
		BPFFSRootPath:          record.BPFFSRootPath,
		BootID:                 record.BootID,
		Token:                  record.Token,
		OwnerCreatedAt:         record.CreatedAt,
		RetiredFromResourceKey: record.RetiredFromResourceKey,
		RetiredFromBootID:      record.RetiredFromBootID,
		Sequence:               sourceSequence,
		ActiveGeneration:       record.ActiveGeneration,
		NextGeneration:         record.NextGeneration,
		Maps:                   slices.Clone(record.Maps),
		ActiveFilters:          slices.Clone(record.ActiveFilters),
		DesiredFilters:         slices.Clone(record.DesiredFilters),
		ProgramStages:          slices.Clone(record.ProgramStages),
		MapStages:              slices.Clone(record.MapStages),
		Coverage:               hex.EncodeToString(coverage[:]),
	}
	data, err := json.Marshal(source)
	if err != nil {
		return tcHandoffWitnessSource{}, [sha256.Size]byte{},
			fmt.Errorf("marshal TC handoff witness source: %w", err)
	}
	return source, sha256.Sum256(data), nil
}

func tcHandoffCompletionCoverageDigest(
	generation uint64,
	filters []tcFilterBinding,
) ([sha256.Size]byte, error) {
	coverage := tcHandoffCompletionCoverage{
		ActiveGeneration: generation,
		ActiveFilters:    slices.Clone(filters),
	}
	sortTCFilterBindings(coverage.ActiveFilters)
	data, err := json.Marshal(coverage)
	if err != nil {
		return [sha256.Size]byte{},
			fmt.Errorf("marshal TC handoff completion coverage: %w", err)
	}
	return sha256.Sum256(data), nil
}

func pendingTCHandoffWitness(
	source tcHandoffWitnessSource,
	digest [sha256.Size]byte,
) *tcHandoffWitness {
	return &tcHandoffWitness{
		Version:      tcHandoffWitnessVersion,
		Revision:     1,
		State:        tcHandoffWitnessPending,
		SourceDigest: hex.EncodeToString(digest[:]),
		Source:       source,
	}
}

func completedTCHandoffWitness(
	pending *tcHandoffWitness,
	cleanup *pinOwnerRecord,
	completedAt time.Time,
) (*tcHandoffWitness, error) {
	if pending == nil || cleanup == nil || completedAt.IsZero() {
		return nil, errors.New("TC handoff witness completion is incomplete")
	}
	coverage, err := tcHandoffCompletionCoverageDigest(
		cleanup.NextGeneration,
		cleanup.DesiredFilters,
	)
	if err != nil {
		return nil, err
	}
	completed := cloneTCHandoffWitness(pending)
	completed.Revision = 2
	completed.State = tcHandoffWitnessComplete
	completed.Completion = &tcHandoffWitnessCompletion{
		Sequence:         cleanup.Sequence,
		ActiveGeneration: cleanup.NextGeneration,
		ActiveFilters:    slices.Clone(cleanup.DesiredFilters),
		Coverage:         hex.EncodeToString(coverage[:]),
		CompletedAt:      completedAt.UTC().Format(time.RFC3339Nano),
	}
	return completed, nil
}

func cloneTCHandoffWitness(witness *tcHandoffWitness) *tcHandoffWitness {
	if witness == nil {
		return nil
	}
	cloned := *witness
	cloned.Source.Maps = slices.Clone(witness.Source.Maps)
	cloned.Source.ActiveFilters = slices.Clone(witness.Source.ActiveFilters)
	cloned.Source.DesiredFilters = slices.Clone(witness.Source.DesiredFilters)
	cloned.Source.ProgramStages = slices.Clone(witness.Source.ProgramStages)
	cloned.Source.MapStages = slices.Clone(witness.Source.MapStages)
	if witness.Completion != nil {
		completion := *witness.Completion
		completion.ActiveFilters = slices.Clone(witness.Completion.ActiveFilters)
		cloned.Completion = &completion
	}
	return &cloned
}

func sameTCHandoffWitnessSource(
	left tcHandoffWitnessSource,
	right tcHandoffWitnessSource,
) bool {
	leftData, leftErr := json.Marshal(left)
	rightData, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftData, rightData)
}

func validateTCHandoffWitness(
	witness *tcHandoffWitness,
	expectedSource tcHandoffWitnessSource,
	expectedDigest [sha256.Size]byte,
) error {
	if witness == nil {
		return errors.New("TC handoff witness is nil")
	}
	if witness.Version != tcHandoffWitnessVersion ||
		witness.SourceDigest != hex.EncodeToString(expectedDigest[:]) ||
		!sameTCHandoffWitnessSource(witness.Source, expectedSource) {
		return errors.New("TC handoff witness does not match the exact source transaction")
	}
	switch witness.State {
	case tcHandoffWitnessPending:
		if witness.Revision != 1 || witness.Completion != nil {
			return errors.New("pending TC handoff witness has completion fields")
		}
	case tcHandoffWitnessComplete:
		if witness.Revision != 2 || witness.Completion == nil {
			return errors.New("completed TC handoff witness has no completion")
		}
		completion := witness.Completion
		if completion.Sequence != expectedSource.Sequence+1 ||
			completion.ActiveGeneration != expectedSource.NextGeneration ||
			!slices.Equal(completion.ActiveFilters, expectedSource.DesiredFilters) {
			return errors.New("TC handoff witness completion does not cover the source next generation")
		}
		coverage, err := tcHandoffCompletionCoverageDigest(
			completion.ActiveGeneration,
			completion.ActiveFilters,
		)
		if err != nil {
			return err
		}
		if completion.Coverage != hex.EncodeToString(coverage[:]) {
			return errors.New("TC handoff witness completion coverage changed")
		}
		completedAt, err := time.Parse(time.RFC3339Nano, completion.CompletedAt)
		if err != nil || completion.CompletedAt != completedAt.UTC().Format(time.RFC3339Nano) {
			return errors.New("TC handoff witness completion timestamp is not canonical UTC")
		}
		createdAt, err := time.Parse(time.RFC3339Nano, expectedSource.OwnerCreatedAt)
		if err != nil || completedAt.Before(createdAt) {
			return errors.New("TC handoff witness completion predates its owner")
		}
	default:
		return fmt.Errorf("TC handoff witness has invalid state %q", witness.State)
	}
	return nil
}

func tcHandoffWitnessNames(
	resourceKey string,
	digest [sha256.Size]byte,
) (canonical string, draft string, next string, err error) {
	if resourceKey == "" {
		return "", "", "", errors.New("TC handoff witness resource key is empty")
	}
	canonical = fmt.Sprintf(
		"%s.tc-handoff.%s.json",
		resourceKey,
		hex.EncodeToString(digest[:]),
	)
	return canonical, canonical + ".draft", canonical + ".next", nil
}

func readTCHandoffWitness(file *os.File) (*tcHandoffWitness, error) {
	if file == nil {
		return nil, errors.New("TC handoff witness file is nil")
	}
	data := make([]byte, tcHandoffWitnessMaxBytes+1)
	n, err := file.ReadAt(data, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("read TC handoff witness: %w", err)
	}
	if n == 0 || n > tcHandoffWitnessMaxBytes {
		return nil, fmt.Errorf(
			"TC handoff witness size = %d, want 1..%d",
			n,
			tcHandoffWitnessMaxBytes,
		)
	}
	data = data[:n]
	if data[len(data)-1] != '\n' || bytes.Count(data, []byte{'\n'}) != 1 {
		return nil, errors.New("TC handoff witness must be exactly one JSON line terminated by LF")
	}
	var witness tcHandoffWitness
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&witness); err != nil {
		return nil, fmt.Errorf("decode TC handoff witness: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("TC handoff witness contains trailing JSON")
	}
	return &witness, nil
}

func marshalTCHandoffWitness(witness *tcHandoffWitness) ([]byte, error) {
	data, err := json.Marshal(witness)
	if err != nil {
		return nil, err
	}
	if len(data)+1 > tcHandoffWitnessMaxBytes {
		return nil, fmt.Errorf("TC handoff witness is too large: %d bytes", len(data)+1)
	}
	return append(data, '\n'), nil
}

func (store *pinOwnerStore) loadTCHandoffWitnessFile(
	name string,
	expectedSource tcHandoffWitnessSource,
	expectedDigest [sha256.Size]byte,
) (*os.File, pinPathInodeIdentity, *tcHandoffWitness, error) {
	file, identity, err := openExistingAnchoredRegularFile(
		store.root,
		name,
		0o600,
		store.expectedUID,
	)
	if err != nil {
		return nil, pinPathInodeIdentity{}, nil, err
	}
	witness, err := readTCHandoffWitness(file)
	if err == nil {
		err = validateTCHandoffWitness(witness, expectedSource, expectedDigest)
	}
	if err != nil {
		return file, identity, nil, err
	}
	if _, err := validateAnchoredRegularFile(
		store.root,
		name,
		int(file.Fd()),
		0o600,
		store.expectedUID,
		&identity,
	); err != nil {
		return file, identity, nil, err
	}
	return file, identity, witness, nil
}

func closeTCHandoffWitnessFile(file *os.File, err error) error {
	if file == nil {
		return err
	}
	return errors.Join(err, file.Close())
}

// recoverTCHandoffWitnessDescriptor converges only the three exact names for
// this source digest. A corrupt, foreign, or ambiguous descriptor is retained
// and reported; it can never be adopted as forward-progress evidence.
func (store *pinOwnerStore) recoverTCHandoffWitnessDescriptor(
	source tcHandoffWitnessSource,
	digest [sha256.Size]byte,
) (returnErr error) {
	if store == nil || store.root == nil {
		return errors.New("TC handoff witness store is unavailable")
	}
	canonical, draft, next, err := tcHandoffWitnessNames(source.ResourceKey, digest)
	if err != nil {
		return err
	}
	if err := discardUnpublishedDescriptorDraft(
		store.root,
		draft,
		store.expectedUID,
	); err != nil {
		return fmt.Errorf("discard unpublished TC handoff witness draft: %w", err)
	}
	nextFile, nextIdentity, nextWitness, nextErr := store.loadTCHandoffWitnessFile(
		next,
		source,
		digest,
	)
	if errors.Is(nextErr, unix.ENOENT) {
		return nil
	}
	if nextErr != nil {
		return closeTCHandoffWitnessFile(
			nextFile,
			fmt.Errorf("inspect pending TC handoff witness descriptor: %w", nextErr),
		)
	}
	defer func() { returnErr = closeTCHandoffWitnessFile(nextFile, returnErr) }()

	currentFile, currentIdentity, currentWitness, currentErr :=
		store.loadTCHandoffWitnessFile(canonical, source, digest)
	if errors.Is(currentErr, unix.ENOENT) {
		if nextWitness.State != tcHandoffWitnessPending {
			return errors.New("completed TC handoff witness has no published pending predecessor")
		}
		if err := store.descriptorOps.rename(
			store.root,
			next,
			canonical,
			unix.RENAME_NOREPLACE,
		); err != nil {
			return fmt.Errorf("recover initial TC handoff witness: %w", err)
		}
		if err := store.descriptorOps.syncDir(store.root); err != nil {
			return err
		}
		_, err := validateAnchoredRegularFile(
			store.root,
			canonical,
			int(nextFile.Fd()),
			0o600,
			store.expectedUID,
			&nextIdentity,
		)
		return err
	}
	if currentErr != nil {
		return closeTCHandoffWitnessFile(
			currentFile,
			fmt.Errorf("inspect current TC handoff witness descriptor: %w", currentErr),
		)
	}
	defer func() { returnErr = closeTCHandoffWitnessFile(currentFile, returnErr) }()

	switch {
	case currentWitness.State == tcHandoffWitnessPending &&
		nextWitness.State == tcHandoffWitnessComplete:
		if err := store.descriptorOps.rename(
			store.root,
			next,
			canonical,
			unix.RENAME_EXCHANGE,
		); err != nil {
			return fmt.Errorf("recover TC handoff witness completion exchange: %w", err)
		}
		if err := store.descriptorOps.syncDir(store.root); err != nil {
			return err
		}
		if _, err := validateAnchoredRegularFile(
			store.root,
			canonical,
			int(nextFile.Fd()),
			0o600,
			store.expectedUID,
			&nextIdentity,
		); err != nil {
			return err
		}
		return unlinkAnchoredRegularFile(
			store.root,
			next,
			int(currentFile.Fd()),
			currentIdentity,
			store.expectedUID,
		)
	case currentWitness.State == tcHandoffWitnessComplete &&
		nextWitness.State == tcHandoffWitnessPending:
		return unlinkAnchoredRegularFile(
			store.root,
			next,
			int(nextFile.Fd()),
			nextIdentity,
			store.expectedUID,
		)
	default:
		return fmt.Errorf(
			"ambiguous TC handoff witness states current=%s next=%s",
			currentWitness.State,
			nextWitness.State,
		)
	}
}

func (store *pinOwnerStore) persistPendingTCHandoffWitness(
	record *pinOwnerRecord,
) (digest [sha256.Size]byte, returnErr error) {
	source, digest, err := tcHandoffWitnessSourceFromMutating(record)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	if store == nil || store.root == nil || store.resource.key != source.ResourceKey ||
		store.resource.parentDevice != source.ParentDevice ||
		store.resource.parentInode != source.ParentInode ||
		store.resource.base != source.PinBaseName {
		return digest, errors.New("TC handoff witness store resource changed")
	}
	if err := store.recoverTCHandoffWitnessDescriptor(source, digest); err != nil {
		return digest, err
	}
	canonical, draft, next, err := tcHandoffWitnessNames(source.ResourceKey, digest)
	if err != nil {
		return digest, err
	}
	currentFile, _, current, currentErr := store.loadTCHandoffWitnessFile(
		canonical,
		source,
		digest,
	)
	if currentErr == nil {
		return digest, closeTCHandoffWitnessFile(currentFile,
			func() error {
				if current.State != tcHandoffWitnessPending &&
					current.State != tcHandoffWitnessComplete {
					return errors.New("TC handoff witness has no durable state")
				}
				return nil
			}(),
		)
	}
	if !errors.Is(currentErr, unix.ENOENT) {
		return digest, closeTCHandoffWitnessFile(currentFile, currentErr)
	}
	pending := pendingTCHandoffWitness(source, digest)
	data, err := marshalTCHandoffWitness(pending)
	if err != nil {
		return digest, err
	}
	staged, identity, err := stageSyncedDescriptor(
		store.root,
		draft,
		next,
		data,
		store.expectedUID,
		store.descriptorOps,
	)
	if err != nil {
		return digest, closeTCHandoffWitnessFile(staged,
			fmt.Errorf("stage pending TC handoff witness: %w", err),
		)
	}
	defer func() { returnErr = closeTCHandoffWitnessFile(staged, returnErr) }()
	if err := store.descriptorOps.rename(
		store.root,
		next,
		canonical,
		unix.RENAME_NOREPLACE,
	); err != nil {
		return digest, fmt.Errorf("publish pending TC handoff witness: %w", err)
	}
	if err := store.descriptorOps.syncDir(store.root); err != nil {
		return digest, err
	}
	if _, err := validateAnchoredRegularFile(
		store.root,
		canonical,
		int(staged.Fd()),
		0o600,
		store.expectedUID,
		&identity,
	); err != nil {
		return digest, err
	}
	return digest, nil
}

// completePendingTCHandoffWitness is called only after recovery has validated
// desired TC and the committed control generation at applying/cleanup. An
// absent pending witness is a normal successful Apply; a present foreign or
// corrupt witness blocks forward cleanup instead of creating false evidence.
func (store *pinOwnerStore) completePendingTCHandoffWitness(
	cleanup *pinOwnerRecord,
) (completed bool, returnErr error) {
	source, digest, err := tcHandoffWitnessSourceFromCleanup(cleanup)
	if err != nil {
		return false, err
	}
	if store == nil || store.root == nil || store.resource.key != source.ResourceKey {
		return false, errors.New("TC handoff completion store resource changed")
	}
	if err := store.recoverTCHandoffWitnessDescriptor(source, digest); err != nil {
		return false, err
	}
	canonical, draft, next, err := tcHandoffWitnessNames(source.ResourceKey, digest)
	if err != nil {
		return false, err
	}
	currentFile, currentIdentity, current, err := store.loadTCHandoffWitnessFile(
		canonical,
		source,
		digest,
	)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, closeTCHandoffWitnessFile(currentFile, err)
	}
	defer func() { returnErr = closeTCHandoffWitnessFile(currentFile, returnErr) }()
	if current.State == tcHandoffWitnessComplete {
		return true, nil
	}
	now, err := ownerRuntimeNow(store.nowRuntime())
	if err != nil {
		return false, err
	}
	completedWitness, err := completedTCHandoffWitness(current, cleanup, now)
	if err != nil {
		return false, err
	}
	data, err := marshalTCHandoffWitness(completedWitness)
	if err != nil {
		return false, err
	}
	staged, nextIdentity, err := stageSyncedDescriptor(
		store.root,
		draft,
		next,
		data,
		store.expectedUID,
		store.descriptorOps,
	)
	if err != nil {
		return false, closeTCHandoffWitnessFile(staged,
			fmt.Errorf("stage completed TC handoff witness: %w", err),
		)
	}
	defer func() { returnErr = closeTCHandoffWitnessFile(staged, returnErr) }()
	if err := store.descriptorOps.rename(
		store.root,
		next,
		canonical,
		unix.RENAME_EXCHANGE,
	); err != nil {
		return false, fmt.Errorf("exchange completed TC handoff witness: %w", err)
	}
	if err := store.descriptorOps.syncDir(store.root); err != nil {
		return false, err
	}
	if _, err := validateAnchoredRegularFile(
		store.root,
		canonical,
		int(staged.Fd()),
		0o600,
		store.expectedUID,
		&nextIdentity,
	); err != nil {
		return false, err
	}
	if err := unlinkAnchoredRegularFile(
		store.root,
		next,
		int(currentFile.Fd()),
		currentIdentity,
		store.expectedUID,
	); err != nil {
		return false, err
	}
	return true, nil
}

func (store *pinOwnerStore) nowRuntime() pinPathRuntime {
	return pinPathRuntime{now: store.now}
}

func (store *pinOwnerStore) loadCompletedTCHandoffWitness(
	record *pinOwnerRecord,
	expectedDigest [sha256.Size]byte,
) (bool, error) {
	source, digest, err := tcHandoffWitnessSourceFromMutating(record)
	if err != nil {
		return false, err
	}
	if digest != expectedDigest {
		return false, errors.New("TC handoff binding source digest changed")
	}
	if store == nil || store.root == nil || store.resource.key != source.ResourceKey ||
		store.resource.parentDevice != source.ParentDevice ||
		store.resource.parentInode != source.ParentInode ||
		store.resource.base != source.PinBaseName {
		return false, errors.New("TC handoff completion store resource changed")
	}
	if err := store.recoverTCHandoffWitnessDescriptor(source, digest); err != nil {
		return false, err
	}
	canonical, _, _, err := tcHandoffWitnessNames(source.ResourceKey, digest)
	if err != nil {
		return false, err
	}
	file, _, witness, err := store.loadTCHandoffWitnessFile(
		canonical,
		source,
		digest,
	)
	if err != nil {
		return false, closeTCHandoffWitnessFile(file, err)
	}
	if witness.State != tcHandoffWitnessComplete {
		return false, closeTCHandoffWitnessFile(
			file,
			errors.New("TC handoff witness is not completed"),
		)
	}
	return true, closeTCHandoffWitnessFile(file, nil)
}
