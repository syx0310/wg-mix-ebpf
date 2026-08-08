//go:build linux

package dataplane

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	tcHandoffWitnessVersion  = 2
	tcHandoffWitnessPending  = "pending"
	tcHandoffWitnessComplete = "complete"
	tcHandoffWitnessMaxBytes = pinOwnerRecordMaxBytes
	tcHandoffWitnessMaxScan  = 4096
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

type tcHandoffWitnessHolder struct {
	ID string `json:"id"`
}

type tcHandoffWitness struct {
	Version      int                         `json:"version"`
	Revision     uint64                      `json:"revision"`
	State        string                      `json:"state"`
	SourceDigest string                      `json:"source_sha256"`
	Source       tcHandoffWitnessSource      `json:"source"`
	Holders      []tcHandoffWitnessHolder    `json:"holders"`
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
	digest, err := tcHandoffWitnessSourceDigest(source)
	if err != nil {
		return tcHandoffWitnessSource{}, [sha256.Size]byte{}, err
	}
	return source, digest, nil
}

func tcHandoffWitnessSourceDigest(
	source tcHandoffWitnessSource,
) ([sha256.Size]byte, error) {
	data, err := json.Marshal(source)
	if err != nil {
		return [sha256.Size]byte{},
			fmt.Errorf("marshal TC handoff witness source: %w", err)
	}
	return sha256.Sum256(data), nil
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
	holderID string,
) *tcHandoffWitness {
	return &tcHandoffWitness{
		Version:      tcHandoffWitnessVersion,
		Revision:     1,
		State:        tcHandoffWitnessPending,
		SourceDigest: hex.EncodeToString(digest[:]),
		Source:       source,
		Holders:      []tcHandoffWitnessHolder{{ID: holderID}},
	}
}

func newTCHandoffWitnessHolderID() (string, error) {
	var token [sha256.Size]byte
	if _, err := io.ReadFull(rand.Reader, token[:]); err != nil {
		return "", fmt.Errorf("generate TC handoff witness holder ID: %w", err)
	}
	return hex.EncodeToString(token[:]), nil
}

func validateTCHandoffWitnessHolderID(holderID string) error {
	decoded, err := hex.DecodeString(holderID)
	if err != nil || len(decoded) != sha256.Size ||
		holderID != strings.ToLower(holderID) ||
		bytes.Equal(decoded, make([]byte, sha256.Size)) {
		return errors.New("TC handoff witness holder ID is invalid")
	}
	return nil
}

func tcHandoffWitnessHasHolder(witness *tcHandoffWitness, holderID string) bool {
	if witness == nil || holderID == "" {
		return false
	}
	_, found := slices.BinarySearchFunc(
		witness.Holders,
		holderID,
		func(holder tcHandoffWitnessHolder, want string) int {
			return strings.Compare(holder.ID, want)
		},
	)
	return found
}

func addTCHandoffWitnessHolder(
	witness *tcHandoffWitness,
	holderID string,
) (*tcHandoffWitness, bool, error) {
	if err := validateTCHandoffWitnessHolderID(holderID); err != nil {
		return nil, false, err
	}
	if witness == nil {
		return nil, false, errors.New("TC handoff witness is nil")
	}
	index, found := slices.BinarySearchFunc(
		witness.Holders,
		holderID,
		func(holder tcHandoffWitnessHolder, want string) int {
			return strings.Compare(holder.ID, want)
		},
	)
	if found {
		return cloneTCHandoffWitness(witness), false, nil
	}
	if witness.Revision == ^uint64(0) {
		return nil, false, errors.New("TC handoff witness revision is exhausted")
	}
	updated := cloneTCHandoffWitness(witness)
	updated.Revision++
	updated.Holders = append(updated.Holders, tcHandoffWitnessHolder{})
	copy(updated.Holders[index+1:], updated.Holders[index:])
	updated.Holders[index] = tcHandoffWitnessHolder{ID: holderID}
	return updated, true, nil
}

func removeTCHandoffWitnessHolder(
	witness *tcHandoffWitness,
	holderID string,
) (*tcHandoffWitness, bool, error) {
	if err := validateTCHandoffWitnessHolderID(holderID); err != nil {
		return nil, false, err
	}
	if witness == nil {
		return nil, false, errors.New("TC handoff witness is nil")
	}
	index, found := slices.BinarySearchFunc(
		witness.Holders,
		holderID,
		func(holder tcHandoffWitnessHolder, want string) int {
			return strings.Compare(holder.ID, want)
		},
	)
	if !found {
		return cloneTCHandoffWitness(witness), false, nil
	}
	if len(witness.Holders) == 1 {
		return nil, true, nil
	}
	if witness.Revision == ^uint64(0) {
		return nil, false, errors.New("TC handoff witness revision is exhausted")
	}
	updated := cloneTCHandoffWitness(witness)
	updated.Revision++
	updated.Holders = append(updated.Holders[:index], updated.Holders[index+1:]...)
	return updated, true, nil
}

func completedTCHandoffWitness(
	pending *tcHandoffWitness,
	cleanup *pinOwnerRecord,
	source tcHandoffWitnessSource,
	digest [sha256.Size]byte,
	completedAt time.Time,
) (*tcHandoffWitness, error) {
	if pending == nil || cleanup == nil || completedAt.IsZero() {
		return nil, errors.New("TC handoff witness completion is incomplete")
	}
	if err := validateTCHandoffWitness(pending, source, digest); err != nil {
		return nil, fmt.Errorf("validate pending TC handoff witness before completion: %w", err)
	}
	completedAt, err := validateTCHandoffCompletionClock(
		source,
		cleanup,
		completedAt,
	)
	if err != nil {
		return nil, err
	}
	coverage, err := tcHandoffCompletionCoverageDigest(
		cleanup.NextGeneration,
		cleanup.DesiredFilters,
	)
	if err != nil {
		return nil, err
	}
	if pending.Revision == ^uint64(0) {
		return nil, errors.New("TC handoff witness revision is exhausted")
	}
	completed := cloneTCHandoffWitness(pending)
	completed.Revision = pending.Revision + 1
	completed.State = tcHandoffWitnessComplete
	completed.Completion = &tcHandoffWitnessCompletion{
		Sequence:         cleanup.Sequence,
		ActiveGeneration: cleanup.NextGeneration,
		ActiveFilters:    slices.Clone(cleanup.DesiredFilters),
		Coverage:         hex.EncodeToString(coverage[:]),
		CompletedAt:      completedAt.Format(time.RFC3339Nano),
	}
	if err := validateTCHandoffWitness(completed, source, digest); err != nil {
		return nil, fmt.Errorf("validate completed TC handoff witness before publication: %w", err)
	}
	return completed, nil
}

func validateTCHandoffCompletionClock(
	source tcHandoffWitnessSource,
	cleanup *pinOwnerRecord,
	completedAt time.Time,
) (time.Time, error) {
	if cleanup == nil || completedAt.IsZero() {
		return time.Time{}, errors.New("TC handoff witness completion clock is incomplete")
	}
	cleanupUpdatedAt, err := time.Parse(time.RFC3339Nano, cleanup.UpdatedAt)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse TC handoff cleanup updated_at: %w", err)
	}
	ownerCreatedAt, err := time.Parse(time.RFC3339Nano, source.OwnerCreatedAt)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse TC handoff owner created_at: %w", err)
	}
	completedAt = completedAt.UTC()
	if completedAt.Before(cleanupUpdatedAt) || completedAt.Before(ownerCreatedAt) {
		return time.Time{}, errors.New("TC handoff completion clock precedes durable owner time")
	}
	return completedAt, nil
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
	cloned.Holders = slices.Clone(witness.Holders)
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
	if witness.Revision == 0 || len(witness.Holders) == 0 {
		return errors.New("TC handoff witness has no durable holder")
	}
	previousHolder := ""
	for _, holder := range witness.Holders {
		if err := validateTCHandoffWitnessHolderID(holder.ID); err != nil ||
			(previousHolder != "" && holder.ID <= previousHolder) {
			return errors.New("TC handoff witness holders are invalid, repeated, or unsorted")
		}
		previousHolder = holder.ID
	}
	switch witness.State {
	case tcHandoffWitnessPending:
		if witness.Completion != nil {
			return errors.New("pending TC handoff witness has completion fields")
		}
	case tcHandoffWitnessComplete:
		if witness.Completion == nil {
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

func sameTCHandoffWitnessCompletion(
	left *tcHandoffWitnessCompletion,
	right *tcHandoffWitnessCompletion,
) bool {
	leftData, leftErr := json.Marshal(left)
	rightData, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftData, rightData)
}

func singleTCHandoffHolderDelta(
	left []tcHandoffWitnessHolder,
	right []tcHandoffWitnessHolder,
) bool {
	if len(left)+1 != len(right) && len(right)+1 != len(left) {
		return false
	}
	shorter, longer := left, right
	if len(shorter) > len(longer) {
		shorter, longer = longer, shorter
	}
	shortIndex := 0
	for _, holder := range longer {
		if shortIndex < len(shorter) && holder == shorter[shortIndex] {
			shortIndex++
		}
	}
	return shortIndex == len(shorter)
}

// isTCHandoffWitnessSuccessor accepts only one durable state transition:
// registering/releasing one exact holder, or completing the exact pending
// witness without changing its holder set. Recovery uses the direction of this
// relation to distinguish pre-exchange from post-exchange descriptor pairs.
func isTCHandoffWitnessSuccessor(
	previous *tcHandoffWitness,
	next *tcHandoffWitness,
) bool {
	if previous == nil || next == nil || previous.Revision == ^uint64(0) ||
		next.Revision != previous.Revision+1 ||
		previous.Version != next.Version ||
		previous.SourceDigest != next.SourceDigest ||
		!sameTCHandoffWitnessSource(previous.Source, next.Source) {
		return false
	}
	if previous.State == tcHandoffWitnessPending &&
		next.State == tcHandoffWitnessComplete {
		return slices.Equal(previous.Holders, next.Holders) &&
			previous.Completion == nil && next.Completion != nil
	}
	return previous.State == next.State &&
		sameTCHandoffWitnessCompletion(previous.Completion, next.Completion) &&
		singleTCHandoffHolderDelta(previous.Holders, next.Holders)
}

func tcHandoffWitnessNames(
	resourceKey string,
	bootID string,
	digest [sha256.Size]byte,
) (canonical string, draft string, next string, err error) {
	if resourceKey == "" || !bootIDPattern.MatchString(bootID) {
		return "", "", "", errors.New("TC handoff witness resource key or boot ID is invalid")
	}
	canonical = fmt.Sprintf(
		"%s.tc-handoff.%s.%s.json",
		resourceKey,
		bootID,
		hex.EncodeToString(digest[:]),
	)
	return canonical, canonical + ".draft", canonical + ".next", nil
}

func tcHandoffWitnessDescriptorSetExists(
	root *anchoredDirectoryPath,
	names ...string,
) (bool, error) {
	if root == nil || len(names) == 0 {
		return false, errors.New("TC handoff witness descriptor probe is incomplete")
	}
	for _, name := range names {
		if name == "" {
			return false, errors.New("TC handoff witness descriptor name is empty")
		}
		var stat unix.Stat_t
		err := unix.Fstatat(root.FD(), name, &stat, unix.AT_SYMLINK_NOFOLLOW)
		switch {
		case err == nil:
			return true, nil
		case errors.Is(err, unix.ENOENT):
			continue
		default:
			return false, fmt.Errorf("probe TC handoff witness descriptor %s: %w", name, err)
		}
	}
	return false, nil
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

func (store *pinOwnerStore) unlinkTCHandoffWitnessFile(
	name string,
	file *os.File,
	identity pinPathInodeIdentity,
) error {
	if store == nil || store.root == nil || store.descriptorOps.unlink == nil || file == nil {
		return errors.New("TC handoff witness unlink operation is unavailable")
	}
	return store.descriptorOps.unlink(
		store.root,
		name,
		int(file.Fd()),
		identity,
		store.expectedUID,
	)
}

func (store *pinOwnerStore) replaceTCHandoffWitness(
	source tcHandoffWitnessSource,
	digest [sha256.Size]byte,
	currentFile *os.File,
	currentIdentity pinPathInodeIdentity,
	current *tcHandoffWitness,
	updated *tcHandoffWitness,
) (returnErr error) {
	if currentFile == nil || current == nil || updated == nil {
		return errors.New("TC handoff witness replacement is incomplete")
	}
	if err := validateTCHandoffWitness(current, source, digest); err != nil {
		return fmt.Errorf("validate current TC handoff witness before replacement: %w", err)
	}
	if err := validateTCHandoffWitness(updated, source, digest); err != nil {
		return fmt.Errorf("validate replacement TC handoff witness before publication: %w", err)
	}
	if !isTCHandoffWitnessSuccessor(current, updated) {
		return errors.New("TC handoff witness replacement is not one exact successor")
	}
	canonical, draft, next, err := tcHandoffWitnessNames(
		source.ResourceKey,
		source.BootID,
		digest,
	)
	if err != nil {
		return err
	}
	data, err := marshalTCHandoffWitness(updated)
	if err != nil {
		return err
	}
	staged, stagedIdentity, err := stageSyncedDescriptor(
		store.root,
		draft,
		next,
		data,
		store.expectedUID,
		store.descriptorOps,
	)
	if err != nil {
		return closeTCHandoffWitnessFile(
			staged,
			fmt.Errorf("stage TC handoff witness replacement: %w", err),
		)
	}
	defer func() { returnErr = closeTCHandoffWitnessFile(staged, returnErr) }()
	if err := store.descriptorOps.rename(
		store.root,
		next,
		canonical,
		unix.RENAME_EXCHANGE,
	); err != nil {
		return fmt.Errorf("exchange TC handoff witness replacement: %w", err)
	}
	if err := store.descriptorOps.syncDir(store.root); err != nil {
		return err
	}
	if _, err := validateAnchoredRegularFile(
		store.root,
		canonical,
		int(staged.Fd()),
		0o600,
		store.expectedUID,
		&stagedIdentity,
	); err != nil {
		return err
	}
	return store.unlinkTCHandoffWitnessFile(next, currentFile, currentIdentity)
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
	canonical, draft, next, err := tcHandoffWitnessNames(
		source.ResourceKey,
		source.BootID,
		digest,
	)
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
		if nextWitness.State != tcHandoffWitnessPending ||
			nextWitness.Revision != 1 || len(nextWitness.Holders) != 1 {
			return errors.New("TC handoff witness has no exact initial pending predecessor")
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
	case isTCHandoffWitnessSuccessor(currentWitness, nextWitness):
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
		return store.unlinkTCHandoffWitnessFile(next, currentFile, currentIdentity)
	case isTCHandoffWitnessSuccessor(nextWitness, currentWitness):
		return store.unlinkTCHandoffWitnessFile(next, nextFile, nextIdentity)
	default:
		return fmt.Errorf(
			"ambiguous TC handoff witness transition current=%s/%d next=%s/%d",
			currentWitness.State,
			currentWitness.Revision,
			nextWitness.State,
			nextWitness.Revision,
		)
	}
}

func (store *pinOwnerStore) persistPendingTCHandoffWitness(
	record *pinOwnerRecord,
	holderID string,
) (digest [sha256.Size]byte, returnErr error) {
	source, digest, err := tcHandoffWitnessSourceFromMutating(record)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	if err := validateTCHandoffWitnessHolderID(holderID); err != nil {
		return digest, err
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
	canonical, draft, next, err := tcHandoffWitnessNames(
		source.ResourceKey,
		source.BootID,
		digest,
	)
	if err != nil {
		return digest, err
	}
	currentFile, currentIdentity, current, currentErr := store.loadTCHandoffWitnessFile(
		canonical,
		source,
		digest,
	)
	if currentErr == nil {
		defer func() { returnErr = closeTCHandoffWitnessFile(currentFile, returnErr) }()
		updated, changed, err := addTCHandoffWitnessHolder(current, holderID)
		if err != nil || !changed {
			return digest, err
		}
		return digest, store.replaceTCHandoffWitness(
			source,
			digest,
			currentFile,
			currentIdentity,
			current,
			updated,
		)
	}
	if !errors.Is(currentErr, unix.ENOENT) {
		return digest, closeTCHandoffWitnessFile(currentFile, currentErr)
	}
	pending := pendingTCHandoffWitness(source, digest, holderID)
	if err := validateTCHandoffWitness(pending, source, digest); err != nil {
		return digest, fmt.Errorf("validate initial pending TC handoff witness: %w", err)
	}
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
	if store == nil || store.root == nil || store.resource.key != source.ResourceKey ||
		store.resource.parentDevice != source.ParentDevice ||
		store.resource.parentInode != source.ParentInode ||
		store.resource.base != source.PinBaseName {
		return false, errors.New("TC handoff completion store resource changed")
	}
	canonical, draft, next, err := tcHandoffWitnessNames(
		source.ResourceKey,
		source.BootID,
		digest,
	)
	if err != nil {
		return false, err
	}
	present, err := tcHandoffWitnessDescriptorSetExists(
		store.root,
		canonical,
		draft,
		next,
	)
	if err != nil {
		return false, err
	}
	var now time.Time
	if present {
		now, err = ownerRuntimeNow(store.nowRuntime())
		if err != nil {
			return false, err
		}
		if _, err := validateTCHandoffCompletionClock(source, cleanup, now); err != nil {
			return false, err
		}
	}
	if err := store.recoverTCHandoffWitnessDescriptor(source, digest); err != nil {
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
	if now.IsZero() {
		now, err = ownerRuntimeNow(store.nowRuntime())
		if err != nil {
			return false, err
		}
	}
	completedWitness, err := completedTCHandoffWitness(
		current,
		cleanup,
		source,
		digest,
		now,
	)
	if err != nil {
		return false, err
	}
	if err := store.replaceTCHandoffWitness(
		source,
		digest,
		currentFile,
		currentIdentity,
		current,
		completedWitness,
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
	holderID string,
) (bool, error) {
	if err := validateTCHandoffWitnessHolderID(holderID); err != nil {
		return false, err
	}
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
	canonical, _, _, err := tcHandoffWitnessNames(
		source.ResourceKey,
		source.BootID,
		digest,
	)
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
	if !tcHandoffWitnessHasHolder(witness, holderID) {
		return false, closeTCHandoffWitnessFile(
			file,
			errors.New("TC handoff completion witness does not retain the exact stage holder"),
		)
	}
	return true, closeTCHandoffWitnessFile(file, nil)
}

// releaseTCHandoffWitnessHolder is called only after the exact retained stage
// has been resolved and its plan has closed successfully. Removing a non-last
// holder is an atomic successor transition; removing the last holder validates
// and unlinks the one exact canonical file. Missing/absent state is idempotent
// because a prior retry may have committed the removal before reporting an
// fsync/close error.
func (store *pinOwnerStore) releaseTCHandoffWitnessHolder(
	record *pinOwnerRecord,
	expectedDigest [sha256.Size]byte,
	holderID string,
) (returnErr error) {
	if holderID == "" {
		return nil
	}
	if err := validateTCHandoffWitnessHolderID(holderID); err != nil {
		return err
	}
	source, digest, err := tcHandoffWitnessSourceFromMutating(record)
	if err != nil {
		return err
	}
	if digest != expectedDigest {
		return errors.New("TC handoff holder release source digest changed")
	}
	if store == nil || store.root == nil || store.resource.key != source.ResourceKey ||
		store.resource.parentDevice != source.ParentDevice ||
		store.resource.parentInode != source.ParentInode ||
		store.resource.base != source.PinBaseName {
		return errors.New("TC handoff holder release store resource changed")
	}
	if err := store.recoverTCHandoffWitnessDescriptor(source, digest); err != nil {
		return err
	}
	canonical, _, _, err := tcHandoffWitnessNames(
		source.ResourceKey,
		source.BootID,
		digest,
	)
	if err != nil {
		return err
	}
	currentFile, currentIdentity, current, err := store.loadTCHandoffWitnessFile(
		canonical,
		source,
		digest,
	)
	if errors.Is(err, unix.ENOENT) {
		return store.descriptorOps.syncDir(store.root)
	}
	if err != nil {
		return closeTCHandoffWitnessFile(currentFile, err)
	}
	defer func() { returnErr = closeTCHandoffWitnessFile(currentFile, returnErr) }()
	updated, changed, err := removeTCHandoffWitnessHolder(current, holderID)
	if err != nil {
		return err
	}
	if !changed {
		return store.descriptorOps.syncDir(store.root)
	}
	if updated == nil {
		return store.unlinkTCHandoffWitnessFile(
			canonical,
			currentFile,
			currentIdentity,
		)
	}
	if err := validateTCHandoffWitness(updated, source, digest); err != nil {
		return fmt.Errorf("validate TC handoff witness after holder release: %w", err)
	}
	return store.replaceTCHandoffWitness(
		source,
		digest,
		currentFile,
		currentIdentity,
		current,
		updated,
	)
}

type tcHandoffWitnessDescriptorKind uint8

const (
	tcHandoffWitnessDescriptorCanonical tcHandoffWitnessDescriptorKind = iota + 1
	tcHandoffWitnessDescriptorDraft
	tcHandoffWitnessDescriptorNext
)

type parsedTCHandoffWitnessName struct {
	name   string
	bootID string
	digest [sha256.Size]byte
	kind   tcHandoffWitnessDescriptorKind
}

func parseTCHandoffWitnessName(
	resourceKey string,
	name string,
) (parsedTCHandoffWitnessName, bool, error) {
	prefix := resourceKey + ".tc-handoff."
	if resourceKey == "" || !strings.HasPrefix(name, prefix) {
		return parsedTCHandoffWitnessName{}, false, nil
	}
	remainder := strings.TrimPrefix(name, prefix)
	kind := tcHandoffWitnessDescriptorCanonical
	switch {
	case strings.HasSuffix(remainder, ".json.draft"):
		kind = tcHandoffWitnessDescriptorDraft
		remainder = strings.TrimSuffix(remainder, ".json.draft")
	case strings.HasSuffix(remainder, ".json.next"):
		kind = tcHandoffWitnessDescriptorNext
		remainder = strings.TrimSuffix(remainder, ".json.next")
	case strings.HasSuffix(remainder, ".json"):
		remainder = strings.TrimSuffix(remainder, ".json")
	default:
		return parsedTCHandoffWitnessName{}, true,
			fmt.Errorf("TC handoff witness name %q has an invalid descriptor suffix", name)
	}
	parts := strings.Split(remainder, ".")
	if len(parts) != 2 || !bootIDPattern.MatchString(parts[0]) ||
		len(parts[1]) != sha256.Size*2 || parts[1] != strings.ToLower(parts[1]) {
		return parsedTCHandoffWitnessName{}, true,
			fmt.Errorf("TC handoff witness name %q has an invalid boot/digest identity", name)
	}
	digestBytes, err := hex.DecodeString(parts[1])
	if err != nil || len(digestBytes) != sha256.Size {
		return parsedTCHandoffWitnessName{}, true,
			fmt.Errorf("TC handoff witness name %q has an invalid source digest", name)
	}
	var digest [sha256.Size]byte
	copy(digest[:], digestBytes)
	canonical, draft, next, err := tcHandoffWitnessNames(resourceKey, parts[0], digest)
	if err != nil {
		return parsedTCHandoffWitnessName{}, true, err
	}
	want := canonical
	if kind == tcHandoffWitnessDescriptorDraft {
		want = draft
	} else if kind == tcHandoffWitnessDescriptorNext {
		want = next
	}
	if name != want {
		return parsedTCHandoffWitnessName{}, true,
			fmt.Errorf("TC handoff witness name %q is not canonical", name)
	}
	return parsedTCHandoffWitnessName{
		name:   name,
		bootID: parts[0],
		digest: digest,
		kind:   kind,
	}, true, nil
}

type openedTCHandoffWitnessDescriptor struct {
	parsed   parsedTCHandoffWitnessName
	file     *os.File
	identity pinPathInodeIdentity
}

func closeOpenedTCHandoffWitnessDescriptors(
	descriptors []openedTCHandoffWitnessDescriptor,
	err error,
) error {
	for index := range descriptors {
		if descriptors[index].file != nil {
			err = errors.Join(err, descriptors[index].file.Close())
		}
		descriptors[index].file = nil
	}
	return err
}

// cleanupPriorBootTCHandoffWitnesses reclaims only this resource's strictly
// named witnesses from older kernels. It first performs a bounded directory
// read and validates every candidate, so malformed/foreign descriptors block
// all cleanup. Each unlink remains FD/inode anchored and names one exact file.
func (store *pinOwnerStore) cleanupPriorBootTCHandoffWitnesses(
	currentBootID string,
) error {
	if store == nil || store.root == nil ||
		store.resource.key == "" || !bootIDPattern.MatchString(currentBootID) {
		return errors.New("prior-boot TC handoff cleanup is not exactly bound")
	}
	directoryFD, err := unix.Openat(
		store.root.FD(),
		".",
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return fmt.Errorf("open TC handoff witness directory for bounded cleanup: %w", err)
	}
	directory := os.NewFile(uintptr(directoryFD), "TC handoff witness owner root")
	entries, readErr := directory.ReadDir(tcHandoffWitnessMaxScan + 1)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return errors.Join(
			fmt.Errorf("read TC handoff witness directory for bounded cleanup: %w", readErr),
			closeErr,
		)
	}
	if closeErr != nil {
		return closeErr
	}
	if len(entries) > tcHandoffWitnessMaxScan {
		return fmt.Errorf(
			"TC handoff witness cleanup scan exceeds %d entries",
			tcHandoffWitnessMaxScan,
		)
	}
	var opened []openedTCHandoffWitnessDescriptor
	for _, entry := range entries {
		parsed, related, err := parseTCHandoffWitnessName(
			store.resource.key,
			entry.Name(),
		)
		if err != nil {
			return closeOpenedTCHandoffWitnessDescriptors(opened, err)
		}
		if !related || parsed.bootID == currentBootID {
			continue
		}
		file, identity, err := openExistingAnchoredRegularFile(
			store.root,
			parsed.name,
			0o600,
			store.expectedUID,
		)
		if err != nil {
			return closeOpenedTCHandoffWitnessDescriptors(
				opened,
				fmt.Errorf("open prior-boot TC handoff witness %s: %w", parsed.name, err),
			)
		}
		candidate := openedTCHandoffWitnessDescriptor{
			parsed:   parsed,
			file:     file,
			identity: identity,
		}
		opened = append(opened, candidate)
		if parsed.kind == tcHandoffWitnessDescriptorDraft {
			// A crash can leave draft bytes partial, so they are never parsed or
			// adopted. The strict resource/boot/digest/draft name plus anchored
			// regular-file identity is the complete unpublished-state proof.
			continue
		}
		witness, err := readTCHandoffWitness(file)
		if err != nil {
			return closeOpenedTCHandoffWitnessDescriptors(
				opened,
				fmt.Errorf("read prior-boot TC handoff witness %s: %w", parsed.name, err),
			)
		}
		digest, err := tcHandoffWitnessSourceDigest(witness.Source)
		if err != nil || digest != parsed.digest ||
			witness.Source.ResourceKey != store.resource.key ||
			witness.Source.BootID != parsed.bootID {
			return closeOpenedTCHandoffWitnessDescriptors(
				opened,
				errors.Join(
					errors.New("prior-boot TC handoff witness source/name identity changed"),
					err,
				),
			)
		}
		if err := validateTCHandoffWitness(witness, witness.Source, parsed.digest); err != nil {
			return closeOpenedTCHandoffWitnessDescriptors(
				opened,
				fmt.Errorf("validate prior-boot TC handoff witness %s: %w", parsed.name, err),
			)
		}
		if _, err := validateAnchoredRegularFile(
			store.root,
			parsed.name,
			int(file.Fd()),
			0o600,
			store.expectedUID,
			&identity,
		); err != nil {
			return closeOpenedTCHandoffWitnessDescriptors(opened, err)
		}
	}
	slices.SortFunc(opened, func(left, right openedTCHandoffWitnessDescriptor) int {
		return strings.Compare(left.parsed.name, right.parsed.name)
	})
	for index := range opened {
		candidate := &opened[index]
		if err := store.unlinkTCHandoffWitnessFile(
			candidate.parsed.name,
			candidate.file,
			candidate.identity,
		); err != nil {
			return closeOpenedTCHandoffWitnessDescriptors(
				opened[index:],
				fmt.Errorf("remove prior-boot TC handoff witness %s: %w", candidate.parsed.name, err),
			)
		}
		if err := candidate.file.Close(); err != nil {
			candidate.file = nil
			return closeOpenedTCHandoffWitnessDescriptors(opened[index+1:], err)
		}
		candidate.file = nil
	}
	return nil
}
