//go:build linux

package dataplane

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
	"golang.org/x/sys/unix"
)

type pinOwnerRecoveryResult struct {
	record           *pinOwnerRecord
	directoryRemoved bool
}

// durableTCOwnerJournalHandoff is created only after the exact mutating owner
// record has been read back from durable storage and every active/desired
// program stage has been revalidated. Holding it proves that a partial or
// missing TC filter set can be rolled forward after this process exits.
type durableTCOwnerJournalHandoff struct {
	mu sync.Mutex

	handle      *pinPathHandle
	store       *pinOwnerStore
	plan        *tcAttachPlan
	intent      *pinOwnerRecord
	resourceKey string
	mountID     uint64
	sequence    uint64
	coverage    [sha256.Size]byte
	programs    map[string]*pinnedProgramObservation
	state       durableTCOwnerJournalHandoffState
}

type durableTCOwnerJournalHandoffState uint8

const (
	durableTCOwnerJournalHandoffPrepared durableTCOwnerJournalHandoffState = iota + 1
	durableTCOwnerJournalHandoffTransferred
	durableTCOwnerJournalHandoffReleased
	durableTCOwnerJournalHandoffExported
)

// durableTCOwnerJournalBinding is the handle/store-independent capability
// retained across an Apply return. The next operation must bind it to freshly
// opened owner resources before it can transfer a stage.
type durableTCOwnerJournalBinding struct {
	plan        *tcAttachPlan
	intent      *pinOwnerRecord
	resourceKey string
	sequence    uint64
	coverage    [sha256.Size]byte
}

type durableTCOwnerJournalProgress uint8

const (
	durableTCOwnerJournalProgressUnproven durableTCOwnerJournalProgress = iota
	durableTCOwnerJournalProgressExact
	durableTCOwnerJournalProgressAdvanced
)

type tcOwnerJournalCoverageSummary struct {
	ActiveFilters  []tcFilterBinding      `json:"active_filters"`
	DesiredFilters []tcFilterBinding      `json:"desired_filters"`
	ProgramStages  []pinOwnerProgramStage `json:"program_stages"`
}

func tcOwnerJournalCoverageDigest(
	record *pinOwnerRecord,
) ([sha256.Size]byte, error) {
	if record == nil {
		return [sha256.Size]byte{}, errors.New("TC owner journal coverage record is nil")
	}
	summary := tcOwnerJournalCoverageSummary{
		ActiveFilters:  slices.Clone(record.ActiveFilters),
		DesiredFilters: slices.Clone(record.DesiredFilters),
		ProgramStages:  slices.Clone(record.ProgramStages),
	}
	sortTCFilterBindings(summary.ActiveFilters)
	sortTCFilterBindings(summary.DesiredFilters)
	slices.SortFunc(summary.ProgramStages, func(left, right pinOwnerProgramStage) int {
		switch {
		case left.ProgramID < right.ProgramID:
			return -1
		case left.ProgramID > right.ProgramID:
			return 1
		case left.Kind < right.Kind:
			return -1
		case left.Kind > right.Kind:
			return 1
		case left.FileName < right.FileName:
			return -1
		case left.FileName > right.FileName:
			return 1
		default:
			return 0
		}
	})
	data, err := json.Marshal(summary)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("marshal TC owner journal coverage: %w", err)
	}
	return sha256.Sum256(data), nil
}

func validateTCOwnerJournalCoverage(
	intent *pinOwnerRecord,
	persisted *pinOwnerRecord,
	active []tcFilterBinding,
	desired []tcFilterBinding,
) (*durableTCOwnerJournalHandoff, error) {
	if intent == nil || persisted == nil {
		return nil, errors.New("TC owner journal handoff requires intent and persisted records")
	}
	if !sameExpectedOwnerRecord(intent, persisted) {
		return nil, errors.New("persisted TC owner journal differs from the mutating intent")
	}
	if persisted.Phase != pinOwnerPhaseApplying || persisted.Step != pinOwnerStepMutating {
		return nil, fmt.Errorf(
			"TC owner journal handoff requires applying/%s, got %s/%s",
			pinOwnerStepMutating, persisted.Phase, persisted.Step,
		)
	}
	if !slices.Equal(persisted.ActiveFilters, active) {
		return nil, errors.New("TC owner journal handoff does not exactly cover the active filter set")
	}
	if !slices.Equal(persisted.DesiredFilters, desired) {
		return nil, errors.New("TC owner journal handoff does not exactly cover the desired filter set")
	}
	token, err := tokenFromOwnerRecord(persisted)
	if err != nil {
		return nil, err
	}
	wantStages := buildOwnerProgramStages(
		persisted.ResourceKey,
		token,
		active,
		desired,
	)
	if !slices.Equal(persisted.ProgramStages, wantStages) {
		return nil, errors.New("TC owner journal handoff program stages do not exactly cover active and desired programs")
	}
	coverage, err := tcOwnerJournalCoverageDigest(persisted)
	if err != nil {
		return nil, err
	}
	return &durableTCOwnerJournalHandoff{
		resourceKey: persisted.ResourceKey,
		sequence:    persisted.Sequence,
		coverage:    coverage,
		intent:      clonePinOwnerRecord(persisted),
	}, nil
}

func prepareDurableTCOwnerJournalHandoff(
	handle *pinPathHandle,
	store *pinOwnerStore,
	intent *pinOwnerRecord,
	active []tcFilterBinding,
	desired []tcFilterBinding,
	plan *tcAttachPlan,
) (*durableTCOwnerJournalHandoff, error) {
	if handle == nil || store == nil || plan == nil {
		return nil, errors.New("TC owner journal handoff requires a pin handle, owner store, and attach plan")
	}
	if handle.mountID == 0 || handle.resource.key == "" ||
		store.resource.key != handle.resource.key {
		return nil, errors.New("TC owner journal handoff has inconsistent resource or mount identity")
	}
	if plan.closed || plan.executed || plan.stage != nil {
		return nil, errors.New("TC owner journal handoff requires a fresh unexecuted attach plan")
	}
	persisted, err := store.Load(handle.mountID)
	if err != nil {
		return nil, fmt.Errorf("read back mutating TC owner journal: %w", err)
	}
	handoff, err := validateTCOwnerJournalCoverage(
		intent,
		persisted,
		active,
		desired,
	)
	if err != nil {
		return nil, err
	}
	if persisted.ResourceKey != handle.resource.key {
		return nil, errors.New("TC owner journal handoff resource does not match the pin handle")
	}
	if err := plan.validateOwnerJournalCoverage(active, desired); err != nil {
		return nil, err
	}
	if err := validateOwnerDirectoryEntries(handle, persisted); err != nil {
		return nil, fmt.Errorf("validate TC owner journal directory coverage: %w", err)
	}
	pins, err := inspectPinnedMapSetWithPolicy(handle, true, false, false)
	if err != nil {
		return nil, fmt.Errorf("inspect durable TC owner journal maps: %w", err)
	}
	if err := validateOwnerPins(handle, persisted, pins, true); err != nil {
		return nil, errors.Join(
			fmt.Errorf("validate durable TC owner journal maps: %w", err),
			closePinnedMapPins(pins),
		)
	}
	if err := validateOwnerControlGeneration(pins, persisted.ActiveGeneration); err != nil {
		return nil, errors.Join(
			fmt.Errorf("validate durable TC owner journal control generation: %w", err),
			closePinnedMapPins(pins),
		)
	}
	if err := closePinnedMapPins(pins); err != nil {
		return nil, fmt.Errorf("close durable TC owner journal map observations: %w", err)
	}
	programs, err := retainTCOwnerJournalPrograms(handle, persisted)
	if err != nil {
		return nil, err
	}
	handoff.handle = handle
	handoff.store = store
	handoff.plan = plan
	handoff.mountID = handle.mountID
	handoff.programs = programs
	handoff.state = durableTCOwnerJournalHandoffPrepared
	return handoff, nil
}

func retainTCOwnerJournalPrograms(
	handle *pinPathHandle,
	record *pinOwnerRecord,
) (map[string]*pinnedProgramObservation, error) {
	programs := make(map[string]*pinnedProgramObservation, len(record.ProgramStages))
	closeOnError := func(err error) (map[string]*pinnedProgramObservation, error) {
		var closeErrs []error
		for _, observation := range programs {
			closeErrs = append(closeErrs, observation.Close())
		}
		return nil, errors.Join(err, errors.Join(closeErrs...))
	}
	for _, stage := range record.ProgramStages {
		if err := validateOwnerProgramStage(handle, record, stage); err != nil {
			return closeOnError(fmt.Errorf(
				"validate durable TC owner program stage %s: %w",
				stage.FileName,
				err,
			))
		}
		observation, err := handle.runtime.loadPinnedProgram(
			filepath.Join(handle.procPath(), stage.FileName),
		)
		if err != nil {
			return closeOnError(fmt.Errorf(
				"retain durable TC owner program stage %s: %w",
				stage.FileName,
				err,
			))
		}
		if observation == nil || observation.fd < 0 ||
			observation.id != stage.ProgramID || observation.pin == nil {
			invalidErr := fmt.Errorf(
				"retain durable TC owner program stage %s returned invalid FD/ID/pin capability",
				stage.FileName,
			)
			if observation != nil {
				if closeErr := observation.Close(); closeErr != nil {
					invalidErr = errors.Join(invalidErr, fmt.Errorf(
						"close invalid durable TC owner program stage %s: %w",
						stage.FileName,
						closeErr,
					))
				}
			}
			return closeOnError(invalidErr)
		}
		programs[stage.FileName] = observation
		backupName := stage.FileName + ".handoff"
		var stat unix.Stat_t
		statErr := unix.Fstatat(
			handle.targetFD,
			backupName,
			&stat,
			unix.AT_SYMLINK_NOFOLLOW,
		)
		switch {
		case statErr == nil:
			if err := validatePinnedProgramAt(
				handle,
				backupName,
				stage.ProgramID,
			); err != nil {
				return closeOnError(fmt.Errorf(
					"validate durable TC owner handoff program stage %s: %w",
					backupName,
					err,
				))
			}
		case errors.Is(statErr, unix.ENOENT):
			if err := observation.pin(filepath.Join(
				handle.procPath(),
				backupName,
			)); err != nil {
				return closeOnError(fmt.Errorf(
					"pin durable TC owner handoff program stage %s: %w",
					backupName,
					err,
				))
			}
			if err := validatePinnedProgramAt(
				handle,
				backupName,
				stage.ProgramID,
			); err != nil {
				return closeOnError(fmt.Errorf(
					"validate pinned TC owner handoff program stage %s: %w",
					backupName,
					err,
				))
			}
		default:
			return closeOnError(statErr)
		}
	}
	return programs, nil
}

func (handoff *durableTCOwnerJournalHandoff) repairMissingProgramStages() error {
	if err := handoff.handle.recheckTargetEntry(); err != nil {
		return err
	}
	for _, stage := range handoff.intent.ProgramStages {
		var stat unix.Stat_t
		err := unix.Fstatat(
			handoff.handle.targetFD,
			stage.FileName,
			&stat,
			unix.AT_SYMLINK_NOFOLLOW,
		)
		if err == nil {
			continue
		}
		if !errors.Is(err, unix.ENOENT) {
			return err
		}
		observation := handoff.programs[stage.FileName]
		if observation == nil || observation.id != stage.ProgramID ||
			observation.pin == nil {
			return fmt.Errorf(
				"missing program stage %s has no retained repair capability",
				stage.FileName,
			)
		}
		if err := observation.pin(filepath.Join(
			handoff.handle.procPath(),
			stage.FileName,
		)); err != nil {
			return fmt.Errorf("repair missing program stage %s: %w", stage.FileName, err)
		}
		if err := validateOwnerProgramStage(
			handoff.handle,
			handoff.intent,
			stage,
		); err != nil {
			return fmt.Errorf("validate repaired program stage %s: %w", stage.FileName, err)
		}
	}
	return nil
}

func (handoff *durableTCOwnerJournalHandoff) releaseProgramsLocked(
	next durableTCOwnerJournalHandoffState,
) error {
	if handoff.state != durableTCOwnerJournalHandoffPrepared {
		return nil
	}
	handoff.state = next
	var errs []error
	for name, observation := range handoff.programs {
		if err := observation.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close retained owner program %s: %w", name, err))
		}
	}
	handoff.programs = nil
	handoff.handle = nil
	handoff.store = nil
	return errors.Join(errs...)
}

func (handoff *durableTCOwnerJournalHandoff) Close() error {
	if handoff == nil {
		return nil
	}
	handoff.mu.Lock()
	defer handoff.mu.Unlock()
	if handoff.state == 0 && len(handoff.programs) == 0 {
		handoff.state = durableTCOwnerJournalHandoffReleased
		return nil
	}
	return handoff.releaseProgramsLocked(durableTCOwnerJournalHandoffReleased)
}

func (handoff *durableTCOwnerJournalHandoff) exportRetryBinding(
	stage *tcAttachStage,
) (*durableTCOwnerJournalBinding, error, error) {
	if handoff == nil || stage == nil {
		return nil, nil, errors.New("TC owner journal retry export is incomplete")
	}
	handoff.mu.Lock()
	defer handoff.mu.Unlock()
	if handoff.state != durableTCOwnerJournalHandoffPrepared {
		return nil, nil, errors.New("TC owner journal handoff is not prepared")
	}
	stage.mu.Lock()
	defer stage.mu.Unlock()
	if stage.done || stage.plan != handoff.plan || handoff.plan.stage != stage {
		return nil, nil, errors.New("TC owner journal retry export does not own the exact retained stage")
	}
	binding := &durableTCOwnerJournalBinding{
		plan:        handoff.plan,
		intent:      clonePinOwnerRecord(handoff.intent),
		resourceKey: handoff.resourceKey,
		sequence:    handoff.sequence,
		coverage:    handoff.coverage,
	}
	closeReport := handoff.releaseProgramsLocked(
		durableTCOwnerJournalHandoffExported,
	)
	return binding, closeReport, nil
}

func rebindDurableTCOwnerJournalHandoff(
	binding *durableTCOwnerJournalBinding,
	handle *pinPathHandle,
	store *pinOwnerStore,
) (*durableTCOwnerJournalHandoff, error) {
	if binding == nil || binding.plan == nil || binding.intent == nil ||
		handle == nil || store == nil {
		return nil, errors.New("TC owner journal retry rebind is incomplete")
	}
	if binding.resourceKey == "" || handle.mountID == 0 ||
		handle.resource.key != binding.resourceKey ||
		store.resource.key != binding.resourceKey {
		return nil, errors.New("TC owner journal retry rebind resource changed")
	}
	handoff := &durableTCOwnerJournalHandoff{
		handle:      handle,
		store:       store,
		plan:        binding.plan,
		intent:      clonePinOwnerRecord(binding.intent),
		resourceKey: binding.resourceKey,
		mountID:     handle.mountID,
		sequence:    binding.sequence,
		coverage:    binding.coverage,
	}
	if err := handoff.validateFreshCoverage(); err != nil {
		return nil, err
	}
	programs, err := retainTCOwnerRecoveryPrograms(handle, binding.intent)
	if err != nil {
		return nil, err
	}
	handoff.programs = programs
	handoff.state = durableTCOwnerJournalHandoffPrepared
	return handoff, nil
}

// classifyDurableTCOwnerJournalProgress is the rollback gate for a retained
// in-process stage. Only the exact original mutating record permits a local
// rollback. A proven forward descendant has already made the durable owner
// responsible for TC and must disarm the old stage. Every other state is
// unproven and therefore remains fail-closed.
func classifyDurableTCOwnerJournalProgress(
	binding *durableTCOwnerJournalBinding,
	handle *pinPathHandle,
	store *pinOwnerStore,
) (durableTCOwnerJournalProgress, error) {
	if binding == nil || binding.intent == nil || handle == nil || store == nil {
		return durableTCOwnerJournalProgressUnproven,
			errors.New("TC owner journal progress proof is incomplete")
	}
	if binding.resourceKey == "" || binding.sequence == 0 ||
		binding.intent.ResourceKey != binding.resourceKey ||
		binding.intent.Sequence != binding.sequence || handle.mountID == 0 ||
		handle.resource.key != binding.resourceKey ||
		store.resource.key != binding.resourceKey {
		return durableTCOwnerJournalProgressUnproven,
			errors.New("TC owner journal progress proof resource changed")
	}
	persisted, err := store.Load(handle.mountID)
	if err != nil {
		return durableTCOwnerJournalProgressUnproven,
			fmt.Errorf("load TC owner journal progress proof: %w", err)
	}
	if persisted.Sequence == binding.sequence &&
		sameExpectedOwnerRecord(persisted, binding.intent) {
		return durableTCOwnerJournalProgressExact, nil
	}
	if provesDurableTCOwnerJournalAdvanced(binding.intent, persisted) {
		return durableTCOwnerJournalProgressAdvanced, nil
	}
	return durableTCOwnerJournalProgressUnproven, fmt.Errorf(
		"TC owner journal sequence %d at %s/%s is neither exact sequence %d nor a proven forward descendant",
		persisted.Sequence,
		persisted.Phase,
		persisted.Step,
		binding.sequence,
	)
}

func provesDurableTCOwnerJournalAdvanced(
	intent *pinOwnerRecord,
	persisted *pinOwnerRecord,
) bool {
	if intent == nil || persisted == nil ||
		intent.Phase != pinOwnerPhaseApplying ||
		intent.Step != pinOwnerStepMutating ||
		persisted.Sequence <= intent.Sequence ||
		intent.ResourceKey != persisted.ResourceKey ||
		intent.ParentDevice != persisted.ParentDevice ||
		intent.ParentInode != persisted.ParentInode ||
		intent.PinBaseName != persisted.PinBaseName ||
		intent.PinPath != persisted.PinPath ||
		intent.BPFFSRootPath != persisted.BPFFSRootPath ||
		!samePinOwnerImmutableFields(intent, persisted) ||
		!slices.Equal(intent.Maps, persisted.Maps) {
		return false
	}

	// The cleanup record is the first durable point after recovery has rolled
	// TC forward and committed the next control generation. Its transaction
	// payload must still exactly match the retained mutating intent.
	if persisted.Phase == pinOwnerPhaseApplying &&
		persisted.Step == pinOwnerStepCleanup &&
		persisted.ActiveGeneration == intent.ActiveGeneration &&
		persisted.NextGeneration == intent.NextGeneration &&
		slices.Equal(persisted.ActiveFilters, intent.ActiveFilters) &&
		slices.Equal(persisted.DesiredFilters, intent.DesiredFilters) &&
		slices.Equal(persisted.ProgramStages, intent.ProgramStages) &&
		slices.Equal(persisted.MapStages, intent.MapStages) {
		return true
	}

	// Once the original next generation is the current active snapshot, the
	// old rollback stage is obsolete even if a later Apply/Detach has already
	// started from that snapshot.
	return persisted.ActiveGeneration == intent.NextGeneration &&
		slices.Equal(persisted.ActiveFilters, intent.DesiredFilters)
}

func retainTCOwnerRecoveryPrograms(
	handle *pinPathHandle,
	record *pinOwnerRecord,
) (map[string]*pinnedProgramObservation, error) {
	programs := make(map[string]*pinnedProgramObservation, len(record.ProgramStages))
	closeOnError := func(err error) (map[string]*pinnedProgramObservation, error) {
		var closeErrs []error
		for _, observation := range programs {
			closeErrs = append(closeErrs, observation.Close())
		}
		return nil, errors.Join(err, errors.Join(closeErrs...))
	}
	for _, stage := range record.ProgramStages {
		fileName, err := validateOwnerProgramRecoveryStage(handle, record, stage)
		if err != nil {
			return closeOnError(err)
		}
		observation, err := handle.runtime.loadPinnedProgram(
			filepath.Join(handle.procPath(), fileName),
		)
		if err != nil {
			return closeOnError(fmt.Errorf(
				"retain recovery program stage %s: %w",
				fileName,
				err,
			))
		}
		if observation == nil || observation.fd < 0 ||
			observation.id != stage.ProgramID {
			invalidErr := fmt.Errorf(
				"retain recovery program stage %s returned invalid FD/ID",
				fileName,
			)
			if observation != nil {
				if closeErr := observation.Close(); closeErr != nil {
					invalidErr = errors.Join(invalidErr, fmt.Errorf(
						"close invalid recovery program stage %s: %w",
						fileName,
						closeErr,
					))
				}
			}
			return closeOnError(invalidErr)
		}
		programs[stage.FileName] = observation
	}
	return programs, nil
}

func (handoff *durableTCOwnerJournalHandoff) validateFreshCoverage() error {
	if handoff.handle == nil || handoff.store == nil || handoff.plan == nil ||
		handoff.intent == nil {
		return errors.New("TC owner journal handoff is not bound to durable state and an attach plan")
	}
	if handoff.handle.mountID != handoff.mountID ||
		handoff.handle.resource.key != handoff.resourceKey ||
		handoff.store.resource.key != handoff.resourceKey {
		return errors.New("TC owner journal handoff resource or mount binding changed")
	}
	persisted, err := handoff.store.Load(handoff.mountID)
	if err != nil {
		return fmt.Errorf("revalidate TC owner journal handoff: %w", err)
	}
	if persisted.ResourceKey != handoff.resourceKey ||
		persisted.Sequence != handoff.sequence ||
		!sameExpectedOwnerRecord(persisted, handoff.intent) {
		return errors.New("TC owner journal handoff is stale")
	}
	coverage, err := tcOwnerJournalCoverageDigest(persisted)
	if err != nil {
		return err
	}
	if coverage != handoff.coverage {
		return errors.New("TC owner journal handoff binding or program coverage changed")
	}
	if err := handoff.plan.validateOwnerJournalCoverage(
		persisted.ActiveFilters,
		persisted.DesiredFilters,
	); err != nil {
		return err
	}
	if err := validateOwnerDirectoryEntries(handoff.handle, persisted); err != nil {
		return fmt.Errorf("revalidate TC owner journal directory coverage: %w", err)
	}
	pins, err := inspectPinnedMapSetWithPolicy(
		handoff.handle,
		true,
		false,
		false,
	)
	if err != nil {
		return fmt.Errorf("revalidate TC owner journal maps: %w", err)
	}
	if err := validateOwnerPins(handoff.handle, persisted, pins, true); err != nil {
		return errors.Join(
			fmt.Errorf("revalidate TC owner journal map coverage: %w", err),
			closePinnedMapPins(pins),
		)
	}
	if err := closePinnedMapPins(pins); err != nil {
		return fmt.Errorf("close revalidated TC owner journal maps: %w", err)
	}
	for _, programStage := range persisted.ProgramStages {
		if _, err := validateOwnerProgramRecoveryStage(
			handoff.handle,
			persisted,
			programStage,
		); err != nil {
			return fmt.Errorf(
				"revalidate TC owner program stage %s: %w",
				programStage.FileName,
				err,
			)
		}
	}
	return nil
}

// Transfer atomically consumes this capability only for the live retained
// stage produced by the exact plan covered by the still-current durable
// applying/mutating journal. A failed validation leaves the stage armed.
func (handoff *durableTCOwnerJournalHandoff) Transfer(
	stage *tcAttachStage,
) (bool, error) {
	if handoff == nil {
		return false, errors.New("TC owner journal handoff is nil")
	}
	handoff.mu.Lock()
	defer handoff.mu.Unlock()
	switch handoff.state {
	case durableTCOwnerJournalHandoffPrepared:
	case durableTCOwnerJournalHandoffTransferred:
		return false, errors.New("TC owner journal handoff was already transferred")
	case durableTCOwnerJournalHandoffReleased:
		return false, errors.New("TC owner journal handoff was already released")
	case durableTCOwnerJournalHandoffExported:
		return false, errors.New("TC owner journal handoff was already exported")
	default:
		return false, fmt.Errorf(
			"TC owner journal handoff has invalid state %d",
			handoff.state,
		)
	}
	if stage == nil {
		return false, errors.New("retained TC stage is nil")
	}
	// Serializing all plan reads with stage.Close is required because closing
	// retained program references updates the bound plan in place.
	stage.mu.Lock()
	defer stage.mu.Unlock()
	if stage.done {
		return false, errors.New("retained TC stage is already resolved")
	}
	if stage.plan != handoff.plan || handoff.plan.stage != stage {
		return false, errors.New("retained TC stage is not the exact stage produced by the bound plan")
	}
	if err := handoff.validateFreshCoverage(); err != nil {
		if repairErr := handoff.repairMissingProgramStages(); repairErr != nil {
			return false, errors.Join(err, repairErr)
		}
		if retryErr := handoff.validateFreshCoverage(); retryErr != nil {
			return false, errors.Join(err, fmt.Errorf("revalidate repaired TC owner journal handoff: %w", retryErr))
		}
	}
	if err := stage.transferToOwnerJournalLocked(
		handoff.plan,
		handoff.intent.ActiveFilters,
		handoff.intent.DesiredFilters,
	); err != nil {
		return false, err
	}
	return true, handoff.releaseProgramsLocked(
		durableTCOwnerJournalHandoffTransferred,
	)
}

// resolveFailedOwnerApply is the production return-boundary owner resolver for
// a failed TC mutation. It accepts only one of three terminal outcomes:
//
//   - the prior TC set was observed exact and the transient stage is disarmed;
//   - the durable owner journal accepted the exact stage; or
//   - local rollback completed, or the still-armed stage was retained by the
//     process-lifetime retry owner.
//
// In particular, a fresh journal validation fault can never strand an armed
// stage in the caller's stack frame.
func resolveFailedOwnerApply(
	handle *pinPathHandle,
	store *pinOwnerStore,
	record *pinOwnerRecord,
	handoff *durableTCOwnerJournalHandoff,
	stage *tcAttachStage,
	tcRuntime tcRuntime,
) error {
	rollbackVerified, abortErr := abortFailedOwnerApply(
		handle,
		store,
		record,
		tcRuntime,
	)
	if stage == nil {
		return errors.Join(abortErr, handoff.Close())
	}
	if rollbackVerified {
		stage.Disarm()
		return errors.Join(abortErr, handoff.Close())
	}

	transferred, transferErr := handoff.Transfer(stage)
	if transferred {
		// The durable journal owns the stage even if releasing the independent
		// proof observations produced a terminal close report.
		return errors.Join(abortErr, transferErr)
	}

	// Fresh store/directory/map/program validation can fail after Execute has
	// already returned a live stage. Production code, rather than its caller,
	// owns the fallback rollback and verifies every changed slot in Close.
	rollbackErr := stage.Close()
	if rollbackErr == nil {
		return errors.Join(
			abortErr,
			fmt.Errorf("transfer retained TC rollback to owner journal: %w", transferErr),
			handoff.Close(),
		)
	}
	if !stage.hasLiveFilterOwnership() {
		// Filter rollback is complete; only fallible program-reference closing
		// remains. Return those references to the plan's existing deferred Close.
		returnErr := stage.returnProgramReferencesToPlan()
		return errors.Join(
			abortErr,
			fmt.Errorf("transfer retained TC rollback to owner journal: %w", transferErr),
			rollbackErr,
			returnErr,
			handoff.Close(),
		)
	}
	closeReport, retainErr := retainTCRollbackOwner(
		record.ResourceKey,
		stage,
		handoff,
	)
	return errors.Join(
		abortErr,
		fmt.Errorf("transfer retained TC rollback to owner journal: %w", transferErr),
		rollbackErr,
		closeReport,
		retainErr,
	)
}

// ownerApplyFailureBoundary is the exact post-Execute failure state consumed
// by LinuxLoader.Apply. Keeping this boundary explicit lets the loader's
// named-return defer and plan ownership be exercised without privileged BPF
// syscalls in fault tests.
type ownerApplyFailureBoundary struct {
	plan      *tcAttachPlan
	handle    *pinPathHandle
	store     *pinOwnerStore
	record    *pinOwnerRecord
	handoff   *durableTCOwnerJournalHandoff
	stage     *tcAttachStage
	tcRuntime tcRuntime
	attachErr error
}

func (boundary *ownerApplyFailureBoundary) Resolve() error {
	if boundary == nil || boundary.plan == nil || boundary.attachErr == nil {
		return errors.New("owner apply failure boundary is incomplete")
	}
	abortErr := resolveFailedOwnerApply(
		boundary.handle,
		boundary.store,
		boundary.record,
		boundary.handoff,
		boundary.stage,
		boundary.tcRuntime,
	)
	if abortErr != nil {
		return errors.Join(
			boundary.attachErr,
			fmt.Errorf("owner-aware apply rollback: %w", abortErr),
		)
	}
	return boundary.attachErr
}

func ownerRuntimeNow(runtime pinPathRuntime) (time.Time, error) {
	if runtime.now == nil {
		return time.Time{}, errors.New("pin owner clock is unavailable")
	}
	now := runtime.now().UTC()
	if now.IsZero() {
		return time.Time{}, errors.New("pin owner clock returned zero time")
	}
	return now, nil
}

func observeOwnerMount(record *pinOwnerRecord, mountID uint64) {
	if record == nil || mountID == 0 {
		return
	}
	if !slices.Contains(record.BPFFSMountIDs, mountID) {
		record.BPFFSMountIDs = append(record.BPFFSMountIDs, mountID)
	}
	normalizePinOwnerRecord(record)
}

func validateOwnerPins(
	handle *pinPathHandle,
	record *pinOwnerRecord,
	pins []pinnedMapPin,
	requireComplete bool,
) error {
	if requireComplete {
		if err := validateOwnerMapsAgainstPins(record, pins); err != nil {
			return err
		}
	} else {
		recordMaps := make(map[string]uint32, len(record.Maps))
		for _, ownerMap := range record.Maps {
			recordMaps[ownerMap.Name] = ownerMap.ID
		}
		for _, pin := range pins {
			wantID, exists := recordMaps[pin.descriptor.name]
			if !exists || pin.observation == nil || pin.observation.id != wantID {
				return fmt.Errorf(
					"partial canonical pin %s is outside the owner record",
					pin.descriptor.name,
				)
			}
		}
	}
	ownerPin, err := ownerMapPin(pins)
	if err != nil {
		if requireComplete {
			return err
		}
		return nil
	}
	return validateOwnerSentinel(
		ownerPin.observation.owner,
		ownerPin.observation.ownerSeen,
		record,
		handle.resource,
	)
}

func ownerControlValue(pins []pinnedMapPin) (abi.ControlValue, error) {
	for _, pin := range pins {
		if pin.descriptor.name != "control_map" {
			continue
		}
		if pin.observation == nil || !pin.observation.controlSeen {
			return abi.ControlValue{}, errors.New("owner control_map value is unavailable")
		}
		return pin.observation.control, nil
	}
	return abi.ControlValue{}, errors.New("owner canonical set is missing control_map")
}

func validateOwnerControlGeneration(
	pins []pinnedMapPin,
	generation uint64,
) error {
	value, err := ownerControlValue(pins)
	if err != nil {
		if generation == 0 {
			for _, pin := range pins {
				if pin.descriptor.name == "control_map" {
					return err
				}
			}
			return nil
		}
		return err
	}
	if generation == 0 {
		if value != (abi.ControlValue{}) {
			return fmt.Errorf(
				"fresh owner control value = %+v, want zero",
				value,
			)
		}
		return nil
	}
	if value.ActiveGeneration != generation ||
		value.ABIVersion != abi.Version {
		return fmt.Errorf(
			"owner control value generation/ABI = %d/%d, want %d/%d",
			value.ActiveGeneration, value.ABIVersion,
			generation, abi.Version,
		)
	}
	return nil
}

func commitOwnerControlGeneration(
	handle *pinPathHandle,
	record *pinOwnerRecord,
	pins []pinnedMapPin,
) error {
	if record == nil || record.NextGeneration == 0 {
		return errors.New("owner recovery has no next generation to commit")
	}
	for _, pin := range pins {
		if pin.descriptor.name != "control_map" {
			continue
		}
		if pin.observation == nil || pin.observation.updateControl == nil {
			return errors.New("owner control_map update is unavailable")
		}
		value := abi.ControlValue{
			ActiveGeneration: record.NextGeneration,
			ABIVersion:       abi.Version,
		}
		if err := pin.observation.updateControl(value); err != nil {
			return fmt.Errorf("commit recovered owner control generation: %w", err)
		}
		reloaded, err := validatePinnedMapAt(
			handle,
			pin.descriptor,
			pin.descriptor.name,
			pin.observation.id,
		)
		if err != nil {
			return err
		}
		defer reloaded.observation.Close()
		if !reloaded.observation.controlSeen ||
			reloaded.observation.control != value {
			return errors.New("owner control_map did not retain recovered generation")
		}
		return nil
	}
	return errors.New("owner canonical set is missing control_map")
}

func recoverPinOwnerTransaction(
	handle *pinPathHandle,
	store *pinOwnerStore,
	record *pinOwnerRecord,
	tcRuntime tcRuntime,
) (*pinOwnerRecoveryResult, error) {
	if handle == nil || store == nil || record == nil {
		return nil, errors.New("owner recovery requires a handle, store, and record")
	}
	if err := validatePinOwnerRecord(
		record,
		handle.resource,
		handle.mountID,
	); err != nil {
		return nil, err
	}
	if err := validateOwnerDirectoryEntries(handle, record); err != nil {
		return nil, err
	}
	now, err := ownerRuntimeNow(handle.runtime)
	if err != nil {
		return nil, err
	}

	switch record.Phase {
	case pinOwnerPhaseActive:
		pins, err := inspectPinnedMapSet(handle, true)
		if err != nil {
			return nil, err
		}
		defer closePinnedMapPins(pins)
		if err := validateOwnerPins(handle, record, pins, true); err != nil {
			return nil, err
		}
		if err := validateOwnerControlGeneration(
			pins,
			record.ActiveGeneration,
		); err != nil {
			return nil, err
		}
		if err := validateOwnerTCExact(
			record.ActiveFilters,
			record.ActiveFilters,
			tcRuntime,
		); err != nil {
			return nil, err
		}
		return &pinOwnerRecoveryResult{record: record}, nil

	case pinOwnerPhaseApplying:
		return recoverApplyingPinOwnerTransaction(
			handle,
			store,
			record,
			now,
			tcRuntime,
		)

	case pinOwnerPhaseDetaching:
		return recoverDetachingPinOwnerTransaction(
			handle,
			store,
			record,
			now,
			tcRuntime,
		)

	default:
		return nil, fmt.Errorf("cannot recover owner phase %q", record.Phase)
	}
}

func recoverApplyingPinOwnerTransaction(
	handle *pinPathHandle,
	store *pinOwnerStore,
	record *pinOwnerRecord,
	now time.Time,
	tcRuntime tcRuntime,
) (*pinOwnerRecoveryResult, error) {
	pins, err := inspectPinnedMapSetWithPolicy(
		handle,
		record.ActiveGeneration != 0,
		false,
		false,
	)
	if err != nil {
		return nil, err
	}
	defer closePinnedMapPins(pins)
	if err := validateOwnerPins(
		handle,
		record,
		pins,
		record.ActiveGeneration != 0,
	); err != nil {
		return nil, err
	}
	covered := retainStaleOwnerFilters(
		record.DesiredFilters,
		record.ActiveFilters,
	)

	switch record.Step {
	case pinOwnerStepStaging:
		if err := validateOwnerControlGeneration(
			pins,
			record.ActiveGeneration,
		); err != nil {
			return nil, err
		}
		if err := validateOwnerTCExact(
			record.ActiveFilters,
			covered,
			tcRuntime,
		); err != nil {
			return nil, err
		}
		if record.ActiveGeneration == 0 {
			if err := removeOwnerProgramStages(handle, record); err != nil {
				return nil, err
			}
			detaching, err := newInitialAbortDetachingPinOwnerRecord(
				record,
				now,
			)
			if err != nil {
				return nil, err
			}
			observeOwnerMount(detaching, handle.mountID)
			if err := store.Persist(detaching, record, handle.mountID); err != nil {
				return nil, err
			}
			return recoverDetachingPinOwnerTransaction(
				handle,
				store,
				detaching,
				now,
				tcRuntime,
			)
		}
		if err := removeOwnerProgramStages(handle, record); err != nil {
			return nil, err
		}
		active, err := abortApplyingPinOwnerRecord(record, now)
		if err != nil {
			return nil, err
		}
		observeOwnerMount(active, handle.mountID)
		if err := store.Persist(active, record, handle.mountID); err != nil {
			return nil, err
		}
		return &pinOwnerRecoveryResult{record: active}, nil

	case pinOwnerStepMutating:
		programs, err := loadOwnerPrograms(handle, record)
		if err != nil {
			return nil, err
		}
		defer programs.Close()
		if err := rollForwardOwnerApplyFilters(
			record.ActiveFilters,
			record.DesiredFilters,
			programs,
			tcRuntime,
		); err != nil {
			return nil, err
		}
		control, err := ownerControlValue(pins)
		if err != nil {
			return nil, err
		}
		switch control.ActiveGeneration {
		case record.ActiveGeneration:
			if err := commitOwnerControlGeneration(
				handle,
				record,
				pins,
			); err != nil {
				return nil, err
			}
		case record.NextGeneration:
			if control.ABIVersion != abi.Version {
				return nil, errors.New("recovered owner control ABI is invalid")
			}
		default:
			return nil, fmt.Errorf(
				"owner control generation %d is outside journal old/new set",
				control.ActiveGeneration,
			)
		}
		cleanup := advancePinOwnerRecord(
			record,
			now,
			pinOwnerPhaseApplying,
			pinOwnerStepCleanup,
		)
		observeOwnerMount(cleanup, handle.mountID)
		if err := store.Persist(cleanup, record, handle.mountID); err != nil {
			return nil, err
		}
		return recoverApplyingPinOwnerTransaction(
			handle,
			store,
			cleanup,
			now,
			tcRuntime,
		)

	case pinOwnerStepRollbackCleanup:
		if err := validateOwnerControlGeneration(
			pins,
			record.ActiveGeneration,
		); err != nil {
			return nil, err
		}
		if err := validateOwnerTCExact(
			record.ActiveFilters,
			covered,
			tcRuntime,
		); err != nil {
			return nil, err
		}
		// Program stages are cleanup targets at this durable step, not
		// recovery prerequisites. removeOwnerProgramStages accepts both the
		// original and quarantined name and treats an absent target as done.
		if err := removeOwnerProgramStages(handle, record); err != nil {
			return nil, err
		}
		if record.ActiveGeneration == 0 {
			detaching, err := newInitialAbortDetachingPinOwnerRecord(
				record,
				now,
			)
			if err != nil {
				return nil, err
			}
			observeOwnerMount(detaching, handle.mountID)
			if err := store.Persist(detaching, record, handle.mountID); err != nil {
				return nil, err
			}
			return recoverDetachingPinOwnerTransaction(
				handle,
				store,
				detaching,
				now,
				tcRuntime,
			)
		}
		active, err := abortApplyingPinOwnerRecord(record, now)
		if err != nil {
			return nil, err
		}
		observeOwnerMount(active, handle.mountID)
		if err := store.Persist(active, record, handle.mountID); err != nil {
			return nil, err
		}
		return &pinOwnerRecoveryResult{record: active}, nil

	case pinOwnerStepCleanup:
		if err := validateOwnerControlGeneration(
			pins,
			record.NextGeneration,
		); err != nil {
			return nil, err
		}
		if err := validateOwnerTCExact(
			record.DesiredFilters,
			covered,
			tcRuntime,
		); err != nil {
			return nil, err
		}
		if err := removeOwnerProgramStages(handle, record); err != nil {
			return nil, err
		}
		active := completeApplyingPinOwnerRecord(record, now)
		observeOwnerMount(active, handle.mountID)
		if err := store.Persist(active, record, handle.mountID); err != nil {
			return nil, err
		}
		return &pinOwnerRecoveryResult{record: active}, nil

	default:
		return nil, fmt.Errorf("cannot recover applying step %q", record.Step)
	}
}

// abortFailedOwnerApply reports whether the active TC set was observed exact.
// Every path before that boundary is read-only. Once true is returned, a
// transient tcAttachStage no longer owns a live filter even if later journal
// cleanup or persistence fails.
func abortFailedOwnerApply(
	handle *pinPathHandle,
	store *pinOwnerStore,
	record *pinOwnerRecord,
	tcRuntime tcRuntime,
) (bool, error) {
	if record == nil ||
		record.Phase != pinOwnerPhaseApplying ||
		(record.Step != pinOwnerStepStaging &&
			record.Step != pinOwnerStepMutating) {
		return false, errors.New("failed owner apply is not at a rollback-safe journal step")
	}
	if err := validateOwnerDirectoryEntries(handle, record); err != nil {
		return false, err
	}
	pins, err := inspectPinnedMapSetWithPolicy(
		handle,
		record.ActiveGeneration != 0,
		false,
		false,
	)
	if err != nil {
		return false, err
	}
	defer closePinnedMapPins(pins)
	if err := validateOwnerPins(
		handle,
		record,
		pins,
		record.ActiveGeneration != 0,
	); err != nil {
		return false, err
	}
	if err := validateOwnerControlGeneration(
		pins,
		record.ActiveGeneration,
	); err != nil {
		return false, err
	}
	covered := retainStaleOwnerFilters(
		record.DesiredFilters,
		record.ActiveFilters,
	)
	if err := validateOwnerTCExact(
		record.ActiveFilters,
		covered,
		tcRuntime,
	); err != nil {
		return false, fmt.Errorf(
			"TC rollback did not restore the owner journal's active set: %w",
			err,
		)
	}
	rollbackVerified := true
	now, err := ownerRuntimeNow(handle.runtime)
	if err != nil {
		return rollbackVerified, err
	}
	rollbackCleanup, err := newRollbackCleanupPinOwnerRecord(record, now)
	if err != nil {
		return rollbackVerified, err
	}
	observeOwnerMount(rollbackCleanup, handle.mountID)
	if err := store.Persist(
		rollbackCleanup,
		record,
		handle.mountID,
	); err != nil {
		return rollbackVerified, err
	}
	_, err = recoverApplyingPinOwnerTransaction(
		handle,
		store,
		rollbackCleanup,
		now,
		tcRuntime,
	)
	return rollbackVerified, err
}

func executeOwnerDetachTransaction(
	handle *pinPathHandle,
	store *pinOwnerStore,
	active *pinOwnerRecord,
	tcRuntime tcRuntime,
) error {
	now, err := ownerRuntimeNow(handle.runtime)
	if err != nil {
		return err
	}
	detaching, err := newDetachingPinOwnerRecord(active, now)
	if err != nil {
		return err
	}
	observeOwnerMount(detaching, handle.mountID)
	if err := store.Persist(detaching, active, handle.mountID); err != nil {
		return err
	}

	pins, err := inspectPinnedMapSet(handle, true)
	if err != nil {
		return err
	}
	defer closePinnedMapPins(pins)
	if err := validateOwnerPins(handle, detaching, pins, true); err != nil {
		return err
	}
	if err := stageOwnerPrograms(handle, detaching); err != nil {
		return err
	}
	if err := stageOwnerMaps(handle, detaching, pins); err != nil {
		return err
	}
	mutating := advancePinOwnerRecord(
		detaching,
		now,
		pinOwnerPhaseDetaching,
		pinOwnerStepMutatingTC,
	)
	observeOwnerMount(mutating, handle.mountID)
	if err := store.Persist(mutating, detaching, handle.mountID); err != nil {
		return err
	}
	programs, err := loadOwnerPrograms(handle, mutating)
	if err != nil {
		return err
	}
	defer programs.Close()
	mapStages, err := loadOwnerMapStages(handle, mutating)
	if err != nil {
		return err
	}
	defer mapStages.Close()
	if err := rollForwardOwnerDetachFilters(
		mutating.ActiveFilters,
		programs,
		tcRuntime,
	); err != nil {
		rollbackErr := rollbackOwnerDetachToActive(
			handle,
			store,
			mutating,
			programs,
			mapStages,
			tcRuntime,
		)
		return errors.Join(
			err,
			wrapNonNilError("rollback failed owner detach", rollbackErr),
		)
	}
	unlinking := advancePinOwnerRecord(
		mutating,
		now,
		pinOwnerPhaseDetaching,
		pinOwnerStepUnlinkingMaps,
	)
	observeOwnerMount(unlinking, handle.mountID)
	if err := store.Persist(unlinking, mutating, handle.mountID); err != nil {
		return err
	}
	if err := removeCanonicalOwnerMaps(
		handle,
		unlinking,
		mapStages,
	); err != nil {
		rollbackErr := rollbackOwnerDetachToActive(
			handle,
			store,
			unlinking,
			programs,
			mapStages,
			tcRuntime,
		)
		return errors.Join(
			err,
			wrapNonNilError("rollback failed owner map unlink", rollbackErr),
		)
	}
	cleanup := advancePinOwnerRecord(
		unlinking,
		now,
		pinOwnerPhaseDetaching,
		pinOwnerStepCleanupStages,
	)
	observeOwnerMount(cleanup, handle.mountID)
	if err := store.Persist(cleanup, unlinking, handle.mountID); err != nil {
		return err
	}
	_, err = recoverDetachingPinOwnerTransaction(
		handle,
		store,
		cleanup,
		now,
		tcRuntime,
	)
	return err
}

func wrapNonNilError(prefix string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", prefix, err)
}

func rollbackOwnerDetachToActive(
	handle *pinPathHandle,
	store *pinOwnerStore,
	record *pinOwnerRecord,
	programs *loadedOwnerPrograms,
	mapStages *loadedOwnerMapStages,
	tcRuntime tcRuntime,
) error {
	var errs []error
	if err := restoreCanonicalOwnerMaps(
		handle,
		record,
		mapStages,
	); err != nil {
		errs = append(errs, fmt.Errorf("restore canonical owner maps: %w", err))
	}
	if err := restoreOwnerActiveFilters(
		record.ActiveFilters,
		programs,
		tcRuntime,
	); err != nil {
		errs = append(errs, fmt.Errorf("restore owner TC filters: %w", err))
	}
	if len(errs) != 0 {
		return errors.Join(errs...)
	}
	if err := removeOwnerProgramStages(handle, record); err != nil {
		return err
	}
	if err := removeOwnerMapStages(handle, record); err != nil {
		return err
	}
	now, err := ownerRuntimeNow(handle.runtime)
	if err != nil {
		return err
	}
	active, err := abortDetachingPinOwnerRecord(record, now)
	if err != nil {
		return err
	}
	observeOwnerMount(active, handle.mountID)
	return store.Persist(active, record, handle.mountID)
}

func recoverRolledBackOwnerDetach(
	handle *pinPathHandle,
	store *pinOwnerStore,
	record *pinOwnerRecord,
	now time.Time,
	tcRuntime tcRuntime,
) (*pinOwnerRecoveryResult, bool, error) {
	if record.ActiveGeneration == 0 ||
		(record.Step != pinOwnerStepMutatingTC &&
			record.Step != pinOwnerStepUnlinkingMaps) {
		return nil, false, nil
	}
	if err := validateOwnerTCExact(
		record.ActiveFilters,
		record.ActiveFilters,
		tcRuntime,
	); err != nil {
		return nil, false, nil
	}
	pins, err := inspectPinnedMapSet(handle, true)
	if err != nil {
		return nil, false, nil
	}
	defer closePinnedMapPins(pins)
	if err := validateOwnerPins(handle, record, pins, true); err != nil {
		return nil, false, nil
	}
	if err := validateOwnerControlGeneration(
		pins,
		record.ActiveGeneration,
	); err != nil {
		return nil, false, nil
	}
	if err := removeOwnerProgramStages(handle, record); err != nil {
		return nil, true, err
	}
	if err := removeOwnerMapStages(handle, record); err != nil {
		return nil, true, err
	}
	active, err := abortDetachingPinOwnerRecord(record, now)
	if err != nil {
		return nil, true, err
	}
	observeOwnerMount(active, handle.mountID)
	if err := store.Persist(active, record, handle.mountID); err != nil {
		return nil, true, err
	}
	return &pinOwnerRecoveryResult{record: active}, true, nil
}

func recoverDetachingPinOwnerTransaction(
	handle *pinPathHandle,
	store *pinOwnerStore,
	record *pinOwnerRecord,
	now time.Time,
	tcRuntime tcRuntime,
) (*pinOwnerRecoveryResult, error) {
	if recovered, handled, err := recoverRolledBackOwnerDetach(
		handle,
		store,
		record,
		now,
		tcRuntime,
	); handled {
		return recovered, err
	}
	switch record.Step {
	case pinOwnerStepStaging:
		pins, err := inspectPinnedMapSetWithPolicy(
			handle,
			record.ActiveGeneration != 0,
			record.ActiveGeneration != 0,
			false,
		)
		if err != nil {
			return nil, err
		}
		defer closePinnedMapPins(pins)
		if err := validateOwnerPins(
			handle,
			record,
			pins,
			record.ActiveGeneration != 0,
		); err != nil {
			return nil, err
		}
		if err := validateOwnerControlGeneration(
			pins,
			record.ActiveGeneration,
		); err != nil {
			return nil, err
		}
		if err := validateOwnerTCExact(
			record.ActiveFilters,
			record.ActiveFilters,
			tcRuntime,
		); err != nil {
			return nil, err
		}
		if err := stageOwnerPrograms(handle, record); err != nil {
			return nil, err
		}
		if err := stageOwnerMaps(handle, record, pins); err != nil {
			return nil, err
		}
		mutating := advancePinOwnerRecord(
			record,
			now,
			pinOwnerPhaseDetaching,
			pinOwnerStepMutatingTC,
		)
		observeOwnerMount(mutating, handle.mountID)
		if err := store.Persist(mutating, record, handle.mountID); err != nil {
			return nil, err
		}
		return recoverDetachingPinOwnerTransaction(
			handle,
			store,
			mutating,
			now,
			tcRuntime,
		)

	case pinOwnerStepMutatingTC:
		programs, err := loadOwnerPrograms(handle, record)
		if err != nil {
			return nil, err
		}
		defer programs.Close()
		mapStages, err := loadOwnerMapStages(handle, record)
		if err != nil {
			return nil, err
		}
		defer mapStages.Close()
		if err := rollForwardOwnerDetachFilters(
			record.ActiveFilters,
			programs,
			tcRuntime,
		); err != nil {
			return nil, err
		}
		unlinking := advancePinOwnerRecord(
			record,
			now,
			pinOwnerPhaseDetaching,
			pinOwnerStepUnlinkingMaps,
		)
		observeOwnerMount(unlinking, handle.mountID)
		if err := store.Persist(unlinking, record, handle.mountID); err != nil {
			return nil, err
		}
		return recoverDetachingPinOwnerTransaction(
			handle,
			store,
			unlinking,
			now,
			tcRuntime,
		)

	case pinOwnerStepUnlinkingMaps:
		if err := validateOwnerTCExact(
			nil,
			record.ActiveFilters,
			tcRuntime,
		); err != nil {
			return nil, err
		}
		mapStages, err := loadOwnerMapStages(handle, record)
		if err != nil {
			return nil, err
		}
		defer mapStages.Close()
		partial, err := inspectPinnedMapSetWithPolicy(
			handle,
			false,
			false,
			false,
		)
		if err != nil {
			return nil, err
		}
		defer closePinnedMapPins(partial)
		if err := validateOwnerPins(
			handle,
			record,
			partial,
			false,
		); err != nil {
			return nil, err
		}
		if err := removeCanonicalOwnerMaps(
			handle,
			record,
			mapStages,
		); err != nil {
			return nil, err
		}
		cleanup := advancePinOwnerRecord(
			record,
			now,
			pinOwnerPhaseDetaching,
			pinOwnerStepCleanupStages,
		)
		observeOwnerMount(cleanup, handle.mountID)
		if err := store.Persist(cleanup, record, handle.mountID); err != nil {
			return nil, err
		}
		return recoverDetachingPinOwnerTransaction(
			handle,
			store,
			cleanup,
			now,
			tcRuntime,
		)

	case pinOwnerStepCleanupStages:
		if err := validateOwnerTCExact(
			nil,
			record.ActiveFilters,
			tcRuntime,
		); err != nil {
			return nil, err
		}
		if err := removeOwnerProgramStages(handle, record); err != nil {
			return nil, err
		}
		if err := removeOwnerMapStages(handle, record); err != nil {
			return nil, err
		}
		empty, err := pinDirectoryIsEmpty(handle.targetFD, handle.pinPath)
		if err != nil {
			return nil, err
		}
		if !empty {
			return nil, errors.New("owner detach left unexpected BPF pin entries")
		}
		if err := store.Remove(record); err != nil {
			return nil, err
		}
		if err := handle.recheckTargetEntry(); err != nil {
			return nil, err
		}
		if err := unix.Unlinkat(
			handle.parentFD,
			handle.base,
			unix.AT_REMOVEDIR,
		); err != nil {
			return nil, fmt.Errorf(
				"remove empty owned BPF pin path %s: %w",
				handle.pinPath, err,
			)
		}
		return &pinOwnerRecoveryResult{directoryRemoved: true}, nil

	default:
		return nil, fmt.Errorf("cannot recover detaching step %q", record.Step)
	}
}
