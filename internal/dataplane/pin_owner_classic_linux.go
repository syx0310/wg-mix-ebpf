//go:build linux

package dataplane

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/pinidentity"
	"golang.org/x/sys/unix"
)

func validateClassicOwnerDirectoryEntries(
	handle *pinPathHandle,
	record *pinOwnerRecord,
) error {
	if handle == nil || record == nil {
		return errors.New("owner directory validation requires a handle and record")
	}
	if err := handle.recheckTargetEntry(); err != nil {
		return err
	}
	directoryFD, err := unix.Openat(
		handle.targetFD,
		".",
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(directoryFD), handle.pinPath)
	entries, readErr := directory.ReadDir(257)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	if len(entries) > 256 {
		return errors.New("BPF pin directory has more than 256 entries")
	}

	canonical := make(map[string]struct{}, len(pinnedMapDescriptors()))
	allowed := make(map[string]struct{}, len(entries))
	for _, descriptor := range pinnedMapDescriptors() {
		canonical[descriptor.name] = struct{}{}
		allowed[descriptor.name] = struct{}{}
	}
	for _, stage := range record.ProgramStages {
		allowed[stage.FileName] = struct{}{}
		allowed[stage.FileName+".retired"] = struct{}{}
	}
	for _, stage := range record.MapStages {
		allowed[stage.FileName] = struct{}{}
		allowed[stage.FileName+".retired"] = struct{}{}
		allowed[stage.FileName+".canonical-retired"] = struct{}{}
	}

	seen := make(map[string]struct{}, len(entries))
	canonicalCount := 0
	for _, entry := range entries {
		name := entry.Name()
		if _, duplicate := seen[name]; duplicate {
			return fmt.Errorf("BPF pin directory repeats entry %q", name)
		}
		seen[name] = struct{}{}
		if _, ok := allowed[name]; !ok {
			return fmt.Errorf(
				"unknown BPF pin entry %q is not covered by owner transaction sequence %d",
				name, record.Sequence,
			)
		}
		if _, ok := canonical[name]; ok {
			canonicalCount++
		}
	}

	wantCanonical := len(canonical)
	switch {
	case record.Phase == pinOwnerPhaseActive:
		if canonicalCount != wantCanonical || len(seen) != wantCanonical {
			return fmt.Errorf(
				"active owner directory has %d canonical and %d total entries, want %d",
				canonicalCount, len(seen), wantCanonical,
			)
		}
	case record.Phase == pinOwnerPhaseApplying:
		if record.Step == pinOwnerStepStaging &&
			record.ActiveGeneration == 0 {
			break
		}
		if canonicalCount != wantCanonical {
			return fmt.Errorf(
				"applying owner directory has %d canonical maps, want %d",
				canonicalCount, wantCanonical,
			)
		}
	case record.Phase == pinOwnerPhaseDetaching &&
		(record.Step == pinOwnerStepStaging ||
			record.Step == pinOwnerStepMutatingTC):
		if record.ActiveGeneration == 0 {
			break
		}
		if canonicalCount != wantCanonical {
			return fmt.Errorf(
				"detaching owner directory has %d canonical maps before unlink, want %d",
				canonicalCount, wantCanonical,
			)
		}
	case record.Phase == pinOwnerPhaseDetaching &&
		record.Step == pinOwnerStepCleanupStages:
		if canonicalCount != 0 {
			return fmt.Errorf(
				"detaching cleanup has %d canonical maps, want none",
				canonicalCount,
			)
		}
	}
	return nil
}

func newClassicActivePinOwnerRecord(
	parent *pinPathParent,
	token [32]byte,
	bootID string,
	now time.Time,
	generation uint64,
	maps []pinOwnerMapIdentity,
	filters []tcFilterBinding,
) (*pinOwnerRecord, error) {
	if parent == nil {
		return nil, errors.New("pin owner parent is nil")
	}
	timestamp := now.UTC().Format(time.RFC3339Nano)
	record := &pinOwnerRecord{
		Version:          pinOwnerLegacyClassicVersion,
		Sequence:         1,
		ResourceKey:      parent.resource.key,
		ParentDevice:     parent.resource.parentDevice,
		ParentInode:      parent.resource.parentInode,
		PinBaseName:      parent.resource.base,
		PinPath:          parent.pinPath,
		BPFFSRootPath:    filepath.Dir(parent.pinPath),
		BPFFSMountIDs:    []uint64{parent.mountID},
		BootID:           bootID,
		Token:            hex.EncodeToString(token[:]),
		CreatedAt:        timestamp,
		UpdatedAt:        timestamp,
		Phase:            pinOwnerPhaseActive,
		Step:             pinOwnerStepReady,
		ActiveGeneration: generation,
		Maps:             slices.Clone(maps),
		ActiveFilters:    slices.Clone(filters),
		DesiredFilters:   []tcFilterBinding{},
		ProgramStages:    []pinOwnerProgramStage{},
		MapStages:        []pinOwnerMapStage{},
	}
	normalizePinOwnerRecord(record)
	if err := validateClassicPinOwnerRecord(record, parent.resource, parent.mountID); err != nil {
		return nil, err
	}
	return record, nil
}

func newClassicApplyingPinOwnerRecord(
	parent *pinPathParent,
	token [32]byte,
	bootID string,
	now time.Time,
	activeGeneration uint64,
	nextGeneration uint64,
	maps []pinOwnerMapIdentity,
	activeFilters []tcFilterBinding,
	desiredFilters []tcFilterBinding,
	previous *pinOwnerRecord,
) (*pinOwnerRecord, error) {
	if parent == nil {
		return nil, errors.New("pin owner parent is nil")
	}
	if nextGeneration == 0 {
		return nil, errors.New("applying owner record requires a non-zero next generation")
	}
	timestamp := now.UTC().Format(time.RFC3339Nano)
	sequence := uint64(1)
	createdAt := timestamp
	if previous != nil {
		sequence = previous.Sequence + 1
		createdAt = previous.CreatedAt
	}
	record := &pinOwnerRecord{
		Version:          pinOwnerLegacyClassicVersion,
		Sequence:         sequence,
		ResourceKey:      parent.resource.key,
		ParentDevice:     parent.resource.parentDevice,
		ParentInode:      parent.resource.parentInode,
		PinBaseName:      parent.resource.base,
		PinPath:          parent.pinPath,
		BPFFSRootPath:    filepath.Dir(parent.pinPath),
		BPFFSMountIDs:    []uint64{parent.mountID},
		BootID:           bootID,
		Token:            hex.EncodeToString(token[:]),
		CreatedAt:        createdAt,
		UpdatedAt:        timestamp,
		Phase:            pinOwnerPhaseApplying,
		Step:             pinOwnerStepStaging,
		ActiveGeneration: activeGeneration,
		NextGeneration:   nextGeneration,
		Maps:             slices.Clone(maps),
		ActiveFilters:    slices.Clone(activeFilters),
		DesiredFilters:   slices.Clone(desiredFilters),
		MapStages:        []pinOwnerMapStage{},
	}
	if previous != nil {
		record.BPFFSMountIDs = slices.Clone(previous.BPFFSMountIDs)
		record.RetiredFromResourceKey = previous.RetiredFromResourceKey
		record.RetiredFromBootID = previous.RetiredFromBootID
		if !slices.Contains(record.BPFFSMountIDs, parent.mountID) {
			record.BPFFSMountIDs = append(record.BPFFSMountIDs, parent.mountID)
		}
	}
	record.ProgramStages = buildClassicOwnerProgramStages(
		record.ResourceKey,
		token,
		record.ActiveFilters,
		record.DesiredFilters,
	)
	normalizePinOwnerRecord(record)
	if err := validateClassicPinOwnerRecord(record, parent.resource, parent.mountID); err != nil {
		return nil, err
	}
	return record, nil
}

func sortTCFilterBindings(filters []tcFilterBinding) {
	sort.Slice(filters, func(i, j int) bool {
		left := filters[i]
		right := filters[j]
		if left.IfIndex != right.IfIndex {
			return left.IfIndex < right.IfIndex
		}
		leftDirection := 0
		if left.Direction == "egress" {
			leftDirection = 1
		}
		rightDirection := 0
		if right.Direction == "egress" {
			rightDirection = 1
		}
		if leftDirection != rightDirection {
			return leftDirection < rightDirection
		}
		if left.Parent != right.Parent {
			return left.Parent < right.Parent
		}
		if left.Handle != right.Handle {
			return left.Handle < right.Handle
		}
		if left.Priority != right.Priority {
			return left.Priority < right.Priority
		}
		return left.ProgramID < right.ProgramID
	})
}

func retainStaleOwnerFilters(
	desired []tcFilterBinding,
	active []tcFilterBinding,
) []tcFilterBinding {
	desiredSlots := make(map[string]struct{}, len(desired))
	out := slices.Clone(desired)
	for _, filter := range desired {
		desiredSlots[fmt.Sprintf("%d/%s", filter.IfIndex, filter.Direction)] = struct{}{}
	}
	for _, filter := range active {
		key := fmt.Sprintf("%d/%s", filter.IfIndex, filter.Direction)
		if _, replaced := desiredSlots[key]; replaced {
			continue
		}
		out = append(out, filter)
	}
	sortTCFilterBindings(out)
	return out
}

func validateClassicPinOwnerRecord(
	record *pinOwnerRecord,
	resource pinResourceIdentity,
	currentMountID uint64,
) error {
	if record == nil {
		return errors.New("pin owner record is nil")
	}
	if record.Version != pinOwnerLegacyClassicVersion {
		return fmt.Errorf("pin owner record version = %d, want %d", record.Version, pinOwnerLegacyClassicVersion)
	}
	if record.Sequence == 0 {
		return errors.New("pin owner record sequence is zero")
	}
	if !pinidentity.ValidKey(record.ResourceKey) ||
		record.ResourceKey != resource.key ||
		record.ParentDevice != resource.parentDevice ||
		record.ParentInode != resource.parentInode ||
		record.PinBaseName != resource.base {
		return errors.New("pin owner record resource identity does not match the FD-anchored bpffs target")
	}
	if record.PinPath == "" || !filepath.IsAbs(record.PinPath) ||
		filepath.Clean(record.PinPath) != record.PinPath ||
		filepath.Base(record.PinPath) != resource.base {
		return fmt.Errorf("pin owner record path %q is not canonical", record.PinPath)
	}
	if record.BPFFSRootPath == "" || !filepath.IsAbs(record.BPFFSRootPath) ||
		filepath.Clean(record.BPFFSRootPath) != record.BPFFSRootPath ||
		record.BPFFSRootPath == string(filepath.Separator) {
		return fmt.Errorf("pin owner bpffs root path %q is not canonical", record.BPFFSRootPath)
	}
	if filepath.Dir(record.PinPath) != record.BPFFSRootPath {
		return errors.New("pin owner record pin path is not a direct child of its bpffs root path")
	}
	if !bootIDPattern.MatchString(record.BootID) {
		return fmt.Errorf("pin owner boot ID %q is not canonical", record.BootID)
	}
	if _, err := tokenFromOwnerRecord(record); err != nil {
		return err
	}
	createdAt, err := time.Parse(time.RFC3339Nano, record.CreatedAt)
	if err != nil {
		return fmt.Errorf("parse pin owner created_at: %w", err)
	}
	if record.CreatedAt != createdAt.UTC().Format(time.RFC3339Nano) {
		return errors.New("pin owner created_at is not canonical RFC3339Nano UTC")
	}
	updatedAt, err := time.Parse(time.RFC3339Nano, record.UpdatedAt)
	if err != nil {
		return fmt.Errorf("parse pin owner updated_at: %w", err)
	}
	if record.UpdatedAt != updatedAt.UTC().Format(time.RFC3339Nano) {
		return errors.New("pin owner updated_at is not canonical RFC3339Nano UTC")
	}
	if updatedAt.Before(createdAt) {
		return errors.New("pin owner updated_at precedes created_at")
	}
	if len(record.BPFFSMountIDs) == 0 {
		return errors.New("pin owner record has no observed bpffs mount IDs")
	}
	seenMountIDs := make(map[uint64]struct{}, len(record.BPFFSMountIDs))
	for index, mountID := range record.BPFFSMountIDs {
		if mountID == 0 {
			return errors.New("pin owner record contains a zero bpffs mount ID")
		}
		if _, duplicate := seenMountIDs[mountID]; duplicate {
			return fmt.Errorf("pin owner record repeats bpffs mount ID %d", mountID)
		}
		if index != 0 && record.BPFFSMountIDs[index-1] > mountID {
			return errors.New("pin owner bpffs mount IDs are not sorted")
		}
		seenMountIDs[mountID] = struct{}{}
	}
	// A bind-mount alias may have a different mount ID while still resolving to
	// the same FD-anchored parent device/inode. The next mutation appends that
	// ID; loading the descriptor must not turn such an alias into a separate
	// ownership domain.
	_ = currentMountID
	if (record.RetiredFromResourceKey == "") !=
		(record.RetiredFromBootID == "") {
		return errors.New("pin owner reboot lineage must include both resource key and boot ID")
	}
	if record.RetiredFromResourceKey != "" {
		if !pinidentity.ValidKey(record.RetiredFromResourceKey) ||
			!bootIDPattern.MatchString(record.RetiredFromBootID) ||
			record.RetiredFromBootID == record.BootID {
			return errors.New("pin owner reboot lineage is invalid")
		}
	}
	if err := validateOwnerMaps(record.Maps); err != nil {
		return err
	}
	if len(record.ActiveLinks) != 0 || len(record.DesiredLinks) != 0 {
		return errors.New("pin owner schema v3 must not contain TCX links")
	}
	if err := validateClassicOwnerFilters(record.ActiveFilters, "active"); err != nil {
		return err
	}
	if err := validateClassicOwnerFilters(record.DesiredFilters, "desired"); err != nil {
		return err
	}
	if err := validateClassicOwnerStages(record); err != nil {
		return err
	}
	switch record.Phase {
	case pinOwnerPhaseActive:
		if record.Step != pinOwnerStepReady ||
			record.ActiveGeneration == 0 ||
			record.NextGeneration != 0 ||
			len(record.DesiredFilters) != 0 ||
			len(record.ProgramStages) != 0 ||
			len(record.MapStages) != 0 {
			return errors.New("active pin owner record has inconsistent transaction fields")
		}
	case pinOwnerPhaseApplying:
		if record.Step != pinOwnerStepStaging &&
			record.Step != pinOwnerStepMutating &&
			record.Step != pinOwnerStepCleanup {
			return fmt.Errorf("applying pin owner record has invalid step %q", record.Step)
		}
		if record.NextGeneration == 0 ||
			len(record.MapStages) != 0 {
			return errors.New("applying pin owner record has incomplete transaction intent")
		}
	case pinOwnerPhaseDetaching:
		if record.Step != pinOwnerStepStaging &&
			record.Step != pinOwnerStepMutatingTC &&
			record.Step != pinOwnerStepUnlinkingMaps &&
			record.Step != pinOwnerStepCleanupStages {
			return fmt.Errorf("detaching pin owner record has invalid step %q", record.Step)
		}
		if record.NextGeneration != 0 ||
			len(record.DesiredFilters) != 0 ||
			len(record.MapStages) != len(pinnedMapDescriptors()) {
			return errors.New("detaching pin owner record has incomplete transaction intent")
		}
		if record.ActiveGeneration == 0 &&
			(len(record.ActiveFilters) != 0 ||
				len(record.ProgramStages) != 0) {
			return errors.New("fresh abort detach unexpectedly owns active filters or programs")
		}
	default:
		return fmt.Errorf("pin owner record has invalid phase %q", record.Phase)
	}
	return nil
}

func validateClassicOwnerFilters(filters []tcFilterBinding, label string) error {
	previousIfindex := -1
	seen := make(map[string]struct{}, len(filters))
	for index, filter := range filters {
		if filter.IfIndex <= 0 || filter.ProgramID == 0 {
			return fmt.Errorf("%s filter[%d] has an invalid ifindex or program ID", label, index)
		}
		var slot tcFilterSlot
		switch filter.Direction {
		case "ingress":
			slot = canonicalTCFilterSlots()[0]
		case "egress":
			slot = canonicalTCFilterSlots()[1]
		default:
			return fmt.Errorf("%s filter[%d] has invalid direction %q", label, index, filter.Direction)
		}
		if filter.Parent != slot.parent ||
			filter.Handle != slot.handle ||
			filter.Priority != filterPriority {
			return fmt.Errorf("%s filter[%d] does not use its canonical TC slot", label, index)
		}
		key := fmt.Sprintf("%d/%s", filter.IfIndex, filter.Direction)
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("%s filters repeat %s", label, key)
		}
		seen[key] = struct{}{}
		if filter.IfIndex < previousIfindex {
			return fmt.Errorf("%s filters are not sorted", label)
		}
		previousIfindex = filter.IfIndex
	}
	sorted := slices.Clone(filters)
	sortTCFilterBindings(sorted)
	if !slices.Equal(sorted, filters) {
		return fmt.Errorf("%s filters are not canonically sorted", label)
	}
	return nil
}

func validateClassicOwnerStages(record *pinOwnerRecord) error {
	token, err := tokenFromOwnerRecord(record)
	if err != nil {
		return err
	}
	expectedPrograms := []pinOwnerProgramStage{}
	switch record.Phase {
	case pinOwnerPhaseApplying:
		expectedPrograms = buildClassicOwnerProgramStages(
			record.ResourceKey,
			token,
			record.ActiveFilters,
			record.DesiredFilters,
		)
	case pinOwnerPhaseDetaching:
		expectedPrograms = buildClassicOwnerProgramStages(
			record.ResourceKey,
			token,
			record.ActiveFilters,
			nil,
		)
	}
	if !slices.Equal(record.ProgramStages, expectedPrograms) {
		return errors.New("classic program stage list does not exactly cover the owner transaction programs")
	}
	activeIDs := make(map[uint32]struct{})
	for _, filter := range record.ActiveFilters {
		activeIDs[filter.ProgramID] = struct{}{}
	}
	desiredIDs := make(map[uint32]struct{})
	for _, filter := range record.DesiredFilters {
		desiredIDs[filter.ProgramID] = struct{}{}
	}
	seenProgramFiles := make(map[string]struct{}, len(record.ProgramStages))
	for _, stage := range record.ProgramStages {
		if filepath.Base(stage.FileName) != stage.FileName ||
			stage.ProgramID == 0 {
			return fmt.Errorf("unsafe pin owner program stage %+v", stage)
		}
		switch stage.Kind {
		case pinOwnerProgramStageActive:
			if _, ok := activeIDs[stage.ProgramID]; !ok {
				return fmt.Errorf("active program stage ID %d is not an active filter program", stage.ProgramID)
			}
		case pinOwnerProgramStageNext:
			if _, ok := desiredIDs[stage.ProgramID]; !ok {
				return fmt.Errorf("desired program stage ID %d is not a desired filter program", stage.ProgramID)
			}
		default:
			return fmt.Errorf("program stage has invalid kind %q", stage.Kind)
		}
		want := pinOwnerProgramStageName(record.ResourceKey, token, stage.Kind, stage.ProgramID)
		if stage.FileName != want {
			return fmt.Errorf("program stage filename = %q, want %q", stage.FileName, want)
		}
		if _, duplicate := seenProgramFiles[stage.FileName]; duplicate {
			return fmt.Errorf("duplicate program stage filename %q", stage.FileName)
		}
		seenProgramFiles[stage.FileName] = struct{}{}
	}
	if len(record.MapStages) != 0 {
		mapIDs := make(map[string]uint32, len(record.Maps))
		for _, ownerMap := range record.Maps {
			mapIDs[ownerMap.Name] = ownerMap.ID
		}
		if len(record.MapStages) != len(record.Maps) {
			return errors.New("map stage list does not cover every canonical owner map")
		}
		for index, stage := range record.MapStages {
			ownerMap := record.Maps[index]
			if stage.Name != ownerMap.Name ||
				stage.MapID != ownerMap.ID ||
				stage.FileName != pinOwnerMapStageName(record.ResourceKey, token, stage.Name) {
				return fmt.Errorf("map stage[%d] does not match canonical map %s", index, ownerMap.Name)
			}
			if mapIDs[stage.Name] != stage.MapID {
				return fmt.Errorf("map stage %s has mismatched ID", stage.Name)
			}
		}
	}
	return nil
}

func buildClassicOwnerProgramStages(
	resourceKey string,
	token [32]byte,
	active []tcFilterBinding,
	desired []tcFilterBinding,
) []pinOwnerProgramStage {
	type stageKey struct {
		id   uint32
		kind string
	}
	seen := make(map[stageKey]struct{})
	var stages []pinOwnerProgramStage
	add := func(filters []tcFilterBinding, kind string) {
		for _, filter := range filters {
			key := stageKey{id: filter.ProgramID, kind: kind}
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			stages = append(stages, pinOwnerProgramStage{
				FileName:  pinOwnerProgramStageName(resourceKey, token, kind, filter.ProgramID),
				ProgramID: filter.ProgramID,
				Kind:      kind,
			})
		}
	}
	add(active, pinOwnerProgramStageActive)
	add(desired, pinOwnerProgramStageNext)
	sort.Slice(stages, func(i, j int) bool {
		if stages[i].ProgramID != stages[j].ProgramID {
			return stages[i].ProgramID < stages[j].ProgramID
		}
		if stages[i].Kind != stages[j].Kind {
			return stages[i].Kind < stages[j].Kind
		}
		return stages[i].FileName < stages[j].FileName
	})
	return stages
}
