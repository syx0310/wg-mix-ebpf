//go:build linux

package dataplane

import (
	"bytes"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/syx0310/wg-mix-ebpf/internal/pinidentity"
	"golang.org/x/sys/unix"
)

const (
	pinOwnerSentinelVersion = 1
	pinOwnerRecordVersion   = 3
	pinOwnerRecordMaxBytes  = 256 * 1024

	pinOwnerPhaseActive    = "active"
	pinOwnerPhaseApplying  = "applying"
	pinOwnerPhaseDetaching = "detaching"

	pinOwnerStepReady           = "ready"
	pinOwnerStepStaging         = "staging"
	pinOwnerStepMutating        = "mutating"
	pinOwnerStepRollbackCleanup = "rollback_cleanup"
	pinOwnerStepMutatingTC      = "mutating_tc"
	pinOwnerStepUnlinkingMaps   = "unlinking_maps"
	pinOwnerStepCleanup         = "cleanup"
	pinOwnerStepCleanupStages   = "cleanup_stages"
	pinOwnerProgramStageActive  = "active"
	pinOwnerProgramStageNext    = "desired"
)

var bootIDPattern = regexp.MustCompile(
	`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`,
)

type pinOwnerMapIdentity struct {
	Name string `json:"name"`
	ID   uint32 `json:"id"`
}

type pinOwnerProgramStage struct {
	FileName  string `json:"filename"`
	ProgramID uint32 `json:"program_id"`
	Kind      string `json:"kind"`
}

type pinOwnerMapStage struct {
	Name     string `json:"name"`
	FileName string `json:"filename"`
	MapID    uint32 `json:"map_id"`
}

type pinOwnerRecord struct {
	Version                int                    `json:"version"`
	Sequence               uint64                 `json:"sequence"`
	ResourceKey            string                 `json:"resource_key"`
	ParentDevice           uint64                 `json:"parent_device"`
	ParentInode            uint64                 `json:"parent_inode"`
	PinBaseName            string                 `json:"pin_basename"`
	PinPath                string                 `json:"pin_path"`
	BPFFSRootPath          string                 `json:"bpffs_root_path"`
	BPFFSMountIDs          []uint64               `json:"bpffs_mount_ids"`
	BootID                 string                 `json:"boot_id"`
	Token                  string                 `json:"token"`
	CreatedAt              string                 `json:"created_at"`
	UpdatedAt              string                 `json:"updated_at"`
	Phase                  string                 `json:"phase"`
	Step                   string                 `json:"step"`
	ActiveGeneration       uint64                 `json:"active_generation"`
	NextGeneration         uint64                 `json:"next_generation"`
	Maps                   []pinOwnerMapIdentity  `json:"maps"`
	ActiveFilters          []tcFilterBinding      `json:"active_filters"`
	DesiredFilters         []tcFilterBinding      `json:"desired_filters"`
	ProgramStages          []pinOwnerProgramStage `json:"program_stages"`
	MapStages              []pinOwnerMapStage     `json:"map_stages"`
	RetiredFromResourceKey string                 `json:"retired_from_resource_key"`
	RetiredFromBootID      string                 `json:"retired_from_boot_id"`
}

type pinOwnerStore struct {
	root                *anchoredDirectoryPath
	resource            pinResourceIdentity
	expectedUID         uint32
	fileName            string
	draftName           string
	nextName            string
	retiredName         string
	beforeOwnerExchange func()
	descriptorOps       pinOwnerDescriptorOps
	now                 func() time.Time
}

// pinOwnerDescriptorOps keeps the small set of durability primitives used by
// owner and index publication injectable for deterministic crash testing. Live
// stores always use the syscall-backed defaults below.
type pinOwnerDescriptorOps struct {
	create   func(*anchoredDirectoryPath, string, uint32, uint32) (*os.File, pinPathInodeIdentity, error)
	validate func(*anchoredDirectoryPath, string, int, uint32, uint32, *pinPathInodeIdentity) (pinPathInodeIdentity, error)
	write    func(*os.File, []byte) (int, error)
	syncFile func(*os.File) error
	rename   func(*anchoredDirectoryPath, string, string, uint) error
	syncDir  func(*anchoredDirectoryPath) error
}

func livePinOwnerDescriptorOps() pinOwnerDescriptorOps {
	return pinOwnerDescriptorOps{
		create:   createAnchoredRegularFileExclusive,
		validate: validateAnchoredRegularFile,
		write: func(file *os.File, data []byte) (int, error) {
			return file.Write(data)
		},
		syncFile: func(file *os.File) error { return file.Sync() },
		rename: func(
			root *anchoredDirectoryPath,
			oldName string,
			newName string,
			flags uint,
		) error {
			return unix.Renameat2(root.FD(), oldName, root.FD(), newName, flags)
		},
		syncDir: func(root *anchoredDirectoryPath) error {
			return unix.Fsync(root.FD())
		},
	}
}

type canonicalPinDirectoryState int

const (
	canonicalPinsEmpty canonicalPinDirectoryState = iota
	canonicalPinsLegacy
	canonicalPinsOwned
)

func readLinuxBootID() (string, error) {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", fmt.Errorf("read kernel boot ID: %w", err)
	}
	bootID := strings.TrimSpace(string(data))
	if !bootIDPattern.MatchString(bootID) {
		return "", fmt.Errorf("kernel boot ID %q is not canonical", bootID)
	}
	return bootID, nil
}

func classifyCanonicalPinDirectory(
	handle *pinPathHandle,
) (canonicalPinDirectoryState, error) {
	if handle == nil {
		return canonicalPinsEmpty, nil
	}
	if err := handle.recheckTargetEntry(); err != nil {
		return canonicalPinsEmpty, err
	}
	directoryFD, err := unix.Openat(
		handle.targetFD,
		".",
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return canonicalPinsEmpty, err
	}
	directory := os.NewFile(uintptr(directoryFD), handle.pinPath)
	entries, readErr := directory.ReadDir(257)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return canonicalPinsEmpty, readErr
	}
	if closeErr != nil {
		return canonicalPinsEmpty, closeErr
	}
	if len(entries) > 256 {
		return canonicalPinsEmpty, errors.New("BPF pin directory has more than 256 entries")
	}
	known := make(map[string]struct{}, len(pinnedMapDescriptors()))
	for _, descriptor := range pinnedMapDescriptors() {
		known[descriptor.name] = struct{}{}
	}
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if _, duplicate := seen[name]; duplicate {
			return canonicalPinsEmpty, fmt.Errorf("BPF pin directory repeats entry %q", name)
		}
		seen[name] = struct{}{}
		if _, ok := known[name]; !ok {
			return canonicalPinsEmpty, fmt.Errorf(
				"unknown BPF pin entry %q is not covered by an active owner transaction",
				name,
			)
		}
	}
	if len(seen) == 0 {
		return canonicalPinsEmpty, nil
	}
	_, ownerSeen := seen["owner_map"]
	want := len(pinnedMapDescriptors())
	if ownerSeen && len(seen) == want {
		return canonicalPinsOwned, nil
	}
	if !ownerSeen && len(seen) == want-1 {
		for _, descriptor := range pinnedMapDescriptors() {
			if descriptor.name == "owner_map" {
				continue
			}
			if _, ok := seen[descriptor.name]; !ok {
				return canonicalPinsEmpty, fmt.Errorf(
					"legacy BPF pins are incomplete: missing %s",
					descriptor.name,
				)
			}
		}
		return canonicalPinsLegacy, nil
	}
	return canonicalPinsEmpty, fmt.Errorf(
		"incomplete canonical BPF pin set: found %d entries, owner_map=%t, want either %d legacy or %d owned maps",
		len(seen), ownerSeen, want-1, want,
	)
}

func validateOwnerDirectoryEntries(
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
		allowed[stage.FileName+".handoff"] = struct{}{}
		allowed[stage.FileName+".handoff.retired"] = struct{}{}
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

func newPinOwnerToken(random io.Reader) ([32]byte, error) {
	var token [32]byte
	if random == nil {
		return token, errors.New("pin owner random source is unavailable")
	}
	if _, err := io.ReadFull(random, token[:]); err != nil {
		return token, fmt.Errorf("generate pin owner token: %w", err)
	}
	if subtle.ConstantTimeCompare(token[:], make([]byte, len(token))) == 1 {
		return token, errors.New("pin owner random source returned an all-zero token")
	}
	return token, nil
}

func pinProgramByID(id uint32, path string) (returnErr error) {
	if id == 0 {
		return errors.New("cannot pin zero TC program ID")
	}
	program, err := ebpf.NewProgramFromID(ebpf.ProgramID(id))
	if err != nil {
		return err
	}
	defer func() {
		returnErr = errors.Join(returnErr, program.Close())
	}()
	if err := program.Pin(path); err != nil {
		return err
	}
	return nil
}

func loadPinnedProgramObservation(path string) (*pinnedProgramObservation, error) {
	program, err := ebpf.LoadPinnedProgram(path, &ebpf.LoadPinOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	info, err := program.Info()
	if err != nil {
		return nil, errors.Join(err, program.Close())
	}
	id, ok := info.ID()
	if !ok || id == 0 {
		return nil, errors.Join(
			errors.New("kernel did not report a pinned program ID"),
			program.Close(),
		)
	}
	return &pinnedProgramObservation{
		fd:    program.FD(),
		id:    uint32(id),
		pin:   program.Pin,
		close: program.Close,
	}, nil
}

func (observation *pinnedProgramObservation) Close() error {
	if observation == nil || observation.close == nil {
		return nil
	}
	closeProgram := observation.close
	observation.close = nil
	return closeProgram()
}

func pinOwnerSentinelFor(
	resource pinResourceIdentity,
	token [32]byte,
) (pinOwnerSentinel, error) {
	digest, err := hex.DecodeString(resource.key)
	if err != nil || len(digest) != 32 {
		return pinOwnerSentinel{}, fmt.Errorf("decode BPF pin resource key %q", resource.key)
	}
	sentinel := pinOwnerSentinel{
		Version: pinOwnerSentinelVersion,
		Token:   token,
	}
	copy(sentinel.ResourceDigest[:], digest)
	return sentinel, nil
}

func tokenFromOwnerRecord(record *pinOwnerRecord) ([32]byte, error) {
	var token [32]byte
	if record == nil {
		return token, errors.New("pin owner record is nil")
	}
	decoded, err := hex.DecodeString(record.Token)
	if err != nil || len(decoded) != len(token) {
		return token, fmt.Errorf("pin owner token %q is not 32-byte lowercase hexadecimal", record.Token)
	}
	if record.Token != strings.ToLower(record.Token) {
		return token, errors.New("pin owner token must use lowercase hexadecimal")
	}
	copy(token[:], decoded)
	if subtle.ConstantTimeCompare(token[:], make([]byte, len(token))) == 1 {
		return token, errors.New("pin owner token is all zero")
	}
	return token, nil
}

func newActivePinOwnerRecord(
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
		Version:          pinOwnerRecordVersion,
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
	if err := validatePinOwnerRecord(record, parent.resource, parent.mountID); err != nil {
		return nil, err
	}
	return record, nil
}

func newApplyingPinOwnerRecord(
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
		Version:          pinOwnerRecordVersion,
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
	record.ProgramStages = buildOwnerProgramStages(
		record.ResourceKey,
		token,
		record.ActiveFilters,
		record.DesiredFilters,
	)
	normalizePinOwnerRecord(record)
	if err := validatePinOwnerRecord(record, parent.resource, parent.mountID); err != nil {
		return nil, err
	}
	return record, nil
}

func advancePinOwnerRecord(
	current *pinOwnerRecord,
	now time.Time,
	phase string,
	step string,
) *pinOwnerRecord {
	next := clonePinOwnerRecord(current)
	next.Sequence++
	next.UpdatedAt = now.UTC().Format(time.RFC3339Nano)
	next.Phase = phase
	next.Step = step
	normalizePinOwnerRecord(next)
	return next
}

func completeApplyingPinOwnerRecord(
	current *pinOwnerRecord,
	now time.Time,
) *pinOwnerRecord {
	next := advancePinOwnerRecord(
		current,
		now,
		pinOwnerPhaseActive,
		pinOwnerStepReady,
	)
	next.ActiveGeneration = current.NextGeneration
	next.NextGeneration = 0
	next.ActiveFilters = slices.Clone(current.DesiredFilters)
	next.DesiredFilters = []tcFilterBinding{}
	next.ProgramStages = []pinOwnerProgramStage{}
	next.MapStages = []pinOwnerMapStage{}
	normalizePinOwnerRecord(next)
	return next
}

func abortApplyingPinOwnerRecord(
	current *pinOwnerRecord,
	now time.Time,
) (*pinOwnerRecord, error) {
	if current == nil ||
		current.Phase != pinOwnerPhaseApplying ||
		current.ActiveGeneration == 0 {
		return nil, errors.New("only an applying update with an active generation can be aborted")
	}
	next := advancePinOwnerRecord(
		current,
		now,
		pinOwnerPhaseActive,
		pinOwnerStepReady,
	)
	next.NextGeneration = 0
	next.DesiredFilters = []tcFilterBinding{}
	next.ProgramStages = []pinOwnerProgramStage{}
	next.MapStages = []pinOwnerMapStage{}
	normalizePinOwnerRecord(next)
	if err := validatePinOwnerRecord(next, pinResourceIdentity{
		key:          next.ResourceKey,
		parentDevice: next.ParentDevice,
		parentInode:  next.ParentInode,
		base:         next.PinBaseName,
	}, 0); err != nil {
		return nil, err
	}
	return next, nil
}

func newRollbackCleanupPinOwnerRecord(
	current *pinOwnerRecord,
	now time.Time,
) (*pinOwnerRecord, error) {
	if current == nil ||
		current.Phase != pinOwnerPhaseApplying ||
		(current.Step != pinOwnerStepStaging &&
			current.Step != pinOwnerStepMutating) {
		return nil, errors.New("rollback cleanup requires a pre-commit applying owner record")
	}
	next := advancePinOwnerRecord(
		current,
		now,
		pinOwnerPhaseApplying,
		pinOwnerStepRollbackCleanup,
	)
	if err := validatePinOwnerRecord(next, pinResourceIdentity{
		key:          next.ResourceKey,
		parentDevice: next.ParentDevice,
		parentInode:  next.ParentInode,
		base:         next.PinBaseName,
	}, 0); err != nil {
		return nil, err
	}
	return next, nil
}

func newDetachingPinOwnerRecord(
	current *pinOwnerRecord,
	now time.Time,
) (*pinOwnerRecord, error) {
	if current == nil ||
		current.Phase != pinOwnerPhaseActive ||
		current.Step != pinOwnerStepReady {
		return nil, errors.New("detach requires an active owner record")
	}
	token, err := tokenFromOwnerRecord(current)
	if err != nil {
		return nil, err
	}
	next := advancePinOwnerRecord(
		current,
		now,
		pinOwnerPhaseDetaching,
		pinOwnerStepStaging,
	)
	next.DesiredFilters = []tcFilterBinding{}
	next.ProgramStages = buildOwnerProgramStages(
		next.ResourceKey,
		token,
		next.ActiveFilters,
		nil,
	)
	next.MapStages = buildOwnerMapStages(next.ResourceKey, token, next.Maps)
	normalizePinOwnerRecord(next)
	if err := validatePinOwnerRecord(next, pinResourceIdentity{
		key:          next.ResourceKey,
		parentDevice: next.ParentDevice,
		parentInode:  next.ParentInode,
		base:         next.PinBaseName,
	}, 0); err != nil {
		return nil, err
	}
	return next, nil
}

func newInitialAbortDetachingPinOwnerRecord(
	current *pinOwnerRecord,
	now time.Time,
) (*pinOwnerRecord, error) {
	if current == nil ||
		current.Phase != pinOwnerPhaseApplying ||
		(current.Step != pinOwnerStepStaging &&
			current.Step != pinOwnerStepMutating &&
			current.Step != pinOwnerStepRollbackCleanup) ||
		current.ActiveGeneration != 0 {
		return nil, errors.New("initial abort requires a fresh pre-commit applying owner record")
	}
	token, err := tokenFromOwnerRecord(current)
	if err != nil {
		return nil, err
	}
	next := advancePinOwnerRecord(
		current,
		now,
		pinOwnerPhaseDetaching,
		pinOwnerStepStaging,
	)
	next.NextGeneration = 0
	next.ActiveFilters = []tcFilterBinding{}
	next.DesiredFilters = []tcFilterBinding{}
	next.ProgramStages = []pinOwnerProgramStage{}
	next.MapStages = buildOwnerMapStages(next.ResourceKey, token, next.Maps)
	normalizePinOwnerRecord(next)
	if err := validatePinOwnerRecord(next, pinResourceIdentity{
		key:          next.ResourceKey,
		parentDevice: next.ParentDevice,
		parentInode:  next.ParentInode,
		base:         next.PinBaseName,
	}, 0); err != nil {
		return nil, err
	}
	return next, nil
}

func abortDetachingPinOwnerRecord(
	current *pinOwnerRecord,
	now time.Time,
) (*pinOwnerRecord, error) {
	if current == nil ||
		current.Phase != pinOwnerPhaseDetaching ||
		current.ActiveGeneration == 0 {
		return nil, errors.New("only an owned detach can be rolled back to active")
	}
	next := advancePinOwnerRecord(
		current,
		now,
		pinOwnerPhaseActive,
		pinOwnerStepReady,
	)
	next.NextGeneration = 0
	next.DesiredFilters = []tcFilterBinding{}
	next.ProgramStages = []pinOwnerProgramStage{}
	next.MapStages = []pinOwnerMapStage{}
	normalizePinOwnerRecord(next)
	if err := validatePinOwnerRecord(next, pinResourceIdentity{
		key:          next.ResourceKey,
		parentDevice: next.ParentDevice,
		parentInode:  next.ParentInode,
		base:         next.PinBaseName,
	}, 0); err != nil {
		return nil, err
	}
	return next, nil
}

func clonePinOwnerRecord(record *pinOwnerRecord) *pinOwnerRecord {
	if record == nil {
		return nil
	}
	cloned := *record
	cloned.BPFFSMountIDs = slices.Clone(record.BPFFSMountIDs)
	cloned.Maps = slices.Clone(record.Maps)
	cloned.ActiveFilters = slices.Clone(record.ActiveFilters)
	cloned.DesiredFilters = slices.Clone(record.DesiredFilters)
	cloned.ProgramStages = slices.Clone(record.ProgramStages)
	cloned.MapStages = slices.Clone(record.MapStages)
	return &cloned
}

func normalizePinOwnerRecord(record *pinOwnerRecord) {
	if record == nil {
		return
	}
	sort.Slice(record.BPFFSMountIDs, func(i, j int) bool {
		return record.BPFFSMountIDs[i] < record.BPFFSMountIDs[j]
	})
	sort.Slice(record.Maps, func(i, j int) bool {
		return record.Maps[i].Name < record.Maps[j].Name
	})
	sortTCFilterBindings(record.ActiveFilters)
	sortTCFilterBindings(record.DesiredFilters)
	sort.Slice(record.ProgramStages, func(i, j int) bool {
		left := record.ProgramStages[i]
		right := record.ProgramStages[j]
		if left.ProgramID != right.ProgramID {
			return left.ProgramID < right.ProgramID
		}
		if left.Kind != right.Kind {
			return left.Kind < right.Kind
		}
		return left.FileName < right.FileName
	})
	sort.Slice(record.MapStages, func(i, j int) bool {
		return record.MapStages[i].Name < record.MapStages[j].Name
	})
	if record.ActiveFilters == nil {
		record.ActiveFilters = []tcFilterBinding{}
	}
	if record.DesiredFilters == nil {
		record.DesiredFilters = []tcFilterBinding{}
	}
	if record.ProgramStages == nil {
		record.ProgramStages = []pinOwnerProgramStage{}
	}
	if record.MapStages == nil {
		record.MapStages = []pinOwnerMapStage{}
	}
	if record.Maps == nil {
		record.Maps = []pinOwnerMapIdentity{}
	}
	if record.BPFFSMountIDs == nil {
		record.BPFFSMountIDs = []uint64{}
	}
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

func validatePinOwnerRecord(
	record *pinOwnerRecord,
	resource pinResourceIdentity,
	currentMountID uint64,
) error {
	if record == nil {
		return errors.New("pin owner record is nil")
	}
	if record.Version != pinOwnerRecordVersion {
		return fmt.Errorf("pin owner record version = %d, want %d", record.Version, pinOwnerRecordVersion)
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
	if err := validateOwnerFilters(record.ActiveFilters, "active"); err != nil {
		return err
	}
	if err := validateOwnerFilters(record.DesiredFilters, "desired"); err != nil {
		return err
	}
	if err := validateOwnerStages(record); err != nil {
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
			record.Step != pinOwnerStepRollbackCleanup &&
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

func validateOwnerMaps(maps []pinOwnerMapIdentity) error {
	descriptors := pinnedMapDescriptors()
	if len(maps) != len(descriptors) {
		return fmt.Errorf("pin owner record maps = %d, want %d", len(maps), len(descriptors))
	}
	wantNames := make([]string, 0, len(descriptors))
	for _, descriptor := range descriptors {
		wantNames = append(wantNames, descriptor.name)
	}
	sort.Strings(wantNames)
	seenIDs := make(map[uint32]string, len(maps))
	for index, ownerMap := range maps {
		if ownerMap.Name != wantNames[index] {
			return fmt.Errorf(
				"pin owner map[%d] name = %q, want %q",
				index, ownerMap.Name, wantNames[index],
			)
		}
		if ownerMap.ID == 0 {
			return fmt.Errorf("pin owner map %s has zero ID", ownerMap.Name)
		}
		if previous, duplicate := seenIDs[ownerMap.ID]; duplicate {
			return fmt.Errorf(
				"pin owner maps %s and %s share ID %d",
				previous, ownerMap.Name, ownerMap.ID,
			)
		}
		seenIDs[ownerMap.ID] = ownerMap.Name
	}
	return nil
}

func validateOwnerFilters(filters []tcFilterBinding, label string) error {
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

func validateOwnerStages(record *pinOwnerRecord) error {
	token, err := tokenFromOwnerRecord(record)
	if err != nil {
		return err
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

func pinOwnerProgramStageName(
	resourceKey string,
	token [32]byte,
	kind string,
	programID uint32,
) string {
	return fmt.Sprintf(
		"txn-%s-%x-program-%s-%010d",
		resourceKey,
		token,
		kind,
		programID,
	)
}

func buildOwnerProgramStages(
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

func stageOwnerPrograms(
	handle *pinPathHandle,
	record *pinOwnerRecord,
) error {
	if handle == nil {
		return errors.New("pin handle is nil")
	}
	if record.Phase != pinOwnerPhaseApplying && record.Phase != pinOwnerPhaseDetaching {
		return fmt.Errorf("cannot stage programs for owner phase %q", record.Phase)
	}
	if len(record.ProgramStages) == 0 {
		return nil
	}
	if handle.runtime.pinProgram == nil || handle.runtime.loadPinnedProgram == nil {
		return errors.New("pinned-program runtime is unavailable")
	}
	for _, stage := range record.ProgramStages {
		if err := handle.recheckTargetEntry(); err != nil {
			return err
		}
		var stat unix.Stat_t
		err := unix.Fstatat(
			handle.targetFD,
			stage.FileName,
			&stat,
			unix.AT_SYMLINK_NOFOLLOW,
		)
		if err == nil {
			if err := validateOwnerProgramStage(handle, record, stage); err != nil {
				return err
			}
			continue
		}
		if !errors.Is(err, unix.ENOENT) {
			return err
		}
		if err := handle.runtime.pinProgram(
			stage.ProgramID,
			filepath.Join(handle.procPath(), stage.FileName),
		); err != nil {
			return fmt.Errorf(
				"stage program ID %d at %s/%s: %w",
				stage.ProgramID, handle.pinPath, stage.FileName, err,
			)
		}
		if err := validateOwnerProgramStage(handle, record, stage); err != nil {
			return err
		}
	}
	return nil
}

func validateOwnerProgramStage(
	handle *pinPathHandle,
	record *pinOwnerRecord,
	stage pinOwnerProgramStage,
) error {
	token, err := tokenFromOwnerRecord(record)
	if err != nil {
		return err
	}
	if stage.FileName != pinOwnerProgramStageName(
		record.ResourceKey,
		token,
		stage.Kind,
		stage.ProgramID,
	) {
		return errors.New("program stage filename is not derived from the owner transaction")
	}
	return validatePinnedProgramAt(
		handle,
		stage.FileName,
		stage.ProgramID,
	)
}

// validateOwnerProgramRecoveryStage returns an exact durable program pin for
// restart recovery. The primary stage is preferred, while the independently
// pinned handoff copy keeps recovery complete if the primary name is missing
// or was damaged after the pre-mutation proof.
func validateOwnerProgramRecoveryStage(
	handle *pinPathHandle,
	record *pinOwnerRecord,
	stage pinOwnerProgramStage,
) (string, error) {
	primaryErr := validateOwnerProgramStage(handle, record, stage)
	if primaryErr == nil {
		return stage.FileName, nil
	}
	backupName := stage.FileName + ".handoff"
	if backupErr := validatePinnedProgramAt(
		handle,
		backupName,
		stage.ProgramID,
	); backupErr == nil {
		return backupName, nil
	} else {
		return "", errors.Join(
			fmt.Errorf("primary program stage %s: %w", stage.FileName, primaryErr),
			fmt.Errorf("handoff program stage %s: %w", backupName, backupErr),
		)
	}
}

func validatePinnedProgramAt(
	handle *pinPathHandle,
	fileName string,
	programID uint32,
) error {
	if handle == nil || filepath.Base(fileName) != fileName {
		return fmt.Errorf("unsafe pinned-program filename %q", fileName)
	}
	var stat unix.Stat_t
	if err := unix.Fstatat(
		handle.targetFD,
		fileName,
		&stat,
		unix.AT_SYMLINK_NOFOLLOW,
	); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Mode&0o7777 != 0o600 ||
		stat.Uid != handle.runtime.expectedUID ||
		stat.Nlink != 1 {
		return fmt.Errorf(
			"unsafe program stage %s/%s: mode=%#o uid=%d links=%d",
			handle.pinPath, fileName, stat.Mode, stat.Uid, stat.Nlink,
		)
	}
	mountID, err := handle.runtime.mountIDAt(
		handle.targetFD,
		fileName,
		unix.AT_NO_AUTOMOUNT|unix.AT_SYMLINK_NOFOLLOW,
	)
	if err != nil {
		return err
	}
	if mountID != handle.mountID {
		return fmt.Errorf("program stage %s is on another mount", fileName)
	}
	observation, err := handle.runtime.loadPinnedProgram(
		filepath.Join(handle.procPath(), fileName),
	)
	if err != nil {
		return err
	}
	defer observation.Close()
	if observation.id != programID {
		return fmt.Errorf(
			"program stage %s has ID %d, owner journal requires %d",
			fileName, observation.id, programID,
		)
	}
	var after unix.Stat_t
	if err := unix.Fstatat(
		handle.targetFD,
		fileName,
		&after,
		unix.AT_SYMLINK_NOFOLLOW,
	); err != nil {
		return err
	}
	if !samePinPathInode(
		pinPathInodeFromStat(&stat),
		pinPathInodeFromStat(&after),
	) {
		return fmt.Errorf("program stage %s changed while validating", fileName)
	}
	return nil
}

func removeOwnerProgramStages(
	handle *pinPathHandle,
	record *pinOwnerRecord,
) error {
	for _, stage := range record.ProgramStages {
		retiredName := stage.FileName + ".retired"
		var retiredStat unix.Stat_t
		retiredErr := unix.Fstatat(
			handle.targetFD,
			retiredName,
			&retiredStat,
			unix.AT_SYMLINK_NOFOLLOW,
		)
		if retiredErr == nil {
			var stageStat unix.Stat_t
			if err := unix.Fstatat(
				handle.targetFD,
				stage.FileName,
				&stageStat,
				unix.AT_SYMLINK_NOFOLLOW,
			); err == nil {
				return fmt.Errorf(
					"both active and retired program stage %s exist",
					stage.FileName,
				)
			} else if !errors.Is(err, unix.ENOENT) {
				return err
			}
			if err := validatePinnedProgramAt(
				handle,
				retiredName,
				stage.ProgramID,
			); err != nil {
				return err
			}
			if handle.runtime.beforePinUnlink != nil {
				if err := handle.runtime.beforePinUnlink(retiredName); err != nil {
					return fmt.Errorf("program stage unlink hook %s: %w", retiredName, err)
				}
			}
			if err := validatePinnedProgramAt(
				handle,
				retiredName,
				stage.ProgramID,
			); err != nil {
				return fmt.Errorf(
					"program stage %s changed at unlink hook: %w",
					retiredName, err,
				)
			}
			if err := unix.Unlinkat(handle.targetFD, retiredName, 0); err != nil {
				return fmt.Errorf("remove retired program stage %s: %w", retiredName, err)
			}
			continue
		}
		if !errors.Is(retiredErr, unix.ENOENT) {
			return retiredErr
		}
		var stat unix.Stat_t
		err := unix.Fstatat(
			handle.targetFD,
			stage.FileName,
			&stat,
			unix.AT_SYMLINK_NOFOLLOW,
		)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return err
		}
		if err := validateOwnerProgramStage(handle, record, stage); err != nil {
			return err
		}
		if handle.runtime.beforePinQuarantine != nil {
			if err := handle.runtime.beforePinQuarantine(stage.FileName); err != nil {
				return fmt.Errorf("program stage quarantine hook %s: %w", stage.FileName, err)
			}
		}
		if err := handle.recheckTargetEntry(); err != nil {
			return err
		}
		var recheck unix.Stat_t
		if err := unix.Fstatat(
			handle.targetFD,
			stage.FileName,
			&recheck,
			unix.AT_SYMLINK_NOFOLLOW,
		); err != nil {
			return err
		}
		if !samePinPathInode(
			pinPathInodeFromStat(&stat),
			pinPathInodeFromStat(&recheck),
		) {
			return fmt.Errorf("program stage %s changed before quarantine", stage.FileName)
		}
		if err := unix.Renameat2(
			handle.targetFD,
			stage.FileName,
			handle.targetFD,
			retiredName,
			unix.RENAME_NOREPLACE,
		); err != nil {
			return fmt.Errorf("quarantine program stage %s: %w", stage.FileName, err)
		}
		if err := validatePinnedProgramAt(
			handle,
			retiredName,
			stage.ProgramID,
		); err != nil {
			return fmt.Errorf("validate retired program stage %s: %w", retiredName, err)
		}
		if handle.runtime.beforePinUnlink != nil {
			if err := handle.runtime.beforePinUnlink(retiredName); err != nil {
				return fmt.Errorf("program stage unlink hook %s: %w", retiredName, err)
			}
		}
		if err := validatePinnedProgramAt(
			handle,
			retiredName,
			stage.ProgramID,
		); err != nil {
			return fmt.Errorf(
				"program stage %s changed at unlink hook: %w",
				retiredName, err,
			)
		}
		if err := unix.Unlinkat(handle.targetFD, retiredName, 0); err != nil {
			return fmt.Errorf("remove retired program stage %s: %w", retiredName, err)
		}
	}
	return removeOwnerProgramHandoffStages(handle, record)
}

func removeOwnerProgramHandoffStages(
	handle *pinPathHandle,
	record *pinOwnerRecord,
) error {
	for _, stage := range record.ProgramStages {
		name := stage.FileName + ".handoff"
		retiredName := name + ".retired"
		var retiredStat unix.Stat_t
		retiredErr := unix.Fstatat(
			handle.targetFD,
			retiredName,
			&retiredStat,
			unix.AT_SYMLINK_NOFOLLOW,
		)
		if retiredErr == nil {
			var activeStat unix.Stat_t
			if err := unix.Fstatat(
				handle.targetFD,
				name,
				&activeStat,
				unix.AT_SYMLINK_NOFOLLOW,
			); err == nil {
				return fmt.Errorf("both active and retired handoff stage %s exist", name)
			} else if !errors.Is(err, unix.ENOENT) {
				return err
			}
			if err := validatePinnedProgramAt(
				handle,
				retiredName,
				stage.ProgramID,
			); err != nil {
				return err
			}
			if handle.runtime.beforePinUnlink != nil {
				if err := handle.runtime.beforePinUnlink(retiredName); err != nil {
					return fmt.Errorf("handoff stage unlink hook %s: %w", retiredName, err)
				}
			}
			if err := validatePinnedProgramAt(
				handle,
				retiredName,
				stage.ProgramID,
			); err != nil {
				return fmt.Errorf("handoff stage %s changed at unlink hook: %w", retiredName, err)
			}
			if err := unix.Unlinkat(handle.targetFD, retiredName, 0); err != nil {
				return fmt.Errorf("remove retired handoff stage %s: %w", retiredName, err)
			}
			continue
		}
		if !errors.Is(retiredErr, unix.ENOENT) {
			return retiredErr
		}
		var stat unix.Stat_t
		if err := unix.Fstatat(
			handle.targetFD,
			name,
			&stat,
			unix.AT_SYMLINK_NOFOLLOW,
		); errors.Is(err, unix.ENOENT) {
			continue
		} else if err != nil {
			return err
		}
		if err := validatePinnedProgramAt(handle, name, stage.ProgramID); err != nil {
			return err
		}
		if handle.runtime.beforePinQuarantine != nil {
			if err := handle.runtime.beforePinQuarantine(name); err != nil {
				return fmt.Errorf("handoff stage quarantine hook %s: %w", name, err)
			}
		}
		if err := handle.recheckTargetEntry(); err != nil {
			return err
		}
		var recheck unix.Stat_t
		if err := unix.Fstatat(
			handle.targetFD,
			name,
			&recheck,
			unix.AT_SYMLINK_NOFOLLOW,
		); err != nil {
			return err
		}
		if !samePinPathInode(
			pinPathInodeFromStat(&stat),
			pinPathInodeFromStat(&recheck),
		) {
			return fmt.Errorf("handoff stage %s changed before quarantine", name)
		}
		if err := unix.Renameat2(
			handle.targetFD,
			name,
			handle.targetFD,
			retiredName,
			unix.RENAME_NOREPLACE,
		); err != nil {
			return fmt.Errorf("quarantine handoff stage %s: %w", name, err)
		}
		if err := validatePinnedProgramAt(
			handle,
			retiredName,
			stage.ProgramID,
		); err != nil {
			return fmt.Errorf("validate retired handoff stage %s: %w", retiredName, err)
		}
		if handle.runtime.beforePinUnlink != nil {
			if err := handle.runtime.beforePinUnlink(retiredName); err != nil {
				return fmt.Errorf("handoff stage unlink hook %s: %w", retiredName, err)
			}
		}
		if err := validatePinnedProgramAt(
			handle,
			retiredName,
			stage.ProgramID,
		); err != nil {
			return fmt.Errorf("handoff stage %s changed at unlink hook: %w", retiredName, err)
		}
		if err := unix.Unlinkat(handle.targetFD, retiredName, 0); err != nil {
			return fmt.Errorf("remove retired handoff stage %s: %w", retiredName, err)
		}
	}
	return nil
}

func pinOwnerMapStageName(
	resourceKey string,
	token [32]byte,
	name string,
) string {
	return fmt.Sprintf("txn-%s-%x-map-%s", resourceKey, token, name)
}

func buildOwnerMapStages(
	resourceKey string,
	token [32]byte,
	maps []pinOwnerMapIdentity,
) []pinOwnerMapStage {
	stages := make([]pinOwnerMapStage, 0, len(maps))
	for _, ownerMap := range maps {
		stages = append(stages, pinOwnerMapStage{
			Name:     ownerMap.Name,
			FileName: pinOwnerMapStageName(resourceKey, token, ownerMap.Name),
			MapID:    ownerMap.ID,
		})
	}
	sort.Slice(stages, func(i, j int) bool {
		return stages[i].Name < stages[j].Name
	})
	return stages
}

func ownerMapsFromPins(pins []pinnedMapPin) []pinOwnerMapIdentity {
	maps := make([]pinOwnerMapIdentity, 0, len(pins))
	for _, pin := range pins {
		if pin.observation == nil {
			continue
		}
		maps = append(maps, pinOwnerMapIdentity{
			Name: pin.descriptor.name,
			ID:   pin.observation.id,
		})
	}
	sort.Slice(maps, func(i, j int) bool {
		return maps[i].Name < maps[j].Name
	})
	return maps
}

func writeCollectionOwnerSentinel(
	collection *ebpf.Collection,
	sentinel pinOwnerSentinel,
) error {
	if collection == nil {
		return errors.New("BPF collection is nil")
	}
	ownerMap := collection.Maps["owner_map"]
	if ownerMap == nil {
		return errors.New(`BPF collection missing map "owner_map"`)
	}
	if err := ownerMap.Update(uint32(0), sentinel, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("write owner_map sentinel: %w", err)
	}
	return nil
}

func ownerMapPin(pins []pinnedMapPin) (*pinnedMapPin, error) {
	for index := range pins {
		if pins[index].descriptor.name == "owner_map" {
			return &pins[index], nil
		}
	}
	return nil, errors.New("canonical pinned-map set is missing owner_map")
}

func validateOwnerMapsAgainstPins(
	record *pinOwnerRecord,
	pins []pinnedMapPin,
) error {
	observed := ownerMapsFromPins(pins)
	if len(observed) != len(record.Maps) {
		return fmt.Errorf(
			"owner record lists %d maps but pin directory has %d",
			len(record.Maps), len(observed),
		)
	}
	for index := range observed {
		if observed[index] != record.Maps[index] {
			return fmt.Errorf(
				"owner map identity mismatch at %s: record ID=%d observed name=%s ID=%d",
				record.Maps[index].Name,
				record.Maps[index].ID,
				observed[index].Name,
				observed[index].ID,
			)
		}
	}
	return nil
}

func validateOwnerSentinel(
	owner pinOwnerSentinel,
	seen bool,
	record *pinOwnerRecord,
	resource pinResourceIdentity,
) error {
	if !seen {
		return errors.New("owner_map sentinel is unavailable")
	}
	token, err := tokenFromOwnerRecord(record)
	if err != nil {
		return err
	}
	want, err := pinOwnerSentinelFor(resource, token)
	if err != nil {
		return err
	}
	if owner != want {
		return errors.New("owner_map sentinel does not match the persistent owner record")
	}
	return nil
}

func openPinOwnerStore(
	runtime pinPathRuntime,
	resource pinResourceIdentity,
	createRoot bool,
) (*pinOwnerStore, error) {
	return openPinOwnerStoreWithPolicy(runtime, resource, createRoot, true)
}

func openPinOwnerStoreWithPolicy(
	runtime pinPathRuntime,
	resource pinResourceIdentity,
	createRoot bool,
	recoverDescriptors bool,
) (*pinOwnerStore, error) {
	fileName, err := pinidentity.OwnerFileName(
		resource.parentDevice,
		resource.parentInode,
		resource.base,
	)
	if err != nil {
		return nil, err
	}
	if fileName != resource.key+".owner.json" {
		return nil, errors.New("pin owner identity helper returned an inconsistent filename")
	}
	root, _, err := openAnchoredDirectoryPath(
		runtime.ownerRoot,
		createRoot,
		0o700,
		runtime.expectedUID,
		runtime.allowUnsafeAncestors,
	)
	if err != nil {
		return nil, fmt.Errorf("open pin owner root %s: %w", runtime.ownerRoot, err)
	}
	store := &pinOwnerStore{
		root:                root,
		resource:            resource,
		expectedUID:         runtime.expectedUID,
		fileName:            fileName,
		draftName:           resource.key + ".owner.draft",
		nextName:            resource.key + ".owner.next",
		retiredName:         resource.key + ".owner.retired",
		beforeOwnerExchange: runtime.beforeOwnerExchange,
		descriptorOps:       livePinOwnerDescriptorOps(),
		now:                 runtime.now,
	}
	if recoverDescriptors {
		if err := store.recoverDescriptorTransaction(); err != nil {
			_ = root.Close()
			return nil, err
		}
		if err := indexStoreFromOwner(store).recoverOwnerArchive(
			resource,
		); err != nil {
			_ = root.Close()
			return nil, err
		}
		if err := store.repairIndexForCurrentResource(); err != nil {
			_ = root.Close()
			return nil, err
		}
	}
	return store, nil
}

func (store *pinOwnerStore) Close() error {
	if store == nil || store.root == nil {
		return nil
	}
	err := store.root.Close()
	store.root = nil
	return err
}

func (store *pinOwnerStore) Load(currentMountID uint64) (*pinOwnerRecord, error) {
	if store == nil || store.root == nil {
		return nil, errors.New("pin owner store is unavailable")
	}
	file, identity, err := openExistingAnchoredRegularFile(
		store.root,
		store.fileName,
		0o600,
		store.expectedUID,
	)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	record, err := readPinOwnerRecord(file)
	if err != nil {
		return nil, err
	}
	if err := validatePinOwnerRecord(record, store.resource, currentMountID); err != nil {
		return nil, err
	}
	if _, err := validateAnchoredRegularFile(
		store.root,
		store.fileName,
		int(file.Fd()),
		0o600,
		store.expectedUID,
		&identity,
	); err != nil {
		return nil, fmt.Errorf("recheck pin owner record: %w", err)
	}
	return record, nil
}

func (store *pinOwnerStore) LoadOptional(
	currentMountID uint64,
) (*pinOwnerRecord, bool, error) {
	record, err := store.Load(currentMountID)
	if errors.Is(err, unix.ENOENT) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return record, true, nil
}

func readPinOwnerRecord(file *os.File) (*pinOwnerRecord, error) {
	if file == nil {
		return nil, errors.New("pin owner record file is nil")
	}
	data := make([]byte, pinOwnerRecordMaxBytes+1)
	n, err := file.ReadAt(data, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("read pin owner record: %w", err)
	}
	if n == 0 || n > pinOwnerRecordMaxBytes {
		return nil, fmt.Errorf("pin owner record size = %d, want 1..%d", n, pinOwnerRecordMaxBytes)
	}
	data = data[:n]
	if data[len(data)-1] != '\n' || bytes.Count(data, []byte{'\n'}) != 1 {
		return nil, errors.New("pin owner record must be exactly one JSON line terminated by LF")
	}
	var record pinOwnerRecord
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return nil, fmt.Errorf("decode pin owner record: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("pin owner record contains trailing JSON")
	}
	return &record, nil
}

func marshalPinOwnerRecord(record *pinOwnerRecord) ([]byte, error) {
	data, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	if len(data)+1 > pinOwnerRecordMaxBytes {
		return nil, fmt.Errorf("pin owner record is too large: %d bytes", len(data)+1)
	}
	return append(data, '\n'), nil
}

// stageSyncedDescriptor writes through a name that recovery never adopts.
// Only after the complete file has passed file fsync and identity validation
// is it atomically published under the recoverable pending name.
func stageSyncedDescriptor(
	root *anchoredDirectoryPath,
	draftName string,
	nextName string,
	data []byte,
	expectedUID uint32,
	ops pinOwnerDescriptorOps,
) (*os.File, pinPathInodeIdentity, error) {
	file, identity, err := ops.create(root, draftName, 0o600, expectedUID)
	if err != nil {
		return nil, pinPathInodeIdentity{}, err
	}
	fail := func(err error) (*os.File, pinPathInodeIdentity, error) {
		return file, identity, err
	}
	if err := writeAndSyncAnchoredFileWithOps(
		root,
		draftName,
		file,
		identity,
		data,
		expectedUID,
		ops,
	); err != nil {
		return fail(err)
	}
	if _, err := ops.validate(
		root,
		draftName,
		int(file.Fd()),
		0o600,
		expectedUID,
		&identity,
	); err != nil {
		return fail(err)
	}
	if err := ops.rename(root, draftName, nextName, unix.RENAME_NOREPLACE); err != nil {
		return fail(err)
	}
	if err := ops.syncDir(root); err != nil {
		return fail(err)
	}
	if _, err := ops.validate(
		root,
		nextName,
		int(file.Fd()),
		0o600,
		expectedUID,
		&identity,
	); err != nil {
		return fail(err)
	}
	return file, identity, nil
}

func (store *pinOwnerStore) Persist(
	record *pinOwnerRecord,
	expected *pinOwnerRecord,
	currentMountID uint64,
) error {
	if store == nil || store.root == nil {
		return errors.New("pin owner store is unavailable")
	}
	normalizePinOwnerRecord(record)
	if err := validatePinOwnerRecord(record, store.resource, currentMountID); err != nil {
		return err
	}
	if expected == nil {
		if record.Sequence != 1 {
			return fmt.Errorf("initial pin owner sequence = %d, want 1", record.Sequence)
		}
	} else {
		if record.Sequence != expected.Sequence+1 {
			return fmt.Errorf(
				"next pin owner sequence = %d, want %d",
				record.Sequence, expected.Sequence+1,
			)
		}
		if record.Token != expected.Token ||
			record.CreatedAt != expected.CreatedAt ||
			record.BootID != expected.BootID ||
			record.RetiredFromResourceKey != expected.RetiredFromResourceKey ||
			record.RetiredFromBootID != expected.RetiredFromBootID {
			return errors.New("pin owner immutable fields changed during update")
		}
	}
	data, err := marshalPinOwnerRecord(record)
	if err != nil {
		return err
	}
	if err := store.recoverDescriptorTransaction(); err != nil {
		return err
	}
	nextFile, nextIdentity, err := stageSyncedDescriptor(
		store.root,
		store.draftName,
		store.nextName,
		data,
		store.expectedUID,
		store.descriptorOps,
	)
	if err != nil {
		if nextFile != nil {
			_ = nextFile.Close()
		}
		return fmt.Errorf("stage next pin owner record: %w", err)
	}
	defer nextFile.Close()

	targetFile, targetIdentity, targetErr := openExistingAnchoredRegularFile(
		store.root,
		store.fileName,
		0o600,
		store.expectedUID,
	)
	if expected == nil {
		if targetErr == nil {
			_ = targetFile.Close()
			return errors.New("pin owner record unexpectedly already exists")
		}
		if !errors.Is(targetErr, unix.ENOENT) {
			return targetErr
		}
		if err := store.root.Recheck(); err != nil {
			return err
		}
		if _, err := validateAnchoredRegularFile(
			store.root,
			store.nextName,
			int(nextFile.Fd()),
			0o600,
			store.expectedUID,
			&nextIdentity,
		); err != nil {
			return err
		}
		if store.beforeOwnerExchange != nil {
			store.beforeOwnerExchange()
		}
		if err := store.root.Recheck(); err != nil {
			return fmt.Errorf("owner root changed at initial publish hook: %w", err)
		}
		if _, err := validateAnchoredRegularFile(
			store.root,
			store.nextName,
			int(nextFile.Fd()),
			0o600,
			store.expectedUID,
			&nextIdentity,
		); err != nil {
			return fmt.Errorf("next owner record changed at initial publish hook: %w", err)
		}
		if err := store.descriptorOps.rename(
			store.root,
			store.nextName,
			store.fileName,
			unix.RENAME_NOREPLACE,
		); err != nil {
			return fmt.Errorf("publish initial pin owner record: %w", err)
		}
		if err := store.descriptorOps.syncDir(store.root); err != nil {
			return fmt.Errorf("sync pin owner root after initial publish: %w", err)
		}
		_, err := validateAnchoredRegularFile(
			store.root,
			store.fileName,
			int(nextFile.Fd()),
			0o600,
			store.expectedUID,
			&nextIdentity,
		)
		if err != nil {
			return err
		}
		return store.syncIndexRecord(record, false)
	}
	if targetErr != nil {
		return targetErr
	}
	defer targetFile.Close()
	current, err := readPinOwnerRecord(targetFile)
	if err != nil {
		return err
	}
	if !sameExpectedOwnerRecord(current, expected) {
		return errors.New("pin owner record changed before descriptor exchange")
	}
	if _, err := validateAnchoredRegularFile(
		store.root,
		store.fileName,
		int(targetFile.Fd()),
		0o600,
		store.expectedUID,
		&targetIdentity,
	); err != nil {
		return err
	}
	if _, err := validateAnchoredRegularFile(
		store.root,
		store.nextName,
		int(nextFile.Fd()),
		0o600,
		store.expectedUID,
		&nextIdentity,
	); err != nil {
		return err
	}
	if store.beforeOwnerExchange != nil {
		store.beforeOwnerExchange()
	}
	if _, err := validateAnchoredRegularFile(
		store.root,
		store.fileName,
		int(targetFile.Fd()),
		0o600,
		store.expectedUID,
		&targetIdentity,
	); err != nil {
		return fmt.Errorf("owner record changed at exchange hook: %w", err)
	}
	if _, err := validateAnchoredRegularFile(
		store.root,
		store.nextName,
		int(nextFile.Fd()),
		0o600,
		store.expectedUID,
		&nextIdentity,
	); err != nil {
		return fmt.Errorf("next owner record changed at exchange hook: %w", err)
	}
	if err := store.descriptorOps.rename(
		store.root,
		store.nextName,
		store.fileName,
		unix.RENAME_EXCHANGE,
	); err != nil {
		return fmt.Errorf("exchange pin owner record: %w", err)
	}
	if err := store.descriptorOps.syncDir(store.root); err != nil {
		return fmt.Errorf("sync pin owner root after exchange: %w", err)
	}
	if _, err := validateAnchoredRegularFile(
		store.root,
		store.fileName,
		int(nextFile.Fd()),
		0o600,
		store.expectedUID,
		&nextIdentity,
	); err != nil {
		return fmt.Errorf("verify published pin owner record: %w", err)
	}
	if _, err := validateAnchoredRegularFile(
		store.root,
		store.nextName,
		int(targetFile.Fd()),
		0o600,
		store.expectedUID,
		&targetIdentity,
	); err != nil {
		return fmt.Errorf("verify quarantined old pin owner record: %w", err)
	}
	if err := store.syncIndexRecord(record, false); err != nil {
		return err
	}
	if err := unlinkAnchoredRegularFile(
		store.root,
		store.nextName,
		int(targetFile.Fd()),
		targetIdentity,
		store.expectedUID,
	); err != nil {
		return err
	}
	return nil
}

func writeAndSyncAnchoredFile(
	root *anchoredDirectoryPath,
	name string,
	file *os.File,
	identity pinPathInodeIdentity,
	data []byte,
	expectedUID uint32,
) error {
	return writeAndSyncAnchoredFileWithOps(
		root,
		name,
		file,
		identity,
		data,
		expectedUID,
		livePinOwnerDescriptorOps(),
	)
}

func writeAndSyncAnchoredFileWithOps(
	root *anchoredDirectoryPath,
	name string,
	file *os.File,
	identity pinPathInodeIdentity,
	data []byte,
	expectedUID uint32,
	ops pinOwnerDescriptorOps,
) error {
	if _, err := ops.validate(
		root,
		name,
		int(file.Fd()),
		0o600,
		expectedUID,
		&identity,
	); err != nil {
		return err
	}
	if err := file.Truncate(0); err != nil {
		return err
	}
	if _, err := file.Seek(0, 0); err != nil {
		return err
	}
	written, err := ops.write(file, data)
	if err != nil {
		return err
	}
	if written != len(data) {
		return io.ErrShortWrite
	}
	if err := ops.syncFile(file); err != nil {
		return err
	}
	_, err = ops.validate(
		root,
		name,
		int(file.Fd()),
		0o600,
		expectedUID,
		&identity,
	)
	return err
}

func sameExpectedOwnerRecord(left, right *pinOwnerRecord) bool {
	if left == nil || right == nil {
		return left == right
	}
	leftData, leftErr := json.Marshal(left)
	rightData, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftData, rightData)
}

func unlinkAnchoredRegularFile(
	root *anchoredDirectoryPath,
	name string,
	fd int,
	identity pinPathInodeIdentity,
	expectedUID uint32,
) error {
	if _, err := validateAnchoredRegularFile(
		root,
		name,
		fd,
		0o600,
		expectedUID,
		&identity,
	); err != nil {
		return err
	}
	if err := unix.Unlinkat(root.FD(), name, 0); err != nil {
		return err
	}
	if err := unix.Fsync(root.FD()); err != nil {
		return err
	}
	return nil
}

func discardUnpublishedDescriptorDraft(
	root *anchoredDirectoryPath,
	name string,
	expectedUID uint32,
) error {
	file, identity, err := openExistingAnchoredRegularFile(
		root,
		name,
		0o600,
		expectedUID,
	)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	return unlinkAnchoredRegularFile(
		root,
		name,
		int(file.Fd()),
		identity,
		expectedUID,
	)
}

func (store *pinOwnerStore) recoverDescriptorTransaction() error {
	if store == nil || store.root == nil {
		return errors.New("pin owner store is unavailable")
	}
	if err := discardUnpublishedDescriptorDraft(
		store.root,
		store.draftName,
		store.expectedUID,
	); err != nil {
		return fmt.Errorf("discard unpublished pin owner draft: %w", err)
	}
	if err := store.recoverRetiredRecord(); err != nil {
		return err
	}
	nextFile, nextIdentity, nextErr := openExistingAnchoredRegularFile(
		store.root,
		store.nextName,
		0o600,
		store.expectedUID,
	)
	if errors.Is(nextErr, unix.ENOENT) {
		return nil
	}
	if nextErr != nil {
		return fmt.Errorf("inspect pending pin owner descriptor: %w", nextErr)
	}
	defer nextFile.Close()
	nextRecord, err := readPinOwnerRecord(nextFile)
	if err != nil {
		return err
	}
	if err := validatePinOwnerRecord(nextRecord, store.resource, 0); err != nil {
		return fmt.Errorf("validate pending pin owner descriptor: %w", err)
	}
	targetFile, targetIdentity, targetErr := openExistingAnchoredRegularFile(
		store.root,
		store.fileName,
		0o600,
		store.expectedUID,
	)
	if errors.Is(targetErr, unix.ENOENT) {
		if err := unix.Renameat2(
			store.root.FD(),
			store.nextName,
			store.root.FD(),
			store.fileName,
			unix.RENAME_NOREPLACE,
		); err != nil {
			return fmt.Errorf("recover initial pin owner descriptor: %w", err)
		}
		if err := unix.Fsync(store.root.FD()); err != nil {
			return err
		}
		return store.syncIndexRecord(nextRecord, false)
	}
	if targetErr != nil {
		return targetErr
	}
	defer targetFile.Close()
	targetRecord, err := readPinOwnerRecord(targetFile)
	if err != nil {
		return err
	}
	if err := validatePinOwnerRecord(targetRecord, store.resource, 0); err != nil {
		return fmt.Errorf("validate current pin owner descriptor: %w", err)
	}
	switch {
	case nextRecord.Sequence == targetRecord.Sequence+1:
		if !samePinOwnerImmutableFields(nextRecord, targetRecord) {
			return errors.New("pending pin owner descriptor immutable fields mismatch")
		}
		if err := unix.Renameat2(
			store.root.FD(),
			store.nextName,
			store.root.FD(),
			store.fileName,
			unix.RENAME_EXCHANGE,
		); err != nil {
			return fmt.Errorf("recover pin owner descriptor exchange: %w", err)
		}
		if err := unix.Fsync(store.root.FD()); err != nil {
			return err
		}
		if err := store.syncIndexRecord(nextRecord, false); err != nil {
			return err
		}
		return unlinkAnchoredRegularFile(
			store.root,
			store.nextName,
			int(targetFile.Fd()),
			targetIdentity,
			store.expectedUID,
		)
	case targetRecord.Sequence == nextRecord.Sequence+1:
		if !samePinOwnerImmutableFields(targetRecord, nextRecord) {
			return errors.New("quarantined pin owner descriptor immutable fields mismatch")
		}
		if err := store.syncIndexRecord(targetRecord, false); err != nil {
			return err
		}
		return unlinkAnchoredRegularFile(
			store.root,
			store.nextName,
			int(nextFile.Fd()),
			nextIdentity,
			store.expectedUID,
		)
	default:
		return fmt.Errorf(
			"ambiguous pin owner descriptor sequences target=%d next=%d",
			targetRecord.Sequence, nextRecord.Sequence,
		)
	}
}

func samePinOwnerImmutableFields(left, right *pinOwnerRecord) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.Token == right.Token &&
		left.CreatedAt == right.CreatedAt &&
		left.BootID == right.BootID &&
		left.RetiredFromResourceKey == right.RetiredFromResourceKey &&
		left.RetiredFromBootID == right.RetiredFromBootID
}

func (store *pinOwnerStore) Remove(expected *pinOwnerRecord) error {
	if store == nil || store.root == nil {
		return errors.New("pin owner store is unavailable")
	}
	if expected == nil ||
		expected.Phase != pinOwnerPhaseDetaching ||
		expected.Step != pinOwnerStepCleanupStages {
		return errors.New("pin owner record can only be removed from detaching cleanup_stages")
	}
	if err := store.recoverDescriptorTransaction(); err != nil {
		return err
	}
	var retiredStat unix.Stat_t
	if err := unix.Fstatat(
		store.root.FD(),
		store.retiredName,
		&retiredStat,
		unix.AT_SYMLINK_NOFOLLOW,
	); err == nil {
		return errors.New("pin owner retired quarantine unexpectedly exists")
	} else if !errors.Is(err, unix.ENOENT) {
		return err
	}
	targetFile, targetIdentity, err := openExistingAnchoredRegularFile(
		store.root,
		store.fileName,
		0o600,
		store.expectedUID,
	)
	if err != nil {
		return err
	}
	defer targetFile.Close()
	current, err := readPinOwnerRecord(targetFile)
	if err != nil {
		return err
	}
	if !sameExpectedOwnerRecord(current, expected) {
		return errors.New("pin owner record changed before retirement")
	}
	if _, err := validateAnchoredRegularFile(
		store.root,
		store.fileName,
		int(targetFile.Fd()),
		0o600,
		store.expectedUID,
		&targetIdentity,
	); err != nil {
		return err
	}
	if err := unix.Renameat2(
		store.root.FD(),
		store.fileName,
		store.root.FD(),
		store.retiredName,
		unix.RENAME_NOREPLACE,
	); err != nil {
		return fmt.Errorf("quarantine retired pin owner record: %w", err)
	}
	if err := unix.Fsync(store.root.FD()); err != nil {
		return err
	}
	if _, err := validateAnchoredRegularFile(
		store.root,
		store.retiredName,
		int(targetFile.Fd()),
		0o600,
		store.expectedUID,
		&targetIdentity,
	); err != nil {
		return err
	}
	if err := store.syncIndexRecord(expected, true); err != nil {
		return err
	}
	return unlinkAnchoredRegularFile(
		store.root,
		store.retiredName,
		int(targetFile.Fd()),
		targetIdentity,
		store.expectedUID,
	)
}

func (store *pinOwnerStore) recoverRetiredRecord() error {
	retiredFile, retiredIdentity, err := openExistingAnchoredRegularFile(
		store.root,
		store.retiredName,
		0o600,
		store.expectedUID,
	)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	defer retiredFile.Close()
	record, err := readPinOwnerRecord(retiredFile)
	if err != nil {
		return err
	}
	if err := validatePinOwnerRecord(record, store.resource, 0); err != nil {
		return err
	}
	if record.ResourceKey != store.resource.key ||
		record.Phase != pinOwnerPhaseDetaching ||
		record.Step != pinOwnerStepCleanupStages {
		return errors.New("retired pin owner quarantine is not a completed detach record")
	}
	var targetStat unix.Stat_t
	if err := unix.Fstatat(
		store.root.FD(),
		store.fileName,
		&targetStat,
		unix.AT_SYMLINK_NOFOLLOW,
	); err == nil {
		return errors.New("both active and retired pin owner records exist")
	} else if !errors.Is(err, unix.ENOENT) {
		return err
	}
	if err := store.syncIndexRecord(record, true); err != nil {
		return err
	}
	return unlinkAnchoredRegularFile(
		store.root,
		store.retiredName,
		int(retiredFile.Fd()),
		retiredIdentity,
		store.expectedUID,
	)
}
