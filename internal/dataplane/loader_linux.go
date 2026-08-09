//go:build linux

package dataplane

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/syx0310/wg-mix-ebpf/internal/abi"
	"github.com/syx0310/wg-mix-ebpf/internal/control"
	"github.com/syx0310/wg-mix-ebpf/internal/lockfile"
	"github.com/syx0310/wg-mix-ebpf/internal/pinidentity"
	"golang.org/x/sys/unix"
)

const (
	ingressFilterName = "wg_mix_ingress"
	egressFilterName  = "wg_mix_egress"
	xorSegmentCount   = 8
	pinPathPrefix     = "wg-mix-ebpf"
	maxPinPathSuffix  = 64
	pinPathLockRoot   = "/run/wg-mix-ebpf/pin-locks"
	pinOwnerRoot      = "/var/lib/wg-mix-ebpf/pin-owners"
	pinPathOwnerV2    = 2
)

type pinPathFilesystem struct {
	fsType int64
}

type pinPathValidator struct {
	bpffsMagic int64
	statFS     func(string) (pinPathFilesystem, error)
	mountID    func(string) (uint64, error)
}

type validatedPinPath struct {
	exists         bool
	bpffsRoot      string
	mountID        uint64
	parentInode    pinPathInodeIdentity
	targetInode    pinPathInodeIdentity
	targetHasInode bool
}

type pinPathInodeIdentity struct {
	device uint64
	inode  uint64
	mode   uint32
	uid    uint32
	gid    uint32
	nlink  uint64
}

type pinPathRuntime struct {
	validator            pinPathValidator
	lockRoot             string
	ownerRoot            string
	expectedUID          uint32
	bpffsRootMode        uint32
	allowUnsafeAncestors bool
	mountIDAt            func(int, string, int) (uint64, error)
	loadPinnedMap        func(string, string) (*pinnedMapObservation, error)
	beforeLockWrite      func(string)
	random               io.Reader
	now                  func() time.Time
	bootID               func() (string, error)
	pinProgram           func(uint32, string) error
	loadPinnedProgram    func(string) (*pinnedProgramObservation, error)
	exactTCX             exactTCXRuntime
	beforeOwnerExchange  func()
	beforePinQuarantine  func(string) error
	beforePinUnlink      func(string) error
}

type pinnedProgramObservation struct {
	fd      int
	id      uint32
	program *ebpf.Program
	close   func() error
}

type pinResourceIdentity struct {
	key          string
	parentDevice uint64
	parentInode  uint64
	base         string
	pinPath      string
}

type pinnedMapDescriptor struct {
	name       string
	mapType    ebpf.MapType
	keySize    uint32
	valueSize  uint32
	maxEntries uint32
	flags      uint32
}

type pinnedMapObservation struct {
	id            uint32
	mapType       ebpf.MapType
	keySize       uint32
	valueSize     uint32
	maxEntries    uint32
	flags         uint32
	kernelName    string
	mapExtra      uint64
	frozen        bool
	control       abi.ControlValue
	controlSeen   bool
	owner         pinOwnerSentinel
	ownerSeen     bool
	pin           func(string) error
	updateControl func(abi.ControlValue) error
	updateOwner   func(pinOwnerSentinel) error
	close         func() error
}

type pinOwnerSentinel struct {
	Version        uint32
	Flags          uint32
	ResourceDigest [32]byte
	Token          [32]byte
}

type pinnedMapPin struct {
	descriptor  pinnedMapDescriptor
	inode       pinPathInodeIdentity
	observation *pinnedMapObservation
}

type pinnedMapCleanupPlan struct {
	handle *pinPathHandle
	pins   []pinnedMapPin
}

type pinPathOwner struct {
	Version      int    `json:"version"`
	PID          int    `json:"pid"`
	Action       string `json:"action"`
	ResourceKey  string `json:"resource_key"`
	ParentDevice uint64 `json:"parent_device"`
	ParentInode  uint64 `json:"parent_inode"`
	PinBaseName  string `json:"pin_basename"`
	PinPath      string `json:"pin_path"`
}

type pinPathLock struct {
	path string
	file *os.File
	root *anchoredDirectoryPath
}

type pinPathParent struct {
	pinPath  string
	base     string
	path     *anchoredDirectoryPath
	mountID  uint64
	resource pinResourceIdentity
	runtime  pinPathRuntime
}

type pinPathHandle struct {
	pinPath     string
	base        string
	parentFD    int
	parentPath  *anchoredDirectoryPath
	targetFD    int
	mountID     uint64
	targetInode pinPathInodeIdentity
	resource    pinResourceIdentity
	runtime     pinPathRuntime
}

var livePinPathValidator = pinPathValidator{
	bpffsMagic: int64(unix.BPF_FS_MAGIC),
	statFS: func(path string) (pinPathFilesystem, error) {
		var stat unix.Statfs_t
		if err := unix.Statfs(path, &stat); err != nil {
			return pinPathFilesystem{}, err
		}
		return pinPathFilesystem{
			fsType: int64(stat.Type),
		}, nil
	},
	mountID: linuxMountID,
}

var livePinPathRuntime = pinPathRuntime{
	validator:         livePinPathValidator,
	lockRoot:          pinPathLockRoot,
	ownerRoot:         pinOwnerRoot,
	expectedUID:       0,
	mountIDAt:         linuxMountIDAt,
	loadPinnedMap:     loadPinnedMapObservation,
	random:            rand.Reader,
	now:               time.Now,
	bootID:            readLinuxBootID,
	pinProgram:        pinProgramByID,
	loadPinnedProgram: loadPinnedProgramObservation,
	exactTCX:          liveExactTCXRuntime,
}

var xorTailCallBindings = []struct {
	mapName      string
	programNames [xorSegmentCount]string
}{
	{
		mapName: "xor_egress_programs",
		programNames: [xorSegmentCount]string{
			"wg_xor_eg_0",
			"wg_xor_eg_1",
			"wg_xor_eg_2",
			"wg_xor_eg_3",
			"wg_xor_eg_4",
			"wg_xor_eg_5",
			"wg_xor_eg_6",
			"wg_xor_eg_7",
		},
	},
	{
		mapName: "xor_ingress_programs",
		programNames: [xorSegmentCount]string{
			"wg_xor_in_0",
			"wg_xor_in_1",
			"wg_xor_in_2",
			"wg_xor_in_3",
			"wg_xor_in_4",
			"wg_xor_in_5",
			"wg_xor_in_6",
			"wg_xor_in_7",
		},
	},
}

type LinuxLoader struct {
	ObjectPath       string
	PinPath          string
	AdoptLegacyPins  bool
	runtime          *pinPathRuntime
	objectPathFrozen bool
}

func NewLoader() Loader {
	return NewLoaderWithOptions(LoaderOptions{})
}

func NewLoaderWithOptions(options LoaderOptions) Loader {
	baseline := LinuxLoader{
		ObjectPath:      objectPathFromEnv(""),
		PinPath:         pinPathFromEnv(""),
		AdoptLegacyPins: options.AdoptLegacyPins,
	}
	return newFakeTCPProductionLoader(baseline)
}

func LoadObjectTest(ctx context.Context, objectPath string) error {
	_, err := LoadObjectTestIdentity(ctx, objectPath)
	return err
}

func LoadObjectTestIdentity(
	ctx context.Context,
	objectPath string,
) (ObjectIdentity, error) {
	if err := ctx.Err(); err != nil {
		return ObjectIdentity{}, err
	}
	spec, identity, err := loadCollectionSpec(objectPath)
	if err != nil {
		return ObjectIdentity{}, err
	}
	if err := validateBaselineLoaderCollectionSpec(spec, identity.Source); err != nil {
		return ObjectIdentity{}, err
	}
	if err := removeMemlockLimit(); err != nil {
		return ObjectIdentity{}, err
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return ObjectIdentity{}, fmt.Errorf(
			"create BPF collection from %s: %w",
			identity.Source,
			err,
		)
	}
	defer coll.Close()
	if err := populateXORTailCalls(coll, 0); err != nil {
		return ObjectIdentity{}, err
	}
	return identity, nil
}

func preflightUnpinnedCollection(spec *ebpf.CollectionSpec, source string) error {
	// Verify every map, program, relocation, and deferred map population before
	// PinByName can make a failed load persistent.
	preflightSpec := spec.Copy()
	for _, descriptor := range pinnedMapDescriptors() {
		preflightSpec.Maps[descriptor.name].Pinning = ebpf.PinNone
	}
	collection, err := ebpf.NewCollection(preflightSpec)
	if err != nil {
		return fmt.Errorf("preflight BPF collection from %s without persistent pins: %w", source, err)
	}
	defer collection.Close()
	if err := populateXORTailCalls(collection, 0); err != nil {
		return fmt.Errorf("preflight BPF tail calls from %s: %w", source, err)
	}
	if collection.Programs[ingressFilterName] == nil {
		return fmt.Errorf("BPF object %s missing program %q", source, ingressFilterName)
	}
	if collection.Programs[egressFilterName] == nil {
		return fmt.Errorf("BPF object %s missing program %q", source, egressFilterName)
	}
	return nil
}

func (l LinuxLoader) Apply(ctx context.Context, state *control.State) (returnErr error) {
	if ctx == nil {
		return errors.New("apply context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if state == nil {
		return errors.New("apply control state is nil")
	}
	// Keep this defence in depth even when a production caller performs the
	// same activation check. LinuxLoader is exported and can be constructed
	// directly, so it must refuse FakeTCP before pin validation, object loading,
	// owner intent, map writes, or TCX mutation.
	if err := preflightFakeTCPKernelRequirements(state); err != nil {
		return err
	}
	if l.AdoptLegacyPins {
		return errors.New(
			"classic pin adoption is unsupported by owner schema v4; detach with a trusted legacy build before upgrading",
		)
	}
	runtime := l.pinRuntime(ctx)
	pinPath := pinPathFromEnv(l.PinPath)
	validated, err := validatePinPath(pinPath, runtime.validator)
	if err != nil {
		return err
	}
	// This read-only feature/revision probe is deliberately before BPF object
	// loading, owner intent, map pinning, or any TCX kernel write. Production
	// never falls back to non-exact classic TC after this point.
	if err := preflightExactTCXCapabilities(state, runtime.exactTCX); err != nil {
		return err
	}
	parent, err := openPinPathParent(pinPath, validated, runtime)
	if err != nil {
		return err
	}
	defer parent.Close()
	spec, identity, err := l.loadCollectionSpec()
	if err != nil {
		return err
	}
	source := identity.Source
	if err := validateBaselineLoaderCollectionSpec(spec, source); err != nil {
		return err
	}
	if err := validateAndSetPinnedMaps(spec); err != nil {
		return fmt.Errorf("validate BPF object %s: %w", source, err)
	}
	if err := removeMemlockLimit(); err != nil {
		return err
	}
	if err := preflightUnpinnedCollection(spec, source); err != nil {
		return err
	}

	lock, err := acquirePinPathLock(ctx, parent.resource, "apply", runtime)
	if err != nil {
		return fmt.Errorf("serialize BPF pin path %s: %w", pinPath, err)
	}
	defer lock.Close()

	validated, err = validatePinPath(pinPath, runtime.validator)
	if err != nil {
		return err
	}
	handle, created, err := openPinPathHandleFromParent(parent, validated, true)
	if err != nil {
		return err
	}
	defer handle.Close()
	rollbackFreshPins := created
	// Before the initial owner descriptor is durable, a fresh attempt has not
	// pinned any maps. Its only rollback is the exact empty directory created
	// under this lock. Once the descriptor exists, recovery owns every later
	// durable transition and this legacy fallback is disabled.
	defer func() {
		if returnErr == nil || !rollbackFreshPins {
			return
		}
		if err := rollbackFreshPinnedMaps(handle, created); err != nil {
			returnErr = errors.Join(
				returnErr,
				fmt.Errorf("rollback fresh pinned maps under %s: %w", pinPath, err),
			)
		}
	}()
	if err := handle.recheckTargetEntry(); err != nil {
		return err
	}

	if runtime.random == nil ||
		runtime.bootID == nil ||
		runtime.pinProgram == nil ||
		runtime.loadPinnedProgram == nil {
		return errors.New("pin ownership runtime is incomplete")
	}
	bootID, err := runtime.bootID()
	if err != nil {
		return err
	}
	store, err := openPinOwnerStore(runtime, handle.resource, true)
	if err != nil {
		return err
	}
	defer store.Close()
	ownerRecord, ownerExists, err := store.LoadOptional(handle.mountID)
	if err != nil {
		return fmt.Errorf("load persistent BPF pin owner: %w", err)
	}
	if ownerExists && ownerRecord.BootID == bootID {
		rollbackFreshPins = false
		recovered, err := recoverExactPinOwnerTransaction(
			ctx,
			handle,
			store,
			ownerRecord,
			runtime.exactTCX,
		)
		if err != nil {
			return fmt.Errorf("recover persistent BPF pin owner: %w", err)
		}
		if recovered.directoryRemoved {
			return errors.New(
				"completed an interrupted BPF detach; retry apply against the newly empty pin path",
			)
		}
		ownerRecord = recovered.record
	}

	directoryState, err := classifyCanonicalPinDirectory(handle)
	if err != nil {
		return err
	}
	var rebootSource *pinOwnerIndexEntry
	if ownerExists && ownerRecord.BootID != bootID {
		if directoryState != canonicalPinsEmpty &&
			directoryState != canonicalPinsOwned {
			return errors.New(
				"prior-boot owner can only be archived after every prior-boot exact TCX link pin is absent",
			)
		}
		indexed, err := activeIndexedOwnerForRecord(
			indexStoreFromOwner(store),
			ownerRecord,
		)
		if err != nil {
			return fmt.Errorf("index prior-boot BPF owner: %w", err)
		}
		archiveNow, err := ownerRuntimeNow(runtime)
		if err != nil {
			return err
		}
		rebootSource, err = indexStoreFromOwner(store).archivePriorBootOwner(
			*indexed,
			ownerRecord,
			directoryState == canonicalPinsOwned,
			archiveNow,
		)
		if err != nil {
			return fmt.Errorf("archive prior-boot BPF owner: %w", err)
		}
		ownerRecord = nil
		ownerExists = false
	}
	if !ownerExists {
		indexed, err := indexedOwnerEntryForRekey(store, handle)
		if err != nil {
			return err
		}
		if indexed != nil {
			if indexed.BootID == bootID {
				return fmt.Errorf(
					"same-boot BPF pin identity changed or lost its owner record at %s/%s",
					indexed.BPFFSRootPath,
					indexed.PinBaseName,
				)
			}
			switch indexed.Status {
			case pinOwnerIndexActive:
				if directoryState != canonicalPinsEmpty &&
					directoryState != canonicalPinsOwned {
					return errors.New(
						"indexed prior-boot owner can only be archived after every prior-boot exact TCX link pin is absent",
					)
				}
				priorRecord, err := loadIndexedPriorBootOwner(
					indexStoreFromOwner(store),
					*indexed,
				)
				if err != nil {
					return err
				}
				archiveNow, err := ownerRuntimeNow(runtime)
				if err != nil {
					return err
				}
				rebootSource, err = indexStoreFromOwner(store).archivePriorBootOwner(
					*indexed,
					priorRecord,
					directoryState == canonicalPinsOwned,
					archiveNow,
				)
				if err != nil {
					return err
				}
			case pinOwnerIndexRekeySource:
				source := *indexed
				source.BPFFSMountIDs = slices.Clone(indexed.BPFFSMountIDs)
				rebootSource = &source
			default:
				return fmt.Errorf(
					"indexed BPF owner has non-recoverable status %q",
					indexed.Status,
				)
			}
		}
	}
	if !ownerExists &&
		directoryState == canonicalPinsOwned &&
		rebootSource != nil {
		rekeyNow, err := ownerRuntimeNow(runtime)
		if err != nil {
			return err
		}
		ownerRecord, err = rekeyRebootedPinOwner(
			handle,
			parent,
			store,
			rebootSource,
			bootID,
			rekeyNow,
			runtime.exactTCX,
		)
		if err != nil {
			return fmt.Errorf("rekey rebooted BPF owner: %w", err)
		}
		ownerExists = true
		rollbackFreshPins = false
	}
	if ownerExists {
		if directoryState != canonicalPinsOwned && directoryState != canonicalPinsOwnedTCX {
			return errors.New("active BPF owner record does not have its exact canonical map/link set")
		}
	} else {
		switch directoryState {
		case canonicalPinsEmpty:
		case canonicalPinsLegacy:
			return errors.New(
				"found legacy BPF pins without exact TCX ownership; detach them with a trusted legacy build before upgrading",
			)
		case canonicalPinsOwned:
			return errors.New(
				"found owner_map pins without their persistent exact TCX owner record; refusing name-only adoption",
			)
		case canonicalPinsOwnedTCX:
			return errors.New(
				"found exact TCX link pins without their persistent owner record; refusing link-ID adoption",
			)
		}
	}
	freshPins := !ownerExists && directoryState == canonicalPinsEmpty

	var preexistingPins []pinnedMapPin
	if ownerExists {
		preexistingPins, err = inspectPinnedMapSetWithPolicy(
			handle,
			true,
			true,
			false,
		)
		if err != nil {
			return fmt.Errorf("preflight existing pinned maps under %s: %w", pinPath, err)
		}
		defer closePinnedMapPins(preexistingPins)
		if err := validateOwnerPins(
			handle,
			ownerRecord,
			preexistingPins,
			true,
		); err != nil {
			return err
		}
	}

	loadSpec := spec
	if freshPins {
		loadSpec = spec.Copy()
		for _, descriptor := range pinnedMapDescriptors() {
			loadSpec.Maps[descriptor.name].Pinning = ebpf.PinNone
		}
	}
	coll, err := ebpf.NewCollectionWithOptions(loadSpec, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: handle.procPath()},
	})
	if err != nil {
		if errors.Is(err, ebpf.ErrMapIncompatible) {
			return fmt.Errorf("create BPF collection from %s with pinned maps under %s: %w; run detach or remove stale pinned maps after stopping the agent", source, pinPath, err)
		}
		return fmt.Errorf("create BPF collection from %s: %w", source, err)
	}
	defer coll.Close()
	if err := handle.recheckTargetEntry(); err != nil {
		return err
	}
	if len(preexistingPins) != 0 {
		if err := validateCollectionMapIDs(coll, preexistingPins); err != nil {
			return fmt.Errorf("existing pinned maps changed while loading %s: %w", source, err)
		}
	}
	if ownerExists {
		err = validateCollectionPinnedMaps(handle, coll, true)
	}
	if err != nil {
		return fmt.Errorf("validate collection pins under %s: %w", pinPath, err)
	}

	active, err := activeGeneration(coll)
	if err != nil {
		return err
	}
	if freshPins {
		if active != 0 {
			return fmt.Errorf("fresh unpinned control generation = %d, want zero", active)
		}
	} else if ownerExists && active != ownerRecord.ActiveGeneration {
		return fmt.Errorf(
			"active control generation %d differs from owner record %d",
			active, ownerRecord.ActiveGeneration,
		)
	}
	next := active + 1
	if next == 0 {
		next = 1
	}
	snapshot, err := abi.FromStateWithGeneration(state, next)
	if err != nil {
		return err
	}
	ingress := coll.Programs[ingressFilterName]
	if ingress == nil {
		return fmt.Errorf("BPF object missing program %q", ingressFilterName)
	}
	egress := coll.Programs[egressFilterName]
	if egress == nil {
		return fmt.Errorf("BPF object missing program %q", egressFilterName)
	}
	ingressProgramID, err := exactTCXProgramIdentity(ingress)
	if err != nil {
		return fmt.Errorf("inspect ingress TCX program: %w", err)
	}
	egressProgramID, err := exactTCXProgramIdentity(egress)
	if err != nil {
		return fmt.Errorf("inspect egress TCX program: %w", err)
	}
	desiredLinks, err := exactTCXBindingsForState(
		state,
		ingressProgramID,
		egressProgramID,
	)
	if err != nil {
		return fmt.Errorf("build exact TCX attachment transaction: %w", err)
	}
	activeLinks := []exactTCXBinding{}
	var token [32]byte
	var ownerMaps []pinOwnerMapIdentity
	if freshPins {
		token, err = newPinOwnerToken(runtime.random)
		if err != nil {
			return err
		}
		sentinel, err := pinOwnerSentinelFor(handle.resource, token)
		if err != nil {
			return err
		}
		if err := writeCollectionOwnerSentinel(coll, sentinel); err != nil {
			return err
		}
		ownerMaps, err = ownerMapsFromCollection(coll)
		if err != nil {
			return err
		}
	} else {
		token, err = tokenFromOwnerRecord(ownerRecord)
		if err != nil {
			return err
		}
		ownerMaps = slices.Clone(ownerRecord.Maps)
		activeLinks = slices.Clone(ownerRecord.ActiveLinks)
	}
	desiredLinks, err = bindDesiredExactTCXLinks(activeLinks, desiredLinks)
	if err != nil {
		return err
	}
	now, err := ownerRuntimeNow(runtime)
	if err != nil {
		return err
	}
	applying, err := newApplyingPinOwnerRecord(
		parent,
		token,
		bootID,
		now,
		active,
		next,
		ownerMaps,
		activeLinks,
		desiredLinks,
		ownerRecord,
	)
	if err != nil {
		return err
	}
	if ownerRecord == nil && rebootSource != nil {
		applying.RetiredFromResourceKey = rebootSource.ResourceKey
		applying.RetiredFromBootID = rebootSource.BootID
		normalizePinOwnerRecord(applying)
		if err := validatePinOwnerRecord(
			applying,
			handle.resource,
			handle.mountID,
		); err != nil {
			return err
		}
	}
	if err := store.Persist(
		applying,
		ownerRecord,
		handle.mountID,
	); err != nil {
		if _, exists, loadErr := store.LoadOptional(handle.mountID); loadErr == nil && exists {
			rollbackFreshPins = false
		}
		return fmt.Errorf("persist applying BPF owner intent: %w", err)
	}
	rollbackFreshPins = false
	if freshPins {
		if err := pinFreshCollectionMaps(handle, applying, coll); err != nil {
			return err
		}
	}
	if err := validateCollectionPinnedMaps(handle, coll, false); err != nil {
		return fmt.Errorf("validate journaled collection pins under %s: %w", pinPath, err)
	}
	journalPins, err := inspectPinnedMapSetWithPolicy(
		handle,
		true,
		false,
		false,
	)
	if err != nil {
		return err
	}
	if err := validateOwnerPins(handle, applying, journalPins, true); err != nil {
		_ = closePinnedMapPins(journalPins)
		return err
	}
	if err := closePinnedMapPins(journalPins); err != nil {
		return err
	}
	if err := deleteGenerationMapEntries(coll, next); err != nil {
		return err
	}
	if err := populateDataMaps(coll, snapshot); err != nil {
		return err
	}
	if err := populateXORTailCalls(coll, next); err != nil {
		return err
	}
	if err := stageOwnerPrograms(handle, applying); err != nil {
		return err
	}
	mutating := advancePinOwnerRecord(
		applying,
		now,
		pinOwnerPhaseApplying,
		pinOwnerStepMutating,
	)
	observeOwnerMount(mutating, handle.mountID)
	if err := store.Persist(mutating, applying, handle.mountID); err != nil {
		return err
	}
	abortApply := func(cause error, current *pinOwnerRecord) error {
		abortErr := abortFailedExactOwnerApply(
			ctx,
			handle,
			store,
			current,
			runtime.exactTCX,
		)
		if abortErr != nil {
			return errors.Join(
				cause,
				fmt.Errorf("exact owner-aware apply rollback: %w", abortErr),
			)
		}
		return cause
	}
	programs, err := loadOwnerPrograms(handle, mutating)
	if err != nil {
		return abortApply(err, mutating)
	}
	converged, convergeErr := convergeOwnerApplyExactTCXLinks(
		ctx,
		handle,
		store,
		mutating,
		programs,
		runtime.exactTCX,
	)
	closeProgramsErr := programs.Close()
	if converged != nil {
		mutating = converged
	}
	if convergeErr != nil || closeProgramsErr != nil {
		return abortApply(errors.Join(convergeErr, closeProgramsErr), mutating)
	}
	if err := commitControl(coll, snapshot.Control[abi.ControlKeyGlobal]); err != nil {
		return abortApply(err, mutating)
	}
	cleanupNow, err := ownerRuntimeNow(handle.runtime)
	if err != nil {
		return err
	}
	cleanup := advancePinOwnerRecord(
		mutating,
		cleanupNow,
		pinOwnerPhaseApplying,
		pinOwnerStepCleanup,
	)
	observeOwnerMount(cleanup, handle.mountID)
	if err := store.Persist(cleanup, mutating, handle.mountID); err != nil {
		return err
	}
	recovered, err := recoverExactApplyingPinOwnerTransaction(
		ctx,
		handle,
		store,
		cleanup,
		runtime.exactTCX,
	)
	if err != nil {
		return err
	}
	ownerRecord = recovered.record
	if err := deleteStaleMapEntries(coll, snapshot); err != nil {
		return err
	}
	if err := validateCollectionPinnedMaps(handle, coll, true); err != nil {
		return fmt.Errorf("validate committed collection pins under %s: %w", pinPath, err)
	}
	finalPins, err := inspectPinnedMapSet(handle, true)
	if err != nil {
		return err
	}
	defer closePinnedMapPins(finalPins)
	if err := validateOwnerPins(handle, ownerRecord, finalPins, true); err != nil {
		return err
	}
	return nil
}

func (l LinuxLoader) effectiveObjectPath() string {
	if l.objectPathFrozen {
		return l.ObjectPath
	}
	return objectPathFromEnv(l.ObjectPath)
}

func (l LinuxLoader) loadCollectionSpec() (*ebpf.CollectionSpec, ObjectIdentity, error) {
	return loadCollectionSpecFromResolvedPath(l.effectiveObjectPath())
}

func (l LinuxLoader) DetachStale(ctx context.Context, previous *control.State, current *control.State) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Apply now includes owner-recorded stale exact TCX links in the same global
	// preflight, rollback, and journal transaction as replacements/additions.
	// Keep this compatibility hook side-effect free for older reconcile callers.
	return nil
}

func (l LinuxLoader) Detach(ctx context.Context, state *control.State) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	runtime := l.pinRuntime(ctx)
	pinPath := pinPathFromEnv(l.PinPath)
	validated, err := validatePinPath(pinPath, runtime.validator)
	if err != nil {
		return err
	}
	parent, err := openPinPathParent(pinPath, validated, runtime)
	if err != nil {
		return err
	}
	defer parent.Close()

	lock, err := acquirePinPathLock(ctx, parent.resource, "detach", runtime)
	if err != nil {
		return fmt.Errorf("serialize BPF pin path %s: %w", pinPath, err)
	}
	defer lock.Close()

	validated, err = validatePinPath(pinPath, runtime.validator)
	if err != nil {
		return err
	}
	handle, _, err := openPinPathHandleFromParent(parent, validated, false)
	if err != nil {
		return err
	}
	if handle == nil {
		return ensureMissingPinDirectoryHasNoActiveOwnership(
			runtime,
			parent,
		)
	}
	defer handle.Close()
	store, err := openPinOwnerStore(runtime, handle.resource, false)
	if err != nil {
		return fmt.Errorf("open persistent BPF pin owner: %w", err)
	}
	defer store.Close()
	record, exists, err := store.LoadOptional(handle.mountID)
	if err != nil {
		return err
	}
	if !exists {
		directoryState, classifyErr := classifyCanonicalPinDirectory(handle)
		if classifyErr != nil {
			return classifyErr
		}
		if directoryState == canonicalPinsEmpty {
			empty, err := pinDirectoryIsEmpty(handle.targetFD, handle.pinPath)
			if err != nil {
				return err
			}
			if !empty {
				return errors.New("ownerless BPF pin path is not empty")
			}
			if err := handle.recheckTargetEntry(); err != nil {
				return err
			}
			return unix.Unlinkat(handle.parentFD, handle.base, unix.AT_REMOVEDIR)
		}
		return errors.New(
			"BPF pins have no persistent owner record; refusing state/name-based detach",
		)
	}
	if runtime.bootID == nil {
		return errors.New("pin owner boot ID runtime is unavailable")
	}
	bootID, err := runtime.bootID()
	if err != nil {
		return err
	}
	if record.BootID != bootID {
		return fmt.Errorf(
			"BPF pin owner was created on boot %s but current boot is %s; refusing unindexed reboot detach",
			record.BootID, bootID,
		)
	}
	recovered, err := recoverExactPinOwnerTransaction(
		ctx,
		handle,
		store,
		record,
		runtime.exactTCX,
	)
	if err != nil {
		return fmt.Errorf("recover BPF owner before detach: %w", err)
	}
	if recovered.directoryRemoved {
		return nil
	}
	if recovered.record == nil ||
		recovered.record.Phase != pinOwnerPhaseActive {
		return errors.New("BPF owner recovery did not reach an active state")
	}
	return executeExactOwnerDetachTransaction(
		ctx,
		handle,
		store,
		recovered.record,
		runtime.exactTCX,
	)
}

func pinPathFromEnv(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if path := os.Getenv(EnvPinPath); path != "" {
		return path
	}
	return DefaultPinPath
}

func validatePinPath(pinPath string, validator pinPathValidator) (validatedPinPath, error) {
	if pinPath == "" {
		return validatedPinPath{}, fmt.Errorf("validate BPF pin path: path is empty")
	}
	if !filepath.IsAbs(pinPath) {
		return validatedPinPath{}, fmt.Errorf("validate BPF pin path %q: path must be absolute", pinPath)
	}
	if cleaned := filepath.Clean(pinPath); cleaned != pinPath {
		return validatedPinPath{}, fmt.Errorf("validate BPF pin path %q: path must be clean (canonical spelling %q)", pinPath, cleaned)
	}
	if validator.statFS == nil || validator.mountID == nil {
		return validatedPinPath{}, fmt.Errorf("validate BPF pin path %q: filesystem or mount validator is unavailable", pinPath)
	}

	nearest, exists, err := nearestExistingPinPathAncestor(pinPath)
	if err != nil {
		return validatedPinPath{}, fmt.Errorf("validate BPF pin path %q: %w", pinPath, err)
	}
	parent := filepath.Dir(pinPath)
	if !exists && nearest != parent {
		return validatedPinPath{}, fmt.Errorf(
			"validate BPF pin path %q: direct parent %s must already exist",
			pinPath, parent,
		)
	}
	parentFilesystem, err := validator.statFS(parent)
	if err != nil {
		return validatedPinPath{}, fmt.Errorf("validate BPF pin path %q: statfs parent %s: %w", pinPath, parent, err)
	}
	parentMountID, err := validator.mountID(parent)
	if err != nil {
		return validatedPinPath{}, fmt.Errorf("validate BPF pin path %q: inspect parent mount %s: %w", pinPath, parent, err)
	}
	if parentFilesystem.fsType != validator.bpffsMagic {
		if exists {
			targetFilesystem, targetFSErr := validator.statFS(pinPath)
			targetMountID, targetMountErr := validator.mountID(pinPath)
			if targetFSErr == nil && targetMountErr == nil &&
				targetFilesystem.fsType == validator.bpffsMagic && targetMountID != parentMountID {
				return validatedPinPath{}, fmt.Errorf("validate BPF pin path %q: path must not be the bpffs top level", pinPath)
			}
		}
		return validatedPinPath{}, fmt.Errorf("validate BPF pin path %q: direct parent %s is not a bpffs mount root", pinPath, parent)
	}
	parentParent := filepath.Dir(parent)
	if parentParent == parent {
		return validatedPinPath{}, fmt.Errorf("validate BPF pin path %q: cannot use filesystem root as the bpffs mount root", pinPath)
	}
	parentParentMountID, err := validator.mountID(parentParent)
	if err != nil {
		return validatedPinPath{}, fmt.Errorf("validate BPF pin path %q: inspect mount above %s: %w", pinPath, parent, err)
	}
	if parentMountID == parentParentMountID {
		return validatedPinPath{}, fmt.Errorf(
			"validate BPF pin path %q: direct parent %s is inside bpffs but is not its mount root",
			pinPath, parent,
		)
	}
	if exists {
		targetMountID, err := validator.mountID(pinPath)
		if err != nil {
			return validatedPinPath{}, fmt.Errorf("validate BPF pin path %q: inspect target mount: %w", pinPath, err)
		}
		if targetMountID != parentMountID {
			return validatedPinPath{}, fmt.Errorf(
				"validate BPF pin path %q: target is a nested mount instead of a directory on bpffs mount %s",
				pinPath, parent,
			)
		}
	}
	parentInode, err := lstatPinPathInode(parent)
	if err != nil {
		return validatedPinPath{}, fmt.Errorf("validate BPF pin path %q: inspect parent identity: %w", pinPath, err)
	}
	var targetInode pinPathInodeIdentity
	if exists {
		targetInode, err = lstatPinPathInode(pinPath)
		if err != nil {
			return validatedPinPath{}, fmt.Errorf("validate BPF pin path %q: inspect target identity: %w", pinPath, err)
		}
	}
	if !validPinPathBase(filepath.Base(pinPath)) {
		return validatedPinPath{}, fmt.Errorf(
			"validate BPF pin path %q: directory name must be %q or %q plus a 1-%d byte ASCII alphanumeric suffix with optional internal hyphens",
			pinPath, pinPathPrefix, pinPathPrefix+"-",
			maxPinPathSuffix,
		)
	}
	return validatedPinPath{
		exists:         exists,
		bpffsRoot:      parent,
		mountID:        parentMountID,
		parentInode:    parentInode,
		targetInode:    targetInode,
		targetHasInode: exists,
	}, nil
}

func linuxMountID(path string) (uint64, error) {
	return linuxMountIDAt(unix.AT_FDCWD, path, unix.AT_NO_AUTOMOUNT|unix.AT_SYMLINK_NOFOLLOW)
}

func linuxMountIDAt(dirFD int, path string, flags int) (uint64, error) {
	var stat unix.Statx_t
	if err := unix.Statx(
		dirFD,
		path,
		flags,
		unix.STATX_MNT_ID,
		&stat,
	); err != nil {
		return 0, err
	}
	if stat.Mask&unix.STATX_MNT_ID == 0 || stat.Mnt_id == 0 {
		return 0, errors.New("kernel did not report a statx mount ID")
	}
	return stat.Mnt_id, nil
}

func lstatPinPathInode(path string) (pinPathInodeIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil {
		return pinPathInodeIdentity{}, err
	}
	return pinPathInodeFromStat(&stat), nil
}

func pinPathInodeFromStat(stat *unix.Stat_t) pinPathInodeIdentity {
	return pinPathInodeIdentity{
		device: uint64(stat.Dev),
		inode:  stat.Ino,
		mode:   stat.Mode,
		uid:    stat.Uid,
		gid:    stat.Gid,
		nlink:  uint64(stat.Nlink),
	}
}

func samePinPathInode(left, right pinPathInodeIdentity) bool {
	return left.device == right.device &&
		left.inode == right.inode &&
		left.mode&unix.S_IFMT == right.mode&unix.S_IFMT
}

func (l LinuxLoader) pinRuntime(ctx context.Context) pinPathRuntime {
	if l.runtime != nil {
		return *l.runtime
	}
	runtime := livePinPathRuntime
	lifecycleLease := lockfile.LifecycleLeasePath(ctx)
	if lifecycleLease != lockfile.DefaultLifecycleLeasePath {
		// The isolated netns entrypoint binds its shared lifecycle lease to the
		// run-owned root. Keep both resource serialization and persistent owner
		// records in that same manifest and teardown scope.
		runRoot := filepath.Dir(lifecycleLease)
		runtime.lockRoot = filepath.Join(runRoot, "pin-locks")
		runtime.ownerRoot = filepath.Join(runRoot, "pin-owners")
		runtime.bpffsRootMode = 0o700
	}
	return runtime
}

func acquirePinPathLock(
	ctx context.Context,
	resource pinResourceIdentity,
	action string,
	runtime pinPathRuntime,
) (*pinPathLock, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !pinidentity.ValidKey(resource.key) {
		return nil, fmt.Errorf("invalid BPF pin resource key %q", resource.key)
	}
	name, err := pinidentity.LockFileName(
		resource.parentDevice,
		resource.parentInode,
		resource.base,
	)
	if err != nil {
		return nil, fmt.Errorf("derive BPF pin lock name: %w", err)
	}
	if name != resource.key+".lock" {
		return nil, errors.New("BPF pin lock identity helper returned an inconsistent name")
	}
	root, _, err := openAnchoredDirectoryPath(
		runtime.lockRoot,
		true,
		0o700,
		runtime.expectedUID,
		runtime.allowUnsafeAncestors,
	)
	if err != nil {
		return nil, fmt.Errorf("open pin-path lock root %s: %w", runtime.lockRoot, err)
	}
	closeRootOnError := func() {
		_ = root.Close()
	}
	lockPath := filepath.Join(runtime.lockRoot, name)
	file, fileIdentity, _, err := openAnchoredRegularFile(
		root,
		name,
		0o600,
		runtime.expectedUID,
	)
	if err != nil {
		closeRootOnError()
		return nil, fmt.Errorf("open pin-path lock %s: %w", lockPath, err)
	}
	fd := int(file.Fd())
	closeAllOnError := func() {
		_ = file.Close()
		closeRootOnError()
	}

	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			closeAllOnError()
			return nil, fmt.Errorf("acquire pin-path lock %s: %w", lockPath, err)
		}
		select {
		case <-ctx.Done():
			closeAllOnError()
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}

	if _, err := validateAnchoredRegularFile(
		root,
		name,
		fd,
		0o600,
		runtime.expectedUID,
		&fileIdentity,
	); err != nil {
		closeAllOnError()
		return nil, fmt.Errorf("recheck pin-path lock %s: %w", lockPath, err)
	}
	if runtime.beforeLockWrite != nil {
		runtime.beforeLockWrite(lockPath)
	}

	owner, err := json.Marshal(pinPathOwner{
		Version:      pinPathOwnerV2,
		PID:          os.Getpid(),
		Action:       action,
		ResourceKey:  resource.key,
		ParentDevice: resource.parentDevice,
		ParentInode:  resource.parentInode,
		PinBaseName:  resource.base,
		PinPath:      resource.pinPath,
	})
	if err == nil {
		_, err = validateAnchoredRegularFile(
			root,
			name,
			fd,
			0o600,
			runtime.expectedUID,
			&fileIdentity,
		)
	}
	if err == nil {
		err = file.Truncate(0)
	}
	if err == nil {
		_, err = file.Seek(0, 0)
	}
	if err == nil {
		var written int
		written, err = file.Write(append(owner, '\n'))
		if err == nil && written != len(owner)+1 {
			err = io.ErrShortWrite
		}
	}
	if err == nil {
		err = file.Sync()
	}
	if err != nil {
		closeAllOnError()
		return nil, fmt.Errorf("record pin-path lock owner in %s: %w", lockPath, err)
	}
	if _, err := validateAnchoredRegularFile(
		root,
		name,
		fd,
		0o600,
		runtime.expectedUID,
		&fileIdentity,
	); err != nil {
		closeAllOnError()
		return nil, fmt.Errorf("verify pin-path lock owner in %s: %w", lockPath, err)
	}
	return &pinPathLock{path: lockPath, file: file, root: root}, nil
}

func (l *pinPathLock) Close() error {
	if l == nil {
		return nil
	}
	var errs []error
	if l.file != nil {
		if err := l.file.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close pin-path lock %s: %w", l.path, err))
		}
		l.file = nil
	}
	if l.root != nil {
		if err := l.root.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close pin-path lock root for %s: %w", l.path, err))
		}
		l.root = nil
	}
	return errors.Join(errs...)
}

func openPinPathHandle(
	pinPath string,
	validated validatedPinPath,
	create bool,
	runtime pinPathRuntime,
) (*pinPathHandle, bool, error) {
	parent, err := openPinPathParent(pinPath, validated, runtime)
	if err != nil {
		return nil, false, err
	}
	handle, created, err := openPinPathHandleFromParent(parent, validated, create)
	if err != nil || handle == nil {
		_ = parent.Close()
	}
	return handle, created, err
}

func openPinPathParent(
	pinPath string,
	validated validatedPinPath,
	runtime pinPathRuntime,
) (*pinPathParent, error) {
	if runtime.mountIDAt == nil {
		return nil, errors.New("pin-path mount-ID-at validator is unavailable")
	}
	parentPath, _, err := openAnchoredDirectoryPath(
		validated.bpffsRoot,
		false,
		runtime.bpffsRootMode,
		runtime.expectedUID,
		runtime.allowUnsafeAncestors,
	)
	if err != nil {
		return nil, fmt.Errorf("open bpffs mount root %s: %w", validated.bpffsRoot, err)
	}
	closeOnError := func() {
		_ = parentPath.Close()
	}
	parentIdentity := parentPath.Identity()
	if !samePinPathInode(parentIdentity, validated.parentInode) {
		closeOnError()
		return nil, fmt.Errorf("bpffs mount root %s changed after validation", validated.bpffsRoot)
	}
	parentMountID, err := runtime.mountIDAt(
		parentPath.FD(),
		"",
		unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT,
	)
	if err != nil {
		closeOnError()
		return nil, fmt.Errorf("inspect opened bpffs mount ID: %w", err)
	}
	if parentMountID != validated.mountID {
		closeOnError()
		return nil, fmt.Errorf("bpffs mount root %s changed mount identity after validation", validated.bpffsRoot)
	}
	base := filepath.Base(pinPath)
	resourceKey, err := pinidentity.Key(parentIdentity.device, parentIdentity.inode, base)
	if err != nil {
		closeOnError()
		return nil, fmt.Errorf("derive BPF pin resource identity: %w", err)
	}
	return &pinPathParent{
		pinPath: pinPath,
		base:    base,
		path:    parentPath,
		mountID: parentMountID,
		resource: pinResourceIdentity{
			key:          resourceKey,
			parentDevice: parentIdentity.device,
			parentInode:  parentIdentity.inode,
			base:         base,
			pinPath:      pinPath,
		},
		runtime: runtime,
	}, nil
}

func openPinPathHandleFromParent(
	parent *pinPathParent,
	validated validatedPinPath,
	create bool,
) (*pinPathHandle, bool, error) {
	if parent == nil || parent.path == nil {
		return nil, false, errors.New("bpffs parent anchor is unavailable")
	}
	if err := parent.Recheck(); err != nil {
		return nil, false, err
	}
	if !samePinPathInode(parent.path.Identity(), validated.parentInode) ||
		parent.mountID != validated.mountID {
		return nil, false, fmt.Errorf("validated bpffs root changed for %s", parent.pinPath)
	}
	parentFD := parent.path.FD()
	created := false
	if create && !validated.exists {
		if err := parent.Recheck(); err != nil {
			return nil, false, fmt.Errorf("recheck bpffs root before creating pin directory: %w", err)
		}
		if err := unix.Mkdirat(parentFD, parent.base, 0o700); err != nil {
			if !errors.Is(err, unix.EEXIST) {
				return nil, false, fmt.Errorf("create BPF pin directory %s: %w", parent.pinPath, err)
			}
		} else {
			created = true
		}
	}
	if !create && !validated.exists {
		var stat unix.Stat_t
		err := unix.Fstatat(parentFD, parent.base, &stat, unix.AT_SYMLINK_NOFOLLOW)
		if err == nil {
			return nil, false, fmt.Errorf(
				"BPF pin directory %s appeared after absence preflight",
				parent.pinPath,
			)
		}
		if !errors.Is(err, unix.ENOENT) {
			return nil, false, fmt.Errorf(
				"recheck absent BPF pin directory %s: %w",
				parent.pinPath, err,
			)
		}
		return nil, false, nil
	}
	targetFD, err := unix.Openat(
		parentFD,
		parent.base,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return nil, false, fmt.Errorf("open BPF pin directory %s: %w", parent.pinPath, err)
	}
	closeTargetOnError := func() {
		_ = unix.Close(targetFD)
	}
	var targetStat unix.Stat_t
	if err := unix.Fstat(targetFD, &targetStat); err != nil {
		closeTargetOnError()
		return nil, false, fmt.Errorf("inspect opened BPF pin directory %s: %w", parent.pinPath, err)
	}
	targetInode := pinPathInodeFromStat(&targetStat)
	if err := validateOwnedPinDirectory(
		parent.pinPath,
		targetInode,
		parent.runtime.expectedUID,
	); err != nil {
		closeTargetOnError()
		return nil, false, err
	}
	if validated.targetHasInode && !samePinPathInode(targetInode, validated.targetInode) {
		closeTargetOnError()
		return nil, false, fmt.Errorf("BPF pin directory %s changed after validation", parent.pinPath)
	}
	targetMountID, err := parent.runtime.mountIDAt(
		targetFD,
		"",
		unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT,
	)
	if err != nil {
		closeTargetOnError()
		return nil, false, fmt.Errorf("inspect opened BPF pin directory mount ID: %w", err)
	}
	if targetMountID != parent.mountID {
		closeTargetOnError()
		return nil, false, fmt.Errorf("BPF pin directory %s is a nested mount", parent.pinPath)
	}
	var targetPathStat unix.Stat_t
	if err := unix.Fstatat(
		parentFD,
		parent.base,
		&targetPathStat,
		unix.AT_SYMLINK_NOFOLLOW,
	); err != nil {
		closeTargetOnError()
		return nil, false, fmt.Errorf("recheck opened BPF pin directory %s: %w", parent.pinPath, err)
	}
	targetAtPath := pinPathInodeFromStat(&targetPathStat)
	if !samePinPathInode(targetAtPath, targetInode) ||
		targetAtPath.uid != targetInode.uid ||
		targetAtPath.mode&0o7777 != targetInode.mode&0o7777 ||
		targetAtPath.nlink == 0 {
		closeTargetOnError()
		return nil, false, fmt.Errorf("BPF pin directory %s changed while opening", parent.pinPath)
	}
	parentPath := parent.path
	parent.path = nil
	return &pinPathHandle{
		pinPath:     parent.pinPath,
		base:        parent.base,
		parentFD:    parentFD,
		parentPath:  parentPath,
		targetFD:    targetFD,
		mountID:     targetMountID,
		targetInode: targetInode,
		resource:    parent.resource,
		runtime:     parent.runtime,
	}, created, nil
}

func validateOwnedPinDirectory(
	pinPath string,
	identity pinPathInodeIdentity,
	expectedUID uint32,
) error {
	if identity.mode&unix.S_IFMT != unix.S_IFDIR ||
		identity.mode&0o7777 != 0o700 ||
		identity.uid != expectedUID ||
		identity.nlink == 0 {
		return fmt.Errorf(
			"refuse unsafe BPF pin directory %s: mode=%#o uid=%d links=%d; want directory 0700 uid=%d with non-zero links",
			pinPath, identity.mode, identity.uid, identity.nlink, expectedUID,
		)
	}
	return nil
}

func (parent *pinPathParent) Recheck() error {
	if parent == nil || parent.path == nil {
		return errors.New("bpffs parent anchor is unavailable")
	}
	if err := parent.path.Recheck(); err != nil {
		return err
	}
	mountID, err := parent.runtime.mountIDAt(
		parent.path.FD(),
		"",
		unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT,
	)
	if err != nil {
		return fmt.Errorf("recheck bpffs mount ID for %s: %w", parent.pinPath, err)
	}
	if mountID != parent.mountID {
		return fmt.Errorf("bpffs mount identity changed for %s", parent.pinPath)
	}
	identity := parent.path.Identity()
	if identity.device != parent.resource.parentDevice ||
		identity.inode != parent.resource.parentInode {
		return fmt.Errorf("bpffs resource identity changed for %s", parent.pinPath)
	}
	return nil
}

func (parent *pinPathParent) Close() error {
	if parent == nil || parent.path == nil {
		return nil
	}
	err := parent.path.Close()
	parent.path = nil
	return err
}

func (h *pinPathHandle) recheckTargetEntry() error {
	if h == nil {
		return nil
	}
	if h.parentPath == nil {
		return fmt.Errorf("bpffs parent anchor for %s is unavailable", h.pinPath)
	}
	if err := h.parentPath.Recheck(); err != nil {
		return fmt.Errorf("recheck bpffs boundary for %s: %w", h.pinPath, err)
	}
	var stat unix.Stat_t
	if err := unix.Fstatat(h.parentFD, h.base, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("recheck BPF pin directory %s: %w", h.pinPath, err)
	}
	current := pinPathInodeFromStat(&stat)
	if !samePinPathInode(current, h.targetInode) ||
		current.uid != h.targetInode.uid ||
		current.mode&0o7777 != h.targetInode.mode&0o7777 ||
		current.nlink == 0 {
		return fmt.Errorf("BPF pin directory %s changed after it was opened", h.pinPath)
	}
	if err := validateOwnedPinDirectory(h.pinPath, current, h.runtime.expectedUID); err != nil {
		return err
	}
	mountID, err := h.runtime.mountIDAt(
		h.parentFD,
		h.base,
		unix.AT_NO_AUTOMOUNT|unix.AT_SYMLINK_NOFOLLOW,
	)
	if err != nil {
		return fmt.Errorf("recheck BPF pin directory mount ID %s: %w", h.pinPath, err)
	}
	if mountID != h.mountID {
		return fmt.Errorf("BPF pin directory %s changed mount identity", h.pinPath)
	}
	return nil
}

func (h *pinPathHandle) procPath() string {
	return fmt.Sprintf("/proc/self/fd/%d", h.targetFD)
}

func (h *pinPathHandle) Close() error {
	if h == nil {
		return nil
	}
	var errs []error
	if h.targetFD >= 0 {
		if err := unix.Close(h.targetFD); err != nil {
			errs = append(errs, fmt.Errorf("close BPF pin directory %s: %w", h.pinPath, err))
		}
		h.targetFD = -1
	}
	if h.parentPath != nil {
		if err := h.parentPath.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close bpffs mount root for %s: %w", h.pinPath, err))
		}
		h.parentPath = nil
		h.parentFD = -1
	}
	return errors.Join(errs...)
}

func validPinPathBase(base string) bool {
	if base == pinPathPrefix {
		return true
	}
	prefix := pinPathPrefix + "-"
	if !strings.HasPrefix(base, prefix) {
		return false
	}
	suffix := strings.TrimPrefix(base, prefix)
	if len(suffix) == 0 || len(suffix) > maxPinPathSuffix {
		return false
	}
	for index := range len(suffix) {
		character := suffix[index]
		isAlphaNumeric := character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9'
		if isAlphaNumeric {
			continue
		}
		if character != '-' || index == 0 || index == len(suffix)-1 {
			return false
		}
	}
	return true
}

func nearestExistingPinPathAncestor(pinPath string) (string, bool, error) {
	current := string(filepath.Separator)
	relative := strings.TrimPrefix(pinPath, current)
	components := strings.Split(relative, string(filepath.Separator))
	for index, component := range components {
		next := filepath.Join(current, component)
		info, err := os.Lstat(next)
		if errors.Is(err, os.ErrNotExist) {
			return current, false, nil
		}
		if err != nil {
			return "", false, fmt.Errorf("inspect path component %s: %w", next, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", false, fmt.Errorf("path component %s is a symbolic link", next)
		}
		if !info.IsDir() {
			if index == len(components)-1 {
				return "", false, fmt.Errorf("pin path target %s is not a directory", next)
			}
			return "", false, fmt.Errorf("path ancestor %s is not a directory", next)
		}
		current = next
	}
	return current, true, nil
}

func removeMemlockLimit() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock rlimit: %w", err)
	}
	return nil
}

func pinnedMapDescriptors() []pinnedMapDescriptor {
	return []pinnedMapDescriptor{
		{name: "control_map", mapType: ebpf.Array, keySize: 4, valueSize: 16, maxEntries: 1},
		{name: "owner_map", mapType: ebpf.Array, keySize: 4, valueSize: 72, maxEntries: 1},
		{name: "profile_map", mapType: ebpf.Hash, keySize: 16, valueSize: 48, maxEntries: 128},
		{name: "cipher_map", mapType: ebpf.Hash, keySize: 16, valueSize: 288, maxEntries: 128},
		{name: "underlay_config_map", mapType: ebpf.Hash, keySize: 16, valueSize: 16, maxEntries: 512},
		{name: "managed_fwmark_map", mapType: ebpf.Hash, keySize: 16, valueSize: 16, maxEntries: 512},
		{name: "egress_rule_map", mapType: ebpf.Hash, keySize: 24, valueSize: 32, maxEntries: 2048},
		{name: "ingress_listener_map", mapType: ebpf.Hash, keySize: 16, valueSize: 24, maxEntries: 2048},
		{name: "icmp_listener_map", mapType: ebpf.Hash, keySize: 16, valueSize: 24, maxEntries: 2048},
		{name: "stats_map", mapType: ebpf.PerCPUArray, keySize: 4, valueSize: 8, maxEntries: 36},
		{name: "xor_egress_programs", mapType: ebpf.ProgramArray, keySize: 4, valueSize: 4, maxEntries: 16},
		{name: "xor_ingress_programs", mapType: ebpf.ProgramArray, keySize: 4, valueSize: 4, maxEntries: 16},
	}
}

func pinnedMapNames() []string {
	descriptors := pinnedMapDescriptors()
	names := make([]string, 0, len(descriptors))
	for _, descriptor := range descriptors {
		names = append(names, descriptor.name)
	}
	return names
}

func validateAndSetPinnedMaps(spec *ebpf.CollectionSpec) error {
	if spec == nil {
		return errors.New("validate BPF collection maps: collection spec is nil")
	}
	descriptors := pinnedMapDescriptors()
	known := make(map[string]struct{}, len(descriptors))
	for _, descriptor := range descriptors {
		known[descriptor.name] = struct{}{}
		mapSpec := spec.Maps[descriptor.name]
		if mapSpec == nil {
			return fmt.Errorf("BPF object missing required pinned map %q", descriptor.name)
		}
		if err := validatePinnedMapSpec(descriptor, mapSpec); err != nil {
			return err
		}
	}

	var unexpectedPinned []string
	for name, mapSpec := range spec.Maps {
		if mapSpec == nil {
			return fmt.Errorf("BPF object map %q has a nil spec", name)
		}
		if _, ok := known[name]; !ok && mapSpec.Pinning != ebpf.PinNone {
			unexpectedPinned = append(unexpectedPinned, name)
		}
	}
	if len(unexpectedPinned) != 0 {
		sort.Strings(unexpectedPinned)
		return fmt.Errorf("BPF object requests unexpected pinned maps: %s", strings.Join(unexpectedPinned, ", "))
	}
	for _, descriptor := range descriptors {
		spec.Maps[descriptor.name].Pinning = ebpf.PinByName
	}
	return nil
}

func validatePinnedMapSpec(descriptor pinnedMapDescriptor, spec *ebpf.MapSpec) error {
	if spec.Name != descriptor.name {
		return fmt.Errorf(
			"BPF map %q has kernel name %q, want %q",
			descriptor.name, spec.Name, descriptor.name,
		)
	}
	if spec.Type != descriptor.mapType ||
		spec.KeySize != descriptor.keySize ||
		spec.ValueSize != descriptor.valueSize ||
		spec.MaxEntries != descriptor.maxEntries ||
		spec.Flags != descriptor.flags {
		return fmt.Errorf(
			"BPF map %q schema is %s key=%d value=%d max=%d flags=%#x, want %s key=%d value=%d max=%d flags=%#x",
			descriptor.name,
			spec.Type, spec.KeySize, spec.ValueSize, spec.MaxEntries, spec.Flags,
			descriptor.mapType, descriptor.keySize, descriptor.valueSize, descriptor.maxEntries, descriptor.flags,
		)
	}
	if spec.NumaNode != 0 || spec.InnerMap != nil || spec.MapExtra != 0 ||
		(spec.Extra != nil && spec.Extra.Len() != 0) || len(spec.Contents) != 0 {
		return fmt.Errorf(
			"BPF map %q has unsupported creation metadata (numa=%d inner=%t extra=%d trailing=%t contents=%d)",
			descriptor.name,
			spec.NumaNode, spec.InnerMap != nil, spec.MapExtra,
			spec.Extra != nil && spec.Extra.Len() != 0, len(spec.Contents),
		)
	}
	if spec.Pinning != ebpf.PinNone && spec.Pinning != ebpf.PinByName {
		return fmt.Errorf(
			"BPF map %q has unsupported pinning mode %d",
			descriptor.name, spec.Pinning,
		)
	}
	return nil
}

func loadPinnedMapObservation(path string, name string) (*pinnedMapObservation, error) {
	pinnedMap, err := ebpf.LoadPinnedMap(path, &ebpf.LoadPinOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	closeOnError := func() {
		_ = pinnedMap.Close()
	}
	info, err := pinnedMap.Info()
	if err != nil {
		closeOnError()
		return nil, fmt.Errorf("inspect pinned map info: %w", err)
	}
	mapID, ok := info.ID()
	if !ok || mapID == 0 {
		closeOnError()
		return nil, errors.New("kernel did not report a pinned map ID")
	}
	mapExtra, _ := info.MapExtra()
	observation := &pinnedMapObservation{
		id:         uint32(mapID),
		mapType:    info.Type,
		keySize:    info.KeySize,
		valueSize:  info.ValueSize,
		maxEntries: info.MaxEntries,
		flags:      info.Flags,
		kernelName: info.Name,
		mapExtra:   mapExtra,
		frozen:     info.Frozen(),
		close:      pinnedMap.Close,
	}
	if name == "control_map" {
		if err := pinnedMap.Lookup(abi.ControlKeyGlobal, &observation.control); err != nil {
			closeOnError()
			return nil, fmt.Errorf("lookup control identity: %w", err)
		}
		observation.controlSeen = true
		observation.updateControl = func(value abi.ControlValue) error {
			return updatePinnedMapValue(
				path,
				uint32(mapID),
				abi.ControlKeyGlobal,
				value,
			)
		}
	}
	if name == "owner_map" {
		if err := pinnedMap.Lookup(uint32(0), &observation.owner); err != nil {
			closeOnError()
			return nil, fmt.Errorf("lookup owner sentinel: %w", err)
		}
		observation.ownerSeen = true
		observation.updateOwner = func(value pinOwnerSentinel) error {
			return updatePinnedMapValue(
				path,
				uint32(mapID),
				uint32(0),
				value,
			)
		}
	}
	observation.pin = pinnedMap.Pin
	return observation, nil
}

func updatePinnedMapValue(
	path string,
	expectedID uint32,
	key any,
	value any,
) (returnErr error) {
	if expectedID == 0 {
		return errors.New("writable pinned-map reopen requires a non-zero map ID")
	}
	writable, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return fmt.Errorf("reopen pinned map read-write: %w", err)
	}
	defer func() {
		returnErr = errors.Join(returnErr, writable.Close())
	}()
	info, err := writable.Info()
	if err != nil {
		return fmt.Errorf("inspect writable pinned map: %w", err)
	}
	mapID, ok := info.ID()
	if !ok || mapID == 0 || uint32(mapID) != expectedID {
		return fmt.Errorf(
			"writable pinned map ID = %d (reported=%t), want %d",
			mapID,
			ok,
			expectedID,
		)
	}
	if err := writable.Update(key, value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update writable pinned map ID %d: %w", expectedID, err)
	}
	return nil
}

func (observation *pinnedMapObservation) Close() error {
	if observation == nil || observation.close == nil {
		return nil
	}
	closeMap := observation.close
	observation.close = nil
	return closeMap()
}

func validatePinnedMapObservation(
	descriptor pinnedMapDescriptor,
	observation *pinnedMapObservation,
	requireCommittedControl bool,
) error {
	if observation == nil {
		return fmt.Errorf("pinned map %q observation is nil", descriptor.name)
	}
	if observation.id == 0 {
		return fmt.Errorf("pinned map %q has no stable map ID", descriptor.name)
	}
	if observation.mapType != descriptor.mapType ||
		observation.keySize != descriptor.keySize ||
		observation.valueSize != descriptor.valueSize ||
		observation.maxEntries != descriptor.maxEntries ||
		observation.flags != descriptor.flags {
		return fmt.Errorf(
			"pinned map %q schema is %s key=%d value=%d max=%d flags=%#x, want %s key=%d value=%d max=%d flags=%#x",
			descriptor.name,
			observation.mapType, observation.keySize, observation.valueSize,
			observation.maxEntries, observation.flags,
			descriptor.mapType, descriptor.keySize, descriptor.valueSize,
			descriptor.maxEntries, descriptor.flags,
		)
	}
	if observation.mapExtra != 0 {
		return fmt.Errorf("pinned map %q has unsupported map_extra=%d", descriptor.name, observation.mapExtra)
	}
	if observation.frozen {
		return fmt.Errorf("pinned map %q is frozen", descriptor.name)
	}
	expectedName := descriptor.name
	if len(expectedName) > 15 {
		expectedName = expectedName[:15]
	}
	if observation.kernelName != expectedName {
		return fmt.Errorf(
			"pinned map %q reports kernel name %q, want %q",
			descriptor.name, observation.kernelName, expectedName,
		)
	}
	if descriptor.name != "control_map" {
		if descriptor.name == "owner_map" && !observation.ownerSeen {
			return errors.New("pinned owner_map sentinel value is unavailable")
		}
		return nil
	}
	if !observation.controlSeen {
		return errors.New("pinned control_map identity value is unavailable")
	}
	control := observation.control
	if !requireCommittedControl && control == (abi.ControlValue{}) {
		return nil
	}
	if control.ABIVersion != abi.Version {
		return fmt.Errorf(
			"pinned control_map ABI version = %d, want %d",
			control.ABIVersion, abi.Version,
		)
	}
	if control.Flags != 0 {
		return fmt.Errorf("pinned control_map flags = %#x, want 0", control.Flags)
	}
	if requireCommittedControl && control.ActiveGeneration == 0 {
		return errors.New("pinned control_map has no committed generation")
	}
	return nil
}

func populateXORTailCalls(coll *ebpf.Collection, generation uint64) error {
	bankStart := xorTailCallBankStart(generation)
	for _, binding := range xorTailCallBindings {
		m := coll.Maps[binding.mapName]
		if m == nil {
			return fmt.Errorf("BPF object missing map %q", binding.mapName)
		}
		for segment, programName := range binding.programNames {
			program := coll.Programs[programName]
			if program == nil {
				return fmt.Errorf("BPF object missing program %q", programName)
			}
			index := bankStart + uint32(segment)
			fd := uint32(program.FD())
			if err := m.Update(index, fd, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("populate %s[%d] with %s: %w",
					binding.mapName, index, programName, err)
			}
		}
	}
	return nil
}

func xorTailCallBankStart(generation uint64) uint32 {
	return uint32(generation&1) * xorSegmentCount
}

func activeGeneration(coll *ebpf.Collection) (uint64, error) {
	m := coll.Maps["control_map"]
	if m == nil {
		return 0, fmt.Errorf("BPF object missing map %q", "control_map")
	}
	var value abi.ControlValue
	if err := m.Lookup(abi.ControlKeyGlobal, &value); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return 0, nil
		}
		return 0, fmt.Errorf("lookup active generation: %w", err)
	}
	if value.ABIVersion != 0 && value.ABIVersion != abi.Version {
		return 0, fmt.Errorf("pinned control_map ABI version = %d, want %d", value.ABIVersion, abi.Version)
	}
	return value.ActiveGeneration, nil
}

func populateDataMaps(coll *ebpf.Collection, snapshot *abi.Snapshot) error {
	if err := updateMap(coll, "profile_map", snapshot.Profiles); err != nil {
		return err
	}
	if err := updateMap(coll, "cipher_map", snapshot.Ciphers); err != nil {
		return err
	}
	if err := updateMap(coll, "underlay_config_map", snapshot.Underlays); err != nil {
		return err
	}
	if err := updateMap(coll, "managed_fwmark_map", snapshot.ManagedFwmarks); err != nil {
		return err
	}
	if err := updateMap(coll, "egress_rule_map", snapshot.EgressRules); err != nil {
		return err
	}
	if err := updateMap(coll, "ingress_listener_map", snapshot.IngressListeners); err != nil {
		return err
	}
	if err := updateMap(coll, "icmp_listener_map", snapshot.ICMPListeners); err != nil {
		return err
	}
	return nil
}

func commitControl(coll *ebpf.Collection, value abi.ControlValue) error {
	m := coll.Maps["control_map"]
	if m == nil {
		return fmt.Errorf("BPF object missing map %q", "control_map")
	}
	if err := m.Update(abi.ControlKeyGlobal, value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("commit control map: %w", err)
	}
	return nil
}

func updateMap[K comparable, V any](coll *ebpf.Collection, name string, entries map[K]V) error {
	m := coll.Maps[name]
	if m == nil {
		return fmt.Errorf("BPF object missing map %q", name)
	}
	for key, value := range entries {
		if err := m.Update(key, value, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update map %s: %w", name, err)
		}
	}
	return nil
}

func deleteStaleMapEntries(coll *ebpf.Collection, snapshot *abi.Snapshot) error {
	return errors.Join(
		deleteStaleEntries(coll, "profile_map", snapshot.Profiles),
		deleteStaleEntries(coll, "cipher_map", snapshot.Ciphers),
		deleteStaleEntries(coll, "underlay_config_map", snapshot.Underlays),
		deleteStaleEntries(coll, "managed_fwmark_map", snapshot.ManagedFwmarks),
		deleteStaleEntries(coll, "egress_rule_map", snapshot.EgressRules),
		deleteStaleEntries(coll, "ingress_listener_map", snapshot.IngressListeners),
		deleteStaleEntries(coll, "icmp_listener_map", snapshot.ICMPListeners),
	)
}

func deleteGenerationMapEntries(coll *ebpf.Collection, generation uint64) error {
	return errors.Join(
		deleteEntriesByGeneration[abi.ProfileKey, abi.ProfileValue](coll, "profile_map", generation),
		deleteEntriesByGeneration[abi.CipherKey, abi.CipherValue](coll, "cipher_map", generation),
		deleteEntriesByGeneration[abi.UnderlayConfigKey, abi.UnderlayConfigValue](coll, "underlay_config_map", generation),
		deleteEntriesByGeneration[abi.ManagedFwmarkKey, abi.ManagedFwmarkValue](coll, "managed_fwmark_map", generation),
		deleteEntriesByGeneration[abi.EgressRuleKey, abi.EgressRuleValue](coll, "egress_rule_map", generation),
		deleteEntriesByGeneration[abi.IngressListenerKey, abi.IngressListenerValue](coll, "ingress_listener_map", generation),
		deleteEntriesByGeneration[abi.ICMPListenerKey, abi.ICMPListenerValue](coll, "icmp_listener_map", generation),
	)
}

func deleteEntriesByGeneration[K comparable, V interface{ MapGeneration() uint64 }](coll *ebpf.Collection, name string, generation uint64) error {
	m := coll.Maps[name]
	if m == nil {
		return fmt.Errorf("BPF object missing map %q", name)
	}
	var (
		key   K
		value V
		errs  []error
	)
	iter := m.Iterate()
	for iter.Next(&key, &value) {
		if value.MapGeneration() != generation {
			continue
		}
		if err := m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("delete generation %d entry from %s: %w", generation, name, err))
		}
	}
	if err := iter.Err(); err != nil {
		errs = append(errs, fmt.Errorf("iterate map %s: %w", name, err))
	}
	return errors.Join(errs...)
}

func deleteStaleEntries[K comparable, V any](coll *ebpf.Collection, name string, desired map[K]V) error {
	m := coll.Maps[name]
	if m == nil {
		return fmt.Errorf("BPF object missing map %q", name)
	}
	var (
		key   K
		value V
		errs  []error
	)
	iter := m.Iterate()
	for iter.Next(&key, &value) {
		if _, ok := desired[key]; ok {
			continue
		}
		if err := m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("delete stale entry from %s: %w", name, err))
		}
	}
	if err := iter.Err(); err != nil {
		errs = append(errs, fmt.Errorf("iterate map %s: %w", name, err))
	}
	return errors.Join(errs...)
}

func preparePinnedMapCleanup(pinPath string, runtime pinPathRuntime) (*pinnedMapCleanupPlan, error) {
	validated, err := validatePinPath(pinPath, runtime.validator)
	if err != nil {
		return nil, err
	}
	if !validated.exists {
		return &pinnedMapCleanupPlan{}, nil
	}
	handle, _, err := openPinPathHandle(pinPath, validated, false, runtime)
	if err != nil {
		return nil, err
	}
	return preparePinnedMapCleanupHandle(handle)
}

func preparePinnedMapCleanupHandle(
	handle *pinPathHandle,
) (*pinnedMapCleanupPlan, error) {
	if handle == nil {
		return &pinnedMapCleanupPlan{}, nil
	}
	pins, err := inspectPinnedMapSet(handle, true)
	if err != nil {
		_ = handle.Close()
		return nil, err
	}
	return &pinnedMapCleanupPlan{
		handle: handle,
		pins:   pins,
	}, nil
}

func rollbackFreshPinnedMaps(handle *pinPathHandle, removeEmptyDirectory bool) error {
	pins, err := inspectFreshUncommittedPins(handle)
	if err != nil {
		return err
	}
	defer closePinnedMapPins(pins)
	plan := &pinnedMapCleanupPlan{
		handle: handle,
		pins:   pins,
	}
	return plan.execute(false, true, removeEmptyDirectory)
}

func inspectPinnedMapSet(
	handle *pinPathHandle,
	requireCommittedControl bool,
) ([]pinnedMapPin, error) {
	return inspectPinnedMapSetWithPolicy(handle, true, requireCommittedControl, false)
}

func inspectFreshUncommittedPins(handle *pinPathHandle) ([]pinnedMapPin, error) {
	return inspectPinnedMapSetWithPolicy(handle, false, false, true)
}

func inspectPinnedMapSetWithPolicy(
	handle *pinPathHandle,
	requireComplete bool,
	requireCommittedControl bool,
	requireZeroControl bool,
) ([]pinnedMapPin, error) {
	if handle == nil {
		return nil, nil
	}
	if handle.runtime.loadPinnedMap == nil {
		return nil, errors.New("pinned-map loader is unavailable")
	}
	if err := handle.recheckTargetEntry(); err != nil {
		return nil, err
	}

	descriptors := pinnedMapDescriptors()
	pins := make([]pinnedMapPin, 0, len(descriptors))
	for _, descriptor := range descriptors {
		var stat unix.Stat_t
		err := unix.Fstatat(
			handle.targetFD,
			descriptor.name,
			&stat,
			unix.AT_SYMLINK_NOFOLLOW,
		)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("inspect pinned map %s/%s: %w", handle.pinPath, descriptor.name, err)
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFREG {
			return nil, fmt.Errorf(
				"refuse pinned object %s/%s: mode %#o is not a regular map pin",
				handle.pinPath, descriptor.name, stat.Mode,
			)
		}
		if stat.Mode&0o7777 != 0o600 ||
			stat.Uid != handle.runtime.expectedUID ||
			stat.Nlink != 1 {
			return nil, fmt.Errorf(
				"refuse unsafe pinned object %s/%s: mode=%#o uid=%d links=%d; want 0600 uid=%d links=1",
				handle.pinPath, descriptor.name,
				stat.Mode, stat.Uid, stat.Nlink, handle.runtime.expectedUID,
			)
		}
		mountID, err := handle.runtime.mountIDAt(
			handle.targetFD,
			descriptor.name,
			unix.AT_NO_AUTOMOUNT|unix.AT_SYMLINK_NOFOLLOW,
		)
		if err != nil {
			return nil, fmt.Errorf("inspect pinned map mount %s/%s: %w", handle.pinPath, descriptor.name, err)
		}
		if mountID != handle.mountID {
			return nil, fmt.Errorf(
				"refuse pinned object %s/%s: mount ID %d differs from validated bpffs mount ID %d",
				handle.pinPath, descriptor.name, mountID, handle.mountID,
			)
		}
		pins = append(pins, pinnedMapPin{
			descriptor: descriptor,
			inode:      pinPathInodeFromStat(&stat),
		})
	}
	if len(pins) == 0 {
		return nil, nil
	}
	if requireComplete && len(pins) != len(descriptors) {
		return nil, fmt.Errorf(
			"found an incomplete pinned-map set (%d of %d known pins); refusing any deletion",
			len(pins), len(descriptors),
		)
	}

	seenIDs := make(map[uint32]string, len(pins))
	closeOnError := func() {
		_ = closePinnedMapPins(pins)
	}
	for index := range pins {
		pin := &pins[index]
		path := filepath.Join(handle.procPath(), pin.descriptor.name)
		observation, err := handle.runtime.loadPinnedMap(path, pin.descriptor.name)
		if err != nil {
			closeOnError()
			return nil, fmt.Errorf("load pinned map %s/%s: %w", handle.pinPath, pin.descriptor.name, err)
		}
		pin.observation = observation
		if err := validatePinnedMapObservation(
			pin.descriptor,
			observation,
			requireCommittedControl,
		); err != nil {
			closeOnError()
			return nil, err
		}
		if requireZeroControl && pin.descriptor.name == "control_map" &&
			observation.control != (abi.ControlValue{}) {
			closeOnError()
			return nil, fmt.Errorf(
				"freshly created control_map is already initialized; refusing rollback",
			)
		}
		if previous, ok := seenIDs[observation.id]; ok {
			closeOnError()
			return nil, fmt.Errorf(
				"pinned maps %q and %q unexpectedly share map ID %d",
				previous, pin.descriptor.name, observation.id,
			)
		}
		seenIDs[observation.id] = pin.descriptor.name
	}
	for _, pin := range pins {
		if err := recheckPinnedMapEntry(handle, pin, "map identity preflight"); err != nil {
			closeOnError()
			return nil, err
		}
	}
	if err := handle.recheckTargetEntry(); err != nil {
		closeOnError()
		return nil, err
	}
	return pins, nil
}

func recheckPinnedMapEntry(
	handle *pinPathHandle,
	pin pinnedMapPin,
	stage string,
) error {
	var stat unix.Stat_t
	if err := unix.Fstatat(
		handle.targetFD,
		pin.descriptor.name,
		&stat,
		unix.AT_SYMLINK_NOFOLLOW,
	); err != nil {
		return fmt.Errorf(
			"%s for %s/%s: %w",
			stage, handle.pinPath, pin.descriptor.name, err,
		)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Mode&0o7777 != 0o600 ||
		stat.Uid != handle.runtime.expectedUID ||
		stat.Nlink != 1 ||
		!samePinPathInode(pinPathInodeFromStat(&stat), pin.inode) {
		return fmt.Errorf(
			"%s for %s/%s: pin changed (mode=%#o links=%d)",
			stage, handle.pinPath, pin.descriptor.name, stat.Mode, stat.Nlink,
		)
	}
	mountID, err := handle.runtime.mountIDAt(
		handle.targetFD,
		pin.descriptor.name,
		unix.AT_NO_AUTOMOUNT|unix.AT_SYMLINK_NOFOLLOW,
	)
	if err != nil {
		return fmt.Errorf(
			"%s mount for %s/%s: %w",
			stage, handle.pinPath, pin.descriptor.name, err,
		)
	}
	if mountID != handle.mountID {
		return fmt.Errorf(
			"%s for %s/%s: mount ID changed from %d to %d",
			stage, handle.pinPath, pin.descriptor.name, handle.mountID, mountID,
		)
	}
	return nil
}

func closePinnedMapPins(pins []pinnedMapPin) error {
	var errs []error
	for index := range pins {
		if err := pins[index].observation.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close pinned map %s: %w", pins[index].descriptor.name, err))
		}
	}
	return errors.Join(errs...)
}

func validateCollectionPinnedMaps(
	handle *pinPathHandle,
	collection *ebpf.Collection,
	requireCommittedControl bool,
) error {
	return validateCollectionPinnedMapsWithPolicy(
		handle,
		collection,
		requireCommittedControl,
		false,
	)
}

func validateFreshCollectionPinnedMaps(
	handle *pinPathHandle,
	collection *ebpf.Collection,
) error {
	return validateCollectionPinnedMapsWithPolicy(handle, collection, false, true)
}

func validateCollectionPinnedMapsWithPolicy(
	handle *pinPathHandle,
	collection *ebpf.Collection,
	requireCommittedControl bool,
	requireZeroControl bool,
) error {
	pins, err := inspectPinnedMapSetWithPolicy(
		handle,
		true,
		requireCommittedControl,
		requireZeroControl,
	)
	if err != nil {
		return err
	}
	defer closePinnedMapPins(pins)
	if len(pins) != len(pinnedMapDescriptors()) {
		return fmt.Errorf(
			"collection pin directory contains %d known maps, want %d",
			len(pins), len(pinnedMapDescriptors()),
		)
	}
	return validateCollectionMapIDs(collection, pins)
}

func validateCollectionMapIDs(collection *ebpf.Collection, pins []pinnedMapPin) error {
	if collection == nil {
		return errors.New("BPF collection is nil")
	}
	for _, pin := range pins {
		collectionMap := collection.Maps[pin.descriptor.name]
		if collectionMap == nil {
			return fmt.Errorf("BPF collection missing map %q", pin.descriptor.name)
		}
		info, err := collectionMap.Info()
		if err != nil {
			return fmt.Errorf("inspect collection map %q: %w", pin.descriptor.name, err)
		}
		mapID, ok := info.ID()
		if !ok || mapID == 0 {
			return fmt.Errorf("collection map %q has no stable map ID", pin.descriptor.name)
		}
		if uint32(mapID) != pin.observation.id {
			return fmt.Errorf(
				"collection map %q has ID %d, pinned path has ID %d",
				pin.descriptor.name, mapID, pin.observation.id,
			)
		}
	}
	return nil
}

func (plan *pinnedMapCleanupPlan) Execute() error {
	return plan.execute(true, false, true)
}

func (plan *pinnedMapCleanupPlan) execute(
	requireCommittedControl bool,
	requireZeroControl bool,
	removeEmptyDirectory bool,
) error {
	if plan == nil || plan.handle == nil {
		return nil
	}
	handle := plan.handle
	if err := handle.recheckTargetEntry(); err != nil {
		return err
	}

	reopened := make([]pinnedMapPin, 0, len(plan.pins))
	closeReopened := func() {
		_ = closePinnedMapPins(reopened)
	}
	for _, original := range plan.pins {
		var stat unix.Stat_t
		if err := unix.Fstatat(
			handle.targetFD,
			original.descriptor.name,
			&stat,
			unix.AT_SYMLINK_NOFOLLOW,
		); err != nil {
			closeReopened()
			return fmt.Errorf(
				"recheck pinned map %s/%s before cleanup: %w",
				handle.pinPath, original.descriptor.name, err,
			)
		}
		if !samePinPathInode(pinPathInodeFromStat(&stat), original.inode) {
			closeReopened()
			return fmt.Errorf(
				"pinned map %s/%s changed after cleanup preflight",
				handle.pinPath, original.descriptor.name,
			)
		}
		mountID, err := handle.runtime.mountIDAt(
			handle.targetFD,
			original.descriptor.name,
			unix.AT_NO_AUTOMOUNT|unix.AT_SYMLINK_NOFOLLOW,
		)
		if err != nil {
			closeReopened()
			return fmt.Errorf(
				"recheck pinned map mount %s/%s: %w",
				handle.pinPath, original.descriptor.name, err,
			)
		}
		if mountID != handle.mountID {
			closeReopened()
			return fmt.Errorf(
				"pinned map %s/%s changed mount identity after cleanup preflight",
				handle.pinPath, original.descriptor.name,
			)
		}

		path := filepath.Join(handle.procPath(), original.descriptor.name)
		observation, err := handle.runtime.loadPinnedMap(path, original.descriptor.name)
		if err != nil {
			closeReopened()
			return fmt.Errorf(
				"reload pinned map %s/%s before cleanup: %w",
				handle.pinPath, original.descriptor.name, err,
			)
		}
		current := pinnedMapPin{
			descriptor:  original.descriptor,
			inode:       pinPathInodeFromStat(&stat),
			observation: observation,
		}
		reopened = append(reopened, current)
		if err := validatePinnedMapObservation(
			original.descriptor,
			observation,
			requireCommittedControl,
		); err != nil {
			closeReopened()
			return err
		}
		if requireZeroControl && original.descriptor.name == "control_map" &&
			observation.control != (abi.ControlValue{}) {
			closeReopened()
			return errors.New("freshly created control_map changed before rollback")
		}
		if observation.id != original.observation.id {
			closeReopened()
			return fmt.Errorf(
				"pinned map %s/%s changed ID from %d to %d after cleanup preflight",
				handle.pinPath, original.descriptor.name,
				original.observation.id, observation.id,
			)
		}
		if original.descriptor.name == "control_map" &&
			observation.control != original.observation.control {
			closeReopened()
			return fmt.Errorf("pinned control_map identity changed after cleanup preflight")
		}
	}
	for _, pin := range reopened {
		if err := recheckPinnedMapEntry(handle, pin, "final map cleanup preflight"); err != nil {
			closeReopened()
			return err
		}
	}
	if err := handle.recheckTargetEntry(); err != nil {
		closeReopened()
		return err
	}

	for _, pin := range reopened {
		if err := unix.Unlinkat(handle.targetFD, pin.descriptor.name, 0); err != nil {
			closeReopened()
			return fmt.Errorf(
				"remove pinned map %s/%s: %w",
				handle.pinPath, pin.descriptor.name, err,
			)
		}
	}
	closeReopened()

	if !removeEmptyDirectory {
		return nil
	}
	empty, err := pinDirectoryIsEmpty(handle.targetFD, handle.pinPath)
	if err != nil {
		return err
	}
	if !empty {
		return nil
	}
	if err := handle.recheckTargetEntry(); err != nil {
		return err
	}
	if err := unix.Unlinkat(handle.parentFD, handle.base, unix.AT_REMOVEDIR); err != nil {
		if errors.Is(err, unix.ENOTEMPTY) {
			return nil
		}
		return fmt.Errorf("remove empty BPF pin path %s: %w", handle.pinPath, err)
	}
	return nil
}

func pinDirectoryIsEmpty(targetFD int, pinPath string) (bool, error) {
	directoryFD, err := unix.Openat(
		targetFD,
		".",
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return false, fmt.Errorf("open BPF pin path %s for listing: %w", pinPath, err)
	}
	directory := os.NewFile(uintptr(directoryFD), pinPath)
	entries, readErr := directory.ReadDir(1)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return false, fmt.Errorf("inspect BPF pin path %s before removal: %w", pinPath, readErr)
	}
	if closeErr != nil {
		return false, fmt.Errorf("close BPF pin path listing %s: %w", pinPath, closeErr)
	}
	return len(entries) == 0, nil
}

func (plan *pinnedMapCleanupPlan) Close() error {
	if plan == nil {
		return nil
	}
	pinErr := closePinnedMapPins(plan.pins)
	plan.pins = nil
	handleErr := plan.handle.Close()
	plan.handle = nil
	return errors.Join(pinErr, handleErr)
}
