//go:build linux

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/cilium/ebpf"
	"github.com/syx0310/wg-mix-ebpf/internal/abi"
	"github.com/syx0310/wg-mix-ebpf/internal/control"
)

func (l LinuxLoader) applyClassicTC(ctx context.Context, state *control.State) (returnErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := preflightFakeTCPKernelRequirements(state); err != nil {
		return err
	}
	runtime := l.pinRuntime(ctx)
	if err := validateTCRuntime(runtime.classicTC); err != nil {
		return err
	}
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
	if ownerExists && ownerRecord.Version != pinOwnerLegacyClassicVersion {
		return fmt.Errorf(
			"configured classic_tc backend found owner schema %d; detach the existing backend before switching",
			ownerRecord.Version,
		)
	}
	if ownerExists && ownerRecord.BootID == bootID {
		rollbackFreshPins = false
		recovered, err := recoverPinOwnerTransaction(
			handle,
			store,
			ownerRecord,
			runtime.classicTC,
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
				"prior-boot owner can only be archived with an empty or exact owned canonical pin set",
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
						"indexed prior-boot owner can only be archived with an empty or exact owned canonical pin set",
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
		ownerRecord, err = rekeyRebootedClassicPinOwner(
			handle,
			parent,
			store,
			rebootSource,
			bootID,
			rekeyNow,
			runtime.classicTC,
		)
		if err != nil {
			return fmt.Errorf("rekey rebooted BPF owner: %w", err)
		}
		ownerExists = true
		rollbackFreshPins = false
	}
	legacyAdoption := false
	if ownerExists {
		if directoryState != canonicalPinsOwned {
			return fmt.Errorf("active BPF owner record does not have its exact %d-map canonical set", len(pinnedMapDescriptors()))
		}
	} else {
		switch directoryState {
		case canonicalPinsEmpty:
		case canonicalPinsLegacy:
			if !l.AdoptLegacyPins {
				return errors.New(
					"found legacy BPF pins without owner_map; refusing implicit adoption (run reload --adopt-legacy-pins explicitly)",
				)
			}
			legacyAdoption = true
		case canonicalPinsOwned:
			if !l.AdoptLegacyPins {
				return errors.New(
					"found owner_map pins without their root-owned persistent owner record; refusing name-only ownership",
				)
			}
			// An explicitly requested adoption also recovers the narrow crash
			// window after owner_map was added but before its first descriptor
			// publish. Schema/control/TC identity are still fully preflighted.
			legacyAdoption = true
		case canonicalPinsOwnedTCX:
			return errors.New("configured classic_tc backend found pinned TCX links; detach the existing backend before switching")
		}
	}
	freshPins := !ownerExists && directoryState == canonicalPinsEmpty

	var preexistingPins []pinnedMapPin
	if ownerExists || legacyAdoption {
		preexistingPins, err = inspectPinnedMapSetWithPolicy(
			handle,
			!legacyAdoption || directoryState == canonicalPinsOwned,
			true,
			false,
		)
		if err != nil {
			return fmt.Errorf("preflight existing pinned maps under %s: %w", pinPath, err)
		}
		defer closePinnedMapPins(preexistingPins)
		if ownerExists {
			if err := validateOwnerPins(
				handle,
				ownerRecord,
				preexistingPins,
				true,
			); err != nil {
				return err
			}
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
	if ownerExists || legacyAdoption {
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
	ingressIdentity, err := tcProgramIdentityFromProgram(ingress)
	if err != nil {
		return fmt.Errorf("inspect ingress TC program: %w", err)
	}
	egressIdentity, err := tcProgramIdentityFromProgram(egress)
	if err != nil {
		return fmt.Errorf("inspect egress TC program: %w", err)
	}
	attachPlan, err := prepareTCAttachPlan(
		state,
		ingressIdentity,
		egressIdentity,
		runtime.classicTC,
	)
	if err != nil {
		return fmt.Errorf("preflight TC attachment transaction: %w", err)
	}
	defer attachPlan.Close()
	activeFilters := []tcFilterBinding{}
	var token [32]byte
	var ownerMaps []pinOwnerMapIdentity
	if freshPins || legacyAdoption {
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
		if legacyAdoption {
			activeFilters = attachPlan.ObservedBindings()
		}
	} else {
		token, err = tokenFromOwnerRecord(ownerRecord)
		if err != nil {
			return err
		}
		ownerMaps = slices.Clone(ownerRecord.Maps)
		activeFilters = slices.Clone(ownerRecord.ActiveFilters)
	}
	if err := attachPlan.ValidatePreviousBindings(
		activeFilters,
		freshPins,
	); err != nil {
		return err
	}
	if err := attachPlan.AddOwnedStaleRemovals(activeFilters); err != nil {
		return err
	}
	desiredFilters := attachPlan.Bindings()
	now, err := ownerRuntimeNow(runtime)
	if err != nil {
		return err
	}
	applying, err := newClassicApplyingPinOwnerRecord(
		parent,
		token,
		bootID,
		now,
		active,
		next,
		ownerMaps,
		activeFilters,
		desiredFilters,
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
	if err := attachPlan.Execute(func() error {
		return commitControl(coll, snapshot.Control[abi.ControlKeyGlobal])
	}); err != nil {
		abortErr := abortFailedOwnerApply(
			handle,
			store,
			mutating,
			runtime.classicTC,
		)
		if abortErr != nil {
			return errors.Join(
				err,
				fmt.Errorf("owner-aware apply rollback: %w", abortErr),
			)
		}
		return err
	}
	cleanup := advancePinOwnerRecord(
		mutating,
		now,
		pinOwnerPhaseApplying,
		pinOwnerStepCleanup,
	)
	observeOwnerMount(cleanup, handle.mountID)
	if err := store.Persist(cleanup, mutating, handle.mountID); err != nil {
		return err
	}
	recovered, err := recoverApplyingPinOwnerTransaction(
		handle,
		store,
		cleanup,
		now,
		runtime.classicTC,
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
