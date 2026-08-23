//go:build linux

package dataplane

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/syx0310/wg-mix-ebpf/internal/pinidentity"
)

const classicOwnerTestBootID = "12345678-1234-1234-1234-123456789abc"

func classicOwnerTestBindings(ifindex int, ingressID, egressID uint32) []tcFilterBinding {
	slots := canonicalTCFilterSlots()
	return []tcFilterBinding{
		{
			IfIndex: ifindex, Direction: "ingress", Parent: slots[0].parent,
			Handle: slots[0].handle, Priority: filterPriority, ProgramID: ingressID,
		},
		{
			IfIndex: ifindex, Direction: "egress", Parent: slots[1].parent,
			Handle: slots[1].handle, Priority: filterPriority, ProgramID: egressID,
		},
	}
}

func setClassicOwnerTestBindings(
	t *testing.T,
	kernel *fakeTCKernel,
	bindings []tcFilterBinding,
) {
	t.Helper()
	for _, binding := range bindings {
		slot, err := ownerFilterSlot(binding)
		if err != nil {
			t.Fatal(err)
		}
		key := fakeTCFilterKey{ifindex: binding.IfIndex, parent: slot.parent}
		kernel.filters[key] = nil
		kernel.addManagedFilter(binding.IfIndex, slot, binding.ProgramID)
	}
}

func installClassicOwnerTestRuntime(
	t *testing.T,
	fixture *exactTCXOwnerTestFixture,
	kernel *fakeTCKernel,
) {
	t.Helper()
	for id, fd := range map[uint32]int{501: 1501, 502: 1502, 601: 1601, 602: 1602} {
		kernel.addProgram(id, fd)
	}
	pinProgram := func(id uint32, path string) error {
		if _, exists := kernel.programFDs[id]; !exists {
			return fmt.Errorf("unknown fake program ID %d", id)
		}
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		if _, err := file.WriteString(strconv.FormatUint(uint64(id), 10) + "\n"); err != nil {
			_ = file.Close()
			return err
		}
		return file.Close()
	}
	loadProgram := func(path string) (*pinnedProgramObservation, error) {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		parsed, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 32)
		if err != nil {
			return nil, err
		}
		id := uint32(parsed)
		fd, exists := kernel.programFDs[id]
		if !exists {
			return nil, fmt.Errorf("fake program ID %d has no FD", id)
		}
		return &pinnedProgramObservation{
			fd: fd, id: id, close: func() error { return nil },
		}, nil
	}
	unexpectedTCX := exactTCXRuntime{
		query: func(int, ebpf.AttachType) (exactTCXQuery, error) {
			t.Fatal("classic owner path queried TCX")
			return exactTCXQuery{}, errors.New("unexpected TCX query")
		},
		attach: func(int, ebpf.AttachType, uint64, exactTCXProgram) (exactTCXKernelLink, error) {
			t.Fatal("classic owner path attached TCX")
			return nil, errors.New("unexpected TCX attach")
		},
		loadPinned: func(string) (exactTCXKernelLink, error) {
			t.Fatal("classic owner path loaded a TCX link")
			return nil, errors.New("unexpected TCX link load")
		},
	}
	fixture.runtime.bootID = func() (string, error) { return classicOwnerTestBootID, nil }
	fixture.runtime.pinProgram = pinProgram
	fixture.runtime.loadPinnedProgram = loadProgram
	fixture.runtime.classicTC = kernel.runtime()
	fixture.runtime.exactTCX = unexpectedTCX
	fixture.handle.runtime = fixture.runtime
	fixture.parent.runtime = fixture.runtime
}

func persistClassicOwnerTestActive(
	t *testing.T,
	fixture *exactTCXOwnerTestFixture,
	bindings []tcFilterBinding,
) *pinOwnerRecord {
	t.Helper()
	record, err := newClassicActivePinOwnerRecord(
		fixture.parent,
		fixture.token,
		classicOwnerTestBootID,
		fixture.now,
		7,
		fixture.maps,
		bindings,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.Persist(record, nil, fixture.handle.mountID); err != nil {
		t.Fatal(err)
	}
	return record
}

func TestClassicOwnerApplyRecoveryConvergesEveryCrashStep(t *testing.T) {
	for _, step := range []string{
		pinOwnerStepStaging,
		pinOwnerStepMutating,
		pinOwnerStepCleanup,
	} {
		t.Run(step, func(t *testing.T) {
			fixture := newExactTCXOwnerTestFixture(t)
			kernel := newFakeTCKernel(21)
			installClassicOwnerTestRuntime(t, fixture, kernel)
			kernel.addClsact(21)
			activeBindings := classicOwnerTestBindings(21, 501, 502)
			desiredBindings := classicOwnerTestBindings(21, 601, 602)
			setClassicOwnerTestBindings(t, kernel, activeBindings)
			active := persistClassicOwnerTestActive(t, fixture, activeBindings)

			applying, err := newClassicApplyingPinOwnerRecord(
				fixture.parent,
				fixture.token,
				classicOwnerTestBootID,
				fixture.now.Add(time.Second),
				7,
				8,
				fixture.maps,
				activeBindings,
				desiredBindings,
				active,
			)
			if err != nil {
				t.Fatal(err)
			}
			if err := fixture.store.Persist(applying, active, fixture.handle.mountID); err != nil {
				t.Fatal(err)
			}
			crashed := applying
			if step != pinOwnerStepStaging {
				if err := stageOwnerPrograms(fixture.handle, applying); err != nil {
					t.Fatal(err)
				}
				mutating := advancePinOwnerRecord(
					applying,
					fixture.now.Add(2*time.Second),
					pinOwnerPhaseApplying,
					pinOwnerStepMutating,
				)
				if err := fixture.store.Persist(mutating, applying, fixture.handle.mountID); err != nil {
					t.Fatal(err)
				}
				crashed = mutating
				if step == pinOwnerStepCleanup {
					setClassicOwnerTestBindings(t, kernel, desiredBindings)
					control := fixture.mapStore.observations["control_map"]
					control.control.ActiveGeneration = 8
					fixture.mapStore.observations["control_map"] = control
					cleanup := advancePinOwnerRecord(
						mutating,
						fixture.now.Add(3*time.Second),
						pinOwnerPhaseApplying,
						pinOwnerStepCleanup,
					)
					if err := fixture.store.Persist(cleanup, mutating, fixture.handle.mountID); err != nil {
						t.Fatal(err)
					}
					crashed = cleanup
				}
			}

			recovered, err := recoverPinOwnerTransaction(
				fixture.handle,
				fixture.store,
				crashed,
				kernel.runtime(),
			)
			if err != nil {
				t.Fatal(err)
			}
			wantGeneration := uint64(8)
			wantBindings := desiredBindings
			if step == pinOwnerStepStaging {
				wantGeneration = 7
				wantBindings = activeBindings
			}
			if recovered.directoryRemoved || recovered.record == nil ||
				recovered.record.Phase != pinOwnerPhaseActive ||
				recovered.record.ActiveGeneration != wantGeneration {
				t.Fatalf("recovered applying owner = %#v", recovered)
			}
			for _, binding := range wantBindings {
				slot, err := ownerFilterSlot(binding)
				if err != nil {
					t.Fatal(err)
				}
				if got := kernel.managedProgramID(t, binding.IfIndex, slot); got != binding.ProgramID {
					t.Fatalf("recovered %s program = %d, want %d", binding.Direction, got, binding.ProgramID)
				}
			}
		})
	}
}

func TestClassicOwnerDetachRecoveryHandlesEveryCrashStep(t *testing.T) {
	for _, step := range []string{
		pinOwnerStepStaging,
		pinOwnerStepMutatingTC,
		pinOwnerStepUnlinkingMaps,
		pinOwnerStepCleanupStages,
	} {
		t.Run(step, func(t *testing.T) {
			fixture := newExactTCXOwnerTestFixture(t)
			kernel := newFakeTCKernel(21)
			installClassicOwnerTestRuntime(t, fixture, kernel)
			kernel.addClsact(21)
			activeBindings := classicOwnerTestBindings(21, 501, 502)
			setClassicOwnerTestBindings(t, kernel, activeBindings)
			active := persistClassicOwnerTestActive(t, fixture, activeBindings)
			detaching, err := newDetachingPinOwnerRecord(
				active,
				fixture.now.Add(time.Second),
			)
			if err != nil {
				t.Fatal(err)
			}
			if err := fixture.store.Persist(detaching, active, fixture.handle.mountID); err != nil {
				t.Fatal(err)
			}
			crashed := detaching
			if step != pinOwnerStepStaging {
				pins, err := inspectPinnedMapSet(fixture.handle, true)
				if err != nil {
					t.Fatal(err)
				}
				if err := stageOwnerPrograms(fixture.handle, detaching); err != nil {
					t.Fatal(err)
				}
				if err := stageOwnerMaps(fixture.handle, detaching, pins); err != nil {
					_ = closePinnedMapPins(pins)
					t.Fatal(err)
				}
				if err := closePinnedMapPins(pins); err != nil {
					t.Fatal(err)
				}
				mutating := advancePinOwnerRecord(
					detaching,
					fixture.now.Add(2*time.Second),
					pinOwnerPhaseDetaching,
					pinOwnerStepMutatingTC,
				)
				if err := fixture.store.Persist(mutating, detaching, fixture.handle.mountID); err != nil {
					t.Fatal(err)
				}
				crashed = mutating
				if step == pinOwnerStepMutatingTC {
					slot, err := ownerFilterSlot(activeBindings[0])
					if err != nil {
						t.Fatal(err)
					}
					kernel.filters[fakeTCFilterKey{ifindex: 21, parent: slot.parent}] = nil
				}
				if step == pinOwnerStepUnlinkingMaps || step == pinOwnerStepCleanupStages {
					programs, err := loadOwnerPrograms(fixture.handle, mutating)
					if err != nil {
						t.Fatal(err)
					}
					if err := rollForwardOwnerDetachFilters(
						mutating.ActiveFilters,
						programs,
						kernel.runtime(),
					); err != nil {
						_ = programs.Close()
						t.Fatal(err)
					}
					if err := programs.Close(); err != nil {
						t.Fatal(err)
					}
					unlinking := advancePinOwnerRecord(
						mutating,
						fixture.now.Add(3*time.Second),
						pinOwnerPhaseDetaching,
						pinOwnerStepUnlinkingMaps,
					)
					if err := fixture.store.Persist(unlinking, mutating, fixture.handle.mountID); err != nil {
						t.Fatal(err)
					}
					crashed = unlinking
					if step == pinOwnerStepCleanupStages {
						stages, err := loadOwnerMapStages(fixture.handle, unlinking)
						if err != nil {
							t.Fatal(err)
						}
						if err := removeCanonicalOwnerMaps(fixture.handle, unlinking, stages); err != nil {
							_ = stages.Close()
							t.Fatal(err)
						}
						if err := stages.Close(); err != nil {
							t.Fatal(err)
						}
						cleanup := advancePinOwnerRecord(
							unlinking,
							fixture.now.Add(4*time.Second),
							pinOwnerPhaseDetaching,
							pinOwnerStepCleanupStages,
						)
						if err := fixture.store.Persist(cleanup, unlinking, fixture.handle.mountID); err != nil {
							t.Fatal(err)
						}
						crashed = cleanup
					}
				}
			}

			recovered, err := recoverPinOwnerTransaction(
				fixture.handle,
				fixture.store,
				crashed,
				kernel.runtime(),
			)
			if err != nil {
				t.Fatal(err)
			}
			if step == pinOwnerStepStaging {
				if recovered.directoryRemoved || recovered.record == nil ||
					recovered.record.Phase != pinOwnerPhaseActive {
					t.Fatalf("staging recovery did not roll back to active: %#v", recovered)
				}
				return
			}
			if !recovered.directoryRemoved || recovered.record != nil {
				t.Fatalf("detach recovery did not remove the owned directory: %#v", recovered)
			}
		})
	}
}

func TestLinuxLoaderDetachRoutesClassicOwnerWithoutTCX(t *testing.T) {
	fixture := newExactTCXOwnerTestFixture(t)
	kernel := newFakeTCKernel(21)
	installClassicOwnerTestRuntime(t, fixture, kernel)
	kernel.addClsact(21)
	activeBindings := classicOwnerTestBindings(21, 501, 502)
	setClassicOwnerTestBindings(t, kernel, activeBindings)
	persistClassicOwnerTestActive(t, fixture, activeBindings)

	loader := LinuxLoader{PinPath: fixture.handle.pinPath, runtime: &fixture.runtime}
	if err := loader.Detach(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(fixture.handle.pinPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("classic detach left pin directory: %v", err)
	}
	for _, binding := range activeBindings {
		slot, err := ownerFilterSlot(binding)
		if err != nil {
			t.Fatal(err)
		}
		if got := kernel.managedProgramID(t, binding.IfIndex, slot); got != 0 {
			t.Fatalf("classic detach left %s program %d", binding.Direction, got)
		}
	}
}

func TestClassicOwnerRekeysArchivedPriorBootWithoutFilters(t *testing.T) {
	fixture := newExactTCXOwnerTestFixture(t)
	kernel := newFakeTCKernel()
	installClassicOwnerTestRuntime(t, fixture, kernel)
	fixture.runtime.random = bytes.NewReader(bytes.Repeat([]byte{0x5a}, 32))
	fixture.handle.runtime.random = fixture.runtime.random

	oldResource := fixture.handle.resource
	oldResource.parentDevice += 1000
	oldResource.parentInode += 1000
	var err error
	oldResource.key, err = pinidentity.Key(
		oldResource.parentDevice,
		oldResource.parentInode,
		oldResource.base,
	)
	if err != nil {
		t.Fatal(err)
	}
	oldParent := &pinPathParent{
		pinPath:  fixture.handle.pinPath,
		base:     oldResource.base,
		mountID:  fixture.handle.mountID,
		resource: oldResource,
		runtime:  fixture.runtime,
	}
	oldSentinel, err := pinOwnerSentinelFor(oldResource, fixture.token)
	if err != nil {
		t.Fatal(err)
	}
	owner := fixture.mapStore.observations["owner_map"]
	owner.owner = oldSentinel
	owner.ownerSeen = true
	fixture.mapStore.observations["owner_map"] = owner
	oldRecord, err := newClassicActivePinOwnerRecord(
		oldParent,
		fixture.token,
		classicOwnerTestBootID,
		fixture.now,
		7,
		fixture.maps,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	oldStore, err := openPinOwnerStore(fixture.runtime, oldResource, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := oldStore.Persist(oldRecord, nil, fixture.handle.mountID); err != nil {
		_ = oldStore.Close()
		t.Fatal(err)
	}
	indexed, err := activeIndexedOwnerForRecord(indexStoreFromOwner(oldStore), oldRecord)
	if err != nil {
		_ = oldStore.Close()
		t.Fatal(err)
	}
	historical, err := indexStoreFromOwner(oldStore).archivePriorBootOwner(
		*indexed,
		oldRecord,
		true,
		fixture.now.Add(time.Minute),
	)
	if err != nil {
		_ = oldStore.Close()
		t.Fatal(err)
	}
	if err := oldStore.Close(); err != nil {
		t.Fatal(err)
	}

	entry, err := indexedOwnerEntryForRekey(fixture.store, fixture.handle)
	if err != nil {
		t.Fatal(err)
	}
	if entry == nil || entry.RecordFileName != historical.RecordFileName {
		t.Fatalf("classic rekey source = %#v, want %#v", entry, historical)
	}
	currentBoot := "87654321-4321-4321-4321-cba987654321"
	rekeyed, err := rekeyRebootedClassicPinOwner(
		fixture.handle,
		fixture.parent,
		fixture.store,
		entry,
		currentBoot,
		fixture.now.Add(2*time.Minute),
		kernel.runtime(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if rekeyed.Version != pinOwnerLegacyClassicVersion ||
		rekeyed.BootID != currentBoot ||
		rekeyed.ResourceKey != fixture.handle.resource.key ||
		rekeyed.RetiredFromResourceKey != oldResource.key ||
		rekeyed.RetiredFromBootID != oldRecord.BootID ||
		len(rekeyed.ActiveFilters) != 0 || len(rekeyed.ActiveLinks) != 0 {
		t.Fatalf("rekeyed classic owner = %#v", rekeyed)
	}
	loaded, err := fixture.store.Load(fixture.handle.mountID)
	if err != nil {
		t.Fatal(err)
	}
	if !sameExpectedOwnerRecord(loaded, rekeyed) {
		t.Fatalf("loaded rekeyed classic owner = %#v, want %#v", loaded, rekeyed)
	}
	if _, err := os.Stat(filepath.Join(
		fixture.runtime.ownerRoot,
		historical.RecordFileName,
	)); err != nil {
		t.Fatalf("archived classic owner was not retained: %v", err)
	}
}
