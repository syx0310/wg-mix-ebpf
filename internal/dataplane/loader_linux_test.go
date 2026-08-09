//go:build linux

package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/syx0310/wg-mix-ebpf/internal/abi"
	"github.com/syx0310/wg-mix-ebpf/internal/control"
	"github.com/syx0310/wg-mix-ebpf/internal/lockfile"
	"github.com/syx0310/wg-mix-ebpf/internal/pinidentity"
)

func TestApplyRefusesLegacyAdoptionBeforeRuntimeAccess(t *testing.T) {
	loader := LinuxLoader{AdoptLegacyPins: true}
	err := loader.Apply(context.Background(), &control.State{})
	if err == nil || !strings.Contains(err.Error(), "detach with a trusted legacy build") {
		t.Fatalf("legacy adoption error = %v", err)
	}
}

func TestXORTailCallBankStartAlternatesWithoutOverlap(t *testing.T) {
	tests := []struct {
		generation uint64
		want       uint32
	}{
		{generation: 0, want: 0},
		{generation: 1, want: xorSegmentCount},
		{generation: 2, want: 0},
		{generation: 3, want: xorSegmentCount},
	}
	for _, tt := range tests {
		if got := xorTailCallBankStart(tt.generation); got != tt.want {
			t.Fatalf("generation %d bank start = %d, want %d", tt.generation, got, tt.want)
		}
	}
}

func TestXORTailCallBindingsCoverEverySegment(t *testing.T) {
	if len(xorTailCallBindings) != 2 {
		t.Fatalf("tail-call map bindings = %d, want 2", len(xorTailCallBindings))
	}
	seenMaps := make(map[string]struct{})
	seenPrograms := make(map[string]struct{})
	for _, binding := range xorTailCallBindings {
		if _, duplicate := seenMaps[binding.mapName]; duplicate {
			t.Fatalf("duplicate tail-call map %q", binding.mapName)
		}
		seenMaps[binding.mapName] = struct{}{}
		for segment, name := range binding.programNames {
			if name == "" {
				t.Fatalf("%s segment %d has no program", binding.mapName, segment)
			}
			if _, duplicate := seenPrograms[name]; duplicate {
				t.Fatalf("duplicate tail-call program %q", name)
			}
			seenPrograms[name] = struct{}{}
		}
	}
	if len(seenPrograms) != len(xorTailCallBindings)*xorSegmentCount {
		t.Fatalf("tail-call programs = %d, want %d", len(seenPrograms), len(xorTailCallBindings)*xorSegmentCount)
	}
}

func TestPopulateXORTailCallsRejectsMissingLayout(t *testing.T) {
	t.Run("map", func(t *testing.T) {
		err := populateXORTailCalls(&ebpf.Collection{}, 1)
		if err == nil || !strings.Contains(err.Error(), `missing map "xor_egress_programs"`) {
			t.Fatalf("error = %v, want missing egress ProgramArray", err)
		}
	})

	t.Run("program", func(t *testing.T) {
		coll := &ebpf.Collection{
			Maps: map[string]*ebpf.Map{
				"xor_egress_programs": {},
			},
			Programs: map[string]*ebpf.Program{},
		}
		err := populateXORTailCalls(coll, 1)
		if err == nil || !strings.Contains(err.Error(), `missing program "wg_xor_eg_0"`) {
			t.Fatalf("error = %v, want missing first egress segment", err)
		}
	})
}

func TestValidateAndSetPinnedMapsRequiresCanonicalMapABI(t *testing.T) {
	spec := canonicalPinnedMapCollectionSpec()
	if err := validateAndSetPinnedMaps(spec); err != nil {
		t.Fatalf("validate canonical pinned maps: %v", err)
	}
	for _, descriptor := range pinnedMapDescriptors() {
		if got := spec.Maps[descriptor.name].Pinning; got != ebpf.PinByName {
			t.Fatalf("%s pinning = %v, want PinByName", descriptor.name, got)
		}
	}
	if got := spec.Maps["icmp_seq_map"].Pinning; got != ebpf.PinNone {
		t.Fatalf("non-owned icmp_seq_map pinning = %v, want PinNone", got)
	}

	tests := []struct {
		name    string
		mutate  func(*ebpf.CollectionSpec)
		wantErr string
	}{
		{
			name: "missing required map",
			mutate: func(spec *ebpf.CollectionSpec) {
				delete(spec.Maps, "profile_map")
			},
			wantErr: `missing required pinned map "profile_map"`,
		},
		{
			name: "unexpected pinned map",
			mutate: func(spec *ebpf.CollectionSpec) {
				spec.Maps["icmp_seq_map"].Pinning = ebpf.PinByName
			},
			wantErr: "unexpected pinned maps: icmp_seq_map",
		},
		{
			name: "unexpected unsupported pin mode",
			mutate: func(spec *ebpf.CollectionSpec) {
				spec.Maps["icmp_seq_map"].Pinning = ebpf.PinType(2)
			},
			wantErr: "unexpected pinned maps: icmp_seq_map",
		},
		{
			name: "canonical unsupported pin mode",
			mutate: func(spec *ebpf.CollectionSpec) {
				spec.Maps["profile_map"].Pinning = ebpf.PinType(2)
			},
			wantErr: "unsupported pinning mode",
		},
		{
			name: "nil noncanonical spec",
			mutate: func(spec *ebpf.CollectionSpec) {
				spec.Maps["icmp_seq_map"] = nil
			},
			wantErr: "has a nil spec",
		},
		{
			name: "wrong kernel name",
			mutate: func(spec *ebpf.CollectionSpec) {
				spec.Maps["profile_map"].Name = "foreign_map"
			},
			wantErr: "has kernel name",
		},
		{
			name: "wrong type",
			mutate: func(spec *ebpf.CollectionSpec) {
				spec.Maps["profile_map"].Type = ebpf.Array
			},
			wantErr: "schema is",
		},
		{
			name: "wrong key size",
			mutate: func(spec *ebpf.CollectionSpec) {
				spec.Maps["profile_map"].KeySize++
			},
			wantErr: "schema is",
		},
		{
			name: "wrong value size",
			mutate: func(spec *ebpf.CollectionSpec) {
				spec.Maps["profile_map"].ValueSize++
			},
			wantErr: "schema is",
		},
		{
			name: "wrong max entries",
			mutate: func(spec *ebpf.CollectionSpec) {
				spec.Maps["profile_map"].MaxEntries++
			},
			wantErr: "schema is",
		},
		{
			name: "wrong flags",
			mutate: func(spec *ebpf.CollectionSpec) {
				spec.Maps["profile_map"].Flags = 1
			},
			wantErr: "schema is",
		},
		{
			name: "map extra",
			mutate: func(spec *ebpf.CollectionSpec) {
				spec.Maps["profile_map"].MapExtra = 1
			},
			wantErr: "unsupported creation metadata",
		},
		{
			name: "initial contents",
			mutate: func(spec *ebpf.CollectionSpec) {
				spec.Maps["profile_map"].Contents = []ebpf.MapKV{{Key: uint32(1), Value: uint32(2)}}
			},
			wantErr: "unsupported creation metadata",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := canonicalPinnedMapCollectionSpec()
			tt.mutate(spec)
			if err := validateAndSetPinnedMaps(spec); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validation error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidatePinPathAcceptsProjectPathsOnBPFFS(t *testing.T) {
	bpffsRoot, validator := newTestBPFFS(t)
	existing := filepath.Join(bpffsRoot, pinPathPrefix+"-smoke-instance")
	if err := os.Mkdir(existing, 0o700); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		path       string
		wantExists bool
	}{
		{
			name:       "default project directory",
			path:       filepath.Join(bpffsRoot, pinPathPrefix),
			wantExists: false,
		},
		{
			name:       "existing safe suffix",
			path:       existing,
			wantExists: true,
		},
		{
			name:       "missing safe suffix",
			path:       filepath.Join(bpffsRoot, pinPathPrefix+"-test-a"),
			wantExists: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validated, err := validatePinPath(tt.path, validator)
			if err != nil {
				t.Fatalf("validatePinPath(%q): %v", tt.path, err)
			}
			if validated.exists != tt.wantExists {
				t.Fatalf("exists = %v, want %v", validated.exists, tt.wantExists)
			}
			if validated.bpffsRoot != bpffsRoot {
				t.Fatalf("bpffs root = %q, want %q", validated.bpffsRoot, bpffsRoot)
			}
		})
	}
}

func TestValidatePinPathRejectsUnsafePaths(t *testing.T) {
	bpffsRoot, validator := newTestBPFFS(t)
	ordinaryPath := filepath.Join(bpffsRoot, pinPathPrefix+"-ordinary")
	if err := os.WriteFile(ordinaryPath, []byte("do not remove"), 0o600); err != nil {
		t.Fatal(err)
	}
	nonProjectPath := filepath.Join(bpffsRoot, "other-project")
	if err := os.Mkdir(nonProjectPath, 0o700); err != nil {
		t.Fatal(err)
	}
	nestedPath := filepath.Join(bpffsRoot, pinPathPrefix, "instance")
	if err := os.MkdirAll(nestedPath, 0o700); err != nil {
		t.Fatal(err)
	}
	nonBPFFSPath := filepath.Join(filepath.Dir(bpffsRoot), pinPathPrefix+"-hostfs")
	if err := os.Mkdir(nonBPFFSPath, 0o700); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		path    string
		wantErr string
	}{
		{
			name:    "relative",
			path:    pinPathPrefix,
			wantErr: "must be absolute",
		},
		{
			name:    "unclean parent traversal",
			path:    filepath.Join(bpffsRoot, pinPathPrefix) + "/../" + pinPathPrefix,
			wantErr: "must be clean",
		},
		{
			name:    "trailing slash",
			path:    filepath.Join(bpffsRoot, pinPathPrefix) + "/",
			wantErr: "must be clean",
		},
		{
			name:    "bpffs top level",
			path:    bpffsRoot,
			wantErr: "must not be the bpffs top level",
		},
		{
			name:    "non project prefix",
			path:    nonProjectPath,
			wantErr: "directory name must be",
		},
		{
			name:    "nested project path",
			path:    nestedPath,
			wantErr: "is inside bpffs but is not its mount root",
		},
		{
			name:    "empty suffix",
			path:    filepath.Join(bpffsRoot, pinPathPrefix+"-"),
			wantErr: "directory name must be",
		},
		{
			name:    "unsafe suffix",
			path:    filepath.Join(bpffsRoot, pinPathPrefix+"-test_side"),
			wantErr: "directory name must be",
		},
		{
			name:    "suffix too long",
			path:    filepath.Join(bpffsRoot, pinPathPrefix+"-"+strings.Repeat("a", maxPinPathSuffix+1)),
			wantErr: "directory name must be",
		},
		{
			name:    "ordinary target",
			path:    ordinaryPath,
			wantErr: "is not a directory",
		},
		{
			name:    "not bpffs",
			path:    nonBPFFSPath,
			wantErr: "is not a bpffs mount root",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := validatePinPath(tt.path, validator); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validatePinPath(%q) error = %v, want substring %q", tt.path, err, tt.wantErr)
			}
		})
	}

	content, err := os.ReadFile(ordinaryPath)
	if err != nil {
		t.Fatalf("ordinary target was changed: %v", err)
	}
	if string(content) != "do not remove" {
		t.Fatalf("ordinary target content = %q", content)
	}
}

func TestValidatePinPathRejectsTargetAndAncestorSymlinks(t *testing.T) {
	bpffsRoot, validator := newTestBPFFS(t)
	realTarget := filepath.Join(bpffsRoot, pinPathPrefix+"-real")
	if err := os.MkdirAll(filepath.Join(realTarget, "instance"), 0o700); err != nil {
		t.Fatal(err)
	}

	targetLink := filepath.Join(bpffsRoot, pinPathPrefix+"-target-link")
	if err := os.Symlink(realTarget, targetLink); err != nil {
		t.Fatal(err)
	}
	if _, err := validatePinPath(targetLink, validator); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("target symlink error = %v", err)
	}

	ancestorLink := filepath.Join(bpffsRoot, pinPathPrefix+"-ancestor-link")
	if err := os.Symlink(realTarget, ancestorLink); err != nil {
		t.Fatal(err)
	}
	if _, err := validatePinPath(filepath.Join(ancestorLink, "instance"), validator); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("ancestor symlink error = %v", err)
	}
	if _, err := os.Lstat(targetLink); err != nil {
		t.Fatalf("target symlink was changed: %v", err)
	}
	if _, err := os.Lstat(ancestorLink); err != nil {
		t.Fatalf("ancestor symlink was changed: %v", err)
	}
}

func TestValidatePinPathRejectsNestedMountByMountID(t *testing.T) {
	bpffsRoot, validator := newTestBPFFS(t)
	pinPath := filepath.Join(bpffsRoot, pinPathPrefix+"-nested-mount")
	if err := os.Mkdir(pinPath, 0o700); err != nil {
		t.Fatal(err)
	}
	originalMountID := validator.mountID
	validator.mountID = func(path string) (uint64, error) {
		if path == pinPath {
			return 303, nil
		}
		return originalMountID(path)
	}

	if _, err := validatePinPath(pinPath, validator); err == nil ||
		!strings.Contains(err.Error(), "target is a nested mount") {
		t.Fatalf("nested-mount validation error = %v", err)
	}
}

func TestCleanupPinnedMapsRemovesKnownPinsAndOnlyEmptyDirectory(t *testing.T) {
	t.Run("known pins and empty directory", func(t *testing.T) {
		bpffsRoot, validator := newTestBPFFS(t)
		pinPath := filepath.Join(bpffsRoot, pinPathPrefix+"-empty")
		store := writeCanonicalMockPins(t, pinPath)
		runtime := newTestPinPathRuntime(t, validator, store)

		if err := executeTestCleanup(pinPath, runtime); err != nil {
			t.Fatalf("executeTestCleanup: %v", err)
		}
		if _, err := os.Lstat(pinPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("empty pin directory still exists or cannot be inspected: %v", err)
		}
		if _, err := os.Stat(bpffsRoot); err != nil {
			t.Fatalf("bpffs root was changed: %v", err)
		}
	})

	t.Run("unknown entry keeps directory", func(t *testing.T) {
		bpffsRoot, validator := newTestBPFFS(t)
		pinPath := filepath.Join(bpffsRoot, pinPathPrefix+"-nonempty")
		store := writeCanonicalMockPins(t, pinPath)
		runtime := newTestPinPathRuntime(t, validator, store)
		unknownPath := filepath.Join(pinPath, "operator-note")
		if err := os.WriteFile(unknownPath, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}

		if err := executeTestCleanup(pinPath, runtime); err != nil {
			t.Fatalf("executeTestCleanup: %v", err)
		}
		for _, name := range pinnedMapNames() {
			if _, err := os.Lstat(filepath.Join(pinPath, name)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("known pin %s still exists or cannot be inspected: %v", name, err)
			}
		}
		content, err := os.ReadFile(unknownPath)
		if err != nil {
			t.Fatalf("unknown entry was changed: %v", err)
		}
		if string(content) != "keep" {
			t.Fatalf("unknown entry content = %q", content)
		}
		if info, err := os.Stat(pinPath); err != nil || !info.IsDir() {
			t.Fatalf("non-empty pin directory was removed or changed: info=%v err=%v", info, err)
		}
	})

	t.Run("unknown-only directory is preserved", func(t *testing.T) {
		bpffsRoot, validator := newTestBPFFS(t)
		pinPath := filepath.Join(bpffsRoot, pinPathPrefix+"-unknown")
		if err := os.Mkdir(pinPath, 0o700); err != nil {
			t.Fatal(err)
		}
		marker := filepath.Join(pinPath, "operator-note")
		if err := os.WriteFile(marker, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
		runtime := newTestPinPathRuntime(t, validator, newFakePinnedMapStore())
		if err := executeTestCleanup(pinPath, runtime); err != nil {
			t.Fatalf("executeTestCleanup: %v", err)
		}
		assertFileContent(t, marker, "keep")
	})
}

func TestCleanupPinnedMapsRejectsUnsafeTargetsWithoutChanges(t *testing.T) {
	bpffsRoot, validator := newTestBPFFS(t)
	runtime := newTestPinPathRuntime(t, validator, newFakePinnedMapStore())

	t.Run("ordinary file", func(t *testing.T) {
		target := filepath.Join(bpffsRoot, pinPathPrefix+"-file")
		if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := executeTestCleanup(target, runtime); err == nil || !strings.Contains(err.Error(), "is not a directory") {
			t.Fatalf("cleanup error = %v", err)
		}
		assertFileContent(t, target, "keep")
	})

	t.Run("bpffs top level", func(t *testing.T) {
		marker := filepath.Join(bpffsRoot, "marker")
		if err := os.WriteFile(marker, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := executeTestCleanup(bpffsRoot, runtime); err == nil || !strings.Contains(err.Error(), "bpffs top level") {
			t.Fatalf("cleanup error = %v", err)
		}
		assertFileContent(t, marker, "keep")
	})

	t.Run("non project path", func(t *testing.T) {
		target := filepath.Join(bpffsRoot, "another-agent")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}
		marker := filepath.Join(target, "marker")
		if err := os.WriteFile(marker, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := executeTestCleanup(target, runtime); err == nil || !strings.Contains(err.Error(), "directory name must be") {
			t.Fatalf("cleanup error = %v", err)
		}
		assertFileContent(t, marker, "keep")
	})

	t.Run("target symlink", func(t *testing.T) {
		realTarget := filepath.Join(bpffsRoot, pinPathPrefix+"-real-target")
		if err := os.Mkdir(realTarget, 0o700); err != nil {
			t.Fatal(err)
		}
		marker := filepath.Join(realTarget, "marker")
		if err := os.WriteFile(marker, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(bpffsRoot, pinPathPrefix+"-link-target")
		if err := os.Symlink(realTarget, link); err != nil {
			t.Fatal(err)
		}
		if err := executeTestCleanup(link, runtime); err == nil || !strings.Contains(err.Error(), "symbolic link") {
			t.Fatalf("cleanup error = %v", err)
		}
		if _, err := os.Lstat(link); err != nil {
			t.Fatalf("target symlink was changed: %v", err)
		}
		assertFileContent(t, marker, "keep")
	})
}

func TestCleanupPinnedMapsPreflightsAllKnownPins(t *testing.T) {
	bpffsRoot, validator := newTestBPFFS(t)
	pinPath := filepath.Join(bpffsRoot, pinPathPrefix+"-preflight")
	if err := os.Mkdir(pinPath, 0o700); err != nil {
		t.Fatal(err)
	}
	firstPin := filepath.Join(pinPath, pinnedMapNames()[0])
	if err := os.WriteFile(firstPin, []byte("keep until full preflight passes"), 0o600); err != nil {
		t.Fatal(err)
	}
	runtime := newTestPinPathRuntime(t, validator, newFakePinnedMapStore())

	err := executeTestCleanup(pinPath, runtime)
	if err == nil || !strings.Contains(err.Error(), "incomplete pinned-map set") {
		t.Fatalf("cleanup error = %v", err)
	}
	assertFileContent(t, firstPin, "keep until full preflight passes")
}

func TestCleanupPinnedMapsRejectsUnsafeKnownPinEntriesWithoutDeletion(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		bpffsRoot, validator := newTestBPFFS(t)
		pinPath := filepath.Join(bpffsRoot, pinPathPrefix+"-pin-link")
		store := writeCanonicalMockPins(t, pinPath)
		targetName := pinnedMapNames()[1]
		targetPath := filepath.Join(pinPath, targetName)
		originalPath := filepath.Join(pinPath, "original-"+targetName)
		if err := os.Rename(targetPath, originalPath); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(originalPath, targetPath); err != nil {
			t.Fatal(err)
		}
		runtime := newTestPinPathRuntime(t, validator, store)

		err := executeTestCleanup(pinPath, runtime)
		if err == nil || !strings.Contains(err.Error(), "not a regular map pin") {
			t.Fatalf("cleanup error = %v, want symlink rejection", err)
		}
		if _, err := os.Lstat(targetPath); err != nil {
			t.Fatalf("known-pin symlink was changed: %v", err)
		}
		for _, name := range pinnedMapNames()[2:] {
			if _, err := os.Lstat(filepath.Join(pinPath, name)); err != nil {
				t.Fatalf("known pin %s was changed: %v", name, err)
			}
		}
	})

	t.Run("nested mount ID", func(t *testing.T) {
		bpffsRoot, validator := newTestBPFFS(t)
		pinPath := filepath.Join(bpffsRoot, pinPathPrefix+"-pin-mount")
		store := writeCanonicalMockPins(t, pinPath)
		runtime := newTestPinPathRuntime(t, validator, store)
		runtime.mountIDAt = func(_ int, path string, _ int) (uint64, error) {
			if path == "profile_map" {
				return 303, nil
			}
			return 101, nil
		}

		err := executeTestCleanup(pinPath, runtime)
		if err == nil || !strings.Contains(err.Error(), "differs from validated bpffs mount ID") {
			t.Fatalf("cleanup error = %v, want nested map mount rejection", err)
		}
		assertAllMockPinsExist(t, pinPath)
	})
}

func TestCleanupPinnedMapsRejectsObjectAndSchemaMismatchesWithoutDeletion(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*fakePinnedMapStore)
		wantErr string
	}{
		{
			name: "program masquerading as map",
			mutate: func(store *fakePinnedMapStore) {
				store.loadErrors["profile_map"] = errors.New("object is not a Map")
			},
			wantErr: "object is not a Map",
		},
		{
			name: "wrong map type",
			mutate: func(store *fakePinnedMapStore) {
				observation := store.observations["profile_map"]
				observation.mapType = ebpf.Array
				store.observations["profile_map"] = observation
			},
			wantErr: "schema is",
		},
		{
			name: "wrong key size",
			mutate: func(store *fakePinnedMapStore) {
				observation := store.observations["profile_map"]
				observation.keySize++
				store.observations["profile_map"] = observation
			},
			wantErr: "schema is",
		},
		{
			name: "wrong value size",
			mutate: func(store *fakePinnedMapStore) {
				observation := store.observations["profile_map"]
				observation.valueSize++
				store.observations["profile_map"] = observation
			},
			wantErr: "schema is",
		},
		{
			name: "wrong max entries",
			mutate: func(store *fakePinnedMapStore) {
				observation := store.observations["profile_map"]
				observation.maxEntries++
				store.observations["profile_map"] = observation
			},
			wantErr: "schema is",
		},
		{
			name: "wrong flags",
			mutate: func(store *fakePinnedMapStore) {
				observation := store.observations["profile_map"]
				observation.flags = 1
				store.observations["profile_map"] = observation
			},
			wantErr: "schema is",
		},
		{
			name: "wrong kernel name",
			mutate: func(store *fakePinnedMapStore) {
				observation := store.observations["underlay_config_map"]
				observation.kernelName = "foreign_map"
				store.observations["underlay_config_map"] = observation
			},
			wantErr: "reports kernel name",
		},
		{
			name: "missing kernel name",
			mutate: func(store *fakePinnedMapStore) {
				observation := store.observations["underlay_config_map"]
				observation.kernelName = ""
				store.observations["underlay_config_map"] = observation
			},
			wantErr: "reports kernel name",
		},
		{
			name: "map extra",
			mutate: func(store *fakePinnedMapStore) {
				observation := store.observations["profile_map"]
				observation.mapExtra = 1
				store.observations["profile_map"] = observation
			},
			wantErr: "map_extra",
		},
		{
			name: "frozen",
			mutate: func(store *fakePinnedMapStore) {
				observation := store.observations["profile_map"]
				observation.frozen = true
				store.observations["profile_map"] = observation
			},
			wantErr: "is frozen",
		},
		{
			name: "duplicate map ID",
			mutate: func(store *fakePinnedMapStore) {
				observation := store.observations["profile_map"]
				observation.id = store.observations["control_map"].id
				store.observations["profile_map"] = observation
			},
			wantErr: "share map ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bpffsRoot, validator := newTestBPFFS(t)
			pinPath := filepath.Join(bpffsRoot, pinPathPrefix+"-schema")
			store := writeCanonicalMockPins(t, pinPath)
			tt.mutate(store)
			runtime := newTestPinPathRuntime(t, validator, store)

			err := executeTestCleanup(pinPath, runtime)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("cleanup error = %v, want substring %q", err, tt.wantErr)
			}
			assertAllMockPinsExist(t, pinPath)
		})
	}
}

func TestCleanupPinnedMapsRequiresCommittedControlIdentity(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*pinnedMapObservation)
		wantErr string
	}{
		{
			name: "missing identity",
			mutate: func(observation *pinnedMapObservation) {
				observation.controlSeen = false
			},
			wantErr: "identity value is unavailable",
		},
		{
			name: "zero ABI",
			mutate: func(observation *pinnedMapObservation) {
				observation.control.ABIVersion = 0
			},
			wantErr: "ABI version",
		},
		{
			name: "old ABI",
			mutate: func(observation *pinnedMapObservation) {
				observation.control.ABIVersion--
			},
			wantErr: "ABI version",
		},
		{
			name: "unknown flags",
			mutate: func(observation *pinnedMapObservation) {
				observation.control.Flags = 1
			},
			wantErr: "flags",
		},
		{
			name: "uncommitted generation",
			mutate: func(observation *pinnedMapObservation) {
				observation.control.ActiveGeneration = 0
			},
			wantErr: "no committed generation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bpffsRoot, validator := newTestBPFFS(t)
			pinPath := filepath.Join(bpffsRoot, pinPathPrefix+"-identity")
			store := writeCanonicalMockPins(t, pinPath)
			observation := store.observations["control_map"]
			tt.mutate(&observation)
			store.observations["control_map"] = observation
			runtime := newTestPinPathRuntime(t, validator, store)

			err := executeTestCleanup(pinPath, runtime)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("cleanup error = %v, want substring %q", err, tt.wantErr)
			}
			assertAllMockPinsExist(t, pinPath)
		})
	}
}

func TestCleanupPinnedMapsRechecksIDsBeforeAnyDeletion(t *testing.T) {
	bpffsRoot, validator := newTestBPFFS(t)
	pinPath := filepath.Join(bpffsRoot, pinPathPrefix+"-id-swap")
	store := writeCanonicalMockPins(t, pinPath)
	runtime := newTestPinPathRuntime(t, validator, store)
	plan, err := preparePinnedMapCleanup(pinPath, runtime)
	if err != nil {
		t.Fatalf("prepare cleanup: %v", err)
	}
	defer plan.Close()

	observation := store.observations["control_map"]
	observation.id += 1000
	store.observations["control_map"] = observation
	if err := plan.Execute(); err == nil || !strings.Contains(err.Error(), "changed ID") {
		t.Fatalf("execute cleanup error = %v, want map ID change", err)
	}
	assertAllMockPinsExist(t, pinPath)
}

func TestCleanupPinnedMapsBindsLoadedMapToPinnedEntryIdentity(t *testing.T) {
	bpffsRoot, validator := newTestBPFFS(t)
	pinPath := filepath.Join(bpffsRoot, pinPathPrefix+"-entry-swap")
	store := writeCanonicalMockPins(t, pinPath)
	swapped := false
	store.onLoad = func(name string) {
		if name != "profile_map" || swapped {
			return
		}
		swapped = true
		path := filepath.Join(pinPath, name)
		if err := os.Rename(path, filepath.Join(pinPath, "original-"+name)); err != nil {
			t.Fatalf("move original mock pin: %v", err)
		}
		if err := os.WriteFile(path, []byte("replacement mock pin"), 0o600); err != nil {
			t.Fatalf("create replacement mock pin: %v", err)
		}
	}
	runtime := newTestPinPathRuntime(t, validator, store)

	err := executeTestCleanup(pinPath, runtime)
	if err == nil || !strings.Contains(err.Error(), "map identity preflight") {
		t.Fatalf("cleanup error = %v, want pin-entry identity change", err)
	}
	assertAllMockPinsExist(t, pinPath)
	if _, err := os.Lstat(filepath.Join(pinPath, "original-profile_map")); err != nil {
		t.Fatalf("original mock pin was changed or removed: %v", err)
	}
}

func TestCleanupPinnedMapsRejectsReplacedTargetDirectory(t *testing.T) {
	bpffsRoot, validator := newTestBPFFS(t)
	pinPath := filepath.Join(bpffsRoot, pinPathPrefix+"-replace")
	store := writeCanonicalMockPins(t, pinPath)
	runtime := newTestPinPathRuntime(t, validator, store)
	plan, err := preparePinnedMapCleanup(pinPath, runtime)
	if err != nil {
		t.Fatalf("prepare cleanup: %v", err)
	}
	defer plan.Close()

	originalPath := filepath.Join(bpffsRoot, pinPathPrefix+"-original")
	if err := os.Rename(pinPath, originalPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(pinPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := plan.Execute(); err == nil || !strings.Contains(err.Error(), "changed after it was opened") {
		t.Fatalf("execute cleanup error = %v, want target identity change", err)
	}
	assertAllMockPinsExist(t, originalPath)
}

func TestFreshApplyRollbackRemovesOnlyItsUncommittedPartialPins(t *testing.T) {
	bpffsRoot, validator := newTestBPFFS(t)
	pinPath := filepath.Join(bpffsRoot, pinPathPrefix+"-fresh-rollback")
	store := writeCanonicalMockPins(t, pinPath)
	names := pinnedMapNames()
	for _, name := range names[4:] {
		if err := os.Remove(filepath.Join(pinPath, name)); err != nil {
			t.Fatal(err)
		}
	}
	controlObservation := store.observations["control_map"]
	controlObservation.control = abi.ControlValue{}
	store.observations["control_map"] = controlObservation
	runtime := newTestPinPathRuntime(t, validator, store)
	validated, err := validatePinPath(pinPath, validator)
	if err != nil {
		t.Fatal(err)
	}
	handle, _, err := openPinPathHandle(pinPath, validated, false, runtime)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()

	if err := rollbackFreshPinnedMaps(handle, false); err != nil {
		t.Fatalf("rollback fresh partial pin set: %v", err)
	}
	entries, err := os.ReadDir(pinPath)
	if err != nil {
		t.Fatalf("pre-existing pin directory was removed: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("pre-existing pin directory entries after rollback = %v, want empty", entries)
	}
}

func TestFreshApplyRollbackRejectsInitializedControlWithoutDeletion(t *testing.T) {
	bpffsRoot, validator := newTestBPFFS(t)
	pinPath := filepath.Join(bpffsRoot, pinPathPrefix+"-fresh-foreign")
	store := writeCanonicalMockPins(t, pinPath)
	runtime := newTestPinPathRuntime(t, validator, store)
	validated, err := validatePinPath(pinPath, validator)
	if err != nil {
		t.Fatal(err)
	}
	handle, _, err := openPinPathHandle(pinPath, validated, false, runtime)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()

	if err := rollbackFreshPinnedMaps(handle, false); err == nil ||
		!strings.Contains(err.Error(), "already initialized") {
		t.Fatalf("fresh rollback error = %v, want initialized-control refusal", err)
	}
	assertAllMockPinsExist(t, pinPath)
}

func TestFreshApplyRollbackRemovesDirectoryCreatedByAttempt(t *testing.T) {
	bpffsRoot, validator := newTestBPFFS(t)
	pinPath := filepath.Join(bpffsRoot, pinPathPrefix+"-fresh-created")
	store := newFakePinnedMapStore()
	runtime := newTestPinPathRuntime(t, validator, store)
	validated, err := validatePinPath(pinPath, validator)
	if err != nil {
		t.Fatal(err)
	}
	handle, created, err := openPinPathHandle(pinPath, validated, true, runtime)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	if !created {
		t.Fatal("test pin directory was not reported as created")
	}

	if err := rollbackFreshPinnedMaps(handle, created); err != nil {
		t.Fatalf("rollback fresh created directory: %v", err)
	}
	if _, err := os.Lstat(pinPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("attempt-owned empty pin directory still exists or cannot be inspected: %v", err)
	}
}

func TestPinPathLockSerializesAndRecordsOwner(t *testing.T) {
	runtime := newTestPinLockRuntime(t, filepath.Join(t.TempDir(), "pin-locks"))
	pinPath := "/sys/fs/bpf/" + pinPathPrefix + "-lock-test"
	resource := newTestPinResource(t, pinPath)
	first, err := acquirePinPathLock(context.Background(), resource, "apply", runtime)
	if err != nil {
		t.Fatalf("acquire first lock: %v", err)
	}
	defer first.Close()

	ownerBytes, err := os.ReadFile(first.path)
	if err != nil {
		t.Fatalf("read lock owner: %v", err)
	}
	var owner pinPathOwner
	if err := json.Unmarshal(ownerBytes, &owner); err != nil {
		t.Fatalf("decode lock owner: %v", err)
	}
	if owner.Version != pinPathOwnerV2 ||
		owner.PID != os.Getpid() ||
		owner.Action != "apply" ||
		owner.ResourceKey != resource.key ||
		owner.ParentDevice != resource.parentDevice ||
		owner.ParentInode != resource.parentInode ||
		owner.PinBaseName != resource.base ||
		owner.PinPath != pinPath {
		t.Fatalf("lock owner = %+v", owner)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	if _, err := acquirePinPathLock(ctx, resource, "detach", runtime); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("contended lock error = %v, want deadline exceeded", err)
	}

	if err := first.Close(); err != nil {
		t.Fatalf("release first lock: %v", err)
	}
	second, err := acquirePinPathLock(context.Background(), resource, "detach", runtime)
	if err != nil {
		t.Fatalf("acquire released lock: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("release second lock: %v", err)
	}
}

func TestPinRuntimeDerivesLockRootFromIsolatedLifecycleContext(t *testing.T) {
	loader := LinuxLoader{}
	if got := loader.pinRuntime(context.Background()).lockRoot; got != pinPathLockRoot {
		t.Fatalf("default pin lock root = %q, want %q", got, pinPathLockRoot)
	}

	root := t.TempDir()
	runDir := filepath.Join(root, "run-a")
	ctx := lockfile.WithLifecyclePathsForTest(
		context.Background(),
		filepath.Join(runDir, "daemon.lease"),
		filepath.Join(root, "maintenance.gate"),
	)
	want := filepath.Join(runDir, "pin-locks")
	if got := loader.pinRuntime(ctx).lockRoot; got != want {
		t.Fatalf("isolated pin lock root = %q, want %q", got, want)
	}
	if got, wantOwner := loader.pinRuntime(ctx).ownerRoot, filepath.Join(runDir, "pin-owners"); got != wantOwner {
		t.Fatalf("isolated pin owner root = %q, want %q", got, wantOwner)
	}
	if got := loader.pinRuntime(ctx).bpffsRootMode; got != 0o700 {
		t.Fatalf("isolated bpffs root mode = %#o, want 0700", got)
	}
	if got := loader.pinRuntime(ctx).lockRoot; strings.HasPrefix(got, "/run/wg-mix-ebpf/") {
		t.Fatalf("isolated pin lock root escaped to production runtime: %q", got)
	}
}

func TestPinPathLockRejectsSymlinksAndHardlinks(t *testing.T) {
	pinPath := "/sys/fs/bpf/" + pinPathPrefix + "-unsafe-lock"
	resource := newTestPinResource(t, pinPath)
	lockName, err := pinidentity.LockFileName(
		resource.parentDevice,
		resource.parentInode,
		resource.base,
	)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("symlink", func(t *testing.T) {
		lockRoot := filepath.Join(t.TempDir(), "pin-locks")
		if err := os.Mkdir(lockRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(t.TempDir(), "target")
		if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(lockRoot, lockName)); err != nil {
			t.Fatal(err)
		}
		runtime := newTestPinLockRuntime(t, lockRoot)
		if _, err := acquirePinPathLock(context.Background(), resource, "detach", runtime); err == nil {
			t.Fatal("symlink lock unexpectedly accepted")
		}
		assertFileContent(t, target, "keep")
	})

	t.Run("hardlink", func(t *testing.T) {
		lockRoot := filepath.Join(t.TempDir(), "pin-locks")
		if err := os.Mkdir(lockRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(t.TempDir(), "target")
		if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(target, filepath.Join(lockRoot, lockName)); err != nil {
			t.Fatal(err)
		}
		runtime := newTestPinLockRuntime(t, lockRoot)
		if _, err := acquirePinPathLock(context.Background(), resource, "detach", runtime); err == nil ||
			!strings.Contains(err.Error(), "links=2") {
			t.Fatalf("hardlink lock error = %v", err)
		}
		assertFileContent(t, target, "keep")
	})
}

func TestPinPathLockRejectsUnsafeMetadataAndEntrySwap(t *testing.T) {
	pinPath := "/sys/fs/bpf/" + pinPathPrefix + "-metadata-lock"
	resource := newTestPinResource(t, pinPath)
	lockName, err := pinidentity.LockFileName(
		resource.parentDevice,
		resource.parentInode,
		resource.base,
	)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("root mode", func(t *testing.T) {
		lockRoot := filepath.Join(t.TempDir(), "pin-locks")
		if err := os.Mkdir(lockRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		setExactTestPermissions(t, lockRoot, 0o755)
		runtime := newTestPinLockRuntime(t, lockRoot)
		if _, err := acquirePinPathLock(
			context.Background(),
			resource,
			"apply",
			runtime,
		); err == nil || !strings.Contains(err.Error(), "mode=") {
			t.Fatalf("unsafe root mode error = %v", err)
		}
	})

	t.Run("file mode", func(t *testing.T) {
		lockRoot := filepath.Join(t.TempDir(), "pin-locks")
		if err := os.Mkdir(lockRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(lockRoot, lockName), []byte("keep"), 0o644); err != nil {
			t.Fatal(err)
		}
		setExactTestPermissions(t, filepath.Join(lockRoot, lockName), 0o644)
		runtime := newTestPinLockRuntime(t, lockRoot)
		if _, err := acquirePinPathLock(
			context.Background(),
			resource,
			"apply",
			runtime,
		); err == nil || !strings.Contains(err.Error(), "mode=") {
			t.Fatalf("unsafe file mode error = %v", err)
		}
	})

	t.Run("uid", func(t *testing.T) {
		lockRoot := filepath.Join(t.TempDir(), "pin-locks")
		if err := os.Mkdir(lockRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		runtime := newTestPinLockRuntime(t, lockRoot)
		runtime.expectedUID++
		if _, err := acquirePinPathLock(
			context.Background(),
			resource,
			"apply",
			runtime,
		); err == nil || !strings.Contains(err.Error(), "uid=") {
			t.Fatalf("foreign uid error = %v", err)
		}
	})

	t.Run("swap before write", func(t *testing.T) {
		lockRoot := filepath.Join(t.TempDir(), "pin-locks")
		runtime := newTestPinLockRuntime(t, lockRoot)
		replacement := []byte("replacement\n")
		runtime.beforeLockWrite = func(lockPath string) {
			if err := os.Rename(lockPath, lockPath+".swapped"); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(lockPath, replacement, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := acquirePinPathLock(
			context.Background(),
			resource,
			"apply",
			runtime,
		); err == nil || !strings.Contains(err.Error(), "changed") {
			t.Fatalf("lock swap error = %v", err)
		}
		content, err := os.ReadFile(filepath.Join(lockRoot, lockName))
		if err != nil {
			t.Fatal(err)
		}
		if string(content) != string(replacement) {
			t.Fatalf("replacement lock was modified: %q", content)
		}
	})
}

func TestApplyDetachAndStatusShareFailClosedPinPathValidation(t *testing.T) {
	const invalidPinPath = "relative-pin-path"
	state := &control.State{}
	loader := LinuxLoader{
		ObjectPath: "object-must-not-be-opened",
		PinPath:    invalidPinPath,
	}

	if err := loader.Apply(context.Background(), state); err == nil || !strings.Contains(err.Error(), "path must be absolute") {
		t.Fatalf("Apply error = %v", err)
	}
	if err := loader.Detach(context.Background(), state); err == nil || !strings.Contains(err.Error(), "path must be absolute") {
		t.Fatalf("Detach error = %v", err)
	}

	t.Setenv(EnvPinPath, invalidPinPath)
	status, err := inspect(context.Background(), state)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if status.PinPath != invalidPinPath {
		t.Fatalf("status pin path = %q, want invalid configured path to be reported without fallback", status.PinPath)
	}
	if !strings.Contains(status.MapError, "path must be absolute") {
		t.Fatalf("status MapError = %q", status.MapError)
	}
}

func TestBPFFSPinLifecycleIntegration(t *testing.T) {
	if os.Getenv(scopedBPFFSRunEnv) != "1" {
		t.Skip("set WG_MIX_EBPF_RUN_BPFFS_INTEGRATION=1 for an explicitly approved real bpffs test")
	}
	config, err := scopedBPFFSConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	runScopedBPFFSIntegration(t, config)
}

func newTestBPFFS(t *testing.T) (string, pinPathValidator) {
	t.Helper()
	bpffsRoot := filepath.Join(t.TempDir(), "bpffs")
	if err := os.Mkdir(bpffsRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	const testBPFFSMagic = int64(0x1234)
	bpffsFilesystem := pinPathFilesystem{
		fsType: testBPFFSMagic,
	}
	hostFilesystem := pinPathFilesystem{
		fsType: 0x4321,
	}
	isOnTestBPFFS := func(path string) bool {
		relative, err := filepath.Rel(bpffsRoot, filepath.Clean(path))
		return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
	}
	return bpffsRoot, pinPathValidator{
		bpffsMagic: testBPFFSMagic,
		statFS: func(path string) (pinPathFilesystem, error) {
			if isOnTestBPFFS(path) {
				return bpffsFilesystem, nil
			}
			return hostFilesystem, nil
		},
		mountID: func(path string) (uint64, error) {
			if isOnTestBPFFS(path) {
				return 101, nil
			}
			return 202, nil
		},
	}
}

func canonicalPinnedMapCollectionSpec() *ebpf.CollectionSpec {
	spec := &ebpf.CollectionSpec{
		Maps: make(map[string]*ebpf.MapSpec),
	}
	for _, descriptor := range pinnedMapDescriptors() {
		spec.Maps[descriptor.name] = &ebpf.MapSpec{
			Name:       descriptor.name,
			Type:       descriptor.mapType,
			KeySize:    descriptor.keySize,
			ValueSize:  descriptor.valueSize,
			MaxEntries: descriptor.maxEntries,
			Flags:      descriptor.flags,
		}
	}
	spec.Maps["icmp_seq_map"] = &ebpf.MapSpec{
		Name:       "icmp_seq_map",
		Type:       ebpf.LRUHash,
		KeySize:    24,
		ValueSize:  16,
		MaxEntries: 2048,
	}
	return spec
}

type fakePinnedMapStore struct {
	observations map[string]pinnedMapObservation
	loadErrors   map[string]error
	onLoad       func(string)
}

func newFakePinnedMapStore() *fakePinnedMapStore {
	return &fakePinnedMapStore{
		observations: make(map[string]pinnedMapObservation),
		loadErrors:   make(map[string]error),
	}
}

func (store *fakePinnedMapStore) load(path string, name string) (*pinnedMapObservation, error) {
	if !strings.HasPrefix(path, "/proc/self/fd/") {
		return nil, fmt.Errorf("pinned map path %q is not directory-FD anchored", path)
	}
	if err := store.loadErrors[name]; err != nil {
		return nil, err
	}
	observation, ok := store.observations[name]
	if !ok {
		return nil, fmt.Errorf("no fake pinned map %q", name)
	}
	if store.onLoad != nil {
		store.onLoad(name)
	}
	observation.close = func() error { return nil }
	return &observation, nil
}

func writeCanonicalMockPins(t *testing.T, pinPath string) *fakePinnedMapStore {
	t.Helper()
	if err := os.Mkdir(pinPath, 0o700); err != nil {
		t.Fatal(err)
	}
	store := newFakePinnedMapStore()
	for index, descriptor := range pinnedMapDescriptors() {
		if err := os.WriteFile(
			filepath.Join(pinPath, descriptor.name),
			[]byte("mock BPF pin: "+descriptor.name),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
		kernelName := descriptor.name
		if len(kernelName) > 15 {
			kernelName = kernelName[:15]
		}
		observation := pinnedMapObservation{
			id:         uint32(100 + index),
			mapType:    descriptor.mapType,
			keySize:    descriptor.keySize,
			valueSize:  descriptor.valueSize,
			maxEntries: descriptor.maxEntries,
			flags:      descriptor.flags,
			kernelName: kernelName,
		}
		name := descriptor.name
		observation.pin = func(path string) error {
			file, err := os.OpenFile(
				path,
				os.O_CREATE|os.O_EXCL|os.O_WRONLY,
				0o600,
			)
			if err != nil {
				return err
			}
			if _, err := file.WriteString("mock BPF pin: " + name); err != nil {
				_ = file.Close()
				return err
			}
			return file.Close()
		}
		if descriptor.name == "control_map" {
			observation.controlSeen = true
			observation.control = abi.ControlValue{
				ActiveGeneration: 1,
				ABIVersion:       abi.Version,
			}
			observation.updateControl = func(value abi.ControlValue) error {
				current := store.observations[name]
				current.control = value
				current.controlSeen = true
				store.observations[name] = current
				return nil
			}
		}
		if descriptor.name == "owner_map" {
			observation.ownerSeen = true
			observation.updateOwner = func(value pinOwnerSentinel) error {
				current := store.observations[name]
				current.owner = value
				current.ownerSeen = true
				store.observations[name] = current
				return nil
			}
		}
		store.observations[descriptor.name] = observation
	}
	return store
}

func newTestPinPathRuntime(
	t *testing.T,
	validator pinPathValidator,
	store *fakePinnedMapStore,
) pinPathRuntime {
	t.Helper()
	return pinPathRuntime{
		validator:            validator,
		lockRoot:             filepath.Join(t.TempDir(), "pin-locks"),
		ownerRoot:            filepath.Join(t.TempDir(), "pin-owners"),
		expectedUID:          uint32(os.Getuid()),
		bpffsRootMode:        0o700,
		allowUnsafeAncestors: true,
		mountIDAt: func(int, string, int) (uint64, error) {
			return 101, nil
		},
		loadPinnedMap: store.load,
	}
}

func newTestPinLockRuntime(t *testing.T, lockRoot string) pinPathRuntime {
	t.Helper()
	return pinPathRuntime{
		lockRoot:             lockRoot,
		expectedUID:          uint32(os.Getuid()),
		allowUnsafeAncestors: true,
	}
}

func newTestPinResource(t *testing.T, pinPath string) pinResourceIdentity {
	t.Helper()
	const (
		parentDevice = 42
		parentInode  = 99
	)
	base := filepath.Base(pinPath)
	key, err := pinidentity.Key(parentDevice, parentInode, base)
	if err != nil {
		t.Fatal(err)
	}
	return pinResourceIdentity{
		key:          key,
		parentDevice: parentDevice,
		parentInode:  parentInode,
		base:         base,
		pinPath:      pinPath,
	}
}

func executeTestCleanup(pinPath string, runtime pinPathRuntime) error {
	plan, err := preparePinnedMapCleanup(pinPath, runtime)
	if err != nil {
		return err
	}
	defer plan.Close()
	return plan.Execute()
}

func assertAllMockPinsExist(t *testing.T, pinPath string) {
	t.Helper()
	for _, name := range pinnedMapNames() {
		if _, err := os.Lstat(filepath.Join(pinPath, name)); err != nil {
			t.Fatalf("known pin %s was changed or removed: %v", name, err)
		}
	}
}

func assertFileContent(t *testing.T, path string, want string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(content) != want {
		t.Fatalf("%s content = %q, want %q", path, content, want)
	}
}
