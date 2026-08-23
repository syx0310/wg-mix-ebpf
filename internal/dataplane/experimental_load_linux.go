//go:build linux

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

// LoadExperimentalFakeTCPObjectTestIdentity verifier-loads every map and
// program in an explicitly supplied experimental object, then closes the
// collection without attaching, pinning, or populating any map.
func LoadExperimentalFakeTCPObjectTestIdentity(
	ctx context.Context,
	objectPath string,
) (ObjectIdentity, error) {
	if ctx == nil {
		return ObjectIdentity{}, errors.New("experimental FakeTCP BPF load: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return ObjectIdentity{}, err
	}
	if strings.TrimSpace(objectPath) == "" {
		return ObjectIdentity{}, fmt.Errorf("experimental FakeTCP BPF load requires an explicit non-empty object path")
	}
	spec, identity, err := loadCollectionSpec(objectPath)
	if err != nil {
		return ObjectIdentity{}, err
	}
	if err := ctx.Err(); err != nil {
		return ObjectIdentity{}, err
	}
	err = verifierLoadEveryExperimentalFakeTCPProgram(
		ctx,
		spec,
		identity.Source,
		liveExperimentalCollectionAcquisitionDependencies(),
	)
	if err != nil {
		return ObjectIdentity{}, err
	}
	return identity, nil
}

// LoadLegacy515FakeTCPObjectTestIdentity verifier-loads every program in an
// explicitly supplied legacy-5.15 FakeTCP object. Unlike the modern path it
// validates the kprobe bridge manifest and deliberately does not probe the
// modern kfunc dependency. It never attaches, pins, or seeds the collection.
func LoadLegacy515FakeTCPObjectTestIdentity(
	ctx context.Context,
	objectPath string,
) (ObjectIdentity, error) {
	if ctx == nil {
		return ObjectIdentity{}, errors.New("legacy-5.15 FakeTCP BPF load: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return ObjectIdentity{}, err
	}
	if strings.TrimSpace(objectPath) == "" {
		return ObjectIdentity{}, fmt.Errorf("legacy-5.15 FakeTCP BPF load requires an explicit non-empty object path")
	}
	spec, identity, err := loadFakeTCPLegacy515CollectionSpecFromResolvedPath(objectPath)
	if err != nil {
		return ObjectIdentity{}, err
	}
	if err := ctx.Err(); err != nil {
		return ObjectIdentity{}, err
	}
	dependencies := liveExperimentalCollectionAcquisitionDependencies()
	dependencies.probeKernelDependency = func() error { return nil }
	if err := verifierLoadEveryFakeTCPProgram(
		ctx,
		spec,
		identity.Source,
		"legacy-5.15 FakeTCP",
		validateLegacy515ExtensionManifest,
		dependencies,
	); err != nil {
		return ObjectIdentity{}, err
	}
	return identity, nil
}

// InspectExperimentalFakeTCPObjectTestPrograms validates an explicitly
// supplied modern FakeTCP object and returns its real, sorted program set
// without creating any kernel resource.
func InspectExperimentalFakeTCPObjectTestPrograms(
	ctx context.Context,
	objectPath string,
) (ObjectIdentity, []string, error) {
	return inspectFakeTCPObjectTestPrograms(
		ctx,
		objectPath,
		"experimental FakeTCP",
		loadCollectionSpec,
		validateExperimentalExtensionManifest,
	)
}

// InspectLegacy515FakeTCPObjectTestPrograms is the legacy-5.15 counterpart of
// InspectExperimentalFakeTCPObjectTestPrograms. Loading it on a newer kernel
// proves only that newer kernel's verifier acceptance; it does not claim 5.15
// compatibility.
func InspectLegacy515FakeTCPObjectTestPrograms(
	ctx context.Context,
	objectPath string,
) (ObjectIdentity, []string, error) {
	return inspectFakeTCPObjectTestPrograms(
		ctx,
		objectPath,
		"legacy-5.15 FakeTCP",
		loadFakeTCPLegacy515CollectionSpecFromResolvedPath,
		validateLegacy515ExtensionManifest,
	)
}

type fakeTCPVerifierSpecLoader func(string) (*ebpf.CollectionSpec, ObjectIdentity, error)

func inspectFakeTCPObjectTestPrograms(
	ctx context.Context,
	objectPath string,
	kind string,
	loadSpec fakeTCPVerifierSpecLoader,
	validateManifest func(*ebpf.CollectionSpec) error,
) (ObjectIdentity, []string, error) {
	if ctx == nil {
		return ObjectIdentity{}, nil, fmt.Errorf("inspect %s BPF object: context is nil", kind)
	}
	if err := ctx.Err(); err != nil {
		return ObjectIdentity{}, nil, err
	}
	if strings.TrimSpace(objectPath) == "" {
		return ObjectIdentity{}, nil, fmt.Errorf("inspect %s BPF object requires an explicit non-empty object path", kind)
	}
	if loadSpec == nil || validateManifest == nil {
		return ObjectIdentity{}, nil, fmt.Errorf("inspect %s BPF object: verifier dependency is nil", kind)
	}
	spec, identity, err := loadSpec(objectPath)
	if err != nil {
		return ObjectIdentity{}, nil, err
	}
	if err := validateManifest(spec); err != nil {
		return ObjectIdentity{}, nil, fmt.Errorf("validate %s BPF object %s: %w", kind, identity.Source, err)
	}
	names := sortedFakeTCPProgramNames(spec)
	if len(names) == 0 {
		return ObjectIdentity{}, nil, fmt.Errorf("validate %s BPF object %s: no programs", kind, identity.Source)
	}
	return identity, names, nil
}

// LoadExperimentalFakeTCPObjectProgramTestIdentity verifier-loads exactly one
// manifest-approved modern program in a fresh collection and closes it before
// returning.
func LoadExperimentalFakeTCPObjectProgramTestIdentity(
	ctx context.Context,
	objectPath string,
	programName string,
) (ObjectIdentity, error) {
	return loadFakeTCPObjectProgramTestIdentity(
		ctx,
		objectPath,
		programName,
		"experimental FakeTCP",
		loadCollectionSpec,
		validateExperimentalExtensionManifest,
		liveExperimentalCollectionAcquisitionDependencies(),
	)
}

// LoadLegacy515FakeTCPObjectProgramTestIdentity verifier-loads exactly one
// manifest-approved legacy program in a fresh collection. It deliberately
// skips the modern kfunc probe and makes no Linux 5.15 support claim.
func LoadLegacy515FakeTCPObjectProgramTestIdentity(
	ctx context.Context,
	objectPath string,
	programName string,
) (ObjectIdentity, error) {
	dependencies := liveExperimentalCollectionAcquisitionDependencies()
	dependencies.probeKernelDependency = func() error { return nil }
	return loadFakeTCPObjectProgramTestIdentity(
		ctx,
		objectPath,
		programName,
		"legacy-5.15 FakeTCP",
		loadFakeTCPLegacy515CollectionSpecFromResolvedPath,
		validateLegacy515ExtensionManifest,
		dependencies,
	)
}

func loadFakeTCPObjectProgramTestIdentity(
	ctx context.Context,
	objectPath string,
	programName string,
	kind string,
	loadSpec fakeTCPVerifierSpecLoader,
	validateManifest func(*ebpf.CollectionSpec) error,
	dependencies experimentalCollectionAcquisitionDependencies,
) (ObjectIdentity, error) {
	identity, names, err := inspectFakeTCPObjectTestPrograms(
		ctx, objectPath, kind, loadSpec, validateManifest,
	)
	if err != nil {
		return ObjectIdentity{}, err
	}
	if strings.TrimSpace(programName) == "" {
		return ObjectIdentity{}, fmt.Errorf("verifier-load %s requires an exact non-empty program name", kind)
	}
	index := sort.SearchStrings(names, programName)
	if index == len(names) || names[index] != programName {
		return ObjectIdentity{}, fmt.Errorf("verifier-load %s program %q: program is not in the validated object", kind, programName)
	}
	spec, loadedIdentity, err := loadSpec(objectPath)
	if err != nil {
		return ObjectIdentity{}, err
	}
	if loadedIdentity != identity {
		return ObjectIdentity{}, fmt.Errorf("verifier-load %s object identity changed during inspection", kind)
	}
	if err := verifierLoadOneFakeTCPProgram(
		ctx, spec, identity.Source, kind, programName, validateManifest, dependencies,
	); err != nil {
		return ObjectIdentity{}, err
	}
	return identity, nil
}

func sortedFakeTCPProgramNames(spec *ebpf.CollectionSpec) []string {
	names := make([]string, 0, len(spec.Programs))
	for name := range spec.Programs {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func verifierLoadOneFakeTCPProgram(
	ctx context.Context,
	spec *ebpf.CollectionSpec,
	source string,
	kind string,
	programName string,
	validateManifest func(*ebpf.CollectionSpec) error,
	dependencies experimentalCollectionAcquisitionDependencies,
) error {
	if err := validateManifest(spec); err != nil {
		return fmt.Errorf("validate %s BPF object %s: %w", kind, source, err)
	}
	if err := validateExperimentalCollectionAcquisitionDependencies(dependencies); err != nil {
		return err
	}
	if err := dependencies.probeKernelDependency(); err != nil {
		return fmt.Errorf("probe %s kernel dependency: %w", kind, err)
	}
	if err := dependencies.removeMemlock(); err != nil {
		return fmt.Errorf("remove %s memlock limit: %w", kind, err)
	}
	isolated := spec.Copy()
	for other := range isolated.Programs {
		if other != programName {
			delete(isolated.Programs, other)
		}
	}
	collection, err := dependencies.newCollection(isolated)
	if err != nil {
		failure := fmt.Errorf(
			"verifier-load %s program %q from %s: %w",
			kind, programName, source, err,
		)
		if collection != nil {
			failure = errors.Join(
				failure,
				closeUnownedExperimentalCollection(collection, source, dependencies),
			)
		}
		return failure
	}
	if collection == nil {
		return fmt.Errorf(
			"verifier-load %s program %q from %s: loader returned nil collection",
			kind, programName, source,
		)
	}
	return closeUnownedExperimentalCollection(collection, source, dependencies)
}

// verifierLoadEveryExperimentalFakeTCPProgram loads each manifest-approved
// program in an otherwise complete isolated collection. A rejected program
// doesn't hide verifier errors in later programs, so one diagnostic run
// reports the complete failing set. Every partial or successful collection is
// closed before the next program and nothing is attached, pinned, or seeded.
func verifierLoadEveryExperimentalFakeTCPProgram(
	ctx context.Context,
	spec *ebpf.CollectionSpec,
	source string,
	dependencies experimentalCollectionAcquisitionDependencies,
) error {
	return verifierLoadEveryFakeTCPProgram(
		ctx,
		spec,
		source,
		"experimental FakeTCP",
		validateExperimentalExtensionManifest,
		dependencies,
	)
}

func verifierLoadEveryFakeTCPProgram(
	ctx context.Context,
	spec *ebpf.CollectionSpec,
	source string,
	kind string,
	validateManifest func(*ebpf.CollectionSpec) error,
	dependencies experimentalCollectionAcquisitionDependencies,
) error {
	if ctx == nil {
		return fmt.Errorf("verifier-load %s BPF collection: context is nil", kind)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if validateManifest == nil {
		return fmt.Errorf("validate %s BPF object %s: no manifest validator", kind, source)
	}
	if err := validateManifest(spec); err != nil {
		return fmt.Errorf("validate %s BPF object %s: %w", kind, source, err)
	}
	if err := validateExperimentalCollectionAcquisitionDependencies(dependencies); err != nil {
		return err
	}
	if err := dependencies.probeKernelDependency(); err != nil {
		return fmt.Errorf("probe %s kernel dependency: %w", kind, err)
	}
	if err := dependencies.removeMemlock(); err != nil {
		return fmt.Errorf("remove %s memlock limit: %w", kind, err)
	}

	names := sortedFakeTCPProgramNames(spec)
	var failures []error
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			failures = append(failures, err)
			break
		}
		isolated := spec.Copy()
		for other := range isolated.Programs {
			if other != name {
				delete(isolated.Programs, other)
			}
		}
		collection, err := dependencies.newCollection(isolated)
		if err != nil {
			failure := fmt.Errorf(
				"verifier-load %s program %q from %s: %w",
				kind,
				name,
				source,
				err,
			)
			if collection != nil {
				failure = errors.Join(
					failure,
					closeUnownedExperimentalCollection(collection, source, dependencies),
				)
			}
			failures = append(failures, failure)
			continue
		}
		if collection == nil {
			failures = append(failures, fmt.Errorf(
				"verifier-load %s program %q from %s: loader returned nil collection",
				kind,
				name,
				source,
			))
			continue
		}
		if err := closeUnownedExperimentalCollection(collection, source, dependencies); err != nil {
			failures = append(failures, fmt.Errorf(
				"verifier-load %s program %q: %w",
				kind,
				name,
				err,
			))
		}
	}
	return errors.Join(failures...)
}

func loadExperimentalFakeTCPCollection(
	ctx context.Context,
	spec *ebpf.CollectionSpec,
	source string,
	dependencies experimentalCollectionAcquisitionDependencies,
) error {
	owner, err := acquireExperimentalFakeTCPCollection(ctx, spec, source, dependencies)
	if err != nil {
		return err
	}
	// This is deliberately verifier-only: acquisition can retain ownership for
	// a future runtime builder, while this path explicitly closes immediately.
	if err := ctx.Err(); err != nil {
		return errors.Join(err, closeExperimentalCollectionOwner(owner, source))
	}
	return closeExperimentalCollectionOwner(owner, source)
}

func probeExperimentalFakeTCPKernelDependency() error {
	return probeExperimentalFakeTCPKernelDependencyWith(btf.LoadKernelModuleSpec)
}

// ProbeFakeTCPKernelDependency performs the same read-only module BTF and
// exact-kfunc contract check used immediately before production activation.
// It never loads or unloads the administrator-owned module.
func ProbeFakeTCPKernelDependency() error {
	return probeExperimentalFakeTCPKernelDependency()
}

func probeExperimentalFakeTCPKernelDependencyWith(
	loadModule func(string) (*btf.Spec, error),
) error {
	if loadModule == nil {
		return fmt.Errorf("kernel module BTF loader is nil")
	}
	spec, err := loadModule(experimentalFakeTCPKfuncModule)
	if err != nil {
		return fmt.Errorf(
			"load required module BTF %q: %w",
			experimentalFakeTCPKfuncModule, err,
		)
	}
	if spec == nil {
		return fmt.Errorf("required module BTF %q is nil", experimentalFakeTCPKfuncModule)
	}
	for _, name := range experimentalFakeTCPKfuncNames {
		var function *btf.Func
		if err := spec.TypeByName(name, &function); err != nil {
			return fmt.Errorf(
				"required module %q has no kfunc BTF %q: %w",
				experimentalFakeTCPKfuncModule, name, err,
			)
		}
		if function == nil {
			return fmt.Errorf(
				"required module %q returned nil kfunc BTF %q",
				experimentalFakeTCPKfuncModule, name,
			)
		}
		if err := validateExperimentalFakeTCPKfuncPrototype(name, function); err != nil {
			return fmt.Errorf(
				"required module %q kfunc BTF %q has an incompatible prototype: %w",
				experimentalFakeTCPKfuncModule, name, err,
			)
		}
	}
	return nil
}

type experimentalFakeTCPKfuncParameterKind uint8

const (
	experimentalFakeTCPSKBPointerParameter experimentalFakeTCPKfuncParameterKind = iota + 1
	experimentalFakeTCPUnsigned32Parameter
	experimentalFakeTCPUnsigned64Parameter
)

var experimentalFakeTCPKfuncPrototypes = map[string][]experimentalFakeTCPKfuncParameterKind{
	experimentalFakeTCPPrepareKfuncName: {
		experimentalFakeTCPSKBPointerParameter,
		experimentalFakeTCPUnsigned32Parameter,
		experimentalFakeTCPUnsigned32Parameter,
		experimentalFakeTCPUnsigned32Parameter,
	},
	experimentalFakeTCPGSOCommitKfuncName: {
		experimentalFakeTCPSKBPointerParameter,
		experimentalFakeTCPUnsigned32Parameter,
		experimentalFakeTCPUnsigned32Parameter,
		experimentalFakeTCPUnsigned32Parameter,
		experimentalFakeTCPUnsigned64Parameter,
	},
}

func validateExperimentalFakeTCPKfuncPrototype(name string, function *btf.Func) error {
	wantParams, ok := experimentalFakeTCPKfuncPrototypes[name]
	if !ok {
		return fmt.Errorf("no reviewed prototype")
	}
	prototype, ok := btf.As[*btf.FuncProto](function.Type)
	if !ok || prototype == nil {
		return fmt.Errorf("type is %T, want FuncProto", function.Type)
	}
	if err := validateExperimentalFakeTCPScalarType(prototype.Return, 4, btf.Signed); err != nil {
		return fmt.Errorf("return type: %w", err)
	}
	if len(prototype.Params) != len(wantParams) {
		return fmt.Errorf("parameter count is %d, want %d", len(prototype.Params), len(wantParams))
	}
	for index, want := range wantParams {
		if err := validateExperimentalFakeTCPKfuncParameter(prototype.Params[index].Type, want); err != nil {
			return fmt.Errorf("parameter %d: %w", index, err)
		}
	}
	return nil
}

func validateExperimentalFakeTCPKfuncParameter(
	typeValue btf.Type,
	want experimentalFakeTCPKfuncParameterKind,
) error {
	switch want {
	case experimentalFakeTCPSKBPointerParameter:
		pointer, ok := btf.As[*btf.Pointer](typeValue)
		if !ok || pointer == nil {
			return fmt.Errorf("type is %T, want pointer to struct __sk_buff", typeValue)
		}
		target := btf.UnderlyingType(pointer.Target)
		switch value := target.(type) {
		case *btf.Struct:
			if value.Name != "__sk_buff" {
				return fmt.Errorf("pointer target struct is %q, want %q", value.Name, "__sk_buff")
			}
		case *btf.Fwd:
			if value.Kind != btf.FwdStruct || value.Name != "__sk_buff" {
				return fmt.Errorf("pointer target forward declaration is %s %q, want struct %q", value.Kind, value.Name, "__sk_buff")
			}
		default:
			return fmt.Errorf("pointer target is %T, want struct __sk_buff", target)
		}
		return nil
	case experimentalFakeTCPUnsigned32Parameter:
		return validateExperimentalFakeTCPScalarType(typeValue, 4, btf.Unsigned)
	case experimentalFakeTCPUnsigned64Parameter:
		return validateExperimentalFakeTCPScalarType(typeValue, 8, btf.Unsigned)
	default:
		return fmt.Errorf("unreviewed expected parameter kind %d", want)
	}
}

func validateExperimentalFakeTCPScalarType(
	typeValue btf.Type,
	wantSize uint32,
	wantEncoding btf.IntEncoding,
) error {
	integer, ok := btf.As[*btf.Int](typeValue)
	if !ok || integer == nil {
		return fmt.Errorf("type is %T, want %s %d-bit integer", typeValue, wantEncoding, wantSize*8)
	}
	if integer.Size != wantSize || integer.Encoding != wantEncoding {
		return fmt.Errorf(
			"integer is %s %d-bit, want %s %d-bit",
			integer.Encoding,
			integer.Size*8,
			wantEncoding,
			wantSize*8,
		)
	}
	return nil
}
