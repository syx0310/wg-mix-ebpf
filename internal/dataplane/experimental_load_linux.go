//go:build linux

package dataplane

import (
	"context"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

type experimentalCollectionCloser interface {
	Close() error
}

// LoadExperimentalFakeTCPObjectTestIdentity verifier-loads every map and
// program in an explicitly supplied experimental object, then closes the
// collection without attaching, pinning, or populating any map.
func LoadExperimentalFakeTCPObjectTestIdentity(
	ctx context.Context,
	objectPath string,
) (ObjectIdentity, error) {
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
	err = loadExperimentalFakeTCPCollection(
		spec,
		identity.Source,
		probeExperimentalFakeTCPKernelDependency,
		removeMemlockLimit,
		func(spec *ebpf.CollectionSpec) (experimentalCollectionCloser, error) {
			collection, err := ebpf.NewCollection(spec)
			if err != nil {
				return nil, err
			}
			owner, err := newExperimentalCollectionOwner(collection)
			if err != nil {
				collection.Close()
				return nil, err
			}
			return owner, nil
		},
	)
	if err != nil {
		return ObjectIdentity{}, err
	}
	return identity, nil
}

func loadExperimentalFakeTCPCollection(
	spec *ebpf.CollectionSpec,
	source string,
	probeKernelDependency func() error,
	removeMemlock func() error,
	newCollection func(*ebpf.CollectionSpec) (experimentalCollectionCloser, error),
) error {
	if err := validateExperimentalExtensionManifest(spec); err != nil {
		return fmt.Errorf("validate experimental FakeTCP BPF object %s: %w", source, err)
	}
	if probeKernelDependency == nil {
		return fmt.Errorf("probe experimental FakeTCP kernel dependency: no probe configured")
	}
	if err := probeKernelDependency(); err != nil {
		return fmt.Errorf("probe experimental FakeTCP kernel dependency: %w", err)
	}
	if err := removeMemlock(); err != nil {
		return err
	}
	collection, err := newCollection(spec)
	if err != nil {
		return fmt.Errorf("create experimental FakeTCP BPF collection from %s: %w", source, err)
	}
	if collection == nil {
		return fmt.Errorf("create experimental FakeTCP BPF collection from %s: loader returned nil collection", source)
	}
	if err := collection.Close(); err != nil {
		return fmt.Errorf("close experimental FakeTCP BPF collection from %s: %w", source, err)
	}
	return nil
}

func probeExperimentalFakeTCPKernelDependency() error {
	return probeExperimentalFakeTCPKernelDependencyWith(btf.LoadKernelModuleSpec)
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
	var function *btf.Func
	if err := spec.TypeByName(experimentalFakeTCPKfuncName, &function); err != nil {
		return fmt.Errorf(
			"required module %q has no kfunc BTF %q: %w",
			experimentalFakeTCPKfuncModule, experimentalFakeTCPKfuncName, err,
		)
	}
	if function == nil {
		return fmt.Errorf(
			"required module %q returned nil kfunc BTF %q",
			experimentalFakeTCPKfuncModule, experimentalFakeTCPKfuncName,
		)
	}
	return nil
}
