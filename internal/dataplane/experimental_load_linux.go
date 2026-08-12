//go:build linux

package dataplane

import (
	"context"
	"errors"
	"fmt"
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
	err = loadExperimentalFakeTCPCollection(
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
	}
	return nil
}
