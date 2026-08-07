//go:build linux

package dataplane

import (
	"context"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
)

type experimentalCollectionCloser interface {
	Close()
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
		removeMemlockLimit,
		func(spec *ebpf.CollectionSpec) (experimentalCollectionCloser, error) {
			return ebpf.NewCollection(spec)
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
	removeMemlock func() error,
	newCollection func(*ebpf.CollectionSpec) (experimentalCollectionCloser, error),
) error {
	if err := validateExperimentalExtensionManifest(spec); err != nil {
		return fmt.Errorf("validate experimental FakeTCP BPF object %s: %w", source, err)
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
	collection.Close()
	return nil
}
