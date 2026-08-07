//go:build linux

package dataplane

import (
	"context"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
)

// experimentalCollectionAcquisitionDependencies keeps the live kernel steps
// injectable without weakening the ownership boundary. A non-nil owner
// returned by newOwner means ownership has moved out of the raw collection,
// even when newOwner also returns an error. Returning a nil owner leaves the
// raw collection owned by the acquisition path.
type experimentalCollectionAcquisitionDependencies struct {
	probeKernelDependency  func() error
	removeMemlock          func() error
	newCollection          func(*ebpf.CollectionSpec) (*ebpf.Collection, error)
	newOwner               func(*ebpf.Collection) (*experimentalCollectionOwner, error)
	closeUnownedCollection func(*ebpf.Collection) error
}

func liveExperimentalCollectionAcquisitionDependencies() experimentalCollectionAcquisitionDependencies {
	return experimentalCollectionAcquisitionDependencies{
		probeKernelDependency: probeExperimentalFakeTCPKernelDependency,
		removeMemlock:         removeMemlockLimit,
		newCollection: func(spec *ebpf.CollectionSpec) (*ebpf.Collection, error) {
			return ebpf.NewCollection(spec)
		},
		newOwner: newExperimentalCollectionOwner,
		closeUnownedCollection: func(collection *ebpf.Collection) error {
			if collection != nil {
				collection.Close()
			}
			return nil
		},
	}
}

// acquireExperimentalFakeTCPCollection validates and verifier-loads an
// unpinned experimental collection, then transfers sole ownership to an
// experimentalCollectionOwner. It does not attach programs, pin resources,
// populate policy, or make the generation reachable.
//
// Every expensive kernel boundary has a cancellation checkpoint on both
// sides. Once a kernel collection exists, cancellation and all later failures
// close its current sole owner synchronously before returning.
func acquireExperimentalFakeTCPCollection(
	ctx context.Context,
	spec *ebpf.CollectionSpec,
	source string,
	dependencies experimentalCollectionAcquisitionDependencies,
) (*experimentalCollectionOwner, error) {
	if ctx == nil {
		return nil, errors.New("acquire experimental FakeTCP BPF collection: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateExperimentalExtensionManifest(spec); err != nil {
		return nil, fmt.Errorf("validate experimental FakeTCP BPF object %s: %w", source, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateExperimentalCollectionAcquisitionDependencies(dependencies); err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := dependencies.probeKernelDependency(); err != nil {
		return nil, errors.Join(
			fmt.Errorf("probe experimental FakeTCP kernel dependency: %w", err),
			ctx.Err(),
		)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if err := dependencies.removeMemlock(); err != nil {
		return nil, errors.Join(
			fmt.Errorf("remove experimental FakeTCP memlock limit: %w", err),
			ctx.Err(),
		)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	collection, err := dependencies.newCollection(spec)
	if err != nil {
		loadErr := errors.Join(
			fmt.Errorf(
				"create experimental FakeTCP BPF collection from %s: %w",
				source,
				err,
			),
			ctx.Err(),
		)
		if collection == nil {
			return nil, loadErr
		}
		return nil, errors.Join(
			loadErr,
			closeUnownedExperimentalCollection(collection, source, dependencies),
		)
	}
	if collection == nil {
		return nil, errors.Join(
			fmt.Errorf(
				"create experimental FakeTCP BPF collection from %s: loader returned nil collection",
				source,
			),
			ctx.Err(),
		)
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(
			err,
			closeUnownedExperimentalCollection(collection, source, dependencies),
		)
	}

	owner, ownerErr := dependencies.newOwner(collection)
	if owner != nil {
		// A non-nil result is the factory's explicit ownership-transfer signal.
		// Never close the raw collection after this point.
		collection = nil
	}
	if ownerErr != nil {
		ownerErr = errors.Join(
			fmt.Errorf(
				"construct experimental FakeTCP collection owner from %s: %w",
				source,
				ownerErr,
			),
			ctx.Err(),
		)
		if owner != nil {
			return nil, errors.Join(
				ownerErr,
				closeExperimentalCollectionOwner(owner, source),
			)
		}
		return nil, errors.Join(
			ownerErr,
			closeUnownedExperimentalCollection(collection, source, dependencies),
		)
	}
	if owner == nil {
		return nil, errors.Join(
			fmt.Errorf(
				"construct experimental FakeTCP collection owner from %s: factory returned nil owner",
				source,
			),
			ctx.Err(),
			closeUnownedExperimentalCollection(collection, source, dependencies),
		)
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(err, closeExperimentalCollectionOwner(owner, source))
	}
	return owner, nil
}

func validateExperimentalCollectionAcquisitionDependencies(
	dependencies experimentalCollectionAcquisitionDependencies,
) error {
	switch {
	case dependencies.probeKernelDependency == nil:
		return errors.New("probe experimental FakeTCP kernel dependency: no probe configured")
	case dependencies.removeMemlock == nil:
		return errors.New("remove experimental FakeTCP memlock limit: no implementation configured")
	case dependencies.newCollection == nil:
		return errors.New("create experimental FakeTCP BPF collection: no factory configured")
	case dependencies.newOwner == nil:
		return errors.New("construct experimental FakeTCP collection owner: no factory configured")
	case dependencies.closeUnownedCollection == nil:
		return errors.New("close unowned experimental FakeTCP collection: no closer configured")
	default:
		return nil
	}
}

func closeUnownedExperimentalCollection(
	collection *ebpf.Collection,
	source string,
	dependencies experimentalCollectionAcquisitionDependencies,
) error {
	if collection == nil {
		return nil
	}
	if err := dependencies.closeUnownedCollection(collection); err != nil {
		return fmt.Errorf(
			"close unowned experimental FakeTCP BPF collection from %s: %w",
			source,
			err,
		)
	}
	return nil
}

func closeExperimentalCollectionOwner(
	owner *experimentalCollectionOwner,
	source string,
) error {
	if owner == nil {
		return nil
	}
	if err := owner.Close(); err != nil {
		return fmt.Errorf(
			"close experimental FakeTCP BPF collection from %s: %w",
			source,
			err,
		)
	}
	return nil
}
