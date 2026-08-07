//go:build linux

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
)

// acquireAndBuildExperimentalFakeTCPRuntime is the single ownership boundary
// between a verified collection spec and a complete experimental runtime. The
// call consumes buildOptions.transaction immediately: callers must not use or
// close it after invoking this function, regardless of the return value.
//
// The caller may not supply a collection owner. Acquisition installs the sole
// owner into a private copy of buildOptions, and buildExperimentalFakeTCPRuntime
// keeps its existing atomic claim, seed, reachability, and commit sequence.
// Before the builder claims the transaction this function closes both owned
// resources on failure. After a claim, the builder closes them itself; the
// closed-state checks prevent the same retained close error from being joined
// into the result twice. On success only the returned runtime owns collection,
// session, event, slow-path, and XDP resources, and the transaction is spent.
func acquireAndBuildExperimentalFakeTCPRuntime(
	ctx context.Context,
	spec *ebpf.CollectionSpec,
	source string,
	dependencies experimentalCollectionAcquisitionDependencies,
	buildOptions experimentalFakeTCPRuntimeBuildOptions,
) (*ExperimentalFakeTCPRuntime, error) {
	return acquireAndBuildExperimentalFakeTCPRuntimeWithBuilder(
		ctx,
		spec,
		source,
		dependencies,
		buildOptions,
		buildExperimentalFakeTCPRuntime,
	)
}

type experimentalFakeTCPRuntimeBuilder func(
	context.Context,
	experimentalFakeTCPRuntimeBuildOptions,
) (*ExperimentalFakeTCPRuntime, error)

// acquireAndBuildExperimentalFakeTCPRuntimeWithBuilder exposes only the final
// builder call as a package-local test seam. The production entrypoint above
// always supplies buildExperimentalFakeTCPRuntime.
func acquireAndBuildExperimentalFakeTCPRuntimeWithBuilder(
	ctx context.Context,
	spec *ebpf.CollectionSpec,
	source string,
	dependencies experimentalCollectionAcquisitionDependencies,
	buildOptions experimentalFakeTCPRuntimeBuildOptions,
	builder experimentalFakeTCPRuntimeBuilder,
) (
	runtime *ExperimentalFakeTCPRuntime,
	returnErr error,
) {
	transaction := buildOptions.transaction
	var owner *experimentalCollectionOwner

	// This defer is installed before validation because passing the transaction
	// transfers ownership at function entry, including malformed-input paths.
	defer func() {
		if returnErr == nil {
			return
		}
		if runtime != nil {
			returnErr = errors.Join(
				returnErr,
				wrapExperimentalRuntimeClose("failed factory result", runtime),
			)
			runtime = nil
		}
		if owner != nil && !owner.isClosed() {
			returnErr = errors.Join(
				returnErr,
				closeExperimentalCollectionOwner(owner, source),
			)
		}
		if transaction != nil && !transaction.isClosed() {
			if err := transaction.Close(); err != nil {
				returnErr = errors.Join(
					returnErr,
					fmt.Errorf("close experimental FakeTCP factory generation transaction: %w", err),
				)
			}
		}
	}()

	switch {
	case ctx == nil:
		return nil, errors.New("acquire and build experimental FakeTCP runtime: context is nil")
	case buildOptions.transaction == nil:
		return nil, fmt.Errorf(
			"acquire and build experimental FakeTCP runtime: %w",
			errFakeTCPPolicyGenerationLeaseRequired,
		)
	case buildOptions.collection != nil:
		return nil, errors.New(
			"acquire and build experimental FakeTCP runtime: caller-supplied collection owner is forbidden",
		)
	case spec == nil:
		return nil, errors.New("acquire and build experimental FakeTCP runtime: collection spec is nil")
	case strings.TrimSpace(source) == "":
		return nil, errors.New("acquire and build experimental FakeTCP runtime: source is empty")
	case builder == nil:
		return nil, errors.New("acquire and build experimental FakeTCP runtime: builder is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var err error
	owner, err = acquireExperimentalFakeTCPCollection(ctx, spec, source, dependencies)
	if err != nil {
		return nil, err
	}

	buildOptions.collection = owner
	runtime, err = builder(ctx, buildOptions)
	if err != nil {
		// Preserve an anomalous non-nil result for the cleanup defer. The fixed
		// production builder currently returns nil with every error, but this
		// boundary must remain leak-free if that implementation later changes.
		return runtime, err
	}
	if runtime == nil {
		return nil, errors.New(
			"acquire and build experimental FakeTCP runtime: builder returned a nil runtime",
		)
	}
	if !experimentalFakeTCPRuntimeOwnsExactCollection(runtime, owner) {
		return runtime, errors.New(
			"acquire and build experimental FakeTCP runtime: returned runtime does not own the exact acquired collection",
		)
	}
	if !transaction.isClosed() {
		return runtime, errors.New(
			"acquire and build experimental FakeTCP runtime: successful builder left generation transaction open",
		)
	}

	// The runtime now holds owner. Clearing the local pointer documents the
	// successful transfer; returnErr remains nil so the cleanup defer is inert.
	owner = nil
	return runtime, nil
}

// experimentalFakeTCPRuntimeOwnsExactCollection proves that a builder success
// transferred the exact acquisition owner into a live runtime state. The lock
// order matches runtime shutdown (state before collection); Close releases the
// state lock before it enters the collection owner, so this nested read cannot
// deadlock with normal teardown.
func experimentalFakeTCPRuntimeOwnsExactCollection(
	runtime *ExperimentalFakeTCPRuntime,
	owner *experimentalCollectionOwner,
) bool {
	if runtime == nil || runtime.state == nil || owner == nil {
		return false
	}
	state := runtime.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.closing || state.closed || state.collection != owner {
		return false
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	return !owner.closing && !owner.closed
}
