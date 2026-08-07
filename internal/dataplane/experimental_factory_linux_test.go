//go:build linux

package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/syx0310/wg-mix-ebpf/internal/lockfile"
)

type experimentalRuntimeFactoryFixture struct {
	ctx          context.Context
	transaction  *fakeTCPPolicyGenerationTransaction
	acquisition  *experimentalAcquisitionFixture
	runtime      *runtimeTestFixture
	spec         *ebpf.CollectionSpec
	source       string
	dependencies experimentalCollectionAcquisitionDependencies
	options      experimentalFakeTCPRuntimeBuildOptions
}

func newExperimentalRuntimeFactoryFixture(
	t *testing.T,
	generation uint64,
) *experimentalRuntimeFactoryFixture {
	t.Helper()
	runtimeFixture := newRuntimeTestFixture(t)
	snapshot := mustFakeTCPPolicySnapshot(t, generation)
	ctx, transaction, _ := newTestFakeTCPPolicyGenerationTransaction(t, generation)
	acquisition := newExperimentalAcquisitionFixture()
	dependencies := acquisition.dependencies(t)
	dependencies.newOwner = func(got *ebpf.Collection) (*experimentalCollectionOwner, error) {
		acquisition.order = append(acquisition.order, "new-owner")
		if got != acquisition.raw {
			t.Fatal("runtime factory owner received an unrelated raw collection")
		}
		return runtimeFixture.collection, nil
	}
	options := runtimeFixture.buildOptions(snapshot, transaction)
	options.collection = nil
	return &experimentalRuntimeFactoryFixture{
		ctx:          ctx,
		transaction:  transaction,
		acquisition:  acquisition,
		runtime:      runtimeFixture,
		spec:         canonicalExperimentalCollectionSpec(),
		source:       "/reviewed/experimental.o",
		dependencies: dependencies,
		options:      options,
	}
}

func (fixture *experimentalRuntimeFactoryFixture) build(
	ctx context.Context,
) (*ExperimentalFakeTCPRuntime, error) {
	return acquireAndBuildExperimentalFakeTCPRuntime(
		ctx,
		fixture.spec,
		fixture.source,
		fixture.dependencies,
		fixture.options,
	)
}

func installFactoryTransactionClose(
	t *testing.T,
	transaction *fakeTCPPolicyGenerationTransaction,
	closeErr error,
) *int {
	t.Helper()
	closeCalls := new(int)
	transaction.closeLifecycleLease = func(lease *lockfile.LifecycleLease) error {
		*closeCalls++
		return errors.Join(lease.Close(), closeErr)
	}
	return closeCalls
}

func assertFactoryCollectionCloseCount(
	t *testing.T,
	fixture *runtimeTestFixture,
	want int,
) {
	t.Helper()
	for name, resource := range fixture.mapResources {
		if resource.closes != want {
			t.Fatalf("map %s close count = %d, want %d", name, resource.closes, want)
		}
	}
	for name, resource := range fixture.programs {
		if resource.closes != want {
			t.Fatalf("program %s close count = %d, want %d", name, resource.closes, want)
		}
	}
}

func TestExperimentalRuntimeFactoryAcquisitionFailureConsumesTransaction(t *testing.T) {
	fixture := newExperimentalRuntimeFactoryFixture(t, 91)
	wantErr := errors.New("injected kernel dependency failure")
	fixture.dependencies.probeKernelDependency = func() error {
		fixture.acquisition.order = append(fixture.acquisition.order, "kernel-dependency")
		return wantErr
	}
	closeCalls := installFactoryTransactionClose(t, fixture.transaction, nil)

	runtime, err := fixture.build(fixture.ctx)
	if runtime != nil || !errors.Is(err, wantErr) {
		t.Fatalf("runtime=%#v error=%v", runtime, err)
	}
	if !fixture.transaction.isClosed() || *closeCalls != 1 {
		t.Fatalf("transaction closed=%t close calls=%d", fixture.transaction.isClosed(), *closeCalls)
	}
	if got := strings.Join(fixture.acquisition.order, ","); got != "kernel-dependency" {
		t.Fatalf("acquisition order = %q", got)
	}
	if fixture.acquisition.rawCloseCalls != 0 {
		t.Fatalf("raw collection close calls = %d", fixture.acquisition.rawCloseCalls)
	}
	assertFactoryCollectionCloseCount(t, fixture.runtime, 0)
}

func TestExperimentalRuntimeFactoryPreservesTransactionCloseErrorOnce(t *testing.T) {
	fixture := newExperimentalRuntimeFactoryFixture(t, 91)
	acquisitionErr := errors.New("injected acquisition failure")
	transactionErr := errors.New("injected transaction close failure")
	fixture.dependencies.probeKernelDependency = func() error { return acquisitionErr }
	closeCalls := installFactoryTransactionClose(t, fixture.transaction, transactionErr)

	runtime, err := fixture.build(fixture.ctx)
	if runtime != nil || !errors.Is(err, acquisitionErr) || !errors.Is(err, transactionErr) {
		t.Fatalf("runtime=%#v error=%v", runtime, err)
	}
	if *closeCalls != 1 || !fixture.transaction.isClosed() {
		t.Fatalf("transaction closes=%d closed=%t", *closeCalls, fixture.transaction.isClosed())
	}
	if strings.Count(err.Error(), transactionErr.Error()) != 1 {
		t.Fatalf("transaction close error duplicated: %v", err)
	}
}

func TestExperimentalRuntimeFactoryBuilderPreClaimFailureClosesBothOwners(t *testing.T) {
	fixture := newExperimentalRuntimeFactoryFixture(t, 91)
	closeCalls := installFactoryTransactionClose(t, fixture.transaction, nil)
	otherRoot := t.TempDir()
	wrongCtx := lockfile.WithLifecyclePathsForTest(
		t.Context(),
		filepath.Join(otherRoot, "other-daemon.lease"),
		filepath.Join(otherRoot, "other-maintenance.gate"),
	)

	runtime, err := fixture.build(wrongCtx)
	if runtime != nil || err == nil || !strings.Contains(err.Error(), "does not match transaction path") {
		t.Fatalf("runtime=%#v error=%v", runtime, err)
	}
	if !fixture.transaction.isClosed() || *closeCalls != 1 {
		t.Fatalf("transaction closed=%t closes=%d", fixture.transaction.isClosed(), *closeCalls)
	}
	if fixture.acquisition.rawCloseCalls != 0 {
		t.Fatalf("raw collection close calls = %d", fixture.acquisition.rawCloseCalls)
	}
	assertFactoryCollectionCloseCount(t, fixture.runtime, 1)
	if fixture.runtime.sessionStore.closes != 0 || fixture.runtime.commitCalls != 0 {
		t.Fatalf(
			"pre-claim session closes=%d commit calls=%d",
			fixture.runtime.sessionStore.closes,
			fixture.runtime.commitCalls,
		)
	}
}

func TestExperimentalRuntimeFactoryClaimedPrepareFailureClosesExactlyOnce(t *testing.T) {
	fixture := newExperimentalRuntimeFactoryFixture(t, 91)
	prepareErr := "does not match snapshot generation"
	collectionErr := errors.New("injected collection close failure")
	transactionErr := errors.New("injected claimed transaction close failure")
	fixture.options.engineOptions.Generation++
	fixture.runtime.mapResources[fakeTCPSessionMapName].closeErr = collectionErr
	closeCalls := installFactoryTransactionClose(t, fixture.transaction, transactionErr)

	runtime, err := fixture.build(fixture.ctx)
	if runtime != nil || err == nil || !strings.Contains(err.Error(), prepareErr) ||
		!errors.Is(err, collectionErr) || !errors.Is(err, transactionErr) {
		t.Fatalf("runtime=%#v error=%v", runtime, err)
	}
	if *closeCalls != 1 || !fixture.transaction.isClosed() {
		t.Fatalf("transaction closes=%d closed=%t", *closeCalls, fixture.transaction.isClosed())
	}
	if strings.Count(err.Error(), collectionErr.Error()) != 1 ||
		strings.Count(err.Error(), transactionErr.Error()) != 1 {
		t.Fatalf("builder cleanup error was joined more than once: %v", err)
	}
	assertFactoryCollectionCloseCount(t, fixture.runtime, 1)
	if fixture.runtime.sessionStore.closes != 0 || fixture.runtime.commitCalls != 0 {
		t.Fatalf(
			"prepare failure session closes=%d commit calls=%d",
			fixture.runtime.sessionStore.closes,
			fixture.runtime.commitCalls,
		)
	}
}

func TestExperimentalRuntimeFactoryCommittedFailureDoesNotRecloseOwners(t *testing.T) {
	fixture := newExperimentalRuntimeFactoryFixture(t, 91)
	commitErr := errors.New("injected committed transaction close failure")
	closeCalls := installFactoryTransactionClose(t, fixture.transaction, commitErr)

	runtime, err := fixture.build(fixture.ctx)
	if runtime != nil || !errors.Is(err, commitErr) {
		t.Fatalf("runtime=%#v error=%v", runtime, err)
	}
	if *closeCalls != 1 || !fixture.transaction.isClosed() {
		t.Fatalf("transaction closes=%d closed=%t", *closeCalls, fixture.transaction.isClosed())
	}
	if strings.Count(err.Error(), commitErr.Error()) != 1 {
		t.Fatalf("committed close error duplicated: %v", err)
	}
	if len(fixture.runtime.programArray.deletes) != 0 ||
		len(fixture.runtime.policyTrace.deleteAttempts) != 0 {
		t.Fatalf(
			"committed failure rolled back reachable state: programs=%v policy=%v",
			fixture.runtime.programArray.deletes,
			fixture.runtime.policyTrace.deleteAttempts,
		)
	}
	assertFactoryCollectionCloseCount(t, fixture.runtime, 1)
	if fixture.runtime.sessionStore.closes != 1 {
		t.Fatalf("session close count = %d", fixture.runtime.sessionStore.closes)
	}
	if _, _, closes := fixture.runtime.slowPath.counts(); closes != 1 {
		t.Fatalf("slow-path close count = %d", closes)
	}
	for ifindex, link := range fixture.runtime.xdpRuntime.links {
		if link.closes != 1 {
			t.Fatalf("XDP link %d close count = %d", ifindex, link.closes)
		}
	}
}

func TestExperimentalRuntimeFactoryCancellationConsumesTransaction(t *testing.T) {
	fixture := newExperimentalRuntimeFactoryFixture(t, 91)
	ctx, cancel := context.WithCancel(fixture.ctx)
	closeCalls := installFactoryTransactionClose(t, fixture.transaction, nil)
	fixture.dependencies.newOwner = func(*ebpf.Collection) (*experimentalCollectionOwner, error) {
		fixture.acquisition.order = append(fixture.acquisition.order, "new-owner")
		cancel()
		return fixture.runtime.collection, nil
	}

	runtime, err := fixture.build(ctx)
	if runtime != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("runtime=%#v error=%v", runtime, err)
	}
	if *closeCalls != 1 || !fixture.transaction.isClosed() {
		t.Fatalf("transaction closes=%d closed=%t", *closeCalls, fixture.transaction.isClosed())
	}
	if got, want := strings.Join(fixture.acquisition.order, ","),
		"kernel-dependency,remove-memlock,new-collection,new-owner"; got != want {
		t.Fatalf("canceled acquisition order = %q", got)
	}
	if fixture.acquisition.rawCloseCalls != 0 {
		t.Fatalf("raw collection close calls = %d", fixture.acquisition.rawCloseCalls)
	}
	assertFactoryCollectionCloseCount(t, fixture.runtime, 1)
}

func TestExperimentalRuntimeFactorySuccessTransfersOnlyRuntimeOwnership(t *testing.T) {
	fixture := newExperimentalRuntimeFactoryFixture(t, 91)
	closeCalls := installFactoryTransactionClose(t, fixture.transaction, nil)

	runtime, err := fixture.build(fixture.ctx)
	if err != nil || runtime == nil {
		t.Fatalf("runtime=%#v error=%v", runtime, err)
	}
	if !fixture.transaction.isClosed() || *closeCalls != 1 {
		t.Fatalf("transaction closed=%t closes=%d", fixture.transaction.isClosed(), *closeCalls)
	}
	if got, want := strings.Join(fixture.acquisition.order, ","),
		"kernel-dependency,remove-memlock,new-collection,new-owner"; got != want {
		t.Fatalf("factory order = %q, want %q", got, want)
	}
	if fixture.acquisition.rawCloseCalls != 0 {
		t.Fatalf("raw collection close calls = %d", fixture.acquisition.rawCloseCalls)
	}
	assertFactoryCollectionCloseCount(t, fixture.runtime, 0)
	if fixture.runtime.sessionStore.closes != 0 {
		t.Fatalf("live runtime session close count = %d", fixture.runtime.sessionStore.closes)
	}
	if _, _, closes := fixture.runtime.slowPath.counts(); closes != 0 {
		t.Fatalf("live runtime slow-path close count = %d", closes)
	}

	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	assertFactoryCollectionCloseCount(t, fixture.runtime, 1)
	if fixture.runtime.sessionStore.closes != 1 {
		t.Fatalf("closed runtime session close count = %d", fixture.runtime.sessionStore.closes)
	}
	if _, _, closes := fixture.runtime.slowPath.counts(); closes != 1 {
		t.Fatalf("closed runtime slow-path close count = %d", closes)
	}
	for ifindex, link := range fixture.runtime.xdpRuntime.links {
		if link.closes != 1 {
			t.Fatalf("closed runtime XDP link %d close count = %d", ifindex, link.closes)
		}
	}
	if err := fixture.transaction.Close(); err != nil || *closeCalls != 1 {
		t.Fatalf("spent transaction close=%v underlying closes=%d", err, *closeCalls)
	}
}

func TestExperimentalRuntimeFactoryInputsFailClosedBeforeAcquisition(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(*experimentalRuntimeFactoryFixture) context.Context
		match     string
	}{
		{
			name:      "nil context",
			configure: func(*experimentalRuntimeFactoryFixture) context.Context { return nil },
			match:     "context is nil",
		},
		{
			name: "nil spec",
			configure: func(fixture *experimentalRuntimeFactoryFixture) context.Context {
				fixture.spec = nil
				return fixture.ctx
			},
			match: "collection spec is nil",
		},
		{
			name: "empty source",
			configure: func(fixture *experimentalRuntimeFactoryFixture) context.Context {
				fixture.source = " \t\n"
				return fixture.ctx
			},
			match: "source is empty",
		},
		{
			name: "caller supplied collection",
			configure: func(fixture *experimentalRuntimeFactoryFixture) context.Context {
				fixture.options.collection = fixture.runtime.collection
				return fixture.ctx
			},
			match: "caller-supplied collection owner is forbidden",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newExperimentalRuntimeFactoryFixture(t, 91)
			closeCalls := installFactoryTransactionClose(t, fixture.transaction, nil)
			ctx := test.configure(fixture)
			runtime, err := fixture.build(ctx)
			if runtime != nil || err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("runtime=%#v error=%v", runtime, err)
			}
			if !fixture.transaction.isClosed() || *closeCalls != 1 {
				t.Fatalf(
					"transaction closed=%t closes=%d",
					fixture.transaction.isClosed(),
					*closeCalls,
				)
			}
			if len(fixture.acquisition.order) != 0 {
				t.Fatalf("invalid input reached acquisition: %v", fixture.acquisition.order)
			}
			assertFactoryCollectionCloseCount(t, fixture.runtime, 0)
		})
	}
}

func TestExperimentalRuntimeFactoryRejectsMissingDependenciesAndTransaction(t *testing.T) {
	t.Run("missing dependency", func(t *testing.T) {
		fixture := newExperimentalRuntimeFactoryFixture(t, 91)
		fixture.dependencies.newCollection = nil
		closeCalls := installFactoryTransactionClose(t, fixture.transaction, nil)
		runtime, err := fixture.build(fixture.ctx)
		if runtime != nil || err == nil || !strings.Contains(err.Error(), "no factory configured") {
			t.Fatalf("runtime=%#v error=%v", runtime, err)
		}
		if !fixture.transaction.isClosed() || *closeCalls != 1 {
			t.Fatalf("transaction closed=%t closes=%d", fixture.transaction.isClosed(), *closeCalls)
		}
		if len(fixture.acquisition.order) != 0 {
			t.Fatalf("missing dependency reached kernel acquisition: %v", fixture.acquisition.order)
		}
	})

	t.Run("missing builder", func(t *testing.T) {
		fixture := newExperimentalRuntimeFactoryFixture(t, 91)
		closeCalls := installFactoryTransactionClose(t, fixture.transaction, nil)
		runtime, err := acquireAndBuildExperimentalFakeTCPRuntimeWithBuilder(
			fixture.ctx,
			fixture.spec,
			fixture.source,
			fixture.dependencies,
			fixture.options,
			nil,
		)
		if runtime != nil || err == nil || !strings.Contains(err.Error(), "builder is nil") {
			t.Fatalf("runtime=%#v error=%v", runtime, err)
		}
		if !fixture.transaction.isClosed() || *closeCalls != 1 {
			t.Fatalf("transaction closed=%t closes=%d", fixture.transaction.isClosed(), *closeCalls)
		}
		if len(fixture.acquisition.order) != 0 {
			t.Fatalf("missing builder reached acquisition: %v", fixture.acquisition.order)
		}
	})

	t.Run("missing transaction", func(t *testing.T) {
		fixture := newExperimentalRuntimeFactoryFixture(t, 91)
		fixture.options.transaction = nil
		runtime, err := fixture.build(fixture.ctx)
		if runtime != nil || !errors.Is(err, errFakeTCPPolicyGenerationLeaseRequired) {
			t.Fatalf("runtime=%#v error=%v", runtime, err)
		}
		if len(fixture.acquisition.order) != 0 {
			t.Fatalf("missing transaction reached acquisition: %v", fixture.acquisition.order)
		}
	})
}

func TestExperimentalRuntimeFactoryClosesUnexpectedRuntimeReturnedWithError(t *testing.T) {
	fixture := newExperimentalRuntimeFactoryFixture(t, 91)
	closeCalls := installFactoryTransactionClose(t, fixture.transaction, nil)
	wantErr := errors.New("injected builder result error")
	builderCalls := 0

	runtime, err := acquireAndBuildExperimentalFakeTCPRuntimeWithBuilder(
		fixture.ctx,
		fixture.spec,
		fixture.source,
		fixture.dependencies,
		fixture.options,
		func(
			_ context.Context,
			options experimentalFakeTCPRuntimeBuildOptions,
		) (*ExperimentalFakeTCPRuntime, error) {
			builderCalls++
			if options.collection != fixture.runtime.collection {
				t.Fatal("builder did not receive the acquired collection owner")
			}
			return &ExperimentalFakeTCPRuntime{
				state: &experimentalFakeTCPRuntimeState{
					collection: options.collection,
					closeDone:  make(chan struct{}),
				},
			}, wantErr
		},
	)
	if runtime != nil || !errors.Is(err, wantErr) {
		t.Fatalf("runtime=%#v error=%v", runtime, err)
	}
	if builderCalls != 1 {
		t.Fatalf("builder calls = %d", builderCalls)
	}
	if !fixture.transaction.isClosed() || *closeCalls != 1 {
		t.Fatalf("transaction closed=%t closes=%d", fixture.transaction.isClosed(), *closeCalls)
	}
	assertFactoryCollectionCloseCount(t, fixture.runtime, 1)
	if strings.Count(err.Error(), wantErr.Error()) != 1 {
		t.Fatalf("builder error duplicated: %v", err)
	}
}

func TestExperimentalOwnershipClosedStateHelpers(t *testing.T) {
	fixture := newExperimentalRuntimeFactoryFixture(t, 91)
	if fixture.runtime.collection.isClosed() || fixture.transaction.isClosed() {
		t.Fatal("fresh owners reported closed")
	}

	const readers = 16
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wait sync.WaitGroup
	for range readers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			for range 128 {
				_ = fixture.runtime.collection.isClosed()
				_ = fixture.transaction.isClosed()
			}
		}()
	}
	wait.Add(2)
	go func() {
		defer wait.Done()
		<-start
		errs <- fixture.runtime.collection.Close()
	}()
	go func() {
		defer wait.Done()
		<-start
		errs <- fixture.transaction.Close()
	}()
	close(start)
	wait.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if !fixture.runtime.collection.isClosed() || !fixture.transaction.isClosed() {
		t.Fatal("closed owners reported open")
	}
	if !(*experimentalCollectionOwner)(nil).isClosed() ||
		!(*fakeTCPPolicyGenerationTransaction)(nil).isClosed() {
		t.Fatal("nil owners did not report terminal state")
	}
}

func TestExperimentalRuntimeFactorySourceDoesNotCreateProductionCaller(t *testing.T) {
	for _, candidate := range []string{
		"../daemon/daemon.go",
		"loader_linux.go",
	} {
		contents, err := os.ReadFile(candidate)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(contents), "acquireAndBuildExperimentalFakeTCPRuntime") {
			t.Fatalf("production caller was added to %s", candidate)
		}
	}
}
