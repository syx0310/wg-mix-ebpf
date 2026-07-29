package app

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/syx0310/wg-mix-ebpf/internal/dataplane"
	"github.com/syx0310/wg-mix-ebpf/internal/lockfile"
)

type fakeIsolatedPinOwnershipAPI struct {
	inspectStatuses []*dataplane.PinOwnershipStatus
	recoverStatus   *dataplane.PinOwnershipStatus
	calls           []string
	wantLease       *lockfile.LifecycleLease
}

func (fake *fakeIsolatedPinOwnershipAPI) Inspect(
	_ context.Context,
	pinPath string,
) (*dataplane.PinOwnershipStatus, error) {
	fake.calls = append(fake.calls, "inspect:"+pinPath)
	if len(fake.inspectStatuses) == 0 {
		return nil, errors.New("unexpected inspect")
	}
	status := fake.inspectStatuses[0]
	fake.inspectStatuses = fake.inspectStatuses[1:]
	return status, nil
}

func (fake *fakeIsolatedPinOwnershipAPI) Recover(
	_ context.Context,
	pinPath string,
	lease *lockfile.LifecycleLease,
) (*dataplane.PinOwnershipStatus, error) {
	fake.calls = append(fake.calls, "recover:"+pinPath)
	if lease != fake.wantLease {
		return nil, errors.New("recover received a different lifecycle lease")
	}
	if fake.recoverStatus == nil {
		return nil, errors.New("unexpected recover")
	}
	return fake.recoverStatus, nil
}

func (fake *fakeIsolatedPinOwnershipAPI) Detach(
	_ context.Context,
	pinPath string,
	lease *lockfile.LifecycleLease,
) error {
	fake.calls = append(fake.calls, "detach:"+pinPath)
	if lease != fake.wantLease {
		return errors.New("detach received a different lifecycle lease")
	}
	return nil
}

func TestIsolatedPinOwnershipDetachSequence(t *testing.T) {
	tests := []struct {
		name               string
		recoveryRequired   bool
		wantOperationCalls []string
		wantStages         []string
	}{
		{
			name:               "active owner",
			wantOperationCalls: []string{"inspect", "inspect", "detach", "inspect"},
			wantStages:         []string{"initial", "ready", "final"},
		},
		{
			name:               "recovery required",
			recoveryRequired:   true,
			wantOperationCalls: []string{"inspect", "recover", "inspect", "detach", "inspect"},
			wantStages:         []string{"initial", "recovered", "ready", "final"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contract := isolatedOwnershipFixture(t, "a")
			lease := acquireIsolatedOwnershipFixtureLease(t, contract)
			active := isolatedOwnershipStatus(contract, "a", false)
			initial := isolatedOwnershipStatus(contract, "a", false)
			initial.RecoveryRequired = tt.recoveryRequired
			fake := &fakeIsolatedPinOwnershipAPI{
				inspectStatuses: []*dataplane.PinOwnershipStatus{
					initial,
					isolatedOwnershipStatus(contract, "a", false),
					isolatedOwnershipStatus(contract, "a", true),
				},
				recoverStatus: active,
				wantLease:     lease,
			}
			result, err := runIsolatedPinOwnershipOperation(
				t.Context(),
				contract,
				"detach",
				lease,
				fake,
			)
			if err != nil {
				t.Fatalf("detach sequence: %v", err)
			}
			if result.Format != isolatedPinOwnershipResultFormat ||
				result.Operation != "detach" ||
				result.PinPath != contract.pinPath ||
				result.ResourceKey != contract.manifest.values["pin_resource_key_a"] ||
				result.OwnerRoot != contract.manifest.values["pin_owner_root"] {
				t.Fatalf("unexpected versioned result: %#v", result)
			}
			gotCalls := operationNames(fake.calls)
			if strings.Join(gotCalls, ",") != strings.Join(tt.wantOperationCalls, ",") {
				t.Fatalf("call order = %v, want %v", gotCalls, tt.wantOperationCalls)
			}
			gotStages := make([]string, 0, len(result.Stages))
			for _, stage := range result.Stages {
				gotStages = append(gotStages, stage.Stage)
			}
			if strings.Join(gotStages, ",") != strings.Join(tt.wantStages, ",") {
				t.Fatalf("stages = %v, want %v", gotStages, tt.wantStages)
			}
		})
	}
}

func TestIsolatedPinOwnershipRecoverAndInspectSequences(t *testing.T) {
	contract := isolatedOwnershipFixture(t, "a")
	lease := acquireIsolatedOwnershipFixtureLease(t, contract)
	active := isolatedOwnershipStatus(contract, "a", false)
	fake := &fakeIsolatedPinOwnershipAPI{
		inspectStatuses: []*dataplane.PinOwnershipStatus{
			isolatedOwnershipStatus(contract, "a", false),
			isolatedOwnershipStatus(contract, "a", false),
		},
		recoverStatus: active,
		wantLease:     lease,
	}
	result, err := runIsolatedPinOwnershipOperation(
		t.Context(),
		contract,
		"recover",
		lease,
		fake,
	)
	if err != nil {
		t.Fatalf("recover sequence: %v", err)
	}
	if got := strings.Join(operationNames(fake.calls), ","); got != "inspect,recover,inspect" {
		t.Fatalf("recover call order = %s", got)
	}
	if got := len(result.Stages); got != 3 {
		t.Fatalf("recover stages = %d, want 3", got)
	}

	inspectFake := &fakeIsolatedPinOwnershipAPI{
		inspectStatuses: []*dataplane.PinOwnershipStatus{
			isolatedOwnershipStatus(contract, "a", false),
		},
		wantLease: lease,
	}
	if _, err := runIsolatedPinOwnershipOperation(
		t.Context(),
		contract,
		"inspect",
		lease,
		inspectFake,
	); err != nil {
		t.Fatalf("inspect sequence: %v", err)
	}
	if got := strings.Join(operationNames(inspectFake.calls), ","); got != "inspect" {
		t.Fatalf("inspect call order = %s", got)
	}
}

func TestIsolatedPinOwnershipRejectsForeignAndDirtyFinalStatus(t *testing.T) {
	t.Run("foreign resource", func(t *testing.T) {
		contract := isolatedOwnershipFixture(t, "a")
		lease := acquireIsolatedOwnershipFixtureLease(t, contract)
		foreign := isolatedOwnershipStatus(contract, "a", false)
		foreign.ResourceKey = strings.Repeat("f", 64)
		fake := &fakeIsolatedPinOwnershipAPI{
			inspectStatuses: []*dataplane.PinOwnershipStatus{foreign},
			wantLease:       lease,
		}
		if _, err := runIsolatedPinOwnershipOperation(
			t.Context(),
			contract,
			"detach",
			lease,
			fake,
		); err == nil || !strings.Contains(err.Error(), "resource key") {
			t.Fatalf("foreign resource error = %v", err)
		}
		if got := strings.Join(operationNames(fake.calls), ","); got != "inspect" {
			t.Fatalf("foreign resource calls = %s", got)
		}
	})

	t.Run("dirty final", func(t *testing.T) {
		contract := isolatedOwnershipFixture(t, "a")
		lease := acquireIsolatedOwnershipFixtureLease(t, contract)
		fake := &fakeIsolatedPinOwnershipAPI{
			inspectStatuses: []*dataplane.PinOwnershipStatus{
				isolatedOwnershipStatus(contract, "a", false),
				isolatedOwnershipStatus(contract, "a", false),
				isolatedOwnershipStatus(contract, "a", false),
			},
			wantLease: lease,
		}
		if _, err := runIsolatedPinOwnershipOperation(
			t.Context(),
			contract,
			"detach",
			lease,
			fake,
		); err == nil || !strings.Contains(err.Error(), "not clean") {
			t.Fatalf("dirty final error = %v", err)
		}
		if got := strings.Join(operationNames(fake.calls), ","); got != "inspect,inspect,detach,inspect" {
			t.Fatalf("dirty final calls = %s", got)
		}
	})
}

func TestIsolatedPinOwnershipStopsOnContractOrLeaseDrift(t *testing.T) {
	t.Run("contract drift", func(t *testing.T) {
		contract := isolatedOwnershipFixture(t, "a")
		lease := acquireIsolatedOwnershipFixtureLease(t, contract)
		contract.revalidate = func() error {
			return errors.New("mount options changed")
		}
		fake := &fakeIsolatedPinOwnershipAPI{
			inspectStatuses: []*dataplane.PinOwnershipStatus{
				isolatedOwnershipStatus(contract, "a", false),
			},
			wantLease: lease,
		}
		if _, err := runIsolatedPinOwnershipOperation(
			t.Context(),
			contract,
			"inspect",
			lease,
			fake,
		); err == nil || !strings.Contains(err.Error(), "mount options changed") {
			t.Fatalf("contract drift error = %v", err)
		}
		if len(fake.calls) != 0 {
			t.Fatalf("API ran after contract drift: %v", fake.calls)
		}
	})

	t.Run("foreign lease", func(t *testing.T) {
		contract := isolatedOwnershipFixture(t, "a")
		foreignContract := isolatedOwnershipFixture(t, "a")
		foreignLease := acquireIsolatedOwnershipFixtureLease(t, foreignContract)
		fake := &fakeIsolatedPinOwnershipAPI{
			inspectStatuses: []*dataplane.PinOwnershipStatus{
				isolatedOwnershipStatus(contract, "a", false),
			},
			wantLease: foreignLease,
		}
		if _, err := runIsolatedPinOwnershipOperation(
			t.Context(),
			contract,
			"inspect",
			foreignLease,
			fake,
		); err == nil || !strings.Contains(err.Error(), "shared lifecycle lease") {
			t.Fatalf("foreign lease error = %v", err)
		}
		if len(fake.calls) != 0 {
			t.Fatalf("API ran with a foreign lease: %v", fake.calls)
		}
	})
}

func TestValidatedIsolatedOwnershipLeaseRevalidatesAndReleases(t *testing.T) {
	contract := isolatedOwnershipFixture(t, "a")
	var contextRevalidations int
	ctx := lockfile.WithIsolatedNetNSTestLifecycleValidation(
		t.Context(),
		contract.layout.lease,
		func() error {
			contextRevalidations++
			return nil
		},
	)
	var callbackLease *lockfile.LifecycleLease
	if err := withValidatedIsolatedOwnershipLease(
		ctx,
		contract,
		"inspect",
		func(lease *lockfile.LifecycleLease) error {
			callbackLease = lease
			if !lease.HeldAt(contract.layout.lease) {
				return errors.New("shared lease is not held in callback")
			}
			return nil
		},
	); err != nil {
		t.Fatalf("with validated lease: %v", err)
	}
	if callbackLease == nil || contextRevalidations != 1 {
		t.Fatalf(
			"lease callback=%v context revalidations=%d",
			callbackLease != nil,
			contextRevalidations,
		)
	}
	reacquired, err := lockfile.AcquireLifecycleAt(
		contract.layout.lease,
		lockfile.LifecycleOwner{PID: os.Getpid(), Action: "reacquire"},
	)
	if err != nil {
		t.Fatalf("lease was not explicitly released: %v", err)
	}
	if err := reacquired.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestIsolatedOwnershipRolesAndCleanValidationShareLease(t *testing.T) {
	contractA := isolatedOwnershipFixture(t, "a")
	contractB := isolatedOwnershipFixture(t, "b")
	contractB.layout.lease = contractA.layout.lease
	contractB.manifest.values["lifecycle_lease"] = contractA.layout.lease
	lease := acquireIsolatedOwnershipFixtureLease(t, contractA)

	for _, contract := range []isolatedOwnershipContract{contractA, contractB} {
		fake := &fakeIsolatedPinOwnershipAPI{
			inspectStatuses: []*dataplane.PinOwnershipStatus{
				isolatedOwnershipStatus(contract, contract.endpoint, false),
			},
			wantLease: lease,
		}
		if _, err := runIsolatedPinOwnershipOperation(
			t.Context(),
			contract,
			"inspect",
			lease,
			fake,
		); err != nil {
			t.Fatalf("role %s shared lease: %v", contract.layout.role, err)
		}
	}

	cleanFake := &fakeIsolatedPinOwnershipAPI{
		inspectStatuses: []*dataplane.PinOwnershipStatus{
			isolatedOwnershipStatus(contractA, "a", true),
			isolatedOwnershipStatus(contractA, "b", true),
		},
		wantLease: lease,
	}
	stages, err := validateAllIsolatedOwnershipPinsClean(
		t.Context(),
		contractA,
		lease,
		cleanFake,
	)
	if err != nil {
		t.Fatalf("validate both pins clean: %v", err)
	}
	if len(stages) != 2 ||
		stages[0].Stage != "clean-a" ||
		stages[1].Stage != "clean-b" {
		t.Fatalf("clean stages = %#v", stages)
	}
}

func TestIsolatedOwnershipBridgeIsHiddenAndRequiresGate(t *testing.T) {
	var usage bytes.Buffer
	printUsage(&usage)
	if strings.Contains(usage.String(), isolatedPinOwnershipCommand) {
		t.Fatal("isolated ownership command leaked into user usage")
	}
	var stdout bytes.Buffer
	err := runIsolatedPinOwnershipCommand(
		t.Context(),
		[]string{"--operation", "inspect"},
		&stdout,
	)
	if err == nil || !strings.Contains(err.Error(), "requires --isolated-netns-test") {
		t.Fatalf("ungated ownership bridge error = %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("ungated ownership bridge wrote output: %q", stdout.String())
	}
}

func isolatedOwnershipFixture(
	t *testing.T,
	role string,
) isolatedOwnershipContract {
	t.Helper()
	layout, _, _, _, _ := isolatedFixtureLayout(t, role)
	manifest, err := parseIsolatedNetNSTestManifest(
		isolatedFixtureManifest(layout),
	)
	if err != nil {
		t.Fatal(err)
	}
	leasePath := filepath.Join(t.TempDir(), "lifecycle.lease")
	layout.lease = leasePath
	manifest.values["lifecycle_lease"] = leasePath
	endpoint, err := manifestEndpointForRole(manifest, role)
	if err != nil {
		t.Fatal(err)
	}
	return isolatedOwnershipContract{
		layout:   layout,
		manifest: manifest,
		endpoint: endpoint,
		pinPath:  manifest.values["pin_"+endpoint],
		revalidate: func() error {
			return nil
		},
	}
}

func isolatedOwnershipStatus(
	contract isolatedOwnershipContract,
	endpoint string,
	clean bool,
) *dataplane.PinOwnershipStatus {
	status := &dataplane.PinOwnershipStatus{
		PinPath:    contract.manifest.values["pin_"+endpoint],
		OwnerRoot:  contract.manifest.values["pin_owner_root"],
		RecordPath: contract.manifest.values["pin_owner_"+endpoint],
		IndexPath: filepath.Join(
			contract.manifest.values["pin_owner_root"],
			isolatedPinOwnershipIndexName,
		),
		ResourceKey: contract.manifest.values["pin_resource_key_"+endpoint],
	}
	if !clean {
		status.DirectoryExists = true
		status.OwnerExists = true
		status.Version = 3
		status.Sequence = 1
		status.BootID = contract.manifest.values["boot_id"]
		status.Phase = "active"
		status.Step = "ready"
		status.ActiveGeneration = 1
		status.MapCount = 12
		status.ActiveFilterCount = 2
	}
	return status
}

func acquireIsolatedOwnershipFixtureLease(
	t *testing.T,
	contract isolatedOwnershipContract,
) *lockfile.LifecycleLease {
	t.Helper()
	lease, err := lockfile.AcquireLifecycleAt(
		contract.layout.lease,
		lockfile.LifecycleOwner{PID: os.Getpid(), Action: "test"},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := lease.Close(); err != nil {
			t.Errorf("close fixture lifecycle lease: %v", err)
		}
	})
	return lease
}

func operationNames(calls []string) []string {
	names := make([]string, 0, len(calls))
	for _, call := range calls {
		name, _, _ := strings.Cut(call, ":")
		names = append(names, name)
	}
	return names
}
