package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/syx0310/wg-mix-ebpf/internal/config"
	"github.com/syx0310/wg-mix-ebpf/internal/dataplane"
	"github.com/syx0310/wg-mix-ebpf/internal/lockfile"
)

const (
	isolatedPinOwnershipResultFormat = "wg-mix-ebpf-isolated-pin-ownership-v1"
	isolatedPinOwnershipIndexName    = "instances.v2.json"
)

type isolatedOwnershipContractContextKey struct{}

type isolatedOwnershipContract struct {
	layout     isolatedNetNSTestLayout
	manifest   isolatedNetNSTestManifest
	endpoint   string
	pinPath    string
	revalidate func() error
}

type isolatedPinOwnershipAPI interface {
	Inspect(context.Context, string) (*dataplane.PinOwnershipStatus, error)
	Recover(
		context.Context,
		string,
		*lockfile.LifecycleLease,
	) (*dataplane.PinOwnershipStatus, error)
	Detach(context.Context, string, *lockfile.LifecycleLease) error
}

type liveIsolatedPinOwnershipAPI struct{}

func (liveIsolatedPinOwnershipAPI) Inspect(
	ctx context.Context,
	pinPath string,
) (*dataplane.PinOwnershipStatus, error) {
	return dataplane.InspectPinOwnership(ctx, pinPath)
}

func (liveIsolatedPinOwnershipAPI) Recover(
	ctx context.Context,
	pinPath string,
	lease *lockfile.LifecycleLease,
) (*dataplane.PinOwnershipStatus, error) {
	return dataplane.RecoverPinOwnership(ctx, pinPath, lease)
}

func (liveIsolatedPinOwnershipAPI) Detach(
	ctx context.Context,
	pinPath string,
	lease *lockfile.LifecycleLease,
) error {
	return dataplane.DetachPinOwnership(ctx, pinPath, lease)
}

type isolatedPinOwnershipStage struct {
	Stage  string                       `json:"stage"`
	Status dataplane.PinOwnershipStatus `json:"status"`
}

type isolatedPinOwnershipResult struct {
	Format      string                      `json:"format"`
	Operation   string                      `json:"operation"`
	Role        string                      `json:"role"`
	Endpoint    string                      `json:"endpoint"`
	PinPath     string                      `json:"pin_path"`
	ResourceKey string                      `json:"resource_key"`
	OwnerRoot   string                      `json:"owner_root"`
	Stages      []isolatedPinOwnershipStage `json:"stages"`
}

func withIsolatedOwnershipContract(
	ctx context.Context,
	contract isolatedOwnershipContract,
) context.Context {
	return context.WithValue(
		ctx,
		isolatedOwnershipContractContextKey{},
		contract,
	)
}

func isolatedOwnershipContractFromContext(
	ctx context.Context,
) (isolatedOwnershipContract, error) {
	if ctx == nil {
		return isolatedOwnershipContract{}, errors.New(
			"isolated ownership context is unavailable",
		)
	}
	contract, ok := ctx.Value(
		isolatedOwnershipContractContextKey{},
	).(isolatedOwnershipContract)
	if !ok {
		return isolatedOwnershipContract{}, errors.New(
			"isolated ownership context was not validated",
		)
	}
	if err := validateIsolatedOwnershipContract(contract); err != nil {
		return isolatedOwnershipContract{}, err
	}
	return contract, nil
}

func validateIsolatedOwnershipContract(contract isolatedOwnershipContract) error {
	if contract.revalidate == nil {
		return errors.New("isolated ownership revalidator is unavailable")
	}
	if contract.layout.lease == "" ||
		contract.layout.lease != contract.manifest.values["lifecycle_lease"] {
		return errors.New("isolated ownership contract does not use the manifest lifecycle lease")
	}
	endpoint, err := manifestEndpointForRole(
		contract.manifest,
		contract.layout.role,
	)
	if err != nil {
		return err
	}
	if endpoint != contract.endpoint {
		return fmt.Errorf(
			"isolated ownership endpoint=%q, want %q",
			contract.endpoint,
			endpoint,
		)
	}
	if contract.pinPath != contract.manifest.values["pin_"+endpoint] {
		return fmt.Errorf(
			"isolated ownership pin=%q, want manifest pin %q",
			contract.pinPath,
			contract.manifest.values["pin_"+endpoint],
		)
	}
	return nil
}

func runIsolatedPinOwnershipCommand(
	ctx context.Context,
	args []string,
	stdout io.Writer,
) error {
	fs := flag.NewFlagSet(isolatedPinOwnershipCommand, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	operation := fs.String(
		"operation",
		"",
		"isolated ownership operation",
	)
	configPath := fs.String(
		"config",
		config.DefaultConfigPath,
		"path to wg-mix-ebpf config",
	)
	runDir := fs.String("run-dir", "", "isolated runtime directory")
	stateDir := fs.String("state-dir", "", "isolated state directory")
	isolatedNetNSTest := fs.Bool(
		"isolated-netns-test",
		false,
		"require the strict isolated network-namespace contract",
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("%s does not accept positional arguments", isolatedPinOwnershipCommand)
	}
	if !*isolatedNetNSTest {
		return fmt.Errorf(
			"%s requires --isolated-netns-test",
			isolatedPinOwnershipCommand,
		)
	}
	switch *operation {
	case "inspect", "recover", "detach":
	default:
		return fmt.Errorf(
			"%s requires --operation inspect, recover, or detach",
			isolatedPinOwnershipCommand,
		)
	}
	pinPath := os.Getenv(dataplane.EnvPinPath)
	validatedContext, err := isolatedNetNSTestContext(
		ctx,
		isolatedPinOwnershipCommand,
		*configPath,
		*runDir,
		*stateDir,
		pinPath,
	)
	if err != nil {
		return err
	}
	contract, err := isolatedOwnershipContractFromContext(validatedContext)
	if err != nil {
		return err
	}
	var result *isolatedPinOwnershipResult
	err = withValidatedIsolatedOwnershipLease(
		validatedContext,
		contract,
		*operation,
		func(lease *lockfile.LifecycleLease) error {
			var runErr error
			result, runErr = runIsolatedPinOwnershipOperation(
				validatedContext,
				contract,
				*operation,
				lease,
				liveIsolatedPinOwnershipAPI{},
			)
			return runErr
		},
	)
	if err != nil {
		return err
	}
	if result == nil {
		return errors.New("isolated ownership bridge returned no result")
	}
	return writeJSON(stdout, result)
}

func withValidatedIsolatedOwnershipLease(
	ctx context.Context,
	contract isolatedOwnershipContract,
	operation string,
	fn func(*lockfile.LifecycleLease) error,
) error {
	if ctx == nil {
		return errors.New("isolated ownership context is unavailable")
	}
	if fn == nil {
		return errors.New("isolated ownership lease callback is unavailable")
	}
	if err := validateIsolatedOwnershipContract(contract); err != nil {
		return err
	}
	owner := lockfile.LifecycleOwner{
		PID:        os.Getpid(),
		Action:     isolatedPinOwnershipCommand + "-" + operation,
		ConfigPath: contract.manifest.values["config_"+contract.endpoint],
		RunDir:     contract.manifest.values["run_dir_"+contract.endpoint],
	}
	return lockfile.WithLifecycle(
		ctx,
		nil,
		owner,
		func(lease *lockfile.LifecycleLease) error {
			if err := revalidateIsolatedOwnershipLease(
				ctx,
				contract,
				lease,
			); err != nil {
				return err
			}
			runErr := fn(lease)
			revalidateErr := revalidateIsolatedOwnershipLease(
				ctx,
				contract,
				lease,
			)
			return errors.Join(runErr, revalidateErr)
		},
	)
}

func revalidateIsolatedOwnershipLease(
	ctx context.Context,
	contract isolatedOwnershipContract,
	lease *lockfile.LifecycleLease,
) error {
	if ctx == nil {
		return errors.New("isolated ownership context is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if lease == nil || !lease.HeldAt(contract.layout.lease) {
		return fmt.Errorf(
			"isolated ownership lifecycle lease is not held at %s",
			contract.layout.lease,
		)
	}
	if err := contract.revalidate(); err != nil {
		return fmt.Errorf("revalidate isolated ownership contract: %w", err)
	}
	if !lease.HeldAt(contract.layout.lease) {
		return fmt.Errorf(
			"isolated ownership lifecycle lease identity changed at %s",
			contract.layout.lease,
		)
	}
	return nil
}

func runIsolatedPinOwnershipOperation(
	ctx context.Context,
	contract isolatedOwnershipContract,
	operation string,
	lease *lockfile.LifecycleLease,
	api isolatedPinOwnershipAPI,
) (*isolatedPinOwnershipResult, error) {
	if api == nil {
		return nil, errors.New("isolated pin ownership API is unavailable")
	}
	if err := validateIsolatedOwnershipContract(contract); err != nil {
		return nil, err
	}
	if lease == nil || !lease.HeldAt(contract.layout.lease) {
		return nil, errors.New("isolated pin ownership operation requires the shared lifecycle lease")
	}
	result := &isolatedPinOwnershipResult{
		Format:      isolatedPinOwnershipResultFormat,
		Operation:   operation,
		Role:        contract.layout.role,
		Endpoint:    contract.endpoint,
		PinPath:     contract.pinPath,
		ResourceKey: contract.manifest.values["pin_resource_key_"+contract.endpoint],
		OwnerRoot:   contract.manifest.values["pin_owner_root"],
		Stages:      make([]isolatedPinOwnershipStage, 0, 4),
	}
	inspect := func(stage string) (*dataplane.PinOwnershipStatus, error) {
		if err := revalidateIsolatedOwnershipLease(ctx, contract, lease); err != nil {
			return nil, err
		}
		status, err := api.Inspect(ctx, contract.pinPath)
		if err != nil {
			return nil, fmt.Errorf("%s isolated pin ownership: %w", stage, err)
		}
		if err := validateIsolatedPinOwnershipStatus(
			contract,
			contract.endpoint,
			status,
		); err != nil {
			return nil, fmt.Errorf("%s isolated pin ownership: %w", stage, err)
		}
		if err := revalidateIsolatedOwnershipLease(ctx, contract, lease); err != nil {
			return nil, err
		}
		result.Stages = append(result.Stages, isolatedPinOwnershipStage{
			Stage:  stage,
			Status: *status,
		})
		return status, nil
	}
	recoverOwnership := func(stage string) (*dataplane.PinOwnershipStatus, error) {
		if err := revalidateIsolatedOwnershipLease(ctx, contract, lease); err != nil {
			return nil, err
		}
		status, err := api.Recover(ctx, contract.pinPath, lease)
		if err != nil {
			return nil, fmt.Errorf("%s isolated pin ownership: %w", stage, err)
		}
		if err := validateIsolatedPinOwnershipStatus(
			contract,
			contract.endpoint,
			status,
		); err != nil {
			return nil, fmt.Errorf("%s isolated pin ownership: %w", stage, err)
		}
		if err := revalidateIsolatedOwnershipLease(ctx, contract, lease); err != nil {
			return nil, err
		}
		result.Stages = append(result.Stages, isolatedPinOwnershipStage{
			Stage:  stage,
			Status: *status,
		})
		return status, nil
	}

	switch operation {
	case "inspect":
		if _, err := inspect("inspect"); err != nil {
			return nil, err
		}
	case "recover":
		if _, err := inspect("initial"); err != nil {
			return nil, err
		}
		if _, err := recoverOwnership("recovered"); err != nil {
			return nil, err
		}
		final, err := inspect("final")
		if err != nil {
			return nil, err
		}
		if final.RecoveryRequired || final.LegacyPins {
			return nil, errors.New(
				"isolated pin ownership remains unresolved after recovery",
			)
		}
	case "detach":
		initial, err := inspect("initial")
		if err != nil {
			return nil, err
		}
		if initial.RecoveryRequired {
			if _, err := recoverOwnership("recovered"); err != nil {
				return nil, err
			}
		}
		ready, err := inspect("ready")
		if err != nil {
			return nil, err
		}
		if ready.RecoveryRequired || ready.LegacyPins {
			return nil, errors.New(
				"isolated pin ownership is not safe for owner-proven detach",
			)
		}
		if err := revalidateIsolatedOwnershipLease(ctx, contract, lease); err != nil {
			return nil, err
		}
		if err := api.Detach(ctx, contract.pinPath, lease); err != nil {
			return nil, fmt.Errorf("detach isolated pin ownership: %w", err)
		}
		if err := revalidateIsolatedOwnershipLease(ctx, contract, lease); err != nil {
			return nil, err
		}
		final, err := inspect("final")
		if err != nil {
			return nil, err
		}
		if err := validateCleanIsolatedPinOwnershipStatus(final); err != nil {
			return nil, fmt.Errorf("validate final isolated pin ownership: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported isolated pin ownership operation %q", operation)
	}
	return result, nil
}

func validateIsolatedPinOwnershipStatus(
	contract isolatedOwnershipContract,
	endpoint string,
	status *dataplane.PinOwnershipStatus,
) error {
	if status == nil {
		return errors.New("pin ownership status is nil")
	}
	if endpoint != "a" && endpoint != "b" {
		return fmt.Errorf("isolated pin ownership endpoint %q is invalid", endpoint)
	}
	expectedPin := contract.manifest.values["pin_"+endpoint]
	expectedKey := contract.manifest.values["pin_resource_key_"+endpoint]
	expectedOwnerRoot := contract.manifest.values["pin_owner_root"]
	expectedRecord := contract.manifest.values["pin_owner_"+endpoint]
	if status.PinPath != expectedPin {
		return fmt.Errorf(
			"pin ownership path=%q, want manifest pin %q",
			status.PinPath,
			expectedPin,
		)
	}
	if status.ResourceKey != expectedKey {
		return fmt.Errorf(
			"pin ownership resource key=%q, want manifest key %q",
			status.ResourceKey,
			expectedKey,
		)
	}
	if status.OwnerRoot != expectedOwnerRoot {
		return fmt.Errorf(
			"pin ownership root=%q, want manifest root %q",
			status.OwnerRoot,
			expectedOwnerRoot,
		)
	}
	if status.RecordPath != expectedRecord {
		return fmt.Errorf(
			"pin ownership record=%q, want manifest record %q",
			status.RecordPath,
			expectedRecord,
		)
	}
	expectedIndex := filepath.Join(
		expectedOwnerRoot,
		isolatedPinOwnershipIndexName,
	)
	if status.IndexPath != expectedIndex {
		return fmt.Errorf(
			"pin ownership index=%q, want isolated index %q",
			status.IndexPath,
			expectedIndex,
		)
	}
	return nil
}

func validateCleanIsolatedPinOwnershipStatus(
	status *dataplane.PinOwnershipStatus,
) error {
	if status == nil {
		return errors.New("pin ownership status is nil")
	}
	if status.DirectoryExists ||
		status.OwnerExists ||
		status.LegacyPins ||
		status.RecoveryRequired ||
		status.DirectoryRemoved ||
		status.Version != 0 ||
		status.Sequence != 0 ||
		status.BootID != "" ||
		status.Phase != "" ||
		status.Step != "" ||
		status.ActiveGeneration != 0 ||
		status.NextGeneration != 0 ||
		status.MapCount != 0 ||
		status.ActiveFilterCount != 0 {
		return errors.New("pin ownership is not clean")
	}
	return nil
}

func validateAllIsolatedOwnershipPinsClean(
	ctx context.Context,
	contract isolatedOwnershipContract,
	lease *lockfile.LifecycleLease,
	api isolatedPinOwnershipAPI,
) ([]isolatedPinOwnershipStage, error) {
	if api == nil {
		return nil, errors.New("isolated pin ownership API is unavailable")
	}
	stages := make([]isolatedPinOwnershipStage, 0, 2)
	for _, endpoint := range []string{"a", "b"} {
		if err := revalidateIsolatedOwnershipLease(ctx, contract, lease); err != nil {
			return nil, err
		}
		status, err := api.Inspect(
			ctx,
			contract.manifest.values["pin_"+endpoint],
		)
		if err != nil {
			return nil, fmt.Errorf(
				"inspect isolated endpoint %s ownership: %w",
				endpoint,
				err,
			)
		}
		if err := validateIsolatedPinOwnershipStatus(
			contract,
			endpoint,
			status,
		); err != nil {
			return nil, fmt.Errorf(
				"validate isolated endpoint %s ownership: %w",
				endpoint,
				err,
			)
		}
		if err := validateCleanIsolatedPinOwnershipStatus(status); err != nil {
			return nil, fmt.Errorf(
				"isolated endpoint %s ownership is not clean: %w",
				endpoint,
				err,
			)
		}
		stages = append(stages, isolatedPinOwnershipStage{
			Stage:  "clean-" + endpoint,
			Status: *status,
		})
	}
	if err := revalidateIsolatedOwnershipLease(ctx, contract, lease); err != nil {
		return nil, err
	}
	return stages, nil
}
