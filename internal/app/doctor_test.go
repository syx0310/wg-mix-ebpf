package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/syx0310/wg-mix-ebpf/internal/config"
	"github.com/syx0310/wg-mix-ebpf/internal/control"
	"github.com/syx0310/wg-mix-ebpf/internal/feature"
	"github.com/syx0310/wg-mix-ebpf/internal/guard"
	"github.com/syx0310/wg-mix-ebpf/internal/reconcile"
)

type doctorNFTableListerFunc func(context.Context) ([]guard.NFTable, error)

func (f doctorNFTableListerFunc) ListTables(ctx context.Context) ([]guard.NFTable, error) {
	return f(ctx)
}

func TestDoctorExplicitNoNFTDoesNotRequireNFTBinary(t *testing.T) {
	cfg := config.SafeTemplate()
	cfg.StartupGuard.Mode = config.StartupGuardModeNone
	inventoryCalls := 0
	preflight := guard.NewProjectTablePreflightWithLister(doctorNFTableListerFunc(
		func(context.Context) ([]guard.NFTable, error) {
			inventoryCalls++
			return nil, nil
		},
	))
	deps := healthyDoctorDependencies(cfg)
	deps.inspectNoNFT = preflight.Check

	checks := runDoctorChecks(t, deps)
	if inventoryCalls != 1 {
		t.Fatalf("no-nft inventory calls = %d, want 1", inventoryCalls)
	}
	if _, found := findDoctorCheck(checks, "cmd.nft"); found {
		t.Fatalf("explicit no-nft doctor unexpectedly required the nft binary: %#v", checks)
	}
	check, found := findDoctorCheck(checks, "startup_guard.no_nft_inventory")
	if !found {
		t.Fatalf("no-nft inventory check missing: %#v", checks)
	}
	if check.Status != "PASS" || !strings.Contains(check.Detail, "no inet") {
		t.Fatalf("empty no-nft inventory check = %#v", check)
	}
	if !strings.Contains(check.Message, "HIGH RISK") || !strings.Contains(check.Message, "traffic-leak guard") {
		t.Fatalf("no-nft PASS lacks explicit risk warning: %#v", check)
	}
}

func TestDoctorExplicitNoNFTProjectsInventoryFailures(t *testing.T) {
	tests := []struct {
		name       string
		listTables doctorNFTableListerFunc
		message    string
	}{
		{
			name: "project table conflict",
			listTables: func(context.Context) ([]guard.NFTable, error) {
				return []guard.NFTable{{Family: "inet", Name: guard.TableName}}, nil
			},
			message: "project guard tables",
		},
		{
			name: "permission denied",
			listTables: func(context.Context) ([]guard.NFTable, error) {
				return nil, fmt.Errorf("open NETLINK_NETFILTER: %w", os.ErrPermission)
			},
			message: "permission denied",
		},
		{
			name: "unsupported platform",
			listTables: func(context.Context) ([]guard.NFTable, error) {
				return nil, guard.ErrNFTableInventoryUnsupported
			},
			message: "unsupported",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := config.SafeTemplate()
			cfg.StartupGuard.Mode = config.StartupGuardModeNone
			preflight := guard.NewProjectTablePreflightWithLister(test.listTables)
			deps := healthyDoctorDependencies(cfg)
			deps.inspectNoNFT = preflight.Check

			checks := runDoctorChecks(t, deps)
			if _, found := findDoctorCheck(checks, "cmd.nft"); found {
				t.Fatalf("inventory failure incorrectly fell back to an nft binary check: %#v", checks)
			}
			check, found := findDoctorCheck(checks, "startup_guard.no_nft_inventory")
			if !found || check.Status != "FAIL" {
				t.Fatalf("inventory failure was not projected as FAIL: %#v", checks)
			}
			if !strings.Contains(check.Message, test.message) {
				t.Fatalf("inventory failure check = %#v, want message containing %q", check, test.message)
			}
		})
	}
}

func TestDoctorGuardedAndUnknownConfigsStillRequireNFTBinary(t *testing.T) {
	t.Run("guarded default", func(t *testing.T) {
		deps := healthyDoctorDependencies(config.SafeTemplate())
		deps.inspectNoNFT = func(context.Context) (guard.Outcome, error) {
			t.Fatal("guarded doctor must not run the no-nft inventory")
			return guard.Outcome{}, nil
		}
		assertDoctorRequiresNFT(t, runDoctorChecks(t, deps))
	})

	t.Run("missing config", func(t *testing.T) {
		deps := healthyDoctorDependencies(config.SafeTemplate())
		deps.statConfig = func(string) error { return os.ErrNotExist }
		deps.buildState = func(context.Context, reconcile.Options) (*config.Config, *control.State, error) {
			t.Fatal("missing config must not build runtime state")
			return nil, nil, nil
		}
		deps.loadConfig = func(string) (*config.Config, error) {
			t.Fatal("missing config must not be parsed")
			return nil, nil
		}
		deps.inspectNoNFT = func(context.Context) (guard.Outcome, error) {
			t.Fatal("unknown config must not run the no-nft inventory")
			return guard.Outcome{}, nil
		}
		assertDoctorRequiresNFT(t, runDoctorChecks(t, deps))
	})

	t.Run("invalid config", func(t *testing.T) {
		deps := healthyDoctorDependencies(config.SafeTemplate())
		deps.buildState = func(context.Context, reconcile.Options) (*config.Config, *control.State, error) {
			return nil, nil, errors.New("invalid startup_guard.mode")
		}
		deps.loadConfig = func(string) (*config.Config, error) {
			return nil, errors.New("invalid startup_guard.mode")
		}
		deps.inspectNoNFT = func(context.Context) (guard.Outcome, error) {
			t.Fatal("invalid config must not run the no-nft inventory")
			return guard.Outcome{}, nil
		}
		assertDoctorRequiresNFT(t, runDoctorChecks(t, deps))
	})
}

func TestDoctorRecognizesExplicitNoNFTWhenRuntimeStateFails(t *testing.T) {
	cfg := config.SafeTemplate()
	cfg.StartupGuard.Mode = config.StartupGuardModeNone
	deps := healthyDoctorDependencies(cfg)
	deps.buildState = func(context.Context, reconcile.Options) (*config.Config, *control.State, error) {
		return nil, nil, errors.New("runtime WireGuard state unavailable")
	}
	preflight := guard.NewProjectTablePreflightWithLister(doctorNFTableListerFunc(
		func(context.Context) ([]guard.NFTable, error) { return nil, nil },
	))
	deps.inspectNoNFT = preflight.Check

	checks := runDoctorChecks(t, deps)
	if _, found := findDoctorCheck(checks, "cmd.nft"); found {
		t.Fatalf("known mode=none config with runtime failure required nft: %#v", checks)
	}
	if check, found := findDoctorCheck(checks, "startup_guard.no_nft_inventory"); !found || check.Status != "PASS" {
		t.Fatalf("known mode=none config did not run read-only inventory: %#v", checks)
	}
	if check, found := findDoctorCheck(checks, "config/runtime"); !found || check.Status != "FAIL" {
		t.Fatalf("runtime failure was not retained independently: %#v", checks)
	}
}

func healthyDoctorDependencies(cfg *config.Config) doctorDependencies {
	return doctorDependencies{
		probe: func() feature.Probe {
			return feature.Probe{
				GOOS:           "linux",
				GOARCH:         "amd64",
				SupportedArch:  true,
				ProcAvailable:  true,
				SysFSAvailable: true,
				BPFFSAvailable: true,
				BPFFSMounted:   true,
				Commands: map[string]string{
					"tc": "/usr/sbin/tc",
					"wg": "/usr/bin/wg",
					// nft is intentionally absent. Tests must not depend on PATH.
					"nft": "",
				},
			}
		},
		statConfig: func(string) error { return nil },
		loadConfig: func(string) (*config.Config, error) {
			return cfg, nil
		},
		buildState: func(context.Context, reconcile.Options) (*config.Config, *control.State, error) {
			return cfg, &control.State{}, nil
		},
		inspectNoNFT: func(context.Context) (guard.Outcome, error) {
			return guard.Outcome{Observation: guard.ObservationAbsent}, nil
		},
	}
}

func runDoctorChecks(t *testing.T, deps doctorDependencies) []doctorCheck {
	t.Helper()
	var stdout bytes.Buffer
	if err := runDoctorWithDependencies(
		t.Context(),
		[]string{"--config", "/test/config.yaml", "--json"},
		&stdout,
		deps,
	); err != nil {
		t.Fatalf("doctor returned an error instead of reporting checks: %v", err)
	}
	var output struct {
		Checks []doctorCheck `json:"checks"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatalf("decode doctor JSON: %v\n%s", err, stdout.String())
	}
	return output.Checks
}

func assertDoctorRequiresNFT(t *testing.T, checks []doctorCheck) {
	t.Helper()
	if _, found := findDoctorCheck(checks, "startup_guard.no_nft_inventory"); found {
		t.Fatalf("guarded or unknown config unexpectedly used no-nft inventory: %#v", checks)
	}
	check, found := findDoctorCheck(checks, "cmd.nft")
	if !found || check.Status != "FAIL" || !strings.Contains(check.Message, "not found") {
		t.Fatalf("missing nft binary was not required: %#v", checks)
	}
}

func findDoctorCheck(checks []doctorCheck, name string) (doctorCheck, bool) {
	for _, check := range checks {
		if check.Name == name {
			return check, true
		}
	}
	return doctorCheck{}, false
}
