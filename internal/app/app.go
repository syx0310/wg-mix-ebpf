package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
	"github.com/syx0310/wg-mix-ebpf/internal/config"
	"github.com/syx0310/wg-mix-ebpf/internal/control"
	"github.com/syx0310/wg-mix-ebpf/internal/dataplane"
	"github.com/syx0310/wg-mix-ebpf/internal/feature"
	"github.com/syx0310/wg-mix-ebpf/internal/guard"
	"github.com/syx0310/wg-mix-ebpf/internal/runtime"
	"github.com/syx0310/wg-mix-ebpf/internal/underlay"
)

const Version = "dev"

func Run(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) error {
	if len(args) == 0 {
		printUsage(stderr)
		return fmt.Errorf("missing command")
	}
	cmd := args[0]
	switch cmd {
	case "help", "-h", "--help":
		printUsage(stdout)
		return nil
	case "version":
		fmt.Fprintln(stdout, Version)
		return nil
	case "features":
		data, err := feature.Run().JSON()
		if err != nil {
			return err
		}
		fmt.Fprintln(stdout, string(data))
		return nil
	case "bpf-load-test":
		return runBPFLoadTest(ctx, args[1:], stdout)
	case "validate", "status", "dump", "dump-abi", "reload", "detach", "guard-plan", "guard-apply", "guard-cleanup":
		return runStateCommand(ctx, cmd, args[1:], stdout)
	default:
		printUsage(stderr)
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func runBPFLoadTest(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("bpf-load-test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	objectPath := fs.String("object", "", "path to TC/eBPF object")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := dataplane.LoadObjectTest(ctx, *objectPath); err != nil {
		return err
	}
	path := *objectPath
	if path == "" {
		path = dataplane.DisplayObjectPath("")
	}
	fmt.Fprintf(stdout, "BPF object loaded successfully: %s\n", path)
	return nil
}

func runStateCommand(ctx context.Context, cmd string, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configPath := fs.String("config", config.DefaultConfigPath, "path to wg-mix-ebpf config")
	offline := fs.Bool("offline", false, "skip runtime and underlay reads")
	dryRun := fs.Bool("dry-run", false, "print actions instead of applying them")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.LoadFile(*configPath)
	if err != nil {
		return fmt.Errorf("load config %s: %w", *configPath, err)
	}
	state, err := control.BuildState(ctx, cfg, runtime.NewSystemProvider(), underlay.NewSystemResolver(), nil, control.BuildOptions{Offline: *offline})
	if err != nil {
		if control.IsUnsupportedRuntime(err) && !*offline {
			return fmt.Errorf("%w (use --offline for static validation on this platform)", err)
		}
		return err
	}

	switch cmd {
	case "validate":
		fmt.Fprintln(stdout, "ok")
	case "status", "dump":
		if cmd == "status" {
			view := struct {
				Desired        *control.State          `json:"desired"`
				Dataplane      *dataplane.KernelStatus `json:"dataplane,omitempty"`
				DataplaneError string                  `json:"dataplane_error,omitempty"`
			}{Desired: state}
			if kernelStatus, err := dataplane.Inspect(ctx, state); err == nil {
				view.Dataplane = kernelStatus
			} else if !errors.Is(err, dataplane.ErrUnsupported) {
				view.DataplaneError = err.Error()
			}
			data, err := json.MarshalIndent(view, "", "  ")
			if err != nil {
				return err
			}
			fmt.Fprintln(stdout, string(data))
			return nil
		}
		data, err := state.JSON()
		if err != nil {
			return err
		}
		fmt.Fprintln(stdout, string(data))
	case "dump-abi":
		snapshot, err := abi.FromState(state)
		if err != nil {
			return err
		}
		data, err := json.MarshalIndent(snapshot, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(stdout, string(data))
	case "reload":
		if *dryRun {
			fmt.Fprintln(stdout, "reload plan validated")
			return nil
		}
		guardApplied := false
		if shouldApplyStartupGuard(cfg) {
			plan := guard.BuildNftPlan(state)
			if err := guard.NewCommandExecutor().Apply(ctx, plan); err != nil {
				return fmt.Errorf("apply startup guard: %w", err)
			}
			guardApplied = true
		}
		if err := dataplane.NewLoader().Apply(ctx, state); err != nil {
			return err
		}
		if guardApplied {
			if err := guard.NewCommandExecutor().Cleanup(ctx); err != nil {
				return fmt.Errorf("cleanup startup guard after reload: %w", err)
			}
		}
		fmt.Fprintln(stdout, "dataplane reloaded")
	case "detach":
		if *dryRun {
			fmt.Fprintln(stdout, "detach plan validated")
			return nil
		}
		if err := dataplane.NewLoader().Detach(ctx, state); err != nil {
			return err
		}
		fmt.Fprintln(stdout, "dataplane detached")
	case "guard-plan":
		plan := guard.BuildNftPlan(state)
		fmt.Fprint(stdout, plan.Script())
	case "guard-apply":
		plan := guard.BuildNftPlan(state)
		if *dryRun {
			fmt.Fprint(stdout, plan.Script())
			return nil
		}
		if err := guard.NewCommandExecutor().Apply(ctx, plan); err != nil {
			return err
		}
		fmt.Fprintln(stdout, "startup guard applied")
	case "guard-cleanup":
		if *dryRun {
			fmt.Fprint(stdout, guard.CleanupScript())
			return nil
		}
		if err := guard.NewCommandExecutor().Cleanup(ctx); err != nil {
			return err
		}
		fmt.Fprintln(stdout, "startup guard removed")
	}
	return nil
}

func shouldApplyStartupGuard(cfg *config.Config) bool {
	return cfg.StartupGuard.Mode == "nft-temporary-drop" &&
		cfg.Policy.StartupFailMode == "fail_closed_for_managed_flows"
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, strings.TrimSpace(`
wg-mix-ebpf <command> [flags]

Commands:
  validate   validate config and desired state
  status     print desired/runtime state as JSON
  dump       print desired map state as JSON
  dump-abi   print fixed BPF map ABI snapshot as JSON
  reload     validate reload plan (dataplane attach is implemented on Linux later)
  detach     validate detach plan (dataplane detach is implemented on Linux later)
  guard-plan print nft startup guard script
  guard-apply apply nft startup guard
  guard-cleanup remove nft startup guard table
  bpf-load-test load BPF object and exit without TC attach or WireGuard reads
  features   print local feature probe
  version    print version

Common flags:
  --config PATH   config path (default /etc/wg-mix-ebpf/config.yaml)
  --offline       skip runtime and underlay reads
  --dry-run       print external actions instead of applying them
`))
}
