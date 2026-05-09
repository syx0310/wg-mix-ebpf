package app

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
	"github.com/syx0310/wg-mix-ebpf/internal/config"
	"github.com/syx0310/wg-mix-ebpf/internal/control"
	"github.com/syx0310/wg-mix-ebpf/internal/daemon"
	"github.com/syx0310/wg-mix-ebpf/internal/dataplane"
	"github.com/syx0310/wg-mix-ebpf/internal/feature"
	"github.com/syx0310/wg-mix-ebpf/internal/install"
	"github.com/syx0310/wg-mix-ebpf/internal/profile"
	"github.com/syx0310/wg-mix-ebpf/internal/reconcile"
	"github.com/syx0310/wg-mix-ebpf/internal/wgconfig"
)

const Version = "dev"

func Run(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) error {
	return RunWithIO(ctx, args, os.Stdin, stdout, stderr)
}

func RunWithIO(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
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
	case "doctor":
		return runDoctor(ctx, args[1:], stdout)
	case "features":
		data, err := feature.Run().JSON()
		if err != nil {
			return err
		}
		fmt.Fprintln(stdout, string(data))
		return nil
	case "install":
		return runInstall(ctx, args[1:], stdout)
	case "uninstall":
		return runUninstall(ctx, args[1:], stdout)
	case "init":
		return runInit(ctx, args[1:], stdin, stdout)
	case "profile":
		return runProfile(args[1:], stdout)
	case "run":
		return runDaemon(ctx, args[1:])
	case "stop":
		return runStop(ctx, args[1:], stdout)
	case "bpf-load-test":
		return runBPFLoadTest(ctx, args[1:], stdout)
	case "validate", "status", "dump", "dump-abi", "reload", "detach", "guard-plan", "guard-apply", "guard-cleanup":
		return runStateCommand(ctx, cmd, args[1:], stdout)
	default:
		printUsage(stderr)
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func runDoctor(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configPath := fs.String("config", config.DefaultConfigPath, "path to wg-mix-ebpf config")
	jsonOut := fs.Bool("json", false, "print JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	probe := feature.Run()
	checks := []doctorCheck{
		statusCheck("arch", probe.SupportedArch, fmt.Sprintf("%s/%s", probe.GOOS, probe.GOARCH), "unsupported architecture outside MVP matrix"),
		statusCheck("proc", probe.ProcAvailable, "/proc", "missing /proc"),
		statusCheck("sysfs", probe.SysFSAvailable, "/sys/fs", "missing /sys/fs"),
		statusCheck("bpffs", probe.BPFFSAvailable && probe.BPFFSMounted, "/sys/fs/bpf", "bpffs is not mounted on /sys/fs/bpf"),
		commandCheck("tc", probe.Commands["tc"]),
		commandCheck("nft", probe.Commands["nft"]),
		commandCheck("wg", probe.Commands["wg"]),
	}
	if _, err := os.Stat(*configPath); err != nil {
		checks = append(checks, doctorCheck{Name: "config", Status: "WARN", Detail: *configPath, Message: err.Error()})
	} else if _, _, err := reconcile.BuildState(ctx, reconcile.Options{ConfigPath: *configPath}); err != nil {
		checks = append(checks, doctorCheck{Name: "config/runtime", Status: "FAIL", Detail: *configPath, Message: err.Error()})
	} else {
		checks = append(checks, doctorCheck{Name: "config/runtime", Status: "PASS", Detail: *configPath})
	}
	if *jsonOut {
		return writeJSON(stdout, struct {
			Probe  feature.Probe `json:"probe"`
			Checks []doctorCheck `json:"checks"`
		}{Probe: probe, Checks: checks})
	}
	for _, check := range checks {
		line := fmt.Sprintf("%-11s %-20s %s", check.Status, check.Name, check.Detail)
		if check.Message != "" {
			line += " - " + check.Message
		}
		fmt.Fprintln(stdout, line)
	}
	return nil
}

type doctorCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Detail  string `json:"detail,omitempty"`
	Message string `json:"message,omitempty"`
}

func statusCheck(name string, ok bool, detail string, message string) doctorCheck {
	if ok {
		return doctorCheck{Name: name, Status: "PASS", Detail: detail}
	}
	return doctorCheck{Name: name, Status: "FAIL", Detail: detail, Message: message}
}

func commandCheck(name string, path string) doctorCheck {
	if path == "" {
		return doctorCheck{Name: "cmd." + name, Status: "FAIL", Message: "not found in PATH"}
	}
	return doctorCheck{Name: "cmd." + name, Status: "PASS", Detail: path}
}

func runInstall(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configPath := fs.String("config", "", "path to wg-mix-ebpf config")
	system := fs.String("system", "", "init system override: systemd, openwrt, unknown")
	enable := fs.Bool("enable", false, "enable service without starting it")
	dryRun := fs.Bool("dry-run", false, "print actions instead of applying them")
	if err := fs.Parse(args); err != nil {
		return err
	}
	plan, err := install.Install(ctx, install.Options{ConfigPath: *configPath, System: *system, Enable: *enable, DryRun: *dryRun})
	if err != nil {
		return err
	}
	printPlan(stdout, plan)
	return nil
}

func runUninstall(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configPath := fs.String("config", "", "path to wg-mix-ebpf config")
	system := fs.String("system", "", "init system override: systemd, openwrt, unknown")
	dryRun := fs.Bool("dry-run", false, "print actions instead of applying them")
	yes := fs.Bool("yes", false, "confirm detach while WireGuard may still be running")
	purge := fs.Bool("purge", false, "delete /etc/wg-mix-ebpf as well")
	if err := fs.Parse(args); err != nil {
		return err
	}
	plan, err := install.Uninstall(ctx, install.Options{ConfigPath: *configPath, System: *system, DryRun: *dryRun, Yes: *yes, Purge: *purge})
	if err != nil {
		return err
	}
	printPlan(stdout, plan)
	return nil
}

func printPlan(stdout io.Writer, plan *install.Plan) {
	fmt.Fprintf(stdout, "system: %s\n", plan.System)
	fmt.Fprintf(stdout, "config: %s\n", plan.ConfigPath)
	fmt.Fprintf(stdout, "binary: %s\n", plan.BinaryPath)
	for _, action := range plan.Actions {
		fmt.Fprintf(stdout, "- %s\n", action)
	}
}

func runInit(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configPath := fs.String("config", config.DefaultConfigPath, "path to wg-mix-ebpf config")
	wgName := fs.String("wg", "", "WireGuard interface name")
	wgConfig := fs.String("wg-config", "", "WireGuard config path")
	underlaySpec := fs.String("underlay", "", "underlay as name:type, type defaults to netdev")
	profileName := fs.String("profile", "", "profile name")
	profileRandom := fs.Bool("profile-random", false, "create profile with random type_word values")
	profileToken := fs.String("profile-token", "", "create/import profile from token")
	profilePreset := fs.String("profile-preset", "", "create profile from preset")
	reload := fs.Bool("reload", false, "apply after writing config")
	if err := fs.Parse(args); err != nil {
		return err
	}

	reader := bufio.NewReader(stdin)
	if *wgName == "" {
		*wgName = prompt(reader, stdout, "WireGuard interface name")
	}
	if *underlaySpec == "" {
		*underlaySpec = prompt(reader, stdout, "Underlay (name:type)")
	}
	if *profileName == "" {
		*profileName = prompt(reader, stdout, "Profile name")
	}
	if *wgName == "" || *underlaySpec == "" || *profileName == "" {
		return errors.New("init requires --wg, --underlay and --profile")
	}
	if *wgConfig == "" {
		*wgConfig = config.DefaultWGDir + "/" + *wgName + ".conf"
	}
	parsedWG, err := wgconfig.ParseFile(*wgConfig)
	if err != nil {
		return fmt.Errorf("read WireGuard config %s: %w", *wgConfig, err)
	}
	if parsedWG.FwMark == nil || *parsedWG.FwMark == 0 {
		return fmt.Errorf("WireGuard config %s must contain non-zero FwMark or PostUp 'wg set %%i fwmark ...'; wg-mix-ebpf will not modify it", *wgConfig)
	}

	cfg, err := loadOrTemplate(*configPath)
	if err != nil {
		return err
	}
	if cfg.Profiles == nil {
		cfg.Profiles = make(map[string]config.Profile)
	}
	if _, ok := cfg.Profiles[*profileName]; !ok {
		prof, err := profileForInit(*profileRandom, *profileToken, *profilePreset, reader, stdout)
		if err != nil {
			return err
		}
		cfg.Profiles[*profileName] = prof
	} else if *profileRandom || *profileToken != "" || *profilePreset != "" {
		return fmt.Errorf("profile %q already exists; choose a new name or edit it with profile commands", *profileName)
	}
	underlay, err := parseUnderlaySpec(*underlaySpec)
	if err != nil {
		return err
	}
	upsertUnderlay(cfg, underlay)
	upsertWireGuard(cfg, config.WireGuard{Name: *wgName, Config: *wgConfig, Profile: *profileName, NetNS: "root"})
	if err := cfg.ValidateStatic(); err != nil {
		return err
	}
	if err := config.SaveFile(*configPath, cfg); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "config initialized: %s\n", *configPath)
	if *reload {
		_, err := reconcile.Reload(ctx, reconcile.Options{ConfigPath: *configPath})
		if err != nil {
			return err
		}
		fmt.Fprintln(stdout, "dataplane reloaded")
	}
	return nil
}

func profileForInit(random bool, token string, preset string, reader *bufio.Reader, stdout io.Writer) (config.Profile, error) {
	selected := 0
	for _, enabled := range []bool{random, token != "", preset != ""} {
		if enabled {
			selected++
		}
	}
	if selected > 1 {
		return config.Profile{}, errors.New("choose only one of --profile-random, --profile-token or --profile-preset")
	}
	if token != "" {
		return profile.DecodeToken(token)
	}
	if preset != "" {
		return profile.Preset(preset)
	}
	if random {
		return profile.GenerateRandom()
	}
	choice := prompt(reader, stdout, "Profile source (preset/random/token)")
	switch choice {
	case "", "preset":
		return profile.Preset("wireguard-mix-wire-values-v1")
	case "random":
		return profile.GenerateRandom()
	case "token":
		tokenValue := prompt(reader, stdout, "Profile token")
		return profile.DecodeToken(tokenValue)
	default:
		return config.Profile{}, fmt.Errorf("unknown profile source %q", choice)
	}
}

func runProfile(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		printProfileUsage(stdout)
		return errors.New("missing profile command")
	}
	cmd := args[0]
	switch cmd {
	case "list":
		cfg, _, err := loadProfileConfig(args[1:])
		if err != nil {
			return err
		}
		names := make([]string, 0, len(cfg.Profiles))
		for name := range cfg.Profiles {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			fmt.Fprintln(stdout, name)
		}
		return nil
	case "show":
		cfg, rest, err := loadProfileConfig(args[1:])
		if err != nil {
			return err
		}
		if len(rest) != 1 {
			return errors.New("profile show requires a profile name")
		}
		prof, ok := cfg.Profiles[rest[0]]
		if !ok {
			return fmt.Errorf("profile %q not found", rest[0])
		}
		data, err := yaml.Marshal(prof)
		if err != nil {
			return err
		}
		fmt.Fprint(stdout, string(data))
		return nil
	case "add":
		return runProfileAdd(args[1:], stdout)
	case "token":
		cfg, rest, err := loadProfileConfig(args[1:])
		if err != nil {
			return err
		}
		if len(rest) != 1 {
			return errors.New("profile token requires a profile name")
		}
		prof, ok := cfg.Profiles[rest[0]]
		if !ok {
			return fmt.Errorf("profile %q not found", rest[0])
		}
		token, err := profile.EncodeToken(prof)
		if err != nil {
			return err
		}
		fmt.Fprintln(stdout, token)
		return nil
	case "check":
		fs := flag.NewFlagSet("profile check", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return errors.New("profile check requires a token")
		}
		if _, err := profile.DecodeToken(fs.Arg(0)); err != nil {
			return err
		}
		fmt.Fprintln(stdout, "ok")
		return nil
	case "remove":
		return runProfileRemove(args[1:], stdout)
	default:
		printProfileUsage(stdout)
		return fmt.Errorf("unknown profile command %q", cmd)
	}
}

func runProfileAdd(args []string, stdout io.Writer) error {
	configPath, rest, err := extractStringFlag(args, "config", config.DefaultConfigPath)
	if err != nil {
		return err
	}
	preset, rest, err := extractStringFlag(rest, "preset", "")
	if err != nil {
		return err
	}
	token, rest, err := extractStringFlag(rest, "token", "")
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return errors.New("profile add requires a profile name")
	}
	name := rest[0]
	cfg, err := loadOrTemplate(configPath)
	if err != nil {
		return err
	}
	if cfg.Profiles == nil {
		cfg.Profiles = make(map[string]config.Profile)
	}
	if _, exists := cfg.Profiles[name]; exists {
		return fmt.Errorf("profile %q already exists", name)
	}
	if preset != "" && token != "" {
		return errors.New("choose only one of --preset or --token")
	}
	var prof config.Profile
	if token != "" {
		prof, err = profile.DecodeToken(token)
	} else if preset != "" {
		prof, err = profile.Preset(preset)
	} else {
		prof, err = profile.GenerateRandom()
	}
	if err != nil {
		return err
	}
	cfg.Profiles[name] = prof
	if err := validateLenientForProfileWrite(cfg); err != nil {
		return err
	}
	if err := config.SaveFile(configPath, cfg); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "profile %s added\n", name)
	return nil
}

func runProfileRemove(args []string, stdout io.Writer) error {
	configPath, rest, err := extractStringFlag(args, "config", config.DefaultConfigPath)
	if err != nil {
		return err
	}
	force, rest, err := extractBoolFlag(rest, "force")
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return errors.New("profile remove requires a profile name")
	}
	name := rest[0]
	cfg, err := config.LoadFileLenient(configPath)
	if err != nil {
		return err
	}
	if _, ok := cfg.Profiles[name]; !ok {
		return fmt.Errorf("profile %q not found", name)
	}
	var refs []string
	for _, wg := range cfg.WireGuards {
		if wg.Profile == name {
			refs = append(refs, wg.Name)
		}
	}
	if len(refs) > 0 && !force {
		return fmt.Errorf("profile %q is used by wireguards %s; rerun with --force to stop managing those interfaces", name, strings.Join(refs, ","))
	}
	delete(cfg.Profiles, name)
	if len(refs) > 0 {
		filtered := cfg.WireGuards[:0]
		for _, wg := range cfg.WireGuards {
			if wg.Profile != name {
				filtered = append(filtered, wg)
			}
		}
		cfg.WireGuards = filtered
	}
	if err := validateLenientForProfileWrite(cfg); err != nil {
		return err
	}
	if err := config.SaveFile(configPath, cfg); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "profile %s removed\n", name)
	if len(refs) > 0 {
		fmt.Fprintf(stdout, "unmanaged wireguards: %s\n", strings.Join(refs, ","))
	}
	return nil
}

func loadProfileConfig(args []string) (*config.Config, []string, error) {
	configPath, rest, err := extractStringFlag(args, "config", config.DefaultConfigPath)
	if err != nil {
		return nil, nil, err
	}
	cfg, err := config.LoadFileLenient(configPath)
	if err != nil {
		return nil, nil, err
	}
	return cfg, rest, nil
}

func validateLenientForProfileWrite(cfg *config.Config) error {
	if cfg.Profiles == nil {
		return nil
	}
	_, err := profile.CompileAll(cfg.Profiles)
	return err
}

func extractStringFlag(args []string, name string, fallback string) (string, []string, error) {
	value := fallback
	out := make([]string, 0, len(args))
	long := "--" + name
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == long {
			if i+1 >= len(args) {
				return "", nil, fmt.Errorf("%s requires a value", long)
			}
			value = args[i+1]
			i++
			continue
		}
		if strings.HasPrefix(arg, long+"=") {
			value = strings.TrimPrefix(arg, long+"=")
			continue
		}
		out = append(out, arg)
	}
	return value, out, nil
}

func extractBoolFlag(args []string, name string) (bool, []string, error) {
	value := false
	out := make([]string, 0, len(args))
	long := "--" + name
	for _, arg := range args {
		if arg == long {
			value = true
			continue
		}
		if strings.HasPrefix(arg, long+"=") {
			raw := strings.TrimPrefix(arg, long+"=")
			switch raw {
			case "1", "true", "yes", "on":
				value = true
			case "0", "false", "no", "off":
				value = false
			default:
				return false, nil, fmt.Errorf("%s has invalid boolean value %q", long, raw)
			}
			continue
		}
		out = append(out, arg)
	}
	return value, out, nil
}

func runDaemon(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configPath := fs.String("config", config.DefaultConfigPath, "path to wg-mix-ebpf config")
	runDir := fs.String("run-dir", "", "runtime status/request directory")
	stateDir := fs.String("state-dir", "", "persistent attach-state directory")
	once := fs.Bool("once", false, "run one reconcile and exit")
	offline := fs.Bool("offline", false, "skip runtime and underlay reads")
	dryRun := fs.Bool("dry-run", false, "validate/reconcile without applying dataplane")
	openwrt := fs.Bool("openwrt", false, "OpenWrt service mode marker")
	_ = openwrt
	if err := fs.Parse(args); err != nil {
		return err
	}
	return daemon.Run(ctx, daemon.Options{ConfigPath: *configPath, RunDir: *runDir, StateDir: *stateDir, Once: *once, Offline: *offline, DryRun: *dryRun})
}

func runStop(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("stop", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configPath := fs.String("config", config.DefaultConfigPath, "path to wg-mix-ebpf config")
	runDir := fs.String("run-dir", "", "daemon runtime directory")
	stateDir := fs.String("state-dir", "", "persistent attach-state directory")
	timeout := fs.Duration("timeout", 10*time.Second, "stop request timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if status, err := daemon.ReadStatus(*runDir); err == nil && daemon.IsRunning(status) {
		if _, err := daemon.RequestStop(ctx, *runDir, *configPath, *timeout); err != nil {
			return err
		}
		fmt.Fprintln(stdout, "daemon stopped and dataplane detached")
		return nil
	}
	if _, err := reconcile.Stop(ctx, reconcile.Options{ConfigPath: *configPath, RunDir: daemonRunDir(*runDir), StateDir: *stateDir}); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "dataplane detached")
	return nil
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
	runDir := fs.String("run-dir", "", "daemon runtime directory")
	stateDir := fs.String("state-dir", "", "persistent attach-state directory")
	reason := fs.String("reason", "manual", "operation reason")
	_ = reason
	if err := fs.Parse(args); err != nil {
		return err
	}
	opts := reconcile.Options{ConfigPath: *configPath, RunDir: daemonRunDir(*runDir), StateDir: *stateDir, Offline: *offline, DryRun: *dryRun}

	switch cmd {
	case "validate":
		if _, err := reconcile.Validate(ctx, opts); err != nil {
			return err
		}
		fmt.Fprintln(stdout, "ok")
	case "status", "dump":
		if cmd == "status" {
			view := struct {
				Daemon        *daemon.Status `json:"daemon,omitempty"`
				Desired       *control.State `json:"desired,omitempty"`
				Dataplane     any            `json:"dataplane,omitempty"`
				Error         string         `json:"dataplane_error,omitempty"`
				DesiredError  string         `json:"desired_error,omitempty"`
				DataplaneNote string         `json:"dataplane_note,omitempty"`
			}{}
			if status, err := daemon.ReadStatus(*runDir); err == nil {
				view.Daemon = status
			}
			result, err := reconcile.Status(ctx, opts)
			if err != nil {
				if view.Daemon == nil {
					return err
				}
				view.DesiredError = err.Error()
				view.DataplaneNote = "desired state unavailable; showing daemon status only"
				return writeJSON(stdout, view)
			}
			view.Desired = result.State
			view.Dataplane = result.Dataplane
			view.Error = result.DataplaneError
			return writeJSON(stdout, view)
		}
		result, err := reconcile.Validate(ctx, opts)
		if err != nil {
			return err
		}
		data, err := result.State.JSON()
		if err != nil {
			return err
		}
		fmt.Fprintln(stdout, string(data))
	case "dump-abi":
		result, err := reconcile.Validate(ctx, opts)
		if err != nil {
			return err
		}
		snapshot, err := abi.FromState(result.State)
		if err != nil {
			return err
		}
		return writeJSON(stdout, snapshot)
	case "reload":
		if !*dryRun && !*offline {
			if status, err := daemon.ReadStatus(*runDir); err == nil && daemon.IsRunning(status) {
				if _, err := daemon.RequestReload(ctx, *runDir, *configPath, 10*time.Second); err != nil {
					return err
				}
				fmt.Fprintln(stdout, "daemon reload requested")
				return nil
			}
		}
		if _, err := reconcile.Reload(ctx, opts); err != nil {
			return err
		}
		if *dryRun {
			fmt.Fprintln(stdout, "reload plan validated")
		} else {
			fmt.Fprintln(stdout, "dataplane reloaded")
		}
	case "detach":
		if _, err := reconcile.Detach(ctx, opts); err != nil {
			return err
		}
		if *dryRun {
			fmt.Fprintln(stdout, "detach plan validated")
		} else {
			fmt.Fprintln(stdout, "dataplane detached")
		}
	case "guard-plan":
		result, err := reconcile.GuardPlan(ctx, opts)
		if err != nil {
			return err
		}
		fmt.Fprint(stdout, result.GuardScript)
	case "guard-apply":
		result, err := reconcile.GuardApply(ctx, opts)
		if err != nil {
			return err
		}
		if *dryRun {
			fmt.Fprint(stdout, result.GuardScript)
		} else {
			fmt.Fprintln(stdout, "startup guard applied")
		}
	case "guard-cleanup":
		result, err := reconcile.GuardCleanup(ctx, opts)
		if err != nil {
			return err
		}
		if *dryRun {
			fmt.Fprint(stdout, result.GuardCleanup)
		} else {
			fmt.Fprintln(stdout, "startup guard removed")
		}
	}
	return nil
}

func daemonRunDir(path string) string {
	if path != "" {
		return path
	}
	if env := os.Getenv(daemon.EnvRunDir); env != "" {
		return env
	}
	return daemon.DefaultRunDir
}

func loadOrTemplate(path string) (*config.Config, error) {
	cfg, err := config.LoadFileLenient(path)
	if errors.Is(err, os.ErrNotExist) {
		return config.SafeTemplate(), nil
	}
	return cfg, err
}

func parseUnderlaySpec(raw string) (config.Underlay, error) {
	name, typ, ok := strings.Cut(raw, ":")
	name = strings.TrimSpace(name)
	typ = strings.TrimSpace(typ)
	if !ok || typ == "" {
		typ = "netdev"
	}
	if name == "" {
		return config.Underlay{}, errors.New("underlay name is required")
	}
	return config.Underlay{Name: name, Type: typ}, nil
}

func upsertUnderlay(cfg *config.Config, underlay config.Underlay) {
	for i := range cfg.Underlays {
		if cfg.Underlays[i].Name == underlay.Name {
			cfg.Underlays[i] = underlay
			return
		}
	}
	cfg.Underlays = append(cfg.Underlays, underlay)
}

func upsertWireGuard(cfg *config.Config, wg config.WireGuard) {
	for i := range cfg.WireGuards {
		if cfg.WireGuards[i].Name == wg.Name {
			cfg.WireGuards[i] = wg
			return
		}
	}
	cfg.WireGuards = append(cfg.WireGuards, wg)
}

func prompt(reader *bufio.Reader, stdout io.Writer, label string) string {
	fmt.Fprintf(stdout, "%s: ", label)
	value, _ := reader.ReadString('\n')
	return strings.TrimSpace(value)
}

func writeJSON(stdout io.Writer, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, string(data))
	return nil
}

func printProfileUsage(w io.Writer) {
	fmt.Fprintln(w, strings.TrimSpace(`
wg-mix-ebpf profile <command> [flags]

Commands:
  list                  list profiles
  show <name>           show a profile
  add <name>            add a random profile
  add <name> --preset P add a preset profile
  add <name> --token T  add a token profile
  token <name>          print export token
  check <token>         validate a token
  remove <name>         remove an unused profile
  remove <name> --force remove profile and stop managing dependent wg entries
`))
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, strings.TrimSpace(`
wg-mix-ebpf <command> [flags]

Commands:
  doctor      inspect local environment without changing it
  install     install binary, config template, service/init files; does not start
  init        initialize config and profiles
  profile     manage transform profiles
  run         internal daemon reconcile loop
  stop        ask daemon to detach dataplane and exit, or one-shot detach
  validate    validate config and desired state
  status      print desired/runtime/dataplane state as JSON
  dump        print desired map state as JSON
  dump-abi    print fixed BPF map ABI snapshot as JSON
  reload      notify daemon or one-shot apply dataplane
  detach      detach this agent's dataplane
  uninstall   stop service, detach, remove pins/state/service; keeps config by default
  guard-plan  print nft startup guard script
  guard-apply apply nft startup guard
  guard-cleanup remove nft startup guard table
  bpf-load-test load BPF object and exit without TC attach or WireGuard reads
  features    print raw local feature probe JSON
  version     print version

Common flags:
  --config PATH   config path (default /etc/wg-mix-ebpf/config.yaml)
  --offline       skip runtime and underlay reads where supported
  --dry-run       print external actions instead of applying them
`))
}
