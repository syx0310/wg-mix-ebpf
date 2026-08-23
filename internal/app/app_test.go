package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
	"github.com/syx0310/wg-mix-ebpf/internal/buildinfo"
	"github.com/syx0310/wg-mix-ebpf/internal/config"
	"github.com/syx0310/wg-mix-ebpf/internal/daemon"
	"github.com/syx0310/wg-mix-ebpf/internal/dataplane"
	"github.com/syx0310/wg-mix-ebpf/internal/guard"
	"github.com/syx0310/wg-mix-ebpf/internal/install"
	"github.com/syx0310/wg-mix-ebpf/internal/lockfile"
	"github.com/syx0310/wg-mix-ebpf/internal/reconcile"
)

func TestFakeTCPChecksumDoctorChecksSelectsKfuncBeforeEquivalentKprobe(t *testing.T) {
	checks := fakeTCPChecksumDoctorChecks("auto", []dataplane.FakeTCPChecksumBackendProbe{
		{
			Backend: "kfunc", Available: true, Equivalent: true,
			Capability: dataplane.FakeTCPChecksumCapabilityFullGSOV1,
			Module:     dataplane.DefaultFakeTCPKfuncModule,
		},
		{
			Backend: "kprobe", Available: true, Equivalent: true,
			Capability: dataplane.FakeTCPChecksumCapabilityFullGSOV1,
			Module:     dataplane.DefaultFakeTCPKprobeModule,
			Requirements: []dataplane.FakeTCPChecksumRequirement{
				{Name: "CONFIG_KPROBES", Status: "PASS", Detail: "y"},
			},
		},
	})
	selection := checks[len(checks)-1]
	if selection.Status != "PASS" || !strings.Contains(selection.Detail, "selected=kfunc") {
		t.Fatalf("selection = %#v", selection)
	}
	seenRequirement := false
	for _, check := range checks {
		if check.Name == "faketcp.kprobe.CONFIG_KPROBES" && check.Status == "PASS" {
			seenRequirement = true
		}
	}
	if !seenRequirement {
		t.Fatalf("doctor did not expand kprobe requirements: %#v", checks)
	}
}

func TestFakeTCPChecksumDoctorChecksNeverFallsBackFromExplicitKfunc(t *testing.T) {
	checks := fakeTCPChecksumDoctorChecks("kfunc", []dataplane.FakeTCPChecksumBackendProbe{
		{Backend: "kfunc", Available: false, Equivalent: false, Error: "BTF unavailable"},
		{Backend: "kprobe", Available: true, Equivalent: true},
	})
	selection := checks[len(checks)-1]
	if selection.Status != "FAIL" || strings.Contains(selection.Detail, "selected=kprobe") {
		t.Fatalf("explicit selection silently fell back: %#v", selection)
	}
}

func TestFakeTCPChecksumDoctorChecksAutoFallsBackOnlyFromUnsupportedKfunc(t *testing.T) {
	kprobe := dataplane.FakeTCPChecksumBackendProbe{
		Backend: "kprobe", Available: true, Equivalent: true,
	}
	checks := fakeTCPChecksumDoctorChecks("auto", []dataplane.FakeTCPChecksumBackendProbe{
		{Backend: "kfunc", Error: "permission denied"},
		kprobe,
	})
	selection := checks[len(checks)-1]
	if selection.Status != "FAIL" || !strings.Contains(selection.Message, "refusing automatic fallback") {
		t.Fatalf("operational failure selection = %#v", selection)
	}
	checks = fakeTCPChecksumDoctorChecks("auto", []dataplane.FakeTCPChecksumBackendProbe{
		{Backend: "kfunc", Unsupported: true, Error: "module not found"},
		kprobe,
	})
	selection = checks[len(checks)-1]
	if selection.Status != "PASS" || !strings.Contains(selection.Detail, "selected=kprobe") {
		t.Fatalf("unsupported selection = %#v", selection)
	}
}

func TestBPFLoadTestDefaultsToBaselineLoaderAndOutput(t *testing.T) {
	var baselineCalls, experimentalCalls int
	identity := dataplane.ObjectIdentity{
		Source:   "embedded:wg_mix_tc.o",
		SHA256:   strings.Repeat("a", 64),
		Embedded: true,
	}
	baseline := func(_ context.Context, objectPath string) (dataplane.ObjectIdentity, error) {
		baselineCalls++
		if objectPath != "" {
			t.Fatalf("default object path = %q, want empty embedded-object selector", objectPath)
		}
		return identity, nil
	}
	experimental := func(context.Context, string) (dataplane.ObjectIdentity, error) {
		experimentalCalls++
		return dataplane.ObjectIdentity{}, errors.New("experimental loader must not run")
	}

	var stdout bytes.Buffer
	if err := runBPFLoadTestWithLoaders(
		t.Context(), nil, &stdout, baseline, experimental, experimental,
	); err != nil {
		t.Fatal(err)
	}
	if baselineCalls != 1 || experimentalCalls != 0 {
		t.Fatalf("loader calls baseline=%d experimental=%d", baselineCalls, experimentalCalls)
	}
	want := "BPF object loaded successfully: " + identity.Source + " (sha256=" + identity.SHA256 + ")\n"
	if got := stdout.String(); got != want {
		t.Fatalf("default text output = %q, want %q", got, want)
	}

	stdout.Reset()
	if err := runBPFLoadTestWithLoaders(
		t.Context(), []string{"--json"}, &stdout, baseline, experimental, experimental,
	); err != nil {
		t.Fatal(err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatalf("decode default JSON: %v\n%s", err, stdout.String())
	}
	if _, found := document["kind"]; found {
		t.Fatalf("default baseline JSON unexpectedly changed kind contract: %s", stdout.String())
	}
	if baselineCalls != 2 || experimentalCalls != 0 {
		t.Fatalf("loader calls after JSON baseline=%d experimental=%d", baselineCalls, experimentalCalls)
	}
}

func TestParseDaemonOptionsProgressStatus(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		want bool
	}{
		{name: "default", want: true},
		{name: "explicit true", args: []string{"--progress-status=true"}, want: true},
		{name: "explicit false", args: []string{"--progress-status=false"}, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			opts, err := parseDaemonOptions(test.args)
			if err != nil {
				t.Fatal(err)
			}
			if opts.ProgressStatus == nil || *opts.ProgressStatus != test.want {
				t.Fatalf("progress status = %v, want %t", opts.ProgressStatus, test.want)
			}
		})
	}
	if _, err := parseDaemonOptions([]string{"--progress-status=false", "unexpected"}); err == nil {
		t.Fatal("run accepted an unexpected positional argument")
	}
}

func TestBPFLoadTestFakeTCPFlagsRequireExplicitObject(t *testing.T) {
	loaderCalls := 0
	loader := func(context.Context, string) (dataplane.ObjectIdentity, error) {
		loaderCalls++
		return dataplane.ObjectIdentity{}, errors.New("loader must not run")
	}
	for _, args := range [][]string{
		{"--faketcp"},
		{"--faketcp", "--object="},
		{"--faketcp", "--object", "   "},
		{"--experimental-faketcp"},
		{"--faketcp-legacy-515"},
	} {
		var stdout bytes.Buffer
		err := runBPFLoadTestWithLoaders(t.Context(), args, &stdout, loader, loader, loader)
		if err == nil || !strings.Contains(err.Error(), "requires an explicit non-empty --object path") {
			t.Fatalf("args=%q error=%v", args, err)
		}
		if stdout.Len() != 0 {
			t.Fatalf("args=%q produced output %q", args, stdout.String())
		}
	}
	if loaderCalls != 0 {
		t.Fatalf("missing-object contract invoked a loader %d times", loaderCalls)
	}
}

func TestBPFLoadTestFakeTCPDispatchIdentityAndDeprecatedAlias(t *testing.T) {
	const objectPath = "/reviewed/wg_mix_faketcp_experimental.o"
	identity := dataplane.ObjectIdentity{
		Source: objectPath,
		SHA256: strings.Repeat("b", 64),
	}
	baselineCalls := 0
	baseline := func(context.Context, string) (dataplane.ObjectIdentity, error) {
		baselineCalls++
		return dataplane.ObjectIdentity{}, errors.New("baseline loader must not run")
	}
	experimentalCalls := 0
	experimental := func(_ context.Context, gotPath string) (dataplane.ObjectIdentity, error) {
		experimentalCalls++
		if gotPath != objectPath {
			t.Fatalf("experimental object path = %q, want %q", gotPath, objectPath)
		}
		return identity, nil
	}

	var textOut bytes.Buffer
	err := runBPFLoadTestWithLoaders(
		t.Context(),
		[]string{"--faketcp", "--object", objectPath},
		&textOut,
		baseline,
		experimental,
		experimental,
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"kind=" + dataplane.FakeTCPObjectKind,
		"source=" + objectPath,
		"sha256=" + identity.SHA256,
	} {
		if !strings.Contains(textOut.String(), want) {
			t.Fatalf("experimental text output %q missing %q", textOut.String(), want)
		}
	}

	var jsonOut bytes.Buffer
	err = runBPFLoadTestWithLoaders(
		t.Context(),
		[]string{"--experimental-faketcp", "--object", objectPath, "--json"},
		&jsonOut,
		baseline,
		experimental,
		experimental,
	)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Status string                   `json:"status"`
		Kind   string                   `json:"kind"`
		Object dataplane.ObjectIdentity `json:"object"`
	}
	if err := json.Unmarshal(jsonOut.Bytes(), &got); err != nil {
		t.Fatalf("decode output: %v\n%s", err, jsonOut.String())
	}
	if got.Status != "loaded" || got.Kind != dataplane.FakeTCPObjectKind || got.Object != identity {
		t.Fatalf("experimental JSON identity = %#v", got)
	}
	if baselineCalls != 0 || experimentalCalls != 2 {
		t.Fatalf("loader calls baseline=%d experimental=%d", baselineCalls, experimentalCalls)
	}
}

func TestBPFLoadTestLegacy515DispatchesIndependentLoader(t *testing.T) {
	const objectPath = "/reviewed/wg_mix_faketcp_legacy_515.o"
	identity := dataplane.ObjectIdentity{
		Source: objectPath,
		SHA256: strings.Repeat("c", 64),
	}
	unexpected := func(context.Context, string) (dataplane.ObjectIdentity, error) {
		return dataplane.ObjectIdentity{}, errors.New("unexpected loader")
	}
	legacyCalls := 0
	legacy := func(_ context.Context, gotPath string) (dataplane.ObjectIdentity, error) {
		legacyCalls++
		if gotPath != objectPath {
			t.Fatalf("legacy object path = %q, want %q", gotPath, objectPath)
		}
		return identity, nil
	}

	var stdout bytes.Buffer
	err := runBPFLoadTestWithLoaders(
		t.Context(),
		[]string{"--faketcp-legacy-515", "--object", objectPath, "--json"},
		&stdout,
		unexpected,
		unexpected,
		legacy,
	)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Status string                   `json:"status"`
		Kind   string                   `json:"kind"`
		Object dataplane.ObjectIdentity `json:"object"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode output: %v\n%s", err, stdout.String())
	}
	if got.Status != "loaded" || got.Kind != dataplane.FakeTCPLegacy515ObjectKind || got.Object != identity {
		t.Fatalf("legacy JSON identity = %#v", got)
	}
	if legacyCalls != 1 {
		t.Fatalf("legacy loader calls = %d, want 1", legacyCalls)
	}
}

func TestBPFLoadTestRejectsConflictingFakeTCPModes(t *testing.T) {
	loader := func(context.Context, string) (dataplane.ObjectIdentity, error) {
		return dataplane.ObjectIdentity{}, errors.New("loader must not run")
	}
	err := runBPFLoadTestWithLoaders(
		t.Context(),
		[]string{"--faketcp", "--faketcp-legacy-515", "--object", "/object.o"},
		io.Discard,
		loader,
		loader,
		loader,
	)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("conflicting mode error = %v", err)
	}
}

func TestBPFLoadTestListsThenLoadsOneExactFakeTCPProgram(t *testing.T) {
	identity := dataplane.ObjectIdentity{
		Source: "/proc/self/fd/101", SHA256: strings.Repeat("d", 64),
	}
	unexpected := func(context.Context, string) (dataplane.ObjectIdentity, error) {
		return dataplane.ObjectIdentity{}, errors.New("aggregate loader must not run")
	}
	inspector := func(_ context.Context, path string) (dataplane.ObjectIdentity, []string, error) {
		if path != identity.Source {
			t.Fatalf("inspect path = %q", path)
		}
		return identity, []string{"a_program", "z_program"}, nil
	}
	programCalls := 0
	programLoader := func(_ context.Context, path, program string) (dataplane.ObjectIdentity, error) {
		programCalls++
		if path != identity.Source || program != "z_program" {
			t.Fatalf("program load path=%q program=%q", path, program)
		}
		return identity, nil
	}
	var output bytes.Buffer
	err := runBPFLoadTestWithVerifierLoaders(
		t.Context(),
		[]string{"--faketcp", "--object", identity.Source, "--list-programs", "--json"},
		&output,
		unexpected,
		unexpected,
		unexpected,
		inspector,
		inspector,
		programLoader,
		programLoader,
	)
	if err != nil {
		t.Fatal(err)
	}
	var listing struct {
		Status   string                   `json:"status"`
		Object   dataplane.ObjectIdentity `json:"object"`
		Programs []string                 `json:"programs"`
	}
	if err := json.Unmarshal(output.Bytes(), &listing); err != nil {
		t.Fatal(err)
	}
	if listing.Status != "inspected" || listing.Object != identity || strings.Join(listing.Programs, ",") != "a_program,z_program" {
		t.Fatalf("listing = %#v", listing)
	}

	output.Reset()
	err = runBPFLoadTestWithVerifierLoaders(
		t.Context(),
		[]string{"--faketcp", "--object", identity.Source, "--program", "z_program", "--json"},
		&output,
		unexpected,
		unexpected,
		unexpected,
		inspector,
		inspector,
		programLoader,
		programLoader,
	)
	if err != nil {
		t.Fatal(err)
	}
	var loaded struct {
		Program string `json:"program"`
	}
	if err := json.Unmarshal(output.Bytes(), &loaded); err != nil {
		t.Fatal(err)
	}
	if programCalls != 1 || loaded.Program != "z_program" {
		t.Fatalf("program calls=%d output=%s", programCalls, output.String())
	}
}

func TestBPFLoadTestExplicitObjectWithoutOptInRemainsBaseline(t *testing.T) {
	const objectPath = "/candidate/object.o"
	baselineCalls := 0
	baseline := func(_ context.Context, gotPath string) (dataplane.ObjectIdentity, error) {
		baselineCalls++
		if gotPath != objectPath {
			t.Fatalf("baseline object path = %q, want %q", gotPath, objectPath)
		}
		return dataplane.ObjectIdentity{Source: gotPath, SHA256: strings.Repeat("c", 64)}, nil
	}
	experimentalCalls := 0
	experimental := func(context.Context, string) (dataplane.ObjectIdentity, error) {
		experimentalCalls++
		return dataplane.ObjectIdentity{}, errors.New("experimental loader must not run")
	}
	var stdout bytes.Buffer
	if err := runBPFLoadTestWithLoaders(
		t.Context(), []string{"--object", objectPath}, &stdout, baseline, experimental, experimental,
	); err != nil {
		t.Fatal(err)
	}
	if baselineCalls != 1 || experimentalCalls != 0 {
		t.Fatalf("loader calls baseline=%d experimental=%d", baselineCalls, experimentalCalls)
	}
}

func TestVersionOutputIsBackwardCompatible(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := Run(t.Context(), []string{"version"}, &stdout, &stderr); err != nil {
		t.Fatalf("version failed: %v stderr=%s", err, stderr.String())
	}
	if got, want := stdout.String(), Version+"\n"; got != want {
		t.Fatalf("version output = %q, want %q", got, want)
	}
}

func TestVersionJSONReportsDeterministicBuildIdentity(t *testing.T) {
	var first, second, stderr bytes.Buffer
	if err := Run(t.Context(), []string{"version", "--json"}, &first, &stderr); err != nil {
		t.Fatalf("version --json failed: %v stderr=%s", err, stderr.String())
	}
	if err := Run(t.Context(), []string{"version", "--json"}, &second, &stderr); err != nil {
		t.Fatalf("second version --json failed: %v stderr=%s", err, stderr.String())
	}
	if first.String() != second.String() {
		t.Fatalf("version JSON changed between calls:\nfirst=%s\nsecond=%s", first.String(), second.String())
	}
	var got buildinfo.Info
	if err := json.Unmarshal(first.Bytes(), &got); err != nil {
		t.Fatalf("decode version JSON: %v\n%s", err, first.String())
	}
	if want := buildinfo.Current(); got != want {
		t.Fatalf("version identity = %#v, want %#v", got, want)
	}
}

func TestStatusReportsClientBuildIdentity(t *testing.T) {
	cfgPath := writeTestConfig(t, "[Interface]\nFwMark = 0x10000002\nListenPort = 31001\n")
	var stdout, stderr bytes.Buffer
	if err := Run(
		t.Context(),
		[]string{"status", "--config", cfgPath, "--offline"},
		&stdout,
		&stderr,
	); err != nil {
		t.Fatalf("status failed: %v stderr=%s", err, stderr.String())
	}
	var got struct {
		ClientBuild buildinfo.Info `json:"client_build"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode status JSON: %v\n%s", err, stdout.String())
	}
	if want := buildinfo.Current(); got.ClientBuild != want {
		t.Fatalf("status client build identity = %#v, want %#v", got.ClientBuild, want)
	}
}

func TestStatusDistinguishesClientAndDaemonBuilds(t *testing.T) {
	cfgPath := writeTestConfig(t, "[Interface]\nFwMark = 0x10000002\nListenPort = 31001\n")
	runDir := t.TempDir()
	daemonBuild := buildinfo.Info{
		Version:                 "previous",
		SourceCommit:            "1111111111111111111111111111111111111111",
		EmbeddedBPFObjectSHA256: "2222222222222222222222222222222222222222222222222222222222222222",
		BPFABIVersion:           abi.Version,
	}
	statusData, err := json.Marshal(daemon.Status{
		PID:             os.Getpid(),
		ConfigPath:      cfgPath,
		State:           "active",
		Build:           &daemonBuild,
		RequestProtocol: 1,
		InstanceID:      "0123456789abcdef0123456789abcdef",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "status.json"), statusData, 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if err := Run(
		t.Context(),
		[]string{
			"status",
			"--config", cfgPath,
			"--run-dir", runDir,
			"--offline",
		},
		&stdout,
		&stderr,
	); err != nil {
		t.Fatalf("status failed: %v stderr=%s", err, stderr.String())
	}
	var got struct {
		ClientBuild buildinfo.Info `json:"client_build"`
		Daemon      *daemon.Status `json:"daemon"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode status JSON: %v\n%s", err, stdout.String())
	}
	if got.ClientBuild != buildinfo.Current() {
		t.Fatalf("client build = %#v, want %#v", got.ClientBuild, buildinfo.Current())
	}
	if got.Daemon == nil || got.Daemon.Build == nil || *got.Daemon.Build != daemonBuild {
		t.Fatalf("daemon build = %#v, want %#v", got.Daemon, daemonBuild)
	}
}

func TestStatusUsesFreshGuardAndLiveDaemonObservationWhenDesiredStateFails(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(`
version: 1
startup_guard:
  mode: none
underlays:
  - name: eth0
    type: netdev
wireguards:
  - name: wg0
    config: /definitely/missing/wg0.conf
    profile: mix-default
profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
`), 0o600); err != nil {
		t.Fatal(err)
	}
	runDir := t.TempDir()
	now := time.Now().UTC()
	liveDataplane := &dataplane.KernelStatus{
		Mode: "faketcp",
		FakeTCP: &dataplane.FakeTCPRuntimeStatus{
			Generation: 2, OwnerKind: "process-owned", AttachmentBackend: "tcx", Healthy: false,
			Ownership: &dataplane.FakeTCPOwnershipStatus{
				Runtime: dataplane.FakeTCPProcessOwnershipStatus{
					Kind: "process-owned", Generation: 2, Healthy: false,
				},
			},
		},
	}
	current := &reconcile.Observation{
		ObservationTime: now,
		Reconcile: reconcile.ReconcileStatus{
			Phase: reconcile.ReconcilePhaseFailed, Since: now, ObservationTime: now,
			Error: "reload failed",
		},
		StartupGuard: reconcile.StartupGuardStatus{
			Mode: "nft-temporary-drop", KernelState: reconcile.StartupGuardKernelAbsent,
			ObservationTime: now,
			RuntimePause: &dataplane.StartupGuardPauseStatus{
				Phase: "held", Reason: "startup_guard", Since: now, ObservationTime: now,
			},
		},
		Dataplane: liveDataplane,
	}
	statusData, err := json.Marshal(daemon.Status{
		PID: os.Getpid(), ConfigPath: cfgPath, State: "degraded",
		RequestProtocol: 1, InstanceID: "0123456789abcdef0123456789abcdef",
		Current: current,
		LastResult: &reconcile.Result{Dataplane: &dataplane.KernelStatus{
			Mode: "faketcp", FakeTCP: &dataplane.FakeTCPRuntimeStatus{Generation: 1},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "status.json"), statusData, 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if err := Run(t.Context(), []string{
		"status", "--config", cfgPath, "--run-dir", runDir,
	}, &stdout, &stderr); err != nil {
		t.Fatalf("status failed: %v stderr=%s", err, stderr.String())
	}
	var got struct {
		DesiredError string                        `json:"desired_error"`
		StartupGuard *reconcile.StartupGuardStatus `json:"startup_guard"`
		Reconcile    *reconcile.ReconcileStatus    `json:"reconcile"`
		Dataplane    *dataplane.KernelStatus       `json:"dataplane"`
		Note         string                        `json:"dataplane_note"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode status: %v\n%s", err, stdout.String())
	}
	if got.DesiredError == "" {
		t.Fatalf("desired-state failure disappeared: %s", stdout.String())
	}
	if got.StartupGuard == nil || got.StartupGuard.Mode != "none" ||
		got.StartupGuard.KernelState != reconcile.StartupGuardKernelDisabled ||
		got.StartupGuard.RuntimePause == nil || got.StartupGuard.RuntimePause.Phase != "held" {
		t.Fatalf("merged startup guard = %#v", got.StartupGuard)
	}
	if got.Reconcile == nil || got.Reconcile.Phase != reconcile.ReconcilePhaseFailed ||
		got.Dataplane == nil || got.Dataplane.FakeTCP == nil || got.Dataplane.FakeTCP.Generation != 2 ||
		!strings.Contains(got.Note, "live resident") {
		t.Fatalf("live daemon projection = reconcile=%#v dataplane=%#v note=%q", got.Reconcile, got.Dataplane, got.Note)
	}

	current.Dataplane = nil
	current.DataplaneError = "resident runtime snapshot unavailable"
	statusData, err = json.Marshal(daemon.Status{
		PID: os.Getpid(), ConfigPath: cfgPath, State: "degraded",
		RequestProtocol: 1, InstanceID: "0123456789abcdef0123456789abcdef",
		Current: current,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "status.json"), statusData, 0o644); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if err := Run(t.Context(), []string{
		"status", "--config", cfgPath, "--run-dir", runDir,
	}, &stdout, &stderr); err != nil {
		t.Fatalf("status with resident observation error failed: %v stderr=%s", err, stderr.String())
	}
	var failed struct {
		Error string `json:"dataplane_error"`
		Note  string `json:"dataplane_note"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &failed); err != nil {
		t.Fatalf("decode status with resident error: %v\n%s", err, stdout.String())
	}
	if failed.Error != current.DataplaneError || !strings.Contains(failed.Note, "observation failed") {
		t.Fatalf("resident dataplane error was lost: error=%q note=%q", failed.Error, failed.Note)
	}
}

func TestValidateOffline(t *testing.T) {
	dir := t.TempDir()
	wgPath := filepath.Join(dir, "wg0.conf")
	if err := os.WriteFile(wgPath, []byte("[Interface]\nFwMark = 0x10000002\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(`
version: 1
underlays:
  - name: eth0
    type: netdev
wireguards:
  - name: wg0
    config: `+wgPath+`
    profile: mix-default
profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := Run(t.Context(), []string{"validate", "--config", cfgPath, "--offline"}, &stdout, &stderr); err != nil {
		t.Fatalf("Run returned error: %v stderr=%s", err, stderr.String())
	}
	if stdout.String() != "ok\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestFeatures(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := Run(t.Context(), []string{"features"}, &stdout, &stderr); err != nil {
		t.Fatalf("Run returned error: %v stderr=%s", err, stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte(`"goos"`)) {
		t.Fatalf("unexpected features output: %s", stdout.String())
	}
}

func TestGuardPlanOffline(t *testing.T) {
	cfgPath := writeTestConfig(t, "[Interface]\nFwMark = 0x10000002\nListenPort = 31001\n")
	var stdout, stderr bytes.Buffer
	if err := Run(t.Context(), []string{"guard-plan", "--config", cfgPath, "--offline"}, &stdout, &stderr); err != nil {
		t.Fatalf("Run returned error: %v stderr=%s", err, stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("meta mark 0x10000002")) {
		t.Fatalf("guard plan missing mark rule: %s", stdout.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("udp dport 31001")) {
		t.Fatalf("guard plan missing listen port rule: %s", stdout.String())
	}
}

func TestGuardApplyDryRunOffline(t *testing.T) {
	cfgPath := writeTestConfig(t, "[Interface]\nFwMark = 0x10000002\nListenPort = 31001\n")
	var stdout, stderr bytes.Buffer
	if err := Run(t.Context(), []string{"guard-apply", "--config", cfgPath, "--offline", "--dry-run"}, &stdout, &stderr); err != nil {
		t.Fatalf("Run returned error: %v stderr=%s", err, stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("meta mark 0x10000002")) {
		t.Fatalf("guard apply dry-run missing mark rule: %s", stdout.String())
	}
}

func TestDumpABIOffline(t *testing.T) {
	cfgPath := writeTestConfig(t, "[Interface]\nFwMark = 0x10000002\nListenPort = 31001\n")
	var stdout, stderr bytes.Buffer
	if err := Run(t.Context(), []string{"dump-abi", "--config", cfgPath, "--offline"}, &stdout, &stderr); err != nil {
		t.Fatalf("Run returned error: %v stderr=%s", err, stderr.String())
	}
	want := []byte(`"ABIVersion": ` + strconv.FormatUint(uint64(abi.Version), 10))
	if !bytes.Contains(stdout.Bytes(), want) {
		t.Fatalf("dump-abi missing ABI version: %s", stdout.String())
	}
}

func TestGuardCleanupDryRun(t *testing.T) {
	cfgPath := writeTestConfig(t, "[Interface]\nFwMark = 0x10000002\n")
	var stdout, stderr bytes.Buffer
	if err := Run(t.Context(), []string{"guard-cleanup", "--config", cfgPath, "--offline", "--dry-run"}, &stdout, &stderr); err != nil {
		t.Fatalf("Run returned error: %v stderr=%s", err, stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("delete table inet handle <validated-handle>")) ||
		bytes.Contains(stdout.Bytes(), []byte("delete table inet wg_mix_ebpf_guard")) {
		t.Fatalf("guard cleanup dry-run must require validated ownership: %s", stdout.String())
	}
}

func TestStopFallbackDetachDryRunOffline(t *testing.T) {
	cfgPath := writeTestConfig(t, "[Interface]\nFwMark = 0x10000002\n")
	dir := t.TempDir()
	dir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	fakeBin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fakeBin, "nft"), []byte(
		"#!/bin/sh\n"+
			"if [ \"$*\" = '-j list tables' ]; then\n"+
			"  printf '%s\\n' '{\"nftables\":[{\"metainfo\":{\"json_schema_version\":1}}]}'\n"+
			"  exit 0\n"+
			"fi\n"+
			"printf '%s\\n' 'Error: No such file or directory' 'list table inet wg_mix_ebpf_guard' >&2\n"+
			"exit 1\n",
	), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	runDir := filepath.Join(dir, "run")
	stateDir := filepath.Join(dir, "state")
	ctx := lockfile.WithLifecyclePathsForTest(
		t.Context(),
		filepath.Join(dir, "daemon.lease"),
		filepath.Join(dir, "maintenance.gate"),
	)
	ctx = guard.WithNftBinaryForTest(ctx, filepath.Join(fakeBin, "nft"))
	var stdout, stderr bytes.Buffer
	if err := Run(ctx, []string{"stop", "--config", cfgPath, "--run-dir", runDir, "--state-dir", stateDir}, &stdout, &stderr); err != nil {
		t.Fatalf("stop fallback should tolerate missing runtime when there is no attach-state to detach: %v stderr=%s", err, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if err := Run(t.Context(), []string{"detach", "--config", cfgPath, "--offline", "--dry-run", "--run-dir", runDir, "--state-dir", stateDir}, &stdout, &stderr); err != nil {
		t.Fatalf("detach dry-run offline failed: %v stderr=%s", err, stderr.String())
	}
}

func TestWrongRunDirOneShotStopCannotRaceDaemon(t *testing.T) {
	dir := t.TempDir()
	leasePath := filepath.Join(dir, "daemon.lease")
	maintenancePath := filepath.Join(dir, "maintenance.gate")
	ctx := lockfile.WithLifecyclePathsForTest(
		t.Context(),
		leasePath,
		maintenancePath,
	)
	lease, err := lockfile.AcquireLifecycle(ctx, lockfile.LifecycleOwner{
		PID:        os.Getpid(),
		Action:     "daemon",
		ConfigPath: "/etc/wg-mix-ebpf/config.yaml",
		RunDir:     "/run/real-daemon",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()

	var stdout, stderr bytes.Buffer
	err = Run(ctx, []string{
		"stop",
		"--config", filepath.Join(dir, "wrong.yaml"),
		"--run-dir", filepath.Join(dir, "wrong-run-dir"),
		"--state-dir", filepath.Join(dir, "wrong-state-dir"),
	}, &stdout, &stderr)
	if !errors.Is(err, lockfile.ErrLifecycleLeaseHeld) {
		t.Fatalf("wrong-run-dir stop error = %v, want held lifecycle lease", err)
	}
	if !strings.Contains(err.Error(), "/run/real-daemon") {
		t.Fatalf("wrong-run-dir stop error lacks real owner: %v", err)
	}
}

func TestStopExitRaceFallsBackThroughGlobalLifecycleLease(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(dir, "run")
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.yaml")
	status := daemon.Status{
		PID:             os.Getpid(),
		ConfigPath:      configPath,
		State:           "active",
		RequestProtocol: 1,
		InstanceID:      "0123456789abcdef0123456789abcdef",
	}
	writeStatus := func(status daemon.Status) error {
		data, err := json.Marshal(status)
		if err != nil {
			return err
		}
		tmp := filepath.Join(runDir, "status.json.next")
		if err := os.WriteFile(tmp, data, 0o644); err != nil {
			return err
		}
		return os.Rename(tmp, filepath.Join(runDir, "status.json"))
	}
	if err := writeStatus(status); err != nil {
		t.Fatal(err)
	}

	leasePath := filepath.Join(dir, "daemon.lease")
	maintenancePath := filepath.Join(dir, "maintenance.gate")
	ctx := lockfile.WithLifecyclePathsForTest(
		t.Context(),
		leasePath,
		maintenancePath,
	)
	lease, err := lockfile.AcquireLifecycle(ctx, lockfile.LifecycleOwner{
		PID:        os.Getpid(),
		Action:     "daemon-cleanup",
		ConfigPath: configPath,
		RunDir:     runDir,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()

	statusUpdated := make(chan error, 1)
	go func() {
		deadline := time.Now().Add(time.Second)
		requestDir := filepath.Join(runDir, "requests")
		for time.Now().Before(deadline) {
			entries, err := os.ReadDir(requestDir)
			if err == nil {
				for _, entry := range entries {
					if strings.HasSuffix(entry.Name(), ".json") {
						status.PID = 1 << 30
						statusUpdated <- writeStatus(status)
						return
					}
				}
			}
			time.Sleep(5 * time.Millisecond)
		}
		statusUpdated <- errors.New("stop request was not enqueued")
	}()

	var stdout, stderr bytes.Buffer
	err = Run(ctx, []string{
		"stop",
		"--config", configPath,
		"--run-dir", runDir,
		"--state-dir", filepath.Join(dir, "state"),
		"--timeout", "1s",
	}, &stdout, &stderr)
	if updateErr := <-statusUpdated; updateErr != nil {
		t.Fatal(updateErr)
	}
	if !errors.Is(err, lockfile.ErrLifecycleLeaseHeld) {
		t.Fatalf("exit-race fallback error = %v, want global lifecycle ownership rejection", err)
	}
	if errors.Is(err, daemon.ErrDaemonNotRunning) {
		t.Fatalf("CLI returned request race instead of using safe one-shot fallback: %v", err)
	}
}

func writeTestConfig(t *testing.T, wgConfig string) string {
	t.Helper()
	dir := t.TempDir()
	wgPath := filepath.Join(dir, "wg0.conf")
	if err := os.WriteFile(wgPath, []byte(wgConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(`
version: 1
underlays:
  - name: eth0
    type: netdev
wireguards:
  - name: wg0
    config: `+wgPath+`
    profile: mix-default
profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
`), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}

func TestProfileAddTokenCheckAndRemoveForce(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	wgPath := filepath.Join(dir, "wg0.conf")
	if err := os.WriteFile(wgPath, []byte("[Interface]\nFwMark = 0x10000002\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte(`
version: 1
underlays:
  - name: eth0
    type: netdev
wireguards:
  - name: wg0
    config: `+wgPath+`
    profile: home
profiles:
  home:
    preset: wireguard-mix-wire-values-v1
`), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if err := Run(t.Context(), []string{"profile", "token", "home", "--config", cfgPath}, &stdout, &stderr); err != nil {
		t.Fatalf("token failed: %v", err)
	}
	token := strings.TrimSpace(stdout.String())
	stdout.Reset()
	if err := Run(t.Context(), []string{"profile", "check", token}, &stdout, &stderr); err != nil {
		t.Fatalf("check failed: %v", err)
	}
	stdout.Reset()
	if err := Run(t.Context(), []string{"profile", "add", "imported", "--config", cfgPath, "--token", token}, &stdout, &stderr); err != nil {
		t.Fatalf("add token failed: %v", err)
	}
	stdout.Reset()
	if err := Run(t.Context(), []string{"profile", "remove", "home", "--config", cfgPath}, &stdout, &stderr); err == nil {
		t.Fatal("expected referenced profile remove to require --force")
	}
	if err := Run(t.Context(), []string{"profile", "remove", "home", "--config", cfgPath, "--force"}, &stdout, &stderr); err != nil {
		t.Fatalf("remove force failed: %v", err)
	}
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("name: wg0")) {
		t.Fatalf("force remove should stop managing referenced wg: %s", data)
	}
}

func TestInitNonInteractiveCreatesConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	wgPath := filepath.Join(dir, "wg0.conf")
	if err := os.WriteFile(wgPath, []byte("[Interface]\nFwMark = 0x10000002\nListenPort = 31001\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	args := []string{"init", "--config", cfgPath, "--wg", "wg0", "--wg-config", wgPath, "--underlay", "eth0:netdev", "--profile", "home", "--profile-preset", "wireguard-mix-wire-values-v1"}
	if err := Run(t.Context(), args, &stdout, &stderr); err != nil {
		t.Fatalf("init failed: %v stderr=%s", err, stderr.String())
	}
	if err := Run(t.Context(), []string{"validate", "--config", cfgPath, "--offline"}, &stdout, &stderr); err != nil {
		t.Fatalf("validate initialized config failed: %v", err)
	}
}

func TestInstallDryRunUsesOverrides(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WG_MIX_EBPF_ETC_DIR", filepath.Join(dir, "wg-mix-ebpf"))
	t.Setenv("WG_MIX_EBPF_BINARY_PATH", filepath.Join(dir, "sbin", "wg-mix-ebpf"))
	t.Setenv("WG_MIX_EBPF_VAR_LIB_DIR", filepath.Join(dir, "wg-mix-ebpf-state-test"))
	t.Setenv("WG_MIX_EBPF_RUN_DIR", filepath.Join(dir, "wg-mix-ebpf-run-test"))
	t.Setenv("WG_MIX_EBPF_PIN_PATH", filepath.Join(dir, "wg-mix-ebpf-pins-test"))
	t.Setenv("WG_MIX_EBPF_SYSTEMD_DIR", filepath.Join(dir, "systemd"))
	var stdout, stderr bytes.Buffer
	if err := Run(t.Context(), []string{"install", "--system", "systemd", "--dry-run", "--enable"}, &stdout, &stderr); err != nil {
		t.Fatalf("install dry-run failed: %v", err)
	}
	if !bytes.Contains(stdout.Bytes(), []byte("enable systemd service")) {
		t.Fatalf("install dry-run missing enable action: %s", stdout.String())
	}
}

func TestInstallDryRunRequiresAdoptExistingFlag(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "wg-mix-ebpf-config-cli-adopt")
	configPath := filepath.Join(configDir, "config.yaml")
	binaryPath := filepath.Join(root, "sbin", "wg-mix-ebpf")
	stateDir := filepath.Join(root, "wg-mix-ebpf-state-cli-adopt")
	runDir := filepath.Join(root, "wg-mix-ebpf-run-cli-adopt")
	pinPath := filepath.Join(root, "wg-mix-ebpf-pins-cli-adopt")
	for _, dir := range []string{configDir, stateDir, runDir, pinPath} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := config.SaveFile(configPath, config.SafeTemplate()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "lock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(install.EnvEtcDir, configDir)
	t.Setenv(install.EnvBinaryPath, binaryPath)
	t.Setenv(install.EnvVarLibDir, stateDir)
	t.Setenv(daemon.EnvRunDir, runDir)
	t.Setenv(dataplane.EnvPinPath, pinPath)

	var stdout, stderr bytes.Buffer
	err := Run(
		t.Context(),
		[]string{"install", "--system", "unknown", "--dry-run"},
		&stdout,
		&stderr,
	)
	if err == nil || !strings.Contains(err.Error(), "--adopt-existing") {
		t.Fatalf("install dry-run error = %v, want explicit-adoption rejection", err)
	}
	stdout.Reset()
	err = Run(
		t.Context(),
		[]string{"install", "--system", "unknown", "--dry-run", "--adopt-existing"},
		&stdout,
		&stderr,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "adopt strictly validated existing resources") {
		t.Fatalf("install dry-run omitted adoption action: %s", stdout.String())
	}
	for _, path := range []string{
		filepath.Join(configDir, ".wg-mix-ebpf-cleanup.json"),
		binaryPath,
	} {
		if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("install dry-run wrote %s: %v", path, statErr)
		}
	}
}

func TestRunOnceDryOfflineWritesStatus(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeTestConfig(t, "[Interface]\nFwMark = 0x10000002\nListenPort = 31001\n")
	runDir := filepath.Join(dir, "run")
	var stdout, stderr bytes.Buffer
	if err := Run(t.Context(), []string{"run", "--config", cfgPath, "--run-dir", runDir, "--offline", "--dry-run", "--once"}, &stdout, &stderr); err != nil {
		t.Fatalf("run once failed: %v stderr=%s", err, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(runDir, "status.json")); err != nil {
		t.Fatalf("status not written: %v", err)
	}
	status, err := daemon.ReadStatus(runDir)
	if err != nil {
		t.Fatalf("read daemon status: %v", err)
	}
	if status.Build == nil || *status.Build != buildinfo.Current() {
		t.Fatalf("daemon build identity = %#v, want %#v", status.Build, buildinfo.Current())
	}
}

func TestRunOfflineWithoutDryRunIsRejected(t *testing.T) {
	cfgPath := writeTestConfig(t, "[Interface]\nFwMark = 0x10000002\n")
	var stdout, stderr bytes.Buffer
	err := Run(t.Context(), []string{"run", "--config", cfgPath, "--offline", "--once"}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "requires --dry-run") {
		t.Fatalf("expected offline daemon rejection, got %v", err)
	}
}

func TestRunRejectsNegativeShutdownTimeout(t *testing.T) {
	cfgPath := writeTestConfig(t, "[Interface]\nFwMark = 0x10000002\n")
	var stdout, stderr bytes.Buffer
	err := Run(t.Context(), []string{
		"run",
		"--config", cfgPath,
		"--run-dir", t.TempDir(),
		"--offline",
		"--dry-run",
		"--once",
		"--shutdown-timeout=-1s",
	}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "shutdown timeout must not be negative") {
		t.Fatalf("expected shutdown timeout rejection, got %v", err)
	}
}

func TestReloadOfflineWithoutDryRunIsRejected(t *testing.T) {
	cfgPath := writeTestConfig(t, "[Interface]\nFwMark = 0x10000002\n")
	var stdout, stderr bytes.Buffer
	err := Run(t.Context(), []string{"reload", "--config", cfgPath, "--offline"}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "requires --dry-run") {
		t.Fatalf("expected offline reload rejection, got %v", err)
	}
}

func TestAdoptLegacyPinsIsReloadOnly(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Run(
		t.Context(),
		[]string{"status", "--adopt-legacy-pins"},
		&stdout,
		&stderr,
	)
	if err == nil || !strings.Contains(err.Error(), "only valid with reload") {
		t.Fatalf("status legacy-adoption error = %v", err)
	}
}

func TestAdoptLegacyPinsRejectsRunningDaemon(t *testing.T) {
	runDir := t.TempDir()
	status := daemon.Status{
		PID:             os.Getpid(),
		ConfigPath:      "/etc/wg-mix-ebpf/config.yaml",
		State:           "active",
		RequestProtocol: 1,
		InstanceID:      "0123456789abcdef0123456789abcdef",
	}
	data, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(runDir, "status.json"),
		data,
		0o644,
	); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	err = Run(
		t.Context(),
		[]string{
			"reload",
			"--adopt-legacy-pins",
			"--run-dir", runDir,
		},
		&stdout,
		&stderr,
	)
	if err == nil ||
		!strings.Contains(err.Error(), "while the daemon is stopped") {
		t.Fatalf("running-daemon legacy-adoption error = %v", err)
	}
}

func TestInitPreservesExistingTransportCipherAndParser(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	wgPath := filepath.Join(dir, "wg0.conf")
	if err := os.WriteFile(wgPath, []byte("[Interface]\nFwMark = 0x10000002\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte(`
version: 1
underlays:
  - name: eth0
    type: netdev
    parser: l3
wireguards:
  - name: wg0
    config: `+wgPath+`
    profile: home
    cipher: xor-home
    transport:
      mode: udp
profiles:
  home:
    preset: wireguard-mix-wire-values-v1
ciphers:
  xor-home:
    mode: xor
    key_derivation: udp2raw-md5-key1
    password: test-password
`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	args := []string{"init", "--config", cfgPath, "--wg", "wg0", "--wg-config", wgPath, "--underlay", "eth0:netdev", "--profile", "home"}
	if err := Run(t.Context(), args, &stdout, &stderr); err != nil {
		t.Fatalf("init failed: %v stderr=%s", err, stderr.String())
	}
	cfg, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Underlays[0].Parser; got != "l3" {
		t.Fatalf("underlay parser was overwritten: %q", got)
	}
	if got := cfg.WireGuards[0].Cipher; got != "xor-home" {
		t.Fatalf("cipher was overwritten: %q", got)
	}
	if got := cfg.WireGuards[0].Transport.Mode; got != "udp" {
		t.Fatalf("transport was overwritten: %q", got)
	}
}

func TestDumpABIRedactsCipherKey(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(`
version: 1
underlays: []
wireguards: []
profiles: {}
ciphers:
  xor:
    mode: xor
    key_derivation: udp2raw-md5-key1
    password: highly-sensitive
`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := Run(t.Context(), []string{"dump-abi", "--config", cfgPath, "--offline"}, &stdout, &stderr); err != nil {
		t.Fatalf("dump-abi failed: %v", err)
	}
	if strings.Contains(stdout.String(), `"Key":`) || !strings.Contains(stdout.String(), `"KeyRedacted": true`) {
		t.Fatalf("dump-abi did not redact cipher key: %s", stdout.String())
	}
}

func TestInitRefusesToOverwriteExistingProfile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	wgPath := filepath.Join(dir, "wg0.conf")
	if err := os.WriteFile(wgPath, []byte("[Interface]\nFwMark = 0x10000002\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte(`
version: 1
underlays: []
wireguards: []
profiles:
  home:
    preset: wireguard-mix-wire-values-v1
`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	args := []string{"init", "--config", cfgPath, "--wg", "wg0", "--wg-config", wgPath, "--underlay", "eth0:netdev", "--profile", "home", "--profile-random"}
	if err := Run(t.Context(), args, &stdout, &stderr); err == nil {
		t.Fatal("expected init to refuse overwriting existing profile")
	}
}
