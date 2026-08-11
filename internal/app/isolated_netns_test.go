package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/pinidentity"
)

const isolatedFixtureOwnerToken = "0123456789abcdef0123456789abcdef"

const (
	isolatedPrivilegedMountTestGate   = "WG_MIX_EBPF_RUN_PRIVILEGED_MOUNT_TESTS"
	isolatedPrivilegedMountTestHelper = "WG_MIX_EBPF_PRIVILEGED_MOUNT_HELPER"
	isolatedPrivilegedMountHelperFD   = "WG_MIX_EBPF_PRIVILEGED_MOUNT_HELPER_FD"
	isolatedPrivilegedLaunchFormat    = "wg-mix-ebpf-privileged-mount-launch-v1"
	isolatedPrivilegedAuditFormat     = "wg-mix-ebpf-privileged-command-audit-v1"
	isolatedReviewedUnsharePath       = "/usr/bin/unshare"
	isolatedReviewedMountPath         = "/usr/bin/mount"
	isolatedReviewedUmountPath        = "/usr/bin/umount"
	isolatedPrivilegedLaunchFD        = 3
	isolatedPrivilegedExecutableFD    = 4
	isolatedPrivilegedTestPrefix      = "/tmp/wg-mix-ebpf-privileged-mount-tests"
	isolatedPrivilegedOwnerMarker     = ".wg-mix-ebpf-owner"
	isolatedPrivilegedOwnerFormat     = "wg-mix-ebpf-privileged-test-owner-v1"
	isolatedPrivilegedWriteFormat     = "wg-mix-ebpf-privileged-write-v1"
	isolatedPrivilegedCleanupFormat   = "wg-mix-ebpf-privileged-cleanup-v1"
)

type isolatedMountNamespaceIdentity struct {
	device uint64
	inode  uint64
}

type isolatedPrivilegedLaunchRecord struct {
	Format          string `json:"format"`
	OuterPID        int    `json:"outer_pid"`
	OuterMountDev   uint64 `json:"outer_mount_dev"`
	OuterMountInode uint64 `json:"outer_mount_inode"`
	ExecutableDev   uint64 `json:"executable_dev"`
	ExecutableInode uint64 `json:"executable_inode"`
}

type isolatedReviewedToolMetadata struct {
	mode  os.FileMode
	uid   uint32
	nlink uint64
}

type isolatedPrivilegedCommandAudit struct {
	Format     string   `json:"format"`
	StartedAt  string   `json:"started_at"`
	FinishedAt string   `json:"finished_at"`
	Tool       string   `json:"tool"`
	Argv       []string `json:"argv"`
	Target     string   `json:"target"`
	ExitCode   int      `json:"exit_code"`
}

type isolatedReviewedCommandSpec struct {
	tool       string
	args       []string
	target     string
	env        []string
	extraFiles []*os.File
	timeout    time.Duration
}

type isolatedReviewedMountTargetSnapshot struct {
	target string
	device uint64
	inode  uint64
	chain  []mountInfoEntry
}

type isolatedReviewedMountedTarget struct {
	target         string
	before         isolatedReviewedMountTargetSnapshot
	mounted        mountInfoEntry
	operations     isolatedReviewedMountLifecycleOperations
	unmountIssued  bool
	cleanupBlocked bool
	active         bool
}

type isolatedReviewedMountLifecycleOperations struct {
	snapshotTarget     func() (isolatedReviewedMountTargetSnapshot, error)
	readMountInfo      func() ([]mountInfoEntry, error)
	readTargetIdentity func() (isolatedMountNamespaceIdentity, error)
	runMount           func() error
	runUnmount         func() error
}

type isolatedReviewedMountLifecycleFixture struct {
	target          string
	before          isolatedReviewedMountTargetSnapshot
	restoredEntries []mountInfoEntry
	mountedEntries  []mountInfoEntry
	stateEntries    []mountInfoEntry
	beforeIdentity  isolatedMountNamespaceIdentity
	mountedIdentity isolatedMountNamespaceIdentity
	mountCommits    bool
	unmountCommits  bool
	mountErr        error
	unmountErr      error
	readErrors      []error
	snapshotErrors  []error
	mountCalls      int
	unmountCalls    int
	readCalls       int
	snapshotCalls   int
	identityCalls   int
	currentIdentity isolatedMountNamespaceIdentity
}

type isolatedReviewedOwnedPath struct {
	path   string
	device uint64
	inode  uint64
	uid    uint32
	mode   os.FileMode
}

type isolatedReviewedPrivilegedResources struct {
	root          string
	runID         string
	markerContent string
	owned         []isolatedReviewedOwnedPath
	cleaned       bool
}

type isolatedReviewedCleanupAudit struct {
	Format    string   `json:"format"`
	Timestamp string   `json:"timestamp"`
	Host      string   `json:"host"`
	Argv      []string `json:"argv"`
	Target    string   `json:"target"`
	Device    uint64   `json:"device"`
	Inode     uint64   `json:"inode"`
	ExitCode  int      `json:"exit_code"`
}

type isolatedReviewedFilesystemWriteAudit struct {
	Format    string `json:"format"`
	Timestamp string `json:"timestamp"`
	Operation string `json:"operation"`
	Target    string `json:"target"`
	ExitCode  int    `json:"exit_code"`
}

func TestIsolatedNetNSTestPaths(t *testing.T) {
	base := filepath.Join(isolatedNetNSTestRoot, "0123456789abcdef")
	layout, err := isolatedNetNSTestPaths(
		"reload",
		filepath.Join(base, "secrets", "agent-a.yaml"),
		filepath.Join(base, "run-a"),
		filepath.Join(base, "state-a"),
		filepath.Join(base, "bpffs", "wg-mix-ebpf-a"),
	)
	if err != nil {
		t.Fatalf("isolatedNetNSTestPaths() error = %v", err)
	}
	if layout.runBase != base {
		t.Fatalf("run base = %q, want %q", layout.runBase, base)
	}
	if layout.runID != "0123456789abcdef" || layout.role != "a" {
		t.Fatalf("layout identity = run_id %q role %q", layout.runID, layout.role)
	}
	if layout.lease != filepath.Join(base, isolatedNetNSLifecycleLeaseName) {
		t.Fatalf("lease = %q", layout.lease)
	}
	if layout.gate != isolatedNetNSLifecycleGatePath {
		t.Fatalf("maintenance gate = %q, want %q", layout.gate, isolatedNetNSLifecycleGatePath)
	}
	if filepath.Dir(layout.gate) != isolatedNetNSTestRoot {
		t.Fatalf("maintenance gate is outside fixed test root: %q", layout.gate)
	}
	if layout.ledger != filepath.Join(base, isolatedNetNSBPFFSLedgerName) {
		t.Fatalf("bpffs creation ledger = %q", layout.ledger)
	}
}

func TestIsolatedNetNSTestPathsAcceptsReadOnlyStatus(t *testing.T) {
	base := filepath.Join(isolatedNetNSTestRoot, "0123456789abcdef")
	if _, err := isolatedNetNSTestPaths(
		"status",
		filepath.Join(base, "secrets", "agent-a.yaml"),
		filepath.Join(base, "run-a"),
		filepath.Join(base, "state-a"),
		filepath.Join(base, "bpffs", "wg-mix-ebpf-a"),
	); err != nil {
		t.Fatalf("isolated status paths: %v", err)
	}
}

func TestIsolatedNetNSTestRolesShareLifecycleLease(t *testing.T) {
	base := filepath.Join(isolatedNetNSTestRoot, "0123456789abcdef")
	layouts := make([]isolatedNetNSTestLayout, 0, 2)
	for _, role := range []string{"client", "server"} {
		layout, err := isolatedNetNSTestPaths(
			"reload",
			filepath.Join(base, "secrets", "agent-"+role+".yaml"),
			filepath.Join(base, "run-"+role),
			filepath.Join(base, "state-"+role),
			filepath.Join(base, "bpffs", "wg-mix-ebpf-"+role),
		)
		if err != nil {
			t.Fatalf("role %s paths: %v", role, err)
		}
		layouts = append(layouts, layout)
	}
	if layouts[0].lease != layouts[1].lease {
		t.Fatalf("role leases differ: a=%q b=%q", layouts[0].lease, layouts[1].lease)
	}
	if layouts[0].gate != layouts[1].gate ||
		layouts[0].gate != isolatedNetNSLifecycleGatePath {
		t.Fatalf("role maintenance gates differ: %#v", layouts)
	}
	if strings.Contains(layouts[0].lease, "run-client") ||
		strings.Contains(layouts[1].lease, "run-server") {
		t.Fatalf("role-specific lease permits serialization bypass: %#v", layouts)
	}
}

func TestIsolatedNetNSTestRunsShareFixedRootMaintenanceGate(t *testing.T) {
	var gates []string
	for _, runID := range []string{"0123456789abcdef", "fedcba9876543210"} {
		base := filepath.Join(isolatedNetNSTestRoot, runID)
		layout, err := isolatedNetNSTestPaths(
			"reload",
			filepath.Join(base, "secrets", "agent-a.yaml"),
			filepath.Join(base, "run-a"),
			filepath.Join(base, "state-a"),
			filepath.Join(base, "bpffs", "wg-mix-ebpf-a"),
		)
		if err != nil {
			t.Fatalf("run %s paths: %v", runID, err)
		}
		gates = append(gates, layout.gate)
		if strings.Contains(layout.gate, runID) {
			t.Fatalf("run-specific permanent maintenance gate = %q", layout.gate)
		}
	}
	if gates[0] != gates[1] || gates[0] != isolatedNetNSLifecycleGatePath {
		t.Fatalf("isolated runs do not share the fixed gate: %q", gates)
	}
}

func TestIsolatedNetNSTestPathsRejectsEscapesAndMismatches(t *testing.T) {
	base := filepath.Join(isolatedNetNSTestRoot, "01234567")
	validConfig := filepath.Join(base, "secrets", "agent-a.yaml")
	validRun := filepath.Join(base, "run-a")
	validState := filepath.Join(base, "state-a")
	validPin := filepath.Join(base, "bpffs", "wg-mix-ebpf-a")

	tests := []struct {
		name   string
		cmd    string
		config string
		run    string
		state  string
		pin    string
	}{
		{name: "unsupported read-only command", cmd: "validate", config: validConfig, run: validRun, state: validState, pin: validPin},
		{name: "short run id", cmd: "reload", config: validConfig, run: filepath.Join(isolatedNetNSTestRoot, "1234", "run-a"), state: validState, pin: validPin},
		{name: "invalid role", cmd: "reload", config: filepath.Join(base, "secrets", "agent-BAD.yaml"), run: filepath.Join(base, "run-BAD"), state: filepath.Join(base, "state-BAD"), pin: filepath.Join(base, "bpffs", "wg-mix-ebpf-BAD")},
		{name: "state role mismatch", cmd: "reload", config: validConfig, run: validRun, state: filepath.Join(base, "state-b"), pin: validPin},
		{name: "config role mismatch", cmd: "reload", config: filepath.Join(base, "secrets", "agent-b.yaml"), run: validRun, state: validState, pin: validPin},
		{name: "config outside secrets", cmd: "reload", config: filepath.Join(base, "agent.yaml"), run: validRun, state: validState, pin: validPin},
		{name: "pin role mismatch", cmd: "detach", config: validConfig, run: validRun, state: validState, pin: filepath.Join(base, "bpffs", "wg-mix-ebpf-b")},
		{name: "pin outside bpffs", cmd: "detach", config: validConfig, run: validRun, state: validState, pin: filepath.Join(base, "wg-mix-ebpf-client")},
		{name: "noncanonical run", cmd: "reload", config: validConfig, run: base + "/evidence/../run-a", state: validState, pin: validPin},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := isolatedNetNSTestPaths(
				tt.cmd,
				tt.config,
				tt.run,
				tt.state,
				tt.pin,
			); err == nil {
				t.Fatal("isolatedNetNSTestPaths() unexpectedly succeeded")
			}
		})
	}
}

func TestParseIsolatedNetNSTestManifestAndLayout(t *testing.T) {
	layout, configPath, runDir, stateDir, pinPath := isolatedFixtureLayout(t, "a")
	manifest, err := parseIsolatedNetNSTestManifest(isolatedFixtureManifest(layout))
	if err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	if err := validateIsolatedNetNSTestManifestLayout(
		manifest,
		layout,
		configPath,
		runDir,
		stateDir,
		pinPath,
	); err != nil {
		t.Fatalf("validate manifest layout: %v", err)
	}
	manifest.values["pin_lock_a"] = "/run/wg-mix-ebpf/pin-locks/foreign.lock"
	if err := validateIsolatedNetNSTestManifestLayout(
		manifest,
		layout,
		configPath,
		runDir,
		stateDir,
		pinPath,
	); err == nil {
		t.Fatal("production pin lock path unexpectedly accepted")
	}

	for name, mutate := range map[string]func(isolatedNetNSTestManifest){
		"resource key mismatch": func(value isolatedNetNSTestManifest) {
			value.values["pin_resource_key_a"] = strings.Repeat("0", 64)
		},
		"production owner path": func(value isolatedNetNSTestManifest) {
			value.values["pin_owner_a"] = "/var/lib/wg-mix-ebpf/pin-owners/foreign.owner.json"
		},
		"duplicate endpoint role": func(value isolatedNetNSTestManifest) {
			value.values["role_b"] = value.values["role_a"]
		},
		"namespace without run id": func(value isolatedNetNSTestManifest) {
			value.values["netns_a"] = "foreign-a"
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate, err := parseIsolatedNetNSTestManifest(isolatedFixtureManifest(layout))
			if err != nil {
				t.Fatal(err)
			}
			mutate(candidate)
			if err := validateIsolatedNetNSTestManifestLayout(
				candidate,
				layout,
				configPath,
				runDir,
				stateDir,
				pinPath,
			); err == nil {
				t.Fatal("mutated manifest layout unexpectedly accepted")
			}
		})
	}
}

func TestValidateIsolatedNetNSTestManifestLayoutSupportsNamedRoles(t *testing.T) {
	for _, role := range []string{"client", "server"} {
		layout, configPath, runDir, stateDir, pinPath := isolatedFixtureLayout(t, role)
		manifest, err := parseIsolatedNetNSTestManifest(
			isolatedFixtureManifestForRoles(layout, "client", "server"),
		)
		if err != nil {
			t.Fatalf("parse %s manifest: %v", role, err)
		}
		if err := validateIsolatedNetNSTestManifestLayout(
			manifest,
			layout,
			configPath,
			runDir,
			stateDir,
			pinPath,
		); err != nil {
			t.Fatalf("validate %s manifest layout: %v", role, err)
		}
	}
}

func TestParseIsolatedNetNSTestManifestRejectsMalformedDocuments(t *testing.T) {
	layout, _, _, _, _ := isolatedFixtureLayout(t, "a")
	valid := string(isolatedFixtureManifest(layout))
	tests := []struct {
		name string
		edit func(string) string
	}{
		{
			name: "duplicate key",
			edit: func(value string) string {
				return value + "run_id=" + layout.runID + "\n"
			},
		},
		{
			name: "unknown key",
			edit: func(value string) string {
				return value + "unexpected=value\n"
			},
		},
		{
			name: "missing key",
			edit: func(value string) string {
				return strings.Replace(value, "host=test-host\n", "", 1)
			},
		},
		{
			name: "missing newline",
			edit: func(value string) string {
				return strings.TrimSuffix(value, "\n")
			},
		},
		{
			name: "carriage return",
			edit: func(value string) string {
				return strings.Replace(value, "host=test-host\n", "host=test-host\r\n", 1)
			},
		},
		{
			name: "noncanonical mount id",
			edit: func(value string) string {
				return strings.Replace(value, "bpffs_mount_id=42\n", "bpffs_mount_id=042\n", 1)
			},
		},
		{
			name: "bad owner token",
			edit: func(value string) string {
				return strings.Replace(
					value,
					"owner_token=0123456789abcdef0123456789abcdef\n",
					"owner_token=uppercaseBAD\n",
					1,
				)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseIsolatedNetNSTestManifest([]byte(tt.edit(valid))); err == nil {
				t.Fatal("parse manifest unexpectedly succeeded")
			}
		})
	}
}

func TestValidateIsolatedNetNSTestOwner(t *testing.T) {
	layout, _, _, _, _ := isolatedFixtureLayout(t, "a")
	manifest, err := parseIsolatedNetNSTestManifest(isolatedFixtureManifest(layout))
	if err != nil {
		t.Fatal(err)
	}
	valid := []byte(
		"format=" + isolatedNetNSOwnerFormat + "\n" +
			"run_id=" + layout.runID + "\n" +
			"owner_token=0123456789abcdef0123456789abcdef\n" +
			"boot_id=01234567-89ab-cdef-0123-456789abcdef\n" +
			"role=run-a\n",
	)
	if err := validateIsolatedNetNSTestOwner(valid, manifest, "run-a"); err != nil {
		t.Fatalf("validate owner: %v", err)
	}
	duplicate := append(append([]byte(nil), valid...), []byte("role=run-a\n")...)
	if err := validateIsolatedNetNSTestOwner(duplicate, manifest, "run-a"); err == nil {
		t.Fatal("duplicate owner key unexpectedly accepted")
	}
	wrongRole := strings.Replace(string(valid), "role=run-a\n", "role=run-b\n", 1)
	if err := validateIsolatedNetNSTestOwner([]byte(wrongRole), manifest, "run-a"); err == nil {
		t.Fatal("wrong owner role unexpectedly accepted")
	}
}

func TestValidateManifestNetworkNamespaces(t *testing.T) {
	layout, _, _, _, _ := isolatedFixtureLayout(t, "a")
	manifest, err := parseIsolatedNetNSTestManifest(isolatedFixtureManifest(layout))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateManifestNetworkNamespaces(manifest, "a", 100, 101); err != nil {
		t.Fatalf("validate role a namespace: %v", err)
	}
	if err := validateManifestNetworkNamespaces(manifest, "a", 100, 103); err == nil {
		t.Fatal("role b namespace identity unexpectedly accepted for role a")
	}
	if err := validateManifestNetworkNamespaces(manifest, "unknown", 100, 101); err == nil {
		t.Fatal("unknown role unexpectedly accepted")
	}
	manifest.values["netns_b_ino"] = manifest.values["netns_a_ino"]
	if err := validateManifestNetworkNamespaces(manifest, "a", 100, 101); err == nil {
		t.Fatal("duplicate role namespace identity unexpectedly accepted")
	}
}

func TestValidateBPFFSParentIdentity(t *testing.T) {
	layout, _, _, _, _ := isolatedFixtureLayout(t, "a")
	manifest, err := parseIsolatedNetNSTestManifest(isolatedFixtureManifest(layout))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateBPFFSParentIdentity(manifest, 200, 201); err != nil {
		t.Fatalf("validate bpffs identity: %v", err)
	}
	for _, identity := range []struct {
		device uint64
		inode  uint64
	}{
		{device: 199, inode: 201},
		{device: 200, inode: 202},
	} {
		if err := validateBPFFSParentIdentity(
			manifest,
			identity.device,
			identity.inode,
		); err == nil {
			t.Fatalf("mismatched bpffs identity unexpectedly accepted: %#v", identity)
		}
	}
}

func TestParseAndValidatePrivateBPFFSMountInfo(t *testing.T) {
	layout, _, _, _, _ := isolatedFixtureLayout(t, "a")
	manifest, err := parseIsolatedNetNSTestManifest(isolatedFixtureManifest(layout))
	if err != nil {
		t.Fatal(err)
	}
	validFixture := isolatedMountInfoFixture(layout, "0:42", "/", "bpf", "")
	entries, err := parseMountInfo([]byte(validFixture))
	if err != nil {
		t.Fatalf("parse valid mountinfo: %v", err)
	}
	pinMountID := uint64(42)
	if err := validatePrivateBPFFSMountInfo(entries, layout, manifest, 42, &pinMountID); err != nil {
		t.Fatalf("validate private bpffs: %v", err)
	}
	independentFixture := isolatedMountInfoFixture(
		layout,
		"0:42",
		"/",
		"bpf",
		"43 21 0:77 / /run/wg-mix-ebpf-tests/independent/bpffs rw,nosuid,nodev,noexec,relatime - bpf bpf rw\n",
	)
	independentEntries, err := parseMountInfo([]byte(independentFixture))
	if err != nil {
		t.Fatalf("parse independent mount fixture: %v", err)
	}
	if err := validatePrivateBPFFSMountInfo(
		independentEntries,
		layout,
		manifest,
		42,
		&pinMountID,
	); err != nil {
		t.Fatalf("independent bpf mount unexpectedly rejected: %v", err)
	}

	tests := []struct {
		name         string
		fixture      string
		statxMountID uint64
		pinMountID   uint64
		mutate       func(isolatedNetNSTestManifest) isolatedNetNSTestManifest
	}{
		{
			name:         "statx mismatch",
			fixture:      validFixture,
			statxMountID: 41,
			pinMountID:   42,
		},
		{
			name:         "pin mount mismatch",
			fixture:      validFixture,
			statxMountID: 42,
			pinMountID:   41,
		},
		{
			name:         "not mount root",
			fixture:      isolatedMountInfoFixture(layout, "0:42", "/production/subtree", "bpf", ""),
			statxMountID: 42,
			pinMountID:   42,
		},
		{
			name:         "custom source label",
			fixture:      isolatedMountInfoFixture(layout, "0:42", "/", "wg-mix-ebpf-"+layout.runID, ""),
			statxMountID: 42,
			pinMountID:   42,
		},
		{
			name: "legacy bpf source label",
			fixture: strings.Replace(
				validFixture,
				" - bpf "+isolatedNetNSTestBPFFSSource(
					layout.runID,
					isolatedFixtureOwnerToken,
				)+" ",
				" - bpf bpf ",
				1,
			),
			statxMountID: 42,
			pinMountID:   42,
		},
		{
			name: "nested pin mount",
			fixture: isolatedMountInfoFixture(
				layout,
				"0:42",
				"/",
				"bpf",
				fmt.Sprintf(
					"43 42 0:43 / %s rw,nosuid,nodev,noexec,relatime - tmpfs nested rw\n",
					filepath.Join(layout.bpffsDir, "wg-mix-ebpf-a"),
				),
			),
			statxMountID: 42,
			pinMountID:   42,
		},
		{
			name: "stacked target mount",
			fixture: validFixture + fmt.Sprintf(
				"44 21 0:44 / %s rw,nosuid,nodev,noexec,relatime - bpf other rw\n",
				layout.bpffsDir,
			),
			statxMountID: 42,
			pinMountID:   42,
		},
		{
			name: "production bind alias",
			fixture: isolatedMountInfoFixture(
				layout,
				"0:30",
				"/",
				"bpf",
				"",
			),
			statxMountID: 42,
			pinMountID:   42,
		},
		{
			name: "other test bind alias",
			fixture: isolatedMountInfoFixture(
				layout,
				"0:42",
				"/",
				"bpf",
				"43 21 0:42 / /run/wg-mix-ebpf-tests/ffffffff/bpffs rw,nosuid,nodev,noexec,relatime - bpf bpf rw\n",
			),
			statxMountID: 42,
			pinMountID:   42,
		},
		{
			name:         "manifest custom source label",
			fixture:      validFixture,
			statxMountID: 42,
			pinMountID:   42,
			mutate: func(value isolatedNetNSTestManifest) isolatedNetNSTestManifest {
				value.values["bpffs_source"] = "wg-mix-ebpf-" + layout.runID
				return value
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries, err := parseMountInfo([]byte(tt.fixture))
			if err != nil {
				t.Fatalf("parse fixture: %v", err)
			}
			testManifest := isolatedNetNSTestManifest{
				values: make(map[string]string, len(manifest.values)),
			}
			for key, value := range manifest.values {
				testManifest.values[key] = value
			}
			if tt.mutate != nil {
				testManifest = tt.mutate(testManifest)
			}
			if err := validatePrivateBPFFSMountInfo(
				entries,
				layout,
				testManifest,
				tt.statxMountID,
				&tt.pinMountID,
			); err == nil {
				t.Fatal("private bpffs validation unexpectedly succeeded")
			}
		})
	}
}

func TestPrivateBPFFSMountOptionsAreOrderIndependentAndFailClosed(t *testing.T) {
	layout, _, _, _, _ := isolatedFixtureLayout(t, "a")
	manifest, err := parseIsolatedNetNSTestManifest(isolatedFixtureManifest(layout))
	if err != nil {
		t.Fatal(err)
	}
	validOptions := []string{
		"rw,nosuid,nodev,noexec,relatime",
		"noexec,nodev,strictatime,nosuid,rw",
		"noatime,rw,noexec,nosuid,nodev",
	}
	for _, options := range validOptions {
		t.Run(options, func(t *testing.T) {
			fixture := isolatedMountInfoFixtureWithTargetOptions(
				layout,
				options,
				"",
				"mode=700,rw",
			)
			entries, err := parseMountInfo([]byte(fixture))
			if err != nil {
				t.Fatalf("parse mountinfo: %v", err)
			}
			if err := validatePrivateBPFFSMountInfo(
				entries,
				layout,
				manifest,
				42,
				nil,
			); err != nil {
				t.Fatalf("validate reordered safe options: %v", err)
			}
		})
	}
	for _, superOptions := range []string{
		"rw",
		"rw,mode=700",
		"mode=700,rw",
		"rw,mode=0700",
	} {
		t.Run("super "+superOptions, func(t *testing.T) {
			fixture := isolatedMountInfoFixtureWithTargetOptions(
				layout,
				"rw,nosuid,nodev,noexec,relatime",
				"",
				superOptions,
			)
			entries, err := parseMountInfo([]byte(fixture))
			if err != nil {
				t.Fatalf("parse safe super options: %v", err)
			}
			if err := validatePrivateBPFFSMountInfo(
				entries,
				layout,
				manifest,
				42,
				nil,
			); err != nil {
				t.Fatalf("validate safe super options: %v", err)
			}
		})
	}

	invalidOptions := map[string]string{
		"missing rw":        "nosuid,nodev,noexec,relatime",
		"missing nosuid":    "rw,nodev,noexec,relatime",
		"missing nodev":     "rw,nosuid,noexec,relatime",
		"missing noexec":    "rw,nosuid,nodev,relatime",
		"missing atime":     "rw,nosuid,nodev,noexec",
		"conflicting rw":    "rw,ro,nosuid,nodev,noexec,relatime",
		"conflicting exec":  "rw,nosuid,nodev,noexec,exec,relatime",
		"multiple atime":    "rw,nosuid,nodev,noexec,relatime,noatime",
		"unknown mount opt": "rw,nosuid,nodev,noexec,relatime,lazytime",
	}
	for name, options := range invalidOptions {
		t.Run(name, func(t *testing.T) {
			fixture := isolatedMountInfoFixtureWithTargetOptions(
				layout,
				options,
				"",
				"rw",
			)
			entries, err := parseMountInfo([]byte(fixture))
			if err != nil {
				t.Fatalf("parse invalid semantic fixture: %v", err)
			}
			if err := validatePrivateBPFFSMountInfo(
				entries,
				layout,
				manifest,
				42,
				nil,
			); err == nil {
				t.Fatal("unsafe or ambiguous mount options unexpectedly accepted")
			}
		})
	}

	invalidSuperOptions := map[string]string{
		"read only":        "ro",
		"missing rw":       "mode=700",
		"unsafe mode":      "rw,mode=755",
		"noncanonical":     "rw,mode=00700",
		"unknown":          "rw,uid=0",
		"duplicate mode":   "rw,mode=700,mode=0700",
		"conflicting mode": "rw,mode=700,mode=755",
	}
	for name, options := range invalidSuperOptions {
		t.Run("super "+name, func(t *testing.T) {
			fixture := isolatedMountInfoFixtureWithTargetOptions(
				layout,
				"rw,nosuid,nodev,noexec,relatime",
				"",
				options,
			)
			entries, err := parseMountInfo([]byte(fixture))
			if err != nil {
				t.Fatalf("parse invalid super option fixture: %v", err)
			}
			if err := validatePrivateBPFFSMountInfo(
				entries,
				layout,
				manifest,
				42,
				nil,
			); err == nil {
				t.Fatal("unsafe or ambiguous super options unexpectedly accepted")
			}
		})
	}
}

func TestPrivateBPFFSMountRejectsPropagationAndAliasForms(t *testing.T) {
	layout, _, _, _, _ := isolatedFixtureLayout(t, "a")
	manifest, err := parseIsolatedNetNSTestManifest(isolatedFixtureManifest(layout))
	if err != nil {
		t.Fatal(err)
	}
	optionalFields := []string{
		"shared:7",
		"master:8",
		"propagate_from:9",
		"unbindable",
		"future_optional:10",
		"shared:7 master:8",
	}
	for _, optional := range optionalFields {
		t.Run(optional, func(t *testing.T) {
			fixture := isolatedMountInfoFixtureWithTargetOptions(
				layout,
				"rw,nosuid,nodev,noexec,relatime",
				optional,
				"rw",
			)
			entries, err := parseMountInfo([]byte(fixture))
			if err != nil {
				t.Fatalf("parse propagation fixture: %v", err)
			}
			if err := validatePrivateBPFFSMountInfo(
				entries,
				layout,
				manifest,
				42,
				nil,
			); err == nil {
				t.Fatal("propagating or unknown target mount unexpectedly accepted")
			}
		})
	}

	bindSubtree := isolatedMountInfoFixture(
		layout,
		"0:42",
		"/",
		"bpf",
		"43 21 0:42 /subtree /run/wg-mix-ebpf-tests/ffffffff/bpffs rw,nosuid,nodev,noexec,relatime - bpf bpf rw\n",
	)
	entries, err := parseMountInfo([]byte(bindSubtree))
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePrivateBPFFSMountInfo(
		entries,
		layout,
		manifest,
		42,
		nil,
	); err == nil {
		t.Fatal("same-superblock bind subtree unexpectedly accepted")
	}

	source := isolatedNetNSTestBPFFSSource(layout.runID, isolatedFixtureOwnerToken)
	topologyFixtures := map[string]string{
		"missing parent": strings.Replace(
			isolatedMountInfoFixture(layout, "0:42", "/", "bpf", ""),
			"42 21 0:42",
			"42 99 0:42",
			1,
		),
		"bpf parent": fmt.Sprintf(
			"21 1 8:1 / / rw,relatime - ext4 /dev/root rw\n"+
				"41 21 0:41 / %s rw,nosuid,nodev,noexec,relatime - bpf bpf rw\n"+
				"42 41 0:42 / %s rw,nosuid,nodev,noexec,relatime - bpf %s rw\n",
			isolatedNetNSTestRoot,
			layout.bpffsDir,
			source,
		),
		"unrelated parent": fmt.Sprintf(
			"21 1 8:1 / / rw,relatime - ext4 /dev/root rw\n"+
				"41 21 8:2 / /unrelated rw,relatime - ext4 /dev/other rw\n"+
				"42 41 0:42 / %s rw,nosuid,nodev,noexec,relatime - bpf %s rw\n",
			layout.bpffsDir,
			source,
		),
		"shared root ancestor": strings.Replace(
			isolatedMountInfoFixture(layout, "0:42", "/", "bpf", ""),
			"21 1 8:1 / / rw,relatime -",
			"21 1 8:1 / / rw,relatime shared:7 -",
			1,
		),
		"master intermediate ancestor": fmt.Sprintf(
			"21 1 8:1 / / rw,relatime - ext4 /dev/root rw\n"+
				"41 21 0:41 / %s rw,relatime master:8 - tmpfs tmpfs rw\n"+
				"42 41 0:42 / %s rw,nosuid,nodev,noexec,relatime - bpf %s rw\n",
			"/run",
			layout.bpffsDir,
			source,
		),
		"bpf ancestor separated by tmpfs": fmt.Sprintf(
			"21 1 8:1 / / rw,relatime - ext4 /dev/root rw\n"+
				"31 21 0:31 / /run rw,nosuid,nodev,noexec,relatime - bpf prior rw\n"+
				"41 31 0:41 / %s rw,relatime - tmpfs tmpfs rw\n"+
				"42 41 0:42 / %s rw,nosuid,nodev,noexec,relatime - bpf %s rw\n",
			isolatedNetNSTestRoot,
			layout.bpffsDir,
			source,
		),
		"ancestor cycle": fmt.Sprintf(
			"21 1 8:1 / / rw,relatime - ext4 /dev/root rw\n"+
				"41 42 0:41 / %s rw,relatime - tmpfs tmpfs rw\n"+
				"42 41 0:42 / %s rw,nosuid,nodev,noexec,relatime - bpf %s rw\n",
			isolatedNetNSTestRoot,
			layout.bpffsDir,
			source,
		),
		"runBase subtree bind": fmt.Sprintf(
			"21 1 8:1 / / rw,relatime - ext4 /dev/root rw\n"+
				"41 21 8:2 /outside/run %s rw,relatime - ext4 /dev/other rw\n"+
				"42 41 0:42 / %s rw,nosuid,nodev,noexec,relatime - bpf %s rw\n",
			layout.runBase,
			layout.bpffsDir,
			source,
		),
		"config child bind": isolatedMountInfoFixture(
			layout,
			"0:42",
			"/",
			"bpf",
			fmt.Sprintf(
				"50 21 8:2 /outside/config %s rw,relatime - ext4 /dev/other rw\n",
				filepath.Join(layout.runBase, "secrets", "agent-a.yaml"),
			),
		),
		"subtree bind ancestor": fmt.Sprintf(
			"21 1 8:1 / / rw,relatime - ext4 /dev/root rw\n"+
				"41 21 0:41 /outside/run /run rw,relatime - tmpfs tmpfs rw\n"+
				"42 41 0:42 / %s rw,nosuid,nodev,noexec,relatime - bpf %s rw\n",
			layout.bpffsDir,
			source,
		),
		"whole-root bind ancestor": fmt.Sprintf(
			"21 1 8:1 / / rw,relatime - ext4 /dev/root rw\n"+
				"31 21 0:41 / /mnt/source rw,relatime - tmpfs tmpfs rw\n"+
				"41 21 0:41 / /run rw,relatime - tmpfs tmpfs rw\n"+
				"42 41 0:42 / %s rw,nosuid,nodev,noexec,relatime - bpf %s rw\n",
			layout.bpffsDir,
			source,
		),
		"direct namespace root whole-root alias": fmt.Sprintf(
			"21 1 8:1 / / rw,relatime - ext4 /dev/root rw\n"+
				"31 21 8:1 / /host rw,relatime - ext4 /dev/root rw\n"+
				"42 21 0:42 / %s rw,nosuid,nodev,noexec,relatime - bpf %s rw\n",
			layout.bpffsDir,
			source,
		),
		"namespace root subtree": fmt.Sprintf(
			"21 1 8:1 /host-root / rw,relatime - ext4 /dev/root rw\n"+
				"42 21 0:42 / %s rw,nosuid,nodev,noexec,relatime - bpf %s rw\n",
			layout.bpffsDir,
			source,
		),
		"isolated root mount": fmt.Sprintf(
			"21 1 8:1 / / rw,relatime - ext4 /dev/root rw\n"+
				"41 21 0:41 / %s rw,relatime - tmpfs tmpfs rw\n"+
				"42 41 0:42 / %s rw,nosuid,nodev,noexec,relatime - bpf %s rw\n",
			isolatedNetNSTestRoot,
			layout.bpffsDir,
			source,
		),
	}
	for name, fixture := range topologyFixtures {
		t.Run(name, func(t *testing.T) {
			entries, err := parseMountInfo([]byte(fixture))
			if err != nil {
				t.Fatalf("parse topology fixture: %v", err)
			}
			if err := validatePrivateBPFFSMountInfo(
				entries,
				layout,
				manifest,
				42,
				nil,
			); err == nil {
				t.Fatal("invalid bpffs parent topology unexpectedly accepted")
			}
		})
	}
}

func TestPrivateBPFFSMountRejectsRealLinuxRunSubtreeBinds(t *testing.T) {
	if os.Getenv(isolatedPrivilegedMountTestHelper) == "1" {
		if err := runIsolatedPrivilegedMountHelper(t); err != nil {
			t.Fatal(err)
		}
		return
	}
	if runtime.GOOS != "linux" {
		t.Skip("Linux mount namespace integration test")
	}
	if os.Getenv(isolatedPrivilegedMountTestGate) != "1" {
		t.Skip(
			"set WG_MIX_EBPF_RUN_PRIVILEGED_MOUNT_TESTS=1 to run reviewed mount integration",
		)
	}
	if os.Geteuid() != 0 {
		t.Skip("reviewed mount integration requires root inside an isolated mount namespace")
	}
	if err := validateReviewedPrivilegedTools(); err != nil {
		t.Fatalf("validate reviewed privileged tools: %v", err)
	}
	outerNamespace, err := readMountNamespaceIdentity("/proc/self/ns/mnt")
	if err != nil {
		t.Fatalf("read outer mount namespace identity: %v", err)
	}
	runningExecutable, executableIdentity, err := openReviewedRunningExecutable()
	if err != nil {
		t.Fatalf("bind reviewed child executable to current process image: %v", err)
	}
	defer runningExecutable.Close()
	recordData, err := json.Marshal(isolatedPrivilegedLaunchRecord{
		Format:          isolatedPrivilegedLaunchFormat,
		OuterPID:        os.Getpid(),
		OuterMountDev:   outerNamespace.device,
		OuterMountInode: outerNamespace.inode,
		ExecutableDev:   executableIdentity.device,
		ExecutableInode: executableIdentity.inode,
	})
	if err != nil {
		t.Fatalf("encode privileged launch record: %v", err)
	}
	recordReader, recordWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("create privileged launch pipe: %v", err)
	}
	defer recordReader.Close()
	if _, err := recordWriter.Write(append(recordData, '\n')); err != nil {
		_ = recordWriter.Close()
		t.Fatalf("write privileged launch record: %v", err)
	}
	if err := recordWriter.Close(); err != nil {
		t.Fatalf("close privileged launch record writer: %v", err)
	}
	output, _, err := runReviewedPrivilegedCommand(t, isolatedReviewedCommandSpec{
		tool: isolatedReviewedUnsharePath,
		args: []string{
			"--mount",
			"--propagation",
			"private",
			fmt.Sprintf("/proc/self/fd/%d", isolatedPrivilegedExecutableFD),
			"-test.run=^TestPrivateBPFFSMountRejectsRealLinuxRunSubtreeBinds$",
			"-test.count=1",
		},
		target: "new-private-mount-namespace",
		env: []string{
			isolatedPrivilegedMountTestGate + "=1",
			isolatedPrivilegedMountTestHelper + "=1",
			isolatedPrivilegedMountHelperFD + "=" +
				strconv.Itoa(isolatedPrivilegedLaunchFD),
		},
		extraFiles: []*os.File{recordReader, runningExecutable},
		timeout:    60 * time.Second,
	})
	if err != nil {
		t.Fatalf(
			"run reviewed private mount namespace integration: %v\n%s",
			err,
			output,
		)
	}
}

func runIsolatedPrivilegedMountHelper(t *testing.T) error {
	t.Helper()
	launchFD, err := validatePrivilegedMountHelperEnvironment(os.Environ())
	if err != nil {
		return fmt.Errorf("validate privileged helper environment: %w", err)
	}
	if err := validatePrivilegedMountHelperArguments(os.Args); err != nil {
		return fmt.Errorf("validate privileged helper arguments: %w", err)
	}
	if runtime.GOOS != "linux" {
		return fmt.Errorf("privileged mount helper requires Linux")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("privileged mount helper requires effective uid 0")
	}
	if err := validateReviewedPrivilegedTools(); err != nil {
		return fmt.Errorf("validate reviewed privileged tools: %w", err)
	}
	record, err := readPrivilegedLaunchRecord(launchFD)
	if err != nil {
		return fmt.Errorf("read privileged launch record: %w", err)
	}
	currentNamespace, err := readMountNamespaceIdentity("/proc/self/ns/mnt")
	if err != nil {
		return fmt.Errorf("read helper mount namespace: %w", err)
	}
	initialNamespace, err := readMountNamespaceIdentity("/proc/1/ns/mnt")
	if err != nil {
		return fmt.Errorf("read initial mount namespace: %w", err)
	}
	parentPID := os.Getppid()
	parentNamespace, err := readMountNamespaceIdentity(
		fmt.Sprintf("/proc/%d/ns/mnt", parentPID),
	)
	if err != nil {
		return fmt.Errorf("read outer parent mount namespace: %w", err)
	}
	if err := validatePrivilegedLaunchContext(
		record,
		parentPID,
		currentNamespace,
		initialNamespace,
		parentNamespace,
	); err != nil {
		return fmt.Errorf("validate privileged launch context: %w", err)
	}
	openedExecutable, err := readFileIdentity(
		fmt.Sprintf("/proc/self/fd/%d", isolatedPrivilegedExecutableFD),
	)
	if err != nil {
		return fmt.Errorf("read opened child executable identity: %w", err)
	}
	currentExecutable, err := readFileIdentity("/proc/self/exe")
	if err != nil {
		return fmt.Errorf("read current child executable identity: %w", err)
	}
	if err := validatePrivilegedExecutableContext(
		record,
		openedExecutable,
		currentExecutable,
	); err != nil {
		return fmt.Errorf("validate privileged executable context: %w", err)
	}
	if err := validateCurrentPrivateMountPaths("/"); err != nil {
		return fmt.Errorf("validate helper mount namespace root propagation: %w", err)
	}

	resources, err := newReviewedPrivilegedResources(t, "run-subtree")
	if err != nil {
		return fmt.Errorf("create reviewed privileged resources: %w", err)
	}
	root := resources.root
	source, err := resources.createDirectory(t, "source")
	if err != nil {
		return fmt.Errorf("create reviewed bind source: %w", err)
	}
	runBase, err := resources.createDirectory(t, "run")
	if err != nil {
		return fmt.Errorf("create reviewed run target: %w", err)
	}
	if err := validateCurrentPrivateMountPaths("/", root, source, runBase); err != nil {
		return fmt.Errorf("validate reviewed target propagation before mounts: %w", err)
	}
	layout := isolatedNetNSTestLayout{
		runBase:  runBase,
		bpffsDir: filepath.Join(runBase, "bpffs"),
	}
	for _, target := range []string{
		runBase,
		filepath.Join(runBase, "state-a"),
	} {
		if !t.Run(filepath.Base(target), func(t *testing.T) {
			if target != runBase {
				created, err := resources.createDirectory(
					t,
					filepath.Join("run", filepath.Base(target)),
				)
				if err != nil {
					t.Fatal(err)
				}
				if created != target {
					t.Fatalf("created target %s, want %s", created, target)
				}
			}
			mounted, err := mountReviewedTarget(
				t,
				[]string{"--bind", "--", source, target},
				target,
			)
			if err != nil {
				t.Fatalf("bind reviewed test target %s: %v", target, err)
			}
			defer mounted.deferredUnmount(t)
			entries, err := readCurrentMountInfo()
			if err != nil {
				t.Fatal(err)
			}
			if err := validateProtectedRunSubtreeMounts(entries, layout); err == nil {
				t.Fatalf("real bind mount at %s unexpectedly accepted", target)
			}
			if err := mounted.unmountAndVerify(t); err != nil {
				t.Fatalf("unmount reviewed test target %s: %v", target, err)
			}
		}) {
			return fmt.Errorf("reviewed bind rejection subtest failed for %s", target)
		}
	}
	if err := runIsolatedPrivilegedAncestorBindHelper(t); err != nil {
		return err
	}
	if err := resources.cleanup(t); err != nil {
		return fmt.Errorf("cleanup reviewed privileged resources: %w", err)
	}
	return nil
}

func runIsolatedPrivilegedAncestorBindHelper(t *testing.T) error {
	t.Helper()
	for _, mode := range []string{"subtree", "whole-root"} {
		if !t.Run("ancestor-"+mode, func(t *testing.T) {
			resources, err := newReviewedPrivilegedResources(
				t,
				"ancestor-"+mode,
			)
			if err != nil {
				t.Fatal(err)
			}
			root := resources.root
			source, err := resources.createDirectory(t, "source")
			if err != nil {
				t.Fatal(err)
			}
			ancestor, err := resources.createDirectory(t, "ancestor")
			if err != nil {
				t.Fatal(err)
			}
			if err := validateCurrentPrivateMountPaths(
				"/",
				root,
				source,
				ancestor,
			); err != nil {
				t.Fatalf("validate ancestor targets before mounts: %v", err)
			}
			var sourceMounted *isolatedReviewedMountedTarget
			if mode == "whole-root" {
				var err error
				sourceMounted, err = mountReviewedTarget(
					t,
					[]string{
						"-t",
						"tmpfs",
						"-o",
						"mode=0700,size=1m",
						"wg-mix-ebpf-ancestor-test",
						source,
					},
					source,
				)
				if err != nil {
					t.Fatalf("mount reviewed tmpfs source %s: %v", source, err)
				}
				defer sourceMounted.deferredUnmount(t)
			}
			protectedRoot := filepath.Join(ancestor, "isolated-root")
			sourceProtectedRoot := filepath.Join(source, "isolated-root")
			if mode == "whole-root" {
				if err := reviewedMkdir(
					t,
					"create-ephemeral-mounted-directory",
					sourceProtectedRoot,
					0o700,
				); err != nil {
					t.Fatal(err)
				}
			} else {
				created, err := resources.createDirectory(
					t,
					filepath.Join("source", "isolated-root"),
				)
				if err != nil {
					t.Fatal(err)
				}
				if created != sourceProtectedRoot {
					t.Fatalf(
						"created protected source %s, want %s",
						created,
						sourceProtectedRoot,
					)
				}
			}
			bindMounted, err := mountReviewedTarget(
				t,
				[]string{"--bind", "--", source, ancestor},
				ancestor,
			)
			if err != nil {
				t.Fatalf("bind reviewed ancestor %s: %v", ancestor, err)
			}
			defer bindMounted.deferredUnmount(t)
			entries, err := readCurrentMountInfo()
			if err != nil {
				t.Fatal(err)
			}
			chain, err := isolatedAncestorChainForTest(
				entries,
				ancestor,
				filepath.Join(protectedRoot, "run", "bpffs"),
			)
			if err != nil {
				t.Fatal(err)
			}
			err = validatePrivateBPFFSMountAncestors(
				entries,
				chain,
				protectedRoot,
			)
			if err == nil {
				t.Fatalf("real %s ancestor bind unexpectedly accepted", mode)
			}
			want := "subtree bind"
			if mode == "whole-root" {
				want = "aliases whole mount root"
			}
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("real %s ancestor bind error = %v, want %q", mode, err, want)
			}
			if err := bindMounted.unmountAndVerify(t); err != nil {
				t.Fatalf("unmount reviewed ancestor %s: %v", ancestor, err)
			}
			if sourceMounted != nil {
				if err := sourceMounted.unmountAndVerify(t); err != nil {
					t.Fatalf("unmount reviewed source %s: %v", source, err)
				}
			}
			if err := resources.cleanup(t); err != nil {
				t.Fatalf("cleanup reviewed ancestor resources: %v", err)
			}
		}) {
			return fmt.Errorf("reviewed ancestor rejection subtest failed for %s", mode)
		}
	}
	return nil
}

func isolatedAncestorChainForTest(
	entries []mountInfoEntry,
	ancestorPath string,
	targetPath string,
) ([]mountInfoEntry, error) {
	byMountID := make(map[uint64]mountInfoEntry, len(entries))
	var ancestor *mountInfoEntry
	var maximumMountID uint64
	for index := range entries {
		entry := entries[index]
		byMountID[entry.mountID] = entry
		if entry.mountID > maximumMountID {
			maximumMountID = entry.mountID
		}
		if entry.mountPath == ancestorPath {
			if ancestor != nil {
				return nil, fmt.Errorf("multiple mounts found at ancestor %s", ancestorPath)
			}
			copy := entry
			ancestor = &copy
		}
	}
	if ancestor == nil {
		return nil, fmt.Errorf("ancestor mount %s is absent", ancestorPath)
	}
	chain := []mountInfoEntry{{
		mountID:   maximumMountID + 1,
		parentID:  ancestor.mountID,
		device:    "0:999999",
		root:      "/",
		mountPath: targetPath,
		fsType:    "bpf",
		source:    "reviewed-test-target",
	}}
	current := *ancestor
	seen := make(map[uint64]struct{})
	for {
		if _, cycle := seen[current.mountID]; cycle {
			return nil, fmt.Errorf("ancestor test chain cycles at %d", current.mountID)
		}
		seen[current.mountID] = struct{}{}
		chain = append(chain, current)
		if current.mountPath == "/" {
			return chain, nil
		}
		parent, ok := byMountID[current.parentID]
		if !ok {
			return nil, fmt.Errorf("ancestor test chain misses parent %d", current.parentID)
		}
		current = parent
	}
}

func reviewedMkdir(
	t *testing.T,
	operation string,
	target string,
	mode os.FileMode,
) error {
	t.Helper()
	if err := validateReviewedFilesystemWrite(
		operation,
		target,
	); err != nil {
		return err
	}
	operationErr := os.Mkdir(target, mode)
	return recordReviewedFilesystemWrite(
		t,
		operation,
		target,
		operationErr,
	)
}

func reviewedMkdirTemp(
	t *testing.T,
	parent string,
	pattern string,
) (string, error) {
	t.Helper()
	if parent != isolatedPrivilegedTestPrefix ||
		pattern == "" ||
		strings.ContainsAny(pattern, `/\`+"\x00\r\n") {
		return "", fmt.Errorf(
			"reviewed unique directory request is outside its fixed prefix",
		)
	}
	root, operationErr := os.MkdirTemp(parent, pattern)
	auditTarget := root
	if auditTarget == "" {
		auditTarget = parent
	}
	auditErr := recordReviewedFilesystemWrite(
		t,
		"create-unique-test-root",
		auditTarget,
		operationErr,
	)
	if operationErr != nil || auditErr != nil {
		return root, auditErr
	}
	return root, nil
}

func createReviewedOwnerMarker(
	t *testing.T,
	target string,
	content string,
) error {
	t.Helper()
	if err := validateReviewedFilesystemWrite(
		"create-owner-marker",
		target,
	); err != nil {
		return err
	}
	file, openErr := os.OpenFile(
		target,
		os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW,
		0o600,
	)
	if openErr != nil {
		return recordReviewedFilesystemWrite(
			t,
			"create-owner-marker",
			target,
			openErr,
		)
	}
	_, writeErr := io.WriteString(file, content)
	syncErr := file.Sync()
	closeErr := file.Close()
	operationErr := errors.Join(writeErr, syncErr, closeErr)
	return recordReviewedFilesystemWrite(
		t,
		"create-owner-marker",
		target,
		operationErr,
	)
}

func validateReviewedFilesystemWrite(
	operation string,
	target string,
) error {
	switch operation {
	case "create-dedicated-prefix",
		"create-unique-test-root",
		"create-owner-marker",
		"create-owned-directory",
		"create-ephemeral-mounted-directory":
	default:
		return fmt.Errorf(
			"reviewed filesystem write operation %q is not allowed",
			operation,
		)
	}
	if target == "" ||
		!filepath.IsAbs(target) ||
		filepath.Clean(target) != target ||
		target == "/" ||
		(target != isolatedPrivilegedTestPrefix &&
			!mountPathStrictAncestor(
				isolatedPrivilegedTestPrefix,
				target,
			)) {
		return fmt.Errorf(
			"reviewed filesystem write target %q is outside its dedicated prefix",
			target,
		)
	}
	return nil
}

func recordReviewedFilesystemWrite(
	t *testing.T,
	operation string,
	target string,
	operationErr error,
) error {
	t.Helper()
	exitCode := 0
	if operationErr != nil {
		exitCode = 1
	}
	audit := isolatedReviewedFilesystemWriteAudit{
		Format:    isolatedPrivilegedWriteFormat,
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Operation: operation,
		Target:    target,
		ExitCode:  exitCode,
	}
	if err := validateReviewedFilesystemWriteAudit(
		audit,
		operation,
		target,
		exitCode,
	); err != nil {
		return errors.Join(operationErr, err)
	}
	auditData, auditErr := json.Marshal(audit)
	if auditErr != nil {
		return errors.Join(
			operationErr,
			fmt.Errorf("encode reviewed filesystem write audit: %w", auditErr),
		)
	}
	t.Logf("reviewed privileged filesystem write audit: %s", auditData)
	return operationErr
}

func validateReviewedFilesystemWriteAudit(
	audit isolatedReviewedFilesystemWriteAudit,
	operation string,
	target string,
	expectedExitCode int,
) error {
	if audit.Format != isolatedPrivilegedWriteFormat {
		return fmt.Errorf("reviewed filesystem write audit format is invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, audit.Timestamp); err != nil {
		return fmt.Errorf(
			"reviewed filesystem write audit timestamp is invalid",
		)
	}
	if audit.Operation != operation {
		return fmt.Errorf(
			"reviewed filesystem write audit operation differs from write",
		)
	}
	if audit.Target != target {
		return fmt.Errorf(
			"reviewed filesystem write audit target differs from write",
		)
	}
	if audit.ExitCode != expectedExitCode {
		return fmt.Errorf(
			"reviewed filesystem write audit exit code differs from write",
		)
	}
	return nil
}

func newReviewedPrivilegedResources(
	t *testing.T,
	purpose string,
) (*isolatedReviewedPrivilegedResources, error) {
	t.Helper()
	switch purpose {
	case "run-subtree", "ancestor-subtree", "ancestor-whole-root":
	default:
		return nil, fmt.Errorf(
			"reviewed privileged resource purpose %q is not allowed",
			purpose,
		)
	}
	if err := ensureReviewedPrivilegedTestPrefix(t); err != nil {
		return nil, err
	}
	root, err := reviewedMkdirTemp(
		t,
		isolatedPrivilegedTestPrefix,
		purpose+"-",
	)
	if err != nil {
		return nil, fmt.Errorf("create reviewed unique test root: %w", err)
	}
	root = filepath.Clean(root)
	rootOwned, err := readReviewedOwnedPath(root)
	if err != nil {
		return nil, fmt.Errorf("record reviewed unique test root: %w", err)
	}
	if !rootOwned.mode.IsDir() ||
		rootOwned.mode.Perm() != 0o700 ||
		rootOwned.uid != 0 {
		return nil, fmt.Errorf(
			"reviewed unique test root %s is not a root-owned 0700 directory",
			root,
		)
	}
	runID := filepath.Base(root)
	if len(runID) < len(purpose)+7 ||
		!strings.HasPrefix(runID, purpose+"-") {
		return nil, fmt.Errorf(
			"reviewed unique test root %s has invalid run id %q",
			root,
			runID,
		)
	}
	markerContent := fmt.Sprintf(
		"format=%s\nrun_id=%s\nroot=%s\npid=%d\n",
		isolatedPrivilegedOwnerFormat,
		runID,
		root,
		os.Getpid(),
	)
	markerPath := filepath.Join(root, isolatedPrivilegedOwnerMarker)
	if err := createReviewedOwnerMarker(
		t,
		markerPath,
		markerContent,
	); err != nil {
		return nil, err
	}
	markerOwned, err := readReviewedOwnedPath(markerPath)
	if err != nil {
		return nil, fmt.Errorf("record reviewed owner marker: %w", err)
	}
	if !markerOwned.mode.IsRegular() ||
		markerOwned.mode.Perm() != 0o600 ||
		markerOwned.uid != 0 ||
		markerOwned.device != rootOwned.device {
		return nil, fmt.Errorf(
			"reviewed owner marker %s has unsafe metadata",
			markerPath,
		)
	}
	resources := &isolatedReviewedPrivilegedResources{
		root:          root,
		runID:         runID,
		markerContent: markerContent,
		owned:         []isolatedReviewedOwnedPath{rootOwned, markerOwned},
	}
	t.Logf(
		"reviewed privileged resource creation: timestamp=%s root=%q run_id=%q marker=%q",
		time.Now().UTC().Format(time.RFC3339Nano),
		root,
		runID,
		markerPath,
	)
	return resources, nil
}

func ensureReviewedPrivilegedTestPrefix(t *testing.T) error {
	t.Helper()
	if isolatedPrivilegedTestPrefix == "" ||
		!filepath.IsAbs(isolatedPrivilegedTestPrefix) ||
		filepath.Clean(isolatedPrivilegedTestPrefix) !=
			isolatedPrivilegedTestPrefix {
		return fmt.Errorf("reviewed privileged test prefix is not canonical")
	}
	err := reviewedMkdir(
		t,
		"create-dedicated-prefix",
		isolatedPrivilegedTestPrefix,
		0o700,
	)
	if err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create reviewed privileged test prefix: %w", err)
	}
	info, err := os.Lstat(isolatedPrivilegedTestPrefix)
	if err != nil {
		return fmt.Errorf("lstat reviewed privileged test prefix: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf(
			"reviewed privileged test prefix lacks stat metadata",
		)
	}
	if !info.IsDir() ||
		info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o700 ||
		stat.Uid != 0 {
		return fmt.Errorf(
			"reviewed privileged test prefix %s must be a root-owned real 0700 directory",
			isolatedPrivilegedTestPrefix,
		)
	}
	resolved, err := filepath.EvalSymlinks(isolatedPrivilegedTestPrefix)
	if err != nil {
		return fmt.Errorf("resolve reviewed privileged test prefix: %w", err)
	}
	if resolved != isolatedPrivilegedTestPrefix {
		return fmt.Errorf(
			"reviewed privileged test prefix resolves to %s",
			resolved,
		)
	}
	return nil
}

func (resources *isolatedReviewedPrivilegedResources) createDirectory(
	t *testing.T,
	relative string,
) (string, error) {
	t.Helper()
	if resources == nil || resources.cleaned {
		return "", fmt.Errorf("reviewed privileged resources are unavailable")
	}
	if relative == "" ||
		filepath.IsAbs(relative) ||
		filepath.Clean(relative) != relative ||
		relative == "." ||
		relative == ".." ||
		strings.HasPrefix(
			relative,
			".."+string(filepath.Separator),
		) {
		return "", fmt.Errorf(
			"reviewed resource path %q is not a canonical relative path",
			relative,
		)
	}
	target := filepath.Join(resources.root, relative)
	if !mountPathStrictAncestor(resources.root, target) {
		return "", fmt.Errorf(
			"reviewed resource target %s escapes root %s",
			target,
			resources.root,
		)
	}
	parent := filepath.Dir(target)
	parentOwned := false
	for _, owned := range resources.owned {
		if owned.path == parent && owned.mode.IsDir() {
			parentOwned = true
			break
		}
	}
	if !parentOwned {
		return "", fmt.Errorf(
			"reviewed resource parent %s was not created by this run",
			parent,
		)
	}
	if err := reviewedMkdir(
		t,
		"create-owned-directory",
		target,
		0o700,
	); err != nil {
		return "", fmt.Errorf("create reviewed directory %s: %w", target, err)
	}
	owned, err := readReviewedOwnedPath(target)
	if err != nil {
		return "", err
	}
	if !owned.mode.IsDir() ||
		owned.mode.Perm() != 0o700 ||
		owned.uid != 0 ||
		owned.device != resources.owned[0].device {
		return "", fmt.Errorf(
			"reviewed directory %s has unsafe metadata",
			target,
		)
	}
	resources.owned = append(resources.owned, owned)
	return target, nil
}

func readReviewedOwnedPath(path string) (isolatedReviewedOwnedPath, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return isolatedReviewedOwnedPath{}, fmt.Errorf(
			"reviewed owned path %q is not canonical and absolute",
			path,
		)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return isolatedReviewedOwnedPath{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return isolatedReviewedOwnedPath{}, fmt.Errorf(
			"reviewed owned path %s is a symlink",
			path,
		)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Ino == 0 {
		return isolatedReviewedOwnedPath{}, fmt.Errorf(
			"reviewed owned path %s lacks stable stat identity",
			path,
		)
	}
	return isolatedReviewedOwnedPath{
		path:   path,
		device: uint64(stat.Dev),
		inode:  uint64(stat.Ino),
		uid:    stat.Uid,
		mode:   info.Mode(),
	}, nil
}

func (resources *isolatedReviewedPrivilegedResources) cleanup(
	t *testing.T,
) error {
	t.Helper()
	if resources == nil {
		return fmt.Errorf("reviewed privileged resources are nil")
	}
	if resources.cleaned {
		return fmt.Errorf(
			"reviewed privileged resources %s were already cleaned",
			resources.root,
		)
	}
	resolved, err := filepath.EvalSymlinks(resources.root)
	if err != nil {
		return fmt.Errorf("resolve reviewed cleanup root: %w", err)
	}
	if resolved != resources.root {
		return fmt.Errorf(
			"reviewed cleanup root %s resolves to %s",
			resources.root,
			resolved,
		)
	}
	markerPath := filepath.Join(
		resources.root,
		isolatedPrivilegedOwnerMarker,
	)
	if len(resources.owned) < 2 {
		return fmt.Errorf("reviewed cleanup owner marker identity is absent")
	}
	currentMarker, err := readReviewedOwnedPath(markerPath)
	if err != nil {
		return fmt.Errorf("revalidate reviewed owner marker: %w", err)
	}
	if !sameReviewedOwnedPath(currentMarker, resources.owned[1]) {
		return fmt.Errorf(
			"reviewed cleanup owner marker %s changed from creation",
			markerPath,
		)
	}
	markerContent, err := readReviewedOwnerMarker(markerPath)
	if err != nil {
		return err
	}
	if markerContent != resources.markerContent {
		return fmt.Errorf(
			"reviewed cleanup owner marker %s does not match this run",
			markerPath,
		)
	}
	entries, err := readCurrentMountInfo()
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if mountPathContainsPath(resources.root, entry.mountPath) {
			return fmt.Errorf(
				"reviewed cleanup root %s still contains mount %s",
				resources.root,
				entry.mountPath,
			)
		}
	}
	observed := make([]isolatedReviewedOwnedPath, 0, len(resources.owned))
	err = filepath.Walk(
		resources.root,
		func(path string, _ os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if len(observed) >= 64 {
				return fmt.Errorf(
					"reviewed cleanup tree exceeds 64 entries",
				)
			}
			owned, err := readReviewedOwnedPath(path)
			if err != nil {
				return err
			}
			observed = append(observed, owned)
			return nil
		},
	)
	if err != nil {
		return fmt.Errorf("list reviewed cleanup tree: %w", err)
	}
	if err := validateReviewedCleanupPlan(resources, observed); err != nil {
		return err
	}
	host, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("read cleanup host identity: %w", err)
	}
	for _, observedPath := range observed {
		t.Logf(
			"reviewed cleanup read-only listing: host=%q target=%q device=%d inode=%d mode=%s",
			host,
			observedPath.path,
			observedPath.device,
			observedPath.inode,
			observedPath.mode,
		)
	}
	for index := len(resources.owned) - 1; index >= 0; index-- {
		expected := resources.owned[index]
		current, err := readReviewedOwnedPath(expected.path)
		if err != nil {
			return fmt.Errorf(
				"revalidate reviewed cleanup target %s: %w",
				expected.path,
				err,
			)
		}
		if !sameReviewedOwnedPath(current, expected) {
			return fmt.Errorf(
				"reviewed cleanup target %s changed before removal",
				expected.path,
			)
		}
		removeErr := os.Remove(expected.path)
		exitCode := 0
		if removeErr != nil {
			exitCode = 1
		}
		audit := isolatedReviewedCleanupAudit{
			Format:    isolatedPrivilegedCleanupFormat,
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			Host:      host,
			Argv:      []string{"os.Remove", "--", expected.path},
			Target:    expected.path,
			Device:    expected.device,
			Inode:     expected.inode,
			ExitCode:  exitCode,
		}
		auditData, auditErr := json.Marshal(audit)
		if auditErr != nil {
			return fmt.Errorf("encode reviewed cleanup audit: %w", auditErr)
		}
		t.Logf("reviewed privileged cleanup audit: %s", auditData)
		if removeErr != nil {
			return fmt.Errorf(
				"remove exact reviewed cleanup target %s: %w",
				expected.path,
				removeErr,
			)
		}
		if _, err := os.Lstat(expected.path); !errors.Is(err, os.ErrNotExist) {
			if err == nil {
				return fmt.Errorf(
					"reviewed cleanup target %s still exists after removal",
					expected.path,
				)
			}
			return fmt.Errorf(
				"verify reviewed cleanup target %s removal: %w",
				expected.path,
				err,
			)
		}
	}
	resources.cleaned = true
	return nil
}

func readReviewedOwnerMarker(path string) (string, error) {
	file, err := os.OpenFile(
		path,
		os.O_RDONLY|syscall.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return "", fmt.Errorf("open reviewed owner marker: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil {
		return "", fmt.Errorf("read reviewed owner marker: %w", err)
	}
	if len(data) == 0 || len(data) > 4096 {
		return "", fmt.Errorf(
			"reviewed owner marker must contain 1..4096 bytes",
		)
	}
	return string(data), nil
}

func validateReviewedCleanupPlan(
	resources *isolatedReviewedPrivilegedResources,
	observed []isolatedReviewedOwnedPath,
) error {
	if resources == nil ||
		resources.root == "" ||
		resources.runID == "" ||
		resources.root != filepath.Join(
			isolatedPrivilegedTestPrefix,
			resources.runID,
		) ||
		!mountPathStrictAncestor(
			isolatedPrivilegedTestPrefix,
			resources.root,
		) {
		return fmt.Errorf("reviewed cleanup root is outside its dedicated prefix")
	}
	if len(resources.owned) < 2 ||
		resources.owned[0].path != resources.root ||
		resources.owned[1].path != filepath.Join(
			resources.root,
			isolatedPrivilegedOwnerMarker,
		) {
		return fmt.Errorf(
			"reviewed cleanup plan does not start with root and owner marker",
		)
	}
	if len(observed) != len(resources.owned) {
		return fmt.Errorf(
			"reviewed cleanup listing has %d entries, want exactly %d",
			len(observed),
			len(resources.owned),
		)
	}
	rootDevice := resources.owned[0].device
	expectedByPath := make(
		map[string]isolatedReviewedOwnedPath,
		len(resources.owned),
	)
	expectedIndex := make(map[string]int, len(resources.owned))
	for index, expected := range resources.owned {
		if expected.path == "" ||
			!filepath.IsAbs(expected.path) ||
			filepath.Clean(expected.path) != expected.path ||
			(expected.path != resources.root &&
				!mountPathStrictAncestor(resources.root, expected.path)) ||
			expected.device != rootDevice ||
			expected.uid != 0 ||
			expected.mode&os.ModeSymlink != 0 {
			return fmt.Errorf(
				"reviewed cleanup target %q has unsafe ownership or scope",
				expected.path,
			)
		}
		if _, duplicate := expectedByPath[expected.path]; duplicate {
			return fmt.Errorf(
				"reviewed cleanup target %s is duplicated",
				expected.path,
			)
		}
		if expected.mode.IsDir() {
			if expected.mode.Perm() != 0o700 {
				return fmt.Errorf(
					"reviewed cleanup directory %s is not mode 0700",
					expected.path,
				)
			}
		} else if expected.path ==
			filepath.Join(resources.root, isolatedPrivilegedOwnerMarker) {
			if !expected.mode.IsRegular() ||
				expected.mode.Perm() != 0o600 {
				return fmt.Errorf(
					"reviewed cleanup owner marker metadata is unsafe",
				)
			}
		} else {
			return fmt.Errorf(
				"reviewed cleanup target %s is not an allowed directory or marker",
				expected.path,
			)
		}
		if expected.path != resources.root {
			parentIndex, parentOwned := expectedIndex[filepath.Dir(expected.path)]
			if !parentOwned || parentIndex >= index {
				return fmt.Errorf(
					"reviewed cleanup target %s lacks an earlier owned parent",
					expected.path,
				)
			}
		}
		expectedByPath[expected.path] = expected
		expectedIndex[expected.path] = index
	}
	observedPaths := make(map[string]struct{}, len(observed))
	for _, current := range observed {
		expected, ok := expectedByPath[current.path]
		if !ok || !sameReviewedOwnedPath(current, expected) {
			return fmt.Errorf(
				"reviewed cleanup observed unexpected or changed path %s",
				current.path,
			)
		}
		if _, duplicate := observedPaths[current.path]; duplicate {
			return fmt.Errorf(
				"reviewed cleanup listing duplicates %s",
				current.path,
			)
		}
		observedPaths[current.path] = struct{}{}
	}
	return nil
}

func sameReviewedOwnedPath(
	left isolatedReviewedOwnedPath,
	right isolatedReviewedOwnedPath,
) bool {
	return left.path == right.path &&
		left.device == right.device &&
		left.inode == right.inode &&
		left.uid == right.uid &&
		left.mode == right.mode
}

func validatePrivilegedMountHelperEnvironment(environ []string) (int, error) {
	expected := map[string]string{
		isolatedPrivilegedMountTestGate:   "1",
		isolatedPrivilegedMountTestHelper: "1",
		isolatedPrivilegedMountHelperFD:   strconv.Itoa(isolatedPrivilegedLaunchFD),
	}
	seen := make(map[string]string, len(environ))
	for _, item := range environ {
		key, value, ok := strings.Cut(item, "=")
		if !ok || key == "" {
			return 0, fmt.Errorf("privileged helper environment contains an invalid entry")
		}
		if _, duplicate := seen[key]; duplicate {
			return 0, fmt.Errorf(
				"privileged helper environment duplicates %s",
				key,
			)
		}
		if _, allowed := expected[key]; !allowed {
			return 0, fmt.Errorf(
				"privileged helper environment contains unexpected key %s",
				key,
			)
		}
		seen[key] = value
	}
	if len(seen) != len(expected) {
		return 0, fmt.Errorf(
			"privileged helper environment must contain exactly %d entries",
			len(expected),
		)
	}
	for key, value := range expected {
		if seen[key] != value {
			return 0, fmt.Errorf(
				"privileged helper environment has invalid value for %s",
				key,
			)
		}
	}
	return isolatedPrivilegedLaunchFD, nil
}

func validatePrivilegedMountHelperArguments(arguments []string) error {
	expected := []string{
		fmt.Sprintf("/proc/self/fd/%d", isolatedPrivilegedExecutableFD),
		"-test.run=^TestPrivateBPFFSMountRejectsRealLinuxRunSubtreeBinds$",
		"-test.count=1",
	}
	if !sameStrings(arguments, expected) {
		return fmt.Errorf(
			"privileged helper arguments are not the fixed reviewed invocation",
		)
	}
	return nil
}

func readPrivilegedLaunchRecord(fd int) (isolatedPrivilegedLaunchRecord, error) {
	if fd != isolatedPrivilegedLaunchFD {
		return isolatedPrivilegedLaunchRecord{}, fmt.Errorf(
			"privileged launch record fd %d is not reviewed fd %d",
			fd,
			isolatedPrivilegedLaunchFD,
		)
	}
	file := os.NewFile(uintptr(fd), "reviewed-privileged-launch-record")
	if file == nil {
		return isolatedPrivilegedLaunchRecord{}, fmt.Errorf(
			"privileged launch record fd %d is invalid",
			fd,
		)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil {
		return isolatedPrivilegedLaunchRecord{}, fmt.Errorf(
			"read privileged launch record fd: %w",
			err,
		)
	}
	if len(data) == 0 || len(data) > 4096 {
		return isolatedPrivilegedLaunchRecord{}, fmt.Errorf(
			"privileged launch record must contain 1..4096 bytes",
		)
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var record isolatedPrivilegedLaunchRecord
	if err := decoder.Decode(&record); err != nil {
		return isolatedPrivilegedLaunchRecord{}, fmt.Errorf(
			"decode privileged launch record: %w",
			err,
		)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return isolatedPrivilegedLaunchRecord{}, fmt.Errorf(
				"privileged launch record contains trailing JSON",
			)
		}
		return isolatedPrivilegedLaunchRecord{}, fmt.Errorf(
			"decode privileged launch record trailer: %w",
			err,
		)
	}
	return record, nil
}

func readMountNamespaceIdentity(path string) (isolatedMountNamespaceIdentity, error) {
	return readFileIdentity(path)
}

func readFileIdentity(path string) (isolatedMountNamespaceIdentity, error) {
	info, err := os.Stat(path)
	if err != nil {
		return isolatedMountNamespaceIdentity{}, err
	}
	return fileInfoIdentity(info)
}

func fileInfoIdentity(info os.FileInfo) (isolatedMountNamespaceIdentity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return isolatedMountNamespaceIdentity{}, fmt.Errorf(
			"file metadata does not expose stat identity",
		)
	}
	if stat.Ino == 0 {
		return isolatedMountNamespaceIdentity{}, fmt.Errorf(
			"file identity has zero inode",
		)
	}
	return isolatedMountNamespaceIdentity{
		device: uint64(stat.Dev),
		inode:  uint64(stat.Ino),
	}, nil
}

func openReviewedRunningExecutable() (
	*os.File,
	isolatedMountNamespaceIdentity,
	error,
) {
	file, err := os.Open("/proc/self/exe")
	if err != nil {
		return nil, isolatedMountNamespaceIdentity{}, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, isolatedMountNamespaceIdentity{}, err
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, isolatedMountNamespaceIdentity{}, fmt.Errorf(
			"/proc/self/exe does not resolve to a regular file",
		)
	}
	identity, err := fileInfoIdentity(info)
	if err != nil {
		_ = file.Close()
		return nil, isolatedMountNamespaceIdentity{}, err
	}
	current, err := readFileIdentity("/proc/self/exe")
	if err != nil {
		_ = file.Close()
		return nil, isolatedMountNamespaceIdentity{}, err
	}
	if identity != current {
		_ = file.Close()
		return nil, isolatedMountNamespaceIdentity{}, fmt.Errorf(
			"opened test executable identity changed during binding",
		)
	}
	return file, identity, nil
}

func validatePrivilegedLaunchContext(
	record isolatedPrivilegedLaunchRecord,
	parentPID int,
	current isolatedMountNamespaceIdentity,
	initial isolatedMountNamespaceIdentity,
	parent isolatedMountNamespaceIdentity,
) error {
	if record.Format != isolatedPrivilegedLaunchFormat {
		return fmt.Errorf("privileged launch record format is invalid")
	}
	if record.OuterPID <= 1 || parentPID != record.OuterPID {
		return fmt.Errorf(
			"helper parent pid %d does not match recorded outer pid %d",
			parentPID,
			record.OuterPID,
		)
	}
	recordedParent := isolatedMountNamespaceIdentity{
		device: record.OuterMountDev,
		inode:  record.OuterMountInode,
	}
	if recordedParent.device == 0 && recordedParent.inode == 0 {
		return fmt.Errorf("recorded outer mount namespace identity is empty")
	}
	if parent != recordedParent {
		return fmt.Errorf(
			"outer parent mount namespace does not match launch record",
		)
	}
	if current == parent {
		return fmt.Errorf(
			"helper still runs in the outer parent mount namespace",
		)
	}
	if current == initial {
		return fmt.Errorf(
			"helper runs in the initial process mount namespace",
		)
	}
	return nil
}

func validatePrivilegedExecutableContext(
	record isolatedPrivilegedLaunchRecord,
	opened isolatedMountNamespaceIdentity,
	current isolatedMountNamespaceIdentity,
) error {
	recorded := isolatedMountNamespaceIdentity{
		device: record.ExecutableDev,
		inode:  record.ExecutableInode,
	}
	if recorded.inode == 0 {
		return fmt.Errorf("recorded executable identity is empty")
	}
	if opened != recorded {
		return fmt.Errorf(
			"inherited executable fd does not match launch record",
		)
	}
	if current != recorded {
		return fmt.Errorf(
			"current executable does not match inherited executable fd",
		)
	}
	return nil
}

func validateReviewedPrivilegedTools() error {
	for _, path := range []string{
		isolatedReviewedUnsharePath,
		isolatedReviewedMountPath,
		isolatedReviewedUmountPath,
	} {
		if err := validateReviewedToolPath(path); err != nil {
			return err
		}
	}
	return nil
}

func validateReviewedToolPath(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("lstat reviewed tool %s: %w", path, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("reviewed tool %s does not expose stat metadata", path)
	}
	return validateReviewedToolMetadata(path, isolatedReviewedToolMetadata{
		mode:  info.Mode(),
		uid:   stat.Uid,
		nlink: uint64(stat.Nlink),
	})
}

func validateReviewedToolMetadata(
	path string,
	metadata isolatedReviewedToolMetadata,
) error {
	switch path {
	case isolatedReviewedUnsharePath,
		isolatedReviewedMountPath,
		isolatedReviewedUmountPath:
	default:
		return fmt.Errorf("tool path %q is not in the reviewed allowlist", path)
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("reviewed tool path %q is not canonical and absolute", path)
	}
	if !metadata.mode.IsRegular() {
		return fmt.Errorf("reviewed tool %s is not a regular file", path)
	}
	if metadata.uid != 0 {
		return fmt.Errorf("reviewed tool %s is not root-owned", path)
	}
	if metadata.nlink == 0 {
		return fmt.Errorf("reviewed tool %s has zero links", path)
	}
	if metadata.mode.Perm()&0o111 == 0 {
		return fmt.Errorf("reviewed tool %s is not executable", path)
	}
	if metadata.mode.Perm()&0o022 != 0 {
		return fmt.Errorf(
			"reviewed tool %s is writable by group or other",
			path,
		)
	}
	return nil
}

func validateReviewedCommandSpec(spec isolatedReviewedCommandSpec) error {
	if spec.timeout <= 0 || spec.timeout > 2*time.Minute {
		return fmt.Errorf("reviewed command timeout is outside 1ns..2m")
	}
	if spec.env == nil {
		return fmt.Errorf("reviewed command environment must be explicit")
	}
	if spec.target == "" || strings.ContainsAny(spec.target, "\x00\r\n") {
		return fmt.Errorf("reviewed command target is invalid")
	}
	for _, arg := range spec.args {
		if arg == "" || strings.ContainsRune(arg, '\x00') {
			return fmt.Errorf("reviewed command contains an invalid argument")
		}
	}
	switch spec.tool {
	case isolatedReviewedUnsharePath:
		if spec.target != "new-private-mount-namespace" {
			return fmt.Errorf("reviewed unshare target is invalid")
		}
		expectedArgs := []string{
			"--mount",
			"--propagation",
			"private",
			fmt.Sprintf("/proc/self/fd/%d", isolatedPrivilegedExecutableFD),
			"-test.run=^TestPrivateBPFFSMountRejectsRealLinuxRunSubtreeBinds$",
			"-test.count=1",
		}
		if !sameStrings(spec.args, expectedArgs) {
			return fmt.Errorf("reviewed unshare argv is not the fixed helper launch")
		}
		if _, err := validatePrivilegedMountHelperEnvironment(spec.env); err != nil {
			return fmt.Errorf("reviewed unshare environment: %w", err)
		}
		if len(spec.extraFiles) != 2 ||
			spec.extraFiles[0] == nil ||
			spec.extraFiles[1] == nil {
			return fmt.Errorf(
				"reviewed unshare requires launch-record and executable fds",
			)
		}
	case isolatedReviewedMountPath:
		if len(spec.env) != 0 || len(spec.extraFiles) != 0 {
			return fmt.Errorf(
				"reviewed mount requires empty environment and no inherited files",
			)
		}
		if err := validateReviewedMountArgv(spec.args, spec.target); err != nil {
			return err
		}
	case isolatedReviewedUmountPath:
		if len(spec.env) != 0 || len(spec.extraFiles) != 0 {
			return fmt.Errorf(
				"reviewed umount requires empty environment and no inherited files",
			)
		}
		if !sameStrings(spec.args, []string{"--", spec.target}) {
			return fmt.Errorf("reviewed umount argv is not exact")
		}
		if err := validateCanonicalReviewedPath(spec.target); err != nil {
			return err
		}
	default:
		return fmt.Errorf("reviewed command tool %q is not allowed", spec.tool)
	}
	return nil
}

func validateReviewedMountArgv(args []string, target string) error {
	if err := validateCanonicalReviewedPath(target); err != nil {
		return err
	}
	if len(args) == 4 &&
		args[0] == "--bind" &&
		args[1] == "--" &&
		args[3] == target {
		if err := validateCanonicalReviewedPath(args[2]); err != nil {
			return fmt.Errorf("reviewed bind source: %w", err)
		}
		return nil
	}
	expectedTmpfs := []string{
		"-t",
		"tmpfs",
		"-o",
		"mode=0700,size=1m",
		"wg-mix-ebpf-ancestor-test",
		target,
	}
	if sameStrings(args, expectedTmpfs) {
		return nil
	}
	return fmt.Errorf("reviewed mount argv is not an allowed exact form")
}

func validateCanonicalReviewedPath(path string) error {
	if path == "" ||
		!filepath.IsAbs(path) ||
		filepath.Clean(path) != path ||
		path == "/" {
		return fmt.Errorf(
			"reviewed path %q must be canonical, absolute, and non-root",
			path,
		)
	}
	return nil
}

func runReviewedPrivilegedCommand(
	t *testing.T,
	spec isolatedReviewedCommandSpec,
) (string, isolatedPrivilegedCommandAudit, error) {
	t.Helper()
	if err := validateReviewedCommandSpec(spec); err != nil {
		return "", isolatedPrivilegedCommandAudit{}, err
	}
	if err := validateReviewedToolPath(spec.tool); err != nil {
		return "", isolatedPrivilegedCommandAudit{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), spec.timeout)
	defer cancel()
	command := exec.CommandContext(ctx, spec.tool, spec.args...)
	command.Env = make([]string, len(spec.env))
	copy(command.Env, spec.env)
	command.ExtraFiles = append([]*os.File(nil), spec.extraFiles...)
	started := time.Now().UTC()
	output, commandErr := command.CombinedOutput()
	finished := time.Now().UTC()
	exitCode := 0
	if commandErr != nil {
		exitCode = -1
		var exitError *exec.ExitError
		if errors.As(commandErr, &exitError) {
			exitCode = exitError.ExitCode()
		}
	}
	audit := isolatedPrivilegedCommandAudit{
		Format:     isolatedPrivilegedAuditFormat,
		StartedAt:  started.Format(time.RFC3339Nano),
		FinishedAt: finished.Format(time.RFC3339Nano),
		Tool:       spec.tool,
		Argv:       append([]string{spec.tool}, spec.args...),
		Target:     spec.target,
		ExitCode:   exitCode,
	}
	auditData, auditErr := json.Marshal(audit)
	if auditErr != nil {
		return string(output), audit, fmt.Errorf(
			"encode reviewed command audit: %w",
			auditErr,
		)
	}
	t.Logf("reviewed privileged command audit: %s", auditData)
	if err := validatePrivilegedCommandAudit(audit, spec, exitCode); err != nil {
		return string(output), audit, fmt.Errorf(
			"validate reviewed command audit: %w",
			err,
		)
	}
	if ctx.Err() != nil {
		return string(output), audit, fmt.Errorf(
			"reviewed command %s timed out after %s: %w",
			spec.tool,
			spec.timeout,
			ctx.Err(),
		)
	}
	if commandErr != nil {
		return string(output), audit, fmt.Errorf(
			"reviewed command %s failed with rc=%d: %w; output=%q",
			spec.tool,
			exitCode,
			commandErr,
			string(output),
		)
	}
	return string(output), audit, nil
}

func validatePrivilegedCommandAudit(
	audit isolatedPrivilegedCommandAudit,
	spec isolatedReviewedCommandSpec,
	expectedExitCode int,
) error {
	if audit.Format != isolatedPrivilegedAuditFormat {
		return fmt.Errorf("reviewed command audit format is invalid")
	}
	started, err := time.Parse(time.RFC3339Nano, audit.StartedAt)
	if err != nil {
		return fmt.Errorf("reviewed command start timestamp is invalid")
	}
	finished, err := time.Parse(time.RFC3339Nano, audit.FinishedAt)
	if err != nil {
		return fmt.Errorf("reviewed command finish timestamp is invalid")
	}
	if finished.Before(started) {
		return fmt.Errorf("reviewed command finish precedes start")
	}
	if audit.Tool != spec.tool {
		return fmt.Errorf("reviewed command audit tool differs from command")
	}
	if !sameStrings(audit.Argv, append([]string{spec.tool}, spec.args...)) {
		return fmt.Errorf("reviewed command audit argv differs from command")
	}
	if audit.Target != spec.target {
		return fmt.Errorf("reviewed command audit target differs from command")
	}
	if audit.ExitCode != expectedExitCode {
		return fmt.Errorf("reviewed command audit exit code differs from command")
	}
	return nil
}

func sameStrings(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func readCurrentMountInfo() ([]mountInfoEntry, error) {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil, fmt.Errorf("read current mountinfo: %w", err)
	}
	entries, err := parseMountInfo(data)
	if err != nil {
		return nil, fmt.Errorf("parse current mountinfo: %w", err)
	}
	return entries, nil
}

func mountPathContainsPath(root string, path string) bool {
	if root == "/" {
		return filepath.IsAbs(path)
	}
	return path == root ||
		strings.HasPrefix(path, root+string(filepath.Separator))
}

func containingMountInfoChain(
	entries []mountInfoEntry,
	path string,
) ([]mountInfoEntry, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("mount lookup path %q is not canonical and absolute", path)
	}
	byMountID := make(map[uint64]mountInfoEntry, len(entries))
	var containing *mountInfoEntry
	for index := range entries {
		entry := entries[index]
		if entry.mountPath == "" ||
			!filepath.IsAbs(entry.mountPath) ||
			filepath.Clean(entry.mountPath) != entry.mountPath {
			return nil, fmt.Errorf(
				"mount %d has noncanonical path %q",
				entry.mountID,
				entry.mountPath,
			)
		}
		byMountID[entry.mountID] = entry
		if !mountPathContainsPath(entry.mountPath, path) {
			continue
		}
		if containing == nil || len(entry.mountPath) > len(containing.mountPath) {
			copy := entry
			containing = &copy
			continue
		}
		if len(entry.mountPath) == len(containing.mountPath) {
			return nil, fmt.Errorf(
				"mount lookup path %s has stacked containing mounts at %s",
				path,
				entry.mountPath,
			)
		}
	}
	if containing == nil {
		return nil, fmt.Errorf("mount lookup path %s has no containing mount", path)
	}
	chain := make([]mountInfoEntry, 0, 8)
	seen := make(map[uint64]struct{}, 8)
	current := *containing
	for {
		if _, duplicate := seen[current.mountID]; duplicate {
			return nil, fmt.Errorf(
				"mount lookup path %s has an ancestry cycle at %d",
				path,
				current.mountID,
			)
		}
		seen[current.mountID] = struct{}{}
		chain = append(chain, current)
		if current.mountPath == "/" {
			return chain, nil
		}
		parent, ok := byMountID[current.parentID]
		if !ok {
			return nil, fmt.Errorf(
				"mount lookup path %s misses parent mount %d",
				path,
				current.parentID,
			)
		}
		if !mountPathStrictAncestor(parent.mountPath, current.mountPath) {
			return nil, fmt.Errorf(
				"mount parent %s is not a strict ancestor of %s",
				parent.mountPath,
				current.mountPath,
			)
		}
		current = parent
	}
}

func validatePrivateMountInfoForPaths(
	entries []mountInfoEntry,
	paths ...string,
) error {
	if len(paths) == 0 {
		return fmt.Errorf("private mount validation requires at least one path")
	}
	for _, path := range paths {
		chain, err := containingMountInfoChain(entries, path)
		if err != nil {
			return err
		}
		for _, entry := range chain {
			if len(entry.optionalFields) != 0 {
				return fmt.Errorf(
					"mount chain for %s has propagation fields at %s: %s",
					path,
					entry.mountPath,
					strings.Join(entry.optionalFields, ","),
				)
			}
		}
	}
	return nil
}

func validateCurrentPrivateMountPaths(paths ...string) error {
	entries, err := readCurrentMountInfo()
	if err != nil {
		return err
	}
	return validatePrivateMountInfoForPaths(entries, paths...)
}

func snapshotReviewedMountTarget(
	t *testing.T,
	target string,
) (isolatedReviewedMountTargetSnapshot, error) {
	t.Helper()
	if err := validateCanonicalReviewedPath(target); err != nil {
		return isolatedReviewedMountTargetSnapshot{}, err
	}
	resolved, err := filepath.EvalSymlinks(target)
	if err != nil {
		return isolatedReviewedMountTargetSnapshot{}, fmt.Errorf(
			"resolve reviewed mount target %s: %w",
			target,
			err,
		)
	}
	if resolved != target {
		return isolatedReviewedMountTargetSnapshot{}, fmt.Errorf(
			"reviewed mount target %s resolves through symlinks to %s",
			target,
			resolved,
		)
	}
	info, err := os.Lstat(target)
	if err != nil {
		return isolatedReviewedMountTargetSnapshot{}, fmt.Errorf(
			"lstat reviewed mount target %s: %w",
			target,
			err,
		)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return isolatedReviewedMountTargetSnapshot{}, fmt.Errorf(
			"reviewed mount target %s is not a real directory",
			target,
		)
	}
	identity, err := fileInfoIdentity(info)
	if err != nil {
		return isolatedReviewedMountTargetSnapshot{}, err
	}
	entries, err := readCurrentMountInfo()
	if err != nil {
		return isolatedReviewedMountTargetSnapshot{}, err
	}
	for _, entry := range entries {
		if mountPathContainsPath(target, entry.mountPath) {
			return isolatedReviewedMountTargetSnapshot{}, fmt.Errorf(
				"reviewed mount target %s already contains mount %s",
				target,
				entry.mountPath,
			)
		}
	}
	if err := validatePrivateMountInfoForPaths(entries, "/", target); err != nil {
		return isolatedReviewedMountTargetSnapshot{}, err
	}
	chain, err := containingMountInfoChain(entries, target)
	if err != nil {
		return isolatedReviewedMountTargetSnapshot{}, err
	}
	snapshot := isolatedReviewedMountTargetSnapshot{
		target: target,
		device: identity.device,
		inode:  identity.inode,
		chain:  append([]mountInfoEntry(nil), chain...),
	}
	t.Logf(
		"reviewed mount target identity: timestamp=%s target=%q device=%d inode=%d containing_mount_id=%d",
		time.Now().UTC().Format(time.RFC3339Nano),
		target,
		snapshot.device,
		snapshot.inode,
		snapshot.chain[0].mountID,
	)
	return snapshot, nil
}

func mountReviewedTarget(
	t *testing.T,
	args []string,
	target string,
) (*isolatedReviewedMountedTarget, error) {
	t.Helper()
	operations := isolatedReviewedMountLifecycleOperations{
		snapshotTarget: func() (isolatedReviewedMountTargetSnapshot, error) {
			return snapshotReviewedMountTarget(t, target)
		},
		readMountInfo: readCurrentMountInfo,
		readTargetIdentity: func() (isolatedMountNamespaceIdentity, error) {
			return readReviewedTargetIdentity(target)
		},
		runMount: func() error {
			output, _, err := runReviewedPrivilegedCommand(
				t,
				isolatedReviewedCommandSpec{
					tool:    isolatedReviewedMountPath,
					args:    append([]string(nil), args...),
					target:  target,
					env:     make([]string, 0),
					timeout: 10 * time.Second,
				},
			)
			if err != nil {
				return fmt.Errorf(
					"mount reviewed target %s: %w; output=%q",
					target,
					err,
					output,
				)
			}
			return nil
		},
		runUnmount: func() error {
			output, _, err := runReviewedPrivilegedCommand(
				t,
				isolatedReviewedCommandSpec{
					tool:    isolatedReviewedUmountPath,
					args:    []string{"--", target},
					target:  target,
					env:     make([]string, 0),
					timeout: 10 * time.Second,
				},
			)
			if err != nil {
				return fmt.Errorf(
					"exact unmount of %s: %w; output=%q",
					target,
					err,
					output,
				)
			}
			return nil
		},
	}
	return mountReviewedTargetWithOperations(target, operations)
}

func mountReviewedTargetWithOperations(
	target string,
	operations isolatedReviewedMountLifecycleOperations,
) (*isolatedReviewedMountedTarget, error) {
	if err := validateReviewedMountLifecycleOperations(operations); err != nil {
		return nil, err
	}
	before, err := operations.snapshotTarget()
	if err != nil {
		return nil, fmt.Errorf("snapshot reviewed target before mount: %w", err)
	}
	if before.target != target {
		return nil, fmt.Errorf(
			"reviewed target snapshot path %s differs from mount target %s",
			before.target,
			target,
		)
	}
	mounted := &isolatedReviewedMountedTarget{
		target:     target,
		before:     before,
		operations: operations,
	}
	mountErr := operations.runMount()
	entries, mountInfoErr := operations.readMountInfo()
	if mountInfoErr != nil {
		cleanupErr := mounted.unmountAmbiguousMountAndVerify()
		return nil, joinReviewedLifecycleErrors(
			"reconcile ambiguous reviewed mount result",
			mountErr,
			fmt.Errorf("read mountinfo after mount command: %w", mountInfoErr),
			cleanupErr,
		)
	}
	mountedEntry, present, stateErr := reviewedMountAtTarget(entries, target)
	if stateErr != nil {
		mounted.cleanupBlocked = true
		return nil, joinReviewedLifecycleErrors(
			"reconcile reviewed mount result",
			mountErr,
			stateErr,
		)
	}
	if !present {
		after, snapshotErr := operations.snapshotTarget()
		restorationErr := validateRestoredSnapshotIfAvailable(
			before,
			after,
			snapshotErr,
		)
		if mountErr != nil {
			return nil, joinReviewedLifecycleErrors(
				"mount command failed without a committed target mount",
				mountErr,
				restorationErr,
			)
		}
		return nil, joinReviewedLifecycleErrors(
			"mount command reported success without a committed target mount",
			fmt.Errorf("reviewed target %s is not an exact mount", target),
			restorationErr,
		)
	}
	mounted.mounted = mountedEntry
	mounted.active = true
	validationErr := validatePrivateMountInfoForPaths(entries, "/", target)
	if validationErr == nil {
		var identity isolatedMountNamespaceIdentity
		identity, validationErr = operations.readTargetIdentity()
		if validationErr == nil &&
			identity.device == before.device &&
			identity.inode == before.inode {
			validationErr = fmt.Errorf(
				"reviewed mount target %s identity did not change after mount",
				target,
			)
		}
	}
	if mountErr != nil || validationErr != nil {
		cleanupErr := mounted.cleanupFailedMountAttempt()
		return nil, joinReviewedLifecycleErrors(
			"reviewed mount attempt did not complete cleanly",
			mountErr,
			validationErr,
			cleanupErr,
		)
	}
	return mounted, nil
}

func (mounted *isolatedReviewedMountedTarget) cleanupFailedMountAttempt() error {
	cleanupErr := mounted.unmountAndVerifyWithOperations()
	if mounted.active && !mounted.unmountIssued && !mounted.cleanupBlocked {
		fallbackErr := mounted.unmountAmbiguousMountAndVerify()
		return errors.Join(cleanupErr, fallbackErr)
	}
	return cleanupErr
}

func reviewedMountAtTarget(
	entries []mountInfoEntry,
	target string,
) (mountInfoEntry, bool, error) {
	var found *mountInfoEntry
	for index := range entries {
		entry := entries[index]
		if !mountPathContainsPath(target, entry.mountPath) {
			continue
		}
		if entry.mountPath != target {
			return mountInfoEntry{}, false, fmt.Errorf(
				"reviewed target %s contains unexpected mount %s",
				target,
				entry.mountPath,
			)
		}
		if found != nil {
			return mountInfoEntry{}, false, fmt.Errorf(
				"multiple mounts are stacked at reviewed target %s",
				target,
			)
		}
		copy := entry
		found = &copy
	}
	if found == nil {
		return mountInfoEntry{}, false, nil
	}
	return *found, true, nil
}

func readReviewedTargetIdentity(
	target string,
) (isolatedMountNamespaceIdentity, error) {
	info, err := os.Lstat(target)
	if err != nil {
		return isolatedMountNamespaceIdentity{}, fmt.Errorf(
			"lstat reviewed target %s: %w",
			target,
			err,
		)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return isolatedMountNamespaceIdentity{}, fmt.Errorf(
			"reviewed target %s is not a real directory",
			target,
		)
	}
	return fileInfoIdentity(info)
}

func validateReviewedMountLifecycleOperations(
	operations isolatedReviewedMountLifecycleOperations,
) error {
	if operations.snapshotTarget == nil ||
		operations.readMountInfo == nil ||
		operations.readTargetIdentity == nil ||
		operations.runMount == nil ||
		operations.runUnmount == nil {
		return fmt.Errorf("reviewed mount lifecycle operations are incomplete")
	}
	return nil
}

func joinReviewedLifecycleErrors(message string, values ...error) error {
	joined := errors.Join(values...)
	if joined == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", message, joined)
}

func validateRestoredSnapshotIfAvailable(
	before isolatedReviewedMountTargetSnapshot,
	after isolatedReviewedMountTargetSnapshot,
	snapshotErr error,
) error {
	if snapshotErr != nil {
		return fmt.Errorf("snapshot restored target: %w", snapshotErr)
	}
	return validateReviewedMountTargetRestored(before, after)
}

func (mounted *isolatedReviewedMountedTarget) deferredUnmount(t *testing.T) {
	t.Helper()
	if mounted == nil ||
		!mounted.active ||
		mounted.unmountIssued ||
		mounted.cleanupBlocked {
		return
	}
	if err := mounted.unmountAndVerifyWithOperations(); err != nil {
		t.Errorf(
			"deferred exact unmount and restoration failed for %s: %v",
			mounted.target,
			err,
		)
	}
}

func (mounted *isolatedReviewedMountedTarget) unmountAndVerify(
	t *testing.T,
) error {
	t.Helper()
	return mounted.unmountAndVerifyWithOperations()
}

func (mounted *isolatedReviewedMountedTarget) unmountAndVerifyWithOperations() error {
	if mounted == nil {
		return fmt.Errorf("reviewed mounted target is nil")
	}
	if !mounted.active {
		return fmt.Errorf("reviewed mounted target %s is not active", mounted.target)
	}
	if mounted.cleanupBlocked {
		return fmt.Errorf(
			"reviewed mounted target %s cleanup is blocked by ambiguous state",
			mounted.target,
		)
	}
	if mounted.unmountIssued {
		return fmt.Errorf(
			"reviewed mounted target %s already had its single unmount attempt",
			mounted.target,
		)
	}
	if err := validateReviewedMountLifecycleOperations(mounted.operations); err != nil {
		return err
	}
	entries, err := mounted.operations.readMountInfo()
	if err != nil {
		return fmt.Errorf("read mountinfo before exact unmount: %w", err)
	}
	current, present, err := reviewedMountAtTarget(entries, mounted.target)
	if err != nil {
		mounted.cleanupBlocked = true
		return err
	}
	if !present {
		after, snapshotErr := mounted.operations.snapshotTarget()
		restorationErr := validateRestoredSnapshotIfAvailable(
			mounted.before,
			after,
			snapshotErr,
		)
		if restorationErr == nil {
			mounted.active = false
		}
		return restorationErr
	}
	if !sameMountInfoEntry(current, mounted.mounted) {
		mounted.cleanupBlocked = true
		return fmt.Errorf(
			"reviewed mount identity at %s changed before unmount",
			mounted.target,
		)
	}
	mounted.unmountIssued = true
	commandErr := mounted.operations.runUnmount()
	reconciliationErr := mounted.reconcileAfterUnmount()
	return joinReviewedLifecycleErrors(
		"exact unmount and restoration",
		commandErr,
		reconciliationErr,
	)
}

func (mounted *isolatedReviewedMountedTarget) unmountAmbiguousMountAndVerify() error {
	if mounted == nil {
		return fmt.Errorf("reviewed ambiguous mounted target is nil")
	}
	if mounted.unmountIssued {
		return fmt.Errorf(
			"reviewed target %s already had its single unmount attempt",
			mounted.target,
		)
	}
	mounted.unmountIssued = true
	commandErr := mounted.operations.runUnmount()
	after, snapshotErr := mounted.operations.snapshotTarget()
	restorationErr := validateRestoredSnapshotIfAvailable(
		mounted.before,
		after,
		snapshotErr,
	)
	if restorationErr == nil {
		mounted.active = false
	} else {
		mounted.cleanupBlocked = true
	}
	return joinReviewedLifecycleErrors(
		"ambiguous mount result exact unmount and restoration",
		commandErr,
		restorationErr,
	)
}

func (mounted *isolatedReviewedMountedTarget) reconcileAfterUnmount() error {
	entries, err := mounted.operations.readMountInfo()
	if err != nil {
		after, snapshotErr := mounted.operations.snapshotTarget()
		restorationErr := validateRestoredSnapshotIfAvailable(
			mounted.before,
			after,
			snapshotErr,
		)
		if restorationErr == nil {
			mounted.active = false
		} else {
			mounted.cleanupBlocked = true
		}
		return joinReviewedLifecycleErrors(
			"reconcile exact unmount after mountinfo read failure",
			fmt.Errorf("read mountinfo after exact unmount: %w", err),
			restorationErr,
		)
	}
	current, present, stateErr := reviewedMountAtTarget(entries, mounted.target)
	if stateErr != nil {
		mounted.cleanupBlocked = true
		return stateErr
	}
	if present {
		if !sameMountInfoEntry(current, mounted.mounted) {
			mounted.cleanupBlocked = true
			return fmt.Errorf(
				"reviewed target %s changed to a different mount after unmount",
				mounted.target,
			)
		}
		return fmt.Errorf(
			"reviewed target %s remains mounted after its single unmount attempt",
			mounted.target,
		)
	}
	mounted.active = false
	after, snapshotErr := mounted.operations.snapshotTarget()
	return validateRestoredSnapshotIfAvailable(
		mounted.before,
		after,
		snapshotErr,
	)
}

func validateReviewedMountTargetRestored(
	before isolatedReviewedMountTargetSnapshot,
	after isolatedReviewedMountTargetSnapshot,
) error {
	if before.target == "" || before.target != after.target {
		return fmt.Errorf("reviewed mount target path was not restored")
	}
	if before.device != after.device || before.inode != after.inode {
		return fmt.Errorf(
			"reviewed mount target %s filesystem identity was not restored",
			before.target,
		)
	}
	if len(before.chain) != len(after.chain) {
		return fmt.Errorf(
			"reviewed mount target %s ancestry length was not restored",
			before.target,
		)
	}
	for index := range before.chain {
		if !sameMountInfoEntry(before.chain[index], after.chain[index]) {
			return fmt.Errorf(
				"reviewed mount target %s ancestry changed at index %d",
				before.target,
				index,
			)
		}
	}
	return nil
}

func (fixture *isolatedReviewedMountLifecycleFixture) operations() isolatedReviewedMountLifecycleOperations {
	return isolatedReviewedMountLifecycleOperations{
		snapshotTarget: func() (isolatedReviewedMountTargetSnapshot, error) {
			fixture.snapshotCalls++
			if len(fixture.snapshotErrors) != 0 {
				err := fixture.snapshotErrors[0]
				fixture.snapshotErrors = fixture.snapshotErrors[1:]
				if err != nil {
					return isolatedReviewedMountTargetSnapshot{}, err
				}
			}
			_, present, err := reviewedMountAtTarget(
				fixture.stateEntries,
				fixture.target,
			)
			if err != nil {
				return isolatedReviewedMountTargetSnapshot{}, err
			}
			if present {
				return isolatedReviewedMountTargetSnapshot{}, fmt.Errorf(
					"fixture target remains mounted",
				)
			}
			after := fixture.before
			after.chain = append([]mountInfoEntry(nil), fixture.before.chain...)
			return after, nil
		},
		readMountInfo: func() ([]mountInfoEntry, error) {
			fixture.readCalls++
			if len(fixture.readErrors) != 0 {
				err := fixture.readErrors[0]
				fixture.readErrors = fixture.readErrors[1:]
				if err != nil {
					return nil, err
				}
			}
			return append([]mountInfoEntry(nil), fixture.stateEntries...), nil
		},
		readTargetIdentity: func() (isolatedMountNamespaceIdentity, error) {
			fixture.identityCalls++
			return fixture.currentIdentity, nil
		},
		runMount: func() error {
			fixture.mountCalls++
			if fixture.mountCommits {
				fixture.stateEntries = append(
					[]mountInfoEntry(nil),
					fixture.mountedEntries...,
				)
				fixture.currentIdentity = fixture.mountedIdentity
			}
			return fixture.mountErr
		},
		runUnmount: func() error {
			fixture.unmountCalls++
			if fixture.unmountCommits {
				fixture.stateEntries = append(
					[]mountInfoEntry(nil),
					fixture.restoredEntries...,
				)
				fixture.currentIdentity = fixture.beforeIdentity
			}
			return fixture.unmountErr
		},
	}
}

func newReviewedMountLifecycleFixture() *isolatedReviewedMountLifecycleFixture {
	target := "/tmp/reviewed-target"
	rootEntry := mountInfoEntry{
		mountID:        21,
		parentID:       1,
		device:         "8:1",
		root:           "/",
		mountPath:      "/",
		mountOptions:   []string{"relatime", "rw"},
		optionalFields: nil,
		fsType:         "ext4",
		source:         "/dev/root",
		superOptions:   []string{"rw"},
	}
	mountedEntry := mountInfoEntry{
		mountID:        42,
		parentID:       rootEntry.mountID,
		device:         "8:1",
		root:           "/tmp/reviewed-source",
		mountPath:      target,
		mountOptions:   []string{"relatime", "rw"},
		optionalFields: nil,
		fsType:         "ext4",
		source:         "/dev/root",
		superOptions:   []string{"rw"},
	}
	beforeIdentity := isolatedMountNamespaceIdentity{device: 10, inode: 20}
	return &isolatedReviewedMountLifecycleFixture{
		target: target,
		before: isolatedReviewedMountTargetSnapshot{
			target: target,
			device: beforeIdentity.device,
			inode:  beforeIdentity.inode,
			chain:  []mountInfoEntry{rootEntry},
		},
		restoredEntries: []mountInfoEntry{rootEntry},
		mountedEntries:  []mountInfoEntry{rootEntry, mountedEntry},
		stateEntries:    []mountInfoEntry{rootEntry},
		beforeIdentity:  beforeIdentity,
		mountedIdentity: isolatedMountNamespaceIdentity{device: 10, inode: 30},
		mountCommits:    true,
		unmountCommits:  true,
		currentIdentity: beforeIdentity,
	}
}

func TestPrivilegedMountLifecycleReconcilesAmbiguousResults(t *testing.T) {
	t.Run("mount error after commit is reconciled and unmounted once", func(t *testing.T) {
		fixture := newReviewedMountLifecycleFixture()
		fixture.mountErr = context.DeadlineExceeded
		mounted, err := mountReviewedTargetWithOperations(
			fixture.target,
			fixture.operations(),
		)
		if err == nil {
			t.Fatal("committed mount with command error unexpectedly succeeded")
		}
		if mounted != nil {
			t.Fatal("failed mount attempt unexpectedly returned an active guard")
		}
		if fixture.unmountCalls != 1 {
			t.Fatalf("unmount calls = %d, want 1", fixture.unmountCalls)
		}
		if _, present, stateErr := reviewedMountAtTarget(
			fixture.stateEntries,
			fixture.target,
		); stateErr != nil || present {
			t.Fatalf(
				"mount error cleanup state = present %t error %v",
				present,
				stateErr,
			)
		}
	})

	t.Run("post-mount read failure uses one exact fallback unmount", func(t *testing.T) {
		fixture := newReviewedMountLifecycleFixture()
		fixture.readErrors = []error{errors.New("injected post-mount read failure")}
		mounted, err := mountReviewedTargetWithOperations(
			fixture.target,
			fixture.operations(),
		)
		if err == nil {
			t.Fatal("post-mount read failure unexpectedly succeeded")
		}
		if mounted != nil {
			t.Fatal("ambiguous mount attempt unexpectedly returned an active guard")
		}
		if fixture.unmountCalls != 1 {
			t.Fatalf("unmount calls = %d, want 1", fixture.unmountCalls)
		}
		if fixture.snapshotCalls != 2 {
			t.Fatalf("snapshot calls = %d, want 2", fixture.snapshotCalls)
		}
	})

	t.Run("failed mount without commit restores without umount", func(t *testing.T) {
		fixture := newReviewedMountLifecycleFixture()
		fixture.mountCommits = false
		fixture.mountErr = errors.New("injected mount rejection")
		if mounted, err := mountReviewedTargetWithOperations(
			fixture.target,
			fixture.operations(),
		); err == nil || mounted != nil {
			t.Fatalf("failed uncommitted mount = guard %#v error %v", mounted, err)
		}
		if fixture.unmountCalls != 0 {
			t.Fatalf("unmount calls = %d, want 0", fixture.unmountCalls)
		}
		if fixture.snapshotCalls != 2 {
			t.Fatalf("snapshot calls = %d, want 2", fixture.snapshotCalls)
		}
	})

	t.Run("pre-unmount read failure does not consume command allowance", func(t *testing.T) {
		fixture := newReviewedMountLifecycleFixture()
		mounted, err := mountReviewedTargetWithOperations(
			fixture.target,
			fixture.operations(),
		)
		if err != nil {
			t.Fatalf("create reviewed mounted fixture: %v", err)
		}
		fixture.readErrors = []error{errors.New("injected pre-unmount read failure")}
		if err := mounted.unmountAndVerifyWithOperations(); err == nil {
			t.Fatal("pre-unmount read failure unexpectedly succeeded")
		}
		if mounted.unmountIssued {
			t.Fatal("preflight read failure consumed the unmount command allowance")
		}
		if fixture.unmountCalls != 0 {
			t.Fatalf("unmount calls = %d, want 0", fixture.unmountCalls)
		}
		if err := mounted.unmountAndVerifyWithOperations(); err != nil {
			t.Fatalf("retry preflight and exact unmount: %v", err)
		}
		if fixture.unmountCalls != 1 {
			t.Fatalf("unmount calls after recovery = %d, want 1", fixture.unmountCalls)
		}
	})

	t.Run("umount error after commit still verifies restoration", func(t *testing.T) {
		fixture := newReviewedMountLifecycleFixture()
		mounted, err := mountReviewedTargetWithOperations(
			fixture.target,
			fixture.operations(),
		)
		if err != nil {
			t.Fatalf("create reviewed mounted fixture: %v", err)
		}
		fixture.unmountErr = context.DeadlineExceeded
		if err := mounted.unmountAndVerifyWithOperations(); err == nil {
			t.Fatal("umount command error unexpectedly disappeared")
		}
		if mounted.active {
			t.Fatal("restored target remained marked active")
		}
		if fixture.unmountCalls != 1 || fixture.snapshotCalls != 2 {
			t.Fatalf(
				"umount calls = %d snapshots = %d, want 1 and 2",
				fixture.unmountCalls,
				fixture.snapshotCalls,
			)
		}
	})

	t.Run("umount error without commit is not retried", func(t *testing.T) {
		fixture := newReviewedMountLifecycleFixture()
		mounted, err := mountReviewedTargetWithOperations(
			fixture.target,
			fixture.operations(),
		)
		if err != nil {
			t.Fatalf("create reviewed mounted fixture: %v", err)
		}
		fixture.unmountCommits = false
		fixture.unmountErr = context.DeadlineExceeded
		if err := mounted.unmountAndVerifyWithOperations(); err == nil {
			t.Fatal("uncommitted umount error unexpectedly succeeded")
		}
		if !mounted.active || !mounted.unmountIssued {
			t.Fatalf(
				"uncommitted umount state = active %t issued %t",
				mounted.active,
				mounted.unmountIssued,
			)
		}
		if err := mounted.unmountAndVerifyWithOperations(); err == nil {
			t.Fatal("second umount attempt unexpectedly accepted")
		}
		if fixture.unmountCalls != 1 {
			t.Fatalf("unmount calls = %d, want exactly 1", fixture.unmountCalls)
		}
	})

	t.Run("post-umount read failure is reported without retry", func(t *testing.T) {
		fixture := newReviewedMountLifecycleFixture()
		mounted, err := mountReviewedTargetWithOperations(
			fixture.target,
			fixture.operations(),
		)
		if err != nil {
			t.Fatalf("create reviewed mounted fixture: %v", err)
		}
		fixture.readErrors = []error{
			nil,
			errors.New("injected post-umount read failure"),
		}
		if err := mounted.unmountAndVerifyWithOperations(); err == nil {
			t.Fatal("post-umount read failure unexpectedly succeeded")
		}
		if fixture.unmountCalls != 1 || !mounted.unmountIssued {
			t.Fatalf(
				"post-read failure unmount calls = %d issued = %t",
				fixture.unmountCalls,
				mounted.unmountIssued,
			)
		}
		if mounted.active {
			t.Fatal("fallback restored snapshot did not clear active mount state")
		}
		if fixture.snapshotCalls != 2 {
			t.Fatalf("snapshot calls = %d, want 2", fixture.snapshotCalls)
		}
		if err := mounted.unmountAndVerifyWithOperations(); err == nil {
			t.Fatal("post-read failure permitted a second umount")
		}
		if fixture.unmountCalls != 1 {
			t.Fatalf("unmount calls after retry = %d, want 1", fixture.unmountCalls)
		}
	})

	t.Run("post-umount snapshot failure is reported", func(t *testing.T) {
		fixture := newReviewedMountLifecycleFixture()
		mounted, err := mountReviewedTargetWithOperations(
			fixture.target,
			fixture.operations(),
		)
		if err != nil {
			t.Fatalf("create reviewed mounted fixture: %v", err)
		}
		fixture.snapshotErrors = []error{
			errors.New("injected restored snapshot failure"),
		}
		if err := mounted.unmountAndVerifyWithOperations(); err == nil {
			t.Fatal("restored snapshot failure unexpectedly succeeded")
		}
		if mounted.active {
			t.Fatal("absent mount remained marked active after snapshot failure")
		}
		if fixture.unmountCalls != 1 {
			t.Fatalf("unmount calls = %d, want 1", fixture.unmountCalls)
		}
	})
}

func TestReviewedPrivilegedCleanupPlanFailsClosed(t *testing.T) {
	runID := "run-subtree-0123456789"
	root := filepath.Join(isolatedPrivilegedTestPrefix, runID)
	owned := []isolatedReviewedOwnedPath{
		{
			path:   root,
			device: 10,
			inode:  20,
			uid:    0,
			mode:   os.ModeDir | 0o700,
		},
		{
			path: filepath.Join(
				root,
				isolatedPrivilegedOwnerMarker,
			),
			device: 10,
			inode:  21,
			uid:    0,
			mode:   0o600,
		},
		{
			path:   filepath.Join(root, "source"),
			device: 10,
			inode:  22,
			uid:    0,
			mode:   os.ModeDir | 0o700,
		},
		{
			path:   filepath.Join(root, "source", "isolated-root"),
			device: 10,
			inode:  23,
			uid:    0,
			mode:   os.ModeDir | 0o700,
		},
	}
	resources := &isolatedReviewedPrivilegedResources{
		root:  root,
		runID: runID,
		owned: append([]isolatedReviewedOwnedPath(nil), owned...),
	}
	observed := append([]isolatedReviewedOwnedPath(nil), owned...)
	if err := validateReviewedCleanupPlan(resources, observed); err != nil {
		t.Fatalf("valid reviewed cleanup plan: %v", err)
	}

	t.Run("root outside prefix", func(t *testing.T) {
		copy := *resources
		copy.root = "/tmp/unreviewed"
		if err := validateReviewedCleanupPlan(&copy, observed); err == nil {
			t.Fatal("cleanup root outside dedicated prefix unexpectedly accepted")
		}
	})
	t.Run("changed inode", func(t *testing.T) {
		copy := append([]isolatedReviewedOwnedPath(nil), observed...)
		copy[len(copy)-1].inode++
		if err := validateReviewedCleanupPlan(resources, copy); err == nil {
			t.Fatal("changed cleanup target identity unexpectedly accepted")
		}
	})
	t.Run("cross filesystem", func(t *testing.T) {
		copy := *resources
		copy.owned = append([]isolatedReviewedOwnedPath(nil), resources.owned...)
		copy.owned[len(copy.owned)-1].device++
		if err := validateReviewedCleanupPlan(&copy, observed); err == nil {
			t.Fatal("cross-filesystem cleanup target unexpectedly accepted")
		}
	})
	t.Run("non-root owner", func(t *testing.T) {
		copy := *resources
		copy.owned = append([]isolatedReviewedOwnedPath(nil), resources.owned...)
		copy.owned[len(copy.owned)-1].uid = 1
		if err := validateReviewedCleanupPlan(&copy, observed); err == nil {
			t.Fatal("non-root-owned cleanup target unexpectedly accepted")
		}
	})
	t.Run("unknown observed path", func(t *testing.T) {
		copy := append([]isolatedReviewedOwnedPath(nil), observed...)
		copy[len(copy)-1].path = filepath.Join(root, "unknown")
		if err := validateReviewedCleanupPlan(resources, copy); err == nil {
			t.Fatal("unknown cleanup path unexpectedly accepted")
		}
	})
	t.Run("missing marker", func(t *testing.T) {
		copy := *resources
		copy.owned = append(
			[]isolatedReviewedOwnedPath{resources.owned[0]},
			resources.owned[2:]...,
		)
		if err := validateReviewedCleanupPlan(&copy, copy.owned); err == nil {
			t.Fatal("cleanup plan without owner marker unexpectedly accepted")
		}
	})
	t.Run("parent recorded after child", func(t *testing.T) {
		copy := *resources
		copy.owned = []isolatedReviewedOwnedPath{
			owned[0],
			owned[1],
			owned[3],
			owned[2],
		}
		if err := validateReviewedCleanupPlan(&copy, copy.owned); err == nil {
			t.Fatal("unsafe cleanup order unexpectedly accepted")
		}
	})
}

func TestReviewedFilesystemWriteAuditFailsClosed(t *testing.T) {
	target := filepath.Join(
		isolatedPrivilegedTestPrefix,
		"run-subtree-0123456789",
	)
	if err := validateReviewedFilesystemWrite(
		"create-unique-test-root",
		target,
	); err != nil {
		t.Fatalf("valid reviewed filesystem write: %v", err)
	}
	for name, testCase := range map[string]struct {
		operation string
		target    string
	}{
		"unknown operation": {
			operation: "remove-recursively",
			target:    target,
		},
		"relative target": {
			operation: "create-owned-directory",
			target:    "relative",
		},
		"root target": {
			operation: "create-owned-directory",
			target:    "/",
		},
		"outside prefix": {
			operation: "create-owned-directory",
			target:    "/tmp/unreviewed",
		},
		"noncanonical": {
			operation: "create-owned-directory",
			target: filepath.Join(
				isolatedPrivilegedTestPrefix,
				"run",
			) + "/../other",
		},
	} {
		t.Run("write "+name, func(t *testing.T) {
			if err := validateReviewedFilesystemWrite(
				testCase.operation,
				testCase.target,
			); err == nil {
				t.Fatal("unsafe reviewed filesystem write unexpectedly accepted")
			}
		})
	}

	timestamp := time.Date(2026, 7, 29, 2, 3, 4, 5, time.UTC)
	validAudit := isolatedReviewedFilesystemWriteAudit{
		Format:    isolatedPrivilegedWriteFormat,
		Timestamp: timestamp.Format(time.RFC3339Nano),
		Operation: "create-owned-directory",
		Target:    target,
		ExitCode:  0,
	}
	if err := validateReviewedFilesystemWriteAudit(
		validAudit,
		validAudit.Operation,
		validAudit.Target,
		0,
	); err != nil {
		t.Fatalf("valid reviewed filesystem write audit: %v", err)
	}
	mutations := map[string]func(
		isolatedReviewedFilesystemWriteAudit,
	) isolatedReviewedFilesystemWriteAudit{
		"format": func(
			copy isolatedReviewedFilesystemWriteAudit,
		) isolatedReviewedFilesystemWriteAudit {
			copy.Format = "wrong"
			return copy
		},
		"timestamp": func(
			copy isolatedReviewedFilesystemWriteAudit,
		) isolatedReviewedFilesystemWriteAudit {
			copy.Timestamp = "invalid"
			return copy
		},
		"operation": func(
			copy isolatedReviewedFilesystemWriteAudit,
		) isolatedReviewedFilesystemWriteAudit {
			copy.Operation = "create-owner-marker"
			return copy
		},
		"target": func(
			copy isolatedReviewedFilesystemWriteAudit,
		) isolatedReviewedFilesystemWriteAudit {
			copy.Target = filepath.Join(target, "other")
			return copy
		},
		"exit code": func(
			copy isolatedReviewedFilesystemWriteAudit,
		) isolatedReviewedFilesystemWriteAudit {
			copy.ExitCode = 1
			return copy
		},
	}
	for name, mutate := range mutations {
		t.Run("audit "+name, func(t *testing.T) {
			if err := validateReviewedFilesystemWriteAudit(
				mutate(validAudit),
				validAudit.Operation,
				validAudit.Target,
				0,
			); err == nil {
				t.Fatal("inexact filesystem write audit unexpectedly accepted")
			}
		})
	}
}

func TestPrivilegedMountHarnessValidationFailsClosed(t *testing.T) {
	validEnvironment := []string{
		isolatedPrivilegedMountTestGate + "=1",
		isolatedPrivilegedMountTestHelper + "=1",
		isolatedPrivilegedMountHelperFD + "=" +
			strconv.Itoa(isolatedPrivilegedLaunchFD),
	}
	if fd, err := validatePrivilegedMountHelperEnvironment(validEnvironment); err != nil {
		t.Fatalf("valid privileged helper environment: %v", err)
	} else if fd != isolatedPrivilegedLaunchFD {
		t.Fatalf("validated launch fd = %d, want %d", fd, isolatedPrivilegedLaunchFD)
	}
	invalidEnvironments := map[string][]string{
		"old two-variable gate": {
			isolatedPrivilegedMountTestGate + "=1",
			isolatedPrivilegedMountTestHelper + "=1",
		},
		"inherited PATH": append(
			append([]string(nil), validEnvironment...),
			"PATH=/usr/bin",
		),
		"duplicate gate": append(
			append([]string(nil), validEnvironment...),
			isolatedPrivilegedMountTestGate+"=1",
		),
		"wrong launch fd": {
			isolatedPrivilegedMountTestGate + "=1",
			isolatedPrivilegedMountTestHelper + "=1",
			isolatedPrivilegedMountHelperFD + "=9",
		},
		"unknown key": {
			isolatedPrivilegedMountTestGate + "=1",
			isolatedPrivilegedMountTestHelper + "=1",
			"UNREVIEWED=1",
		},
		"malformed": {"not-an-assignment"},
	}
	for name, environment := range invalidEnvironments {
		t.Run("environment "+name, func(t *testing.T) {
			if _, err := validatePrivilegedMountHelperEnvironment(environment); err == nil {
				t.Fatal("unsafe privileged helper environment unexpectedly accepted")
			}
		})
	}
	validArguments := []string{
		fmt.Sprintf("/proc/self/fd/%d", isolatedPrivilegedExecutableFD),
		"-test.run=^TestPrivateBPFFSMountRejectsRealLinuxRunSubtreeBinds$",
		"-test.count=1",
	}
	if err := validatePrivilegedMountHelperArguments(validArguments); err != nil {
		t.Fatalf("valid privileged helper arguments: %v", err)
	}
	for name, arguments := range map[string][]string{
		"relative executable": {
			"isolated_netns.test",
			validArguments[1],
			validArguments[2],
		},
		"extra argument": append(
			append([]string(nil), validArguments...),
			"-test.v",
		),
		"wrong test": {
			validArguments[0],
			"-test.run=.",
			validArguments[2],
		},
	} {
		t.Run("arguments "+name, func(t *testing.T) {
			if err := validatePrivilegedMountHelperArguments(arguments); err == nil {
				t.Fatal("unsafe privileged helper arguments unexpectedly accepted")
			}
		})
	}

	record := isolatedPrivilegedLaunchRecord{
		Format:          isolatedPrivilegedLaunchFormat,
		OuterPID:        4242,
		OuterMountDev:   10,
		OuterMountInode: 20,
		ExecutableDev:   30,
		ExecutableInode: 40,
	}
	currentNamespace := isolatedMountNamespaceIdentity{device: 10, inode: 30}
	initialNamespace := isolatedMountNamespaceIdentity{device: 10, inode: 10}
	parentNamespace := isolatedMountNamespaceIdentity{device: 10, inode: 20}
	if err := validatePrivilegedLaunchContext(
		record,
		4242,
		currentNamespace,
		initialNamespace,
		parentNamespace,
	); err != nil {
		t.Fatalf("valid privileged launch context: %v", err)
	}
	namespaceCases := []struct {
		name    string
		record  isolatedPrivilegedLaunchRecord
		pid     int
		current isolatedMountNamespaceIdentity
		initial isolatedMountNamespaceIdentity
		parent  isolatedMountNamespaceIdentity
	}{
		{
			name: "wrong format",
			record: func() isolatedPrivilegedLaunchRecord {
				copy := record
				copy.Format = "wrong"
				return copy
			}(),
			pid:     4242,
			current: currentNamespace,
			initial: initialNamespace,
			parent:  parentNamespace,
		},
		{
			name:    "wrong parent pid",
			record:  record,
			pid:     4243,
			current: currentNamespace,
			initial: initialNamespace,
			parent:  parentNamespace,
		},
		{
			name:    "outer namespace mismatch",
			record:  record,
			pid:     4242,
			current: currentNamespace,
			initial: initialNamespace,
			parent:  isolatedMountNamespaceIdentity{device: 10, inode: 21},
		},
		{
			name:    "same as parent namespace",
			record:  record,
			pid:     4242,
			current: parentNamespace,
			initial: initialNamespace,
			parent:  parentNamespace,
		},
		{
			name:    "same as initial namespace",
			record:  record,
			pid:     4242,
			current: initialNamespace,
			initial: initialNamespace,
			parent:  parentNamespace,
		},
	}
	for _, testCase := range namespaceCases {
		t.Run("namespace "+testCase.name, func(t *testing.T) {
			if err := validatePrivilegedLaunchContext(
				testCase.record,
				testCase.pid,
				testCase.current,
				testCase.initial,
				testCase.parent,
			); err == nil {
				t.Fatal("unsafe privileged launch context unexpectedly accepted")
			}
		})
	}

	executableIdentity := isolatedMountNamespaceIdentity{device: 30, inode: 40}
	if err := validatePrivilegedExecutableContext(
		record,
		executableIdentity,
		executableIdentity,
	); err != nil {
		t.Fatalf("valid privileged executable identity: %v", err)
	}
	for name, identities := range map[string][2]isolatedMountNamespaceIdentity{
		"opened fd mismatch": {
			{device: 30, inode: 41},
			executableIdentity,
		},
		"current executable mismatch": {
			executableIdentity,
			{device: 30, inode: 41},
		},
	} {
		t.Run("executable "+name, func(t *testing.T) {
			if err := validatePrivilegedExecutableContext(
				record,
				identities[0],
				identities[1],
			); err == nil {
				t.Fatal("mismatched executable identity unexpectedly accepted")
			}
		})
	}

	validToolMetadata := isolatedReviewedToolMetadata{
		mode:  0o755,
		uid:   0,
		nlink: 1,
	}
	if err := validateReviewedToolMetadata(
		isolatedReviewedMountPath,
		validToolMetadata,
	); err != nil {
		t.Fatalf("valid reviewed tool metadata: %v", err)
	}
	toolCases := []struct {
		name     string
		path     string
		metadata isolatedReviewedToolMetadata
	}{
		{name: "relative", path: "usr/bin/mount", metadata: validToolMetadata},
		{name: "unapproved", path: "/bin/echo", metadata: validToolMetadata},
		{
			name: "symlink",
			path: isolatedReviewedMountPath,
			metadata: isolatedReviewedToolMetadata{
				mode: os.ModeSymlink | 0o777, uid: 0, nlink: 1,
			},
		},
		{
			name: "directory",
			path: isolatedReviewedMountPath,
			metadata: isolatedReviewedToolMetadata{
				mode: os.ModeDir | 0o755, uid: 0, nlink: 1,
			},
		},
		{
			name: "group writable",
			path: isolatedReviewedMountPath,
			metadata: isolatedReviewedToolMetadata{
				mode: 0o775, uid: 0, nlink: 1,
			},
		},
		{
			name: "non-root owner",
			path: isolatedReviewedMountPath,
			metadata: isolatedReviewedToolMetadata{
				mode: 0o755, uid: 1, nlink: 1,
			},
		},
		{
			name: "non-executable",
			path: isolatedReviewedMountPath,
			metadata: isolatedReviewedToolMetadata{
				mode: 0o644, uid: 0, nlink: 1,
			},
		},
		{
			name: "zero links",
			path: isolatedReviewedMountPath,
			metadata: isolatedReviewedToolMetadata{
				mode: 0o755, uid: 0, nlink: 0,
			},
		},
	}
	for _, testCase := range toolCases {
		t.Run("tool "+testCase.name, func(t *testing.T) {
			if err := validateReviewedToolMetadata(
				testCase.path,
				testCase.metadata,
			); err == nil {
				t.Fatal("unsafe reviewed tool metadata unexpectedly accepted")
			}
		})
	}

	privateFixture := "" +
		"21 1 8:1 / / rw,relatime - ext4 /dev/root rw\n" +
		"31 21 0:31 / /tmp rw,relatime - tmpfs tmpfs rw\n"
	privateEntries, err := parseMountInfo([]byte(privateFixture))
	if err != nil {
		t.Fatalf("parse private propagation fixture: %v", err)
	}
	if err := validatePrivateMountInfoForPaths(
		privateEntries,
		"/",
		"/tmp/reviewed",
	); err != nil {
		t.Fatalf("valid private mount chains: %v", err)
	}
	if !mountPathContainsPath("/", "/tmp/reviewed") {
		t.Fatal("namespace root did not contain an absolute path")
	}
	propagationFixtures := map[string]string{
		"shared root": strings.Replace(
			privateFixture,
			"/ / rw,relatime -",
			"/ / rw,relatime shared:7 -",
			1,
		),
		"master intermediate": strings.Replace(
			privateFixture,
			"/ /tmp rw,relatime -",
			"/ /tmp rw,relatime master:8 -",
			1,
		),
		"propagate-from intermediate": strings.Replace(
			privateFixture,
			"/ /tmp rw,relatime -",
			"/ /tmp rw,relatime propagate_from:9 -",
			1,
		),
	}
	for name, fixture := range propagationFixtures {
		t.Run("propagation "+name, func(t *testing.T) {
			entries, err := parseMountInfo([]byte(fixture))
			if err != nil {
				t.Fatalf("parse propagation fixture: %v", err)
			}
			if err := validatePrivateMountInfoForPaths(
				entries,
				"/",
				"/tmp/reviewed",
			); err == nil {
				t.Fatal("propagating mount chain unexpectedly accepted")
			}
		})
	}

	mountSpec := isolatedReviewedCommandSpec{
		tool: isolatedReviewedMountPath,
		args: []string{
			"--bind",
			"--",
			"/tmp/reviewed-source",
			"/tmp/reviewed-target",
		},
		target:  "/tmp/reviewed-target",
		env:     make([]string, 0),
		timeout: 10 * time.Second,
	}
	if err := validateReviewedCommandSpec(mountSpec); err != nil {
		t.Fatalf("valid reviewed mount spec: %v", err)
	}
	inheritedEnvironmentSpec := mountSpec
	inheritedEnvironmentSpec.env = []string{"PATH=/usr/bin"}
	if err := validateReviewedCommandSpec(inheritedEnvironmentSpec); err == nil {
		t.Fatal("reviewed mount spec with inherited environment unexpectedly accepted")
	}
	nilEnvironmentSpec := mountSpec
	nilEnvironmentSpec.env = nil
	if err := validateReviewedCommandSpec(nilEnvironmentSpec); err == nil {
		t.Fatal("reviewed mount spec with nil environment unexpectedly accepted")
	}
	unshareSpec := isolatedReviewedCommandSpec{
		tool: isolatedReviewedUnsharePath,
		args: []string{
			"--mount",
			"--propagation",
			"private",
			fmt.Sprintf("/proc/self/fd/%d", isolatedPrivilegedExecutableFD),
			"-test.run=^TestPrivateBPFFSMountRejectsRealLinuxRunSubtreeBinds$",
			"-test.count=1",
		},
		target:     "new-private-mount-namespace",
		env:        append([]string(nil), validEnvironment...),
		extraFiles: []*os.File{new(os.File), new(os.File)},
		timeout:    60 * time.Second,
	}
	if err := validateReviewedCommandSpec(unshareSpec); err != nil {
		t.Fatalf("valid reviewed unshare spec: %v", err)
	}

	auditSpec := isolatedReviewedCommandSpec{
		tool:    isolatedReviewedUmountPath,
		args:    []string{"--", "/tmp/reviewed-target"},
		target:  "/tmp/reviewed-target",
		env:     make([]string, 0),
		timeout: 10 * time.Second,
	}
	started := time.Date(2026, 7, 29, 1, 2, 3, 4, time.UTC)
	validAudit := isolatedPrivilegedCommandAudit{
		Format:     isolatedPrivilegedAuditFormat,
		StartedAt:  started.Format(time.RFC3339Nano),
		FinishedAt: started.Add(time.Second).Format(time.RFC3339Nano),
		Tool:       auditSpec.tool,
		Argv:       append([]string{auditSpec.tool}, auditSpec.args...),
		Target:     auditSpec.target,
		ExitCode:   0,
	}
	if err := validatePrivilegedCommandAudit(validAudit, auditSpec, 0); err != nil {
		t.Fatalf("valid reviewed command audit: %v", err)
	}
	auditMutations := map[string]func(isolatedPrivilegedCommandAudit) isolatedPrivilegedCommandAudit{
		"format": func(copy isolatedPrivilegedCommandAudit) isolatedPrivilegedCommandAudit {
			copy.Format = "wrong"
			return copy
		},
		"start timestamp": func(copy isolatedPrivilegedCommandAudit) isolatedPrivilegedCommandAudit {
			copy.StartedAt = "not-a-timestamp"
			return copy
		},
		"timestamp order": func(copy isolatedPrivilegedCommandAudit) isolatedPrivilegedCommandAudit {
			copy.FinishedAt = started.Add(-time.Second).Format(time.RFC3339Nano)
			return copy
		},
		"tool": func(copy isolatedPrivilegedCommandAudit) isolatedPrivilegedCommandAudit {
			copy.Tool = isolatedReviewedMountPath
			return copy
		},
		"argv": func(copy isolatedPrivilegedCommandAudit) isolatedPrivilegedCommandAudit {
			copy.Argv = append([]string(nil), copy.Argv...)
			copy.Argv[len(copy.Argv)-1] = "/tmp/other"
			return copy
		},
		"target": func(copy isolatedPrivilegedCommandAudit) isolatedPrivilegedCommandAudit {
			copy.Target = "/tmp/other"
			return copy
		},
		"exit code": func(copy isolatedPrivilegedCommandAudit) isolatedPrivilegedCommandAudit {
			copy.ExitCode = 1
			return copy
		},
	}
	for name, mutate := range auditMutations {
		t.Run("audit "+name, func(t *testing.T) {
			if err := validatePrivilegedCommandAudit(
				mutate(validAudit),
				auditSpec,
				0,
			); err == nil {
				t.Fatal("inexact reviewed command audit unexpectedly accepted")
			}
		})
	}

	rootEntry := mountInfoEntry{
		mountID:        21,
		parentID:       1,
		device:         "8:1",
		root:           "/",
		mountPath:      "/",
		mountOptions:   []string{"relatime", "rw"},
		optionalFields: nil,
		fsType:         "ext4",
		source:         "/dev/root",
		superOptions:   []string{"rw"},
	}
	before := isolatedReviewedMountTargetSnapshot{
		target: "/tmp/reviewed-target",
		device: 10,
		inode:  20,
		chain:  []mountInfoEntry{rootEntry},
	}
	after := before
	after.chain = append([]mountInfoEntry(nil), before.chain...)
	if err := validateReviewedMountTargetRestored(before, after); err != nil {
		t.Fatalf("valid restored target snapshot: %v", err)
	}
	restorationMutations := map[string]func(isolatedReviewedMountTargetSnapshot) isolatedReviewedMountTargetSnapshot{
		"inode": func(copy isolatedReviewedMountTargetSnapshot) isolatedReviewedMountTargetSnapshot {
			copy.inode++
			return copy
		},
		"target": func(copy isolatedReviewedMountTargetSnapshot) isolatedReviewedMountTargetSnapshot {
			copy.target = "/tmp/other"
			return copy
		},
		"chain length": func(copy isolatedReviewedMountTargetSnapshot) isolatedReviewedMountTargetSnapshot {
			copy.chain = append(copy.chain, rootEntry)
			return copy
		},
		"propagation": func(copy isolatedReviewedMountTargetSnapshot) isolatedReviewedMountTargetSnapshot {
			copy.chain = append([]mountInfoEntry(nil), copy.chain...)
			copy.chain[0].optionalFields = []string{"shared:7"}
			return copy
		},
	}
	for name, mutate := range restorationMutations {
		t.Run("restoration "+name, func(t *testing.T) {
			if err := validateReviewedMountTargetRestored(
				before,
				mutate(after),
			); err == nil {
				t.Fatal("changed restored target snapshot unexpectedly accepted")
			}
		})
	}
}

func TestMountInfoEscapesAndStructuralConflicts(t *testing.T) {
	escaped, err := parseMountInfo([]byte(
		"42 21 0:42 /root\\040dir /target\\040dir rw,nosuid,nodev,noexec,relatime - bpf source\\134name rw\n",
	))
	if err != nil {
		t.Fatalf("parse escaped mountinfo: %v", err)
	}
	if len(escaped) != 1 ||
		escaped[0].root != "/root dir" ||
		escaped[0].mountPath != "/target dir" ||
		escaped[0].source != "source\\name" {
		t.Fatalf("unexpected escaped mountinfo: %#v", escaped)
	}

	invalid := []string{
		"42 21 0:42 / /target rw,rw - bpf bpf rw\n",
		"42 21 0:42 / /target rw shared:7 shared:7 - bpf bpf rw\n",
		"42 21 0:42 / /target rw shared:7 shared:8 - bpf bpf rw\n",
		"42 21 00:42 / /target rw - bpf bpf rw\n",
		"42 21 0:042 / /target rw - bpf bpf rw\n",
		"42 21 0:42 / /target rw - bpf bpf rw unexpected\n",
		"42 21 0:42 / /target rw - bpf bpf\n",
	}
	for _, fixture := range invalid {
		if _, err := parseMountInfo([]byte(fixture)); err == nil {
			t.Fatalf("conflicting mountinfo unexpectedly accepted: %q", fixture)
		}
	}
}

func TestPrivateBPFFSMountSnapshotDetectsRemountOptionDrift(t *testing.T) {
	layout, _, _, _, _ := isolatedFixtureLayout(t, "a")
	before, err := parseMountInfo([]byte(
		isolatedMountInfoFixture(layout, "0:42", "/", "bpf", ""),
	))
	if err != nil {
		t.Fatal(err)
	}
	reorderedFixture := isolatedMountInfoFixtureWithTargetOptions(
		layout,
		"noexec,relatime,nodev,rw,nosuid",
		"",
		"rw",
	)
	reordered, err := parseMountInfo([]byte(reorderedFixture))
	if err != nil {
		t.Fatal(err)
	}
	afterFixture := isolatedMountInfoFixtureWithTargetOptions(
		layout,
		"rw,nosuid,nodev,noexec,noatime",
		"",
		"rw",
	)
	after, err := parseMountInfo([]byte(afterFixture))
	if err != nil {
		t.Fatal(err)
	}
	var beforeTarget, reorderedTarget, afterTarget mountInfoEntry
	for _, entry := range before {
		if entry.mountPath == layout.bpffsDir {
			beforeTarget = entry
		}
	}
	for _, entry := range reordered {
		if entry.mountPath == layout.bpffsDir {
			reorderedTarget = entry
		}
	}
	for _, entry := range after {
		if entry.mountPath == layout.bpffsDir {
			afterTarget = entry
		}
	}
	if !sameMountInfoEntry(beforeTarget, reorderedTarget) {
		t.Fatal("equivalent reordered mount options changed the normalized snapshot")
	}
	if sameMountInfoEntry(beforeTarget, afterTarget) {
		t.Fatal("remount option drift was not detected")
	}
}

func TestPrivateBPFFSMountSnapshotDetectsAncestorDrift(t *testing.T) {
	layout, _, _, _, _ := isolatedFixtureLayout(t, "a")
	source := isolatedNetNSTestBPFFSSource(layout.runID, isolatedFixtureOwnerToken)
	fixture := func(ancestorDevice string, ancestorOptions string) string {
		return fmt.Sprintf(
			"21 1 8:1 / / rw,relatime - ext4 /dev/root rw\n"+
				"41 21 %s / %s %s - tmpfs tmpfs rw\n"+
				"42 41 0:42 / %s rw,nosuid,nodev,noexec,relatime - bpf %s rw\n",
			ancestorDevice,
			"/run",
			ancestorOptions,
			layout.bpffsDir,
			source,
		)
	}
	beforeEntries, err := parseMountInfo([]byte(fixture("0:41", "rw,relatime")))
	if err != nil {
		t.Fatal(err)
	}
	before, err := privateBPFFSMountChain(beforeEntries, layout)
	if err != nil {
		t.Fatal(err)
	}
	reorderedEntries, err := parseMountInfo([]byte(
		fixture("0:41", "relatime,rw"),
	))
	if err != nil {
		t.Fatal(err)
	}
	reordered, err := privateBPFFSMountChain(reorderedEntries, layout)
	if err != nil {
		t.Fatal(err)
	}
	if !sameMountInfoChain(before, reordered) {
		t.Fatal("equivalent reordered ancestor options changed normalized chain snapshot")
	}
	driftedEntries, err := parseMountInfo([]byte(fixture("0:99", "rw,relatime")))
	if err != nil {
		t.Fatal(err)
	}
	drifted, err := privateBPFFSMountChain(driftedEntries, layout)
	if err != nil {
		t.Fatal(err)
	}
	if sameMountInfoChain(before, drifted) {
		t.Fatal("ancestor identity drift was not detected by full-chain snapshot")
	}
}

func TestRelevantMountSnapshotDetectsSecurityDriftOnly(t *testing.T) {
	layout, _, _, _, _ := isolatedFixtureLayout(t, "a")
	beforeEntries, err := parseMountInfo([]byte(
		isolatedMountInfoFixture(layout, "0:42", "/", "bpf", ""),
	))
	if err != nil {
		t.Fatal(err)
	}
	beforeChain, err := privateBPFFSMountChain(beforeEntries, layout)
	if err != nil {
		t.Fatal(err)
	}
	before := snapshotIsolatedNetNSTestRelevantMounts(
		beforeEntries,
		beforeChain,
		layout,
	)

	unrelatedEntries, err := parseMountInfo([]byte(
		isolatedMountInfoFixture(
			layout,
			"0:42",
			"/",
			"bpf",
			"70 21 8:70 / /mnt/unrelated rw,relatime - ext4 /dev/unrelated rw\n",
		),
	))
	if err != nil {
		t.Fatal(err)
	}
	unrelatedChain, err := privateBPFFSMountChain(unrelatedEntries, layout)
	if err != nil {
		t.Fatal(err)
	}
	unrelated := snapshotIsolatedNetNSTestRelevantMounts(
		unrelatedEntries,
		unrelatedChain,
		layout,
	)
	if !sameRelevantMountSnapshot(before, unrelated) {
		t.Fatal("unrelated namespace mount drift changed security snapshot")
	}

	otherBPFDriftData := strings.Replace(
		isolatedMountInfoFixture(layout, "0:42", "/", "bpf", ""),
		"- bpf bpf rw\n",
		"- bpf changed-source rw\n",
		1,
	)
	otherBPFEntries, err := parseMountInfo([]byte(otherBPFDriftData))
	if err != nil {
		t.Fatal(err)
	}
	otherBPFChain, err := privateBPFFSMountChain(otherBPFEntries, layout)
	if err != nil {
		t.Fatal(err)
	}
	otherBPFDrift := snapshotIsolatedNetNSTestRelevantMounts(
		otherBPFEntries,
		otherBPFChain,
		layout,
	)
	if sameRelevantMountSnapshot(before, otherBPFDrift) {
		t.Fatal("full-entry drift on another BPF mount was not detected")
	}

	childMountData := isolatedMountInfoFixture(
		layout,
		"0:42",
		"/",
		"bpf",
		fmt.Sprintf(
			"71 21 8:71 /outside/state %s rw,relatime - ext4 /dev/other rw\n",
			filepath.Join(layout.runBase, "state-a"),
		),
	)
	childMountEntries, err := parseMountInfo([]byte(childMountData))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := privateBPFFSMountChain(childMountEntries, layout); err == nil {
		t.Fatal("post-lock protected child mount drift unexpectedly accepted")
	}
	childMountDrift := snapshotIsolatedNetNSTestRelevantMounts(
		childMountEntries,
		beforeChain,
		layout,
	)
	if sameRelevantMountSnapshot(before, childMountDrift) {
		t.Fatal("post-lock runBase mount drift was not detected")
	}
}

func TestProtectedContractPathsUseTrustedContainingMount(t *testing.T) {
	layout, _, _, _, _ := isolatedFixtureLayout(t, "a")
	manifest, err := parseIsolatedNetNSTestManifest(isolatedFixtureManifest(layout))
	if err != nil {
		t.Fatal(err)
	}
	paths := isolatedNetNSTestProtectedPaths(manifest, layout)
	required := []string{
		isolatedNetNSTestRoot,
		layout.runBase,
		layout.manifest,
		layout.ledger,
		layout.lease,
		manifest.values["config_a"],
		manifest.values["wg_config_b"],
		manifest.values["run_dir_a"],
		manifest.values["state_dir_b"],
		manifest.values["evidence"],
		manifest.values["secrets"],
		manifest.values["pin_lock_root"],
		manifest.values["pin_owner_root"],
		filepath.Join(layout.runBase, isolatedNetNSOwnerMarker),
	}
	pathSet := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		pathSet[path] = struct{}{}
	}
	for _, path := range required {
		if _, ok := pathSet[path]; !ok {
			t.Fatalf("protected contract path is absent: %s", path)
		}
	}
	trustedParent := mountInfoEntry{mountID: 21, device: "8:1"}
	mounts := make(map[string]isolatedNetNSTestMountIdentity, len(paths))
	for _, path := range paths {
		mounts[path] = isolatedNetNSTestMountIdentity{
			mountID: trustedParent.mountID,
			device:  trustedParent.device,
		}
	}
	if err := validateIsolatedNetNSTestProtectedMounts(
		mounts,
		trustedParent,
	); err != nil {
		t.Fatalf("validate protected mount identities: %v", err)
	}
	for _, mismatch := range []isolatedNetNSTestMountIdentity{
		{mountID: 22, device: trustedParent.device},
		{mountID: trustedParent.mountID, device: "8:2"},
	} {
		mounts[manifest.values["config_a"]] = mismatch
		if err := validateIsolatedNetNSTestProtectedMounts(
			mounts,
			trustedParent,
		); err == nil {
			t.Fatal("foreign protected path mount identity unexpectedly accepted")
		}
	}
}

func TestParseAndValidateIsolatedBPFFSCreationLedger(t *testing.T) {
	layout, _, _, _, _ := isolatedFixtureLayout(t, "a")
	manifest, err := parseIsolatedNetNSTestManifest(isolatedFixtureManifest(layout))
	if err != nil {
		t.Fatal(err)
	}
	entries, err := parseMountInfo([]byte(
		isolatedMountInfoFixture(layout, "0:42", "/", "bpf", ""),
	))
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePrivateBPFFSMountInfo(
		entries,
		layout,
		manifest,
		42,
		nil,
	); err != nil {
		t.Fatalf("validate mount fixture: %v", err)
	}
	chain, err := privateBPFFSMountChain(entries, layout)
	if err != nil {
		t.Fatal(err)
	}
	validData := isolatedBPFFSLedgerFixture(
		layout,
		"21",
		"8:1",
		"30@0:30",
		"42",
		"0:42",
		"201",
	)
	ledger, err := parseIsolatedNetNSTestBPFFSLedger(validData)
	if err != nil {
		t.Fatalf("parse valid creation ledger: %v", err)
	}
	if err := validateIsolatedNetNSTestBPFFSLedger(
		ledger,
		entries,
		chain,
		layout,
		manifest,
		"0:42",
		201,
	); err != nil {
		t.Fatalf("validate creation ledger: %v", err)
	}
	for _, removedInodeValue := range []string{"1", "999999999999"} {
		withRemovedFieldRestored := strings.Replace(
			string(validData),
			"pre_bpf_mounts=",
			"pre_target_ino="+removedInodeValue+"\npre_bpf_mounts=",
			1,
		)
		if _, err := parseIsolatedNetNSTestBPFFSLedger(
			[]byte(withRemovedFieldRestored),
		); err == nil {
			t.Fatalf(
				"removed pre_target_ino field %q unexpectedly accepted",
				removedInodeValue,
			)
		}
	}

	type ledgerMutation struct {
		old string
		new string
	}
	tests := map[string]ledgerMutation{
		"run id mismatch": {
			old: "run_id=" + layout.runID,
			new: "run_id=ffffffffffffffff",
		},
		"owner token mismatch": {
			old: "owner_token=" + isolatedFixtureOwnerToken,
			new: "owner_token=ffffffffffffffffffffffffffffffff",
		},
		"target mismatch": {
			old: "target=" + layout.bpffsDir,
			new: "target=" + filepath.Join(layout.runBase, "other-bpffs"),
		},
		"source mismatch": {
			old: "source=" + isolatedNetNSTestBPFFSSource(
				layout.runID,
				isolatedFixtureOwnerToken,
			),
			new: "source=wg-mix-ebpf-foreign",
		},
		"pre target mount mismatch": {
			old: "pre_target_mount_id=21",
			new: "pre_target_mount_id=20",
		},
		"pre target device mismatch": {
			old: "pre_target_dev=8:1",
			new: "pre_target_dev=8:2",
		},
		"post mount mismatch": {
			old: "post_mount_id=42",
			new: "post_mount_id=43",
		},
		"post device mismatch": {
			old: "post_dev=0:42",
			new: "post_dev=0:43",
		},
		"post inode mismatch": {
			old: "post_ino=201",
			new: "post_ino=202",
		},
		"missing visible baseline mount": {
			old: "pre_bpf_mounts=30@0:30",
			new: "pre_bpf_mounts=none",
		},
		"post mount id in baseline": {
			old: "pre_bpf_mounts=30@0:30",
			new: "pre_bpf_mounts=30@0:30,42@0:99",
		},
		"post device in baseline": {
			old: "pre_bpf_mounts=30@0:30",
			new: "pre_bpf_mounts=30@0:30,41@0:42",
		},
	}
	for name, mutation := range tests {
		t.Run(name, func(t *testing.T) {
			mutated := strings.Replace(string(validData), mutation.old, mutation.new, 1)
			if mutated == string(validData) {
				t.Fatalf("mutation source %q was absent", mutation.old)
			}
			candidate, err := parseIsolatedNetNSTestBPFFSLedger([]byte(mutated))
			if err != nil {
				t.Fatalf("parse structurally valid negative ledger: %v", err)
			}
			if err := validateIsolatedNetNSTestBPFFSLedger(
				candidate,
				entries,
				chain,
				layout,
				manifest,
				"0:42",
				201,
			); err == nil {
				t.Fatal("mismatched creation ledger unexpectedly accepted")
			}
		})
	}

	t.Run("manifest mount mismatch", func(t *testing.T) {
		candidateManifest, err := parseIsolatedNetNSTestManifest(
			isolatedFixtureManifest(layout),
		)
		if err != nil {
			t.Fatal(err)
		}
		candidateManifest.values["bpffs_mount_id"] = "43"
		if err := validateIsolatedNetNSTestBPFFSLedger(
			ledger,
			entries,
			chain,
			layout,
			candidateManifest,
			"0:42",
			201,
		); err == nil {
			t.Fatal("ledger post mount ID differing from manifest unexpectedly accepted")
		}
	})
}

func TestSmokeScriptBPFFSCreationLedgerMatchesGoContract(t *testing.T) {
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve isolated netns test source path")
	}
	scriptPath := filepath.Join(
		filepath.Dir(testFile),
		"..",
		"..",
		"scripts",
		"smoke-netns-wg.sh",
	)
	scriptData, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("read smoke script: %v", err)
	}
	const functionHeader = "bpffs_creation_ledger_payload() {"
	functionStart := strings.Index(string(scriptData), functionHeader)
	if functionStart < 0 {
		t.Fatalf("smoke script does not define %s", functionHeader)
	}
	functionEndOffset := strings.Index(
		string(scriptData[functionStart:]),
		"\nwrite_marker() {",
	)
	if functionEndOffset < 0 {
		t.Fatal("smoke script bpffs creation ledger payload has no fixed boundary")
	}
	functionSource := string(
		scriptData[functionStart : functionStart+functionEndOffset],
	)

	layout, _, _, _, _ := isolatedFixtureLayout(t, "a")
	source := isolatedNetNSTestBPFFSSource(
		layout.runID,
		isolatedFixtureOwnerToken,
	)
	harness := fmt.Sprintf(`set -euo pipefail
RUN_ID=%q
OWNER_TOKEN=%q
BPFFS_DIR=%q
BPFFS_SOURCE=%q
BPFFS_PRE_TARGET_MOUNT_ID=21
BPFFS_PRE_TARGET_DEVICE=8:1
BPFFS_PRE_BPF_MOUNTS=30@0:30
BPFFS_MOUNT_ID=42
BPFFS_MOUNT_DEVICE=0:42
BPFFS_PARENT_INO=201
%s
bpffs_creation_ledger_payload
`, layout.runID, isolatedFixtureOwnerToken, layout.bpffsDir, source, functionSource)
	command := exec.Command("/bin/bash", "-c", harness)
	command.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	ledgerData, err := command.Output()
	if err != nil {
		t.Fatalf("render smoke script bpffs creation ledger: %v", err)
	}
	ledger, err := parseIsolatedNetNSTestBPFFSLedger(ledgerData)
	if err != nil {
		t.Fatalf("parse smoke script bpffs creation ledger: %v", err)
	}
	manifest, err := parseIsolatedNetNSTestManifest(
		isolatedFixtureManifest(layout),
	)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := parseMountInfo([]byte(
		isolatedMountInfoFixture(layout, "0:42", "/", "bpf", ""),
	))
	if err != nil {
		t.Fatal(err)
	}
	chain, err := privateBPFFSMountChain(entries, layout)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateIsolatedNetNSTestBPFFSLedger(
		ledger,
		entries,
		chain,
		layout,
		manifest,
		"0:42",
		201,
	); err != nil {
		t.Fatalf("validate smoke script bpffs creation ledger: %v", err)
	}

	legacyData := bytes.Replace(
		ledgerData,
		[]byte("source="+source+"\n"),
		[]byte("source=bpf\n"),
		1,
	)
	legacy, err := parseIsolatedNetNSTestBPFFSLedger(legacyData)
	if err != nil {
		t.Fatalf("parse structurally valid legacy source fixture: %v", err)
	}
	if err := validateIsolatedNetNSTestBPFFSLedger(
		legacy,
		entries,
		chain,
		layout,
		manifest,
		"0:42",
		201,
	); err == nil {
		t.Fatal("legacy bpf shell source unexpectedly satisfied Go contract")
	}
}

func TestIsolatedBPFFSCreationLedgerRejectsHistoricalAliases(t *testing.T) {
	layout, _, _, _, _ := isolatedFixtureLayout(t, "a")
	source := isolatedNetNSTestBPFFSSource(layout.runID, isolatedFixtureOwnerToken)
	tests := []struct {
		name        string
		mountID     string
		device      string
		baseline    string
		manifestID  string
		postMountID string
	}{
		{
			name:        "moved pre-existing mount",
			mountID:     "30",
			device:      "0:30",
			baseline:    "30@0:30",
			manifestID:  "30",
			postMountID: "30",
		},
		{
			name:        "hidden bind source",
			mountID:     "42",
			device:      "0:30",
			baseline:    "30@0:30",
			manifestID:  "42",
			postMountID: "42",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest, err := parseIsolatedNetNSTestManifest(
				isolatedFixtureManifest(layout),
			)
			if err != nil {
				t.Fatal(err)
			}
			manifest.values["bpffs_mount_id"] = tt.manifestID
			fixture := fmt.Sprintf(
				"21 1 8:1 / / rw,relatime - ext4 /dev/root rw\n"+
					"%s 21 %s / %s rw,nosuid,nodev,noexec,relatime - bpf %s rw\n",
				tt.mountID,
				tt.device,
				layout.bpffsDir,
				source,
			)
			entries, err := parseMountInfo([]byte(fixture))
			if err != nil {
				t.Fatal(err)
			}
			mountID, err := parseCanonicalPositiveUint(tt.mountID, "fixture mount ID")
			if err != nil {
				t.Fatal(err)
			}
			if err := validatePrivateBPFFSMountInfo(
				entries,
				layout,
				manifest,
				mountID,
				nil,
			); err != nil {
				t.Fatalf("current-only mount validation did not expose historical case: %v", err)
			}
			chain, err := privateBPFFSMountChain(entries, layout)
			if err != nil {
				t.Fatal(err)
			}
			ledger, err := parseIsolatedNetNSTestBPFFSLedger(
				isolatedBPFFSLedgerFixture(
					layout,
					"21",
					"8:1",
					tt.baseline,
					tt.postMountID,
					tt.device,
					"201",
				),
			)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateIsolatedNetNSTestBPFFSLedger(
				ledger,
				entries,
				chain,
				layout,
				manifest,
				tt.device,
				201,
			); err == nil {
				t.Fatal("historical BPF mount alias unexpectedly accepted")
			}
		})
	}
}

func TestParseIsolatedBPFFSCreationLedgerRejectsMalformedBaseline(t *testing.T) {
	for name, baseline := range map[string]string{
		"empty":            "",
		"noncanonical id":  "030@0:30",
		"noncanonical dev": "30@00:30",
		"duplicate id":     "30@0:30,30@0:31",
		"unsorted":         "31@0:31,30@0:30",
		"invalid record":   "30:0:30",
		"none mixed":       "none,30@0:30",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseIsolatedNetNSTestBPFMountBaseline(baseline); err == nil {
				t.Fatal("malformed BPF mount baseline unexpectedly accepted")
			}
		})
	}
	records := make([]string, 1025)
	for index := range records {
		records[index] = strconv.Itoa(index+1) + "@0:1"
	}
	if _, err := parseIsolatedNetNSTestBPFMountBaseline(
		strings.Join(records, ","),
	); err == nil {
		t.Fatal("oversized BPF mount baseline unexpectedly accepted")
	}
}

func TestParseMountInfoRejectsInvalidFixtures(t *testing.T) {
	tests := []string{
		"",
		"42 21 0:42 / /target rw\n",
		"42 21 0:42 / /target rw - bpf source rw\n42 21 0:43 / /other rw - bpf other rw\n",
		"42 21 0:42 / /bad\\777path rw - bpf source rw\n",
	}
	for _, fixture := range tests {
		if _, err := parseMountInfo([]byte(fixture)); err == nil {
			t.Fatalf("invalid mountinfo fixture unexpectedly accepted: %q", fixture)
		}
	}
}

func isolatedFixtureLayout(
	t *testing.T,
	role string,
) (isolatedNetNSTestLayout, string, string, string, string) {
	t.Helper()
	base := filepath.Join(isolatedNetNSTestRoot, "0123456789abcdef")
	configPath := filepath.Join(base, "secrets", "agent-"+role+".yaml")
	runDir := filepath.Join(base, "run-"+role)
	stateDir := filepath.Join(base, "state-"+role)
	pinPath := filepath.Join(base, "bpffs", "wg-mix-ebpf-"+role)
	layout, err := isolatedNetNSTestPaths(
		"reload",
		configPath,
		runDir,
		stateDir,
		pinPath,
	)
	if err != nil {
		t.Fatalf("fixture layout: %v", err)
	}
	return layout, configPath, runDir, stateDir, pinPath
}

func isolatedFixtureManifest(layout isolatedNetNSTestLayout) []byte {
	return isolatedFixtureManifestForRoles(layout, "a", "b")
}

func isolatedFixtureManifestForRoles(
	layout isolatedNetNSTestLayout,
	roleA string,
	roleB string,
) []byte {
	base := layout.runBase
	secrets := filepath.Join(base, "secrets")
	pinLockRoot := filepath.Join(base, "pin-locks")
	pinOwnerRoot := filepath.Join(base, "pin-owners")
	pinA := filepath.Join(layout.bpffsDir, "wg-mix-ebpf-"+roleA)
	pinB := filepath.Join(layout.bpffsDir, "wg-mix-ebpf-"+roleB)
	keyA, err := pinidentity.Key(200, 201, filepath.Base(pinA))
	if err != nil {
		panic(err)
	}
	keyB, err := pinidentity.Key(200, 201, filepath.Base(pinB))
	if err != nil {
		panic(err)
	}
	return []byte(fmt.Sprintf(
		`format=%s
run_id=%s
owner_token=%s
boot_id=01234567-89ab-cdef-0123-456789abcdef
host=test-host
run_base=%s
bpffs=%s
bpffs_source=%s
bpffs_mount_id=42
pin_parent_dev=200
pin_parent_ino=201
pin_resource_key_a=%s
pin_resource_key_b=%s
pin_lock_root=%s
pin_lock_a=%s
pin_lock_b=%s
pin_owner_root=%s
pin_owner_a=%s
pin_owner_b=%s
role_a=%s
pin_a=%s
role_b=%s
pin_b=%s
netns_a=wme%sa
netns_a_dev=100
netns_a_ino=101
netns_r=wme%sr
netns_r_dev=100
netns_r_ino=102
netns_b=wme%sb
netns_b_dev=100
netns_b_ino=103
run_dir_a=%s
state_dir_a=%s
config_a=%s
wg_config_a=%s
underlay_a=under0
run_dir_b=%s
state_dir_b=%s
config_b=%s
wg_config_b=%s
underlay_b=under0
lifecycle_lease=%s
evidence=%s
secrets=%s
`,
		isolatedNetNSManifestFormat,
		layout.runID,
		isolatedFixtureOwnerToken,
		base,
		layout.bpffsDir,
		isolatedNetNSTestBPFFSSource(
			layout.runID,
			isolatedFixtureOwnerToken,
		),
		keyA,
		keyB,
		pinLockRoot,
		filepath.Join(pinLockRoot, keyA+".lock"),
		filepath.Join(pinLockRoot, keyB+".lock"),
		pinOwnerRoot,
		filepath.Join(pinOwnerRoot, keyA+".owner.json"),
		filepath.Join(pinOwnerRoot, keyB+".owner.json"),
		roleA,
		pinA,
		roleB,
		pinB,
		layout.runID,
		layout.runID,
		layout.runID,
		filepath.Join(base, "run-"+roleA),
		filepath.Join(base, "state-"+roleA),
		filepath.Join(secrets, "agent-"+roleA+".yaml"),
		filepath.Join(secrets, "wg-"+roleA+".conf"),
		filepath.Join(base, "run-"+roleB),
		filepath.Join(base, "state-"+roleB),
		filepath.Join(secrets, "agent-"+roleB+".yaml"),
		filepath.Join(secrets, "wg-"+roleB+".conf"),
		layout.lease,
		filepath.Join(base, "evidence"),
		secrets,
	))
}

func isolatedMountInfoFixture(
	layout isolatedNetNSTestLayout,
	device string,
	root string,
	source string,
	extra string,
) string {
	if source == "bpf" {
		source = isolatedNetNSTestBPFFSSource(
			layout.runID,
			isolatedFixtureOwnerToken,
		)
	}
	return fmt.Sprintf(
		"21 1 8:1 / / rw,relatime - ext4 /dev/root rw\n"+
			"30 21 0:30 / /sys/fs/bpf rw,nosuid,nodev,noexec,relatime - bpf bpf rw\n"+
			"42 21 %s %s %s rw,nosuid,nodev,noexec,relatime - bpf %s rw\n%s",
		device,
		root,
		layout.bpffsDir,
		source,
		extra,
	)
}

func isolatedMountInfoFixtureWithTargetOptions(
	layout isolatedNetNSTestLayout,
	mountOptions string,
	optionalFields string,
	superOptions string,
) string {
	if optionalFields != "" {
		optionalFields = " " + optionalFields
	}
	return fmt.Sprintf(
		"21 1 8:1 / / rw,relatime - ext4 /dev/root rw\n"+
			"30 21 0:30 / /sys/fs/bpf rw,nosuid,nodev,noexec,relatime - bpf bpf rw\n"+
			"42 21 0:42 / %s %s%s - bpf %s %s\n",
		layout.bpffsDir,
		mountOptions,
		optionalFields,
		isolatedNetNSTestBPFFSSource(
			layout.runID,
			isolatedFixtureOwnerToken,
		),
		superOptions,
	)
}

func isolatedBPFFSLedgerFixture(
	layout isolatedNetNSTestLayout,
	preTargetMountID string,
	preTargetDevice string,
	preBPFMounts string,
	postMountID string,
	postDevice string,
	postInode string,
) []byte {
	return []byte(fmt.Sprintf(
		`format=%s
run_id=%s
owner_token=%s
target=%s
source=%s
pre_target_mount_id=%s
pre_target_dev=%s
pre_bpf_mounts=%s
post_mount_id=%s
post_dev=%s
post_ino=%s
`,
		isolatedNetNSBPFFSLedgerFormat,
		layout.runID,
		isolatedFixtureOwnerToken,
		layout.bpffsDir,
		isolatedNetNSTestBPFFSSource(layout.runID, isolatedFixtureOwnerToken),
		preTargetMountID,
		preTargetDevice,
		preBPFMounts,
		postMountID,
		postDevice,
		postInode,
	))
}
