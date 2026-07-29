package app

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/syx0310/wg-mix-ebpf/internal/pinidentity"
)

const isolatedFixtureOwnerToken = "0123456789abcdef0123456789abcdef"

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
	if layout.ledger != filepath.Join(base, isolatedNetNSBPFFSLedgerName) {
		t.Fatalf("bpffs creation ledger = %q", layout.ledger)
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
	if strings.Contains(layouts[0].lease, "run-client") ||
		strings.Contains(layouts[1].lease, "run-server") {
		t.Fatalf("role-specific lease permits serialization bypass: %#v", layouts)
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
		{name: "read-only command", cmd: "status", config: validConfig, run: validRun, state: validState, pin: validPin},
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
			layout.runBase,
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
			layout.runBase,
			layout.bpffsDir,
			source,
		),
		"bpf ancestor separated by tmpfs": fmt.Sprintf(
			"21 1 8:1 / / rw,relatime - ext4 /dev/root rw\n"+
				"31 21 0:31 / /run rw,nosuid,nodev,noexec,relatime - bpf prior rw\n"+
				"41 31 0:41 / %s rw,relatime - tmpfs tmpfs rw\n"+
				"42 41 0:42 / %s rw,nosuid,nodev,noexec,relatime - bpf %s rw\n",
			layout.runBase,
			layout.bpffsDir,
			source,
		),
		"ancestor cycle": fmt.Sprintf(
			"21 1 8:1 / / rw,relatime - ext4 /dev/root rw\n"+
				"41 42 0:41 / %s rw,relatime - tmpfs tmpfs rw\n"+
				"42 41 0:42 / %s rw,nosuid,nodev,noexec,relatime - bpf %s rw\n",
			layout.runBase,
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
			layout.runBase,
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
		"100",
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
					"100",
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
	preTargetInode string,
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
pre_target_ino=%s
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
		preTargetInode,
		preBPFMounts,
		postMountID,
		postDevice,
		postInode,
	))
}
