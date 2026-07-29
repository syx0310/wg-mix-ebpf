package app

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

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
}

func TestIsolatedNetNSTestRolesShareLifecycleLease(t *testing.T) {
	base := filepath.Join(isolatedNetNSTestRoot, "0123456789abcdef")
	layouts := make([]isolatedNetNSTestLayout, 0, 2)
	for _, role := range []string{"a", "b"} {
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
	if strings.Contains(layouts[0].lease, "run-a") ||
		strings.Contains(layouts[1].lease, "run-b") {
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
		{name: "unknown role", cmd: "reload", config: filepath.Join(base, "secrets", "agent-client.yaml"), run: filepath.Join(base, "run-client"), state: filepath.Join(base, "state-client"), pin: filepath.Join(base, "bpffs", "wg-mix-ebpf-client")},
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

func TestParseAndValidatePrivateBPFFSMountInfo(t *testing.T) {
	layout, _, _, _, _ := isolatedFixtureLayout(t, "a")
	manifest, err := parseIsolatedNetNSTestManifest(isolatedFixtureManifest(layout))
	if err != nil {
		t.Fatal(err)
	}
	validFixture := isolatedMountInfoFixture(layout, "0:42", "/", "wg-mix-ebpf-"+layout.runID, "")
	entries, err := parseMountInfo([]byte(validFixture))
	if err != nil {
		t.Fatalf("parse valid mountinfo: %v", err)
	}
	pinMountID := uint64(42)
	if err := validatePrivateBPFFSMountInfo(entries, layout, manifest, 42, &pinMountID); err != nil {
		t.Fatalf("validate private bpffs: %v", err)
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
			fixture:      isolatedMountInfoFixture(layout, "0:42", "/production/subtree", "wg-mix-ebpf-"+layout.runID, ""),
			statxMountID: 42,
			pinMountID:   42,
		},
		{
			name:         "wrong source",
			fixture:      isolatedMountInfoFixture(layout, "0:42", "/", "bpf", ""),
			statxMountID: 42,
			pinMountID:   42,
		},
		{
			name: "nested pin mount",
			fixture: isolatedMountInfoFixture(
				layout,
				"0:42",
				"/",
				"wg-mix-ebpf-"+layout.runID,
				fmt.Sprintf(
					"43 42 0:43 / %s rw,nosuid,nodev,noexec - tmpfs nested rw\n",
					filepath.Join(layout.bpffsDir, "wg-mix-ebpf-a"),
				),
			),
			statxMountID: 42,
			pinMountID:   42,
		},
		{
			name: "stacked target mount",
			fixture: validFixture + fmt.Sprintf(
				"44 21 0:44 / %s rw,nosuid,nodev,noexec - bpf other rw\n",
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
			mutate: func(value isolatedNetNSTestManifest) isolatedNetNSTestManifest {
				value.values["bpffs_source"] = "bpf"
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
	base := layout.runBase
	secrets := filepath.Join(base, "secrets")
	return []byte(fmt.Sprintf(
		`format=%s
run_id=%s
owner_token=0123456789abcdef0123456789abcdef
boot_id=01234567-89ab-cdef-0123-456789abcdef
host=test-host
run_base=%s
bpffs=%s
bpffs_source=wg-mix-ebpf-%s
bpffs_mount_id=42
role_a=a
pin_a=%s
role_b=b
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
		base,
		layout.bpffsDir,
		layout.runID,
		filepath.Join(layout.bpffsDir, "wg-mix-ebpf-a"),
		filepath.Join(layout.bpffsDir, "wg-mix-ebpf-b"),
		layout.runID,
		layout.runID,
		layout.runID,
		filepath.Join(base, "run-a"),
		filepath.Join(base, "state-a"),
		filepath.Join(secrets, "agent-a.yaml"),
		filepath.Join(secrets, "wg-a.conf"),
		filepath.Join(base, "run-b"),
		filepath.Join(base, "state-b"),
		filepath.Join(secrets, "agent-b.yaml"),
		filepath.Join(secrets, "wg-b.conf"),
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
	return fmt.Sprintf(
		"21 1 8:1 / / rw,relatime - ext4 /dev/root rw\n"+
			"30 21 0:30 / /sys/fs/bpf rw,nosuid,nodev,noexec - bpf bpf rw\n"+
			"42 21 %s %s %s rw,nosuid,nodev,noexec - bpf %s rw\n%s",
		device,
		root,
		layout.bpffsDir,
		source,
		extra,
	)
}
