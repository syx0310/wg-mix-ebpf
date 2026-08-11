package app

import (
	"bufio"
	"bytes"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/syx0310/wg-mix-ebpf/internal/pinidentity"
)

const (
	isolatedNetNSTestRoot           = "/run/wg-mix-ebpf-tests"
	isolatedNetNSOwnerMarker        = ".wg-mix-ebpf-test-owner"
	isolatedNetNSOwnerFormat        = "wg-mix-ebpf-test-owner-v1"
	isolatedNetNSManifestFormat     = "wg-mix-ebpf-test-manifest-v2"
	isolatedNetNSBPFFSLedgerFormat  = "wg-mix-ebpf-bpffs-creation-v1"
	isolatedNetNSBPFFSLedgerName    = "bpffs.creation.v1"
	isolatedNetNSLifecycleLeaseName = "lifecycle.lease"
	isolatedNetNSLifecycleGateName  = ".lifecycle.maintenance"
	isolatedNetNSLifecycleGatePath  = isolatedNetNSTestRoot + "/" + isolatedNetNSLifecycleGateName
	isolatedPinOwnershipCommand     = "isolated-pin-ownership"
)

var (
	isolatedNetNSTestRunID      = regexp.MustCompile(`^[0-9a-f]{8,64}$`)
	isolatedNetNSTestOwnerToken = regexp.MustCompile(`^[0-9a-f]{32}$`)
	isolatedNetNSTestBootID     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	isolatedNetNSTestRole       = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	isolatedNetNSTestKey        = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	isolatedNetNSTestNetNS      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$`)
	isolatedNetNSTestInterface  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$`)
)

type isolatedNetNSTestLayout struct {
	runBase  string
	runID    string
	role     string
	bpffsDir string
	manifest string
	ledger   string
	lease    string
	gate     string
}

type isolatedNetNSTestManifest struct {
	values map[string]string
}

type isolatedNetNSTestMountIdentity struct {
	mountID uint64
	device  string // Canonical mountinfo major:minor, never raw stat st_dev.
}

type isolatedNetNSTestBPFFSLedger struct {
	runID            string
	ownerToken       string
	target           string
	source           string
	preTargetMountID uint64
	preTargetDevice  string // Canonical mountinfo major:minor.
	preBPFMounts     []isolatedNetNSTestMountIdentity
	postMountID      uint64
	postDevice       string // Canonical mountinfo major:minor.
	postInode        uint64
}

type isolatedNetNSTestRelevantMountSnapshot struct {
	targetChain    []mountInfoEntry
	otherBPFMounts []mountInfoEntry
	runBaseMounts  []mountInfoEntry
}

type mountInfoEntry struct {
	mountID        uint64
	parentID       uint64
	device         string
	root           string
	mountPath      string
	mountOptions   []string
	optionalFields []string
	fsType         string
	source         string
	superOptions   []string
}

func isolatedNetNSTestPaths(
	cmd string,
	configPath string,
	runDir string,
	stateDir string,
	pinPath string,
) (isolatedNetNSTestLayout, error) {
	if cmd != "reload" && cmd != "status" && cmd != "detach" && cmd != isolatedPinOwnershipCommand {
		return isolatedNetNSTestLayout{}, fmt.Errorf(
			"--isolated-netns-test is only valid for reload, status, detach, and the isolated ownership bridge",
		)
	}
	for name, path := range map[string]string{
		"config":    configPath,
		"run-dir":   runDir,
		"state-dir": stateDir,
		"pin":       pinPath,
	} {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return isolatedNetNSTestLayout{}, fmt.Errorf(
				"--isolated-netns-test requires a non-empty canonical absolute %s path",
				name,
			)
		}
	}

	runBase := filepath.Dir(runDir)
	runID := filepath.Base(runBase)
	if filepath.Dir(runBase) != isolatedNetNSTestRoot ||
		!isolatedNetNSTestRunID.MatchString(runID) {
		return isolatedNetNSTestLayout{}, fmt.Errorf(
			"--isolated-netns-test run-dir must be below %s/<hex-run-id>",
			isolatedNetNSTestRoot,
		)
	}
	if filepath.Dir(isolatedNetNSLifecycleGatePath) != isolatedNetNSTestRoot ||
		filepath.Base(isolatedNetNSLifecycleGatePath) != isolatedNetNSLifecycleGateName {
		return isolatedNetNSTestLayout{}, fmt.Errorf(
			"internal isolated lifecycle gate must be a direct child of %s",
			isolatedNetNSTestRoot,
		)
	}

	runName := filepath.Base(runDir)
	if !strings.HasPrefix(runName, "run-") || len(runName) == len("run-") {
		return isolatedNetNSTestLayout{}, fmt.Errorf(
			"--isolated-netns-test run-dir must have a run-<role> basename",
		)
	}
	role := strings.TrimPrefix(runName, "run-")
	if !isolatedNetNSTestRole.MatchString(role) {
		return isolatedNetNSTestLayout{}, fmt.Errorf(
			"--isolated-netns-test role is not a canonical lowercase identifier",
		)
	}
	if stateDir != filepath.Join(runBase, "state-"+role) {
		return isolatedNetNSTestLayout{}, fmt.Errorf(
			"--isolated-netns-test state-dir does not match run-dir role %q",
			role,
		)
	}

	secretsDir := filepath.Join(runBase, "secrets")
	if filepath.Dir(configPath) != secretsDir {
		return isolatedNetNSTestLayout{}, fmt.Errorf(
			"--isolated-netns-test config must be a direct child of %s",
			secretsDir,
		)
	}
	if filepath.Base(configPath) != "agent-"+role+".yaml" {
		return isolatedNetNSTestLayout{}, fmt.Errorf(
			"--isolated-netns-test config filename does not match role %q",
			role,
		)
	}
	bpffsDir := filepath.Join(runBase, "bpffs")
	if pinPath != filepath.Join(bpffsDir, "wg-mix-ebpf-"+role) {
		return isolatedNetNSTestLayout{}, fmt.Errorf(
			"--isolated-netns-test pin path does not match role %q",
			role,
		)
	}

	return isolatedNetNSTestLayout{
		runBase:  runBase,
		runID:    runID,
		role:     role,
		bpffsDir: bpffsDir,
		manifest: filepath.Join(runBase, "manifest"),
		ledger:   filepath.Join(runBase, isolatedNetNSBPFFSLedgerName),
		// Both roles intentionally share one lease. Per-role leases would let
		// callers relabel a pin or underlay and bypass lifecycle serialization.
		lease: filepath.Join(runBase, isolatedNetNSLifecycleLeaseName),
		// All isolated runs share one fixed gate under the already validated
		// test root. A per-run permanent gate would accumulate after each run.
		gate: isolatedNetNSLifecycleGatePath,
	}, nil
}

func parseIsolatedNetNSTestManifest(data []byte) (isolatedNetNSTestManifest, error) {
	allowed := []string{
		"format",
		"run_id",
		"owner_token",
		"boot_id",
		"host",
		"run_base",
		"bpffs",
		"bpffs_source",
		"bpffs_mount_id",
		"pin_parent_dev",
		"pin_parent_ino",
		"pin_resource_key_a",
		"pin_resource_key_b",
		"pin_lock_root",
		"pin_lock_a",
		"pin_lock_b",
		"pin_owner_root",
		"pin_owner_a",
		"pin_owner_b",
		"role_a",
		"pin_a",
		"role_b",
		"pin_b",
		"netns_a",
		"netns_a_dev",
		"netns_a_ino",
		"netns_r",
		"netns_r_dev",
		"netns_r_ino",
		"netns_b",
		"netns_b_dev",
		"netns_b_ino",
		"run_dir_a",
		"state_dir_a",
		"config_a",
		"wg_config_a",
		"underlay_a",
		"run_dir_b",
		"state_dir_b",
		"config_b",
		"wg_config_b",
		"underlay_b",
		"lifecycle_lease",
		"evidence",
		"secrets",
	}
	values, err := parseStrictKeyValueDocument(data, allowed)
	if err != nil {
		return isolatedNetNSTestManifest{}, fmt.Errorf("parse isolated test manifest: %w", err)
	}
	if values["format"] != isolatedNetNSManifestFormat {
		return isolatedNetNSTestManifest{}, fmt.Errorf(
			"unsupported isolated test manifest format %q",
			values["format"],
		)
	}
	if !isolatedNetNSTestRunID.MatchString(values["run_id"]) {
		return isolatedNetNSTestManifest{}, fmt.Errorf("manifest run_id is not canonical lowercase hex")
	}
	if !isolatedNetNSTestOwnerToken.MatchString(values["owner_token"]) {
		return isolatedNetNSTestManifest{}, fmt.Errorf("manifest owner_token must be 32 lowercase hex characters")
	}
	if !isolatedNetNSTestBootID.MatchString(values["boot_id"]) {
		return isolatedNetNSTestManifest{}, fmt.Errorf("manifest boot_id is not canonical")
	}
	for _, key := range []string{
		"bpffs_mount_id",
		"pin_parent_dev",
		"pin_parent_ino",
		"netns_a_dev",
		"netns_a_ino",
		"netns_r_dev",
		"netns_r_ino",
		"netns_b_dev",
		"netns_b_ino",
	} {
		if _, err := parseCanonicalPositiveUint(values[key], key); err != nil {
			return isolatedNetNSTestManifest{}, err
		}
	}
	return isolatedNetNSTestManifest{values: values}, nil
}

func validateIsolatedNetNSTestManifestLayout(
	manifest isolatedNetNSTestManifest,
	layout isolatedNetNSTestLayout,
	configPath string,
	runDir string,
	stateDir string,
	pinPath string,
) error {
	values := manifest.values
	secretsDir := filepath.Join(layout.runBase, "secrets")
	pinLockRoot := filepath.Join(layout.runBase, "pin-locks")
	pinOwnerRoot := filepath.Join(layout.runBase, "pin-owners")
	expected := map[string]string{
		"run_id":   layout.runID,
		"run_base": layout.runBase,
		"bpffs":    layout.bpffsDir,
		"bpffs_source": isolatedNetNSTestBPFFSSource(
			layout.runID,
			values["owner_token"],
		),
		"pin_lock_root":   pinLockRoot,
		"pin_owner_root":  pinOwnerRoot,
		"lifecycle_lease": layout.lease,
		"evidence":        filepath.Join(layout.runBase, "evidence"),
		"secrets":         secretsDir,
	}
	for key, want := range expected {
		if values[key] != want {
			return fmt.Errorf(
				"isolated test manifest %s=%q, want %q",
				key,
				values[key],
				want,
			)
		}
	}
	parentDevice, err := parseCanonicalPositiveUint(values["pin_parent_dev"], "pin_parent_dev")
	if err != nil {
		return err
	}
	parentInode, err := parseCanonicalPositiveUint(values["pin_parent_ino"], "pin_parent_ino")
	if err != nil {
		return err
	}
	if values["role_a"] == values["role_b"] {
		return fmt.Errorf("isolated test manifest endpoint roles must be distinct")
	}
	resourceKeys := make(map[string]string, 2)
	for _, endpoint := range []string{"a", "b"} {
		role := values["role_"+endpoint]
		if !isolatedNetNSTestRole.MatchString(role) {
			return fmt.Errorf("isolated test manifest role_%s=%q is invalid", endpoint, role)
		}
		endpointPin := filepath.Join(layout.bpffsDir, "wg-mix-ebpf-"+role)
		resourceKey, err := pinidentity.Key(
			parentDevice,
			parentInode,
			filepath.Base(endpointPin),
		)
		if err != nil {
			return fmt.Errorf("derive isolated pin identity for role %s: %w", role, err)
		}
		if previousEndpoint, duplicate := resourceKeys[resourceKey]; duplicate {
			return fmt.Errorf(
				"isolated test endpoints %s and %s share pin resource key %s",
				previousEndpoint,
				endpoint,
				resourceKey,
			)
		}
		resourceKeys[resourceKey] = endpoint
		rolePaths := map[string]string{
			"pin_" + endpoint:              endpointPin,
			"pin_resource_key_" + endpoint: resourceKey,
			"pin_lock_" + endpoint:         filepath.Join(pinLockRoot, resourceKey+".lock"),
			"pin_owner_" + endpoint:        filepath.Join(pinOwnerRoot, resourceKey+".owner.json"),
			"run_dir_" + endpoint:          filepath.Join(layout.runBase, "run-"+role),
			"state_dir_" + endpoint:        filepath.Join(layout.runBase, "state-"+role),
			"config_" + endpoint:           filepath.Join(secretsDir, "agent-"+role+".yaml"),
			"wg_config_" + endpoint:        filepath.Join(secretsDir, "wg-"+role+".conf"),
		}
		for key, want := range rolePaths {
			if values[key] != want {
				return fmt.Errorf(
					"isolated test manifest %s=%q, want %q",
					key,
					values[key],
					want,
				)
			}
		}
		if !isolatedNetNSTestNetNS.MatchString(values["netns_"+endpoint]) ||
			!strings.Contains(values["netns_"+endpoint], layout.runID) {
			return fmt.Errorf(
				"isolated test manifest netns_%s=%q is not tied to run_id",
				endpoint,
				values["netns_"+endpoint],
			)
		}
		if !isolatedNetNSTestInterface.MatchString(values["underlay_"+endpoint]) {
			return fmt.Errorf(
				"isolated test manifest underlay_%s=%q is invalid",
				endpoint,
				values["underlay_"+endpoint],
			)
		}
	}
	if !isolatedNetNSTestNetNS.MatchString(values["netns_r"]) ||
		!strings.Contains(values["netns_r"], layout.runID) {
		return fmt.Errorf("isolated test manifest router namespace is not tied to run_id")
	}
	endpoint, err := manifestEndpointForRole(manifest, layout.role)
	if err != nil {
		return err
	}
	currentExpected := map[string]string{
		"pin_" + endpoint:       pinPath,
		"run_dir_" + endpoint:   runDir,
		"state_dir_" + endpoint: stateDir,
		"config_" + endpoint:    configPath,
	}
	for key, want := range currentExpected {
		if values[key] != want {
			return fmt.Errorf("isolated test manifest %s=%q, want %q", key, values[key], want)
		}
	}
	for _, key := range []string{
		"run_base",
		"bpffs",
		"pin_lock_root",
		"pin_lock_a",
		"pin_lock_b",
		"pin_owner_root",
		"pin_owner_a",
		"pin_owner_b",
		"pin_a",
		"pin_b",
		"run_dir_a",
		"state_dir_a",
		"config_a",
		"wg_config_a",
		"run_dir_b",
		"state_dir_b",
		"config_b",
		"wg_config_b",
		"lifecycle_lease",
		"evidence",
		"secrets",
	} {
		value := values[key]
		if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return fmt.Errorf("isolated test manifest %s is not a canonical absolute path", key)
		}
		if value != layout.runBase && !strings.HasPrefix(value, layout.runBase+string(filepath.Separator)) {
			return fmt.Errorf("isolated test manifest %s escapes the run root", key)
		}
	}
	return nil
}

func isolatedNetNSTestBPFFSSource(runID string, ownerToken string) string {
	return "wg-mix-ebpf-" + runID + "-" + ownerToken
}

func parseIsolatedNetNSTestBPFFSLedger(
	data []byte,
) (isolatedNetNSTestBPFFSLedger, error) {
	const (
		formatKey           = "format"
		runIDKey            = "run_id"
		ownerTokenKey       = "owner_token"
		targetKey           = "target"
		sourceKey           = "source"
		preTargetMountIDKey = "pre_target_mount_id"
		preTargetDeviceKey  = "pre_target_dev"
		preBPFMountsKey     = "pre_bpf_mounts"
		postMountIDKey      = "post_mount_id"
		postDeviceKey       = "post_dev"
		postInodeKey        = "post_ino"
	)
	values, err := parseStrictKeyValueDocument(data, []string{
		formatKey,
		runIDKey,
		ownerTokenKey,
		targetKey,
		sourceKey,
		preTargetMountIDKey,
		preTargetDeviceKey,
		preBPFMountsKey,
		postMountIDKey,
		postDeviceKey,
		postInodeKey,
	})
	if err != nil {
		return isolatedNetNSTestBPFFSLedger{}, fmt.Errorf(
			"parse isolated bpffs creation ledger: %w",
			err,
		)
	}
	if values[formatKey] != isolatedNetNSBPFFSLedgerFormat {
		return isolatedNetNSTestBPFFSLedger{}, fmt.Errorf(
			"unsupported isolated bpffs creation ledger format %q",
			values[formatKey],
		)
	}
	if !isolatedNetNSTestRunID.MatchString(values[runIDKey]) {
		return isolatedNetNSTestBPFFSLedger{}, fmt.Errorf(
			"isolated bpffs creation ledger run_id is not canonical lowercase hex",
		)
	}
	if !isolatedNetNSTestOwnerToken.MatchString(values[ownerTokenKey]) {
		return isolatedNetNSTestBPFFSLedger{}, fmt.Errorf(
			"isolated bpffs creation ledger owner_token must be 32 lowercase hex characters",
		)
	}
	if values[targetKey] == "" ||
		!filepath.IsAbs(values[targetKey]) ||
		filepath.Clean(values[targetKey]) != values[targetKey] {
		return isolatedNetNSTestBPFFSLedger{}, fmt.Errorf(
			"isolated bpffs creation ledger target is not a canonical absolute path",
		)
	}
	preTargetMountID, err := parseCanonicalPositiveUint(
		values[preTargetMountIDKey],
		preTargetMountIDKey,
	)
	if err != nil {
		return isolatedNetNSTestBPFFSLedger{}, err
	}
	preTargetDevice, err := parseCanonicalMountInfoDevice(
		values[preTargetDeviceKey],
		preTargetDeviceKey,
	)
	if err != nil {
		return isolatedNetNSTestBPFFSLedger{}, err
	}
	preBPFMounts, err := parseIsolatedNetNSTestBPFMountBaseline(
		values[preBPFMountsKey],
	)
	if err != nil {
		return isolatedNetNSTestBPFFSLedger{}, err
	}
	postMountID, err := parseCanonicalPositiveUint(
		values[postMountIDKey],
		postMountIDKey,
	)
	if err != nil {
		return isolatedNetNSTestBPFFSLedger{}, err
	}
	postDevice, err := parseCanonicalMountInfoDevice(
		values[postDeviceKey],
		postDeviceKey,
	)
	if err != nil {
		return isolatedNetNSTestBPFFSLedger{}, err
	}
	postInode, err := parseCanonicalPositiveUint(
		values[postInodeKey],
		postInodeKey,
	)
	if err != nil {
		return isolatedNetNSTestBPFFSLedger{}, err
	}
	return isolatedNetNSTestBPFFSLedger{
		runID:            values[runIDKey],
		ownerToken:       values[ownerTokenKey],
		target:           values[targetKey],
		source:           values[sourceKey],
		preTargetMountID: preTargetMountID,
		preTargetDevice:  preTargetDevice,
		preBPFMounts:     preBPFMounts,
		postMountID:      postMountID,
		postDevice:       postDevice,
		postInode:        postInode,
	}, nil
}

func parseIsolatedNetNSTestBPFMountBaseline(
	value string,
) ([]isolatedNetNSTestMountIdentity, error) {
	const maximumBPFMountBaselineEntries = 1024

	if value == "none" {
		return nil, nil
	}
	records := strings.Split(value, ",")
	if len(records) > maximumBPFMountBaselineEntries {
		return nil, fmt.Errorf(
			"pre_bpf_mounts exceeds %d entries",
			maximumBPFMountBaselineEntries,
		)
	}
	result := make([]isolatedNetNSTestMountIdentity, 0, len(records))
	seenMountIDs := make(map[uint64]struct{}, len(records))
	var previousMountID uint64
	for _, record := range records {
		mountIDValue, deviceValue, found := strings.Cut(record, "@")
		if !found || mountIDValue == "" || deviceValue == "" {
			return nil, fmt.Errorf(
				"pre_bpf_mounts entry %q must be mount-id@major:minor",
				record,
			)
		}
		mountID, err := parseCanonicalPositiveUint(
			mountIDValue,
			"pre_bpf_mounts mount id",
		)
		if err != nil {
			return nil, err
		}
		device, err := parseCanonicalMountInfoDevice(
			deviceValue,
			"pre_bpf_mounts device",
		)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seenMountIDs[mountID]; duplicate {
			return nil, fmt.Errorf("pre_bpf_mounts duplicates mount ID %d", mountID)
		}
		seenMountIDs[mountID] = struct{}{}
		if previousMountID != 0 && mountID <= previousMountID {
			return nil, fmt.Errorf(
				"pre_bpf_mounts entries must be unique and sorted by mount ID",
			)
		}
		previousMountID = mountID
		result = append(result, isolatedNetNSTestMountIdentity{
			mountID: mountID,
			device:  device,
		})
	}
	return result, nil
}

func parseCanonicalMountInfoDevice(value string, field string) (string, error) {
	majorValue, minorValue, found := strings.Cut(value, ":")
	if !found || majorValue == "" || minorValue == "" ||
		strings.Contains(minorValue, ":") {
		return "", fmt.Errorf("%s must be a canonical major:minor device", field)
	}
	major, err := parseCanonicalUint(majorValue, field+" major")
	if err != nil {
		return "", err
	}
	minor, err := parseCanonicalUint(minorValue, field+" minor")
	if err != nil {
		return "", err
	}
	return strconv.FormatUint(major, 10) + ":" + strconv.FormatUint(minor, 10), nil
}

func manifestEndpointForRole(
	manifest isolatedNetNSTestManifest,
	role string,
) (string, error) {
	for _, endpoint := range []string{"a", "b"} {
		if manifest.values["role_"+endpoint] == role {
			return endpoint, nil
		}
	}
	return "", fmt.Errorf("isolated test manifest has no endpoint for role %q", role)
}

func validateManifestNetworkNamespaces(
	manifest isolatedNetNSTestManifest,
	endpoint string,
	currentDevice uint64,
	currentInode uint64,
) error {
	type identity struct {
		device uint64
		inode  uint64
	}
	identities := make(map[string]identity, 3)
	seen := make(map[identity]string, 3)
	for _, manifestRole := range []string{"a", "r", "b"} {
		device, err := parseCanonicalPositiveUint(
			manifest.values["netns_"+manifestRole+"_dev"],
			"netns_"+manifestRole+"_dev",
		)
		if err != nil {
			return err
		}
		inode, err := parseCanonicalPositiveUint(
			manifest.values["netns_"+manifestRole+"_ino"],
			"netns_"+manifestRole+"_ino",
		)
		if err != nil {
			return err
		}
		id := identity{device: device, inode: inode}
		if previous, duplicate := seen[id]; duplicate {
			return fmt.Errorf(
				"isolated test manifest reuses network namespace identity for roles %s and %s",
				previous,
				manifestRole,
			)
		}
		seen[id] = manifestRole
		identities[manifestRole] = id
	}
	current, ok := identities[endpoint]
	if !ok {
		return fmt.Errorf("isolated test endpoint %q has no manifest network namespace", endpoint)
	}
	if current.device != currentDevice || current.inode != currentInode {
		return fmt.Errorf(
			"current network namespace dev:ino=%d:%d does not match manifest role %s dev:ino=%d:%d",
			currentDevice,
			currentInode,
			endpoint,
			current.device,
			current.inode,
		)
	}
	return nil
}

func validateBPFFSParentIdentity(
	manifest isolatedNetNSTestManifest,
	device uint64,
	inode uint64,
) error {
	parentDevice, err := parseCanonicalPositiveUint(
		manifest.values["pin_parent_dev"],
		"pin_parent_dev",
	)
	if err != nil {
		return err
	}
	parentInode, err := parseCanonicalPositiveUint(
		manifest.values["pin_parent_ino"],
		"pin_parent_ino",
	)
	if err != nil {
		return err
	}
	if device != parentDevice || inode != parentInode {
		return fmt.Errorf(
			"isolated bpffs dev:ino=%d:%d does not match manifest pin parent dev:ino=%d:%d",
			device,
			inode,
			parentDevice,
			parentInode,
		)
	}
	return nil
}

func validateIsolatedNetNSTestOwner(
	data []byte,
	manifest isolatedNetNSTestManifest,
	role string,
) error {
	values, err := parseStrictKeyValueDocument(data, []string{
		"format",
		"run_id",
		"owner_token",
		"boot_id",
		"role",
	})
	if err != nil {
		return fmt.Errorf("parse isolated test owner marker: %w", err)
	}
	if values["format"] != isolatedNetNSOwnerFormat {
		return fmt.Errorf("unsupported isolated test owner format %q", values["format"])
	}
	if values["run_id"] != manifest.values["run_id"] ||
		values["owner_token"] != manifest.values["owner_token"] ||
		values["boot_id"] != manifest.values["boot_id"] ||
		values["role"] != role {
		return fmt.Errorf("isolated test owner marker does not match manifest role %q", role)
	}
	return nil
}

func parseStrictKeyValueDocument(data []byte, allowed []string) (map[string]string, error) {
	if len(data) == 0 || !bytes.HasSuffix(data, []byte{'\n'}) {
		return nil, fmt.Errorf("document must be non-empty and newline-terminated")
	}
	if bytes.ContainsAny(data, "\x00\r") {
		return nil, fmt.Errorf("document contains a NUL or carriage return")
	}
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, key := range allowed {
		allowedSet[key] = struct{}{}
	}
	values := make(map[string]string, len(allowed))
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 1024), 16*1024)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		key, value, found := strings.Cut(line, "=")
		if !found || key == "" || value == "" || !isolatedNetNSTestKey.MatchString(key) {
			return nil, fmt.Errorf("line %d is not a canonical key=value record", lineNumber)
		}
		if strings.TrimSpace(key) != key || strings.TrimSpace(value) != value {
			return nil, fmt.Errorf("line %d contains leading or trailing whitespace", lineNumber)
		}
		if _, ok := allowedSet[key]; !ok {
			return nil, fmt.Errorf("line %d contains unknown key %q", lineNumber, key)
		}
		if _, duplicate := values[key]; duplicate {
			return nil, fmt.Errorf("line %d duplicates key %q", lineNumber, key)
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan document: %w", err)
	}
	for _, key := range allowed {
		if _, ok := values[key]; !ok {
			return nil, fmt.Errorf("document is missing key %q", key)
		}
	}
	return values, nil
}

func parseCanonicalPositiveUint(value string, field string) (uint64, error) {
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || parsed == 0 || strconv.FormatUint(parsed, 10) != value {
		return 0, fmt.Errorf("%s must be a canonical positive decimal integer", field)
	}
	return parsed, nil
}

func parseCanonicalUint(value string, field string) (uint64, error) {
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || strconv.FormatUint(parsed, 10) != value {
		return 0, fmt.Errorf("%s must be a canonical decimal integer", field)
	}
	return parsed, nil
}

func parseMountInfo(data []byte) ([]mountInfoEntry, error) {
	var entries []mountInfoEntry
	seenIDs := make(map[uint64]struct{})
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		fields := strings.Fields(scanner.Text())
		separator := -1
		for index, field := range fields {
			if field == "-" {
				separator = index
				break
			}
		}
		if separator < 6 || separator+4 != len(fields) {
			return nil, fmt.Errorf("mountinfo line %d has an invalid field layout", lineNumber)
		}
		mountID, err := parseCanonicalPositiveUint(fields[0], "mount id")
		if err != nil {
			return nil, fmt.Errorf("mountinfo line %d: %w", lineNumber, err)
		}
		parentID, err := parseCanonicalPositiveUint(fields[1], "parent mount id")
		if err != nil {
			return nil, fmt.Errorf("mountinfo line %d: %w", lineNumber, err)
		}
		if _, duplicate := seenIDs[mountID]; duplicate {
			return nil, fmt.Errorf("mountinfo line %d duplicates mount id %d", lineNumber, mountID)
		}
		seenIDs[mountID] = struct{}{}
		deviceParts := strings.Split(fields[2], ":")
		if len(deviceParts) != 2 {
			return nil, fmt.Errorf("mountinfo line %d has an invalid device number", lineNumber)
		}
		if _, err := parseCanonicalUint(deviceParts[0], "device major"); err != nil {
			return nil, fmt.Errorf("mountinfo line %d: %w", lineNumber, err)
		}
		if _, err := parseCanonicalUint(deviceParts[1], "device minor"); err != nil {
			return nil, fmt.Errorf("mountinfo line %d: %w", lineNumber, err)
		}
		root, err := unescapeMountInfoField(fields[3])
		if err != nil {
			return nil, fmt.Errorf("mountinfo line %d root: %w", lineNumber, err)
		}
		mountPath, err := unescapeMountInfoField(fields[4])
		if err != nil {
			return nil, fmt.Errorf("mountinfo line %d mount point: %w", lineNumber, err)
		}
		source, err := unescapeMountInfoField(fields[separator+2])
		if err != nil {
			return nil, fmt.Errorf("mountinfo line %d source: %w", lineNumber, err)
		}
		mountOptions, err := parseMountInfoOptionList(
			fields[5],
			fmt.Sprintf("mountinfo line %d mount options", lineNumber),
		)
		if err != nil {
			return nil, err
		}
		optionalFields, err := parseMountInfoOptionalFields(
			fields[6:separator],
			lineNumber,
		)
		if err != nil {
			return nil, err
		}
		superOptions, err := parseMountInfoOptionList(
			fields[separator+3],
			fmt.Sprintf("mountinfo line %d super options", lineNumber),
		)
		if err != nil {
			return nil, err
		}
		entries = append(entries, mountInfoEntry{
			mountID:        mountID,
			parentID:       parentID,
			device:         fields[2],
			root:           root,
			mountPath:      mountPath,
			mountOptions:   mountOptions,
			optionalFields: optionalFields,
			fsType:         fields[separator+1],
			source:         source,
			superOptions:   superOptions,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan mountinfo: %w", err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("mountinfo is empty")
	}
	return entries, nil
}

func parseMountInfoOptionList(raw string, field string) ([]string, error) {
	if raw == "" {
		return nil, fmt.Errorf("%s is empty", field)
	}
	options := strings.Split(raw, ",")
	seen := make(map[string]struct{}, len(options))
	for _, option := range options {
		if option == "" || strings.ContainsAny(option, " \t\r\n\x00") {
			return nil, fmt.Errorf("%s contains an invalid option %q", field, option)
		}
		if _, duplicate := seen[option]; duplicate {
			return nil, fmt.Errorf("%s duplicates option %q", field, option)
		}
		seen[option] = struct{}{}
	}
	sort.Strings(options)
	return options, nil
}

func parseMountInfoOptionalFields(fields []string, lineNumber int) ([]string, error) {
	seen := make(map[string]struct{}, len(fields))
	seenKinds := make(map[string]struct{}, 4)
	for _, field := range fields {
		if field == "" || strings.ContainsAny(field, " \t\r\n\x00") {
			return nil, fmt.Errorf(
				"mountinfo line %d contains an invalid optional field %q",
				lineNumber,
				field,
			)
		}
		if _, duplicate := seen[field]; duplicate {
			return nil, fmt.Errorf(
				"mountinfo line %d duplicates optional field %q",
				lineNumber,
				field,
			)
		}
		seen[field] = struct{}{}
		kind := ""
		switch {
		case field == "unbindable":
			kind = "unbindable"
		case strings.HasPrefix(field, "shared:"):
			kind = "shared"
			if _, err := parseCanonicalPositiveUint(
				strings.TrimPrefix(field, "shared:"),
				"shared peer group",
			); err != nil {
				return nil, fmt.Errorf("mountinfo line %d: %w", lineNumber, err)
			}
		case strings.HasPrefix(field, "master:"):
			kind = "master"
			if _, err := parseCanonicalPositiveUint(
				strings.TrimPrefix(field, "master:"),
				"master peer group",
			); err != nil {
				return nil, fmt.Errorf("mountinfo line %d: %w", lineNumber, err)
			}
		case strings.HasPrefix(field, "propagate_from:"):
			kind = "propagate_from"
			if _, err := parseCanonicalPositiveUint(
				strings.TrimPrefix(field, "propagate_from:"),
				"propagation source peer group",
			); err != nil {
				return nil, fmt.Errorf("mountinfo line %d: %w", lineNumber, err)
			}
		default:
			// The kernel may add optional fields in future mountinfo versions.
			// Preserve them during parsing so an unrelated mount does not make
			// the whole namespace unreadable. The isolated target validator
			// rejects every optional field, including unknown ones.
		}
		if kind != "" {
			if _, duplicate := seenKinds[kind]; duplicate {
				return nil, fmt.Errorf(
					"mountinfo line %d repeats optional field kind %q",
					lineNumber,
					kind,
				)
			}
			seenKinds[kind] = struct{}{}
		}
	}
	sort.Strings(fields)
	return fields, nil
}

func unescapeMountInfoField(value string) (string, error) {
	var out strings.Builder
	for index := 0; index < len(value); index++ {
		if value[index] != '\\' {
			out.WriteByte(value[index])
			continue
		}
		if index+3 >= len(value) {
			return "", fmt.Errorf("truncated mountinfo escape")
		}
		escape := value[index+1 : index+4]
		switch escape {
		case "040":
			out.WriteByte(' ')
		case "011":
			out.WriteByte('\t')
		case "012":
			out.WriteByte('\n')
		case "134":
			out.WriteByte('\\')
		default:
			return "", fmt.Errorf("unsupported mountinfo escape \\%s", escape)
		}
		index += 3
	}
	return out.String(), nil
}

func validatePrivateBPFFSMountInfo(
	entries []mountInfoEntry,
	layout isolatedNetNSTestLayout,
	manifest isolatedNetNSTestManifest,
	statxMountID uint64,
	pinMountID *uint64,
) error {
	chain, err := privateBPFFSMountChain(entries, layout)
	if err != nil {
		return err
	}
	target := chain[0]
	var otherBPFFSMounts []*mountInfoEntry
	for index := range entries {
		entry := &entries[index]
		if entry.mountPath != layout.bpffsDir && entry.fsType == "bpf" {
			otherBPFFSMounts = append(otherBPFFSMounts, entry)
		}
	}
	if target.fsType != "bpf" || target.root != "/" {
		return fmt.Errorf(
			"isolated bpffs must be a bpf mount rooted at /: type=%q root=%q",
			target.fsType,
			target.root,
		)
	}
	if err := validatePrivateBPFFSMountOptions(target); err != nil {
		return err
	}
	expectedSource := isolatedNetNSTestBPFFSSource(
		layout.runID,
		manifest.values["owner_token"],
	)
	if target.source != expectedSource ||
		manifest.values["bpffs_source"] != expectedSource {
		return fmt.Errorf(
			"isolated bpffs source=%q and manifest source=%q must both equal run-bound source %q",
			target.source,
			manifest.values["bpffs_source"],
			expectedSource,
		)
	}
	manifestMountID, err := parseCanonicalPositiveUint(
		manifest.values["bpffs_mount_id"],
		"bpffs_mount_id",
	)
	if err != nil {
		return err
	}
	if target.mountID != manifestMountID || statxMountID != manifestMountID {
		return fmt.Errorf(
			"isolated bpffs mount IDs disagree: manifest=%d mountinfo=%d statx=%d",
			manifestMountID,
			target.mountID,
			statxMountID,
		)
	}
	if pinMountID != nil && *pinMountID != manifestMountID {
		return fmt.Errorf(
			"isolated pin target is on mount %d, want bpffs mount %d",
			*pinMountID,
			manifestMountID,
		)
	}
	for _, otherMount := range otherBPFFSMounts {
		if target.mountID == otherMount.mountID ||
			target.device == otherMount.device {
			return fmt.Errorf(
				"isolated bpffs is a bind or alias of another bpf mount %s",
				otherMount.mountPath,
			)
		}
	}
	return nil
}

func privateBPFFSMountChain(
	entries []mountInfoEntry,
	layout isolatedNetNSTestLayout,
) ([]mountInfoEntry, error) {
	if err := validateProtectedRunSubtreeMounts(entries, layout); err != nil {
		return nil, err
	}
	var target *mountInfoEntry
	byMountID := make(map[uint64]*mountInfoEntry, len(entries))
	for index := range entries {
		entry := &entries[index]
		byMountID[entry.mountID] = entry
		if entry.mountPath == layout.bpffsDir {
			if target != nil {
				return nil, fmt.Errorf(
					"multiple mounts are stacked on isolated bpffs %s",
					layout.bpffsDir,
				)
			}
			target = entry
		}
	}
	if target == nil {
		return nil, fmt.Errorf(
			"isolated bpffs %s is not an exact mount point",
			layout.bpffsDir,
		)
	}

	chain := make([]mountInfoEntry, 0, 8)
	seen := make(map[uint64]struct{}, 8)
	current := target
	for {
		if _, duplicate := seen[current.mountID]; duplicate {
			return nil, fmt.Errorf(
				"isolated bpffs mount ancestry contains a cycle at mount ID %d",
				current.mountID,
			)
		}
		seen[current.mountID] = struct{}{}
		if current.mountPath == "" ||
			!filepath.IsAbs(current.mountPath) ||
			filepath.Clean(current.mountPath) != current.mountPath {
			return nil, fmt.Errorf(
				"isolated bpffs mount ancestor %d has noncanonical path %q",
				current.mountID,
				current.mountPath,
			)
		}
		if len(current.optionalFields) != 0 {
			return nil, fmt.Errorf(
				"isolated bpffs mount ancestor %s has propagation fields: %s",
				current.mountPath,
				strings.Join(current.optionalFields, ","),
			)
		}
		if len(chain) != 0 && current.fsType == "bpf" {
			return nil, fmt.Errorf(
				"isolated bpffs is nested below bpf mount %s",
				current.mountPath,
			)
		}
		chain = append(chain, *current)
		if current.mountPath == "/" {
			if err := validatePrivateBPFFSMountAncestors(
				entries,
				chain,
				isolatedNetNSTestRoot,
			); err != nil {
				return nil, err
			}
			return chain, nil
		}
		parent := byMountID[current.parentID]
		if parent == nil {
			return nil, fmt.Errorf(
				"isolated bpffs mount ancestry breaks at absent parent mount ID %d",
				current.parentID,
			)
		}
		if _, cycle := seen[parent.mountID]; cycle {
			return nil, fmt.Errorf(
				"isolated bpffs mount ancestry contains a cycle at mount ID %d",
				parent.mountID,
			)
		}
		if parent.mountPath != "/" &&
			!strings.HasPrefix(
				current.mountPath,
				parent.mountPath+string(filepath.Separator),
			) {
			return nil, fmt.Errorf(
				"mount %s (ID %d) is not a strict descendant of parent mount %s (ID %d)",
				current.mountPath,
				current.mountID,
				parent.mountPath,
				parent.mountID,
			)
		}
		current = parent
	}
}

func validateProtectedRunSubtreeMounts(
	entries []mountInfoEntry,
	layout isolatedNetNSTestLayout,
) error {
	for _, entry := range entries {
		if mountPathAtOrBelow(entry.mountPath, layout.runBase) &&
			entry.mountPath != layout.bpffsDir {
			return fmt.Errorf(
				"unexpected mount %s exists in protected run subtree %s",
				entry.mountPath,
				layout.runBase,
			)
		}
	}
	return nil
}

func validatePrivateBPFFSMountAncestors(
	entries []mountInfoEntry,
	chain []mountInfoEntry,
	protectedRoot string,
) error {
	if len(chain) < 2 {
		return fmt.Errorf("isolated bpffs mount ancestry does not include a parent mount")
	}
	parent := chain[1]
	if !mountPathStrictAncestor(parent.mountPath, protectedRoot) {
		return fmt.Errorf(
			"isolated bpffs parent mount %s must be a strict ancestor of isolated root %s",
			parent.mountPath,
			protectedRoot,
		)
	}
	for chainIndex := 1; chainIndex < len(chain); chainIndex++ {
		ancestor := chain[chainIndex]
		if ancestor.root != "/" {
			return fmt.Errorf(
				"isolated bpffs ancestor %s is a subtree bind rooted at %s",
				ancestor.mountPath,
				ancestor.root,
			)
		}
		for _, entry := range entries {
			if entry.mountID == ancestor.mountID {
				continue
			}
			if entry.device == ancestor.device && entry.root == ancestor.root {
				return fmt.Errorf(
					"isolated bpffs ancestor %s aliases whole mount root at %s",
					ancestor.mountPath,
					entry.mountPath,
				)
			}
		}
	}
	return nil
}

func mountPathAtOrBelow(path string, root string) bool {
	return path == root ||
		strings.HasPrefix(path, root+string(filepath.Separator))
}

func mountPathStrictAncestor(parent string, child string) bool {
	if parent == "/" {
		return child != "/" && filepath.IsAbs(child)
	}
	return parent != child &&
		strings.HasPrefix(child, parent+string(filepath.Separator))
}

func validateIsolatedNetNSTestBPFFSLedger(
	ledger isolatedNetNSTestBPFFSLedger,
	entries []mountInfoEntry,
	chain []mountInfoEntry,
	layout isolatedNetNSTestLayout,
	manifest isolatedNetNSTestManifest,
	currentDevice string,
	currentInode uint64,
) error {
	if len(chain) < 2 {
		return fmt.Errorf("isolated bpffs mount ancestry does not include a parent mount")
	}
	expectedSource := isolatedNetNSTestBPFFSSource(
		layout.runID,
		manifest.values["owner_token"],
	)
	if ledger.runID != layout.runID ||
		ledger.runID != manifest.values["run_id"] ||
		ledger.ownerToken != manifest.values["owner_token"] ||
		ledger.target != layout.bpffsDir ||
		ledger.source != expectedSource ||
		manifest.values["bpffs_source"] != expectedSource ||
		chain[0].source != expectedSource {
		return fmt.Errorf(
			"isolated bpffs creation ledger is not bound to the manifest, run, target, and mount source",
		)
	}
	if ledger.preTargetMountID != chain[1].mountID ||
		ledger.preTargetDevice != chain[1].device {
		return fmt.Errorf(
			"isolated bpffs pre-mount target identity does not match its current parent mount",
		)
	}
	manifestMountID, err := parseCanonicalPositiveUint(
		manifest.values["bpffs_mount_id"],
		"bpffs_mount_id",
	)
	if err != nil {
		return err
	}
	if ledger.postMountID != chain[0].mountID ||
		ledger.postMountID != manifestMountID ||
		ledger.postDevice != chain[0].device ||
		ledger.postDevice != currentDevice ||
		ledger.postInode != currentInode {
		return fmt.Errorf(
			"isolated bpffs post-mount identity does not match the current mount",
		)
	}
	if ledger.preTargetMountID == ledger.postMountID ||
		ledger.preTargetDevice == ledger.postDevice {
		return fmt.Errorf(
			"isolated bpffs pre-mount and post-mount identities are not independent",
		)
	}

	baselineByMountID := make(map[uint64]string, len(ledger.preBPFMounts))
	for _, identity := range ledger.preBPFMounts {
		if identity.mountID == ledger.postMountID ||
			identity.device == ledger.postDevice {
			return fmt.Errorf(
				"isolated bpffs post-mount identity existed in the pre-creation BPF baseline",
			)
		}
		baselineByMountID[identity.mountID] = identity.device
	}
	currentBPFMounts := make(map[uint64]string)
	for _, entry := range entries {
		if entry.fsType != "bpf" || entry.mountID == chain[0].mountID {
			continue
		}
		currentBPFMounts[entry.mountID] = entry.device
	}
	if len(currentBPFMounts) != len(baselineByMountID) {
		return fmt.Errorf(
			"visible BPF mount set changed from the pre-creation baseline",
		)
	}
	for mountID, device := range baselineByMountID {
		if currentBPFMounts[mountID] != device {
			return fmt.Errorf(
				"visible BPF mount ID %d changed from pre-creation device %s",
				mountID,
				device,
			)
		}
	}
	return nil
}

func validatePrivateBPFFSMountOptions(entry mountInfoEntry) error {
	if len(entry.optionalFields) != 0 {
		return fmt.Errorf(
			"isolated bpffs has shared, slave, unbindable, or unknown propagation fields: %s",
			strings.Join(entry.optionalFields, ","),
		)
	}
	mountOptions := make(map[string]struct{}, len(entry.mountOptions))
	for _, option := range entry.mountOptions {
		mountOptions[option] = struct{}{}
	}
	required := []string{"rw", "nosuid", "nodev", "noexec"}
	for _, option := range required {
		if _, ok := mountOptions[option]; !ok {
			return fmt.Errorf("isolated bpffs mount options are missing %s", option)
		}
	}
	for _, unsafe := range []string{"ro", "suid", "dev", "exec"} {
		if _, ok := mountOptions[unsafe]; ok {
			return fmt.Errorf("isolated bpffs mount options contain conflicting %s", unsafe)
		}
	}
	atimePolicies := 0
	for _, option := range []string{"relatime", "noatime", "strictatime"} {
		if _, ok := mountOptions[option]; ok {
			atimePolicies++
		}
	}
	if atimePolicies != 1 {
		return fmt.Errorf(
			"isolated bpffs must have exactly one atime policy: relatime, noatime, or strictatime",
		)
	}
	allowedMountOptions := map[string]struct{}{
		"rw":          {},
		"nosuid":      {},
		"nodev":       {},
		"noexec":      {},
		"relatime":    {},
		"noatime":     {},
		"strictatime": {},
	}
	for _, option := range entry.mountOptions {
		if _, ok := allowedMountOptions[option]; !ok {
			return fmt.Errorf("isolated bpffs has unsupported mount option %q", option)
		}
	}

	if len(entry.superOptions) == 0 {
		return fmt.Errorf("isolated bpffs super options are empty")
	}
	seenRW := false
	seenMode := false
	for _, option := range entry.superOptions {
		switch {
		case option == "rw":
			seenRW = true
		case option == "ro":
			return fmt.Errorf("isolated bpffs super options are read-only")
		case strings.HasPrefix(option, "mode="):
			// The directory metadata is independently required to be 0700.
			// Kernels may omit the bpf mode from mountinfo or render it as
			// either 700 or 0700; no other filesystem-specific option is
			// accepted.
			if seenMode {
				return fmt.Errorf("isolated bpffs super options repeat mode")
			}
			mode := strings.TrimPrefix(option, "mode=")
			parsed, err := strconv.ParseUint(mode, 8, 32)
			if err != nil || parsed != 0o700 ||
				(mode != "700" && mode != "0700") {
				return fmt.Errorf(
					"isolated bpffs super option mode=%q must be 700",
					mode,
				)
			}
			seenMode = true
		default:
			return fmt.Errorf("isolated bpffs has unsupported super option %q", option)
		}
	}
	if !seenRW {
		return fmt.Errorf("isolated bpffs super options are missing rw")
	}
	return nil
}

func sameMountInfoEntry(left mountInfoEntry, right mountInfoEntry) bool {
	return left.mountID == right.mountID &&
		left.parentID == right.parentID &&
		left.device == right.device &&
		left.root == right.root &&
		left.mountPath == right.mountPath &&
		strings.Join(left.mountOptions, ",") == strings.Join(right.mountOptions, ",") &&
		strings.Join(left.optionalFields, ",") == strings.Join(right.optionalFields, ",") &&
		left.fsType == right.fsType &&
		left.source == right.source &&
		strings.Join(left.superOptions, ",") == strings.Join(right.superOptions, ",")
}

func snapshotIsolatedNetNSTestRelevantMounts(
	entries []mountInfoEntry,
	chain []mountInfoEntry,
	layout isolatedNetNSTestLayout,
) isolatedNetNSTestRelevantMountSnapshot {
	snapshot := isolatedNetNSTestRelevantMountSnapshot{
		targetChain: append([]mountInfoEntry(nil), chain...),
	}
	var targetMountID uint64
	if len(chain) != 0 {
		targetMountID = chain[0].mountID
	}
	for _, entry := range entries {
		if entry.fsType == "bpf" && entry.mountID != targetMountID {
			snapshot.otherBPFMounts = append(snapshot.otherBPFMounts, entry)
		}
		if mountPathAtOrBelow(entry.mountPath, layout.runBase) {
			snapshot.runBaseMounts = append(snapshot.runBaseMounts, entry)
		}
	}
	sortMountInfoEntries(snapshot.otherBPFMounts)
	sortMountInfoEntries(snapshot.runBaseMounts)
	return snapshot
}

func sortMountInfoEntries(entries []mountInfoEntry) {
	sort.Slice(entries, func(left int, right int) bool {
		return entries[left].mountID < entries[right].mountID
	})
}

func sameRelevantMountSnapshot(
	left isolatedNetNSTestRelevantMountSnapshot,
	right isolatedNetNSTestRelevantMountSnapshot,
) bool {
	return sameMountInfoChain(left.targetChain, right.targetChain) &&
		sameMountInfoChain(left.otherBPFMounts, right.otherBPFMounts) &&
		sameMountInfoChain(left.runBaseMounts, right.runBaseMounts)
}

func sameMountInfoChain(left []mountInfoEntry, right []mountInfoEntry) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !sameMountInfoEntry(left[index], right[index]) {
			return false
		}
	}
	return true
}

func isolatedNetNSTestProtectedPaths(
	manifest isolatedNetNSTestManifest,
	layout isolatedNetNSTestLayout,
) []string {
	values := manifest.values
	paths := []string{
		isolatedNetNSTestRoot,
		layout.runBase,
		layout.manifest,
		layout.ledger,
		layout.lease,
		values["run_dir_a"],
		values["run_dir_b"],
		values["state_dir_a"],
		values["state_dir_b"],
		values["config_a"],
		values["config_b"],
		values["wg_config_a"],
		values["wg_config_b"],
		values["secrets"],
		values["evidence"],
		values["pin_lock_root"],
		values["pin_lock_a"],
		values["pin_lock_b"],
		values["pin_owner_root"],
		values["pin_owner_a"],
		values["pin_owner_b"],
	}
	for _, directory := range []string{
		layout.runBase,
		values["run_dir_a"],
		values["run_dir_b"],
		values["state_dir_a"],
		values["state_dir_b"],
		values["secrets"],
		values["evidence"],
		values["pin_lock_root"],
		values["pin_owner_root"],
	} {
		paths = append(paths, filepath.Join(directory, isolatedNetNSOwnerMarker))
	}
	seen := make(map[string]struct{}, len(paths))
	result := make([]string, 0, len(paths))
	for _, path := range paths {
		if _, duplicate := seen[path]; duplicate {
			continue
		}
		seen[path] = struct{}{}
		result = append(result, path)
	}
	sort.Strings(result)
	return result
}

func validateIsolatedNetNSTestProtectedMounts(
	mounts map[string]isolatedNetNSTestMountIdentity,
	trustedParent mountInfoEntry,
) error {
	if len(mounts) == 0 {
		return fmt.Errorf("protected isolated path mount snapshot is empty")
	}
	for path, identity := range mounts {
		if identity.mountID != trustedParent.mountID ||
			identity.device != trustedParent.device {
			return fmt.Errorf(
				"protected isolated path %s is on mount %d device %s, want trusted parent mount %d device %s",
				path,
				identity.mountID,
				identity.device,
				trustedParent.mountID,
				trustedParent.device,
			)
		}
	}
	return nil
}
