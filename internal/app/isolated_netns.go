package app

import (
	"bufio"
	"bytes"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/syx0310/wg-mix-ebpf/internal/pinidentity"
)

const (
	isolatedNetNSTestRoot           = "/run/wg-mix-ebpf-tests"
	isolatedNetNSOwnerMarker        = ".wg-mix-ebpf-test-owner"
	isolatedNetNSOwnerFormat        = "wg-mix-ebpf-test-owner-v1"
	isolatedNetNSManifestFormat     = "wg-mix-ebpf-test-manifest-v2"
	isolatedNetNSLifecycleLeaseName = "lifecycle.lease"
	isolatedNetNSLifecycleGateName  = ".lifecycle.maintenance"
	isolatedNetNSLifecycleGatePath  = isolatedNetNSTestRoot + "/" + isolatedNetNSLifecycleGateName
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
	lease    string
	gate     string
}

type isolatedNetNSTestManifest struct {
	values map[string]string
}

type mountInfoEntry struct {
	mountID   uint64
	parentID  uint64
	device    string
	root      string
	mountPath string
	fsType    string
	source    string
}

func isolatedNetNSTestPaths(
	cmd string,
	configPath string,
	runDir string,
	stateDir string,
	pinPath string,
) (isolatedNetNSTestLayout, error) {
	if cmd != "reload" && cmd != "detach" {
		return isolatedNetNSTestLayout{}, fmt.Errorf(
			"--isolated-netns-test is only valid for reload and detach",
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
		"run_id":          layout.runID,
		"run_base":        layout.runBase,
		"bpffs":           layout.bpffsDir,
		"bpffs_source":    "bpf",
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
		if separator < 6 || separator+3 >= len(fields) {
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
		entries = append(entries, mountInfoEntry{
			mountID:   mountID,
			parentID:  parentID,
			device:    fields[2],
			root:      root,
			mountPath: mountPath,
			fsType:    fields[separator+1],
			source:    source,
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
	var target *mountInfoEntry
	var otherBPFFSMounts []*mountInfoEntry
	for index := range entries {
		entry := &entries[index]
		if entry.mountPath == layout.bpffsDir {
			if target != nil {
				return fmt.Errorf("multiple mounts are stacked on isolated bpffs %s", layout.bpffsDir)
			}
			target = entry
		} else if entry.fsType == "bpf" {
			otherBPFFSMounts = append(otherBPFFSMounts, entry)
		}
		if strings.HasPrefix(entry.mountPath, layout.bpffsDir+string(filepath.Separator)) {
			return fmt.Errorf(
				"nested mount %s exists below isolated bpffs %s",
				entry.mountPath,
				layout.bpffsDir,
			)
		}
	}
	if target == nil {
		return fmt.Errorf("isolated bpffs %s is not an exact mount point", layout.bpffsDir)
	}
	if target.fsType != "bpf" || target.root != "/" {
		return fmt.Errorf(
			"isolated bpffs must be a bpf mount rooted at /: type=%q root=%q",
			target.fsType,
			target.root,
		)
	}
	if target.source != "bpf" || manifest.values["bpffs_source"] != "bpf" {
		return fmt.Errorf(
			"isolated bpffs source=%q and manifest source=%q must both be the kernel bpf source",
			target.source,
			manifest.values["bpffs_source"],
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
			(target.device == otherMount.device &&
				target.root == otherMount.root) {
			return fmt.Errorf(
				"isolated bpffs is a bind or alias of another bpf mount %s",
				otherMount.mountPath,
			)
		}
	}
	return nil
}
