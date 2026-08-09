//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/control"
	"github.com/syx0310/wg-mix-ebpf/internal/lockfile"
)

const (
	scopedRealNICGateEnv = "WG_MIX_EBPF_RUN_SCOPED_REALNIC_INTEGRATION"
	scopedRealNICPrefix  = "WG_MIX_EBPF_SCOPED_REALNIC_"
	scopedRealNICRunID   = "c8e41d73"

	scopedIPBinary      = "/usr/sbin/ip"
	scopedWGBinary      = "/usr/bin/wg"
	scopedIperfBinary   = "/usr/bin/iperf3"
	scopedPingBinary    = "/usr/bin/ping"
	scopedPythonBinary  = "/usr/bin/python3"
	scopedDefaultIfName = "ens33"
)

var (
	scopedCommitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	scopedSHA256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	scopedMACPattern    = regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)
	scopedIfNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.=+:-]{1,15}$`)
)

type scopedRealNICCommon struct {
	RunID          string `json:"run_id"`
	Cell           string `json:"cell"`
	SourceCommit   string `json:"source_commit"`
	BundleSHA256   string `json:"bundle_sha256"`
	ObjectPath     string `json:"object_path"`
	Root           string `json:"root"`
	StateRoot      string `json:"state_root"`
	LeaseRoot      string `json:"lease_root"`
	OwnerRoot      string `json:"owner_root"`
	EvidenceRoot   string `json:"evidence_root"`
	PinPath        string `json:"pin_path"`
	InitialNetNS   string `json:"initial_netns"`
	Interface      string `json:"interface"`
	IfIndex        int    `json:"ifindex"`
	MAC            string `json:"mac"`
	WGInterface    string `json:"wg_interface"`
	WGLocalAddress string `json:"wg_local_address"`
	WGPeerAddress  string `json:"wg_peer_address"`
	PeerPort       int    `json:"peer_port"`
}

type scopedRealNICTraffic struct {
	Profile                string   `json:"profile"`
	CheckerPath            string   `json:"checker_path"`
	Streams                []int    `json:"streams"`
	Directions             []string `json:"directions"`
	Passes                 int      `json:"passes"`
	SessionSeconds         int      `json:"session_seconds"`
	SoakSeconds            int      `json:"soak_seconds"`
	SoakWindows            int      `json:"soak_windows"`
	PingIntervalSeconds    int      `json:"ping_interval_seconds"`
	MonitorIntervalSeconds int      `json:"monitor_interval_seconds"`
	MonitorSamples         int      `json:"monitor_samples"`
}

type scopedRealNICConfig struct {
	Action  string
	Common  scopedRealNICCommon
	Traffic scopedRealNICTraffic
}

type scopedRouteIdentity struct {
	Destination string `json:"destination"`
	Device      string `json:"device"`
	Gateway     string `json:"gateway,omitempty"`
	Preferred   string `json:"preferred_source,omitempty"`
	Source      string `json:"source,omitempty"`
	Table       string `json:"table,omitempty"`
}

type scopedWGIdentity struct {
	Name       string   `json:"name"`
	IfIndex    int      `json:"ifindex"`
	MTU        int      `json:"mtu"`
	Flags      string   `json:"flags"`
	Addresses  []string `json:"addresses"`
	ListenPort uint16   `json:"listen_port"`
	FwMark     uint32   `json:"fwmark"`
	Endpoints  []string `json:"endpoints"`
}

type scopedRealNICHostIdentity struct {
	Base  scopedHostIdentity  `json:"base"`
	WG    scopedWGIdentity    `json:"wireguard"`
	Route scopedRouteIdentity `json:"route"`
}

type scopedRealNICJournal struct {
	Version      int                       `json:"version"`
	Common       scopedRealNICCommon       `json:"common"`
	Traffic      scopedRealNICTraffic      `json:"traffic"`
	State        control.State             `json:"state"`
	Host         scopedRealNICHostIdentity `json:"host"`
	Object       scopedFileIdentity        `json:"object"`
	Checker      scopedFileIdentity        `json:"checker"`
	RootIdentity scopedDirectoryIdentity   `json:"root_identity"`
	StateRoot    scopedDirectoryIdentity   `json:"state_root_identity"`
	LeaseRoot    scopedDirectoryIdentity   `json:"lease_root_identity"`
	LockRoot     scopedDirectoryIdentity   `json:"lock_root_identity"`
	OwnerRoot    scopedDirectoryIdentity   `json:"owner_root_identity"`
	EvidenceRoot scopedDirectoryIdentity   `json:"evidence_root_identity"`
}

type scopedAppliedJournal struct {
	Version     int                 `json:"version"`
	Common      scopedRealNICCommon `json:"common"`
	OwnerRecord scopedFileIdentity  `json:"owner_record"`
	OwnerIndex  scopedFileIdentity  `json:"owner_index"`
	Links       []FilterStatus      `json:"links"`
}

type scopedStatusDocument struct {
	Dataplane *KernelStatus       `json:"dataplane"`
	Ownership *PinOwnershipStatus `json:"ownership"`
}

type scopedWGTransfer struct {
	Received uint64 `json:"received"`
	Sent     uint64 `json:"sent"`
}

type scopedRestoredMarker struct {
	Version  int    `json:"version"`
	Cell     string `json:"cell"`
	Restored bool   `json:"restored"`
}

func TestScopedRealNICDataplaneActiveIntegration(t *testing.T) {
	if os.Getenv(scopedRealNICGateEnv) != "1" {
		t.Skip("set WG_MIX_EBPF_RUN_SCOPED_REALNIC_INTEGRATION=1 for the reviewed physical-NIC integration")
	}
	config, err := scopedRealNICConfigFromEnv("run")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateScopedTestDeadline(t, config); err != nil {
		t.Fatal(err)
	}
	if err := executeScopedRealNICActive(t.Context(), config); err != nil {
		t.Fatalf("scoped real-NIC active test failed; evidence and exact owner journal retained at %s: %v", config.Common.Root, err)
	}
	fmt.Printf("SCOPED_REALNIC_COMPLETE cell=%s restored=1\n", config.Common.Cell)
}

func TestScopedRealNICDataplaneRestoreIntegration(t *testing.T) {
	if os.Getenv(scopedRealNICGateEnv) != "1" {
		t.Skip("set WG_MIX_EBPF_RUN_SCOPED_REALNIC_INTEGRATION=1 for the reviewed physical-NIC restore")
	}
	config, err := scopedRealNICConfigFromEnv("restore")
	if err != nil {
		t.Fatal(err)
	}
	if err := executeScopedRealNICRestore(t.Context(), config); err != nil {
		t.Fatalf("scoped real-NIC restore failed; evidence retained at %s: %v", config.Common.Root, err)
	}
	fmt.Printf("SCOPED_REALNIC_RESTORE_COMPLETE cell=%s restored=1\n", config.Common.Cell)
}

func scopedRealNICConfigFromEnv(wantAction string) (scopedRealNICConfig, error) {
	get := func(suffix string) string { return os.Getenv(scopedRealNICPrefix + suffix) }
	rawMAC := get("INTERFACE_MAC")
	config := scopedRealNICConfig{
		Action: get("ACTION"),
		Common: scopedRealNICCommon{
			RunID: get("RUN_ID"), Cell: get("CELL"), SourceCommit: get("SOURCE_COMMIT"),
			BundleSHA256: get("BUNDLE_SHA256"), ObjectPath: get("OBJECT"), Root: get("ROOT"),
			StateRoot: get("STATE_ROOT"), LeaseRoot: get("LEASE_ROOT"), OwnerRoot: get("OWNER_ROOT"),
			EvidenceRoot: get("EVIDENCE_ROOT"), PinPath: get("PIN_PATH"), InitialNetNS: get("INITIAL_NETNS"),
			Interface: get("INTERFACE"), MAC: rawMAC, WGInterface: get("WG_INTERFACE"),
			WGLocalAddress: get("WG_LOCAL_ADDRESS"), WGPeerAddress: get("WG_PEER_ADDRESS"),
		},
	}
	if config.Action != wantAction {
		return config, fmt.Errorf("%sACTION must be %s", scopedRealNICPrefix, wantAction)
	}
	if config.Common.RunID != scopedRealNICRunID {
		return config, fmt.Errorf("%sRUN_ID must be %s", scopedRealNICPrefix, scopedRealNICRunID)
	}
	if !validScopedCell(config.Common.Cell) {
		return config, fmt.Errorf("%sCELL is not a reviewed cell", scopedRealNICPrefix)
	}
	if !validNontrivialHex(config.Common.SourceCommit, scopedCommitPattern) {
		return config, fmt.Errorf("%sSOURCE_COMMIT must be a nontrivial lowercase 40-hex commit", scopedRealNICPrefix)
	}
	if !validNontrivialHex(config.Common.BundleSHA256, scopedSHA256Pattern) {
		return config, fmt.Errorf("%sBUNDLE_SHA256 must be a nontrivial lowercase SHA-256", scopedRealNICPrefix)
	}
	for suffix, path := range map[string]string{
		"OBJECT": config.Common.ObjectPath, "ROOT": config.Common.Root, "STATE_ROOT": config.Common.StateRoot,
		"LEASE_ROOT": config.Common.LeaseRoot, "OWNER_ROOT": config.Common.OwnerRoot,
		"EVIDENCE_ROOT": config.Common.EvidenceRoot, "PIN_PATH": config.Common.PinPath,
	} {
		if err := validateCleanAbsolutePath(scopedRealNICPrefix+suffix, path); err != nil {
			return config, err
		}
	}
	if err := validateScopedRealNICLayout(config.Common); err != nil {
		return config, err
	}
	if !scopedNetNSPattern.MatchString(config.Common.InitialNetNS) {
		return config, fmt.Errorf("%sINITIAL_NETNS must be an exact net:[N] identity", scopedRealNICPrefix)
	}
	if config.Common.Interface != scopedDefaultIfName {
		return config, fmt.Errorf("%sINTERFACE must be %s", scopedRealNICPrefix, scopedDefaultIfName)
	}
	ifindex, err := positiveEnvInteger(scopedRealNICPrefix + "INTERFACE_IFINDEX")
	if err != nil {
		return config, err
	}
	config.Common.IfIndex = ifindex
	if rawMAC != strings.ToLower(rawMAC) || !scopedMACPattern.MatchString(config.Common.MAC) {
		return config, fmt.Errorf("%sINTERFACE_MAC must be a canonical unicast MAC", scopedRealNICPrefix)
	}
	mac, _ := net.ParseMAC(config.Common.MAC)
	if len(mac) != 6 || mac[0]&1 != 0 {
		return config, fmt.Errorf("%sINTERFACE_MAC must be a canonical unicast MAC", scopedRealNICPrefix)
	}
	if !scopedIfNamePattern.MatchString(config.Common.WGInterface) || config.Common.WGInterface == config.Common.Interface {
		return config, fmt.Errorf("%sWG_INTERFACE is invalid", scopedRealNICPrefix)
	}
	localAddress, err := netip.ParseAddr(config.Common.WGLocalAddress)
	if err != nil || !localAddress.Is4() || localAddress.String() != config.Common.WGLocalAddress || localAddress.IsUnspecified() || localAddress.IsMulticast() {
		return config, fmt.Errorf("%sWG_LOCAL_ADDRESS must be a canonical unicast IPv4 address", scopedRealNICPrefix)
	}
	peerAddress, err := netip.ParseAddr(config.Common.WGPeerAddress)
	if err != nil || !peerAddress.Is4() || peerAddress.String() != config.Common.WGPeerAddress || peerAddress.IsUnspecified() || peerAddress.IsMulticast() || peerAddress == localAddress {
		return config, fmt.Errorf("%sWG_PEER_ADDRESS must be a distinct canonical unicast IPv4 address", scopedRealNICPrefix)
	}
	peerPort, err := positiveEnvInteger(scopedRealNICPrefix + "PEER_PORT")
	if err != nil || peerPort != 5201 {
		return config, fmt.Errorf("%sPEER_PORT must be 5201", scopedRealNICPrefix)
	}
	config.Common.PeerPort = peerPort
	if get("TC_ATTACH") != "tcx" || get("FAILURE_POLICY") != "retain" {
		return config, errors.New("scoped real-NIC test requires TC_ATTACH=tcx and FAILURE_POLICY=retain")
	}
	if wantAction == "restore" {
		return config, nil
	}
	if get("TYPEWORD_MODE") != "identity" || get("TRANSPORT") != "udp" || get("CIPHER") != "none" {
		return config, errors.New("scoped real-NIC active test requires identity typewords over unciphered UDP")
	}
	checker := get("IPERF_CHECKER")
	if err := validateCleanAbsolutePath(scopedRealNICPrefix+"IPERF_CHECKER", checker); err != nil {
		return config, err
	}
	traffic, err := scopedTrafficFromEnv(get, config.Common.Cell, checker)
	if err != nil {
		return config, err
	}
	config.Traffic = traffic
	return config, nil
}

func scopedTrafficFromEnv(get func(string) string, cell, checker string) (scopedRealNICTraffic, error) {
	traffic := scopedRealNICTraffic{Profile: get("PROFILE"), CheckerPath: checker}
	var err error
	if traffic.Streams, err = parseStrictIntegerList(scopedRealNICPrefix+"STREAMS", get("STREAMS"), []int{1, 4, 16}); err != nil {
		return traffic, err
	}
	if traffic.Directions, err = parseStrictStringList(scopedRealNICPrefix+"DIRECTIONS", get("DIRECTIONS"), []string{"forward", "reverse", "bidir"}); err != nil {
		return traffic, err
	}
	fields := []struct {
		suffix string
		target *int
	}{
		{"PASSES", &traffic.Passes}, {"SESSION_SECONDS", &traffic.SessionSeconds},
		{"SOAK_SECONDS", &traffic.SoakSeconds}, {"SOAK_WINDOWS", &traffic.SoakWindows},
		{"PING_INTERVAL_SECONDS", &traffic.PingIntervalSeconds},
		{"MONITOR_INTERVAL_SECONDS", &traffic.MonitorIntervalSeconds}, {"MONITOR_SAMPLES", &traffic.MonitorSamples},
	}
	for _, field := range fields {
		*field.target, err = positiveEnvInteger(scopedRealNICPrefix + field.suffix)
		if err != nil {
			return traffic, err
		}
	}
	if traffic.PingIntervalSeconds != 1 || traffic.MonitorIntervalSeconds != 10 || traffic.MonitorSamples != 360 || traffic.SoakSeconds != 3600 {
		return traffic, errors.New("scoped real-NIC ping/monitor/soak constants differ from the reviewed contract")
	}
	expectedProfile := "matrix"
	expectedStreams := []int{1, 4, 16}
	expectedDirections := []string{"forward", "reverse", "bidir"}
	expectedPasses, expectedSession, expectedWindows := 2, 30, 1
	switch cell {
	case "mtu1492", "mtu1500":
		expectedProfile, expectedStreams, expectedDirections = "mtu", []int{4}, []string{"bidir"}
		expectedPasses, expectedSession = 2, 30
	case "soak":
		expectedProfile, expectedStreams, expectedDirections = "soak", []int{4}, []string{"bidir"}
		expectedPasses, expectedSession, expectedWindows = 1, 300, 12
	}
	if traffic.Profile != expectedProfile || !reflect.DeepEqual(traffic.Streams, expectedStreams) ||
		!reflect.DeepEqual(traffic.Directions, expectedDirections) || traffic.Passes != expectedPasses ||
		traffic.SessionSeconds != expectedSession || traffic.SoakWindows != expectedWindows {
		return traffic, fmt.Errorf("traffic budget for cell %s does not match reviewed profile %s", cell, expectedProfile)
	}
	if traffic.Profile == "soak" && traffic.SessionSeconds*traffic.SoakWindows != traffic.SoakSeconds {
		return traffic, errors.New("soak windows do not exactly fill SOAK_SECONDS")
	}
	return traffic, nil
}

func validateScopedRealNICLayout(common scopedRealNICCommon) error {
	if filepath.Base(common.Root) != "scoped-realnic-"+common.Cell {
		return errors.New("scoped real-NIC root basename does not match the cell")
	}
	children := map[string]struct {
		path string
		base string
	}{
		"STATE_ROOT": {common.StateRoot, "state"}, "LEASE_ROOT": {common.LeaseRoot, "lease"},
		"OWNER_ROOT": {common.OwnerRoot, "owners"}, "EVIDENCE_ROOT": {common.EvidenceRoot, "evidence"},
	}
	for suffix, child := range children {
		if child.path != filepath.Join(common.Root, child.base) {
			return fmt.Errorf("%s%s is not its exact run-owned child", scopedRealNICPrefix, suffix)
		}
	}
	if err := rejectProductionStatePath(common.Root); err != nil {
		return err
	}
	wantPin := "/sys/fs/bpf/wg-mix-ebpf-" + common.RunID + "-nic-" + common.Cell
	if common.PinPath != wantPin || !validPinPathBase(filepath.Base(common.PinPath)) {
		return fmt.Errorf("%sPIN_PATH must be %s", scopedRealNICPrefix, wantPin)
	}
	return nil
}

func validScopedCell(cell string) bool {
	switch cell {
	case "original", "all-on", "all-off", "tx-path", "rx-path", "mtu1492", "mtu1500", "soak":
		return true
	default:
		return false
	}
}

func validNontrivialHex(value string, pattern *regexp.Regexp) bool {
	return pattern.MatchString(value) && strings.Trim(value, "0") != "" && strings.Trim(value, "f") != ""
}

func positiveEnvInteger(name string) (int, error) {
	text := os.Getenv(name)
	if text == "" || (len(text) > 1 && text[0] == '0') {
		return 0, fmt.Errorf("%s must be a canonical positive integer", name)
	}
	value, err := strconv.Atoi(text)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("%s must be a canonical positive integer", name)
	}
	return value, nil
}

func parseStrictIntegerList(name, text string, allowed []int) ([]int, error) {
	if text == "" {
		return nil, fmt.Errorf("%s is required", name)
	}
	parts := strings.Split(text, ",")
	values := make([]int, 0, len(parts))
	seen := make(map[int]bool)
	for _, part := range parts {
		value, err := strconv.Atoi(part)
		if err != nil || !containsInteger(allowed, value) || seen[value] || strconv.Itoa(value) != part {
			return nil, fmt.Errorf("%s contains an invalid or duplicate value", name)
		}
		seen[value] = true
		values = append(values, value)
	}
	return values, nil
}

func parseStrictStringList(name, text string, allowed []string) ([]string, error) {
	if text == "" {
		return nil, fmt.Errorf("%s is required", name)
	}
	values := strings.Split(text, ",")
	seen := make(map[string]bool)
	for _, value := range values {
		if !containsString(allowed, value) || seen[value] {
			return nil, fmt.Errorf("%s contains an invalid or duplicate value", name)
		}
		seen[value] = true
	}
	return values, nil
}

func containsInteger(values []int, want int) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func validateScopedTestDeadline(t *testing.T, config scopedRealNICConfig) error {
	deadline, ok := t.Deadline()
	if !ok {
		return errors.New("scoped real-NIC integration requires a finite go test timeout")
	}
	minimum := len(config.Traffic.Streams) * len(config.Traffic.Directions) * config.Traffic.Passes * config.Traffic.SessionSeconds
	if config.Traffic.Profile == "soak" {
		minimum = config.Traffic.SessionSeconds * config.Traffic.SoakWindows
	}
	if time.Until(deadline) < time.Duration(minimum+60)*time.Second {
		return fmt.Errorf("go test deadline leaves less than reviewed traffic budget plus 60-second margin: minimum=%ds", minimum)
	}
	return nil
}

func executeScopedRealNICActive(ctx context.Context, config scopedRealNICConfig) error {
	if os.Geteuid() != 0 {
		return errors.New("scoped physical-NIC integration requires root")
	}
	if err := validateNoSymlinkDirectoryChain(filepath.Dir(config.Common.Root)); err != nil {
		return err
	}
	if err := validatePrivateOwnedDirectory(filepath.Dir(config.Common.Root), 0); err != nil {
		return fmt.Errorf("validate scoped root parent: %w", err)
	}
	if _, err := os.Lstat(config.Common.Root); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("refuse active run because scoped root already exists: %s: %w", config.Common.Root, err)
	}
	if _, err := os.Lstat(config.Common.PinPath); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("refuse active run because scoped pin already exists: %s: %w", config.Common.PinPath, err)
	}
	objectIdentity, err := snapshotScopedFile(config.Common.ObjectPath, 0)
	if err != nil {
		return fmt.Errorf("validate BPF object: %w", err)
	}
	checkerIdentity, err := snapshotScopedFile(config.Traffic.CheckerPath, 0)
	if err != nil {
		return fmt.Errorf("validate iperf checker: %w", err)
	}
	if filepath.Base(config.Traffic.CheckerPath) != "check-realhost-iperf.py" {
		return errors.New("IPERF_CHECKER basename is not the reviewed checker")
	}
	host, err := snapshotScopedRealNICHost(ctx, config.Common)
	if err != nil {
		return fmt.Errorf("capture pre-mutation host identity: %w", err)
	}
	state := buildScopedIdentityState(config.Common, host.WG.FwMark, host.WG.ListenPort, host.WG.IfIndex)

	if err := createScopedRealNICLayout(config.Common); err != nil {
		return err
	}
	lockRoot := filepath.Join(config.Common.LeaseRoot, "pin-locks")
	rootIdentity, err := snapshotScopedDirectory(config.Common.Root, 0)
	if err != nil {
		return err
	}
	stateIdentity, err := snapshotScopedDirectory(config.Common.StateRoot, 0)
	if err != nil {
		return err
	}
	leaseIdentity, err := snapshotScopedDirectory(config.Common.LeaseRoot, 0)
	if err != nil {
		return err
	}
	lockIdentity, err := snapshotScopedDirectory(lockRoot, 0)
	if err != nil {
		return err
	}
	ownerIdentity, err := snapshotScopedDirectory(config.Common.OwnerRoot, 0)
	if err != nil {
		return err
	}
	evidenceIdentity, err := snapshotScopedDirectory(config.Common.EvidenceRoot, 0)
	if err != nil {
		return err
	}
	journal := scopedRealNICJournal{
		Version: 1, Common: config.Common, Traffic: config.Traffic, State: *state, Host: host,
		Object: objectIdentity, Checker: checkerIdentity, RootIdentity: rootIdentity,
		StateRoot: stateIdentity, LeaseRoot: leaseIdentity, LockRoot: lockIdentity,
		OwnerRoot: ownerIdentity, EvidenceRoot: evidenceIdentity,
	}
	if err := writeJSONExclusive(scopedRealNICJournalPath(config.Common), journal); err != nil {
		return err
	}
	if err := writeJSONExclusive(filepath.Join(config.Common.EvidenceRoot, "host-before.json"), host); err != nil {
		return err
	}

	runtime, err := newScopedLinuxLoaderRuntime(lockRoot, config.Common.OwnerRoot)
	if err != nil {
		return err
	}
	loader := LinuxLoader{ObjectPath: config.Common.ObjectPath, PinPath: config.Common.PinPath, runtime: runtime}
	lifecycleCtx := lockfile.WithLifecyclePathsForTest(
		ctx,
		filepath.Join(config.Common.LeaseRoot, "daemon.lease"),
		filepath.Join(config.Common.LeaseRoot, "maintenance.gate"),
	)
	return lockfile.WithLifecycle(lifecycleCtx, nil, lockfile.LifecycleOwner{
		PID: os.Getpid(), Action: "scoped-realnic-active", RunDir: config.Common.Root,
	}, func(lease *lockfile.LifecycleLease) error {
		if !lease.HeldAt(filepath.Join(config.Common.LeaseRoot, "daemon.lease")) {
			return errors.New("run-owned lifecycle lease is not held")
		}
		if err := recheckScopedRealNICHost(lifecycleCtx, config.Common, host); err != nil {
			return fmt.Errorf("post-lease pre-apply host identity: %w", err)
		}
		if err := recheckScopedFile(objectIdentity); err != nil {
			return fmt.Errorf("pre-apply BPF object identity: %w", err)
		}
		if err := loader.Apply(lifecycleCtx, state); err != nil {
			return fmt.Errorf("TCX Apply: %w", err)
		}
		// Deliberately no deferred Detach: every failure after Apply retains the
		// exact LinuxLoader owner journal for the explicit restore test.
		applied, err := captureScopedAppliedJournal(lifecycleCtx, config.Common, state, *runtime)
		if err != nil {
			return fmt.Errorf("capture exact applied owner/link identity: %w", err)
		}
		if err := writeJSONExclusive(scopedRealNICAppliedPath(config.Common), applied); err != nil {
			return err
		}
		beforeStatusPath := filepath.Join(config.Common.EvidenceRoot, "status-before.json")
		beforeStatus, err := captureScopedStatus(lifecycleCtx, beforeStatusPath, config.Common.PinPath, state, *runtime)
		if err != nil {
			return fmt.Errorf("capture pre-traffic status: %w", err)
		}
		beforeTransferPath := filepath.Join(config.Common.EvidenceRoot, "wg-transfer-before.txt")
		beforeTransfer, err := captureScopedWGTransfer(lifecycleCtx, config.Common.WGInterface, beforeTransferPath)
		if err != nil {
			return fmt.Errorf("capture pre-traffic WireGuard transfer: %w", err)
		}
		if err := executeScopedTraffic(lifecycleCtx, config, state, *runtime, checkerIdentity); err != nil {
			return err
		}
		afterStatusPath := filepath.Join(config.Common.EvidenceRoot, "status-after.json")
		afterStatus, err := captureScopedStatus(lifecycleCtx, afterStatusPath, config.Common.PinPath, state, *runtime)
		if err != nil {
			return fmt.Errorf("capture post-traffic status: %w", err)
		}
		afterTransferPath := filepath.Join(config.Common.EvidenceRoot, "wg-transfer-after.txt")
		afterTransfer, err := captureScopedWGTransfer(lifecycleCtx, config.Common.WGInterface, afterTransferPath)
		if err != nil {
			return fmt.Errorf("capture post-traffic WireGuard transfer: %w", err)
		}
		if afterTransfer.Received <= beforeTransfer.Received || afterTransfer.Sent <= beforeTransfer.Sent {
			return fmt.Errorf("WireGuard peer transfer did not grow in both directions: before=%+v after=%+v", beforeTransfer, afterTransfer)
		}
		if err := validateScopedCounterGrowth(beforeStatus, afterStatus); err != nil {
			return err
		}
		if err := recheckScopedFile(checkerIdentity); err != nil {
			return fmt.Errorf("revalidate checker before status acceptance: %w", err)
		}
		if err := runScopedChecker(lifecycleCtx, config.Traffic.CheckerPath,
			[]string{"stats", beforeStatusPath, afterStatusPath, "--require-egress", "--require-ingress"},
			filepath.Join(config.Common.EvidenceRoot, "status-check.json")); err != nil {
			return fmt.Errorf("validate dataplane counter evidence: %w", err)
		}
		if err := recheckScopedRealNICHost(lifecycleCtx, config.Common, host); err != nil {
			return fmt.Errorf("pre-detach host identity: %w", err)
		}
		if err := recheckScopedRealNICJournalLayout(journal); err != nil {
			return fmt.Errorf("pre-detach scoped layout identity: %w", err)
		}
		if err := recheckScopedAppliedJournal(config.Common, applied, state, *runtime, lifecycleCtx); err != nil {
			return fmt.Errorf("pre-detach exact owner/link identity: %w", err)
		}
		if err := loader.Detach(lifecycleCtx, state); err != nil {
			return fmt.Errorf("exact LinuxLoader Detach: %w", err)
		}
		if _, err := os.Lstat(config.Common.PinPath); !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("pin path remains after exact Detach: %s: %w", config.Common.PinPath, err)
		}
		if err := recheckScopedRealNICHost(lifecycleCtx, config.Common, host); err != nil {
			return fmt.Errorf("post-detach host identity: %w", err)
		}
		if err := recheckScopedRealNICJournalLayout(journal); err != nil {
			return fmt.Errorf("post-detach scoped layout identity: %w", err)
		}
		return writeScopedRestoredMarker(filepath.Join(config.Common.StateRoot, "restored.v1.json"), config.Common.Cell)
	})
}

func executeScopedRealNICRestore(ctx context.Context, config scopedRealNICConfig) error {
	if os.Geteuid() != 0 {
		return errors.New("scoped physical-NIC restore requires root")
	}
	if err := validateNoSymlinkDirectoryChain(config.Common.Root); err != nil {
		return err
	}
	for _, path := range []string{config.Common.Root, config.Common.StateRoot, config.Common.LeaseRoot, config.Common.OwnerRoot, config.Common.EvidenceRoot} {
		if err := validatePrivateOwnedDirectory(path, 0); err != nil {
			return err
		}
	}
	var journal scopedRealNICJournal
	if err := readJSONFile(scopedRealNICJournalPath(config.Common), &journal); err != nil {
		return err
	}
	if journal.Version != 1 || journal.Common != config.Common {
		return errors.New("restore environment does not exactly match the run-owned journal")
	}
	if err := recheckScopedRealNICJournalLayout(journal); err != nil {
		return err
	}
	if err := recheckScopedFile(journal.Object); err != nil {
		return fmt.Errorf("revalidate journaled BPF object: %w", err)
	}
	if err := recheckScopedRealNICHost(ctx, config.Common, journal.Host); err != nil {
		return fmt.Errorf("pre-restore host identity: %w", err)
	}
	runtime, err := newScopedLinuxLoaderRuntime(journal.LockRoot.Path, journal.OwnerRoot.Path)
	if err != nil {
		return err
	}
	loader := LinuxLoader{ObjectPath: journal.Object.Path, PinPath: journal.Common.PinPath, runtime: runtime}
	lifecycleCtx := lockfile.WithLifecyclePathsForTest(
		ctx,
		filepath.Join(journal.Common.LeaseRoot, "daemon.lease"),
		filepath.Join(journal.Common.LeaseRoot, "maintenance.gate"),
	)
	return lockfile.WithLifecycle(lifecycleCtx, nil, lockfile.LifecycleOwner{
		PID: os.Getpid(), Action: "scoped-realnic-restore", RunDir: journal.Common.Root,
	}, func(lease *lockfile.LifecycleLease) error {
		if !lease.HeldAt(filepath.Join(journal.Common.LeaseRoot, "daemon.lease")) {
			return errors.New("run-owned lifecycle lease is not held for restore")
		}
		if err := recheckScopedRealNICHost(lifecycleCtx, config.Common, journal.Host); err != nil {
			return err
		}
		status, inspectErr := inspectPinOwnershipWithRuntime(
			lifecycleCtx, journal.Common.PinPath, false, *runtime, runtime.exactTCX,
		)
		if inspectErr != nil {
			return fmt.Errorf("inspect exact LinuxLoader owner before restore: %w", inspectErr)
		}
		if status.PinPath != journal.Common.PinPath || status.OwnerRoot != journal.Common.OwnerRoot ||
			status.IndexPath != filepath.Join(journal.Common.OwnerRoot, pinOwnerIndexFileName) {
			return fmt.Errorf("restore owner identity escaped run-owned roots: %+v", status)
		}
		if status.RecoveryRequired {
			status, inspectErr = inspectPinOwnershipWithRuntime(
				lifecycleCtx, journal.Common.PinPath, true, *runtime, runtime.exactTCX,
			)
			if inspectErr != nil {
				return fmt.Errorf("recover exact LinuxLoader owner before restore: %w", inspectErr)
			}
			if status.PinPath != journal.Common.PinPath || status.OwnerRoot != journal.Common.OwnerRoot ||
				status.IndexPath != filepath.Join(journal.Common.OwnerRoot, pinOwnerIndexFileName) {
				return fmt.Errorf("recovered owner identity escaped run-owned roots: %+v", status)
			}
		}
		alreadyRestored := !status.DirectoryExists && !status.OwnerExists && !status.RecoveryRequired
		var applied scopedAppliedJournal
		appliedPath := scopedRealNICAppliedPath(journal.Common)
		if err := readJSONFile(appliedPath, &applied); err == nil {
			if !alreadyRestored {
				if err := recheckScopedAppliedLinks(journal.Common, applied, &journal.State, *runtime, lifecycleCtx); err != nil {
					return err
				}
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := loader.Detach(lifecycleCtx, &journal.State); err != nil {
			return fmt.Errorf("restore exact LinuxLoader owner journal: %w", err)
		}
		if _, err := os.Lstat(journal.Common.PinPath); !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("pin path remains after explicit restore: %w", err)
		}
		if err := recheckScopedRealNICHost(lifecycleCtx, config.Common, journal.Host); err != nil {
			return fmt.Errorf("post-restore host identity: %w", err)
		}
		return writeScopedRestoredMarker(
			filepath.Join(journal.Common.StateRoot, "explicit-restore.v1.json"),
			journal.Common.Cell,
		)
	})
}

func createScopedRealNICLayout(common scopedRealNICCommon) error {
	if err := createPrivateDirectory(common.Root); err != nil {
		return err
	}
	for _, path := range []string{common.StateRoot, common.LeaseRoot, common.OwnerRoot, common.EvidenceRoot} {
		if err := createPrivateDirectory(path); err != nil {
			return err
		}
	}
	return createPrivateDirectory(filepath.Join(common.LeaseRoot, "pin-locks"))
}

func recheckScopedRealNICJournalLayout(journal scopedRealNICJournal) error {
	for _, identity := range []scopedDirectoryIdentity{
		journal.RootIdentity, journal.StateRoot, journal.LeaseRoot,
		journal.LockRoot, journal.OwnerRoot, journal.EvidenceRoot,
	} {
		if err := recheckScopedDirectory(identity); err != nil {
			return fmt.Errorf("revalidate run-owned directory: %w", err)
		}
	}
	return nil
}

func validateNoSymlinkDirectoryChain(path string) error {
	if err := validateCleanAbsolutePath("scoped root parent", path); err != nil {
		return err
	}
	current := string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(path, current), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect scoped root ancestor %s: %w", current, err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("scoped root ancestor %s is not a direct directory", current)
		}
	}
	return nil
}

func scopedRealNICJournalPath(common scopedRealNICCommon) string {
	return filepath.Join(common.StateRoot, "journal.v1.json")
}

func scopedRealNICAppliedPath(common scopedRealNICCommon) string {
	return filepath.Join(common.StateRoot, "applied.v1.json")
}

func buildScopedIdentityState(common scopedRealNICCommon, fwmark uint32, listenPort uint16, wgIfIndex int) *control.State {
	identity := [4]uint32{1, 2, 3, 4}
	state := &control.State{
		Generation: 1,
		Profiles: []control.ProfileState{{
			ID: 1, Name: "identity-standard-typeword", StandardToMixed: identity, MixedToStandard: identity,
		}},
		WireGuards: []control.WireGuardState{{
			ID: 1, Name: common.WGInterface, Profile: "identity-standard-typeword", ProfileID: 1,
			ConfigFwMark: fwmark, RuntimeFirewallMark: fwmark, RuntimeListenPort: listenPort,
			RuntimeIfIndex: wgIfIndex, RuntimeStateAvailable: true, TransportMode: "udp",
		}},
		Underlays: []control.UnderlayState{{
			ID: 1, Name: "scoped-realnic-ens33", Type: "physical", Parser: "ethernet",
			IfName: common.Interface, IfIndex: common.IfIndex, LinkType: "ethernet", Role: "transform", Resolved: true,
		}},
		ManagedFwmarks: []control.ManagedFwmarkRule{{
			Generation: 1, FwMark: fwmark, UnderlayIfIndex: common.IfIndex, ActionOnMiss: "drop",
		}},
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		state.EgressRules = append(state.EgressRules, control.EgressRule{
			Generation: 1, Family: family, FwMark: fwmark, SourcePort: listenPort,
			UnderlayIfIndex: common.IfIndex, ProfileID: 1, WGID: 1, Action: "rewrite", TransportMode: "udp",
		})
		state.IngressListeners = append(state.IngressListeners, control.IngressListener{
			Generation: 1, Family: family, DestinationPort: listenPort, UnderlayIfIndex: common.IfIndex,
			ProfileID: 1, WGID: 1, Action: "rewrite",
		})
	}
	return state
}

func snapshotScopedRealNICHost(ctx context.Context, common scopedRealNICCommon) (scopedRealNICHostIdentity, error) {
	base, err := snapshotScopedHost(common.IfIndex)
	if err != nil {
		return scopedRealNICHostIdentity{}, err
	}
	if base.NetNS != common.InitialNetNS || base.PID1NetNS != common.InitialNetNS {
		return scopedRealNICHostIdentity{}, fmt.Errorf(
			"initial network namespace mismatch: self=%s pid1=%s expected=%s",
			base.NetNS, base.PID1NetNS, common.InitialNetNS,
		)
	}
	if base.Interface.Name != common.Interface || base.Interface.IfIndex != common.IfIndex ||
		base.Interface.HardwareAddr != common.MAC {
		return scopedRealNICHostIdentity{}, fmt.Errorf("physical interface identity mismatch: %+v", base.Interface)
	}
	wgInterface, err := net.InterfaceByName(common.WGInterface)
	if err != nil {
		return scopedRealNICHostIdentity{}, fmt.Errorf("resolve WireGuard interface %s: %w", common.WGInterface, err)
	}
	addresses, err := wgInterface.Addrs()
	if err != nil {
		return scopedRealNICHostIdentity{}, fmt.Errorf("read WireGuard addresses: %w", err)
	}
	addressStrings := make([]string, 0, len(addresses))
	localSeen := false
	for _, address := range addresses {
		text := address.String()
		prefix, err := netip.ParsePrefix(text)
		if err != nil {
			return scopedRealNICHostIdentity{}, fmt.Errorf("parse WireGuard address %q: %w", text, err)
		}
		if prefix.Addr().String() == common.WGLocalAddress {
			localSeen = true
		}
		addressStrings = append(addressStrings, text)
	}
	sort.Strings(addressStrings)
	if !localSeen {
		return scopedRealNICHostIdentity{}, fmt.Errorf("WireGuard interface %s does not own local address %s", common.WGInterface, common.WGLocalAddress)
	}
	listenText, _, err := runScopedOutput(ctx, scopedWGBinary, "show", common.WGInterface, "listen-port")
	if err != nil {
		return scopedRealNICHostIdentity{}, err
	}
	listenValue, err := strconv.ParseUint(strings.TrimSpace(string(listenText)), 10, 16)
	if err != nil || listenValue == 0 {
		return scopedRealNICHostIdentity{}, errors.New("WireGuard listen port is not a positive uint16")
	}
	fwmarkText, _, err := runScopedOutput(ctx, scopedWGBinary, "show", common.WGInterface, "fwmark")
	if err != nil {
		return scopedRealNICHostIdentity{}, err
	}
	fwmarkRaw := strings.TrimSpace(string(fwmarkText))
	if fwmarkRaw == "off" {
		return scopedRealNICHostIdentity{}, errors.New("WireGuard fwmark is off")
	}
	fwmarkValue, err := strconv.ParseUint(fwmarkRaw, 0, 32)
	if err != nil || fwmarkValue == 0 {
		return scopedRealNICHostIdentity{}, errors.New("WireGuard fwmark is not a positive uint32")
	}
	endpointBytes, _, err := runScopedOutput(ctx, scopedWGBinary, "show", common.WGInterface, "endpoints")
	if err != nil {
		return scopedRealNICHostIdentity{}, err
	}
	endpoints, err := normalizeWGEndpoints(endpointBytes)
	if err != nil {
		return scopedRealNICHostIdentity{}, err
	}
	route, err := snapshotScopedRoute(ctx, common)
	if err != nil {
		return scopedRealNICHostIdentity{}, err
	}
	return scopedRealNICHostIdentity{
		Base: base,
		WG: scopedWGIdentity{
			Name: common.WGInterface, IfIndex: wgInterface.Index, MTU: wgInterface.MTU,
			Flags: wgInterface.Flags.String(), Addresses: addressStrings,
			ListenPort: uint16(listenValue), FwMark: uint32(fwmarkValue), Endpoints: endpoints,
		},
		Route: route,
	}, nil
}

func recheckScopedRealNICHost(ctx context.Context, common scopedRealNICCommon, want scopedRealNICHostIdentity) error {
	got, err := snapshotScopedRealNICHost(ctx, common)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(got, want) {
		return fmt.Errorf("physical/WireGuard/route identity changed: got %+v, want %+v", got, want)
	}
	return nil
}

func normalizeWGEndpoints(data []byte) ([]string, error) {
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return nil, errors.New("WireGuard interface has no peer endpoints")
	}
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 2 || len(fields[0]) != 44 || fields[1] == "(none)" {
			return nil, fmt.Errorf("malformed or inactive WireGuard endpoint line %q", line)
		}
		result = append(result, fields[0]+"\t"+fields[1])
	}
	sort.Strings(result)
	return result, nil
}

func snapshotScopedRoute(ctx context.Context, common scopedRealNICCommon) (scopedRouteIdentity, error) {
	stdout, _, err := runScopedOutput(ctx, scopedIPBinary, "-j", "route", "get", common.WGPeerAddress)
	if err != nil {
		return scopedRouteIdentity{}, err
	}
	var routes []map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(stdout))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&routes); err != nil {
		return scopedRouteIdentity{}, fmt.Errorf("decode route to WireGuard peer: %w", err)
	}
	if len(routes) != 1 {
		return scopedRouteIdentity{}, fmt.Errorf("route to WireGuard peer returned %d entries, want 1", len(routes))
	}
	stringField := func(name string) (string, error) {
		raw, exists := routes[0][name]
		if !exists {
			return "", nil
		}
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return "", fmt.Errorf("decode route field %s: %w", name, err)
		}
		return value, nil
	}
	destination, err := stringField("dst")
	if err != nil {
		return scopedRouteIdentity{}, err
	}
	device, err := stringField("dev")
	if err != nil {
		return scopedRouteIdentity{}, err
	}
	gateway, err := stringField("gateway")
	if err != nil {
		return scopedRouteIdentity{}, err
	}
	preferred, err := stringField("prefsrc")
	if err != nil {
		return scopedRouteIdentity{}, err
	}
	source, err := stringField("src")
	if err != nil {
		return scopedRouteIdentity{}, err
	}
	table := ""
	if raw, exists := routes[0]["table"]; exists {
		table = string(raw)
	}
	if device != common.WGInterface || destination != common.WGPeerAddress ||
		(preferred != common.WGLocalAddress && source != common.WGLocalAddress) {
		return scopedRouteIdentity{}, fmt.Errorf(
			"route to %s is not bound to %s from %s: dst=%s dev=%s prefsrc=%s src=%s",
			common.WGPeerAddress, common.WGInterface, common.WGLocalAddress,
			destination, device, preferred, source,
		)
	}
	return scopedRouteIdentity{
		Destination: destination, Device: device, Gateway: gateway,
		Preferred: preferred, Source: source, Table: table,
	}, nil
}

func runScopedOutput(ctx context.Context, executable string, args ...string) ([]byte, []byte, error) {
	if ctx == nil {
		return nil, nil, errors.New("external command context is nil")
	}
	command := exec.CommandContext(ctx, executable, args...)
	command.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return stdout.Bytes(), stderr.Bytes(), fmt.Errorf(
			"fixed command %s failed: %w; stderr=%s", executable, err, strings.TrimSpace(stderr.String()),
		)
	}
	return stdout.Bytes(), stderr.Bytes(), nil
}

func captureScopedAppliedJournal(
	ctx context.Context,
	common scopedRealNICCommon,
	state *control.State,
	runtime pinPathRuntime,
) (scopedAppliedJournal, error) {
	status, err := inspectPinOwnershipWithRuntime(ctx, common.PinPath, false, runtime, runtime.exactTCX)
	if err != nil {
		return scopedAppliedJournal{}, err
	}
	if !status.OwnerExists || status.RecoveryRequired || status.ActiveLinkCount != 2 ||
		status.AttachmentBackend != exactTCXBackend || status.OwnerRoot != common.OwnerRoot {
		return scopedAppliedJournal{}, fmt.Errorf("exact owner is not in a steady two-link TCX state: %+v", status)
	}
	recordIdentity, err := snapshotScopedFile(status.RecordPath, 0)
	if err != nil {
		return scopedAppliedJournal{}, fmt.Errorf("snapshot owner record: %w", err)
	}
	indexIdentity, err := snapshotScopedFile(status.IndexPath, 0)
	if err != nil {
		return scopedAppliedJournal{}, fmt.Errorf("snapshot owner index: %w", err)
	}
	kernel, err := scopedInspect(ctx, state, common.PinPath, runtime)
	if err != nil {
		return scopedAppliedJournal{}, fmt.Errorf("inspect exact TCX links: %w", err)
	}
	if kernel == nil || kernel.MapError != "" {
		return scopedAppliedJournal{}, fmt.Errorf("inspect exact TCX links returned incomplete status: %+v", kernel)
	}
	if len(kernel.Underlays) != 1 || len(kernel.Underlays[0].Filters) != 2 ||
		!kernel.Underlays[0].IngressAttached || !kernel.Underlays[0].EgressAttached {
		return scopedAppliedJournal{}, fmt.Errorf("exact TCX link set is incomplete: %+v", kernel.Underlays)
	}
	links := append([]FilterStatus(nil), kernel.Underlays[0].Filters...)
	sort.Slice(links, func(left, right int) bool { return links[left].Direction < links[right].Direction })
	for _, link := range links {
		if link.Backend != exactTCXBackend || link.LinkID == 0 || link.ProgramID == 0 {
			return scopedAppliedJournal{}, fmt.Errorf("exact TCX link identity is incomplete: %+v", link)
		}
	}
	return scopedAppliedJournal{
		Version: 1, Common: common, OwnerRecord: recordIdentity, OwnerIndex: indexIdentity, Links: links,
	}, nil
}

func recheckScopedAppliedJournal(
	common scopedRealNICCommon,
	want scopedAppliedJournal,
	state *control.State,
	runtime pinPathRuntime,
	ctx context.Context,
) error {
	if want.Version != 1 || want.Common != common || len(want.Links) != 2 {
		return errors.New("applied journal does not match the requested run")
	}
	for _, identity := range []scopedFileIdentity{want.OwnerRecord, want.OwnerIndex} {
		if err := recheckScopedFile(identity); err != nil {
			return err
		}
	}
	got, err := captureScopedAppliedJournal(ctx, common, state, runtime)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(got, want) {
		return fmt.Errorf("exact owner/link identity changed: got %+v, want %+v", got, want)
	}
	return nil
}

func recheckScopedAppliedLinks(
	common scopedRealNICCommon,
	want scopedAppliedJournal,
	state *control.State,
	runtime pinPathRuntime,
	ctx context.Context,
) error {
	if want.Version != 1 || want.Common != common || len(want.Links) != 2 {
		return errors.New("applied link journal does not match the requested run")
	}
	kernel, err := scopedInspect(ctx, state, common.PinPath, runtime)
	if err != nil {
		return err
	}
	if kernel == nil || kernel.MapError != "" || len(kernel.Underlays) != 1 || len(kernel.Underlays[0].Filters) != 2 {
		return fmt.Errorf("current exact TCX link status is incomplete: %+v", kernel)
	}
	links := append([]FilterStatus(nil), kernel.Underlays[0].Filters...)
	sort.Slice(links, func(left, right int) bool { return links[left].Direction < links[right].Direction })
	if !reflect.DeepEqual(links, want.Links) {
		return fmt.Errorf("current exact TCX links differ from applied journal: got %+v, want %+v", links, want.Links)
	}
	return nil
}

func captureScopedStatus(
	ctx context.Context,
	path string,
	pinPath string,
	state *control.State,
	runtime pinPathRuntime,
) (*scopedStatusDocument, error) {
	kernel, err := scopedInspect(ctx, state, pinPath, runtime)
	if err != nil {
		return nil, err
	}
	if kernel.MapError != "" {
		return nil, errors.New(kernel.MapError)
	}
	ownership, err := inspectPinOwnershipWithRuntime(ctx, pinPath, false, runtime, runtime.exactTCX)
	if err != nil {
		return nil, err
	}
	document := &scopedStatusDocument{Dataplane: kernel, Ownership: ownership}
	if err := writeJSONExclusive(path, document); err != nil {
		return nil, err
	}
	return document, nil
}

func captureScopedWGTransfer(ctx context.Context, interfaceName, path string) (scopedWGTransfer, error) {
	stdout, stderr, err := runScopedOutput(ctx, scopedWGBinary, "show", interfaceName, "transfer")
	if writeErr := writeBytesExclusive(path, stdout); writeErr != nil {
		return scopedWGTransfer{}, writeErr
	}
	if len(stderr) != 0 {
		if writeErr := writeBytesExclusive(path+".stderr", stderr); writeErr != nil {
			return scopedWGTransfer{}, writeErr
		}
	}
	if err != nil {
		return scopedWGTransfer{}, err
	}
	var result scopedWGTransfer
	lines := strings.Split(strings.TrimSpace(string(stdout)), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return result, errors.New("WireGuard transfer output has no peers")
	}
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 3 || len(fields[0]) != 44 {
			return result, fmt.Errorf("malformed WireGuard transfer line %q", line)
		}
		received, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return result, fmt.Errorf("parse WireGuard received bytes: %w", err)
		}
		sent, err := strconv.ParseUint(fields[2], 10, 64)
		if err != nil {
			return result, fmt.Errorf("parse WireGuard sent bytes: %w", err)
		}
		if ^uint64(0)-result.Received < received || ^uint64(0)-result.Sent < sent {
			return result, errors.New("WireGuard transfer sum overflow")
		}
		result.Received += received
		result.Sent += sent
	}
	return result, nil
}

func validateScopedCounterGrowth(before, after *scopedStatusDocument) error {
	if before == nil || after == nil || before.Dataplane == nil || after.Dataplane == nil {
		return errors.New("dataplane counter documents are incomplete")
	}
	beforeStats, afterStats := before.Dataplane.Stats, after.Dataplane.Stats
	if len(beforeStats) != len(afterStats) {
		return errors.New("dataplane counter schema changed")
	}
	for name, beforeValue := range beforeStats {
		afterValue, exists := afterStats[name]
		if !exists || afterValue < beforeValue {
			return fmt.Errorf("dataplane counter %s disappeared or decreased", name)
		}
	}
	if afterStats["egress_rewrite_ok"] <= beforeStats["egress_rewrite_ok"] ||
		afterStats["ingress_rewrite_ok"] <= beforeStats["ingress_rewrite_ok"] {
		return errors.New("managed traffic did not grow both rewrite-success counters")
	}
	for _, name := range scopedErrorCounterNames() {
		if afterStats[name] != beforeStats[name] {
			return fmt.Errorf("dataplane error counter %s grew by %d", name, afterStats[name]-beforeStats[name])
		}
	}
	return nil
}

func scopedErrorCounterNames() []string {
	return []string{
		// Rule misses are policy/observation counters, not hard dataplane errors.
		// In particular, unrelated physical-NIC UDP can grow ingress_rule_miss.
		"egress_bad_type", "egress_bad_length", "egress_fragment", "egress_ipv6_ext",
		"ingress_bad_type", "ingress_bad_length", "ingress_fragment", "ingress_ipv6_ext",
		"checksum_error", "skb_load_error", "skb_store_error", "icmp_checksum_error",
		"xor_key_missing", "xor_len_overflow", "xor_bad_type_after_decrypt", "xor_load_error", "xor_store_error",
		"xor_csum_error", "ingress_bad_checksum", "egress_bad_checksum", "xor_egress_dispatch_error", "xor_ingress_dispatch_error",
	}
}

func writeBytesExclusive(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create evidence %s: %w", path, err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("write evidence %s: %w", path, err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync evidence %s: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close evidence %s: %w", path, err)
	}
	return nil
}

func writeScopedRestoredMarker(path, cell string) error {
	want := scopedRestoredMarker{Version: 1, Cell: cell, Restored: true}
	if err := writeJSONExclusive(path, want); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrExist) {
		return err
	}
	var existing scopedRestoredMarker
	if err := readJSONFile(path, &existing); err != nil {
		return err
	}
	if existing != want {
		return fmt.Errorf("existing restored marker %s does not match this run", path)
	}
	return nil
}

func executeScopedTraffic(
	ctx context.Context,
	config scopedRealNICConfig,
	state *control.State,
	runtime pinPathRuntime,
	checkerIdentity scopedFileIdentity,
) error {
	trafficCtx, cancelTraffic := context.WithCancel(ctx)
	defer cancelTraffic()
	var monitorDone <-chan error
	if config.Traffic.Profile == "soak" {
		monitorDone = startScopedStatusMonitor(
			trafficCtx, cancelTraffic, config, state, runtime,
		)
	}
	var soakPaths []string
	sequence := 0
	for pass := 1; pass <= config.Traffic.Passes; pass++ {
		for _, streams := range config.Traffic.Streams {
			for _, direction := range config.Traffic.Directions {
				windows := 1
				if config.Traffic.Profile == "soak" {
					windows = config.Traffic.SoakWindows
				}
				for window := 1; window <= windows; window++ {
					sequence++
					label := fmt.Sprintf("traffic-%03d-p%d-s%d-%s-w%d", sequence, pass, streams, direction, window)
					iperfPath := filepath.Join(config.Common.EvidenceRoot, label+".iperf.json")
					pingPath := filepath.Join(config.Common.EvidenceRoot, label+".ping.txt")
					if err := runScopedTrafficSession(trafficCtx, config, streams, direction, iperfPath, pingPath); err != nil {
						cancelTraffic()
						if monitorDone != nil {
							<-monitorDone
						}
						return fmt.Errorf("%s: %w", label, err)
					}
					if err := recheckScopedFile(checkerIdentity); err != nil {
						cancelTraffic()
						return fmt.Errorf("revalidate iperf checker before %s: %w", label, err)
					}
					if err := runScopedChecker(trafficCtx, config.Traffic.CheckerPath,
						[]string{"one", iperfPath, "--direction", direction, "--streams", strconv.Itoa(streams)},
						filepath.Join(config.Common.EvidenceRoot, label+".check.json")); err != nil {
						cancelTraffic()
						return fmt.Errorf("%s acceptance: %w", label, err)
					}
					if config.Traffic.Profile == "soak" {
						soakPaths = append(soakPaths, iperfPath)
					}
				}
			}
		}
	}
	if monitorDone != nil {
		if err := <-monitorDone; err != nil {
			return fmt.Errorf("soak status monitor: %w", err)
		}
	}
	if config.Traffic.Profile == "soak" {
		if err := recheckScopedFile(checkerIdentity); err != nil {
			return fmt.Errorf("revalidate iperf checker before soak summary: %w", err)
		}
		args := append([]string{"soak"}, soakPaths...)
		args = append(args,
			"--expected-windows", strconv.Itoa(config.Traffic.SoakWindows),
			"--streams", strconv.Itoa(config.Traffic.Streams[0]),
		)
		if err := runScopedChecker(trafficCtx, config.Traffic.CheckerPath, args,
			filepath.Join(config.Common.EvidenceRoot, "soak-check.json")); err != nil {
			return fmt.Errorf("soak acceptance: %w", err)
		}
	}
	return nil
}

func runScopedTrafficSession(
	ctx context.Context,
	config scopedRealNICConfig,
	streams int,
	direction string,
	iperfPath string,
	pingPath string,
) error {
	pingCtx, cancelPing := context.WithCancel(ctx)
	pingDone := make(chan error, 1)
	go func() {
		pingDone <- runCapturedCommand(
			pingCtx,
			scopedPingBinary,
			[]string{
				"-4", "-I", config.Common.WGInterface,
				"-i", strconv.Itoa(config.Traffic.PingIntervalSeconds),
				"-c", strconv.Itoa(config.Traffic.SessionSeconds),
				"-W", "2", config.Common.WGPeerAddress,
			},
			pingPath,
		)
	}()
	args := []string{
		"-c", config.Common.WGPeerAddress,
		"-p", strconv.Itoa(config.Common.PeerPort),
		"--connect-timeout", "5000", "--json", "--omit", "2",
		"-t", strconv.Itoa(config.Traffic.SessionSeconds),
		"-P", strconv.Itoa(streams),
		"-B", config.Common.WGLocalAddress,
		"--bind-dev", config.Common.WGInterface,
	}
	switch direction {
	case "forward":
	case "reverse":
		args = append(args, "-R")
	case "bidir":
		args = append(args, "--bidir")
	default:
		cancelPing()
		<-pingDone
		return fmt.Errorf("unsupported traffic direction %q", direction)
	}
	iperfErr := runCapturedCommand(ctx, scopedIperfBinary, args, iperfPath)
	if iperfErr != nil {
		cancelPing()
	}
	pingErr := <-pingDone
	cancelPing()
	if iperfErr != nil || pingErr != nil {
		return errors.Join(iperfErr, pingErr)
	}
	pingBytes, err := os.ReadFile(pingPath)
	if err != nil {
		return fmt.Errorf("read ping evidence: %w", err)
	}
	if err := validateScopedPingEvidence(pingBytes); err != nil {
		return err
	}
	return nil
}

func runCapturedCommand(ctx context.Context, executable string, args []string, stdoutPath string) (returnErr error) {
	stdout, err := os.OpenFile(stdoutPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create command evidence %s: %w", stdoutPath, err)
	}
	stderrPath := stdoutPath + ".stderr"
	stderr, err := os.OpenFile(stderrPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		_ = stdout.Close()
		return fmt.Errorf("create command stderr evidence %s: %w", stderrPath, err)
	}
	defer func() {
		returnErr = errors.Join(returnErr, stdout.Close(), stderr.Close())
	}()
	command := exec.CommandContext(ctx, executable, args...)
	command.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "PYTHONNOUSERSITE=1"}
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("fixed command %s failed: %w", executable, err)
	}
	if err := stdout.Sync(); err != nil {
		return fmt.Errorf("sync command evidence %s: %w", stdoutPath, err)
	}
	if err := stderr.Sync(); err != nil {
		return fmt.Errorf("sync command evidence %s: %w", stderrPath, err)
	}
	return nil
}

func runScopedChecker(ctx context.Context, checkerPath string, args []string, outputPath string) error {
	commandArgs := make([]string, 0, len(args)+1)
	commandArgs = append(commandArgs, checkerPath)
	commandArgs = append(commandArgs, args...)
	return runCapturedCommand(ctx, scopedPythonBinary, commandArgs, outputPath)
}

var scopedPingLossPattern = regexp.MustCompile(`([0-9]+(?:\.[0-9]+)?)% packet loss`)

func validateScopedPingEvidence(data []byte) error {
	matches := scopedPingLossPattern.FindSubmatch(data)
	if len(matches) != 2 {
		return errors.New("ping evidence has no canonical packet-loss summary")
	}
	loss, err := strconv.ParseFloat(string(matches[1]), 64)
	if err != nil || loss > 0.01 {
		return fmt.Errorf("inner-WireGuard ping loss %s%% exceeds 0.01%%", matches[1])
	}
	return nil
}

func startScopedStatusMonitor(
	ctx context.Context,
	cancel context.CancelFunc,
	config scopedRealNICConfig,
	state *control.State,
	runtime pinPathRuntime,
) <-chan error {
	done := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(time.Duration(config.Traffic.MonitorIntervalSeconds) * time.Second)
		defer ticker.Stop()
		for sample := 1; sample <= config.Traffic.MonitorSamples; sample++ {
			select {
			case <-ctx.Done():
				done <- ctx.Err()
				return
			case <-ticker.C:
				path := filepath.Join(config.Common.EvidenceRoot, fmt.Sprintf("status-monitor-%03d.json", sample))
				if _, err := captureScopedStatus(ctx, path, config.Common.PinPath, state, runtime); err != nil {
					cancel()
					done <- err
					return
				}
			}
		}
		done <- nil
	}()
	return done
}
