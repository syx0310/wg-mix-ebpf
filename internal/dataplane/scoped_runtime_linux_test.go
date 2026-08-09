//go:build linux

package dataplane

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/syx0310/wg-mix-ebpf/internal/control"
	"github.com/syx0310/wg-mix-ebpf/internal/lockfile"
)

const (
	scopedBPFFSRunEnv       = "WG_MIX_EBPF_RUN_BPFFS_INTEGRATION"
	scopedBPFFSObjectEnv    = "WG_MIX_EBPF_TEST_OBJECT_PATH"
	scopedBPFFSPinEnv       = "WG_MIX_EBPF_TEST_PIN_PATH"
	scopedBPFFSIfIndexEnv   = "WG_MIX_EBPF_TEST_IFINDEX"
	scopedBPFFSRootEnv      = "WG_MIX_EBPF_TEST_RUNTIME_ROOT"
	scopedBPFFSLockRootEnv  = "WG_MIX_EBPF_TEST_PIN_LOCK_ROOT"
	scopedBPFFSOwnerRootEnv = "WG_MIX_EBPF_TEST_PIN_OWNER_ROOT"
	scopedBPFFSNetNSEnv     = "WG_MIX_EBPF_TEST_INITIAL_NETNS"
	scopedBPFFSActionEnv    = "WG_MIX_EBPF_TEST_ACTION"
	scopedBPFFSPolicyEnv    = "WG_MIX_EBPF_TEST_FAILURE_POLICY"
)

var (
	scopedNetNSPattern = regexp.MustCompile(`^net:\[[1-9][0-9]*\]$`)
	scopedBootPattern  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

type scopedBPFFSIntegrationConfig struct {
	Action       string `json:"action"`
	ObjectPath   string `json:"object_path"`
	PinPath      string `json:"pin_path"`
	IfIndex      int    `json:"ifindex"`
	RuntimeRoot  string `json:"runtime_root"`
	LockRoot     string `json:"lock_root"`
	OwnerRoot    string `json:"owner_root"`
	InitialNetNS string `json:"initial_netns"`
}

type scopedInterfaceIdentity struct {
	Name         string `json:"name"`
	IfIndex      int    `json:"ifindex"`
	HardwareAddr string `json:"hardware_address"`
}

type scopedHostIdentity struct {
	NetNS     string                  `json:"netns"`
	PID1NetNS string                  `json:"pid1_netns"`
	BootID    string                  `json:"boot_id"`
	Interface scopedInterfaceIdentity `json:"interface"`
}

type scopedBPFFSJournal struct {
	Version     int                          `json:"version"`
	Config      scopedBPFFSIntegrationConfig `json:"config"`
	Host        scopedHostIdentity           `json:"host"`
	Object      scopedFileIdentity           `json:"object"`
	RuntimeRoot scopedDirectoryIdentity      `json:"runtime_root_identity"`
	LockRoot    scopedDirectoryIdentity      `json:"lock_root_identity"`
	OwnerRoot   scopedDirectoryIdentity      `json:"owner_root_identity"`
}

type scopedDirectoryIdentity struct {
	Path   string `json:"path"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	Mode   uint32 `json:"mode"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
	NLink  uint64 `json:"nlink"`
}

type scopedFileIdentity struct {
	Path   string `json:"path"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	Mode   uint32 `json:"mode"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
	NLink  uint64 `json:"nlink"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

func TestScopedRealNICContextIsolationContract(t *testing.T) {
	root := t.TempDir()
	leaseRoot := filepath.Join(root, "lease")
	lockRoot := filepath.Join(root, "locks")
	ownerRoot := filepath.Join(root, "owners")
	for _, path := range []string{leaseRoot, lockRoot, ownerRoot} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatalf("create scoped contract directory %s: %v", path, err)
		}
	}
	leasePath := filepath.Join(leaseRoot, "daemon.lease")
	gatePath := filepath.Join(leaseRoot, "maintenance.gate")
	ctx := lockfile.WithLifecyclePathsForTest(t.Context(), leasePath, gatePath)
	if got := lockfile.LifecycleLeasePath(ctx); got != leasePath {
		t.Fatalf("scoped lifecycle lease = %q, want %q", got, leasePath)
	}
	if got := lockfile.LifecycleMaintenancePath(ctx); got != gatePath {
		t.Fatalf("scoped lifecycle gate = %q, want %q", got, gatePath)
	}
	if leasePath == lockfile.DefaultLifecycleLeasePath ||
		pathWithin(leasePath, filepath.Dir(lockfile.DefaultLifecycleLeasePath)) {
		t.Fatalf("scoped lifecycle lease escaped to the production runtime: %s", leasePath)
	}

	runtime, err := newScopedLinuxLoaderRuntime(lockRoot, ownerRoot)
	if err != nil {
		t.Fatal(err)
	}
	loader := LinuxLoader{runtime: runtime}
	gotRuntime := loader.pinRuntime(ctx)
	if gotRuntime.lockRoot != lockRoot || gotRuntime.ownerRoot != ownerRoot {
		t.Fatalf(
			"scoped loader roots = lock %q owner %q, want %q and %q",
			gotRuntime.lockRoot,
			gotRuntime.ownerRoot,
			lockRoot,
			ownerRoot,
		)
	}
	if gotRuntime.bpffsRootMode != 0 {
		t.Fatalf("real-bpffs scoped runtime mode = %#o, want existing mount mode accepted", gotRuntime.bpffsRootMode)
	}
	if gotRuntime.lockRoot == pinPathLockRoot || gotRuntime.ownerRoot == pinOwnerRoot {
		t.Fatalf("scoped loader resolved a production root: %+v", gotRuntime)
	}

	err = lockfile.WithLifecycle(ctx, nil, lockfile.LifecycleOwner{
		PID:    os.Getpid(),
		Action: "scoped-realnic-contract",
		RunDir: root,
	}, func(lease *lockfile.LifecycleLease) error {
		if !lease.HeldAt(leasePath) {
			return fmt.Errorf("test lifecycle lease is not held at %s", leasePath)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("hold scoped lifecycle contract: %v", err)
	}
	for _, path := range []string{leasePath, gatePath} {
		if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() {
			t.Fatalf("scoped lifecycle artifact %s is not a regular file: info=%v err=%v", path, info, err)
		}
	}

	objectPath := filepath.Join(root, "wg_mix_tc.o")
	if err := os.WriteFile(objectPath, []byte("contract-only"), 0o600); err != nil {
		t.Fatal(err)
	}
	runtimeRoot := filepath.Join(root, "standalone-runtime")
	contractPin := "/sys/fs/bpf/wg-mix-ebpf-contract-only"
	setScopedBPFFSContractEnv(t, scopedBPFFSIntegrationConfig{
		Action:       "run",
		ObjectPath:   objectPath,
		PinPath:      contractPin,
		IfIndex:      1,
		RuntimeRoot:  runtimeRoot,
		LockRoot:     filepath.Join(runtimeRoot, "locks"),
		OwnerRoot:    filepath.Join(runtimeRoot, "owners"),
		InitialNetNS: "net:[1]",
	})
	config, err := scopedBPFFSConfigFromEnv()
	if err != nil {
		t.Fatalf("parse standalone scoped runtime contract: %v", err)
	}
	standaloneRuntime, err := newScopedLinuxLoaderRuntime(config.LockRoot, config.OwnerRoot)
	if err != nil {
		t.Fatal(err)
	}
	standaloneLoader := LinuxLoader{runtime: standaloneRuntime}
	if got := standaloneLoader.pinRuntime(t.Context()); got.lockRoot != config.LockRoot || got.ownerRoot != config.OwnerRoot {
		t.Fatalf("standalone integration did not honor explicit roots: %+v", got)
	}

	realNICRoot := filepath.Join(root, "scoped-realnic-original")
	realNICCommon := scopedRealNICCommon{
		RunID: scopedRealNICRunID, Cell: "original", Root: realNICRoot,
		StateRoot: filepath.Join(realNICRoot, "state"), LeaseRoot: filepath.Join(realNICRoot, "lease"),
		OwnerRoot: filepath.Join(realNICRoot, "owners"), EvidenceRoot: filepath.Join(realNICRoot, "evidence"),
		PinPath: "/sys/fs/bpf/wg-mix-ebpf-c8e41d73-nic-original",
	}
	if err := validateScopedRealNICLayout(realNICCommon); err != nil {
		t.Fatalf("real-NIC scoped layout contract: %v", err)
	}
	realNICLockRoot := filepath.Join(realNICCommon.LeaseRoot, "pin-locks")
	realNICRuntime, err := newScopedLinuxLoaderRuntime(realNICLockRoot, realNICCommon.OwnerRoot)
	if err != nil {
		t.Fatal(err)
	}
	gotRealNICRuntime := (LinuxLoader{runtime: realNICRuntime}).pinRuntime(t.Context())
	if gotRealNICRuntime.lockRoot != realNICLockRoot || gotRealNICRuntime.ownerRoot != realNICCommon.OwnerRoot ||
		gotRealNICRuntime.lockRoot == pinPathLockRoot || gotRealNICRuntime.ownerRoot == pinOwnerRoot {
		t.Fatalf("real-NIC integration runtime escaped scoped roots: %+v", gotRealNICRuntime)
	}
}

func setScopedBPFFSContractEnv(t *testing.T, config scopedBPFFSIntegrationConfig) {
	t.Helper()
	values := map[string]string{
		scopedBPFFSObjectEnv:    config.ObjectPath,
		scopedBPFFSPinEnv:       config.PinPath,
		scopedBPFFSIfIndexEnv:   strconv.Itoa(config.IfIndex),
		scopedBPFFSRootEnv:      config.RuntimeRoot,
		scopedBPFFSLockRootEnv:  config.LockRoot,
		scopedBPFFSOwnerRootEnv: config.OwnerRoot,
		scopedBPFFSNetNSEnv:     config.InitialNetNS,
		scopedBPFFSActionEnv:    config.Action,
		scopedBPFFSPolicyEnv:    "retain",
	}
	for name, value := range values {
		t.Setenv(name, value)
	}
}

func scopedBPFFSConfigFromEnv() (scopedBPFFSIntegrationConfig, error) {
	config := scopedBPFFSIntegrationConfig{
		Action:       os.Getenv(scopedBPFFSActionEnv),
		ObjectPath:   os.Getenv(scopedBPFFSObjectEnv),
		PinPath:      os.Getenv(scopedBPFFSPinEnv),
		RuntimeRoot:  os.Getenv(scopedBPFFSRootEnv),
		LockRoot:     os.Getenv(scopedBPFFSLockRootEnv),
		OwnerRoot:    os.Getenv(scopedBPFFSOwnerRootEnv),
		InitialNetNS: os.Getenv(scopedBPFFSNetNSEnv),
	}
	if config.Action != "run" && config.Action != "restore" {
		return config, fmt.Errorf("%s must be run or restore", scopedBPFFSActionEnv)
	}
	if os.Getenv(scopedBPFFSPolicyEnv) != "retain" {
		return config, fmt.Errorf("%s must be retain", scopedBPFFSPolicyEnv)
	}
	for name, path := range map[string]string{
		scopedBPFFSObjectEnv:    config.ObjectPath,
		scopedBPFFSPinEnv:       config.PinPath,
		scopedBPFFSRootEnv:      config.RuntimeRoot,
		scopedBPFFSLockRootEnv:  config.LockRoot,
		scopedBPFFSOwnerRootEnv: config.OwnerRoot,
	} {
		if err := validateCleanAbsolutePath(name, path); err != nil {
			return config, err
		}
	}
	if config.LockRoot != filepath.Join(config.RuntimeRoot, "locks") {
		return config, fmt.Errorf("%s must be the exact locks child of %s", scopedBPFFSLockRootEnv, scopedBPFFSRootEnv)
	}
	if config.OwnerRoot != filepath.Join(config.RuntimeRoot, "owners") {
		return config, fmt.Errorf("%s must be the exact owners child of %s", scopedBPFFSOwnerRootEnv, scopedBPFFSRootEnv)
	}
	if err := rejectProductionStatePath(config.RuntimeRoot); err != nil {
		return config, err
	}
	if filepath.Dir(config.PinPath) != "/sys/fs/bpf" || !validPinPathBase(filepath.Base(config.PinPath)) {
		return config, fmt.Errorf("%s must be a direct valid wg-mix-ebpf bpffs child", scopedBPFFSPinEnv)
	}
	if !scopedNetNSPattern.MatchString(config.InitialNetNS) {
		return config, fmt.Errorf("%s must be an exact net:[N] identity", scopedBPFFSNetNSEnv)
	}
	ifindex, err := strconv.Atoi(os.Getenv(scopedBPFFSIfIndexEnv))
	if err != nil || ifindex <= 0 {
		return config, fmt.Errorf("%s must be a positive integer", scopedBPFFSIfIndexEnv)
	}
	config.IfIndex = ifindex
	return config, nil
}

func runScopedBPFFSIntegration(t *testing.T, config scopedBPFFSIntegrationConfig) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("explicit bpffs integration test requires root")
	}
	if config.Action == "restore" {
		restoreScopedBPFFSIntegration(t, config)
		return
	}
	if err := validateNoSymlinkDirectoryChain(filepath.Dir(config.RuntimeRoot)); err != nil {
		t.Fatal(err)
	}
	if err := validatePrivateOwnedDirectory(filepath.Dir(config.RuntimeRoot), 0); err != nil {
		t.Fatalf("validate scoped bpffs runtime parent: %v", err)
	}
	objectIdentity, err := snapshotScopedFile(config.ObjectPath, 0)
	if err != nil {
		t.Fatalf("validate explicit BPF object: %v", err)
	}
	if _, err := os.Lstat(config.RuntimeRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("refuse run because scoped runtime root already exists: %s: %v", config.RuntimeRoot, err)
	}
	if _, err := os.Lstat(config.PinPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("refuse run because pin path already exists: %s: %v", config.PinPath, err)
	}
	if err := createPrivateDirectory(config.RuntimeRoot); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{config.LockRoot, config.OwnerRoot} {
		if err := createPrivateDirectory(path); err != nil {
			t.Fatal(err)
		}
	}

	runtimeIdentity, err := snapshotScopedDirectory(config.RuntimeRoot, 0)
	if err != nil {
		t.Fatal(err)
	}
	lockIdentity, err := snapshotScopedDirectory(config.LockRoot, 0)
	if err != nil {
		t.Fatal(err)
	}
	ownerIdentity, err := snapshotScopedDirectory(config.OwnerRoot, 0)
	if err != nil {
		t.Fatal(err)
	}
	host, err := snapshotScopedHost(config.IfIndex)
	if err != nil {
		t.Fatal(err)
	}
	if host.NetNS != config.InitialNetNS {
		t.Fatalf("initial network namespace = %q, want %q", host.NetNS, config.InitialNetNS)
	}
	journal := scopedBPFFSJournal{
		Version: 1, Config: config, Host: host, Object: objectIdentity,
		RuntimeRoot: runtimeIdentity, LockRoot: lockIdentity, OwnerRoot: ownerIdentity,
	}
	journalPath := filepath.Join(config.RuntimeRoot, "bpffs-journal.v1.json")
	if err := writeJSONExclusive(journalPath, journal); err != nil {
		t.Fatal(err)
	}

	runtime, err := newScopedLinuxLoaderRuntime(config.LockRoot, config.OwnerRoot)
	if err != nil {
		t.Fatal(err)
	}
	loader := LinuxLoader{ObjectPath: config.ObjectPath, PinPath: config.PinPath, runtime: runtime}
	state := &control.State{Underlays: []control.UnderlayState{{
		Name:     "approved-bpffs-integration",
		IfIndex:  config.IfIndex,
		Role:     "transform",
		Resolved: true,
	}}}

	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	ctx = lockfile.WithLifecyclePathsForTest(
		ctx,
		filepath.Join(config.RuntimeRoot, "daemon.lease"),
		filepath.Join(config.RuntimeRoot, "maintenance.gate"),
	)
	err = lockfile.WithLifecycle(ctx, nil, lockfile.LifecycleOwner{
		PID:    os.Getpid(),
		Action: "bpffs-integration-run",
		RunDir: config.RuntimeRoot,
	}, func(_ *lockfile.LifecycleLease) error {
		if err := recheckScopedHost(host); err != nil {
			return fmt.Errorf("pre-apply host identity: %w", err)
		}
		if err := loader.Apply(ctx, state); err != nil {
			return fmt.Errorf("apply test collection: %w", err)
		}
		first, err := scopedInspect(ctx, state, config.PinPath, *runtime)
		if err != nil {
			return fmt.Errorf("inspect first exact TCX apply: %w", err)
		}
		if first == nil || first.MapError != "" || len(first.Underlays) != 1 || len(first.Underlays[0].Filters) != 2 {
			return fmt.Errorf("inspect first exact TCX apply returned incomplete status: %+v", first)
		}
		firstByDirection := make(map[string]FilterStatus, 2)
		for _, filter := range first.Underlays[0].Filters {
			if filter.Backend != exactTCXBackend || filter.LinkID == 0 || filter.ProgramID == 0 {
				return fmt.Errorf("first apply returned incomplete exact TCX filter: %+v", filter)
			}
			firstByDirection[filter.Direction] = filter
		}
		if len(firstByDirection) != 2 {
			return fmt.Errorf("first exact TCX apply did not expose both directions: %+v", first.Underlays[0].Filters)
		}
		if err := loader.Apply(ctx, state); err != nil {
			return fmt.Errorf("compare-update test collection: %w", err)
		}
		second, err := scopedInspect(ctx, state, config.PinPath, *runtime)
		if err != nil {
			return fmt.Errorf("inspect compare-updated exact TCX apply: %w", err)
		}
		if second == nil || second.MapError != "" || len(second.Underlays) != 1 || len(second.Underlays[0].Filters) != 2 {
			return fmt.Errorf("inspect compare-updated exact TCX apply returned incomplete status: %+v", second)
		}
		for _, filter := range second.Underlays[0].Filters {
			previous, ok := firstByDirection[filter.Direction]
			if !ok || filter.LinkID != previous.LinkID || filter.ProgramID == 0 || filter.ProgramID == previous.ProgramID {
				return fmt.Errorf("exact TCX update did not preserve link/switch program: before=%+v after=%+v", previous, filter)
			}
		}
		if err := recheckScopedHost(host); err != nil {
			return fmt.Errorf("pre-detach host identity: %w", err)
		}
		if err := loader.Detach(ctx, state); err != nil {
			return fmt.Errorf("exact detach test collection: %w", err)
		}
		return recheckScopedHost(host)
	})
	if err != nil {
		t.Fatalf("scoped bpffs integration failed; evidence retained at %s: %v", config.RuntimeRoot, err)
	}
	if _, err := os.Lstat(config.PinPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("test pin path still exists or cannot be inspected: %v", err)
	}
	if err := writeJSONExclusive(filepath.Join(config.RuntimeRoot, "bpffs-restored.v1.json"), journal); err != nil {
		t.Fatal(err)
	}
	fmt.Println("SCOPED_BPFFS_COMPLETE restored=1")
}

func restoreScopedBPFFSIntegration(t *testing.T, config scopedBPFFSIntegrationConfig) {
	t.Helper()
	if err := validateNoSymlinkDirectoryChain(config.RuntimeRoot); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{config.RuntimeRoot, config.LockRoot, config.OwnerRoot} {
		if err := validatePrivateOwnedDirectory(path, uint32(os.Geteuid())); err != nil {
			t.Fatal(err)
		}
	}
	var journal scopedBPFFSJournal
	if err := readJSONFile(filepath.Join(config.RuntimeRoot, "bpffs-journal.v1.json"), &journal); err != nil {
		t.Fatal(err)
	}
	runConfig := config
	runConfig.Action = "run"
	if journal.Version != 1 || journal.Config != runConfig {
		t.Fatal("scoped bpffs restore environment does not exactly match the run journal")
	}
	if err := recheckScopedFile(journal.Object); err != nil {
		t.Fatalf("revalidate BPF object: %v", err)
	}
	for _, identity := range []scopedDirectoryIdentity{journal.RuntimeRoot, journal.LockRoot, journal.OwnerRoot} {
		if err := recheckScopedDirectory(identity); err != nil {
			t.Fatalf("revalidate scoped runtime directory: %v", err)
		}
	}
	if err := recheckScopedHost(journal.Host); err != nil {
		t.Fatalf("pre-restore host identity: %v", err)
	}
	runtime, err := newScopedLinuxLoaderRuntime(config.LockRoot, config.OwnerRoot)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	ctx = lockfile.WithLifecyclePathsForTest(
		ctx,
		filepath.Join(config.RuntimeRoot, "daemon.lease"),
		filepath.Join(config.RuntimeRoot, "maintenance.gate"),
	)
	loader := LinuxLoader{ObjectPath: config.ObjectPath, PinPath: config.PinPath, runtime: runtime}
	err = lockfile.WithLifecycle(ctx, nil, lockfile.LifecycleOwner{
		PID:    os.Getpid(),
		Action: "bpffs-integration-restore",
		RunDir: config.RuntimeRoot,
	}, func(_ *lockfile.LifecycleLease) error {
		if err := recheckScopedHost(journal.Host); err != nil {
			return err
		}
		status, inspectErr := inspectPinOwnershipWithRuntime(ctx, config.PinPath, false, *runtime, runtime.exactTCX)
		if inspectErr != nil {
			return fmt.Errorf("verify exact owner journal before restore: %w", inspectErr)
		}
		if status.PinPath != config.PinPath || status.OwnerRoot != config.OwnerRoot || status.IndexPath != filepath.Join(config.OwnerRoot, pinOwnerIndexFileName) {
			return fmt.Errorf("owner journal escaped scoped roots: %+v", status)
		}
		if err := loader.Detach(ctx, nil); err != nil {
			return fmt.Errorf("restore exact TCX owner: %w", err)
		}
		return recheckScopedHost(journal.Host)
	})
	if err != nil {
		t.Fatalf("scoped bpffs restore failed; evidence retained at %s: %v", config.RuntimeRoot, err)
	}
	if _, err := os.Lstat(config.PinPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("restored pin path still exists or cannot be inspected: %v", err)
	}
	if err := writeJSONExclusive(filepath.Join(config.RuntimeRoot, "bpffs-explicit-restore.v1.json"), journal); err != nil {
		t.Fatal(err)
	}
	fmt.Println("SCOPED_BPFFS_RESTORE_COMPLETE restored=1")
}

func newScopedLinuxLoaderRuntime(lockRoot, ownerRoot string) (*pinPathRuntime, error) {
	for name, path := range map[string]string{"pin lock root": lockRoot, "pin owner root": ownerRoot} {
		if err := validateCleanAbsolutePath(name, path); err != nil {
			return nil, err
		}
		if err := rejectProductionStatePath(path); err != nil {
			return nil, err
		}
	}
	runtime := livePinPathRuntime
	runtime.lockRoot = lockRoot
	runtime.ownerRoot = ownerRoot
	// The real-host tests use the already-mounted global bpffs. Its mount root
	// is not test-owned, so only the unique direct child is required to be 0700.
	runtime.bpffsRootMode = 0
	return &runtime, nil
}

func scopedInspect(ctx context.Context, state *control.State, pinPath string, runtime pinPathRuntime) (*KernelStatus, error) {
	if ctx == nil {
		return nil, errors.New("inspect context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if state == nil {
		return nil, errors.New("inspect control state is nil")
	}
	status := &KernelStatus{PinPath: pinPath}
	activeLinks, mapErr := scopedInspectPinnedMaps(ctx, status, runtime)
	if mapErr != nil {
		status.MapError = mapErr.Error()
	}
	linksBySlot := make(map[string]exactTCXBinding, len(activeLinks))
	for _, binding := range activeLinks {
		linksBySlot[exactTCXOwnerKey(binding)] = binding
	}
	for _, underlay := range state.Underlays {
		if !underlay.Resolved || underlay.IfIndex == 0 || underlay.Role == "disabled" {
			continue
		}
		entry := UnderlayKernelStatus{Name: underlay.Name, IfIndex: underlay.IfIndex, IfName: underlay.IfName}
		for _, direction := range []exactTCXDirection{exactTCXIngress, exactTCXEgress} {
			binding, exists := linksBySlot[exactTCXOwnerKey(exactTCXBinding{IfIndex: underlay.IfIndex, Direction: direction})]
			if !exists {
				continue
			}
			entry.Filters = append(entry.Filters, FilterStatus{
				Direction: string(direction), Name: binding.PinName, Backend: binding.Backend,
				AttachType: binding.AttachType, LinkID: binding.LinkID, ProgramID: binding.ProgramID,
			})
			if direction == exactTCXIngress {
				entry.IngressAttached = true
			} else {
				entry.EgressAttached = true
			}
		}
		status.Underlays = append(status.Underlays, entry)
	}
	return status, nil
}

func scopedInspectPinnedMaps(ctx context.Context, status *KernelStatus, runtime pinPathRuntime) ([]exactTCXBinding, error) {
	validated, err := validatePinPath(status.PinPath, runtime.validator)
	if err != nil {
		return nil, err
	}
	if !validated.exists {
		return nil, nil
	}
	parent, err := openPinPathParent(status.PinPath, validated, runtime)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	lock, err := acquirePinPathLock(ctx, parent.resource, "scoped-status", runtime)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	validated, err = validatePinPath(status.PinPath, runtime.validator)
	if err != nil {
		return nil, err
	}
	handle, _, err := openPinPathHandleFromParent(parent, validated, false)
	if err != nil {
		return nil, err
	}
	if handle == nil {
		return nil, nil
	}
	defer handle.Close()
	store, err := openPinOwnerStoreWithPolicy(runtime, handle.resource, false, false)
	if err != nil {
		return nil, fmt.Errorf("open persistent BPF pin owner: %w", err)
	}
	defer store.Close()
	record, exists, err := store.LoadOptional(handle.mountID)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.New("BPF pins have no persistent owner record")
	}
	if record.Phase != pinOwnerPhaseActive || record.Step != pinOwnerStepReady {
		return nil, fmt.Errorf("BPF owner transaction is %s/%s at sequence %d; status is not steady", record.Phase, record.Step, record.Sequence)
	}
	if err := validateOwnerDirectoryEntries(handle, record); err != nil {
		return nil, err
	}
	pins, err := inspectPinnedMapSet(handle, true)
	if err != nil {
		return nil, err
	}
	defer closePinnedMapPins(pins)
	if err := validateOwnerPins(handle, record, pins, true); err != nil {
		return nil, err
	}
	controlValue, err := ownerControlValue(pins)
	if err != nil {
		return nil, err
	}
	if err := validateOwnerControlGeneration(pins, record.ActiveGeneration); err != nil {
		return nil, err
	}
	if err := validateOwnerExactTCXLinks(handle, record.ActiveLinks, runtime.exactTCX); err != nil {
		return nil, err
	}
	status.ActiveGeneration = controlValue.ActiveGeneration
	status.ABIVersion = controlValue.ABIVersion
	stats, err := ebpf.LoadPinnedMap(filepath.Join(handle.procPath(), "stats_map"), nil)
	if err != nil {
		return nil, fmt.Errorf("load pinned stats_map: %w", err)
	}
	defer stats.Close()
	status.Stats = make(map[string]uint64, len(statNames))
	for key, name := range statNames {
		var values []uint64
		if err := stats.Lookup(uint32(key), &values); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				continue
			}
			return nil, fmt.Errorf("lookup stats_map[%s]: %w", name, err)
		}
		for _, value := range values {
			status.Stats[name] += value
		}
	}
	return append([]exactTCXBinding(nil), record.ActiveLinks...), nil
}

func snapshotScopedHost(ifindex int) (scopedHostIdentity, error) {
	netns, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return scopedHostIdentity{}, fmt.Errorf("read current network namespace: %w", err)
	}
	if !scopedNetNSPattern.MatchString(netns) {
		return scopedHostIdentity{}, fmt.Errorf("current network namespace identity is malformed: %q", netns)
	}
	pid1NetNS, err := os.Readlink("/proc/1/ns/net")
	if err != nil {
		return scopedHostIdentity{}, fmt.Errorf("read PID 1 network namespace: %w", err)
	}
	if !scopedNetNSPattern.MatchString(pid1NetNS) {
		return scopedHostIdentity{}, fmt.Errorf("PID 1 network namespace identity is malformed: %q", pid1NetNS)
	}
	if netns != pid1NetNS {
		return scopedHostIdentity{}, fmt.Errorf("test is not in the initial network namespace: self=%s pid1=%s", netns, pid1NetNS)
	}
	bootBytes, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return scopedHostIdentity{}, fmt.Errorf("read boot ID: %w", err)
	}
	bootID := strings.TrimSpace(string(bootBytes))
	if !scopedBootPattern.MatchString(bootID) {
		return scopedHostIdentity{}, fmt.Errorf("boot ID is malformed: %q", bootID)
	}
	iface, err := net.InterfaceByIndex(ifindex)
	if err != nil {
		return scopedHostIdentity{}, fmt.Errorf("resolve interface index %d: %w", ifindex, err)
	}
	return scopedHostIdentity{
		NetNS:     netns,
		PID1NetNS: pid1NetNS,
		BootID:    bootID,
		Interface: scopedInterfaceIdentity{
			Name: iface.Name, IfIndex: iface.Index, HardwareAddr: strings.ToLower(iface.HardwareAddr.String()),
		},
	}, nil
}

func recheckScopedHost(want scopedHostIdentity) error {
	got, err := snapshotScopedHost(want.Interface.IfIndex)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("host identity changed: got %+v, want %+v", got, want)
	}
	return nil
}

func validateCleanAbsolutePath(name, path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("%s must be a non-empty clean absolute path", name)
	}
	return nil
}

func rejectProductionStatePath(path string) error {
	for _, root := range []string{"/run/wg-mix-ebpf", "/var/lib/wg-mix-ebpf"} {
		if pathWithin(path, root) {
			return fmt.Errorf("scoped test path %s resolves inside forbidden production root %s", path, root)
		}
	}
	return nil
}

func pathWithin(path, root string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func createPrivateDirectory(path string) error {
	if err := validateCleanAbsolutePath("private directory", path); err != nil {
		return err
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		return fmt.Errorf("create private directory %s: %w", path, err)
	}
	return validatePrivateOwnedDirectory(path, uint32(os.Geteuid()))
}

func validatePrivateOwnedDirectory(path string, expectedUID uint32) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect private directory %s: %w", path, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return fmt.Errorf("private directory %s has unsafe type or mode %s", path, info.Mode())
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("private directory %s has no Linux stat identity", path)
	}
	if stat.Uid != expectedUID {
		return fmt.Errorf("private directory %s uid=%d, want %d", path, stat.Uid, expectedUID)
	}
	return nil
}

func snapshotScopedDirectory(path string, expectedUID uint32) (scopedDirectoryIdentity, error) {
	if err := validatePrivateOwnedDirectory(path, expectedUID); err != nil {
		return scopedDirectoryIdentity{}, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return scopedDirectoryIdentity{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return scopedDirectoryIdentity{}, fmt.Errorf("directory %s has no Linux stat identity", path)
	}
	if stat.Nlink == 0 {
		return scopedDirectoryIdentity{}, fmt.Errorf("directory %s has zero links", path)
	}
	return scopedDirectoryIdentity{
		Path: path, Device: uint64(stat.Dev), Inode: stat.Ino, Mode: stat.Mode,
		UID: stat.Uid, GID: stat.Gid, NLink: uint64(stat.Nlink),
	}, nil
}

func recheckScopedDirectory(want scopedDirectoryIdentity) error {
	got, err := snapshotScopedDirectory(want.Path, want.UID)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("directory identity changed: got %+v, want %+v", got, want)
	}
	return nil
}

func snapshotScopedFile(path string, expectedUID uint32) (scopedFileIdentity, error) {
	if err := validateCleanAbsolutePath("scoped artifact", path); err != nil {
		return scopedFileIdentity{}, err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return scopedFileIdentity{}, fmt.Errorf("inspect scoped artifact %s: %w", path, err)
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm()&0o022 != 0 {
		return scopedFileIdentity{}, fmt.Errorf("scoped artifact %s has unsafe type or mode %s", path, before.Mode())
	}
	file, err := os.Open(path)
	if err != nil {
		return scopedFileIdentity{}, fmt.Errorf("open scoped artifact %s: %w", path, err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return scopedFileIdentity{}, fmt.Errorf("stat opened scoped artifact %s: %w", path, err)
	}
	beforeStat, beforeOK := before.Sys().(*syscall.Stat_t)
	openedStat, openedOK := opened.Sys().(*syscall.Stat_t)
	if !beforeOK || !openedOK {
		return scopedFileIdentity{}, fmt.Errorf("scoped artifact %s has no Linux stat identity", path)
	}
	if beforeStat.Dev != openedStat.Dev || beforeStat.Ino != openedStat.Ino || openedStat.Nlink != 1 || openedStat.Uid != expectedUID {
		return scopedFileIdentity{}, fmt.Errorf("scoped artifact %s identity or ownership is unsafe", path)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return scopedFileIdentity{}, fmt.Errorf("hash scoped artifact %s: %w", path, err)
	}
	after, err := file.Stat()
	if err != nil {
		return scopedFileIdentity{}, fmt.Errorf("restat scoped artifact %s: %w", path, err)
	}
	afterStat, ok := after.Sys().(*syscall.Stat_t)
	if !ok || !sameScopedFileStat(openedStat, afterStat) {
		return scopedFileIdentity{}, fmt.Errorf("scoped artifact %s changed while hashing", path)
	}
	afterPath, err := os.Lstat(path)
	if err != nil {
		return scopedFileIdentity{}, fmt.Errorf("reinspect scoped artifact %s: %w", path, err)
	}
	afterPathStat, ok := afterPath.Sys().(*syscall.Stat_t)
	if !ok || !afterPath.Mode().IsRegular() || afterPath.Mode()&os.ModeSymlink != 0 ||
		!sameScopedFileStat(openedStat, afterPathStat) {
		return scopedFileIdentity{}, fmt.Errorf("scoped artifact %s pathname identity changed while hashing", path)
	}
	return scopedFileIdentity{
		Path: path, Device: uint64(openedStat.Dev), Inode: openedStat.Ino, Mode: openedStat.Mode,
		UID: openedStat.Uid, GID: openedStat.Gid, NLink: uint64(openedStat.Nlink),
		Size: opened.Size(), SHA256: fmt.Sprintf("%x", hash.Sum(nil)),
	}, nil
}

func sameScopedFileStat(left, right *syscall.Stat_t) bool {
	return left != nil && right != nil &&
		left.Dev == right.Dev && left.Ino == right.Ino && left.Mode == right.Mode &&
		left.Uid == right.Uid && left.Gid == right.Gid && left.Nlink == right.Nlink &&
		left.Size == right.Size && left.Mtim == right.Mtim && left.Ctim == right.Ctim
}

func recheckScopedFile(want scopedFileIdentity) error {
	got, err := snapshotScopedFile(want.Path, want.UID)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("file identity changed: got %+v, want %+v", got, want)
	}
	return nil
}

func writeJSONExclusive(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode evidence %s: %w", path, err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create evidence %s: %w", path, err)
	}
	if _, err := file.Write(append(data, '\n')); err != nil {
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

func readJSONFile(path string, destination any) error {
	before, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect journal %s: %w", path, err)
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("journal %s has unsafe type or mode %s", path, before.Mode())
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open journal %s: %w", path, err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat opened journal %s: %w", path, err)
	}
	beforeStat, beforeOK := before.Sys().(*syscall.Stat_t)
	openedStat, openedOK := opened.Sys().(*syscall.Stat_t)
	if !beforeOK || !openedOK || !sameScopedFileStat(beforeStat, openedStat) || openedStat.Nlink != 1 {
		return fmt.Errorf("journal %s pathname and opened identity differ", path)
	}
	data, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("read journal %s: %w", path, err)
	}
	after, err := file.Stat()
	if err != nil {
		return fmt.Errorf("restat journal %s: %w", path, err)
	}
	afterStat, ok := after.Sys().(*syscall.Stat_t)
	if !ok || !sameScopedFileStat(openedStat, afterStat) {
		return fmt.Errorf("journal %s changed while reading", path)
	}
	afterPath, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("reinspect journal %s: %w", path, err)
	}
	afterPathStat, ok := afterPath.Sys().(*syscall.Stat_t)
	if !ok || !afterPath.Mode().IsRegular() || afterPath.Mode()&os.ModeSymlink != 0 ||
		!sameScopedFileStat(openedStat, afterPathStat) {
		return fmt.Errorf("journal %s pathname identity changed while reading", path)
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode journal %s: %w", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("decode journal %s: trailing JSON value", path)
		}
		return fmt.Errorf("decode journal %s trailing data: %w", path, err)
	}
	return nil
}
