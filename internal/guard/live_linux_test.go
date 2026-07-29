//go:build linux && realhosttest

package guard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/control"
)

const (
	liveGuardRunPrefix = "/var/lib/wg-mix-ebpf-test-runs"
	liveGuardEnabled   = "WG_MIX_EBPF_LIVE_GUARD"
)

var liveGuardRunIDPattern = regexp.MustCompile(`^g[0-9]{8}t[0-9]{6}z-[0-9a-f]{12}$`)

// liveGuardBuiltCommit must be set by -ldflags -X when building the privileged
// test binary. The runtime harness compares it with its reviewed candidate.
var liveGuardBuiltCommit = "unset"

func TestLiveGuardOwnership(t *testing.T) {
	if os.Getenv(liveGuardEnabled) != "1" {
		t.Skip("live guard mutation requires the locked realhost harness")
	}
	if os.Geteuid() != 0 {
		t.Fatal("live guard ownership test must run as root")
	}

	runID := requiredLiveGuardEnv(t, "WG_MIX_EBPF_LIVE_GUARD_RUN_ID")
	if !liveGuardRunIDPattern.MatchString(runID) {
		t.Fatalf("invalid live guard run ID %q", runID)
	}
	stateDir := requiredLiveGuardEnv(t, "WG_MIX_EBPF_LIVE_GUARD_STATE_DIR")
	wantStateDir := filepath.Join(liveGuardRunPrefix, runID, "state")
	if stateDir != wantStateDir || filepath.Clean(stateDir) != stateDir {
		t.Fatalf("live guard state directory = %q, want %q", stateDir, wantStateDir)
	}
	commit := requiredLiveGuardEnv(t, "WG_MIX_EBPF_LIVE_GUARD_CANDIDATE_COMMIT")
	if matched, _ := regexp.MatchString(`^[0-9a-f]{40}$`, commit); !matched {
		t.Fatalf("invalid candidate commit %q", commit)
	}
	if liveGuardBuiltCommit != commit {
		t.Fatalf(
			"test binary was built for commit %q, harness requested %q",
			liveGuardBuiltCommit,
			commit,
		)
	}
	requireLiveGuardHostIdentity(t)

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if tables := listProjectGuardTables(t, ctx); len(tables) != 0 {
		t.Fatalf("refuse live guard test with pre-existing project tables: %v", tables)
	}

	plan := BuildNftPlan(&control.State{})
	if len(plan.Rules) != 0 {
		t.Fatalf("live guard plan must be empty, got rules %v", plan.Rules)
	}
	executor := NewCommandExecutor(stateDir)

	t.Logf("candidate=%s phase=create state_dir=%s", commit, stateDir)
	if err := executor.Apply(ctx, plan); err != nil {
		t.Fatalf("create empty owned guard: %v", err)
	}
	firstOwner, present, err := executor.loadOwnerIfPresent()
	if err != nil {
		t.Fatalf("load first owner record: %v", err)
	}
	if !present {
		t.Fatal("first apply did not persist an owner record")
	}
	firstOwnerData := readLiveOwnerRecord(t, stateDir)
	firstOwnerDigest := sha256.Sum256(firstOwnerData)
	firstIdentity, err := executor.inspect(ctx, firstOwner.Table)
	if err != nil {
		t.Fatalf("inspect first owned table: %v", err)
	}
	if err := requireOwnedTable(firstOwner, firstIdentity); err != nil {
		t.Fatalf("first table ownership: %v", err)
	}
	inspectLiveGuardTableShape(t, ctx, firstOwner, firstIdentity.Handle)
	requireNoPendingOwnerPublication(t, stateDir)
	t.Logf(
		"phase=create table=%s marker=%s handle=%d owner_sha256=%s",
		firstOwner.Table,
		firstOwner.Marker,
		firstIdentity.Handle,
		hex.EncodeToString(firstOwnerDigest[:]),
	)

	t.Log("phase=replace")
	if err := executor.Apply(ctx, plan); err != nil {
		t.Fatalf("replace empty owned guard by handle: %v", err)
	}
	secondOwner, present, err := executor.loadOwnerIfPresent()
	if err != nil {
		t.Fatalf("load owner record after replacement: %v", err)
	}
	if !present || secondOwner != firstOwner {
		t.Fatalf("owner identity changed across replacement: first=%#v second=%#v", firstOwner, secondOwner)
	}
	secondOwnerData := readLiveOwnerRecord(t, stateDir)
	secondOwnerDigest := sha256.Sum256(secondOwnerData)
	if secondOwnerDigest != firstOwnerDigest {
		t.Fatalf(
			"owner record changed across replacement: first=%s second=%s",
			hex.EncodeToString(firstOwnerDigest[:]),
			hex.EncodeToString(secondOwnerDigest[:]),
		)
	}
	secondIdentity, err := executor.inspect(ctx, secondOwner.Table)
	if err != nil {
		t.Fatalf("inspect replaced owned table: %v", err)
	}
	if err := requireOwnedTable(secondOwner, secondIdentity); err != nil {
		t.Fatalf("replaced table ownership: %v", err)
	}
	inspectLiveGuardTableShape(t, ctx, secondOwner, secondIdentity.Handle)
	requireNoPendingOwnerPublication(t, stateDir)
	t.Logf("phase=replace table=%s handle=%d", secondOwner.Table, secondIdentity.Handle)

	t.Logf("phase=cleanup validated_handle=%d", secondIdentity.Handle)
	if err := executor.Cleanup(ctx); err != nil {
		t.Fatalf("cleanup owned guard by validated handle: %v", err)
	}
	afterCleanup, err := executor.inspect(ctx, secondOwner.Table)
	if err != nil {
		t.Fatalf("inspect table after cleanup: %v", err)
	}
	if afterCleanup.Exists {
		t.Fatalf("owned table still exists after cleanup: %#v", afterCleanup)
	}

	t.Log("phase=idempotent-cleanup")
	if err := executor.Cleanup(ctx); err != nil {
		t.Fatalf("second cleanup was not idempotent: %v", err)
	}
	if tables := listProjectGuardTables(t, ctx); len(tables) != 0 {
		t.Fatalf("project tables remain after successful cleanup: %v", tables)
	}
	if finalOwnerData := readLiveOwnerRecord(t, stateDir); string(finalOwnerData) != string(firstOwnerData) {
		t.Fatal("cleanup changed the durable owner record")
	}
	t.Log("live guard ownership create/replace/handle-cleanup gate passed")
}

func requiredLiveGuardEnv(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("required live guard environment variable is empty: %s", name)
	}
	return value
}

func requireLiveGuardHostIdentity(t *testing.T) {
	t.Helper()
	expectedHostname := requiredLiveGuardEnv(t, "WG_MIX_EBPF_LIVE_GUARD_EXPECTED_HOSTNAME")
	hostname, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	if hostname != expectedHostname {
		t.Fatalf("hostname = %q, want %q", hostname, expectedHostname)
	}
	expectedKernel := requiredLiveGuardEnv(t, "WG_MIX_EBPF_LIVE_GUARD_EXPECTED_KERNEL")
	kernelData, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		t.Fatal(err)
	}
	if kernel := strings.TrimSpace(string(kernelData)); kernel != expectedKernel {
		t.Fatalf("kernel = %q, want %q", kernel, expectedKernel)
	}
	expectedMachineID := requiredLiveGuardEnv(t, "WG_MIX_EBPF_LIVE_GUARD_EXPECTED_MACHINE_ID")
	machineIDData, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		t.Fatal(err)
	}
	if machineID := strings.TrimSpace(string(machineIDData)); machineID != expectedMachineID {
		t.Fatalf("machine-id = %q, want %q", machineID, expectedMachineID)
	}
}

func readLiveOwnerRecord(t *testing.T, stateDir string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(stateDir, OwnerRecordFileName))
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateOwnerRecordBytes(stateDir, data); err != nil {
		t.Fatalf("persisted owner record validation: %v", err)
	}
	return data
}

func requireNoPendingOwnerPublication(t *testing.T, stateDir string) {
	t.Helper()
	_, err := os.Lstat(filepath.Join(stateDir, ownerRecordPendingFileName))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending owner publication remains after success: %v", err)
	}
}

func listProjectGuardTables(t *testing.T, ctx context.Context) []string {
	t.Helper()
	command := exec.CommandContext(ctx, "nft", "list", "tables")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("list nftables tables: %v: %s", err, output)
	}
	var tables []string
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[0] != "table" || fields[1] != "inet" {
			continue
		}
		if fields[2] == TableName || strings.HasPrefix(fields[2], TableName+"_") {
			tables = append(tables, fields[2])
		}
	}
	sort.Strings(tables)
	return tables
}

func inspectLiveGuardTableShape(
	t *testing.T,
	ctx context.Context,
	owner ownerRecord,
	expectedHandle uint64,
) {
	t.Helper()
	command := exec.CommandContext(ctx, "nft", "-j", "-a", "list", "table", "inet", owner.Table)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("list live guard table JSON: %v: %s", err, output)
	}
	var document struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(output, &document); err != nil {
		t.Fatalf("parse live guard table JSON: %v", err)
	}
	tableCount := 0
	ruleCount := 0
	chains := make(map[string]string)
	for _, item := range document.Nftables {
		if raw, ok := item["table"]; ok {
			var table struct {
				Family  string `json:"family"`
				Name    string `json:"name"`
				Comment string `json:"comment"`
				Handle  uint64 `json:"handle"`
			}
			if err := json.Unmarshal(raw, &table); err != nil {
				t.Fatal(err)
			}
			if table.Family == "inet" && table.Name == owner.Table {
				tableCount++
				if table.Comment != owner.Marker || table.Handle != expectedHandle {
					t.Fatalf("live table identity mismatch: %#v", table)
				}
			}
		}
		if raw, ok := item["chain"]; ok {
			var chain struct {
				Family string `json:"family"`
				Table  string `json:"table"`
				Name   string `json:"name"`
				Policy string `json:"policy"`
			}
			if err := json.Unmarshal(raw, &chain); err != nil {
				t.Fatal(err)
			}
			if chain.Family == "inet" && chain.Table == owner.Table {
				chains[chain.Name] = chain.Policy
			}
		}
		if _, ok := item["rule"]; ok {
			ruleCount++
		}
	}
	if tableCount != 1 {
		t.Fatalf("live guard table metadata entries = %d, want 1", tableCount)
	}
	if ruleCount != 0 {
		t.Fatalf("empty live guard unexpectedly has %d rules", ruleCount)
	}
	if len(chains) != 2 || chains["input"] != "accept" || chains["output"] != "accept" {
		t.Fatalf("live guard chains = %v, want input/output accept", chains)
	}
}

func Example_liveGuardBuildCommand() {
	fmt.Println("CGO_ENABLED=0 go test -c -tags realhosttest -ldflags=-X=github.com/syx0310/wg-mix-ebpf/internal/guard.liveGuardBuiltCommit=0123456789abcdef0123456789abcdef01234567 -o guard-live.test ./internal/guard")
	// Output:
	// CGO_ENABLED=0 go test -c -tags realhosttest -ldflags=-X=github.com/syx0310/wg-mix-ebpf/internal/guard.liveGuardBuiltCommit=0123456789abcdef0123456789abcdef01234567 -o guard-live.test ./internal/guard
}
