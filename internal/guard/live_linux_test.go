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

type liveGuardResult struct {
	Version         int    `json:"version"`
	RunID           string `json:"run_id"`
	CandidateCommit string `json:"candidate_commit"`
	Table           string `json:"table"`
	Marker          string `json:"marker"`
	FirstHandle     uint64 `json:"first_handle"`
	SecondHandle    uint64 `json:"second_handle"`
	OwnerSHA256     string `json:"owner_sha256"`
	CleanupVerified bool   `json:"cleanup_verified"`
}

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
	resultFile := requiredLiveGuardEnv(t, "WG_MIX_EBPF_LIVE_GUARD_RESULT_FILE")
	wantResultFile := filepath.Join(
		liveGuardRunPrefix,
		runID,
		"evidence",
		"guard-live.result.json",
	)
	if resultFile != wantResultFile || filepath.Clean(resultFile) != resultFile {
		t.Fatalf("live guard result file = %q, want %q", resultFile, wantResultFile)
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
	realExecutor := NewCommandExecutor(stateDir)
	executor := realExecutor
	nftWrites := 0
	executor.runScript = func(ctx context.Context, script string) error {
		nftWrites++
		digest := sha256.Sum256([]byte(script))
		t.Logf(
			"nft_write=%d argv=%q script_sha256=%x script=%q",
			nftWrites,
			[]string{"nft", "-f", "-"},
			digest,
			script,
		)
		return realExecutor.run(ctx, script)
	}

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
	if secondIdentity.Handle == firstIdentity.Handle {
		t.Fatalf(
			"replacement retained table handle %d; replacement was not proven",
			firstIdentity.Handle,
		)
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
	if nftWrites != 3 {
		t.Fatalf("live guard nft write transactions = %d, want create/replace/delete", nftWrites)
	}
	writeLiveGuardResult(t, resultFile, liveGuardResult{
		Version:         1,
		RunID:           runID,
		CandidateCommit: commit,
		Table:           firstOwner.Table,
		Marker:          firstOwner.Marker,
		FirstHandle:     firstIdentity.Handle,
		SecondHandle:    secondIdentity.Handle,
		OwnerSHA256:     hex.EncodeToString(firstOwnerDigest[:]),
		CleanupVerified: true,
	})
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
	command := exec.CommandContext(ctx, "nft", "-j", "list", "tables")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("list nftables tables as JSON: %v: %s", err, output)
	}
	tables, err := parseProjectTableInventoryJSON(output)
	if err != nil {
		t.Fatalf("validate nftables project table inventory: %v", err)
	}
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
	if err := validateLiveGuardTableShapeJSON(output, owner, expectedHandle); err != nil {
		t.Fatalf("validate live guard table shape: %v", err)
	}
}

func writeLiveGuardResult(t *testing.T, path string, result liveGuardResult) {
	t.Helper()
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if len(data) > 4096 {
		t.Fatalf("live guard result is too large: %d bytes", len(data))
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatalf("create live guard result: %v", err)
	}
	written := 0
	for written < len(data) {
		count, writeErr := file.Write(data[written:])
		if writeErr != nil {
			_ = file.Close()
			t.Fatalf("write live guard result: %v", writeErr)
		}
		if count == 0 {
			_ = file.Close()
			t.Fatal("write live guard result: zero-byte write")
		}
		written += count
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		t.Fatalf("sync live guard result: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close live guard result: %v", err)
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		t.Fatalf("open live guard evidence directory: %v", err)
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		t.Fatalf("sync live guard evidence directory: %v", err)
	}
	if err := directory.Close(); err != nil {
		t.Fatalf("close live guard evidence directory: %v", err)
	}
}

func Example_liveGuardBuildCommand() {
	fmt.Println("CGO_ENABLED=0 go test -c -tags realhosttest -ldflags=-X=github.com/syx0310/wg-mix-ebpf/internal/guard.liveGuardBuiltCommit=0123456789abcdef0123456789abcdef01234567 -o guard-live.test ./internal/guard")
	// Output:
	// CGO_ENABLED=0 go test -c -tags realhosttest -ldflags=-X=github.com/syx0310/wg-mix-ebpf/internal/guard.liveGuardBuiltCommit=0123456789abcdef0123456789abcdef01234567 -o guard-live.test ./internal/guard
}
