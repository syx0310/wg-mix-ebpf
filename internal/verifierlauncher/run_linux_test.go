//go:build linux

package verifierlauncher

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

type linuxTestLayout struct {
	evidenceRoot string
	runnerDir    string
	runner       string
	arguments    Arguments
	policy       policy
}

func writeNewFile(path string, content []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func fileSHA256(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(content)), nil
}

func newLinuxTestLayout(t *testing.T, caseName string, runnerContent []byte) linuxTestLayout {
	t.Helper()
	evidenceRoot, err := os.MkdirTemp(
		"",
		"wg-mix-faketcp-launcher-"+caseName+".",
	)
	if err != nil {
		t.Fatalf("create retained evidence root: %v", err)
	}
	evidenceRoot, err = filepath.EvalSymlinks(evidenceRoot)
	if err != nil {
		t.Fatalf("resolve retained evidence root: %v", err)
	}
	prefix := filepath.Join(evidenceRoot, "wg-mix-ebpf-faketcp-verifier")
	stagingRoot := filepath.Join(prefix, "caseid-01234567")
	runnerDir := filepath.Join(stagingRoot, "runner")
	artifactDir := filepath.Join(stagingRoot, "artifacts")
	for _, directory := range []string{
		evidenceRoot,
		prefix,
		stagingRoot,
		runnerDir,
		artifactDir,
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatalf("create %s: %v", directory, err)
		}
		if err := os.Chmod(directory, 0o700); err != nil {
			t.Fatalf("lock %s: %v", directory, err)
		}
	}
	runnerPath := filepath.Join(runnerDir, "run-faketcp-verifier-only.py")
	if err := writeNewFile(runnerPath, runnerContent, 0o600); err != nil {
		t.Fatalf("write runner: %v", err)
	}
	runnerHash, err := fileSHA256(runnerPath)
	if err != nil {
		t.Fatalf("hash runner: %v", err)
	}
	currentOwner := owner{uid: uint32(os.Geteuid()), gid: uint32(os.Getegid())}
	directoryOwners := map[owner]struct{}{
		{uid: 0, gid: 0}: {},
		currentOwner:     {},
	}
	layout := linuxTestLayout{
		evidenceRoot: evidenceRoot,
		runnerDir:    runnerDir,
		runner:       runnerPath,
		arguments: Arguments{
			Runner:       runnerPath,
			RunnerSHA256: runnerHash,
			StagingRoot:  stagingRoot,
			Binary:       filepath.Join(artifactDir, "wg-mix-ebpf"),
			BinarySHA256: strings.Repeat("b", 64),
			Object:       filepath.Join(artifactDir, "wg_mix_faketcp_experimental.o"),
			ObjectSHA256: strings.Repeat("c", 64),
		},
		policy: policy{
			stagingPrefix:       prefix,
			pythonPath:          productionPythonPath,
			procFDPrefix:        productionProcFDPrefix,
			requireRoot:         false,
			directoryOwners:     directoryOwners,
			runnerOwner:         currentOwner,
			allowStickyAncestor: true,
		},
	}
	t.Logf("retained FakeTCP launcher evidence: %s", evidenceRoot)
	return layout
}

func openRunnerForTest(
	t *testing.T,
	layout linuxTestLayout,
) (int, error) {
	t.Helper()
	return openVerifiedRunner(
		layout.arguments,
		layout.policy,
		productionLinuxSystem(),
	)
}

func TestLinuxRunnerAdmissionRejectsHashOwnerModeLinkAndSymlink(t *testing.T) {
	runnerContent := []byte("print('reviewed runner')\n")
	type rejectionCase struct {
		expected string
		prepare  func(*testing.T, *linuxTestLayout)
	}
	for name, currentCase := range map[string]rejectionCase{
		"wrong hash": {
			expected: "runner SHA-256 mismatch",
			prepare: func(_ *testing.T, layout *linuxTestLayout) {
				layout.arguments.RunnerSHA256 = strings.Repeat("f", 64)
			},
		},
		"wrong owner": {
			expected: "runner is not owned by the required uid:gid",
			prepare: func(_ *testing.T, layout *linuxTestLayout) {
				layout.policy.runnerOwner.uid++
			},
		},
		"group writable mode": {
			expected: "runner must not be group- or other-writable",
			prepare: func(t *testing.T, layout *linuxTestLayout) {
				if err := os.Chmod(layout.runner, 0o620); err != nil {
					t.Fatalf("make runner group writable: %v", err)
				}
			},
		},
		"second hard link": {
			expected: "runner link count must be exactly one",
			prepare: func(t *testing.T, layout *linuxTestLayout) {
				if err := os.Link(layout.runner, layout.runner+".link"); err != nil {
					t.Fatalf("link runner: %v", err)
				}
			},
		},
		"runner symlink": {
			expected: "open runner",
			prepare: func(t *testing.T, layout *linuxTestLayout) {
				symlink := layout.runner + ".symlink"
				if err := os.Symlink(layout.runner, symlink); err != nil {
					t.Fatalf("symlink runner: %v", err)
				}
				layout.arguments.Runner = symlink
			},
		},
		"symlink ancestor": {
			expected: "open runner ancestor",
			prepare: func(t *testing.T, layout *linuxTestLayout) {
				symlink := filepath.Join(layout.arguments.StagingRoot, "runner-link")
				if err := os.Symlink(layout.runnerDir, symlink); err != nil {
					t.Fatalf("symlink runner directory: %v", err)
				}
				layout.arguments.Runner = filepath.Join(
					symlink,
					filepath.Base(layout.runner),
				)
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			layout := newLinuxTestLayout(t, strings.ReplaceAll(name, " ", "-"), runnerContent)
			currentCase.prepare(t, &layout)
			descriptor, err := openRunnerForTest(t, layout)
			if err == nil {
				_ = unix.Close(descriptor)
				t.Fatal("unexpectedly accepted invalid runner")
			}
			if !strings.Contains(err.Error(), currentCase.expected) {
				t.Fatalf("runner rejection error = %v, want %q", err, currentCase.expected)
			}
		})
	}
}

func TestDirectoryMetadataAllowsSingleLink(t *testing.T) {
	currentOwner := owner{uid: uint32(os.Geteuid()), gid: uint32(os.Getegid())}
	currentPolicy := policy{
		directoryOwners: map[owner]struct{}{currentOwner: {}},
	}
	err := validateDirectory(
		fileMetadata{
			mode:  unix.S_IFDIR | 0o700,
			uid:   currentOwner.uid,
			gid:   currentOwner.gid,
			links: 1,
		},
		"/synthetic-overlay",
		currentPolicy,
	)
	if err != nil {
		t.Fatalf("single-link directory rejected: %v", err)
	}
}

func TestLinuxRunnerAdmissionRejectsWritableAncestor(t *testing.T) {
	layout := newLinuxTestLayout(
		t,
		"writable-ancestor",
		[]byte("print('reviewed runner')\n"),
	)
	if err := os.Chmod(layout.runnerDir, 0o720); err != nil {
		t.Fatalf("make runner ancestor group writable: %v", err)
	}
	descriptor, err := openRunnerForTest(t, layout)
	if err == nil {
		_ = unix.Close(descriptor)
		t.Fatal("unexpectedly accepted writable runner ancestor")
	}
}

func TestLinuxRunnerAdmissionRejectsUnacceptedAncestorOwner(t *testing.T) {
	layout := newLinuxTestLayout(
		t,
		"unaccepted-ancestor-owner",
		[]byte("print('reviewed runner')\n"),
	)
	layout.policy.directoryOwners = map[owner]struct{}{
		{uid: uint32(os.Geteuid()) + 1, gid: uint32(os.Getegid())}: {},
	}
	descriptor, err := openRunnerForTest(t, layout)
	if err == nil {
		_ = unix.Close(descriptor)
		t.Fatal("unexpectedly accepted unowned staging ancestor")
	}
	if !strings.Contains(err.Error(), "not owned by an accepted uid:gid") {
		t.Fatalf("unexpected ancestor owner error: %v", err)
	}
}

func TestLinuxProductionPolicyRejectsNonRootBeforeOpeningRunner(t *testing.T) {
	arguments := validContractArguments()
	system := productionLinuxSystem()
	system.getEUID = func() int { return 1000 }
	err := runWithPolicy(
		contractArgv(arguments),
		productionPolicy,
		system,
		nil,
	)
	if err == nil || !strings.Contains(err.Error(), "must run as root") {
		t.Fatalf("non-root production error = %v", err)
	}
}

func TestLinuxRunnerAdmissionDetectsMetadataChangeWhileHashing(t *testing.T) {
	layout := newLinuxTestLayout(
		t,
		"metadata-change",
		[]byte("print('reviewed runner')\n"),
	)
	system := productionLinuxSystem()
	originalRead := system.read
	changed := false
	system.read = func(descriptor int, buffer []byte) (int, error) {
		count, err := originalRead(descriptor, buffer)
		if count > 0 && !changed {
			changed = true
			if chmodErr := os.Chmod(layout.runner, 0o400); chmodErr != nil {
				return count, chmodErr
			}
		}
		return count, err
	}
	descriptor, err := openVerifiedRunner(layout.arguments, layout.policy, system)
	if err == nil {
		_ = unix.Close(descriptor)
		t.Fatal("unexpectedly accepted runner changed while hashing")
	}
	if !strings.Contains(err.Error(), "metadata changed while hashing") {
		t.Fatalf("unexpected metadata race error: %v", err)
	}
}

func TestLinuxTempIntegrationReachesExecWithSingleLinkDirectories(t *testing.T) {
	originalContent := []byte("print('held original')\n")
	layout := newLinuxTestLayout(t, "exact-exec", originalContent)
	system := productionLinuxSystem()
	originalFstat := system.fstat
	system.fstat = func(descriptor int, value *unix.Stat_t) error {
		if err := originalFstat(descriptor, value); err != nil {
			return err
		}
		if value.Mode&unix.S_IFMT == unix.S_IFDIR {
			value.Nlink = 1
		}
		return nil
	}
	var (
		gotPlan       execPlan
		gotContent    []byte
		sourceFlags   int
		inheritedFlag int
		closeRanges   [][2]uint
	)
	execSentinel := errors.New("captured fixed exec")
	system.closeRange = func(first, last, flags uint) error {
		if flags != 0 {
			t.Fatalf("close_range flags = %d, want 0", flags)
		}
		closeRanges = append(closeRanges, [2]uint{first, last})
		return nil
	}
	system.exec = func(path string, argv, environment []string) error {
		gotPlan = execPlan{
			path: path,
			argv: append([]string(nil), argv...),
			env:  append([]string(nil), environment...),
		}
		var err error
		inheritedFlag, err = unix.FcntlInt(runnerExecFD, unix.F_GETFD, 0)
		if err != nil {
			t.Fatalf("read inherited runner flags: %v", err)
		}
		if _, err := unix.Seek(runnerExecFD, 0, 0); err != nil {
			t.Fatalf("rewind inherited runner: %v", err)
		}
		buffer := make([]byte, len(originalContent)+32)
		count, err := unix.Read(runnerExecFD, buffer)
		if err != nil {
			t.Fatalf("read inherited runner: %v", err)
		}
		gotContent = append([]byte(nil), buffer[:count]...)
		for _, forbiddenFD := range []int{childBinaryExecFD, childObjectExecFD} {
			if _, err := unix.FcntlInt(uintptr(forbiddenFD), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
				t.Fatalf("forbidden FD %d is open: %v", forbiddenFD, err)
			}
		}
		return execSentinel
	}
	beforeExec := func(sourceDescriptor int) error {
		var err error
		sourceFlags, err = unix.FcntlInt(uintptr(sourceDescriptor), unix.F_GETFD, 0)
		if err != nil {
			return err
		}
		if err := os.Rename(layout.runner, layout.runner+".approved"); err != nil {
			return err
		}
		return writeNewFile(
			layout.runner,
			[]byte("print('path replacement')\n"),
			0o600,
		)
	}
	err := runWithPolicy(
		contractArgv(layout.arguments),
		layout.policy,
		system,
		beforeExec,
	)
	if !errors.Is(err, execSentinel) {
		t.Fatalf("run error = %v, want injected exec error", err)
	}
	wantPlan := makeExecPlan(layout.arguments, layout.policy)
	if !reflect.DeepEqual(gotPlan, wantPlan) {
		t.Fatalf("exec plan mismatch:\n got: %#v\nwant: %#v", gotPlan, wantPlan)
	}
	if !reflect.DeepEqual(gotContent, originalContent) {
		t.Fatalf("held runner changed after rename: %q", gotContent)
	}
	if sourceFlags&unix.FD_CLOEXEC == 0 {
		t.Fatal("source runner FD was not close-on-exec")
	}
	if inheritedFlag&unix.FD_CLOEXEC != 0 {
		t.Fatal("fixed inherited runner FD was close-on-exec")
	}
	if !reflect.DeepEqual(closeRanges, [][2]uint{
		{3, runnerExecFD - 1},
		{runnerExecFD + 1, ^uint(0)},
	}) {
		t.Fatalf("close_range contract mismatch: %#v", closeRanges)
	}
}

func TestLinuxReservedArtifactDescriptorsMustStartUnused(t *testing.T) {
	layout := newLinuxTestLayout(
		t,
		"reserved-fd",
		[]byte("print('reviewed runner')\n"),
	)
	source, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open /dev/null: %v", err)
	}
	defer func() { _ = unix.Close(source) }()
	if err := unix.Dup3(source, childBinaryExecFD, 0); err != nil {
		t.Fatalf("occupy reserved FD: %v", err)
	}
	defer func() { _ = unix.Close(childBinaryExecFD) }()
	err = runWithPolicy(
		contractArgv(layout.arguments),
		layout.policy,
		productionLinuxSystem(),
		nil,
	)
	if err == nil || !strings.Contains(err.Error(), "descriptor 100 is already in use") {
		t.Fatalf("reserved descriptor error = %v", err)
	}
}

type subprocessContract struct {
	Arguments Arguments `json:"arguments"`
	Prefix    string    `json:"prefix"`
}

func TestLinuxLauncherExecHelper(t *testing.T) {
	encoded := os.Getenv("WG_MIX_TEST_LAUNCHER_SUBPROCESS")
	if encoded == "" {
		return
	}
	serialized, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		fmt.Fprintf(os.Stderr, "decode helper contract: %v\n", err)
		os.Exit(110)
	}
	var contract subprocessContract
	if err := json.Unmarshal(serialized, &contract); err != nil {
		fmt.Fprintf(os.Stderr, "unmarshal helper contract: %v\n", err)
		os.Exit(111)
	}
	currentOwner := owner{uid: uint32(os.Geteuid()), gid: uint32(os.Getegid())}
	currentPolicy := policy{
		stagingPrefix:       contract.Prefix,
		pythonPath:          productionPythonPath,
		procFDPrefix:        productionProcFDPrefix,
		requireRoot:         false,
		directoryOwners:     map[owner]struct{}{{}: {}, currentOwner: {}},
		runnerOwner:         currentOwner,
		allowStickyAncestor: true,
	}
	beforeExec := func(_ int) error {
		if err := os.Rename(contract.Arguments.Runner, contract.Arguments.Runner+".approved"); err != nil {
			return err
		}
		return writeNewFile(
			contract.Arguments.Runner,
			[]byte("print('path replacement executed'); raise SystemExit(88)\n"),
			0o600,
		)
	}
	if err := runWithPolicy(
		contractArgv(contract.Arguments),
		currentPolicy,
		productionLinuxSystem(),
		beforeExec,
	); err != nil {
		fmt.Fprintf(os.Stderr, "launcher helper: %v\n", err)
		os.Exit(112)
	}
	os.Exit(113)
}

func TestLinuxRenameReplacementExecutesOriginalHeldRunner(t *testing.T) {
	originalRunner := []byte(
		"import errno, os, sys\n" +
			"assert sys.flags.isolated\n" +
			"assert __file__ == '/proc/self/fd/99'\n" +
			"assert os.get_inheritable(99)\n" +
			"for descriptor in (100, 101):\n" +
			"    try:\n" +
			"        os.fstat(descriptor)\n" +
			"    except OSError as error:\n" +
			"        assert error.errno == errno.EBADF\n" +
			"    else:\n" +
			"        raise AssertionError(f'unexpected inherited FD {descriptor}')\n" +
			"assert os.environ == {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}\n" +
			"print('held runner original executed', flush=True)\n" +
			"raise SystemExit(37)\n",
	)
	layout := newLinuxTestLayout(t, "subprocess-rename", originalRunner)
	contract := subprocessContract{
		Arguments: layout.arguments,
		Prefix:    layout.policy.stagingPrefix,
	}
	serialized, err := json.Marshal(contract)
	if err != nil {
		t.Fatalf("marshal helper contract: %v", err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestLinuxLauncherExecHelper$")
	command.Env = append(
		os.Environ(),
		"WG_MIX_TEST_LAUNCHER_SUBPROCESS="+
			base64.RawStdEncoding.EncodeToString(serialized),
	)
	output, err := command.CombinedOutput()
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) || exitError.ExitCode() != 37 {
		t.Fatalf("held runner subprocess error = %v, output = %q", err, output)
	}
	if !strings.Contains(string(output), "held runner original executed") ||
		strings.Contains(string(output), "path replacement executed") {
		t.Fatalf("unexpected held runner subprocess output: %q", output)
	}
}
