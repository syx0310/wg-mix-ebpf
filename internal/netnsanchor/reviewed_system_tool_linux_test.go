//go:build linux

package netnsanchor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

type reviewedToolFixture struct {
	root       string
	logical    string
	link       string
	target     string
	other      string
	policy     reviewedPathPolicy
	targetMeta reviewedMetadata
}

type stagedLaunchFixture struct {
	root        string
	sourceRoot  string
	policy      reviewedPathPolicy
	descriptors map[string]int
}

func TestReviewedSystemToolAcceptsRootControlledMulticallSymlink(t *testing.T) {
	fixture := newReviewedToolFixture(t)
	resolved, err := openReviewedSystemTool(fixture.logical, fixture.policy)
	if err != nil {
		t.Fatalf("root-controlled multicall symlink was rejected: %v", err)
	}
	defer resolved.close()
	if resolved.canonicalPath != "/lib/cargo/bin/coreutils" {
		t.Fatalf("canonical path = %q", resolved.canonicalPath)
	}
	if resolved.target != fixture.targetMeta {
		t.Fatalf("held target = %#v, want %#v", resolved.target, fixture.targetMeta)
	}
	if len(resolved.chain) < 5 {
		t.Fatalf("descriptor chain is unexpectedly short: %#v", resolved.chain)
	}
	foundLink := false
	for _, entry := range resolved.chain {
		if entry.kind == "symlink" &&
			entry.path == "/usr/bin/env" &&
			entry.linkTarget == "../../lib/cargo/bin/coreutils" {
			foundLink = true
		}
	}
	if !foundLink {
		t.Fatalf("logical symlink is absent from reviewed chain: %#v", resolved.chain)
	}
}

func TestReviewedSystemToolPreservesLogicalArgv0AndHeldFD(t *testing.T) {
	fixture := newReviewedToolFixture(t)
	wantEnvironment := []string{"PATH=/usr/bin", "LC_ALL=C"}
	called := false
	err := execReviewedSystemTool(
		fixture.logical,
		[]string{"--version"},
		wantEnvironment,
		fixture.policy,
		func(path string, argv []string, environment []string) error {
			called = true
			const prefix = "/proc/self/fd/"
			if !strings.HasPrefix(path, prefix) {
				t.Fatalf("exec path = %q, want held FD path", path)
			}
			descriptor, err := strconv.Atoi(strings.TrimPrefix(path, prefix))
			if err != nil {
				t.Fatalf("parse held FD path: %v", err)
			}
			metadata, err := reviewedMetadataFromFD(descriptor)
			if err != nil {
				t.Fatalf("stat held exec FD: %v", err)
			}
			if metadata != fixture.targetMeta {
				t.Fatalf("exec FD = %#v, want %#v", metadata, fixture.targetMeta)
			}
			if len(argv) != 2 || argv[0] != fixture.logical || argv[1] != "--version" {
				t.Fatalf("exec argv = %#v", argv)
			}
			if strings.Join(environment, "\x00") != strings.Join(wantEnvironment, "\x00") {
				t.Fatalf("exec environment = %#v", environment)
			}
			return nil
		},
	)
	if err != nil {
		t.Fatalf("prepare held reviewed exec: %v", err)
	}
	if !called {
		t.Fatal("reviewed exec callback was not called")
	}
}

func TestReviewedSystemToolRejectsUntrustedOwnership(t *testing.T) {
	fixture := newReviewedToolFixture(t)
	fixture.policy.expectedUID++
	if _, err := openReviewedSystemTool(fixture.logical, fixture.policy); err == nil {
		t.Fatal("user-owned reviewed path was accepted as another trusted UID")
	}
}

func TestReviewedSystemToolRejectsWritableLogicalAncestor(t *testing.T) {
	fixture := newReviewedToolFixture(t)
	if err := os.Chmod(filepath.Join(fixture.root, "usr", "bin"), 0o777); err != nil {
		t.Fatalf("make logical ancestor unsafe: %v", err)
	}
	if _, err := openReviewedSystemTool(fixture.logical, fixture.policy); err == nil {
		t.Fatal("group/world-writable logical ancestor was accepted")
	}
}

func TestReviewedSystemToolRejectsWritableTargetAncestor(t *testing.T) {
	fixture := newReviewedToolFixture(t)
	if err := os.Chmod(filepath.Join(fixture.root, "lib", "cargo"), 0o777); err != nil {
		t.Fatalf("make target ancestor unsafe: %v", err)
	}
	if _, err := openReviewedSystemTool(fixture.logical, fixture.policy); err == nil {
		t.Fatal("group/world-writable target ancestor was accepted")
	}
}

func TestReviewedSystemToolRejectsWritableTarget(t *testing.T) {
	fixture := newReviewedToolFixture(t)
	if err := os.Chmod(fixture.target, 0o777); err != nil {
		t.Fatalf("make target unsafe: %v", err)
	}
	if _, err := openReviewedSystemTool(fixture.logical, fixture.policy); err == nil {
		t.Fatal("group/world-writable executable target was accepted")
	}
}

func TestReviewedSystemToolRejectsSymlinkRetarget(t *testing.T) {
	fixture := newReviewedToolFixture(t)
	fixture.policy.afterResolve = func() error {
		if err := os.Remove(fixture.link); err != nil {
			return err
		}
		return os.Symlink("../../lib/cargo/bin/other", fixture.link)
	}
	if _, err := openReviewedSystemTool(fixture.logical, fixture.policy); err == nil {
		t.Fatal("symlink retarget during review was accepted")
	}
}

func TestReviewedSystemToolRejectsSameTargetSymlinkReplacement(t *testing.T) {
	fixture := newReviewedToolFixture(t)
	fixture.policy.afterResolve = func() error {
		if err := os.Remove(fixture.link); err != nil {
			return err
		}
		return os.Symlink("../../lib/cargo/bin/coreutils", fixture.link)
	}
	if _, err := openReviewedSystemTool(fixture.logical, fixture.policy); err == nil {
		t.Fatal("same-target symlink replacement during review was accepted")
	}
}

func TestReviewedSystemToolRejectsTargetFDMismatch(t *testing.T) {
	fixture := newReviewedToolFixture(t)
	replacement := filepath.Join(filepath.Dir(fixture.target), "replacement")
	writeReviewedExecutable(t, replacement, "replacement\n")
	fixture.policy.afterResolve = func() error {
		return os.Rename(replacement, fixture.target)
	}
	if _, err := openReviewedSystemTool(fixture.logical, fixture.policy); err == nil {
		t.Fatal("target replacement after initial FD open was accepted")
	}
}

func TestReviewedSystemToolRejectsEscapingAndLoopingSymlinks(t *testing.T) {
	for _, target := range []string{
		"../../../../../../outside",
		"env",
	} {
		t.Run(strings.ReplaceAll(target, "/", "_"), func(t *testing.T) {
			fixture := newReviewedToolFixture(t)
			if err := os.Remove(fixture.link); err != nil {
				t.Fatalf("remove fixture link: %v", err)
			}
			if err := os.Symlink(target, fixture.link); err != nil {
				t.Fatalf("replace fixture link: %v", err)
			}
			if _, err := openReviewedSystemTool(fixture.logical, fixture.policy); err == nil {
				t.Fatalf("unsafe symlink target %q was accepted", target)
			}
		})
	}
}

func TestReviewedSystemToolRejectsUnallowlistedPath(t *testing.T) {
	fixture := newReviewedToolFixture(t)
	if _, err := openReviewedSystemTool("/usr/bin/not-reviewed", fixture.policy); err == nil {
		t.Fatal("unallowlisted system tool path was accepted")
	}
}

func TestReviewedExecRejectsNilCallback(t *testing.T) {
	fixture := newReviewedToolFixture(t)
	err := execReviewedSystemTool(
		fixture.logical,
		nil,
		nil,
		fixture.policy,
		nil,
	)
	if err == nil {
		t.Fatal("nil reviewed exec callback was accepted")
	}
}

func TestStrictStagedLaunchAcceptsOnlyHeldRegularFiles(t *testing.T) {
	fixture := newStagedLaunchFixture(t)
	defer fixture.close()
	if err := reviewStagedLaunch(
		fixture.sourceRoot,
		fixture.descriptors,
		fixture.policy,
		false,
	); err != nil {
		t.Fatalf("strict staged launch was rejected: %v", err)
	}
}

func TestStrictStagedLaunchRejectsEveryLeafSymlink(t *testing.T) {
	for _, name := range []string{
		stagedLauncherName,
		stagedSmokeName,
		stagedHelperName,
		stagedAnchorName,
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newStagedLaunchFixture(t)
			defer fixture.close()
			path := filepath.Join(fixture.root, strings.TrimPrefix(fixture.sourceRoot, "/"), name)
			replacement := path + ".replacement"
			if err := os.Rename(path, replacement); err != nil {
				t.Fatalf("move staged leaf fixture: %v", err)
			}
			if err := os.Symlink(filepath.Base(replacement), path); err != nil {
				t.Fatalf("replace staged leaf with symlink: %v", err)
			}
			if err := reviewStagedLaunch(
				fixture.sourceRoot,
				fixture.descriptors,
				fixture.policy,
				false,
			); err == nil {
				t.Fatalf("staged symlink leaf was accepted: %s", name)
			}
		})
	}
}

func TestStrictStagedLaunchRejectsSymlinkAncestor(t *testing.T) {
	fixture := newStagedLaunchFixture(t)
	defer fixture.close()
	scripts := filepath.Join(
		fixture.root,
		strings.TrimPrefix(fixture.sourceRoot, "/"),
		"scripts",
	)
	replacement := scripts + ".replacement"
	if err := os.Rename(scripts, replacement); err != nil {
		t.Fatalf("move staged scripts fixture: %v", err)
	}
	if err := os.Symlink(filepath.Base(replacement), scripts); err != nil {
		t.Fatalf("replace staged scripts with symlink: %v", err)
	}
	if err := reviewStagedLaunch(
		fixture.sourceRoot,
		fixture.descriptors,
		fixture.policy,
		false,
	); err == nil {
		t.Fatal("staged symlink ancestor was accepted")
	}
}

func TestStrictStagedLaunchRejectsHardLinkedLeaf(t *testing.T) {
	fixture := newStagedLaunchFixture(t)
	defer fixture.close()
	launcher := filepath.Join(
		fixture.root,
		strings.TrimPrefix(fixture.sourceRoot, "/"),
		stagedLauncherName,
	)
	if err := os.Link(launcher, launcher+".hardlink"); err != nil {
		t.Fatalf("create staged hardlink fixture: %v", err)
	}
	if err := reviewStagedLaunch(
		fixture.sourceRoot,
		fixture.descriptors,
		fixture.policy,
		false,
	); err == nil {
		t.Fatal("hard-linked staged executable was accepted")
	}
}

func TestPrivateMountNSLaunchUsesSameProcessFDExec(t *testing.T) {
	fixture := newStagedLaunchFixture(t)
	defer fixture.close()
	installFixtureSystemTool(t, fixture.root, "/usr/bin/bash")
	validCommit := "0123456789abcdef0123456789abcdef01234567"
	originalCommit := sourceCommit
	sourceCommit = validCommit
	t.Cleanup(func() {
		sourceCommit = originalCommit
	})
	smokeFD := fixture.descriptors[stagedSmokeName]
	smokeMetadata, err := reviewedMetadataFromFD(smokeFD)
	if err != nil {
		t.Fatalf("stat held staged smoke fixture: %v", err)
	}
	environment := privateMountNSFixtureEnvironment(
		t,
		fixture.sourceRoot,
		smokeFD,
		smokeMetadata,
		validCommit,
	)
	order := make([]string, 0, 3)
	execError := errors.New("exec callback returned")
	err = launchPrivateMountNS(
		fixture.sourceRoot,
		smokeFD,
		environment,
		fixture.policy,
		privateMountNSOperations{
			unshare: func(flags int) error {
				order = append(order, "unshare")
				if flags != unix.CLONE_NEWNS {
					t.Fatalf("unshare flags = %#x", flags)
				}
				return nil
			},
			mount: func(source, target, filesystem string, flags uintptr, data string) error {
				order = append(order, "mount")
				if source != "" || target != "/" || filesystem != "" ||
					flags != unix.MS_REC|unix.MS_PRIVATE || data != "" {
					t.Fatalf(
						"mount contract = %q %q %q %#x %q",
						source,
						target,
						filesystem,
						flags,
						data,
					)
				}
				return nil
			},
			exec: func(path string, argv []string, gotEnvironment []string) error {
				order = append(order, "exec")
				if !strings.HasPrefix(path, "/proc/self/fd/") {
					t.Fatalf("private launch exec path = %q", path)
				}
				if len(argv) != 3 ||
					argv[0] != "/usr/bin/bash" ||
					argv[1] != "/proc/self/fd/"+strconv.Itoa(smokeFD) ||
					argv[2] != "--private-mountns-child-v1" {
					t.Fatalf("private launch argv = %#v", argv)
				}
				if strings.Join(gotEnvironment, "\x00") != strings.Join(environment, "\x00") {
					t.Fatalf("private launch environment changed: %#v", gotEnvironment)
				}
				return execError
			},
		},
	)
	if !errors.Is(err, execError) {
		t.Fatalf("private mount namespace launch error = %v", err)
	}
	if strings.Join(order, ",") != "unshare,mount,exec" {
		t.Fatalf("private mount namespace operation order = %#v", order)
	}
}

func TestPrivateMountNSLaunchRejectsUnallowlistedEnvironment(t *testing.T) {
	fixture := newStagedLaunchFixture(t)
	defer fixture.close()
	installFixtureSystemTool(t, fixture.root, "/usr/bin/bash")
	validCommit := "0123456789abcdef0123456789abcdef01234567"
	originalCommit := sourceCommit
	sourceCommit = validCommit
	t.Cleanup(func() {
		sourceCommit = originalCommit
	})
	smokeFD := fixture.descriptors[stagedSmokeName]
	smokeMetadata, err := reviewedMetadataFromFD(smokeFD)
	if err != nil {
		t.Fatalf("stat held staged smoke fixture: %v", err)
	}
	environment := append(
		privateMountNSFixtureEnvironment(
			t,
			fixture.sourceRoot,
			smokeFD,
			smokeMetadata,
			validCommit,
		),
		"LD_PRELOAD=/tmp/not-reviewed.so",
	)
	mutated := false
	err = launchPrivateMountNS(
		fixture.sourceRoot,
		smokeFD,
		environment,
		fixture.policy,
		privateMountNSOperations{
			unshare: func(int) error { mutated = true; return nil },
			mount: func(string, string, string, uintptr, string) error {
				mutated = true
				return nil
			},
			exec: func(string, []string, []string) error {
				mutated = true
				return nil
			},
		},
	)
	if err == nil {
		t.Fatal("unallowlisted child environment was accepted")
	}
	if mutated {
		t.Fatal("private mount namespace mutated before environment rejection")
	}
}

func TestPrivateMountNSLaunchRejectsSealMismatchBeforeMutation(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, []string)
	}{
		{
			name: "smoke-hash",
			mutate: func(t *testing.T, environment []string) {
				replaceEnvironmentValue(
					t,
					environment,
					"WG_MIX_EBPF_SMOKE_MOUNTNS_SCRIPT_SHA256",
					strings.Repeat("c", 64),
				)
			},
		},
		{
			name: "outer-namespace-identity",
			mutate: func(t *testing.T, environment []string) {
				replaceEnvironmentValue(
					t,
					environment,
					"WG_MIX_EBPF_SMOKE_MOUNTNS_OUTER_ID",
					"9:9",
				)
			},
		},
		{
			name: "descriptor-alias",
			mutate: func(t *testing.T, environment []string) {
				launchFD := environmentValue(
					t,
					environment,
					"WG_MIX_EBPF_SMOKE_MOUNTNS_LAUNCH_FD",
				)
				replaceEnvironmentValue(
					t,
					environment,
					"WG_MIX_EBPF_SMOKE_MOUNTNS_XOR_SECRET_FD",
					launchFD,
				)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newStagedLaunchFixture(t)
			defer fixture.close()
			installFixtureSystemTool(t, fixture.root, "/usr/bin/bash")
			validCommit := "0123456789abcdef0123456789abcdef01234567"
			originalCommit := sourceCommit
			sourceCommit = validCommit
			t.Cleanup(func() {
				sourceCommit = originalCommit
			})
			smokeFD := fixture.descriptors[stagedSmokeName]
			smokeMetadata, err := reviewedMetadataFromFD(smokeFD)
			if err != nil {
				t.Fatalf("stat held staged smoke fixture: %v", err)
			}
			environment := privateMountNSFixtureEnvironment(
				t,
				fixture.sourceRoot,
				smokeFD,
				smokeMetadata,
				validCommit,
			)
			test.mutate(t, environment)
			mutated := false
			err = launchPrivateMountNS(
				fixture.sourceRoot,
				smokeFD,
				environment,
				fixture.policy,
				privateMountNSOperations{
					unshare: func(int) error { mutated = true; return nil },
					mount: func(string, string, string, uintptr, string) error {
						mutated = true
						return nil
					},
					exec: func(string, []string, []string) error {
						mutated = true
						return nil
					},
				},
			)
			if err == nil {
				t.Fatal("private mount namespace launch seal mismatch was accepted")
			}
			if mutated {
				t.Fatal("private mount namespace mutated before seal rejection")
			}
		})
	}
}

func newReviewedToolFixture(t *testing.T) reviewedToolFixture {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatalf("make fixture root traversable: %v", err)
	}
	for _, directory := range []string{
		"usr",
		"usr/bin",
		"lib",
		"lib/cargo",
		"lib/cargo/bin",
	} {
		if err := os.Mkdir(filepath.Join(root, directory), 0o755); err != nil {
			t.Fatalf("create fixture directory %s: %v", directory, err)
		}
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		t.Fatalf("stat fixture root: %v", err)
	}
	rootStat, ok := rootInfo.Sys().(*unix.Stat_t)
	if !ok {
		t.Fatal("fixture root did not expose Linux stat metadata")
	}
	target := filepath.Join(root, "lib", "cargo", "bin", "coreutils")
	other := filepath.Join(root, "lib", "cargo", "bin", "other")
	writeReviewedExecutable(t, target, "coreutils\n")
	writeReviewedExecutable(t, other, "other\n")
	link := filepath.Join(root, "usr", "bin", "env")
	if err := os.Symlink("../../lib/cargo/bin/coreutils", link); err != nil {
		t.Fatalf("create multicall logical symlink: %v", err)
	}
	targetFD, err := unix.Open(target, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open fixture target: %v", err)
	}
	targetMetadata, err := reviewedMetadataFromFD(targetFD)
	if closeErr := unix.Close(targetFD); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatalf("inspect fixture target: %v", err)
	}
	return reviewedToolFixture{
		root:    root,
		logical: "/usr/bin/env",
		link:    link,
		target:  target,
		other:   other,
		policy: reviewedPathPolicy{
			filesystemRoot: root,
			expectedUID:    rootStat.Uid,
			expectedGID:    rootStat.Gid,
		},
		targetMeta: targetMetadata,
	}
}

func newStagedLaunchFixture(t *testing.T) stagedLaunchFixture {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatalf("make staged fixture root traversable: %v", err)
	}
	sourceRoot := "/run/wg-mix-ebpf-source-stages/deadbeef/source"
	for _, directory := range []string{
		"run",
		"run/wg-mix-ebpf-source-stages",
		"run/wg-mix-ebpf-source-stages/deadbeef",
		"run/wg-mix-ebpf-source-stages/deadbeef/source",
		"run/wg-mix-ebpf-source-stages/deadbeef/source/scripts",
		"run/wg-mix-ebpf-source-stages/deadbeef/source/bin",
	} {
		if err := os.Mkdir(filepath.Join(root, directory), 0o755); err != nil {
			t.Fatalf("create staged fixture directory %s: %v", directory, err)
		}
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		t.Fatalf("stat staged fixture root: %v", err)
	}
	rootStat, ok := rootInfo.Sys().(*unix.Stat_t)
	if !ok {
		t.Fatal("staged fixture root did not expose Linux stat metadata")
	}
	descriptors := make(map[string]int, 4)
	for _, name := range []string{
		stagedLauncherName,
		stagedSmokeName,
		stagedHelperName,
		stagedAnchorName,
	} {
		path := filepath.Join(root, strings.TrimPrefix(sourceRoot, "/"), name)
		writeReviewedExecutable(t, path, name+"\n")
		descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatalf("open held staged fixture %s: %v", name, err)
		}
		descriptors[name] = descriptor
	}
	return stagedLaunchFixture{
		root:       root,
		sourceRoot: sourceRoot,
		policy: reviewedPathPolicy{
			filesystemRoot: root,
			expectedUID:    rootStat.Uid,
			expectedGID:    rootStat.Gid,
		},
		descriptors: descriptors,
	}
}

func (fixture stagedLaunchFixture) close() {
	for _, descriptor := range fixture.descriptors {
		_ = unix.Close(descriptor)
	}
}

func installFixtureSystemTool(t *testing.T, root, logicalPath string) {
	t.Helper()
	for _, directory := range []string{"usr", "usr/bin", "lib", "libexec"} {
		path := filepath.Join(root, directory)
		if err := os.Mkdir(path, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
			t.Fatalf("create fixture system directory %s: %v", directory, err)
		}
	}
	target := filepath.Join(root, "lib", "libexec", "multicall")
	writeReviewedExecutable(t, target, "multicall\n")
	logical := filepath.Join(root, strings.TrimPrefix(logicalPath, "/"))
	if err := os.Symlink("../../lib/libexec/multicall", logical); err != nil {
		t.Fatalf("create fixture system logical symlink: %v", err)
	}
}

func privateMountNSFixtureEnvironment(
	t *testing.T,
	sourceRoot string,
	smokeFD int,
	smokeMetadata reviewedMetadata,
	commit string,
) []string {
	t.Helper()
	launchFD, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open launch record FD fixture: %v", err)
	}
	outerFD, err := unix.Open("/proc/self/ns/mnt", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = unix.Close(launchFD)
		t.Fatalf("open outer mount namespace FD fixture: %v", err)
	}
	xorFD, err := unix.Open("/dev/zero", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = unix.Close(launchFD)
		_ = unix.Close(outerFD)
		t.Fatalf("open XOR secret FD fixture: %v", err)
	}
	t.Cleanup(func() {
		_ = unix.Close(launchFD)
		_ = unix.Close(outerFD)
		_ = unix.Close(xorFD)
	})
	var outerMetadata unix.Stat_t
	if err := unix.Fstat(outerFD, &outerMetadata); err != nil {
		t.Fatalf("stat outer mount namespace FD fixture: %v", err)
	}
	smokeDigest, err := sha256RegularFD(smokeFD, 16*1024*1024)
	if err != nil {
		t.Fatalf("hash staged smoke FD fixture: %v", err)
	}
	return []string{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"LC_ALL=C",
		"WG_MIX_EBPF_SMOKE_MOUNTNS_CHILD=1",
		"WG_MIX_EBPF_SMOKE_MOUNTNS_LAUNCH_FD=" + strconv.Itoa(launchFD),
		"WG_MIX_EBPF_SMOKE_MOUNTNS_LAUNCH_NONCE=01234567-89ab-4cde-8fab-0123456789ab",
		"WG_MIX_EBPF_SMOKE_MOUNTNS_LAUNCH_SHA256=" + strings.Repeat("a", 64),
		"WG_MIX_EBPF_SMOKE_MOUNTNS_OUTER_FD=" + strconv.Itoa(outerFD),
		"WG_MIX_EBPF_SMOKE_MOUNTNS_OUTER_ID=" + fmt.Sprintf("%d:%d", outerMetadata.Dev, outerMetadata.Ino),
		"WG_MIX_EBPF_SMOKE_MOUNTNS_OUTER_PID=" + strconv.Itoa(os.Getppid()),
		"WG_MIX_EBPF_SMOKE_MOUNTNS_SCRIPT_DEV=" + strconv.FormatUint(smokeMetadata.device, 10),
		"WG_MIX_EBPF_SMOKE_MOUNTNS_SCRIPT_FD=" + strconv.Itoa(smokeFD),
		"WG_MIX_EBPF_SMOKE_MOUNTNS_SCRIPT_INO=" + strconv.FormatUint(smokeMetadata.inode, 10),
		"WG_MIX_EBPF_SMOKE_MOUNTNS_SCRIPT_SHA256=" + smokeDigest,
		"WG_MIX_EBPF_SMOKE_MOUNTNS_SOURCE_COMMIT=" + commit,
		"WG_MIX_EBPF_SMOKE_MOUNTNS_SOURCE_ROOT=" + sourceRoot,
		"WG_MIX_EBPF_SMOKE_MOUNTNS_XOR_SECRET_FD=" + strconv.Itoa(xorFD),
	}
}

func environmentValue(t *testing.T, environment []string, name string) string {
	t.Helper()
	prefix := name + "="
	for _, entry := range environment {
		if strings.HasPrefix(entry, prefix) {
			return strings.TrimPrefix(entry, prefix)
		}
	}
	t.Fatalf("environment fixture is missing %s", name)
	return ""
}

func replaceEnvironmentValue(
	t *testing.T,
	environment []string,
	name string,
	value string,
) {
	t.Helper()
	prefix := name + "="
	for index, entry := range environment {
		if strings.HasPrefix(entry, prefix) {
			environment[index] = prefix + value
			return
		}
	}
	t.Fatalf("environment fixture is missing %s", name)
}

func writeReviewedExecutable(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o755); err != nil {
		t.Fatalf("write reviewed executable fixture: %v", err)
	}
}
