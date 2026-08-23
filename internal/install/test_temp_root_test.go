package install

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	installTestTempPrefix    = ".wg-mix-ebpf-install-tests-"
	installTestTempParentEnv = "WG_MIX_EBPF_INSTALL_TEST_TEMP_PARENT"
)

// Capture the inherited value before TestMain changes it. The regression test
// uses this to prove that an external GOTMPDIR is replaced before t.TempDir is
// first called.
var installTestInitialGOTMPDIR = os.Getenv("GOTMPDIR")

// Capture the parent before TestMain runs for the same reason. Real-host and
// other hermetic runners can keep the test tree outside the source checkout,
// so package-parallel tests never make source identity appear dirty.
var installTestInitialTempParent = os.Getenv(installTestTempParentEnv)

var installTestsTemp installTestTempState

type installTestTempState struct {
	parentDir      string
	parentIdentity os.FileInfo
	root           string
	rootIdentity   os.FileInfo
}

func prepareInstallTestTemp() (installTestTempState, error) {
	var state installTestTempState

	parentDir, parentIdentity, err := resolveInstallTestTempParent(
		installTestInitialTempParent,
	)
	if err != nil {
		return state, err
	}
	state.parentDir = parentDir
	state.parentIdentity = parentIdentity

	root, err := os.MkdirTemp(state.parentDir, installTestTempPrefix)
	if err != nil {
		return state, fmt.Errorf("create isolated install test root: %w", err)
	}
	state.root = filepath.Clean(root)
	state.rootIdentity, err = os.Lstat(state.root)
	if err != nil {
		return state, fmt.Errorf("identify isolated install test root: %w", err)
	}
	if err := validateInstallTestTempIdentity(state); err != nil {
		return state, fmt.Errorf("validate isolated install test root: %w", err)
	}
	if err := setInstallTestTempEnvironment(state.root, os.Setenv); err != nil {
		return state, err
	}
	if err := validateInstallTestTempEnvironment(state); err != nil {
		return state, fmt.Errorf("validate isolated install test environment: %w", err)
	}
	return state, nil
}

func resolveInstallTestTempParent(
	externalParent string,
) (string, os.FileInfo, error) {
	parentDir := externalParent
	if parentDir == "" {
		workingDir, err := os.Getwd()
		if err != nil {
			return "", nil, fmt.Errorf(
				"resolve install package test directory: %w",
				err,
			)
		}
		parentDir, err = filepath.Abs(workingDir)
		if err != nil {
			return "", nil, fmt.Errorf(
				"make install package test directory absolute: %w",
				err,
			)
		}
	} else if !filepath.IsAbs(parentDir) {
		return "", nil, fmt.Errorf(
			"refuse non-absolute isolated install test parent %q",
			parentDir,
		)
	}

	parentDir = filepath.Clean(parentDir)
	if parentDir == string(os.PathSeparator) {
		return "", nil, errors.New("refuse kernel root as isolated install test parent")
	}
	canonicalParent, err := filepath.EvalSymlinks(parentDir)
	if err != nil {
		return "", nil, fmt.Errorf(
			"canonicalize isolated install test parent %s: %w",
			parentDir,
			err,
		)
	}
	canonicalParent = filepath.Clean(canonicalParent)
	parentIdentity, err := os.Lstat(parentDir)
	if err != nil {
		return "", nil, fmt.Errorf(
			"identify isolated install test parent %s: %w",
			parentDir,
			err,
		)
	}
	if canonicalParent != parentDir || !parentIdentity.IsDir() ||
		parentIdentity.Mode()&os.ModeSymlink != 0 {
		return "", nil, fmt.Errorf(
			"isolated install test parent is not a canonical directory: %s",
			parentDir,
		)
	}
	if parentIdentity.Mode().Perm()&0o022 != 0 {
		return "", nil, fmt.Errorf(
			"refuse group/other writable isolated install test parent %s mode %#o",
			parentDir,
			parentIdentity.Mode().Perm(),
		)
	}
	return parentDir, parentIdentity, nil
}

func setInstallTestTempEnvironment(
	root string,
	setenv func(string, string) error,
) error {
	for _, name := range []string{"TMPDIR", "GOTMPDIR"} {
		if err := setenv(name, root); err != nil {
			return fmt.Errorf("set %s to isolated install test root: %w", name, err)
		}
	}
	return nil
}

func validateInstallTestTempIdentity(state installTestTempState) error {
	if state.parentDir == "" || !filepath.IsAbs(state.parentDir) ||
		filepath.Clean(state.parentDir) != state.parentDir ||
		state.parentDir == string(os.PathSeparator) {
		return fmt.Errorf(
			"refuse unsafe isolated install test parent %q",
			state.parentDir,
		)
	}
	rootName := filepath.Base(state.root)
	if state.root == "" || !filepath.IsAbs(state.root) ||
		filepath.Clean(state.root) != state.root ||
		filepath.Dir(state.root) != state.parentDir ||
		!strings.HasPrefix(rootName, installTestTempPrefix) ||
		len(rootName) <= len(installTestTempPrefix) {
		return fmt.Errorf("refuse unsafe isolated install test root %q", state.root)
	}
	if state.parentIdentity == nil || state.rootIdentity == nil {
		return errors.New("isolated install test root identity is missing")
	}

	canonicalParent, err := filepath.EvalSymlinks(state.parentDir)
	if err != nil {
		return fmt.Errorf("canonicalize isolated install test parent: %w", err)
	}
	parentIdentity, err := os.Lstat(state.parentDir)
	if err != nil {
		return fmt.Errorf("identify isolated install test parent: %w", err)
	}
	if filepath.Clean(canonicalParent) != state.parentDir ||
		!parentIdentity.IsDir() ||
		parentIdentity.Mode()&os.ModeSymlink != 0 ||
		parentIdentity.Mode().Perm()&0o022 != 0 ||
		!os.SameFile(state.parentIdentity, parentIdentity) {
		return fmt.Errorf(
			"isolated install test parent identity changed: %s",
			state.parentDir,
		)
	}

	canonicalRoot, err := filepath.EvalSymlinks(state.root)
	if err != nil {
		return fmt.Errorf("canonicalize isolated install test root: %w", err)
	}
	rootIdentity, err := os.Lstat(state.root)
	if err != nil {
		return fmt.Errorf("identify isolated install test root: %w", err)
	}
	if filepath.Clean(canonicalRoot) != state.root ||
		!rootIdentity.IsDir() ||
		rootIdentity.Mode()&os.ModeSymlink != 0 ||
		rootIdentity.Mode().Perm() != 0o700 ||
		!os.SameFile(state.rootIdentity, rootIdentity) {
		return fmt.Errorf(
			"isolated install test root identity changed: %s",
			state.root,
		)
	}
	return nil
}

func validateInstallTestTempEnvironment(state installTestTempState) error {
	if err := validateInstallTestTempIdentity(state); err != nil {
		return err
	}
	for _, name := range []string{"TMPDIR", "GOTMPDIR"} {
		value, present := os.LookupEnv(name)
		if !present || value != state.root {
			return fmt.Errorf("%s=%q, want isolated root %q", name, value, state.root)
		}
	}
	if tempDir := filepath.Clean(os.TempDir()); tempDir != state.root {
		return fmt.Errorf("os.TempDir()=%q, want isolated root %q", tempDir, state.root)
	}
	return nil
}

func removeInstallTestTemp(state installTestTempState) error {
	if err := validateInstallTestTempEnvironment(state); err != nil {
		return err
	}
	entries, err := os.ReadDir(state.root)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return fmt.Errorf(
			"isolated install test root %s retained %d entries",
			state.root,
			len(entries),
		)
	}
	if err := validateInstallTestTempIdentity(state); err != nil {
		return err
	}
	return os.Remove(state.root)
}

func runInstallTestMain(run func() int, stderr io.Writer) int {
	return runInstallTestMainWithSetup(prepareInstallTestTemp, run, stderr)
}

func runInstallTestMainWithSetup(
	setup func() (installTestTempState, error),
	run func() int,
	stderr io.Writer,
) int {
	state, err := setup()
	if err != nil {
		fmt.Fprintf(stderr, "prepare isolated install test root: %v\n", err)
		if state.root != "" {
			fmt.Fprintf(
				stderr,
				"retain isolated install test root after setup failure: %s\n",
				state.root,
			)
		}
		return 1
	}
	installTestsTemp = state

	code := run()
	if err := removeInstallTestTemp(state); err != nil {
		fmt.Fprintf(stderr, "remove isolated install test root %s: %v\n", state.root, err)
		if code == 0 {
			code = 1
		}
	}
	return code
}

func TestInstallTempDirUsesTestMainRoot(t *testing.T) {
	if expected, ok := os.LookupEnv("WG_MIX_EBPF_TEST_EXPECT_INITIAL_GOTMPDIR"); ok &&
		installTestInitialGOTMPDIR != expected {
		t.Fatalf(
			"initial GOTMPDIR=%q, want external root %q",
			installTestInitialGOTMPDIR,
			expected,
		)
	}
	if err := validateInstallTestTempEnvironment(installTestsTemp); err != nil {
		t.Fatalf("TestMain install test root is invalid: %v", err)
	}
	if installTestInitialTempParent != "" {
		expectedParent, _, err := resolveInstallTestTempParent(
			installTestInitialTempParent,
		)
		if err != nil {
			t.Fatalf("resolve requested external test parent: %v", err)
		}
		if installTestsTemp.parentDir != expectedParent {
			t.Fatalf(
				"isolated test parent=%q, want external parent %q",
				installTestsTemp.parentDir,
				expectedParent,
			)
		}
	}

	testTempDir := t.TempDir()
	canonicalTestTempDir, err := filepath.EvalSymlinks(testTempDir)
	if err != nil {
		t.Fatalf("canonicalize t.TempDir() %s: %v", testTempDir, err)
	}
	canonicalTestTempDir = filepath.Clean(canonicalTestTempDir)
	canonicalRoot, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		t.Fatalf("canonicalize os.TempDir() %s: %v", os.TempDir(), err)
	}
	canonicalRoot = filepath.Clean(canonicalRoot)
	if canonicalRoot != installTestsTemp.root {
		t.Fatalf(
			"canonical os.TempDir()=%q, want TestMain root %q",
			canonicalRoot,
			installTestsTemp.root,
		)
	}
	relative, err := filepath.Rel(canonicalRoot, canonicalTestTempDir)
	if err != nil || relative == "." || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		t.Fatalf(
			"canonical t.TempDir()=%q is outside canonical root %q (relative=%q, err=%v)",
			canonicalTestTempDir,
			canonicalRoot,
			relative,
			err,
		)
	}
}

func TestResolveInstallTestTempParentRejectsUnsafeExternalPaths(t *testing.T) {
	secureParent := filepath.Join(t.TempDir(), "secure-parent")
	if err := os.Mkdir(secureParent, 0o700); err != nil {
		t.Fatal(err)
	}
	resolved, identity, err := resolveInstallTestTempParent(secureParent)
	if err != nil {
		t.Fatalf("resolve secure external parent: %v", err)
	}
	if resolved != secureParent || identity == nil || !identity.IsDir() {
		t.Fatalf(
			"resolved parent=(%q, %#v), want secure directory %q",
			resolved,
			identity,
			secureParent,
		)
	}

	writableParent := filepath.Join(t.TempDir(), "writable-parent")
	if err := os.Mkdir(writableParent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writableParent, 0o770); err != nil {
		t.Fatal(err)
	}
	symlinkParent := filepath.Join(t.TempDir(), "parent-link")
	if err := os.Symlink(secureParent, symlinkParent); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name string
		path string
	}{
		{name: "relative", path: "relative-parent"},
		{name: "kernel-root", path: string(os.PathSeparator)},
		{name: "group-writable", path: writableParent},
		{name: "symlink", path: symlinkParent},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := resolveInstallTestTempParent(test.path); err == nil {
				t.Fatalf("unsafe external parent %q was accepted", test.path)
			}
		})
	}
}

func TestInstallTempRootSetupFailureFailsClosed(t *testing.T) {
	sentinel := errors.New("injected TestMain setup failure")
	called := false
	code := runInstallTestMainWithSetup(
		func() (installTestTempState, error) {
			return installTestTempState{}, sentinel
		},
		func() int {
			called = true
			return 0
		},
		io.Discard,
	)
	if code == 0 {
		t.Fatal("setup failure returned a successful test exit code")
	}
	if called {
		t.Fatal("test runner executed after TestMain setup failure")
	}
}
