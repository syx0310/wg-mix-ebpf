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

const installTestTempPrefix = ".wg-mix-ebpf-install-tests-"

// Capture the inherited value before TestMain changes it. The regression test
// uses this to prove that an external GOTMPDIR is replaced before t.TempDir is
// first called.
var installTestInitialGOTMPDIR = os.Getenv("GOTMPDIR")

var installTestsTemp installTestTempState

type installTestTempState struct {
	packageDir   string
	root         string
	rootIdentity os.FileInfo
}

func prepareInstallTestTemp() (installTestTempState, error) {
	var state installTestTempState

	packageDir, err := os.Getwd()
	if err != nil {
		return state, fmt.Errorf("resolve install package test directory: %w", err)
	}
	packageDir, err = filepath.Abs(packageDir)
	if err != nil {
		return state, fmt.Errorf("make install package test directory absolute: %w", err)
	}
	packageDir, err = filepath.EvalSymlinks(filepath.Clean(packageDir))
	if err != nil {
		return state, fmt.Errorf("canonicalize install package test directory: %w", err)
	}
	state.packageDir = filepath.Clean(packageDir)

	root, err := os.MkdirTemp(state.packageDir, installTestTempPrefix)
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
	if state.packageDir == "" || !filepath.IsAbs(state.packageDir) ||
		filepath.Clean(state.packageDir) != state.packageDir {
		return fmt.Errorf(
			"refuse unsafe install package test directory %q",
			state.packageDir,
		)
	}
	rootName := filepath.Base(state.root)
	if state.root == "" || !filepath.IsAbs(state.root) ||
		filepath.Clean(state.root) != state.root ||
		filepath.Dir(state.root) != state.packageDir ||
		!strings.HasPrefix(rootName, installTestTempPrefix) ||
		len(rootName) <= len(installTestTempPrefix) {
		return fmt.Errorf("refuse unsafe isolated install test root %q", state.root)
	}
	if state.rootIdentity == nil {
		return errors.New("isolated install test root identity is missing")
	}

	canonicalPackageDir, err := filepath.EvalSymlinks(state.packageDir)
	if err != nil {
		return fmt.Errorf("canonicalize install package test directory: %w", err)
	}
	packageDirIdentity, err := os.Lstat(state.packageDir)
	if err != nil {
		return fmt.Errorf("identify install package test directory: %w", err)
	}
	if filepath.Clean(canonicalPackageDir) != state.packageDir ||
		!packageDirIdentity.IsDir() ||
		packageDirIdentity.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf(
			"install package test directory is no longer canonical: %s",
			state.packageDir,
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
