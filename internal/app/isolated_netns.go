package app

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

const isolatedNetNSTestRoot = "/run/wg-mix-ebpf-tests"

var isolatedNetNSTestRunID = regexp.MustCompile(`^[0-9a-f]{8,64}$`)

type isolatedNetNSTestLayout struct {
	runBase  string
	bpffsDir string
	lease    string
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

	runName := filepath.Base(runDir)
	if !strings.HasPrefix(runName, "run-") || len(runName) == len("run-") {
		return isolatedNetNSTestLayout{}, fmt.Errorf(
			"--isolated-netns-test run-dir must have a run-<role> basename",
		)
	}
	role := strings.TrimPrefix(runName, "run-")
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
	bpffsDir := filepath.Join(runBase, "bpffs")
	if filepath.Dir(pinPath) != bpffsDir || filepath.Base(pinPath) == "." {
		return isolatedNetNSTestLayout{}, fmt.Errorf(
			"--isolated-netns-test pin must be a direct child of %s",
			bpffsDir,
		)
	}

	return isolatedNetNSTestLayout{
		runBase:  runBase,
		bpffsDir: bpffsDir,
		lease:    filepath.Join(runDir, "daemon.lease"),
	}, nil
}
