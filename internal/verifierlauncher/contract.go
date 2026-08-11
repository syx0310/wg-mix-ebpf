package verifierlauncher

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

const (
	productionStagingPrefix = "/run/wg-mix-ebpf-faketcp-verifier"
	productionPythonPath    = "/usr/bin/python3"
	productionProcFDPrefix  = "/proc/self/fd"
	runnerExecFD            = 99
	childBinaryExecFD       = 100
	childObjectExecFD       = 101
	childPath               = "/usr/sbin:/usr/bin:/sbin:/bin"
)

var (
	safePathPattern  = regexp.MustCompile(`^/[A-Za-z0-9_./+@-]+$`)
	safeRunIDPattern = regexp.MustCompile(
		`^[a-z0-9][a-z0-9-]{6,62}[a-z0-9]$`,
	)
	sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Arguments is the complete, closed launcher contract. The production command
// has no switches for selecting another interpreter, environment, descriptor,
// or additional child arguments.
type Arguments struct {
	Runner       string
	RunnerSHA256 string
	StagingRoot  string
	Binary       string
	BinarySHA256 string
	Object       string
	ObjectSHA256 string
}

type owner struct {
	uid uint32
	gid uint32
}

type policy struct {
	stagingPrefix       string
	pythonPath          string
	procFDPrefix        string
	requireRoot         bool
	directoryOwners     map[owner]struct{}
	runnerOwner         owner
	allowStickyAncestor bool
}

var productionPolicy = policy{
	stagingPrefix:   productionStagingPrefix,
	pythonPath:      productionPythonPath,
	procFDPrefix:    productionProcFDPrefix,
	requireRoot:     true,
	directoryOwners: map[owner]struct{}{{uid: 0, gid: 0}: {}},
	runnerOwner:     owner{uid: 0, gid: 0},
}

type execPlan struct {
	path string
	argv []string
	env  []string
}

func parseArguments(argv []string) (Arguments, error) {
	var arguments Arguments
	if len(argv) != 14 {
		return arguments, fmt.Errorf("exactly seven option/value pairs are required")
	}

	seen := make(map[string]struct{}, 7)
	for index := 0; index < len(argv); index += 2 {
		option := argv[index]
		value := argv[index+1]
		if _, duplicate := seen[option]; duplicate {
			return Arguments{}, fmt.Errorf("%s may be specified only once", option)
		}
		seen[option] = struct{}{}
		switch option {
		case "--runner":
			arguments.Runner = value
		case "--runner-sha256":
			arguments.RunnerSHA256 = value
		case "--staging-root":
			arguments.StagingRoot = value
		case "--binary":
			arguments.Binary = value
		case "--binary-sha256":
			arguments.BinarySHA256 = value
		case "--object":
			arguments.Object = value
		case "--object-sha256":
			arguments.ObjectSHA256 = value
		default:
			return Arguments{}, fmt.Errorf("unsupported launcher option %q", option)
		}
	}

	required := map[string]string{
		"--runner":        arguments.Runner,
		"--runner-sha256": arguments.RunnerSHA256,
		"--staging-root":  arguments.StagingRoot,
		"--binary":        arguments.Binary,
		"--binary-sha256": arguments.BinarySHA256,
		"--object":        arguments.Object,
		"--object-sha256": arguments.ObjectSHA256,
	}
	for option, value := range required {
		if value == "" {
			return Arguments{}, fmt.Errorf("%s is required exactly once", option)
		}
	}
	return arguments, nil
}

func requireSafePath(value, label string) error {
	if value == "" || value == "/" || strings.HasPrefix(value, "//") ||
		strings.HasSuffix(value, "/") || !safePathPattern.MatchString(value) ||
		path.Clean(value) != value {
		return fmt.Errorf("%s must be an absolute normalized safe path", label)
	}
	return nil
}

func requireSHA256(value, label string) error {
	if !sha256Pattern.MatchString(value) {
		return fmt.Errorf(
			"%s SHA-256 must be exactly 64 lowercase hexadecimal characters",
			label,
		)
	}
	return nil
}

func validateStagingRoot(stagingRoot string, currentPolicy policy) error {
	if err := requireSafePath(stagingRoot, "staging root"); err != nil {
		return err
	}
	if path.Dir(stagingRoot) != currentPolicy.stagingPrefix {
		return fmt.Errorf(
			"staging root must be one unique-ID directory below %s",
			currentPolicy.stagingPrefix,
		)
	}
	if !safeRunIDPattern.MatchString(path.Base(stagingRoot)) {
		return fmt.Errorf("staging root unique ID is not canonical")
	}
	return nil
}

func targetRelativeParts(target, stagingRoot, label string) ([]string, error) {
	if err := requireSafePath(target, label+" path"); err != nil {
		return nil, err
	}
	prefix := stagingRoot + "/"
	if !strings.HasPrefix(target, prefix) {
		return nil, fmt.Errorf("%s path is outside the staging root", label)
	}
	relative := strings.TrimPrefix(target, prefix)
	parts := strings.Split(relative, "/")
	if len(parts) == 0 {
		return nil, fmt.Errorf("%s path is not canonical below the staging root", label)
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, fmt.Errorf(
				"%s path is not canonical below the staging root",
				label,
			)
		}
	}
	return parts, nil
}

func validateArguments(arguments Arguments, currentPolicy policy) error {
	if err := validateStagingRoot(arguments.StagingRoot, currentPolicy); err != nil {
		return err
	}
	for _, candidate := range []struct {
		path  string
		label string
		hash  string
	}{
		{path: arguments.Runner, label: "runner", hash: arguments.RunnerSHA256},
		{path: arguments.Binary, label: "binary", hash: arguments.BinarySHA256},
		{path: arguments.Object, label: "object", hash: arguments.ObjectSHA256},
	} {
		if _, err := targetRelativeParts(
			candidate.path,
			arguments.StagingRoot,
			candidate.label,
		); err != nil {
			return err
		}
		if err := requireSHA256(candidate.hash, candidate.label); err != nil {
			return err
		}
	}
	return nil
}

func makeExecPlan(arguments Arguments, currentPolicy policy) execPlan {
	runnerDescriptorPath := fmt.Sprintf(
		"%s/%d",
		currentPolicy.procFDPrefix,
		runnerExecFD,
	)
	return execPlan{
		path: currentPolicy.pythonPath,
		argv: []string{
			currentPolicy.pythonPath,
			"-I",
			runnerDescriptorPath,
			"--runner-sha256",
			arguments.RunnerSHA256,
			"--staging-root",
			arguments.StagingRoot,
			"--binary",
			arguments.Binary,
			"--binary-sha256",
			arguments.BinarySHA256,
			"--object",
			arguments.Object,
			"--object-sha256",
			arguments.ObjectSHA256,
		},
		env: []string{
			"PATH=" + childPath,
			"LC_ALL=C",
		},
	}
}
