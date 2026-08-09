package verifierlauncher

import (
	"reflect"
	"strings"
	"testing"
)

func validContractArguments() Arguments {
	stagingRoot := productionStagingPrefix + "/caseid-01234567"
	return Arguments{
		Runner:       stagingRoot + "/runner/run-faketcp-verifier-only.py",
		RunnerSHA256: strings.Repeat("a", 64),
		StagingRoot:  stagingRoot,
		Binary:       stagingRoot + "/artifacts/wg-mix-ebpf",
		BinarySHA256: strings.Repeat("b", 64),
		Object:       stagingRoot + "/artifacts/wg_mix_faketcp_experimental.o",
		ObjectSHA256: strings.Repeat("c", 64),
	}
}

func contractArgv(arguments Arguments) []string {
	return []string{
		"--runner", arguments.Runner,
		"--runner-sha256", arguments.RunnerSHA256,
		"--staging-root", arguments.StagingRoot,
		"--binary", arguments.Binary,
		"--binary-sha256", arguments.BinarySHA256,
		"--object", arguments.Object,
		"--object-sha256", arguments.ObjectSHA256,
	}
}

func TestParseArgumentsRequiresClosedSingleUseCLI(t *testing.T) {
	arguments := validContractArguments()
	parsed, err := parseArguments(contractArgv(arguments))
	if err != nil {
		t.Fatalf("parse valid arguments: %v", err)
	}
	if !reflect.DeepEqual(parsed, arguments) {
		t.Fatalf("parsed arguments mismatch:\n got: %#v\nwant: %#v", parsed, arguments)
	}

	for name, argv := range map[string][]string{
		"missing":   contractArgv(arguments)[:12],
		"duplicate": append(contractArgv(arguments)[:12], "--runner", arguments.Runner),
		"abbreviation": append(
			[]string{"--run", arguments.Runner},
			contractArgv(arguments)[2:]...,
		),
		"equals form": append(
			[]string{"--runner=" + arguments.Runner, "ignored"},
			contractArgv(arguments)[2:]...,
		),
		"python override": append(
			contractArgv(arguments)[:12],
			"--python", productionPythonPath,
		),
		"environment override": append(
			contractArgv(arguments)[:12],
			"--env", "PATH=/tmp",
		),
		"extra argv": append(
			contractArgv(arguments)[:12],
			"--arg", "--unsafe",
		),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseArguments(argv); err == nil {
				t.Fatal("unexpectedly accepted invalid launcher CLI")
			}
		})
	}
}

func TestValidateArgumentsLocksPrefixPathsAndHashes(t *testing.T) {
	arguments := validContractArguments()
	if err := validateArguments(arguments, productionPolicy); err != nil {
		t.Fatalf("validate production-shaped arguments: %v", err)
	}

	for name, mutate := range map[string]func(*Arguments){
		"wrong prefix": func(value *Arguments) {
			value.StagingRoot = "/tmp/wg-mix-ebpf-faketcp-verifier/caseid-01234567"
		},
		"nested unique ID": func(value *Arguments) {
			value.StagingRoot = productionStagingPrefix + "/nested/caseid-01234567"
		},
		"noncanonical unique ID": func(value *Arguments) {
			value.StagingRoot = productionStagingPrefix + "/BAD-ID"
		},
		"runner escape": func(value *Arguments) {
			value.Runner = productionStagingPrefix + "/runner.py"
		},
		"binary sibling prefix": func(value *Arguments) {
			value.Binary = value.StagingRoot + "-other/wg-mix-ebpf"
		},
		"object traversal": func(value *Arguments) {
			value.Object = value.StagingRoot + "/artifacts/../object.o"
		},
		"uppercase hash": func(value *Arguments) {
			value.RunnerSHA256 = strings.Repeat("A", 64)
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := arguments
			mutate(&changed)
			if err := validateArguments(changed, productionPolicy); err == nil {
				t.Fatal("unexpectedly accepted invalid launcher arguments")
			}
		})
	}
}

func TestProductionExecPlanIsExactAndDescriptorOnly(t *testing.T) {
	arguments := validContractArguments()
	plan := makeExecPlan(arguments, productionPolicy)
	wantArgv := []string{
		"/usr/bin/python3",
		"-I",
		"/proc/self/fd/99",
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
	}
	if plan.path != "/usr/bin/python3" {
		t.Fatalf("exec path = %q, want fixed Python", plan.path)
	}
	if !reflect.DeepEqual(plan.argv, wantArgv) {
		t.Fatalf("exec argv mismatch:\n got: %#v\nwant: %#v", plan.argv, wantArgv)
	}
	if !reflect.DeepEqual(plan.env, []string{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"LC_ALL=C",
	}) {
		t.Fatalf("exec environment mismatch: %#v", plan.env)
	}
	if runnerExecFD == childBinaryExecFD || runnerExecFD == childObjectExecFD {
		t.Fatal("launcher runner FD conflicts with Python runner artifact FDs")
	}
}

func TestProductionPolicyRequiresExternalRootTrustBoundary(t *testing.T) {
	if productionPolicy.stagingPrefix != productionStagingPrefix ||
		productionPolicy.pythonPath != productionPythonPath ||
		productionPolicy.procFDPrefix != productionProcFDPrefix ||
		!productionPolicy.requireRoot || productionPolicy.runnerOwner != (owner{}) ||
		len(productionPolicy.directoryOwners) != 1 {
		t.Fatalf("production policy drifted: %#v", productionPolicy)
	}
	if _, accepted := productionPolicy.directoryOwners[owner{}]; !accepted {
		t.Fatal("production directory owner is not locked to root:root")
	}
}
