package buildinfo

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

func TestNormalizeSourceCommit(t *testing.T) {
	valid := "0123456789abcdef0123456789abcdef01234567"
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "valid", value: valid, want: valid},
		{name: "default", value: UnknownCommit, want: UnknownCommit},
		{name: "empty", value: "", want: UnknownCommit},
		{name: "short", value: valid[:12], want: UnknownCommit},
		{name: "uppercase", value: "0123456789ABCDEF0123456789ABCDEF01234567", want: UnknownCommit},
		{name: "shell syntax", value: "$(touch injected)0123456789abcdef01234567", want: UnknownCommit},
		{name: "newline", value: valid[:39] + "\n", want: UnknownCommit},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeSourceCommit(tt.value); got != tt.want {
				t.Fatalf("normalizeSourceCommit(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestCurrentHasDeterministicDefaults(t *testing.T) {
	info := Current()
	if info.Version != Version {
		t.Fatalf("version = %q, want %q", info.Version, Version)
	}
	if info.SourceCommit != UnknownCommit {
		t.Fatalf("source commit = %q, want %q", info.SourceCommit, UnknownCommit)
	}
	if info.BPFABIVersion != abi.Version {
		t.Fatalf("BPF ABI version = %d, want %d", info.BPFABIVersion, abi.Version)
	}
	if info.EmbeddedBPFObjectSHA256 != UnknownSHA256 &&
		!regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(info.EmbeddedBPFObjectSHA256) {
		t.Fatalf("embedded BPF SHA-256 = %q", info.EmbeddedBPFObjectSHA256)
	}
}

func TestSourceCommitScriptRejectsRepositoryEnvironmentRedirects(t *testing.T) {
	root := repositoryRoot(t)
	baseline := sourceCommitScript(t, root, nil)
	if baseline != UnknownCommit && normalizeSourceCommit(baseline) != baseline {
		t.Fatalf("source commit script output = %q", baseline)
	}
	polluted := sourceCommitScript(t, root, map[string]string{
		"GIT_DIR":             filepath.Join(root, "not-a-git-directory"),
		"GIT_WORK_TREE":       filepath.Join(root, "not-a-worktree"),
		"GIT_INDEX_FILE":      filepath.Join(root, "not-an-index"),
		"GIT_CONFIG_COUNT":    "1",
		"GIT_CONFIG_KEY_0":    "core.worktree",
		"GIT_CONFIG_VALUE_0":  filepath.Join(root, "not-a-worktree"),
		"SOURCE_COMMIT":       "ffffffffffffffffffffffffffffffffffffffff",
		"BUILD_SOURCE_COMMIT": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
	})
	if polluted != baseline {
		t.Fatalf("polluted source commit = %q, want baseline %q", polluted, baseline)
	}
}

func TestMakeBuildIdentityCannotBeOverridden(t *testing.T) {
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("make is unavailable")
	}
	root := repositoryRoot(t)
	want := sourceCommitScript(t, root, nil)
	injectedCommit := "ffffffffffffffffffffffffffffffffffffffff"
	cmd := exec.Command(
		"make",
		"-n",
		"BUILD_SOURCE_COMMIT="+injectedCommit,
		"BUILD_IDENTITY_LDFLAG=-X=injected",
		"build-linux-amd64",
	)
	cmd.Dir = root
	cmd.Env = environmentWith(os.Environ(), map[string]string{
		"SOURCE_COMMIT":       injectedCommit,
		"BUILD_SOURCE_COMMIT": injectedCommit,
	})
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("make -n build-linux-amd64: %v\n%s", err, output)
	}
	got := string(output)
	wantFlag := "internal/buildinfo.sourceCommit=" + want
	if !strings.Contains(got, wantFlag) {
		t.Fatalf("make output lacks %q:\n%s", wantFlag, got)
	}
	if want != injectedCommit && strings.Contains(got, "sourceCommit="+injectedCommit) {
		t.Fatalf("make accepted injected commit:\n%s", got)
	}
	if strings.Contains(got, "-X=injected") {
		t.Fatalf("make accepted injected identity linker flag:\n%s", got)
	}
	if !strings.Contains(got, "-buildvcs=false") {
		t.Fatalf("make output lacks explicit VCS isolation:\n%s", got)
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

func sourceCommitScript(
	t *testing.T,
	root string,
	environment map[string]string,
) string {
	t.Helper()
	cmd := exec.Command(filepath.Join(root, "scripts", "source-commit.sh"))
	cmd.Dir = root
	cmd.Env = environmentWith(os.Environ(), environment)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("source commit script: %v\n%s", err, output)
	}
	return strings.TrimSpace(string(output))
}

func environmentWith(base []string, overrides map[string]string) []string {
	if len(overrides) == 0 {
		return base
	}
	out := make([]string, 0, len(base)+len(overrides))
	for _, entry := range base {
		name, _, _ := strings.Cut(entry, "=")
		if _, replaced := overrides[name]; !replaced {
			out = append(out, entry)
		}
	}
	for name, value := range overrides {
		out = append(out, name+"="+value)
	}
	return out
}
