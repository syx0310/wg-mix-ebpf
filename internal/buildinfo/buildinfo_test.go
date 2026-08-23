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
	if info.EmbeddedFakeTCPObjectSHA256 != UnknownSHA256 &&
		!regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(info.EmbeddedFakeTCPObjectSHA256) {
		t.Fatalf("embedded FakeTCP BPF SHA-256 = %q", info.EmbeddedFakeTCPObjectSHA256)
	}
	if info.EmbeddedFakeTCPLegacy515ObjectSHA256 != UnknownSHA256 &&
		!regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(info.EmbeddedFakeTCPLegacy515ObjectSHA256) {
		t.Fatalf("embedded legacy 5.15 FakeTCP BPF SHA-256 = %q", info.EmbeddedFakeTCPLegacy515ObjectSHA256)
	}
}

func TestSourceCommitScriptRejectsRepositoryEnvironmentRedirects(t *testing.T) {
	root := repositoryRoot(t)
	repo := identityTestRepository(t)
	script := filepath.Join(root, "scripts", "source-commit.sh")
	baseline := runSourceCommitScript(t, script, repo, nil)
	if want := runGit(t, repo, "rev-parse", "HEAD"); baseline != want {
		t.Fatalf("clean source commit = %q, want %q", baseline, want)
	}
	polluted := runSourceCommitScript(t, script, repo, map[string]string{
		"PATH":                filepath.Join(repo, "not-a-path"),
		"GIT_DIR":             filepath.Join(repo, "not-a-git-directory"),
		"GIT_WORK_TREE":       filepath.Join(repo, "not-a-worktree"),
		"GIT_INDEX_FILE":      filepath.Join(repo, "not-an-index"),
		"GIT_CONFIG_COUNT":    "1",
		"GIT_CONFIG_KEY_0":    "core.worktree",
		"GIT_CONFIG_VALUE_0":  filepath.Join(repo, "not-a-worktree"),
		"SOURCE_COMMIT":       "ffffffffffffffffffffffffffffffffffffffff",
		"BUILD_SOURCE_COMMIT": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
	})
	if polluted != baseline {
		t.Fatalf("polluted source commit = %q, want baseline %q", polluted, baseline)
	}
}

func TestSourceCommitScriptRejectsDirtyWorktrees(t *testing.T) {
	root := repositoryRoot(t)
	script := filepath.Join(root, "scripts", "source-commit.sh")
	tests := []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{
			name: "tracked",
			mutate: func(t *testing.T, repo string) {
				t.Helper()
				if err := os.WriteFile(
					filepath.Join(repo, "tracked.txt"),
					[]byte("modified\n"),
					0o600,
				); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "staged",
			mutate: func(t *testing.T, repo string) {
				t.Helper()
				if err := os.WriteFile(
					filepath.Join(repo, "tracked.txt"),
					[]byte("staged\n"),
					0o600,
				); err != nil {
					t.Fatal(err)
				}
				runGit(t, repo, "add", "tracked.txt")
			},
		},
		{
			name: "untracked",
			mutate: func(t *testing.T, repo string) {
				t.Helper()
				if err := os.WriteFile(
					filepath.Join(repo, "untracked.txt"),
					[]byte("untracked\n"),
					0o600,
				); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := identityTestRepository(t)
			tt.mutate(t, repo)
			if got := runSourceCommitScript(t, script, repo, nil); got != UnknownCommit {
				t.Fatalf("dirty source commit = %q, want %q", got, UnknownCommit)
			}
		})
	}
}

func TestSourceCommitScriptAcceptsCleanDetachedHead(t *testing.T) {
	root := repositoryRoot(t)
	repo := identityTestRepository(t)
	want := runGit(t, repo, "rev-parse", "HEAD")
	runGit(t, repo, "checkout", "--detach", "--quiet", want)
	if got := runSourceCommitScript(
		t,
		filepath.Join(root, "scripts", "source-commit.sh"),
		repo,
		nil,
	); got != want {
		t.Fatalf("detached source commit = %q, want %q", got, want)
	}
}

func TestMakeBuildIdentityCannotBeOverridden(t *testing.T) {
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("make is unavailable")
	}
	root := repositoryRoot(t)
	repo := makeBuildIdentityTestRepository(t, root)
	want := sourceCommitScript(t, repo, nil)
	injectedCommit := "ffffffffffffffffffffffffffffffffffffffff"
	overlay := filepath.Join(repo, "outside-overlay.json")
	cmd := exec.Command(
		"make",
		"-n",
		"BUILD_SOURCE_COMMIT="+injectedCommit,
		"BUILD_IDENTITY_LDFLAG=-X=injected",
		"GOFLAGS=-overlay="+overlay,
		"GOENV="+filepath.Join(repo, "outside-goenv"),
		"GOWORK="+filepath.Join(repo, "outside-go.work"),
		"build-linux-amd64",
	)
	cmd.Dir = repo
	cmd.Env = environmentWith(os.Environ(), map[string]string{
		"SOURCE_COMMIT":       injectedCommit,
		"BUILD_SOURCE_COMMIT": injectedCommit,
		"GOFLAGS":             "-overlay=" + overlay,
		"GOENV":               filepath.Join(repo, "outside-goenv"),
		"GOWORK":              filepath.Join(repo, "outside-go.work"),
		"GO111MODULE":         "off",
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
	if strings.Contains(got, overlay) || strings.Contains(got, "outside-go") {
		t.Fatalf("make accepted external Go build inputs:\n%s", got)
	}
	for _, required := range []string{
		"GOENV=off",
		"GOWORK=off",
		"GOFLAGS=",
		"GO111MODULE=on",
		"-mod=readonly",
		"-buildvcs=false",
	} {
		if !strings.Contains(got, required) {
			t.Fatalf("make output lacks %q:\n%s", required, got)
		}
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
	return runSourceCommitScript(
		t,
		filepath.Join(root, "scripts", "source-commit.sh"),
		root,
		environment,
	)
}

func runSourceCommitScript(
	t *testing.T,
	script string,
	repo string,
	environment map[string]string,
) string {
	t.Helper()
	cmd := exec.Command(script)
	cmd.Dir = repo
	cmd.Env = environmentWith(os.Environ(), environment)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("source commit script: %v\n%s", err, output)
	}
	return strings.TrimSpace(string(output))
}

func identityTestRepository(t *testing.T) string {
	t.Helper()
	if _, err := os.Stat("/usr/bin/git"); err != nil {
		t.Skip("fixed system Git is unavailable")
	}
	repo := t.TempDir()
	runGit(t, repo, "init", "-q")
	runGit(t, repo, "config", "user.name", "Identity Test")
	runGit(t, repo, "config", "user.email", "identity@example.invalid")
	if err := os.WriteFile(
		filepath.Join(repo, "tracked.txt"),
		[]byte("initial\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	runGit(t, repo, "add", "tracked.txt")
	runGit(t, repo, "commit", "-q", "--no-gpg-sign", "--no-verify", "-m", "initial")
	return repo
}

func makeBuildIdentityTestRepository(t *testing.T, sourceRoot string) string {
	t.Helper()
	repo := identityTestRepository(t)
	if err := os.Mkdir(filepath.Join(repo, "scripts"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []struct {
		path string
		mode os.FileMode
	}{
		{path: "Makefile", mode: 0o600},
		{path: filepath.Join("scripts", "source-commit.sh"), mode: 0o700},
	} {
		data, err := os.ReadFile(filepath.Join(sourceRoot, fixture.path))
		if err != nil {
			t.Fatalf("read build identity fixture %s: %v", fixture.path, err)
		}
		if err := os.WriteFile(
			filepath.Join(repo, fixture.path),
			data,
			fixture.mode,
		); err != nil {
			t.Fatalf("write build identity fixture %s: %v", fixture.path, err)
		}
	}
	runGit(t, repo, "add", "Makefile", "scripts/source-commit.sh")
	runGit(
		t,
		repo,
		"commit",
		"-q",
		"--no-gpg-sign",
		"--no-verify",
		"-m",
		"add build identity inputs",
	)
	head := runGit(t, repo, "rev-parse", "HEAD")
	runGit(t, repo, "checkout", "--detach", "--quiet", head)
	return repo
}

func runGit(t *testing.T, repo string, args ...string) string {
	t.Helper()
	cmd := exec.Command("/usr/bin/git", args...)
	cmd.Dir = repo
	cmd.Env = environmentWith(os.Environ(), map[string]string{
		"GIT_CONFIG_NOSYSTEM": "1",
		"GIT_CONFIG_GLOBAL":   os.DevNull,
		"GIT_OPTIONAL_LOCKS":  "0",
	})
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, output)
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
