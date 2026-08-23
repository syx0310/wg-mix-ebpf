package guard

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestResolveNftBinaryRequiresExecutableAbsolutePath(t *testing.T) {
	executable := filepath.Join(t.TempDir(), "nft")
	if err := os.WriteFile(executable, []byte("test executable\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	resolved, err := resolveNftBinary(executable)
	if err != nil {
		t.Fatal(err)
	}
	if resolved != executable {
		t.Fatalf("resolved nft binary = %q, want %q", resolved, executable)
	}

	nonExecutable := filepath.Join(t.TempDir(), "nft")
	if err := os.WriteFile(nonExecutable, []byte("not executable\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, binary := range map[string]string{
		"relative":       "nft-wrapper",
		"unclean":        executable + "/../nft",
		"missing":        filepath.Join(t.TempDir(), "missing-nft"),
		"directory":      t.TempDir(),
		"non-executable": nonExecutable,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := resolveNftBinary(binary); err == nil {
				t.Fatalf("unsafe nft binary path %q was accepted", binary)
			}
		})
	}
}

func TestResolveDefaultNftBinaryDoesNotUseInheritedPATH(t *testing.T) {
	trusted := filepath.Join(t.TempDir(), "trusted-nft")
	if err := os.WriteFile(trusted, []byte("test executable\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	maliciousDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(maliciousDir, "nft"), []byte("path executable\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", maliciousDir)

	original := trustedNftBinaryCandidates
	trustedNftBinaryCandidates = []string{trusted}
	t.Cleanup(func() {
		trustedNftBinaryCandidates = original
	})

	for _, binary := range []string{"", "nft"} {
		resolved, err := resolveNftBinary(binary)
		if err != nil {
			t.Fatal(err)
		}
		if resolved != trusted {
			t.Fatalf("resolved nft binary = %q, want trusted path %q", resolved, trusted)
		}
	}
}

func TestNewNftCommandUsesAbsoluteBinaryAndMinimalEnvironment(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "nft")
	if err := os.WriteFile(binary, []byte("test executable\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LD_PRELOAD", "/tmp/hostile.so")
	t.Setenv("LANG", "zh_CN.UTF-8")

	command, err := newNftCommand(t.Context(), binary, "-j", "list", "tables")
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(command.Path) || command.Path != binary {
		t.Fatalf("command path = %q, want %q", command.Path, binary)
	}
	wantArgs := []string{binary, "-j", "list", "tables"}
	if !reflect.DeepEqual(command.Args, wantArgs) {
		t.Fatalf("command args = %q, want %q", command.Args, wantArgs)
	}
	wantEnv := []string{
		"PATH=" + nftCommandPATH,
		"LC_ALL=C",
		"LANG=C",
	}
	if !reflect.DeepEqual(command.Env, wantEnv) {
		t.Fatalf("command env = %q, want %q", command.Env, wantEnv)
	}
	if strings.Contains(strings.Join(command.Env, "\n"), "LD_PRELOAD") {
		t.Fatalf("command inherited unsafe environment: %q", command.Env)
	}
}

func TestNewNftCommandAcceptsTestOnlyContextBinary(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "nft")
	if err := os.WriteFile(binary, []byte("test executable\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	ctx := WithNftBinaryForTest(t.Context(), binary)
	command, err := newNftCommand(ctx, "nft", "-j", "list", "tables")
	if err != nil {
		t.Fatal(err)
	}
	if command.Path != binary {
		t.Fatalf("test command path = %q, want %q", command.Path, binary)
	}
}

func TestNewNftCommandFailsBeforeExecutionWhenBinaryIsMissing(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nft")
	command, err := newNftCommand(t.Context(), missing, "-f", "-")
	if err == nil || command != nil {
		t.Fatalf("missing nft binary produced command=%v error=%v", command, err)
	}
	if !strings.Contains(err.Error(), "inspect nft binary") {
		t.Fatalf("missing nft binary error lacks preflight detail: %v", err)
	}
}
