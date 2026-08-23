package guard

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const nftCommandPATH = "/usr/sbin:/usr/bin:/sbin:/bin"

var trustedNftBinaryCandidates = []string{
	"/usr/sbin/nft",
	"/usr/bin/nft",
	"/sbin/nft",
	"/bin/nft",
}

type nftBinaryTestContextKey struct{}

// WithNftBinaryForTest supplies an explicit absolute nft binary to a call
// chain which otherwise constructs its CommandExecutor internally. It is
// unavailable outside Go test binaries and therefore cannot weaken the fixed
// production search path.
func WithNftBinaryForTest(ctx context.Context, binary string) context.Context {
	if flag.Lookup("test.v") == nil {
		panic("WithNftBinaryForTest is only available in Go test binaries")
	}
	return context.WithValue(ctx, nftBinaryTestContextKey{}, binary)
}

func nftBinaryFromTestContext(ctx context.Context) (string, bool) {
	if flag.Lookup("test.v") == nil || ctx == nil {
		return "", false
	}
	binary, ok := ctx.Value(nftBinaryTestContextKey{}).(string)
	return binary, ok
}

// resolveNftBinary returns an absolute executable path without consulting the
// caller's PATH. Production uses an empty string or "nft" and is therefore
// limited to the fixed system locations above. An explicit path exists for
// dependency injection and tests, but it must already be clean and absolute.
func resolveNftBinary(binary string) (string, error) {
	if binary != "" && binary != "nft" {
		return validateNftBinaryPath(binary)
	}

	var failures []error
	for _, candidate := range trustedNftBinaryCandidates {
		resolved, err := validateNftBinaryPath(candidate)
		if err == nil {
			return resolved, nil
		}
		failures = append(failures, err)
	}
	return "", fmt.Errorf(
		"resolve nft binary from trusted absolute paths %v: %w",
		trustedNftBinaryCandidates,
		errors.Join(failures...),
	)
}

func validateNftBinaryPath(binary string) (string, error) {
	if binary == "" || !filepath.IsAbs(binary) || filepath.Clean(binary) != binary {
		return "", fmt.Errorf("nft binary path %q must be clean and absolute", binary)
	}
	info, err := os.Stat(binary)
	if err != nil {
		return "", fmt.Errorf("inspect nft binary %s: %w", binary, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("nft binary %s is not a regular file", binary)
	}
	if info.Mode().Perm()&0o111 == 0 {
		return "", fmt.Errorf("nft binary %s is not executable", binary)
	}
	return binary, nil
}

// newNftCommand builds an nft subprocess with an absolute argv[0] and a
// minimal deterministic environment. In particular, locale-dependent stderr
// cannot change the missing-table classifier and inherited loader/search
// variables cannot redirect the privileged subprocess.
func newNftCommand(
	ctx context.Context,
	binary string,
	args ...string,
) (*exec.Cmd, error) {
	if binary == "" || binary == "nft" {
		if injected, ok := nftBinaryFromTestContext(ctx); ok {
			binary = injected
		}
	}
	resolved, err := resolveNftBinary(binary)
	if err != nil {
		return nil, err
	}
	command := exec.CommandContext(ctx, resolved, args...)
	command.Env = []string{
		"PATH=" + nftCommandPATH,
		"LC_ALL=C",
		"LANG=C",
	}
	return command, nil
}
