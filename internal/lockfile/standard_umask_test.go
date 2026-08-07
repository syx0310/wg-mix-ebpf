//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package lockfile

import (
	"os"
	"testing"

	"github.com/syx0310/wg-mix-ebpf/internal/testutil"
)

func TestMain(m *testing.M) {
	os.Exit(testutil.RunWithStandardUmask(m.Run))
}
