//go:build !windows

package pinidentity

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestActualDirectoryPathAliasesProduceOneResourceKey(t *testing.T) {
	parent := t.TempDir()
	if err := os.Mkdir(filepath.Join(parent, "alias-step"), 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(parent, "alias-step", "..")
	directInfo, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	aliasInfo, err := os.Stat(alias)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(directInfo, aliasInfo) {
		t.Fatalf("%s and %s do not resolve to one directory", parent, alias)
	}
	directStat, ok := directInfo.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("direct stat type = %T", directInfo.Sys())
	}
	aliasStat, ok := aliasInfo.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("alias stat type = %T", aliasInfo.Sys())
	}
	directKey, err := Key(
		uint64(directStat.Dev),
		uint64(directStat.Ino),
		"wg-mix-ebpf-a",
	)
	if err != nil {
		t.Fatal(err)
	}
	aliasKey, err := Key(
		uint64(aliasStat.Dev),
		uint64(aliasStat.Ino),
		"wg-mix-ebpf-a",
	)
	if err != nil {
		t.Fatal(err)
	}
	if directKey != aliasKey {
		t.Fatalf("path alias keys differ: %s != %s", directKey, aliasKey)
	}
}

func TestBasenameAndKeyBoundaries(t *testing.T) {
	maximum := "a" + strings.Repeat("-", 253) + "z"
	if len(maximum) != 255 {
		t.Fatalf("test basename length = %d", len(maximum))
	}
	if _, err := Key(1, 1, maximum); err != nil {
		t.Fatalf("255-byte basename rejected: %v", err)
	}
	if _, err := Key(1, 1, maximum+"z"); err == nil {
		t.Fatal("256-byte basename unexpectedly accepted")
	}
	key, err := Key(1, 1, "wg-mix-ebpf")
	if err != nil {
		t.Fatal(err)
	}
	if !ValidKey(key) {
		t.Fatalf("valid key rejected: %s", key)
	}
	if ValidKey(strings.ToUpper(key)) ||
		ValidKey(key[:63]) ||
		ValidKey(key+"0") ||
		ValidKey(strings.Repeat("g", 64)) {
		t.Fatal("ValidKey accepted a non-canonical digest")
	}
}
