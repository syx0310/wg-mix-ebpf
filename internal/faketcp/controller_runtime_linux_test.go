//go:build linux

package faketcp

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func TestLinuxControllerStatsKernelNameIsExactTruncationContract(t *testing.T) {
	const elfResourceName = "faketcp_stats_map"
	if fakeTCPStatsCount != 19 {
		t.Fatalf("controller stats entries=%d, want final BPF ABI size 19", fakeTCPStatsCount)
	}
	want := elfResourceName[:unix.BPF_OBJ_NAME_LEN-1]
	if fakeTCPStatsKernelMapName != want || fakeTCPStatsKernelMapName == elfResourceName {
		t.Fatalf(
			"stats kernel name=%q, want exact %q separate from ELF resource %q",
			fakeTCPStatsKernelMapName,
			want,
			elfResourceName,
		)
	}
}

func TestInspectLinuxControllerMapAcceptsRealTruncatedStatsName(t *testing.T) {
	stats, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "faketcp_stats_map",
		Type:       ebpf.PerCPUArray,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: fakeTCPStatsCount,
	})
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("real BPF map creation is unavailable without privilege: %v", err)
		}
		t.Fatalf("create real FakeTCP stats map: %v", err)
	}
	t.Cleanup(func() {
		if err := stats.Close(); err != nil {
			t.Errorf("close real FakeTCP stats map: %v", err)
		}
	})

	info, err := stats.Info()
	if err != nil {
		t.Fatal(err)
	}
	if info.Name != fakeTCPStatsKernelMapName {
		t.Fatalf("real stats kernel name=%q, want %q", info.Name, fakeTCPStatsKernelMapName)
	}
	id, err := inspectLinuxControllerMap(
		stats,
		fakeTCPStatsKernelMapName,
		ebpf.PerCPUArray,
		4,
		8,
		fakeTCPStatsCount,
	)
	if err != nil || id == 0 {
		t.Fatalf("inspect real stats map ID=%d error=%v", id, err)
	}
	if _, err := inspectLinuxControllerMap(
		stats,
		"faketcp_stats_map",
		ebpf.PerCPUArray,
		4,
		8,
		fakeTCPStatsCount,
	); err == nil {
		t.Fatal("full ELF resource name was accepted as a kernel map identity")
	}
}
