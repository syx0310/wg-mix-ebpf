//go:build linux

package faketcp

import "golang.org/x/sys/unix"

// LinuxMonotonicClock is the production backend for values compared with
// bpf_ktime_get_ns timestamps.
type LinuxMonotonicClock struct{}

func (LinuxMonotonicClock) Domain() string { return BPFMonotonicClockDomain }

func (LinuxMonotonicClock) NowNanos() (uint64, error) {
	var value unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &value); err != nil {
		return 0, err
	}
	return monotonicNanosFromParts(value.Sec, value.Nsec)
}
