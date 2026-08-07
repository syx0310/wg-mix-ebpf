package faketcp

import (
	"errors"
	"math"
)

// BPFMonotonicClockDomain names the exact clock domain used by
// bpf_ktime_get_ns. Wall time, process-relative time, CLOCK_BOOTTIME and test
// counters from another origin are not interchangeable with persisted map
// values in this domain.
const BPFMonotonicClockDomain = "CLOCK_MONOTONIC/bpf_ktime_get_ns"

// MonotonicClock supplies nanoseconds from the same Linux CLOCK_MONOTONIC
// origin as bpf_ktime_get_ns. Implementations must return an error rather than
// falling back to wall time or another domain.
type MonotonicClock interface {
	Domain() string
	NowNanos() (uint64, error)
}

func monotonicNanosFromParts(seconds, nanoseconds int64) (uint64, error) {
	if seconds < 0 || nanoseconds < 0 || nanoseconds >= 1_000_000_000 {
		return 0, errors.New("CLOCK_MONOTONIC returned an invalid timespec")
	}
	unsignedSeconds := uint64(seconds)
	if unsignedSeconds > (math.MaxUint64-uint64(nanoseconds))/1_000_000_000 {
		return 0, errors.New("CLOCK_MONOTONIC nanoseconds overflow uint64")
	}
	return unsignedSeconds*1_000_000_000 + uint64(nanoseconds), nil
}
