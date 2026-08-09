package dataplane

import (
	"reflect"
	"strconv"
	"testing"
)

func scopedSessionCheckerArgs(sessionSeconds int) []string {
	return []string{
		"--expected-seconds", strconv.Itoa(sessionSeconds),
		"--maximum-duration-deviation", "0.5",
		"--minimum-delivery-ratio", "0.99",
		"--minimum-stream-bytes", "1048576",
	}
}

func scopedOneCheckerArgs(path, direction string, streams, sessionSeconds int) []string {
	args := []string{
		"one", path,
		"--direction", direction,
		"--streams", strconv.Itoa(streams),
		"--minimum-fairness", "0.90",
		"--maximum-retransmit-rate", "0.0001",
	}
	return append(args, scopedSessionCheckerArgs(sessionSeconds)...)
}

func scopedSoakCheckerArgs(paths []string, windows, streams, sessionSeconds int) []string {
	args := append([]string{"soak"}, paths...)
	args = append(args,
		"--expected-windows", strconv.Itoa(windows),
		"--streams", strconv.Itoa(streams),
		"--minimum-fairness", "0.90",
		"--maximum-window-retransmit-rate", "0.005",
		"--maximum-overall-retransmit-rate", "0.001",
		"--minimum-throughput-ratio", "0.70",
	)
	return append(args, scopedSessionCheckerArgs(sessionSeconds)...)
}

func TestScopedRealNICCheckerArgvContract(t *testing.T) {
	wantOne := []string{
		"one", "/evidence/session.json",
		"--direction", "bidir",
		"--streams", "16",
		"--minimum-fairness", "0.90",
		"--maximum-retransmit-rate", "0.0001",
		"--expected-seconds", "30",
		"--maximum-duration-deviation", "0.5",
		"--minimum-delivery-ratio", "0.99",
		"--minimum-stream-bytes", "1048576",
	}
	if got := scopedOneCheckerArgs("/evidence/session.json", "bidir", 16, 30); !reflect.DeepEqual(got, wantOne) {
		t.Fatalf("one-session checker argv drifted:\n got: %q\nwant: %q", got, wantOne)
	}
	wantSoak := []string{
		"soak", "/evidence/window-1.json", "/evidence/window-2.json",
		"--expected-windows", "12",
		"--streams", "4",
		"--minimum-fairness", "0.90",
		"--maximum-window-retransmit-rate", "0.005",
		"--maximum-overall-retransmit-rate", "0.001",
		"--minimum-throughput-ratio", "0.70",
		"--expected-seconds", "300",
		"--maximum-duration-deviation", "0.5",
		"--minimum-delivery-ratio", "0.99",
		"--minimum-stream-bytes", "1048576",
	}
	paths := []string{"/evidence/window-1.json", "/evidence/window-2.json"}
	if got := scopedSoakCheckerArgs(paths, 12, 4, 300); !reflect.DeepEqual(got, wantSoak) {
		t.Fatalf("soak checker argv drifted:\n got: %q\nwant: %q", got, wantSoak)
	}
}
