//go:build linux

package dataplane

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"unsafe"
)

func TestFakeTCPKprobeStatusV1MatchesFrozenKernelUAPI(t *testing.T) {
	var status fakeTCPKprobeStatusV1
	checks := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{name: "sizeof", got: unsafe.Sizeof(status), want: 64},
		{name: "abi", got: unsafe.Offsetof(status.ABIVersion), want: 0},
		{name: "size", got: unsafe.Offsetof(status.StructSize), want: 4},
		{name: "capabilities", got: unsafe.Offsetof(status.Capabilities), want: 8},
		{name: "cookie", got: unsafe.Offsetof(status.Cookie), want: 16},
		{name: "prepare_hits", got: unsafe.Offsetof(status.PrepareHits), want: 24},
		{name: "commit_hits", got: unsafe.Offsetof(status.CommitHits), want: 32},
		{name: "errors", got: unsafe.Offsetof(status.Errors), want: 40},
		{name: "nmissed", got: unsafe.Offsetof(status.NMissed), want: 48},
		{name: "flags", got: unsafe.Offsetof(status.Flags), want: 56},
		{name: "reserved", got: unsafe.Offsetof(status.Reserved), want: 60},
	}
	for _, check := range checks {
		if check.got != check.want {
			t.Errorf("%s offset/size=%d, want %d", check.name, check.got, check.want)
		}
	}
	if fakeTCPKprobeGetStatusIOCTL != 0x80405701 {
		t.Fatalf("GET_STATUS ioctl=%#x, want %#x", fakeTCPKprobeGetStatusIOCTL, uintptr(0x80405701))
	}
}

func TestValidateFakeTCPKprobeStatusRequiresFullHealthyLease(t *testing.T) {
	status := validFakeTCPKprobeStatusForTest(0x1122334455667788)
	capabilities, requirements, err := validateFakeTCPKprobeStatus(status, status.Cookie)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateEquivalentFakeTCPChecksumCapabilities(capabilities); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"fail-closed", "multi-lease"} {
		if !containsChecksumTestString(strings.Join(capabilities, ","), want) {
			t.Fatalf("capabilities=%v missing %q", capabilities, want)
		}
	}
	for _, requirement := range requirements {
		if requirement.Status != "PASS" {
			t.Fatalf("requirement=%#v", requirement)
		}
	}
}

func TestValidateFakeTCPKprobeStatusReportsAllFailuresWithoutCookie(t *testing.T) {
	const secretCookie = uint64(0x1122334455667788)
	status := validFakeTCPKprobeStatusForTest(secretCookie)
	status.ABIVersion = 9
	status.StructSize = 32
	status.Capabilities = fakeTCPKprobeCapChecksumState
	status.Flags = 0
	status.Errors = 3
	status.NMissed = 4
	status.Reserved = 1
	status.Cookie++
	_, requirements, err := validateFakeTCPKprobeStatus(status, secretCookie)
	if err == nil {
		t.Fatal("expected invalid status rejection")
	}
	got := err.Error()
	for _, want := range []string{
		"ABI=9", "status size=32", "reserved field", "missing capabilities",
		"lease-active", "probes-ready", "bridge-healthy", "3 internal errors",
		"4 missed return probes", "lease identity changed",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("error %q missing %q", got, want)
		}
	}
	if strings.Contains(got, fmt.Sprintf("%d", secretCookie)) ||
		strings.Contains(got, fmt.Sprintf("%x", secretCookie)) {
		t.Fatalf("error leaked cookie: %q", got)
	}
	failures := 0
	for _, requirement := range requirements {
		if requirement.Status == "FAIL" {
			failures++
		}
	}
	if failures < 9 {
		t.Fatalf("requirements did not retain all failures: %#v", requirements)
	}
}

func TestFakeTCPKprobeRuntimeHealthUsesSameLeaseAndStableCookie(t *testing.T) {
	file, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	lease := &fakeTCPKprobeLease{file: file}
	t.Cleanup(func() { _ = lease.Close() })
	const cookie = uint64(0x8877665544332211)
	calls := 0
	probe := &fakeTCPKprobeRuntimeProbe{
		lease: lease,
		ioctlStatus: func(gotFile *os.File, status *fakeTCPKprobeStatusV1) error {
			calls++
			if gotFile != file {
				t.Fatal("health queried a different lease file")
			}
			*status = validFakeTCPKprobeStatusForTest(cookie)
			return nil
		},
	}
	if err := probe.healthy(context.Background(), cookie); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("ioctl calls=%d, want 1", calls)
	}
}

func validFakeTCPKprobeStatusForTest(cookie uint64) fakeTCPKprobeStatusV1 {
	return fakeTCPKprobeStatusV1{
		ABIVersion:   fakeTCPKprobeBridgeABIVersion,
		StructSize:   fakeTCPKprobeStatusStructSize,
		Capabilities: fakeTCPKprobeRequiredCapabilities,
		Cookie:       cookie,
		Flags:        fakeTCPKprobeRequiredStatusFlags,
	}
}

func containsChecksumTestString(value, substring string) bool {
	return strings.Contains(value, substring)
}
