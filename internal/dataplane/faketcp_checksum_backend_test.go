package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/syx0310/wg-mix-ebpf/internal/config"
)

type fakeTCPChecksumTestLease struct {
	closes int
	err    error
}

func mustJSONForChecksumTest(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func (lease *fakeTCPChecksumTestLease) Close() error {
	lease.closes++
	return lease.err
}

func TestResolveFakeTCPChecksumBackendAutoPrefersKfuncWithoutOpeningKprobeLease(t *testing.T) {
	kprobeCalls := 0
	selection, err := resolveFakeTCPChecksumBackendWith(
		t.Context(),
		config.FakeTCPChecksumBackendAuto,
		fakeTCPChecksumBackendDependencies{
			probeKfunc: func() error { return nil },
			acquireKprobe: func(context.Context) (fakeTCPKprobeBackendAcquisition, error) {
				kprobeCalls++
				return fakeTCPKprobeBackendAcquisition{}, errors.New("must not run")
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if selection.Backend != config.FakeTCPChecksumBackendKfunc ||
		selection.ObjectVariant != FakeTCPObjectVariantModernKfunc || selection.LeaseHeld {
		t.Fatalf("selection = %#v", selection)
	}
	if kprobeCalls != 0 {
		t.Fatalf("kprobe acquisition calls = %d", kprobeCalls)
	}
	if err := selection.Healthy(t.Context()); err != nil {
		t.Fatalf("kfunc health: %v", err)
	}
}

func TestResolveFakeTCPChecksumBackendAutoUsesOnlyEquivalentKprobe(t *testing.T) {
	lease := &fakeTCPChecksumTestLease{}
	selection, err := resolveFakeTCPChecksumBackendWith(
		t.Context(),
		config.FakeTCPChecksumBackendAuto,
		fakeTCPChecksumBackendDependencies{
			probeKfunc: func() error {
				return errors.Join(ErrFakeTCPChecksumBackendUnsupported, errors.New("no module BTF"))
			},
			acquireKprobe: func(context.Context) (fakeTCPKprobeBackendAcquisition, error) {
				return fakeTCPKprobeBackendAcquisition{
					module:       DefaultFakeTCPKprobeModule,
					capabilities: append([]string(nil), fullFakeTCPChecksumCapabilities...),
					cookie:       0x1122334455667788,
					lease:        lease,
					health:       func(context.Context, uint64) error { return nil },
				}, nil
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if selection.Backend != config.FakeTCPChecksumBackendKprobe ||
		selection.ObjectVariant != FakeTCPObjectVariantLegacy515 || !selection.LeaseHeld {
		t.Fatalf("selection = %#v", selection)
	}
	if cookie, ok := selection.KprobeCookie(); !ok || cookie != 0x1122334455667788 {
		t.Fatalf("cookie = %x, available=%v", cookie, ok)
	}
	if err := selection.Healthy(t.Context()); err != nil {
		t.Fatalf("kprobe health: %v", err)
	}
	status := selection.RuntimeStatus()
	if status.Backend != config.FakeTCPChecksumBackendKprobe || !status.LeaseHeld {
		t.Fatalf("status = %#v", status)
	}
	if rendered := strings.ToLower(strings.TrimSpace(mustJSONForChecksumTest(t, status))); strings.Contains(rendered, "112233") || strings.Contains(rendered, "cookie") {
		t.Fatalf("status exposed cookie: %s", rendered)
	}
	if err := selection.Close(); err != nil {
		t.Fatal(err)
	}
	if lease.closes != 1 {
		t.Fatalf("lease closes = %d", lease.closes)
	}
	if _, ok := selection.KprobeCookie(); ok {
		t.Fatal("closed selection retained kprobe cookie")
	}
	if selection.RuntimeStatus().LeaseHeld {
		t.Fatal("closed selection reported held lease")
	}
}

func TestResolveFakeTCPChecksumBackendAutoRejectsOperationalKfuncFailure(t *testing.T) {
	kprobeCalls := 0
	selection, err := resolveFakeTCPChecksumBackendWith(
		t.Context(),
		config.FakeTCPChecksumBackendAuto,
		fakeTCPChecksumBackendDependencies{
			probeKfunc: func() error { return errors.New("permission denied") },
			acquireKprobe: func(context.Context) (fakeTCPKprobeBackendAcquisition, error) {
				kprobeCalls++
				return fakeTCPKprobeBackendAcquisition{}, nil
			},
		},
	)
	if selection != nil || err == nil || !strings.Contains(err.Error(), "refuses fallback") {
		t.Fatalf("selection=%#v error=%v", selection, err)
	}
	if kprobeCalls != 0 {
		t.Fatalf("operational kfunc failure opened kprobe lease %d times", kprobeCalls)
	}
}

func TestFakeTCPChecksumSelectionCloseFailureRetainsRetryCapability(t *testing.T) {
	lease := &fakeTCPChecksumTestLease{err: errors.New("injected close failure")}
	selection := newFakeTCPChecksumSelection(
		config.FakeTCPChecksumBackendKprobe,
		config.FakeTCPChecksumBackendKprobe,
		FakeTCPObjectVariantLegacy515,
		DefaultFakeTCPKprobeModule,
		lease,
	)
	selection.cookie = 1
	selection.health = func(context.Context, uint64) error { return nil }
	if err := selection.Close(); err == nil {
		t.Fatal("expected first close failure")
	}
	if !selection.RuntimeStatus().LeaseHeld {
		t.Fatal("failed close hid retained lease")
	}
	lease.err = nil
	if err := selection.Close(); err != nil {
		t.Fatalf("retry close: %v", err)
	}
	if lease.closes != 2 || selection.RuntimeStatus().LeaseHeld {
		t.Fatalf("retry state: closes=%d status=%#v", lease.closes, selection.RuntimeStatus())
	}
}

func TestResolveFakeTCPChecksumBackendRejectsReducedKprobeCapabilityAndClosesLease(t *testing.T) {
	lease := &fakeTCPChecksumTestLease{}
	selection, err := resolveFakeTCPChecksumBackendWith(
		t.Context(),
		config.FakeTCPChecksumBackendKprobe,
		fakeTCPChecksumBackendDependencies{
			probeKfunc: func() error { return nil },
			acquireKprobe: func(context.Context) (fakeTCPKprobeBackendAcquisition, error) {
				return fakeTCPKprobeBackendAcquisition{
					module:       DefaultFakeTCPKprobeModule,
					capabilities: []string{"checksum-state", "partial-reset", "pmtu"},
					cookie:       1,
					lease:        lease,
					health:       func(context.Context, uint64) error { return nil },
				}, nil
			},
		},
	)
	if selection != nil || err == nil || !strings.Contains(err.Error(), "udp-gso-to-tcp") {
		t.Fatalf("selection=%#v error=%v", selection, err)
	}
	if lease.closes != 1 {
		t.Fatalf("rejected lease closes = %d", lease.closes)
	}
}

func TestResolveFakeTCPChecksumBackendNeverFallsBackFromExplicitSelection(t *testing.T) {
	kprobeCalls := 0
	selection, err := resolveFakeTCPChecksumBackendWith(
		t.Context(),
		config.FakeTCPChecksumBackendKfunc,
		fakeTCPChecksumBackendDependencies{
			probeKfunc: func() error { return errors.New("kfunc unavailable") },
			acquireKprobe: func(context.Context) (fakeTCPKprobeBackendAcquisition, error) {
				kprobeCalls++
				return fakeTCPKprobeBackendAcquisition{
					cookie: 1,
					lease:  io.NopCloser(strings.NewReader("")),
					health: func(context.Context, uint64) error { return nil },
				}, nil
			},
		},
	)
	if selection != nil || err == nil || !strings.Contains(err.Error(), "kfunc unavailable") {
		t.Fatalf("selection=%#v error=%v", selection, err)
	}
	if kprobeCalls != 0 {
		t.Fatalf("explicit kfunc silently fell back; kprobe calls=%d", kprobeCalls)
	}
}
