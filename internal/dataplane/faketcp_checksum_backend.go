package dataplane

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/syx0310/wg-mix-ebpf/internal/config"
)

const (
	FakeTCPChecksumCapabilityFullGSOV1 = "full-gso-v1"
	FakeTCPObjectVariantModernKfunc    = "modern-kfunc"
	FakeTCPObjectVariantLegacy515      = "legacy-515-kprobe"
	DefaultFakeTCPKfuncModule          = "wg_mix_faketcp_checksum"
	DefaultFakeTCPKprobeModule         = "wg_mix_faketcp_checksum_kprobe"
	DefaultFakeTCPKprobeLeaseDevice    = "/dev/wg_mix_faketcp_checksum_kprobe"
)

var fullFakeTCPChecksumCapabilities = []string{
	"checksum-state",
	"partial-reset",
	"pmtu",
	"udp-gso-to-tcp",
}

// ErrFakeTCPChecksumBackendUnsupported marks a read-only capability result
// which permits auto to try the next backend. Permission, malformed-response,
// health and other operational failures must not carry this marker.
var ErrFakeTCPChecksumBackendUnsupported = errors.New("FakeTCP checksum backend is unsupported")

// FakeTCPChecksumSelection is a pre-mutation decision binding a checksum
// backend, its exact BPF object family and (for kprobe) the open kernel-module
// lease that keeps the bridge registered. The selection is immutable. A
// caller must retain it for the complete resident FakeTCP runtime and Close it
// only after all programs using the bridge have been detached.
type FakeTCPChecksumSelection struct {
	Requested     string   `json:"requested"`
	Backend       string   `json:"backend"`
	Capability    string   `json:"capability"`
	Capabilities  []string `json:"capabilities"`
	ObjectVariant string   `json:"object_variant"`
	Module        string   `json:"module,omitempty"`
	LeaseHeld     bool     `json:"lease_held"`

	mu       sync.Mutex
	lease    io.Closer
	cookie   uint64
	health   func(context.Context, uint64) error
	closeErr error
	closed   bool
}

// KprobeCookie returns the per-lease cookie needed to populate the legacy BPF
// runtime map. It is never serialized. The value becomes invalid immediately
// after Close and callers must not log it.
func (selection *FakeTCPChecksumSelection) KprobeCookie() (uint64, bool) {
	if selection == nil {
		return 0, false
	}
	selection.mu.Lock()
	defer selection.mu.Unlock()
	if selection.closed || selection.Backend != config.FakeTCPChecksumBackendKprobe || selection.cookie == 0 {
		return 0, false
	}
	return selection.cookie, true
}

type FakeTCPChecksumRequirement struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Detail  string `json:"detail,omitempty"`
	Message string `json:"message,omitempty"`
}

type FakeTCPChecksumBackendProbe struct {
	Backend      string                       `json:"backend"`
	Available    bool                         `json:"available"`
	Unsupported  bool                         `json:"unsupported,omitempty"`
	Equivalent   bool                         `json:"equivalent"`
	Capability   string                       `json:"capability,omitempty"`
	Capabilities []string                     `json:"capabilities,omitempty"`
	Module       string                       `json:"module,omitempty"`
	LeasePath    string                       `json:"lease_path,omitempty"`
	Requirements []FakeTCPChecksumRequirement `json:"requirements"`
	Error        string                       `json:"error,omitempty"`
}

type fakeTCPKprobeBackendAcquisition struct {
	module       string
	capabilities []string
	cookie       uint64
	lease        io.Closer
	health       func(context.Context, uint64) error
}

type fakeTCPChecksumBackendDependencies struct {
	probeKfunc    func() error
	acquireKprobe func(context.Context) (fakeTCPKprobeBackendAcquisition, error)
}

// ResolveFakeTCPChecksumBackend performs all backend and module checks before
// a caller starts a dataplane transaction. auto always prefers the typed kfunc
// contract and accepts kprobe only when the bridge advertises the same full
// checksum, PMTU and GSO capability. It never changes backend after returning.
func ResolveFakeTCPChecksumBackend(
	ctx context.Context,
	requested string,
) (*FakeTCPChecksumSelection, error) {
	return resolveFakeTCPChecksumBackend(ctx, requested)
}

// ProbeFakeTCPChecksumBackends returns read-only diagnostics for doctor. A
// temporary kprobe module lease may be opened and immediately closed; no BPF
// object is loaded and no TC/XDP state is changed.
func ProbeFakeTCPChecksumBackends(ctx context.Context) []FakeTCPChecksumBackendProbe {
	return probeFakeTCPChecksumBackends(ctx)
}

func (selection *FakeTCPChecksumSelection) Close() error {
	if selection == nil {
		return nil
	}
	selection.mu.Lock()
	defer selection.mu.Unlock()
	if selection.closed {
		return nil
	}
	if selection.lease != nil {
		if err := selection.lease.Close(); err != nil {
			selection.closeErr = err
			return err
		}
	}
	selection.closed = true
	selection.LeaseHeld = false
	selection.lease = nil
	selection.cookie = 0
	selection.health = nil
	selection.closeErr = nil
	return nil
}

// Healthy revalidates the selected backend without changing it. A runtime
// must treat any error as fail-closed; this method never attempts another
// backend and never reacquires a different module lease.
func (selection *FakeTCPChecksumSelection) Healthy(ctx context.Context) error {
	if selection == nil {
		return errors.New("FakeTCP checksum selection is nil")
	}
	if ctx == nil {
		return errors.New("FakeTCP checksum health context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	selection.mu.Lock()
	defer selection.mu.Unlock()
	if selection.closed {
		return errors.New("FakeTCP checksum selection is closed")
	}
	if selection.health == nil {
		return errors.New("FakeTCP checksum selection has no health probe")
	}
	if selection.Backend == config.FakeTCPChecksumBackendKprobe &&
		(selection.lease == nil || !selection.LeaseHeld || selection.cookie == 0) {
		return errors.New("FakeTCP kprobe checksum module lease is not held")
	}
	return selection.health(ctx, selection.cookie)
}

// RuntimeStatus returns a redacted status projection. Module cookies, trigger
// nonces and cipher keys are intentionally absent from both the selection and
// this value.
func (selection *FakeTCPChecksumSelection) RuntimeStatus() FakeTCPChecksumRuntimeStatus {
	if selection == nil {
		return FakeTCPChecksumRuntimeStatus{}
	}
	selection.mu.Lock()
	defer selection.mu.Unlock()
	return FakeTCPChecksumRuntimeStatus{
		Backend:       selection.Backend,
		Capability:    selection.Capability,
		Capabilities:  append([]string(nil), selection.Capabilities...),
		ObjectVariant: selection.ObjectVariant,
		Module:        selection.Module,
		LeaseHeld:     selection.LeaseHeld && !selection.closed,
	}
}

func newFakeTCPChecksumSelection(
	requested string,
	backend string,
	objectVariant string,
	module string,
	lease io.Closer,
) *FakeTCPChecksumSelection {
	return &FakeTCPChecksumSelection{
		Requested:     requested,
		Backend:       backend,
		Capability:    FakeTCPChecksumCapabilityFullGSOV1,
		Capabilities:  append([]string(nil), fullFakeTCPChecksumCapabilities...),
		ObjectVariant: objectVariant,
		Module:        module,
		LeaseHeld:     lease != nil,
		lease:         lease,
	}
}

func resolveFakeTCPChecksumBackendWith(
	ctx context.Context,
	requested string,
	dependencies fakeTCPChecksumBackendDependencies,
) (*FakeTCPChecksumSelection, error) {
	if ctx == nil {
		return nil, errors.New("resolve FakeTCP checksum backend: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	normalized, err := normalizeFakeTCPChecksumBackend(requested)
	if err != nil {
		return nil, err
	}
	if dependencies.probeKfunc == nil || dependencies.acquireKprobe == nil {
		return nil, errors.New("resolve FakeTCP checksum backend: probe dependencies are incomplete")
	}

	selectKfunc := func() (*FakeTCPChecksumSelection, error) {
		if err := dependencies.probeKfunc(); err != nil {
			return nil, fmt.Errorf("kfunc checksum backend unavailable: %w", err)
		}
		selection := newFakeTCPChecksumSelection(
			normalized,
			config.FakeTCPChecksumBackendKfunc,
			FakeTCPObjectVariantModernKfunc,
			DefaultFakeTCPKfuncModule,
			nil,
		)
		selection.health = func(ctx context.Context, _ uint64) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			return dependencies.probeKfunc()
		}
		return selection, nil
	}
	selectKprobe := func() (*FakeTCPChecksumSelection, error) {
		acquisition, err := dependencies.acquireKprobe(ctx)
		if err != nil {
			return nil, fmt.Errorf("kprobe checksum backend unavailable: %w", err)
		}
		if acquisition.lease == nil {
			return nil, errors.New("kprobe checksum backend returned no module lease")
		}
		if acquisition.cookie == 0 || acquisition.health == nil {
			closeErr := acquisition.lease.Close()
			return nil, errors.Join(
				errors.New("kprobe checksum backend returned an incomplete cookie/health lease"),
				closeErr,
			)
		}
		if err := validateEquivalentFakeTCPChecksumCapabilities(acquisition.capabilities); err != nil {
			closeErr := acquisition.lease.Close()
			return nil, errors.Join(
				fmt.Errorf("kprobe checksum backend is not full-GSO equivalent: %w", err),
				closeErr,
			)
		}
		selection := newFakeTCPChecksumSelection(
			normalized,
			config.FakeTCPChecksumBackendKprobe,
			FakeTCPObjectVariantLegacy515,
			acquisition.module,
			acquisition.lease,
		)
		selection.Capabilities = append([]string(nil), acquisition.capabilities...)
		selection.cookie = acquisition.cookie
		selection.health = acquisition.health
		return selection, nil
	}

	switch normalized {
	case config.FakeTCPChecksumBackendKfunc:
		return selectKfunc()
	case config.FakeTCPChecksumBackendKprobe:
		return selectKprobe()
	case config.FakeTCPChecksumBackendAuto:
		selection, kfuncErr := selectKfunc()
		if kfuncErr == nil {
			return selection, nil
		}
		if !errors.Is(kfuncErr, ErrFakeTCPChecksumBackendUnsupported) {
			return nil, fmt.Errorf(
				"auto checksum backend refuses fallback after a non-unsupported kfunc probe failure: %w",
				kfuncErr,
			)
		}
		selection, kprobeErr := selectKprobe()
		if kprobeErr == nil {
			return selection, nil
		}
		return nil, errors.Join(
			fmt.Errorf("auto checksum backend: %w", kfuncErr),
			fmt.Errorf("auto checksum backend: %w", kprobeErr),
		)
	default:
		return nil, fmt.Errorf("unhandled FakeTCP checksum backend %q", normalized)
	}
}

func normalizeFakeTCPChecksumBackend(requested string) (string, error) {
	if requested == "" {
		return config.FakeTCPChecksumBackendAuto, nil
	}
	switch requested {
	case config.FakeTCPChecksumBackendAuto,
		config.FakeTCPChecksumBackendKfunc,
		config.FakeTCPChecksumBackendKprobe:
		return requested, nil
	default:
		return "", fmt.Errorf("unsupported FakeTCP checksum backend %q", requested)
	}
}

func validateEquivalentFakeTCPChecksumCapabilities(capabilities []string) error {
	present := make(map[string]struct{}, len(capabilities))
	for _, capability := range capabilities {
		present[capability] = struct{}{}
	}
	var missing []error
	for _, capability := range fullFakeTCPChecksumCapabilities {
		if _, ok := present[capability]; !ok {
			missing = append(missing, fmt.Errorf("missing capability %s", capability))
		}
	}
	return errors.Join(missing...)
}
