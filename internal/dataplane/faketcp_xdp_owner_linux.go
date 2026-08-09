//go:build linux

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"sync"

	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

type fakeTCPXDPAttachMode uint8

const (
	fakeTCPXDPAttachNative fakeTCPXDPAttachMode = iota + 1
	fakeTCPXDPAttachGeneric
	fakeTCPXDPAttachLibXDP
)

func (mode fakeTCPXDPAttachMode) String() string {
	switch mode {
	case fakeTCPXDPAttachNative:
		return "native"
	case fakeTCPXDPAttachGeneric:
		return "generic"
	case fakeTCPXDPAttachLibXDP:
		return "libxdp-chain"
	default:
		return fmt.Sprintf("unknown(%d)", mode)
	}
}

type fakeTCPXDPBackendFamily uint8

const (
	fakeTCPXDPBackendDirect fakeTCPXDPBackendFamily = iota + 1
	fakeTCPXDPBackendLibXDP
)

func (family fakeTCPXDPBackendFamily) String() string {
	switch family {
	case fakeTCPXDPBackendDirect:
		return "bpf-link"
	case fakeTCPXDPBackendLibXDP:
		return "libxdp"
	default:
		return fmt.Sprintf("unknown(%d)", family)
	}
}

type fakeTCPXDPAttachRequest struct {
	IfIndex int
	Mode    fakeTCPXDPAttachMode
}

// fakeTCPXDPBackendCapabilities is detected once when a backend is built.
// Runtime attachment never changes backend or retries through another mode.
// A libxdp adapter must prove all three ownership properties before it may be
// used: an atomic expected-dispatcher attach, an exact component owner, and a
// stable dispatcher identity.
type fakeTCPXDPBackendCapabilities struct {
	Family                  fakeTCPXDPBackendFamily
	APIVersion              uint32
	AtomicExpectedAttach    bool
	ExactOwner              bool
	ExactDispatcherIdentity bool
}

type fakeTCPXDPProbe struct {
	IfIndex    int
	Attached   bool
	ProgramID  uint32
	AttachMode uint32
	Dispatcher bool
	// DispatcherID is an adapter-defined, stable identity for one exact
	// libxdp dispatcher configuration. A program ID alone is recyclable and
	// therefore cannot authorize component attachment or retirement.
	DispatcherID uint64
}

type fakeTCPXDPLinkIdentity struct {
	Family              fakeTCPXDPBackendFamily
	Mode                fakeTCPXDPAttachMode
	IfIndex             int
	ProgramID           uint32
	OwnerID             uint64
	DispatcherProgramID uint32
	DispatcherID        uint64
}

type fakeTCPXDPReleaseResult struct {
	Observed fakeTCPXDPLinkIdentity
	Released bool
}

// fakeTCPXDPLink is the exact capability returned by one successful backend
// mutation. Release must compare expected identity inside the same backend
// operation that retires the link/component. Returning Released=false means
// the capability remains valid for a later retry.
type fakeTCPXDPLink interface {
	Identity() (fakeTCPXDPLinkIdentity, error)
	Release(fakeTCPXDPLinkIdentity) (fakeTCPXDPReleaseResult, error)
}

type fakeTCPXDPRuntime struct {
	capabilities fakeTCPXDPBackendCapabilities
	probe        func(int) (fakeTCPXDPProbe, error)
	attach       func(
		fakeTCPXDPAttachRequest,
		fakeTCPXDPProbe,
		experimentalProgramResource,
	) (fakeTCPXDPLink, error)
}

func newFakeTCPXDPRuntime(
	detect func() (fakeTCPXDPBackendCapabilities, error),
	probe func(int) (fakeTCPXDPProbe, error),
	attach func(
		fakeTCPXDPAttachRequest,
		fakeTCPXDPProbe,
		experimentalProgramResource,
	) (fakeTCPXDPLink, error),
) (fakeTCPXDPRuntime, error) {
	if detect == nil || probe == nil || attach == nil {
		return fakeTCPXDPRuntime{}, errors.New(
			"construct FakeTCP XDP backend: detect, probe, and attach are required",
		)
	}
	capabilities, err := detect()
	if err != nil {
		return fakeTCPXDPRuntime{}, fmt.Errorf(
			"detect FakeTCP XDP backend capability: %w", err,
		)
	}
	if err := validateFakeTCPXDPBackendCapabilities(capabilities); err != nil {
		return fakeTCPXDPRuntime{}, err
	}
	return fakeTCPXDPRuntime{
		capabilities: capabilities,
		probe:        probe,
		attach:       attach,
	}, nil
}

func validateFakeTCPXDPBackendCapabilities(
	capabilities fakeTCPXDPBackendCapabilities,
) error {
	if capabilities.APIVersion == 0 || !capabilities.AtomicExpectedAttach ||
		!capabilities.ExactOwner {
		return fmt.Errorf(
			"construct FakeTCP XDP backend %s: exact expected-attach and owner capability is not proven",
			capabilities.Family,
		)
	}
	if capabilities.Family == fakeTCPXDPBackendLibXDP {
		if !capabilities.ExactDispatcherIdentity {
			return errors.New(
				"construct FakeTCP XDP libxdp backend: exact dispatcher identity is not proven",
			)
		}
	} else if capabilities.Family != fakeTCPXDPBackendDirect {
		return fmt.Errorf(
			"construct FakeTCP XDP backend: unsupported family %s",
			capabilities.Family,
		)
	}
	return nil
}

type liveFakeTCPXDPLink struct {
	mu   sync.Mutex
	mode fakeTCPXDPAttachMode
	link link.Link
}

func (owned *liveFakeTCPXDPLink) Identity() (fakeTCPXDPLinkIdentity, error) {
	if owned == nil {
		return fakeTCPXDPLinkIdentity{}, errors.New("owned XDP link is nil")
	}
	owned.mu.Lock()
	defer owned.mu.Unlock()
	return owned.identityLocked()
}

func (owned *liveFakeTCPXDPLink) identityLocked() (fakeTCPXDPLinkIdentity, error) {
	if owned.link == nil {
		return fakeTCPXDPLinkIdentity{}, errors.New("owned XDP link is released")
	}
	info, err := owned.link.Info()
	if err != nil {
		return fakeTCPXDPLinkIdentity{}, fmt.Errorf("inspect owned XDP link: %w", err)
	}
	xdp := info.XDP()
	if xdp == nil || xdp.Ifindex == 0 || info.Program == 0 || info.ID == 0 {
		return fakeTCPXDPLinkIdentity{}, errors.New(
			"owned XDP link has incomplete interface/program/link identity",
		)
	}
	return fakeTCPXDPLinkIdentity{
		Family:    fakeTCPXDPBackendDirect,
		Mode:      owned.mode,
		IfIndex:   int(xdp.Ifindex),
		ProgramID: uint32(info.Program),
		OwnerID:   uint64(info.ID),
	}, nil
}

func (owned *liveFakeTCPXDPLink) Release(
	expected fakeTCPXDPLinkIdentity,
) (fakeTCPXDPReleaseResult, error) {
	if owned == nil {
		return fakeTCPXDPReleaseResult{}, errors.New("release owned XDP link: owner is nil")
	}
	owned.mu.Lock()
	defer owned.mu.Unlock()
	observed, err := owned.identityLocked()
	result := fakeTCPXDPReleaseResult{Observed: observed}
	if err != nil {
		return result, err
	}
	if observed != expected {
		return result, fmt.Errorf(
			"release owned XDP link: stale identity: observed %+v, expected %+v",
			observed, expected,
		)
	}
	// cilium/ebpf consumes its FD even when close(2) reports an error. Record
	// Released=true and clear the handle in both cases; retrying a recycled FD
	// would be unsafe.
	err = owned.link.Close()
	owned.link = nil
	result.Released = true
	return result, err
}

func mustLiveFakeTCPXDPRuntime() fakeTCPXDPRuntime {
	runtime, err := newFakeTCPXDPRuntime(
		func() (fakeTCPXDPBackendCapabilities, error) {
			return fakeTCPXDPBackendCapabilities{
				Family: fakeTCPXDPBackendDirect, APIVersion: 1,
				AtomicExpectedAttach: true, ExactOwner: true,
			}, nil
		},
		probeLiveFakeTCPXDP,
		func(
			request fakeTCPXDPAttachRequest,
			expected fakeTCPXDPProbe,
			program experimentalProgramResource,
		) (fakeTCPXDPLink, error) {
			if expected.Attached || expected.ProgramID != 0 {
				return nil, errors.New("live XDP attach received an occupied expected hook")
			}
			if program == nil || program.kernelProgram() == nil {
				return nil, errors.New("live XDP attach requires a kernel program")
			}
			var flags link.XDPAttachFlags
			switch request.Mode {
			case fakeTCPXDPAttachNative:
				flags = link.XDPDriverMode
			case fakeTCPXDPAttachGeneric:
				flags = link.XDPGenericMode
			default:
				return nil, fmt.Errorf("unsupported direct XDP attach mode %s", request.Mode)
			}
			attached, err := link.AttachXDP(link.XDPOptions{
				Program: program.kernelProgram(), Interface: request.IfIndex, Flags: flags,
			})
			if err != nil {
				return nil, err
			}
			return &liveFakeTCPXDPLink{mode: request.Mode, link: attached}, nil
		},
	)
	if err != nil {
		panic(err)
	}
	return runtime
}

var liveFakeTCPXDPRuntime = mustLiveFakeTCPXDPRuntime()

func probeLiveFakeTCPXDP(ifindex int) (fakeTCPXDPProbe, error) {
	if ifindex <= 0 {
		return fakeTCPXDPProbe{}, fmt.Errorf("probe XDP: invalid ifindex %d", ifindex)
	}
	networkLink, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		return fakeTCPXDPProbe{}, err
	}
	if networkLink == nil || networkLink.Attrs() == nil ||
		networkLink.Attrs().Index != ifindex {
		return fakeTCPXDPProbe{}, errors.New("XDP probe returned mismatched network link")
	}
	probe := fakeTCPXDPProbe{IfIndex: ifindex}
	xdp := networkLink.Attrs().Xdp
	if xdp == nil || !xdp.Attached {
		return probe, nil
	}
	if xdp.ProgId == 0 {
		return fakeTCPXDPProbe{}, errors.New(
			"XDP probe found an attachment without a program ID",
		)
	}
	probe.Attached = true
	probe.ProgramID = xdp.ProgId
	probe.AttachMode = xdp.AttachMode
	return probe, nil
}

type fakeTCPXDPOwnershipState uint8

const (
	fakeTCPXDPOwnershipUnverified fakeTCPXDPOwnershipState = iota + 1
	fakeTCPXDPOwnershipAdopted
	fakeTCPXDPOwnershipStale
)

type fakeTCPXDPAttachment struct {
	request  fakeTCPXDPAttachRequest
	probe    fakeTCPXDPProbe
	identity fakeTCPXDPLinkIdentity
	link     fakeTCPXDPLink
	state    fakeTCPXDPOwnershipState
}

func (attachment *fakeTCPXDPAttachment) adopt(
	family fakeTCPXDPBackendFamily,
	programID uint32,
) error {
	identity, err := attachment.link.Identity()
	if err != nil {
		return fmt.Errorf("inspect new owner identity: %w", err)
	}
	if err := validateFakeTCPXDPLinkIdentity(
		family, attachment.request, attachment.probe, programID, identity,
	); err != nil {
		return err
	}
	attachment.identity = identity
	attachment.state = fakeTCPXDPOwnershipAdopted
	return nil
}

func (attachment *fakeTCPXDPAttachment) release() (bool, error) {
	switch attachment.state {
	case fakeTCPXDPOwnershipUnverified:
		return false, errors.New("release refused: XDP owner identity was never verified")
	case fakeTCPXDPOwnershipStale:
		return false, errors.New("release refused: XDP owner identity is stale")
	case fakeTCPXDPOwnershipAdopted:
	default:
		return false, fmt.Errorf("release refused: invalid XDP ownership state %d", attachment.state)
	}
	result, err := attachment.link.Release(attachment.identity)
	if result.Observed != attachment.identity {
		if result.Released {
			return true, errors.Join(err, errors.New(
				"XDP backend released an owner after observing stale identity",
			))
		}
		attachment.state = fakeTCPXDPOwnershipStale
		return false, errors.Join(err, fmt.Errorf(
			"XDP owner identity changed: observed %+v, expected %+v",
			result.Observed, attachment.identity,
		))
	}
	if result.Released {
		return true, err
	}
	if err == nil {
		err = errors.New("XDP backend retained an owner without an error")
	}
	return false, err
}

type fakeTCPXDPStage struct {
	mu          sync.Mutex
	attachments []fakeTCPXDPAttachment
}

type fakeTCPXDPPlannedAttachment struct {
	request fakeTCPXDPAttachRequest
	probe   fakeTCPXDPProbe
}

func stageFakeTCPXDPAttachments(
	ctx context.Context,
	requests []fakeTCPXDPAttachRequest,
	program experimentalProgramResource,
	runtime fakeTCPXDPRuntime,
) (*fakeTCPXDPStage, error) {
	if ctx == nil {
		return nil, errors.New("stage FakeTCP XDP: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(requests) == 0 {
		return nil, errors.New("stage FakeTCP XDP: at least one attachment is required")
	}
	if program == nil {
		return nil, errors.New("stage FakeTCP XDP: program is nil")
	}
	if runtime.probe == nil || runtime.attach == nil {
		return nil, errors.New("stage FakeTCP XDP: backend is incomplete")
	}
	programID, err := program.ID()
	if err != nil {
		return nil, fmt.Errorf("stage FakeTCP XDP: inspect program identity: %w", err)
	}
	if programID == 0 {
		return nil, errors.New("stage FakeTCP XDP: program ID is zero")
	}

	ordered, err := canonicalFakeTCPXDPRequests(requests, runtime.capabilities.Family)
	if err != nil {
		return nil, err
	}
	planned := make([]fakeTCPXDPPlannedAttachment, 0, len(ordered))
	// Probe every hook exactly once before the first mutation. The exact probe
	// is passed into Attach so an adapter can reject a changed dispatcher in
	// the same operation that registers the component.
	for _, request := range ordered {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		probe, err := runtime.probe(request.IfIndex)
		if err != nil {
			return nil, fmt.Errorf(
				"stage FakeTCP XDP probe ifindex %d: %w", request.IfIndex, err,
			)
		}
		if err := validateFakeTCPXDPProbe(runtime.capabilities.Family, request, probe); err != nil {
			return nil, err
		}
		planned = append(planned, fakeTCPXDPPlannedAttachment{request: request, probe: probe})
	}

	stage := &fakeTCPXDPStage{}
	for _, plan := range planned {
		if err := ctx.Err(); err != nil {
			return stageOrNil(stage), err
		}
		ownedLink, attachErr := runtime.attach(plan.request, plan.probe, program)
		if ownedLink == nil {
			if attachErr == nil {
				attachErr = errors.New("backend returned a nil owner")
			}
			return stageOrNil(stage), fmt.Errorf(
				"stage FakeTCP XDP attach ifindex %d mode %s: %w",
				plan.request.IfIndex, plan.request.Mode, attachErr,
			)
		}
		attachment := fakeTCPXDPAttachment{
			request: plan.request,
			probe:   plan.probe,
			link:    ownedLink,
			state:   fakeTCPXDPOwnershipUnverified,
		}
		stage.attachments = append(stage.attachments, attachment)
		current := &stage.attachments[len(stage.attachments)-1]
		adoptErr := current.adopt(runtime.capabilities.Family, programID)
		if attachErr != nil || adoptErr != nil {
			return stage, errors.Join(
				wrapNonNilError(fmt.Sprintf(
					"stage FakeTCP XDP attach ifindex %d mode %s",
					plan.request.IfIndex, plan.request.Mode,
				), attachErr),
				wrapNonNilError(fmt.Sprintf(
					"stage FakeTCP XDP adopt ifindex %d mode %s",
					plan.request.IfIndex, plan.request.Mode,
				), adoptErr),
			)
		}
	}
	return stage, nil
}

func canonicalFakeTCPXDPRequests(
	requests []fakeTCPXDPAttachRequest,
	family fakeTCPXDPBackendFamily,
) ([]fakeTCPXDPAttachRequest, error) {
	ordered := append([]fakeTCPXDPAttachRequest(nil), requests...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].IfIndex < ordered[j].IfIndex })
	for index, request := range ordered {
		if request.IfIndex <= 0 || uint64(request.IfIndex) > math.MaxUint32 {
			return nil, fmt.Errorf("stage FakeTCP XDP: invalid ifindex %d", request.IfIndex)
		}
		if index > 0 && ordered[index-1].IfIndex == request.IfIndex {
			return nil, fmt.Errorf("stage FakeTCP XDP: duplicate ifindex %d", request.IfIndex)
		}
		switch family {
		case fakeTCPXDPBackendDirect:
			if request.Mode != fakeTCPXDPAttachNative && request.Mode != fakeTCPXDPAttachGeneric {
				return nil, fmt.Errorf(
					"stage FakeTCP XDP: mode %s does not match constructed %s backend",
					request.Mode, family,
				)
			}
		case fakeTCPXDPBackendLibXDP:
			if request.Mode != fakeTCPXDPAttachLibXDP {
				return nil, fmt.Errorf(
					"stage FakeTCP XDP: mode %s does not match constructed %s backend",
					request.Mode, family,
				)
			}
		default:
			return nil, fmt.Errorf("stage FakeTCP XDP: unsupported backend %s", family)
		}
	}
	return ordered, nil
}

func validateFakeTCPXDPProbe(
	family fakeTCPXDPBackendFamily,
	request fakeTCPXDPAttachRequest,
	probe fakeTCPXDPProbe,
) error {
	if probe.IfIndex != request.IfIndex {
		return fmt.Errorf(
			"stage FakeTCP XDP probe ifindex %d returned identity %d",
			request.IfIndex, probe.IfIndex,
		)
	}
	if family == fakeTCPXDPBackendLibXDP {
		if !probe.Attached || probe.ProgramID == 0 || !probe.Dispatcher ||
			probe.DispatcherID == 0 {
			return fmt.Errorf(
				"stage FakeTCP XDP ifindex %d: exact libxdp dispatcher identity is not proven",
				request.IfIndex,
			)
		}
		return nil
	}
	if probe.Attached || probe.ProgramID != 0 || probe.Dispatcher || probe.DispatcherID != 0 {
		return fmt.Errorf(
			"stage FakeTCP XDP ifindex %d mode %s: existing program ID %d is not owned; replacement is refused",
			request.IfIndex, request.Mode, probe.ProgramID,
		)
	}
	return nil
}

func validateFakeTCPXDPLinkIdentity(
	family fakeTCPXDPBackendFamily,
	request fakeTCPXDPAttachRequest,
	probe fakeTCPXDPProbe,
	programID uint32,
	identity fakeTCPXDPLinkIdentity,
) error {
	if identity.Family != family || identity.Mode != request.Mode ||
		identity.IfIndex != request.IfIndex || identity.ProgramID != programID ||
		identity.OwnerID == 0 {
		return fmt.Errorf(
			"new XDP owner identity %+v does not match backend=%s mode=%s ifindex=%d program=%d",
			identity, family, request.Mode, request.IfIndex, programID,
		)
	}
	if family == fakeTCPXDPBackendLibXDP {
		if identity.DispatcherProgramID != probe.ProgramID ||
			identity.DispatcherID != probe.DispatcherID {
			return fmt.Errorf(
				"new libxdp owner identity %+v does not match dispatcher program=%d identity=%d",
				identity, probe.ProgramID, probe.DispatcherID,
			)
		}
	} else if identity.DispatcherProgramID != 0 || identity.DispatcherID != 0 {
		return fmt.Errorf("new direct XDP owner has dispatcher identity: %+v", identity)
	}
	return nil
}

func stageOrNil(stage *fakeTCPXDPStage) *fakeTCPXDPStage {
	if stage == nil || len(stage.attachments) == 0 {
		return nil
	}
	return stage
}

// Close rolls back or retires only exact adopted owners. Unverified or stale
// identities are quarantined and never passed to a destructive backend call.
// Successfully released entries are forgotten immediately; retained entries
// remain available for one later retry.
func (stage *fakeTCPXDPStage) Close() error {
	if stage == nil {
		return nil
	}
	stage.mu.Lock()
	defer stage.mu.Unlock()
	if len(stage.attachments) == 0 {
		return nil
	}
	var errs []error
	remaining := make([]fakeTCPXDPAttachment, 0, len(stage.attachments))
	for index := len(stage.attachments) - 1; index >= 0; index-- {
		attachment := stage.attachments[index]
		released, err := attachment.release()
		if err != nil {
			errs = append(errs, fmt.Errorf(
				"release owned FakeTCP XDP ifindex %d mode %s program %d: %w",
				attachment.request.IfIndex, attachment.request.Mode,
				attachment.identity.ProgramID, err,
			))
		}
		if !released {
			remaining = append(remaining, attachment)
		}
	}
	// The loop is reverse-order; restore canonical order for deterministic
	// retries and model inspection.
	for left, right := 0, len(remaining)-1; left < right; left, right = left+1, right-1 {
		remaining[left], remaining[right] = remaining[right], remaining[left]
	}
	stage.attachments = remaining
	return errors.Join(errs...)
}
