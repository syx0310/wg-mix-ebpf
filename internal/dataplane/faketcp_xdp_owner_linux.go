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

type fakeTCPXDPAttachGuarantee uint8

const (
	fakeTCPXDPExactSelectedModeLink fakeTCPXDPAttachGuarantee = iota + 1
	fakeTCPXDPExactDispatcherComponent
)

type fakeTCPXDPOwnershipScope uint8

const (
	fakeTCPXDPOwnershipSelectedMode fakeTCPXDPOwnershipScope = iota + 1
	fakeTCPXDPOwnershipAllHooks
)

type fakeTCPXDPActivationRequirement uint8

const (
	// Zero remains the strongest contract so an omitted option fails closed.
	fakeTCPXDPRequireAllHooksExclusive fakeTCPXDPActivationRequirement = iota
	// Production may explicitly select the direct bpf_link backend. The
	// planner must first prove that the interface has no aggregate XDP owner,
	// must choose one fixed mode without fallback, and retains the exact link
	// identity for rollback. This contract deliberately does not claim libxdp
	// dispatcher chaining or coexistence with another XDP mode.
	fakeTCPXDPRequireExactSelectedMode
	// Tests which exercise lifecycle mechanics with an injected selected-mode
	// backend use a separate value so production cannot opt in accidentally.
	fakeTCPXDPAllowSelectedModeTestOnly
)

// fakeTCPXDPBackendCapabilities is detected once when a backend is built.
// Guarantee describes the mutation primitive while Scope describes what that
// primitive excludes. In particular, a direct bpf_link owns exactly one
// selected XDP mode; observations of native, generic, or hardware modes are
// compatibility snapshots and are not atomic with that attach.
type fakeTCPXDPBackendCapabilities struct {
	Family                  fakeTCPXDPBackendFamily
	APIVersion              uint32
	Guarantee               fakeTCPXDPAttachGuarantee
	Scope                   fakeTCPXDPOwnershipScope
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
	Observed     fakeTCPXDPLinkIdentity
	AutoDetached bool
	Released     bool
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
	if capabilities.APIVersion == 0 {
		return fmt.Errorf("construct FakeTCP XDP backend %s: API version is not proven", capabilities.Family)
	}
	switch capabilities.Family {
	case fakeTCPXDPBackendDirect:
		if capabilities.Guarantee != fakeTCPXDPExactSelectedModeLink ||
			capabilities.Scope != fakeTCPXDPOwnershipSelectedMode {
			return errors.New(
				"construct FakeTCP XDP direct backend: exact selected-mode bpf_link ownership is not proven",
			)
		}
	case fakeTCPXDPBackendLibXDP:
		if capabilities.Guarantee != fakeTCPXDPExactDispatcherComponent ||
			capabilities.Scope != fakeTCPXDPOwnershipAllHooks {
			return errors.New(
				"construct FakeTCP XDP libxdp backend: exact all-hooks dispatcher-component ownership is not proven",
			)
		}
		if !capabilities.ExactDispatcherIdentity {
			return errors.New(
				"construct FakeTCP XDP libxdp backend: exact dispatcher identity is not proven",
			)
		}
	default:
		return fmt.Errorf(
			"construct FakeTCP XDP backend: unsupported family %s",
			capabilities.Family,
		)
	}
	return nil
}

func validateFakeTCPXDPActivationRequirement(
	capabilities fakeTCPXDPBackendCapabilities,
	requirement fakeTCPXDPActivationRequirement,
) error {
	switch requirement {
	case fakeTCPXDPRequireAllHooksExclusive:
		if capabilities.Scope != fakeTCPXDPOwnershipAllHooks {
			return fmt.Errorf(
				"FakeTCP XDP backend %s owns only the selected mode; all-hooks exclusive activation is unavailable",
				capabilities.Family,
			)
		}
	case fakeTCPXDPRequireExactSelectedMode:
		if capabilities.Family != fakeTCPXDPBackendDirect ||
			capabilities.Guarantee != fakeTCPXDPExactSelectedModeLink ||
			capabilities.Scope != fakeTCPXDPOwnershipSelectedMode {
			return fmt.Errorf(
				"FakeTCP XDP backend %s does not provide exact selected-mode bpf_link ownership",
				capabilities.Family,
			)
		}
	case fakeTCPXDPAllowSelectedModeTestOnly:
		return nil
	default:
		return fmt.Errorf("invalid FakeTCP XDP activation requirement %d", requirement)
	}
	return nil
}

type liveFakeTCPXDPLink struct {
	mu sync.Mutex

	inspect  func() (fakeTCPXDPLinkIdentity, error)
	close    func() error
	identity fakeTCPXDPLinkIdentity
	adopted  bool
}

func newLiveFakeTCPXDPLink(
	mode fakeTCPXDPAttachMode,
	attached link.Link,
) *liveFakeTCPXDPLink {
	return &liveFakeTCPXDPLink{
		inspect: func() (fakeTCPXDPLinkIdentity, error) {
			return inspectLiveFakeTCPXDPLink(mode, attached)
		},
		close: attached.Close,
	}
}

func (owned *liveFakeTCPXDPLink) Identity() (fakeTCPXDPLinkIdentity, error) {
	if owned == nil {
		return fakeTCPXDPLinkIdentity{}, errors.New("owned XDP link is nil")
	}
	owned.mu.Lock()
	defer owned.mu.Unlock()
	identity, err := owned.identityLocked()
	if err != nil {
		return fakeTCPXDPLinkIdentity{}, err
	}
	if identity.IfIndex == 0 {
		return fakeTCPXDPLinkIdentity{}, errors.New(
			"owned XDP link has no interface identity before adoption",
		)
	}
	if !owned.adopted {
		owned.identity = identity
		owned.adopted = true
	}
	return identity, nil
}

func (owned *liveFakeTCPXDPLink) identityLocked() (fakeTCPXDPLinkIdentity, error) {
	if owned.inspect == nil || owned.close == nil {
		return fakeTCPXDPLinkIdentity{}, errors.New("owned XDP link is released")
	}
	identity, err := owned.inspect()
	if err != nil {
		return fakeTCPXDPLinkIdentity{}, fmt.Errorf("inspect owned XDP link: %w", err)
	}
	return identity, nil
}

func inspectLiveFakeTCPXDPLink(
	mode fakeTCPXDPAttachMode,
	attached link.Link,
) (fakeTCPXDPLinkIdentity, error) {
	if attached == nil {
		return fakeTCPXDPLinkIdentity{}, errors.New("owned XDP link is nil")
	}
	info, err := attached.Info()
	if err != nil {
		return fakeTCPXDPLinkIdentity{}, err
	}
	xdp := info.XDP()
	if xdp == nil || info.Program == 0 || info.ID == 0 {
		return fakeTCPXDPLinkIdentity{}, errors.New(
			"owned XDP link has incomplete program/link identity",
		)
	}
	return fakeTCPXDPLinkIdentity{
		Family:    fakeTCPXDPBackendDirect,
		Mode:      mode,
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
	if !owned.adopted {
		return fakeTCPXDPReleaseResult{}, errors.New(
			"release owned XDP link: owner identity was not adopted",
		)
	}
	if expected != owned.identity {
		return fakeTCPXDPReleaseResult{Observed: owned.identity}, fmt.Errorf(
			"release owned XDP link: expected identity does not match adopted owner: got %+v, owner %+v",
			expected, owned.identity,
		)
	}
	observed, err := owned.identityLocked()
	result := fakeTCPXDPReleaseResult{Observed: observed}
	if err != nil {
		return result, err
	}
	result.AutoDetached = fakeTCPXDPAutoDetachedIdentity(expected, observed)
	if observed != expected && !result.AutoDetached {
		return result, fmt.Errorf(
			"release owned XDP link: stale identity: observed %+v, expected %+v",
			observed, expected,
		)
	}
	// cilium/ebpf consumes its FD even when close(2) reports an error. Record
	// Released=true and clear the handle in both cases; retrying a recycled FD
	// would be unsafe.
	err = owned.close()
	owned.inspect = nil
	owned.close = nil
	result.Released = true
	return result, err
}

func fakeTCPXDPAutoDetachedIdentity(
	expected fakeTCPXDPLinkIdentity,
	observed fakeTCPXDPLinkIdentity,
) bool {
	if expected.Family != fakeTCPXDPBackendDirect || expected.IfIndex == 0 ||
		observed.IfIndex != 0 {
		return false
	}
	observed.IfIndex = expected.IfIndex
	return observed == expected
}

func mustLiveFakeTCPXDPRuntime() fakeTCPXDPRuntime {
	runtime, err := newFakeTCPXDPRuntime(
		func() (fakeTCPXDPBackendCapabilities, error) {
			return fakeTCPXDPBackendCapabilities{
				Family: fakeTCPXDPBackendDirect, APIVersion: 1,
				Guarantee: fakeTCPXDPExactSelectedModeLink,
				Scope:     fakeTCPXDPOwnershipSelectedMode,
			}, nil
		},
		probeLiveFakeTCPXDP,
		func(
			request fakeTCPXDPAttachRequest,
			expected fakeTCPXDPProbe,
			program experimentalProgramResource,
		) (fakeTCPXDPLink, error) {
			if program == nil || program.kernelProgram() == nil {
				return nil, errors.New("live XDP attach requires a kernel program")
			}
			if expected.IfIndex != request.IfIndex || expected.Attached ||
				expected.ProgramID != 0 || expected.Dispatcher || expected.DispatcherID != 0 {
				return nil, errors.New("live XDP attach requires an exact absent preflight observation")
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
			owned := newLiveFakeTCPXDPLink(request.Mode, attached)
			identity, identityErr := owned.Identity()
			post, postErr := probeLiveFakeTCPXDP(request.IfIndex)
			return owned, errors.Join(
				identityErr,
				validateLiveFakeTCPXDPPostAttach(request, identity, post, postErr),
			)
		},
	)
	if err != nil {
		panic(err)
	}
	return runtime
}

var liveFakeTCPXDPRuntime = mustLiveFakeTCPXDPRuntime()

func validateLiveFakeTCPXDPPostAttach(
	request fakeTCPXDPAttachRequest,
	identity fakeTCPXDPLinkIdentity,
	probe fakeTCPXDPProbe,
	probeErr error,
) error {
	if probeErr != nil {
		return fmt.Errorf("post-attach aggregate XDP probe: %w", probeErr)
	}
	wantMode := uint32(0)
	switch request.Mode {
	case fakeTCPXDPAttachNative:
		wantMode = uint32(link.XDPDriverMode)
	case fakeTCPXDPAttachGeneric:
		wantMode = uint32(link.XDPGenericMode)
	default:
		return fmt.Errorf("post-attach aggregate XDP probe has unsupported mode %s", request.Mode)
	}
	if identity.Family != fakeTCPXDPBackendDirect || identity.Mode != request.Mode ||
		identity.IfIndex != request.IfIndex || identity.ProgramID == 0 || identity.OwnerID == 0 {
		return fmt.Errorf("post-attach direct XDP owner identity is incomplete: %+v", identity)
	}
	if probe.IfIndex != request.IfIndex || !probe.Attached ||
		probe.ProgramID != identity.ProgramID || probe.AttachMode != wantMode ||
		probe.Dispatcher || probe.DispatcherID != 0 {
		return fmt.Errorf(
			"post-attach aggregate XDP identity %+v does not match exact owner %+v mode=%d",
			probe, identity, wantMode,
		)
	}
	return nil
}

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
	request   fakeTCPXDPAttachRequest
	probe     fakeTCPXDPProbe
	family    fakeTCPXDPBackendFamily
	programID uint32
	identity  fakeTCPXDPLinkIdentity
	link      fakeTCPXDPLink
	state     fakeTCPXDPOwnershipState
}

func (attachment *fakeTCPXDPAttachment) adopt(
	family fakeTCPXDPBackendFamily,
	programID uint32,
) error {
	attachment.family = family
	attachment.programID = programID
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
		// Identity inspection can fail after a successful direct bpf_link
		// attach. Retry the exact FD identity before release so a transient
		// inspection error does not quarantine the process-owned link forever.
		// A mismatch remains fail-closed and never reaches Release.
		if err := attachment.adopt(attachment.family, attachment.programID); err != nil {
			return false, fmt.Errorf("release refused: XDP owner identity is still unverified: %w", err)
		}
	case fakeTCPXDPOwnershipStale:
		return false, errors.New("release refused: XDP owner identity is stale")
	case fakeTCPXDPOwnershipAdopted:
	default:
		return false, fmt.Errorf("release refused: invalid XDP ownership state %d", attachment.state)
	}
	result, err := attachment.link.Release(attachment.identity)
	identityMatches := result.Observed == attachment.identity
	if result.AutoDetached {
		identityMatches = fakeTCPXDPAutoDetachedIdentity(
			attachment.identity,
			result.Observed,
		)
	}
	if !identityMatches {
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
	runtime     fakeTCPXDPRuntime
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
	// Probe every hook exactly once before the first mutation. A libxdp adapter
	// receives the snapshot for its same-operation dispatcher CAS. Direct
	// backends use it only as a compatibility observation; their selected-mode
	// ownership contract makes no atomic claim about other XDP modes.
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

	stage := &fakeTCPXDPStage{runtime: runtime}
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
			request:   plan.request,
			probe:     plan.probe,
			family:    runtime.capabilities.Family,
			programID: programID,
			link:      ownedLink,
			state:     fakeTCPXDPOwnershipUnverified,
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
	// Re-prove the complete owner set after the last attach. Per-attachment
	// adoption proves each link FD at one point in time, but a foreign writer
	// can still replace an earlier interface's aggregate XDP owner while a
	// later interface is being attached. Returning the populated stage keeps
	// every exact process-owned link available to the caller's rollback path.
	if err := validateFakeTCPXDPAttachments(ctx, stage.runtime, stage.attachments); err != nil {
		return stage, fmt.Errorf("stage FakeTCP XDP final owner recheck: %w", err)
	}
	return stage, nil
}

func validateFakeTCPXDPAttachments(
	ctx context.Context,
	runtime fakeTCPXDPRuntime,
	attachments []fakeTCPXDPAttachment,
) error {
	if ctx == nil {
		return errors.New("inspect FakeTCP XDP owners: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(attachments) == 0 || runtime.probe == nil {
		return errors.New("inspect FakeTCP XDP owners: owner set is incomplete")
	}
	for index := range attachments {
		if err := ctx.Err(); err != nil {
			return err
		}
		attachment := &attachments[index]
		if attachment.state != fakeTCPXDPOwnershipAdopted {
			return fmt.Errorf(
				"ifindex %d ownership state %d is not adopted",
				attachment.request.IfIndex,
				attachment.state,
			)
		}
		if attachment.link == nil {
			return fmt.Errorf("ifindex %d owner link is nil", attachment.request.IfIndex)
		}
		identity, err := attachment.link.Identity()
		if err != nil {
			return fmt.Errorf("inspect link ifindex %d: %w", attachment.request.IfIndex, err)
		}
		if identity != attachment.identity {
			return fmt.Errorf(
				"inspect link ifindex %d: identity %+v differs from owner %+v",
				attachment.request.IfIndex,
				identity,
				attachment.identity,
			)
		}
		probe, err := runtime.probe(attachment.request.IfIndex)
		if err != nil {
			return fmt.Errorf("probe aggregate owner ifindex %d: %w", attachment.request.IfIndex, err)
		}
		switch attachment.family {
		case fakeTCPXDPBackendDirect:
			if err := validateLiveFakeTCPXDPPostAttach(
				attachment.request,
				attachment.identity,
				probe,
				nil,
			); err != nil {
				return fmt.Errorf("ifindex %d: %w", attachment.request.IfIndex, err)
			}
		case fakeTCPXDPBackendLibXDP:
			if !probe.Attached || !probe.Dispatcher ||
				probe.ProgramID != attachment.identity.DispatcherProgramID ||
				probe.DispatcherID != attachment.identity.DispatcherID {
				return fmt.Errorf(
					"inspect libxdp ifindex %d: aggregate identity %+v differs from owner %+v",
					attachment.request.IfIndex,
					probe,
					attachment.identity,
				)
			}
		default:
			return fmt.Errorf("unsupported backend %s", attachment.family)
		}
	}
	return nil
}

// Healthy re-proves every process-owned XDP link through both the held link
// FD identity and an aggregate per-interface observation. Production uses a
// direct generic exact-selected-mode backend, so disappearance or replacement
// of either identity makes the runtime unhealthy and triggers serial rebuild.
func (stage *fakeTCPXDPStage) Healthy(ctx context.Context) error {
	if stage == nil {
		return errors.New("FakeTCP XDP stage is nil")
	}
	if ctx == nil {
		return errors.New("inspect FakeTCP XDP health: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	stage.mu.Lock()
	defer stage.mu.Unlock()
	if err := validateFakeTCPXDPAttachments(ctx, stage.runtime, stage.attachments); err != nil {
		return fmt.Errorf("inspect FakeTCP XDP health: %w", err)
	}
	return nil
}

func (stage *fakeTCPXDPStage) productionStatus() []FakeTCPXDPStatus {
	if stage == nil {
		return nil
	}
	stage.mu.Lock()
	defer stage.mu.Unlock()
	result := make([]FakeTCPXDPStatus, 0, len(stage.attachments))
	for _, attachment := range stage.attachments {
		result = append(result, FakeTCPXDPStatus{
			IfIndex:   attachment.identity.IfIndex,
			Mode:      attachment.identity.Mode.String(),
			LinkID:    attachment.identity.OwnerID,
			ProgramID: attachment.identity.ProgramID,
		})
	}
	return result
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
