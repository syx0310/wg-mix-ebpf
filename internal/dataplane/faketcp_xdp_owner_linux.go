//go:build linux

package dataplane

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
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

type fakeTCPXDPAttachRequest struct {
	IfIndex int
	Mode    fakeTCPXDPAttachMode
}

type fakeTCPXDPProbe struct {
	IfIndex           int
	Attached          bool
	ProgramID         uint32
	AttachMode        uint32
	Dispatcher        bool
	ChainingAvailable bool
}

type fakeTCPXDPLink interface {
	Identity() (ifindex int, programID uint32, err error)
	Close() error
}

type fakeTCPXDPRuntime struct {
	probe func(int) (fakeTCPXDPProbe, error)
	// attach must return the owning link whenever mutation succeeded. A nil
	// link or an error must mean no attachment was created; this mirrors
	// link.AttachXDP's atomic ownership contract.
	attach func(fakeTCPXDPAttachRequest, experimentalProgramResource) (fakeTCPXDPLink, error)
}

type liveFakeTCPXDPLink struct {
	link link.Link
}

func (owned *liveFakeTCPXDPLink) Identity() (int, uint32, error) {
	if owned == nil || owned.link == nil {
		return 0, 0, errors.New("owned XDP link is nil")
	}
	info, err := owned.link.Info()
	if err != nil {
		return 0, 0, fmt.Errorf("inspect owned XDP link: %w", err)
	}
	xdp := info.XDP()
	if xdp == nil || xdp.Ifindex == 0 || info.Program == 0 {
		return 0, 0, errors.New("owned XDP link has incomplete interface/program identity")
	}
	return int(xdp.Ifindex), uint32(info.Program), nil
}

func (owned *liveFakeTCPXDPLink) Close() error {
	if owned == nil || owned.link == nil {
		return nil
	}
	return owned.link.Close()
}

var liveFakeTCPXDPRuntime = fakeTCPXDPRuntime{
	probe: probeLiveFakeTCPXDP,
	attach: func(
		request fakeTCPXDPAttachRequest,
		program experimentalProgramResource,
	) (fakeTCPXDPLink, error) {
		if request.Mode == fakeTCPXDPAttachLibXDP {
			return nil, errors.New("libxdp dispatcher chaining backend is unavailable")
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
			return nil, fmt.Errorf("unsupported XDP attach mode %s", request.Mode)
		}
		attached, err := link.AttachXDP(link.XDPOptions{
			Program: program.kernelProgram(), Interface: request.IfIndex, Flags: flags,
		})
		if err != nil {
			return nil, err
		}
		return &liveFakeTCPXDPLink{link: attached}, nil
	},
}

func probeLiveFakeTCPXDP(ifindex int) (fakeTCPXDPProbe, error) {
	if ifindex <= 0 {
		return fakeTCPXDPProbe{}, fmt.Errorf("probe XDP: invalid ifindex %d", ifindex)
	}
	networkLink, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		return fakeTCPXDPProbe{}, err
	}
	if networkLink == nil || networkLink.Attrs() == nil || networkLink.Attrs().Index != ifindex {
		return fakeTCPXDPProbe{}, errors.New("XDP probe returned mismatched network link")
	}
	probe := fakeTCPXDPProbe{IfIndex: ifindex}
	xdp := networkLink.Attrs().Xdp
	if xdp == nil || !xdp.Attached {
		return probe, nil
	}
	if xdp.ProgId == 0 {
		return fakeTCPXDPProbe{}, errors.New("XDP probe found an attachment without a program ID")
	}
	probe.Attached = true
	probe.ProgramID = xdp.ProgId
	probe.AttachMode = xdp.AttachMode

	program, err := ebpf.NewProgramFromID(ebpf.ProgramID(xdp.ProgId))
	if err != nil {
		return fakeTCPXDPProbe{}, fmt.Errorf("inspect attached XDP program ID %d: %w", xdp.ProgId, err)
	}
	info, infoErr := program.Info()
	closeErr := program.Close()
	if infoErr != nil || closeErr != nil {
		return fakeTCPXDPProbe{}, errors.Join(
			wrapNonNilError("inspect attached XDP program", infoErr),
			wrapNonNilError("close attached XDP program observation", closeErr),
		)
	}
	// Observation is intentionally not a capability claim. The in-process
	// runtime has no libxdp component registration API, so it always reports
	// ChainingAvailable=false even when the conventional dispatcher name is
	// visible. A future adapter must supply both a positive probe and an exact
	// chained-link owner before the mode can mutate anything.
	probe.Dispatcher = strings.HasPrefix(info.Name, "xdp_dispatcher")
	return probe, nil
}

type fakeTCPXDPAttachment struct {
	request   fakeTCPXDPAttachRequest
	programID uint32
	link      fakeTCPXDPLink
}

type fakeTCPXDPStage struct {
	mu          sync.Mutex
	attachments []fakeTCPXDPAttachment
	closed      bool
	closeErr    error
}

func stageFakeTCPXDPAttachments(
	requests []fakeTCPXDPAttachRequest,
	program experimentalProgramResource,
	runtime fakeTCPXDPRuntime,
) (*fakeTCPXDPStage, error) {
	if len(requests) == 0 {
		return nil, errors.New("stage FakeTCP XDP: at least one attachment is required")
	}
	if program == nil {
		return nil, errors.New("stage FakeTCP XDP: program is nil")
	}
	if runtime.probe == nil || runtime.attach == nil {
		return nil, errors.New("stage FakeTCP XDP: probe and attach backends are required")
	}
	programID, err := program.ID()
	if err != nil {
		return nil, fmt.Errorf("stage FakeTCP XDP: inspect program identity: %w", err)
	}
	if programID == 0 {
		return nil, errors.New("stage FakeTCP XDP: program ID is zero")
	}

	ordered := append([]fakeTCPXDPAttachRequest(nil), requests...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].IfIndex < ordered[j].IfIndex })
	for index, request := range ordered {
		if request.IfIndex <= 0 || uint64(request.IfIndex) > math.MaxUint32 {
			return nil, fmt.Errorf("stage FakeTCP XDP: invalid ifindex %d", request.IfIndex)
		}
		if index > 0 && ordered[index-1].IfIndex == request.IfIndex {
			return nil, fmt.Errorf("stage FakeTCP XDP: duplicate ifindex %d", request.IfIndex)
		}
		if request.Mode != fakeTCPXDPAttachNative && request.Mode != fakeTCPXDPAttachGeneric &&
			request.Mode != fakeTCPXDPAttachLibXDP {
			return nil, fmt.Errorf("stage FakeTCP XDP: unsupported mode %s", request.Mode)
		}
	}

	stage := &fakeTCPXDPStage{}
	// Complete every read-only ownership/capability probe before the first
	// attach. One invalid later interface must not cause a transient partial
	// deployment on an earlier interface.
	for _, request := range ordered {
		probe, err := runtime.probe(request.IfIndex)
		if err != nil {
			return nil, fmt.Errorf("stage FakeTCP XDP probe ifindex %d: %w", request.IfIndex, err)
		}
		if err := validateFakeTCPXDPProbe(request, probe); err != nil {
			return nil, err
		}
	}
	for _, request := range ordered {
		ownedLink, err := runtime.attach(request, program)
		if err != nil {
			return stageOrNil(stage), fmt.Errorf(
				"stage FakeTCP XDP attach ifindex %d mode %s: %w",
				request.IfIndex, request.Mode, err,
			)
		}
		if ownedLink == nil {
			return stageOrNil(stage), fmt.Errorf(
				"stage FakeTCP XDP attach ifindex %d returned a nil link",
				request.IfIndex,
			)
		}
		stage.attachments = append(stage.attachments, fakeTCPXDPAttachment{
			request: request, programID: programID, link: ownedLink,
		})
		actualIfindex, actualProgramID, err := ownedLink.Identity()
		if err != nil {
			return stage, fmt.Errorf("stage FakeTCP XDP verify ifindex %d: %w", request.IfIndex, err)
		}
		if actualIfindex != request.IfIndex || actualProgramID != programID {
			return stage, fmt.Errorf(
				"stage FakeTCP XDP verify ifindex %d: link identity is ifindex=%d program=%d, want ifindex=%d program=%d",
				request.IfIndex, actualIfindex, actualProgramID, request.IfIndex, programID,
			)
		}
	}
	return stage, nil
}

func validateFakeTCPXDPProbe(request fakeTCPXDPAttachRequest, probe fakeTCPXDPProbe) error {
	if probe.IfIndex != request.IfIndex {
		return fmt.Errorf(
			"stage FakeTCP XDP probe ifindex %d returned identity %d",
			request.IfIndex, probe.IfIndex,
		)
	}
	if request.Mode == fakeTCPXDPAttachLibXDP {
		if !probe.Attached || probe.ProgramID == 0 || !probe.Dispatcher ||
			!probe.ChainingAvailable {
			return fmt.Errorf(
				"stage FakeTCP XDP ifindex %d: libxdp chaining capability is not proven",
				request.IfIndex,
			)
		}
		return nil
	}
	if probe.Attached || probe.ProgramID != 0 {
		return fmt.Errorf(
			"stage FakeTCP XDP ifindex %d mode %s: existing program ID %d is not owned; replacement is refused",
			request.IfIndex, request.Mode, probe.ProgramID,
		)
	}
	return nil
}

func stageOrNil(stage *fakeTCPXDPStage) *fakeTCPXDPStage {
	if stage == nil || len(stage.attachments) == 0 {
		return nil
	}
	return stage
}

// Close rolls back or retires only links returned by this exact stage. Every
// link handle is closed exactly once. The joined result is retained so later
// and concurrent callers observe the failure without risking a double detach.
func (stage *fakeTCPXDPStage) Close() error {
	if stage == nil {
		return nil
	}
	stage.mu.Lock()
	defer stage.mu.Unlock()
	if stage.closed {
		return stage.closeErr
	}
	var errs []error
	for index := len(stage.attachments) - 1; index >= 0; index-- {
		attachment := stage.attachments[index]
		if err := attachment.link.Close(); err != nil {
			errs = append(errs, fmt.Errorf(
				"close owned FakeTCP XDP link ifindex %d mode %s program %d: %w",
				attachment.request.IfIndex, attachment.request.Mode, attachment.programID, err,
			))
		}
	}
	stage.attachments = nil
	stage.closeErr = errors.Join(errs...)
	stage.closed = true
	return stage.closeErr
}
