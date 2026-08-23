package dataplane

import (
	"context"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/control"
	"github.com/syx0310/wg-mix-ebpf/internal/faketcp"
)

type KernelStatus struct {
	Mode             string                 `json:"mode,omitempty"`
	PinPath          string                 `json:"pin_path,omitempty"`
	ActiveGeneration uint64                 `json:"active_generation,omitempty"`
	ABIVersion       uint32                 `json:"abi_version,omitempty"`
	Stats            map[string]uint64      `json:"stats,omitempty"`
	MapError         string                 `json:"map_error,omitempty"`
	Underlays        []UnderlayKernelStatus `json:"underlays"`
	FakeTCP          *FakeTCPRuntimeStatus  `json:"faketcp,omitempty"`
}

// FakeTCPRuntimeStatus describes the resident, process-owned production
// generation. It intentionally contains identities and digests only; cipher
// key material and userspace session contents are never exposed.
type FakeTCPRuntimeStatus struct {
	Generation        uint64                       `json:"generation"`
	Incarnation       string                       `json:"incarnation"`
	OwnerKind         string                       `json:"owner_kind"`
	AttachmentBackend string                       `json:"attachment_backend"`
	ObjectSource      string                       `json:"object_source"`
	ObjectSHA256      string                       `json:"object_sha256"`
	ChecksumBackend   FakeTCPChecksumRuntimeStatus `json:"checksum_backend"`
	Barrier           string                       `json:"barrier"`
	StartupGuardPause *StartupGuardPauseStatus     `json:"startup_guard_pause,omitempty"`
	Healthy           bool                         `json:"healthy"`
	Error             string                       `json:"error,omitempty"`
	XDP               []FakeTCPXDPStatus           `json:"xdp"`
	TCX               []FakeTCPTCXStatus           `json:"tcx,omitempty"`
	ClassicTC         []FakeTCPClassicTCStatus     `json:"classic_tc,omitempty"`
	Ownership         *FakeTCPOwnershipStatus      `json:"ownership,omitempty"`
}

// StartupGuardPauseStatus is the non-secret projection of the resident
// userspace barrier. ObservationTime is set by the control plane when it
// samples the resident runtime; Since belongs to the runtime transition
// itself and therefore remains stable across repeated status calls.
type StartupGuardPauseStatus struct {
	Phase           string    `json:"phase"`
	Reason          string    `json:"reason"`
	Since           time.Time `json:"since,omitempty"`
	ObservationTime time.Time `json:"observation_time"`
}

// FakeTCPOwnershipStatus separates the three independent ownership domains
// retained by a production FakeTCP generation. Keeping this projection
// explicit prevents a process-owned userspace runtime from being confused
// with durable classic-TC filters or process-owned XDP links.
type FakeTCPOwnershipStatus struct {
	Runtime FakeTCPProcessOwnershipStatus `json:"runtime"`
	XDP     []FakeTCPXDPStatus            `json:"xdp"`
	TC      FakeTCPOwnershipTCStatus      `json:"tc"`
}

const (
	FakeTCPOwnerKindProcessOwned             = "process-owned"
	FakeTCPOwnerKindDurableInstallationOwned = "durable-installation-owned"
)

type FakeTCPProcessOwnershipStatus struct {
	Kind              string                       `json:"kind"`
	Generation        uint64                       `json:"generation"`
	Incarnation       string                       `json:"incarnation"`
	ObjectSource      string                       `json:"object_source"`
	ObjectSHA256      string                       `json:"object_sha256"`
	ChecksumBackend   FakeTCPChecksumRuntimeStatus `json:"checksum_backend"`
	StartupGuardPause *StartupGuardPauseStatus     `json:"startup_guard_pause,omitempty"`
	Healthy           bool                         `json:"healthy"`
	Error             string                       `json:"error,omitempty"`
}

type FakeTCPOwnershipTCStatus struct {
	Backend   string                   `json:"backend"`
	Kind      string                   `json:"kind"`
	TCX       []FakeTCPTCXStatus       `json:"tcx,omitempty"`
	ClassicTC []FakeTCPClassicTCStatus `json:"classic_tc,omitempty"`
}

// FakeTCPChecksumRuntimeStatus contains only non-secret backend identity and
// health-relevant capabilities. The kprobe module cookie/nonce is never part
// of the status ABI.
type FakeTCPChecksumRuntimeStatus struct {
	Backend       string   `json:"backend,omitempty"`
	Capability    string   `json:"capability,omitempty"`
	Capabilities  []string `json:"capabilities,omitempty"`
	ObjectVariant string   `json:"object_variant,omitempty"`
	Module        string   `json:"module,omitempty"`
	LeaseHeld     bool     `json:"lease_held,omitempty"`
}

type FakeTCPXDPStatus struct {
	IfIndex   int    `json:"ifindex"`
	Mode      string `json:"mode"`
	LinkID    uint64 `json:"link_id"`
	ProgramID uint32 `json:"program_id"`
	Kind      string `json:"kind,omitempty"`
}

type FakeTCPTCXStatus struct {
	IfIndex    int    `json:"ifindex"`
	Direction  string `json:"direction"`
	AttachType uint32 `json:"attach_type"`
	LinkID     uint32 `json:"link_id"`
	ProgramID  uint32 `json:"program_id"`
	Kind       string `json:"kind,omitempty"`
}

// FakeTCPClassicTCStatus exposes the complete durable classic-TC identity.
// ProgramID, handle and priority together prove that a persistent filter still
// belongs to the resident FakeTCP generation.
type FakeTCPClassicTCStatus struct {
	IfIndex   int    `json:"ifindex"`
	Direction string `json:"direction"`
	Parent    uint32 `json:"parent"`
	Handle    uint32 `json:"handle"`
	Priority  uint16 `json:"priority"`
	ProgramID uint32 `json:"program_id"`
	Kind      string `json:"kind,omitempty"`
}

type UnderlayKernelStatus struct {
	Name            string         `json:"name"`
	IfIndex         int            `json:"ifindex"`
	IfName          string         `json:"ifname,omitempty"`
	IngressAttached bool           `json:"ingress_attached"`
	EgressAttached  bool           `json:"egress_attached"`
	XDPAttached     bool           `json:"xdp_attached,omitempty"`
	XDPMode         string         `json:"xdp_mode,omitempty"`
	XDPLinkID       uint64         `json:"xdp_link_id,omitempty"`
	XDPProgramID    uint32         `json:"xdp_program_id,omitempty"`
	Filters         []FilterStatus `json:"filters,omitempty"`
	Error           string         `json:"error,omitempty"`
}

type FilterStatus struct {
	Direction  string `json:"direction"`
	Name       string `json:"name"`
	Handle     uint32 `json:"handle"`
	Priority   uint16 `json:"priority"`
	Backend    string `json:"backend,omitempty"`
	AttachType uint32 `json:"attach_type,omitempty"`
	LinkID     uint32 `json:"link_id,omitempty"`
	ProgramID  uint32 `json:"program_id,omitempty"`
}

func Inspect(ctx context.Context, state *control.State) (*KernelStatus, error) {
	return inspect(ctx, state)
}

// StartupGuardPauseStatus delegates the production loader's read-only status
// contract to the process-wide supervisor. Declaring the adapter here keeps
// reconcile independent of the concrete supervisor while preserving the
// coordinator's operation lock around its shared owner pointer.
func (coordinator *fakeTCPProductionCoordinator) StartupGuardPauseStatus() faketcp.StartupGuardPauseStatus {
	if coordinator == nil || coordinator.shared == nil || coordinator.shared.supervisor == nil {
		return faketcp.StartupGuardPauseStatus{
			Phase:  faketcp.StartupGuardPausePhaseStopped,
			Reason: faketcp.StartupGuardPauseReasonRuntimeStopped,
		}
	}
	coordinator.shared.operationMu.Lock()
	defer coordinator.shared.operationMu.Unlock()
	provider, ok := coordinator.shared.supervisor.(faketcp.RuntimeStartupGuardPauseStatusProvider)
	if !ok {
		return faketcp.StartupGuardPauseStatus{
			Phase:  faketcp.StartupGuardPausePhaseStopped,
			Reason: faketcp.StartupGuardPauseReasonRuntimeStopped,
		}
	}
	return provider.StartupGuardPauseStatus()
}

// ProjectFakeTCPOwnership materialises an explicit, redacted ownership view
// from the historical flat FakeTCP status fields. It is idempotent and never
// includes cipher keys, module cookies, admission tokens, or session data.
func ProjectFakeTCPOwnership(status *KernelStatus) {
	if status == nil || status.FakeTCP == nil {
		return
	}
	runtime := status.FakeTCP
	xdp := append([]FakeTCPXDPStatus(nil), runtime.XDP...)
	for index := range xdp {
		xdp[index].Kind = FakeTCPOwnerKindProcessOwned
	}
	tcx := append([]FakeTCPTCXStatus(nil), runtime.TCX...)
	for index := range tcx {
		tcx[index].Kind = FakeTCPOwnerKindProcessOwned
	}
	classicTC := append([]FakeTCPClassicTCStatus(nil), runtime.ClassicTC...)
	for index := range classicTC {
		classicTC[index].Kind = FakeTCPOwnerKindDurableInstallationOwned
	}
	tcKind := "unknown"
	switch runtime.AttachmentBackend {
	case "tcx":
		tcKind = FakeTCPOwnerKindProcessOwned
	case "classic_tc":
		tcKind = FakeTCPOwnerKindDurableInstallationOwned
	}
	runtime.Ownership = &FakeTCPOwnershipStatus{
		Runtime: FakeTCPProcessOwnershipStatus{
			Kind:              FakeTCPOwnerKindProcessOwned,
			Generation:        runtime.Generation,
			Incarnation:       runtime.Incarnation,
			ObjectSource:      runtime.ObjectSource,
			ObjectSHA256:      runtime.ObjectSHA256,
			ChecksumBackend:   cloneFakeTCPChecksumStatus(runtime.ChecksumBackend),
			StartupGuardPause: cloneStartupGuardPauseStatus(runtime.StartupGuardPause),
			Healthy:           runtime.Healthy,
			Error:             runtime.Error,
		},
		XDP: xdp,
		TC: FakeTCPOwnershipTCStatus{
			Backend:   runtime.AttachmentBackend,
			Kind:      tcKind,
			TCX:       tcx,
			ClassicTC: classicTC,
		},
	}
}

func cloneFakeTCPChecksumStatus(status FakeTCPChecksumRuntimeStatus) FakeTCPChecksumRuntimeStatus {
	status.Capabilities = append([]string(nil), status.Capabilities...)
	return status
}

func cloneStartupGuardPauseStatus(status *StartupGuardPauseStatus) *StartupGuardPauseStatus {
	if status == nil {
		return nil
	}
	clone := *status
	return &clone
}
