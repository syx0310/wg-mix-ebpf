package dataplane

import (
	"context"

	"github.com/syx0310/wg-mix-ebpf/internal/control"
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
	Healthy           bool                         `json:"healthy"`
	Error             string                       `json:"error,omitempty"`
	XDP               []FakeTCPXDPStatus           `json:"xdp"`
	TCX               []FakeTCPTCXStatus           `json:"tcx,omitempty"`
	ClassicTC         []FakeTCPClassicTCStatus     `json:"classic_tc,omitempty"`
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
}

type FakeTCPTCXStatus struct {
	IfIndex    int    `json:"ifindex"`
	Direction  string `json:"direction"`
	AttachType uint32 `json:"attach_type"`
	LinkID     uint32 `json:"link_id"`
	ProgramID  uint32 `json:"program_id"`
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
