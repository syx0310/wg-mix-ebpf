package faketcp

import (
	"fmt"
)

const (
	// FakeTCPHeaderDelta is the growth from an 8-byte UDP header to a
	// fixed 20-byte TCP header. Admission is deliberately exact: accepting an
	// arbitrary caller-provided delta would let control-plane and BPF policy
	// silently diverge.
	FakeTCPHeaderDelta uint64 = 12
)

// MTUErrorCode is the stable rejection axis used by the userspace audit
// decoder and the test-only admission oracle.
type MTUErrorCode string

const (
	MTUErrorInvalidInput          MTUErrorCode = "invalid-input"
	MTUErrorArithmeticOverflow    MTUErrorCode = "arithmetic-overflow"
	MTUErrorFragmentationRejected MTUErrorCode = "fragmentation-rejected"
	MTUErrorUnknown               MTUErrorCode = "mtu-unknown"
	MTUErrorExceeded              MTUErrorCode = "mtu-exceeded"
)

// MTUBoundary identifies the independent admission boundary that rejected a
// request. Keeping boundary separate from reason avoids a combinatorial error
// taxonomy while preserving device-versus-route auditability.
type MTUBoundary string

const (
	MTUBoundaryInput  MTUBoundary = "input"
	MTUBoundaryDevice MTUBoundary = "device"
	MTUBoundaryRoute  MTUBoundary = "route"

	mtuAuditReasonCount   uint32 = 5
	mtuAuditBoundaryCount uint32 = 3
	// MTUAuditKeyCount is the exact reason-by-boundary BPF map cardinality.
	MTUAuditKeyCount = mtuAuditReasonCount * mtuAuditBoundaryCount
)

var (
	mtuAuditReasons = [...]MTUErrorCode{
		MTUErrorInvalidInput,
		MTUErrorArithmeticOverflow,
		MTUErrorFragmentationRejected,
		MTUErrorUnknown,
		MTUErrorExceeded,
	}
	mtuAuditBoundaries = [...]MTUBoundary{
		MTUBoundaryInput,
		MTUBoundaryDevice,
		MTUBoundaryRoute,
	}
)

// EncodeMTUAuditKey returns the BPF counter key for one reason/boundary pair.
func EncodeMTUAuditKey(code MTUErrorCode, boundary MTUBoundary) (uint32, error) {
	reasonIndex := -1
	for index, candidate := range mtuAuditReasons {
		if candidate == code {
			reasonIndex = index
			break
		}
	}
	boundaryIndex := -1
	for index, candidate := range mtuAuditBoundaries {
		if candidate == boundary {
			boundaryIndex = index
			break
		}
	}
	if reasonIndex < 0 || boundaryIndex < 0 {
		return 0, fmt.Errorf("invalid faketcp MTU audit classification %q/%q", code, boundary)
	}
	return uint32(reasonIndex)*mtuAuditBoundaryCount + uint32(boundaryIndex), nil
}

// DecodeMTUAuditKey decodes the reason×boundary key used by
// faketcp_mtu_audit_map. It is the userspace propagation boundary for BPF
// counters; no caller needs to duplicate the numeric layout.
func DecodeMTUAuditKey(key uint32) (MTUErrorCode, MTUBoundary, error) {
	if key >= MTUAuditKeyCount {
		return "", "", fmt.Errorf("faketcp MTU audit key %d is outside [0,%d)", key, MTUAuditKeyCount)
	}
	return mtuAuditReasons[key/mtuAuditBoundaryCount], mtuAuditBoundaries[key%mtuAuditBoundaryCount], nil
}
