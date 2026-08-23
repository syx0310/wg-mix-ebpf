package faketcp

const (
	// FakeTCPHeaderDelta is the growth from an 8-byte UDP header to a
	// fixed 20-byte TCP header. Admission is deliberately exact: accepting an
	// arbitrary caller-provided delta would let control-plane and BPF policy
	// silently diverge.
	FakeTCPHeaderDelta uint64 = 12
)
