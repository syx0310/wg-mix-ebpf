package dataplane

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestProjectFakeTCPOwnershipSeparatesRuntimeXDPAndTC(t *testing.T) {
	observed := time.Unix(123, 456).UTC()
	status := &KernelStatus{FakeTCP: &FakeTCPRuntimeStatus{
		Generation:        19,
		Incarnation:       "00112233445566778899aabbccddeeff",
		OwnerKind:         "durable-classic-tc+process-owned-runtime",
		AttachmentBackend: "classic_tc",
		ObjectSource:      "embedded",
		ObjectSHA256:      strings.Repeat("a", 64),
		ChecksumBackend: FakeTCPChecksumRuntimeStatus{
			Backend: "kprobe", Capabilities: []string{"checksum"}, LeaseHeld: true,
		},
		StartupGuardPause: &StartupGuardPauseStatus{
			Phase: "held", Reason: "startup_guard", Since: observed, ObservationTime: observed,
		},
		Healthy: false,
		Error:   "guard barrier held",
		XDP:     []FakeTCPXDPStatus{{IfIndex: 2, Mode: "generic", LinkID: 7, ProgramID: 11}},
		ClassicTC: []FakeTCPClassicTCStatus{{
			IfIndex: 2, Direction: "ingress", Parent: 0xfffffff2,
			Handle: 0x10001, Priority: 49152, ProgramID: 13,
		}},
	}}

	ProjectFakeTCPOwnership(status)
	owners := status.FakeTCP.Ownership
	if owners == nil {
		t.Fatal("ownership projection is nil")
	}
	if owners.Runtime.Kind != FakeTCPOwnerKindProcessOwned ||
		owners.Runtime.Generation != status.FakeTCP.Generation ||
		owners.Runtime.StartupGuardPause == status.FakeTCP.StartupGuardPause {
		t.Fatalf("runtime ownership = %#v", owners.Runtime)
	}
	if len(owners.XDP) != 1 || owners.XDP[0].LinkID != 7 ||
		owners.XDP[0].Kind != FakeTCPOwnerKindProcessOwned {
		t.Fatalf("XDP ownership = %#v", owners.XDP)
	}
	if owners.TC.Backend != "classic_tc" ||
		owners.TC.Kind != FakeTCPOwnerKindDurableInstallationOwned ||
		len(owners.TC.ClassicTC) != 1 ||
		owners.TC.ClassicTC[0].Kind != FakeTCPOwnerKindDurableInstallationOwned ||
		len(owners.TC.TCX) != 0 {
		t.Fatalf("TC ownership = %#v", owners.TC)
	}
	if status.FakeTCP.OwnerKind != "durable-classic-tc+process-owned-runtime" ||
		status.FakeTCP.XDP[0].Kind != "" || status.FakeTCP.ClassicTC[0].Kind != "" {
		t.Fatalf("legacy flat ownership fields changed: %#v", status.FakeTCP)
	}
}

func TestProjectFakeTCPOwnershipMarksResidentTCXProcessOwned(t *testing.T) {
	status := &KernelStatus{FakeTCP: &FakeTCPRuntimeStatus{
		OwnerKind:         "process-owned",
		AttachmentBackend: "tcx",
		TCX: []FakeTCPTCXStatus{{
			IfIndex: 3, Direction: "egress", AttachType: 44, LinkID: 17, ProgramID: 19,
		}},
	}}

	ProjectFakeTCPOwnership(status)
	owners := status.FakeTCP.Ownership
	if owners == nil || owners.Runtime.Kind != FakeTCPOwnerKindProcessOwned ||
		owners.TC.Backend != "tcx" || owners.TC.Kind != FakeTCPOwnerKindProcessOwned ||
		len(owners.TC.TCX) != 1 || owners.TC.TCX[0].Kind != FakeTCPOwnerKindProcessOwned ||
		len(owners.TC.ClassicTC) != 0 {
		t.Fatalf("TCX ownership = %#v", owners)
	}
	if status.FakeTCP.TCX[0].Kind != "" {
		t.Fatalf("legacy flat TCX ownership changed: %#v", status.FakeTCP.TCX)
	}
}

func TestFakeTCPOwnershipJSONContainsNoSecretBearingFields(t *testing.T) {
	status := &KernelStatus{FakeTCP: &FakeTCPRuntimeStatus{
		Generation: 1,
		ChecksumBackend: FakeTCPChecksumRuntimeStatus{
			Backend: "kprobe", Module: "wg_mix_faketcp_kprobe", LeaseHeld: true,
		},
	}}
	ProjectFakeTCPOwnership(status)
	data, err := json.Marshal(status.FakeTCP.Ownership)
	if err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(string(data))
	for _, forbidden := range []string{"secret", "password", "cookie", "nonce", "session"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("ownership JSON contains forbidden token %q: %s", forbidden, data)
		}
	}
}
