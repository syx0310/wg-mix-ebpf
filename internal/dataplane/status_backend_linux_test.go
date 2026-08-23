//go:build linux

package dataplane

import "testing"

func TestAttachmentStatusesRenderClassicAndTCXOwners(t *testing.T) {
	classic := &pinOwnerRecord{
		Version: pinOwnerLegacyClassicVersion,
		ActiveFilters: []tcFilterBinding{
			{
				IfIndex: 9, Direction: "egress", Parent: canonicalTCFilterSlots()[1].parent,
				Handle: egressHandle, Priority: filterPriority, ProgramID: 502,
			},
			{
				IfIndex: 9, Direction: "ingress", Parent: canonicalTCFilterSlots()[0].parent,
				Handle: ingressHandle, Priority: filterPriority, ProgramID: 501,
			},
			{
				IfIndex: 10, Direction: "ingress", Parent: canonicalTCFilterSlots()[0].parent,
				Handle: ingressHandle, Priority: filterPriority, ProgramID: 503,
			},
		},
	}
	got := attachmentStatusesForIfindex(classic, 9)
	if len(got) != 2 ||
		got[0].Direction != "ingress" || got[0].Backend != classicTCBackend ||
		got[0].Name != ingressFilterName || got[0].Handle != ingressHandle ||
		got[0].Priority != filterPriority || got[0].ProgramID != 501 ||
		got[1].Direction != "egress" || got[1].Backend != classicTCBackend ||
		got[1].Name != egressFilterName || got[1].Handle != egressHandle ||
		got[1].Priority != filterPriority || got[1].ProgramID != 502 {
		t.Fatalf("classic attachment status = %#v", got)
	}

	ingress := testExactTCXBinding(9, exactTCXIngress, 601)
	ingress.LinkID = 701
	egress := testExactTCXBinding(9, exactTCXEgress, 602)
	egress.LinkID = 702
	tcx := &pinOwnerRecord{
		Version:     pinOwnerRecordVersion,
		ActiveLinks: []exactTCXBinding{egress, ingress},
	}
	got = attachmentStatusesForIfindex(tcx, 9)
	if len(got) != 2 ||
		got[0].Direction != "ingress" || got[0].Backend != exactTCXBackend ||
		got[0].LinkID != 701 || got[0].ProgramID != 601 ||
		got[1].Direction != "egress" || got[1].Backend != exactTCXBackend ||
		got[1].LinkID != 702 || got[1].ProgramID != 602 {
		t.Fatalf("TCX attachment status = %#v", got)
	}
}

func TestPinOwnershipStatusReportsBackendSpecificCounts(t *testing.T) {
	classic := &PinOwnershipStatus{}
	setPinOwnershipStatusRecord(classic, &pinOwnerRecord{
		Version: pinOwnerLegacyClassicVersion,
		Phase:   pinOwnerPhaseActive,
		Step:    pinOwnerStepReady,
		ActiveFilters: []tcFilterBinding{
			{ProgramID: 1}, {ProgramID: 2},
		},
	})
	if classic.AttachmentBackend != classicTCBackend ||
		classic.ActiveFilterCount != 2 || classic.ActiveLinkCount != 0 {
		t.Fatalf("classic ownership status = %#v", classic)
	}

	tcx := &PinOwnershipStatus{}
	setPinOwnershipStatusRecord(tcx, &pinOwnerRecord{
		Version: pinOwnerRecordVersion,
		Phase:   pinOwnerPhaseActive,
		Step:    pinOwnerStepReady,
		ActiveLinks: []exactTCXBinding{
			{LinkID: 1}, {LinkID: 2},
		},
	})
	if tcx.AttachmentBackend != exactTCXBackend ||
		tcx.ActiveFilterCount != 2 || tcx.ActiveLinkCount != 2 {
		t.Fatalf("TCX ownership status = %#v", tcx)
	}
}
