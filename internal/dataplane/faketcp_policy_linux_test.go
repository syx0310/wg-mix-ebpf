//go:build linux

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/syx0310/wg-mix-ebpf/internal/abi"
	"github.com/syx0310/wg-mix-ebpf/internal/lockfile"
)

func TestStageFakeTCPPolicyGenerationWritesReachabilityLatchLast(t *testing.T) {
	snapshot := mustFakeTCPPolicySnapshot(t, 91)
	ctx, transaction, isolation := newTestFakeTCPPolicyGenerationTransaction(t, snapshot.Generation)
	policyMaps, trace := newMemoryFakeTCPPolicyMaps()
	isolation.events = &trace.events
	stage, err := transaction.Stage(ctx, policyMaps, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		fakeTCPControlPolicyMapName,
		fakeTCPControlPolicyMapName,
		fakeTCPManagedPortMapName,
		fakeTCPManagedPortMapName,
		fakeTCPManagedIfMapName,
		fakeTCPManagedIfMapName,
	}
	if !slices.Equal(trace.successfulUpdates, want) {
		t.Fatalf("update order = %v, want %v", trace.successfulUpdates, want)
	}
	if len(trace.events) == 0 || trace.events[0] != "assert-inactive" {
		t.Fatalf("first generation/map event = %v, want assert-inactive", trace.events)
	}
	if !slices.Equal(isolation.inactiveCalls, []uint64{snapshot.Generation}) {
		t.Fatalf("inactive checks = %v, want generation %d", isolation.inactiveCalls, snapshot.Generation)
	}
	for _, flags := range trace.updateFlags {
		if flags != ebpf.UpdateNoExist {
			t.Fatalf("policy update flags = %v, want UpdateNoExist", flags)
		}
	}
	assertMemoryPolicyMapMatches(t, policyMaps.ControlPolicies, snapshot.ControlPolicies)
	assertMemoryPolicyMapMatches(t, policyMaps.ManagedPorts, snapshot.ManagedPorts)
	assertMemoryPolicyMapMatches(t, policyMaps.ManagedInterfaces, snapshot.ManagedInterfaces)
	if err := transaction.Disarm(ctx, stage); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Rollback(ctx, stage); err != nil {
		t.Fatal(err)
	}
	assertMemoryPolicyMapMatches(t, policyMaps.ControlPolicies, snapshot.ControlPolicies)
}

func TestStageFakeTCPPolicyGenerationRequiresInactiveBeforeMapAccess(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*memoryFakeTCPPolicyQuiescer)
		wantError string
	}{
		{
			name: "backend failure",
			configure: func(isolation *memoryFakeTCPPolicyQuiescer) {
				isolation.failInactive = errors.New("injected inactive check failure")
			},
			wantError: "injected inactive check failure",
		},
		{
			name: "backend rejects wrong generation",
			configure: func(isolation *memoryFakeTCPPolicyQuiescer) {
				isolation.generation++
			},
			wantError: "inactive generation 91, want 92",
		},
		{
			name: "target is active",
			configure: func(isolation *memoryFakeTCPPolicyQuiescer) {
				isolation.inactive = false
			},
			wantError: "target generation is active",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := mustFakeTCPPolicySnapshot(t, 91)
			ctx, transaction, isolation := newTestFakeTCPPolicyGenerationTransaction(t, snapshot.Generation)
			policyMaps, trace := newMemoryFakeTCPPolicyMaps()
			isolation.events = &trace.events
			test.configure(isolation)

			stage, err := transaction.Stage(ctx, policyMaps, snapshot)
			if stage != nil || err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("inactive-gated stage handle=%v error=%v, want %q", stage, err, test.wantError)
			}
			if !slices.Equal(trace.events, []string{"assert-inactive"}) ||
				len(trace.updateAttempts) != 0 || len(trace.deleteAttempts) != 0 ||
				len(isolation.calls) != 0 {
				t.Fatalf(
					"failed inactive proof touched maps/quiesce: events=%v updates=%v deletes=%v quiesce=%v",
					trace.events,
					trace.updateAttempts,
					trace.deleteAttempts,
					isolation.calls,
				)
			}
		})
	}
}

func TestFakeTCPPolicyGenerationTransactionRejectsMismatchedLifecycleContext(t *testing.T) {
	snapshot := mustFakeTCPPolicySnapshot(t, 91)
	ctx, transaction, isolation := newTestFakeTCPPolicyGenerationTransaction(t, snapshot.Generation)
	policyMaps, trace := newMemoryFakeTCPPolicyMaps()
	isolation.events = &trace.events
	wrongRoot := t.TempDir()
	wrongCtx := lockfile.WithLifecyclePathsForTest(
		t.Context(),
		filepath.Join(wrongRoot, "other-daemon.lease"),
		filepath.Join(wrongRoot, "other-maintenance.gate"),
	)

	stage, err := transaction.Stage(wrongCtx, policyMaps, snapshot)
	if stage != nil || err == nil || !strings.Contains(err.Error(), "does not match transaction path") {
		t.Fatalf("mismatched-context stage handle=%v error=%v", stage, err)
	}
	if len(trace.events) != 0 || len(isolation.inactiveCalls) != 0 || len(isolation.calls) != 0 {
		t.Fatalf(
			"mismatched stage context touched backend/maps: events=%v inactive=%v quiesce=%v",
			trace.events,
			isolation.inactiveCalls,
			isolation.calls,
		)
	}

	stage, err = transaction.Stage(ctx, policyMaps, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	eventCount := len(trace.events)
	deleteCount := len(trace.deleteAttempts)
	quiesceCount := len(isolation.calls)
	if err := transaction.Rollback(wrongCtx, stage); err == nil ||
		!strings.Contains(err.Error(), "does not match transaction path") {
		t.Fatalf("mismatched-context rollback error = %v", err)
	}
	if len(trace.events) != eventCount || len(trace.deleteAttempts) != deleteCount ||
		len(isolation.calls) != quiesceCount {
		t.Fatalf(
			"mismatched rollback context touched maps/quiesce: events=%v deletes=%v quiesce=%v",
			trace.events[eventCount:],
			trace.deleteAttempts[deleteCount:],
			isolation.calls[quiesceCount:],
		)
	}
	if err := transaction.Rollback(ctx, stage); err != nil {
		t.Fatal(err)
	}
}

func TestStageFakeTCPPolicyGenerationRollsBackEveryWriteFailureInReverse(t *testing.T) {
	snapshot := mustFakeTCPPolicySnapshot(t, 91)
	totalWrites := len(snapshot.ControlPolicies) + len(snapshot.ManagedPorts) + len(snapshot.ManagedInterfaces)
	for failAt := 1; failAt <= totalWrites; failAt++ {
		t.Run(fmt.Sprintf("write-%d", failAt), func(t *testing.T) {
			ctx, transaction, _ := newTestFakeTCPPolicyGenerationTransaction(t, snapshot.Generation)
			policyMaps, trace := newMemoryFakeTCPPolicyMaps()
			old := seedOldFakeTCPPolicyGeneration(policyMaps, 90)
			trace.failUpdateAt = failAt
			stage, err := transaction.Stage(ctx, policyMaps, snapshot)
			if stage != nil {
				t.Fatal("failed stage returned a rollback handle")
			}
			if err == nil || !strings.Contains(err.Error(), "injected update failure") {
				t.Fatalf("stage error = %v", err)
			}
			assertNoMemoryPolicyGeneration(t, policyMaps, snapshot.Generation)
			assertOldFakeTCPPolicyGeneration(t, policyMaps, old)

			wantDeletes := slices.Clone(trace.successfulUpdates)
			slices.Reverse(wantDeletes)
			if !slices.Equal(trace.deletes, wantDeletes) {
				t.Fatalf("rollback order = %v, want %v", trace.deletes, wantDeletes)
			}
		})
	}
}

func TestFakeTCPPolicyStageRollsBackLaterTransactionFailureAndIsIdempotent(t *testing.T) {
	snapshot := mustFakeTCPPolicySnapshot(t, 91)
	ctx, transaction, _ := newTestFakeTCPPolicyGenerationTransaction(t, snapshot.Generation)
	policyMaps, trace := newMemoryFakeTCPPolicyMaps()
	old := seedOldFakeTCPPolicyGeneration(policyMaps, 90)
	stage, err := transaction.Stage(ctx, policyMaps, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	wantDeletes := slices.Clone(trace.successfulUpdates)
	slices.Reverse(wantDeletes)
	if err := transaction.Rollback(ctx, stage); err != nil {
		t.Fatal(err)
	}
	assertNoMemoryPolicyGeneration(t, policyMaps, snapshot.Generation)
	assertOldFakeTCPPolicyGeneration(t, policyMaps, old)
	if !slices.Equal(trace.deletes, wantDeletes) {
		t.Fatalf("outer rollback order = %v, want %v", trace.deletes, wantDeletes)
	}
	deleteCount := len(trace.deletes)
	if err := transaction.Rollback(ctx, stage); err != nil {
		t.Fatalf("idempotent rollback: %v", err)
	}
	if len(trace.deletes) != deleteCount {
		t.Fatalf("second rollback deleted more entries: %v", trace.deletes)
	}
	if err := transaction.Disarm(ctx, stage); err == nil || !strings.Contains(err.Error(), "rolled-back") {
		t.Fatalf("disarm after rollback error = %v", err)
	}
}

func TestFakeTCPPolicyStageChangedValueIsRetryableAndNeverBlindDeleted(t *testing.T) {
	snapshot := mustFakeTCPPolicySnapshot(t, 91)
	ctx, transaction, _ := newTestFakeTCPPolicyGenerationTransaction(t, snapshot.Generation)
	policyMaps, _ := newMemoryFakeTCPPolicyMaps()
	stage, err := transaction.Stage(ctx, policyMaps, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	managedInterfaces := policyMaps.ManagedInterfaces.(*memoryFakeTCPPolicyMap)
	var changedKey abi.FakeTCPManagedIfKey
	var inserted abi.FakeTCPManagedIfValue
	for key, value := range snapshot.ManagedInterfaces {
		changedKey, inserted = key, value
		break
	}
	changed := inserted
	changed.Generation++
	managedInterfaces.entries[changedKey] = changed

	err = transaction.Rollback(ctx, stage)
	if err == nil || !strings.Contains(err.Error(), "refusing rollback because inserted value changed") {
		t.Fatalf("changed-value rollback error = %v", err)
	}
	if got := managedInterfaces.entries[changedKey]; got != changed {
		t.Fatalf("changed value was blindly deleted or overwritten: %#v", got)
	}
	assertMemoryPolicyMapMatches(t, policyMaps.ControlPolicies, snapshot.ControlPolicies)
	assertMemoryPolicyMapMatches(t, policyMaps.ManagedPorts, snapshot.ManagedPorts)
	if err := transaction.Disarm(ctx, stage); err == nil || !strings.Contains(err.Error(), "incomplete rollback") {
		t.Fatalf("disarm after incomplete rollback error = %v", err)
	}

	// Once the exact latch is restored, retry completes the latch phase,
	// quiesces BPF, and only then removes ports and policies.
	managedInterfaces.entries[changedKey] = inserted
	if err := transaction.Rollback(ctx, stage); err != nil {
		t.Fatalf("retry exact rollback: %v", err)
	}
	assertNoMemoryPolicyGeneration(t, policyMaps, snapshot.Generation)
}

func TestFakeTCPPolicyRollbackStopsAtFailedInterfaceLatch(t *testing.T) {
	tests := []struct {
		name   string
		inject func(*memoryFakeTCPPolicyMap)
	}{
		{
			name: "lookup",
			inject: func(policyMap *memoryFakeTCPPolicyMap) {
				policyMap.failNextLookup = errors.New("injected interface lookup failure")
			},
		},
		{
			name: "delete",
			inject: func(policyMap *memoryFakeTCPPolicyMap) {
				policyMap.failNextDelete = errors.New("injected interface delete failure")
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := mustFakeTCPPolicySnapshot(t, 91)
			ctx, transaction, quiescer := newTestFakeTCPPolicyGenerationTransaction(t, snapshot.Generation)
			policyMaps, trace := newMemoryFakeTCPPolicyMaps()
			stage, err := transaction.Stage(ctx, policyMaps, snapshot)
			if err != nil {
				t.Fatal(err)
			}
			test.inject(policyMaps.ManagedInterfaces.(*memoryFakeTCPPolicyMap))

			err = transaction.Rollback(ctx, stage)
			if err == nil || !strings.Contains(err.Error(), "interface") {
				t.Fatalf("interface-phase rollback error = %v", err)
			}
			if len(quiescer.calls) != 0 {
				t.Fatalf("quiesce ran with an unconfirmed interface latch: %v", quiescer.calls)
			}
			if slices.Contains(trace.deleteAttempts, fakeTCPManagedPortMapName) ||
				slices.Contains(trace.deleteAttempts, fakeTCPControlPolicyMapName) {
				t.Fatalf("interface failure touched dependencies: %v", trace.deleteAttempts)
			}
			assertMemoryPolicyMapMatches(t, policyMaps.ManagedPorts, snapshot.ManagedPorts)
			assertMemoryPolicyMapMatches(t, policyMaps.ControlPolicies, snapshot.ControlPolicies)

			if err := transaction.Rollback(ctx, stage); err != nil {
				t.Fatalf("retry interface rollback: %v", err)
			}
			assertNoMemoryPolicyGeneration(t, policyMaps, snapshot.Generation)
		})
	}
}

func TestFakeTCPPolicyRollbackStopsAtFailedQuiescenceBarrier(t *testing.T) {
	snapshot := mustFakeTCPPolicySnapshot(t, 91)
	ctx, transaction, quiescer := newTestFakeTCPPolicyGenerationTransaction(t, snapshot.Generation)
	policyMaps, trace := newMemoryFakeTCPPolicyMaps()
	stage, err := transaction.Stage(ctx, policyMaps, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	quiescer.fail = errors.New("injected quiescence failure")

	err = transaction.Rollback(ctx, stage)
	if err == nil || !strings.Contains(err.Error(), "injected quiescence failure") {
		t.Fatalf("quiescence rollback error = %v", err)
	}
	if slices.Contains(trace.deleteAttempts, fakeTCPManagedPortMapName) ||
		slices.Contains(trace.deleteAttempts, fakeTCPControlPolicyMapName) {
		t.Fatalf("quiescence failure touched dependencies: %v", trace.deleteAttempts)
	}
	if len(policyMaps.ManagedInterfaces.(*memoryFakeTCPPolicyMap).entries) != 0 {
		t.Fatal("quiescence ran before every interface latch was removed")
	}
	assertMemoryPolicyMapMatches(t, policyMaps.ManagedPorts, snapshot.ManagedPorts)
	assertMemoryPolicyMapMatches(t, policyMaps.ControlPolicies, snapshot.ControlPolicies)

	quiescer.fail = nil
	if err := transaction.Rollback(ctx, stage); err != nil {
		t.Fatalf("retry after quiescence failure: %v", err)
	}
	assertNoMemoryPolicyGeneration(t, policyMaps, snapshot.Generation)
}

func TestFakeTCPPolicyRollbackStopsAtFailedPortBeforePolicies(t *testing.T) {
	snapshot := mustFakeTCPPolicySnapshot(t, 91)
	ctx, transaction, _ := newTestFakeTCPPolicyGenerationTransaction(t, snapshot.Generation)
	policyMaps, trace := newMemoryFakeTCPPolicyMaps()
	stage, err := transaction.Stage(ctx, policyMaps, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	policyMaps.ManagedPorts.(*memoryFakeTCPPolicyMap).failNextDelete =
		errors.New("injected port delete failure")

	err = transaction.Rollback(ctx, stage)
	if err == nil || !strings.Contains(err.Error(), "injected port delete failure") {
		t.Fatalf("port-phase rollback error = %v", err)
	}
	if slices.Contains(trace.deleteAttempts, fakeTCPControlPolicyMapName) {
		t.Fatalf("port failure touched control policies: %v", trace.deleteAttempts)
	}
	assertMemoryPolicyMapMatches(t, policyMaps.ControlPolicies, snapshot.ControlPolicies)

	if err := transaction.Rollback(ctx, stage); err != nil {
		t.Fatalf("retry port rollback: %v", err)
	}
	assertNoMemoryPolicyGeneration(t, policyMaps, snapshot.Generation)
}

func TestFakeTCPPolicyRollbackQuiescesBPFBeforeCursorCompareDeleteWindow(t *testing.T) {
	snapshot := mustFakeTCPPolicySnapshot(t, 91)
	ctx, transaction, quiescer := newTestFakeTCPPolicyGenerationTransaction(t, snapshot.Generation)
	policyMaps, _ := newMemoryFakeTCPPolicyMaps()
	stage, err := transaction.Stage(ctx, policyMaps, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	controlPolicies := policyMaps.ControlPolicies.(*memoryFakeTCPPolicyMap)
	controlPolicies.beforeDelete = func(policyMap *memoryFakeTCPPolicyMap, key any) {
		quiescer.attemptBPFMutation(func() {
			value := policyMap.entries[key].(abi.FakeTCPControlPolicyValue)
			value.VirtualTimeNanos++
			policyMap.entries[key] = value
		})
	}

	if err := transaction.Rollback(ctx, stage); err != nil {
		t.Fatal(err)
	}
	if quiescer.bpfMutationAttempts != len(snapshot.ControlPolicies) ||
		quiescer.bpfMutationBlocked != quiescer.bpfMutationAttempts ||
		quiescer.bpfMutationUnexpectedly != 0 {
		t.Fatalf(
			"compare/delete cursor mutation attempts=%d blocked=%d unexpected=%d",
			quiescer.bpfMutationAttempts,
			quiescer.bpfMutationBlocked,
			quiescer.bpfMutationUnexpectedly,
		)
	}
	assertNoMemoryPolicyGeneration(t, policyMaps, snapshot.Generation)
}

func TestFakeTCPPolicyRollbackAcceptsOnlyPreexistingBPFControlCursorDrift(t *testing.T) {
	snapshot := mustFakeTCPPolicySnapshot(t, 91)
	ctx, transaction, isolation := newTestFakeTCPPolicyGenerationTransaction(t, snapshot.Generation)
	policyMaps, _ := newMemoryFakeTCPPolicyMaps()
	stage, err := transaction.Stage(ctx, policyMaps, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	controlPolicies := policyMaps.ControlPolicies.(*memoryFakeTCPPolicyMap)
	for key, inserted := range snapshot.ControlPolicies {
		drifted := inserted
		drifted.VirtualTimeNanos = 987654321
		controlPolicies.entries[key] = drifted
	}
	if isolation.quiesced {
		t.Fatal("test cursor drift did not precede the quiescence barrier")
	}

	if err := transaction.Rollback(ctx, stage); err != nil {
		t.Fatalf("rollback cursor-only drift after quiescence: %v", err)
	}
	if !isolation.quiesced || len(isolation.calls) == 0 {
		t.Fatal("cursor-only rollback bypassed the quiescence barrier")
	}
	assertNoMemoryPolicyGeneration(t, policyMaps, snapshot.Generation)
}

func TestFakeTCPPolicyRollbackRejectsManagedPortReservedDrift(t *testing.T) {
	snapshot := mustFakeTCPPolicySnapshot(t, 91)
	ctx, transaction, _ := newTestFakeTCPPolicyGenerationTransaction(t, snapshot.Generation)
	policyMaps, _ := newMemoryFakeTCPPolicyMaps()
	stage, err := transaction.Stage(ctx, policyMaps, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	managedPorts := policyMaps.ManagedPorts.(*memoryFakeTCPPolicyMap)
	var changedKey abi.FakeTCPManagedPortKey
	var inserted abi.FakeTCPManagedPortValue
	for key, value := range snapshot.ManagedPorts {
		changedKey, inserted = key, value
		break
	}
	changed := inserted
	changed.Reserved[0] = 1
	managedPorts.entries[changedKey] = changed

	err = transaction.Rollback(ctx, stage)
	if err == nil || !strings.Contains(err.Error(), "refusing rollback because inserted value changed") {
		t.Fatalf("managed-port reserved drift rollback error = %v", err)
	}
	if got := managedPorts.entries[changedKey]; got != changed {
		t.Fatalf("managed-port reserved drift was deleted or overwritten: got %#v want %#v", got, changed)
	}
	if err := transaction.Disarm(ctx, stage); err == nil ||
		!strings.Contains(err.Error(), "incomplete rollback") {
		t.Fatalf("disarm after managed-port reserved drift error = %v", err)
	}

	managedPorts.entries[changedKey] = inserted
	if err := transaction.Rollback(ctx, stage); err != nil {
		t.Fatalf("retry exact managed-port rollback: %v", err)
	}
	assertNoMemoryPolicyGeneration(t, policyMaps, snapshot.Generation)
}

func TestFakeTCPPolicyRollbackRejectsNonCursorControlPolicyDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*abi.FakeTCPControlPolicyValue)
	}{
		{
			name: "generation",
			mutate: func(value *abi.FakeTCPControlPolicyValue) {
				value.Generation++
			},
		},
		{
			name: "interval",
			mutate: func(value *abi.FakeTCPControlPolicyValue) {
				value.IntervalNanos++
			},
		},
		{
			name: "burst",
			mutate: func(value *abi.FakeTCPControlPolicyValue) {
				value.Burst++
			},
		},
		{
			name: "reserved",
			mutate: func(value *abi.FakeTCPControlPolicyValue) {
				value.Reserved++
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := mustFakeTCPPolicySnapshot(t, 91)
			ctx, transaction, isolation := newTestFakeTCPPolicyGenerationTransaction(t, snapshot.Generation)
			policyMaps, _ := newMemoryFakeTCPPolicyMaps()
			stage, err := transaction.Stage(ctx, policyMaps, snapshot)
			if err != nil {
				t.Fatal(err)
			}
			controlPolicies := policyMaps.ControlPolicies.(*memoryFakeTCPPolicyMap)
			var changedKey abi.FakeTCPControlPolicyKey
			var inserted abi.FakeTCPControlPolicyValue
			for key, value := range snapshot.ControlPolicies {
				changedKey, inserted = key, value
				break
			}
			changed := inserted
			changed.VirtualTimeNanos = 123456789
			test.mutate(&changed)
			controlPolicies.entries[changedKey] = changed

			err = transaction.Rollback(ctx, stage)
			if err == nil || !strings.Contains(err.Error(), "refusing rollback because inserted value changed") {
				t.Fatalf("non-cursor policy drift rollback error = %v", err)
			}
			if !isolation.quiesced {
				t.Fatal("control policy comparator ran before quiescence")
			}
			if got := controlPolicies.entries[changedKey]; got != changed {
				t.Fatalf("non-cursor drift was deleted or overwritten: got %#v want %#v", got, changed)
			}
			if err := transaction.Disarm(ctx, stage); err == nil ||
				!strings.Contains(err.Error(), "incomplete rollback") {
				t.Fatalf("disarm after non-cursor drift error = %v", err)
			}

			controlPolicies.entries[changedKey] = inserted
			if err := transaction.Rollback(ctx, stage); err != nil {
				t.Fatalf("retry exact non-cursor policy rollback: %v", err)
			}
			assertNoMemoryPolicyGeneration(t, policyMaps, snapshot.Generation)
		})
	}
}

func TestStageFakeTCPPolicyInternalFailureUsesLatchAndQuiescenceBarrier(t *testing.T) {
	snapshot := mustFakeTCPPolicySnapshot(t, 91)
	ctx, transaction, quiescer := newTestFakeTCPPolicyGenerationTransaction(t, snapshot.Generation)
	policyMaps, trace := newMemoryFakeTCPPolicyMaps()
	trace.failUpdateAt = len(snapshot.ControlPolicies) + len(snapshot.ManagedPorts) +
		len(snapshot.ManagedInterfaces)
	quiescer.fail = errors.New("injected internal rollback quiescence failure")

	stage, err := transaction.Stage(ctx, policyMaps, snapshot)
	if stage == nil || err == nil ||
		!strings.Contains(err.Error(), "injected internal rollback quiescence failure") {
		t.Fatalf("internal stage failure handle=%v error=%v", stage, err)
	}
	if len(policyMaps.ManagedInterfaces.(*memoryFakeTCPPolicyMap).entries) != 0 {
		t.Fatal("internal rollback left its partial interface latch reachable")
	}
	if slices.Contains(trace.deleteAttempts, fakeTCPManagedPortMapName) ||
		slices.Contains(trace.deleteAttempts, fakeTCPControlPolicyMapName) {
		t.Fatalf("internal quiescence failure touched dependencies: %v", trace.deleteAttempts)
	}
	assertMemoryPolicyMapMatches(t, policyMaps.ManagedPorts, snapshot.ManagedPorts)
	assertMemoryPolicyMapMatches(t, policyMaps.ControlPolicies, snapshot.ControlPolicies)

	quiescer.fail = nil
	if err := transaction.Rollback(ctx, stage); err != nil {
		t.Fatalf("retry internal rollback: %v", err)
	}
	assertNoMemoryPolicyGeneration(t, policyMaps, snapshot.Generation)
}

func TestFakeTCPPolicyGenerationTransactionRequiresHeldLeaseAndBarrier(t *testing.T) {
	root := t.TempDir()
	ctx := lockfile.WithLifecyclePathsForTest(
		t.Context(),
		filepath.Join(root, "daemon.lease"),
		filepath.Join(root, "maintenance.gate"),
	)
	isolation := &memoryFakeTCPPolicyQuiescer{generation: 91, inactive: true}
	if transaction, err := newFakeTCPPolicyGenerationTransaction(ctx, 91, nil, isolation); transaction != nil || !errors.Is(err, errFakeTCPPolicyGenerationLeaseRequired) {
		t.Fatalf("transaction without lease = %v, error = %v", transaction, err)
	}
	lease, err := lockfile.AcquireLifecycle(
		ctx,
		lockfile.LifecycleOwner{PID: os.Getpid(), Action: "test-faketcp-required-lease"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if transaction, err := newFakeTCPPolicyGenerationTransaction(ctx, 91, lease, nil); transaction != nil || !errors.Is(err, errFakeTCPPolicyGenerationLeaseRequired) {
		t.Fatalf("transaction without isolation backend = %v, error = %v", transaction, err)
	}
	var typedNilIsolation *memoryFakeTCPPolicyQuiescer
	if transaction, err := newFakeTCPPolicyGenerationTransaction(ctx, 91, lease, typedNilIsolation); transaction != nil || !errors.Is(err, errFakeTCPPolicyGenerationLeaseRequired) {
		t.Fatalf("transaction with typed-nil isolation backend = %v, error = %v", transaction, err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if transaction, err := newFakeTCPPolicyGenerationTransaction(ctx, 91, lease, isolation); transaction != nil || !errors.Is(err, errFakeTCPPolicyGenerationLeaseRequired) {
		t.Fatalf("transaction with closed lease = %v, error = %v", transaction, err)
	}
}

func TestFakeTCPPolicyGenerationTransactionRetainsLeaseUntilTerminalStage(t *testing.T) {
	snapshot := mustFakeTCPPolicySnapshot(t, 91)
	ctx, transaction, _ := newTestFakeTCPPolicyGenerationTransaction(t, snapshot.Generation)
	policyMaps, _ := newMemoryFakeTCPPolicyMaps()
	stage, err := transaction.Stage(ctx, policyMaps, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if contender, err := lockfile.AcquireLifecycle(
		ctx,
		lockfile.LifecycleOwner{PID: os.Getpid(), Action: "test-faketcp-contender"},
	); !errors.Is(err, lockfile.ErrLifecycleLeaseHeld) {
		if contender != nil {
			_ = contender.Close()
		}
		t.Fatalf("generation transaction did not retain lifecycle lease: %v", err)
	}
	if err := transaction.Close(); err == nil || !strings.Contains(err.Error(), "live policy stage") {
		t.Fatalf("close with live stage error = %v", err)
	}
	if err := transaction.Rollback(ctx, stage); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Close(); err != nil {
		t.Fatal(err)
	}
	reacquired, err := lockfile.AcquireLifecycle(
		ctx,
		lockfile.LifecycleOwner{PID: os.Getpid(), Action: "test-faketcp-after-terminal-stage"},
	)
	if err != nil {
		t.Fatalf("lifecycle lease was not released after terminal stage: %v", err)
	}
	if err := reacquired.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestFakeTCPPolicyStageRejectsWrongGenerationTransactionAndOwner(t *testing.T) {
	snapshot := mustFakeTCPPolicySnapshot(t, 91)
	wrongCtx, wrongTransaction, _ := newTestFakeTCPPolicyGenerationTransaction(t, 92)
	policyMaps, trace := newMemoryFakeTCPPolicyMaps()
	stage, err := wrongTransaction.Stage(wrongCtx, policyMaps, snapshot)
	if stage != nil || err == nil || !strings.Contains(err.Error(), "does not match transaction") {
		t.Fatalf("wrong-generation stage handle=%v error=%v", stage, err)
	}
	if len(trace.updateAttempts) != 0 || len(trace.deleteAttempts) != 0 {
		t.Fatalf("wrong-generation transaction mutated maps: %#v", trace)
	}

	ctx, transaction, _ := newTestFakeTCPPolicyGenerationTransaction(t, snapshot.Generation)
	stage, err = transaction.Stage(ctx, policyMaps, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	deleteAttempts := len(trace.deleteAttempts)
	if err := wrongTransaction.Rollback(wrongCtx, stage); err == nil ||
		!strings.Contains(err.Error(), "not owned") {
		t.Fatalf("wrong-owner rollback error = %v", err)
	}
	if len(trace.deleteAttempts) != deleteAttempts {
		t.Fatalf("wrong-owner rollback mutated maps: %v", trace.deleteAttempts)
	}
	if err := transaction.Close(); err == nil || !strings.Contains(err.Error(), "live policy stage") {
		t.Fatalf("close with live stage error = %v", err)
	}
	if err := transaction.Rollback(ctx, stage); err != nil {
		t.Fatal(err)
	}
}

func TestStageFakeTCPPolicyGenerationRejectsExistingKeyWithoutResettingCursor(t *testing.T) {
	tests := []struct {
		name string
		seed func(fakeTCPPolicyMaps, *fakeTCPPolicySnapshot) (*memoryFakeTCPPolicyMap, any, any)
	}{
		{
			name: "control policy with live cursor",
			seed: func(policyMaps fakeTCPPolicyMaps, snapshot *fakeTCPPolicySnapshot) (*memoryFakeTCPPolicyMap, any, any) {
				var key abi.FakeTCPControlPolicyKey
				for key = range snapshot.ControlPolicies {
					break
				}
				value := snapshot.ControlPolicies[key]
				value.VirtualTimeNanos = 987654321
				return policyMaps.ControlPolicies.(*memoryFakeTCPPolicyMap), key, value
			},
		},
		{
			name: "managed port",
			seed: func(policyMaps fakeTCPPolicyMaps, snapshot *fakeTCPPolicySnapshot) (*memoryFakeTCPPolicyMap, any, any) {
				var key abi.FakeTCPManagedPortKey
				for key = range snapshot.ManagedPorts {
					break
				}
				return policyMaps.ManagedPorts.(*memoryFakeTCPPolicyMap), key, snapshot.ManagedPorts[key]
			},
		},
		{
			name: "managed interface",
			seed: func(policyMaps fakeTCPPolicyMaps, snapshot *fakeTCPPolicySnapshot) (*memoryFakeTCPPolicyMap, any, any) {
				var key abi.FakeTCPManagedIfKey
				for key = range snapshot.ManagedInterfaces {
					break
				}
				return policyMaps.ManagedInterfaces.(*memoryFakeTCPPolicyMap), key, snapshot.ManagedInterfaces[key]
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := mustFakeTCPPolicySnapshot(t, 91)
			ctx, transaction, _ := newTestFakeTCPPolicyGenerationTransaction(t, snapshot.Generation)
			policyMaps, trace := newMemoryFakeTCPPolicyMaps()
			memoryMap, key, existing := test.seed(policyMaps, snapshot)
			memoryMap.entries[key] = existing

			stage, err := transaction.Stage(ctx, policyMaps, snapshot)
			if stage != nil {
				t.Fatal("existing-key stage returned a rollback handle")
			}
			if err == nil || !strings.Contains(err.Error(), "exact key already exists") {
				t.Fatalf("existing-key error = %v", err)
			}
			if len(trace.updateAttempts) != 0 || len(trace.deletes) != 0 {
				t.Fatalf("existing-key preflight mutated maps: updates=%v deletes=%v", trace.updateAttempts, trace.deletes)
			}
			if got := memoryMap.entries[key]; got != existing {
				t.Fatalf("existing value changed: got %#v want %#v", got, existing)
			}
		})
	}
}

func TestStageFakeTCPPolicyGenerationReadbackMismatchRollsBack(t *testing.T) {
	snapshot := mustFakeTCPPolicySnapshot(t, 91)
	ctx, transaction, _ := newTestFakeTCPPolicyGenerationTransaction(t, snapshot.Generation)
	policyMaps, _ := newMemoryFakeTCPPolicyMaps()
	policyMaps.ManagedPorts.(*memoryFakeTCPPolicyMap).corruptNextSuccessfulReadback = true
	stage, err := transaction.Stage(ctx, policyMaps, snapshot)
	if stage != nil {
		t.Fatal("readback mismatch returned a rollback handle")
	}
	if err == nil || !strings.Contains(err.Error(), "read back value differs") {
		t.Fatalf("readback mismatch error = %v", err)
	}
	assertNoMemoryPolicyGeneration(t, policyMaps, snapshot.Generation)
}

func TestStageFakeTCPPolicyGenerationNeverDeletesChangedRollbackValue(t *testing.T) {
	snapshot := mustFakeTCPPolicySnapshot(t, 91)
	ctx, transaction, _ := newTestFakeTCPPolicyGenerationTransaction(t, snapshot.Generation)
	policyMaps, _ := newMemoryFakeTCPPolicyMaps()
	managedPorts := policyMaps.ManagedPorts.(*memoryFakeTCPPolicyMap)
	managedPorts.changeFirstInsertedValue = func(value any) any {
		changed := value.(abi.FakeTCPManagedPortValue)
		changed.WGID++
		return changed
	}
	stage, err := transaction.Stage(ctx, policyMaps, snapshot)
	if stage == nil {
		t.Fatal("incomplete internal rollback did not return a retryable rollback handle")
	}
	if err == nil || !strings.Contains(err.Error(), "rollback incomplete") ||
		!strings.Contains(err.Error(), "refusing rollback because inserted value changed") {
		t.Fatalf("changed rollback value error = %v", err)
	}
	if len(managedPorts.entries) != 1 {
		t.Fatalf("changed value was deleted or unexpected residue remains: %#v", managedPorts.entries)
	}
	var changedKey abi.FakeTCPManagedPortKey
	var wantValue abi.FakeTCPManagedPortValue
	for key, value := range managedPorts.entries {
		changedKey = key.(abi.FakeTCPManagedPortKey)
		wantValue = snapshot.ManagedPorts[changedKey]
		if value == wantValue {
			t.Fatalf("test did not change inserted value: %#v", value)
		}
	}
	if len(policyMaps.ManagedInterfaces.(*memoryFakeTCPPolicyMap).entries) != 0 {
		t.Fatal("internal rollback unexpectedly retained an interface latch")
	}
	assertMemoryPolicyMapMatches(t, policyMaps.ControlPolicies, snapshot.ControlPolicies)
	if err := transaction.Disarm(ctx, stage); err == nil || !strings.Contains(err.Error(), "incomplete rollback") {
		t.Fatalf("incomplete stage disarm error = %v", err)
	}
	managedPorts.entries[changedKey] = wantValue
	if err := transaction.Rollback(ctx, stage); err != nil {
		t.Fatalf("retry incomplete stage rollback: %v", err)
	}
	assertNoMemoryPolicyGeneration(t, policyMaps, snapshot.Generation)
}

func TestStageFakeTCPPolicyGenerationRejectsMalformedSnapshotBeforeWrites(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*fakeTCPPolicySnapshot)
		wantErr string
	}{
		{
			name: "nonzero cursor",
			mutate: func(snapshot *fakeTCPPolicySnapshot) {
				for key, value := range snapshot.ControlPolicies {
					value.VirtualTimeNanos = 1
					snapshot.ControlPolicies[key] = value
					break
				}
			},
			wantErr: "nonzero BPF-owned virtual time",
		},
		{
			name: "nonzero control reserved",
			mutate: func(snapshot *fakeTCPPolicySnapshot) {
				for key, value := range snapshot.ControlPolicies {
					value.Reserved = 1
					snapshot.ControlPolicies[key] = value
					break
				}
			},
			wantErr: "nonzero reserved field",
		},
		{
			name: "nonzero managed port reserved",
			mutate: func(snapshot *fakeTCPPolicySnapshot) {
				for key, value := range snapshot.ManagedPorts {
					value.Reserved[2] = 1
					snapshot.ManagedPorts[key] = value
					break
				}
			},
			wantErr: "nonzero reserved bytes",
		},
		{
			name: "missing interface latch",
			mutate: func(snapshot *fakeTCPPolicySnapshot) {
				for key := range snapshot.ManagedInterfaces {
					delete(snapshot.ManagedInterfaces, key)
					break
				}
			},
			wantErr: "has no interface latch",
		},
		{
			name: "missing control policy",
			mutate: func(snapshot *fakeTCPPolicySnapshot) {
				for key := range snapshot.ControlPolicies {
					delete(snapshot.ControlPolicies, key)
					break
				}
			},
			wantErr: "has no WireGuard control policy",
		},
		{
			name: "wrong generation",
			mutate: func(snapshot *fakeTCPPolicySnapshot) {
				for key, value := range snapshot.ManagedPorts {
					value.Generation++
					snapshot.ManagedPorts[key] = value
					break
				}
			},
			wantErr: "generation does not match",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := mustFakeTCPPolicySnapshot(t, 91)
			ctx, transaction, _ := newTestFakeTCPPolicyGenerationTransaction(t, snapshot.Generation)
			test.mutate(snapshot)
			policyMaps, trace := newMemoryFakeTCPPolicyMaps()
			stage, err := transaction.Stage(ctx, policyMaps, snapshot)
			if stage != nil {
				t.Fatal("malformed snapshot returned a rollback handle")
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("malformed snapshot error = %v, want %q", err, test.wantErr)
			}
			if len(trace.updateAttempts) != 0 || len(trace.deletes) != 0 {
				t.Fatalf("malformed snapshot mutated maps: %#v", trace)
			}
		})
	}
}

func TestFakeTCPPolicyPrimitiveDoesNotClaimActivationCapability(t *testing.T) {
	if fakeTCPImplementedCapabilities&fakeTCPCapabilityManagedPolicyPopulation != 0 {
		t.Fatal("policy staging primitive claimed managed population before loader/XDP transaction integration")
	}
	if !strings.Contains(strings.Join(missingFakeTCPCapabilities(), "\n"),
		"atomic managed-interface/port policy population") {
		t.Fatal("activation gate stopped reporting managed policy population as incomplete")
	}
}

func TestFakeTCPPolicyPerGenerationLimitsMatchTwoBankELFMaps(t *testing.T) {
	want := map[string]uint32{
		fakeTCPControlPolicyMapName: uint32(fakeTCPControlPoliciesPerGeneration * 2),
		fakeTCPManagedPortMapName:   uint32(fakeTCPManagedPortsPerGeneration * 2),
		fakeTCPManagedIfMapName:     uint32(fakeTCPManagedInterfacesPerGeneration * 2),
	}
	for _, descriptor := range experimentalMapDescriptors() {
		capacity, relevant := want[descriptor.name]
		if !relevant {
			continue
		}
		if descriptor.maxEntries != capacity {
			t.Fatalf("%s entries = %d, want two policy banks (%d)",
				descriptor.name, descriptor.maxEntries, capacity)
		}
		delete(want, descriptor.name)
	}
	if len(want) != 0 {
		t.Fatalf("experimental manifest is missing policy maps: %v", want)
	}
}

type memoryFakeTCPPolicyQuiescer struct {
	generation              uint64
	inactiveCalls           []uint64
	failInactive            error
	inactive                bool
	calls                   []uint64
	fail                    error
	quiesced                bool
	events                  *[]string
	bpfMutationAttempts     int
	bpfMutationBlocked      int
	bpfMutationUnexpectedly int
}

func (quiescer *memoryFakeTCPPolicyQuiescer) AssertInactive(
	ctx context.Context,
	generation uint64,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	quiescer.inactiveCalls = append(quiescer.inactiveCalls, generation)
	if quiescer.events != nil {
		*quiescer.events = append(*quiescer.events, "assert-inactive")
	}
	if generation != quiescer.generation {
		return fmt.Errorf("inactive generation %d, want %d", generation, quiescer.generation)
	}
	if quiescer.failInactive != nil {
		return quiescer.failInactive
	}
	if !quiescer.inactive {
		return errors.New("target generation is active")
	}
	return nil
}

func (quiescer *memoryFakeTCPPolicyQuiescer) Quiesce(
	ctx context.Context,
	generation uint64,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	quiescer.calls = append(quiescer.calls, generation)
	if quiescer.events != nil {
		*quiescer.events = append(*quiescer.events, "quiesce")
	}
	if generation != quiescer.generation {
		return fmt.Errorf("quiesce generation %d, want %d", generation, quiescer.generation)
	}
	if quiescer.fail != nil {
		return quiescer.fail
	}
	quiescer.quiesced = true
	return nil
}

func (quiescer *memoryFakeTCPPolicyQuiescer) attemptBPFMutation(mutate func()) {
	quiescer.bpfMutationAttempts++
	if quiescer.quiesced {
		quiescer.bpfMutationBlocked++
		return
	}
	quiescer.bpfMutationUnexpectedly++
	mutate()
}

func newTestFakeTCPPolicyGenerationTransaction(
	t *testing.T,
	generation uint64,
) (context.Context, *fakeTCPPolicyGenerationTransaction, *memoryFakeTCPPolicyQuiescer) {
	t.Helper()
	root := t.TempDir()
	ctx := lockfile.WithLifecyclePathsForTest(
		t.Context(),
		filepath.Join(root, "daemon.lease"),
		filepath.Join(root, "maintenance.gate"),
	)
	lease, err := lockfile.AcquireLifecycle(
		ctx,
		lockfile.LifecycleOwner{PID: os.Getpid(), Action: "test-faketcp-policy-generation"},
	)
	if err != nil {
		t.Fatal(err)
	}
	quiescer := &memoryFakeTCPPolicyQuiescer{generation: generation, inactive: true}
	transaction, err := newFakeTCPPolicyGenerationTransaction(
		ctx,
		generation,
		lease,
		quiescer,
	)
	if err != nil {
		_ = lease.Close()
		t.Fatal(err)
	}
	// The transaction's retained descriptor, rather than the caller's handle,
	// must keep the global mutation lease held until rollback or disarm.
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := transaction.Close(); err != nil {
			t.Errorf("close FakeTCP policy generation transaction: %v", err)
		}
	})
	return ctx, transaction, quiescer
}

type memoryFakeTCPPolicyTrace struct {
	events            []string
	updateAttempts    []string
	successfulUpdates []string
	updateFlags       []ebpf.MapUpdateFlags
	deletes           []string
	deleteAttempts    []string
	failUpdateAt      int
}

type memoryFakeTCPPolicyMap struct {
	name                          string
	entries                       map[any]any
	trace                         *memoryFakeTCPPolicyTrace
	corruptNextSuccessfulReadback bool
	changeFirstInsertedValue      func(any) any
	failNextLookup                error
	failNextDelete                error
	beforeDelete                  func(*memoryFakeTCPPolicyMap, any)
}

func (m *memoryFakeTCPPolicyMap) Lookup(key, valueOut any) error {
	m.trace.events = append(m.trace.events, "lookup:"+m.name)
	if m.failNextLookup != nil {
		err := m.failNextLookup
		m.failNextLookup = nil
		return err
	}
	value, exists := m.entries[key]
	if !exists {
		return ebpf.ErrKeyNotExist
	}
	if m.corruptNextSuccessfulReadback {
		m.corruptNextSuccessfulReadback = false
		return assignMemoryPolicyValue(valueOut, reflect.Zero(reflect.TypeOf(value)).Interface())
	}
	return assignMemoryPolicyValue(valueOut, value)
}

func (m *memoryFakeTCPPolicyMap) Update(key, value any, flags ebpf.MapUpdateFlags) error {
	m.trace.events = append(m.trace.events, "update:"+m.name)
	m.trace.updateAttempts = append(m.trace.updateAttempts, m.name)
	m.trace.updateFlags = append(m.trace.updateFlags, flags)
	if m.trace.failUpdateAt != 0 && len(m.trace.updateAttempts) == m.trace.failUpdateAt {
		return errors.New("injected update failure")
	}
	if flags != ebpf.UpdateNoExist {
		return fmt.Errorf("unexpected update flags %v", flags)
	}
	if _, exists := m.entries[key]; exists {
		return ebpf.ErrKeyExist
	}
	stored := value
	if m.changeFirstInsertedValue != nil {
		stored = m.changeFirstInsertedValue(value)
		m.changeFirstInsertedValue = nil
	}
	m.entries[key] = stored
	m.trace.successfulUpdates = append(m.trace.successfulUpdates, m.name)
	return nil
}

func (m *memoryFakeTCPPolicyMap) Delete(key any) error {
	m.trace.events = append(m.trace.events, "delete:"+m.name)
	m.trace.deleteAttempts = append(m.trace.deleteAttempts, m.name)
	if m.failNextDelete != nil {
		err := m.failNextDelete
		m.failNextDelete = nil
		return err
	}
	if _, exists := m.entries[key]; !exists {
		return ebpf.ErrKeyNotExist
	}
	if m.beforeDelete != nil {
		m.beforeDelete(m, key)
	}
	delete(m.entries, key)
	m.trace.deletes = append(m.trace.deletes, m.name)
	return nil
}

func assignMemoryPolicyValue(destination, value any) error {
	target := reflect.ValueOf(destination)
	if target.Kind() != reflect.Pointer || target.IsNil() {
		return errors.New("lookup destination must be a non-nil pointer")
	}
	source := reflect.ValueOf(value)
	if !source.Type().AssignableTo(target.Elem().Type()) {
		return fmt.Errorf("lookup value type %s is not assignable to %s", source.Type(), target.Elem().Type())
	}
	target.Elem().Set(source)
	return nil
}

func newMemoryFakeTCPPolicyMaps() (fakeTCPPolicyMaps, *memoryFakeTCPPolicyTrace) {
	trace := &memoryFakeTCPPolicyTrace{}
	newMap := func(name string) *memoryFakeTCPPolicyMap {
		return &memoryFakeTCPPolicyMap{name: name, entries: make(map[any]any), trace: trace}
	}
	return fakeTCPPolicyMaps{
		ControlPolicies:   newMap(fakeTCPControlPolicyMapName),
		ManagedPorts:      newMap(fakeTCPManagedPortMapName),
		ManagedInterfaces: newMap(fakeTCPManagedIfMapName),
	}, trace
}

type oldFakeTCPPolicyEntries struct {
	control    map[any]any
	ports      map[any]any
	interfaces map[any]any
}

func seedOldFakeTCPPolicyGeneration(
	policyMaps fakeTCPPolicyMaps,
	generation uint64,
) oldFakeTCPPolicyEntries {
	controlMap := policyMaps.ControlPolicies.(*memoryFakeTCPPolicyMap)
	portMap := policyMaps.ManagedPorts.(*memoryFakeTCPPolicyMap)
	interfaceMap := policyMaps.ManagedInterfaces.(*memoryFakeTCPPolicyMap)
	controlMap.entries[abi.FakeTCPControlPolicyKey{Generation: generation, WGID: 44}] =
		abi.FakeTCPControlPolicyValue{
			Generation: generation, VirtualTimeNanos: 1234,
			IntervalNanos: uint64(fakeTCPControlMinInterval), Burst: 1,
		}
	portMap.entries[abi.FakeTCPManagedPortKey{
		Generation: generation, UnderlayIndex: 55, DestinationPort: 32000,
	}] = abi.FakeTCPManagedPortValue{Generation: generation, WGID: 44, Action: abi.ActionRewrite}
	interfaceMap.entries[abi.FakeTCPManagedIfKey{
		Generation: generation, UnderlayIndex: 55,
	}] = abi.FakeTCPManagedIfValue{Generation: generation}
	return oldFakeTCPPolicyEntries{
		control:    maps.Clone(controlMap.entries),
		ports:      maps.Clone(portMap.entries),
		interfaces: maps.Clone(interfaceMap.entries),
	}
}

func assertOldFakeTCPPolicyGeneration(
	t *testing.T,
	policyMaps fakeTCPPolicyMaps,
	want oldFakeTCPPolicyEntries,
) {
	t.Helper()
	if got := policyMaps.ControlPolicies.(*memoryFakeTCPPolicyMap).entries; !reflect.DeepEqual(got, want.control) {
		t.Fatalf("old control generation changed: got %#v want %#v", got, want.control)
	}
	if got := policyMaps.ManagedPorts.(*memoryFakeTCPPolicyMap).entries; !reflect.DeepEqual(got, want.ports) {
		t.Fatalf("old port generation changed: got %#v want %#v", got, want.ports)
	}
	if got := policyMaps.ManagedInterfaces.(*memoryFakeTCPPolicyMap).entries; !reflect.DeepEqual(got, want.interfaces) {
		t.Fatalf("old interface generation changed: got %#v want %#v", got, want.interfaces)
	}
}

func assertNoMemoryPolicyGeneration(t *testing.T, policyMaps fakeTCPPolicyMaps, generation uint64) {
	t.Helper()
	for _, memoryMap := range []*memoryFakeTCPPolicyMap{
		policyMaps.ControlPolicies.(*memoryFakeTCPPolicyMap),
		policyMaps.ManagedPorts.(*memoryFakeTCPPolicyMap),
		policyMaps.ManagedInterfaces.(*memoryFakeTCPPolicyMap),
	} {
		for key := range memoryMap.entries {
			var keyGeneration uint64
			switch typed := key.(type) {
			case abi.FakeTCPControlPolicyKey:
				keyGeneration = typed.Generation
			case abi.FakeTCPManagedPortKey:
				keyGeneration = typed.Generation
			case abi.FakeTCPManagedIfKey:
				keyGeneration = typed.Generation
			default:
				t.Fatalf("unexpected key type %T", key)
			}
			if keyGeneration == generation {
				t.Fatalf("%s retained failed target-generation key %#v", memoryMap.name, key)
			}
		}
	}
}

func assertMemoryPolicyMapMatches[K comparable, V comparable](
	t *testing.T,
	policyMap fakeTCPPolicyMap,
	want map[K]V,
) {
	t.Helper()
	entries := policyMap.(*memoryFakeTCPPolicyMap).entries
	if len(entries) != len(want) {
		t.Fatalf("map entries = %d, want %d", len(entries), len(want))
	}
	for key, value := range want {
		if got, exists := entries[key]; !exists || got != value {
			t.Fatalf("map key %#v = %#v, want %#v", key, got, value)
		}
	}
}

func mustFakeTCPPolicySnapshot(t *testing.T, generation uint64) *fakeTCPPolicySnapshot {
	t.Helper()
	snapshot, err := buildFakeTCPPolicySnapshot(fakeTCPPolicyTestState(), generation)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}
