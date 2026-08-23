package reconcile

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/attachstate"
	"github.com/syx0310/wg-mix-ebpf/internal/control"
	"github.com/syx0310/wg-mix-ebpf/internal/dataplane"
	"github.com/syx0310/wg-mix-ebpf/internal/faketcp"
	"github.com/syx0310/wg-mix-ebpf/internal/guard"
	"github.com/syx0310/wg-mix-ebpf/internal/runtime"
)

func TestReloadResumesFreshBarrierWhenInitialApplyFailsObservedAbsent(t *testing.T) {
	applyErr := errors.New("initial nft mutation failed after removing the table")
	loader := newTxnTestLoader(dataplane.NewStartupGuardLease())
	guardExec := &scriptedGuardExecutor{
		observeOutcome: guard.Outcome{Observation: guard.ObservationAbsent},
		applyOutcomes: []guard.Outcome{{
			Observation: guard.ObservationAbsent,
			Mutated:     true,
		}},
		applyErrors: []error{applyErr},
	}

	_, err := reloadUnlocked(t.Context(), successfulReloadOptions(t, loader, guardExec, nil))
	if !errors.Is(err, applyErr) {
		t.Fatalf("reload error = %v", err)
	}
	if loader.quiesceCalls != 1 || loader.resumeCalls != 1 || loader.applyCalls != 0 {
		t.Fatalf("calls: quiesce=%d resume=%d apply=%d", loader.quiesceCalls, loader.resumeCalls, loader.applyCalls)
	}
	if guardExec.cleanupCalls != 0 || loader.pause.Phase != faketcp.StartupGuardPausePhaseOpen {
		t.Fatalf("unexpected cleanup/pause: cleanup=%d pause=%#v", guardExec.cleanupCalls, loader.pause)
	}
}

func TestReloadResumesFreshBarrierWhenObservedExpansionApplyFailsObservedAbsent(t *testing.T) {
	const runtimeMark = uint32(0x10000003)
	expandErr := errors.New("observed-fwmark replacement failed after removing the table")
	loader := newTxnTestLoader(dataplane.NewStartupGuardLease())
	guardExec := &scriptedGuardExecutor{
		observeOutcome: guard.Outcome{Observation: guard.ObservationAbsent},
		applyOutcomes: []guard.Outcome{
			{Observation: guard.ObservationActive, Mutated: true},
			{Observation: guard.ObservationAbsent, Mutated: true},
		},
		applyErrors: []error{nil, expandErr},
	}
	opts := successfulReloadOptions(t, loader, guardExec, nil)
	appendConfig(t, opts.ConfigPath, "\nruntime:\n  strict_runtime_fwmark: false\n")
	opts.deps.runtimeProvider = runtime.StaticProvider{Devices: map[string]*runtime.Device{
		"wg0": {
			Name: "wg0", ListenPort: 31001,
			FirewallMark: runtimeMark, Up: true,
		},
	}}

	_, err := reloadUnlocked(t.Context(), opts)
	if !errors.Is(err, expandErr) {
		t.Fatalf("reload error = %v", err)
	}
	if guardExec.applyCalls != 2 || guardExec.cleanupCalls != 0 ||
		loader.resumeCalls != 1 || loader.applyCalls != 0 ||
		loader.pause.Phase != faketcp.StartupGuardPausePhaseOpen {
		t.Fatalf("guard=%#v loader=%#v", guardExec, loader)
	}
}

func TestStartupGuardTxnResumesFreshBarrierWhenRuntimeExpansionFailsObservedAbsent(t *testing.T) {
	runtimeExpandErr := errors.New("runtime-fwmark replacement failed after removing the table")
	loader := newTxnTestLoader(dataplane.NewStartupGuardLease())
	lease, err := loader.QuiesceForStartupGuard(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	txn := newStartupGuardTxn(StartupGuardStatus{KernelState: StartupGuardKernelAbsent})
	if err := txn.recordLease(loader, lease); err != nil {
		t.Fatal(err)
	}
	executor := &scriptedGuardExecutor{
		applyOutcomes: []guard.Outcome{
			{Observation: guard.ObservationActive, Mutated: true},
			{Observation: guard.ObservationActive, Mutated: true},
			{Observation: guard.ObservationAbsent, Mutated: true},
		},
		applyErrors: []error{nil, nil, runtimeExpandErr},
	}
	for index := 0; index < 3; index++ {
		_, applyErr := txn.apply(t.Context(), executor, guard.NftPlan{})
		if index < 2 && applyErr != nil {
			t.Fatalf("apply %d: %v", index, applyErr)
		}
		if index == 2 && !errors.Is(applyErr, runtimeExpandErr) {
			t.Fatalf("runtime expansion error = %v", applyErr)
		}
	}
	if !txn.barrierFresh || !txn.shouldResumeAfterFailure() {
		t.Fatalf("txn did not retain fresh lease across observations: %#v", txn)
	}
	recoveryCtx, cancel := startupGuardFinalizationContext(t.Context())
	defer cancel()
	if err := txn.resume(recoveryCtx); err != nil {
		t.Fatal(err)
	}
	if loader.resumeCalls != 1 || loader.pause.Phase != faketcp.StartupGuardPausePhaseOpen {
		t.Fatalf("runtime expansion failure was not recovered: %#v", loader)
	}
}

func TestReloadBorrowedBarrierDoesNotResumeOnPreDataplaneAbsentFailure(t *testing.T) {
	dataplaneErr := errors.New("first dataplane mutation failed")
	applyErr := errors.New("retry nft apply failed after proving absence")
	fresh := dataplane.NewStartupGuardLease()
	loader := newTxnTestLoader(fresh, borrowTxnTestLease(fresh))
	loader.applyErrors = []error{dataplaneErr}
	guardExec := &scriptedGuardExecutor{
		observeOutcome: guard.Outcome{Observation: guard.ObservationActive},
		applyOutcomes: []guard.Outcome{
			{Observation: guard.ObservationActive, Mutated: true},
			{Observation: guard.ObservationAbsent, Mutated: true},
		},
		applyErrors: []error{nil, applyErr},
	}
	opts := successfulReloadOptions(t, loader, guardExec, nil)

	if _, err := reloadUnlocked(t.Context(), opts); !errors.Is(err, dataplaneErr) {
		t.Fatalf("first reload error = %v", err)
	}
	if loader.resumeCalls != 0 || loader.pause.Phase != faketcp.StartupGuardPausePhaseHeld {
		t.Fatalf("first failure did not retain barrier: %#v", loader)
	}
	_, err := reloadUnlocked(t.Context(), opts)
	if !errors.Is(err, applyErr) {
		t.Fatalf("retry reload error = %v", err)
	}
	if guardExec.applyCalls != 2 || loader.applyCalls != 1 || loader.resumeCalls != 0 ||
		guardExec.cleanupCalls != 0 || loader.pause.Phase != faketcp.StartupGuardPausePhaseHeld {
		t.Fatalf("borrowed pre-dataplane failure started prior runtime: guard=%#v loader=%#v", guardExec, loader)
	}
}

func TestReloadKeepsFreshBarrierWhenApplyFailureObservationUnknown(t *testing.T) {
	applyErr := errors.New("nft apply postcondition is unknown")
	loader := newTxnTestLoader(dataplane.NewStartupGuardLease())
	guardExec := &scriptedGuardExecutor{
		observeOutcome: guard.Outcome{Observation: guard.ObservationAbsent},
		applyOutcomes:  []guard.Outcome{{Observation: guard.ObservationUnknown, Mutated: true}},
		applyErrors:    []error{applyErr},
	}

	_, err := reloadUnlocked(t.Context(), successfulReloadOptions(t, loader, guardExec, nil))
	if !errors.Is(err, applyErr) {
		t.Fatalf("reload error = %v", err)
	}
	if loader.resumeCalls != 0 || guardExec.cleanupCalls != 0 ||
		loader.pause.Phase != faketcp.StartupGuardPausePhaseHeld {
		t.Fatalf("unknown guard state was opened: guard=%#v loader=%#v", guardExec, loader)
	}
}

func TestReloadRollsBackFreshGuardWhenApplyFailureObservationActive(t *testing.T) {
	applyErr := errors.New("nft apply returned an active postcondition with an error")
	loader := newTxnTestLoader(dataplane.NewStartupGuardLease())
	guardExec := &scriptedGuardExecutor{
		observeOutcome: guard.Outcome{Observation: guard.ObservationAbsent},
		applyOutcomes:  []guard.Outcome{{Observation: guard.ObservationActive, Mutated: true}},
		applyErrors:    []error{applyErr},
		cleanupOutcome: guard.Outcome{Observation: guard.ObservationAbsent, Mutated: true},
	}

	_, err := reloadUnlocked(t.Context(), successfulReloadOptions(t, loader, guardExec, nil))
	if !errors.Is(err, applyErr) {
		t.Fatalf("reload error = %v", err)
	}
	if loader.resumeCalls != 1 || guardExec.cleanupCalls != 1 ||
		loader.pause.Phase != faketcp.StartupGuardPausePhaseOpen {
		t.Fatalf("transaction-created active guard was not rolled back: guard=%#v loader=%#v", guardExec, loader)
	}
}

func TestReloadKeepsFreshBarrierWhenActiveObservationIsUnchangedByFailedApply(t *testing.T) {
	applyErr := errors.New("replacement preflight failed without mutation")
	loader := newTxnTestLoader(dataplane.NewStartupGuardLease())
	guardExec := &scriptedGuardExecutor{
		observeOutcome: guard.Outcome{Observation: guard.ObservationActive},
		applyOutcomes:  []guard.Outcome{{Observation: guard.ObservationUnchanged}},
		applyErrors:    []error{applyErr},
	}

	_, err := reloadUnlocked(t.Context(), successfulReloadOptions(t, loader, guardExec, nil))
	if !errors.Is(err, applyErr) {
		t.Fatalf("reload error = %v", err)
	}
	if loader.resumeCalls != 0 || guardExec.cleanupCalls != 0 ||
		loader.pause.Phase != faketcp.StartupGuardPausePhaseHeld {
		t.Fatalf("unchanged outcome erased active observation: guard=%#v loader=%#v", guardExec, loader)
	}
}

func TestReloadKeepsFreshBarrierForPreexistingActiveGuardAfterApplyError(t *testing.T) {
	applyErr := errors.New("replacement failed but existing guard remains active")
	loader := newTxnTestLoader(dataplane.NewStartupGuardLease())
	guardExec := &scriptedGuardExecutor{
		observeOutcome: guard.Outcome{Observation: guard.ObservationActive},
		applyOutcomes:  []guard.Outcome{{Observation: guard.ObservationActive, Mutated: true}},
		applyErrors:    []error{applyErr},
	}

	_, err := reloadUnlocked(t.Context(), successfulReloadOptions(t, loader, guardExec, nil))
	if !errors.Is(err, applyErr) {
		t.Fatalf("reload error = %v", err)
	}
	if loader.resumeCalls != 0 || guardExec.cleanupCalls != 0 ||
		loader.pause.Phase != faketcp.StartupGuardPausePhaseHeld {
		t.Fatalf("preexisting active guard was removed or opened: guard=%#v loader=%#v", guardExec, loader)
	}
}

func TestReloadBorrowedBarrierKeepsNonAbsentGuardPostconditions(t *testing.T) {
	for _, test := range []struct {
		name    string
		initial guard.Observation
		outcome guard.Outcome
	}{
		{
			name:    "active",
			initial: guard.ObservationActive,
			outcome: guard.Outcome{Observation: guard.ObservationActive, Mutated: true},
		},
		{
			name:    "unknown",
			initial: guard.ObservationActive,
			outcome: guard.Outcome{Observation: guard.ObservationUnknown, Mutated: true},
		},
		{
			name:    "unchanged-preserves-active",
			initial: guard.ObservationActive,
			outcome: guard.Outcome{Observation: guard.ObservationUnchanged},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			applyErr := errors.New("guard apply failed")
			fresh := dataplane.NewStartupGuardLease()
			loader := newTxnTestLoader(borrowTxnTestLease(fresh))
			loader.pause = heldTxnPauseStatus()
			guardExec := &scriptedGuardExecutor{
				observeOutcome: guard.Outcome{Observation: test.initial},
				applyOutcomes:  []guard.Outcome{test.outcome},
				applyErrors:    []error{applyErr},
			}

			_, err := reloadUnlocked(t.Context(), successfulReloadOptions(t, loader, guardExec, nil))
			if !errors.Is(err, applyErr) {
				t.Fatalf("reload error = %v", err)
			}
			if loader.resumeCalls != 0 || guardExec.cleanupCalls != 0 ||
				loader.pause.Phase != faketcp.StartupGuardPausePhaseHeld {
				t.Fatalf("non-absent borrowed barrier was released: guard=%#v loader=%#v", guardExec, loader)
			}
		})
	}
}

func TestReloadRejectsEmptyRuntimeLeaseBeforeGuardMutation(t *testing.T) {
	loader := newTxnTestLoader(dataplane.StartupGuardLease{})
	guardExec := &scriptedGuardExecutor{
		observeOutcome: guard.Outcome{Observation: guard.ObservationAbsent},
		applyOutcomes:  []guard.Outcome{{Observation: guard.ObservationActive, Mutated: true}},
	}

	_, err := reloadUnlocked(t.Context(), successfulReloadOptions(t, loader, guardExec, nil))
	if err == nil || !strings.Contains(err.Error(), "empty lease token") {
		t.Fatalf("empty lease error = %v", err)
	}
	if guardExec.applyCalls != 0 || guardExec.cleanupCalls != 0 ||
		loader.applyCalls != 0 || loader.resumeCalls != 0 {
		t.Fatalf("mutation occurred after empty lease: guard=%#v loader=%#v", guardExec, loader)
	}
}

func TestReloadRollsBackNewGuardOnPreLoaderBuildFailure(t *testing.T) {
	buildErr := errors.New("runtime device disappeared before state build")
	loader := newTxnTestLoader(dataplane.NewStartupGuardLease())
	guardExec := &scriptedGuardExecutor{
		observeOutcome: guard.Outcome{Observation: guard.ObservationAbsent},
		applyOutcomes:  []guard.Outcome{{Observation: guard.ObservationActive, Mutated: true}},
		cleanupOutcome: guard.Outcome{Observation: guard.ObservationAbsent, Mutated: true},
	}
	opts := successfulReloadOptions(t, loader, guardExec, nil)
	opts.deps.runtimeProvider = txnRuntimeProviderFunc(func(context.Context, string) (*runtime.Device, error) {
		return nil, buildErr
	})

	_, err := reloadUnlocked(t.Context(), opts)
	if !errors.Is(err, buildErr) {
		t.Fatalf("reload error = %v", err)
	}
	if guardExec.cleanupCalls != 1 || loader.applyCalls != 0 || loader.resumeCalls != 1 ||
		loader.pause.Phase != faketcp.StartupGuardPausePhaseOpen {
		t.Fatalf("rollback did not restore pre-transaction state: guard=%#v loader=%#v", guardExec, loader)
	}
}

func TestReloadResumesWhenRollbackCleanupReturnsAbsentWithError(t *testing.T) {
	buildErr := errors.New("runtime state build failed")
	cleanupErr := errors.New("cleanup command failed after removing the table")
	loader := newTxnTestLoader(dataplane.NewStartupGuardLease())
	guardExec := &scriptedGuardExecutor{
		observeOutcome: guard.Outcome{Observation: guard.ObservationAbsent},
		applyOutcomes:  []guard.Outcome{{Observation: guard.ObservationActive, Mutated: true}},
		cleanupOutcome: guard.Outcome{Observation: guard.ObservationAbsent, Mutated: true},
		cleanupErr:     cleanupErr,
	}
	opts := successfulReloadOptions(t, loader, guardExec, nil)
	opts.deps.runtimeProvider = txnRuntimeProviderFunc(func(context.Context, string) (*runtime.Device, error) {
		return nil, buildErr
	})

	_, err := reloadUnlocked(t.Context(), opts)
	if !errors.Is(err, buildErr) || !errors.Is(err, cleanupErr) {
		t.Fatalf("joined rollback error = %v", err)
	}
	if guardExec.cleanupCalls != 1 || loader.resumeCalls != 1 ||
		loader.pause.Phase != faketcp.StartupGuardPausePhaseOpen {
		t.Fatalf("proved-absent cleanup did not resume: guard=%#v loader=%#v", guardExec, loader)
	}
}

func TestReloadKeepsBarrierAfterDataplaneMutationStarts(t *testing.T) {
	applyErr := errors.New("dataplane apply failed after mutation started")
	loader := newTxnTestLoader(dataplane.NewStartupGuardLease())
	loader.applyErrors = []error{applyErr}
	guardExec := &scriptedGuardExecutor{
		observeOutcome: guard.Outcome{Observation: guard.ObservationAbsent},
		applyOutcomes:  []guard.Outcome{{Observation: guard.ObservationActive, Mutated: true}},
		cleanupOutcome: guard.Outcome{Observation: guard.ObservationAbsent, Mutated: true},
	}

	_, err := reloadUnlocked(t.Context(), successfulReloadOptions(t, loader, guardExec, nil))
	if !errors.Is(err, applyErr) {
		t.Fatalf("reload error = %v", err)
	}
	if loader.applyCalls != 1 || loader.resumeCalls != 0 || guardExec.cleanupCalls != 0 ||
		loader.pause.Phase != faketcp.StartupGuardPausePhaseHeld {
		t.Fatalf("post-mutation failure did not remain fail-closed: guard=%#v loader=%#v", guardExec, loader)
	}
}

func TestReloadRetriesResumeAfterCleanupWithFinalizationContext(t *testing.T) {
	resumeErr := errors.New("transient runtime resume failure")
	requestCtx, cancelRequest := context.WithCancel(t.Context())
	loader := newTxnTestLoader(dataplane.NewStartupGuardLease())
	loader.resumeErrors = []error{resumeErr, nil}
	guardExec := &scriptedGuardExecutor{
		observeOutcome: guard.Outcome{Observation: guard.ObservationAbsent},
		applyOutcomes:  []guard.Outcome{{Observation: guard.ObservationActive, Mutated: true}},
		cleanupOutcome: guard.Outcome{Observation: guard.ObservationAbsent, Mutated: true},
		cleanupHook:    cancelRequest,
	}

	_, err := reloadUnlocked(requestCtx, successfulReloadOptions(t, loader, guardExec, nil))
	if !errors.Is(err, resumeErr) {
		t.Fatalf("reload error = %v", err)
	}
	if loader.resumeCalls != 2 || loader.lastResumeContextErr != nil ||
		loader.pause.Phase != faketcp.StartupGuardPausePhaseOpen {
		t.Fatalf("resume retry = %#v", loader)
	}
}

func TestReloadStaleLeaseMismatchRemainsFailClosed(t *testing.T) {
	fresh := dataplane.NewStartupGuardLease()
	replacement := dataplane.NewStartupGuardLease()
	loader := newTxnTestLoader(fresh)
	guardExec := &scriptedGuardExecutor{
		observeOutcome: guard.Outcome{Observation: guard.ObservationAbsent},
		applyOutcomes:  []guard.Outcome{{Observation: guard.ObservationActive, Mutated: true}},
		cleanupOutcome: guard.Outcome{Observation: guard.ObservationAbsent, Mutated: true},
		cleanupHook: func() {
			loader.activeToken = replacement.Token
		},
	}

	_, err := reloadUnlocked(t.Context(), successfulReloadOptions(t, loader, guardExec, nil))
	if !errors.Is(err, dataplane.ErrStartupGuardLeaseMismatch) {
		t.Fatalf("stale lease error = %v", err)
	}
	if loader.resumeCalls != 2 || loader.pause.Phase != faketcp.StartupGuardPausePhaseHeld {
		t.Fatalf("stale lease opened barrier: %#v", loader)
	}
}

func TestReloadRetryWithBorrowedLeaseResumesAfterCleanup(t *testing.T) {
	dataplaneErr := errors.New("first dataplane mutation failed")
	fresh := dataplane.NewStartupGuardLease()
	loader := newTxnTestLoader(fresh, borrowTxnTestLease(fresh))
	loader.applyErrors = []error{dataplaneErr, nil}
	guardExec := &scriptedGuardExecutor{
		observeOutcome: guard.Outcome{Observation: guard.ObservationActive},
		applyOutcomes: []guard.Outcome{
			{Observation: guard.ObservationActive, Mutated: true},
			{Observation: guard.ObservationActive, Mutated: true},
		},
		cleanupOutcome: guard.Outcome{Observation: guard.ObservationAbsent, Mutated: true},
	}
	opts := successfulReloadOptions(t, loader, guardExec, nil)

	if _, err := reloadUnlocked(t.Context(), opts); !errors.Is(err, dataplaneErr) {
		t.Fatalf("first reload error = %v", err)
	}
	if loader.resumeCalls != 0 || loader.pause.Phase != faketcp.StartupGuardPausePhaseHeld {
		t.Fatalf("first failure did not retain barrier: %#v", loader)
	}
	result, err := reloadUnlocked(t.Context(), opts)
	if err != nil {
		t.Fatalf("retry reload: %v", err)
	}
	if result == nil || !result.GuardCleaned || loader.quiesceCalls != 2 ||
		loader.resumeCalls != 1 || loader.pause.Phase != faketcp.StartupGuardPausePhaseOpen {
		t.Fatalf("borrowed lease retry did not recover: result=%#v loader=%#v", result, loader)
	}
}

func TestReloadBorrowedLeaseDoesNotResumeBeforeProductionHealthValidation(t *testing.T) {
	dataplaneErr := errors.New("first dataplane mutation failed")
	healthErr := errors.New("replacement runtime health is unverified")
	fresh := dataplane.NewStartupGuardLease()
	loader := newTxnTestLoader(fresh, borrowTxnTestLease(fresh))
	loader.applyErrors = []error{dataplaneErr, nil}
	guardExec := &scriptedGuardExecutor{
		observeOutcome: guard.Outcome{Observation: guard.ObservationActive},
		applyOutcomes: []guard.Outcome{
			{Observation: guard.ObservationActive, Mutated: true},
			{Observation: guard.ObservationActive, Mutated: true},
		},
		cleanupOutcome: guard.Outcome{Observation: guard.ObservationAbsent, Mutated: true},
	}
	opts := successfulReloadOptions(t, loader, guardExec, nil)
	opts.deps.productionFakeTCPStatus = func(
		context.Context,
		*control.State,
	) (bool, *dataplane.KernelStatus, error) {
		if loader.applyCalls < 2 {
			return false, nil, nil
		}
		return true, nil, healthErr
	}

	if _, err := reloadUnlocked(t.Context(), opts); !errors.Is(err, dataplaneErr) {
		t.Fatalf("first reload error = %v", err)
	}
	_, err := reloadUnlocked(t.Context(), opts)
	if !errors.Is(err, healthErr) {
		t.Fatalf("retry reload error = %v", err)
	}
	if loader.applyCalls != 2 || guardExec.cleanupCalls != 0 || loader.resumeCalls != 0 ||
		loader.pause.Phase != faketcp.StartupGuardPausePhaseHeld {
		t.Fatalf("borrowed lease resumed before health validation: guard=%#v loader=%#v", guardExec, loader)
	}
}

func TestReloadBorrowedLeaseRetriesResumeOnlyAfterValidatedNormalCleanup(t *testing.T) {
	dataplaneErr := errors.New("first dataplane mutation failed")
	resumeErr := errors.New("transient borrowed-lease resume failure")
	fresh := dataplane.NewStartupGuardLease()
	loader := newTxnTestLoader(fresh, borrowTxnTestLease(fresh))
	loader.applyErrors = []error{dataplaneErr, nil}
	loader.resumeErrors = []error{resumeErr, nil}
	guardExec := &scriptedGuardExecutor{
		observeOutcome: guard.Outcome{Observation: guard.ObservationActive},
		applyOutcomes: []guard.Outcome{
			{Observation: guard.ObservationActive, Mutated: true},
			{Observation: guard.ObservationActive, Mutated: true},
		},
		cleanupOutcome: guard.Outcome{Observation: guard.ObservationAbsent, Mutated: true},
	}
	opts := successfulReloadOptions(t, loader, guardExec, nil)

	if _, err := reloadUnlocked(t.Context(), opts); !errors.Is(err, dataplaneErr) {
		t.Fatalf("first reload error = %v", err)
	}
	_, err := reloadUnlocked(t.Context(), opts)
	if !errors.Is(err, resumeErr) {
		t.Fatalf("retry reload error = %v", err)
	}
	if loader.applyCalls != 2 || guardExec.cleanupCalls != 1 || loader.resumeCalls != 2 ||
		loader.pause.Phase != faketcp.StartupGuardPausePhaseOpen {
		t.Fatalf("borrowed resume retry did not converge: guard=%#v loader=%#v", guardExec, loader)
	}
}

func TestReloadNoNFTRevalidatesImmediatelyBeforeDataplaneApply(t *testing.T) {
	events := make([]string, 0, 3)
	loader := newTxnTestLoader()
	loader.events = &events
	opts := successfulReloadOptions(t, loader, nil, nil)
	appendConfig(t, opts.ConfigPath, "\nstartup_guard:\n  mode: none\n")
	preflightCalls := 0
	opts.deps.noNFTGuardPreflight = func(context.Context, string) error {
		preflightCalls++
		events = append(events, "preflight")
		return nil
	}

	if _, err := reloadUnlocked(t.Context(), opts); err != nil {
		t.Fatal(err)
	}
	want := []string{"preflight", "preflight", "loader-apply"}
	if preflightCalls != 2 || !reflect.DeepEqual(events, want) {
		t.Fatalf("preflight order: calls=%d events=%v, want %v", preflightCalls, events, want)
	}
}

func TestReloadNoNFTSecondPreflightFailurePrecedesAllMutation(t *testing.T) {
	preflightErr := errors.New("project nft table appeared before apply")
	events := make([]string, 0, 2)
	loader := newTxnTestLoader()
	loader.events = &events
	opts := successfulReloadOptions(t, loader, nil, nil)
	appendConfig(t, opts.ConfigPath, "\nstartup_guard:\n  mode: none\n")
	preflightCalls := 0
	opts.deps.noNFTGuardPreflight = func(context.Context, string) error {
		preflightCalls++
		events = append(events, "preflight")
		if preflightCalls == 2 {
			return preflightErr
		}
		return nil
	}

	_, err := reloadUnlocked(t.Context(), opts)
	if !errors.Is(err, preflightErr) || !strings.Contains(err.Error(), "immediately before dataplane apply") {
		t.Fatalf("reload error = %v", err)
	}
	if preflightCalls != 2 || !reflect.DeepEqual(events, []string{"preflight", "preflight"}) {
		t.Fatalf("preflight order: calls=%d events=%v", preflightCalls, events)
	}
	if loader.applyCalls != 0 || loader.quiesceCalls != 0 || loader.resumeCalls != 0 {
		t.Fatalf("mutation occurred after failed preflight: %#v", loader)
	}
	if _, loadErr := attachstate.Load(opts.StateDir); !errors.Is(loadErr, os.ErrNotExist) {
		t.Fatalf("attach state was published before failed preflight: %v", loadErr)
	}
}

type txnRuntimeProviderFunc func(context.Context, string) (*runtime.Device, error)

func (fn txnRuntimeProviderFunc) Device(ctx context.Context, name string) (*runtime.Device, error) {
	return fn(ctx, name)
}

type txnTestLoader struct {
	pause                faketcp.StartupGuardPauseStatus
	leases               []dataplane.StartupGuardLease
	quiesceCalls         int
	resumeCalls          int
	applyCalls           int
	applyErrors          []error
	resumeErrors         []error
	lastResumeContextErr error
	events               *[]string
	activeToken          dataplane.StartupGuardLeaseToken
}

func newTxnTestLoader(leases ...dataplane.StartupGuardLease) *txnTestLoader {
	return &txnTestLoader{pause: openPauseStatus(), leases: leases}
}

func (loader *txnTestLoader) StartupGuardPauseStatus() faketcp.StartupGuardPauseStatus {
	return loader.pause
}

func (loader *txnTestLoader) QuiesceForStartupGuard(context.Context) (dataplane.StartupGuardLease, error) {
	index := loader.quiesceCalls
	loader.quiesceCalls++
	loader.pause = heldTxnPauseStatus()
	if index < len(loader.leases) {
		lease := loader.leases[index]
		if !lease.Token.IsZero() {
			switch {
			case loader.activeToken.IsZero():
				loader.activeToken = lease.Token
			case loader.activeToken != lease.Token:
				return dataplane.StartupGuardLease{}, dataplane.ErrStartupGuardLeaseMismatch
			}
		}
		return lease, nil
	}
	return dataplane.StartupGuardLease{}, nil
}

func (loader *txnTestLoader) ResumeAfterStartupGuard(
	ctx context.Context,
	lease dataplane.StartupGuardLease,
) error {
	index := loader.resumeCalls
	loader.resumeCalls++
	loader.lastResumeContextErr = ctx.Err()
	if loader.lastResumeContextErr != nil {
		return loader.lastResumeContextErr
	}
	if loader.activeToken.IsZero() ||
		lease.Token.IsZero() ||
		loader.activeToken != lease.Token {
		return dataplane.ErrStartupGuardLeaseMismatch
	}
	if index < len(loader.resumeErrors) && loader.resumeErrors[index] != nil {
		return loader.resumeErrors[index]
	}
	loader.pause = openPauseStatus()
	loader.activeToken = dataplane.StartupGuardLeaseToken{}
	return nil
}

func (loader *txnTestLoader) Apply(context.Context, *control.State) error {
	index := loader.applyCalls
	loader.applyCalls++
	if loader.events != nil {
		*loader.events = append(*loader.events, "loader-apply")
	}
	if index < len(loader.applyErrors) {
		return loader.applyErrors[index]
	}
	return nil
}

func (*txnTestLoader) Detach(context.Context, *control.State) error {
	return nil
}

func heldTxnPauseStatus() faketcp.StartupGuardPauseStatus {
	return faketcp.StartupGuardPauseStatus{
		Phase:  faketcp.StartupGuardPausePhaseHeld,
		Reason: faketcp.StartupGuardPauseReasonStartupGuard,
		Since:  time.Now(),
	}
}

func borrowTxnTestLease(fresh dataplane.StartupGuardLease) dataplane.StartupGuardLease {
	return dataplane.StartupGuardLease{Token: fresh.Token}
}
