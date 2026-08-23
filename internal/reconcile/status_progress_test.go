package reconcile

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/control"
	"github.com/syx0310/wg-mix-ebpf/internal/dataplane"
)

func TestIntermediateProgressNeverRunsDeepDataplaneInspection(t *testing.T) {
	var deepCalls atomic.Int64
	var published []Observation
	opts := Options{
		Progress: func(observation Observation) {
			published = append(published, observation)
		},
		deps: &dependencies{
			productionFakeTCPStatus: func(context.Context, *control.State) (bool, *dataplane.KernelStatus, error) {
				deepCalls.Add(1)
				return true, &dataplane.KernelStatus{Mode: "unexpected-deep-inspection"}, nil
			},
		},
	}
	state := progressBenchmarkState(1024)
	phases := []string{
		ReconcilePhasePreparing,
		ReconcilePhaseQuiescing,
		ReconcilePhaseGuarded,
		ReconcilePhaseApplying,
		ReconcilePhaseFinalizing,
		ReconcilePhaseFailed,
	}
	for _, phase := range phases {
		observation := publishProgress(
			t.Context(), opts, phase, time.Now(), state,
			StartupGuardStatus{KernelState: StartupGuardKernelUnknown},
			&recordingDataplaneLoader{}, nil,
		)
		if observation.Dataplane != nil || observation.DataplaneError != "" {
			t.Fatalf("phase %s published deep dataplane state: %#v", phase, observation)
		}
	}
	if got := deepCalls.Load(); got != 0 {
		t.Fatalf("intermediate progress deep-inspection calls = %d, want 0", got)
	}
	if len(published) != len(phases) {
		t.Fatalf("published phases = %d, want %d", len(published), len(phases))
	}
	for index, observation := range published {
		if observation.Reconcile.Phase != phases[index] ||
			observation.Dataplane != nil || observation.DataplaneError != "" {
			t.Fatalf("published[%d] = %#v", index, observation)
		}
	}

	// A nil callback is a common one-shot/control-plane path. It must not turn
	// phase publication into a hidden status request either.
	opts.Progress = nil
	publishProgress(
		t.Context(), opts, ReconcilePhaseApplying, time.Now(), state,
		StartupGuardStatus{KernelState: StartupGuardKernelActive},
		&recordingDataplaneLoader{}, nil,
	)
	if got := deepCalls.Load(); got != 0 {
		t.Fatalf("nil-progress deep-inspection calls = %d, want 0", got)
	}
}

func TestFinalProgressRunsOneDeepInspectionBeforePublishing(t *testing.T) {
	var deepCalls atomic.Int64
	wantStatus := &dataplane.KernelStatus{
		Mode:    "faketcp",
		FakeTCP: &dataplane.FakeTCPRuntimeStatus{Healthy: true},
	}
	var published Observation
	opts := Options{
		Progress: func(observation Observation) { published = observation },
		deps: &dependencies{
			productionFakeTCPStatus: func(context.Context, *control.State) (bool, *dataplane.KernelStatus, error) {
				deepCalls.Add(1)
				return true, wantStatus, nil
			},
		},
	}
	observation := publishFinalProgress(
		t.Context(), opts, ReconcilePhaseActive, time.Now(),
		progressBenchmarkState(1024),
		StartupGuardStatus{KernelState: StartupGuardKernelAbsent},
		&recordingDataplaneLoader{}, nil,
	)
	if got := deepCalls.Load(); got != 1 {
		t.Fatalf("terminal deep-inspection calls = %d, want 1", got)
	}
	if observation.Dataplane != wantStatus || published.Dataplane == nil ||
		published.Dataplane.Mode != wantStatus.Mode {
		t.Fatalf("terminal observations = returned %#v published %#v", observation, published)
	}
	if published.Reconcile.Phase != ReconcilePhaseActive {
		t.Fatalf("terminal phase = %q", published.Reconcile.Phase)
	}
}

func TestProgressDoesNotWaitForConcurrentDeepStatusInspection(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	statusDone := make(chan error, 1)
	var startedOnce sync.Once
	loader := &recordingDataplaneLoader{}
	opts := successfulReloadOptions(t, loader, &recordingGuardExecutor{}, nil)
	opts.deps.productionFakeTCPStatus = func(context.Context, *control.State) (bool, *dataplane.KernelStatus, error) {
		startedOnce.Do(func() { close(started) })
		<-release
		return true, &dataplane.KernelStatus{
			Mode:    "faketcp",
			FakeTCP: &dataplane.FakeTCPRuntimeStatus{Healthy: true},
		}, nil
	}
	state := progressBenchmarkState(1024)
	go func() {
		_, err := Status(t.Context(), opts)
		statusDone <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("deep status fake did not start")
	}

	progressDone := make(chan *Observation, 1)
	go func() {
		progressDone <- publishProgress(
			t.Context(), opts, ReconcilePhaseGuarded, time.Now(), state,
			StartupGuardStatus{KernelState: StartupGuardKernelActive},
			loader, nil,
		)
	}()
	select {
	case observation := <-progressDone:
		if observation.Dataplane != nil {
			t.Fatalf("progress inherited concurrent deep status: %#v", observation)
		}
	case <-time.After(time.Second):
		close(release)
		<-statusDone
		t.Fatal("phase progress waited for concurrent deep status inspection")
	}
	close(release)
	select {
	case err := <-statusDone:
		if err != nil {
			t.Fatalf("deep status failed after release: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("deep status fake did not finish after release")
	}
}

func BenchmarkPhaseProgress1024Rules(b *testing.B) {
	state := progressBenchmarkState(1024)
	guardStatus := StartupGuardStatus{KernelState: StartupGuardKernelActive}
	loader := &recordingDataplaneLoader{}
	for _, benchmark := range []struct {
		name     string
		progress ProgressFunc
	}{
		{name: "progress-off"},
		{name: "progress-on", progress: func(Observation) {}},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			opts := Options{Progress: benchmark.progress}
			b.ReportAllocs()
			b.ReportMetric(1024, "rules/input")
			b.ResetTimer()
			for range b.N {
				publishProgress(
					context.Background(), opts, ReconcilePhaseApplying,
					time.Unix(1, 0), state, guardStatus, loader, nil,
				)
			}
		})
	}
}

func BenchmarkPhaseProgressWithConcurrentDeepStatus1024Rules(b *testing.B) {
	state := progressBenchmarkState(1024)
	loader := &recordingDataplaneLoader{}
	opts := Options{
		Progress: func(Observation) {},
		deps: &dependencies{
			productionFakeTCPStatus: func(context.Context, *control.State) (bool, *dataplane.KernelStatus, error) {
				return true, &dataplane.KernelStatus{
					Mode:    "faketcp",
					FakeTCP: &dataplane.FakeTCPRuntimeStatus{Healthy: true},
				}, nil
			},
		},
	}
	// Exercise the deep-observation portion of Status concurrently while
	// keeping config/filesystem noise out of this userspace microbenchmark.
	// This is a timing seam, not a kernel performance claim.
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				observation := newPhaseObservation(
					ReconcilePhaseIdle, time.Unix(1, 0),
					StartupGuardStatus{}, loader, nil,
				)
				refreshDeepObservation(context.Background(), opts, state, loader, observation)
			}
		}
	}()
	b.Cleanup(func() {
		close(stop)
		<-done
	})
	b.ReportAllocs()
	b.ReportMetric(1024, "rules/input")
	b.ResetTimer()
	for range b.N {
		publishProgress(
			context.Background(), opts, ReconcilePhaseApplying,
			time.Unix(1, 0), state,
			StartupGuardStatus{KernelState: StartupGuardKernelActive},
			loader, nil,
		)
	}
}

func progressBenchmarkState(ruleCount int) *control.State {
	state := &control.State{
		WireGuards: []control.WireGuardState{{Name: "wg0"}},
		Underlays:  []control.UnderlayState{{Name: "eth0", IfIndex: 2}},
	}
	state.EgressRules = make([]control.EgressRule, ruleCount)
	for index := range state.EgressRules {
		state.EgressRules[index] = control.EgressRule{
			FwMark: uint32(index + 1), UnderlayIfIndex: 2,
		}
	}
	return state
}
