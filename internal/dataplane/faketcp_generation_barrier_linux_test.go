//go:build linux

package dataplane

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/syx0310/wg-mix-ebpf/internal/faketcp"
	"golang.org/x/sys/unix"
)

type cancelBetweenBarrierChecksContext struct {
	firstCheck chan struct{}
	done       chan struct{}
	firstOnce  sync.Once
	cancelOnce sync.Once
	canceled   atomic.Bool
}

func newCancelBetweenBarrierChecksContext() *cancelBetweenBarrierChecksContext {
	return &cancelBetweenBarrierChecksContext{
		firstCheck: make(chan struct{}),
		done:       make(chan struct{}),
	}
}

func (*cancelBetweenBarrierChecksContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (ctx *cancelBetweenBarrierChecksContext) Done() <-chan struct{}   { return ctx.done }
func (*cancelBetweenBarrierChecksContext) Value(any) any               { return nil }

func (ctx *cancelBetweenBarrierChecksContext) Err() error {
	ctx.firstOnce.Do(func() { close(ctx.firstCheck) })
	if ctx.canceled.Load() {
		return context.Canceled
	}
	return nil
}

func (ctx *cancelBetweenBarrierChecksContext) cancel() {
	ctx.cancelOnce.Do(func() {
		ctx.canceled.Store(true)
		close(ctx.done)
	})
}

func TestLiveFakeTCPGenerationBarrierBindCancellationWhileWaitingDoesNotBorrow(t *testing.T) {
	barrier, err := newLiveFakeTCPGenerationBarrier(91)
	if err != nil {
		t.Fatal(err)
	}
	ctx := newCancelBetweenBarrierChecksContext()
	identity := faketcp.RuntimeIdentity{Generation: 91}
	identity.Incarnation[0] = 1

	barrier.mu.Lock()
	result := make(chan error, 1)
	go func() {
		result <- barrier.BindCollection(ctx, &experimentalCollectionOwner{}, identity)
	}()
	<-ctx.firstCheck
	ctx.cancel()
	barrier.mu.Unlock()

	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("BindCollection cancellation error = %v", err)
	}
	if barrier.gate != nil || barrier.wake != nil || barrier.control != nil ||
		barrier.identity != (faketcp.RuntimeIdentity{}) {
		t.Fatalf("canceled bind borrowed resources: %#v", barrier)
	}
}

func TestExperimentalGenerationBarrierManifestIsExact(t *testing.T) {
	wantMaps := map[string]pinnedMapDescriptor{
		fakeTCPGenerationGateMapName: {
			name: fakeTCPGenerationGateMapName, mapType: ebpf.Array,
			keySize: 4, valueSize: 16, maxEntries: 1, flags: unix.BPF_F_RDONLY,
		},
		fakeTCPGenerationWakeMapName: {
			name: fakeTCPGenerationWakeMapName, mapType: ebpf.RingBuf,
			maxEntries: 4096,
		},
	}
	for _, descriptor := range experimentalMapDescriptors() {
		if !strings.HasPrefix(descriptor.name, "faketcp_gen_") {
			continue
		}
		want, ok := wantMaps[descriptor.name]
		if !ok || descriptor != want {
			t.Fatalf("unexpected generation map descriptor: %#v", descriptor)
		}
		delete(wantMaps, descriptor.name)
	}
	if len(wantMaps) != 0 {
		t.Fatalf("missing generation map descriptors: %v", wantMaps)
	}

	wantProgram := baselineProgramDescriptor{
		name:        fakeTCPGenerationControlProgramName,
		sectionName: "classifier/faketcp_generation_control",
		programType: ebpf.SchedCLS,
		license:     experimentalFakeTCPLicense,
	}
	count := 0
	for _, descriptor := range experimentalProgramDescriptors() {
		if descriptor.name == fakeTCPGenerationControlProgramName {
			count++
			if descriptor != wantProgram {
				t.Fatalf("generation control descriptor=%#v, want %#v", descriptor, wantProgram)
			}
		}
	}
	if count != 1 {
		t.Fatalf("generation control descriptor count=%d, want one", count)
	}
}
