//go:build linux

package dataplane

import (
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/syx0310/wg-mix-ebpf/internal/control"
)

type fakeExperimentalTCXLink struct {
	kernel    *fakeExperimentalTCXKernel
	id        int
	closeErrs []error
	closes    int
}

func (owned *fakeExperimentalTCXLink) Close() error {
	owned.closes++
	if len(owned.closeErrs) != 0 {
		err := owned.closeErrs[0]
		owned.closeErrs = owned.closeErrs[1:]
		if err != nil {
			return err
		}
	}
	delete(owned.kernel.active, owned.id)
	return nil
}

type fakeExperimentalTCXAttachment struct {
	ifindex    int
	attachType ebpf.AttachType
	program    experimentalProgramResource
}

type fakeExperimentalTCXKernel struct {
	active       map[int]fakeExperimentalTCXAttachment
	links        []*fakeExperimentalTCXLink
	attachCalls  []fakeExperimentalTCXAttachment
	failAttachAt int
	attachErr    error
	closeErrsAt  map[int][]error
}

func newFakeExperimentalTCXKernel() *fakeExperimentalTCXKernel {
	return &fakeExperimentalTCXKernel{
		active:      make(map[int]fakeExperimentalTCXAttachment),
		closeErrsAt: make(map[int][]error),
	}
}

func (kernel *fakeExperimentalTCXKernel) runtime() experimentalTCXRuntime {
	return experimentalTCXRuntime{attach: func(
		ifindex int,
		program experimentalProgramResource,
		attachType ebpf.AttachType,
	) (experimentalTCXOwnedLink, error) {
		request := fakeExperimentalTCXAttachment{
			ifindex: ifindex, attachType: attachType, program: program,
		}
		kernel.attachCalls = append(kernel.attachCalls, request)
		if kernel.failAttachAt != 0 && len(kernel.attachCalls) == kernel.failAttachAt {
			return nil, kernel.attachErr
		}
		id := len(kernel.links) + 1
		owned := &fakeExperimentalTCXLink{
			kernel: kernel, id: id,
			closeErrs: slices.Clone(kernel.closeErrsAt[len(kernel.attachCalls)]),
		}
		kernel.links = append(kernel.links, owned)
		kernel.active[id] = request
		return owned, nil
	}}
}

func fakeExperimentalTCXPrograms() (experimentalProgramResource, experimentalProgramResource) {
	closeLog := []string{}
	return &fakeExperimentalOwnedProgram{name: "ingress", id: 11, closeLog: &closeLog},
		&fakeExperimentalOwnedProgram{name: "egress", id: 12, closeLog: &closeLog}
}

func experimentalTestTCState(ifindexes ...int) *control.State {
	state := &control.State{}
	for _, ifindex := range ifindexes {
		state.Underlays = append(state.Underlays, control.UnderlayState{
			Name:     fmt.Sprintf("u%d", ifindex),
			IfIndex:  ifindex,
			Resolved: true,
		})
	}
	return state
}

func TestExperimentalTCXStageAttachesEveryCanonicalDirection(t *testing.T) {
	kernel := newFakeExperimentalTCXKernel()
	ingress, egress := fakeExperimentalTCXPrograms()
	commits := 0
	stage, err := stageExperimentalTCX(
		t.Context(), experimentalTestTCState(12, 11), ingress, egress,
		func() error { commits++; return nil }, kernel.runtime(),
	)
	if err != nil || stage == nil {
		t.Fatalf("stage=%#v error=%v", stage, err)
	}
	want := []struct {
		ifindex    int
		attachType ebpf.AttachType
	}{
		{11, ebpf.AttachTCXIngress}, {11, ebpf.AttachTCXEgress},
		{12, ebpf.AttachTCXIngress}, {12, ebpf.AttachTCXEgress},
	}
	if len(kernel.attachCalls) != len(want) {
		t.Fatalf("attach calls=%v", kernel.attachCalls)
	}
	for index, request := range kernel.attachCalls {
		if request.ifindex != want[index].ifindex || request.attachType != want[index].attachType {
			t.Fatalf("attach[%d]=%+v want=%+v", index, request, want[index])
		}
	}
	if commits != 1 || len(kernel.active) != 4 {
		t.Fatalf("commits=%d active=%v", commits, kernel.active)
	}
	if err := stage.Close(); err != nil {
		t.Fatal(err)
	}
	if len(kernel.active) != 0 || !stage.done {
		t.Fatalf("active=%v done=%t", kernel.active, stage.done)
	}
}

func TestExperimentalTCXStageReturnsOwnedPrefixOnPartialAttach(t *testing.T) {
	kernel := newFakeExperimentalTCXKernel()
	kernel.failAttachAt = 2
	kernel.attachErr = errors.New("injected TCX attach failure")
	ingress, egress := fakeExperimentalTCXPrograms()
	commits := 0
	stage, err := stageExperimentalTCX(
		t.Context(), experimentalTestTCState(11), ingress, egress,
		func() error { commits++; return nil }, kernel.runtime(),
	)
	if stage == nil || !errors.Is(err, kernel.attachErr) {
		t.Fatalf("stage=%#v error=%v", stage, err)
	}
	if commits != 0 || len(kernel.active) != 1 {
		t.Fatalf("commits=%d active=%v", commits, kernel.active)
	}
	if err := stage.Close(); err != nil {
		t.Fatal(err)
	}
	if len(kernel.active) != 0 {
		t.Fatalf("partial owner retained links: %v", kernel.active)
	}
}

func TestExperimentalTCXStageCloseRetriesOnlyExactFailedLink(t *testing.T) {
	kernel := newFakeExperimentalTCXKernel()
	closeErr := errors.New("injected TCX link close failure")
	kernel.closeErrsAt[2] = []error{closeErr}
	ingress, egress := fakeExperimentalTCXPrograms()
	stage, err := stageExperimentalTCX(
		t.Context(), experimentalTestTCState(11), ingress, egress,
		func() error { return nil }, kernel.runtime(),
	)
	if err != nil {
		t.Fatal(err)
	}
	// A concurrently attached foreign TCX program has its own link identity.
	const foreignID = 999
	kernel.active[foreignID] = fakeExperimentalTCXAttachment{
		ifindex: 11, attachType: ebpf.AttachTCXEgress,
	}
	if err := stage.Close(); !errors.Is(err, closeErr) {
		t.Fatalf("first Close error=%v", err)
	}
	if len(stage.attachments) != 1 || len(kernel.active) != 2 {
		t.Fatalf("retained=%v active=%v", stage.attachments, kernel.active)
	}
	if _, exists := kernel.active[foreignID]; !exists {
		t.Fatal("exact link Close removed a foreign concurrent TCX program")
	}
	if err := stage.Close(); err != nil {
		t.Fatalf("retry Close: %v", err)
	}
	if len(kernel.active) != 1 {
		t.Fatalf("retry active=%v", kernel.active)
	}
	if kernel.links[0].closes != 1 || kernel.links[1].closes != 2 {
		t.Fatalf("link closes=%d/%d", kernel.links[0].closes, kernel.links[1].closes)
	}
}

func TestExperimentalTCXStageCommitFailureRetainsEveryExactLink(t *testing.T) {
	kernel := newFakeExperimentalTCXKernel()
	commitErr := errors.New("injected activation failure")
	ingress, egress := fakeExperimentalTCXPrograms()
	stage, err := stageExperimentalTCX(
		t.Context(), experimentalTestTCState(11), ingress, egress,
		func() error { return commitErr }, kernel.runtime(),
	)
	if stage == nil || !errors.Is(err, commitErr) || len(kernel.active) != 2 {
		t.Fatalf("stage=%#v error=%v active=%v", stage, err, kernel.active)
	}
	if err := stage.Close(); err != nil {
		t.Fatal(err)
	}
	if len(kernel.active) != 0 {
		t.Fatalf("commit failure retained links: %v", kernel.active)
	}
}
