//go:build linux

package dataplane

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const fakeTCPClassicTestBootID = "12345678-1234-1234-1234-123456789abc"

func fakeTCPClassicTestRuntime(
	t *testing.T,
	kernel *fakeTCKernel,
) (pinPathRuntime, fakeTCPProductionScopeIdentity) {
	t.Helper()
	bpffsRoot, validator := newTestBPFFS(t)
	pinPath := filepath.Join(bpffsRoot, "wg-mix-ebpf-faketcp-classic-test")
	runRoot := t.TempDir()
	runtime := pinPathRuntime{
		validator:            validator,
		lockRoot:             filepath.Join(runRoot, "pin-locks"),
		ownerRoot:            filepath.Join(runRoot, "pin-owners"),
		expectedUID:          uint32(os.Getuid()),
		bpffsRootMode:        0o700,
		allowUnsafeAncestors: true,
		mountIDAt: func(int, string, int) (uint64, error) {
			return 101, nil
		},
		now: func() time.Time {
			return time.Date(2026, 8, 12, 1, 2, 3, 4, time.UTC)
		},
		bootID:    func() (string, error) { return fakeTCPClassicTestBootID, nil },
		classicTC: kernel.runtime(),
		exactTCX: exactTCXRuntime{
			query: func(int, ebpf.AttachType) (exactTCXQuery, error) {
				return exactTCXQuery{}, unix.EOPNOTSUPP
			},
		},
	}
	scope := fakeTCPProductionScopeIdentity{
		objectKind:                 fakeTCPProductionObjectScopeFilesystem,
		objectPath:                 filepath.Join(runRoot, "baseline.o"),
		fakeTCPObjectPath:          EmbeddedFakeTCPObjectSource,
		fakeTCPLegacy515ObjectPath: EmbeddedFakeTCPLegacy515ObjectSource,
		pinPath:                    pinPath,
		lifecyclePath:              filepath.Join(runRoot, "daemon.lease"),
	}
	return runtime, scope
}

func stageFakeTCPClassicTestOwner(
	t *testing.T,
	kernel *fakeTCKernel,
	runtime pinPathRuntime,
	scope fakeTCPProductionScopeIdentity,
) *productionFakeTCPClassicStage {
	t.Helper()
	state := testTCState(11)
	state.Generation = 7
	commits := 0
	stage, err := stageProductionFakeTCPClassicWithPrograms(
		t.Context(),
		state,
		tcProgramIdentity{fd: 1001, id: 101},
		tcProgramIdentity{fd: 1002, id: 102},
		func() error {
			commits++
			return nil
		},
		runtime,
		scope,
		ObjectIdentity{
			Source:   EmbeddedFakeTCPObjectSource,
			SHA256:   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			Embedded: true,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if commits != 1 {
		t.Fatalf("classic activation commits = %d, want 1", commits)
	}
	return stage
}

func TestProductionFakeTCPClassicStageOwnsDurableExactFilters(t *testing.T) {
	kernel := newFakeTCKernel(11)
	kernel.addProgram(101, 1001)
	kernel.addProgram(102, 1002)
	runtime, scope := fakeTCPClassicTestRuntime(t, kernel)
	stage := stageFakeTCPClassicTestOwner(t, kernel, runtime, scope)

	if err := stage.Healthy(t.Context()); err != nil {
		t.Fatalf("healthy active classic owner: %v", err)
	}
	status := stage.status()
	if len(status) != 2 || status[0].IfIndex != 11 || status[1].IfIndex != 11 ||
		status[0].ProgramID == status[1].ProgramID ||
		!slices.Equal([]string{status[0].Direction, status[1].Direction}, []string{"ingress", "egress"}) {
		t.Fatalf("classic status = %#v", status)
	}
	owner, published, recovery, err := inspectFakeTCPClassicOwnerEvidence(scope, runtime)
	if err != nil || owner == nil || !published || !recovery ||
		owner.Phase != fakeTCPClassicPhaseActive || owner.Generation != 7 {
		t.Fatalf(
			"classic owner evidence = %#v published=%t recovery=%t err=%v",
			owner, published, recovery, err,
		)
	}
	if err := stage.Close(); err != nil {
		t.Fatalf("close classic owner: %v", err)
	}
	for index, slot := range canonicalTCFilterSlots() {
		if got := kernel.managedProgramID(t, 11, slot); got != 0 {
			t.Fatalf("classic filter[%d] program after close = %d", index, got)
		}
	}
	owner, published, recovery, err = inspectFakeTCPClassicOwnerEvidence(scope, runtime)
	if err != nil || owner != nil || published || recovery {
		t.Fatalf(
			"retired classic owner evidence = %#v published=%t recovery=%t err=%v",
			owner, published, recovery, err,
		)
	}
}

func TestProductionFakeTCPClassicCloseRefusesForeignReplacementAndRetries(t *testing.T) {
	kernel := newFakeTCKernel(11)
	kernel.addProgram(101, 1001)
	kernel.addProgram(102, 1002)
	runtime, scope := fakeTCPClassicTestRuntime(t, kernel)
	stage := stageFakeTCPClassicTestOwner(t, kernel, runtime, scope)

	slots := canonicalTCFilterSlots()
	key := fakeTCFilterKey{ifindex: 11, parent: slots[0].parent}
	filter := kernel.filters[key][0].(*netlink.BpfFilter)
	filter.Id = 909
	if err := stage.Close(); err == nil {
		t.Fatal("classic close accepted a foreign replacement")
	}
	if got := kernel.managedProgramID(t, 11, slots[1]); got != 102 {
		t.Fatalf("two-pass preflight partially deleted egress filter: %d", got)
	}
	owner, published, recovery, err := inspectFakeTCPClassicOwnerEvidence(scope, runtime)
	if err != nil || owner == nil || !published || !recovery ||
		owner.Phase != fakeTCPClassicPhaseDetaching {
		t.Fatalf(
			"failed close owner evidence = %#v published=%t recovery=%t err=%v",
			owner, published, recovery, err,
		)
	}
	filter.Id = 101
	if err := stage.Close(); err != nil {
		t.Fatalf("retry exact classic close: %v", err)
	}
}

func TestProductionFakeTCPClassicAutoIsStickyAndCrashRecoverable(t *testing.T) {
	kernel := newFakeTCKernel(11)
	kernel.addProgram(101, 1001)
	kernel.addProgram(102, 1002)
	runtime, scope := fakeTCPClassicTestRuntime(t, kernel)
	stage := stageFakeTCPClassicTestOwner(t, kernel, runtime, scope)

	// Simulate process loss: release only the process flock/descriptors. The
	// kernel filters and durable owner journal deliberately remain.
	if err := stage.resources.Close(); err != nil {
		t.Fatal(err)
	}
	stage.resources = nil
	queries := 0
	runtime.exactTCX.query = func(int, ebpf.AttachType) (exactTCXQuery, error) {
		queries++
		return exactTCXQuery{Revision: 1}, nil
	}
	state := testTCState(11)
	state.Generation = 8
	state.AttachmentBackend = attachmentBackendAuto
	backend, recoverClassic, err := resolveFakeTCPProductionAttachmentBackend(
		state, scope, runtime,
	)
	if err != nil || backend != classicTCBackend || !recoverClassic || queries != 0 {
		t.Fatalf(
			"sticky backend=%q recover=%t queries=%d err=%v",
			backend, recoverClassic, queries, err,
		)
	}
	if err := recoverFakeTCPProductionClassicOwner(t.Context(), scope, runtime); err != nil {
		t.Fatalf("recover crashed classic owner: %v", err)
	}
	for index, slot := range canonicalTCFilterSlots() {
		if got := kernel.managedProgramID(t, 11, slot); got != 0 {
			t.Fatalf("recovered classic filter[%d] remains as program %d", index, got)
		}
	}
	if _, _, recovery, err := inspectFakeTCPClassicOwnerEvidence(scope, runtime); err != nil || recovery {
		t.Fatalf("classic recovery residue: recovery=%t err=%v", recovery, err)
	}
}
