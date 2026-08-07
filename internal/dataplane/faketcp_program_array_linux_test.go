//go:build linux

package dataplane

import (
	"errors"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

type memoryFakeTCPProgramArray struct {
	entries         map[uint32]uint32
	events          *[]string
	insertErr       error
	lookupErr       error
	deleteErr       error
	rewriteAfterPut uint32
	inserts         []uint32
	deletes         []uint32
}

type fakeKernelExperimentalProgram struct {
	program *ebpf.Program
}

func (*fakeKernelExperimentalProgram) ID() (uint32, error) { return 8001, nil }
func (*fakeKernelExperimentalProgram) Close() error        { return nil }
func (program *fakeKernelExperimentalProgram) kernelProgram() *ebpf.Program {
	return program.program
}

type flagCaptureProgramArrayMap struct {
	flags ebpf.MapUpdateFlags
	value any
}

func (*flagCaptureProgramArrayMap) Lookup(any, any) error { return ebpf.ErrKeyNotExist }
func (resource *flagCaptureProgramArrayMap) Update(
	_ any,
	value any,
	flags ebpf.MapUpdateFlags,
) error {
	resource.flags = flags
	resource.value = value
	return nil
}
func (*flagCaptureProgramArrayMap) Delete(any) error { return nil }
func (*flagCaptureProgramArrayMap) Close() error     { return nil }

func (programs *memoryFakeTCPProgramArray) LookupProgramID(slot uint32) (uint32, error) {
	if programs.events != nil {
		*programs.events = append(*programs.events, "program-lookup")
	}
	if programs.lookupErr != nil {
		err := programs.lookupErr
		programs.lookupErr = nil
		return 0, err
	}
	id, exists := programs.entries[slot]
	if !exists {
		return 0, ebpf.ErrKeyNotExist
	}
	return id, nil
}

func (programs *memoryFakeTCPProgramArray) InsertProgram(
	slot uint32,
	program experimentalProgramResource,
) error {
	if programs.events != nil {
		*programs.events = append(*programs.events, "program-insert")
	}
	programs.inserts = append(programs.inserts, slot)
	if programs.insertErr != nil {
		return programs.insertErr
	}
	if _, exists := programs.entries[slot]; exists {
		return errors.New("program bank exists")
	}
	id, err := program.ID()
	if err != nil {
		return err
	}
	programs.entries[slot] = id
	if programs.rewriteAfterPut != 0 {
		programs.entries[slot] = programs.rewriteAfterPut
	}
	return nil
}

func (programs *memoryFakeTCPProgramArray) DeleteProgram(slot uint32) error {
	if programs.events != nil {
		*programs.events = append(*programs.events, "program-delete")
	}
	programs.deletes = append(programs.deletes, slot)
	if programs.deleteErr != nil {
		return programs.deleteErr
	}
	delete(programs.entries, slot)
	return nil
}

func TestFakeTCPEgressProgramStageOwnsGenerationBankAndRollsBack(t *testing.T) {
	ctx, transaction, _ := newTestFakeTCPPolicyGenerationTransaction(t, 91)
	programs := &memoryFakeTCPProgramArray{entries: make(map[uint32]uint32)}
	program := &fakeExperimentalOwnedProgram{id: 8001}

	stage, err := stageFakeTCPEgressProgram(ctx, transaction, programs, program)
	if err != nil {
		t.Fatal(err)
	}
	if !stage.owned || stage.slot != 1 || programs.entries[1] != 8001 {
		t.Fatalf("stage = %#v entries=%v", stage, programs.entries)
	}
	if err := stage.Rollback(ctx, transaction); err != nil {
		t.Fatal(err)
	}
	if len(programs.entries) != 0 || len(programs.deletes) != 1 {
		t.Fatalf("rollback entries=%v deletes=%v", programs.entries, programs.deletes)
	}
	if err := stage.Rollback(ctx, transaction); err != nil || len(programs.deletes) != 1 {
		t.Fatalf("idempotent rollback error=%v deletes=%v", err, programs.deletes)
	}
}

func TestLiveFakeTCPProgramArrayUsesArrayCompatibleSingleWriterUpdate(t *testing.T) {
	resource := &flagCaptureProgramArrayMap{}
	kernelProgram := &ebpf.Program{}
	program := &fakeKernelExperimentalProgram{program: kernelProgram}
	programs := liveFakeTCPProgramArray{resource: resource}
	if err := programs.InsertProgram(1, program); err != nil {
		t.Fatal(err)
	}
	if resource.flags != ebpf.UpdateAny || resource.value != kernelProgram {
		t.Fatalf("program-array update flags=%v value=%T", resource.flags, resource.value)
	}
}

func TestFakeTCPEgressProgramStageBorrowsExactExistingBank(t *testing.T) {
	ctx, transaction, _ := newTestFakeTCPPolicyGenerationTransaction(t, 92)
	programs := &memoryFakeTCPProgramArray{entries: map[uint32]uint32{0: 8001}}
	program := &fakeExperimentalOwnedProgram{id: 8001}

	stage, err := stageFakeTCPEgressProgram(ctx, transaction, programs, program)
	if err != nil {
		t.Fatal(err)
	}
	if stage.owned || len(programs.inserts) != 0 {
		t.Fatalf("exact existing bank was claimed: stage=%#v inserts=%v", stage, programs.inserts)
	}
	if err := stage.Rollback(ctx, transaction); err != nil {
		t.Fatal(err)
	}
	if programs.entries[0] != 8001 || len(programs.deletes) != 0 {
		t.Fatalf("borrowed bank changed: entries=%v deletes=%v", programs.entries, programs.deletes)
	}
}

func TestFakeTCPEgressProgramStageRejectsDifferentExistingBank(t *testing.T) {
	ctx, transaction, _ := newTestFakeTCPPolicyGenerationTransaction(t, 91)
	programs := &memoryFakeTCPProgramArray{entries: map[uint32]uint32{1: 7001}}
	stage, err := stageFakeTCPEgressProgram(
		ctx, transaction, programs, &fakeExperimentalOwnedProgram{id: 8001},
	)
	if stage != nil || err == nil || !strings.Contains(err.Error(), "differs from desired") {
		t.Fatalf("stage=%#v error=%v", stage, err)
	}
	if len(programs.inserts) != 0 || len(programs.deletes) != 0 {
		t.Fatalf("different bank was mutated: inserts=%v deletes=%v", programs.inserts, programs.deletes)
	}
}

func TestFakeTCPEgressProgramStageReturnsRollbackHandleAfterReadbackDrift(t *testing.T) {
	ctx, transaction, _ := newTestFakeTCPPolicyGenerationTransaction(t, 91)
	programs := &memoryFakeTCPProgramArray{
		entries: make(map[uint32]uint32), rewriteAfterPut: 9001,
	}
	stage, err := stageFakeTCPEgressProgram(
		ctx, transaction, programs, &fakeExperimentalOwnedProgram{id: 8001},
	)
	if stage == nil || err == nil || !strings.Contains(err.Error(), "differs from inserted") {
		t.Fatalf("stage=%#v error=%v", stage, err)
	}
	if err := stage.Rollback(ctx, transaction); err == nil ||
		!strings.Contains(err.Error(), "refused") {
		t.Fatalf("changed-bank rollback error = %v", err)
	}
	if programs.entries[1] != 9001 || len(programs.deletes) != 0 {
		t.Fatalf("changed bank was deleted: entries=%v deletes=%v", programs.entries, programs.deletes)
	}
	programs.entries[1] = 8001
	if err := stage.Rollback(ctx, transaction); err != nil {
		t.Fatalf("retry exact rollback: %v", err)
	}
}

func TestFakeTCPEgressProgramStageDisarmRetainsOwnedBank(t *testing.T) {
	ctx, transaction, _ := newTestFakeTCPPolicyGenerationTransaction(t, 91)
	programs := &memoryFakeTCPProgramArray{entries: make(map[uint32]uint32)}
	stage, err := stageFakeTCPEgressProgram(
		ctx, transaction, programs, &fakeExperimentalOwnedProgram{id: 8001},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := stage.Disarm(); err != nil {
		t.Fatal(err)
	}
	if err := stage.Rollback(ctx, transaction); err != nil {
		t.Fatal(err)
	}
	if programs.entries[1] != 8001 || len(programs.deletes) != 0 {
		t.Fatalf("disarmed bank changed: entries=%v deletes=%v", programs.entries, programs.deletes)
	}
}
