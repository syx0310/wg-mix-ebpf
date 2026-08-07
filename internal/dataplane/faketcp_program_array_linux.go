//go:build linux

package dataplane

import (
	"context"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
)

const fakeTCPEgressProgramArrayMapName = "faketcp_egress_programs"

type fakeTCPProgramArray interface {
	LookupProgramID(uint32) (uint32, error)
	InsertProgram(uint32, experimentalProgramResource) error
	DeleteProgram(uint32) error
}

type fakeTCPPolicyGenerationLeaseAccess interface {
	assertHeld(context.Context) error
	policyGeneration() uint64
}

type liveFakeTCPProgramArray struct {
	resource experimentalMapResource
}

func (programs liveFakeTCPProgramArray) LookupProgramID(slot uint32) (uint32, error) {
	var id uint32
	if err := programs.resource.Lookup(slot, &id); err != nil {
		return 0, err
	}
	return id, nil
}

func (programs liveFakeTCPProgramArray) InsertProgram(
	slot uint32,
	program experimentalProgramResource,
) error {
	if program == nil || program.kernelProgram() == nil {
		return errors.New("insert FakeTCP tail program: live kernel program is unavailable")
	}
	// Program arrays are array-like maps: BPF_NOEXIST is not a usable empty-
	// slot primitive. The retained lifecycle lease supplies the single-writer
	// exclusion between the preceding lookup and this BPF_ANY update; exact-ID
	// readback and rollback comparisons detect any non-cooperating mutation.
	return programs.resource.Update(slot, program.kernelProgram(), ebpf.UpdateAny)
}

func (programs liveFakeTCPProgramArray) DeleteProgram(slot uint32) error {
	return programs.resource.Delete(slot)
}

const (
	fakeTCPProgramArrayStageActive uint8 = iota
	fakeTCPProgramArrayStageRolledBack
	fakeTCPProgramArrayStageDisarmed
)

// fakeTCPProgramArrayStage owns only a newly inserted generation bank. An
// already-present exact program ID is borrowed and is never deleted by this
// stage. This lets two adjacent generations share one collection without
// turning rollback into an overwrite of a still-live bank.
type fakeTCPProgramArrayStage struct {
	programs  fakeTCPProgramArray
	slot      uint32
	programID uint32
	owned     bool
	state     uint8
}

func stageFakeTCPEgressProgram(
	ctx context.Context,
	leaseAccess fakeTCPPolicyGenerationLeaseAccess,
	programs fakeTCPProgramArray,
	program experimentalProgramResource,
) (*fakeTCPProgramArrayStage, error) {
	if leaseAccess == nil {
		return nil, fmt.Errorf("stage FakeTCP egress program: %w", errFakeTCPPolicyGenerationLeaseRequired)
	}
	if programs == nil {
		return nil, errors.New("stage FakeTCP egress program: program array is nil")
	}
	if program == nil {
		return nil, errors.New("stage FakeTCP egress program: program is nil")
	}
	if err := leaseAccess.assertHeld(ctx); err != nil {
		return nil, fmt.Errorf("stage FakeTCP egress program: %w", err)
	}
	programID, err := program.ID()
	if err != nil {
		return nil, fmt.Errorf("stage FakeTCP egress program: inspect program identity: %w", err)
	}
	if programID == 0 {
		return nil, errors.New("stage FakeTCP egress program: program ID is zero")
	}
	slot := uint32(leaseAccess.policyGeneration() & 1)
	actual, err := programs.LookupProgramID(slot)
	switch {
	case err == nil:
		if actual != programID {
			return nil, fmt.Errorf(
				"stage FakeTCP egress program bank %d: existing program ID %d differs from desired ID %d",
				slot, actual, programID,
			)
		}
		return &fakeTCPProgramArrayStage{
			programs: programs, slot: slot, programID: programID,
		}, nil
	case !errors.Is(err, ebpf.ErrKeyNotExist):
		return nil, fmt.Errorf("stage FakeTCP egress program bank %d preflight: %w", slot, err)
	}

	if err := programs.InsertProgram(slot, program); err != nil {
		return nil, fmt.Errorf("stage FakeTCP egress program bank %d insert: %w", slot, err)
	}
	stage := &fakeTCPProgramArrayStage{
		programs: programs, slot: slot, programID: programID, owned: true,
	}
	if err := leaseAccess.assertHeld(ctx); err != nil {
		return stage, fmt.Errorf("stage FakeTCP egress program bank %d lost ownership: %w", slot, err)
	}
	actual, err = programs.LookupProgramID(slot)
	if err != nil {
		return stage, fmt.Errorf("stage FakeTCP egress program bank %d verify: %w", slot, err)
	}
	if actual != programID {
		return stage, fmt.Errorf(
			"stage FakeTCP egress program bank %d verify: program ID %d differs from inserted ID %d",
			slot, actual, programID,
		)
	}
	return stage, nil
}

func (stage *fakeTCPProgramArrayStage) Rollback(
	ctx context.Context,
	leaseAccess fakeTCPPolicyGenerationLeaseAccess,
) error {
	if stage == nil || stage.state == fakeTCPProgramArrayStageRolledBack ||
		stage.state == fakeTCPProgramArrayStageDisarmed {
		return nil
	}
	if leaseAccess == nil {
		return errFakeTCPPolicyGenerationLeaseRequired
	}
	if err := leaseAccess.assertHeld(ctx); err != nil {
		return fmt.Errorf("rollback FakeTCP egress program: %w", err)
	}
	if !stage.owned {
		stage.state = fakeTCPProgramArrayStageRolledBack
		return nil
	}
	actual, err := stage.programs.LookupProgramID(stage.slot)
	switch {
	case errors.Is(err, ebpf.ErrKeyNotExist):
		stage.state = fakeTCPProgramArrayStageRolledBack
		return nil
	case err != nil:
		return fmt.Errorf("rollback FakeTCP egress program bank %d lookup: %w", stage.slot, err)
	case actual != stage.programID:
		return fmt.Errorf(
			"rollback FakeTCP egress program bank %d refused: program ID changed from %d to %d",
			stage.slot, stage.programID, actual,
		)
	}
	if err := stage.programs.DeleteProgram(stage.slot); err != nil &&
		!errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("rollback FakeTCP egress program bank %d delete: %w", stage.slot, err)
	}
	actual, err = stage.programs.LookupProgramID(stage.slot)
	switch {
	case errors.Is(err, ebpf.ErrKeyNotExist):
		stage.state = fakeTCPProgramArrayStageRolledBack
		stage.owned = false
		return nil
	case err != nil:
		return fmt.Errorf("rollback FakeTCP egress program bank %d confirm absent: %w", stage.slot, err)
	default:
		return fmt.Errorf(
			"rollback FakeTCP egress program bank %d failed: program ID %d remains",
			stage.slot, actual,
		)
	}
}

func (stage *fakeTCPProgramArrayStage) Disarm() error {
	if stage == nil || stage.state == fakeTCPProgramArrayStageDisarmed {
		return nil
	}
	if stage.state == fakeTCPProgramArrayStageRolledBack {
		return errors.New("cannot disarm a rolled-back FakeTCP egress program stage")
	}
	stage.state = fakeTCPProgramArrayStageDisarmed
	return nil
}
