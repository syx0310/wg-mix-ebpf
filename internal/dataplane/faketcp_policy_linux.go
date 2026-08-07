//go:build linux

package dataplane

import (
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

const (
	fakeTCPControlPolicyMapName = "faketcp_control_policy_map"
	fakeTCPManagedPortMapName   = "faketcp_managed_port_map"
	fakeTCPManagedIfMapName     = "faketcp_managed_if_map"
)

type fakeTCPPolicyMap interface {
	Lookup(key, valueOut any) error
	Update(key, value any, flags ebpf.MapUpdateFlags) error
	Delete(key any) error
}

type fakeTCPPolicyMaps struct {
	ControlPolicies   fakeTCPPolicyMap
	ManagedPorts      fakeTCPPolicyMap
	ManagedInterfaces fakeTCPPolicyMap
}

// stageFakeTCPPolicyGeneration stages one previously absent generation. The
// interface marker is the XDP reachability latch and is therefore always
// written last. This helper deliberately does not commit control_map or attach
// a program; those remain responsibilities of a future owner transaction.
func stageFakeTCPPolicyGeneration(
	maps fakeTCPPolicyMaps,
	snapshot *fakeTCPPolicySnapshot,
) (*fakeTCPPolicyStage, error) {
	if err := validateFakeTCPPolicySnapshot(snapshot); err != nil {
		return nil, fmt.Errorf("stage FakeTCP policy: %w", err)
	}
	if maps.ControlPolicies == nil || maps.ManagedPorts == nil || maps.ManagedInterfaces == nil {
		return nil, errors.New("stage FakeTCP policy: all three experimental policy maps are required")
	}

	operations := fakeTCPPolicyOperations(maps, snapshot)
	// Reject the whole target generation before the first write if any exact
	// key already exists. In particular, this prevents a reload from resetting
	// the BPF-owned virtual_time_nanos cursor.
	for _, operation := range operations {
		if err := operation.requireAbsent(); err != nil {
			return nil, fmt.Errorf("stage FakeTCP policy preflight %s: %w", operation.label, err)
		}
	}

	applied := make([]fakeTCPPolicyOperation, 0, len(operations))
	for _, operation := range operations {
		if err := operation.insert(); err != nil {
			return failFakeTCPPolicyStage(
				fmt.Errorf("stage FakeTCP policy insert %s: %w", operation.label, err),
				applied,
			)
		}
		applied = append(applied, operation)
		if err := operation.verify(); err != nil {
			return failFakeTCPPolicyStage(
				fmt.Errorf("stage FakeTCP policy verify %s: %w", operation.label, err),
				applied,
			)
		}
	}
	return &fakeTCPPolicyStage{operations: applied}, nil
}

const (
	fakeTCPPolicyStageActive uint8 = iota
	fakeTCPPolicyStageRollbackPending
	fakeTCPPolicyStageRolledBack
	fakeTCPPolicyStageDisarmed
)

// fakeTCPPolicyStage lets the future collection/XDP owner transaction undo a
// successful stage if a later attachment or owner-record commit fails. It owns
// only the exact keys and values inserted by stageFakeTCPPolicyGeneration.
type fakeTCPPolicyStage struct {
	mu         sync.Mutex
	operations []fakeTCPPolicyOperation
	state      uint8
}

// Rollback is idempotent after a complete rollback or Disarm. If an inserted
// value changed, Rollback refuses to delete that key and remains retryable.
func (stage *fakeTCPPolicyStage) Rollback() error {
	if stage == nil {
		return nil
	}
	stage.mu.Lock()
	defer stage.mu.Unlock()
	if stage.state == fakeTCPPolicyStageRolledBack || stage.state == fakeTCPPolicyStageDisarmed {
		return nil
	}
	stage.state = fakeTCPPolicyStageRollbackPending
	if err := rollbackFakeTCPPolicyOperations(stage.operations); err != nil {
		return err
	}
	stage.operations = nil
	stage.state = fakeTCPPolicyStageRolledBack
	return nil
}

// Disarm transfers responsibility for the staged entries to the successful
// outer transaction. It refuses to hide a partially failed rollback.
func (stage *fakeTCPPolicyStage) Disarm() error {
	if stage == nil {
		return nil
	}
	stage.mu.Lock()
	defer stage.mu.Unlock()
	switch stage.state {
	case fakeTCPPolicyStageActive:
		stage.operations = nil
		stage.state = fakeTCPPolicyStageDisarmed
		return nil
	case fakeTCPPolicyStageDisarmed:
		return nil
	case fakeTCPPolicyStageRollbackPending:
		return errors.New("cannot disarm FakeTCP policy stage after an incomplete rollback")
	default:
		return errors.New("cannot disarm a rolled-back FakeTCP policy stage")
	}
}

type fakeTCPPolicyOperation struct {
	label         string
	requireAbsent func() error
	insert        func() error
	verify        func() error
	rollback      func() error
}

func fakeTCPPolicyOperations(
	maps fakeTCPPolicyMaps,
	snapshot *fakeTCPPolicySnapshot,
) []fakeTCPPolicyOperation {
	operations := make([]fakeTCPPolicyOperation, 0,
		len(snapshot.ControlPolicies)+len(snapshot.ManagedPorts)+len(snapshot.ManagedInterfaces))

	policyKeys := make([]abi.FakeTCPControlPolicyKey, 0, len(snapshot.ControlPolicies))
	for key := range snapshot.ControlPolicies {
		policyKeys = append(policyKeys, key)
	}
	sort.Slice(policyKeys, func(i, j int) bool {
		return policyKeys[i].WGID < policyKeys[j].WGID
	})
	for _, key := range policyKeys {
		operations = append(operations, newFakeTCPPolicyOperation(
			maps.ControlPolicies,
			fakeTCPControlPolicyMapName,
			key,
			snapshot.ControlPolicies[key],
		))
	}

	portKeys := make([]abi.FakeTCPManagedPortKey, 0, len(snapshot.ManagedPorts))
	for key := range snapshot.ManagedPorts {
		portKeys = append(portKeys, key)
	}
	sort.Slice(portKeys, func(i, j int) bool {
		if portKeys[i].UnderlayIndex != portKeys[j].UnderlayIndex {
			return portKeys[i].UnderlayIndex < portKeys[j].UnderlayIndex
		}
		return portKeys[i].DestinationPort < portKeys[j].DestinationPort
	})
	for _, key := range portKeys {
		operations = append(operations, newFakeTCPPolicyOperation(
			maps.ManagedPorts,
			fakeTCPManagedPortMapName,
			key,
			snapshot.ManagedPorts[key],
		))
	}

	interfaceKeys := make([]abi.FakeTCPManagedIfKey, 0, len(snapshot.ManagedInterfaces))
	for key := range snapshot.ManagedInterfaces {
		interfaceKeys = append(interfaceKeys, key)
	}
	sort.Slice(interfaceKeys, func(i, j int) bool {
		return interfaceKeys[i].UnderlayIndex < interfaceKeys[j].UnderlayIndex
	})
	for _, key := range interfaceKeys {
		operations = append(operations, newFakeTCPPolicyOperation(
			maps.ManagedInterfaces,
			fakeTCPManagedIfMapName,
			key,
			snapshot.ManagedInterfaces[key],
		))
	}
	return operations
}

func newFakeTCPPolicyOperation[K comparable, V comparable](
	m fakeTCPPolicyMap,
	mapName string,
	key K,
	value V,
) fakeTCPPolicyOperation {
	label := fmt.Sprintf("%s key=%#v", mapName, key)
	lookup := func() (V, error) {
		var actual V
		err := m.Lookup(key, &actual)
		return actual, err
	}
	return fakeTCPPolicyOperation{
		label: label,
		requireAbsent: func() error {
			_, err := lookup()
			switch {
			case err == nil:
				return errors.New("exact key already exists")
			case errors.Is(err, ebpf.ErrKeyNotExist):
				return nil
			default:
				return fmt.Errorf("lookup existing key: %w", err)
			}
		},
		insert: func() error {
			if err := m.Update(key, value, ebpf.UpdateNoExist); err != nil {
				return err
			}
			return nil
		},
		verify: func() error {
			actual, err := lookup()
			if err != nil {
				return fmt.Errorf("read back inserted value: %w", err)
			}
			if actual != value {
				return errors.New("read back value differs from inserted value")
			}
			return nil
		},
		rollback: func() error {
			actual, err := lookup()
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return nil
			}
			if err != nil {
				return fmt.Errorf("read back before rollback: %w", err)
			}
			if actual != value {
				return errors.New("refusing rollback because inserted value changed")
			}
			if err := m.Delete(key); err != nil {
				return fmt.Errorf("delete exact inserted key: %w", err)
			}
			return nil
		},
	}
}

func failFakeTCPPolicyStage(
	cause error,
	applied []fakeTCPPolicyOperation,
) (*fakeTCPPolicyStage, error) {
	rollbackErr := rollbackFakeTCPPolicyOperations(applied)
	if rollbackErr != nil {
		return &fakeTCPPolicyStage{
			operations: applied,
			state:      fakeTCPPolicyStageRollbackPending,
		}, errors.Join(cause, fmt.Errorf("FakeTCP policy rollback incomplete: %w", rollbackErr))
	}
	return nil, cause
}

func rollbackFakeTCPPolicyOperations(applied []fakeTCPPolicyOperation) error {
	var rollbackErrors []error
	for index := len(applied) - 1; index >= 0; index-- {
		if err := applied[index].rollback(); err != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf(
				"rollback %s: %w", applied[index].label, err,
			))
		}
	}
	return errors.Join(rollbackErrors...)
}
