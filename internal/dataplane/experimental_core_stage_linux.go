//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/syx0310/wg-mix-ebpf/internal/abi"
	"github.com/syx0310/wg-mix-ebpf/internal/control"
)

type experimentalCoreProgramFD func(experimentalProgramResource) (uint32, error)

type experimentalCoreStageDependencies struct {
	programFD experimentalCoreProgramFD
}

type experimentalCoreDataMapResource struct {
	name     string
	resource experimentalMapResource
}

type experimentalCoreTailCallResources struct {
	mapName  string
	array    experimentalMapResource
	programs [xorSegmentCount]experimentalProgramResource
}

// experimentalCoreResources is a borrowed, immutable resource bundle resolved
// before the fresh-collection callback takes collection.mu. No owner accessor
// may be called while that callback is active because its lock is deliberately
// held across seed, staging, and commit.
type experimentalCoreResources struct {
	control   experimentalMapResource
	dataMaps  []experimentalCoreDataMapResource
	tailCalls []experimentalCoreTailCallResources
}

type experimentalCoreMapChange struct {
	name     string
	resource experimentalMapResource
	key      any
	expected any
}

// experimentalCoreStage owns all baseline map and XOR tail-call writes made
// in one fresh unpinned collection.  control_map remains zero while staging;
// CommitControl is the only operation that makes TC/XDP selectors reach the
// generation.  Close first deactivates that exact control value, then removes
// only entries whose values still match this stage.
type experimentalCoreStage struct {
	mu sync.Mutex

	control          experimentalMapResource
	controlValue     abi.ControlValue
	controlCommitted bool
	changes          []experimentalCoreMapChange
	closed           bool
	closeErr         error
}

func resolveExperimentalCoreResources(
	owner *experimentalCollectionOwner,
) (experimentalCoreResources, error) {
	if owner == nil {
		return experimentalCoreResources{}, errors.New("resolve experimental baseline core: collection owner is nil")
	}
	control, err := owner.mapResource("control_map")
	if err != nil {
		return experimentalCoreResources{}, err
	}
	resources := experimentalCoreResources{control: control}
	for _, name := range []string{
		"profile_map",
		"cipher_map",
		"underlay_config_map",
		"managed_fwmark_map",
		"egress_rule_map",
		"ingress_listener_map",
		"icmp_listener_map",
	} {
		resource, err := owner.mapResource(name)
		if err != nil {
			return experimentalCoreResources{}, err
		}
		resources.dataMaps = append(resources.dataMaps, experimentalCoreDataMapResource{
			name: name, resource: resource,
		})
	}
	for _, binding := range xorTailCallBindings {
		array, err := owner.mapResource(binding.mapName)
		if err != nil {
			return experimentalCoreResources{}, err
		}
		resolved := experimentalCoreTailCallResources{
			mapName: binding.mapName,
			array:   array,
		}
		for segment, programName := range binding.programNames {
			program, err := owner.programResource(programName)
			if err != nil {
				return experimentalCoreResources{}, err
			}
			resolved.programs[segment] = program
		}
		resources.tailCalls = append(resources.tailCalls, resolved)
	}
	return resources, nil
}

func stageExperimentalCoreCollection(
	ctx context.Context,
	resources experimentalCoreResources,
	snapshot *abi.Snapshot,
	dependencies experimentalCoreStageDependencies,
) (_ *experimentalCoreStage, returnErr error) {
	if ctx == nil {
		return nil, errors.New("stage experimental baseline core: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if resources.control == nil {
		return nil, errors.New("stage experimental baseline core: resource bundle is incomplete")
	}
	if snapshot == nil {
		return nil, errors.New("stage experimental baseline core: snapshot is nil")
	}
	controlValue, ok := snapshot.Control[abi.ControlKeyGlobal]
	if !ok || controlValue.ActiveGeneration == 0 || controlValue.ABIVersion != abi.Version ||
		controlValue.Flags != 0 {
		return nil, errors.New("stage experimental baseline core: control snapshot is invalid")
	}
	if dependencies.programFD == nil {
		dependencies.programFD = liveExperimentalCoreProgramFD
	}
	control := resources.control
	var inactive abi.ControlValue
	if err := control.Lookup(abi.ControlKeyGlobal, &inactive); err != nil {
		return nil, fmt.Errorf("read fresh experimental control map: %w", err)
	}
	if inactive != (abi.ControlValue{}) {
		return nil, errors.New("fresh experimental control map is already active")
	}
	stage := &experimentalCoreStage{
		control:      control,
		controlValue: controlValue,
	}
	defer func() {
		if returnErr == nil {
			return
		}
		returnErr = errors.Join(returnErr, stage.Close())
	}()

	if len(resources.dataMaps) != 7 || len(resources.tailCalls) != len(xorTailCallBindings) {
		return nil, errors.New("stage experimental baseline core: resource bundle has the wrong shape")
	}
	for index, apply := range []func(experimentalMapResource, string) error{
		func(resource experimentalMapResource, name string) error {
			return stage.stageMap(resource, name, snapshot.Profiles)
		},
		func(resource experimentalMapResource, name string) error {
			return stage.stageMap(resource, name, snapshot.Ciphers)
		},
		func(resource experimentalMapResource, name string) error {
			return stage.stageMap(resource, name, snapshot.Underlays)
		},
		func(resource experimentalMapResource, name string) error {
			return stage.stageMap(resource, name, snapshot.ManagedFwmarks)
		},
		func(resource experimentalMapResource, name string) error {
			return stage.stageMap(resource, name, snapshot.EgressRules)
		},
		func(resource experimentalMapResource, name string) error {
			return stage.stageMap(resource, name, snapshot.IngressListeners)
		},
		func(resource experimentalMapResource, name string) error {
			return stage.stageMap(resource, name, snapshot.ICMPListeners)
		},
	} {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		resource := resources.dataMaps[index]
		if err := apply(resource.resource, resource.name); err != nil {
			return nil, err
		}
	}
	bankStart := xorTailCallBankStart(controlValue.ActiveGeneration)
	for _, binding := range resources.tailCalls {
		if binding.array == nil {
			return nil, fmt.Errorf("stage experimental program array %s: resource is nil", binding.mapName)
		}
		for segment, program := range binding.programs {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if program == nil {
				return nil, fmt.Errorf("stage experimental program array %s[%d]: program is nil", binding.mapName, segment)
			}
			fd, err := dependencies.programFD(program)
			if err != nil {
				return nil, fmt.Errorf("resolve experimental XOR program %s[%d]: %w", binding.mapName, segment, err)
			}
			programID, err := program.ID()
			if err != nil {
				return nil, fmt.Errorf("resolve experimental XOR program ID %s[%d]: %w", binding.mapName, segment, err)
			}
			index := bankStart + uint32(segment)
			var existing uint32
			if err := binding.array.Lookup(index, &existing); !errors.Is(err, ebpf.ErrKeyNotExist) {
				if err == nil {
					return nil, fmt.Errorf("fresh experimental program array %s[%d] is occupied", binding.mapName, index)
				}
				return nil, fmt.Errorf("inspect experimental program array %s[%d]: %w", binding.mapName, index, err)
			}
			if err := binding.array.Update(index, fd, ebpf.UpdateAny); err != nil {
				return nil, fmt.Errorf("stage experimental program array %s[%d]: %w", binding.mapName, index, err)
			}
			stage.changes = append(stage.changes, experimentalCoreMapChange{
				name: binding.mapName, resource: binding.array,
				key: index, expected: programID,
			})
			if err := binding.array.Lookup(index, &existing); err != nil {
				return nil, fmt.Errorf("verify experimental program array %s[%d]: %w", binding.mapName, index, err)
			}
			if existing != programID {
				return nil, fmt.Errorf(
					"verify experimental program array %s[%d]: program ID %d differs from inserted ID %d",
					binding.mapName, index, existing, programID,
				)
			}
		}
	}
	return stage, nil
}

func (stage *experimentalCoreStage) stageMap(
	resource experimentalMapResource,
	name string,
	entries any,
) error {
	if resource == nil {
		return fmt.Errorf("stage experimental map %s: resource is nil", name)
	}
	value := reflect.ValueOf(entries)
	if value.Kind() != reflect.Map {
		return fmt.Errorf("stage experimental map %s: entries are not a map", name)
	}
	keys := value.MapKeys()
	sort.Slice(keys, func(i, j int) bool {
		left, _ := json.Marshal(keys[i].Interface())
		right, _ := json.Marshal(keys[j].Interface())
		return bytes.Compare(left, right) < 0
	})
	for _, keyValue := range keys {
		key := keyValue.Interface()
		entry := value.MapIndex(keyValue).Interface()
		if err := resource.Update(key, entry, ebpf.UpdateNoExist); err != nil {
			return fmt.Errorf("stage experimental map %s: %w", name, err)
		}
		stage.changes = append(stage.changes, experimentalCoreMapChange{
			name: name, resource: resource, key: key, expected: entry,
		})
		observed := reflect.New(reflect.TypeOf(entry))
		if err := resource.Lookup(key, observed.Interface()); err != nil {
			return fmt.Errorf("verify experimental map %s: %w", name, err)
		}
		if !reflect.DeepEqual(observed.Elem().Interface(), entry) {
			return fmt.Errorf("verify experimental map %s: value differs from inserted value", name)
		}
	}
	return nil
}

func (stage *experimentalCoreStage) CommitControl() error {
	if stage == nil {
		return errors.New("commit experimental baseline core: stage is nil")
	}
	stage.mu.Lock()
	defer stage.mu.Unlock()
	if stage.closed {
		return errors.New("commit experimental baseline core: stage is closed")
	}
	if stage.controlCommitted {
		return errors.New("commit experimental baseline core: control is already committed")
	}
	if err := stage.control.Update(
		abi.ControlKeyGlobal,
		stage.controlValue,
		ebpf.UpdateAny,
	); err != nil {
		return fmt.Errorf("commit experimental baseline control map: %w", err)
	}
	// Update is the reachability point. From here onward Close must attempt an
	// exact deactivation even when readback itself fails.
	stage.controlCommitted = true
	var observed abi.ControlValue
	if err := stage.control.Lookup(abi.ControlKeyGlobal, &observed); err != nil {
		return fmt.Errorf("verify experimental baseline control map: %w", err)
	}
	if observed != stage.controlValue {
		return errors.New("verify experimental baseline control map: committed value changed")
	}
	return nil
}

func (stage *experimentalCoreStage) Close() error {
	if stage == nil {
		return nil
	}
	stage.mu.Lock()
	defer stage.mu.Unlock()
	if stage.closed {
		return stage.closeErr
	}
	if err := stage.deactivateLocked(); err != nil {
		stage.closeErr = err
		return stage.closeErr
	}
	var errs []error
	var remaining []experimentalCoreMapChange
	for index := len(stage.changes) - 1; index >= 0; index-- {
		change := stage.changes[index]
		observed := reflect.New(reflect.TypeOf(change.expected))
		if err := change.resource.Lookup(change.key, observed.Interface()); err != nil {
			if !errors.Is(err, ebpf.ErrKeyNotExist) {
				errs = append(errs, fmt.Errorf("read experimental map %s before rollback: %w", change.name, err))
				remaining = append([]experimentalCoreMapChange{change}, remaining...)
			}
			continue
		}
		if !reflect.DeepEqual(observed.Elem().Interface(), change.expected) {
			errs = append(errs, fmt.Errorf("refuse rollback of experimental map %s because its value changed", change.name))
			remaining = append([]experimentalCoreMapChange{change}, remaining...)
			continue
		}
		if err := change.resource.Delete(change.key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("rollback experimental map %s: %w", change.name, err))
			remaining = append([]experimentalCoreMapChange{change}, remaining...)
			continue
		}
		if err := change.resource.Lookup(change.key, observed.Interface()); err != nil {
			if !errors.Is(err, ebpf.ErrKeyNotExist) {
				errs = append(errs, fmt.Errorf("verify rollback of experimental map %s: %w", change.name, err))
				remaining = append([]experimentalCoreMapChange{change}, remaining...)
			}
			continue
		}
		errs = append(errs, fmt.Errorf("verify rollback of experimental map %s: key remains", change.name))
		remaining = append([]experimentalCoreMapChange{change}, remaining...)
	}
	stage.changes = remaining
	stage.closeErr = errors.Join(errs...)
	stage.closed = len(stage.changes) == 0
	return stage.closeErr
}

// Deactivate verifies that this stage still owns the exact active selector,
// writes zero, and verifies zero before any dependent map is removed. A
// failure deliberately leaves controlCommitted set so Close cannot dismantle
// baseline data while attached programs might still select it.
func (stage *experimentalCoreStage) Deactivate() error {
	if stage == nil {
		return nil
	}
	stage.mu.Lock()
	defer stage.mu.Unlock()
	if stage.closed {
		return stage.closeErr
	}
	return stage.deactivateLocked()
}

func (stage *experimentalCoreStage) deactivateLocked() error {
	if !stage.controlCommitted {
		return nil
	}
	var observed abi.ControlValue
	if err := stage.control.Lookup(abi.ControlKeyGlobal, &observed); err != nil {
		return fmt.Errorf("read experimental control map before deactivate: %w", err)
	}
	zero := abi.ControlValue{}
	if observed == zero {
		// A prior zero write may have succeeded even though Update or its
		// readback reported an error. Observed zero is the authoritative
		// inactive state, so retry converges without issuing another write.
		stage.controlCommitted = false
		return nil
	}
	if observed != stage.controlValue {
		return errors.New("refuse to deactivate experimental control map because its value changed")
	}
	if err := stage.control.Update(abi.ControlKeyGlobal, zero, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("deactivate experimental control map: %w", err)
	}
	if err := stage.control.Lookup(abi.ControlKeyGlobal, &observed); err != nil {
		return fmt.Errorf("verify inactive experimental control map: %w", err)
	}
	if observed != zero {
		return errors.New("verify inactive experimental control map: value is non-zero")
	}
	stage.controlCommitted = false
	return nil
}

func liveExperimentalCoreProgramFD(program experimentalProgramResource) (uint32, error) {
	if program == nil || program.kernelProgram() == nil {
		return 0, errors.New("experimental program is not a live eBPF program")
	}
	fd := program.kernelProgram().FD()
	if fd < 0 {
		return 0, errors.New("experimental program has an invalid file descriptor")
	}
	return uint32(fd), nil
}

func stageLiveExperimentalTC(
	ctx context.Context,
	state *control.State,
	ingress experimentalProgramResource,
	egress experimentalProgramResource,
	commit func() error,
) (experimentalTCStageOwner, error) {
	if ctx == nil {
		return nil, errors.New("stage experimental TC core: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if state == nil {
		return nil, errors.New("stage experimental TC core: attach state is nil")
	}
	ingressIdentity, err := tcProgramIdentityFromProgram(ingress.kernelProgram())
	if err != nil {
		return nil, fmt.Errorf("resolve experimental ingress TC program: %w", err)
	}
	egressIdentity, err := tcProgramIdentityFromProgram(egress.kernelProgram())
	if err != nil {
		return nil, fmt.Errorf("resolve experimental egress TC program: %w", err)
	}
	plan, err := prepareTCAttachPlan(state, ingressIdentity, egressIdentity, liveTCRuntime)
	if err != nil {
		return nil, fmt.Errorf("prepare experimental TC core: %w", err)
	}
	return executeFreshExperimentalTCPlan(plan, commit)
}

func executeFreshExperimentalTCPlan(
	plan *tcAttachPlan,
	commit func() error,
) (experimentalTCStageOwner, error) {
	if plan == nil {
		return nil, errors.New("execute fresh experimental TC core: plan is nil")
	}
	// Experimental generations have no persistent TC owner record. A reserved
	// slot that merely looks managed is therefore foreign and must never be
	// replaced on first activation.
	if err := plan.ValidatePreviousBindings(nil, true); err != nil {
		return nil, errors.Join(
			fmt.Errorf("validate fresh experimental TC ownership: %w", err),
			plan.Close(),
		)
	}
	stage, err := plan.ExecuteRetained(commit)
	if err != nil {
		if stage != nil {
			return stage, err
		}
		return nil, errors.Join(err, plan.Close())
	}
	return stage, nil
}
