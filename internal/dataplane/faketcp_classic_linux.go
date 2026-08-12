//go:build linux

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/control"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type fakeTCPClassicOwnerResources struct {
	parent *pinPathParent
	lock   *pinPathLock
	store  *fakeTCPClassicOwnerStore
}

func openFakeTCPClassicOwnerResources(
	ctx context.Context,
	scope fakeTCPProductionScopeIdentity,
	runtime pinPathRuntime,
	action string,
	createStore bool,
) (*fakeTCPClassicOwnerResources, error) {
	validated, err := validatePinPath(scope.pinPath, runtime.validator)
	if err != nil {
		return nil, fmt.Errorf("validate FakeTCP classic owner pin scope: %w", err)
	}
	parent, err := openPinPathParent(scope.pinPath, validated, runtime)
	if err != nil {
		return nil, fmt.Errorf("open FakeTCP classic owner pin scope: %w", err)
	}
	resources := &fakeTCPClassicOwnerResources{parent: parent}
	fail := func(cause error) (*fakeTCPClassicOwnerResources, error) {
		return nil, errors.Join(cause, resources.Close())
	}
	resources.lock, err = acquirePinPathLock(ctx, parent.resource, action, runtime)
	if err != nil {
		return fail(fmt.Errorf("lock FakeTCP classic owner: %w", err))
	}
	resources.store, err = openFakeTCPClassicOwnerStore(runtime, parent.resource, createStore)
	if err != nil {
		return fail(err)
	}
	return resources, nil
}

func (resources *fakeTCPClassicOwnerResources) Close() error {
	if resources == nil {
		return nil
	}
	var errs []error
	if resources.store != nil {
		if err := resources.store.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close FakeTCP classic owner store: %w", err))
		} else {
			resources.store = nil
		}
	}
	if resources.lock != nil {
		if err := resources.lock.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close FakeTCP classic owner lock: %w", err))
		} else {
			resources.lock = nil
		}
	}
	if resources.parent != nil {
		if err := resources.parent.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close FakeTCP classic pin scope: %w", err))
		} else {
			resources.parent = nil
		}
	}
	return errors.Join(errs...)
}

// inspectFakeTCPClassicOwnerEvidence is read-only. It is used during
// production planning, before the coordinator is allowed to detach a working
// baseline. A published owner makes auto sticky to classic_tc; an interrupted
// unpublished next file only schedules recovery before the first build write.
func inspectFakeTCPClassicOwnerEvidence(
	scope fakeTCPProductionScopeIdentity,
	runtime pinPathRuntime,
) (record *fakeTCPClassicOwnerRecord, published bool, recovery bool, returnErr error) {
	validated, err := validatePinPath(scope.pinPath, runtime.validator)
	if err != nil {
		return nil, false, false, err
	}
	parent, err := openPinPathParent(scope.pinPath, validated, runtime)
	if err != nil {
		return nil, false, false, err
	}
	defer func() {
		returnErr = errors.Join(
			returnErr,
			wrapNonNilError("close FakeTCP classic owner pin scope inspection", parent.Close()),
		)
	}()
	store, err := openFakeTCPClassicOwnerStore(runtime, parent.resource, false)
	if errors.Is(err, unix.ENOENT) {
		return nil, false, false, nil
	}
	if err != nil {
		return nil, false, false, err
	}
	defer func() {
		returnErr = errors.Join(
			returnErr,
			wrapNonNilError("close FakeTCP classic owner journal inspection", store.Close()),
		)
	}()
	record, published, err = store.LoadOptional()
	if err != nil {
		return nil, false, false, err
	}
	if published {
		return record, true, true, nil
	}
	var stat unix.Stat_t
	err = unix.Fstatat(store.root.FD(), store.nextName, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil, false, false, nil
	}
	if err != nil {
		return nil, false, false, err
	}
	file, identity, err := openExistingAnchoredRegularFile(
		store.root, store.nextName, 0o600, store.expectedUID,
	)
	if err != nil {
		return nil, false, false, err
	}
	defer file.Close()
	if _, err := validateAnchoredRegularFile(
		store.root, store.nextName, int(file.Fd()), 0o600, store.expectedUID, &identity,
	); err != nil {
		return nil, false, false, err
	}
	return nil, false, true, nil
}

func resolveFakeTCPProductionAttachmentBackend(
	state *control.State,
	scope fakeTCPProductionScopeIdentity,
	runtime pinPathRuntime,
) (backend string, recoverClassic bool, err error) {
	if state == nil {
		return "", false, errors.New("resolve production FakeTCP attachment backend: state is nil")
	}
	_, classicPublished, classicRecovery, err := inspectFakeTCPClassicOwnerEvidence(scope, runtime)
	if err != nil {
		return "", false, fmt.Errorf("inspect durable FakeTCP classic owner: %w", err)
	}
	configured := state.AttachmentBackend
	if configured == "" {
		configured = attachmentBackendAuto
	}
	if configured == attachmentBackendAuto && classicPublished {
		return classicTCBackend, true, nil
	}
	backend, err = resolveAttachmentBackend(state, runtime.exactTCX)
	if err != nil {
		return "", false, err
	}
	return backend, classicRecovery, nil
}

func recoverFakeTCPProductionClassicOwner(
	ctx context.Context,
	scope fakeTCPProductionScopeIdentity,
	runtime pinPathRuntime,
) error {
	resources, err := openFakeTCPClassicOwnerResources(
		ctx, scope, runtime, "recover-faketcp-classic", false,
	)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := resources.store.recoverNext(); err != nil {
		return errors.Join(err, resources.Close())
	}
	record, exists, err := resources.store.LoadOptional()
	if err != nil {
		return errors.Join(err, resources.Close())
	}
	if !exists {
		return resources.Close()
	}
	stage := &productionFakeTCPClassicStage{
		runtime:   runtime.classicTC,
		bootID:    runtime.bootID,
		now:       runtime.now,
		resources: resources,
		record:    record,
		bindings:  slices.Clone(record.ActiveFilters),
	}
	if err := stage.Close(); err != nil {
		return errors.Join(
			fmt.Errorf("recover durable FakeTCP classic owner: %w", err),
			wrapNonNilError(
				"close failed FakeTCP classic recovery resources", resources.Close(),
			),
		)
	}
	return nil
}

func experimentalTCProgramIdentityFromResource(
	label string,
	resource experimentalProgramResource,
) (tcProgramIdentity, error) {
	if resource == nil || resource.kernelProgram() == nil {
		return tcProgramIdentity{}, fmt.Errorf("production FakeTCP classic %s program is unavailable", label)
	}
	id, err := resource.ID()
	if err != nil {
		return tcProgramIdentity{}, fmt.Errorf("inspect production FakeTCP classic %s program: %w", label, err)
	}
	fd := resource.kernelProgram().FD()
	if id == 0 || fd < 0 {
		return tcProgramIdentity{}, fmt.Errorf("production FakeTCP classic %s program has invalid FD/ID", label)
	}
	return tcProgramIdentity{fd: fd, id: id}, nil
}

func stageProductionFakeTCPClassic(
	ctx context.Context,
	state *control.State,
	ingress experimentalProgramResource,
	egress experimentalProgramResource,
	commit func() error,
	runtime pinPathRuntime,
	scope fakeTCPProductionScopeIdentity,
	object ObjectIdentity,
) (*productionFakeTCPClassicStage, error) {
	ingressIdentity, err := experimentalTCProgramIdentityFromResource("ingress", ingress)
	if err != nil {
		return nil, err
	}
	egressIdentity, err := experimentalTCProgramIdentityFromResource("egress", egress)
	if err != nil {
		return nil, err
	}
	return stageProductionFakeTCPClassicWithPrograms(
		ctx, state, ingressIdentity, egressIdentity, commit, runtime, scope, object,
	)
}

func stageProductionFakeTCPClassicWithPrograms(
	ctx context.Context,
	state *control.State,
	ingress tcProgramIdentity,
	egress tcProgramIdentity,
	commit func() error,
	runtime pinPathRuntime,
	scope fakeTCPProductionScopeIdentity,
	object ObjectIdentity,
) (*productionFakeTCPClassicStage, error) {
	if ctx == nil {
		return nil, errors.New("stage production FakeTCP classic TC: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if state == nil || state.Generation == 0 || commit == nil {
		return nil, errors.New("stage production FakeTCP classic TC: inputs are incomplete")
	}
	if err := validateTCRuntime(runtime.classicTC); err != nil {
		return nil, fmt.Errorf("stage production FakeTCP classic TC: %w", err)
	}
	if runtime.bootID == nil || runtime.now == nil {
		return nil, errors.New("stage production FakeTCP classic TC: owner clock/boot runtime is unavailable")
	}
	resources, err := openFakeTCPClassicOwnerResources(
		ctx, scope, runtime, "attach-faketcp-classic", true,
	)
	if err != nil {
		return nil, err
	}
	failWithoutOwner := func(cause error) (*productionFakeTCPClassicStage, error) {
		return nil, errors.Join(cause, resources.Close())
	}
	if err := resources.store.recoverNext(); err != nil {
		return failWithoutOwner(err)
	}
	if existing, exists, err := resources.store.LoadOptional(); err != nil {
		return failWithoutOwner(err)
	} else if exists {
		return failWithoutOwner(fmt.Errorf(
			"stage production FakeTCP classic TC: durable owner sequence %d/%s already exists",
			existing.Sequence, existing.Phase,
		))
	}
	attachPlan, err := prepareTCAttachPlan(
		state, ingress, egress, runtime.classicTC,
	)
	if err != nil {
		return failWithoutOwner(fmt.Errorf("preflight production FakeTCP classic TC: %w", err))
	}
	defer attachPlan.Close()
	if err := attachPlan.ValidatePreviousBindings(nil, true); err != nil {
		return failWithoutOwner(err)
	}
	bindings := attachPlan.Bindings()
	bootID, err := runtime.bootID()
	if err != nil {
		return failWithoutOwner(err)
	}
	now := runtime.now().UTC()
	record := newFakeTCPClassicOwnerRecord(
		resources.parent.resource,
		bootID,
		now,
		state.Generation,
		object.SHA256,
		bindings,
	)
	if err := resources.store.Persist(record, nil); err != nil {
		return failWithoutOwner(fmt.Errorf("persist FakeTCP classic attach intent: %w", err))
	}
	stage := &productionFakeTCPClassicStage{
		runtime:   runtime.classicTC,
		bootID:    runtime.bootID,
		now:       runtime.now,
		resources: resources,
		record:    record,
		bindings:  slices.Clone(bindings),
	}
	err = attachPlan.Execute(func() error {
		active := advanceFakeTCPClassicOwnerRecord(record, fakeTCPClassicPhaseActive, runtime.now())
		if err := resources.store.Persist(active, record); err != nil {
			return fmt.Errorf("publish active FakeTCP classic owner: %w", err)
		}
		stage.record = active
		if err := commit(); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return stage, fmt.Errorf("activate production FakeTCP classic TC: %w", err)
	}
	return stage, nil
}

// productionFakeTCPClassicStage retains the resource flock for the complete
// runtime. This makes the durable record both crash-recoverable and exclusive
// without pinning the otherwise process-owned FakeTCP collection.
type productionFakeTCPClassicStage struct {
	mu        sync.Mutex
	runtime   tcRuntime
	bootID    func() (string, error)
	now       func() time.Time
	resources *fakeTCPClassicOwnerResources
	record    *fakeTCPClassicOwnerRecord
	bindings  []tcFilterBinding
}

func validateFakeTCPClassicFiltersExact(
	bindings []tcFilterBinding,
	runtime tcRuntime,
) error {
	if err := validateTCRuntime(runtime); err != nil {
		return err
	}
	for _, binding := range bindings {
		link, err := runtime.linkByIndex(binding.IfIndex)
		if err != nil {
			return fmt.Errorf("inspect FakeTCP classic link %d: %w", binding.IfIndex, err)
		}
		if link == nil || link.Attrs() == nil || link.Attrs().Index != binding.IfIndex {
			return fmt.Errorf("inspect FakeTCP classic link %d returned a mismatch", binding.IfIndex)
		}
		slot, err := ownerFilterSlot(binding)
		if err != nil {
			return err
		}
		snapshot, err := inspectTCFilterSlot(link, slot, runtime, false)
		if err != nil {
			return fmt.Errorf("inspect FakeTCP classic filter %d/%s: %w", binding.IfIndex, binding.Direction, err)
		}
		if !snapshot.existed || snapshot.programID != binding.ProgramID {
			return fmt.Errorf(
				"FakeTCP classic filter %d/%s has present=%t program=%d, want present program=%d",
				binding.IfIndex, binding.Direction, snapshot.existed,
				snapshot.programID, binding.ProgramID,
			)
		}
	}
	return nil
}

type fakeTCPClassicFilterRemoval struct {
	binding tcFilterBinding
	link    netlink.Link
	slot    tcFilterSlot
	program tcProgramRef
}

func removeFakeTCPClassicFiltersExact(
	bindings []tcFilterBinding,
	runtime tcRuntime,
	allowDelete bool,
) (returnErr error) {
	if err := validateTCRuntime(runtime); err != nil {
		return err
	}
	removals := make([]fakeTCPClassicFilterRemoval, 0, len(bindings))
	defer func() {
		for index := range removals {
			if removals[index].program != nil {
				returnErr = errors.Join(returnErr, removals[index].program.Close())
			}
		}
	}()
	// Inspect every recorded slot before the first delete. A program mismatch is
	// foreign ownership and must not result in a partial cleanup.
	for _, binding := range bindings {
		link, err := runtime.linkByIndex(binding.IfIndex)
		if err != nil {
			if isNotFound(err) {
				continue
			}
			return fmt.Errorf("inspect FakeTCP classic cleanup link %d: %w", binding.IfIndex, err)
		}
		if link == nil || link.Attrs() == nil || link.Attrs().Index != binding.IfIndex {
			return fmt.Errorf("inspect FakeTCP classic cleanup link %d returned a mismatch", binding.IfIndex)
		}
		slot, err := ownerFilterSlot(binding)
		if err != nil {
			return err
		}
		snapshot, err := inspectTCFilterSlot(link, slot, runtime, false)
		if err != nil {
			return err
		}
		if !snapshot.existed {
			continue
		}
		if snapshot.programID != binding.ProgramID {
			return fmt.Errorf(
				"refuse FakeTCP classic cleanup of %d/%s: program ID %d replaced recorded %d",
				binding.IfIndex, binding.Direction, snapshot.programID, binding.ProgramID,
			)
		}
		if !allowDelete {
			return fmt.Errorf(
				"refuse prior-boot FakeTCP classic cleanup of occupied %d/%s program ID %d",
				binding.IfIndex, binding.Direction, binding.ProgramID,
			)
		}
		program, err := runtime.loadProgram(binding.ProgramID)
		if err != nil {
			return fmt.Errorf("retain FakeTCP classic program ID %d for cleanup: %w", binding.ProgramID, err)
		}
		if program == nil || program.FD() < 0 {
			if program != nil {
				_ = program.Close()
			}
			return fmt.Errorf("retain FakeTCP classic program ID %d returned an invalid FD", binding.ProgramID)
		}
		removals = append(removals, fakeTCPClassicFilterRemoval{
			binding: binding, link: link, slot: slot, program: program,
		})
	}
	for _, removal := range removals {
		current, err := inspectTCFilterSlot(removal.link, removal.slot, runtime, false)
		if err != nil {
			return err
		}
		if !current.existed {
			continue
		}
		if current.programID != removal.binding.ProgramID {
			return fmt.Errorf(
				"FakeTCP classic filter %d/%s changed immediately before delete",
				removal.binding.IfIndex, removal.binding.Direction,
			)
		}
		filter := managedBpfFilter(
			removal.binding.IfIndex, removal.slot, removal.program.FD(),
		).(*netlink.BpfFilter)
		filter.Id = int(removal.binding.ProgramID)
		if err := runtime.filterDelete(filter); err != nil {
			return fmt.Errorf(
				"delete FakeTCP classic filter %d/%s program %d: %w",
				removal.binding.IfIndex, removal.binding.Direction,
				removal.binding.ProgramID, err,
			)
		}
		after, err := inspectTCFilterSlot(removal.link, removal.slot, runtime, false)
		if err != nil {
			return err
		}
		if after.existed {
			return fmt.Errorf(
				"FakeTCP classic filter %d/%s remains after delete with program ID %d",
				removal.binding.IfIndex, removal.binding.Direction, after.programID,
			)
		}
	}
	return nil
}

func (stage *productionFakeTCPClassicStage) Healthy(ctx context.Context) error {
	if ctx == nil {
		return errors.New("inspect production FakeTCP classic health: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if stage == nil {
		return errors.New("inspect production FakeTCP classic health: stage is nil")
	}
	stage.mu.Lock()
	defer stage.mu.Unlock()
	if stage.resources == nil || stage.resources.store == nil || stage.record == nil ||
		stage.record.Phase != fakeTCPClassicPhaseActive || len(stage.bindings) == 0 {
		return errors.New("inspect production FakeTCP classic health: owner is inactive")
	}
	record, exists, err := stage.resources.store.LoadOptional()
	if err != nil {
		return fmt.Errorf("inspect production FakeTCP classic owner journal: %w", err)
	}
	if !exists || !sameFakeTCPClassicOwnerRecord(record, stage.record) {
		return errors.New("inspect production FakeTCP classic owner journal: active record changed")
	}
	if err := validateFakeTCPClassicFiltersExact(stage.bindings, stage.runtime); err != nil {
		return fmt.Errorf("inspect production FakeTCP classic filters: %w", err)
	}
	return nil
}

func (stage *productionFakeTCPClassicStage) Close() error {
	if stage == nil {
		return nil
	}
	stage.mu.Lock()
	defer stage.mu.Unlock()
	if stage.resources == nil {
		return nil
	}
	if stage.record == nil {
		err := stage.resources.Close()
		if err == nil {
			stage.resources = nil
		}
		return err
	}
	store := stage.resources.store
	if store == nil {
		return errors.New("close production FakeTCP classic owner: store is unavailable")
	}
	current, exists, err := store.LoadOptional()
	if err != nil {
		return fmt.Errorf("close production FakeTCP classic owner: load journal: %w", err)
	}
	if !exists {
		if err := removeFakeTCPClassicFiltersExact(stage.bindings, stage.runtime, false); err != nil {
			return fmt.Errorf("close production FakeTCP classic owner without journal: %w", err)
		}
		stage.record = nil
		stage.bindings = nil
		err := stage.resources.Close()
		if err == nil {
			stage.resources = nil
		}
		return err
	}
	if !sameFakeTCPClassicOwnerRecord(current, stage.record) {
		return errors.New("close production FakeTCP classic owner: journal changed")
	}
	if current.Phase != fakeTCPClassicPhaseDetaching {
		if stage.now == nil {
			return errors.New("close production FakeTCP classic owner: clock is unavailable")
		}
		detaching := advanceFakeTCPClassicOwnerRecord(
			current, fakeTCPClassicPhaseDetaching, stage.now(),
		)
		if err := store.Persist(detaching, current); err != nil {
			return fmt.Errorf("persist FakeTCP classic detach intent: %w", err)
		}
		stage.record = detaching
		current = detaching
	}
	if stage.bootID == nil {
		return errors.New("close production FakeTCP classic owner: boot ID runtime is unavailable")
	}
	bootID, err := stage.bootID()
	if err != nil {
		return err
	}
	if err := removeFakeTCPClassicFiltersExact(
		stage.bindings,
		stage.runtime,
		bootID == current.BootID,
	); err != nil {
		return err
	}
	if err := store.Remove(current); err != nil {
		return err
	}
	stage.record = nil
	stage.bindings = nil
	err = stage.resources.Close()
	if err == nil {
		stage.resources = nil
	}
	return err
}

func (stage *productionFakeTCPClassicStage) status() []FakeTCPClassicTCStatus {
	if stage == nil {
		return nil
	}
	stage.mu.Lock()
	defer stage.mu.Unlock()
	result := make([]FakeTCPClassicTCStatus, 0, len(stage.bindings))
	for _, binding := range stage.bindings {
		result = append(result, FakeTCPClassicTCStatus{
			IfIndex: binding.IfIndex, Direction: binding.Direction,
			Parent: binding.Parent, Handle: binding.Handle,
			Priority: binding.Priority, ProgramID: binding.ProgramID,
		})
	}
	return result
}
