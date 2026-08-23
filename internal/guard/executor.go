package guard

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

type Executor interface {
	Apply(ctx context.Context, plan NftPlan) (Outcome, error)
	Cleanup(ctx context.Context) (Outcome, error)
	Observe(ctx context.Context) (Outcome, error)
}

type CommandExecutor struct {
	Binary        string
	StateDir      string
	runScript     func(context.Context, string) error
	inspectTable  func(context.Context, string) (tableIdentity, error)
	listTables    func(context.Context) ([]string, error)
	nfTableLister NFTableLister
}

type tableIdentity struct {
	Exists  bool
	Handle  uint64
	Comment string
}

func NewCommandExecutor(stateDir string) CommandExecutor {
	return NewCommandExecutorWithNFTableLister(stateDir, newKernelNFTableLister())
}

// NewCommandExecutorWithNFTableLister supplies the independent, read-only
// kernel inventory used when nft cannot inspect one exact table. Production
// uses NewCommandExecutor; this constructor keeps that fallback deterministic
// in tests without replacing the nft mutation path.
func NewCommandExecutorWithNFTableLister(
	stateDir string,
	lister NFTableLister,
) CommandExecutor {
	return CommandExecutor{
		Binary:        "nft",
		StateDir:      stateDir,
		nfTableLister: lister,
	}
}

// Observe performs a fresh, read-only cross-check of the durable owner record,
// the exact owned table, and the complete project-table inventory. It never
// creates the state directory or issues an nft mutation.
func (e CommandExecutor) Observe(ctx context.Context) (Outcome, error) {
	legacy, legacyErr := e.inspectLegacy(ctx)
	if legacyErr != nil {
		legacyErr = fmt.Errorf("inspect legacy startup guard table: %w", legacyErr)
	}

	owner, present, ownerErr := e.loadOwnerIfPresent()
	if ownerErr != nil {
		ownerErr = fmt.Errorf("load guard ownership: %w", ownerErr)
	}

	var outcome Outcome
	var observationErr error
	switch {
	case ownerErr != nil:
		// Still collect the independent kernel inventory so the error retains
		// all available diagnostic evidence without trusting a damaged owner.
		_, inventoryErr := e.projectTables(ctx)
		if inventoryErr != nil {
			inventoryErr = fmt.Errorf("inventory startup guard tables: %w", inventoryErr)
		}
		outcome = unknownOutcome()
		observationErr = errors.Join(ownerErr, inventoryErr)
	case present:
		outcome, _, observationErr = e.observeOwnedState(ctx, owner)
	case !present:
		tables, inventoryErr := e.projectTables(ctx)
		if inventoryErr != nil {
			outcome = unknownOutcome()
			observationErr = fmt.Errorf("inventory startup guard tables: %w", inventoryErr)
		} else if len(tables) != 0 {
			outcome = unknownOutcome()
			observationErr = fmt.Errorf(
				"project startup guard tables %v exist without a v2 owner record",
				tables,
			)
		} else {
			outcome = Outcome{Observation: ObservationAbsent}
		}
	}

	if legacyErr != nil {
		outcome = unknownOutcome()
		observationErr = errors.Join(observationErr, legacyErr)
	} else if legacy.Exists {
		outcome = unknownOutcome()
		observationErr = errors.Join(
			observationErr,
			fmt.Errorf(
				"legacy startup guard table %s exists without instance ownership",
				TableName,
			),
		)
	}
	return outcome, observationErr
}

func (e CommandExecutor) Apply(ctx context.Context, plan NftPlan) (Outcome, error) {
	legacy, err := e.inspectLegacy(ctx)
	if err != nil {
		return unchangedOutcome(), fmt.Errorf("inspect legacy startup guard table: %w", err)
	}
	if legacy.Exists {
		return unchangedOutcome(), fmt.Errorf(
			"legacy startup guard table %s exists without instance ownership; refusing to replace or adopt it",
			TableName,
		)
	}
	owner, present, err := e.loadOwnerIfPresent()
	if err != nil {
		return unchangedOutcome(), fmt.Errorf("load guard ownership: %w", err)
	}
	if err := e.requireProjectTablePrestate(ctx, owner, present); err != nil {
		return unchangedOutcome(), err
	}
	fresh := false
	if !present {
		owner, fresh, err = e.loadOrCreateOwner()
		if err != nil {
			return unchangedOutcome(), fmt.Errorf("create guard ownership: %w", err)
		}
	}
	createScript, err := plan.ownedCreateScript(owner)
	if err != nil {
		return unchangedOutcome(), fmt.Errorf("build owned startup guard: %w", err)
	}
	if fresh {
		if err := e.run(ctx, createScript); err != nil {
			return e.observeApplyFailure(
				ctx,
				owner,
				fmt.Errorf("create startup guard for new installation identity: %w", err),
			)
		}
		return e.verifyAppliedOwner(ctx, owner, 0)
	}
	identity, err := e.inspect(ctx, owner.Table)
	if err != nil {
		return unchangedOutcome(), fmt.Errorf("inspect startup guard ownership: %w", err)
	}
	if !identity.Exists {
		if err := e.run(ctx, createScript); err != nil {
			return e.observeApplyFailure(
				ctx,
				owner,
				fmt.Errorf("create missing owned startup guard: %w", err),
			)
		}
		return e.verifyAppliedOwner(ctx, owner, 0)
	}
	if err := requireOwnedTable(owner, identity); err != nil {
		return unchangedOutcome(), err
	}
	replacement, err := plan.ownedReplacementScript(owner, identity.Handle)
	if err != nil {
		return unchangedOutcome(), fmt.Errorf("build owned startup guard replacement: %w", err)
	}
	if err := e.run(ctx, replacement); err != nil {
		return e.observeApplyFailure(
			ctx,
			owner,
			fmt.Errorf("replace owned startup guard atomically by handle: %w", err),
		)
	}
	return e.verifyAppliedOwner(ctx, owner, identity.Handle)
}

func (e CommandExecutor) verifyAppliedOwner(
	ctx context.Context,
	owner ownerRecord,
	previousHandle uint64,
) (Outcome, error) {
	outcome, identity, err := e.observeOwnedState(ctx, owner)
	outcome.Mutated = true
	if err != nil {
		return outcome, fmt.Errorf("verify applied startup guard: %w", err)
	}
	if outcome.Observation != ObservationActive {
		return outcome, errors.New("verify applied startup guard: startup guard table is absent")
	}
	if previousHandle != 0 && identity.Handle == previousHandle {
		return outcome, fmt.Errorf(
			"startup guard replacement retained table handle %d; replacement postcondition was not proven",
			previousHandle,
		)
	}
	return outcome, nil
}

func (e CommandExecutor) observeApplyFailure(
	ctx context.Context,
	owner ownerRecord,
	mutationErr error,
) (Outcome, error) {
	outcome, _, observationErr := e.observeOwnedState(ctx, owner)
	outcome.Mutated = true
	if observationErr != nil {
		observationErr = fmt.Errorf("observe startup guard after failed apply command: %w", observationErr)
	}
	return outcome, errors.Join(mutationErr, observationErr)
}

func (e CommandExecutor) Cleanup(ctx context.Context) (Outcome, error) {
	legacy, err := e.inspectLegacy(ctx)
	if err != nil {
		return unchangedOutcome(), fmt.Errorf("inspect legacy startup guard table for cleanup: %w", err)
	}
	if legacy.Exists {
		return unchangedOutcome(), fmt.Errorf(
			"legacy startup guard table %s exists without instance ownership; manual migration is required before cleanup",
			TableName,
		)
	}
	owner, ok, err := e.loadOwnerIfPresent()
	if err != nil {
		return unchangedOutcome(), fmt.Errorf("load guard ownership for cleanup: %w", err)
	}
	if err := e.requireProjectTablePrestate(ctx, owner, ok); err != nil {
		return unchangedOutcome(), err
	}
	if !ok {
		if err := e.requireExactProjectTables(
			ctx,
			nil,
			"verify ownerless startup guard cleanup inventory",
		); err != nil {
			return unknownOutcome(), err
		}
		return Outcome{Observation: ObservationAbsent}, nil
	}
	identity, err := e.inspect(ctx, owner.Table)
	if err != nil {
		return unchangedOutcome(), fmt.Errorf("inspect startup guard ownership for cleanup: %w", err)
	}
	if !identity.Exists {
		outcome, _, observationErr := e.observeOwnedState(ctx, owner)
		if observationErr != nil {
			return outcome, fmt.Errorf("verify absent startup guard table: %w", observationErr)
		}
		if outcome.Observation != ObservationAbsent {
			return outcome, errors.New("verify absent startup guard table: owned startup guard is active")
		}
		return outcome, nil
	}
	if err := requireOwnedTable(owner, identity); err != nil {
		return unchangedOutcome(), err
	}
	mutationErr := e.run(ctx, cleanupHandleScript(identity.Handle))
	if mutationErr != nil {
		mutationErr = fmt.Errorf("delete owned startup guard by handle: %w", mutationErr)
	}
	outcome, _, observationErr := e.observeOwnedState(ctx, owner)
	outcome.Mutated = true
	if observationErr != nil {
		observationErr = fmt.Errorf("verify startup guard cleanup: %w", observationErr)
	}
	if mutationErr != nil {
		if observationErr == nil && outcome.Observation == ObservationAbsent {
			outcome.Warning = fmt.Errorf(
				"startup guard is absent after the failed cleanup command; preserving command warning: %w",
				mutationErr,
			)
			return outcome, nil
		}
		return outcome, errors.Join(mutationErr, observationErr)
	}
	if observationErr != nil {
		return outcome, observationErr
	}
	if outcome.Observation != ObservationAbsent {
		return outcome, errors.New("startup guard table still exists after handle-based cleanup; refusing any name-based deletion")
	}
	return outcome, nil
}

func (e CommandExecutor) observeOwnedState(
	ctx context.Context,
	owner ownerRecord,
) (Outcome, tableIdentity, error) {
	identity, inspectErr := e.inspect(ctx, owner.Table)
	if inspectErr != nil {
		inspectErr = fmt.Errorf("inspect exact owned startup guard table %s: %w", owner.Table, inspectErr)
	}
	tables, inventoryErr := e.projectTables(ctx)
	if inventoryErr != nil {
		inventoryErr = fmt.Errorf("inventory complete project startup guard tables: %w", inventoryErr)
	}
	if err := errors.Join(inspectErr, inventoryErr); err != nil {
		return unknownOutcome(), tableIdentity{}, err
	}

	if identity.Exists {
		if err := requireOwnedTable(owner, identity); err != nil {
			return unknownOutcome(), identity, fmt.Errorf("verify exact startup guard ownership: %w", err)
		}
		if !equalStrings(tables, []string{owner.Table}) {
			return unknownOutcome(), identity, fmt.Errorf(
				"owned startup guard table is active but complete project table inventory is %v, want [%s]",
				tables,
				owner.Table,
			)
		}
		return Outcome{Observation: ObservationActive}, identity, nil
	}
	if len(tables) != 0 {
		return unknownOutcome(), identity, fmt.Errorf(
			"owned startup guard table %s is absent but complete project table inventory is %v, want []",
			owner.Table,
			tables,
		)
	}
	return Outcome{Observation: ObservationAbsent}, identity, nil
}

func (e CommandExecutor) requireProjectTablePrestate(
	ctx context.Context,
	owner ownerRecord,
	ownerPresent bool,
) error {
	tables, err := e.projectTables(ctx)
	if err != nil {
		return fmt.Errorf("inventory startup guard tables before mutation: %w", err)
	}
	if !ownerPresent {
		if len(tables) == 0 {
			return nil
		}
		return fmt.Errorf(
			"project startup guard tables %v exist without a v2 owner record; refusing mutation and requiring explicit ownership recovery",
			tables,
		)
	}
	if len(tables) == 0 || (len(tables) == 1 && tables[0] == owner.Table) {
		return nil
	}
	return fmt.Errorf(
		"project startup guard tables %v do not match v2 owner table %q; refusing mutation and requiring explicit ownership recovery",
		tables,
		owner.Table,
	)
}

func (e CommandExecutor) requireExactProjectTables(
	ctx context.Context,
	want []string,
	operation string,
) error {
	tables, err := e.projectTables(ctx)
	if err != nil {
		return fmt.Errorf("%s: %w", operation, err)
	}
	if equalStrings(tables, want) {
		return nil
	}
	return fmt.Errorf(
		"%s: project startup guard tables = %v, want %v",
		operation,
		tables,
		want,
	)
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range got {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}

func (e CommandExecutor) projectTables(ctx context.Context) ([]string, error) {
	if e.listTables != nil {
		return e.listTables(ctx)
	}
	if e.inspectTable != nil {
		return nil, errors.New("table inventory hook is required with a custom table inspector")
	}
	binary := e.Binary
	if binary == "" {
		binary = "nft"
	}
	cmd, err := newNftCommand(ctx, binary, "-j", "list", "tables")
	if err != nil {
		return nil, fmt.Errorf("prepare nft table inventory command: %w", err)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s -j list tables failed: %w: %s", cmd.Path, err, string(out))
	}
	return parseProjectTableInventoryJSON(out)
}

func parseProjectTableInventoryJSON(data []byte) ([]string, error) {
	items, err := parseNftJSONItems(data)
	if err != nil {
		return nil, fmt.Errorf("parse nft table inventory JSON: %w", err)
	}
	seen := make(map[string]struct{})
	var tables []string
	metainfoCount := 0
	for index, item := range items {
		if len(item) != 1 {
			return nil, fmt.Errorf("nft table inventory item %d has %d object keys, want 1", index, len(item))
		}
		raw, isTable := item["table"]
		if !isTable {
			if metainfo, isMetadata := item["metainfo"]; isMetadata {
				metainfoCount++
				if metainfoCount != 1 {
					return nil, errors.New("nft table inventory contains duplicate metainfo")
				}
				if err := validateNftJSONMetainfo(metainfo); err != nil {
					return nil, err
				}
				continue
			}
			for objectType := range item {
				return nil, fmt.Errorf(
					"nft table inventory item %d has unexpected object type %q",
					index,
					objectType,
				)
			}
			continue
		}
		var table struct {
			Family  string   `json:"family"`
			Name    string   `json:"name"`
			Handle  *uint64  `json:"handle"`
			Comment *string  `json:"comment"`
			Flags   []string `json:"flags"`
		}
		if err := decodeStrictJSON(raw, &table); err != nil {
			return nil, fmt.Errorf("parse nft table inventory entry: %w", err)
		}
		if table.Family == "" || table.Name == "" {
			return nil, fmt.Errorf("nft table inventory item %d has an empty family or name", index)
		}
		if table.Family != "inet" || !isProjectTableName(table.Name) {
			continue
		}
		if _, duplicate := seen[table.Name]; duplicate {
			return nil, fmt.Errorf("nft table inventory contains duplicate inet table %s", table.Name)
		}
		seen[table.Name] = struct{}{}
		tables = append(tables, table.Name)
	}
	if metainfoCount != 1 {
		return nil, fmt.Errorf(
			"nft table inventory metainfo entries = %d, want 1",
			metainfoCount,
		)
	}
	sort.Strings(tables)
	return tables, nil
}

func isProjectTableName(name string) bool {
	return name == TableName || strings.HasPrefix(name, TableName+"_")
}

func requireOwnedTable(owner ownerRecord, identity tableIdentity) error {
	if !identity.Exists {
		return errors.New("startup guard table is absent")
	}
	if identity.Handle == 0 {
		return errors.New("startup guard table has no stable handle")
	}
	if identity.Comment != owner.Marker {
		return fmt.Errorf(
			"startup guard table %s ownership marker does not match the durable owner record; refusing mutation",
			owner.Table,
		)
	}
	return nil
}

func (e CommandExecutor) run(ctx context.Context, script string) error {
	if e.runScript != nil {
		return e.runScript(ctx, script)
	}
	binary := e.Binary
	if binary == "" {
		binary = "nft"
	}
	cmd, err := newNftCommand(ctx, binary, "-f", "-")
	if err != nil {
		return fmt.Errorf("prepare nft transaction command: %w", err)
	}
	cmd.Stdin = bytes.NewBufferString(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s -f - failed: %w: %s", cmd.Path, err, string(out))
	}
	return nil
}

func (e CommandExecutor) inspectLegacy(ctx context.Context) (tableIdentity, error) {
	// A valid instance-owned table also has the project prefix. The legacy
	// probe therefore resolves only the fixed legacy name and leaves the full
	// snapshot policy to requireProjectTablePrestate/observeOwnedState.
	return e.inspectWithInventory(ctx, TableName, true)
}

func (e CommandExecutor) inspect(ctx context.Context, table string) (tableIdentity, error) {
	return e.inspectWithInventory(ctx, table, false)
}

func (e CommandExecutor) inspectWithInventory(
	ctx context.Context,
	table string,
	allowOtherProjectTables bool,
) (tableIdentity, error) {
	if e.inspectTable != nil {
		return e.inspectTable(ctx, table)
	}
	binary := e.Binary
	if binary == "" {
		binary = "nft"
	}
	cmd, err := newNftCommand(ctx, binary, "-j", "-a", "list", "table", "inet", table)
	if err != nil {
		return e.resolveFailedTableInspection(
			ctx,
			table,
			allowOtherProjectTables,
			fmt.Errorf("prepare nft table inspection command: %w", err),
		)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return e.resolveFailedTableInspection(
			ctx,
			table,
			allowOtherProjectTables,
			fmt.Errorf(
				"%s -j -a list table inet %s failed: %w: %s",
				cmd.Path,
				table,
				err,
				string(out),
			),
		)
	}
	return parseTableIdentityJSON(out, table)
}

func (e CommandExecutor) resolveFailedTableInspection(
	ctx context.Context,
	table string,
	allowOtherProjectTables bool,
	commandErr error,
) (tableIdentity, error) {
	projectTables, inventoryErr := e.failedInspectionProjectTables(ctx)
	if inventoryErr != nil {
		return tableIdentity{}, errors.Join(
			commandErr,
			fmt.Errorf(
				"resolve failed nft inspection of inet table %s with read-only netlink inventory: %w",
				table,
				inventoryErr,
			),
		)
	}

	targetPresent := false
	otherTables := make([]string, 0, len(projectTables))
	for _, projectTable := range projectTables {
		if projectTable == table {
			targetPresent = true
			continue
		}
		otherTables = append(otherTables, projectTable)
	}
	if targetPresent {
		return tableIdentity{Exists: true}, fmt.Errorf(
			"read-only netlink inventory confirms inet project table %s exists, but its exact handle and ownership could not be inspected: %w",
			table,
			commandErr,
		)
	}
	if !allowOtherProjectTables && len(otherTables) != 0 {
		return tableIdentity{}, fmt.Errorf(
			"read-only netlink inventory confirms inet table %s is absent but conflicting project tables %v exist: %w",
			table,
			otherTables,
			commandErr,
		)
	}

	// The independent kernel dump, not nft's stderr wording, is authoritative
	// for absence. commandErr is intentionally discarded after that proof.
	return tableIdentity{}, nil
}

func (e CommandExecutor) failedInspectionProjectTables(ctx context.Context) ([]string, error) {
	// Higher-level tests inject a hermetic nft binary which models both exact
	// inspection and the complete table inventory. Keep those existing tests
	// hermetic on non-Linux hosts. The context key is private to this package
	// and WithNftBinaryForTest rejects non-test binaries, so production cannot
	// select this branch.
	if (e.Binary == "" || e.Binary == "nft") && ctx != nil {
		if _, injected := nftBinaryFromTestContext(ctx); injected {
			return e.projectTables(ctx)
		}
	}
	return listProjectTables(ctx, e.nfTableLister)
}

func parseTableIdentityJSON(data []byte, table string) (tableIdentity, error) {
	items, err := parseNftJSONItems(data)
	if err != nil {
		return tableIdentity{}, fmt.Errorf("parse nft JSON for table %s: %w", table, err)
	}
	var found []tableIdentity
	metainfoCount := 0
	for index, item := range items {
		if len(item) != 1 {
			return tableIdentity{}, fmt.Errorf(
				"nft table inspection item %d has %d object keys, want 1",
				index,
				len(item),
			)
		}
		if metainfo, ok := item["metainfo"]; ok {
			metainfoCount++
			if metainfoCount != 1 {
				return tableIdentity{}, errors.New("nft table inspection contains duplicate metainfo")
			}
			if err := validateNftJSONMetainfo(metainfo); err != nil {
				return tableIdentity{}, err
			}
			continue
		}
		raw, ok := item["table"]
		if !ok {
			continue
		}
		var listed struct {
			Family  string   `json:"family"`
			Name    string   `json:"name"`
			Handle  uint64   `json:"handle"`
			Comment string   `json:"comment"`
			Flags   []string `json:"flags"`
		}
		if err := decodeStrictJSON(raw, &listed); err != nil {
			return tableIdentity{}, fmt.Errorf("parse nft table metadata for %s: %w", table, err)
		}
		if listed.Family == "inet" && listed.Name == table {
			found = append(found, tableIdentity{
				Exists:  true,
				Handle:  listed.Handle,
				Comment: listed.Comment,
			})
		}
	}
	if metainfoCount != 1 {
		return tableIdentity{}, fmt.Errorf(
			"nft table inspection metainfo entries = %d, want 1",
			metainfoCount,
		)
	}
	if len(found) != 1 {
		return tableIdentity{}, fmt.Errorf("nft JSON contains %d metadata entries for inet table %s, want 1", len(found), table)
	}
	if found[0].Handle == 0 {
		return tableIdentity{}, fmt.Errorf("nft JSON table %s has no non-zero handle", table)
	}
	return found[0], nil
}

type DryRunExecutor struct {
	AppliedScript  string
	FallbackScript string
	CleanupScript  string
}

func (e *DryRunExecutor) Apply(_ context.Context, plan NftPlan) (Outcome, error) {
	e.AppliedScript = plan.ReplacementScript()
	e.FallbackScript = plan.Script()
	return unchangedOutcome(), nil
}

func (e *DryRunExecutor) Cleanup(context.Context) (Outcome, error) {
	e.CleanupScript = CleanupScript()
	return unchangedOutcome(), nil
}

func (*DryRunExecutor) Observe(context.Context) (Outcome, error) {
	return unchangedOutcome(), nil
}
