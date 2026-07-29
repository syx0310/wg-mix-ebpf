package guard

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"
)

type Executor interface {
	Apply(ctx context.Context, plan NftPlan) error
	Cleanup(ctx context.Context) error
}

type CommandExecutor struct {
	Binary       string
	StateDir     string
	runScript    func(context.Context, string) error
	inspectTable func(context.Context, string) (tableIdentity, error)
	listTables   func(context.Context) ([]string, error)
}

type tableIdentity struct {
	Exists  bool
	Handle  uint64
	Comment string
}

func NewCommandExecutor(stateDir string) CommandExecutor {
	return CommandExecutor{Binary: "nft", StateDir: stateDir}
}

func (e CommandExecutor) Apply(ctx context.Context, plan NftPlan) error {
	legacy, err := e.inspect(ctx, TableName)
	if err != nil {
		return fmt.Errorf("inspect legacy startup guard table: %w", err)
	}
	if legacy.Exists {
		return fmt.Errorf(
			"legacy startup guard table %s exists without instance ownership; refusing to replace or adopt it",
			TableName,
		)
	}
	owner, present, err := e.loadOwnerIfPresent()
	if err != nil {
		return fmt.Errorf("load guard ownership: %w", err)
	}
	if err := e.requireProjectTablePrestate(ctx, owner, present); err != nil {
		return err
	}
	fresh := false
	if !present {
		owner, fresh, err = e.loadOrCreateOwner()
		if err != nil {
			return fmt.Errorf("create guard ownership: %w", err)
		}
	}
	createScript, err := plan.ownedCreateScript(owner)
	if err != nil {
		return fmt.Errorf("build owned startup guard: %w", err)
	}
	if fresh {
		if err := e.run(ctx, createScript); err != nil {
			return fmt.Errorf("create startup guard for new installation identity: %w", err)
		}
		return e.verifyAppliedOwner(ctx, owner, 0)
	}
	identity, err := e.inspect(ctx, owner.Table)
	if err != nil {
		return fmt.Errorf("inspect startup guard ownership: %w", err)
	}
	if !identity.Exists {
		if err := e.run(ctx, createScript); err != nil {
			return fmt.Errorf("create missing owned startup guard: %w", err)
		}
		return e.verifyAppliedOwner(ctx, owner, 0)
	}
	if err := requireOwnedTable(owner, identity); err != nil {
		return err
	}
	replacement, err := plan.ownedReplacementScript(owner, identity.Handle)
	if err != nil {
		return fmt.Errorf("build owned startup guard replacement: %w", err)
	}
	if err := e.run(ctx, replacement); err != nil {
		return fmt.Errorf("replace owned startup guard atomically by handle: %w", err)
	}
	return e.verifyAppliedOwner(ctx, owner, identity.Handle)
}

func (e CommandExecutor) verifyAppliedOwner(
	ctx context.Context,
	owner ownerRecord,
	previousHandle uint64,
) error {
	identity, err := e.inspect(ctx, owner.Table)
	if err != nil {
		return fmt.Errorf("verify applied startup guard ownership: %w", err)
	}
	if err := requireOwnedTable(owner, identity); err != nil {
		return fmt.Errorf("verify applied startup guard ownership: %w", err)
	}
	if previousHandle != 0 && identity.Handle == previousHandle {
		return fmt.Errorf(
			"startup guard replacement retained table handle %d; replacement postcondition was not proven",
			previousHandle,
		)
	}
	return e.requireExactProjectTables(
		ctx,
		[]string{owner.Table},
		"verify applied startup guard table inventory",
	)
}

func (e CommandExecutor) Cleanup(ctx context.Context) error {
	legacy, err := e.inspect(ctx, TableName)
	if err != nil {
		return fmt.Errorf("inspect legacy startup guard table for cleanup: %w", err)
	}
	if legacy.Exists {
		return fmt.Errorf(
			"legacy startup guard table %s exists without instance ownership; manual migration is required before cleanup",
			TableName,
		)
	}
	owner, ok, err := e.loadOwnerIfPresent()
	if err != nil {
		return fmt.Errorf("load guard ownership for cleanup: %w", err)
	}
	if err := e.requireProjectTablePrestate(ctx, owner, ok); err != nil {
		return err
	}
	if !ok {
		return e.requireExactProjectTables(
			ctx,
			nil,
			"verify ownerless startup guard cleanup inventory",
		)
	}
	identity, err := e.inspect(ctx, owner.Table)
	if err != nil {
		return fmt.Errorf("inspect startup guard ownership for cleanup: %w", err)
	}
	if !identity.Exists {
		return e.requireExactProjectTables(
			ctx,
			nil,
			"verify absent startup guard table inventory",
		)
	}
	if err := requireOwnedTable(owner, identity); err != nil {
		return err
	}
	if err := e.run(ctx, cleanupHandleScript(identity.Handle)); err != nil {
		deleteErr := fmt.Errorf("delete owned startup guard by handle: %w", err)
		after, inspectErr := e.inspect(ctx, owner.Table)
		if inspectErr != nil {
			return errors.Join(
				deleteErr,
				fmt.Errorf("inspect startup guard after failed cleanup: %w", inspectErr),
			)
		}
		if !after.Exists {
			return fmt.Errorf(
				"startup guard table is absent after the failed cleanup command; preserving the command failure: %w",
				deleteErr,
			)
		}
		return deleteErr
	}
	after, err := e.inspect(ctx, owner.Table)
	if err != nil {
		return fmt.Errorf("verify startup guard cleanup: %w", err)
	}
	if after.Exists {
		return errors.New("startup guard table still exists after handle-based cleanup; refusing any name-based deletion")
	}
	return e.requireExactProjectTables(
		ctx,
		nil,
		"verify startup guard cleanup inventory",
	)
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
	cmd := exec.CommandContext(ctx, binary, "-j", "list", "tables")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s -j list tables failed: %w: %s", binary, err, string(out))
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
			"startup guard table %s has ownership marker %q, want %q; refusing mutation",
			owner.Table,
			identity.Comment,
			owner.Marker,
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
	cmd := exec.CommandContext(ctx, binary, "-f", "-")
	cmd.Stdin = bytes.NewBufferString(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s -f - failed: %w: %s", binary, err, string(out))
	}
	return nil
}

func (e CommandExecutor) inspect(ctx context.Context, table string) (tableIdentity, error) {
	if e.inspectTable != nil {
		return e.inspectTable(ctx, table)
	}
	binary := e.Binary
	if binary == "" {
		binary = "nft"
	}
	cmd := exec.CommandContext(ctx, binary, "-j", "-a", "list", "table", "inet", table)
	out, err := cmd.CombinedOutput()
	if err != nil {
		wrapped := fmt.Errorf("%s -j -a list table inet %s failed: %w: %s", binary, table, err, string(out))
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && isMissingTableDiagnostic(out, table) {
			return tableIdentity{}, nil
		}
		return tableIdentity{}, wrapped
	}
	return parseTableIdentityJSON(out, table)
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

func isMissingTableDiagnostic(output []byte, table string) bool {
	if len(output) == 0 || table == "" {
		return false
	}
	lower := strings.ToLower(string(output))
	missing := strings.Contains(lower, "no such file or directory") ||
		strings.Contains(lower, "does not exist")
	if !missing {
		return false
	}
	expectedRequest := "list table inet " + strings.ToLower(table)
	for _, line := range strings.Split(lower, "\n") {
		if strings.TrimSpace(line) == expectedRequest {
			return true
		}
	}
	return false
}

type DryRunExecutor struct {
	AppliedScript  string
	FallbackScript string
	CleanupScript  string
}

func (e *DryRunExecutor) Apply(_ context.Context, plan NftPlan) error {
	e.AppliedScript = plan.ReplacementScript()
	e.FallbackScript = plan.Script()
	return nil
}

func (e *DryRunExecutor) Cleanup(context.Context) error {
	e.CleanupScript = CleanupScript()
	return nil
}
