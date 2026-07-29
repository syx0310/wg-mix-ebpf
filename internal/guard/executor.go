package guard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
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
	owner, fresh, err := e.loadOrCreateOwner()
	if err != nil {
		return fmt.Errorf("load guard ownership: %w", err)
	}
	createScript, err := plan.ownedCreateScript(owner)
	if err != nil {
		return fmt.Errorf("build owned startup guard: %w", err)
	}
	if fresh {
		if err := e.run(ctx, createScript); err != nil {
			return fmt.Errorf("create startup guard for new installation identity: %w", err)
		}
		return nil
	}
	identity, err := e.inspect(ctx, owner.Table)
	if err != nil {
		return fmt.Errorf("inspect startup guard ownership: %w", err)
	}
	if !identity.Exists {
		if err := e.run(ctx, createScript); err != nil {
			return fmt.Errorf("create missing owned startup guard: %w", err)
		}
		return nil
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
	return nil
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
	if !ok {
		return nil
	}
	identity, err := e.inspect(ctx, owner.Table)
	if err != nil {
		return fmt.Errorf("inspect startup guard ownership for cleanup: %w", err)
	}
	if !identity.Exists {
		return nil
	}
	if err := requireOwnedTable(owner, identity); err != nil {
		return err
	}
	if err := e.run(ctx, cleanupHandleScript(identity.Handle)); err != nil {
		after, inspectErr := e.inspect(ctx, owner.Table)
		if inspectErr == nil && !after.Exists {
			return nil
		}
		return fmt.Errorf("delete owned startup guard by handle: %w", err)
	}
	after, err := e.inspect(ctx, owner.Table)
	if err != nil {
		return fmt.Errorf("verify startup guard cleanup: %w", err)
	}
	if after.Exists {
		return errors.New("startup guard table still exists after handle-based cleanup; refusing any name-based deletion")
	}
	return nil
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
	var document struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return tableIdentity{}, fmt.Errorf("parse nft JSON for table %s: %w", table, err)
	}
	var found []tableIdentity
	for _, item := range document.Nftables {
		raw, ok := item["table"]
		if !ok {
			continue
		}
		var listed struct {
			Family  string `json:"family"`
			Name    string `json:"name"`
			Handle  uint64 `json:"handle"`
			Comment string `json:"comment"`
		}
		if err := json.Unmarshal(raw, &listed); err != nil {
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
