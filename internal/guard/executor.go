package guard

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

type Executor interface {
	Apply(ctx context.Context, plan NftPlan) error
	Cleanup(ctx context.Context) error
}

type CommandExecutor struct {
	Binary string
}

func NewCommandExecutor() CommandExecutor {
	return CommandExecutor{Binary: "nft"}
}

func (e CommandExecutor) Apply(ctx context.Context, plan NftPlan) error {
	_ = e.Cleanup(ctx)
	return e.run(ctx, plan.Script())
}

func (e CommandExecutor) Cleanup(ctx context.Context) error {
	if err := e.run(ctx, CleanupScript()); err != nil {
		if isMissingGuardTable(err) {
			return nil
		}
		return err
	}
	return nil
}

func (e CommandExecutor) run(ctx context.Context, script string) error {
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

func isMissingGuardTable(err error) bool {
	if err == nil {
		return false
	}
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, TableName) &&
		(strings.Contains(lower, "no such file") ||
			strings.Contains(lower, "does not exist") ||
			strings.Contains(lower, "not found"))
}

type DryRunExecutor struct {
	AppliedScript string
	CleanupScript string
}

func (e *DryRunExecutor) Apply(_ context.Context, plan NftPlan) error {
	e.AppliedScript = plan.Script()
	return nil
}

func (e *DryRunExecutor) Cleanup(context.Context) error {
	e.CleanupScript = CleanupScript()
	return nil
}
