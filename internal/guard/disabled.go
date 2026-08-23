package guard

import "context"

// DisabledExecutor represents the explicit startup_guard.mode=none profile.
// It never invokes an nft subprocess or mutates nf_tables, but every operation
// first performs a read-only netlink inventory and refuses to coexist with any
// project guard table. It must not be selected as an automatic fallback from a
// CommandExecutor failure. Explicit guard cleanup and ownership recovery must
// continue to use CommandExecutor even when the current profile is none.
type DisabledExecutor struct {
	preflight ProjectTablePreflight
}

func NewDisabledExecutor() DisabledExecutor {
	return DisabledExecutor{preflight: NewProjectTablePreflight()}
}

// NewDisabledExecutorWithLister injects the complete read-only nf_tables
// inventory used by the mode=none preflight.
func NewDisabledExecutorWithLister(lister NFTableLister) DisabledExecutor {
	return DisabledExecutor{
		preflight: NewProjectTablePreflightWithLister(lister),
	}
}

// Preflight proves that no inet wg-mix-ebpf guard table exists. Callers which
// bypass Executor.Apply for mode=none must invoke this method before any
// dataplane mutation.
func (e DisabledExecutor) Preflight(ctx context.Context) (Outcome, error) {
	return e.preflight.Check(ctx)
}

func (e DisabledExecutor) Apply(ctx context.Context, _ NftPlan) (Outcome, error) {
	return e.Preflight(ctx)
}

func (e DisabledExecutor) Cleanup(ctx context.Context) (Outcome, error) {
	return e.Preflight(ctx)
}

func (e DisabledExecutor) Observe(ctx context.Context) (Outcome, error) {
	return e.Preflight(ctx)
}

var _ Executor = DisabledExecutor{}
