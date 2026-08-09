package faketcp

import (
	"errors"
	"sync"
)

var errRuntimeIdentityCommitStateUnavailable = errors.New("faketcp runtime identity commit state is unavailable")

type runtimeIdentityCommitState struct {
	once sync.Once
	err  error
}

// commitRuntimeIdentityOnce atomically consumes the one kernel-collection
// commit available to an Engine identity. Concurrent or later callers wait
// for the first result, then fail without executing their callback.
func (engine *Engine) commitRuntimeIdentityOnce(
	consumed error,
	commit func() error,
) error {
	if engine == nil || engine.runtimeIdentityCommit == nil || commit == nil {
		return errors.Join(consumed, errRuntimeIdentityCommitStateUnavailable)
	}
	state := engine.runtimeIdentityCommit
	executed := false
	state.once.Do(func() {
		executed = true
		state.err = commit()
	})
	if executed {
		return state.err
	}
	if state.err != nil {
		return errors.Join(consumed, state.err)
	}
	return consumed
}
