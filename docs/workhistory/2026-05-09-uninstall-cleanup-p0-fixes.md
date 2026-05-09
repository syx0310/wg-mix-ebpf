# 2026-05-09 uninstall cleanup P0 fixes

## Context

Review found three release-blocking cleanup issues:

- `uninstall` held the global run lock and then called `reconcile.Stop`, which tried to acquire the same lock again and could hang.
- Linux detach removed pinned BPF maps even when TC filter deletion failed.
- `uninstall` skipped stop/detach when the config file was missing, even if attach-state still existed.

## Changes

- Moved the uninstall stop call outside the uninstall cleanup lock to avoid nested lock acquisition.
- Made uninstall run stop cleanup when either the config file exists or attach-state exists.
- Kept the post-stop cleanup under the global lock for guard, pin/state, service, and runtime file cleanup.
- Changed Linux detach to return immediately on TC detach errors and only remove pinned maps after all expected TC filters are removed successfully.
- Tightened normal TC deletion to match this agent's filter name, priority, and handle.
- Made guard cleanup treat a missing `nft` binary as an idempotent no-op. This keeps `startup_guard: none` systems without nftables from failing during `stop` / `uninstall`.
- Added regression tests for uninstall completion, attach-state-only cleanup selection, and detach dry-run from attach-state without a config file.

## Validation

- `go test ./...` passed locally.
- The previous local reproducer for `uninstall --system unknown --yes` now returns successfully instead of timing out.
