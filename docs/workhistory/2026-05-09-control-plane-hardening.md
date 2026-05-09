# 2026-05-09 Control Plane Hardening

## Scope

Addressed review feedback for daemon, uninstall, startup guard, FwMark policy, and IPv6 checksum handling.

## Changes

- Added a shared runtime file lock used by daemon reload, manual reload, detach, stop, and uninstall cleanup.
- Added `wg-mix-ebpf stop`.
- Changed systemd `ExecStop` and OpenWrt `stop_service()` to call `wg-mix-ebpf stop` instead of racing the daemon with a separate direct detach process.
- Daemon now handles SIGINT/SIGTERM by detaching dataplane before exiting.
- Daemon watches reload request files with a short request ticker, independent of the low-frequency poll interval.
- Daemon poll-noop now checks actual pinned map and TC attach health before reporting active.
- Startup guard generation now uses config-only state, so egress fwmark guard can be built before the WireGuard runtime device exists.
- `uninstall --purge` now refuses non-owned config directories and unsafe parent directories.
- `uninstall` no longer ignores critical cleanup errors for service stop, detach, guard cleanup, pins, state dirs, service files, or daemon reload.
- OpenWrt hotplug no longer depends on BusyBox `date +%s%N`.
- `runtime.require_nonzero_fwmark=false` is rejected in the MVP.
- Ingress IPv6 checksum correction now passes `BPF_F_IPV6` to `bpf_l4_csum_replace()` without passing that flag to `bpf_skb_store_bytes()`.
- `guard-cleanup` treats missing nft guard table as idempotent success.
- `status` can still return daemon degraded state when desired runtime state cannot be built.

## Validation

Local:

```text
go test ./...: pass
CGO_ENABLED=0 go build -trimpath -o /tmp/wg-mix-ebpf-hardening-check ./cmd/wg-mix-ebpf: pass
```

## Deferred

Not completed in this pass:

- rtnetlink event watcher.
- attach-state metadata for stale underlay cleanup independent of current config.
- deep doctor probe that loads a minimal sched_cls program and attaches/detaches temporary TC filters.
- real-host retest of the new stop/uninstall behavior.
