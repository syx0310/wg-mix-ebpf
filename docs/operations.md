# Operations

This document describes the intended operational flow for `wg-mix-ebpf`.
Configuration details and support levels are documented in
[configuration.md](configuration.md) and [compatibility.md](compatibility.md).

## Command Model

The normal user-facing commands are:

```text
doctor
install
init
profile
reload
status
stop
uninstall
```

`run` is the daemon entrypoint used by systemd or OpenWrt procd. It is available as a command, but users normally interact with it through the service manager.

## Install

`install` only installs files and service definitions:

```bash
sudo wg-mix-ebpf install
```

It does not start the service, enable boot startup, attach TC filters, reload dataplane state, or modify WireGuard configuration.
Non-dry-run installation acquires the global lifecycle lease and then the
runtime-directory operation lock before replacing any files, so it refuses to
replace a binary or service definition while a daemon or one-shot mutation is
active.

To enable the service without starting it:

```bash
sudo wg-mix-ebpf install --enable
```

Start explicitly:

```bash
sudo systemctl start wg-mix-ebpf
```

On OpenWrt:

```bash
/etc/init.d/wg-mix-ebpf start
```

## Init

`init` creates or updates `/etc/wg-mix-ebpf/config.yaml`. It can create or import a profile and bind WireGuard interfaces to underlays:

```bash
sudo wg-mix-ebpf init \
  --wg wg0 \
  --underlay eth0:netdev \
  --profile home \
  --profile-preset wireguard-mix-wire-values-v1
```

For a matching endpoint profile:

```bash
sudo wg-mix-ebpf profile token home
sudo wg-mix-ebpf profile check 'wgmix1....'
sudo wg-mix-ebpf init --wg wg0 --underlay eth0:netdev --profile-token 'wgmix1....'
```

`init` reads the expected `FwMark` from the WireGuard config or supported `PostUp = wg set %i fwmark ...` command. It does not add or change `FwMark`, `ListenPort`, peers, routes, or addresses. Re-running `init` for an existing entry preserves its cipher, transport, and underlay parser settings. `init --reload` requests the running daemon when present and otherwise uses the global lifecycle lease plus reconcile operation lock.

## Daemon Reconcile

The daemon performs startup reconcile, poll reconcile, and reload-request handling:

```bash
sudo wg-mix-ebpf run --config /etc/wg-mix-ebpf/config.yaml
```

FakeTCP uses a resident BPF collection, direct generic XDP links, selected TC
backend, checksum bridge and slow path. A FakeTCP configuration therefore
rejects `run --once` and one-shot fallback `reload` before network mutation.
Start the service first, then send reload requests to that daemon. Before
activation, an administrator must provision the kernel-matched kfunc or
kprobe checksum module. Check the selected contract with:

```bash
sudo wg-mix-ebpf doctor --config /etc/wg-mix-ebpf/config.yaml
```

For kfunc, the service validates module BTF and required kfuncs before
detaching a baseline runtime and again while acquiring the FakeTCP collection.
For kprobe, it validates both trigger symbols, opens a per-runtime FD lease,
reads the versioned health record, and checks the cookie/capability contract.
The module supports multiple simultaneous leases and cookies; each daemon
retains its own FD and fixed cookie through detach and never switches backend
after activation. It never installs or loads either administrator-owned module.
OpenWrt without a separately packaged matching kmod supports UDP/ICMP but not
FakeTCP.

FakeTCP additionally requires a fixed non-zero `ListenPort` and fail-closed
managed-flow policy. In the default `nft-temporary-drop` profile, the daemon
keeps the guard through object acquisition, map population, selected TC/XDP
attachment, checksum-backend lease, and the final retained-owner health check.
An explicit `startup_guard.mode: none` profile is permitted only as a high-risk
operator choice; it never results from automatic fallback and provides no
startup/reload leak or host-stack RST guarantee.

For an active FakeTCP runtime, `status` reports the resolved attachment and
checksum backends, object variant/digest, exact XDP and TC identities, and the
checksum lease/capabilities. Cookie material is never reported. A kprobe
`nmissed` increment or lease loss changes health to failed; it is never
presented as a successful automatic fallback.

A dataplane-mutating daemon holds an exclusive lifecycle lease at
`/run/wg-mix-ebpf/daemon.lease` from before startup reconcile until shutdown
cleanup and the final status write have completed. This lease is deliberately
independent of `--run-dir`: changing the status/request directory cannot start a
second daemon against the same global BPF pins, TC filters, nftables tables, and
attach state. A second instance fails immediately and reports the current lease
owner. Dry-run daemons use a lease in their selected runtime directory because
they do not mutate those shared resources.

Every non-dry-run one-shot mutation (`install`, `reload`, `detach`, `stop`,
`guard-apply`, `guard-cleanup`, and uninstall cleanup) must acquire that same
global lease before its runtime-directory operation lock. If a caller selects
the wrong `--run-dir` and misses the daemon status file, its fallback operation
is rejected by the global lease and the error includes the current owner and
owner runtime directory. The lease and operation lock reject symbolic links and
multiply-linked files.

The reconcile loop reloads dataplane state when local runtime inputs change:

```text
WireGuard runtime ListenPort
WireGuard runtime FirewallMark
WireGuard interface presence/state
underlay ifindex/link state
OpenWrt hotplug reload request
manual reload request
```

Config file changes are not applied automatically by the low-frequency poll loop. When the daemon notices a config content change during poll/runtime handling, it reports `config_changed` and `need_reload` in status. Apply config changes explicitly:

```bash
sudo wg-mix-ebpf reload
```

This keeps runtime changes automatic while making profile and underlay edits operator-controlled.

It does not update dataplane maps for peer endpoint, handshake time, transfer counter, or DDNS changes.

## Reload

Manual reload uses the same reconcile path as the daemon:

```bash
sudo wg-mix-ebpf reload
```

Offline reload is validation-only and must be a dry run:

```bash
wg-mix-ebpf reload --config configs/example.yaml --offline --dry-run
```

If the daemon is running, `reload` creates a uniquely identified request under
the runtime directory and waits for the ack with that exact request ID. If the
daemon is not running, it performs a one-shot reconcile while holding the
global lifecycle lease.

Requests are stored independently under `requests/`, and acknowledgements under
`acks/`; concurrent clients do not overwrite each other and unrelated poll or
status updates cannot acknowledge a command. Each request is bound to the
random instance ID published by the daemon status, so a stale stop left by an
exiting process is rejected rather than consumed by the next daemon. Requests
already queued while that daemon is starting are processed after startup
reconcile. When a scan contains both stop and reload requests, stop takes
precedence and each reload receives a specific superseded acknowledgement. A
reload already being processed finishes before a later stop. If a client times
out, its error includes the request ID and warns that the queued operation may
still complete.

Queue admission is serialized and capped at 256 pending request files. Clients
return a validated ack immediately, but remove it only after its request file
is gone. If the daemon writes the ack and crashes before removing the request,
the next instance validates the ack kind and processing instance before
discarding the paired request, preserving crash deduplication. The daemon
retains at most 512 ack files, pruning the oldest unpaired entries first and
never pruning an ack whose request still exists.

Protocol-v1 daemons never execute `stop:` from the legacy `reload.request`
file because that format cannot identify the daemon instance. Legacy
`reload:` notifications and OpenWrt `runtime.request` events remain compatible.
These legacy files use the same bounded, no-follow control-file reads; unsafe,
oversized, or unsupported notifications are recorded in status and ignored
without terminating the daemon.

Reload uses generation-scoped maps. New entries are prepared under a new generation, then `active_generation` is committed, and stale generations are cleaned afterward.

Reload and detach operations are serialized with a separate operation lock
under the runtime directory. The daemon keeps its lifecycle lease while
acquiring this short-lived operation lock; the two lock files are distinct, so
stop cleanup does not self-deadlock.

Dataplane map semantics are versioned even when a map's byte size is unchanged.
A binary that finds pinned maps from a different ABI refuses to activate them.
During an upgrade, freeze the old/new commit, binary, embedded object and module
identities; run offline validation and `install --dry-run`; stop the old service
cleanly; transition an administrator-owned module only after all leases are
gone; then install and explicitly start the new service. Never copy or reuse
pinned maps across ABI versions. Keep the previous frozen package for rollback.

Same-key and changed-key reloads both use the generation transaction. Confirm
the exact request acknowledgement, active generation, desired-key state,
runtime pause phase, guard observation and traffic; a successful client return
alone is not the complete proof. Rollback follows the same stop/verify/install/
start boundary and never uses broad pin deletion, blind TC/XDP replacement or
table-name-only nft deletion.

## Status

`status` reports config, runtime, attach, generation, and stats state:

The status file is read with the same bounded, no-follow, regular,
single-link control-file policy as request and acknowledgement files.

```bash
wg-mix-ebpf status
```

Important fields:

```text
active_generation
runtime ListenPort
runtime FirewallMark
underlay ifindex/link type/parser
TC ingress/egress attach state
dataplane counters
last reconcile result
request_protocol / instance_id / last_request_id / last_request_kind
top-level observation_time
startup_guard mode / kernel_state / observation_time / warning / error / risk
startup_guard.runtime_pause phase / reason / since / observation_time
reconcile phase / since / observation_time / error
dataplane
```

`status` reads desired state, pinned/resident dataplane state and the startup
guard kernel observation. Guard state is one of
`active|absent|unknown|disabled`. Inspection failure in a guarded profile is
`unknown`, while explicit mode `none` is `disabled`; neither condition removes
the rest of status output. A warning/error remains visible even when a failed
cleanup command is followed by a complete observation proving the table
absent.

The CLI combines a fresh kernel guard observation with the resident runtime
pause snapshot; the daemon exposes the same projection under `daemon.current`.
Pause phase is `open|draining|held|resuming|stopped`. Pause reason is
`none|startup_guard|runtime_stopping|runtime_closed|runtime_stopped`.

For an active FakeTCP daemon, `status` prefers the resident daemon snapshot
instead of baseline pins. It reports lifecycle and attachment ownership state,
object source and SHA-256, generation/incarnation,
generation-barrier state, health, and exact XDP/TCX link and program IDs.
Runtime, XDP and production TCX ownership is process/FD-owned; classic-TC
filters alone use the durable installation owner and recovery journal. A
baseline exact-TCX pinned journal is not the production FakeTCP TCX stage.
Cipher keys, desired-key digests, cookie material and session contents are
never included.
A separate one-shot status process uses the live daemon snapshot when that
daemon is present and cannot claim its resources.

## Guard And Runtime Emergency State

Interpret guard and runtime pause together:

| Guard kernel state | Pause | Meaning/action |
| --- | --- | --- |
| `absent` or `disabled` | released | Normal; continue owner and traffic checks. |
| `active` | held | Intentional fail-closed; preserve evidence and diagnose the failed stage. |
| `unknown` | held | Do not force resume; repair trusted nft inspection and re-observe. |
| `absent` | held | Finalization fault; preserve journal/status and use version-matched recovery. |
| `active` | released | Inconsistent and potentially dropping traffic; stop further changes. |

Before any recovery, capture complete `status`, `doctor --json`, service logs
and `nft -j list tables` output once. `guard-cleanup` validates the owner record,
random installation table marker, exact handle and complete project inventory;
it is not a general table-name cleanup command. `unknown` remains fail-closed.
After cleanup proves `absent`, runtime resume uses an independent bounded
finalization context and releases only the barrier acquired by that transaction.

## Explicit No-nft Operations

`startup_guard.mode: none` is accepted for UDP, ICMP and FakeTCP only by
explicit configuration. Before entering an environment without the nft binary,
use a working inspection path to prove and record that no owned, legacy or extra
project guard table exists. A no-nft preflight that observes any such table
fails before dataplane mutation and points to explicit recovery.

Successful `guard-cleanup` deliberately preserves the final v2 owner record as
the installation's stable identity. No-nft accepts that record only after
descriptor-anchored strict schema, file, state-directory and identity checks,
followed by a fresh empty kernel project-table inventory. A legacy v1 record,
pending v2 publication, malformed or identity-mismatched v2 record, or any
project table remains fail-closed and requires version-matched recovery.

The daemon does not execute the nft binary in this profile. It still performs a
fresh read-only `NETLINK_NETFILTER` `NFT_MSG_GETTABLE` kernel inventory with a
five-second upper bound, so no-nft is not permission to skip ownership
inspection.

In this profile, `doctor` distinguishes intentional guard disablement from a
missing dependency: `cmd.nft` is non-required and non-failing for explicit
mode `none`, but `startup_guard.inventory` must be `PASS`. A guarded profile
still requires nft. `status` reports `startup_guard.kernel_state=disabled` plus
`startup_guard.risk` describing that standard UDP may leak or the FakeTCP host
stack may interfere during startup/reload. To migrate back, install/verify nft,
prove inventory, change to
`nft-temporary-drop`, inspect `guard-plan`, request a resident reload, and verify
that the healthy transaction ends with guard absent and pause released.

## Stop And Detach

Stopping the service detaches this agent's TC filters:

```bash
sudo systemctl stop wg-mix-ebpf
```

OpenWrt:

```bash
/etc/init.d/wg-mix-ebpf stop
```

If WireGuard continues running after service stop, it may send standard WireGuard type words because the transparent transform is no longer attached.

Service stop calls:

```bash
wg-mix-ebpf stop --config /etc/wg-mix-ebpf/config.yaml
```

When the daemon is alive, `stop` requests the daemon to stop polling, detach
dataplane under the shared operation lock, remove any exactly owned startup
guard, write stopped status, and exit. If the daemon is not alive, `stop` falls
back to one-shot ownership-aware cleanup.

Daemon cleanup has a 10-second deadline by default and can be configured on the
daemon entrypoint with `run --shutdown-timeout`. After that deadline, a fixed
25-millisecond arbitration window captures a cleanup error returned concurrently
with cancellation, so total return time remains hard-bounded. The `stop` client
waits 15 seconds by default (`stop --timeout`) so it can observe the exact
request ack. A cleanup timeout, detach/guard failure, or final status-write
failure is returned to the service manager and produces a non-zero process
exit; when possible the persisted daemon state is `degraded` with the cleanup
error. If a kernel or library call ignores context cancellation, the daemon
returns after the bounded arbitration window but a duplicate lease descriptor
remains owned by the cleanup worker. This prevents another process from mutating
global state before the worker completes; normal service execution exits
immediately on the returned error.

On SIGINT or SIGTERM, the first signal starts the same bounded cleanup and
restores the operating system's default signal behavior. A second signal
therefore terminates the process immediately if cleanup is stuck.

Dataplane cleanup uses `/var/lib/wg-mix-ebpf/attach-state.json` when available. This lets `stop`, `detach`, and `uninstall` remove TC filters even if the WireGuard interface was already stopped or deleted.

Stop never deletes a fixed table by name. A guarded installation recovers and
removes only its exact random owner table after validating marker, handle and
inventory. An explicit no-nft installation with no owner record or a securely
validated stable final v2 owner record reports guard state `disabled` only when
fresh inventory is empty; if an earlier owned/legacy/extra table or unsafe
ownership state is observed, cleanup stops for explicit recovery rather than
ignoring or taking over that state.

## Uninstall

Default uninstall removes network-impacting state but keeps configuration:

```bash
sudo wg-mix-ebpf uninstall
```

It stops the service, detaches this agent's TC/XDP objects using attach-state
when available, removes BPF pins, removes an exactly owned nft guard, removes runtime,
state, and service artifacts, and leaves
`/etc/wg-mix-ebpf/config.yaml` in place. The persistent global lease file and
its parent runtime directory are retained so uninstall never unlinks a live
lock inode. Destructive cleanup paths are restricted to managed descendants of
`/run`, `/var/lib`, `/sys/fs/bpf`, or the system temporary directory; broad or
overlapping paths are rejected even for a dry run.

To remove the config directory too:

```bash
sudo wg-mix-ebpf uninstall --purge
```

The binary and WireGuard configuration are not deleted by either form.

`--purge` refuses custom config paths whose parent directory is not the owned config directory. For example, `--config /etc/wg-mix-ebpf.yaml --purge` is rejected rather than deleting `/etc`.

If the binary was installed manually, remove it manually after uninstall. If it was installed by a package manager, remove it with that package manager.
