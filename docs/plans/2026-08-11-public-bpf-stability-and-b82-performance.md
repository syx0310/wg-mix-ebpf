# Public BPF Stability And B82 Performance Plan

## Scope

This change adds one standalone real-host tool and records a separate B82
performance execution plan:

* `scripts/realhost-public-smoke-v1` runs a low-rate, bounded WireGuard plus
  baseline eBPF stability test between `192.168.10.82` and `47.116.202.155`.
* the B82 performance phase reuses the already reviewed isolated netns smoke
  only after a clean current source stage can be built on `192.168.10.82`.

The public test does not call the existing B82 release controller, retirement
machinery, real-NIC acceptance matrix, or soak harness. It also does not claim
FakeTCP production coverage: the current production FakeTCP request builder is
intentionally fail-closed. The public test exercises the currently attachable
UDP type-word dataplane on both endpoints.

## Fixed safety boundary

Both suites are fail-closed and use a caller-selected 12-24 lowercase hex run
ID. Every created path contains that run ID; the 15-byte staging-interface
limit is handled with a role prefix plus a contract-bound claim digest. The
root runner accepts only an absolute, root-owned, non-symlink copy of itself
and exact artifact SHA-256 values. It refuses pre-existing run paths,
WireGuard names, BPF pin paths, or foreign interface state.

The public test may create only:

* one local evidence directory under
  `/private/tmp/wg-mix-public-smoke-evidence-*`;
* one non-root intake directory per host under
  `/tmp/wg-mix-public-smoke-*-intake`;
* one executable run directory per host under `/var/tmp/wg-mix-ebpf-public-smoke-*`;
* one claim-derived staging WireGuard name per host, renamed to the fixed test
  name (`wgps82` or `wgps47`) only after its ownership alias is installed;
* one run-owned BPF pin directory immediately below the host bpffs mount;
* one run-owned attach-state directory;
* bounded foreground traffic/capture commands; their SSH calls remain open,
  and a held shared service lock prevents restore while either command runs.

It does not edit firewall/routing policy, change MTU or offloads, touch
`idxhy_v4`, or adopt foreign TC/BPF objects. The production loader uses exact
TCX ownership on B82 and the journaled classic-TC backend on the 5.15 public
host. Both backends share the same map owner, recovery, status, and detach
lifecycle; backend switching with an existing owner is rejected until detach.
The loader may also update its project-scoped lease, pin-lock, owner-index, and
append-only owner-history records below `/run/wg-mix-ebpf` and
`/var/lib/wg-mix-ebpf/pin-owners`. These shared audit records are disclosed in
the frozen execution contract and are not deleted by the smoke-test cleanup.

The B82 performance test may create only the resources already declared by the
reviewed private-mountns smoke harness. It does not touch `ens33` or any
pre-existing interface.

Cleanup is a separate, contract-bound and retryable `cleanup` operation; a
failed run never starts it automatically. Cleanup first proves the ownership
marker and exact device/PID identity, detaches the BPF owner, exports evidence
through resumable local files, removes only the named test devices and known
files, and verifies their absence. Its final purge keeps the ownership marker
until only the endpoint and terminal markers remain, so interruption is
recoverable. It never uses recursive deletion.

## Public stability traffic

The planned qualification is intentionally low-rate:

* one 1 Hz ping stream in each direction for 5 minutes;
* UDP at 96 Kbit/s in each direction;
* one bounded 256 KiB TCP transfer in each direction;
* state samples every 10 seconds;
* bounded underlay capture with a packet and time limit.

Acceptance requires a recent WireGuard handshake, bidirectional byte growth,
no three consecutive ping losses, total ping loss at most one percent, BPF
rewrite counters increasing on both endpoints, zero dataplane error-counter
deltas, no test process exit, and no ownership drift.

## B82 performance matrix

The intended report compares:

1. raw veth TCP;
2. standard WireGuard TCP;
3. the same WireGuard path with the baseline eBPF transform attached to both
   veth endpoints.

For the first current-version report, the reviewed runner records
single-stream forward and reverse TCP and four-stream bidirectional TCP at MTU
1420. A 5-second qualification precedes the 30-second report profile. The
report must disclose the exact source commit/tree, duration, streams,
directions, throughput, retransmits, Jain fairness, and dataplane counters.
No previous or partial evidence may be presented as a fresh result.

## Execution gates

Before any host mutation:

1. commit the scripts on a dedicated branch;
2. pass syntax, static, hermetic, Go, and diff checks;
3. record the commit, each script/artifact SHA-256, complete remote argv, and
   exact write set;
4. obtain an independent review of the frozen scripts;
5. run read-only host probes and bind their hostname/kernel/interface/bpffs/
   selected attachment-backend results into the execution packet;
6. re-hash every remote artifact immediately before execution.

If a probe, identity check, traffic gate, or restore check fails, stop. Do not
retry, substitute another interface/backend, or broaden the cleanup set.
