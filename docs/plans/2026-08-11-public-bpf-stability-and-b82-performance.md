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
ID. Every created name contains that run ID. The root runner accepts only an
absolute, root-owned, non-symlink copy of itself and exact artifact SHA-256
values. It refuses pre-existing run paths, WireGuard names, BPF pin paths, or
foreign interface state.

The public test may create only:

* one run directory per host under `/run/wg-mix-ebpf-public-smoke-*`;
* one temporary WireGuard interface per host (`wgps82` or `wgps47`);
* one run-owned BPF pin directory immediately below the host bpffs mount;
* one run-owned attach-state directory;
* bounded traffic/capture processes whose PIDs and `/proc` identities are
  recorded in the run directory.

It does not install packages, edit firewall/routing policy, change MTU or
offloads, delete/recreate qdiscs, touch `idxhy_v4`, or adopt foreign TC/BPF
objects. The current loader requires exact TCX ownership. A host without TCX
support stops during the read-only `probe` phase; there is no classic-TC
fallback.

The B82 performance test may create only the resources already declared by the
reviewed private-mountns smoke harness. It does not touch `ens33` or any
pre-existing interface.

Cleanup is a separate `restore` operation. Failure never invokes automatic
root cleanup. Restore first proves the ownership marker and exact device/PID
identity, detaches the BPF owner, removes only the named test devices and known
files, and verifies their absence. It never uses recursive deletion.

## Public stability traffic

The default qualification is intentionally low-rate:

* one 1 Hz ping stream in each direction for 15 minutes;
* UDP at 384 Kbit/s in each direction;
* one bounded 1 MiB TCP transfer in each direction;
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
   TCX results into the execution packet;
6. re-hash every remote artifact immediately before execution.

If a probe, identity check, traffic gate, or restore check fails, stop. Do not
retry, substitute another interface/backend, or broaden the cleanup set.
