# B82 FakeTCP backends v1

This versioned harness validates the production FakeTCP backend matrix on the
controlled `192.168.10.82` host. It does not contain SSH or credentials and
must be executed from an exact root-owned source stage:

```text
/var/tmp/wg-mix-ebpf-source-stages/<8hex>/source
```

Entry points:

* `matrix.py plan --source ... --commit ...` prints every classified cell and
  performs no mutation.
* `matrix.py run --source ... --commit ...` invokes the root cell runner for
  supported cells and records a complete matrix log.
* `root-cell.sh plan ...` prints the exact per-cell resource and command
  contract without mutation.
* `root-cell.sh run ...` creates the isolated topology, runs the cell, and
  explicitly restores only that run's resources after success.

`matrix.py` invokes only `root-cell.sh`. The root cell owns source/artifact
identity, complete phase logs, failure evidence, and the one explicit restore
call. `root-netns-cell.sh` is its internal per-cell topology driver: `run`
creates and proves the topology, then returns `PASS_READY_FOR_RESTORE` without
cleaning; `restore` removes exact run-owned resources. Keeping these roles
separate avoids two cleanup owners or a hidden second execution path.

Each daemon enters its exact endpoint network namespace before creating its
private mount namespace. The endpoint child proves that `/proc/self/ns/net`
matches the run-derived `/run/netns/<name>` mount, then bind-mounts its private
run/state/gate paths, mounts its private bpffs, and directly execs the daemon.
No second `ip netns exec` occurs after the bpffs mount, so the namespace helper
cannot replace `/sys` and hide the daemon's private bpffs view.

Reviewed entry argv (replace placeholders only with the staged commit and an
eight-hex matrix ID):

```bash
/usr/bin/python3 -B -I \
  "/var/tmp/wg-mix-ebpf-source-stages/<stage-id>/source/scripts/realhost-b82-faketcp-backends-v1/matrix.py" \
  plan \
  --source "/var/tmp/wg-mix-ebpf-source-stages/<stage-id>/source" \
  --commit "<40-lowercase-hex>" \
  --kernel-release "$(uname -r)" \
  --matrix-id "<8-lowercase-hex>"

/usr/bin/python3 -B -I \
  "/var/tmp/wg-mix-ebpf-source-stages/<stage-id>/source/scripts/realhost-b82-faketcp-backends-v1/matrix.py" \
  run \
  --source "/var/tmp/wg-mix-ebpf-source-stages/<stage-id>/source" \
  --commit "<40-lowercase-hex>" \
  --kernel-release "$(uname -r)" \
  --matrix-id "<8-lowercase-hex>"
```

Run `plan` first and review its expanded root-cell `argv`, write set, and
classifications. The script itself has no SSH transport; staging and invocation
on B82 remain a separately reviewed controller operation.

The matrix crosses WireGuard counts `1/2/4`, TC backends `tcx/classic_tc`, and
checksum bridges `kfunc/kprobe`. XOR modes rotate through
`none/prefix/full`; the 2- and 4-WG cells exercise GSO traffic. Every FakeTCP
cell retains exact generic XDP.

Each WireGuard explicitly receives bounded policy values rather than aggregate-
unsafe defaults: session 2048, half-open 256, source ledger 512, pending flows
128, and pending bytes 131072. Even the 4-WG cell remains strictly below every
shared implementation ceiling. Each WG gets independent ping and short iperf
traffic, followed by simultaneous per-WG pings. The driver waits for the exact
iperf TCP listen socket before starting a client and lets the per-WG `/30`
route select the source address instead of forcing an additional `-B` bind.
`gso=off` and `gso=on` are real interface profiles: both endpoint underlays and
every run-owned WireGuard device have TX checksum offload plus TSO/GSO/GRO
explicitly disabled or enabled, and the resulting `ethtool -k` state is
recorded and validated before traffic begins. RX checksum is not forced because
WireGuard advertises it as fixed off on supported kernels.

WireGuard private keys are generated into unexported shell variables, used to
derive the public keys, and streamed through anonymous pipes. No private-key
path is created. Only the pipe crosses the `ip`/`wg` exec boundary, where `wg
set` consumes it through `private-key /dev/stdin`. This avoids the Ubuntu
AppArmor/LSM path recheck that can reject reopening `/dev/stdin` when it is
backed directly by a regular file. The driver records only the redacted stdin
contract. Neither private-key value enters a child command argv or logs; both
values are unset before an observed `wg set` failure exits, so the other peer
cannot leave an unconsumed named key behind.

On a Linux 5.15 boot, TCX cells are recorded as `SKIP_UNSUPPORTED` before the
cell runner is invoked. Explicit kfunc cells are recorded as
`REJECT_UNSUPPORTED`; classic TC + kprobe + legacy artifact remains the
required 5.15 execution path. A kernel 7.x B82 run cannot be used as evidence
that the legacy verifier accepts the object on 5.15.

The harness intentionally retains the complete evidence root under
`/var/tmp/wg-mix-ebpf-faketcp-backends-v1/<run-id>`. The persistent parent,
matrix root, and each cell root are root-owned mode `0700`. It does not delete
evidence after success or failure. An unexpected failure stops the matrix,
captures all stdout/stderr and read-only state in one pass, and leaves the
failed cell resources for an explicit, reviewed recovery invocation.

Root writes are bounded to the matrix/cell evidence roots (including per-cell
`artifacts/` and `build-cache/` directories on `/var/tmp`), the staged
read-only Go module cache, three run-derived network namespaces, two private
bpffs mounts/pin roots, and the selected module only when this cell loaded it
and recorded its boot/object/module identity. Writable Go build, path, and
temporary caches never consume the `/run` source-stage tmpfs.
The root-owned source checkout is frozen: three BPF objects, the Go binary and
the selected module are all redirected to the cell artifact directory, and a
full non-`.git` tree digest plus Git clean/commit identity is checked before
and after build, cell execution, and restore. No build rewrites embedded
objects in the source checkout.

The kfunc module load uses the exact 17-character
`<stage-id>-<cell-run-id>` lease. The receipt and restore path bind that lease
to the module object and loaded generation. A pre-existing module is never
unloaded; the daemon status/doctor contract must still prove the requested
backend. The capture and daemon PIDs are stopped only after executable,
namespace, boot, and start identity checks. Evidence is retained after
successful restore.

After the kfunc module identity and lease are ready, every modern/kfunc cell
runs the built binary's production verifier sweep:

```text
wg-mix-ebpf bpf-load-test --faketcp --object <modern-object> --json
wg-mix-ebpf bpf-load-test --faketcp-legacy-515 --object <legacy-object> --json
```

The command loads every manifest-approved FakeTCP program independently, so a
single invocation reports all verifier failures instead of stopping at the
first program. Its exact argv, full stdout/stderr, and exit code are recorded
through the normal evidence logger. A failure stops the cell and retains all
evidence and owned resources for explicit review and restore. This gate runs
before endpoint state creation and before any network namespace, WireGuard,
link, address, route, qdisc/filter, XDP, or nftables mutation. Legacy/kprobe
cells do not invoke it because the CLI verifier command currently accepts only
the modern FakeTCP object; legacy loading is still exercised by the production
daemon path.

No file in this directory connects to a host, reads `credientials/`, invokes
`sudo`, starts a local container, or performs work merely by being imported.
