# B82 FakeTCP backends v1

This versioned harness validates the production FakeTCP backend matrix on the
controlled `192.168.10.82` host. It does not contain SSH or credentials and
must be executed from an exact root-owned source stage:

```text
/run/wg-mix-ebpf-source-stages/<8hex>/source
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

Reviewed entry argv (replace placeholders only with the staged commit and an
eight-hex matrix ID):

```bash
/usr/bin/python3 -B -I \
  "/run/wg-mix-ebpf-source-stages/<stage-id>/source/scripts/realhost-b82-faketcp-backends-v1/matrix.py" \
  plan \
  --source "/run/wg-mix-ebpf-source-stages/<stage-id>/source" \
  --commit "<40-lowercase-hex>" \
  --kernel-release "$(uname -r)" \
  --matrix-id "<8-lowercase-hex>"

/usr/bin/python3 -B -I \
  "/run/wg-mix-ebpf-source-stages/<stage-id>/source/scripts/realhost-b82-faketcp-backends-v1/matrix.py" \
  run \
  --source "/run/wg-mix-ebpf-source-stages/<stage-id>/source" \
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
traffic, followed by simultaneous per-WG pings.

WireGuard private keys remain run-owned mode-0600 files only long enough to
derive the public keys and configure their matching interface. The driver opens
each private key on a held file descriptor, passes it to `wg set` through
`private-key /dev/stdin`, records only that redacted stdin contract, and removes
the exact key file immediately after the matching command succeeds. Neither the
private-key value nor its backing path enters the child command argv.

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

Root writes are bounded to the matrix/cell evidence roots (including a
per-cell `artifacts/` directory), stage-owned Go caches, three run-derived
network namespaces, two private bpffs mounts/pin roots, and the selected module
only when this cell loaded it and recorded its boot/object/module identity.
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

No file in this directory connects to a host, reads `credientials/`, invokes
`sudo`, starts a local container, or performs work merely by being imported.
