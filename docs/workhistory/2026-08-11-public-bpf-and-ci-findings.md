# Public BPF and CI findings — 2026-08-11

## Read-only host qualification

The new standalone controller ran only its fixed read-only probe. It did not
invoke `sudo`, upload files, create interfaces, attach BPF, or alter either
host.

* `192.168.10.82`: Ubuntu test host identity matched, kernel
  `7.0.0-28-generic`, `ens33` present, bpffs present, required tools present,
  TCX eligibility passed.
* `47.116.202.155`: kernel `5.15.0-71-generic`, `eth0` present and bpffs
  present, but `bpftool` is absent and the kernel is below the current loader's
  conservative TCX floor.

The public two-host BPF run therefore stopped with zero remote writes. The
follow-up development adds a production `classic_tc` backend for the 5.15
endpoint while retaining exact TCX on newer kernels. A new run still requires a
fresh read-only probe and a newly frozen execution packet; the earlier stopped
run is not reused as evidence.

## B82 performance readiness

The B82 host is capable of the intended isolated performance run. Its previous
root-owned source stage has already been retired, as designed. The retained
`/run/wg-mix-ebpf-tests/*` directories inspected during this work contain no
completed TCP/iperf result set suitable for a current performance report; no
numbers were invented or reused.

A fresh stage currently cannot be built by the reviewed stage builder because
the same baseline BPF compilation error described below fails before the
isolated performance harness can start. The existing incomplete run directories
pre-date this task and were not modified or removed.

## GitHub Actions diagnosis

The failing GitHub Actions run is
<https://github.com/syx0310/wg-mix-ebpf-private/actions/runs/31453242688>.
The Linux amd64 job first fails in `make test-bpf-object-manifests`:

```text
bpf/wg_mix_tc.c:1622:29: error: unused function
'set_faketcp_xor_context' [-Werror,-Wunused-function]
```

`set_faketcp_xor_context` is defined unconditionally, while its only callers
are inside `WG_MIX_EXPERIMENTAL_FAKETCP`. The baseline build does not define
that macro, and `-Wall -Werror` promotes the unused-function warning to an
error. The helper was introduced by commit
`9c099a0c509d8d1cc2ce3556fb29ad3c3488d498`.

The failure is a compile-time feature-guard mismatch, not a BPF verifier or
real-host failure. All later unit, static, race, architecture-build, offline
validation, and packaging steps were skipped, so that run provides no evidence
about them. The baseline-only build now appends the explicitly approved
`-Wno-unused-function`; the experimental object retains the full
`-Wall -Werror` policy. The helper and runtime feature guards were not changed.

Reproducing the next build step with the workflow's Ubuntu 24.04 and Clang 18
also exposed stale FakeTCP GSO ABI constants: Clang reports the egress
admission and its map slot as 176 and 184 bytes, while the merge that added the
24-byte GSO projection had retained 168/176 assertions. The compile-time
assertions, experimental manifest, and source contract now agree on 176/184;
the pinned baseline ABI is unaffected because this map exists only in the
separately built experimental object.

The same compiler then exposed three verifier-facing implementation issues
that the earlier toolchain did not reject:

* FakeTCP admission used a 32-bit atomic compare-and-swap operand. The state is
  now a 64-bit value, matching the native BPF atomic width accepted by Clang
  18 and preserving the single-use transition semantics.
* several egress, GSO, continuation, XDP, and ingress proof objects could exist
  simultaneously on the BPF stack. They now live in a dedicated per-CPU
  runtime scratch map. Its experimental ABI value is 344 bytes and is locked
  by the source and object-manifest tests. Large objects are addressed through
  scratch pointers; the egress admission is populated field by field so Clang
  cannot synthesize another stack-sized compound temporary.
* the variable-bound GSO XOR loop could not be fully unrolled. It is now a
  verifier-friendly fixed-bound loop with an explicit active-range guard.

Clang emits two mutually exclusive static call-site relocations for the
FakeTCP prepare kfunc (GSO and non-GSO) and one relocation for the commit
kfunc. The experimental manifest therefore requires exact counts 2 and 1;
this is a static object property, not a claim that both prepare branches run
for one packet.

After these changes, the exact workflow-equivalent Ubuntu 24.04, Clang 18 and
Go 1.25 invocation of `make test-bpf-object-manifests` passes for both the
baseline and experimental objects. The baseline retains its pinned map and
program ABI; the new scratch map and changed FakeTCP structures are confined
to the explicitly experimental object.

## Classic TC compatibility implementation

The production loader now supports two durable attachment backends:

* `tcx`, using the existing exact-link schema-v4 ownership record;
* `classic_tc`, using fixed clsact ingress/egress filter slots and the existing
  schema-v3 ownership wire format.

`runtime.attachment_backend` accepts `auto`, `tcx`, or `classic_tc`. Auto mode
is sticky to an existing durable owner, probes TCX before any owner mutation
when targets exist, and falls back only for classified unsupported-kernel
errors. Permission, malformed-state, and other ambiguous failures remain
fail-closed. A fresh idle configuration remains a true no-op, while explicit
legacy adoption selects the classic backend and retains its existing integrity
checks.

Classic TC uses the same staged owner journal, crash recovery, reboot rekey,
status, and detach lifecycle as TCX, but records exact classic filter program
IDs instead of TCX link IDs. Schema-v3 serialization is canonicalized to the
historical field set and ordering, including required empty filter arrays, so
old active and archived owner digests remain readable. Schema-aware comparison
is also used by cleanup CAS checks.

The Linux fake runtime now covers applying and detaching recovery phases,
top-level backend-specific detach dispatch, prior-boot classic rekey, and the
production-constructor fresh-idle auto path. These tests do not substitute for
the planned real 5.15 verifier/load test, which remains gated on a committed,
reviewed script and exact host execution packet.

## Public execution-controller hardening

The first independent review of the standalone public controller stopped the
live run before any write. The execution path now binds controller, transport,
endpoint, traffic, report, binary, object, source HEAD/tree/cleanliness,
traffic bounds, remote layout, write set, and expanded endpoint argv into one
plan SHA-256 that both `run` and `cleanup` must reproduce.

Remote run roots use fresh `mkdir` plus no-target endpoint installation. The
endpoint publishes its owner record before copying artifacts; an exact
unclaimed-root abort and partial-prepare restore/export/purge path cover the
earlier failure window. Local evidence export and remote cleanup are
idempotent, so qualification failure or an interrupted restore can be resumed
with the frozen cleanup argv. The 5.15 gate also records that `eth0` had one
pre-existing shared `clsact` and no ingress/egress filters, and restore requires
that exact filter baseline again.

The final execution review additionally made the owner record an atomic
pending-to-final publication, bound each non-root intake to a deterministic
contract claim before creating the root run directory, and made the WG alias
part of the single link-create operation. Server and capture commands now stay
in bounded foreground SSH calls instead of detached child processes; they hold
a shared service lock that restore must acquire exclusively. Local endpoint
evidence uses resumable pending files and a complete manifest binding each
file's size and digest, while remote purge retains recovery markers until its
last three unlink operations.
