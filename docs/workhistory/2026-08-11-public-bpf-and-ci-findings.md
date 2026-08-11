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
current product has no reviewed classic-TC fallback; loading a different
backend would not test the current production path. The next public run
requires upgrading the public endpoint to a TCX-capable kernel and making the
fixed tools available, followed by a fresh read-only probe and a new frozen
execution packet.

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
about them. Per instruction, this task did not edit the helper, rerun/cancel the
workflow, or otherwise fix CI.
