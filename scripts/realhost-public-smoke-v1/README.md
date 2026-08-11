# Public two-host BPF smoke

This directory contains a standalone, low-rate test path for
`192.168.10.82` and `47.116.202.155`. It does not invoke the B82 release,
retirement, real-NIC, or soak controllers.

The test is deliberately split into an offline plan, a read-only eligibility
probe, an executing run, and an explicit recovery command:

```sh
scripts/realhost-public-smoke-v1/controller.py plan \
  --run-id 0123456789ab \
  --commit COMMIT_40HEX \
  --binary /absolute/path/to/wg-mix-ebpf-linux-amd64 \
  --object /absolute/path/to/wg_mix_tc.o \
  --seconds 120

scripts/realhost-public-smoke-v1/controller.py probe

scripts/realhost-public-smoke-v1/controller.py run \
  --run-id 0123456789ab \
  --commit COMMIT_40HEX \
  --binary /absolute/path/to/wg-mix-ebpf-linux-amd64 \
  --object /absolute/path/to/wg_mix_tc.o \
  --seconds 120 \
  --ownership-token TOKEN_32HEX_FROM_PLAN \
  --contract-sha256 SHA256_FROM_PLAN
```

`run` uses the same production loader in two explicit modes: `tcx` on the B82
kernel and `classic_tc` on the 5.15 public endpoint. It refuses to start unless
both read-only probes report the role's minimum kernel, bpffs, the fixed
physical interface, and all fixed tools. This is not a smoke-only attach
implementation: both modes use the production owner journal, recovery, status,
and detach paths. A failed operation never triggers a broad or `finally`-style
privileged cleanup. Once qualification passes, the controller enters an
explicit restore/export/purge sequence; if that sequence stops, the same
frozen cleanup command is retryable. The plan binds the controller, transport,
endpoint, traffic helper, report, binary, object, traffic bounds, remote
layout, and root endpoint argv into one SHA-256. After reviewing retained
ownership state, use the exact `cleanup_argv` printed by `plan`:

```sh
scripts/realhost-public-smoke-v1/controller.py cleanup \
  --run-id 0123456789ab \
  --commit COMMIT_40HEX \
  --binary /absolute/path/to/wg-mix-ebpf-linux-amd64 \
  --object /absolute/path/to/wg_mix_tc.o \
  --seconds 120 \
  --ownership-token TOKEN_32HEX_FROM_PLAN \
  --contract-sha256 SHA256_FROM_PLAN
```

The controller accepts 30–900 seconds and at most 1 Mbit/s of UDP per
direction. The default is 120 seconds at 384 Kbit/s plus one 1 MiB TCP transfer
per direction. A release stability run uses `--seconds 900` only after the
short qualification succeeds.

The server and capture commands are bounded foreground SSH operations rather
than detached daemons. Both hold a shared run service lock; cleanup must obtain
the exclusive lock before touching WG/BPF resources, so an interrupted local
controller cannot race a still-running remote command.

Never bypass a failed probe, substitute another interface/backend, reuse a run
ID, or run `root-endpoint.py` from a user-owned checkout. Before a real run,
commit and independently review these files, freeze all artifact hashes and
expanded argv, and install the endpoint through the controller's root-owned
copy gate.

The run removes its WireGuard interfaces, BPF links/filters, pins, run roots,
and intake directories. Its run-specific local evidence directory under
`/private/tmp` is retained. Classic TC deliberately retains the shared
`clsact` qdisc; the release gate must prove it existed before the run and that
both canonical filter slots were empty. Production lifecycle serialization
and pin ownership also update project lock/audit records under `/run/wg-mix-ebpf`,
`/run/.wg-mix-ebpf-daemon.lease.maintenance`, and
`/var/lib/wg-mix-ebpf/pin-owners`. Those records are retained as recovery
history rather than byte-restored; they are not active network/BPF resources.
