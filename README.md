# wg-mix-ebpf

Transparent WireGuard `type_word` transform using eBPF.

Current status: control-plane foundation, daemon reconcile loop, profile management, generation-scoped map ABI, startup guard tooling, attach-state cleanup, baseline plus modern/legacy FakeTCP embedded BPF packaging, Linux TC/eBPF dataplane loading, UDP type-word mode, optional XOR payload obfuscation, IPv4 ICMP mode, and production IPv4 FakeTCP mode are implemented. Live BPF load, TC/XDP attach, WireGuard, offload, and performance tests must run on controlled external Linux machines.

## Commands

```bash
wg-mix-ebpf doctor
wg-mix-ebpf install --dry-run
wg-mix-ebpf init --wg wg0 --underlay eth0:netdev --profile home --profile-preset wireguard-mix-wire-values-v1
wg-mix-ebpf profile list
wg-mix-ebpf profile show home
wg-mix-ebpf profile add home-random
wg-mix-ebpf profile token home
wg-mix-ebpf profile check 'wgmix1....'
wg-mix-ebpf profile remove home --force
wg-mix-ebpf run --once --offline --dry-run
wg-mix-ebpf reload --config configs/example.yaml --offline --dry-run
wg-mix-ebpf validate --config configs/example.yaml --offline
wg-mix-ebpf status --config configs/example.yaml --offline
wg-mix-ebpf dump --config configs/example.yaml --offline
wg-mix-ebpf dump-abi --config configs/example.yaml --offline
wg-mix-ebpf guard-plan --config configs/example.yaml --offline
wg-mix-ebpf guard-apply --config configs/example.yaml --offline --dry-run
wg-mix-ebpf guard-cleanup --config configs/example.yaml --offline --dry-run
wg-mix-ebpf features
wg-mix-ebpf uninstall --dry-run --yes
```

`--offline` skips runtime WireGuard and underlay reads. It is intended for local static validation and unit-test environments. Applying a reload or running the daemon with `--offline` requires `--dry-run`; the agent refuses to replace live maps with an empty runtime-derived state.

`install` only installs files and registers service/init scripts. It does not start, enable, reload, attach TC, or modify WireGuard. Use `install --enable` if service enablement is desired, then start the service explicitly with systemd or OpenWrt init.

`run` is the internal daemon entrypoint used by service managers. It performs startup reconcile, periodic runtime reconcile, and reload-request handling. Manual `reload` notifies the daemon when it is running; otherwise it performs a one-shot reconcile.

`profile remove <name> --force` removes the profile and stops managing WireGuard entries that reference it. It does not change WireGuard configuration or interfaces.

Supported transport modes:

```text
udp    original transparent UDP type-word transform
icmp   IPv4 ICMP Echo transport
faketcp IPv4 TCP-shaped packet transport (one or more WireGuards, resident daemon)
```

Optional cipher mode:

```text
xor    UDP or FakeTCP WireGuard payload XOR obfuscation, auth=none
```

Implemented combinations:

| Transport | IP | Attachment | XOR | Operational contract |
| --- | --- | --- | --- | --- |
| UDP | IPv4/IPv6 | `auto`, `tcx`, `classic_tc` | none, prefix, full | normal daemon or one-shot reload |
| ICMP Echo | IPv4 | `auto`, `tcx`, `classic_tc` | unsupported | client/server roles |
| FakeTCP | IPv4 | `auto`, `tcx`, `classic_tc`; always exact generic XDP | none, prefix, full | one or more WGs, resident daemon, fixed distinct ListenPorts, `auto`/`kfunc`/`kprobe` checksum backend |

Pure kernel WireGuard without this dataplane remains the performance and
interoperability baseline; it is not a fourth transform mode. FakeTCP does not
support libxdp chaining, existing XDP ownership, XDP replacement/fallback, or
one-shot execution. TC attachment and checksum bridging are independent:
modern kernels prefer TCX plus kfunc, while classic TC plus the legacy kprobe
bridge is the Linux 5.15 compatibility path. Exact generic XDP remains required
in every FakeTCP combination.

Operational behavior is documented in:

```text
docs/architecture.md
docs/build.md
docs/compatibility.md
docs/configuration.md
docs/operations.md
```

## Development

```bash
make test-unit
CGO_ENABLED=0 go build -o /tmp/wg-mix-ebpf ./cmd/wg-mix-ebpf
```

The default Makefile build and test targets use `CGO_ENABLED=0` for reproducible cross-platform builds.

## Linux Dataplane

The Go binary does not require cgo. Baseline, modern FakeTCP, and legacy Linux
5.15 FakeTCP BPF objects are compiled during packaging and embedded into the
binary:

```bash
make build-bpf
make build-faketcp-legacy-515-bpf
make build-linux-amd64
sudo ./bin/wg-mix-ebpf-linux-amd64 bpf-load-test
```

Packaged binaries do not need clang, kernel headers, or a separate `.o` file on the target machine. For development, override the embedded object with:

```text
WG_MIX_EBPF_OBJECT=/path/to/wg_mix_tc.o
```

or `--object /path/to/wg_mix_tc.o`.

FakeTCP uses independent object overrides and never falls back to the baseline
object:

```text
WG_MIX_EBPF_FAKETCP_OBJECT=/path/to/wg_mix_faketcp_experimental.o
WG_MIX_EBPF_FAKETCP_LEGACY_515_OBJECT=/path/to/wg_mix_faketcp_legacy_515.o
```

The selected `runtime.checksum_backend` additionally requires the administrator
to provision and load either the matching `wg_mix_faketcp_checksum` kfunc
module or `wg_mix_faketcp_checksum_kprobe` legacy module. The kprobe module
supports multiple per-runtime FD leases/cookies; each daemon retains its own
fixed cookie and never falls back after activation. The currently validated
kprobe bridge target is Linux x86_64; arm64 FakeTCP requires the kfunc backend
until a separate kprobe calling-convention implementation is validated.
`wg-mix-ebpf doctor
--config ...` checks the selected module, artifact, bridge ABI, trigger, and
health contract before activation. The service never loads or unloads an
administrator-owned module.

Every FakeTCP WireGuard requires a fixed, distinct, non-zero `ListenPort`,
`startup_guard.mode: nft-temporary-drop`, and
`policy.startup_fail_mode: fail_closed_for_managed_flows`. The guard remains
installed until the resident runtime passes its final map and attachment
health check.

Do not run BPF load, TC attach, netns, OpenWrt, offload, or performance tests on non-Linux development machines.

`bpf-load-test` only loads and closes the BPF collection. It does not read WireGuard runtime state, attach TC filters, create network namespaces, or send tunnel traffic.

External Linux/OpenWrt/BPF/TC tests require controlled machines. Do not run those tests on laptops or unrelated shared hosts.

On a controlled Linux test host, the full isolated namespace gate is:

```bash
sudo make test-netns-full
```

To run only the TCP 1/4/16-flow, forward/reverse/bidirectional, and WireGuard
MTU 1419-1422 tail-alignment matrix (type-word-only, XOR prefix, and XOR full),
use:

```bash
sudo make test-netns-tcp
```

The positive 1500-byte underlay PMTU boundaries are a separate IPv4/IPv6 gate:

```bash
sudo make test-netns-tcp-pmtu-positive
```

The TCP matrix requires `iperf3`; the default lightweight namespace smoke
targets do not. It treats TCP delivery, retransmits, packet captures, and
dataplane error counters as correctness gates. Inner TCP GSO capability and
outer UDP GSO/GRO observations are reported separately, because kernel
WireGuard may segment an inner GSO skb before producing the outer UDP packets.
Use `sudo make test-netns-tcp-outer-gso-observe` for a focused 16-flow,
simultaneous-bidirectional outer-GSO observation run; a missing observation is
reported as `not-covered`, not as a pass. This is still TCP-over-WireGuard and
does not replace a dedicated outer-UDP `UDP_SEGMENT`/GRO workload.

Run `bpf-load-test` on every supported kernel baseline as well as the build
kernel; verifier acceptance can differ even when the embedded object is
identical.
