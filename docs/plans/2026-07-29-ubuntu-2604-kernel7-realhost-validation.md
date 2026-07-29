# Ubuntu 26.04 / Linux 7.0 Real-Host Validation Plan

## Scope

Primary test host:

```text
address: 192.168.10.82
hostname: ubuntu-2604-test
OS: Ubuntu 26.04 LTS
kernel: 7.0.0-28-generic
machine-id: 9db3fb717cc74974b2a6b243d67f67b9
underlay: ens33, vmxnet3, MTU 1500
```

Controlled peer:

```text
address: 47.116.202.155
OS: Ubuntu 22.04 LTS
kernel: 5.15.0-71-generic
physical NIC: eth0, virtio_net, MTU 1500
route to 192.168.10.82: existing active WireGuard interface idxhy_v4
```

The peer is not an empty test host: `idxhy_v4` carries active WireGuard
traffic, and `eth0` already has a `clsact` qdisc. Until a separately reviewed
design proves isolation from those existing resources, the peer may only act
as an unmodified iperf/ping endpoint. Do not attach BPF or TC programs, change
MTU/offloads/routes, or create competing WireGuard state on either peer
interface.

Credentials are stored outside Git under the ignored `credientials/`
directory. Passwords, private keys, WireGuard private keys, and raw credential
files must not appear in commands, logs, commits, evidence, or documentation.

`192.168.10.28` is outside this test scope.

## Mandatory Safety Gates

No privileged script may run until all of the following are true:

1. The script is committed on a dedicated branch.
2. `bash -n`, available static checks, unit tests, and a failure-path review
   pass. If provisioning supplies `shellcheck`, it must pass before any later
   privileged test script is approved.
3. The main Agent records the target host, script path, Git commit/blob or
   SHA-256, complete argv, and expected write set.
4. A separate reviewer accepts the exact locked content.
5. The remote copy is hashed and matches the approved content immediately
   before execution.

The following are prohibited:

```text
host-root bind mounts
chroot or host mount-namespace entry
inline privileged SSH scripts
root EXIT/ERR cleanup traps
pre-emptive deletion of names or paths
rm -rf
unbounded or pathless find -delete
default /run/wg-mix-ebpf or /var/lib/wg-mix-ebpf test state
the fixed nft startup-guard table
cleanup errors redirected away or converted to success
```

Every test run must use a random run ID, unique run/state/pin/evidence
directories, an ownership marker, and exact resource manifests. A failed run
keeps evidence and stops automatic mutation. Cleanup is a separate, explicit,
auditable action after ownership and device identity are revalidated.

## Phase 1: Provisioning

Run the locked provisioning script in `--check` mode first, with the exact
hostname, interface, kernel release, address, and machine-id above. Its only
approved write set in `--apply` mode is the Ubuntu APT package database/cache
and files installed by this fixed package list:

```text
bpftool ca-certificates clang ethtool gcc git golang-go iproute2 jq
iperf3 libbpf-dev linux-libc-dev llvm make nftables pkg-config python3
shellcheck tcpdump wireguard-tools
```

The initial missing-package set is locked to:

```text
clang gcc golang-go iperf3 libbpf-dev llvm make pkg-config shellcheck
wireguard-tools
```

For a host that already completed the earlier toolchain-only provisioning pass,
the only other accepted missing-package set is exactly `iperf3`. The script
must fail on every other package-state drift, any simulated upgrade/removal, or
any active/enabled service-set change. Do not run `apt upgrade`, remove
packages, mount filesystems, or change network state during provisioning.

## Phase 2: Unprivileged Build And Unit Validation

Run as the normal user:

```text
make test-unit
make test-unit-race
make test-lint
make build-bpf
make build-linux-amd64
```

Record Go, clang, bpftool, compiler, and Git versions together with the tested
commit and built binary/object SHA-256 values.

## Phase 3: Linux 7.0 Verifier Gate

Run the locked binary's `bpf-load-test`. This phase loads and closes the BPF
collection only. It must not attach TC filters, pin maps, create namespaces, or
change network state.

Acceptance:

```text
load succeeds on Linux 7.0
no verifier rejection
no kernel warning/OOPS
no persistent BPF program/map/link remains
```

## Phase 4: Isolated Netns Matrix

Only run the safety-refactored smoke scripts. Required coverage:

```text
UDP outer IPv4 and IPv6
XOR prefix 128 and XOR full 2048
ICMP IPv4 and enforced negative checks
TCP 1, 4, and 16 flows
both traffic directions
tail alignment MTUs 1419, 1420, 1421, and 1422
real PMTU positive boundaries:
  IPv4 1439 and 1440 for underlay MTU 1500
  IPv6 1419 and 1420 for underlay MTU 1500
expected-failure characterization:
  IPv4 1441
  IPv6 1421
```

Correctness gates:

```text
all requested iperf streams transfer non-zero data
netns TCP retransmits are zero
rewrite success counters increase on both sides
all type/length/fragment/checksum/load/store/XOR/dispatch error counters
  have zero delta in positive tests
GSO-enabled cases must increment the corresponding managed-seen and
  rewrite-success counters
standard WireGuard type-word leakage is zero
received UDP checksum failures are zero
WireGuard transfer counters increase in both directions
```

## Phase 5: Real Underlay NIC / Offload Matrix

Before touching `ens33`, record:

```text
machine-id and boot-id
ifindex, ifname, MAC, driver, MTU, master, addresses and routes
all ethtool feature values and fixed/mutable status
TC qdisc and ingress/egress filters
BPF programs/maps/links
WireGuard interfaces
nftables state relevant to wg-mix-ebpf
```

Fail closed if an interface identity changes, an unexpected filter is present,
or the target carries an unprotected management path whose loss would prevent
recovery.

The current peer baseline fails the mutation precondition because `eth0` and
`idxhy_v4` carry pre-existing state. Treat peer-side BPF/TC/offload cells as
`not covered`, not as passes. They require either a dedicated disposable peer
or a separately authorized, independently reviewed isolation design.

The matrix must distinguish unsupported feature toggles from passing cells:

```text
all supported offloads on
all mutable checksum/GSO/GRO/TSO features off
TX checksum only
RX checksum only
TX checksum plus GSO/TSO/UDP tunnel segmentation
RX checksum plus GRO/UDP GRO forwarding
asymmetric endpoint combinations
```

After each change, read `ethtool -k` again and compare with the requested
state. Restore the exact original values, not a hard-coded `on` state, and
verify restoration before the next cell.

For every correctness cell:

```text
1, 4, and 16 TCP streams
forward, reverse, and simultaneous bidirectional traffic
at least 30 seconds per direction
Jain fairness >= 0.90 for multi-stream tests
estimated retransmit rate <= 0.01%
zero dataplane error-counter delta
zero received checksum failures
zero standard type-word leakage
```

## Phase 6: Bounded Soak

First run a one-hour qualification soak:

```text
XOR prefix 128
all supported offloads enabled
4 simultaneous streams in each direction
12 bounded five-minute sessions
1 Hz ping
status/counter sample every 10 seconds
```

If the one-hour run passes, start the release soak:

```text
24 hours
288 bounded five-minute sessions
one 16+16 stream five-minute burst each hour
no infinite loop
```

Acceptance:

```text
all sessions complete
ping loss <= 0.01%, with no three consecutive losses
overall retransmit rate <= 0.1%
no five-minute retransmit window above 0.5%
no five-minute throughput below 70% of the first-hour median
zero dataplane error/drop counter growth
no sustained map-count or RSS growth
no BPF/WireGuard errors, soft lockup, OOM, or NIC error events
```

## Evidence And Completion

Keep logs and captures in the run-owned evidence directory on failure. On
success, copy a bounded evidence archive to the private workspace before the
explicit teardown. The final work-history report must distinguish:

```text
passed
failed
unsupported
not covered
```

Do not describe netns/veth results as real NIC offload coverage. Do not push
this plan, evidence, credentials, or private test documentation to the OSS
repository.
