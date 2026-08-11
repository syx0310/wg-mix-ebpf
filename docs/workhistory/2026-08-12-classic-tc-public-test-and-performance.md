# Classic TC public test and B82 performance — 2026-08-12

## Release state

The local feature tip used for the final recovery work is
`c0062520c87ed4f0a203f03b341b04e4d7ff5839`.  The performance binaries were
built from `381c336bcf524bf99c59524283d8e61957c8d036`; the only changes from that
commit to the feature tip are the failed-run recovery script and its tests.
There is no diff in `bpf/`, the dataplane, reconciliation code, commands,
Makefile, or Go module files.

The tested artifacts on `192.168.10.82` were:

* launcher SHA-256 `ded3aab5f123e9dc84db84dbb6af9162ac08571b7c71e3146d8feb10e223bf12`;
* `wg-mix-ebpf` SHA-256
  `c80ec838c86cde27042ad2950b79a6b99d178330cd5362bc9f5f5cf0a0384b66`;
* baseline BPF object SHA-256
  `c77cbd5a3eecfb0095391a0f5f4af22fb98bae434400cc3656962b1bbd94a2dc`.

Linux, BPF, recovery, and fault-injection tests in this batch ran on
`192.168.10.82`; no local Docker or Podman test environment was used.

## Public two-host result

The standalone public test exercised TCX on `192.168.10.82` and the production
classic-TC backend on the 5.15 kernel at `47.116.202.155`.  The run reached the
bounded traffic phase, then stopped because the public endpoint received none
of the WireGuard initiation packets.  B82 emitted 17 UDP/31155 handshakes at
roughly five-second intervals, while the public host capture saw zero matching
packets.  The public host's local firewall accepted the traffic, so the result
is consistent with an upstream Alibaba EIP/security-group rule blocking
UDP/31155 rather than a loader or verifier failure.

Explicit cleanup completed.  Both hosts have no test WireGuard interface,
run-owned BPF pin, run root, or intake directory.  The public host's pre-existing
shared `clsact` remains, with zero ingress and zero egress filters.  A new
end-to-end traffic run should wait until inbound UDP/31155 is allowed.

## B82 current-version performance

All cases used an isolated private mount namespace, IPv4 underlay, WireGuard
MTU 1420, baseline eBPF transform on both endpoints, no XOR mode, a 30-second
iperf3 interval, and a 1,024-packet bounded capture per side.  Acceptance
required zero retransmits and Jain fairness at least 0.90.

| Case | Received bytes | Receiver throughput | Retransmits | Jain fairness |
| --- | ---: | ---: | ---: | ---: |
| 1-stream forward | 4,822,007,808 | 1,285.75 Mbit/s | 0 | 1.000000 |
| 1-stream reverse | 5,196,480,512 | 1,385.71 Mbit/s | 0 | 1.000000 |
| 4-stream bidirectional, forward half | 4,965,007,360 | 1,323.78 Mbit/s | 0 | 0.999997 |
| 4-stream bidirectional, reverse half | 4,924,112,896 | 1,312.88 Mbit/s | 0 | 1.000000 |

The bidirectional aggregate receiver throughput was 2,636.66 Mbit/s and the
aggregate received volume was 9,889,120,256 bytes.

Additional iperf3 endpoint observations:

* forward mean RTT was 1.660 ms (1.153–1.941 ms); client/server CPU utilization
  was 6.89%/33.28%;
* reverse sender mean RTT was 1.872 ms (1.278–2.539 ms); receiver/sender CPU
  utilization was 32.90%/6.35%;
* bidirectional forward-stream mean RTT was 6.169 ms and reverse-stream mean
  RTT was 6.173 ms; endpoint CPU utilization was 31.12%/31.13%.

The three runs were `aadb8bb2`, `1cbff877`, and `1f03edc9`.  Each completed
exact detach, stopped all anonymous network namespaces, removed its private
bpffs mount and secrets, and left no test interface.  Only the intentionally
retained evidence directory, manifest, root owner marker, and bpffs creation
ledger remain below each run root for audit.  They contain no active BPF or
network resource and no private key.

## Failed-run recovery closure

The earlier failed performance run `b4fc2b79` was recovered with the committed
script SHA-256
`cd8e595bf2833b8325507c04d0865bdfa9837d2605e78f416be3569059ad7aed`.
The final B82 gates were 12/12 recovery tests, 30/30 static tests with two
environment-dependent skips, and a no-write plan over all 90 recorded files.
An independent review found no P0–P2 blocker.  The real recovery completed with
`root=absent receipt=absent`; exact postchecks found neither run root nor either
receipt name.

The final lifecycle rule is: a recovery must hold and revalidate the recorded
lease through lease unlink and root removal.  A missing lease is accepted only
for the unique interruption state in which the recorded root directory is
already otherwise empty.

## CI diagnosis

The prior GitHub Actions failure was the baseline build treating the
FakeTCP-only `set_faketcp_xor_context` helper as an unused function under
`-Wall -Werror`.  The baseline build now explicitly permits that one warning
class with `-Wno-unused-function`; the experimental build retains its strict
warning policy.  The detailed compiler and verifier follow-up is recorded in
`docs/workhistory/2026-08-11-public-bpf-and-ci-findings.md`.
