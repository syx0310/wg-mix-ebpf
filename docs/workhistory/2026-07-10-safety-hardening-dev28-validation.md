# 2026-07-10 Safety Hardening And Dev28 Validation

## Scope

This pass fixed confirmed control-plane safety and correctness defects. It did
not expand the dataplane feature set or touch any host other than dev28
(`192.168.10.28`).

## Fixes

- Made YAML parsing strict, rejected multiple documents, unsupported selector
  values, duplicate WireGuard names, non-root netns entries, ambiguous/empty
  cipher secrets, unsafe poll intervals, and configurations that cannot fit
  two staged BPF map generations.
- Made config and binary replacement atomic and enforced private config file
  permissions.
- Redacted cipher key bytes from `dump-abi` JSON as well as status output.
- Preserved existing cipher, transport, and underlay parser settings when
  `init` updates an existing entry; `init --reload` now uses daemon request or
  the shared reconcile lock.
- Refused non-dry offline reload/daemon apply so an empty runtime-derived state
  cannot replace live maps.
- Made file locking context-aware, tightened TC attachment status checks, and
  surfaced pinned-map ABI mismatches.
- Stopped treating a missing `nft` binary as successful guard cleanup unless
  the loaded config explicitly disables the guard.
- Restricted uninstall cleanup to managed descendants of `/run`, `/var/lib`,
  `/sys/fs/bpf`, or the system temporary directory and rejected broad,
  overlapping, or config-containing paths.

Regression tests were added for each control-plane behavior above.

## Local Verification

Passed:

```text
CGO_ENABLED=0 go test -count=1 ./...
CGO_ENABLED=0 go test -race -count=1 ./...
CGO_ENABLED=0 go vet ./...
CGO_ENABLED=0 go test -p 1 -shuffle=on -count=10 ./...
Linux amd64 and arm64 cross-builds
Bash syntax checks for smoke scripts
Python syntax check for the pcap checker
```

The negative poll-interval, offline-apply, unknown-field, and ABI key-leak
reproductions were also rerun and now fail closed or redact as intended.

## Dev28 Verification

Non-root validation passed with Go 1.25.3, clang 18, and kernel 6.8.0-117:

```text
make test-unit
make test-unit-race
go vet ./...
make build-bpf
make build-linux-amd64
```

Root validation summary:

```text
bpf-load       pass
UDP IPv4       pass
UDP IPv6       pass
XOR IPv4       pass
XOR IPv6       pass
ICMP IPv4      pass
ICMP negatives pass (enforced)
```

UDP/XOR veth pcaps retained the known offload-shaped checksum fields; the
smokes required successful WireGuard handshake/transport, mixed type words,
zero standard type-word leakage, and clean dataplane error counters. ICMP saw
12/12 valid ICMP checksums. The enforced negative checks confirmed ordinary
ping passes and raw IPv4/IPv6 UDP cannot bypass ICMP transport.

## Cleanup

The test traps removed their namespaces, TC filters, pins, and temporary
files. A separate root cleanup verification then confirmed no owned BPF pin
path, root-namespace `wg_mix_*` TC filter, nft guard table, smoke process, or
test workspace remained. A final unprivileged check reported:

```text
remaining_codex_paths=0
remaining_namespaces=0
remaining_smoke_tmp=0
remaining_wg_mix_root_filters=0
```

## Remaining Work

The next highest-value areas are daemon/dataplane unit-test seams, event-driven
link/runtime reconciliation, generation rollback fault injection, fragment and
offload matrix expansion, and longer performance/soak runs. ICMPv6, fakeTCP,
and cross-netns WireGuard remain explicit future features rather than partial
configuration options.
