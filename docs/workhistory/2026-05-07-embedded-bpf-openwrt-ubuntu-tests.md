# 2026-05-07 Embedded BPF Loader and OpenWrt/Ubuntu Tests

## Changes

- Added embedded BPF object packaging: `make build*` now compiles `bpf/wg_mix_tc.c`, copies the object into `internal/dataplane/embedded/wg_mix_tc.o`, and embeds it into the Go binary.
- Kept `WG_MIX_EBPF_OBJECT` as an explicit debug override; normal runtime now loads `embedded:wg_mix_tc.o` and does not require clang or C sources on the target machine.
- Added pinned BPF map support under `WG_MIX_EBPF_PIN_PATH` with default `/sys/fs/bpf/wg-mix-ebpf`.
- Changed reload to prepare a new generation in pinned maps, attach TC programs, then commit `control_map.active_generation`; failed reloads keep the previous active generation.
- Added stale map entry cleanup after commit and pinned map cleanup on `detach`.
- Added dataplane status visibility for pin path, active generation, ABI version, and per-CPU stats aggregation.
- Updated netns smoke to use embedded object and per-netns temporary bpffs mount for pinned maps.

## Local Verification

- `go test ./...` passed on the local development machine.

## Ubuntu Build Verification

On `192.168.10.28`:

- `make test-unit` passed.
- `make build-linux-amd64` built a static Linux amd64 binary with embedded BPF object.
- `sudo ./bin/wg-mix-ebpf-linux-amd64 bpf-load-test` passed and reported `embedded:wg_mix_tc.o`.
- `sudo make test-netns-smoke` passed with router pcap result: `pcap_udp_payload_words=28 mixed_type_words=28 standard_type_words=0`.

## OpenWrt/Ubuntu Functional Tests

Test pair:

- Ubuntu endpoint: `192.168.10.28`, underlay `ens33`, exposed via `dxhy.siyx.net:52000`.
- OpenWrt endpoint: `10.191.3.3`, underlay `br-lan`.
- Router/capture node: `10.191.3.1`, read-only tcpdump on `br-lan`.
- WG tunnel addresses: `10.191.65.1/32 peer 10.191.65.2/32` and `10.191.65.2/32 peer 10.191.65.1/32`.
- `Table = off`, MTU `1380`, Ubuntu listen port `52000`.

Modes tested:

- raw `ip link` + `wg setconf`: passed, OpenWrt ping to Ubuntu succeeded, pcap `mixed=1 standard=0`.
- official `wg-quick`: passed, OpenWrt ping to Ubuntu succeeded, pcap `mixed=1 standard=0`.
- `wg-quick-op v0.4.1`: passed with `PostUp = wg set %i fwmark ...`, OpenWrt ping to Ubuntu succeeded, pcap `mixed=1 standard=0`.

Notes:

- The first internal-endpoint attempt to `192.168.10.28:52000` did not reach Ubuntu UDP; switching OpenWrt peer endpoint to `dxhy.siyx.net:52000` matched the exposed-port requirement and fixed the path.
- `wg-quick-op version` tries to create `/etc/wg-quick-op.toml`; tests used `-c /tmp/wme-test/wg-quick-op.toml` to avoid persistent config writes.
- OpenWrt did not ship `wg-quick`; a temporary copy of the official `wg-quick` script and temporary `bash` package were used on `10.191.3.3`.
- Test status JSON was captured immediately after reload, before ping traffic, so the saved stats do not represent post-ping counters. The pcap checks and ping logs are the primary pass evidence for these runs.

## Cleanup

After tests:

- Removed temporary WG interfaces on both endpoints.
- Removed agent TC filters from `br-lan` and `ens33`.
- Removed `/sys/fs/bpf/wme-test` pinned maps on both endpoints.
- Removed `/tmp/wme-test` and temporary `/etc/wireguard/wme*.conf` files on both endpoints.
- `10.191.3.1` was used only for read-only tcpdump/status commands.
