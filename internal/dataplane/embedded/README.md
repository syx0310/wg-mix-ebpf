# Embedded BPF Object

`make prepare-embedded-bpf` compiles and copies two independent objects here:

- `wg_mix_tc.o` for the baseline UDP/ICMP dataplane;
- `wg_mix_faketcp.o` for the production FakeTCP dataplane.

The Go binary embeds both objects so target machines do not need clang or
kernel headers at runtime. The FakeTCP loader never falls back to the baseline
object.

At runtime, artifact diagnostics calculate SHA-256 directly from these
embedded bytes. No separately supplied checksum is trusted.
