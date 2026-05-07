# Embedded BPF Object

`make build-bpf` compiles `bpf/wg_mix_tc.c` into `build/wg_mix_tc.o` and copies the object here as `wg_mix_tc.o`.

The Go binary embeds this object so target machines do not need clang or kernel headers at runtime.
