.PHONY: test-unit test-unit-race test-lint test-config test-profile test-reconcile test-packet-helper test-bpf-pkt test-netns test-netns-full test-vm test-openwrt-vm test-hw bench soak build

build:
	go build ./cmd/wg-mix-ebpf

test-unit:
	go test ./...

test-unit-race:
	go test -race ./...

test-lint:
	go test ./...

test-config:
	go test ./internal/config ./internal/wgconfig

test-profile:
	go test ./internal/profile

test-reconcile:
	go test ./internal/control ./internal/guard

test-packet-helper:
	go test ./internal/packet

test-bpf-pkt:
	@echo "skip: requires external Linux root VM with BPF/TC support"

test-netns:
	@echo "skip: requires external Linux root VM with network namespace, WireGuard, and tc"

test-netns-full:
	@echo "skip: requires external Linux root VM with full netns matrix"

test-vm:
	@echo "skip: requires external VM matrix"

test-openwrt-vm:
	@echo "skip: requires external OpenWrt VM"

test-hw:
	@echo "skip: requires external hardware lab"

bench:
	@echo "skip: requires external performance environment"

soak:
	@echo "skip: requires external long-running environment"
