CGO_ENABLED ?= 0
GO ?= go
GOFLAGS ?= -trimpath
BINARY ?= bin/wg-mix-ebpf

.PHONY: test-unit test-unit-race test-lint test-config test-profile test-reconcile test-packet-helper test-bpf-pkt test-netns test-netns-full test-vm test-openwrt-vm test-hw bench soak build build-linux-amd64 build-linux-arm64

build:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build $(GOFLAGS) -o $(BINARY) ./cmd/wg-mix-ebpf

build-linux-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -o bin/wg-mix-ebpf-linux-amd64 ./cmd/wg-mix-ebpf

build-linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build $(GOFLAGS) -o bin/wg-mix-ebpf-linux-arm64 ./cmd/wg-mix-ebpf

test-unit:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test ./...

test-unit-race:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test -race ./...

test-lint:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test ./...

test-config:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test ./internal/config ./internal/wgconfig

test-profile:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test ./internal/profile

test-reconcile:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test ./internal/control ./internal/guard

test-packet-helper:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test ./internal/packet

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
