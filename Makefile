CGO_ENABLED ?= 0
GO ?= go
GOFMT ?= gofmt
GOFLAGS ?= -trimpath
BINARY ?= bin/wg-mix-ebpf
CLANG ?= clang
BPF_MULTIARCH ?= $(shell gcc -print-multiarch 2>/dev/null)
BPF_CFLAGS ?= -O2 -g -Wall -Werror -target bpf $(if $(BPF_MULTIARCH),-I/usr/include/$(BPF_MULTIARCH),)
BPF_OBJECT ?= build/wg_mix_tc.o
EMBEDDED_BPF_OBJECT ?= internal/dataplane/embedded/wg_mix_tc.o

.PHONY: test-unit test-unit-race test-lint test-config test-profile test-reconcile test-packet-helper test-pcap-helper test-bpf-pkt test-netns-smoke test-netns-xor-smoke test-netns-xor-full-smoke test-netns-icmp-smoke test-netns-tcp test-netns-tcp-native test-netns-tcp-xor-prefix test-netns-tcp-xor-full test-netns test-netns-full test-vm test-openwrt-vm test-hw bench soak build build-linux-amd64 build-linux-arm64 build-bpf prepare-embedded-bpf bpf-load-test

build: prepare-embedded-bpf
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build $(GOFLAGS) -o $(BINARY) ./cmd/wg-mix-ebpf

build-linux-amd64: prepare-embedded-bpf
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -o bin/wg-mix-ebpf-linux-amd64 ./cmd/wg-mix-ebpf

build-linux-arm64: prepare-embedded-bpf
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build $(GOFLAGS) -o bin/wg-mix-ebpf-linux-arm64 ./cmd/wg-mix-ebpf

build-bpf:
	@mkdir -p $(dir $(BPF_OBJECT))
	$(CLANG) $(BPF_CFLAGS) -c bpf/wg_mix_tc.c -o $(BPF_OBJECT)

prepare-embedded-bpf: build-bpf
	@mkdir -p $(dir $(EMBEDDED_BPF_OBJECT))
	cp $(BPF_OBJECT) $(EMBEDDED_BPF_OBJECT)

bpf-load-test: build
	./$(BINARY) bpf-load-test

test-netns-smoke: build
	scripts/smoke-netns-wg.sh

test-netns-xor-smoke: build
	XOR_PASSWORD=wg-mix-ebpf-xor-smoke XOR_SCOPE=wg-payload-prefix XOR_MAX_BYTES=128 scripts/smoke-netns-wg.sh

test-netns-xor-full-smoke: build
	XOR_PASSWORD=wg-mix-ebpf-xor-smoke XOR_SCOPE=wg-payload-full XOR_MAX_BYTES=2048 XOR_GENERATION_CHECKS=enforce XOR_DISPATCH_FAILURE_CHECKS=enforce scripts/smoke-netns-wg.sh

test-netns-icmp-smoke: build
	NEGATIVE_CHECKS=enforce scripts/smoke-netns-icmp.sh

test-netns-tcp-native: build
	RUN_ID=tcpnat4 TCP_CHECKS=enforce scripts/smoke-netns-wg.sh

test-netns-tcp-xor-prefix: build
	RUN_ID=tcppfx4 TCP_CHECKS=enforce XOR_PASSWORD=wg-mix-ebpf-xor-smoke XOR_SCOPE=wg-payload-prefix XOR_MAX_BYTES=128 scripts/smoke-netns-wg.sh

test-netns-tcp-xor-full: build
	RUN_ID=tcpfull4 TCP_CHECKS=enforce XOR_PASSWORD=wg-mix-ebpf-xor-smoke XOR_SCOPE=wg-payload-full XOR_MAX_BYTES=2048 scripts/smoke-netns-wg.sh

test-netns-tcp: test-netns-tcp-native test-netns-tcp-xor-prefix test-netns-tcp-xor-full

test-unit: test-pcap-helper
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test ./...

test-unit-race:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test -race ./...

test-lint:
	@command -v $(GOFMT) >/dev/null || { echo "missing gofmt: $(GOFMT)"; exit 1; }
	@test -z "$$($(GOFMT) -l $$(find cmd internal -name '*.go' -type f))" || \
		{ echo "gofmt required for:"; $(GOFMT) -l $$(find cmd internal -name '*.go' -type f); exit 1; }
	CGO_ENABLED=$(CGO_ENABLED) $(GO) vet ./...
	bash -n scripts/inspect-linux-test-host.sh scripts/provision-ubuntu-test-host.sh scripts/smoke-netns-wg.sh scripts/smoke-netns-icmp.sh
	scripts/inspect-linux-test-host.sh --self-test-nft-table-gate
	scripts/provision-ubuntu-test-host.sh --self-test-apt-gate
	python3 -c 'from pathlib import Path; compile(Path("scripts/check-wg-pcap.py").read_text(), "scripts/check-wg-pcap.py", "exec")'

test-config:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test ./internal/config ./internal/wgconfig

test-profile:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test ./internal/profile

test-reconcile:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test ./internal/control ./internal/guard

test-packet-helper:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test ./internal/packet

test-pcap-helper:
	python3 scripts/test_check_wg_pcap.py

test-bpf-pkt:
	@echo "skip: requires external Linux root VM with BPF/TC support"

test-netns:
	@echo "run as root on an external Linux VM: make test-netns-smoke"

test-netns-full: build
	RUN_ID=fullu4 scripts/smoke-netns-wg.sh
	RUN_ID=fullu6 OUTER_FAMILY=ipv6 UDP_ZERO_CHECKSUM_CHECKS=enforce scripts/smoke-netns-wg.sh
	RUN_ID=fullx4p XOR_PASSWORD=wg-mix-ebpf-xor-smoke XOR_SCOPE=wg-payload-prefix XOR_MAX_BYTES=128 scripts/smoke-netns-wg.sh
	RUN_ID=fullx6p OUTER_FAMILY=ipv6 XOR_PASSWORD=wg-mix-ebpf-xor-smoke XOR_SCOPE=wg-payload-prefix XOR_MAX_BYTES=128 scripts/smoke-netns-wg.sh
	RUN_ID=fullx4f XOR_PASSWORD=wg-mix-ebpf-xor-smoke XOR_SCOPE=wg-payload-full XOR_MAX_BYTES=2048 XOR_GENERATION_CHECKS=enforce XOR_DISPATCH_FAILURE_CHECKS=enforce scripts/smoke-netns-wg.sh
	RUN_ID=fullx6f OUTER_FAMILY=ipv6 XOR_PASSWORD=wg-mix-ebpf-xor-smoke XOR_SCOPE=wg-payload-full XOR_MAX_BYTES=2048 XOR_GENERATION_CHECKS=enforce UDP_ZERO_CHECKSUM_CHECKS=enforce scripts/smoke-netns-wg.sh
	RUN_ID=fulli4 NEGATIVE_CHECKS=enforce scripts/smoke-netns-icmp.sh
	$(MAKE) test-netns-tcp

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
