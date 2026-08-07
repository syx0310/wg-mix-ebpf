CGO_ENABLED ?= 0
GO ?= go
GOFMT ?= gofmt
BINARY ?= bin/wg-mix-ebpf
NETNS_ANCHOR_BINARY ?= bin/wg-mix-ebpf-netns-anchor
CLANG ?= clang
BPF_MULTIARCH ?= $(shell gcc -print-multiarch 2>/dev/null)
BPF_CFLAGS ?= -O2 -g -Wall -Werror -target bpf $(if $(BPF_MULTIARCH),-I/usr/include/$(BPF_MULTIARCH),)
BPF_OBJECT ?= build/wg_mix_tc.o
EMBEDDED_BPF_OBJECT ?= internal/dataplane/embedded/wg_mix_tc.o
override BUILD_SOURCE_COMMIT := $(shell ./scripts/source-commit.sh)
override BUILD_IDENTITY_LDFLAG := -X=github.com/syx0310/wg-mix-ebpf/internal/buildinfo.sourceCommit=$(BUILD_SOURCE_COMMIT)
override NETNS_ANCHOR_IDENTITY_LDFLAG := -X=github.com/syx0310/wg-mix-ebpf/internal/netnsanchor.sourceCommit=$(BUILD_SOURCE_COMMIT)

.PHONY: test-unit test-unit-race test-lint test-live-guard-build-provenance test-config test-profile test-reconcile test-packet-helper test-pcap-helper test-smoke-script-helper test-stage-source-helper test-bpf-pkt test-netns-smoke test-netns-xor-smoke test-netns-xor-full-smoke test-netns-icmp-smoke test-netns-tcp test-netns-tcp-native test-netns-tcp-xor-prefix test-netns-tcp-xor-full test-netns-tcp-pmtu-positive test-netns-tcp-pmtu-ipv4 test-netns-tcp-pmtu-ipv6 test-netns-tcp-outer-gso-observe test-netns test-netns-full test-vm test-openwrt-vm test-hw bench soak build build-netns-anchor build-linux-amd64 build-linux-arm64 build-live-guard-test build-bpf prepare-embedded-bpf bpf-load-test

build: prepare-embedded-bpf
	GOENV=off GOWORK=off GOFLAGS= GO111MODULE=on CGO_ENABLED=$(CGO_ENABLED) $(GO) build -trimpath -mod=readonly -buildvcs=false -ldflags=$(BUILD_IDENTITY_LDFLAG) -o $(BINARY) ./cmd/wg-mix-ebpf

build-netns-anchor:
	GOENV=off GOWORK=off GOFLAGS= GO111MODULE=on CGO_ENABLED=0 GOOS=linux $(GO) build -trimpath -mod=readonly -buildvcs=false -ldflags=$(NETNS_ANCHOR_IDENTITY_LDFLAG) -o $(NETNS_ANCHOR_BINARY) ./cmd/wg-mix-ebpf-netns-anchor

build-linux-amd64: prepare-embedded-bpf
	GOENV=off GOWORK=off GOFLAGS= GO111MODULE=on CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -mod=readonly -buildvcs=false -ldflags=$(BUILD_IDENTITY_LDFLAG) -o bin/wg-mix-ebpf-linux-amd64 ./cmd/wg-mix-ebpf

build-linux-arm64: prepare-embedded-bpf
	GOENV=off GOWORK=off GOFLAGS= GO111MODULE=on CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -mod=readonly -buildvcs=false -ldflags=$(BUILD_IDENTITY_LDFLAG) -o bin/wg-mix-ebpf-linux-arm64 ./cmd/wg-mix-ebpf

# This convenience target is unprivileged. The fixed-tool and immutable
# candidate-snapshot checks in the invoked script define the artifact gate;
# Make variables are not a sudo or privileged execution boundary.
build-live-guard-test:
	@test -n "$$LIVE_GUARD_COMMIT" || { echo "LIVE_GUARD_COMMIT is required"; exit 2; }
	@test -n "$$LIVE_GUARD_TEST_BINARY" || { echo "LIVE_GUARD_TEST_BINARY is required"; exit 2; }
	scripts/build-live-guard-test.sh \
		--candidate-commit "$$LIVE_GUARD_COMMIT" \
		--output "$$LIVE_GUARD_TEST_BINARY"

test-live-guard-build-provenance:
	scripts/test-build-live-guard-provenance.sh \
		"$(CURDIR)/scripts/build-live-guard-test.sh"

build-bpf:
	@mkdir -p $(dir $(BPF_OBJECT))
	$(CLANG) $(BPF_CFLAGS) -c bpf/wg_mix_tc.c -o $(BPF_OBJECT)

prepare-embedded-bpf: build-bpf
	@mkdir -p $(dir $(EMBEDDED_BPF_OBJECT))
	cp $(BPF_OBJECT) $(EMBEDDED_BPF_OBJECT)

bpf-load-test: build
	./$(BINARY) bpf-load-test

test-netns-smoke: build build-netns-anchor
	scripts/smoke-netns-wg.sh

test-netns-xor-smoke: build build-netns-anchor
	XOR_PASSWORD=wg-mix-ebpf-xor-smoke XOR_SCOPE=wg-payload-prefix XOR_MAX_BYTES=128 scripts/smoke-netns-wg.sh

test-netns-xor-full-smoke: build build-netns-anchor
	XOR_PASSWORD=wg-mix-ebpf-xor-smoke XOR_SCOPE=wg-payload-full XOR_MAX_BYTES=2048 XOR_GENERATION_CHECKS=enforce XOR_DISPATCH_FAILURE_CHECKS=enforce scripts/smoke-netns-wg.sh

test-netns-icmp-smoke: build
	NEGATIVE_CHECKS=enforce scripts/smoke-netns-icmp.sh

test-netns-tcp-native: build build-netns-anchor
	TCP_CHECKS=enforce TCP_INNER_GSO_CHECKS=report TCP_OUTER_GSO_CHECKS=observe scripts/smoke-netns-wg.sh

test-netns-tcp-xor-prefix: build build-netns-anchor
	TCP_CHECKS=enforce TCP_INNER_GSO_CHECKS=report TCP_OUTER_GSO_CHECKS=observe XOR_PASSWORD=wg-mix-ebpf-xor-smoke XOR_SCOPE=wg-payload-prefix XOR_MAX_BYTES=128 scripts/smoke-netns-wg.sh

test-netns-tcp-xor-full: build build-netns-anchor
	TCP_CHECKS=enforce TCP_INNER_GSO_CHECKS=report TCP_OUTER_GSO_CHECKS=observe XOR_PASSWORD=wg-mix-ebpf-xor-smoke XOR_SCOPE=wg-payload-full XOR_MAX_BYTES=2048 scripts/smoke-netns-wg.sh

test-netns-tcp: test-netns-tcp-native test-netns-tcp-xor-prefix test-netns-tcp-xor-full

test-netns-tcp-pmtu-ipv4: build build-netns-anchor
	OUTER_FAMILY=ipv4 UNDERLAY_MTU=1500 TCP_CHECKS=enforce TCP_MTUS="1439 1440" TCP_INNER_GSO_CHECKS=report TCP_OUTER_GSO_CHECKS=observe scripts/smoke-netns-wg.sh

test-netns-tcp-pmtu-ipv6: build build-netns-anchor
	OUTER_FAMILY=ipv6 UNDERLAY_MTU=1500 TCP_CHECKS=enforce TCP_MTUS="1419 1420" TCP_INNER_GSO_CHECKS=report TCP_OUTER_GSO_CHECKS=observe scripts/smoke-netns-wg.sh

test-netns-tcp-pmtu-positive: test-netns-tcp-pmtu-ipv4 test-netns-tcp-pmtu-ipv6

test-netns-tcp-outer-gso-observe: build build-netns-anchor
	TCP_CHECKS=enforce TCP_INNER_GSO_CHECKS=report TCP_OUTER_GSO_CHECKS=observe TCP_MTUS="1420" TCP_STREAMS="16" TCP_DIRECTIONS="bidir" TCP_DURATION=30 scripts/smoke-netns-wg.sh

test-unit: test-pcap-helper test-smoke-script-helper test-stage-source-helper
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test ./...

test-unit-race:
	CGO_ENABLED=1 $(GO) test -race ./...

test-lint:
	@command -v $(GOFMT) >/dev/null || { echo "missing gofmt: $(GOFMT)"; exit 1; }
	@test -z "$$($(GOFMT) -l $$(find cmd internal -name '*.go' -type f))" || \
		{ echo "gofmt required for:"; $(GOFMT) -l $$(find cmd internal -name '*.go' -type f); exit 1; }
	CGO_ENABLED=$(CGO_ENABLED) $(GO) vet ./...
	sh -n scripts/source-commit.sh
	bash -n scripts/inspect-linux-test-host.sh scripts/provision-ubuntu-test-host.sh scripts/smoke-netns-wg.sh scripts/smoke-netns-icmp.sh scripts/build-live-guard-test.sh scripts/test-build-live-guard-provenance.sh scripts/test-live-guard-ownership.sh scripts/run-root-owned-test-source-stage.sh scripts/stage-root-owned-test-source.sh
	scripts/inspect-linux-test-host.sh --self-test-nft-table-gate
	scripts/provision-ubuntu-test-host.sh --self-test-apt-gate
	scripts/build-live-guard-test.sh --self-test-safety-gate
	@if test -x /usr/bin/env && test -x /usr/bin/python3; then \
		scripts/test-build-live-guard-provenance.sh --self-test-tmpdir-gate; \
	else \
		echo "skip: provenance TMPDIR gate self-test requires fixed env and python3"; \
	fi
	scripts/test-live-guard-ownership.sh --self-test-safety-gate
	@if test "$$(/usr/bin/uname -s)" = Linux && \
		test "$$(/usr/bin/id -u)" != 0 && \
		test -x /usr/bin/go && test -x /usr/bin/timeout && \
		test -x /usr/bin/sha256sum; then \
		$(MAKE) --no-print-directory test-live-guard-build-provenance; \
	else \
		echo "skip: live guard build provenance regression requires unprivileged Linux fixed tools"; \
	fi
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) vet -tags realhosttest ./internal/guard
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) vet ./internal/netnsanchor ./cmd/wg-mix-ebpf-netns-anchor
	@if command -v shellcheck >/dev/null 2>&1; then \
		shellcheck scripts/build-live-guard-test.sh scripts/test-build-live-guard-provenance.sh scripts/test-live-guard-ownership.sh scripts/smoke-netns-wg.sh scripts/run-root-owned-test-source-stage.sh scripts/stage-root-owned-test-source.sh; \
	else \
		echo "skip: shellcheck is unavailable"; \
	fi
	python3 -c 'from pathlib import Path; compile(Path("scripts/check-wg-pcap.py").read_text(), "scripts/check-wg-pcap.py", "exec")'
	python3 -c 'from pathlib import Path; compile(Path("scripts/check-iperf3-tcp.py").read_text(), "scripts/check-iperf3-tcp.py", "exec")'
	python3 -c 'from pathlib import Path; compile(Path("scripts/hold-isolated-lifecycle-lease.py").read_text(), "scripts/hold-isolated-lifecycle-lease.py", "exec")'
	python3 -c 'from pathlib import Path; compile(Path("scripts/test_check_iperf3_tcp.py").read_text(), "scripts/test_check_iperf3_tcp.py", "exec")'
	python3 -c 'from pathlib import Path; compile(Path("scripts/test_hold_isolated_lifecycle_lease.py").read_text(), "scripts/test_hold_isolated_lifecycle_lease.py", "exec")'
	python3 -c 'from pathlib import Path; compile(Path("scripts/test_smoke_netns_wg_static.py").read_text(), "scripts/test_smoke_netns_wg_static.py", "exec")'
	python3 -c 'from pathlib import Path; compile(Path("scripts/delete-owned-netns.py").read_text(), "scripts/delete-owned-netns.py", "exec")'
	python3 -c 'from pathlib import Path; compile(Path("scripts/test_delete_owned_netns.py").read_text(), "scripts/test_delete_owned_netns.py", "exec")'
	python3 -c 'from pathlib import Path; compile(Path("scripts/stage-root-owned-test-source.py").read_text(), "scripts/stage-root-owned-test-source.py", "exec")'
	python3 -c 'from pathlib import Path; compile(Path("scripts/test_stage_root_owned_test_source_static.py").read_text(), "scripts/test_stage_root_owned_test_source_static.py", "exec")'
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_stage_root_owned_test_source_static.py

test-config:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test ./internal/config ./internal/wgconfig

test-profile:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test ./internal/profile

test-reconcile:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test ./internal/control ./internal/guard

test-packet-helper:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test ./internal/packet

test-pcap-helper:
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_check_wg_pcap.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_check_iperf3_tcp.py

test-smoke-script-helper:
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_smoke_netns_wg_static.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_hold_isolated_lifecycle_lease.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_delete_owned_netns.py

test-stage-source-helper:
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_stage_root_owned_test_source_static.py

test-bpf-pkt:
	@echo "skip: requires external Linux root VM with BPF/TC support"

test-netns:
	@echo "run as root on an external Linux VM: make test-netns-smoke"

test-netns-full: build build-netns-anchor
	scripts/smoke-netns-wg.sh
	OUTER_FAMILY=ipv6 UDP_ZERO_CHECKSUM_CHECKS=enforce scripts/smoke-netns-wg.sh
	XOR_PASSWORD=wg-mix-ebpf-xor-smoke XOR_SCOPE=wg-payload-prefix XOR_MAX_BYTES=128 scripts/smoke-netns-wg.sh
	OUTER_FAMILY=ipv6 XOR_PASSWORD=wg-mix-ebpf-xor-smoke XOR_SCOPE=wg-payload-prefix XOR_MAX_BYTES=128 scripts/smoke-netns-wg.sh
	XOR_PASSWORD=wg-mix-ebpf-xor-smoke XOR_SCOPE=wg-payload-full XOR_MAX_BYTES=2048 XOR_GENERATION_CHECKS=enforce XOR_DISPATCH_FAILURE_CHECKS=enforce scripts/smoke-netns-wg.sh
	OUTER_FAMILY=ipv6 XOR_PASSWORD=wg-mix-ebpf-xor-smoke XOR_SCOPE=wg-payload-full XOR_MAX_BYTES=2048 XOR_GENERATION_CHECKS=enforce UDP_ZERO_CHECKSUM_CHECKS=enforce scripts/smoke-netns-wg.sh
	NEGATIVE_CHECKS=enforce scripts/smoke-netns-icmp.sh
	$(MAKE) test-netns-tcp
	$(MAKE) test-netns-tcp-pmtu-positive

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
