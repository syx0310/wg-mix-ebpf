override SHELL := /bin/sh
CGO_ENABLED ?= 0
GO ?= go
GOFMT ?= gofmt
BINARY ?= bin/wg-mix-ebpf
NETNS_ANCHOR_BINARY ?= bin/wg-mix-ebpf-netns-anchor
override WG_NETNS_SMOKE_LAUNCHER := scripts/run-smoke-netns-wg-private-mountns.sh
CLANG ?= clang
BPF_MULTIARCH ?= $(shell gcc -print-multiarch 2>/dev/null)
BPF_CFLAGS ?= -O2 -g -Wall -Werror -target bpf $(if $(BPF_MULTIARCH),-I/usr/include/$(BPF_MULTIARCH),)
BPF_OBJECT ?= build/wg_mix_tc.o
FAKETCP_EXPERIMENTAL_BPF_OBJECT ?= build/wg_mix_faketcp_experimental.o
FAKETCP_CHECKSUM_KMOD_SOURCE ?= $(CURDIR)/kernel/faketcp_checksum
FAKETCP_CHECKSUM_KMOD_OUTPUT ?= $(CURDIR)/build/faketcp_checksum_kmod
FAKETCP_CHECKSUM_KMOD_OBJECT ?= $(FAKETCP_CHECKSUM_KMOD_OUTPUT)/wg_mix_faketcp_checksum.ko
KERNEL_RELEASE ?= $(shell uname -r)
KERNEL_BUILD ?= /lib/modules/$(KERNEL_RELEASE)/build
FAKETCP_VERIFIER_LAUNCHER_AMD64 ?= bin/faketcp-verifier-launcher-linux-amd64
FAKETCP_VERIFIER_LAUNCHER_ARM64 ?= bin/faketcp-verifier-launcher-linux-arm64
FAKETCP_VERIFIER_LAUNCHER_TEST_AMD64 ?= build/verifierlauncher-linux-amd64.test
FAKETCP_VERIFIER_LAUNCHER_TEST_ARM64 ?= build/verifierlauncher-linux-arm64.test
FAKETCP_DATAPLANE_TEST_AMD64 ?= build/dataplane-linux-amd64.test
EMBEDDED_BPF_OBJECT ?= internal/dataplane/embedded/wg_mix_tc.o
override BUILD_SOURCE_COMMIT := $(shell ./scripts/source-commit.sh)
override BUILD_IDENTITY_LDFLAG := -X=github.com/syx0310/wg-mix-ebpf/internal/buildinfo.sourceCommit=$(BUILD_SOURCE_COMMIT)
override NETNS_ANCHOR_IDENTITY_LDFLAG := -X=github.com/syx0310/wg-mix-ebpf/internal/netnsanchor.sourceCommit=$(BUILD_SOURCE_COMMIT)

.PHONY: test-unit test-unit-race test-private-oss-history-replay test-lint test-live-guard-build-provenance test-faketcp-verifier-only test-faketcp-verifier-launcher test-b82-fresh-verifier-gate test-bpf-object-manifests test-bpf-object-manifest-path-contract _test-bpf-object-manifests test-config test-profile test-reconcile test-packet-helper test-pcap-helper test-smoke-script-helper test-stage-source-helper test-bpf-pkt test-netns-smoke test-netns-xor-smoke test-netns-xor-full-smoke test-netns-icmp-smoke test-netns-tcp test-netns-tcp-native test-netns-tcp-xor-prefix test-netns-tcp-xor-full test-netns-tcp-pmtu-positive test-netns-tcp-pmtu-ipv4 test-netns-tcp-pmtu-ipv6 test-netns-tcp-outer-gso-observe test-netns test-netns-full test-vm test-openwrt-vm test-hw bench soak build build-netns-anchor build-linux-amd64 build-linux-arm64 build-faketcp-verifier-launcher build-faketcp-verifier-launcher-linux-amd64 build-faketcp-verifier-launcher-linux-arm64 build-live-guard-test build-bpf build-faketcp-experimental-bpf build-faketcp-checksum-kmod prepare-embedded-bpf bpf-load-test

build: prepare-embedded-bpf
	GOENV=off GOWORK=off GOFLAGS= GO111MODULE=on CGO_ENABLED=$(CGO_ENABLED) $(GO) build -trimpath -mod=readonly -buildvcs=false -ldflags=$(BUILD_IDENTITY_LDFLAG) -o $(BINARY) ./cmd/wg-mix-ebpf

build-netns-anchor:
	GOENV=off GOWORK=off GOFLAGS= GO111MODULE=on CGO_ENABLED=0 GOOS=linux $(GO) build -trimpath -mod=readonly -buildvcs=false -ldflags=$(NETNS_ANCHOR_IDENTITY_LDFLAG) -o $(NETNS_ANCHOR_BINARY) ./cmd/wg-mix-ebpf-netns-anchor

build-linux-amd64: prepare-embedded-bpf
	GOENV=off GOWORK=off GOFLAGS= GO111MODULE=on CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -mod=readonly -buildvcs=false -ldflags=$(BUILD_IDENTITY_LDFLAG) -o bin/wg-mix-ebpf-linux-amd64 ./cmd/wg-mix-ebpf

build-linux-arm64: prepare-embedded-bpf
	GOENV=off GOWORK=off GOFLAGS= GO111MODULE=on CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -mod=readonly -buildvcs=false -ldflags=$(BUILD_IDENTITY_LDFLAG) -o bin/wg-mix-ebpf-linux-arm64 ./cmd/wg-mix-ebpf

# These standalone launchers only become trusted after the root phase verifies
# the selected root-owned artifact and its approved SHA-256 before execution.
build-faketcp-verifier-launcher: build-faketcp-verifier-launcher-linux-amd64 build-faketcp-verifier-launcher-linux-arm64

build-faketcp-verifier-launcher-linux-amd64:
	@mkdir -p $(dir $(FAKETCP_VERIFIER_LAUNCHER_AMD64))
	GOENV=off GOWORK=off GOFLAGS= GO111MODULE=on CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -mod=readonly -buildvcs=false -o $(FAKETCP_VERIFIER_LAUNCHER_AMD64) ./cmd/faketcp-verifier-launcher

build-faketcp-verifier-launcher-linux-arm64:
	@mkdir -p $(dir $(FAKETCP_VERIFIER_LAUNCHER_ARM64))
	GOENV=off GOWORK=off GOFLAGS= GO111MODULE=on CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -mod=readonly -buildvcs=false -o $(FAKETCP_VERIFIER_LAUNCHER_ARM64) ./cmd/faketcp-verifier-launcher

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

test-faketcp-verifier-launcher:
	GOENV=off GOWORK=off GOFLAGS= GO111MODULE=on CGO_ENABLED=$(CGO_ENABLED) $(GO) test -count=1 ./internal/verifierlauncher ./cmd/faketcp-verifier-launcher
	@mkdir -p $(dir $(FAKETCP_VERIFIER_LAUNCHER_TEST_AMD64)) $(dir $(FAKETCP_VERIFIER_LAUNCHER_TEST_ARM64))
	GOENV=off GOWORK=off GOFLAGS= GO111MODULE=on CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) test -c -o $(FAKETCP_VERIFIER_LAUNCHER_TEST_AMD64) ./internal/verifierlauncher
	GOENV=off GOWORK=off GOFLAGS= GO111MODULE=on CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) test -c -o $(FAKETCP_VERIFIER_LAUNCHER_TEST_ARM64) ./internal/verifierlauncher

test-faketcp-verifier-only: test-faketcp-verifier-launcher
	scripts/test-faketcp-verifier-only.sh \
		"$(CURDIR)/scripts/run-faketcp-verifier-only.py"

test-b82-fresh-verifier-gate:
	scripts/realhost-b82-c8e41d73/test-hermetic-checksum-module-lease.sh
	scripts/realhost-b82-c8e41d73/test-hermetic-fresh-verifier-gate.sh \
		"$(CURDIR)/scripts/realhost-b82-c8e41d73/root-fresh-verifier-gate.sh" \
		"$(CURDIR)/scripts/realhost-b82-c8e41d73/checksum-module-lease.sh"
	PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -I \
		scripts/realhost-b82-c8e41d73/test_fresh_verifier_gate_static.py \
		"$(CURDIR)/scripts/realhost-b82-c8e41d73/root-fresh-verifier-gate.sh" \
		"$(CURDIR)/scripts/realhost-b82-c8e41d73/checksum-module-lease.sh"
	@mkdir -p $(dir $(FAKETCP_DATAPLANE_TEST_AMD64))
	GOENV=off GOWORK=off GOFLAGS= GO111MODULE=on CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		$(GO) test -c -o $(FAKETCP_DATAPLANE_TEST_AMD64) ./internal/dataplane

build-bpf:
	@mkdir -p $(dir $(BPF_OBJECT))
	$(CLANG) $(BPF_CFLAGS) -c bpf/wg_mix_tc.c -o $(BPF_OBJECT)

# The Mimic-style FakeTCP wire path is a separate, deliberately unembedded
# experiment. The ordinary loader only accepts the baseline object above.
build-faketcp-experimental-bpf:
	@mkdir -p $(dir $(FAKETCP_EXPERIMENTAL_BPF_OBJECT))
	$(CLANG) $(BPF_CFLAGS) -DWG_MIX_EXPERIMENTAL_FAKETCP=1 \
		-c bpf/wg_mix_tc.c -o $(FAKETCP_EXPERIMENTAL_BPF_OBJECT)

# This target only builds an out-of-tree module into build/. Installation,
# loading, unloading and cleanup require a separately reviewed real-host step.
build-faketcp-checksum-kmod:
	@test -d "$(KERNEL_BUILD)" || { echo "kernel build tree not found: $(KERNEL_BUILD)"; exit 2; }
	@mkdir -p "$(FAKETCP_CHECKSUM_KMOD_OUTPUT)"
	$(MAKE) -C "$(KERNEL_BUILD)" \
		M="$(FAKETCP_CHECKSUM_KMOD_SOURCE)" \
		MO="$(FAKETCP_CHECKSUM_KMOD_OUTPUT)" modules
	@test -f "$(FAKETCP_CHECKSUM_KMOD_OBJECT)" || \
		{ echo "expected module was not built: $(FAKETCP_CHECKSUM_KMOD_OBJECT)"; exit 2; }

define run_bpf_object_manifest_test
	@baseline_object="$(BPF_OBJECT)"; \
	experimental_object="$(FAKETCP_EXPERIMENTAL_BPF_OBJECT)"; \
	case "$$baseline_object" in \
		/*) ;; \
		*) baseline_object="$(CURDIR)/$$baseline_object" ;; \
	esac; \
	case "$$experimental_object" in \
		/*) ;; \
		*) experimental_object="$(CURDIR)/$$experimental_object" ;; \
	esac; \
	WG_MIX_BASELINE_MANIFEST_OBJECT="$$baseline_object" \
	WG_MIX_FAKETCP_MANIFEST_OBJECT="$$experimental_object" \
	WG_MIX_MANIFEST_CONTRACT_EXPECT_BASELINE="$(MANIFEST_CONTRACT_EXPECT_BASELINE)" \
	WG_MIX_MANIFEST_CONTRACT_EXPECT_EXPERIMENTAL="$(MANIFEST_CONTRACT_EXPECT_EXPERIMENTAL)" \
	WG_MIX_MANIFEST_CONTRACT_EXPECT_CWD="$(MANIFEST_CONTRACT_EXPECT_CWD)" \
	CGO_ENABLED=0 "$(GO)" test ./internal/dataplane \
		-run '^TestBuiltBPFObjectManifests$$' -count=1
endef

test-bpf-object-manifests: build-bpf build-faketcp-experimental-bpf
	$(run_bpf_object_manifest_test)

# This internal entry point deliberately has no BPF build prerequisites. The
# path-contract test substitutes a capture helper for Go, so it runs on hosts
# without Linux headers or a BPF-capable clang.
_test-bpf-object-manifests:
	$(run_bpf_object_manifest_test)

test-bpf-object-manifest-path-contract:
	@$(MAKE) --no-print-directory -C "$(CURDIR)" _test-bpf-object-manifests \
		BPF_OBJECT="manifest contract/relative baseline object.o" \
		FAKETCP_EXPERIMENTAL_BPF_OBJECT="manifest contract/relative experimental object.o" \
		MANIFEST_CONTRACT_EXPECT_BASELINE="$(CURDIR)/manifest contract/relative baseline object.o" \
		MANIFEST_CONTRACT_EXPECT_EXPERIMENTAL="$(CURDIR)/manifest contract/relative experimental object.o" \
		MANIFEST_CONTRACT_EXPECT_CWD="$(CURDIR)" \
		GO="$(CURDIR)/scripts/test-bpf-object-manifest-path-contract.sh"
	@$(MAKE) --no-print-directory -C "$(CURDIR)" _test-bpf-object-manifests \
		BPF_OBJECT="$(CURDIR)/manifest contract/absolute baseline object.o" \
		FAKETCP_EXPERIMENTAL_BPF_OBJECT="$(CURDIR)/manifest contract/absolute experimental object.o" \
		MANIFEST_CONTRACT_EXPECT_BASELINE="$(CURDIR)/manifest contract/absolute baseline object.o" \
		MANIFEST_CONTRACT_EXPECT_EXPERIMENTAL="$(CURDIR)/manifest contract/absolute experimental object.o" \
		MANIFEST_CONTRACT_EXPECT_CWD="$(CURDIR)" \
		GO="$(CURDIR)/scripts/test-bpf-object-manifest-path-contract.sh"

prepare-embedded-bpf: build-bpf
	@mkdir -p $(dir $(EMBEDDED_BPF_OBJECT))
	cp $(BPF_OBJECT) $(EMBEDDED_BPF_OBJECT)

bpf-load-test: build
	./$(BINARY) bpf-load-test

test-netns-smoke: build build-netns-anchor
	$(WG_NETNS_SMOKE_LAUNCHER)

test-netns-xor-smoke: build build-netns-anchor
	XOR_PASSWORD=wg-mix-ebpf-xor-smoke XOR_SCOPE=wg-payload-prefix XOR_MAX_BYTES=128 $(WG_NETNS_SMOKE_LAUNCHER)

test-netns-xor-full-smoke: build build-netns-anchor
	XOR_PASSWORD=wg-mix-ebpf-xor-smoke XOR_SCOPE=wg-payload-full XOR_MAX_BYTES=2048 XOR_GENERATION_CHECKS=enforce XOR_DISPATCH_FAILURE_CHECKS=enforce $(WG_NETNS_SMOKE_LAUNCHER)

test-netns-icmp-smoke: build
	NEGATIVE_CHECKS=enforce scripts/smoke-netns-icmp.sh

test-netns-tcp-native: build build-netns-anchor
	TCP_CHECKS=enforce TCP_INNER_GSO_CHECKS=report TCP_OUTER_GSO_CHECKS=observe $(WG_NETNS_SMOKE_LAUNCHER)

test-netns-tcp-xor-prefix: build build-netns-anchor
	TCP_CHECKS=enforce TCP_INNER_GSO_CHECKS=report TCP_OUTER_GSO_CHECKS=observe XOR_PASSWORD=wg-mix-ebpf-xor-smoke XOR_SCOPE=wg-payload-prefix XOR_MAX_BYTES=128 $(WG_NETNS_SMOKE_LAUNCHER)

test-netns-tcp-xor-full: build build-netns-anchor
	TCP_CHECKS=enforce TCP_INNER_GSO_CHECKS=report TCP_OUTER_GSO_CHECKS=observe XOR_PASSWORD=wg-mix-ebpf-xor-smoke XOR_SCOPE=wg-payload-full XOR_MAX_BYTES=2048 $(WG_NETNS_SMOKE_LAUNCHER)

test-netns-tcp: test-netns-tcp-native test-netns-tcp-xor-prefix test-netns-tcp-xor-full

test-netns-tcp-pmtu-ipv4: build build-netns-anchor
	OUTER_FAMILY=ipv4 UNDERLAY_MTU=1500 TCP_CHECKS=enforce TCP_MTUS="1439 1440" TCP_INNER_GSO_CHECKS=report TCP_OUTER_GSO_CHECKS=observe $(WG_NETNS_SMOKE_LAUNCHER)

test-netns-tcp-pmtu-ipv6: build build-netns-anchor
	OUTER_FAMILY=ipv6 UNDERLAY_MTU=1500 TCP_CHECKS=enforce TCP_MTUS="1419 1420" TCP_INNER_GSO_CHECKS=report TCP_OUTER_GSO_CHECKS=observe $(WG_NETNS_SMOKE_LAUNCHER)

test-netns-tcp-pmtu-positive: test-netns-tcp-pmtu-ipv4 test-netns-tcp-pmtu-ipv6

test-netns-tcp-outer-gso-observe: build build-netns-anchor
	TCP_CHECKS=enforce TCP_INNER_GSO_CHECKS=report TCP_OUTER_GSO_CHECKS=observe TCP_MTUS="1420" TCP_STREAMS="16" TCP_DIRECTIONS="bidir" TCP_DURATION=30 $(WG_NETNS_SMOKE_LAUNCHER)

test-private-oss-history-replay:
	@if test -e scripts/private-release; then \
		test -f scripts/private-release/test_oss_history_replay.py || \
			{ echo "private release tree is incomplete"; exit 1; }; \
		python3 -B scripts/private-release/test_oss_history_replay.py; \
	else \
		echo "SKIP: private OSS history replay gate not present"; \
	fi

test-unit: test-pcap-helper test-smoke-script-helper test-stage-source-helper test-bpf-object-manifest-path-contract test-private-oss-history-replay test-b82-fresh-verifier-gate
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test ./...

test-unit-race:
	CGO_ENABLED=1 $(GO) test -race ./...

test-lint:
	@command -v $(GOFMT) >/dev/null || { echo "missing gofmt: $(GOFMT)"; exit 1; }
	@test -z "$$($(GOFMT) -l $$(find cmd internal -name '*.go' -type f))" || \
		{ echo "gofmt required for:"; $(GOFMT) -l $$(find cmd internal -name '*.go' -type f); exit 1; }
	CGO_ENABLED=$(CGO_ENABLED) $(GO) vet ./...
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) vet ./internal/verifierlauncher ./cmd/faketcp-verifier-launcher
	sh -n scripts/source-commit.sh scripts/test-bpf-object-manifest-path-contract.sh
	bash -n scripts/inspect-linux-test-host.sh scripts/provision-ubuntu-test-host.sh scripts/run-smoke-netns-wg-private-mountns.sh scripts/smoke-netns-wg.sh scripts/smoke-netns-icmp.sh scripts/build-live-guard-test.sh scripts/test-build-live-guard-provenance.sh scripts/test-live-guard-ownership.sh scripts/run-root-owned-test-source-stage.sh scripts/stage-root-owned-test-source.sh scripts/test-faketcp-verifier-only.sh scripts/realhost-b82-c8e41d73/checksum-module-lease.sh scripts/realhost-b82-c8e41d73/root-fresh-verifier-gate.sh scripts/realhost-b82-c8e41d73/test-hermetic-fresh-verifier-gate.sh
	/usr/bin/python3 -I -c 'from pathlib import Path; [compile(Path(p).read_text(), p, "exec") for p in ("scripts/run-faketcp-verifier-only.py", "scripts/test_faketcp_verifier_only.py", "scripts/realhost-b82-c8e41d73/test_fresh_verifier_gate_static.py")]'
	scripts/inspect-linux-test-host.sh --self-test-nft-table-gate
	scripts/provision-ubuntu-test-host.sh --self-test-apt-gate
	scripts/build-live-guard-test.sh --self-test-safety-gate
	@if test -x /usr/bin/env && test -x /usr/bin/python3; then \
		scripts/test-build-live-guard-provenance.sh --self-test-tmpdir-gate; \
	else \
		echo "skip: provenance TMPDIR gate self-test requires fixed env and python3"; \
	fi
	scripts/test-live-guard-ownership.sh --self-test-safety-gate
	$(MAKE) --no-print-directory test-faketcp-verifier-only
	$(MAKE) --no-print-directory test-b82-fresh-verifier-gate
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
		shellcheck scripts/build-live-guard-test.sh scripts/test-build-live-guard-provenance.sh scripts/test-live-guard-ownership.sh scripts/run-smoke-netns-wg-private-mountns.sh scripts/smoke-netns-wg.sh scripts/run-root-owned-test-source-stage.sh scripts/stage-root-owned-test-source.sh scripts/test-faketcp-verifier-only.sh scripts/realhost-b82-c8e41d73/checksum-module-lease.sh scripts/realhost-b82-c8e41d73/root-fresh-verifier-gate.sh scripts/realhost-b82-c8e41d73/test-hermetic-fresh-verifier-gate.sh; \
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
	python3 -c 'from pathlib import Path; compile(Path("scripts/test_root_stage_source_fd.py").read_text(), "scripts/test_root_stage_source_fd.py", "exec")'
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_stage_root_owned_test_source_static.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_root_stage_source_fd.py

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
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_root_stage_source_fd.py

test-bpf-pkt:
	@echo "skip: requires external Linux root VM with BPF/TC support"

test-netns:
	@echo "run as root on an external Linux VM: make test-netns-smoke"

test-netns-full: build build-netns-anchor
	$(WG_NETNS_SMOKE_LAUNCHER)
	OUTER_FAMILY=ipv6 UDP_ZERO_CHECKSUM_CHECKS=enforce $(WG_NETNS_SMOKE_LAUNCHER)
	XOR_PASSWORD=wg-mix-ebpf-xor-smoke XOR_SCOPE=wg-payload-prefix XOR_MAX_BYTES=128 $(WG_NETNS_SMOKE_LAUNCHER)
	OUTER_FAMILY=ipv6 XOR_PASSWORD=wg-mix-ebpf-xor-smoke XOR_SCOPE=wg-payload-prefix XOR_MAX_BYTES=128 $(WG_NETNS_SMOKE_LAUNCHER)
	XOR_PASSWORD=wg-mix-ebpf-xor-smoke XOR_SCOPE=wg-payload-full XOR_MAX_BYTES=2048 XOR_GENERATION_CHECKS=enforce XOR_DISPATCH_FAILURE_CHECKS=enforce $(WG_NETNS_SMOKE_LAUNCHER)
	OUTER_FAMILY=ipv6 XOR_PASSWORD=wg-mix-ebpf-xor-smoke XOR_SCOPE=wg-payload-full XOR_MAX_BYTES=2048 XOR_GENERATION_CHECKS=enforce UDP_ZERO_CHECKSUM_CHECKS=enforce $(WG_NETNS_SMOKE_LAUNCHER)
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
