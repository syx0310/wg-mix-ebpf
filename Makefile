CGO_ENABLED ?= 0
GO ?= go
GOFMT ?= gofmt
BINARY ?= bin/wg-mix-ebpf
CLANG ?= clang
BPF_MULTIARCH ?= $(shell gcc -print-multiarch 2>/dev/null)
BPF_CFLAGS ?= -O2 -g -Wall -Werror -target bpf $(if $(BPF_MULTIARCH),-I/usr/include/$(BPF_MULTIARCH),)
BPF_OBJECT ?= build/wg_mix_tc.o
FAKETCP_EXPERIMENTAL_BPF_OBJECT ?= build/wg_mix_faketcp_experimental.o
EMBEDDED_BPF_OBJECT ?= internal/dataplane/embedded/wg_mix_tc.o
override BUILD_SOURCE_COMMIT := $(shell ./scripts/source-commit.sh)
override BUILD_IDENTITY_LDFLAG := -X=github.com/syx0310/wg-mix-ebpf/internal/buildinfo.sourceCommit=$(BUILD_SOURCE_COMMIT)

.PHONY: test-unit test-unit-race test-lint test-live-guard-build-provenance test-faketcp-verifier-only test-bpf-object-manifests test-bpf-object-manifest-path-contract _test-bpf-object-manifests test-config test-profile test-reconcile test-packet-helper test-pcap-helper test-bpf-pkt test-netns-smoke test-netns-xor-smoke test-netns-xor-full-smoke test-netns-icmp-smoke test-netns-tcp test-netns-tcp-native test-netns-tcp-xor-prefix test-netns-tcp-xor-full test-netns test-netns-full test-vm test-openwrt-vm test-hw bench soak build build-linux-amd64 build-linux-arm64 build-live-guard-test build-bpf build-faketcp-experimental-bpf prepare-embedded-bpf bpf-load-test

build: prepare-embedded-bpf
	GOENV=off GOWORK=off GOFLAGS= GO111MODULE=on CGO_ENABLED=$(CGO_ENABLED) $(GO) build -trimpath -mod=readonly -buildvcs=false -ldflags=$(BUILD_IDENTITY_LDFLAG) -o $(BINARY) ./cmd/wg-mix-ebpf

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

test-faketcp-verifier-only:
	scripts/test-faketcp-verifier-only.sh \
		"$(CURDIR)/scripts/run-faketcp-verifier-only.py"

build-bpf:
	@mkdir -p $(dir $(BPF_OBJECT))
	$(CLANG) $(BPF_CFLAGS) -c bpf/wg_mix_tc.c -o $(BPF_OBJECT)

# The Mimic-style FakeTCP wire path is a separate, deliberately unembedded
# experiment. The ordinary loader only accepts the baseline object above.
build-faketcp-experimental-bpf:
	@mkdir -p $(dir $(FAKETCP_EXPERIMENTAL_BPF_OBJECT))
	$(CLANG) $(BPF_CFLAGS) -DWG_MIX_EXPERIMENTAL_FAKETCP=1 \
		-c bpf/wg_mix_tc.c -o $(FAKETCP_EXPERIMENTAL_BPF_OBJECT)

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

test-unit: test-pcap-helper test-bpf-object-manifest-path-contract
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test ./...

test-unit-race:
	CGO_ENABLED=1 $(GO) test -race ./...

test-lint:
	@command -v $(GOFMT) >/dev/null || { echo "missing gofmt: $(GOFMT)"; exit 1; }
	@test -z "$$($(GOFMT) -l $$(find cmd internal -name '*.go' -type f))" || \
		{ echo "gofmt required for:"; $(GOFMT) -l $$(find cmd internal -name '*.go' -type f); exit 1; }
	CGO_ENABLED=$(CGO_ENABLED) $(GO) vet ./...
	sh -n scripts/source-commit.sh scripts/test-bpf-object-manifest-path-contract.sh
	bash -n scripts/inspect-linux-test-host.sh scripts/provision-ubuntu-test-host.sh scripts/smoke-netns-wg.sh scripts/smoke-netns-icmp.sh scripts/build-live-guard-test.sh scripts/test-build-live-guard-provenance.sh scripts/test-live-guard-ownership.sh scripts/test-faketcp-verifier-only.sh
	/usr/bin/python3 -I -c 'from pathlib import Path; [compile(Path(p).read_text(), p, "exec") for p in ("scripts/run-faketcp-verifier-only.py", "scripts/test_faketcp_verifier_only.py")]'
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
	@if test "$$(/usr/bin/uname -s)" = Linux && \
		test "$$(/usr/bin/id -u)" != 0 && \
		test -x /usr/bin/go && test -x /usr/bin/timeout && \
		test -x /usr/bin/sha256sum; then \
		$(MAKE) --no-print-directory test-live-guard-build-provenance; \
	else \
		echo "skip: live guard build provenance regression requires unprivileged Linux fixed tools"; \
	fi
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) vet -tags realhosttest ./internal/guard
	@if command -v shellcheck >/dev/null 2>&1; then \
		shellcheck scripts/build-live-guard-test.sh scripts/test-build-live-guard-provenance.sh scripts/test-live-guard-ownership.sh scripts/test-faketcp-verifier-only.sh; \
	else \
		echo "skip: shellcheck is unavailable"; \
	fi
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
