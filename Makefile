override SHELL := /bin/sh

CGO_ENABLED ?= 0
GO ?= go
GOFMT ?= gofmt
PYTHON ?= python3
BINARY ?= bin/wg-mix-ebpf
CLANG ?= clang

BPF_MULTIARCH ?= $(shell gcc -print-multiarch 2>/dev/null)
BPF_CFLAGS ?= -O2 -g -Wall -Werror -target bpfel $(if $(BPF_MULTIARCH),-I/usr/include/$(BPF_MULTIARCH),)
BPF_BASELINE_CFLAGS ?= $(BPF_CFLAGS) -Wno-unused-function
override FAKETCP_PRODUCTION_CFLAGS := -UWG_MIX_FAKETCP_STAGE_PROFILE -DWG_MIX_FAKETCP_PRODUCTION_BUILD=1

BPF_OBJECT ?= build/wg_mix_tc.o
FAKETCP_EXPERIMENTAL_BPF_OBJECT ?= build/wg_mix_faketcp_experimental.o
FAKETCP_LEGACY_515_BPF_OBJECT ?= build/wg_mix_faketcp_legacy_515.o

FAKETCP_CHECKSUM_KMOD_SOURCE ?= $(CURDIR)/kernel/faketcp_checksum
FAKETCP_CHECKSUM_KMOD_OUTPUT ?= $(CURDIR)/build/faketcp_checksum_kmod
FAKETCP_CHECKSUM_KMOD_OBJECT ?= $(FAKETCP_CHECKSUM_KMOD_OUTPUT)/wg_mix_faketcp_checksum.ko
FAKETCP_CHECKSUM_KMOD_BTF_HELPER ?= $(CURDIR)/scripts/finalize-faketcp-checksum-module-btf.sh
FAKETCP_CHECKSUM_KPROBE_KMOD_SOURCE ?= $(CURDIR)/kernel/faketcp_checksum_kprobe
FAKETCP_CHECKSUM_KPROBE_KMOD_OUTPUT ?= $(CURDIR)/build/faketcp_checksum_kprobe_kmod
FAKETCP_CHECKSUM_KPROBE_KMOD_OBJECT ?= $(FAKETCP_CHECKSUM_KPROBE_KMOD_OUTPUT)/wg_mix_faketcp_checksum_kprobe.ko
KERNEL_RELEASE ?= $(shell uname -r)
KERNEL_BUILD ?= /lib/modules/$(KERNEL_RELEASE)/build
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux

EMBEDDED_BPF_OBJECT ?= internal/dataplane/embedded/wg_mix_tc.o
EMBEDDED_FAKETCP_BPF_OBJECT ?= internal/dataplane/embedded/wg_mix_faketcp.o
EMBEDDED_FAKETCP_LEGACY_515_BPF_OBJECT ?= internal/dataplane/embedded/wg_mix_faketcp_legacy_515.o

override BUILD_SOURCE_COMMIT := $(shell ./scripts/source-commit.sh)
override BUILD_IDENTITY_LDFLAG := -X=github.com/syx0310/wg-mix-ebpf/internal/buildinfo.sourceCommit=$(BUILD_SOURCE_COMMIT)

.PHONY: \
	build build-linux-amd64 build-linux-arm64 \
	build-bpf build-faketcp-experimental-bpf build-faketcp-legacy-515-bpf \
	build-faketcp-checksum-kmod build-faketcp-checksum-kprobe-kmod \
	test-bpf-object-manifests test-bpf-object-manifest-path-contract _test-bpf-object-manifests \
	prepare-embedded-bpf bpf-load-test \
	test-unit test-unit-race test-lint test-config test-profile test-reconcile \
	test-packet-helper test-pcap-helper \
	test-netns-smoke test-netns-xor-smoke test-netns-xor-full-smoke \
	test-netns-icmp-smoke test-netns-tcp test-netns-tcp-native \
	test-netns-tcp-xor-prefix test-netns-tcp-xor-full test-netns test-netns-full \
	test-bpf-pkt test-vm test-openwrt-vm test-hw bench soak

build: prepare-embedded-bpf
	GOENV=off GOWORK=off GOFLAGS= GO111MODULE=on CGO_ENABLED=$(CGO_ENABLED) \
		$(GO) build -trimpath -mod=readonly -buildvcs=false \
		-ldflags=$(BUILD_IDENTITY_LDFLAG) -o $(BINARY) ./cmd/wg-mix-ebpf

build-linux-amd64: prepare-embedded-bpf
	GOENV=off GOWORK=off GOFLAGS= GO111MODULE=on CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		$(GO) build -trimpath -mod=readonly -buildvcs=false \
		-ldflags=$(BUILD_IDENTITY_LDFLAG) -o bin/wg-mix-ebpf-linux-amd64 ./cmd/wg-mix-ebpf

build-linux-arm64: prepare-embedded-bpf
	GOENV=off GOWORK=off GOFLAGS= GO111MODULE=on CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
		$(GO) build -trimpath -mod=readonly -buildvcs=false \
		-ldflags=$(BUILD_IDENTITY_LDFLAG) -o bin/wg-mix-ebpf-linux-arm64 ./cmd/wg-mix-ebpf

build-bpf:
	@mkdir -p $(dir $(BPF_OBJECT))
	$(CLANG) $(BPF_BASELINE_CFLAGS) -c bpf/wg_mix_tc.c -o $(BPF_OBJECT)

build-faketcp-experimental-bpf:
	@mkdir -p $(dir $(FAKETCP_EXPERIMENTAL_BPF_OBJECT))
	$(CLANG) $(BPF_CFLAGS) -DWG_MIX_EXPERIMENTAL_FAKETCP=1 \
		$(FAKETCP_PRODUCTION_CFLAGS) \
		-c bpf/wg_mix_tc.c -o $(FAKETCP_EXPERIMENTAL_BPF_OBJECT)

build-faketcp-legacy-515-bpf:
	@mkdir -p $(dir $(FAKETCP_LEGACY_515_BPF_OBJECT))
	$(CLANG) $(BPF_CFLAGS) -DWG_MIX_EXPERIMENTAL_FAKETCP=1 \
		-DWG_MIX_FAKETCP_LEGACY_515=1 \
		$(FAKETCP_PRODUCTION_CFLAGS) \
		-c bpf/wg_mix_tc.c -o $(FAKETCP_LEGACY_515_BPF_OBJECT)

# This target only builds an out-of-tree module into build/. Installation,
# loading and unloading are explicit administrator operations.
build-faketcp-checksum-kmod:
	@test -d "$(KERNEL_BUILD)" || { echo "kernel build tree not found: $(KERNEL_BUILD)"; exit 2; }
	@test -r "$(VMLINUX_BTF)" || { echo "kernel BTF base not found: $(VMLINUX_BTF)"; exit 2; }
	@mkdir -p "$(FAKETCP_CHECKSUM_KMOD_OUTPUT)"
	$(MAKE) -C "$(KERNEL_BUILD)" \
		M="$(FAKETCP_CHECKSUM_KMOD_SOURCE)" \
		MO="$(FAKETCP_CHECKSUM_KMOD_OUTPUT)" modules
	@test -f "$(FAKETCP_CHECKSUM_KMOD_OBJECT)" || \
		{ echo "expected module was not built: $(FAKETCP_CHECKSUM_KMOD_OBJECT)"; exit 2; }
	/usr/bin/bash "$(FAKETCP_CHECKSUM_KMOD_BTF_HELPER)" \
		--kernel-build "$(KERNEL_BUILD)" \
		--vmlinux-btf "$(VMLINUX_BTF)" \
		--module "$(FAKETCP_CHECKSUM_KMOD_OBJECT)"

# The Linux 5.15 bridge copies its small source set into build/ because older
# external-module build trees do not support the newer MO output variable.
build-faketcp-checksum-kprobe-kmod:
	@test -d "$(KERNEL_BUILD)" || { echo "kernel build tree not found: $(KERNEL_BUILD)"; exit 2; }
	@mkdir -p "$(FAKETCP_CHECKSUM_KPROBE_KMOD_OUTPUT)"
	cp "$(FAKETCP_CHECKSUM_KPROBE_KMOD_SOURCE)/Kbuild" \
		"$(FAKETCP_CHECKSUM_KPROBE_KMOD_SOURCE)/wg_mix_faketcp_checksum_kprobe.c" \
		"$(FAKETCP_CHECKSUM_KPROBE_KMOD_SOURCE)/wg_mix_faketcp_checksum_kprobe_abi.h" \
		"$(FAKETCP_CHECKSUM_KPROBE_KMOD_SOURCE)/wg_mix_faketcp_checksum_kprobe_uapi.h" \
		"$(FAKETCP_CHECKSUM_KPROBE_KMOD_OUTPUT)/"
	$(MAKE) -C "$(KERNEL_BUILD)" M="$(FAKETCP_CHECKSUM_KPROBE_KMOD_OUTPUT)" modules
	@test -f "$(FAKETCP_CHECKSUM_KPROBE_KMOD_OBJECT)" || \
		{ echo "expected module was not built: $(FAKETCP_CHECKSUM_KPROBE_KMOD_OBJECT)"; exit 2; }

define run_bpf_object_manifest_test
	@baseline_object="$(BPF_OBJECT)"; \
	experimental_object="$(FAKETCP_EXPERIMENTAL_BPF_OBJECT)"; \
	legacy_515_object="$(FAKETCP_LEGACY_515_BPF_OBJECT)"; \
	case "$$baseline_object" in /*) ;; *) baseline_object="$(CURDIR)/$$baseline_object" ;; esac; \
	case "$$experimental_object" in /*) ;; *) experimental_object="$(CURDIR)/$$experimental_object" ;; esac; \
	case "$$legacy_515_object" in /*) ;; *) legacy_515_object="$(CURDIR)/$$legacy_515_object" ;; esac; \
	WG_MIX_BASELINE_MANIFEST_OBJECT="$$baseline_object" \
	WG_MIX_FAKETCP_MANIFEST_OBJECT="$$experimental_object" \
	WG_MIX_FAKETCP_LEGACY_515_MANIFEST_OBJECT="$$legacy_515_object" \
	WG_MIX_MANIFEST_CONTRACT_EXPECT_BASELINE="$(MANIFEST_CONTRACT_EXPECT_BASELINE)" \
	WG_MIX_MANIFEST_CONTRACT_EXPECT_EXPERIMENTAL="$(MANIFEST_CONTRACT_EXPECT_EXPERIMENTAL)" \
	WG_MIX_MANIFEST_CONTRACT_EXPECT_LEGACY_515="$(MANIFEST_CONTRACT_EXPECT_LEGACY_515)" \
	WG_MIX_MANIFEST_CONTRACT_EXPECT_CWD="$(MANIFEST_CONTRACT_EXPECT_CWD)" \
	CGO_ENABLED=0 "$(GO)" test ./internal/dataplane \
		-run '^TestBuiltBPFObjectManifests$$' -count=1
endef

test-bpf-object-manifests: build-bpf build-faketcp-experimental-bpf build-faketcp-legacy-515-bpf
	$(run_bpf_object_manifest_test)

_test-bpf-object-manifests:
	$(run_bpf_object_manifest_test)

test-bpf-object-manifest-path-contract:
	@$(MAKE) --no-print-directory -C "$(CURDIR)" _test-bpf-object-manifests \
		BPF_OBJECT="manifest contract/relative baseline object.o" \
		FAKETCP_EXPERIMENTAL_BPF_OBJECT="manifest contract/relative experimental object.o" \
		FAKETCP_LEGACY_515_BPF_OBJECT="manifest contract/relative legacy 515 object.o" \
		MANIFEST_CONTRACT_EXPECT_BASELINE="$(CURDIR)/manifest contract/relative baseline object.o" \
		MANIFEST_CONTRACT_EXPECT_EXPERIMENTAL="$(CURDIR)/manifest contract/relative experimental object.o" \
		MANIFEST_CONTRACT_EXPECT_LEGACY_515="$(CURDIR)/manifest contract/relative legacy 515 object.o" \
		MANIFEST_CONTRACT_EXPECT_CWD="$(CURDIR)" \
		GO="$(CURDIR)/scripts/test-bpf-object-manifest-path-contract.sh"
	@$(MAKE) --no-print-directory -C "$(CURDIR)" _test-bpf-object-manifests \
		BPF_OBJECT="$(CURDIR)/manifest contract/absolute baseline object.o" \
		FAKETCP_EXPERIMENTAL_BPF_OBJECT="$(CURDIR)/manifest contract/absolute experimental object.o" \
		FAKETCP_LEGACY_515_BPF_OBJECT="$(CURDIR)/manifest contract/absolute legacy 515 object.o" \
		MANIFEST_CONTRACT_EXPECT_BASELINE="$(CURDIR)/manifest contract/absolute baseline object.o" \
		MANIFEST_CONTRACT_EXPECT_EXPERIMENTAL="$(CURDIR)/manifest contract/absolute experimental object.o" \
		MANIFEST_CONTRACT_EXPECT_LEGACY_515="$(CURDIR)/manifest contract/absolute legacy 515 object.o" \
		MANIFEST_CONTRACT_EXPECT_CWD="$(CURDIR)" \
		GO="$(CURDIR)/scripts/test-bpf-object-manifest-path-contract.sh"

prepare-embedded-bpf: build-bpf build-faketcp-experimental-bpf build-faketcp-legacy-515-bpf
	@mkdir -p $(dir $(EMBEDDED_BPF_OBJECT)) \
		$(dir $(EMBEDDED_FAKETCP_BPF_OBJECT)) \
		$(dir $(EMBEDDED_FAKETCP_LEGACY_515_BPF_OBJECT))
	cp $(BPF_OBJECT) $(EMBEDDED_BPF_OBJECT)
	cp $(FAKETCP_EXPERIMENTAL_BPF_OBJECT) $(EMBEDDED_FAKETCP_BPF_OBJECT)
	cp $(FAKETCP_LEGACY_515_BPF_OBJECT) $(EMBEDDED_FAKETCP_LEGACY_515_BPF_OBJECT)

bpf-load-test: build
	./$(BINARY) bpf-load-test

test-unit: test-pcap-helper test-bpf-object-manifest-path-contract
	GOENV=off GOWORK=off GOFLAGS= GO111MODULE=on CGO_ENABLED=$(CGO_ENABLED) \
		$(GO) test -count=1 ./...

test-unit-race:
	GOENV=off GOWORK=off GOFLAGS= GO111MODULE=on CGO_ENABLED=1 \
		$(GO) test -race -count=1 ./...

test-lint:
	@command -v $(GOFMT) >/dev/null || { echo "missing gofmt: $(GOFMT)"; exit 1; }
	@test -z "$$($(GOFMT) -l $$(find cmd internal -name '*.go' -type f))" || \
		{ echo "gofmt required for:"; $(GOFMT) -l $$(find cmd internal -name '*.go' -type f); exit 1; }
	GOENV=off GOWORK=off GOFLAGS= GO111MODULE=on CGO_ENABLED=$(CGO_ENABLED) $(GO) vet ./...
	sh -n scripts/source-commit.sh scripts/test-bpf-object-manifest-path-contract.sh
	bash -n scripts/finalize-faketcp-checksum-module-btf.sh \
		scripts/smoke-netns-wg.sh scripts/smoke-netns-icmp.sh
	$(PYTHON) -B -c 'from pathlib import Path; compile(Path("scripts/check-wg-pcap.py").read_text(), "scripts/check-wg-pcap.py", "exec")'
	$(PYTHON) -B -c 'from pathlib import Path; compile(Path("scripts/test_check_wg_pcap.py").read_text(), "scripts/test_check_wg_pcap.py", "exec")'
	@if command -v shellcheck >/dev/null 2>&1; then \
		shellcheck scripts/source-commit.sh scripts/test-bpf-object-manifest-path-contract.sh \
			scripts/finalize-faketcp-checksum-module-btf.sh \
			scripts/smoke-netns-wg.sh scripts/smoke-netns-icmp.sh; \
	else \
		echo "skip: shellcheck is unavailable"; \
	fi

test-config:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test ./internal/config ./internal/wgconfig

test-profile:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test ./internal/profile

test-reconcile:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test ./internal/control ./internal/guard

test-packet-helper:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test ./internal/packet

test-pcap-helper:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) scripts/test_check_wg_pcap.py

test-netns-smoke: build
	scripts/smoke-netns-wg.sh

test-netns-xor-smoke: build
	XOR_PASSWORD=wg-mix-ebpf-xor-smoke XOR_SCOPE=wg-payload-prefix XOR_MAX_BYTES=128 scripts/smoke-netns-wg.sh

test-netns-xor-full-smoke: build
	XOR_PASSWORD=wg-mix-ebpf-xor-smoke XOR_SCOPE=wg-payload-full XOR_MAX_BYTES=2048 \
		XOR_GENERATION_CHECKS=enforce XOR_DISPATCH_FAILURE_CHECKS=enforce scripts/smoke-netns-wg.sh

test-netns-icmp-smoke: build
	NEGATIVE_CHECKS=enforce scripts/smoke-netns-icmp.sh

test-netns-tcp-native: build
	RUN_ID=tcpnat4 TCP_CHECKS=enforce scripts/smoke-netns-wg.sh

test-netns-tcp-xor-prefix: build
	RUN_ID=tcppfx4 TCP_CHECKS=enforce XOR_PASSWORD=wg-mix-ebpf-xor-smoke \
		XOR_SCOPE=wg-payload-prefix XOR_MAX_BYTES=128 scripts/smoke-netns-wg.sh

test-netns-tcp-xor-full: build
	RUN_ID=tcpfull4 TCP_CHECKS=enforce XOR_PASSWORD=wg-mix-ebpf-xor-smoke \
		XOR_SCOPE=wg-payload-full XOR_MAX_BYTES=2048 scripts/smoke-netns-wg.sh

test-netns-tcp: test-netns-tcp-native test-netns-tcp-xor-prefix test-netns-tcp-xor-full

test-netns:
	@echo "run as root on a controlled Linux test machine: make test-netns-smoke"

test-netns-full: build
	RUN_ID=fullu4 scripts/smoke-netns-wg.sh
	RUN_ID=fullu6 OUTER_FAMILY=ipv6 UDP_ZERO_CHECKSUM_CHECKS=enforce scripts/smoke-netns-wg.sh
	RUN_ID=fullx4p XOR_PASSWORD=wg-mix-ebpf-xor-smoke XOR_SCOPE=wg-payload-prefix XOR_MAX_BYTES=128 scripts/smoke-netns-wg.sh
	RUN_ID=fullx6p OUTER_FAMILY=ipv6 XOR_PASSWORD=wg-mix-ebpf-xor-smoke XOR_SCOPE=wg-payload-prefix XOR_MAX_BYTES=128 scripts/smoke-netns-wg.sh
	RUN_ID=fullx4f XOR_PASSWORD=wg-mix-ebpf-xor-smoke XOR_SCOPE=wg-payload-full XOR_MAX_BYTES=2048 XOR_GENERATION_CHECKS=enforce XOR_DISPATCH_FAILURE_CHECKS=enforce scripts/smoke-netns-wg.sh
	RUN_ID=fullx6f OUTER_FAMILY=ipv6 XOR_PASSWORD=wg-mix-ebpf-xor-smoke XOR_SCOPE=wg-payload-full XOR_MAX_BYTES=2048 XOR_GENERATION_CHECKS=enforce UDP_ZERO_CHECKSUM_CHECKS=enforce scripts/smoke-netns-wg.sh
	RUN_ID=fulli4 NEGATIVE_CHECKS=enforce scripts/smoke-netns-icmp.sh
	$(MAKE) test-netns-tcp

test-bpf-pkt:
	@echo "skip: requires a controlled Linux machine with BPF/TC support"

test-vm:
	@echo "skip: requires an external VM matrix"

test-openwrt-vm:
	@echo "skip: requires an external OpenWrt VM"

test-hw:
	@echo "skip: requires an external hardware lab"

bench:
	@echo "skip: requires an external performance environment"

soak:
	@echo "skip: requires an external long-running environment"
