#!/usr/bin/env python3
"""Static and executable lifecycle contract for the routed-veth harness."""

from __future__ import annotations

import copy
import dataclasses
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile


def fail(message: str) -> None:
    raise SystemExit(message)


def read_regular(path_text: str) -> tuple[pathlib.Path, str]:
    path = pathlib.Path(path_text)
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        fail(f"input is not an absolute regular file: {path}")
    return path, path.read_text(encoding="utf-8")


def function_body(source: str, name: str) -> str:
    match = re.search(
        rf"^{re.escape(name)}\(\) \{{\n(?P<body>.*?)(?=^\}}\n)",
        source,
        re.MULTILINE | re.DOTALL,
    )
    if not match:
        fail(f"missing shell function {name}")
    return match.group("body")


class Rejected(RuntimeError):
    """The lifecycle rejected ambiguous or foreign state."""


class FailureCut(RuntimeError):
    """Execution stopped immediately after one durable convergence point."""


@dataclasses.dataclass
class Lifecycle:
    owner: bool = True
    baseline: bool = True
    operation: bool = True
    dependency_intent: bool = False
    dependency_caches: str = "absent"  # absent, exact, foreign
    dependencies_downloaded: bool = False
    dependencies_verified: bool = False
    artifact_intent: str = "absent"  # absent, exact, foreign
    artifact_receipt: str = "absent"  # absent, exact, foreign
    artifact_root: str = "absent"  # absent, partial, exact, foreign
    dependency_binary: bool = False
    preflight: bool = False
    runtime_temp: str = "absent"  # absent, exact, foreign
    veth_intent: bool = False
    receipts: set[str] = dataclasses.field(default_factory=set)
    veth: str = "absent"
    address: str = "absent"  # absent, exact, foreign
    route: str = "absent"
    neighbor: str = "absent"
    offload: str = "baseline"  # baseline, desired, foreign
    offload_baseline: bool = False
    module_lock: bool = True
    module_intent: bool = False
    module: str = "absent"  # absent, exact, foreign, empty-lease
    module_unloaded: bool = False
    bpf_baseline: bool = True
    cleanup: bool = False
    restored: bool = False


SETUP = ("veth", "address", "route", "neighbor", "offload", "module")
RESTORE = ("module", "offload", "neighbor", "route", "address", "veth")
OWNED_VETH_CUTS = {
    "owned-empty",
    "owned-a-alias",
    "owned-aliases",
    "owned-a-up",
}


def checkpoint(label: str, cut_after: str | None) -> None:
    if label == cut_after:
        raise FailureCut(label)


def require_exact_or_absent(value: str, label: str) -> None:
    if value not in {"absent", "exact"}:
        raise Rejected(label)


def classify_artifact_retry_state_model(state: Lifecycle) -> str:
    """Model the read-only classifier that runs before any bootstrap or P0 work."""
    if state.artifact_receipt != "absent":
        if (
            state.artifact_intent != "exact"
            or state.artifact_receipt != "exact"
            or state.artifact_root != "exact"
        ):
            raise Rejected("artifact-receipt-drift")
        return "receipt"
    if state.artifact_intent != "absent":
        if state.artifact_intent != "exact" or state.artifact_root not in {
            "absent",
            "partial",
            "exact",
        }:
            raise Rejected("artifact-intent-drift")
        raise Rejected("artifact-intent-without-receipt")
    if state.artifact_root != "absent":
        raise Rejected("artifact-root-without-intent")
    return "absent"


def run_model(state: Lifecycle, cut_after: str | None = None) -> None:
    artifact_state = classify_artifact_retry_state_model(state)
    if not state.owner or not state.baseline or not state.operation:
        raise Rejected("foundation")
    if state.cleanup or state.restored or not state.bpf_baseline or not state.module_lock:
        raise Rejected("run-after-cleanup-or-bpf-drift")
    require_exact_or_absent(state.dependency_caches, "dependency-caches")
    if not state.dependency_intent:
        if state.dependency_caches != "absent" or state.dependency_binary:
            raise Rejected("dependency-resource-without-intent")
        state.dependency_intent = True
        checkpoint("dependency-intent", cut_after)
    if state.dependency_caches == "absent":
        state.dependency_caches = "exact"
        checkpoint("dependency-cache-create", cut_after)
    if not state.dependencies_downloaded:
        state.dependencies_downloaded = True
        checkpoint("dependency-download", cut_after)
    if not state.dependencies_verified:
        state.dependencies_verified = True
        checkpoint("dependency-verify", cut_after)
    if artifact_state == "absent":
        state.artifact_intent = "exact"
        checkpoint("artifact-intent", cut_after)
        state.artifact_root = "partial"
        checkpoint("artifact-build", cut_after)
        state.artifact_root = "exact"
        checkpoint("artifact-mode", cut_after)
        state.artifact_receipt = "exact"
        checkpoint("artifact-receipt", cut_after)
    if not state.dependency_binary:
        state.dependency_binary = True
        checkpoint("dependency-build", cut_after)
    if not state.preflight:
        state.preflight = True
        checkpoint("dependency-receipt", cut_after)

    require_exact_or_absent(state.runtime_temp, "runtime-temp")
    if state.runtime_temp == "absent":
        state.runtime_temp = "exact"
        checkpoint("runtime-temp", cut_after)

    if not state.veth_intent:
        state.veth_intent = True
        checkpoint("veth-intent", cut_after)
    if state.veth in {"foreign", "foreign-alias"}:
        raise Rejected("veth")
    if state.veth == "absent":
        state.veth = "owned-empty"
        checkpoint("veth-add", cut_after)
    for before, after, label in (
        ("owned-empty", "owned-a-alias", "veth-alias-a"),
        ("owned-a-alias", "owned-aliases", "veth-alias-b"),
        ("owned-aliases", "owned-a-up", "veth-up-a"),
        ("owned-a-up", "exact", "veth-up-b"),
    ):
        if state.veth == before:
            state.veth = after
            checkpoint(label, cut_after)
    if state.veth != "exact":
        raise Rejected("veth")
    state.receipts.add("veth")
    checkpoint("veth-receipt", cut_after)

    for label in ("address", "route", "neighbor"):
        value = getattr(state, label)
        require_exact_or_absent(value, label)
        if value == "absent":
            setattr(state, label, "exact")
            checkpoint(f"{label}-mutation", cut_after)
        state.receipts.add(label)
        checkpoint(f"{label}-receipt", cut_after)

    if state.offload not in {"baseline", "desired"}:
        raise Rejected("offload")
    if not state.offload_baseline:
        state.offload_baseline = True
        checkpoint("offload-baseline", cut_after)
    if state.offload == "baseline":
        state.offload = "desired"
        checkpoint("offload-mutation", cut_after)
    state.receipts.add("offload")
    checkpoint("offload-receipt", cut_after)

    require_exact_or_absent(state.module, "module")
    if state.module_unloaded:
        raise Rejected("module-already-restored")
    if state.module == "absent":
        if state.module_intent:
            raise Rejected("module-intent-without-live")
        state.module_intent = True
        checkpoint("module-intent", cut_after)
        state.module = "exact"
        checkpoint("module-mutation", cut_after)
    elif not state.module_intent:
        raise Rejected("module-live-without-intent")
    state.receipts.add("module")
    checkpoint("module-receipt", cut_after)


def restore_model(state: Lifecycle, cut_after: str | None = None) -> None:
    if state.restored:
        if (
            state.runtime_temp == "foreign"
            or (state.veth_intent and state.runtime_temp != "exact")
            or state.veth != "absent"
            or state.module != "absent"
            or not state.bpf_baseline
            or not state.module_lock
            or (state.module_intent and not state.module_unloaded)
        ):
            raise Rejected("restored-drift")
        return
    if not state.owner or not state.baseline or not state.operation or not state.module_lock:
        raise Rejected("foundation")
    artifact_state = classify_artifact_retry_state_model(state)
    if not state.bpf_baseline:
        raise Rejected("bpf-drift")
    if state.dependency_caches == "foreign":
        raise Rejected("dependency-cache-identity")
    if not state.dependency_intent and (
        state.dependency_caches != "absent"
        or state.dependencies_downloaded
        or state.dependencies_verified
        or state.dependency_binary
        or state.preflight
    ):
        raise Rejected("dependency-resource-without-intent")
    if artifact_state == "absent":
        if (
            state.runtime_temp != "absent"
            or state.veth_intent
            or state.receipts
            or state.veth != "absent"
            or state.address != "absent"
            or state.route != "absent"
            or state.neighbor != "absent"
            or state.offload != "baseline"
            or state.module != "absent"
            or state.module_intent
        ):
            raise Rejected("live-state-before-artifact-receipt")
        if not state.cleanup:
            state.cleanup = True
            checkpoint("cleanup-intent", cut_after)
        state.restored = True
        checkpoint("restored", cut_after)
        return

    receipt_prefix = tuple(name for name in SETUP if name in state.receipts)
    if receipt_prefix != SETUP[: len(receipt_prefix)]:
        raise Rejected("receipt-prefix")
    first_missing = SETUP[len(receipt_prefix)] if len(receipt_prefix) < len(SETUP) else None
    if state.runtime_temp == "foreign":
        raise Rejected("runtime-temp-identity")
    if state.veth_intent and not state.preflight:
        raise Rejected("veth-intent-without-preflight")
    if state.veth_intent and state.runtime_temp != "exact":
        raise Rejected("veth-intent-without-runtime-temp")
    if not state.veth_intent:
        if (
            state.veth != "absent"
            or state.module != "absent"
            or state.module_intent
            or state.receipts
        ):
            raise Rejected("resource-without-veth-intent")
    elif state.veth in {"foreign", "foreign-alias"}:
        raise Rejected("veth-identity")
    elif state.veth in OWNED_VETH_CUTS and first_missing != "veth":
        raise Rejected("owned-cut-out-of-order")

    for label in ("address", "route", "neighbor"):
        value = getattr(state, label)
        if value == "foreign":
            raise Rejected(f"{label}-identity")
        if value == "exact" and label not in state.receipts and first_missing != label:
            raise Rejected(f"{label}-out-of-order")
    if state.offload == "foreign":
        raise Rejected("offload-identity")
    if state.offload == "desired" and "offload" not in state.receipts and first_missing != "offload":
        raise Rejected("offload-out-of-order")
    if state.module in {"foreign", "empty-lease"}:
        raise Rejected("module-identity")
    if state.module == "exact" and not state.module_intent:
        raise Rejected("module-live-without-intent")
    if "module" in state.receipts and not state.module_intent:
        raise Rejected("module-receipt-without-intent")
    if state.module == "exact" and "module" not in state.receipts and first_missing != "module":
        raise Rejected("module-out-of-order")

    if not state.cleanup:
        state.cleanup = True
        checkpoint("cleanup-intent", cut_after)

    if state.module == "exact":
        state.module = "absent"
        checkpoint("module-delete", cut_after)
    elif state.module != "absent":
        raise Rejected("module-identity")
    if state.module_intent and not state.module_unloaded:
        state.module_unloaded = True
        checkpoint("module-unloaded-receipt", cut_after)

    if state.offload == "desired":
        state.offload = "baseline"
        checkpoint("offload-restore", cut_after)
    elif state.offload != "baseline":
        raise Rejected("offload-identity")

    for label in ("neighbor", "route", "address"):
        value = getattr(state, label)
        if value == "exact":
            setattr(state, label, "absent")
            checkpoint(f"{label}-delete", cut_after)
        elif value != "absent":
            raise Rejected(f"{label}-identity")

    if state.veth == "exact" or state.veth in OWNED_VETH_CUTS:
        state.veth = "absent"
        checkpoint("veth-delete", cut_after)
    if not state.bpf_baseline:
        raise Rejected("final-bpf-drift")
    state.restored = True
    checkpoint("restored", cut_after)


def exercise_lifecycle_model() -> None:
    setup_cuts = (
        "dependency-intent",
        "dependency-cache-create",
        "dependency-download",
        "dependency-verify",
        "artifact-receipt",
        "dependency-build",
        "dependency-receipt",
        "runtime-temp",
        "veth-intent",
        "veth-add",
        "veth-alias-a",
        "veth-alias-b",
        "veth-up-a",
        "veth-up-b",
        "veth-receipt",
        "address-mutation",
        "address-receipt",
        "route-mutation",
        "route-receipt",
        "neighbor-mutation",
        "neighbor-receipt",
        "offload-baseline",
        "offload-mutation",
        "offload-receipt",
        "module-intent",
        "module-mutation",
        "module-receipt",
    )
    for cut in setup_cuts:
        state = Lifecycle()
        try:
            run_model(state, cut)
        except FailureCut:
            pass
        else:
            fail(f"setup cut {cut} did not fire")
        restore_model(state)
        if (
            not state.restored
            or state.runtime_temp not in {"absent", "exact"}
            or state.veth != "absent"
            or state.module != "absent"
        ):
            fail(f"setup cut {cut} did not restore directly from partial state: {state}")

    for cut in ("artifact-intent", "artifact-build", "artifact-mode"):
        state = Lifecycle()
        try:
            run_model(state, cut)
        except FailureCut:
            pass
        else:
            fail(f"artifact producer cut {cut} did not fire")
        retained = copy.deepcopy(state)
        try:
            run_model(state)
        except Rejected:
            pass
        else:
            fail(f"artifact intent-only retry after {cut} was accepted")
        if state != retained:
            fail(f"artifact intent-only retry after {cut} caused side effects")
        try:
            restore_model(state)
        except Rejected:
            pass
        else:
            fail(f"artifact intent-only restore after {cut} was accepted")
        if state != retained:
            fail(f"artifact intent-only restore after {cut} caused live-state changes")

    clean_stage = Lifecycle()
    run_model(clean_stage)
    if (
        not clean_stage.preflight
        or clean_stage.dependency_caches != "exact"
        or not clean_stage.dependencies_downloaded
        or clean_stage.runtime_temp != "exact"
        or clean_stage.receipts != set(SETUP)
    ):
        fail(f"clean-stage fixture did not produce dependencies before mutation: {clean_stage}")
    missing_dependencies = Lifecycle(dependency_caches="foreign")
    try:
        run_model(missing_dependencies)
    except Rejected:
        if (
            missing_dependencies.runtime_temp != "absent"
            or missing_dependencies.veth != "absent"
            or missing_dependencies.receipts
        ):
            fail("dependency preflight failure reached a host mutation")
    else:
        fail("clean-stage fixture accepted a foreign dependency cache")

    restored_cuts = (
        "cleanup-intent",
        "module-delete",
        "module-unloaded-receipt",
        "offload-restore",
        "neighbor-delete",
        "route-delete",
        "address-delete",
        "veth-delete",
        "restored",
    )
    complete = Lifecycle()
    run_model(complete)
    receipt_reuse = copy.deepcopy(complete)
    run_model(receipt_reuse)
    if receipt_reuse != complete:
        fail(f"exact receipt reuse mutated lifecycle state: {receipt_reuse}")
    for cut in restored_cuts:
        state = copy.deepcopy(complete)
        try:
            restore_model(state, cut)
        except FailureCut:
            pass
        else:
            fail(f"restore cut {cut} did not fire")
        restore_model(state)
        if not state.restored or state.veth != "absent" or state.module != "absent":
            fail(f"restore cut {cut} did not converge: {state}")

    for label, mutate in {
        "foreign-veth": lambda state: setattr(state, "veth", "foreign"),
        "foreign-veth-alias": lambda state: setattr(state, "veth", "foreign-alias"),
        "foreign-runtime-temp": lambda state: setattr(state, "runtime_temp", "foreign"),
        "foreign-dependency-cache": lambda state: setattr(state, "dependency_caches", "foreign"),
        "foreign-artifact-intent": lambda state: setattr(state, "artifact_intent", "foreign"),
        "foreign-artifact-receipt": lambda state: setattr(state, "artifact_receipt", "foreign"),
        "foreign-artifact-root": lambda state: setattr(state, "artifact_root", "foreign"),
        "foreign-route": lambda state: setattr(state, "route", "foreign"),
        "foreign-offload": lambda state: setattr(state, "offload", "foreign"),
        "foreign-module": lambda state: setattr(state, "module", "foreign"),
        "empty-lease-module": lambda state: setattr(state, "module", "empty-lease"),
        "module-lock-missing": lambda state: setattr(state, "module_lock", False),
        "bpf-drift": lambda state: setattr(state, "bpf_baseline", False),
    }.items():
        state = copy.deepcopy(complete)
        mutate(state)
        try:
            restore_model(state)
        except Rejected:
            continue
        fail(f"restore model accepted {label}")

    for label, state in {
        "receipt-without-intent": Lifecycle(
            artifact_receipt="exact", artifact_root="exact"
        ),
        "root-without-intent": Lifecycle(artifact_root="exact"),
    }.items():
        before = copy.deepcopy(state)
        try:
            run_model(state)
        except Rejected:
            pass
        else:
            fail(f"run model accepted {label}")
        if state != before:
            fail(f"early artifact classifier mutated {label}")

    incomplete = Lifecycle(
        preflight=True,
        veth_intent=True,
        receipts={"veth", "route"},
        veth="exact",
        route="exact",
    )
    try:
        restore_model(incomplete)
    except Rejected:
        pass
    else:
        fail("restore model accepted a non-prefix receipt set")

    foreign_alias = Lifecycle(preflight=True, veth="foreign-alias")
    try:
        run_model(foreign_alias)
    except Rejected:
        if foreign_alias.veth != "foreign-alias":
            fail("foreign veth alias was overwritten before rejection")
    else:
        fail("run model claimed a foreign non-empty veth alias")


def inspect_sources(runner_path: pathlib.Path, runner: str, seam: str) -> None:
    production = {runner_path.name: runner, "controller-seam.sh": seam}
    forbidden = (
        r"\brm\s+-[^\n]*r",
        r"\bfind\b[^\n]*-delete",
        r"\bxargs\b[^\n]*\brm\b",
        r"\brsync\b[^\n]*--delete",
        r"\bchroot\b",
        r"\bnsenter\b",
        r"\b(?:docker|podman)\b",
        r"(?:^|\s)eval(?:\s|$)",
        r"(?:^|\s)(?:sh|bash)\s+-c(?:\s|$)",
        r"(?:^|\s)trap(?:\s|$)",
        r"/proc/1/root",
        r"(?:^|\s)--privileged(?:\s|$)",
        r"\|\|\s*true",
        r"(?:>|2>)\s*/dev/null",
        r"while\s+true",
    )
    for name, source in production.items():
        for pattern in forbidden:
            if re.search(pattern, source, re.MULTILINE):
                fail(f"{name} contains prohibited pattern {pattern}")

    if runner.count("build_argv() {") != 1:
        fail("runner must have exactly one operation argv builder")
    required = (
        "readonly RUN_ID='c8e41d73'",
        "readonly RESOURCE_ID='5b8d30f1'",
        "STATE_SCHEMA='owner,baseline,operation-intent,dependency-intent,artifact-intent,artifacts,dependency-preflight,veth-intent,veth,address,route,neighbor,offload,module-intent,module,tested,cleanup-intent,restored'",
        "readonly LOCAL_IPV4='198.18.82.1'",
        "readonly REMOTE_IPV4='198.18.82.2'",
        "readonly ROUTE_MTU='1500'",
        'readonly GO_CACHE="${EVIDENCE_ROOT}/go-cache"',
        'readonly GO_MOD_CACHE="${EVIDENCE_ROOT}/go-mod-cache"',
        'readonly GO_PATH="${EVIDENCE_ROOT}/go-path"',
        'readonly GO_TMP="${EVIDENCE_ROOT}/go-tmp"',
        'readonly RUNTIME_TEMP="${STAGE_ROOT}/go-tmp-realhost-${RESOURCE_ID}"',
        'readonly VETH_A="wg${RESOURCE_ID:0:5}a"',
        'readonly VETH_B="wg${RESOURCE_ID:0:5}b"',
        'readonly VETH_A_ALIAS="wg-mix-ebpf:${RUN_ID}:${RESOURCE_ID}:a"',
        'readonly VETH_B_ALIAS="wg-mix-ebpf:${RUN_ID}:${RESOURCE_ID}:b"',
        'readonly MODULE_LEASE_HELPER_RELATIVE="scripts/realhost-b82-c8e41d73/checksum-module-lease.sh"',
        'readonly MODULE_LEASE_LOCK="${STAGE_ROOT}/checksum-module-lease.v1.lock"',
        'readonly MODULE_LEASE_ID="${RUN_ID}-${RESOURCE_ID}"',
        "GOFLAGS=-mod=readonly",
        "WG_MIX_FAKETCP_ROUTED_LOCAL_IPV4=\"${LOCAL_IPV4}\"",
        "WG_MIX_FAKETCP_ROUTED_REMOTE_IPV4=\"${REMOTE_IPV4}\"",
        "WG_MIX_FAKETCP_ROUTED_ROUTE_MTU=\"${ROUTE_MTU}\"",
        "WG_MIX_FAKETCP_REALHOST_RESOURCE_ID=\"${RESOURCE_ID}\"",
        "TestFakeTCPRealHostXORTypewordHeaderCompositionIntegration",
        "TestFakeTCPRealHostRoutedIPHdrInclNone",
        "TestFakeTCPRealHostRoutedUDPSocketPartial",
        "TestFakeTCPRealHostRoutedUDPSegmentGSO",
        "GOPROXY=off",
        "GOPROXY=https://proxy.golang.org",
        "preflight-mod-download",
        "preflight-mod-verify",
        "preflight-build",
        "TestFakeTCPRealHostRoutedHarnessSelectedBinaryContract",
        "ensure_operation_intent",
        "ensure_dependency_intent",
        "classify_artifact_retry_state",
        "ensure_artifacts",
        "ensure_dependency_preflight",
        "ensure_runtime_temp",
        "ensure_veth_intent",
        "validate_partial_setup_for_restore",
        "unreceipted-reconcile=exact-pair-and-empty-or-owned-alias-only",
        "reuse=exact-receipt-only",
        "capability_bits_changed=0",
        "no automatic teardown",
        "ensure_cleanup_intent",
        "assert_bpf_links_baseline",
        "load_checksum_module_helper",
        "configure_checksum_module_lease",
        "module-lease-binding-contract",
        "c8_checksum_module_acquire",
        "c8_checksum_module_load",
        "c8_checksum_module_restore",
        "c8_checksum_module_validate_restore_state",
    )
    for literal in required:
        if literal not in runner:
            fail(f"runner is missing {literal!r}")
    for stale_cache in ("go-cache-routed", "go-mod-cache-routed"):
        if stale_cache in runner:
            fail(f"runner still relies on empty harness-only cache {stale_cache!r}")
    if "readonly RUN_ID='c8e41d73'" not in seam:
        fail("controller seam is not bound to the controller stage run ID")

    builder = function_body(runner, "build_argv")
    for literal in (
        'OP_ARGV=(/usr/sbin/ip link delete dev "${VETH_A}")',
        'OP_ARGV=(/usr/sbin/ip -4 neigh del "${REMOTE_IPV4}" lladdr "${VETH_B_MAC}" nud permanent dev "${VETH_A}")',
        'OP_ARGV=(/usr/sbin/ip -4 route del "${REMOTE_IPV4}/${PREFIX_BITS}" dev "${VETH_A}" src "${LOCAL_IPV4}" mtu "${ROUTE_MTU}" proto static scope link)',
        'OP_ARGV=(/usr/sbin/ip -4 address del "${LOCAL_IPV4}/${PREFIX_BITS}" dev "${VETH_A}" scope global)',
        'OP_ARGV=(/usr/sbin/ethtool -K "${VETH_A}" tso on)',
        'OP_ARGV=(/usr/bin/mkdir --mode=0700 -- "${RUNTIME_TEMP}")',
        'OP_ARGV=(/usr/bin/mkdir --mode=0700 -- "${GO_CACHE}")',
        'OP_ARGV=(/usr/bin/mkdir --mode=0700 -- "${GO_MOD_CACHE}")',
        'OP_ARGV=(/usr/bin/mkdir --mode=0700 -- "${GO_PATH}")',
        'OP_ARGV=(/usr/bin/mkdir --mode=0700 -- "${GO_TMP}")',
    ):
        if literal not in builder:
            fail(f"argv builder is missing exact reverse operation {literal!r}")
    outside_builder = runner.replace(builder, "")
    if re.search(r"/(?:usr/)?sbin/(?:ip|ethtool)\s+[^\n]*(?:del|delete|-K)", outside_builder):
        fail("runner has a destructive network argv outside the sole builder")
    if "/usr/sbin/insmod" in builder or "/usr/sbin/rmmod" in builder:
        fail("runner duplicates shared module mutation argv in its local builder")
    if "c8_checksum_module_load M0" not in function_body(runner, "ensure_module_phase"):
        fail("module setup does not delegate to the shared lease helper")
    if "c8_checksum_module_restore R1" not in function_body(runner, "restore_module"):
        fail("module restore does not delegate to the shared lease helper")
    if '"${PREFLIGHT_BINARY}" -test.run' not in builder:
        fail("post-mutation tests do not execute the preflight-bound binary")
    if 'TMPDIR="${RUNTIME_TEMP}"' not in builder:
        fail("selected binary does not receive the reviewed real-host TMPDIR")
    if 'GOTMPDIR="${GO_TMP}" TMPDIR="${GO_TMP}"' not in runner:
        fail("Go preflight does not use its run-owned temp root")
    run_tests = function_body(runner, "run_tests")
    if "/usr/bin/go" in run_tests or "list:" in run_tests:
        fail("post-mutation test phase can rebuild or rediscover dependencies")

    restore = function_body(runner, "restore_state_machine")
    first_cleanup = restore.index("ensure_cleanup_intent")
    first_bpf = restore.index("assert_bpf_links_baseline", first_cleanup)
    destructive_tail = restore[restore.index("restore_module", first_bpf) :]
    order = (
        "restore_module",
        "restore_offload",
        "restore_network",
        "assert_bpf_links_baseline",
        'write_phase "${RESTORED_PHASE}"',
    )
    positions = [destructive_tail.index(item) for item in order]
    if positions != sorted(positions):
        fail("restore lifecycle order drifted")
    for forward in (
        "ensure_veth_phase",
        "ensure_address_phase",
        "ensure_route_phase",
        "ensure_neighbor_phase",
        "ensure_offload_phase",
        "ensure_module_phase",
    ):
        if forward in restore:
            fail(f"restore path can recreate forward resource through {forward}")

    run = function_body(runner, "run_state_machine")
    run_order = (
        "classify_artifact_retry_state",
        "bootstrap_evidence",
        "c8_checksum_module_acquire",
        "ensure_owner",
        "ensure_baseline",
        "ensure_operation_intent",
        "ensure_dependency_intent",
        "ensure_dependency_preflight",
        "configure_checksum_module_lease",
        "ensure_runtime_temp",
        "ensure_veth_phase",
    )
    positions = [run.index(item) for item in run_order]
    if positions != sorted(positions):
        fail("run did not finish dependency/build preflight before host mutation")
    first_run_statement = next(
        line.strip() for line in run.splitlines() if line.strip()
    )
    if first_run_statement != "classify_artifact_retry_state":
        fail("artifact retry classifier is not the first run-state operation")
    classifier = function_body(runner, "classify_artifact_retry_state")
    for forbidden_classifier in (
        "run_operation",
        "write_phase",
        "bootstrap_evidence",
        "ensure_dependency_preflight",
        "preflight-mod-download",
        "/usr/bin/make",
        "ensure_veth_phase",
    ):
        if forbidden_classifier in classifier:
            fail(
                "artifact retry classifier has a side-effect authority: "
                f"{forbidden_classifier}"
            )
    for classifier_gate in (
        "artifact-receipt-without-intent-preflight",
        "artifact-intent-without-receipt-preflight",
        "artifact-root-without-intent-preflight",
        "validate_artifact_receipt",
    ):
        if classifier_gate not in classifier:
            fail(f"artifact retry classifier is missing {classifier_gate!r}")
    restore_prefix = (
        "bootstrap_evidence",
        "c8_checksum_module_acquire",
        "ensure_owner",
        "ensure_baseline",
        "validate_dependency_caches_for_restore",
        "configure_checksum_module_lease",
        "validate_partial_setup_for_restore",
    )
    positions = [restore.index(item) for item in restore_prefix]
    if positions != sorted(positions):
        fail("restore does not hold the shared module lock across validation and cleanup")
    preflight = function_body(runner, "ensure_dependency_preflight")
    if not all(
        item in preflight
        for item in (
            "preflight-mod-verify",
            "preflight-mod-download",
            "preflight-build",
            "list:${name}",
            "preflight-contract",
        )
    ):
        fail("dependency preflight does not compile and bind every selected test")
    preflight_order = (
        "preflight-mod-download",
        "preflight-mod-verify",
        "ensure_artifacts",
        "preflight-build",
    )
    if [preflight.index(item) for item in preflight_order] != sorted(
        preflight.index(item) for item in preflight_order
    ):
        fail("dependency download/artifact/preflight build order drifted")
    artifacts = function_body(runner, "ensure_artifacts")
    artifact_order = (
        'write_phase "${ARTIFACT_INTENT_PHASE}"',
        "run_operation P.artifact-build artifact-build",
        "run_operation P.artifact-mode artifact-mode",
        "load_artifact_identity",
        'write_phase "${ARTIFACT_PHASE}"',
        "validate_artifact_receipt || fail 'artifact-receipt-postwrite'",
    )
    if [artifacts.index(item) for item in artifact_order] != sorted(
        artifacts.index(item) for item in artifact_order
    ):
        fail("artifact intent/build/mode/receipt order drifted")
    if "run_operation" in function_body(runner, "validate_dependency_preflight"):
        fail("restore dependency validation can execute a build")

    veth = function_body(runner, "ensure_veth_phase")
    alias_guard = function_body(runner, "unreceipted_veth_pair_matches")
    if not all(
        literal in alias_guard
        for literal in (
            '[[ -z "${a_alias}" || "${a_alias}" == "${VETH_A_ALIAS}" ]]',
            '[[ -z "${b_alias}" || "${b_alias}" == "${VETH_B_ALIAS}" ]]',
        )
    ):
        fail("unreceipted veth claim does not reject foreign non-empty aliases")
    if veth.index("unreceipted_veth_pair_matches") > veth.index("claim_veth_alias"):
        fail("veth aliases can be overwritten before the foreign-alias gate")

    cleanup = function_body(runner, "render_cleanup_intent")
    for receipt in (
        "DEPENDENCY_INTENT",
        "ARTIFACT_INTENT",
        "ARTIFACT",
        "DEPENDENCY",
        "VETH_INTENT",
        "VETH",
        "ADDRESS",
        "ROUTE",
        "NEIGHBOR",
        "OFFLOAD",
        "MODULE_INTENT",
        "MODULE",
    ):
        if f'"${{{receipt}_PHASE}}"' not in cleanup:
            fail(f"cleanup intent does not bind {receipt} receipt")
    if '"${OFFLOAD_BASELINE_A}"' not in cleanup:
        fail("cleanup intent does not bind the optional offload baseline")
    if 'directory_binding "${RUNTIME_TEMP}"' not in cleanup:
        fail("cleanup intent does not bind the retained real-host TMPDIR identity")
    for cache in ("GO_CACHE", "GO_MOD_CACHE", "GO_PATH", "GO_TMP"):
        if f'directory_binding "${{{cache}}}"' not in cleanup:
            fail(f"cleanup intent does not bind retained dependency directory {cache}")

    partial_restore = function_body(runner, "validate_partial_setup_for_restore")
    if "validate_runtime_temp_for_restore" not in partial_restore:
        fail("partial restore does not validate the retained real-host TMPDIR")
    if "validate_dependency_caches_for_restore" not in partial_restore:
        fail("partial restore does not validate run-owned dependency caches")
    if "validate_module_for_restore" not in partial_restore:
        fail("partial restore does not classify the shared module lease state")

    for forbidden in ("ssh", "scp", "sudo", "credientials/", "192.168.10.28", "47.116.202.155"):
        if forbidden in seam:
            fail(f"controller seam contains forbidden transport/input {forbidden!r}")
    for required_seam in (
        "build_runner_argv",
        "/bin/bash -p \"${ROOT_RUNNER}\"",
        'exec /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C "${RUNNER_ARGV[@]}"',
    ):
        if required_seam not in seam:
            fail(f"controller seam is missing {required_seam!r}")


def exercise_empty_go_cache() -> None:
    """Execute the producer/offline-consumer contract against genuinely empty caches."""

    go = shutil.which("go")
    if go is None:
        fail("clean-stage cache fixture requires go")
    with tempfile.TemporaryDirectory(prefix="wg-mix-routed-clean-cache-") as temp_text:
        root = pathlib.Path(temp_text)
        proxy = root / "proxy"
        dependency = "example.com/cachedep"
        version = "v1.0.0"
        version_root = proxy / dependency / "@v"
        version_root.mkdir(parents=True, mode=0o700)
        (version_root / f"{version}.info").write_text(
            json.dumps({"Version": version, "Time": "2026-01-01T00:00:00Z"}) + "\n",
            encoding="utf-8",
        )
        (version_root / f"{version}.mod").write_text(
            f"module {dependency}\n\ngo 1.20\n", encoding="utf-8"
        )
        with zipfile.ZipFile(
            version_root / f"{version}.zip", "w", compression=zipfile.ZIP_DEFLATED
        ) as archive:
            archive.writestr(
                f"{dependency}@{version}/dep.go",
                "package cachedep\n\nconst Value = 42\n",
            )

        source = root / "source"
        source.mkdir(mode=0o700)
        (source / "go.mod").write_text(
            "module example.com/fixture\n\ngo 1.20\n\n"
            f"require {dependency} {version}\n",
            encoding="utf-8",
        )
        (source / "fixture.go").write_text(
            'package fixture\n\nimport "example.com/cachedep"\n\n'
            "const Value = cachedep.Value\n",
            encoding="utf-8",
        )
        (source / "fixture_test.go").write_text(
            'package fixture\n\nimport "testing"\n\n'
            "func TestValue(t *testing.T) { if Value != 42 { t.Fatal(Value) } }\n",
            encoding="utf-8",
        )

        seed_dirs = {name: root / f"seed-{name}" for name in ("cache", "mod", "path", "tmp")}
        for path in seed_dirs.values():
            path.mkdir(mode=0o700)
        base_env = {
            "PATH": f"{pathlib.Path(go).parent}:/usr/bin:/bin",
            "LC_ALL": "C",
            "CGO_ENABLED": "0",
            "GOENV": "off",
            "GOTOOLCHAIN": "local",
            "GOWORK": "off",
            "GO111MODULE": "on",
            "GOVCS": "*:off",
            "GOPROXY": proxy.as_uri(),
            "GOSUMDB": "off",
            "GOCACHE": str(seed_dirs["cache"]),
            "GOMODCACHE": str(seed_dirs["mod"]),
            "GOPATH": str(seed_dirs["path"]),
            "GOTMPDIR": str(seed_dirs["tmp"]),
            "TMPDIR": str(seed_dirs["tmp"]),
        }
        subprocess.run(
            [go, "-C", str(source), "mod", "download", "all"],
            env=base_env,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if not (source / "go.sum").is_file():
            fail("clean-stage fixture failed to seed a committed-style go.sum")

        caches = {name: root / name for name in ("go-cache", "go-mod-cache", "go-path", "go-tmp")}
        for path in caches.values():
            path.mkdir(mode=0o700)
            if any(path.iterdir()):
                fail(f"clean-stage target cache was not empty: {path}")
        clean_env = base_env | {
            "GOFLAGS": "-mod=readonly",
            "GOCACHE": str(caches["go-cache"]),
            "GOMODCACHE": str(caches["go-mod-cache"]),
            "GOPATH": str(caches["go-path"]),
            "GOTMPDIR": str(caches["go-tmp"]),
            "TMPDIR": str(caches["go-tmp"]),
        }
        subprocess.run(
            [go, "-C", str(source), "mod", "download", "all"],
            env=clean_env,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        offline_env = clean_env | {"GOPROXY": "off"}
        for argv in (
            [go, "-C", str(source), "mod", "verify"],
            [go, "-C", str(source), "test", "-c", "-o", str(root / "fixture.test"), "."],
        ):
            subprocess.run(
                argv,
                env=offline_env,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
        downloaded = caches["go-mod-cache"] / "cache" / "download" / dependency / "@v" / f"{version}.zip"
        if not downloaded.is_file() or not (root / "fixture.test").is_file():
            fail("clean-stage producer did not make the offline dependency build executable")


def main() -> None:
    if len(sys.argv) != 3:
        fail("usage: test_routed_veth_harness_static.py ROOT_RUNNER CONTROLLER_SEAM")
    runner_path, runner = read_regular(sys.argv[1])
    _, seam = read_regular(sys.argv[2])
    inspect_sources(runner_path, runner, seam)
    exercise_lifecycle_model()
    exercise_empty_go_cache()
    print("routed-veth static safety, empty-cache execution and failure-cut lifecycle model: PASS")


if __name__ == "__main__":
    main()
