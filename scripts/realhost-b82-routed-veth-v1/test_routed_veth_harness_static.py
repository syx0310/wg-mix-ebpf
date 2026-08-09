#!/usr/bin/env python3
"""Static and executable lifecycle contract for the routed-veth harness."""

from __future__ import annotations

import copy
import dataclasses
import pathlib
import re
import sys


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
    dependencies_staged: bool = True
    dependencies_verified: bool = False
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
    module: str = "absent"  # absent, exact, foreign
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


def run_model(state: Lifecycle, cut_after: str | None = None) -> None:
    if not state.owner or not state.baseline or not state.operation:
        raise Rejected("foundation")
    if state.cleanup or state.restored or not state.bpf_baseline:
        raise Rejected("run-after-cleanup-or-bpf-drift")
    if not state.dependencies_staged:
        raise Rejected("dependency-preflight-before-host-mutation")
    if not state.dependencies_verified:
        state.dependencies_verified = True
        checkpoint("dependency-verify", cut_after)
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
    if state.module == "absent":
        state.module = "exact"
        checkpoint("module-mutation", cut_after)
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
        ):
            raise Rejected("restored-drift")
        return
    if not state.owner or not state.baseline or not state.operation:
        raise Rejected("foundation")
    if not state.bpf_baseline:
        raise Rejected("bpf-drift")

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
        if state.veth != "absent" or state.module != "absent" or state.receipts:
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
    if state.module == "foreign":
        raise Rejected("module-identity")
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
        "dependency-verify",
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

    clean_stage = Lifecycle(dependencies_staged=True)
    run_model(clean_stage)
    if (
        not clean_stage.preflight
        or clean_stage.runtime_temp != "exact"
        or clean_stage.receipts != set(SETUP)
    ):
        fail(f"clean-stage fixture did not use the bound staged dependencies: {clean_stage}")
    missing_dependencies = Lifecycle(dependencies_staged=False)
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
        fail("clean-stage fixture accepted missing staged dependencies")

    restored_cuts = (
        "cleanup-intent",
        "module-delete",
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
        "foreign-route": lambda state: setattr(state, "route", "foreign"),
        "foreign-offload": lambda state: setattr(state, "offload", "foreign"),
        "foreign-module": lambda state: setattr(state, "module", "foreign"),
        "bpf-drift": lambda state: setattr(state, "bpf_baseline", False),
    }.items():
        state = copy.deepcopy(complete)
        mutate(state)
        try:
            restore_model(state)
        except Rejected:
            continue
        fail(f"restore model accepted {label}")

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
        "STATE_SCHEMA='owner,baseline,operation-intent,dependency-preflight,veth-intent,veth,address,route,neighbor,offload,module,tested,cleanup-intent,restored'",
        "readonly LOCAL_IPV4='198.18.82.1'",
        "readonly REMOTE_IPV4='198.18.82.2'",
        "readonly ROUTE_MTU='1500'",
        'readonly GO_MOD_CACHE="${STAGE_ROOT}/go-mod-cache"',
        'readonly RUNTIME_TEMP="${STAGE_ROOT}/go-tmp-realhost-${RESOURCE_ID}"',
        'readonly VETH_A="wg${RESOURCE_ID:0:5}a"',
        'readonly VETH_B="wg${RESOURCE_ID:0:5}b"',
        'readonly VETH_A_ALIAS="wg-mix-ebpf:${RUN_ID}:${RESOURCE_ID}:a"',
        'readonly VETH_B_ALIAS="wg-mix-ebpf:${RUN_ID}:${RESOURCE_ID}:b"',
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
        "preflight-mod-verify",
        "preflight-build",
        "TestFakeTCPRealHostRoutedHarnessSelectedBinaryContract",
        "ensure_operation_intent",
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
        'OP_ARGV=(/usr/sbin/rmmod "${MODULE_NAME}")',
        'OP_ARGV=(/usr/bin/mkdir --mode=0700 -- "${RUNTIME_TEMP}")',
    ):
        if literal not in builder:
            fail(f"argv builder is missing exact reverse operation {literal!r}")
    outside_builder = runner.replace(builder, "")
    if re.search(r"/(?:usr/)?sbin/(?:ip|ethtool|rmmod)\s+[^\n]*(?:del|delete|-K)", outside_builder):
        fail("runner has a destructive network/module argv outside the sole builder")
    if '"${PREFLIGHT_BINARY}" -test.run' not in builder:
        fail("post-mutation tests do not execute the preflight-bound binary")
    if 'TMPDIR="${RUNTIME_TEMP}"' not in builder:
        fail("selected binary does not receive the reviewed real-host TMPDIR")
    if 'GOTMPDIR="${GO_TMP}" TMPDIR="${GO_TMP}"' not in runner:
        fail("offline Go preflight does not retain the generic staged temp root")
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
        "ensure_owner",
        "ensure_baseline",
        "ensure_operation_intent",
        "ensure_dependency_preflight",
        "ensure_runtime_temp",
        "ensure_veth_phase",
    )
    positions = [run.index(item) for item in run_order]
    if positions != sorted(positions):
        fail("run did not finish dependency/build preflight before host mutation")
    preflight = function_body(runner, "ensure_dependency_preflight")
    if not all(
        item in preflight
        for item in (
            "preflight-mod-verify",
            "preflight-build",
            "list:${name}",
            "preflight-contract",
        )
    ):
        fail("dependency preflight does not compile and bind every selected test")
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
        "DEPENDENCY",
        "VETH_INTENT",
        "VETH",
        "ADDRESS",
        "ROUTE",
        "NEIGHBOR",
        "OFFLOAD",
        "MODULE",
    ):
        if f'"${{{receipt}_PHASE}}"' not in cleanup:
            fail(f"cleanup intent does not bind {receipt} receipt")
    if '"${OFFLOAD_BASELINE_A}"' not in cleanup:
        fail("cleanup intent does not bind the optional offload baseline")
    if 'directory_binding "${RUNTIME_TEMP}"' not in cleanup:
        fail("cleanup intent does not bind the retained real-host TMPDIR identity")

    partial_restore = function_body(runner, "validate_partial_setup_for_restore")
    if "validate_runtime_temp_for_restore" not in partial_restore:
        fail("partial restore does not validate the retained real-host TMPDIR")

    for forbidden in ("ssh", "scp", "sudo", "credientials/", "192.168.10.28", "47.116.202.155"):
        if forbidden in seam:
            fail(f"controller seam contains forbidden transport/input {forbidden!r}")
    for required_seam in (
        "build_runner_argv",
        "/bin/bash -p \"${ROOT_RUNNER}\"",
        "credential_read=0 remote_connections=0",
        "transport_integration=pending",
    ):
        if required_seam not in seam:
            fail(f"controller seam is missing {required_seam!r}")


def main() -> None:
    if len(sys.argv) != 3:
        fail("usage: test_routed_veth_harness_static.py ROOT_RUNNER CONTROLLER_SEAM")
    runner_path, runner = read_regular(sys.argv[1])
    _, seam = read_regular(sys.argv[2])
    inspect_sources(runner_path, runner, seam)
    exercise_lifecycle_model()
    print("routed-veth static safety and failure-cut lifecycle model: PASS")


if __name__ == "__main__":
    main()
