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
    mutation: bool = True
    receipts: set[str] = dataclasses.field(default_factory=set)
    veth: str = "absent"  # absent, exact, foreign, partial
    address: str = "absent"  # absent, exact, foreign
    route: str = "absent"
    neighbor: str = "absent"
    offload: str = "baseline"  # baseline, desired, foreign
    module: str = "absent"  # absent, exact, foreign
    bpf_baseline: bool = True
    cleanup: bool = False
    restored: bool = False


SETUP = ("veth", "address", "route", "neighbor", "offload", "module")
RESTORE = ("module", "offload", "neighbor", "route", "address", "veth")


def checkpoint(label: str, cut_after: str | None) -> None:
    if label == cut_after:
        raise FailureCut(label)


def require_exact_or_absent(value: str, label: str) -> None:
    if value not in {"absent", "exact"}:
        raise Rejected(label)


def run_model(state: Lifecycle, cut_after: str | None = None) -> None:
    if not state.owner or not state.baseline or not state.mutation:
        raise Rejected("foundation")
    if state.cleanup or state.restored or not state.bpf_baseline:
        raise Rejected("run-after-cleanup-or-bpf-drift")

    require_exact_or_absent(state.veth, "veth")
    if state.veth == "absent":
        state.veth = "exact"
        checkpoint("veth-mutation", cut_after)
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
            state.veth != "absent"
            or state.module != "absent"
            or not state.bpf_baseline
        ):
            raise Rejected("restored-drift")
        return
    if not state.owner or not state.baseline or not state.mutation:
        raise Rejected("foundation")
    if state.receipts != set(SETUP):
        raise Rejected("restore-requires-reconciled-run-state")
    if not state.bpf_baseline:
        raise Rejected("bpf-drift")

    if not state.cleanup:
        state.cleanup = True
        checkpoint("cleanup-intent", cut_after)

    if state.veth == "absent":
        if state.module != "absent":
            raise Rejected("veth-absent-module-present")
        state.restored = True
        checkpoint("restored", cut_after)
        return
    if state.veth != "exact":
        raise Rejected("veth-identity")

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

    state.veth = "absent"
    checkpoint("veth-delete", cut_after)
    if not state.bpf_baseline:
        raise Rejected("final-bpf-drift")
    state.restored = True
    checkpoint("restored", cut_after)


def exercise_lifecycle_model() -> None:
    setup_cuts = tuple(
        f"{name}-{point}"
        for name in SETUP
        for point in ("mutation", "receipt")
    )
    for cut in setup_cuts:
        state = Lifecycle()
        try:
            run_model(state, cut)
        except FailureCut:
            pass
        else:
            fail(f"setup cut {cut} did not fire")
        run_model(state)
        if state.receipts != set(SETUP):
            fail(f"setup cut {cut} did not converge: {state}")
        restore_model(state)
        if not state.restored:
            fail(f"setup cut {cut} did not restore: {state}")

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
        "partial-veth": lambda state: setattr(state, "veth", "partial"),
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

    incomplete = Lifecycle(receipts=set(SETUP) - {"route"}, veth="exact")
    try:
        restore_model(incomplete)
    except Rejected:
        pass
    else:
        fail("restore model accepted an unreconciled run cut")


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
        "STATE_SCHEMA='owner,baseline,mutation-plan,veth,address,route,neighbor,offload,module,tested,cleanup-intent,restored'",
        "readonly LOCAL_IPV4='198.18.82.1'",
        "readonly REMOTE_IPV4='198.18.82.2'",
        "readonly ROUTE_MTU='1500'",
        "WG_MIX_FAKETCP_ROUTED_LOCAL_IPV4=\"${LOCAL_IPV4}\"",
        "WG_MIX_FAKETCP_ROUTED_REMOTE_IPV4=\"${REMOTE_IPV4}\"",
        "WG_MIX_FAKETCP_ROUTED_ROUTE_MTU=\"${ROUTE_MTU}\"",
        "TestFakeTCPRealHostXORTypewordHeaderCompositionIntegration",
        "TestFakeTCPRealHostRoutedIPHdrInclNone",
        "TestFakeTCPRealHostRoutedUDPSocketPartial",
        "TestFakeTCPRealHostRoutedUDPSegmentGSO",
        "GOPROXY=off",
        "capability_bits_changed=0",
        "no automatic teardown",
        "ensure_cleanup_intent",
        "assert_bpf_links_baseline",
        "restore-requires-reconciled-run-state",
    )
    for literal in required:
        if literal not in runner:
            fail(f"runner is missing {literal!r}")

    builder = function_body(runner, "build_argv")
    for literal in (
        'OP_ARGV=(/usr/sbin/ip link delete dev "${VETH_A}")',
        'OP_ARGV=(/usr/sbin/ip -4 neigh del "${REMOTE_IPV4}" lladdr "${VETH_B_MAC}" nud permanent dev "${VETH_A}")',
        'OP_ARGV=(/usr/sbin/ip -4 route del "${REMOTE_IPV4}/${PREFIX_BITS}" dev "${VETH_A}" src "${LOCAL_IPV4}" mtu "${ROUTE_MTU}" proto static scope link)',
        'OP_ARGV=(/usr/sbin/ip -4 address del "${LOCAL_IPV4}/${PREFIX_BITS}" dev "${VETH_A}" scope global)',
        'OP_ARGV=(/usr/sbin/ethtool -K "${VETH_A}" tso on)',
        'OP_ARGV=(/usr/sbin/rmmod "${MODULE_NAME}")',
    ):
        if literal not in builder:
            fail(f"argv builder is missing exact reverse operation {literal!r}")
    outside_builder = runner.replace(builder, "")
    if re.search(r"/(?:usr/)?sbin/(?:ip|ethtool|rmmod)\s+[^\n]*(?:del|delete|-K)", outside_builder):
        fail("runner has a destructive network/module argv outside the sole builder")

    restore = function_body(runner, "restore_state_machine")
    first_cleanup = restore.index("ensure_cleanup_intent")
    first_bpf = restore.index("assert_bpf_links_baseline", first_cleanup)
    destructive_tail = restore[restore.index("verify_veth_pair || fail 'cleanup-veth-identity'", first_bpf) :]
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

    cleanup = function_body(runner, "render_cleanup_intent")
    for receipt in ("VETH", "ADDRESS", "ROUTE", "NEIGHBOR", "OFFLOAD", "MODULE"):
        if f'"${{{receipt}_PHASE}}"' not in cleanup:
            fail(f"cleanup intent does not bind {receipt} receipt")

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
