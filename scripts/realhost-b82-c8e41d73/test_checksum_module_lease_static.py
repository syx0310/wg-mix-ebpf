#!/usr/bin/env python3
"""Static and failure-cut contract for the shared c8 checksum-module lease."""

from __future__ import annotations

import copy
import dataclasses
import pathlib
import re
import sys


def fail(message: str) -> None:
    raise SystemExit(message)


def read_regular(path_text: str) -> str:
    path = pathlib.Path(path_text)
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        fail(f"input is not an absolute regular file: {path}")
    return path.read_text(encoding="utf-8")


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
    """The helper rejected foreign or ambiguous module state."""


class Cut(RuntimeError):
    """The process stopped after one durable lifecycle point."""


@dataclasses.dataclass
class Lease:
    locked: bool = True
    intent: bool = False
    owned: bool = False
    unloaded: bool = False
    live: str = "absent"  # absent, ours, foreign, empty-lease


def checkpoint(name: str, cut_after: str | None) -> None:
    if name == cut_after:
        raise Cut(name)


def load(state: Lease, insmod_rc: int = 0, cut_after: str | None = None) -> None:
    if not state.locked:
        raise Rejected("lock")
    if state.owned and not state.unloaded and state.live == "ours":
        return
    if state.intent or state.owned or state.unloaded or state.live != "absent":
        raise Rejected("load-requires-restore")
    state.intent = True
    checkpoint("intent", cut_after)
    if state.live != "absent":
        raise Rejected("appeared-after-intent")
    if insmod_rc != 0:
        raise Rejected("insmod-not-owned")
    state.live = "ours"
    checkpoint("insmod-rc0", cut_after)
    state.owned = True
    checkpoint("owned-receipt", cut_after)


def restore(state: Lease, cut_after: str | None = None) -> None:
    if not state.locked:
        raise Rejected("lock")
    if state.unloaded:
        if state.live != "absent" or not state.intent:
            raise Rejected("restored-drift")
        return
    if not state.intent:
        if state.owned or state.live != "absent":
            raise Rejected("foreign-without-intent")
        return
    if state.live in {"foreign", "empty-lease"}:
        raise Rejected("lease-identity")
    if state.live == "ours":
        state.live = "absent"
        checkpoint("rmmod", cut_after)
    elif state.live != "absent":
        raise Rejected("live-identity")
    state.unloaded = True
    checkpoint("unloaded-receipt", cut_after)


def exercise_model() -> None:
    for cut in ("intent", "insmod-rc0", "owned-receipt"):
        state = Lease()
        try:
            load(state, cut_after=cut)
        except Cut:
            pass
        else:
            fail(f"load cut did not fire: {cut}")
        restore(state)
        if state.live != "absent" or not state.unloaded:
            fail(f"load cut did not restore: {cut}: {state}")

    # 00, 10, 11 and 01 are all explicit and convergent for our exact token.
    fixtures = {
        "00": Lease(),
        "10": Lease(intent=True, live="ours"),
        "11": Lease(intent=True, owned=True, live="ours"),
        "01": Lease(intent=True, owned=True, live="absent"),
    }
    for name, state in fixtures.items():
        restore(state)
        if state.live != "absent" or (name != "00" and not state.unloaded):
            fail(f"failure-cut state {name} did not converge: {state}")

    for foreign in ("foreign", "empty-lease"):
        state = Lease(intent=True, live=foreign)
        try:
            restore(state)
        except Rejected:
            if state.live != foreign or state.unloaded:
                fail(f"foreign generation was mutated before rejection: {state}")
        else:
            fail(f"restore accepted {foreign} generation")

    # EEXIST/any nonzero insmod result never produces an owned receipt.
    failed = Lease()
    try:
        load(failed, insmod_rc=17)
    except Rejected:
        if failed.owned or failed.live != "absent" or not failed.intent:
            fail(f"failed insmod created ownership: {failed}")
    else:
        fail("failed insmod was accepted")

    complete = Lease()
    load(complete)
    replay = copy.deepcopy(complete)
    load(replay)
    if replay != complete:
        fail(f"exact owned receipt replay mutated state: {replay}")
    for cut in ("rmmod", "unloaded-receipt"):
        state = copy.deepcopy(complete)
        try:
            restore(state, cut_after=cut)
        except Cut:
            pass
        else:
            fail(f"restore cut did not fire: {cut}")
        restore(state)
        if state.live != "absent" or not state.unloaded:
            fail(f"restore cut did not converge: {cut}: {state}")


def inspect(helper: str, module: str) -> None:
    for pattern in (
        r"\brm\s+-[^\n]*r",
        r"\bfind\b[^\n]*-delete",
        r"\beval\b",
        r"\b(?:sh|bash)\s+-c\b",
        r"\btrap\b",
        r"\|\|\s*true",
        r">\s*/dev/null",
    ):
        if re.search(pattern, helper):
            fail(f"helper contains prohibited pattern {pattern}")

    for literal in (
        "readonly C8_CHECKSUM_MODULE_RUN_ID='c8e41d73'",
        "checksum-module-lease.v1.lock",
        "C8_CHECKSUM_MODULE_CENTRAL_OBJECT",
        "C8_CHECKSUM_MODULE_FRESH_OBJECT",
        "C8_CHECKSUM_MODULE_FRESH_EVIDENCE",
        'C8_CHECKSUM_MODULE_STAGE_ROOT}/realhost-v6-${C8_CHECKSUM_MODULE_RESOURCE_ID}',
        'C8_CHECKSUM_MODULE_STAGE_ROOT}/routed-evidence-${C8_CHECKSUM_MODULE_RESOURCE_ID}',
        "/run/wg-mix-ebpf-faketcp-verifier/fresh-c8e41d73",
        "/usr/bin/flock --exclusive --nonblock",
        "ownership=exact-insmod-rc0-only",
        '"${C8_CHECKSUM_MODULE_PARAMETER}=${C8_CHECKSUM_MODULE_LEASE_ID}"',
        "10-unreceipted-live",
        "11-owned-live",
        "01-owned-live-absent",
        "c8_checksum_module_validate_owned_receipt",
        "c8_checksum_module_validate_unloaded_receipt",
        "btf_sha256=",
        "restore-generation-changed",
    ):
        if literal not in helper:
            fail(f"helper is missing {literal!r}")

    load_body = function_body(helper, "c8_checksum_module_load")
    intent_write = load_body.index('c8_checksum_module_write "${C8_CHECKSUM_MODULE_INTENT}"')
    load_call = load_body.index("/usr/sbin/insmod", intent_write)
    rc_gate = load_body.index("((rc == 0))", load_call)
    live_identity = load_body.index("c8_checksum_module_read_live", rc_gate)
    owned_write = load_body.index('c8_checksum_module_write "${C8_CHECKSUM_MODULE_OWNED}"', live_identity)
    if [intent_write, load_call, rc_gate, live_identity, owned_write] != sorted(
        [intent_write, load_call, rc_gate, live_identity, owned_write]
    ):
        fail("intent/insmod/rc0/generation/receipt order drifted")
    if "C8_CHECKSUM_MODULE_OWNED" in load_body[intent_write:rc_gate]:
        fail("owned receipt is reachable before exact insmod rc=0")
    if "adopt" in helper.lower():
        fail("helper contains an adoption path")

    restore_body = function_body(helper, "c8_checksum_module_restore")
    for literal in (
        "c8_checksum_module_read_live",
        "c8_checksum_module_render_owned",
        "restore-refcount",
        "restore-generation-changed",
        "/usr/sbin/rmmod",
        'c8_checksum_module_write "${C8_CHECKSUM_MODULE_UNLOADED}"',
    ):
        if literal not in restore_body:
            fail(f"restore is missing {literal!r}")
    if restore_body.index("restore-generation-changed") > restore_body.index("/usr/sbin/rmmod"):
        fail("restore mutates before exact generation recheck")

    for literal in (
        "#define WG_MIX_FAKETCP_LEASE_ID_LENGTH 17U",
        "module_param_string(lease_id, lease_id, sizeof(lease_id), 0444);",
        "if (!lease_id[0])",
        "lease_id[8] != '-'",
        "lease_id[index] >= 'a' && lease_id[index] <= 'f'",
        "if (!wg_mix_faketcp_valid_lease_id())",
        "return -EINVAL;",
    ):
        if literal not in module:
            fail(f"module lease ABI is missing {literal!r}")


def main() -> None:
    if len(sys.argv) != 3:
        fail("usage: test_checksum_module_lease_static.py HELPER MODULE_SOURCE")
    helper = read_regular(sys.argv[1])
    module = read_regular(sys.argv[2])
    inspect(helper, module)
    exercise_model()
    print("shared checksum-module lease static and 00/10/11/01 failure-cut model: PASS")


if __name__ == "__main__":
    main()
