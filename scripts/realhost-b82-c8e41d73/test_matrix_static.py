#!/usr/bin/env python3
"""Static safety checks for the v6 real-host matrix and iperf checker."""

from __future__ import annotations

import importlib.util
import pathlib
import re
import sys
from types import ModuleType


def fail(message: str) -> None:
    raise SystemExit(message)


def load_checker(path: pathlib.Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location("reviewed_realhost_checker", path)
    if spec is None or spec.loader is None:
        fail("cannot load iperf checker")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def iperf_fixture(streams: int = 4) -> dict[str, object]:
    rows = []
    for _ in range(streams):
        rows.append(
            {
                "sender": {
                    "sender": True,
                    "bytes": 14_480_000,
                    "retransmits": 0,
                },
                "receiver": {"sender": True, "bytes": 14_480_000},
            }
        )
    return {
        "start": {
            "test_start": {
                "num_streams": streams,
                "reverse": 0,
                "bidir": 0,
                "duration": 10,
            }
        },
        "end": {
            "streams": rows,
            "sum_sent": {
                "bytes": 14_480_000 * streams,
                "retransmits": 0,
                "seconds": 10.0,
            },
            "sum_received": {
                "bytes": 14_480_000 * streams,
                "seconds": 10.0,
            },
        },
    }


def main() -> None:
    if len(sys.argv) != 3:
        fail("usage: test_matrix_static.py ROOT_MATRIX IPERF_CHECKER")
    matrix_path = pathlib.Path(sys.argv[1])
    checker_path = pathlib.Path(sys.argv[2])
    if not matrix_path.is_absolute() or not checker_path.is_absolute():
        fail("review paths must be absolute")
    matrix = matrix_path.read_text(encoding="utf-8")
    checker = checker_path.read_text(encoding="utf-8")

    def integer_constant(name: str) -> int:
        match = re.search(rf"^readonly {re.escape(name)}=([0-9]+)$", matrix, re.MULTILINE)
        if not match:
            fail(f"matrix integer constant is missing: {name}")
        return int(match.group(1))

    required_literals = (
        "readonly RUN_ID='c8e41d73'",
        "readonly PACKAGE_ID='4f2a9b61'",
        "readonly EVIDENCE_ID='6bd913ac'",
        "valid_commit \"${COMMIT}\"",
        "valid_sha256 \"${BUNDLE_SHA256}\"",
        "TestBPFFSPinLifecycleIntegration",
        "TestFakeTCPBPFPacketProbe",
        "TestExperimentalFakeTCPRealHostLifecycleIntegration",
        "TestFakeTCPRealHostXORTypewordHeaderCompositionIntegration",
        "TestBaselineExperimentalRealHostMutualExclusionIntegration",
        "WG_MIX_FAKETCP_REALHOST_XDP_MODE=generic",
        "TestScopedRealNICContextIsolationContract",
        "TestScopedRealNICDataplaneActiveIntegration",
        "TestScopedRealNICDataplaneRestoreIntegration",
        'WG_MIX_EBPF_TEST_RUNTIME_ROOT="${TCX_RUNTIME_ROOT}"',
        'WG_MIX_EBPF_TEST_PIN_LOCK_ROOT="${TCX_RUNTIME_ROOT}/locks"',
        'WG_MIX_EBPF_TEST_PIN_OWNER_ROOT="${TCX_RUNTIME_ROOT}/owners"',
        'WG_MIX_EBPF_TEST_INITIAL_NETNS="${INITIAL_NETNS}"',
        "WG_MIX_EBPF_TEST_ACTION=run",
        "WG_MIX_EBPF_TEST_ACTION=restore",
        "WG_MIX_EBPF_TEST_FAILURE_POLICY=retain",
        "SCOPED_BPFFS_COMPLETE restored=1",
        "SCOPED_BPFFS_RESTORE_COMPLETE restored=1",
        "WG_MIX_EBPF_SCOPED_REALNIC_ACTION=run",
        "WG_MIX_EBPF_SCOPED_REALNIC_ACTION=restore",
        'WG_MIX_EBPF_SCOPED_REALNIC_RUN_ID="${RUN_ID}"',
        'WG_MIX_EBPF_SCOPED_REALNIC_CELL="${cell}"',
        'WG_MIX_EBPF_SCOPED_REALNIC_PROFILE="${profile}"',
        'WG_MIX_EBPF_SCOPED_REALNIC_SOURCE_COMMIT="${COMMIT}"',
        'WG_MIX_EBPF_SCOPED_REALNIC_BUNDLE_SHA256="${BUNDLE_SHA256}"',
        'WG_MIX_EBPF_SCOPED_REALNIC_OBJECT="${SOURCE}/build/wg_mix_tc.o"',
        'WG_MIX_EBPF_SCOPED_REALNIC_ROOT="${scope}"',
        "WG_MIX_EBPF_SCOPED_REALNIC_TC_ATTACH=tcx",
        "WG_MIX_EBPF_SCOPED_REALNIC_TYPEWORD_MODE=identity",
        "WG_MIX_EBPF_SCOPED_REALNIC_TRANSPORT=udp",
        "WG_MIX_EBPF_SCOPED_REALNIC_CIPHER=none",
        "WG_MIX_EBPF_SCOPED_REALNIC_FAILURE_POLICY=retain",
        'WG_MIX_EBPF_SCOPED_REALNIC_LEASE_ROOT="${scope}/lease"',
        'WG_MIX_EBPF_SCOPED_REALNIC_OWNER_ROOT="${scope}/owners"',
        'WG_MIX_EBPF_SCOPED_REALNIC_STATE_ROOT="${scope}/state"',
        'WG_MIX_EBPF_SCOPED_REALNIC_EVIDENCE_ROOT="${scope}/evidence"',
        'WG_MIX_EBPF_SCOPED_REALNIC_PIN_PATH="${pin}"',
        'WG_MIX_EBPF_SCOPED_REALNIC_INITIAL_NETNS="${INITIAL_NETNS}"',
        'WG_MIX_EBPF_SCOPED_REALNIC_INTERFACE="${INTERFACE}"',
        'WG_MIX_EBPF_SCOPED_REALNIC_INTERFACE_IFINDEX="${ORIGINAL_IFINDEX}"',
        'WG_MIX_EBPF_SCOPED_REALNIC_INTERFACE_MAC="${ORIGINAL_MAC}"',
        'WG_MIX_EBPF_SCOPED_REALNIC_WG_INTERFACE="${WG_INTERFACE}"',
        'WG_MIX_EBPF_SCOPED_REALNIC_WG_LOCAL_ADDRESS="${WG_LOCAL_ADDRESS}"',
        'WG_MIX_EBPF_SCOPED_REALNIC_WG_PEER_ADDRESS="${WG_PEER_ADDRESS}"',
        'WG_MIX_EBPF_SCOPED_REALNIC_PEER_PORT="${PEER_PORT}"',
        'WG_MIX_EBPF_SCOPED_REALNIC_IPERF_CHECKER="${SOURCE}/scripts/realhost-b82-${RUN_ID}/check-realhost-iperf.py"',
        'WG_MIX_EBPF_SCOPED_REALNIC_STREAMS="${streams}"',
        'WG_MIX_EBPF_SCOPED_REALNIC_DIRECTIONS="${directions}"',
        'WG_MIX_EBPF_SCOPED_REALNIC_PASSES="${passes}"',
        'WG_MIX_EBPF_SCOPED_REALNIC_SESSION_SECONDS="${traffic_seconds}"',
        'WG_MIX_EBPF_SCOPED_REALNIC_SOAK_SECONDS="${SOAK_SECONDS}"',
        'WG_MIX_EBPF_SCOPED_REALNIC_SOAK_WINDOWS="${windows}"',
        "WG_MIX_EBPF_SCOPED_REALNIC_PING_INTERVAL_SECONDS=1",
        "WG_MIX_EBPF_SCOPED_REALNIC_MONITOR_INTERVAL_SECONDS=10",
        "WG_MIX_EBPF_SCOPED_REALNIC_MONITOR_SAMPLES=360",
        "SCOPED_REALNIC_COMPLETE cell=${cell} restored=1",
        "SCOPED_REALNIC_RESTORE_COMPLETE cell=${cell} restored=1",
        "verify_scoped_kernel_restored",
        "valid_interface_name",
        "valid_unicast_ipv4",
        "bootstrap_run_step",
        "create_bootstrap_audit_log",
        "verify_full_feature_restore",
        '/usr/bin/cmp -s "${EVIDENCE_ROOT}/A7.out" "${STEP_LOG}"',
        "REALHOST_V6_STOP",
        "no automatic teardown",
    )
    for literal in required_literals:
        if literal not in matrix:
            fail(f"matrix contract is missing {literal!r}")
    for literal in (
        "stats-contrast",
        "--require-egress",
        "--require-ingress",
        "OBSERVATION_COUNTERS",
        "HARD_ERROR_COUNTERS",
        "first_hour_throughput_baseline",
        "soak_group_totals",
        '"sent_bytes": sum(sent)',
    ):
        if literal not in checker:
            fail(f"checker contract is missing {literal!r}")
    for literal in ("owner-snapshot", "OWNER_ROOT"):
        if literal in checker:
            fail(f"checker unexpectedly contains lifecycle ownership command {literal!r}")

    forbidden_patterns = {
        "recursive remove": r"\brm\s+-[^\n]*r",
        "find deletion": r"\bfind\b[^\n]*-delete",
        "batch remover": r"\bxargs\b[^\n]*\brm\b",
        "sync deletion": r"\brsync\b[^\n]*--delete",
        "host root transition": r"\b(chroot|nsenter)\b",
        "container escape": r"\b(docker|podman)\b",
        "cleanup signal handler": r"\btrap\b",
        "dynamic evaluation": r"\beval\b",
        "host-root alias": r"/host(?:/|\b)",
        "error suppression": r"\|\|\s*true\b",
        "unbounded loop": r"\bwhile\s+true\b|\bfor\s*\(\s*;\s*;",
    }
    for label, pattern in forbidden_patterns.items():
        if re.search(pattern, matrix):
            fail(f"matrix contains forbidden {label}")

    if re.search(r"(?:^|\s)(?:mount|umount)(?:\s|$)", matrix, re.MULTILINE):
        fail("matrix must not create or remove mounts")
    if "192.168.10.28" in matrix + checker:
        fail("retired host appears in v6 scripts")
    if re.search(r"/usr/bin/wg[^\n]*(?:\bdump\b|private-key|preshared-key)", matrix):
        fail("matrix reads a WireGuard secret-bearing field")
    all_interface_wg = re.compile(r"/usr/bin/wg\s+show\s+all(?:\s|$)")
    if not all_interface_wg.search("/usr/bin/wg show all peers"):
        fail("internal all-interface WireGuard detector fixture did not match")
    if all_interface_wg.search(matrix):
        fail("matrix reads WireGuard state outside the exact reviewed interface")
    wg_show_targets = re.findall(r"/usr/bin/wg\s+show\s+([^\s;\\]+)", matrix)
    if not wg_show_targets or set(wg_show_targets) != {'"${WG_INTERFACE}"'}:
        fail("every WireGuard snapshot must name the exact reviewed interface")
    for selector in (
        "public-key",
        "listen-port",
        "fwmark",
        "peers",
        "endpoints",
        "allowed-ips",
        "latest-handshakes",
        "transfer",
    ):
        literal = f'/usr/bin/wg show "${{WG_INTERFACE}}" {selector}'
        if literal not in matrix:
            fail(f"matrix exact-interface WireGuard selector is missing: {selector}")
    for production_root in ("/run/wg-mix-ebpf/daemon.lease", "/var/lib/wg-mix-ebpf"):
        if production_root in matrix + checker:
            fail(f"production lifecycle root appears in scoped test scripts: {production_root}")
    if re.search(r"\btc\s+qdisc\s+(?:add|delete|del)\b", matrix):
        fail("matrix manually creates or removes clsact despite TCX contract")
    if '>>"${NIC_STATE}"' in matrix or '>"${NIC_STATE}"' in matrix:
        fail("NIC state is written incrementally outside audited write_once")
    if 'write_once "${NIC_STATE}" "${records[@]}"' not in matrix:
        fail("NIC state is not materialized by one audited exclusive write")
    if matrix.count('verify_full_feature_restore "${prefix}"') != 1:
        fail("every NIC restoration must end in one complete offload comparison")
    if "FINAL_INTEGRATION_COMMIT_REQUIRED" in matrix:
        fail("matrix embeds a source-commit placeholder instead of requiring argv")
    if "COMMIT='c8e41d73'" in matrix:
        fail("run ID is incorrectly used as a source commit")

    matrix_minimum = (
        3
        * 3
        * integer_constant("MATRIX_TRAFFIC_SECONDS")
        * integer_constant("MATRIX_PASSES")
    )
    matrix_go = integer_constant("MATRIX_GO_TIMEOUT_SECONDS")
    matrix_outer = integer_constant("MATRIX_OUTER_TIMEOUT_SECONDS")
    if matrix_go < matrix_minimum + 60 or matrix_outer < matrix_go + 30:
        fail("matrix Go/outer timeout cannot contain the reviewed 9-group two-pass budget")
    mtu_minimum = integer_constant("MTU_TRAFFIC_SECONDS") * integer_constant("MTU_PASSES")
    mtu_go = integer_constant("MTU_GO_TIMEOUT_SECONDS")
    mtu_outer = integer_constant("MTU_OUTER_TIMEOUT_SECONDS")
    if mtu_go < mtu_minimum + 60 or mtu_outer < mtu_go + 30:
        fail("MTU Go/outer timeout cannot contain the reviewed active-control budget")
    soak_minimum = integer_constant("SOAK_WINDOWS") * 300
    soak_go = integer_constant("SOAK_GO_TIMEOUT_SECONDS")
    soak_outer = integer_constant("SOAK_OUTER_TIMEOUT_SECONDS")
    if "readonly EXPECTED_SESSION_SECONDS='300'" not in matrix:
        fail("soak session duration is not fixed to 300 seconds")
    if soak_minimum != 3600 or soak_go < soak_minimum + 60 or soak_outer < soak_go + 30:
        fail("soak Go/outer timeout cannot contain exactly twelve five-minute windows")

    checker_module = load_checker(checker_path)
    fixture = iperf_fixture()
    checker_module.expected_direction(fixture, "forward", 4, 10)
    groups = checker_module.measured_groups(fixture, "forward", 4, 10, 0.5, 0.99)
    if (
        len(groups) != 1
        or groups[0]["sent_bytes"] != 57_920_000
        or groups[0]["received_bytes"] != 57_920_000
    ):
        fail("iperf positive fixture was not measured exactly")
    fixture["end"]["streams"][0]["sender"]["retransmits"] = 1000  # type: ignore[index]
    fixture["end"]["sum_sent"]["retransmits"] = 1000  # type: ignore[index]
    groups = checker_module.measured_groups(fixture, "forward", 4, 10, 0.5, 0.99)
    if groups[0]["retransmit_rate"] <= 0.0001:
        fail("iperf retransmit fixture did not exceed the acceptance threshold")

    before = {
        name: 0
        for name in (
            *checker_module.OBSERVATION_COUNTERS,
            *checker_module.HARD_ERROR_COUNTERS,
        )
    }
    before.update({"egress_rewrite_ok": 10, "ingress_rewrite_ok": 20})
    after = dict(before)
    after["egress_rewrite_ok"] += 2
    after["ingress_rewrite_ok"] += 3
    after["egress_rule_miss"] += 5
    after["ingress_rule_miss"] += 7
    deltas = checker_module.counter_deltas(
        before,
        after,
        require_egress=True,
        require_ingress=True,
        forbid_rewrite_growth=False,
    )
    if deltas["egress_rewrite_ok"] != 2 or deltas["ingress_rewrite_ok"] != 3:
        fail("program-active counter fixture was not measured exactly")
    if deltas["egress_rule_miss"] != 5 or deltas["ingress_rule_miss"] != 7:
        fail("rule-miss observation fixture was not retained exactly")
    try:
        checker_module.counter_deltas(
            before,
            after,
            require_egress=False,
            require_ingress=False,
            forbid_rewrite_growth=True,
        )
    except checker_module.CheckError:
        pass
    else:
        fail("bare-control rewrite growth was accepted")
    error_after = dict(before)
    error_after[checker_module.HARD_ERROR_COUNTERS[0]] = 1
    try:
        checker_module.counter_deltas(
            before,
            error_after,
            require_egress=False,
            require_ingress=False,
            forbid_rewrite_growth=False,
        )
    except checker_module.CheckError:
        pass
    else:
        fail("dataplane error-counter growth was accepted")

    sender_denominator = checker_module.soak_group_totals(
        [
            {
                "sent_bytes": 14_480,
                "received_bytes": 1_448,
                "throughput_mbps": 1.0,
                "retransmits": 5,
                "minimum_stream_delivery_ratio": 0.1,
            }
        ]
    )
    if (
        sender_denominator["estimated_segments"] != 10
        or sender_denominator["retransmit_rate"] != 0.5
    ):
        fail("soak retransmits were not normalized by sender bytes")

    first_hour = [
        {"throughput_mbps": 10.0, "window": index}
        for index in range(3)
    ] + [
        {"throughput_mbps": 100.0, "window": index}
        for index in range(3, 12)
    ]
    try:
        checker_module.first_hour_throughput_baseline(first_hour, 0.70)
    except checker_module.CheckError:
        pass
    else:
        fail("three slow opening windows bypassed the full first-hour median")
    baseline, floor = checker_module.first_hour_throughput_baseline(
        [{"throughput_mbps": 100.0, "window": index} for index in range(12)],
        0.70,
    )
    if baseline != 100.0 or floor != 70.0:
        fail("first-hour twelve-window median fixture was not measured exactly")

    print("static real-host safety and checker fixtures: PASS")


if __name__ == "__main__":
    main()
