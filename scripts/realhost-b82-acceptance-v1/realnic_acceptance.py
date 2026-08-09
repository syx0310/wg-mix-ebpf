#!/usr/bin/env python3
"""Review-locked real-NIC characterization and acceptance harness.

``plan`` performs read-only inspection and emits a canonical JSON plan.  The
mutating ``run`` and ``restore`` modes are intentionally implemented below but
will only accept the exact plan bytes and SHA-256 reviewed by an operator.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import ipaddress
import json
import os
import re
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


SCHEMA = "wg-mix-ebpf-b82-realnic-acceptance-plan-v1"
JOURNAL_SCHEMA = "wg-mix-ebpf-b82-realnic-acceptance-journal-v1"
READ_ONLY_PEER = "47.116.202.155"
RUN_ROOT_PREFIX = "/run/wg-mix-ebpf-realnic-acceptance-"
RUN_ID_RE = re.compile(r"^[0-9a-f]{8,32}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
IFNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$")
DRIVER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
MAC_RE = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)

TOOLS = {
    "bpftool": "/usr/sbin/bpftool",
    "cat": "/usr/bin/cat",
    "ethtool": "/usr/sbin/ethtool",
    "hostname": "/usr/bin/hostname",
    "ip": "/usr/sbin/ip",
    "iperf3": "/usr/bin/iperf3",
    "ping": "/usr/bin/ping",
    "readlink": "/usr/bin/readlink",
    "stat": "/usr/bin/stat",
    "tc": "/usr/sbin/tc",
    "timeout": "/usr/bin/timeout",
    "uname": "/usr/bin/uname",
    "wg": "/usr/bin/wg",
}

FEATURE_ORDER = (
    "rx-checksumming",
    "tx-checksumming",
    "generic-segmentation-offload",
    "generic-receive-offload",
    "tcp-segmentation-offload",
    "tx-udp-segmentation",
    "rx-udp-gro-forwarding",
)

TX_FEATURES = frozenset(
    {
        "tx-checksumming",
        "generic-segmentation-offload",
        "tcp-segmentation-offload",
        "tx-udp-segmentation",
    }
)
RX_FEATURES = frozenset(
    {"rx-checksumming", "generic-receive-offload", "rx-udp-gro-forwarding"}
)


class HarnessError(RuntimeError):
    """Fail-closed harness error."""


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def nontrivial_hex(value: str, pattern: re.Pattern[str], label: str) -> str:
    if not pattern.fullmatch(value) or len(set(value)) == 1:
        raise HarnessError(f"{label} must be nontrivial lowercase hexadecimal")
    return value


def clean_single_line(value: str, label: str) -> str:
    if not value or value.strip() != value or "\n" in value or "\r" in value or "\x00" in value:
        raise HarnessError(f"{label} must be one canonical nonempty line")
    return value


@dataclasses.dataclass(frozen=True)
class CoreSpec:
    run_id: str
    run_root: str
    source_commit: str
    interface: str
    expected_ifindex: int
    expected_mac: str
    expected_driver: str
    expected_bus_info: str
    expected_device_path: str
    expected_device_dev: int
    expected_device_ino: int
    expected_mtu: int
    expected_hostname: str
    expected_kernel: str
    expected_machine_id: str
    expected_boot_id: str
    peer_address: str
    peer_port: int
    traffic_seconds: int
    soak_seconds: int
    soak_window_seconds: int
    mtu_low: int

    def validate(self) -> "CoreSpec":
        nontrivial_hex(self.run_id, RUN_ID_RE, "run-id")
        expected_root = f"{RUN_ROOT_PREFIX}{self.run_id}"
        if self.run_root != expected_root:
            raise HarnessError(f"run-root must be exactly {expected_root}")
        nontrivial_hex(self.source_commit, COMMIT_RE, "source-commit")
        if not IFNAME_RE.fullmatch(self.interface) or self.interface in {"lo", ".", ".."}:
            raise HarnessError("interface is not a valid explicit real interface")
        if self.expected_ifindex <= 0:
            raise HarnessError("expected-ifindex must be positive")
        if not MAC_RE.fullmatch(self.expected_mac):
            raise HarnessError("expected-mac must be canonical lowercase")
        first_octet = int(self.expected_mac[:2], 16)
        if first_octet & 1:
            raise HarnessError("expected-mac must be unicast")
        if not DRIVER_RE.fullmatch(self.expected_driver):
            raise HarnessError("expected-driver is invalid")
        clean_single_line(self.expected_bus_info, "expected-bus-info")
        if not self.expected_device_path.startswith("/sys/devices/"):
            raise HarnessError("expected-device-path must be an absolute /sys/devices path")
        if os.path.normpath(self.expected_device_path) != self.expected_device_path:
            raise HarnessError("expected-device-path must be normalized")
        if self.expected_device_dev <= 0 or self.expected_device_ino <= 0:
            raise HarnessError("expected device dev/inode must be positive")
        if not 1280 <= self.expected_mtu <= 9216:
            raise HarnessError("expected-mtu is outside the reviewed range")
        if not 1280 <= self.mtu_low < self.expected_mtu:
            raise HarnessError("mtu-low must be at least 1280 and below expected-mtu")
        clean_single_line(self.expected_hostname, "expected-hostname")
        clean_single_line(self.expected_kernel, "expected-kernel")
        nontrivial_hex(self.expected_machine_id, re.compile(r"^[0-9a-f]{32}$"), "expected-machine-id")
        if not UUID_RE.fullmatch(self.expected_boot_id):
            raise HarnessError("expected-boot-id must be a canonical UUID")
        try:
            peer = ipaddress.ip_address(self.peer_address)
        except ValueError as exc:
            raise HarnessError("peer-address is invalid") from exc
        if peer.version != 4 or str(peer) != READ_ONLY_PEER:
            raise HarnessError(f"peer-address must be the read-only endpoint {READ_ONLY_PEER}")
        if self.peer_port != 5201:
            raise HarnessError("peer-port must be 5201")
        if not 5 <= self.traffic_seconds <= 60:
            raise HarnessError("traffic-seconds must be in [5,60]")
        if not 60 <= self.soak_seconds <= 3600:
            raise HarnessError("soak-seconds must be in [60,3600]")
        if not 10 <= self.soak_window_seconds <= 300:
            raise HarnessError("soak-window-seconds must be in [10,300]")
        if self.soak_seconds % self.soak_window_seconds:
            raise HarnessError("soak-seconds must be exactly divisible by soak-window-seconds")
        return self

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


class CommandRunner:
    """Runs fixed argv only; shell evaluation is deliberately unavailable."""

    def capture(self, argv: Sequence[str], timeout: int = 20) -> tuple[int, bytes, bytes]:
        if not argv or not os.path.isabs(argv[0]):
            raise HarnessError("every command must use an absolute executable path")
        try:
            result = subprocess.run(
                list(argv),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=timeout,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise HarnessError(f"command did not complete: {argv!r}: {exc}") from exc
        return result.returncode, result.stdout, result.stderr


def snapshot_command_table(spec: CoreSpec) -> list[tuple[str, list[str]]]:
    sysfs = f"/sys/class/net/{spec.interface}"
    return [
        ("hostname", [TOOLS["hostname"]]),
        ("kernel", [TOOLS["uname"], "-r"]),
        ("machine_id", [TOOLS["cat"], "/etc/machine-id"]),
        ("boot_id", [TOOLS["cat"], "/proc/sys/kernel/random/boot_id"]),
        ("netns", [TOOLS["readlink"], "/proc/self/ns/net"]),
        ("ifindex", [TOOLS["cat"], f"{sysfs}/ifindex"]),
        ("mac", [TOOLS["cat"], f"{sysfs}/address"]),
        ("mtu", [TOOLS["cat"], f"{sysfs}/mtu"]),
        ("device_path", [TOOLS["readlink"], "-e", f"{sysfs}/device"]),
        ("device_stat", [TOOLS["stat"], "-Lc", "%d:%i", f"{sysfs}/device"]),
        ("driver", [TOOLS["ethtool"], "-i", spec.interface]),
        ("features", [TOOLS["ethtool"], "-k", spec.interface]),
        ("link", [TOOLS["ip"], "-d", "-j", "link", "show", "dev", spec.interface]),
        ("addresses", [TOOLS["ip"], "-j", "address", "show", "dev", spec.interface]),
        ("routes", [TOOLS["ip"], "-j", "route", "show", "table", "all", "dev", spec.interface]),
        ("peer_route", [TOOLS["ip"], "-j", "route", "get", spec.peer_address]),
        ("qdisc", [TOOLS["tc"], "-j", "qdisc", "show", "dev", spec.interface]),
        ("tc_ingress", [TOOLS["tc"], "-j", "filter", "show", "dev", spec.interface, "ingress"]),
        ("tc_egress", [TOOLS["tc"], "-j", "filter", "show", "dev", spec.interface, "egress"]),
        ("bpf_links", [TOOLS["bpftool"], "-j", "link", "show"]),
        ("bpf_programs", [TOOLS["bpftool"], "-j", "prog", "show"]),
        ("bpf_maps", [TOOLS["bpftool"], "-j", "map", "show"]),
        ("wg_interfaces", [TOOLS["wg"], "show", "interfaces"]),
        ("nic_stats", [TOOLS["ethtool"], "-S", spec.interface]),
    ]


def single_line(data: bytes, label: str) -> str:
    try:
        value = data.decode("utf-8").rstrip("\n")
    except UnicodeDecodeError as exc:
        raise HarnessError(f"{label} output is not UTF-8") from exc
    if "\n" in value or "\r" in value or not value:
        raise HarnessError(f"{label} did not return one nonempty line")
    return value


def parse_json_output(data: bytes, label: str) -> Any:
    try:
        return json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HarnessError(f"{label} did not return JSON") from exc


def stable_sort(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: stable_sort(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        normalized = [stable_sort(item) for item in value]
        return sorted(normalized, key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")))
    return value


def parse_key_values(data: bytes, label: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw in data.decode("utf-8").splitlines():
        if not raw.strip():
            continue
        if ":" not in raw:
            raise HarnessError(f"{label} has an unexpected line: {raw!r}")
        key, value = raw.split(":", 1)
        key, value = key.strip(), value.strip()
        if not key or key in result:
            raise HarnessError(f"{label} has a duplicate or empty key")
        result[key] = value
    return result


def parse_features(data: bytes) -> dict[str, dict[str, Any]]:
    features: dict[str, dict[str, Any]] = {}
    lines = data.decode("utf-8").splitlines()
    if not lines or not lines[0].startswith("Features for "):
        raise HarnessError("ethtool feature output has no header")
    pattern = re.compile(r"^\s*([a-z0-9][a-z0-9_-]*):\s+(on|off)(?:\s+\[fixed\])?\s*$")
    for raw in lines[1:]:
        match = pattern.fullmatch(raw)
        if not match:
            raise HarnessError(f"unparsed ethtool feature line: {raw!r}")
        name, value = match.groups()
        if name in features:
            raise HarnessError(f"duplicate ethtool feature: {name}")
        features[name] = {"enabled": value == "on", "fixed": "[fixed]" in raw}
    missing = sorted(set(FEATURE_ORDER) - set(features))
    if missing:
        raise HarnessError(f"required ethtool features are missing: {','.join(missing)}")
    return features


def normalize_bpf(items: Any, kind: str) -> list[dict[str, Any]]:
    if not isinstance(items, list):
        raise HarnessError(f"bpftool {kind} output is not an array")
    allowed = {
        "links": ("id", "type", "prog_id", "ifindex", "attach_type", "netns_ino"),
        "programs": ("id", "type", "name", "map_ids", "btf_id", "tag"),
        "maps": ("id", "type", "name", "key", "value", "max_entries", "btf_id"),
    }[kind]
    normalized = []
    for item in items:
        if not isinstance(item, dict):
            raise HarnessError(f"bpftool {kind} item is not an object")
        normalized.append({key: stable_sort(item[key]) for key in allowed if key in item})
    return stable_sort(normalized)


def nic_stat_keys(data: bytes) -> list[str]:
    keys: list[str] = []
    for raw in data.decode("utf-8").splitlines()[1:]:
        if ":" not in raw:
            continue
        key = raw.split(":", 1)[0].strip()
        if key:
            keys.append(key)
    return sorted(set(keys))


def collect_snapshot(spec: CoreSpec, runner: CommandRunner) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    raw: dict[str, bytes] = {}
    commands: list[dict[str, Any]] = []
    for label, argv in snapshot_command_table(spec):
        rc, stdout, stderr = runner.capture(argv)
        commands.append({"label": label, "argv": argv, "timeout_seconds": 20, "write_set": []})
        if rc != 0:
            detail = stderr.decode("utf-8", "replace").strip()
            raise HarnessError(f"read-only snapshot {label} failed rc={rc}: {detail}")
        raw[label] = stdout

    driver = parse_key_values(raw["driver"], "ethtool driver")
    stat_value = single_line(raw["device_stat"], "device-stat")
    try:
        device_dev, device_ino = (int(part) for part in stat_value.split(":"))
    except (ValueError, TypeError) as exc:
        raise HarnessError("device-stat is not decimal dev:inode") from exc

    snapshot = {
        "host": {
            "hostname": single_line(raw["hostname"], "hostname"),
            "kernel": single_line(raw["kernel"], "kernel"),
            "machine_id": single_line(raw["machine_id"], "machine-id"),
            "boot_id": single_line(raw["boot_id"], "boot-id"),
            "netns": single_line(raw["netns"], "netns"),
        },
        "interface_identity": {
            "name": spec.interface,
            "ifindex": int(single_line(raw["ifindex"], "ifindex")),
            "mac": single_line(raw["mac"], "mac"),
            "mtu": int(single_line(raw["mtu"], "mtu")),
            "driver": driver.get("driver", ""),
            "bus_info": driver.get("bus-info", ""),
            "device_path": single_line(raw["device_path"], "device-path"),
            "device_dev": device_dev,
            "device_ino": device_ino,
        },
        "features": parse_features(raw["features"]),
        "link": stable_sort(parse_json_output(raw["link"], "ip link")),
        "addresses": stable_sort(parse_json_output(raw["addresses"], "ip address")),
        "routes": stable_sort(parse_json_output(raw["routes"], "ip routes")),
        "peer_route": stable_sort(parse_json_output(raw["peer_route"], "peer route")),
        "qdisc": stable_sort(parse_json_output(raw["qdisc"], "tc qdisc")),
        "tc_ingress": stable_sort(parse_json_output(raw["tc_ingress"], "tc ingress")),
        "tc_egress": stable_sort(parse_json_output(raw["tc_egress"], "tc egress")),
        "bpf_links": normalize_bpf(parse_json_output(raw["bpf_links"], "bpf links"), "links"),
        "bpf_programs": normalize_bpf(parse_json_output(raw["bpf_programs"], "bpf programs"), "programs"),
        "bpf_maps": normalize_bpf(parse_json_output(raw["bpf_maps"], "bpf maps"), "maps"),
        "wg_interfaces": sorted(raw["wg_interfaces"].decode("utf-8").split()),
        "nic_stat_keys": nic_stat_keys(raw["nic_stats"]),
    }
    validate_snapshot_identity(spec, snapshot)
    return snapshot, commands


def validate_snapshot_identity(spec: CoreSpec, snapshot: Mapping[str, Any]) -> None:
    expected_host = {
        "hostname": spec.expected_hostname,
        "kernel": spec.expected_kernel,
        "machine_id": spec.expected_machine_id,
        "boot_id": spec.expected_boot_id,
    }
    host = snapshot["host"]
    for key, expected in expected_host.items():
        if host.get(key) != expected:
            raise HarnessError(f"host identity mismatch for {key}")
    if not re.fullmatch(r"net:\[[1-9][0-9]*\]", str(host.get("netns", ""))):
        raise HarnessError("initial network namespace identity is invalid")
    identity = snapshot["interface_identity"]
    expected_identity = {
        "name": spec.interface,
        "ifindex": spec.expected_ifindex,
        "mac": spec.expected_mac,
        "mtu": spec.expected_mtu,
        "driver": spec.expected_driver,
        "bus_info": spec.expected_bus_info,
        "device_path": spec.expected_device_path,
        "device_dev": spec.expected_device_dev,
        "device_ino": spec.expected_device_ino,
    }
    if identity != expected_identity:
        mismatches = [key for key, value in expected_identity.items() if identity.get(key) != value]
        raise HarnessError(f"interface identity mismatch: {','.join(mismatches)}")
    peer_routes = snapshot.get("peer_route")
    if not isinstance(peer_routes, list) or not peer_routes:
        raise HarnessError("peer route is empty")
    if not any(item.get("dev") == spec.interface for item in peer_routes if isinstance(item, dict)):
        raise HarnessError("peer route does not use the reviewed interface")


def feature_target(features: Mapping[str, Mapping[str, Any]], policy: str) -> dict[str, bool]:
    original = {name: bool(features[name]["enabled"]) for name in FEATURE_ORDER}
    if policy == "original":
        return original
    if policy == "all-on":
        return {name: True for name in FEATURE_ORDER}
    if policy == "all-off":
        return {name: False for name in FEATURE_ORDER}
    if policy == "tx-path":
        return {name: name in TX_FEATURES for name in FEATURE_ORDER}
    if policy == "rx-path":
        return {name: name in RX_FEATURES for name in FEATURE_ORDER}
    raise HarnessError(f"unknown feature policy {policy}")


def output_paths(root: str, label: str) -> tuple[str, str]:
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,95}", label):
        raise HarnessError(f"invalid command label {label!r}")
    base = f"{root}/logs/{label}"
    return f"{base}.stdout", f"{base}.stderr"


def command_step(root: str, label: str, argv: Sequence[str], timeout: int, expect: str = "zero") -> dict[str, Any]:
    stdout_path, stderr_path = output_paths(root, label)
    return {
        "label": label,
        "argv": list(argv),
        "timeout_seconds": timeout,
        "expect_rc": expect,
        "stdout": stdout_path,
        "stderr": stderr_path,
    }


def ethtool_steps(
    spec: CoreSpec,
    snapshot: Mapping[str, Any],
    policy: str,
    cell_name: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, bool], list[str]]:
    features = snapshot["features"]
    original = {name: bool(features[name]["enabled"]) for name in FEATURE_ORDER}
    requested = feature_target(features, policy)
    expected = dict(original)
    mutation: list[dict[str, Any]] = []
    unsupported: list[str] = []
    changed: list[str] = []
    for name in FEATURE_ORDER:
        desired = requested[name]
        if bool(features[name]["fixed"]):
            if original[name] != desired:
                unsupported.append(name)
            continue
        expected[name] = desired
        if original[name] == desired:
            continue
        changed.append(name)
        mutation.append(
            command_step(
                spec.run_root,
                f"{cell_name}.mutate.{len(mutation):02d}.{name}",
                [TOOLS["ethtool"], "-K", spec.interface, name, "on" if desired else "off"],
                20,
            )
        )
    restore: list[dict[str, Any]] = []
    for name in reversed(changed):
        restore.append(
            command_step(
                spec.run_root,
                f"{cell_name}.restore.{len(restore):02d}.{name}",
                [TOOLS["ethtool"], "-K", spec.interface, name, "on" if original[name] else "off"],
                20,
            )
        )
    return mutation, restore, expected, unsupported


def iperf_steps(spec: CoreSpec, cell_name: str) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    for streams in (1, 4, 16):
        for direction in ("forward", "reverse", "bidir"):
            argv = [
                TOOLS["timeout"],
                "--signal=TERM",
                "--kill-after=10s",
                f"{spec.traffic_seconds + 20}s",
                TOOLS["iperf3"],
                "-c",
                spec.peer_address,
                "-p",
                str(spec.peer_port),
                "--connect-timeout",
                "5000",
                "--json",
                "--omit",
                "2",
                "-t",
                str(spec.traffic_seconds),
                "-P",
                str(streams),
            ]
            if direction == "reverse":
                argv.append("-R")
            elif direction == "bidir":
                argv.append("--bidir")
            step = command_step(
                spec.run_root,
                f"{cell_name}.tcp.p{streams}.{direction}",
                argv,
                spec.traffic_seconds + 35,
            )
            step.update({"kind": "iperf", "streams": streams, "direction": direction})
            steps.append(step)
    return steps


def feature_cell(spec: CoreSpec, snapshot: Mapping[str, Any], name: str, policy: str) -> dict[str, Any]:
    mutation, restore, expected, unsupported = ethtool_steps(spec, snapshot, policy, name)
    return {
        "name": name,
        "kind": "tcp-offload",
        "runnable": True,
        "classification": "eligible" if not unsupported else "unsupported",
        "classification_reason": (
            "all requested mutable features can reach the reviewed state"
            if not unsupported
            else "fixed features prevent the complete requested state: " + ",".join(unsupported)
        ),
        "mutation": mutation,
        "restore": restore,
        "expected_primary_features": expected,
        "expected_mtu": spec.expected_mtu,
        "traffic": iperf_steps(spec, name),
        "evidence_limits": [
            "real TCP traffic and NIC feature configuration only",
            "does not prove skb CHECKSUM_NONE/PARTIAL at the FakeTCP transform",
            "does not prove FakeTCP GSO/GRO segmentation correctness",
        ],
    }


def ping_step(spec: CoreSpec, cell: str, mtu: int, positive: bool) -> dict[str, Any]:
    payload = mtu - 28 + (0 if positive else 1)
    label = f"{cell}.ping.{'positive' if positive else 'negative'}"
    return command_step(
        spec.run_root,
        label,
        [
            TOOLS["timeout"],
            "--signal=TERM",
            "--kill-after=5s",
            "15s",
            TOOLS["ping"],
            "-4",
            "-I",
            spec.interface,
            "-M",
            "do",
            "-c",
            "3" if positive else "1",
            "-W",
            "2",
            "-s",
            str(payload),
            spec.peer_address,
        ],
        20,
        "zero" if positive else "nonzero",
    )


def mtu_cell(spec: CoreSpec, name: str, target_mtu: int) -> dict[str, Any]:
    mutation: list[dict[str, Any]] = []
    restore: list[dict[str, Any]] = []
    if target_mtu != spec.expected_mtu:
        mutation.append(
            command_step(
                spec.run_root,
                f"{name}.mutate.mtu",
                [TOOLS["ip"], "link", "set", "dev", spec.interface, "mtu", str(target_mtu)],
                20,
            )
        )
        restore.append(
            command_step(
                spec.run_root,
                f"{name}.restore.mtu",
                [TOOLS["ip"], "link", "set", "dev", spec.interface, "mtu", str(spec.expected_mtu)],
                20,
            )
        )
    traffic = [ping_step(spec, name, target_mtu, True), ping_step(spec, name, target_mtu, False)]
    iperf = iperf_steps(spec, name)
    traffic.extend(step for step in iperf if step["streams"] == 4 and step["direction"] == "bidir")
    return {
        "name": name,
        "kind": "tcp-mtu-boundary",
        "runnable": True,
        "classification": "characterization",
        "classification_reason": "validates local real-NIC IPv4 MTU boundary and TCP transfer, not FakeTCP +12 PMTU",
        "mutation": mutation,
        "restore": restore,
        "expected_primary_features": None,
        "expected_mtu": target_mtu,
        "traffic": traffic,
        "evidence_limits": ["AF_PACKET/no-dst evidence is never used as positive PMTU evidence"],
    }


def soak_cell(spec: CoreSpec, snapshot: Mapping[str, Any]) -> dict[str, Any]:
    name = "tcp-soak-all-on"
    mutation, restore, expected, unsupported = ethtool_steps(spec, snapshot, "all-on", name)
    windows = spec.soak_seconds // spec.soak_window_seconds
    traffic: list[dict[str, Any]] = []
    ping = command_step(
        spec.run_root,
        f"{name}.ping",
        [
            TOOLS["timeout"],
            "--signal=TERM",
            "--kill-after=5s",
            f"{spec.soak_seconds + 5}s",
            TOOLS["ping"],
            "-4",
            "-I",
            spec.interface,
            "-i",
            "1",
            "-w",
            str(spec.soak_seconds),
            spec.peer_address,
        ],
        spec.soak_seconds + 15,
    )
    ping.update({"kind": "ping-monitor", "parallel_group": name})
    traffic.append(ping)
    for window in range(windows):
        argv = [
            TOOLS["timeout"],
            "--signal=TERM",
            "--kill-after=10s",
            f"{spec.soak_window_seconds + 20}s",
            TOOLS["iperf3"],
            "-c",
            spec.peer_address,
            "-p",
            str(spec.peer_port),
            "--connect-timeout",
            "5000",
            "--json",
            "--omit",
            "2",
            "-t",
            str(spec.soak_window_seconds),
            "-P",
            "4",
            "--bidir",
        ]
        step = command_step(
            spec.run_root,
            f"{name}.window.{window:03d}",
            argv,
            spec.soak_window_seconds + 35,
        )
        step.update({"kind": "iperf", "streams": 4, "direction": "bidir", "window": window})
        traffic.append(step)
    return {
        "name": name,
        "kind": "tcp-soak",
        "runnable": True,
        "classification": "eligible" if not unsupported else "unsupported",
        "classification_reason": (
            "bounded real-NIC TCP soak"
            if not unsupported
            else "fixed features prevent all-on soak state: " + ",".join(unsupported)
        ),
        "mutation": mutation,
        "restore": restore,
        "expected_primary_features": expected,
        "expected_mtu": spec.expected_mtu,
        "traffic": traffic,
        "windows": windows,
        "evidence_limits": ["soak covers raw TCP only until the FakeTCP real-NIC path is admitted"],
    }


def blocked_cells() -> list[dict[str, Any]]:
    reasons = {
        "faketcp-realnic-tcp-multiflow": "the current final keeps FakeTCP physical-E2E admission closed and the endpoint is read-only",
        "faketcp-checksum-none": "no admitted real-NIC producer proves skb CHECKSUM_NONE at the transform",
        "faketcp-checksum-partial": "no admitted real-NIC producer proves skb CHECKSUM_PARTIAL at the transform",
        "faketcp-gso-gro": "FakeTCP GSO/GRO admission remains closed; feature toggles alone are not packet-path proof",
        "faketcp-pmtu-boundary": "no routed positive PMTU evidence exists; AF_PACKET/no-dst is fail-closed",
        "faketcp-bounded-soak": "the prerequisite FakeTCP physical-E2E path is not admitted",
    }
    return [
        {
            "name": name,
            "kind": "required-faketcp-acceptance",
            "runnable": False,
            "classification": "not-covered",
            "classification_reason": reason,
            "mutation": [],
            "restore": [],
            "traffic": [],
        }
        for name, reason in reasons.items()
    ]


def build_plan(spec: CoreSpec, snapshot: Mapping[str, Any], snapshot_commands: list[dict[str, Any]]) -> dict[str, Any]:
    cells = [
        feature_cell(spec, snapshot, "tcp-original", "original"),
        feature_cell(spec, snapshot, "tcp-all-on", "all-on"),
        feature_cell(spec, snapshot, "tcp-all-off", "all-off"),
        feature_cell(spec, snapshot, "tcp-tx-path", "tx-path"),
        feature_cell(spec, snapshot, "tcp-rx-path", "rx-path"),
        mtu_cell(spec, "tcp-mtu-low", spec.mtu_low),
        mtu_cell(spec, "tcp-mtu-original", spec.expected_mtu),
        soak_cell(spec, snapshot),
    ]
    cells.extend(blocked_cells())
    files = {
        f"{spec.run_root}/owner.json",
        f"{spec.run_root}/approved-plan.json",
        f"{spec.run_root}/journal.jsonl",
        f"{spec.run_root}/baseline.json",
        f"{spec.run_root}/results.json",
        f"{spec.run_root}/complete.json",
        f"{spec.run_root}/explicit-restored.json",
    }
    for cell in cells:
        for group in ("mutation", "traffic", "restore"):
            for step in cell.get(group, []):
                files.add(step["stdout"])
                files.add(step["stderr"])
    network_write_set = [
        {
            "target": f"netdev:{spec.interface}:features",
            "operations": sorted(
                {tuple(step["argv"]) for cell in cells for step in cell.get("mutation", []) + cell.get("restore", []) if step["argv"][0] == TOOLS["ethtool"]}
            ),
        },
        {
            "target": f"netdev:{spec.interface}:mtu",
            "operations": sorted(
                {tuple(step["argv"]) for cell in cells for step in cell.get("mutation", []) + cell.get("restore", []) if step["argv"][0] == TOOLS["ip"]}
            ),
        },
    ]
    for entry in network_write_set:
        entry["operations"] = [list(argv) for argv in entry["operations"]]
    return {
        "schema": SCHEMA,
        "spec": spec.as_dict(),
        "snapshot_commands": snapshot_commands,
        "baseline": snapshot,
        "cells": cells,
        "write_set": {
            "filesystem": [spec.run_root, f"{spec.run_root}/logs", *sorted(files)],
            "network": network_write_set,
            "peer": [],
            "qdisc": [],
            "routes": [],
            "firewall": [],
            "bpf": [],
        },
        "safety_contract": {
            "target_host": "local reviewed test host only",
            "peer_policy": f"{READ_ONLY_PEER} receives iperf/ping traffic only; no peer-side writes",
            "implemented_capability_bits_changed": False,
            "af_packet_no_dst_positive_pmtu": False,
            "automatic_failure_restore": False,
            "recursive_cleanup": False,
            "shell_evaluation": False,
            "run_requires_exact_plan_sha256": True,
            "restore_is_a_separate_explicit_action": True,
            "artifacts_are_retained": True,
        },
    }


def core_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-root", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--interface", required=True)
    parser.add_argument("--expected-ifindex", type=int, required=True)
    parser.add_argument("--expected-mac", required=True)
    parser.add_argument("--expected-driver", required=True)
    parser.add_argument("--expected-bus-info", required=True)
    parser.add_argument("--expected-device-path", required=True)
    parser.add_argument("--expected-device-dev", type=int, required=True)
    parser.add_argument("--expected-device-ino", type=int, required=True)
    parser.add_argument("--expected-mtu", type=int, required=True)
    parser.add_argument("--expected-hostname", required=True)
    parser.add_argument("--expected-kernel", required=True)
    parser.add_argument("--expected-machine-id", required=True)
    parser.add_argument("--expected-boot-id", required=True)
    parser.add_argument("--peer-address", required=True)
    parser.add_argument("--peer-port", type=int, required=True)
    parser.add_argument("--traffic-seconds", type=int, required=True)
    parser.add_argument("--soak-seconds", type=int, required=True)
    parser.add_argument("--soak-window-seconds", type=int, required=True)
    parser.add_argument("--mtu-low", type=int, required=True)


def spec_from_namespace(namespace: argparse.Namespace) -> CoreSpec:
    names = {field.name for field in dataclasses.fields(CoreSpec)}
    return CoreSpec(**{name: getattr(namespace, name) for name in names}).validate()


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    modes = result.add_subparsers(dest="mode", required=True)
    for mode in ("plan", "run", "restore"):
        child = modes.add_parser(mode)
        core_arguments(child)
        if mode in {"run", "restore"}:
            child.add_argument("--approved-plan", required=True)
            child.add_argument("--approved-plan-sha256", required=True)
    return result


def plan_mode(spec: CoreSpec, runner: CommandRunner) -> int:
    snapshot, commands = collect_snapshot(spec, runner)
    sys.stdout.buffer.write(canonical_json(build_plan(spec, snapshot, commands)))
    return 0


def main(argv: Sequence[str] | None = None, runner: CommandRunner | None = None) -> int:
    namespace = parser().parse_args(argv)
    try:
        spec = spec_from_namespace(namespace)
        actual_runner = runner or CommandRunner()
        if namespace.mode == "plan":
            return plan_mode(spec, actual_runner)
        if namespace.mode == "run":
            return run_mode(spec, namespace.approved_plan, namespace.approved_plan_sha256, actual_runner)
        return restore_mode(spec, namespace.approved_plan, namespace.approved_plan_sha256, actual_runner)
    except HarnessError as exc:
        print(f"REALNIC_ACCEPTANCE_STOP reason={exc}", file=sys.stderr)
        return 125


# Implemented in the second, independently reviewable commit.  Keeping these
# entry points fail-closed makes the initial planner commit safe on its own.
def run_mode(spec: CoreSpec, approved_plan: str, approved_sha256: str, runner: CommandRunner) -> int:
    del spec, approved_plan, approved_sha256, runner
    raise HarnessError("run mode is closed in the planner-only revision")


def restore_mode(spec: CoreSpec, approved_plan: str, approved_sha256: str, runner: CommandRunner) -> int:
    del spec, approved_plan, approved_sha256, runner
    raise HarnessError("restore mode is closed in the planner-only revision")


if __name__ == "__main__":
    raise SystemExit(main())
