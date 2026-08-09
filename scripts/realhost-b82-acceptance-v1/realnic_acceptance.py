#!/usr/bin/env python3
"""Review-locked real-NIC characterization and acceptance harness.

``plan`` performs read-only inspection and emits a canonical JSON plan.  The
mutating ``run`` and ``restore`` modes are intentionally implemented below but
will only accept the exact plan bytes and SHA-256 reviewed by an operator.
"""

from __future__ import annotations

import argparse
import dataclasses
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import signal
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Mapping, Sequence


SCHEMA = "wg-mix-ebpf-b82-realnic-acceptance-plan-v1"
JOURNAL_SCHEMA = "wg-mix-ebpf-b82-realnic-acceptance-journal-v1"
LEASE_SCHEMA = "wg-mix-ebpf-b82-realnic-interface-lease-v1"
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
    "python3": "/usr/bin/python3",
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
FEATURE_DISABLE_ORDER = (
    "tx-udp-segmentation",
    "tcp-segmentation-offload",
    "generic-segmentation-offload",
    "rx-udp-gro-forwarding",
    "generic-receive-offload",
    "tx-checksumming",
    "rx-checksumming",
)
FEATURE_ENABLE_ORDER = FEATURE_ORDER


class HarnessError(RuntimeError):
    """Fail-closed harness error."""


class HarnessAbort(HarnessError):
    """Catchable process-level termination request."""


def termination_signals() -> tuple[int, ...]:
    values = [signal.SIGTERM, signal.SIGINT]
    if hasattr(signal, "SIGHUP"):
        values.append(signal.SIGHUP)
    return tuple(values)


class TerminationBoundary:
    """Turns catchable termination signals into ordinary stack unwinding."""

    def __init__(self) -> None:
        self._previous: dict[int, Any] = {}
        self._triggered: int | None = None

    def _handle(self, signum: int, _frame: Any) -> None:
        if self._triggered is None:
            self._triggered = signum
            raise HarnessAbort(f"termination signal {signal.Signals(signum).name}")

    def __enter__(self) -> "TerminationBoundary":
        if threading.current_thread() is not threading.main_thread():
            raise HarnessError("termination boundary requires the main thread")
        for signum in termination_signals():
            self._previous[signum] = signal.getsignal(signum)
            signal.signal(signum, self._handle)
        return self

    def __exit__(self, _kind: Any, _error: Any, _traceback: Any) -> bool:
        for signum, previous in self._previous.items():
            signal.signal(signum, previous)
        return False


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


def netns_number(value: str) -> int:
    match = re.fullmatch(r"net:\[([1-9][0-9]*)\]", value)
    if not match:
        raise HarnessError("network namespace identity is invalid")
    return int(match.group(1))


def interface_lease_path(spec: "CoreSpec", netns: str) -> str:
    parent = os.path.dirname(RUN_ROOT_PREFIX)
    if not parent or not os.path.isabs(parent):
        raise HarnessError("run-root prefix has no stable absolute lease directory")
    return (
        f"{parent}/wg-mix-ebpf-realnic-interface-{netns_number(netns)}-"
        f"{spec.expected_ifindex}-{spec.expected_device_dev}-{spec.expected_device_ino}.jsonl"
    )


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
        with OwnedProcessScope(self, argv) as process:
            return process.wait(timeout)

    def start(self, argv: Sequence[str]) -> "RunningProcess":
        if not argv or not os.path.isabs(argv[0]):
            raise HarnessError("every command must use an absolute executable path")
        previous_mask: set[signal.Signals] | None = None
        if hasattr(signal, "pthread_sigmask"):
            previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, termination_signals())
        owned: RunningProcess | None = None
        try:
            try:
                process = subprocess.Popen(
                    list(argv),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
                    start_new_session=True,
                )
            except OSError as exc:
                raise HarnessError(f"command did not start: {argv!r}: {exc}") from exc
            owned = RunningProcess(process)
        finally:
            if previous_mask is not None:
                try:
                    signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
                except BaseException as abort_error:
                    if owned is not None:
                        try:
                            owned.converge()
                        except BaseException as cleanup_error:
                            raise HarnessError(
                                f"start interruption ({abort_error}); process-group convergence failure ({cleanup_error})"
                            ) from cleanup_error
                    raise
        if owned is None:
            raise HarnessError("command start produced no owned process")
        return owned


class OwnedProcessScope:
    """Guarantees one bounded convergence attempt for an owned process group."""

    def __init__(self, runner: CommandRunner, argv: Sequence[str]):
        self.runner = runner
        self.argv = argv
        self.process: RunningProcess | None = None

    def __enter__(self) -> "RunningProcess":
        self.process = self.runner.start(self.argv)
        return self.process

    def __exit__(self, kind: Any, error: Any, _traceback: Any) -> bool:
        if self.process is None or self.process.proven_absent:
            return False
        if self.process.convergence_attempted:
            return False
        try:
            self.process.converge()
        except BaseException as cleanup_error:
            if error is not None:
                raise HarnessError(
                    f"command failure ({error}); process-group convergence failure ({cleanup_error})"
                ) from cleanup_error
            raise
        if kind is None:
            raise HarnessError("owned process scope exited before its process group was reaped")
        return False


class RunningProcess:
    def __init__(self, process: subprocess.Popen[bytes]):
        self._process = process
        self.pid = process.pid
        self.pgid = process.pid
        self.proven_absent = False
        self.convergence_attempted = False
        try:
            actual_pgid = os.getpgid(process.pid)
        except ProcessLookupError:
            actual_pgid = process.pid
        if actual_pgid != process.pid:
            process.kill()
            process.wait(timeout=5)
            raise HarnessError("background command did not enter its exact owned process group")
        self._stdout = bytearray()
        self._stderr = bytearray()
        self._overflow = False
        self._threads = [
            threading.Thread(target=self._drain, args=(process.stdout, self._stdout), daemon=True),
            threading.Thread(target=self._drain, args=(process.stderr, self._stderr), daemon=True),
        ]
        for thread in self._threads:
            thread.start()

    def _drain(self, stream: Any, destination: bytearray) -> None:
        if stream is None:
            return
        while True:
            chunk = stream.read(65536)
            if not chunk:
                break
            if len(destination) + len(chunk) <= 8 << 20:
                destination.extend(chunk)
            else:
                self._overflow = True

    def _collect_output(self) -> tuple[bytes, bytes]:
        for thread in self._threads:
            thread.join(timeout=5)
        if any(thread.is_alive() for thread in self._threads):
            raise HarnessError("background command output drain did not converge")
        for stream in (self._process.stdout, self._process.stderr):
            if stream is not None and not stream.closed:
                stream.close()
        if self._overflow:
            raise HarnessError("background command output exceeded 8 MiB")
        return bytes(self._stdout), bytes(self._stderr)

    def _group_exists(self) -> bool:
        try:
            os.killpg(self.pgid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True

    def _wait_group_absent(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self._process.poll()
            if not self._group_exists():
                return True
            time.sleep(0.05)
        self._process.poll()
        return not self._group_exists()

    def _signal_group(self, wanted_signal: int) -> str:
        try:
            os.killpg(self.pgid, wanted_signal)
            return "sent"
        except ProcessLookupError:
            return "already-absent"
        except OSError as exc:
            return f"error:{type(exc).__name__}:{exc}"

    def wait(self, timeout: int) -> tuple[int, bytes, bytes]:
        try:
            rc = self._process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise HarnessError("background command exceeded its reviewed timeout") from exc
        stdout, stderr = self._collect_output()
        if self._group_exists():
            raise HarnessError("owned process group remains after wrapper exit")
        self.proven_absent = True
        return rc, stdout, stderr

    def converge(
        self,
        *,
        term_timeout: float = 5.0,
        kill_timeout: float = 5.0,
    ) -> tuple[int, bytes, bytes, dict[str, Any]]:
        self.convergence_attempted = True
        report: dict[str, Any] = {
            "pid": self.pid,
            "pgid": self.pgid,
            "term": "not-needed",
            "kill": "not-needed",
        }
        if self._group_exists():
            report["term"] = self._signal_group(signal.SIGTERM)
        if not self._wait_group_absent(term_timeout):
            report["kill"] = self._signal_group(signal.SIGKILL)
            if not self._wait_group_absent(kill_timeout):
                raise HarnessError(f"owned process group {self.pgid} survived TERM and KILL: {report}")
        if self._process.poll() is None:
            try:
                self._process.wait(timeout=kill_timeout)
            except subprocess.TimeoutExpired as exc:
                raise HarnessError("owned wrapper was not reaped after process-group convergence") from exc
        stdout, stderr = self._collect_output()
        if self._group_exists():
            raise HarnessError(f"owned process group {self.pgid} still exists after convergence")
        rc = self._process.returncode
        if rc is None:
            raise HarnessError("owned wrapper has no terminal return code")
        report["group_absent"] = True
        report["wrapper_rc"] = rc
        self.proven_absent = True
        return rc, stdout, stderr, report


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


def normalize_addresses(items: Any) -> list[dict[str, Any]]:
    if not isinstance(items, list):
        raise HarnessError("ip address output is not an array")
    normalized: list[dict[str, Any]] = []
    address_keys = ("family", "local", "prefixlen", "scope", "label", "flags", "broadcast")
    for item in items:
        if not isinstance(item, dict):
            raise HarnessError("ip address item is not an object")
        entry = {key: stable_sort(item[key]) for key in ("ifindex", "ifname") if key in item}
        addr_info = item.get("addr_info", [])
        if not isinstance(addr_info, list):
            raise HarnessError("ip addr_info is not an array")
        entry["addr_info"] = stable_sort(
            [
                {key: stable_sort(address[key]) for key in address_keys if key in address}
                for address in addr_info
                if isinstance(address, dict)
            ]
        )
        normalized.append(entry)
    return stable_sort(normalized)


def normalize_routes(items: Any) -> list[dict[str, Any]]:
    if not isinstance(items, list):
        raise HarnessError("ip route output is not an array")
    keys = (
        "dst",
        "gateway",
        "dev",
        "prefsrc",
        "src",
        "table",
        "protocol",
        "scope",
        "type",
        "metric",
        "mtu",
    )
    result = []
    for item in items:
        if not isinstance(item, dict):
            raise HarnessError("ip route item is not an object")
        result.append({key: stable_sort(item[key]) for key in keys if key in item})
    return stable_sort(result)


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


def collect_snapshot(
    spec: CoreSpec,
    runner: CommandRunner,
    *,
    expected_mtu: int | None = None,
    allowed_mtu: frozenset[int] | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
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
        "addresses": normalize_addresses(parse_json_output(raw["addresses"], "ip address")),
        "routes": normalize_routes(parse_json_output(raw["routes"], "ip routes")),
        "peer_route": normalize_routes(parse_json_output(raw["peer_route"], "peer route")),
        "qdisc": stable_sort(parse_json_output(raw["qdisc"], "tc qdisc")),
        "tc_ingress": stable_sort(parse_json_output(raw["tc_ingress"], "tc ingress")),
        "tc_egress": stable_sort(parse_json_output(raw["tc_egress"], "tc egress")),
        "bpf_links": normalize_bpf(parse_json_output(raw["bpf_links"], "bpf links"), "links"),
        "bpf_programs": normalize_bpf(parse_json_output(raw["bpf_programs"], "bpf programs"), "programs"),
        "bpf_maps": normalize_bpf(parse_json_output(raw["bpf_maps"], "bpf maps"), "maps"),
        "wg_interfaces": sorted(raw["wg_interfaces"].decode("utf-8").split()),
        "nic_stat_keys": nic_stat_keys(raw["nic_stats"]),
    }
    validate_snapshot_identity(spec, snapshot, expected_mtu=expected_mtu, allowed_mtu=allowed_mtu)
    return snapshot, commands


def validate_snapshot_identity(
    spec: CoreSpec,
    snapshot: Mapping[str, Any],
    *,
    expected_mtu: int | None = None,
    allowed_mtu: frozenset[int] | None = None,
) -> None:
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
        "driver": spec.expected_driver,
        "bus_info": spec.expected_bus_info,
        "device_path": spec.expected_device_path,
        "device_dev": spec.expected_device_dev,
        "device_ino": spec.expected_device_ino,
    }
    mismatches = [key for key, value in expected_identity.items() if identity.get(key) != value]
    wanted_mtu = spec.expected_mtu if expected_mtu is None else expected_mtu
    if allowed_mtu is not None:
        if identity.get("mtu") not in allowed_mtu:
            mismatches.append("mtu")
    elif identity.get("mtu") != wanted_mtu:
        mismatches.append("mtu")
    if mismatches:
        raise HarnessError(f"interface identity mismatch: {','.join(mismatches)}")
    peer_routes = snapshot.get("peer_route")
    if not isinstance(peer_routes, list) or not peer_routes:
        raise HarnessError("peer route is empty")
    if not any(item.get("dev") == spec.interface for item in peer_routes if isinstance(item, dict)):
        raise HarnessError("peer route does not use the reviewed interface")


def lease_identity(spec: CoreSpec, snapshot: Mapping[str, Any]) -> dict[str, Any]:
    try:
        identity = snapshot["interface_identity"]
        result = {
            "netns": snapshot["host"]["netns"],
            "name": identity["name"],
            "ifindex": identity["ifindex"],
            "mac": identity["mac"],
            "driver": identity["driver"],
            "bus_info": identity["bus_info"],
            "device_path": identity["device_path"],
            "device_dev": identity["device_dev"],
            "device_ino": identity["device_ino"],
        }
    except (KeyError, TypeError) as exc:
        raise HarnessError("baseline has no complete interface lease identity") from exc
    expected = {
        "name": spec.interface,
        "ifindex": spec.expected_ifindex,
        "mac": spec.expected_mac,
        "driver": spec.expected_driver,
        "bus_info": spec.expected_bus_info,
        "device_path": spec.expected_device_path,
        "device_dev": spec.expected_device_dev,
        "device_ino": spec.expected_device_ino,
    }
    if any(result.get(key) != value for key, value in expected.items()):
        raise HarnessError("baseline interface lease identity does not match the exact specification")
    netns_number(str(result["netns"]))
    return result


def write_guard_command_table(spec: CoreSpec) -> list[tuple[str, list[str]]]:
    sysfs = f"/sys/class/net/{spec.interface}"
    return [
        ("netns", [TOOLS["readlink"], "/proc/self/ns/net"]),
        ("ifindex", [TOOLS["cat"], f"{sysfs}/ifindex"]),
        ("mac", [TOOLS["cat"], f"{sysfs}/address"]),
        ("device_path", [TOOLS["readlink"], "-e", f"{sysfs}/device"]),
        ("device_stat", [TOOLS["stat"], "-Lc", "%d:%i", f"{sysfs}/device"]),
        ("driver", [TOOLS["ethtool"], "-i", spec.interface]),
    ]


def collect_write_guard_identity(spec: CoreSpec, runner: CommandRunner) -> dict[str, Any]:
    raw: dict[str, bytes] = {}
    for label, argv in write_guard_command_table(spec):
        rc, stdout, stderr = runner.capture(argv, timeout=20)
        if rc != 0:
            reason = stderr.decode("utf-8", "replace").strip()
            raise HarnessError(f"network-write identity guard {label} failed rc={rc}: {reason}")
        raw[label] = stdout
    driver = parse_key_values(raw["driver"], "network-write driver")
    try:
        device_dev, device_ino = (
            int(part) for part in single_line(raw["device_stat"], "network-write device-stat").split(":")
        )
    except ValueError as exc:
        raise HarnessError("network-write device-stat is not decimal dev:inode") from exc
    return {
        "netns": single_line(raw["netns"], "network-write netns"),
        "name": spec.interface,
        "ifindex": int(single_line(raw["ifindex"], "network-write ifindex")),
        "mac": single_line(raw["mac"], "network-write mac"),
        "driver": driver.get("driver", ""),
        "bus_info": driver.get("bus-info", ""),
        "device_path": single_line(raw["device_path"], "network-write device-path"),
        "device_dev": device_dev,
        "device_ino": device_ino,
    }


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


def command_step(
    root: str,
    label: str,
    argv: Sequence[str],
    timeout: int,
    expect: str = "zero",
    *,
    target: str | None = None,
) -> dict[str, Any]:
    stdout_path, stderr_path = output_paths(root, label)
    return {
        "label": label,
        "argv": list(argv),
        "timeout_seconds": timeout,
        "expect_rc": expect,
        "stdout": stdout_path,
        "stderr": stderr_path,
        "target": target if target is not None else argv[-1],
    }


def iperf_checker_path() -> str:
    return str(Path(__file__).resolve().parent.parent / "realhost-b82-c8e41d73" / "check-realhost-iperf.py")


def iperf_checker_contract() -> dict[str, str]:
    path = iperf_checker_path()
    return {"path": path, "sha256": sha256_bytes(read_regular_file(path))}


def attach_iperf_oracle(
    spec: CoreSpec,
    step: dict[str, Any],
    direction: str,
    streams: int,
    *,
    soak: bool,
    checker: Mapping[str, str],
) -> None:
    oracle = command_step(
        spec.run_root,
        f"{step['label']}.oracle",
        [
            TOOLS["python3"],
            "-I",
            checker["path"],
            "one",
            step["stdout"],
            "--direction",
            direction,
            "--streams",
            str(streams),
            "--minimum-bytes",
            "1048576",
            "--minimum-fairness",
            "0.90",
            "--maximum-retransmit-rate",
            "0.001" if soak else "0.0001",
        ],
        30,
        target=step["stdout"],
    )
    oracle.update(
        {
            "kind": "iperf-oracle",
            "direction": direction,
            "streams": streams,
            "program_path": checker["path"],
            "program_sha256": checker["sha256"],
        }
    )
    step["oracle"] = oracle


def monitor_steps(spec: CoreSpec, cell_name: str, phase: str) -> list[dict[str, Any]]:
    return [
        command_step(
            spec.run_root,
            f"{cell_name}.monitor.{phase}.nic",
            [TOOLS["ethtool"], "-S", spec.interface],
            20,
            target=f"netdev:{spec.interface}",
        ),
        command_step(
            spec.run_root,
            f"{cell_name}.monitor.{phase}.link",
            [TOOLS["ip"], "-s", "-j", "link", "show", "dev", spec.interface],
            20,
            target=f"netdev:{spec.interface}",
        ),
    ]


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
    mutation_order = [
        name
        for name in FEATURE_DISABLE_ORDER
        if not bool(features[name]["fixed"]) and original[name] and not requested[name]
    ] + [
        name
        for name in FEATURE_ENABLE_ORDER
        if not bool(features[name]["fixed"]) and not original[name] and requested[name]
    ]
    for name in mutation_order:
        desired = requested[name]
        changed.append(name)
        mutation.append(
            command_step(
                spec.run_root,
                f"{cell_name}.mutate.{len(mutation):02d}.{name}",
                [TOOLS["ethtool"], "-K", spec.interface, name, "on" if desired else "off"],
                20,
                target=f"netdev:{spec.interface}",
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
                target=f"netdev:{spec.interface}",
            )
        )
    return mutation, restore, expected, unsupported


def recovery_steps_from_restore(restore: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    for step in restore:
        steps.append(
            {
                "label": step["label"].replace(".restore.", ".explicit-restore."),
                "argv": list(step["argv"]),
                "timeout_seconds": step["timeout_seconds"],
                "expect_rc": step["expect_rc"],
                "target": step["target"],
                "evidence": "append-only-journal",
            }
        )
    return steps


def iperf_steps(spec: CoreSpec, cell_name: str) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    checker = iperf_checker_contract()
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
                target=f"peer:{spec.peer_address}:{spec.peer_port}",
            )
            step.update({"kind": "iperf", "streams": streams, "direction": direction})
            attach_iperf_oracle(spec, step, direction, streams, soak=False, checker=checker)
            steps.append(step)
    return steps


def feature_cell(spec: CoreSpec, snapshot: Mapping[str, Any], name: str, policy: str) -> dict[str, Any]:
    mutation, restore, expected, unsupported = ethtool_steps(spec, snapshot, policy, name)
    recovery_restore = recovery_steps_from_restore(restore)
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
        "recovery_restore": recovery_restore,
        "expected_primary_features": expected,
        "expected_mtu": spec.expected_mtu,
        "monitor_before": monitor_steps(spec, name, "before"),
        "monitor_after": monitor_steps(spec, name, "after"),
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
        target=f"peer:{spec.peer_address}",
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
                target=f"netdev:{spec.interface}",
            )
        )
        restore.append(
            command_step(
                spec.run_root,
                f"{name}.restore.mtu",
                [TOOLS["ip"], "link", "set", "dev", spec.interface, "mtu", str(spec.expected_mtu)],
                20,
                target=f"netdev:{spec.interface}",
            )
        )
    traffic = [ping_step(spec, name, target_mtu, True), ping_step(spec, name, target_mtu, False)]
    iperf = iperf_steps(spec, name)
    traffic.extend(step for step in iperf if step["streams"] == 4 and step["direction"] == "bidir")
    recovery_restore = recovery_steps_from_restore(restore)
    return {
        "name": name,
        "kind": "tcp-mtu-boundary",
        "runnable": True,
        "classification": "characterization",
        "classification_reason": "validates local real-NIC IPv4 MTU boundary and TCP transfer, not FakeTCP +12 PMTU",
        "mutation": mutation,
        "restore": restore,
        "recovery_restore": recovery_restore,
        "expected_primary_features": None,
        "expected_mtu": target_mtu,
        "monitor_before": monitor_steps(spec, name, "before"),
        "monitor_after": monitor_steps(spec, name, "after"),
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
        target=f"peer:{spec.peer_address}",
    )
    ping.update({"kind": "ping-monitor", "parallel_group": name})
    traffic.append(ping)
    checker = iperf_checker_contract()
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
            target=f"peer:{spec.peer_address}:{spec.peer_port}",
        )
        step.update({"kind": "iperf", "streams": 4, "direction": "bidir", "window": window})
        attach_iperf_oracle(spec, step, "bidir", 4, soak=True, checker=checker)
        traffic.append(step)
    recovery_restore = recovery_steps_from_restore(restore)
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
        "recovery_restore": recovery_restore,
        "expected_primary_features": expected,
        "expected_mtu": spec.expected_mtu,
        "monitor_before": monitor_steps(spec, name, "before"),
        "monitor_after": monitor_steps(spec, name, "after"),
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
            "recovery_restore": [],
            "monitor_before": [],
            "monitor_after": [],
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
        f"{spec.run_root}/explicit-restored-snapshot.json",
    }
    for cell in cells:
        if cell["runnable"]:
            files.add(f"{spec.run_root}/active-{cell['name']}.json")
            files.add(f"{spec.run_root}/restored-{cell['name']}.json")
        for group in ("mutation", "monitor_before", "traffic", "monitor_after", "restore"):
            for step in cell.get(group, []):
                files.add(step["stdout"])
                files.add(step["stderr"])
                oracle = step.get("oracle")
                if isinstance(oracle, dict):
                    files.add(oracle["stdout"])
                    files.add(oracle["stderr"])
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
    identity = lease_identity(spec, snapshot)
    lease_path = interface_lease_path(spec, identity["netns"])
    traffic_oracle = iperf_checker_contract()
    guard_commands = [
        {"label": label, "argv": argv, "timeout_seconds": 20, "write_set": []}
        for label, argv in write_guard_command_table(spec)
    ]
    return {
        "schema": SCHEMA,
        "spec": spec.as_dict(),
        "snapshot_commands": snapshot_commands,
        "baseline": snapshot,
        "traffic_oracle": traffic_oracle,
        "interface_lease": {
            "path": lease_path,
            "identity": identity,
            "held_for_entire_run_or_restore": True,
            "persistent_active_owner": True,
            "guard_before_each_network_write": guard_commands,
        },
        "cells": cells,
        "runtime_snapshot_schedule": {
            "commands": snapshot_commands,
            "points": [
                "run-start",
                *[
                    point
                    for cell in cells
                    if cell["runnable"]
                    for point in (f"active:{cell['name']}", f"restored:{cell['name']}")
                ],
                "explicit-restore-start",
                "explicit-restore-finish",
            ],
        },
        "write_set": {
            "filesystem": [spec.run_root, f"{spec.run_root}/logs", lease_path, *sorted(files)],
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


def reject_ambiguous_cli(argv: Sequence[str]) -> None:
    if not argv:
        raise HarnessError("mode and exact arguments are required")
    seen: set[str] = set()
    for token in argv[1:]:
        if not token.startswith("--"):
            continue
        if "=" in token:
            raise HarnessError("option=value syntax is prohibited; use one exact argv element per value")
        if token in seen:
            raise HarnessError(f"duplicate option is prohibited: {token}")
        seen.add(token)


def plan_mode(spec: CoreSpec, runner: CommandRunner) -> int:
    snapshot, commands = collect_snapshot(spec, runner)
    sys.stdout.buffer.write(canonical_json(build_plan(spec, snapshot, commands)))
    return 0


def read_approved_plan(path_value: str, expected_sha256: str, spec: CoreSpec) -> tuple[dict[str, Any], bytes]:
    nontrivial_hex(expected_sha256, SHA256_RE, "approved-plan-sha256")
    path = Path(path_value)
    if not path.is_absolute() or os.path.normpath(path_value) != path_value:
        raise HarnessError("approved-plan must be a normalized absolute path")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path_value, flags)
    except OSError as exc:
        raise HarnessError(f"cannot open approved plan: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > 16 << 20:
            raise HarnessError("approved plan must be a bounded single-link regular file")
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1 << 20))
            if not chunk:
                raise HarnessError("approved plan was truncated while reading")
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
    finally:
        os.close(descriptor)
    if not payload or sha256_bytes(payload) != expected_sha256:
        raise HarnessError("approved plan SHA-256 mismatch")
    try:
        plan = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HarnessError("approved plan is not JSON") from exc
    if canonical_json(plan) != payload:
        raise HarnessError("approved plan is not canonical JSON")
    if plan.get("schema") != SCHEMA or plan.get("spec") != spec.as_dict():
        raise HarnessError("approved plan schema/spec does not match exact argv")
    validate_plan_shape(plan, spec)
    return plan, payload


def validate_plan_shape(plan: Mapping[str, Any], spec: CoreSpec) -> None:
    baseline = plan.get("baseline")
    if not isinstance(baseline, dict):
        raise HarnessError("approved plan has no baseline")
    oracle_contract = plan.get("traffic_oracle")
    if (
        not isinstance(oracle_contract, dict)
        or oracle_contract.get("path") != iperf_checker_path()
        or not isinstance(oracle_contract.get("sha256"), str)
        or not SHA256_RE.fullmatch(oracle_contract["sha256"])
        or set(oracle_contract) != {"path", "sha256"}
    ):
        raise HarnessError("approved plan traffic oracle contract is not exact")
    expected_identity = lease_identity(spec, baseline)
    expected_lease_path = interface_lease_path(spec, expected_identity["netns"])
    expected_guard = [
        {"label": label, "argv": argv, "timeout_seconds": 20, "write_set": []}
        for label, argv in write_guard_command_table(spec)
    ]
    expected_lease = {
        "path": expected_lease_path,
        "identity": expected_identity,
        "held_for_entire_run_or_restore": True,
        "persistent_active_owner": True,
        "guard_before_each_network_write": expected_guard,
    }
    if plan.get("interface_lease") != expected_lease:
        raise HarnessError("approved plan interface lease contract is not exact")
    write_set = plan.get("write_set")
    if not isinstance(write_set, dict):
        raise HarnessError("approved plan has no write set")
    for field in ("peer", "qdisc", "routes", "firewall", "bpf"):
        if write_set.get(field) != []:
            raise HarnessError(f"approved plan unexpectedly writes {field}")
    filesystem = write_set.get("filesystem")
    if not isinstance(filesystem, list) or len(filesystem) != len(set(filesystem)):
        raise HarnessError("filesystem write set is not a unique array")
    allowed_roots = {spec.run_root, f"{spec.run_root}/logs"}
    for path in filesystem:
        if (
            not isinstance(path, str)
            or not path.startswith(f"{spec.run_root}/")
            and path not in allowed_roots
            and path != expected_lease_path
        ):
            raise HarnessError("filesystem write escaped the run-owned root")
        if os.path.normpath(path) != path:
            raise HarnessError("filesystem write path is not normalized")
    if filesystem.count(expected_lease_path) != 1:
        raise HarnessError("filesystem write set must contain the exact stable interface lease")
    cells = plan.get("cells")
    if not isinstance(cells, list) or not cells:
        raise HarnessError("approved plan has no cells")
    names: set[str] = set()
    filesystem_set = set(filesystem)
    for cell in cells:
        if not isinstance(cell, dict) or cell.get("name") in names:
            raise HarnessError("approved plan cell is malformed or duplicated")
        names.add(cell["name"])
        if not cell.get("runnable"):
            if any(cell.get(group) for group in ("mutation", "restore", "recovery_restore", "traffic")):
                raise HarnessError("non-runnable cell contains executable work")
            continue
        for group in ("mutation", "monitor_before", "traffic", "monitor_after", "restore"):
            steps = cell.get(group)
            if not isinstance(steps, list):
                raise HarnessError(f"cell {cell['name']} has invalid {group}")
            for step in steps:
                validate_step(step, filesystem_set)
                if looks_like_network_write(step["argv"]) and not is_owned_network_write(step["argv"], spec):
                    raise HarnessError("planned network write is outside the exact owned interface knobs")
                oracle = step.get("oracle")
                if step.get("kind") == "iperf":
                    if not isinstance(oracle, dict):
                        raise HarnessError("iperf step has no strict oracle")
                    validate_step(oracle, filesystem_set)
                    if (
                        oracle.get("kind") != "iperf-oracle"
                        or oracle.get("direction") != step.get("direction")
                        or oracle.get("streams") != step.get("streams")
                        or oracle.get("program_path") != oracle_contract["path"]
                        or oracle.get("program_sha256") != oracle_contract["sha256"]
                        or oracle["argv"][:5]
                        != [
                            TOOLS["python3"],
                            "-I",
                            oracle_contract["path"],
                            "one",
                            step["stdout"],
                        ]
                    ):
                        raise HarnessError("iperf oracle does not match its exact traffic step")
                elif oracle is not None:
                    raise HarnessError("non-iperf step unexpectedly has a traffic oracle")
        recovery_steps = cell.get("recovery_restore")
        if not isinstance(recovery_steps, list):
            raise HarnessError(f"cell {cell['name']} has invalid recovery_restore")
        for step in recovery_steps:
            validate_recovery_step(step)
        normal = [step["argv"] for step in cell["restore"]]
        recovery = [step["argv"] for step in recovery_steps]
        if normal != recovery:
            raise HarnessError(f"cell {cell['name']} recovery restore is not exact")


def validate_step(step: Mapping[str, Any], filesystem_set: set[str]) -> None:
    required = {"label", "argv", "timeout_seconds", "expect_rc", "stdout", "stderr", "target"}
    if not required.issubset(step):
        raise HarnessError("planned command is incomplete")
    argv = step["argv"]
    if not isinstance(argv, list) or not argv or not all(isinstance(value, str) for value in argv):
        raise HarnessError("planned argv is invalid")
    if not os.path.isabs(argv[0]):
        raise HarnessError("planned executable is not absolute")
    if not isinstance(step["target"], str) or not step["target"]:
        raise HarnessError("planned command target is invalid")
    if step["expect_rc"] not in {"zero", "nonzero"}:
        raise HarnessError("planned command has invalid return-code expectation")
    if not isinstance(step["timeout_seconds"], int) or not 1 <= step["timeout_seconds"] <= 3700:
        raise HarnessError("planned command timeout is outside the bound")
    if step["stdout"] not in filesystem_set or step["stderr"] not in filesystem_set:
        raise HarnessError("planned command output is absent from the write set")


def validate_recovery_step(step: Mapping[str, Any]) -> None:
    required = {"label", "argv", "timeout_seconds", "expect_rc", "target", "evidence"}
    if set(step) != required or step.get("evidence") != "append-only-journal":
        raise HarnessError("recovery command must use only append-only journal evidence")
    argv = step["argv"]
    if not isinstance(argv, list) or not argv or not all(isinstance(value, str) for value in argv):
        raise HarnessError("recovery argv is invalid")
    if not os.path.isabs(argv[0]) or not isinstance(step["target"], str) or not step["target"]:
        raise HarnessError("recovery executable/target is invalid")
    if step["expect_rc"] != "zero":
        raise HarnessError("recovery command must require zero")
    if not isinstance(step["timeout_seconds"], int) or not 1 <= step["timeout_seconds"] <= 60:
        raise HarnessError("recovery timeout is outside the reviewed bound")


def ensure_absent(path: str) -> None:
    if os.path.lexists(path):
        raise HarnessError(f"run-owned path already exists: {path}")


def write_exclusive(path: str, payload: bytes, mode: int = 0o600) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, mode)
    except OSError as exc:
        raise HarnessError(f"exclusive evidence create failed for {path}: {exc}") from exc
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise HarnessError(f"short evidence write for {path}")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_idempotent_exact(path: str, payload: bytes, mode: int = 0o600) -> None:
    if os.path.lexists(path):
        if read_regular_file(path) != payload:
            raise HarnessError(f"existing idempotent evidence differs: {path}")
        return
    write_exclusive(path, payload, mode)


def read_regular_file(path: str, maximum: int = 16 << 20) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise HarnessError(f"cannot open run-owned evidence {path}: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > maximum:
            raise HarnessError(f"run-owned evidence has an invalid shape: {path}")
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1 << 20))
            if not chunk:
                raise HarnessError(f"run-owned evidence was truncated: {path}")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


class Journal:
    def __init__(self, path: str, run_id: str, plan_sha256: str, *, create: bool):
        self.path = path
        self.run_id = run_id
        self.plan_sha256 = plan_sha256
        flags = os.O_RDWR | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        if create:
            flags |= os.O_CREAT | os.O_EXCL
        try:
            self.descriptor = os.open(path, flags, 0o600)
        except OSError as exc:
            raise HarnessError(f"journal open failed: {exc}") from exc
        try:
            metadata = os.fstat(self.descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise HarnessError("journal must be a single-link regular file")
            fcntl.flock(self.descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._poisoned = False
            self._tail_recovery: dict[str, Any] | None = None
            self.events = [] if create else self._read_events()
            if self._tail_recovery is not None:
                self.append("JOURNAL_TAIL_TRUNCATED", **self._tail_recovery)
        except BaseException:
            os.close(self.descriptor)
            raise

    def _read_events(self) -> list[dict[str, Any]]:
        os.lseek(self.descriptor, 0, os.SEEK_SET)
        size = os.fstat(self.descriptor).st_size
        if size >= 8 << 20:
            raise HarnessError("journal exceeds the reviewed size")
        chunks: list[bytes] = []
        remaining = size
        while remaining:
            chunk = os.read(self.descriptor, min(remaining, 1 << 20))
            if not chunk:
                raise HarnessError("journal was truncated while reading")
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        complete_payload = payload
        if payload and not payload.endswith(b"\n"):
            boundary = payload.rfind(b"\n") + 1
            complete_payload = payload[:boundary]
            fragment = payload[boundary:]
            self._tail_recovery = {
                "removed_bytes": len(fragment),
                "removed_sha256": sha256_bytes(fragment),
            }
        events: list[dict[str, Any]] = []
        for index, raw in enumerate(complete_payload.splitlines(), start=1):
            try:
                event = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise HarnessError("journal contains an invalid line") from exc
            if canonical_json(event).rstrip(b"\n") != raw:
                raise HarnessError("journal line is not canonical")
            if (
                event.get("schema") != JOURNAL_SCHEMA
                or event.get("run_id") != self.run_id
                or event.get("plan_sha256") != self.plan_sha256
                or event.get("sequence") != index
            ):
                raise HarnessError("journal identity or sequence is invalid")
            events.append(event)
        if self._tail_recovery is not None:
            os.ftruncate(self.descriptor, len(complete_payload))
            os.fsync(self.descriptor)
        return events

    def append(self, event: str, **fields: Any) -> None:
        if self._poisoned:
            raise HarnessError("journal is poisoned after an incomplete append")
        record = {
            "schema": JOURNAL_SCHEMA,
            "run_id": self.run_id,
            "plan_sha256": self.plan_sha256,
            "sequence": len(self.events) + 1,
            "monotonic_ns": time.monotonic_ns(),
            "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event": event,
            **fields,
        }
        payload = canonical_json(record)
        try:
            offset = 0
            while offset < len(payload):
                written = os.write(self.descriptor, payload[offset:])
                if written <= 0:
                    raise HarnessError("journal append made no progress")
                offset += written
            os.fsync(self.descriptor)
        except (HarnessError, OSError) as exc:
            self._poisoned = True
            if isinstance(exc, HarnessError):
                raise
            raise HarnessError(f"journal append failed: {exc}") from exc
        self.events.append(record)

    def close(self) -> None:
        fcntl.flock(self.descriptor, fcntl.LOCK_UN)
        os.close(self.descriptor)


class InterfaceLease:
    """Persistent active owner plus an exclusive lock for one physical interface."""

    def __init__(
        self,
        path: str,
        run_id: str,
        plan_sha256: str,
        expected_identity: Mapping[str, Any],
    ):
        self.path = path
        self.run_id = run_id
        self.plan_sha256 = plan_sha256
        self.expected_identity = dict(expected_identity)
        self._poisoned = False
        flags = os.O_RDWR | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        try:
            self.descriptor = os.open(path, flags, 0o600)
        except OSError as exc:
            raise HarnessError(f"interface lease open failed: {exc}") from exc
        try:
            metadata = os.fstat(self.descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_uid != os.getuid()
            ):
                raise HarnessError("interface lease must be an owned 0600 single-link regular file")
            fcntl.flock(self.descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.events = self._read_events()
            self.active_owner, self.last_owner = self._replay_state()
        except BlockingIOError as exc:
            os.close(self.descriptor)
            raise HarnessError("reviewed interface is locked by another harness process") from exc
        except BaseException:
            os.close(self.descriptor)
            raise

    def __enter__(self) -> "InterfaceLease":
        return self

    def __exit__(self, _kind: Any, _error: Any, _traceback: Any) -> bool:
        self.close()
        return False

    def _read_events(self) -> list[dict[str, Any]]:
        os.lseek(self.descriptor, 0, os.SEEK_SET)
        size = os.fstat(self.descriptor).st_size
        if size > 8 << 20:
            raise HarnessError("interface lease history exceeds the reviewed size")
        payload = b""
        while len(payload) < size:
            chunk = os.read(self.descriptor, min(size - len(payload), 1 << 20))
            if not chunk:
                raise HarnessError("interface lease was truncated while reading")
            payload += chunk
        complete = payload
        fragment = b""
        if payload and not payload.endswith(b"\n"):
            boundary = payload.rfind(b"\n") + 1
            complete, fragment = payload[:boundary], payload[boundary:]
        events: list[dict[str, Any]] = []
        for sequence, raw in enumerate(complete.splitlines(), start=1):
            try:
                event = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise HarnessError("interface lease contains an invalid complete line") from exc
            if canonical_json(event).rstrip(b"\n") != raw:
                raise HarnessError("interface lease line is not canonical")
            if event.get("schema") != LEASE_SCHEMA or event.get("sequence") != sequence:
                raise HarnessError("interface lease schema or sequence is invalid")
            events.append(event)
        if fragment:
            os.ftruncate(self.descriptor, len(complete))
            os.fsync(self.descriptor)
            self.events = events
            self._append(
                "TAIL_TRUNCATED",
                run_id=self.run_id,
                plan_sha256=self.plan_sha256,
                removed_bytes=len(fragment),
                removed_sha256=sha256_bytes(fragment),
            )
            events = self.events
        return events

    def _owner(self, event: Mapping[str, Any]) -> dict[str, Any]:
        owner = {
            "run_id": event.get("run_id"),
            "plan_sha256": event.get("plan_sha256"),
            "identity": event.get("identity"),
        }
        identity = owner["identity"]
        required_identity = {
            "netns",
            "name",
            "ifindex",
            "mac",
            "driver",
            "bus_info",
            "device_path",
            "device_dev",
            "device_ino",
        }
        if (
            not isinstance(owner["run_id"], str)
            or not RUN_ID_RE.fullmatch(owner["run_id"])
            or not isinstance(owner["plan_sha256"], str)
            or not SHA256_RE.fullmatch(owner["plan_sha256"])
            or not isinstance(identity, dict)
            or set(identity) != required_identity
        ):
            raise HarnessError("interface lease owner record is malformed")
        try:
            netns_number(str(identity["netns"]))
        except HarnessError as exc:
            raise HarnessError("interface lease owner identity is malformed") from exc
        return owner

    def _replay_state(self) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        active: dict[str, Any] | None = None
        last: dict[str, Any] | None = None
        for event in self.events:
            kind = event.get("event")
            if kind == "CLAIM":
                if active is not None:
                    raise HarnessError("interface lease contains overlapping claims")
                active = self._owner(event)
                last = active
            elif kind == "RELEASE":
                owner = self._owner(event)
                if active != owner:
                    raise HarnessError("interface lease release does not match its active claim")
                active = None
                last = owner
            elif kind != "TAIL_TRUNCATED":
                raise HarnessError("interface lease contains an unknown event")
        return active, last

    def _append(self, event: str, **fields: Any) -> None:
        if self._poisoned:
            raise HarnessError("interface lease is poisoned after an incomplete append")
        record = {
            "schema": LEASE_SCHEMA,
            "sequence": len(self.events) + 1,
            "monotonic_ns": time.monotonic_ns(),
            "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event": event,
            **fields,
        }
        payload = canonical_json(record)
        try:
            offset = 0
            while offset < len(payload):
                written = os.write(self.descriptor, payload[offset:])
                if written <= 0:
                    raise HarnessError("interface lease append made no progress")
                offset += written
            os.fsync(self.descriptor)
        except (HarnessError, OSError) as exc:
            self._poisoned = True
            if isinstance(exc, HarnessError):
                raise
            raise HarnessError(f"interface lease append failed: {exc}") from exc
        self.events.append(record)

    def _wanted_owner(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "plan_sha256": self.plan_sha256,
            "identity": self.expected_identity,
        }

    def require_available_for_run(self) -> None:
        if self.active_owner is not None:
            raise HarnessError(
                f"interface has an active run owner {self.active_owner.get('run_id')}; explicit restore is required"
            )

    def claim(self) -> None:
        self.require_available_for_run()
        owner = self._wanted_owner()
        self._append("CLAIM", **owner)
        self.active_owner = owner
        self.last_owner = owner

    def require_restore_owner(self) -> None:
        if self.active_owner != self._wanted_owner():
            raise HarnessError("interface lease is not actively owned by this exact restore")

    def same_owner_released(self) -> bool:
        return self.active_owner is None and self.last_owner == self._wanted_owner()

    def assert_owned_for_write(
        self,
        spec: CoreSpec,
        runner: CommandRunner,
        journal: Journal,
        argv: Sequence[str],
    ) -> None:
        self.require_restore_owner()
        actual = collect_write_guard_identity(spec, runner)
        if actual != self.expected_identity:
            different = sorted(key for key in self.expected_identity if actual.get(key) != self.expected_identity[key])
            raise HarnessError(f"network-write interface identity changed: {','.join(different)}")
        self.require_restore_owner()
        journal.append(
            "NETWORK_WRITE_GUARD_VERIFIED",
            argv=list(argv),
            lease_path=self.path,
            identity_sha256=sha256_bytes(canonical_json(actual)),
        )

    def release(self) -> None:
        wanted = self._wanted_owner()
        if self.active_owner is None:
            if self.last_owner == wanted:
                return
            raise HarnessError("interface lease has no matching owner to release")
        if self.active_owner != wanted:
            raise HarnessError("interface lease owner changed before release")
        self._append("RELEASE", **wanted)
        self.active_owner = None
        self.last_owner = wanted

    def close(self) -> None:
        fcntl.flock(self.descriptor, fcntl.LOCK_UN)
        os.close(self.descriptor)


def directory_identity(path: str) -> dict[str, int]:
    metadata = os.lstat(path)
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise HarnessError(f"run-owned directory identity is invalid: {path}")
    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mode": stat.S_IMODE(metadata.st_mode),
    }


def create_run_root(spec: CoreSpec) -> dict[str, dict[str, int]]:
    ensure_absent(spec.run_root)
    try:
        os.mkdir(spec.run_root, 0o700)
        os.mkdir(f"{spec.run_root}/logs", 0o700)
    except OSError as exc:
        raise HarnessError(f"cannot create exact run-owned directories: {exc}") from exc
    for path in (spec.run_root, f"{spec.run_root}/logs"):
        metadata = os.lstat(path)
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700:
            raise HarnessError(f"run-owned directory has unexpected identity: {path}")
    return {
        "root": directory_identity(spec.run_root),
        "logs": directory_identity(f"{spec.run_root}/logs"),
    }


def validate_run_root_identity(spec: CoreSpec, expected: Mapping[str, Any]) -> None:
    actual = {
        "root": directory_identity(spec.run_root),
        "logs": directory_identity(f"{spec.run_root}/logs"),
    }
    if actual != expected:
        raise HarnessError("run-owned directory identity changed")


def is_owned_network_write(argv: Sequence[str], spec: CoreSpec) -> bool:
    return (
        len(argv) == 5
        and list(argv[:3]) == [TOOLS["ethtool"], "-K", spec.interface]
        or len(argv) == 7
        and list(argv[:6]) == [TOOLS["ip"], "link", "set", "dev", spec.interface, "mtu"]
    )


def looks_like_network_write(argv: Sequence[str]) -> bool:
    return (
        len(argv) >= 2
        and list(argv[:2]) == [TOOLS["ethtool"], "-K"]
        or len(argv) >= 3
        and list(argv[:3]) == [TOOLS["ip"], "link", "set"]
    )


def execute_step(
    step: Mapping[str, Any],
    runner: CommandRunner,
    journal: Journal,
    *,
    spec: CoreSpec | None = None,
    lease: InterfaceLease | None = None,
) -> tuple[int, bytes, bytes]:
    journal.append("COMMAND_START", label=step["label"], argv=step["argv"], target=step["target"])
    if looks_like_network_write(step["argv"]):
        if spec is None or lease is None or not is_owned_network_write(step["argv"], spec):
            raise HarnessError("network write has no exact interface lease")
        lease.assert_owned_for_write(spec, runner, journal, step["argv"])
    program_path = step.get("program_path")
    program_sha256 = step.get("program_sha256")
    if program_path is not None or program_sha256 is not None:
        if (
            not isinstance(program_path, str)
            or not isinstance(program_sha256, str)
            or not SHA256_RE.fullmatch(program_sha256)
            or sha256_bytes(read_regular_file(program_path)) != program_sha256
        ):
            raise HarnessError(f"planned program identity changed for {step['label']}")
    try:
        rc, stdout, stderr = runner.capture(step["argv"], timeout=step["timeout_seconds"])
    except HarnessError as exc:
        journal.append(
            "COMMAND_ERROR",
            label=step["label"],
            argv=step["argv"],
            target=step["target"],
            rc="exception",
            reason=str(exc),
        )
        raise
    write_exclusive(step["stdout"], stdout)
    write_exclusive(step["stderr"], stderr)
    journal.append(
        "COMMAND_FINISH",
        label=step["label"],
        argv=step["argv"],
        target=step["target"],
        rc=rc,
    )
    if step["expect_rc"] == "zero" and rc != 0:
        raise HarnessError(f"command {step['label']} failed rc={rc}")
    if step["expect_rc"] == "nonzero" and rc == 0:
        raise HarnessError(f"negative command {step['label']} unexpectedly succeeded")
    return rc, stdout, stderr


def execute_started_result(
    step: Mapping[str, Any],
    process: RunningProcess,
    journal: Journal,
) -> tuple[int, bytes, bytes]:
    rc, stdout, stderr = process.wait(step["timeout_seconds"])
    write_exclusive(step["stdout"], stdout)
    write_exclusive(step["stderr"], stderr)
    journal.append(
        "COMMAND_FINISH",
        label=step["label"],
        argv=step["argv"],
        target=step["target"],
        rc=rc,
    )
    if rc != 0:
        raise HarnessError(f"command {step['label']} failed rc={rc}")
    return rc, stdout, stderr


def recovery_output(payload: bytes) -> dict[str, Any]:
    if len(payload) > 65536:
        raise HarnessError("recovery command output exceeds 64 KiB")
    return {
        "length": len(payload),
        "sha256": sha256_bytes(payload),
        "text": payload.decode("utf-8", "backslashreplace"),
    }


def execute_recovery_step(
    step: Mapping[str, Any],
    runner: CommandRunner,
    journal: Journal,
    *,
    attempt: int,
    index: int,
    spec: CoreSpec,
    lease: InterfaceLease,
) -> None:
    audit = {
        "attempt": attempt,
        "index": index,
        "label": step["label"],
        "argv": step["argv"],
        "target": step["target"],
    }
    journal.append("RECOVERY_COMMAND_START", **audit)
    if not is_owned_network_write(step["argv"], spec):
        raise HarnessError("recovery command is not an exact owned network write")
    lease.assert_owned_for_write(spec, runner, journal, step["argv"])
    try:
        rc, stdout, stderr = runner.capture(step["argv"], timeout=step["timeout_seconds"])
    except HarnessError as exc:
        journal.append("RECOVERY_COMMAND_ERROR", **audit, rc="exception", reason=str(exc))
        raise
    journal.append(
        "RECOVERY_COMMAND_FINISH",
        **audit,
        rc=rc,
        stdout=recovery_output(stdout),
        stderr=recovery_output(stderr),
    )
    if rc != 0:
        raise HarnessError(f"recovery command {step['label']} failed rc={rc}")


def iperf_oracle_metrics(payload: bytes, streams: int, direction: str) -> list[dict[str, Any]]:
    groups = parse_json_output(payload, "strict iperf oracle")
    wanted_directions = {"forward", "reverse"} if direction == "bidir" else {direction}
    if not isinstance(groups, list) or len(groups) != len(wanted_directions):
        raise HarnessError("strict iperf oracle returned an incomplete direction set")
    observed: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for group in groups:
        if (
            not isinstance(group, dict)
            or group.get("direction") not in wanted_directions
            or not isinstance(group.get("received_bytes"), int)
            or group["received_bytes"] <= 0
            or not isinstance(group.get("throughput_mbps"), (int, float))
            or group["throughput_mbps"] <= 0
            or not isinstance(group.get("retransmits"), int)
            or group["retransmits"] < 0
            or not isinstance(group.get("fairness"), (int, float))
            or not 0.90 <= group["fairness"] <= 1.0
        ):
            raise HarnessError("strict iperf oracle returned malformed metrics")
        observed.add(group["direction"])
        normalized.append({**group, "streams": streams})
    if observed != wanted_directions:
        raise HarnessError("strict iperf oracle direction set differs from the reviewed argv")
    return normalized


def run_iperf_step(
    step: Mapping[str, Any], runner: CommandRunner, journal: Journal
) -> tuple[int, list[dict[str, Any]]]:
    rc, _, _ = execute_step(step, runner, journal)
    oracle = step["oracle"]
    _, oracle_stdout, _ = execute_step(oracle, runner, journal)
    return rc, iperf_oracle_metrics(oracle_stdout, step["streams"], step["direction"])


def ping_metrics(payload: bytes) -> dict[str, Any]:
    text = payload.decode("utf-8", "replace")
    match = re.search(r"([0-9]+(?:\.[0-9]+)?)% packet loss", text)
    if not match:
        raise HarnessError("ping output has no packet-loss summary")
    return {"packet_loss_percent": float(match.group(1))}


def parse_nic_counters(payload: bytes) -> dict[str, int]:
    result: dict[str, int] = {}
    for raw in payload.decode("utf-8", "replace").splitlines()[1:]:
        if ":" not in raw:
            continue
        name, value = (part.strip() for part in raw.split(":", 1))
        if re.fullmatch(r"[A-Za-z0-9_.-]+", name) and re.fullmatch(r"[0-9]+", value):
            result[name] = int(value)
    return result


def parse_link_counters(payload: bytes) -> dict[str, int]:
    items = parse_json_output(payload, "ip link counters")
    if not isinstance(items, list) or len(items) != 1 or not isinstance(items[0], dict):
        raise HarnessError("ip link counter output has an unexpected shape")
    stats = items[0].get("stats64", items[0].get("stats", {}))
    if not isinstance(stats, dict):
        raise HarnessError("ip link counter output has no stats")
    result: dict[str, int] = {}
    for direction in ("rx", "tx"):
        values = stats.get(direction, {})
        if not isinstance(values, dict):
            continue
        for name, value in values.items():
            if isinstance(value, int) and value >= 0:
                result[f"{direction}_{name}"] = value
    return result


def run_monitor(
    steps: Sequence[Mapping[str, Any]], runner: CommandRunner, journal: Journal
) -> dict[str, int]:
    combined: dict[str, int] = {}
    for step in steps:
        _, stdout, _ = execute_step(step, runner, journal)
        parser_fn = parse_nic_counters if step["argv"][:2] == [TOOLS["ethtool"], "-S"] else parse_link_counters
        for key, value in parser_fn(stdout).items():
            combined[f"{step['argv'][0]}:{key}"] = value
    return combined


def counter_delta(before: Mapping[str, int], after: Mapping[str, int]) -> dict[str, int]:
    return {key: after[key] - before[key] for key in sorted(before.keys() & after.keys())}


def run_traffic(
    cell: Mapping[str, Any], runner: CommandRunner, journal: Journal
) -> list[dict[str, Any]]:
    steps = cell["traffic"]
    results: list[dict[str, Any]] = []
    if cell["kind"] != "tcp-soak":
        for step in steps:
            if step.get("kind") == "iperf":
                rc, metrics = run_iperf_step(step, runner, journal)
                result: dict[str, Any] = {"label": step["label"], "rc": rc, "metrics": metrics}
            else:
                rc, stdout, _ = execute_step(step, runner, journal)
                result = {"label": step["label"], "rc": rc}
            if step.get("kind") != "iperf" and step["argv"][-1] == READ_ONLY_PEER and TOOLS["ping"] in step["argv"] and rc == 0:
                result["metrics"] = ping_metrics(stdout)
            results.append(result)
        return results

    monitor = steps[0]
    journal.append("COMMAND_START", label=monitor["label"], argv=monitor["argv"], target=monitor["target"])
    with OwnedProcessScope(runner, monitor["argv"]) as process:
        journal.append(
            "OWNED_PROCESS_GROUP_BOUND",
            label=monitor["label"],
            pid=process.pid,
            pgid=process.pgid,
        )
        try:
            for step in steps[1:]:
                rc, metrics = run_iperf_step(step, runner, journal)
                results.append(
                    {
                        "label": step["label"],
                        "rc": rc,
                        "metrics": metrics,
                    }
                )
            rc, stdout, _ = execute_started_result(monitor, process, journal)
            metrics = ping_metrics(stdout)
            if metrics["packet_loss_percent"] > 0.01:
                raise HarnessError("soak ping loss exceeds 0.01%")
            results.insert(0, {"label": monitor["label"], "rc": rc, "metrics": metrics})
        except BaseException as primary_error:
            journal.append(
                "OWNED_PROCESS_GROUP_STOP_INTENT",
                label=monitor["label"],
                pid=process.pid,
                pgid=process.pgid,
                reason=str(primary_error),
            )
            try:
                rc, stdout, stderr, report = process.converge()
                write_idempotent_exact(monitor["stdout"], stdout)
                write_idempotent_exact(monitor["stderr"], stderr)
                journal.append(
                    "OWNED_PROCESS_GROUP_STOPPED",
                    label=monitor["label"],
                    rc=rc,
                    report=report,
                )
            except BaseException as stop_error:
                journal.append(
                    "OWNED_PROCESS_GROUP_STOP_FAILED",
                    label=monitor["label"],
                    pid=process.pid,
                    pgid=process.pgid,
                    primary_reason=str(primary_error),
                    convergence_reason=str(stop_error),
                )
                raise HarnessError(
                    f"traffic failure ({primary_error}); owned process-group convergence failure ({stop_error})"
                ) from stop_error
            raise
    return results


def scrub_key(value: Any, key_to_remove: str) -> Any:
    if isinstance(value, dict):
        return {key: scrub_key(item, key_to_remove) for key, item in value.items() if key != key_to_remove}
    if isinstance(value, list):
        return [scrub_key(item, key_to_remove) for item in value]
    return value


def validate_scoped_snapshot(
    baseline: Mapping[str, Any],
    current: Mapping[str, Any],
    cell: Mapping[str, Any],
    *,
    allow_partial: bool = False,
) -> None:
    unchanged_fields = (
        "host",
        "addresses",
        "routes",
        "peer_route",
        "qdisc",
        "tc_ingress",
        "tc_egress",
        "bpf_links",
        "bpf_programs",
        "bpf_maps",
        "wg_interfaces",
        "nic_stat_keys",
    )
    for field in unchanged_fields:
        if current[field] != baseline[field]:
            raise HarnessError(f"unexpected drift in {field}")
    if scrub_key(current["link"], "mtu") != scrub_key(baseline["link"], "mtu"):
        raise HarnessError("interface link identity changed outside MTU")
    wanted_mtu = int(cell["expected_mtu"])
    actual_mtu = int(current["interface_identity"]["mtu"])
    if allow_partial:
        if actual_mtu not in {int(baseline["interface_identity"]["mtu"]), wanted_mtu}:
            raise HarnessError("MTU is neither baseline nor the cell target")
    elif actual_mtu != wanted_mtu:
        raise HarnessError("cell MTU does not match the exact target")
    expected_features = cell.get("expected_primary_features")
    if expected_features is not None:
        for name, expected in expected_features.items():
            actual = bool(current["features"][name]["enabled"])
            if allow_partial:
                original = bool(baseline["features"][name]["enabled"])
                if actual not in {original, bool(expected)}:
                    raise HarnessError(f"feature {name} is outside baseline/target")
            elif actual != bool(expected):
                raise HarnessError(f"feature {name} did not reach the exact target")


def validate_fully_restored(baseline: Mapping[str, Any], current: Mapping[str, Any]) -> None:
    if current != baseline:
        different = [key for key in baseline if baseline.get(key) != current.get(key)]
        raise HarnessError(f"full baseline restoration mismatch: {','.join(different)}")


def plan_cell(plan: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    for cell in plan["cells"]:
        if cell["name"] == name:
            return cell
    raise HarnessError(f"journal references an unknown cell: {name}")


def journal_active_cell(events: Sequence[Mapping[str, Any]]) -> tuple[str | None, bool]:
    active: str | None = None
    complete = False
    for event in events:
        kind = event["event"]
        if kind == "CELL_MUTATION_INTENT":
            if active is not None:
                raise HarnessError("journal starts a second cell before restoration")
            active = event.get("cell")
        elif kind == "CELL_RESTORED":
            if active != event.get("cell"):
                raise HarnessError("journal restored a different cell")
            active = None
        elif kind == "COMPLETE":
            if active is not None:
                raise HarnessError("journal completed with an active cell")
            complete = True
    return active, complete


def run_mode(spec: CoreSpec, approved_plan: str, approved_sha256: str, runner: CommandRunner) -> int:
    if os.geteuid() != 0:
        raise HarnessError("run mode requires root after explicit approval")
    plan, plan_payload = read_approved_plan(approved_plan, approved_sha256, spec)
    lease_contract = plan["interface_lease"]
    with InterfaceLease(
        lease_contract["path"],
        spec.run_id,
        approved_sha256,
        lease_contract["identity"],
    ) as lease:
        lease.require_available_for_run()
        return run_with_interface_lease(spec, approved_sha256, runner, plan, plan_payload, lease)


def run_with_interface_lease(
    spec: CoreSpec,
    approved_sha256: str,
    runner: CommandRunner,
    plan: Mapping[str, Any],
    plan_payload: bytes,
    lease: InterfaceLease,
) -> int:
    current, commands = collect_snapshot(spec, runner)
    rebuilt = canonical_json(build_plan(spec, current, commands))
    if rebuilt != plan_payload:
        raise HarnessError("current read-only snapshot no longer matches the approved plan")
    run_root_identity = create_run_root(spec)
    write_exclusive(f"{spec.run_root}/approved-plan.json", plan_payload)
    write_exclusive(f"{spec.run_root}/baseline.json", canonical_json(current))
    owner = {
        "schema": "wg-mix-ebpf-b82-realnic-owner-v1",
        "run_id": spec.run_id,
        "plan_sha256": approved_sha256,
        "source_commit": spec.source_commit,
        "interface_identity": current["interface_identity"],
        "boot_id": spec.expected_boot_id,
        "interface_lease_path": lease.path,
        "interface_lease_identity": lease.expected_identity,
        "run_root_identity": run_root_identity,
    }
    write_exclusive(f"{spec.run_root}/owner.json", canonical_json(owner))
    journal = Journal(f"{spec.run_root}/journal.jsonl", spec.run_id, approved_sha256, create=True)
    results: list[dict[str, Any]] = []
    active_cell: str | None = None
    try:
        journal.append("BASELINE_CAPTURED", baseline_sha256=sha256_bytes(canonical_json(current)))
        lease.claim()
        journal.append("INTERFACE_LEASE_CLAIMED", path=lease.path, identity=lease.expected_identity)
        for cell in plan["cells"]:
            if not cell["runnable"]:
                results.append(
                    {
                        "cell": cell["name"],
                        "classification": cell["classification"],
                        "reason": cell["classification_reason"],
                    }
                )
                continue
            active_cell = cell["name"]
            journal.append(
                "CELL_MUTATION_INTENT",
                cell=active_cell,
                mutation_argv=[step["argv"] for step in cell["mutation"]],
                exact_reverse_argv=[step["argv"] for step in cell["restore"]],
            )
            for index, step in enumerate(cell["mutation"]):
                execute_step(step, runner, journal, spec=spec, lease=lease)
                journal.append("MUTATION_APPLIED", cell=active_cell, index=index)
            active_snapshot, _ = collect_snapshot(spec, runner, expected_mtu=cell["expected_mtu"])
            validate_scoped_snapshot(current, active_snapshot, cell)
            write_exclusive(f"{spec.run_root}/active-{active_cell}.json", canonical_json(active_snapshot))
            journal.append("CELL_ACTIVE", cell=active_cell)
            counters_before = run_monitor(cell["monitor_before"], runner, journal)
            traffic_results = run_traffic(cell, runner, journal)
            counters_after = run_monitor(cell["monitor_after"], runner, journal)
            results.append(
                {
                    "cell": active_cell,
                    "classification": (
                        "passed" if cell["classification"] in {"eligible", "characterization"} else cell["classification"]
                    ),
                    "plan_classification": cell["classification"],
                    "traffic": traffic_results,
                    "counter_delta": counter_delta(counters_before, counters_after),
                    "evidence_limits": cell.get("evidence_limits", []),
                }
            )
            journal.append("TRAFFIC_COMPLETE", cell=active_cell)
            journal.append(
                "RESTORE_INTENT",
                cell=active_cell,
                exact_reverse_argv=[step["argv"] for step in cell["restore"]],
            )
            for index, step in enumerate(cell["restore"]):
                execute_step(step, runner, journal, spec=spec, lease=lease)
                journal.append("RESTORE_APPLIED", cell=active_cell, index=index)
            restored, _ = collect_snapshot(spec, runner)
            validate_fully_restored(current, restored)
            write_exclusive(f"{spec.run_root}/restored-{active_cell}.json", canonical_json(restored))
            journal.append("CELL_RESTORED", cell=active_cell)
            active_cell = None

        counts: dict[str, int] = {}
        for result in results:
            classification = result["classification"]
            counts[classification] = counts.get(classification, 0) + 1
        outcome = {
            "schema": "wg-mix-ebpf-b82-realnic-result-v1",
            "run_id": spec.run_id,
            "source_commit": spec.source_commit,
            "plan_sha256": approved_sha256,
            "overall": "incomplete" if counts.get("not-covered", 0) else "passed",
            "classification_counts": counts,
            "cells": results,
        }
        write_exclusive(f"{spec.run_root}/results.json", canonical_json(outcome))
        write_exclusive(
            f"{spec.run_root}/complete.json",
            canonical_json({"run_id": spec.run_id, "overall": outcome["overall"], "plan_sha256": approved_sha256}),
        )
        journal.append("COMPLETE", overall=outcome["overall"])
        lease.release()
        journal.append("INTERFACE_LEASE_RELEASED", path=lease.path)
        print(
            f"REALNIC_CHARACTERIZATION_COMPLETE run_id={spec.run_id} overall={outcome['overall']} "
            f"evidence={spec.run_root}"
        )
        return 3 if outcome["overall"] == "incomplete" else 0
    except BaseException as exc:
        journal.append("FAILED", cell=active_cell, reason=str(exc))
        raise
    finally:
        journal.close()


def restore_mode(spec: CoreSpec, approved_plan: str, approved_sha256: str, runner: CommandRunner) -> int:
    if os.geteuid() != 0:
        raise HarnessError("restore mode requires root after separate explicit approval")
    plan, plan_payload = read_approved_plan(approved_plan, approved_sha256, spec)
    lease_contract = plan["interface_lease"]
    with InterfaceLease(
        lease_contract["path"],
        spec.run_id,
        approved_sha256,
        lease_contract["identity"],
    ) as lease:
        return restore_with_interface_lease(spec, approved_sha256, runner, plan, plan_payload, lease)


def restore_with_interface_lease(
    spec: CoreSpec,
    approved_sha256: str,
    runner: CommandRunner,
    plan: Mapping[str, Any],
    plan_payload: bytes,
    lease: InterfaceLease,
) -> int:
    for path in (spec.run_root, f"{spec.run_root}/owner.json", f"{spec.run_root}/approved-plan.json"):
        if not os.path.lexists(path):
            raise HarnessError(f"restore ownership path is absent: {path}")
    stored_plan = read_regular_file(f"{spec.run_root}/approved-plan.json")
    if stored_plan != plan_payload:
        raise HarnessError("run-owned approved plan bytes changed")
    owner_payload = read_regular_file(f"{spec.run_root}/owner.json")
    owner = json.loads(owner_payload)
    if canonical_json(owner) != owner_payload:
        raise HarnessError("run owner marker is not canonical")
    if (
        owner.get("run_id") != spec.run_id
        or owner.get("plan_sha256") != approved_sha256
        or owner.get("source_commit") != spec.source_commit
        or owner.get("interface_lease_path") != lease.path
        or owner.get("interface_lease_identity") != lease.expected_identity
    ):
        raise HarnessError("run owner marker does not match restore argv")
    validate_run_root_identity(spec, owner.get("run_root_identity", {}))
    baseline_payload = read_regular_file(f"{spec.run_root}/baseline.json")
    baseline = json.loads(baseline_payload)
    if canonical_json(baseline) != baseline_payload:
        raise HarnessError("run baseline is not canonical")
    journal = Journal(f"{spec.run_root}/journal.jsonl", spec.run_id, approved_sha256, create=False)
    try:
        if not journal.events or journal.events[0].get("event") != "BASELINE_CAPTURED":
            raise HarnessError("journal has no baseline-captured origin")
        if journal.events[0].get("baseline_sha256") != sha256_bytes(baseline_payload):
            raise HarnessError("journal baseline SHA-256 mismatch")
        if owner.get("interface_identity") != baseline.get("interface_identity"):
            raise HarnessError("owner/baseline interface identity mismatch")
        active, complete = journal_active_cell(journal.events)
        if complete:
            release_needed = not lease.same_owner_released()
            if release_needed:
                lease.require_restore_owner()
            current, _ = collect_snapshot(spec, runner)
            validate_fully_restored(baseline, current)
            if release_needed:
                lease.release()
                journal.append("INTERFACE_LEASE_RELEASED", path=lease.path, terminal_restore=True)
            print(f"REALNIC_RESTORE_NOT_NEEDED run_id={spec.run_id} state=complete")
            return 0
        marker_path = f"{spec.run_root}/explicit-restored.json"
        marker = {"run_id": spec.run_id, "plan_sha256": approved_sha256, "state": "restored"}
        marker_payload = canonical_json(marker)
        explicit_complete = any(event.get("event") == "EXPLICIT_RESTORE_COMPLETE" for event in journal.events)
        if explicit_complete:
            release_needed = not lease.same_owner_released()
            if release_needed:
                lease.require_restore_owner()
            if not os.path.lexists(marker_path) or read_regular_file(marker_path) != marker_payload:
                raise HarnessError("completed explicit restore has no exact marker")
            current, _ = collect_snapshot(spec, runner)
            validate_fully_restored(baseline, current)
            if release_needed:
                lease.release()
                journal.append("INTERFACE_LEASE_RELEASED", path=lease.path, terminal_restore=True)
            print(f"REALNIC_RESTORE_NOT_NEEDED run_id={spec.run_id} state=explicit-restored")
            return 0
        if os.path.lexists(marker_path) and read_regular_file(marker_path) != marker_payload:
            raise HarnessError("existing explicit restore marker differs")
        if lease.active_owner is None and not any(
            event.get("event") == "CELL_MUTATION_INTENT" for event in journal.events
        ):
            lease.claim()
            journal.append(
                "INTERFACE_LEASE_CLAIMED",
                path=lease.path,
                identity=lease.expected_identity,
                restore_handoff=True,
            )
        lease.require_restore_owner()
        attempt = 1 + sum(event.get("event") == "EXPLICIT_RESTORE_INTENT" for event in journal.events)
        if active is None:
            current, _ = collect_snapshot(spec, runner)
            validate_fully_restored(baseline, current)
            journal.append("EXPLICIT_RESTORE_INTENT", attempt=attempt, cell=None, exact_reverse_argv=[])
        else:
            cell = plan_cell(plan, active)
            current, _ = collect_snapshot(
                spec,
                runner,
                allowed_mtu=frozenset({spec.expected_mtu, int(cell["expected_mtu"])}),
            )
            validate_scoped_snapshot(baseline, current, cell, allow_partial=True)
            journal.append(
                "EXPLICIT_RESTORE_INTENT",
                attempt=attempt,
                cell=active,
                exact_reverse_argv=[step["argv"] for step in cell["recovery_restore"]],
            )
            for index, step in enumerate(cell["recovery_restore"]):
                execute_recovery_step(
                    step,
                    runner,
                    journal,
                    attempt=attempt,
                    index=index,
                    spec=spec,
                    lease=lease,
                )
                journal.append("EXPLICIT_RESTORE_APPLIED", attempt=attempt, cell=active, index=index)
        restored, _ = collect_snapshot(spec, runner)
        validate_fully_restored(baseline, restored)
        write_idempotent_exact(f"{spec.run_root}/explicit-restored-snapshot.json", canonical_json(restored))
        write_idempotent_exact(marker_path, marker_payload)
        if active is not None:
            journal.append("CELL_RESTORED", attempt=attempt, cell=active, explicit=True)
        journal.append("EXPLICIT_RESTORE_COMPLETE", attempt=attempt, cell=active)
        lease.release()
        journal.append("INTERFACE_LEASE_RELEASED", path=lease.path, terminal_restore=True)
        print(f"REALNIC_EXPLICIT_RESTORE_COMPLETE run_id={spec.run_id} evidence={spec.run_root}")
        return 0
    except BaseException as exc:
        journal.append("EXPLICIT_RESTORE_FAILED", reason=str(exc))
        raise
    finally:
        journal.close()


def main(argv: Sequence[str] | None = None, runner: CommandRunner | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    try:
        with TerminationBoundary():
            reject_ambiguous_cli(raw_argv)
            namespace = parser().parse_args(raw_argv)
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


if __name__ == "__main__":
    raise SystemExit(main())
