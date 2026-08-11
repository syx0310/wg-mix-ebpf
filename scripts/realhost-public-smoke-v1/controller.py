#!/usr/bin/env python3
"""Bounded controller for the standalone two-host public BPF smoke test."""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import hmac
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, NoReturn


RUN_ID_RE = re.compile(r"^[0-9a-f]{12,24}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
OWNERSHIP_TOKEN_RE = re.compile(r"^[0-9a-f]{32}$")
PING_SUMMARY_RE = re.compile(
    r"(?m)^(\d+) packets transmitted, (\d+) (?:packets )?received,"
)
PING_SEQUENCE_RE = re.compile(r"icmp_seq=(\d+)")
ROLES = {
    "b82": {
        "host": "192.168.10.82",
        "credential": Path(
            "/Users/siyixuan/codes-2/wg-mix-ebpf/credientials/192.168.10.82"
        ),
        "interface": "ens33",
        "expected_hostname": "ubuntu-2604-test",
        "attachment_backend": "tcx",
        "minimum_kernel": (6, 6),
    },
    "public": {
        "host": "47.116.202.155",
        "credential": Path(
            "/Users/siyixuan/codes-2/wg-mix-ebpf/credientials/47.116.202.155"
        ),
        "interface": "eth0",
        "expected_hostname": None,
        "attachment_backend": "classic_tc",
        "minimum_kernel": (5, 15),
    },
}
REMOTE_TOOLS = (
    "/usr/bin/find",
    "/usr/bin/python3",
    "/usr/bin/ping",
    "/usr/bin/sha256sum",
    "/usr/bin/stat",
    "/usr/bin/sudo",
    "/usr/sbin/tc",
    "/usr/bin/tcpdump",
    "/usr/bin/timeout",
    "/usr/bin/uname",
    "/usr/sbin/ip",
    "/usr/bin/wg",
)


def stop(reason: str, rc: int = 78) -> NoReturn:
    print(f"PUBLIC_CONTROLLER_STOP reason={reason} rc={rc}", file=sys.stderr)
    raise SystemExit(rc)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_local_file(path: Path, *, executable: bool = False) -> str:
    if not path.is_absolute():
        stop(f"local-path:{path.name}", 64)
    try:
        observed = path.lstat()
    except OSError:
        stop(f"local-file:{path.name}", 66)
    if (
        not stat.S_ISREG(observed.st_mode)
        or observed.st_nlink != 1
        or observed.st_mode & 0o022
        or (executable and not observed.st_mode & 0o100)
    ):
        stop(f"local-shape:{path.name}", 66)
    return sha256_file(path)


def normalized_output(raw: bytes) -> str:
    try:
        return raw.decode("utf-8").replace("\r", "")
    except UnicodeDecodeError:
        stop("remote-output-encoding", 77)


class Remote:
    def __init__(self, transport: Path, role: str) -> None:
        self.transport = transport
        self.role = role
        self.spec = ROLES[role]

    def invoke(self, operation: str, *arguments: str) -> bytes:
        argv = [
            "/usr/bin/expect",
            str(self.transport),
            str(self.spec["credential"]),
            str(self.spec["host"]),
            operation,
            *arguments,
        ]
        try:
            completed = subprocess.run(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=1950,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            stop(f"transport:{self.role}:{type(error).__name__}", 77)
        if completed.returncode != 0:
            safe_error = normalized_output(completed.stderr).strip()
            if safe_error:
                print(safe_error, file=sys.stderr)
            stop(f"transport:{self.role}:rc{completed.returncode}", 77)
        return completed.stdout

    def ssh(self, *arguments: str) -> str:
        return normalized_output(self.invoke("ssh", *arguments)).strip()

    def scp(self, source: Path, target: str) -> None:
        self.invoke("scp-put", str(source), target)


def script_paths() -> dict[str, Path]:
    root = Path(__file__).resolve(strict=True).parent
    paths = {
        "controller": root / "controller.py",
        "transport": root / "transport.exp",
        "endpoint": root / "root-endpoint.py",
        "traffic": root / "traffic.py",
        "report": root / "report.py",
    }
    for name, path in paths.items():
        safe_local_file(path, executable=name != "report")
    return paths


def kernel_tuple(release: str) -> tuple[int, int] | None:
    match = re.match(r"^([0-9]+)\.([0-9]+)(?:\.|-)", release)
    return (int(match.group(1)), int(match.group(2))) if match else None


def probe_one(remote: Remote) -> dict[str, Any]:
    spec = remote.spec
    hostname = remote.ssh("/usr/bin/uname", "-n")
    kernel = remote.ssh("/usr/bin/uname", "-r")
    try:
        link = json.loads(
            remote.ssh(
                "/usr/sbin/ip",
                "-j",
                "link",
                "show",
                "dev",
                str(spec["interface"]),
            )
        )
    except (ValueError, SystemExit):
        link = None
    bpffs = remote.ssh("/usr/bin/stat", "-fc", "%T", "/sys/fs/bpf") == "bpf_fs"
    missing = []
    for tool in REMOTE_TOOLS:
        try:
            remote.ssh("/usr/bin/test", "-x", tool)
        except SystemExit:
            missing.append(tool)
    parsed_kernel = kernel_tuple(kernel)
    expected_hostname = spec["expected_hostname"]
    host_ok = expected_hostname is None or hostname == expected_hostname
    classic_baseline: dict[str, Any] | None = None
    classic_ok = True
    if remote.role == "public":
        try:
            qdiscs = json.loads(remote.ssh("/usr/sbin/tc", "-j", "qdisc", "show", "dev", str(spec["interface"])))
            ingress = json.loads(remote.ssh("/usr/sbin/tc", "-j", "filter", "show", "dev", str(spec["interface"]), "ingress"))
            egress = json.loads(remote.ssh("/usr/sbin/tc", "-j", "filter", "show", "dev", str(spec["interface"]), "egress"))
        except (ValueError, SystemExit):
            qdiscs, ingress, egress = None, None, None
        clsact_count = (
            sum(1 for item in qdiscs if isinstance(item, dict) and item.get("kind") == "clsact")
            if isinstance(qdiscs, list)
            else -1
        )
        classic_ok = clsact_count == 1 and ingress == [] and egress == []
        classic_baseline = {
            "clsact_count": clsact_count,
            "ingress_filters": len(ingress) if isinstance(ingress, list) else None,
            "egress_filters": len(egress) if isinstance(egress, list) else None,
            "clean": classic_ok,
        }
    eligible = (
        host_ok
        and isinstance(link, list)
        and len(link) == 1
        and not missing
        and bpffs
        and parsed_kernel is not None
        and parsed_kernel >= spec["minimum_kernel"]
        and classic_ok
    )
    return {
        "role": remote.role,
        "host": spec["host"],
        "hostname": hostname,
        "kernel": kernel,
        "interface": spec["interface"],
        "ifindex": link[0].get("ifindex") if isinstance(link, list) and len(link) == 1 else None,
        "bpffs": bpffs,
        "tools_missing": missing,
        "attachment_backend": spec["attachment_backend"],
        "minimum_kernel": ".".join(str(value) for value in spec["minimum_kernel"]),
        "kernel_floor_ok": parsed_kernel is not None
        and parsed_kernel >= spec["minimum_kernel"],
        "host_identity_ok": host_ok,
        "classic_tc_baseline": classic_baseline,
        "eligible": eligible,
    }


def remote_layout(run_id: str, role: str) -> tuple[str, str]:
    return (
        f"/tmp/wg-mix-public-smoke-{run_id}-{role}-intake",
        f"/run/wg-mix-ebpf-public-smoke-{run_id}-{role}",
    )


def sudo_endpoint(
    remote: Remote,
    run_id: str,
    commit: str,
    claim_sha256: str,
    *argv: str,
) -> str:
    _, root = remote_layout(run_id, remote.role)
    return remote.ssh(
        "/usr/bin/sudo",
        "-S",
        "-p",
        "PUBLIC_SUDO_PASSWORD:",
        f"{root}/root-endpoint.py",
        *argv,
        "--role",
        remote.role,
        "--run-id",
        run_id,
        "--commit",
        commit,
        "--claim-sha256",
        claim_sha256,
    )


def parse_json_line(output: str, label: str) -> dict[str, Any]:
    lines = [line for line in output.splitlines() if line.startswith("{")]
    if len(lines) != 1:
        stop(f"json-lines:{label}", 77)
    try:
        value = json.loads(lines[0])
    except ValueError:
        stop(f"json:{label}", 77)
    if not isinstance(value, dict):
        stop(f"json-shape:{label}", 77)
    return value


def artifact_contract(args: argparse.Namespace, paths: dict[str, Path]) -> dict[str, Any]:
    binary = Path(args.binary).resolve(strict=True)
    object_path = Path(args.object).resolve(strict=True)
    return {
        "controller": {"path": str(paths["controller"]), "sha256": safe_local_file(paths["controller"], executable=True)},
        "transport": {"path": str(paths["transport"]), "sha256": safe_local_file(paths["transport"], executable=True)},
        "endpoint": {"path": str(paths["endpoint"]), "sha256": safe_local_file(paths["endpoint"], executable=True)},
        "traffic": {"path": str(paths["traffic"]), "sha256": safe_local_file(paths["traffic"], executable=True)},
        "report": {"path": str(paths["report"]), "sha256": safe_local_file(paths["report"])},
        "binary": {"path": str(binary), "sha256": safe_local_file(binary, executable=True)},
        "object": {"path": str(object_path), "sha256": safe_local_file(object_path)},
    }


def endpoint_argv(
    run_id: str,
    commit: str,
    role: str,
    claim_sha256: str,
    mode: str,
    *argv: str,
) -> list[str]:
    _, root = remote_layout(run_id, role)
    return [
        f"{root}/root-endpoint.py",
        mode,
        *argv,
        "--role",
        role,
        "--run-id",
        run_id,
        "--commit",
        commit,
        "--claim-sha256",
        claim_sha256,
    ]


def intake_claim_document(
    args: argparse.Namespace, role: str, artifacts: dict[str, Any]
) -> dict[str, Any]:
    intake, root = remote_layout(args.run_id, role)
    return {
        "schema": "wg-mix-public-intake-claim-v1",
        "run_id": args.run_id,
        "role": role,
        "commit": args.commit,
        "ownership_token": args.ownership_token,
        "intake": intake,
        "root": root,
        "artifacts": {
            name: artifacts[name]["sha256"]
            for name in ("binary", "endpoint", "object", "traffic")
        },
    }


def intake_claim_bytes(
    args: argparse.Namespace, role: str, artifacts: dict[str, Any]
) -> bytes:
    return (
        json.dumps(
            intake_claim_document(args, role, artifacts),
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode()


def execution_contract(
    args: argparse.Namespace, paths: dict[str, Path], artifacts: dict[str, Any]
) -> dict[str, Any]:
    operations: dict[str, dict[str, list[str]]] = {}
    for role in ROLES:
        intake, _ = remote_layout(args.run_id, role)
        claim_sha256 = hashlib.sha256(
            intake_claim_bytes(args, role, artifacts)
        ).hexdigest()
        operations[role] = {
            "prepare": endpoint_argv(
                args.run_id,
                args.commit,
                role,
                claim_sha256,
                "prepare",
                "--script-sha256",
                artifacts["endpoint"]["sha256"],
                "--binary-source",
                f"{intake}/wg-mix-ebpf",
                "--binary-sha256",
                artifacts["binary"]["sha256"],
                "--object-source",
                f"{intake}/wg_mix_tc.o",
                "--object-sha256",
                artifacts["object"]["sha256"],
                "--traffic-source",
                f"{intake}/traffic.py",
                "--traffic-sha256",
                artifacts["traffic"]["sha256"],
            ),
            "apply": endpoint_argv(
                args.run_id,
                args.commit,
                role,
                claim_sha256,
                "apply",
                "--peer-public-key",
                f"@prepared-public-key:{'public' if role == 'b82' else 'b82'}",
            ),
            "server": endpoint_argv(args.run_id, args.commit, role, claim_sha256, "server", "--seconds", str(args.seconds + 30)),
            "capture": endpoint_argv(args.run_id, args.commit, role, claim_sha256, "capture", "--seconds", str(args.seconds + 30)),
            "ping": endpoint_argv(args.run_id, args.commit, role, claim_sha256, "ping", "--count", str(args.seconds)),
            "udp-client": endpoint_argv(
                args.run_id,
                args.commit,
                role,
                claim_sha256,
                "client",
                "--traffic-mode",
                "udp-client",
                "--seconds",
                str(args.seconds),
                "--bits-per-second",
                str(args.bits_per_second),
            ),
            "tcp-client": endpoint_argv(
                args.run_id,
                args.commit,
                role,
                claim_sha256,
                "client",
                "--traffic-mode",
                "tcp-client",
                "--bytes",
                str(args.tcp_bytes),
            ),
            "sample": endpoint_argv(args.run_id, args.commit, role, claim_sha256, "sample"),
            "restore": endpoint_argv(args.run_id, args.commit, role, claim_sha256, "restore"),
            "export": endpoint_argv(args.run_id, args.commit, role, claim_sha256, "export"),
            "purge": endpoint_argv(args.run_id, args.commit, role, claim_sha256, "purge"),
        }
    return {
        "schema": "wg-mix-public-execution-contract-v1",
        "run_id": args.run_id,
        "commit": args.commit,
        "ownership_token": args.ownership_token,
        "source": source_contract(args.commit, paths),
        "artifacts": artifacts,
        "remote_layout": {
            role: dict(zip(("intake", "root"), remote_layout(args.run_id, role)))
            for role in ROLES
        },
        "traffic": {
            "seconds": args.seconds,
            "bits_per_second_each_direction": args.bits_per_second,
            "tcp_bytes_each_direction": args.tcp_bytes,
        },
        "endpoint_argv": operations,
        "intake_claims": {
            role: intake_claim_document(args, role, artifacts) for role in ROLES
        },
        "host_write_set": {
            "run_owned": [
                "/tmp/wg-mix-public-smoke-<run-id>-<role>-intake",
                "/run/wg-mix-ebpf-public-smoke-<run-id>-<role>",
                "/sys/fs/bpf/wg-mix-ebpf-public-smoke-<run-id>-<role>",
                "wireguard:wgps82",
                "wireguard:wgps47",
                "address:10.203.82.1/30",
                "address:10.203.82.2/30",
                "tcx:ens33:ingress+egress",
                "classic_tc:eth0:priority49152:handles0x10001+0x10002",
            ],
            "shared_audit_and_lock_state": [
                "/run/wg-mix-ebpf/daemon.lease",
                "/run/.wg-mix-ebpf-daemon.lease.maintenance",
                "/run/wg-mix-ebpf/pin-locks/<resource-key>.lock",
                "/var/lib/wg-mix-ebpf/pin-owners/instances.v2.json",
                "/var/lib/wg-mix-ebpf/pin-owners/<resource-owner-and-history-files>",
            ],
            "not_modified": ["firewall", "offload", "mtu"],
        },
        "local_write_set": [
            "/private/tmp/wg-mix-public-smoke-evidence-<run-id>",
        ],
    }


def contract_sha256(contract: dict[str, Any]) -> str:
    encoded = json.dumps(contract, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def source_contract(commit: str, paths: dict[str, Path]) -> dict[str, Any]:
    repository = paths["controller"].parents[2]
    try:
        head = subprocess.check_output(
            ["/usr/bin/git", "-C", str(repository), "rev-parse", "HEAD"],
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            timeout=10,
            text=True,
        ).strip()
        tree = subprocess.check_output(
            ["/usr/bin/git", "-C", str(repository), "rev-parse", "HEAD^{tree}"],
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            timeout=10,
            text=True,
        ).strip()
        status = subprocess.check_output(
            ["/usr/bin/git", "-C", str(repository), "status", "--porcelain=v1", "--untracked-files=all"],
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            timeout=10,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        stop("source-git", 66)
    if head != commit:
        stop("source-commit", 66)
    return {
        "repository": str(repository),
        "head": head,
        "tree": tree,
        "worktree_clean": status == "",
    }


def frozen_run_argv(args: argparse.Namespace, paths: dict[str, Path], digest: str) -> list[str]:
    return [
        "/usr/bin/python3",
        str(paths["controller"]),
        "run",
        "--run-id",
        args.run_id,
        "--commit",
        args.commit,
        "--binary",
        str(Path(args.binary).resolve(strict=True)),
        "--object",
        str(Path(args.object).resolve(strict=True)),
        "--seconds",
        str(args.seconds),
        "--bits-per-second",
        str(args.bits_per_second),
        "--tcp-bytes",
        str(args.tcp_bytes),
        "--ownership-token",
        args.ownership_token,
        "--contract-sha256",
        digest,
    ]


def frozen_cleanup_argv(args: argparse.Namespace, paths: dict[str, Path], digest: str) -> list[str]:
    argv = frozen_run_argv(args, paths, digest)
    argv[2] = "cleanup"
    return argv


def stage_one(
    remote: Remote,
    run_id: str,
    commit: str,
    artifacts: dict[str, Any],
    claim_path: Path,
    claim_sha256: str,
) -> str:
    intake, root = remote_layout(run_id, remote.role)
    remote.ssh("/usr/bin/mkdir", "--mode=700", "--", intake)
    remote.scp(claim_path, f"{intake}/intake-owner.json")
    claim_output = remote.ssh(
        "/usr/bin/sha256sum", "--", f"{intake}/intake-owner.json"
    )
    if claim_output != f"{claim_sha256}  {intake}/intake-owner.json":
        stop(f"intake-claim:{remote.role}", 79)
    claim_shape = remote.ssh(
        "/usr/bin/stat",
        "-c",
        "%a:%h:%s:%F",
        f"{intake}/intake-owner.json",
    )
    if claim_shape != f"600:1:{claim_path.stat().st_size}:regular file":
        stop(f"intake-claim-shape:{remote.role}", 79)
    for key, remote_name in (
        ("endpoint", "root-endpoint.py"),
        ("traffic", "traffic.py"),
        ("binary", "wg-mix-ebpf"),
        ("object", "wg_mix_tc.o"),
    ):
        remote.scp(Path(artifacts[key]["path"]), f"{intake}/{remote_name}")
    remote.ssh(
        "/usr/bin/sudo",
        "-S",
        "-p",
        "PUBLIC_SUDO_PASSWORD:",
        "/usr/bin/mkdir",
        "--mode=700",
        "--",
        root,
    )
    remote.ssh(
        "/usr/bin/sudo",
        "-S",
        "-p",
        "PUBLIC_SUDO_PASSWORD:",
        "/usr/bin/install",
        "-m0600",
        "-oroot",
        "-groot",
        "--no-target-directory",
        f"{intake}/intake-owner.json",
        f"{root}/root-claim.json",
    )
    remote.ssh(
        "/usr/bin/sudo",
        "-S",
        "-p",
        "PUBLIC_SUDO_PASSWORD:",
        "/usr/bin/install",
        "-m0700",
        "-oroot",
        "-groot",
        "--no-target-directory",
        f"{intake}/root-endpoint.py",
        f"{root}/root-endpoint.py",
    )
    output = sudo_endpoint(
        remote,
        run_id,
        commit,
        claim_sha256,
        "prepare",
        "--script-sha256",
        artifacts["endpoint"]["sha256"],
        "--binary-source",
        f"{intake}/wg-mix-ebpf",
        "--binary-sha256",
        artifacts["binary"]["sha256"],
        "--object-source",
        f"{intake}/wg_mix_tc.o",
        "--object-sha256",
        artifacts["object"]["sha256"],
        "--traffic-source",
        f"{intake}/traffic.py",
        "--traffic-sha256",
        artifacts["traffic"]["sha256"],
    )
    prepared = parse_json_line(output, f"prepare-{remote.role}")
    public_key = prepared.get("public_key")
    if not isinstance(public_key, str) or not re.fullmatch(r"[A-Za-z0-9+/]{43}=", public_key):
        stop(f"public-key:{remote.role}", 77)
    return public_key


def sample_both(
    remotes: dict[str, Remote],
    run_id: str,
    commit: str,
    claim_sha256: dict[str, str],
) -> dict[str, Any]:
    result = {}
    for role, remote in remotes.items():
        output = sudo_endpoint(
            remote, run_id, commit, claim_sha256[role], "sample"
        )
        result[role] = parse_json_line(output, f"sample-{role}")
    return result


def parse_ping(output: str, count: int) -> dict[str, int]:
    summary = PING_SUMMARY_RE.search(output)
    if not summary:
        stop("ping-summary", 77)
    transmitted, received = map(int, summary.groups())
    if transmitted != count or not 0 <= received <= transmitted:
        stop("ping-count", 77)
    seen = {int(value) for value in PING_SEQUENCE_RE.findall(output)}
    longest = current = 0
    for sequence in range(1, count + 1):
        if sequence in seen:
            current = 0
        else:
            current += 1
            longest = max(longest, current)
    return {
        "transmitted": transmitted,
        "received": received,
        "max_consecutive_loss": longest,
    }


def remote_named_entry_exists(remote: Remote, parent: str, name: str) -> bool:
    observed = remote.ssh(
        "/usr/bin/find",
        parent,
        "-maxdepth",
        "1",
        "-name",
        name,
        "-printf",
        "%f",
    )
    if observed not in ("", name):
        stop(f"remote-entry:{remote.role}:{name}", 79)
    return observed == name


def remote_directory_entries(remote: Remote, directory: str) -> dict[str, str]:
    observed = remote.ssh(
        "/usr/bin/find",
        directory,
        "-mindepth",
        "1",
        "-maxdepth",
        "1",
        "-printf",
        "%f:%y,",
    )
    result: dict[str, str] = {}
    if not observed:
        return result
    for raw in observed.split(","):
        if not raw:
            continue
        name, separator, kind = raw.rpartition(":")
        if separator != ":" or not re.fullmatch(r"[A-Za-z0-9_.-]+", name) or kind not in {"d", "f"} or name in result:
            stop(f"remote-directory:{remote.role}", 79)
        result[name] = kind
    return result


def verify_intake_claim(
    remote: Remote, args: argparse.Namespace, artifacts: dict[str, Any]
) -> None:
    intake, _ = remote_layout(args.run_id, remote.role)
    expected = intake_claim_bytes(args, remote.role, artifacts)
    expected_sha256 = hashlib.sha256(expected).hexdigest()
    marker = f"{intake}/intake-owner.json"
    directory_shape = remote.ssh(
        "/usr/bin/stat", "-c", "%u:%g:%a:%F", intake
    )
    shape = remote.ssh("/usr/bin/stat", "-c", "%u:%g:%a:%h:%s:%F", marker)
    directory_parts = directory_shape.split(":")
    marker_parts = shape.split(":")
    if (
        len(directory_parts) != 4
        or len(marker_parts) != 7
        or directory_parts[0:2] != marker_parts[0:2]
        or directory_parts[2:] != ["700", "directory"]
        or marker_parts[2:] != ["600", "1", str(len(expected)), "regular file"]
    ):
        stop(f"intake-claim-shape:{remote.role}", 79)
    digest = remote.ssh("/usr/bin/sha256sum", "--", marker)
    if digest != f"{expected_sha256}  {marker}":
        stop(f"intake-claim-digest:{remote.role}", 79)


def verify_root_claim(
    remote: Remote, args: argparse.Namespace, artifacts: dict[str, Any]
) -> str:
    _, root = remote_layout(args.run_id, remote.role)
    expected_sha256 = hashlib.sha256(
        intake_claim_bytes(args, remote.role, artifacts)
    ).hexdigest()
    marker = f"{root}/root-claim.json"
    shape = remote.ssh("/usr/bin/stat", "-c", "%u:%g:%a:%h:%s:%F", marker)
    if shape != (
        f"0:0:600:1:{len(intake_claim_bytes(args, remote.role, artifacts))}:"
        "regular file"
    ):
        stop(f"root-claim-shape:{remote.role}", 79)
    digest = remote.ssh("/usr/bin/sha256sum", "--", marker)
    if digest != f"{expected_sha256}  {marker}":
        stop(f"root-claim-digest:{remote.role}", 79)
    return expected_sha256


def cleanup_intake(
    remote: Remote, args: argparse.Namespace, artifacts: dict[str, Any]
) -> None:
    intake, _ = remote_layout(args.run_id, remote.role)
    parent, name = intake.rsplit("/", 1)
    if not remote_named_entry_exists(remote, parent, name):
        return
    entries = remote_directory_entries(remote, intake)
    allowed = {
        "intake-owner.json",
        "root-endpoint.py",
        "traffic.py",
        "wg-mix-ebpf",
        "wg_mix_tc.o",
    }
    if not set(entries).issubset(allowed) or any(kind != "f" for kind in entries.values()):
        stop(f"intake-foreign:{remote.role}", 79)
    if "intake-owner.json" not in entries:
        stop(f"intake-unclaimed:{remote.role}", 79)
    verify_intake_claim(remote, args, artifacts)
    payload_entries = entries.keys() - {"intake-owner.json"}
    if payload_entries:
        remote.ssh(
            "/usr/bin/rm",
            "--",
            *(f"{intake}/{name}" for name in sorted(payload_entries)),
        )
    remote.ssh("/usr/bin/rm", "--", f"{intake}/intake-owner.json")
    remote.ssh("/usr/bin/rmdir", "--", intake)


def write_local_intake_claim(
    local_root: Path,
    args: argparse.Namespace,
    role: str,
    artifacts: dict[str, Any],
) -> tuple[Path, str]:
    data = intake_claim_bytes(args, role, artifacts)
    path = local_root / f"intake-claim-{role}.json"
    try:
        with path.open("xb", buffering=0) as handle:
            os.fchmod(handle.fileno(), 0o600)
            offset = 0
            while offset < len(data):
                written = handle.write(data[offset:])
                if written is None or written <= 0:
                    stop(f"local-intake-claim-write:{role}", 73)
                offset += written
            os.fsync(handle.fileno())
    except OSError:
        stop(f"local-intake-claim:{role}", 73)
    return path, hashlib.sha256(data).hexdigest()


def write_evidence_export(
    local_root: Path, run_id: str, role: str, document: dict[str, Any]
) -> None:
    if (
        document.get("schema") != "wg-mix-public-evidence-export-v1"
        or document.get("run_id") != run_id
        or document.get("role") != role
        or not isinstance(document.get("files"), dict)
    ):
        stop(f"export-shape:{role}", 77)
    decoded: dict[str, bytes] = {}
    for name, encoded in document["files"].items():
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
            stop(f"export-name:{role}", 77)
        try:
            decoded[name] = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError):
            stop(f"export-data:{role}", 77)
    target = local_root / role
    if target.exists():
        observed = target.lstat()
        if not stat.S_ISDIR(observed.st_mode) or stat.S_IMODE(observed.st_mode) != 0o700 or observed.st_uid != os.getuid():
            stop(f"export-directory:{role}", 77)
    else:
        target.mkdir(mode=0o700)
    complete_path = target / ".complete.json"
    if complete_path.exists():
        complete_item = complete_path.lstat()
        complete_pending = target / ".pending-.complete.json"
        pending_item = complete_pending.lstat() if complete_pending.exists() else None
        if pending_item is not None:
            if (
                not stat.S_ISREG(complete_item.st_mode)
                or not stat.S_ISREG(pending_item.st_mode)
                or complete_item.st_nlink != 2
                or pending_item.st_nlink != 2
                or stat.S_IMODE(complete_item.st_mode) != 0o600
                or stat.S_IMODE(pending_item.st_mode) != 0o600
                or complete_item.st_uid != os.getuid()
                or pending_item.st_uid != os.getuid()
                or (complete_item.st_dev, complete_item.st_ino)
                != (pending_item.st_dev, pending_item.st_ino)
            ):
                stop(f"export-complete-pending:{role}", 77)
            os.unlink(complete_pending)
            complete_directory_fd = os.open(
                target,
                os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
            )
            try:
                os.fsync(complete_directory_fd)
            finally:
                os.close(complete_directory_fd)
            complete_item = complete_path.lstat()
        try:
            complete = json.loads(complete_path.read_bytes())
        except (OSError, ValueError):
            stop(f"export-complete:{role}", 77)
        if (
            not stat.S_ISREG(complete_item.st_mode)
            or complete_item.st_nlink != 1
            or stat.S_IMODE(complete_item.st_mode) != 0o600
            or complete_item.st_uid != os.getuid()
            or not isinstance(complete, dict)
            or complete.get("schema") != "wg-mix-public-local-evidence-complete-v1"
            or complete.get("run_id") != run_id
            or complete.get("role") != role
            or not isinstance(complete.get("files"), dict)
        ):
            stop(f"export-complete:{role}", 77)
        recorded_files = complete["files"]
        if {entry.name for entry in target.iterdir()} != set(recorded_files) | {".complete.json"}:
            stop(f"export-complete-files:{role}", 77)
        for name, record in recorded_files.items():
            path = target / name
            if (
                not isinstance(name, str)
                or not re.fullmatch(r"[A-Za-z0-9_.-]+", name)
                or not isinstance(record, dict)
                or set(record) != {"sha256", "size"}
                or not isinstance(record.get("size"), int)
                or record["size"] < 0
                or not isinstance(record.get("sha256"), str)
                or not SHA256_RE.fullmatch(record["sha256"])
            ):
                stop(f"export-complete-record:{role}", 77)
            item = path.lstat()
            data = path.read_bytes()
            if (
                not stat.S_ISREG(item.st_mode)
                or item.st_nlink != 1
                or stat.S_IMODE(item.st_mode) != 0o600
                or item.st_uid != os.getuid()
                or len(data) != record["size"]
                or hashlib.sha256(data).hexdigest() != record["sha256"]
            ):
                stop(f"export-complete-file:{role}:{name}", 77)
        if not set(decoded).issubset(recorded_files):
            stop(f"export-complete-drift:{role}", 77)
        for name, data in decoded.items():
            record = recorded_files[name]
            if len(data) != record["size"] or hashlib.sha256(data).hexdigest() != record["sha256"]:
                stop(f"export-complete-drift:{role}:{name}", 77)
        return
    allowed_entries = (
        set(decoded)
        | {f".pending-{name}" for name in decoded}
        | {".pending-.complete.json"}
    )
    if not {entry.name for entry in target.iterdir()}.issubset(allowed_entries):
        stop(f"export-existing:{role}", 77)
    directory_fd = os.open(
        target,
        os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        def publish(name: str, data: bytes) -> None:
            final = target / name
            pending = target / f".pending-{name}"
            if final.exists():
                final_item = final.lstat()
                pending_item = pending.lstat() if pending.exists() else None
                if (
                    not stat.S_ISREG(final_item.st_mode)
                    or stat.S_IMODE(final_item.st_mode) != 0o600
                    or final_item.st_uid != os.getuid()
                    or final.read_bytes() != data
                    or (
                        pending_item is None
                        and final_item.st_nlink != 1
                    )
                    or (
                        pending_item is not None
                        and (
                            not stat.S_ISREG(pending_item.st_mode)
                            or stat.S_IMODE(pending_item.st_mode) != 0o600
                            or pending_item.st_uid != os.getuid()
                            or pending_item.st_nlink != 2
                            or final_item.st_nlink != 2
                            or (final_item.st_dev, final_item.st_ino)
                            != (pending_item.st_dev, pending_item.st_ino)
                        )
                    )
                ):
                    stop(f"export-existing:{role}:{name}", 77)
                if pending_item is not None:
                    os.unlink(pending)
                    os.fsync(directory_fd)
                return
            if pending.exists():
                pending_item = pending.lstat()
                if (
                    not stat.S_ISREG(pending_item.st_mode)
                    or pending_item.st_nlink != 1
                    or stat.S_IMODE(pending_item.st_mode) != 0o600
                    or pending_item.st_uid != os.getuid()
                    or pending_item.st_size > len(data)
                    or pending.read_bytes() != data[: pending_item.st_size]
                ):
                    stop(f"export-pending:{role}:{name}", 77)
                fd = os.open(
                    pending,
                    os.O_WRONLY | os.O_APPEND | os.O_CLOEXEC | os.O_NOFOLLOW,
                )
            else:
                fd = os.open(
                    pending,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | os.O_CLOEXEC
                    | os.O_NOFOLLOW,
                    0o600,
                )
                os.fchmod(fd, 0o600)
            try:
                opened = os.fstat(fd)
                named = pending.lstat()
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or opened.st_nlink != 1
                    or stat.S_IMODE(opened.st_mode) != 0o600
                    or opened.st_uid != os.getuid()
                    or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
                    or opened.st_size > len(data)
                ):
                    stop(f"export-pending:{role}:{name}", 77)
                offset = opened.st_size
                while offset < len(data):
                    written = os.write(fd, data[offset:])
                    if written <= 0:
                        stop(f"export-write:{role}:{name}", 77)
                    offset += written
                os.fsync(fd)
            finally:
                os.close(fd)
            os.link(pending, final, follow_symlinks=False)
            os.unlink(pending)
            os.fsync(directory_fd)

        for name, data in decoded.items():
            publish(name, data)
        complete = {
            "schema": "wg-mix-public-local-evidence-complete-v1",
            "run_id": run_id,
            "role": role,
            "files": {
                name: {
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "size": len(data),
                }
                for name, data in sorted(decoded.items())
            },
        }
        publish(
            ".complete.json",
            (json.dumps(complete, sort_keys=True, separators=(",", ":")) + "\n").encode(),
        )
    finally:
        os.close(directory_fd)


def create_local_evidence(run_id: str, *, allow_existing: bool = False) -> Path:
    root = Path(f"/private/tmp/wg-mix-public-smoke-evidence-{run_id}")
    try:
        root.mkdir(mode=0o700)
    except FileExistsError:
        if not allow_existing:
            stop("local-evidence-exists", 73)
        observed = root.lstat()
        if (
            not stat.S_ISDIR(observed.st_mode)
            or stat.S_IMODE(observed.st_mode) != 0o700
            or observed.st_uid != os.getuid()
        ):
            stop("local-evidence-shape", 73)
        allowed = {
            "controller.json",
            "report.json",
            "intake-claim-b82.json",
            "intake-claim-public.json",
            "b82",
            "public",
        }
        if not {entry.name for entry in root.iterdir()}.issubset(allowed):
            stop("local-evidence-foreign", 73)
    except OSError:
        stop("local-evidence-create", 73)
    return root


def run_test(
    args: argparse.Namespace, paths: dict[str, Path], artifacts: dict[str, Any]
) -> None:
    remotes = {role: Remote(paths["transport"], role) for role in ROLES}
    probes = {role: probe_one(remote) for role, remote in remotes.items()}
    print(json.dumps({"schema": "wg-mix-public-probes-v1", "probes": probes}, sort_keys=True))
    if not all(item["eligible"] for item in probes.values()):
        stop("probe-ineligible", 77)
    local_evidence = create_local_evidence(args.run_id)
    claim_files = {
        role: write_local_intake_claim(local_evidence, args, role, artifacts)
        for role in ROLES
    }
    claim_sha256 = {role: item[1] for role, item in claim_files.items()}
    keys: dict[str, str] = {}
    for role in ("public", "b82"):
        claim_path, claim_sha256 = claim_files[role]
        keys[role] = stage_one(
            remotes[role],
            args.run_id,
            args.commit,
            artifacts,
            claim_path,
            claim_sha256,
        )
    sudo_endpoint(
        remotes["public"],
        args.run_id,
        args.commit,
        claim_sha256["public"],
        "apply",
        "--peer-public-key",
        keys["b82"],
    )
    sudo_endpoint(
        remotes["b82"],
        args.run_id,
        args.commit,
        claim_sha256["b82"],
        "apply",
        "--peer-public-key",
        keys["public"],
    )
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as service_executor:
        services = {
            f"server-{role}": service_executor.submit(
                sudo_endpoint,
                remote,
                args.run_id,
                args.commit,
                claim_sha256[role],
                "server",
                "--seconds",
                str(args.seconds + 30),
            )
            for role, remote in remotes.items()
        }
        services.update(
            {
                f"capture-{role}": service_executor.submit(
                    sudo_endpoint,
                    remote,
                    args.run_id,
                    args.commit,
                    claim_sha256[role],
                    "capture",
                    "--seconds",
                    str(args.seconds + 30),
                )
                for role, remote in remotes.items()
            }
        )
        time.sleep(1.0)
        samples = [sample_both(remotes, args.run_id, args.commit, claim_sha256)]
        tasks: dict[str, concurrent.futures.Future[str]] = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            for role, remote in remotes.items():
                tasks[f"ping-{role}"] = executor.submit(
                    sudo_endpoint,
                    remote,
                    args.run_id,
                    args.commit,
                    claim_sha256[role],
                    "ping",
                    "--count",
                    str(args.seconds),
                )
                tasks[f"udp-{role}"] = executor.submit(
                    sudo_endpoint,
                    remote,
                    args.run_id,
                    args.commit,
                    claim_sha256[role],
                    "client",
                    "--traffic-mode",
                    "udp-client",
                    "--seconds",
                    str(args.seconds),
                    "--bits-per-second",
                    str(args.bits_per_second),
                )
            deadline = time.monotonic() + args.seconds
            while time.monotonic() < deadline:
                time.sleep(min(10.0, max(0.0, deadline - time.monotonic())))
                samples.append(
                    sample_both(remotes, args.run_id, args.commit, claim_sha256)
                )
            traffic = {name: future.result() for name, future in tasks.items()}
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            tcp_futures = {
                role: executor.submit(
                    sudo_endpoint,
                    remote,
                    args.run_id,
                    args.commit,
                    claim_sha256[role],
                    "client",
                    "--traffic-mode",
                    "tcp-client",
                    "--bytes",
                    str(args.tcp_bytes),
                )
                for role, remote in remotes.items()
            }
            for role, future in tcp_futures.items():
                traffic[f"tcp-{role}"] = future.result()
        for future in services.values():
            future.result()
    samples.append(sample_both(remotes, args.run_id, args.commit, claim_sha256))
    ping_parts = [parse_ping(traffic[f"ping-{role}"], args.seconds) for role in ROLES]
    ping = {
        "transmitted": sum(item["transmitted"] for item in ping_parts),
        "received": sum(item["received"] for item in ping_parts),
        "max_consecutive_loss": max(item["max_consecutive_loss"] for item in ping_parts),
    }
    evidence_document = {
        "schema": "wg-mix-public-controller-evidence-v1",
        "run_id": args.run_id,
        "commit": args.commit,
        "probes": probes,
        "samples": samples,
        "ping": ping,
        "traffic": traffic,
        "artifacts": artifacts,
    }
    evidence_path = local_evidence / "controller.json"
    with evidence_path.open("x", encoding="utf-8") as handle:
        os.fchmod(handle.fileno(), 0o600)
        json.dump(evidence_document, handle, indent=2, sort_keys=True)
        handle.write("\n")
    report_path = local_evidence / "report.json"
    completed = subprocess.run(
        ["/usr/bin/python3", str(paths["report"]), str(evidence_path), "--output", str(report_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )
    if completed.returncode != 0:
        stop(f"qualification-failed:evidence={local_evidence}", 76)
    for role in ("b82", "public"):
        sudo_endpoint(
            remotes[role],
            args.run_id,
            args.commit,
            claim_sha256[role],
            "restore",
        )
    for role in ROLES:
        exported = parse_json_line(
            sudo_endpoint(
                remotes[role],
                args.run_id,
                args.commit,
                claim_sha256[role],
                "export",
            ),
            f"export-{role}",
        )
        write_evidence_export(local_evidence, args.run_id, role, exported)
    for role in ("b82", "public"):
        sudo_endpoint(
            remotes[role],
            args.run_id,
            args.commit,
            claim_sha256[role],
            "purge",
        )
        cleanup_intake(remotes[role], args, artifacts)
    print(
        f"PUBLIC_CONTROLLER_COMPLETE run_id={args.run_id} commit={args.commit} "
        f"evidence={local_evidence} restored=1 purged=1"
    )


def cleanup_unclaimed_root(
    remote: Remote,
    args: argparse.Namespace,
    artifacts: dict[str, Any],
) -> bool:
    _, root = remote_layout(args.run_id, remote.role)
    parent, name = root.rsplit("/", 1)
    if not remote_named_entry_exists(remote, parent, name):
        return False
    entries = remote_directory_entries(remote, root)
    if "owner.json" in entries:
        verify_intake_claim(remote, args, artifacts)
        verify_root_claim(remote, args, artifacts)
        return True
    verify_intake_claim(remote, args, artifacts)
    claim_sha256 = verify_root_claim(remote, args, artifacts)
    if entries == {"root-claim.json": "f"}:
        remote.ssh(
            "/usr/bin/sudo",
            "-S",
            "-p",
            "PUBLIC_SUDO_PASSWORD:",
            "/usr/bin/rm",
            "--",
            f"{root}/root-claim.json",
        )
        remote.ssh(
            "/usr/bin/sudo",
            "-S",
            "-p",
            "PUBLIC_SUDO_PASSWORD:",
            "/usr/bin/rmdir",
            "--",
            root,
        )
        return False
    if entries not in (
        {"root-claim.json": "f", "root-endpoint.py": "f"},
        {
            "root-claim.json": "f",
            "root-endpoint.py": "f",
            "owner.pending.json": "f",
        },
    ):
        stop(f"unclaimed-root-foreign:{remote.role}", 79)
    sudo_endpoint(
        remote,
        args.run_id,
        args.commit,
        claim_sha256,
        "abort-unclaimed",
        "--script-sha256",
        artifacts["endpoint"]["sha256"],
    )
    return False


def cleanup(
    args: argparse.Namespace,
    paths: dict[str, Path],
    artifacts: dict[str, Any],
) -> None:
    remotes = {role: Remote(paths["transport"], role) for role in ROLES}
    claim_sha256 = {
        role: hashlib.sha256(intake_claim_bytes(args, role, artifacts)).hexdigest()
        for role in ROLES
    }
    present: dict[str, bool] = {}
    for role, remote in remotes.items():
        present[role] = cleanup_unclaimed_root(remote, args, artifacts)
    for role in ("b82", "public"):
        if present[role]:
            sudo_endpoint(
                remotes[role],
                args.run_id,
                args.commit,
                claim_sha256[role],
                "restore",
            )
    local_evidence = create_local_evidence(args.run_id, allow_existing=True)
    for role in ROLES:
        if present[role]:
            exported = parse_json_line(
                sudo_endpoint(
                    remotes[role],
                    args.run_id,
                    args.commit,
                    claim_sha256[role],
                    "export",
                ),
                f"export-{role}",
            )
            write_evidence_export(local_evidence, args.run_id, role, exported)
    for role in ("b82", "public"):
        if present[role]:
            sudo_endpoint(
                remotes[role],
                args.run_id,
                args.commit,
                claim_sha256[role],
                "purge",
            )
        cleanup_intake(remotes[role], args, artifacts)
    print(f"PUBLIC_CONTROLLER_CLEANUP_COMPLETE run_id={args.run_id} evidence={local_evidence}")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("plan", "probe", "run", "cleanup"))
    parser.add_argument("--run-id")
    parser.add_argument("--commit")
    parser.add_argument("--binary")
    parser.add_argument("--object")
    parser.add_argument("--seconds", type=int, default=120)
    parser.add_argument("--bits-per-second", type=int, default=384_000)
    parser.add_argument("--tcp-bytes", type=int, default=1_048_576)
    parser.add_argument("--ownership-token")
    parser.add_argument("--contract-sha256")
    args = parser.parse_args(argv)
    if args.mode in {"plan", "run", "cleanup"}:
        if not args.run_id or not RUN_ID_RE.fullmatch(args.run_id):
            stop("run-id", 64)
        if not args.commit or not COMMIT_RE.fullmatch(args.commit):
            stop("commit", 64)
        if args.mode == "plan" and args.ownership_token is None:
            args.ownership_token = secrets.token_hex(16)
        if not args.ownership_token or not OWNERSHIP_TOKEN_RE.fullmatch(
            args.ownership_token
        ):
            stop("ownership-token", 64)
    if args.mode in {"plan", "run", "cleanup"} and (not args.binary or not args.object):
        stop("artifacts", 64)
    if args.mode in {"run", "cleanup"} and (
        not args.contract_sha256 or not SHA256_RE.fullmatch(args.contract_sha256)
    ):
        stop("contract-sha256", 64)
    if not 30 <= args.seconds <= 900 or not 1 <= args.bits_per_second <= 1_000_000 or not 1 <= args.tcp_bytes <= 8 * 1024 * 1024:
        stop("traffic-bounds", 64)
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    paths = script_paths()
    if args.mode == "probe":
        probes = {
            role: probe_one(Remote(paths["transport"], role)) for role in ROLES
        }
        print(json.dumps({"schema": "wg-mix-public-probes-v1", "probes": probes}, indent=2, sort_keys=True))
        return 0 if all(item["eligible"] for item in probes.values()) else 77
    if args.mode == "plan":
        artifacts = artifact_contract(args, paths)
        contract = execution_contract(args, paths, artifacts)
        digest = contract_sha256(contract)
        print(
            json.dumps(
                {
                    "schema": "wg-mix-public-plan-v1",
                    "contract": contract,
                    "contract_sha256": digest,
                    "run_argv": frozen_run_argv(args, paths, digest),
                    "cleanup_argv": frozen_cleanup_argv(args, paths, digest),
                    "credential_read": 0,
                    "network_operations": 0,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    artifacts = artifact_contract(args, paths)
    contract = execution_contract(args, paths, artifacts)
    observed_contract = contract_sha256(contract)
    if not hmac.compare_digest(observed_contract, args.contract_sha256):
        stop("contract-drift", 66)
    if not contract["source"]["worktree_clean"]:
        stop("source-worktree-dirty", 66)
    if args.mode == "cleanup":
        cleanup(args, paths, artifacts)
    else:
        run_test(args, paths, artifacts)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
