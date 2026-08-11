#!/usr/bin/env python3
"""Bounded controller for the standalone two-host public BPF smoke test."""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, NoReturn


RUN_ID_RE = re.compile(r"^[0-9a-f]{12,24}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
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
    "/usr/bin/python3",
    "/usr/bin/ping",
    "/usr/bin/sha256sum",
    "/usr/bin/stat",
    "/usr/bin/sudo",
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
    eligible = (
        host_ok
        and isinstance(link, list)
        and len(link) == 1
        and not missing
        and bpffs
        and parsed_kernel is not None
        and parsed_kernel >= spec["minimum_kernel"]
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
        "eligible": eligible,
    }


def remote_layout(run_id: str, role: str) -> tuple[str, str]:
    return (
        f"/tmp/wg-mix-public-smoke-{run_id}-{role}-intake",
        f"/run/wg-mix-ebpf-public-smoke-{run_id}-{role}",
    )


def sudo_endpoint(remote: Remote, run_id: str, commit: str, *argv: str) -> str:
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
        "endpoint": {"path": str(paths["endpoint"]), "sha256": safe_local_file(paths["endpoint"], executable=True)},
        "traffic": {"path": str(paths["traffic"]), "sha256": safe_local_file(paths["traffic"], executable=True)},
        "binary": {"path": str(binary), "sha256": safe_local_file(binary, executable=True)},
        "object": {"path": str(object_path), "sha256": safe_local_file(object_path)},
    }


def stage_one(
    remote: Remote,
    run_id: str,
    commit: str,
    artifacts: dict[str, Any],
) -> str:
    intake, root = remote_layout(run_id, remote.role)
    remote.ssh("/usr/bin/mkdir", "--mode=700", "--", intake)
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
        "/usr/bin/install",
        "-d",
        "-m0700",
        "-oroot",
        "-groot",
        root,
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
        f"{intake}/root-endpoint.py",
        f"{root}/root-endpoint.py",
    )
    output = sudo_endpoint(
        remote,
        run_id,
        commit,
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


def sample_both(remotes: dict[str, Remote], run_id: str, commit: str) -> dict[str, Any]:
    result = {}
    for role, remote in remotes.items():
        output = sudo_endpoint(remote, run_id, commit, "sample")
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


def cleanup_intake(remote: Remote, run_id: str) -> None:
    intake, _ = remote_layout(run_id, remote.role)
    remote.ssh(
        "/usr/bin/rm",
        "--",
        f"{intake}/root-endpoint.py",
        f"{intake}/traffic.py",
        f"{intake}/wg-mix-ebpf",
        f"{intake}/wg_mix_tc.o",
    )
    remote.ssh("/usr/bin/rmdir", "--", intake)


def write_evidence_export(local_root: Path, role: str, document: dict[str, Any]) -> None:
    if (
        document.get("schema") != "wg-mix-public-evidence-export-v1"
        or document.get("role") != role
        or not isinstance(document.get("files"), dict)
    ):
        stop(f"export-shape:{role}", 77)
    target = local_root / role
    target.mkdir(mode=0o700)
    for name, encoded in document["files"].items():
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
            stop(f"export-name:{role}", 77)
        try:
            data = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError):
            stop(f"export-data:{role}", 77)
        path = target / name
        with path.open("xb") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(data)


def create_local_evidence(run_id: str) -> Path:
    root = Path(f"/private/tmp/wg-mix-public-smoke-evidence-{run_id}")
    try:
        root.mkdir(mode=0o700)
    except OSError:
        stop("local-evidence-exists", 73)
    return root


def run_test(args: argparse.Namespace, paths: dict[str, Path]) -> None:
    remotes = {role: Remote(paths["transport"], role) for role in ROLES}
    probes = {role: probe_one(remote) for role, remote in remotes.items()}
    print(json.dumps({"schema": "wg-mix-public-probes-v1", "probes": probes}, sort_keys=True))
    if not all(item["eligible"] for item in probes.values()):
        stop("probe-ineligible", 77)
    artifacts = artifact_contract(args, paths)
    keys: dict[str, str] = {}
    for role in ("public", "b82"):
        keys[role] = stage_one(remotes[role], args.run_id, args.commit, artifacts)
    sudo_endpoint(remotes["public"], args.run_id, args.commit, "apply", "--peer-public-key", keys["b82"])
    sudo_endpoint(remotes["b82"], args.run_id, args.commit, "apply", "--peer-public-key", keys["public"])
    for role in ("public", "b82"):
        sudo_endpoint(remotes[role], args.run_id, args.commit, "server", "--seconds", str(args.seconds + 120))
        sudo_endpoint(remotes[role], args.run_id, args.commit, "capture", "--seconds", str(args.seconds + 120))
    samples = [sample_both(remotes, args.run_id, args.commit)]
    tasks: dict[str, concurrent.futures.Future[str]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        for role, remote in remotes.items():
            tasks[f"ping-{role}"] = executor.submit(
                sudo_endpoint,
                remote,
                args.run_id,
                args.commit,
                "ping",
                "--count",
                str(args.seconds),
            )
            tasks[f"udp-{role}"] = executor.submit(
                sudo_endpoint,
                remote,
                args.run_id,
                args.commit,
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
            samples.append(sample_both(remotes, args.run_id, args.commit))
        traffic = {name: future.result() for name, future in tasks.items()}
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        tcp_futures = {
            role: executor.submit(
                sudo_endpoint,
                remote,
                args.run_id,
                args.commit,
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
    samples.append(sample_both(remotes, args.run_id, args.commit))
    ping_parts = [parse_ping(traffic[f"ping-{role}"], args.seconds) for role in ROLES]
    ping = {
        "transmitted": sum(item["transmitted"] for item in ping_parts),
        "received": sum(item["received"] for item in ping_parts),
        "max_consecutive_loss": max(item["max_consecutive_loss"] for item in ping_parts),
    }
    local_evidence = create_local_evidence(args.run_id)
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
        sudo_endpoint(remotes[role], args.run_id, args.commit, "restore")
    for role in ROLES:
        exported = parse_json_line(
            sudo_endpoint(remotes[role], args.run_id, args.commit, "export"),
            f"export-{role}",
        )
        write_evidence_export(local_evidence, role, exported)
    for role in ("b82", "public"):
        sudo_endpoint(remotes[role], args.run_id, args.commit, "purge")
        cleanup_intake(remotes[role], args.run_id)
    print(
        f"PUBLIC_CONTROLLER_COMPLETE run_id={args.run_id} commit={args.commit} "
        f"evidence={local_evidence} restored=1 purged=1"
    )


def cleanup(args: argparse.Namespace, paths: dict[str, Path]) -> None:
    remotes = {role: Remote(paths["transport"], role) for role in ROLES}
    local_evidence = create_local_evidence(args.run_id)
    for role in ("b82", "public"):
        sudo_endpoint(remotes[role], args.run_id, args.commit, "restore")
    for role in ROLES:
        exported = parse_json_line(
            sudo_endpoint(remotes[role], args.run_id, args.commit, "export"),
            f"export-{role}",
        )
        write_evidence_export(local_evidence, role, exported)
    for role in ("b82", "public"):
        sudo_endpoint(remotes[role], args.run_id, args.commit, "purge")
        cleanup_intake(remotes[role], args.run_id)
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
    args = parser.parse_args(argv)
    if args.mode in {"plan", "run", "cleanup"}:
        if not args.run_id or not RUN_ID_RE.fullmatch(args.run_id):
            stop("run-id", 64)
        if not args.commit or not COMMIT_RE.fullmatch(args.commit):
            stop("commit", 64)
    if args.mode in {"plan", "run"} and (not args.binary or not args.object):
        stop("artifacts", 64)
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
        print(
            json.dumps(
                {
                    "schema": "wg-mix-public-plan-v1",
                    "run_id": args.run_id,
                    "commit": args.commit,
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
                    "credential_read": 0,
                    "network_operations": 0,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if args.mode == "cleanup":
        cleanup(args, paths)
    else:
        run_test(args, paths)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
