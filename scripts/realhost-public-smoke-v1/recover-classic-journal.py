#!/usr/bin/env python3
"""Recover one owned classic-TC journal with a newer, locally bound binary."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, NoReturn

from controller import (
    Remote,
    intake_claim_bytes,
    remote_directory_entries,
    remote_layout,
    safe_local_file,
    source_contract,
    verify_intake_claim,
    verify_root_claim,
)


RUN_ID_RE = re.compile(r"^[0-9a-f]{12,24}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
TOKEN_RE = re.compile(r"^[0-9a-f]{32}$")
ROLE = "public"
INTERFACE = "eth0"


def stop(reason: str, rc: int = 78) -> NoReturn:
    print(f"PUBLIC_RECOVERY_STOP reason={reason} rc={rc}", file=sys.stderr)
    raise SystemExit(rc)


def script_paths() -> dict[str, Path]:
    root = Path(__file__).resolve(strict=True).parent
    paths = {
        "recovery": root / "recover-classic-journal.py",
        "controller": root / "controller.py",
        "transport": root / "transport.exp",
        "endpoint": root / "root-endpoint.py",
        "traffic": root / "traffic.py",
    }
    for name, path in paths.items():
        safe_local_file(path, executable=True)
    return paths


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def old_artifacts(args: argparse.Namespace, paths: dict[str, Path]) -> dict[str, Any]:
    return {
        "binary": {"sha256": args.old_binary_sha256},
        "endpoint": {"sha256": sha256_file(paths["endpoint"])},
        "object": {"sha256": args.object_sha256},
        "traffic": {"sha256": sha256_file(paths["traffic"])},
    }


def old_claim_args(args: argparse.Namespace) -> SimpleNamespace:
    return SimpleNamespace(
        run_id=args.old_run_id,
        commit=args.old_commit,
        ownership_token=args.ownership_token,
    )


def recovery_names(args: argparse.Namespace) -> tuple[str, str, str, str]:
    intake, root = remote_layout(args.old_run_id, ROLE)
    name = f"wg-mix-ebpf-recovery-{args.recovery_id}"
    return intake, root, f"{intake}/{name}", f"{root}/{name}"


def detach_argv(args: argparse.Namespace) -> list[str]:
    _, old_root, _, recovery_binary = recovery_names(args)
    pin_path = f"/sys/fs/bpf/wg-mix-ebpf-public-smoke-{args.old_run_id}-public"
    return [
        "/usr/bin/sudo",
        "-S",
        "-p",
        "PUBLIC_SUDO_PASSWORD:",
        "/usr/bin/env",
        "LC_ALL=C",
        "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
        f"WG_MIX_EBPF_OBJECT={old_root}/wg_mix_tc.o",
        f"WG_MIX_EBPF_PIN_PATH={pin_path}",
        recovery_binary,
        "detach",
        "--config",
        f"{old_root}/agent.yaml",
        "--run-dir",
        f"{old_root}/runtime",
        "--state-dir",
        f"{old_root}/state",
    ]


def contract(args: argparse.Namespace, paths: dict[str, Path]) -> dict[str, Any]:
    binary = Path(args.binary).resolve(strict=True)
    if safe_local_file(binary, executable=True) != args.binary_sha256:
        stop("binary-sha256", 66)
    artifacts = old_artifacts(args, paths)
    claim = intake_claim_bytes(old_claim_args(args), ROLE, artifacts)
    intake, root, intake_binary, root_binary = recovery_names(args)
    pin_path = f"/sys/fs/bpf/wg-mix-ebpf-public-smoke-{args.old_run_id}-public"
    return {
        "schema": "wg-mix-public-classic-journal-recovery-v1",
        "recovery_id": args.recovery_id,
        "old_run_id": args.old_run_id,
        "old_commit": args.old_commit,
        "new_commit": args.new_commit,
        "role": ROLE,
        "host": "47.116.202.155",
        "interface": INTERFACE,
        "source": source_contract(args.new_commit, paths),
        "artifacts": {
            "recovery": sha256_file(paths["recovery"]),
            "controller": sha256_file(paths["controller"]),
            "transport": sha256_file(paths["transport"]),
            "endpoint": artifacts["endpoint"]["sha256"],
            "traffic": artifacts["traffic"]["sha256"],
            "old_binary": args.old_binary_sha256,
            "object": args.object_sha256,
            "recovery_binary": args.binary_sha256,
        },
        "old_claim_sha256": hashlib.sha256(claim).hexdigest(),
        "old_claim_size": len(claim),
        "detach_argv": detach_argv(args),
        "write_set": {
            "temporary": [intake_binary, root_binary],
            "owned_recovery": [
                pin_path,
                "classic_tc:eth0:priority49152:handles0x10001+0x10002",
                "/var/lib/wg-mix-ebpf/pin-owners/instances.v2.json",
                "/var/lib/wg-mix-ebpf/pin-owners/<owned-resource-files>",
                "/run/wg-mix-ebpf/pin-locks/<owned-resource-key>.lock",
            ],
            "preserved": [
                root,
                intake,
                "wireguard:wgps47",
                "qdisc:eth0:clsact",
                "firewall",
                "offload",
                "mtu",
            ],
        },
    }


def contract_sha256(value: dict[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def recover_argv(
    args: argparse.Namespace, digest: str, paths: dict[str, Path]
) -> list[str]:
    return [
        "/usr/bin/python3",
        str(paths["recovery"]),
        "recover",
        "--recovery-id",
        args.recovery_id,
        "--old-run-id",
        args.old_run_id,
        "--old-commit",
        args.old_commit,
        "--new-commit",
        args.new_commit,
        "--old-binary-sha256",
        args.old_binary_sha256,
        "--object-sha256",
        args.object_sha256,
        "--ownership-token",
        args.ownership_token,
        "--binary",
        str(Path(args.binary).resolve(strict=True)),
        "--binary-sha256",
        args.binary_sha256,
        "--contract-sha256",
        digest,
    ]


def exact_file(
    remote: Remote,
    path: str,
    digest: str,
    size: int,
    *,
    root_owned: bool,
) -> None:
    prefix = (
        ("/usr/bin/sudo", "-S", "-p", "PUBLIC_SUDO_PASSWORD:") if root_owned else ()
    )
    shape = remote.ssh(*prefix, "/usr/bin/stat", "-c", "%u:%g:%a:%h:%s:%F", path)
    parts = shape.split(":")
    if (
        len(parts) != 6
        or parts[2:] != ["700", "1", str(size), "regular file"]
        or (root_owned and parts[:2] != ["0", "0"])
    ):
        stop(f"recovery-file-shape:{'root' if root_owned else 'intake'}", 79)
    observed = remote.ssh(*prefix, "/usr/bin/sha256sum", "--", path)
    if observed != f"{digest}  {path}":
        stop(f"recovery-file-sha256:{'root' if root_owned else 'intake'}", 79)


def named_entry(remote: Remote, parent: str, name: str, *, privileged: bool) -> bool:
    prefix = (
        ("/usr/bin/sudo", "-S", "-p", "PUBLIC_SUDO_PASSWORD:") if privileged else ()
    )
    output = remote.ssh(
        *prefix,
        "/usr/bin/find",
        parent,
        "-maxdepth",
        "1",
        "-name",
        name,
        "-printf",
        "%f",
    )
    if output not in ("", name):
        stop("remote-entry", 79)
    return output == name


def verify_classic_removed(remote: Remote, args: argparse.Namespace) -> None:
    for direction in ("ingress", "egress"):
        output = remote.ssh(
            "/usr/sbin/tc", "-j", "filter", "show", "dev", INTERFACE, direction
        )
        try:
            filters = json.loads(output)
        except ValueError:
            stop(f"filter-json:{direction}", 79)
        if filters != []:
            stop(f"filter-remains:{direction}", 79)
    pin_name = f"wg-mix-ebpf-public-smoke-{args.old_run_id}-public"
    if named_entry(remote, "/sys/fs/bpf", pin_name, privileged=True):
        stop("pin-remains", 79)


def stage_recovery_binary(
    remote: Remote,
    args: argparse.Namespace,
    paths: dict[str, Path],
) -> tuple[str, str]:
    artifacts = old_artifacts(args, paths)
    verify_intake_claim(remote, old_claim_args(args), artifacts)
    verify_root_claim(remote, old_claim_args(args), artifacts)
    intake, root, intake_binary, root_binary = recovery_names(args)
    name = intake_binary.rsplit("/", 1)[1]
    binary = Path(args.binary).resolve(strict=True)
    size = binary.stat().st_size

    intake_entries = remote_directory_entries(remote, intake)
    expected_intake_entries = {
        "intake-owner.json",
        "root-endpoint.py",
        "traffic.py",
        "wg-mix-ebpf",
        "wg_mix_tc.o",
    }
    if set(intake_entries) not in (
        expected_intake_entries,
        expected_intake_entries | {name},
    ) or any(kind != "f" for kind in intake_entries.values()):
        stop("recovery-intake-foreign", 79)
    if name in intake_entries:
        if intake_entries[name] != "f":
            stop("recovery-intake-entry", 79)
        exact_file(remote, intake_binary, args.binary_sha256, size, root_owned=False)
    else:
        remote.scp(binary, intake_binary)
        remote.ssh("/usr/bin/chmod", "0700", "--", intake_binary)
        exact_file(remote, intake_binary, args.binary_sha256, size, root_owned=False)

    root_entries = remote_directory_entries(remote, root, privileged=True)
    if name in root_entries:
        if root_entries[name] != "f":
            stop("recovery-root-entry", 79)
        exact_file(remote, root_binary, args.binary_sha256, size, root_owned=True)
    else:
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
            intake_binary,
            root_binary,
        )
        exact_file(remote, root_binary, args.binary_sha256, size, root_owned=True)
    return intake_binary, root_binary


def remove_recovery_binary(
    remote: Remote,
    args: argparse.Namespace,
    intake_binary: str,
    root_binary: str,
) -> None:
    size = Path(args.binary).resolve(strict=True).stat().st_size
    exact_file(remote, root_binary, args.binary_sha256, size, root_owned=True)
    remote.ssh(
        "/usr/bin/sudo",
        "-S",
        "-p",
        "PUBLIC_SUDO_PASSWORD:",
        "/usr/bin/unlink",
        "--",
        root_binary,
    )
    exact_file(remote, intake_binary, args.binary_sha256, size, root_owned=False)
    remote.ssh("/usr/bin/unlink", "--", intake_binary)
    intake, root, _, _ = recovery_names(args)
    name = intake_binary.rsplit("/", 1)[1]
    if named_entry(remote, root, name, privileged=True) or named_entry(
        remote, intake, name, privileged=False
    ):
        stop("recovery-file-remains", 79)


def execute_recovery(args: argparse.Namespace, paths: dict[str, Path]) -> None:
    value = contract(args, paths)
    digest = contract_sha256(value)
    if args.contract_sha256 != digest:
        stop("contract-sha256", 66)
    remote = Remote(paths["transport"], ROLE)
    intake_binary, root_binary = stage_recovery_binary(remote, args, paths)
    remote.ssh(*detach_argv(args))
    verify_classic_removed(remote, args)
    remove_recovery_binary(remote, args, intake_binary, root_binary)
    print(
        "PUBLIC_CLASSIC_JOURNAL_RECOVERED "
        f"old_run_id={args.old_run_id} new_commit={args.new_commit} "
        "filters=0 pin=absent recovery_files=absent result=PASS"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("plan", "recover"))
    parser.add_argument("--recovery-id", required=True)
    parser.add_argument("--old-run-id", required=True)
    parser.add_argument("--old-commit", required=True)
    parser.add_argument("--new-commit", required=True)
    parser.add_argument("--old-binary-sha256", required=True)
    parser.add_argument("--object-sha256", required=True)
    parser.add_argument("--ownership-token", required=True)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument("--contract-sha256")
    args = parser.parse_args()
    if (
        not RUN_ID_RE.fullmatch(args.recovery_id)
        or not RUN_ID_RE.fullmatch(args.old_run_id)
        or not COMMIT_RE.fullmatch(args.old_commit)
        or not COMMIT_RE.fullmatch(args.new_commit)
        or not SHA256_RE.fullmatch(args.old_binary_sha256)
        or not SHA256_RE.fullmatch(args.object_sha256)
        or not SHA256_RE.fullmatch(args.binary_sha256)
        or not TOKEN_RE.fullmatch(args.ownership_token)
        or (
            args.contract_sha256 is not None
            and not SHA256_RE.fullmatch(args.contract_sha256)
        )
        or (args.mode == "recover" and args.contract_sha256 is None)
        or (args.mode == "plan" and args.contract_sha256 is not None)
    ):
        stop("arguments", 64)
    return args


def main() -> None:
    args = parse_args()
    paths = script_paths()
    value = contract(args, paths)
    digest = contract_sha256(value)
    if args.mode == "plan":
        print(json.dumps(value, sort_keys=True, indent=2))
        print(
            json.dumps(
                {
                    "contract_sha256": digest,
                    "recover_argv": recover_argv(args, digest, paths),
                    "remote_writes": 0,
                    "credential_read": 0,
                    "network_operations": 0,
                },
                sort_keys=True,
            )
        )
        return
    execute_recovery(args, paths)


if __name__ == "__main__":
    main()
