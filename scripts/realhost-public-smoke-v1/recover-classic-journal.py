#!/usr/bin/env python3
"""Recover one owned classic-TC or exact-TCX journal with a newer binary."""

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
ROLE = {
    "public": {
        "host": "47.116.202.155",
        "interface": "eth0",
        "backend": "classic_tc",
        "wg": "wgps47",
    },
    "b82": {
        "host": "192.168.10.82",
        "interface": "ens33",
        "backend": "tcx",
        "wg": "wgps82",
    },
}


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
    intake, root = remote_layout(args.old_run_id, args.role)
    name = f"wg-mix-ebpf-recovery-{args.recovery_id}"
    return intake, root, f"{intake}/{name}", f"{root}/{name}"


def recovery_state_dir(args: argparse.Namespace) -> str:
    _, root = remote_layout(args.old_run_id, args.role)
    return f"{root}/recovery-state-{args.recovery_id}"


def detach_argv(args: argparse.Namespace) -> list[str]:
    _, old_root, _, recovery_binary = recovery_names(args)
    pin_path = f"/sys/fs/bpf/wg-mix-ebpf-public-smoke-{args.old_run_id}-{args.role}"
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
        recovery_state_dir(args),
    ]


def contract(args: argparse.Namespace, paths: dict[str, Path]) -> dict[str, Any]:
    binary = Path(args.binary).resolve(strict=True)
    if safe_local_file(binary, executable=True) != args.binary_sha256:
        stop("binary-sha256", 66)
    artifacts = old_artifacts(args, paths)
    claim = intake_claim_bytes(old_claim_args(args), args.role, artifacts)
    intake, root, intake_binary, root_binary = recovery_names(args)
    role = ROLE[args.role]
    pin_path = f"/sys/fs/bpf/wg-mix-ebpf-public-smoke-{args.old_run_id}-{args.role}"
    backend_resource = (
        "classic_tc:eth0:priority49152:handles0x10001+0x10002"
        if args.role == "public"
        else (
            "tcx:ens33:"
            f"ingress-link{args.tcx_ingress_link_id}-program{args.tcx_ingress_program_id}+"
            f"egress-link{args.tcx_egress_link_id}-program{args.tcx_egress_program_id}"
        )
    )
    owned_recovery = [
        pin_path,
        backend_resource,
        "/var/lib/wg-mix-ebpf/pin-owners/instances.v2.json",
        "/var/lib/wg-mix-ebpf/pin-owners/<owned-resource-files>",
        "/run/wg-mix-ebpf/pin-locks/<owned-resource-key>.lock",
    ]
    shared_lifecycle_and_lock = [
        "/run/.wg-mix-ebpf-daemon.lease.maintenance",
        "/run/wg-mix-ebpf/daemon.lease",
        f"{root}/runtime/lock",
    ]
    preserved = [
        root,
        intake,
        f"wireguard:{role['wg']}",
        f"qdisc:{role['interface']}:clsact",
        "firewall",
        "offload",
        "mtu",
        f"{root}/state/attach-state.json",
        f"absent:{recovery_state_dir(args)}",
    ]
    return {
        "schema": "wg-mix-public-owned-journal-recovery-v1",
        "operation": args.operation,
        "recovery_id": args.recovery_id,
        "old_run_id": args.old_run_id,
        "old_commit": args.old_commit,
        "new_commit": args.new_commit,
        "role": args.role,
        "host": role["host"],
        "interface": role["interface"],
        "attachment_backend": role["backend"],
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
        "expected_tcx_links": (
            []
            if args.role == "public" or args.operation == "cleanup-staged"
            else [
                {
                    "direction": "ingress",
                    "link_id": args.tcx_ingress_link_id,
                    "program_id": args.tcx_ingress_program_id,
                },
                {
                    "direction": "egress",
                    "link_id": args.tcx_egress_link_id,
                    "program_id": args.tcx_egress_program_id,
                },
            ]
        ),
        "detach_argv": detach_argv(args) if args.operation == "recover" else [],
        "write_set": (
            {
                "temporary": [intake_binary, root_binary],
                "owned_recovery": owned_recovery,
                "shared_lifecycle_and_lock": shared_lifecycle_and_lock,
                "preserved": preserved,
            }
            if args.operation == "recover"
            else {
                "removed": [intake_binary, root_binary],
                "preserved": [*preserved, *owned_recovery, *shared_lifecycle_and_lock],
            }
        ),
    }


def contract_sha256(value: dict[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def execute_argv(
    args: argparse.Namespace, digest: str, paths: dict[str, Path]
) -> list[str]:
    return [
        "/usr/bin/python3",
        str(paths["recovery"]),
        args.operation,
        "--operation",
        args.operation,
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
        "<redacted>",
        "--binary",
        str(Path(args.binary).resolve(strict=True)),
        "--binary-sha256",
        args.binary_sha256,
        "--role",
        args.role,
        "--tcx-ingress-link-id",
        str(args.tcx_ingress_link_id),
        "--tcx-ingress-program-id",
        str(args.tcx_ingress_program_id),
        "--tcx-egress-link-id",
        str(args.tcx_egress_link_id),
        "--tcx-egress-program-id",
        str(args.tcx_egress_program_id),
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
    expected_owner: tuple[str, str] | None = None,
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
        or (not root_owned and (expected_owner is None or parts[:2] != list(expected_owner)))
    ):
        stop(f"recovery-file-shape:{'root' if root_owned else 'intake'}", 79)
    observed = remote.ssh(*prefix, "/usr/bin/sha256sum", "--", path)
    if observed != f"{digest}  {path}":
        stop(f"recovery-file-sha256:{'root' if root_owned else 'intake'}", 79)


def intake_owner(remote: Remote, intake: str) -> tuple[str, str]:
    shape = remote.ssh("/usr/bin/stat", "-c", "%u:%g:%a:%F", intake)
    parts = shape.split(":")
    if len(parts) != 4 or parts[2:] != ["700", "directory"]:
        stop("recovery-intake-shape", 79)
    return parts[0], parts[1]


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


def bpftool_links(remote: Remote) -> list[dict[str, Any]]:
    output = remote.ssh(
        "/usr/bin/sudo",
        "-S",
        "-p",
        "PUBLIC_SUDO_PASSWORD:",
        "/usr/sbin/bpftool",
        "-j",
        "link",
        "show",
    )
    try:
        links = json.loads(output)
    except ValueError:
        stop("tcx-link-json", 79)
    if not isinstance(links, list) or any(not isinstance(item, dict) for item in links):
        stop("tcx-link-json", 79)
    return links


def interface_ifindex(remote: Remote, args: argparse.Namespace) -> int:
    interface = ROLE[args.role]["interface"]
    output = remote.ssh("/usr/sbin/ip", "-j", "link", "show", "dev", interface)
    try:
        links = json.loads(output)
    except ValueError:
        stop("interface-json", 79)
    if (
        not isinstance(links, list)
        or len(links) != 1
        or not isinstance(links[0], dict)
        or links[0].get("ifname") != interface
        or not isinstance(links[0].get("ifindex"), int)
        or links[0]["ifindex"] <= 0
    ):
        stop("interface-identity", 79)
    return links[0]["ifindex"]


def matching_tcx_link_ids(remote: Remote, args: argparse.Namespace) -> set[int]:
    expected = {
        args.tcx_ingress_link_id: (args.tcx_ingress_program_id, "tcx_ingress"),
        args.tcx_egress_link_id: (args.tcx_egress_program_id, "tcx_egress"),
    }
    ifindex = interface_ifindex(remote, args)
    observed = {item.get("id"): item for item in bpftool_links(remote)}
    matching: set[int] = set()
    for link_id, (program_id, attach_type) in expected.items():
        item = observed.get(link_id)
        if item is None:
            continue
        if (
            item.get("type") != "tcx"
            or item.get("ifindex") != ifindex
            or item.get("attach_type") != attach_type
            or item.get("prog_id") != program_id
        ):
            stop(f"tcx-link-identity:{link_id}", 79)
        matching.add(link_id)
    return matching


def verify_tcx_links(remote: Remote, args: argparse.Namespace, *, present: bool) -> None:
    matching = matching_tcx_link_ids(remote, args)
    expected = {args.tcx_ingress_link_id, args.tcx_egress_link_id}
    if present and matching != expected:
        stop("tcx-links-incomplete", 79)
    if not present and matching:
        stop(f"tcx-link-remains:{min(matching)}", 79)


def verify_backend_removed(remote: Remote, args: argparse.Namespace) -> None:
    if args.role == "b82":
        verify_tcx_links(remote, args, present=False)
    else:
        interface = ROLE[args.role]["interface"]
        for direction in ("ingress", "egress"):
            output = remote.ssh(
                "/usr/sbin/tc", "-j", "filter", "show", "dev", interface, direction
            )
            try:
                filters = json.loads(output)
            except ValueError:
                stop(f"filter-json:{direction}", 79)
            if filters != []:
                stop(f"filter-remains:{direction}", 79)
    pin_name = f"wg-mix-ebpf-public-smoke-{args.old_run_id}-{args.role}"
    if named_entry(remote, "/sys/fs/bpf", pin_name, privileged=True):
        stop("pin-remains", 79)


def attach_state_snapshot(
    remote: Remote, args: argparse.Namespace
) -> tuple[str, str] | None:
    _, root = remote_layout(args.old_run_id, args.role)
    state_dir = f"{root}/state"
    entries = remote_directory_entries(remote, state_dir, privileged=True)
    if entries not in ({}, {"attach-state.json": "f"}):
        stop("attach-state-foreign", 79)
    if not entries:
        return None
    path = f"{state_dir}/attach-state.json"
    prefix = ("/usr/bin/sudo", "-S", "-p", "PUBLIC_SUDO_PASSWORD:")
    shape = remote.ssh(*prefix, "/usr/bin/stat", "-c", "%u:%g:%a:%h:%s:%F", path)
    parts = shape.split(":")
    if (
        len(parts) != 6
        or parts[:4] != ["0", "0", "600", "1"]
        or not parts[4].isdigit()
        or parts[5] != "regular file"
    ):
        stop("attach-state-shape", 79)
    digest = remote.ssh(*prefix, "/usr/bin/sha256sum", "--", path)
    if not digest.endswith(f"  {path}") or not SHA256_RE.fullmatch(
        digest.removesuffix(f"  {path}")
    ):
        stop("attach-state-sha256", 79)
    return shape, digest


def stage_recovery_binary(
    remote: Remote,
    args: argparse.Namespace,
    paths: dict[str, Path],
) -> tuple[str, str]:
    artifacts = old_artifacts(args, paths)
    verify_intake_claim(remote, old_claim_args(args), artifacts)
    verify_root_claim(remote, old_claim_args(args), artifacts)
    intake, root, intake_binary, root_binary = recovery_names(args)
    expected_intake_owner = intake_owner(remote, intake)
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
        exact_file(
            remote,
            intake_binary,
            args.binary_sha256,
            size,
            root_owned=False,
            expected_owner=expected_intake_owner,
        )
    else:
        remote.scp(binary, intake_binary)
        remote.ssh("/usr/bin/chmod", "0700", "--", intake_binary)
        exact_file(
            remote,
            intake_binary,
            args.binary_sha256,
            size,
            root_owned=False,
            expected_owner=expected_intake_owner,
        )

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
    intake, root, _, _ = recovery_names(args)
    name = intake_binary.rsplit("/", 1)[1]
    expected_intake_owner = intake_owner(remote, intake)
    root_present = named_entry(remote, root, name, privileged=True)
    intake_present = named_entry(remote, intake, name, privileged=False)
    if root_present:
        exact_file(remote, root_binary, args.binary_sha256, size, root_owned=True)
    if intake_present:
        exact_file(
            remote,
            intake_binary,
            args.binary_sha256,
            size,
            root_owned=False,
            expected_owner=expected_intake_owner,
        )
    if root_present:
        remote.ssh(
            "/usr/bin/sudo",
            "-S",
            "-p",
            "PUBLIC_SUDO_PASSWORD:",
            "/usr/bin/unlink",
            "--",
            root_binary,
        )
    if intake_present:
        remote.ssh("/usr/bin/unlink", "--", intake_binary)
    if named_entry(remote, root, name, privileged=True) or named_entry(
        remote, intake, name, privileged=False
    ):
        stop("recovery-file-remains", 79)


def execute_recovery(args: argparse.Namespace, paths: dict[str, Path]) -> None:
    value = contract(args, paths)
    digest = contract_sha256(value)
    if args.contract_sha256 != digest:
        stop("contract-sha256", 66)
    remote = Remote(paths["transport"], args.role)
    intake_binary, root_binary = stage_recovery_binary(remote, args, paths)
    _, root = remote_layout(args.old_run_id, args.role)
    recovery_state_name = recovery_state_dir(args).rsplit("/", 1)[1]
    if named_entry(remote, root, recovery_state_name, privileged=True):
        stop("recovery-state-exists", 79)
    before_state = attach_state_snapshot(remote, args)
    if args.role == "b82":
        matching_tcx_link_ids(remote, args)
    remote.ssh(*detach_argv(args))
    verify_backend_removed(remote, args)
    if named_entry(remote, root, recovery_state_name, privileged=True):
        stop("recovery-state-created", 79)
    if attach_state_snapshot(remote, args) != before_state:
        stop("attach-state-changed", 79)
    remove_recovery_binary(remote, args, intake_binary, root_binary)
    print(
        "PUBLIC_OWNED_JOURNAL_RECOVERED "
        f"old_run_id={args.old_run_id} new_commit={args.new_commit} "
        f"role={args.role} backend={ROLE[args.role]['backend']} "
        "owned_links=absent pin=absent recovery_files=absent result=PASS"
    )


def execute_cleanup_staged(
    args: argparse.Namespace, paths: dict[str, Path]
) -> None:
    value = contract(args, paths)
    digest = contract_sha256(value)
    if args.contract_sha256 != digest:
        stop("contract-sha256", 66)
    remote = Remote(paths["transport"], args.role)
    artifacts = old_artifacts(args, paths)
    verify_intake_claim(remote, old_claim_args(args), artifacts)
    verify_root_claim(remote, old_claim_args(args), artifacts)
    _, _, intake_binary, root_binary = recovery_names(args)
    remove_recovery_binary(remote, args, intake_binary, root_binary)
    print(
        "PUBLIC_RECOVERY_FILES_REMOVED "
        f"old_run_id={args.old_run_id} recovery_id={args.recovery_id} "
        f"role={args.role} owner_journal=preserved pin=preserved result=PASS"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("plan", "recover", "cleanup-staged"))
    parser.add_argument("--operation", choices=("recover", "cleanup-staged"), required=True)
    parser.add_argument("--recovery-id", required=True)
    parser.add_argument("--old-run-id", required=True)
    parser.add_argument("--old-commit", required=True)
    parser.add_argument("--new-commit", required=True)
    parser.add_argument("--old-binary-sha256", required=True)
    parser.add_argument("--object-sha256", required=True)
    parser.add_argument("--ownership-token", required=True)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument("--role", choices=tuple(ROLE), default="public")
    parser.add_argument("--tcx-ingress-link-id", type=int, default=0)
    parser.add_argument("--tcx-ingress-program-id", type=int, default=0)
    parser.add_argument("--tcx-egress-link-id", type=int, default=0)
    parser.add_argument("--tcx-egress-program-id", type=int, default=0)
    parser.add_argument("--contract-sha256")
    args = parser.parse_args()
    tcx_values = (
        args.tcx_ingress_link_id,
        args.tcx_ingress_program_id,
        args.tcx_egress_link_id,
        args.tcx_egress_program_id,
    )
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
        or (args.mode == "cleanup-staged" and args.contract_sha256 is None)
        or (args.mode == "plan" and args.contract_sha256 is not None)
        or (args.mode != "plan" and args.mode != args.operation)
        or (args.role == "public" and tcx_values != (0, 0, 0, 0))
        or (
            args.role == "b82"
            and (
                any(value <= 0 for value in tcx_values)
                or args.tcx_ingress_link_id == args.tcx_egress_link_id
            )
        )
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
                    "execute_argv": execute_argv(args, digest, paths),
                    "ownership_token_redacted": 1,
                    "remote_writes": 0,
                    "credential_read": 0,
                    "network_operations": 0,
                },
                sort_keys=True,
            )
        )
        return
    if args.mode == "recover":
        execute_recovery(args, paths)
    else:
        execute_cleanup_staged(args, paths)


if __name__ == "__main__":
    main()
