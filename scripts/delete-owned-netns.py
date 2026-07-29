#!/usr/bin/env python3
"""Delete one run-owned network namespace after a final identity check."""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import stat
import subprocess
import sys
from collections.abc import Callable


class ContractError(RuntimeError):
    pass


DeleteRunner = Callable[[str], int]
BeforeFinalRecheck = Callable[[], None]


def canonical_absolute_path(value: str, label: str) -> pathlib.Path:
    path = pathlib.Path(value)
    if not path.is_absolute() or os.path.normpath(value) != value:
        raise ContractError(
            f"{label} is not a canonical absolute path: {value!r}"
        )
    return path


def validate_identity_request(
    *,
    name: str,
    run_id: str,
    role: str,
    expected_device: int,
    expected_inode: int,
) -> None:
    if not re.fullmatch(r"[0-9a-f]{8}", run_id):
        raise ContractError("run ID is not eight lowercase hex characters")
    if role not in {"a", "r", "b"}:
        raise ContractError(f"unsupported network namespace role: {role!r}")
    expected_name = f"wme{run_id}{role}"
    if name != expected_name:
        raise ContractError(
            f"network namespace name {name!r} does not match "
            f"role {role!r}: {expected_name!r}"
        )
    if expected_device <= 0 or expected_inode <= 0:
        raise ContractError("network namespace identity is not sealed")


def verify_netns_root(path: pathlib.Path) -> int:
    metadata = os.lstat(path)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or path.resolve(strict=True) != path
    ):
        raise ContractError(
            f"network namespace root is not an exact directory: {path}"
        )
    return os.open(
        path,
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_CLOEXEC
        | getattr(os, "O_NOFOLLOW", 0),
    )


def open_verified_target(
    *,
    root_fd: int,
    name: str,
    expected_device: int,
    expected_inode: int,
) -> tuple[int, os.stat_result]:
    target_fd = os.open(
        name,
        getattr(os, "O_PATH", os.O_RDONLY)
        | os.O_CLOEXEC
        | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=root_fd,
    )
    try:
        metadata = os.fstat(target_fd)
        path_metadata = os.stat(
            name,
            dir_fd=root_fd,
            follow_symlinks=False,
        )
        expected = (expected_device, expected_inode)
        if (
            stat.S_ISLNK(path_metadata.st_mode)
            or (metadata.st_dev, metadata.st_ino) != expected
            or (path_metadata.st_dev, path_metadata.st_ino) != expected
        ):
            raise ContractError(
                "network namespace pathname identity does not match "
                f"sealed identity {expected_device}:{expected_inode}"
            )
        return target_fd, metadata
    except BaseException:
        os.close(target_fd)
        raise


def recheck_verified_target(
    *,
    root_fd: int,
    target_fd: int,
    name: str,
    expected_metadata: os.stat_result,
) -> None:
    metadata = os.fstat(target_fd)
    path_metadata = os.stat(
        name,
        dir_fd=root_fd,
        follow_symlinks=False,
    )
    expected = (expected_metadata.st_dev, expected_metadata.st_ino)
    if (
        stat.S_ISLNK(path_metadata.st_mode)
        or (metadata.st_dev, metadata.st_ino) != expected
        or (path_metadata.st_dev, path_metadata.st_ino) != expected
    ):
        raise ContractError(
            "network namespace pathname identity changed before delete"
        )


def delete_owned_netns(
    *,
    netns_root: pathlib.Path,
    name: str,
    run_id: str,
    role: str,
    expected_device: int,
    expected_inode: int,
    delete_runner: DeleteRunner,
    before_final_recheck: BeforeFinalRecheck | None = None,
) -> None:
    validate_identity_request(
        name=name,
        run_id=run_id,
        role=role,
        expected_device=expected_device,
        expected_inode=expected_inode,
    )
    root_fd = verify_netns_root(netns_root)
    target_fd = -1
    try:
        target_fd, metadata = open_verified_target(
            root_fd=root_fd,
            name=name,
            expected_device=expected_device,
            expected_inode=expected_inode,
        )
        if before_final_recheck is not None:
            before_final_recheck()
        recheck_verified_target(
            root_fd=root_fd,
            target_fd=target_fd,
            name=name,
            expected_metadata=metadata,
        )
        status = delete_runner(name)
        if status != 0:
            raise ContractError(
                f"ip netns delete failed for {name}: exit={status}"
            )
        try:
            os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ContractError(
                "network namespace pathname still exists after delete"
            )
    finally:
        if target_fd >= 0:
            os.close(target_fd)
        os.close(root_fd)


def validate_ip_binary(path: pathlib.Path) -> None:
    metadata = os.stat(path, follow_symlinks=False)
    if (
        path.resolve(strict=True) != path
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & 0o022
        or not os.access(path, os.X_OK)
    ):
        raise ContractError(
            f"ip binary is not an exact root-owned non-writable executable: {path}"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--role", required=True)
    parser.add_argument("--expected-device", type=int, required=True)
    parser.add_argument("--expected-inode", type=int, required=True)
    parser.add_argument("--ip-bin", required=True)
    return parser.parse_args()


def main() -> int:
    try:
        if os.geteuid() != 0:
            raise ContractError("network namespace deletion requires root")
        args = parse_args()
        ip_binary = canonical_absolute_path(args.ip_bin, "ip binary")
        validate_ip_binary(ip_binary)
        print(
            "netns delete boundary: final FD/path identity is checked "
            "immediately before one fixed ip argv; iproute2 deletion remains "
            "name-resolved and is not claimed atomic against concurrent root",
            file=sys.stderr,
        )

        def run_delete(name: str) -> int:
            return subprocess.run(
                [str(ip_binary), "netns", "delete", name],
                check=False,
            ).returncode

        delete_owned_netns(
            netns_root=pathlib.Path("/run/netns"),
            name=args.name,
            run_id=args.run_id,
            role=args.role,
            expected_device=args.expected_device,
            expected_inode=args.expected_inode,
            delete_runner=run_delete,
        )
    except (ContractError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
