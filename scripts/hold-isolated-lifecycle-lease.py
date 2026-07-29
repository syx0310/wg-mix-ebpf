#!/usr/bin/env python3
import argparse
import fcntl
import json
import os
import pathlib
import re
import signal
import stat
import sys
import time


class ContractError(RuntimeError):
    pass


def canonical_absolute_path(value: str, label: str) -> pathlib.Path:
    path = pathlib.Path(value)
    if not path.is_absolute() or os.path.normpath(value) != value:
        raise ContractError(f"{label} is not a canonical absolute path: {value!r}")
    return path


def verify_directory(path: pathlib.Path, expected_uid: int) -> os.stat_result:
    metadata = os.lstat(path)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ContractError(
            f"directory must be owned by uid {expected_uid} with mode 0700: {path}"
        )
    if path.resolve(strict=True) != path:
        raise ContractError(f"directory path contains a symlink: {path}")
    return metadata


def open_verified_file(
    path: pathlib.Path,
    expected_uid: int,
    flags: int,
) -> tuple[int, os.stat_result]:
    fd = os.open(
        path,
        flags | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        metadata = os.fstat(fd)
        path_metadata = os.lstat(path)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(path_metadata.st_mode)
            or metadata.st_uid != expected_uid
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or (metadata.st_dev, metadata.st_ino)
            != (path_metadata.st_dev, path_metadata.st_ino)
        ):
            raise ContractError(
                f"file must be an exact uid {expected_uid}, mode 0600, "
                f"single-link regular file: {path}"
            )
        return fd, metadata
    except BaseException:
        os.close(fd)
        raise


def recheck_verified_file(
    path: pathlib.Path,
    fd: int,
    expected_uid: int,
    expected_metadata: os.stat_result,
    label: str,
) -> os.stat_result:
    metadata = os.fstat(fd)
    path_metadata = os.lstat(path)
    if (
        (metadata.st_dev, metadata.st_ino)
        != (expected_metadata.st_dev, expected_metadata.st_ino)
        or (path_metadata.st_dev, path_metadata.st_ino)
        != (expected_metadata.st_dev, expected_metadata.st_ino)
    ):
        raise ContractError(f"{label} pathname identity changed")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(path_metadata.st_mode)
        or metadata.st_uid != expected_uid
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
    ):
        raise ContractError(
            f"{label} must remain an exact uid {expected_uid}, mode 0600, "
            "single-link regular file"
        )
    return metadata


def read_exact_file(fd: int, metadata: os.stat_result, maximum: int) -> bytes:
    if metadata.st_size <= 0 or metadata.st_size > maximum:
        raise ContractError(
            f"file size {metadata.st_size} is outside 1..{maximum} bytes"
        )
    data = os.pread(fd, metadata.st_size + 1, 0)
    if len(data) != metadata.st_size:
        raise ContractError("short or unstable file read")
    return data


def parse_manifest(data: bytes) -> dict[str, str]:
    if (
        not data.endswith(b"\n")
        or b"\0" in data
        or b"\r" in data
    ):
        raise ContractError("manifest must be newline-terminated without NUL or CR")
    values: dict[str, str] = {}
    for number, raw_line in enumerate(data[:-1].split(b"\n"), start=1):
        try:
            line = raw_line.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ContractError(f"manifest line {number} is not UTF-8") from exc
        key, separator, value = line.partition("=")
        if (
            separator != "="
            or not re.fullmatch(r"[a-z][a-z0-9_]*", key)
            or not value
            or value.strip() != value
            or key in values
        ):
            raise ContractError(f"manifest line {number} is not canonical")
        values[key] = value
    return values


def validate_manifest(
    data: bytes,
    *,
    manifest_path: pathlib.Path,
    lease_path: pathlib.Path,
    run_base: pathlib.Path,
    run_id: str,
    owner_token: str,
    boot_id: str,
    expected_config: pathlib.Path,
    expected_run_dir: pathlib.Path,
    evidence_dir: pathlib.Path,
) -> None:
    values = parse_manifest(data)
    expected = {
        "format": "wg-mix-ebpf-test-manifest-v2",
        "run_id": run_id,
        "owner_token": owner_token,
        "boot_id": boot_id,
        "run_base": str(run_base),
        "lifecycle_lease": str(lease_path),
        "config_b": str(expected_config),
        "run_dir_b": str(expected_run_dir),
        "evidence": str(evidence_dir),
    }
    for key, value in expected.items():
        if values.get(key) != value:
            raise ContractError(
                f"manifest {key}={values.get(key)!r}, want {value!r}"
            )
    if manifest_path != run_base / "manifest":
        raise ContractError("manifest path is not the exact run manifest")
    if lease_path != run_base / "lifecycle.lease":
        raise ContractError("lease path is not the exact manifest lifecycle lease")


def validate_lease_owner(
    data: bytes,
    expected_config: pathlib.Path,
    expected_run_dir: pathlib.Path,
) -> None:
    if (
        not data.endswith(b"\n")
        or data.count(b"\n") != 1
        or b"\0" in data
        or b"\r" in data
    ):
        raise ContractError("lifecycle owner must be one JSON line plus LF")
    try:
        owner = json.loads(data[:-1].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError("lifecycle owner is not canonical JSON") from exc
    if set(owner) != {"pid", "action", "config_path", "run_dir"}:
        raise ContractError("lifecycle owner has unexpected keys")
    if (
        type(owner["pid"]) is not int
        or owner["pid"] <= 0
        or owner["action"] != "detach"
        or owner["config_path"] != str(expected_config)
        or owner["run_dir"] != str(expected_run_dir)
    ):
        raise ContractError(f"lifecycle owner does not match final detach: {owner!r}")


def hold(args: argparse.Namespace) -> None:
    lease_path = canonical_absolute_path(args.lease, "lease")
    manifest_path = canonical_absolute_path(args.manifest, "manifest")
    run_base = canonical_absolute_path(args.run_base, "run base")
    expected_config = canonical_absolute_path(args.expected_config, "config")
    expected_run_dir = canonical_absolute_path(args.expected_run_dir, "run directory")
    status_path = canonical_absolute_path(args.status_path, "status")
    evidence_dir = status_path.parent
    if not re.fullmatch(r"[0-9a-f]{8,64}", args.run_id):
        raise ContractError("run ID is not canonical lowercase hex")
    if not re.fullmatch(r"[0-9a-f]{32}", args.owner_token):
        raise ContractError("owner token is not 32 lowercase hex characters")
    if not re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        args.boot_id,
    ):
        raise ContractError("boot ID is not canonical")

    verify_directory(run_base, args.expected_uid)
    verify_directory(evidence_dir, args.expected_uid)
    if evidence_dir.parent != run_base:
        raise ContractError("holder status directory is not the run evidence directory")
    if not re.fullmatch(
        r"lifecycle-holder-[0-9a-f]{32}\.status",
        status_path.name,
    ):
        raise ContractError("holder status filename is not run-token bound")
    if args.parent_pid <= 1 or os.getppid() != args.parent_pid:
        raise ContractError("holder parent PID does not match the invoking shell")
    if status_path.exists() or status_path.is_symlink():
        raise ContractError(f"holder status path already exists: {status_path}")
    manifest_fd, manifest_metadata = open_verified_file(
        manifest_path,
        args.expected_uid,
        os.O_RDONLY,
    )
    lease_fd = -1
    try:
        manifest_data = read_exact_file(manifest_fd, manifest_metadata, 64 * 1024)
        validate_manifest(
            manifest_data,
            manifest_path=manifest_path,
            lease_path=lease_path,
            run_base=run_base,
            run_id=args.run_id,
            owner_token=args.owner_token,
            boot_id=args.boot_id,
            expected_config=expected_config,
            expected_run_dir=expected_run_dir,
            evidence_dir=evidence_dir,
        )

        lease_fd, lease_metadata = open_verified_file(
            lease_path,
            args.expected_uid,
            os.O_RDWR,
        )
        try:
            fcntl.flock(lease_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ContractError("lifecycle lease is held; refusing cleanup") from exc

        # Recheck every pathname, descriptor, and immutable contract input
        # after flock. The held lease is not enough if the pathname was swapped
        # or its metadata changed while this process waited.
        verify_directory(run_base, args.expected_uid)
        verify_directory(evidence_dir, args.expected_uid)
        current_lease_metadata = recheck_verified_file(
            lease_path,
            lease_fd,
            args.expected_uid,
            lease_metadata,
            "lifecycle lease",
        )
        current_manifest_metadata = recheck_verified_file(
            manifest_path,
            manifest_fd,
            args.expected_uid,
            manifest_metadata,
            "manifest",
        )
        current_manifest_data = read_exact_file(
            manifest_fd,
            current_manifest_metadata,
            64 * 1024,
        )
        if current_manifest_data != manifest_data:
            raise ContractError("manifest changed while acquiring lifecycle lease")
        validate_manifest(
            current_manifest_data,
            manifest_path=manifest_path,
            lease_path=lease_path,
            run_base=run_base,
            run_id=args.run_id,
            owner_token=args.owner_token,
            boot_id=args.boot_id,
            expected_config=expected_config,
            expected_run_dir=expected_run_dir,
            evidence_dir=evidence_dir,
        )
        validate_lease_owner(
            read_exact_file(lease_fd, current_lease_metadata, 16 * 1024),
            expected_config,
            expected_run_dir,
        )
        recheck_verified_file(
            lease_path,
            lease_fd,
            args.expected_uid,
            lease_metadata,
            "lifecycle lease",
        )
        recheck_verified_file(
            manifest_path,
            manifest_fd,
            args.expected_uid,
            manifest_metadata,
            "manifest",
        )

        release_requested = False

        def request_release(
            _signal_number: int,
            _frame: object,
        ) -> None:
            nonlocal release_requested
            release_requested = True

        signal.signal(signal.SIGUSR1, request_release)
        status_fd = os.open(
            status_path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            os.fchmod(status_fd, 0o600)

            def write_status(state: str) -> None:
                payload = (
                    f"{state} {os.getpid()} {args.owner_token}\n"
                ).encode("ascii")
                os.ftruncate(status_fd, 0)
                if os.pwrite(status_fd, payload, 0) != len(payload):
                    raise ContractError("short lifecycle holder status write")
                os.fsync(status_fd)
                metadata = os.fstat(status_fd)
                path_metadata = os.lstat(status_path)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != args.expected_uid
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                    or metadata.st_nlink != 1
                    or (metadata.st_dev, metadata.st_ino)
                    != (path_metadata.st_dev, path_metadata.st_ino)
                ):
                    raise ContractError(
                        "lifecycle holder status pathname identity changed"
                    )

            write_status("READY")
            while not release_requested:
                if os.getppid() != args.parent_pid:
                    raise ContractError(
                        "invoking shell exited before authorizing lease release"
                    )
                time.sleep(0.05)
            write_status("RELEASED")
        finally:
            os.close(status_fd)
    finally:
        if lease_fd >= 0:
            os.close(lease_fd)
        os.close(manifest_fd)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lease", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--run-base", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--owner-token", required=True)
    parser.add_argument("--boot-id", required=True)
    parser.add_argument("--expected-config", required=True)
    parser.add_argument("--expected-run-dir", required=True)
    parser.add_argument("--expected-uid", type=int, required=True)
    parser.add_argument("--status-path", required=True)
    parser.add_argument("--parent-pid", type=int, required=True)
    return parser.parse_args()


def main() -> int:
    try:
        hold(parse_args())
    except (ContractError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
