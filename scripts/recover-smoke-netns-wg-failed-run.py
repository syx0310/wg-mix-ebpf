#!/usr/bin/python3
"""Recover one owner-proven failed smoke run after its private mountns died.

This tool deliberately handles only the post-mountns state: no mount below the
run root, no live anchor PID, and no run-named host interface may remain.  It
never detaches BPF or deletes network objects.  A parent-directory receipt
makes the exact file cleanup retryable across interruption.
"""

from __future__ import annotations

import argparse
import fcntl
import grp
import hashlib
import json
import os
import pwd
import re
import stat
import sys
from pathlib import Path


RUN_RE = re.compile(r"[0-9a-f]{8}")
SHA_RE = re.compile(r"[0-9a-f]{64}")
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
TOKEN_RE = re.compile(r"[0-9a-f]{32}")
SAFE_NAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,160}")
TEST_PARENT = Path("/run/wg-mix-ebpf-tests")
RECEIPT_FORMAT = "wg-mix-ebpf-failed-run-recovery-v1"


def stop(reason: str, rc: int = 79) -> "NoReturn":
    print(f"SMOKE_RECOVERY_STOP reason={reason} rc={rc}", file=sys.stderr)
    raise SystemExit(rc)


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def read_regular(
    path: Path,
    *,
    maximum: int = 8 * 1024 * 1024,
    allowed_nlinks: tuple[int, ...] = (1,),
) -> bytes:
    try:
        before = path.lstat()
    except OSError:
        stop("required-file")
    if not stat.S_ISREG(before.st_mode) or before.st_nlink not in allowed_nlinks:
        stop("file-shape")
    if before.st_size > maximum:
        stop("file-size")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError:
        stop("file-open")
    try:
        held = os.fstat(fd)
        if (held.st_dev, held.st_ino) != (before.st_dev, before.st_ino):
            stop("file-identity")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(fd)
        if len(payload) != held.st_size or (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ) != (held.st_dev, held.st_ino, held.st_size, held.st_mtime_ns):
            stop("file-drift")
        return payload
    finally:
        os.close(fd)


def parse_fields(payload: bytes, expected_format: str) -> dict[str, str]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        stop("field-encoding")
    if not text.endswith("\n") or "\r" in text:
        stop("field-framing")
    result: dict[str, str] = {}
    for line in text.splitlines():
        if line.count("=") != 1:
            stop("field-line")
        key, value = line.split("=", 1)
        if not key or key in result or not value:
            stop("field-duplicate")
        result[key] = value
    if result.get("format") != expected_format:
        stop("field-format")
    return result


def parse_json_object(payload: bytes, reason: str) -> dict[str, object]:
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        stop(reason)
    if not isinstance(value, dict):
        stop(reason)
    return value


def unescape_mount(value: str) -> str:
    for encoded, plain in (("\\040", " "), ("\\011", "\t"), ("\\134", "\\")):
        value = value.replace(encoded, plain)
    return value


def proc_text(path: Path, maximum: int = 4 * 1024 * 1024) -> str | None:
    try:
        with path.open("r", encoding="utf-8", errors="strict") as handle:
            payload = handle.read(maximum + 1)
    except (FileNotFoundError, ProcessLookupError):
        return None
    except (OSError, UnicodeError):
        stop("proc-read")
    if len(payload) > maximum:
        stop("proc-size")
    return payload


def proc_processes(proc_root: Path) -> list[Path]:
    try:
        entries = list(proc_root.iterdir())
    except OSError:
        stop("proc-list")
    return sorted(
        (entry for entry in entries if entry.name.isdigit()),
        key=lambda item: item.name,
    )


def assert_no_live_mount(
    root: Path, source: str, proc_root: Path = Path("/proc")
) -> None:
    prefix = f"{root}/"
    for process in proc_processes(proc_root):
        payload = proc_text(process / "mountinfo")
        if payload is None:
            continue
        for line in payload.splitlines():
            fields = line.split()
            if len(fields) < 10 or "-" not in fields:
                stop("mountinfo")
            separator = fields.index("-")
            if separator + 2 >= len(fields):
                stop("mountinfo")
            target = unescape_mount(fields[4])
            mounted_source = unescape_mount(fields[separator + 2])
            if (
                target == str(root)
                or target.startswith(prefix)
                or mounted_source == source
            ):
                stop("live-mount")


def assert_no_live_netns(
    manifest: dict[str, str], proc_root: Path = Path("/proc")
) -> None:
    expected = set()
    for role in ("a", "r", "b"):
        try:
            expected.add(
                (
                    int(manifest[f"netns_{role}_dev"], 10),
                    int(manifest[f"netns_{role}_ino"], 10),
                )
            )
        except (KeyError, ValueError):
            stop("manifest-netns")
    if len(expected) != 3:
        stop("manifest-netns")
    for process in proc_processes(proc_root):
        try:
            info = (process / "ns" / "net").stat()
        except (FileNotFoundError, ProcessLookupError):
            continue
        except OSError:
            stop("proc-netns")
        if (info.st_dev, info.st_ino) in expected:
            stop("live-netns")


def assert_no_run_network(run_id: str) -> None:
    names = (
        f"wme{run_id}a",
        f"wme{run_id}r",
        f"wme{run_id}b",
        f"wma{run_id}0",
        f"wmr{run_id}a",
        f"wmb{run_id}0",
        f"wmr{run_id}b",
    )
    for name in names:
        if (Path("/sys/class/net") / name).exists():
            stop("live-interface")
        if (Path("/run/netns") / name).exists():
            stop("live-netns")


def exact_directory(path: Path, *, device: int | None = None) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError:
        stop("directory-missing")
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != 0
        or info.st_gid != 0
        or stat.S_IMODE(info.st_mode) != 0o700
        or (device is not None and info.st_dev != device)
    ):
        stop("directory-shape")
    return info


def owner_marker(path: Path, run_id: str, token: str, boot_id: str, role: str) -> None:
    fields = parse_fields(read_regular(path, maximum=1024), "wg-mix-ebpf-test-owner-v1")
    if fields != {
        "format": "wg-mix-ebpf-test-owner-v1",
        "run_id": run_id,
        "owner_token": token,
        "boot_id": boot_id,
        "role": role,
    }:
        stop("owner-marker")


def receipt_paths(run_id: str) -> tuple[Path, Path]:
    final = TEST_PARENT / f".failed-recovery-{run_id}.v1"
    pending = TEST_PARENT / f".pending-.failed-recovery-{run_id}.v1"
    return pending, final


def validate_double_receipt(pending: Path, final: Path, payload: bytes) -> None:
    pinfo = pending.lstat()
    finfo = final.lstat()
    if (
        (pinfo.st_dev, pinfo.st_ino) != (finfo.st_dev, finfo.st_ino)
        or pinfo.st_uid != 0
        or pinfo.st_gid != 0
        or stat.S_IMODE(pinfo.st_mode) != 0o600
        or pinfo.st_nlink != 2
        or finfo.st_nlink != 2
        or read_regular(final, maximum=1024 * 1024, allowed_nlinks=(2,))
        != payload
        or read_regular(pending, maximum=1024 * 1024, allowed_nlinks=(2,))
        != payload
    ):
        stop("receipt-double-name")


def read_receipt(path: Path, *, double_name: bool) -> bytes:
    try:
        info = path.lstat()
    except OSError:
        stop("receipt-missing")
    expected_nlink = 2 if double_name else 1
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_gid != 0
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_nlink != expected_nlink
    ):
        stop("receipt-shape")
    return read_regular(
        path,
        maximum=1024 * 1024,
        allowed_nlinks=(expected_nlink,),
    )


def publish_receipt(payload: bytes, run_id: str) -> None:
    pending, final = receipt_paths(run_id)
    maximum = 1024 * 1024

    def sync_parent() -> None:
        parent_fd = os.open(TEST_PARENT, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)

    if final.exists() and pending.exists():
        validate_double_receipt(pending, final, payload)
        os.unlink(pending)
        sync_parent()
    if final.exists():
        if read_regular(final, maximum=maximum) != payload:
            stop("receipt-drift")
        return
    if pending.exists() and read_regular(pending, maximum=maximum) != payload:
        info = pending.lstat()
        if (
            info.st_uid != 0
            or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
        ):
            stop("receipt-pending-shape")
        os.unlink(pending)
        sync_parent()
    if not pending.exists():
        try:
            fd = os.open(
                pending,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_CLOEXEC
                | os.O_NOFOLLOW,
                0o600,
            )
        except OSError:
            stop("receipt-create")
        try:
            view = memoryview(payload)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    stop("receipt-write")
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
    if read_regular(pending, maximum=maximum) != payload:
        stop("receipt-pending-drift")
    try:
        os.link(pending, final, follow_symlinks=False)
    except FileExistsError:
        pass
    except OSError:
        stop("receipt-publish")
    pinfo = pending.lstat()
    finfo = final.lstat()
    if (
        (pinfo.st_dev, pinfo.st_ino) != (finfo.st_dev, finfo.st_ino)
        or pinfo.st_nlink != 2
        or finfo.st_nlink != 2
        or read_regular(final, maximum=maximum, allowed_nlinks=(2,)) != payload
    ):
        stop("receipt-publish-identity")
    sync_parent()
    os.unlink(pending)
    sync_parent()
    if read_regular(final, maximum=maximum) != payload:
        stop("receipt-final")


def validate_tree(root: Path, manifest: dict[str, str], *, initial: bool) -> list[Path]:
    root_info = exact_directory(root)
    token = manifest["owner_token"]
    boot_id = manifest["boot_id"]
    run_id = manifest["run_id"]
    expected_dirs = {
        "pin-owners",
        "pin-locks",
        "bpffs",
        "secrets",
        "evidence",
        "state-a",
        "state-b",
        "run-a",
        "run-b",
    }
    expected_root_files = {
        ".wg-mix-ebpf-test-owner",
        "manifest",
        "bpffs.creation.v1",
        "lifecycle.lease",
    }
    entries = {entry.name: entry for entry in os.scandir(root)}
    if initial and set(entries) != expected_dirs | expected_root_files:
        stop("root-entries")
    if not set(entries).issubset(expected_dirs | expected_root_files):
        stop("root-extra")
    files: list[Path] = []
    for name, entry in entries.items():
        path = root / name
        if name in expected_dirs:
            info = exact_directory(path, device=root_info.st_dev)
            if entry.is_symlink() or info.st_ino != entry.inode():
                stop("child-directory-identity")
        else:
            files.append(path)
    roles = {
        "pin-owners": "pin-owners",
        "pin-locks": "pin-locks",
        "secrets": "secrets",
        "evidence": "evidence",
        "state-a": "state-a",
        "state-b": "state-b",
        "run-a": "run-a",
        "run-b": "run-b",
    }
    fixed_names = {
        "bpffs": set(),
        "secrets": {
            ".wg-mix-ebpf-test-owner",
            "netns-anchor-token",
            "xor-password",
            "a.key",
            "a.pub",
            "b.key",
            "b.pub",
            "wg-a.conf",
            "wg-b.conf",
            "agent-a.yaml",
            "agent-b.yaml",
        },
        "state-a": {".wg-mix-ebpf-test-owner", "attach-state.json"},
        "state-b": {".wg-mix-ebpf-test-owner", "attach-state.json"},
        "run-a": {".wg-mix-ebpf-test-owner", "lock"},
        "run-b": {".wg-mix-ebpf-test-owner", "lock"},
        "pin-locks": {
            ".wg-mix-ebpf-test-owner",
            f"{manifest['pin_resource_key_a']}.lock",
            f"{manifest['pin_resource_key_b']}.lock",
        },
        "pin-owners": {
            ".wg-mix-ebpf-test-owner",
            "instances.v2.json",
            f"{manifest['pin_resource_key_a']}.owner.json",
            f"{manifest['pin_resource_key_b']}.owner.json",
        },
    }
    tcpdump_uid = pwd.getpwnam("tcpdump").pw_uid
    tcpdump_gid = grp.getgrnam("tcpdump").gr_gid
    for dirname in expected_dirs:
        child = root / dirname
        if not child.exists():
            if initial:
                stop("child-directory-missing")
            continue
        child_entries = {entry.name: entry for entry in os.scandir(child)}
        if dirname == "evidence":
            if initial and ".wg-mix-ebpf-test-owner" not in child_entries:
                stop("evidence-owner-missing")
            if any(not SAFE_NAME_RE.fullmatch(name) for name in child_entries):
                stop("evidence-name")
        else:
            allowed = fixed_names[dirname]
            if dirname == "secrets":
                allowed_initial_sets = (allowed, allowed - {"xor-password"})
                if initial and set(child_entries) not in allowed_initial_sets:
                    stop("secrets-entries")
            elif initial and set(child_entries) != allowed:
                stop(f"{dirname}-entries")
            if not set(child_entries).issubset(allowed):
                stop(f"{dirname}-extra")
        for name, entry in child_entries.items():
            path = child / name
            info = path.lstat()
            if (
                entry.is_symlink()
                or not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_dev != root_info.st_dev
                or stat.S_IMODE(info.st_mode) & 0o077
            ):
                stop("leaf-shape")
            allowed_uids = {0, tcpdump_uid} if dirname == "evidence" else {0}
            allowed_gids = {0, tcpdump_gid} if dirname == "evidence" else {0}
            if info.st_uid not in allowed_uids or info.st_gid not in allowed_gids:
                stop("leaf-owner")
            files.append(path)
        marker = child / ".wg-mix-ebpf-test-owner"
        if marker.exists():
            owner_marker(marker, run_id, token, boot_id, roles[dirname])
    if (root / ".wg-mix-ebpf-test-owner").exists():
        owner_marker(root / ".wg-mix-ebpf-test-owner", run_id, token, boot_id, "root")
    return files


def inventory_entry(root: Path, path: Path) -> dict[str, object]:
    info = path.lstat()
    relative = "." if path == root else str(path.relative_to(root))
    common: dict[str, object] = {
        "path": relative,
        "device": info.st_dev,
        "inode": info.st_ino,
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": stat.S_IMODE(info.st_mode),
    }
    if stat.S_ISDIR(info.st_mode):
        common["type"] = "directory"
        return common
    if not stat.S_ISREG(info.st_mode):
        stop("inventory-type")
    common.update(
        {
            "type": "regular",
            "nlink": info.st_nlink,
            "size": info.st_size,
            "sha256": sha256_bytes(read_regular(path)),
        }
    )
    return common


def tree_inventory(root: Path, files: list[Path]) -> list[dict[str, object]]:
    paths = [root]
    for entry in os.scandir(root):
        if entry.is_dir(follow_symlinks=False):
            paths.append(root / entry.name)
    paths.extend(files)
    return [inventory_entry(root, path) for path in sorted(paths, key=str)]


def validated_inventory(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        stop("receipt-inventory")
    result: list[dict[str, object]] = []
    seen: set[str] = set()
    directory_keys = {"path", "device", "inode", "uid", "gid", "mode", "type"}
    regular_keys = directory_keys | {"nlink", "size", "sha256"}
    for raw in value:
        if not isinstance(raw, dict):
            stop("inventory-record")
        entry = dict(raw)
        relative = entry.get("path")
        entry_type = entry.get("type")
        expected_keys = directory_keys if entry_type == "directory" else regular_keys
        if set(entry) != expected_keys or not isinstance(relative, str):
            stop("inventory-record")
        if relative != ".":
            parts = relative.split("/")
            if (
                not relative
                or relative.startswith("/")
                or any(part in ("", ".", "..") for part in parts)
            ):
                stop("inventory-path")
        if relative in seen:
            stop("inventory-record")
        seen.add(relative)
        for key in ("device", "inode", "uid", "gid", "mode"):
            field = entry.get(key)
            if isinstance(field, bool) or not isinstance(field, int) or field < 0:
                stop("inventory-record")
        if entry_type == "regular":
            for key in ("nlink", "size"):
                field = entry.get(key)
                if isinstance(field, bool) or not isinstance(field, int) or field < 0:
                    stop("inventory-record")
            if not isinstance(entry.get("sha256"), str) or not SHA_RE.fullmatch(
                str(entry["sha256"])
            ):
                stop("inventory-record")
        elif entry_type != "directory":
            stop("inventory-record")
        result.append(entry)
    if "." not in seen:
        stop("inventory-record")
    return result


def preflight_inventory(
    root: Path,
    files: list[Path],
    recorded: list[dict[str, object]],
) -> dict[str, dict[str, object]]:
    recorded_by_path = {str(entry.get("path")): entry for entry in recorded}
    if len(recorded_by_path) != len(recorded) or "." not in recorded_by_path:
        stop("inventory-record")
    current = tree_inventory(root, files)
    current_by_path = {str(entry["path"]): entry for entry in current}
    if not set(current_by_path).issubset(recorded_by_path):
        stop("inventory-new-entry")
    for relative, entry in current_by_path.items():
        if entry != recorded_by_path[relative]:
            stop("inventory-drift")
    return recorded_by_path


def recheck_recorded_path(
    root: Path, path: Path, recorded_by_path: dict[str, dict[str, object]]
) -> None:
    relative = "." if path == root else str(path.relative_to(root))
    if relative not in recorded_by_path:
        stop("inventory-unrecorded")
    if inventory_entry(root, path) != recorded_by_path[relative]:
        stop("inventory-recheck")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("plan", "run"))
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--failed-source-commit", required=True)
    parser.add_argument("--script-sha256", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or os.getegid() != 0:
        stop("root", 78)
    if (
        not RUN_RE.fullmatch(args.run_id)
        or not SHA_RE.fullmatch(args.manifest_sha256)
        or not COMMIT_RE.fullmatch(args.failed_source_commit)
        or not SHA_RE.fullmatch(args.script_sha256)
    ):
        stop("arguments", 64)
    script_path = Path(__file__).resolve(strict=True)
    if sha256_bytes(read_regular(script_path)) != args.script_sha256:
        stop("script-sha256")
    exact_directory(TEST_PARENT)
    root = TEST_PARENT / args.run_id
    pending_receipt, final_receipt = receipt_paths(args.run_id)
    manifest_path = root / "manifest"
    if not root.exists():
        if final_receipt.exists():
            payload = read_receipt(
                final_receipt, double_name=pending_receipt.exists()
            )
            if pending_receipt.exists():
                validate_double_receipt(pending_receipt, final_receipt, payload)
            if pending_receipt.exists() and args.mode == "run":
                publish_receipt(payload, args.run_id)
            receipt = parse_json_object(payload, "completed-receipt-json")
            if (
                receipt.get("format") != RECEIPT_FORMAT
                or receipt.get("run_id") != args.run_id
                or receipt.get("manifest_sha256") != args.manifest_sha256
                or receipt.get("failed_source_commit") != args.failed_source_commit
                or receipt.get("script_sha256") != args.script_sha256
            ):
                stop("completed-receipt")
            if args.mode == "plan":
                print(
                    f"SMOKE_RECOVERY_PLAN run_id={args.run_id} root=absent "
                    "receipt=present mutation=0"
                )
                return
            os.unlink(final_receipt)
            parent_fd = os.open(
                TEST_PARENT, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
            )
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
            print(f"SMOKE_RECOVERY_COMPLETE run_id={args.run_id} root=absent receipt=absent")
            return
        stop("run-root-missing")
    root_info = exact_directory(root, device=TEST_PARENT.stat().st_dev)
    receipt_exists = final_receipt.exists()
    if receipt_exists:
        receipt_payload = read_receipt(
            final_receipt, double_name=pending_receipt.exists()
        )
        if pending_receipt.exists():
            validate_double_receipt(
                pending_receipt, final_receipt, receipt_payload
            )
        if pending_receipt.exists() and args.mode == "run":
            publish_receipt(receipt_payload, args.run_id)
        receipt = parse_json_object(receipt_payload, "receipt-json")
        if (
            receipt.get("format") != RECEIPT_FORMAT
            or receipt.get("run_id") != args.run_id
            or receipt.get("manifest_sha256") != args.manifest_sha256
            or receipt.get("failed_source_commit") != args.failed_source_commit
            or receipt.get("script_sha256") != args.script_sha256
            or receipt.get("root_device") != root_info.st_dev
            or receipt.get("root_inode") != root_info.st_ino
        ):
            stop("receipt-contract")
        manifest_value = receipt.get("manifest")
        if not isinstance(manifest_value, dict) or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in manifest_value.items()
        ):
            stop("receipt-manifest")
        manifest = manifest_value
        recorded_inventory = validated_inventory(receipt.get("inventory"))
        encoded_inventory = json.dumps(
            recorded_inventory, sort_keys=True, separators=(",", ":")
        ).encode()
        if receipt.get("inventory_sha256") != sha256_bytes(encoded_inventory):
            stop("receipt-inventory-sha256")
    else:
        manifest_payload = read_regular(manifest_path)
        if sha256_bytes(manifest_payload) != args.manifest_sha256:
            stop("manifest-sha256")
        manifest = parse_fields(manifest_payload, "wg-mix-ebpf-test-manifest-v2")
        required = {
            "run_id": args.run_id,
            "run_base": str(root),
            "bpffs": str(root / "bpffs"),
            "pin_lock_root": str(root / "pin-locks"),
            "pin_owner_root": str(root / "pin-owners"),
            "evidence": str(root / "evidence"),
            "secrets": str(root / "secrets"),
        }
        if any(manifest.get(key) != value for key, value in required.items()):
            stop("manifest-contract")
        if not TOKEN_RE.fullmatch(manifest.get("owner_token", "")):
            stop("manifest-token")
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
        if manifest.get("boot_id") != boot_id or manifest.get("host") != "ubuntu-2604-test":
            stop("host-identity")
        for role in ("a", "b"):
            status_path = root / "evidence" / f"status-{role}-before.json"
            status = parse_json_object(read_regular(status_path), "status-json")
            client_build = status.get("client_build")
            if (
                not isinstance(client_build, dict)
                or client_build.get("source_commit") != args.failed_source_commit
            ):
                stop("source-commit")
        validate_tree(root, manifest, initial=True)
        assert_no_live_mount(root, manifest["bpffs_source"])
        assert_no_live_netns(manifest)
        assert_no_run_network(args.run_id)
        for role in ("a", "r", "b"):
            ready = parse_fields(
                read_regular(root / "evidence" / f"netns-anchor-{role}.ready", maximum=2048),
                "wg-mix-ebpf-netns-anchor-v1",
            )
            if ready.get("run_id") != args.run_id or ready.get("role") != role:
                stop("anchor-contract")
            if Path("/proc").joinpath(ready.get("anchor_pid", "invalid")).exists():
                stop("anchor-live")
        recorded_inventory = tree_inventory(
            root, validate_tree(root, manifest, initial=True)
        )
        encoded_inventory = json.dumps(
            recorded_inventory, sort_keys=True, separators=(",", ":")
        ).encode()
        receipt = {
            "format": RECEIPT_FORMAT,
            "run_id": args.run_id,
            "manifest_sha256": args.manifest_sha256,
            "failed_source_commit": args.failed_source_commit,
            "script_sha256": args.script_sha256,
            "root_device": root_info.st_dev,
            "root_inode": root_info.st_ino,
            "owner_token_sha256": sha256_bytes(manifest["owner_token"].encode()),
            "inventory": recorded_inventory,
            "inventory_sha256": sha256_bytes(encoded_inventory),
            "manifest": manifest,
        }
        receipt_payload = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()
        if args.mode == "run":
            publish_receipt(receipt_payload, args.run_id)
    assert_no_live_mount(root, manifest["bpffs_source"])
    assert_no_live_netns(manifest)
    assert_no_run_network(args.run_id)
    files = validate_tree(root, manifest, initial=False)
    recorded_by_path = preflight_inventory(root, files, recorded_inventory)
    if args.mode == "plan":
        print(
            f"SMOKE_RECOVERY_PLAN run_id={args.run_id} files={len(files)} "
            f"root={root} mount=absent anchors=absent mutation=0"
        )
        return
    lease_fd = None
    lease_path = root / "lifecycle.lease"
    if lease_path.exists():
        lease_fd = os.open(lease_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            fcntl.flock(lease_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(lease_fd)
            stop("lifecycle-busy")
    protected = {
        root / ".wg-mix-ebpf-test-owner",
        root / "manifest",
        root / "bpffs.creation.v1",
        root / "lifecycle.lease",
    }
    try:
        for path in sorted((item for item in files if item not in protected), reverse=True):
            recheck_recorded_path(root, path, recorded_by_path)
        for path in sorted((item for item in files if item not in protected), reverse=True):
            if path.exists():
                recheck_recorded_path(root, path, recorded_by_path)
                os.unlink(path)
        for dirname in ("evidence", "secrets", "state-a", "state-b", "run-a", "run-b", "pin-owners", "pin-locks", "bpffs"):
            path = root / dirname
            if path.exists():
                recheck_recorded_path(root, path, recorded_by_path)
                os.rmdir(path)
        for path in (
            root / "bpffs.creation.v1",
            root / "manifest",
            root / ".wg-mix-ebpf-test-owner",
        ):
            if path.exists():
                recheck_recorded_path(root, path, recorded_by_path)
                os.unlink(path)
        if lease_fd is not None:
            os.close(lease_fd)
            lease_fd = None
        if lease_path.exists():
            recheck_recorded_path(root, lease_path, recorded_by_path)
            os.unlink(lease_path)
        recheck_recorded_path(root, root, recorded_by_path)
        os.rmdir(root)
        parent_fd = os.open(TEST_PARENT, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        if final_receipt.exists():
            os.unlink(final_receipt)
        if pending_receipt.exists():
            os.unlink(pending_receipt)
        parent_fd = os.open(TEST_PARENT, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        if lease_fd is not None:
            os.close(lease_fd)
    print(f"SMOKE_RECOVERY_COMPLETE run_id={args.run_id} root=absent receipt=absent")


if __name__ == "__main__":
    main()
