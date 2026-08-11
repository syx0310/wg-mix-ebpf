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


def read_regular(path: Path, *, maximum: int = 8 * 1024 * 1024) -> bytes:
    try:
        before = path.lstat()
    except OSError:
        stop("required-file")
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
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


def unescape_mount(value: str) -> str:
    for encoded, plain in (("\\040", " "), ("\\011", "\t"), ("\\134", "\\")):
        value = value.replace(encoded, plain)
    return value


def assert_no_live_mount(root: Path) -> None:
    prefix = f"{root}/"
    for line in Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if len(fields) < 6:
            stop("mountinfo")
        target = unescape_mount(fields[4])
        if target == str(root) or target.startswith(prefix):
            stop("live-mount")


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


def publish_receipt(payload: bytes, run_id: str) -> None:
    pending, final = receipt_paths(run_id)
    if final.exists():
        if read_regular(final, maximum=16384) != payload:
            stop("receipt-drift")
    else:
        if pending.exists() and read_regular(pending, maximum=16384) != payload:
            info = pending.lstat()
            if (
                info.st_uid != 0
                or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1
            ):
                stop("receipt-pending-shape")
            os.unlink(pending)
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
        if read_regular(pending, maximum=16384) != payload:
            stop("receipt-pending-drift")
        try:
            os.link(pending, final, follow_symlinks=False)
        except FileExistsError:
            if read_regular(final, maximum=16384) != payload:
                stop("receipt-race")
        except OSError:
            stop("receipt-publish")
        parent_fd = os.open(TEST_PARENT, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    if pending.exists():
        pinfo = pending.lstat()
        finfo = final.lstat()
        if (pinfo.st_dev, pinfo.st_ino, pinfo.st_nlink) != (
            finfo.st_dev,
            finfo.st_ino,
            2,
        ) or finfo.st_nlink != 2:
            stop("receipt-double-name")
        os.unlink(pending)
        parent_fd = os.open(TEST_PARENT, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)


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
            if initial and set(child_entries) != allowed:
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
            payload = read_regular(final_receipt, maximum=4096)
            receipt = json.loads(payload)
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
            print(f"SMOKE_RECOVERY_COMPLETE run_id={args.run_id} root=absent receipt=absent")
            return
        stop("run-root-missing")
    root_info = exact_directory(root, device=TEST_PARENT.stat().st_dev)
    receipt_exists = final_receipt.exists()
    if receipt_exists:
        receipt_payload = read_regular(final_receipt, maximum=16384)
        receipt = json.loads(receipt_payload)
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
        manifest = receipt["manifest"]
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
            status = json.loads(read_regular(status_path))
            if status.get("source_commit") != args.failed_source_commit:
                stop("source-commit")
        validate_tree(root, manifest, initial=True)
        assert_no_live_mount(root)
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
        inventory = []
        for path in sorted(validate_tree(root, manifest, initial=True)):
            info = path.lstat()
            inventory.append(
                [str(path.relative_to(root)), info.st_mode, info.st_uid, info.st_gid, info.st_size, sha256_bytes(read_regular(path))]
            )
        receipt = {
            "format": RECEIPT_FORMAT,
            "run_id": args.run_id,
            "manifest_sha256": args.manifest_sha256,
            "failed_source_commit": args.failed_source_commit,
            "script_sha256": args.script_sha256,
            "root_device": root_info.st_dev,
            "root_inode": root_info.st_ino,
            "owner_token_sha256": sha256_bytes(manifest["owner_token"].encode()),
            "inventory_sha256": sha256_bytes(json.dumps(inventory, separators=(",", ":")).encode()),
            "manifest": manifest,
        }
        receipt_payload = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()
        if args.mode == "run":
            publish_receipt(receipt_payload, args.run_id)
    assert_no_live_mount(root)
    assert_no_run_network(args.run_id)
    files = validate_tree(root, manifest, initial=False)
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
            read_regular(path)
        for path in sorted((item for item in files if item not in protected), reverse=True):
            if path.exists():
                os.unlink(path)
        for dirname in ("evidence", "secrets", "state-a", "state-b", "run-a", "run-b", "pin-owners", "pin-locks", "bpffs"):
            path = root / dirname
            if path.exists():
                os.rmdir(path)
        for path in (
            root / "bpffs.creation.v1",
            root / "manifest",
            root / ".wg-mix-ebpf-test-owner",
        ):
            if path.exists():
                read_regular(path)
                os.unlink(path)
        if lease_fd is not None:
            os.close(lease_fd)
            lease_fd = None
        if lease_path.exists():
            read_regular(lease_path)
            os.unlink(lease_path)
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
    finally:
        if lease_fd is not None:
            os.close(lease_fd)
    print(f"SMOKE_RECOVERY_COMPLETE run_id={args.run_id} root=absent receipt=absent")


if __name__ == "__main__":
    main()
