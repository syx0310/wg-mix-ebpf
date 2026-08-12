#!/usr/bin/python3
"""Precisely remove one successfully exported B82 production performance run."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import subprocess
import sys
import tarfile
from pathlib import Path


RUN_PARENT = Path("/run/wg-mix-ebpf-performance-tests")
RUN_ID_RE = re.compile(r"[0-9a-f]{8}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")


class CleanupError(RuntimeError):
    pass


def fail(message: str) -> "None":
    raise CleanupError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb", buffering=0) as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def regular(path: Path, modes: int | tuple[int, ...]) -> os.stat_result:
    allowed = (modes,) if isinstance(modes, int) else modes
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) not in allowed
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or metadata.st_nlink != 1
    ):
        fail(f"unsafe regular file metadata: {path}")
    return metadata


def directory(path: Path, modes: int | tuple[int, ...]) -> os.stat_result:
    allowed = (modes,) if isinstance(modes, int) else modes
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) not in allowed
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or metadata.st_nlink < 1
    ):
        fail(f"unsafe directory metadata: {path}")
    return metadata


def parse_fields(path: Path) -> dict[str, str]:
    data = path.read_bytes()
    if not data.endswith(b"\n") or b"\0" in data or b"\r" in data:
        fail(f"non-canonical proof file: {path}")
    result: dict[str, str] = {}
    for raw_line in data[:-1].split(b"\n"):
        try:
            line = raw_line.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CleanupError(f"non-UTF-8 proof file: {path}") from exc
        key, separator, value = line.partition("=")
        if not separator or not key or key in result:
            fail(f"invalid proof field in {path}")
        result[key] = value
    return result


def validate_archive(archive: Path, expected_sha256: str, run_id: str) -> None:
    regular(archive, 0o600)
    if sha256_file(archive) != expected_sha256:
        fail("evidence export SHA-256 mismatch")
    prefix = f"{run_id}/"
    with tarfile.open(archive, mode="r:") as bundle:
        members = bundle.getmembers()
        if not members:
            fail("evidence export is empty")
        seen: set[str] = set()
        for member in members:
            name = member.name
            if name in seen:
                fail(f"duplicate evidence export member: {name}")
            seen.add(name)
            if name != run_id and not name.startswith(prefix):
                fail(f"evidence export escapes the exact run: {name}")
            parts = Path(name).parts
            if any(part in ("", ".", "..") for part in parts):
                fail(f"non-canonical evidence export member: {name}")
            if not (member.isfile() or member.isdir()):
                fail(f"unsupported evidence export member type: {name}")
            if member.uid != 0 or member.gid != 0:
                fail(f"evidence export member ownership mismatch: {name}")
        required = {f"{run_id}/owner", f"{run_id}/manifest", f"{run_id}/complete"}
        if not required.issubset(seen):
            fail("evidence export lacks the run ownership proofs")


def assert_no_live_resources(run_id: str, run_root: Path, kind: str) -> None:
    completed = subprocess.run(
        ["/usr/sbin/ip", "netns", "list"],
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        fail(f"network namespace inventory failed: {completed.stderr.strip()}")
    names = {line.split(maxsplit=1)[0] for line in completed.stdout.splitlines() if line}
    expected = {f"wgp{run_id}a", f"wgp{run_id}r", f"wgp{run_id}b"}
    if names & expected:
        fail(f"run-owned network namespaces are still live: {sorted(names & expected)}")
    if kind == "cell":
        for role in ("a", "b"):
            pid_path = run_root / f"daemon-{role}.pid"
            regular(pid_path, 0o600)
            raw = pid_path.read_text(encoding="ascii").strip()
            if not raw.isdecimal() or int(raw) <= 0:
                fail(f"invalid retained daemon PID: {pid_path}")
            if Path(f"/proc/{raw}").exists():
                fail(f"retained daemon PID is still live: role={role} pid={raw}")
    mountinfo = Path("/proc/self/mountinfo").read_text(
        encoding="utf-8", errors="strict"
    )
    if str(run_root) in mountinfo:
        fail("the exact run root is still present in current mountinfo")


def inventory_tree(run_root: Path) -> tuple[list[Path], list[Path]]:
    files: list[Path] = []
    directories: list[Path] = []
    total_bytes = 0
    for current_raw, dir_names, file_names in os.walk(
        run_root, topdown=True, followlinks=False
    ):
        current = Path(current_raw)
        directory(current, (0o700, 0o755))
        directories.append(current)
        if len(directories) > 4096:
            fail("run tree directory count exceeds the 4096-entry cleanup bound")
        dir_names.sort()
        file_names.sort()
        for name in dir_names:
            candidate = current / name
            if candidate.is_symlink():
                fail(f"symbolic link is forbidden in run tree: {candidate}")
        for name in file_names:
            candidate = current / name
            metadata = regular(candidate, (0o600, 0o644))
            files.append(candidate)
            total_bytes += metadata.st_size
            if len(files) > 4096:
                fail("run tree file count exceeds the 4096-entry cleanup bound")
            if total_bytes > 1024 * 1024 * 1024:
                fail("run tree exceeds the 1 GiB cleanup inventory bound")
    if not files or directories[0] != run_root:
        fail("run tree inventory is empty or unanchored")
    return files, directories


def cleanup(args: argparse.Namespace) -> None:
    if os.geteuid() != 0 or os.getegid() != 0:
        fail("run the B82 performance evidence cleanup as root")
    if not RUN_ID_RE.fullmatch(args.run_id):
        fail("invalid run ID")
    if not SHA256_RE.fullmatch(args.export_sha256):
        fail("invalid evidence export SHA-256")
    archive = Path(args.export)
    if not archive.is_absolute() or archive == Path("/") or RUN_PARENT in archive.parents:
        fail("evidence export path must be absolute and outside the run parent")

    directory(RUN_PARENT, 0o700)
    run_root = RUN_PARENT / args.run_id
    if run_root.resolve(strict=True) != run_root:
        fail("run root is not canonical and exact")
    directory(run_root, 0o700)
    owner = run_root / "owner"
    manifest = run_root / "manifest"
    complete = run_root / "complete"
    for proof in (owner, manifest, complete):
        regular(proof, 0o600)
    if owner.read_text(encoding="utf-8") != f"wg-mix-ebpf-performance:{args.run_id}\n":
        fail("run ownership marker mismatch")
    fields = parse_fields(complete)
    expected_fields = {
        "format": "wg-mix-ebpf-b82-production-performance-complete-v1",
        "run_id": args.run_id,
        "manifest_sha256": sha256_file(manifest),
        "active_resources": "absent",
        "sensitive_files": "absent",
    }
    if fields != expected_fields:
        fail("completed run proof mismatch")

    validate_archive(archive, args.export_sha256, args.run_id)
    manifest_fields = parse_fields(manifest)
    kind = manifest_fields.get("kind", "cell")
    if kind not in ("cell", "matrix"):
        fail("run manifest kind is invalid")
    assert_no_live_resources(args.run_id, run_root, kind)
    files, directories = inventory_tree(run_root)

    print(
        f"CLEANUP_INVENTORY run_id={args.run_id} root={run_root} "
        f"files={len(files)} directories={len(directories)} export={archive}"
    )
    for path in files:
        print(f"CLEANUP_TARGET kind=file path={path}")
    for path in reversed(directories):
        print(f"CLEANUP_TARGET kind=directory path={path}")
    print(f"CLEANUP_TARGET kind=export path={archive}")

    for path in files:
        os.unlink(path)
        print(f"CLEANUP_RESULT kind=file path={path} rc=0")
    for path in reversed(directories):
        os.rmdir(path)
        print(f"CLEANUP_RESULT kind=directory path={path} rc=0")
    os.unlink(archive)
    print(f"CLEANUP_RESULT kind=export path={archive} rc=0")
    if run_root.exists() or archive.exists():
        fail("exact cleanup verification failed")
    print(
        f"PERFORMANCE_EVIDENCE_CLEANUP_COMPLETE run_id={args.run_id} "
        f"root={run_root} export={archive}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--export", required=True)
    parser.add_argument("--export-sha256", required=True)
    args = parser.parse_args()
    try:
        cleanup(args)
    except (CleanupError, OSError, tarfile.TarError, UnicodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
