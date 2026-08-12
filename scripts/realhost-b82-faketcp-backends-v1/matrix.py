#!/usr/bin/env python3
"""Plan or execute the bounded B82 FakeTCP production backend matrix."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import platform
import re
import secrets
import stat
import subprocess
import sys
from dataclasses import asdict, dataclass


STAGE_RE = re.compile(r"/var/tmp/wg-mix-ebpf-source-stages/([0-9a-f]{8})/source")
HEX40_RE = re.compile(r"[0-9a-f]{40}")
RUN_RE = re.compile(r"[0-9a-f]{8}")
RUN_PARENT = pathlib.Path("/var/tmp/wg-mix-ebpf-faketcp-backends-v1")
SAFE_ENV = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "LC_ALL": "C",
    "PYTHONDONTWRITEBYTECODE": "1",
}


@dataclass(frozen=True)
class Cell:
    wg_count: int
    attachment_backend: str
    checksum_backend: str
    artifact: str
    xor: str
    gso: str

    @property
    def label(self) -> str:
        return (
            f"wg{self.wg_count}-{self.attachment_backend}-"
            f"{self.checksum_backend}-{self.xor}-gso-{self.gso}"
        )


def cells() -> list[Cell]:
    result: list[Cell] = []
    profiles = {1: ("none", "off"), 2: ("prefix", "on"), 4: ("full", "on")}
    for wg_count in (1, 2, 4):
        xor, gso = profiles[wg_count]
        for attachment in ("tcx", "classic_tc"):
            for checksum in ("kfunc", "kprobe"):
                result.append(
                    Cell(
                        wg_count,
                        attachment,
                        checksum,
                        "modern" if checksum == "kfunc" else "legacy_515",
                        xor,
                        gso,
                    )
                )
    return result


def kernel_pair(release: str) -> tuple[int, int]:
    match = re.match(r"(\d+)\.(\d+)", release)
    if not match:
        raise ValueError(f"cannot classify kernel release {release!r}")
    return int(match.group(1)), int(match.group(2))


def classify(cell: Cell, release: str) -> tuple[str, str]:
    version = kernel_pair(release)
    if version <= (5, 15) and cell.attachment_backend == "tcx":
        return "SKIP_UNSUPPORTED", "linux-5.15-has-no-production-tcx-contract"
    if version <= (5, 15) and cell.checksum_backend == "kfunc":
        return "REJECT_UNSUPPORTED", "linux-5.15-requires-legacy-kprobe-bridge"
    return "RUN", "capability-must-pass-root-cell-preflight"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("plan", "run"))
    parser.add_argument("--source", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--kernel-release", default=platform.release())
    parser.add_argument("--matrix-id")
    return parser.parse_args()


def validate(args: argparse.Namespace) -> tuple[pathlib.Path, str, str]:
    source = pathlib.Path(args.source)
    source_text = str(source)
    match = STAGE_RE.fullmatch(source_text)
    if not match:
        raise SystemExit("source must be the exact root-owned source stage")
    if not HEX40_RE.fullmatch(args.commit) or args.commit in {"0" * 40, "f" * 40}:
        raise SystemExit("commit must be a non-sentinel 40 character lowercase SHA")
    matrix_id = args.matrix_id or secrets.token_hex(4)
    if not RUN_RE.fullmatch(matrix_id):
        raise SystemExit("matrix-id must be 8 lowercase hex characters")
    kernel_pair(args.kernel_release)
    return source, match.group(1), matrix_id


def iso_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def ensure_run_parent() -> None:
    if not RUN_PARENT.exists():
        RUN_PARENT.mkdir(mode=0o700, parents=False, exist_ok=False)
    if (
        not RUN_PARENT.is_dir()
        or RUN_PARENT.is_symlink()
        or RUN_PARENT.resolve() != RUN_PARENT
    ):
        raise SystemExit("persistent run parent identity is unsafe")
    shape = RUN_PARENT.stat()
    if shape.st_uid != 0 or shape.st_gid != 0 or stat.S_IMODE(shape.st_mode) != 0o700:
        raise SystemExit("persistent run parent must be root:root mode 0700")


def main() -> int:
    args = parse_args()
    source, stage_id, matrix_id = validate(args)
    runner = source / "scripts/realhost-b82-faketcp-backends-v1/root-cell.sh"
    matrix_root = RUN_PARENT / f"{stage_id}-{matrix_id}"
    document = {
        "format": "wg-mix-ebpf-b82-faketcp-backends-v1",
        "mode": args.mode,
        "stage_id": stage_id,
        "matrix_id": matrix_id,
        "commit": args.commit,
        "kernel_release": args.kernel_release,
        "xdp_contract": "exact-generic-always",
        "cells": [],
    }
    for index, cell in enumerate(cells(), start=1):
        disposition, reason = classify(cell, args.kernel_release)
        run_id = hashlib.sha256(f"{matrix_id}:{index}".encode()).hexdigest()[:8]
        argv = [
            "/bin/bash",
            "-p",
            str(runner),
            args.mode,
            "--source",
            str(source),
            "--commit",
            args.commit,
            "--run-id",
            run_id,
            "--label",
            cell.label,
            "--wg-count",
            str(cell.wg_count),
            "--attachment-backend",
            cell.attachment_backend,
            "--checksum-backend",
            cell.checksum_backend,
            "--artifact",
            cell.artifact,
            "--xor",
            cell.xor,
            "--gso",
            cell.gso,
        ]
        entry = asdict(cell) | {
            "label": cell.label,
            "run_id": run_id,
            "disposition": disposition,
            "reason": reason,
            "argv": argv,
        }
        document["cells"].append(entry)

    if args.mode == "plan":
        print(json.dumps(document, indent=2, sort_keys=True))
        return 0

    if os.geteuid() != 0 or os.getegid() != 0:
        raise SystemExit("matrix run requires root")
    if not source.is_dir() or source.is_symlink() or source.resolve() != source:
        raise SystemExit("source stage identity is unsafe")
    shape = source.stat()
    if shape.st_uid != 0 or shape.st_gid != 0 or shape.st_mode & 0o022:
        raise SystemExit("source stage must be root-owned and not group/world writable")
    actual = subprocess.run(
        ["/usr/bin/git", "-C", str(source), "rev-parse", "--verify", "HEAD^{commit}"],
        text=True,
        capture_output=True,
        check=False,
        env=SAFE_ENV,
    )
    if actual.returncode or actual.stdout.strip() != args.commit:
        sys.stderr.write(actual.stdout)
        sys.stderr.write(actual.stderr)
        raise SystemExit("staged source commit mismatch")
    ensure_run_parent()
    matrix_root.mkdir(mode=0o700, parents=False, exist_ok=False)
    (matrix_root / "manifest.json").write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    summary: list[dict[str, object]] = []
    for entry in document["cells"]:
        if entry["disposition"] != "RUN":
            summary.append(
                {
                    "label": entry["label"],
                    "result": entry["disposition"],
                    "reason": entry["reason"],
                }
            )
            continue
        stdout_path = matrix_root / f"{entry['label']}.stdout.log"
        stderr_path = matrix_root / f"{entry['label']}.stderr.log"
        started = iso_now()
        with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
            completed = subprocess.run(
                entry["argv"],
                stdout=stdout,
                stderr=stderr,
                check=False,
                env=SAFE_ENV,
            )
        summary.append(
            {
                "label": entry["label"],
                "result": "PASS" if completed.returncode == 0 else "FAIL",
                "returncode": completed.returncode,
                "started": started,
                "finished": iso_now(),
                "stdout": str(stdout_path),
                "stderr": str(stderr_path),
            }
        )
        if completed.returncode:
            for item in summary:
                print(json.dumps(item, sort_keys=True))
            sys.stderr.write(stdout_path.read_text(encoding="utf-8", errors="replace"))
            sys.stderr.write(stderr_path.read_text(encoding="utf-8", errors="replace"))
            (matrix_root / "summary.json").write_text(
                json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            return completed.returncode
    (matrix_root / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    for item in summary:
        print(json.dumps(item, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
