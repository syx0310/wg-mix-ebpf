#!/usr/bin/env python3
"""Validate a complete B82 performance matrix and render its Chinese report."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import re
import sys
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True


CELL_COUNT = 63
SAMPLE_COUNT = 567
REPETITIONS = 3
MINIMUM_BYTES = 1_048_576
MAXIMUM_RETRANSMITS = 2_147_483_647
MINIMUM_FAIRNESS = 0.90
DIRECTIONS = ("forward", "reverse", "bidir")
PREFIX_LENGTHS = (4, 16, 64, 128, 256, 512, 1024, 2048)
CELL_HEADER = (
    "ordinal",
    "label",
    "transport",
    "attachment_backend",
    "checksum_backend",
    "artifact",
    "cipher",
    "max_bytes",
    "run_id",
    "evidence",
)


class ReportError(ValueError):
    """The matrix evidence is incomplete or internally inconsistent."""


def expected_cells() -> list[tuple[str, str, str, str, str, str, int]]:
    cells: list[tuple[str, str, str, str, str, str, int]] = [
        ("wireguard-baseline", "wireguard", "none", "none", "none", "none", 0)
    ]
    for backend in ("tcx", "classic_tc"):
        cells.append((f"udp-{backend}-none", "udp", backend, "none", "baseline", "none", 0))
        for size in PREFIX_LENGTHS:
            cells.append(
                (f"udp-{backend}-prefix-{size}", "udp", backend, "none", "baseline", "prefix", size)
            )
        cells.append(
            (f"udp-{backend}-full-2048", "udp", backend, "none", "baseline", "full", 2048)
        )
    for backend in ("tcx", "classic_tc"):
        cells.append((f"icmp-{backend}-none", "icmp", backend, "none", "baseline", "none", 0))
    for checksum, artifact in (("kfunc", "modern"), ("kprobe", "legacy_515")):
        for backend in ("tcx", "classic_tc"):
            cells.append(
                (
                    f"faketcp-{backend}-{checksum}-none",
                    "faketcp",
                    backend,
                    checksum,
                    artifact,
                    "none",
                    0,
                )
            )
            for size in PREFIX_LENGTHS:
                cells.append(
                    (
                        f"faketcp-{backend}-{checksum}-prefix-{size}",
                        "faketcp",
                        backend,
                        checksum,
                        artifact,
                        "prefix",
                        size,
                    )
                )
            cells.append(
                (
                    f"faketcp-{backend}-{checksum}-full-2048",
                    "faketcp",
                    backend,
                    checksum,
                    artifact,
                    "full",
                    2048,
                )
            )
    if len(cells) != CELL_COUNT or len({cell[0] for cell in cells}) != CELL_COUNT:
        raise AssertionError("internal B82 matrix definition is not 63 unique cells")
    return cells


def parse_fields(path: Path) -> dict[str, str]:
    raw = path.read_bytes()
    if not raw.endswith(b"\n") or b"\0" in raw or b"\r" in raw:
        raise ReportError(f"{path}: non-canonical field file")
    result: dict[str, str] = {}
    try:
        lines = raw[:-1].decode("utf-8", "strict").split("\n")
    except UnicodeDecodeError as exc:
        raise ReportError(f"{path}: field file is not UTF-8") from exc
    for line in lines:
        if not line or "=" not in line:
            raise ReportError(f"{path}: malformed field line")
        key, value = line.split("=", 1)
        if not re.fullmatch(r"[a-z][a-z0-9_]*", key) or key in result or not value:
            raise ReportError(f"{path}: malformed or duplicate field {key!r}")
        result[key] = value
    return result


def load_checker(source_root: Path) -> Any:
    path = source_root / "scripts" / "check-iperf3-tcp.py"
    spec = importlib.util.spec_from_file_location("wg_mix_iperf_checker", path)
    if spec is None or spec.loader is None:
        raise ReportError(f"cannot load iperf checker from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_cell_index(path: Path) -> list[dict[str, str]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or tuple(lines[0].split("\t")) != CELL_HEADER:
        raise ReportError("cells.v1.tsv has an unexpected header")
    rows: list[dict[str, str]] = []
    for number, line in enumerate(lines[1:], start=2):
        fields = line.split("\t")
        if len(fields) != len(CELL_HEADER) or any(not value for value in fields):
            raise ReportError(f"cells.v1.tsv:{number}: malformed row")
        rows.append(dict(zip(CELL_HEADER, fields, strict=True)))
    if len(rows) != CELL_COUNT:
        raise ReportError(f"cell index has {len(rows)} rows, want {CELL_COUNT}")
    return rows


def validate_cell_set(
    rows: list[dict[str, str]], matrix_root: Path | None = None
) -> None:
    wanted = expected_cells()
    for ordinal, (row, wanted_cell) in enumerate(zip(rows, wanted, strict=True), start=1):
        label, transport, attachment, checksum, artifact, cipher, max_bytes = wanted_cell
        expected = {
            "ordinal": str(ordinal),
            "label": label,
            "transport": transport,
            "attachment_backend": attachment,
            "checksum_backend": checksum,
            "artifact": artifact,
            "cipher": cipher,
            "max_bytes": str(max_bytes),
        }
        for key, value in expected.items():
            if row[key] != value:
                raise ReportError(
                    f"cell {ordinal} {key}={row[key]!r}, want {value!r}"
                )
        if not re.fullmatch(r"[0-9a-f]{8}", row["run_id"]):
            raise ReportError(f"cell {ordinal} has an invalid run ID")
        if matrix_root is not None:
            expected_run_id = hashlib.sha256(
                f"{matrix_root.name}:{ordinal}:{label}".encode("ascii")
            ).hexdigest()[:8]
            if row["run_id"] != expected_run_id:
                raise ReportError(
                    f"cell {ordinal} run_id={row['run_id']!r}, "
                    f"want deterministic {expected_run_id!r}"
                )
        expected_evidence = (
            str(matrix_root / "children" / row["run_id"] / "evidence")
            if matrix_root is not None
            else None
        )
        if (
            expected_evidence is not None
            and row["evidence"] != expected_evidence
        ) or (
            expected_evidence is None
            and not re.fullmatch(
                r"/var/tmp/wg-mix-ebpf-performance-tests/[0-9a-f]{8}/children/[0-9a-f]{8}/evidence",
                row["evidence"],
            )
        ):
            raise ReportError(f"cell {ordinal} has an invalid evidence path")
    if len({row["run_id"] for row in rows}) != CELL_COUNT:
        raise ReportError("cell run IDs are not unique")


def finite_number(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ReportError(f"{label} is not numeric")
    number = float(value)
    if not math.isfinite(number) or number < 0:
        raise ReportError(f"{label} must be finite and non-negative")
    return number


def aggregate_cell(
    checker: Any, raw_root: Path
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    wanted_names = {
        f"iperf-{direction}-r{repetition}.json"
        for direction in DIRECTIONS
        for repetition in range(1, REPETITIONS + 1)
    }
    if not raw_root.is_dir() or raw_root.is_symlink():
        raise ReportError(f"missing exact raw sample directory {raw_root}")
    observed_names: set[str] = set()
    for path in raw_root.iterdir():
        if not path.is_file() or path.is_symlink():
            raise ReportError(f"unsafe raw sample entry {path}")
        observed_names.add(path.name)
    if observed_names != wanted_names:
        raise ReportError(
            f"{raw_root}: raw sample set differs: "
            f"missing={sorted(wanted_names - observed_names)!r} "
            f"extra={sorted(observed_names - wanted_names)!r}"
        )
    result: list[dict[str, Any]] = []
    sample_sha256: dict[str, str] = {}
    for requested in DIRECTIONS:
        samples: list[list[dict[str, Any]]] = []
        for repetition in range(1, REPETITIONS + 1):
            path = raw_root / f"iperf-{requested}-r{repetition}.json"
            if not path.is_file() or path.is_symlink():
                raise ReportError(f"missing exact iperf sample {path}")
            try:
                raw = path.read_bytes()
                document = json.loads(raw.decode("utf-8"))
                if not isinstance(document, dict):
                    raise ValueError("top-level iperf3 JSON must be an object")
                sample = checker.validate_iperf(
                    document,
                    direction=requested,
                    expected_streams=1,
                    minimum_bytes=MINIMUM_BYTES,
                    maximum_retransmits=MAXIMUM_RETRANSMITS,
                    minimum_fairness=MINIMUM_FAIRNESS,
                )
            except (
                OSError,
                UnicodeError,
                json.JSONDecodeError,
                ValueError,
                KeyError,
                TypeError,
                OverflowError,
            ) as exc:
                raise ReportError(f"invalid iperf sample {path}: {exc}") from exc
            sample_sha256[path.name] = hashlib.sha256(raw).hexdigest()
            samples.append(sample)
        aggregates = checker.aggregate_iperf_results(
            samples, requested_direction=requested
        )
        for item in aggregates:
            if item.get("samples") != REPETITIONS:
                raise ReportError(f"{raw_root}: aggregate sample count is not 3")
            for key in (
                "throughput_mean_mbps",
                "throughput_pstdev_mbps",
                "throughput_min_mbps",
                "throughput_max_mbps",
                "fairness_mean",
                "fairness_min",
            ):
                item[key] = finite_number(item.get(key), f"{raw_root}:{key}")
            retransmits = item.get("retransmits_total")
            if (
                isinstance(retransmits, bool)
                or not isinstance(retransmits, int)
                or retransmits < 0
            ):
                raise ReportError(f"{raw_root}: retransmit total is invalid")
            if not (
                item["throughput_min_mbps"]
                <= item["throughput_mean_mbps"]
                <= item["throughput_max_mbps"]
            ):
                raise ReportError(f"{raw_root}: throughput min/mean/max are inconsistent")
            if not 0 <= item["fairness_min"] <= item["fairness_mean"] <= 1:
                raise ReportError(f"{raw_root}: Jain fairness is inconsistent")
            result.append(item)
    keys = [(item["requested_direction"], item["direction"]) for item in result]
    expected_keys = [
        ("forward", "forward"),
        ("reverse", "reverse"),
        ("bidir", "forward"),
        ("bidir", "reverse"),
        ("bidir", "aggregate"),
    ]
    if keys != expected_keys:
        raise ReportError(f"{raw_root}: aggregate direction set is {keys!r}")
    if len(sample_sha256) != 9:
        raise ReportError(f"{raw_root}: raw sample digest set is not exact")
    return result, dict(sorted(sample_sha256.items()))


def result_by_key(cell: dict[str, Any], requested: str, direction: str) -> dict[str, Any]:
    found = [
        value
        for value in cell["aggregates"]
        if value["requested_direction"] == requested and value["direction"] == direction
    ]
    if len(found) != 1:
        raise ReportError(f"missing aggregate {requested}/{direction}")
    return found[0]


def throughput_text(item: dict[str, Any]) -> str:
    return (
        f"{item['throughput_mean_mbps']:.2f} ± "
        f"{item['throughput_pstdev_mbps']:.2f} "
        f"({item['throughput_min_mbps']:.2f}–{item['throughput_max_mbps']:.2f})"
    )


def display_name(cell: dict[str, Any]) -> str:
    if cell["transport"] == "wireguard":
        return "原生 WireGuard"
    cipher = "无 XOR"
    if cell["cipher"] == "prefix":
        cipher = f"XOR 前缀 {cell['max_bytes']} B"
    elif cell["cipher"] == "full":
        cipher = "XOR 全载荷（上限 2048 B）"
    backend = {"tcx": "TCX", "classic_tc": "传统 TC"}[cell["attachment_backend"]]
    checksum = ""
    if cell["transport"] == "faketcp":
        checksum = f" / {cell['checksum_backend']} / {cell['artifact']}"
    return f"{cell['transport'].upper()} / {backend}{checksum} / {cipher}"


def render_markdown(document: dict[str, Any]) -> str:
    cells = document["cell_results"]
    retransmits_total = 0
    fairness_min = 1.0
    for cell in cells:
        selected = (
            result_by_key(cell, "forward", "forward"),
            result_by_key(cell, "reverse", "reverse"),
            result_by_key(cell, "bidir", "aggregate"),
        )
        retransmits_total += sum(int(item["retransmits_total"]) for item in selected)
        fairness_min = min(fairness_min, *(float(item["fairness_min"]) for item in selected))
    lines = [
        "# B82 完整性能矩阵报告",
        "",
        "## 结论摘要",
        "",
        f"- 结果：`PASS`，完整配置 {CELL_COUNT}/{CELL_COUNT}，原始 iperf3 采样 {SAMPLE_COUNT}/{SAMPLE_COUNT}。",
        f"- 总重传：{retransmits_total}；全矩阵最低 Jain 公平性：{fairness_min:.6f}。",
        f"- Matrix ID：`{document['matrix_id']}`；commit：`{document['commit']}`；内核：`{document['kernel_release']}`。",
        "- 吞吐量统一为 Mbit/s；表内格式为“均值 ± 总体标准差（最小–最大）”。",
        "",
        "## 测试口径",
        "",
        "每个配置依次执行正向、反向、双向，各重复 3 次，每次 3 秒、单 TCP 流。"
        "双向汇总先在每轮内合并两个方向，再对 3 轮计算总体标准差；重传不重复计算双向的分项。",
        "",
    ]
    sections = (
        ("wireguard", "原生 WireGuard 基线"),
        ("udp", "UDP 模式"),
        ("icmp", "ICMP 模式"),
        ("faketcp", "FakeTCP 模式"),
    )
    for transport, title in sections:
        lines.extend(
            [
                f"## {title}",
                "",
                "| # | 配置 | 正向 | 反向 | 双向汇总 | 重传（9 次） | Jain（均值/最低） | Run ID |",
                "|---:|---|---:|---:|---:|---:|---:|---|",
            ]
        )
        for cell in cells:
            if cell["transport"] != transport:
                continue
            forward = result_by_key(cell, "forward", "forward")
            reverse = result_by_key(cell, "reverse", "reverse")
            bidir = result_by_key(cell, "bidir", "aggregate")
            selected = (forward, reverse, bidir)
            retransmits = sum(int(item["retransmits_total"]) for item in selected)
            fairness_mean = sum(float(item["fairness_mean"]) for item in selected) / 3
            minimum = min(float(item["fairness_min"]) for item in selected)
            lines.append(
                f"| {cell['ordinal']} | {display_name(cell)} | {throughput_text(forward)} | "
                f"{throughput_text(reverse)} | {throughput_text(bidir)} | {retransmits} | "
                f"{fairness_mean:.6f} / {minimum:.6f} | `{cell['run_id']}` |"
            )
        lines.append("")
    lines.extend(
        [
            "## 统计定义与证据",
            "",
            "标准差使用总体标准差（`pstdev`）。Jain 公平性由每个样本的实际接收字节计算；"
            "双向行使用该轮两个方向中的较低值。JSON 汇总保留未舍入浮点值，Markdown 仅做显示舍入。",
            "",
            f"原始 567 个客户端 JSON、逐格元数据及规范化结果均位于 Matrix ID `{document['matrix_id']}` 的 evidence 导出中。",
            "",
        ]
    )
    return "\n".join(lines)


def build_report(matrix_root: Path, source_root: Path) -> tuple[dict[str, Any], str]:
    manifest = parse_fields(matrix_root / "manifest")
    if manifest.get("format") != "wg-mix-ebpf-b82-performance-matrix-v2":
        raise ReportError("matrix manifest format is not v2")
    if manifest.get("cells") != str(CELL_COUNT) or manifest.get("samples") != str(SAMPLE_COUNT):
        raise ReportError("matrix manifest count is not 63/567")
    matrix_id = manifest.get("run_id", "")
    if not re.fullmatch(r"[0-9a-f]{8}", matrix_id) or matrix_root.name != matrix_id:
        raise ReportError("matrix root and manifest run ID differ")
    commit = manifest.get("commit", "")
    kernel = manifest.get("kernel_release", "")
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or not re.fullmatch(r"[A-Za-z0-9._+-]+", kernel):
        raise ReportError("matrix source/kernel identity is malformed")
    rows = read_cell_index(matrix_root / "cells.v1.tsv")
    validate_cell_set(rows, matrix_root)
    checker = load_checker(source_root)
    cell_results: list[dict[str, Any]] = []
    for row in rows:
        evidence_root = Path(row["evidence"])
        if not evidence_root.is_dir() or evidence_root.is_symlink():
            raise ReportError(
                f"cell {row['ordinal']} lacks its exact child evidence directory"
            )
        cell_root = matrix_root / "cells" / f"{int(row['ordinal']):02d}-{row['label']}"
        if not cell_root.is_dir() or cell_root.is_symlink():
            raise ReportError(f"missing exact matrix cell directory {cell_root}")
        metadata = parse_fields(cell_root / "cell.v1")
        for key in CELL_HEADER:
            if metadata.get(key) != row[key]:
                raise ReportError(f"{cell_root}: metadata differs for {key}")
        if metadata.get("samples") != "9" or metadata.get("state") != "complete":
            raise ReportError(f"{cell_root}: cell is not a complete 9-sample result")
        aggregates, sample_sha256 = aggregate_cell(checker, cell_root / "raw")
        result: dict[str, Any] = {
            key: int(value) if key in {"ordinal", "max_bytes"} else value
            for key, value in row.items()
        }
        result["samples"] = 9
        result["sample_sha256"] = sample_sha256
        result["aggregates"] = aggregates
        cell_results.append(result)
    document = {
        "format": "wg-mix-ebpf-b82-performance-results-v1",
        "matrix_id": matrix_id,
        "commit": commit,
        "kernel_release": kernel,
        "cells": CELL_COUNT,
        "samples": SAMPLE_COUNT,
        "repetitions": REPETITIONS,
        "duration_seconds": 3,
        "cell_results": cell_results,
    }
    return document, render_markdown(document)


def write_exclusive(path: Path, data: str) -> None:
    parent = path.parent.resolve(strict=True)
    if parent / path.name != path.resolve(strict=False) or path.exists() or path.is_symlink():
        raise ReportError(f"output target is not fresh and canonical: {path}")
    with path.open("x", encoding="utf-8") as handle:
        handle.write(data)
    path.chmod(0o600)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix-root", required=True, type=Path)
    parser.add_argument("--source-root", required=True, type=Path)
    args = parser.parse_args()
    try:
        root = args.matrix_root.resolve(strict=True)
        source = args.source_root.resolve(strict=True)
        document, markdown = build_report(root, source)
        write_exclusive(
            root / "results.v1.json",
            json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        )
        write_exclusive(root / "report.zh-CN.md", markdown)
    except (
        OSError,
        UnicodeError,
        ReportError,
        ValueError,
        KeyError,
        TypeError,
        OverflowError,
    ) as exc:
        parser.error(str(exc))
    print(
        f"B82_PERFORMANCE_REPORT_COMPLETE matrix_id={document['matrix_id']} "
        f"cells={document['cells']} samples={document['samples']} "
        f"json={root / 'results.v1.json'} markdown={root / 'report.zh-CN.md'}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
