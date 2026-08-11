#!/usr/bin/env python3
"""Build a concise public stability report from controller-owned JSON evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def load(path: Path) -> Any:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise SystemExit(f"unsafe evidence path: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def nonnegative(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise SystemExit(f"invalid {label}")
    return value


def summarize(document: dict[str, Any]) -> dict[str, Any]:
    samples = document.get("samples")
    if not isinstance(samples, list) or len(samples) < 2:
        raise SystemExit("report needs at least two samples")
    ping = document.get("ping")
    if not isinstance(ping, dict):
        raise SystemExit("missing ping summary")
    transmitted = nonnegative(ping.get("transmitted"), "ping transmitted")
    received = nonnegative(ping.get("received"), "ping received")
    if transmitted < 1 or received > transmitted:
        raise SystemExit("invalid ping counts")
    loss = (transmitted - received) / transmitted
    max_consecutive_loss = nonnegative(
        ping.get("max_consecutive_loss"), "max consecutive loss"
    )
    first = samples[0]
    last = samples[-1]
    endpoints: dict[str, Any] = {}
    for role in ("b82", "public"):
        before = first.get(role)
        after = last.get(role)
        if not isinstance(before, dict) or not isinstance(after, dict):
            raise SystemExit(f"missing {role} samples")
        tx_delta = nonnegative(after.get("wg_tx"), f"{role} wg_tx") - nonnegative(
            before.get("wg_tx"), f"{role} initial wg_tx"
        )
        rx_delta = nonnegative(after.get("wg_rx"), f"{role} wg_rx") - nonnegative(
            before.get("wg_rx"), f"{role} initial wg_rx"
        )
        rewrite_delta = nonnegative(
            after.get("rewrite_success"), f"{role} rewrite"
        ) - nonnegative(before.get("rewrite_success"), f"{role} initial rewrite")
        error_delta = nonnegative(after.get("error_total"), f"{role} errors") - nonnegative(
            before.get("error_total"), f"{role} initial errors"
        )
        sample_time = nonnegative(after.get("timestamp"), f"{role} timestamp")
        handshake = nonnegative(
            after.get("latest_handshake"), f"{role} latest handshake"
        )
        handshake_age = sample_time - handshake if handshake else sample_time
        endpoints[role] = {
            "wg_tx_delta": tx_delta,
            "wg_rx_delta": rx_delta,
            "rewrite_success_delta": rewrite_delta,
            "error_delta": error_delta,
            "latest_handshake_age_seconds": handshake_age,
            "pass": tx_delta > 0
            and rx_delta > 0
            and rewrite_delta > 0
            and error_delta == 0
            and 0 <= handshake_age <= 180,
        }
    passed = (
        loss <= 0.01
        and max_consecutive_loss < 3
        and all(item["pass"] for item in endpoints.values())
    )
    return {
        "schema": "wg-mix-public-stability-report-v1",
        "commit": document.get("commit"),
        "run_id": document.get("run_id"),
        "samples": len(samples),
        "ping_loss_ratio": loss,
        "ping_loss_percent": loss * 100.0,
        "max_consecutive_ping_loss": max_consecutive_loss,
        "endpoints": endpoints,
        "result": "PASS" if passed else "FAIL",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    document = load(args.evidence)
    if not isinstance(document, dict):
        raise SystemExit("evidence root must be an object")
    report = summarize(document)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        if not args.output.is_absolute() or args.output.exists():
            raise SystemExit("output must be a new absolute path")
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if report["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
