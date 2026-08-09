#!/usr/bin/env python3
"""Fail-closed iperf3 JSON checks for the reviewed real-host matrix."""

from __future__ import annotations

import argparse
import json
import math
import re
import statistics
import sys
from pathlib import Path
from typing import Any


MSS_ESTIMATE = 1448
OBSERVATION_COUNTERS = (
    "egress_rule_miss",
    "ingress_rule_miss",
)
HARD_ERROR_COUNTERS = (
    "egress_bad_type",
    "egress_bad_length",
    "egress_fragment",
    "egress_ipv6_ext",
    "ingress_bad_type",
    "ingress_bad_length",
    "ingress_fragment",
    "ingress_ipv6_ext",
    "checksum_error",
    "skb_load_error",
    "skb_store_error",
    "icmp_checksum_error",
    "xor_key_missing",
    "xor_len_overflow",
    "xor_bad_type_after_decrypt",
    "xor_load_error",
    "xor_store_error",
    "xor_csum_error",
    "ingress_bad_checksum",
    "egress_bad_checksum",
    "xor_egress_dispatch_error",
    "xor_ingress_dispatch_error",
)


class CheckError(ValueError):
    """The iperf document does not meet the reviewed acceptance contract."""


def integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CheckError(f"{label} must be a non-negative integer")
    return value


def number(value: Any, label: str) -> float:
    if isinstance(value, bool):
        raise CheckError(f"{label} must be numeric")
    try:
        result = float(value)
    except (TypeError, ValueError) as error:
        raise CheckError(f"{label} must be numeric") from error
    if not math.isfinite(result) or result < 0:
        raise CheckError(f"{label} must be finite and non-negative")
    return result


def document(path: Path) -> dict[str, Any]:
    if not path.is_absolute():
        raise CheckError(f"iperf JSON path must be absolute: {path}")
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, json.JSONDecodeError) as error:
        raise CheckError(f"read iperf JSON {path}: {error}") from error
    if not isinstance(value, dict):
        raise CheckError(f"iperf JSON top level must be an object: {path}")
    if value.get("error"):
        raise CheckError(f"iperf reported an error in {path}: {value['error']}")
    return value


def status_stats(path: Path) -> dict[str, int]:
    value = document(path)
    if value.get("dataplane_error"):
        raise CheckError(f"dataplane status reported an error in {path}")
    dataplane = value.get("dataplane")
    if not isinstance(dataplane, dict) or not isinstance(dataplane.get("stats"), dict):
        raise CheckError(f"dataplane stats are missing in {path}")
    result: dict[str, int] = {}
    for name, raw in dataplane["stats"].items():
        if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9_]{1,80}", name):
            raise CheckError(f"invalid dataplane counter name in {path}")
        result[name] = integer(raw, f"counter {name}")
    for required in (
        "egress_rewrite_ok",
        "ingress_rewrite_ok",
        *OBSERVATION_COUNTERS,
        *HARD_ERROR_COUNTERS,
    ):
        if required not in result:
            raise CheckError(f"required dataplane counter {required} is missing in {path}")
    return result


def counter_deltas(
    before: dict[str, int],
    after: dict[str, int],
    *,
    require_egress: bool,
    require_ingress: bool,
    forbid_rewrite_growth: bool,
) -> dict[str, int]:
    if set(before) != set(after):
        raise CheckError("dataplane counter schema changed during a matrix cell")
    deltas: dict[str, int] = {}
    for name in sorted(before):
        delta = after[name] - before[name]
        if delta < 0:
            raise CheckError(f"dataplane counter {name} decreased")
        deltas[name] = delta
    for name in HARD_ERROR_COUNTERS:
        if deltas[name] != 0:
            raise CheckError(f"dataplane error counter {name} grew by {deltas[name]}")
    if forbid_rewrite_growth and (
        deltas["egress_rewrite_ok"] != 0 or deltas["ingress_rewrite_ok"] != 0
    ):
        raise CheckError("bare TCP control unexpectedly changed managed rewrite counters")
    if require_egress and deltas["egress_rewrite_ok"] <= 0:
        raise CheckError("program-active traffic did not traverse managed egress")
    if require_ingress and deltas["ingress_rewrite_ok"] <= 0:
        raise CheckError("program-active traffic did not traverse managed ingress")
    return deltas


def check_stats(args: argparse.Namespace) -> dict[str, int]:
    return counter_deltas(
        status_stats(args.before),
        status_stats(args.after),
        require_egress=args.require_egress,
        require_ingress=args.require_ingress,
        forbid_rewrite_growth=args.forbid_rewrite_growth,
    )


def check_stats_contrast(args: argparse.Namespace) -> dict[str, dict[str, int]]:
    before = status_stats(args.before)
    middle = status_stats(args.middle)
    after = status_stats(args.after)
    bare = counter_deltas(
        before,
        middle,
        require_egress=False,
        require_ingress=False,
        forbid_rewrite_growth=False,
    )
    active = counter_deltas(
        middle,
        after,
        require_egress=True,
        require_ingress=True,
        forbid_rewrite_growth=False,
    )
    for name in ("egress_rewrite_ok", "ingress_rewrite_ok"):
        if active[name] <= bare[name]:
            raise CheckError(
                f"program-active {name} delta={active[name]} did not exceed "
                f"same-duration bare/background delta={bare[name]}"
            )
    return {"bare_or_background": bare, "program_active": active}


def fairness(values: list[int]) -> float:
    total = sum(values)
    squares = sum(value * value for value in values)
    if not values or total == 0 or squares == 0:
        return 0.0
    return total * total / (len(values) * squares)


def expected_direction(
    doc: dict[str, Any], direction: str, streams: int, expected_seconds: float
) -> None:
    start = doc.get("start")
    if not isinstance(start, dict) or not isinstance(start.get("test_start"), dict):
        raise CheckError("iperf start.test_start is missing")
    test_start = start["test_start"]
    if integer(test_start.get("num_streams"), "num_streams") != streams:
        raise CheckError("iperf stream count differs from the reviewed argv")
    reverse = integer(test_start.get("reverse", 0), "reverse")
    bidirectional = integer(test_start.get("bidir", 0), "bidir")
    if reverse != (1 if direction == "reverse" else 0):
        raise CheckError("iperf reverse marker differs from the reviewed argv")
    if bidirectional != (1 if direction == "bidir" else 0):
        raise CheckError("iperf bidirectional marker differs from the reviewed argv")
    if number(test_start.get("duration"), "test_start duration") != expected_seconds:
        raise CheckError("iperf configured duration differs from the reviewed argv")


def reviewed_session(args: argparse.Namespace) -> tuple[float, float, float, int]:
    expected_seconds = number(args.expected_seconds, "expected seconds")
    maximum_deviation = number(
        args.maximum_duration_deviation, "maximum duration deviation"
    )
    minimum_delivery_ratio = number(
        args.minimum_delivery_ratio, "minimum delivery ratio"
    )
    minimum_stream_bytes = integer(args.minimum_stream_bytes, "minimum stream bytes")
    if (
        expected_seconds <= 0
        or not 0 < minimum_delivery_ratio <= 1
        or minimum_stream_bytes <= 0
    ):
        raise CheckError("iperf session thresholds are outside the reviewed range")
    return expected_seconds, maximum_deviation, minimum_delivery_ratio, minimum_stream_bytes


def measured_groups(
    doc: dict[str, Any],
    direction: str,
    streams: int,
    expected_seconds: float,
    maximum_duration_deviation: float,
    minimum_delivery_ratio: float,
    minimum_stream_bytes: int,
) -> list[dict[str, float | int]]:
    end = doc.get("end")
    if not isinstance(end, dict) or not isinstance(end.get("streams"), list):
        raise CheckError("iperf end.streams is missing")
    raw_streams = end["streams"]
    expected_count = streams * (2 if direction == "bidir" else 1)
    if len(raw_streams) != expected_count:
        raise CheckError(
            f"iperf end.streams count={len(raw_streams)}, want {expected_count}"
        )
    grouped: dict[str, list[dict[str, Any]]] = {
        "reverse" if direction == "reverse" else "forward": []
    }
    if direction == "bidir":
        grouped["reverse"] = []
    for index, raw in enumerate(raw_streams):
        if not isinstance(raw, dict):
            raise CheckError(f"iperf stream {index} is not an object")
        sender = raw.get("sender")
        receiver = raw.get("receiver")
        if not isinstance(sender, dict) or not isinstance(receiver, dict):
            raise CheckError(f"iperf stream {index} has no sender/receiver pair")
        marker = sender.get("sender")
        if not isinstance(marker, bool) or receiver.get("sender") is not marker:
            raise CheckError(f"iperf stream {index} direction markers are invalid")
        if direction == "bidir":
            label = "forward" if marker else "reverse"
        else:
            want_marker = direction == "forward"
            if marker is not want_marker:
                raise CheckError(f"iperf stream {index} direction is unexpected")
            label = direction
        grouped[label].append(raw)

    result: list[dict[str, float | int]] = []
    for label, group in sorted(grouped.items()):
        if len(group) != streams:
            raise CheckError(f"iperf {label} stream count is incomplete")
        received = [
            integer(item["receiver"].get("bytes"), f"{label} receiver bytes")
            for item in group
        ]
        sent = [
            integer(item["sender"].get("bytes"), f"{label} sender bytes")
            for item in group
        ]
        if any(value < minimum_stream_bytes for value in (*sent, *received)):
            raise CheckError(f"iperf {label} stream bytes are below minimum")
        if any(received_value > sent_value for sent_value, received_value in zip(sent, received)):
            raise CheckError(f"iperf {label} received bytes exceed sent bytes")
        stream_delivery_ratios = [
            received_value / sent_value
            for sent_value, received_value in zip(sent, received)
        ]
        if min(stream_delivery_ratios) < minimum_delivery_ratio:
            raise CheckError(f"iperf {label} stream delivery ratio is below minimum")
        retransmits = sum(
            integer(item["sender"].get("retransmits"), f"{label} retransmits")
            for item in group
        )
        suffix = "_bidir_reverse" if direction == "bidir" and label == "reverse" else ""
        summary = end.get(f"sum_received{suffix}")
        sent_summary = end.get(f"sum_sent{suffix}")
        if not isinstance(summary, dict) or not isinstance(sent_summary, dict):
            raise CheckError(f"iperf {label} summary is missing")
        if integer(summary.get("bytes"), f"{label} summary bytes") != sum(received):
            raise CheckError(f"iperf {label} received-byte summary mismatch")
        if integer(sent_summary.get("bytes"), f"{label} sent bytes") != sum(sent):
            raise CheckError(f"iperf {label} sent-byte summary mismatch")
        if integer(sent_summary.get("retransmits"), f"{label} retransmit summary") != retransmits:
            raise CheckError(f"iperf {label} retransmit summary mismatch")
        received_seconds = number(summary.get("seconds"), f"{label} received seconds")
        sent_seconds = number(sent_summary.get("seconds"), f"{label} sent seconds")
        if (
            abs(received_seconds - expected_seconds) > maximum_duration_deviation
            or abs(sent_seconds - expected_seconds) > maximum_duration_deviation
        ):
            raise CheckError(f"iperf {label} measured duration differs from the reviewed argv")
        delivery_ratio = sum(received) / sum(sent)
        if delivery_ratio < minimum_delivery_ratio:
            raise CheckError(f"iperf {label} aggregate delivery ratio is below minimum")
        estimated_segments = max(1, math.ceil(sum(sent) / MSS_ESTIMATE))
        result.append(
            {
                "direction": label,
                "sent_bytes": sum(sent),
                "received_bytes": sum(received),
                "throughput_mbps": sum(received) * 8 / received_seconds / 1_000_000,
                "retransmits": retransmits,
                "retransmit_rate": retransmits / estimated_segments,
                "fairness": fairness(received),
                "sent_duration_seconds": sent_seconds,
                "received_duration_seconds": received_seconds,
                "delivery_ratio": delivery_ratio,
                "minimum_stream_delivery_ratio": min(stream_delivery_ratios),
                "minimum_stream_sent_bytes": min(sent),
                "minimum_stream_received_bytes": min(received),
            }
        )
    return result


def check_one(args: argparse.Namespace) -> list[dict[str, float | int]]:
    doc = document(args.path)
    expected_seconds, maximum_deviation, minimum_delivery_ratio, minimum_stream_bytes = (
        reviewed_session(args)
    )
    expected_direction(doc, args.direction, args.streams, expected_seconds)
    groups = measured_groups(
        doc,
        args.direction,
        args.streams,
        expected_seconds,
        maximum_deviation,
        minimum_delivery_ratio,
        minimum_stream_bytes,
    )
    for group in groups:
        if float(group["fairness"]) < args.minimum_fairness:
            raise CheckError(f"Jain fairness below minimum: {group}")
        if float(group["retransmit_rate"]) > args.maximum_retransmit_rate:
            raise CheckError(f"estimated retransmit rate above maximum: {group}")
    return groups


def soak_group_totals(
    groups: list[dict[str, float | int]],
) -> dict[str, float | int]:
    sent_bytes = sum(int(group["sent_bytes"]) for group in groups)
    received_bytes = sum(int(group["received_bytes"]) for group in groups)
    retransmits = sum(int(group["retransmits"]) for group in groups)
    segments = max(1, math.ceil(sent_bytes / MSS_ESTIMATE))
    return {
        "sent_bytes": sent_bytes,
        "received_bytes": received_bytes,
        "throughput_mbps": sum(float(group["throughput_mbps"]) for group in groups),
        "retransmits": retransmits,
        "estimated_segments": segments,
        "retransmit_rate": retransmits / segments,
        "delivery_ratio": received_bytes / sent_bytes,
        "minimum_stream_delivery_ratio": min(
            float(group["minimum_stream_delivery_ratio"]) for group in groups
        ),
        "minimum_stream_sent_bytes": min(
            int(group["minimum_stream_sent_bytes"]) for group in groups
        ),
        "minimum_stream_received_bytes": min(
            int(group["minimum_stream_received_bytes"]) for group in groups
        ),
    }


def first_hour_throughput_baseline(
    windows: list[dict[str, float | int]], minimum_ratio: float
) -> tuple[float, float]:
    if len(windows) != 12:
        raise CheckError(f"first-hour soak window count={len(windows)}, want 12")
    baseline = statistics.median(
        float(window["throughput_mbps"]) for window in windows
    )
    floor = baseline * minimum_ratio
    for window in windows:
        if float(window["throughput_mbps"]) < floor:
            raise CheckError(f"soak throughput window below floor: {window}")
    return baseline, floor


def check_soak(args: argparse.Namespace) -> dict[str, Any]:
    expected_seconds, maximum_deviation, minimum_delivery_ratio, minimum_stream_bytes = (
        reviewed_session(args)
    )
    if args.expected_windows != 12:
        raise CheckError(
            f"reviewed first-hour soak requires 12 windows, got {args.expected_windows}"
        )
    if len(args.paths) != args.expected_windows:
        raise CheckError(
            f"soak JSON count={len(args.paths)}, want {args.expected_windows}"
        )
    windows: list[dict[str, float | int]] = []
    total_received_bytes = 0
    total_sent_bytes = 0
    total_retransmits = 0
    for path in args.paths:
        doc = document(path)
        expected_direction(doc, "bidir", args.streams, expected_seconds)
        groups = measured_groups(
            doc,
            "bidir",
            args.streams,
            expected_seconds,
            maximum_deviation,
            minimum_delivery_ratio,
            minimum_stream_bytes,
        )
        totals = soak_group_totals(groups)
        if float(totals["retransmit_rate"]) > args.maximum_window_retransmit_rate:
            raise CheckError(
                f"soak retransmit window above maximum in {path}: "
                f"{totals['retransmit_rate']}"
            )
        if any(float(group["fairness"]) < args.minimum_fairness for group in groups):
            raise CheckError(f"soak fairness below minimum in {path}")
        windows.append({"path": str(path), **totals})
        total_received_bytes += int(totals["received_bytes"])
        total_sent_bytes += int(totals["sent_bytes"])
        total_retransmits += int(totals["retransmits"])
    baseline, floor = first_hour_throughput_baseline(
        windows, args.minimum_throughput_ratio
    )
    overall_segments = max(1, math.ceil(total_sent_bytes / MSS_ESTIMATE))
    overall_rate = total_retransmits / overall_segments
    if overall_rate > args.maximum_overall_retransmit_rate:
        raise CheckError(f"soak overall retransmit rate above maximum: {overall_rate}")
    return {
        "windows": windows,
        "baseline_mbps": baseline,
        "minimum_mbps": floor,
        "sent_bytes": total_sent_bytes,
        "received_bytes": total_received_bytes,
        "retransmits": total_retransmits,
        "retransmit_rate": overall_rate,
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    subparsers = result.add_subparsers(dest="command", required=True)
    one = subparsers.add_parser("one")
    one.add_argument("path", type=Path)
    one.add_argument("--direction", choices=("forward", "reverse", "bidir"), required=True)
    one.add_argument("--streams", type=int, choices=(1, 4, 16), required=True)
    one.add_argument("--minimum-fairness", type=float, default=0.90)
    one.add_argument("--maximum-retransmit-rate", type=float, default=0.0001)
    one.add_argument("--expected-seconds", type=float, required=True)
    one.add_argument("--maximum-duration-deviation", type=float, required=True)
    one.add_argument("--minimum-delivery-ratio", type=float, required=True)
    one.add_argument("--minimum-stream-bytes", type=int, required=True)

    soak = subparsers.add_parser("soak")
    soak.add_argument("paths", nargs="+", type=Path)
    soak.add_argument("--expected-windows", type=int, required=True)
    soak.add_argument("--streams", type=int, choices=(4, 16), required=True)
    soak.add_argument("--minimum-fairness", type=float, default=0.90)
    soak.add_argument("--maximum-window-retransmit-rate", type=float, default=0.005)
    soak.add_argument("--maximum-overall-retransmit-rate", type=float, default=0.001)
    soak.add_argument("--minimum-throughput-ratio", type=float, default=0.70)
    soak.add_argument("--expected-seconds", type=float, required=True)
    soak.add_argument("--maximum-duration-deviation", type=float, required=True)
    soak.add_argument("--minimum-delivery-ratio", type=float, required=True)
    soak.add_argument("--minimum-stream-bytes", type=int, required=True)

    stats_parser = subparsers.add_parser("stats")
    stats_parser.add_argument("before", type=Path)
    stats_parser.add_argument("after", type=Path)
    stats_parser.add_argument("--require-egress", action="store_true")
    stats_parser.add_argument("--require-ingress", action="store_true")
    stats_parser.add_argument("--forbid-rewrite-growth", action="store_true")

    contrast = subparsers.add_parser("stats-contrast")
    contrast.add_argument("before", type=Path)
    contrast.add_argument("middle", type=Path)
    contrast.add_argument("after", type=Path)

    return result


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "one":
            output = check_one(args)
        elif args.command == "soak":
            output = check_soak(args)
        elif args.command == "stats":
            output = check_stats(args)
        elif args.command == "stats-contrast":
            output = check_stats_contrast(args)
        else:
            raise CheckError(f"unsupported checker command: {args.command}")
    except CheckError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
