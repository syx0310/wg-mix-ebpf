#!/usr/bin/env python3
"""Validate per-flow TCP delivery and retransmits in iperf3 JSON output."""

from __future__ import annotations

import argparse
import json
import math
import statistics
from pathlib import Path
from typing import Any


def _integer(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{label} must be an integer")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str) and value.isascii() and value.isdigit():
        result = int(value)
    else:
        raise ValueError(f"{label} must be an integer: {value!r}")
    if result < 0:
        raise ValueError(f"{label} must be non-negative: {result}")
    return result


def _number(value: Any, label: str) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{label} must be numeric: {value!r}")
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be numeric: {value!r}") from exc
    if not math.isfinite(result) or result < 0:
        raise ValueError(f"{label} must be finite and non-negative: {result}")
    return result


def jain_fairness(values: list[int]) -> float:
    if not values or any(value < 0 for value in values):
        raise ValueError("fairness requires non-negative flow values")
    total = sum(values)
    squares = sum(value * value for value in values)
    if total == 0 or squares == 0:
        return 0.0
    return total * total / (len(values) * squares)


def _stream_directions(
    end: dict[str, Any],
    direction: str,
    expected_streams: int,
) -> dict[str, list[dict[str, Any]]]:
    raw_streams = end.get("streams")
    if not isinstance(raw_streams, list):
        raise ValueError("end.streams is missing or is not a list")
    expected_total = expected_streams * (2 if direction == "bidir" else 1)
    if len(raw_streams) != expected_total:
        raise ValueError(
            f"end.streams count={len(raw_streams)}, want {expected_total}"
        )

    grouped: dict[str, list[dict[str, Any]]] = {
        "forward" if direction != "reverse" else "reverse": []
    }
    if direction == "bidir":
        grouped["reverse"] = []
    for index, stream in enumerate(raw_streams):
        if not isinstance(stream, dict):
            raise ValueError(f"end.streams[{index}] is not an object")
        sender = stream.get("sender")
        receiver = stream.get("receiver")
        if not isinstance(sender, dict) or not isinstance(receiver, dict):
            raise ValueError(
                f"end.streams[{index}] requires sender and receiver objects"
            )
        marker = sender.get("sender")
        if not isinstance(marker, bool):
            raise ValueError(
                f"end.streams[{index}].sender.sender must be boolean"
            )
        if not isinstance(receiver.get("sender"), bool):
            raise ValueError(
                f"end.streams[{index}].receiver.sender must be boolean"
            )
        if direction == "bidir":
            label = "forward" if marker else "reverse"
            if receiver.get("sender") is not marker:
                raise ValueError(
                    f"end.streams[{index}] sender/receiver direction mismatch"
                )
        else:
            label = "reverse" if direction == "reverse" else "forward"
            expected_marker = direction == "forward"
            if marker is not expected_marker or receiver.get("sender") is not marker:
                raise ValueError(
                    f"end.streams[{index}] direction marker mismatch for {direction}"
                )
        grouped[label].append(stream)

    for label, streams in grouped.items():
        if len(streams) != expected_streams:
            raise ValueError(
                f"{label} stream count={len(streams)}, want {expected_streams}"
            )
    return grouped


def validate_iperf(
    doc: dict[str, Any],
    *,
    direction: str,
    expected_streams: int,
    minimum_bytes: int,
    maximum_retransmits: int,
    minimum_fairness: float,
) -> list[dict[str, Any]]:
    if direction not in {"forward", "reverse", "bidir"}:
        raise ValueError(f"unsupported direction: {direction}")
    if expected_streams < 1:
        raise ValueError("expected_streams must be positive")
    if minimum_bytes < 1:
        raise ValueError("minimum_bytes must be positive")
    if maximum_retransmits < 0:
        raise ValueError("maximum_retransmits must be non-negative")
    if not 0.0 <= minimum_fairness <= 1.0:
        raise ValueError("minimum_fairness must be in [0, 1]")
    if doc.get("error"):
        raise ValueError(f"iperf3 error: {doc['error']}")

    start = doc.get("start")
    if not isinstance(start, dict):
        raise ValueError("start object is missing")
    test_start = start.get("test_start")
    if not isinstance(test_start, dict):
        raise ValueError("start.test_start object is missing")
    observed_streams = _integer(
        test_start.get("num_streams"), "start.test_start.num_streams"
    )
    if observed_streams != expected_streams:
        raise ValueError(
            f"iperf requested streams={observed_streams}, want {expected_streams}"
        )
    observed_reverse = _integer(
        test_start.get("reverse", 0), "start.test_start.reverse"
    )
    observed_bidir = _integer(
        test_start.get("bidir", 0), "start.test_start.bidir"
    )
    expected_reverse = 1 if direction == "reverse" else 0
    expected_bidir = 1 if direction == "bidir" else 0
    if observed_reverse != expected_reverse or observed_bidir != expected_bidir:
        raise ValueError(
            "iperf direction mismatch: "
            f"reverse={observed_reverse} bidir={observed_bidir}, "
            f"want reverse={expected_reverse} bidir={expected_bidir}"
        )

    end = doc.get("end")
    if not isinstance(end, dict):
        raise ValueError("end object is missing")
    grouped = _stream_directions(end, direction, expected_streams)
    results = []
    for label, streams in grouped.items():
        received = [
            _integer(
                stream["receiver"].get("bytes"),
                f"{label} receiver[{index}].bytes",
            )
            for index, stream in enumerate(streams)
        ]
        retransmits = [
            _integer(
                stream["sender"].get("retransmits"),
                f"{label} sender[{index}].retransmits",
            )
            for index, stream in enumerate(streams)
        ]
        below_minimum = [
            (index, value)
            for index, value in enumerate(received)
            if value < minimum_bytes
        ]
        if below_minimum:
            raise ValueError(
                f"{label} receiver streams below {minimum_bytes} bytes: "
                f"{below_minimum}"
            )
        retransmit_total = sum(retransmits)
        if retransmit_total > maximum_retransmits:
            raise ValueError(
                f"{label} retransmits={retransmit_total}, "
                f"maximum={maximum_retransmits}"
            )
        fairness = jain_fairness(received)
        if fairness < minimum_fairness:
            raise ValueError(
                f"{label} fairness={fairness:.6f}, "
                f"minimum={minimum_fairness:.6f}"
            )

        reverse_suffix = "_bidir_reverse" if label == "reverse" and direction == "bidir" else ""
        received_summary = end.get(f"sum_received{reverse_suffix}")
        sent_summary = end.get(f"sum_sent{reverse_suffix}")
        if not isinstance(received_summary, dict) or not isinstance(
            sent_summary, dict
        ):
            raise ValueError(f"{label} summary objects are missing")
        summary_bytes = _integer(
            received_summary.get("bytes"), f"{label} sum_received.bytes"
        )
        if summary_bytes != sum(received):
            raise ValueError(
                f"{label} receiver byte sum={sum(received)}, "
                f"summary={summary_bytes}"
            )
        summary_retransmits = _integer(
            sent_summary.get("retransmits"),
            f"{label} sum_sent.retransmits",
        )
        if summary_retransmits != retransmit_total:
            raise ValueError(
                f"{label} retransmit sum={retransmit_total}, "
                f"summary={summary_retransmits}"
            )
        sent_bytes = [
            _integer(
                stream["sender"].get("bytes"),
                f"{label} sender[{index}].bytes",
            )
            for index, stream in enumerate(streams)
        ]
        summary_sent_bytes = _integer(
            sent_summary.get("bytes"), f"{label} sum_sent.bytes"
        )
        if summary_sent_bytes != sum(sent_bytes):
            raise ValueError(
                f"{label} sender byte sum={sum(sent_bytes)}, "
                f"summary={summary_sent_bytes}"
            )
        seconds = _number(
            received_summary.get("seconds"), f"{label} sum_received.seconds"
        )
        if seconds <= 0:
            raise ValueError(f"{label} receive duration must be positive")
        results.append(
            {
                "direction": label,
                "streams": expected_streams,
                "received_bytes": summary_bytes,
                "throughput_mbps": summary_bytes * 8 / seconds / 1_000_000,
                "retransmits": retransmit_total,
                "fairness": fairness,
                "per_stream_received_bytes": received,
            }
        )
    return results


def aggregate_iperf_results(
    samples: list[list[dict[str, Any]]],
    *,
    requested_direction: str,
) -> list[dict[str, Any]]:
    if not samples:
        raise ValueError("aggregate requires at least one sample")
    expected_directions = {
        "forward": ("forward",),
        "reverse": ("reverse",),
        "bidir": ("forward", "reverse"),
    }.get(requested_direction)
    if expected_directions is None:
        raise ValueError(f"unsupported direction: {requested_direction}")
    for index, sample in enumerate(samples):
        observed = tuple(item.get("direction") for item in sample)
        if observed != expected_directions:
            raise ValueError(
                f"sample {index} directions={observed!r}, "
                f"want {expected_directions!r}"
            )

    def summarize(label: str, values: list[dict[str, Any]]) -> dict[str, Any]:
        throughputs = [float(value["throughput_mbps"]) for value in values]
        fairness = [float(value["fairness"]) for value in values]
        retransmits = [int(value["retransmits"]) for value in values]
        return {
            "requested_direction": requested_direction,
            "direction": label,
            "samples": len(values),
            "throughput_mean_mbps": statistics.fmean(throughputs),
            "throughput_pstdev_mbps": statistics.pstdev(throughputs),
            "throughput_min_mbps": min(throughputs),
            "throughput_max_mbps": max(throughputs),
            "retransmits_total": sum(retransmits),
            "fairness_mean": statistics.fmean(fairness),
            "fairness_min": min(fairness),
        }

    result = []
    for direction_index, direction in enumerate(expected_directions):
        result.append(
            summarize(direction, [sample[direction_index] for sample in samples])
        )
    if requested_direction == "bidir":
        totals = []
        for sample in samples:
            totals.append(
                {
                    "throughput_mbps": sum(
                        float(item["throughput_mbps"]) for item in sample
                    ),
                    "retransmits": sum(int(item["retransmits"]) for item in sample),
                    "fairness": min(float(item["fairness"]) for item in sample),
                }
            )
        result.append(summarize("aggregate", totals))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("json_paths", nargs="+", type=Path)
    parser.add_argument(
        "--direction",
        choices=("forward", "reverse", "bidir"),
        required=True,
    )
    parser.add_argument("--streams", type=int, required=True)
    parser.add_argument("--minimum-bytes", type=int, required=True)
    parser.add_argument("--maximum-retransmits", type=int, default=0)
    parser.add_argument("--minimum-fairness", type=float, default=0.0)
    parser.add_argument("--aggregate", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    try:
        if len(args.json_paths) != 1 and not args.aggregate:
            raise ValueError("multiple JSON inputs require --aggregate")
        samples = []
        for json_path in args.json_paths:
            with json_path.open("r", encoding="utf-8") as handle:
                document = json.load(handle)
            if not isinstance(document, dict):
                raise ValueError(
                    f"{json_path}: top-level iperf3 JSON must be an object"
                )
            samples.append(
                validate_iperf(
                    document,
                    direction=args.direction,
                    expected_streams=args.streams,
                    minimum_bytes=args.minimum_bytes,
                    maximum_retransmits=args.maximum_retransmits,
                    minimum_fairness=args.minimum_fairness,
                )
            )
        results = (
            aggregate_iperf_results(
                samples,
                requested_direction=args.direction,
            )
            if args.aggregate
            else samples[0]
        )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        parser.error(str(exc))

    if args.json:
        print(json.dumps(results, sort_keys=True))
    else:
        for result in results:
            if args.aggregate:
                print(
                    "tcp aggregate requested_direction={requested_direction} "
                    "direction={direction} samples={samples} "
                    "throughput_mean={throughput_mean_mbps:.2f}Mbps "
                    "throughput_pstdev={throughput_pstdev_mbps:.2f}Mbps "
                    "throughput_min={throughput_min_mbps:.2f}Mbps "
                    "throughput_max={throughput_max_mbps:.2f}Mbps "
                    "retransmits_total={retransmits_total} "
                    "fairness_mean={fairness_mean:.6f} "
                    "fairness_min={fairness_min:.6f}".format(**result)
                )
            else:
                print(
                    "tcp direction={direction} streams={streams} "
                    "received={received_bytes} throughput={throughput_mbps:.2f}Mbps "
                    "retransmits={retransmits} fairness={fairness:.6f}".format(
                        **result
                    )
                )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
