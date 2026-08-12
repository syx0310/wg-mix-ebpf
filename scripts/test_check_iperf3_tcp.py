#!/usr/bin/env python3
"""Unit tests for the iperf3 TCP result validator."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


CHECKER_PATH = Path(__file__).with_name("check-iperf3-tcp.py")
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("check_iperf3_tcp", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {CHECKER_PATH}")
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)


def stream(
    received: int,
    *,
    retransmits: int = 0,
    forward: bool = True,
) -> dict:
    return {
        "sender": {
            "bytes": received,
            "retransmits": retransmits,
            "sender": forward,
        },
        "receiver": {
            "bytes": received,
            "sender": forward,
        },
    }


def document(
    direction: str,
    primary: list[dict],
    reverse: list[dict] | None = None,
) -> dict:
    if direction == "reverse":
        for item in primary:
            item["sender"]["sender"] = False
            item["receiver"]["sender"] = False
    streams = list(primary)
    end = {
        "streams": streams,
        "sum_sent": {
            "bytes": sum(item["sender"]["bytes"] for item in primary),
            "retransmits": sum(
                item["sender"]["retransmits"] for item in primary
            ),
        },
        "sum_received": {
            "bytes": sum(item["receiver"]["bytes"] for item in primary),
            "seconds": 2.0,
        },
    }
    if reverse is not None:
        streams.extend(reverse)
        end["sum_sent_bidir_reverse"] = {
            "bytes": sum(item["sender"]["bytes"] for item in reverse),
            "retransmits": sum(
                item["sender"]["retransmits"] for item in reverse
            ),
        }
        end["sum_received_bidir_reverse"] = {
            "bytes": sum(item["receiver"]["bytes"] for item in reverse),
            "seconds": 2.0,
        }
    return {
        "start": {
            "test_start": {
                "num_streams": len(primary),
                "reverse": int(direction == "reverse"),
                "bidir": int(direction == "bidir"),
            }
        },
        "end": end,
    }


class Iperf3TCPValidatorTests(unittest.TestCase):
    def validate(self, doc: dict, direction: str, streams: int) -> list[dict]:
        return CHECKER.validate_iperf(
            doc,
            direction=direction,
            expected_streams=streams,
            minimum_bytes=100,
            maximum_retransmits=0,
            minimum_fairness=0.90,
        )

    def test_forward_and_reverse_validate_each_stream(self) -> None:
        for direction in ("forward", "reverse"):
            with self.subTest(direction=direction):
                result = self.validate(
                    document(
                        direction,
                        [stream(120), stream(125)],
                    ),
                    direction,
                    2,
                )
                self.assertEqual([direction], [item["direction"] for item in result])
                self.assertEqual(245, result[0]["received_bytes"])
                self.assertEqual(0, result[0]["retransmits"])
                self.assertGreater(result[0]["fairness"], 0.99)

    def test_bidir_separates_primary_and_reverse_streams(self) -> None:
        result = self.validate(
            document(
                "bidir",
                [stream(120), stream(130)],
                [
                    stream(140, forward=False),
                    stream(150, forward=False),
                ],
            ),
            "bidir",
            2,
        )
        self.assertEqual(
            ["forward", "reverse"],
            [item["direction"] for item in result],
        )
        self.assertEqual([250, 290], [item["received_bytes"] for item in result])

    def test_aggregate_reports_mean_spread_and_bidir_total(self) -> None:
        samples = [
            self.validate(
                document(
                    "bidir",
                    [stream(120)],
                    [stream(180, forward=False)],
                ),
                "bidir",
                1,
            ),
            self.validate(
                document(
                    "bidir",
                    [stream(160)],
                    [stream(200, forward=False)],
                ),
                "bidir",
                1,
            ),
        ]
        result = CHECKER.aggregate_iperf_results(
            samples,
            requested_direction="bidir",
        )
        self.assertEqual(
            ["forward", "reverse", "aggregate"],
            [item["direction"] for item in result],
        )
        self.assertEqual(2, result[2]["samples"])
        self.assertAlmostEqual(1.32e-3, result[2]["throughput_mean_mbps"])
        self.assertGreater(result[2]["throughput_pstdev_mbps"], 0)
        self.assertEqual(0, result[2]["retransmits_total"])

    def test_zero_or_short_stream_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "below 100 bytes"):
            self.validate(
                document("forward", [stream(0), stream(120)]),
                "forward",
                2,
            )

    def test_retransmit_is_rejected_even_when_summary_matches(self) -> None:
        with self.assertRaisesRegex(ValueError, "retransmits=1"):
            self.validate(
                document(
                    "forward",
                    [stream(120, retransmits=1), stream(120)],
                ),
                "forward",
                2,
            )

    def test_unfair_multi_stream_result_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "fairness="):
            self.validate(
                document("forward", [stream(100), stream(1000)]),
                "forward",
                2,
            )

    def test_summary_mismatch_and_direction_mismatch_are_rejected(self) -> None:
        bad_summary = document("forward", [stream(120)])
        bad_summary["end"]["sum_received"]["bytes"] = 121
        with self.assertRaisesRegex(ValueError, "summary=121"):
            self.validate(bad_summary, "forward", 1)

        bad_direction = document("forward", [stream(120)])
        bad_direction["start"]["test_start"]["bidir"] = 1
        with self.assertRaisesRegex(ValueError, "direction mismatch"):
            self.validate(bad_direction, "forward", 1)

        bad_sent_summary = document("forward", [stream(120)])
        bad_sent_summary["end"]["sum_sent"]["bytes"] = 121
        with self.assertRaisesRegex(ValueError, "sender byte sum=120"):
            self.validate(bad_sent_summary, "forward", 1)

    def test_non_bidir_stream_markers_must_match_direction(self) -> None:
        malformed = document("reverse", [stream(120)])
        malformed["end"]["streams"][0]["sender"]["sender"] = True
        with self.assertRaisesRegex(ValueError, "direction marker mismatch"):
            self.validate(malformed, "reverse", 1)

    def test_fractional_integer_and_boolean_number_are_rejected(self) -> None:
        fractional = document("forward", [stream(120)])
        fractional["end"]["streams"][0]["receiver"]["bytes"] = 120.5
        with self.assertRaisesRegex(ValueError, "must be an integer"):
            self.validate(fractional, "forward", 1)

        boolean_duration = document("forward", [stream(120)])
        boolean_duration["end"]["sum_received"]["seconds"] = True
        with self.assertRaisesRegex(ValueError, "must be numeric"):
            self.validate(boolean_duration, "forward", 1)

    def test_bidir_requires_consistent_stream_direction_markers(self) -> None:
        malformed = document(
            "bidir",
            [stream(120)],
            [stream(130, forward=False)],
        )
        malformed["end"]["streams"][1]["receiver"]["sender"] = True
        with self.assertRaisesRegex(ValueError, "direction mismatch"):
            self.validate(malformed, "bidir", 1)


if __name__ == "__main__":
    unittest.main()
