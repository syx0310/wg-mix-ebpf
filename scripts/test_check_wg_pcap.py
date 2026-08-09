#!/usr/bin/env python3
"""Unit tests for the dependency-free pcap checker."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


CHECKER_PATH = Path(__file__).with_name("check-wg-pcap.py")
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("check_wg_pcap", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {CHECKER_PATH}")
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)


class WireGuardLengthTest(unittest.TestCase):
    def test_handshake_lengths_remain_exact(self) -> None:
        cases = {
            "initiation": 148,
            "response": 92,
            "cookie": 64,
        }
        for kind, exact_length in cases.items():
            with self.subTest(kind=kind, payload_len=exact_length):
                self.assertTrue(
                    CHECKER.valid_wireguard_length(kind, exact_length)
                )
            for invalid_length in (exact_length - 1, exact_length + 1):
                with self.subTest(kind=kind, payload_len=invalid_length):
                    self.assertFalse(
                        CHECKER.valid_wireguard_length(kind, invalid_length)
                    )

    def test_transport_accepts_every_length_at_or_above_minimum(self) -> None:
        for payload_len in (32, 33, 1451, 1452):
            with self.subTest(payload_len=payload_len):
                self.assertTrue(
                    CHECKER.valid_wireguard_length("transport", payload_len)
                )

    def test_transport_rejects_length_below_minimum(self) -> None:
        self.assertFalse(CHECKER.valid_wireguard_length("transport", 31))

    def test_unknown_kind_is_invalid(self) -> None:
        self.assertFalse(CHECKER.valid_wireguard_length("unknown", 148))


if __name__ == "__main__":
    unittest.main()
