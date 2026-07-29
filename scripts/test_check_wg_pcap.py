#!/usr/bin/env python3
"""Unit tests for the dependency-free pcap checker."""

from __future__ import annotations

import hashlib
import importlib.util
import struct
import sys
import tempfile
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


class XORKeyInputTest(unittest.TestCase):
    def test_udp2raw_password_file_matches_password_derivation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            password_file = Path(temp_dir, "password")
            password_file.write_text("test-password\n", encoding="utf-8")
            actual = CHECKER.parse_xor_key(None, None, password_file)
        expected = hashlib.md5(b"test-passwordkey1").digest()
        self.assertEqual(actual, expected)

    def test_xor_key_sources_are_mutually_exclusive(self) -> None:
        with self.assertRaises(SystemExit):
            CHECKER.parse_xor_key("raw-key", "password", None)

    def test_empty_udp2raw_password_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            password_file = Path(temp_dir, "password")
            password_file.write_text("\n", encoding="utf-8")
            with self.assertRaises(SystemExit):
                CHECKER.parse_xor_key(None, None, password_file)


def ethernet_header(protocol: int) -> bytes:
    return b"\x00" * 12 + struct.pack("!H", protocol)


def truncated_ipv4_udp(type_word: int, payload_len: int = 1452) -> bytes:
    ip_total_len = 20 + 8 + payload_len
    ip_header = bytearray(20)
    ip_header[0] = 0x45
    ip_header[2:4] = struct.pack("!H", ip_total_len)
    ip_header[8] = 64
    ip_header[9] = CHECKER.IPPROTO_UDP
    ip_header[12:16] = b"\xc0\x00\x02\x01"
    ip_header[16:20] = b"\xc6\x33\x64\x01"
    udp_header = struct.pack(
        "!HHHH",
        31001,
        31002,
        8 + payload_len,
        0,
    )
    packet = (
        ethernet_header(CHECKER.ETH_P_IP)
        + bytes(ip_header)
        + udp_header
        + type_word.to_bytes(4, "little")
        + b"\x00" * (payload_len - 4)
    )
    return packet[:192]


def truncated_ipv6_udp(type_word: int, payload_len: int = 1452) -> bytes:
    ipv6_header = bytearray(40)
    ipv6_header[0] = 0x60
    ipv6_header[4:6] = struct.pack("!H", 8 + payload_len)
    ipv6_header[6] = CHECKER.IPPROTO_UDP
    ipv6_header[7] = 64
    ipv6_header[8:24] = bytes.fromhex("20010db8000000000000000000000001")
    ipv6_header[24:40] = bytes.fromhex("20010db8000000000000000000000002")
    udp_header = struct.pack(
        "!HHHH",
        31001,
        31002,
        8 + payload_len,
        0x1234,
    )
    packet = (
        ethernet_header(CHECKER.ETH_P_IPV6)
        + bytes(ipv6_header)
        + udp_header
        + type_word.to_bytes(4, "little")
        + b"\x00" * (payload_len - 4)
    )
    return packet[:192]


class TruncatedUDPPacketTest(unittest.TestCase):
    def test_large_truncated_mixed_packet_uses_declared_payload_length(
        self,
    ) -> None:
        record = CHECKER.parse_udp_record(
            Path("truncated-ipv4.pcap"),
            1,
            CHECKER.DLT_EN10MB,
            truncated_ipv4_udp(0x13DFF06B),
        )
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual("mixed", record.word_class)
        self.assertEqual("transport", record.kind)
        self.assertEqual(1452, record.payload_len)
        self.assertLess(record.captured_payload_len, record.payload_len)
        self.assertTrue(record.capture_truncated)
        self.assertTrue(record.length_valid)
        self.assertEqual("unverified", record.udp_checksum)

    def test_large_truncated_standard_packet_remains_a_leak(self) -> None:
        record = CHECKER.parse_udp_record(
            Path("truncated-ipv6.pcap"),
            1,
            CHECKER.DLT_EN10MB,
            truncated_ipv6_udp(0x00000004),
        )
        self.assertIsNotNone(record)
        assert record is not None
        summary = CHECKER.summarize([record], 12)
        self.assertEqual(1, summary["standard_type_words"])
        self.assertEqual(1, summary["truncated_packets"])
        self.assertEqual(1, summary["checksums"]["udp_unverified"])
        self.assertEqual(1452, record.payload_len)
        self.assertTrue(record.length_valid)


if __name__ == "__main__":
    unittest.main()
