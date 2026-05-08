#!/usr/bin/env python3
"""Validate WireGuard type_word transforms in pcap files.

The checker is intentionally dependency-free so it can run on small test hosts
and CI runners without scapy/tshark. It understands Ethernet, Linux cooked, and
raw IPv4/IPv6 pcaps well enough for the project smoke tests.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


STANDARD_WORDS = {
    0x00000001: "initiation",
    0x00000002: "response",
    0x00000003: "cookie",
    0x00000004: "transport",
}

MIXED_WORDS = {
    0xF658C2E6: "initiation",
    0x0686B1D0: "response",
    0x075AE5E0: "cookie",
    0x13DFF06B: "transport",
}

KINDS = ("initiation", "response", "cookie", "transport")

ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
ETH_P_8021Q = 0x8100
ETH_P_8021AD = 0x88A8
IPPROTO_UDP = 17

DLT_EN10MB = 1
DLT_RAW = 101
DLT_LINUX_SLL = 113
DLT_LINUX_SLL2 = 276


@dataclass
class UdpRecord:
    file: str
    packet_index: int
    family: int
    src: str
    dst: str
    sport: int
    dport: int
    payload_len: int
    type_word: int | None
    word_class: str
    kind: str | None
    length_valid: bool | None
    ipv4_header_checksum: str
    udp_checksum: str


def ones_complement_checksum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
        total = (total & 0xFFFF) + (total >> 16)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def valid_wireguard_length(kind: str, payload_len: int) -> bool:
    if kind == "initiation":
        return payload_len == 148
    if kind == "response":
        return payload_len == 92
    if kind == "cookie":
        return payload_len == 64
    if kind == "transport":
        return payload_len >= 32 and (payload_len - 32) % 16 == 0
    return False


def parse_pcap(path: Path) -> Iterable[tuple[int, int, bytes]]:
    data = path.read_bytes()
    if len(data) < 24:
        raise ValueError(f"{path}: file too short for pcap header")

    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise ValueError(f"{path}: unsupported pcap magic {magic.hex()}")

    linktype = struct.unpack(endian + "I", data[20:24])[0] & 0xFFFF
    offset = 24
    packet_index = 0
    while offset + 16 <= len(data):
        _ts_sec, _ts_frac, incl_len, _orig_len = struct.unpack(
            endian + "IIII", data[offset : offset + 16]
        )
        offset += 16
        if offset + incl_len > len(data):
            break
        packet_index += 1
        yield packet_index, linktype, data[offset : offset + incl_len]
        offset += incl_len


def parse_link(pkt: bytes, linktype: int) -> tuple[int, int] | None:
    if linktype == DLT_EN10MB:
        if len(pkt) < 14:
            return None
        proto = int.from_bytes(pkt[12:14], "big")
        offset = 14
        for _ in range(2):
            if proto not in (ETH_P_8021Q, ETH_P_8021AD):
                break
            if len(pkt) < offset + 4:
                return None
            proto = int.from_bytes(pkt[offset + 2 : offset + 4], "big")
            offset += 4
        return proto, offset

    if linktype == DLT_RAW:
        if not pkt:
            return None
        version = pkt[0] >> 4
        if version == 4:
            return ETH_P_IP, 0
        if version == 6:
            return ETH_P_IPV6, 0
        return None

    if linktype == DLT_LINUX_SLL:
        if len(pkt) < 16:
            return None
        return int.from_bytes(pkt[14:16], "big"), 16

    if linktype == DLT_LINUX_SLL2:
        if len(pkt) < 20:
            return None
        return int.from_bytes(pkt[0:2], "big"), 20

    raise ValueError(f"unsupported pcap linktype {linktype}")


def classify_type_word(word: int | None) -> tuple[str, str | None]:
    if word is None:
        return "none", None
    if word in STANDARD_WORDS:
        return "standard", STANDARD_WORDS[word]
    if word in MIXED_WORDS:
        return "mixed", MIXED_WORDS[word]
    return "unknown", None


def parse_udp_record(path: Path, packet_index: int, linktype: int, pkt: bytes) -> UdpRecord | None:
    link = parse_link(pkt, linktype)
    if link is None:
        return None
    proto, ip_offset = link

    if proto == ETH_P_IP:
        if len(pkt) < ip_offset + 20:
            return None
        first = pkt[ip_offset]
        if first >> 4 != 4:
            return None
        ihl = (first & 0x0F) * 4
        if ihl < 20 or len(pkt) < ip_offset + ihl:
            return None
        ip_header = pkt[ip_offset : ip_offset + ihl]
        total_len = int.from_bytes(pkt[ip_offset + 2 : ip_offset + 4], "big")
        if total_len < ihl or len(pkt) < ip_offset + total_len:
            return None
        if pkt[ip_offset + 9] != IPPROTO_UDP:
            return None
        frag = int.from_bytes(pkt[ip_offset + 6 : ip_offset + 8], "big")
        if frag & 0x1FFF:
            return None
        udp_offset = ip_offset + ihl
        udp_limit = ip_offset + total_len
        if udp_limit < udp_offset + 8:
            return None
        family = 4
        src_raw = pkt[ip_offset + 12 : ip_offset + 16]
        dst_raw = pkt[ip_offset + 16 : ip_offset + 20]
        src = str(ipaddress.IPv4Address(src_raw))
        dst = str(ipaddress.IPv4Address(dst_raw))
        ipv4_header_checksum = "valid" if ones_complement_checksum(ip_header) == 0 else "invalid"
        pseudo = src_raw + dst_raw + bytes([0, IPPROTO_UDP])

    elif proto == ETH_P_IPV6:
        if len(pkt) < ip_offset + 40:
            return None
        first = pkt[ip_offset]
        if first >> 4 != 6:
            return None
        payload_len = int.from_bytes(pkt[ip_offset + 4 : ip_offset + 6], "big")
        nexthdr = pkt[ip_offset + 6]
        if nexthdr != IPPROTO_UDP:
            return None
        udp_offset = ip_offset + 40
        udp_limit = udp_offset + payload_len
        if udp_limit < udp_offset + 8 or len(pkt) < udp_limit:
            return None
        family = 6
        src_raw = pkt[ip_offset + 8 : ip_offset + 24]
        dst_raw = pkt[ip_offset + 24 : ip_offset + 40]
        src = str(ipaddress.IPv6Address(src_raw))
        dst = str(ipaddress.IPv6Address(dst_raw))
        ipv4_header_checksum = "n/a"
        pseudo = src_raw + dst_raw + payload_len.to_bytes(4, "big") + b"\x00\x00\x00" + bytes([IPPROTO_UDP])

    else:
        return None

    udp_len = int.from_bytes(pkt[udp_offset + 4 : udp_offset + 6], "big")
    if udp_len < 8 or udp_offset + udp_len > udp_limit or udp_offset + udp_len > len(pkt):
        return None
    udp_segment = pkt[udp_offset : udp_offset + udp_len]
    payload = udp_segment[8:]
    sport = int.from_bytes(udp_segment[0:2], "big")
    dport = int.from_bytes(udp_segment[2:4], "big")
    checksum_field = int.from_bytes(udp_segment[6:8], "big")

    if checksum_field == 0 and family == 4:
        udp_checksum = "zero"
    elif checksum_field == 0 and family == 6:
        udp_checksum = "invalid"
    else:
        if family == 4:
            pseudo_hdr = pseudo + udp_len.to_bytes(2, "big")
        else:
            pseudo_hdr = pseudo
        udp_checksum = "valid" if ones_complement_checksum(pseudo_hdr + udp_segment) == 0 else "invalid"

    word = int.from_bytes(payload[:4], "little") if len(payload) >= 4 else None
    word_class, kind = classify_type_word(word)
    length_valid = valid_wireguard_length(kind, len(payload)) if kind else None

    return UdpRecord(
        file=str(path),
        packet_index=packet_index,
        family=family,
        src=src,
        dst=dst,
        sport=sport,
        dport=dport,
        payload_len=len(payload),
        type_word=word,
        word_class=word_class,
        kind=kind,
        length_valid=length_valid,
        ipv4_header_checksum=ipv4_header_checksum,
        udp_checksum=udp_checksum,
    )


def parse_required_kinds(values: list[str] | None) -> set[str]:
    result: set[str] = set()
    if not values:
        return result
    for value in values:
        for item in value.split(","):
            item = item.strip()
            if not item:
                continue
            if item not in KINDS:
                raise SystemExit(f"unsupported kind in --require-mixed: {item}")
            result.add(item)
    return result


def summarize(records: list[UdpRecord], max_examples: int) -> dict:
    mixed_by_kind = {kind: 0 for kind in KINDS}
    standard_by_kind = {kind: 0 for kind in KINDS}
    unknown = 0
    invalid_lengths = 0
    checksum = {
        "ipv4_header_valid": 0,
        "ipv4_header_invalid": 0,
        "udp_valid": 0,
        "udp_invalid": 0,
        "udp_zero": 0,
    }
    examples = []

    for record in records:
        if record.word_class == "mixed" and record.kind:
            mixed_by_kind[record.kind] += 1
        elif record.word_class == "standard" and record.kind:
            standard_by_kind[record.kind] += 1
        elif record.word_class == "unknown":
            unknown += 1

        if record.length_valid is False:
            invalid_lengths += 1

        if record.ipv4_header_checksum == "valid":
            checksum["ipv4_header_valid"] += 1
        elif record.ipv4_header_checksum == "invalid":
            checksum["ipv4_header_invalid"] += 1

        if record.udp_checksum == "valid":
            checksum["udp_valid"] += 1
        elif record.udp_checksum == "invalid":
            checksum["udp_invalid"] += 1
        elif record.udp_checksum == "zero":
            checksum["udp_zero"] += 1

        if len(examples) < max_examples and record.word_class in {"mixed", "standard"}:
            examples.append(
                {
                    "file": record.file,
                    "packet_index": record.packet_index,
                    "family": record.family,
                    "tuple": f"{record.src}:{record.sport}->{record.dst}:{record.dport}",
                    "payload_len": record.payload_len,
                    "type_word": f"0x{record.type_word:08x}" if record.type_word is not None else None,
                    "class": record.word_class,
                    "kind": record.kind,
                    "length_valid": record.length_valid,
                    "udp_checksum": record.udp_checksum,
                }
            )

    mixed_total = sum(mixed_by_kind.values())
    standard_total = sum(standard_by_kind.values())
    return {
        "udp_packets": len(records),
        "pcap_udp_payload_words": sum(1 for record in records if record.type_word is not None),
        "mixed_type_words": mixed_total,
        "standard_type_words": standard_total,
        "unknown_type_words": unknown,
        "mixed_by_kind": mixed_by_kind,
        "standard_by_kind": standard_by_kind,
        "invalid_wireguard_lengths": invalid_lengths,
        "checksums": checksum,
        "examples": examples,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcaps", nargs="+", type=Path)
    parser.add_argument("--src", action="append", help="Only include packets with this source IP")
    parser.add_argument("--dst", action="append", help="Only include packets with this destination IP")
    parser.add_argument("--sport", action="append", type=int, help="Only include packets with this UDP source port")
    parser.add_argument("--dport", action="append", type=int, help="Only include packets with this UDP destination port")
    parser.add_argument("--forbid-standard", action="store_true")
    parser.add_argument("--require-mixed", action="append", help="Comma-separated WG kinds to require")
    parser.add_argument("--require-valid-udp-checksum", action="store_true")
    parser.add_argument("--json", action="store_true", help="Print JSON only")
    parser.add_argument("--max-examples", type=int, default=12)
    args = parser.parse_args()

    records: list[UdpRecord] = []
    for path in args.pcaps:
        for packet_index, linktype, pkt in parse_pcap(path):
            record = parse_udp_record(path, packet_index, linktype, pkt)
            if record is not None:
                records.append(record)
    if args.src:
        allowed = set(args.src)
        records = [record for record in records if record.src in allowed]
    if args.dst:
        allowed = set(args.dst)
        records = [record for record in records if record.dst in allowed]
    if args.sport:
        allowed = set(args.sport)
        records = [record for record in records if record.sport in allowed]
    if args.dport:
        allowed = set(args.dport)
        records = [record for record in records if record.dport in allowed]

    summary = summarize(records, args.max_examples)
    required_mixed = parse_required_kinds(args.require_mixed)
    failures = []

    if args.forbid_standard and summary["standard_type_words"]:
        failures.append(f"standard WireGuard type_word leaked: {summary['standard_type_words']}")

    missing = sorted(kind for kind in required_mixed if summary["mixed_by_kind"][kind] == 0)
    if missing:
        failures.append("missing required mixed kinds: " + ",".join(missing))

    if summary["invalid_wireguard_lengths"]:
        failures.append(f"invalid WireGuard-like payload lengths: {summary['invalid_wireguard_lengths']}")

    if args.require_valid_udp_checksum and summary["checksums"]["udp_invalid"]:
        failures.append(f"invalid UDP checksums: {summary['checksums']['udp_invalid']}")

    result = {
        "files": [str(path) for path in args.pcaps],
        "summary": summary,
        "failures": failures,
    }

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"pcap_files={len(args.pcaps)}")
        print(
            "udp_packets={udp_packets} pcap_udp_payload_words={pcap_udp_payload_words} "
            "mixed_type_words={mixed_type_words} standard_type_words={standard_type_words} "
            "unknown_type_words={unknown_type_words}".format(**summary)
        )
        print(
            "mixed initiation={initiation} response={response} cookie={cookie} transport={transport}".format(
                **summary["mixed_by_kind"]
            )
        )
        print(
            "standard initiation={initiation} response={response} cookie={cookie} transport={transport}".format(
                **summary["standard_by_kind"]
            )
        )
        print(
            "udp_checksum_valid={udp_valid} udp_checksum_invalid={udp_invalid} udp_checksum_zero={udp_zero}".format(
                **summary["checksums"]
            )
        )
        print(
            "ipv4_header_checksum_valid={ipv4_header_valid} ipv4_header_checksum_invalid={ipv4_header_invalid}".format(
                **summary["checksums"]
            )
        )
        if summary["examples"]:
            print("examples:")
            for example in summary["examples"]:
                print(
                    "  {class} {kind} {type_word} len={payload_len} checksum={udp_checksum} {tuple} file={file}#{packet_index}".format(
                        **example
                    )
                )
        if failures:
            for failure in failures:
                print(f"failure: {failure}", file=sys.stderr)

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
