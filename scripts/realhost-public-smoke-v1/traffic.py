#!/usr/bin/env python3
"""Small bounded TCP/UDP traffic endpoint for the public BPF smoke test."""

from __future__ import annotations

import argparse
import json
import selectors
import socket
import sys
import time
from dataclasses import dataclass
from typing import NoReturn


MAX_SECONDS = 1800
MAX_TCP_BYTES = 8 * 1024 * 1024
MAX_UDP_BPS = 1_000_000
PAYLOAD_SIZE = 768


def die(message: str) -> NoReturn:
    raise SystemExit(f"public-traffic: {message}")


def positive_int(raw: str, label: str, maximum: int) -> int:
    if not raw.isascii() or not raw.isdecimal():
        die(f"{label} must be a positive decimal integer")
    value = int(raw)
    if value < 1 or value > maximum:
        die(f"{label} must be in [1,{maximum}]")
    return value


@dataclass
class Counts:
    udp_packets: int = 0
    udp_bytes: int = 0
    tcp_connections: int = 0
    tcp_bytes: int = 0


def server(address: str, port: int, seconds: int) -> int:
    selector = selectors.DefaultSelector()
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    for sock in (udp, tcp):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setblocking(False)
    udp.bind((address, port))
    tcp.bind((address, port))
    tcp.listen(4)
    selector.register(udp, selectors.EVENT_READ, "udp")
    selector.register(tcp, selectors.EVENT_READ, "listener")
    counts = Counts()
    deadline = time.monotonic() + seconds
    clients: set[socket.socket] = set()
    try:
        while time.monotonic() < deadline:
            remaining = max(0.0, deadline - time.monotonic())
            for key, _ in selector.select(min(1.0, remaining)):
                if key.data == "udp":
                    data, _ = udp.recvfrom(PAYLOAD_SIZE + 64)
                    counts.udp_packets += 1
                    counts.udp_bytes += len(data)
                elif key.data == "listener":
                    client, _ = tcp.accept()
                    client.setblocking(False)
                    clients.add(client)
                    selector.register(client, selectors.EVENT_READ, "client")
                    counts.tcp_connections += 1
                else:
                    client = key.fileobj
                    data = client.recv(64 * 1024)
                    if data:
                        counts.tcp_bytes += len(data)
                    else:
                        selector.unregister(client)
                        clients.discard(client)
                        client.close()
    finally:
        for client in clients:
            client.close()
        selector.close()
        udp.close()
        tcp.close()
    print(json.dumps({"mode": "server", **counts.__dict__}, sort_keys=True))
    return 0


def udp_client(address: str, port: int, seconds: int, bits_per_second: int) -> int:
    prefix = b"wg-mix-public-smoke-v1\0"
    payload = prefix + bytes(PAYLOAD_SIZE - len(prefix))
    packets_per_second = max(1.0, bits_per_second / (8 * len(payload)))
    interval = 1.0 / packets_per_second
    deadline = time.monotonic() + seconds
    next_send = time.monotonic()
    packets = 0
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((address, port))
        while time.monotonic() < deadline:
            sock.send(payload)
            packets += 1
            next_send += interval
            delay = next_send - time.monotonic()
            if delay > 0:
                time.sleep(delay)
    finally:
        sock.close()
    print(
        json.dumps(
            {
                "mode": "udp-client",
                "packets": packets,
                "bytes": packets * len(payload),
                "bits_per_second": bits_per_second,
            },
            sort_keys=True,
        )
    )
    return 0


def tcp_client(address: str, port: int, byte_count: int) -> int:
    payload = bytes(64 * 1024)
    sent = 0
    started = time.monotonic()
    with socket.create_connection((address, port), timeout=10) as sock:
        sock.settimeout(10)
        while sent < byte_count:
            chunk = payload[: min(len(payload), byte_count - sent)]
            sock.sendall(chunk)
            sent += len(chunk)
        sock.shutdown(socket.SHUT_WR)
    elapsed = time.monotonic() - started
    print(
        json.dumps(
            {"mode": "tcp-client", "bytes": sent, "seconds": elapsed},
            sort_keys=True,
        )
    )
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="mode", required=True)
    serve = sub.add_parser("server")
    serve.add_argument("--address", required=True)
    serve.add_argument("--port", required=True)
    serve.add_argument("--seconds", required=True)
    udp = sub.add_parser("udp-client")
    udp.add_argument("--address", required=True)
    udp.add_argument("--port", required=True)
    udp.add_argument("--seconds", required=True)
    udp.add_argument("--bits-per-second", required=True)
    tcp = sub.add_parser("tcp-client")
    tcp.add_argument("--address", required=True)
    tcp.add_argument("--port", required=True)
    tcp.add_argument("--bytes", required=True)
    args = parser.parse_args(argv)
    try:
        socket.inet_aton(args.address)
    except OSError:
        die("address must be canonical IPv4")
    args.port = positive_int(args.port, "port", 65535)
    if args.port < 1024:
        die("port must be at least 1024")
    if args.mode in {"server", "udp-client"}:
        args.seconds = positive_int(args.seconds, "seconds", MAX_SECONDS)
    if args.mode == "udp-client":
        args.bits_per_second = positive_int(
            args.bits_per_second, "bits-per-second", MAX_UDP_BPS
        )
    if args.mode == "tcp-client":
        args.bytes = positive_int(args.bytes, "bytes", MAX_TCP_BYTES)
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.mode == "server":
        return server(args.address, args.port, args.seconds)
    if args.mode == "udp-client":
        return udp_client(args.address, args.port, args.seconds, args.bits_per_second)
    return tcp_client(args.address, args.port, args.bytes)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
