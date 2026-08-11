#!/usr/bin/env python3
"""Hermetic checks for the standalone public BPF smoke scripts."""

from __future__ import annotations

import importlib.util
import json
import os
import socket
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[1]


def load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {filename}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class PublicSmokeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.controller = load("public_controller", "controller.py")
        cls.root = load("public_root_endpoint", "root-endpoint.py")
        cls.traffic = load("public_traffic", "traffic.py")
        cls.report = load("public_report", "report.py")

    def test_canonical_resource_names_and_bounds(self) -> None:
        self.assertEqual(
            "/run/wg-mix-ebpf-public-smoke-0123456789ab-b82",
            str(self.root.canonical_run_root("0123456789ab", "b82")),
        )
        with self.assertRaises(SystemExit) as caught:
            self.root.canonical_run_root("../bad", "b82")
        self.assertEqual(64, caught.exception.code)

    def test_report_accepts_only_fresh_bidirectional_zero_error_growth(self) -> None:
        document = {
            "run_id": "0123456789ab",
            "commit": "1" * 40,
            "ping": {
                "transmitted": 200,
                "received": 199,
                "max_consecutive_loss": 1,
            },
            "samples": [
                {
                    role: {
                        "timestamp": 1000,
                        "latest_handshake": 995,
                        "wg_tx": 10,
                        "wg_rx": 20,
                        "rewrite_success": 30,
                        "error_total": 0,
                    }
                    for role in ("b82", "public")
                },
                {
                    role: {
                        "timestamp": 1100,
                        "latest_handshake": 1090,
                        "wg_tx": 110,
                        "wg_rx": 120,
                        "rewrite_success": 130,
                        "error_total": 0,
                    }
                    for role in ("b82", "public")
                },
            ],
        }
        summary = self.report.summarize(document)
        self.assertEqual("PASS", summary["result"])
        document["samples"][-1]["public"]["error_total"] = 1
        self.assertEqual("FAIL", self.report.summarize(document)["result"])

    def test_low_rate_tcp_and_udp_helpers_exchange_real_local_traffic(self) -> None:
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        result: list[int] = []
        server = threading.Thread(
            target=lambda: result.append(
                self.traffic.server("127.0.0.1", port, 2)
            ),
            daemon=True,
        )
        server.start()
        time.sleep(0.1)
        self.assertEqual(
            0, self.traffic.udp_client("127.0.0.1", port, 1, 32_000)
        )
        self.assertEqual(0, self.traffic.tcp_client("127.0.0.1", port, 65536))
        server.join(timeout=4)
        self.assertEqual([0], result)

    def test_controller_plan_is_offline_and_does_not_read_credentials(self) -> None:
        commit = subprocess.check_output(
            ["/usr/bin/git", "-C", str(REPOSITORY), "rev-parse", "HEAD"],
            text=True,
        ).strip()
        completed = subprocess.run(
            [
                "/usr/bin/python3",
                str(HERE / "controller.py"),
                "plan",
                "--run-id",
                "0123456789ab",
                "--commit",
                commit,
                "--binary",
                "/usr/bin/true",
                "--object",
                str(REPOSITORY / "Makefile"),
                "--seconds",
                "30",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            timeout=10,
        )
        self.assertEqual(0, completed.returncode, completed.stderr.decode())
        plan = json.loads(completed.stdout)
        self.assertEqual(0, plan["credential_read"])
        self.assertEqual(0, plan["network_operations"])

    def test_hosts_use_the_production_backends_for_their_kernel_generation(self) -> None:
        self.assertEqual("tcx", self.controller.ROLES["b82"]["attachment_backend"])
        self.assertEqual(
            "classic_tc", self.controller.ROLES["public"]["attachment_backend"]
        )
        self.assertNotIn("bpftool", " ".join(self.controller.REMOTE_TOOLS))
        for role, backend in (("b82", "tcx"), ("public", "classic_tc")):
            _, agent = self.root.config_bytes(Path("/run/wg-mix-ebpf-test"), role)
            self.assertIn(
                f"  attachment_backend: {backend}\n".encode(),
                agent,
            )

    def test_sources_exclude_broad_cleanup_and_unreviewed_network_changes(self) -> None:
        sources = "\n".join(
            (HERE / name).read_text(encoding="utf-8")
            for name in (
                "controller.py",
                "root-endpoint.py",
                "traffic.py",
                "transport.exp",
            )
        )
        for forbidden in (
            "rm -rf",
            "find -delete",
            "xargs rm",
            "rsync --delete",
            "nft ",
            "iptables",
            "ethtool -K",
            "ip route add",
            "ip route del",
            "tc qdisc",
            "WG_MIX_EXPERIMENTAL_FAKETCP",
        ):
            self.assertNotIn(forbidden, sources)
        endpoint = (HERE / "root-endpoint.py").read_text(encoding="utf-8")
        self.assertIn('if verify_owned_link(root, args.run_id, args.role):', endpoint)
        self.assertIn('command([TOOLS["ip"], "link", "delete", "dev"', endpoint)
        self.assertIn('os.unlink(root / "root-endpoint.py")', endpoint)


if __name__ == "__main__":
    unittest.main()
