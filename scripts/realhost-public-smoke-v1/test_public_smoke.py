#!/usr/bin/env python3
"""Hermetic checks for the standalone public BPF smoke scripts."""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import socket
import subprocess
import sys
import tempfile
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
        self.assertEqual(commit, plan["contract"]["source"]["head"])
        self.assertEqual(
            plan["contract_sha256"],
            self.controller.contract_sha256(plan["contract"]),
        )
        self.assertEqual(
            {"binary", "controller", "endpoint", "object", "report", "traffic", "transport"},
            set(plan["contract"]["artifacts"]),
        )
        self.assertEqual("run", plan["run_argv"][2])
        self.assertEqual("cleanup", plan["cleanup_argv"][2])
        self.assertEqual(plan["contract_sha256"], plan["run_argv"][-1])
        self.assertEqual(plan["contract_sha256"], plan["cleanup_argv"][-1])
        self.assertEqual(
            ["/private/tmp/wg-mix-public-smoke-evidence-<run-id>"],
            plan["contract"]["local_write_set"],
        )
        self.assertEqual(
            {"b82", "public"}, set(plan["contract"]["intake_claims"])
        )
        self.assertRegex(
            plan["contract"]["ownership_token"], r"^[0-9a-f]{32}$"
        )
        self.assertIn("--ownership-token", plan["run_argv"])

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

    def test_prepare_claim_and_cleanup_retry_contracts_are_structural(self) -> None:
        controller = (HERE / "controller.py").read_text(encoding="utf-8")
        endpoint = (HERE / "root-endpoint.py").read_text(encoding="utf-8")
        self.assertLess(
            endpoint.index("write_owner_new(root,"),
            endpoint.index('copy_new(source, root / name'),
        )
        self.assertIn('"--no-target-directory"', controller)
        self.assertIn('"/usr/bin/mkdir",\n        "--mode=700"', controller)
        self.assertIn("allow_existing=True", controller)
        self.assertIn('"abort-unclaimed"', endpoint)
        self.assertIn("remote_directory_entries", controller)
        self.assertIn("contract-drift", controller)
        partial_restore = endpoint.index("if partial:", endpoint.index("def restore("))
        pin_check = endpoint.index(
            'pin_path = Path(f"/sys/fs/bpf/{root.name}")', partial_restore
        )
        self.assertLess(partial_restore, pin_check)
        self.assertNotIn("subprocess.Popen", endpoint)
        self.assertNotIn("server.pid.json", endpoint)
        self.assertNotIn("capture.pid.json", endpoint)
        self.assertIn('"alias",\n            intent["alias"],\n            "type"', endpoint)
        self.assertNotIn(
            '"link", "set", "dev", wg_name, "alias"', endpoint
        )
        self.assertIn("write_owner_new", endpoint)
        self.assertIn('"owner.pending.json"', endpoint)
        self.assertIn("acquire_service_lock(root, exclusive=True)", endpoint)
        self.assertIn("verify_intake_claim(remote, args, artifacts)", controller)
        self.assertIn('"claim_sha256": claim_sha256', endpoint)
        claimed_root = controller.index('if "owner.json" in entries:')
        self.assertLess(
            controller.index(
                "verify_root_claim(remote, args, artifacts)", claimed_root
            ),
            controller.index("return True", claimed_root),
        )
        self.assertIn(
            'if not partial and (\n        Path(f"/sys/class/net/{ROLE[args.role][\'wg\']}"',
            endpoint,
        )
        run_start = controller.index("def run_test(")
        local_reserve = controller.index(
            "local_evidence = create_local_evidence(args.run_id)", run_start
        )
        first_stage = controller.index("stage_one(", local_reserve)
        self.assertLess(local_reserve, first_stage)
        cleanup_start = controller.index("def cleanup(")
        first_restore = controller.index('"restore",', cleanup_start)
        cleanup_evidence = controller.index(
            "local_evidence = create_local_evidence(args.run_id, allow_existing=True)",
            cleanup_start,
        )
        self.assertLess(first_restore, cleanup_evidence)

    def test_local_evidence_export_resumes_partial_and_linked_publish(self) -> None:
        payload = b"bounded-evidence-payload\n"
        document = {
            "schema": "wg-mix-public-evidence-export-v1",
            "run_id": "0123456789ab",
            "role": "b82",
            "files": {"sample.txt": base64.b64encode(payload).decode("ascii")},
        }
        with tempfile.TemporaryDirectory() as temporary:
            local_root = Path(temporary)
            role_root = local_root / "b82"
            role_root.mkdir(mode=0o700)
            pending = role_root / ".pending-sample.txt"
            pending.write_bytes(payload[:7])
            pending.chmod(0o600)

            self.controller.write_evidence_export(
                local_root, "0123456789ab", "b82", document
            )
            final = role_root / "sample.txt"
            self.assertEqual(payload, final.read_bytes())
            self.assertFalse(pending.exists())
            self.assertEqual(1, final.stat().st_nlink)
            complete = role_root / ".complete.json"
            self.assertTrue(complete.is_file())

            os.unlink(complete)
            pending.write_bytes(payload)
            pending.chmod(0o600)
            os.unlink(final)
            os.link(pending, final)
            self.assertEqual(2, final.stat().st_nlink)
            self.controller.write_evidence_export(
                local_root, "0123456789ab", "b82", document
            )
            self.assertEqual(payload, final.read_bytes())
            self.assertFalse(pending.exists())
            self.assertEqual(1, final.stat().st_nlink)

            complete_pending = role_root / ".pending-.complete.json"
            os.link(complete, complete_pending)
            self.assertEqual(2, complete.stat().st_nlink)
            self.controller.write_evidence_export(
                local_root, "0123456789ab", "b82", document
            )
            self.assertFalse(complete_pending.exists())
            self.assertEqual(1, complete.stat().st_nlink)

            reduced = dict(document)
            reduced["files"] = {}
            self.controller.write_evidence_export(
                local_root, "0123456789ab", "b82", reduced
            )
            self.assertEqual(payload, final.read_bytes())

    def test_remote_purge_keeps_recovery_markers_until_last(self) -> None:
        endpoint = (HERE / "root-endpoint.py").read_text(encoding="utf-8")
        intent = endpoint.index('intent = root / "intent.json"')
        artifacts = endpoint.index("for name in sorted(KNOWN_ROOT_FILES - terminal_files")
        restored = endpoint.index('restored = root / "restored.json"', artifacts)
        owner = endpoint.index('os.unlink(root / "owner.json")', restored)
        script = endpoint.index('os.unlink(root / "root-endpoint.py")', owner)
        root = endpoint.index("os.rmdir(root)", script)
        self.assertLess(intent, artifacts)
        self.assertLess(artifacts, restored)
        self.assertLess(restored, owner)
        self.assertLess(owner, script)
        self.assertLess(script, root)


if __name__ == "__main__":
    unittest.main()
