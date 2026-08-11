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
from types import SimpleNamespace
from unittest import mock


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
        sys.modules["controller"] = cls.controller
        cls.root = load("public_root_endpoint", "root-endpoint.py")
        cls.traffic = load("public_traffic", "traffic.py")
        cls.report = load("public_report", "report.py")
        cls.recovery = load("public_recovery", "recover-classic-journal.py")

    def test_client_failure_preserves_complete_stdout_and_stderr(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "evidence").mkdir()
            (root / "applied.json").write_text("{}\n", encoding="utf-8")
            lock_fd = os.open("/dev/null", os.O_RDONLY)

            def fail_client(argv, **kwargs):
                self.assertEqual(["/usr/bin/python3", "traffic.py"], argv)
                kwargs["stdout"].write(b"complete client stdout\n")
                kwargs["stderr"].write(b"complete client stderr: connection timed out\n")
                return SimpleNamespace(returncode=23)

            with mock.patch.object(
                self.root, "acquire_service_lock", return_value=lock_fd
            ), mock.patch.object(self.root.subprocess, "run", side_effect=fail_client):
                with self.assertRaises(SystemExit) as caught:
                    self.root.run_recorded_command(
                        root,
                        "udp-client",
                        ["/usr/bin/python3", "traffic.py"],
                        timeout=5,
                    )
            self.assertEqual(77, caught.exception.code)
            self.assertEqual(
                b"complete client stdout\n",
                (root / "evidence/udp-client.stdout").read_bytes(),
            )
            self.assertEqual(
                b"complete client stderr: connection timed out\n",
                (root / "evidence/udp-client.stderr").read_bytes(),
            )
            self.assertEqual(
                0o600,
                (root / "evidence/udp-client.stderr").stat().st_mode & 0o777,
            )
            self.assertTrue(self.root.KNOWN_EVIDENCE_RE.fullmatch("udp-client.stdout"))
            self.assertTrue(self.root.KNOWN_EVIDENCE_RE.fullmatch("tcp-client.stderr"))

    def test_tcx_recovery_binds_exact_live_link_identities(self) -> None:
        args = SimpleNamespace(
            role="b82",
            tcx_ingress_link_id=5,
            tcx_ingress_program_id=444,
            tcx_egress_link_id=4,
            tcx_egress_program_id=448,
        )

        class Remote:
            def __init__(self, links: list[dict[str, object]]) -> None:
                self.links = links

            def ssh(self, *argv: str) -> str:
                if argv == ("/usr/sbin/ip", "-j", "link", "show", "dev", "ens33"):
                    return json.dumps([{"ifindex": 2, "ifname": "ens33"}])
                self.assert_bpftool_argv(argv)
                return json.dumps(self.links)

            @staticmethod
            def assert_bpftool_argv(argv: tuple[str, ...]) -> None:
                if argv != (
                    "/usr/bin/sudo",
                    "-S",
                    "-p",
                    "PUBLIC_SUDO_PASSWORD:",
                    "/usr/sbin/bpftool",
                    "-j",
                    "link",
                    "show",
                ):
                    raise AssertionError(argv)

        exact = [
            {
                "id": 4,
                "type": "tcx",
                "prog_id": 448,
                "ifindex": 2,
                "attach_type": "tcx_egress",
            },
            {
                "id": 5,
                "type": "tcx",
                "prog_id": 444,
                "ifindex": 2,
                "attach_type": "tcx_ingress",
            },
        ]
        self.recovery.verify_tcx_links(Remote(exact), args, present=True)
        self.recovery.verify_tcx_links(Remote([]), args, present=False)
        self.assertEqual(
            {4}, self.recovery.matching_tcx_link_ids(Remote(exact[:1]), args)
        )
        with self.assertRaises(SystemExit) as caught:
            self.recovery.verify_tcx_links(Remote(exact[:1]), args, present=True)
        self.assertEqual(79, caught.exception.code)

        for field, value in (
            ("prog_id", 999),
            ("ifindex", 9),
            ("type", "xdp"),
            ("attach_type", "tcx_ingress"),
        ):
            wrong = [dict(item) for item in exact]
            wrong[0][field] = value
            with self.subTest(field=field):
                with self.assertRaises(SystemExit) as caught:
                    self.recovery.matching_tcx_link_ids(Remote(wrong), args)
                self.assertEqual(79, caught.exception.code)

        foreign = [{"id": 99, "type": "tcx", "prog_id": 1, "ifindex": 2}]
        self.assertEqual(
            set(), self.recovery.matching_tcx_link_ids(Remote(foreign), args)
        )

    def test_recovery_argv_preserves_role_and_tcx_identity(self) -> None:
        args = SimpleNamespace(
            recovery_id="0123456789ab",
            old_run_id="0123456789abcdef",
            old_commit="1" * 40,
            new_commit="2" * 40,
            old_binary_sha256="3" * 64,
            object_sha256="4" * 64,
            ownership_token="5" * 32,
            binary="/bin/echo",
            binary_sha256="6" * 64,
            operation="recover",
            role="b82",
            tcx_ingress_link_id=5,
            tcx_ingress_program_id=444,
            tcx_egress_link_id=4,
            tcx_egress_program_id=448,
        )
        digest = "7" * 64
        argv = self.recovery.execute_argv(
            args, digest, {"recovery": HERE / "recover-classic-journal.py"}
        )
        self.assertEqual("recover", argv[2])
        self.assertEqual("recover", argv[argv.index("--operation") + 1])
        self.assertEqual(1, argv.count(digest))
        self.assertNotIn(args.ownership_token, argv)
        self.assertEqual("<redacted>", argv[argv.index("--ownership-token") + 1])
        self.assertEqual("b82", argv[argv.index("--role") + 1])
        self.assertEqual("5", argv[argv.index("--tcx-ingress-link-id") + 1])
        self.assertEqual("444", argv[argv.index("--tcx-ingress-program-id") + 1])
        self.assertEqual("4", argv[argv.index("--tcx-egress-link-id") + 1])
        self.assertEqual("448", argv[argv.index("--tcx-egress-program-id") + 1])

    def test_recovery_role_rejects_unbound_tcx_identity(self) -> None:
        common = [
            "recover-classic-journal.py",
            "plan",
            "--operation",
            "recover",
            "--recovery-id",
            "0123456789ab",
            "--old-run-id",
            "0123456789abcdef",
            "--old-commit",
            "1" * 40,
            "--new-commit",
            "2" * 40,
            "--old-binary-sha256",
            "3" * 64,
            "--object-sha256",
            "4" * 64,
            "--ownership-token",
            "5" * 32,
            "--binary",
            "/bin/echo",
            "--binary-sha256",
            "6" * 64,
        ]
        with mock.patch.object(sys, "argv", common):
            args = self.recovery.parse_args()
        self.assertEqual("public", args.role)
        self.assertEqual(0, args.tcx_ingress_link_id)

        with mock.patch.object(sys, "argv", [*common, "--role", "b82"]):
            with self.assertRaises(SystemExit) as caught:
                self.recovery.parse_args()
        self.assertEqual(64, caught.exception.code)

        exact = [
            *common,
            "--role",
            "b82",
            "--tcx-ingress-link-id",
            "5",
            "--tcx-ingress-program-id",
            "444",
            "--tcx-egress-link-id",
            "4",
            "--tcx-egress-program-id",
            "448",
        ]
        with mock.patch.object(sys, "argv", exact):
            args = self.recovery.parse_args()
        self.assertEqual("b82", args.role)
        self.assertEqual(
            (5, 444, 4, 448),
            (
                args.tcx_ingress_link_id,
                args.tcx_ingress_program_id,
                args.tcx_egress_link_id,
                args.tcx_egress_program_id,
            ),
        )

    def test_tcx_recovery_retries_partial_and_fully_detached_journal(self) -> None:
        args = SimpleNamespace(
            contract_sha256="contract",
            role="b82",
            old_run_id="0123456789abcdef",
            new_commit="2" * 40,
            recovery_id="0123456789ab",
            tcx_ingress_link_id=5,
            tcx_ingress_program_id=444,
            tcx_egress_link_id=4,
            tcx_egress_program_id=448,
        )

        for preexisting in ({5}, set()):
            events: list[str] = []

            class Remote:
                def __init__(self, _transport: Path, role: str) -> None:
                    self.role = role

                def ssh(self, *argv: str) -> str:
                    self.assert_argv(argv)
                    events.append("detach")
                    return ""

                @staticmethod
                def assert_argv(argv: tuple[str, ...]) -> None:
                    if argv != ("detach",):
                        raise AssertionError(argv)

            def precheck(_remote: Remote, _args: SimpleNamespace) -> set[int]:
                events.append("precheck")
                return set(preexisting)

            def postcheck(_remote: Remote, _args: SimpleNamespace) -> None:
                events.append("postcheck")

            def remove(*_args: object) -> None:
                events.append("remove")

            with self.subTest(preexisting=preexisting), mock.patch.multiple(
                self.recovery,
                contract=mock.Mock(return_value={}),
                contract_sha256=mock.Mock(return_value="contract"),
                Remote=Remote,
                stage_recovery_binary=mock.Mock(return_value=("intake-bin", "root-bin")),
                named_entry=mock.Mock(return_value=False),
                attach_state_snapshot=mock.Mock(return_value=None),
                matching_tcx_link_ids=mock.Mock(side_effect=precheck),
                detach_argv=mock.Mock(return_value=["detach"]),
                verify_backend_removed=mock.Mock(side_effect=postcheck),
                remove_recovery_binary=mock.Mock(side_effect=remove),
            ), mock.patch("builtins.print"):
                self.recovery.execute_recovery(
                    args, {"transport": HERE / "transport.exp"}
                )
            self.assertEqual(["precheck", "detach", "postcheck", "remove"], events)

    def test_staged_cleanup_validates_both_claims_before_exact_removal(self) -> None:
        args = SimpleNamespace(
            contract_sha256="contract",
            role="b82",
            old_run_id="0123456789abcdef",
            old_commit="1" * 40,
            new_commit="2" * 40,
            ownership_token="5" * 32,
            recovery_id="0123456789ab",
        )
        events: list[str] = []

        def intake(*_args: object) -> None:
            events.append("intake-claim")

        def root(*_args: object) -> None:
            events.append("root-claim")

        def remove(*_args: object) -> None:
            events.append("remove")

        with mock.patch.multiple(
            self.recovery,
            contract=mock.Mock(return_value={}),
            contract_sha256=mock.Mock(return_value="contract"),
            Remote=mock.Mock(return_value=object()),
            old_artifacts=mock.Mock(return_value={}),
            verify_intake_claim=mock.Mock(side_effect=intake),
            verify_root_claim=mock.Mock(side_effect=root),
            remove_recovery_binary=mock.Mock(side_effect=remove),
        ), mock.patch("builtins.print"):
            self.recovery.execute_cleanup_staged(
                args, {"transport": HERE / "transport.exp"}
            )
        self.assertEqual(["intake-claim", "root-claim", "remove"], events)

    def test_recovery_binary_removal_preflights_and_retries_each_copy(self) -> None:
        args = SimpleNamespace(
            binary="/bin/echo",
            binary_sha256="6" * 64,
            old_run_id="0123456789abcdef",
            recovery_id="0123456789ab",
            role="b82",
        )
        intake, root, intake_binary, root_binary = self.recovery.recovery_names(args)

        class Remote:
            def __init__(self, present: set[str], interrupt_root: bool = False) -> None:
                self.present = present
                self.interrupt_root = interrupt_root
                self.events: list[str] = []

            def ssh(self, *argv: str) -> str:
                path = argv[-1]
                self.events.append(f"unlink:{path}")
                self.present.remove(path)
                if path == root_binary and self.interrupt_root:
                    self.interrupt_root = False
                    raise ConnectionError("simulated post-unlink disconnect")
                return ""

        def run_case(initial: set[str], interrupt_root: bool = False) -> list[str]:
            remote = Remote(set(initial), interrupt_root)

            def present(
                _remote: object, parent: str, name: str, *, privileged: bool
            ) -> bool:
                del privileged
                return f"{parent}/{name}" in remote.present

            def exact(
                _remote: object,
                path: str,
                _digest: str,
                _size: int,
                *,
                root_owned: bool,
                expected_owner: tuple[str, str] | None = None,
            ) -> None:
                if path not in remote.present:
                    raise AssertionError(f"preflight missing {path}")
                if root_owned:
                    self.assertIsNone(expected_owner)
                else:
                    self.assertEqual(("1000", "1000"), expected_owner)
                remote.events.append(f"preflight:{path}")

            patches = mock.patch.multiple(
                self.recovery,
                named_entry=mock.Mock(side_effect=present),
                exact_file=mock.Mock(side_effect=exact),
                intake_owner=mock.Mock(return_value=("1000", "1000")),
            )
            with patches:
                if interrupt_root:
                    with self.assertRaises(ConnectionError):
                        self.recovery.remove_recovery_binary(
                            remote, args, intake_binary, root_binary
                        )
                self.recovery.remove_recovery_binary(
                    remote, args, intake_binary, root_binary
                )
                self.recovery.remove_recovery_binary(
                    remote, args, intake_binary, root_binary
                )
            self.assertEqual(set(), remote.present)
            return remote.events

        both_events = run_case({root_binary, intake_binary}, interrupt_root=True)
        self.assertLess(
            both_events.index(f"preflight:{intake_binary}"),
            both_events.index(f"unlink:{root_binary}"),
        )
        self.assertIn(f"unlink:{intake_binary}", both_events)
        self.assertEqual([f"preflight:{root_binary}", f"unlink:{root_binary}"], run_case({root_binary}))
        self.assertEqual([f"preflight:{intake_binary}", f"unlink:{intake_binary}"], run_case({intake_binary}))
        self.assertEqual([], run_case(set()))

    def test_intake_recovery_binary_owner_must_match_claimed_directory(self) -> None:
        class Remote:
            def ssh(self, *argv: str) -> str:
                if argv[-3:-1] == ("-c", "%u:%g:%a:%h:%s:%F"):
                    return "1001:1001:700:1:5:regular file"
                raise AssertionError(argv)

        with self.assertRaises(SystemExit) as caught:
            self.recovery.exact_file(
                Remote(),
                "/tmp/intake/recovery",
                "6" * 64,
                5,
                root_owned=False,
                expected_owner=("1000", "1000"),
            )
        self.assertEqual(79, caught.exception.code)

    def test_canonical_resource_names_and_bounds(self) -> None:
        self.assertEqual(
            "/var/tmp/wg-mix-ebpf-public-smoke-0123456789ab-b82",
            str(self.root.canonical_run_root("0123456789ab", "b82")),
        )
        with self.assertRaises(SystemExit) as caught:
            self.root.canonical_run_root("../bad", "b82")
        self.assertEqual(64, caught.exception.code)
        self.assertEqual("wmbaaaaaaaaaaaa", self.root.staging_wg_name("a" * 64, "b82"))
        self.assertEqual(
            "wmpaaaaaaaaaaaa", self.controller.staging_wg_name("a" * 64, "public")
        )
        self.assertEqual(15, len(self.root.staging_wg_name("a" * 64, "public")))

    def test_command_error_class_is_bounded_and_redacted(self) -> None:
        self.assertEqual("empty-stderr", self.root.command_error_class(b""))
        self.assertEqual(
            "key-format",
            self.root.command_error_class(
                b"Key is not the correct length or format: `/secret/private.key'\n"
            ),
        )
        self.assertEqual(
            "netlink-not-supported",
            self.root.command_error_class(
                b"Unable to modify interface: Operation not supported\n"
            ),
        )
        self.assertEqual(
            "other-stderr",
            self.root.command_error_class(b"untrusted path /secret/private.key\n"),
        )
        self.assertEqual(
            "pin-path-tcx-not-supported",
            self.root.agent_error_class(
                b"validate BPF pin path /secret: TCX operation not supported\n"
            ),
        )
        self.assertEqual(
            "keywords-path",
            self.root.agent_error_class(b"untrusted path /secret/private.key\n"),
        )
        self.assertEqual(
            "keywords-failed-load-program",
            self.root.agent_error_class(b"failed to load program: bad descriptor\n"),
        )

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
        self.assertIn("owned_link, preserve_fixed = classify_owned_link(", endpoint)
        self.assertIn('command([TOOLS["ip"], "link", "delete", "dev"', endpoint)
        self.assertIn('os.unlink(root / "root-endpoint.py")', endpoint)

    def test_prepare_claim_and_cleanup_retry_contracts_are_structural(self) -> None:
        controller = (HERE / "controller.py").read_text(encoding="utf-8")
        endpoint = (HERE / "root-endpoint.py").read_text(encoding="utf-8")
        transport = (HERE / "transport.exp").read_text(encoding="utf-8")
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
        self.assertIn('"-Z",\n        "root",', endpoint)
        self.assertIn(
            "output = run_recorded_command(root, mode, argv, timeout=args.seconds + 15)",
            endpoint,
        )
        add_staging = endpoint.index('"add",\n            "dev",\n            staging_name')
        alias_staging = endpoint.index('"dev",\n            staging_name,\n            "alias"')
        rename_fixed = endpoint.index(
            '[TOOLS["ip"], "link", "set", "dev", staging_name, "name", wg_name]'
        )
        configure_fixed = endpoint.index('TOOLS["wg"],\n        "set",\n        wg_name')
        self.assertLess(add_staging, alias_staging)
        self.assertLess(alias_staging, rename_fixed)
        self.assertLess(rename_fixed, configure_fixed)
        self.assertIn("write_owner_new", endpoint)
        self.assertIn('"owner.pending.json"', endpoint)
        self.assertIn("acquire_service_lock(root, exclusive=True)", endpoint)
        self.assertIn("verify_intake_claim(remote, args, artifacts)", controller)
        self.assertIn('"claim_sha256": claim_sha256', endpoint)
        self.assertIn(
            '"/usr/bin/python3",\n        f"{root}/root-endpoint.py"', controller
        )
        self.assertIn(
            "entries = remote_directory_entries(remote, root, privileged=True)",
            controller,
        )
        self.assertIn(
            'sudo = ("/usr/bin/sudo", "-S", "-p", "PUBLIC_SUDO_PASSWORD:")',
            controller,
        )
        self.assertIn("emit_safe_endpoint_stops $captured", transport)
        self.assertIn("emit_complete_child_diagnostics $captured $password $wait_result", transport)
        self.assertIn("PUBLIC_TRANSPORT_CHILD_DIAGNOSTIC_BEGIN", transport)
        self.assertIn("PUBLIC_TRANSPORT_CHILD_DIAGNOSTIC_END", transport)
        self.assertIn("PUBLIC_TRANSPORT_CHILD_WAIT result=$wait_result", transport)
        self.assertLess(
            transport.index("emit_complete_child_diagnostics $captured $password $wait_result"),
            transport.index('set password ""', transport.index("set wait_failed")),
        )
        self.assertNotIn("puts stderr $captured", transport)
        self.assertIn(
            r"PUBLIC_ENDPOINT_STOP reason=[A-Za-z0-9_.:-]+ rc=[0-9]+",
            transport,
        )
        self.assertNotIn("claim_path, claim_sha256 = claim_files[role]", controller)
        self.assertIn(
            "claim_path, role_claim_sha256 = claim_files[role]", controller
        )
        claimed_root = controller.index('if "owner.json" in entries:')
        self.assertLess(
            controller.index(
                "verify_root_claim(remote, args, artifacts)", claimed_root
            ),
            controller.index("return True", claimed_root),
        )
        self.assertIn("staging_name = staging_wg_name(args.claim_sha256", endpoint)
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

    def test_intake_claim_accepts_the_actual_six_field_stat_shape(self) -> None:
        args = SimpleNamespace(
            run_id="0123456789ab",
            commit="1" * 40,
            ownership_token="2" * 32,
        )
        artifacts = {
            name: {"sha256": character * 64}
            for name, character in (
                ("binary", "3"),
                ("endpoint", "4"),
                ("object", "5"),
                ("traffic", "6"),
            )
        }
        expected = self.controller.intake_claim_bytes(args, "b82", artifacts)
        digest = self.controller.hashlib.sha256(expected).hexdigest()
        intake, _ = self.controller.remote_layout(args.run_id, "b82")

        class Remote:
            role = "b82"

            def ssh(self, *argv: str) -> str:
                if argv[0] == "/usr/bin/stat" and argv[-1] == intake:
                    return "1000:1000:700:directory"
                if argv[0] == "/usr/bin/stat":
                    return f"1000:1000:600:1:{len(expected)}:regular file"
                return f"{digest}  {intake}/intake-owner.json"

        self.controller.verify_intake_claim(Remote(), args, artifacts)

    def test_pristine_unaliased_wireguard_is_recoverable_before_configuration(
        self,
    ) -> None:
        claim_sha256 = "a" * 64
        staging_name = self.root.staging_wg_name(claim_sha256, "public")
        responses = [
            json.dumps(
                [
                    {
                        "ifname": staging_name,
                        "flags": ["POINTOPOINT", "NOARP"],
                        "operstate": "DOWN",
                        "linkinfo": {"info_kind": "wireguard"},
                    }
                ]
            ).encode(),
            json.dumps([{"ifname": staging_name, "addr_info": []}]).encode(),
            b"",
            b"0\n",
            b"off\n",
        ]
        staging_path = f"/sys/class/net/{staging_name}"

        def exists(path: Path) -> bool:
            return str(path) == staging_path

        with mock.patch.object(Path, "exists", exists), mock.patch.object(
            self.root, "command", side_effect=responses
        ):
            owned, preserve_fixed = self.root.classify_owned_link(
                Path("/var/tmp/wg-mix-ebpf-public-smoke-test-public"),
                "0123456789ab",
                "public",
                claim_sha256,
            )
        self.assertEqual(staging_name, owned)
        self.assertFalse(preserve_fixed)

    def test_fixed_name_collision_preserves_foreign_and_selects_staging(self) -> None:
        claim_sha256 = "a" * 64
        run_id = "0123456789ab"
        staging_name = self.root.staging_wg_name(claim_sha256, "public")
        expected_alias = f"wg-mix-public-smoke:{run_id}:public"
        links = {
            staging_name: {
                "ifname": staging_name,
                "ifalias": expected_alias,
                "flags": ["POINTOPOINT", "NOARP"],
                "operstate": "DOWN",
                "linkinfo": {"info_kind": "wireguard"},
            },
            "wgps47": {
                "ifname": "wgps47",
                "ifalias": "foreign-service",
                "flags": ["UP"],
                "operstate": "UP",
                "linkinfo": {"info_kind": "wireguard"},
            },
        }

        def exists(path: Path) -> bool:
            return str(path) in {
                f"/sys/class/net/{staging_name}",
                "/sys/class/net/wgps47",
            }

        def command(argv: list[str], **_kwargs: object) -> bytes:
            return json.dumps([links[argv[-1]]]).encode()

        with mock.patch.object(Path, "exists", exists), mock.patch.object(
            self.root, "command", side_effect=command
        ):
            owned, preserve_fixed = self.root.classify_owned_link(
                Path("/var/tmp/wg-mix-ebpf-public-smoke-test-public"),
                run_id,
                "public",
                claim_sha256,
            )
        self.assertEqual(staging_name, owned)
        self.assertTrue(preserve_fixed)

    def test_apply_aliases_unique_staging_link_before_fixed_name(self) -> None:
        claim_sha256 = "b" * 64
        staging_name = self.root.staging_wg_name(claim_sha256, "public")
        args = SimpleNamespace(
            run_id="0123456789ab",
            role="public",
            commit="1" * 40,
            claim_sha256=claim_sha256,
            peer_public_key=base64.b64encode(b"p" * 32).decode("ascii"),
        )
        command_calls: list[list[str]] = []

        def command(argv: list[str], **_kwargs: object) -> bytes:
            command_calls.append(argv)
            return b""

        status = json.dumps(
            {
                "dataplane": {
                    "underlays": [
                        {
                            "ingress_attached": True,
                            "egress_attached": True,
                            "filters": [
                                {"backend": "classic_tc"},
                                {"backend": "classic_tc"},
                            ],
                        }
                    ]
                }
            }
        ).encode()
        with (
            mock.patch.object(self.root, "require_root_directory"),
            mock.patch.object(
                self.root, "load_owner", return_value={"script_sha256": "c" * 64}
            ),
            mock.patch.object(self.root, "self_check"),
            mock.patch.object(self.root, "artifact_check"),
            mock.patch.object(self.root, "verify_host"),
            mock.patch.object(
                self.root,
                "load_private_key",
                return_value=b"A" * 43 + b"=\n",
            ),
            mock.patch.object(Path, "exists", return_value=False),
            mock.patch.object(self.root, "write_new"),
            mock.patch.object(self.root, "command", side_effect=command),
            mock.patch.object(
                self.root, "config_bytes", return_value=(b"wg", b"agent")
            ),
            mock.patch.object(self.root, "binary_command", side_effect=(b"", status)),
        ):
            self.root.apply_endpoint(args)
        self.assertEqual(
            [
                [
                    self.root.TOOLS["ip"],
                    "link",
                    "add",
                    "dev",
                    staging_name,
                    "type",
                    "wireguard",
                ],
                [
                    self.root.TOOLS["ip"],
                    "link",
                    "set",
                    "dev",
                    staging_name,
                    "alias",
                    "wg-mix-public-smoke:0123456789ab:public",
                ],
                [
                    self.root.TOOLS["ip"],
                    "link",
                    "set",
                    "dev",
                    staging_name,
                    "name",
                    "wgps47",
                ],
            ],
            command_calls[:3],
        )

    def test_b82_applies_endpoint_in_a_separate_labeled_wg_step(self) -> None:
        claim_sha256 = "c" * 64
        args = SimpleNamespace(
            run_id="0123456789ab",
            role="b82",
            commit="1" * 40,
            claim_sha256=claim_sha256,
            peer_public_key=base64.b64encode(b"q" * 32).decode("ascii"),
        )
        command_calls: list[tuple[list[str], dict[str, object]]] = []

        def command(argv: list[str], **kwargs: object) -> bytes:
            command_calls.append((argv, kwargs))
            return b""

        status = json.dumps(
            {
                "dataplane": {
                    "underlays": [
                        {
                            "ingress_attached": True,
                            "egress_attached": True,
                            "filters": [{"backend": "tcx"}, {"backend": "tcx"}],
                        }
                    ]
                }
            }
        ).encode()
        with (
            mock.patch.object(self.root, "require_root_directory"),
            mock.patch.object(
                self.root, "load_owner", return_value={"script_sha256": "d" * 64}
            ),
            mock.patch.object(self.root, "self_check"),
            mock.patch.object(self.root, "artifact_check"),
            mock.patch.object(self.root, "verify_host"),
            mock.patch.object(
                self.root,
                "load_private_key",
                return_value=b"A" * 43 + b"=\n",
            ),
            mock.patch.object(Path, "exists", return_value=False),
            mock.patch.object(self.root, "write_new"),
            mock.patch.object(self.root, "command", side_effect=command),
            mock.patch.object(
                self.root, "config_bytes", return_value=(b"wg", b"agent")
            ),
            mock.patch.object(self.root, "binary_command", side_effect=(b"", status)),
        ):
            self.root.apply_endpoint(args)

        wg_calls = [
            item
            for item in command_calls
            if item[0][:2] == [self.root.TOOLS["wg"], "set"]
        ]
        self.assertEqual(5, len(wg_calls))
        self.assertEqual("wg-private-key", wg_calls[0][1].get("stop_label"))
        self.assertEqual(
            [self.root.TOOLS["wg"], "set", "wgps82", "private-key", "/dev/stdin"],
            wg_calls[0][0],
        )
        self.assertEqual(b"A" * 43 + b"=\n", wg_calls[0][1].get("input_bytes"))
        self.assertEqual("wg-listen-port", wg_calls[1][1].get("stop_label"))
        self.assertEqual("wg-fwmark", wg_calls[2][1].get("stop_label"))
        self.assertEqual("wg-peer", wg_calls[3][1].get("stop_label"))
        for call, _kwargs in wg_calls[:4]:
            self.assertNotIn("endpoint", call)
        self.assertEqual(
            [
                self.root.TOOLS["wg"],
                "set",
                "wgps82",
                "peer",
                args.peer_public_key,
                "endpoint",
                "47.116.202.155:31155",
            ],
            wg_calls[4][0],
        )
        self.assertEqual("wg-endpoint", wg_calls[4][1].get("stop_label"))

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
