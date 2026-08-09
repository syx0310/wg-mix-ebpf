#!/usr/bin/env python3

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import pathlib
import sys
import unittest


MODULE_PATH = pathlib.Path(__file__).with_name("realnic_acceptance.py")
SPEC = importlib.util.spec_from_file_location("realnic_acceptance", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class FixtureRunner(MODULE.CommandRunner):
    def __init__(self, spec, *, fixed=()):
        self.calls = []
        self.outputs = fixture_outputs(spec, fixed=fixed)

    def capture(self, argv, timeout=20):
        self.calls.append((list(argv), timeout))
        key = tuple(argv)
        if key not in self.outputs:
            raise AssertionError(f"unexpected command {argv!r}")
        return 0, self.outputs[key], b""


def fixture_spec(**changes):
    values = dict(
        run_id="a1b2c3d4",
        run_root="/run/wg-mix-ebpf-realnic-acceptance-a1b2c3d4",
        source_commit="1234567890abcdef1234567890abcdef12345678",
        interface="ens33",
        expected_ifindex=2,
        expected_mac="00:50:56:aa:bb:cc",
        expected_driver="vmxnet3",
        expected_bus_info="0000:03:00.0",
        expected_device_path="/sys/devices/pci0000:00/0000:00:11.0/0000:03:00.0",
        expected_device_dev=19,
        expected_device_ino=4242,
        expected_mtu=1500,
        expected_hostname="ubuntu-2604-test",
        expected_kernel="7.0.0-28-generic",
        expected_machine_id="9db3fb717cc74974b2a6b243d67f67b9",
        expected_boot_id="12345678-1234-4234-9234-1234567890ab",
        peer_address=MODULE.READ_ONLY_PEER,
        peer_port=5201,
        traffic_seconds=5,
        soak_seconds=60,
        soak_window_seconds=10,
        mtu_low=1492,
    )
    values.update(changes)
    return MODULE.CoreSpec(**values).validate()


def fixture_outputs(spec, *, fixed=()):
    sysfs = f"/sys/class/net/{spec.interface}"
    features = [f"Features for {spec.interface}:"]
    initial = {
        "rx-checksumming": True,
        "tx-checksumming": True,
        "generic-segmentation-offload": True,
        "generic-receive-offload": True,
        "tcp-segmentation-offload": True,
        "tx-udp-segmentation": False,
        "rx-udp-gro-forwarding": False,
    }
    for name in MODULE.FEATURE_ORDER:
        suffix = " [fixed]" if name in fixed else ""
        features.append(f"{name}: {'on' if initial[name] else 'off'}{suffix}")
    json_bytes = lambda value: json.dumps(value).encode()
    result = {
        (MODULE.TOOLS["hostname"],): f"{spec.expected_hostname}\n".encode(),
        (MODULE.TOOLS["uname"], "-r"): f"{spec.expected_kernel}\n".encode(),
        (MODULE.TOOLS["cat"], "/etc/machine-id"): f"{spec.expected_machine_id}\n".encode(),
        (MODULE.TOOLS["cat"], "/proc/sys/kernel/random/boot_id"): f"{spec.expected_boot_id}\n".encode(),
        (MODULE.TOOLS["readlink"], "/proc/self/ns/net"): b"net:[4026531840]\n",
        (MODULE.TOOLS["cat"], f"{sysfs}/ifindex"): f"{spec.expected_ifindex}\n".encode(),
        (MODULE.TOOLS["cat"], f"{sysfs}/address"): f"{spec.expected_mac}\n".encode(),
        (MODULE.TOOLS["cat"], f"{sysfs}/mtu"): f"{spec.expected_mtu}\n".encode(),
        (MODULE.TOOLS["readlink"], "-e", f"{sysfs}/device"): f"{spec.expected_device_path}\n".encode(),
        (MODULE.TOOLS["stat"], "-Lc", "%d:%i", f"{sysfs}/device"): f"{spec.expected_device_dev}:{spec.expected_device_ino}\n".encode(),
        (MODULE.TOOLS["ethtool"], "-i", spec.interface): (
            f"driver: {spec.expected_driver}\nversion: 1\nfirmware-version: 2\nbus-info: {spec.expected_bus_info}\n"
        ).encode(),
        (MODULE.TOOLS["ethtool"], "-k", spec.interface): ("\n".join(features) + "\n").encode(),
        (MODULE.TOOLS["ip"], "-d", "-j", "link", "show", "dev", spec.interface): json_bytes(
            [{"ifindex": spec.expected_ifindex, "ifname": spec.interface, "mtu": spec.expected_mtu, "address": spec.expected_mac, "flags": ["UP", "LOWER_UP"]}]
        ),
        (MODULE.TOOLS["ip"], "-j", "address", "show", "dev", spec.interface): json_bytes(
            [{"ifindex": spec.expected_ifindex, "ifname": spec.interface, "addr_info": [{"family": "inet", "local": "192.168.10.82", "prefixlen": 24}]}]
        ),
        (MODULE.TOOLS["ip"], "-j", "route", "show", "table", "all", "dev", spec.interface): json_bytes(
            [{"dst": "default", "gateway": "192.168.10.1", "dev": spec.interface}]
        ),
        (MODULE.TOOLS["ip"], "-j", "route", "get", spec.peer_address): json_bytes(
            [{"dst": spec.peer_address, "gateway": "192.168.10.1", "dev": spec.interface, "prefsrc": "192.168.10.82"}]
        ),
        (MODULE.TOOLS["tc"], "-j", "qdisc", "show", "dev", spec.interface): b"[]",
        (MODULE.TOOLS["tc"], "-j", "filter", "show", "dev", spec.interface, "ingress"): b"[]",
        (MODULE.TOOLS["tc"], "-j", "filter", "show", "dev", spec.interface, "egress"): b"[]",
        (MODULE.TOOLS["bpftool"], "-j", "link", "show"): b"[]",
        (MODULE.TOOLS["bpftool"], "-j", "prog", "show"): b"[]",
        (MODULE.TOOLS["bpftool"], "-j", "map", "show"): b"[]",
        (MODULE.TOOLS["wg"], "show", "interfaces"): b"wg0\n",
        (MODULE.TOOLS["ethtool"], "-S", spec.interface): b"NIC statistics:\n     rx_errors: 0\n     tx_errors: 0\n",
    }
    return result


class PlannerTests(unittest.TestCase):
    def test_plan_is_deterministic_and_read_only(self):
        spec = fixture_spec()
        first_runner = FixtureRunner(spec)
        snapshot, commands = MODULE.collect_snapshot(spec, first_runner)
        first = MODULE.canonical_json(MODULE.build_plan(spec, snapshot, commands))
        second_runner = FixtureRunner(spec)
        snapshot2, commands2 = MODULE.collect_snapshot(spec, second_runner)
        second = MODULE.canonical_json(MODULE.build_plan(spec, snapshot2, commands2))
        self.assertEqual(first, second)
        self.assertTrue(first_runner.calls)
        for argv, _ in first_runner.calls:
            self.assertNotIn(argv[:2], [[MODULE.TOOLS["ethtool"], "-K"]])
            self.assertNotEqual(argv[1:3], ["link", "set"])
        plan = json.loads(first)
        self.assertEqual(plan["schema"], MODULE.SCHEMA)
        self.assertEqual(plan["write_set"]["peer"], [])
        self.assertEqual(plan["write_set"]["qdisc"], [])
        self.assertEqual(plan["write_set"]["routes"], [])
        self.assertEqual(plan["write_set"]["bpf"], [])

    def test_plan_covers_p1_without_false_faketcp_passes(self):
        spec = fixture_spec()
        runner = FixtureRunner(spec)
        snapshot, commands = MODULE.collect_snapshot(spec, runner)
        plan = MODULE.build_plan(spec, snapshot, commands)
        by_name = {cell["name"]: cell for cell in plan["cells"]}
        for name in (
            "tcp-original",
            "tcp-all-on",
            "tcp-all-off",
            "tcp-tx-path",
            "tcp-rx-path",
            "tcp-mtu-low",
            "tcp-mtu-original",
            "tcp-soak-all-on",
        ):
            self.assertTrue(by_name[name]["runnable"], name)
        for name in (
            "faketcp-realnic-tcp-multiflow",
            "faketcp-checksum-none",
            "faketcp-checksum-partial",
            "faketcp-gso-gro",
            "faketcp-pmtu-boundary",
            "faketcp-bounded-soak",
        ):
            self.assertFalse(by_name[name]["runnable"], name)
            self.assertEqual(by_name[name]["classification"], "not-covered")
            self.assertEqual(by_name[name]["mutation"], [])
        self.assertFalse(plan["safety_contract"]["implemented_capability_bits_changed"])
        self.assertFalse(plan["safety_contract"]["af_packet_no_dst_positive_pmtu"])

    def test_fixed_feature_is_unsupported_not_silently_toggled(self):
        spec = fixture_spec()
        runner = FixtureRunner(spec, fixed={"tx-udp-segmentation"})
        snapshot, commands = MODULE.collect_snapshot(spec, runner)
        plan = MODULE.build_plan(spec, snapshot, commands)
        all_on = next(cell for cell in plan["cells"] if cell["name"] == "tcp-all-on")
        self.assertEqual(all_on["classification"], "unsupported")
        self.assertIn("tx-udp-segmentation", all_on["classification_reason"])
        mutated = [step["argv"][-2] for step in all_on["mutation"]]
        self.assertNotIn("tx-udp-segmentation", mutated)

    def test_each_network_mutation_has_explicit_restore(self):
        spec = fixture_spec()
        runner = FixtureRunner(spec)
        snapshot, commands = MODULE.collect_snapshot(spec, runner)
        plan = MODULE.build_plan(spec, snapshot, commands)
        baseline = {name: entry["enabled"] for name, entry in snapshot["features"].items()}
        for cell in plan["cells"]:
            if not cell["runnable"]:
                continue
            changed = [step["argv"][-2] for step in cell["mutation"] if step["argv"][0] == MODULE.TOOLS["ethtool"]]
            restored = [step["argv"][-2] for step in cell["restore"] if step["argv"][0] == MODULE.TOOLS["ethtool"]]
            self.assertEqual(restored, list(reversed(changed)), cell["name"])
            for step in cell["restore"]:
                if step["argv"][0] == MODULE.TOOLS["ethtool"]:
                    name, state = step["argv"][-2:]
                    self.assertEqual(state, "on" if baseline[name] else "off")
            mtu_mutations = [step for step in cell["mutation"] if step["argv"][0] == MODULE.TOOLS["ip"]]
            mtu_restores = [step for step in cell["restore"] if step["argv"][0] == MODULE.TOOLS["ip"]]
            self.assertEqual(bool(mtu_mutations), bool(mtu_restores), cell["name"])

    def test_plan_mode_outputs_canonical_json_only(self):
        spec = fixture_spec()
        runner = FixtureRunner(spec)
        stdout = io.BytesIO()
        wrapper = io.TextIOWrapper(stdout, encoding="utf-8")
        with contextlib.redirect_stdout(wrapper):
            rc = MODULE.plan_mode(spec, runner)
            wrapper.flush()
        self.assertEqual(rc, 0)
        payload = stdout.getvalue()
        self.assertTrue(payload.endswith(b"\n"))
        self.assertEqual(payload, MODULE.canonical_json(json.loads(payload)))

    def test_identity_mismatch_fails_closed(self):
        spec = fixture_spec(expected_ifindex=9)
        runner = FixtureRunner(fixture_spec())
        with self.assertRaisesRegex(MODULE.HarnessError, "interface identity mismatch"):
            MODULE.collect_snapshot(spec, runner)

    def test_peer_and_run_root_are_locked(self):
        with self.assertRaises(MODULE.HarnessError):
            fixture_spec(peer_address="192.0.2.1")
        with self.assertRaises(MODULE.HarnessError):
            fixture_spec(run_root="/run/wrong")


if __name__ == "__main__":
    unittest.main()
