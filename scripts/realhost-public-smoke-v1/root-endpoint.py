#!/usr/bin/env python3
"""Fail-closed root endpoint for a bounded two-host baseline-BPF smoke test."""

from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, NoReturn


SCHEMA = "wg-mix-public-endpoint-owner-v1"
RUN_ID_RE = re.compile(r"^[0-9a-f]{12,24}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PUBKEY_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")
ROLE = {
    "b82": {
        "host": "ubuntu-2604-test",
        "interface": "ens33",
        "wg": "wgps82",
        "address": "10.203.82.1/30",
        "peer_address": "10.203.82.2",
        "listen_port": 31882,
        "fwmark": "0x51820001",
        "attachment_backend": "tcx",
        "minimum_kernel": (6, 6),
    },
    "public": {
        "host": None,
        "interface": "eth0",
        "wg": "wgps47",
        "address": "10.203.82.2/30",
        "peer_address": "10.203.82.1",
        "listen_port": 31155,
        "fwmark": "0x51820002",
        "attachment_backend": "classic_tc",
        "minimum_kernel": (5, 15),
    },
}
TOOLS = {
    "ip": "/usr/sbin/ip",
    "ping": "/usr/bin/ping",
    "python": "/usr/bin/python3",
    "sha256sum": "/usr/bin/sha256sum",
    "tcpdump": "/usr/bin/tcpdump",
    "tc": "/usr/sbin/tc",
    "timeout": "/usr/bin/timeout",
    "uname": "/usr/bin/uname",
    "wg": "/usr/bin/wg",
}
KNOWN_ROOT_FILES = frozenset(
    {
        "root-endpoint.py",
        "root-claim.json",
        "owner.json",
        "owner.pending.json",
        "intent.json",
        "wg-mix-ebpf",
        "wg_mix_tc.o",
        "traffic.py",
        "private.key",
        "public.key",
        "wg-interface.conf",
        "agent.yaml",
        "applied.json",
        "restored.json",
        "services.lock",
    }
)
KNOWN_EVIDENCE_RE = re.compile(
    r"^(?:server|capture)\.(?:stdout|stderr|pcap)|sample\.[0-9]{6}\.json|"
    r"(?:ping|udp|tcp)\.[a-z0-9_-]+\.(?:json|txt)$"
)


def stop(reason: str, rc: int = 78) -> NoReturn:
    print(f"PUBLIC_ENDPOINT_STOP reason={reason} rc={rc}", file=sys.stderr)
    raise SystemExit(rc)


def command(
    argv: list[str], *, input_bytes: bytes | None = None, timeout: int = 60
) -> bytes:
    try:
        completed = subprocess.run(
            argv,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        stop(f"command:{Path(argv[0]).name}:{type(error).__name__}")
    if completed.returncode != 0:
        stop(f"command:{Path(argv[0]).name}:rc{completed.returncode}", 77)
    return completed.stdout


def canonical_run_root(run_id: str, role: str) -> Path:
    if not RUN_ID_RE.fullmatch(run_id) or role not in ROLE:
        stop("arguments", 64)
    return Path(f"/var/tmp/wg-mix-ebpf-public-smoke-{run_id}-{role}")


def staging_wg_name(claim_sha256: str, role: str) -> str:
    if not SHA256_RE.fullmatch(claim_sha256) or role not in ROLE:
        stop("staging-wg", 64)
    prefix = "wmb" if role == "b82" else "wmp"
    return f"{prefix}{claim_sha256[:12]}"


def sha256_fd(fd: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while True:
        chunk = os.pread(fd, 1024 * 1024, offset)
        if not chunk:
            break
        digest.update(chunk)
        offset += len(chunk)
    return digest.hexdigest()


def secure_regular(path: Path, expected_sha256: str, *, root_owned: bool) -> os.stat_result:
    if not path.is_absolute() or not SHA256_RE.fullmatch(expected_sha256):
        stop("artifact-arguments", 64)
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        fd = os.open(path, flags)
    except OSError:
        stop(f"artifact-open:{path.name}", 79)
    try:
        observed = os.fstat(fd)
        if not stat.S_ISREG(observed.st_mode) or observed.st_nlink != 1:
            stop(f"artifact-shape:{path.name}", 79)
        if root_owned and (observed.st_uid != 0 or observed.st_gid != 0 or observed.st_mode & 0o022):
            stop(f"artifact-owner:{path.name}", 79)
        if not root_owned and observed.st_mode & 0o022:
            stop(f"artifact-writable:{path.name}", 79)
        if sha256_fd(fd) != expected_sha256:
            stop(f"artifact-sha256:{path.name}", 79)
        named = os.stat(path, follow_symlinks=False)
        if (named.st_dev, named.st_ino) != (observed.st_dev, observed.st_ino):
            stop(f"artifact-pathswap:{path.name}", 79)
        return observed
    finally:
        os.close(fd)


def write_new(path: Path, data: bytes, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, mode)
    except OSError:
        stop(f"create:{path.name}", 79)
    try:
        os.fchmod(fd, mode)
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                stop(f"write:{path.name}")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def write_owner_new(root: Path, data: bytes) -> None:
    pending = root / "owner.pending.json"
    final = root / "owner.json"
    if pending.exists() or final.exists():
        stop("owner-create", 79)
    write_new(pending, data, 0o600)
    try:
        os.rename(pending, final)
        directory_fd = os.open(
            root,
            os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError:
        stop("owner-publish", 79)


def copy_new(source: Path, target: Path, expected_sha256: str, mode: int) -> None:
    secure_regular(source, expected_sha256, root_owned=False)
    source_fd = os.open(
        source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    )
    try:
        data = bytearray()
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > 128 * 1024 * 1024:
                stop(f"artifact-size:{source.name}")
        if hashlib.sha256(data).hexdigest() != expected_sha256:
            stop(f"artifact-reread:{source.name}", 79)
        write_new(target, bytes(data), mode)
    finally:
        os.close(source_fd)


def require_root_directory(path: Path) -> os.stat_result:
    try:
        observed = os.stat(path, follow_symlinks=False)
    except OSError:
        stop(f"directory-missing:{path.name}", 79)
    if (
        not stat.S_ISDIR(observed.st_mode)
        or observed.st_uid != 0
        or observed.st_gid != 0
        or stat.S_IMODE(observed.st_mode) != 0o700
    ):
        stop(f"directory-identity:{path.name}", 79)
    return observed


def self_check(root: Path, expected_sha256: str) -> None:
    expected = root / "root-endpoint.py"
    try:
        actual = Path(__file__).resolve(strict=True)
    except OSError:
        stop("self-resolve", 79)
    if actual != expected:
        stop("self-path", 79)
    secure_regular(expected, expected_sha256, root_owned=True)


def kernel_tuple(release: str) -> tuple[int, int]:
    match = re.match(r"^([0-9]+)\.([0-9]+)(?:\.|-)", release)
    if not match:
        stop("kernel-release", 79)
    return int(match.group(1)), int(match.group(2))


def probe(role: str) -> dict[str, Any]:
    spec = ROLE[role]
    missing = [path for path in TOOLS.values() if not Path(path).is_file()]
    hostname = os.uname().nodename
    release = os.uname().release
    interface = spec["interface"]
    link: Any = None
    try:
        completed = subprocess.run(
            [TOOLS["ip"], "-j", "link", "show", "dev", interface],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=5,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
        decoded = json.loads(completed.stdout) if completed.returncode == 0 else None
        if isinstance(decoded, list) and len(decoded) == 1:
            link = decoded[0]
    except (OSError, ValueError, subprocess.TimeoutExpired):
        pass
    bpffs = False
    try:
        fs_type = subprocess.run(
            ["/usr/bin/stat", "-fc", "%T", "/sys/fs/bpf"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=5,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
        bpffs = fs_type.returncode == 0 and fs_type.stdout == b"bpf_fs\n"
    except (OSError, subprocess.TimeoutExpired):
        pass
    expected_host = spec["host"]
    host_ok = expected_host is None or hostname == expected_host
    kernel_ok = kernel_tuple(release) >= spec["minimum_kernel"]
    classic_baseline: dict[str, Any] | None = None
    classic_ok = True
    if role == "public":
        try:
            qdiscs_run = subprocess.run(
                [TOOLS["tc"], "-j", "qdisc", "show", "dev", interface],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=5,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
            )
            ingress_run = subprocess.run(
                [TOOLS["tc"], "-j", "filter", "show", "dev", interface, "ingress"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=5,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
            )
            egress_run = subprocess.run(
                [TOOLS["tc"], "-j", "filter", "show", "dev", interface, "egress"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=5,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
            )
            qdiscs = json.loads(qdiscs_run.stdout) if qdiscs_run.returncode == 0 else None
            ingress = json.loads(ingress_run.stdout) if ingress_run.returncode == 0 else None
            egress = json.loads(egress_run.stdout) if egress_run.returncode == 0 else None
        except (OSError, ValueError, subprocess.TimeoutExpired):
            qdiscs, ingress, egress = None, None, None
        clsact_count = (
            sum(1 for item in qdiscs if isinstance(item, dict) and item.get("kind") == "clsact")
            if isinstance(qdiscs, list)
            else -1
        )
        classic_ok = clsact_count == 1 and ingress == [] and egress == []
        classic_baseline = {
            "clsact_count": clsact_count,
            "ingress_filters": len(ingress) if isinstance(ingress, list) else None,
            "egress_filters": len(egress) if isinstance(egress, list) else None,
            "clean": classic_ok,
        }
    return {
        "schema": "wg-mix-public-endpoint-probe-v1",
        "role": role,
        "hostname": hostname,
        "kernel": release,
        "interface": interface,
        "ifindex": link.get("ifindex") if isinstance(link, dict) else None,
        "link_type": link.get("link_type") if isinstance(link, dict) else None,
        "host_identity_ok": host_ok,
        "tools_missing": missing,
        "bpffs": bpffs,
        "attachment_backend": spec["attachment_backend"],
        "minimum_kernel": ".".join(str(value) for value in spec["minimum_kernel"]),
        "kernel_floor_ok": kernel_ok,
        "classic_tc_baseline": classic_baseline,
        "eligible": host_ok and not missing and bpffs and kernel_ok and link is not None and classic_ok,
    }


def load_owner(
    root: Path,
    run_id: str,
    role: str,
    commit: str,
    claim_sha256: str,
) -> dict[str, Any]:
    owner_path = root / "owner.json"
    fd = -1
    try:
        fd = os.open(
            owner_path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
        )
        observed = os.fstat(fd)
        if (
            not stat.S_ISREG(observed.st_mode)
            or observed.st_uid != 0
            or observed.st_gid != 0
            or stat.S_IMODE(observed.st_mode) != 0o600
            or observed.st_nlink != 1
            or observed.st_size < 2
            or observed.st_size > 16 * 1024
        ):
            stop("owner-shape", 79)
        data = os.pread(fd, observed.st_size, 0)
        named = os.stat(owner_path, follow_symlinks=False)
        if (named.st_dev, named.st_ino) != (observed.st_dev, observed.st_ino):
            stop("owner-pathswap", 79)
        owner = json.loads(data)
    except (OSError, ValueError):
        stop("owner-read", 79)
    finally:
        if fd >= 0:
            os.close(fd)
    expected = {
        "schema": SCHEMA,
        "run_id": run_id,
        "role": role,
        "commit": commit,
        "run_root": str(root),
        "claim_sha256": claim_sha256,
    }
    if not isinstance(owner, dict) or any(owner.get(k) != v for k, v in expected.items()):
        stop("owner-drift", 79)
    return owner


def prepare(args: argparse.Namespace) -> None:
    root = canonical_run_root(args.run_id, args.role)
    require_root_directory(root)
    self_check(root, args.script_sha256)
    if not COMMIT_RE.fullmatch(args.commit):
        stop("commit", 64)
    if not args.claim_sha256 or not SHA256_RE.fullmatch(args.claim_sha256):
        stop("claim-sha256", 64)
    entries = sorted(path.name for path in root.iterdir())
    if entries != ["root-claim.json", "root-endpoint.py"]:
        stop("prepare-root-not-empty", 79)
    for name in (
        "script_sha256",
        "claim_sha256",
        "binary_sha256",
        "object_sha256",
        "traffic_sha256",
    ):
        if not SHA256_RE.fullmatch(getattr(args, name)):
            stop(f"prepare-{name}", 64)
    claim = secure_regular(root / "root-claim.json", args.claim_sha256, root_owned=True)
    if stat.S_IMODE(claim.st_mode) != 0o600:
        stop("prepare-claim-mode", 79)
    current_probe = probe(args.role)
    artifacts = {
        "binary": (Path(args.binary_source), "wg-mix-ebpf", args.binary_sha256, 0o700),
        "object": (Path(args.object_source), "wg_mix_tc.o", args.object_sha256, 0o600),
        "traffic": (Path(args.traffic_source), "traffic.py", args.traffic_sha256, 0o700),
    }
    owner = {
        "schema": SCHEMA,
        "run_id": args.run_id,
        "role": args.role,
        "commit": args.commit,
        "run_root": str(root),
        "hostname": current_probe["hostname"],
        "kernel": current_probe["kernel"],
        "interface": ROLE[args.role]["interface"],
        "ifindex": current_probe["ifindex"],
        "attachment_backend": current_probe["attachment_backend"],
        "script_sha256": args.script_sha256,
        "claim_sha256": args.claim_sha256,
        "binary_sha256": args.binary_sha256,
        "object_sha256": args.object_sha256,
        "traffic_sha256": args.traffic_sha256,
    }
    write_owner_new(root, (json.dumps(owner, sort_keys=True) + "\n").encode())
    if not current_probe["eligible"]:
        stop("probe-ineligible", 77)
    for source, name, digest, mode in artifacts.values():
        copy_new(source, root / name, digest, mode)
    (root / "state").mkdir(mode=0o700)
    (root / "runtime").mkdir(mode=0o700)
    (root / "evidence").mkdir(mode=0o700)
    write_new(root / "services.lock", b"", 0o600)
    private = command([TOOLS["wg"], "genkey"])
    if len(private) != 45 or not private.endswith(b"\n"):
        stop("private-key-shape")
    public = command([TOOLS["wg"], "pubkey"], input_bytes=private)
    if len(public) != 45 or not PUBKEY_RE.fullmatch(public.decode().rstrip("\n")):
        stop("public-key-shape")
    write_new(root / "private.key", private, 0o600)
    write_new(root / "public.key", public, 0o600)
    print(
        json.dumps(
            {
                "status": "prepared",
                "role": args.role,
                "run_id": args.run_id,
                "public_key": public.decode().rstrip("\n"),
            },
            sort_keys=True,
        )
    )


def artifact_check(
    root: Path, owner: dict[str, Any], *, allow_missing: bool = False
) -> None:
    for name, key, mode in (
        ("root-endpoint.py", "script_sha256", 0o700),
        ("root-claim.json", "claim_sha256", 0o600),
        ("wg-mix-ebpf", "binary_sha256", 0o700),
        ("wg_mix_tc.o", "object_sha256", 0o600),
        ("traffic.py", "traffic_sha256", 0o700),
    ):
        path = root / name
        if allow_missing and name not in {"root-endpoint.py", "root-claim.json"}:
            if not path.exists():
                continue
            try:
                observed = os.stat(path, follow_symlinks=False)
            except OSError:
                stop(f"artifact-partial:{name}", 79)
            if (
                not stat.S_ISREG(observed.st_mode)
                or observed.st_uid != 0
                or observed.st_gid != 0
                or observed.st_nlink != 1
                or stat.S_IMODE(observed.st_mode) != mode
            ):
                stop(f"artifact-partial:{name}", 79)
            continue
        observed = secure_regular(path, owner[key], root_owned=True)
        if stat.S_IMODE(observed.st_mode) != mode:
            stop(f"artifact-mode:{name}", 79)


def abort_unclaimed(args: argparse.Namespace) -> None:
    root = canonical_run_root(args.run_id, args.role)
    require_root_directory(root)
    self_check(root, args.script_sha256)
    entries = sorted(path.name for path in root.iterdir())
    if entries not in (
        ["root-claim.json", "root-endpoint.py"],
        ["owner.pending.json", "root-claim.json", "root-endpoint.py"],
    ):
        stop("abort-unclaimed-foreign", 79)
    claim = secure_regular(root / "root-claim.json", args.claim_sha256, root_owned=True)
    if stat.S_IMODE(claim.st_mode) != 0o600:
        stop("abort-unclaimed-claim", 79)
    pending = root / "owner.pending.json"
    if pending.exists():
        observed = pending.lstat()
        if (
            not stat.S_ISREG(observed.st_mode)
            or observed.st_uid != 0
            or observed.st_gid != 0
            or observed.st_nlink != 1
            or stat.S_IMODE(observed.st_mode) != 0o600
            or observed.st_size > 16 * 1024
        ):
            stop("abort-unclaimed-owner-pending", 79)
        os.unlink(pending)
    os.unlink(root / "root-claim.json")
    os.unlink(root / "root-endpoint.py")
    os.rmdir(root)
    print(json.dumps({"status": "aborted-unclaimed", "run_id": args.run_id, "role": args.role}))


def config_bytes(root: Path, role: str) -> tuple[bytes, bytes]:
    spec = ROLE[role]
    wg_config = f"[Interface]\nListenPort = {spec['listen_port']}\nFwMark = {spec['fwmark']}\n"
    agent = f"""version: 1
mode: transparent-typeword
underlays:
  - name: {spec['interface']}
    type: netdev
    parser: ethernet
wireguards:
  - name: {spec['wg']}
    config: {root}/wg-interface.conf
    profile: public-smoke
    transport:
      mode: udp
profiles:
  public-smoke:
    preset: wireguard-mix-wire-values-v1
    index:
      mode: none
fwmark_policy:
  mode: config-required
runtime:
  poll_interval: 5s
  attachment_backend: {spec['attachment_backend']}
  require_nonzero_fwmark: true
  strict_runtime_fwmark: true
  allow_zero_fwmark_fallback: false
startup_guard:
  mode: none
  egress:
    match: fwmark
  ingress:
    match: config-listen-port-if-present
    random_listen_port_behavior: best-effort
underlay_overlap_policy: reject
"""
    return wg_config.encode(), agent.encode()


def loader_env(root: Path) -> dict[str, str]:
    return {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LC_ALL": "C",
        "WG_MIX_EBPF_OBJECT": str(root / "wg_mix_tc.o"),
        "WG_MIX_EBPF_PIN_PATH": f"/sys/fs/bpf/{root.name}",
    }


def binary_command(root: Path, argv: list[str], timeout: int = 120) -> bytes:
    try:
        completed = subprocess.run(
            [str(root / "wg-mix-ebpf"), *argv],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
            env=loader_env(root),
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        stop(f"agent:{type(error).__name__}")
    if completed.returncode != 0:
        stop(f"agent:rc{completed.returncode}", 77)
    return completed.stdout


def verify_host(owner: dict[str, Any]) -> None:
    current = probe(owner["role"])
    for key in ("hostname", "kernel", "interface", "ifindex", "attachment_backend"):
        if current.get(key) != owner.get(key):
            stop(f"host-drift:{key}", 79)
    if not current["eligible"]:
        stop("host-ineligible", 77)


def apply_endpoint(args: argparse.Namespace) -> None:
    root = canonical_run_root(args.run_id, args.role)
    require_root_directory(root)
    owner = load_owner(
        root, args.run_id, args.role, args.commit, args.claim_sha256
    )
    self_check(root, owner["script_sha256"])
    artifact_check(root, owner)
    verify_host(owner)
    if not PUBKEY_RE.fullmatch(args.peer_public_key):
        stop("peer-public-key", 64)
    try:
        base64.b64decode(args.peer_public_key, validate=True)
    except ValueError:
        stop("peer-public-key", 64)
    spec = ROLE[args.role]
    wg_name = spec["wg"]
    staging_name = staging_wg_name(args.claim_sha256, args.role)
    pin_path = Path(f"/sys/fs/bpf/{root.name}")
    if (
        Path(f"/sys/class/net/{wg_name}").exists()
        or Path(f"/sys/class/net/{staging_name}").exists()
        or pin_path.exists()
    ):
        stop("apply-resource-exists", 79)
    intent = {
        "schema": "wg-mix-public-endpoint-intent-v1",
        "run_id": args.run_id,
        "role": args.role,
        "wg": wg_name,
        "staging_wg": staging_name,
        "alias": f"wg-mix-public-smoke:{args.run_id}:{args.role}",
        "pin_path": str(pin_path),
        "peer_public_key": args.peer_public_key,
        "attachment_backend": spec["attachment_backend"],
    }
    write_new(root / "intent.json", (json.dumps(intent, sort_keys=True) + "\n").encode(), 0o600)
    command(
        [
            TOOLS["ip"],
            "link",
            "add",
            "dev",
            staging_name,
            "type",
            "wireguard",
        ]
    )
    command(
        [
            TOOLS["ip"],
            "link",
            "set",
            "dev",
            staging_name,
            "alias",
            intent["alias"],
        ]
    )
    command([TOOLS["ip"], "link", "set", "dev", staging_name, "name", wg_name])
    wg_argv = [
        TOOLS["wg"],
        "set",
        wg_name,
        "private-key",
        str(root / "private.key"),
        "listen-port",
        str(spec["listen_port"]),
        "fwmark",
        spec["fwmark"],
        "peer",
        args.peer_public_key,
        "allowed-ips",
        f"{spec['peer_address']}/32",
        "persistent-keepalive",
        "15",
    ]
    if args.role == "b82":
        wg_argv.extend(["endpoint", "47.116.202.155:31155"])
    command(wg_argv)
    command([TOOLS["ip"], "address", "add", spec["address"], "dev", wg_name])
    command([TOOLS["ip"], "link", "set", "dev", wg_name, "up"])
    wg_config, agent = config_bytes(root, args.role)
    write_new(root / "wg-interface.conf", wg_config, 0o600)
    write_new(root / "agent.yaml", agent, 0o600)
    binary_command(
        root,
        [
            "reload",
            "--config",
            str(root / "agent.yaml"),
            "--run-dir",
            str(root / "runtime"),
            "--state-dir",
            str(root / "state"),
        ],
    )
    status = json.loads(
        binary_command(
            root,
            [
                "status",
                "--config",
                str(root / "agent.yaml"),
                "--run-dir",
                str(root / "runtime"),
                "--state-dir",
                str(root / "state"),
            ],
        )
    )
    dataplane = status.get("dataplane") if isinstance(status, dict) else None
    underlays = dataplane.get("underlays") if isinstance(dataplane, dict) else None
    if (
        not isinstance(underlays, list)
        or len(underlays) != 1
        or not underlays[0].get("ingress_attached")
        or not underlays[0].get("egress_attached")
        or len(underlays[0].get("filters", [])) != 2
        or any(
            item.get("backend") != spec["attachment_backend"]
            for item in underlays[0].get("filters", [])
        )
    ):
        stop("attachment-postcondition", 79)
    write_new(
        root / "applied.json",
        (json.dumps({"status": "applied", **intent}, sort_keys=True) + "\n").encode(),
        0o600,
    )
    print(json.dumps({"status": "applied", "role": args.role, "run_id": args.run_id}))


def run_recorded_command(
    root: Path, name: str, argv: list[str], *, timeout: int
) -> None:
    lock_fd = acquire_service_lock(root, exclusive=False)
    try:
        if not (root / "applied.json").is_file() or (root / "restored.json").exists():
            stop(f"recorded-command-state:{name}", 79)
        with open(root / f"evidence/{name}.stdout", "xb", buffering=0) as stdout:
            with open(root / f"evidence/{name}.stderr", "xb", buffering=0) as stderr:
                completed = subprocess.run(
                    argv,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=stderr,
                    check=False,
                    timeout=timeout,
                    env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
                    pass_fds=(lock_fd,),
                )
    except (OSError, subprocess.TimeoutExpired) as error:
        stop(f"recorded-command:{name}:{type(error).__name__}", 77)
    finally:
        os.close(lock_fd)
    if completed.returncode != 0:
        stop(f"recorded-command:{name}:rc{completed.returncode}", 77)


def acquire_service_lock(root: Path, *, exclusive: bool) -> int:
    path = root / "services.lock"
    try:
        fd = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
        )
        observed = os.fstat(fd)
        named = os.stat(path, follow_symlinks=False)
        if (
            not stat.S_ISREG(observed.st_mode)
            or observed.st_uid != 0
            or observed.st_gid != 0
            or observed.st_nlink != 1
            or observed.st_size != 0
            or stat.S_IMODE(observed.st_mode) != 0o600
            or (observed.st_dev, observed.st_ino) != (named.st_dev, named.st_ino)
        ):
            stop("services-lock-shape", 79)
        operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        fcntl.flock(fd, operation | fcntl.LOCK_NB)
        return fd
    except BlockingIOError:
        if "fd" in locals():
            os.close(fd)
        stop("services-active", 78)
    except OSError:
        if "fd" in locals():
            os.close(fd)
        stop("services-lock", 79)


def start_server(args: argparse.Namespace) -> None:
    root = canonical_run_root(args.run_id, args.role)
    owner = load_owner(
        root, args.run_id, args.role, args.commit, args.claim_sha256
    )
    artifact_check(root, owner)
    if not (root / "applied.json").is_file():
        stop("server-state", 79)
    spec = ROLE[args.role]
    argv = [
        TOOLS["python"],
        str(root / "traffic.py"),
        "server",
        "--address",
        spec["address"].split("/", 1)[0],
        "--port",
        "45982",
        "--seconds",
        str(args.seconds),
    ]
    run_recorded_command(root, "server", argv, timeout=args.seconds + 15)
    print(json.dumps({"status": "server-complete", "role": args.role}))


def start_capture(args: argparse.Namespace) -> None:
    root = canonical_run_root(args.run_id, args.role)
    owner = load_owner(
        root, args.run_id, args.role, args.commit, args.claim_sha256
    )
    artifact_check(root, owner)
    if not (root / "applied.json").is_file():
        stop("capture-state", 79)
    listen_port = str(ROLE[args.role]["listen_port"])
    argv = [
        TOOLS["timeout"],
        "--signal=INT",
        "--kill-after=5s",
        "--preserve-status",
        str(args.seconds),
        TOOLS["tcpdump"],
        "-i",
        ROLE[args.role]["interface"],
        "-nn",
        "-s",
        "128",
        "-c",
        "2048",
        "-w",
        str(root / "evidence/capture.pcap"),
        "udp",
        "port",
        listen_port,
    ]
    run_recorded_command(root, "capture", argv, timeout=args.seconds + 15)
    print(json.dumps({"status": "capture-complete", "role": args.role}))


def client(args: argparse.Namespace) -> None:
    root = canonical_run_root(args.run_id, args.role)
    owner = load_owner(
        root, args.run_id, args.role, args.commit, args.claim_sha256
    )
    artifact_check(root, owner)
    if not (root / "applied.json").is_file():
        stop("client-state", 79)
    mode = args.traffic_mode
    argv = [
        TOOLS["python"],
        str(root / "traffic.py"),
        mode,
        "--address",
        ROLE[args.role]["peer_address"],
        "--port",
        "45982",
    ]
    if mode == "udp-client":
        argv += ["--seconds", str(args.seconds), "--bits-per-second", str(args.bits_per_second)]
    else:
        argv += ["--bytes", str(args.bytes)]
    output = command(argv, timeout=args.seconds + 15)
    print(output.decode("utf-8"), end="")


def ping_peer(args: argparse.Namespace) -> None:
    root = canonical_run_root(args.run_id, args.role)
    owner = load_owner(
        root, args.run_id, args.role, args.commit, args.claim_sha256
    )
    artifact_check(root, owner)
    if not (root / "applied.json").is_file():
        stop("ping-state", 79)
    output = command(
        [
            TOOLS["ping"],
            "-I",
            ROLE[args.role]["wg"],
            "-n",
            "-c",
            str(args.count),
            "-i",
            "1",
            "-W",
            "2",
            ROLE[args.role]["peer_address"],
        ],
        timeout=args.count + 15,
    )
    print(output.decode("utf-8"), end="")


def sample(args: argparse.Namespace) -> None:
    root = canonical_run_root(args.run_id, args.role)
    owner = load_owner(
        root, args.run_id, args.role, args.commit, args.claim_sha256
    )
    artifact_check(root, owner)
    spec = ROLE[args.role]
    transfer = command([TOOLS["wg"], "show", spec["wg"], "transfer"]).decode().strip().split("\t")
    handshake = command([TOOLS["wg"], "show", spec["wg"], "latest-handshakes"]).decode().strip().split("\t")
    if len(transfer) != 3 or len(handshake) != 2 or transfer[0] != handshake[0]:
        stop("wg-sample-shape", 79)
    status = json.loads(
        binary_command(
            root,
            [
                "status",
                "--config",
                str(root / "agent.yaml"),
                "--run-dir",
                str(root / "runtime"),
                "--state-dir",
                str(root / "state"),
            ],
        )
    )
    if not isinstance(status, dict):
        stop("status-shape", 79)
    dataplane = status.get("dataplane")
    stats = dataplane.get("stats", {}) if isinstance(dataplane, dict) else {}
    if not isinstance(stats, dict):
        stop("stats-shape", 79)
    error_names = (
        "egress_bad_type",
        "egress_bad_length",
        "ingress_bad_type",
        "ingress_bad_length",
        "checksum_error",
        "skb_load_error",
        "skb_store_error",
        "ingress_bad_checksum",
        "egress_bad_checksum",
    )
    result = {
        "role": args.role,
        "timestamp": int(time.time()),
        "peer_public_key": transfer[0],
        "wg_rx": int(transfer[1]),
        "wg_tx": int(transfer[2]),
        "latest_handshake": int(handshake[1]),
        "attachment_backend": spec["attachment_backend"],
        "rewrite_success": int(stats.get("egress_rewrite_ok", 0))
        + int(stats.get("ingress_rewrite_ok", 0)),
        "error_total": sum(int(stats.get(name, 0)) for name in error_names),
        "stats": stats,
    }
    print(json.dumps(result, sort_keys=True))


def export_evidence(args: argparse.Namespace) -> None:
    root = canonical_run_root(args.run_id, args.role)
    owner = load_owner(
        root, args.run_id, args.role, args.commit, args.claim_sha256
    )
    partial = not (root / "intent.json").exists()
    artifact_check(root, owner, allow_missing=partial)
    if not (root / "restored.json").is_file():
        stop("export-before-restore", 79)
    evidence = root / "evidence"
    encoded: dict[str, str] = {}
    total = 0
    if not evidence.exists():
        if not partial:
            stop("export-evidence-missing", 79)
        entries: list[os.DirEntry[str]] = []
    else:
        require_root_directory(evidence)
        entries = sorted(os.scandir(evidence), key=lambda item: item.name)
    for entry in entries:
        if (
            not KNOWN_EVIDENCE_RE.fullmatch(entry.name)
            or not entry.is_file(follow_symlinks=False)
        ):
            stop(f"export-foreign:{entry.name}", 79)
        opened = os.open(
            entry.path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
        )
        try:
            observed = os.fstat(opened)
            if (
                not stat.S_ISREG(observed.st_mode)
                or observed.st_uid != 0
                or observed.st_gid != 0
                or observed.st_nlink != 1
                or observed.st_size > 4 * 1024 * 1024
            ):
                stop(f"export-shape:{entry.name}", 79)
            data = os.pread(opened, observed.st_size, 0)
        finally:
            os.close(opened)
        total += len(data)
        if total > 16 * 1024 * 1024:
            stop("export-size", 79)
        encoded[entry.name] = base64.b64encode(data).decode("ascii")
    print(
        json.dumps(
            {
                "schema": "wg-mix-public-evidence-export-v1",
                "run_id": args.run_id,
                "role": args.role,
                "files": encoded,
            },
            sort_keys=True,
        )
    )


def read_link(name: str) -> dict[str, Any] | None:
    if not Path(f"/sys/class/net/{name}").exists():
        return None
    try:
        links = json.loads(
            command([TOOLS["ip"], "-j", "-d", "link", "show", "dev", name])
        )
    except ValueError:
        stop("restore-link-foreign", 79)
    if not isinstance(links, list) or len(links) != 1:
        stop("restore-link-foreign", 79)
    link = links[0]
    if not isinstance(link, dict) or link.get("ifname") != name:
        stop("restore-link-foreign", 79)
    return link


def pristine_unaliased_staging_link(name: str, link: dict[str, Any]) -> bool:
    linkinfo = link.get("linkinfo")
    flags = link.get("flags")
    if (
        "ifalias" in link
        or not isinstance(linkinfo, dict)
        or linkinfo.get("info_kind") != "wireguard"
        or not isinstance(flags, list)
        or any(not isinstance(flag, str) for flag in flags)
        or "UP" in flags
        or link.get("operstate") not in {"DOWN", "UNKNOWN"}
    ):
        return False
    try:
        addresses = json.loads(
            command([TOOLS["ip"], "-j", "address", "show", "dev", name])
        )
    except ValueError:
        return False
    return not (
        not isinstance(addresses, list)
        or len(addresses) != 1
        or not isinstance(addresses[0], dict)
        or addresses[0].get("addr_info") not in (None, [])
        or command([TOOLS["wg"], "show", name, "peers"]).strip()
        or command([TOOLS["wg"], "show", name, "listen-port"]).strip() != b"0"
        or command([TOOLS["wg"], "show", name, "fwmark"]).strip() != b"off"
    )


def classify_owned_link(
    root: Path, run_id: str, role: str, claim_sha256: str
) -> tuple[str | None, bool]:
    fixed_name = ROLE[role]["wg"]
    staging_name = staging_wg_name(claim_sha256, role)
    expected_alias = f"wg-mix-public-smoke:{run_id}:{role}"
    staging = read_link(staging_name)
    fixed = read_link(fixed_name)
    if staging is not None:
        staging_owned = staging.get("ifalias") == expected_alias
        if not staging_owned and not pristine_unaliased_staging_link(staging_name, staging):
            stop("restore-staging-link-foreign", 79)
        if (root / "applied.json").exists() or Path(
            f"/sys/fs/bpf/{root.name}"
        ).exists():
            stop("restore-staging-state", 79)
        if fixed is not None and fixed.get("ifalias") == expected_alias:
            stop("restore-link-duplicate", 79)
        return staging_name, fixed is not None
    if fixed is None:
        return None, False
    if fixed.get("ifalias") == expected_alias:
        return fixed_name, False
    if Path(f"/sys/fs/bpf/{root.name}").exists() or (root / "applied.json").exists():
        stop("restore-link-foreign", 79)
    return None, True


def restore(args: argparse.Namespace) -> None:
    root = canonical_run_root(args.run_id, args.role)
    owner = load_owner(
        root, args.run_id, args.role, args.commit, args.claim_sha256
    )
    partial = not (root / "intent.json").exists()
    artifact_check(root, owner, allow_missing=partial)
    if partial:
        if not (root / "restored.json").exists():
            write_new(
                root / "restored.json",
                (
                    json.dumps(
                        {
                            "status": "restored-partial-prepare",
                            "run_id": args.run_id,
                            "role": args.role,
                        },
                        sort_keys=True,
                    )
                    + "\n"
                ).encode(),
                0o600,
            )
        print(
            json.dumps(
                {
                    "status": "restored-partial-prepare",
                    "run_id": args.run_id,
                    "role": args.role,
                }
            )
        )
        return
    service_lock_fd = acquire_service_lock(root, exclusive=True)
    pin_path = Path(f"/sys/fs/bpf/{root.name}")
    owned_link, preserve_fixed = classify_owned_link(
        root, args.run_id, args.role, args.claim_sha256
    )
    fixed_name = ROLE[args.role]["wg"]
    staging_name = staging_wg_name(args.claim_sha256, args.role)
    if pin_path.exists() and (preserve_fixed or owned_link == staging_name):
        stop("restore-resource-collision", 79)
    if pin_path.exists():
        binary_command(
            root,
            [
                "detach",
                "--config",
                str(root / "agent.yaml"),
                "--run-dir",
                str(root / "runtime"),
                "--state-dir",
                str(root / "state"),
            ],
        )
    if owned_link is not None:
        command([TOOLS["ip"], "link", "delete", "dev", owned_link])
    if (
        pin_path.exists()
        or Path(f"/sys/class/net/{staging_name}").exists()
        or (
            Path(f"/sys/class/net/{fixed_name}").exists()
            and not preserve_fixed
        )
    ):
        stop("restore-postcondition", 79)
    if args.role == "public":
        baseline = probe(args.role).get("classic_tc_baseline")
        if not isinstance(baseline, dict) or not baseline.get("clean"):
            stop("restore-classic-tc-postcondition", 79)
    if not (root / "restored.json").exists():
        write_new(
            root / "restored.json",
            (
                json.dumps(
                    {
                        "status": "restored",
                        "run_id": args.run_id,
                        "role": args.role,
                        "preserved_foreign_fixed": preserve_fixed,
                    },
                    sort_keys=True,
                )
                + "\n"
            ).encode(),
            0o600,
        )
    os.close(service_lock_fd)
    print(json.dumps({"status": "restored", "run_id": args.run_id, "role": args.role}))


def purge(args: argparse.Namespace) -> None:
    root = canonical_run_root(args.run_id, args.role)
    owner = load_owner(
        root, args.run_id, args.role, args.commit, args.claim_sha256
    )
    partial = not (root / "intent.json").exists()
    artifact_check(root, owner, allow_missing=partial)
    if not (root / "restored.json").is_file():
        stop("purge-before-restore", 79)
    purge_service_fd = -1
    if not partial:
        purge_service_fd = acquire_service_lock(root, exclusive=True)
    if not partial:
        staging_name = staging_wg_name(args.claim_sha256, args.role)
        fixed = read_link(ROLE[args.role]["wg"])
        expected_alias = f"wg-mix-public-smoke:{args.run_id}:{args.role}"
        if (
            Path(f"/sys/class/net/{staging_name}").exists()
            or Path(f"/sys/fs/bpf/{root.name}").exists()
            or (fixed is not None and fixed.get("ifalias") == expected_alias)
        ):
            stop("purge-live-resource", 79)
    intent = root / "intent.json"
    if intent.exists():
        os.unlink(intent)
    evidence = root / "evidence"
    state_dir = root / "state"
    runtime_dir = root / "runtime"
    for directory, predicate in (
        (evidence, lambda name: KNOWN_EVIDENCE_RE.fullmatch(name) is not None),
        (state_dir, lambda name: name == "attach-state.json"),
        (
            runtime_dir,
            lambda name: name
            in {"lock", "daemon.lease", ".daemon-maintenance.gate"},
        ),
    ):
        if not directory.exists():
            continue
        require_root_directory(directory)
        for entry in os.scandir(directory):
            if not entry.is_file(follow_symlinks=False) or not predicate(entry.name):
                stop(f"purge-foreign:{directory.name}:{entry.name}", 79)
            os.unlink(entry.path)
        os.rmdir(directory)
    for entry in os.scandir(root):
        if entry.name not in KNOWN_ROOT_FILES or not entry.is_file(follow_symlinks=False):
            stop(f"purge-foreign:root:{entry.name}", 79)
    terminal_files = {"root-endpoint.py", "owner.json", "restored.json"}
    for name in sorted(KNOWN_ROOT_FILES - terminal_files - {"intent.json"}):
        path = root / name
        if path.exists():
            os.unlink(path)
    restored = root / "restored.json"
    if restored.exists():
        os.unlink(restored)
    os.unlink(root / "owner.json")
    os.unlink(root / "root-endpoint.py")
    os.rmdir(root)
    if purge_service_fd >= 0:
        os.close(purge_service_fd)
    print(json.dumps({"status": "purged", "run_id": args.run_id, "role": args.role}))


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "mode",
        choices=(
            "probe",
            "abort-unclaimed",
            "prepare",
            "apply",
            "server",
            "capture",
            "client",
            "ping",
            "sample",
            "export",
            "restore",
            "purge",
        ),
    )
    parser.add_argument("--role", choices=tuple(ROLE), required=True)
    parser.add_argument("--run-id")
    parser.add_argument("--commit")
    parser.add_argument("--script-sha256")
    parser.add_argument("--claim-sha256")
    parser.add_argument("--binary-source")
    parser.add_argument("--binary-sha256")
    parser.add_argument("--object-source")
    parser.add_argument("--object-sha256")
    parser.add_argument("--traffic-source")
    parser.add_argument("--traffic-sha256")
    parser.add_argument("--peer-public-key")
    parser.add_argument("--seconds", type=int, default=900)
    parser.add_argument("--traffic-mode", choices=("udp-client", "tcp-client"))
    parser.add_argument("--bits-per-second", type=int, default=384_000)
    parser.add_argument("--bytes", type=int, default=1_048_576)
    parser.add_argument("--count", type=int, default=900)
    args = parser.parse_args(argv)
    if args.mode == "probe":
        return args
    required = ("run_id", "commit")
    if any(not getattr(args, name) for name in required):
        stop("arguments", 64)
    if not COMMIT_RE.fullmatch(args.commit):
        stop("commit", 64)
    if args.mode == "prepare":
        prepare_required = (
            "script_sha256",
            "claim_sha256",
            "binary_source",
            "binary_sha256",
            "object_source",
            "object_sha256",
            "traffic_source",
            "traffic_sha256",
        )
        if any(not getattr(args, name) for name in prepare_required):
            stop("prepare-arguments", 64)
    if args.mode == "abort-unclaimed" and (
        not args.script_sha256 or not args.claim_sha256
    ):
        stop("abort-unclaimed-arguments", 64)
    if args.mode == "apply" and not args.peer_public_key:
        stop("apply-arguments", 64)
    if args.mode == "client" and not args.traffic_mode:
        stop("client-arguments", 64)
    if (
        not 1 <= args.seconds <= 1800
        or not 1 <= args.bits_per_second <= 1_000_000
        or not 1 <= args.bytes <= 8 * 1024 * 1024
        or not 1 <= args.count <= 1800
    ):
        stop("traffic-bounds", 64)
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.mode == "probe":
        print(json.dumps(probe(args.role), sort_keys=True))
    elif args.mode == "abort-unclaimed":
        abort_unclaimed(args)
    elif args.mode == "prepare":
        prepare(args)
    elif args.mode == "apply":
        apply_endpoint(args)
    elif args.mode == "server":
        start_server(args)
    elif args.mode == "capture":
        start_capture(args)
    elif args.mode == "client":
        client(args)
    elif args.mode == "ping":
        ping_peer(args)
    elif args.mode == "sample":
        sample(args)
    elif args.mode == "export":
        export_evidence(args)
    elif args.mode == "restore":
        restore(args)
    else:
        purge(args)
    return 0


if __name__ == "__main__":
    if os.geteuid() != 0 and len(sys.argv) > 1 and sys.argv[1] != "probe":
        stop("root-required", 77)
    raise SystemExit(main(sys.argv[1:]))
