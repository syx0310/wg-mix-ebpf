#!/usr/bin/env python3
"""Static safety contract for the v6 binder, controller, transport and stager."""

from __future__ import annotations

import pathlib
import re
import sys


def fail(message: str) -> None:
    raise SystemExit(message)


def read_regular(path_text: str) -> tuple[pathlib.Path, str]:
    path = pathlib.Path(path_text)
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        fail(f"input is not an absolute regular file: {path}")
    return path, path.read_text(encoding="utf-8")


def bash_function(payload: str, name: str) -> str:
    match = re.search(
        rf"(?ms)^{re.escape(name)}\(\) \{{\n(?P<body>.*?)^\}}\n", payload
    )
    if not match:
        fail(f"cannot isolate Bash function {name}")
    return match.group("body")


def bash_array(payload: str, name: str) -> str:
    match = re.search(
        rf"(?ms)^readonly -a {re.escape(name)}=\((?P<body>.*?)\)\n", payload
    )
    if not match:
        fail(f"cannot isolate Bash array {name}")
    return match.group("body").strip("\n")


def tcl_proc(payload: str, name: str) -> str:
    match = re.search(
        rf"(?ms)^proc {re.escape(name)} \{{[^}}]*\}} \{{\n(?P<body>.*?)^\}}\n",
        payload,
    )
    if not match:
        fail(f"cannot isolate Tcl procedure {name}")
    return match.group("body")


def python_function(payload: str, name: str) -> str:
    match = re.search(rf"(?m)^def {re.escape(name)}\(", payload)
    if not match:
        fail(f"cannot isolate embedded Python function {name}")
    start = match.start()
    following = re.search(
        r"(?m)^(?:def [A-Za-z_][A-Za-z0-9_]*\(|class [A-Za-z_][A-Za-z0-9_]*|try:\s*$)",
        payload[start + 1 :],
    )
    end = len(payload) if not following else start + 1 + following.start()
    return payload[start:end]


def tcl_return_words(payload: str, name: str) -> tuple[str, ...]:
    match = re.search(
        rf"(?ms)^proc {re.escape(name)} \{{[^\n]*\}} \{{\s*return \{{(.*?)\}}\s*\}}\n",
        payload,
    )
    if not match:
        fail(f"cannot isolate fixed Tcl list {name}")
    return tuple(match.group(1).split())


def ordered(body: str, literals: tuple[str, ...], contract: str) -> None:
    remaining = body
    for literal in literals:
        position = remaining.find(literal)
        if position < 0:
            fail(f"{contract} is missing ordered literal {literal!r}")
        remaining = remaining[position + len(literal) :]


def manifest_reader_keys(payload: str, function_name: str) -> tuple[str, ...]:
    body = bash_function(payload, function_name)
    return tuple(
        re.findall(r"(?m)^\s*read_manifest_field ([a-z0-9_]+) [A-Z_a-z0-9{}\"$-]+", body)
    )


def array_path_basenames(body: str) -> tuple[str, ...]:
    return tuple(re.findall(r'/([A-Za-z0-9_.-]+)"', body))


def main() -> None:
    if len(sys.argv) != 7:
        fail(
            "usage: test_controller_static.py BINDER CONTROLLER TRANSPORT "
            "ROOT_STAGER ROOT_MATRIX PROVISIONER"
        )
    binder_path, binder = read_regular(sys.argv[1])
    controller_path, controller = read_regular(sys.argv[2])
    transport_path, transport = read_regular(sys.argv[3])
    stager_path, stager = read_regular(sys.argv[4])
    matrix_path, matrix = read_regular(sys.argv[5])
    provisioner_path, provisioner = read_regular(sys.argv[6])
    fresh_path, fresh = read_regular(
        str(controller_path.with_name("root-fresh-verifier-gate.sh"))
    )
    hermetic_path, hermetic = read_regular(
        str(controller_path.with_name("test-hermetic-controller.sh"))
    )

    production = {
        binder_path.name: binder,
        controller_path.name: controller,
        transport_path.name: transport,
        stager_path.name: stager,
        fresh_path.name: fresh,
    }
    retire_id = "c8e41d73-2c690050ae1d-r1"
    predecessor_commit = "2c690050ae1d69dbd074acfd612faa2b80e29f8a"
    predecessor_manifest_sha = (
        "21f14e1f7e646649fdad864dce23dce2055585962d92bfaba6e71158372c1ebe"
    )
    retired_bundle_sha = (
        "5c53adec58363ec2ff51d9bd5dcd7e467874c839393178491c74b16a8c9f922c"
    )
    predecessor_local_package = (
        "/private/tmp/wg-mix-b82-v6-c8e41d73-4f2a9b61-2c690050ae1d"
    )
    predecessor_remote_package = "/home/siyixuan/wg-mix-ebpf-test/unpriv-4f2a9b61"
    retirement_constant_contracts = {
        controller_path.name: (
            f"readonly PREDECESSOR_COMMIT='{predecessor_commit}'",
            f"readonly PREDECESSOR_PACKAGE='{predecessor_local_package}'",
            'readonly PREDECESSOR_MANIFEST="${PREDECESSOR_PACKAGE}/package-manifest.v1"',
            f"readonly PREDECESSOR_MANIFEST_SHA256='{predecessor_manifest_sha}'",
        ),
        transport_path.name: (
            f'set ::RETIRE_ID "{retire_id}"',
            f'set ::PREDECESSOR_COMMIT "{predecessor_commit}"',
            f'    "{predecessor_manifest_sha}"',
            f'    "{predecessor_local_package}"',
            '    "/home/siyixuan/wg-mix-ebpf-test/retire-prestage-${::RETIRE_ID}.intake"',
            'set ::RETIREMENT_HOME_QROOT "/home/.wg-mix-ebpf-retirement-${::RETIRE_ID}"',
            'set ::RETIREMENT_AUTH_ROOT "${::RETIREMENT_HOME_QROOT}/authority"',
            "set ::RETIREMENT_AUTH_MANIFEST \\",
            '    "${::RETIREMENT_AUTH_ROOT}/package-manifest.v1"',
            "set ::RETIREMENT_AUTH_SELF \\",
            '    "${::RETIREMENT_AUTH_ROOT}/prepare-stage-root.sh"',
            'set ::RETIREMENT_Q_INTAKE "${::RETIREMENT_HOME_QROOT}/intake"',
            'set ::RETIREMENT_Q_PACKAGE "${::RETIREMENT_HOME_QROOT}/package"',
            'set ::RETIREMENT_RUN_QROOT "/run/wg-mix-ebpf-retirement-${::RETIRE_ID}"',
            'set ::RETIREMENT_Q_BOOTSTRAP "${::RETIREMENT_RUN_QROOT}/bootstrap"',
            'set ::RETIREMENT_LOCK "${::RETIREMENT_RUN_QROOT}/retirement.v1.lock"',
            '    "${::RETIREMENT_RUN_QROOT}/retirement-complete.v1.pending"',
            '    "${::RETIREMENT_RUN_QROOT}/retirement-complete.v1"',
        ),
        stager_path.name: (
            f"readonly RETIRE_ID='{retire_id}'",
            f"readonly PREDECESSOR_COMMIT='{predecessor_commit}'",
            f"readonly PREDECESSOR_MANIFEST_SHA256='{predecessor_manifest_sha}'",
            'readonly RETIREMENT_USER_INTAKE="/home/siyixuan/wg-mix-ebpf-test/retire-prestage-${RETIRE_ID}.intake"',
            'readonly RETIREMENT_HOME_QROOT="/home/.wg-mix-ebpf-retirement-${RETIRE_ID}"',
            'readonly RETIREMENT_AUTH_ROOT="${RETIREMENT_HOME_QROOT}/authority"',
            'readonly RETIREMENT_AUTH_MANIFEST="${RETIREMENT_AUTH_ROOT}/package-manifest.v1"',
            'readonly RETIREMENT_AUTH_SELF="${RETIREMENT_AUTH_ROOT}/prepare-stage-root.sh"',
            'readonly RETIREMENT_Q_INTAKE="${RETIREMENT_HOME_QROOT}/intake"',
            'readonly RETIREMENT_Q_PACKAGE="${RETIREMENT_HOME_QROOT}/package"',
            'readonly RETIREMENT_RUN_QROOT="/run/wg-mix-ebpf-retirement-${RETIRE_ID}"',
            'readonly RETIREMENT_Q_BOOTSTRAP="${RETIREMENT_RUN_QROOT}/bootstrap"',
            'readonly RETIREMENT_LOCK="${RETIREMENT_RUN_QROOT}/retirement.v1.lock"',
            'readonly RETIREMENT_RECEIPT_PENDING="${RETIREMENT_RUN_QROOT}/retirement-complete.v1.pending"',
            'readonly RETIREMENT_RECEIPT_FINAL="${RETIREMENT_RUN_QROOT}/retirement-complete.v1"',
        ),
    }
    retirement_sources = {
        controller_path.name: controller,
        transport_path.name: transport,
        stager_path.name: stager,
    }
    for name, required_constants in retirement_constant_contracts.items():
        payload = retirement_sources[name]
        for literal in required_constants:
            if payload.count(literal) != 1:
                fail(f"{name} retirement constant is not unique and fixed: {literal!r}")
        literal_digests = re.findall(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", payload)
        if literal_digests != [predecessor_manifest_sha]:
            fail(f"{name} does not carry the sole predecessor-manifest digest literal")
        if retired_bundle_sha in payload:
            fail(f"{name} hard-codes the retired bundle digest outside its manifest")

    executable_rmdir_pattern = r"(?<![A-Za-z0-9_-])rmdir(?=\s|\()"
    if re.search(executable_rmdir_pattern, "no-unlink-no-rmdir-no-copy-fallback"):
        fail("executable rmdir matcher rejects the exact retention receipt literal")
    for executable_rmdir in (
        "rmdir /fixed/path",
        "/usr/bin/rmdir /fixed/path",
        'os.rmdir("/fixed/path")',
    ):
        if not re.search(executable_rmdir_pattern, executable_rmdir):
            fail("executable rmdir matcher no longer rejects an executable form")
    forbidden_patterns = (
        r"\brm\s+-[^\n]*r",
        executable_rmdir_pattern,
        r"\bfind\b[^\n]*-delete",
        r"\bxargs\b[^\n]*\brm\b",
        r"\brsync\b[^\n]*--delete",
        r"\bchroot\b",
        r"\bnsenter\b",
        r"\b(?:docker|podman)\b",
        r"(?:^|\s)eval(?:\s|$)",
        r"(?:^|\s)(?:sh|bash)\s+-c(?:\s|$)",
        r"(?:^|\s)trap(?:\s|$)",
        r"/proc/1/root",
        r"(?:^|\s)-v\s+/:/host(?:\s|$)",
        r"(?:^|\s)--privileged(?:\s|$)",
    )
    for name, payload in production.items():
        for pattern in forbidden_patterns:
            if re.search(pattern, payload, re.MULTILINE):
                fail(f"{name} contains prohibited executable pattern: {pattern}")

    for name, payload in {
        binder_path.name: binder,
        controller_path.name: controller,
        stager_path.name: stager,
    }.items():
        if re.search(r"(?:^|\s)/(?:usr/)?bin/(?:ssh|scp)(?:\s|$)", payload):
            fail(f"{name} directly invokes SSH/SCP outside Expect")

    manifest_prefix = (
        "format",
        "run_id",
        "package_id",
        "integration_ref",
        "integration_commit",
        "bundle_name",
        "bundle_sha256",
        "history_verification",
        "history_commit_count",
        "history_roots_sha256",
        "history_objects_sha256",
        "wg_state",
        "wg_interface",
        "wg_local_address",
        "wg_peer_address",
        "local_repository",
        "local_package_dir",
        "remote_package_dir",
        "remote_source",
        "target_user",
        "target_host",
        "target_hostname",
        "target_kernel",
        "target_machine_id",
        "target_interface",
        "peer_address",
        "peer_port",
        "soak_seconds",
        "session_seconds",
        "physical_nic_forward_authority",
        "physical_interface_lock",
        "legacy_matrix_mode",
        "realnic_profile",
        "realnic_traffic_seconds",
    )
    package_identity_names = (
        "root-matrix-n-r.sh",
        "check-realhost-iperf.py",
        "test-hermetic-matrix.sh",
        "test_matrix_static.py",
        "checksum-module-lease.sh",
        "root-fresh-verifier-gate.sh",
        "test-hermetic-fresh-verifier-gate.sh",
        "test_fresh_verifier_gate_static.py",
        "prepare-stage-root.sh",
        "realnic_acceptance.py",
        "test_realnic_acceptance.py",
        "test_realnic_acceptance_static.py",
        "provision-ubuntu-test-host.sh",
    )
    staged_identity_names = (
        "root-veth-n-r.sh",
        "test-hermetic-veth-runner.sh",
        "test_veth_runner_static.py",
        "controller-seam.sh",
        "root-routed-veth-n-r.sh",
        "test-hermetic-routed-veth-harness.sh",
        "test_routed_veth_harness_static.py",
    )
    identity_names = (
        "bind-final-package.sh",
        "controller.sh",
        "locked-transport.exp",
        *package_identity_names,
        *staged_identity_names,
    )
    identity_keys = tuple(name.replace("-", "_").replace(".", "_") for name in identity_names)
    expected_manifest_keys = manifest_prefix + tuple(
        f"{key}_{suffix}"
        for key in identity_keys
        for suffix in ("path", "blob", "sha256")
    )
    if len(expected_manifest_keys) != 103 or len(set(expected_manifest_keys)) != 103:
        fail("test fixture no longer defines one unique package-v4/103 schema")

    package_array = bash_array(binder, "PACKAGE_PATHS")
    staged_array = bash_array(binder, "STAGED_IDENTITY_PATHS")
    identity_array = bash_array(binder, "IDENTITY_PATHS")
    if array_path_basenames(package_array) != package_identity_names:
        fail("binder package identities do not match the exact package-v4 schema")
    if array_path_basenames(staged_array) != staged_identity_names:
        fail("binder staged identities do not match the exact package-v4 schema")
    expected_identity_lines = (
        '"${REPOSITORY_PATH_FROM_ROOT}/bind-final-package.sh"',
        '"${REPOSITORY_PATH_FROM_ROOT}/controller.sh"',
        '"${REPOSITORY_PATH_FROM_ROOT}/locked-transport.exp"',
        '"${PACKAGE_PATHS[@]}"',
        '"${STAGED_IDENTITY_PATHS[@]}"',
    )
    if tuple(line.strip() for line in identity_array.splitlines()) != expected_identity_lines:
        fail("binder identity expansion is not the exact fixed package/staged sequence")
    bind_body = bash_function(binder, "bind_package")
    path_key_body = bash_function(binder, "path_key")
    ordered(
        path_key_body,
        (
            'local name="${1##*/}"',
            'name="${name//-/_}"',
            'name="${name//./_}"',
            "printf '%s\\n' \"${name}\"",
        ),
        "binder identity path-key mapping",
    )
    binder_prefix = tuple(
        re.findall(r"(?m)^\s*manifest_line ([a-z0-9_]+) ", bind_body)
    )
    if binder_prefix != manifest_prefix:
        fail("binder package-v4 manifest prefix changed order or cardinality")
    ordered(
        bind_body,
        (
            'for path in "${IDENTITY_PATHS[@]}"; do',
            'key="$(path_key "${path}")"',
            'manifest_line "${key}_path" "${path}"',
            'manifest_line "${key}_blob" "${blob}"',
            'manifest_line "${key}_sha256" "${sha}"',
        ),
        "binder manifest identity expansion",
    )
    if tuple(
        re.findall(r'manifest_line "\$\{key\}_([a-z0-9]+)"', bind_body)
    ) != ("path", "blob", "sha256"):
        fail("binder identity loop does not emit exactly path/blob/sha256")
    if "printf '%s\\t%s\\n' \"$1\" \"$2\"" not in bash_function(
        binder, "manifest_line"
    ):
        fail("binder manifest_line no longer emits exactly one newline-terminated field")
    binder_manifest_keys = binder_prefix + tuple(
        f"{key}_{suffix}"
        for key in identity_keys
        for suffix in ("path", "blob", "sha256")
    )

    transport_load = tcl_proc(transport, "load_manifest")
    expected_keys_match = re.search(
        r"(?ms)^\s*set expected_keys \{\n(?P<body>.*?)^\s*\}\n\s*set channel ",
        transport_load,
    )
    if not expected_keys_match:
        fail("cannot isolate transport package-v4 expected_keys")
    transport_manifest_keys = tuple(expected_keys_match.group("body").split())
    consumer_keys = {
        "binder": binder_manifest_keys,
        "controller": manifest_reader_keys(controller, "load_manifest"),
        "root-stager": manifest_reader_keys(stager, "load_manifest"),
        "root-fresh": manifest_reader_keys(fresh, "load_manifest_once"),
        "transport": transport_manifest_keys,
    }
    for name, keys in consumer_keys.items():
        if keys != expected_manifest_keys or len(keys) != 103 or len(set(keys)) != 103:
            fail(f"{name} does not consume the exact unique package-v4/103 key sequence")
    version_contracts = (
        (
            "binder",
            bind_body,
            "manifest_line format wg-mix-ebpf-b82-v6-package-v4",
        ),
        (
            "controller",
            bash_function(controller, "verify_manifest_contract"),
            '"${FORMAT}" == \'wg-mix-ebpf-b82-v6-package-v4\'',
        ),
        (
            "root-stager",
            bash_function(stager, "validate_manifest"),
            '"${FORMAT}" == \'wg-mix-ebpf-b82-v6-package-v4\'',
        ),
        (
            "root-fresh",
            bash_function(fresh, "validate_snapshot_contract"),
            '"${FORMAT}" == \'wg-mix-ebpf-b82-v6-package-v4\'',
        ),
        (
            "transport",
            tcl_proc(transport, "validate_manifest_values"),
            '[dict get $values format] ne "wg-mix-ebpf-b82-v6-package-v4"',
        ),
    )
    for name, body, version_literal in version_contracts:
        if body.count(version_literal) != 1:
            fail(f"{name} does not bind exactly one package-v4 format value")

    bash_eof_contracts = (
        (
            "controller",
            bash_function(controller, "load_manifest"),
            'if IFS= read -r unexpected <&3 || [[ -n "${unexpected}" ]]; then',
        ),
        (
            "root-stager",
            bash_function(stager, "load_manifest"),
            'if IFS= read -r unexpected <&3 || [[ -n "${unexpected}" ]]; then',
        ),
        (
            "root-fresh",
            bash_function(fresh, "load_manifest_once"),
            'if IFS= read -r -u "${MANIFEST_FD}" unexpected || [[ -n "${unexpected}" ]]; then',
        ),
    )
    for name, body, eof_guard in bash_eof_contracts:
        if body.count("local unexpected=''") != 1 or body.count(eof_guard) != 1:
            fail(
                f"{name} EOF guard does not reject a 104th line both with and without newline"
            )
    nul_helpers = tuple(
        bash_function(payload, "require_manifest_fd_without_nul")
        for payload in (controller, stager, fresh)
    )
    if len(set(nul_helpers)) != 1:
        fail("Bash manifest consumers do not share one identical NUL precheck")
    nul_helper = nul_helpers[0]
    ordered(
        nul_helper,
        (
            "/usr/bin/python3 -B -I -c '",
            "descriptor = int(sys.argv[1])",
            "offset = 0",
            "chunk = os.pread(descriptor, 65536, offset)",
            'if b"\\0" in chunk:',
            "raise SystemExit(65)",
            "offset += len(chunk)",
            "except (OSError, ValueError):",
            "raise SystemExit(66)",
        ),
        "same-FD manifest NUL precheck",
    )
    if re.search(r"os\.(?:read|lseek)\(|print\(|sys\.(?:stdout|stderr)", nul_helper):
        fail("manifest NUL helper consumes the parser FD or emits file bytes")
    for name, load, open_fd, scan_fd in (
        ("controller", bash_function(controller, "load_manifest"), 'exec 3<"${MANIFEST}"', "require_manifest_fd_without_nul 3"),
        ("root-stager", bash_function(stager, "load_manifest"), 'exec 3<"${MANIFEST}"', "require_manifest_fd_without_nul 3"),
        ("root-fresh", bash_function(fresh, "load_manifest_once"), 'exec {MANIFEST_FD}<"${SNAPSHOT_MANIFEST}"', 'require_manifest_fd_without_nul "${MANIFEST_FD}"'),
    ):
        prefix = load[: load.index("read_manifest_field format FORMAT")]
        ordered(prefix, (open_fd, scan_fd, "rc=$?", 'return "${rc}"'), f"{name} NUL gate")
        if prefix.count(scan_fd) != 1:
            fail(f"{name} does not scan its already-open parser FD exactly once")
    required_transport_eof = (
        'set payload [read $channel]',
        '![string match "*\\n" $payload]',
        'set lines [split [string range $payload 0 end-1] "\\n"]',
        'if {[llength $lines] != [llength $expected_keys]}',
    )
    ordered(transport_load, required_transport_eof, "transport strict manifest EOF")
    if 'string trimright $payload "\\n"' in transport_load:
        fail("transport trims arbitrary trailing newlines before its exact line-count check")

    required_binder = (
        "--source-ref",
        "--commit",
        'actual_commit="$(git_checked rev-parse --verify "${SOURCE_REF}^{commit}")"',
        '[[ "${actual_commit}" == "${COMMIT}" ]]',
        'source_ref_after="$(git_checked rev-parse --verify "${SOURCE_REF}^{commit}")"',
        "git_checked bundle create",
        "git_checked bundle verify",
        "git_checked rev-parse --is-shallow-repository",
        "[[ \"${shallow_state}\" == 'false' ]]",
        "isolated-unbundle-rev-list-fsck-v1",
        "bundle unbundle",
        "rev-list --parents --objects --missing=print",
        "fsck --full --strict --no-dangling",
        "manifest_line history_commit_count",
        "manifest_line history_roots_sha256",
        "manifest_line history_objects_sha256",
        "wg-mix-ebpf-b82-v6-package-v4",
        "manifest_line wg_state",
        "absent)",
        '"${WG_INTERFACE}" == \'absent\'',
        "prepare-stage-root.sh",
        "scripts/provision-ubuntu-test-host.sh",
        "locked-transport.exp",
        "controller.sh",
        "checksum-module-lease.sh",
        "root-fresh-verifier-gate.sh",
        "test-hermetic-fresh-verifier-gate.sh",
        "test_fresh_verifier_gate_static.py",
        "manifest_line physical_nic_forward_authority realnic-acceptance-v1",
        'manifest_line physical_interface_lock "${PHYSICAL_INTERFACE_LOCK}"',
        "manifest_line legacy_matrix_mode retired",
        "manifest_line realnic_profile acceptance",
        "manifest_line realnic_traffic_seconds 30",
        '"${REALNIC_PATH_FROM_ROOT}/realnic_acceptance.py"',
        '"${REALNIC_PATH_FROM_ROOT}/test_realnic_acceptance.py"',
        '"${REALNIC_PATH_FROM_ROOT}/test_realnic_acceptance_static.py"',
        'readonly -a STAGED_IDENTITY_PATHS=(',
        '"${REPOSITORY_PATH_FROM_ROOT}/root-veth-n-r.sh"',
        '"${ROUTED_PATH_FROM_ROOT}/controller-seam.sh"',
        '"${ROUTED_PATH_FROM_ROOT}/root-routed-veth-n-r.sh"',
    )
    for literal in required_binder:
        if literal not in binder:
            fail(f"binder contract is missing {literal!r}")
    if re.search(r"rev-parse(?:\s+--verify)?\s+HEAD", binder):
        fail("binder defaults or resolves the package from HEAD")
    if binder.index("require_full_repository || fail 'repository-became-shallow'") > binder.index(
        "git_checked bundle create"
    ):
        fail("binder checks shallow state after bundle creation")
    if re.search(r"\b(?:apt|apt-get)\b", binder):
        fail("binder contains package installation")

    required_controller = (
        "B82_V6_LEGACY_MATRIX_RETIRED controller_entries=0 historical_recovery=frozen-original-package-before-final-staging",
        "verify-package|plan|preflight|prepare|provision-apply",
        "B82_V6_CONTROLLER_PACKAGE_VERIFIED",
        "identity-wg-interfaces",
        "identity-netns",
        "identity-driver",
        "tool-go tool-clang tool-llvm tool-bpftool tool-make tool-gcc tool-iperf3",
        "kernel-btf kernel-bpffs kernel-headers",
        "/usr/bin/expect",
        "--manifest-sha256",
        "--credential-path",
        "credential_read=0 network_operations=0 mutations=0",
        "BASE_IDENTITY_OPERATIONS",
        "POSTFLIGHT_OPERATIONS",
        "BOOTSTRAP_CREATE_OPERATIONS",
        "bootstrap-absent bootstrap-not-symlink bootstrap-create bootstrap-root-readlink bootstrap-root-stat",
        "bootstrap-install-provisioner bootstrap-install-stager",
        "BOOTSTRAP_ROOT_VERIFY_OPERATIONS=(bootstrap-root-readlink bootstrap-root-stat)",
        "PROVISIONER_VERIFY_OPERATIONS",
        "STAGER_VERIFY_OPERATIONS",
        "STAGE_OPERATIONS=(stage-snapshot stage-plan stage-run)",
        "run_operation execute prepare",
        "run_operation execute provision-apply",
        "fresh-plan | fresh-run | fresh-restore",
        "veth-plan | veth-run | veth-restore",
        "routed-plan | routed-run | routed-restore",
        "for operation in fresh-plan fresh-run fresh-restore",
        "run_operation execute fresh-plan",
        "run_operation execute fresh-run",
        "run_operation execute fresh-restore",
        "run_operation execute veth-plan",
        "run_operation execute veth-run",
        "run_operation execute veth-restore",
        "run_operation execute routed-plan",
        "run_operation execute routed-run",
        "run_operation execute routed-restore",
        "CHECKSUM_MODULE_LEASE_SH_PATH",
        "ROOT_FRESH_VERIFIER_GATE_SH_PATH",
        "realnic-plan | realnic-run | realnic-restore",
        "transport capture realnic-plan",
        "capture-local",
        "realnic-plan.${APPROVED_PLAN_SHA256}.json",
        "verify_local_approved_plan",
        "scp-realnic-approved-plan verify-sha-realnic-approved-plan",
        "verify-stat-realnic-approved-plan stage-realnic-plan-snapshot realnic-run",
        "stage-realnic-plan-verify",
        "run_operation execute realnic-run",
        "run_operation execute realnic-restore",
        "legacy_forward=retired",
    )
    for literal in required_controller:
        if literal not in controller:
            fail(f"controller contract is missing {literal!r}")
    if re.search(r"\b(?:apt|apt-get)\b", controller):
        fail("controller contains an implicit package installation path")
    if "open ${CREDENTIAL" in controller or "<\"${CREDENTIAL" in controller:
        fail("controller directly reads the credential file")
    if re.search(r"--approved-plan(?!-sha256)", controller):
        fail("controller exposes the removed public approved-plan path argument")

    approved_operations = (
        "scp-realnic-approved-plan",
        "verify-sha-realnic-approved-plan",
        "verify-stat-realnic-approved-plan",
        "stage-realnic-plan-snapshot",
        "realnic-run",
        "stage-realnic-plan-verify",
        "realnic-restore",
    )
    controller_transport = bash_function(controller, "transport")
    approved_case = re.search(
        r'(?ms)case "\$\{operation\}" in\s*(?P<operations>.*?)\)\s*'
        r'transport_approved_sha256="\$\{APPROVED_PLAN_SHA256\}"',
        controller_transport,
    )
    if not approved_case:
        fail("cannot isolate controller approved-plan digest operation case")
    controller_approved_operations = tuple(
        re.findall(r"[a-z][a-z0-9-]+", approved_case.group("operations"))
    )
    if controller_approved_operations != approved_operations:
        fail("controller does not pass the digest for exactly seven approved operations")
    if (
        controller_transport.count("transport_approved_sha256='none'") != 1
        or controller_transport.count(
            'transport_approved_sha256="${APPROVED_PLAN_SHA256}"'
        )
        != 1
    ):
        fail("controller approved-plan digest default or sole override changed")
    ordered(
        controller_transport,
        (
            '--manifest "${MANIFEST}"',
            '--manifest-sha256 "${MANIFEST_SHA256}"',
            '--credential-path "${SUPPLIED_CREDENTIAL_PATH}"',
            '--action "${action}"',
            '--operation "${operation}"',
            '--approved-plan-sha256 "${transport_approved_sha256}"',
        ),
        "controller digest-only transport argv",
    )

    expected_stale_operations = (
        "stale-package-root",
        "stale-bootstrap-root",
        "stale-alternate-bootstrap-root",
        "stale-stage-root",
        "stale-fresh-root",
        "stale-standalone-root",
        "stale-routed-evidence-root",
        "stale-realnic-run-roots",
        "stale-realnic-interface-leases",
        "stale-veth-wgc8e41a",
        "stale-veth-wgc8e41b",
        "stale-veth-wga19f7a",
        "stale-veth-wga19f7b",
        "stale-veth-wg5b8d3a",
        "stale-veth-wg5b8d3b",
        "stale-pin-fresh",
        "stale-pin-standalone",
        "stale-pin-legacy-tcx",
        "stale-pin-legacy-nic-original",
        "stale-pin-legacy-nic-all-on",
        "stale-pin-legacy-nic-all-off",
        "stale-pin-legacy-nic-tx-path",
        "stale-pin-legacy-nic-rx-path",
        "stale-pin-legacy-nic-mtu1492",
        "stale-pin-legacy-nic-mtu1500",
        "stale-pin-legacy-nic-soak",
        "stale-checksum-module",
        "stale-checksum-module-btf",
        "stale-checksum-module-lock",
        "stale-physical-interface-lock",
    )
    actual_stale_operations = tuple(
        bash_array(controller, "PREPARE_NEW_STALE_OPERATIONS").split()
    )
    if (
        actual_stale_operations != expected_stale_operations
        or len(actual_stale_operations) != 30
        or len(set(actual_stale_operations)) != 30
    ):
        fail("PREPARE_NEW_STALE_OPERATIONS is not the exact ordered 30-item tuple")
    stale_gate = bash_function(controller, "run_prepare_new_stale_gate")
    ordered(
        stale_gate,
        (
            'local total="${#PREPARE_NEW_STALE_OPERATIONS[@]}"',
            'for operation in "${PREPARE_NEW_STALE_OPERATIONS[@]}"; do',
            "((ordinal += 1))",
            'id="${operation#stale-}"',
            'run_operation "${action}" "${operation}"',
            "rc=$?",
            "B82_V6_STALE_ITEM_V1",
            "B82_V6_STALE_SUMMARY_V1",
        ),
        "prepare-new stale gate",
    )
    if stale_gate.count('run_operation "${action}" "${operation}"') != 1:
        fail("prepare-new stale gate does not issue exactly one ordered call per tuple item")
    if (
        stale_gate.count("B82_V6_STALE_ITEM_V1") != 2
        or stale_gate.count("B82_V6_STALE_SUMMARY_V1") != 2
    ):
        fail("prepare-new stale gate does not emit exact stop/success item summaries")
    stale_calls = tuple(
        re.findall(r"(?m)^\s*run_prepare_new_stale_gate (plan|execute)(?: \|\| return \$\?)?$", controller)
    )
    if stale_calls != ("plan", "execute"):
        fail("prepare-new stale gate call sites or action order changed")
    ordered(
        bash_function(controller, "plan_all"),
        (
            'for operation in "${BASE_IDENTITY_OPERATIONS[@]}"; do',
            "run_prepare_new_stale_gate plan || return $?",
            "for operation in package-parent-stat package-mkdir; do",
        ),
        "plan prepare-new stale gate",
    )
    controller_transactions = {
        "execute_prepare": ("run_operation execute prepare",),
        "execute_provision_apply": ("run_operation execute provision-apply",),
        "execute_realnic_run": (
            "verify_local_approved_plan || return $?",
            "run_operation execute realnic-run",
        ),
        "execute_realnic_restore": ("run_operation execute realnic-restore",),
    }
    for name, expected in controller_transactions.items():
        lines = tuple(
            line.strip()
            for line in bash_function(controller, name).splitlines()
            if line.strip()
        )
        if lines != expected:
            fail(f"controller {name} is not one fixed high-level transaction")
    for mode in (
        "fresh-plan",
        "fresh-run",
        "fresh-restore",
        "veth-plan",
        "veth-run",
        "veth-restore",
        "routed-plan",
        "routed-run",
        "routed-restore",
    ):
        if not re.search(
            rf"{mode}\)\s+run_operation execute {mode}", controller, re.MULTILINE
        ):
            fail(f"controller {mode} is not an independent fixed operation")
    for retired in ("matrix-plan", "matrix-run", "matrix-restore-", "--restore-cell"):
        if retired in controller:
            fail(f"controller still exposes retired physical-NIC mode {retired}")
    if re.search(r"(?:^|[| {])restore(?:[| )}]|$)", controller):
        fail("controller still exposes the legacy top-level restore mode")
    if "hermetic-realnic-" in controller or "hermetic-realnic-" in transport:
        fail("controller/transport runs realNIC tests from the flat package copy")
    literal_executes = re.findall(r"run_operation execute ([a-z][a-z0-9-]+)", controller)
    allowed_executes = {
        "prepare", "provision-apply", "realnic-run", "realnic-restore",
        "fresh-plan", "fresh-run", "fresh-restore", "veth-plan", "veth-run",
        "veth-restore", "routed-plan", "routed-run", "routed-restore",
        "retire-prestage-2c690050", "verify-retirement",
    }
    if set(literal_executes) != allowed_executes or len(literal_executes) != len(allowed_executes):
        fail("controller retains direct primitive mutation sequencing")
    controller_main = bash_function(controller, "main")
    controller_retirement_executes = tuple(
        re.findall(
            r"run_operation execute (retire-prestage-2c690050|verify-retirement)",
            controller_main,
        )
    )
    if controller_retirement_executes != (
        "retire-prestage-2c690050",
        "verify-retirement",
    ):
        fail("controller does not expose exactly one retirement mutation and verification")
    parse_arguments = bash_function(controller, "parse_arguments")
    if parse_arguments.count(
        "retire-prestage-2c690050 | verify-retirement) ;;"
    ) != 1:
        fail("controller retirement mode parser is not the exact two-mode surface")
    if "retire-raw-" in controller or re.search(
        r"run_operation execute (?:retire|verify-retirement)[a-z0-9-]+",
        controller_main.replace(
            "run_operation execute retire-prestage-2c690050", ""
        ).replace("run_operation execute verify-retirement", ""),
    ):
        fail("controller exposes a private retirement primitive")
    predecessor_authority = controller[
        controller.index("verify_predecessor_manifest_contract() {") :
        controller.index("\n}\n\nverify_retirement_local_authority() {")
    ]
    for literal in (
        '[[ -f "${PREDECESSOR_MANIFEST}" && ! -L "${PREDECESSOR_MANIFEST}" ]]',
        'sha256_file "${PREDECESSOR_MANIFEST}"',
        'canonical_package="$(CDPATH=\'\' cd -- "${PREDECESSOR_PACKAGE}" && pwd -P)"',
        "/usr/bin/python3 -B -I -c '",
        'flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)',
        "metadata = os.fstat(descriptor)",
        "named = os.stat(path, follow_symlinks=False)",
        "(metadata.st_dev, metadata.st_ino) != (named.st_dev, named.st_ino)",
        "hashlib.sha256(payload).hexdigest() != expected_sha",
        '"integration_commit": expected_commit',
        '"local_package_dir": expected_package',
        f'"remote_package_dir": "{predecessor_remote_package}"',
        'for key in ("bundle_sha256", "prepare_stage_root_sh_sha256",',
        '"${PREDECESSOR_MANIFEST}" "${PREDECESSOR_MANIFEST_SHA256}"',
        '"${PREDECESSOR_COMMIT}" "${PREDECESSOR_PACKAGE}"',
    ):
        if predecessor_authority.count(literal) != 1:
            fail(f"controller predecessor authority is missing exact gate {literal!r}")
    local_retirement_authority = bash_function(
        controller, "verify_retirement_local_authority"
    )
    ordered(
        local_retirement_authority,
        (
            "verify_predecessor_manifest_contract || return $?",
            "B82_V6_RETIREMENT_LOCAL_AUTHORITY",
            "current_manifest_sha256=%s current_commit=%s",
            "predecessor_commit=%s predecessor_manifest_sha256=%s",
            "credential_read=0 network_operations=0",
        ),
        "controller retirement local authority",
    )
    if local_retirement_authority.count("verify_predecessor_manifest_contract") != 1:
        fail("controller retirement modes do not share one predecessor authority gate")
    ordered(
        controller_main,
        (
            'parse_arguments "$@"',
            "verify_manifest_contract || fail 'manifest-contract' $?",
            "derive_approved_plan_path || fail 'approved-plan-binding' $?",
            "retire-prestage-2c690050 | verify-retirement)",
            "verify_retirement_local_authority || fail 'retirement-local-authority' $?",
            "run_operation execute retire-prestage-2c690050",
            "run_operation execute verify-retirement",
        ),
        "controller pre-transport current and predecessor authority",
    )
    if (
        controller_main.count("verify_manifest_contract") != 1
        or controller_main.count("verify_retirement_local_authority") != 1
    ):
        fail("controller duplicates or bypasses retirement pre-transport authority")
    verify_arm = re.search(
        r"(?ms)^\s*verify-package\)\n(.*?)^\s*;;$", controller_main
    )
    if (
        not verify_arm
        or "B82_V6_CONTROLLER_PACKAGE_VERIFIED" not in verify_arm.group(1)
        or any(word in verify_arm.group(1) for word in ("run_operation", "transport "))
    ):
        fail("controller verify-package seam is not read-only")

    required_transport = (
        'set action [lindex $argv 7]',
        'if {$action eq "plan"}',
        "credential_read=0 network_operations=0",
        'if {[catch {open $credential_path r} credential_file]}',
        'send -i $child_id -- "$password\\r"',
        'spawn -noecho {*}$spawn_argv',
        "B82_V6_TRANSPORT_EXECUTE operation=$operation",
        "credential_in_argv=0",
        "/usr/bin/ssh",
        "/usr/bin/scp",
        "StrictHostKeyChecking=yes",
        "CheckHostIP=yes",
        "ClearAllForwardings=yes",
        "ForwardAgent=no",
        "ForwardX11=no",
        "ProxyCommand=none",
        "ControlMaster=no",
        "identity-wg-interfaces",
        "contains:go1.26.0",
        "contains:21.1.8",
        "/usr/sbin/bpftool -V",
        "contains:v7.7.0",
        "contains:GNU Make 4.4.1",
        "set assertion empty",
        "/usr/bin/test -r /sys/kernel/btf/vmlinux",
        "/usr/bin/findmnt --noheadings --raw --output FSTYPE,TARGET --target /sys/fs/bpf",
        "controller-shellcheck",
        "hermetic-fresh",
        "proc fresh_remote_argv",
        "fresh-plan - fresh-run - fresh-restore",
        "proc veth_remote_argv",
        "veth-plan - veth-run - veth-restore",
        "proc routed_remote_argv",
        "routed-plan - routed-run - routed-restore",
        "proc realnic_remote_argv",
        "realnic-plan - realnic-run - realnic-restore",
        "/usr/bin/python3 -B -I",
        "realnic-plan-snapshot",
        "realnic-plan-verify",
        "scp-realnic-approved-plan verify-sha-realnic-approved-plan",
        "verify-stat-realnic-approved-plan",
        "/run/wg-mix-ebpf-source-bootstrap-c8e41d73/realnic-approved-plan.json",
        "proc capture_child_payload",
        "capture-payload-frame",
        "operation_requires_approved_sha",
        "proc transaction_operation",
        "proc read_only_operation",
        "proc require_controller_verifier_authority",
        "proc execute_controller_package_verifier",
        "proc require_transaction_local_authority",
        "proc execute_transaction",
        "B82_V6_TRANSPORT_TRANSACTION_START",
        "B82_V6_TRANSPORT_TRANSACTION_COMPLETE",
        "/root-fresh-verifier-gate.sh",
        "--controller-source $source",
        'set bootstrap_root "/run/wg-mix-ebpf-source-bootstrap-c8e41d73"',
        "bootstrap-absent",
        "/usr/bin/test ! -e $bootstrap_root",
        "bootstrap-not-symlink",
        "/usr/bin/test ! -L $bootstrap_root",
        "bootstrap-create",
        "/usr/bin/mkdir --mode=0700 -- $bootstrap_root",
        "bootstrap-root-readlink",
        "bootstrap-root-stat",
        "bootstrap-install-stager",
        "/usr/bin/install --owner=root --group=root --mode=0700 --no-target-directory --",
        "bootstrap-stager-readlink",
        "bootstrap-stager-sha",
        "bootstrap-stager-stat",
        "bootstrap-install-provisioner",
        'set bootstrap_provisioner "${bootstrap_root}/provision-ubuntu-test-host.sh"',
        '"${package}/provision-ubuntu-test-host.sh" $bootstrap_provisioner',
        "bootstrap-provisioner-readlink",
        "bootstrap-provisioner-stat",
        "bootstrap-provisioner-sha",
        "provision-check - provision-apply",
        "/bin/bash -p $bootstrap_provisioner $provision_mode",
        "--expected-address 192.168.10.82",
        "--expected-interface ens33",
        "--expected-hostname ubuntu-2604-test",
        "--expected-kernel 7.0.0-28-generic",
        "--expected-machine-id 9db3fb717cc74974b2a6b243d67f67b9",
        "provision_plan_policy",
        "unexpected-missing-set",
        "B82_V6_PROVISION_AUDIT",
        "child_rc=$child_rc plan=unverified missing_set=unverified next_state=STOP",
        "stage-snapshot",
        'set snapshot_manifest "${bootstrap_root}/package-manifest.v1"',
        'snapshot --manifest "${package}/package-manifest.v1"',
        "$stage_mode --manifest $snapshot_manifest",
        'set assertion exact:root:root:700:1:regular\\ file',
        "/usr/bin/test -d /usr/src/linux-headers-7.0.0-28-generic",
    )
    for literal in required_transport:
        if literal not in transport:
            fail(f"transport contract is missing {literal!r}")

    transport_main = tcl_proc(transport, "transport_main")
    expected_transport_flags = (
        (0, "--manifest"),
        (2, "--manifest-sha256"),
        (4, "--credential-path"),
        (6, "--action"),
        (8, "--operation"),
        (10, "--approved-plan-sha256"),
    )
    actual_transport_flags = tuple(
        (int(index), flag)
        for index, flag in re.findall(
            r'\[lindex \$argv ([0-9]+)\] ne "(--[a-z0-9-]+)"', transport_main
        )
    )
    if transport_main.count("$argc != 12") != 1 or actual_transport_flags != expected_transport_flags:
        fail("transport_main is not the exact digest-only 12-argument interface")
    expected_transport_values = (
        ("manifest", 1),
        ("manifest_sha", 3),
        ("credential_path", 5),
        ("action", 7),
        ("operation", 9),
        ("approved_sha", 11),
    )
    actual_transport_values = tuple(
        (name, int(index))
        for name, index in re.findall(
            r"(?m)^\s*set ([a-z_]+) \[lindex \$argv ([0-9]+)\]$", transport_main
        )
    )
    if actual_transport_values != expected_transport_values:
        fail("transport_main does not bind all six values from the exact odd positions")
    required_action_guard = (
        'if {($action eq "capture" && $operation ne "realnic-plan") ||',
        '($action eq "execute" && ![transaction_operation $operation] &&',
        '![read_only_operation $operation])}',
        'fail "action-operation" 65',
    )
    ordered(transport_main, required_action_guard, "transport action/operation gate")
    action_guard = transport_main[
        transport_main.index('if {($action eq "capture"') : transport_main.index(
            "set sha_is_valid"
        )
    ]
    if '$action eq "plan"' in action_guard:
        fail("transport blocks fixed mutation leaves from credential-free planning")

    transaction_match = re.search(
        r"(?ms)\$operation in \{(.*?)\}",
        tcl_proc(transport, "transaction_operation"),
    )
    expected_transactions = tuple(
        "prepare provision-apply fresh-run fresh-restore veth-run veth-restore "
        "routed-run routed-restore realnic-run realnic-restore "
        "retire-prestage-2c690050".split()
    )
    if not transaction_match or tuple(transaction_match.group(1).split()) != expected_transactions:
        fail("transport high-level transaction set is not exact")
    read_only = tcl_proc(transport, "read_only_operation")
    read_only_match = re.search(r"(?ms)if \{\$operation in \{(.*?)\}\} \{", read_only)
    expected_read_only = tuple(
        "package-parent-stat bootstrap-absent bootstrap-not-symlink "
        "bootstrap-root-readlink bootstrap-root-stat bootstrap-stager-readlink "
        "bootstrap-stager-stat bootstrap-stager-sha bootstrap-provisioner-readlink "
        "bootstrap-provisioner-stat bootstrap-provisioner-sha provision-check stage-plan "
        "fresh-plan veth-plan routed-plan verify-sha-realnic-approved-plan "
        "verify-stat-realnic-approved-plan stage-realnic-plan-verify".split()
    )
    if not read_only_match or tuple(read_only_match.group(1).split()) != expected_read_only:
        fail("transport explicit read-only operation set is not exact")
    ordered(
        read_only,
        (
            "[lsearch -exact [concat [base_identity_operations] [postflight_operations]",
            "[prepare_stale_operations]] $operation] >= 0",
            r"[regexp {^verify-(?:sha|stat)-(.+)$} $operation -> name]",
            "[lsearch -exact [package_names] $name] >= 0",
            "return 0",
        ),
        "transport closed read-only operation set",
    )
    if "{^(identity-|tool-|kernel-|stale-)}" in read_only:
        fail("transport read-only authority accepts an open-ended operation prefix")

    retirement_mutation = tcl_proc(transport, "retirement_mutation_operation")
    retirement_verification = tcl_proc(transport, "retirement_read_only_operation")
    if retirement_mutation.strip() != (
        'return [expr {$operation eq "retire-prestage-2c690050"}]'
    ):
        fail("transport retirement mutation classifier is not one exact high-level mode")
    if retirement_verification.strip() != (
        'return [expr {$operation eq "verify-retirement"}]'
    ):
        fail("transport retirement verification classifier is not one exact read-only mode")
    if read_only.count("retirement_read_only_operation $operation") != 1:
        fail("transport read-only surface does not admit only the fixed retirement verifier")

    retirement_helper_argv = tcl_proc(transport, "retirement_helper_remote_argv")
    ordered(
        retirement_helper_argv,
        (
            'if {$mode ni {retire-prestage-2c690050 verify-retirement}}',
            'return -code error "retirement-helper-mode"',
            "return [list /bin/bash -p $::RETIREMENT_AUTH_SELF $mode",
            "--manifest $::RETIREMENT_AUTH_MANIFEST",
            "--manifest-sha256 $manifest_sha]",
        ),
        "fixed root retirement helper argv",
    )
    if any(
        literal in retirement_helper_argv
        for literal in ("RETIREMENT_USER_INTAKE", "PREDECESSOR_LOCAL_PACKAGE", "eval", "sh -c")
    ):
        fail("root retirement helper argv interprets a user-owned or caller-supplied script")

    retirement_builder = tcl_proc(transport, "build_retirement_operation")
    expected_retirement_raw_leaves = {
        "retire-raw-auth-manifest-install",
        "retire-raw-auth-root-create",
        "retire-raw-auth-self-install",
        "retire-raw-helper-mutate",
        "retire-raw-home-qroot-create",
        "retire-raw-intake-mkdir",
        "retire-raw-link-auth-manifest",
        "retire-raw-link-auth-self",
        "retire-raw-run-qroot-create",
        "retire-raw-scp-manifest",
        "retire-raw-scp-self",
        "retire-raw-sync-auth-manifest-pending",
        "retire-raw-sync-auth-root",
        "retire-raw-sync-auth-self-pending",
        "retire-raw-sync-home-parent",
        "retire-raw-sync-home-qroot",
        "retire-raw-sync-intake-directory",
        "retire-raw-sync-intake-manifest",
        "retire-raw-sync-intake-parent",
        "retire-raw-sync-intake-self",
        "retire-raw-sync-run-parent",
    }
    actual_retirement_raw_leaves = set(
        re.findall(r"\bretire-raw-[a-z0-9-]+\b", retirement_builder)
    )
    if actual_retirement_raw_leaves != expected_retirement_raw_leaves:
        fail("transport private retirement raw-leaf set is not exact")
    public_retirement_surface = "\n".join(
        (
            tcl_proc(transport, "transaction_operation"),
            retirement_mutation,
            retirement_verification,
            read_only,
            transport_main,
        )
    )
    if any(leaf in public_retirement_surface for leaf in expected_retirement_raw_leaves):
        fail("transport accepts a private retirement raw leaf at its CLI boundary")
    retirement_primitive = tcl_proc(transport, "execute_retirement_primitive")
    if transport.count("build_retirement_operation") != 2 or retirement_primitive.count(
        "build_retirement_operation"
    ) != 1:
        fail("private retirement builder is reachable outside its sole executor")
    if "retire-raw-lock" in retirement_builder or "retirement.v1.lock" in retirement_builder:
        fail("transport contains an inline retirement-lock mutation leaf")
    helper_builder = retirement_builder[
        retirement_builder.index("retire-raw-helper-mutate - retire-ro-helper-verify") :
    ]
    ordered(
        helper_builder,
        (
            'retire-raw-helper-mutate - retire-ro-helper-verify',
            '"retire-prestage-2c690050" : "verify-retirement"',
            "[list /usr/bin/sudo --] [env_argv]",
            "[retirement_helper_remote_argv $values $manifest_sha $helper_mode]",
        ),
        "root AUTH_SELF helper transport branch",
    )
    if re.search(
        r"/bin/bash[^\n]*(?:RETIREMENT_USER_INTAKE|retire-prestage-.*\.intake)",
        transport,
    ):
        fail("transport executes the user-owned retirement intake self")

    list_pairs = (
        ("BASE_IDENTITY_OPERATIONS", "base_identity_operations"),
        ("POSTFLIGHT_OPERATIONS", "postflight_operations"),
        ("PREPARE_NEW_STALE_OPERATIONS", "prepare_stale_operations"),
        ("PACKAGE_NAMES", "package_names"),
        ("BOOTSTRAP_CREATE_OPERATIONS", "bootstrap_create_operations"),
        ("BOOTSTRAP_ROOT_VERIFY_OPERATIONS", "bootstrap_verify_operations"),
        ("PROVISIONER_VERIFY_OPERATIONS", "provisioner_verify_operations"),
        ("STAGER_VERIFY_OPERATIONS", "stager_verify_operations"),
        ("STAGE_OPERATIONS", "stage_operations"),
    )
    for bash_name, tcl_name in list_pairs:
        if tuple(bash_array(controller, bash_name).split()) != tcl_return_words(
            transport, tcl_name
        ):
            fail(f"controller/transport fixed list mismatch: {bash_name}")

    verifier_authority = tcl_proc(transport, "require_controller_verifier_authority")
    for literal in (
        'set controller_source "${repository}/${controller_path}"',
        'set controller_copy "${package}/controller.sh"',
        '$source_stat(type) ne "file" || $source_stat(nlink) != 1',
        '$source_stat(size) < 1 || $source_stat(size) > 16777216',
        "($source_stat(mode) & 07777) != 0755",
        '$copy_stat(type) ne "file" || $copy_stat(nlink) != 1',
        '$copy_stat(size) < 1 || $copy_stat(size) > 16777216',
        "($copy_stat(mode) & 07777) != 0600",
        "file_sha256 $controller_source",
        "file_sha256 $controller_copy",
        "hash-object -- $controller_source",
        'rev-parse "${integration_commit}:${controller_path}"',
        "ls-tree $integration_commit -- $controller_path",
        '100755 blob ${expected_blob}\\t${controller_path}',
    ):
        if literal not in verifier_authority:
            fail(f"controller source/tree/flat authority is missing {literal!r}")
    package_verifier = tcl_proc(transport, "execute_controller_package_verifier")
    local_authority = tcl_proc(transport, "require_transaction_local_authority")
    ordered(
        local_authority,
        (
            "require_controller_verifier_authority $values",
            "foreach name [package_names]",
            'build_operation $values $manifest_sha "scp-$name" none',
            "execute_controller_package_verifier $values $manifest_sha",
            'if {$operation eq "realnic-run"',
            "build_operation $values $manifest_sha scp-realnic-approved-plan",
        ),
        "pre-credential transaction authority",
    )
    ordered(
        package_verifier,
        (
            'set controller "${package}/controller.sh"',
            "/bin/bash $controller verify-package",
            "B82_V6_TRANSPORT_PACKAGE_AUTHORITY",
        ),
        "flat controller verify-package seam",
    )
    ordered(
        transport_main,
        (
            'if {$action eq "plan"}',
            'if {$action eq "capture"}',
            "set prebuilt_operation_spec {}",
            "require_transaction_local_authority $values $manifest_sha $operation $approved_sha",
            "build_operation $values $manifest_sha $operation",
            "set password [read_execute_credential $credential_path]",
            "execute_transaction $values $manifest_sha $operation $approved_sha $password",
        ),
        "credential-front transaction/prebuild seam",
    )
    predecessor_transport_authority = tcl_proc(
        transport, "require_retirement_predecessor_authority"
    )
    ordered(
        predecessor_transport_authority,
        (
            'set manifest "${::PREDECESSOR_LOCAL_PACKAGE}/package-manifest.v1"',
            "load_manifest $manifest $::PREDECESSOR_MANIFEST_SHA256",
            "validate_manifest_values $values",
            "[dict get $values integration_commit] ne $::PREDECESSOR_COMMIT",
            "[dict get $values local_package_dir] ne $::PREDECESSOR_LOCAL_PACKAGE",
            f'"{predecessor_remote_package}"',
            "require_manifest_authority $values $::PREDECESSOR_MANIFEST_SHA256",
            "B82_V6_RETIREMENT_PREDECESSOR_AUTHORITY",
            "credential_read=0 network_operations=0",
            "return $values",
        ),
        "transport predecessor pre-credential authority",
    )
    ordered(
        transport_main,
        (
            "set prebuilt_operation_spec {}",
            "set predecessor_values {}",
            "require_transaction_local_authority $values $manifest_sha $operation $approved_sha",
            "set predecessor_values [require_retirement_predecessor_authority]",
            '} elseif {[retirement_read_only_operation $operation]}',
            "require_transaction_local_authority $values $manifest_sha $operation $approved_sha",
            "set predecessor_values [require_retirement_predecessor_authority]",
            "set password [read_execute_credential $credential_path]",
            "execute_retirement_transaction $values $manifest_sha",
            '} elseif {[retirement_read_only_operation $operation]}',
            "execute_retirement_verify_transaction $values $manifest_sha",
        ),
        "direct retirement invocation authority-before-credential seam",
    )
    credential_prefix = transport_main[: transport_main.index(
        "set password [read_execute_credential $credential_path]"
    )]
    if (
        credential_prefix.count("require_transaction_local_authority") != 2
        or credential_prefix.count("require_retirement_predecessor_authority") != 2
        or "execute_retirement_transaction" in credential_prefix
        or "execute_retirement_verify_transaction" in credential_prefix
    ):
        fail("transport retirement authority does not fail closed before credential read")

    retirement_stale = tcl_proc(transport, "retirement_stale_operations")
    ordered(
        retirement_stale,
        (
            "foreach operation [prepare_stale_operations]",
            'if {$operation ni {stale-package-root stale-bootstrap-root}}',
            "lappend operations $operation",
            "[llength $operations] != 28",
            'return -code error "retirement-stale-cardinality"',
            "return $operations",
        ),
        "retirement exact 28-item stale projection",
    )
    if tuple(tcl_return_words(transport, "base_identity_operations")) != tuple(
        bash_array(controller, "BASE_IDENTITY_OPERATIONS").split()
    ) or len(tcl_return_words(transport, "base_identity_operations")) != 5:
        fail("retirement common gate base identity set is not the fixed five")
    if tuple(expected_stale_operations[2:]) != tuple(
        item
        for item in expected_stale_operations
        if item not in {"stale-package-root", "stale-bootstrap-root"}
    ):
        fail("static stale fixture does not define the expected retirement projection")
    common_gate = tcl_proc(transport, "execute_retirement_common_gate")
    ordered(
        common_gate,
        (
            "foreach operation [base_identity_operations]",
            "transaction_step $values $manifest_sha $operation none $password",
            "set stale_operations [retirement_stale_operations]",
            "set total [llength $stale_operations]",
            "foreach operation $stale_operations",
            "execute_primitive $values $manifest_sha $operation none $password",
            "B82_V6_RETIREMENT_STALE_SUMMARY items=$total checked=$total absent=$total",
            "B82_V6_RETIREMENT_COMMON_GATE identities=5 stale_absent=28 writes=0 result=PASS",
        ),
        "retirement 5+28 common gate",
    )
    if (
        common_gate.count("foreach operation [base_identity_operations]") != 1
        or common_gate.count("foreach operation $stale_operations") != 1
    ):
        fail("retirement common gate does not execute each fixed set exactly once")

    predecessor_gate = tcl_proc(transport, "execute_retirement_predecessor_gate")
    package_names = tcl_return_words(transport, "package_names")
    if len(package_names) != 17 or len(set(package_names)) != 17:
        fail("retirement predecessor package authority is not the exact 17 files")
    ordered(
        predecessor_gate,
        (
            "transaction_step $values $manifest_sha package-parent-stat none $password",
            "retire-ro-old-package-readlink retire-ro-old-package-stat",
            "retire-ro-old-package-entries",
            "foreach name [package_names]",
            '"verify-sha-$name"',
            '"verify-stat-$name"',
            "bootstrap-root-readlink bootstrap-root-stat",
            "bootstrap-provisioner-readlink bootstrap-provisioner-stat",
            "bootstrap-provisioner-sha bootstrap-stager-readlink bootstrap-stager-stat",
            "bootstrap-stager-sha",
            "retire-ro-old-bootstrap-entries",
            "provision-check $password",
            'if {[lindex $provision_result 3] ne "none"}',
            "package_files=17 bootstrap_files=2 provision_missing=none writes=0 result=PASS",
        ),
        "retirement predecessor remote authority gate",
    )
    for operation, assertion in (
        ("retire-ro-old-package-entries", "[package_names]"),
        (
            "retire-ro-old-bootstrap-entries",
            "{prepare-stage-root.sh provision-ubuntu-test-host.sh}",
        ),
    ):
        branch = retirement_builder[retirement_builder.index(operation) :]
        branch = branch[: branch.index("}", branch.index("set assertion")) + 1]
        if assertion not in branch:
            fail(f"retirement predecessor no-extra entry assertion drifted: {operation}")

    retirement_transaction = tcl_proc(transport, "execute_retirement_transaction")
    ordered(
        retirement_transaction,
        (
            "set state [retirement_authority_state",
            'if {$state ne "complete"}',
            "execute_retirement_common_gate $values $manifest_sha $password",
            "execute_retirement_predecessor_gate $values $manifest_sha",
            "retirement_ensure_delivery $values $manifest_sha",
            "retirement_converge_delivery_durability $values $manifest_sha",
            "retirement_ensure_authority $values $manifest_sha $predecessor_values",
            "execute_retirement_common_gate $values $manifest_sha $password",
            "retire-raw-helper-mutate $password",
            "retire-ro-helper-verify $password",
            "B82_V6_RETIREMENT_TRANSACTION_COMPLETE",
        ),
        "single retirement high-level transaction",
    )
    if retirement_transaction.count("execute_retirement_common_gate") != 2:
        fail("retirement mutation does not gate both initial and complete-authority retries")
    final_common_gate = retirement_transaction.rindex(
        "execute_retirement_common_gate $values $manifest_sha $password"
    )
    helper_mutation = retirement_transaction.index(
        "retire-raw-helper-mutate $password", final_common_gate
    )
    between_gate_and_mutation = retirement_transaction[
        final_common_gate:helper_mutation
    ]
    if (
        between_gate_and_mutation.count("retirement_step") != 1
        or "retirement_ensure_" in between_gate_and_mutation
        or "execute_retirement_predecessor_gate" in between_gate_and_mutation
    ):
        fail("5+28 common gate is not immediately before every helper mutation retry")
    retirement_verify_transaction = tcl_proc(
        transport, "execute_retirement_verify_transaction"
    )
    ordered(
        retirement_verify_transaction,
        (
            "set state [retirement_authority_state",
            'if {$state ne "complete"}',
            'fail "retirement-verify-authority-state" 78',
            "retire-ro-helper-verify $password",
            "state=T mutations=0",
        ),
        "read-only retirement verification transaction",
    )
    if "retire-raw-" in retirement_verify_transaction:
        fail("verify-retirement can reach a raw mutation leaf")

    intake_prefix = tcl_proc(transport, "retirement_require_intake_prefix")
    ordered(
        intake_prefix,
        (
            "retirement_local_delivery_file $values $manifest_sha $name",
            "file lstat $local_path local_stat",
            "retirement_observe_user_file_size",
            "retirement_observe_sha",
            'if {$remote_sha eq $expected_sha}',
            "return exact",
            "$remote_size > $local_stat(size)",
            "file_prefix_sha256 $local_path $remote_size",
            "$remote_sha ne $prefix_sha",
            'fail "retirement-intake-nonprefix" 78',
            "retirement_local_delivery_file $values $manifest_sha $name",
            "foreach field {dev ino size mode nlink uid gid type}",
            'fail "retirement-intake-local-drift" 66',
            "return prefix",
        ),
        "manifest-bound empty-or-exact-prefix intake proof",
    )
    retirement_delivery = tcl_proc(transport, "retirement_ensure_delivery")
    ordered(
        retirement_delivery,
        (
            'if {$entries eq {}}',
            "retire-raw-scp-manifest",
            "retirement_require_intake_prefix $values $manifest_sha",
            'if {$prefix_state eq "prefix"}',
            "retire-raw-scp-manifest",
            'if {[retirement_require_intake_prefix $values $manifest_sha',
            'package-manifest.v1 $password] ne "exact"}',
            'fail "retirement-intake-earlier-prefix" 78',
            "retirement_require_intake_prefix $values $manifest_sha",
            "prepare-stage-root.sh $password",
            "retire-raw-scp-self",
            "retire-ro-intake-manifest-stat retire-ro-intake-manifest-sha",
            "retire-ro-intake-self-stat retire-ro-intake-self-sha",
            '"retirement-intake-final-entries"',
        ),
        "prefix-only retirement intake delivery",
    )
    delivery_durability = tcl_proc(
        transport, "retirement_converge_delivery_durability"
    )
    ordered(
        delivery_durability,
        (
            "retire-raw-sync-intake-manifest retire-raw-sync-intake-self",
            "retire-raw-sync-intake-directory retire-raw-sync-intake-parent",
            "package-parent-stat",
            "retire-ro-intake-readlink retire-ro-intake-stat",
            "retire-ro-intake-manifest-stat retire-ro-intake-manifest-sha",
            "retire-ro-intake-self-stat retire-ro-intake-self-sha",
            '"retirement-intake-postsync-entries"',
            "B82_V6_RETIREMENT_INTAKE_DURABLE files=2 directories=2 postcheck=exact",
        ),
        "retirement intake file/directory/parent durability convergence",
    )

    for proc_name, mode, pair_operation in (
        ("retirement_verify_manifest_pair", "600", "retire-ro-auth-manifest-pair"),
        ("retirement_verify_self_pair", "700", "retire-ro-auth-self-pair"),
    ):
        pair_body = tcl_proc(transport, proc_name)
        if pair_operation not in pair_body:
            fail(f"retirement authority pair verifier missing {pair_operation}")
        stat_literal = f"exact:root:root:{mode}:2:regular\\ file"
        if stat_literal not in retirement_builder:
            fail(f"retirement authority final mode/link contract missing {mode}:2")
    for operation, pending, final in (
        (
            "retire-ro-auth-manifest-pair",
            "RETIREMENT_AUTH_MANIFEST_PENDING",
            "RETIREMENT_AUTH_MANIFEST",
        ),
        (
            "retire-ro-auth-self-pair",
            "RETIREMENT_AUTH_SELF_PENDING",
            "RETIREMENT_AUTH_SELF",
        ),
    ):
        pair_branch = retirement_builder[retirement_builder.index(operation) :]
        ordered(
            pair_branch,
            (
                f"$::{pending}",
                f"$::{final}",
                "set assertion same-two-inodes",
            ),
            f"retirement authority same-inode pair {operation}",
        )
    if retirement_builder.count("set assertion same-two-inodes") != 2:
        fail("retirement root authority pairs are not both same-inode/nlink-two")
    authority_convergence = tcl_proc(transport, "retirement_ensure_authority")
    ordered(
        authority_convergence,
        (
            "retire-raw-auth-manifest-install",
            "retire-ro-auth-manifest-pending-stat",
            "retire-ro-auth-manifest-pending-sha",
            "retire-raw-sync-auth-manifest-pending retire-raw-sync-auth-root",
            "retire-raw-link-auth-manifest",
            "retire-raw-sync-auth-root",
            'if {$state ne "manifest-pair"}',
            "retire-raw-auth-self-install",
            "retire-ro-auth-self-pending-stat retire-ro-auth-self-pending-sha",
            "retire-raw-sync-auth-self-pending retire-raw-sync-auth-root",
            "retire-raw-link-auth-self",
            "retire-raw-sync-auth-root",
            'if {$state ne "complete"}',
            "retire-raw-sync-auth-manifest-pending retire-raw-sync-auth-self-pending",
            "retire-raw-sync-auth-root",
            'fail "retirement-authority-final-recheck" 78',
        ),
        "root authority pending-sync-hardlink-parent-sync convergence",
    )
    if (
        retirement_builder.count("/usr/bin/ln --no-target-directory --") != 2
        or "/bin/cp" in retirement_builder
        or "--force" in retirement_builder
    ):
        fail("retirement authority publication is not two no-clobber hardlinks")

    approved_proc = tcl_proc(transport, "operation_requires_approved_sha")
    approved_match = re.search(r"(?ms)\$operation in \{(?P<body>.*?)\}", approved_proc)
    if not approved_match or tuple(approved_match.group("body").split()) != approved_operations:
        fail("transport digest requirement is not the exact seven-operation tuple")
    if transport_main.count("operation_requires_approved_sha $operation") != 2:
        fail("transport does not enforce both required-digest and forbidden-digest directions")

    build_operation = tcl_proc(transport, "build_operation")
    stale_switch = build_operation[
        build_operation.index("stale-package-root") : build_operation.index("package-mkdir")
    ]
    transport_stale_operations = re.findall(r"stale-[a-z0-9-]+", stale_switch)
    if (
        len(transport_stale_operations) != 30
        or set(transport_stale_operations) != set(expected_stale_operations)
    ):
        fail("transport does not implement exactly the controller's 30 stale operations")

    prepare_transaction = tcl_proc(transport, "execute_prepare_transaction")
    ordered(
        prepare_transaction,
        (
            "execute_stale_transaction_gate $values $manifest_sha $password",
            "transaction_step $values $manifest_sha package-mkdir none $password",
            "foreach name [package_names]",
            'transaction_step $values $manifest_sha "scp-$name" none $password',
            'transaction_step $values $manifest_sha "verify-sha-$name" none $password',
            'transaction_step $values $manifest_sha "verify-stat-$name" none $password',
            "foreach operation [bootstrap_create_operations]",
        ),
        "atomic prepare transaction copy/verify sequence",
    )
    ordered(
        tcl_proc(transport, "verify_remote_package_transaction"),
        (
            "foreach name [package_names]",
            'transaction_step $values $manifest_sha "verify-sha-$name" none $password',
            'transaction_step $values $manifest_sha "verify-stat-$name" none $password',
        ),
        "remote package verification transaction",
    )
    execute_transaction = tcl_proc(transport, "execute_transaction")
    for operation, expected in (
        ("realnic-run", "scp-realnic-approved-plan verify-sha-realnic-approved-plan verify-stat-realnic-approved-plan stage-realnic-plan-snapshot realnic-run"),
        ("realnic-restore", "stage-realnic-plan-verify realnic-restore"),
    ):
        match = re.search(
            rf"(?ms)^\s*{operation} \{{\s*foreach primitive \{{(.*?)\}} \{{",
            execute_transaction,
        )
        if not match or tuple(match.group(1).split()) != tuple(expected.split()):
            fail(f"transport {operation} transaction leaf sequence is not exact")

    generic_package = build_operation[build_operation.index(
        '} elseif {[regexp {^(scp|verify-sha|verify-stat)-(.+)$} $operation'
    ) :]
    ordered(
        generic_package,
        (
            "set expected_sha [package_sha $values $name]",
            'if {$family eq "scp"}',
            "file lstat $local_path local_stat",
            "$local_stat(size) < 1 || $local_stat(size) > 16777216",
            "[file_sha256 $local_path] ne $expected_sha",
            'return -code error "scp-local-file"',
            "return [list scp $spawn_argv",
            '} elseif {$family eq "verify-sha"}',
            "/usr/bin/sha256sum",
            "/usr/bin/stat -Lc %U:%G:%a:%h:%F",
        ),
        "bounded manifest-bound generic SCP",
    )

    clean_status = tcl_proc(transport, "clean_child_exit_status")
    clean_status_contract = (
        "[llength $wait_status] != 4",
        "[lindex $wait_status 2] != 0",
        "![string is integer -strict [lindex $wait_status 3]]",
        "[lindex $wait_status 3] < 0",
        "[lindex $wait_status 3] > 255",
        'return -code error "child-wait-status"',
        "return [lindex $wait_status 3]",
    )
    ordered(clean_status, clean_status_contract, "clean child exit status")
    if transport.count("clean_child_exit_status $wait_status") != 3:
        fail("not every capture/ordinary child wait uses the signal-rejecting status parser")
    ordinary_execute = tcl_proc(transport, "execute_operation_spec")
    ordered(
        ordinary_execute,
        (
            "spawn -noecho {*}$spawn_argv",
            "set child_id $spawn_id",
            "wait -i $child_id",
            "clean_child_exit_status $wait_status",
            'fail "child-wait-status" 78',
            "if {$child_rc != 0}",
            "return [list child-failure $child_rc $captured_output none]",
            "if {$assertion eq \"provision-check\"}",
            "assert_output $assertion $captured_output",
        ),
        "ordinary execute signal fail-closed path",
    )
    if transport_main.index('if {$action eq "plan"}') > transport_main.index(
        "read_execute_credential $credential_path"
    ):
        fail("transport opens credentials before the plan-mode exit")
    if re.search(r"puts[^\n]*\$password", transport):
        fail("transport prints the credential variable")
    if re.search(r"spawn[^\n]*\$password", transport):
        fail("transport places the password in child argv")
    if "lrange $argv 2 end" in transport or "--remote-argv" in transport:
        fail("transport accepts a caller-supplied remote argv")
    if "/usr/sbin/bpftool version" in transport:
        fail("transport retains the legacy bpftool version argv")
    for retired in (
        "matrix-plan - matrix-run",
        '"matrix-plan"',
        '"matrix-run"',
        "matrix-restore-",
        "proc matrix_remote_argv",
    ):
        if retired in transport:
            fail(f"transport still exposes retired physical-NIC operation {retired}")
    fresh_argv_body = transport[
        transport.index("proc fresh_remote_argv") : transport.index("proc veth_remote_argv")
    ]
    if "wg_state" in fresh_argv_body or "wireguard" in fresh_argv_body.lower():
        fail("fresh transport reachability depends on WireGuard topology")
    if re.search(
        r'/bin/bash\s+-p\s+"?\$\{package\}/prepare-stage-root\.sh', transport
    ):
        fail("transport executes the user-writable package stager")
    bootstrap_order = (
        "bootstrap-absent",
        "bootstrap-not-symlink",
        "bootstrap-create",
        "bootstrap-root-readlink",
        "bootstrap-root-stat",
        "bootstrap-install-stager",
        "bootstrap-stager-readlink",
        "bootstrap-stager-sha",
        "bootstrap-stager-stat",
        "stage-snapshot",
        "stage-plan - stage-run",
    )
    positions = [transport.index(item) for item in bootstrap_order]
    if positions != sorted(positions):
        fail("root-owned bootstrap operation order changed")
    if transport.count('set bootstrap_root "/run/wg-mix-ebpf-source-bootstrap-c8e41d73"') != 1:
        fail("transport has zero or multiple bootstrap roots")
    if transport.count('set bootstrap_provisioner "${bootstrap_root}/provision-ubuntu-test-host.sh"') != 1:
        fail("transport has zero or multiple provisioner paths")
    provision_verify = (
        "bootstrap-provisioner-readlink",
        "bootstrap-provisioner-stat",
        "bootstrap-provisioner-sha",
    )
    verify_positions = [transport.index(item) for item in provision_verify]
    if verify_positions != sorted(verify_positions):
        fail("provisioner canonical path/stat/SHA order changed")

    required_stager = (
        "root-required",
        "host-identity",
        "snapshot-bundle",
        "stage-exists",
        "clone --no-local",
        "checkout --detach",
        "staged-content",
        "/usr/bin/shellcheck",
        "status --porcelain=v1",
        "noclobber",
        "retained=1",
        'readonly BOOTSTRAP_ROOT="/run/wg-mix-ebpf-source-bootstrap-${RUN_ID}"',
        'readonly EXPECTED_SELF="${BOOTSTRAP_ROOT}/prepare-stage-root.sh"',
        'readonly USER_MANIFEST="${EXPECTED_REMOTE_PACKAGE}/package-manifest.v1"',
        'readonly USER_BUNDLE="${EXPECTED_REMOTE_PACKAGE}/source-${PACKAGE_ID}.bundle"',
        'readonly SNAPSHOT_MANIFEST="${BOOTSTRAP_ROOT}/package-manifest.v1"',
        'readonly SNAPSHOT_BUNDLE="${BOOTSTRAP_ROOT}/source-${PACKAGE_ID}.bundle"',
        "snapshot-plan | snapshot | plan | run",
        "copy_noclobber",
        '/usr/bin/cat -- "${source}" >"${destination}"',
        "snapshot-destination-exists",
        "root:root:600:1:regular file",
        'local bundle="${SNAPSHOT_BUNDLE}"',
        '[[ "${MANIFEST}" == "${SNAPSHOT_MANIFEST}" ]]',
        "require_root_owned_self",
        "root:root:700:1:regular file",
        'canonical_self="$(/usr/bin/readlink -e -- "$0")"',
        '[[ "$(sha256_file "${EXPECTED_SELF}")" == "${PREPARE_SHA256}" ]]',
        'readonly MODULE_LEASE_LOCK="${STAGE_ROOT}/checksum-module-lease.v1.lock"',
        'readonly MODULE_LEASE_HELPER_RELATIVE="scripts/realhost-b82-${RUN_ID}/checksum-module-lease.sh"',
        "plan_command S3.lock /usr/bin/install --owner=root --group=root --mode=0600",
        '--no-target-directory -- /dev/null "${MODULE_LEASE_LOCK}"',
        "require_module_lease_lock",
        "module-lease-lock-create",
        "module-lease-lock-drift",
        '"module_lease_lock=${MODULE_LEASE_LOCK}"',
        '"${EXPECTED_SOURCE}/${MODULE_LEASE_HELPER_PATH}"',
        "checksum_module_lease_sh_path",
        "root_fresh_verifier_gate_sh_path",
        "test_hermetic_fresh_verifier_gate_sh_path",
        "test_fresh_verifier_gate_static_py_path",
        "root_veth_n_r_sh_path",
        "test_hermetic_veth_runner_sh_path",
        "test_veth_runner_static_py_path",
        "controller_seam_sh_path",
        "root_routed_veth_n_r_sh_path",
        "test_hermetic_routed_veth_harness_sh_path",
        "test_routed_veth_harness_static_py_path",
        '"${EXPECTED_SOURCE}/${ROOT_FRESH_PATH}"',
        "provision_ubuntu_test_host_sh_path",
        "provision_ubuntu_test_host_sh_blob",
        "provision_ubuntu_test_host_sh_sha256",
        "${EXPECTED_SOURCE}/${PROVISION_PATH}",
        'readonly USER_REALNIC_PLAN="${EXPECTED_REMOTE_PACKAGE}/realnic-approved-plan.json"',
        'readonly ROOT_REALNIC_PLAN="${BOOTSTRAP_ROOT}/realnic-approved-plan.json"',
        "realnic-plan-snapshot | realnic-plan-verify",
        "require_completed_stage",
        "open_approved_plan_intake",
        'exec {APPROVED_PLAN_FD}<"${USER_REALNIC_PLAN}"',
        '"/proc/self/fd/${APPROVED_PLAN_FD}"',
        'APPROVED_PLAN_PENDING="${ROOT_REALNIC_PLAN}.pending.${APPROVED_PLAN_SHA256}"',
        "create_approved_plan_pending",
        "write_approved_plan_pending",
        "require_approved_plan_pending_fd",
        "fsync_exact_target",
        '/bin/ln --no-target-directory --',
        "held-fd-writeall-fsync-hardlink-noclobber",
        "final-pending-same-inode",
        "approved-plan-preexisting-differs",
        "approved-plan-root-snapshot",
        "verified-existing",
        "verify_realnic_plan",
        "root:root:600:1:regular file",
        "siyixuan:siyixuan",
        "realnic_acceptance_py_path",
        "test_realnic_acceptance_py_path",
        "test_realnic_acceptance_static_py_path",
        "S6.realnic-unit",
        "S6.realnic-static",
        "S6.veth-hermetic",
        "S6.veth-static",
        "S6.routed-hermetic",
        "S6.routed-static",
        "S7 /usr/bin/shellcheck --norc --shell=bash --",
        "PYTHONDONTWRITEBYTECODE=1",
        '"${EXPECTED_SOURCE}/${REALNIC_TEST_PATH}"',
        '"${EXPECTED_SOURCE}/${REALNIC_STATIC_PATH}"',
        "realnic-hermetic-unit",
        "realnic-hermetic-static",
    )
    for literal in required_stager:
        if literal not in stager:
            fail(f"root stager contract is missing {literal!r}")

    retirement_wrapper_start = stager.index("run_retirement_engine() {")
    retirement_wrapper_end = stager.index("\n}\n\nrun_stage() {", retirement_wrapper_start)
    retirement_wrapper = stager[retirement_wrapper_start:retirement_wrapper_end]
    retirement_heredoc = re.search(
        r"(?ms)<<'PY'\n(?P<body>.*?)\nPY$", retirement_wrapper
    )
    if not retirement_heredoc:
        fail("cannot isolate fixed embedded retirement engine")
    retirement_engine = retirement_heredoc.group("body")
    retirement_shell_argv = tuple(
        re.findall(
            r'"\$\{([A-Z][A-Z0-9_]*)\}"',
            retirement_wrapper[: retirement_wrapper.index("<<'PY'")],
        )
    )
    expected_retirement_shell_argv = (
        "MODE",
        "MANIFEST",
        "MANIFEST_SHA256",
        "RETIREMENT_AUTH_MANIFEST_PENDING",
        "RETIREMENT_AUTH_SELF",
        "RETIREMENT_AUTH_SELF_PENDING",
        "PREPARE_SHA256",
        "RETIREMENT_USER_INTAKE",
        "RETIREMENT_HOME_QROOT",
        "RETIREMENT_AUTH_ROOT",
        "RETIREMENT_Q_INTAKE",
        "RETIREMENT_Q_PACKAGE",
        "EXPECTED_REMOTE_PACKAGE",
        "BOOTSTRAP_ROOT",
        "RETIREMENT_RUN_QROOT",
        "RETIREMENT_Q_BOOTSTRAP",
        "RETIREMENT_LOCK",
        "RETIREMENT_RECEIPT_PENDING",
        "RETIREMENT_RECEIPT_FINAL",
        "PREDECESSOR_COMMIT",
        "PREDECESSOR_MANIFEST_SHA256",
        "EXPECTED_HOSTNAME",
        "EXPECTED_KERNEL",
        "EXPECTED_MACHINE_ID",
    )
    if retirement_shell_argv != expected_retirement_shell_argv:
        fail("root stager retirement helper argv is not the fixed ordered 24 values")
    if retirement_wrapper.count("/usr/bin/python3 -B -I -") != 1:
        fail("root stager retirement engine is not one isolated stdin program")
    if retirement_engine.count("if len(sys.argv) != 25:") != 1:
        fail("root stager retirement engine does not enforce argc 25 exactly once")
    unpack_match = re.search(
        r"(?ms)^\((?P<body>.*?)\) = sys\.argv\[1:\]$", retirement_engine
    )
    if not unpack_match:
        fail("cannot isolate root stager retirement argv unpack")
    actual_engine_argv = tuple(
        re.findall(r"[a-z][a-z0-9_]*", unpack_match.group("body"))
    )
    expected_engine_argv = (
        "mode",
        "current_manifest",
        "current_manifest_sha",
        "current_manifest_pending",
        "current_self",
        "current_self_pending",
        "current_self_sha",
        "user_intake",
        "home_qroot",
        "auth_root",
        "q_intake",
        "q_package",
        "source_package",
        "source_bootstrap",
        "run_qroot",
        "q_bootstrap",
        "lock_path",
        "receipt_pending",
        "receipt_final",
        "predecessor_commit",
        "predecessor_manifest_sha",
        "expected_hostname",
        "expected_kernel",
        "expected_machine_id",
    )
    if actual_engine_argv != expected_engine_argv:
        fail("root stager retirement Python argv binding drifted")
    if retirement_engine.count(
        'mode not in {"retire-prestage-2c690050", "verify-retirement"}'
    ) != 1:
        fail("root stager retirement engine mode set is not exact")

    current_authority = python_function(
        retirement_engine, "validate_current_authority"
    )
    ordered(
        current_authority,
        (
            "require_exact_names(auth_descriptor",
            "os.path.basename(current_manifest_pending)",
            "os.path.basename(current_self_pending)",
            "require_pair(",
            "os.path.basename(current_manifest), 0o600, current_manifest_sha",
            "require_pair(",
            "os.path.basename(current_self), 0o700, current_self_sha",
            'values.get("format") != "wg-mix-ebpf-b82-v6-package-v4"',
            'values.get("integration_commit") == predecessor_commit',
            "hashlib.sha256(self_payload).hexdigest() != current_self_sha",
        ),
        "root stager current manifest/self nlink-two authority",
    )
    require_pair_body = python_function(retirement_engine, "require_pair")
    if require_pair_body.count("require_file_at(") != 2 or "links, 2" in require_pair_body:
        fail("root stager authority pair validation structure drifted")
    ordered(
        require_pair_body,
        (
            "pending_descriptor = require_file_at(",
            "mode_bits, 2,",
            "final_descriptor = require_file_at(",
            "mode_bits, 2,",
            "(first.st_dev, first.st_ino) != (second.st_dev, second.st_ino)",
        ),
        "root authority same-inode nlink-two validation",
    )

    receipt_body = python_function(retirement_engine, "receipt_bytes")
    receipt_lines = receipt_body[
        receipt_body.index("lines = (") : receipt_body.index("if len(lines) != 18")
    ]
    receipt_keys = tuple(re.findall(r'\("([a-z0-9_]+)",', receipt_lines))
    expected_receipt_keys = (
        "format",
        "retire_id",
        "state",
        "predecessor_commit",
        "predecessor_manifest_sha256",
        "predecessor_bundle_sha256",
        "authority_manifest_sha256",
        "authority_prepare_stage_root_sha256",
        "authority_integration_commit",
        "source_intake",
        "source_package",
        "source_bootstrap",
        "quarantine_intake",
        "quarantine_package",
        "quarantine_bootstrap",
        "rename_order",
        "rename_primitive",
        "retention",
    )
    if receipt_keys != expected_receipt_keys or receipt_body.count("len(lines) != 18") != 1:
        fail("root stager retirement receipt is not the exact ordered 18-line contract")
    for literal in (
        f'("retire_id", "{retire_id}")',
        '("state", "TERMINAL")',
        '("predecessor_bundle_sha256", bundle_sha)',
        '("rename_order", "intake,package,bootstrap")',
        '("rename_primitive", "renameat2-RENAME_NOREPLACE-dirfd-v1")',
        '("retention", "no-unlink-no-rmdir-no-copy-fallback")',
    ):
        if receipt_body.count(literal) != 1:
            fail(f"root stager receipt field drifted: {literal!r}")
    if "boot_id" in receipt_body or retired_bundle_sha in receipt_body:
        fail("root stager receipt adds boot identity or hard-codes the old bundle digest")
    pending_receipt = python_function(retirement_engine, "validate_pending_receipt")
    ordered(
        pending_receipt,
        (
            "require_file_at(",
            "0o600, 1, None",
            "existing = read_all(descriptor, 8192)",
            "if not expected_payload.startswith(existing)",
            'stop("receipt-pending-not-owned-prefix")',
        ),
        "retained receipt empty-or-exact-prefix ownership proof",
    )

    classify_state = python_function(retirement_engine, "classify_state")
    state_signatures = (
        '(True, True, True, False, False, False, False): "D"',
        '(False, True, True, True, False, False, False): "I"',
        '(False, False, True, True, True, False, False): "S1"',
        '(False, False, False, True, True, True, False): "S2"',
        '(False, False, False, True, True, True, True): "T_CANDIDATE"',
    )
    for signature in state_signatures:
        if classify_state.count(signature) != 1:
            fail(f"root stager retirement state signature drifted: {signature}")
    state_labels = set(
        re.findall(r'"(D|I|S1|S2|S2P|T_CANDIDATE)"', classify_state)
    )
    if state_labels != {"D", "I", "S1", "S2", "S2P", "T_CANDIDATE"}:
        fail("root stager retirement state classifier adds or drops a state")
    ordered(
        classify_state,
        (
            'if state == "S2" and pending_present',
            'state = "S2P"',
            "elif pending_present",
            'stop("retirement-state")',
            'expected_run = set() if allow_lockless_d and state == "D" else',
            "os.path.basename(lock_path)",
            'if state == "S2P"',
            "os.path.basename(receipt_pending)",
            'if state == "T_CANDIDATE"',
            "os.path.basename(receipt_final)",
            'require_exact_names(run_descriptor, expected_run, "run-qroot")',
        ),
        "retirement classifier lock/receipt exact namespace",
    )

    if retirement_engine.count('ctypes.CDLL("libc.so.6", use_errno=True)') != 1:
        fail("root stager does not bind glibc renameat2 exactly once")
    for literal in (
        "RENAME_NOREPLACE = 1",
        "libc_renameat2 = libc.renameat2",
        "libc_renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p,",
        "ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]",
        "libc_renameat2.restype = ctypes.c_int",
        'stop("glibc-renameat2-unavailable", 69)',
    ):
        if retirement_engine.count(literal) != 1:
            fail(f"root stager glibc renameat2 contract is missing {literal!r}")
    rename_wrapper = python_function(retirement_engine, "renameat2_noreplace")
    ordered(
        rename_wrapper,
        (
            "libc_renameat2(source_parent, os.fsencode(source_name)",
            "destination_parent, os.fsencode(destination_name)",
            "RENAME_NOREPLACE)",
            "ctypes.get_errno()",
            "raise OSError(error_number, os.strerror(error_number))",
        ),
        "glibc renameat2 RENAME_NOREPLACE wrapper",
    )
    retirement_forbidden_mutations = (
        r"os\.(?:unlink|remove|rmdir|rename|replace)\s*\(",
        r"\b(?:shutil|subprocess)\b",
        r"libc\.syscall\s*\(",
        r"\bSYS_renameat2\b",
        r"/(?:usr/)?bin/mv\b",
        r"\bcopy(?:file|tree)\s*\(",
    )
    for pattern in retirement_forbidden_mutations:
        if re.search(pattern, retirement_engine):
            fail(f"root retirement engine contains forbidden delete/copy/fallback: {pattern}")
    if (
        retirement_engine.count("renameat2_noreplace(") != 3
        or retirement_engine.count("libc_renameat2(") != 1
    ):
        fail("root retirement engine has an extra rename primitive or fallback")
    directory_rename = python_function(retirement_engine, "rename_directory_noreplace")
    ordered(
        directory_rename,
        (
            "validator(held_descriptor)",
            "renameat2_noreplace(source_parent, source_name",
            "same_open_inode(held_descriptor, destination_descriptor",
            "validator(destination_descriptor)",
            "entry_stat(source_parent, source_name) is not None",
            "os.fsync(source_parent)",
            "os.fsync(destination_parent)",
            "validator(held_descriptor)",
        ),
        "retained directory rename and parent durability",
    )

    acquire_lock = python_function(retirement_engine, "acquire_retirement_lock")
    ordered(
        acquire_lock,
        (
            'writable = mode == "retire-prestage-2c690050"',
            "if entry_stat(run_descriptor, lock_name) is None",
            "if not writable",
            'stop("retirement-lock-absent", 78)',
            "classify_state(",
            "allow_lockless_d=True",
            'if provisional_state != "D" or provisional_pending',
            "os.O_RDWR | os.O_CREAT | os.O_EXCL | O_NOFOLLOW | O_CLOEXEC",
            "metadata.st_nlink != 1",
            "(metadata.st_dev, metadata.st_ino) != (named.st_dev, named.st_ino)",
            "os.fsync(lock_descriptor)",
            "os.fsync(run_descriptor)",
            "lock_descriptor = require_file_at(",
            "ROOT_UID, ROOT_GID, 0o600, 1",
            "fcntl.LOCK_EX if writable else fcntl.LOCK_SH",
            "fcntl.flock(lock_descriptor, lock_mode | fcntl.LOCK_NB)",
        ),
        "provisional-D O_EXCL retirement lock acquisition",
    )
    boot_marker = python_function(
        retirement_engine, "initialize_or_verify_boot_marker"
    )
    ordered(
        boot_marker,
        (
            'writable = mode == "retire-prestage-2c690050"',
            'expected = f"boot_id\\t{boot_id}\\n".encode("ascii")',
            "if existing == expected",
            "os.fsync(lock_descriptor)",
            "os.fsync(run_descriptor)",
            "if read_all(lock_descriptor, 256) != expected",
            'state != "D" or not writable or not expected.startswith(existing)',
            'stop("same-boot-residual")',
            "os.ftruncate(lock_descriptor, 0)",
            "write_all(lock_descriptor, expected)",
            "os.fsync(lock_descriptor)",
            "os.fsync(run_descriptor)",
            "if read_all(lock_descriptor, 256) != expected",
        ),
        "same-boot lock marker convergence",
    )
    engine_main = python_function(retirement_engine, "engine_main")
    ordered(
        engine_main,
        (
            "current_values = validate_current_authority(auth_descriptor)",
            "fsync_current_authority(auth_descriptor)",
            "validate_current_authority(auth_descriptor) != current_values",
            "acquire_retirement_lock(",
            "state, pending_present = classify_state(",
            "boot_id = boot_identity()",
            "initialize_or_verify_boot_marker(lock_descriptor, run_descriptor, state, boot_id)",
            "state_after_lock, pending_after_lock = classify_state(",
            'stop("post-lock-state-drift")',
            "validate_state_objects(",
        ),
        "lock-before-classification and boot convergence",
    )
    if engine_main.count("acquire_retirement_lock(") != 1:
        fail("root retirement engine does not hold one lock for the full transaction")

    require_file = python_function(retirement_engine, "require_file_at")
    ordered(
        require_file,
        (
            "metadata = os.fstat(descriptor)",
            "metadata.st_nlink != links",
            "os.fsync(descriptor)",
            "sha256_fd(descriptor) != expected_sha",
            "os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)",
            "(path_metadata.st_dev, path_metadata.st_ino) != (metadata.st_dev, metadata.st_ino)",
        ),
        "retained file fsync/SHA/named-inode gate",
    )
    fsync_authority = python_function(retirement_engine, "fsync_current_authority")
    ordered(
        fsync_authority,
        (
            "os.path.basename(current_manifest), os.path.basename(current_self)",
            "os.fsync(descriptor)",
            "os.fsync(auth_descriptor)",
        ),
        "current authority retained-file and parent fsync",
    )
    for function_name, postcheck_literal in (
        ("validate_intake", "intake-manifest-postfsync"),
        ("validate_old_package", "predecessor-package-postfsync-"),
        ("validate_old_bootstrap", "predecessor-bootstrap-postfsync-"),
    ):
        validator = python_function(retirement_engine, function_name)
        ordered(
            validator,
            (
                "require_file_at(",
                "os.fsync(descriptor)",
                "require_file_at(",
                postcheck_literal,
            ),
            f"{function_name} retained-file parent convergence",
        )
    completed_parents = python_function(
        retirement_engine, "converge_completed_rename_parents"
    )
    ordered(
        completed_parents,
        (
            'state in {"I", "S1", "S2", "S2P", "T_CANDIDATE"}',
            '"converge-intake"',
            'state in {"S1", "S2", "S2P", "T_CANDIDATE"}',
            '"converge-package"',
            'state in {"S2", "S2P", "T_CANDIDATE"}',
            '"converge-bootstrap"',
            "converge_completed_rename(source, destination, uid, gid, label)",
        ),
        "I/S1/S2/S2P/T retained parent convergence matrix",
    )
    completed_rename = python_function(retirement_engine, "converge_completed_rename")
    ordered(
        completed_rename,
        (
            "entry_stat(source_parent, source_name) is not None",
            "destination_descriptor = open_child_dir(",
            "os.fsync(source_parent)",
            "os.fsync(destination_parent)",
            "entry_stat(source_parent, source_name) is not None",
            "os.stat(",
            "fd_mnt_id(destination_descriptor) != destination_mount",
            "require_dir_fd(destination_descriptor",
        ),
        "completed rename source/destination parent convergence",
    )
    resumed_state = python_function(retirement_engine, "converge_resumed_state")
    ordered(
        resumed_state,
        (
            'expected_state not in {"I", "S1", "S2", "S2P"}',
            "converge_completed_rename_parents(expected_state, user_uid, user_gid)",
            "visible_state, visible_pending = classify_state(",
            "validate_state_objects(",
            "final_state, final_pending = classify_state(",
            'stop("resume-postvalidation-state")',
        ),
        "resumed I/S1/S2/S2P convergence and reclassification",
    )
    terminal_convergence = python_function(retirement_engine, "converge_terminal")
    ordered(
        terminal_convergence,
        (
            'converge_completed_rename_parents("T_CANDIDATE"',
            "validate_receipt(run_descriptor, payload)",
            "os.fsync(final_descriptor)",
            "os.fsync(run_descriptor)",
            "visible_state, visible_pending = classify_state(",
            "validate_state_objects(",
            'visible_state != "T_CANDIDATE"',
            "final_state, final_pending = classify_state(",
            'final_state != "T_CANDIDATE" or final_pending',
            'return "T"',
        ),
        "terminal T read-only durability convergence",
    )
    ordered(
        engine_main,
        (
            'if state in {"I", "S1", "S2", "S2P"}',
            "converge_resumed_state(",
            'if mode == "verify-retirement"',
            'if state != "T_CANDIDATE"',
            "terminal_state = converge_terminal(",
            'if terminal_state != "T"',
            "namespace_writes=0",
            'if state == "T_CANDIDATE"',
            "terminal_state = converge_terminal(",
            'if terminal_state != "T"',
            "disposition=verified-existing",
            "namespace_writes=0",
            'if state == "D"',
            "rename_directory_noreplace(",
            'if state == "I"',
            "rename_directory_noreplace(",
            'if state == "S1"',
            "rename_directory_noreplace(",
            'if state not in {"S2", "S2P"}',
            "publish_receipt(",
            'if state != "T_CANDIDATE"',
            "terminal_state = converge_terminal(",
            'if terminal_state != "T"',
            "disposition=advanced",
        ),
        "D/I/S1/S2/S2P/T retirement convergence",
    )
    dispatch_markers = (
        'if state in {"I", "S1", "S2", "S2P"}:',
        'if mode == "verify-retirement":',
        'if state == "T_CANDIDATE":',
        'if state == "D":',
        'if state == "I":',
        'if state == "S1":',
        'if state not in {"S2", "S2P"}:',
    )
    for marker in dispatch_markers:
        if engine_main.count(marker) != 1:
            fail(f"root retirement engine dispatch marker is not unique: {marker}")
    if re.search(r'if state\s*==\s*["\']T["\']', engine_main):
        fail("root retirement engine treats synthetic T as a classifier input state")

    resume_dispatch = engine_main[
        engine_main.index('if state in {"I", "S1", "S2", "S2P"}:') :
        engine_main.index('if mode == "verify-retirement":')
    ]
    ordered(
        resume_dispatch,
        (
            'if state in {"I", "S1", "S2", "S2P"}:',
            "predecessor_values, payload = converge_resumed_state(",
            "state, pending_present, home_descriptor, run_descriptor,",
            "user.pw_uid, user.pw_gid, current_values, boot_id)",
        ),
        "I/S1/S2/S2P exact resume dispatch argv",
    )
    if (
        resume_dispatch.count("converge_resumed_state(") != 1
        or "rename_directory_noreplace(" in resume_dispatch
        or "publish_receipt(" in resume_dispatch
    ):
        fail("I/S1/S2/S2P resume dispatch adds a namespace mutation")

    verify_dispatch = engine_main[
        engine_main.index('if mode == "verify-retirement":') :
        engine_main.index('if state == "T_CANDIDATE":')
    ]
    ordered(
        verify_dispatch,
        (
            'if mode == "verify-retirement":',
            'if state != "T_CANDIDATE":',
            'stop("retirement-not-terminal", 78)',
            "terminal_state = converge_terminal(",
            "home_descriptor, run_descriptor, user.pw_uid, user.pw_gid,",
            "current_values, boot_id, payload)",
            'if terminal_state != "T":',
            'stop("verify-terminal-state")',
            "B82_V6_RETIREMENT_VERIFIED state=T namespace_writes=0",
            "return",
        ),
        "verify-retirement T_CANDIDATE-to-T dispatch",
    )
    if (
        verify_dispatch.count("converge_terminal(") != 1
        or "rename_directory_noreplace(" in verify_dispatch
        or "publish_receipt(" in verify_dispatch
        or "namespace_writes +=" in verify_dispatch
    ):
        fail("verify-retirement terminal dispatch is not read-only")

    terminal_retry_dispatch = engine_main[
        engine_main.index('if state == "T_CANDIDATE":') :
        engine_main.index("namespace_writes = 1 if lock_created else 0")
    ]
    ordered(
        terminal_retry_dispatch,
        (
            'if state == "T_CANDIDATE":',
            "terminal_state = converge_terminal(",
            "home_descriptor, run_descriptor, user.pw_uid, user.pw_gid,",
            "current_values, boot_id, payload)",
            'if terminal_state != "T":',
            'stop("retire-terminal-state")',
            "state=T disposition=verified-existing",
            "namespace_writes=0 same_boot=1",
            "return",
        ),
        "mutation T_CANDIDATE-to-T retry dispatch",
    )
    if (
        terminal_retry_dispatch.count("converge_terminal(") != 1
        or "rename_directory_noreplace(" in terminal_retry_dispatch
        or "publish_receipt(" in terminal_retry_dispatch
        or "namespace_writes +=" in terminal_retry_dispatch
    ):
        fail("mutation terminal retry can perform a new namespace write")

    state_d_dispatch = engine_main[
        engine_main.index('if state == "D":') : engine_main.index('if state == "I":')
    ]
    ordered(
        state_d_dispatch,
        (
            'if state == "D":',
            "rename_directory_noreplace(",
            "user_intake, q_intake, user.pw_uid, user.pw_gid,",
            "lambda descriptor: validate_intake(",
            'descriptor, user.pw_uid, user.pw_gid), "retire-intake")',
            "namespace_writes += 1",
            "state, pending_present = classify_state(",
            "home_descriptor, run_descriptor, user.pw_uid, user.pw_gid)",
            'if state != "I":',
            'stop("post-intake-state")',
            "predecessor_values, payload = validate_state_objects(",
            "state, pending_present, home_descriptor, run_descriptor,",
            "user.pw_uid, user.pw_gid, current_values, boot_id)",
            "confirmed_state, confirmed_pending = classify_state(",
            'stop("post-intake-validation-state")',
        ),
        "D-to-I intake dispatch wiring",
    )
    if (
        state_d_dispatch.count("rename_directory_noreplace(") != 1
        or state_d_dispatch.count("classify_state(") != 2
        or state_d_dispatch.count("validate_state_objects(") != 1
        or state_d_dispatch.count("namespace_writes += 1") != 1
        or any(
            name in state_d_dispatch
            for name in ("source_package", "q_package", "source_bootstrap", "q_bootstrap")
        )
    ):
        fail("D-to-I dispatch is not the sole intake rename/validate transition")

    state_i_dispatch = engine_main[
        engine_main.index('if state == "I":') : engine_main.index('if state == "S1":')
    ]
    ordered(
        state_i_dispatch,
        (
            'if state == "I":',
            "rename_directory_noreplace(",
            "source_package, q_package, user.pw_uid, user.pw_gid,",
            "lambda descriptor: validate_old_package(",
            'descriptor, user.pw_uid, user.pw_gid), "retire-package")',
            "namespace_writes += 1",
            "state, pending_present = classify_state(",
            'if state != "S1":',
            'stop("post-package-state")',
            "predecessor_values, payload = validate_state_objects(",
            "confirmed_state, confirmed_pending = classify_state(",
            'stop("post-package-validation-state")',
        ),
        "I-to-S1 package dispatch wiring",
    )
    if (
        state_i_dispatch.count("rename_directory_noreplace(") != 1
        or state_i_dispatch.count("classify_state(") != 2
        or state_i_dispatch.count("validate_state_objects(") != 1
        or state_i_dispatch.count("namespace_writes += 1") != 1
        or any(
            name in state_i_dispatch
            for name in ("user_intake", "q_intake", "source_bootstrap", "q_bootstrap")
        )
    ):
        fail("I-to-S1 dispatch is not the sole predecessor-package transition")

    state_s1_dispatch = engine_main[
        engine_main.index('if state == "S1":') :
        engine_main.index('if state not in {"S2", "S2P"}:')
    ]
    ordered(
        state_s1_dispatch,
        (
            'if state == "S1":',
            "rename_directory_noreplace(",
            "source_bootstrap, q_bootstrap, ROOT_UID, ROOT_GID,",
            "lambda descriptor: validate_old_bootstrap(",
            'descriptor, predecessor_values), "retire-bootstrap")',
            "namespace_writes += 1",
            "state, pending_present = classify_state(",
            'if state != "S2":',
            'stop("post-bootstrap-state")',
            "predecessor_values, payload = validate_state_objects(",
            "confirmed_state, confirmed_pending = classify_state(",
            'stop("post-bootstrap-validation-state")',
        ),
        "S1-to-S2 bootstrap dispatch wiring",
    )
    if (
        state_s1_dispatch.count("rename_directory_noreplace(") != 1
        or state_s1_dispatch.count("classify_state(") != 2
        or state_s1_dispatch.count("validate_state_objects(") != 1
        or state_s1_dispatch.count("namespace_writes += 1") != 1
        or any(
            name in state_s1_dispatch
            for name in ("user_intake", "q_intake", "source_package", "q_package")
        )
    ):
        fail("S1-to-S2 dispatch is not the sole root bootstrap transition")

    receipt_dispatch = engine_main[
        engine_main.index('if state not in {"S2", "S2P"}:') :
        engine_main.index("    finally:")
    ]
    ordered(
        receipt_dispatch,
        (
            'if state not in {"S2", "S2P"}:',
            'stop("pre-receipt-state")',
            "namespace_writes += publish_receipt(",
            'run_descriptor, payload, state == "S2P" and pending_present)',
            "state, pending_present = classify_state(",
            'if state != "T_CANDIDATE":',
            'stop("post-receipt-visible-state")',
            "terminal_state = converge_terminal(",
            "home_descriptor, run_descriptor, user.pw_uid, user.pw_gid,",
            "current_values, boot_id, payload)",
            'if terminal_state != "T":',
            'stop("post-receipt-terminal-state")',
            "state=T disposition=advanced",
        ),
        "S2/S2P receipt-to-T dispatch wiring",
    )
    if (
        receipt_dispatch.count("publish_receipt(") != 1
        or receipt_dispatch.count("classify_state(") != 1
        or receipt_dispatch.count("converge_terminal(") != 1
        or "rename_directory_noreplace(" in receipt_dispatch
    ):
        fail("S2/S2P-to-T dispatch does not use one receipt publish and convergence")
    if retirement_engine.count("\n    engine_main()\n") != 1:
        fail("embedded production retirement engine does not invoke engine_main exactly once")

    harness_marker = "<<'RETIREMENT_ENGINE_HARNESS_PY'\n"
    if hermetic.count(harness_marker) != 1:
        fail("hermetic test does not define one retirement engine fault harness")
    harness_start = hermetic.index(harness_marker) + len(harness_marker)
    harness_end = hermetic.index("\nRETIREMENT_ENGINE_HARNESS_PY\n", harness_start)
    fault_harness = hermetic[harness_start:harness_end]
    selected_match = re.search(
        r"(?ms)^SELECTED = \{(?P<body>.*?)^\}\n", fault_harness
    )
    if not selected_match:
        fail("cannot isolate hermetic extracted-engine function set")
    selected_functions = tuple(
        re.findall(r'"([A-Za-z_][A-Za-z0-9_]*)"', selected_match.group("body"))
    )
    if (
        selected_functions.count("engine_main") != 1
        or len(selected_functions) != len(set(selected_functions))
    ):
        fail("hermetic dynamic matrix does not extract production engine_main exactly once")
    load_fault_engine = python_function(fault_harness, "load_engine")
    ordered(
        load_fault_engine,
        (
            'marker = "<<\'PY\'\\n"',
            'engine = shell[start:shell.index("\\nPY\\n", start)]',
            'tree = ast.parse(engine, filename="retirement-engine")',
            "node for node in tree.body",
            "node.name in SELECTED",
            "compile(ast.Module(body=selected, type_ignores=[])",
            '"retirement-engine-selected", "exec")',
        ),
        "hermetic production engine AST extraction",
    )
    if re.search(
        r'[A-Za-z_][A-Za-z0-9_]*\["engine_main"\]\s*=', fault_harness
    ):
        fail("hermetic matrix replaces production engine_main with a fixture implementation")
    engine_main_calls = tuple(
        re.finditer(
            r'\b[A-Za-z_][A-Za-z0-9_]*\["engine_main"\]\(\)', fault_harness
        )
    )
    if len(engine_main_calls) != 1:
        fail("hermetic dynamic matrix does not invoke extracted engine_main exactly once")
    engine_call_position = engine_main_calls[0].start()
    enclosing_headers = tuple(
        re.finditer(
            r"(?m)^def ([A-Za-z_][A-Za-z0-9_]*)\([^\n]*\):",
            fault_harness[:engine_call_position],
        )
    )
    if not enclosing_headers:
        fail("hermetic extracted engine_main invocation is outside a test driver")
    engine_driver_name = enclosing_headers[-1].group(1)
    matrix_test_bodies = {
        name: python_function(fault_harness, name)
        for name in ("test_all_failure_cuts", "drive_fault_matrix")
    }
    engine_driver_wired = engine_driver_name in matrix_test_bodies or any(
        re.search(rf"\b{re.escape(engine_driver_name)}\(", body)
        for body in matrix_test_bodies.values()
    )
    if engine_driver_name == "run_child":
        child_result_body = python_function(fault_harness, "child_result")
        harness_main_body = python_function(fault_harness, "main")
        ordered(
            child_result_body,
            (
                "subprocess.run(",
                '[sys.executable, "-B", "-I", os.path.realpath(__file__)',
                '"--child", stager, raw_root, operation, cut,',
                '"retire-prestage-2c690050"',
            ),
            "fault matrix child-to-engine_main subprocess wiring",
        )
        ordered(
            harness_main_body,
            (
                'arguments[0] == "--child"',
                "run_child(*arguments[1:])",
                "test_all_failure_cuts(stager)",
                "drive_fault_matrix(stager)",
            ),
            "fault harness child/parent dispatch wiring",
        )
        engine_driver_wired = all(
            "child_result(" in body for body in matrix_test_bodies.values()
        )
    if not engine_driver_wired:
        fail("extracted engine_main invocation is not wired into the dynamic fault matrix")

    failure_cut_test = matrix_test_bodies["test_all_failure_cuts"]
    expected_states_start = failure_cut_test.index("expected_states = {")
    expected_states_end = failure_cut_test.index(
        "    for operation in expected_states:", expected_states_start
    )
    expected_states_block = failure_cut_test[
        expected_states_start:expected_states_end
    ]
    expected_failure_states = tuple(
        (operation, state, pending == "True")
        for operation, state, pending in re.findall(
            r'"([a-z-]+)": \("([A-Z0-9_]+)", (True|False)\)',
            expected_states_block,
        )
    )
    if expected_failure_states != (
        ("intake", "I", False),
        ("package", "S1", False),
        ("bootstrap", "S2", False),
        ("receipt-pending", "S2P", True),
        ("receipt-final", "T_CANDIDATE", False),
    ):
        fail("hermetic fault-cut oracle is not the fixed independent state table")
    if any(
        derived in expected_states_block
        for derived in ("classify", "namespace", "load_engine", "ast.", "engine")
    ):
        fail("hermetic fault-cut state oracle is derived from production source")
    if (
        'assert classify(namespace, value) == expected_states[operation]'
        not in failure_cut_test
    ):
        fail("hermetic production classifier is not checked against the fixed state oracle")

    fault_matrix = matrix_test_bodies["drive_fault_matrix"]
    for independent_oracle in (
        'assert transitions == ["D", "I", "S1", "S2", "S2P", "T_CANDIDATE", "T"]',
        "assert cuts == [91, -signal.SIGTERM, 91, 91, -signal.SIGTERM]",
    ):
        if fault_matrix.count(independent_oracle) != 1:
            fail(f"hermetic dynamic oracle drifted: {independent_oracle!r}")
    prepare_fault_state = python_function(fault_harness, "prepare_for_operation")
    ordered(
        prepare_fault_state,
        (
            'operation in {"package", "bootstrap", "receipt-pending", "receipt-final"}',
            'os.rename(value["user_intake"], value["q_intake"])',
            'operation in {"bootstrap", "receipt-pending", "receipt-final"}',
            'os.rename(value["source_package"], value["q_package"])',
            'operation in {"receipt-pending", "receipt-final"}',
            'os.rename(value["source_bootstrap"], value["q_bootstrap"])',
            'if operation == "receipt-final"',
            'exact_file(value["receipt_pending"], PAYLOAD)',
        ),
        "independent fixed fault-cut filesystem oracle",
    )
    if prepare_fault_state.count("os.rename(") != 3 or any(
        source_derived in prepare_fault_state
        for source_derived in ("namespace", "load_engine", "classify", "ast.")
    ):
        fail("hermetic fault prestate oracle is generated from production behavior")

    expect_harness_marker = "<<'EXPECT_HARNESS'\n"
    if hermetic.count(expect_harness_marker) != 1:
        fail("hermetic test does not define one transport transaction harness")
    expect_harness_start = hermetic.index(expect_harness_marker) + len(
        expect_harness_marker
    )
    expect_harness_end = hermetic.index("\nEXPECT_HARNESS\n", expect_harness_start)
    transport_harness = hermetic[expect_harness_start:expect_harness_end]
    sequence_oracle = transport_harness[
        transport_harness.index("    retirement-sequence {") :
        transport_harness.index("    retirement-delivery-durability {")
    ]
    for same_source_oracle in (
        "[base_identity_operations]",
        "[retirement_stale_operations]",
        "[package_names]",
    ):
        if same_source_oracle in sequence_oracle:
            fail(f"hermetic retirement sequence oracle is production-derived: {same_source_oracle}")
    common_match = re.search(
        r"(?ms)\n\s*set common \{(?P<body>.*?)\n\s*\}\n\s*set predecessor \{",
        sequence_oracle,
    )
    if not common_match:
        fail("cannot isolate independent retirement 5+28 sequence oracle")
    fixed_common_oracle = (
        "identity-hostname",
        "identity-kernel",
        "identity-machine",
        "identity-netns",
        "identity-interface",
    ) + expected_stale_operations[2:]
    if tuple(common_match.group("body").split()) != fixed_common_oracle:
        fail("hermetic retirement common-gate oracle is not the fixed 5+28 tuple")
    predecessor_names_match = re.search(
        r"(?ms)\n\s*set predecessor_package_names \{(?P<body>.*?)\n\s*\}\n",
        sequence_oracle,
    )
    if not predecessor_names_match:
        fail("cannot isolate independent predecessor package-name oracle")
    fixed_predecessor_names = (
        "source-4f2a9b61.bundle",
        "package-manifest.v1",
        "bind-final-package.sh",
        "controller.sh",
        "prepare-stage-root.sh",
        "provision-ubuntu-test-host.sh",
        "root-matrix-n-r.sh",
        "check-realhost-iperf.py",
        "test-hermetic-matrix.sh",
        "test_matrix_static.py",
        "checksum-module-lease.sh",
        "root-fresh-verifier-gate.sh",
        "test-hermetic-fresh-verifier-gate.sh",
        "test_fresh_verifier_gate_static.py",
        "realnic_acceptance.py",
        "test_realnic_acceptance.py",
        "test_realnic_acceptance_static.py",
    )
    if tuple(predecessor_names_match.group("body").split()) != fixed_predecessor_names:
        fail("hermetic predecessor package oracle is not the fixed 17-file tuple")
    ordered(
        sequence_oracle,
        (
            "set predecessor {",
            "package-parent-stat retire-ro-old-package-readlink",
            "retire-ro-old-package-stat retire-ro-old-package-entries",
            "foreach name $predecessor_package_names",
            'lappend predecessor "verify-sha-$name" "verify-stat-$name"',
            "bootstrap-root-readlink bootstrap-root-stat",
            "bootstrap-provisioner-readlink bootstrap-provisioner-stat",
            "bootstrap-provisioner-sha bootstrap-stager-readlink",
            "bootstrap-stager-stat bootstrap-stager-sha",
            "retire-ro-old-bootstrap-entries provision-check",
            "[list FIRST_DELIVERY_WRITE DELIVERY_DURABLE AUTHORITY] $common",
            "[list retire-raw-helper-mutate retire-ro-helper-verify]",
            "[lsearch -exact $::observed FIRST_DELIVERY_WRITE] != 82",
            "set ::authority_state complete",
            "[list STATE AUTHORITY] $common",
            '[lindex $::observed end-1] ne "retire-raw-helper-mutate"',
        ),
        "fixed independent retirement sequence oracle",
    )

    prefix_oracle = transport_harness[
        transport_harness.index("    retirement-intake-prefixes {") :
        transport_harness.index("    default { harness_die", transport_harness.index(
            "    retirement-intake-prefixes {"
        ))
    ]
    if "file_prefix_sha256" in prefix_oracle:
        fail("hermetic intake-prefix oracle reuses the production prefix helper")
    ordered(
        prefix_oracle,
        (
            "proc harness_prefix_sha256 {path length}",
            "/usr/bin/python3 -B -I -c {",
            "payload = pathlib.Path(sys.argv[1]).read_bytes()",
            "length = int(sys.argv[2])",
            "length < 0 or length > len(payload)",
            "hashlib.sha256(payload[:length]).hexdigest()",
            'harness_die "independent-prefix-sha"',
            "set before_sha [harness_prefix_sha256 $local_path $before_stat(size)]",
            "set ::remote_sha [harness_prefix_sha256 $local_path 0]",
            "set ::remote_sha [harness_prefix_sha256 $local_path 17]",
            "[harness_prefix_sha256 $local_path $after_stat(size)] ne",
        ),
        "independent retirement intake-prefix SHA oracle",
    )
    if re.search(r"\b(?:apt|apt-get)\b", stager):
        fail("root stager contains package installation")
    if "${EXPECTED_SOURCE}" not in stager or "${STAGE_ROOT}" not in stager:
        fail("root stager does not use the fixed run-owned stage")
    if "require_package_file" in stager:
        fail("root stager still revalidates user-owned package scripts")
    if 'local bundle="${EXPECTED_REMOTE_PACKAGE}/${BUNDLE_NAME}"' in stager:
        fail("root stager clones by reopening the user-owned bundle")
    if stager.index('run_copy_step C7 "${USER_BUNDLE}"') > stager.index(
        'require_snapshot_file "${SNAPSHOT_MANIFEST}"'
    ):
        fail("root stager parses or validates the manifest before both intake copies complete")
    if stager.index('run_copy_step C7 "${USER_BUNDLE}"') > stager.index(
        'MANIFEST="${SNAPSHOT_MANIFEST}"'
    ):
        fail("root stager parses the manifest before the bundle intake copy completes")
    if stager.count("validate_manifest || fail 'manifest-contract'") != 2:
        fail("root stager manifest parsing escaped the two root-snapshot consumers")
    if stager.index("run_step S3.lock") > stager.index("run_step S4"):
        fail("root stager creates the shared module lock after source staging begins")
    if stager.index("require_module_lease_lock || fail 'module-lease-lock-drift'") > stager.index(
        "write_binding_marker || fail 'binding-marker'"
    ):
        fail("root stager binds the stage before revalidating the shared module lock")
    render_plan = bash_function(stager, "render_plan")
    run_stage = bash_function(stager, "run_stage")
    plan_gate_order = (
        'checkout --detach "${INTEGRATION_COMMIT}"',
        "plan_command S6 /bin/bash -n",
        "plan_command S6.realnic /usr/bin/python3 -B -I",
        "plan_command S6.realnic-unit /usr/bin/env -i",
        "plan_command S6.realnic-static /usr/bin/env -i",
        "plan_command S6.veth-hermetic /usr/bin/env -i",
        "plan_command S6.veth-static /usr/bin/env -i",
        "plan_command S6.routed-hermetic /usr/bin/env -i",
        "plan_command S6.routed-static /usr/bin/env -i",
        "plan_command S7 /usr/bin/shellcheck --norc --shell=bash --",
        "plan_command S8 shell-builtin noclobber-write",
    )
    run_gate_order = (
        'checkout --detach "${INTEGRATION_COMMIT}"',
        "require_staged_content || fail 'staged-content'",
        "run_step S6 /bin/bash -n",
        "run_step S6.realnic /usr/bin/python3 -B -I",
        "run_step S6.realnic-unit",
        "run_step S6.realnic-static",
        "run_step S6.veth-hermetic",
        "run_step S6.veth-static",
        "run_step S6.routed-hermetic",
        "run_step S6.routed-static",
        "run_step S7 /usr/bin/shellcheck --norc --shell=bash --",
        "require_staged_content || fail 'staged-content-postcheck'",
        "require_physical_interface_lock || fail 'physical-interface-lock-drift'",
        "require_legacy_retirement_reservation || fail 'legacy-retirement-reservation-drift'",
        "require_module_lease_lock || fail 'module-lease-lock-drift'",
        "write_binding_marker || fail 'binding-marker'",
    )
    ordered(render_plan, plan_gate_order, "planned staged-source gates")
    ordered(run_stage, run_gate_order, "mandatory staged-source gates")
    gate_labels = (
        "S6",
        "S6.realnic",
        "S6.realnic-unit",
        "S6.realnic-static",
        "S6.veth-hermetic",
        "S6.veth-static",
        "S6.routed-hermetic",
        "S6.routed-static",
        "S7",
    )
    for label in gate_labels:
        if render_plan.count(f"plan_command {label} ") != 1:
            fail(f"stager plan has zero or multiple mandatory {label} gates")
        if run_stage.count(f"run_step {label} ") != 1:
            fail(f"stager run has zero or multiple mandatory {label} gates")
    gate_argv_contracts = (
        (
            "S6.veth-hermetic",
            "S6.veth-static",
            ('"${EXPECTED_SOURCE}/${VETH_HERMETIC_PATH}"',),
        ),
        (
            "S6.veth-static",
            "S6.routed-hermetic",
            (
                '"${EXPECTED_SOURCE}/${VETH_STATIC_PATH}"',
                '"${EXPECTED_SOURCE}/${ROOT_VETH_PATH}"',
                '"${EXPECTED_SOURCE}/${ROOT_MATRIX_PATH}"',
                '"${EXPECTED_SOURCE}/${MODULE_LEASE_HELPER_PATH}"',
            ),
        ),
        (
            "S6.routed-hermetic",
            "S6.routed-static",
            ('"${EXPECTED_SOURCE}/${ROUTED_HERMETIC_PATH}"',),
        ),
        (
            "S6.routed-static",
            "S7",
            (
                '"${EXPECTED_SOURCE}/${ROUTED_STATIC_PATH}"',
                '"${EXPECTED_SOURCE}/${ROUTED_ROOT_PATH}"',
                '"${EXPECTED_SOURCE}/${ROUTED_SEAM_PATH}"',
            ),
        ),
    )
    for name, body, command in (
        ("plan", render_plan, "plan_command"),
        ("run", run_stage, "run_step"),
    ):
        for label, next_label, expected_paths in gate_argv_contracts:
            gate_body = body[
                body.index(f"{command} {label} ") : body.index(
                    f"{command} {next_label} "
                )
            ]
            ordered(gate_body, expected_paths, f"{name} {label} argv")
    shellcheck_paths = (
        '"${EXPECTED_SOURCE}/${ROOT_MATRIX_PATH}"',
        '"${EXPECTED_SOURCE}/${HERMETIC_PATH}"',
        '"${EXPECTED_SOURCE}/${PREPARE_PATH}"',
        '"${EXPECTED_SOURCE}/${MODULE_LEASE_HELPER_PATH}"',
        '"${EXPECTED_SOURCE}/${ROOT_FRESH_PATH}"',
        '"${EXPECTED_SOURCE}/${FRESH_HERMETIC_PATH}"',
        '"${EXPECTED_SOURCE}/${PROVISION_PATH}"',
        '"${EXPECTED_SOURCE}/${ROOT_VETH_PATH}"',
        '"${EXPECTED_SOURCE}/${VETH_HERMETIC_PATH}"',
        '"${EXPECTED_SOURCE}/${ROUTED_SEAM_PATH}"',
        '"${EXPECTED_SOURCE}/${ROUTED_ROOT_PATH}"',
        '"${EXPECTED_SOURCE}/${ROUTED_HERMETIC_PATH}"',
    )
    plan_shellcheck = render_plan[
        render_plan.index("plan_command S7 ") : render_plan.index("plan_command S8 ")
    ]
    run_shellcheck = run_stage[
        run_stage.index("run_step S7 ") : run_stage.index(
            "require_staged_content || fail 'staged-content-postcheck'"
        )
    ]
    for name, body in (("plan", plan_shellcheck), ("run", run_shellcheck)):
        ordered(body, shellcheck_paths, f"{name} S7 shellcheck argv")
        for path in shellcheck_paths:
            if body.count(path) != 1:
                fail(f"{name} S7 shellcheck does not bind every shell path exactly once")
    if stager.count('readonly BOOTSTRAP_ROOT="/run/wg-mix-ebpf-source-bootstrap-${RUN_ID}"') != 1:
        fail("root stager has zero or multiple bootstrap roots")
    if stager.count('readonly ROOT_REALNIC_PLAN="${BOOTSTRAP_ROOT}/realnic-approved-plan.json"') != 1:
        fail("root stager has zero or multiple approved-plan authorities")
    snapshot_body = stager[
        stager.index("snapshot_realnic_plan() {") : stager.index("verify_realnic_plan() {")
    ]
    publish_order = (
        "require_completed_stage",
        "acquire_physical_interface_lock",
        "open_approved_plan_intake",
        "create_approved_plan_pending",
        "write_approved_plan_pending",
        'fsync_exact_target "${BOOTSTRAP_ROOT}" directory',
        "require_approved_plan_pending_fd",
        '/bin/ln --no-target-directory --',
        'require_approved_plan_path "${ROOT_REALNIC_PLAN}"',
        'fsync_exact_target "${BOOTSTRAP_ROOT}" directory',
    )
    remaining = snapshot_body
    for literal in publish_order:
        position = remaining.find(literal)
        if position < 0:
            fail(f"realNIC durable publish order is missing {literal!r}")
        remaining = remaining[position + len(literal) :]
    if snapshot_body.count('/bin/ln --no-target-directory --') != 1:
        fail("realNIC durable publish has zero or multiple final link primitives")
    if snapshot_body.count('fsync_exact_target "${BOOTSTRAP_ROOT}" directory') != 2:
        fail("realNIC durable publish does not fsync the parent before and after link")
    verify_body = stager[
        stager.index("verify_realnic_plan() {") : stager.index("run_stage() {")
    ]
    if "USER_REALNIC_PLAN" in verify_body or "write_approved_plan_pending" in verify_body:
        fail("realNIC restore verification reopens or recopies user intake")
    if "published.v1" in stager or "publish-receipt" in stager:
        fail("root stager introduced a second approved-plan terminal authority")
    redundant_manifest_fields = (
        "manifest_line physical_interface_lock_interface",
        "manifest_line legacy_matrix_restore_cells",
        "manifest_line legacy_retirement_reservation",
        "manifest_line realnic_soak_window_seconds",
        "manifest_line realnic_plan_intake_name",
        "manifest_line realnic_root_plan",
    )
    for literal in redundant_manifest_fields:
        if literal in binder:
            fail(f"binder repeats derivable manifest field {literal}")

    required_provisioner = (
        "--check",
        "--apply",
        "BPFTOOL_VERSION_COMMAND",
        "/usr/sbin/bpftool -V",
        "missing_packages=",
        "plan_complete planned_commands_executed=0 writes=0 automatic_cleanup=0",
    )
    for literal in required_provisioner:
        if literal not in provisioner:
            fail(f"reviewed provisioner contract is missing {literal!r}")
    if "/usr/sbin/bpftool version" in provisioner:
        fail("reviewed provisioner retains the legacy bpftool version argv")

    matrix_forbidden = (
        "chroot",
        "nsenter",
        "--privileged",
        "find -delete",
        "rm -rf",
        "/usr/sbin/ethtool",
        "/usr/sbin/ip",
        "/usr/sbin/bpftool",
        "/usr/bin/iperf3",
        "--restore-cell",
    )
    for literal in matrix_forbidden:
        if literal in matrix:
            fail(f"existing matrix contains prohibited literal: {literal}")
    if "readonly RUN_ID='c8e41d73'" not in matrix:
        fail("existing matrix run identity changed")
    for literal in (
        "REALHOST_V6_LEGACY_CONTROLLER_AUTHORITY state=retired controller_entries=0 restore_entries=0",
        "REALHOST_V6_HISTORICAL_RECOVERY package=frozen-original-package timing=before-final-staging",
        "legacy-matrix-retired-use-frozen-original-package-before-final-staging",
    ):
        if literal not in matrix:
            fail(f"retired matrix contract is missing {literal!r}")

    print("static v6 binder/controller/transport/stager safety contract: PASS")


if __name__ == "__main__":
    main()
