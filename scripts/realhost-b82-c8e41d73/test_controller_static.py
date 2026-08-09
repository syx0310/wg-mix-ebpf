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
        rf"(?ms)^readonly -a {re.escape(name)}=\(\n(?P<body>.*?)^\)\n", payload
    )
    if not match:
        fail(f"cannot isolate Bash array {name}")
    return match.group("body")


def tcl_proc(payload: str, name: str) -> str:
    match = re.search(
        rf"(?ms)^proc {re.escape(name)} \{{[^\n]*\}} \{{\n(?P<body>.*?)^\}}\n",
        payload,
    )
    if not match:
        fail(f"cannot isolate Tcl procedure {name}")
    return match.group("body")


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

    production = {
        binder_path.name: binder,
        controller_path.name: controller,
        transport_path.name: transport,
        stager_path.name: stager,
        fresh_path.name: fresh,
    }
    forbidden_patterns = (
        r"\brm\s+-[^\n]*r",
        r"\brmdir\b",
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
        "bootstrap-provisioner-readlink bootstrap-provisioner-stat bootstrap-provisioner-sha",
        "bootstrap-stager-readlink bootstrap-stager-stat bootstrap-stager-sha",
        "STAGE_OPERATIONS=(stage-snapshot stage-plan stage-run)",
        "state_transition PACKAGE_BOUND BOOTSTRAP_ONLY",
        "state_transition BOOTSTRAP_ONLY PROVISION_CHECK",
        "state_transition PROVISION_CHECK AWAIT_APPLY",
        "state_transition AWAIT_APPLY PROVISION_APPLY",
        "state_transition PROVISION_APPLY POSTFLIGHT",
        "run_operation execute provision-apply",
        "B82_V6_PROVISION_AWAIT_APPLY",
        "automatic_apply=0",
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
        "stage-realnic-plan-snapshot realnic-run",
        "stage-realnic-plan-verify",
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
    if stale_calls != ("plan", "execute", "execute"):
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
    ordered(
        bash_function(controller, "execute_prepare"),
        (
            'for operation in "${BASE_IDENTITY_OPERATIONS[@]}"; do',
            "run_prepare_new_stale_gate execute || return $?",
            "run_operation execute package-parent-stat || return $?",
            "run_operation execute package-mkdir || return $?",
        ),
        "execute prepare-new stale gate",
    )
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
    realnic_run = controller[
        controller.index("execute_realnic_run() {") : controller.index(
            "execute_realnic_restore() {"
        )
    ]
    run_order = (
        "verify_local_approved_plan",
        "scp-realnic-approved-plan verify-sha-realnic-approved-plan",
        "verify-stat-realnic-approved-plan stage-realnic-plan-snapshot realnic-run",
    )
    positions = [realnic_run.index(item) for item in run_order]
    if positions != sorted(positions):
        fail("realNIC run does not use the single fixed intake-before-run sequence")
    realnic_restore = controller[
        controller.index("execute_realnic_restore() {") : controller.index("main() {")
    ]
    if "scp-realnic-approved-plan" in realnic_restore or realnic_restore.count(
        "stage-realnic-plan-verify"
    ) != 1:
        fail("realNIC restore recopies intake or lacks one root snapshot verification")
    prepare_body = controller[
        controller.index("execute_prepare() {") : controller.index("execute_provision_apply() {")
    ]
    if "run_operation execute provision-apply" in prepare_body:
        fail("prepare can trigger provisioning apply")
    apply_body = controller[
        controller.index("execute_provision_apply() {") : controller.index("main() {")
    ]
    if apply_body.count("run_operation execute provision-apply") != 1:
        fail("explicit apply path does not contain exactly one fixed apply operation")
    apply_order = (
        "verify_remote_package || return $?",
        "run_provision_check || return $?",
        "state_transition PROVISION_CHECK AWAIT_APPLY",
        "state_transition AWAIT_APPLY PROVISION_APPLY",
        "verify_provisioner || return $?",
        "run_operation execute provision-apply",
        "verify_provisioner || return $?",
        "run_provision_check || return $?",
        "state_transition PROVISION_APPLY POSTFLIGHT",
        "execute_postflight",
    )
    remaining = apply_body
    for literal in apply_order:
        position = remaining.find(literal)
        if position < 0:
            fail(f"explicit apply order is missing {literal!r}")
        remaining = remaining[position + len(literal) :]
    postflight_body = controller[
        controller.index("execute_postflight() {") : controller.index("execute_prepare() {")
    ]
    postflight_order = (
        "verify_remote_package || return $?",
        '"${POSTFLIGHT_OPERATIONS[@]}" controller-shellcheck hermetic-matrix',
        "verify_stager || return $?",
        '"${STAGE_OPERATIONS[@]}"',
        "B82_V6_CONTROLLER_POSTFLIGHT_COMPLETE",
    )
    positions = [postflight_body.index(item) for item in postflight_order]
    if positions != sorted(positions):
        fail("postflight no longer performs full preflight before staging")

    required_transport = (
        'set action [lindex $argv 7]',
        'if {$action eq "plan"}',
        "credential_read=0 network_operations=0",
        'if {[catch {open $credential_path r} credential_file]}',
        'send -- "$password\\r"',
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
        '($action eq "execute" && $operation eq "realnic-plan")}',
        'fail "action-operation" 65',
    )
    ordered(transport_main, required_action_guard, "transport action/operation gate")

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
    ordinary_execute = transport_main[transport_main.index("set timeout $timeout_seconds") :]
    ordered(
        ordinary_execute,
        (
            "if {[catch {wait -i $spawn_id} wait_status]}",
            'fail "child-wait-status" 78',
            "if {[catch {clean_child_exit_status $wait_status} child_rc]}",
            'fail "child-wait-status" 78',
            "if {$child_rc != 0}",
            "if {$assertion eq \"provision-check\"}",
            "assert_output $assertion $captured_output",
        ),
        "ordinary execute signal fail-closed path",
    )
    if transport.index('if {$action eq "plan"}') > transport.index("open $credential_path r"):
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
