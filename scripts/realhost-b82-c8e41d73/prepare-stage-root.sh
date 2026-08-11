#!/usr/bin/env bash
set -u
set -o pipefail
umask 077

readonly RUN_ID='c8e41d73'
readonly PACKAGE_ID='4f2a9b61'
readonly R2_RETIRE_ID='c8e41d73-f75fe7678cfd-r2'
readonly R2_PREDECESSOR_COMMIT='f75fe7678cfdecf08173fd201be5c055417d6e11'
readonly R2_PREDECESSOR_MANIFEST_SHA256='2d6c6caac080b599fbfa0f73c64f6976cf30d1504fc506ebd39c638b2f9449e3'
readonly EXPECTED_REMOTE_PACKAGE="/home/siyixuan/wg-mix-ebpf-test/unpriv-${PACKAGE_ID}"
readonly BOOTSTRAP_ROOT="/run/wg-mix-ebpf-source-bootstrap-${RUN_ID}"
readonly EXPECTED_SELF="${BOOTSTRAP_ROOT}/prepare-stage-root.sh"
readonly USER_MANIFEST="${EXPECTED_REMOTE_PACKAGE}/package-manifest.v1"
readonly USER_BUNDLE="${EXPECTED_REMOTE_PACKAGE}/source-${PACKAGE_ID}.bundle"
readonly USER_REALNIC_PLAN="${EXPECTED_REMOTE_PACKAGE}/realnic-approved-plan.json"
readonly SNAPSHOT_MANIFEST="${BOOTSTRAP_ROOT}/package-manifest.v1"
readonly SNAPSHOT_BUNDLE="${BOOTSTRAP_ROOT}/source-${PACKAGE_ID}.bundle"
readonly ROOT_REALNIC_PLAN="${BOOTSTRAP_ROOT}/realnic-approved-plan.json"
readonly STAGES_ROOT='/run/wg-mix-ebpf-source-stages'
readonly STAGE_ROOT="${STAGES_ROOT}/${RUN_ID}"
readonly EXPECTED_SOURCE="${STAGE_ROOT}/source"
readonly BINDING_MARKER="${STAGE_ROOT}/binding.v1"
readonly MODULE_LEASE_LOCK="${STAGE_ROOT}/checksum-module-lease.v1.lock"
readonly PHYSICAL_INTERFACE_LOCK='/run/wg-mix-ebpf-realnic-physical-interface.v1.lock'
readonly PHYSICAL_INTERFACE_LOCK_INTERFACE='ens33'
readonly LEGACY_RETIREMENT_RESERVATION="${STAGE_ROOT}/realhost-v6-6bd913ac"
readonly LEGACY_RETIREMENT_RESERVATION_SHAPE='root:root:600:1:0:regular file'
readonly MODULE_LEASE_HELPER_RELATIVE="scripts/realhost-b82-${RUN_ID}/checksum-module-lease.sh"
readonly EXPECTED_HOSTNAME='ubuntu-2604-test'
readonly EXPECTED_KERNEL='7.0.0-28-generic'
readonly EXPECTED_MACHINE_ID='9db3fb717cc74974b2a6b243d67f67b9'
readonly R2_USER_INTAKE="/home/siyixuan/wg-mix-ebpf-test/retire-postflight-${R2_RETIRE_ID}.intake"
readonly R2_HOME_QROOT="/home/.wg-mix-ebpf-retirement-${R2_RETIRE_ID}"
readonly R2_AUTH_ROOT="${R2_HOME_QROOT}/authority"
readonly R2_AUTH_MANIFEST="${R2_AUTH_ROOT}/package-manifest.v1"
readonly R2_AUTH_MANIFEST_PENDING="${R2_AUTH_MANIFEST}.pending"
readonly R2_AUTH_SELF="${R2_AUTH_ROOT}/prepare-stage-root.sh"
readonly R2_AUTH_SELF_PENDING="${R2_AUTH_SELF}.pending"
readonly R2_Q_INTAKE="${R2_HOME_QROOT}/intake"
readonly R2_Q_PACKAGE="${R2_HOME_QROOT}/package"
readonly R2_RUN_QROOT="/run/wg-mix-ebpf-retirement-${R2_RETIRE_ID}"
readonly R2_Q_BOOTSTRAP="${R2_RUN_QROOT}/bootstrap"
readonly R2_LOCK="${R2_RUN_QROOT}/retirement.v1.lock"
readonly R2_RECEIPT_PENDING="${R2_RUN_QROOT}/retirement-complete.v1.pending"
readonly R2_RECEIPT_FINAL="${R2_RUN_QROOT}/retirement-complete.v1"

MODE=''
MANIFEST=''
MANIFEST_SHA256=''
FORMAT=''
MANIFEST_RUN_ID=''
MANIFEST_PACKAGE_ID=''
INTEGRATION_REF=''
INTEGRATION_COMMIT=''
BUNDLE_NAME=''
BUNDLE_SHA256=''
WG_STATE=''
WG_INTERFACE=''
WG_LOCAL_ADDRESS=''
WG_PEER_ADDRESS=''
REMOTE_PACKAGE_DIR=''
REMOTE_SOURCE=''
TARGET_USER=''
TARGET_HOST=''
TARGET_HOSTNAME=''
TARGET_KERNEL=''
TARGET_MACHINE_ID=''
TARGET_INTERFACE=''
PEER_ADDRESS=''
PEER_PORT=''
SOAK_SECONDS=''
SESSION_SECONDS=''
PHYSICAL_NIC_FORWARD_AUTHORITY=''
MANIFEST_PHYSICAL_INTERFACE_LOCK=''
LEGACY_MATRIX_MODE=''
REALNIC_PROFILE=''
REALNIC_TRAFFIC_SECONDS=''
IGNORED=''
ROOT_MATRIX_PATH=''
ROOT_MATRIX_BLOB=''
ROOT_MATRIX_SHA256=''
CHECKER_PATH=''
CHECKER_BLOB=''
CHECKER_SHA256=''
HERMETIC_PATH=''
HERMETIC_BLOB=''
HERMETIC_SHA256=''
STATIC_PATH=''
STATIC_BLOB=''
STATIC_SHA256=''
MODULE_LEASE_HELPER_PATH=''
MODULE_LEASE_HELPER_BLOB=''
MODULE_LEASE_HELPER_SHA256=''
MODULE_LEASE_HERMETIC_PATH=''
MODULE_LEASE_HERMETIC_BLOB=''
MODULE_LEASE_HERMETIC_SHA256=''
MODULE_LEASE_STATIC_PATH=''
MODULE_LEASE_STATIC_BLOB=''
MODULE_LEASE_STATIC_SHA256=''
MODULE_SOURCE_PATH=''
MODULE_SOURCE_BLOB=''
MODULE_SOURCE_SHA256=''
ROOT_FRESH_PATH=''
ROOT_FRESH_BLOB=''
ROOT_FRESH_SHA256=''
FRESH_HERMETIC_PATH=''
FRESH_HERMETIC_BLOB=''
FRESH_HERMETIC_SHA256=''
FRESH_STATIC_PATH=''
FRESH_STATIC_BLOB=''
FRESH_STATIC_SHA256=''
REALNIC_PATH=''
REALNIC_BLOB=''
REALNIC_SHA256=''
REALNIC_TEST_PATH=''
REALNIC_TEST_BLOB=''
REALNIC_TEST_SHA256=''
REALNIC_STATIC_PATH=''
REALNIC_STATIC_BLOB=''
REALNIC_STATIC_SHA256=''
PREPARE_PATH=''
PREPARE_BLOB=''
PREPARE_SHA256=''
PROVISION_PATH=''
PROVISION_BLOB=''
PROVISION_SHA256=''
ROOT_VETH_PATH=''
ROOT_VETH_BLOB=''
ROOT_VETH_SHA256=''
VETH_HERMETIC_PATH=''
VETH_HERMETIC_BLOB=''
VETH_HERMETIC_SHA256=''
VETH_STATIC_PATH=''
VETH_STATIC_BLOB=''
VETH_STATIC_SHA256=''
ROUTED_SEAM_PATH=''
ROUTED_SEAM_BLOB=''
ROUTED_SEAM_SHA256=''
ROUTED_ROOT_PATH=''
ROUTED_ROOT_BLOB=''
ROUTED_ROOT_SHA256=''
ROUTED_HERMETIC_PATH=''
ROUTED_HERMETIC_BLOB=''
ROUTED_HERMETIC_SHA256=''
ROUTED_STATIC_PATH=''
ROUTED_STATIC_BLOB=''
ROUTED_STATIC_SHA256=''
PHYSICAL_INTERFACE_LOCK_FD=''
APPROVED_PLAN_SHA256=''
APPROVED_PLAN_FD=''
APPROVED_PLAN_PENDING=''
APPROVED_PLAN_PENDING_FD=''

fail() {
  printf 'B82_V6_STAGE_STOP mode=%s reason=%s rc=%s snapshot=%s stage=%s; retained=1\n' \
    "${MODE:-unparsed}" "$1" "${2:-125}" "${BOOTSTRAP_ROOT}" "${STAGE_ROOT}" >&2
  exit "${2:-125}"
}

usage() {
  printf '%s\n' \
    "usage: $0 {snapshot-plan|snapshot|plan|run} --manifest ABSOLUTE --manifest-sha256 64-lowercase-hex" \
    "       $0 {realnic-plan-snapshot|realnic-plan-verify} --manifest ABSOLUTE --manifest-sha256 64-lowercase-hex --approved-plan-sha256 64-lowercase-hex" \
    "       $0 {retire-postflight-f75fe7678cfd-r2|verify-postflight-retirement-r2} --manifest ${R2_AUTH_MANIFEST} --manifest-sha256 64-lowercase-hex" >&2
}

sha256_file() {
  local line
  if [[ -x /usr/bin/sha256sum ]]; then
    line="$(/usr/bin/sha256sum -- "$1")" || return $?
  elif [[ -x /usr/bin/shasum ]]; then
    line="$(/usr/bin/shasum -a 256 -- "$1")" || return $?
  else
    return 69
  fi
  line="${line%% *}"
  [[ "${line}" =~ ^[0-9a-f]{64}$ ]] || return 65
  printf '%s\n' "${line}"
}

valid_sha256() {
  [[ "$1" =~ ^[0-9a-f]{64}$ && ! "$1" =~ ^0{64}$ && ! "$1" =~ ^f{64}$ ]]
}

parse_arguments() {
  (($# >= 1)) || { usage; return 64; }
  MODE="$1"
  shift
  case "${MODE}" in
    snapshot-plan | snapshot | plan | run | \
      retire-postflight-f75fe7678cfd-r2 | verify-postflight-retirement-r2)
      (($# == 4)) || { usage; return 64; }
      ;;
    realnic-plan-snapshot | realnic-plan-verify)
      (($# == 6)) || { usage; return 64; }
      ;;
    *) return 64 ;;
  esac
  [[ "$1" == '--manifest' && "$3" == '--manifest-sha256' ]] || return 64
  MANIFEST="$2"
  MANIFEST_SHA256="$4"
  if [[ "${MODE}" == realnic-plan-* ]]; then
    [[ "$5" == '--approved-plan-sha256' ]] || return 64
    APPROVED_PLAN_SHA256="$6"
    valid_sha256 "${APPROVED_PLAN_SHA256}" || return 65
    APPROVED_PLAN_PENDING="${ROOT_REALNIC_PLAN}.pending.${APPROVED_PLAN_SHA256}"
  fi
  [[ "${MANIFEST}" == /* ]] || return 65
  valid_sha256 "${MANIFEST_SHA256}" || return 65
}

read_manifest_field() {
  local expected="$1" destination="$2" key value extra
  IFS=$'\t' read -r key value extra <&3 || return 65
  [[ "${key}" == "${expected}" && -n "${value}" && -z "${extra}" ]] || return 65
  printf -v "${destination}" '%s' "${value}"
}

require_manifest_fd_without_nul() {
  /usr/bin/python3 -B -I -c '
import os
import sys

try:
    descriptor = int(sys.argv[1])
    offset = 0
    while True:
        chunk = os.pread(descriptor, 65536, offset)
        if not chunk:
            raise SystemExit(0)
        if b"\0" in chunk:
            raise SystemExit(65)
        offset += len(chunk)
except (OSError, ValueError):
    raise SystemExit(66)
' "$1"
}

load_manifest() {
  local unexpected='' rc
  exec 3<"${MANIFEST}" || return 66
  require_manifest_fd_without_nul 3 || {
    rc=$?
    exec 3<&-
    return "${rc}"
  }
  if ! {
    read_manifest_field format FORMAT &&
    read_manifest_field run_id MANIFEST_RUN_ID &&
    read_manifest_field package_id MANIFEST_PACKAGE_ID &&
    read_manifest_field integration_ref INTEGRATION_REF &&
    read_manifest_field integration_commit INTEGRATION_COMMIT &&
    read_manifest_field bundle_name BUNDLE_NAME &&
    read_manifest_field bundle_sha256 BUNDLE_SHA256 &&
    read_manifest_field history_verification IGNORED &&
    read_manifest_field history_commit_count IGNORED &&
    read_manifest_field history_roots_sha256 IGNORED &&
    read_manifest_field history_objects_sha256 IGNORED &&
    read_manifest_field wg_state WG_STATE &&
    read_manifest_field wg_interface WG_INTERFACE &&
    read_manifest_field wg_local_address WG_LOCAL_ADDRESS &&
    read_manifest_field wg_peer_address WG_PEER_ADDRESS &&
    read_manifest_field local_repository IGNORED &&
    read_manifest_field local_package_dir IGNORED &&
    read_manifest_field remote_package_dir REMOTE_PACKAGE_DIR &&
    read_manifest_field remote_source REMOTE_SOURCE &&
    read_manifest_field target_user TARGET_USER &&
    read_manifest_field target_host TARGET_HOST &&
    read_manifest_field target_hostname TARGET_HOSTNAME &&
    read_manifest_field target_kernel TARGET_KERNEL &&
    read_manifest_field target_machine_id TARGET_MACHINE_ID &&
    read_manifest_field target_interface TARGET_INTERFACE &&
    read_manifest_field peer_address PEER_ADDRESS &&
    read_manifest_field peer_port PEER_PORT &&
    read_manifest_field soak_seconds SOAK_SECONDS &&
    read_manifest_field session_seconds SESSION_SECONDS &&
    read_manifest_field physical_nic_forward_authority PHYSICAL_NIC_FORWARD_AUTHORITY &&
    read_manifest_field physical_interface_lock MANIFEST_PHYSICAL_INTERFACE_LOCK &&
    read_manifest_field legacy_matrix_mode LEGACY_MATRIX_MODE &&
    read_manifest_field realnic_profile REALNIC_PROFILE &&
    read_manifest_field realnic_traffic_seconds REALNIC_TRAFFIC_SECONDS &&
    read_manifest_field bind_final_package_sh_path IGNORED &&
    read_manifest_field bind_final_package_sh_blob IGNORED &&
    read_manifest_field bind_final_package_sh_sha256 IGNORED &&
    read_manifest_field controller_sh_path IGNORED &&
    read_manifest_field controller_sh_blob IGNORED &&
    read_manifest_field controller_sh_sha256 IGNORED &&
    read_manifest_field locked_transport_exp_path IGNORED &&
    read_manifest_field locked_transport_exp_blob IGNORED &&
    read_manifest_field locked_transport_exp_sha256 IGNORED &&
    read_manifest_field root_matrix_n_r_sh_path ROOT_MATRIX_PATH &&
    read_manifest_field root_matrix_n_r_sh_blob ROOT_MATRIX_BLOB &&
    read_manifest_field root_matrix_n_r_sh_sha256 ROOT_MATRIX_SHA256 &&
    read_manifest_field check_realhost_iperf_py_path CHECKER_PATH &&
    read_manifest_field check_realhost_iperf_py_blob CHECKER_BLOB &&
    read_manifest_field check_realhost_iperf_py_sha256 CHECKER_SHA256 &&
    read_manifest_field test_hermetic_matrix_sh_path HERMETIC_PATH &&
    read_manifest_field test_hermetic_matrix_sh_blob HERMETIC_BLOB &&
    read_manifest_field test_hermetic_matrix_sh_sha256 HERMETIC_SHA256 &&
    read_manifest_field test_matrix_static_py_path STATIC_PATH &&
    read_manifest_field test_matrix_static_py_blob STATIC_BLOB &&
    read_manifest_field test_matrix_static_py_sha256 STATIC_SHA256 &&
    read_manifest_field checksum_module_lease_sh_path MODULE_LEASE_HELPER_PATH &&
    read_manifest_field checksum_module_lease_sh_blob MODULE_LEASE_HELPER_BLOB &&
    read_manifest_field checksum_module_lease_sh_sha256 MODULE_LEASE_HELPER_SHA256 &&
    read_manifest_field test_hermetic_checksum_module_lease_sh_path MODULE_LEASE_HERMETIC_PATH &&
    read_manifest_field test_hermetic_checksum_module_lease_sh_blob MODULE_LEASE_HERMETIC_BLOB &&
    read_manifest_field test_hermetic_checksum_module_lease_sh_sha256 MODULE_LEASE_HERMETIC_SHA256 &&
    read_manifest_field test_checksum_module_lease_static_py_path MODULE_LEASE_STATIC_PATH &&
    read_manifest_field test_checksum_module_lease_static_py_blob MODULE_LEASE_STATIC_BLOB &&
    read_manifest_field test_checksum_module_lease_static_py_sha256 MODULE_LEASE_STATIC_SHA256 &&
    read_manifest_field wg_mix_faketcp_checksum_c_path MODULE_SOURCE_PATH &&
    read_manifest_field wg_mix_faketcp_checksum_c_blob MODULE_SOURCE_BLOB &&
    read_manifest_field wg_mix_faketcp_checksum_c_sha256 MODULE_SOURCE_SHA256 &&
    read_manifest_field root_fresh_verifier_gate_sh_path ROOT_FRESH_PATH &&
    read_manifest_field root_fresh_verifier_gate_sh_blob ROOT_FRESH_BLOB &&
    read_manifest_field root_fresh_verifier_gate_sh_sha256 ROOT_FRESH_SHA256 &&
    read_manifest_field test_hermetic_fresh_verifier_gate_sh_path FRESH_HERMETIC_PATH &&
    read_manifest_field test_hermetic_fresh_verifier_gate_sh_blob FRESH_HERMETIC_BLOB &&
    read_manifest_field test_hermetic_fresh_verifier_gate_sh_sha256 FRESH_HERMETIC_SHA256 &&
    read_manifest_field test_fresh_verifier_gate_static_py_path FRESH_STATIC_PATH &&
    read_manifest_field test_fresh_verifier_gate_static_py_blob FRESH_STATIC_BLOB &&
    read_manifest_field test_fresh_verifier_gate_static_py_sha256 FRESH_STATIC_SHA256 &&
    read_manifest_field prepare_stage_root_sh_path PREPARE_PATH &&
    read_manifest_field prepare_stage_root_sh_blob PREPARE_BLOB &&
    read_manifest_field prepare_stage_root_sh_sha256 PREPARE_SHA256 &&
    read_manifest_field realnic_acceptance_py_path REALNIC_PATH &&
    read_manifest_field realnic_acceptance_py_blob REALNIC_BLOB &&
    read_manifest_field realnic_acceptance_py_sha256 REALNIC_SHA256 &&
    read_manifest_field test_realnic_acceptance_py_path REALNIC_TEST_PATH &&
    read_manifest_field test_realnic_acceptance_py_blob REALNIC_TEST_BLOB &&
    read_manifest_field test_realnic_acceptance_py_sha256 REALNIC_TEST_SHA256 &&
    read_manifest_field test_realnic_acceptance_static_py_path REALNIC_STATIC_PATH &&
    read_manifest_field test_realnic_acceptance_static_py_blob REALNIC_STATIC_BLOB &&
    read_manifest_field test_realnic_acceptance_static_py_sha256 REALNIC_STATIC_SHA256 &&
    read_manifest_field provision_ubuntu_test_host_sh_path PROVISION_PATH &&
    read_manifest_field provision_ubuntu_test_host_sh_blob PROVISION_BLOB &&
    read_manifest_field provision_ubuntu_test_host_sh_sha256 PROVISION_SHA256 &&
    read_manifest_field root_veth_n_r_sh_path ROOT_VETH_PATH &&
    read_manifest_field root_veth_n_r_sh_blob ROOT_VETH_BLOB &&
    read_manifest_field root_veth_n_r_sh_sha256 ROOT_VETH_SHA256 &&
    read_manifest_field test_hermetic_veth_runner_sh_path VETH_HERMETIC_PATH &&
    read_manifest_field test_hermetic_veth_runner_sh_blob VETH_HERMETIC_BLOB &&
    read_manifest_field test_hermetic_veth_runner_sh_sha256 VETH_HERMETIC_SHA256 &&
    read_manifest_field test_veth_runner_static_py_path VETH_STATIC_PATH &&
    read_manifest_field test_veth_runner_static_py_blob VETH_STATIC_BLOB &&
    read_manifest_field test_veth_runner_static_py_sha256 VETH_STATIC_SHA256 &&
    read_manifest_field controller_seam_sh_path ROUTED_SEAM_PATH &&
    read_manifest_field controller_seam_sh_blob ROUTED_SEAM_BLOB &&
    read_manifest_field controller_seam_sh_sha256 ROUTED_SEAM_SHA256 &&
    read_manifest_field root_routed_veth_n_r_sh_path ROUTED_ROOT_PATH &&
    read_manifest_field root_routed_veth_n_r_sh_blob ROUTED_ROOT_BLOB &&
    read_manifest_field root_routed_veth_n_r_sh_sha256 ROUTED_ROOT_SHA256 &&
    read_manifest_field test_hermetic_routed_veth_harness_sh_path ROUTED_HERMETIC_PATH &&
    read_manifest_field test_hermetic_routed_veth_harness_sh_blob ROUTED_HERMETIC_BLOB &&
    read_manifest_field test_hermetic_routed_veth_harness_sh_sha256 ROUTED_HERMETIC_SHA256 &&
    read_manifest_field test_routed_veth_harness_static_py_path ROUTED_STATIC_PATH &&
    read_manifest_field test_routed_veth_harness_static_py_blob ROUTED_STATIC_BLOB &&
    read_manifest_field test_routed_veth_harness_static_py_sha256 ROUTED_STATIC_SHA256
  }; then
    exec 3<&-
    return 65
  fi
  if IFS= read -r unexpected <&3 || [[ -n "${unexpected}" ]]; then
    exec 3<&-
    return 65
  fi
  exec 3<&-
}

validate_manifest() {
  load_manifest || return $?
  [[ "${FORMAT}" == 'wg-mix-ebpf-b82-v6-package-v5' &&
    "${MANIFEST_RUN_ID}" == "${RUN_ID}" && "${MANIFEST_PACKAGE_ID}" == "${PACKAGE_ID}" &&
    "${INTEGRATION_REF}" =~ ^refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]{0,180}$ &&
    "${INTEGRATION_REF}" != *'..'* && "${INTEGRATION_REF}" != *'//'* &&
    "${INTEGRATION_COMMIT}" =~ ^[0-9a-f]{40}$ &&
    "${BUNDLE_NAME}" == "source-${PACKAGE_ID}.bundle" &&
    "${REMOTE_PACKAGE_DIR}" == "${EXPECTED_REMOTE_PACKAGE}" &&
    "${REMOTE_SOURCE}" == "${EXPECTED_SOURCE}" &&
    "${TARGET_USER}" == 'siyixuan' && "${TARGET_HOST}" == '192.168.10.82' &&
    "${TARGET_HOSTNAME}" == "${EXPECTED_HOSTNAME}" && "${TARGET_KERNEL}" == "${EXPECTED_KERNEL}" &&
    "${TARGET_MACHINE_ID}" == "${EXPECTED_MACHINE_ID}" && "${TARGET_INTERFACE}" == 'ens33' &&
    "${PEER_ADDRESS}" == '47.116.202.155' && "${PEER_PORT}" == '5201' &&
    "${SOAK_SECONDS}" == '3600' && "${SESSION_SECONDS}" == '300' &&
    "${PHYSICAL_NIC_FORWARD_AUTHORITY}" == 'realnic-acceptance-v1' &&
    "${MANIFEST_PHYSICAL_INTERFACE_LOCK}" == "${PHYSICAL_INTERFACE_LOCK}" &&
    "${LEGACY_MATRIX_MODE}" == 'retired' &&
    "${REALNIC_PROFILE}" == 'acceptance' && "${REALNIC_TRAFFIC_SECONDS}" == '30' &&
    "${TARGET_INTERFACE}" == "${PHYSICAL_INTERFACE_LOCK_INTERFACE}" &&
    "${SESSION_SECONDS}" == '300' ]] || return 65
  valid_sha256 "${BUNDLE_SHA256}" && valid_sha256 "${ROOT_MATRIX_SHA256}" &&
    valid_sha256 "${CHECKER_SHA256}" && valid_sha256 "${HERMETIC_SHA256}" &&
    valid_sha256 "${STATIC_SHA256}" && valid_sha256 "${MODULE_LEASE_HELPER_SHA256}" &&
    valid_sha256 "${MODULE_LEASE_HERMETIC_SHA256}" &&
    valid_sha256 "${MODULE_LEASE_STATIC_SHA256}" && valid_sha256 "${MODULE_SOURCE_SHA256}" &&
    valid_sha256 "${ROOT_FRESH_SHA256}" && valid_sha256 "${FRESH_HERMETIC_SHA256}" &&
    valid_sha256 "${FRESH_STATIC_SHA256}" && valid_sha256 "${PREPARE_SHA256}" &&
    valid_sha256 "${REALNIC_SHA256}" && valid_sha256 "${REALNIC_TEST_SHA256}" &&
    valid_sha256 "${REALNIC_STATIC_SHA256}" &&
    valid_sha256 "${PROVISION_SHA256}" && valid_sha256 "${ROOT_VETH_SHA256}" &&
    valid_sha256 "${VETH_HERMETIC_SHA256}" && valid_sha256 "${VETH_STATIC_SHA256}" &&
    valid_sha256 "${ROUTED_SEAM_SHA256}" && valid_sha256 "${ROUTED_ROOT_SHA256}" &&
    valid_sha256 "${ROUTED_HERMETIC_SHA256}" && valid_sha256 "${ROUTED_STATIC_SHA256}" || return 65
  [[ "${ROOT_MATRIX_BLOB}" =~ ^[0-9a-f]{40}$ && "${CHECKER_BLOB}" =~ ^[0-9a-f]{40}$ &&
    "${HERMETIC_BLOB}" =~ ^[0-9a-f]{40}$ && "${STATIC_BLOB}" =~ ^[0-9a-f]{40}$ &&
    "${MODULE_LEASE_HELPER_BLOB}" =~ ^[0-9a-f]{40}$ &&
    "${MODULE_LEASE_HERMETIC_BLOB}" =~ ^[0-9a-f]{40}$ &&
    "${MODULE_LEASE_STATIC_BLOB}" =~ ^[0-9a-f]{40}$ &&
    "${MODULE_SOURCE_BLOB}" =~ ^[0-9a-f]{40}$ &&
    "${ROOT_FRESH_BLOB}" =~ ^[0-9a-f]{40}$ &&
    "${FRESH_HERMETIC_BLOB}" =~ ^[0-9a-f]{40}$ &&
    "${FRESH_STATIC_BLOB}" =~ ^[0-9a-f]{40}$ &&
    "${PREPARE_BLOB}" =~ ^[0-9a-f]{40}$ &&
    "${REALNIC_BLOB}" =~ ^[0-9a-f]{40}$ && "${REALNIC_TEST_BLOB}" =~ ^[0-9a-f]{40}$ &&
    "${REALNIC_STATIC_BLOB}" =~ ^[0-9a-f]{40}$ && "${PROVISION_BLOB}" =~ ^[0-9a-f]{40}$ &&
    "${ROOT_VETH_BLOB}" =~ ^[0-9a-f]{40}$ && "${VETH_HERMETIC_BLOB}" =~ ^[0-9a-f]{40}$ &&
    "${VETH_STATIC_BLOB}" =~ ^[0-9a-f]{40}$ && "${ROUTED_SEAM_BLOB}" =~ ^[0-9a-f]{40}$ &&
    "${ROUTED_ROOT_BLOB}" =~ ^[0-9a-f]{40}$ && "${ROUTED_HERMETIC_BLOB}" =~ ^[0-9a-f]{40}$ &&
    "${ROUTED_STATIC_BLOB}" =~ ^[0-9a-f]{40}$ &&
    -n "${IGNORED}" ]] || return 65
  [[ "${ROOT_MATRIX_PATH}" == "scripts/realhost-b82-${RUN_ID}/root-matrix-n-r.sh" &&
    "${CHECKER_PATH}" == "scripts/realhost-b82-${RUN_ID}/check-realhost-iperf.py" &&
    "${HERMETIC_PATH}" == "scripts/realhost-b82-${RUN_ID}/test-hermetic-matrix.sh" &&
    "${STATIC_PATH}" == "scripts/realhost-b82-${RUN_ID}/test_matrix_static.py" &&
    "${MODULE_LEASE_HELPER_PATH}" == "${MODULE_LEASE_HELPER_RELATIVE}" &&
    "${MODULE_LEASE_HERMETIC_PATH}" == "scripts/realhost-b82-${RUN_ID}/test-hermetic-checksum-module-lease.sh" &&
    "${MODULE_LEASE_STATIC_PATH}" == "scripts/realhost-b82-${RUN_ID}/test_checksum_module_lease_static.py" &&
    "${MODULE_SOURCE_PATH}" == 'kernel/faketcp_checksum/wg_mix_faketcp_checksum.c' &&
    "${ROOT_FRESH_PATH}" == "scripts/realhost-b82-${RUN_ID}/root-fresh-verifier-gate.sh" &&
    "${FRESH_HERMETIC_PATH}" == "scripts/realhost-b82-${RUN_ID}/test-hermetic-fresh-verifier-gate.sh" &&
    "${FRESH_STATIC_PATH}" == "scripts/realhost-b82-${RUN_ID}/test_fresh_verifier_gate_static.py" &&
    "${PREPARE_PATH}" == "scripts/realhost-b82-${RUN_ID}/prepare-stage-root.sh" &&
    "${REALNIC_PATH}" == 'scripts/realhost-b82-acceptance-v1/realnic_acceptance.py' &&
    "${REALNIC_TEST_PATH}" == 'scripts/realhost-b82-acceptance-v1/test_realnic_acceptance.py' &&
    "${REALNIC_STATIC_PATH}" == 'scripts/realhost-b82-acceptance-v1/test_realnic_acceptance_static.py' &&
    "${PROVISION_PATH}" == 'scripts/provision-ubuntu-test-host.sh' &&
    "${ROOT_VETH_PATH}" == "scripts/realhost-b82-${RUN_ID}/root-veth-n-r.sh" &&
    "${VETH_HERMETIC_PATH}" == "scripts/realhost-b82-${RUN_ID}/test-hermetic-veth-runner.sh" &&
    "${VETH_STATIC_PATH}" == "scripts/realhost-b82-${RUN_ID}/test_veth_runner_static.py" &&
    "${ROUTED_SEAM_PATH}" == 'scripts/realhost-b82-routed-veth-v1/controller-seam.sh' &&
    "${ROUTED_ROOT_PATH}" == 'scripts/realhost-b82-routed-veth-v1/root-routed-veth-n-r.sh' &&
    "${ROUTED_HERMETIC_PATH}" == 'scripts/realhost-b82-routed-veth-v1/test-hermetic-routed-veth-harness.sh' &&
    "${ROUTED_STATIC_PATH}" == 'scripts/realhost-b82-routed-veth-v1/test_routed_veth_harness_static.py' ]] || return 65
  case "${WG_STATE}" in
    bound) [[ "${WG_INTERFACE}" != 'absent' && "${WG_LOCAL_ADDRESS}" != 'absent' && "${WG_PEER_ADDRESS}" != 'absent' ]] ;;
    absent) [[ "${WG_INTERFACE}" == 'absent' && "${WG_LOCAL_ADDRESS}" == 'absent' && "${WG_PEER_ADDRESS}" == 'absent' ]] ;;
    *) return 65 ;;
  esac
}

quote_argv() {
  printf '%q ' "$@"
}

plan_command() {
  local label="$1"
  shift
  printf '%s argv=' "${label}"
  quote_argv "$@"
  printf '\n'
}

render_snapshot_plan() {
  printf 'B82_V6_SNAPSHOT_PLAN run_id=%s manifest_sha256=%s source_parent=%s destination_parent=%s\n' \
    "${RUN_ID}" "${MANIFEST_SHA256}" "${EXPECTED_REMOTE_PACKAGE}" "${BOOTSTRAP_ROOT}"
  plan_command C0 /usr/bin/readlink -e -- "${BOOTSTRAP_ROOT}"
  plan_command C1 /usr/bin/stat -Lc '%U:%G:%a:%F' -- "${BOOTSTRAP_ROOT}"
  plan_command C2 /usr/bin/test ! -e "${SNAPSHOT_MANIFEST}"
  plan_command C3 /usr/bin/test ! -L "${SNAPSHOT_MANIFEST}"
  plan_command C4 shell-builtin noclobber-copy "${USER_MANIFEST}" "${SNAPSHOT_MANIFEST}"
  plan_command C5 /usr/bin/test ! -e "${SNAPSHOT_BUNDLE}"
  plan_command C6 /usr/bin/test ! -L "${SNAPSHOT_BUNDLE}"
  plan_command C7 shell-builtin noclobber-copy "${USER_BUNDLE}" "${SNAPSHOT_BUNDLE}"
  plan_command C8 /usr/bin/readlink -e -- "${SNAPSHOT_MANIFEST}"
  plan_command C9 /usr/bin/stat -Lc '%U:%G:%a:%h:%F' -- "${SNAPSHOT_MANIFEST}"
  plan_command C10 /usr/bin/sha256sum -- "${SNAPSHOT_MANIFEST}"
  plan_command C11 shell-builtin parse-verified-root-manifest "${SNAPSHOT_MANIFEST}"
  plan_command C12 /usr/bin/readlink -e -- "${SNAPSHOT_BUNDLE}"
  plan_command C13 /usr/bin/stat -Lc '%U:%G:%a:%h:%F' -- "${SNAPSHOT_BUNDLE}"
  plan_command C14 /usr/bin/sha256sum -- "${SNAPSHOT_BUNDLE}"
  printf 'B82_V6_SNAPSHOT_PLAN_COMPLETE no_commands_executed=1 no_cleanup=1 failure_resources_retained=1\n'
}

render_plan() {
  local bundle="${SNAPSHOT_BUNDLE}" branch="${INTEGRATION_REF#refs/heads/}"
  printf 'B82_V6_STAGE_PLAN run_id=%s commit=%s manifest_sha256=%s wg_state=%s\n' \
    "${RUN_ID}" "${INTEGRATION_COMMIT}" "${MANIFEST_SHA256}" "${WG_STATE}"
  plan_command S0 /usr/bin/sha256sum -- "${SNAPSHOT_MANIFEST}"
  plan_command S1 /usr/bin/sha256sum -- "${bundle}"
  plan_command S2 /usr/bin/mkdir --mode=0700 -- "${STAGES_ROOT}"
  plan_command S3 /usr/bin/mkdir --mode=0700 -- "${STAGE_ROOT}"
  printf 'B82_V6_PHYSICAL_INTERFACE_LOCK path=%s interface=%s shape=root:root:600:1:regular-file create=atomic-open-if-absent\n' \
    "${PHYSICAL_INTERFACE_LOCK}" "${PHYSICAL_INTERFACE_LOCK_INTERFACE}"
  plan_command S3.physical-lock /usr/bin/flock --exclusive --nonblock \
    --conflict-exit-code 78 "${PHYSICAL_INTERFACE_LOCK}" /usr/bin/true
  plan_command S3.physical-lock-hold /usr/bin/flock --exclusive --nonblock \
    --conflict-exit-code 78 PHYSICAL_INTERFACE_LOCK_FD
  printf 'B82_V6_LEGACY_RETIREMENT_RESERVATION path=%s shape=root:root:600:1:0:regular-file creator=root-stager-O_CREAT|O_EXCL existing=reject-retain\n' \
    "${LEGACY_RETIREMENT_RESERVATION}"
  plan_command S3.legacy-reservation shell-builtin noclobber-o-excl-create \
    "${LEGACY_RETIREMENT_RESERVATION}"
  plan_command S3.lock /usr/bin/install --owner=root --group=root --mode=0600 \
    --no-target-directory -- /dev/null "${MODULE_LEASE_LOCK}"
  plan_command S4 /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C \
    GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_NO_REPLACE_OBJECTS=1 \
    /usr/bin/git -c core.hooksPath=/dev/null clone --no-local --no-checkout \
    --single-branch --branch "${branch}" -- "${bundle}" "${EXPECTED_SOURCE}"
  plan_command S5 /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C \
    GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_NO_REPLACE_OBJECTS=1 \
    /usr/bin/git -c core.hooksPath=/dev/null -C "${EXPECTED_SOURCE}" \
    checkout --detach "${INTEGRATION_COMMIT}"
  plan_command S6 /bin/bash -n "${EXPECTED_SOURCE}/${ROOT_MATRIX_PATH}" \
    "${EXPECTED_SOURCE}/${HERMETIC_PATH}" "${EXPECTED_SOURCE}/${PREPARE_PATH}" \
    "${EXPECTED_SOURCE}/${MODULE_LEASE_HELPER_PATH}" \
    "${EXPECTED_SOURCE}/${MODULE_LEASE_HERMETIC_PATH}" \
    "${EXPECTED_SOURCE}/${ROOT_FRESH_PATH}" "${EXPECTED_SOURCE}/${FRESH_HERMETIC_PATH}" \
    "${EXPECTED_SOURCE}/${PROVISION_PATH}" "${EXPECTED_SOURCE}/${ROOT_VETH_PATH}" \
    "${EXPECTED_SOURCE}/${VETH_HERMETIC_PATH}" "${EXPECTED_SOURCE}/${ROUTED_SEAM_PATH}" \
    "${EXPECTED_SOURCE}/${ROUTED_ROOT_PATH}" "${EXPECTED_SOURCE}/${ROUTED_HERMETIC_PATH}"
  plan_command S6.realnic /usr/bin/python3 -B -I "${EXPECTED_SOURCE}/${REALNIC_PATH}" --help
  plan_command S6.realnic-unit /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
    PYTHONDONTWRITEBYTECODE=1 /usr/bin/timeout --signal=TERM --kill-after=10s 10m \
    /usr/bin/python3 -B -I "${EXPECTED_SOURCE}/${REALNIC_TEST_PATH}"
  plan_command S6.realnic-static /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
    PYTHONDONTWRITEBYTECODE=1 /usr/bin/timeout --signal=TERM --kill-after=10s 2m \
    /usr/bin/python3 -B -I "${EXPECTED_SOURCE}/${REALNIC_STATIC_PATH}"
  plan_command S6.veth-hermetic /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
    /usr/bin/timeout --signal=TERM --kill-after=10s 10m \
    /bin/bash "${EXPECTED_SOURCE}/${VETH_HERMETIC_PATH}"
  plan_command S6.veth-static /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
    PYTHONDONTWRITEBYTECODE=1 /usr/bin/timeout --signal=TERM --kill-after=10s 2m \
    /usr/bin/python3 -B -I "${EXPECTED_SOURCE}/${VETH_STATIC_PATH}" \
    "${EXPECTED_SOURCE}/${ROOT_VETH_PATH}" "${EXPECTED_SOURCE}/${ROOT_MATRIX_PATH}" \
    "${EXPECTED_SOURCE}/${MODULE_LEASE_HELPER_PATH}"
  plan_command S6.routed-hermetic /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
    /usr/bin/timeout --signal=TERM --kill-after=10s 10m \
    /bin/bash "${EXPECTED_SOURCE}/${ROUTED_HERMETIC_PATH}"
  plan_command S6.routed-static /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
    PYTHONDONTWRITEBYTECODE=1 /usr/bin/timeout --signal=TERM --kill-after=10s 2m \
    /usr/bin/python3 -B -I "${EXPECTED_SOURCE}/${ROUTED_STATIC_PATH}" \
    "${EXPECTED_SOURCE}/${ROUTED_ROOT_PATH}" "${EXPECTED_SOURCE}/${ROUTED_SEAM_PATH}"
  plan_command S7 /usr/bin/shellcheck --norc --shell=bash -- \
    "${EXPECTED_SOURCE}/${ROOT_MATRIX_PATH}" "${EXPECTED_SOURCE}/${HERMETIC_PATH}" \
    "${EXPECTED_SOURCE}/${PREPARE_PATH}" "${EXPECTED_SOURCE}/${MODULE_LEASE_HELPER_PATH}" \
    "${EXPECTED_SOURCE}/${MODULE_LEASE_HERMETIC_PATH}" \
    "${EXPECTED_SOURCE}/${ROOT_FRESH_PATH}" "${EXPECTED_SOURCE}/${FRESH_HERMETIC_PATH}" \
    "${EXPECTED_SOURCE}/${PROVISION_PATH}" "${EXPECTED_SOURCE}/${ROOT_VETH_PATH}" \
    "${EXPECTED_SOURCE}/${VETH_HERMETIC_PATH}" "${EXPECTED_SOURCE}/${ROUTED_SEAM_PATH}" \
    "${EXPECTED_SOURCE}/${ROUTED_ROOT_PATH}" "${EXPECTED_SOURCE}/${ROUTED_HERMETIC_PATH}"
  plan_command S8 shell-builtin noclobber-write "${BINDING_MARKER}"
  printf 'B82_V6_REALNIC_AUTHORITY script=%s profile=%s traffic_seconds=%s soak_seconds=%s soak_window_seconds=%s approved_plan=%s snapshot=held-fd-writeall-fsync-hardlink-noclobber verify=final-pending-same-inode\n' \
    "${EXPECTED_SOURCE}/${REALNIC_PATH}" "${REALNIC_PROFILE}" "${REALNIC_TRAFFIC_SECONDS}" \
    "${SOAK_SECONDS}" "${SESSION_SECONDS}" "${ROOT_REALNIC_PLAN}"
  printf 'B82_V6_STAGE_PLAN_COMPLETE no_commands_executed=1 no_cleanup=1\n'
}

run_step() {
  local label="$1" rc started finished
  shift
  started="$(/usr/bin/date -u '+%Y-%m-%dT%H:%M:%SZ')" || return 70
  printf 'B82_V6_STAGE_EVENT utc=%s event=start step=%s argv=' "${started}" "${label}"
  quote_argv "$@"
  printf '\n'
  "$@"
  rc=$?
  finished="$(/usr/bin/date -u '+%Y-%m-%dT%H:%M:%SZ')" || return 70
  printf 'B82_V6_STAGE_EVENT utc=%s event=finish step=%s rc=%s\n' "${finished}" "${label}" "${rc}"
  return "${rc}"
}

copy_noclobber() {
  local source="$1" destination="$2"
  case "${source}:${destination}" in
    "${USER_MANIFEST}:${SNAPSHOT_MANIFEST}" | "${USER_BUNDLE}:${SNAPSHOT_BUNDLE}") ;;
    *) return 65 ;;
  esac
  [[ ! -e "${destination}" && ! -L "${destination}" ]] || return 73
  (umask 077
    set -o noclobber
    /usr/bin/cat -- "${source}" >"${destination}")
}

run_copy_step() {
  local label="$1" source="$2" destination="$3" rc started finished
  started="$(/usr/bin/date -u '+%Y-%m-%dT%H:%M:%SZ')" || return 70
  printf 'B82_V6_STAGE_EVENT utc=%s event=start step=%s argv=shell-builtin noclobber-copy ' \
    "${started}" "${label}"
  quote_argv "${source}" "${destination}"
  printf '\n'
  copy_noclobber "${source}" "${destination}"
  rc=$?
  finished="$(/usr/bin/date -u '+%Y-%m-%dT%H:%M:%SZ')" || return 70
  printf 'B82_V6_STAGE_EVENT utc=%s event=finish step=%s target=%s rc=%s\n' \
    "${finished}" "${label}" "${destination}" "${rc}"
  return "${rc}"
}

git_stage() {
  /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C \
    GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 \
    GIT_NO_REPLACE_OBJECTS=1 GIT_OPTIONAL_LOCKS=0 \
    /usr/bin/git --no-pager --no-replace-objects \
    -c core.attributesFile=/dev/null -c core.fsmonitor=false \
    -c core.hooksPath=/dev/null "$@"
}

verify_host() {
  [[ "$(/usr/bin/hostname)" == "${EXPECTED_HOSTNAME}" ]] || return 78
  [[ "$(/usr/bin/uname -r)" == "${EXPECTED_KERNEL}" ]] || return 78
  [[ "$(/usr/bin/cat /etc/machine-id)" == "${EXPECTED_MACHINE_ID}" ]] || return 78
}

require_bootstrap_root() {
  local canonical_root root_shape
  canonical_root="$(/usr/bin/readlink -e -- "${BOOTSTRAP_ROOT}")" || return 78
  [[ "${canonical_root}" == "${BOOTSTRAP_ROOT}" && -d "${BOOTSTRAP_ROOT}" &&
    ! -L "${BOOTSTRAP_ROOT}" ]] || return 78
  root_shape="$(/usr/bin/stat -Lc '%U:%G:%a:%F' -- "${BOOTSTRAP_ROOT}")" || return 78
  [[ "${root_shape}" == 'root:root:700:directory' ]] || return 78
}

require_root_owned_self_shape() {
  local canonical_self self_shape
  [[ "$(/usr/bin/id -u)" == '0' ]] || return 77
  canonical_self="$(/usr/bin/readlink -e -- "$0")" || return 78
  [[ "${canonical_self}" == "${EXPECTED_SELF}" && -f "${EXPECTED_SELF}" && ! -L "${EXPECTED_SELF}" ]] || return 78
  self_shape="$(/usr/bin/stat -Lc '%U:%G:%a:%h:%F' -- "${EXPECTED_SELF}")" || return 78
  [[ "${self_shape}" == 'root:root:700:1:regular file' ]] || return 78
}

require_root_owned_self() {
  require_root_owned_self_shape || return $?
  [[ "$(sha256_file "${EXPECTED_SELF}")" == "${PREPARE_SHA256}" ]] || return 78
}

require_snapshot_file() {
  local path="$1" expected_sha="$2" canonical_path file_shape
  case "${path}" in
    "${SNAPSHOT_MANIFEST}" | "${SNAPSHOT_BUNDLE}") ;;
    *) return 65 ;;
  esac
  canonical_path="$(/usr/bin/readlink -e -- "${path}")" || return 78
  [[ "${canonical_path}" == "${path}" && -f "${path}" && ! -L "${path}" ]] || return 78
  file_shape="$(/usr/bin/stat -Lc '%U:%G:%a:%h:%F' -- "${path}")" || return 78
  [[ "${file_shape}" == 'root:root:600:1:regular file' ]] || return 78
  [[ "$(sha256_file "${path}")" == "${expected_sha}" ]] || return 67
}

snapshot_package() {
  [[ "$(/usr/bin/id -u)" == '0' ]] || fail 'root-required' 77
  require_root_owned_self_shape || fail 'root-owned-self-shape' $?
  require_bootstrap_root || fail 'bootstrap-root' $?
  [[ "${MANIFEST}" == "${USER_MANIFEST}" ]] || fail 'snapshot-source-manifest-path' 65
  verify_host || fail 'host-identity' $?
  [[ ! -e "${SNAPSHOT_MANIFEST}" && ! -L "${SNAPSHOT_MANIFEST}" &&
    ! -e "${SNAPSHOT_BUNDLE}" && ! -L "${SNAPSHOT_BUNDLE}" ]] ||
    fail 'snapshot-destination-exists' 73
  run_copy_step C4 "${USER_MANIFEST}" "${SNAPSHOT_MANIFEST}" || fail 'manifest-copy' $?
  run_copy_step C7 "${USER_BUNDLE}" "${SNAPSHOT_BUNDLE}" || fail 'bundle-copy' $?
  require_snapshot_file "${SNAPSHOT_MANIFEST}" "${MANIFEST_SHA256}" || fail 'snapshot-manifest' $?
  MANIFEST="${SNAPSHOT_MANIFEST}"
  validate_manifest || fail 'manifest-contract' $?
  require_root_owned_self || fail 'root-owned-self' $?
  require_snapshot_file "${SNAPSHOT_BUNDLE}" "${BUNDLE_SHA256}" || fail 'snapshot-bundle' $?
  printf 'B82_V6_SNAPSHOT_COMPLETE run_id=%s manifest=%s bundle=%s retained=1\n' \
    "${RUN_ID}" "${SNAPSHOT_MANIFEST}" "${SNAPSHOT_BUNDLE}"
}

load_root_snapshot_contract() {
  [[ "$(/usr/bin/id -u)" == '0' ]] || fail 'root-required' 77
  require_root_owned_self_shape || fail 'root-owned-self-shape' $?
  require_bootstrap_root || fail 'bootstrap-root' $?
  [[ "${MANIFEST}" == "${SNAPSHOT_MANIFEST}" ]] || fail 'snapshot-manifest-path' 65
  verify_host || fail 'host-identity' $?
  require_snapshot_file "${SNAPSHOT_MANIFEST}" "${MANIFEST_SHA256}" || fail 'snapshot-manifest' $?
  validate_manifest || fail 'manifest-contract' $?
  require_root_owned_self || fail 'root-owned-self' $?
  require_snapshot_file "${SNAPSHOT_BUNDLE}" "${BUNDLE_SHA256}" || fail 'snapshot-bundle' $?
}

load_r2_retirement_authority_contract() {
  [[ "$(/usr/bin/id -u)" == '0' ]] || fail 'root-required' 77
  [[ "${MANIFEST}" == "${R2_AUTH_MANIFEST}" ]] ||
    fail 'r2-authority-manifest-path' 65
  [[ "$0" == "${R2_AUTH_SELF}" ]] || fail 'r2-authority-self-path' 65
}


render_binding_marker() {
  printf '%s\n' \
    'format=wg-mix-ebpf-b82-v6-stage-binding-v1' \
    "run_id=${RUN_ID}" "package_id=${PACKAGE_ID}" \
    "integration_ref=${INTEGRATION_REF}" "integration_commit=${INTEGRATION_COMMIT}" \
    "bundle_sha256=${BUNDLE_SHA256}" "manifest_sha256=${MANIFEST_SHA256}" \
    "wg_state=${WG_STATE}" \
    "physical_nic_forward_authority=${PHYSICAL_NIC_FORWARD_AUTHORITY}" \
    "physical_interface_lock=${PHYSICAL_INTERFACE_LOCK}" \
    "physical_interface_lock_interface=${PHYSICAL_INTERFACE_LOCK_INTERFACE}" \
    "legacy_matrix_mode=${LEGACY_MATRIX_MODE}" \
    "legacy_retirement_reservation=${LEGACY_RETIREMENT_RESERVATION}" \
    "legacy_retirement_reservation_shape=${LEGACY_RETIREMENT_RESERVATION_SHAPE}" \
    "module_lease_lock=${MODULE_LEASE_LOCK}" \
    "module_lease_helper=${EXPECTED_SOURCE}/${MODULE_LEASE_HELPER_PATH}" \
    "fresh_verifier_gate=${EXPECTED_SOURCE}/${ROOT_FRESH_PATH}" \
    "realnic_acceptance=${EXPECTED_SOURCE}/${REALNIC_PATH}" \
    "realnic_acceptance_sha256=${REALNIC_SHA256}" \
    "realnic_profile=${REALNIC_PROFILE}" \
    "realnic_traffic_seconds=${REALNIC_TRAFFIC_SECONDS}" \
    "realnic_soak_seconds=${SOAK_SECONDS}" \
    "realnic_soak_window_seconds=${SESSION_SECONDS}" \
    "realnic_approved_plan=${ROOT_REALNIC_PLAN}"
}

write_binding_marker() {
  (set -o noclobber
    render_binding_marker >"${BINDING_MARKER}")
}

require_binding_marker() {
  local canonical shape expected_sha
  canonical="$(/usr/bin/readlink -e -- "${BINDING_MARKER}")" || return 79
  [[ "${canonical}" == "${BINDING_MARKER}" && -f "${BINDING_MARKER}" && \
    ! -L "${BINDING_MARKER}" ]] || return 79
  shape="$(/usr/bin/stat -Lc '%U:%G:%a:%h:%F' -- "${BINDING_MARKER}")" || return 79
  [[ "${shape}" == 'root:root:600:1:regular file' ]] || return 79
  expected_sha="$(render_binding_marker | sha256_file /dev/stdin)" || return $?
  [[ "$(sha256_file "${BINDING_MARKER}")" == "${expected_sha}" ]]
}

require_physical_interface_lock() {
  [[ -f "${PHYSICAL_INTERFACE_LOCK}" && ! -L "${PHYSICAL_INTERFACE_LOCK}" ]] || return 79
  [[ "$(/usr/bin/stat -Lc '%U:%G:%a:%h:%s:%F' -- "${PHYSICAL_INTERFACE_LOCK}")" == \
    'root:root:600:1:0:regular file' ]]
}

acquire_physical_interface_lock() {
  local descriptor_identity path_identity
  if [[ ! -e "${PHYSICAL_INTERFACE_LOCK}" && ! -L "${PHYSICAL_INTERFACE_LOCK}" ]]; then
    run_step S3.physical-lock /usr/bin/flock --exclusive --nonblock \
      --conflict-exit-code 78 "${PHYSICAL_INTERFACE_LOCK}" /usr/bin/true || return $?
  fi
  require_physical_interface_lock || return $?
  exec {PHYSICAL_INTERFACE_LOCK_FD}<>"${PHYSICAL_INTERFACE_LOCK}" || return 79
  descriptor_identity="$(/usr/bin/stat -Lc '%d:%i' -- \
    "/proc/self/fd/${PHYSICAL_INTERFACE_LOCK_FD}")" || return 79
  path_identity="$(/usr/bin/stat -Lc '%d:%i' -- "${PHYSICAL_INTERFACE_LOCK}")" || return 79
  [[ "${descriptor_identity}" == "${path_identity}" ]] || return 79
  run_step S3.physical-lock-hold /usr/bin/flock --exclusive --nonblock \
    --conflict-exit-code 78 "${PHYSICAL_INTERFACE_LOCK_FD}" || return $?
  require_physical_interface_lock || return $?
  [[ "$(/usr/bin/stat -Lc '%d:%i' -- "${PHYSICAL_INTERFACE_LOCK}")" == \
    "${descriptor_identity}" ]]
}

create_legacy_retirement_reservation() {
  [[ ! -e "${LEGACY_RETIREMENT_RESERVATION}" && \
    ! -L "${LEGACY_RETIREMENT_RESERVATION}" ]] || return 73
  (umask 077
    set -o noclobber
    : >"${LEGACY_RETIREMENT_RESERVATION}")
}

require_legacy_retirement_reservation() {
  [[ -f "${LEGACY_RETIREMENT_RESERVATION}" && \
    ! -L "${LEGACY_RETIREMENT_RESERVATION}" ]] || return 79
  [[ "$(/usr/bin/stat -Lc '%U:%G:%a:%h:%s:%F' -- \
    "${LEGACY_RETIREMENT_RESERVATION}")" == "${LEGACY_RETIREMENT_RESERVATION_SHAPE}" ]]
}

require_module_lease_lock() {
  [[ -f "${MODULE_LEASE_LOCK}" && ! -L "${MODULE_LEASE_LOCK}" ]] || return 79
  [[ "$(/usr/bin/stat -Lc '%U:%G:%a:%h:%F' -- "${MODULE_LEASE_LOCK}")" == \
    'root:root:600:1:regular file' ]]
}

require_staged_identity() {
  local relative="$1" expected_blob="$2" expected_sha="$3"
  local expected_tree_mode="${4:-100755}" expected_file_mode="${5:-700}"
  local path canonical shape
  local mapped actual_blob tree_entry
  path="${EXPECTED_SOURCE}/${relative}"
  canonical="$(/usr/bin/readlink -e -- "${path}")" || return 79
  [[ "${canonical}" == "${path}" && -f "${path}" && ! -L "${path}" ]] || return 79
  shape="$(/usr/bin/stat -Lc '%U:%G:%a:%h:%F' -- "${path}")" || return 79
  [[ "${shape}" == "root:root:${expected_file_mode}:1:regular file" ]] || return 79
  mapped="$(git_stage -C "${EXPECTED_SOURCE}" rev-parse "${INTEGRATION_COMMIT}:${relative}")" || return 79
  tree_entry="$(git_stage -C "${EXPECTED_SOURCE}" ls-tree "${INTEGRATION_COMMIT}" -- "${relative}")" || return 79
  actual_blob="$(git_stage -C "${EXPECTED_SOURCE}" hash-object -- "${path}")" || return 79
  [[ "${tree_entry}" == "${expected_tree_mode}"$' blob '"${expected_blob}"$'\t'"${relative}" &&
    "${mapped}" == "${expected_blob}" && "${actual_blob}" == "${expected_blob}" &&
    "$(sha256_file "${path}")" == "${expected_sha}" ]]
}

require_staged_content() {
  local canonical stage_head stage_status stage_shape source_shape
  canonical="$(/usr/bin/readlink -e -- "${STAGE_ROOT}")" || return 79
  [[ "${canonical}" == "${STAGE_ROOT}" && -d "${STAGE_ROOT}" && ! -L "${STAGE_ROOT}" ]] || return 79
  stage_shape="$(/usr/bin/stat -Lc '%U:%G:%a:%F' -- "${STAGE_ROOT}")" || return 79
  [[ "${stage_shape}" == 'root:root:700:directory' ]] || return 79
  canonical="$(/usr/bin/readlink -e -- "${EXPECTED_SOURCE}")" || return 79
  [[ "${canonical}" == "${EXPECTED_SOURCE}" && -d "${EXPECTED_SOURCE}" && \
    ! -L "${EXPECTED_SOURCE}" ]] || return 79
  source_shape="$(/usr/bin/stat -Lc '%U:%G:%a:%F' -- "${EXPECTED_SOURCE}")" || return 79
  [[ "${source_shape}" == 'root:root:700:directory' ]] || return 79
  stage_head="$(git_stage -C "${EXPECTED_SOURCE}" rev-parse HEAD)" || return 79
  [[ "${stage_head}" == "${INTEGRATION_COMMIT}" ]] || return 79
  stage_status="$(git_stage -C "${EXPECTED_SOURCE}" status --porcelain=v1 \
    --untracked-files=all --ignore-submodules=none)" || return 79
  [[ -z "${stage_status}" ]] || return 79
  [[ "$(sha256_file "${EXPECTED_SOURCE}/${ROOT_MATRIX_PATH}")" == "${ROOT_MATRIX_SHA256}" &&
    "$(sha256_file "${EXPECTED_SOURCE}/${CHECKER_PATH}")" == "${CHECKER_SHA256}" &&
    "$(sha256_file "${EXPECTED_SOURCE}/${HERMETIC_PATH}")" == "${HERMETIC_SHA256}" &&
    "$(sha256_file "${EXPECTED_SOURCE}/${STATIC_PATH}")" == "${STATIC_SHA256}" &&
    "$(sha256_file "${EXPECTED_SOURCE}/${MODULE_LEASE_HELPER_PATH}")" == "${MODULE_LEASE_HELPER_SHA256}" &&
    "$(sha256_file "${EXPECTED_SOURCE}/${MODULE_LEASE_HERMETIC_PATH}")" == "${MODULE_LEASE_HERMETIC_SHA256}" &&
    "$(sha256_file "${EXPECTED_SOURCE}/${MODULE_LEASE_STATIC_PATH}")" == "${MODULE_LEASE_STATIC_SHA256}" &&
    "$(sha256_file "${EXPECTED_SOURCE}/${MODULE_SOURCE_PATH}")" == "${MODULE_SOURCE_SHA256}" &&
    "$(sha256_file "${EXPECTED_SOURCE}/${ROOT_FRESH_PATH}")" == "${ROOT_FRESH_SHA256}" &&
    "$(sha256_file "${EXPECTED_SOURCE}/${FRESH_HERMETIC_PATH}")" == "${FRESH_HERMETIC_SHA256}" &&
    "$(sha256_file "${EXPECTED_SOURCE}/${FRESH_STATIC_PATH}")" == "${FRESH_STATIC_SHA256}" &&
    "$(sha256_file "${EXPECTED_SOURCE}/${PREPARE_PATH}")" == "${PREPARE_SHA256}" &&
    "$(sha256_file "${EXPECTED_SOURCE}/${REALNIC_PATH}")" == "${REALNIC_SHA256}" &&
    "$(sha256_file "${EXPECTED_SOURCE}/${REALNIC_TEST_PATH}")" == "${REALNIC_TEST_SHA256}" &&
    "$(sha256_file "${EXPECTED_SOURCE}/${REALNIC_STATIC_PATH}")" == "${REALNIC_STATIC_SHA256}" &&
    "$(sha256_file "${EXPECTED_SOURCE}/${PROVISION_PATH}")" == "${PROVISION_SHA256}" ]] || return 79
  require_staged_identity "${MODULE_LEASE_HERMETIC_PATH}" "${MODULE_LEASE_HERMETIC_BLOB}" \
      "${MODULE_LEASE_HERMETIC_SHA256}" &&
    require_staged_identity "${MODULE_LEASE_STATIC_PATH}" "${MODULE_LEASE_STATIC_BLOB}" \
      "${MODULE_LEASE_STATIC_SHA256}" &&
    require_staged_identity "${MODULE_SOURCE_PATH}" "${MODULE_SOURCE_BLOB}" \
      "${MODULE_SOURCE_SHA256}" 100644 600 &&
    require_staged_identity "${ROOT_VETH_PATH}" "${ROOT_VETH_BLOB}" "${ROOT_VETH_SHA256}" &&
    require_staged_identity "${VETH_HERMETIC_PATH}" "${VETH_HERMETIC_BLOB}" "${VETH_HERMETIC_SHA256}" &&
    require_staged_identity "${VETH_STATIC_PATH}" "${VETH_STATIC_BLOB}" "${VETH_STATIC_SHA256}" &&
    require_staged_identity "${ROUTED_SEAM_PATH}" "${ROUTED_SEAM_BLOB}" "${ROUTED_SEAM_SHA256}" &&
    require_staged_identity "${ROUTED_ROOT_PATH}" "${ROUTED_ROOT_BLOB}" "${ROUTED_ROOT_SHA256}" &&
    require_staged_identity "${ROUTED_HERMETIC_PATH}" "${ROUTED_HERMETIC_BLOB}" "${ROUTED_HERMETIC_SHA256}" &&
    require_staged_identity "${ROUTED_STATIC_PATH}" "${ROUTED_STATIC_BLOB}" "${ROUTED_STATIC_SHA256}"
}

require_completed_stage() {
  require_staged_content || return $?
  require_physical_interface_lock || return $?
  require_legacy_retirement_reservation || return $?
  require_module_lease_lock || return $?
  require_binding_marker
}

require_approved_plan_object() {
  local object="$1" owner="$2" expected_sha="$3" expected_links="$4" shape size
  shape="$(/usr/bin/stat -Lc '%U:%G:%a:%h:%F' -- "${object}")" || return 79
  size="$(/usr/bin/stat -Lc '%s' -- "${object}")" || return 79
  [[ "${shape}" == "${owner}:600:${expected_links}:regular file" && "${size}" =~ ^[1-9][0-9]*$ &&
    "${size}" -le 16777216 && "$(sha256_file "${object}")" == "${expected_sha}" ]]
}

require_approved_plan_publish() (
  local final_identity pending_identity path canonical
  [[ "${APPROVED_PLAN_PENDING}" == \
    "${ROOT_REALNIC_PLAN}.pending.${APPROVED_PLAN_SHA256}" ]] || return 65
  for path in "${ROOT_REALNIC_PLAN}" "${APPROVED_PLAN_PENDING}"; do
    canonical="$(/usr/bin/readlink -e -- "${path}")" || return 79
    [[ "${canonical}" == "${path}" && -f "${path}" && ! -L "${path}" ]] || return 79
    require_approved_plan_object "${path}" 'root:root' \
      "${APPROVED_PLAN_SHA256}" 2 || return $?
  done
  final_identity="$(/usr/bin/stat -Lc '%d:%i' -- "${ROOT_REALNIC_PLAN}")" || return 79
  pending_identity="$(/usr/bin/stat -Lc '%d:%i' -- "${APPROVED_PLAN_PENDING}")" || return 79
  [[ "${final_identity}" == "${pending_identity}" ]]
)

require_approved_plan_path() (
  local path="$1" owner="$2" expected_sha="$3" canonical descriptor
  local descriptor_identity path_identity
  if [[ "${path}:${owner}" == "${ROOT_REALNIC_PLAN}:root:root" ]]; then
    require_approved_plan_publish
    return $?
  fi
  [[ "${path}:${owner}" == "${USER_REALNIC_PLAN}:siyixuan:siyixuan" ]] || return 65
  canonical="$(/usr/bin/readlink -e -- "${path}")" || return 79
  [[ "${canonical}" == "${path}" && -f "${path}" && ! -L "${path}" ]] || return 79
  exec {descriptor}<"${path}" || return 79
  require_approved_plan_object "/proc/self/fd/${descriptor}" "${owner}" \
    "${expected_sha}" 1 || return $?
  descriptor_identity="$(/usr/bin/stat -Lc '%d:%i' -- "/proc/self/fd/${descriptor}")" || return 79
  path_identity="$(/usr/bin/stat -Lc '%d:%i' -- "${path}")" || return 79
  [[ "${descriptor_identity}" == "${path_identity}" && ! -L "${path}" ]]
)

open_approved_plan_intake() {
  local descriptor_identity path_identity
  require_approved_plan_path "${USER_REALNIC_PLAN}" 'siyixuan:siyixuan' \
    "${APPROVED_PLAN_SHA256}" || return $?
  exec {APPROVED_PLAN_FD}<"${USER_REALNIC_PLAN}" || return 79
  require_approved_plan_object "/proc/self/fd/${APPROVED_PLAN_FD}" \
    'siyixuan:siyixuan' "${APPROVED_PLAN_SHA256}" 1 || return $?
  descriptor_identity="$(/usr/bin/stat -Lc '%d:%i' -- \
    "/proc/self/fd/${APPROVED_PLAN_FD}")" || return 79
  path_identity="$(/usr/bin/stat -Lc '%d:%i' -- "${USER_REALNIC_PLAN}")" || return 79
  [[ "${descriptor_identity}" == "${path_identity}" ]]
}

create_approved_plan_pending() {
  [[ ! -e "${APPROVED_PLAN_PENDING}" && ! -L "${APPROVED_PLAN_PENDING}" ]] || return 73
  (umask 077
    set -o noclobber
    : >"${APPROVED_PLAN_PENDING}")
}

require_approved_plan_pending_shape() {
  local canonical shape size
  canonical="$(/usr/bin/readlink -e -- "${APPROVED_PLAN_PENDING}")" || return 79
  [[ "${canonical}" == "${APPROVED_PLAN_PENDING}" && \
    -f "${APPROVED_PLAN_PENDING}" && ! -L "${APPROVED_PLAN_PENDING}" ]] || return 79
  shape="$(/usr/bin/stat -Lc '%U:%G:%a:%h:%F' -- "${APPROVED_PLAN_PENDING}")" || return 79
  size="$(/usr/bin/stat -Lc '%s' -- "${APPROVED_PLAN_PENDING}")" || return 79
  [[ "${shape}" == 'root:root:600:1:regular file' && "${size}" =~ ^[0-9]+$ && \
    "${size}" -le 16777216 ]]
}

fsync_exact_target() {
  local target="$1" kind="$2"
  case "${target}:${kind}" in
    "${APPROVED_PLAN_PENDING_FD}:file" | "${BOOTSTRAP_ROOT}:directory") ;;
    *) return 65 ;;
  esac
  /usr/bin/python3 -B -I -c \
    'import os, stat, sys
target, kind = sys.argv[1:]
opened = kind == "directory"
fd = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_DIRECTORY", 0)) if opened else int(target)
try:
    mode = os.fstat(fd).st_mode
    if (kind == "file" and not stat.S_ISREG(mode)) or (kind == "directory" and not stat.S_ISDIR(mode)):
        raise OSError("fsync target type changed")
    os.fsync(fd)
finally:
    if opened:
        os.close(fd)' "${target}" "${kind}"
}

write_approved_plan_pending() {
  local descriptor_identity path_identity
  [[ "${APPROVED_PLAN_FD}" =~ ^[0-9]+$ ]] || return 65
  require_approved_plan_pending_shape || return $?
  exec {APPROVED_PLAN_PENDING_FD}<>"${APPROVED_PLAN_PENDING}" || return 79
  require_approved_plan_pending_shape || return $?
  descriptor_identity="$(/usr/bin/stat -Lc '%d:%i' -- \
    "/proc/self/fd/${APPROVED_PLAN_PENDING_FD}")" || return 79
  path_identity="$(/usr/bin/stat -Lc '%d:%i' -- "${APPROVED_PLAN_PENDING}")" || return 79
  [[ "${descriptor_identity}" == "${path_identity}" && \
    ! -L "${APPROVED_PLAN_PENDING}" ]] || return 79
  /usr/bin/cat -- "/proc/self/fd/${APPROVED_PLAN_FD}" \
    >"/proc/self/fd/${APPROVED_PLAN_PENDING_FD}" || return $?
  fsync_exact_target "${APPROVED_PLAN_PENDING_FD}" file || return $?
  [[ "$(/usr/bin/stat -Lc '%d:%i' -- "${APPROVED_PLAN_PENDING}")" == \
    "${descriptor_identity}" ]] || return 79
  require_approved_plan_object "/proc/self/fd/${APPROVED_PLAN_PENDING_FD}" \
    'root:root' "${APPROVED_PLAN_SHA256}" 1 || return $?
  require_approved_plan_object "${APPROVED_PLAN_PENDING}" 'root:root' \
    "${APPROVED_PLAN_SHA256}" 1
}

require_approved_plan_pending_fd() {
  local descriptor_identity path_identity
  [[ "${APPROVED_PLAN_PENDING_FD}" =~ ^[0-9]+$ ]] || return 65
  require_approved_plan_pending_shape || return $?
  descriptor_identity="$(/usr/bin/stat -Lc '%d:%i' -- \
    "/proc/self/fd/${APPROVED_PLAN_PENDING_FD}")" || return 79
  path_identity="$(/usr/bin/stat -Lc '%d:%i' -- "${APPROVED_PLAN_PENDING}")" || return 79
  [[ "${descriptor_identity}" == "${path_identity}" && \
    ! -L "${APPROVED_PLAN_PENDING}" ]] || return 79
  require_approved_plan_object "/proc/self/fd/${APPROVED_PLAN_PENDING_FD}" \
    'root:root' "${APPROVED_PLAN_SHA256}" 1
}

snapshot_realnic_plan() {
  local descriptor_identity path_identity disposition='created'
  require_completed_stage || fail 'completed-stage-contract' $?
  require_bootstrap_root || fail 'bootstrap-root-drift' $?
  acquire_physical_interface_lock || fail 'physical-interface-lock' $?
  open_approved_plan_intake || fail 'approved-plan-intake' $?
  descriptor_identity="$(/usr/bin/stat -Lc '%d:%i' -- \
    "/proc/self/fd/${APPROVED_PLAN_FD}")" || fail 'approved-plan-intake-fd-identity' 79
  if [[ -e "${ROOT_REALNIC_PLAN}" || -L "${ROOT_REALNIC_PLAN}" ]]; then
    require_approved_plan_path "${ROOT_REALNIC_PLAN}" 'root:root' \
      "${APPROVED_PLAN_SHA256}" || fail 'approved-plan-preexisting-differs' $?
    disposition='verified-existing'
  else
    if [[ ! -e "${APPROVED_PLAN_PENDING}" && ! -L "${APPROVED_PLAN_PENDING}" ]]; then
      run_step RP1 create_approved_plan_pending || fail 'approved-plan-pending-create' $?
    fi
    require_approved_plan_pending_shape || fail 'approved-plan-pending-shape' $?
    run_step RP2 write_approved_plan_pending || fail 'approved-plan-pending-write' $?
    run_step RP2.parent fsync_exact_target "${BOOTSTRAP_ROOT}" directory ||
      fail 'approved-plan-pending-parent-fsync' $?
    require_approved_plan_pending_fd || fail 'approved-plan-pending-prepublish-drift' $?
    run_step RP3 /bin/ln --no-target-directory -- \
      "${APPROVED_PLAN_PENDING}" "${ROOT_REALNIC_PLAN}" ||
      fail 'approved-plan-publish' $?
  fi
  require_approved_plan_path "${ROOT_REALNIC_PLAN}" 'root:root' \
    "${APPROVED_PLAN_SHA256}" || fail 'approved-plan-root-snapshot' $?
  run_step RP4 fsync_exact_target "${BOOTSTRAP_ROOT}" directory ||
    fail 'approved-plan-parent-fsync' $?
  require_bootstrap_root || fail 'bootstrap-root-postpublish-drift' $?
  path_identity="$(/usr/bin/stat -Lc '%d:%i' -- "${USER_REALNIC_PLAN}")" ||
    fail 'approved-plan-intake-path-identity' 79
  [[ "${descriptor_identity}" == "${path_identity}" ]] ||
    fail 'approved-plan-intake-replaced' 79
  require_approved_plan_path "${USER_REALNIC_PLAN}" 'siyixuan:siyixuan' \
    "${APPROVED_PLAN_SHA256}" || fail 'approved-plan-intake-postcopy' $?
  printf 'B82_V6_REALNIC_PLAN_SNAPSHOT_COMPLETE source=%s destination=%s sha256=%s disposition=%s retained=1\n' \
    "${USER_REALNIC_PLAN}" "${ROOT_REALNIC_PLAN}" "${APPROVED_PLAN_SHA256}" "${disposition}"
}

verify_realnic_plan() {
  require_completed_stage || fail 'completed-stage-contract' $?
  require_approved_plan_path "${ROOT_REALNIC_PLAN}" 'root:root' \
    "${APPROVED_PLAN_SHA256}" || fail 'approved-plan-root-snapshot' $?
  printf 'B82_V6_REALNIC_PLAN_VERIFIED path=%s sha256=%s authority=root-stager-snapshot\n' \
    "${ROOT_REALNIC_PLAN}" "${APPROVED_PLAN_SHA256}"
}


run_r2_retirement_engine() {
  /usr/bin/python3 -B -I - "${MODE}" "${MANIFEST}" "${MANIFEST_SHA256}" \
    "${R2_AUTH_MANIFEST_PENDING}" "${R2_AUTH_SELF}" \
    "${R2_AUTH_SELF_PENDING}" \
    "${R2_USER_INTAKE}" "${R2_HOME_QROOT}" \
    "${R2_AUTH_ROOT}" "${R2_Q_INTAKE}" \
    "${R2_Q_PACKAGE}" "${EXPECTED_REMOTE_PACKAGE}" "${BOOTSTRAP_ROOT}" \
    "${R2_RUN_QROOT}" "${R2_Q_BOOTSTRAP}" "${R2_LOCK}" \
    "${R2_RECEIPT_PENDING}" "${R2_RECEIPT_FINAL}" \
    "${R2_PREDECESSOR_COMMIT}" "${R2_PREDECESSOR_MANIFEST_SHA256}" \
    "${EXPECTED_HOSTNAME}" "${EXPECTED_KERNEL}" "${EXPECTED_MACHINE_ID}" <<'PY'
import ctypes
import fcntl
import hashlib
import os
import pwd
import re
import stat
import subprocess
import sys


class RetirementStop(Exception):
    def __init__(self, reason, code=79):
        super().__init__(reason)
        self.reason = reason
        self.code = code


def stop(reason, code=79):
    raise RetirementStop(reason, code)


if len(sys.argv) != 24:
    stop("engine-arguments", 64)

(mode, current_manifest, current_manifest_sha, current_manifest_pending,
 current_self, current_self_pending, user_intake, home_qroot,
 auth_root, q_intake, q_package, source_package, source_bootstrap, run_qroot,
 q_bootstrap, lock_path, receipt_pending, receipt_final, predecessor_commit,
 predecessor_manifest_sha, expected_hostname, expected_kernel,
 expected_machine_id) = sys.argv[1:]

current_self_sha = None

if mode not in {"retire-postflight-f75fe7678cfd-r2", "verify-postflight-retirement-r2"}:
    stop("engine-mode", 64)

if not all(hasattr(os, name) for name in (
        "O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK")):
    stop("open-flags-unavailable", 69)
O_DIRECTORY = os.O_DIRECTORY
O_NOFOLLOW = os.O_NOFOLLOW
O_CLOEXEC = os.O_CLOEXEC
O_NONBLOCK = os.O_NONBLOCK
DIR_FLAGS = os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK
RENAME_NOREPLACE = 1
ROOT_UID = 0
ROOT_GID = 0

CURRENT_KEYS = (
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
    "bind_final_package_sh_path",
    "bind_final_package_sh_blob",
    "bind_final_package_sh_sha256",
    "controller_sh_path",
    "controller_sh_blob",
    "controller_sh_sha256",
    "locked_transport_exp_path",
    "locked_transport_exp_blob",
    "locked_transport_exp_sha256",
    "root_matrix_n_r_sh_path",
    "root_matrix_n_r_sh_blob",
    "root_matrix_n_r_sh_sha256",
    "check_realhost_iperf_py_path",
    "check_realhost_iperf_py_blob",
    "check_realhost_iperf_py_sha256",
    "test_hermetic_matrix_sh_path",
    "test_hermetic_matrix_sh_blob",
    "test_hermetic_matrix_sh_sha256",
    "test_matrix_static_py_path",
    "test_matrix_static_py_blob",
    "test_matrix_static_py_sha256",
    "checksum_module_lease_sh_path",
    "checksum_module_lease_sh_blob",
    "checksum_module_lease_sh_sha256",
    "test_hermetic_checksum_module_lease_sh_path",
    "test_hermetic_checksum_module_lease_sh_blob",
    "test_hermetic_checksum_module_lease_sh_sha256",
    "test_checksum_module_lease_static_py_path",
    "test_checksum_module_lease_static_py_blob",
    "test_checksum_module_lease_static_py_sha256",
    "wg_mix_faketcp_checksum_c_path",
    "wg_mix_faketcp_checksum_c_blob",
    "wg_mix_faketcp_checksum_c_sha256",
    "root_fresh_verifier_gate_sh_path",
    "root_fresh_verifier_gate_sh_blob",
    "root_fresh_verifier_gate_sh_sha256",
    "test_hermetic_fresh_verifier_gate_sh_path",
    "test_hermetic_fresh_verifier_gate_sh_blob",
    "test_hermetic_fresh_verifier_gate_sh_sha256",
    "test_fresh_verifier_gate_static_py_path",
    "test_fresh_verifier_gate_static_py_blob",
    "test_fresh_verifier_gate_static_py_sha256",
    "prepare_stage_root_sh_path",
    "prepare_stage_root_sh_blob",
    "prepare_stage_root_sh_sha256",
    "realnic_acceptance_py_path",
    "realnic_acceptance_py_blob",
    "realnic_acceptance_py_sha256",
    "test_realnic_acceptance_py_path",
    "test_realnic_acceptance_py_blob",
    "test_realnic_acceptance_py_sha256",
    "test_realnic_acceptance_static_py_path",
    "test_realnic_acceptance_static_py_blob",
    "test_realnic_acceptance_static_py_sha256",
    "provision_ubuntu_test_host_sh_path",
    "provision_ubuntu_test_host_sh_blob",
    "provision_ubuntu_test_host_sh_sha256",
    "root_veth_n_r_sh_path",
    "root_veth_n_r_sh_blob",
    "root_veth_n_r_sh_sha256",
    "test_hermetic_veth_runner_sh_path",
    "test_hermetic_veth_runner_sh_blob",
    "test_hermetic_veth_runner_sh_sha256",
    "test_veth_runner_static_py_path",
    "test_veth_runner_static_py_blob",
    "test_veth_runner_static_py_sha256",
    "controller_seam_sh_path",
    "controller_seam_sh_blob",
    "controller_seam_sh_sha256",
    "root_routed_veth_n_r_sh_path",
    "root_routed_veth_n_r_sh_blob",
    "root_routed_veth_n_r_sh_sha256",
    "test_hermetic_routed_veth_harness_sh_path",
    "test_hermetic_routed_veth_harness_sh_blob",
    "test_hermetic_routed_veth_harness_sh_sha256",
    "test_routed_veth_harness_static_py_path",
    "test_routed_veth_harness_static_py_blob",
    "test_routed_veth_harness_static_py_sha256",
)

OLD_MANIFEST_BYTES = (
    "format\twg-mix-ebpf-b82-v6-package-v4\n"
    "run_id\tc8e41d73\n"
    "package_id\t4f2a9b61\n"
    "integration_ref\trefs/heads/codex/tcx-faketcp-final-v2\n"
    "integration_commit\tf75fe7678cfdecf08173fd201be5c055417d6e11\n"
    "bundle_name\tsource-4f2a9b61.bundle\n"
    "bundle_sha256\tb74811808e0413714dcf20b8292fe68631f603c0b9a68bc9951af481477b413b\n"
    "history_verification\tisolated-unbundle-rev-list-fsck-v1\n"
    "history_commit_count\t668\n"
    "history_roots_sha256\t9356df63b3d4c4c362912b14ab8ee5cb54d12cd1f14be9aa1fe8e18adbad6f05\n"
    "history_objects_sha256\t21647f92e57f9dbb8e15707699f632544d6dfcf2e1b4279d775cce1fb82163f3\n"
    "wg_state\tabsent\n"
    "wg_interface\tabsent\n"
    "wg_local_address\tabsent\n"
    "wg_peer_address\tabsent\n"
    "local_repository\t/Users/siyixuan/codes-2/wg-mix-ebpf/.worktree/tcx-faketcp-final-v2\n"
    "local_package_dir\t/private/tmp/wg-mix-b82-v6-c8e41d73-4f2a9b61-f75fe7678cfd\n"
    "remote_package_dir\t/home/siyixuan/wg-mix-ebpf-test/unpriv-4f2a9b61\n"
    "remote_source\t/run/wg-mix-ebpf-source-stages/c8e41d73/source\n"
    "target_user\tsiyixuan\n"
    "target_host\t192.168.10.82\n"
    "target_hostname\tubuntu-2604-test\n"
    "target_kernel\t7.0.0-28-generic\n"
    "target_machine_id\t9db3fb717cc74974b2a6b243d67f67b9\n"
    "target_interface\tens33\n"
    "peer_address\t47.116.202.155\n"
    "peer_port\t5201\n"
    "soak_seconds\t3600\n"
    "session_seconds\t300\n"
    "physical_nic_forward_authority\trealnic-acceptance-v1\n"
    "physical_interface_lock\t/run/wg-mix-ebpf-realnic-physical-interface.v1.lock\n"
    "legacy_matrix_mode\tretired\n"
    "realnic_profile\tacceptance\n"
    "realnic_traffic_seconds\t30\n"
    "bind_final_package_sh_path\tscripts/realhost-b82-c8e41d73/bind-final-package.sh\n"
    "bind_final_package_sh_blob\t13ec99ddafb7452c98f05bf4855ef52c3f54b185\n"
    "bind_final_package_sh_sha256\ta808a7879ef64190eff9e81e6b694acea7bc04b1b74ffad44109b237a5eb14ca\n"
    "controller_sh_path\tscripts/realhost-b82-c8e41d73/controller.sh\n"
    "controller_sh_blob\t8371e5492c4e88f3e855fa3c7edfbff15bcf3a5f\n"
    "controller_sh_sha256\tfb8a7a685b5a6b73de851ee9a3396f4154cc4ae083a7c36f3b3128b2b9a2e77d\n"
    "locked_transport_exp_path\tscripts/realhost-b82-c8e41d73/locked-transport.exp\n"
    "locked_transport_exp_blob\t264f0cf74e6ff53d0cbee2688faa5d886898d22f\n"
    "locked_transport_exp_sha256\tc70e4f040dc082c4f286c237bda32fe2a60b3e5f6300ec57734645a0be12abec\n"
    "root_matrix_n_r_sh_path\tscripts/realhost-b82-c8e41d73/root-matrix-n-r.sh\n"
    "root_matrix_n_r_sh_blob\td2b2d473afb79c4463fd6c712d4eda3faeed5c7e\n"
    "root_matrix_n_r_sh_sha256\t9ec125c2933866431779b760d41c6484cc0fbb9e5e9f3b5431c4a56fbab63e07\n"
    "check_realhost_iperf_py_path\tscripts/realhost-b82-c8e41d73/check-realhost-iperf.py\n"
    "check_realhost_iperf_py_blob\t765871ef3af87cd8a101a42e71ea97c1245dc9da\n"
    "check_realhost_iperf_py_sha256\t9a52378b8a1ef6043d4d5792471c8239a0392a80da72f5c00846dd89e88ccd67\n"
    "test_hermetic_matrix_sh_path\tscripts/realhost-b82-c8e41d73/test-hermetic-matrix.sh\n"
    "test_hermetic_matrix_sh_blob\t81f7cd86d8dc5a93133ea755311ba57aa66e4c76\n"
    "test_hermetic_matrix_sh_sha256\t9b81949416a1b4df91fee0e7d31a3de2c6ba9b474dc9c0f4dbbb1cc609207499\n"
    "test_matrix_static_py_path\tscripts/realhost-b82-c8e41d73/test_matrix_static.py\n"
    "test_matrix_static_py_blob\t0a2b1538d3127e8bae8953b0dff59d60cc379f39\n"
    "test_matrix_static_py_sha256\t8de2dcdc866938da0502f1ad73ac9b38c9b6ff4066c76e9cbc946c9ca30a53f8\n"
    "checksum_module_lease_sh_path\tscripts/realhost-b82-c8e41d73/checksum-module-lease.sh\n"
    "checksum_module_lease_sh_blob\tc2e6077005e046eef0e1186c26cdaaf29c780f98\n"
    "checksum_module_lease_sh_sha256\t4ab9a22910e8d597cc04bb4fdde9e1b32d37a1bb2c6ad7b76f52d576b5a9adb2\n"
    "root_fresh_verifier_gate_sh_path\tscripts/realhost-b82-c8e41d73/root-fresh-verifier-gate.sh\n"
    "root_fresh_verifier_gate_sh_blob\t48dd5e68071798c3d25daf0051cbf54f8cd3297e\n"
    "root_fresh_verifier_gate_sh_sha256\t4c2cf85b7e571df9b7ed4a77fa720c9f5e35950d44af5a39499a7ad700fe6a27\n"
    "test_hermetic_fresh_verifier_gate_sh_path\tscripts/realhost-b82-c8e41d73/test-hermetic-fresh-verifier-gate.sh\n"
    "test_hermetic_fresh_verifier_gate_sh_blob\tf3f7367d28253ebae746eb0e225c11f90eaa8305\n"
    "test_hermetic_fresh_verifier_gate_sh_sha256\tc9b5b1f954c794c5c986214777727a76579f670db9587f319ac148fc0c2a05f3\n"
    "test_fresh_verifier_gate_static_py_path\tscripts/realhost-b82-c8e41d73/test_fresh_verifier_gate_static.py\n"
    "test_fresh_verifier_gate_static_py_blob\tf86736b1c4a5b884814f062edbb2d652172f024f\n"
    "test_fresh_verifier_gate_static_py_sha256\tace6951027788e82ad879caf285316af4e6ee81fdb6746f569cd7c22b9f80bf3\n"
    "prepare_stage_root_sh_path\tscripts/realhost-b82-c8e41d73/prepare-stage-root.sh\n"
    "prepare_stage_root_sh_blob\t057db657b0ba096a4f660eedda2e0a4242af7de5\n"
    "prepare_stage_root_sh_sha256\t1bcb8db91d976d2a1d95f7d87223a2dac4a1678f74c1c25542e54b01ee10eeea\n"
    "realnic_acceptance_py_path\tscripts/realhost-b82-acceptance-v1/realnic_acceptance.py\n"
    "realnic_acceptance_py_blob\te1edba5c9dd62c8c169d7129e8b376d4ce7d1168\n"
    "realnic_acceptance_py_sha256\ta88100b2a23ad41dd3e644c3ba1c7a722d58c8184a997aabf0ceab78552c6339\n"
    "test_realnic_acceptance_py_path\tscripts/realhost-b82-acceptance-v1/test_realnic_acceptance.py\n"
    "test_realnic_acceptance_py_blob\te92f8f7db9733eb3f655b388f1efd685f738c2c4\n"
    "test_realnic_acceptance_py_sha256\tfcb3d0dadee6da6e0ad67d028f268ebe43575287f555cd8100d279f8a3b0b79c\n"
    "test_realnic_acceptance_static_py_path\tscripts/realhost-b82-acceptance-v1/test_realnic_acceptance_static.py\n"
    "test_realnic_acceptance_static_py_blob\tb0dd244937b9139fe8c8548d6c046b76d9f611e9\n"
    "test_realnic_acceptance_static_py_sha256\tba8aef3219a0cf2a5c6b5058b245f64eb828a08bb532d2aa0291f51ee7206ad2\n"
    "provision_ubuntu_test_host_sh_path\tscripts/provision-ubuntu-test-host.sh\n"
    "provision_ubuntu_test_host_sh_blob\t143eb89a2e4bbbf548b510bcc2fd9f66184d3d76\n"
    "provision_ubuntu_test_host_sh_sha256\t078d191b0edbafe27e9f684d3fa495e04d7217a01d0ec1fd32eaede211178c8f\n"
    "root_veth_n_r_sh_path\tscripts/realhost-b82-c8e41d73/root-veth-n-r.sh\n"
    "root_veth_n_r_sh_blob\ta72f7f2eebe765bc7fa8a5352c134233b30ac8aa\n"
    "root_veth_n_r_sh_sha256\tfbb8779039137383df6f51f05319faea966c69a80001da837dee22d04d8f7a70\n"
    "test_hermetic_veth_runner_sh_path\tscripts/realhost-b82-c8e41d73/test-hermetic-veth-runner.sh\n"
    "test_hermetic_veth_runner_sh_blob\tae0c74eefe33cf6afda681ba6fca17b54700108f\n"
    "test_hermetic_veth_runner_sh_sha256\t939c3b28310596ed6bada0eb3ccdd5ebbb7eeebeaf959504c7d468b929f8174c\n"
    "test_veth_runner_static_py_path\tscripts/realhost-b82-c8e41d73/test_veth_runner_static.py\n"
    "test_veth_runner_static_py_blob\t5bc3d0ac0ac48c3adc0cd86166f533edc676c712\n"
    "test_veth_runner_static_py_sha256\te40da6b1a6541a9b8b6c56d9277d4d73838e037876180e479b5af5d64a4edc90\n"
    "controller_seam_sh_path\tscripts/realhost-b82-routed-veth-v1/controller-seam.sh\n"
    "controller_seam_sh_blob\t18d9e4d72a0b9022019e738d9de4fd4e23bc4903\n"
    "controller_seam_sh_sha256\t2bd7b65c3e770ff53445cbc7c195e741e8fff5eeef9e51bd6fcaa2f513d1f251\n"
    "root_routed_veth_n_r_sh_path\tscripts/realhost-b82-routed-veth-v1/root-routed-veth-n-r.sh\n"
    "root_routed_veth_n_r_sh_blob\t9d30910b692b2d42c1528c75c2a3ba0a5d0a11cb\n"
    "root_routed_veth_n_r_sh_sha256\t5af8b848c9fc5f915b25c6c03822622f2ac75996a54ebf8172c7c5391c9f3485\n"
    "test_hermetic_routed_veth_harness_sh_path\tscripts/realhost-b82-routed-veth-v1/test-hermetic-routed-veth-harness.sh\n"
    "test_hermetic_routed_veth_harness_sh_blob\t253c7b0b4d4c2d065475a82742418446146d0a0a\n"
    "test_hermetic_routed_veth_harness_sh_sha256\t674f96665eb26f879eae08936683fdac2beb974841ed99f9021abe9e04752032\n"
    "test_routed_veth_harness_static_py_path\tscripts/realhost-b82-routed-veth-v1/test_routed_veth_harness_static.py\n"
    "test_routed_veth_harness_static_py_blob\t06e0fa14779ce778440250f4a437426017754cd4\n"
    "test_routed_veth_harness_static_py_sha256\t5bb678726ecc6bcc946233ae138d541fc50dc9f6ec40ddf139350863690d88c1\n"
).encode("utf-8")

STAGE_PATH = "/run/wg-mix-ebpf-source-stages/c8e41d73"
PHYSICAL_LOCK_PATH = "/run/wg-mix-ebpf-realnic-physical-interface.v1.lock"
FAILURE_BASENAME = "test-hermetic-checksum-module-lease.sh"
R1_ID = "c8e41d73-2c690050ae1d-r1"
R1_HOME_QROOT = "/home/.wg-mix-ebpf-retirement-" + R1_ID
R1_Q_INTAKE = R1_HOME_QROOT + "/intake"
R1_Q_PACKAGE = R1_HOME_QROOT + "/package"
R1_RUN_QROOT = "/run/wg-mix-ebpf-retirement-" + R1_ID
R1_Q_BOOTSTRAP = R1_RUN_QROOT + "/bootstrap"
R1_AUTH_MANIFEST_SHA = "c4532671304d30755b1c42bb55f82186d96df3f6c84af73078ca16c3fddfe4e6"
R1_AUTH_SELF_SHA = "a4a1c89dcd9f087b79149f52a01346ed6db5c209ad4985bdbb8c9132276c0077"
R1_RECEIPT_SHA = "4c3e9bfd3d4e64f6626abaa43e20cf5e4df6b193395cee6a39953b1c4da7d188"
R1_PACKAGE_FILES = {
    "source-4f2a9b61.bundle":
        (2404122, "5c53adec58363ec2ff51d9bd5dcd7e467874c839393178491c74b16a8c9f922c"),
    "package-manifest.v1":
        (7315, "21f14e1f7e646649fdad864dce23dce2055585962d92bfaba6e71158372c1ebe"),
    "bind-final-package.sh":
        (17009, "13a186008662548b191c8e18a3cf764597504451a30e50cd3c7e7cd9d98dfc6e"),
    "controller.sh":
        (43170, "ff315162affccc51454f3f9a0c80f9c7412291581a9a2abc03ed1df46a266a1c"),
    "prepare-stage-root.sh":
        (54217, "cc8e0e82c369ff9983600879827d350ea3b2da13d4d3315b309ea0924e911a95"),
    "provision-ubuntu-test-host.sh":
        (18613, "01aaf3767d9e048f11ca21f35cadba063f355c3c9e94aadd606734d02c260388"),
    "root-matrix-n-r.sh":
        (984, "d0d0f6f532516e16d98239e5ad79963c2c70bc8bd682a3f6439b4479e7b60fb3"),
    "check-realhost-iperf.py":
        (21027, "9a52378b8a1ef6043d4d5792471c8239a0392a80da72f5c00846dd89e88ccd67"),
    "test-hermetic-matrix.sh":
        (6669, "be011f72367b6b383ece727f1048db992b9068db224109ee2f60ed5a6ce0c891"),
    "test_matrix_static.py":
        (5656, "8de2dcdc866938da0502f1ad73ac9b38c9b6ff4066c76e9cbc946c9ca30a53f8"),
    "checksum-module-lease.sh":
        (23755, "4ab9a22910e8d597cc04bb4fdde9e1b32d37a1bb2c6ad7b76f52d576b5a9adb2"),
    "root-fresh-verifier-gate.sh":
        (65112, "762502215e1138b53a656fd085b1718b867a3cc488a5c5bd874a04561cf10e9d"),
    "test-hermetic-fresh-verifier-gate.sh":
        (14628, "c9b5b1f954c794c5c986214777727a76579f670db9587f319ac148fc0c2a05f3"),
    "test_fresh_verifier_gate_static.py":
        (17307, "ace6951027788e82ad879caf285316af4e6ee81fdb6746f569cd7c22b9f80bf3"),
    "realnic_acceptance.py":
        (216405, "a88100b2a23ad41dd3e644c3ba1c7a722d58c8184a997aabf0ceab78552c6339"),
    "test_realnic_acceptance.py":
        (148160, "fcb3d0dadee6da6e0ad67d028f268ebe43575287f555cd8100d279f8a3b0b79c"),
    "test_realnic_acceptance_static.py":
        (14894, "ba8aef3219a0cf2a5c6b5058b245f64eb828a08bb532d2aa0291f51ee7206ad2"),
}
R1_BOOTSTRAP_FILES = {
    "prepare-stage-root.sh":
        (54217, "cc8e0e82c369ff9983600879827d350ea3b2da13d4d3315b309ea0924e911a95"),
    "provision-ubuntu-test-host.sh":
        (18613, "01aaf3767d9e048f11ca21f35cadba063f355c3c9e94aadd606734d02c260388"),
}




def require_absolute(path, label):
    if (not path.startswith("/") or path == "/" or "//" in path or
            any(part in {"", ".", ".."} for part in path.split("/")[1:])):
        stop(label + "-path", 65)


for fixed_path in (
        current_manifest, current_manifest_pending, current_self,
        current_self_pending, user_intake, home_qroot, auth_root, q_intake,
        q_package, source_package, source_bootstrap, run_qroot, q_bootstrap,
        lock_path, receipt_pending, receipt_final):
    require_absolute(fixed_path, "fixed")


def open_abs_dir(path):
    require_absolute(path, "directory")
    descriptor = os.open("/", DIR_FLAGS)
    try:
        for component in path.split("/")[1:]:
            next_descriptor = os.open(component, DIR_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def open_parent(path):
    parent, name = os.path.split(path)
    if not name or "/" in name or name in {".", ".."}:
        stop("leaf-path", 65)
    return open_abs_dir(parent), name


def fd_mnt_id(descriptor):
    value = None
    with open(f"/proc/self/fdinfo/{descriptor}", "r", encoding="ascii") as stream:
        for line in stream:
            if line.startswith("mnt_id:\t"):
                value = line.split("\t", 1)[1].strip()
                break
    if value is None or not value.isdecimal():
        stop("mount-id")
    return value


def require_dir_fd(descriptor, uid, gid, mode_bits, label):
    metadata = os.fstat(descriptor)
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != uid or
            metadata.st_gid != gid or stat.S_IMODE(metadata.st_mode) != mode_bits):
        stop(label + "-metadata")
    return metadata


def names_at(descriptor):
    return set(os.listdir(descriptor))


def entry_stat(parent_descriptor, name):
    try:
        return os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return None


def entry_is_directory(parent_descriptor, name, label):
    metadata = entry_stat(parent_descriptor, name)
    if metadata is None:
        return False
    if not stat.S_ISDIR(metadata.st_mode):
        stop(label + "-not-directory")
    return True


def read_all(descriptor, maximum=16777216):
    metadata = os.fstat(descriptor)
    if metadata.st_size < 0 or metadata.st_size > maximum:
        stop("file-size")
    chunks = []
    offset = 0
    while offset < metadata.st_size:
        chunk = os.pread(descriptor, min(65536, metadata.st_size - offset), offset)
        if not chunk:
            stop("short-read")
        chunks.append(chunk)
        offset += len(chunk)
    return b"".join(chunks)


def sha256_fd(descriptor):
    digest = hashlib.sha256()
    offset = 0
    while True:
        chunk = os.pread(descriptor, 65536, offset)
        if not chunk:
            break
        digest.update(chunk)
        offset += len(chunk)
    return digest.hexdigest()


def require_file_at(parent_descriptor, name, uid, gid, mode_bits, links,
                    expected_sha, label, writable=False):
    flags = ((os.O_RDWR if writable else os.O_RDONLY) |
             O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
    descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    try:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != uid or
                metadata.st_gid != gid or stat.S_IMODE(metadata.st_mode) != mode_bits or
                metadata.st_nlink != links):
            stop(label + "-metadata")
        os.fsync(descriptor)
        if expected_sha is not None and sha256_fd(descriptor) != expected_sha:
            stop(label + "-sha256", 67)
        path_metadata = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (path_metadata.st_dev, path_metadata.st_ino) != (metadata.st_dev, metadata.st_ino):
            stop(label + "-replaced")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def require_sized_file_at(parent_descriptor, name, uid, gid, mode_bits, links,
                          expected_sha, expected_size, label, writable=False):
    descriptor = require_file_at(
        parent_descriptor, name, uid, gid, mode_bits, links, expected_sha,
        label, writable=writable)
    try:
        if os.fstat(descriptor).st_size != expected_size:
            stop(label + "-size")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def parse_manifest_ordered(payload, label):
    if not payload.endswith(b"\n") or b"\0" in payload or b"\r" in payload:
        stop(label + "-encoding", 65)
    try:
        lines = payload[:-1].decode("utf-8", "strict").split("\n")
    except UnicodeDecodeError:
        stop(label + "-encoding", 65)
    keys = []
    values = {}
    for line in lines:
        fields = line.split("\t")
        if len(fields) != 2 or not fields[0] or not fields[1] or fields[0] in values:
            stop(label + "-field", 65)
        keys.append(fields[0])
        values[fields[0]] = fields[1]
    return tuple(keys), values
def require_pair(directory_descriptor, pending_name, final_name, mode_bits,
                 expected_sha, label):
    pending_descriptor = require_file_at(
        directory_descriptor, pending_name, ROOT_UID, ROOT_GID, mode_bits, 2,
        expected_sha, label + "-pending")
    try:
        final_descriptor = require_file_at(
            directory_descriptor, final_name, ROOT_UID, ROOT_GID, mode_bits, 2,
            expected_sha, label + "-final")
        try:
            first = os.fstat(pending_descriptor)
            second = os.fstat(final_descriptor)
            if (first.st_dev, first.st_ino) != (second.st_dev, second.st_ino):
                stop(label + "-inode")
            return read_all(final_descriptor)
        finally:
            os.close(final_descriptor)
    finally:
        os.close(pending_descriptor)


def same_open_inode(first_descriptor, second_descriptor, label):
    first = os.fstat(first_descriptor)
    second = os.fstat(second_descriptor)
    if ((first.st_dev, first.st_ino) != (second.st_dev, second.st_ino) or
            fd_mnt_id(first_descriptor) != fd_mnt_id(second_descriptor)):
        stop(label + "-inode")


def require_host_identity():
    if os.geteuid() != ROOT_UID or os.getegid() != ROOT_GID:
        stop("root-required", 77)
    if (os.uname().nodename != expected_hostname or
            os.uname().release != expected_kernel):
        stop("host-identity", 78)
    with open("/etc/machine-id", "r", encoding="ascii") as machine_stream:
        if machine_stream.read().strip() != expected_machine_id:
            stop("machine-identity", 78)


def require_exact_names(descriptor, expected, label):
    actual = names_at(descriptor)
    if actual != set(expected):
        stop(label + "-entries")


def open_child_dir(parent_descriptor, name, uid, gid, mode_bits, label):
    descriptor = os.open(name, DIR_FLAGS, dir_fd=parent_descriptor)
    try:
        require_dir_fd(descriptor, uid, gid, mode_bits, label)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def require_path_absent(path, label):
    require_absolute(path, label)
    try:
        parent_descriptor, name = open_parent(path)
    except FileNotFoundError:
        return
    try:
        if entry_stat(parent_descriptor, name) is not None:
            stop(label + "-present", 78)
    finally:
        os.close(parent_descriptor)


def r1_receipt_bytes():
    lines = (
        ("format", "wg-mix-ebpf-b82-prestage-retirement-terminal-v1"),
        ("retire_id", R1_ID),
        ("state", "TERMINAL"),
        ("predecessor_commit", "2c690050ae1d69dbd074acfd612faa2b80e29f8a"),
        ("predecessor_manifest_sha256",
         "21f14e1f7e646649fdad864dce23dce2055585962d92bfaba6e71158372c1ebe"),
        ("predecessor_bundle_sha256",
         "5c53adec58363ec2ff51d9bd5dcd7e467874c839393178491c74b16a8c9f922c"),
        ("authority_manifest_sha256", R1_AUTH_MANIFEST_SHA),
        ("authority_prepare_stage_root_sha256", R1_AUTH_SELF_SHA),
        ("authority_integration_commit", "4bdfdfd9075669566d5137de4550aefb240d13c4"),
        ("source_intake", "/home/siyixuan/wg-mix-ebpf-test/retire-prestage-" + R1_ID +
         ".intake"),
        ("source_package", source_package),
        ("source_bootstrap", source_bootstrap),
        ("quarantine_intake", R1_Q_INTAKE),
        ("quarantine_package", R1_Q_PACKAGE),
        ("quarantine_bootstrap", R1_Q_BOOTSTRAP),
        ("rename_order", "intake,package,bootstrap"),
        ("rename_primitive", "renameat2-RENAME_NOREPLACE-dirfd-v1"),
        ("retention", "no-unlink-no-rmdir-no-copy-fallback"),
    )
    payload = "".join(f"{key}\t{value}\n" for key, value in lines).encode("utf-8")
    if (len(lines) != 18 or len(payload) != 1211 or
            hashlib.sha256(payload).hexdigest() != R1_RECEIPT_SHA):
        stop("r1-receipt-constant", 65)
    return payload


def validate_r1_retained_entries(package_descriptor, bootstrap_descriptor,
                                 user_uid, user_gid, label_suffix):
    if len(R1_PACKAGE_FILES) != 17:
        stop("r1-package-count", 65)
    require_exact_names(
        package_descriptor, R1_PACKAGE_FILES, "r1-package" + label_suffix)
    for name, (expected_size, expected_sha) in R1_PACKAGE_FILES.items():
        file_descriptor = require_sized_file_at(
            package_descriptor, name, user_uid, user_gid, 0o600, 1,
            expected_sha, expected_size,
            "r1-package-" + name + label_suffix)
        os.close(file_descriptor)
    if len(R1_BOOTSTRAP_FILES) != 2:
        stop("r1-bootstrap-count", 65)
    require_exact_names(
        bootstrap_descriptor, R1_BOOTSTRAP_FILES,
        "r1-bootstrap" + label_suffix)
    for name, (expected_size, expected_sha) in R1_BOOTSTRAP_FILES.items():
        file_descriptor = require_sized_file_at(
            bootstrap_descriptor, name, ROOT_UID, ROOT_GID, 0o700, 1,
            expected_sha, expected_size,
            "r1-bootstrap-" + name + label_suffix)
        os.close(file_descriptor)


def validate_r1_terminal(boot_id, user_uid, user_gid):
    require_path_absent(
        "/home/siyixuan/wg-mix-ebpf-test/retire-prestage-" + R1_ID + ".intake",
        "r1-source-intake")
    home_descriptor = run_descriptor = None
    auth_descriptor = intake_descriptor = package_descriptor = bootstrap_descriptor = None
    r1_lock_descriptor = None
    try:
        home_descriptor = open_abs_dir(R1_HOME_QROOT)
        run_descriptor = open_abs_dir(R1_RUN_QROOT)
        require_dir_fd(home_descriptor, ROOT_UID, ROOT_GID, 0o700, "r1-home-qroot")
        require_dir_fd(run_descriptor, ROOT_UID, ROOT_GID, 0o700, "r1-run-qroot")
        require_exact_names(home_descriptor, {"authority", "intake", "package"},
                            "r1-home-qroot")
        require_exact_names(run_descriptor,
                            {"bootstrap", "retirement.v1.lock", "retirement-complete.v1"},
                            "r1-run-qroot")
        auth_descriptor = open_child_dir(
            home_descriptor, "authority", ROOT_UID, ROOT_GID, 0o700, "r1-authority")
        intake_descriptor = open_child_dir(
            home_descriptor, "intake", user_uid, user_gid, 0o700, "r1-intake")
        package_descriptor = open_child_dir(
            home_descriptor, "package", user_uid, user_gid, 0o700, "r1-package")
        bootstrap_descriptor = open_child_dir(
            run_descriptor, "bootstrap", ROOT_UID, ROOT_GID, 0o700, "r1-bootstrap")
        require_exact_names(auth_descriptor, {
            "package-manifest.v1", "package-manifest.v1.pending",
            "prepare-stage-root.sh", "prepare-stage-root.sh.pending"}, "r1-authority")
        manifest_payload = require_pair(
            auth_descriptor, "package-manifest.v1.pending", "package-manifest.v1",
            0o600, R1_AUTH_MANIFEST_SHA, "r1-authority-manifest")
        self_payload = require_pair(
            auth_descriptor, "prepare-stage-root.sh.pending", "prepare-stage-root.sh",
            0o700, R1_AUTH_SELF_SHA, "r1-authority-self")
        if (hashlib.sha256(manifest_payload).hexdigest() != R1_AUTH_MANIFEST_SHA or
                hashlib.sha256(self_payload).hexdigest() != R1_AUTH_SELF_SHA):
            stop("r1-authority-content")
        require_exact_names(intake_descriptor,
                            {"package-manifest.v1", "prepare-stage-root.sh"}, "r1-intake")
        for name, expected_sha in (("package-manifest.v1", R1_AUTH_MANIFEST_SHA),
                                   ("prepare-stage-root.sh", R1_AUTH_SELF_SHA)):
            file_descriptor = require_file_at(
                intake_descriptor, name, user_uid, user_gid, 0o600, 1,
                expected_sha, "r1-intake-" + name)
            os.close(file_descriptor)
        validate_r1_retained_entries(
            package_descriptor, bootstrap_descriptor, user_uid, user_gid, "")
        r1_lock_descriptor = require_file_at(
            run_descriptor, "retirement.v1.lock", ROOT_UID, ROOT_GID, 0o600, 1,
            None, "r1-lock")
        try:
            fcntl.flock(r1_lock_descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            stop("r1-lock-busy", 78)
        if read_all(r1_lock_descriptor, 256) != f"boot_id\t{boot_id}\n".encode("ascii"):
            stop("r1-lock-boot")
        receipt_payload = r1_receipt_bytes()
        receipt_descriptor = require_sized_file_at(
            run_descriptor, "retirement-complete.v1", ROOT_UID, ROOT_GID, 0o600, 1,
            R1_RECEIPT_SHA, len(receipt_payload), "r1-receipt")
        try:
            if read_all(receipt_descriptor, 8192) != receipt_payload:
                stop("r1-receipt-content")
        finally:
            os.close(receipt_descriptor)
        for descriptor in (auth_descriptor, intake_descriptor, package_descriptor,
                           bootstrap_descriptor, r1_lock_descriptor,
                           home_descriptor, run_descriptor):
            os.fsync(descriptor)
        validate_r1_retained_entries(
            package_descriptor, bootstrap_descriptor, user_uid, user_gid,
            "-postfsync")
    finally:
        for descriptor in (r1_lock_descriptor, bootstrap_descriptor, package_descriptor,
                           intake_descriptor, auth_descriptor, run_descriptor,
                           home_descriptor):
            if descriptor is not None:
                os.close(descriptor)


CURRENT_PACKAGE_FILE_FIELDS = {
    "bind-final-package.sh": ("bind_final_package_sh_path",
                              "scripts/realhost-b82-c8e41d73/bind-final-package.sh"),
    "controller.sh": ("controller_sh_path",
                      "scripts/realhost-b82-c8e41d73/controller.sh"),
    "prepare-stage-root.sh": ("prepare_stage_root_sh_path",
                              "scripts/realhost-b82-c8e41d73/prepare-stage-root.sh"),
    "provision-ubuntu-test-host.sh": (
        "provision_ubuntu_test_host_sh_path", "scripts/provision-ubuntu-test-host.sh"),
    "root-matrix-n-r.sh": ("root_matrix_n_r_sh_path",
                           "scripts/realhost-b82-c8e41d73/root-matrix-n-r.sh"),
    "check-realhost-iperf.py": ("check_realhost_iperf_py_path",
                                "scripts/realhost-b82-c8e41d73/check-realhost-iperf.py"),
    "test-hermetic-matrix.sh": ("test_hermetic_matrix_sh_path",
                                "scripts/realhost-b82-c8e41d73/test-hermetic-matrix.sh"),
    "test_matrix_static.py": ("test_matrix_static_py_path",
                              "scripts/realhost-b82-c8e41d73/test_matrix_static.py"),
    "checksum-module-lease.sh": ("checksum_module_lease_sh_path",
                                 "scripts/realhost-b82-c8e41d73/checksum-module-lease.sh"),
    "test-hermetic-checksum-module-lease.sh": (
        "test_hermetic_checksum_module_lease_sh_path",
        "scripts/realhost-b82-c8e41d73/test-hermetic-checksum-module-lease.sh"),
    "test_checksum_module_lease_static.py": (
        "test_checksum_module_lease_static_py_path",
        "scripts/realhost-b82-c8e41d73/test_checksum_module_lease_static.py"),
    "wg_mix_faketcp_checksum.c": (
        "wg_mix_faketcp_checksum_c_path", "kernel/faketcp_checksum/wg_mix_faketcp_checksum.c"),
    "root-fresh-verifier-gate.sh": (
        "root_fresh_verifier_gate_sh_path",
        "scripts/realhost-b82-c8e41d73/root-fresh-verifier-gate.sh"),
    "test-hermetic-fresh-verifier-gate.sh": (
        "test_hermetic_fresh_verifier_gate_sh_path",
        "scripts/realhost-b82-c8e41d73/test-hermetic-fresh-verifier-gate.sh"),
    "test_fresh_verifier_gate_static.py": (
        "test_fresh_verifier_gate_static_py_path",
        "scripts/realhost-b82-c8e41d73/test_fresh_verifier_gate_static.py"),
    "realnic_acceptance.py": (
        "realnic_acceptance_py_path", "scripts/realhost-b82-acceptance-v1/realnic_acceptance.py"),
    "test_realnic_acceptance.py": (
        "test_realnic_acceptance_py_path",
        "scripts/realhost-b82-acceptance-v1/test_realnic_acceptance.py"),
    "test_realnic_acceptance_static.py": (
        "test_realnic_acceptance_static_py_path",
        "scripts/realhost-b82-acceptance-v1/test_realnic_acceptance_static.py"),
}

CURRENT_REVIEW_ONLY_PATHS = {
    "locked_transport_exp_path": "scripts/realhost-b82-c8e41d73/locked-transport.exp",
    "root_veth_n_r_sh_path": "scripts/realhost-b82-c8e41d73/root-veth-n-r.sh",
    "test_hermetic_veth_runner_sh_path":
        "scripts/realhost-b82-c8e41d73/test-hermetic-veth-runner.sh",
    "test_veth_runner_static_py_path":
        "scripts/realhost-b82-c8e41d73/test_veth_runner_static.py",
    "controller_seam_sh_path": "scripts/realhost-b82-routed-veth-v1/controller-seam.sh",
    "root_routed_veth_n_r_sh_path":
        "scripts/realhost-b82-routed-veth-v1/root-routed-veth-n-r.sh",
    "test_hermetic_routed_veth_harness_sh_path":
        "scripts/realhost-b82-routed-veth-v1/test-hermetic-routed-veth-harness.sh",
    "test_routed_veth_harness_static_py_path":
        "scripts/realhost-b82-routed-veth-v1/test_routed_veth_harness_static.py",
}


def validate_current_manifest_payload(payload, label):
    keys, values = parse_manifest_ordered(payload, label)
    if keys != CURRENT_KEYS or len(keys) != 112:
        stop(label + "-schema", 65)
    fixed = {
        "format": "wg-mix-ebpf-b82-v6-package-v5",
        "run_id": "c8e41d73",
        "package_id": "4f2a9b61",
        "bundle_name": "source-4f2a9b61.bundle",
        "remote_package_dir": source_package,
        "remote_source": "/run/wg-mix-ebpf-source-stages/c8e41d73/source",
        "target_user": "siyixuan",
        "target_host": "192.168.10.82",
        "target_hostname": expected_hostname,
        "target_kernel": expected_kernel,
        "target_machine_id": expected_machine_id,
        "target_interface": "ens33",
        "peer_address": "47.116.202.155",
        "peer_port": "5201",
        "soak_seconds": "3600",
        "session_seconds": "300",
        "physical_nic_forward_authority": "realnic-acceptance-v1",
        "physical_interface_lock": "/run/wg-mix-ebpf-realnic-physical-interface.v1.lock",
        "legacy_matrix_mode": "retired",
        "realnic_profile": "acceptance",
        "realnic_traffic_seconds": "30",
        "history_verification": "isolated-unbundle-rev-list-fsck-v1",
    }
    if any(values.get(key) != value for key, value in fixed.items()):
        stop(label + "-fixed-contract", 65)
    wg_values = (values.get("wg_interface"), values.get("wg_local_address"),
                 values.get("wg_peer_address"))
    if ((values.get("wg_state") == "absent" and wg_values != ("absent",) * 3) or
            (values.get("wg_state") == "bound" and "absent" in wg_values) or
            values.get("wg_state") not in {"absent", "bound"}):
        stop(label + "-wg-contract", 65)
    if (not re.fullmatch(r"refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]{0,180}",
                         values.get("integration_ref", "")) or
            ".." in values["integration_ref"] or "//" in values["integration_ref"] or
            not re.fullmatch(r"[0-9a-f]{40}", values.get("integration_commit", "")) or
            values["integration_commit"] == predecessor_commit or
            not values.get("history_commit_count", "").isdigit() or
            int(values["history_commit_count"]) < 1):
        stop(label + "-generation", 65)
    for key, value in values.items():
        if key.endswith("_blob") and (not re.fullmatch(r"[0-9a-f]{40}", value) or
                                       value in {"0" * 40, "f" * 40}):
            stop(label + "-blob", 65)
        if key.endswith("_sha256") and (not re.fullmatch(r"[0-9a-f]{64}", value) or
                                         value in {"0" * 64, "f" * 64}):
            stop(label + "-digest", 65)
    if len(CURRENT_PACKAGE_FILE_FIELDS) + 2 != 20:
        stop(label + "-package-count", 65)
    all_paths = dict(CURRENT_REVIEW_ONLY_PATHS)
    for basename, (field, expected_path) in CURRENT_PACKAGE_FILE_FIELDS.items():
        if os.path.basename(expected_path) != basename:
            stop(label + "-flat-name-contract", 65)
        all_paths[field] = expected_path
    for field, expected_path in all_paths.items():
        if values.get(field) != expected_path:
            stop(label + "-path-contract", 65)
        stem = field[:-5]
        if (not re.fullmatch(r"[0-9a-f]{40}", values.get(stem + "_blob", "")) or
                not re.fullmatch(r"[0-9a-f]{64}", values.get(stem + "_sha256", ""))):
            stop(label + "-identity-contract", 65)
    if (not re.fullmatch(r"[0-9a-f]{64}",
                         values.get("prepare_stage_root_sh_sha256", "")) or
            not re.fullmatch(r"[0-9a-f]{64}", values.get("bundle_sha256", ""))):
        stop(label + "-self-contract", 65)
    return values


def validate_current_authority(auth_descriptor):
    require_exact_names(auth_descriptor, {
        os.path.basename(current_manifest), os.path.basename(current_manifest_pending),
        os.path.basename(current_self), os.path.basename(current_self_pending),
    }, "authority")
    descriptors = []
    try:
        for name, mode_bits, expected_sha, label in (
                (os.path.basename(current_manifest_pending), 0o600,
                 current_manifest_sha, "authority-manifest-pending"),
                (os.path.basename(current_manifest), 0o600,
                 current_manifest_sha, "authority-manifest-final")):
            descriptors.append(require_file_at(
                auth_descriptor, name, ROOT_UID, ROOT_GID, mode_bits, 2,
                expected_sha, label))
        same_open_inode(descriptors[0], descriptors[1], "authority-manifest")
        manifest_payload = read_all(descriptors[1])
        values = validate_current_manifest_payload(
            manifest_payload, "authority-manifest")
        authority_self_sha = values["prepare_stage_root_sh_sha256"]
        for name, label in (
                (os.path.basename(current_self_pending), "authority-self-pending"),
                (os.path.basename(current_self), "authority-self-final")):
            descriptors.append(require_file_at(
                auth_descriptor, name, ROOT_UID, ROOT_GID, 0o700, 2,
                authority_self_sha, label))
        same_open_inode(descriptors[2], descriptors[3], "authority-self")
        if hashlib.sha256(read_all(descriptors[3])).hexdigest() != authority_self_sha:
            stop("authority-manifest-contract", 65)
        return values, authority_self_sha, tuple(descriptors)
    except BaseException:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        raise


def converge_current_authority(auth_descriptor, expected_values,
                               authority_self_sha, descriptors):
    if len(descriptors) != 4:
        stop("authority-held-count", 65)
    expected = (
        (os.path.basename(current_manifest_pending), 0o600,
         current_manifest_sha, "authority-manifest-pending-postfsync"),
        (os.path.basename(current_manifest), 0o600,
         current_manifest_sha, "authority-manifest-final-postfsync"),
        (os.path.basename(current_self_pending), 0o700,
         authority_self_sha, "authority-self-pending-postfsync"),
        (os.path.basename(current_self), 0o700,
         authority_self_sha, "authority-self-final-postfsync"),
    )
    for descriptor in descriptors:
        os.fsync(descriptor)
    os.fsync(auth_descriptor)
    require_exact_names(auth_descriptor, {item[0] for item in expected},
                        "authority-postfsync")
    for descriptor, (name, mode_bits, expected_sha, label) in zip(
            descriptors, expected):
        metadata = os.fstat(descriptor)
        named = os.stat(name, dir_fd=auth_descriptor, follow_symlinks=False)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != ROOT_UID or
                metadata.st_gid != ROOT_GID or
                stat.S_IMODE(metadata.st_mode) != mode_bits or
                metadata.st_nlink != 2 or
                (metadata.st_dev, metadata.st_ino) != (named.st_dev, named.st_ino) or
                sha256_fd(descriptor) != expected_sha):
            stop(label)
    same_open_inode(descriptors[0], descriptors[1],
                    "authority-manifest-postfsync")
    same_open_inode(descriptors[2], descriptors[3],
                    "authority-self-postfsync")
    post_values = validate_current_manifest_payload(
        read_all(descriptors[1]), "authority-manifest-postfsync")
    if (post_values != expected_values or
            post_values["prepare_stage_root_sh_sha256"] != authority_self_sha or
            hashlib.sha256(read_all(descriptors[3])).hexdigest() != authority_self_sha):
        stop("authority-postfsync-drift")


def validate_intake(descriptor, user_uid, user_gid):
    require_dir_fd(descriptor, user_uid, user_gid, 0o700, "intake")
    require_exact_names(descriptor, {"package-manifest.v1", "prepare-stage-root.sh"},
                        "intake")
    manifest_descriptor = self_descriptor = None
    try:
        manifest_descriptor = require_file_at(
            descriptor, "package-manifest.v1", user_uid, user_gid, 0o600, 1,
            current_manifest_sha, "intake-manifest")
        self_descriptor = require_file_at(
            descriptor, "prepare-stage-root.sh", user_uid, user_gid, 0o600, 1,
            current_self_sha, "intake-self")
        validate_current_manifest_payload(read_all(manifest_descriptor), "intake-manifest")
    finally:
        if self_descriptor is not None:
            os.close(self_descriptor)
        if manifest_descriptor is not None:
            os.close(manifest_descriptor)
    os.fsync(descriptor)
    manifest_descriptor = self_descriptor = None
    try:
        manifest_descriptor = require_file_at(
            descriptor, "package-manifest.v1", user_uid, user_gid, 0o600, 1,
            current_manifest_sha, "intake-manifest-postfsync")
        self_descriptor = require_file_at(
            descriptor, "prepare-stage-root.sh", user_uid, user_gid, 0o600, 1,
            current_self_sha, "intake-self-postfsync")
        validate_current_manifest_payload(
            read_all(manifest_descriptor), "intake-manifest-postfsync")
    finally:
        if self_descriptor is not None:
            os.close(self_descriptor)
        if manifest_descriptor is not None:
            os.close(manifest_descriptor)


OLD_PACKAGE_FILES = {
    "source-4f2a9b61.bundle":
        (2469874, "b74811808e0413714dcf20b8292fe68631f603c0b9a68bc9951af481477b413b"),
    "package-manifest.v1":
        (7315, "2d6c6caac080b599fbfa0f73c64f6976cf30d1504fc506ebd39c638b2f9449e3"),
    "bind-final-package.sh":
        (17015, "a808a7879ef64190eff9e81e6b694acea7bc04b1b74ffad44109b237a5eb14ca"),
    "controller.sh":
        (43303, "fb8a7a685b5a6b73de851ee9a3396f4154cc4ae083a7c36f3b3128b2b9a2e77d"),
    "prepare-stage-root.sh":
        (54230, "1bcb8db91d976d2a1d95f7d87223a2dac4a1678f74c1c25542e54b01ee10eeea"),
    "provision-ubuntu-test-host.sh":
        (19437, "078d191b0edbafe27e9f684d3fa495e04d7217a01d0ec1fd32eaede211178c8f"),
    "root-matrix-n-r.sh":
        (1101, "9ec125c2933866431779b760d41c6484cc0fbb9e5e9f3b5431c4a56fbab63e07"),
    "check-realhost-iperf.py":
        (21027, "9a52378b8a1ef6043d4d5792471c8239a0392a80da72f5c00846dd89e88ccd67"),
    "test-hermetic-matrix.sh":
        (6694, "9b81949416a1b4df91fee0e7d31a3de2c6ba9b474dc9c0f4dbbb1cc609207499"),
    "test_matrix_static.py":
        (5656, "8de2dcdc866938da0502f1ad73ac9b38c9b6ff4066c76e9cbc946c9ca30a53f8"),
    "checksum-module-lease.sh":
        (23755, "4ab9a22910e8d597cc04bb4fdde9e1b32d37a1bb2c6ad7b76f52d576b5a9adb2"),
    "root-fresh-verifier-gate.sh":
        (65201, "4c2cf85b7e571df9b7ed4a77fa720c9f5e35950d44af5a39499a7ad700fe6a27"),
    "test-hermetic-fresh-verifier-gate.sh":
        (14628, "c9b5b1f954c794c5c986214777727a76579f670db9587f319ac148fc0c2a05f3"),
    "test_fresh_verifier_gate_static.py":
        (17307, "ace6951027788e82ad879caf285316af4e6ee81fdb6746f569cd7c22b9f80bf3"),
    "realnic_acceptance.py":
        (216405, "a88100b2a23ad41dd3e644c3ba1c7a722d58c8184a997aabf0ceab78552c6339"),
    "test_realnic_acceptance.py":
        (148160, "fcb3d0dadee6da6e0ad67d028f268ebe43575287f555cd8100d279f8a3b0b79c"),
    "test_realnic_acceptance_static.py":
        (14894, "ba8aef3219a0cf2a5c6b5058b245f64eb828a08bb532d2aa0291f51ee7206ad2"),
}

OLD_BOOTSTRAP_FILES = {
    "prepare-stage-root.sh":
        (54230, "1bcb8db91d976d2a1d95f7d87223a2dac4a1678f74c1c25542e54b01ee10eeea"),
    "provision-ubuntu-test-host.sh":
        (19437, "078d191b0edbafe27e9f684d3fa495e04d7217a01d0ec1fd32eaede211178c8f"),
}


def validate_old_package(descriptor, user_uid, user_gid):
    require_dir_fd(descriptor, user_uid, user_gid, 0o700, "predecessor-package")
    if len(OLD_PACKAGE_FILES) != 17:
        stop("predecessor-package-count", 65)
    require_exact_names(descriptor, OLD_PACKAGE_FILES, "predecessor-package")
    manifest_descriptor = require_sized_file_at(
        descriptor, "package-manifest.v1", user_uid, user_gid, 0o600, 1,
        predecessor_manifest_sha, 7315, "predecessor-manifest")
    try:
        manifest_payload = read_all(manifest_descriptor)
    finally:
        os.close(manifest_descriptor)
    old_keys, values = parse_manifest_ordered(manifest_payload, "predecessor-manifest")
    if (manifest_payload != OLD_MANIFEST_BYTES or len(old_keys) != 103 or
            values.get("format") != "wg-mix-ebpf-b82-v6-package-v4" or
            values.get("integration_commit") != predecessor_commit or
            values.get("bundle_sha256") !=
            "b74811808e0413714dcf20b8292fe68631f603c0b9a68bc9951af481477b413b"):
        stop("predecessor-manifest-contract", 65)
    if entry_stat(descriptor, FAILURE_BASENAME) is not None:
        stop("failure-input-unexpectedly-present", 78)
    for name, (expected_size, expected_sha) in OLD_PACKAGE_FILES.items():
        file_descriptor = require_sized_file_at(
            descriptor, name, user_uid, user_gid, 0o600, 1, expected_sha,
            expected_size, "predecessor-package-" + name)
        os.close(file_descriptor)
    os.fsync(descriptor)
    for name, (expected_size, expected_sha) in OLD_PACKAGE_FILES.items():
        file_descriptor = require_sized_file_at(
            descriptor, name, user_uid, user_gid, 0o600, 1, expected_sha,
            expected_size, "predecessor-package-postfsync-" + name)
        os.close(file_descriptor)
    return values


def validate_old_bootstrap(descriptor):
    require_dir_fd(descriptor, ROOT_UID, ROOT_GID, 0o700, "predecessor-bootstrap")
    if len(OLD_BOOTSTRAP_FILES) != 2:
        stop("predecessor-bootstrap-count", 65)
    require_exact_names(descriptor, OLD_BOOTSTRAP_FILES, "predecessor-bootstrap")
    for name, (expected_size, expected_sha) in OLD_BOOTSTRAP_FILES.items():
        file_descriptor = require_sized_file_at(
            descriptor, name, ROOT_UID, ROOT_GID, 0o700, 1,
            expected_sha, expected_size, "predecessor-bootstrap-" + name)
        os.close(file_descriptor)
    os.fsync(descriptor)
    for name, (expected_size, expected_sha) in OLD_BOOTSTRAP_FILES.items():
        file_descriptor = require_sized_file_at(
            descriptor, name, ROOT_UID, ROOT_GID, 0o700, 1,
            expected_sha, expected_size, "predecessor-bootstrap-postfsync-" + name)
        os.close(file_descriptor)


def verify_old_provisioner_check(bootstrap_descriptor):
    provisioner = require_sized_file_at(
        bootstrap_descriptor, "provision-ubuntu-test-host.sh", ROOT_UID, ROOT_GID,
        0o700, 1, OLD_BOOTSTRAP_FILES["provision-ubuntu-test-host.sh"][1],
        OLD_BOOTSTRAP_FILES["provision-ubuntu-test-host.sh"][0],
        "predecessor-provisioner-check")
    try:
        try:
            result = subprocess.run(
                ["/bin/bash", "-p", f"/proc/self/fd/{provisioner}", "--check",
                 "--expected-address", "192.168.10.82",
                 "--expected-interface", "ens33",
                 "--expected-hostname", expected_hostname,
                 "--expected-kernel", expected_kernel,
                 "--expected-machine-id", expected_machine_id],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, check=False, timeout=600,
                pass_fds=(provisioner,),
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
        except subprocess.TimeoutExpired:
            stop("predecessor-provision-check-timeout", 124)
        if result.returncode != 0:
            stop("predecessor-provision-check-rc", 78)
        try:
            output = result.stdout.decode("utf-8", "strict")
        except UnicodeDecodeError:
            stop("predecessor-provision-check-encoding", 78)
        if not output.endswith("\n") or "\0" in output or "\r" in output:
            stop("predecessor-provision-check-encoding", 78)
        lines = output[:-1].split("\n")
        required = (
            "mode=check",
            "missing_packages=",
            "plan_apt_commands=skipped reason=fixed-package-set-already-installed",
            "plan_complete planned_commands_executed=0 writes=0 automatic_cleanup=0",
        )
        if any(lines.count(line) != 1 for line in required):
            stop("predecessor-provision-check-evidence", 78)
        forbidden_prefixes = ("plan_command=", "write_start ", "write_finish ")
        if (any(line.startswith(forbidden_prefixes) for line in lines) or
                lines.count("provisioning completed") != 0 or
                sum(line.startswith("missing_packages=") for line in lines) != 1):
            stop("predecessor-provision-check-writes", 78)
        held = os.fstat(provisioner)
        named = os.stat("provision-ubuntu-test-host.sh", dir_fd=bootstrap_descriptor,
                        follow_symlinks=False)
        if ((held.st_dev, held.st_ino) != (named.st_dev, named.st_ino) or
                held.st_size != OLD_BOOTSTRAP_FILES["provision-ubuntu-test-host.sh"][0] or
                sha256_fd(provisioner) !=
                OLD_BOOTSTRAP_FILES["provision-ubuntu-test-host.sh"][1]):
            stop("predecessor-provision-check-postidentity", 78)
        os.fsync(provisioner)
        os.fsync(bootstrap_descriptor)
        return ("none", "0")
    finally:
        os.close(provisioner)


def regular_present(parent_descriptor, name, label):
    metadata = entry_stat(parent_descriptor, name)
    if metadata is None:
        return False
    if not stat.S_ISREG(metadata.st_mode):
        stop(label + "-not-regular")
    return True


def classify_state(home_descriptor, run_descriptor, user_uid, user_gid,
                   allow_lockless_d=False):
    source_intake_parent = source_package_parent = source_bootstrap_parent = None
    try:
        source_intake_parent, source_intake_name = open_parent(user_intake)
        source_package_parent, source_package_name = open_parent(source_package)
        source_bootstrap_parent, source_bootstrap_name = open_parent(source_bootstrap)
        source_bits = (
            entry_is_directory(source_intake_parent, source_intake_name, "source-intake"),
            entry_is_directory(source_package_parent, source_package_name, "source-package"),
            entry_is_directory(source_bootstrap_parent, source_bootstrap_name,
                               "source-bootstrap"),
        )
    finally:
        if source_bootstrap_parent is not None:
            os.close(source_bootstrap_parent)
        if source_package_parent is not None:
            os.close(source_package_parent)
        if source_intake_parent is not None:
            os.close(source_intake_parent)
    destination_bits = (
        entry_is_directory(home_descriptor, os.path.basename(q_intake), "q-intake"),
        entry_is_directory(home_descriptor, os.path.basename(q_package), "q-package"),
        entry_is_directory(run_descriptor, os.path.basename(q_bootstrap), "q-bootstrap"),
    )
    final_present = regular_present(
        run_descriptor, os.path.basename(receipt_final), "receipt-final")
    pending_present = regular_present(
        run_descriptor, os.path.basename(receipt_pending), "receipt-pending")
    signature = source_bits + destination_bits + (pending_present, final_present)
    states = {
        (True, True, True, False, False, False, False, False): "D",
        (False, True, True, True, False, False, False, False): "I",
        (False, False, True, True, True, False, False, False): "S1",
        (False, False, False, True, True, True, False, False): "S2",
        (False, False, False, True, True, True, True, False): "S2P",
        (False, False, False, True, True, True, False, True): "T_CANDIDATE",
    }
    state = states.get(signature)
    if state is None and ((destination_bits[0] or destination_bits[1]) and
                          not source_bits[2] and not destination_bits[2]):
        stop("same-boot-residual")
    if state is None:
        stop("retirement-state")
    expected_home = {"authority"}
    if state in {"I", "S1", "S2", "S2P", "T_CANDIDATE"}:
        expected_home.add(os.path.basename(q_intake))
    if state in {"S1", "S2", "S2P", "T_CANDIDATE"}:
        expected_home.add(os.path.basename(q_package))
    expected_run = set() if allow_lockless_d and state == "D" else {
        os.path.basename(lock_path)}
    if state in {"S2", "S2P", "T_CANDIDATE"}:
        expected_run.add(os.path.basename(q_bootstrap))
    if state == "S2P":
        expected_run.add(os.path.basename(receipt_pending))
    if state == "T_CANDIDATE":
        expected_run.add(os.path.basename(receipt_final))
    require_exact_names(home_descriptor, expected_home, "home-qroot")
    require_exact_names(run_descriptor, expected_run, "run-qroot")
    return state, pending_present


def boot_identity():
    with open("/proc/sys/kernel/random/boot_id", "r", encoding="ascii") as stream:
        value = stream.read().strip()
    if not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                        value):
        stop("boot-id")
    return value


def write_all(descriptor, payload):
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            stop("short-write")
        offset += written


def acquire_retirement_lock(home_descriptor, run_descriptor, user_uid, user_gid):
    writable = mode == "retire-postflight-f75fe7678cfd-r2"
    lock_name = os.path.basename(lock_path)
    created = False
    lock_descriptor = None
    try:
        if entry_stat(run_descriptor, lock_name) is None:
            if not writable:
                stop("retirement-lock-absent", 78)
            provisional_state, provisional_pending = classify_state(
                home_descriptor, run_descriptor, user_uid, user_gid,
                allow_lockless_d=True)
            if provisional_state != "D" or provisional_pending:
                stop("lockless-state-not-delivered")
            try:
                lock_descriptor = os.open(
                    lock_name,
                    os.O_RDWR | os.O_CREAT | os.O_EXCL |
                    O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK,
                    0o600, dir_fd=run_descriptor)
            except FileExistsError:
                stop("retirement-lock-create-race", 73)
            created = True
            metadata = os.fstat(lock_descriptor)
            named = os.stat(lock_name, dir_fd=run_descriptor, follow_symlinks=False)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != ROOT_UID or
                    metadata.st_gid != ROOT_GID or
                    stat.S_IMODE(metadata.st_mode) != 0o600 or
                    metadata.st_nlink != 1 or
                    (metadata.st_dev, metadata.st_ino) != (named.st_dev, named.st_ino)):
                stop("retirement-lock-created-metadata")
            os.fsync(lock_descriptor)
            os.fsync(run_descriptor)
        else:
            lock_descriptor = require_file_at(
                run_descriptor, lock_name, ROOT_UID, ROOT_GID, 0o600, 1,
                None, "retirement-lock", writable=writable)
        lock_mode = fcntl.LOCK_EX if writable else fcntl.LOCK_SH
        try:
            fcntl.flock(lock_descriptor, lock_mode | fcntl.LOCK_NB)
        except BlockingIOError:
            stop("retirement-lock-busy", 78)
        return lock_descriptor, created
    except BaseException:
        if lock_descriptor is not None:
            os.close(lock_descriptor)
        raise


def initialize_or_verify_boot_marker(lock_descriptor, run_descriptor, state, boot_id):
    writable = mode == "retire-postflight-f75fe7678cfd-r2"
    expected = f"boot_id\t{boot_id}\n".encode("ascii")
    held = os.fstat(lock_descriptor)
    named = os.stat(os.path.basename(lock_path), dir_fd=run_descriptor,
                    follow_symlinks=False)
    if (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino):
        stop("boot-marker-lock-replaced")
    existing = read_all(lock_descriptor, 256)
    if existing == expected:
        os.fsync(lock_descriptor)
        os.fsync(run_descriptor)
        named = os.stat(os.path.basename(lock_path), dir_fd=run_descriptor,
                        follow_symlinks=False)
        if ((held.st_dev, held.st_ino) != (named.st_dev, named.st_ino) or
                read_all(lock_descriptor, 256) != expected):
            stop("boot-marker-convergence-drift")
        return
    if (state != "D" or not writable or not expected.startswith(existing)):
        stop("same-boot-residual")
    os.ftruncate(lock_descriptor, 0)
    os.lseek(lock_descriptor, 0, os.SEEK_SET)
    write_all(lock_descriptor, expected)
    os.fsync(lock_descriptor)
    os.fsync(run_descriptor)
    named = os.stat(os.path.basename(lock_path), dir_fd=run_descriptor,
                    follow_symlinks=False)
    if ((held.st_dev, held.st_ino) != (named.st_dev, named.st_ino) or
            read_all(lock_descriptor, 256) != expected):
        stop("boot-marker-postwrite")


def receipt_bytes(predecessor_values, current_values):
    if (not re.fullmatch(r"[0-9a-f]{64}", current_manifest_sha) or
            not re.fullmatch(r"[0-9a-f]{64}", current_self_sha) or
            not re.fullmatch(r"[0-9a-f]{40}",
                             current_values.get("integration_commit", ""))):
        stop("receipt-dynamic-authority", 65)
    lines = (
        ("format", "wg-mix-ebpf-b82-postflight-retirement-terminal-v1"),
        ("retire_id", "c8e41d73-f75fe7678cfd-r2"),
        ("state", "TERMINAL"),
        ("predecessor_commit", "f75fe7678cfdecf08173fd201be5c055417d6e11"),
        ("predecessor_manifest_sha256",
         "2d6c6caac080b599fbfa0f73c64f6976cf30d1504fc506ebd39c638b2f9449e3"),
        ("predecessor_bundle_sha256",
         "b74811808e0413714dcf20b8292fe68631f603c0b9a68bc9951af481477b413b"),
        ("predecessor_package_format", "wg-mix-ebpf-b82-v6-package-v4"),
        ("predecessor_manifest_field_count", "103"),
        ("predecessor_package_entry_count", "17"),
        ("predecessor_bootstrap_entry_count", "2"),
        ("authority_manifest_sha256", current_manifest_sha),
        ("authority_prepare_stage_root_sha256", current_self_sha),
        ("authority_integration_commit", current_values["integration_commit"]),
        ("authority_package_format", "wg-mix-ebpf-b82-v6-package-v5"),
        ("authority_manifest_field_count", "112"),
        ("authority_transfer_entry_count", "20"),
        ("prior_retirement_id", "c8e41d73-2c690050ae1d-r1"),
        ("prior_retirement_receipt_sha256",
         "4c3e9bfd3d4e64f6626abaa43e20cf5e4df6b193395cee6a39953b1c4da7d188"),
        ("failure_cut", "postflight-hermetic-matrix-before-stage-snapshot"),
        ("failure_point", "hermetic-matrix"),
        ("failure_reason", "review-input-is-not-a-regular-file"),
        ("failure_path", source_package + "/test-hermetic-checksum-module-lease.sh"),
        ("failure_rc", "1"),
        ("provision_check", "missing_set=none,writes=0"),
        ("bootstrap_snapshot_state", "absent"),
        ("stage_root_state", "absent"),
        ("source_intake", user_intake),
        ("source_package", source_package),
        ("source_bootstrap", source_bootstrap),
        ("quarantine_intake", q_intake),
        ("quarantine_package", q_package),
        ("quarantine_bootstrap", q_bootstrap),
        ("rename_order", "intake,package,bootstrap"),
        ("rename_primitive", "renameat2-RENAME_NOREPLACE-dirfd-v1"),
        ("retention", "no-unlink-no-rmdir-no-copy-fallback"),
    )
    payload = ("".join(f"{key}\t{value}\n" for key, value in lines)).encode("ascii")
    if (len(lines) != 35 or len(payload) != 1998 or b"\0" in payload or
            b"\r" in payload or not payload.endswith(b"\n")):
        stop("receipt-contract", 65)
    return payload


def validate_receipt(run_descriptor, payload):
    descriptor = require_file_at(
        run_descriptor, os.path.basename(receipt_final), ROOT_UID, ROOT_GID, 0o600,
        1, hashlib.sha256(payload).hexdigest(), "receipt-final")
    try:
        if read_all(descriptor, 8192) != payload:
            stop("receipt-content")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def validate_pending_receipt(run_descriptor, expected_payload, writable=False):
    descriptor = require_file_at(
        run_descriptor, os.path.basename(receipt_pending), ROOT_UID, ROOT_GID,
        0o600, 1, None, "receipt-pending", writable=writable)
    try:
        existing = read_all(descriptor, 8192)
        if not expected_payload.startswith(existing):
            stop("receipt-pending-not-owned-prefix")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def validate_state_objects(state, pending_present, home_descriptor, run_descriptor,
                           user_uid, user_gid, current_values, boot_id):
    require_path_absent(STAGE_PATH, "failed-stage")
    require_path_absent(PHYSICAL_LOCK_PATH, "physical-interface-lock")
    validate_r1_terminal(boot_id, user_uid, user_gid)
    intake_path = user_intake if state == "D" else q_intake
    package_path = source_package if state in {"D", "I"} else q_package
    bootstrap_path = source_bootstrap if state in {"D", "I", "S1"} else q_bootstrap
    intake_descriptor = package_descriptor = bootstrap_descriptor = None
    try:
        intake_descriptor = open_abs_dir(intake_path)
        package_descriptor = open_abs_dir(package_path)
        bootstrap_descriptor = open_abs_dir(bootstrap_path)
        validate_intake(intake_descriptor, user_uid, user_gid)
        predecessor_values = validate_old_package(
            package_descriptor, user_uid, user_gid)
        validate_old_bootstrap(bootstrap_descriptor)
        provision_proof = verify_old_provisioner_check(bootstrap_descriptor)
    finally:
        if bootstrap_descriptor is not None:
            os.close(bootstrap_descriptor)
        if package_descriptor is not None:
            os.close(package_descriptor)
        if intake_descriptor is not None:
            os.close(intake_descriptor)
    if provision_proof != ("none", "0"):
        stop("predecessor-provision-proof")
    payload = receipt_bytes(predecessor_values, current_values)
    if state == "T_CANDIDATE":
        receipt_descriptor = validate_receipt(run_descriptor, payload)
        os.close(receipt_descriptor)
    elif state == "S2P" and pending_present:
        pending_descriptor = validate_pending_receipt(run_descriptor, payload)
        os.close(pending_descriptor)
    return predecessor_values, payload


try:
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    libc_renameat2 = libc.renameat2
except (OSError, AttributeError):
    stop("glibc-renameat2-unavailable", 69)
libc_renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p,
                           ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
libc_renameat2.restype = ctypes.c_int


def renameat2_noreplace(source_parent, source_name, destination_parent,
                        destination_name):
    result = libc_renameat2(source_parent, os.fsencode(source_name),
                            destination_parent, os.fsencode(destination_name),
                            RENAME_NOREPLACE)
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))


def rename_directory_noreplace(source, destination, uid, gid, validator, label):
    source_parent = destination_parent = None
    held_descriptor = None
    destination_descriptor = None
    try:
        source_parent, source_name = open_parent(source)
        destination_parent, destination_name = open_parent(destination)
        source_parent_metadata = os.fstat(source_parent)
        destination_parent_metadata = os.fstat(destination_parent)
        if (source_parent_metadata.st_dev != destination_parent_metadata.st_dev or
                fd_mnt_id(source_parent) != fd_mnt_id(destination_parent)):
            stop(label + "-cross-mount")
        if entry_stat(destination_parent, destination_name) is not None:
            stop(label + "-destination-exists", 73)
        held_descriptor = open_child_dir(
            source_parent, source_name, uid, gid, 0o700, label + "-source")
        validator(held_descriptor)
        held_identity = os.fstat(held_descriptor)
        held_mount = fd_mnt_id(held_descriptor)
        if (held_identity.st_dev != source_parent_metadata.st_dev or
                held_mount != fd_mnt_id(source_parent)):
            stop(label + "-source-mount")
        renameat2_noreplace(source_parent, source_name,
                            destination_parent, destination_name)
        destination_descriptor = open_child_dir(
            destination_parent, destination_name, uid, gid, 0o700,
            label + "-destination")
        same_open_inode(held_descriptor, destination_descriptor, label + "-held")
        if ((held_identity.st_dev, held_identity.st_ino) !=
                (os.fstat(destination_descriptor).st_dev,
                 os.fstat(destination_descriptor).st_ino) or
                held_mount != fd_mnt_id(destination_descriptor)):
            stop(label + "-postrename-identity")
        validator(destination_descriptor)
        if entry_stat(source_parent, source_name) is not None:
            stop(label + "-source-still-present")
        os.fsync(source_parent)
        os.fsync(destination_parent)
        if entry_stat(source_parent, source_name) is not None:
            stop(label + "-source-postfsync")
        post_named = os.stat(
            destination_name, dir_fd=destination_parent, follow_symlinks=False)
        if ((post_named.st_dev, post_named.st_ino) !=
                (held_identity.st_dev, held_identity.st_ino) or
                fd_mnt_id(destination_descriptor) != held_mount):
            stop(label + "-destination-postfsync")
        same_open_inode(held_descriptor, destination_descriptor, label + "-postfsync")
        validator(destination_descriptor)
        validator(held_descriptor)
    finally:
        if destination_descriptor is not None:
            os.close(destination_descriptor)
        if held_descriptor is not None:
            os.close(held_descriptor)
        if destination_parent is not None:
            os.close(destination_parent)
        if source_parent is not None:
            os.close(source_parent)


def publish_receipt(run_descriptor, payload, pending_present):
    pending_name = os.path.basename(receipt_pending)
    final_name = os.path.basename(receipt_final)
    namespace_writes = 0
    pending_descriptor = None
    try:
        if pending_present:
            pending_descriptor = validate_pending_receipt(
                run_descriptor, payload, writable=True)
        else:
            try:
                pending_descriptor = os.open(
                    pending_name,
                    os.O_RDWR | os.O_CREAT | os.O_EXCL |
                    O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK,
                    0o600, dir_fd=run_descriptor)
            except FileExistsError:
                stop("receipt-pending-race", 73)
            namespace_writes += 1
            metadata = os.fstat(pending_descriptor)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != ROOT_UID or
                    metadata.st_gid != ROOT_GID or
                    stat.S_IMODE(metadata.st_mode) != 0o600 or
                    metadata.st_nlink != 1):
                stop("receipt-pending-created-metadata")
            os.fsync(run_descriptor)
        if entry_stat(run_descriptor, final_name) is not None:
            stop("receipt-final-exists", 73)
        pending_identity = os.fstat(pending_descriptor)
        os.ftruncate(pending_descriptor, 0)
        os.lseek(pending_descriptor, 0, os.SEEK_SET)
        write_all(pending_descriptor, payload)
        os.fsync(pending_descriptor)
        path_identity = os.stat(
            pending_name, dir_fd=run_descriptor, follow_symlinks=False)
        if ((pending_identity.st_dev, pending_identity.st_ino) !=
                (path_identity.st_dev, path_identity.st_ino) or
                read_all(pending_descriptor, 8192) != payload):
            stop("receipt-pending-postwrite")
        renameat2_noreplace(run_descriptor, pending_name, run_descriptor, final_name)
        namespace_writes += 1
    finally:
        if pending_descriptor is not None:
            os.close(pending_descriptor)
    final_descriptor = validate_receipt(run_descriptor, payload)
    try:
        os.fsync(final_descriptor)
        os.fsync(run_descriptor)
    finally:
        os.close(final_descriptor)
    return namespace_writes


def converge_completed_rename(source, destination, uid, gid, label):
    source_parent = destination_parent = None
    destination_descriptor = None
    try:
        source_parent, source_name = open_parent(source)
        destination_parent, destination_name = open_parent(destination)
        source_parent_metadata = os.fstat(source_parent)
        destination_parent_metadata = os.fstat(destination_parent)
        if (source_parent_metadata.st_dev != destination_parent_metadata.st_dev or
                fd_mnt_id(source_parent) != fd_mnt_id(destination_parent)):
            stop(label + "-cross-mount")
        if entry_stat(source_parent, source_name) is not None:
            stop(label + "-source-present")
        destination_descriptor = open_child_dir(
            destination_parent, destination_name, uid, gid, 0o700,
            label + "-destination")
        destination_identity = os.fstat(destination_descriptor)
        destination_mount = fd_mnt_id(destination_descriptor)
        if (destination_identity.st_dev != destination_parent_metadata.st_dev or
                destination_mount != fd_mnt_id(destination_parent)):
            stop(label + "-destination-mount")
        os.fsync(source_parent)
        os.fsync(destination_parent)
        if entry_stat(source_parent, source_name) is not None:
            stop(label + "-source-postfsync")
        named = os.stat(
            destination_name, dir_fd=destination_parent, follow_symlinks=False)
        if ((named.st_dev, named.st_ino) !=
                (destination_identity.st_dev, destination_identity.st_ino) or
                fd_mnt_id(destination_descriptor) != destination_mount):
            stop(label + "-destination-postfsync")
        require_dir_fd(destination_descriptor, uid, gid, 0o700,
                       label + "-destination-postfsync")
    finally:
        if destination_descriptor is not None:
            os.close(destination_descriptor)
        if destination_parent is not None:
            os.close(destination_parent)
        if source_parent is not None:
            os.close(source_parent)


def converge_completed_rename_parents(state, user_uid, user_gid):
    completed = []
    if state in {"I", "S1", "S2", "S2P", "T_CANDIDATE"}:
        completed.append((user_intake, q_intake, user_uid, user_gid,
                          "converge-intake"))
    if state in {"S1", "S2", "S2P", "T_CANDIDATE"}:
        completed.append((source_package, q_package, user_uid, user_gid,
                          "converge-package"))
    if state in {"S2", "S2P", "T_CANDIDATE"}:
        completed.append((source_bootstrap, q_bootstrap, ROOT_UID, ROOT_GID,
                          "converge-bootstrap"))
    for source, destination, uid, gid, label in completed:
        converge_completed_rename(source, destination, uid, gid, label)


def converge_resumed_state(expected_state, expected_pending, home_descriptor,
                           run_descriptor, user_uid, user_gid, current_values,
                           boot_id):
    if expected_state not in {"I", "S1", "S2", "S2P"}:
        stop("resume-state")
    converge_completed_rename_parents(expected_state, user_uid, user_gid)
    visible_state, visible_pending = classify_state(
        home_descriptor, run_descriptor, user_uid, user_gid)
    if (visible_state != expected_state or
            visible_pending != expected_pending):
        stop("resume-reclassification")
    predecessor_values, payload = validate_state_objects(
        visible_state, visible_pending, home_descriptor, run_descriptor,
        user_uid, user_gid, current_values, boot_id)
    final_state, final_pending = classify_state(
        home_descriptor, run_descriptor, user_uid, user_gid)
    if final_state != expected_state or final_pending != expected_pending:
        stop("resume-postvalidation-state")
    return predecessor_values, payload


def converge_terminal(home_descriptor, run_descriptor, user_uid, user_gid,
                      current_values, boot_id, payload):
    converge_completed_rename_parents("T_CANDIDATE", user_uid, user_gid)
    final_descriptor = validate_receipt(run_descriptor, payload)
    try:
        os.fsync(final_descriptor)
    finally:
        os.close(final_descriptor)
    os.fsync(run_descriptor)
    visible_state, visible_pending = classify_state(
        home_descriptor, run_descriptor, user_uid, user_gid)
    validate_state_objects(
        visible_state, visible_pending, home_descriptor, run_descriptor,
        user_uid, user_gid, current_values, boot_id)
    if visible_state != "T_CANDIDATE":
        stop("terminal-reclassification")
    final_state, final_pending = classify_state(
        home_descriptor, run_descriptor, user_uid, user_gid)
    if final_state != "T_CANDIDATE" or final_pending:
        stop("terminal-postvalidation-state")
    return "T"


def engine_main():
    global current_self_sha
    require_host_identity()
    if (not re.fullmatch(r"[0-9a-f]{64}", current_manifest_sha) or
            predecessor_manifest_sha !=
            "2d6c6caac080b599fbfa0f73c64f6976cf30d1504fc506ebd39c638b2f9449e3" or
            predecessor_commit != "f75fe7678cfdecf08173fd201be5c055417d6e11"):
        stop("digest-authority", 65)
    if (os.path.dirname(current_manifest) != auth_root or
            os.path.dirname(current_manifest_pending) != auth_root or
            os.path.dirname(current_self) != auth_root or
            os.path.dirname(current_self_pending) != auth_root or
            os.path.dirname(q_intake) != home_qroot or
            os.path.dirname(q_package) != home_qroot or
            os.path.dirname(q_bootstrap) != run_qroot or
            os.path.dirname(lock_path) != run_qroot or
            os.path.dirname(receipt_pending) != run_qroot or
            os.path.dirname(receipt_final) != run_qroot):
        stop("path-topology", 65)
    fixed_paths = {
        current_manifest:
            "/home/.wg-mix-ebpf-retirement-c8e41d73-f75fe7678cfd-r2/authority/package-manifest.v1",
        current_manifest_pending:
            "/home/.wg-mix-ebpf-retirement-c8e41d73-f75fe7678cfd-r2/authority/package-manifest.v1.pending",
        current_self:
            "/home/.wg-mix-ebpf-retirement-c8e41d73-f75fe7678cfd-r2/authority/prepare-stage-root.sh",
        current_self_pending:
            "/home/.wg-mix-ebpf-retirement-c8e41d73-f75fe7678cfd-r2/authority/prepare-stage-root.sh.pending",
        user_intake:
            "/home/siyixuan/wg-mix-ebpf-test/retire-postflight-c8e41d73-f75fe7678cfd-r2.intake",
        home_qroot: "/home/.wg-mix-ebpf-retirement-c8e41d73-f75fe7678cfd-r2",
        auth_root: "/home/.wg-mix-ebpf-retirement-c8e41d73-f75fe7678cfd-r2/authority",
        q_intake: "/home/.wg-mix-ebpf-retirement-c8e41d73-f75fe7678cfd-r2/intake",
        q_package: "/home/.wg-mix-ebpf-retirement-c8e41d73-f75fe7678cfd-r2/package",
        source_package: "/home/siyixuan/wg-mix-ebpf-test/unpriv-4f2a9b61",
        source_bootstrap: "/run/wg-mix-ebpf-source-bootstrap-c8e41d73",
        run_qroot: "/run/wg-mix-ebpf-retirement-c8e41d73-f75fe7678cfd-r2",
        q_bootstrap: "/run/wg-mix-ebpf-retirement-c8e41d73-f75fe7678cfd-r2/bootstrap",
        lock_path:
            "/run/wg-mix-ebpf-retirement-c8e41d73-f75fe7678cfd-r2/retirement.v1.lock",
        receipt_pending:
            "/run/wg-mix-ebpf-retirement-c8e41d73-f75fe7678cfd-r2/retirement-complete.v1.pending",
        receipt_final:
            "/run/wg-mix-ebpf-retirement-c8e41d73-f75fe7678cfd-r2/retirement-complete.v1",
    }
    if len(fixed_paths) != 16 or any(actual != expected for actual, expected in fixed_paths.items()):
        stop("fixed-path-contract", 65)
    user = pwd.getpwnam("siyixuan")
    home_descriptor = run_descriptor = None
    auth_descriptor = None
    authority_file_descriptors = ()
    lock_descriptor = None
    try:
        home_descriptor = open_abs_dir(home_qroot)
        run_descriptor = open_abs_dir(run_qroot)
        require_dir_fd(home_descriptor, ROOT_UID, ROOT_GID, 0o700, "home-qroot")
        require_dir_fd(run_descriptor, ROOT_UID, ROOT_GID, 0o700, "run-qroot")
        auth_descriptor = open_child_dir(
            home_descriptor, os.path.basename(auth_root), ROOT_UID, ROOT_GID,
            0o700, "authority-root")
        (current_values, current_self_sha,
         authority_file_descriptors) = validate_current_authority(auth_descriptor)
        converge_current_authority(
            auth_descriptor, current_values, current_self_sha,
            authority_file_descriptors)
        boot_id = boot_identity()
        if entry_stat(run_descriptor, os.path.basename(lock_path)) is None:
            state, pending_present = classify_state(
                home_descriptor, run_descriptor, user.pw_uid, user.pw_gid,
                allow_lockless_d=True)
            if state != "D" or pending_present:
                stop("lockless-state-not-delivered")
            validate_state_objects(
                state, pending_present, home_descriptor, run_descriptor,
                user.pw_uid, user.pw_gid, current_values, boot_id)
        lock_descriptor, lock_created = acquire_retirement_lock(
            home_descriptor, run_descriptor, user.pw_uid, user.pw_gid)
        state, pending_present = classify_state(
            home_descriptor, run_descriptor, user.pw_uid, user.pw_gid)
        validate_state_objects(
            state, pending_present, home_descriptor, run_descriptor,
            user.pw_uid, user.pw_gid, current_values, boot_id)
        initialize_or_verify_boot_marker(lock_descriptor, run_descriptor, state, boot_id)
        state_after_lock, pending_after_lock = classify_state(
            home_descriptor, run_descriptor, user.pw_uid, user.pw_gid)
        if state_after_lock != state or pending_after_lock != pending_present:
            stop("post-lock-state-drift")
        if state in {"I", "S1", "S2", "S2P"}:
            predecessor_values, payload = converge_resumed_state(
                state, pending_present, home_descriptor, run_descriptor,
                user.pw_uid, user.pw_gid, current_values, boot_id)
        else:
            predecessor_values, payload = validate_state_objects(
                state, pending_present, home_descriptor, run_descriptor,
                user.pw_uid, user.pw_gid, current_values, boot_id)

        if mode == "verify-postflight-retirement-r2":
            if state != "T_CANDIDATE":
                stop("retirement-not-terminal", 78)
            terminal_state = converge_terminal(
                home_descriptor, run_descriptor, user.pw_uid, user.pw_gid,
                current_values, boot_id, payload)
            if terminal_state != "T":
                stop("verify-terminal-state")
            print("B82_V6_RETIREMENT_VERIFIED state=T namespace_writes=0 "
                  f"same_boot=1 receipt={receipt_final}")
            return

        if state == "T_CANDIDATE":
            terminal_state = converge_terminal(
                home_descriptor, run_descriptor, user.pw_uid, user.pw_gid,
                current_values, boot_id, payload)
            if terminal_state != "T":
                stop("retire-terminal-state")
            print("B82_V6_RETIREMENT_COMPLETE state=T disposition=verified-existing "
                  "namespace_writes=0 same_boot=1")
            return

        namespace_writes = 1 if lock_created else 0
        if state == "D":
            rename_directory_noreplace(
                user_intake, q_intake, user.pw_uid, user.pw_gid,
                lambda descriptor: validate_intake(
                    descriptor, user.pw_uid, user.pw_gid), "retire-intake")
            namespace_writes += 1
            state, pending_present = classify_state(
                home_descriptor, run_descriptor, user.pw_uid, user.pw_gid)
            if state != "I":
                stop("post-intake-state")
            predecessor_values, payload = validate_state_objects(
                state, pending_present, home_descriptor, run_descriptor,
                user.pw_uid, user.pw_gid, current_values, boot_id)
            confirmed_state, confirmed_pending = classify_state(
                home_descriptor, run_descriptor, user.pw_uid, user.pw_gid)
            if confirmed_state != state or confirmed_pending != pending_present:
                stop("post-intake-validation-state")
        if state == "I":
            rename_directory_noreplace(
                source_package, q_package, user.pw_uid, user.pw_gid,
                lambda descriptor: validate_old_package(
                    descriptor, user.pw_uid, user.pw_gid), "retire-package")
            namespace_writes += 1
            state, pending_present = classify_state(
                home_descriptor, run_descriptor, user.pw_uid, user.pw_gid)
            if state != "S1":
                stop("post-package-state")
            predecessor_values, payload = validate_state_objects(
                state, pending_present, home_descriptor, run_descriptor,
                user.pw_uid, user.pw_gid, current_values, boot_id)
            confirmed_state, confirmed_pending = classify_state(
                home_descriptor, run_descriptor, user.pw_uid, user.pw_gid)
            if confirmed_state != state or confirmed_pending != pending_present:
                stop("post-package-validation-state")
        if state == "S1":
            rename_directory_noreplace(
                source_bootstrap, q_bootstrap, ROOT_UID, ROOT_GID,
                validate_old_bootstrap, "retire-bootstrap")
            namespace_writes += 1
            state, pending_present = classify_state(
                home_descriptor, run_descriptor, user.pw_uid, user.pw_gid)
            if state != "S2":
                stop("post-bootstrap-state")
            predecessor_values, payload = validate_state_objects(
                state, pending_present, home_descriptor, run_descriptor,
                user.pw_uid, user.pw_gid, current_values, boot_id)
            confirmed_state, confirmed_pending = classify_state(
                home_descriptor, run_descriptor, user.pw_uid, user.pw_gid)
            if confirmed_state != state or confirmed_pending != pending_present:
                stop("post-bootstrap-validation-state")
        if state not in {"S2", "S2P"}:
            stop("pre-receipt-state")
        namespace_writes += publish_receipt(
            run_descriptor, payload, state == "S2P" and pending_present)
        state, pending_present = classify_state(
            home_descriptor, run_descriptor, user.pw_uid, user.pw_gid)
        if state != "T_CANDIDATE":
            stop("post-receipt-visible-state")
        terminal_state = converge_terminal(
            home_descriptor, run_descriptor, user.pw_uid, user.pw_gid,
            current_values, boot_id, payload)
        if terminal_state != "T":
            stop("post-receipt-terminal-state")
        print("B82_V6_RETIREMENT_COMPLETE state=T disposition=advanced "
              f"namespace_writes={namespace_writes} same_boot=1")
    finally:
        if lock_descriptor is not None:
            os.close(lock_descriptor)
        for descriptor in reversed(authority_file_descriptors):
            os.close(descriptor)
        if auth_descriptor is not None:
            os.close(auth_descriptor)
        if run_descriptor is not None:
            os.close(run_descriptor)
        if home_descriptor is not None:
            os.close(home_descriptor)


try:
    engine_main()
except RetirementStop as error:
    print(f"B82_V6_RETIREMENT_ENGINE_STOP reason={error.reason} rc={error.code} "
          "cleanup=0 retained=1", file=sys.stderr)
    raise SystemExit(error.code)
except KeyError:
    print("B82_V6_RETIREMENT_ENGINE_STOP reason=manifest-key rc=65 cleanup=0 retained=1",
          file=sys.stderr)
    raise SystemExit(65)
except OSError as error:
    error_number = error.errno if error.errno is not None else 79
    print(f"B82_V6_RETIREMENT_ENGINE_STOP reason=oserror-{error_number} rc=79 "
          "cleanup=0 retained=1", file=sys.stderr)
    raise SystemExit(79)
PY
}


run_stage() {
  local bundle="${SNAPSHOT_BUNDLE}" branch="${INTEGRATION_REF#refs/heads/}"
  local parent_shape

  if [[ -e "${STAGES_ROOT}" || -L "${STAGES_ROOT}" ]]; then
    [[ -d "${STAGES_ROOT}" && ! -L "${STAGES_ROOT}" ]] || fail 'stages-root-shape' 79
    parent_shape="$(/usr/bin/stat -Lc '%U:%G:%a:%F' -- "${STAGES_ROOT}")" || fail 'stages-root-stat'
    [[ "${parent_shape}" == 'root:root:700:directory' ]] || fail 'stages-root-metadata' 79
  else
    run_step S2 /usr/bin/mkdir --mode=0700 -- "${STAGES_ROOT}" || fail 'stages-root-create' $?
  fi
  [[ ! -e "${STAGE_ROOT}" && ! -L "${STAGE_ROOT}" ]] || fail 'stage-exists' 73
  run_step S3 /usr/bin/mkdir --mode=0700 -- "${STAGE_ROOT}" || fail 'stage-create' $?
  acquire_physical_interface_lock || fail 'physical-interface-lock' $?
  run_step S3.legacy-reservation create_legacy_retirement_reservation ||
    fail 'legacy-retirement-reservation-create' $?
  require_legacy_retirement_reservation || fail 'legacy-retirement-reservation-shape' $?
  run_step S3.lock /usr/bin/install --owner=root --group=root --mode=0600 \
    --no-target-directory -- /dev/null "${MODULE_LEASE_LOCK}" || fail 'module-lease-lock-create' $?
  require_module_lease_lock || fail 'module-lease-lock-shape' $?
  run_step S4 /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C \
    GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_NO_REPLACE_OBJECTS=1 \
    /usr/bin/git -c core.hooksPath=/dev/null clone --no-local --no-checkout \
    --single-branch --branch "${branch}" -- "${bundle}" "${EXPECTED_SOURCE}" || fail 'bundle-clone' $?
  run_step S5 /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C \
    GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_NO_REPLACE_OBJECTS=1 \
    /usr/bin/git -c core.hooksPath=/dev/null -C "${EXPECTED_SOURCE}" \
    checkout --detach "${INTEGRATION_COMMIT}" || fail 'checkout' $?
  require_staged_content || fail 'staged-content' $?
  run_step S6 /bin/bash -n "${EXPECTED_SOURCE}/${ROOT_MATRIX_PATH}" \
    "${EXPECTED_SOURCE}/${HERMETIC_PATH}" "${EXPECTED_SOURCE}/${PREPARE_PATH}" \
    "${EXPECTED_SOURCE}/${MODULE_LEASE_HELPER_PATH}" \
    "${EXPECTED_SOURCE}/${MODULE_LEASE_HERMETIC_PATH}" \
    "${EXPECTED_SOURCE}/${ROOT_FRESH_PATH}" "${EXPECTED_SOURCE}/${FRESH_HERMETIC_PATH}" \
    "${EXPECTED_SOURCE}/${PROVISION_PATH}" "${EXPECTED_SOURCE}/${ROOT_VETH_PATH}" \
    "${EXPECTED_SOURCE}/${VETH_HERMETIC_PATH}" "${EXPECTED_SOURCE}/${ROUTED_SEAM_PATH}" \
    "${EXPECTED_SOURCE}/${ROUTED_ROOT_PATH}" "${EXPECTED_SOURCE}/${ROUTED_HERMETIC_PATH}" ||
    fail 'bash-syntax' $?
  run_step S6.realnic /usr/bin/python3 -B -I \
    "${EXPECTED_SOURCE}/${REALNIC_PATH}" --help || fail 'realnic-python-syntax' $?
  run_step S6.realnic-unit /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
    PYTHONDONTWRITEBYTECODE=1 /usr/bin/timeout --signal=TERM --kill-after=10s 10m \
    /usr/bin/python3 -B -I "${EXPECTED_SOURCE}/${REALNIC_TEST_PATH}" ||
    fail 'realnic-hermetic-unit' $?
  run_step S6.realnic-static /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
    PYTHONDONTWRITEBYTECODE=1 /usr/bin/timeout --signal=TERM --kill-after=10s 2m \
    /usr/bin/python3 -B -I "${EXPECTED_SOURCE}/${REALNIC_STATIC_PATH}" ||
    fail 'realnic-hermetic-static' $?
  run_step S6.veth-hermetic /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
    /usr/bin/timeout --signal=TERM --kill-after=10s 10m \
    /bin/bash "${EXPECTED_SOURCE}/${VETH_HERMETIC_PATH}" || fail 'veth-hermetic' $?
  run_step S6.veth-static /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
    PYTHONDONTWRITEBYTECODE=1 /usr/bin/timeout --signal=TERM --kill-after=10s 2m \
    /usr/bin/python3 -B -I "${EXPECTED_SOURCE}/${VETH_STATIC_PATH}" \
    "${EXPECTED_SOURCE}/${ROOT_VETH_PATH}" "${EXPECTED_SOURCE}/${ROOT_MATRIX_PATH}" \
    "${EXPECTED_SOURCE}/${MODULE_LEASE_HELPER_PATH}" || fail 'veth-static' $?
  run_step S6.routed-hermetic /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
    /usr/bin/timeout --signal=TERM --kill-after=10s 10m \
    /bin/bash "${EXPECTED_SOURCE}/${ROUTED_HERMETIC_PATH}" || fail 'routed-hermetic' $?
  run_step S6.routed-static /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
    PYTHONDONTWRITEBYTECODE=1 /usr/bin/timeout --signal=TERM --kill-after=10s 2m \
    /usr/bin/python3 -B -I "${EXPECTED_SOURCE}/${ROUTED_STATIC_PATH}" \
    "${EXPECTED_SOURCE}/${ROUTED_ROOT_PATH}" "${EXPECTED_SOURCE}/${ROUTED_SEAM_PATH}" ||
    fail 'routed-static' $?
  run_step S7 /usr/bin/shellcheck --norc --shell=bash -- \
    "${EXPECTED_SOURCE}/${ROOT_MATRIX_PATH}" "${EXPECTED_SOURCE}/${HERMETIC_PATH}" \
    "${EXPECTED_SOURCE}/${PREPARE_PATH}" "${EXPECTED_SOURCE}/${MODULE_LEASE_HELPER_PATH}" \
    "${EXPECTED_SOURCE}/${MODULE_LEASE_HERMETIC_PATH}" \
    "${EXPECTED_SOURCE}/${ROOT_FRESH_PATH}" "${EXPECTED_SOURCE}/${FRESH_HERMETIC_PATH}" \
    "${EXPECTED_SOURCE}/${PROVISION_PATH}" "${EXPECTED_SOURCE}/${ROOT_VETH_PATH}" \
    "${EXPECTED_SOURCE}/${VETH_HERMETIC_PATH}" "${EXPECTED_SOURCE}/${ROUTED_SEAM_PATH}" \
    "${EXPECTED_SOURCE}/${ROUTED_ROOT_PATH}" "${EXPECTED_SOURCE}/${ROUTED_HERMETIC_PATH}" ||
    fail 'shellcheck' $?
  require_staged_content || fail 'staged-content-postcheck' $?
  require_physical_interface_lock || fail 'physical-interface-lock-drift' $?
  require_legacy_retirement_reservation || fail 'legacy-retirement-reservation-drift' $?
  require_module_lease_lock || fail 'module-lease-lock-drift' $?
  write_binding_marker || fail 'binding-marker' $?
  printf 'B82_V6_STAGE_COMPLETE run_id=%s commit=%s source=%s binding=%s\n' \
    "${RUN_ID}" "${INTEGRATION_COMMIT}" "${EXPECTED_SOURCE}" "${BINDING_MARKER}"
}

main() {
  parse_arguments "$@" || fail 'arguments' $?
  case "${MODE}" in
    snapshot-plan)
      [[ "${MANIFEST}" == "${USER_MANIFEST}" ]] || fail 'snapshot-source-manifest-path' 65
      render_snapshot_plan
      ;;
    snapshot)
      snapshot_package
      ;;
    plan)
      load_root_snapshot_contract
      render_plan
      ;;
    run)
      load_root_snapshot_contract
      run_stage
      ;;
    realnic-plan-snapshot)
      load_root_snapshot_contract
      snapshot_realnic_plan
      ;;
    realnic-plan-verify)
      load_root_snapshot_contract
      verify_realnic_plan
      ;;
    retire-postflight-f75fe7678cfd-r2 | verify-postflight-retirement-r2)
      load_r2_retirement_authority_contract
      run_r2_retirement_engine || fail 'r2-retirement-engine' $?
      ;;
  esac
}

main "$@"
