#!/usr/bin/env bash
set -u
set -o pipefail
umask 077

readonly RUN_ID='c8e41d73'
readonly PACKAGE_ID='4f2a9b61'
readonly CREDENTIAL_PATH='/Users/siyixuan/codes-2/wg-mix-ebpf/credientials/192.168.10.82'
readonly EXPECTED_OUTPUT_PREFIX="/private/tmp/wg-mix-b82-v6-${RUN_ID}-${PACKAGE_ID}-"
readonly R2_PREDECESSOR_COMMIT='f75fe7678cfdecf08173fd201be5c055417d6e11'
readonly R2_PREDECESSOR_REF='refs/heads/codex/tcx-faketcp-final-v2'
readonly R2_PREDECESSOR_PACKAGE='/private/tmp/wg-mix-b82-v6-c8e41d73-4f2a9b61-f75fe7678cfd'
readonly R2_PREDECESSOR_MANIFEST="${R2_PREDECESSOR_PACKAGE}/package-manifest.v1"
readonly R2_PREDECESSOR_MANIFEST_SHA256='2d6c6caac080b599fbfa0f73c64f6976cf30d1504fc506ebd39c638b2f9449e3'
readonly R2_PREDECESSOR_BUNDLE_SHA256='b74811808e0413714dcf20b8292fe68631f603c0b9a68bc9951af481477b413b'
readonly R2_PREDECESSOR_HISTORY_ROOTS_SHA256='9356df63b3d4c4c362912b14ab8ee5cb54d12cd1f14be9aa1fe8e18adbad6f05'
readonly R2_PREDECESSOR_HISTORY_OBJECTS_SHA256='21647f92e57f9dbb8e15707699f632544d6dfcf2e1b4279d775cce1fb82163f3'
R2_PREDECESSOR_DEVICE_INODE=''

MODE=''
MANIFEST=''
MANIFEST_SHA256=''
SUPPLIED_CREDENTIAL_PATH=''
APPROVED_PLAN='none'
APPROVED_PLAN_SHA256='none'

FORMAT=''
MANIFEST_RUN_ID=''
MANIFEST_PACKAGE_ID=''
INTEGRATION_REF=''
INTEGRATION_COMMIT=''
BUNDLE_NAME=''
BUNDLE_SHA256=''
HISTORY_VERIFICATION=''
HISTORY_COMMIT_COUNT=''
HISTORY_ROOTS_SHA256=''
HISTORY_OBJECTS_SHA256=''
WG_STATE=''
WG_INTERFACE=''
WG_LOCAL_ADDRESS=''
WG_PEER_ADDRESS=''
LOCAL_REPOSITORY=''
LOCAL_PACKAGE_DIR=''
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
PHYSICAL_INTERFACE_LOCK=''
LEGACY_MATRIX_MODE=''
REALNIC_PROFILE=''
REALNIC_TRAFFIC_SECONDS=''

BIND_FINAL_PACKAGE_SH_PATH=''
BIND_FINAL_PACKAGE_SH_BLOB=''
BIND_FINAL_PACKAGE_SH_SHA256=''
CONTROLLER_SH_PATH=''
CONTROLLER_SH_BLOB=''
CONTROLLER_SH_SHA256=''
LOCKED_TRANSPORT_EXP_PATH=''
LOCKED_TRANSPORT_EXP_BLOB=''
LOCKED_TRANSPORT_EXP_SHA256=''
ROOT_MATRIX_N_R_SH_PATH=''
ROOT_MATRIX_N_R_SH_BLOB=''
ROOT_MATRIX_N_R_SH_SHA256=''
CHECK_REALHOST_IPERF_PY_PATH=''
CHECK_REALHOST_IPERF_PY_BLOB=''
CHECK_REALHOST_IPERF_PY_SHA256=''
TEST_HERMETIC_MATRIX_SH_PATH=''
TEST_HERMETIC_MATRIX_SH_BLOB=''
TEST_HERMETIC_MATRIX_SH_SHA256=''
TEST_MATRIX_STATIC_PY_PATH=''
TEST_MATRIX_STATIC_PY_BLOB=''
TEST_MATRIX_STATIC_PY_SHA256=''
CHECKSUM_MODULE_LEASE_SH_PATH=''
CHECKSUM_MODULE_LEASE_SH_BLOB=''
CHECKSUM_MODULE_LEASE_SH_SHA256=''
TEST_HERMETIC_CHECKSUM_MODULE_LEASE_SH_PATH=''
TEST_HERMETIC_CHECKSUM_MODULE_LEASE_SH_BLOB=''
TEST_HERMETIC_CHECKSUM_MODULE_LEASE_SH_SHA256=''
TEST_CHECKSUM_MODULE_LEASE_STATIC_PY_PATH=''
TEST_CHECKSUM_MODULE_LEASE_STATIC_PY_BLOB=''
TEST_CHECKSUM_MODULE_LEASE_STATIC_PY_SHA256=''
WG_MIX_FAKETCP_CHECKSUM_C_PATH=''
WG_MIX_FAKETCP_CHECKSUM_C_BLOB=''
WG_MIX_FAKETCP_CHECKSUM_C_SHA256=''
ROOT_FRESH_VERIFIER_GATE_SH_PATH=''
ROOT_FRESH_VERIFIER_GATE_SH_BLOB=''
ROOT_FRESH_VERIFIER_GATE_SH_SHA256=''
TEST_HERMETIC_FRESH_VERIFIER_GATE_SH_PATH=''
TEST_HERMETIC_FRESH_VERIFIER_GATE_SH_BLOB=''
TEST_HERMETIC_FRESH_VERIFIER_GATE_SH_SHA256=''
TEST_FRESH_VERIFIER_GATE_STATIC_PY_PATH=''
TEST_FRESH_VERIFIER_GATE_STATIC_PY_BLOB=''
TEST_FRESH_VERIFIER_GATE_STATIC_PY_SHA256=''
REALNIC_ACCEPTANCE_PY_PATH=''
REALNIC_ACCEPTANCE_PY_BLOB=''
REALNIC_ACCEPTANCE_PY_SHA256=''
TEST_REALNIC_ACCEPTANCE_PY_PATH=''
TEST_REALNIC_ACCEPTANCE_PY_BLOB=''
TEST_REALNIC_ACCEPTANCE_PY_SHA256=''
TEST_REALNIC_ACCEPTANCE_STATIC_PY_PATH=''
TEST_REALNIC_ACCEPTANCE_STATIC_PY_BLOB=''
TEST_REALNIC_ACCEPTANCE_STATIC_PY_SHA256=''
PREPARE_STAGE_ROOT_SH_PATH=''
PREPARE_STAGE_ROOT_SH_BLOB=''
PREPARE_STAGE_ROOT_SH_SHA256=''
PROVISION_UBUNTU_TEST_HOST_SH_PATH=''
PROVISION_UBUNTU_TEST_HOST_SH_BLOB=''
PROVISION_UBUNTU_TEST_HOST_SH_SHA256=''
ROOT_VETH_N_R_SH_PATH=''
ROOT_VETH_N_R_SH_BLOB=''
ROOT_VETH_N_R_SH_SHA256=''
TEST_HERMETIC_VETH_RUNNER_SH_PATH=''
TEST_HERMETIC_VETH_RUNNER_SH_BLOB=''
TEST_HERMETIC_VETH_RUNNER_SH_SHA256=''
TEST_VETH_RUNNER_STATIC_PY_PATH=''
TEST_VETH_RUNNER_STATIC_PY_BLOB=''
TEST_VETH_RUNNER_STATIC_PY_SHA256=''
CONTROLLER_SEAM_SH_PATH=''
CONTROLLER_SEAM_SH_BLOB=''
CONTROLLER_SEAM_SH_SHA256=''
ROOT_ROUTED_VETH_N_R_SH_PATH=''
ROOT_ROUTED_VETH_N_R_SH_BLOB=''
ROOT_ROUTED_VETH_N_R_SH_SHA256=''
TEST_HERMETIC_ROUTED_VETH_HARNESS_SH_PATH=''
TEST_HERMETIC_ROUTED_VETH_HARNESS_SH_BLOB=''
TEST_HERMETIC_ROUTED_VETH_HARNESS_SH_SHA256=''
TEST_ROUTED_VETH_HARNESS_STATIC_PY_PATH=''
TEST_ROUTED_VETH_HARNESS_STATIC_PY_BLOB=''
TEST_ROUTED_VETH_HARNESS_STATIC_PY_SHA256=''
fail() {
  printf 'B82_V6_CONTROLLER_STOP mode=%s reason=%s rc=%s; no automatic cleanup\n' \
    "${MODE:-unparsed}" "$1" "${2:-125}" >&2
  exit "${2:-125}"
}

usage() {
  printf '%s\n' \
    "usage: $0 {verify-package|verify-r2-predecessor-package|plan|preflight|prepare|provision-apply|fresh-plan|fresh-run|fresh-restore|veth-plan|veth-run|veth-restore|routed-plan|routed-run|routed-restore|realnic-plan|realnic-run|realnic-restore|retire-postflight-f75fe7678cfd-r2|verify-postflight-retirement-r2}" \
    '  --manifest ABSOLUTE_PACKAGE_MANIFEST --manifest-sha256 64-lowercase-hex' \
    "  --credential-path ${CREDENTIAL_PATH}" \
    '  --approved-plan-sha256 {none|64-lowercase-hex}' >&2
}

sha256_file() {
  local path="$1" line
  if [[ -x /usr/bin/shasum ]]; then
    line="$(/usr/bin/shasum -a 256 -- "${path}")" || return $?
  elif [[ -x /usr/bin/sha256sum ]]; then
    line="$(/usr/bin/sha256sum -- "${path}")" || return $?
  else
    return 69
  fi
  line="${line%% *}"
  [[ "${line}" =~ ^[0-9a-f]{64}$ ]] || return 65
  printf '%s\n' "${line}"
}

sha256_stream() {
  local line
  if [[ -x /usr/bin/shasum ]]; then
    line="$(/usr/bin/shasum -a 256)" || return $?
  elif [[ -x /usr/bin/sha256sum ]]; then
    line="$(/usr/bin/sha256sum)" || return $?
  else
    return 69
  fi
  line="${line%% *}"
  [[ "${line}" =~ ^[0-9a-f]{64}$ ]] || return 65
  printf '%s\n' "${line}"
}

path_device_inode() {
  if [[ "$(/usr/bin/uname -s)" == 'Darwin' ]]; then
    /usr/bin/stat -f '%d:%i' -- "$1"
  else
    /usr/bin/stat -Lc '%d:%i' -- "$1"
  fi
}

valid_sha256() {
  [[ "$1" =~ ^[0-9a-f]{64}$ && ! "$1" =~ ^0{64}$ && ! "$1" =~ ^f{64}$ ]]
}

valid_commit() {
  [[ "$1" =~ ^[0-9a-f]{40}$ && ! "$1" =~ ^0{40}$ && ! "$1" =~ ^f{40}$ ]]
}

valid_interface_name() {
  [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$ && "$1" != '.' && "$1" != '..' &&
    "$1" != 'ens33' && "$1" != 'wgc8e41a' && "$1" != 'wgc8e41b' ]]
}

valid_unicast_ipv4() {
  local value="$1" first second third fourth extra octet number
  IFS=. read -r first second third fourth extra <<<"${value}"
  [[ -z "${extra}" && -n "${first}" && -n "${second}" && -n "${third}" && -n "${fourth}" ]] || return 1
  [[ "${value}" == "${first}.${second}.${third}.${fourth}" ]] || return 1
  for octet in "${first}" "${second}" "${third}" "${fourth}"; do
    [[ "${octet}" =~ ^(0|[1-9][0-9]{0,2})$ ]] || return 1
    number=$((10#${octet}))
    ((number <= 255)) || return 1
  done
  number=$((10#${first}))
  ((number >= 1 && number <= 223 && number != 127)) || return 1
  [[ "${value}" != '255.255.255.255' ]]
}

parse_arguments() {
  local seen_manifest=0 seen_manifest_sha256=0 seen_credential_path=0
  local seen_approved_plan_sha256=0
  (($# >= 1)) || { usage; return 64; }
  MODE="$1"
  shift
  case "${MODE}" in
    verify-package | verify-r2-predecessor-package | plan | preflight | prepare | provision-apply | \
      fresh-plan | fresh-run | fresh-restore | \
      veth-plan | veth-run | veth-restore | routed-plan | routed-run | routed-restore | \
      realnic-plan | realnic-run | realnic-restore | \
      retire-postflight-f75fe7678cfd-r2 | verify-postflight-retirement-r2) ;;
    *) usage; return 64 ;;
  esac
  while (($# > 0)); do
    (($# >= 2)) || { usage; return 64; }
    case "$1" in
      --manifest)
        ((seen_manifest == 0)) || return 65
        seen_manifest=1
        MANIFEST="$2"
        ;;
      --manifest-sha256)
        ((seen_manifest_sha256 == 0)) || return 65
        seen_manifest_sha256=1
        MANIFEST_SHA256="$2"
        ;;
      --credential-path)
        ((seen_credential_path == 0)) || return 65
        seen_credential_path=1
        SUPPLIED_CREDENTIAL_PATH="$2"
        ;;
      --approved-plan-sha256)
        ((seen_approved_plan_sha256 == 0)) || return 65
        seen_approved_plan_sha256=1
        APPROVED_PLAN_SHA256="$2"
        ;;
      *) usage; return 64 ;;
    esac
    shift 2
  done
  [[ "${MANIFEST}" == /* && "${SUPPLIED_CREDENTIAL_PATH}" == "${CREDENTIAL_PATH}" ]] || return 65
  valid_sha256 "${MANIFEST_SHA256}" || return 65
  case "${MODE}" in
    realnic-run | realnic-restore)
      valid_sha256 "${APPROVED_PLAN_SHA256}" || return 65
      ;;
    plan)
      [[ "${APPROVED_PLAN_SHA256}" == 'none' ]] || valid_sha256 "${APPROVED_PLAN_SHA256}" || return 65
      ;;
    *) [[ "${APPROVED_PLAN_SHA256}" == 'none' ]] || return 65 ;;
  esac
}

read_manifest_field() {
  local expected="$1" destination="$2" key value extra
  IFS=$'\t' read -r key value extra <&3 || return 65
  [[ "${key}" == "${expected}" && -n "${value}" && -z "${extra}" &&
    "${value}" != *$'\t'* && "${value}" != *$'\n'* ]] || return 65
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
    read_manifest_field history_verification HISTORY_VERIFICATION &&
    read_manifest_field history_commit_count HISTORY_COMMIT_COUNT &&
    read_manifest_field history_roots_sha256 HISTORY_ROOTS_SHA256 &&
    read_manifest_field history_objects_sha256 HISTORY_OBJECTS_SHA256 &&
    read_manifest_field wg_state WG_STATE &&
    read_manifest_field wg_interface WG_INTERFACE &&
    read_manifest_field wg_local_address WG_LOCAL_ADDRESS &&
    read_manifest_field wg_peer_address WG_PEER_ADDRESS &&
    read_manifest_field local_repository LOCAL_REPOSITORY &&
    read_manifest_field local_package_dir LOCAL_PACKAGE_DIR &&
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
    read_manifest_field physical_interface_lock PHYSICAL_INTERFACE_LOCK &&
    read_manifest_field legacy_matrix_mode LEGACY_MATRIX_MODE &&
    read_manifest_field realnic_profile REALNIC_PROFILE &&
    read_manifest_field realnic_traffic_seconds REALNIC_TRAFFIC_SECONDS &&
    read_manifest_field bind_final_package_sh_path BIND_FINAL_PACKAGE_SH_PATH &&
    read_manifest_field bind_final_package_sh_blob BIND_FINAL_PACKAGE_SH_BLOB &&
    read_manifest_field bind_final_package_sh_sha256 BIND_FINAL_PACKAGE_SH_SHA256 &&
    read_manifest_field controller_sh_path CONTROLLER_SH_PATH &&
    read_manifest_field controller_sh_blob CONTROLLER_SH_BLOB &&
    read_manifest_field controller_sh_sha256 CONTROLLER_SH_SHA256 &&
    read_manifest_field locked_transport_exp_path LOCKED_TRANSPORT_EXP_PATH &&
    read_manifest_field locked_transport_exp_blob LOCKED_TRANSPORT_EXP_BLOB &&
    read_manifest_field locked_transport_exp_sha256 LOCKED_TRANSPORT_EXP_SHA256 &&
    read_manifest_field root_matrix_n_r_sh_path ROOT_MATRIX_N_R_SH_PATH &&
    read_manifest_field root_matrix_n_r_sh_blob ROOT_MATRIX_N_R_SH_BLOB &&
    read_manifest_field root_matrix_n_r_sh_sha256 ROOT_MATRIX_N_R_SH_SHA256 &&
    read_manifest_field check_realhost_iperf_py_path CHECK_REALHOST_IPERF_PY_PATH &&
    read_manifest_field check_realhost_iperf_py_blob CHECK_REALHOST_IPERF_PY_BLOB &&
    read_manifest_field check_realhost_iperf_py_sha256 CHECK_REALHOST_IPERF_PY_SHA256 &&
    read_manifest_field test_hermetic_matrix_sh_path TEST_HERMETIC_MATRIX_SH_PATH &&
    read_manifest_field test_hermetic_matrix_sh_blob TEST_HERMETIC_MATRIX_SH_BLOB &&
    read_manifest_field test_hermetic_matrix_sh_sha256 TEST_HERMETIC_MATRIX_SH_SHA256 &&
    read_manifest_field test_matrix_static_py_path TEST_MATRIX_STATIC_PY_PATH &&
    read_manifest_field test_matrix_static_py_blob TEST_MATRIX_STATIC_PY_BLOB &&
    read_manifest_field test_matrix_static_py_sha256 TEST_MATRIX_STATIC_PY_SHA256 &&
    read_manifest_field checksum_module_lease_sh_path CHECKSUM_MODULE_LEASE_SH_PATH &&
    read_manifest_field checksum_module_lease_sh_blob CHECKSUM_MODULE_LEASE_SH_BLOB &&
    read_manifest_field checksum_module_lease_sh_sha256 CHECKSUM_MODULE_LEASE_SH_SHA256 &&
    read_manifest_field test_hermetic_checksum_module_lease_sh_path TEST_HERMETIC_CHECKSUM_MODULE_LEASE_SH_PATH &&
    read_manifest_field test_hermetic_checksum_module_lease_sh_blob TEST_HERMETIC_CHECKSUM_MODULE_LEASE_SH_BLOB &&
    read_manifest_field test_hermetic_checksum_module_lease_sh_sha256 TEST_HERMETIC_CHECKSUM_MODULE_LEASE_SH_SHA256 &&
    read_manifest_field test_checksum_module_lease_static_py_path TEST_CHECKSUM_MODULE_LEASE_STATIC_PY_PATH &&
    read_manifest_field test_checksum_module_lease_static_py_blob TEST_CHECKSUM_MODULE_LEASE_STATIC_PY_BLOB &&
    read_manifest_field test_checksum_module_lease_static_py_sha256 TEST_CHECKSUM_MODULE_LEASE_STATIC_PY_SHA256 &&
    read_manifest_field wg_mix_faketcp_checksum_c_path WG_MIX_FAKETCP_CHECKSUM_C_PATH &&
    read_manifest_field wg_mix_faketcp_checksum_c_blob WG_MIX_FAKETCP_CHECKSUM_C_BLOB &&
    read_manifest_field wg_mix_faketcp_checksum_c_sha256 WG_MIX_FAKETCP_CHECKSUM_C_SHA256 &&
    read_manifest_field root_fresh_verifier_gate_sh_path ROOT_FRESH_VERIFIER_GATE_SH_PATH &&
    read_manifest_field root_fresh_verifier_gate_sh_blob ROOT_FRESH_VERIFIER_GATE_SH_BLOB &&
    read_manifest_field root_fresh_verifier_gate_sh_sha256 ROOT_FRESH_VERIFIER_GATE_SH_SHA256 &&
    read_manifest_field test_hermetic_fresh_verifier_gate_sh_path TEST_HERMETIC_FRESH_VERIFIER_GATE_SH_PATH &&
    read_manifest_field test_hermetic_fresh_verifier_gate_sh_blob TEST_HERMETIC_FRESH_VERIFIER_GATE_SH_BLOB &&
    read_manifest_field test_hermetic_fresh_verifier_gate_sh_sha256 TEST_HERMETIC_FRESH_VERIFIER_GATE_SH_SHA256 &&
    read_manifest_field test_fresh_verifier_gate_static_py_path TEST_FRESH_VERIFIER_GATE_STATIC_PY_PATH &&
    read_manifest_field test_fresh_verifier_gate_static_py_blob TEST_FRESH_VERIFIER_GATE_STATIC_PY_BLOB &&
    read_manifest_field test_fresh_verifier_gate_static_py_sha256 TEST_FRESH_VERIFIER_GATE_STATIC_PY_SHA256 &&
    read_manifest_field prepare_stage_root_sh_path PREPARE_STAGE_ROOT_SH_PATH &&
    read_manifest_field prepare_stage_root_sh_blob PREPARE_STAGE_ROOT_SH_BLOB &&
    read_manifest_field prepare_stage_root_sh_sha256 PREPARE_STAGE_ROOT_SH_SHA256 &&
    read_manifest_field realnic_acceptance_py_path REALNIC_ACCEPTANCE_PY_PATH &&
    read_manifest_field realnic_acceptance_py_blob REALNIC_ACCEPTANCE_PY_BLOB &&
    read_manifest_field realnic_acceptance_py_sha256 REALNIC_ACCEPTANCE_PY_SHA256 &&
    read_manifest_field test_realnic_acceptance_py_path TEST_REALNIC_ACCEPTANCE_PY_PATH &&
    read_manifest_field test_realnic_acceptance_py_blob TEST_REALNIC_ACCEPTANCE_PY_BLOB &&
    read_manifest_field test_realnic_acceptance_py_sha256 TEST_REALNIC_ACCEPTANCE_PY_SHA256 &&
    read_manifest_field test_realnic_acceptance_static_py_path TEST_REALNIC_ACCEPTANCE_STATIC_PY_PATH &&
    read_manifest_field test_realnic_acceptance_static_py_blob TEST_REALNIC_ACCEPTANCE_STATIC_PY_BLOB &&
    read_manifest_field test_realnic_acceptance_static_py_sha256 TEST_REALNIC_ACCEPTANCE_STATIC_PY_SHA256 &&
    read_manifest_field provision_ubuntu_test_host_sh_path PROVISION_UBUNTU_TEST_HOST_SH_PATH &&
    read_manifest_field provision_ubuntu_test_host_sh_blob PROVISION_UBUNTU_TEST_HOST_SH_BLOB &&
    read_manifest_field provision_ubuntu_test_host_sh_sha256 PROVISION_UBUNTU_TEST_HOST_SH_SHA256 &&
    read_manifest_field root_veth_n_r_sh_path ROOT_VETH_N_R_SH_PATH &&
    read_manifest_field root_veth_n_r_sh_blob ROOT_VETH_N_R_SH_BLOB &&
    read_manifest_field root_veth_n_r_sh_sha256 ROOT_VETH_N_R_SH_SHA256 &&
    read_manifest_field test_hermetic_veth_runner_sh_path TEST_HERMETIC_VETH_RUNNER_SH_PATH &&
    read_manifest_field test_hermetic_veth_runner_sh_blob TEST_HERMETIC_VETH_RUNNER_SH_BLOB &&
    read_manifest_field test_hermetic_veth_runner_sh_sha256 TEST_HERMETIC_VETH_RUNNER_SH_SHA256 &&
    read_manifest_field test_veth_runner_static_py_path TEST_VETH_RUNNER_STATIC_PY_PATH &&
    read_manifest_field test_veth_runner_static_py_blob TEST_VETH_RUNNER_STATIC_PY_BLOB &&
    read_manifest_field test_veth_runner_static_py_sha256 TEST_VETH_RUNNER_STATIC_PY_SHA256 &&
    read_manifest_field controller_seam_sh_path CONTROLLER_SEAM_SH_PATH &&
    read_manifest_field controller_seam_sh_blob CONTROLLER_SEAM_SH_BLOB &&
    read_manifest_field controller_seam_sh_sha256 CONTROLLER_SEAM_SH_SHA256 &&
    read_manifest_field root_routed_veth_n_r_sh_path ROOT_ROUTED_VETH_N_R_SH_PATH &&
    read_manifest_field root_routed_veth_n_r_sh_blob ROOT_ROUTED_VETH_N_R_SH_BLOB &&
    read_manifest_field root_routed_veth_n_r_sh_sha256 ROOT_ROUTED_VETH_N_R_SH_SHA256 &&
    read_manifest_field test_hermetic_routed_veth_harness_sh_path TEST_HERMETIC_ROUTED_VETH_HARNESS_SH_PATH &&
    read_manifest_field test_hermetic_routed_veth_harness_sh_blob TEST_HERMETIC_ROUTED_VETH_HARNESS_SH_BLOB &&
    read_manifest_field test_hermetic_routed_veth_harness_sh_sha256 TEST_HERMETIC_ROUTED_VETH_HARNESS_SH_SHA256 &&
    read_manifest_field test_routed_veth_harness_static_py_path TEST_ROUTED_VETH_HARNESS_STATIC_PY_PATH &&
    read_manifest_field test_routed_veth_harness_static_py_blob TEST_ROUTED_VETH_HARNESS_STATIC_PY_BLOB &&
    read_manifest_field test_routed_veth_harness_static_py_sha256 TEST_ROUTED_VETH_HARNESS_STATIC_PY_SHA256
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

git_checked() {
  /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C \
    GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 \
    GIT_NO_REPLACE_OBJECTS=1 GIT_OPTIONAL_LOCKS=0 \
    /usr/bin/git --no-pager --no-replace-objects \
    -c core.attributesFile=/dev/null -c core.fsmonitor=false \
    -c core.hooksPath=/dev/null -C "${LOCAL_REPOSITORY}" "$@"
}

git_history() {
  local history_repository="$1"
  shift
  /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C \
    GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 \
    GIT_NO_REPLACE_OBJECTS=1 GIT_OPTIONAL_LOCKS=0 \
    /usr/bin/git --no-pager --no-replace-objects \
    -c core.attributesFile=/dev/null -c core.fsmonitor=false \
    -c core.hooksPath=/dev/null -C "${history_repository}" "$@"
}

verify_bound_history() {
  local history_repository="${LOCAL_PACKAGE_DIR}/history-verification.git"
  local history_objects="${LOCAL_PACKAGE_DIR}/history-objects.v1"
  local history_roots="${LOCAL_PACKAGE_DIR}/history-roots.v1"
  local isolated_count missing_rc actual_roots actual_objects_sha
  [[ -d "${history_repository}" && ! -L "${history_repository}" &&
    -f "${history_objects}" && ! -L "${history_objects}" &&
    -f "${history_roots}" && ! -L "${history_roots}" ]] || return 66
  [[ "$(sha256_file "${history_objects}")" == "${HISTORY_OBJECTS_SHA256}" &&
    "$(sha256_file "${history_roots}")" == "${HISTORY_ROOTS_SHA256}" ]] || return 67
  /usr/bin/grep -E '^\?' -- "${history_objects}"
  missing_rc=$?
  case "${missing_rc}" in
    1) ;;
    0) return 76 ;;
    *) return 67 ;;
  esac
  git_history "${history_repository}" cat-file -e "${INTEGRATION_COMMIT}^{commit}" || return 76
  git_history "${history_repository}" fsck --full --strict --no-dangling "${INTEGRATION_COMMIT}" || return 76
  isolated_count="$(git_history "${history_repository}" rev-list --count "${INTEGRATION_COMMIT}")" || return 76
  [[ "${isolated_count}" == "${HISTORY_COMMIT_COUNT}" ]] || return 76
  actual_roots="$(git_history "${history_repository}" rev-list --max-parents=0 --reverse \
    "${INTEGRATION_COMMIT}")" || return 76
  [[ "$(<"${history_roots}")" == "${actual_roots}" && -n "${actual_roots}" ]] || return 76
  actual_objects_sha="$(git_history "${history_repository}" rev-list --parents --objects \
    --missing=print "${INTEGRATION_COMMIT}" | sha256_stream)" || return 76
  [[ "${actual_objects_sha}" == "${HISTORY_OBJECTS_SHA256}" ]] || return 76
}

verify_identity() {
  local path="$1" blob="$2" sha="$3" actual_blob actual_sha mapped_blob
  [[ ("${path}" =~ ^scripts/realhost-b82-(c8e41d73|acceptance-v1|routed-veth-v1)/[A-Za-z0-9_.-]+$ ||
      "${path}" == 'scripts/provision-ubuntu-test-host.sh' ||
      "${path}" == 'kernel/faketcp_checksum/wg_mix_faketcp_checksum.c') &&
    "${blob}" =~ ^[0-9a-f]{40}$ ]] || return 65
  valid_sha256 "${sha}" || return 65
  [[ -f "${LOCAL_REPOSITORY}/${path}" && ! -L "${LOCAL_REPOSITORY}/${path}" ]] || return 66
  actual_blob="$(git_checked hash-object -- "${LOCAL_REPOSITORY}/${path}")" || return 66
  actual_sha="$(sha256_file "${LOCAL_REPOSITORY}/${path}")" || return 66
  mapped_blob="$(git_checked rev-parse "${INTEGRATION_COMMIT}:${path}")" || return 66
  [[ "${actual_blob}" == "${blob}" && "${actual_sha}" == "${sha}" && "${mapped_blob}" == "${blob}" ]]
}

verify_manifest_contract() {
  local canonical_repository canonical_package canonical_manifest actual_commit bundle_head name sha shallow_state
  [[ -f "${MANIFEST}" && ! -L "${MANIFEST}" ]] || return 66
  [[ "$(sha256_file "${MANIFEST}")" == "${MANIFEST_SHA256}" ]] || return 67
  load_manifest || return $?
  [[ "${FORMAT}" == 'wg-mix-ebpf-b82-v6-package-v5' &&
    "${MANIFEST_RUN_ID}" == "${RUN_ID}" && "${MANIFEST_PACKAGE_ID}" == "${PACKAGE_ID}" &&
    "${INTEGRATION_REF}" =~ ^refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]{0,180}$ &&
    "${INTEGRATION_REF}" != *'..'* && "${INTEGRATION_REF}" != *'//'* &&
    "${BUNDLE_NAME}" == "source-${PACKAGE_ID}.bundle" &&
    "${HISTORY_VERIFICATION}" == 'isolated-unbundle-rev-list-fsck-v1' &&
    "${HISTORY_COMMIT_COUNT}" =~ ^[1-9][0-9]*$ &&
    "${REMOTE_PACKAGE_DIR}" == "/home/siyixuan/wg-mix-ebpf-test/unpriv-${PACKAGE_ID}" &&
    "${REMOTE_SOURCE}" == "/run/wg-mix-ebpf-source-stages/${RUN_ID}/source" &&
    "${TARGET_USER}" == 'siyixuan' && "${TARGET_HOST}" == '192.168.10.82' &&
    "${TARGET_HOSTNAME}" == 'ubuntu-2604-test' && "${TARGET_KERNEL}" == '7.0.0-28-generic' &&
    "${TARGET_MACHINE_ID}" == '9db3fb717cc74974b2a6b243d67f67b9' &&
    "${TARGET_INTERFACE}" == 'ens33' && "${PEER_ADDRESS}" == '47.116.202.155' &&
    "${PEER_PORT}" == '5201' && "${SOAK_SECONDS}" == '3600' &&
    "${SESSION_SECONDS}" == '300' &&
    "${PHYSICAL_NIC_FORWARD_AUTHORITY}" == 'realnic-acceptance-v1' &&
    "${PHYSICAL_INTERFACE_LOCK}" == '/run/wg-mix-ebpf-realnic-physical-interface.v1.lock' &&
    "${LEGACY_MATRIX_MODE}" == 'retired' &&
    "${REALNIC_PROFILE}" == 'acceptance' && "${REALNIC_TRAFFIC_SECONDS}" == '30' &&
    "${TEST_HERMETIC_CHECKSUM_MODULE_LEASE_SH_PATH}" == "scripts/realhost-b82-${RUN_ID}/test-hermetic-checksum-module-lease.sh" &&
    "${TEST_CHECKSUM_MODULE_LEASE_STATIC_PY_PATH}" == "scripts/realhost-b82-${RUN_ID}/test_checksum_module_lease_static.py" &&
    "${WG_MIX_FAKETCP_CHECKSUM_C_PATH}" == 'kernel/faketcp_checksum/wg_mix_faketcp_checksum.c' &&
    "${ROOT_VETH_N_R_SH_PATH}" == "scripts/realhost-b82-${RUN_ID}/root-veth-n-r.sh" &&
    "${TEST_HERMETIC_VETH_RUNNER_SH_PATH}" == "scripts/realhost-b82-${RUN_ID}/test-hermetic-veth-runner.sh" &&
    "${TEST_VETH_RUNNER_STATIC_PY_PATH}" == "scripts/realhost-b82-${RUN_ID}/test_veth_runner_static.py" &&
    "${CONTROLLER_SEAM_SH_PATH}" == 'scripts/realhost-b82-routed-veth-v1/controller-seam.sh' &&
    "${ROOT_ROUTED_VETH_N_R_SH_PATH}" == 'scripts/realhost-b82-routed-veth-v1/root-routed-veth-n-r.sh' &&
    "${TEST_HERMETIC_ROUTED_VETH_HARNESS_SH_PATH}" == 'scripts/realhost-b82-routed-veth-v1/test-hermetic-routed-veth-harness.sh' &&
    "${TEST_ROUTED_VETH_HARNESS_STATIC_PY_PATH}" == 'scripts/realhost-b82-routed-veth-v1/test_routed_veth_harness_static.py' ]] || return 65
  valid_commit "${INTEGRATION_COMMIT}" || return 65
  case "${WG_STATE}" in
    bound)
      valid_interface_name "${WG_INTERFACE}" && valid_unicast_ipv4 "${WG_LOCAL_ADDRESS}" &&
        valid_unicast_ipv4 "${WG_PEER_ADDRESS}" &&
        [[ "${WG_LOCAL_ADDRESS}" != "${WG_PEER_ADDRESS}" ]] || return 65
      ;;
    absent)
      [[ "${WG_INTERFACE}" == 'absent' && "${WG_LOCAL_ADDRESS}" == 'absent' &&
        "${WG_PEER_ADDRESS}" == 'absent' ]] || return 65
      ;;
    *) return 65 ;;
  esac
  valid_sha256 "${BUNDLE_SHA256}" || return 65
  valid_sha256 "${HISTORY_ROOTS_SHA256}" && valid_sha256 "${HISTORY_OBJECTS_SHA256}" || return 65
  canonical_repository="$(CDPATH='' cd -- "${LOCAL_REPOSITORY}" && pwd -P)" || return 66
  canonical_package="$(CDPATH='' cd -- "${LOCAL_PACKAGE_DIR}" && pwd -P)" || return 66
  canonical_manifest="${canonical_package}/package-manifest.v1"
  [[ "${canonical_repository}" == "${LOCAL_REPOSITORY}" &&
    "${canonical_package}" == "${LOCAL_PACKAGE_DIR}" &&
    "${MANIFEST}" == "${canonical_manifest}" &&
    "${LOCAL_PACKAGE_DIR}" == "${EXPECTED_OUTPUT_PREFIX}${INTEGRATION_COMMIT:0:12}" ]] || return 65
  actual_commit="$(git_checked rev-parse --verify "${INTEGRATION_REF}^{commit}")" || return 67
  [[ "${actual_commit}" == "${INTEGRATION_COMMIT}" ]] || return 67
  shallow_state="$(git_checked rev-parse --is-shallow-repository)" || return 67
  [[ "${shallow_state}" == 'false' ]] || return 76

  verify_identity "${BIND_FINAL_PACKAGE_SH_PATH}" "${BIND_FINAL_PACKAGE_SH_BLOB}" "${BIND_FINAL_PACKAGE_SH_SHA256}" &&
    verify_identity "${CONTROLLER_SH_PATH}" "${CONTROLLER_SH_BLOB}" "${CONTROLLER_SH_SHA256}" &&
    verify_identity "${LOCKED_TRANSPORT_EXP_PATH}" "${LOCKED_TRANSPORT_EXP_BLOB}" "${LOCKED_TRANSPORT_EXP_SHA256}" &&
    verify_identity "${ROOT_MATRIX_N_R_SH_PATH}" "${ROOT_MATRIX_N_R_SH_BLOB}" "${ROOT_MATRIX_N_R_SH_SHA256}" &&
    verify_identity "${CHECK_REALHOST_IPERF_PY_PATH}" "${CHECK_REALHOST_IPERF_PY_BLOB}" "${CHECK_REALHOST_IPERF_PY_SHA256}" &&
    verify_identity "${TEST_HERMETIC_MATRIX_SH_PATH}" "${TEST_HERMETIC_MATRIX_SH_BLOB}" "${TEST_HERMETIC_MATRIX_SH_SHA256}" &&
    verify_identity "${TEST_MATRIX_STATIC_PY_PATH}" "${TEST_MATRIX_STATIC_PY_BLOB}" "${TEST_MATRIX_STATIC_PY_SHA256}" &&
    verify_identity "${CHECKSUM_MODULE_LEASE_SH_PATH}" "${CHECKSUM_MODULE_LEASE_SH_BLOB}" "${CHECKSUM_MODULE_LEASE_SH_SHA256}" &&
    verify_identity "${TEST_HERMETIC_CHECKSUM_MODULE_LEASE_SH_PATH}" "${TEST_HERMETIC_CHECKSUM_MODULE_LEASE_SH_BLOB}" "${TEST_HERMETIC_CHECKSUM_MODULE_LEASE_SH_SHA256}" &&
    verify_identity "${TEST_CHECKSUM_MODULE_LEASE_STATIC_PY_PATH}" "${TEST_CHECKSUM_MODULE_LEASE_STATIC_PY_BLOB}" "${TEST_CHECKSUM_MODULE_LEASE_STATIC_PY_SHA256}" &&
    verify_identity "${WG_MIX_FAKETCP_CHECKSUM_C_PATH}" "${WG_MIX_FAKETCP_CHECKSUM_C_BLOB}" "${WG_MIX_FAKETCP_CHECKSUM_C_SHA256}" &&
    verify_identity "${ROOT_FRESH_VERIFIER_GATE_SH_PATH}" "${ROOT_FRESH_VERIFIER_GATE_SH_BLOB}" "${ROOT_FRESH_VERIFIER_GATE_SH_SHA256}" &&
    verify_identity "${TEST_HERMETIC_FRESH_VERIFIER_GATE_SH_PATH}" "${TEST_HERMETIC_FRESH_VERIFIER_GATE_SH_BLOB}" "${TEST_HERMETIC_FRESH_VERIFIER_GATE_SH_SHA256}" &&
    verify_identity "${TEST_FRESH_VERIFIER_GATE_STATIC_PY_PATH}" "${TEST_FRESH_VERIFIER_GATE_STATIC_PY_BLOB}" "${TEST_FRESH_VERIFIER_GATE_STATIC_PY_SHA256}" &&
    verify_identity "${PREPARE_STAGE_ROOT_SH_PATH}" "${PREPARE_STAGE_ROOT_SH_BLOB}" "${PREPARE_STAGE_ROOT_SH_SHA256}" &&
    verify_identity "${REALNIC_ACCEPTANCE_PY_PATH}" "${REALNIC_ACCEPTANCE_PY_BLOB}" "${REALNIC_ACCEPTANCE_PY_SHA256}" &&
    verify_identity "${TEST_REALNIC_ACCEPTANCE_PY_PATH}" "${TEST_REALNIC_ACCEPTANCE_PY_BLOB}" "${TEST_REALNIC_ACCEPTANCE_PY_SHA256}" &&
    verify_identity "${TEST_REALNIC_ACCEPTANCE_STATIC_PY_PATH}" "${TEST_REALNIC_ACCEPTANCE_STATIC_PY_BLOB}" "${TEST_REALNIC_ACCEPTANCE_STATIC_PY_SHA256}" &&
    verify_identity "${PROVISION_UBUNTU_TEST_HOST_SH_PATH}" "${PROVISION_UBUNTU_TEST_HOST_SH_BLOB}" \
      "${PROVISION_UBUNTU_TEST_HOST_SH_SHA256}" &&
    verify_identity "${ROOT_VETH_N_R_SH_PATH}" "${ROOT_VETH_N_R_SH_BLOB}" "${ROOT_VETH_N_R_SH_SHA256}" &&
    verify_identity "${TEST_HERMETIC_VETH_RUNNER_SH_PATH}" "${TEST_HERMETIC_VETH_RUNNER_SH_BLOB}" "${TEST_HERMETIC_VETH_RUNNER_SH_SHA256}" &&
    verify_identity "${TEST_VETH_RUNNER_STATIC_PY_PATH}" "${TEST_VETH_RUNNER_STATIC_PY_BLOB}" "${TEST_VETH_RUNNER_STATIC_PY_SHA256}" &&
    verify_identity "${CONTROLLER_SEAM_SH_PATH}" "${CONTROLLER_SEAM_SH_BLOB}" "${CONTROLLER_SEAM_SH_SHA256}" &&
    verify_identity "${ROOT_ROUTED_VETH_N_R_SH_PATH}" "${ROOT_ROUTED_VETH_N_R_SH_BLOB}" "${ROOT_ROUTED_VETH_N_R_SH_SHA256}" &&
    verify_identity "${TEST_HERMETIC_ROUTED_VETH_HARNESS_SH_PATH}" "${TEST_HERMETIC_ROUTED_VETH_HARNESS_SH_BLOB}" "${TEST_HERMETIC_ROUTED_VETH_HARNESS_SH_SHA256}" &&
    verify_identity "${TEST_ROUTED_VETH_HARNESS_STATIC_PY_PATH}" "${TEST_ROUTED_VETH_HARNESS_STATIC_PY_BLOB}" "${TEST_ROUTED_VETH_HARNESS_STATIC_PY_SHA256}" || return $?

  for name in bind-final-package.sh controller.sh root-matrix-n-r.sh check-realhost-iperf.py \
    test-hermetic-matrix.sh test_matrix_static.py checksum-module-lease.sh \
    test-hermetic-checksum-module-lease.sh test_checksum_module_lease_static.py \
    wg_mix_faketcp_checksum.c \
    root-fresh-verifier-gate.sh test-hermetic-fresh-verifier-gate.sh \
    test_fresh_verifier_gate_static.py prepare-stage-root.sh \
    realnic_acceptance.py test_realnic_acceptance.py test_realnic_acceptance_static.py \
    provision-ubuntu-test-host.sh; do
    [[ -f "${LOCAL_PACKAGE_DIR}/${name}" && ! -L "${LOCAL_PACKAGE_DIR}/${name}" ]] || return 66
    case "${name}" in
      bind-final-package.sh) sha="${BIND_FINAL_PACKAGE_SH_SHA256}" ;;
      controller.sh) sha="${CONTROLLER_SH_SHA256}" ;;
      root-matrix-n-r.sh) sha="${ROOT_MATRIX_N_R_SH_SHA256}" ;;
      check-realhost-iperf.py) sha="${CHECK_REALHOST_IPERF_PY_SHA256}" ;;
      test-hermetic-matrix.sh) sha="${TEST_HERMETIC_MATRIX_SH_SHA256}" ;;
      test_matrix_static.py) sha="${TEST_MATRIX_STATIC_PY_SHA256}" ;;
      checksum-module-lease.sh) sha="${CHECKSUM_MODULE_LEASE_SH_SHA256}" ;;
      test-hermetic-checksum-module-lease.sh) sha="${TEST_HERMETIC_CHECKSUM_MODULE_LEASE_SH_SHA256}" ;;
      test_checksum_module_lease_static.py) sha="${TEST_CHECKSUM_MODULE_LEASE_STATIC_PY_SHA256}" ;;
      wg_mix_faketcp_checksum.c) sha="${WG_MIX_FAKETCP_CHECKSUM_C_SHA256}" ;;
      root-fresh-verifier-gate.sh) sha="${ROOT_FRESH_VERIFIER_GATE_SH_SHA256}" ;;
      test-hermetic-fresh-verifier-gate.sh) sha="${TEST_HERMETIC_FRESH_VERIFIER_GATE_SH_SHA256}" ;;
      test_fresh_verifier_gate_static.py) sha="${TEST_FRESH_VERIFIER_GATE_STATIC_PY_SHA256}" ;;
      prepare-stage-root.sh) sha="${PREPARE_STAGE_ROOT_SH_SHA256}" ;;
      realnic_acceptance.py) sha="${REALNIC_ACCEPTANCE_PY_SHA256}" ;;
      test_realnic_acceptance.py) sha="${TEST_REALNIC_ACCEPTANCE_PY_SHA256}" ;;
      test_realnic_acceptance_static.py) sha="${TEST_REALNIC_ACCEPTANCE_STATIC_PY_SHA256}" ;;
      provision-ubuntu-test-host.sh) sha="${PROVISION_UBUNTU_TEST_HOST_SH_SHA256}" ;;
    esac
    [[ "$(sha256_file "${LOCAL_PACKAGE_DIR}/${name}")" == "${sha}" ]] || return 67
  done
  [[ -f "${LOCAL_PACKAGE_DIR}/${BUNDLE_NAME}" && ! -L "${LOCAL_PACKAGE_DIR}/${BUNDLE_NAME}" &&
    "$(sha256_file "${LOCAL_PACKAGE_DIR}/${BUNDLE_NAME}")" == "${BUNDLE_SHA256}" ]] || return 67
  git_checked bundle verify "${LOCAL_PACKAGE_DIR}/${BUNDLE_NAME}" || return 67
  bundle_head="$(git_checked bundle list-heads "${LOCAL_PACKAGE_DIR}/${BUNDLE_NAME}" "${INTEGRATION_REF}")" || return 67
  [[ "${bundle_head}" == "${INTEGRATION_COMMIT} ${INTEGRATION_REF}" ]] || return 67
  verify_bound_history || return $?
}

verify_r2_predecessor_manifest_contract() {
  /usr/bin/python3 -B -I -c '
import hashlib
import os
import stat
import subprocess
import sys

(
    manifest_name,
    package_name,
    manifest_sha,
    bundle_sha,
    roots_sha,
    objects_sha,
    integration_commit,
    integration_ref,
) = sys.argv[1:]
expected_manifest = sys.stdin.buffer.read()
if (manifest_name != os.path.join(package_name, "package-manifest.v1") or
        package_name !=
        "/private/tmp/wg-mix-b82-v6-c8e41d73-4f2a9b61-f75fe7678cfd" or
        integration_commit != "f75fe7678cfdecf08173fd201be5c055417d6e11" or
        integration_ref != "refs/heads/codex/tcx-faketcp-final-v2"):
    raise SystemExit(66)
if (not expected_manifest.endswith(b"\n") or expected_manifest.endswith(b"\n\n") or
        b"\0" in expected_manifest or b"\r" in expected_manifest):
    raise SystemExit(70)
expected_lines = expected_manifest[:-1].split(b"\n")
expected_pairs = [line.split(b"\t") for line in expected_lines]
if (len(expected_lines) != 103 or any(len(pair) != 2 or not pair[0] or not pair[1]
                                      for pair in expected_pairs) or
        len({pair[0] for pair in expected_pairs}) != 103):
    raise SystemExit(70)
expected_values = dict(expected_pairs)
if (expected_values.get(b"local_package_dir") != package_name.encode("utf-8") or
        expected_values.get(b"integration_commit") != integration_commit.encode("ascii") or
        expected_values.get(b"integration_ref") != integration_ref.encode("ascii")):
    raise SystemExit(70)

expected_files = {
    "source-4f2a9b61.bundle": (bundle_sha, 2469874),
    "package-manifest.v1": (manifest_sha, 7315),
    "bind-final-package.sh": (
        "a808a7879ef64190eff9e81e6b694acea7bc04b1b74ffad44109b237a5eb14ca", 17015),
    "controller.sh": (
        "fb8a7a685b5a6b73de851ee9a3396f4154cc4ae083a7c36f3b3128b2b9a2e77d", 43303),
    "prepare-stage-root.sh": (
        "1bcb8db91d976d2a1d95f7d87223a2dac4a1678f74c1c25542e54b01ee10eeea", 54230),
    "provision-ubuntu-test-host.sh": (
        "078d191b0edbafe27e9f684d3fa495e04d7217a01d0ec1fd32eaede211178c8f", 19437),
    "root-matrix-n-r.sh": (
        "9ec125c2933866431779b760d41c6484cc0fbb9e5e9f3b5431c4a56fbab63e07", 1101),
    "check-realhost-iperf.py": (
        "9a52378b8a1ef6043d4d5792471c8239a0392a80da72f5c00846dd89e88ccd67", 21027),
    "test-hermetic-matrix.sh": (
        "9b81949416a1b4df91fee0e7d31a3de2c6ba9b474dc9c0f4dbbb1cc609207499", 6694),
    "test_matrix_static.py": (
        "8de2dcdc866938da0502f1ad73ac9b38c9b6ff4066c76e9cbc946c9ca30a53f8", 5656),
    "checksum-module-lease.sh": (
        "4ab9a22910e8d597cc04bb4fdde9e1b32d37a1bb2c6ad7b76f52d576b5a9adb2", 23755),
    "root-fresh-verifier-gate.sh": (
        "4c2cf85b7e571df9b7ed4a77fa720c9f5e35950d44af5a39499a7ad700fe6a27", 65201),
    "test-hermetic-fresh-verifier-gate.sh": (
        "c9b5b1f954c794c5c986214777727a76579f670db9587f319ac148fc0c2a05f3", 14628),
    "test_fresh_verifier_gate_static.py": (
        "ace6951027788e82ad879caf285316af4e6ee81fdb6746f569cd7c22b9f80bf3", 17307),
    "realnic_acceptance.py": (
        "a88100b2a23ad41dd3e644c3ba1c7a722d58c8184a997aabf0ceab78552c6339", 216405),
    "test_realnic_acceptance.py": (
        "fcb3d0dadee6da6e0ad67d028f268ebe43575287f555cd8100d279f8a3b0b79c", 148160),
    "test_realnic_acceptance_static.py": (
        "ba8aef3219a0cf2a5c6b5058b245f64eb828a08bb532d2aa0291f51ee7206ad2", 14894),
}
history_files = {
    "history-roots.v1": (roots_sha, 41),
    "history-objects.v1": (objects_sha, 351103),
}
expected_tree = (
    ("scripts/realhost-b82-c8e41d73/bind-final-package.sh",
     "13ec99ddafb7452c98f05bf4855ef52c3f54b185",
     "a808a7879ef64190eff9e81e6b694acea7bc04b1b74ffad44109b237a5eb14ca"),
    ("scripts/realhost-b82-c8e41d73/controller.sh",
     "8371e5492c4e88f3e855fa3c7edfbff15bcf3a5f",
     "fb8a7a685b5a6b73de851ee9a3396f4154cc4ae083a7c36f3b3128b2b9a2e77d"),
    ("scripts/realhost-b82-c8e41d73/locked-transport.exp",
     "264f0cf74e6ff53d0cbee2688faa5d886898d22f",
     "c70e4f040dc082c4f286c237bda32fe2a60b3e5f6300ec57734645a0be12abec"),
    ("scripts/realhost-b82-c8e41d73/root-matrix-n-r.sh",
     "d2b2d473afb79c4463fd6c712d4eda3faeed5c7e",
     "9ec125c2933866431779b760d41c6484cc0fbb9e5e9f3b5431c4a56fbab63e07"),
    ("scripts/realhost-b82-c8e41d73/check-realhost-iperf.py",
     "765871ef3af87cd8a101a42e71ea97c1245dc9da",
     "9a52378b8a1ef6043d4d5792471c8239a0392a80da72f5c00846dd89e88ccd67"),
    ("scripts/realhost-b82-c8e41d73/test-hermetic-matrix.sh",
     "81f7cd86d8dc5a93133ea755311ba57aa66e4c76",
     "9b81949416a1b4df91fee0e7d31a3de2c6ba9b474dc9c0f4dbbb1cc609207499"),
    ("scripts/realhost-b82-c8e41d73/test_matrix_static.py",
     "0a2b1538d3127e8bae8953b0dff59d60cc379f39",
     "8de2dcdc866938da0502f1ad73ac9b38c9b6ff4066c76e9cbc946c9ca30a53f8"),
    ("scripts/realhost-b82-c8e41d73/checksum-module-lease.sh",
     "c2e6077005e046eef0e1186c26cdaaf29c780f98",
     "4ab9a22910e8d597cc04bb4fdde9e1b32d37a1bb2c6ad7b76f52d576b5a9adb2"),
    ("scripts/realhost-b82-c8e41d73/root-fresh-verifier-gate.sh",
     "48dd5e68071798c3d25daf0051cbf54f8cd3297e",
     "4c2cf85b7e571df9b7ed4a77fa720c9f5e35950d44af5a39499a7ad700fe6a27"),
    ("scripts/realhost-b82-c8e41d73/test-hermetic-fresh-verifier-gate.sh",
     "f3f7367d28253ebae746eb0e225c11f90eaa8305",
     "c9b5b1f954c794c5c986214777727a76579f670db9587f319ac148fc0c2a05f3"),
    ("scripts/realhost-b82-c8e41d73/test_fresh_verifier_gate_static.py",
     "f86736b1c4a5b884814f062edbb2d652172f024f",
     "ace6951027788e82ad879caf285316af4e6ee81fdb6746f569cd7c22b9f80bf3"),
    ("scripts/realhost-b82-c8e41d73/prepare-stage-root.sh",
     "057db657b0ba096a4f660eedda2e0a4242af7de5",
     "1bcb8db91d976d2a1d95f7d87223a2dac4a1678f74c1c25542e54b01ee10eeea"),
    ("scripts/realhost-b82-acceptance-v1/realnic_acceptance.py",
     "e1edba5c9dd62c8c169d7129e8b376d4ce7d1168",
     "a88100b2a23ad41dd3e644c3ba1c7a722d58c8184a997aabf0ceab78552c6339"),
    ("scripts/realhost-b82-acceptance-v1/test_realnic_acceptance.py",
     "e92f8f7db9733eb3f655b388f1efd685f738c2c4",
     "fcb3d0dadee6da6e0ad67d028f268ebe43575287f555cd8100d279f8a3b0b79c"),
    ("scripts/realhost-b82-acceptance-v1/test_realnic_acceptance_static.py",
     "b0dd244937b9139fe8c8548d6c046b76d9f611e9",
     "ba8aef3219a0cf2a5c6b5058b245f64eb828a08bb532d2aa0291f51ee7206ad2"),
    ("scripts/provision-ubuntu-test-host.sh",
     "143eb89a2e4bbbf548b510bcc2fd9f66184d3d76",
     "078d191b0edbafe27e9f684d3fa495e04d7217a01d0ec1fd32eaede211178c8f"),
    ("scripts/realhost-b82-c8e41d73/root-veth-n-r.sh",
     "a72f7f2eebe765bc7fa8a5352c134233b30ac8aa",
     "fbb8779039137383df6f51f05319faea966c69a80001da837dee22d04d8f7a70"),
    ("scripts/realhost-b82-c8e41d73/test-hermetic-veth-runner.sh",
     "ae0c74eefe33cf6afda681ba6fca17b54700108f",
     "939c3b28310596ed6bada0eb3ccdd5ebbb7eeebeaf959504c7d468b929f8174c"),
    ("scripts/realhost-b82-c8e41d73/test_veth_runner_static.py",
     "5bc3d0ac0ac48c3adc0cd86166f533edc676c712",
     "e40da6b1a6541a9b8b6c56d9277d4d73838e037876180e479b5af5d64a4edc90"),
    ("scripts/realhost-b82-routed-veth-v1/controller-seam.sh",
     "18d9e4d72a0b9022019e738d9de4fd4e23bc4903",
     "2bd7b65c3e770ff53445cbc7c195e741e8fff5eeef9e51bd6fcaa2f513d1f251"),
    ("scripts/realhost-b82-routed-veth-v1/root-routed-veth-n-r.sh",
     "9d30910b692b2d42c1528c75c2a3ba0a5d0a11cb",
     "5af8b848c9fc5f915b25c6c03822622f2ac75996a54ebf8172c7c5391c9f3485"),
    ("scripts/realhost-b82-routed-veth-v1/test-hermetic-routed-veth-harness.sh",
     "253c7b0b4d4c2d065475a82742418446146d0a0a",
     "674f96665eb26f879eae08936683fdac2beb974841ed99f9021abe9e04752032"),
    ("scripts/realhost-b82-routed-veth-v1/test_routed_veth_harness_static.py",
     "06e0fa14779ce778440250f4a437426017754cd4",
     "5bb678726ecc6bcc946233ae138d541fc50dc9f6ec40ddf139350863690d88c1"),
)
directory_flags = (os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                   getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) |
                   getattr(os, "O_NONBLOCK", 0))
file_flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
              getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0))
expected_package_entries = (
    set(expected_files) | set(history_files) | {"history-verification.git"}
)
expected_history_entries = {"HEAD", "config", "description", "hooks", "info", "objects", "refs"}


def directory_identity(metadata):
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def file_identity(metadata):
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


package_fd = -1
history_fd = -1
bundle_fd = -1
try:
    try:
        package_fd = os.open(package_name, directory_flags)
        held_package = os.fstat(package_fd)
        named_package = os.stat(package_name, follow_symlinks=False)
    except OSError:
        raise SystemExit(66)
    if (not stat.S_ISDIR(held_package.st_mode) or
            not stat.S_ISDIR(named_package.st_mode) or
            directory_identity(held_package) != directory_identity(named_package) or
            os.path.realpath(package_name) != package_name or
            held_package.st_uid != os.getuid() or
            stat.S_IMODE(held_package.st_mode) != 0o700 or
            set(os.listdir(package_fd)) != expected_package_entries):
        raise SystemExit(66)
    package_identity = directory_identity(held_package)

    def read_exact_regular(name, expected_sha, expected_size, keep_open=False):
        descriptor = -1
        try:
            descriptor = os.open(name, file_flags, dir_fd=package_fd)
            held = os.fstat(descriptor)
            named = os.stat(name, dir_fd=package_fd, follow_symlinks=False)
            if (not stat.S_ISREG(held.st_mode) or not stat.S_ISREG(named.st_mode) or
                    file_identity(held) != file_identity(named) or
                    held.st_uid != held_package.st_uid or
                    held.st_gid != held_package.st_gid or
                    stat.S_IMODE(held.st_mode) != 0o600 or held.st_nlink != 1 or
                    held.st_size != expected_size or
                    not (1 <= held.st_size <= 16777216)):
                raise SystemExit(66)
            payload = b""
            offset = 0
            while True:
                chunk = os.pread(descriptor, 65536, offset)
                if not chunk:
                    break
                payload += chunk
                offset += len(chunk)
            after = os.fstat(descriptor)
            if file_identity(held) != file_identity(after):
                raise SystemExit(66)
            if (len(payload) != expected_size or
                    hashlib.sha256(payload).hexdigest() != expected_sha):
                raise SystemExit(67)
            identity = file_identity(held)
            if keep_open:
                kept_descriptor = descriptor
                descriptor = -1
                return payload, identity, kept_descriptor
            return payload, identity, -1
        except OSError:
            raise SystemExit(66)
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    payloads = {}
    initial_file_identities = {}
    for entry_name, (expected_sha, expected_size) in expected_files.items():
        keep_open = entry_name == "source-4f2a9b61.bundle"
        payload, identity, kept_descriptor = read_exact_regular(
            entry_name, expected_sha, expected_size, keep_open=keep_open
        )
        payloads[entry_name] = payload
        initial_file_identities[entry_name] = identity
        if keep_open:
            bundle_fd = kept_descriptor
    history_payloads = {}
    for entry_name, (expected_sha, expected_size) in history_files.items():
        payload, identity, _ = read_exact_regular(entry_name, expected_sha, expected_size)
        history_payloads[entry_name] = payload
        initial_file_identities[entry_name] = identity

    if (payloads["package-manifest.v1"] != expected_manifest or
            hashlib.sha256(expected_manifest).hexdigest() != manifest_sha):
        raise SystemExit(67)
    if any(line.startswith(b"?") for line in history_payloads["history-objects.v1"].splitlines()):
        raise SystemExit(76)

    try:
        history_fd = os.open("history-verification.git", directory_flags, dir_fd=package_fd)
        held_history = os.fstat(history_fd)
        named_history = os.stat(
            "history-verification.git", dir_fd=package_fd, follow_symlinks=False
        )
    except OSError:
        raise SystemExit(66)
    if (not stat.S_ISDIR(held_history.st_mode) or
            not stat.S_ISDIR(named_history.st_mode) or
            directory_identity(held_history) != directory_identity(named_history) or
            held_history.st_uid != held_package.st_uid or
            held_history.st_gid != held_package.st_gid or
            stat.S_IMODE(held_history.st_mode) != 0o700 or
            set(os.listdir(history_fd)) != expected_history_entries):
        raise SystemExit(66)
    history_identity = directory_identity(held_history)

    git_environment = {
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
    }
    git_prefix = [
        "/usr/bin/git",
        "--no-pager",
        "--no-replace-objects",
        "-c", "core.attributesFile=/dev/null",
        "-c", "core.fsmonitor=false",
        "-c", "core.hooksPath=/dev/null",
    ]

    def enter_held_history():
        os.fchdir(history_fd)

    def run_git(arguments, failure_rc=76):
        try:
            result = subprocess.run(
                git_prefix + list(arguments),
                env=git_environment,
                pass_fds=(history_fd, bundle_fd),
                preexec_fn=enter_held_history,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=120,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            raise SystemExit(failure_rc)
        if result.returncode != 0:
            raise SystemExit(failure_rc)
        return result.stdout

    if run_git(("rev-parse", f"{integration_commit}^{{commit}}")) != (
            integration_commit + "\n").encode("ascii"):
        raise SystemExit(76)
    if run_git(("rev-parse", "--is-shallow-repository")) != b"false\n":
        raise SystemExit(76)
    run_git(("fsck", "--full", "--strict", "--no-dangling", integration_commit))
    if run_git(("rev-list", "--count", integration_commit)) != b"668\n":
        raise SystemExit(76)
    actual_roots = run_git(("rev-list", "--max-parents=0", "--reverse", integration_commit))
    if not actual_roots or actual_roots != history_payloads["history-roots.v1"]:
        raise SystemExit(76)
    actual_objects = run_git(
        ("rev-list", "--parents", "--objects", "--missing=print", integration_commit)
    )
    if hashlib.sha256(actual_objects).hexdigest() != objects_sha:
        raise SystemExit(76)

    bundle_argument = f"/dev/fd/{bundle_fd}"
    try:
        os.lseek(bundle_fd, 0, os.SEEK_SET)
    except OSError:
        raise SystemExit(67)
    run_git(("bundle", "verify", bundle_argument), failure_rc=67)
    try:
        os.lseek(bundle_fd, 0, os.SEEK_SET)
    except OSError:
        raise SystemExit(67)
    bundle_heads = run_git(
        ("bundle", "list-heads", bundle_argument, integration_ref), failure_rc=67
    )
    if bundle_heads != f"{integration_commit} {integration_ref}\n".encode("ascii"):
        raise SystemExit(67)

    if len(expected_tree) != 23:
        raise SystemExit(70)
    for repository_file, expected_blob, expected_sha in expected_tree:
        expected_listing = (
            f"100755 blob {expected_blob}\t{repository_file}\n".encode("utf-8")
        )
        if run_git(("ls-tree", integration_commit, "--", repository_file)) != expected_listing:
            raise SystemExit(76)
        blob_payload = run_git(("cat-file", "blob", expected_blob))
        if hashlib.sha256(blob_payload).hexdigest() != expected_sha:
            raise SystemExit(76)

    for entry_name, (expected_sha, expected_size) in expected_files.items():
        payload, identity, _ = read_exact_regular(entry_name, expected_sha, expected_size)
        if (identity != initial_file_identities[entry_name] or
                payload != payloads[entry_name]):
            raise SystemExit(66)
    for entry_name, (expected_sha, expected_size) in history_files.items():
        payload, identity, _ = read_exact_regular(entry_name, expected_sha, expected_size)
        if (identity != initial_file_identities[entry_name] or
                payload != history_payloads[entry_name]):
            raise SystemExit(66)
    if file_identity(os.fstat(bundle_fd)) != initial_file_identities[
            "source-4f2a9b61.bundle"]:
        raise SystemExit(66)

    held_history_after = os.fstat(history_fd)
    named_history_after = os.stat(
        "history-verification.git", dir_fd=package_fd, follow_symlinks=False
    )
    if (directory_identity(held_history_after) != history_identity or
            directory_identity(named_history_after) != history_identity or
            set(os.listdir(history_fd)) != expected_history_entries):
        raise SystemExit(66)
    held_package_after = os.fstat(package_fd)
    named_package_after = os.stat(package_name, follow_symlinks=False)
    if (directory_identity(held_package_after) != package_identity or
            directory_identity(named_package_after) != package_identity or
            os.path.realpath(package_name) != package_name or
            set(os.listdir(package_fd)) != expected_package_entries):
        raise SystemExit(66)
    print(f"{held_package_after.st_dev}:{held_package_after.st_ino}")
except OSError:
    raise SystemExit(66)
finally:
    if bundle_fd >= 0:
        os.close(bundle_fd)
    if history_fd >= 0:
        os.close(history_fd)
    if package_fd >= 0:
        os.close(package_fd)
' "${R2_PREDECESSOR_MANIFEST}" "${R2_PREDECESSOR_PACKAGE}" \
    "${R2_PREDECESSOR_MANIFEST_SHA256}" "${R2_PREDECESSOR_BUNDLE_SHA256}" \
    "${R2_PREDECESSOR_HISTORY_ROOTS_SHA256}" \
    "${R2_PREDECESSOR_HISTORY_OBJECTS_SHA256}" "${R2_PREDECESSOR_COMMIT}" \
    "${R2_PREDECESSOR_REF}" <<'R2_PREDECESSOR_MANIFEST_V4' || return $?
format	wg-mix-ebpf-b82-v6-package-v4
run_id	c8e41d73
package_id	4f2a9b61
integration_ref	refs/heads/codex/tcx-faketcp-final-v2
integration_commit	f75fe7678cfdecf08173fd201be5c055417d6e11
bundle_name	source-4f2a9b61.bundle
bundle_sha256	b74811808e0413714dcf20b8292fe68631f603c0b9a68bc9951af481477b413b
history_verification	isolated-unbundle-rev-list-fsck-v1
history_commit_count	668
history_roots_sha256	9356df63b3d4c4c362912b14ab8ee5cb54d12cd1f14be9aa1fe8e18adbad6f05
history_objects_sha256	21647f92e57f9dbb8e15707699f632544d6dfcf2e1b4279d775cce1fb82163f3
wg_state	absent
wg_interface	absent
wg_local_address	absent
wg_peer_address	absent
local_repository	/Users/siyixuan/codes-2/wg-mix-ebpf/.worktree/tcx-faketcp-final-v2
local_package_dir	/private/tmp/wg-mix-b82-v6-c8e41d73-4f2a9b61-f75fe7678cfd
remote_package_dir	/home/siyixuan/wg-mix-ebpf-test/unpriv-4f2a9b61
remote_source	/run/wg-mix-ebpf-source-stages/c8e41d73/source
target_user	siyixuan
target_host	192.168.10.82
target_hostname	ubuntu-2604-test
target_kernel	7.0.0-28-generic
target_machine_id	9db3fb717cc74974b2a6b243d67f67b9
target_interface	ens33
peer_address	47.116.202.155
peer_port	5201
soak_seconds	3600
session_seconds	300
physical_nic_forward_authority	realnic-acceptance-v1
physical_interface_lock	/run/wg-mix-ebpf-realnic-physical-interface.v1.lock
legacy_matrix_mode	retired
realnic_profile	acceptance
realnic_traffic_seconds	30
bind_final_package_sh_path	scripts/realhost-b82-c8e41d73/bind-final-package.sh
bind_final_package_sh_blob	13ec99ddafb7452c98f05bf4855ef52c3f54b185
bind_final_package_sh_sha256	a808a7879ef64190eff9e81e6b694acea7bc04b1b74ffad44109b237a5eb14ca
controller_sh_path	scripts/realhost-b82-c8e41d73/controller.sh
controller_sh_blob	8371e5492c4e88f3e855fa3c7edfbff15bcf3a5f
controller_sh_sha256	fb8a7a685b5a6b73de851ee9a3396f4154cc4ae083a7c36f3b3128b2b9a2e77d
locked_transport_exp_path	scripts/realhost-b82-c8e41d73/locked-transport.exp
locked_transport_exp_blob	264f0cf74e6ff53d0cbee2688faa5d886898d22f
locked_transport_exp_sha256	c70e4f040dc082c4f286c237bda32fe2a60b3e5f6300ec57734645a0be12abec
root_matrix_n_r_sh_path	scripts/realhost-b82-c8e41d73/root-matrix-n-r.sh
root_matrix_n_r_sh_blob	d2b2d473afb79c4463fd6c712d4eda3faeed5c7e
root_matrix_n_r_sh_sha256	9ec125c2933866431779b760d41c6484cc0fbb9e5e9f3b5431c4a56fbab63e07
check_realhost_iperf_py_path	scripts/realhost-b82-c8e41d73/check-realhost-iperf.py
check_realhost_iperf_py_blob	765871ef3af87cd8a101a42e71ea97c1245dc9da
check_realhost_iperf_py_sha256	9a52378b8a1ef6043d4d5792471c8239a0392a80da72f5c00846dd89e88ccd67
test_hermetic_matrix_sh_path	scripts/realhost-b82-c8e41d73/test-hermetic-matrix.sh
test_hermetic_matrix_sh_blob	81f7cd86d8dc5a93133ea755311ba57aa66e4c76
test_hermetic_matrix_sh_sha256	9b81949416a1b4df91fee0e7d31a3de2c6ba9b474dc9c0f4dbbb1cc609207499
test_matrix_static_py_path	scripts/realhost-b82-c8e41d73/test_matrix_static.py
test_matrix_static_py_blob	0a2b1538d3127e8bae8953b0dff59d60cc379f39
test_matrix_static_py_sha256	8de2dcdc866938da0502f1ad73ac9b38c9b6ff4066c76e9cbc946c9ca30a53f8
checksum_module_lease_sh_path	scripts/realhost-b82-c8e41d73/checksum-module-lease.sh
checksum_module_lease_sh_blob	c2e6077005e046eef0e1186c26cdaaf29c780f98
checksum_module_lease_sh_sha256	4ab9a22910e8d597cc04bb4fdde9e1b32d37a1bb2c6ad7b76f52d576b5a9adb2
root_fresh_verifier_gate_sh_path	scripts/realhost-b82-c8e41d73/root-fresh-verifier-gate.sh
root_fresh_verifier_gate_sh_blob	48dd5e68071798c3d25daf0051cbf54f8cd3297e
root_fresh_verifier_gate_sh_sha256	4c2cf85b7e571df9b7ed4a77fa720c9f5e35950d44af5a39499a7ad700fe6a27
test_hermetic_fresh_verifier_gate_sh_path	scripts/realhost-b82-c8e41d73/test-hermetic-fresh-verifier-gate.sh
test_hermetic_fresh_verifier_gate_sh_blob	f3f7367d28253ebae746eb0e225c11f90eaa8305
test_hermetic_fresh_verifier_gate_sh_sha256	c9b5b1f954c794c5c986214777727a76579f670db9587f319ac148fc0c2a05f3
test_fresh_verifier_gate_static_py_path	scripts/realhost-b82-c8e41d73/test_fresh_verifier_gate_static.py
test_fresh_verifier_gate_static_py_blob	f86736b1c4a5b884814f062edbb2d652172f024f
test_fresh_verifier_gate_static_py_sha256	ace6951027788e82ad879caf285316af4e6ee81fdb6746f569cd7c22b9f80bf3
prepare_stage_root_sh_path	scripts/realhost-b82-c8e41d73/prepare-stage-root.sh
prepare_stage_root_sh_blob	057db657b0ba096a4f660eedda2e0a4242af7de5
prepare_stage_root_sh_sha256	1bcb8db91d976d2a1d95f7d87223a2dac4a1678f74c1c25542e54b01ee10eeea
realnic_acceptance_py_path	scripts/realhost-b82-acceptance-v1/realnic_acceptance.py
realnic_acceptance_py_blob	e1edba5c9dd62c8c169d7129e8b376d4ce7d1168
realnic_acceptance_py_sha256	a88100b2a23ad41dd3e644c3ba1c7a722d58c8184a997aabf0ceab78552c6339
test_realnic_acceptance_py_path	scripts/realhost-b82-acceptance-v1/test_realnic_acceptance.py
test_realnic_acceptance_py_blob	e92f8f7db9733eb3f655b388f1efd685f738c2c4
test_realnic_acceptance_py_sha256	fcb3d0dadee6da6e0ad67d028f268ebe43575287f555cd8100d279f8a3b0b79c
test_realnic_acceptance_static_py_path	scripts/realhost-b82-acceptance-v1/test_realnic_acceptance_static.py
test_realnic_acceptance_static_py_blob	b0dd244937b9139fe8c8548d6c046b76d9f611e9
test_realnic_acceptance_static_py_sha256	ba8aef3219a0cf2a5c6b5058b245f64eb828a08bb532d2aa0291f51ee7206ad2
provision_ubuntu_test_host_sh_path	scripts/provision-ubuntu-test-host.sh
provision_ubuntu_test_host_sh_blob	143eb89a2e4bbbf548b510bcc2fd9f66184d3d76
provision_ubuntu_test_host_sh_sha256	078d191b0edbafe27e9f684d3fa495e04d7217a01d0ec1fd32eaede211178c8f
root_veth_n_r_sh_path	scripts/realhost-b82-c8e41d73/root-veth-n-r.sh
root_veth_n_r_sh_blob	a72f7f2eebe765bc7fa8a5352c134233b30ac8aa
root_veth_n_r_sh_sha256	fbb8779039137383df6f51f05319faea966c69a80001da837dee22d04d8f7a70
test_hermetic_veth_runner_sh_path	scripts/realhost-b82-c8e41d73/test-hermetic-veth-runner.sh
test_hermetic_veth_runner_sh_blob	ae0c74eefe33cf6afda681ba6fca17b54700108f
test_hermetic_veth_runner_sh_sha256	939c3b28310596ed6bada0eb3ccdd5ebbb7eeebeaf959504c7d468b929f8174c
test_veth_runner_static_py_path	scripts/realhost-b82-c8e41d73/test_veth_runner_static.py
test_veth_runner_static_py_blob	5bc3d0ac0ac48c3adc0cd86166f533edc676c712
test_veth_runner_static_py_sha256	e40da6b1a6541a9b8b6c56d9277d4d73838e037876180e479b5af5d64a4edc90
controller_seam_sh_path	scripts/realhost-b82-routed-veth-v1/controller-seam.sh
controller_seam_sh_blob	18d9e4d72a0b9022019e738d9de4fd4e23bc4903
controller_seam_sh_sha256	2bd7b65c3e770ff53445cbc7c195e741e8fff5eeef9e51bd6fcaa2f513d1f251
root_routed_veth_n_r_sh_path	scripts/realhost-b82-routed-veth-v1/root-routed-veth-n-r.sh
root_routed_veth_n_r_sh_blob	9d30910b692b2d42c1528c75c2a3ba0a5d0a11cb
root_routed_veth_n_r_sh_sha256	5af8b848c9fc5f915b25c6c03822622f2ac75996a54ebf8172c7c5391c9f3485
test_hermetic_routed_veth_harness_sh_path	scripts/realhost-b82-routed-veth-v1/test-hermetic-routed-veth-harness.sh
test_hermetic_routed_veth_harness_sh_blob	253c7b0b4d4c2d065475a82742418446146d0a0a
test_hermetic_routed_veth_harness_sh_sha256	674f96665eb26f879eae08936683fdac2beb974841ed99f9021abe9e04752032
test_routed_veth_harness_static_py_path	scripts/realhost-b82-routed-veth-v1/test_routed_veth_harness_static.py
test_routed_veth_harness_static_py_blob	06e0fa14779ce778440250f4a437426017754cd4
test_routed_veth_harness_static_py_sha256	5bb678726ecc6bcc946233ae138d541fc50dc9f6ec40ddf139350863690d88c1
R2_PREDECESSOR_MANIFEST_V4
}

verify_r2_local_authorities() {
  printf 'B82_V6_R2_CURRENT_LOCAL_AUTHORITY manifest_sha256=%s integration_commit=%s format=v5 fields=112 package_files=20 credential_read=0 network_operations=0\n' \
    "${MANIFEST_SHA256}" "${INTEGRATION_COMMIT}"
  R2_PREDECESSOR_DEVICE_INODE="$(verify_r2_predecessor_manifest_contract)" || return $?
  [[ "${R2_PREDECESSOR_DEVICE_INODE}" =~ ^[0-9]+:[0-9]+$ ]] || return 70
  printf 'B82_V6_R2_PREDECESSOR_LOCAL_AUTHORITY predecessor_package=%s predecessor_package_device_inode=%s predecessor_manifest_sha256=%s predecessor_commit=%s predecessor_bundle_sha256=%s format=v4 fields=103 package_files=17 credential_read=0 network_operations=0\n' \
    "${R2_PREDECESSOR_PACKAGE}" "${R2_PREDECESSOR_DEVICE_INODE}" \
    "${R2_PREDECESSOR_MANIFEST_SHA256}" "${R2_PREDECESSOR_COMMIT}" \
    "${R2_PREDECESSOR_BUNDLE_SHA256}"
}

verify_local_approved_plan() {
  local canonical shape size package_shape caller_uid package_uid package_gid package_mode package_type
  [[ "${APPROVED_PLAN}" == "${LOCAL_PACKAGE_DIR}/realnic-plan.${APPROVED_PLAN_SHA256}.json" ]] || return 65
  [[ "${APPROVED_PLAN}" == /* && -f "${APPROVED_PLAN}" && ! -L "${APPROVED_PLAN}" ]] || return 66
  canonical="$(CDPATH='' cd -- "$(/usr/bin/dirname -- "${APPROVED_PLAN}")" && pwd -P)/${APPROVED_PLAN##*/}" || return 66
  [[ "${canonical}" == "${APPROVED_PLAN}" ]] || return 66
  caller_uid="$(/usr/bin/id -u)" || return 66
  if [[ "$(/usr/bin/uname -s)" == 'Darwin' ]]; then
    package_shape="$(/usr/bin/stat -f '%u:%g:%Lp:%HT' -- "${LOCAL_PACKAGE_DIR}")" || return 66
    shape="$(/usr/bin/stat -f '%u:%g:%Lp:%l:%HT' -- "${APPROVED_PLAN}")" || return 66
    size="$(/usr/bin/stat -f '%z' -- "${APPROVED_PLAN}")" || return 66
    IFS=: read -r package_uid package_gid package_mode package_type <<<"${package_shape}"
    [[ "${package_uid}" == "${caller_uid}" && "${package_mode}" == '700' &&
      "${package_type}" == 'Directory' &&
      "${shape}" == "${package_uid}:${package_gid}:600:1:Regular File" ]] || return 66
  else
    package_shape="$(/usr/bin/stat -Lc '%u:%g:%a:%F' -- "${LOCAL_PACKAGE_DIR}")" || return 66
    shape="$(/usr/bin/stat -Lc '%u:%g:%a:%h:%F' -- "${APPROVED_PLAN}")" || return 66
    size="$(/usr/bin/stat -Lc '%s' -- "${APPROVED_PLAN}")" || return 66
    IFS=: read -r package_uid package_gid package_mode package_type <<<"${package_shape}"
    [[ "${package_uid}" == "${caller_uid}" && "${package_mode}" == '700' &&
      "${package_type}" == 'directory' &&
      "${shape}" == "${package_uid}:${package_gid}:600:1:regular file" ]] || return 66
  fi
  [[ "${size}" =~ ^[1-9][0-9]*$ &&
    "${size}" -le 16777216 && "$(sha256_file "${APPROVED_PLAN}")" == "${APPROVED_PLAN_SHA256}" ]]
}

derive_approved_plan_path() {
  if [[ "${APPROVED_PLAN_SHA256}" == 'none' ]]; then
    APPROVED_PLAN='none'
  else
    valid_sha256 "${APPROVED_PLAN_SHA256}" || return 65
    APPROVED_PLAN="${LOCAL_PACKAGE_DIR}/realnic-plan.${APPROVED_PLAN_SHA256}.json"
  fi
}

transport() {
  local action="$1" operation="$2" transport_approved_sha256='none'
  case "${operation}" in
    scp-realnic-approved-plan | verify-sha-realnic-approved-plan | \
      verify-stat-realnic-approved-plan | stage-realnic-plan-snapshot | \
      realnic-run | stage-realnic-plan-verify | realnic-restore)
      transport_approved_sha256="${APPROVED_PLAN_SHA256}"
      ;;
  esac
  /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C \
    /usr/bin/expect "${LOCAL_REPOSITORY}/${LOCKED_TRANSPORT_EXP_PATH}" \
    --manifest "${MANIFEST}" --manifest-sha256 "${MANIFEST_SHA256}" \
    --credential-path "${SUPPLIED_CREDENTIAL_PATH}" --action "${action}" \
    --operation "${operation}" --approved-plan-sha256 "${transport_approved_sha256}"
}

run_operation() {
  local action="$1" operation="$2" rc started finished
  started="$(/bin/date -u '+%Y-%m-%dT%H:%M:%SZ')" || return 70
  printf 'B82_V6_CONTROLLER_EVENT utc=%s event=start mode=%s operation=%s target=%s\n' \
    "${started}" "${MODE}" "${operation}" "${TARGET_HOST}"
  transport "${action}" "${operation}"
  rc=$?
  finished="$(/bin/date -u '+%Y-%m-%dT%H:%M:%SZ')" || return 70
  printf 'B82_V6_CONTROLLER_EVENT utc=%s event=finish mode=%s operation=%s target=%s rc=%s\n' \
    "${finished}" "${MODE}" "${operation}" "${TARGET_HOST}" "${rc}"
  return "${rc}"
}

readonly -a BASE_IDENTITY_OPERATIONS=(
  identity-hostname identity-kernel identity-machine identity-netns identity-interface
)
readonly -a POSTFLIGHT_OPERATIONS=(
  identity-driver identity-wg-interfaces
  tool-go tool-clang tool-llvm tool-bpftool tool-make tool-gcc tool-iperf3
  tool-shellcheck tool-jq tool-wireguard tool-ethtool tool-tc tool-ip
  kernel-btf kernel-bpffs kernel-headers
)
readonly -a PREPARE_NEW_STALE_OPERATIONS=(
  stale-package-root
  stale-bootstrap-root
  stale-alternate-bootstrap-root
  stale-stage-root
  stale-fresh-root
  stale-standalone-root
  stale-routed-evidence-root
  stale-realnic-run-roots
  stale-realnic-interface-leases
  stale-veth-wgc8e41a
  stale-veth-wgc8e41b
  stale-veth-wga19f7a
  stale-veth-wga19f7b
  stale-veth-wg5b8d3a
  stale-veth-wg5b8d3b
  stale-pin-fresh
  stale-pin-standalone
  stale-pin-legacy-tcx
  stale-pin-legacy-nic-original
  stale-pin-legacy-nic-all-on
  stale-pin-legacy-nic-all-off
  stale-pin-legacy-nic-tx-path
  stale-pin-legacy-nic-rx-path
  stale-pin-legacy-nic-mtu1492
  stale-pin-legacy-nic-mtu1500
  stale-pin-legacy-nic-soak
  stale-checksum-module
  stale-checksum-module-btf
  stale-checksum-module-lock
  stale-physical-interface-lock
)
readonly -a PACKAGE_NAMES=(
  source-4f2a9b61.bundle package-manifest.v1 bind-final-package.sh controller.sh prepare-stage-root.sh
  provision-ubuntu-test-host.sh root-matrix-n-r.sh check-realhost-iperf.py
  test-hermetic-matrix.sh test_matrix_static.py checksum-module-lease.sh
  test-hermetic-checksum-module-lease.sh test_checksum_module_lease_static.py
  wg_mix_faketcp_checksum.c
  root-fresh-verifier-gate.sh test-hermetic-fresh-verifier-gate.sh
  test_fresh_verifier_gate_static.py realnic_acceptance.py
  test_realnic_acceptance.py test_realnic_acceptance_static.py
)
readonly -a BOOTSTRAP_CREATE_OPERATIONS=(
  bootstrap-absent bootstrap-not-symlink bootstrap-create bootstrap-root-readlink bootstrap-root-stat
  bootstrap-install-provisioner bootstrap-install-stager
)
# This tuple is a source contract mirrored by the locked transport and static verifier.
# shellcheck disable=SC2034
readonly -a BOOTSTRAP_ROOT_VERIFY_OPERATIONS=(bootstrap-root-readlink bootstrap-root-stat)
readonly -a PROVISIONER_VERIFY_OPERATIONS=(
  bootstrap-provisioner-readlink bootstrap-provisioner-stat bootstrap-provisioner-sha
)
readonly -a STAGER_VERIFY_OPERATIONS=(
  bootstrap-stager-readlink bootstrap-stager-stat bootstrap-stager-sha
)
readonly -a STAGE_OPERATIONS=(stage-snapshot stage-plan stage-run)

state_transition() {
  printf 'B82_V6_CONTROLLER_STATE from=%s to=%s automatic_apply=0\n' "$1" "$2"
}

run_prepare_new_stale_gate() {
  local action="$1" operation id class rc ordinal=0 absent=0
  local total="${#PREPARE_NEW_STALE_OPERATIONS[@]}"
  for operation in "${PREPARE_NEW_STALE_OPERATIONS[@]}"; do
    ((ordinal += 1))
    id="${operation#stale-}"
    run_operation "${action}" "${operation}"
    rc=$?
    if ((rc != 0)); then
      printf 'B82_V6_STALE_ITEM_V1 ordinal=%02d id=%s class=STOP writes=0 cleanup=0 rc=%d\n' \
        "${ordinal}" "${id}" "${rc}"
      printf 'B82_V6_STALE_SUMMARY_V1 profile=prepare-new items=%d checked=%d absent=%d writes=0 cleanup=0 result=STOP rc=%d\n' \
        "${total}" "${ordinal}" "${absent}" "${rc}"
      return "${rc}"
    fi
    if [[ "${action}" == plan ]]; then
      class='PLANNED'
    else
      class='ABSENT'
      ((absent += 1))
    fi
    printf 'B82_V6_STALE_ITEM_V1 ordinal=%02d id=%s class=%s writes=0 cleanup=0 rc=0\n' \
      "${ordinal}" "${id}" "${class}"
  done
  if [[ "${action}" == plan ]]; then class='PLANNED'; else class='PASS'; fi
  printf 'B82_V6_STALE_SUMMARY_V1 profile=prepare-new items=%d checked=%d absent=%d writes=0 cleanup=0 result=%s rc=0\n' \
    "${total}" "${total}" "${absent}" "${class}"
}

plan_all() {
  local operation name
  printf 'B82_V6_CONTROLLER_STATE current=PACKAGE_BOUND automatic_apply=0\n'
  for operation in "${BASE_IDENTITY_OPERATIONS[@]}"; do
    run_operation plan "${operation}" || return $?
  done
  run_prepare_new_stale_gate plan || return $?
  for operation in package-parent-stat package-mkdir; do
    run_operation plan "${operation}" || return $?
  done
  for name in "${PACKAGE_NAMES[@]}"; do
    run_operation plan "scp-${name}" || return $?
    run_operation plan "verify-sha-${name}" || return $?
    run_operation plan "verify-stat-${name}" || return $?
  done
  for operation in "${BOOTSTRAP_CREATE_OPERATIONS[@]}"; do
    run_operation plan "${operation}" || return $?
  done
  state_transition PACKAGE_BOUND BOOTSTRAP_ONLY
  for operation in "${PROVISIONER_VERIFY_OPERATIONS[@]}" provision-check; do
    run_operation plan "${operation}" || return $?
  done
  printf '%s\n' \
    'B82_V6_CONTROLLER_BRANCH missing_set=none next_state=POSTFLIGHT' \
    'B82_V6_CONTROLLER_BRANCH missing_set=initial|iperf3 next_state=AWAIT_APPLY' \
    'B82_V6_CONTROLLER_STATE from=AWAIT_APPLY to=PROVISION_APPLY explicit_mode=provision-apply automatic_apply=0'
  for operation in "${PROVISIONER_VERIFY_OPERATIONS[@]}" provision-apply; do
    run_operation plan "${operation}" || return $?
  done
  for operation in "${POSTFLIGHT_OPERATIONS[@]}" controller-shellcheck hermetic-matrix hermetic-fresh \
    "${STAGER_VERIFY_OPERATIONS[@]}" "${STAGE_OPERATIONS[@]}"; do
    run_operation plan "${operation}" || return $?
  done
  for operation in fresh-plan fresh-run fresh-restore; do
    run_operation plan "${operation}" || return $?
  done
  if [[ "${WG_STATE}" == absent ]]; then
    for operation in veth-plan veth-run veth-restore; do
      run_operation plan "${operation}" || return $?
    done
  else
    printf 'B82_V6_CONTROLLER_PLAN veth-unavailable wg_state=bound operations=veth-plan,veth-run,veth-restore\n'
  fi
  for operation in routed-plan routed-run routed-restore; do
    run_operation plan "${operation}" || return $?
  done
  run_operation plan realnic-plan || return $?
  if [[ "${APPROVED_PLAN_SHA256}" != 'none' ]]; then
    verify_local_approved_plan || return $?
    for operation in scp-realnic-approved-plan verify-sha-realnic-approved-plan \
      verify-stat-realnic-approved-plan stage-realnic-plan-snapshot realnic-run \
      stage-realnic-plan-verify realnic-restore; do
      run_operation plan "${operation}" || return $?
    done
  else
    printf 'B82_V6_REALNIC_APPROVAL_REQUIRED capture_mode=realnic-plan local_plan_pattern=%s/realnic-plan.SHA256.json approved_plan_sha256=explicit automatic_approval=0\n' \
      "${LOCAL_PACKAGE_DIR}"
  fi
  printf '%s\n' \
    'B82_V6_LEGACY_MATRIX_RETIRED controller_entries=0 historical_recovery=frozen-original-package-before-final-staging'
  printf 'B82_V6_CONTROLLER_PLAN_COMPLETE credential_read=0 network_operations=0 mutations=0 legacy_forward=retired\n'
}

execute_preflight() {
  local operation
  for operation in "${BASE_IDENTITY_OPERATIONS[@]}" "${POSTFLIGHT_OPERATIONS[@]}"; do
    run_operation execute "${operation}" || return $?
  done
  run_prepare_new_stale_gate execute
}

execute_prepare() {
  run_operation execute prepare
}

execute_provision_apply() {
  run_operation execute provision-apply
}

execute_realnic_run() {
  verify_local_approved_plan || return $?
  run_operation execute realnic-run
}

execute_realnic_plan_capture() {
  local started finished transport_rc publisher_rc
  local -a pipeline_status
  started="$(/bin/date -u '+%Y-%m-%dT%H:%M:%SZ')" || return 70
  printf 'B82_V6_CONTROLLER_EVENT utc=%s event=start mode=%s operation=realnic-plan target=%s channel=capture\n' \
    "${started}" "${MODE}" "${TARGET_HOST}" >&2
  transport capture realnic-plan | \
    /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C \
      /usr/bin/python3 -B -I "${LOCAL_PACKAGE_DIR}/realnic_acceptance.py" capture-local \
      --source-commit "${INTEGRATION_COMMIT}" \
      --manifest "${MANIFEST}" --manifest-sha256 "${MANIFEST_SHA256}"
  pipeline_status=("${PIPESTATUS[@]}")
  transport_rc="${pipeline_status[0]}"
  publisher_rc="${pipeline_status[1]}"
  finished="$(/bin/date -u '+%Y-%m-%dT%H:%M:%SZ')" || return 70
  printf 'B82_V6_CONTROLLER_EVENT utc=%s event=finish mode=%s operation=realnic-plan target=%s channel=capture transport_rc=%s publisher_rc=%s\n' \
    "${finished}" "${MODE}" "${TARGET_HOST}" "${transport_rc}" "${publisher_rc}" >&2
  ((transport_rc == 0)) || return "${transport_rc}"
  return "${publisher_rc}"
}

execute_realnic_restore() {
  run_operation execute realnic-restore
}

main() {
  local package_device_inode
  parse_arguments "$@" || fail 'arguments' $?
  verify_manifest_contract || fail 'manifest-contract' $?
  derive_approved_plan_path || fail 'approved-plan-binding' $?
  case "${MODE}" in
    verify-r2-predecessor-package | \
      retire-postflight-f75fe7678cfd-r2 | verify-postflight-retirement-r2)
      verify_r2_local_authorities || fail 'r2-local-authority' $?
      ;;
  esac
  case "${MODE}" in
    veth-plan | veth-run | veth-restore)
      [[ "${WG_STATE}" == absent ]] || fail 'veth-wireguard-state' 65
      ;;
  esac
  case "${MODE}" in
    verify-package)
      package_device_inode="$(path_device_inode "${LOCAL_PACKAGE_DIR}")" ||
        fail 'package-device-inode' $?
      printf 'B82_V6_CONTROLLER_PACKAGE_VERIFIED manifest_sha256=%s integration_commit=%s package_device_inode=%s credential_read=0 network_operations=0\n' \
        "${MANIFEST_SHA256}" "${INTEGRATION_COMMIT}" "${package_device_inode}"
      ;;
    verify-r2-predecessor-package)
      printf 'B82_V6_CONTROLLER_R2_PREDECESSOR_VERIFIED predecessor_manifest_sha256=%s predecessor_commit=%s package_device_inode=%s credential_read=0 network_operations=0\n' \
        "${R2_PREDECESSOR_MANIFEST_SHA256}" "${R2_PREDECESSOR_COMMIT}" \
        "${R2_PREDECESSOR_DEVICE_INODE}"
      ;;
    plan) plan_all || fail 'plan-operation' $? ;;
    preflight) execute_preflight || fail 'preflight-operation' $? ;;
    prepare) execute_prepare || fail 'prepare-operation' $? ;;
    provision-apply) execute_provision_apply || fail 'provision-apply-operation' $? ;;
    fresh-plan)
      run_operation execute fresh-plan || fail 'fresh-plan-operation' $?
      ;;
    fresh-run)
      run_operation execute fresh-run || fail 'fresh-run-operation' $?
      ;;
    fresh-restore)
      run_operation execute fresh-restore || fail 'fresh-restore-operation' $?
      ;;
    veth-plan)
      run_operation execute veth-plan || fail 'veth-plan-operation' $?
      ;;
    veth-run)
      run_operation execute veth-run || fail 'veth-run-operation' $?
      ;;
    veth-restore)
      run_operation execute veth-restore || fail 'veth-restore-operation' $?
      ;;
    routed-plan)
      run_operation execute routed-plan || fail 'routed-plan-operation' $?
      ;;
    routed-run)
      run_operation execute routed-run || fail 'routed-run-operation' $?
      ;;
    routed-restore)
      run_operation execute routed-restore || fail 'routed-restore-operation' $?
      ;;
    realnic-plan)
      execute_realnic_plan_capture || fail 'realnic-plan-operation' $?
      ;;
    realnic-run)
      execute_realnic_run || fail 'realnic-run-operation' $?
      ;;
    realnic-restore)
      execute_realnic_restore || fail 'realnic-restore-operation' $?
      ;;
    retire-postflight-f75fe7678cfd-r2)
      run_operation execute retire-postflight-f75fe7678cfd-r2 ||
        fail 'retire-postflight-f75fe7678cfd-r2-operation' $?
      ;;
    verify-postflight-retirement-r2)
      run_operation execute verify-postflight-retirement-r2 ||
        fail 'verify-postflight-retirement-r2-operation' $?
      ;;
  esac
}

main "$@"
