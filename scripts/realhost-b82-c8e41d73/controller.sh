#!/usr/bin/env bash
set -u
set -o pipefail
umask 077

readonly RUN_ID='c8e41d73'
readonly PACKAGE_ID='4f2a9b61'
readonly CREDENTIAL_PATH='/Users/siyixuan/codes-2/wg-mix-ebpf/credientials/192.168.10.82'
readonly EXPECTED_OUTPUT_PREFIX="/private/tmp/wg-mix-b82-v6-${RUN_ID}-${PACKAGE_ID}-"

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
PROVISION_RESULT=''

fail() {
  printf 'B82_V6_CONTROLLER_STOP mode=%s reason=%s rc=%s; no automatic cleanup\n' \
    "${MODE:-unparsed}" "$1" "${2:-125}" >&2
  exit "${2:-125}"
}

usage() {
  printf '%s\n' \
    "usage: $0 {plan|preflight|prepare|provision-apply|fresh-plan|fresh-run|fresh-restore|veth-plan|veth-run|veth-restore|routed-plan|routed-run|routed-restore|realnic-plan|realnic-run|realnic-restore}" \
    '  --manifest ABSOLUTE_PACKAGE_MANIFEST --manifest-sha256 64-lowercase-hex' \
    "  --credential-path ${CREDENTIAL_PATH}" \
    '  --approved-plan {none|ABSOLUTE_LOCAL_FILE} --approved-plan-sha256 {none|64-lowercase-hex}' >&2
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
  (($# >= 1)) || { usage; return 64; }
  MODE="$1"
  shift
  case "${MODE}" in
    plan | preflight | prepare | provision-apply | \
      fresh-plan | fresh-run | fresh-restore | \
      veth-plan | veth-run | veth-restore | routed-plan | routed-run | routed-restore | \
      realnic-plan | realnic-run | realnic-restore) ;;
    *) usage; return 64 ;;
  esac
  while (($# > 0)); do
    (($# >= 2)) || { usage; return 64; }
    case "$1" in
      --manifest) MANIFEST="$2" ;;
      --manifest-sha256) MANIFEST_SHA256="$2" ;;
      --credential-path) SUPPLIED_CREDENTIAL_PATH="$2" ;;
      --approved-plan) APPROVED_PLAN="$2" ;;
      --approved-plan-sha256) APPROVED_PLAN_SHA256="$2" ;;
      *) usage; return 64 ;;
    esac
    shift 2
  done
  [[ "${MANIFEST}" == /* && "${SUPPLIED_CREDENTIAL_PATH}" == "${CREDENTIAL_PATH}" ]] || return 65
  valid_sha256 "${MANIFEST_SHA256}" || return 65
  case "${MODE}" in
    realnic-run)
      [[ "${APPROVED_PLAN}" == /* ]] && valid_sha256 "${APPROVED_PLAN_SHA256}" || return 65
      ;;
    realnic-restore)
      [[ "${APPROVED_PLAN}" == 'none' ]] && valid_sha256 "${APPROVED_PLAN_SHA256}" || return 65
      ;;
    plan)
      if [[ "${APPROVED_PLAN}" != 'none' || "${APPROVED_PLAN_SHA256}" != 'none' ]]; then
        [[ "${APPROVED_PLAN}" == /* ]] && valid_sha256 "${APPROVED_PLAN_SHA256}" || return 65
      fi
      ;;
    *) [[ "${APPROVED_PLAN}" == 'none' && "${APPROVED_PLAN_SHA256}" == 'none' ]] || return 65 ;;
  esac
}

read_manifest_field() {
  local expected="$1" destination="$2" key value extra
  IFS=$'\t' read -r key value extra <&3 || return 65
  [[ "${key}" == "${expected}" && -n "${value}" && -z "${extra}" &&
    "${value}" != *$'\t'* && "${value}" != *$'\n'* ]] || return 65
  printf -v "${destination}" '%s' "${value}"
}

load_manifest() {
  local unexpected
  exec 3<"${MANIFEST}" || return 66
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
    read_manifest_field test_routed_veth_harness_static_py_sha256 TEST_ROUTED_VETH_HARNESS_STATIC_PY_SHA256 || {
      exec 3<&-
      return 65
    }
  if IFS= read -r unexpected <&3; then
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
  local isolated_count missing_rc actual_roots
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
  [[ "$(git_history "${history_repository}" rev-list --parents --objects --missing=print \
    "${INTEGRATION_COMMIT}" | sha256_stream)" == "${HISTORY_OBJECTS_SHA256}" ]] || return 76
}

verify_identity() {
  local path="$1" blob="$2" sha="$3" actual_blob actual_sha mapped_blob
  [[ ("${path}" =~ ^scripts/realhost-b82-(c8e41d73|acceptance-v1|routed-veth-v1)/[A-Za-z0-9_.-]+$ ||
      "${path}" == 'scripts/provision-ubuntu-test-host.sh') &&
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
  [[ "${FORMAT}" == 'wg-mix-ebpf-b82-v6-package-v4' &&
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
  canonical_repository="$(CDPATH= cd -- "${LOCAL_REPOSITORY}" && pwd -P)" || return 66
  canonical_package="$(CDPATH= cd -- "${LOCAL_PACKAGE_DIR}" && pwd -P)" || return 66
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

verify_local_approved_plan() {
  local canonical shape size
  [[ "${APPROVED_PLAN}" == /* && -f "${APPROVED_PLAN}" && ! -L "${APPROVED_PLAN}" ]] || return 66
  canonical="$(CDPATH= cd -- "$(/usr/bin/dirname -- "${APPROVED_PLAN}")" && pwd -P)/${APPROVED_PLAN##*/}" || return 66
  [[ "${canonical}" == "${APPROVED_PLAN}" ]] || return 66
  if [[ "$(/usr/bin/uname -s)" == 'Darwin' ]]; then
    shape="$(/usr/bin/stat -f '%Lp:%l:%HT' -- "${APPROVED_PLAN}")" || return 66
    size="$(/usr/bin/stat -f '%z' -- "${APPROVED_PLAN}")" || return 66
    [[ "${shape}" == '600:1:Regular File' ]] || return 66
  else
    shape="$(/usr/bin/stat -Lc '%a:%h:%F' -- "${APPROVED_PLAN}")" || return 66
    size="$(/usr/bin/stat -Lc '%s' -- "${APPROVED_PLAN}")" || return 66
    [[ "${shape}" == '600:1:regular file' ]] || return 66
  fi
  [[ "${size}" =~ ^[1-9][0-9]*$ &&
    "${size}" -le 16777216 && "$(sha256_file "${APPROVED_PLAN}")" == "${APPROVED_PLAN_SHA256}" ]]
}

transport() {
  local action="$1" operation="$2"
  /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C \
    /usr/bin/expect "${LOCAL_REPOSITORY}/${LOCKED_TRANSPORT_EXP_PATH}" \
    --manifest "${MANIFEST}" --manifest-sha256 "${MANIFEST_SHA256}" \
    --credential-path "${SUPPLIED_CREDENTIAL_PATH}" --action "${action}" \
    --operation "${operation}" --approved-plan "${APPROVED_PLAN}" \
    --approved-plan-sha256 "${APPROVED_PLAN_SHA256}"
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
  root-fresh-verifier-gate.sh test-hermetic-fresh-verifier-gate.sh
  test_fresh_verifier_gate_static.py realnic_acceptance.py
  test_realnic_acceptance.py test_realnic_acceptance_static.py
)
readonly -a BOOTSTRAP_CREATE_OPERATIONS=(
  bootstrap-absent bootstrap-not-symlink bootstrap-create bootstrap-root-readlink bootstrap-root-stat
  bootstrap-install-provisioner bootstrap-install-stager
)
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
    printf 'B82_V6_REALNIC_APPROVAL_REQUIRED local_plan=explicit approved_plan_sha256=explicit automatic_approval=0\n'
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

verify_remote_package() {
  local name
  for name in "${PACKAGE_NAMES[@]}"; do
    run_operation execute "verify-sha-${name}" || return $?
    run_operation execute "verify-stat-${name}" || return $?
  done
}

verify_provisioner() {
  local operation
  for operation in "${PROVISIONER_VERIFY_OPERATIONS[@]}"; do
    run_operation execute "${operation}" || return $?
  done
}

verify_stager() {
  local operation
  for operation in "${STAGER_VERIFY_OPERATIONS[@]}"; do
    run_operation execute "${operation}" || return $?
  done
}

run_provision_check() {
  local output rc started finished marker
  PROVISION_RESULT=''
  started="$(/bin/date -u '+%Y-%m-%dT%H:%M:%SZ')" || return 70
  printf 'B82_V6_CONTROLLER_EVENT utc=%s event=start mode=%s operation=provision-check target=%s\n' \
    "${started}" "${MODE}" "${TARGET_HOST}"
  output="$(transport execute provision-check 2>&1)"
  rc=$?
  printf '%s\n' "${output}"
  finished="$(/bin/date -u '+%Y-%m-%dT%H:%M:%SZ')" || return 70
  printf 'B82_V6_CONTROLLER_EVENT utc=%s event=finish mode=%s operation=provision-check target=%s rc=%s\n' \
    "${finished}" "${MODE}" "${TARGET_HOST}" "${rc}"
  ((rc == 0)) || return "${rc}"
  marker="$(printf '%s\n' "${output}" | /usr/bin/awk '
    /^B82_V6_PROVISION_AUDIT operation=provision-check child_rc=0 plan=valid missing_set=(none|initial|iperf3) next_state=(POSTFLIGHT|AWAIT_APPLY)$/ {
      if (++seen > 1) exit 65
      value = $0
    }
    END { if (seen != 1) exit 65; print value }
  ')" || return 78
  case "${marker}" in
    *' missing_set=none next_state=POSTFLIGHT') PROVISION_RESULT='none' ;;
    *' missing_set=initial next_state=AWAIT_APPLY') PROVISION_RESULT='initial' ;;
    *' missing_set=iperf3 next_state=AWAIT_APPLY') PROVISION_RESULT='iperf3' ;;
    *) return 78 ;;
  esac
}

execute_postflight() {
  local operation
  verify_remote_package || return $?
  for operation in "${POSTFLIGHT_OPERATIONS[@]}" controller-shellcheck hermetic-matrix hermetic-fresh; do
    run_operation execute "${operation}" || return $?
  done
  verify_stager || return $?
  for operation in "${STAGE_OPERATIONS[@]}"; do
    run_operation execute "${operation}" || return $?
  done
  printf 'B82_V6_CONTROLLER_POSTFLIGHT_COMPLETE state=POSTFLIGHT\n'
}

execute_prepare() {
  local operation name
  for operation in "${BASE_IDENTITY_OPERATIONS[@]}"; do
    run_operation execute "${operation}" || return $?
  done
  run_prepare_new_stale_gate execute || return $?
  run_operation execute package-parent-stat || return $?
  run_operation execute package-mkdir || return $?
  for name in "${PACKAGE_NAMES[@]}"; do
    run_operation execute "scp-${name}" || return $?
    run_operation execute "verify-sha-${name}" || return $?
    run_operation execute "verify-stat-${name}" || return $?
  done
  for operation in "${BOOTSTRAP_CREATE_OPERATIONS[@]}"; do
    run_operation execute "${operation}" || return $?
  done
  state_transition PACKAGE_BOUND BOOTSTRAP_ONLY
  verify_provisioner || return $?
  state_transition BOOTSTRAP_ONLY PROVISION_CHECK
  run_provision_check || return $?
  case "${PROVISION_RESULT}" in
    none)
      state_transition PROVISION_CHECK POSTFLIGHT
      execute_postflight
      ;;
    initial | iperf3)
      state_transition PROVISION_CHECK AWAIT_APPLY
      printf 'B82_V6_PROVISION_AWAIT_APPLY missing_set=%s explicit_mode=provision-apply automatic_apply=0\n' \
        "${PROVISION_RESULT}"
      ;;
    *) return 78 ;;
  esac
}

execute_provision_apply() {
  local operation expected_missing
  for operation in "${BASE_IDENTITY_OPERATIONS[@]}" "${BOOTSTRAP_ROOT_VERIFY_OPERATIONS[@]}"; do
    run_operation execute "${operation}" || return $?
  done
  verify_remote_package || return $?
  verify_provisioner || return $?
  state_transition BOOTSTRAP_ONLY PROVISION_CHECK
  run_provision_check || return $?
  if [[ "${PROVISION_RESULT}" == 'none' ]]; then
    state_transition PROVISION_CHECK POSTFLIGHT
    execute_postflight
    return $?
  fi
  [[ "${PROVISION_RESULT}" == 'initial' || "${PROVISION_RESULT}" == 'iperf3' ]] || return 78
  expected_missing="${PROVISION_RESULT}"
  state_transition PROVISION_CHECK AWAIT_APPLY
  state_transition AWAIT_APPLY PROVISION_APPLY
  verify_provisioner || return $?
  run_operation execute provision-apply || return $?
  verify_provisioner || return $?
  run_provision_check || return $?
  [[ "${PROVISION_RESULT}" == 'none' ]] || {
    printf 'B82_V6_PROVISION_POSTCHECK_STOP expected_before=%s actual_after=%s\n' \
      "${expected_missing}" "${PROVISION_RESULT}" >&2
    return 78
  }
  state_transition PROVISION_APPLY POSTFLIGHT
  execute_postflight
}

execute_realnic_run() {
  local operation
  verify_local_approved_plan || return $?
  for operation in scp-realnic-approved-plan verify-sha-realnic-approved-plan \
    verify-stat-realnic-approved-plan stage-realnic-plan-snapshot realnic-run; do
    run_operation execute "${operation}" || return $?
  done
}

execute_realnic_restore() {
  run_operation execute stage-realnic-plan-verify || return $?
  run_operation execute realnic-restore
}

main() {
  parse_arguments "$@" || fail 'arguments' $?
  verify_manifest_contract || fail 'manifest-contract' $?
  case "${MODE}" in
    veth-plan | veth-run | veth-restore)
      [[ "${WG_STATE}" == absent ]] || fail 'veth-wireguard-state' 65
      ;;
  esac
  case "${MODE}" in
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
      run_operation execute realnic-plan || fail 'realnic-plan-operation' $?
      ;;
    realnic-run)
      execute_realnic_run || fail 'realnic-run-operation' $?
      ;;
    realnic-restore)
      execute_realnic_restore || fail 'realnic-restore-operation' $?
      ;;
  esac
}

main "$@"
