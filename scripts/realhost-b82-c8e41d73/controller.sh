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
RESTORE_CELL='none'

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
PREPARE_STAGE_ROOT_SH_PATH=''
PREPARE_STAGE_ROOT_SH_BLOB=''
PREPARE_STAGE_ROOT_SH_SHA256=''

fail() {
  printf 'B82_V6_CONTROLLER_STOP mode=%s reason=%s rc=%s; no automatic cleanup\n' \
    "${MODE:-unparsed}" "$1" "${2:-125}" >&2
  exit "${2:-125}"
}

usage() {
  printf '%s\n' \
    "usage: $0 {plan|preflight|prepare|matrix-plan|run|restore}" \
    '  --manifest ABSOLUTE_PACKAGE_MANIFEST --manifest-sha256 64-lowercase-hex' \
    "  --credential-path ${CREDENTIAL_PATH}" \
    '  --restore-cell {none|tcx|original|all-on|all-off|tx-path|rx-path|mtu1492|mtu1500|soak}' >&2
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
    plan | preflight | prepare | matrix-plan | run | restore) ;;
    *) usage; return 64 ;;
  esac
  while (($# > 0)); do
    (($# >= 2)) || { usage; return 64; }
    case "$1" in
      --manifest) MANIFEST="$2" ;;
      --manifest-sha256) MANIFEST_SHA256="$2" ;;
      --credential-path) SUPPLIED_CREDENTIAL_PATH="$2" ;;
      --restore-cell) RESTORE_CELL="$2" ;;
      *) usage; return 64 ;;
    esac
    shift 2
  done
  [[ "${MANIFEST}" == /* && "${SUPPLIED_CREDENTIAL_PATH}" == "${CREDENTIAL_PATH}" ]] || return 65
  valid_sha256 "${MANIFEST_SHA256}" || return 65
  case "${MODE}:${RESTORE_CELL}" in
    plan:none | preflight:none | prepare:none | matrix-plan:none | run:none | \
      restore:tcx | restore:original | restore:all-on | restore:all-off | \
      restore:tx-path | restore:rx-path | restore:mtu1492 | restore:mtu1500 | restore:soak) ;;
    *) return 65 ;;
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
    read_manifest_field prepare_stage_root_sh_path PREPARE_STAGE_ROOT_SH_PATH &&
    read_manifest_field prepare_stage_root_sh_blob PREPARE_STAGE_ROOT_SH_BLOB &&
    read_manifest_field prepare_stage_root_sh_sha256 PREPARE_STAGE_ROOT_SH_SHA256 || {
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
  [[ "${path}" =~ ^scripts/realhost-b82-c8e41d73/[A-Za-z0-9_.-]+$ &&
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
  [[ "${FORMAT}" == 'wg-mix-ebpf-b82-v6-package-v1' &&
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
    "${SESSION_SECONDS}" == '300' ]] || return 65
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
    verify_identity "${PREPARE_STAGE_ROOT_SH_PATH}" "${PREPARE_STAGE_ROOT_SH_BLOB}" "${PREPARE_STAGE_ROOT_SH_SHA256}" || return $?

  for name in bind-final-package.sh controller.sh root-matrix-n-r.sh check-realhost-iperf.py \
    test-hermetic-matrix.sh test_matrix_static.py prepare-stage-root.sh; do
    [[ -f "${LOCAL_PACKAGE_DIR}/${name}" && ! -L "${LOCAL_PACKAGE_DIR}/${name}" ]] || return 66
    case "${name}" in
      bind-final-package.sh) sha="${BIND_FINAL_PACKAGE_SH_SHA256}" ;;
      controller.sh) sha="${CONTROLLER_SH_SHA256}" ;;
      root-matrix-n-r.sh) sha="${ROOT_MATRIX_N_R_SH_SHA256}" ;;
      check-realhost-iperf.py) sha="${CHECK_REALHOST_IPERF_PY_SHA256}" ;;
      test-hermetic-matrix.sh) sha="${TEST_HERMETIC_MATRIX_SH_SHA256}" ;;
      test_matrix_static.py) sha="${TEST_MATRIX_STATIC_PY_SHA256}" ;;
      prepare-stage-root.sh) sha="${PREPARE_STAGE_ROOT_SH_SHA256}" ;;
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

transport() {
  local action="$1" operation="$2"
  /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C \
    /usr/bin/expect "${LOCAL_REPOSITORY}/${LOCKED_TRANSPORT_EXP_PATH}" \
    --manifest "${MANIFEST}" --manifest-sha256 "${MANIFEST_SHA256}" \
    --credential-path "${SUPPLIED_CREDENTIAL_PATH}" --action "${action}" \
    --operation "${operation}"
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

readonly -a PREFLIGHT_OPERATIONS=(
  identity-hostname identity-kernel identity-machine identity-netns identity-interface
  identity-driver identity-wg-interfaces
  tool-go tool-clang tool-llvm tool-bpftool tool-make tool-gcc tool-iperf3
  tool-shellcheck tool-jq tool-wireguard tool-ethtool tool-tc tool-ip
  kernel-btf kernel-bpffs kernel-headers
)
readonly -a PACKAGE_NAMES=(
  source-4f2a9b61.bundle package-manifest.v1 bind-final-package.sh controller.sh prepare-stage-root.sh
  root-matrix-n-r.sh check-realhost-iperf.py test-hermetic-matrix.sh test_matrix_static.py
)
readonly -a BOOTSTRAP_OPERATIONS=(
  bootstrap-absent bootstrap-not-symlink bootstrap-create bootstrap-root-readlink bootstrap-root-stat
  bootstrap-install-stager
  bootstrap-stager-readlink bootstrap-stager-sha bootstrap-stager-stat
)

plan_all() {
  local operation name
  for operation in "${PREFLIGHT_OPERATIONS[@]}" package-parent-stat package-mkdir; do
    run_operation plan "${operation}" || return $?
  done
  for name in "${PACKAGE_NAMES[@]}"; do
    run_operation plan "scp-${name}" || return $?
    run_operation plan "verify-sha-${name}" || return $?
    run_operation plan "verify-stat-${name}" || return $?
  done
  for operation in controller-shellcheck hermetic-matrix "${BOOTSTRAP_OPERATIONS[@]}" stage-plan stage-run; do
    run_operation plan "${operation}" || return $?
  done
  if [[ "${WG_STATE}" == 'absent' ]]; then
    printf 'B82_V6_MATRIX_BLOCKED reason=wireguard-topology-absent wg_active_scoped=not-covered pass=0\n'
    printf 'B82_V6_CONTROLLER_PLAN_COMPLETE credential_read=0 network_operations=0 mutations=0 matrix_blocked=1\n'
    return 0
  fi
  for operation in matrix-plan matrix-run; do
    run_operation plan "${operation}" || return $?
  done
  for operation in tcx original all-on all-off tx-path rx-path mtu1492 mtu1500 soak; do
    run_operation plan "matrix-restore-${operation}" || return $?
  done
  printf 'B82_V6_CONTROLLER_PLAN_COMPLETE credential_read=0 network_operations=0 mutations=0\n'
}

require_bound_wireguard() {
  [[ "${WG_STATE}" == 'bound' ]] || fail 'wireguard-topology-absent' 78
}

execute_preflight() {
  local operation
  for operation in "${PREFLIGHT_OPERATIONS[@]}"; do
    run_operation execute "${operation}" || return $?
  done
}

execute_prepare() {
  local operation name
  execute_preflight || return $?
  run_operation execute package-parent-stat || return $?
  run_operation execute package-mkdir || return $?
  for name in "${PACKAGE_NAMES[@]}"; do
    run_operation execute "scp-${name}" || return $?
    run_operation execute "verify-sha-${name}" || return $?
    run_operation execute "verify-stat-${name}" || return $?
  done
  for operation in controller-shellcheck hermetic-matrix "${BOOTSTRAP_OPERATIONS[@]}" stage-plan stage-run; do
    run_operation execute "${operation}" || return $?
  done
}

main() {
  parse_arguments "$@" || fail 'arguments' $?
  verify_manifest_contract || fail 'manifest-contract' $?
  case "${MODE}" in
    plan) plan_all || fail 'plan-operation' $? ;;
    preflight) execute_preflight || fail 'preflight-operation' $? ;;
    prepare) execute_prepare || fail 'prepare-operation' $? ;;
    matrix-plan)
      require_bound_wireguard
      run_operation execute matrix-plan || fail 'matrix-plan-operation' $?
      ;;
    run)
      require_bound_wireguard
      run_operation execute matrix-run || fail 'matrix-run-operation' $?
      ;;
    restore)
      require_bound_wireguard
      run_operation execute "matrix-restore-${RESTORE_CELL}" || fail 'matrix-restore-operation' $?
      ;;
  esac
}

main "$@"
