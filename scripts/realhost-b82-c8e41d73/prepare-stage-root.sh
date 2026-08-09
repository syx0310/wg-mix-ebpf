#!/usr/bin/env bash
set -u
set -o pipefail
umask 077

readonly RUN_ID='c8e41d73'
readonly PACKAGE_ID='4f2a9b61'
readonly EXPECTED_REMOTE_PACKAGE="/home/siyixuan/wg-mix-ebpf-test/unpriv-${PACKAGE_ID}"
readonly BOOTSTRAP_ROOT="/run/wg-mix-ebpf-source-bootstrap-${RUN_ID}"
readonly EXPECTED_SELF="${BOOTSTRAP_ROOT}/prepare-stage-root.sh"
readonly USER_MANIFEST="${EXPECTED_REMOTE_PACKAGE}/package-manifest.v1"
readonly USER_BUNDLE="${EXPECTED_REMOTE_PACKAGE}/source-${PACKAGE_ID}.bundle"
readonly SNAPSHOT_MANIFEST="${BOOTSTRAP_ROOT}/package-manifest.v1"
readonly SNAPSHOT_BUNDLE="${BOOTSTRAP_ROOT}/source-${PACKAGE_ID}.bundle"
readonly STAGES_ROOT='/run/wg-mix-ebpf-source-stages'
readonly STAGE_ROOT="${STAGES_ROOT}/${RUN_ID}"
readonly EXPECTED_SOURCE="${STAGE_ROOT}/source"
readonly BINDING_MARKER="${STAGE_ROOT}/binding.v1"
readonly MODULE_LEASE_LOCK="${STAGE_ROOT}/checksum-module-lease.v1.lock"
readonly MODULE_LEASE_HELPER_RELATIVE="scripts/realhost-b82-${RUN_ID}/checksum-module-lease.sh"
readonly EXPECTED_HOSTNAME='ubuntu-2604-test'
readonly EXPECTED_KERNEL='7.0.0-28-generic'
readonly EXPECTED_MACHINE_ID='9db3fb717cc74974b2a6b243d67f67b9'

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
PREPARE_PATH=''
PREPARE_BLOB=''
PREPARE_SHA256=''
PROVISION_PATH=''
PROVISION_BLOB=''
PROVISION_SHA256=''

fail() {
  printf 'B82_V6_STAGE_STOP mode=%s reason=%s rc=%s snapshot=%s stage=%s; retained=1\n' \
    "${MODE:-unparsed}" "$1" "${2:-125}" "${BOOTSTRAP_ROOT}" "${STAGE_ROOT}" >&2
  exit "${2:-125}"
}

usage() {
  printf 'usage: %s {snapshot-plan|snapshot|plan|run} --manifest ABSOLUTE --manifest-sha256 64-lowercase-hex\n' "$0" >&2
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
  (($# == 5)) || { usage; return 64; }
  MODE="$1"
  shift
  case "${MODE}" in
    snapshot-plan | snapshot | plan | run) ;;
    *) return 64 ;;
  esac
  [[ "$1" == '--manifest' && "$3" == '--manifest-sha256' ]] || return 64
  MANIFEST="$2"
  MANIFEST_SHA256="$4"
  [[ "${MANIFEST}" == /* ]] || return 65
  valid_sha256 "${MANIFEST_SHA256}" || return 65
}

read_manifest_field() {
  local expected="$1" destination="$2" key value extra
  IFS=$'\t' read -r key value extra <&3 || return 65
  [[ "${key}" == "${expected}" && -n "${value}" && -z "${extra}" ]] || return 65
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
    read_manifest_field prepare_stage_root_sh_path PREPARE_PATH &&
    read_manifest_field prepare_stage_root_sh_blob PREPARE_BLOB &&
    read_manifest_field prepare_stage_root_sh_sha256 PREPARE_SHA256 &&
    read_manifest_field provision_ubuntu_test_host_sh_path PROVISION_PATH &&
    read_manifest_field provision_ubuntu_test_host_sh_blob PROVISION_BLOB &&
    read_manifest_field provision_ubuntu_test_host_sh_sha256 PROVISION_SHA256 || {
      exec 3<&-
      return 65
    }
  if IFS= read -r unexpected <&3; then
    exec 3<&-
    return 65
  fi
  exec 3<&-
}

validate_manifest() {
  load_manifest || return $?
  [[ "${FORMAT}" == 'wg-mix-ebpf-b82-v6-package-v1' &&
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
    "${SOAK_SECONDS}" == '3600' && "${SESSION_SECONDS}" == '300' ]] || return 65
  valid_sha256 "${BUNDLE_SHA256}" && valid_sha256 "${ROOT_MATRIX_SHA256}" &&
    valid_sha256 "${CHECKER_SHA256}" && valid_sha256 "${HERMETIC_SHA256}" &&
    valid_sha256 "${STATIC_SHA256}" && valid_sha256 "${PREPARE_SHA256}" &&
    valid_sha256 "${PROVISION_SHA256}" || return 65
  [[ "${ROOT_MATRIX_BLOB}" =~ ^[0-9a-f]{40}$ && "${CHECKER_BLOB}" =~ ^[0-9a-f]{40}$ &&
    "${HERMETIC_BLOB}" =~ ^[0-9a-f]{40}$ && "${STATIC_BLOB}" =~ ^[0-9a-f]{40}$ &&
    "${PREPARE_BLOB}" =~ ^[0-9a-f]{40}$ && "${PROVISION_BLOB}" =~ ^[0-9a-f]{40}$ &&
    -n "${IGNORED}" ]] || return 65
  [[ "${ROOT_MATRIX_PATH}" == "scripts/realhost-b82-${RUN_ID}/root-matrix-n-r.sh" &&
    "${CHECKER_PATH}" == "scripts/realhost-b82-${RUN_ID}/check-realhost-iperf.py" &&
    "${HERMETIC_PATH}" == "scripts/realhost-b82-${RUN_ID}/test-hermetic-matrix.sh" &&
    "${STATIC_PATH}" == "scripts/realhost-b82-${RUN_ID}/test_matrix_static.py" &&
    "${PREPARE_PATH}" == "scripts/realhost-b82-${RUN_ID}/prepare-stage-root.sh" &&
    "${PROVISION_PATH}" == 'scripts/provision-ubuntu-test-host.sh' ]] || return 65
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
    "${EXPECTED_SOURCE}/${MODULE_LEASE_HELPER_RELATIVE}" \
    "${EXPECTED_SOURCE}/${PROVISION_PATH}"
  plan_command S7 /usr/bin/shellcheck --norc --shell=bash -- \
    "${EXPECTED_SOURCE}/${ROOT_MATRIX_PATH}" "${EXPECTED_SOURCE}/${HERMETIC_PATH}" \
    "${EXPECTED_SOURCE}/${PREPARE_PATH}" "${EXPECTED_SOURCE}/${MODULE_LEASE_HELPER_RELATIVE}" \
    "${EXPECTED_SOURCE}/${PROVISION_PATH}"
  plan_command S8 shell-builtin noclobber-write "${BINDING_MARKER}"
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

write_binding_marker() {
  (set -o noclobber
    printf '%s\n' \
      'format=wg-mix-ebpf-b82-v6-stage-binding-v1' \
      "run_id=${RUN_ID}" "package_id=${PACKAGE_ID}" \
      "integration_ref=${INTEGRATION_REF}" "integration_commit=${INTEGRATION_COMMIT}" \
      "bundle_sha256=${BUNDLE_SHA256}" "manifest_sha256=${MANIFEST_SHA256}" \
      "wg_state=${WG_STATE}" "module_lease_lock=${MODULE_LEASE_LOCK}" >"${BINDING_MARKER}")
}

require_module_lease_lock() {
  [[ -f "${MODULE_LEASE_LOCK}" && ! -L "${MODULE_LEASE_LOCK}" ]] || return 79
  [[ "$(/usr/bin/stat -Lc '%U:%G:%a:%h:%F' -- "${MODULE_LEASE_LOCK}")" == \
    'root:root:600:1:regular file' ]]
}

run_stage() {
  local bundle="${SNAPSHOT_BUNDLE}" branch="${INTEGRATION_REF#refs/heads/}"
  local parent_shape stage_head stage_status

  if [[ -e "${STAGES_ROOT}" || -L "${STAGES_ROOT}" ]]; then
    [[ -d "${STAGES_ROOT}" && ! -L "${STAGES_ROOT}" ]] || fail 'stages-root-shape' 79
    parent_shape="$(/usr/bin/stat -Lc '%U:%G:%a:%F' -- "${STAGES_ROOT}")" || fail 'stages-root-stat'
    [[ "${parent_shape}" == 'root:root:700:directory' ]] || fail 'stages-root-metadata' 79
  else
    run_step S2 /usr/bin/mkdir --mode=0700 -- "${STAGES_ROOT}" || fail 'stages-root-create' $?
  fi
  [[ ! -e "${STAGE_ROOT}" && ! -L "${STAGE_ROOT}" ]] || fail 'stage-exists' 73
  run_step S3 /usr/bin/mkdir --mode=0700 -- "${STAGE_ROOT}" || fail 'stage-create' $?
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
  stage_head="$(git_stage -C "${EXPECTED_SOURCE}" rev-parse HEAD)" || fail 'stage-head'
  [[ "${stage_head}" == "${INTEGRATION_COMMIT}" ]] || fail 'stage-head-mismatch' 79
  [[ "$(sha256_file "${EXPECTED_SOURCE}/${ROOT_MATRIX_PATH}")" == "${ROOT_MATRIX_SHA256}" &&
    "$(sha256_file "${EXPECTED_SOURCE}/${CHECKER_PATH}")" == "${CHECKER_SHA256}" &&
    "$(sha256_file "${EXPECTED_SOURCE}/${HERMETIC_PATH}")" == "${HERMETIC_SHA256}" &&
    "$(sha256_file "${EXPECTED_SOURCE}/${STATIC_PATH}")" == "${STATIC_SHA256}" &&
    "$(sha256_file "${EXPECTED_SOURCE}/${PREPARE_PATH}")" == "${PREPARE_SHA256}" &&
    "$(sha256_file "${EXPECTED_SOURCE}/${PROVISION_PATH}")" == "${PROVISION_SHA256}" ]] ||
    fail 'staged-script-hash' 79
  run_step S6 /bin/bash -n "${EXPECTED_SOURCE}/${ROOT_MATRIX_PATH}" \
    "${EXPECTED_SOURCE}/${HERMETIC_PATH}" "${EXPECTED_SOURCE}/${PREPARE_PATH}" \
    "${EXPECTED_SOURCE}/${MODULE_LEASE_HELPER_RELATIVE}" \
    "${EXPECTED_SOURCE}/${PROVISION_PATH}" || fail 'bash-syntax' $?
  run_step S7 /usr/bin/shellcheck --norc --shell=bash -- \
    "${EXPECTED_SOURCE}/${ROOT_MATRIX_PATH}" "${EXPECTED_SOURCE}/${HERMETIC_PATH}" \
    "${EXPECTED_SOURCE}/${PREPARE_PATH}" "${EXPECTED_SOURCE}/${MODULE_LEASE_HELPER_RELATIVE}" \
    "${EXPECTED_SOURCE}/${PROVISION_PATH}" || fail 'shellcheck' $?
  stage_status="$(git_stage -C "${EXPECTED_SOURCE}" status --porcelain=v1 --untracked-files=all)" || fail 'stage-status'
  [[ -z "${stage_status}" ]] || fail 'stage-dirty' 79
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
  esac
}

main "$@"
