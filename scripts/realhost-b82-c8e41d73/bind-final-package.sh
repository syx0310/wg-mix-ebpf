#!/usr/bin/env bash
set -u
set -o pipefail
umask 077

readonly RUN_ID='c8e41d73'
readonly PACKAGE_ID='4f2a9b61'
readonly REMOTE_PACKAGE_DIR="/home/siyixuan/wg-mix-ebpf-test/unpriv-${PACKAGE_ID}"
readonly REMOTE_SOURCE="/run/wg-mix-ebpf-source-stages/${RUN_ID}/source"
readonly EXPECTED_OUTPUT_PREFIX="/private/tmp/wg-mix-b82-v6-${RUN_ID}-${PACKAGE_ID}-"
SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)" || exit 70
readonly SCRIPT_DIR
readonly REPOSITORY_PATH_FROM_ROOT="scripts/realhost-b82-${RUN_ID}"
readonly REALNIC_PATH_FROM_ROOT='scripts/realhost-b82-acceptance-v1'
readonly ROUTED_PATH_FROM_ROOT='scripts/realhost-b82-routed-veth-v1'
readonly PHYSICAL_INTERFACE_LOCK='/run/wg-mix-ebpf-realnic-physical-interface.v1.lock'

MODE=''
REPOSITORY=''
SOURCE_REF=''
COMMIT=''
WG_STATE=''
WG_INTERFACE=''
WG_LOCAL_ADDRESS=''
WG_PEER_ADDRESS=''
OUTPUT_DIR=''
HISTORY_COMMIT_COUNT=''
HISTORY_ROOTS_SHA256=''
HISTORY_OBJECTS_SHA256=''

fail() {
  printf 'B82_V6_BIND_STOP reason=%s rc=%s; retained=1\n' "$1" "${2:-125}" >&2
  exit "${2:-125}"
}

usage() {
  printf '%s\n' \
    "usage: $0 {plan|bind} --repository ABSOLUTE_WORKTREE" \
    '  --source-ref refs/heads/NAME --commit 40-lowercase-hex' \
    '  --wg-state {bound|absent} --wg-interface VALUE' \
    '  --wg-local-address VALUE --wg-peer-address VALUE' \
    "  --output-dir ${EXPECTED_OUTPUT_PREFIX}<first-12-commit-hex>" >&2
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

valid_commit() {
  local value="$1"
  [[ "${value}" =~ ^[0-9a-f]{40}$ &&
    ! "${value}" =~ ^0{40}$ && ! "${value}" =~ ^f{40}$ ]]
}

valid_sha256() {
  local value="$1"
  [[ "${value}" =~ ^[0-9a-f]{64}$ &&
    ! "${value}" =~ ^0{64}$ && ! "${value}" =~ ^f{64}$ ]]
}

valid_source_ref() {
  local value="$1"
  [[ "${value}" =~ ^refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]{0,180}$ &&
    "${value}" != *'..'* && "${value}" != *'//'*
  ]]
}

valid_interface_name() {
  local value="$1"
  [[ "${value}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$ &&
    "${value}" != '.' && "${value}" != '..' && "${value}" != 'ens33' &&
    "${value}" != 'wgc8e41a' && "${value}" != 'wgc8e41b' ]]
}

valid_unicast_ipv4() {
  local value="$1" first second third fourth extra octet number
  IFS=. read -r first second third fourth extra <<<"${value}"
  [[ -z "${extra}" && -n "${first}" && -n "${second}" &&
    -n "${third}" && -n "${fourth}" ]] || return 1
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
  [[ "${MODE}" == 'plan' || "${MODE}" == 'bind' ]] || { usage; return 64; }
  while (($# > 0)); do
    (($# >= 2)) || { usage; return 64; }
    case "$1" in
      --repository) REPOSITORY="$2" ;;
      --source-ref) SOURCE_REF="$2" ;;
      --commit) COMMIT="$2" ;;
      --wg-state) WG_STATE="$2" ;;
      --wg-interface) WG_INTERFACE="$2" ;;
      --wg-local-address) WG_LOCAL_ADDRESS="$2" ;;
      --wg-peer-address) WG_PEER_ADDRESS="$2" ;;
      --output-dir) OUTPUT_DIR="$2" ;;
      *) usage; return 64 ;;
    esac
    shift 2
  done
  [[ "${REPOSITORY}" == /* && "${OUTPUT_DIR}" == /* ]] || return 65
  valid_source_ref "${SOURCE_REF}" || return 65
  valid_commit "${COMMIT}" || return 65
  case "${WG_STATE}" in
    bound)
      valid_interface_name "${WG_INTERFACE}" || return 65
      valid_unicast_ipv4 "${WG_LOCAL_ADDRESS}" || return 65
      valid_unicast_ipv4 "${WG_PEER_ADDRESS}" || return 65
      [[ "${WG_LOCAL_ADDRESS}" != "${WG_PEER_ADDRESS}" ]] || return 65
      ;;
    absent)
      [[ "${WG_INTERFACE}" == 'absent' && "${WG_LOCAL_ADDRESS}" == 'absent' &&
        "${WG_PEER_ADDRESS}" == 'absent' ]] || return 65
      ;;
    *) return 65 ;;
  esac
  [[ "${OUTPUT_DIR}" == "${EXPECTED_OUTPUT_PREFIX}${COMMIT:0:12}" ]] || return 65
}

git_checked() {
  /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C \
    GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 \
    GIT_NO_REPLACE_OBJECTS=1 GIT_OPTIONAL_LOCKS=0 \
    /usr/bin/git --no-pager --no-replace-objects \
    -c core.attributesFile=/dev/null -c core.fsmonitor=false \
    -c core.hooksPath=/dev/null -C "${REPOSITORY}" "$@"
}

require_repository_contract() {
  local canonical_repository canonical_script_root actual_commit
  canonical_repository="$(CDPATH='' cd -- "${REPOSITORY}" && pwd -P)" || return 66
  [[ "${canonical_repository}" == "${REPOSITORY}" ]] || return 66
  canonical_script_root="${REPOSITORY}/${REPOSITORY_PATH_FROM_ROOT}"
  [[ "${SCRIPT_DIR}" == "${canonical_script_root}" ]] || return 66
  actual_commit="$(git_checked rev-parse --verify "${SOURCE_REF}^{commit}")" || return 66
  [[ "${actual_commit}" == "${COMMIT}" ]] || return 67
  git_checked cat-file -e "${COMMIT}^{commit}" || return 67
}

require_full_repository() {
  local shallow_state
  shallow_state="$(git_checked rev-parse --is-shallow-repository)" || return 66
  [[ "${shallow_state}" == 'false' ]] || return 76
}

readonly -a PACKAGE_PATHS=(
  "${REPOSITORY_PATH_FROM_ROOT}/root-matrix-n-r.sh"
  "${REPOSITORY_PATH_FROM_ROOT}/check-realhost-iperf.py"
  "${REPOSITORY_PATH_FROM_ROOT}/test-hermetic-matrix.sh"
  "${REPOSITORY_PATH_FROM_ROOT}/test_matrix_static.py"
  "${REPOSITORY_PATH_FROM_ROOT}/checksum-module-lease.sh"
  "${REPOSITORY_PATH_FROM_ROOT}/root-fresh-verifier-gate.sh"
  "${REPOSITORY_PATH_FROM_ROOT}/test-hermetic-fresh-verifier-gate.sh"
  "${REPOSITORY_PATH_FROM_ROOT}/test_fresh_verifier_gate_static.py"
  "${REPOSITORY_PATH_FROM_ROOT}/prepare-stage-root.sh"
  "${REALNIC_PATH_FROM_ROOT}/realnic_acceptance.py"
  "${REALNIC_PATH_FROM_ROOT}/test_realnic_acceptance.py"
  "${REALNIC_PATH_FROM_ROOT}/test_realnic_acceptance_static.py"
  "scripts/provision-ubuntu-test-host.sh"
)

# These privileged runners are consumed only from the root-owned staged Git
# tree.  They are manifest-bound, but deliberately are not copied into the
# user-owned flat transport package as a second executable authority.
readonly -a STAGED_IDENTITY_PATHS=(
  "${REPOSITORY_PATH_FROM_ROOT}/root-veth-n-r.sh"
  "${REPOSITORY_PATH_FROM_ROOT}/test-hermetic-veth-runner.sh"
  "${REPOSITORY_PATH_FROM_ROOT}/test_veth_runner_static.py"
  "${ROUTED_PATH_FROM_ROOT}/controller-seam.sh"
  "${ROUTED_PATH_FROM_ROOT}/root-routed-veth-n-r.sh"
  "${ROUTED_PATH_FROM_ROOT}/test-hermetic-routed-veth-harness.sh"
  "${ROUTED_PATH_FROM_ROOT}/test_routed_veth_harness_static.py"
)

readonly -a IDENTITY_PATHS=(
  "${REPOSITORY_PATH_FROM_ROOT}/bind-final-package.sh"
  "${REPOSITORY_PATH_FROM_ROOT}/controller.sh"
  "${REPOSITORY_PATH_FROM_ROOT}/locked-transport.exp"
  "${PACKAGE_PATHS[@]}"
  "${STAGED_IDENTITY_PATHS[@]}"
)

readonly -a TRANSFER_PATHS=(
  "${REPOSITORY_PATH_FROM_ROOT}/bind-final-package.sh"
  "${REPOSITORY_PATH_FROM_ROOT}/controller.sh"
  "${PACKAGE_PATHS[@]}"
)

path_key() {
  local name="${1##*/}"
  name="${name//-/_}"
  name="${name//./_}"
  printf '%s\n' "${name}"
}

require_committed_identity() {
  local path mapped_blob actual_blob committed_sha actual_sha
  for path in "${IDENTITY_PATHS[@]}"; do
    mapped_blob="$(git_checked rev-parse "${COMMIT}:${path}")" || return 68
    [[ "${mapped_blob}" =~ ^[0-9a-f]{40}$ ]] || return 68
    committed_sha="$(git_checked show "${COMMIT}:${path}" | sha256_stream)" || return 68
    valid_sha256 "${committed_sha}" || return 68
    if [[ "${path}" == "${REPOSITORY_PATH_FROM_ROOT}/bind-final-package.sh" ]]; then
      actual_blob="$(git_checked hash-object -- "${REPOSITORY}/${path}")" || return 68
      actual_sha="$(sha256_file "${REPOSITORY}/${path}")" || return 68
      [[ "${actual_blob}" == "${mapped_blob}" && "${actual_sha}" == "${committed_sha}" ]] || return 68
    fi
  done
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

plan_binding() {
  printf 'B82_V6_BIND_PLAN run_id=%s package_id=%s source_ref=%s commit=%s\n' \
    "${RUN_ID}" "${PACKAGE_ID}" "${SOURCE_REF}" "${COMMIT}"
  printf 'output_dir=%s remote_package_dir=%s remote_source=%s\n' \
    "${OUTPUT_DIR}" "${REMOTE_PACKAGE_DIR}" "${REMOTE_SOURCE}"
  printf 'wg_state=%s wg_interface=%s wg_local_address=%s wg_peer_address=%s\n' \
    "${WG_STATE}" "${WG_INTERFACE}" "${WG_LOCAL_ADDRESS}" "${WG_PEER_ADDRESS}"
  printf '%s\n' \
    'physical_nic_forward_authority=realnic-acceptance-v1 legacy_matrix_mode=retired'
  printf 'bundle_argv=/usr/bin/git bundle create %s %s\n' \
    "${OUTPUT_DIR}/source-${PACKAGE_ID}.bundle" "${SOURCE_REF}"
  printf 'repository_shallow=false history_verification=isolated-unbundle-rev-list-fsck-v1\n'
  printf 'no_files_created=1 credential_read=0 network_operations=0\n'
}

manifest_line() {
  [[ "$1" != *$'\t'* && "$1" != *$'\n'* && "$2" != *$'\t'* && "$2" != *$'\n'* && -n "$2" ]] || return 65
  printf '%s\t%s\n' "$1" "$2"
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

verify_bundle_history() {
  local bundle="$1" history_repository history_objects history_roots
  local source_count isolated_count source_roots missing_rc
  history_repository="${OUTPUT_DIR}/history-verification.git"
  history_objects="${OUTPUT_DIR}/history-objects.v1"
  history_roots="${OUTPUT_DIR}/history-roots.v1"
  [[ ! -e "${history_repository}" && ! -L "${history_repository}" &&
    ! -e "${history_objects}" && ! -L "${history_objects}" &&
    ! -e "${history_roots}" && ! -L "${history_roots}" ]] || return 73
  /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C \
    GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 \
    GIT_NO_REPLACE_OBJECTS=1 GIT_OPTIONAL_LOCKS=0 \
    /usr/bin/git --no-pager --no-replace-objects \
    -c core.attributesFile=/dev/null -c core.fsmonitor=false \
    -c core.hooksPath=/dev/null init --bare -- "${history_repository}" || return 74
  git_history "${history_repository}" bundle unbundle "${bundle}" || return 74
  git_history "${history_repository}" update-ref refs/heads/history-verified "${COMMIT}" || return 74
  git_history "${history_repository}" cat-file -e "${COMMIT}^{commit}" || return 74
  (set -o noclobber
    git_history "${history_repository}" rev-list --parents --objects --missing=print \
      "${COMMIT}" >"${history_objects}") || return 74
  /usr/bin/grep -E '^\?' -- "${history_objects}"
  missing_rc=$?
  case "${missing_rc}" in
    1) ;;
    0) return 76 ;;
    *) return 74 ;;
  esac
  (set -o noclobber
    git_history "${history_repository}" rev-list --max-parents=0 --reverse \
      "${COMMIT}" >"${history_roots}") || return 74
  source_count="$(git_checked rev-list --count "${COMMIT}")" || return 74
  isolated_count="$(git_history "${history_repository}" rev-list --count "${COMMIT}")" || return 74
  [[ "${source_count}" =~ ^[1-9][0-9]*$ && "${isolated_count}" == "${source_count}" ]] || return 76
  source_roots="$(git_checked rev-list --max-parents=0 --reverse "${COMMIT}")" || return 74
  [[ "$(<"${history_roots}")" == "${source_roots}" && -n "${source_roots}" ]] || return 76
  git_history "${history_repository}" fsck --full --strict --no-dangling "${COMMIT}" || return 76
  HISTORY_COMMIT_COUNT="${isolated_count}"
  HISTORY_ROOTS_SHA256="$(sha256_file "${history_roots}")" || return 74
  HISTORY_OBJECTS_SHA256="$(sha256_file "${history_objects}")" || return 74
  valid_sha256 "${HISTORY_ROOTS_SHA256}" && valid_sha256 "${HISTORY_OBJECTS_SHA256}"
}

bind_package() {
  local bundle manifest source_ref_after bundle_head path name key blob sha canonical_output
  [[ ! -e "${OUTPUT_DIR}" && ! -L "${OUTPUT_DIR}" ]] || fail 'output-exists' 73
  /bin/mkdir -m 0700 -- "${OUTPUT_DIR}" || fail 'output-create' 73
  [[ -d "${OUTPUT_DIR}" && ! -L "${OUTPUT_DIR}" ]] || fail 'output-shape' 73
  canonical_output="$(CDPATH='' cd -- "${OUTPUT_DIR}" && pwd -P)" || fail 'output-canonical' 73
  [[ "${canonical_output}" == "${OUTPUT_DIR}" ]] || fail 'output-canonical-mismatch' 73
  bundle="${OUTPUT_DIR}/source-${PACKAGE_ID}.bundle"
  manifest="${OUTPUT_DIR}/package-manifest.v1"

  require_full_repository || fail 'repository-became-shallow' $?
  git_checked bundle create "${bundle}" "${SOURCE_REF}" || fail 'bundle-create' 74
  bundle_head="$(git_checked bundle list-heads "${bundle}" "${SOURCE_REF}")" || fail 'bundle-head' 74
  [[ "${bundle_head}" == "${COMMIT} ${SOURCE_REF}" ]] || fail 'bundle-head-mismatch' 74
  git_checked bundle verify "${bundle}" || fail 'bundle-verify' 74
  source_ref_after="$(git_checked rev-parse --verify "${SOURCE_REF}^{commit}")" || fail 'source-ref-after' 74
  [[ "${source_ref_after}" == "${COMMIT}" ]] || fail 'source-ref-drift' 75
  verify_bundle_history "${bundle}" || fail 'bundle-history-connectivity' $?

  for path in "${TRANSFER_PATHS[@]}"; do
    name="${path##*/}"
    [[ ! -e "${OUTPUT_DIR}/${name}" && ! -L "${OUTPUT_DIR}/${name}" ]] || fail 'package-file-exists' 73
    (set -o noclobber; git_checked cat-file blob "${COMMIT}:${path}" >"${OUTPUT_DIR}/${name}") ||
      fail "extract-${name}" 74
    /bin/chmod 0600 "${OUTPUT_DIR}/${name}" || fail "mode-${name}" 74
  done
  /bin/chmod 0600 "${bundle}" || fail 'bundle-mode' 74

  (set -o noclobber
    {
      manifest_line format wg-mix-ebpf-b82-v6-package-v4
      manifest_line run_id "${RUN_ID}"
      manifest_line package_id "${PACKAGE_ID}"
      manifest_line integration_ref "${SOURCE_REF}"
      manifest_line integration_commit "${COMMIT}"
      manifest_line bundle_name "source-${PACKAGE_ID}.bundle"
      manifest_line bundle_sha256 "$(sha256_file "${bundle}")"
      manifest_line history_verification isolated-unbundle-rev-list-fsck-v1
      manifest_line history_commit_count "${HISTORY_COMMIT_COUNT}"
      manifest_line history_roots_sha256 "${HISTORY_ROOTS_SHA256}"
      manifest_line history_objects_sha256 "${HISTORY_OBJECTS_SHA256}"
      manifest_line wg_state "${WG_STATE}"
      manifest_line wg_interface "${WG_INTERFACE}"
      manifest_line wg_local_address "${WG_LOCAL_ADDRESS}"
      manifest_line wg_peer_address "${WG_PEER_ADDRESS}"
      manifest_line local_repository "${REPOSITORY}"
      manifest_line local_package_dir "${OUTPUT_DIR}"
      manifest_line remote_package_dir "${REMOTE_PACKAGE_DIR}"
      manifest_line remote_source "${REMOTE_SOURCE}"
      manifest_line target_user siyixuan
      manifest_line target_host 192.168.10.82
      manifest_line target_hostname ubuntu-2604-test
      manifest_line target_kernel 7.0.0-28-generic
      manifest_line target_machine_id 9db3fb717cc74974b2a6b243d67f67b9
      manifest_line target_interface ens33
      manifest_line peer_address 47.116.202.155
      manifest_line peer_port 5201
      manifest_line soak_seconds 3600
      manifest_line session_seconds 300
      manifest_line physical_nic_forward_authority realnic-acceptance-v1
      manifest_line physical_interface_lock "${PHYSICAL_INTERFACE_LOCK}"
      manifest_line legacy_matrix_mode retired
      manifest_line realnic_profile acceptance
      manifest_line realnic_traffic_seconds 30
      for path in "${IDENTITY_PATHS[@]}"; do
        key="$(path_key "${path}")"
        blob="$(git_checked rev-parse "${COMMIT}:${path}")" || exit 68
        sha="$(git_checked show "${COMMIT}:${path}" | sha256_stream)" || exit 68
        manifest_line "${key}_path" "${path}"
        manifest_line "${key}_blob" "${blob}"
        manifest_line "${key}_sha256" "${sha}"
      done
    } >"${manifest}") || fail 'manifest-create' 74
  /bin/chmod 0600 "${manifest}" || fail 'manifest-mode' 74
  printf 'B82_V6_BIND_COMPLETE manifest=%s manifest_sha256=%s commit=%s bundle_sha256=%s\n' \
    "${manifest}" "$(sha256_file "${manifest}")" "${COMMIT}" "$(sha256_file "${bundle}")"
}

main() {
  parse_arguments "$@" || fail 'arguments' $?
  require_repository_contract || fail 'repository-contract' $?
  require_full_repository || fail 'repository-shallow' $?
  require_committed_identity || fail 'committed-identity' $?
  if [[ "${MODE}" == 'plan' ]]; then
    plan_binding
  else
    bind_package
  fi
}

main "$@"
