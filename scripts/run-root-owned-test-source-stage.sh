#!/bin/bash
# TRUST BOUNDARY: this runner is not safe to execute from a user-owned checkout.
# Before any privileged shell starts, reviewed orchestration must copy this exact
# approved-SHA file with fixed /usr/bin/install into the fixed unique bootstrap
# directory, then verify the root:root 0500 copy with fixed stat and sha256sum.
# The required entry is: /usr/bin/sudo -- /usr/bin/env -i
# PATH=/usr/bin:/bin LC_ALL=C /bin/bash <root-owned-runner> <strict arguments>.
# The --runner-sha256 argument is the
# externally approved authenticity root; all later checks are defense in depth.

if [[ -n "${BASH_ENV+x}" || -n "${ENV+x}" ]]; then
  echo "error: BASH_ENV and ENV must be absent at runner startup" >&2
  exit 1
fi
if [[ "$-" == *x* || ":${SHELLOPTS}:" == *:xtrace:* ]]; then
  echo "error: inherited xtrace shell options are forbidden" >&2
  exit 1
fi

set -euo pipefail

readonly PATH="/usr/bin:/bin"
readonly LC_ALL="C"
readonly BASENAME_BIN="/usr/bin/basename"
readonly BASH_BIN="/bin/bash"
readonly DATE_BIN="/usr/bin/date"
readonly DIRNAME_BIN="/usr/bin/dirname"
readonly ENV_BIN="/usr/bin/env"
readonly HOSTNAME_BIN="/usr/bin/hostname"
readonly INSTALL_BIN="/usr/bin/install"
readonly READLINK_BIN="/usr/bin/readlink"
readonly SHA256_BIN="/usr/bin/sha256sum"
readonly STAT_BIN="/usr/bin/stat"
readonly BOOTSTRAP_PREFIX="/run/wg-mix-ebpf-source-bootstrap"
readonly STAGE_PREFIX="/run/wg-mix-ebpf-source-stages"
readonly RUNNER_BASENAME="run-root-owned-test-source-stage.sh"
readonly LAUNCHER_BASENAME="stage-root-owned-test-source.sh"
readonly HELPER_BASENAME="stage-root-owned-test-source.py"
readonly MANIFEST_BASENAME="stage-root-owned-test-source.bootstrap"
export PATH LC_ALL
unset CDPATH
umask 077

usage() {
  printf '%s\n' \
    "usage: ${RUNNER_BASENAME} --runner-sha256 <64hex> --source-launcher /absolute/path --launcher-sha256 <64hex> --source-helper /absolute/path --helper-sha256 <64hex> --source-manifest /absolute/path --manifest-sha256 <64hex> --bundle /absolute/path --bundle-sha256 <64hex> --commit <40hex> --run-id <8hex>" >&2
}

valid_sha256() {
  [[ "$1" =~ ^[0-9a-f]{64}$ ]]
}

valid_commit() {
  [[ "$1" =~ ^[0-9a-f]{40}$ ]]
}

valid_run_id() {
  [[ "$1" =~ ^[0-9a-f]{8}$ ]]
}

valid_absolute_path() {
  [[ "$1" =~ ^/[A-Za-z0-9_+@.,/-]+$ &&
    "$1" != "/" && "$1" != */ && "$1" != *"//"* &&
    "$1" != *"/./"* && "$1" != *"/../"* &&
    "$1" != */. && "$1" != */.. ]]
}

assign_once() {
  local name="$1"
  local current="$2"
  local value="$3"

  [[ -z "${current}" ]] || {
    printf 'error: duplicate argument: --%s\n' "${name}" >&2
    exit 2
  }
  printf '%s' "${value}"
}

RUNNER_SHA256=""
SOURCE_LAUNCHER=""
LAUNCHER_SHA256=""
SOURCE_HELPER=""
HELPER_SHA256=""
SOURCE_MANIFEST=""
MANIFEST_SHA256=""
BUNDLE=""
BUNDLE_SHA256=""
COMMIT=""
RUN_ID=""

while (($# > 0)); do
  (($# >= 2)) || {
    echo "error: every runner option requires a value" >&2
    usage
    exit 2
  }
  case "$1" in
  --runner-sha256)
    RUNNER_SHA256="$(assign_once runner-sha256 "${RUNNER_SHA256}" "$2")"
    ;;
  --source-launcher)
    SOURCE_LAUNCHER="$(assign_once source-launcher "${SOURCE_LAUNCHER}" "$2")"
    ;;
  --launcher-sha256)
    LAUNCHER_SHA256="$(assign_once launcher-sha256 "${LAUNCHER_SHA256}" "$2")"
    ;;
  --source-helper)
    SOURCE_HELPER="$(assign_once source-helper "${SOURCE_HELPER}" "$2")"
    ;;
  --helper-sha256)
    HELPER_SHA256="$(assign_once helper-sha256 "${HELPER_SHA256}" "$2")"
    ;;
  --source-manifest)
    SOURCE_MANIFEST="$(assign_once source-manifest "${SOURCE_MANIFEST}" "$2")"
    ;;
  --manifest-sha256)
    MANIFEST_SHA256="$(assign_once manifest-sha256 "${MANIFEST_SHA256}" "$2")"
    ;;
  --bundle)
    BUNDLE="$(assign_once bundle "${BUNDLE}" "$2")"
    ;;
  --bundle-sha256)
    BUNDLE_SHA256="$(assign_once bundle-sha256 "${BUNDLE_SHA256}" "$2")"
    ;;
  --commit)
    COMMIT="$(assign_once commit "${COMMIT}" "$2")"
    ;;
  --run-id)
    RUN_ID="$(assign_once run-id "${RUN_ID}" "$2")"
    ;;
  *)
    printf 'error: unknown runner argument: %s\n' "$1" >&2
    usage
    exit 2
    ;;
  esac
  shift 2
done

if ! valid_sha256 "${RUNNER_SHA256}" ||
  ! valid_sha256 "${LAUNCHER_SHA256}" ||
  ! valid_sha256 "${HELPER_SHA256}" ||
  ! valid_sha256 "${MANIFEST_SHA256}" ||
  ! valid_sha256 "${BUNDLE_SHA256}" ||
  ! valid_commit "${COMMIT}" ||
  ! valid_run_id "${RUN_ID}" ||
  ! valid_absolute_path "${SOURCE_LAUNCHER}" ||
  ! valid_absolute_path "${SOURCE_HELPER}" ||
  ! valid_absolute_path "${SOURCE_MANIFEST}" ||
  ! valid_absolute_path "${BUNDLE}"; then
  echo "error: runner arguments are missing or malformed" >&2
  usage
  exit 2
fi

[[ "${EUID}" -eq 0 ]] || {
  echo "error: root-owned source stage runner must run as root" >&2
  exit 1
}

for tool in \
  "${BASENAME_BIN}" "${BASH_BIN}" "${DATE_BIN}" "${DIRNAME_BIN}" \
  "${ENV_BIN}" "${HOSTNAME_BIN}" "${INSTALL_BIN}" "${READLINK_BIN}" \
  "${SHA256_BIN}" "${STAT_BIN}"; do
  [[ -x "${tool}" && -f "${tool}" ]] || {
    printf 'error: fixed runner tool is unavailable: %s\n' "${tool}" >&2
    exit 1
  }
done

runner_source="${BASH_SOURCE[0]}"
valid_absolute_path "${runner_source}" || {
  echo "error: runner must be invoked by absolute path" >&2
  exit 1
}
runner_directory="$("${DIRNAME_BIN}" -- "${runner_source}")"
runner_path="${runner_directory}/$("${BASENAME_BIN}" -- "${runner_source}")"
bootstrap_parent="$("${DIRNAME_BIN}" -- "${runner_directory}")"
bootstrap_run_id="$("${BASENAME_BIN}" -- "${runner_directory}")"
[[ "${bootstrap_parent}" == "${BOOTSTRAP_PREFIX}" &&
  "${bootstrap_run_id}" == "${RUN_ID}" &&
  "$("${BASENAME_BIN}" -- "${runner_path}")" == "${RUNNER_BASENAME}" ]] || {
  echo "error: runner is outside its fixed bootstrap run path" >&2
  exit 1
}

validate_root_directory() {
  local path="$1"

  [[ ! -L "${path}" && -d "${path}" &&
    "$("${READLINK_BIN}" -e -- "${path}")" == "${path}" &&
    "$("${STAT_BIN}" -Lc '%u:%g:%a:%F' -- "${path}")" == \
    "0:0:700:directory" ]] || {
    printf 'error: root bootstrap directory is unsafe: %s\n' "${path}" >&2
    return 1
  }
}

validate_root_directory "${BOOTSTRAP_PREFIX}"
validate_root_directory "${runner_directory}"

[[ ! -L "${runner_path}" && -f "${runner_path}" &&
  "$("${READLINK_BIN}" -e -- "${runner_path}")" == "${runner_path}" &&
  "$("${STAT_BIN}" -Lc '%u:%g:%a:%h:%F' -- "${runner_path}")" == \
  "0:0:500:1:regular file" ]] || {
  echo "error: runner is not a canonical one-link root:root 0500 file" >&2
  exit 1
}
exec 9<"${runner_path}"
runner_path_stat="$("${STAT_BIN}" -Lc '%d:%i:%u:%g:%f:%h:%s:%Y:%Z' -- "${runner_path}")"
runner_fd_stat="$("${STAT_BIN}" -Lc '%d:%i:%u:%g:%f:%h:%s:%Y:%Z' -- /proc/self/fd/9)"
[[ "${runner_path_stat}" == "${runner_fd_stat}" ]] || {
  echo "error: runner path and descriptor identity differ" >&2
  exit 1
}
runner_actual_sha="$("${SHA256_BIN}" -- /proc/self/fd/9)"
runner_actual_sha="${runner_actual_sha%% *}"
[[ "${runner_actual_sha}" == "${RUNNER_SHA256}" ]] || {
  printf 'error: runner SHA-256 mismatch: approved=%s actual=%s\n' \
    "${RUNNER_SHA256}" "${runner_actual_sha}" >&2
  exit 1
}
[[ "$("${STAT_BIN}" -Lc '%d:%i:%u:%g:%f:%h:%s:%Y:%Z' -- "${runner_path}")" == \
  "${runner_path_stat}" &&
  "$("${STAT_BIN}" -Lc '%d:%i:%u:%g:%f:%h:%s:%Y:%Z' -- /proc/self/fd/9)" == \
  "${runner_fd_stat}" ]] || {
  echo "error: runner changed while hashing" >&2
  exit 1
}

validate_approved_source() {
  local label="$1"
  local path="$2"
  local approved_sha="$3"
  local source_fd
  local path_stat
  local fd_stat
  local actual_sha

  if ! valid_absolute_path "${path}" ||
    ! valid_sha256 "${approved_sha}" ||
    [[ -L "${path}" || ! -f "${path}" ]] ||
    [[ "$("${READLINK_BIN}" -e -- "${path}")" != "${path}" ]] ||
    [[ "$("${STAT_BIN}" -Lc '%h:%F' -- "${path}")" != "1:regular file" ]]; then
    printf 'error: approved %s source path is unsafe: %s\n' \
      "${label}" "${path}" >&2
    return 1
  fi
  exec {source_fd}<"${path}"
  path_stat="$("${STAT_BIN}" -Lc '%d:%i:%u:%g:%f:%h:%s:%Y:%Z' -- "${path}")"
  fd_stat="$("${STAT_BIN}" -Lc '%d:%i:%u:%g:%f:%h:%s:%Y:%Z' -- "/proc/self/fd/${source_fd}")"
  [[ "${path_stat}" == "${fd_stat}" ]] || {
    printf 'error: approved %s source path/descriptor identity differs\n' \
      "${label}" >&2
    return 1
  }
  actual_sha="$("${SHA256_BIN}" -- "/proc/self/fd/${source_fd}")"
  actual_sha="${actual_sha%% *}"
  [[ "${actual_sha}" == "${approved_sha}" &&
    "$("${STAT_BIN}" -Lc '%d:%i:%u:%g:%f:%h:%s:%Y:%Z' -- "${path}")" == \
    "${path_stat}" &&
    "$("${STAT_BIN}" -Lc '%d:%i:%u:%g:%f:%h:%s:%Y:%Z' -- "/proc/self/fd/${source_fd}")" == \
    "${fd_stat}" ]] || {
    printf 'error: approved %s source changed or has SHA mismatch\n' \
      "${label}" >&2
    return 1
  }
  exec {source_fd}<&-
}

validate_approved_source launcher "${SOURCE_LAUNCHER}" "${LAUNCHER_SHA256}"
validate_approved_source helper "${SOURCE_HELPER}" "${HELPER_SHA256}"
validate_approved_source manifest "${SOURCE_MANIFEST}" "${MANIFEST_SHA256}"

HOST_ID="$("${HOSTNAME_BIN}")"
[[ -n "${HOST_ID}" && ! "${HOST_ID}" =~ [[:space:]] ]] || {
  echo "error: fixed hostname identity is empty or unsafe" >&2
  exit 1
}

AUDIT_READY=0
AUDIT_PATH="${runner_directory}/root-stage-runner.audit"

format_argv() {
  local joined=""
  local argument
  local escaped

  for argument in "$@"; do
    printf -v escaped '%q' "${argument}"
    if [[ -z "${joined}" ]]; then
      joined="${escaped}"
    else
      joined+=" ${escaped}"
    fi
  done
  printf '%s' "${joined}"
}

emit_audit() {
  local event="$1"
  local action="$2"
  local target="$3"
  local rc="$4"
  local argv_text="$5"
  local line

  printf -v line \
    'timestamp=%q host=%q event=%q action=%q argv=%q target=%q rc=%q' \
    "$("${DATE_BIN}" -u '+%Y-%m-%dT%H:%M:%SZ')" "${HOST_ID}" \
    "${event}" "${action}" "${argv_text}" "${target}" "${rc}"
  printf '%s\n' "${line}"
  if ((AUDIT_READY)); then
    printf '%s\n' "${line}" >&10
  fi
}

run_write() {
  local action="$1"
  local target="$2"
  shift 2
  local -a argv=("$@")
  local argv_text
  local rc

  argv_text="$(format_argv "${argv[@]}")"
  emit_audit write_start "${action}" "${target}" pending "${argv_text}"
  set +e
  "${argv[@]}"
  rc=$?
  set -e
  emit_audit write_finish "${action}" "${target}" "${rc}" "${argv_text}"
  ((rc == 0)) || return "${rc}"
}

[[ ! -e "${AUDIT_PATH}" && ! -L "${AUDIT_PATH}" ]] || {
  echo "error: root runner audit path already exists" >&2
  exit 1
}
audit_create_argv=(
  "${INSTALL_BIN}" -o 0 -g 0 -m 0600 -- /dev/null "${AUDIT_PATH}"
)
emit_audit write_start create_root_audit "${AUDIT_PATH}" pending \
  "$(format_argv "${audit_create_argv[@]}")"
set +e
"${audit_create_argv[@]}"
audit_create_rc=$?
set -e
emit_audit write_finish create_root_audit "${AUDIT_PATH}" \
  "${audit_create_rc}" "$(format_argv "${audit_create_argv[@]}")"
((audit_create_rc == 0)) || exit "${audit_create_rc}"
[[ "$("${STAT_BIN}" -Lc '%u:%g:%a:%h:%F' -- "${AUDIT_PATH}")" == \
  "0:0:600:1:regular file" ]] || {
  echo "error: new root runner audit metadata is unsafe" >&2
  exit 1
}
exec 10>>"${AUDIT_PATH}"
AUDIT_READY=1
emit_audit write_start create_root_audit "${AUDIT_PATH}" pending \
  "$(format_argv "${audit_create_argv[@]}")"
emit_audit write_finish create_root_audit "${AUDIT_PATH}" 0 \
  "$(format_argv "${audit_create_argv[@]}")"
emit_audit validation_success create_root_audit "${AUDIT_PATH}" 0 \
  "stat=0:0:600:1:regular-file"
emit_audit validation_success observed_external_bootstrap \
  "${BOOTSTRAP_PREFIX},${runner_directory},${runner_path}" 0 \
  "prefix=root:root:0700 run=root:root:0700 runner=root:root:0500:sha256=${runner_actual_sha}"

stage_run="${STAGE_PREFIX}/${RUN_ID}"
emit_audit write_boundary approved_scope \
  "${BOOTSTRAP_PREFIX},${runner_directory},${STAGE_PREFIX},${stage_run}" 0 \
  "bootstrap_prefix bootstrap_run stage_prefix stage_run"
[[ ! -e "${stage_run}" && ! -L "${stage_run}" ]] || {
  emit_audit validation_failure stage_run_absent "${stage_run}" 1 no-command
  exit 1
}

root_launcher="${runner_directory}/${LAUNCHER_BASENAME}"
root_helper="${runner_directory}/${HELPER_BASENAME}"
root_manifest="${runner_directory}/${MANIFEST_BASENAME}"
for target in "${root_launcher}" "${root_helper}" "${root_manifest}"; do
  [[ ! -e "${target}" && ! -L "${target}" ]] || {
    emit_audit validation_failure bootstrap_target_absent "${target}" 1 no-command
    exit 1
  }
done

run_write install_root_launcher "${root_launcher}" \
  "${INSTALL_BIN}" -o 0 -g 0 -m 0500 -- \
  "${SOURCE_LAUNCHER}" "${root_launcher}"
run_write install_root_helper "${root_helper}" \
  "${INSTALL_BIN}" -o 0 -g 0 -m 0400 -- \
  "${SOURCE_HELPER}" "${root_helper}"
run_write install_root_manifest "${root_manifest}" \
  "${INSTALL_BIN}" -o 0 -g 0 -m 0400 -- \
  "${SOURCE_MANIFEST}" "${root_manifest}"

validate_root_copy() {
  local label="$1"
  local path="$2"
  local mode="$3"
  local approved_sha="$4"
  local actual_sha

  [[ ! -L "${path}" && -f "${path}" &&
    "$("${READLINK_BIN}" -e -- "${path}")" == "${path}" &&
    "$("${STAT_BIN}" -Lc '%u:%g:%a:%h:%F' -- "${path}")" == \
    "0:0:${mode}:1:regular file" ]] || {
    emit_audit validation_failure "postcopy_${label}_stat" "${path}" 1 no-command
    return 1
  }
  actual_sha="$("${SHA256_BIN}" -- "${path}")"
  actual_sha="${actual_sha%% *}"
  [[ "${actual_sha}" == "${approved_sha}" ]] || {
    emit_audit validation_failure "postcopy_${label}_sha256" "${path}" 1 \
      "$("${SHA256_BIN}" -- "${path}")"
    return 1
  }
  emit_audit validation_success "postcopy_${label}" "${path}" 0 \
    "sha256=${actual_sha} stat=0:0:${mode}:1:regular-file"
}

validate_root_copy launcher "${root_launcher}" 500 "${LAUNCHER_SHA256}"
validate_root_copy helper "${root_helper}" 400 "${HELPER_SHA256}"
validate_root_copy manifest "${root_manifest}" 400 "${MANIFEST_SHA256}"

launch_argv=(
  "${ENV_BIN}" -i "PATH=${PATH}" "LC_ALL=${LC_ALL}"
  "${BASH_BIN}" "${root_launcher}"
  --bundle "${BUNDLE}"
  --bundle-sha256 "${BUNDLE_SHA256}"
  --commit "${COMMIT}"
  --run-id "${RUN_ID}"
)
run_write execute_root_stage "${stage_run}" "${launch_argv[@]}"
emit_audit runner_result complete "${stage_run}" 0 \
  "source=${stage_run}/source commit=${COMMIT}"
