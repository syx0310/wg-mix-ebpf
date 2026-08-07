#!/bin/bash
set -euo pipefail

readonly PATH="/usr/bin:/bin"
readonly LC_ALL="C"
readonly BASENAME_BIN="/usr/bin/basename"
readonly DIRNAME_BIN="/usr/bin/dirname"
readonly ENV_BIN="/usr/bin/env"
readonly PYTHON3_BIN="/usr/bin/python3"
readonly READLINK_BIN="/usr/bin/readlink"
readonly SHA256_BIN="/usr/bin/sha256sum"
readonly STAT_BIN="/usr/bin/stat"
readonly BOOTSTRAP_PREFIX="/run/wg-mix-ebpf-source-bootstrap"
readonly LAUNCHER_BASENAME="stage-root-owned-test-source.sh"
readonly HELPER_BASENAME="stage-root-owned-test-source.py"
readonly MANIFEST_BASENAME="stage-root-owned-test-source.bootstrap"
readonly EXPECTED_HELPER_SHA256="d447243bb2150a72ed39b320f03f50c144fcefe65b2feb4f34dffaab742490ca"
export PATH LC_ALL
unset CDPATH
umask 077

[[ "${EUID}" -eq 0 ]] || {
  echo "error: root-owned source staging launcher must run as root" >&2
  exit 1
}

script_source="${BASH_SOURCE[0]}"
[[ "${script_source}" == /* ]] || {
  printf 'error: staging launcher must be invoked by absolute path: %s\n' \
    "${script_source}" >&2
  exit 1
}
script_directory="$(
  cd -- "$("${DIRNAME_BIN}" -- "${script_source}")"
  builtin pwd -P
)"
script_path="${script_directory}/$("${BASENAME_BIN}" -- "${script_source}")"
bootstrap_run_id="$("${BASENAME_BIN}" -- "${script_directory}")"
bootstrap_parent="$("${DIRNAME_BIN}" -- "${script_directory}")"
[[ "${bootstrap_parent}" == "${BOOTSTRAP_PREFIX}" && \
  "$("${BASENAME_BIN}" -- "${script_path}")" == "${LAUNCHER_BASENAME}" && \
  "${bootstrap_run_id}" =~ ^[0-9a-f]{8}$ ]] || {
  printf 'error: launcher is outside the fixed root bootstrap path: %s\n' \
    "${script_path}" >&2
  exit 1
}
helper_path="${script_directory}/${HELPER_BASENAME}"
manifest_path="${script_directory}/${MANIFEST_BASENAME}"

for path in "${BOOTSTRAP_PREFIX}" "${script_directory}"; do
  [[ ! -L "${path}" && -d "${path}" ]] || {
    printf 'error: bootstrap directory is missing or a symlink: %s\n' \
      "${path}" >&2
    exit 1
  }
  [[ "$("${READLINK_BIN}" -e -- "${path}")" == "${path}" && \
    "$("${STAT_BIN}" -Lc '%u:%g:%a:%F' -- "${path}")" == \
    "0:0:700:directory" ]] || {
    printf 'error: bootstrap directory is not canonical root:root mode 0700: %s\n' \
      "${path}" >&2
    exit 1
  }
done

for path in "${script_path}" "${helper_path}" "${manifest_path}"; do
  [[ ! -L "${path}" && -f "${path}" ]] || {
    printf 'error: bootstrap file is missing, non-regular, or a symlink: %s\n' \
      "${path}" >&2
    exit 1
  }
  [[ "$("${READLINK_BIN}" -e -- "${path}")" == "${path}" ]] || {
    printf 'error: staging script path is non-canonical: %s\n' "${path}" >&2
    exit 1
  }
done

[[ "$("${STAT_BIN}" -Lc '%u:%g:%a:%h:%F' -- "${script_path}")" == \
  "0:0:500:1:regular file" && \
  "$("${STAT_BIN}" -Lc '%u:%g:%a:%h:%F' -- "${helper_path}")" == \
  "0:0:400:1:regular file" && \
  "$("${STAT_BIN}" -Lc '%u:%g:%a:%h:%F' -- "${manifest_path}")" == \
  "0:0:400:1:regular file" ]] || {
  echo "error: bootstrap files do not have strict root:root mode and link count" >&2
  exit 1
}

exec 6<"${manifest_path}"
exec 7<"${manifest_path}"
exec 8<"${script_path}"
exec 9<"${helper_path}"
manifest_path_stat="$("${STAT_BIN}" -Lc '%d:%i:%u:%g:%f:%h:%s:%Y:%Z' -- "${manifest_path}")"
manifest_contract_fd_stat="$("${STAT_BIN}" -Lc '%d:%i:%u:%g:%f:%h:%s:%Y:%Z' -- /proc/self/fd/6)"
manifest_hash_fd_stat="$("${STAT_BIN}" -Lc '%d:%i:%u:%g:%f:%h:%s:%Y:%Z' -- /proc/self/fd/7)"
script_path_stat="$("${STAT_BIN}" -Lc '%d:%i:%u:%g:%f:%h:%s:%Y:%Z' -- "${script_path}")"
script_fd_stat="$("${STAT_BIN}" -Lc '%d:%i:%u:%g:%f:%h:%s:%Y:%Z' -- /proc/self/fd/8)"
helper_path_stat="$("${STAT_BIN}" -Lc '%d:%i:%u:%g:%f:%h:%s:%Y:%Z' -- "${helper_path}")"
helper_fd_stat="$("${STAT_BIN}" -Lc '%d:%i:%u:%g:%f:%h:%s:%Y:%Z' -- /proc/self/fd/9)"
[[ "${manifest_path_stat}" == "${manifest_contract_fd_stat}" && \
  "${manifest_path_stat}" == "${manifest_hash_fd_stat}" && \
  "${script_path_stat}" == "${script_fd_stat}" && \
  "${helper_path_stat}" == "${helper_fd_stat}" ]] || {
  echo "error: bootstrap file path/descriptor identity changed" >&2
  exit 1
}

manifest_sha256="$("${SHA256_BIN}" -- /proc/self/fd/7)"
manifest_sha256="${manifest_sha256%% *}"
launcher_sha256="$("${SHA256_BIN}" -- /proc/self/fd/8)"
launcher_sha256="${launcher_sha256%% *}"
helper_sha256="$("${SHA256_BIN}" -- /proc/self/fd/9)"
helper_sha256="${helper_sha256%% *}"
[[ "${helper_sha256}" == "${EXPECTED_HELPER_SHA256}" ]] || {
  printf 'error: staging helper SHA-256 mismatch: expected=%s actual=%s\n' \
    "${EXPECTED_HELPER_SHA256}" "${helper_sha256}" >&2
  exit 1
}

mapfile -t bootstrap_contract </proc/self/fd/6
expected_contract=(
  "version=1"
  "bootstrap_prefix=${BOOTSTRAP_PREFIX}"
  "launcher_file=${LAUNCHER_BASENAME}"
  "launcher_mode=0500"
  "launcher_sha256=${launcher_sha256}"
  "helper_file=${HELPER_BASENAME}"
  "helper_mode=0400"
  "helper_sha256=${helper_sha256}"
  "manifest_file=${MANIFEST_BASENAME}"
  "manifest_mode=0400"
)
[[ "${#bootstrap_contract[@]}" -eq "${#expected_contract[@]}" ]] || {
  echo "error: bootstrap manifest field count is invalid" >&2
  exit 1
}
for index in "${!expected_contract[@]}"; do
  [[ "${bootstrap_contract[${index}]}" == "${expected_contract[${index}]}" ]] || {
    printf 'error: bootstrap manifest mismatch at line %s\n' "$((index + 1))" >&2
    exit 1
  }
done
printf 'timestamp=%s event=bootstrap_verified run_id=%s launcher_sha256=%s helper_sha256=%s manifest_sha256=%s\n' \
  "$(/usr/bin/date -u '+%Y-%m-%dT%H:%M:%SZ')" \
  "${bootstrap_run_id}" "${launcher_sha256}" "${helper_sha256}" \
  "${manifest_sha256}"

exec "${ENV_BIN}" -i \
  "PATH=${PATH}" \
  "LC_ALL=${LC_ALL}" \
  "${PYTHON3_BIN}" -I -B /proc/self/fd/9 \
  "--launcher-fd=/proc/self/fd/8" \
  "--launcher-path=${script_path}" \
  "--launcher-sha256=${launcher_sha256}" \
  "--helper-fd=/proc/self/fd/9" \
  "--helper-sha256=${helper_sha256}" \
  "$@"
