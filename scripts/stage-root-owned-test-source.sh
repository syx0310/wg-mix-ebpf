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
readonly EXPECTED_HELPER_SHA256="6c5c093bff4fa1632f86e77a27d6d54725300b63638f42936f7fb39fd6180864"
export PATH LC_ALL
unset CDPATH
umask 077

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
helper_path="${script_directory}/stage-root-owned-test-source.py"

for path in "${script_path}" "${helper_path}"; do
  [[ ! -L "${path}" && -f "${path}" ]] || {
    printf 'error: staging script is missing, non-regular, or a symlink: %s\n' \
      "${path}" >&2
    exit 1
  }
  [[ "$("${READLINK_BIN}" -e -- "${path}")" == "${path}" ]] || {
    printf 'error: staging script path is non-canonical: %s\n' "${path}" >&2
    exit 1
  }
done

exec 8<"${script_path}"
exec 9<"${helper_path}"
script_path_stat="$("${STAT_BIN}" -Lc '%d:%i:%u:%g:%f:%h:%s:%Y:%Z' -- "${script_path}")"
script_fd_stat="$("${STAT_BIN}" -Lc '%d:%i:%u:%g:%f:%h:%s:%Y:%Z' -- /proc/self/fd/8)"
helper_path_stat="$("${STAT_BIN}" -Lc '%d:%i:%u:%g:%f:%h:%s:%Y:%Z' -- "${helper_path}")"
helper_fd_stat="$("${STAT_BIN}" -Lc '%d:%i:%u:%g:%f:%h:%s:%Y:%Z' -- /proc/self/fd/9)"
[[ "${script_path_stat}" == "${script_fd_stat}" && \
  "${helper_path_stat}" == "${helper_fd_stat}" ]] || {
  echo "error: staging script path/descriptor identity changed" >&2
  exit 1
}
[[ "$("${STAT_BIN}" -Lc '%h' -- /proc/self/fd/8)" == "1" && \
  "$("${STAT_BIN}" -Lc '%h' -- /proc/self/fd/9)" == "1" ]] || {
  echo "error: staging scripts must have exactly one hard link" >&2
  exit 1
}

launcher_sha256="$("${SHA256_BIN}" -- /proc/self/fd/8)"
launcher_sha256="${launcher_sha256%% *}"
helper_sha256="$("${SHA256_BIN}" -- /proc/self/fd/9)"
helper_sha256="${helper_sha256%% *}"
[[ "${helper_sha256}" == "${EXPECTED_HELPER_SHA256}" ]] || {
  printf 'error: staging helper SHA-256 mismatch: expected=%s actual=%s\n' \
    "${EXPECTED_HELPER_SHA256}" "${helper_sha256}" >&2
  exit 1
}

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
