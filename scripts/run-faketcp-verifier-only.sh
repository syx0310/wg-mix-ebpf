#!/bin/bash
set -euo pipefail

readonly PATH="/usr/sbin:/usr/bin:/sbin:/bin"
readonly LC_ALL="C"
readonly EXPECTED_HOSTNAME="ubuntu-2604-test"
readonly EXPECTED_KERNEL_RELEASE="7.0.0-28-generic"
readonly LOAD_TIMEOUT="45s"
readonly LOAD_KILL_AFTER="5s"
export PATH LC_ALL
umask 077

# Production always uses the fixed system tools below. The override exists only
# so an unprivileged local test can exercise every fail-closed branch without
# invoking the Linux verifier; root is never allowed to enable it.
SELF_TEST_TOOL_ROOT="${WG_MIX_FAKETCP_VERIFIER_SELF_TEST_TOOL_ROOT-}"
if [[ -n "${SELF_TEST_TOOL_ROOT}" ]]; then
  [[ "${EUID}" -ne 0 ]] || {
    echo "error: the verifier self-test tool root is forbidden for root" >&2
    exit 1
  }
  [[ "${SELF_TEST_TOOL_ROOT}" == /* &&
    "${SELF_TEST_TOOL_ROOT}" != "/" &&
    "${SELF_TEST_TOOL_ROOT}" != */. &&
    "${SELF_TEST_TOOL_ROOT}" != */.. &&
    "${SELF_TEST_TOOL_ROOT}" != *"/./"* &&
    "${SELF_TEST_TOOL_ROOT}" != *"/../"* &&
    "${SELF_TEST_TOOL_ROOT}" != *"//"* ]] || {
    echo "error: unsafe verifier self-test tool root" >&2
    exit 1
  }
  TOOL_PREFIX="${SELF_TEST_TOOL_ROOT}"
else
  TOOL_PREFIX="/usr/bin"
fi
readonly SELF_TEST_TOOL_ROOT TOOL_PREFIX
readonly DATE_BIN="${TOOL_PREFIX}/date"
readonly ENV_BIN="${TOOL_PREFIX}/env"
readonly HOSTNAME_BIN="${TOOL_PREFIX}/hostname"
readonly ID_BIN="${TOOL_PREFIX}/id"
readonly READLINK_BIN="${TOOL_PREFIX}/readlink"
readonly SHA256_BIN="${TOOL_PREFIX}/sha256sum"
readonly STAT_BIN="${TOOL_PREFIX}/stat"
readonly TIMEOUT_BIN="${TOOL_PREFIX}/timeout"
readonly UNAME_BIN="${TOOL_PREFIX}/uname"

usage() {
  printf '%s\n' \
    "usage: $0 --binary /absolute/path --binary-sha256 <64-lower-hex> \\" \
    "  --object /absolute/path --object-sha256 <64-lower-hex>"
}

fail_usage() {
  echo "error: $1" >&2
  usage >&2
  exit 2
}

fail_gate() {
  echo "error: $1" >&2
  exit 1
}

valid_path_text() {
  local path="$1"

  [[ "${path}" =~ ^/[[:alnum:]_./+@-]+$ &&
    "${path}" != "/" &&
    "${path}" != */ &&
    "${path}" != */. &&
    "${path}" != */.. &&
    "${path}" != *"/./"* &&
    "${path}" != *"/../"* &&
    "${path}" != *"//"* ]]
}

valid_sha256() {
  [[ "$1" =~ ^[0-9a-f]{64}$ ]]
}

require_tools() {
  local tool

  for tool in \
    "${DATE_BIN}" \
    "${ENV_BIN}" \
    "${HOSTNAME_BIN}" \
    "${ID_BIN}" \
    "${READLINK_BIN}" \
    "${SHA256_BIN}" \
    "${STAT_BIN}" \
    "${TIMEOUT_BIN}" \
    "${UNAME_BIN}"; do
    [[ -x "${tool}" && ! -d "${tool}" ]] ||
      fail_gate "required fixed tool is unavailable: ${tool}"
  done
}

require_host_identity() {
  local actual_uid actual_hostname actual_kernel

  actual_uid="$("${ID_BIN}" -u)" || fail_gate "cannot read effective uid"
  [[ "${actual_uid}" == "0" ]] || fail_gate "verifier gate must run as root"

  actual_hostname="$("${HOSTNAME_BIN}")" || fail_gate "cannot read hostname"
  [[ "${actual_hostname}" == "${EXPECTED_HOSTNAME}" ]] ||
    fail_gate "hostname mismatch: got ${actual_hostname}, want ${EXPECTED_HOSTNAME}"

  actual_kernel="$("${UNAME_BIN}" -r)" || fail_gate "cannot read kernel release"
  [[ "${actual_kernel}" == "${EXPECTED_KERNEL_RELEASE}" ]] ||
    fail_gate "kernel mismatch: got ${actual_kernel}, want ${EXPECTED_KERNEL_RELEASE}"
}

file_metadata() {
  "${STAT_BIN}" -c '%u:%g:%h:%a:%d:%i:%s:%F' -- "$1"
}

require_file_identity() {
  local label="$1"
  local path="$2"
  local expected_sha="$3"
  local require_executable="$4"
  local resolved metadata_before metadata_after
  local uid gid links mode _device _inode _size kind actual_sha _ignored

  valid_path_text "${path}" ||
    fail_usage "${label} path must be an absolute normalized safe path"
  valid_sha256 "${expected_sha}" ||
    fail_usage "${label} SHA-256 must be exactly 64 lowercase hexadecimal characters"
  [[ -f "${path}" && ! -L "${path}" && -s "${path}" ]] ||
    fail_gate "${label} must be a non-empty regular file, not a symlink"

  resolved="$("${READLINK_BIN}" -e -- "${path}")" ||
    fail_gate "cannot resolve ${label} path"
  [[ "${resolved}" == "${path}" ]] ||
    fail_gate "${label} path is not canonical"

  metadata_before="$(file_metadata "${path}")" ||
    fail_gate "cannot inspect ${label} metadata"
  IFS=: read -r uid gid links mode _device _inode _size kind <<<"${metadata_before}"
  [[ "${uid}" == "0" && "${gid}" == "0" ]] ||
    fail_gate "${label} must be owned by root:root"
  [[ "${links}" == "1" ]] || fail_gate "${label} link count must be exactly one"
  [[ "${kind}" == "regular file" ]] || fail_gate "${label} is not a regular file"
  [[ "${mode}" =~ ^[0-7]{3,4}$ ]] || fail_gate "${label} mode is invalid"
  (( (8#${mode} & 8#022) == 0 )) ||
    fail_gate "${label} must not be group- or other-writable"
  if [[ "${require_executable}" == "yes" ]]; then
    (( (8#${mode} & 8#111) != 0 )) || fail_gate "${label} is not executable"
    [[ -x "${path}" ]] || fail_gate "${label} is not executable by root"
  fi

  read -r actual_sha _ignored < <("${SHA256_BIN}" -- "${path}") ||
    fail_gate "cannot hash ${label}"
  [[ "${actual_sha}" == "${expected_sha}" ]] ||
    fail_gate "${label} SHA-256 mismatch"

  metadata_after="$(file_metadata "${path}")" ||
    fail_gate "cannot re-inspect ${label} metadata"
  [[ "${metadata_after}" == "${metadata_before}" ]] ||
    fail_gate "${label} metadata changed while it was being verified"
}

audit_event() {
  local event="$1"
  local rc="$2"
  local binary="$3"
  local binary_sha="$4"
  local object="$5"
  local object_sha="$6"
  local timestamp

  timestamp="$("${DATE_BIN}" -u '+%Y-%m-%dT%H:%M:%SZ')" ||
    fail_gate "cannot generate audit timestamp"
  printf 'audit timestamp=%q event=%q host=%q kernel=%q rc=%q binary=%q binary_sha256=%q object=%q object_sha256=%q\n' \
    "${timestamp}" \
    "${event}" \
    "${EXPECTED_HOSTNAME}" \
    "${EXPECTED_KERNEL_RELEASE}" \
    "${rc}" \
    "${binary}" \
    "${binary_sha}" \
    "${object}" \
    "${object_sha}"
}

BINARY=""
BINARY_SHA256=""
OBJECT=""
OBJECT_SHA256=""

while (($# > 0)); do
  case "$1" in
  --binary)
    (($# >= 2)) || fail_usage "--binary requires a value"
    [[ -z "${BINARY}" ]] || fail_usage "--binary may be specified only once"
    BINARY="$2"
    shift 2
    ;;
  --binary-sha256)
    (($# >= 2)) || fail_usage "--binary-sha256 requires a value"
    [[ -z "${BINARY_SHA256}" ]] || fail_usage "--binary-sha256 may be specified only once"
    BINARY_SHA256="$2"
    shift 2
    ;;
  --object)
    (($# >= 2)) || fail_usage "--object requires a value"
    [[ -z "${OBJECT}" ]] || fail_usage "--object may be specified only once"
    OBJECT="$2"
    shift 2
    ;;
  --object-sha256)
    (($# >= 2)) || fail_usage "--object-sha256 requires a value"
    [[ -z "${OBJECT_SHA256}" ]] || fail_usage "--object-sha256 may be specified only once"
    OBJECT_SHA256="$2"
    shift 2
    ;;
  -h | --help)
    usage
    exit 0
    ;;
  *)
    fail_usage "unexpected argument: $1"
    ;;
  esac
done

[[ -n "${BINARY}" ]] || fail_usage "--binary is required"
[[ -n "${BINARY_SHA256}" ]] || fail_usage "--binary-sha256 is required"
[[ -n "${OBJECT}" ]] || fail_usage "--object is required"
[[ -n "${OBJECT_SHA256}" ]] || fail_usage "--object-sha256 is required"

require_tools
require_host_identity
require_file_identity "binary" "${BINARY}" "${BINARY_SHA256}" yes
require_file_identity "experimental BPF object" "${OBJECT}" "${OBJECT_SHA256}" no

readonly BINARY BINARY_SHA256 OBJECT OBJECT_SHA256
readonly -a LOAD_ARGV=(
  "${TIMEOUT_BIN}"
  --signal=TERM
  "--kill-after=${LOAD_KILL_AFTER}"
  "${LOAD_TIMEOUT}"
  "${ENV_BIN}"
  -i
  "PATH=${PATH}"
  "LC_ALL=${LC_ALL}"
  "${BINARY}"
  bpf-load-test
  --experimental-faketcp
  --object
  "${OBJECT}"
)

audit_event start pending \
  "${BINARY}" "${BINARY_SHA256}" "${OBJECT}" "${OBJECT_SHA256}"
printf 'verifier_argv='
printf ' %q' "${LOAD_ARGV[@]}"
printf '\n'

set +e
"${LOAD_ARGV[@]}"
LOAD_RC=$?
set -e

audit_event finish "${LOAD_RC}" \
  "${BINARY}" "${BINARY_SHA256}" "${OBJECT}" "${OBJECT_SHA256}"
exit "${LOAD_RC}"
