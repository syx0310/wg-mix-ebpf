#!/bin/bash
set -euo pipefail

fake_fail() {
  echo "fake tool contract failure: $*" >&2
  exit 90
}

fake_date() {
  [[ "$#" -eq 2 && "$1" == "-u" && "$2" == "+%Y-%m-%dT%H:%M:%SZ" ]] ||
    fake_fail "unexpected date argv"
  printf '%s\n' "2026-08-07T00:00:00Z"
}

fake_id() {
  [[ "$#" -eq 1 && "$1" == "-u" ]] || fake_fail "unexpected id argv"
  printf '%s\n' "0"
}

fake_hostname() {
  [[ "$#" -eq 0 ]] || fake_fail "unexpected hostname argv"
  if [[ "${WG_MIX_FAKETCP_VERIFIER_TEST_CASE-}" == "host-mismatch" ]]; then
    printf '%s\n' "wrong-host"
  else
    printf '%s\n' "ubuntu-2604-test"
  fi
}

fake_uname() {
  [[ "$#" -eq 1 && "$1" == "-r" ]] || fake_fail "unexpected uname argv"
  if [[ "${WG_MIX_FAKETCP_VERIFIER_TEST_CASE-}" == "kernel-mismatch" ]]; then
    printf '%s\n' "7.0.0-wrong"
  else
    printf '%s\n' "7.0.0-28-generic"
  fi
}

fake_readlink() {
  [[ "$#" -eq 3 && "$1" == "-e" && "$2" == "--" ]] ||
    fake_fail "unexpected readlink argv"
  printf '%s\n' "$3"
}

fake_sha256sum() {
  local path

  [[ "$#" -eq 2 && "$1" == "--" ]] || fake_fail "unexpected sha256sum argv"
  path="$2"
  case "${path}" in
  "${WG_MIX_FAKETCP_VERIFIER_TEST_BINARY}")
    printf '%s  %s\n' "${WG_MIX_FAKETCP_VERIFIER_TEST_BINARY_SHA}" "${path}"
    ;;
  "${WG_MIX_FAKETCP_VERIFIER_TEST_OBJECT}")
    printf '%s  %s\n' "${WG_MIX_FAKETCP_VERIFIER_TEST_OBJECT_SHA}" "${path}"
    ;;
  *)
    fake_fail "unexpected sha256sum path"
    ;;
  esac
}

fake_stat() {
  local path uid gid links mode size kind

  [[ "$#" -eq 4 && "$1" == "-c" &&
    "$2" == "%u:%g:%h:%a:%d:%i:%s:%F" && "$3" == "--" ]] ||
    fake_fail "unexpected stat argv"
  path="$4"
  uid=0
  gid=0
  links=1
  size=32
  kind="regular file"
  case "${path}" in
  "${WG_MIX_FAKETCP_VERIFIER_TEST_BINARY}")
    mode=755
    [[ "${WG_MIX_FAKETCP_VERIFIER_TEST_CASE-}" != "owner-mismatch" ]] || uid=1000
    ;;
  "${WG_MIX_FAKETCP_VERIFIER_TEST_OBJECT}")
    mode=644
    [[ "${WG_MIX_FAKETCP_VERIFIER_TEST_CASE-}" != "group-mismatch" ]] || gid=1000
    [[ "${WG_MIX_FAKETCP_VERIFIER_TEST_CASE-}" != "mode-mismatch" ]] || mode=666
    [[ "${WG_MIX_FAKETCP_VERIFIER_TEST_CASE-}" != "nlink-mismatch" ]] || links=2
    ;;
  *)
    fake_fail "unexpected stat path"
    ;;
  esac
  printf '%s:%s:%s:%s:%s:%s:%s:%s\n' \
    "${uid}" "${gid}" "${links}" "${mode}" 1 2 "${size}" "${kind}"
}

fake_timeout() {
  local marker="${WG_MIX_FAKETCP_VERIFIER_TEST_TIMEOUT_MARKER-}"
  local tool_root="${WG_MIX_FAKETCP_VERIFIER_SELF_TEST_TOOL_ROOT-}"

  [[ "$#" -eq 12 ]] || fake_fail "verifier child argv count is $#, want 12"
  [[ "$1" == "--signal=TERM" ]] || fake_fail "unexpected timeout signal"
  [[ "$2" == "--kill-after=5s" ]] || fake_fail "unexpected timeout kill-after"
  [[ "$3" == "45s" ]] || fake_fail "unexpected verifier timeout"
  [[ "$4" == "${tool_root}/env" ]] || fake_fail "unexpected env executable"
  [[ "$5" == "-i" ]] || fake_fail "child environment is not empty"
  [[ "$6" == "PATH=/usr/sbin:/usr/bin:/sbin:/bin" ]] || fake_fail "unexpected child PATH"
  [[ "$7" == "LC_ALL=C" ]] || fake_fail "unexpected child locale"
  [[ "$8" == "${WG_MIX_FAKETCP_VERIFIER_TEST_BINARY}" ]] ||
    fake_fail "unexpected verifier binary"
  [[ "$9" == "bpf-load-test" ]] || fake_fail "unexpected subcommand"
  [[ "${10}" == "--experimental-faketcp" ]] || fake_fail "missing experimental gate"
  [[ "${11}" == "--object" ]] || fake_fail "missing explicit object flag"
  [[ "${12}" == "${WG_MIX_FAKETCP_VERIFIER_TEST_OBJECT}" ]] ||
    fake_fail "unexpected object path"
  [[ -n "${marker}" && "${marker}" == /* ]] || fake_fail "unsafe marker path"
  printf '%s\n' "called" >"${marker}"

  case "${WG_MIX_FAKETCP_VERIFIER_TEST_CASE-}" in
  timeout)
    return 124
    ;;
  child-rc)
    return 23
    ;;
  success)
    printf '%s\n' "fake verifier load succeeded"
    return 0
    ;;
  *)
    fake_fail "timeout was reached by a rejecting test case"
    ;;
  esac
}

case "${0##*/}" in
date)
  fake_date "$@"
  exit 0
  ;;
env)
  fake_fail "fake env must be inspected, not executed"
  ;;
hostname)
  fake_hostname "$@"
  exit 0
  ;;
id)
  fake_id "$@"
  exit 0
  ;;
readlink)
  fake_readlink "$@"
  exit 0
  ;;
sha256sum)
  fake_sha256sum "$@"
  exit 0
  ;;
stat)
  fake_stat "$@"
  exit 0
  ;;
timeout)
  if fake_timeout "$@"; then
    exit 0
  else
    exit $?
  fi
  ;;
uname)
  fake_uname "$@"
  exit 0
  ;;
esac

readonly RUNNER="${1:-}"
[[ -n "${RUNNER}" && "${RUNNER}" == /* && -x "${RUNNER}" ]] || {
  echo "usage: $0 /absolute/path/to/run-faketcp-verifier-only.sh" >&2
  exit 2
}
shift
[[ "$#" -eq 0 ]] || {
  echo "error: self-test accepts exactly one runner path" >&2
  exit 2
}

SELF_PATH="$(cd "$(dirname "$0")" && pwd -P)/${0##*/}"
readonly SELF_PATH
TEST_ROOT_RAW="$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/wg-mix-faketcp-verifier-selftest.XXXXXX")"
TEST_ROOT="$(cd "${TEST_ROOT_RAW}" && pwd -P)"
readonly TEST_ROOT_RAW TEST_ROOT
readonly TOOL_ROOT="${TEST_ROOT}/tools"
readonly FIXTURE_ROOT="${TEST_ROOT}/fixtures"
readonly BINARY="${FIXTURE_ROOT}/wg-mix-ebpf"
readonly OBJECT="${FIXTURE_ROOT}/wg_mix_faketcp_experimental.o"
readonly BINARY_SHA="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
readonly OBJECT_SHA="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
/bin/mkdir -p "${TOOL_ROOT}" "${FIXTURE_ROOT}"
printf '%s\n' "fake verifier binary" >"${BINARY}"
printf '%s\n' "fake experimental object" >"${OBJECT}"
/bin/chmod 0755 "${BINARY}"
/bin/chmod 0644 "${OBJECT}"

for tool in date env hostname id readlink sha256sum stat timeout uname; do
  /bin/ln -s "${SELF_PATH}" "${TOOL_ROOT}/${tool}"
done

readonly -a GOOD_ARGV=(
  --binary "${BINARY}"
  --binary-sha256 "${BINARY_SHA}"
  --object "${OBJECT}"
  --object-sha256 "${OBJECT_SHA}"
)
CASE_INDEX=0

run_case() {
  local test_case="$1"
  local expected_rc="$2"
  local expected_timeout="$3"
  local expected_text="$4"
  local marker output rc
  shift 4

  CASE_INDEX=$((CASE_INDEX + 1))
  marker="${TEST_ROOT}/timeout-called-${CASE_INDEX}"
  set +e
  output="$(
    /usr/bin/env \
      WG_MIX_FAKETCP_VERIFIER_SELF_TEST_TOOL_ROOT="${TOOL_ROOT}" \
      WG_MIX_FAKETCP_VERIFIER_TEST_CASE="${test_case}" \
      WG_MIX_FAKETCP_VERIFIER_TEST_BINARY="${BINARY}" \
      WG_MIX_FAKETCP_VERIFIER_TEST_OBJECT="${OBJECT}" \
      WG_MIX_FAKETCP_VERIFIER_TEST_BINARY_SHA="${BINARY_SHA}" \
      WG_MIX_FAKETCP_VERIFIER_TEST_OBJECT_SHA="${OBJECT_SHA}" \
      WG_MIX_FAKETCP_VERIFIER_TEST_TIMEOUT_MARKER="${marker}" \
      "${RUNNER}" "$@" 2>&1
  )"
  rc=$?
  set -e

  [[ "${rc}" -eq "${expected_rc}" ]] || {
    printf 'error: case %s returned %s, want %s; output=%q\n' \
      "${test_case}" "${rc}" "${expected_rc}" "${output}" >&2
    exit 1
  }
  [[ "${output}" == *"${expected_text}"* ]] || {
    printf 'error: case %s output lacks %q: %q\n' \
      "${test_case}" "${expected_text}" "${output}" >&2
    exit 1
  }
  if [[ "${expected_timeout}" == "yes" ]]; then
    [[ -f "${marker}" ]] || {
      echo "error: case ${test_case} did not invoke the fake verifier runner" >&2
      exit 1
    }
  else
    [[ ! -e "${marker}" ]] || {
      echo "error: rejecting case ${test_case} reached the fake verifier runner" >&2
      exit 1
    }
  fi
}

assert_static_non_mutation() {
  local forbidden_commands forbidden_bpf_mutation

  forbidden_commands='(^|[^[:alnum:]_])(rm|find|sudo|chroot|nsenter)([^[:alnum:]_]|$)'
  forbidden_bpf_mutation='(^|[^[:alnum:]_])(bpftool|attach|pin|populate)([^[:alnum:]_]|$)|map[[:space:]]+(create|update|delete|freeze)'
  if /usr/bin/grep -En "${forbidden_commands}" "${RUNNER}"; then
    echo "error: verifier-only runner contains a forbidden host command" >&2
    exit 1
  fi
  if /usr/bin/grep -En "${forbidden_bpf_mutation}" "${RUNNER}"; then
    echo "error: verifier-only runner contains attach, pin, populate, or map mutation source" >&2
    exit 1
  fi
  if /usr/bin/grep -En '(^|[^[:alnum:]_])(build|install)([^[:alnum:]_]|$)' "${RUNNER}"; then
    echo "error: verifier-only runner contains build or install source" >&2
    exit 1
  fi
}

assert_static_non_mutation
run_case missing 2 no "--binary is required"
run_case relative-path 2 no "absolute normalized safe path" \
  --binary relative/wg-mix-ebpf \
  --binary-sha256 "${BINARY_SHA}" \
  --object "${OBJECT}" \
  --object-sha256 "${OBJECT_SHA}"
run_case hash-mismatch 1 no "binary SHA-256 mismatch" \
  --binary "${BINARY}" \
  --binary-sha256 "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" \
  --object "${OBJECT}" \
  --object-sha256 "${OBJECT_SHA}"
run_case owner-mismatch 1 no "binary must be owned by root:root" "${GOOD_ARGV[@]}"
run_case group-mismatch 1 no "experimental BPF object must be owned by root:root" "${GOOD_ARGV[@]}"
run_case mode-mismatch 1 no "must not be group- or other-writable" "${GOOD_ARGV[@]}"
run_case nlink-mismatch 1 no "link count must be exactly one" "${GOOD_ARGV[@]}"
run_case host-mismatch 1 no "hostname mismatch" "${GOOD_ARGV[@]}"
run_case kernel-mismatch 1 no "kernel mismatch" "${GOOD_ARGV[@]}"
run_case extra-argv 2 no "unexpected argument" "${GOOD_ARGV[@]}" --json
run_case timeout 124 yes "event=finish" "${GOOD_ARGV[@]}"
run_case child-rc 23 yes "event=finish" "${GOOD_ARGV[@]}"
run_case success 0 yes "fake verifier load succeeded" "${GOOD_ARGV[@]}"

printf 'FakeTCP verifier-only gate self-test passed; retained fixtures: %s\n' "${TEST_ROOT}"
