#!/bin/bash
set -euo pipefail

readonly PATH="/usr/sbin:/usr/bin:/sbin:/bin"
readonly LC_ALL="C"
readonly ENV_BIN="/usr/bin/env"
readonly GO_BIN="/usr/bin/go"
readonly GIT_BIN="/usr/bin/git"
readonly SHA256_BIN="/usr/bin/sha256sum"
readonly TIMEOUT_BIN="/usr/bin/timeout"
export PATH LC_ALL
umask 077

usage() {
  cat <<'EOF'
usage:
  scripts/build-live-guard-test.sh --self-test-safety-gate

  scripts/build-live-guard-test.sh \
    --candidate-commit 0123456789abcdef0123456789abcdef01234567 \
    --output /absolute/run-owned/artifacts/guard-live.test

This is an unprivileged Linux build gate. It requires an exact clean Git HEAD,
uses -trimpath and the realhosttest tag, embeds the candidate commit, and
requires the resulting binary to list TestLiveGuardOwnership exactly.
EOF
}

valid_commit() {
  [[ "$1" =~ ^[0-9a-f]{40}$ ]]
}

valid_output_path() {
  [[ "$1" =~ ^/[[:alnum:]_./-]+$ &&
    "$1" != "/" && "$1" != */ &&
    "$1" != */. && "$1" != */.. &&
    "$1" != *"/./"* && "$1" != *"/../"* && "$1" != *"//"* ]]
}

valid_live_test_list() {
  local exit_code="$1"
  local output="$2"

  [[ "${exit_code}" == "0" && "${output}" == "TestLiveGuardOwnership" ]]
}

self_test_safety_gate() {
  valid_commit "0123456789abcdef0123456789abcdef01234567" || {
    echo "error: valid commit fixture was rejected" >&2
    return 1
  }
  if valid_commit "012345" ||
    valid_commit "0123456789abcdef0123456789abcdef0123456G"; then
    echo "error: invalid commit fixture was accepted" >&2
    return 1
  fi
  valid_output_path "/tmp/wg-mix-ebpf-run/artifacts/guard-live.test" || {
    echo "error: valid output fixture was rejected" >&2
    return 1
  }
  if valid_output_path "relative/guard-live.test" ||
    valid_output_path "/tmp/wg-mix-ebpf-run/../guard-live.test" ||
    valid_output_path "/tmp//guard-live.test" ||
    valid_output_path "/tmp/wg-mix-ebpf-run/.." ||
    valid_output_path $'/tmp/wg-mix-ebpf-run/bad\nname'; then
    echo "error: unsafe output fixture was accepted" >&2
    return 1
  fi
  valid_live_test_list 0 "TestLiveGuardOwnership" || {
    echo "error: exact live test-list fixture was rejected" >&2
    return 1
  }
  if valid_live_test_list 0 "" ||
    valid_live_test_list 0 "PASS" ||
    valid_live_test_list 0 $'TestLiveGuardOwnership\nTestOther' ||
    valid_live_test_list 1 "TestLiveGuardOwnership"; then
    echo "error: missing, ambiguous, or failed live test-list fixture was accepted" >&2
    return 1
  fi
  echo "live guard build safety gate self-test passed"
}

SELF_TEST=0
CANDIDATE_COMMIT=""
OUTPUT=""

while (($# > 0)); do
  case "$1" in
  --self-test-safety-gate)
    SELF_TEST=1
    shift
    ;;
  --candidate-commit)
    (($# >= 2)) || {
      echo "error: --candidate-commit requires a value" >&2
      exit 2
    }
    CANDIDATE_COMMIT="$2"
    shift 2
    ;;
  --output)
    (($# >= 2)) || {
      echo "error: --output requires a value" >&2
      exit 2
    }
    OUTPUT="$2"
    shift 2
    ;;
  -h | --help)
    usage
    exit 0
    ;;
  *)
    printf 'error: unknown argument: %s\n' "$1" >&2
    usage >&2
    exit 2
    ;;
  esac
done

if ((SELF_TEST)); then
  [[ -z "${CANDIDATE_COMMIT}" && -z "${OUTPUT}" ]] || {
    echo "error: --self-test-safety-gate does not accept build arguments" >&2
    exit 2
  }
  self_test_safety_gate
  exit 0
fi

[[ "${EUID}" -ne 0 ]] || {
  echo "error: live guard test binary must be built as an unprivileged user" >&2
  exit 1
}
valid_commit "${CANDIDATE_COMMIT}" || {
  echo "error: --candidate-commit must be exactly 40 lowercase hex characters" >&2
  exit 2
}
valid_output_path "${OUTPUT}" || {
  echo "error: --output must be a canonical-looking absolute file path" >&2
  exit 2
}
[[ -x "${ENV_BIN}" && -x "${GO_BIN}" && -x "${GIT_BIN}" &&
  -x "${SHA256_BIN}" && -x "${TIMEOUT_BIN}" ]] || {
  echo "error: fixed system build tools are unavailable" >&2
  exit 1
}

repo_root="$("${GIT_BIN}" rev-parse --show-toplevel)"
repo_root="$(readlink -e -- "${repo_root}")"
[[ "${PWD}" == "${repo_root}" ]] || {
  printf 'error: run from the canonical repository root: pwd=%s root=%s\n' \
    "${PWD}" "${repo_root}" >&2
  exit 1
}
[[ "$("${GIT_BIN}" rev-parse HEAD)" == "${CANDIDATE_COMMIT}" ]] || {
  echo "error: candidate commit does not match HEAD" >&2
  exit 1
}
"${GIT_BIN}" diff --quiet
"${GIT_BIN}" diff --cached --quiet
[[ -z "$("${GIT_BIN}" ls-files --others --exclude-standard)" ]] || {
  echo "error: candidate worktree contains untracked files" >&2
  exit 1
}

output_parent="$(dirname -- "${OUTPUT}")"
resolved_parent="$(readlink -e -- "${output_parent}")"
[[ "${resolved_parent}" == "${output_parent}" ]] || {
  printf 'error: output parent is missing or non-canonical: configured=%s resolved=%s\n' \
    "${output_parent}" "${resolved_parent}" >&2
  exit 1
}
read -r parent_uid parent_mode parent_kind < <(
  stat -c '%u %a %F' -- "${output_parent}"
)
[[ "${parent_uid}" == "${EUID}" && "${parent_kind}" == "directory" ]] || {
  echo "error: output parent is not an EUID-owned directory" >&2
  exit 1
}
((8#${parent_mode} & 8#022 == 0)) || {
  echo "error: output parent is group/other writable" >&2
  exit 1
}
[[ ! -e "${OUTPUT}" && ! -L "${OUTPUT}" ]] || {
  echo "error: output path already exists" >&2
  exit 1
}

readonly BUILD_HOME="${output_parent}/build-home"
readonly BUILD_TMP="${output_parent}/build-tmp"
readonly BUILD_CACHE="${output_parent}/build-cache"
readonly MODULE_CACHE="${output_parent}/module-cache"
for directory in "${BUILD_HOME}" "${BUILD_TMP}" "${BUILD_CACHE}" "${MODULE_CACHE}"; do
  [[ ! -e "${directory}" && ! -L "${directory}" ]] || {
    printf 'error: build directory already exists: %s\n' "${directory}" >&2
    exit 1
  }
  mkdir --mode=0700 -- "${directory}"
done

BUILD_ARGV=(
  "${TIMEOUT_BIN}"
  --signal=TERM
  --kill-after=10s
  5m
  "${ENV_BIN}"
  -i
  "PATH=${PATH}"
  "LC_ALL=${LC_ALL}"
  "HOME=${BUILD_HOME}"
  "TMPDIR=${BUILD_TMP}"
  "GOTMPDIR=${BUILD_TMP}"
  "GOCACHE=${BUILD_CACHE}"
  "GOMODCACHE=${MODULE_CACHE}"
  "CGO_ENABLED=0"
  "GOFLAGS=-mod=readonly"
  "GOTOOLCHAIN=local"
  "${GO_BIN}"
  test
  -trimpath
  -c
  -tags
  realhosttest
  -ldflags
  "-X=github.com/syx0310/wg-mix-ebpf/internal/guard.liveGuardBuiltCommit=${CANDIDATE_COMMIT}"
  -o
  "${OUTPUT}"
  ./internal/guard
)
readonly -a BUILD_ARGV
printf 'build_start commit=%s output=%s argv=' "${CANDIDATE_COMMIT}" "${OUTPUT}"
printf ' %q' "${BUILD_ARGV[@]}"
printf '\n'
"${BUILD_ARGV[@]}"

read -r output_uid output_mode output_links output_kind < <(
  stat -c '%u %a %h %F' -- "${OUTPUT}"
)
[[ "${output_uid}" == "${EUID}" && "${output_mode}" == "755" &&
  "${output_links}" == "1" && "${output_kind}" == "regular file" ]] || {
  printf 'error: built test metadata is unsafe: uid=%s mode=%s links=%s type=%s\n' \
    "${output_uid}" "${output_mode}" "${output_links}" "${output_kind}" >&2
  exit 1
}

LIST_ARGV=(
  "${TIMEOUT_BIN}"
  --signal=TERM
  --kill-after=2s
  10s
  "${ENV_BIN}"
  -i
  "PATH=${PATH}"
  "LC_ALL=${LC_ALL}"
  "HOME=${BUILD_HOME}"
  "TMPDIR=${BUILD_TMP}"
  "${OUTPUT}"
  -test.list
  '^TestLiveGuardOwnership$'
)
readonly -a LIST_ARGV
set +e
listed_tests="$("${LIST_ARGV[@]}" 2>&1)"
list_exit_code=$?
set -e
if ! valid_live_test_list "${list_exit_code}" "${listed_tests}"; then
  printf 'error: built binary test list = %q, want TestLiveGuardOwnership\n' \
    "${listed_tests}" >&2
  exit 1
fi
output_sha256="$("${SHA256_BIN}" -- "${OUTPUT}")"
output_sha256="${output_sha256%% *}"
printf 'build_finish commit=%s output=%s sha256=%s listed_test=%s\n' \
  "${CANDIDATE_COMMIT}" "${OUTPUT}" "${output_sha256}" "${listed_tests}"
