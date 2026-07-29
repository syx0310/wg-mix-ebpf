#!/bin/bash
set -euo pipefail

readonly PATH="/usr/sbin:/usr/bin:/sbin:/bin"
readonly LC_ALL="C"
readonly CHMOD_BIN="/usr/bin/chmod"
readonly DIRNAME_BIN="/usr/bin/dirname"
readonly ENV_BIN="/usr/bin/env"
readonly FIND_BIN="/usr/bin/find"
readonly GO_BIN="/usr/bin/go"
readonly GIT_BIN="/usr/bin/git"
readonly MKDIR_BIN="/usr/bin/mkdir"
readonly READLINK_BIN="/usr/bin/readlink"
readonly SHA256_BIN="/usr/bin/sha256sum"
readonly STAT_BIN="/usr/bin/stat"
readonly TAR_BIN="/usr/bin/tar"
readonly TIMEOUT_BIN="/usr/bin/timeout"
export PATH LC_ALL
umask 077

usage() {
  cat <<'EOF'
usage:
  scripts/build-live-guard-test.sh --self-test-safety-gate

  scripts/build-live-guard-test.sh \
    --self-test-reject-test-binary /absolute/path/to/no-tag.test

  scripts/build-live-guard-test.sh \
    --candidate-commit 0123456789abcdef0123456789abcdef01234567 \
    --output /absolute/run-owned/artifacts/guard-live.test

This is an unprivileged Linux build gate. It requires an exact Git HEAD but
does not compile from the mutable worktree or index. It archives the candidate
commit through an isolated Git repository, builds an independent read-only
snapshot with -trimpath and the realhosttest tag, embeds the candidate commit,
and requires the resulting binary to list TestLiveGuardOwnership exactly.
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

print_argv() {
  local label="$1"
  shift

  printf '%s argv=' "${label}"
  printf ' %q' "$@"
  printf '\n'
}

inspect_test_binary() {
  local binary="$1"
  local binary_home="$2"
  local binary_tmp="$3"
  local -a list_argv

  list_argv=(
    "${TIMEOUT_BIN}"
    --signal=TERM
    --kill-after=2s
    10s
    "${ENV_BIN}"
    -i
    "PATH=${PATH}"
    "LC_ALL=${LC_ALL}"
    "HOME=${binary_home}"
    "TMPDIR=${binary_tmp}"
    "${binary}"
    -test.list
    '^TestLiveGuardOwnership$'
  )
  print_argv "test_list_start" "${list_argv[@]}"
  set +e
  LISTED_TESTS="$("${list_argv[@]}" 2>&1)"
  LIST_EXIT_CODE=$?
  set -e
}

self_test_reject_test_binary() {
  local binary="$1"
  local resolved_binary binary_parent
  local binary_uid binary_links binary_kind

  valid_output_path "${binary}" || {
    echo "error: self-test binary must be a canonical-looking absolute path" >&2
    return 1
  }
  resolved_binary="$("${READLINK_BIN}" -e -- "${binary}")"
  [[ "${resolved_binary}" == "${binary}" ]] || {
    echo "error: self-test binary is missing or non-canonical" >&2
    return 1
  }
  binary_parent="$("${DIRNAME_BIN}" -- "${binary}")"
  read -r binary_uid binary_links binary_kind < <(
    "${STAT_BIN}" -c '%u %h %F' -- "${binary}"
  )
  [[ "${binary_uid}" == "${EUID}" && "${binary_links}" == "1" &&
    "${binary_kind}" == "regular file" && -x "${binary}" ]] || {
    echo "error: self-test binary metadata is unsafe" >&2
    return 1
  }

  inspect_test_binary "${binary}" "${binary_parent}" "${binary_parent}"
  [[ "${LIST_EXIT_CODE}" == "0" && -z "${LISTED_TESTS}" ]] || {
    printf 'error: no-tag fixture did not produce the expected empty live test list: exit=%s output=%q\n' \
      "${LIST_EXIT_CODE}" "${LISTED_TESTS}" >&2
    return 1
  }
  if valid_live_test_list "${LIST_EXIT_CODE}" "${LISTED_TESTS}"; then
    echo "error: no-tag test binary was accepted by the live-test gate" >&2
    return 1
  fi
  echo "live guard build gate rejected the no-tag test binary"
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
SELF_TEST_REJECT_BINARY=""
CANDIDATE_COMMIT=""
OUTPUT=""

while (($# > 0)); do
  case "$1" in
  --self-test-safety-gate)
    SELF_TEST=1
    shift
    ;;
  --self-test-reject-test-binary)
    (($# >= 2)) || {
      echo "error: --self-test-reject-test-binary requires a value" >&2
      exit 2
    }
    SELF_TEST_REJECT_BINARY="$2"
    shift 2
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
  [[ -z "${CANDIDATE_COMMIT}" && -z "${OUTPUT}" &&
    -z "${SELF_TEST_REJECT_BINARY}" ]] || {
    echo "error: --self-test-safety-gate does not accept build arguments" >&2
    exit 2
  }
  self_test_safety_gate
  exit 0
fi

if [[ -n "${SELF_TEST_REJECT_BINARY}" ]]; then
  [[ -z "${CANDIDATE_COMMIT}" && -z "${OUTPUT}" ]] || {
    echo "error: --self-test-reject-test-binary does not accept build arguments" >&2
    exit 2
  }
  [[ -x "${ENV_BIN}" && -x "${READLINK_BIN}" && -x "${STAT_BIN}" &&
    -x "${TIMEOUT_BIN}" ]] || {
    echo "error: fixed system self-test tools are unavailable" >&2
    exit 1
  }
  self_test_reject_test_binary "${SELF_TEST_REJECT_BINARY}"
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
[[ -x "${CHMOD_BIN}" && -x "${DIRNAME_BIN}" && -x "${ENV_BIN}" &&
  -x "${FIND_BIN}" && -x "${GO_BIN}" && -x "${GIT_BIN}" && -x "${MKDIR_BIN}" &&
  -x "${READLINK_BIN}" && -x "${SHA256_BIN}" && -x "${STAT_BIN}" &&
  -x "${TAR_BIN}" && -x "${TIMEOUT_BIN}" ]] || {
  echo "error: fixed system build tools are unavailable" >&2
  exit 1
}

output_parent="$("${DIRNAME_BIN}" -- "${OUTPUT}")"
resolved_parent="$("${READLINK_BIN}" -e -- "${output_parent}")"
[[ "${resolved_parent}" == "${output_parent}" ]] || {
  printf 'error: output parent is missing or non-canonical: configured=%s resolved=%s\n' \
    "${output_parent}" "${resolved_parent}" >&2
  exit 1
}
read -r parent_uid parent_mode parent_kind < <(
  "${STAT_BIN}" -c '%u %a %F' -- "${output_parent}"
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
readonly EMPTY_GIT_TEMPLATE="${output_parent}/empty-git-template"
readonly ISOLATED_GIT_DIR="${output_parent}/candidate.git"
readonly CANDIDATE_ARCHIVE="${output_parent}/candidate.tar"
readonly SOURCE_SNAPSHOT="${output_parent}/source-snapshot"
for directory in \
  "${BUILD_HOME}" \
  "${BUILD_TMP}" \
  "${BUILD_CACHE}" \
  "${MODULE_CACHE}" \
  "${EMPTY_GIT_TEMPLATE}" \
  "${SOURCE_SNAPSHOT}"; do
  [[ ! -e "${directory}" && ! -L "${directory}" ]] || {
    printf 'error: build directory already exists: %s\n' "${directory}" >&2
    exit 1
  }
  "${MKDIR_BIN}" --mode=0700 -- "${directory}"
  read -r directory_uid directory_mode directory_kind < <(
    "${STAT_BIN}" -c '%u %a %F' -- "${directory}"
  )
  [[ "${directory_uid}" == "${EUID}" && "${directory_mode}" == "700" &&
    "${directory_kind}" == "directory" ]] || {
    printf 'error: new build directory metadata is unsafe: path=%s uid=%s mode=%s type=%s\n' \
      "${directory}" "${directory_uid}" "${directory_mode}" "${directory_kind}" >&2
    exit 1
  }
done

[[ ! -e "${ISOLATED_GIT_DIR}" && ! -L "${ISOLATED_GIT_DIR}" &&
  ! -e "${CANDIDATE_ARCHIVE}" && ! -L "${CANDIDATE_ARCHIVE}" ]] || {
  echo "error: isolated Git or candidate archive path already exists" >&2
  exit 1
}

GIT_ENV=(
  "${ENV_BIN}"
  -i
  "PATH=${PATH}"
  "LC_ALL=${LC_ALL}"
  "HOME=${BUILD_HOME}"
  "XDG_CONFIG_HOME=${BUILD_HOME}"
  "GIT_ATTR_NOSYSTEM=1"
  "GIT_CONFIG_GLOBAL=/dev/null"
  "GIT_CONFIG_NOSYSTEM=1"
  "GIT_CONFIG_SYSTEM=/dev/null"
  "GIT_NO_REPLACE_OBJECTS=1"
  "GIT_OPTIONAL_LOCKS=0"
  "${GIT_BIN}"
  --no-pager
  --no-replace-objects
  -c
  core.attributesFile=/dev/null
  -c
  core.fsmonitor=false
  -c
  core.hooksPath=/dev/null
)
readonly -a GIT_ENV

physical_pwd="$(builtin pwd -P)"
repo_root="$("${GIT_ENV[@]}" -C "${physical_pwd}" rev-parse --show-toplevel)"
repo_root="$("${READLINK_BIN}" -e -- "${repo_root}")"
[[ "${physical_pwd}" == "${repo_root}" ]] || {
  printf 'error: run from the canonical repository root: pwd=%s root=%s\n' \
    "${physical_pwd}" "${repo_root}" >&2
  exit 1
}
[[ "$("${GIT_ENV[@]}" -C "${repo_root}" rev-parse --verify HEAD)" == \
  "${CANDIDATE_COMMIT}" ]] || {
  echo "error: candidate commit does not match HEAD" >&2
  exit 1
}
repo_objects="$("${GIT_ENV[@]}" -C "${repo_root}" rev-parse \
  --path-format=absolute --git-path objects)"
repo_objects="$("${READLINK_BIN}" -e -- "${repo_objects}")"
[[ "${repo_objects}" =~ ^/[[:alnum:]_./+@-]+$ &&
  "${repo_objects}" != "/" ]] || {
  echo "error: repository object directory is unsafe" >&2
  exit 1
}

INIT_GIT_ARGV=(
  "${TIMEOUT_BIN}"
  --signal=TERM
  --kill-after=5s
  30s
  "${GIT_ENV[@]}"
  init
  --bare
  --initial-branch=main
  "--template=${EMPTY_GIT_TEMPLATE}"
  "${ISOLATED_GIT_DIR}"
)
readonly -a INIT_GIT_ARGV
print_argv "isolated_git_init" "${INIT_GIT_ARGV[@]}"
"${INIT_GIT_ARGV[@]}"
read -r isolated_uid isolated_mode isolated_kind < <(
  "${STAT_BIN}" -c '%u %a %F' -- "${ISOLATED_GIT_DIR}"
)
[[ "${isolated_uid}" == "${EUID}" && "${isolated_mode}" == "700" &&
  "${isolated_kind}" == "directory" ]] || {
  echo "error: isolated Git directory metadata is unsafe" >&2
  exit 1
}
readonly ALTERNATES_FILE="${ISOLATED_GIT_DIR}/objects/info/alternates"
[[ ! -e "${ALTERNATES_FILE}" && ! -L "${ALTERNATES_FILE}" ]] || {
  echo "error: isolated Git alternates file already exists" >&2
  exit 1
}
(
  set -o noclobber
  printf '%s\n' "${repo_objects}" >"${ALTERNATES_FILE}"
)
"${CHMOD_BIN}" 0400 -- "${ALTERNATES_FILE}"

ISOLATED_GIT_ENV=(
  "${GIT_ENV[@]}"
  "--git-dir=${ISOLATED_GIT_DIR}"
)
readonly -a ISOLATED_GIT_ENV
resolved_candidate="$("${ISOLATED_GIT_ENV[@]}" rev-parse --verify \
  "${CANDIDATE_COMMIT}^{commit}")"
[[ "${resolved_candidate}" == "${CANDIDATE_COMMIT}" ]] || {
  echo "error: isolated Git did not resolve the exact candidate commit" >&2
  exit 1
}

ARCHIVE_ARGV=(
  "${TIMEOUT_BIN}"
  --signal=TERM
  --kill-after=5s
  2m
  "${ISOLATED_GIT_ENV[@]}"
  archive
  --format=tar
  "${CANDIDATE_COMMIT}"
)
readonly -a ARCHIVE_ARGV
print_argv "candidate_archive_start" "${ARCHIVE_ARGV[@]}"
(
  set -o noclobber
  "${ARCHIVE_ARGV[@]}" >"${CANDIDATE_ARCHIVE}"
)
read -r archive_uid archive_mode archive_links archive_size archive_kind < <(
  "${STAT_BIN}" -c '%u %a %h %s %F' -- "${CANDIDATE_ARCHIVE}"
)
[[ "${archive_uid}" == "${EUID}" && "${archive_mode}" == "600" &&
  "${archive_links}" == "1" && "${archive_size}" -gt 0 &&
  "${archive_size}" -le 268435456 &&
  "${archive_kind}" == "regular file" ]] || {
  echo "error: candidate archive metadata is unsafe" >&2
  exit 1
}
archive_sha256="$("${SHA256_BIN}" -- "${CANDIDATE_ARCHIVE}")"
archive_sha256="${archive_sha256%% *}"
"${CHMOD_BIN}" 0400 -- "${CANDIDATE_ARCHIVE}"
[[ "$("${STAT_BIN}" -c '%a' -- "${CANDIDATE_ARCHIVE}")" == "400" ]] || {
  echo "error: candidate archive did not become read-only" >&2
  exit 1
}

EXTRACT_ARGV=(
  "${TIMEOUT_BIN}"
  --signal=TERM
  --kill-after=5s
  2m
  "${TAR_BIN}"
  --extract
  "--file=${CANDIDATE_ARCHIVE}"
  "--directory=${SOURCE_SNAPSHOT}"
  --no-same-owner
  --no-same-permissions
)
readonly -a EXTRACT_ARGV
print_argv "candidate_extract_start" "${EXTRACT_ARGV[@]}"
(
  # Git tree modes contain no group/other write bit. Mask every write bit
  # during extraction so the snapshot is read-only without recursive chmod.
  umask 0222
  "${EXTRACT_ARGV[@]}"
)
"${CHMOD_BIN}" 0500 -- "${SOURCE_SNAPSHOT}"
read -r snapshot_uid snapshot_mode snapshot_kind < <(
  "${STAT_BIN}" -c '%u %a %F' -- "${SOURCE_SNAPSHOT}"
)
[[ "${snapshot_uid}" == "${EUID}" && "${snapshot_mode}" == "500" &&
  "${snapshot_kind}" == "directory" ]] || {
  echo "error: source snapshot metadata is unsafe" >&2
  exit 1
}
writable_snapshot_entry="$("${FIND_BIN}" "${SOURCE_SNAPSHOT}" -xdev \
  -perm /0222 -print -quit)"
[[ -z "${writable_snapshot_entry}" ]] || {
  printf 'error: source snapshot contains a writable entry: %s\n' \
    "${writable_snapshot_entry}" >&2
  exit 1
}
symlink_snapshot_entry="$("${FIND_BIN}" "${SOURCE_SNAPSHOT}" -xdev \
  -type l -print -quit)"
[[ -z "${symlink_snapshot_entry}" ]] || {
  printf 'error: source snapshot contains a symlink: %s\n' \
    "${symlink_snapshot_entry}" >&2
  exit 1
}
[[ -f "${SOURCE_SNAPSHOT}/go.mod" &&
  -d "${SOURCE_SNAPSHOT}/internal/guard" &&
  -f "${SOURCE_SNAPSHOT}/scripts/build-live-guard-test.sh" &&
  ! -L "${SOURCE_SNAPSHOT}/scripts/build-live-guard-test.sh" ]] || {
  echo "error: candidate snapshot is missing required build inputs" >&2
  exit 1
}

script_shell_pid="${BASHPID}"
running_builder="$("${READLINK_BIN}" -e -- "${BASH_SOURCE[0]}")"
expected_builder="${repo_root}/scripts/build-live-guard-test.sh"
builder_descriptor="/proc/${script_shell_pid}/fd/255"
[[ "${running_builder}" == "${expected_builder}" && -f "${running_builder}" &&
  ! -L "${running_builder}" && -r "${builder_descriptor}" ]] || {
  echo "error: running build gate identity is unavailable" >&2
  exit 1
}
read -r builder_identity builder_uid builder_links builder_kind < <(
  "${STAT_BIN}" -c '%d:%i %u %h %F' -- "${running_builder}"
)
descriptor_identity="$("${STAT_BIN}" -Lc '%d:%i' -- "${builder_descriptor}")"
[[ "${builder_identity}" == "${descriptor_identity}" &&
  "${builder_uid}" == "${EUID}" && "${builder_links}" == "1" &&
  "${builder_kind}" == "regular file" ]] || {
  echo "error: running build gate descriptor metadata is unsafe" >&2
  exit 1
}
running_builder_sha="$("${SHA256_BIN}" -- "${builder_descriptor}")"
running_builder_sha="${running_builder_sha%% *}"
candidate_builder_sha="$("${SHA256_BIN}" -- \
  "${SOURCE_SNAPSHOT}/scripts/build-live-guard-test.sh")"
candidate_builder_sha="${candidate_builder_sha%% *}"
[[ "${running_builder_sha}" == "${candidate_builder_sha}" ]] || {
  echo "error: running build gate does not match the candidate snapshot" >&2
  exit 1
}
[[ "$("${STAT_BIN}" -c '%d:%i' -- "${running_builder}")" == \
  "${builder_identity}" ]] || {
  echo "error: running build gate path changed while it was hashed" >&2
  exit 1
}
printf 'candidate_snapshot commit=%s archive=%s sha256=%s source=%s\n' \
  "${CANDIDATE_COMMIT}" "${CANDIDATE_ARCHIVE}" "${archive_sha256}" \
  "${SOURCE_SNAPSHOT}"
printf 'builder_identity commit=%s sha256=%s descriptor=%s\n' \
  "${CANDIDATE_COMMIT}" "${running_builder_sha}" "${builder_descriptor}"

BUILD_ARGV=(
  "${TIMEOUT_BIN}"
  --signal=TERM
  --kill-after=10s
  5m
  "${ENV_BIN}"
  -i
  "--chdir=${SOURCE_SNAPSHOT}"
  "PATH=${PATH}"
  "LC_ALL=${LC_ALL}"
  "HOME=${BUILD_HOME}"
  "TMPDIR=${BUILD_TMP}"
  "GOTMPDIR=${BUILD_TMP}"
  "GOCACHE=${BUILD_CACHE}"
  "GOMODCACHE=${MODULE_CACHE}"
  "CGO_ENABLED=0"
  "GOENV=off"
  "GOFLAGS=-mod=readonly -buildvcs=false"
  "GOTOOLCHAIN=local"
  "GOWORK=off"
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
printf 'build_start commit=%s output=%s snapshot=%s\n' \
  "${CANDIDATE_COMMIT}" "${OUTPUT}" "${SOURCE_SNAPSHOT}"
print_argv "build_command" "${BUILD_ARGV[@]}"
"${BUILD_ARGV[@]}"

read -r output_uid output_mode output_links output_kind < <(
  "${STAT_BIN}" -c '%u %a %h %F' -- "${OUTPUT}"
)
[[ "${output_uid}" == "${EUID}" && "${output_mode}" == "700" &&
  "${output_links}" == "1" && "${output_kind}" == "regular file" ]] || {
  printf 'error: built test metadata is unsafe: uid=%s mode=%s links=%s type=%s\n' \
    "${output_uid}" "${output_mode}" "${output_links}" "${output_kind}" >&2
  exit 1
}

inspect_test_binary "${OUTPUT}" "${BUILD_HOME}" "${BUILD_TMP}"
if ! valid_live_test_list "${LIST_EXIT_CODE}" "${LISTED_TESTS}"; then
  printf 'error: built binary test list = %q, want TestLiveGuardOwnership\n' \
    "${LISTED_TESTS}" >&2
  exit 1
fi
output_sha256="$("${SHA256_BIN}" -- "${OUTPUT}")"
output_sha256="${output_sha256%% *}"
printf 'build_finish commit=%s output=%s sha256=%s archive_sha256=%s listed_test=%s\n' \
  "${CANDIDATE_COMMIT}" "${OUTPUT}" "${output_sha256}" \
  "${archive_sha256}" "${LISTED_TESTS}"
