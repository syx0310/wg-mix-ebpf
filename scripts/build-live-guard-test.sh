#!/bin/bash
set -euo pipefail

readonly PATH="/usr/sbin:/usr/bin:/sbin:/bin"
readonly LC_ALL="C"
readonly CHMOD_BIN="/usr/bin/chmod"
readonly DIRNAME_BIN="/usr/bin/dirname"
readonly ENV_BIN="/usr/bin/env"
readonly GO_BIN="/usr/bin/go"
readonly GIT_BIN="/usr/bin/git"
readonly MKDIR_BIN="/usr/bin/mkdir"
readonly PYTHON3_BIN="/usr/bin/python3"
readonly READLINK_BIN="/usr/bin/readlink"
readonly SHA256_BIN="/usr/bin/sha256sum"
readonly STAT_BIN="/usr/bin/stat"
readonly TAR_BIN="/usr/bin/tar"
readonly TIMEOUT_BIN="/usr/bin/timeout"
readonly ARCHIVE_LIMIT_BYTES=268435456
export PATH LC_ALL
umask 077

[[ "${EUID}" -ne 0 ]] || {
  echo "error: live guard build gate must run as an unprivileged user" >&2
  exit 1
}

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

valid_parent_mode() {
  local mode="$1"

  [[ "${mode}" =~ ^[0-7]{3,4}$ ]] || return 1
  (( (8#${mode} & 8#022) == 0 ))
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
  if ! valid_parent_mode "0700" ||
    ! valid_parent_mode "0755" ||
    ! valid_parent_mode "700" ||
    ! valid_parent_mode "755"; then
    echo "error: safe parent mode fixture was rejected" >&2
    return 1
  fi
  if valid_parent_mode "0020" ||
    valid_parent_mode "0002" ||
    valid_parent_mode "20" ||
    valid_parent_mode "2" ||
    valid_parent_mode "0777" ||
    valid_parent_mode "08"; then
    echo "error: unsafe parent mode fixture was accepted" >&2
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

valid_commit "${CANDIDATE_COMMIT}" || {
  echo "error: --candidate-commit must be exactly 40 lowercase hex characters" >&2
  exit 2
}
valid_output_path "${OUTPUT}" || {
  echo "error: --output must be a canonical-looking absolute file path" >&2
  exit 2
}
[[ -x "${CHMOD_BIN}" && -x "${DIRNAME_BIN}" && -x "${ENV_BIN}" &&
  -x "${GO_BIN}" && -x "${GIT_BIN}" && -x "${MKDIR_BIN}" &&
  -x "${PYTHON3_BIN}" && -x "${READLINK_BIN}" && -x "${SHA256_BIN}" &&
  -x "${STAT_BIN}" &&
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
valid_parent_mode "${parent_mode}" || {
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

readonly ARCHIVE_LIMIT_PYTHON='import os
import sys

destination = sys.argv[1]
limit = int(sys.argv[2], 10)
if limit <= 0:
    print("error: candidate archive hard limit must be positive", file=sys.stderr)
    raise SystemExit(1)

flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
try:
    destination_fd = os.open(destination, flags, 0o600)
except OSError as error:
    print(f"error: cannot create candidate archive: {error}", file=sys.stderr)
    raise SystemExit(1)

total = 0
failed = False
try:
    while True:
        chunk = sys.stdin.buffer.read(min(1024 * 1024, limit - total + 1))
        if not chunk:
            break
        if total + len(chunk) > limit:
            raise RuntimeError(
                f"candidate archive exceeds {limit} byte hard limit"
            )
        view = memoryview(chunk)
        while view:
            written = os.write(destination_fd, view)
            if written <= 0:
                raise RuntimeError("short write while creating candidate archive")
            view = view[written:]
        total += len(chunk)
    os.fsync(destination_fd)
except (OSError, RuntimeError) as error:
    print(f"error: {error}", file=sys.stderr)
    failed = True
finally:
    os.close(destination_fd)

if failed:
    raise SystemExit(1)
'

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
ARCHIVE_LIMIT_ARGV=(
  "${TIMEOUT_BIN}"
  --signal=TERM
  --kill-after=5s
  2m
  "${ENV_BIN}"
  -i
  "PATH=${PATH}"
  "LC_ALL=${LC_ALL}"
  "HOME=${BUILD_HOME}"
  "TMPDIR=${BUILD_TMP}"
  "${PYTHON3_BIN}"
  -I
  -B
  -c
  "${ARCHIVE_LIMIT_PYTHON}"
  "${CANDIDATE_ARCHIVE}"
  "${ARCHIVE_LIMIT_BYTES}"
)
readonly -a ARCHIVE_LIMIT_ARGV
print_argv "candidate_archive_start" "${ARCHIVE_ARGV[@]}"
print_argv "candidate_archive_limit" "${ARCHIVE_LIMIT_ARGV[@]}"
set +e
"${ARCHIVE_ARGV[@]}" | "${ARCHIVE_LIMIT_ARGV[@]}"
archive_pipeline_status=("${PIPESTATUS[@]}")
set -e
if ((${#archive_pipeline_status[@]} != 2)) ||
  [[ "${archive_pipeline_status[0]}" != "0" ||
    "${archive_pipeline_status[1]}" != "0" ]]; then
  printf 'error: candidate archive pipeline failed: producer=%s limiter=%s\n' \
    "${archive_pipeline_status[0]:-missing}" \
    "${archive_pipeline_status[1]:-missing}" >&2
  exit 1
fi
read -r archive_uid archive_mode archive_links archive_size archive_kind < <(
  "${STAT_BIN}" -c '%u %a %h %s %F' -- "${CANDIDATE_ARCHIVE}"
)
[[ "${archive_uid}" == "${EUID}" && "${archive_mode}" == "600" &&
  "${archive_links}" == "1" && "${archive_size}" -gt 0 &&
  "${archive_size}" -le "${ARCHIVE_LIMIT_BYTES}" &&
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
  "${ENV_BIN}"
  -i
  "PATH=${PATH}"
  "LC_ALL=${LC_ALL}"
  "HOME=${BUILD_HOME}"
  "TMPDIR=${BUILD_TMP}"
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
  # GNU tar must retain owner-write while it creates and fills nested
  # directories. The descriptor-anchored seal below removes write bits only
  # after extraction has completed.
  umask 0077
  "${EXTRACT_ARGV[@]}"
)

readonly SNAPSHOT_SEAL_PYTHON='import os
import stat
import sys

snapshot_path = sys.argv[1]
expected_uid = os.geteuid()

for required_flag in ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK"):
    if not hasattr(os, required_flag):
        raise RuntimeError(f"required descriptor flag is unavailable: {required_flag}")

directory_flags = (
    os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
)
file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK


class SealError(RuntimeError):
    pass


def display(key):
    if not key:
        return "."
    return repr("/".join(key))


def identity(metadata):
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_nlink,
        stat.S_IFMT(metadata.st_mode),
    )


def exact_metadata(metadata):
    return identity(metadata) + (stat.S_IMODE(metadata.st_mode),)


def require_open_identity(before, opened, key):
    if identity(before) != identity(opened):
        raise SealError(f"entry identity changed while opening {display(key)}")


def require_exact(metadata, expected, key):
    if exact_metadata(metadata) != expected:
        raise SealError(f"sealed entry metadata changed at {display(key)}")


def list_names(directory_fd, key):
    with os.scandir(directory_fd) as entries:
        names = [entry.name for entry in entries]
    if any(name in ("", ".", "..") or "/" in name for name in names):
        raise SealError(f"invalid directory entry below {display(key)}")
    names.sort()
    return names


sealed = {}
snapshot_device = None


def require_private_entry(metadata, key, expected_kind):
    kind = stat.S_IFMT(metadata.st_mode)
    mode = stat.S_IMODE(metadata.st_mode)
    if kind != expected_kind:
        raise SealError(f"unexpected entry type at {display(key)}")
    if metadata.st_dev != snapshot_device:
        raise SealError(f"entry crosses the snapshot filesystem at {display(key)}")
    if metadata.st_uid != expected_uid:
        raise SealError(f"entry is not EUID-owned at {display(key)}")
    if mode & 0o077:
        raise SealError(f"entry escaped the private extraction mask at {display(key)}")
    if expected_kind == stat.S_IFDIR and mode != 0o700:
        raise SealError(f"directory was not privately extracted at {display(key)}")
    if expected_kind == stat.S_IFREG:
        if metadata.st_nlink != 1:
            raise SealError(f"regular file has multiple links at {display(key)}")
        if mode not in (0o600, 0o700):
            raise SealError(f"regular file has an unsafe extracted mode at {display(key)}")


def seal_regular(parent_fd, name, key, before):
    require_private_entry(before, key, stat.S_IFREG)
    file_fd = os.open(name, file_flags, dir_fd=parent_fd)
    try:
        opened = os.fstat(file_fd)
        require_open_identity(before, opened, key)
        require_private_entry(opened, key, stat.S_IFREG)
        target_mode = 0o500 if stat.S_IMODE(opened.st_mode) == 0o700 else 0o400
        os.fchmod(file_fd, target_mode)
        sealed_metadata = os.fstat(file_fd)
        require_open_identity(opened, sealed_metadata, key)
        if stat.S_IMODE(sealed_metadata.st_mode) != target_mode:
            raise SealError(f"regular file did not seal at {display(key)}")
        sealed[key] = exact_metadata(sealed_metadata)
    finally:
        os.close(file_fd)
    require_exact(
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False),
        sealed[key],
        key,
    )


def seal_directory(directory_fd, key, opened):
    require_private_entry(opened, key, stat.S_IFDIR)
    for name in list_names(directory_fd, key):
        child_key = key + (name,)
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        kind = stat.S_IFMT(before.st_mode)
        if kind == stat.S_IFREG:
            seal_regular(directory_fd, name, child_key, before)
            continue
        if kind != stat.S_IFDIR:
            raise SealError(
                f"symlink or special file is forbidden at {display(child_key)}"
            )
        require_private_entry(before, child_key, stat.S_IFDIR)
        child_fd = os.open(name, directory_flags, dir_fd=directory_fd)
        try:
            child_opened = os.fstat(child_fd)
            require_open_identity(before, child_opened, child_key)
            seal_directory(child_fd, child_key, child_opened)
        finally:
            os.close(child_fd)
        require_exact(
            os.stat(name, dir_fd=directory_fd, follow_symlinks=False),
            sealed[child_key],
            child_key,
        )

    os.fchmod(directory_fd, 0o500)
    sealed_metadata = os.fstat(directory_fd)
    require_open_identity(opened, sealed_metadata, key)
    if stat.S_IMODE(sealed_metadata.st_mode) != 0o500:
        raise SealError(f"directory did not seal at {display(key)}")
    sealed[key] = exact_metadata(sealed_metadata)


def verify_directory(directory_fd, key, seen):
    expected = sealed.get(key)
    if expected is None:
        raise SealError(f"unrecorded directory appeared at {display(key)}")
    opened = os.fstat(directory_fd)
    require_exact(opened, expected, key)
    if (
        stat.S_IFMT(opened.st_mode) != stat.S_IFDIR
        or stat.S_IMODE(opened.st_mode) != 0o500
        or opened.st_uid != expected_uid
        or opened.st_dev != snapshot_device
    ):
        raise SealError(f"directory failed sealed-tree verification at {display(key)}")
    seen.add(key)

    for name in list_names(directory_fd, key):
        child_key = key + (name,)
        child_expected = sealed.get(child_key)
        if child_expected is None:
            raise SealError(f"new entry appeared at {display(child_key)}")
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        require_exact(before, child_expected, child_key)
        kind = stat.S_IFMT(before.st_mode)
        if kind == stat.S_IFDIR:
            child_fd = os.open(name, directory_flags, dir_fd=directory_fd)
            try:
                require_exact(os.fstat(child_fd), child_expected, child_key)
                verify_directory(child_fd, child_key, seen)
            finally:
                os.close(child_fd)
        elif kind == stat.S_IFREG:
            file_fd = os.open(name, file_flags, dir_fd=directory_fd)
            try:
                reopened = os.fstat(file_fd)
                require_exact(reopened, child_expected, child_key)
                if (
                    reopened.st_nlink != 1
                    or stat.S_IMODE(reopened.st_mode) not in (0o400, 0o500)
                    or stat.S_IMODE(reopened.st_mode) & 0o222
                    or reopened.st_uid != expected_uid
                    or reopened.st_dev != snapshot_device
                ):
                    raise SealError(
                        f"regular file failed sealed-tree verification at "
                        f"{display(child_key)}"
                    )
            finally:
                os.close(file_fd)
            seen.add(child_key)
        else:
            raise SealError(
                f"symlink or special file appeared at {display(child_key)}"
            )
        require_exact(
            os.stat(name, dir_fd=directory_fd, follow_symlinks=False),
            child_expected,
            child_key,
        )


def seal_snapshot():
    global snapshot_device

    parent_path, snapshot_name = os.path.split(snapshot_path)
    if (
        not parent_path
        or snapshot_name in ("", ".", "..")
        or not os.path.isabs(snapshot_path)
    ):
        raise SealError("snapshot path is not a canonical-looking absolute child")

    parent_fd = os.open(parent_path, directory_flags)
    try:
        parent_metadata = os.fstat(parent_fd)
        if (
            stat.S_IFMT(parent_metadata.st_mode) != stat.S_IFDIR
            or parent_metadata.st_uid != expected_uid
            or stat.S_IMODE(parent_metadata.st_mode) & 0o022
        ):
            raise SealError("snapshot parent descriptor is unsafe")

        before = os.stat(
            snapshot_name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        snapshot_fd = os.open(
            snapshot_name,
            directory_flags,
            dir_fd=parent_fd,
        )
        try:
            opened = os.fstat(snapshot_fd)
            require_open_identity(before, opened, ())
            if opened.st_dev != parent_metadata.st_dev:
                raise SealError("snapshot root crosses the parent filesystem")
            snapshot_device = opened.st_dev
            seal_directory(snapshot_fd, (), opened)
        finally:
            os.close(snapshot_fd)

        require_exact(
            os.stat(
                snapshot_name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            ),
            sealed[()],
            (),
        )
        reopened_fd = os.open(
            snapshot_name,
            directory_flags,
            dir_fd=parent_fd,
        )
        try:
            require_exact(os.fstat(reopened_fd), sealed[()], ())
            seen = set()
            verify_directory(reopened_fd, (), seen)
        finally:
            os.close(reopened_fd)
    finally:
        os.close(parent_fd)

    if seen != set(sealed):
        raise SealError("sealed-tree verification did not cover every entry")
    return len(sealed)


try:
    sealed_count = seal_snapshot()
except (OSError, RuntimeError, ValueError) as error:
    print(f"error: cannot seal candidate snapshot: {error}", file=sys.stderr)
    raise SystemExit(1)

print(f"candidate_snapshot_sealed entries={sealed_count}")
'
SNAPSHOT_SEAL_ARGV=(
  "${TIMEOUT_BIN}"
  --signal=TERM
  --kill-after=5s
  2m
  "${ENV_BIN}"
  -i
  "PATH=${PATH}"
  "LC_ALL=${LC_ALL}"
  "HOME=${BUILD_HOME}"
  "TMPDIR=${BUILD_TMP}"
  "${PYTHON3_BIN}"
  -I
  -B
  -c
  "${SNAPSHOT_SEAL_PYTHON}"
  "${SOURCE_SNAPSHOT}"
)
readonly -a SNAPSHOT_SEAL_ARGV
print_argv "candidate_snapshot_seal_start" "${SNAPSHOT_SEAL_ARGV[@]}"
"${SNAPSHOT_SEAL_ARGV[@]}"

read -r snapshot_uid snapshot_mode snapshot_kind < <(
  "${STAT_BIN}" -c '%u %a %F' -- "${SOURCE_SNAPSHOT}"
)
[[ "${snapshot_uid}" == "${EUID}" && "${snapshot_mode}" == "500" &&
  "${snapshot_kind}" == "directory" ]] || {
  echo "error: source snapshot metadata is unsafe" >&2
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

readonly GO_MOD_JSON="${BUILD_TMP}/go-mod-edit.json"
[[ ! -e "${GO_MOD_JSON}" && ! -L "${GO_MOD_JSON}" ]] || {
  echo "error: Go module metadata path already exists" >&2
  exit 1
}
GO_MOD_EDIT_ARGV=(
  "${TIMEOUT_BIN}"
  --signal=TERM
  --kill-after=5s
  30s
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
  "GOTOOLCHAIN=local"
  "GOWORK=off"
  "${GO_BIN}"
  mod
  edit
  -json
)
readonly -a GO_MOD_EDIT_ARGV
print_argv "go_mod_edit_start" "${GO_MOD_EDIT_ARGV[@]}"
(
  set -o noclobber
  "${GO_MOD_EDIT_ARGV[@]}" >"${GO_MOD_JSON}"
)
read -r go_mod_uid go_mod_mode go_mod_links go_mod_size go_mod_kind < <(
  "${STAT_BIN}" -c '%u %a %h %s %F' -- "${GO_MOD_JSON}"
)
[[ "${go_mod_uid}" == "${EUID}" && "${go_mod_mode}" == "600" &&
  "${go_mod_links}" == "1" && "${go_mod_size}" -gt 0 &&
  "${go_mod_size}" -le 1048576 &&
  "${go_mod_kind}" == "regular file" ]] || {
  echo "error: Go module metadata is unsafe" >&2
  exit 1
}
"${CHMOD_BIN}" 0400 -- "${GO_MOD_JSON}"

readonly GO_MOD_POLICY_PYTHON='import json
import sys

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result

try:
    with open(sys.argv[1], "r", encoding="utf-8") as metadata_file:
        document = json.load(metadata_file, object_pairs_hook=unique_object)
except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
    print(f"error: invalid go mod edit JSON: {error}", file=sys.stderr)
    raise SystemExit(1)

if not isinstance(document, dict) or "Replace" not in document:
    print("error: go mod edit JSON has no Replace field", file=sys.stderr)
    raise SystemExit(1)

replacements = document["Replace"]
if replacements is None:
    replacements = []
if not isinstance(replacements, list):
    print("error: go mod edit Replace field is not a list", file=sys.stderr)
    raise SystemExit(1)

for index, replacement in enumerate(replacements):
    if not isinstance(replacement, dict) or set(replacement) != {"Old", "New"}:
        print(
            f"error: go mod edit Replace[{index}] has an invalid shape",
            file=sys.stderr,
        )
        raise SystemExit(1)
    old = replacement["Old"]
    new = replacement["New"]
    for endpoint_name, endpoint in (("Old", old), ("New", new)):
        if (
            not isinstance(endpoint, dict)
            or not isinstance(endpoint.get("Path"), str)
            or not endpoint["Path"]
            or not set(endpoint).issubset({"Path", "Version"})
            or (
                "Version" in endpoint
                and not isinstance(endpoint["Version"], str)
            )
        ):
            print(
                f"error: go mod edit Replace[{index}].{endpoint_name} "
                "has an invalid shape",
                file=sys.stderr,
            )
            raise SystemExit(1)
    if new.get("Version", "") == "":
        print(
            "error: candidate go.mod contains a forbidden local replacement "
            f"at Replace[{index}]",
            file=sys.stderr,
        )
        raise SystemExit(1)

print(f"go_mod_policy replacements={len(replacements)} local=0")
'
GO_MOD_POLICY_ARGV=(
  "${TIMEOUT_BIN}"
  --signal=TERM
  --kill-after=5s
  30s
  "${ENV_BIN}"
  -i
  "PATH=${PATH}"
  "LC_ALL=${LC_ALL}"
  "HOME=${BUILD_HOME}"
  "TMPDIR=${BUILD_TMP}"
  "${PYTHON3_BIN}"
  -I
  -B
  -c
  "${GO_MOD_POLICY_PYTHON}"
  "${GO_MOD_JSON}"
)
readonly -a GO_MOD_POLICY_ARGV
print_argv "go_mod_policy_start" "${GO_MOD_POLICY_ARGV[@]}"
"${GO_MOD_POLICY_ARGV[@]}"

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
