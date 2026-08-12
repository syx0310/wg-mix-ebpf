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
readonly PYTHON_BIN="/usr/bin/python3"
readonly READLINK_BIN="/usr/bin/readlink"
readonly SHA256_BIN="/usr/bin/sha256sum"
readonly STAT_BIN="/usr/bin/stat"
readonly APPROVED_SOURCE_MAX_BYTES=16777216
readonly APPROVED_SOURCE_COPY_PROGRAM_VERSION="1"
readonly BOOTSTRAP_PREFIX="/run/wg-mix-ebpf-source-bootstrap"
readonly STAGE_PREFIX="/var/tmp/wg-mix-ebpf-source-stages"
readonly RUNNER_BASENAME="run-root-owned-test-source-stage.sh"
readonly LAUNCHER_BASENAME="stage-root-owned-test-source.sh"
readonly HELPER_BASENAME="stage-root-owned-test-source.py"
readonly MANIFEST_BASENAME="stage-root-owned-test-source.bootstrap"
# This exact isolated -c program is covered by the externally approved runner
# SHA-256. It never imports or executes a helper from the user-owned checkout.
readonly APPROVED_SOURCE_COPY_PROGRAM='import hashlib
import os
import stat
import sys

CHUNK_BYTES = 65536
HEX_DIGITS = frozenset("0123456789abcdef")
PROGRAM_VERSION = "1"
PROGRAM_MAX_BYTES = 16777216


def fail(message):
    raise ValueError(message)


def exact_stat(metadata):
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def hash_exact_size(descriptor, expected_size, label):
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    remaining = expected_size
    while remaining:
        chunk = os.read(descriptor, min(CHUNK_BYTES, remaining))
        if not chunk:
            fail(f"{label} became shorter while hashing")
        digest.update(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1) != b"":
        fail(f"{label} became larger while hashing")
    return digest.hexdigest()


def write_all(descriptor, data):
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            fail("target write made no progress")
        view = view[written:]


def copy_exact_size(source_fd, target_fd, expected_size):
    os.lseek(source_fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    remaining = expected_size
    while remaining:
        chunk = os.read(source_fd, min(CHUNK_BYTES, remaining))
        if not chunk:
            fail("source became shorter while copying")
        digest.update(chunk)
        write_all(target_fd, chunk)
        remaining -= len(chunk)
    if os.read(source_fd, 1) != b"":
        fail("source became larger while copying")
    return digest.hexdigest()


def main():
    if len(sys.argv) != 7:
        fail("expected version, source, sha256, target, mode, and max bytes")
    version, source, approved_sha256, target, mode_text, max_text = sys.argv[1:]
    if version != PROGRAM_VERSION:
        fail("approved source copier version mismatch")
    if len(approved_sha256) != 64 or any(
        character not in HEX_DIGITS for character in approved_sha256
    ):
        fail("approved SHA-256 is malformed")
    if not os.path.isabs(source) or os.path.normpath(source) != source:
        fail("source path is not canonical and absolute")
    if not os.path.isabs(target) or os.path.normpath(target) != target:
        fail("target path is not canonical and absolute")
    if source == target:
        fail("source and target paths must differ")
    modes = {"0500": 0o500, "0400": 0o400}
    if mode_text not in modes:
        fail("target mode is not approved")
    try:
        max_bytes = int(max_text, 10)
    except ValueError:
        fail("maximum byte count is malformed")
    if str(max_bytes) != max_text or max_bytes != PROGRAM_MAX_BYTES:
        fail("maximum byte count does not match the program contract")

    source_flags = (
        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    )
    target_fd = -1
    source_fd = os.open(source, source_flags)
    try:
        source_before = os.fstat(source_fd)
        if not stat.S_ISREG(source_before.st_mode):
            fail("source descriptor is not a regular file")
        if source_before.st_nlink != 1:
            fail("source descriptor does not have exactly one link")
        if source_before.st_size < 0 or source_before.st_size > max_bytes:
            fail("source descriptor exceeds the approved byte limit")
        source_identity = exact_stat(source_before)
        source_sha_before = hash_exact_size(
            source_fd, source_before.st_size, "source"
        )
        source_after_hash = os.fstat(source_fd)
        if exact_stat(source_after_hash) != source_identity:
            fail("source descriptor changed while hashing")
        if source_sha_before != approved_sha256:
            fail("source descriptor SHA-256 mismatch")

        target_flags = (
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | os.O_CLOEXEC
        )
        target_fd = os.open(target, target_flags, modes[mode_text])
        target_created = os.fstat(target_fd)
        if not stat.S_ISREG(target_created.st_mode):
            fail("new target descriptor is not a regular file")
        if target_created.st_nlink != 1 or target_created.st_size != 0:
            fail("new target descriptor metadata is unsafe")

        copied_sha256 = copy_exact_size(
            source_fd, target_fd, source_before.st_size
        )
        os.fchmod(target_fd, modes[mode_text])
        os.fsync(target_fd)

        source_after_copy = os.fstat(source_fd)
        if exact_stat(source_after_copy) != source_identity:
            fail("source descriptor changed while copying")
        source_sha_after = hash_exact_size(
            source_fd, source_before.st_size, "source"
        )
        source_final = os.fstat(source_fd)
        if exact_stat(source_final) != source_identity:
            fail("source descriptor changed during final hashing")
        if source_sha_after != approved_sha256 or copied_sha256 != approved_sha256:
            fail("source descriptor or copied bytes failed final SHA-256")

        target_after_copy = os.fstat(target_fd)
        if not stat.S_ISREG(target_after_copy.st_mode):
            fail("copied target descriptor is not a regular file")
        if target_after_copy.st_nlink != 1:
            fail("copied target descriptor does not have exactly one link")
        if target_after_copy.st_size != source_before.st_size:
            fail("copied target size mismatch")
        if stat.S_IMODE(target_after_copy.st_mode) != modes[mode_text]:
            fail("copied target mode mismatch")
        target_identity = exact_stat(target_after_copy)
        target_sha256 = hash_exact_size(
            target_fd, source_before.st_size, "target"
        )
        if exact_stat(os.fstat(target_fd)) != target_identity:
            fail("target descriptor changed during final hashing")
        if target_sha256 != approved_sha256:
            fail("target descriptor SHA-256 mismatch")
        print(
            f"version={version} bytes={source_before.st_size} "
            f"source_sha256={source_sha_after} target={target}"
        )
    finally:
        if target_fd >= 0:
            os.close(target_fd)
        os.close(source_fd)


try:
    main()
except (OSError, ValueError) as error:
    print(f"error: approved source copier: {error}", file=sys.stderr)
    sys.exit(1)'
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
  "${ENV_BIN}" "${HOSTNAME_BIN}" "${INSTALL_BIN}" "${PYTHON_BIN}" \
  "${READLINK_BIN}" "${SHA256_BIN}" "${STAT_BIN}"; do
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
[[ ! -L "${AUDIT_PATH}" && -f "${AUDIT_PATH}" &&
  "$("${STAT_BIN}" -Lc '%u:%g:%a:%h:%s' -- "${AUDIT_PATH}")" == \
  "0:0:600:1:0" ]] || {
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
  "stat=0:0:600:1:0 type=regular-file"
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

copy_approved_source() {
  local label="$1"
  local source="$2"
  local approved_sha="$3"
  local target="$4"
  local mode="$5"
  local -a copy_argv=(
    "${PYTHON_BIN}" -I -B -c "${APPROVED_SOURCE_COPY_PROGRAM}"
    "${APPROVED_SOURCE_COPY_PROGRAM_VERSION}"
    "${source}" "${approved_sha}" "${target}" "${mode}"
    "${APPROVED_SOURCE_MAX_BYTES}"
  )

  run_write "copy_root_${label}" "${target}" "${copy_argv[@]}"
}

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

copy_approved_source launcher "${SOURCE_LAUNCHER}" "${LAUNCHER_SHA256}" \
  "${root_launcher}" 0500
validate_root_copy launcher "${root_launcher}" 500 "${LAUNCHER_SHA256}"

copy_approved_source helper "${SOURCE_HELPER}" "${HELPER_SHA256}" \
  "${root_helper}" 0400
validate_root_copy helper "${root_helper}" 400 "${HELPER_SHA256}"

copy_approved_source manifest "${SOURCE_MANIFEST}" "${MANIFEST_SHA256}" \
  "${root_manifest}" 0400
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
