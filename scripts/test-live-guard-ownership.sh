#!/bin/bash
set -euo pipefail

readonly RUN_PREFIX="/var/lib/wg-mix-ebpf-test-runs"
readonly PATH="/usr/sbin:/usr/bin:/sbin:/bin"
readonly LC_ALL="C"
readonly ENV_BIN="/usr/bin/env"
readonly PYTHON3_BIN="/usr/bin/python3"
readonly SHA256_BIN="/usr/bin/sha256sum"
readonly TIMEOUT_BIN="/usr/bin/timeout"
export PATH LC_ALL
umask 077

usage() {
  cat <<'EOF'
usage:
  scripts/test-live-guard-ownership.sh --self-test-safety-gate

Privileged mode MUST NOT execute the user-owned repository script. For a
reviewed run-id, first use separately approved fixed argv to install the exact
reviewed script into:

  /var/lib/wg-mix-ebpf-test-runs/<run-id>.gate/test-live-guard-ownership.sh

The staging directory and script must be root-owned mode 0700, and the staged
script SHA-256 must match the reviewed blob. Before invocation, the separately
reviewed staging command must also create, with O_EXCL semantics, fsync, and
root ownership/mode 0600:

  /var/lib/wg-mix-ebpf-test-runs/<run-id>.gate/run.manifest

The manifest is a JSON object with exactly these fields:

  version, run_id, candidate_commit, expected_hostname, expected_kernel,
  expected_machine_id, expected_address, interface,
  approved_script_sha256, staged_script_path, test_binary_path,
  test_binary_sha256

version must be the JSON integer 1; every other value is the exact string later
passed to this script. The manifest binds the staged inputs but does not prove
or replace review of the complete sudo and staging argv. After that separate
review and durable staging, invoke the staged script exactly:

  sudo /usr/bin/env -i \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin \
    LC_ALL=C \
    /bin/bash \
    /var/lib/wg-mix-ebpf-test-runs/g20260729t120000z-012345abcdef.gate/test-live-guard-ownership.sh \
    --approved-script-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
    --expected-address 192.168.10.82 \
    --interface ens33 \
    --expected-hostname ubuntu-2604-test \
    --expected-kernel 7.0.0-28-generic \
    --expected-machine-id 0123456789abcdef0123456789abcdef \
    --candidate-commit 0123456789abcdef0123456789abcdef01234567 \
    --run-id g20260729t120000z-012345abcdef \
    --test-binary /absolute/path/guard-live.test \
    --test-binary-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

The outer, separately reviewed staging argv may create the fixed project
prefix and the root-owned <run-id>.gate directory. This script requires those
objects to exist and writes only one new unique child:

  /var/lib/wg-mix-ebpf-test-runs/<run-id>

It persists run.owner, fsyncs that file, the run directory, and RUN_PREFIX in
that order before creating state, evidence, tmp, or the evidence log. Any
failure stops the sequence and retains the exact run.owner already recorded.

It temporarily creates one empty, instance-owned inet nftables guard table.
The test validates its marker and handle, replaces it, deletes it by validated
handle, and verifies an idempotent second cleanup. A failed run keeps all
evidence and performs no automatic cleanup.
EOF
}

valid_run_id() {
  [[ "$1" =~ ^g[0-9]{8}t[0-9]{6}z-[0-9a-f]{12}$ ]]
}

valid_sha256() {
  [[ "$1" =~ ^[0-9a-f]{64}$ ]]
}

mode_has_no_group_or_other_write() {
  local mode="$1"

  [[ "${mode}" =~ ^[0-7]{3,4}$ ]] || return 1
  (((8#${mode} & 8#022) == 0))
}

validate_secure_directory() {
  local path="$1"
  local expected_uid="$2"
  local expected_mode="${3:-}"
  local resolved
  local uid
  local mode
  local kind

  [[ -d "${path}" && ! -L "${path}" ]] || {
    printf 'error: expected a real directory: %s\n' "${path}" >&2
    return 1
  }
  resolved="$(readlink -e -- "${path}")"
  [[ "${resolved}" == "${path}" ]] || {
    printf 'error: directory is not canonical: configured=%s resolved=%s\n' \
      "${path}" "${resolved}" >&2
    return 1
  }
  read -r uid mode kind < <(stat -c '%u %a %F' -- "${path}")
  [[ "${uid}" == "${expected_uid}" && "${kind}" == "directory" ]] || {
    printf 'error: unsafe directory identity: path=%s uid=%s type=%s\n' \
      "${path}" "${uid}" "${kind}" >&2
    return 1
  }
  mode_has_no_group_or_other_write "${mode}" || {
    printf 'error: directory is group/other writable: path=%s mode=%s\n' \
      "${path}" "${mode}" >&2
    return 1
  }
  if [[ -n "${expected_mode}" && "${mode}" != "${expected_mode}" ]]; then
    printf 'error: directory mode mismatch: path=%s mode=%s expected=%s\n' \
      "${path}" "${mode}" "${expected_mode}" >&2
    return 1
  fi
}

run_isolated_python() {
  local isolated_home="$1"
  local isolated_tmp="$2"
  shift 2

  "${ENV_BIN}" -i \
    "PATH=${PATH}" \
    "LC_ALL=${LC_ALL}" \
    "HOME=${isolated_home}" \
    "TMPDIR=${isolated_tmp}" \
    "${PYTHON3_BIN}" -I -B "$@"
}

validate_gate_manifest() {
  local manifest_path="$1"
  local expected_run_id="$2"
  local expected_commit="$3"
  local expected_hostname="$4"
  local expected_kernel="$5"
  local expected_machine_id="$6"
  local expected_address="$7"
  local expected_interface="$8"
  local expected_script_sha256="$9"
  local expected_script_path="${10}"
  local expected_test_binary_path="${11}"
  local expected_test_binary_sha256="${12}"
  local gate_dir

  gate_dir="$(dirname -- "${manifest_path}")"
  run_isolated_python "${gate_dir}" "${gate_dir}" - \
    "${manifest_path}" \
    "${expected_run_id}" \
    "${expected_commit}" \
    "${expected_hostname}" \
    "${expected_kernel}" \
    "${expected_machine_id}" \
    "${expected_address}" \
    "${expected_interface}" \
    "${expected_script_sha256}" \
    "${expected_script_path}" \
    "${expected_test_binary_path}" \
    "${expected_test_binary_sha256}" <<'PY'
import hashlib
import json
import os
import stat
import sys

(
    path,
    expected_run_id,
    expected_commit,
    expected_hostname,
    expected_kernel,
    expected_machine_id,
    expected_address,
    expected_interface,
    expected_script_sha256,
    expected_script_path,
    expected_test_binary_path,
    expected_test_binary_sha256,
) = sys.argv[1:]

flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
fd = os.open(path, flags)
try:
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode):
        raise RuntimeError("gate manifest is not a regular file")
    if stat.S_IMODE(before.st_mode) != 0o600:
        raise RuntimeError("gate manifest mode is not 0600")
    if before.st_uid != 0 or before.st_nlink != 1:
        raise RuntimeError("gate manifest ownership or link count is unsafe")
    if before.st_size <= 0 or before.st_size > 4096:
        raise RuntimeError("gate manifest size is outside the 1..4096 byte gate")
    data = bytearray()
    while len(data) <= 4096:
        chunk = os.read(fd, 4097 - len(data))
        if not chunk:
            break
        data.extend(chunk)
    after = os.fstat(fd)
    if (
        len(data) != before.st_size
        or len(data) > 4096
        or (after.st_dev, after.st_ino, after.st_size)
        != (before.st_dev, before.st_ino, before.st_size)
    ):
        raise RuntimeError("gate manifest changed while reading")
    named = os.stat(path, follow_symlinks=False)
    if (named.st_dev, named.st_ino) != (before.st_dev, before.st_ino):
        raise RuntimeError("gate manifest name does not match the opened descriptor")
finally:
    os.close(fd)

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result

document = json.loads(data, object_pairs_hook=unique_object)
expected = {
    "version": 1,
    "run_id": expected_run_id,
    "candidate_commit": expected_commit,
    "expected_hostname": expected_hostname,
    "expected_kernel": expected_kernel,
    "expected_machine_id": expected_machine_id,
    "expected_address": expected_address,
    "interface": expected_interface,
    "approved_script_sha256": expected_script_sha256,
    "staged_script_path": expected_script_path,
    "test_binary_path": expected_test_binary_path,
    "test_binary_sha256": expected_test_binary_sha256,
}
if not isinstance(document, dict) or set(document) != set(expected):
    raise RuntimeError("gate manifest keys are invalid")
if type(document["version"]) is not int or document["version"] != 1:
    raise RuntimeError("gate manifest version is not the integer 1")
for key, value in expected.items():
    if key == "version":
        continue
    if type(document[key]) is not str or document[key] != value:
        raise RuntimeError(f"gate manifest field mismatch: {key}")
print(hashlib.sha256(data).hexdigest())
PY
}

initialize_run_layout() {
  local run_prefix="$1"
  local run_dir="$2"
  local manifest_path="$3"
  local evidence_log="$4"
  local expected_uid="$5"
  local failure_point="$6"
  local run_id="$7"
  local candidate_commit="$8"
  local expected_hostname="$9"
  local expected_kernel="${10}"
  local expected_machine_id="${11}"
  local expected_address="${12}"
  local interface="${13}"
  local approved_script_sha256="${14}"
  local gate_manifest_path="${15}"
  local gate_manifest_sha256="${16}"
  local staged_script_path="${17}"
  local test_binary_path="${18}"
  local test_binary_sha256="${19}"
  local state_dir="${20}"
  local evidence_dir="${21}"
  local tmp_dir="${22}"

  run_isolated_python "${run_dir}" "${run_dir}" - \
    "${run_prefix}" \
    "${run_dir}" \
    "${manifest_path}" \
    "${evidence_log}" \
    "${expected_uid}" \
    "${failure_point}" \
    "${run_id}" \
    "${candidate_commit}" \
    "${expected_hostname}" \
    "${expected_kernel}" \
    "${expected_machine_id}" \
    "${expected_address}" \
    "${interface}" \
    "${approved_script_sha256}" \
    "${gate_manifest_path}" \
    "${gate_manifest_sha256}" \
    "${staged_script_path}" \
    "${test_binary_path}" \
    "${test_binary_sha256}" \
    "${state_dir}" \
    "${evidence_dir}" \
    "${tmp_dir}" <<'PY'
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import stat
import sys

(
    run_prefix,
    run_dir,
    manifest_path,
    evidence_log,
    expected_uid_text,
    failure_point,
    run_id,
    candidate_commit,
    expected_hostname,
    expected_kernel,
    expected_machine_id,
    expected_address,
    interface,
    approved_script_sha256,
    gate_manifest_path,
    gate_manifest_sha256,
    staged_script_path,
    test_binary_path,
    test_binary_sha256,
    state_dir,
    evidence_dir,
    tmp_dir,
) = sys.argv[1:]
expected_uid = int(expected_uid_text)
allowed_failures = {"", "prefix_fsync", "state", "evidence", "tmp", "log"}
if failure_point not in allowed_failures:
    raise RuntimeError(f"unknown run-layout failure point: {failure_point}")
marker = f"wg-mix-ebpf-live-guard-run-v1:{run_id}"
if not re.fullmatch(
    r"wg-mix-ebpf-live-guard-run-v1:g[0-9]{8}t[0-9]{6}z-[0-9a-f]{12}",
    marker,
):
    raise RuntimeError("run marker is invalid")

if (
    run_dir != run_prefix + "/" + run_id
    or manifest_path != run_dir + "/run.owner"
    or state_dir != run_dir + "/state"
    or evidence_dir != run_dir + "/evidence"
    or tmp_dir != run_dir + "/tmp"
    or evidence_log != evidence_dir + "/guard-live.log"
):
    raise RuntimeError("run-layout paths are not exact children of the fixed prefix")
if os.path.realpath(run_prefix) != run_prefix:
    raise RuntimeError("run prefix is not canonical")
prefix_fd = os.open(
    run_prefix,
    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
)
prefix_stat = os.fstat(prefix_fd)
named_prefix = os.stat(run_prefix, follow_symlinks=False)
if (
    not stat.S_ISDIR(prefix_stat.st_mode)
    or stat.S_IMODE(prefix_stat.st_mode) != 0o700
    or prefix_stat.st_uid != expected_uid
    or (named_prefix.st_dev, named_prefix.st_ino)
    != (prefix_stat.st_dev, prefix_stat.st_ino)
):
    os.close(prefix_fd)
    raise RuntimeError("run prefix identity is unsafe")
run_fd = os.open(
    run_id,
    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    dir_fd=prefix_fd,
)
run_stat = os.fstat(run_fd)
named_run = os.stat(run_id, dir_fd=prefix_fd, follow_symlinks=False)
if (
    not stat.S_ISDIR(run_stat.st_mode)
    or stat.S_IMODE(run_stat.st_mode) != 0o700
    or run_stat.st_uid != expected_uid
    or os.path.realpath(run_dir) != run_dir
    or (named_run.st_dev, named_run.st_ino) != (run_stat.st_dev, run_stat.st_ino)
):
    os.close(run_fd)
    os.close(prefix_fd)
    raise RuntimeError("run directory identity is unsafe")

created_at = datetime.now(timezone.utc).isoformat()
document = {
    "version": 1,
    "marker": marker,
    "run_id": run_id,
    "run_prefix": run_prefix,
    "run_dir": run_dir,
    "candidate_commit": candidate_commit,
    "expected_hostname": expected_hostname,
    "expected_kernel": expected_kernel,
    "expected_machine_id": expected_machine_id,
    "expected_address": expected_address,
    "interface": interface,
    "approved_script_sha256": approved_script_sha256,
    "gate_manifest_path": gate_manifest_path,
    "gate_manifest_sha256": gate_manifest_sha256,
    "staged_script_path": staged_script_path,
    "test_binary_path": test_binary_path,
    "test_binary_sha256": test_binary_sha256,
    "state_dir": state_dir,
    "evidence_dir": evidence_dir,
    "tmp_dir": tmp_dir,
    "created_at": created_at,
}
payload = (
    json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    + "\n"
).encode("ascii")
if not 0 < len(payload) <= 4096:
    raise RuntimeError("run ownership manifest exceeds the 4096-byte gate")

def write_all(fd, data):
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise RuntimeError("short write while persisting run evidence")
        view = view[written:]

def create_and_sync(data):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    fd = os.open("run.owner", flags, 0o600, dir_fd=run_fd)
    try:
        write_all(fd, data)
        os.fchmod(fd, 0o600)
        os.fsync(fd)
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_uid != expected_uid
            or opened.st_nlink != 1
            or opened.st_size != len(data)
        ):
            raise RuntimeError("new run ownership manifest metadata is unsafe")
        named = os.stat("run.owner", dir_fd=run_fd, follow_symlinks=False)
        if (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino):
            raise RuntimeError("new run ownership manifest name changed")
    finally:
        os.close(fd)
    os.fsync(run_fd)

def inject_failure(point):
    if failure_point == point:
        raise RuntimeError(f"injected run-layout failure: {point}")

def create_run_directory(name, point):
    inject_failure(point)
    os.mkdir(name, 0o700, dir_fd=run_fd)
    child_fd = os.open(
        name,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=run_fd,
    )
    try:
        opened = os.fstat(child_fd)
        named = os.stat(name, dir_fd=run_fd, follow_symlinks=False)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or stat.S_IMODE(opened.st_mode) != 0o700
            or opened.st_uid != expected_uid
            or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise RuntimeError(f"new run directory metadata is unsafe: {name}")
        os.fsync(child_fd)
    finally:
        os.close(child_fd)
    os.fsync(run_fd)

def create_evidence_log():
    inject_failure("log")
    evidence_fd = os.open(
        "evidence",
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=run_fd,
    )
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
        log_fd = os.open("guard-live.log", flags, 0o600, dir_fd=evidence_fd)
        try:
            os.fchmod(log_fd, 0o600)
            os.fsync(log_fd)
            opened = os.fstat(log_fd)
            named = os.stat(
                "guard-live.log",
                dir_fd=evidence_fd,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISREG(opened.st_mode)
                or stat.S_IMODE(opened.st_mode) != 0o600
                or opened.st_uid != expected_uid
                or opened.st_nlink != 1
                or opened.st_size != 0
                or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino)
            ):
                raise RuntimeError("new evidence log metadata is unsafe")
        finally:
            os.close(log_fd)
        os.fsync(evidence_fd)
    finally:
        os.close(evidence_fd)

manifest_sha256 = hashlib.sha256(payload).hexdigest()
manifest_persisted = False
try:
    create_and_sync(payload)

    # Reopen and verify the durable ownership manifest before returning to the
    # caller that creates any other run child.
    read_fd = os.open(
        "run.owner",
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
        dir_fd=run_fd,
    )
    try:
        persisted = os.read(read_fd, len(payload) + 1)
        opened = os.fstat(read_fd)
        named = os.stat("run.owner", dir_fd=run_fd, follow_symlinks=False)
        if (
            persisted != payload
            or opened.st_size != len(payload)
            or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise RuntimeError("durable run ownership manifest validation failed")
        manifest_stat = opened
    finally:
        os.close(read_fd)
    manifest_persisted = True
    after_run = os.fstat(run_fd)
    named_run = os.stat(run_id, dir_fd=prefix_fd, follow_symlinks=False)
    if (
        (after_run.st_dev, after_run.st_ino) != (run_stat.st_dev, run_stat.st_ino)
        or (named_run.st_dev, named_run.st_ino)
        != (run_stat.st_dev, run_stat.st_ino)
        or stat.S_IMODE(after_run.st_mode) != 0o700
        or after_run.st_uid != expected_uid
    ):
        raise RuntimeError("run directory changed while persisting ownership")
    inject_failure("prefix_fsync")
    os.fsync(prefix_fd)
    after_prefix = os.fstat(prefix_fd)
    named_prefix = os.stat(run_prefix, follow_symlinks=False)
    if (
        (after_prefix.st_dev, after_prefix.st_ino)
        != (prefix_stat.st_dev, prefix_stat.st_ino)
        or (named_prefix.st_dev, named_prefix.st_ino)
        != (prefix_stat.st_dev, prefix_stat.st_ino)
        or stat.S_IMODE(after_prefix.st_mode) != 0o700
        or after_prefix.st_uid != expected_uid
    ):
        raise RuntimeError("run prefix changed while persisting ownership")

    create_run_directory("state", "state")
    create_run_directory("evidence", "evidence")
    create_run_directory("tmp", "tmp")
    create_evidence_log()
except Exception:
    if manifest_persisted:
        print(
            "run_manifest_retained"
            f" path={manifest_path}"
            f" sha256={manifest_sha256}"
            f" device={manifest_stat.st_dev}"
            f" inode={manifest_stat.st_ino}"
            f" uid={manifest_stat.st_uid}"
            f" mode={stat.S_IMODE(manifest_stat.st_mode):04o}"
            f" nlink={manifest_stat.st_nlink}"
            f" size={manifest_stat.st_size}"
            f" failure_point={failure_point or 'system'}",
            file=sys.stderr,
            flush=True,
        )
    raise
finally:
    os.close(run_fd)
    os.close(prefix_fd)
print(manifest_sha256)
PY
}

validate_locked_script() {
  local run_id="$1"
  local expected_sha256="$2"
  local gate_dir="${RUN_PREFIX}/${run_id}.gate"
  local expected_path="${gate_dir}/test-live-guard-ownership.sh"
  local configured_path="${BASH_SOURCE[0]}"
  local resolved_path
  local before_identity
  local after_identity
  local descriptor_path
  local descriptor_identity
  local script_shell_pid
  local uid
  local mode
  local links
  local kind
  local actual_sha256

  validate_secure_directory "${gate_dir}" 0 700
  [[ "${configured_path}" == /* && -f "${configured_path}" && ! -L "${configured_path}" ]] || {
    printf 'error: privileged gate script path is not absolute, regular, and non-symlink: %s\n' \
      "${configured_path}" >&2
    return 1
  }
  resolved_path="$(readlink -e -- "${configured_path}")"
  [[ "${resolved_path}" == "${expected_path}" ]] || {
    printf 'error: privileged gate script path mismatch: resolved=%s expected=%s\n' \
      "${resolved_path}" "${expected_path}" >&2
    return 1
  }
  read -r before_identity uid mode links kind < <(
    stat -c '%d:%i %u %a %h %F' -- "${resolved_path}"
  )
  [[ "${uid}" == "0" && "${mode}" == "700" &&
    "${links}" == "1" && "${kind}" == "regular file" ]] || {
    printf 'error: staged gate script metadata is unsafe: uid=%s mode=%s links=%s type=%s\n' \
      "${uid}" "${mode}" "${links}" "${kind}" >&2
    return 1
  }
  script_shell_pid="${BASHPID}"
  descriptor_path="/proc/${script_shell_pid}/fd/255"
  [[ -r "${descriptor_path}" ]] || {
    echo "error: Bash script descriptor 255 is unavailable" >&2
    return 1
  }
  descriptor_identity="$(stat -Lc '%d:%i' -- "${descriptor_path}")"
  [[ "${descriptor_identity}" == "${before_identity}" ]] || {
    printf 'error: executing script descriptor identity %s does not match staged path %s\n' \
      "${descriptor_identity}" "${before_identity}" >&2
    return 1
  }
  actual_sha256="$("${SHA256_BIN}" -- "${descriptor_path}")"
  actual_sha256="${actual_sha256%% *}"
  [[ "${actual_sha256}" == "${expected_sha256}" ]] || {
    printf 'error: staged gate script SHA-256 mismatch: got=%s want=%s\n' \
      "${actual_sha256}" "${expected_sha256}" >&2
    return 1
  }
  after_identity="$(stat -c '%d:%i' -- "${resolved_path}")"
  [[ "${after_identity}" == "${before_identity}" ]] || {
    echo "error: staged gate script identity changed while hashing" >&2
    return 1
  }
}

valid_live_test_list() {
  local exit_code="$1"
  local output="$2"

  [[ "${exit_code}" == "0" && "${output}" == "TestLiveGuardOwnership" ]]
}

self_test_run_evidence_failures() {
  local fixture_root
  local fixture_sha
  local failure_point
  local run_id
  local run_dir
  local output
  local exit_code
  local index
  local success_run_id
  local success_run_dir
  local success_sha256
  local -a failure_points=(prefix_fsync state evidence tmp log)
  local -a run_ids=(
    g20260729t120001z-012345abcdef
    g20260729t120002z-012345abcdef
    g20260729t120003z-012345abcdef
    g20260729t120004z-012345abcdef
    g20260729t120005z-012345abcdef
  )

  fixture_root="$(
    run_isolated_python "${PWD}" "/tmp" - <<'PY'
import os
import tempfile

root = tempfile.mkdtemp(prefix="wg-mix-ebpf-live-guard-selftest-", dir="/tmp")
os.chmod(root, 0o700)
print(os.path.realpath(root))
PY
  )"
  fixture_sha="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

  for ((index = 0; index < ${#failure_points[@]}; index++)); do
    failure_point="${failure_points[index]}"
    run_id="${run_ids[index]}"
    run_dir="${fixture_root}/${run_id}"
    run_isolated_python "${fixture_root}" "${fixture_root}" - "${run_dir}" <<'PY'
import os
import sys

os.mkdir(sys.argv[1], 0o700)
os.chmod(sys.argv[1], 0o700)
PY

    set +e
    output="$(
      initialize_run_layout \
        "${fixture_root}" \
        "${run_dir}" \
        "${run_dir}/run.owner" \
        "${run_dir}/evidence/guard-live.log" \
        "${EUID}" \
        "${failure_point}" \
        "${run_id}" \
        "0123456789abcdef0123456789abcdef01234567" \
        "fixture-host" \
        "7.0.0-28-generic" \
        "0123456789abcdef0123456789abcdef" \
        "192.0.2.1" \
        "fixture0" \
        "${fixture_sha}" \
        "${fixture_root}/${run_id}.gate/run.manifest" \
        "${fixture_sha}" \
        "${fixture_root}/${run_id}.gate/test-live-guard-ownership.sh" \
        "${fixture_root}/guard-live.test" \
        "${fixture_sha}" \
        "${run_dir}/state" \
        "${run_dir}/evidence" \
        "${run_dir}/tmp" 2>&1
    )"
    exit_code=$?
    set -e
    ((exit_code != 0)) || {
      printf 'error: injected run-layout failure unexpectedly succeeded: %s\n' \
        "${failure_point}" >&2
      return 1
    }

    run_isolated_python "${fixture_root}" "${fixture_root}" - \
      "${fixture_root}" \
      "${run_dir}" \
      "${run_id}" \
      "${failure_point}" \
      "${exit_code}" \
      "${output}" \
      "${fixture_sha}" <<'PY'
import hashlib
import json
import os
import re
import stat
import sys

(
    run_prefix,
    run_dir,
    run_id,
    failure_point,
    exit_code_text,
    output,
    fixture_sha,
) = sys.argv[1:]
if int(exit_code_text) == 0:
    raise RuntimeError("injected production run-layout path returned zero")

retained = re.search(
    r"run_manifest_retained"
    r" path=(?P<path>\S+)"
    r" sha256=(?P<sha>[0-9a-f]{64})"
    r" device=(?P<device>[0-9]+)"
    r" inode=(?P<inode>[0-9]+)"
    r" uid=(?P<uid>[0-9]+)"
    r" mode=(?P<mode>[0-7]{4})"
    r" nlink=(?P<nlink>[0-9]+)"
    r" size=(?P<size>[0-9]+)"
    r" failure_point=(?P<failure>[a-z_]+)",
    output,
)
if retained is None or retained.group("failure") != failure_point:
    raise RuntimeError("injected failure lacks exact retained-manifest evidence")
path = retained.group("path")
if path != run_dir + "/run.owner":
    raise RuntimeError("retained-manifest evidence path mismatch")

flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
fd = os.open(path, flags)
try:
    before = os.fstat(fd)
    data = bytearray()
    while len(data) <= 4096:
        chunk = os.read(fd, 4097 - len(data))
        if not chunk:
            break
        data.extend(chunk)
    after = os.fstat(fd)
    named = os.stat(path, follow_symlinks=False)
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_uid != os.geteuid()
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > 4096
        or len(data) != before.st_size
        or (after.st_dev, after.st_ino, after.st_size)
        != (before.st_dev, before.st_ino, before.st_size)
        or (named.st_dev, named.st_ino) != (before.st_dev, before.st_ino)
    ):
        raise RuntimeError("retained run ownership manifest is unsafe or changed")
finally:
    os.close(fd)

if (
    retained.group("sha") != hashlib.sha256(data).hexdigest()
    or int(retained.group("device")) != before.st_dev
    or int(retained.group("inode")) != before.st_ino
    or int(retained.group("uid")) != before.st_uid
    or retained.group("mode") != f"{stat.S_IMODE(before.st_mode):04o}"
    or int(retained.group("nlink")) != before.st_nlink
    or int(retained.group("size")) != before.st_size
):
    raise RuntimeError("retained run.owner content, SHA, or identity changed")

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result

document = json.loads(data, object_pairs_hook=unique_object)
expected_keys = {
    "version",
    "marker",
    "run_id",
    "run_prefix",
    "run_dir",
    "candidate_commit",
    "expected_hostname",
    "expected_kernel",
    "expected_machine_id",
    "expected_address",
    "interface",
    "approved_script_sha256",
    "gate_manifest_path",
    "gate_manifest_sha256",
    "staged_script_path",
    "test_binary_path",
    "test_binary_sha256",
    "state_dir",
    "evidence_dir",
    "tmp_dir",
    "created_at",
}
if not isinstance(document, dict) or set(document) != expected_keys:
    raise RuntimeError("retained run ownership manifest schema is invalid")
if type(document["version"]) is not int or document["version"] != 1:
    raise RuntimeError("retained run ownership manifest version is invalid")
if (
    document["marker"] != f"wg-mix-ebpf-live-guard-run-v1:{run_id}"
    or document["run_id"] != run_id
    or document["run_prefix"] != run_prefix
    or document["run_dir"] != run_dir
    or document["candidate_commit"]
    != "0123456789abcdef0123456789abcdef01234567"
    or document["gate_manifest_sha256"] != fixture_sha
    or document["test_binary_sha256"] != fixture_sha
    or document["state_dir"] != run_dir + "/state"
    or document["evidence_dir"] != run_dir + "/evidence"
    or document["tmp_dir"] != run_dir + "/tmp"
):
    raise RuntimeError("retained run ownership manifest bindings are invalid")

expected_entries = {
    "prefix_fsync": ["run.owner"],
    "state": ["run.owner"],
    "evidence": ["run.owner", "state"],
    "tmp": ["evidence", "run.owner", "state"],
    "log": ["evidence", "run.owner", "state", "tmp"],
}
if sorted(os.listdir(run_dir)) != expected_entries[failure_point]:
    raise RuntimeError("run-layout failure did not stop at its exact injected point")
for name in {"state", "evidence", "tmp"}.intersection(os.listdir(run_dir)):
    info = os.stat(run_dir + "/" + name, follow_symlinks=False)
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_IMODE(info.st_mode) != 0o700
        or info.st_uid != os.geteuid()
    ):
        raise RuntimeError(f"retained run directory is unsafe: {name}")
if os.path.lexists(run_dir + "/evidence/guard-live.log"):
    raise RuntimeError("evidence log exists after an injected pre-log failure")
PY
  done
  success_run_id="g20260729t120006z-012345abcdef"
  success_run_dir="${fixture_root}/${success_run_id}"
  run_isolated_python "${fixture_root}" "${fixture_root}" - "${success_run_dir}" <<'PY'
import os
import sys

os.mkdir(sys.argv[1], 0o700)
os.chmod(sys.argv[1], 0o700)
PY
  success_sha256="$(
    initialize_run_layout \
      "${fixture_root}" \
      "${success_run_dir}" \
      "${success_run_dir}/run.owner" \
      "${success_run_dir}/evidence/guard-live.log" \
      "${EUID}" \
      "" \
      "${success_run_id}" \
      "0123456789abcdef0123456789abcdef01234567" \
      "fixture-host" \
      "7.0.0-28-generic" \
      "0123456789abcdef0123456789abcdef" \
      "192.0.2.1" \
      "fixture0" \
      "${fixture_sha}" \
      "${fixture_root}/${success_run_id}.gate/run.manifest" \
      "${fixture_sha}" \
      "${fixture_root}/${success_run_id}.gate/test-live-guard-ownership.sh" \
      "${fixture_root}/guard-live.test" \
      "${fixture_sha}" \
      "${success_run_dir}/state" \
      "${success_run_dir}/evidence" \
      "${success_run_dir}/tmp"
  )"
  valid_sha256 "${success_sha256}" || {
    echo "error: successful production run-layout self-test returned an invalid SHA-256" >&2
    return 1
  }
  run_isolated_python "${fixture_root}" "${fixture_root}" - \
    "${success_run_dir}" "${success_sha256}" <<'PY'
import hashlib
import os
import stat
import sys

run_dir, expected_sha256 = sys.argv[1:]
if sorted(os.listdir(run_dir)) != ["evidence", "run.owner", "state", "tmp"]:
    raise RuntimeError("successful run layout has unexpected children")
for name in ("state", "evidence", "tmp"):
    info = os.stat(run_dir + "/" + name, follow_symlinks=False)
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_IMODE(info.st_mode) != 0o700
        or info.st_uid != os.geteuid()
    ):
        raise RuntimeError(f"successful run directory is unsafe: {name}")
log_info = os.stat(run_dir + "/evidence/guard-live.log", follow_symlinks=False)
if (
    not stat.S_ISREG(log_info.st_mode)
    or stat.S_IMODE(log_info.st_mode) != 0o600
    or log_info.st_uid != os.geteuid()
    or log_info.st_nlink != 1
    or log_info.st_size != 0
):
    raise RuntimeError("successful evidence log metadata is unsafe")
with open(run_dir + "/run.owner", "rb") as stream:
    if hashlib.sha256(stream.read()).hexdigest() != expected_sha256:
        raise RuntimeError("successful run.owner SHA-256 mismatch")
PY
  printf 'live guard run-evidence failure self-test passed (%d points); fixtures retained at %s\n' \
    "${#failure_points[@]}" "${fixture_root}"
}

self_test_safety_gate() {
  local mode

  for mode in 0700 0755; do
    mode_has_no_group_or_other_write "${mode}" || {
      printf 'error: safe directory mode fixture was rejected: %s\n' "${mode}" >&2
      return 1
    }
  done
  for mode in 0720 0702 0722; do
    if mode_has_no_group_or_other_write "${mode}"; then
      printf 'error: writable directory mode fixture was accepted: %s\n' "${mode}" >&2
      return 1
    fi
  done
  valid_run_id "g20260729t120000z-012345abcdef" || {
    echo "error: valid run-id fixture was rejected" >&2
    return 1
  }
  if valid_run_id "g20260729t120000z-" ||
    valid_run_id "../g20260729t120000z-012345abcdef" ||
    valid_run_id "g20260729t120000z-012345ABCDEf"; then
    echo "error: unsafe run-id fixture was accepted" >&2
    return 1
  fi
  valid_sha256 "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" || {
    echo "error: valid SHA-256 fixture was rejected" >&2
    return 1
  }
  if valid_sha256 "012345" ||
    valid_sha256 "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeF"; then
    echo "error: unsafe SHA-256 fixture was accepted" >&2
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
  local fixture_run_id="g20260729t120000z-012345abcdef"
  [[ "${RUN_PREFIX}/${fixture_run_id}" == \
    "/var/lib/wg-mix-ebpf-test-runs/g20260729t120000z-012345abcdef" ]] || {
    echo "error: run directory derivation escaped its fixed prefix" >&2
    return 1
  }
  [[ "${RUN_PREFIX}/${fixture_run_id}.gate/test-live-guard-ownership.sh" == \
    "/var/lib/wg-mix-ebpf-test-runs/g20260729t120000z-012345abcdef.gate/test-live-guard-ownership.sh" ]] || {
    echo "error: staged script derivation escaped its fixed prefix" >&2
    return 1
  }
  PYTHONPATH="${PWD}" run_isolated_python "${PWD}" "/tmp" - <<'PY'
import os
import sys

cwd = os.path.realpath(os.getcwd())
unsafe = [
    entry
    for entry in sys.path
    if os.path.realpath(entry or cwd) == cwd
]
if unsafe:
    raise SystemExit(f"root Python import path includes the caller directory: {unsafe!r}")
PY
  self_test_run_evidence_failures
  echo "live guard safety gate self-test passed"
}

SELF_TEST=0
EXPECTED_ADDRESS=""
INTERFACE=""
EXPECTED_HOSTNAME=""
EXPECTED_KERNEL=""
EXPECTED_MACHINE_ID=""
CANDIDATE_COMMIT=""
RUN_ID=""
TEST_BINARY=""
TEST_BINARY_SHA256=""
APPROVED_SCRIPT_SHA256=""

while (($# > 0)); do
  case "$1" in
  --self-test-safety-gate)
    SELF_TEST=1
    shift
    ;;
  --approved-script-sha256)
    (($# >= 2)) || {
      echo "error: --approved-script-sha256 requires a value" >&2
      exit 2
    }
    APPROVED_SCRIPT_SHA256="$2"
    shift 2
    ;;
  --expected-address)
    (($# >= 2)) || {
      echo "error: --expected-address requires a value" >&2
      exit 2
    }
    EXPECTED_ADDRESS="$2"
    shift 2
    ;;
  --interface)
    (($# >= 2)) || {
      echo "error: --interface requires a value" >&2
      exit 2
    }
    INTERFACE="$2"
    shift 2
    ;;
  --expected-hostname)
    (($# >= 2)) || {
      echo "error: --expected-hostname requires a value" >&2
      exit 2
    }
    EXPECTED_HOSTNAME="$2"
    shift 2
    ;;
  --expected-kernel)
    (($# >= 2)) || {
      echo "error: --expected-kernel requires a value" >&2
      exit 2
    }
    EXPECTED_KERNEL="$2"
    shift 2
    ;;
  --expected-machine-id)
    (($# >= 2)) || {
      echo "error: --expected-machine-id requires a value" >&2
      exit 2
    }
    EXPECTED_MACHINE_ID="$2"
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
  --run-id)
    (($# >= 2)) || {
      echo "error: --run-id requires a value" >&2
      exit 2
    }
    RUN_ID="$2"
    shift 2
    ;;
  --test-binary)
    (($# >= 2)) || {
      echo "error: --test-binary requires a value" >&2
      exit 2
    }
    TEST_BINARY="$2"
    shift 2
    ;;
  --test-binary-sha256)
    (($# >= 2)) || {
      echo "error: --test-binary-sha256 requires a value" >&2
      exit 2
    }
    TEST_BINARY_SHA256="$2"
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
  [[ -z "${EXPECTED_ADDRESS}" && -z "${INTERFACE}" &&
    -z "${EXPECTED_HOSTNAME}" && -z "${EXPECTED_KERNEL}" &&
    -z "${EXPECTED_MACHINE_ID}" && -z "${CANDIDATE_COMMIT}" &&
    -z "${RUN_ID}" && -z "${TEST_BINARY}" &&
    -z "${TEST_BINARY_SHA256}" && -z "${APPROVED_SCRIPT_SHA256}" ]] || {
    echo "error: --self-test-safety-gate does not accept host arguments" >&2
    exit 2
  }
  self_test_safety_gate
  exit 0
fi

[[ "${EXPECTED_ADDRESS}" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || {
  echo "error: a literal IPv4 --expected-address is required" >&2
  exit 2
}
[[ "${INTERFACE}" =~ ^[[:alnum:]_.-]{1,64}$ ]] || {
  echo "error: a literal --interface is required" >&2
  exit 2
}
[[ "${INTERFACE}" != -* ]] || {
  echo "error: --interface must not begin with '-'" >&2
  exit 2
}
[[ "${EXPECTED_HOSTNAME}" =~ ^[[:alnum:].-]{1,253}$ ]] || {
  echo "error: a literal --expected-hostname is required" >&2
  exit 2
}
[[ "${EXPECTED_KERNEL}" =~ ^[0-9]+\.[0-9]+\.[0-9]+-[[:alnum:].+-]+$ ]] || {
  echo "error: a literal --expected-kernel is required" >&2
  exit 2
}
[[ "${EXPECTED_MACHINE_ID}" =~ ^[0-9a-f]{32}$ ]] || {
  echo "error: --expected-machine-id must be exactly 32 lowercase hex characters" >&2
  exit 2
}
[[ "${CANDIDATE_COMMIT}" =~ ^[0-9a-f]{40}$ ]] || {
  echo "error: --candidate-commit must be exactly 40 lowercase hex characters" >&2
  exit 2
}
valid_run_id "${RUN_ID}" || {
  echo "error: invalid --run-id" >&2
  exit 2
}
valid_sha256 "${TEST_BINARY_SHA256}" || {
  echo "error: invalid --test-binary-sha256" >&2
  exit 2
}
valid_sha256 "${APPROVED_SCRIPT_SHA256}" || {
  echo "error: invalid --approved-script-sha256" >&2
  exit 2
}
[[ "${TEST_BINARY}" == /* && -f "${TEST_BINARY}" && ! -L "${TEST_BINARY}" ]] || {
  echo "error: --test-binary must name an absolute, regular, non-symlink file" >&2
  exit 2
}
[[ "${EUID}" -eq 0 ]] || {
  echo "error: live guard gate must run as root through an explicitly reviewed sudo command" >&2
  exit 1
}

[[ -x "${ENV_BIN}" && -x "${PYTHON3_BIN}" && -x "${SHA256_BIN}" &&
  -x "${TIMEOUT_BIN}" ]] || {
  echo "error: fixed system env/python3/sha256sum/timeout tools are unavailable" >&2
  exit 1
}
for command in awk date dirname grep hostname ip mkdir nft readlink stat tee uname; do
  command -v "${command}" >/dev/null || {
    printf 'error: required command is missing: %s\n' "${command}" >&2
    exit 1
  }
done

if ! ip -o -4 address show dev "${INTERFACE}" |
  awk -v expected="${EXPECTED_ADDRESS}" '
    {
      split($4, address, "/")
      if (address[1] == expected) {
        found = 1
      }
    }
    END { exit !found }
  '; then
  printf 'error: %s does not own %s\n' "${INTERFACE}" "${EXPECTED_ADDRESS}" >&2
  exit 1
fi
[[ "$(hostname)" == "${EXPECTED_HOSTNAME}" ]] || {
  echo "error: hostname identity mismatch" >&2
  exit 1
}
[[ "$(uname -r)" == "${EXPECTED_KERNEL}" ]] || {
  echo "error: kernel identity mismatch" >&2
  exit 1
}
[[ "$(< /etc/machine-id)" == "${EXPECTED_MACHINE_ID}" ]] || {
  echo "error: machine-id identity mismatch" >&2
  exit 1
}

grep -qx 'ID=ubuntu' /etc/os-release &&
  grep -qx 'VERSION_ID="26.04"' /etc/os-release || {
  echo "error: /etc/os-release does not exactly identify Ubuntu 26.04" >&2
  exit 1
}

validate_secure_directory "/" 0
validate_secure_directory "/var" 0
validate_secure_directory "/var/lib" 0
validate_secure_directory "${RUN_PREFIX}" 0 700
validate_locked_script "${RUN_ID}" "${APPROVED_SCRIPT_SHA256}"

readonly GATE_DIR="${RUN_PREFIX}/${RUN_ID}.gate"
readonly STAGED_SCRIPT_PATH="${GATE_DIR}/test-live-guard-ownership.sh"
readonly GATE_MANIFEST="${GATE_DIR}/run.manifest"
GATE_MANIFEST_SHA256="$(
  validate_gate_manifest \
    "${GATE_MANIFEST}" \
    "${RUN_ID}" \
    "${CANDIDATE_COMMIT}" \
    "${EXPECTED_HOSTNAME}" \
    "${EXPECTED_KERNEL}" \
    "${EXPECTED_MACHINE_ID}" \
    "${EXPECTED_ADDRESS}" \
    "${INTERFACE}" \
    "${APPROVED_SCRIPT_SHA256}" \
    "${STAGED_SCRIPT_PATH}" \
    "${TEST_BINARY}" \
    "${TEST_BINARY_SHA256}"
)"
valid_sha256 "${GATE_MANIFEST_SHA256}" || {
  echo "error: validated gate manifest did not produce a SHA-256" >&2
  exit 1
}
readonly GATE_MANIFEST_SHA256

readonly RUN_DIR="${RUN_PREFIX}/${RUN_ID}"
readonly STATE_DIR="${RUN_DIR}/state"
readonly EVIDENCE_DIR="${RUN_DIR}/evidence"
readonly TMP_DIR="${RUN_DIR}/tmp"
readonly LOCKED_TEST_BINARY="${RUN_DIR}/guard-live.test"
readonly RUN_MANIFEST="${RUN_DIR}/run.owner"
readonly EVIDENCE_LOG="${EVIDENCE_DIR}/guard-live.log"
readonly RESULT_FILE="${EVIDENCE_DIR}/guard-live.result.json"

[[ ! -e "${RUN_DIR}" && ! -L "${RUN_DIR}" ]] || {
  printf 'error: run directory already exists: %s\n' "${RUN_DIR}" >&2
  exit 1
}
mkdir --mode=0700 -- "${RUN_DIR}"
validate_secure_directory "${RUN_DIR}" 0 700

RUN_MANIFEST_SHA256="$(
  initialize_run_layout \
    "${RUN_PREFIX}" \
    "${RUN_DIR}" \
    "${RUN_MANIFEST}" \
    "${EVIDENCE_LOG}" \
    0 \
    "" \
    "${RUN_ID}" \
    "${CANDIDATE_COMMIT}" \
    "${EXPECTED_HOSTNAME}" \
    "${EXPECTED_KERNEL}" \
    "${EXPECTED_MACHINE_ID}" \
    "${EXPECTED_ADDRESS}" \
    "${INTERFACE}" \
    "${APPROVED_SCRIPT_SHA256}" \
    "${GATE_MANIFEST}" \
    "${GATE_MANIFEST_SHA256}" \
    "${STAGED_SCRIPT_PATH}" \
    "${TEST_BINARY}" \
    "${TEST_BINARY_SHA256}" \
    "${STATE_DIR}" \
    "${EVIDENCE_DIR}" \
    "${TMP_DIR}"
)"
valid_sha256 "${RUN_MANIFEST_SHA256}" || {
  echo "error: durable run ownership manifest did not produce a SHA-256" >&2
  exit 1
}
readonly RUN_MANIFEST_SHA256
printf 'run_manifest_persisted run_dir=%s path=%s sha256=%s gate_manifest_sha256=%s\n' \
  "${RUN_DIR}" "${RUN_MANIFEST}" "${RUN_MANIFEST_SHA256}" "${GATE_MANIFEST_SHA256}"

cd -- "${RUN_DIR}"

INNER_ARGV=(
  /bin/bash
  "${STAGED_SCRIPT_PATH}"
  --approved-script-sha256 "${APPROVED_SCRIPT_SHA256}"
  --expected-address "${EXPECTED_ADDRESS}"
  --interface "${INTERFACE}"
  --expected-hostname "${EXPECTED_HOSTNAME}"
  --expected-kernel "${EXPECTED_KERNEL}"
  --expected-machine-id "${EXPECTED_MACHINE_ID}"
  --candidate-commit "${CANDIDATE_COMMIT}"
  --run-id "${RUN_ID}"
  --test-binary "${TEST_BINARY}"
  --test-binary-sha256 "${TEST_BINARY_SHA256}"
)
readonly -a INNER_ARGV
printf 'gate_start timestamp=%s target_host=%s address=%s interface=%s run_dir=%s gate_manifest_sha256=%s run_manifest_sha256=%s inner_argv_scope=script_only_not_sudo_or_staging argv=' \
  "$(date --iso-8601=seconds)" "${EXPECTED_HOSTNAME}" "${EXPECTED_ADDRESS}" \
  "${INTERFACE}" "${RUN_DIR}" "${GATE_MANIFEST_SHA256}" "${RUN_MANIFEST_SHA256}" |
  tee -a "${EVIDENCE_LOG}"
printf ' %q' "${INNER_ARGV[@]}" | tee -a "${EVIDENCE_LOG}"
printf '\n' | tee -a "${EVIDENCE_LOG}"
[[ ! -e "${RESULT_FILE}" && ! -L "${RESULT_FILE}" ]] || {
  echo "error: live result file unexpectedly exists before the test" >&2
  exit 1
}

COPY_ARGV=(
  "${TIMEOUT_BIN}"
  --signal=TERM
  --kill-after=5s
  30s
  "${ENV_BIN}"
  -i
  "PATH=${PATH}"
  "LC_ALL=${LC_ALL}"
  "HOME=${RUN_DIR}"
  "TMPDIR=${TMP_DIR}"
  "${PYTHON3_BIN}"
  -I
  -B
  -
  "${TEST_BINARY}"
  "${LOCKED_TEST_BINARY}"
)
readonly -a COPY_ARGV
printf 'copy_start timestamp=%s argv=' "$(date --iso-8601=seconds)" |
  tee -a "${EVIDENCE_LOG}"
printf ' %q' "${COPY_ARGV[@]}" | tee -a "${EVIDENCE_LOG}"
printf '\n' | tee -a "${EVIDENCE_LOG}"

set +e
copy_output="$(
  "${COPY_ARGV[@]}" 2>&1 <<'PY'
import hashlib
import os
import stat
import sys

source, destination = sys.argv[1:3]
source_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
source_fd = os.open(source, source_flags)
try:
    source_stat = os.fstat(source_fd)
    if not stat.S_ISREG(source_stat.st_mode) or source_stat.st_nlink != 1:
        raise RuntimeError("source test binary is not a single-link regular file")
    if source_stat.st_size <= 0 or source_stat.st_size > 128 * 1024 * 1024:
        raise RuntimeError("source test binary size is outside the 1 byte..128 MiB gate")
    destination_flags = (
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    destination_fd = os.open(destination, destination_flags, 0o700)
    digest = hashlib.sha256()
    remaining = source_stat.st_size
    copied = 0
    try:
        while remaining:
            chunk = os.read(source_fd, min(1024 * 1024, remaining))
            if not chunk:
                raise RuntimeError("source test binary ended before its initial size")
            digest.update(chunk)
            copied += len(chunk)
            remaining -= len(chunk)
            if copied > 128 * 1024 * 1024:
                raise RuntimeError("source test binary exceeded the hard copy limit")
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                if written <= 0:
                    raise RuntimeError("short write while locking test binary")
                view = view[written:]
        if os.read(source_fd, 1):
            raise RuntimeError("source test binary grew while it was copied")
        os.fchmod(destination_fd, 0o700)
        os.fsync(destination_fd)
    finally:
        os.close(destination_fd)
    directory_fd = os.open(
        os.path.dirname(destination),
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    print(digest.hexdigest())
finally:
    os.close(source_fd)
PY
)"
copy_exit_code=$?
set -e
printf '%s\n' "${copy_output}" | tee -a "${EVIDENCE_LOG}"
printf 'copy_finish timestamp=%s exit=%d\n' \
  "$(date --iso-8601=seconds)" "${copy_exit_code}" | tee -a "${EVIDENCE_LOG}"
if ((copy_exit_code != 0)); then
  echo "error: bounded test-binary copy failed; run evidence was retained" >&2
  exit "${copy_exit_code}"
fi
copied_sha="${copy_output}"
[[ "${copied_sha}" == "${TEST_BINARY_SHA256}" ]] || {
  printf 'error: copied test binary SHA-256 mismatch: got=%s want=%s\n' \
    "${copied_sha}" "${TEST_BINARY_SHA256}" >&2
  exit 1
}

read -r locked_uid locked_mode locked_links locked_kind < <(
  stat -c '%u %a %h %F' -- "${LOCKED_TEST_BINARY}"
)
[[ "${locked_uid}" == "0" && "${locked_mode}" == "700" &&
  "${locked_links}" == "1" && "${locked_kind}" == "regular file" ]] || {
  printf 'error: locked test binary metadata is unsafe: uid=%s mode=%s links=%s type=%s\n' \
    "${locked_uid}" "${locked_mode}" "${locked_links}" "${locked_kind}" >&2
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
  "HOME=${RUN_DIR}"
  "TMPDIR=${TMP_DIR}"
  "${LOCKED_TEST_BINARY}"
  -test.list
  '^TestLiveGuardOwnership$'
)
readonly -a LIST_ARGV
printf 'list_start timestamp=%s argv=' "$(date --iso-8601=seconds)" |
  tee -a "${EVIDENCE_LOG}"
printf ' %q' "${LIST_ARGV[@]}" | tee -a "${EVIDENCE_LOG}"
printf '\n' | tee -a "${EVIDENCE_LOG}"
set +e
list_output="$("${LIST_ARGV[@]}" 2>&1)"
list_exit_code=$?
set -e
printf '%s\n' "${list_output}" | tee -a "${EVIDENCE_LOG}"
printf 'list_finish timestamp=%s exit=%d\n' \
  "$(date --iso-8601=seconds)" "${list_exit_code}" | tee -a "${EVIDENCE_LOG}"
if ! valid_live_test_list "${list_exit_code}" "${list_output}"; then
  echo "error: locked test binary does not contain exactly the reviewed live test" >&2
  exit 1
fi

TEST_ARGV=(
  "${TIMEOUT_BIN}"
  --signal=TERM
  --kill-after=5s
  60s
  "${ENV_BIN}"
  -i
  "PATH=${PATH}"
  "LC_ALL=${LC_ALL}"
  "HOME=${RUN_DIR}"
  "TMPDIR=${TMP_DIR}"
  "WG_MIX_EBPF_LIVE_GUARD=1"
  "WG_MIX_EBPF_LIVE_GUARD_RUN_ID=${RUN_ID}"
  "WG_MIX_EBPF_LIVE_GUARD_STATE_DIR=${STATE_DIR}"
  "WG_MIX_EBPF_LIVE_GUARD_EXPECTED_HOSTNAME=${EXPECTED_HOSTNAME}"
  "WG_MIX_EBPF_LIVE_GUARD_EXPECTED_KERNEL=${EXPECTED_KERNEL}"
  "WG_MIX_EBPF_LIVE_GUARD_EXPECTED_MACHINE_ID=${EXPECTED_MACHINE_ID}"
  "WG_MIX_EBPF_LIVE_GUARD_CANDIDATE_COMMIT=${CANDIDATE_COMMIT}"
  "WG_MIX_EBPF_LIVE_GUARD_RESULT_FILE=${RESULT_FILE}"
  "${LOCKED_TEST_BINARY}"
  -test.run
  '^TestLiveGuardOwnership$'
  -test.count=1
  -test.timeout=45s
  -test.v
)
readonly -a TEST_ARGV

printf 'write_start timestamp=%s target_host=%s run_dir=%s candidate=%s binary_sha256=%s argv=' \
  "$(date --iso-8601=seconds)" "${EXPECTED_HOSTNAME}" "${RUN_DIR}" \
  "${CANDIDATE_COMMIT}" "${TEST_BINARY_SHA256}" |
  tee -a "${EVIDENCE_LOG}"
printf ' %q' "${TEST_ARGV[@]}" | tee -a "${EVIDENCE_LOG}"
printf '\n' | tee -a "${EVIDENCE_LOG}"

set +e
"${TEST_ARGV[@]}" 2>&1 | tee -a "${EVIDENCE_LOG}"
pipeline_exit_codes=("${PIPESTATUS[@]}")
test_exit_code=${pipeline_exit_codes[0]}
tee_exit_code=${pipeline_exit_codes[1]}
set -e

printf 'write_finish timestamp=%s test_exit=%d tee_exit=%d evidence=%s\n' \
  "$(date --iso-8601=seconds)" "${test_exit_code}" "${tee_exit_code}" "${EVIDENCE_LOG}" |
  tee -a "${EVIDENCE_LOG}"
if ((test_exit_code != 0 || tee_exit_code != 0)); then
  echo "error: live guard gate failed; evidence and any owned nft table were retained" >&2
  if ((test_exit_code != 0)); then
    exit "${test_exit_code}"
  fi
  exit 1
fi

set +e
run_isolated_python "${RUN_DIR}" "${TMP_DIR}" - \
  "${RESULT_FILE}" "${RUN_ID}" "${CANDIDATE_COMMIT}" "${STATE_DIR}" <<'PY' 2>&1 |
  tee -a "${EVIDENCE_LOG}"
import hashlib
import json
import os
import re
import stat
import sys

path, expected_run_id, expected_commit, expected_state_dir = sys.argv[1:5]

def read_secure_file(file_path, label):
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(file_path, flags)
    try:
        data, before = read_locked_descriptor(fd, label)
        named = os.stat(file_path, follow_symlinks=False)
        if (named.st_dev, named.st_ino) != (before.st_dev, before.st_ino):
            raise RuntimeError(f"{label} name does not match the opened descriptor")
        return data
    finally:
        os.close(fd)

def read_locked_descriptor(fd, label):
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode):
        raise RuntimeError(f"{label} is not a regular file")
    if stat.S_IMODE(before.st_mode) != 0o600:
        raise RuntimeError(f"{label} mode is not 0600")
    if before.st_uid != 0 or before.st_nlink != 1:
        raise RuntimeError(f"{label} ownership or link count is unsafe")
    if before.st_size <= 0 or before.st_size > 4096:
        raise RuntimeError(f"{label} size is outside the 1..4096 byte gate")
    data = bytearray()
    while len(data) <= 4096:
        chunk = os.read(fd, 4097 - len(data))
        if not chunk:
            break
        data.extend(chunk)
    after = os.fstat(fd)
    if (
        len(data) != before.st_size
        or len(data) > 4096
        or (after.st_dev, after.st_ino, after.st_size)
        != (before.st_dev, before.st_ino, before.st_size)
    ):
        raise RuntimeError(f"{label} changed while reading")
    return bytes(data), before

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result

result_data = read_secure_file(path, "live result")
document = json.loads(result_data, object_pairs_hook=unique_object)
expected_keys = {
    "version",
    "run_id",
    "candidate_commit",
    "table",
    "marker",
    "first_handle",
    "second_handle",
    "owner_sha256",
    "cleanup_verified",
}
if not isinstance(document, dict):
    raise RuntimeError("live result root is not an object")
if set(document) != expected_keys:
    raise RuntimeError(f"live result keys are invalid: {sorted(document)}")
if type(document["version"]) is not int or document["version"] != 1:
    raise RuntimeError("live result version is not the integer 1")
if type(document["run_id"]) is not str or document["run_id"] != expected_run_id:
    raise RuntimeError("live result run_id mismatch")
if (
    type(document["candidate_commit"]) is not str
    or document["candidate_commit"] != expected_commit
):
    raise RuntimeError("live result candidate_commit mismatch")
marker = document["marker"]
if type(marker) is not str or not re.fullmatch(
    r"wg-mix-ebpf-guard-v2:[0-9a-f]{64}",
    marker,
):
    raise RuntimeError("live result marker is invalid")
installation_id = marker[len("wg-mix-ebpf-guard-v2:") :]
expected_table = f"wg_mix_ebpf_guard_{installation_id[:32]}"
if type(document["table"]) is not str or document["table"] != expected_table:
    raise RuntimeError("live result table does not match its marker")
first_handle = document["first_handle"]
second_handle = document["second_handle"]
if (
    type(first_handle) is not int
    or type(second_handle) is not int
    or first_handle <= 0
    or second_handle <= 0
    or first_handle == second_handle
):
    raise RuntimeError("live result handles do not prove replacement")
if type(document["owner_sha256"]) is not str or not re.fullmatch(
    r"[0-9a-f]{64}",
    document["owner_sha256"],
):
    raise RuntimeError("live result owner_sha256 is invalid")
if type(document["cleanup_verified"]) is not bool or document["cleanup_verified"] is not True:
    raise RuntimeError("live result does not prove cleanup")

if os.path.realpath(expected_state_dir) != expected_state_dir:
    raise RuntimeError("expected state directory is not canonical")
state_fd = os.open(
    expected_state_dir,
    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
)
try:
    state_stat = os.fstat(state_fd)
    if (
        not stat.S_ISDIR(state_stat.st_mode)
        or stat.S_IMODE(state_stat.st_mode) != 0o700
        or state_stat.st_uid != 0
    ):
        raise RuntimeError("live state directory metadata is unsafe")
    owner_name = "guard-owner.v2.json"
    owner_fd = os.open(
        owner_name,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
        dir_fd=state_fd,
    )
    try:
        owner_data, owner_stat = read_locked_descriptor(owner_fd, "guard owner record")
        named_owner = os.stat(
            owner_name,
            dir_fd=state_fd,
            follow_symlinks=False,
        )
        if (named_owner.st_dev, named_owner.st_ino) != (
            owner_stat.st_dev,
            owner_stat.st_ino,
        ):
            raise RuntimeError(
                "guard owner record name does not match the opened descriptor"
            )
    finally:
        os.close(owner_fd)

    owner = json.loads(owner_data, object_pairs_hook=unique_object)
    owner_keys = {
        "version",
        "installation_id",
        "state_dir",
        "state_dir_device",
        "state_dir_inode",
        "table",
        "marker",
    }
    if not isinstance(owner, dict):
        raise RuntimeError("guard owner record root is not an object")
    if set(owner) != owner_keys:
        raise RuntimeError(f"guard owner record keys are invalid: {sorted(owner)}")
    if type(owner["version"]) is not int or owner["version"] != 2:
        raise RuntimeError("guard owner record version is not the integer 2")
    if type(owner["installation_id"]) is not str or not re.fullmatch(
        r"[0-9a-f]{64}",
        owner["installation_id"],
    ):
        raise RuntimeError("guard owner installation_id is invalid")
    if type(owner["state_dir"]) is not str or owner["state_dir"] != expected_state_dir:
        raise RuntimeError("guard owner state_dir mismatch")
    if (
        type(owner["state_dir_device"]) is not int
        or owner["state_dir_device"] < 0
        or owner["state_dir_device"] != state_stat.st_dev
        or type(owner["state_dir_inode"]) is not int
        or owner["state_dir_inode"] <= 0
        or owner["state_dir_inode"] != state_stat.st_ino
    ):
        raise RuntimeError("guard owner state directory identity mismatch")
    owner_table = f"wg_mix_ebpf_guard_{owner['installation_id'][:32]}"
    owner_marker = f"wg-mix-ebpf-guard-v2:{owner['installation_id']}"
    if type(owner["table"]) is not str or owner["table"] != owner_table:
        raise RuntimeError("guard owner table does not match installation_id")
    if type(owner["marker"]) is not str or owner["marker"] != owner_marker:
        raise RuntimeError("guard owner marker does not match installation_id")
    if document["table"] != owner["table"] or document["marker"] != owner["marker"]:
        raise RuntimeError("live result is not bound to the persisted guard owner")
    owner_sha256 = hashlib.sha256(owner_data).hexdigest()
    if document["owner_sha256"] != owner_sha256:
        raise RuntimeError("live result owner_sha256 does not match the persisted owner")

    named_state = os.stat(expected_state_dir, follow_symlinks=False)
    if (named_state.st_dev, named_state.st_ino) != (
        state_stat.st_dev,
        state_stat.st_ino,
    ):
        raise RuntimeError("live state directory name changed")
finally:
    os.close(state_fd)
print(
    "result_verified"
    f" sha256={hashlib.sha256(result_data).hexdigest()}"
    f" owner_sha256={owner_sha256}"
    f" table={document['table']}"
    f" first_handle={first_handle}"
    f" second_handle={second_handle}"
)
PY
verify_pipeline_exit_codes=("${PIPESTATUS[@]}")
verify_exit_code=${verify_pipeline_exit_codes[0]}
verify_tee_exit_code=${verify_pipeline_exit_codes[1]}
set -e
if ((verify_exit_code != 0 || verify_tee_exit_code != 0)); then
  echo "error: live result verification failed; run evidence was retained" >&2
  if ((verify_exit_code != 0)); then
    exit "${verify_exit_code}"
  fi
  exit 1
fi

printf 'gate_finish timestamp=%s result=%s\n' \
  "$(date --iso-8601=seconds)" "${RESULT_FILE}" | tee -a "${EVIDENCE_LOG}"
echo "live guard ownership gate passed; run-owned evidence was retained"
