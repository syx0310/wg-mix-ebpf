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
script SHA-256 must match the reviewed blob. Then invoke exactly:

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
  ((8#${mode} & 8#022 == 0)) || {
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

self_test_safety_gate() {
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
for command in awk date grep hostname ip mkdir nft readlink stat tee uname; do
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

readonly RUN_DIR="${RUN_PREFIX}/${RUN_ID}"
[[ ! -e "${RUN_DIR}" && ! -L "${RUN_DIR}" ]] || {
  printf 'error: run directory already exists: %s\n' "${RUN_DIR}" >&2
  exit 1
}
mkdir --mode=0700 -- "${RUN_DIR}"
validate_secure_directory "${RUN_DIR}" 0 700

readonly STATE_DIR="${RUN_DIR}/state"
readonly EVIDENCE_DIR="${RUN_DIR}/evidence"
readonly TMP_DIR="${RUN_DIR}/tmp"
readonly LOCKED_TEST_BINARY="${RUN_DIR}/guard-live.test"
readonly OWNER_MARKER="${RUN_DIR}/run.owner"
readonly EVIDENCE_LOG="${EVIDENCE_DIR}/guard-live.log"
readonly RESULT_FILE="${EVIDENCE_DIR}/guard-live.result.json"

mkdir --mode=0700 -- "${STATE_DIR}"
mkdir --mode=0700 -- "${EVIDENCE_DIR}"
mkdir --mode=0700 -- "${TMP_DIR}"
validate_secure_directory "${STATE_DIR}" 0 700
validate_secure_directory "${EVIDENCE_DIR}" 0 700
validate_secure_directory "${TMP_DIR}" 0 700
cd -- "${RUN_DIR}"

(
  set -o noclobber
  : >"${EVIDENCE_LOG}"
)
OUTER_ARGV=(
  /bin/bash
  "${BASH_SOURCE[0]}"
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
readonly -a OUTER_ARGV
printf 'gate_start timestamp=%s target_host=%s address=%s interface=%s run_dir=%s argv=' \
  "$(date --iso-8601=seconds)" "${EXPECTED_HOSTNAME}" "${EXPECTED_ADDRESS}" \
  "${INTERFACE}" "${RUN_DIR}" | tee -a "${EVIDENCE_LOG}"
printf ' %q' "${OUTER_ARGV[@]}" | tee -a "${EVIDENCE_LOG}"
printf '\n' | tee -a "${EVIDENCE_LOG}"

(
  set -o noclobber
  umask 077
  {
    printf 'run_id=%s\n' "${RUN_ID}"
    printf 'candidate_commit=%s\n' "${CANDIDATE_COMMIT}"
    printf 'approved_script_sha256=%s\n' "${APPROVED_SCRIPT_SHA256}"
    printf 'test_binary_sha256=%s\n' "${TEST_BINARY_SHA256}"
    printf 'machine_id=%s\n' "${EXPECTED_MACHINE_ID}"
    printf 'created_at=%s\n' "$(date --iso-8601=seconds)"
  } >"${OWNER_MARKER}"
)
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

run_isolated_python "${RUN_DIR}" "${TMP_DIR}" - \
  "${RESULT_FILE}" "${RUN_ID}" "${CANDIDATE_COMMIT}" <<'PY' 2>&1 |
  tee -a "${EVIDENCE_LOG}"
import hashlib
import json
import os
import re
import stat
import sys

path, expected_run_id, expected_commit = sys.argv[1:4]
flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
result_fd = os.open(path, flags)
try:
    result_stat = os.fstat(result_fd)
    if not stat.S_ISREG(result_stat.st_mode):
        raise RuntimeError("live result is not a regular file")
    if stat.S_IMODE(result_stat.st_mode) != 0o600:
        raise RuntimeError("live result mode is not 0600")
    if result_stat.st_uid != 0 or result_stat.st_nlink != 1:
        raise RuntimeError("live result ownership or link count is unsafe")
    if result_stat.st_size <= 0 or result_stat.st_size > 4096:
        raise RuntimeError("live result size is outside the 1..4096 byte gate")
    data = bytearray()
    while len(data) <= 4096:
        chunk = os.read(result_fd, 4097 - len(data))
        if not chunk:
            break
        data.extend(chunk)
    if len(data) != result_stat.st_size or len(data) > 4096:
        raise RuntimeError("live result size changed while reading")
    named_stat = os.stat(path, follow_symlinks=False)
    if (named_stat.st_dev, named_stat.st_ino) != (result_stat.st_dev, result_stat.st_ino):
        raise RuntimeError("live result name does not match the opened descriptor")
finally:
    os.close(result_fd)

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
    "run_id",
    "candidate_commit",
    "table",
    "marker",
    "first_handle",
    "second_handle",
    "owner_sha256",
    "cleanup_verified",
}
if not isinstance(document, dict) or set(document) != expected_keys:
    raise RuntimeError(f"live result keys are invalid: {sorted(document)}")
if document["version"] != 1:
    raise RuntimeError("live result version is not 1")
if document["run_id"] != expected_run_id:
    raise RuntimeError("live result run_id mismatch")
if document["candidate_commit"] != expected_commit:
    raise RuntimeError("live result candidate_commit mismatch")
installation_id = document["marker"].removeprefix("wg-mix-ebpf-guard-v2:")
if not re.fullmatch(r"[0-9a-f]{64}", installation_id):
    raise RuntimeError("live result marker is invalid")
if document["table"] != f"wg_mix_ebpf_guard_{installation_id[:32]}":
    raise RuntimeError("live result table does not match its marker")
first_handle = document["first_handle"]
second_handle = document["second_handle"]
if (
    not isinstance(first_handle, int)
    or isinstance(first_handle, bool)
    or not isinstance(second_handle, int)
    or isinstance(second_handle, bool)
    or first_handle <= 0
    or second_handle <= 0
    or first_handle == second_handle
):
    raise RuntimeError("live result handles do not prove replacement")
if not re.fullmatch(r"[0-9a-f]{64}", document["owner_sha256"]):
    raise RuntimeError("live result owner_sha256 is invalid")
if document["cleanup_verified"] is not True:
    raise RuntimeError("live result does not prove cleanup")
print(
    "result_verified"
    f" sha256={hashlib.sha256(data).hexdigest()}"
    f" table={document['table']}"
    f" first_handle={first_handle}"
    f" second_handle={second_handle}"
)
PY

printf 'gate_finish timestamp=%s result=%s\n' \
  "$(date --iso-8601=seconds)" "${RESULT_FILE}" | tee -a "${EVIDENCE_LOG}"
echo "live guard ownership gate passed; run-owned evidence was retained"
