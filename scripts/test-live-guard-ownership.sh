#!/usr/bin/env bash
set -euo pipefail

readonly RUN_PREFIX="/var/lib/wg-mix-ebpf-test-runs"
readonly PATH="/usr/sbin:/usr/bin:/sbin:/bin"
readonly LC_ALL="C"
export PATH LC_ALL
umask 077

usage() {
  cat <<'EOF'
usage:
  scripts/test-live-guard-ownership.sh --self-test-safety-gate

  sudo scripts/test-live-guard-ownership.sh \
    --expected-address 192.168.10.82 \
    --interface ens33 \
    --expected-hostname ubuntu-2604-test \
    --expected-kernel 7.0.0-28-generic \
    --expected-machine-id 0123456789abcdef0123456789abcdef \
    --candidate-commit 0123456789abcdef0123456789abcdef01234567 \
    --run-id g20260729t120000z-012345abcdef \
    --test-binary /absolute/path/guard-live.test \
    --test-binary-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

The normal mode is a privileged, mutating Linux gate. Its filesystem write
set is the fixed project prefix (when it does not already exist) and one
unique child:

  /var/lib/wg-mix-ebpf-test-runs
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
  local fixture_run_id="g20260729t120000z-012345abcdef"
  [[ "${RUN_PREFIX}/${fixture_run_id}" == \
    "/var/lib/wg-mix-ebpf-test-runs/g20260729t120000z-012345abcdef" ]] || {
    echo "error: run directory derivation escaped its fixed prefix" >&2
    return 1
  }
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

while (($# > 0)); do
  case "$1" in
  --self-test-safety-gate)
    SELF_TEST=1
    shift
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
    -z "${TEST_BINARY_SHA256}" ]] || {
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
[[ "${TEST_BINARY}" == /* && -f "${TEST_BINARY}" && ! -L "${TEST_BINARY}" ]] || {
  echo "error: --test-binary must name an absolute, regular, non-symlink file" >&2
  exit 2
}
[[ "${EUID}" -eq 0 ]] || {
  echo "error: live guard gate must run as root through an explicitly reviewed sudo command" >&2
  exit 1
}

for command in awk date env hostname ip mkdir nft python3 readlink stat tee timeout uname; do
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

# shellcheck source=/dev/null
. /etc/os-release
[[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" == "26.04" ]] || {
  printf 'error: expected Ubuntu 26.04, got %s %s\n' \
    "${ID:-unknown}" "${VERSION_ID:-unknown}" >&2
  exit 1
}

validate_secure_directory "/" 0
validate_secure_directory "/var" 0
validate_secure_directory "/var/lib" 0
if [[ ! -e "${RUN_PREFIX}" ]]; then
  mkdir --mode=0755 -- "${RUN_PREFIX}"
fi
validate_secure_directory "${RUN_PREFIX}" 0

readonly RUN_DIR="${RUN_PREFIX}/${RUN_ID}"
[[ ! -e "${RUN_DIR}" && ! -L "${RUN_DIR}" ]] || {
  printf 'error: run directory already exists: %s\n' "${RUN_DIR}" >&2
  exit 1
}
mkdir --mode=0700 -- "${RUN_DIR}"
validate_secure_directory "${RUN_DIR}" 0

readonly STATE_DIR="${RUN_DIR}/state"
readonly EVIDENCE_DIR="${RUN_DIR}/evidence"
readonly TMP_DIR="${RUN_DIR}/tmp"
readonly LOCKED_TEST_BINARY="${RUN_DIR}/guard-live.test"
readonly OWNER_MARKER="${RUN_DIR}/run.owner"

mkdir --mode=0700 -- "${STATE_DIR}"
mkdir --mode=0700 -- "${EVIDENCE_DIR}"
mkdir --mode=0700 -- "${TMP_DIR}"
validate_secure_directory "${STATE_DIR}" 0
validate_secure_directory "${EVIDENCE_DIR}" 0
validate_secure_directory "${TMP_DIR}" 0

(
  set -o noclobber
  umask 077
  {
    printf 'run_id=%s\n' "${RUN_ID}"
    printf 'candidate_commit=%s\n' "${CANDIDATE_COMMIT}"
    printf 'test_binary_sha256=%s\n' "${TEST_BINARY_SHA256}"
    printf 'machine_id=%s\n' "${EXPECTED_MACHINE_ID}"
    printf 'created_at=%s\n' "$(date --iso-8601=seconds)"
  } >"${OWNER_MARKER}"
)

copied_sha="$(
  python3 - "${TEST_BINARY}" "${LOCKED_TEST_BINARY}" <<'PY'
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
    try:
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                if written <= 0:
                    raise RuntimeError("short write while locking test binary")
                view = view[written:]
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

readonly EVIDENCE_LOG="${EVIDENCE_DIR}/guard-live.log"
TEST_ARGV=(
  timeout
  --signal=TERM
  --kill-after=5s
  60s
  env
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
  tee "${EVIDENCE_LOG}"
printf ' %q' "${TEST_ARGV[@]}" | tee -a "${EVIDENCE_LOG}"
printf '\n' | tee -a "${EVIDENCE_LOG}"

cd -- "${RUN_DIR}"
set +e
"${TEST_ARGV[@]}" 2>&1 | tee -a "${EVIDENCE_LOG}"
test_status=${PIPESTATUS[0]}
set -e

printf 'write_finish timestamp=%s exit=%d evidence=%s\n' \
  "$(date --iso-8601=seconds)" "${test_status}" "${EVIDENCE_LOG}" |
  tee -a "${EVIDENCE_LOG}"
if ((test_status != 0)); then
  echo "error: live guard gate failed; evidence and any owned nft table were retained" >&2
  exit "${test_status}"
fi

echo "live guard ownership gate passed; run-owned evidence was retained"
