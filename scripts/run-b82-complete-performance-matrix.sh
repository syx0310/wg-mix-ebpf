#!/usr/bin/bash -p
if [[ "$-" != *p* ]]; then
  builtin printf '%s\n' \
    'error: B82 performance matrix requires Bash privileged mode' >&2
  exit 1
fi
set -euo pipefail

readonly SAFE_PATH="/usr/sbin:/usr/bin:/sbin:/bin"
readonly STAGED_NAME="scripts/run-b82-complete-performance-matrix.sh"
readonly LAUNCHER_NAME="scripts/run-smoke-netns-wg-private-mountns.sh"
PATH="${SAFE_PATH}"
LC_ALL=C
export PATH LC_ALL
IFS=$' \t\n'
unset BASH_ENV CDPATH ENV GLOBIGNORE LD_LIBRARY_PATH LD_PRELOAD \
  PERL5LIB PYTHONHOME PYTHONPATH RUBYLIB XOR_PASSWORD

if [[ "${EUID}" -ne 0 || "${EGID}" -ne 0 ]]; then
  echo "error: run the B82 performance matrix as root" >&2
  exit 1
fi
if (($# != 0)); then
  echo "error: the B82 performance matrix accepts no arguments" >&2
  exit 2
fi

script_reference="${BASH_SOURCE[0]}"
if [[ "${script_reference}" == /* ]]; then
  script_path="${script_reference}"
elif [[ "${script_reference}" == "${STAGED_NAME}" ]]; then
  script_path="$(builtin pwd -P)/${STAGED_NAME}"
else
  echo "error: matrix path is not the fixed staged entry" >&2
  exit 1
fi
source_root="${script_path%/"${STAGED_NAME}"}"
if [[ ! "${source_root}" =~ ^/run/wg-mix-ebpf-source-stages/[0-9a-f]{8}/source$ ]]; then
  echo "error: matrix must run from a root-owned source stage" >&2
  exit 1
fi
launcher="${source_root}/${LAUNCHER_NAME}"
for executable in "${script_path}" "${launcher}"; do
  if [[ ! -f "${executable}" || -L "${executable}" || ! -x "${executable}" ||
    "$(stat -c '%u:%g:%a:%h' -- "${executable}")" != "0:0:700:1" ]]; then
    echo "error: staged performance executable is unsafe: ${executable}" >&2
    exit 1
  fi
done

matrix_id="$(python3 - <<'PY'
import secrets
print(secrets.token_hex(4))
PY
)"
xor_secret="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
)"
if [[ ! "${matrix_id}" =~ ^[0-9a-f]{8}$ ||
  ! "${xor_secret}" =~ ^[A-Za-z0-9_-]{40,64}$ ]]; then
  echo "error: failed to generate matrix identity or XOR secret" >&2
  exit 1
fi

run_cell() {
  local label="$1"
  local dataplane_mode="$2"
  local backend="$3"
  local xor_mode="$4"
  local scope="$5"
  local max_bytes="$6"
  local status=0
  local common_environment=(
    "DATAPLANE_MODE=${dataplane_mode}"
    "ATTACHMENT_BACKEND=${backend}"
    "OUTER_FAMILY=ipv4"
    "INITIAL_CAPTURE_TIMEOUT=8"
    "UNDERLAY_MTU=2200"
    "WG_MTU=2000"
    "TCP_CHECKS=enforce"
    "TCP_MTUS=1420"
    "TCP_STREAMS=1"
    "TCP_DIRECTIONS=forward reverse bidir"
    "TCP_DURATION=3"
    "TCP_REPETITIONS=3"
    "TCP_MIN_BYTES=1048576"
    "TCP_MAX_RETRANSMITS=0"
    "TCP_MIN_FAIRNESS=0.90"
    "TCP_CAPTURE_PACKETS=128"
    "TCP_INNER_GSO_CHECKS=report"
    "TCP_OUTER_GSO_CHECKS=observe"
    "XOR_SCOPE=${scope}"
    "XOR_MAX_BYTES=${max_bytes}"
  )

  if [[ ! "${label}" =~ ^(wireguard|tcx|classic_tc)-(baseline|prefix-(4|16|64|128|256|512|1024|2048)|full-2048)$ ||
    ! "${dataplane_mode}" =~ ^(ebpf|wireguard)$ ||
    ! "${backend}" =~ ^(auto|tcx|classic_tc)$ ||
    ! "${xor_mode}" =~ ^(off|on)$ ||
    ! "${scope}" =~ ^wg-payload-(prefix|full)$ ||
    ! "${max_bytes}" =~ ^(4|16|64|128|256|512|1024|2048)$ ]]; then
    echo "error: invalid fixed performance cell: ${label}" >&2
    return 1
  fi
  printf 'PERFORMANCE_CELL_START matrix_id=%s label=%s timestamp=%s\n' \
    "${matrix_id}" "${label}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if [[ "${xor_mode}" == "on" ]]; then
    if XOR_PASSWORD="${xor_secret}" /usr/bin/env "${common_environment[@]}" \
      /usr/bin/bash -p "${launcher}"; then
      status=0
    else
      status=$?
    fi
  else
    if /usr/bin/env -u XOR_PASSWORD "${common_environment[@]}" \
      /usr/bin/bash -p "${launcher}"; then
      status=0
    else
      status=$?
    fi
  fi
  printf 'PERFORMANCE_CELL_FINISH matrix_id=%s label=%s rc=%s timestamp=%s\n' \
    "${matrix_id}" "${label}" "${status}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  return "${status}"
}

printf 'PERFORMANCE_MATRIX_START matrix_id=%s cells=21 repetitions=3 duration_seconds=3 timestamp=%s\n' \
  "${matrix_id}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
run_cell wireguard-baseline wireguard auto off wg-payload-prefix 4
run_cell tcx-baseline ebpf tcx off wg-payload-prefix 4
run_cell classic_tc-baseline ebpf classic_tc off wg-payload-prefix 4
for max_bytes in 4 16 64 128 256 512 1024 2048; do
  run_cell "tcx-prefix-${max_bytes}" ebpf tcx on wg-payload-prefix "${max_bytes}"
  run_cell "classic_tc-prefix-${max_bytes}" ebpf classic_tc on wg-payload-prefix "${max_bytes}"
done
run_cell tcx-full-2048 ebpf tcx on wg-payload-full 2048
run_cell classic_tc-full-2048 ebpf classic_tc on wg-payload-full 2048
unset xor_secret
printf 'PERFORMANCE_MATRIX_COMPLETE matrix_id=%s cells=21 samples=189 timestamp=%s\n' \
  "${matrix_id}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
