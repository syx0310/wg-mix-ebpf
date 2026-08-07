#!/usr/bin/env bash
set -euo pipefail

XOR_SECRET="${XOR_PASSWORD-}"
unset XOR_PASSWORD
XOR_ENABLED=0
if [[ -n "${XOR_SECRET}" ]]; then
  XOR_ENABLED=1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT}/bin/wg-mix-ebpf"
NETNS_ANCHOR_HELPER="${ROOT}/bin/wg-mix-ebpf-netns-anchor"
SOURCE_COMMIT_HELPER="${ROOT}/scripts/source-commit.sh"
LIFECYCLE_HOLDER_HELPER="${ROOT}/scripts/hold-isolated-lifecycle-lease.py"
IPERF_CHECKER_HELPER="${ROOT}/scripts/check-iperf3-tcp.py"

source_commit_from_root() {
  (
    builtin cd -- "${ROOT}"
    "${SOURCE_COMMIT_HELPER}"
  )
}

if [[ "${1-}" == "--self-test-source-commit-cwd" ]]; then
  if (($# != 1)); then
    echo "error: --self-test-source-commit-cwd accepts no other arguments" >&2
    exit 2
  fi
  source_commit_from_root
  exit 0
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "error: run as root" >&2
  exit 1
fi

OUTER_FAMILY="${OUTER_FAMILY:-ipv4}"
XOR_SCOPE="${XOR_SCOPE:-wg-payload-full}"
XOR_MAX_BYTES="${XOR_MAX_BYTES:-2048}"
XOR_GENERATION_CHECKS="${XOR_GENERATION_CHECKS:-off}"
XOR_DISPATCH_FAILURE_CHECKS="${XOR_DISPATCH_FAILURE_CHECKS:-off}"
UDP_ZERO_CHECKSUM_CHECKS="${UDP_ZERO_CHECKSUM_CHECKS:-off}"
TCP_CHECKS="${TCP_CHECKS:-off}"
TCP_MTUS="${TCP_MTUS:-1419 1420 1421 1422}"
TCP_STREAMS="${TCP_STREAMS:-1 4 16}"
TCP_DIRECTIONS="${TCP_DIRECTIONS:-forward reverse bidir}"
TCP_DURATION="${TCP_DURATION:-2}"
TCP_MIN_BYTES="${TCP_MIN_BYTES:-1048576}"
TCP_MAX_RETRANSMITS="${TCP_MAX_RETRANSMITS:-0}"
TCP_MIN_FAIRNESS="${TCP_MIN_FAIRNESS:-0.90}"
TCP_INNER_GSO_CHECKS="${TCP_INNER_GSO_CHECKS:-report}"
TCP_OUTER_GSO_CHECKS="${TCP_OUTER_GSO_CHECKS:-observe}"
TCP_CAPTURE_PACKETS="${TCP_CAPTURE_PACKETS:-4096}"
TCP_PORT="${TCP_PORT:-5201}"
UNDERLAY_MTU="${UNDERLAY_MTU:-2200}"
WG_MTU="${WG_MTU:-2000}"
NETNS_ANCHOR_TTL_SECONDS="${NETNS_ANCHOR_TTL_SECONDS:-28800}"

if [[ "${OUTER_FAMILY}" != "ipv4" && "${OUTER_FAMILY}" != "ipv6" ]]; then
  echo "error: OUTER_FAMILY must be ipv4 or ipv6" >&2
  exit 1
fi
if [[ "${XOR_SCOPE}" != "wg-payload-prefix" && "${XOR_SCOPE}" != "wg-payload-full" ]]; then
  echo "error: XOR_SCOPE must be wg-payload-prefix or wg-payload-full" >&2
  exit 1
fi
if ((XOR_ENABLED)); then
  if ((${#XOR_SECRET} > 256)) || [[ "${XOR_SECRET}" =~ [[:space:]] ]]; then
    echo "error: XOR_PASSWORD must contain 1-256 non-whitespace characters" >&2
    exit 1
  fi
fi
if [[ ! "${XOR_MAX_BYTES}" =~ ^[0-9]+$ ]] ||
  ((XOR_MAX_BYTES < 4 || XOR_MAX_BYTES > 2048 || XOR_MAX_BYTES % 4 != 0)); then
  echo "error: XOR_MAX_BYTES must be a multiple of 4 in [4, 2048]" >&2
  exit 1
fi
for check_mode in "${XOR_GENERATION_CHECKS}" "${XOR_DISPATCH_FAILURE_CHECKS}" \
  "${UDP_ZERO_CHECKSUM_CHECKS}" "${TCP_CHECKS}"; do
  if [[ "${check_mode}" != "off" && "${check_mode}" != "enforce" ]]; then
    echo "error: optional checks must be off or enforce" >&2
    exit 1
  fi
done
if [[ -n "${TCP_GSO_CHECKS+x}" ]]; then
  echo "error: TCP_GSO_CHECKS was split into TCP_INNER_GSO_CHECKS and TCP_OUTER_GSO_CHECKS" >&2
  exit 1
fi
if [[ "${TCP_INNER_GSO_CHECKS}" != "off" &&
  "${TCP_INNER_GSO_CHECKS}" != "report" &&
  "${TCP_INNER_GSO_CHECKS}" != "enforce" ]]; then
  echo "error: TCP_INNER_GSO_CHECKS must be off, report, or enforce" >&2
  exit 1
fi
if [[ "${TCP_OUTER_GSO_CHECKS}" != "off" &&
  "${TCP_OUTER_GSO_CHECKS}" != "observe" ]]; then
  echo "error: TCP_OUTER_GSO_CHECKS must be off or observe" >&2
  exit 1
fi
if [[ ! "${NETNS_ANCHOR_TTL_SECONDS}" =~ ^[0-9]+$ ]] ||
  ((NETNS_ANCHOR_TTL_SECONDS < 60 || NETNS_ANCHOR_TTL_SECONDS > 86400)); then
  echo "error: NETNS_ANCHOR_TTL_SECONDS must be an integer in [60, 86400]" >&2
  exit 1
fi
if [[ ! "${UNDERLAY_MTU}" =~ ^[0-9]+$ ]] ||
  ((UNDERLAY_MTU < 1280 || UNDERLAY_MTU > 65535)); then
  echo "error: UNDERLAY_MTU must be an integer in [1280, 65535]" >&2
  exit 1
fi
if [[ ! "${WG_MTU}" =~ ^[0-9]+$ ]] ||
  ((WG_MTU < 576 || WG_MTU > 65535)); then
  echo "error: WG_MTU must be an integer in [576, 65535]" >&2
  exit 1
fi
if [[ "${XOR_DISPATCH_FAILURE_CHECKS}" == "enforce" &&
  ( "${XOR_ENABLED}" -eq 0 || "${XOR_SCOPE}" != "wg-payload-full" || XOR_MAX_BYTES -lt 2048 ) ]]; then
  echo "error: dispatch failure checks require full-payload XOR with max_bytes=2048" >&2
  exit 1
fi
if [[ "${UDP_ZERO_CHECKSUM_CHECKS}" == "enforce" ]]; then
  if [[ "${OUTER_FAMILY}" != "ipv6" ]]; then
    echo "error: UDP zero-checksum checks require an IPv6 underlay" >&2
    exit 1
  fi
  if [[ "${XOR_ENABLED}" -eq 1 &&
    ( "${XOR_SCOPE}" != "wg-payload-full" || XOR_MAX_BYTES -lt 1968 ) ]]; then
    echo "error: XOR UDP zero-checksum checks require full-payload XOR with max_bytes>=1968" >&2
    exit 1
  fi
fi
TCP_MTU_VALUES=()
TCP_STREAM_VALUES=()
TCP_DIRECTION_VALUES=()
if [[ "${TCP_CHECKS}" == "enforce" ]]; then
  read -r -a TCP_MTU_VALUES <<<"${TCP_MTUS}"
  if ((${#TCP_MTU_VALUES[@]} == 0)); then
    echo "error: TCP_MTUS must contain at least one MTU" >&2
    exit 1
  fi
  seen_tcp_mtus=" "
  for tcp_mtu in "${TCP_MTU_VALUES[@]}"; do
    if [[ ! "${tcp_mtu}" =~ ^[0-9]+$ ]] || ((tcp_mtu < 576 || tcp_mtu > 65535)); then
      echo "error: TCP_MTUS values must be integers in [576, 65535]" >&2
      exit 1
    fi
    if [[ "${seen_tcp_mtus}" == *" ${tcp_mtu} "* ]]; then
      echo "error: TCP_MTUS contains duplicate value: ${tcp_mtu}" >&2
      exit 1
    fi
    seen_tcp_mtus+="${tcp_mtu} "
  done
  read -r -a TCP_STREAM_VALUES <<<"${TCP_STREAMS}"
  if ((${#TCP_STREAM_VALUES[@]} == 0)); then
    echo "error: TCP_STREAMS must contain at least one stream count" >&2
    exit 1
  fi
  seen_tcp_streams=" "
  for tcp_streams in "${TCP_STREAM_VALUES[@]}"; do
    if [[ ! "${tcp_streams}" =~ ^[0-9]+$ ]] ||
      ((tcp_streams < 1 || tcp_streams > 32)); then
      echo "error: TCP_STREAMS values must be integers in [1, 32]" >&2
      exit 1
    fi
    if [[ "${seen_tcp_streams}" == *" ${tcp_streams} "* ]]; then
      echo "error: TCP_STREAMS contains duplicate value: ${tcp_streams}" >&2
      exit 1
    fi
    seen_tcp_streams+="${tcp_streams} "
  done
  read -r -a TCP_DIRECTION_VALUES <<<"${TCP_DIRECTIONS}"
  if ((${#TCP_DIRECTION_VALUES[@]} == 0)); then
    echo "error: TCP_DIRECTIONS must contain at least one direction" >&2
    exit 1
  fi
  seen_tcp_directions=" "
  for tcp_direction in "${TCP_DIRECTION_VALUES[@]}"; do
    case "${tcp_direction}" in
      forward | reverse | bidir) ;;
      *)
        echo "error: TCP_DIRECTIONS values must be forward, reverse, or bidir" >&2
        exit 1
        ;;
    esac
    if [[ "${seen_tcp_directions}" == *" ${tcp_direction} "* ]]; then
      echo "error: TCP_DIRECTIONS contains duplicate value: ${tcp_direction}" >&2
      exit 1
    fi
    seen_tcp_directions+="${tcp_direction} "
  done
  if [[ ! "${TCP_DURATION}" =~ ^[0-9]+$ ]] ||
    ((TCP_DURATION < 1 || TCP_DURATION > 600)); then
    echo "error: TCP_DURATION must be an integer in [1, 600]" >&2
    exit 1
  fi
  if [[ ! "${TCP_MIN_BYTES}" =~ ^[0-9]+$ ]] || ((TCP_MIN_BYTES < 1)); then
    echo "error: TCP_MIN_BYTES must be a positive integer" >&2
    exit 1
  fi
  if [[ ! "${TCP_MAX_RETRANSMITS}" =~ ^[0-9]+$ ]]; then
    echo "error: TCP_MAX_RETRANSMITS must be a non-negative integer" >&2
    exit 1
  fi
  if [[ ! "${TCP_MIN_FAIRNESS}" =~ ^(0([.][0-9]+)?|1([.]0+)?)$ ]]; then
    echo "error: TCP_MIN_FAIRNESS must be a decimal in [0, 1]" >&2
    exit 1
  fi
  if [[ ! "${TCP_CAPTURE_PACKETS}" =~ ^[0-9]+$ ]] ||
    ((TCP_CAPTURE_PACKETS < 128 || TCP_CAPTURE_PACKETS > 65536)); then
    echo "error: TCP_CAPTURE_PACKETS must be an integer in [128, 65536]" >&2
    exit 1
  fi
  if [[ ! "${TCP_PORT}" =~ ^[0-9]+$ ]] ||
    ((TCP_PORT < 1024 || TCP_PORT > 65535)); then
    echo "error: TCP_PORT must be an integer in [1024, 65535]" >&2
    exit 1
  fi
fi

for cmd in \
  awk cat chmod date dirname env find grep hostname ip kill mkdir mount mountpoint ping python3 \
  realpath rm rmdir sed sh sleep stat sysctl tcpdump timeout umount wg; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "error: missing command: ${cmd}" >&2
    exit 1
  fi
done
if ((XOR_ENABLED)) && ! command -v bpftool >/dev/null 2>&1; then
  echo "error: missing command: bpftool" >&2
  exit 1
fi
if [[ "${TCP_CHECKS}" == "enforce" ]] && ! command -v iperf3 >/dev/null 2>&1; then
  echo "error: missing command: iperf3 (required when TCP_CHECKS=enforce)" >&2
  exit 1
fi
if [[ "${TCP_CHECKS}" == "enforce" ]] && ! command -v ethtool >/dev/null 2>&1; then
  echo "error: missing command: ethtool (required when TCP_CHECKS=enforce)" >&2
  exit 1
fi

if [[ ! -x "${BIN}" ]]; then
  echo "error: missing binary: ${BIN}" >&2
  exit 1
fi
if [[ ! -f "${LIFECYCLE_HOLDER_HELPER}" || -L "${LIFECYCLE_HOLDER_HELPER}" ]]; then
  echo "error: missing lifecycle holder helper: ${LIFECYCLE_HOLDER_HELPER}" >&2
  exit 1
fi
if [[ ! -f "${IPERF_CHECKER_HELPER}" || -L "${IPERF_CHECKER_HELPER}" ]]; then
  echo "error: missing iperf checker helper: ${IPERF_CHECKER_HELPER}" >&2
  exit 1
fi
if [[ ! -x "${NETNS_ANCHOR_HELPER}" || -L "${NETNS_ANCHOR_HELPER}" ]]; then
  echo "error: missing anonymous netns anchor helper: ${NETNS_ANCHOR_HELPER}" >&2
  exit 1
fi
exec {NETNS_ANCHOR_IMAGE_FD}<"${NETNS_ANCHOR_HELPER}"
NETNS_ANCHOR_EXEC="/proc/self/fd/${NETNS_ANCHOR_IMAGE_FD}"
read -r \
  NETNS_ANCHOR_HELPER_DEV \
  NETNS_ANCHOR_HELPER_INO \
  NETNS_ANCHOR_HELPER_UID \
  NETNS_ANCHOR_HELPER_MODE \
  NETNS_ANCHOR_HELPER_NLINK < <(
  stat -Lc '%d %i %u %a %h' -- "${NETNS_ANCHOR_EXEC}"
)
read -r NETNS_ANCHOR_PATH_DEV NETNS_ANCHOR_PATH_INO < <(
  stat -Lc '%d %i' -- "${NETNS_ANCHOR_HELPER}"
)
if [[ ! "${NETNS_ANCHOR_IMAGE_FD}" =~ ^[1-9][0-9]*$ ||
  ! "${NETNS_ANCHOR_HELPER_DEV}" =~ ^[1-9][0-9]*$ ||
  ! "${NETNS_ANCHOR_HELPER_INO}" =~ ^[1-9][0-9]*$ ||
  "${NETNS_ANCHOR_HELPER_UID}" != "${EUID}" ||
  ! "${NETNS_ANCHOR_HELPER_MODE}" =~ ^[0-7]{3,4}$ ||
  ! "${NETNS_ANCHOR_HELPER_NLINK}" =~ ^1$ ||
  ! -f "${NETNS_ANCHOR_EXEC}" ||
  "${NETNS_ANCHOR_PATH_DEV}" != "${NETNS_ANCHOR_HELPER_DEV}" ||
  "${NETNS_ANCHOR_PATH_INO}" != "${NETNS_ANCHOR_HELPER_INO}" ]] ||
  (((8#${NETNS_ANCHOR_HELPER_MODE} & 8#22) != 0)) ||
  (((8#${NETNS_ANCHOR_HELPER_MODE} & 8#111) == 0)); then
  echo "error: anonymous netns anchor helper file identity or mode is unsafe" >&2
  exit 1
fi
if [[ ! -x "${SOURCE_COMMIT_HELPER}" || -L "${SOURCE_COMMIT_HELPER}" ]]; then
  echo "error: missing fixed source commit helper: ${SOURCE_COMMIT_HELPER}" >&2
  exit 1
fi
EXPECTED_SOURCE_COMMIT="$(source_commit_from_root)"
MAIN_SOURCE_COMMIT="$(
  env -u XOR_PASSWORD "${BIN}" version --json |
    python3 -c 'import json, sys; print(json.load(sys.stdin).get("source_commit", ""))'
)"
NETNS_HELPER_SOURCE_COMMIT="$(
  env -u XOR_PASSWORD \
    "WG_MIX_EBPF_NETNS_ANCHOR_BOOTSTRAP_FD=${NETNS_ANCHOR_IMAGE_FD}" \
    "${NETNS_ANCHOR_EXEC}" identity
)"
for source_commit in \
  "${EXPECTED_SOURCE_COMMIT}" \
  "${MAIN_SOURCE_COMMIT}" \
  "${NETNS_HELPER_SOURCE_COMMIT}"; do
  if [[ ! "${source_commit}" =~ ^[0-9a-f]{40}$ ]]; then
    echo "error: unsealed build source commit: ${source_commit}" >&2
    exit 1
  fi
done
if [[ "${MAIN_SOURCE_COMMIT}" != "${EXPECTED_SOURCE_COMMIT}" ||
  "${NETNS_HELPER_SOURCE_COMMIT}" != "${EXPECTED_SOURCE_COMMIT}" ]]; then
  echo "error: test binaries do not match the clean source commit: source=${EXPECTED_SOURCE_COMMIT} main=${MAIN_SOURCE_COMMIT} anchor=${NETNS_HELPER_SOURCE_COMMIT}" >&2
  exit 1
fi

if [[ -n "${RUN_ID+x}" ]]; then
  echo "error: externally supplied RUN_ID is forbidden; each run uses a fresh random ID" >&2
  exit 1
fi
RUN_ID="$(python3 - <<'PY'
import secrets
print(secrets.token_hex(4))
PY
)"
if [[ ! "${RUN_ID}" =~ ^[0-9a-f]{8}$ ]]; then
  echo "error: failed to generate an 8-character random RUN_ID" >&2
  exit 1
fi
NSA="wme${RUN_ID}a"
NSR="wme${RUN_ID}r"
NSB="wme${RUN_ID}b"
VETH_A="wma${RUN_ID}0"
VETH_RA="wmr${RUN_ID}a"
VETH_B="wmb${RUN_ID}0"
VETH_RB="wmr${RUN_ID}b"
TEST_ROOT="/run/wg-mix-ebpf-tests"
RUN_BASE="${TEST_ROOT}/${RUN_ID}"
BPFFS_DIR="${RUN_BASE}/bpffs"
BPFFS_SOURCE="bpf"
BPFFS_MOUNT_ID=""
BPFFS_PARENT_DEV=""
BPFFS_PARENT_INO=""
PREEXISTING_MOUNT_IDS=""
PINA="${BPFFS_DIR}/wg-mix-ebpf-a"
PINB="${BPFFS_DIR}/wg-mix-ebpf-b"
PIN_RESOURCE_KEY_A=""
PIN_RESOURCE_KEY_B=""
PIN_LOCK_ROOT="${RUN_BASE}/pin-locks"
PIN_LOCK_A=""
PIN_LOCK_B=""
PIN_OWNER_ROOT="${RUN_BASE}/pin-owners"
PIN_OWNER_A=""
PIN_OWNER_B=""
RUN_DIR_A="${RUN_BASE}/run-a"
RUN_DIR_B="${RUN_BASE}/run-b"
STATE_DIR_A="${RUN_BASE}/state-a"
STATE_DIR_B="${RUN_BASE}/state-b"
TMPDIR="${RUN_BASE}/evidence"
SECRET_DIR="${RUN_BASE}/secrets"
LIFECYCLE_LEASE="${RUN_BASE}/lifecycle.lease"
OWNER_MARKER=".wg-mix-ebpf-test-owner"
MANIFEST="${RUN_BASE}/manifest"
OWNER_TOKEN="$(python3 - <<'PY'
import secrets
print(secrets.token_hex(16))
PY
)"
NETNS_SOCKET_A="wme-netns-${RUN_ID}-a-${OWNER_TOKEN}"
NETNS_SOCKET_R="wme-netns-${RUN_ID}-r-${OWNER_TOKEN}"
NETNS_SOCKET_B="wme-netns-${RUN_ID}-b-${OWNER_TOKEN}"
NETNS_AUTH_TOKEN="$(python3 - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
)"
NETNS_AUTH_TOKEN_FILE="${SECRET_DIR}/netns-anchor-token"
NETNS_READY_A="${TMPDIR}/netns-anchor-a.ready"
NETNS_READY_R="${TMPDIR}/netns-anchor-r.ready"
NETNS_READY_B="${TMPDIR}/netns-anchor-b.ready"
LIFECYCLE_HOLDER_STATUS="${TMPDIR}/lifecycle-holder-${OWNER_TOKEN}.status"
BOOT_ID="$(< /proc/sys/kernel/random/boot_id)"
HOST_ID="$(hostname)"
UDP_ZERO_CHECKSUM_RECEIVER_PID=""
AGENT_PID=""
TCP_SERVER_PID=""
TCP_CLIENT_PID=""
PCAP_CHECKER_PID=""
LIFECYCLE_HOLDER_PID=""
TCPDUMP_RA=""
TCPDUMP_RB=""
TCP_INNER_GSO_CAPABILITY="not-covered"
TCP_OUTER_GSO_CAPABILITY="not-covered"
TCP_OUTER_GSO_OBSERVED_ALL=1
TCP_OUTER_GSO_MEASUREMENT_OK=1
NETNS_A_DEV=""
NETNS_A_INO=""
NETNS_R_DEV=""
NETNS_R_INO=""
NETNS_B_DEV=""
NETNS_B_INO=""
NETNS_ANCHOR_PID_A=""
NETNS_ANCHOR_PID_R=""
NETNS_ANCHOR_PID_B=""
RUN_BASE_CREATED=0
TEARDOWN_COMPLETE=0
PHASE="preflight"
umask 077

print_command() {
  printf '  '
  printf '%q ' "$@"
  printf '\n'
}

failure_report() {
  local status="$1"
  local signal="${2:-none}"

  printf 'smoke failure: timestamp=%s status=%s signal=%s phase=%s host=%s run_id=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${status}" "${signal}" \
    "${PHASE}" "${HOST_ID}" "${RUN_ID}" >&2
  printf 'the failure trap performed no detach, delete, unmount, kill, or file cleanup\n' >&2
  if ((RUN_BASE_CREATED)); then
    printf 'evidence root: %s\nownership marker: %s\nmanifest: %s\n' \
      "${RUN_BASE}" "${RUN_BASE}/${OWNER_MARKER}" "${MANIFEST}" >&2
    printf 'sensitive recovery material (never copy as evidence): %s\n' \
      "${SECRET_DIR}" >&2
    printf 'review the marker, manifest, exact paths, and bounded inventory before recovery\n' >&2
    printf 'held anonymous netns helper image: fd=%s identity=%s:%s source_commit=%s\n' \
      "${NETNS_ANCHOR_IMAGE_FD}" \
      "${NETNS_ANCHOR_HELPER_DEV}" "${NETNS_ANCHOR_HELPER_INO}" \
      "${NETNS_HELPER_SOURCE_COMMIT}" >&2
    printf 'sealed anonymous netns anchors: a=%s:%s pid=%s socket=%s router=%s:%s pid=%s socket=%s b=%s:%s pid=%s socket=%s\n' \
      "${NETNS_A_DEV:-unsealed}" "${NETNS_A_INO:-unsealed}" \
      "${NETNS_ANCHOR_PID_A:-unsealed}" "${NETNS_SOCKET_A}" \
      "${NETNS_R_DEV:-unsealed}" "${NETNS_R_INO:-unsealed}" \
      "${NETNS_ANCHOR_PID_R:-unsealed}" "${NETNS_SOCKET_R}" \
      "${NETNS_B_DEV:-unsealed}" "${NETNS_B_INO:-unsealed}" \
      "${NETNS_ANCHOR_PID_B:-unsealed}" "${NETNS_SOCKET_B}" >&2
    printf 'no recovery mutation command is generated; use a separately committed and reviewed recovery script only after revalidating these identities\n' >&2
    printf 'do not remove files until every path is revalidated under %s/%s\n' \
      "${TEST_ROOT}" "${RUN_ID}" >&2
  fi
  for pid_record in \
    "tcpdump-ra:${TCPDUMP_RA}" "tcpdump-rb:${TCPDUMP_RB}" \
    "agent:${AGENT_PID}" "pcap-checker:${PCAP_CHECKER_PID}" \
    "lifecycle-holder:${LIFECYCLE_HOLDER_PID}" \
    "netns-anchor-a:${NETNS_ANCHOR_PID_A}" \
    "netns-anchor-r:${NETNS_ANCHOR_PID_R}" \
    "netns-anchor-b:${NETNS_ANCHOR_PID_B}" \
    "udp-receiver:${UDP_ZERO_CHECKSUM_RECEIVER_PID}" \
    "tcp-server:${TCP_SERVER_PID}" "tcp-client:${TCP_CLIENT_PID}"; do
    [[ "${pid_record#*:}" == "" ]] ||
      printf 'bounded background process left for timeout: %s\n' "${pid_record}" >&2
  done
}

on_exit() {
  local status=$?

  trap - EXIT INT TERM
  if ((status == 0)) && ((TEARDOWN_COMPLETE == 0)); then
    status=1
    printf 'error: refusing successful exit before explicit teardown completed\n' >&2
  fi
  if ((status != 0)); then
    failure_report "${status}"
  fi
  exit "${status}"
}

on_signal() {
  local signal="$1"
  local status="$2"

  trap - INT TERM
  failure_report "${status}" "${signal}"
  trap - EXIT
  exit "${status}"
}

trap on_exit EXIT
trap 'on_signal INT 130' INT
trap 'on_signal TERM 143' TERM

validate_owned_path() {
  local path="$1"
  local normalized

  if [[ -z "${path}" || "${path}" != /* ]]; then
    echo "error: owned path must be a non-empty absolute path: ${path}" >&2
    return 1
  fi
  normalized="$(realpath -m -- "${path}")"
  if [[ "${normalized}" != "${path}" ||
    ( "${path}" != "${RUN_BASE}" && "${path}" != "${RUN_BASE}/"* ) ]]; then
    echo "error: owned path escaped run root: ${path} -> ${normalized}" >&2
    return 1
  fi
}

marker_payload() {
  local role="$1"

  printf 'format=wg-mix-ebpf-test-owner-v1\n'
  printf 'run_id=%s\n' "${RUN_ID}"
  printf 'owner_token=%s\n' "${OWNER_TOKEN}"
  printf 'boot_id=%s\n' "${BOOT_ID}"
  printf 'role=%s\n' "${role}"
}

manifest_payload() {
  printf 'format=wg-mix-ebpf-test-manifest-v2\n'
  printf 'run_id=%s\nowner_token=%s\nboot_id=%s\nhost=%s\n' \
    "${RUN_ID}" "${OWNER_TOKEN}" "${BOOT_ID}" "${HOST_ID}"
  printf 'run_base=%s\nbpffs=%s\nbpffs_source=%s\nbpffs_mount_id=%s\n' \
    "${RUN_BASE}" "${BPFFS_DIR}" "${BPFFS_SOURCE}" "${BPFFS_MOUNT_ID}"
  printf 'pin_parent_dev=%s\npin_parent_ino=%s\n' \
    "${BPFFS_PARENT_DEV}" "${BPFFS_PARENT_INO}"
  printf 'pin_resource_key_a=%s\npin_resource_key_b=%s\n' \
    "${PIN_RESOURCE_KEY_A}" "${PIN_RESOURCE_KEY_B}"
  printf 'pin_lock_root=%s\npin_lock_a=%s\npin_lock_b=%s\n' \
    "${PIN_LOCK_ROOT}" "${PIN_LOCK_A}" "${PIN_LOCK_B}"
  printf 'pin_owner_root=%s\npin_owner_a=%s\npin_owner_b=%s\n' \
    "${PIN_OWNER_ROOT}" "${PIN_OWNER_A}" "${PIN_OWNER_B}"
  printf 'role_a=a\npin_a=%s\nrole_b=b\npin_b=%s\n' "${PINA}" "${PINB}"
  printf 'netns_a=%s\nnetns_a_dev=%s\nnetns_a_ino=%s\n' \
    "${NSA}" "${NETNS_A_DEV}" "${NETNS_A_INO}"
  printf 'netns_r=%s\nnetns_r_dev=%s\nnetns_r_ino=%s\n' \
    "${NSR}" "${NETNS_R_DEV}" "${NETNS_R_INO}"
  printf 'netns_b=%s\nnetns_b_dev=%s\nnetns_b_ino=%s\n' \
    "${NSB}" "${NETNS_B_DEV}" "${NETNS_B_INO}"
  printf 'run_dir_a=%s\nstate_dir_a=%s\nconfig_a=%s\nwg_config_a=%s\nunderlay_a=under0\n' \
    "${RUN_DIR_A}" "${STATE_DIR_A}" "${SECRET_DIR}/agent-a.yaml" \
    "${SECRET_DIR}/wg-a.conf"
  printf 'run_dir_b=%s\nstate_dir_b=%s\nconfig_b=%s\nwg_config_b=%s\nunderlay_b=under0\n' \
    "${RUN_DIR_B}" "${STATE_DIR_B}" "${SECRET_DIR}/agent-b.yaml" \
    "${SECRET_DIR}/wg-b.conf"
  printf 'lifecycle_lease=%s\n' "${LIFECYCLE_LEASE}"
  printf 'evidence=%s\nsecrets=%s\n' "${TMPDIR}" "${SECRET_DIR}"
}

write_marker() {
  local dir="$1"
  local role="$2"
  local marker="${dir}/${OWNER_MARKER}"

  validate_owned_path "${dir}" || return 1
  if [[ ! -d "${dir}" || -L "${dir}" || -e "${marker}" || -L "${marker}" ]]; then
    echo "error: unsafe marker target: ${marker}" >&2
    return 1
  fi
  (set -o noclobber; marker_payload "${role}" >"${marker}")
  chmod 0600 "${marker}"
}

validate_marker() {
  local dir="$1"
  local role="$2"
  local marker="${dir}/${OWNER_MARKER}"
  local expected
  local actual

  validate_owned_path "${dir}" || return 1
  if [[ ! -d "${dir}" || -L "${dir}" || ! -f "${marker}" || -L "${marker}" ||
    "$(stat -c '%u' -- "${dir}")" != "${EUID}" ||
    "$(stat -c '%a' -- "${dir}")" != "700" ||
    "$(stat -c '%u' -- "${marker}")" != "${EUID}" ||
    "$(stat -c '%a' -- "${marker}")" != "600" ||
    "$(stat -c '%h' -- "${marker}")" != "1" ]]; then
    echo "error: invalid ownership marker: ${marker}" >&2
    return 1
  fi
  expected="$(marker_payload "${role}")"
  actual="$(<"${marker}")"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "error: ownership marker content mismatch: ${marker}" >&2
    return 1
  fi
}

validate_manifest() {
  local expected
  local actual

  validate_owned_path "${MANIFEST}" || return 1
  if [[ ! -f "${MANIFEST}" || -L "${MANIFEST}" ||
    "$(stat -c '%u' -- "${MANIFEST}")" != "${EUID}" ||
    "$(stat -c '%a' -- "${MANIFEST}")" != "600" ||
    "$(stat -c '%h' -- "${MANIFEST}")" != "1" ]]; then
    echo "error: invalid manifest file: ${MANIFEST}" >&2
    return 1
  fi
  expected="$(manifest_payload)"
  actual="$(<"${MANIFEST}")"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "error: manifest content mismatch: ${MANIFEST}" >&2
    return 1
  fi
}

inspect_private_bpffs_mount_id() {
  local observed

  if ! mountpoint -q -- "${BPFFS_DIR}"; then
    echo "error: expected private bpffs mount is missing: ${BPFFS_DIR}" >&2
    return 1
  fi
  if ! observed="$(awk \
    -v target="${BPFFS_DIR}" \
    -v expected_source="${BPFFS_SOURCE}" '
      function separator_index(   field_index) {
        for (field_index = 6; field_index <= NF; field_index++) {
          if ($field_index == "-") {
            return field_index
          }
        }
        return 0
      }
      $5 == target {
        target_count++
        separator = separator_index()
        if (separator == 0 || $4 != "/" ||
            $(separator + 1) != "bpf" ||
            $(separator + 2) != expected_source) {
          invalid = 1
        }
        target_id = $1
        target_device = $3
        target_root = $4
        target_source = $(separator + 2)
      }
      $5 != target {
        separator = separator_index()
        if (separator != 0 && $(separator + 1) == "bpf") {
          other_bpf_count++
          other_bpf_id[other_bpf_count] = $1
          other_bpf_device[other_bpf_count] = $3
          other_bpf_root[other_bpf_count] = $4
        }
      }
      index($5, target "/") == 1 {
        nested = 1
      }
      END {
        if (target_count != 1 || invalid || nested) {
          exit 1
        }
        for (other_index = 1; other_index <= other_bpf_count; other_index++) {
          if (target_id == other_bpf_id[other_index] ||
              (target_device == other_bpf_device[other_index] &&
               target_root == other_bpf_root[other_index])) {
            exit 1
          }
        }
        print target_id
      }
    ' /proc/self/mountinfo)"; then
    echo "error: private bpffs is not an independent exact bpf mount root: ${BPFFS_DIR}" >&2
    return 1
  fi
  if [[ ! "${observed}" =~ ^[1-9][0-9]*$ ]]; then
    echo "error: invalid private bpffs mount ID: ${observed}" >&2
    return 1
  fi
  if [[ " ${PREEXISTING_MOUNT_IDS} " == *" ${observed} "* ]]; then
    echo "error: private bpffs mount ID was present before this run mounted bpffs: ${observed}" >&2
    return 1
  fi
  printf '%s\n' "${observed}"
}

validate_private_bpffs_mount() {
  local observed
  local observed_device
  local observed_inode

  observed="$(inspect_private_bpffs_mount_id)" || return 1
  if [[ -z "${BPFFS_MOUNT_ID}" || "${observed}" != "${BPFFS_MOUNT_ID}" ]]; then
    echo "error: private bpffs mount ID changed: expected=${BPFFS_MOUNT_ID} observed=${observed}" >&2
    return 1
  fi
  read -r observed_device observed_inode < <(
    stat -Lc '%d %i' -- "${BPFFS_DIR}"
  )
  if [[ ! "${observed_device}" =~ ^[1-9][0-9]*$ ||
    ! "${observed_inode}" =~ ^[1-9][0-9]*$ ||
    "${observed_device}" != "${BPFFS_PARENT_DEV}" ||
    "${observed_inode}" != "${BPFFS_PARENT_INO}" ]]; then
    echo "error: private bpffs dev:ino changed: expected=${BPFFS_PARENT_DEV}:${BPFFS_PARENT_INO} observed=${observed_device}:${observed_inode}" >&2
    return 1
  fi
}

pin_resource_key() {
  local parent_device="$1"
  local parent_inode="$2"
  local pin_path="$3"

  env -u XOR_PASSWORD python3 - \
    "${parent_device}" "${parent_inode}" "${pin_path}" <<'PY'
import hashlib
import pathlib
import re
import sys

parent_device, parent_inode, pin_path = sys.argv[1:]
for label, value in (
    ("parent device", parent_device),
    ("parent inode", parent_inode),
):
    if not re.fullmatch(r"[1-9][0-9]*", value):
        raise SystemExit(f"invalid canonical {label}: {value!r}")
basename = pathlib.PurePosixPath(pin_path).name
if (
    basename in ("", ".", "..")
    or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}", basename)
):
    raise SystemExit(f"invalid pin basename: {basename!r}")
canonical = (
    f"wg-mix-ebpf-pin-v1:{parent_device}:{parent_inode}:{basename}"
)
print(hashlib.sha256(canonical.encode("ascii")).hexdigest())
PY
}

assert_process_environment_secret_free() {
  local pid="$1"
  local label="$2"
  local secret_path=""

  if ((XOR_ENABLED)); then
    secret_path="${SECRET_DIR}/xor-password"
  fi
  env -u XOR_PASSWORD python3 - "${pid}" "${label}" "${secret_path}" <<'PY'
import pathlib
import sys
import time

root_pid = int(sys.argv[1])
label = sys.argv[2]
secret_path = sys.argv[3]
secret = b""
if secret_path:
    secret = pathlib.Path(secret_path).read_bytes().rstrip(b"\n")
    if not secret:
        raise SystemExit(f"{label}: XOR secret file is empty")

deadline = time.monotonic() + 2.0
descendants = set()
while time.monotonic() < deadline and not descendants:
    pending = [root_pid]
    pass_seen = set()
    root_alive = False
    while pending:
        pid = pending.pop()
        if pid in pass_seen:
            continue
        pass_seen.add(pid)
        proc = pathlib.Path("/proc") / str(pid)
        try:
            environ = (proc / "environ").read_bytes()
        except FileNotFoundError:
            continue
        if pid == root_pid:
            root_alive = True
        else:
            descendants.add(pid)
        entries = environ.split(b"\0")
        if any(entry.startswith(b"XOR_PASSWORD=") for entry in entries):
            raise SystemExit(f"{label}: pid {pid} inherited XOR_PASSWORD")
        values = [
            entry.partition(b"=")[2]
            for entry in entries
            if b"=" in entry
        ]
        if secret and any(
            value == secret or (len(secret) >= 16 and secret in value)
            for value in values
        ):
            raise SystemExit(
                f"{label}: pid {pid} inherited the XOR secret in its environment"
            )
        try:
            children = (proc / "task" / str(pid) / "children").read_text(
                encoding="ascii"
            )
        except FileNotFoundError:
            continue
        child_pids = [int(child) for child in children.split()]
        pending.extend(child_pids)
    if descendants:
        break
    if not root_alive:
        raise SystemExit(
            f"{label}: process {root_pid} exited before a descendant was audited"
        )
    time.sleep(0.01)

if not descendants:
    raise SystemExit(
        f"{label}: no actual descendant observed within the environment-audit window"
    )
PY
}

NETNS_CLIENT_ARGS=()

print_redacted_netns_argv() {
  local argument
  local redact_next=0

  for argument in "$@"; do
    if ((redact_next)); then
      printf '%q ' '<redacted-private-key-source>'
      redact_next=0
      continue
    fi
    case "${argument}" in
      private-key)
        printf '%q ' "${argument}"
        redact_next=1
        ;;
      private-key=*)
        printf '%q ' 'private-key=<redacted-private-key-source>'
        ;;
      *) printf '%q ' "${argument}" ;;
    esac
  done
}

audit_netns_argv() {
  local phase="$1"
  local ns="$2"
  local status="$3"
  shift 3

  case "${phase}" in
    start | finish) ;;
    *)
      echo "error: invalid network namespace audit phase: ${phase}" >&2
      return 1
      ;;
  esac
  if [[ "${status}" != "pending" && ! "${status}" =~ ^[0-9]+$ ]]; then
    echo "error: invalid network namespace audit status: ${status}" >&2
    return 1
  fi
  printf 'netns command %s: timestamp=%s netns=%q rc=%q argv=' \
    "${phase}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${ns}" "${status}" >&2
  print_redacted_netns_argv "$@" >&2
  printf '\n' >&2
}

set_netns_client_args() {
  local ns="$1"
  local prefix="${2:-}"
  local role
  local socket_name
  local expected_device
  local expected_inode
  local anchor_pid

  case "${prefix}" in
    "" | "left-" | "right-") ;;
    *)
      echo "error: invalid anonymous network namespace flag prefix: ${prefix}" >&2
      return 1
      ;;
  esac
  case "${ns}" in
    "${NSA}")
      role=a
      socket_name="${NETNS_SOCKET_A}"
      expected_device="${NETNS_A_DEV}"
      expected_inode="${NETNS_A_INO}"
      anchor_pid="${NETNS_ANCHOR_PID_A}"
      ;;
    "${NSR}")
      role=r
      socket_name="${NETNS_SOCKET_R}"
      expected_device="${NETNS_R_DEV}"
      expected_inode="${NETNS_R_INO}"
      anchor_pid="${NETNS_ANCHOR_PID_R}"
      ;;
    "${NSB}")
      role=b
      socket_name="${NETNS_SOCKET_B}"
      expected_device="${NETNS_B_DEV}"
      expected_inode="${NETNS_B_INO}"
      anchor_pid="${NETNS_ANCHOR_PID_B}"
      ;;
    *)
      echo "error: command requested unknown anonymous network namespace role: ${ns}" >&2
      return 1
      ;;
  esac
  if [[ ! "${expected_device}" =~ ^[1-9][0-9]*$ ||
    ! "${expected_inode}" =~ ^[1-9][0-9]*$ ||
    ! "${anchor_pid}" =~ ^[1-9][0-9]*$ ]]; then
    echo "error: anonymous network namespace contract is unsealed: ${ns}" >&2
    return 1
  fi
  NETNS_CLIENT_ARGS=(
    "--${prefix}socket" "${socket_name}"
    "--${prefix}token-file" "${NETNS_AUTH_TOKEN_FILE}"
    "--${prefix}run-id" "${RUN_ID}"
    "--${prefix}role" "${role}"
    "--${prefix}expected-device" "${expected_device}"
    "--${prefix}expected-inode" "${expected_inode}"
    "--${prefix}expected-anchor-pid" "${anchor_pid}"
    "--${prefix}expected-anchor-uid" "${EUID}"
  )
}

validate_netns_identity() {
  local ns="$1"
  local expected_device="$2"
  local expected_inode="$3"
  local expected_role="$4"

  case "${expected_role}:${ns}:${expected_device}:${expected_inode}" in
    "a:${NSA}:${NETNS_A_DEV}:${NETNS_A_INO}" | \
      "r:${NSR}:${NETNS_R_DEV}:${NETNS_R_INO}" | \
      "b:${NSB}:${NETNS_B_DEV}:${NETNS_B_INO}") ;;
    *)
      echo "error: invalid network namespace identity request: role=${expected_role} netns=${ns}" >&2
      return 1
      ;;
  esac
  if [[ ! "${expected_device}" =~ ^[1-9][0-9]*$ ||
    ! "${expected_inode}" =~ ^[1-9][0-9]*$ ]]; then
    echo "error: unsealed network namespace identity for ${ns}" >&2
    return 1
  fi
  set_netns_client_args "${ns}" || return 1
  env -u XOR_PASSWORD \
    "WG_MIX_EBPF_NETNS_ANCHOR_BOOTSTRAP_FD=${NETNS_ANCHOR_IMAGE_FD}" \
    "${NETNS_ANCHOR_EXEC}" probe \
    "${NETNS_CLIENT_ARGS[@]}"
}

validate_all_netns_identities() {
  validate_netns_identity "${NSA}" "${NETNS_A_DEV}" "${NETNS_A_INO}" a &&
    validate_netns_identity "${NSR}" "${NETNS_R_DEV}" "${NETNS_R_INO}" r &&
    validate_netns_identity "${NSB}" "${NETNS_B_DEV}" "${NETNS_B_INO}" b
}

run_in_owned_netns() {
  local ns="$1"
  local status
  local command=()
  shift

  if (($# == 0)); then
    echo "error: empty command requested for network namespace ${ns}" >&2
    return 1
  fi
  set_netns_client_args "${ns}" || return 1
  command=(
    env -u XOR_PASSWORD
    "WG_MIX_EBPF_NETNS_ANCHOR_BOOTSTRAP_FD=${NETNS_ANCHOR_IMAGE_FD}"
    "${NETNS_ANCHOR_EXEC}" exec
    "${NETNS_CLIENT_ARGS[@]}" --
    env -u XOR_PASSWORD "$@"
  )
  audit_netns_argv start "${ns}" pending "${command[@]}"
  if "${command[@]}"; then
    status=0
  else
    status=$?
  fi
  audit_netns_argv finish "${ns}" "${status}" "${command[@]}"
  return "${status}"
}

run_wg_set_with_private_key_in_owned_netns() {
  local ns="$1"
  local private_key_file="$2"
  local interface="$3"
  local status
  shift 3

  if [[ "${interface}" != "wg0" ]]; then
    echo "error: invalid WireGuard private-key interface" >&2
    return 1
  fi
  if [[ ! -f "${private_key_file}" || -L "${private_key_file}" ]]; then
    echo "error: unsafe WireGuard private-key source" >&2
    return 1
  fi

  # Bash opens the root-only key before any exec-triggered LSM profile change.
  # The producer receives only that inherited descriptor and writes an anonymous
  # pipe, so wg's /dev/stdin open cannot resolve back to the protected key path.
  # shellcheck disable=SC2002
  if env -u XOR_PASSWORD cat <"${private_key_file}" |
    run_in_owned_netns "${ns}" \
      wg set "${interface}" private-key /dev/stdin "$@"; then
    status=0
  else
    status=$?
  fi
  return "${status}"
}

run_bounded_in_owned_netns() {
  local ns="$1"
  local signal="$2"
  local duration="$3"
  shift 3

  if [[ ! "${signal}" =~ ^(TERM|INT)$ ||
    ! "${duration}" =~ ^[1-9][0-9]*$ || $# -eq 0 ]]; then
    echo "error: invalid bounded command for network namespace ${ns}" >&2
    return 1
  fi
  # Keep the auditable wrapper process observable before resolving the
  # exact namespace FD. The helper validates the authenticated anchor peer,
  # response identity, namespace type, and received descriptor before setns.
  sleep 0.2
  set_netns_client_args "${ns}" || return 1
  env -u XOR_PASSWORD timeout -s "${signal}" -k 2 "${duration}" \
    env -u XOR_PASSWORD \
    "WG_MIX_EBPF_NETNS_ANCHOR_BOOTSTRAP_FD=${NETNS_ANCHOR_IMAGE_FD}" \
    "${NETNS_ANCHOR_EXEC}" exec "${NETNS_CLIENT_ARGS[@]}" -- \
    env -u XOR_PASSWORD "$@"
}

create_veth_pair() {
  local left_link="$1"
  local left_ns="$2"
  local right_link="$3"
  local right_ns="$4"
  local left_args=()
  local right_args=()
  local status
  local command=()

  case "${left_link}:${left_ns}:${right_link}:${right_ns}" in
    "${VETH_A}:${NSA}:${VETH_RA}:${NSR}" | \
      "${VETH_B}:${NSB}:${VETH_RB}:${NSR}") ;;
    *)
      echo "error: invalid atomic veth pair request: left=${left_link}:${left_ns} right=${right_link}:${right_ns}" >&2
      return 1
      ;;
  esac
  set_netns_client_args "${left_ns}" "left-" || return 1
  left_args=("${NETNS_CLIENT_ARGS[@]}")
  set_netns_client_args "${right_ns}" "right-" || return 1
  right_args=("${NETNS_CLIENT_ARGS[@]}")
  command=(
    env -u XOR_PASSWORD
    "WG_MIX_EBPF_NETNS_ANCHOR_BOOTSTRAP_FD=${NETNS_ANCHOR_IMAGE_FD}"
    "${NETNS_ANCHOR_EXEC}" create-veth-pair
    "${left_args[@]}"
    "${right_args[@]}"
    --left-link "${left_link}"
    --right-link "${right_link}"
  )
  audit_netns_argv start "${left_ns}<->${right_ns}" pending "${command[@]}"
  if "${command[@]}"; then
    status=0
  else
    status=$?
  fi
  audit_netns_argv finish \
    "${left_ns}<->${right_ns}" "${status}" "${command[@]}"
  return "${status}"
}

start_netns_anchor() {
  local ns="$1"
  local role="$2"
  local socket_name="$3"
  local ready_file="$4"
  local anchor_pid
  local observed_device
  local observed_inode
  local observed_extra
  local ready_identity
  local anchor_status

  validate_owned_path "${ready_file}" || return 1
  if [[ -e "${ready_file}" || -L "${ready_file}" ]]; then
    echo "error: anonymous netns ready file already exists: ${ready_file}" >&2
    return 1
  fi
  env -u XOR_PASSWORD \
    "WG_MIX_EBPF_NETNS_ANCHOR_BOOTSTRAP_FD=${NETNS_ANCHOR_IMAGE_FD}" \
    "${NETNS_ANCHOR_EXEC}" anchor \
    --socket "${socket_name}" \
    --token-file "${NETNS_AUTH_TOKEN_FILE}" \
    --run-id "${RUN_ID}" \
    --role "${role}" \
    --ready-file "${ready_file}" \
    --ttl-seconds "${NETNS_ANCHOR_TTL_SECONDS}" \
    --parent-pid "$$" \
    --expected-client-uid "${EUID}" &
  anchor_pid=$!
  case "${role}" in
    a) NETNS_ANCHOR_PID_A="${anchor_pid}" ;;
    r) NETNS_ANCHOR_PID_R="${anchor_pid}" ;;
    b) NETNS_ANCHOR_PID_B="${anchor_pid}" ;;
    *)
      echo "error: invalid anonymous netns anchor role: ${role}" >&2
      return 1
      ;;
  esac
  for _ in {1..100}; do
    if [[ -f "${ready_file}" && ! -L "${ready_file}" ]]; then
      observed_device=""
      observed_inode=""
      observed_extra=""
      ready_identity=""
      if ready_identity="$(
        env -u XOR_PASSWORD \
          "WG_MIX_EBPF_NETNS_ANCHOR_BOOTSTRAP_FD=${NETNS_ANCHOR_IMAGE_FD}" \
          "${NETNS_ANCHOR_EXEC}" inspect-ready \
          --ready-file "${ready_file}" \
          --run-id "${RUN_ID}" \
          --role "${role}" \
          --socket "${socket_name}" \
          --expected-anchor-pid "${anchor_pid}" \
          --expected-anchor-uid "${EUID}" \
          --expected-parent-pid "$$"
      )"; then
        read -r observed_device observed_inode observed_extra <<<"${ready_identity}"
        if [[ ! "${observed_device}" =~ ^[1-9][0-9]*$ ||
          ! "${observed_inode}" =~ ^[1-9][0-9]*$ ||
          -n "${observed_extra}" ]]; then
          echo "error: anonymous netns inspector returned malformed identity: role=${role}" >&2
          return 1
        fi
        break
      fi
    fi
    if ! kill -0 "${anchor_pid}" >/dev/null 2>&1; then
      if wait "${anchor_pid}"; then
        anchor_status=0
      else
        anchor_status=$?
      fi
      echo "error: anonymous netns anchor exited before readiness: role=${role} status=${anchor_status}" >&2
      return 1
    fi
    sleep 0.05
  done
  if [[ ! "${observed_device}" =~ ^[1-9][0-9]*$ ||
    ! "${observed_inode}" =~ ^[1-9][0-9]*$ ]]; then
    echo "error: anonymous netns anchor readiness timed out: role=${role}" >&2
    return 1
  fi
  case "${role}" in
    a)
      NETNS_A_DEV="${observed_device}"
      NETNS_A_INO="${observed_inode}"
      ;;
    r)
      NETNS_R_DEV="${observed_device}"
      NETNS_R_INO="${observed_inode}"
      ;;
    b)
      NETNS_B_DEV="${observed_device}"
      NETNS_B_INO="${observed_inode}"
      ;;
  esac
  validate_netns_identity \
    "${ns}" "${observed_device}" "${observed_inode}" "${role}"
}

PHASE="create-owned-run-root"
if [[ -L "${TEST_ROOT}" ]]; then
  echo "error: test root must not be a symlink: ${TEST_ROOT}" >&2
  exit 1
fi
if [[ ! -e "${TEST_ROOT}" ]]; then
  mkdir -m 0700 -- "${TEST_ROOT}"
fi
if [[ ! -d "${TEST_ROOT}" || -L "${TEST_ROOT}" ||
  "$(realpath -e -- "${TEST_ROOT}")" != "${TEST_ROOT}" ||
  "$(stat -c '%u' -- "${TEST_ROOT}")" != "${EUID}" ||
  "$(stat -c '%a' -- "${TEST_ROOT}")" != "700" ]]; then
  echo "error: unsafe test root: ${TEST_ROOT}" >&2
  exit 1
fi
if [[ -e "${RUN_BASE}" || -L "${RUN_BASE}" ]]; then
  echo "error: random RUN_ID collision at ${RUN_BASE}; refusing cleanup or retry" >&2
  exit 1
fi
mkdir -m 0700 -- "${RUN_BASE}"
RUN_BASE_CREATED=1
for dir in "${RUN_DIR_A}" "${RUN_DIR_B}" "${STATE_DIR_A}" "${STATE_DIR_B}" \
  "${TMPDIR}" "${SECRET_DIR}" "${BPFFS_DIR}" "${PIN_LOCK_ROOT}" \
  "${PIN_OWNER_ROOT}"; do
  validate_owned_path "${dir}"
  mkdir -m 0700 -- "${dir}"
done
write_marker "${RUN_BASE}" root
write_marker "${RUN_DIR_A}" run-a
write_marker "${RUN_DIR_B}" run-b
write_marker "${STATE_DIR_A}" state-a
write_marker "${STATE_DIR_B}" state-b
write_marker "${TMPDIR}" evidence
write_marker "${SECRET_DIR}" secrets
write_marker "${PIN_LOCK_ROOT}" pin-locks
write_marker "${PIN_OWNER_ROOT}" pin-owners
if [[ ! "${NETNS_AUTH_TOKEN}" =~ ^[0-9a-f]{64}$ ]]; then
  echo "error: failed to generate a canonical anonymous netns authentication token" >&2
  exit 1
fi
(set -o noclobber; printf '%s\n' "${NETNS_AUTH_TOKEN}" >"${NETNS_AUTH_TOKEN_FILE}")
chmod 0600 "${NETNS_AUTH_TOKEN_FILE}"
unset NETNS_AUTH_TOKEN
if ((XOR_ENABLED)); then
  (set -o noclobber; printf '%s\n' "${XOR_SECRET}" >"${SECRET_DIR}/xor-password")
  chmod 0600 "${SECRET_DIR}/xor-password"
fi
unset XOR_SECRET

PHASE="mount-private-bpffs"
if mountpoint -q -- "${BPFFS_DIR}"; then
  echo "error: unexpected mount already exists at ${BPFFS_DIR}" >&2
  exit 1
fi
PREEXISTING_MOUNT_IDS="$(awk '
  {
    if ($1 !~ /^[1-9][0-9]*$/) {
      exit 1
    }
    printf "%s%s", separator, $1
    separator = " "
  }
  END {
    print ""
  }
' /proc/self/mountinfo)"
mount -t bpf -o nosuid,nodev,noexec,mode=0700 "${BPFFS_SOURCE}" "${BPFFS_DIR}"
BPFFS_MOUNT_ID="$(inspect_private_bpffs_mount_id)"
read -r BPFFS_PARENT_DEV BPFFS_PARENT_INO < <(
  stat -Lc '%d %i' -- "${BPFFS_DIR}"
)
for identity_part in "${BPFFS_PARENT_DEV}" "${BPFFS_PARENT_INO}"; do
  if [[ ! "${identity_part}" =~ ^[1-9][0-9]*$ ]]; then
    echo "error: invalid private bpffs identity component: ${identity_part}" >&2
    exit 1
  fi
done
PIN_RESOURCE_KEY_A="$(
  pin_resource_key "${BPFFS_PARENT_DEV}" "${BPFFS_PARENT_INO}" "${PINA}"
)"
PIN_RESOURCE_KEY_B="$(
  pin_resource_key "${BPFFS_PARENT_DEV}" "${BPFFS_PARENT_INO}" "${PINB}"
)"
for resource_key in "${PIN_RESOURCE_KEY_A}" "${PIN_RESOURCE_KEY_B}"; do
  if [[ ! "${resource_key}" =~ ^[0-9a-f]{64}$ ]]; then
    echo "error: invalid pin resource key: ${resource_key}" >&2
    exit 1
  fi
done
if [[ "${PIN_RESOURCE_KEY_A}" == "${PIN_RESOURCE_KEY_B}" ]]; then
  echo "error: isolated pins unexpectedly share a resource key" >&2
  exit 1
fi
PIN_LOCK_A="${PIN_LOCK_ROOT}/${PIN_RESOURCE_KEY_A}.lock"
PIN_LOCK_B="${PIN_LOCK_ROOT}/${PIN_RESOURCE_KEY_B}.lock"
PIN_OWNER_A="${PIN_OWNER_ROOT}/${PIN_RESOURCE_KEY_A}.owner.json"
PIN_OWNER_B="${PIN_OWNER_ROOT}/${PIN_RESOURCE_KEY_B}.owner.json"
for owned_path in "${PIN_LOCK_A}" "${PIN_LOCK_B}" "${PIN_OWNER_A}" "${PIN_OWNER_B}"; do
  validate_owned_path "${owned_path}"
done
validate_private_bpffs_mount

run_agent_in_netns() {
  local ns="$1"
  local pin="$2"
  local expected_pin
  local run_dir
  local state_dir
  local status
  local isolated_args=()
  shift 2

  case "${ns}" in
    "${NSA}")
      expected_pin="${PINA}"
      run_dir="${RUN_DIR_A}"
      state_dir="${STATE_DIR_A}"
      validate_netns_identity "${NSA}" "${NETNS_A_DEV}" "${NETNS_A_INO}" a ||
        return 1
      ;;
    "${NSB}")
      expected_pin="${PINB}"
      run_dir="${RUN_DIR_B}"
      state_dir="${STATE_DIR_B}"
      validate_netns_identity "${NSB}" "${NETNS_B_DEV}" "${NETNS_B_INO}" b ||
        return 1
      ;;
    *)
      echo "error: no isolated run/state directories for netns ${ns}" >&2
      return 1
      ;;
  esac
  if [[ "${pin}" != "${expected_pin}" ]]; then
    echo "error: pin path mismatch for netns ${ns}: ${pin}" >&2
    return 1
  fi
  validate_owned_path "${pin}" || return 1
  validate_marker "${run_dir}" "run-${ns: -1}" || return 1
  validate_marker "${state_dir}" "state-${ns: -1}" || return 1
  validate_marker "${PIN_LOCK_ROOT}" pin-locks || return 1
  validate_marker "${PIN_OWNER_ROOT}" pin-owners || return 1
  validate_manifest || return 1
  validate_private_bpffs_mount || return 1
  case "${1:-}" in
    reload | detach) isolated_args=(--isolated-netns-test) ;;
  esac
  printf 'agent command: timestamp=%s netns=%s pin=%s run_dir=%s state_dir=%s argv=' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${ns}" "${pin}" "${run_dir}" "${state_dir}" >&2
  printf '%q ' "${BIN}" "$@" "${isolated_args[@]}" \
    --run-dir "${run_dir}" --state-dir "${state_dir}" >&2
  printf '\n' >&2
  run_bounded_in_owned_netns "${ns}" TERM 60 \
    env -u XOR_PASSWORD "WG_MIX_EBPF_PIN_PATH=${pin}" \
    "${BIN}" "$@" "${isolated_args[@]}" \
    --run-dir "${run_dir}" --state-dir "${state_dir}" &
  AGENT_PID=$!
  assert_process_environment_secret_free "${AGENT_PID}" "agent-${ns}" || return 1
  if wait "${AGENT_PID}"; then
    status=0
  else
    status=$?
  fi
  AGENT_PID=""
  printf 'agent finish: timestamp=%s netns=%s exit=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${ns}" "${status}" >&2
  return "${status}"
}

teardown_step() {
  local description="$1"
  local status
  shift

  validate_marker "${RUN_BASE}" root || return 1
  validate_manifest || return 1
  printf 'teardown start: timestamp=%s action=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${description}"
  printf 'teardown argv:\n'
  print_command "$@"
  if "$@"; then
    status=0
  else
    status=$?
  fi
  printf 'teardown finish: timestamp=%s action=%s exit=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${description}" "${status}"
  return "${status}"
}

remove_owned_file() {
  local path="$1"

  validate_owned_path "${path}" || return 1
  if [[ ! -e "${path}" && ! -L "${path}" ]]; then
    printf 'teardown file absent: %s exit=0\n' "${path}"
    return 0
  fi
  if [[ ! -f "${path}" || -L "${path}" || "$(stat -c '%h' -- "${path}")" != "1" ]]; then
    echo "error: refusing to remove non-regular, linked, or symlink file: ${path}" >&2
    return 1
  fi
  if [[ "$(stat -c '%d' -- "$(dirname "${path}")")" != "$(stat -c '%d' -- "${RUN_BASE}")" ]]; then
    echo "error: refusing cross-filesystem file removal: ${path}" >&2
    return 1
  fi
  teardown_step "remove exact file ${path}" rm -- "${path}"
}

stop_owned_netns() {
  local ns="$1"
  local expected_device="$2"
  local expected_inode="$3"
  local expected_role="$4"
  local anchor_pid
  local status
  local wait_status

  validate_marker "${RUN_BASE}" root || return 1
  validate_manifest || return 1
  validate_netns_identity \
    "${ns}" "${expected_device}" "${expected_inode}" "${expected_role}" ||
    return 1
  set_netns_client_args "${ns}" || return 1
  case "${expected_role}" in
    a) anchor_pid="${NETNS_ANCHOR_PID_A}" ;;
    r) anchor_pid="${NETNS_ANCHOR_PID_R}" ;;
    b) anchor_pid="${NETNS_ANCHOR_PID_B}" ;;
    *)
      echo "error: invalid anonymous netns stop role: ${expected_role}" >&2
      return 1
      ;;
  esac
  printf 'teardown start: timestamp=%s action=stop anonymous netns anchor identity=%s:%s role=%s pid=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    "${expected_device}" "${expected_inode}" "${expected_role}" "${anchor_pid}"
  printf 'teardown argv:\n'
  print_command env -u XOR_PASSWORD \
    "WG_MIX_EBPF_NETNS_ANCHOR_BOOTSTRAP_FD=${NETNS_ANCHOR_IMAGE_FD}" \
    "${NETNS_ANCHOR_EXEC}" stop \
    "${NETNS_CLIENT_ARGS[@]}"
  if env -u XOR_PASSWORD \
    "WG_MIX_EBPF_NETNS_ANCHOR_BOOTSTRAP_FD=${NETNS_ANCHOR_IMAGE_FD}" \
    "${NETNS_ANCHOR_EXEC}" stop \
    "${NETNS_CLIENT_ARGS[@]}"; then
    status=0
  else
    status=$?
  fi
  if ((status != 0)); then
    printf 'teardown finish: timestamp=%s action=stop anonymous netns anchor role=%s client_exit=%s\n' \
      "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${expected_role}" "${status}"
    return "${status}"
  fi
  if wait "${anchor_pid}"; then
    wait_status=0
  else
    wait_status=$?
  fi
  if ((wait_status == 0)); then
    case "${expected_role}" in
      a) NETNS_ANCHOR_PID_A="" ;;
      r) NETNS_ANCHOR_PID_R="" ;;
      b) NETNS_ANCHOR_PID_B="" ;;
    esac
  fi
  printf 'teardown finish: timestamp=%s action=stop anonymous netns anchor role=%s client_exit=%s anchor_exit=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    "${expected_role}" "${status}" "${wait_status}"
  return "${wait_status}"
}

validate_released_pin_lock() {
  local path="$1"
  local pin="$2"
  local resource_key="$3"

  validate_owned_path "${PIN_LOCK_ROOT}" || return 1
  validate_owned_path "${path}" || return 1
  if [[ "$(dirname "${path}")" != "${PIN_LOCK_ROOT}" ||
    "${path}" != "${PIN_LOCK_ROOT}/${resource_key}.lock" ||
    ! "${resource_key}" =~ ^[0-9a-f]{64}$ ||
    ! -d "${PIN_LOCK_ROOT}" || -L "${PIN_LOCK_ROOT}" ||
    "$(stat -c '%u' -- "${PIN_LOCK_ROOT}")" != "${EUID}" ||
    "$(stat -c '%a' -- "${PIN_LOCK_ROOT}")" != "700" ||
    ! -f "${path}" || -L "${path}" ||
    "$(stat -c '%u' -- "${path}")" != "${EUID}" ||
    "$(stat -c '%a' -- "${path}")" != "600" ||
    "$(stat -c '%h' -- "${path}")" != "1" ]]; then
    echo "error: invalid isolated pin lock path: ${path}" >&2
    return 1
  fi
  env -u XOR_PASSWORD python3 - \
    "${path}" "${pin}" "${resource_key}" \
    "${BPFFS_PARENT_DEV}" "${BPFFS_PARENT_INO}" <<'PY'
import errno
import fcntl
import json
import os
import pathlib
import re
import stat
import sys

path, expected_pin, expected_key, expected_device, expected_inode = sys.argv[1:]
fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
try:
    metadata = os.fstat(fd)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
        or metadata.st_size <= 0
        or metadata.st_size > 64 * 1024
    ):
        raise SystemExit(f"{path}: unsafe pin-lock metadata")
    raw = os.read(fd, metadata.st_size + 1)
    if len(raw) != metadata.st_size:
        raise SystemExit(f"{path}: short pin-lock owner read")
    if (
        not raw.endswith(b"\n")
        or raw.count(b"\n") != 1
        or b"\0" in raw
        or b"\r" in raw
    ):
        raise SystemExit(f"{path}: pin-lock owner is not one JSON line plus LF")
    owner = json.loads(raw[:-1].decode("utf-8"))
    if set(owner) != {
        "version",
        "pid",
        "action",
        "resource_key",
        "parent_device",
        "parent_inode",
        "pin_basename",
        "pin_path",
    }:
        raise SystemExit(f"{path}: unexpected pin-lock owner keys")
    if (
        type(owner["version"]) is not int
        or owner["version"] != 2
        or type(owner["pid"]) is not int
        or owner["pid"] <= 0
        or owner["action"] != "detach"
        or not re.fullmatch(r"[0-9a-f]{64}", owner["resource_key"])
        or owner["resource_key"] != expected_key
        or type(owner["parent_device"]) is not int
        or owner["parent_device"] != int(expected_device)
        or type(owner["parent_inode"]) is not int
        or owner["parent_inode"] != int(expected_inode)
        or owner["pin_basename"] != pathlib.PurePosixPath(expected_pin).name
        or owner["pin_path"] != expected_pin
    ):
        raise SystemExit(f"{path}: pin-lock owner mismatch: {owner!r}")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        if exc.errno in (errno.EACCES, errno.EAGAIN):
            raise SystemExit(f"{path}: pin lock is still held") from exc
        raise
    fcntl.flock(fd, fcntl.LOCK_UN)
finally:
    os.close(fd)
PY
}

validate_pin_owner_absent() {
  local path="$1"
  local resource_key="$2"

  validate_owned_path "${PIN_OWNER_ROOT}" || return 1
  validate_owned_path "${path}" || return 1
  validate_marker "${PIN_OWNER_ROOT}" pin-owners || return 1
  if [[ "$(dirname "${path}")" != "${PIN_OWNER_ROOT}" ||
    "${path}" != "${PIN_OWNER_ROOT}/${resource_key}.owner.json" ||
    ! "${resource_key}" =~ ^[0-9a-f]{64}$ ]]; then
    echo "error: invalid isolated pin owner path: ${path}" >&2
    return 1
  fi
  if [[ -e "${path}" || -L "${path}" ]]; then
    echo "error: pin owner record remains after successful detach: ${path}" >&2
    return 1
  fi
}

validate_directory_only_has_owner_marker() {
  local path="$1"
  local role="$2"
  local unexpected

  validate_marker "${path}" "${role}" || return 1
  if ! unexpected="$(
    find "${path}" -xdev -mindepth 1 -maxdepth 1 \
      ! -path "${path}/${OWNER_MARKER}" -print -quit
  )"; then
    echo "error: could not inspect isolated resource root: ${path}" >&2
    return 1
  fi
  if [[ -n "${unexpected}" ]]; then
    echo "error: unexpected entry remains in isolated resource root: ${unexpected}" >&2
    return 1
  fi
}

validate_lifecycle_holder_status() {
  local state="$1"
  local expected
  local actual

  validate_owned_path "${LIFECYCLE_HOLDER_STATUS}" || return 1
  if [[ -z "${LIFECYCLE_HOLDER_PID}" ||
    "$(dirname "${LIFECYCLE_HOLDER_STATUS}")" != "${TMPDIR}" ||
    ! -f "${LIFECYCLE_HOLDER_STATUS}" || -L "${LIFECYCLE_HOLDER_STATUS}" ||
    "$(stat -c '%u' -- "${LIFECYCLE_HOLDER_STATUS}")" != "${EUID}" ||
    "$(stat -c '%a' -- "${LIFECYCLE_HOLDER_STATUS}")" != "600" ||
    "$(stat -c '%h' -- "${LIFECYCLE_HOLDER_STATUS}")" != "1" ]]; then
    echo "error: invalid lifecycle holder status file" >&2
    return 1
  fi
  expected="${state} ${LIFECYCLE_HOLDER_PID} ${OWNER_TOKEN}"
  actual="$(<"${LIFECYCLE_HOLDER_STATUS}")"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "error: lifecycle holder status mismatch: ${actual}" >&2
    return 1
  fi
}

start_lifecycle_hold() {
  local attempt
  local holder_status=0

  if [[ -n "${LIFECYCLE_HOLDER_PID}" ||
    -e "${LIFECYCLE_HOLDER_STATUS}" ||
    -L "${LIFECYCLE_HOLDER_STATUS}" ]]; then
    echo "error: lifecycle holder is already tracked" >&2
    return 1
  fi
  validate_marker "${RUN_BASE}" root || return 1
  validate_marker "${TMPDIR}" evidence || return 1
  validate_manifest || return 1
  env -u XOR_PASSWORD python3 "${LIFECYCLE_HOLDER_HELPER}" \
    --lease "${LIFECYCLE_LEASE}" \
    --manifest "${MANIFEST}" \
    --run-base "${RUN_BASE}" \
    --run-id "${RUN_ID}" \
    --owner-token "${OWNER_TOKEN}" \
    --boot-id "${BOOT_ID}" \
    --expected-config "${SECRET_DIR}/agent-b.yaml" \
    --expected-run-dir "${RUN_DIR_B}" \
    --expected-uid "${EUID}" \
    --status-path "${LIFECYCLE_HOLDER_STATUS}" \
    --parent-pid "$$" &
  LIFECYCLE_HOLDER_PID=$!
  for ((attempt = 0; attempt < 50; attempt++)); do
    if [[ -e "${LIFECYCLE_HOLDER_STATUS}" ]]; then
      validate_lifecycle_holder_status READY || return 1
      printf 'lifecycle teardown hold acquired: pid=%s lease=%s\n' \
        "${LIFECYCLE_HOLDER_PID}" "${LIFECYCLE_LEASE}"
      return 0
    fi
    if ! kill -0 "${LIFECYCLE_HOLDER_PID}" >/dev/null 2>&1; then
      if wait "${LIFECYCLE_HOLDER_PID}"; then
        holder_status=0
      else
        holder_status=$?
      fi
      echo "error: lifecycle holder exited before readiness (${holder_status}); cleanup is forbidden" >&2
      return 1
    fi
    sleep 0.1
  done
  echo "error: lifecycle holder did not become ready; cleanup is forbidden" >&2
  return 1
}

release_lifecycle_hold() {
  local holder_status=0

  validate_lifecycle_holder_status READY || return 1
  if ! kill -USR1 "${LIFECYCLE_HOLDER_PID}"; then
    echo "error: could not authorize lifecycle holder release" >&2
    return 1
  fi
  if wait "${LIFECYCLE_HOLDER_PID}"; then
    holder_status=0
  else
    holder_status=$?
  fi
  if ((holder_status != 0)); then
    echo "error: lifecycle holder exited with status ${holder_status}" >&2
    return "${holder_status}"
  fi
  validate_lifecycle_holder_status RELEASED || return 1
  printf 'lifecycle teardown hold released: lease=%s\n' "${LIFECYCLE_LEASE}"
  remove_owned_file "${LIFECYCLE_HOLDER_STATUS}" || return 1
  LIFECYCLE_HOLDER_PID=""
}

explicit_teardown() {
  local entry

  PHASE="explicit-teardown"
  validate_marker "${RUN_BASE}" root || return 1
  validate_marker "${RUN_DIR_A}" run-a || return 1
  validate_marker "${RUN_DIR_B}" run-b || return 1
  validate_marker "${STATE_DIR_A}" state-a || return 1
  validate_marker "${STATE_DIR_B}" state-b || return 1
  validate_marker "${TMPDIR}" evidence || return 1
  validate_marker "${SECRET_DIR}" secrets || return 1
  validate_marker "${PIN_LOCK_ROOT}" pin-locks || return 1
  validate_marker "${PIN_OWNER_ROOT}" pin-owners || return 1
  validate_manifest || return 1
  validate_private_bpffs_mount || return 1
  validate_all_netns_identities || return 1
  if [[ -n "${AGENT_PID}" || -n "${PCAP_CHECKER_PID}" ||
    -n "${LIFECYCLE_HOLDER_PID}" ||
    -n "${TCPDUMP_RA}" || -n "${TCPDUMP_RB}" ||
    -n "${UDP_ZERO_CHECKSUM_RECEIVER_PID}" || -n "${TCP_SERVER_PID}" ||
    -n "${TCP_CLIENT_PID}" ]]; then
    echo "error: refusing teardown while a bounded background process is still tracked" >&2
    return 1
  fi

  printf 'teardown host=%s boot_id=%s run_id=%s\n' "${HOST_ID}" "${BOOT_ID}" "${RUN_ID}"
  printf 'teardown exact root=%s\n' "$(realpath -e -- "${RUN_BASE}")"
  printf 'teardown bounded inventory (max depth 3):\n'
  find "${RUN_BASE}" -xdev -mindepth 1 -maxdepth 3 -printf '%y %p\n' |
    sed -n '1,200p' || return 1
  printf 'teardown bounded private bpffs inventory (max depth 3):\n'
  find "${BPFFS_DIR}" -xdev -mindepth 1 -maxdepth 3 -printf '%y %p\n' |
    sed -n '1,200p' || return 1

  teardown_step "detach agent A pin=${PINA}" \
    run_agent_in_netns "${NSA}" "${PINA}" detach \
    --config "${SECRET_DIR}/agent-a.yaml" || return 1
  teardown_step "detach agent B pin=${PINB}" \
    run_agent_in_netns "${NSB}" "${PINB}" detach \
    --config "${SECRET_DIR}/agent-b.yaml" || return 1
  start_lifecycle_hold || return 1
  validate_pin_owner_absent "${PIN_OWNER_A}" "${PIN_RESOURCE_KEY_A}" || return 1
  validate_pin_owner_absent "${PIN_OWNER_B}" "${PIN_RESOURCE_KEY_B}" || return 1
  validate_released_pin_lock \
    "${PIN_LOCK_A}" "${PINA}" "${PIN_RESOURCE_KEY_A}" || return 1
  validate_released_pin_lock \
    "${PIN_LOCK_B}" "${PINB}" "${PIN_RESOURCE_KEY_B}" || return 1
  remove_owned_file "${PIN_LOCK_A}" || return 1
  remove_owned_file "${PIN_LOCK_B}" || return 1
  validate_directory_only_has_owner_marker "${PIN_LOCK_ROOT}" pin-locks || return 1
  remove_owned_file "${PIN_LOCK_ROOT}/${OWNER_MARKER}" || return 1
  teardown_step "remove empty isolated pin lock root ${PIN_LOCK_ROOT}" \
    rmdir -- "${PIN_LOCK_ROOT}" || return 1
  validate_directory_only_has_owner_marker "${PIN_OWNER_ROOT}" pin-owners || return 1
  remove_owned_file "${PIN_OWNER_ROOT}/${OWNER_MARKER}" || return 1
  teardown_step "remove empty isolated pin owner root ${PIN_OWNER_ROOT}" \
    rmdir -- "${PIN_OWNER_ROOT}" || return 1

  if ! entry="$(find "${BPFFS_DIR}" -xdev -mindepth 1 -print -quit)"; then
    echo "error: could not inspect private bpffs before unmount" >&2
    return 1
  fi
  if [[ -n "${entry}" ]]; then
    echo "error: bpffs is not empty after exact detach: ${entry}" >&2
    return 1
  fi

  stop_owned_netns "${NSA}" "${NETNS_A_DEV}" "${NETNS_A_INO}" a || return 1
  stop_owned_netns "${NSR}" "${NETNS_R_DEV}" "${NETNS_R_INO}" r || return 1
  stop_owned_netns "${NSB}" "${NETNS_B_DEV}" "${NETNS_B_INO}" b || return 1

  for secret_file in \
    "${SECRET_DIR}/a.key" "${SECRET_DIR}/a.pub" \
    "${SECRET_DIR}/b.key" "${SECRET_DIR}/b.pub" \
    "${SECRET_DIR}/wg-a.conf" "${SECRET_DIR}/wg-b.conf" \
    "${SECRET_DIR}/agent-a.yaml" "${SECRET_DIR}/agent-b.yaml" \
    "${NETNS_AUTH_TOKEN_FILE}"; do
    remove_owned_file "${secret_file}" || return 1
  done
  if ((XOR_ENABLED)); then
    remove_owned_file "${SECRET_DIR}/xor-password" || return 1
  fi
  remove_owned_file "${SECRET_DIR}/${OWNER_MARKER}" || return 1
  teardown_step "remove empty sensitive directory ${SECRET_DIR}" \
    rmdir -- "${SECRET_DIR}" || return 1

  validate_private_bpffs_mount || return 1
  teardown_step "unmount exact bpffs ${BPFFS_DIR}" \
    umount -- "${BPFFS_DIR}" || return 1
  teardown_step "remove empty bpffs mountpoint ${BPFFS_DIR}" \
    rmdir -- "${BPFFS_DIR}" || return 1

  remove_owned_file "${RUN_DIR_A}/lock" || return 1
  remove_owned_file "${RUN_DIR_B}/lock" || return 1
  remove_owned_file "${LIFECYCLE_LEASE}" || return 1
  remove_owned_file "${RUN_DIR_A}/${OWNER_MARKER}" || return 1
  remove_owned_file "${RUN_DIR_B}/${OWNER_MARKER}" || return 1
  remove_owned_file "${STATE_DIR_A}/${OWNER_MARKER}" || return 1
  remove_owned_file "${STATE_DIR_B}/${OWNER_MARKER}" || return 1
  teardown_step "remove empty run dir A ${RUN_DIR_A}" \
    rmdir -- "${RUN_DIR_A}" || return 1
  teardown_step "remove empty run dir B ${RUN_DIR_B}" \
    rmdir -- "${RUN_DIR_B}" || return 1
  teardown_step "remove empty state dir A ${STATE_DIR_A}" \
    rmdir -- "${STATE_DIR_A}" || return 1
  teardown_step "remove empty state dir B ${STATE_DIR_B}" \
    rmdir -- "${STATE_DIR_B}" || return 1

  release_lifecycle_hold || return 1
  printf 'test evidence intentionally retained at %s\n' "${TMPDIR}"
  printf 'manifest intentionally retained at %s\n' "${MANIFEST}"
  printf 'sensitive recovery material removed from %s\n' "${SECRET_DIR}"
  TEARDOWN_COMPLETE=1
}

make_agent_config() {
  local path="$1"
  local underlay="$2"
  local wg_config="$3"
  local cipher_ref=""
  local cipher_block=""
  if ((XOR_ENABLED)); then
    cipher_ref="    cipher: xor-home"
    cipher_block="
ciphers:
  xor-home:
    mode: xor
    auth: none
    scope: ${XOR_SCOPE}
    key_derivation: udp2raw-md5-key1
    secret_file: ${SECRET_DIR}/xor-password
    max_bytes: ${XOR_MAX_BYTES}
"
  fi
  cat >"${path}" <<EOF_CONFIG
version: 1
mode: transparent-typeword

underlays:
  - name: ${underlay}
    type: netdev

wireguards:
  - name: wg0
    config: ${wg_config}
    profile: mix-default
${cipher_ref}

profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
    index:
      mode: none
${cipher_block}

fwmark_policy:
  mode: config-required

startup_guard:
  mode: none

runtime:
  require_nonzero_fwmark: true
  strict_runtime_fwmark: true
  allow_zero_fwmark_fallback: false

policy:
  managed_egress_map_miss: drop
EOF_CONFIG
}

make_wg_config_stub() {
  local path="$1"
  local port="$2"
  local mark="$3"
  cat >"${path}" <<EOF_CONFIG
[Interface]
ListenPort = ${port}
FwMark = ${mark}
EOF_CONFIG
}

wait_ping() {
  local ns="$1"
  local target="$2"

  for _ in 1 2 3 4 5; do
    if run_in_owned_netns "${ns}" \
      ping -c 1 -W 2 "${target}" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  return 1
}

large_ping() {
  local ns="$1"
  local target="$2"

  run_in_owned_netns "${ns}" \
    ping -c 2 -W 2 -M "do" -s 1900 "${target}" >/dev/null
}

exercise_tunnel() {
  wait_ping "${NSA}" 10.77.0.2
  wait_ping "${NSB}" 10.77.0.1
  if [[ "${XOR_ENABLED}" -eq 1 && "${XOR_SCOPE}" == "wg-payload-full" &&
    "${XOR_MAX_BYTES}" -ge 2048 ]]; then
    large_ping "${NSA}" 10.77.0.2
    large_ping "${NSB}" 10.77.0.1
  fi
}

active_generation() {
  python3 - "$1" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    doc = json.load(fh)
dataplane = doc.get("dataplane") or doc.get("kernel") or doc
print(int(dataplane.get("active_generation", 0)))
PY
}

stat_value() {
  python3 - "$1" "$2" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    doc = json.load(fh)
stats = None
for container_name in ("dataplane", "kernel"):
    container = doc.get(container_name)
    if isinstance(container, dict) and "stats" in container:
        stats = container["stats"]
        break
if stats is None and "stats" in doc:
    stats = doc["stats"]
if not isinstance(stats, dict):
    raise SystemExit(f"{sys.argv[1]}: missing stats map")
stat = sys.argv[2]
if stat not in stats:
    raise SystemExit(f"{sys.argv[1]}: missing stat: {stat}")
try:
    print(int(stats[stat]))
except (TypeError, ValueError) as exc:
    raise SystemExit(
        f"{sys.argv[1]}: invalid stat value for {stat}: {stats[stat]!r}"
    ) from exc
PY
}

assert_stat_increased() {
  local before_path="$1"
  local after_path="$2"
  local stat="$3"
  local before
  local after

  before="$(stat_value "${before_path}" "${stat}")"
  after="$(stat_value "${after_path}" "${stat}")"
  if ((after <= before)); then
    echo "error: ${stat} did not increase (${before} -> ${after})" >&2
    return 1
  fi
}

assert_stat_unchanged() {
  local before_path="$1"
  local after_path="$2"
  local stat="$3"
  local before
  local after

  before="$(stat_value "${before_path}" "${stat}")"
  after="$(stat_value "${after_path}" "${stat}")"
  if ((after != before)); then
    echo "error: ${stat} changed (${before} -> ${after})" >&2
    return 1
  fi
}

print_stat_delta() {
  local before_path="$1"
  local after_path="$2"
  local stat="$3"
  local before
  local after

  before="$(stat_value "${before_path}" "${stat}")"
  after="$(stat_value "${after_path}" "${stat}")"
  printf 'tcp stat_delta=%s before=%s after=%s delta=%s\n' \
    "${stat}" "${before}" "${after}" "$((after - before))"
}

stat_delta_value() {
  local before_path="$1"
  local after_path="$2"
  local stat="$3"
  local before
  local after

  before="$(stat_value "${before_path}" "${stat}")"
  after="$(stat_value "${after_path}" "${stat}")"
  if ((after < before)); then
    echo "error: ${stat} counter moved backwards (${before} -> ${after})" >&2
    return 1
  fi
  printf '%s\n' "$((after - before))"
}

capture_tcp_link_evidence() {
  local phase="$1"
  local label="$2"
  local ns="$3"
  local link="$4"
  local prefix="${TMPDIR}/tcp-evidence-${phase}-${label}"

  run_in_owned_netns "${ns}" \
    ip -details -statistics link show dev "${link}" \
    >"${prefix}-link.txt"
  run_in_owned_netns "${ns}" \
    ethtool -k "${link}" >"${prefix}-offloads.txt"
}

tcp_gso_link_features_enabled() {
  local scope="$1"
  local label="$2"
  local ns="$3"
  local link="$4"
  local evidence="${TMPDIR}/tcp-gso-${scope}-${label}-offloads.txt"
  local feature

  shift 4
  if [[ "${scope}" != "inner" && "${scope}" != "outer" ]] || (($# == 0)); then
    echo "error: invalid TCP GSO capability request: scope=${scope} label=${label} link=${link}" >&2
    return 1
  fi
  run_in_owned_netns "${ns}" ethtool -k "${link}" >"${evidence}"
  for feature in "$@"; do
    if ! awk -F ':' -v wanted="${feature}" '
      {
        key = $1
        sub(/^[[:space:]]+/, "", key)
        sub(/[[:space:]]+$/, "", key)
      }
      key == wanted {
        value = $2
        sub(/^[[:space:]]+/, "", value)
        split(value, fields, /[[:space:]]+/)
        found = 1
        enabled = fields[1] == "on"
      }
      END {
        exit !(found && enabled)
      }
    ' "${evidence}"; then
      printf 'tcp evidence=%s-gso-capability status=unsupported label=%s link=%s feature=%s evidence=%s\n' \
        "${scope}" "${label}" "${link}" "${feature}" "${evidence}"
      return 1
    fi
    printf 'tcp evidence=%s-gso-capability status=supported label=%s link=%s feature=%s state=on\n' \
      "${scope}" "${label}" "${link}" "${feature}"
  done
}

classify_tcp_gso_capabilities() {
  local inner_supported=1
  local outer_supported=1

  if [[ "${TCP_INNER_GSO_CHECKS}" == "off" ]]; then
    TCP_INNER_GSO_CAPABILITY="not-covered"
    printf 'tcp evidence=inner-tcp-gso status=not-covered reason=disabled\n'
  else
    if ! tcp_gso_link_features_enabled inner a-wg "${NSA}" wg0 \
      tx-checksumming scatter-gather \
      tcp-segmentation-offload generic-segmentation-offload; then
      inner_supported=0
    fi
    if ! tcp_gso_link_features_enabled inner b-wg "${NSB}" wg0 \
      tx-checksumming scatter-gather \
      tcp-segmentation-offload generic-segmentation-offload; then
      inner_supported=0
    fi
    if ((inner_supported)); then
      TCP_INNER_GSO_CAPABILITY="supported"
    else
      TCP_INNER_GSO_CAPABILITY="unsupported"
    fi
    printf 'tcp evidence=inner-tcp-gso status=%s mode=%s correctness_gate=false\n' \
      "${TCP_INNER_GSO_CAPABILITY}" "${TCP_INNER_GSO_CHECKS}"
    if [[ "${TCP_INNER_GSO_CHECKS}" == "enforce" &&
      "${TCP_INNER_GSO_CAPABILITY}" != "supported" ]]; then
      echo "error: requested inner TCP GSO capability is unsupported" >&2
      return 1
    fi
  fi

  if [[ "${TCP_OUTER_GSO_CHECKS}" == "off" ]]; then
    TCP_OUTER_GSO_CAPABILITY="not-covered"
    TCP_OUTER_GSO_OBSERVED_ALL=0
    printf 'tcp evidence=outer-udp-gso status=not-covered reason=disabled\n'
    return 0
  fi

  if ! tcp_gso_link_features_enabled outer a-underlay "${NSA}" under0 \
    tx-checksumming scatter-gather generic-segmentation-offload \
    generic-receive-offload tx-udp-segmentation; then
    outer_supported=0
  fi
  if ! tcp_gso_link_features_enabled outer b-underlay "${NSB}" under0 \
    tx-checksumming scatter-gather generic-segmentation-offload \
    generic-receive-offload tx-udp-segmentation; then
    outer_supported=0
  fi
  if ! tcp_gso_link_features_enabled outer router-a "${NSR}" ra0 \
    tx-checksumming scatter-gather generic-segmentation-offload \
    generic-receive-offload tx-udp-segmentation; then
    outer_supported=0
  fi
  if ! tcp_gso_link_features_enabled outer router-b "${NSR}" rb0 \
    tx-checksumming scatter-gather generic-segmentation-offload \
    generic-receive-offload tx-udp-segmentation; then
    outer_supported=0
  fi
  if ((outer_supported)); then
    TCP_OUTER_GSO_CAPABILITY="supported"
  else
    TCP_OUTER_GSO_CAPABILITY="unsupported"
  fi
  printf 'tcp evidence=outer-udp-gso-capability status=%s\n' \
    "${TCP_OUTER_GSO_CAPABILITY}"
}

record_tcp_outer_gso_observation() {
  local before_path="$1"
  local after_path="$2"
  local mtu="$3"
  local side="$4"
  local stat
  local delta
  local measurement_ok=1
  local observed=1
  local status

  if [[ "${TCP_OUTER_GSO_CHECKS}" == "off" ]]; then
    return 0
  fi
  for stat in \
    egress_gso_seen egress_gso_managed_seen egress_gso_rewrite_ok \
    ingress_gso_seen ingress_gso_listener_hit ingress_gso_rewrite_ok; do
    if ! delta="$(stat_delta_value "${before_path}" "${after_path}" "${stat}")"; then
      measurement_ok=0
      observed=0
      TCP_OUTER_GSO_MEASUREMENT_OK=0
      printf 'tcp evidence=outer-udp-gso-counter mtu=%s side=%s stat=%s status=not-covered reason=measurement-error\n' \
        "${mtu}" "${side}" "${stat}" >&2
      continue
    fi
    printf 'tcp stat_delta=%s before_file=%s after_file=%s delta=%s\n' \
      "${stat}" "${before_path}" "${after_path}" "${delta}"
    case "${stat}" in
      egress_gso_managed_seen | egress_gso_rewrite_ok | \
        ingress_gso_listener_hit | ingress_gso_rewrite_ok)
        if ((delta == 0)); then
          observed=0
        fi
        ;;
    esac
  done
  if ((!measurement_ok)); then
    status="not-covered"
    TCP_OUTER_GSO_OBSERVED_ALL=0
  elif ((observed)); then
    status="observed"
  elif [[ "${TCP_OUTER_GSO_CAPABILITY}" == "unsupported" ]]; then
    status="unsupported"
    TCP_OUTER_GSO_OBSERVED_ALL=0
  else
    status="not-covered"
    TCP_OUTER_GSO_OBSERVED_ALL=0
  fi
  printf 'tcp evidence=outer-udp-gso mtu=%s side=%s status=%s\n' \
    "${mtu}" "${side}" "${status}"
}

finalize_tcp_gso_evidence() {
  local status

  if [[ "${TCP_OUTER_GSO_CHECKS}" == "off" ]]; then
    status="not-covered"
  elif ((TCP_OUTER_GSO_OBSERVED_ALL)); then
    status="observed"
  elif ((!TCP_OUTER_GSO_MEASUREMENT_OK)); then
    status="not-covered"
  elif [[ "${TCP_OUTER_GSO_CAPABILITY}" == "unsupported" ]]; then
    status="unsupported"
  else
    status="not-covered"
  fi
  printf 'tcp summary=inner-tcp-gso status=%s mode=%s\n' \
    "${TCP_INNER_GSO_CAPABILITY}" "${TCP_INNER_GSO_CHECKS}"
  printf 'tcp summary=outer-udp-gso status=%s mode=%s correctness_gate=false\n' \
    "${status}" "${TCP_OUTER_GSO_CHECKS}"
}

assert_wg_transfer_increased() {
  local before_path="$1"
  local after_path="$2"
  local side="$3"
  local mtu="$4"

  env -u XOR_PASSWORD python3 - \
    "${before_path}" "${after_path}" "${side}" "${mtu}" <<'PY'
import pathlib
import sys


def read_transfer(path_value: str) -> tuple[str, int, int]:
    path = pathlib.Path(path_value)
    lines = [
        line.split()
        for line in path.read_text(encoding="ascii").splitlines()
        if line.strip()
    ]
    if len(lines) != 1 or len(lines[0]) != 3:
        raise SystemExit(f"{path}: expected exactly one WireGuard transfer row")
    peer, received_raw, sent_raw = lines[0]
    if not peer or not received_raw.isascii() or not received_raw.isdigit():
        raise SystemExit(f"{path}: malformed received transfer row")
    if not sent_raw.isascii() or not sent_raw.isdigit():
        raise SystemExit(f"{path}: malformed sent transfer row")
    return peer, int(received_raw), int(sent_raw)


before_path, after_path, side, mtu = sys.argv[1:]
before_peer, before_received, before_sent = read_transfer(before_path)
after_peer, after_received, after_sent = read_transfer(after_path)
if before_peer != after_peer:
    raise SystemExit(
        f"WireGuard peer changed for side={side} mtu={mtu}: "
        f"{before_peer!r} -> {after_peer!r}"
    )
received_delta = after_received - before_received
sent_delta = after_sent - before_sent
if received_delta <= 0 or sent_delta <= 0:
    raise SystemExit(
        f"WireGuard transfer did not increase both ways for side={side} "
        f"mtu={mtu}: rx_delta={received_delta} tx_delta={sent_delta}"
    )
print(
    f"tcp evidence=wireguard-transfer side={side} mtu={mtu} "
    f"status=passed rx_delta={received_delta} tx_delta={sent_delta}"
)
PY
}

capture_tcp_netns_evidence() {
  local phase="$1"
  local side
  local ns

  case "${phase}" in
    before | after | failure) ;;
    *)
      echo "error: invalid TCP evidence phase: ${phase}" >&2
      return 1
      ;;
  esac
  capture_tcp_link_evidence "${phase}" a "${NSA}" under0
  capture_tcp_link_evidence "${phase}" b "${NSB}" under0
  capture_tcp_link_evidence "${phase}" a-wg "${NSA}" wg0
  capture_tcp_link_evidence "${phase}" b-wg "${NSB}" wg0
  capture_tcp_link_evidence "${phase}" router-a "${NSR}" ra0
  capture_tcp_link_evidence "${phase}" router-b "${NSR}" rb0
  run_in_owned_netns "${NSA}" wg show wg0 \
    >"${TMPDIR}/tcp-evidence-${phase}-a-wg.txt"
  run_in_owned_netns "${NSB}" wg show wg0 \
    >"${TMPDIR}/tcp-evidence-${phase}-b-wg.txt"
  for side in a b router; do
    case "${side}" in
      a) ns="${NSA}" ;;
      b) ns="${NSB}" ;;
      router) ns="${NSR}" ;;
    esac
    run_in_owned_netns "${ns}" cat /proc/net/snmp \
      >"${TMPDIR}/tcp-evidence-${phase}-${side}-snmp.txt"
    run_in_owned_netns "${ns}" cat /proc/net/netstat \
      >"${TMPDIR}/tcp-evidence-${phase}-${side}-netstat.txt"
    run_in_owned_netns "${ns}" ip route show table all \
      >"${TMPDIR}/tcp-evidence-${phase}-${side}-routes.txt"
  done
}

start_tcp_capture() {
  local label="$1"
  local capture_timeout="$2"

  if [[ ! "${label}" =~ ^tcp-mtu[0-9]+-p[0-9]+-(forward|reverse|bidir)$ ||
    ! "${capture_timeout}" =~ ^[1-9][0-9]*$ ]]; then
    echo "error: invalid per-cell TCP capture identity: ${label} timeout=${capture_timeout}" >&2
    return 1
  fi
  if [[ -n "${TCPDUMP_RA}" || -n "${TCPDUMP_RB}" ]]; then
    echo "error: packet capture PID already active before TCP matrix" >&2
    return 1
  fi
  run_bounded_in_owned_netns "${NSR}" INT "${capture_timeout}" \
    tcpdump -s 192 -c "${TCP_CAPTURE_PACKETS}" \
    -i ra0 -w "${TMPDIR}/${label}-ra.pcap" udp \
    >/dev/null 2>"${TMPDIR}/${label}-tcpdump-ra.log" &
  TCPDUMP_RA=$!
  assert_process_environment_secret_free \
    "${TCPDUMP_RA}" "tcpdump-ra-${label}" || return 1
  run_bounded_in_owned_netns "${NSR}" INT "${capture_timeout}" \
    tcpdump -s 192 -c "${TCP_CAPTURE_PACKETS}" \
    -i rb0 -w "${TMPDIR}/${label}-rb.pcap" udp \
    >/dev/null 2>"${TMPDIR}/${label}-tcpdump-rb.log" &
  TCPDUMP_RB=$!
  assert_process_environment_secret_free \
    "${TCPDUMP_RB}" "tcpdump-rb-${label}" || return 1
  sleep 1
  if ! kill -0 "${TCPDUMP_RA}" >/dev/null 2>&1 ||
    ! kill -0 "${TCPDUMP_RB}" >/dev/null 2>&1; then
    echo "error: per-cell TCP capture exited before traffic: ${label}" >&2
    return 1
  fi
}

finish_tcp_capture() {
  local label="$1"
  local ra_status=0
  local rb_status=0
  local result=0

  if [[ ! "${label}" =~ ^tcp-mtu[0-9]+-p[0-9]+-(forward|reverse|bidir)$ ]]; then
    echo "error: invalid per-cell TCP capture finish identity: ${label}" >&2
    return 1
  fi
  if [[ -z "${TCPDUMP_RA}" || -z "${TCPDUMP_RB}" ]]; then
    echo "error: TCP packet capture PID is missing" >&2
    return 1
  fi
  if wait "${TCPDUMP_RA}"; then
    ra_status=0
  else
    ra_status=$?
  fi
  TCPDUMP_RA=""
  if wait "${TCPDUMP_RB}"; then
    rb_status=0
  else
    rb_status=$?
  fi
  TCPDUMP_RB=""
  printf 'tcp capture finish: cell=%s ra exit=%s rb exit=%s\n' \
    "${label}" "${ra_status}" "${rb_status}"
  if ((ra_status != 0 && ra_status != 124)); then
    echo "error: TCP ra0 capture failed unexpectedly: ${ra_status}" >&2
    result="${ra_status}"
  fi
  if ((rb_status != 0 && rb_status != 124)); then
    echo "error: TCP rb0 capture failed unexpectedly: ${rb_status}" >&2
    if ((result == 0)); then
      result="${rb_status}"
    fi
  fi
  return "${result}"
}

check_tcp_capture_file() {
  local label="$1"
  local interface="$2"
  local flow="$3"
  local pcap_path
  local output_path
  local log_path
  local checker_status=0
  local checker_args=()

  if [[ ! "${label}" =~ ^tcp-mtu[0-9]+-p[0-9]+-(forward|reverse|bidir)$ ]]; then
    echo "error: invalid per-cell TCP pcap identity: ${label}" >&2
    return 1
  fi
  case "${interface}" in
    ra | rb) ;;
    *)
      echo "error: invalid TCP pcap interface label: ${interface}" >&2
      return 1
      ;;
  esac
  case "${flow}" in
    forward)
      checker_args+=(
        --src "${A_UNDER}" --dst "${B_UNDER}"
        --sport 31001 --dport 31002
      )
      ;;
    reverse)
      checker_args+=(
        --src "${B_UNDER}" --dst "${A_UNDER}"
        --sport 31002 --dport 31001
      )
      ;;
    *)
      echo "error: invalid TCP pcap flow label: ${flow}" >&2
      return 1
      ;;
  esac
  pcap_path="${TMPDIR}/${label}-${interface}.pcap"
  output_path="${TMPDIR}/${label}-${interface}-${flow}-pcap-check.out"
  log_path="${TMPDIR}/${label}-${interface}-${flow}-pcap-check.log"
  if ((XOR_ENABLED)); then
    checker_args+=(
      --forbid-plain-standard
      --forbid-plain-mixed
      --xor-udp2raw-password-file "${SECRET_DIR}/xor-password"
      --require-xor-mixed transport
    )
  else
    checker_args+=(
      --forbid-standard
      --require-mixed transport
    )
  fi
  env -u XOR_PASSWORD timeout -s TERM -k 2 30 \
    sh -c 'sleep 0.2; exec "$@"' sh \
    python3 "${ROOT}/scripts/check-wg-pcap.py" \
    "${checker_args[@]}" \
    "${pcap_path}" \
    >"${output_path}" \
    2>"${log_path}" &
  PCAP_CHECKER_PID=$!
  assert_process_environment_secret_free \
    "${PCAP_CHECKER_PID}" "pcap-checker-${label}-${interface}-${flow}" || return 1
  if wait "${PCAP_CHECKER_PID}"; then
    checker_status=0
  else
    checker_status=$?
  fi
  PCAP_CHECKER_PID=""
  if ((checker_status != 0)); then
    echo "error: TCP pcap checker failed for ${label}/${interface}/${flow} (${checker_status})" >&2
    cat "${log_path}" >&2
    cat "${output_path}" >&2
    return "${checker_status}"
  fi
  cat "${output_path}"
}

check_tcp_capture() {
  local label="$1"
  local direction="${label##*-}"
  local interface
  local flow
  local flows=()
  local status
  local result=0

  case "${direction}" in
    forward | reverse) flows=("${direction}") ;;
    bidir) flows=(forward reverse) ;;
    *)
      echo "error: could not derive TCP pcap direction from ${label}" >&2
      return 1
      ;;
  esac
  for interface in ra rb; do
    for flow in "${flows[@]}"; do
      if check_tcp_capture_file "${label}" "${interface}" "${flow}"; then
        :
      else
        status=$?
        if ((result == 0)); then
          result="${status}"
        fi
      fi
    done
  done
  return "${result}"
}

tcp_server_listening() {
  run_in_owned_netns "${NSB}" \
    python3 - "${TCP_PORT}" <<'PY'
import pathlib
import sys

port = f"{int(sys.argv[1]):04X}"
for path in (pathlib.Path("/proc/net/tcp"), pathlib.Path("/proc/net/tcp6")):
    try:
        lines = path.read_text(encoding="ascii").splitlines()[1:]
    except FileNotFoundError:
        continue
    for line in lines:
        fields = line.split()
        if len(fields) >= 4 and fields[1].rsplit(":", 1)[-1].upper() == port:
            if fields[3] == "0A":
                raise SystemExit(0)
raise SystemExit(1)
PY
}

exercise_tcp_run() {
  local mtu="$1"
  local streams="$2"
  local direction="$3"
  local label="tcp-mtu${mtu}-p${streams}-${direction}"
  local client_path="${TMPDIR}/${label}-client.json"
  local client_log="${TMPDIR}/${label}-client.log"
  local server_path="${TMPDIR}/${label}-server.json"
  local server_log="${TMPDIR}/${label}-server.log"
  local server_status=0
  local client_status=0
  local capture_status=0
  local pcap_status=0
  local capture_timeout="$((TCP_DURATION + 5))"
  local ready=0
  local attempt
  local client_direction_args=()

  case "${direction}" in
    forward) ;;
    reverse) client_direction_args=(-R) ;;
    bidir) client_direction_args=(--bidir) ;;
    *)
      echo "error: unsupported TCP direction: ${direction}" >&2
      return 1
      ;;
  esac
  run_bounded_in_owned_netns \
    "${NSB}" TERM "$((TCP_DURATION + 15))" \
    iperf3 -s -1 -p "${TCP_PORT}" -J \
    >"${server_path}" 2>"${server_log}" &
  TCP_SERVER_PID=$!
  assert_process_environment_secret_free \
    "${TCP_SERVER_PID}" "iperf3-server-${label}" || return 1

  for ((attempt = 0; attempt < 50; attempt++)); do
    if tcp_server_listening; then
      ready=1
      break
    fi
    if ! kill -0 "${TCP_SERVER_PID}" >/dev/null 2>&1; then
      break
    fi
    sleep 0.1
  done
  if ((ready == 0)); then
    echo "error: iperf3 server did not listen for ${label}" >&2
    echo "bounded iperf3 server left for timeout: pid=${TCP_SERVER_PID}" >&2
    cat "${server_log}" >&2
    return 1
  fi

  start_tcp_capture "${label}" "${capture_timeout}" || return 1
  run_bounded_in_owned_netns \
    "${NSA}" TERM "$((TCP_DURATION + 15))" \
    iperf3 -c 10.77.0.2 -p "${TCP_PORT}" \
    -t "${TCP_DURATION}" -P "${streams}" "${client_direction_args[@]}" -J \
    >"${client_path}" 2>"${client_log}" &
  TCP_CLIENT_PID=$!
  assert_process_environment_secret_free \
    "${TCP_CLIENT_PID}" "iperf3-client-${label}" || return 1
  if wait "${TCP_CLIENT_PID}"; then
    client_status=0
  else
    client_status=$?
  fi
  TCP_CLIENT_PID=""

  if ((client_status != 0)); then
    echo "error: iperf3 client failed for ${label} (${client_status})" >&2
    echo "bounded iperf3 server left for timeout: pid=${TCP_SERVER_PID}" >&2
    cat "${client_log}" >&2
    [[ ! -s "${client_path}" ]] || cat "${client_path}" >&2
  else
    if wait "${TCP_SERVER_PID}"; then
      server_status=0
    else
      server_status=$?
    fi
    TCP_SERVER_PID=""
    if ((server_status != 0)); then
      echo "error: iperf3 server failed for ${label} (${server_status})" >&2
      cat "${server_log}" >&2
      [[ ! -s "${server_path}" ]] || cat "${server_path}" >&2
    fi
  fi

  if finish_tcp_capture "${label}"; then
    capture_status=0
  else
    capture_status=$?
  fi
  if check_tcp_capture "${label}"; then
    pcap_status=0
  else
    pcap_status=$?
  fi
  if ((client_status != 0)); then
    return "${client_status}"
  fi
  if ((server_status != 0)); then
    return "${server_status}"
  fi
  if ((capture_status != 0)); then
    return "${capture_status}"
  fi
  if ((pcap_status != 0)); then
    return "${pcap_status}"
  fi
  env -u XOR_PASSWORD python3 "${IPERF_CHECKER_HELPER}" \
    "${client_path}" \
    --direction "${direction}" \
    --streams "${streams}" \
    --minimum-bytes "${TCP_MIN_BYTES}" \
    --maximum-retransmits "${TCP_MAX_RETRANSMITS}" \
    --minimum-fairness "${TCP_MIN_FAIRNESS}"
}

exercise_tcp_matrix() {
  local mtu
  local streams
  local direction
  local side
  local stat
  local before_path
  local after_path
  local run_status
  local evidence_status

  classify_tcp_gso_capabilities
  capture_tcp_netns_evidence before
  for mtu in "${TCP_MTU_VALUES[@]}"; do
    validate_all_netns_identities
    run_in_owned_netns "${NSA}" ip link set wg0 mtu "${mtu}"
    run_in_owned_netns "${NSB}" ip link set wg0 mtu "${mtu}"
    wait_ping "${NSA}" 10.77.0.2
    wait_ping "${NSB}" 10.77.0.1

    run_agent_in_netns "${NSA}" "${PINA}" status --config "${SECRET_DIR}/agent-a.yaml" \
      >"${TMPDIR}/status-a-tcp-${mtu}-before.json"
    run_agent_in_netns "${NSB}" "${PINB}" status --config "${SECRET_DIR}/agent-b.yaml" \
      >"${TMPDIR}/status-b-tcp-${mtu}-before.json"
    run_in_owned_netns "${NSA}" wg show wg0 transfer \
      >"${TMPDIR}/wg-transfer-a-tcp-${mtu}-before.txt"
    run_in_owned_netns "${NSB}" wg show wg0 transfer \
      >"${TMPDIR}/wg-transfer-b-tcp-${mtu}-before.txt"

    run_status=0
    for streams in "${TCP_STREAM_VALUES[@]}"; do
      for direction in "${TCP_DIRECTION_VALUES[@]}"; do
        if exercise_tcp_run "${mtu}" "${streams}" "${direction}"; then
          :
        else
          run_status=$?
          break 2
        fi
      done
    done

    run_agent_in_netns "${NSA}" "${PINA}" status --config "${SECRET_DIR}/agent-a.yaml" \
      >"${TMPDIR}/status-a-tcp-${mtu}-after.json"
    run_agent_in_netns "${NSB}" "${PINB}" status --config "${SECRET_DIR}/agent-b.yaml" \
      >"${TMPDIR}/status-b-tcp-${mtu}-after.json"
    run_in_owned_netns "${NSA}" wg show wg0 transfer \
      >"${TMPDIR}/wg-transfer-a-tcp-${mtu}-after.txt"
    run_in_owned_netns "${NSB}" wg show wg0 transfer \
      >"${TMPDIR}/wg-transfer-b-tcp-${mtu}-after.txt"

    for side in a b; do
      before_path="${TMPDIR}/status-${side}-tcp-${mtu}-before.json"
      after_path="${TMPDIR}/status-${side}-tcp-${mtu}-after.json"
      for stat in \
        egress_bad_type ingress_bad_type \
        egress_bad_length ingress_bad_length \
        egress_fragment ingress_fragment \
        egress_ipv6_ext ingress_ipv6_ext \
        egress_rule_miss ingress_rule_miss \
        checksum_error skb_load_error skb_store_error \
        xor_key_missing xor_len_overflow xor_bad_type_after_decrypt \
        xor_load_error xor_store_error xor_csum_error \
        xor_egress_dispatch_error xor_ingress_dispatch_error \
        ingress_bad_checksum egress_bad_checksum; do
        if ((run_status == 0)); then
          assert_stat_unchanged "${before_path}" "${after_path}" "${stat}"
        else
          print_stat_delta "${before_path}" "${after_path}" "${stat}"
        fi
      done
      if ((run_status != 0)); then
        continue
      fi
      assert_wg_transfer_increased \
        "${TMPDIR}/wg-transfer-${side}-tcp-${mtu}-before.txt" \
        "${TMPDIR}/wg-transfer-${side}-tcp-${mtu}-after.txt" \
        "${side}" "${mtu}"
      assert_stat_increased "${before_path}" "${after_path}" egress_rewrite_ok
      assert_stat_increased "${before_path}" "${after_path}" ingress_rewrite_ok
      if ((XOR_ENABLED)); then
        assert_stat_increased "${before_path}" "${after_path}" xor_egress_ok
        assert_stat_increased "${before_path}" "${after_path}" xor_ingress_ok
      fi
      record_tcp_outer_gso_observation \
        "${before_path}" "${after_path}" "${mtu}" "${side}"
    done
    if ((run_status != 0)); then
      evidence_status=0
      if capture_tcp_netns_evidence failure; then
        :
      else
        evidence_status=$?
        echo "error: TCP failure-state evidence capture also failed (${evidence_status})" >&2
      fi
      echo "error: TCP matrix failed for mtu=${mtu}; retained per-cell pcaps, client/server JSON, logs, and before/after status evidence under ${TMPDIR}" >&2
      return "${run_status}"
    fi
  done
  capture_tcp_netns_evidence after
  finalize_tcp_gso_evidence
  printf 'tcp summary=correctness status=passed\n'
}

exercise_udp_zero_checksum() {
  local ready_path="${TMPDIR}/udp-zero-checksum.ready"
  local receiver_log="${TMPDIR}/udp-zero-checksum-receiver.log"
  local attempt
  local gateway_mac
  local receiver_status=0

  run_agent_in_netns "${NSA}" "${PINA}" status --config "${SECRET_DIR}/agent-a.yaml" \
    >"${TMPDIR}/status-a-zero-before.json"
  run_agent_in_netns "${NSB}" "${PINB}" status --config "${SECRET_DIR}/agent-b.yaml" \
    >"${TMPDIR}/status-b-zero-before.json"

  # Free the configured WireGuard ports while retaining the already-loaded rules.
  run_in_owned_netns "${NSA}" wg set wg0 listen-port 0
  run_in_owned_netns "${NSB}" wg set wg0 listen-port 0

  gateway_mac="$(
    run_in_owned_netns "${NSR}" cat /sys/class/net/ra0/address
  )"
  if [[ -z "${gateway_mac}" ]]; then
    echo "error: could not resolve IPv6 gateway MAC for UDP zero-checksum check" >&2
    return 1
  fi

  run_bounded_in_owned_netns "${NSB}" TERM 10 \
    python3 - \
    "${A_UNDER}" "${B_UNDER}" "${ready_path}" >"${TMPDIR}/udp-zero-checksum-receiver.out" \
    2>"${receiver_log}" <<'PY' &
import socket
import struct
import sys
import time

source, destination, ready_path = sys.argv[1:]
source_port = 31001
destination_port = 31002
payload = bytearray(1968)
payload[:4] = b"\x04\x00\x00\x00"
payload[-2:] = struct.pack("!H", 0x9DD3)

sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
sock.bind((destination, destination_port))
with open(ready_path, "x", encoding="ascii"):
    pass
deadline = time.monotonic() + 6
while True:
    sock.settimeout(max(0.01, deadline - time.monotonic()))
    data, peer = sock.recvfrom(4096)
    if peer[0] == source and peer[1] == source_port and data == payload:
        break
    if time.monotonic() >= deadline:
        raise SystemExit(
            f"did not receive expected vector; last peer={peer[:2]} length={len(data)}"
        )
PY
  UDP_ZERO_CHECKSUM_RECEIVER_PID=$!
  assert_process_environment_secret_free \
    "${UDP_ZERO_CHECKSUM_RECEIVER_PID}" "udp-zero-checksum-receiver"

  for ((attempt = 0; attempt < 50; attempt++)); do
    if [[ -e "${ready_path}" ]]; then
      break
    fi
    if ! kill -0 "${UDP_ZERO_CHECKSUM_RECEIVER_PID}" >/dev/null 2>&1; then
      break
    fi
    sleep 0.1
  done
  if [[ ! -e "${ready_path}" ]]; then
    echo "error: UDP zero-checksum receiver did not become ready" >&2
    echo "bounded UDP receiver left for timeout: pid=${UDP_ZERO_CHECKSUM_RECEIVER_PID}" >&2
    cat "${receiver_log}" >&2
    return 1
  fi

  run_bounded_in_owned_netns "${NSA}" TERM 5 \
    python3 - \
    "${A_UNDER}" "${B_UNDER}" "${gateway_mac}" <<'PY'
import ipaddress
import socket
import struct
import sys

source, destination, gateway_mac = sys.argv[1:]
source_port = 31001
destination_port = 31002
payload = bytearray(1968)
payload[:4] = b"\x04\x00\x00\x00"
payload[-2:] = struct.pack("!H", 0x9DD3)
udp_length = 8 + len(payload)
udp = struct.pack("!HHHH", source_port, destination_port, udp_length, 0)
pseudoheader = (
    ipaddress.IPv6Address(source).packed
    + ipaddress.IPv6Address(destination).packed
    + struct.pack("!I3xB", udp_length, socket.IPPROTO_UDP)
)
checksum_input = pseudoheader + udp + payload
words = struct.unpack(f"!{len(checksum_input) // 2}H", checksum_input)
folded_sum = sum(words)
while folded_sum >> 16:
    folded_sum = (folded_sum & 0xFFFF) + (folded_sum >> 16)
assert folded_sum == 0xFFFF, f"folded checksum sum={folded_sum:#06x}"
# RFC 8200 requires the computed zero checksum to be encoded as 0xffff.
computed_checksum = (~folded_sum) & 0xFFFF
wire_checksum = computed_checksum or 0xFFFF
assert wire_checksum == 0xFFFF

sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x86DD))
sock.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_MARK", 36), 0x10000001)
sock.bind(("under0", 0))
source_mac = sock.getsockname()[4]
destination_mac = bytes.fromhex(gateway_mac.replace(":", ""))
ethernet = destination_mac + source_mac + struct.pack("!H", 0x86DD)
ipv6 = struct.pack(
    "!IHBB16s16s",
    6 << 28,
    udp_length,
    socket.IPPROTO_UDP,
    64,
    ipaddress.IPv6Address(source).packed,
    ipaddress.IPv6Address(destination).packed,
)
udp = struct.pack(
    "!HHHH", source_port, destination_port, udp_length, wire_checksum
)
frame = ethernet + ipv6 + udp + payload
sent = sock.send(frame)
assert sent == len(frame), f"short Ethernet send: {sent}/{len(frame)}"
PY

  if wait "${UDP_ZERO_CHECKSUM_RECEIVER_PID}"; then
    receiver_status=0
  else
    receiver_status=$?
  fi
  UDP_ZERO_CHECKSUM_RECEIVER_PID=""
  if ((receiver_status != 0)); then
    echo "error: UDP zero-checksum receiver failed (${receiver_status})" >&2
    cat "${receiver_log}" >&2
    return "${receiver_status}"
  fi

  run_in_owned_netns "${NSA}" wg set wg0 listen-port 31001
  run_in_owned_netns "${NSB}" wg set wg0 listen-port 31002

  run_agent_in_netns "${NSA}" "${PINA}" status --config "${SECRET_DIR}/agent-a.yaml" \
    >"${TMPDIR}/status-a-zero-after.json"
  run_agent_in_netns "${NSB}" "${PINB}" status --config "${SECRET_DIR}/agent-b.yaml" \
    >"${TMPDIR}/status-b-zero-after.json"
  assert_stat_increased "${TMPDIR}/status-a-zero-before.json" \
    "${TMPDIR}/status-a-zero-after.json" egress_rewrite_ok
  assert_stat_increased "${TMPDIR}/status-b-zero-before.json" \
    "${TMPDIR}/status-b-zero-after.json" ingress_rewrite_ok
  if ((XOR_ENABLED)); then
    assert_stat_increased "${TMPDIR}/status-a-zero-before.json" \
      "${TMPDIR}/status-a-zero-after.json" xor_egress_ok
    assert_stat_increased "${TMPDIR}/status-b-zero-before.json" \
      "${TMPDIR}/status-b-zero-after.json" xor_ingress_ok
  fi
  for stat in checksum_error xor_csum_error ingress_bad_checksum; do
    assert_stat_unchanged "${TMPDIR}/status-a-zero-before.json" \
      "${TMPDIR}/status-a-zero-after.json" "${stat}"
    assert_stat_unchanged "${TMPDIR}/status-b-zero-before.json" \
      "${TMPDIR}/status-b-zero-after.json" "${stat}"
  done
}

assert_generation() {
  local path="$1"
  local expected="$2"
  local actual

  actual="$(active_generation "${path}")"
  if [[ "${actual}" -ne "${expected}" ]]; then
    echo "error: ${path} active generation=${actual}, want ${expected}" >&2
    return 1
  fi
}

tail_slot_key() {
  local index="$1"

  printf '%02x 00 00 00' "${index}"
}

assert_tail_bank() {
  local pin="$1"
  local status_path="$2"
  local generation
  local bank_start
  local map
  local segment
  local index
  local key

  generation="$(active_generation "${status_path}")"
  bank_start=$(((generation & 1) * 8))
  for map in xor_egress_programs xor_ingress_programs; do
    for segment in 0 1 2 3 4 5 6 7; do
      index=$((bank_start + segment))
      key="$(tail_slot_key "${index}")"
      # shellcheck disable=SC2086
      bpftool map lookup pinned "${pin}/${map}" key hex ${key} >/dev/null
    done
  done
}

delete_tail_slot() {
  local pin="$1"
  local map="$2"
  local generation="$3"
  local segment="$4"
  local index=$((((generation & 1) * 8) + segment))
  local key

  key="$(tail_slot_key "${index}")"
  # shellcheck disable=SC2086
  bpftool map delete pinned "${pin}/${map}" key hex ${key}
}

PHASE="network-test-setup"
start_netns_anchor "${NSA}" a "${NETNS_SOCKET_A}" "${NETNS_READY_A}"
start_netns_anchor "${NSR}" r "${NETNS_SOCKET_R}" "${NETNS_READY_R}"
start_netns_anchor "${NSB}" b "${NETNS_SOCKET_B}" "${NETNS_READY_B}"
for identity_part in \
  "${NETNS_A_DEV}" "${NETNS_A_INO}" \
  "${NETNS_R_DEV}" "${NETNS_R_INO}" \
  "${NETNS_B_DEV}" "${NETNS_B_INO}"; do
  if [[ ! "${identity_part}" =~ ^[1-9][0-9]*$ ]]; then
    echo "error: invalid network namespace identity component: ${identity_part}" >&2
    exit 1
  fi
done
if [[ "${NETNS_A_DEV}:${NETNS_A_INO}" == "${NETNS_R_DEV}:${NETNS_R_INO}" ||
  "${NETNS_A_DEV}:${NETNS_A_INO}" == "${NETNS_B_DEV}:${NETNS_B_INO}" ||
  "${NETNS_R_DEV}:${NETNS_R_INO}" == "${NETNS_B_DEV}:${NETNS_B_INO}" ]]; then
  echo "error: network namespace identities are not unique" >&2
  exit 1
fi
validate_all_netns_identities

create_veth_pair "${VETH_A}" "${NSA}" "${VETH_RA}" "${NSR}"
create_veth_pair "${VETH_B}" "${NSB}" "${VETH_RB}" "${NSR}"

run_in_owned_netns "${NSA}" ip link set lo up
run_in_owned_netns "${NSR}" ip link set lo up
run_in_owned_netns "${NSB}" ip link set lo up
run_in_owned_netns "${NSA}" ip link set "${VETH_A}" name under0
run_in_owned_netns "${NSB}" ip link set "${VETH_B}" name under0
run_in_owned_netns "${NSR}" ip link set "${VETH_RA}" name ra0
run_in_owned_netns "${NSR}" ip link set "${VETH_RB}" name rb0
run_in_owned_netns "${NSA}" ip link set under0 mtu "${UNDERLAY_MTU}"
run_in_owned_netns "${NSB}" ip link set under0 mtu "${UNDERLAY_MTU}"
run_in_owned_netns "${NSR}" ip link set ra0 mtu "${UNDERLAY_MTU}"
run_in_owned_netns "${NSR}" ip link set rb0 mtu "${UNDERLAY_MTU}"

if [[ "${OUTER_FAMILY}" == "ipv4" ]]; then
  A_UNDER="192.0.2.1"
  A_GW="192.0.2.254"
  B_UNDER="198.51.100.1"
  B_GW="198.51.100.254"
  A_ENDPOINT="${A_UNDER}:31001"
  B_ENDPOINT="${B_UNDER}:31002"
  run_in_owned_netns "${NSA}" ip addr add "${A_UNDER}/24" dev under0
  run_in_owned_netns "${NSR}" ip addr add "${A_GW}/24" dev ra0
  run_in_owned_netns "${NSB}" ip addr add "${B_UNDER}/24" dev under0
  run_in_owned_netns "${NSR}" ip addr add "${B_GW}/24" dev rb0
else
  A_UNDER="2001:db8:77:a::1"
  A_GW="2001:db8:77:a::ff"
  B_UNDER="2001:db8:77:b::1"
  B_GW="2001:db8:77:b::ff"
  A_ENDPOINT="[${A_UNDER}]:31001"
  B_ENDPOINT="[${B_UNDER}]:31002"
  run_in_owned_netns "${NSA}" ip addr add "${A_UNDER}/64" dev under0
  run_in_owned_netns "${NSR}" ip addr add "${A_GW}/64" dev ra0
  run_in_owned_netns "${NSB}" ip addr add "${B_UNDER}/64" dev under0
  run_in_owned_netns "${NSR}" ip addr add "${B_GW}/64" dev rb0
fi
run_in_owned_netns "${NSA}" ip link set under0 up
run_in_owned_netns "${NSR}" ip link set ra0 up
run_in_owned_netns "${NSB}" ip link set under0 up
run_in_owned_netns "${NSR}" ip link set rb0 up

if [[ "${OUTER_FAMILY}" == "ipv4" ]]; then
  run_in_owned_netns "${NSR}" sysctl -qw net.ipv4.ip_forward=1
  run_in_owned_netns "${NSA}" ip route add default via "${A_GW}" dev under0
  run_in_owned_netns "${NSB}" ip route add default via "${B_GW}" dev under0
else
  run_in_owned_netns "${NSR}" sysctl -qw net.ipv6.conf.all.forwarding=1
  run_in_owned_netns "${NSA}" ip -6 route add default via "${A_GW}" dev under0
  run_in_owned_netns "${NSB}" ip -6 route add default via "${B_GW}" dev under0
fi

wg genkey >"${SECRET_DIR}/a.key"
wg pubkey <"${SECRET_DIR}/a.key" >"${SECRET_DIR}/a.pub"
wg genkey >"${SECRET_DIR}/b.key"
wg pubkey <"${SECRET_DIR}/b.key" >"${SECRET_DIR}/b.pub"
chmod 0600 "${SECRET_DIR}/a.key" "${SECRET_DIR}/b.key"

A_PUB="$(cat "${SECRET_DIR}/a.pub")"
B_PUB="$(cat "${SECRET_DIR}/b.pub")"

run_in_owned_netns "${NSA}" ip link add wg0 type wireguard
run_in_owned_netns "${NSB}" ip link add wg0 type wireguard
run_in_owned_netns "${NSA}" ip link set wg0 mtu "${WG_MTU}"
run_in_owned_netns "${NSB}" ip link set wg0 mtu "${WG_MTU}"
run_wg_set_with_private_key_in_owned_netns \
  "${NSA}" "${SECRET_DIR}/a.key" wg0 listen-port 31001 \
  fwmark 0x10000001 peer "${B_PUB}" allowed-ips 10.77.0.2/32 \
  endpoint "${B_ENDPOINT}"
run_wg_set_with_private_key_in_owned_netns \
  "${NSB}" "${SECRET_DIR}/b.key" wg0 listen-port 31002 \
  fwmark 0x10000002 peer "${A_PUB}" allowed-ips 10.77.0.1/32 \
  endpoint "${A_ENDPOINT}"
run_in_owned_netns "${NSA}" ip addr add 10.77.0.1/24 dev wg0
run_in_owned_netns "${NSB}" ip addr add 10.77.0.2/24 dev wg0
run_in_owned_netns "${NSA}" ip link set wg0 up
run_in_owned_netns "${NSB}" ip link set wg0 up
run_in_owned_netns "${NSA}" ip route add 10.77.0.2/32 dev wg0
run_in_owned_netns "${NSB}" ip route add 10.77.0.1/32 dev wg0

make_wg_config_stub "${SECRET_DIR}/wg-a.conf" 31001 0x10000001
make_wg_config_stub "${SECRET_DIR}/wg-b.conf" 31002 0x10000002
make_agent_config "${SECRET_DIR}/agent-a.yaml" under0 "${SECRET_DIR}/wg-a.conf"
make_agent_config "${SECRET_DIR}/agent-b.yaml" under0 "${SECRET_DIR}/wg-b.conf"

PHASE="seal-run-contract"
(set -o noclobber; manifest_payload >"${MANIFEST}")
chmod 0600 "${MANIFEST}"
validate_marker "${RUN_BASE}" root
validate_marker "${PIN_LOCK_ROOT}" pin-locks
validate_marker "${PIN_OWNER_ROOT}" pin-owners
validate_manifest
validate_private_bpffs_mount

PHASE="test-execution"
run_agent_in_netns "${NSA}" "${PINA}" reload --config "${SECRET_DIR}/agent-a.yaml"
run_agent_in_netns "${NSB}" "${PINB}" reload --config "${SECRET_DIR}/agent-b.yaml"
run_agent_in_netns "${NSA}" "${PINA}" status --config "${SECRET_DIR}/agent-a.yaml" >"${TMPDIR}/status-a-before.json"
run_agent_in_netns "${NSB}" "${PINB}" status --config "${SECRET_DIR}/agent-b.yaml" >"${TMPDIR}/status-b-before.json"
assert_generation "${TMPDIR}/status-a-before.json" 1
assert_generation "${TMPDIR}/status-b-before.json" 1
if ((XOR_ENABLED)); then
  assert_tail_bank "${PINA}" "${TMPDIR}/status-a-before.json"
  assert_tail_bank "${PINB}" "${TMPDIR}/status-b-before.json"
fi

run_bounded_in_owned_netns "${NSR}" INT 30 \
  tcpdump -i ra0 -w "${TMPDIR}/ra.pcap" udp \
  >/dev/null 2>"${TMPDIR}/tcpdump-ra.log" &
TCPDUMP_RA=$!
assert_process_environment_secret_free "${TCPDUMP_RA}" "tcpdump-ra"
run_bounded_in_owned_netns "${NSR}" INT 30 \
  tcpdump -i rb0 -w "${TMPDIR}/rb.pcap" udp \
  >/dev/null 2>"${TMPDIR}/tcpdump-rb.log" &
TCPDUMP_RB=$!
assert_process_environment_secret_free "${TCPDUMP_RB}" "tcpdump-rb"
sleep 1

exercise_tunnel

if [[ "${XOR_ENABLED}" -eq 1 && "${XOR_GENERATION_CHECKS}" == "enforce" ]]; then
  for expected_generation in 2 3; do
    run_agent_in_netns "${NSA}" "${PINA}" reload --config "${SECRET_DIR}/agent-a.yaml"
    run_agent_in_netns "${NSB}" "${PINB}" reload --config "${SECRET_DIR}/agent-b.yaml"
    run_agent_in_netns "${NSA}" "${PINA}" status --config "${SECRET_DIR}/agent-a.yaml" >"${TMPDIR}/status-a-gen${expected_generation}.json"
    run_agent_in_netns "${NSB}" "${PINB}" status --config "${SECRET_DIR}/agent-b.yaml" >"${TMPDIR}/status-b-gen${expected_generation}.json"
    assert_generation "${TMPDIR}/status-a-gen${expected_generation}.json" "${expected_generation}"
    assert_generation "${TMPDIR}/status-b-gen${expected_generation}.json" "${expected_generation}"
    assert_tail_bank "${PINA}" "${TMPDIR}/status-a-gen${expected_generation}.json"
    assert_tail_bank "${PINB}" "${TMPDIR}/status-b-gen${expected_generation}.json"
    exercise_tunnel
  done
fi

if wait "${TCPDUMP_RA}"; then
  tcpdump_ra_status=0
else
  tcpdump_ra_status=$?
fi
TCPDUMP_RA=""
printf 'capture finish: ra exit=%s\n' "${tcpdump_ra_status}"
if ((tcpdump_ra_status != 0 && tcpdump_ra_status != 124)); then
  echo "error: ra tcpdump failed unexpectedly: ${tcpdump_ra_status}" >&2
  exit "${tcpdump_ra_status}"
fi

if wait "${TCPDUMP_RB}"; then
  tcpdump_rb_status=0
else
  tcpdump_rb_status=$?
fi
TCPDUMP_RB=""
printf 'capture finish: rb exit=%s\n' "${tcpdump_rb_status}"
if ((tcpdump_rb_status != 0 && tcpdump_rb_status != 124)); then
  echo "error: rb tcpdump failed unexpectedly: ${tcpdump_rb_status}" >&2
  exit "${tcpdump_rb_status}"
fi

if ((XOR_ENABLED)); then
  PCAP_CHECKER_ARGS=(
    --forbid-plain-standard
    --forbid-plain-mixed
    --xor-udp2raw-password-file "${SECRET_DIR}/xor-password"
    --require-xor-mixed "initiation,response,transport"
  )
else
  PCAP_CHECKER_ARGS=(
    --forbid-standard
    --require-mixed "initiation,response,transport"
  )
fi
env -u XOR_PASSWORD timeout -s TERM -k 2 30 \
  sh -c 'sleep 0.2; exec "$@"' sh \
  python3 "${ROOT}/scripts/check-wg-pcap.py" \
  "${PCAP_CHECKER_ARGS[@]}" \
  "${TMPDIR}/ra.pcap" "${TMPDIR}/rb.pcap" &
PCAP_CHECKER_PID=$!
assert_process_environment_secret_free "${PCAP_CHECKER_PID}" "pcap-checker"
if wait "${PCAP_CHECKER_PID}"; then
  pcap_checker_status=0
else
  pcap_checker_status=$?
fi
PCAP_CHECKER_PID=""
if ((pcap_checker_status != 0)); then
  echo "error: pcap checker failed (${pcap_checker_status})" >&2
  exit "${pcap_checker_status}"
fi

if [[ "${UDP_ZERO_CHECKSUM_CHECKS}" == "enforce" ]]; then
  exercise_udp_zero_checksum
fi

run_agent_in_netns "${NSA}" "${PINA}" status --config "${SECRET_DIR}/agent-a.yaml" >"${TMPDIR}/status-a-after.json"
run_agent_in_netns "${NSB}" "${PINB}" status --config "${SECRET_DIR}/agent-b.yaml" >"${TMPDIR}/status-b-after.json"

env -u XOR_PASSWORD python3 - \
  "$TMPDIR/status-a-after.json" "$TMPDIR/status-b-after.json" \
  "${XOR_ENABLED}" <<'PY'
import json
import sys

required_zero = (
    "checksum_error",
    "skb_load_error",
    "skb_store_error",
    "icmp_checksum_error",
    "xor_key_missing",
    "xor_len_overflow",
    "xor_bad_type_after_decrypt",
    "xor_load_error",
    "xor_store_error",
    "xor_csum_error",
    "xor_egress_dispatch_error",
    "xor_ingress_dispatch_error",
    "ingress_bad_checksum",
    "egress_bad_checksum",
)
xor_enabled = sys.argv[3] == "1"
required_positive = ["egress_rewrite_ok", "ingress_rewrite_ok"]
if xor_enabled:
    required_positive.extend(["xor_egress_ok", "xor_ingress_ok"])
for path in sys.argv[1:3]:
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    stats = (
        doc.get("dataplane", {}).get("stats")
        or doc.get("kernel", {}).get("stats")
        or doc.get("stats")
        or {}
    )
    if not stats:
        raise SystemExit(f"{path}: missing stats in status JSON: {json.dumps(doc, indent=2)}")
    for key in required_zero:
        if int(stats.get(key, 0)) != 0:
            raise SystemExit(f"{path}: {key}={stats.get(key)}")
    for key in required_positive:
        if int(stats.get(key, 0)) <= 0:
            raise SystemExit(f"{path}: {key}={stats.get(key)}")
PY

if [[ "${XOR_DISPATCH_FAILURE_CHECKS}" == "enforce" ]]; then
  status_a="${TMPDIR}/status-a-after.json"
  status_b="${TMPDIR}/status-b-after.json"
  generation_a="$(active_generation "${status_a}")"
  generation_b="$(active_generation "${status_b}")"
  egress_before="$(stat_value "${status_a}" xor_egress_dispatch_error)"
  ingress_before="$(stat_value "${status_b}" xor_ingress_dispatch_error)"

  delete_tail_slot "${PINA}" xor_egress_programs "${generation_a}" 7
  if large_ping "${NSA}" 10.77.0.2; then
    echo "error: large XOR packet passed with missing egress segment 7" >&2
    exit 1
  fi
  run_agent_in_netns "${NSA}" "${PINA}" status --config "${SECRET_DIR}/agent-a.yaml" >"${TMPDIR}/status-a-egress-miss.json"
  egress_after="$(stat_value "${TMPDIR}/status-a-egress-miss.json" xor_egress_dispatch_error)"
  if ((egress_after <= egress_before)); then
    echo "error: egress dispatch counter did not increase (${egress_before} -> ${egress_after})" >&2
    exit 1
  fi
  run_agent_in_netns "${NSA}" "${PINA}" reload --config "${SECRET_DIR}/agent-a.yaml"
  run_agent_in_netns "${NSA}" "${PINA}" status --config "${SECRET_DIR}/agent-a.yaml" >"${TMPDIR}/status-a-repaired.json"
  assert_tail_bank "${PINA}" "${TMPDIR}/status-a-repaired.json"
  large_ping "${NSA}" 10.77.0.2

  delete_tail_slot "${PINB}" xor_ingress_programs "${generation_b}" 7
  if large_ping "${NSA}" 10.77.0.2; then
    echo "error: large XOR packet passed with missing ingress segment 7" >&2
    exit 1
  fi
  run_agent_in_netns "${NSB}" "${PINB}" status --config "${SECRET_DIR}/agent-b.yaml" >"${TMPDIR}/status-b-ingress-miss.json"
  ingress_after="$(stat_value "${TMPDIR}/status-b-ingress-miss.json" xor_ingress_dispatch_error)"
  if ((ingress_after <= ingress_before)); then
    echo "error: ingress dispatch counter did not increase (${ingress_before} -> ${ingress_after})" >&2
    exit 1
  fi
  run_agent_in_netns "${NSB}" "${PINB}" reload --config "${SECRET_DIR}/agent-b.yaml"
  run_agent_in_netns "${NSB}" "${PINB}" status --config "${SECRET_DIR}/agent-b.yaml" >"${TMPDIR}/status-b-repaired.json"
  assert_tail_bank "${PINB}" "${TMPDIR}/status-b-repaired.json"
  large_ping "${NSA}" 10.77.0.2
fi

if [[ "${TCP_CHECKS}" == "enforce" ]]; then
  exercise_tcp_matrix
fi

explicit_teardown

if ((XOR_ENABLED)); then
  echo "netns WireGuard + eBPF ${OUTER_FAMILY} xor smoke passed (${XOR_SCOPE}, max_bytes=${XOR_MAX_BYTES})"
else
  echo "netns WireGuard + eBPF ${OUTER_FAMILY} smoke passed"
fi
