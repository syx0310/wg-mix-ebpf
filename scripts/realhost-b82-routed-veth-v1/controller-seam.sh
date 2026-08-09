#!/usr/bin/env bash
set -u
set -o pipefail
umask 077

readonly RUN_ID='7e42a19c'
readonly SOURCE="/run/wg-mix-ebpf-source-stages/${RUN_ID}/source"
readonly ROOT_RUNNER="${SOURCE}/scripts/realhost-b82-routed-veth-v1/root-routed-veth-n-r.sh"

MODE=''
COMMIT=''
EXPERIMENTAL_SHA256=''
BASELINE_SHA256=''
MODULE_SHA256=''
declare -a RUNNER_ARGV=()

usage() {
  printf '%s\n' \
    "usage: $0 {plan|run|restore} --commit 40-lowercase-hex" \
    '  --experimental-sha256 64-lowercase-hex' \
    '  --baseline-sha256 64-lowercase-hex' \
    '  --module-sha256 64-lowercase-hex' >&2
}

fail() {
  printf 'B82_ROUTED_CONTROLLER_SEAM_STOP run_id=%s mode=%s reason=%s rc=%s\n' \
    "${RUN_ID}" "${MODE:-unparsed}" "$1" "${2:-125}" >&2
  exit "${2:-125}"
}

valid_commit() {
  [[ "$1" =~ ^[0-9a-f]{40}$ && ! "$1" =~ ^0{40}$ && ! "$1" =~ ^f{40}$ ]]
}

valid_sha256() {
  [[ "$1" =~ ^[0-9a-f]{64}$ && ! "$1" =~ ^0{64}$ && ! "$1" =~ ^f{64}$ ]]
}

parse_arguments() {
  local seen_commit=0 seen_experimental=0 seen_baseline=0 seen_module=0
  (($# >= 1)) || { usage; return 64; }
  MODE="$1"
  shift
  case "${MODE}" in plan | run | restore) ;; *) usage; return 64 ;; esac
  while (($# > 0)); do
    (($# >= 2)) || { usage; return 64; }
    case "$1" in
      --commit)
        ((seen_commit == 0)) || return 65
        seen_commit=1; COMMIT="$2"
        ;;
      --experimental-sha256)
        ((seen_experimental == 0)) || return 65
        seen_experimental=1; EXPERIMENTAL_SHA256="$2"
        ;;
      --baseline-sha256)
        ((seen_baseline == 0)) || return 65
        seen_baseline=1; BASELINE_SHA256="$2"
        ;;
      --module-sha256)
        ((seen_module == 0)) || return 65
        seen_module=1; MODULE_SHA256="$2"
        ;;
      *) usage; return 64 ;;
    esac
    shift 2
  done
  ((seen_commit == 1 && seen_experimental == 1 && seen_baseline == 1 && seen_module == 1)) || return 65
  valid_commit "${COMMIT}" || return 65
  valid_sha256 "${EXPERIMENTAL_SHA256}" || return 65
  valid_sha256 "${BASELINE_SHA256}" || return 65
  valid_sha256 "${MODULE_SHA256}" || return 65
}

build_runner_argv() {
  RUNNER_ARGV=(
    /bin/bash -p "${ROOT_RUNNER}" "${MODE}"
    --source "${SOURCE}"
    --commit "${COMMIT}"
    --experimental-sha256 "${EXPERIMENTAL_SHA256}"
    --baseline-sha256 "${BASELINE_SHA256}"
    --module-sha256 "${MODULE_SHA256}"
  )
}

quote_argv() { printf '%q ' "$@"; }

main() {
  parse_arguments "$@" || fail 'arguments' $?
  build_runner_argv
  if [[ "${MODE}" == plan ]]; then
    printf 'B82_ROUTED_CONTROLLER_SEAM_PLAN run_id=%s target=192.168.10.82 credential_read=0 remote_connections=0 argv=' "${RUN_ID}"
    quote_argv "${RUNNER_ARGV[@]}"
    printf '\n'
    printf 'B82_ROUTED_CONTROLLER_SEAM_PLAN_COMPLETE transport_integration=pending no_commands_executed=1\n'
    return
  fi
  [[ "$EUID" == 0 ]] || fail 'root-required' 77
  [[ -f "${ROOT_RUNNER}" && ! -L "${ROOT_RUNNER}" ]] || fail 'runner-identity' 79
  exec /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C "${RUNNER_ARGV[@]}"
}

main "$@"
