#!/usr/bin/env bash
set -u
set -o pipefail
umask 077

readonly RUN_ID='c8e41d73'
readonly STAGE_ROOT="/run/wg-mix-ebpf-source-stages/${RUN_ID}"
readonly SOURCE="${STAGE_ROOT}/source"
readonly RUNNER_RELATIVE='scripts/realhost-b82-routed-veth-v1/root-routed-veth-n-r.sh'
readonly SELF_RELATIVE='scripts/realhost-b82-routed-veth-v1/controller-seam.sh'
readonly ROOT_RUNNER="${SOURCE}/scripts/realhost-b82-routed-veth-v1/root-routed-veth-n-r.sh"
readonly EXPECTED_SELF="${SOURCE}/scripts/realhost-b82-routed-veth-v1/controller-seam.sh"
readonly -a GIT_COMMAND=(
  /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C
  GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
  GIT_NO_REPLACE_OBJECTS=1 GIT_OPTIONAL_LOCKS=0
  /usr/bin/git --no-pager --no-replace-objects
  -c core.attributesFile=/dev/null -c core.fsmonitor=false
  -c core.hooksPath=/dev/null
)

MODE=''
COMMIT=''
declare -a RUNNER_ARGV=()

usage() {
  printf 'usage: %s {plan|run|restore} --commit 40-lowercase-hex\n' "$0" >&2
}

fail() {
  printf 'B82_ROUTED_CONTROLLER_SEAM_STOP run_id=%s mode=%s reason=%s rc=%s\n' \
    "${RUN_ID}" "${MODE:-unparsed}" "$1" "${2:-125}" >&2
  exit "${2:-125}"
}

valid_commit() {
  [[ "$1" =~ ^[0-9a-f]{40}$ && ! "$1" =~ ^0{40}$ && ! "$1" =~ ^f{40}$ ]]
}

parse_arguments() {
  local seen_commit=0
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
      *) usage; return 64 ;;
    esac
    shift 2
  done
  ((seen_commit == 1)) || return 65
  valid_commit "${COMMIT}" || return 65
}

build_runner_argv() {
  RUNNER_ARGV=(
    /bin/bash -p "${ROOT_RUNNER}" "${MODE}"
    --source "${SOURCE}"
    --commit "${COMMIT}"
  )
}

verify_stage_identity() {
  local actual_blob head mapped path relative shape status tree_entry
  [[ "$EUID" == 0 ]] || fail 'root-required' 77
  [[ "$(/usr/bin/readlink -e -- "${STAGE_ROOT}")" == "${STAGE_ROOT}" &&
    -d "${STAGE_ROOT}" && ! -L "${STAGE_ROOT}" ]] || fail 'stage-root-path' 79
  shape="$(/usr/bin/stat -Lc '%u:%g:%a:%F' -- "${STAGE_ROOT}")" || fail 'stage-root-stat'
  [[ "${shape}" == '0:0:700:directory' ]] || fail 'stage-root-identity' 79
  [[ "$(/usr/bin/readlink -e -- "${SOURCE}")" == "${SOURCE}" &&
    -d "${SOURCE}" && ! -L "${SOURCE}" && -d "${SOURCE}/.git" ]] || fail 'source-path' 79
  shape="$(/usr/bin/stat -Lc '%u:%g:%a:%F' -- "${SOURCE}")" || fail 'source-stat'
  [[ "${shape}" == '0:0:700:directory' ]] || fail 'source-identity' 79
  head="$("${GIT_COMMAND[@]}" -C "${SOURCE}" rev-parse --verify HEAD^{commit})" || fail 'source-head'
  [[ "${head}" == "${COMMIT}" ]] || fail 'source-commit' 79
  "${GIT_COMMAND[@]}" -C "${SOURCE}" diff --quiet "${COMMIT}" -- || fail 'tracked-worktree-drift' 79
  "${GIT_COMMAND[@]}" -C "${SOURCE}" diff --cached --quiet "${COMMIT}" -- || fail 'index-drift' 79
  status="$("${GIT_COMMAND[@]}" -C "${SOURCE}" status --porcelain=v1 \
    --untracked-files=all --ignore-submodules=none)" || fail 'source-status'
  [[ -z "${status}" ]] || fail 'source-status-drift' 79
  for relative in "${SELF_RELATIVE}" "${RUNNER_RELATIVE}"; do
    path="${SOURCE}/${relative}"
    [[ -f "${path}" && ! -L "${path}" ]] || fail "script-shape:${relative}" 79
    shape="$(/usr/bin/stat -Lc '%u:%g:%a:%h:%F' -- "${path}")" || fail "script-stat:${relative}"
    [[ "${shape}" == '0:0:700:1:regular file' ]] || fail "script-identity:${relative}" 79
    mapped="$("${GIT_COMMAND[@]}" -C "${SOURCE}" rev-parse "${COMMIT}:${relative}")" || fail "script-mapped:${relative}"
    tree_entry="$("${GIT_COMMAND[@]}" -C "${SOURCE}" ls-tree "${COMMIT}" -- "${relative}")" || fail "script-tree:${relative}"
    actual_blob="$("${GIT_COMMAND[@]}" -C "${SOURCE}" hash-object -- "${path}")" || fail "script-blob:${relative}"
    [[ "${tree_entry}" == $'100755 blob '"${mapped}"$'\t'"${relative}" &&
      "${mapped}" == "${actual_blob}" ]] || fail "script-drift:${relative}" 79
  done
  [[ "$(/usr/bin/readlink -e -- "$0")" == "${EXPECTED_SELF}" ]] || fail 'self-path' 79
}

main() {
  parse_arguments "$@" || fail 'arguments' $?
  build_runner_argv
  verify_stage_identity
  exec /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C "${RUNNER_ARGV[@]}"
}

main "$@"
