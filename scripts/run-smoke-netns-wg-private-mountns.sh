#!/usr/bin/bash -p
if [[ "$-" != *p* ]]; then
  builtin printf '%s\n' \
    'error: private mount namespace launcher requires Bash privileged mode' >&2
  exit 1
fi
set -euo pipefail

# This launcher is the only supported root entry point for the WireGuard
# network-namespace smoke.  Keep the mount propagation change inside the new
# namespace: never make the host's / mount private in place.
XOR_SECRET="${XOR_PASSWORD-}"
unset XOR_PASSWORD

readonly SHA256_BIN="/usr/bin/sha256sum"
readonly STAT_BIN="/usr/bin/stat"
readonly SAFE_PATH="/usr/sbin:/usr/bin:/sbin:/bin"
readonly STAGED_LAUNCHER_NAME="scripts/run-smoke-netns-wg-private-mountns.sh"
readonly STAGED_SMOKE_NAME="scripts/smoke-netns-wg.sh"
readonly STAGED_SOURCE_HELPER_NAME="scripts/source-commit.sh"
readonly STAGED_ANCHOR_NAME="bin/wg-mix-ebpf-netns-anchor"

PATH="${SAFE_PATH}"
LC_ALL=C
export PATH LC_ALL
IFS=$' \t\n'
unset BASH_ENV CDPATH ENV GLOBIGNORE LD_LIBRARY_PATH LD_PRELOAD \
  PERL5LIB PYTHONHOME PYTHONPATH RUBYLIB

if [[ "${EUID}" -ne 0 ]]; then
  echo "error: run the private mount namespace launcher as root" >&2
  exit 1
fi
if (($# != 0)); then
  echo "error: private mount namespace launcher accepts no arguments" >&2
  exit 2
fi
for internal_name in \
  WG_MIX_EBPF_NETNS_ANCHOR_BOOTSTRAP_FD \
  WG_MIX_EBPF_SMOKE_MOUNTNS_CHILD \
  WG_MIX_EBPF_SMOKE_MOUNTNS_LAUNCH_FD \
  WG_MIX_EBPF_SMOKE_MOUNTNS_LAUNCH_NONCE \
  WG_MIX_EBPF_SMOKE_MOUNTNS_LAUNCH_SHA256 \
  WG_MIX_EBPF_SMOKE_MOUNTNS_OUTER_FD \
  WG_MIX_EBPF_SMOKE_MOUNTNS_OUTER_ID \
  WG_MIX_EBPF_SMOKE_MOUNTNS_OUTER_PID \
  WG_MIX_EBPF_SMOKE_MOUNTNS_SCRIPT_DEV \
  WG_MIX_EBPF_SMOKE_MOUNTNS_SCRIPT_FD \
  WG_MIX_EBPF_SMOKE_MOUNTNS_SCRIPT_INO \
  WG_MIX_EBPF_SMOKE_MOUNTNS_SCRIPT_SHA256 \
  WG_MIX_EBPF_SMOKE_MOUNTNS_SOURCE_COMMIT \
  WG_MIX_EBPF_SMOKE_MOUNTNS_SOURCE_ROOT \
  WG_MIX_EBPF_SMOKE_MOUNTNS_XOR_SECRET_FD; do
  if [[ -n "${!internal_name+x}" ]]; then
    echo "error: inherited private mount namespace control variable is forbidden: ${internal_name}" >&2
    exit 1
  fi
done

launcher_reference="${BASH_SOURCE[0]}"
if [[ "${launcher_reference}" == /* ]]; then
  launcher_path="${launcher_reference}"
elif [[ "${launcher_reference}" == "${STAGED_LAUNCHER_NAME}" ]]; then
  physical_pwd="$(builtin pwd -P)"
  launcher_path="${physical_pwd}/${STAGED_LAUNCHER_NAME}"
else
  echo "error: WG smoke launcher path is not the fixed staged entry" >&2
  exit 1
fi
source_root="${launcher_path%/"${STAGED_LAUNCHER_NAME}"}"
if [[ ! "${source_root}" =~ ^/run/wg-mix-ebpf-source-stages/[0-9a-f]{8}/source$ ]]; then
  echo "error: WG smoke must run from a run-bound root-owned source stage" >&2
  exit 1
fi
smoke_path="${source_root}/${STAGED_SMOKE_NAME}"
source_commit_helper="${source_root}/${STAGED_SOURCE_HELPER_NAME}"
anchor_path="${source_root}/${STAGED_ANCHOR_NAME}"
for staged_path in \
  "${launcher_path}" "${smoke_path}" "${source_commit_helper}" "${anchor_path}"; do
  if [[ "${staged_path}" != /* || -L "${staged_path}" ||
    ! -f "${staged_path}" || ! -x "${staged_path}" ]]; then
    echo "error: staged launch executable is missing or unsafe: ${staged_path}" >&2
    exit 1
  fi
done

exec {launcher_fd}<"${launcher_path}"
exec {smoke_fd}<"${smoke_path}"
exec {source_helper_fd}<"${source_commit_helper}"
exec {anchor_fd}<"${anchor_path}"
# Run() consumes and closes its bootstrap descriptor in each child.  Keep a
# distinct duplicate so review-staged-launch can compare the held stage path
# with /proc/self/exe after the bootstrap FD has been consumed.
exec {anchor_review_fd}<&"${anchor_fd}"
for staged_fd in \
  "${launcher_fd}" "${smoke_fd}" "${source_helper_fd}" \
  "${anchor_fd}" "${anchor_review_fd}"; do
  if [[ ! "${staged_fd}" =~ ^[1-9][0-9]*$ ]]; then
    echo "error: staged launch descriptor allocation failed" >&2
    exit 1
  fi
done
if [[ "${launcher_fd}" == "${smoke_fd}" ||
  "${launcher_fd}" == "${source_helper_fd}" ||
  "${launcher_fd}" == "${anchor_fd}" ||
  "${launcher_fd}" == "${anchor_review_fd}" ||
  "${smoke_fd}" == "${source_helper_fd}" ||
  "${smoke_fd}" == "${anchor_fd}" ||
  "${smoke_fd}" == "${anchor_review_fd}" ||
  "${source_helper_fd}" == "${anchor_fd}" ||
  "${source_helper_fd}" == "${anchor_review_fd}" ||
  "${anchor_fd}" == "${anchor_review_fd}" ]]; then
  echo "error: staged launch descriptors must be distinct" >&2
  exit 1
fi

run_anchor() {
  local subcommand="$1"
  shift
  WG_MIX_EBPF_NETNS_ANCHOR_BOOTSTRAP_FD="${anchor_fd}" \
    "/proc/self/fd/${anchor_fd}" "${subcommand}" "$@"
}

run_reviewed_system_tool() {
  local logical_path="$1"
  shift
  run_anchor reviewed-exec "${logical_path}" -- "$@"
}

run_anchor review-staged-launch \
  --source-root "${source_root}" \
  --launcher-fd "${launcher_fd}" \
  --smoke-fd "${smoke_fd}" \
  --source-helper-fd "${source_helper_fd}" \
  --anchor-fd "${anchor_review_fd}"
run_anchor review-system-tools
exec {launcher_fd}<&-
exec {source_helper_fd}<&-
exec {anchor_review_fd}<&-

exec {outer_mountns_fd}<"/proc/self/ns/mnt"
read -r smoke_dev smoke_ino smoke_uid smoke_mode smoke_links smoke_kind < <(
  run_reviewed_system_tool \
    "${STAT_BIN}" -Lc '%d %i %u %a %h %F' -- "/proc/self/fd/${smoke_fd}"
)
read -r smoke_path_dev smoke_path_ino < <(
  run_reviewed_system_tool "${STAT_BIN}" -Lc '%d %i' -- "${smoke_path}"
)
if [[ ! "${smoke_fd}" =~ ^[1-9][0-9]*$ ||
  ! "${outer_mountns_fd}" =~ ^[1-9][0-9]*$ ||
  "${smoke_fd}" == "${outer_mountns_fd}" ||
  ! "${smoke_dev}" =~ ^[1-9][0-9]*$ ||
  ! "${smoke_ino}" =~ ^[1-9][0-9]*$ ||
  "${smoke_uid}" != "0" || ! "${smoke_mode}" =~ ^[0-7]{3,4}$ ||
  "${smoke_links}" != "1" || "${smoke_kind}" != "regular file" ||
  "${smoke_path_dev}" != "${smoke_dev}" ||
  "${smoke_path_ino}" != "${smoke_ino}" ]] ||
  (((8#${smoke_mode} & 8#22) != 0)) || (((8#${smoke_mode} & 8#111) == 0)); then
  echo "error: staged smoke script identity or mode is unsafe" >&2
  exit 1
fi

smoke_sha256="$(run_reviewed_system_tool \
  "${SHA256_BIN}" -- "/proc/self/fd/${smoke_fd}")"
smoke_sha256="${smoke_sha256%% *}"
source_commit="$(run_anchor identity)"
outer_mountns_id="$(run_reviewed_system_tool \
  "${STAT_BIN}" -Lc '%d:%i' -- "/proc/self/fd/${outer_mountns_fd}")"
if [[ ! "${smoke_sha256}" =~ ^[0-9a-f]{64}$ ||
  ! "${source_commit}" =~ ^[0-9a-f]{40}$ ||
  ! "${outer_mountns_id}" =~ ^[1-9][0-9]*:[1-9][0-9]*$ ]]; then
  echo "error: could not seal private mount namespace launch identity" >&2
  exit 1
fi

IFS= read -r launch_nonce < /proc/sys/kernel/random/uuid
if [[ ! "${launch_nonce}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]]; then
  echo "error: could not generate private mount namespace launch nonce" >&2
  exit 1
fi
exec {xor_secret_fd}<<<"${XOR_SECRET}"
unset XOR_SECRET
launch_record="$(printf '%s\n' \
  'format=wg-mix-ebpf-smoke-mountns-launch-v1' \
  "nonce=${launch_nonce}" \
  "outer_pid=$$" \
  "outer_id=${outer_mountns_id}" \
  "script_fd=${smoke_fd}" \
  "script_dev=${smoke_dev}" \
  "script_ino=${smoke_ino}" \
  "script_sha256=${smoke_sha256}" \
  "source_commit=${source_commit}" \
  "source_root=${source_root}" \
  "xor_secret_fd=${xor_secret_fd}")"
launch_record_sha256="$(printf '%s' "${launch_record}" | \
  run_reviewed_system_tool "${SHA256_BIN}")"
launch_record_sha256="${launch_record_sha256%% *}"
exec {launch_record_fd}<<<"${launch_record}"
if [[ ! "${xor_secret_fd}" =~ ^[1-9][0-9]*$ ||
  ! "${launch_record_fd}" =~ ^[1-9][0-9]*$ ||
  "${xor_secret_fd}" == "${launch_record_fd}" ||
  "${xor_secret_fd}" == "${smoke_fd}" ||
  "${xor_secret_fd}" == "${outer_mountns_fd}" ||
  "${launch_record_fd}" == "${smoke_fd}" ||
  "${launch_record_fd}" == "${outer_mountns_fd}" ||
  ! "${launch_record_sha256}" =~ ^[0-9a-f]{64}$ ]]; then
  echo "error: could not seal private mount namespace launch record" >&2
  exit 1
fi

child_environment=(
  "PATH=${SAFE_PATH}"
  "LC_ALL=C"
  "WG_MIX_EBPF_SMOKE_MOUNTNS_CHILD=1"
  "WG_MIX_EBPF_SMOKE_MOUNTNS_LAUNCH_FD=${launch_record_fd}"
  "WG_MIX_EBPF_SMOKE_MOUNTNS_LAUNCH_NONCE=${launch_nonce}"
  "WG_MIX_EBPF_SMOKE_MOUNTNS_LAUNCH_SHA256=${launch_record_sha256}"
  "WG_MIX_EBPF_SMOKE_MOUNTNS_OUTER_FD=${outer_mountns_fd}"
  "WG_MIX_EBPF_SMOKE_MOUNTNS_OUTER_ID=${outer_mountns_id}"
  "WG_MIX_EBPF_SMOKE_MOUNTNS_OUTER_PID=$$"
  "WG_MIX_EBPF_SMOKE_MOUNTNS_SCRIPT_DEV=${smoke_dev}"
  "WG_MIX_EBPF_SMOKE_MOUNTNS_SCRIPT_FD=${smoke_fd}"
  "WG_MIX_EBPF_SMOKE_MOUNTNS_SCRIPT_INO=${smoke_ino}"
  "WG_MIX_EBPF_SMOKE_MOUNTNS_SCRIPT_SHA256=${smoke_sha256}"
  "WG_MIX_EBPF_SMOKE_MOUNTNS_SOURCE_COMMIT=${source_commit}"
  "WG_MIX_EBPF_SMOKE_MOUNTNS_SOURCE_ROOT=${source_root}"
  "WG_MIX_EBPF_SMOKE_MOUNTNS_XOR_SECRET_FD=${xor_secret_fd}"
)
for business_name in \
  ATTACHMENT_BACKEND NETNS_ANCHOR_TTL_SECONDS OUTER_FAMILY RUN_ID TCP_CAPTURE_PACKETS \
  TCP_CHECKS TCP_DIRECTIONS TCP_DURATION TCP_GSO_CHECKS \
  TCP_INNER_GSO_CHECKS TCP_MAX_RETRANSMITS TCP_MIN_BYTES \
  TCP_MIN_FAIRNESS TCP_MTUS TCP_OUTER_GSO_CHECKS TCP_PORT TCP_STREAMS \
  UDP_ZERO_CHECKSUM_CHECKS UNDERLAY_MTU WG_MTU XOR_DISPATCH_FAILURE_CHECKS \
  XOR_GENERATION_CHECKS XOR_MAX_BYTES XOR_SCOPE; do
  if [[ -n "${!business_name+x}" ]]; then
    child_environment+=("${business_name}=${!business_name}")
  fi
done

status=0
launch_arguments=(
  launch-private-mountns
  --source-root "${source_root}"
  --smoke-fd "${smoke_fd}"
)
for child_entry in "${child_environment[@]}"; do
  launch_arguments+=(--child-env "${child_entry}")
done
if run_anchor "${launch_arguments[@]}"; then
  status=0
else
  status=$?
fi
launcher_current_mountns_id="$(run_reviewed_system_tool \
  "${STAT_BIN}" -Lc '%d:%i' -- /proc/self/ns/mnt)"
launcher_outer_mountns_id="$(run_reviewed_system_tool \
  "${STAT_BIN}" -Lc '%d:%i' -- "/proc/self/fd/${outer_mountns_fd}")"
if [[ "${launcher_current_mountns_id}" != "${outer_mountns_id}" ||
  "${launcher_outer_mountns_id}" != "${outer_mountns_id}" ]]; then
  echo "error: launcher mount namespace identity changed while waiting for child" >&2
  exit 1
fi
exec {outer_mountns_fd}<&-
exec {smoke_fd}<&-
exec {launch_record_fd}<&-
exec {xor_secret_fd}<&-
exec {anchor_fd}<&-
exit "${status}"
