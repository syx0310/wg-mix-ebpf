#!/usr/bin/env bash
set -u
set -o pipefail
umask 077

REVIEW_ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)" || exit 70
readonly REVIEW_ROOT
readonly MATRIX="${REVIEW_ROOT}/root-matrix-n-r.sh"
readonly STAGER="${REVIEW_ROOT}/prepare-stage-root.sh"
readonly STATIC_TEST="${REVIEW_ROOT}/test_matrix_static.py"
readonly MODULE_LEASE_HELPER="${REVIEW_ROOT}/checksum-module-lease.sh"
readonly MODULE_LEASE_HERMETIC="${REVIEW_ROOT}/test-hermetic-checksum-module-lease.sh"
readonly MODULE_LEASE_STATIC="${REVIEW_ROOT}/test_checksum_module_lease_static.py"
readonly MODULE_SOURCE="${REVIEW_ROOT}/wg_mix_faketcp_checksum.c"
readonly COMMIT_FIXTURE='77a15cfa34c10546a9a703596d9dee0deff91a48'
readonly BUNDLE_FIXTURE='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit "${2:-1}"
}

for path in "${MATRIX}" "${STAGER}" "${STATIC_TEST}" \
  "${MODULE_LEASE_HELPER}" "${MODULE_LEASE_HERMETIC}" \
  "${MODULE_LEASE_STATIC}" "${MODULE_SOURCE}"; do
  [[ -f "${path}" && ! -L "${path}" ]] || fail "review input is not a regular file: ${path}"
done

/bin/bash -n "${MATRIX}" "${STAGER}" "${MODULE_LEASE_HELPER}" \
  "${MODULE_LEASE_HERMETIC}" "$0" || fail 'bash syntax gate'
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -B -I "${STATIC_TEST}" "${MATRIX}" "${STAGER}" ||
  fail 'static retirement contract'
/bin/bash "${MODULE_LEASE_HERMETIC}" "${MODULE_LEASE_HELPER}" \
  "${MODULE_LEASE_STATIC}" "${MODULE_SOURCE}" ||
  fail 'shared checksum-module lease contract'

if command -v shellcheck >/dev/null 2>&1; then
  shellcheck --norc --shell=bash -- "${MATRIX}" "${STAGER}" "${MODULE_LEASE_HELPER}" \
    "${MODULE_LEASE_HERMETIC}" "$0" || fail 'ShellCheck gate'
else
  printf 'SKIP: shellcheck unavailable; the .82 unprivileged U gate must run it before sudo\n'
fi

readonly -a MATRIX_ARGS=(
  --source /run/wg-mix-ebpf-source-stages/c8e41d73/source
  --commit "${COMMIT_FIXTURE}"
  --bundle /home/siyixuan/wg-mix-ebpf-test/unpriv-4f2a9b61/source-4f2a9b61.bundle
  --bundle-sha256 "${BUNDLE_FIXTURE}"
  --interface ens33
  --peer-address 47.116.202.155
  --peer-port 5201
  --soak-seconds 3600
  --session-seconds 300
  --wg-interface wg0
  --wg-local-address 10.200.0.1
  --wg-peer-address 10.200.0.2
)

plan_output="$(/bin/bash "${MATRIX}" plan)" || fail 'retired plan expansion'
[[ "${plan_output}" == *'REALHOST_V6_FORWARD_AUTHORITY state=retired replacement=realnic-acceptance-v1'* ]] ||
  fail 'forward retirement marker missing'
[[ "${plan_output}" == *'REALHOST_V6_LEGACY_CONTROLLER_AUTHORITY state=retired controller_entries=0 restore_entries=0'* ]] ||
  fail 'legacy controller retirement marker missing'
[[ "${plan_output}" == *'REALHOST_V6_HISTORICAL_RECOVERY package=frozen-original-package timing=before-final-staging'* ]] ||
  fail 'historical recovery boundary missing'
[[ "${plan_output}" == *'REALHOST_V6_PLAN_COMPLETE commands_executed=0 filesystem_writes=0 network_writes=0'* ]] ||
  fail 'retired plan side-effect fence missing'
for forbidden in '/usr/bin/iperf3' '/usr/sbin/ethtool -K' '/usr/sbin/ip link set' \
  'WG_MIX_EBPF_SCOPED_REALNIC_ACTION=run' 'restore-'; do
  [[ "${plan_output}" != *"${forbidden}"* ]] || fail "retired authority leaked into plan: ${forbidden}"
done

for retired_mode in run restore; do
  retired_output="$(/bin/bash "${MATRIX}" "${retired_mode}" \
    "${MATRIX_ARGS[@]}" --restore-cell tcx 2>&1)"
  retired_rc=$?
  [[ "${retired_rc}" -eq 78 ]] ||
    fail "retired ${retired_mode} returned ${retired_rc}, expected 78"
  [[ "${retired_output}" == *'reason=legacy-matrix-retired-use-frozen-original-package-before-final-staging rc=78'* ]] ||
    fail "retired ${retired_mode} did not emit its fixed reason"
done

reservation_create() {
  local target="$1"
  [[ ! -e "${target}" && ! -L "${target}" ]] || return 73
  (umask 077
    set -o noclobber
    : >"${target}")
}

stage_start() {
  local stage="$1"
  [[ ! -e "${stage}" && ! -L "${stage}" ]] || return 73
  /bin/mkdir -- "${stage}"
}

cut_root="$(/usr/bin/mktemp -d /private/tmp/wg-mix-b82-retirement-hermetic.XXXXXX)" ||
  fail 'retirement cut root creation'

fresh_stage="${cut_root}/fresh-stage"
/bin/mkdir -- "${fresh_stage}" || fail 'fresh stage fixture'
fresh_reservation="${fresh_stage}/realhost-v6-6bd913ac"
reservation_create "${fresh_reservation}" || fail 'fresh reservation create'
[[ -f "${fresh_reservation}" && ! -L "${fresh_reservation}" && ! -s "${fresh_reservation}" ]] ||
  fail 'fresh reservation shape'
[[ ! -e "${fresh_stage}/source" && ! -L "${fresh_stage}/source" ]] ||
  fail 'source appeared before clone'
retry_rc=0
stage_start "${fresh_stage}" || retry_rc=$?
[[ "${retry_rc}" -eq 73 ]] || fail 'post-reservation stager retry did not stop at stage-exists'
[[ ! -e "${fresh_stage}/source" && ! -L "${fresh_stage}/source" ]] ||
  fail 'crash/retry cut reached clone'

file_stage="${cut_root}/preexisting-file"
/bin/mkdir -- "${file_stage}" || fail 'preexisting file stage'
file_reservation="${file_stage}/realhost-v6-6bd913ac"
printf 'foreign\n' >"${file_reservation}" || fail 'preexisting file fixture'
file_rc=0
reservation_create "${file_reservation}" || file_rc=$?
[[ "${file_rc}" -eq 73 && "$(/bin/cat -- "${file_reservation}")" == 'foreign' ]] ||
  fail 'preexisting file was not rejected and retained'
[[ ! -e "${file_stage}/source" ]] || fail 'preexisting file cut reached clone'

directory_stage="${cut_root}/preexisting-directory"
/bin/mkdir -- "${directory_stage}" || fail 'preexisting directory stage'
directory_reservation="${directory_stage}/realhost-v6-6bd913ac"
/bin/mkdir -- "${directory_reservation}" || fail 'preexisting directory fixture'
directory_rc=0
reservation_create "${directory_reservation}" || directory_rc=$?
[[ "${directory_rc}" -eq 73 && -d "${directory_reservation}" && ! -L "${directory_reservation}" ]] ||
  fail 'preexisting directory was not rejected and retained'
[[ ! -e "${directory_stage}/source" ]] || fail 'preexisting directory cut reached clone'

race_stage="${cut_root}/o-excl-race"
/bin/mkdir -- "${race_stage}" || fail 'race stage fixture'
race_reservation="${race_stage}/realhost-v6-6bd913ac"
(umask 077; set -o noclobber; : >"${race_reservation}") 2>"${race_stage}/first.err" &
first_pid=$!
(umask 077; set -o noclobber; : >"${race_reservation}") 2>"${race_stage}/second.err" &
second_pid=$!
first_rc=0
second_rc=0
wait "${first_pid}" || first_rc=$?
wait "${second_pid}" || second_rc=$?
if ! ((first_rc == 0 && second_rc != 0 || first_rc != 0 && second_rc == 0)); then
  fail "O_EXCL race did not produce exactly one creator: first=${first_rc} second=${second_rc}"
fi
[[ -f "${race_reservation}" && ! -L "${race_reservation}" && ! -s "${race_reservation}" ]] ||
  fail 'O_EXCL winner did not leave one empty file'
[[ ! -e "${race_stage}/source" ]] || fail 'O_EXCL race cut reached clone'

printf 'hermetic retired matrix and root-stager reservation cuts: PASS\n'
printf 'RETAINED_HERMETIC_ROOT path=%s reason=auditable-no-cleanup-test-policy\n' "${cut_root}"
