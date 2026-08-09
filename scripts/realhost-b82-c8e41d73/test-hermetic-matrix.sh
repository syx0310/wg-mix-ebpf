#!/usr/bin/env bash
set -u
set -o pipefail
umask 077

readonly REVIEW_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
readonly MATRIX="${REVIEW_ROOT}/root-matrix-n-r.sh"
readonly STAGER="${REVIEW_ROOT}/prepare-stage-root.sh"
readonly STATIC_TEST="${REVIEW_ROOT}/test_matrix_static.py"
readonly MODULE_LEASE_HELPER="${REVIEW_ROOT}/checksum-module-lease.sh"
readonly MODULE_LEASE_HERMETIC="${REVIEW_ROOT}/test-hermetic-checksum-module-lease.sh"
readonly COMMIT_FIXTURE='77a15cfa34c10546a9a703596d9dee0deff91a48'
readonly BUNDLE_FIXTURE='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit "${2:-1}"
}

for path in "${MATRIX}" "${STAGER}" "${STATIC_TEST}" \
  "${MODULE_LEASE_HELPER}" "${MODULE_LEASE_HERMETIC}"; do
  [[ -f "${path}" && ! -L "${path}" ]] || fail "review input is not a regular file: ${path}"
done

/bin/bash -n "${MATRIX}" "${STAGER}" "${MODULE_LEASE_HELPER}" \
  "${MODULE_LEASE_HERMETIC}" "$0" || fail 'bash syntax gate'
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -B -I "${STATIC_TEST}" "${MATRIX}" "${STAGER}" ||
  fail 'static retirement contract'
/bin/bash "${MODULE_LEASE_HERMETIC}" || fail 'shared checksum-module lease contract'

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

plan_output="$("${MATRIX}" plan "${MATRIX_ARGS[@]}" --restore-cell none)" ||
  fail 'restore-only plan expansion'
[[ "${plan_output}" == *'REALHOST_V6_FORWARD_AUTHORITY state=retired replacement=realnic-acceptance'* ]] ||
  fail 'forward retirement marker missing'
[[ "${plan_output}" == *'REALHOST_V6_PLAN_SCOPE restore-only=1 network-writes-executed=0 filesystem-writes-executed=0'* ]] ||
  fail 'restore-only side-effect fence missing'
[[ "${plan_output}" == *'REALHOST_V6_PLAN_COMPLETE restore_entries=9 no_commands_executed=1'* ]] ||
  fail 'restore-only completion fence missing'
restore_entries="$(printf '%s\n' "${plan_output}" | /usr/bin/awk '/^restore-[^ ]+ argv=/ { count++ } END { print count + 0 }')" ||
  fail 'restore entry count'
[[ "${restore_entries}" == '9' ]] || fail 'restore entry set is not exactly nine'
for forbidden in '/usr/bin/iperf3' '/usr/sbin/ethtool -K' '/usr/sbin/ip link set' \
  'WG_MIX_EBPF_SCOPED_REALNIC_ACTION=run'; do
  [[ "${plan_output}" != *"${forbidden}"* ]] || fail "forward command leaked into plan: ${forbidden}"
done

run_output="$("${MATRIX}" run "${MATRIX_ARGS[@]}" --restore-cell none 2>&1)"
run_rc=$?
[[ "${run_rc}" -eq 78 ]] || fail "retired run returned ${run_rc}, expected 78"
[[ "${run_output}" == *'reason=legacy-forward-authority-retired-use-realnic-acceptance rc=78'* ]] ||
  fail 'retired run did not emit its fixed reason'

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
