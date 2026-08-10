#!/usr/bin/env bash
set -u
set -o pipefail
umask 077

REVIEW_ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)" || exit 70
readonly REVIEW_ROOT
REPOSITORY="$(CDPATH='' cd -- "${REVIEW_ROOT}/../.." && pwd -P)" || exit 70
readonly REPOSITORY
readonly BINDER="${REVIEW_ROOT}/bind-final-package.sh"
readonly CONTROLLER="${REVIEW_ROOT}/controller.sh"
readonly TRANSPORT="${REVIEW_ROOT}/locked-transport.exp"
readonly STAGER="${REVIEW_ROOT}/prepare-stage-root.sh"
readonly MATRIX="${REVIEW_ROOT}/root-matrix-n-r.sh"
readonly STATIC_TEST="${REVIEW_ROOT}/test_controller_static.py"
readonly REALNIC_ROOT="${REPOSITORY}/scripts/realhost-b82-acceptance-v1"
readonly REALNIC="${REALNIC_ROOT}/realnic_acceptance.py"
readonly REALNIC_TEST="${REALNIC_ROOT}/test_realnic_acceptance.py"
readonly REALNIC_STATIC_TEST="${REALNIC_ROOT}/test_realnic_acceptance_static.py"
readonly REALNIC_INTEGRATION_MERGE='7621f84df30b52428abed1988c6c1800cc7d1768'
readonly REALNIC_STAGE_B_PARENT='9284344e58f949efb98be963438a173499791669'
readonly REVIEWED_CANONICAL_PARENT='d28585bfaaefe44c0e71d2cbbced494da96dd7fa'
readonly -a REALNIC_INTEGRATION_FILES=(
  scripts/realhost-b82-acceptance-v1/realnic_acceptance.py
  scripts/realhost-b82-acceptance-v1/test_realnic_acceptance.py
  scripts/realhost-b82-acceptance-v1/test_realnic_acceptance_static.py
  scripts/realhost-b82-c8e41d73/bind-final-package.sh
  scripts/realhost-b82-c8e41d73/controller.sh
  scripts/realhost-b82-c8e41d73/locked-transport.exp
  scripts/realhost-b82-c8e41d73/prepare-stage-root.sh
  scripts/realhost-b82-c8e41d73/root-matrix-n-r.sh
)
readonly REALNIC_MANAGED_INTEGRATION_MERGE='93cd6a890ef37d75e9d7a63ed3504a1bbf4b9796'
readonly REALNIC_DURABLE_PARENT='1e8e183fe8ff0d295fe9c40e5b9573b5f23f4e7c'
readonly MANAGED_CANONICAL_PARENT='4636302fd45dae8134faf7b0aec4adc0737c5f3e'
readonly -a REALNIC_DURABLE_INTEGRATION_FILES=(
  internal/dataplane/scoped_realnic_checker_contract_test.go
  internal/dataplane/scoped_realnic_linux_test.go
  scripts/realhost-b82-acceptance-v1/realnic_acceptance.py
  scripts/realhost-b82-acceptance-v1/test_realnic_acceptance.py
  scripts/realhost-b82-acceptance-v1/test_realnic_acceptance_static.py
  scripts/realhost-b82-c8e41d73/bind-final-package.sh
  scripts/realhost-b82-c8e41d73/check-realhost-iperf.py
  scripts/realhost-b82-c8e41d73/controller.sh
  scripts/realhost-b82-c8e41d73/locked-transport.exp
  scripts/realhost-b82-c8e41d73/prepare-stage-root.sh
  scripts/realhost-b82-c8e41d73/root-fresh-verifier-gate.sh
  scripts/realhost-b82-c8e41d73/root-matrix-n-r.sh
  scripts/realhost-b82-c8e41d73/test-hermetic-controller.sh
  scripts/realhost-b82-c8e41d73/test-hermetic-fresh-verifier-gate.sh
  scripts/realhost-b82-c8e41d73/test-hermetic-matrix.sh
  scripts/realhost-b82-c8e41d73/test_controller_static.py
  scripts/realhost-b82-c8e41d73/test_fresh_verifier_gate_static.py
  scripts/realhost-b82-c8e41d73/test_matrix_static.py
)
readonly -a MANAGED_EXACT_INTEGRATION_FILES=(
  bpf/wg_mix_faketcp.h
  internal/dataplane/faketcp_managed_ingress_contract_test.go
  internal/dataplane/faketcp_managed_ingress_realhost_linux_test.go
  internal/faketcp/controller.go
  internal/faketcp/engine.go
  internal/faketcp/engine_router.go
  internal/faketcp/engine_router_test.go
  internal/faketcp/runtime_domain.go
  internal/faketcp/runtime_domain_test.go
  scripts/realhost-b82-c8e41d73/root-veth-n-r.sh
  scripts/realhost-b82-c8e41d73/test_veth_runner_static.py
)
readonly MODULE_LEASE_HELPER="${REVIEW_ROOT}/checksum-module-lease.sh"
readonly PROVISION_POLICY_TEST="${REVIEW_ROOT}/test_provision_policy.tcl"
readonly PROVISIONER="${REPOSITORY}/scripts/provision-ubuntu-test-host.sh"
readonly CREDENTIAL_PATH='/Users/siyixuan/codes-2/wg-mix-ebpf/credientials/192.168.10.82'

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit "${2:-1}"
}

sha256_file() {
  local line
  if [[ -x /usr/bin/shasum ]]; then
    line="$(/usr/bin/shasum -a 256 -- "$1")" || return $?
  else
    line="$(/usr/bin/sha256sum -- "$1")" || return $?
  fi
  printf '%s\n' "${line%% *}"
}

manifest_value() {
  local key="$1" manifest="$2"
  /usr/bin/awk -F '\t' -v expected="${key}" \
    '$1 == expected { if (++seen > 1 || NF != 2) exit 65; value=$2 } END { if (seen != 1) exit 65; print value }' \
    "${manifest}"
}

expect_failure() {
  local label="$1" output
  shift
  if output="$("$@" 2>&1)"; then
    fail "${label} unexpectedly succeeded"
  fi
  printf 'EXPECTED_FAILURE label=%s output=%q\n' "${label}" "${output}"
}

expect_exact_rc() {
  local label="$1" expected_rc="$2" output rc
  shift 2
  output="$("$@" 2>&1)"
  rc=$?
  [[ "${rc}" == "${expected_rc}" ]] ||
    fail "${label}: expected rc=${expected_rc}, observed rc=${rc}, output=${output}"
  printf 'EXPECTED_FAILURE label=%s rc=%s output=%q\n' "${label}" "${rc}" "${output}"
}

require_ordered_literals() {
  local remaining="$1" marker
  shift
  for marker in "$@"; do
    [[ "${remaining}" == *"${marker}"* ]] || fail "ordered plan marker missing: ${marker}"
    remaining="${remaining#*"${marker}"}"
  done
}

fixture_file_identity() {
  /usr/bin/python3 -B -I -c \
    'import os, sys; print(os.stat(sys.argv[1]).st_ino)' "$1"
}

approved_plan_verify_fixture() {
  local destination="$1" expected_sha="$2" pending
  pending="${destination}.pending.${expected_sha}"
  /usr/bin/python3 -B -I -c \
    'import hashlib, os, stat, sys
final_path, pending_path, expected = sys.argv[1:]
values = []
for path in (final_path, pending_path):
    value = os.lstat(path)
    if not stat.S_ISREG(value.st_mode) or stat.S_ISLNK(value.st_mode):
        raise SystemExit(79)
    if stat.S_IMODE(value.st_mode) != 0o600 or value.st_nlink != 2 or not 0 < value.st_size <= 16 << 20:
        raise SystemExit(79)
    with open(path, "rb") as handle:
        if hashlib.sha256(handle.read()).hexdigest() != expected:
            raise SystemExit(79)
    values.append((value.st_dev, value.st_ino))
if values[0] != values[1]:
    raise SystemExit(79)' "${destination}" "${pending}" "${expected_sha}"
}

approved_plan_pending_fixture() {
  /usr/bin/python3 -B -I -c \
    'import os, stat, sys
value = os.lstat(sys.argv[1])
if not stat.S_ISREG(value.st_mode) or stat.S_ISLNK(value.st_mode):
    raise SystemExit(79)
if stat.S_IMODE(value.st_mode) != 0o600 or value.st_nlink != 1 or value.st_size > 16 << 20:
    raise SystemExit(79)' "$1"
}

approved_plan_snapshot_fixture() {
  local source="$1" destination="$2" expected_sha="$3" cut="${4:-none}"
  local source_sha pending descriptor_identity path_identity
  pending="${destination}.pending.${expected_sha}"
  [[ -f "${source}" && ! -L "${source}" ]] || return 79
  source_sha="$(sha256_file "${source}")" || return $?
  [[ "${source_sha}" == "${expected_sha}" ]] || return 79
  exec 9<"${source}" || return 79
  if [[ -e "${destination}" || -L "${destination}" ]]; then
    approved_plan_verify_fixture "${destination}" "${expected_sha}" || return $?
  else
    if [[ ! -e "${pending}" && ! -L "${pending}" ]]; then
      (umask 077
        set -o noclobber
        : >"${pending}") || return $?
    fi
    approved_plan_pending_fixture "${pending}" || return $?
    exec 7<>"${pending}" || return 79
    descriptor_identity="$(fixture_file_identity /dev/fd/7)" || return 79
    path_identity="$(fixture_file_identity "${pending}")" || return 79
    [[ "${descriptor_identity}" == "${path_identity}" ]] || return 79
    if [[ "${cut}" == 'inode-swap' ]]; then
      /bin/ln -- "${pending}" "${pending}.swapped-out" || return $?
      : >"${pending}.replacement" || return $?
      /bin/chmod 0600 "${pending}.replacement" || return $?
      /bin/mv -- "${pending}.replacement" "${pending}" || return $?
    fi
    if [[ "${cut}" == 'partial-write' ]]; then
      printf '{"cut' >"/dev/fd/7" || return $?
      return 91
    fi
    /bin/cat -- /dev/fd/9 >"/dev/fd/7" || return $?
    /usr/bin/python3 -B -I -c 'import os, sys; os.fsync(int(sys.argv[1]))' 7 || return $?
    [[ "$(fixture_file_identity "${pending}")" == "${descriptor_identity}" ]] || return 79
    [[ "$(sha256_file "${pending}")" == "${expected_sha}" ]] || return 79
    /usr/bin/python3 -B -I -c \
      'import os, sys; fd = os.open(sys.argv[1], os.O_RDONLY); os.fsync(fd); os.close(fd)' \
      "$(dirname -- "${destination}")" || return $?
    [[ "${cut}" != 'post-fsync' ]] || return 92
    /bin/ln -- "${pending}" "${destination}" || return $?
    [[ "${cut}" != 'post-link' ]] || return 93
  fi
  /usr/bin/python3 -B -I -c \
    'import os, sys; fd = os.open(sys.argv[1], os.O_RDONLY); os.fsync(fd); os.close(fd)' \
    "$(dirname -- "${destination}")" || return $?
  approved_plan_verify_fixture "${destination}" "${expected_sha}" || return $?
  [[ "$(fixture_file_identity "${source}")" == "$(fixture_file_identity /dev/fd/9)" &&
    "$(sha256_file "${source}")" == "${expected_sha}" ]]
}

for path in "${BINDER}" "${CONTROLLER}" "${TRANSPORT}" "${STAGER}" "${MATRIX}" \
  "${STATIC_TEST}" "${REALNIC}" "${REALNIC_TEST}" "${REALNIC_STATIC_TEST}" \
  "${MODULE_LEASE_HELPER}" "${PROVISION_POLICY_TEST}" "${PROVISIONER}"; do
  [[ -f "${path}" && ! -L "${path}" ]] || fail "review input is not a regular file: ${path}"
done

REALNIC_INTEGRATION_PARENTS="$(/usr/bin/git -C "${REPOSITORY}" show -s --format=%P \
  "${REALNIC_INTEGRATION_MERGE}")" || fail 'cannot read realNIC integration parents'
readonly REALNIC_INTEGRATION_PARENTS
[[ "${REALNIC_INTEGRATION_PARENTS}" == \
  "${REALNIC_STAGE_B_PARENT} ${REVIEWED_CANONICAL_PARENT}" ]] ||
  fail 'realNIC integration does not preserve the exact two-parent topology'
/usr/bin/git -C "${REPOSITORY}" merge-base --is-ancestor \
  "${REALNIC_INTEGRATION_MERGE}" HEAD || fail 'HEAD does not contain the realNIC integration merge'
/usr/bin/git -C "${REPOSITORY}" diff --exit-code \
  "${REALNIC_INTEGRATION_MERGE}^1" "${REALNIC_INTEGRATION_MERGE}" -- \
  "${REALNIC_INTEGRATION_FILES[@]}" ||
  fail 'canonical merge rewrote a Stage B authority or manifest source blob'

REALNIC_MANAGED_INTEGRATION_PARENTS="$(/usr/bin/git -C "${REPOSITORY}" show -s --format=%P \
  "${REALNIC_MANAGED_INTEGRATION_MERGE}")" || fail 'cannot read managed realNIC integration parents'
readonly REALNIC_MANAGED_INTEGRATION_PARENTS
[[ "${REALNIC_MANAGED_INTEGRATION_PARENTS}" == \
  "${REALNIC_DURABLE_PARENT} ${MANAGED_CANONICAL_PARENT}" ]] ||
  fail 'managed realNIC integration does not preserve the exact two-parent topology'
/usr/bin/git -C "${REPOSITORY}" merge-base --is-ancestor \
  "${REALNIC_MANAGED_INTEGRATION_MERGE}" HEAD ||
  fail 'HEAD does not contain the managed realNIC integration merge'
/usr/bin/git -C "${REPOSITORY}" diff --exit-code \
  "${REALNIC_DURABLE_PARENT}" "${REALNIC_MANAGED_INTEGRATION_MERGE}" -- \
  "${REALNIC_DURABLE_INTEGRATION_FILES[@]}" ||
  fail 'managed canonical merge rewrote a durable realNIC authority or manifest source blob'
/usr/bin/git -C "${REPOSITORY}" diff --exit-code \
  "${MANAGED_CANONICAL_PARENT}" "${REALNIC_MANAGED_INTEGRATION_MERGE}" -- \
  "${MANAGED_EXACT_INTEGRATION_FILES[@]}" ||
  fail 'managed realNIC integration rewrote a non-conflicting managed-ingress blob'
MANAGED_INTEGRATION_WRITE_SET="$(/usr/bin/git -C "${REPOSITORY}" diff --name-only \
  "${REALNIC_DURABLE_PARENT}" "${REALNIC_MANAGED_INTEGRATION_MERGE}")" ||
  fail 'cannot read managed realNIC integration write set'
readonly MANAGED_INTEGRATION_WRITE_SET
[[ "${MANAGED_INTEGRATION_WRITE_SET}" == $'bpf/wg_mix_faketcp.h\ninternal/dataplane/faketcp_managed_ingress_contract_test.go\ninternal/dataplane/faketcp_managed_ingress_realhost_linux_test.go\ninternal/faketcp/controller.go\ninternal/faketcp/engine.go\ninternal/faketcp/engine_router.go\ninternal/faketcp/engine_router_test.go\ninternal/faketcp/runtime_domain.go\ninternal/faketcp/runtime_domain_test.go\nscripts/realhost-b82-c8e41d73/root-veth-n-r.sh\nscripts/realhost-b82-c8e41d73/test-hermetic-veth-runner.sh\nscripts/realhost-b82-c8e41d73/test_veth_runner_static.py' ]] ||
  fail 'managed realNIC integration changed a non-topic path'
MANAGED_INTEGRATION_HERMETIC="$(/usr/bin/git -C "${REPOSITORY}" show \
  "${REALNIC_MANAGED_INTEGRATION_MERGE}:scripts/realhost-b82-c8e41d73/test-hermetic-veth-runner.sh")" ||
  fail 'cannot read managed realNIC integration resolution'
readonly MANAGED_INTEGRATION_HERMETIC
for marker in \
  ORIGINAL_MERGE_RESOLUTION_BLOBS \
  MANAGED_INGRESS_ACCOUNTING_PARENTS \
  MANAGED_INGRESS_PRODUCTION_PARENTS \
  MANAGED_INGRESS_ACCEPTANCE_ROOT_PARENTS \
  MANAGED_INGRESS_ACCEPTANCE_PARENTS \
  MANAGED_INGRESS_PRODUCTION_PATHS \
  MANAGED_INGRESS_TEST_PATHS; do
  [[ "${MANAGED_INTEGRATION_HERMETIC}" == *"${marker}"* ]] ||
    fail "managed realNIC integration dropped conflict contract: ${marker}"
done
[[ "${MANAGED_INTEGRATION_HERMETIC}" != *'MERGE_RESOLUTION_FILES'* ]] ||
  fail 'managed realNIC integration replaced exact historical blobs with a moving file list'

/bin/bash -n "${BINDER}" "${CONTROLLER}" "${STAGER}" "${MODULE_LEASE_HELPER}" \
  "${PROVISIONER}" "$0" || fail 'Bash syntax gate'
/usr/bin/python3 -B -I "${STATIC_TEST}" \
  "${BINDER}" "${CONTROLLER}" "${TRANSPORT}" "${STAGER}" "${MATRIX}" "${PROVISIONER}" ||
  fail 'static controller contract'
/usr/bin/expect "${PROVISION_POLICY_TEST}" "${TRANSPORT}" || fail 'provision output policy'
EXPECT_ARGUMENT_OUTPUT="$(/usr/bin/expect "${TRANSPORT}" 2>&1)"
EXPECT_ARGUMENT_RC=$?
[[ "${EXPECT_ARGUMENT_RC}" -eq 64 && "${EXPECT_ARGUMENT_OUTPUT}" == *'reason=arguments rc=64'* ]] ||
  fail 'Expect syntax/argument gate'

if command -v shellcheck >/dev/null 2>&1; then
  shellcheck --norc --shell=bash -- "${BINDER}" "${CONTROLLER}" "${STAGER}" \
    "${MODULE_LEASE_HELPER}" "${PROVISIONER}" "$0" ||
    fail 'ShellCheck gate'
else
  printf 'SKIP: shellcheck unavailable locally; .82 preflight binds /usr/bin/shellcheck\n'
fi

TEST_ROOT="$(/usr/bin/mktemp -d /private/tmp/wg-mix-b82-v6-controller-hermetic.XXXXXX)" ||
  fail 'temporary root creation'
FIXTURE_REPOSITORY="${TEST_ROOT}/repository"
FIXTURE_REVIEW="${FIXTURE_REPOSITORY}/scripts/realhost-b82-c8e41d73"
FIXTURE_REALNIC="${FIXTURE_REPOSITORY}/scripts/realhost-b82-acceptance-v1"
FIXTURE_ROUTED="${FIXTURE_REPOSITORY}/scripts/realhost-b82-routed-veth-v1"
/bin/mkdir -m 0700 -- "${FIXTURE_REPOSITORY}" || fail 'fixture repository creation'
/usr/bin/git -C "${FIXTURE_REPOSITORY}" init || fail 'fixture Git init'
/usr/bin/git -C "${FIXTURE_REPOSITORY}" config user.name 'Hermetic Controller Test' || fail 'fixture Git name'
/usr/bin/git -C "${FIXTURE_REPOSITORY}" config user.email 'hermetic-controller@example.invalid' || fail 'fixture Git email'
printf 'history-root=%s\n' "${TEST_ROOT##*/}" >"${FIXTURE_REPOSITORY}/history-root.v1" ||
  fail 'fixture history root'
/usr/bin/git -C "${FIXTURE_REPOSITORY}" add -- history-root.v1 || fail 'fixture history root add'
/usr/bin/git -C "${FIXTURE_REPOSITORY}" commit -m 'Hermetic history root' || fail 'fixture history root commit'
/bin/mkdir -p -- "${FIXTURE_REVIEW}" "${FIXTURE_REALNIC}" "${FIXTURE_ROUTED}" ||
  fail 'fixture review directory creation'
for name in \
  bind-final-package.sh controller.sh locked-transport.exp prepare-stage-root.sh \
  root-matrix-n-r.sh check-realhost-iperf.py test-hermetic-matrix.sh test_matrix_static.py \
  root-fresh-verifier-gate.sh test-hermetic-fresh-verifier-gate.sh \
  test_fresh_verifier_gate_static.py \
  root-veth-n-r.sh test-hermetic-veth-runner.sh test_veth_runner_static.py \
  checksum-module-lease.sh test-hermetic-checksum-module-lease.sh \
  test_checksum_module_lease_static.py test_provision_policy.tcl; do
  /bin/cp -- "${REVIEW_ROOT}/${name}" "${FIXTURE_REVIEW}/${name}" || fail "fixture copy ${name}"
done
for name in controller-seam.sh root-routed-veth-n-r.sh \
  test-hermetic-routed-veth-harness.sh test_routed_veth_harness_static.py; do
  /bin/cp -- "${REPOSITORY}/scripts/realhost-b82-routed-veth-v1/${name}" \
    "${FIXTURE_ROUTED}/${name}" || fail "fixture copy routed ${name}"
done
for name in realnic_acceptance.py test_realnic_acceptance.py test_realnic_acceptance_static.py; do
  /bin/cp -- "${REALNIC_ROOT}/${name}" "${FIXTURE_REALNIC}/${name}" ||
    fail "fixture copy ${name}"
done
/bin/chmod 0755 "${FIXTURE_REVIEW}/controller.sh" ||
  fail 'fixture controller source authority mode'
/bin/cp -- "${PROVISIONER}" "${FIXTURE_REPOSITORY}/scripts/provision-ubuntu-test-host.sh" ||
  fail 'fixture copy provisioner'
printf 'fixture=%s\n' "${TEST_ROOT##*/}" >"${FIXTURE_REPOSITORY}/fixture-token.v1" || fail 'fixture token'
/usr/bin/git -C "${FIXTURE_REPOSITORY}" add -- scripts fixture-token.v1 || fail 'fixture Git add'
/usr/bin/git -C "${FIXTURE_REPOSITORY}" commit -m 'Hermetic binding fixture' || fail 'fixture Git commit'
FIXTURE_COMMIT="$(/usr/bin/git -C "${FIXTURE_REPOSITORY}" rev-parse HEAD)" || fail 'fixture commit'
FIXTURE_BRANCH="$(/usr/bin/git -C "${FIXTURE_REPOSITORY}" symbolic-ref --short HEAD)" || fail 'fixture branch'
FIXTURE_REF="refs/heads/${FIXTURE_BRANCH}"
BOUND_OUTPUT="/private/tmp/wg-mix-b82-v6-c8e41d73-4f2a9b61-${FIXTURE_COMMIT:0:12}"

BIND_ARGS=(
  --repository "${FIXTURE_REPOSITORY}"
  --source-ref "${FIXTURE_REF}"
  --commit "${FIXTURE_COMMIT}"
  --wg-state bound
  --wg-interface wg0
  --wg-local-address 10.200.0.1
  --wg-peer-address 10.200.0.2
  --output-dir "${BOUND_OUTPUT}"
)

BIND_PLAN="$(/bin/bash "${FIXTURE_REVIEW}/bind-final-package.sh" plan "${BIND_ARGS[@]}")" ||
  fail 'binding plan'
[[ "${BIND_PLAN}" == *'no_files_created=1 credential_read=0 network_operations=0'* ]] ||
  fail 'binding plan side-effect fence'
[[ "${BIND_PLAN}" == *'repository_shallow=false history_verification=isolated-unbundle-rev-list-fsck-v1'* ]] ||
  fail 'binding plan full-history fence'
[[ ! -e "${BOUND_OUTPUT}" && ! -L "${BOUND_OUTPUT}" ]] || fail 'binding plan created output'
BIND_RESULT="$(/bin/bash "${FIXTURE_REVIEW}/bind-final-package.sh" bind "${BIND_ARGS[@]}")" ||
  fail 'package binding'
[[ "${BIND_RESULT}" == *'B82_V6_BIND_COMPLETE'* ]] || fail 'binding completion marker'
BOUND_MANIFEST="${BOUND_OUTPUT}/package-manifest.v1"
BOUND_MANIFEST_SHA="$(sha256_file "${BOUND_MANIFEST}")" || fail 'manifest digest'
CONTROLLER_READER_ONLY="${TEST_ROOT}/controller.manifest-reader.sh"
STAGER_READER_ONLY="${TEST_ROOT}/stager.manifest-reader.sh"
for source_only_spec in \
  "${FIXTURE_REVIEW}/controller.sh:${CONTROLLER_READER_ONLY}" \
  "${FIXTURE_REVIEW}/prepare-stage-root.sh:${STAGER_READER_ONLY}"; do
  source_script="${source_only_spec%%:*}"
  source_only="${source_only_spec#*:}"
  [[ "$(/usr/bin/tail -n 1 -- "${source_script}")" == 'main "$@"' ]] ||
    fail "manifest reader source has an unexpected dispatch tail: ${source_script}"
  /usr/bin/sed '$d' "${source_script}" >"${source_only}" ||
    fail "manifest reader source-only fixture: ${source_script}"
  /bin/chmod 0600 "${source_only}" || fail 'manifest reader source-only fixture mode'
done
MANIFEST_TAIL_NEWLINE="${TEST_ROOT}/package-manifest.trailing-newline.v1"
MANIFEST_TAIL_NO_NEWLINE="${TEST_ROOT}/package-manifest.trailing-no-newline.v1"
MANIFEST_EXTRA_FINAL_LF="${TEST_ROOT}/package-manifest.extra-final-lf.v1"
MANIFEST_NUL_IN_FIELD="${TEST_ROOT}/package-manifest.nul-in-field.v1"
MANIFEST_FINAL_LF_NUL="${TEST_ROOT}/package-manifest.final-lf-nul.v1"
/bin/cp -- "${BOUND_MANIFEST}" "${MANIFEST_TAIL_NEWLINE}" || fail 'newline tail manifest copy'
printf 'unexpected_tail\tfixture-extra\n' >>"${MANIFEST_TAIL_NEWLINE}" ||
  fail 'newline tail manifest append'
/bin/cp -- "${BOUND_MANIFEST}" "${MANIFEST_TAIL_NO_NEWLINE}" ||
  fail 'unterminated tail manifest copy'
printf 'unexpected_tail\tfixture-extra' >>"${MANIFEST_TAIL_NO_NEWLINE}" ||
  fail 'unterminated tail manifest append'
/bin/cp -- "${BOUND_MANIFEST}" "${MANIFEST_EXTRA_FINAL_LF}" ||
  fail 'extra final LF manifest copy'
printf '\n' >>"${MANIFEST_EXTRA_FINAL_LF}" || fail 'extra final LF manifest append'
/usr/bin/python3 -B -I -c '
import pathlib
import sys

source, field_target, tail_target = map(pathlib.Path, sys.argv[1:])
payload = source.read_bytes()
needle = b"format\twg-mix-ebpf-b82-v6-package-v4\n"
if payload.count(needle) != 1:
    raise SystemExit(65)
field_target.write_bytes(payload.replace(needle, needle.replace(b"wg-mix", b"wg\0mix"), 1))
tail_target.write_bytes(payload + b"\0")
' "${BOUND_MANIFEST}" "${MANIFEST_NUL_IN_FIELD}" "${MANIFEST_FINAL_LF_NUL}" ||
  fail 'NUL manifest fixture creation'
/bin/chmod 0600 "${MANIFEST_NUL_IN_FIELD}" "${MANIFEST_FINAL_LF_NUL}" ||
  fail 'NUL manifest fixture mode'
for reader_spec in \
  "controller:${CONTROLLER_READER_ONLY}" \
  "stager:${STAGER_READER_ONLY}"; do
  reader_name="${reader_spec%%:*}"
  reader_script="${reader_spec#*:}"
  for manifest_spec in \
    "newline-tail:${MANIFEST_TAIL_NEWLINE}" \
    "unterminated-tail:${MANIFEST_TAIL_NO_NEWLINE}" \
    "extra-final-lf:${MANIFEST_EXTRA_FINAL_LF}" \
    "nul-in-field:${MANIFEST_NUL_IN_FIELD}" \
    "final-lf-nul:${MANIFEST_FINAL_LF_NUL}"; do
    manifest_name="${manifest_spec%%:*}"
    manifest_path="${manifest_spec#*:}"
    # The child shell expands these positional parameters, not this harness.
    # shellcheck disable=SC2016
    expect_exact_rc "${reader_name}-${manifest_name}" 65 /bin/bash -c '
      source "$1" || exit $?
      MANIFEST="$2"
      load_manifest
    ' manifest-reader "${reader_script}" "${manifest_path}"
  done
  /bin/bash -c '
    source "$1" || exit $?
    exec 8<"$2" || exit $?
    require_manifest_fd_without_nul 8 || exit $?
    IFS=$'"'"'\t'"'"' read -r key value <&8 || exit $?
    [[ "${key}" == format && "${value}" == wg-mix-ebpf-b82-v6-package-v4 ]]
  ' manifest-pread-offset-zero "${reader_script}" "${BOUND_MANIFEST}" ||
    fail "${reader_name} NUL precheck advanced the manifest FD"
  # The child shell expands these positional parameters, not this harness.
  # shellcheck disable=SC2016
  expect_exact_rc "${reader_name}-nul-pread-error" 66 /bin/bash -c '
    source "$1" || exit $?
    : >"$2" || exit $?
    exec 9>"$2" || exit $?
    require_manifest_fd_without_nul 9
  ' manifest-pread-error "${reader_script}" "${TEST_ROOT}/${reader_name}.write-only-fd"
done
/bin/bash "${FIXTURE_REVIEW}/test-hermetic-fresh-verifier-gate.sh" \
  "${FIXTURE_REVIEW}/root-fresh-verifier-gate.sh" \
  "${FIXTURE_REVIEW}/checksum-module-lease.sh" \
  "${FIXTURE_REVIEW}/test_fresh_verifier_gate_static.py" "${BOUND_MANIFEST}" ||
  fail 'fresh verifier exact package-v4 reader target'
for manifest_spec in \
  "newline-tail:${MANIFEST_TAIL_NEWLINE}" \
  "unterminated-tail:${MANIFEST_TAIL_NO_NEWLINE}" \
  "extra-final-lf:${MANIFEST_EXTRA_FINAL_LF}" \
  "nul-in-field:${MANIFEST_NUL_IN_FIELD}" \
  "final-lf-nul:${MANIFEST_FINAL_LF_NUL}"; do
  manifest_name="${manifest_spec%%:*}"
  manifest_path="${manifest_spec#*:}"
  manifest_sha="$(sha256_file "${manifest_path}")" || fail 'malformed manifest digest'
  expect_exact_rc "transport-${manifest_name}" 66 /usr/bin/expect \
    "${FIXTURE_REVIEW}/locked-transport.exp" \
    --manifest "${manifest_path}" --manifest-sha256 "${manifest_sha}" \
    --credential-path "${CREDENTIAL_PATH}" --action plan --operation identity-hostname \
    --approved-plan-sha256 none
done

TRANSPORT_HARNESS="${TEST_ROOT}/transport-transaction-harness.exp"
/bin/cat >"${TRANSPORT_HARNESS}" <<'EXPECT_HARNESS'
#!/usr/bin/expect -f

if {[llength $argv] < 2} {
    puts stderr "HARNESS_FAIL arguments"
    exit 90
}
set transport [file normalize [lindex $argv 0]]
set mode [lindex $argv 1]
set arguments [lrange $argv 2 end]
set argv0 [file normalize [info script]]
source $transport

proc harness_die {message} {
    puts stderr "HARNESS_FAIL $message"
    exit 90
}

proc install_no_io_fences {} {
    set ::credential_reads 0
    set ::spawns 0
    rename read_execute_credential transport_original_read_execute_credential
    proc read_execute_credential {path} {
        incr ::credential_reads
        return fixture-password
    }
    rename execute_operation_spec transport_original_execute_operation_spec
    proc execute_operation_spec {operation operation_spec password} {
        incr ::spawns
        return [list ok 0 "" none]
    }
}

proc expected_prepare_sequence {} {
    set expected {
        identity-hostname identity-kernel identity-machine identity-netns identity-interface
        stale-package-root stale-bootstrap-root stale-alternate-bootstrap-root
        stale-stage-root stale-fresh-root stale-standalone-root
        stale-routed-evidence-root stale-realnic-run-roots
        stale-realnic-interface-leases stale-veth-wgc8e41a stale-veth-wgc8e41b
        stale-veth-wga19f7a stale-veth-wga19f7b stale-veth-wg5b8d3a
        stale-veth-wg5b8d3b stale-pin-fresh stale-pin-standalone
        stale-pin-legacy-tcx stale-pin-legacy-nic-original
        stale-pin-legacy-nic-all-on stale-pin-legacy-nic-all-off
        stale-pin-legacy-nic-tx-path stale-pin-legacy-nic-rx-path
        stale-pin-legacy-nic-mtu1492 stale-pin-legacy-nic-mtu1500
        stale-pin-legacy-nic-soak stale-checksum-module
        stale-checksum-module-btf stale-checksum-module-lock
        stale-physical-interface-lock package-parent-stat
        lineage:lineage-exists-user-intake
        lineage:lineage-exists-home-qroot
        lineage:lineage-exists-run-qroot
        package-mkdir
    }
    foreach name {
        source-4f2a9b61.bundle package-manifest.v1 bind-final-package.sh
        controller.sh prepare-stage-root.sh provision-ubuntu-test-host.sh
        root-matrix-n-r.sh check-realhost-iperf.py test-hermetic-matrix.sh
        test_matrix_static.py checksum-module-lease.sh root-fresh-verifier-gate.sh
        test-hermetic-fresh-verifier-gate.sh test_fresh_verifier_gate_static.py
        realnic_acceptance.py test_realnic_acceptance.py
        test_realnic_acceptance_static.py
    } {
        lappend expected "scp-$name" "verify-sha-$name" "verify-stat-$name"
    }
    lappend expected \
        bootstrap-absent bootstrap-not-symlink bootstrap-create \
        bootstrap-root-readlink bootstrap-root-stat \
        bootstrap-install-provisioner bootstrap-install-stager \
        bootstrap-provisioner-readlink bootstrap-provisioner-stat \
        bootstrap-provisioner-sha provision-check
    return $expected
}

switch -- $mode {
    precredential {
        if {[llength $arguments] != 4} { harness_die "precredential-arguments" }
        lassign $arguments manifest manifest_sha operation approved_sha
        rename fail transport_original_fail
        proc fail {message code} {
            return -code error -errorcode [list B82FAIL $code] $message
        }
        install_no_io_fences
        rename exit harness_real_exit
        proc exit {{code 0}} {
            return -code error -errorcode [list TRANSPORT_EXIT $code] "exit-$code"
        }
        set invocation [list \
            --manifest $manifest --manifest-sha256 $manifest_sha \
            --credential-path /Users/siyixuan/codes-2/wg-mix-ebpf/credientials/192.168.10.82 \
            --action execute --operation $operation --approved-plan-sha256 $approved_sha]
        set caught [catch {transport_main $invocation} message options]
        if {!$caught} { harness_die "transport-main-returned" }
        set result_rc 99
        set result_kind unexpected
        if {[dict exists $options -errorcode]} {
            set errorcode [dict get $options -errorcode]
            if {[lindex $errorcode 0] eq "B82FAIL"} {
                set result_kind stop
                set result_rc [lindex $errorcode 1]
            } elseif {[lindex $errorcode 0] eq "TRANSPORT_EXIT"} {
                set result_kind exit
                set result_rc [lindex $errorcode 1]
            }
        }
        puts "HARNESS_PRECREDENTIAL kind=$result_kind rc=$result_rc reason=$message credential_reads=$::credential_reads spawns=$::spawns"
        harness_real_exit 0
    }
    verify {
        if {[llength $arguments] != 4} { harness_die "verify-arguments" }
        lassign $arguments manifest manifest_sha operation approved_sha
        set values [load_manifest $manifest $manifest_sha]
        validate_manifest_values $values
        validate_self $values
        install_no_io_fences
        require_transaction_local_authority $values $manifest_sha $operation $approved_sha
        puts "HARNESS_VERIFY_ONLY operation=$operation credential_reads=$::credential_reads spawns=$::spawns result=PASS"
    }
    prepare-sequence {
        set ::observed {}
        rename require_manifest_authority transport_original_require_manifest_authority
        proc require_manifest_authority args { return }
        rename execute_operation_spec transport_original_execute_operation_spec
        proc execute_operation_spec {operation operation_spec password} {
            lappend ::observed "lineage:$operation"
            return [list ok 0 "" none]
        }
        rename execute_primitive transport_original_execute_primitive
        proc execute_primitive {values manifest_sha operation approved_sha password} {
            lappend ::observed $operation
            set policy [expr {$operation eq "provision-check" ? "initial" : "none"}]
            return [list ok 0 "" $policy]
        }
        set values [dict create target_user fixture target_host 127.0.0.1]
        set state [execute_prepare_transaction $values [string repeat a 64] fixture-password]
        set expected [expected_prepare_sequence]
        if {$state ne "AWAIT_APPLY" || $::observed ne $expected} {
            harness_die "prepare-sequence observed=$::observed expected=$expected state=$state"
        }
        puts "HARNESS_PREPARE_SEQUENCE steps=[llength $::observed] state=$state result=PASS"
    }
    prewrite-cuts {
        set expected [expected_prepare_sequence]
        set prewrite [lrange $expected 0 35]
        if {[llength $prewrite] != 36 ||
            [lindex $expected 36] ne "lineage:lineage-exists-user-intake"} {
            harness_die "prewrite-cardinality"
        }
        rename execute_primitive transport_original_execute_primitive
        rename exit harness_real_exit
        proc exit {{code 0}} {
            return -code error -errorcode [list TRANSACTION_EXIT $code] "exit-$code"
        }
        set child_nonzero 0
        set child_signal 0
        for {set cut 0} {$cut < [llength $prewrite]} {incr cut} {
            set ::cut $cut
            set ::observed {}
            set ::mutation_trace {}
            proc execute_primitive {values manifest_sha operation approved_sha password} {
                lappend ::observed $operation
                if {$operation eq "package-mkdir" || [string match "scp-*" $operation] ||
                    $operation in {bootstrap-create bootstrap-install-provisioner
                        bootstrap-install-stager provision-apply stage-snapshot stage-run
                        stage-realnic-plan-snapshot realnic-run realnic-restore}} {
                    lappend ::mutation_trace $operation
                }
                if {[llength $::observed] - 1 == $::cut} {
                    if {$::cut % 2 == 0} {
                        return [list child-failure 73 "" none]
                    }
                    fail "child-wait-status" 78
                }
                return [list ok 0 "" none]
            }
            set caught [catch {
                execute_prepare_transaction {} [string repeat a 64] fixture-password
            } message options]
            set expected_rc [expr {$cut % 2 == 0 ? 73 : 78}]
            set expected_prefix [lrange $prewrite 0 $cut]
            if {!$caught || [dict get $options -errorcode] ne
                    [list TRANSACTION_EXIT $expected_rc] ||
                $::observed ne $expected_prefix || [llength $::mutation_trace] != 0} {
                harness_die "prewrite-cut=$cut rc=$expected_rc observed=$::observed mutations=$::mutation_trace"
            }
            if {$expected_rc == 73} { incr child_nonzero } else { incr child_signal }
        }
        puts "HARNESS_PREWRITE_CUTS cuts=36 child_nonzero=$child_nonzero child_signal=$child_signal mutation_trace=0 result=PASS"
        harness_real_exit 0
    }
    mkdir-failure {
        set ::observed {}
        rename require_manifest_authority transport_original_require_manifest_authority
        proc require_manifest_authority args { return }
        rename execute_operation_spec transport_original_execute_operation_spec
        proc execute_operation_spec {operation operation_spec password} {
            lappend ::observed "lineage:$operation"
            return [list ok 0 "" none]
        }
        rename execute_primitive transport_original_execute_primitive
        proc execute_primitive {values manifest_sha operation approved_sha password} {
            lappend ::observed $operation
            if {$operation eq "package-mkdir"} {
                return [list child-failure 73 "" none]
            }
            return [list ok 0 "" none]
        }
        rename exit harness_real_exit
        proc exit {{code 0}} {
            return -code error -errorcode [list TRANSACTION_EXIT $code] "exit-$code"
        }
        set caught [catch {
            execute_prepare_transaction \
                [dict create target_user fixture target_host 127.0.0.1] \
                [string repeat a 64] fixture-password
        } message options]
        set expected [expected_prepare_sequence]
        set mkdir_index [lsearch -exact $expected package-mkdir]
        set expected [lrange $expected 0 $mkdir_index]
        if {!$caught || [dict get $options -errorcode] ne {TRANSACTION_EXIT 73} ||
            $::observed ne $expected || [lsearch -glob $::observed {scp-*}] >= 0} {
            harness_die "mkdir-failure observed=$::observed errorcode=[dict get $options -errorcode]"
        }
        puts "HARNESS_MKDIR_FAILURE rc=73 steps=[llength $::observed] scp=0 result=PASS"
        harness_real_exit 0
    }
    child-nonzero {
        set spec [list local [list /usr/bin/python3 -B -I -c {raise SystemExit(23)}] 0 none 10]
        set result [execute_operation_spec child-nonzero $spec ""]
        if {[lrange $result 0 1] ne {child-failure 23}} {
            harness_die "child-nonzero-result=$result"
        }
        puts "HARNESS_CHILD_NONZERO rc=23 result=PASS"
    }
    child-signal {
        set spec [list local [list /usr/bin/python3 -B -I -c \
            {import os, signal; os.kill(os.getpid(), signal.SIGTERM)}] 0 none 10]
        execute_operation_spec child-signal $spec ""
        harness_die "child-signal-returned"
    }
    scp-build {
        if {[llength $arguments] != 3} { harness_die "scp-build-arguments" }
        lassign $arguments local_package expected_sha expected_result
        set values [dict create \
            target_user fixture target_host 127.0.0.1 \
            remote_package_dir /fixture/remote-package \
            local_package_dir $local_package \
            controller_sh_sha256 $expected_sha]
        set caught [catch {
            build_operation $values [string repeat a 64] scp-controller.sh none
        } result]
        if {$expected_result eq "accept"} {
            if {$caught || [lindex $result 0] ne "scp"} {
                harness_die "scp-build-accept caught=$caught result=$result"
            }
        } elseif {$expected_result eq "reject"} {
            if {!$caught || $result ne "scp-local-file"} {
                harness_die "scp-build-reject caught=$caught result=$result"
            }
        } else {
            harness_die "scp-build-expectation"
        }
        puts "HARNESS_SCP_BUILD expectation=$expected_result result=PASS"
    }
    lineage-existence {
        set ::credential_reads 0
        set ::lineage_payload ""
        set ::lineage_failure none
        rename fail transport_original_fail
        proc fail {message code} {
            return -code error -errorcode [list B82FAIL $code] $message
        }
        rename require_manifest_authority transport_original_require_manifest_authority
        proc require_manifest_authority args { return }
        rename read_execute_credential transport_original_read_execute_credential
        proc read_execute_credential {path} {
            incr ::credential_reads
            return fixture-password
        }
        rename execute_operation_spec transport_original_execute_operation_spec
        proc execute_operation_spec {operation operation_spec password} {
            if {$::lineage_failure eq "child-nonzero"} {
                return [list child-failure 73 "" none]
            }
            if {$::lineage_failure eq "signal"} {
                fail "child-wait-status" 78
            }
            return [list ok 0 $::lineage_payload none]
        }
        set values [dict create target_user fixture target_host 127.0.0.1]
        set password [read_execute_credential /fixture/credential]
        set classified_paths 0
        foreach case [list \
            [list lineage-exists-user-intake \
                /home/siyixuan/wg-mix-ebpf-test/retire-prestage-c8e41d73-2c690050ae1d-r1.intake] \
            [list lineage-exists-home-qroot \
                /home/.wg-mix-ebpf-retirement-c8e41d73-2c690050ae1d-r1] \
            [list lineage-exists-run-qroot \
                /run/wg-mix-ebpf-retirement-c8e41d73-2c690050ae1d-r1] \
            [list lineage-exists-receipt-pending \
                /run/wg-mix-ebpf-retirement-c8e41d73-2c690050ae1d-r1/retirement-complete.v1.pending]] {
            lassign $case operation fixed_path
            set ::lineage_payload ""
            set absent [retirement_lineage_path_exists $values \
                [string repeat a 64] $operation $password]
            set ::lineage_payload $fixed_path
            set present [retirement_lineage_path_exists $values \
                [string repeat a 64] $operation $password]
            if {$absent != 0 || $present != 1} {
                harness_die "lineage-existence operation=$operation absent=$absent present=$present"
            }
            incr classified_paths
        }
        set stopped {}
        foreach failure {child-nonzero signal malformed} {
            set ::lineage_failure $failure
            if {$failure eq "malformed"} {
                set ::lineage_failure none
                set ::lineage_payload /unexpected/lineage/path
            }
            set caught [catch {
                retirement_lineage_path_exists $values [string repeat a 64] \
                    lineage-exists-home-qroot $password
            } message options]
            if {!$caught || ![dict exists $options -errorcode] ||
                [dict get $options -errorcode] ne {B82FAIL 78}} {
                harness_die "lineage-existence failure=$failure message=$message options=$options"
            }
            lappend stopped $failure
        }
        if {$classified_paths != 4 || $::credential_reads != 1 ||
            $stopped ne {child-nonzero signal malformed}} {
            harness_die "lineage-existence paths=$classified_paths stopped=$stopped credential_reads=$::credential_reads"
        }
        puts "HARNESS_LINEAGE_EXISTENCE paths=4 empty=absent exact=present child_nonzero=STOP signal=STOP malformed=STOP credential_reads=1 result=PASS"
    }
    lineage-gate {
        set ::credential_reads 0
        set ::lineage_operations {}
        set ::lineage_mutation_spawns 0
        set ::lineage_scenario fresh
        set ::lineage_fail_operation none
        set ::lineage_fail_kind none
        set ::lineage_presence_calls [dict create]
        set ::test_user_intake \
            /home/siyixuan/wg-mix-ebpf-test/retire-prestage-c8e41d73-2c690050ae1d-r1.intake
        set ::test_home_qroot \
            /home/.wg-mix-ebpf-retirement-c8e41d73-2c690050ae1d-r1
        set ::test_auth_root "$::test_home_qroot/authority"
        set ::test_run_qroot \
            /run/wg-mix-ebpf-retirement-c8e41d73-2c690050ae1d-r1
        set ::test_q_intake "$::test_home_qroot/intake"
        set ::test_q_package "$::test_home_qroot/package"
        set ::test_q_bootstrap "$::test_run_qroot/bootstrap"
        set ::test_receipt_pending \
            "$::test_run_qroot/retirement-complete.v1.pending"
        set ::test_receipt_final \
            "$::test_run_qroot/retirement-complete.v1"
        rename fail transport_original_fail
        proc fail {message code} {
            return -code error -errorcode [list B82FAIL $code] $message
        }
        rename require_manifest_authority transport_original_require_manifest_authority
        proc require_manifest_authority args { return }
        rename read_execute_credential transport_original_read_execute_credential
        proc read_execute_credential {path} {
            incr ::credential_reads
            return fixture-password
        }
        proc lineage_test_terminal_operations {} {
            return {
                lineage-home-readlink lineage-home-stat lineage-home-entries
                lineage-auth-readlink lineage-auth-stat lineage-auth-entries
                lineage-run-readlink lineage-run-stat lineage-run-entries
                lineage-auth-manifest-pending-stat
                lineage-auth-manifest-pending-sha
                lineage-auth-manifest-stat lineage-auth-manifest-sha
                lineage-auth-manifest-pair
                lineage-auth-self-pending-stat lineage-auth-self-pending-sha
                lineage-auth-self-stat lineage-auth-self-sha
                lineage-auth-self-pair
                lineage-q-intake-readlink lineage-q-intake-stat
                lineage-q-intake-entries lineage-q-intake-manifest-stat
                lineage-q-intake-manifest-sha lineage-q-intake-self-stat
                lineage-q-intake-self-sha
                lineage-q-package-readlink lineage-q-package-stat
                lineage-q-package-entries
                lineage-q-bootstrap-readlink lineage-q-bootstrap-stat
                lineage-q-bootstrap-entries
                lineage-lock-stat lineage-receipt-stat lineage-receipt-sha
            }
        }
        proc lineage_test_package_entries {} {
            set entries {}
            foreach name {
                source-4f2a9b61.bundle package-manifest.v1
                bind-final-package.sh controller.sh prepare-stage-root.sh
                provision-ubuntu-test-host.sh root-matrix-n-r.sh
                check-realhost-iperf.py test-hermetic-matrix.sh
                test_matrix_static.py checksum-module-lease.sh
                root-fresh-verifier-gate.sh
                test-hermetic-fresh-verifier-gate.sh
                test_fresh_verifier_gate_static.py realnic_acceptance.py
                test_realnic_acceptance.py test_realnic_acceptance_static.py
            } {
                lappend entries "$name\tf"
            }
            return [join $entries "\n"]
        }
        proc lineage_test_payload {operation} {
            set manifest_sha \
                c4532671304d30755b1c42bb55f82186d96df3f6c84af73078ca16c3fddfe4e6
            set helper_sha \
                a4a1c89dcd9f087b79149f52a01346ed6db5c209ad4985bdbb8c9132276c0077
            set receipt_sha \
                4c3e9bfd3d4e64f6626abaa43e20cf5e4df6b193395cee6a39953b1c4da7d188
            switch -- $operation {
                lineage-home-readlink { return $::test_home_qroot }
                lineage-auth-readlink { return $::test_auth_root }
                lineage-run-readlink { return $::test_run_qroot }
                lineage-q-intake-readlink { return $::test_q_intake }
                lineage-q-package-readlink { return $::test_q_package }
                lineage-q-bootstrap-readlink { return $::test_q_bootstrap }
                lineage-home-stat - lineage-auth-stat - lineage-run-stat -
                lineage-q-bootstrap-stat {
                    return root:root:700:directory
                }
                lineage-q-intake-stat - lineage-q-package-stat {
                    return siyixuan:siyixuan:700:directory
                }
                lineage-home-entries {
                    return "authority\td\nintake\td\npackage\td"
                }
                lineage-auth-entries {
                    return "package-manifest.v1.pending\tf\npackage-manifest.v1\tf\nprepare-stage-root.sh.pending\tf\nprepare-stage-root.sh\tf"
                }
                lineage-run-entries {
                    return "bootstrap\td\nretirement.v1.lock\tf\nretirement-complete.v1\tf"
                }
                lineage-q-intake-entries {
                    return "package-manifest.v1\tf\nprepare-stage-root.sh\tf"
                }
                lineage-q-package-entries {
                    return [lineage_test_package_entries]
                }
                lineage-q-bootstrap-entries {
                    return "prepare-stage-root.sh\tf\nprovision-ubuntu-test-host.sh\tf"
                }
                lineage-auth-manifest-pending-stat -
                lineage-auth-manifest-stat {
                    return "root:root:600:2:regular file"
                }
                lineage-auth-self-pending-stat - lineage-auth-self-stat {
                    return "root:root:700:2:regular file"
                }
                lineage-auth-manifest-pending-sha {
                    return "$manifest_sha  $::test_auth_root/package-manifest.v1.pending"
                }
                lineage-auth-manifest-sha {
                    return "$manifest_sha  $::test_auth_root/package-manifest.v1"
                }
                lineage-auth-self-pending-sha {
                    return "$helper_sha  $::test_auth_root/prepare-stage-root.sh.pending"
                }
                lineage-auth-self-sha {
                    return "$helper_sha  $::test_auth_root/prepare-stage-root.sh"
                }
                lineage-auth-manifest-pair - lineage-auth-self-pair {
                    return "71:113\n71:113"
                }
                lineage-q-intake-manifest-stat -
                lineage-q-intake-self-stat {
                    return "siyixuan:siyixuan:600:1:regular file"
                }
                lineage-q-intake-manifest-sha {
                    return "$manifest_sha  $::test_q_intake/package-manifest.v1"
                }
                lineage-q-intake-self-sha {
                    return "$helper_sha  $::test_q_intake/prepare-stage-root.sh"
                }
                lineage-lock-stat - lineage-receipt-stat {
                    return "root:root:600:1:regular file"
                }
                lineage-receipt-sha {
                    return "$receipt_sha  $::test_receipt_final"
                }
                lineage-retained-helper-verify {
                    return "B82_V6_RETIREMENT_VERIFIED state=T namespace_writes=0 same_boot=1 receipt=$::test_receipt_final"
                }
                default { harness_die "lineage-test-payload-$operation" }
            }
        }
        proc lineage_test_assertion {operation} {
            set manifest_sha \
                c4532671304d30755b1c42bb55f82186d96df3f6c84af73078ca16c3fddfe4e6
            set helper_sha \
                a4a1c89dcd9f087b79149f52a01346ed6db5c209ad4985bdbb8c9132276c0077
            set receipt_sha \
                4c3e9bfd3d4e64f6626abaa43e20cf5e4df6b193395cee6a39953b1c4da7d188
            switch -- $operation {
                lineage-exists-user-intake - lineage-exists-home-qroot -
                lineage-exists-run-qroot -
                lineage-exists-receipt-pending { return none }
                lineage-home-readlink {
                    return "exact:$::test_home_qroot"
                }
                lineage-auth-readlink {
                    return "exact:$::test_auth_root"
                }
                lineage-run-readlink {
                    return "exact:$::test_run_qroot"
                }
                lineage-q-intake-readlink {
                    return "exact:$::test_q_intake"
                }
                lineage-q-package-readlink {
                    return "exact:$::test_q_package"
                }
                lineage-q-bootstrap-readlink {
                    return "exact:$::test_q_bootstrap"
                }
                lineage-home-stat - lineage-auth-stat - lineage-run-stat -
                lineage-q-bootstrap-stat {
                    return exact:root:root:700:directory
                }
                lineage-q-intake-stat - lineage-q-package-stat {
                    return exact:siyixuan:siyixuan:700:directory
                }
                lineage-home-entries {
                    return [list exact-entry-set "authority\td" \
                        "intake\td" "package\td"]
                }
                lineage-auth-entries {
                    return [list exact-entry-set \
                        "package-manifest.v1.pending\tf" \
                        "package-manifest.v1\tf" \
                        "prepare-stage-root.sh.pending\tf" \
                        "prepare-stage-root.sh\tf"]
                }
                lineage-run-entries {
                    return [list exact-entry-set "bootstrap\td" \
                        "retirement.v1.lock\tf" \
                        "retirement-complete.v1\tf"]
                }
                lineage-q-intake-entries {
                    return [list exact-entry-set \
                        "package-manifest.v1\tf" \
                        "prepare-stage-root.sh\tf"]
                }
                lineage-q-package-entries {
                    set assertion [list exact-entry-set]
                    foreach line [split [lineage_test_package_entries] "\n"] {
                        lappend assertion $line
                    }
                    return $assertion
                }
                lineage-q-bootstrap-entries {
                    return [list exact-entry-set \
                        "prepare-stage-root.sh\tf" \
                        "provision-ubuntu-test-host.sh\tf"]
                }
                lineage-auth-manifest-pending-stat -
                lineage-auth-manifest-stat {
                    return "exact:root:root:600:2:regular file"
                }
                lineage-auth-self-pending-stat - lineage-auth-self-stat {
                    return "exact:root:root:700:2:regular file"
                }
                lineage-auth-manifest-pending-sha {
                    return "exact:$manifest_sha  $::test_auth_root/package-manifest.v1.pending"
                }
                lineage-auth-manifest-sha {
                    return "exact:$manifest_sha  $::test_auth_root/package-manifest.v1"
                }
                lineage-auth-self-pending-sha {
                    return "exact:$helper_sha  $::test_auth_root/prepare-stage-root.sh.pending"
                }
                lineage-auth-self-sha {
                    return "exact:$helper_sha  $::test_auth_root/prepare-stage-root.sh"
                }
                lineage-auth-manifest-pair - lineage-auth-self-pair {
                    return same-two-inodes
                }
                lineage-q-intake-manifest-stat -
                lineage-q-intake-self-stat {
                    return "exact:siyixuan:siyixuan:600:1:regular file"
                }
                lineage-q-intake-manifest-sha {
                    return "exact:$manifest_sha  $::test_q_intake/package-manifest.v1"
                }
                lineage-q-intake-self-sha {
                    return "exact:$helper_sha  $::test_q_intake/prepare-stage-root.sh"
                }
                lineage-lock-stat - lineage-receipt-stat {
                    return "exact:root:root:600:1:regular file"
                }
                lineage-receipt-sha {
                    return "exact:$receipt_sha  $::test_receipt_final"
                }
                lineage-retained-helper-verify {
                    return "exact:B82_V6_RETIREMENT_VERIFIED state=T namespace_writes=0 same_boot=1 receipt=$::test_receipt_final"
                }
                default { harness_die "lineage-test-assertion-$operation" }
            }
        }
        proc lineage_test_ssh_prefix {} {
            return {
                /usr/bin/ssh -F /dev/null -tt
                -o BatchMode=no
                -o PasswordAuthentication=yes
                -o PreferredAuthentications=password
                -o PubkeyAuthentication=no
                -o KbdInteractiveAuthentication=no
                -o IdentitiesOnly=yes
                -o NumberOfPasswordPrompts=1
                -o StrictHostKeyChecking=yes
                -o CheckHostIP=yes
                -o UpdateHostKeys=no
                -o VerifyHostKeyDNS=no
                -o ConnectTimeout=15
                -o ConnectionAttempts=1
                -o ServerAliveInterval=15
                -o ServerAliveCountMax=2
                -o ClearAllForwardings=yes
                -o ForwardAgent=no
                -o ForwardX11=no
                -o PermitLocalCommand=no
                -o LocalCommand=none
                -o ProxyCommand=none
                -o ControlMaster=no
                -o ControlPath=none
                -o ControlPersist=no
                -o CanonicalizeHostname=no
                -o Compression=no
                -o LogLevel=ERROR
                -- fixture@127.0.0.1
            }
        }
        proc lineage_test_expected_spawn_argv {operation} {
            set env_prefix {
                /usr/bin/sudo -- /usr/bin/env -i
                PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
            }
            if {[string match "lineage-exists-*" $operation]} {
                switch -- $operation {
                    lineage-exists-user-intake {
                        set parent /home/siyixuan/wg-mix-ebpf-test
                        set leaf \
                            retire-prestage-c8e41d73-2c690050ae1d-r1.intake
                    }
                    lineage-exists-home-qroot {
                        set parent /home
                        set leaf \
                            .wg-mix-ebpf-retirement-c8e41d73-2c690050ae1d-r1
                    }
                    lineage-exists-run-qroot {
                        set parent /run
                        set leaf \
                            wg-mix-ebpf-retirement-c8e41d73-2c690050ae1d-r1
                    }
                    lineage-exists-receipt-pending {
                        set parent $::test_run_qroot
                        set leaf retirement-complete.v1.pending
                    }
                    default { harness_die "lineage-test-existence-argv-$operation" }
                }
                set remote [concat $env_prefix [list /usr/bin/find $parent \
                    -xdev -mindepth 1 -maxdepth 1 -name $leaf -print]]
                return [concat [lineage_test_ssh_prefix] $remote]
            }
            switch -- $operation {
                lineage-home-readlink { set fixed_path $::test_home_qroot }
                lineage-auth-readlink { set fixed_path $::test_auth_root }
                lineage-run-readlink { set fixed_path $::test_run_qroot }
                lineage-q-intake-readlink { set fixed_path $::test_q_intake }
                lineage-q-package-readlink { set fixed_path $::test_q_package }
                lineage-q-bootstrap-readlink {
                    set fixed_path $::test_q_bootstrap
                }
                default { set fixed_path "" }
            }
            if {$fixed_path ne ""} {
                set remote [concat $env_prefix \
                    [list /usr/bin/readlink -e -- $fixed_path]]
                return [concat [lineage_test_ssh_prefix] $remote]
            }
            switch -- $operation {
                lineage-home-stat { set fixed_path $::test_home_qroot }
                lineage-auth-stat { set fixed_path $::test_auth_root }
                lineage-run-stat { set fixed_path $::test_run_qroot }
                lineage-q-intake-stat { set fixed_path $::test_q_intake }
                lineage-q-package-stat { set fixed_path $::test_q_package }
                lineage-q-bootstrap-stat {
                    set fixed_path $::test_q_bootstrap
                }
                default { set fixed_path "" }
            }
            if {$fixed_path ne ""} {
                set remote [concat $env_prefix [list /usr/bin/stat -Lc \
                    %U:%G:%a:%F -- $fixed_path]]
                return [concat [lineage_test_ssh_prefix] $remote]
            }
            switch -- $operation {
                lineage-home-entries { set fixed_path $::test_home_qroot }
                lineage-auth-entries { set fixed_path $::test_auth_root }
                lineage-run-entries { set fixed_path $::test_run_qroot }
                lineage-q-intake-entries { set fixed_path $::test_q_intake }
                lineage-q-package-entries { set fixed_path $::test_q_package }
                lineage-q-bootstrap-entries {
                    set fixed_path $::test_q_bootstrap
                }
                default { set fixed_path "" }
            }
            if {$fixed_path ne ""} {
                set remote [concat $env_prefix [list /usr/bin/find $fixed_path \
                    -xdev -mindepth 1 -maxdepth 1 -printf {'%f\t%y\n'}]]
                return [concat [lineage_test_ssh_prefix] $remote]
            }
            switch -- $operation {
                lineage-auth-manifest-pending-stat {
                    set fixed_path "$::test_auth_root/package-manifest.v1.pending"
                    set format %U:%G:%a:%h:%F
                }
                lineage-auth-manifest-stat {
                    set fixed_path "$::test_auth_root/package-manifest.v1"
                    set format %U:%G:%a:%h:%F
                }
                lineage-auth-self-pending-stat {
                    set fixed_path "$::test_auth_root/prepare-stage-root.sh.pending"
                    set format %U:%G:%a:%h:%F
                }
                lineage-auth-self-stat {
                    set fixed_path "$::test_auth_root/prepare-stage-root.sh"
                    set format %U:%G:%a:%h:%F
                }
                lineage-q-intake-manifest-stat {
                    set fixed_path "$::test_q_intake/package-manifest.v1"
                    set format %U:%G:%a:%h:%F
                }
                lineage-q-intake-self-stat {
                    set fixed_path "$::test_q_intake/prepare-stage-root.sh"
                    set format %U:%G:%a:%h:%F
                }
                lineage-lock-stat {
                    set fixed_path "$::test_run_qroot/retirement.v1.lock"
                    set format %U:%G:%a:%h:%F
                }
                lineage-receipt-stat {
                    set fixed_path $::test_receipt_final
                    set format %U:%G:%a:%h:%F
                }
                default { set fixed_path "" }
            }
            if {$fixed_path ne ""} {
                set remote [concat $env_prefix \
                    [list /usr/bin/stat -Lc $format -- $fixed_path]]
                return [concat [lineage_test_ssh_prefix] $remote]
            }
            switch -- $operation {
                lineage-auth-manifest-pending-sha {
                    set fixed_path "$::test_auth_root/package-manifest.v1.pending"
                }
                lineage-auth-manifest-sha {
                    set fixed_path "$::test_auth_root/package-manifest.v1"
                }
                lineage-auth-self-pending-sha {
                    set fixed_path "$::test_auth_root/prepare-stage-root.sh.pending"
                }
                lineage-auth-self-sha {
                    set fixed_path "$::test_auth_root/prepare-stage-root.sh"
                }
                lineage-q-intake-manifest-sha {
                    set fixed_path "$::test_q_intake/package-manifest.v1"
                }
                lineage-q-intake-self-sha {
                    set fixed_path "$::test_q_intake/prepare-stage-root.sh"
                }
                lineage-receipt-sha { set fixed_path $::test_receipt_final }
                default { set fixed_path "" }
            }
            if {$fixed_path ne ""} {
                set remote [concat $env_prefix \
                    [list /usr/bin/sha256sum -- $fixed_path]]
                return [concat [lineage_test_ssh_prefix] $remote]
            }
            switch -- $operation {
                lineage-auth-manifest-pair {
                    set first "$::test_auth_root/package-manifest.v1.pending"
                    set second "$::test_auth_root/package-manifest.v1"
                }
                lineage-auth-self-pair {
                    set first "$::test_auth_root/prepare-stage-root.sh.pending"
                    set second "$::test_auth_root/prepare-stage-root.sh"
                }
                default { set first "" }
            }
            if {$first ne ""} {
                set remote [concat $env_prefix [list /usr/bin/stat -Lc \
                    %d:%i -- $first $second]]
                return [concat [lineage_test_ssh_prefix] $remote]
            }
            if {$operation eq "lineage-retained-helper-verify"} {
                set remote [concat $env_prefix [list /bin/bash -p \
                    "$::test_auth_root/prepare-stage-root.sh" \
                    verify-retirement --manifest \
                    "$::test_auth_root/package-manifest.v1" \
                    --manifest-sha256 \
                    c4532671304d30755b1c42bb55f82186d96df3f6c84af73078ca16c3fddfe4e6]]
                return [concat [lineage_test_ssh_prefix] $remote]
            }
            harness_die "lineage-test-spawn-argv-$operation"
        }
        proc lineage_test_presence_payload {operation} {
            dict incr ::lineage_presence_calls $operation
            set call_count [dict get $::lineage_presence_calls $operation]
            switch -- $::lineage_scenario {
                fresh {
                    return ""
                }
                terminal - terminal-cut - receipt-pending -
                recheck-user - recheck-home - recheck-run -
                recheck-receipt {
                    switch -- $operation {
                        lineage-exists-user-intake {
                            return [expr {$::lineage_scenario eq "recheck-user" &&
                                $call_count > 1 ? $::test_user_intake : ""}]
                        }
                        lineage-exists-home-qroot {
                            return [expr {$::lineage_scenario eq "recheck-home" &&
                                $call_count > 1 ? "" : $::test_home_qroot}]
                        }
                        lineage-exists-run-qroot {
                            return [expr {$::lineage_scenario eq "recheck-run" &&
                                $call_count > 1 ? "" : $::test_run_qroot}]
                        }
                        lineage-exists-receipt-pending {
                            return [expr {$::lineage_scenario eq "receipt-pending" ||
                                ($::lineage_scenario eq "recheck-receipt" &&
                                $call_count > 1) ? $::test_receipt_pending : ""}]
                        }
                    }
                }
                partial-user {
                    return [expr {$operation eq "lineage-exists-user-intake" ?
                        $::test_user_intake : ""}]
                }
                partial-home {
                    return [expr {$operation eq "lineage-exists-home-qroot" ?
                        $::test_home_qroot : ""}]
                }
                partial-run {
                    return [expr {$operation eq "lineage-exists-run-qroot" ?
                        $::test_run_qroot : ""}]
                }
                partial-user-run {
                    switch -- $operation {
                        lineage-exists-user-intake { return $::test_user_intake }
                        lineage-exists-run-qroot { return $::test_run_qroot }
                        default { return "" }
                    }
                }
                partial-user-home {
                    switch -- $operation {
                        lineage-exists-user-intake { return $::test_user_intake }
                        lineage-exists-home-qroot { return $::test_home_qroot }
                        default { return "" }
                    }
                }
                partial-all {
                    switch -- $operation {
                        lineage-exists-user-intake { return $::test_user_intake }
                        lineage-exists-home-qroot { return $::test_home_qroot }
                        lineage-exists-run-qroot { return $::test_run_qroot }
                        lineage-exists-receipt-pending { return "" }
                    }
                }
                default { harness_die "lineage-test-scenario-$::lineage_scenario" }
            }
            harness_die "lineage-test-presence-$operation"
        }
        rename execute_operation_spec transport_original_execute_operation_spec
        proc execute_operation_spec {operation operation_spec password} {
            lappend ::lineage_operations $operation
            if {[lindex $operation_spec 0] ne "ssh" ||
                [llength $operation_spec] != 5} {
                harness_die "lineage-operation-spec-$operation"
            }
            set actual_spawn_argv [lindex $operation_spec 1]
            set expected_spawn_argv \
                [lineage_test_expected_spawn_argv $operation]
            set expected_timeout [expr {$operation eq
                "lineage-retained-helper-verify" ? 2400 : 600}]
            if {[lrange $actual_spawn_argv 0 end] ne
                    [lrange $expected_spawn_argv 0 end] ||
                [lindex $operation_spec 2] != 2 ||
                [lindex $operation_spec 4] != $expected_timeout} {
                harness_die "lineage-spawn-argv operation=$operation actual=$actual_spawn_argv expected=$expected_spawn_argv prompt=[lindex $operation_spec 2] timeout=[lindex $operation_spec 4]"
            }
            if {![string match "lineage-*" $operation]} {
                incr ::lineage_mutation_spawns
            }
            foreach forbidden {
                /usr/bin/mkdir /usr/bin/install /bin/ln /bin/mv
                /bin/rm /usr/bin/touch /usr/bin/scp
            } {
                if {[lsearch -exact [lindex $operation_spec 1] $forbidden] >= 0} {
                    incr ::lineage_mutation_spawns
                    harness_die "lineage-mutation-argv operation=$operation executable=$forbidden"
                }
            }
            set actual_assertion [lindex $operation_spec 3]
            set expected_assertion [lineage_test_assertion $operation]
            if {$actual_assertion ne $expected_assertion} {
                harness_die "lineage-assertion operation=$operation actual=$actual_assertion expected=$expected_assertion"
            }
            if {$operation eq $::lineage_fail_operation} {
                switch -- $::lineage_fail_kind {
                    child-nonzero { return [list child-failure 73 "" none] }
                    signal { fail "child-wait-status" 78 }
                    missing { set payload "" }
                    malformed { set payload unexpected-lineage-output }
                    default { harness_die "lineage-failure-kind" }
                }
            } elseif {[string match "lineage-exists-*" $operation]} {
                set payload [lineage_test_presence_payload $operation]
            } else {
                set payload [lineage_test_payload $operation]
            }
            if {![string match "lineage-exists-*" $operation] &&
                [catch {assert_output $actual_assertion $payload}]} {
                fail "output-assertion" 78
            }
            return [list ok 0 $payload none]
        }
        set values [dict create target_user fixture target_host 127.0.0.1]
        set password [read_execute_credential /fixture/credential]
        set ::lineage_scenario fresh
        set ::lineage_presence_calls [dict create]
        set fresh_state [execute_retirement_lineage_gate $values \
            [string repeat a 64] $password]
        set fresh_expected {
            lineage-exists-user-intake lineage-exists-home-qroot
            lineage-exists-run-qroot
        }
        if {$fresh_state ne "FRESH" ||
            [lrange $::lineage_operations 0 end] ne
                [lrange $fresh_expected 0 end]} {
            harness_die "lineage-fresh state=$fresh_state operations=$::lineage_operations"
        }
        set ::lineage_scenario terminal
        set ::lineage_operations {}
        set ::lineage_presence_calls [dict create]
        set terminal_state [execute_retirement_lineage_gate $values \
            [string repeat a 64] $password]
        set terminal_expected [concat {
            lineage-exists-user-intake lineage-exists-home-qroot
            lineage-exists-run-qroot lineage-exists-receipt-pending
        } [lineage_test_terminal_operations] {
            lineage-exists-user-intake lineage-exists-home-qroot
            lineage-exists-run-qroot lineage-exists-receipt-pending
            lineage-retained-helper-verify
        }]
        if {$terminal_state ne "TERMINAL" ||
            [lrange $::lineage_operations 0 end] ne
                [lrange $terminal_expected 0 end]} {
            harness_die "lineage-terminal state=$terminal_state operations=$::lineage_operations expected=$terminal_expected"
        }
        set partial_count 0
        foreach scenario {
            partial-run partial-home partial-user partial-user-run
            partial-user-home partial-all
        } {
            set ::lineage_scenario $scenario
            set ::lineage_operations {}
            set ::lineage_presence_calls [dict create]
            set caught [catch {
                execute_retirement_lineage_gate $values \
                    [string repeat a 64] $password
            } message options]
            if {!$caught || ![dict exists $options -errorcode] ||
                [dict get $options -errorcode] ne {B82FAIL 78} ||
                [lrange $::lineage_operations 0 end] ne
                    [lrange $fresh_expected 0 end]} {
                harness_die "lineage-partial scenario=$scenario message=$message options=$options operations=$::lineage_operations"
            }
            incr partial_count
        }
        set ::lineage_scenario receipt-pending
        set ::lineage_operations {}
        set ::lineage_presence_calls [dict create]
        set caught [catch {
            execute_retirement_lineage_gate $values \
                [string repeat a 64] $password
        } message options]
        if {!$caught || ![dict exists $options -errorcode] ||
            [dict get $options -errorcode] ne {B82FAIL 78} ||
            [lrange $::lineage_operations 0 end] ne
                [lrange $terminal_expected 0 3]} {
            harness_die "lineage-receipt-pending message=$message options=$options operations=$::lineage_operations"
        }
        set recheck_drifts 0
        foreach scenario {
            recheck-user recheck-home recheck-run recheck-receipt
        } {
            set ::lineage_scenario $scenario
            set ::lineage_fail_operation none
            set ::lineage_fail_kind none
            set ::lineage_operations {}
            set ::lineage_presence_calls [dict create]
            set caught [catch {
                execute_retirement_lineage_gate $values \
                    [string repeat a 64] $password
            } message options]
            switch -- $scenario {
                recheck-user { set recheck_index 0 }
                recheck-home { set recheck_index 1 }
                recheck-run { set recheck_index 2 }
                recheck-receipt { set recheck_index 3 }
                default { harness_die "lineage-recheck-scenario-$scenario" }
            }
            set expected_recheck_prefix [concat \
                [lrange $terminal_expected 0 38] \
                [lrange {
                    lineage-exists-user-intake
                    lineage-exists-home-qroot
                    lineage-exists-run-qroot
                    lineage-exists-receipt-pending
                } 0 $recheck_index]]
            if {!$caught || ![dict exists $options -errorcode] ||
                [dict get $options -errorcode] ne {B82FAIL 78} ||
                [lrange $::lineage_operations 0 end] ne
                    [lrange $expected_recheck_prefix 0 end]} {
                harness_die "lineage-recheck scenario=$scenario message=$message options=$options operations=$::lineage_operations"
            }
            incr recheck_drifts
        }
        set deep_missing 0
        foreach operation [concat [lineage_test_terminal_operations] {
            lineage-retained-helper-verify
        }] {
            set ::lineage_scenario terminal-cut
            set ::lineage_fail_operation $operation
            set ::lineage_fail_kind missing
            set ::lineage_operations {}
            set ::lineage_presence_calls [dict create]
            set caught [catch {
                execute_retirement_lineage_gate $values \
                    [string repeat a 64] $password
            } message options]
            if {$operation eq "lineage-retained-helper-verify"} {
                set expected_failure_prefix $terminal_expected
            } else {
                set operation_index [lsearch -exact \
                    [lineage_test_terminal_operations] $operation]
                set expected_failure_prefix [concat \
                    [lrange $terminal_expected 0 3] \
                    [lrange [lineage_test_terminal_operations] \
                        0 $operation_index]]
            }
            if {!$caught || ![dict exists $options -errorcode] ||
                [dict get $options -errorcode] ne {B82FAIL 78} ||
                [lrange $::lineage_operations 0 end] ne
                    [lrange $expected_failure_prefix 0 end]} {
                harness_die "lineage-terminal-cut operation=$operation message=$message options=$options operations=$::lineage_operations expected=$expected_failure_prefix"
            }
            incr deep_missing
        }
        set deep_nonzero 0
        foreach operation [lineage_test_terminal_operations] {
            set ::lineage_scenario terminal-cut
            set ::lineage_fail_operation $operation
            set ::lineage_fail_kind child-nonzero
            set ::lineage_operations {}
            set ::lineage_presence_calls [dict create]
            set caught [catch {
                execute_retirement_lineage_gate $values \
                    [string repeat a 64] $password
            } message options]
            set operation_index [lsearch -exact \
                [lineage_test_terminal_operations] $operation]
            set expected_failure_prefix [concat \
                [lrange $terminal_expected 0 3] \
                [lrange [lineage_test_terminal_operations] \
                    0 $operation_index]]
            if {!$caught || ![dict exists $options -errorcode] ||
                [dict get $options -errorcode] ne {B82FAIL 78} ||
                [lrange $::lineage_operations 0 end] ne
                    [lrange $expected_failure_prefix 0 end]} {
                harness_die "lineage-deep-nonzero operation=$operation message=$message options=$options operations=$::lineage_operations expected=$expected_failure_prefix"
            }
            incr deep_nonzero
        }
        set assertion_malformed 0
        foreach operation {
            lineage-home-readlink lineage-home-stat lineage-home-entries
            lineage-auth-manifest-sha lineage-auth-manifest-pair
            lineage-retained-helper-verify
        } {
            set ::lineage_scenario terminal-cut
            set ::lineage_fail_operation $operation
            set ::lineage_fail_kind malformed
            set ::lineage_operations {}
            set ::lineage_presence_calls [dict create]
            set caught [catch {
                execute_retirement_lineage_gate $values \
                    [string repeat a 64] $password
            } message options]
            if {$operation eq "lineage-retained-helper-verify"} {
                set expected_failure_prefix $terminal_expected
            } else {
                set operation_index [lsearch -exact \
                    [lineage_test_terminal_operations] $operation]
                set expected_failure_prefix [concat \
                    [lrange $terminal_expected 0 3] \
                    [lrange [lineage_test_terminal_operations] \
                        0 $operation_index]]
            }
            if {!$caught || ![dict exists $options -errorcode] ||
                [dict get $options -errorcode] ne {B82FAIL 78} ||
                [lrange $::lineage_operations 0 end] ne
                    [lrange $expected_failure_prefix 0 end]} {
                harness_die "lineage-malformed operation=$operation message=$message options=$options operations=$::lineage_operations expected=$expected_failure_prefix"
            }
            incr assertion_malformed
        }
        set helper_failures 0
        foreach failure {child-nonzero signal} {
            set ::lineage_scenario terminal-cut
            set ::lineage_fail_operation lineage-retained-helper-verify
            set ::lineage_fail_kind $failure
            set ::lineage_operations {}
            set ::lineage_presence_calls [dict create]
            set caught [catch {
                execute_retirement_lineage_gate $values \
                    [string repeat a 64] $password
            } message options]
            if {!$caught || ![dict exists $options -errorcode] ||
                [dict get $options -errorcode] ne {B82FAIL 78} ||
                [lrange $::lineage_operations 0 end] ne
                    [lrange $terminal_expected 0 end]} {
                harness_die "lineage-helper-failure=$failure message=$message options=$options operations=$::lineage_operations"
            }
            incr helper_failures
        }
        if {$deep_missing != 36 || $deep_nonzero != 35 ||
            $assertion_malformed != 6 || $helper_failures != 2 ||
            $recheck_drifts != 4 || $partial_count != 6 ||
            $::credential_reads != 1 || $::lineage_mutation_spawns != 0} {
            harness_die "lineage-summary missing=$deep_missing nonzero=$deep_nonzero malformed=$assertion_malformed helper=$helper_failures recheck=$recheck_drifts partial=$partial_count credential_reads=$::credential_reads mutation_spawns=$::lineage_mutation_spawns"
        }
        puts "HARNESS_LINEAGE_GATE fresh=PASS terminal=PASS partial_states=6 receipt_pending=STOP recheck_drifts=4 deep_missing=36 deep_nonzero=35 assertion_malformed=6 helper_failures=2 credential_reads=1 mutation_spawns=0 result=PASS"
    }
    prepare-lineage {
        set ::credential_reads 0
        set ::observed {}
        set ::mutation_trace {}
        set ::scp_spawns 0
        rename fail transport_original_fail
        proc fail {message code} {
            return -code error -errorcode [list B82FAIL $code] $message
        }
        rename exit harness_real_exit
        proc exit {{code 0}} {
            return -code error -errorcode [list TRANSACTION_EXIT $code] "exit-$code"
        }
        rename require_manifest_authority transport_original_require_manifest_authority
        proc require_manifest_authority args { return }
        rename read_execute_credential transport_original_read_execute_credential
        proc read_execute_credential {path} {
            incr ::credential_reads
            return fixture-password
        }
        rename execute_operation_spec transport_original_execute_operation_spec
        proc execute_operation_spec {operation operation_spec password} {
            lappend ::observed $operation
            return [list ok 0 "" none]
        }
        rename execute_primitive transport_original_execute_primitive
        proc execute_primitive {values manifest_sha operation approved_sha password} {
            lappend ::observed $operation
            if {$operation eq "package-mkdir"} {
                lappend ::mutation_trace $operation
                return [list child-failure 73 "" none]
            }
            if {[string match "scp-*" $operation]} {
                incr ::scp_spawns
                lappend ::mutation_trace $operation
            }
            return [list ok 0 "" none]
        }
        set values [dict create target_user fixture target_host 127.0.0.1]
        set password [read_execute_credential /fixture/credential]
        set caught [catch {
            execute_prepare_transaction $values [string repeat a 64] $password
        } message options]
        set expected {
            identity-hostname identity-kernel identity-machine identity-netns
            identity-interface stale-package-root stale-bootstrap-root
            stale-alternate-bootstrap-root stale-stage-root stale-fresh-root
            stale-standalone-root stale-routed-evidence-root stale-realnic-run-roots
            stale-realnic-interface-leases stale-veth-wgc8e41a stale-veth-wgc8e41b
            stale-veth-wga19f7a stale-veth-wga19f7b stale-veth-wg5b8d3a
            stale-veth-wg5b8d3b stale-pin-fresh stale-pin-standalone
            stale-pin-legacy-tcx stale-pin-legacy-nic-original
            stale-pin-legacy-nic-all-on stale-pin-legacy-nic-all-off
            stale-pin-legacy-nic-tx-path stale-pin-legacy-nic-rx-path
            stale-pin-legacy-nic-mtu1492 stale-pin-legacy-nic-mtu1500
            stale-pin-legacy-nic-soak stale-checksum-module
            stale-checksum-module-btf stale-checksum-module-lock
            stale-physical-interface-lock package-parent-stat
            lineage-exists-user-intake lineage-exists-home-qroot
            lineage-exists-run-qroot package-mkdir
        }
        if {!$caught || ![dict exists $options -errorcode] ||
            [dict get $options -errorcode] ne {TRANSACTION_EXIT 73} ||
            [lrange $::observed 0 end] ne [lrange $expected 0 end] ||
            $::mutation_trace ne {package-mkdir} ||
            $::scp_spawns != 0 || $::credential_reads != 1} {
            set errorcode [expr {[dict exists $options -errorcode] ?
                [dict get $options -errorcode] : "missing"}]
            harness_die "prepare-lineage error=$errorcode observed=$::observed mutations=$::mutation_trace scp=$::scp_spawns credential_reads=$::credential_reads"
        }
        puts "HARNESS_PREPARE_LINEAGE readonly_prefix=39 first_mutation=package-mkdir mkdir_rc=73 scp=0 credential_reads=1 result=PASS"
        harness_real_exit 0
    }
    default { harness_die "mode-$mode" }
}
EXPECT_HARNESS
/bin/chmod 0700 "${TRANSPORT_HARNESS}" || fail 'transport transaction harness mode'

expect_precredential_fence() {
  local label="$1" manifest="$2" manifest_sha="$3" operation="$4" approved_sha="$5"
  local expected_rc="$6" expected_reason="$7" output
  output="$(/usr/bin/expect "${TRANSPORT_HARNESS}" "${FIXTURE_REVIEW}/locked-transport.exp" \
    precredential "${manifest}" "${manifest_sha}" "${operation}" "${approved_sha}")" ||
    fail "${label}: precredential harness"
  if [[ "${expected_reason}" == any ]]; then
    [[ "${output}" == *"HARNESS_PRECREDENTIAL kind=stop rc=${expected_rc} reason="* &&
      "${output}" == *' credential_reads=0 spawns=0'* ]] ||
      fail "${label}: precredential fence drifted: ${output}"
  else
    [[ "${output}" == *"HARNESS_PRECREDENTIAL kind=stop rc=${expected_rc} reason=${expected_reason} credential_reads=0 spawns=0"* ]] ||
      fail "${label}: precredential fence drifted: ${output}"
  fi
}

expect_transport_plan_leaf() {
  local label="$1" manifest="$2" manifest_sha="$3" operation="$4" approved_sha="$5" output
  output="$(/usr/bin/expect "${FIXTURE_REVIEW}/locked-transport.exp" \
    --manifest "${manifest}" --manifest-sha256 "${manifest_sha}" \
    --credential-path "${CREDENTIAL_PATH}" --action plan --operation "${operation}" \
    --approved-plan-sha256 "${approved_sha}")" || fail "${label}: transport plan"
  [[ "${output}" == *"B82_V6_TRANSPORT_PLAN operation=${operation} "* &&
    "${output}" == *' credential_read=0 network_operations=0'* &&
    "${output}" == *'EXPECT_SPAWN_ARGV '* ]] ||
    fail "${label}: transport plan marker: ${output}"
}

readonly -a RAW_MUTATION_OPERATIONS=(
  package-mkdir bootstrap-create bootstrap-install-provisioner bootstrap-install-stager
  controller-shellcheck hermetic-matrix hermetic-fresh stage-snapshot stage-run
  stage-realnic-plan-snapshot
)
readonly -a RAW_MUTATION_PACKAGE_NAMES=(
  source-4f2a9b61.bundle package-manifest.v1 bind-final-package.sh
  controller.sh prepare-stage-root.sh provision-ubuntu-test-host.sh
  root-matrix-n-r.sh check-realhost-iperf.py test-hermetic-matrix.sh
  test_matrix_static.py checksum-module-lease.sh root-fresh-verifier-gate.sh
  test-hermetic-fresh-verifier-gate.sh test_fresh_verifier_gate_static.py
  realnic_acceptance.py test_realnic_acceptance.py test_realnic_acceptance_static.py
)
readonly -a RETIRED_PUBLIC_AND_PRIVATE_OPERATIONS=(
  retire-prestage-2c690050 verify-retirement retire-raw-helper-mutate
  retire-raw-future lineage-home-stat
)
RAW_DIRECT_COUNT=0
for operation in "${RAW_MUTATION_OPERATIONS[@]}"; do
  operation_approved_sha='none'
  if [[ "${operation}" == stage-realnic-plan-snapshot ]]; then
    operation_approved_sha='abababababababababababababababababababababababababababababababab'
  fi
  expect_precredential_fence "raw-${operation}" \
    /private/tmp/nonexistent-b82-raw-mutation-manifest \
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    "${operation}" "${operation_approved_sha}" 65 action-operation
  ((RAW_DIRECT_COUNT += 1))
done
for name in "${RAW_MUTATION_PACKAGE_NAMES[@]}"; do
  expect_precredential_fence "raw-scp-${name}" \
    /private/tmp/nonexistent-b82-raw-mutation-manifest \
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    "scp-${name}" none 65 action-operation
  ((RAW_DIRECT_COUNT += 1))
done
expect_precredential_fence raw-scp-realnic-approved-plan \
  /private/tmp/nonexistent-b82-raw-mutation-manifest \
  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  scp-realnic-approved-plan \
  abababababababababababababababababababababababababababababababab \
  65 action-operation
((RAW_DIRECT_COUNT += 1))
[[ "${RAW_DIRECT_COUNT}" -eq 28 ]] || fail 'raw mutation direct-call cardinality'

RETIRED_OPERATION_REJECTIONS=0
for operation in "${RETIRED_PUBLIC_AND_PRIVATE_OPERATIONS[@]}"; do
  private_output="$(/usr/bin/expect "${FIXTURE_REVIEW}/locked-transport.exp" \
    --manifest "${BOUND_MANIFEST}" --manifest-sha256 "${BOUND_MANIFEST_SHA}" \
    --credential-path "${CREDENTIAL_PATH}" --action plan --operation "${operation}" \
    --approved-plan-sha256 none 2>&1)"
  private_rc=$?
  [[ "${private_rc}" -eq 66 && "${private_output}" == *'reason=policy rc=66'* ]] ||
    fail "retired/private plan operation became reachable: ${operation}: ${private_output}"
  private_output="$(/usr/bin/expect "${FIXTURE_REVIEW}/locked-transport.exp" \
    --manifest /private/tmp/nonexistent-b82-retirement-private-manifest \
    --manifest-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    --credential-path "${CREDENTIAL_PATH}" --action execute --operation "${operation}" \
    --approved-plan-sha256 none 2>&1)"
  private_rc=$?
  [[ "${private_rc}" -eq 65 && "${private_output}" == *'reason=action-operation rc=65'* ]] ||
    fail "retired/private execute operation passed the precredential action gate: ${operation}: ${private_output}"
  ((RETIRED_OPERATION_REJECTIONS += 2))
done
[[ "${RETIRED_OPERATION_REJECTIONS}" -eq 10 ]] ||
  fail 'retired/private plan and execute rejection cardinality'
printf 'HERMETIC_RETIRED_OPERATION_SURFACE plan_execute_rejections=%s credential_reads=0 network_operations=0\n' \
  "${RETIRED_OPERATION_REJECTIONS}"

PREPARE_SEQUENCE_OUTPUT="$(/usr/bin/expect "${TRANSPORT_HARNESS}" \
  "${FIXTURE_REVIEW}/locked-transport.exp" prepare-sequence)" ||
  fail 'fixed prepare transaction sequence'
[[ "${PREPARE_SEQUENCE_OUTPUT}" == *'HARNESS_PREPARE_SEQUENCE steps=102 state=AWAIT_APPLY result=PASS'* ]] ||
  fail "fixed prepare transaction marker: ${PREPARE_SEQUENCE_OUTPUT}"
PREWRITE_CUTS_OUTPUT="$(/usr/bin/expect "${TRANSPORT_HARNESS}" \
  "${FIXTURE_REVIEW}/locked-transport.exp" prewrite-cuts 2>&1)" ||
  fail 'prepare prewrite cut matrix'
[[ "${PREWRITE_CUTS_OUTPUT}" == *'HARNESS_PREWRITE_CUTS cuts=36 child_nonzero=18 child_signal=18 mutation_trace=0 result=PASS'* ]] ||
  fail "prepare prewrite cut matrix marker: ${PREWRITE_CUTS_OUTPUT}"
MKDIR_FAILURE_OUTPUT="$(/usr/bin/expect "${TRANSPORT_HARNESS}" \
  "${FIXTURE_REVIEW}/locked-transport.exp" mkdir-failure)" ||
  fail 'atomic package mkdir failure harness'
[[ "${MKDIR_FAILURE_OUTPUT}" == *'HARNESS_MKDIR_FAILURE rc=73 steps=40 scp=0 result=PASS'* ]] ||
  fail "atomic package mkdir failure marker: ${MKDIR_FAILURE_OUTPUT}"
CHILD_NONZERO_OUTPUT="$(/usr/bin/expect "${TRANSPORT_HARNESS}" \
  "${FIXTURE_REVIEW}/locked-transport.exp" child-nonzero)" ||
  fail 'transport child nonzero harness'
[[ "${CHILD_NONZERO_OUTPUT}" == *'HARNESS_CHILD_NONZERO rc=23 result=PASS'* ]] ||
  fail 'transport child nonzero marker'
expect_exact_rc transport-child-signal 78 /usr/bin/expect "${TRANSPORT_HARNESS}" \
  "${FIXTURE_REVIEW}/locked-transport.exp" child-signal
LINEAGE_EXISTENCE_OUTPUT="$(/usr/bin/expect "${TRANSPORT_HARNESS}" \
  "${FIXTURE_REVIEW}/locked-transport.exp" lineage-existence)" ||
  fail 'lineage existence output classifier matrix'
[[ "${LINEAGE_EXISTENCE_OUTPUT}" == *'HARNESS_LINEAGE_EXISTENCE paths=4 empty=absent exact=present child_nonzero=STOP signal=STOP malformed=STOP credential_reads=1 result=PASS'* ]] ||
  fail "lineage existence classifier marker: ${LINEAGE_EXISTENCE_OUTPUT}"
LINEAGE_GATE_OUTPUT="$(/usr/bin/expect "${TRANSPORT_HARNESS}" \
  "${FIXTURE_REVIEW}/locked-transport.exp" lineage-gate)" ||
  fail 'retained retirement lineage gate matrix'
[[ "${LINEAGE_GATE_OUTPUT}" == *'HARNESS_LINEAGE_GATE fresh=PASS terminal=PASS partial_states=6 receipt_pending=STOP recheck_drifts=4 deep_missing=36 deep_nonzero=35 assertion_malformed=6 helper_failures=2 credential_reads=1 mutation_spawns=0 result=PASS'* ]] ||
  fail "retained retirement lineage gate marker: ${LINEAGE_GATE_OUTPUT}"
PREPARE_LINEAGE_OUTPUT="$(/usr/bin/expect "${TRANSPORT_HARNESS}" \
  "${FIXTURE_REVIEW}/locked-transport.exp" prepare-lineage)" ||
  fail 'prepare lineage placement and first mutation'
[[ "${PREPARE_LINEAGE_OUTPUT}" == *'HARNESS_PREPARE_LINEAGE readonly_prefix=39 first_mutation=package-mkdir mkdir_rc=73 scp=0 credential_reads=1 result=PASS'* ]] ||
  fail "prepare lineage placement marker: ${PREPARE_LINEAGE_OUTPUT}"

SCP_BUILD_FIXTURE="${TEST_ROOT}/generic-scp-build"
/bin/mkdir -m 0700 -- "${SCP_BUILD_FIXTURE}" || fail 'generic SCP build fixture directory'
SCP_BUILD_FILE="${SCP_BUILD_FIXTURE}/controller.sh"
printf 'generic-scp-valid\n' >"${SCP_BUILD_FILE}" || fail 'generic SCP valid fixture'
/bin/chmod 0600 "${SCP_BUILD_FILE}" || fail 'generic SCP valid fixture mode'
SCP_BUILD_SHA="$(sha256_file "${SCP_BUILD_FILE}")" || fail 'generic SCP valid fixture SHA'
/usr/bin/expect "${TRANSPORT_HARNESS}" "${FIXTURE_REVIEW}/locked-transport.exp" \
  scp-build "${SCP_BUILD_FIXTURE}" "${SCP_BUILD_SHA}" accept ||
  fail 'generic SCP valid local artifact'
: >"${SCP_BUILD_FILE}" || fail 'generic SCP zero-byte fixture'
SCP_BUILD_SHA="$(sha256_file "${SCP_BUILD_FILE}")" || fail 'generic SCP zero-byte fixture SHA'
/usr/bin/expect "${TRANSPORT_HARNESS}" "${FIXTURE_REVIEW}/locked-transport.exp" \
  scp-build "${SCP_BUILD_FIXTURE}" "${SCP_BUILD_SHA}" reject ||
  fail 'generic SCP zero-byte artifact was accepted'
/usr/bin/python3 -B -I -c \
  'import os, sys; os.truncate(sys.argv[1], (16 << 20) + 1)' "${SCP_BUILD_FILE}" ||
  fail 'generic SCP oversize fixture'
SCP_BUILD_SHA="$(sha256_file "${SCP_BUILD_FILE}")" || fail 'generic SCP oversize fixture SHA'
/usr/bin/expect "${TRANSPORT_HARNESS}" "${FIXTURE_REVIEW}/locked-transport.exp" \
  scp-build "${SCP_BUILD_FIXTURE}" "${SCP_BUILD_SHA}" reject ||
  fail 'generic SCP oversize artifact was accepted'
printf 'HERMETIC_TRANSPORT_TRANSACTION raw_direct=28 prepare_steps=102 prewrite_cuts=36 mutation_trace=0 mkdir_failure_scp=0 child_nonzero=stop child_signal=stop generic_scp_bounds=pass\n'

[[ -d "${BOUND_OUTPUT}/history-verification.git" && ! -L "${BOUND_OUTPUT}/history-verification.git" &&
  -f "${BOUND_OUTPUT}/history-objects.v1" && -f "${BOUND_OUTPUT}/history-roots.v1" ]] ||
  fail 'isolated history evidence shape'
[[ "$(manifest_value history_verification "${BOUND_MANIFEST}")" == 'isolated-unbundle-rev-list-fsck-v1' ]] ||
  fail 'history method manifest binding'
[[ "$(manifest_value history_commit_count "${BOUND_MANIFEST}")" == '2' ]] ||
  fail 'full fixture history count'
[[ "$(sha256_file "${BOUND_OUTPUT}/history-objects.v1")" == \
  "$(manifest_value history_objects_sha256 "${BOUND_MANIFEST}")" ]] || fail 'history objects digest'
[[ "$(sha256_file "${BOUND_OUTPUT}/history-roots.v1")" == \
  "$(manifest_value history_roots_sha256 "${BOUND_MANIFEST}")" ]] || fail 'history roots digest'
[[ "$(manifest_value provision_ubuntu_test_host_sh_path "${BOUND_MANIFEST}")" == \
  'scripts/provision-ubuntu-test-host.sh' ]] || fail 'provisioner manifest path binding'
[[ "$(sha256_file "${BOUND_OUTPUT}/provision-ubuntu-test-host.sh")" == \
  "$(manifest_value provision_ubuntu_test_host_sh_sha256 "${BOUND_MANIFEST}")" ]] ||
  fail 'provisioner package digest binding'
readonly -a REALNIC_MANIFEST_KEYS=(
  realnic_acceptance_py
  test_realnic_acceptance_py
  test_realnic_acceptance_static_py
)
readonly -a REALNIC_MANIFEST_PATHS=(
  scripts/realhost-b82-acceptance-v1/realnic_acceptance.py
  scripts/realhost-b82-acceptance-v1/test_realnic_acceptance.py
  scripts/realhost-b82-acceptance-v1/test_realnic_acceptance_static.py
)
readonly -a REALNIC_PACKAGE_NAMES=(
  realnic_acceptance.py
  test_realnic_acceptance.py
  test_realnic_acceptance_static.py
)
for index in 0 1 2; do
  key="${REALNIC_MANIFEST_KEYS[${index}]}"
  source_file="${REALNIC_MANIFEST_PATHS[${index}]}"
  package_name="${REALNIC_PACKAGE_NAMES[${index}]}"
  expected_blob="$(/usr/bin/git -C "${FIXTURE_REPOSITORY}" rev-parse \
    "${FIXTURE_COMMIT}:${source_file}")" || fail 'realNIC source blob lookup'
  [[ "$(manifest_value "${key}_path" "${BOUND_MANIFEST}")" == "${source_file}" &&
    "$(manifest_value "${key}_blob" "${BOUND_MANIFEST}")" == "${expected_blob}" &&
    "$(sha256_file "${BOUND_OUTPUT}/${package_name}")" == \
      "$(manifest_value "${key}_sha256" "${BOUND_MANIFEST}")" ]] ||
    fail "realNIC manifest triplet is not bound to source blob: ${source_file}"
done
readonly -a STAGED_MANIFEST_KEYS=(
  root_veth_n_r_sh
  test_hermetic_veth_runner_sh
  test_veth_runner_static_py
  controller_seam_sh
  root_routed_veth_n_r_sh
  test_hermetic_routed_veth_harness_sh
  test_routed_veth_harness_static_py
)
readonly -a STAGED_MANIFEST_PATHS=(
  scripts/realhost-b82-c8e41d73/root-veth-n-r.sh
  scripts/realhost-b82-c8e41d73/test-hermetic-veth-runner.sh
  scripts/realhost-b82-c8e41d73/test_veth_runner_static.py
  scripts/realhost-b82-routed-veth-v1/controller-seam.sh
  scripts/realhost-b82-routed-veth-v1/root-routed-veth-n-r.sh
  scripts/realhost-b82-routed-veth-v1/test-hermetic-routed-veth-harness.sh
  scripts/realhost-b82-routed-veth-v1/test_routed_veth_harness_static.py
)
for index in 0 1 2 3 4 5 6; do
  key="${STAGED_MANIFEST_KEYS[${index}]}"
  source_file="${STAGED_MANIFEST_PATHS[${index}]}"
  package_name="${source_file##*/}"
  expected_blob="$(/usr/bin/git -C "${FIXTURE_REPOSITORY}" rev-parse \
    "${FIXTURE_COMMIT}:${source_file}")" || fail 'staged identity blob lookup'
  [[ "$(manifest_value "${key}_path" "${BOUND_MANIFEST}")" == "${source_file}" &&
    "$(manifest_value "${key}_blob" "${BOUND_MANIFEST}")" == "${expected_blob}" &&
    "$(manifest_value "${key}_sha256" "${BOUND_MANIFEST}")" == \
      "$(sha256_file "${FIXTURE_REPOSITORY}/${source_file}")" &&
    ! -e "${BOUND_OUTPUT}/${package_name}" && ! -L "${BOUND_OUTPUT}/${package_name}" ]] ||
    fail "staged-only manifest triplet or flat-package exclusion drifted: ${source_file}"
done
[[ "$(manifest_value format "${BOUND_MANIFEST}")" == 'wg-mix-ebpf-b82-v6-package-v4' &&
  "$(manifest_value physical_nic_forward_authority "${BOUND_MANIFEST}")" == \
    'realnic-acceptance-v1' &&
  "$(manifest_value physical_interface_lock "${BOUND_MANIFEST}")" == \
    '/run/wg-mix-ebpf-realnic-physical-interface.v1.lock' &&
  "$(manifest_value legacy_matrix_mode "${BOUND_MANIFEST}")" == 'retired' &&
  "$(manifest_value realnic_profile "${BOUND_MANIFEST}")" == 'acceptance' &&
  "$(manifest_value realnic_traffic_seconds "${BOUND_MANIFEST}")" == '30' &&
  "$(manifest_value checksum_module_lease_sh_path "${BOUND_MANIFEST}")" == \
    'scripts/realhost-b82-c8e41d73/checksum-module-lease.sh' &&
  "$(manifest_value root_fresh_verifier_gate_sh_path "${BOUND_MANIFEST}")" == \
    'scripts/realhost-b82-c8e41d73/root-fresh-verifier-gate.sh' &&
  "$(sha256_file "${BOUND_OUTPUT}/checksum-module-lease.sh")" == \
    "$(manifest_value checksum_module_lease_sh_sha256 "${BOUND_MANIFEST}")" &&
  "$(sha256_file "${BOUND_OUTPUT}/root-fresh-verifier-gate.sh")" == \
    "$(manifest_value root_fresh_verifier_gate_sh_sha256 "${BOUND_MANIFEST}")" &&
  "$(manifest_value realnic_acceptance_py_path "${BOUND_MANIFEST}")" == \
    'scripts/realhost-b82-acceptance-v1/realnic_acceptance.py' ]] ||
  fail 'single-schema fresh/realNIC authority binding'
/usr/bin/git -C "${BOUND_OUTPUT}/history-verification.git" fsck --full --strict --no-dangling \
  "${FIXTURE_COMMIT}" || fail 'isolated history fsck'
/usr/bin/grep -E '^\?' -- "${BOUND_OUTPUT}/history-objects.v1"
HISTORY_MISSING_RC=$?
case "${HISTORY_MISSING_RC}" in
  1) ;;
  0) fail 'history evidence contains a missing object' ;;
  *) fail 'history evidence scan failed' ;;
esac

PACKAGE_VERIFY_OUTPUT="$(/bin/bash "${BOUND_OUTPUT}/controller.sh" verify-package \
  --manifest "${BOUND_MANIFEST}" --manifest-sha256 "${BOUND_MANIFEST_SHA}" \
  --credential-path "${CREDENTIAL_PATH}" --approved-plan-sha256 none)" ||
  fail 'controller package verify-only seam'
[[ "${PACKAGE_VERIFY_OUTPUT}" == \
  *B82_V6_CONTROLLER_PACKAGE_VERIFIED\ manifest_sha256="${BOUND_MANIFEST_SHA}"\ integration_commit="${FIXTURE_COMMIT}"\ package_device_inode=*\ credential_read=0\ network_operations=0 ]] ||
  fail "controller package verify-only marker: ${PACKAGE_VERIFY_OUTPUT}"
TRANSPORT_VERIFY_OUTPUT="$(/usr/bin/expect "${TRANSPORT_HARNESS}" \
  "${FIXTURE_REVIEW}/locked-transport.exp" verify \
  "${BOUND_MANIFEST}" "${BOUND_MANIFEST_SHA}" prepare none)" ||
  fail 'transport full package verify-only seam'
[[ "${TRANSPORT_VERIFY_OUTPUT}" == *'B82_V6_TRANSPORT_PACKAGE_AUTHORITY '* &&
  "${TRANSPORT_VERIFY_OUTPUT}" == *'HARNESS_VERIFY_ONLY operation=prepare credential_reads=0 spawns=0 result=PASS'* ]] ||
  fail "transport full package verify-only marker: ${TRANSPORT_VERIFY_OUTPUT}"

CONTROLLER_TRANSACTION_SEAM="$(/bin/bash -c '
  source "$1" || exit $?
  run_operation() { printf "%s:%s\n" "$1" "$2"; }
  verify_local_approved_plan() { return 0; }
  execute_prepare || exit $?
  execute_provision_apply || exit $?
  execute_realnic_run || exit $?
  execute_realnic_restore || exit $?
' controller-transaction-seam "${CONTROLLER_READER_ONLY}")" ||
  fail 'controller high-level transaction seam'
[[ "${CONTROLLER_TRANSACTION_SEAM}" == $'execute:prepare\nexecute:provision-apply\nexecute:realnic-run\nexecute:realnic-restore' ]] ||
  fail "controller emitted primitive mutation sequence: ${CONTROLLER_TRANSACTION_SEAM}"
for retired_mode in retire-prestage-2c690050 verify-retirement; do
  expect_exact_rc "controller-retired-mode-${retired_mode}" 64 \
    /bin/bash "${FIXTURE_REVIEW}/controller.sh" "${retired_mode}"
  expect_exact_rc "stager-retired-mode-${retired_mode}" 64 \
    /bin/bash "${FIXTURE_REVIEW}/prepare-stage-root.sh" "${retired_mode}"
done
printf 'HERMETIC_VERIFY_ONLY controller=pass transport=pass credential_reads=0 spawns=0 controller_transactions=single-call retired_modes=unreachable\n'

MANIFEST_AUTHORITY_BACKUP="${TEST_ROOT}/package-manifest.authority-backup.v1"
/bin/cp -- "${BOUND_MANIFEST}" "${MANIFEST_AUTHORITY_BACKUP}" ||
  fail 'manifest authority backup'
/usr/bin/python3 -B -I -c '
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
payload = path.read_bytes()
mutated, count = re.subn(
    br"(?m)^(controller_sh_blob\t)[0-9a-f]{40}$",
    br"\1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    payload,
)
if count != 1 or mutated == payload:
    raise SystemExit(65)
path.write_bytes(mutated)
' "${BOUND_MANIFEST}" || fail 'forged controller manifest triplet fixture'
FORGED_MANIFEST_SHA="$(sha256_file "${BOUND_MANIFEST}")" || fail 'forged manifest digest'
expect_precredential_fence forged-manifest-triplet "${BOUND_MANIFEST}" \
  "${FORGED_MANIFEST_SHA}" prepare none 66 controller-verifier-git-identity
/bin/cp -- "${MANIFEST_AUTHORITY_BACKUP}" "${BOUND_MANIFEST}" ||
  fail 'manifest authority restore'
[[ "$(sha256_file "${BOUND_MANIFEST}")" == "${BOUND_MANIFEST_SHA}" ]] ||
  fail 'manifest authority restore digest'

PACKAGE_TAMPER_CUTS=0
for name in "${RAW_MUTATION_PACKAGE_NAMES[@]}"; do
  FLAT_PACKAGE_FILE="${BOUND_OUTPUT}/${name}"
  FLAT_PACKAGE_BACKUP="${TEST_ROOT}/precredential-${name}.backup"
  /bin/cp -- "${FLAT_PACKAGE_FILE}" "${FLAT_PACKAGE_BACKUP}" ||
    fail "${name}: flat package authority backup"
  printf '\nB82-precredential-content-drift\n' >>"${FLAT_PACKAGE_FILE}" ||
    fail "${name}: flat package content drift fixture"
  expect_precredential_fence "flat-content-${name}" "${BOUND_MANIFEST}" \
    "${BOUND_MANIFEST_SHA}" prepare none 66 any
  ((PACKAGE_TAMPER_CUTS += 1))
  /bin/cp -- "${FLAT_PACKAGE_BACKUP}" "${FLAT_PACKAGE_FILE}" ||
    fail "${name}: flat package content restore"
  /bin/chmod 0600 "${FLAT_PACKAGE_FILE}" || fail "${name}: flat package restore mode"
  /bin/chmod 0644 "${FLAT_PACKAGE_FILE}" || fail "${name}: flat package mode drift fixture"
  expect_precredential_fence "flat-mode-${name}" "${BOUND_MANIFEST}" \
    "${BOUND_MANIFEST_SHA}" prepare none 66 any
  ((PACKAGE_TAMPER_CUTS += 1))
  /bin/chmod 0600 "${FLAT_PACKAGE_FILE}" || fail "${name}: flat package mode restore"
done
[[ "${PACKAGE_TAMPER_CUTS}" -eq 34 ]] || fail 'flat package tamper cut cardinality'
[[ "$(sha256_file "${BOUND_MANIFEST}")" == "${BOUND_MANIFEST_SHA}" ]] ||
  fail 'flat package matrix did not restore the manifest'

FLAT_PACKAGE_FILE="${BOUND_OUTPUT}/root-matrix-n-r.sh"
FLAT_PACKAGE_BACKUP="${TEST_ROOT}/precredential-root-matrix-n-r.sh.backup"
FLAT_PACKAGE_EXTRA_LINK="${TEST_ROOT}/root-matrix-n-r.extra-link.sh"
/bin/cp -- "${FLAT_PACKAGE_FILE}" "${FLAT_PACKAGE_BACKUP}" ||
  fail 'flat package nlink authority backup'
/bin/ln -- "${FLAT_PACKAGE_FILE}" "${FLAT_PACKAGE_EXTRA_LINK}" ||
  fail 'flat package nlink drift fixture'
expect_precredential_fence flat-package-nlink "${BOUND_MANIFEST}" \
  "${BOUND_MANIFEST_SHA}" prepare none 66 local-package-artifact
FLAT_PACKAGE_REPLACEMENT="${TEST_ROOT}/root-matrix-n-r.replacement.sh"
/bin/cp -- "${FLAT_PACKAGE_BACKUP}" "${FLAT_PACKAGE_REPLACEMENT}" ||
  fail 'flat package nlink replacement'
/bin/chmod 0600 "${FLAT_PACKAGE_REPLACEMENT}" || fail 'flat package nlink replacement mode'
/bin/mv -- "${FLAT_PACKAGE_REPLACEMENT}" "${FLAT_PACKAGE_FILE}" ||
  fail 'flat package nlink restore'
[[ "$(sha256_file "${FLAT_PACKAGE_FILE}")" == \
  "$(manifest_value root_matrix_n_r_sh_sha256 "${BOUND_MANIFEST}")" ]] ||
  fail 'flat package authority restore digest'

HISTORY_AUTHORITY_FILE="${BOUND_OUTPUT}/history-objects.v1"
HISTORY_AUTHORITY_BACKUP="${TEST_ROOT}/history-objects.authority-backup.v1"
/bin/cp -- "${HISTORY_AUTHORITY_FILE}" "${HISTORY_AUTHORITY_BACKUP}" ||
  fail 'history authority backup'
printf '?aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' >>"${HISTORY_AUTHORITY_FILE}" ||
  fail 'history authority drift fixture'
expect_precredential_fence history-evidence "${BOUND_MANIFEST}" \
  "${BOUND_MANIFEST_SHA}" prepare none 66 controller-package-verifier
/bin/cp -- "${HISTORY_AUTHORITY_BACKUP}" "${HISTORY_AUTHORITY_FILE}" ||
  fail 'history authority restore'
[[ "$(sha256_file "${HISTORY_AUTHORITY_FILE}")" == \
  "$(manifest_value history_objects_sha256 "${BOUND_MANIFEST}")" ]] ||
  fail 'history authority restore digest'
printf 'HERMETIC_LOCAL_AUTHORITY package_names=17 package_tamper_cuts=34 forged_triplet=blocked flat_sha=blocked flat_mode=blocked flat_nlink=blocked history=blocked credential_reads=0 spawns=0\n'

CONTROLLER_ARGS=(
  --manifest "${BOUND_MANIFEST}"
  --manifest-sha256 "${BOUND_MANIFEST_SHA}"
  --credential-path "${CREDENTIAL_PATH}"
)
readonly -a BOUND_PLAN_LEAVES=(
  provision-check provision-apply fresh-plan fresh-run fresh-restore
  routed-plan routed-run routed-restore realnic-plan
)
for operation in "${BOUND_PLAN_LEAVES[@]}"; do
  expect_transport_plan_leaf "bound-${operation}" "${BOUND_MANIFEST}" \
    "${BOUND_MANIFEST_SHA}" "${operation}" none
done
CONTROLLER_PLAN="$(/bin/bash "${FIXTURE_REVIEW}/controller.sh" plan "${CONTROLLER_ARGS[@]}")" ||
  fail 'controller plan'
for literal in \
  'operation=identity-hostname transport=ssh credential_read=0 network_operations=0' \
  'operation=identity-wg-interfaces transport=ssh credential_read=0 network_operations=0' \
  'operation=tool-bpftool transport=ssh credential_read=0 network_operations=0' \
  '/usr/sbin/bpftool -V' \
  'operation=kernel-btf transport=ssh credential_read=0 network_operations=0' \
  'operation=scp-source-4f2a9b61.bundle transport=scp credential_read=0 network_operations=0' \
  'operation=scp-root-fresh-verifier-gate.sh transport=scp credential_read=0 network_operations=0' \
  "${FIXTURE_REPOSITORY}/scripts/realhost-b82-c8e41d73/locked-transport.exp" \
  "${BOUND_OUTPUT}/source-4f2a9b61.bundle" \
  'siyixuan@192.168.10.82:/home/siyixuan/wg-mix-ebpf-test/unpriv-4f2a9b61/source-4f2a9b61.bundle' \
  'operation=stage-run transport=ssh credential_read=0 network_operations=0' \
  '/usr/bin/sudo -- /usr/bin/env -i' \
  'operation=bootstrap-absent transport=ssh credential_read=0 network_operations=0' \
  '/usr/bin/test ! -e /run/wg-mix-ebpf-source-bootstrap-c8e41d73' \
  'operation=bootstrap-not-symlink transport=ssh credential_read=0 network_operations=0' \
  '/usr/bin/test ! -L /run/wg-mix-ebpf-source-bootstrap-c8e41d73' \
  'operation=bootstrap-create transport=ssh credential_read=0 network_operations=0' \
  '/usr/bin/mkdir --mode=0700 -- /run/wg-mix-ebpf-source-bootstrap-c8e41d73' \
  'operation=bootstrap-root-readlink transport=ssh credential_read=0 network_operations=0' \
  'operation=bootstrap-root-stat transport=ssh credential_read=0 network_operations=0' \
  'operation=bootstrap-install-stager transport=ssh credential_read=0 network_operations=0' \
  '/usr/bin/install --owner=root --group=root --mode=0700 --no-target-directory -- /home/siyixuan/wg-mix-ebpf-test/unpriv-4f2a9b61/prepare-stage-root.sh /run/wg-mix-ebpf-source-bootstrap-c8e41d73/prepare-stage-root.sh' \
  'operation=bootstrap-stager-readlink transport=ssh credential_read=0 network_operations=0' \
  'operation=bootstrap-stager-sha transport=ssh credential_read=0 network_operations=0' \
  'operation=bootstrap-stager-stat transport=ssh credential_read=0 network_operations=0' \
  'operation=bootstrap-install-provisioner transport=ssh credential_read=0 network_operations=0' \
  '/usr/bin/install --owner=root --group=root --mode=0700 --no-target-directory -- /home/siyixuan/wg-mix-ebpf-test/unpriv-4f2a9b61/provision-ubuntu-test-host.sh /run/wg-mix-ebpf-source-bootstrap-c8e41d73/provision-ubuntu-test-host.sh' \
  'operation=bootstrap-provisioner-readlink transport=ssh credential_read=0 network_operations=0' \
  'operation=bootstrap-provisioner-stat transport=ssh credential_read=0 network_operations=0' \
  'operation=bootstrap-provisioner-sha transport=ssh credential_read=0 network_operations=0' \
  'operation=provision-check transport=ssh credential_read=0 network_operations=0' \
  '/usr/bin/sudo -- /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C /bin/bash -p /run/wg-mix-ebpf-source-bootstrap-c8e41d73/provision-ubuntu-test-host.sh --check --expected-address 192.168.10.82 --expected-interface ens33 --expected-hostname ubuntu-2604-test --expected-kernel 7.0.0-28-generic --expected-machine-id 9db3fb717cc74974b2a6b243d67f67b9' \
  'operation=provision-apply transport=ssh credential_read=0 network_operations=0' \
  '/usr/bin/sudo -- /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C /bin/bash -p /run/wg-mix-ebpf-source-bootstrap-c8e41d73/provision-ubuntu-test-host.sh --apply --expected-address 192.168.10.82 --expected-interface ens33 --expected-hostname ubuntu-2604-test --expected-kernel 7.0.0-28-generic --expected-machine-id 9db3fb717cc74974b2a6b243d67f67b9' \
  'B82_V6_CONTROLLER_STATE current=PACKAGE_BOUND automatic_apply=0' \
  'B82_V6_CONTROLLER_STATE from=PACKAGE_BOUND to=BOOTSTRAP_ONLY automatic_apply=0' \
  'B82_V6_CONTROLLER_BRANCH missing_set=none next_state=POSTFLIGHT' \
  'B82_V6_CONTROLLER_BRANCH missing_set=initial|iperf3 next_state=AWAIT_APPLY' \
  'B82_V6_CONTROLLER_STATE from=AWAIT_APPLY to=PROVISION_APPLY explicit_mode=provision-apply automatic_apply=0' \
  'operation=stage-snapshot transport=ssh credential_read=0 network_operations=0' \
  '/bin/bash -p /run/wg-mix-ebpf-source-bootstrap-c8e41d73/prepare-stage-root.sh snapshot --manifest /home/siyixuan/wg-mix-ebpf-test/unpriv-4f2a9b61/package-manifest.v1' \
  '/bin/bash -p /run/wg-mix-ebpf-source-bootstrap-c8e41d73/prepare-stage-root.sh plan --manifest /run/wg-mix-ebpf-source-bootstrap-c8e41d73/package-manifest.v1' \
  '/bin/bash -p /run/wg-mix-ebpf-source-bootstrap-c8e41d73/prepare-stage-root.sh run --manifest /run/wg-mix-ebpf-source-bootstrap-c8e41d73/package-manifest.v1' \
  'operation=hermetic-fresh transport=ssh credential_read=0 network_operations=0' \
  'operation=fresh-plan transport=ssh credential_read=0 network_operations=0' \
  'operation=fresh-run transport=ssh credential_read=0 network_operations=0' \
  'operation=fresh-restore transport=ssh credential_read=0 network_operations=0' \
  '/bin/bash -p /run/wg-mix-ebpf-source-stages/c8e41d73/source/scripts/realhost-b82-c8e41d73/root-fresh-verifier-gate.sh run --controller-source /run/wg-mix-ebpf-source-stages/c8e41d73/source' \
  'operation=realnic-plan transport=ssh credential_read=0 network_operations=0' \
  '/usr/bin/python3 -B -I /run/wg-mix-ebpf-source-stages/c8e41d73/source/scripts/realhost-b82-acceptance-v1/realnic_acceptance.py plan --source-commit' \
  "B82_V6_REALNIC_APPROVAL_REQUIRED capture_mode=realnic-plan local_plan_pattern=${BOUND_OUTPUT}/realnic-plan.SHA256.json approved_plan_sha256=explicit automatic_approval=0" \
  'B82_V6_LEGACY_MATRIX_RETIRED controller_entries=0 historical_recovery=frozen-original-package-before-final-staging' \
  'B82_V6_CONTROLLER_PLAN_COMPLETE credential_read=0 network_operations=0 mutations=0 legacy_forward=retired'; do
  [[ "${CONTROLLER_PLAN}" == *"${literal}"* ]] || fail "controller plan missing ${literal}"
done
[[ "${CONTROLLER_PLAN}" != *'B82_V6_MATRIX_BLOCKED'* ]] || fail 'bound plan was blocked'
[[ "${CONTROLLER_PLAN}" != *'/bin/bash -p /home/siyixuan/wg-mix-ebpf-test/unpriv-4f2a9b61/prepare-stage-root.sh'* ]] ||
  fail 'controller plan executes user-writable package stager'
[[ "${CONTROLLER_PLAN}" != *'/bin/bash -p /home/siyixuan/wg-mix-ebpf-test/unpriv-4f2a9b61/provision-ubuntu-test-host.sh'* ]] ||
  fail 'controller plan executes user-writable package provisioner'
[[ "${CONTROLLER_PLAN}" != *'/usr/sbin/bpftool version'* ]] || fail 'legacy bpftool probe survived'
[[ "${CONTROLLER_PLAN}" != *'operation=matrix-'* ]] ||
  fail 'retired legacy matrix operation remained reachable'
[[ "${CONTROLLER_PLAN}" != *'operation=hermetic-realnic-'* ]] ||
  fail 'controller retained a package-copy realNIC test operation'
[[ "${CONTROLLER_PLAN}" != *'prepare-stage-root.sh plan --manifest /home/siyixuan/wg-mix-ebpf-test/unpriv-4f2a9b61/package-manifest.v1'* ]] ||
  fail 'controller stage plan reopens the user-owned manifest'
[[ "${CONTROLLER_PLAN}" != *'prepare-stage-root.sh run --manifest /home/siyixuan/wg-mix-ebpf-test/unpriv-4f2a9b61/package-manifest.v1'* ]] ||
  fail 'controller stage run reopens the user-owned manifest'
[[ "${CONTROLLER_PLAN}" == *'B82_V6_CONTROLLER_PLAN veth-unavailable wg_state=bound operations=veth-plan,veth-run,veth-restore'* ]] ||
  fail 'bound controller plan did not explicitly classify standalone veth as unavailable'
for operation in routed-plan routed-run routed-restore; do
  [[ "${CONTROLLER_PLAN}" == *"operation=${operation} transport=ssh credential_read=0 network_operations=0"* ]] ||
    fail "bound controller plan cannot reach ${operation}"
done
readonly -a EXPECTED_STALE_IDS=(
  package-root bootstrap-root alternate-bootstrap-root stage-root fresh-root
  standalone-root routed-evidence-root realnic-run-roots realnic-interface-leases
  veth-wgc8e41a veth-wgc8e41b veth-wga19f7a veth-wga19f7b
  veth-wg5b8d3a veth-wg5b8d3b pin-fresh pin-standalone pin-legacy-tcx
  pin-legacy-nic-original pin-legacy-nic-all-on pin-legacy-nic-all-off
  pin-legacy-nic-tx-path pin-legacy-nic-rx-path pin-legacy-nic-mtu1492
  pin-legacy-nic-mtu1500 pin-legacy-nic-soak checksum-module
  checksum-module-btf checksum-module-lock physical-interface-lock
)
[[ "${#EXPECTED_STALE_IDS[@]}" == 30 ]] || fail 'stale fixture cardinality'
for index in "${!EXPECTED_STALE_IDS[@]}"; do
  printf -v ordinal '%02d' "$((index + 1))"
  stale_id="${EXPECTED_STALE_IDS[${index}]}"
  stale_line="B82_V6_STALE_ITEM_V1 ordinal=${ordinal} id=${stale_id} class=PLANNED writes=0 cleanup=0 rc=0"
  [[ "$(printf '%s\n' "${CONTROLLER_PLAN}" | /usr/bin/grep -Fxc -- "${stale_line}")" == 1 ]] ||
    fail "stale plan item is not exact and unique: ${stale_line}"
done
[[ "$(printf '%s\n' "${CONTROLLER_PLAN}" | /usr/bin/grep -Fc -- 'B82_V6_STALE_ITEM_V1 ')" == 30 &&
  "${CONTROLLER_PLAN}" == *'B82_V6_STALE_SUMMARY_V1 profile=prepare-new items=30 checked=30 absent=0 writes=0 cleanup=0 result=PLANNED rc=0'* &&
  "${CONTROLLER_PLAN}" == *'wg-mix-ebpf-realnic-acceptance-\*'* &&
  "${CONTROLLER_PLAN}" == *'wg-mix-ebpf-realnic-interface-\*.jsonl'* ]] ||
  fail 'stale plan cardinality, summary, or protected remote glob drifted'
require_ordered_literals "${CONTROLLER_PLAN}" \
  'operation=bootstrap-absent ' \
  'operation=bootstrap-not-symlink ' \
  'operation=bootstrap-create ' \
  'operation=bootstrap-root-readlink ' \
  'operation=bootstrap-root-stat ' \
  'operation=bootstrap-install-provisioner ' \
  'operation=bootstrap-install-stager ' \
  'operation=bootstrap-provisioner-readlink ' \
  'operation=bootstrap-provisioner-stat ' \
  'operation=bootstrap-provisioner-sha ' \
  'operation=provision-check ' \
  'operation=bootstrap-provisioner-readlink ' \
  'operation=bootstrap-provisioner-stat ' \
  'operation=bootstrap-provisioner-sha ' \
  'operation=provision-apply ' \
  'operation=identity-driver ' \
  'operation=bootstrap-stager-readlink ' \
  'operation=bootstrap-stager-stat ' \
  'operation=bootstrap-stager-sha ' \
  'operation=stage-snapshot ' \
  'operation=stage-plan ' \
  'operation=stage-run ' \
  'operation=fresh-plan ' \
  'operation=fresh-run ' \
  'operation=fresh-restore ' \
  'operation=realnic-plan ' \
  'B82_V6_LEGACY_MATRIX_RETIRED '

APPROVED_PLAN_PAYLOAD="${TEST_ROOT}/reviewed-realnic-plan.payload"
printf '%s\n' '{"fixture":"explicitly-reviewed-realnic-plan"}' >"${APPROVED_PLAN_PAYLOAD}" ||
  fail 'approved plan payload fixture'
APPROVED_PLAN_SHA="$(sha256_file "${APPROVED_PLAN_PAYLOAD}")" || fail 'approved plan fixture digest'
APPROVED_PLAN="${BOUND_OUTPUT}/realnic-plan.${APPROVED_PLAN_SHA}.json"
/bin/cp -- "${APPROVED_PLAN_PAYLOAD}" "${APPROVED_PLAN}" || fail 'approved plan fixed-path fixture'
/bin/chmod 0600 "${APPROVED_PLAN}" || fail 'approved plan fixture mode'
REALNIC_BAD_SHA='cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd'
REALNIC_BAD_SHA_PLAN="${BOUND_OUTPUT}/realnic-plan.${REALNIC_BAD_SHA}.json"
printf '%s\n' '{"fixture":"wrong-digest"}' >"${REALNIC_BAD_SHA_PLAN}" ||
  fail 'realNIC wrong digest fixture'
/bin/chmod 0600 "${REALNIC_BAD_SHA_PLAN}" || fail 'realNIC wrong digest fixture mode'
expect_precredential_fence realnic-local-sha "${BOUND_MANIFEST}" \
  "${BOUND_MANIFEST_SHA}" realnic-run "${REALNIC_BAD_SHA}" 66 realnic-approved-plan-local
/bin/chmod 0644 "${APPROVED_PLAN}" || fail 'realNIC local shape drift fixture'
expect_precredential_fence realnic-local-shape "${BOUND_MANIFEST}" \
  "${BOUND_MANIFEST_SHA}" realnic-run "${APPROVED_PLAN_SHA}" 66 realnic-approved-plan-local
/bin/chmod 0600 "${APPROVED_PLAN}" || fail 'realNIC local shape restore'
for operation in realnic-run realnic-restore; do
  expect_transport_plan_leaf "approved-${operation}" "${BOUND_MANIFEST}" \
    "${BOUND_MANIFEST_SHA}" "${operation}" "${APPROVED_PLAN_SHA}"
done
APPROVED_VERIFY_OUTPUT="$(/usr/bin/expect "${TRANSPORT_HARNESS}" \
  "${FIXTURE_REVIEW}/locked-transport.exp" verify "${BOUND_MANIFEST}" \
  "${BOUND_MANIFEST_SHA}" realnic-run "${APPROVED_PLAN_SHA}")" ||
  fail 'realNIC approved-plan verify-only seam'
[[ "${APPROVED_VERIFY_OUTPUT}" == *'HARNESS_VERIFY_ONLY operation=realnic-run credential_reads=0 spawns=0 result=PASS'* ]] ||
  fail "realNIC approved-plan verify-only marker: ${APPROVED_VERIFY_OUTPUT}"
printf 'HERMETIC_REALNIC_PRECREDENTIAL bad_sha=blocked bad_shape=blocked valid=pass credential_reads=0 spawns=0\n'
APPROVED_CONTROLLER_ARGS=(
  "${CONTROLLER_ARGS[@]}"
  --approved-plan-sha256 "${APPROVED_PLAN_SHA}"
)
APPROVED_CONTROLLER_PLAN="$(/bin/bash "${FIXTURE_REVIEW}/controller.sh" plan \
  "${APPROVED_CONTROLLER_ARGS[@]}")" || fail 'approved controller plan'
for literal in \
  'operation=scp-realnic-approved-plan transport=scp credential_read=0 network_operations=0' \
  "${APPROVED_PLAN}" \
  'siyixuan@192.168.10.82:/home/siyixuan/wg-mix-ebpf-test/unpriv-4f2a9b61/realnic-approved-plan.json' \
  'operation=verify-sha-realnic-approved-plan transport=ssh credential_read=0 network_operations=0' \
  'operation=verify-stat-realnic-approved-plan transport=ssh credential_read=0 network_operations=0' \
  'operation=stage-realnic-plan-snapshot transport=ssh credential_read=0 network_operations=0' \
  'realnic-plan-snapshot --manifest /run/wg-mix-ebpf-source-bootstrap-c8e41d73/package-manifest.v1' \
  'operation=realnic-run transport=ssh credential_read=0 network_operations=0' \
  'realnic_acceptance.py run --source-commit' \
  '--approved-plan /run/wg-mix-ebpf-source-bootstrap-c8e41d73/realnic-approved-plan.json' \
  "--approved-plan-sha256 ${APPROVED_PLAN_SHA}" \
  'operation=stage-realnic-plan-verify transport=ssh credential_read=0 network_operations=0' \
  'realnic-plan-verify --manifest /run/wg-mix-ebpf-source-bootstrap-c8e41d73/package-manifest.v1' \
  'operation=realnic-restore transport=ssh credential_read=0 network_operations=0' \
  'realnic_acceptance.py restore --source-commit'; do
  [[ "${APPROVED_CONTROLLER_PLAN}" == *"${literal}"* ]] ||
    fail "approved controller plan missing ${literal}"
done
require_ordered_literals "${APPROVED_CONTROLLER_PLAN}" \
  'operation=scp-realnic-approved-plan ' \
  'operation=verify-sha-realnic-approved-plan ' \
  'operation=verify-stat-realnic-approved-plan ' \
  'operation=stage-realnic-plan-snapshot ' \
  'operation=realnic-run ' \
  'operation=stage-realnic-plan-verify ' \
  'operation=realnic-restore '
for dynamic in --run-id --run-root --expected-ifindex --expected-mac --expected-driver \
  --expected-device-path --expected-mtu --expected-boot-id --mtu-low; do
  [[ "${APPROVED_CONTROLLER_PLAN}" != *"${dynamic} "* ]] ||
    fail "approved controller retained dynamic CLI option ${dynamic}"
done

BOOTSTRAP_FIXTURE="${TEST_ROOT}/bootstrap-first-run-c8e41d73"
[[ ! -e "${BOOTSTRAP_FIXTURE}" && ! -L "${BOOTSTRAP_FIXTURE}" ]] || fail 'bootstrap fixture was not fresh'
/bin/test ! -e "${BOOTSTRAP_FIXTURE}" || fail 'bootstrap first-run absence gate'
/bin/test ! -L "${BOOTSTRAP_FIXTURE}" || fail 'bootstrap first-run symlink gate'
/bin/mkdir -m 0700 -- "${BOOTSTRAP_FIXTURE}" || fail 'bootstrap first-run creation'
if /bin/test ! -e "${BOOTSTRAP_FIXTURE}"; then
  fail 'pre-existing bootstrap passed the absence gate'
fi
BOOTSTRAP_SYMLINK_FIXTURE="${TEST_ROOT}/bootstrap-dangling-symlink-c8e41d73"
/bin/ln -s "${TEST_ROOT}/missing-bootstrap-target" "${BOOTSTRAP_SYMLINK_FIXTURE}" ||
  fail 'bootstrap dangling symlink fixture'
/bin/test ! -e "${BOOTSTRAP_SYMLINK_FIXTURE}" || fail 'dangling symlink fixture unexpectedly exists'
if /bin/test ! -L "${BOOTSTRAP_SYMLINK_FIXTURE}"; then
  fail 'dangling bootstrap symlink passed the symlink gate'
fi
printf 'HERMETIC_BOOTSTRAP first_run_reachable=1 preexisting_rejected=1 retained=%s\n' "${BOOTSTRAP_FIXTURE}"

IMMUTABLE_FIXTURE="${TEST_ROOT}/immutable-intake-c8e41d73"
/bin/mkdir -m 0700 -- "${IMMUTABLE_FIXTURE}" || fail 'immutable intake fixture creation'
MANIFEST_GOOD="${IMMUTABLE_FIXTURE}/manifest-good.v1"
MANIFEST_EVIL="${IMMUTABLE_FIXTURE}/manifest-evil.v1"
MANIFEST_SOURCE="${IMMUTABLE_FIXTURE}/manifest-source.v1"
MANIFEST_SNAPSHOT="${IMMUTABLE_FIXTURE}/manifest-snapshot.v1"
printf 'decision\ttrusted\n' >"${MANIFEST_GOOD}" || fail 'trusted manifest fixture'
printf 'decision\tuntrusted\n' >"${MANIFEST_EVIL}" || fail 'untrusted manifest fixture'
/bin/cp -- "${MANIFEST_GOOD}" "${MANIFEST_SOURCE}" || fail 'old manifest source setup'
OLD_MANIFEST_SHA="$(sha256_file "${MANIFEST_SOURCE}")" || fail 'old manifest hash gate'
/bin/cp -- "${MANIFEST_EVIL}" "${MANIFEST_SOURCE}" || fail 'old manifest evil swap'
OLD_MANIFEST_VALUE="$(/usr/bin/awk -F '\t' '$1 == "decision" { print $2 }' "${MANIFEST_SOURCE}")" ||
  fail 'old manifest reopen'
[[ "${OLD_MANIFEST_SHA}" == "$(sha256_file "${MANIFEST_GOOD}")" &&
  "${OLD_MANIFEST_VALUE}" == 'untrusted' ]] || fail 'old manifest TOCTOU was not reproduced'
/bin/cp -- "${MANIFEST_GOOD}" "${MANIFEST_SOURCE}" || fail 'manifest source good restore'
(umask 077
  set -o noclobber
  /bin/cat -- "${MANIFEST_SOURCE}" >"${MANIFEST_SNAPSHOT}") || fail 'manifest intake copy'
/bin/cp -- "${MANIFEST_EVIL}" "${MANIFEST_SOURCE}" || fail 'manifest post-copy evil swap'
/bin/cp -- "${MANIFEST_GOOD}" "${MANIFEST_SOURCE}" || fail 'manifest post-copy good restore'
[[ "$(sha256_file "${MANIFEST_SNAPSHOT}")" == "$(sha256_file "${MANIFEST_GOOD}")" &&
  "$(/usr/bin/awk -F '\t' '$1 == "decision" { print $2 }' "${MANIFEST_SNAPSHOT}")" == 'trusted' ]] ||
  fail 'immutable manifest copy changed after source replacement'
if (set -o noclobber
  /bin/cat -- "${MANIFEST_EVIL}" >"${MANIFEST_SNAPSHOT}") \
  2>"${IMMUTABLE_FIXTURE}/manifest-noclobber.err"; then
  fail 'immutable manifest destination was clobbered'
fi

BUNDLE_SOURCE="${IMMUTABLE_FIXTURE}/bundle-source.bundle"
BUNDLE_SNAPSHOT="${IMMUTABLE_FIXTURE}/bundle-snapshot.bundle"
/bin/cp -- "${BOUND_OUTPUT}/source-4f2a9b61.bundle" "${BUNDLE_SOURCE}" || fail 'old bundle source setup'
/usr/bin/git -C "${FIXTURE_REPOSITORY}" bundle verify "${BUNDLE_SOURCE}" || fail 'old bundle verify gate'
printf 'replacement-after-verify\n' >"${BUNDLE_SOURCE}" || fail 'old bundle replacement'
if /usr/bin/git -C "${FIXTURE_REPOSITORY}" bundle verify "${BUNDLE_SOURCE}" \
  >"${IMMUTABLE_FIXTURE}/old-bundle-reopen.log" 2>&1; then
  fail 'old bundle reopen unexpectedly consumed the verified bytes'
fi
/bin/cp -- "${BOUND_OUTPUT}/source-4f2a9b61.bundle" "${BUNDLE_SOURCE}" || fail 'bundle source restore'
(umask 077
  set -o noclobber
  /bin/cat -- "${BUNDLE_SOURCE}" >"${BUNDLE_SNAPSHOT}") || fail 'bundle intake copy'
printf 'replacement-after-copy\n' >"${BUNDLE_SOURCE}" || fail 'bundle post-copy replacement'
[[ "$(sha256_file "${BUNDLE_SNAPSHOT}")" == \
  "$(manifest_value bundle_sha256 "${BOUND_MANIFEST}")" ]] || fail 'immutable bundle digest'
/usr/bin/git -C "${FIXTURE_REPOSITORY}" bundle verify "${BUNDLE_SNAPSHOT}" ||
  fail 'immutable bundle verify'
IMMUTABLE_CLONE="${IMMUTABLE_FIXTURE}/source"
/usr/bin/git clone --no-local --no-checkout --single-branch --branch "${FIXTURE_BRANCH}" -- \
  "${BUNDLE_SNAPSHOT}" "${IMMUTABLE_CLONE}" || fail 'immutable bundle clone'
/usr/bin/git -C "${IMMUTABLE_CLONE}" checkout --detach "${FIXTURE_COMMIT}" ||
  fail 'immutable bundle checkout'
[[ "$(/usr/bin/git -C "${IMMUTABLE_CLONE}" rev-parse HEAD)" == "${FIXTURE_COMMIT}" ]] ||
  fail 'immutable clone commit mismatch'
printf 'HERMETIC_IMMUTABLE_INTAKE old_manifest_reopen=failed old_bundle_reopen=failed root_copy_only=pass retained=%s\n' \
  "${IMMUTABLE_FIXTURE}"

REALNIC_INTAKE_FIXTURE="${TEST_ROOT}/realnic-approved-plan-intake"
/bin/mkdir -m 0700 -- "${REALNIC_INTAKE_FIXTURE}" || fail 'realNIC intake fixture creation'
REALNIC_INTAKE="${REALNIC_INTAKE_FIXTURE}/user-plan.json"
REALNIC_SNAPSHOT="${REALNIC_INTAKE_FIXTURE}/root-plan.json"
printf '%s\n' '{"approved":"exact-held-fd-bytes"}' >"${REALNIC_INTAKE}" || fail 'realNIC intake bytes'
/bin/chmod 0600 "${REALNIC_INTAKE}" || fail 'realNIC intake mode'
REALNIC_INTAKE_SHA="$(sha256_file "${REALNIC_INTAKE}")" || fail 'realNIC intake hash'
approved_plan_snapshot_fixture "${REALNIC_INTAKE}" "${REALNIC_SNAPSHOT}" \
  "${REALNIC_INTAKE_SHA}" || fail 'realNIC fresh snapshot'
approved_plan_snapshot_fixture "${REALNIC_INTAKE}" "${REALNIC_SNAPSHOT}" \
  "${REALNIC_INTAKE_SHA}" || fail 'realNIC exact snapshot retry'
/bin/mv -- "${REALNIC_INTAKE}" "${REALNIC_INTAKE}.held" || fail 'realNIC remove intake before restore'
approved_plan_verify_fixture "${REALNIC_SNAPSHOT}" "${REALNIC_INTAKE_SHA}" ||
  fail 'realNIC restore-only root snapshot verify'
/bin/mv -- "${REALNIC_INTAKE}.held" "${REALNIC_INTAKE}" || fail 'realNIC restore intake fixture'

for cut in partial-write post-fsync post-link; do
  target="${REALNIC_INTAKE_FIXTURE}/root-plan-${cut}.json"
  cut_rc=0
  approved_plan_snapshot_fixture "${REALNIC_INTAKE}" "${target}" \
    "${REALNIC_INTAKE_SHA}" "${cut}" || cut_rc=$?
  case "${cut}:${cut_rc}" in
    partial-write:91 | post-fsync:92 | post-link:93) ;;
    *) fail "realNIC ${cut} did not stop at its exact cut: rc=${cut_rc}" ;;
  esac
  approved_plan_snapshot_fixture "${REALNIC_INTAKE}" "${target}" \
    "${REALNIC_INTAKE_SHA}" || fail "realNIC ${cut} retry did not converge"
  approved_plan_verify_fixture "${target}" "${REALNIC_INTAKE_SHA}" ||
    fail "realNIC ${cut} retry terminal identity"
done

foreign_final="${REALNIC_INTAKE_FIXTURE}/root-plan-foreign-final.json"
foreign_pending="${foreign_final}.pending.${REALNIC_INTAKE_SHA}"
/bin/cp -- "${REALNIC_INTAKE}" "${foreign_final}" || fail 'foreign final fixture'
/bin/cp -- "${REALNIC_INTAKE}" "${foreign_pending}" || fail 'foreign pending fixture'
/bin/chmod 0600 "${foreign_final}" "${foreign_pending}" || fail 'foreign final mode'
if approved_plan_snapshot_fixture "${REALNIC_INTAKE}" "${foreign_final}" "${REALNIC_INTAKE_SHA}"; then
  fail 'same-content foreign final inode was accepted'
fi

for cut in symlink mode nlink; do
  target="${REALNIC_INTAKE_FIXTURE}/root-plan-pending-${cut}.json"
  pending="${target}.pending.${REALNIC_INTAKE_SHA}"
  case "${cut}" in
    symlink) /bin/ln -s "${REALNIC_INTAKE}" "${pending}" ;;
    mode)
      : >"${pending}"
      /bin/chmod 0644 "${pending}"
      ;;
    nlink)
      : >"${pending}"
      /bin/chmod 0600 "${pending}"
      /bin/ln -- "${pending}" "${pending}.extra"
      ;;
  esac || fail "pending ${cut} fixture"
  if approved_plan_snapshot_fixture "${REALNIC_INTAKE}" "${target}" "${REALNIC_INTAKE_SHA}"; then
    fail "pending ${cut} drift was accepted"
  fi
done

inode_swap_final="${REALNIC_INTAKE_FIXTURE}/root-plan-inode-swap.json"
inode_swap_rc=0
approved_plan_snapshot_fixture "${REALNIC_INTAKE}" "${inode_swap_final}" \
  "${REALNIC_INTAKE_SHA}" inode-swap || inode_swap_rc=$?
[[ "${inode_swap_rc}" -eq 79 && ! -e "${inode_swap_final}" &&
  -f "${inode_swap_final}.pending.${REALNIC_INTAKE_SHA}.swapped-out" ]] ||
  fail "pending inode swap was not retained and rejected: rc=${inode_swap_rc}"
approved_plan_snapshot_fixture "${REALNIC_INTAKE}" "${inode_swap_final}" \
  "${REALNIC_INTAKE_SHA}" || fail 'pending inode swap retry did not converge'

extra_link_final="${REALNIC_INTAKE_FIXTURE}/root-plan-extra-link.json"
approved_plan_snapshot_fixture "${REALNIC_INTAKE}" "${extra_link_final}" \
  "${REALNIC_INTAKE_SHA}" || fail 'extra-link terminal setup'
/bin/ln -- "${extra_link_final}" "${extra_link_final}.extra" || fail 'extra-link injection'
if approved_plan_verify_fixture "${extra_link_final}" "${REALNIC_INTAKE_SHA}"; then
  fail 'published plan with nlink greater than two was accepted'
fi
if approved_plan_snapshot_fixture "${REALNIC_INTAKE}" "${extra_link_final}" "${REALNIC_INTAKE_SHA}"; then
  fail 'published plan retry accepted nlink greater than two'
fi

old_sha='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
different_sha_final="${REALNIC_INTAKE_FIXTURE}/root-plan-different-sha.json"
printf 'retained-old-sha-partial\n' >"${different_sha_final}.pending.${old_sha}" ||
  fail 'different-SHA pending fixture'
/bin/chmod 0600 "${different_sha_final}.pending.${old_sha}" || fail 'different-SHA mode'
approved_plan_snapshot_fixture "${REALNIC_INTAKE}" "${different_sha_final}" \
  "${REALNIC_INTAKE_SHA}" || fail 'different-SHA old pending blocked current authority'
[[ "$(/bin/cat -- "${different_sha_final}.pending.${old_sha}")" == \
  'retained-old-sha-partial' ]] || fail 'different-SHA evidence changed'

PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -B -I -c \
  'import fcntl, hashlib, os, stat, sys
root, payload_path, expected = sys.argv[1:]
payload = open(payload_path, "rb").read()
if hashlib.sha256(payload).hexdigest() != expected:
    raise SystemExit("fixture payload digest")
lock_path = os.path.join(root, "physical.lock")
pending = os.path.join(root, f"concurrent.json.pending.{expected}")
final = os.path.join(root, "concurrent.json")
first = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
second = os.open(lock_path, os.O_RDWR)
try:
    fcntl.flock(first, fcntl.LOCK_EX | fcntl.LOCK_NB)
    pending_fd = os.open(pending, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    os.write(pending_fd, payload[:5])
    try:
        fcntl.flock(second, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        pass
    else:
        raise SystemExit("second snapshot entered while pending was mutable")
    os.ftruncate(pending_fd, 0)
    os.lseek(pending_fd, 0, os.SEEK_SET)
    offset = 0
    while offset < len(payload):
        written = os.write(pending_fd, payload[offset:])
        if written <= 0:
            raise SystemExit("write made no progress")
        offset += written
    os.fsync(pending_fd)
    parent_fd = os.open(root, os.O_RDONLY)
    os.fsync(parent_fd)
    os.close(parent_fd)
    os.link(pending, final)
    parent_fd = os.open(root, os.O_RDONLY)
    os.fsync(parent_fd)
    os.close(parent_fd)
    os.close(pending_fd)
    fcntl.flock(first, fcntl.LOCK_UN)
    fcntl.flock(second, fcntl.LOCK_EX | fcntl.LOCK_NB)
    left, right = os.stat(final), os.stat(pending)
    if (left.st_dev, left.st_ino) != (right.st_dev, right.st_ino) or left.st_nlink != 2:
        raise SystemExit("terminal inode contract")
    if open(final, "rb").read() != payload:
        raise SystemExit("published payload changed")
finally:
    os.close(second)
    os.close(first)' "${REALNIC_INTAKE_FIXTURE}" "${REALNIC_INTAKE}" "${REALNIC_INTAKE_SHA}" ||
  fail 'physical-lock concurrent snapshot model'

HELD_SOURCE="${REALNIC_INTAKE_FIXTURE}/held-source.json"
HELD_DESTINATION="${REALNIC_INTAKE_FIXTURE}/held-destination.json"
/bin/cp -- "${REALNIC_INTAKE}" "${HELD_SOURCE}" || fail 'held-FD source setup'
exec 8<"${HELD_SOURCE}" || fail 'held-FD open'
printf '%s\n' '{"approved":"replacement"}' >"${HELD_SOURCE}.replacement" ||
  fail 'held-FD replacement bytes'
/bin/mv -- "${HELD_SOURCE}.replacement" "${HELD_SOURCE}" || fail 'held-FD source replacement'
(umask 077
  set -o noclobber
  /bin/cat -- /dev/fd/8 >"${HELD_DESTINATION}") || fail 'held-FD snapshot copy'
[[ "$(sha256_file "${HELD_DESTINATION}")" == "${REALNIC_INTAKE_SHA}" &&
  "$(sha256_file "${HELD_SOURCE}")" != "${REALNIC_INTAKE_SHA}" ]] ||
  fail 'held-FD bytes were not isolated from path replacement'
printf 'HERMETIC_REALNIC_APPROVED_PLAN fresh=pass retry=durable-link restore=no-intake-copy cuts=10 concurrent_lock=pass held_fd=pass retained=%s\n' \
  "${REALNIC_INTAKE_FIXTURE}"

STAGE_PLAN="$(/bin/bash "${BOUND_OUTPUT}/prepare-stage-root.sh" snapshot-plan \
  --manifest /home/siyixuan/wg-mix-ebpf-test/unpriv-4f2a9b61/package-manifest.v1 \
  --manifest-sha256 "${BOUND_MANIFEST_SHA}")" || fail 'root snapshot plan'
for literal in \
  'B82_V6_SNAPSHOT_PLAN run_id=c8e41d73' \
  'shell-builtin noclobber-copy /home/siyixuan/wg-mix-ebpf-test/unpriv-4f2a9b61/package-manifest.v1 /run/wg-mix-ebpf-source-bootstrap-c8e41d73/package-manifest.v1' \
  'shell-builtin noclobber-copy /home/siyixuan/wg-mix-ebpf-test/unpriv-4f2a9b61/source-4f2a9b61.bundle /run/wg-mix-ebpf-source-bootstrap-c8e41d73/source-4f2a9b61.bundle' \
  'shell-builtin parse-verified-root-manifest /run/wg-mix-ebpf-source-bootstrap-c8e41d73/package-manifest.v1' \
  'B82_V6_SNAPSHOT_PLAN_COMPLETE no_commands_executed=1 no_cleanup=1 failure_resources_retained=1'; do
  [[ "${STAGE_PLAN}" == *"${literal}"* ]] || fail "snapshot plan missing ${literal}"
done
require_ordered_literals "${STAGE_PLAN}" 'C4 argv=' 'C7 argv=' 'C8 argv=' 'C11 argv=' 'C14 argv='

expect_failure wrong-manifest-sha /bin/bash "${FIXTURE_REVIEW}/controller.sh" plan \
  --manifest "${BOUND_MANIFEST}" \
  --manifest-sha256 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  --credential-path "${CREDENTIAL_PATH}"
expect_failure existing-output /bin/bash "${FIXTURE_REVIEW}/bind-final-package.sh" bind "${BIND_ARGS[@]}"
expect_failure ref-commit-mismatch /bin/bash "${FIXTURE_REVIEW}/bind-final-package.sh" plan \
  --repository "${FIXTURE_REPOSITORY}" --source-ref "${FIXTURE_REF}" \
  --commit aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --wg-state bound \
  --wg-interface wg0 --wg-local-address 10.200.0.1 --wg-peer-address 10.200.0.2 \
  --output-dir /private/tmp/wg-mix-b82-v6-c8e41d73-4f2a9b61-aaaaaaaaaaaa
expect_failure inconsistent-absent-binding /bin/bash "${FIXTURE_REVIEW}/bind-final-package.sh" plan \
  --repository "${FIXTURE_REPOSITORY}" --source-ref "${FIXTURE_REF}" --commit "${FIXTURE_COMMIT}" \
  --wg-state absent --wg-interface wg0 --wg-local-address absent --wg-peer-address absent \
  --output-dir "${BOUND_OUTPUT}"
expect_failure invalid-transport-operation /usr/bin/expect "${FIXTURE_REVIEW}/locked-transport.exp" \
  --manifest "${BOUND_MANIFEST}" --manifest-sha256 "${BOUND_MANIFEST_SHA}" \
  --credential-path "${CREDENTIAL_PATH}" --action plan --operation arbitrary-command \
  --approved-plan-sha256 none
expect_failure retired-matrix-run-transport /usr/bin/expect "${FIXTURE_REVIEW}/locked-transport.exp" \
  --manifest "${BOUND_MANIFEST}" --manifest-sha256 "${BOUND_MANIFEST_SHA}" \
  --credential-path "${CREDENTIAL_PATH}" --action plan --operation matrix-run \
  --approved-plan-sha256 none
expect_failure retired-matrix-restore-transport /usr/bin/expect "${FIXTURE_REVIEW}/locked-transport.exp" \
  --manifest "${BOUND_MANIFEST}" --manifest-sha256 "${BOUND_MANIFEST_SHA}" \
  --credential-path "${CREDENTIAL_PATH}" --action plan --operation matrix-restore-tcx \
  --approved-plan-sha256 none
expect_failure retired-matrix-controller-mode /bin/bash "${FIXTURE_REVIEW}/controller.sh" restore \
  "${CONTROLLER_ARGS[@]}" --restore-cell tcx
expect_failure credential-path-before-spawn /usr/bin/expect "${FIXTURE_REVIEW}/locked-transport.exp" \
  --manifest "${BOUND_MANIFEST}" --manifest-sha256 "${BOUND_MANIFEST_SHA}" \
  --credential-path /private/tmp/not-a-credential --action execute --operation identity-hostname \
  --approved-plan-sha256 none
expect_failure removed-public-approved-plan /bin/bash "${FIXTURE_REVIEW}/controller.sh" plan \
  "${CONTROLLER_ARGS[@]}" --approved-plan "${APPROVED_PLAN}"
expect_failure package-stager-root-run /bin/bash "${BOUND_OUTPUT}/prepare-stage-root.sh" run \
  --manifest "${BOUND_MANIFEST}" --manifest-sha256 "${BOUND_MANIFEST_SHA}"

SHALLOW_REPOSITORY="${TEST_ROOT}/shallow-repository"
/usr/bin/git clone --depth 1 --branch "${FIXTURE_BRANCH}" \
  "file://${FIXTURE_REPOSITORY}" "${SHALLOW_REPOSITORY}" || fail 'shallow fixture clone'
[[ "$(/usr/bin/git -C "${SHALLOW_REPOSITORY}" rev-parse --is-shallow-repository)" == 'true' ]] ||
  fail 'shallow fixture is not shallow'
/usr/bin/git -C "${SHALLOW_REPOSITORY}" config user.name 'Hermetic Shallow Test' || fail 'shallow Git name'
/usr/bin/git -C "${SHALLOW_REPOSITORY}" config user.email 'hermetic-shallow@example.invalid' || fail 'shallow Git email'
printf 'shallow-child=%s\n' "${TEST_ROOT##*/}" >"${SHALLOW_REPOSITORY}/shallow-child.v1" ||
  fail 'shallow child fixture'
/usr/bin/git -C "${SHALLOW_REPOSITORY}" add -- shallow-child.v1 || fail 'shallow child add'
/usr/bin/git -C "${SHALLOW_REPOSITORY}" commit -m 'Hermetic shallow child' || fail 'shallow child commit'
SHALLOW_COMMIT="$(/usr/bin/git -C "${SHALLOW_REPOSITORY}" rev-parse HEAD)" || fail 'shallow fixture commit'
SHALLOW_OUTPUT="/private/tmp/wg-mix-b82-v6-c8e41d73-4f2a9b61-${SHALLOW_COMMIT:0:12}"
SHALLOW_ARGS=(
  --repository "${SHALLOW_REPOSITORY}" --source-ref "${FIXTURE_REF}" --commit "${SHALLOW_COMMIT}"
  --wg-state bound --wg-interface wg0 --wg-local-address 10.200.0.1 --wg-peer-address 10.200.0.2
  --output-dir "${SHALLOW_OUTPUT}"
)
expect_failure shallow-plan /bin/bash \
  "${SHALLOW_REPOSITORY}/scripts/realhost-b82-c8e41d73/bind-final-package.sh" plan "${SHALLOW_ARGS[@]}"
expect_failure shallow-bind /bin/bash \
  "${SHALLOW_REPOSITORY}/scripts/realhost-b82-c8e41d73/bind-final-package.sh" bind "${SHALLOW_ARGS[@]}"
[[ ! -e "${SHALLOW_OUTPUT}" && ! -L "${SHALLOW_OUTPUT}" ]] || fail 'shallow bind created output'

printf '?ffffffffffffffffffffffffffffffffffffffff\n' >>"${BOUND_OUTPUT}/history-objects.v1" ||
  fail 'history evidence tamper fixture'
expect_failure tampered-history-evidence /bin/bash "${FIXTURE_REVIEW}/controller.sh" plan "${CONTROLLER_ARGS[@]}"

printf 'fixture-absent=%s\n' "${TEST_ROOT##*/}" >>"${FIXTURE_REPOSITORY}/fixture-token.v1" ||
  fail 'absent fixture token'
/usr/bin/git -C "${FIXTURE_REPOSITORY}" add -- fixture-token.v1 || fail 'absent fixture add'
/usr/bin/git -C "${FIXTURE_REPOSITORY}" commit -m 'Hermetic absent WireGuard fixture' || fail 'absent fixture commit'
ABSENT_COMMIT="$(/usr/bin/git -C "${FIXTURE_REPOSITORY}" rev-parse HEAD)" || fail 'absent commit'
ABSENT_OUTPUT="/private/tmp/wg-mix-b82-v6-c8e41d73-4f2a9b61-${ABSENT_COMMIT:0:12}"
ABSENT_ARGS=(
  --repository "${FIXTURE_REPOSITORY}" --source-ref "${FIXTURE_REF}" --commit "${ABSENT_COMMIT}"
  --wg-state absent --wg-interface absent --wg-local-address absent --wg-peer-address absent
  --output-dir "${ABSENT_OUTPUT}"
)
/bin/bash "${FIXTURE_REVIEW}/bind-final-package.sh" bind "${ABSENT_ARGS[@]}" || fail 'absent package binding'
ABSENT_MANIFEST="${ABSENT_OUTPUT}/package-manifest.v1"
ABSENT_MANIFEST_SHA="$(sha256_file "${ABSENT_MANIFEST}")" || fail 'absent manifest digest'
ABSENT_CONTROLLER_ARGS=(
  --manifest "${ABSENT_MANIFEST}" --manifest-sha256 "${ABSENT_MANIFEST_SHA}"
  --credential-path "${CREDENTIAL_PATH}"
)
for operation in veth-plan veth-run veth-restore; do
  expect_transport_plan_leaf "absent-${operation}" "${ABSENT_MANIFEST}" \
    "${ABSENT_MANIFEST_SHA}" "${operation}" none
done
printf 'HERMETIC_PLAN_RENDER bound_leaves=9 approved_realnic_leaves=2 absent_veth_leaves=3 total=14 credential_read=0 network_operations=0\n'
ABSENT_PLAN="$(/bin/bash "${FIXTURE_REVIEW}/controller.sh" plan "${ABSENT_CONTROLLER_ARGS[@]}")" ||
  fail 'absent controller plan'
[[ "${ABSENT_PLAN}" == *'B82_V6_LEGACY_MATRIX_RETIRED controller_entries=0 historical_recovery=frozen-original-package-before-final-staging'* ]] ||
  fail 'absent WireGuard legacy retirement marker missing'
[[ "${ABSENT_PLAN}" != *'operation=matrix-'* ]] || fail 'absent plan rendered legacy matrix execution'
for operation in fresh-plan fresh-run fresh-restore; do
  [[ "${ABSENT_PLAN}" == *"operation=${operation} transport=ssh credential_read=0 network_operations=0"* ]] ||
    fail "absent WireGuard plan cannot reach ${operation}"
done
for operation in veth-plan veth-run veth-restore routed-plan routed-run routed-restore; do
  [[ "${ABSENT_PLAN}" == *"operation=${operation} transport=ssh credential_read=0 network_operations=0"* ]] ||
    fail "absent WireGuard plan cannot reach ${operation}"
done
[[ "${ABSENT_PLAN}" == *'operation=realnic-plan transport=ssh credential_read=0 network_operations=0'* ]] ||
  fail 'absent WireGuard plan cannot reach realnic-plan'
ABSENT_APPROVED_PLAN="${ABSENT_OUTPUT}/realnic-plan.${APPROVED_PLAN_SHA}.json"
/bin/cp -- "${APPROVED_PLAN_PAYLOAD}" "${ABSENT_APPROVED_PLAN}" ||
  fail 'absent approved plan fixed-path fixture'
/bin/chmod 0600 "${ABSENT_APPROVED_PLAN}" || fail 'absent approved plan fixture mode'
ABSENT_APPROVED_ARGS=(
  "${ABSENT_CONTROLLER_ARGS[@]}"
  --approved-plan-sha256 "${APPROVED_PLAN_SHA}"
)
ABSENT_APPROVED_PLAN="$(/bin/bash "${FIXTURE_REVIEW}/controller.sh" plan \
  "${ABSENT_APPROVED_ARGS[@]}")" || fail 'absent approved controller plan'
for operation in realnic-plan realnic-run realnic-restore; do
  [[ "${ABSENT_APPROVED_PLAN}" == *"operation=${operation} transport=ssh credential_read=0 network_operations=0"* ]] ||
    fail "absent WireGuard approved plan cannot reach ${operation}"
done
ABSENT_FRESH_TRANSPORT="$(/usr/bin/expect "${FIXTURE_REVIEW}/locked-transport.exp" \
  --manifest "${ABSENT_MANIFEST}" --manifest-sha256 "${ABSENT_MANIFEST_SHA}" \
  --credential-path "${CREDENTIAL_PATH}" --action plan --operation fresh-run \
  --approved-plan-sha256 none)" ||
  fail 'absent fresh transport plan'
[[ "${ABSENT_FRESH_TRANSPORT}" == *'credential_read=0 network_operations=0'* &&
  "${ABSENT_FRESH_TRANSPORT}" == *'root-fresh-verifier-gate.sh run --controller-source'* ]] ||
  fail 'absent fresh transport reachability'
ABSENT_VETH_TRANSPORT="$(/usr/bin/expect "${FIXTURE_REVIEW}/locked-transport.exp" \
  --manifest "${ABSENT_MANIFEST}" --manifest-sha256 "${ABSENT_MANIFEST_SHA}" \
  --credential-path "${CREDENTIAL_PATH}" --action plan --operation veth-plan \
  --approved-plan-sha256 none)" || fail 'absent veth transport plan'
ABSENT_BUNDLE_SHA="$(manifest_value bundle_sha256 "${ABSENT_MANIFEST}")" ||
  fail 'absent bundle digest'
[[ "${ABSENT_VETH_TRANSPORT}" == *"/bin/bash -p /run/wg-mix-ebpf-source-stages/c8e41d73/source/scripts/realhost-b82-c8e41d73/root-veth-n-r.sh plan --controller-source /run/wg-mix-ebpf-source-stages/c8e41d73/source --commit ${ABSENT_COMMIT} --bundle /run/wg-mix-ebpf-source-bootstrap-c8e41d73/source-4f2a9b61.bundle --bundle-sha256 ${ABSENT_BUNDLE_SHA} --wg-state absent"$'\n''EXPECT_OUTPUT_ASSERTION none' ]] ||
  fail 'absent veth transport does not use the exact root-owned bundle argv'
ABSENT_ROUTED_TRANSPORT="$(/usr/bin/expect "${FIXTURE_REVIEW}/locked-transport.exp" \
  --manifest "${ABSENT_MANIFEST}" --manifest-sha256 "${ABSENT_MANIFEST_SHA}" \
  --credential-path "${CREDENTIAL_PATH}" --action plan --operation routed-plan \
  --approved-plan-sha256 none)" || fail 'absent routed transport plan'
[[ "${ABSENT_ROUTED_TRANSPORT}" == *"/bin/bash -p /run/wg-mix-ebpf-source-stages/c8e41d73/source/scripts/realhost-b82-routed-veth-v1/controller-seam.sh plan --commit ${ABSENT_COMMIT}"$'\n''EXPECT_OUTPUT_ASSERTION none' ]] ||
  fail 'absent routed transport argv extends beyond the staged seam and commit'
expect_exact_rc capture-non-realnic-operation 65 /usr/bin/expect \
  "${FIXTURE_REVIEW}/locked-transport.exp" \
  --manifest "${ABSENT_MANIFEST}" --manifest-sha256 "${ABSENT_MANIFEST_SHA}" \
  --credential-path "${CREDENTIAL_PATH}" --action capture --operation identity-hostname \
  --approved-plan-sha256 none
expect_exact_rc execute-realnic-plan 65 /usr/bin/expect \
  "${FIXTURE_REVIEW}/locked-transport.exp" \
  --manifest "${ABSENT_MANIFEST}" --manifest-sha256 "${ABSENT_MANIFEST_SHA}" \
  --credential-path "${CREDENTIAL_PATH}" --action execute --operation realnic-plan \
  --approved-plan-sha256 none
expect_failure retired-matrix-run-mode /bin/bash "${FIXTURE_REVIEW}/controller.sh" run \
  "${ABSENT_CONTROLLER_ARGS[@]}"

printf '%s\n' \
  'hermetic v6 full-history binder, explicit toolchain state machine, root-owned bootstrap,' \
  'SSH/SCP/Expect fixed check/apply plans, provision output policy,' \
  'immutable-intake/shallow/failure paths and WireGuard-absent fresh/realNIC reachability: PASS'
printf 'RETAINED_HERMETIC_ROOT path=%s reason=auditable-no-cleanup-test-policy\n' "${TEST_ROOT}"
