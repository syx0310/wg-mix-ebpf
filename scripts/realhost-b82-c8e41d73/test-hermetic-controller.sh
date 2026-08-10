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
readonly R2_PREDECESSOR_FIXED_PACKAGE='/private/tmp/wg-mix-b82-v6-c8e41d73-4f2a9b61-f75fe7678cfd'
readonly R2_PREDECESSOR_MANIFEST_SHA256='2d6c6caac080b599fbfa0f73c64f6976cf30d1504fc506ebd39c638b2f9449e3'
readonly R2_PREDECESSOR_COMMIT='f75fe7678cfdecf08173fd201be5c055417d6e11'

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
R2_PREDECESSOR_CLONE="${TEST_ROOT}/f75-predecessor-package"
[[ -d "${R2_PREDECESSOR_FIXED_PACKAGE}" &&
  ! -L "${R2_PREDECESSOR_FIXED_PACKAGE}" ]] ||
  fail 'fixed f75 predecessor package is unavailable'
/bin/cp -R -- "${R2_PREDECESSOR_FIXED_PACKAGE}" "${R2_PREDECESSOR_CLONE}" ||
  fail 'f75 predecessor copy-on-test fixture'
[[ -d "${R2_PREDECESSOR_CLONE}" && ! -L "${R2_PREDECESSOR_CLONE}" &&
  "$(sha256_file "${R2_PREDECESSOR_CLONE}/package-manifest.v1")" == \
  "${R2_PREDECESSOR_MANIFEST_SHA256}" ]] ||
  fail 'f75 predecessor clone identity'
FIXTURE_REPOSITORY="${TEST_ROOT}/repository"
FIXTURE_REVIEW="${FIXTURE_REPOSITORY}/scripts/realhost-b82-c8e41d73"
FIXTURE_REALNIC="${FIXTURE_REPOSITORY}/scripts/realhost-b82-acceptance-v1"
FIXTURE_ROUTED="${FIXTURE_REPOSITORY}/scripts/realhost-b82-routed-veth-v1"
FIXTURE_CHECKSUM_KERNEL="${FIXTURE_REPOSITORY}/kernel/faketcp_checksum"
/bin/mkdir -m 0700 -- "${FIXTURE_REPOSITORY}" || fail 'fixture repository creation'
/usr/bin/git -C "${FIXTURE_REPOSITORY}" init || fail 'fixture Git init'
/usr/bin/git -C "${FIXTURE_REPOSITORY}" config user.name 'Hermetic Controller Test' || fail 'fixture Git name'
/usr/bin/git -C "${FIXTURE_REPOSITORY}" config user.email 'hermetic-controller@example.invalid' || fail 'fixture Git email'
printf 'history-root=%s\n' "${TEST_ROOT##*/}" >"${FIXTURE_REPOSITORY}/history-root.v1" ||
  fail 'fixture history root'
/usr/bin/git -C "${FIXTURE_REPOSITORY}" add -- history-root.v1 || fail 'fixture history root add'
/usr/bin/git -C "${FIXTURE_REPOSITORY}" commit -m 'Hermetic history root' || fail 'fixture history root commit'
/bin/mkdir -p -- "${FIXTURE_REVIEW}" "${FIXTURE_REALNIC}" "${FIXTURE_ROUTED}" \
  "${FIXTURE_CHECKSUM_KERNEL}" ||
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
/bin/cp -- "${REPOSITORY}/kernel/faketcp_checksum/wg_mix_faketcp_checksum.c" \
  "${FIXTURE_CHECKSUM_KERNEL}/wg_mix_faketcp_checksum.c" ||
  fail 'fixture copy checksum module source'
/bin/chmod 0600 "${FIXTURE_CHECKSUM_KERNEL}/wg_mix_faketcp_checksum.c" ||
  fail 'fixture checksum module source mode'
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
/usr/bin/git -C "${FIXTURE_REPOSITORY}" add -- scripts kernel fixture-token.v1 ||
  fail 'fixture Git add'
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
BOUND_MATRIX_OUTPUT="$(/bin/bash "${BOUND_OUTPUT}/test-hermetic-matrix.sh")" ||
  fail 'bound flat matrix dependency closure'
[[ "${BOUND_MATRIX_OUTPUT}" == \
  *'hermetic shared checksum-module exact scopes, ABI and failure-cut classifier: PASS'* &&
  "${BOUND_MATRIX_OUTPUT}" == *'hermetic retired matrix and root-stager reservation cuts: PASS'* ]] ||
  fail 'bound flat matrix dependency closure markers'
BOUND_CLOSURE_MISSING_CUTS=0
for name in test-hermetic-checksum-module-lease.sh \
  test_checksum_module_lease_static.py wg_mix_faketcp_checksum.c; do
  bound_file="${BOUND_OUTPUT}/${name}"
  bound_backup="${TEST_ROOT}/bound-closure-${name}.backup"
  /bin/mv -- "${bound_file}" "${bound_backup}" ||
    fail "${name}: create bound closure missing fixture"
  bound_missing_output="$(/bin/bash "${BOUND_OUTPUT}/test-hermetic-matrix.sh" 2>&1)"
  bound_missing_rc=$?
  if [[ "${bound_missing_rc}" -eq 0 ||
    "${bound_missing_output}" != *"review input is not a regular file: ${bound_file}"* ]]; then
    /bin/mv -- "${bound_backup}" "${bound_file}" ||
      fail "${name}: restore after unexpected bound closure result"
    fail "${name}: bound flat closure missing artifact did not fail closed: rc=${bound_missing_rc} output=${bound_missing_output}"
  fi
  /bin/mv -- "${bound_backup}" "${bound_file}" ||
    fail "${name}: restore bound closure artifact"
  key="${name//-/_}"
  key="${key//./_}"
  [[ -f "${bound_file}" && ! -L "${bound_file}" &&
    "$(sha256_file "${bound_file}")" == "$(manifest_value "${key}_sha256" "${BOUND_MANIFEST}")" ]] ||
    fail "${name}: restored bound closure identity drifted"
  ((BOUND_CLOSURE_MISSING_CUTS += 1))
done
[[ "${BOUND_CLOSURE_MISSING_CUTS}" -eq 3 ]] ||
  fail 'bound flat closure missing-cut cardinality'
printf 'HERMETIC_BOUND_FLAT_CLOSURE package=v5 current_files=20 checksum_dependencies=3 missing_cuts=3 result=PASS\n'
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
needle = b"format\twg-mix-ebpf-b82-v6-package-v5\n"
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
    [[ "${key}" == format && "${value}" == wg-mix-ebpf-b82-v6-package-v5 ]]
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
  fail 'fresh verifier exact package-v5 reader target'
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

proc r2_test_prewrite_sequence {} {
    # Independent literal oracle: do not construct this from any production
    # lineage, stale, package, or R2 builder/list procedure.
    return {
        lineage-exists-user-intake
        lineage-exists-home-qroot
        lineage-exists-run-qroot
        lineage-exists-receipt-pending
        lineage-home-readlink
        lineage-home-stat
        lineage-home-entries
        lineage-auth-readlink
        lineage-auth-stat
        lineage-auth-entries
        lineage-run-readlink
        lineage-run-stat
        lineage-run-entries
        lineage-auth-manifest-pending-stat
        lineage-auth-manifest-pending-sha
        lineage-auth-manifest-stat
        lineage-auth-manifest-sha
        lineage-auth-manifest-pair
        lineage-auth-self-pending-stat
        lineage-auth-self-pending-sha
        lineage-auth-self-stat
        lineage-auth-self-sha
        lineage-auth-self-pair
        lineage-q-intake-readlink
        lineage-q-intake-stat
        lineage-q-intake-entries
        lineage-q-intake-manifest-stat
        lineage-q-intake-manifest-sha
        lineage-q-intake-self-stat
        lineage-q-intake-self-sha
        lineage-q-package-readlink
        lineage-q-package-stat
        lineage-q-package-entries
        lineage-q-bootstrap-readlink
        lineage-q-bootstrap-stat
        lineage-q-bootstrap-entries
        lineage-lock-stat
        lineage-receipt-stat
        lineage-receipt-sha
        lineage-q-package-stat-source-4f2a9b61.bundle
        lineage-q-package-sha-source-4f2a9b61.bundle
        lineage-q-package-stat-package-manifest.v1
        lineage-q-package-sha-package-manifest.v1
        lineage-q-package-stat-bind-final-package.sh
        lineage-q-package-sha-bind-final-package.sh
        lineage-q-package-stat-controller.sh
        lineage-q-package-sha-controller.sh
        lineage-q-package-stat-prepare-stage-root.sh
        lineage-q-package-sha-prepare-stage-root.sh
        lineage-q-package-stat-provision-ubuntu-test-host.sh
        lineage-q-package-sha-provision-ubuntu-test-host.sh
        lineage-q-package-stat-root-matrix-n-r.sh
        lineage-q-package-sha-root-matrix-n-r.sh
        lineage-q-package-stat-check-realhost-iperf.py
        lineage-q-package-sha-check-realhost-iperf.py
        lineage-q-package-stat-test-hermetic-matrix.sh
        lineage-q-package-sha-test-hermetic-matrix.sh
        lineage-q-package-stat-test_matrix_static.py
        lineage-q-package-sha-test_matrix_static.py
        lineage-q-package-stat-checksum-module-lease.sh
        lineage-q-package-sha-checksum-module-lease.sh
        lineage-q-package-stat-root-fresh-verifier-gate.sh
        lineage-q-package-sha-root-fresh-verifier-gate.sh
        lineage-q-package-stat-test-hermetic-fresh-verifier-gate.sh
        lineage-q-package-sha-test-hermetic-fresh-verifier-gate.sh
        lineage-q-package-stat-test_fresh_verifier_gate_static.py
        lineage-q-package-sha-test_fresh_verifier_gate_static.py
        lineage-q-package-stat-realnic_acceptance.py
        lineage-q-package-sha-realnic_acceptance.py
        lineage-q-package-stat-test_realnic_acceptance.py
        lineage-q-package-sha-test_realnic_acceptance.py
        lineage-q-package-stat-test_realnic_acceptance_static.py
        lineage-q-package-sha-test_realnic_acceptance_static.py
        lineage-q-bootstrap-stat-prepare-stage-root.sh
        lineage-q-bootstrap-sha-prepare-stage-root.sh
        lineage-q-bootstrap-stat-provision-ubuntu-test-host.sh
        lineage-q-bootstrap-sha-provision-ubuntu-test-host.sh
        lineage-boot-id-read
        lineage-lock-content-read
        lineage-lock-stat-recheck
        lineage-exists-user-intake
        lineage-exists-home-qroot
        lineage-exists-run-qroot
        lineage-exists-receipt-pending
        r2-ro-exists-home-qroot
        r2-ro-exists-auth-root
        r2-ro-exists-run-qroot
        r2-ro-exists-auth-manifest-pending
        r2-ro-exists-auth-manifest
        r2-ro-exists-auth-self-pending
        r2-ro-exists-auth-self
        r2-ro-exists-quarantine-intake
        r2-ro-exists-quarantine-package
        r2-ro-exists-quarantine-bootstrap
        r2-ro-exists-lock
        r2-ro-exists-receipt-pending
        r2-ro-exists-receipt-final
        identity-hostname
        identity-kernel
        identity-machine
        identity-netns
        identity-interface
        stale-alternate-bootstrap-root
        stale-stage-root
        stale-fresh-root
        stale-standalone-root
        stale-routed-evidence-root
        stale-realnic-run-roots
        stale-realnic-interface-leases
        stale-veth-wgc8e41a
        stale-veth-wgc8e41b
        stale-veth-wga19f7a
        stale-veth-wga19f7b
        stale-veth-wg5b8d3a
        stale-veth-wg5b8d3b
        stale-pin-fresh
        stale-pin-standalone
        stale-pin-legacy-tcx
        stale-pin-legacy-nic-original
        stale-pin-legacy-nic-all-on
        stale-pin-legacy-nic-all-off
        stale-pin-legacy-nic-tx-path
        stale-pin-legacy-nic-rx-path
        stale-pin-legacy-nic-mtu1492
        stale-pin-legacy-nic-mtu1500
        stale-pin-legacy-nic-soak
        stale-checksum-module
        stale-checksum-module-btf
        stale-checksum-module-lock
        stale-physical-interface-lock
        package-parent-stat
        r2-ro-old-package-readlink
        r2-ro-old-package-stat
        r2-ro-old-package-entries
        r2-ro-old-package-sha-source-4f2a9b61.bundle
        r2-ro-old-package-stat-source-4f2a9b61.bundle
        r2-ro-old-package-sha-package-manifest.v1
        r2-ro-old-package-stat-package-manifest.v1
        r2-ro-old-package-sha-bind-final-package.sh
        r2-ro-old-package-stat-bind-final-package.sh
        r2-ro-old-package-sha-controller.sh
        r2-ro-old-package-stat-controller.sh
        r2-ro-old-package-sha-prepare-stage-root.sh
        r2-ro-old-package-stat-prepare-stage-root.sh
        r2-ro-old-package-sha-provision-ubuntu-test-host.sh
        r2-ro-old-package-stat-provision-ubuntu-test-host.sh
        r2-ro-old-package-sha-root-matrix-n-r.sh
        r2-ro-old-package-stat-root-matrix-n-r.sh
        r2-ro-old-package-sha-check-realhost-iperf.py
        r2-ro-old-package-stat-check-realhost-iperf.py
        r2-ro-old-package-sha-test-hermetic-matrix.sh
        r2-ro-old-package-stat-test-hermetic-matrix.sh
        r2-ro-old-package-sha-test_matrix_static.py
        r2-ro-old-package-stat-test_matrix_static.py
        r2-ro-old-package-sha-checksum-module-lease.sh
        r2-ro-old-package-stat-checksum-module-lease.sh
        r2-ro-old-package-sha-root-fresh-verifier-gate.sh
        r2-ro-old-package-stat-root-fresh-verifier-gate.sh
        r2-ro-old-package-sha-test-hermetic-fresh-verifier-gate.sh
        r2-ro-old-package-stat-test-hermetic-fresh-verifier-gate.sh
        r2-ro-old-package-sha-test_fresh_verifier_gate_static.py
        r2-ro-old-package-stat-test_fresh_verifier_gate_static.py
        r2-ro-old-package-sha-realnic_acceptance.py
        r2-ro-old-package-stat-realnic_acceptance.py
        r2-ro-old-package-sha-test_realnic_acceptance.py
        r2-ro-old-package-stat-test_realnic_acceptance.py
        r2-ro-old-package-sha-test_realnic_acceptance_static.py
        r2-ro-old-package-stat-test_realnic_acceptance_static.py
        r2-ro-old-bootstrap-root-readlink
        r2-ro-old-bootstrap-root-stat
        r2-ro-old-bootstrap-provisioner-readlink
        r2-ro-old-bootstrap-provisioner-stat
        r2-ro-old-bootstrap-provisioner-sha
        r2-ro-old-bootstrap-stager-readlink
        r2-ro-old-bootstrap-stager-stat
        r2-ro-old-bootstrap-stager-sha
        r2-ro-old-bootstrap-entries
        r2-ro-old-provision-check
    }
}

proc r2_test_raw_sequence {} {
    return {
        r2-raw-intake-mkdir
        r2-raw-scp-manifest
        r2-raw-scp-self
        r2-raw-sync-intake-manifest
        r2-raw-sync-intake-self
        r2-raw-sync-intake-directory
        r2-raw-sync-intake-parent
        r2-raw-home-qroot-create
        r2-raw-auth-root-create
        r2-raw-run-qroot-create
        r2-raw-auth-manifest-install
        r2-raw-auth-self-install
        r2-raw-sync-auth-manifest-pending
        r2-raw-sync-auth-self-pending
        r2-raw-link-auth-manifest
        r2-raw-link-auth-self
        r2-raw-sync-auth-root
        r2-raw-sync-home-parent
        r2-raw-sync-home-qroot
        r2-raw-sync-run-parent
        r2-raw-helper-mutate
    }
}

proc r2_test_private_read_only {} {
    return {
        r2-ro-exists-home-qroot
        r2-ro-exists-auth-root
        r2-ro-exists-run-qroot
        r2-ro-exists-auth-manifest-pending
        r2-ro-exists-auth-manifest
        r2-ro-exists-auth-self-pending
        r2-ro-exists-auth-self
        r2-ro-exists-quarantine-intake
        r2-ro-exists-quarantine-package
        r2-ro-exists-quarantine-bootstrap
        r2-ro-exists-lock
        r2-ro-exists-receipt-pending
        r2-ro-exists-receipt-final
        r2-ro-old-package-sha-source-4f2a9b61.bundle
        r2-ro-old-package-stat-source-4f2a9b61.bundle
        r2-ro-old-package-sha-package-manifest.v1
        r2-ro-old-package-stat-package-manifest.v1
        r2-ro-old-package-sha-bind-final-package.sh
        r2-ro-old-package-stat-bind-final-package.sh
        r2-ro-old-package-sha-controller.sh
        r2-ro-old-package-stat-controller.sh
        r2-ro-old-package-sha-prepare-stage-root.sh
        r2-ro-old-package-stat-prepare-stage-root.sh
        r2-ro-old-package-sha-provision-ubuntu-test-host.sh
        r2-ro-old-package-stat-provision-ubuntu-test-host.sh
        r2-ro-old-package-sha-root-matrix-n-r.sh
        r2-ro-old-package-stat-root-matrix-n-r.sh
        r2-ro-old-package-sha-check-realhost-iperf.py
        r2-ro-old-package-stat-check-realhost-iperf.py
        r2-ro-old-package-sha-test-hermetic-matrix.sh
        r2-ro-old-package-stat-test-hermetic-matrix.sh
        r2-ro-old-package-sha-test_matrix_static.py
        r2-ro-old-package-stat-test_matrix_static.py
        r2-ro-old-package-sha-checksum-module-lease.sh
        r2-ro-old-package-stat-checksum-module-lease.sh
        r2-ro-old-package-sha-root-fresh-verifier-gate.sh
        r2-ro-old-package-stat-root-fresh-verifier-gate.sh
        r2-ro-old-package-sha-test-hermetic-fresh-verifier-gate.sh
        r2-ro-old-package-stat-test-hermetic-fresh-verifier-gate.sh
        r2-ro-old-package-sha-test_fresh_verifier_gate_static.py
        r2-ro-old-package-stat-test_fresh_verifier_gate_static.py
        r2-ro-old-package-sha-realnic_acceptance.py
        r2-ro-old-package-stat-realnic_acceptance.py
        r2-ro-old-package-sha-test_realnic_acceptance.py
        r2-ro-old-package-stat-test_realnic_acceptance.py
        r2-ro-old-package-sha-test_realnic_acceptance_static.py
        r2-ro-old-package-stat-test_realnic_acceptance_static.py
        r2-ro-user-intake-exists
        r2-ro-old-package-readlink
        r2-ro-old-package-stat
        r2-ro-old-package-entries
        r2-ro-old-bootstrap-root-readlink
        r2-ro-old-bootstrap-root-stat
        r2-ro-old-bootstrap-provisioner-readlink
        r2-ro-old-bootstrap-provisioner-stat
        r2-ro-old-bootstrap-provisioner-sha
        r2-ro-old-bootstrap-stager-readlink
        r2-ro-old-bootstrap-stager-stat
        r2-ro-old-bootstrap-stager-sha
        r2-ro-old-bootstrap-entries
        r2-ro-old-provision-check
        r2-ro-intake-readlink
        r2-ro-intake-stat
        r2-ro-intake-entries
        r2-ro-intake-manifest-stat
        r2-ro-intake-manifest-shape
        r2-ro-intake-manifest-sha
        r2-ro-intake-manifest-sha-observe
        r2-ro-intake-self-stat
        r2-ro-intake-self-shape
        r2-ro-intake-self-sha
        r2-ro-intake-self-sha-observe
        r2-ro-home-qroot-readlink
        r2-ro-home-qroot-stat
        r2-ro-home-qroot-entries
        r2-ro-auth-root-readlink
        r2-ro-auth-root-stat
        r2-ro-auth-root-entries
        r2-ro-run-qroot-readlink
        r2-ro-run-qroot-stat
        r2-ro-run-qroot-entries
        r2-ro-auth-manifest-pending-sha
        r2-ro-auth-manifest-pending-shape
        r2-ro-auth-manifest-pending-sha-observe
        r2-ro-auth-manifest-sha
        r2-ro-auth-self-pending-sha
        r2-ro-auth-self-pending-shape
        r2-ro-auth-self-pending-sha-observe
        r2-ro-auth-self-sha
        r2-ro-auth-manifest-pending-stat
        r2-ro-auth-self-pending-stat
        r2-ro-auth-manifest-stat
        r2-ro-auth-self-stat
        r2-ro-auth-manifest-pair
        r2-ro-auth-self-pair
        r2-ro-helper-verify
    }
}

proc r2_test_package_names {} {
    return {
        source-4f2a9b61.bundle
        package-manifest.v1
        bind-final-package.sh
        controller.sh
        prepare-stage-root.sh
        provision-ubuntu-test-host.sh
        root-matrix-n-r.sh
        check-realhost-iperf.py
        test-hermetic-matrix.sh
        test_matrix_static.py
        checksum-module-lease.sh
        root-fresh-verifier-gate.sh
        test-hermetic-fresh-verifier-gate.sh
        test_fresh_verifier_gate_static.py
        realnic_acceptance.py
        test_realnic_acceptance.py
        test_realnic_acceptance_static.py
    }
}

proc r2_test_package_sha {name} {
    switch -- $name {
        source-4f2a9b61.bundle {
            return b74811808e0413714dcf20b8292fe68631f603c0b9a68bc9951af481477b413b
        }
        package-manifest.v1 {
            return 2d6c6caac080b599fbfa0f73c64f6976cf30d1504fc506ebd39c638b2f9449e3
        }
        bind-final-package.sh {
            return a808a7879ef64190eff9e81e6b694acea7bc04b1b74ffad44109b237a5eb14ca
        }
        controller.sh {
            return fb8a7a685b5a6b73de851ee9a3396f4154cc4ae083a7c36f3b3128b2b9a2e77d
        }
        prepare-stage-root.sh {
            return 1bcb8db91d976d2a1d95f7d87223a2dac4a1678f74c1c25542e54b01ee10eeea
        }
        provision-ubuntu-test-host.sh {
            return 078d191b0edbafe27e9f684d3fa495e04d7217a01d0ec1fd32eaede211178c8f
        }
        root-matrix-n-r.sh {
            return 9ec125c2933866431779b760d41c6484cc0fbb9e5e9f3b5431c4a56fbab63e07
        }
        check-realhost-iperf.py {
            return 9a52378b8a1ef6043d4d5792471c8239a0392a80da72f5c00846dd89e88ccd67
        }
        test-hermetic-matrix.sh {
            return 9b81949416a1b4df91fee0e7d31a3de2c6ba9b474dc9c0f4dbbb1cc609207499
        }
        test_matrix_static.py {
            return 8de2dcdc866938da0502f1ad73ac9b38c9b6ff4066c76e9cbc946c9ca30a53f8
        }
        checksum-module-lease.sh {
            return 4ab9a22910e8d597cc04bb4fdde9e1b32d37a1bb2c6ad7b76f52d576b5a9adb2
        }
        root-fresh-verifier-gate.sh {
            return 4c2cf85b7e571df9b7ed4a77fa720c9f5e35950d44af5a39499a7ad700fe6a27
        }
        test-hermetic-fresh-verifier-gate.sh {
            return c9b5b1f954c794c5c986214777727a76579f670db9587f319ac148fc0c2a05f3
        }
        test_fresh_verifier_gate_static.py {
            return ace6951027788e82ad879caf285316af4e6ee81fdb6746f569cd7c22b9f80bf3
        }
        realnic_acceptance.py {
            return a88100b2a23ad41dd3e644c3ba1c7a722d58c8184a997aabf0ceab78552c6339
        }
        test_realnic_acceptance.py {
            return fcb3d0dadee6da6e0ad67d028f268ebe43575287f555cd8100d279f8a3b0b79c
        }
        test_realnic_acceptance_static.py {
            return ba8aef3219a0cf2a5c6b5058b245f64eb828a08bb532d2aa0291f51ee7206ad2
        }
        default { harness_die "r2-test-package-sha-$name" }
    }
}

proc r2_test_file_prefix_sha {file_name length} {
    if {[catch {exec /usr/bin/python3 -B -I -c {
import hashlib
import pathlib
import sys

file_name = pathlib.Path(sys.argv[1])
length = int(sys.argv[2])
with file_name.open("rb") as handle:
    payload = handle.read(length)
if len(payload) != length:
    raise SystemExit(65)
print(hashlib.sha256(payload).hexdigest())
} $file_name $length} digest]} {
        harness_die "r2-test-prefix-sha-$file_name-$length"
    }
    return [string trim $digest]
}

proc r2_test_r1_package_entries {} {
    set entries {}
    foreach name {
        source-4f2a9b61.bundle package-manifest.v1 bind-final-package.sh
        controller.sh prepare-stage-root.sh provision-ubuntu-test-host.sh
        root-matrix-n-r.sh check-realhost-iperf.py test-hermetic-matrix.sh
        test_matrix_static.py checksum-module-lease.sh
        root-fresh-verifier-gate.sh test-hermetic-fresh-verifier-gate.sh
        test_fresh_verifier_gate_static.py realnic_acceptance.py
        test_realnic_acceptance.py test_realnic_acceptance_static.py
    } {
        lappend entries "${name}\tf"
    }
    return [join $entries "\n"]
}

proc r2_test_r1_deep_operations {} {
    # Frozen independently from the production lineage builder.  Keep the
    # operation names and order literal so production cannot define its own
    # test oracle.
    return {
        lineage-q-package-stat-source-4f2a9b61.bundle
        lineage-q-package-sha-source-4f2a9b61.bundle
        lineage-q-package-stat-package-manifest.v1
        lineage-q-package-sha-package-manifest.v1
        lineage-q-package-stat-bind-final-package.sh
        lineage-q-package-sha-bind-final-package.sh
        lineage-q-package-stat-controller.sh
        lineage-q-package-sha-controller.sh
        lineage-q-package-stat-prepare-stage-root.sh
        lineage-q-package-sha-prepare-stage-root.sh
        lineage-q-package-stat-provision-ubuntu-test-host.sh
        lineage-q-package-sha-provision-ubuntu-test-host.sh
        lineage-q-package-stat-root-matrix-n-r.sh
        lineage-q-package-sha-root-matrix-n-r.sh
        lineage-q-package-stat-check-realhost-iperf.py
        lineage-q-package-sha-check-realhost-iperf.py
        lineage-q-package-stat-test-hermetic-matrix.sh
        lineage-q-package-sha-test-hermetic-matrix.sh
        lineage-q-package-stat-test_matrix_static.py
        lineage-q-package-sha-test_matrix_static.py
        lineage-q-package-stat-checksum-module-lease.sh
        lineage-q-package-sha-checksum-module-lease.sh
        lineage-q-package-stat-root-fresh-verifier-gate.sh
        lineage-q-package-sha-root-fresh-verifier-gate.sh
        lineage-q-package-stat-test-hermetic-fresh-verifier-gate.sh
        lineage-q-package-sha-test-hermetic-fresh-verifier-gate.sh
        lineage-q-package-stat-test_fresh_verifier_gate_static.py
        lineage-q-package-sha-test_fresh_verifier_gate_static.py
        lineage-q-package-stat-realnic_acceptance.py
        lineage-q-package-sha-realnic_acceptance.py
        lineage-q-package-stat-test_realnic_acceptance.py
        lineage-q-package-sha-test_realnic_acceptance.py
        lineage-q-package-stat-test_realnic_acceptance_static.py
        lineage-q-package-sha-test_realnic_acceptance_static.py
        lineage-q-bootstrap-stat-prepare-stage-root.sh
        lineage-q-bootstrap-sha-prepare-stage-root.sh
        lineage-q-bootstrap-stat-provision-ubuntu-test-host.sh
        lineage-q-bootstrap-sha-provision-ubuntu-test-host.sh
        lineage-boot-id-read
        lineage-lock-content-read
        lineage-lock-stat-recheck
    }
}

proc r2_test_r1_file_oracle {scope name} {
    # Literal retained-R1 byte counts and digests.  These values are not read
    # from the current or predecessor manifests and are not copied from a
    # production Tcl data structure at runtime.
    switch -- "${scope}/${name}" {
        package/source-4f2a9b61.bundle {
            return {2404122 5c53adec58363ec2ff51d9bd5dcd7e467874c839393178491c74b16a8c9f922c}
        }
        package/package-manifest.v1 {
            return {7315 21f14e1f7e646649fdad864dce23dce2055585962d92bfaba6e71158372c1ebe}
        }
        package/bind-final-package.sh {
            return {17009 13a186008662548b191c8e18a3cf764597504451a30e50cd3c7e7cd9d98dfc6e}
        }
        package/controller.sh {
            return {43170 ff315162affccc51454f3f9a0c80f9c7412291581a9a2abc03ed1df46a266a1c}
        }
        package/prepare-stage-root.sh {
            return {54217 cc8e0e82c369ff9983600879827d350ea3b2da13d4d3315b309ea0924e911a95}
        }
        package/provision-ubuntu-test-host.sh {
            return {18613 01aaf3767d9e048f11ca21f35cadba063f355c3c9e94aadd606734d02c260388}
        }
        package/root-matrix-n-r.sh {
            return {984 d0d0f6f532516e16d98239e5ad79963c2c70bc8bd682a3f6439b4479e7b60fb3}
        }
        package/check-realhost-iperf.py {
            return {21027 9a52378b8a1ef6043d4d5792471c8239a0392a80da72f5c00846dd89e88ccd67}
        }
        package/test-hermetic-matrix.sh {
            return {6669 be011f72367b6b383ece727f1048db992b9068db224109ee2f60ed5a6ce0c891}
        }
        package/test_matrix_static.py {
            return {5656 8de2dcdc866938da0502f1ad73ac9b38c9b6ff4066c76e9cbc946c9ca30a53f8}
        }
        package/checksum-module-lease.sh {
            return {23755 4ab9a22910e8d597cc04bb4fdde9e1b32d37a1bb2c6ad7b76f52d576b5a9adb2}
        }
        package/root-fresh-verifier-gate.sh {
            return {65112 762502215e1138b53a656fd085b1718b867a3cc488a5c5bd874a04561cf10e9d}
        }
        package/test-hermetic-fresh-verifier-gate.sh {
            return {14628 c9b5b1f954c794c5c986214777727a76579f670db9587f319ac148fc0c2a05f3}
        }
        package/test_fresh_verifier_gate_static.py {
            return {17307 ace6951027788e82ad879caf285316af4e6ee81fdb6746f569cd7c22b9f80bf3}
        }
        package/realnic_acceptance.py {
            return {216405 a88100b2a23ad41dd3e644c3ba1c7a722d58c8184a997aabf0ceab78552c6339}
        }
        package/test_realnic_acceptance.py {
            return {148160 fcb3d0dadee6da6e0ad67d028f268ebe43575287f555cd8100d279f8a3b0b79c}
        }
        package/test_realnic_acceptance_static.py {
            return {14894 ba8aef3219a0cf2a5c6b5058b245f64eb828a08bb532d2aa0291f51ee7206ad2}
        }
        bootstrap/prepare-stage-root.sh {
            return {54217 cc8e0e82c369ff9983600879827d350ea3b2da13d4d3315b309ea0924e911a95}
        }
        bootstrap/provision-ubuntu-test-host.sh {
            return {18613 01aaf3767d9e048f11ca21f35cadba063f355c3c9e94aadd606734d02c260388}
        }
        default { harness_die "r2-test-r1-file-oracle-${scope}-${name}" }
    }
}

proc r2_test_r1_payload {operation} {
    set home /home/.wg-mix-ebpf-retirement-c8e41d73-2c690050ae1d-r1
    set auth ${home}/authority
    set run /run/wg-mix-ebpf-retirement-c8e41d73-2c690050ae1d-r1
    set intake ${home}/intake
    set package ${home}/package
    set bootstrap ${run}/bootstrap
    set receipt ${run}/retirement-complete.v1
    set manifest_sha \
        c4532671304d30755b1c42bb55f82186d96df3f6c84af73078ca16c3fddfe4e6
    set helper_sha \
        a4a1c89dcd9f087b79149f52a01346ed6db5c209ad4985bdbb8c9132276c0077
    set receipt_sha \
        4c3e9bfd3d4e64f6626abaa43e20cf5e4df6b193395cee6a39953b1c4da7d188
    set boot_id 01234567-89ab-cdef-0123-456789abcdef
    if {[regexp {^lineage-q-(package|bootstrap)-(stat|sha)-(.+)$} \
            $operation -> scope family name]} {
        lassign [r2_test_r1_file_oracle $scope $name] size sha
        set root [expr {$scope eq "package" ? $package : $bootstrap}]
        if {$family eq "stat"} {
            set identity [expr {$scope eq "package" ?
                "siyixuan:siyixuan:600" : "root:root:700"}]
            return "${identity}:1:${size}:regular file"
        }
        return "${sha}  ${root}/${name}"
    }
    switch -- $operation {
        lineage-exists-user-intake - lineage-exists-receipt-pending {
            return ""
        }
        lineage-exists-home-qroot { return $home }
        lineage-exists-run-qroot { return $run }
        lineage-home-readlink { return $home }
        lineage-auth-readlink { return $auth }
        lineage-run-readlink { return $run }
        lineage-q-intake-readlink { return $intake }
        lineage-q-package-readlink { return $package }
        lineage-q-bootstrap-readlink { return $bootstrap }
        lineage-home-stat - lineage-auth-stat - lineage-run-stat -
        lineage-q-bootstrap-stat { return root:root:700:directory }
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
        lineage-q-package-entries { return [r2_test_r1_package_entries] }
        lineage-q-bootstrap-entries {
            return "prepare-stage-root.sh\tf\nprovision-ubuntu-test-host.sh\tf"
        }
        lineage-auth-manifest-pending-stat - lineage-auth-manifest-stat {
            return root:root:600:2:regular\ file
        }
        lineage-auth-self-pending-stat - lineage-auth-self-stat {
            return root:root:700:2:regular\ file
        }
        lineage-auth-manifest-pending-sha {
            return "${manifest_sha}  ${auth}/package-manifest.v1.pending"
        }
        lineage-auth-manifest-sha {
            return "${manifest_sha}  ${auth}/package-manifest.v1"
        }
        lineage-auth-self-pending-sha {
            return "${helper_sha}  ${auth}/prepare-stage-root.sh.pending"
        }
        lineage-auth-self-sha {
            return "${helper_sha}  ${auth}/prepare-stage-root.sh"
        }
        lineage-auth-manifest-pair - lineage-auth-self-pair {
            return "71:113\n71:113"
        }
        lineage-q-intake-manifest-stat - lineage-q-intake-self-stat {
            return siyixuan:siyixuan:600:1:regular\ file
        }
        lineage-q-intake-manifest-sha {
            return "${manifest_sha}  ${intake}/package-manifest.v1"
        }
        lineage-q-intake-self-sha {
            return "${helper_sha}  ${intake}/prepare-stage-root.sh"
        }
        lineage-lock-stat {
            return 71:113:root:root:600:1:45:regular\ file
        }
        lineage-receipt-stat { return root:root:600:1:regular\ file }
        lineage-receipt-sha { return "${receipt_sha}  ${receipt}" }
        lineage-boot-id-read { return "${boot_id}\n" }
        lineage-lock-content-read { return "boot_id\t${boot_id}\n" }
        lineage-lock-stat-recheck {
            return 71:113:root:root:600:1:45:regular\ file
        }
        default { harness_die "r2-test-r1-payload-$operation" }
    }
}

proc r2_test_old_package_entries {} {
    set entries {}
    foreach name [r2_test_package_names] {
        lappend entries "${name}\tf"
    }
    return [join $entries "\n"]
}

proc r2_test_remote_payload {operation} {
    set old_package /home/siyixuan/wg-mix-ebpf-test/unpriv-4f2a9b61
    set old_bootstrap /run/wg-mix-ebpf-source-bootstrap-c8e41d73
    if {[string match "lineage-*" $operation]} {
        return [list ok [r2_test_r1_payload $operation] none]
    }
    if {[string match "r2-ro-exists-*" $operation]} {
        return [list absent "" none]
    }
    switch -- $operation {
        identity-hostname { return [list ok ubuntu-2604-test none] }
        identity-kernel { return [list ok 7.0.0-28-generic none] }
        identity-machine {
            return [list ok 9db3fb717cc74974b2a6b243d67f67b9 none]
        }
        identity-netns { return [list ok {net:[4026531840]} none] }
        identity-interface {
            return [list ok {{"ifname":"ens33"}} none]
        }
        package-parent-stat {
            return [list ok siyixuan:siyixuan:700:directory none]
        }
        r2-ro-old-package-readlink {
            return [list ok $old_package none]
        }
        r2-ro-old-package-stat {
            return [list ok siyixuan:siyixuan:700:directory none]
        }
        r2-ro-old-package-entries {
            return [list ok [r2_test_old_package_entries] none]
        }
        r2-ro-old-bootstrap-root-readlink {
            return [list ok $old_bootstrap none]
        }
        r2-ro-old-bootstrap-root-stat {
            return [list ok root:root:700:directory none]
        }
        r2-ro-old-bootstrap-provisioner-readlink {
            return [list ok ${old_bootstrap}/provision-ubuntu-test-host.sh none]
        }
        r2-ro-old-bootstrap-stager-readlink {
            return [list ok ${old_bootstrap}/prepare-stage-root.sh none]
        }
        r2-ro-old-bootstrap-provisioner-stat -
        r2-ro-old-bootstrap-stager-stat {
            return [list ok root:root:700:1:regular\ file none]
        }
        r2-ro-old-bootstrap-provisioner-sha {
            return [list ok \
                "078d191b0edbafe27e9f684d3fa495e04d7217a01d0ec1fd32eaede211178c8f  ${old_bootstrap}/provision-ubuntu-test-host.sh" none]
        }
        r2-ro-old-bootstrap-stager-sha {
            return [list ok \
                "1bcb8db91d976d2a1d95f7d87223a2dac4a1678f74c1c25542e54b01ee10eeea  ${old_bootstrap}/prepare-stage-root.sh" none]
        }
        r2-ro-old-bootstrap-entries {
            return [list ok \
                "prepare-stage-root.sh\tf\nprovision-ubuntu-test-host.sh\tf" none]
        }
        r2-ro-old-provision-check {
            return [list ok \
                {B82_PROVISION_PLAN mode=check missing_set=none writes=0} none]
        }
    }
    if {[regexp {^r2-ro-old-package-(sha|stat)-(.+)$} $operation -> family name]} {
        if {[lsearch -exact [r2_test_package_names] $name] < 0} {
            harness_die "r2-test-old-package-name-$name"
        }
        if {$family eq "sha"} {
            return [list ok \
                "[r2_test_package_sha $name]  ${old_package}/${name}" none]
        }
        return [list ok siyixuan:siyixuan:600:1:regular\ file none]
    }
    if {[string match "stale-*" $operation]} {
        return [list ok "" none]
    }
    harness_die "r2-test-remote-payload-$operation"
}

proc r2_test_provision_payload {scenario} {
    switch -- $scenario {
        initial {
            return [join {
                mode=check
                {missing_packages= clang gcc golang-go iperf3 libbpf-dev llvm make pkg-config shellcheck wireguard-tools}
                {plan_command=A0 argv=/usr/bin/apt-get update}
                {plan_command=A1 argv=/usr/bin/apt-get install --no-install-recommends fixed-package-set}
                {plan_command=A2 argv=/usr/bin/apt-get clean}
                {plan_complete planned_commands_executed=0 writes=0 automatic_cleanup=0}
            } "\n"]
        }
        iperf3 {
            return [join {
                mode=check
                {missing_packages= iperf3}
                {plan_command=A0 argv=/usr/bin/apt-get update}
                {plan_command=A1 argv=/usr/bin/apt-get install --no-install-recommends iperf3}
                {plan_command=A2 argv=/usr/bin/apt-get clean}
                {plan_complete planned_commands_executed=0 writes=0 automatic_cleanup=0}
            } "\n"]
        }
        malformed {
            return [join {
                mode=check
                missing_packages=
                {plan_apt_commands=skipped reason=fixed-package-set-already-installed}
            } "\n"]
        }
        writes1 {
            return [join {
                mode=check
                missing_packages=
                {plan_apt_commands=skipped reason=fixed-package-set-already-installed}
                {plan_complete planned_commands_executed=0 writes=1 automatic_cleanup=0}
            } "\n"]
        }
        default { harness_die "r2-test-provision-scenario-$scenario" }
    }
}

proc r2_test_authority_payload {operation} {
    set home /home/.wg-mix-ebpf-retirement-c8e41d73-f75fe7678cfd-r2
    set auth ${home}/authority
    set run /run/wg-mix-ebpf-retirement-c8e41d73-f75fe7678cfd-r2
    if {[regexp {^r2-ro-exists-(.+)$} $operation -> name]} {
        return [expr {[dict get $::r2_present $name] ?
            [list ok "" none] : [list absent "" none]}]
    }
    switch -- $operation {
        r2-ro-home-qroot-readlink { return [list ok $home none] }
        r2-ro-auth-root-readlink { return [list ok $auth none] }
        r2-ro-run-qroot-readlink { return [list ok $run none] }
        r2-ro-home-qroot-stat - r2-ro-auth-root-stat -
        r2-ro-run-qroot-stat {
            return [list ok root:root:700:directory none]
        }
        r2-ro-home-qroot-entries {
            set entries {}
            if {[dict get $::r2_present auth-root]} {
                lappend entries [expr {$::r2_foreign eq "home-type" ?
                    "authority\tf" : "authority\td"}]
            }
            if {[dict get $::r2_present quarantine-intake]} {
                lappend entries "intake\td"
            }
            if {[dict get $::r2_present quarantine-package]} {
                lappend entries "package\td"
            }
            if {$::r2_foreign eq "home"} {
                lappend entries "foreign\tf"
            }
            return [list ok [join $entries "\n"] none]
        }
        r2-ro-auth-root-entries {
            set entries {}
            foreach {name entry} {
                auth-manifest-pending package-manifest.v1.pending
                auth-manifest package-manifest.v1
                auth-self-pending prepare-stage-root.sh.pending
                auth-self prepare-stage-root.sh
            } {
                if {[dict get $::r2_present $name]} {
                    set entry_type f
                    if {$::r2_foreign eq "auth-type" &&
                        $name eq "auth-manifest-pending"} {
                        set entry_type d
                    }
                    lappend entries "${entry}\t${entry_type}"
                }
            }
            if {$::r2_foreign eq "auth"} {
                lappend entries "foreign\tf"
            }
            return [list ok [join $entries "\n"] none]
        }
        r2-ro-run-qroot-entries {
            set entries {}
            foreach {name entry} {
                quarantine-bootstrap "bootstrap\td"
                lock "retirement.v1.lock\tf"
                receipt-pending "retirement-complete.v1.pending\tf"
                receipt-final "retirement-complete.v1\tf"
            } {
                if {[dict get $::r2_present $name]} {
                    if {$::r2_foreign eq "run-type" &&
                        $name eq "quarantine-bootstrap"} {
                        set entry "bootstrap\tf"
                    }
                    lappend entries $entry
                }
            }
            if {$::r2_foreign eq "run"} {
                lappend entries "foreign\tf"
            }
            return [list ok [join $entries "\n"] none]
        }
        r2-ro-auth-manifest-pending-stat {
            return [list ok root:root:600:1:regular\ file none]
        }
        r2-ro-auth-self-pending-stat {
            return [list ok root:root:700:1:regular\ file none]
        }
        r2-ro-auth-manifest-stat {
            return [list ok root:root:600:2:regular\ file none]
        }
        r2-ro-auth-self-stat {
            return [list ok root:root:700:2:regular\ file none]
        }
        r2-ro-auth-manifest-pending-sha {
            return [list ok "${::r2_manifest_sha}  ${auth}/package-manifest.v1.pending" none]
        }
        r2-ro-auth-manifest-sha {
            return [list ok "${::r2_manifest_sha}  ${auth}/package-manifest.v1" none]
        }
        r2-ro-auth-self-pending-sha {
            return [list ok "${::r2_self_sha}  ${auth}/prepare-stage-root.sh.pending" none]
        }
        r2-ro-auth-self-sha {
            return [list ok "${::r2_self_sha}  ${auth}/prepare-stage-root.sh" none]
        }
        r2-ro-auth-manifest-pair - r2-ro-auth-self-pair {
            return [list ok "91:117\n91:117" none]
        }
        r2-ro-auth-manifest-pending-shape {
            return [list ok \
                "root:root:600:1:${::r2_pending_size}:regular file" none]
        }
        r2-ro-auth-self-pending-shape {
            return [list ok \
                "root:root:700:1:${::r2_pending_size}:regular file" none]
        }
        r2-ro-auth-manifest-pending-sha-observe {
            return [list ok \
                "${::r2_pending_sha}  ${auth}/package-manifest.v1.pending" none]
        }
        r2-ro-auth-self-pending-sha-observe {
            return [list ok \
                "${::r2_pending_sha}  ${auth}/prepare-stage-root.sh.pending" none]
        }
        default { harness_die "r2-test-authority-payload-$operation" }
    }
}

proc r2_test_intake_payload {operation} {
    set intake \
        /home/siyixuan/wg-mix-ebpf-test/retire-postflight-c8e41d73-f75fe7678cfd-r2.intake
    switch -- $operation {
        r2-ro-intake-readlink { return [list ok $intake none] }
        r2-ro-intake-stat {
            return [list ok siyixuan:siyixuan:700:directory none]
        }
        r2-ro-intake-entries {
            set entries {}
            if {$::r2_intake_manifest ne "absent"} {
                lappend entries "package-manifest.v1\tf"
            }
            if {$::r2_intake_self ne "absent"} {
                lappend entries "prepare-stage-root.sh\tf"
            }
            return [list ok [join $entries "\n"] none]
        }
        r2-ro-intake-manifest-stat {
            return [list ok siyixuan:siyixuan:600:1:regular\ file none]
        }
        r2-ro-intake-self-stat {
            return [list ok siyixuan:siyixuan:600:1:regular\ file none]
        }
        r2-ro-intake-manifest-shape {
            return [list ok \
                "siyixuan:siyixuan:600:1:${::r2_manifest_size}:regular file" none]
        }
        r2-ro-intake-self-shape {
            return [list ok \
                "siyixuan:siyixuan:600:1:${::r2_self_size}:regular file" none]
        }
        r2-ro-intake-manifest-sha - r2-ro-intake-manifest-sha-observe {
            return [list ok \
                "${::r2_manifest_sha}  ${intake}/package-manifest.v1" none]
        }
        r2-ro-intake-self-sha - r2-ro-intake-self-sha-observe {
            return [list ok \
                "${::r2_self_sha}  ${intake}/prepare-stage-root.sh" none]
        }
        default { harness_die "r2-test-intake-payload-$operation" }
    }
}

proc r2_test_full_remote_payload {operation} {
    if {[string match "r2-ro-intake-*" $operation]} {
        return [r2_test_intake_payload $operation]
    }
    if {[string match "r2-ro-auth-*" $operation] ||
        [string match "r2-ro-home-qroot-*" $operation] ||
        [string match "r2-ro-run-qroot-*" $operation] ||
        [string match "r2-ro-exists-*" $operation]} {
        return [r2_test_authority_payload $operation]
    }
    switch -- $operation {
        r2-ro-helper-verify {
            return [list ok \
                {B82_V6_RETIREMENT_VERIFIED state=T namespace_writes=0 same_boot=1 receipt=/run/wg-mix-ebpf-retirement-c8e41d73-f75fe7678cfd-r2/retirement-complete.v1} none]
        }
    }
    return [r2_test_remote_payload $operation]
}

proc r2_test_exact_ssh_prefix {tty} {
    set terminal [expr {$tty ? "-tt" : "-T"}]
    return [list /usr/bin/ssh -F /dev/null $terminal \
        -o BatchMode=no \
        -o PasswordAuthentication=yes \
        -o PreferredAuthentications=password \
        -o PubkeyAuthentication=no \
        -o KbdInteractiveAuthentication=no \
        -o IdentitiesOnly=yes \
        -o NumberOfPasswordPrompts=1 \
        -o StrictHostKeyChecking=yes \
        -o CheckHostIP=yes \
        -o UpdateHostKeys=no \
        -o VerifyHostKeyDNS=no \
        -o ConnectTimeout=15 \
        -o ConnectionAttempts=1 \
        -o ServerAliveInterval=15 \
        -o ServerAliveCountMax=2 \
        -o ClearAllForwardings=yes \
        -o ForwardAgent=no \
        -o ForwardX11=no \
        -o PermitLocalCommand=no \
        -o LocalCommand=none \
        -o ProxyCommand=none \
        -o ControlMaster=no \
        -o ControlPath=none \
        -o ControlPersist=no \
        -o CanonicalizeHostname=no \
        -o Compression=no \
        -o LogLevel=ERROR \
        -- siyixuan@192.168.10.82]
}

proc r2_test_exact_scp_prefix {} {
    return [list /usr/bin/scp -F /dev/null -q \
        -o BatchMode=no \
        -o PasswordAuthentication=yes \
        -o PreferredAuthentications=password \
        -o PubkeyAuthentication=no \
        -o KbdInteractiveAuthentication=no \
        -o IdentitiesOnly=yes \
        -o NumberOfPasswordPrompts=1 \
        -o StrictHostKeyChecking=yes \
        -o CheckHostIP=yes \
        -o UpdateHostKeys=no \
        -o VerifyHostKeyDNS=no \
        -o ConnectTimeout=15 \
        -o ConnectionAttempts=1 \
        -o ServerAliveInterval=15 \
        -o ServerAliveCountMax=2 \
        -o ClearAllForwardings=yes \
        -o ForwardAgent=no \
        -o ForwardX11=no \
        -o PermitLocalCommand=no \
        -o LocalCommand=none \
        -o ProxyCommand=none \
        -o ControlMaster=no \
        -o ControlPath=none \
        -o ControlPersist=no \
        -o CanonicalizeHostname=no \
        -o Compression=no \
        -o LogLevel=ERROR]
}

proc r2_test_validate_raw_spec {operation operation_spec} {
    set spawn_argv [lindex $operation_spec 1]
    set intake \
        /home/siyixuan/wg-mix-ebpf-test/retire-postflight-c8e41d73-f75fe7678cfd-r2.intake
    set home /home/.wg-mix-ebpf-retirement-c8e41d73-f75fe7678cfd-r2
    set auth ${home}/authority
    set run /run/wg-mix-ebpf-retirement-c8e41d73-f75fe7678cfd-r2
    switch -- $operation {
        r2-raw-scp-manifest - r2-raw-scp-self {
            set name [expr {$operation eq "r2-raw-scp-manifest" ?
                "package-manifest.v1" : "prepare-stage-root.sh"}]
            set expected [concat [r2_test_exact_scp_prefix] \
                [list -- "${::r2_local_package}/${name}" \
                "siyixuan@192.168.10.82:${intake}/${name}"]]
            if {[lindex $operation_spec 0] ne "scp" ||
                [lrange $spawn_argv 0 end] ne [lrange $expected 0 end] ||
                [lindex $operation_spec 2] != 1 ||
                [lindex $operation_spec 3] ne "none"} {
                harness_die "r2-raw-scp-spec-$operation actual=$operation_spec"
            }
            return
        }
    }
    if {[lindex $operation_spec 0] ne "ssh" ||
        [lsearch -exact $spawn_argv \
            /Users/siyixuan/codes-2/wg-mix-ebpf/credientials/192.168.10.82] >= 0} {
        harness_die "r2-raw-ssh-spec-$operation actual=$operation_spec"
    }
    switch -- $operation {
        r2-raw-intake-mkdir {
            set remote [list /usr/bin/mkdir --mode=0700 -- $intake]
            set tty 0
        }
        r2-raw-sync-intake-manifest {
            set remote [list /usr/bin/sync -- ${intake}/package-manifest.v1]
            set tty 0
        }
        r2-raw-sync-intake-self {
            set remote [list /usr/bin/sync -- ${intake}/prepare-stage-root.sh]
            set tty 0
        }
        r2-raw-sync-intake-directory {
            set remote [list /usr/bin/sync -- $intake]
            set tty 0
        }
        r2-raw-sync-intake-parent {
            set remote [list /usr/bin/sync -- \
                /home/siyixuan/wg-mix-ebpf-test]
            set tty 0
        }
        r2-raw-home-qroot-create {
            set remote [list /usr/bin/mkdir --mode=0700 -- $home]
            set tty 1
        }
        r2-raw-auth-root-create {
            set remote [list /usr/bin/mkdir --mode=0700 -- $auth]
            set tty 1
        }
        r2-raw-run-qroot-create {
            set remote [list /usr/bin/mkdir --mode=0700 -- $run]
            set tty 1
        }
        r2-raw-auth-manifest-install {
            set remote [list /usr/bin/install --owner=root --group=root \
                --mode=0600 --no-target-directory -- \
                ${intake}/package-manifest.v1 \
                ${auth}/package-manifest.v1.pending]
            set tty 1
        }
        r2-raw-auth-self-install {
            set remote [list /usr/bin/install --owner=root --group=root \
                --mode=0700 --no-target-directory -- \
                ${intake}/prepare-stage-root.sh \
                ${auth}/prepare-stage-root.sh.pending]
            set tty 1
        }
        r2-raw-sync-auth-manifest-pending {
            set remote [list /usr/bin/sync -- \
                ${auth}/package-manifest.v1.pending]
            set tty 1
        }
        r2-raw-sync-auth-self-pending {
            set remote [list /usr/bin/sync -- \
                ${auth}/prepare-stage-root.sh.pending]
            set tty 1
        }
        r2-raw-link-auth-manifest {
            set remote [list /usr/bin/ln --no-target-directory -- \
                ${auth}/package-manifest.v1.pending \
                ${auth}/package-manifest.v1]
            set tty 1
        }
        r2-raw-link-auth-self {
            set remote [list /usr/bin/ln --no-target-directory -- \
                ${auth}/prepare-stage-root.sh.pending \
                ${auth}/prepare-stage-root.sh]
            set tty 1
        }
        r2-raw-sync-auth-root {
            set remote [list /usr/bin/sync -- $auth]
            set tty 1
        }
        r2-raw-sync-home-parent {
            set remote [list /usr/bin/sync -- /home]
            set tty 1
        }
        r2-raw-sync-home-qroot {
            set remote [list /usr/bin/sync -- $home]
            set tty 1
        }
        r2-raw-sync-run-parent {
            set remote [list /usr/bin/sync -- /run]
            set tty 1
        }
        r2-raw-helper-mutate {
            set remote [list /bin/bash -p ${auth}/prepare-stage-root.sh \
                retire-postflight-f75fe7678cfd-r2 --manifest \
                ${auth}/package-manifest.v1 --manifest-sha256 \
                $::r2_manifest_sha]
            set tty 1
            if {[lindex $operation_spec 3] ne "r2-helper-mutate" ||
                [lindex $operation_spec 4] != 2400} {
                harness_die "r2-raw-helper-policy-$operation"
            }
        }
        default { harness_die "r2-test-raw-spec-$operation" }
    }
    if {$tty} {
        set remote [concat [list /usr/bin/sudo -- /usr/bin/env -i \
            PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C] $remote]
    }
    set expected [concat [r2_test_exact_ssh_prefix $tty] $remote]
    if {[lrange $spawn_argv 0 end] ne [lrange $expected 0 end]} {
        harness_die "r2-raw-argv operation=$operation actual=$spawn_argv expected=$expected"
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
        test_matrix_static.py checksum-module-lease.sh
        test-hermetic-checksum-module-lease.sh test_checksum_module_lease_static.py
        wg_mix_faketcp_checksum.c root-fresh-verifier-gate.sh
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
    lineage-output-pty {
        if {[llength $arguments] != 0} {
            harness_die "lineage-output-pty-arguments"
        }
        set ::credential_reads 0
        rename read_execute_credential \
            transport_original_read_execute_credential
        proc read_execute_credential {path} {
            incr ::credential_reads
            harness_die "line-ending-credential-read"
        }
        rename fail transport_original_fail
        proc fail {message code} {
            return -code error -errorcode [list B82FAIL $code] $message
        }
        set ::line_ending_spawns {}
        rename spawn transport_original_spawn
        proc spawn {args} {
            lappend ::line_ending_spawns $args
            return [uplevel 1 [list transport_original_spawn {*}$args]]
        }
        proc line_ending_assert_or_stop {assertion payload} {
            if {[catch {assert_output $assertion $payload}]} {
                fail "output-assertion" 78
            }
        }
        proc line_ending_require_accept {family assertion label payload} {
            if {[catch {
                line_ending_assert_or_stop $assertion $payload
            } message options]} {
                harness_die "line-ending-positive family=$family label=$label message=$message options=$options"
            }
        }
        proc line_ending_require_stop {family assertion label payload} {
            set caught [catch {
                line_ending_assert_or_stop $assertion $payload
            } message options]
            if {!$caught || ![dict exists $options -errorcode] ||
                [dict get $options -errorcode] ne {B82FAIL 78} ||
                $message ne "output-assertion"} {
                harness_die "line-ending-negative family=$family label=$label message=$message options=$options"
            }
        }
        proc line_ending_execute_expect_stop {label spawn_argv assertion} {
            set caught [catch {
                execute_operation_spec "line-ending-$label" \
                    [list local $spawn_argv 0 $assertion 10] ""
            } message options]
            if {!$caught || ![dict exists $options -errorcode] ||
                [dict get $options -errorcode] ne {B82FAIL 78} ||
                $message ne "output-assertion"} {
                harness_die "line-ending-pty-stop label=$label message=$message options=$options"
            }
        }
        set boot_id 01234567-89ab-cdef-0123-456789abcdef
        set lock_assertion "r1-lock-content:${boot_id}"
        set boot_positive [list \
            [list lf "${boot_id}\n"] \
            [list crlf "${boot_id}\r\n"] \
            [list crcrlf "${boot_id}\r\r\n"]]
        set lock_positive [list \
            [list lf "boot_id\t${boot_id}\n"] \
            [list crlf "boot_id\t${boot_id}\r\n"] \
            [list crcrlf "boot_id\t${boot_id}\r\r\n"]]
        set boot_negative [list \
            [list embedded-cr "01234567-89ab-cdef\r-0123-456789abcdef\n"] \
            [list triple-cr "${boot_id}\r\r\r\n"] \
            [list extra-line "${boot_id}\nextra\n"] \
            [list missing-newline "${boot_id}"] \
            [list extra-final-newline "${boot_id}\n\n"] \
            [list wrong-uuid "01234567-89ab-cdef-0123-456789abcdeG\n"]]
        set lock_negative [list \
            [list embedded-cr "boot_id\t01234567-89ab-cdef\r-0123-456789abcdef\n"] \
            [list triple-cr "boot_id\t${boot_id}\r\r\r\n"] \
            [list extra-line "boot_id\t${boot_id}\nextra\n"] \
            [list missing-newline "boot_id\t${boot_id}"] \
            [list extra-final-newline "boot_id\t${boot_id}\n\n"] \
            [list wrong-body "boot_id\t11234567-89ab-cdef-0123-456789abcdef\n"]]
        foreach test_case $boot_positive {
            lassign $test_case label payload
            line_ending_require_accept boot boot-uuid-line $label $payload
        }
        foreach test_case $lock_positive {
            lassign $test_case label payload
            line_ending_require_accept lock $lock_assertion $label $payload
        }
        foreach test_case $boot_negative {
            lassign $test_case label payload
            line_ending_require_stop boot boot-uuid-line $label $payload
        }
        foreach test_case $lock_negative {
            lassign $test_case label payload
            line_ending_require_stop lock $lock_assertion $label $payload
        }
        set boot_result [execute_operation_spec line-ending-boot-pty \
            [list local \
                [list /usr/bin/printf "%s\r\n" $boot_id] \
                0 boot-uuid-line 10] ""]
        set lock_result [execute_operation_spec line-ending-lock-pty \
            [list local \
                [list /usr/bin/printf "boot_id\t%s\r\n" $boot_id] \
                0 $lock_assertion 10] ""]
        line_ending_execute_expect_stop invalid-extra-char \
            [list /usr/bin/printf "%s\r\n" "${boot_id}x"] \
            boot-uuid-line
        line_ending_execute_expect_stop invalid-embedded-cr \
            [list /usr/bin/printf "%s\r\n" \
                "01234567-89ab-cdef\r-0123-456789abcdef"] \
            boot-uuid-line
        line_ending_execute_expect_stop invalid-multiline \
            [list /usr/bin/printf "%s\r\n%s\r\n" $boot_id extra] \
            boot-uuid-line
        set child_nonzero [execute_operation_spec line-ending-child-nonzero \
            [list local [list /usr/bin/python3 -B -I -c \
                {import sys; sys.exit(23)}] 0 none 10] ""]
        set signal_caught [catch {
            execute_operation_spec line-ending-child-signal \
                [list local [list /usr/bin/python3 -B -I -c \
                    {import os, signal; os.kill(os.getpid(), signal.SIGTERM)}] \
                    0 none 10] ""
        } signal_message signal_options]
        set expected_spawns [list \
            [list -noecho /usr/bin/printf "%s\r\n" $boot_id] \
            [list -noecho /usr/bin/printf "boot_id\t%s\r\n" $boot_id] \
            [list -noecho /usr/bin/printf "%s\r\n" "${boot_id}x"] \
            [list -noecho /usr/bin/printf "%s\r\n" \
                "01234567-89ab-cdef\r-0123-456789abcdef"] \
            [list -noecho /usr/bin/printf "%s\r\n%s\r\n" $boot_id extra] \
            [list -noecho /usr/bin/python3 -B -I -c \
                {import sys; sys.exit(23)}] \
            [list -noecho /usr/bin/python3 -B -I -c \
                {import os, signal; os.kill(os.getpid(), signal.SIGTERM)}]]
        if {[lindex $boot_result 0] ne "ok" ||
            [lindex $boot_result 1] != 0 ||
            [lindex $boot_result 2] ne "${boot_id}\r\r\n" ||
            [lindex $lock_result 0] ne "ok" ||
            [lindex $lock_result 1] != 0 ||
            [lindex $lock_result 2] ne "boot_id\t${boot_id}\r\r\n" ||
            [lrange $child_nonzero 0 1] ne {child-failure 23} ||
            !$signal_caught ||
            ![dict exists $signal_options -errorcode] ||
            [dict get $signal_options -errorcode] ne {B82FAIL 78} ||
            $signal_message ne "child-wait-status" ||
            $::line_ending_spawns ne $expected_spawns ||
            $::credential_reads != 0} {
            binary scan [lindex $boot_result 2] H* boot_hex
            binary scan [lindex $lock_result 2] H* lock_hex
            harness_die "line-ending-pty boot=$boot_result boot_hex=$boot_hex lock=$lock_result lock_hex=$lock_hex child_nonzero=$child_nonzero signal_caught=$signal_caught signal_message=$signal_message signal_options=$signal_options spawns=$::line_ending_spawns expected_spawns=$expected_spawns credential_reads=$::credential_reads"
        }
        puts "HARNESS_LINEAGE_OUTPUT_PTY cases=7 boot=PASS lock=PASS invalid_stops=3 child_nonzero=23 signal=STOP raw_suffix=0d0d0a credential_reads=0 network_operations=0 mutation_spawns=0 result=PASS"
        puts "HARNESS_LINE_ENDING_ASSERTIONS boot_positive=3 boot_stops=6 lock_positive=3 lock_stops=6 pty_children=7 raw_suffix=0d0d0a credential_reads=0 network_operations=0 mutation_spawns=0 result=PASS"
    }
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
        set ::lineage_legacy_helper_calls 0
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
            if {[regexp {^lineage-q-(package|bootstrap)-(stat|sha)-(.+)$} \
                    $operation]} {
                return [r2_test_r1_payload $operation]
            }
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
                lineage-lock-stat {
                    return "71:113:root:root:600:1:45:regular file"
                }
                lineage-receipt-stat {
                    return "root:root:600:1:regular file"
                }
                lineage-receipt-sha {
                    return "$receipt_sha  $::test_receipt_final"
                }
                lineage-boot-id-read - lineage-lock-content-read -
                lineage-lock-stat-recheck {
                    return [r2_test_r1_payload $operation]
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
            if {[regexp {^lineage-q-(package|bootstrap)-(stat|sha)-(.+)$} \
                    $operation -> scope family name]} {
                lassign [r2_test_r1_file_oracle $scope $name] size sha
                set root [expr {$scope eq "package" ?
                    $::test_q_package : $::test_q_bootstrap}]
                if {$family eq "stat"} {
                    set identity [expr {$scope eq "package" ?
                        "siyixuan:siyixuan:600" : "root:root:700"}]
                    return "exact:${identity}:1:${size}:regular file"
                }
                return "exact:${sha}  ${root}/${name}"
            }
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
                lineage-lock-stat {
                    return r1-lock-identity
                }
                lineage-receipt-stat {
                    return "exact:root:root:600:1:regular file"
                }
                lineage-receipt-sha {
                    return "exact:$receipt_sha  $::test_receipt_final"
                }
                lineage-boot-id-read { return boot-uuid-line }
                lineage-lock-content-read {
                    return "r1-lock-content:01234567-89ab-cdef-0123-456789abcdef"
                }
                lineage-lock-stat-recheck {
                    return "exact:71:113:root:root:600:1:45:regular file"
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
            if {[regexp {^lineage-q-(package|bootstrap)-(stat|sha)-(.+)$} \
                    $operation -> scope family name]} {
                set root [expr {$scope eq "package" ?
                    $::test_q_package : $::test_q_bootstrap}]
                set fixed_path "${root}/${name}"
                if {$family eq "stat"} {
                    set remote [concat $env_prefix [list /usr/bin/stat -Lc \
                        %U:%G:%a:%h:%s:%F -- $fixed_path]]
                } else {
                    set remote [concat $env_prefix \
                        [list /usr/bin/sha256sum -- $fixed_path]]
                }
                return [concat [lineage_test_ssh_prefix] $remote]
            }
            switch -- $operation {
                lineage-boot-id-read {
                    set remote [concat $env_prefix [list /usr/bin/cat -- \
                        /proc/sys/kernel/random/boot_id]]
                    return [concat [lineage_test_ssh_prefix] $remote]
                }
                lineage-lock-content-read {
                    set lock "$::test_run_qroot/retirement.v1.lock"
                    set remote [concat $env_prefix [list /usr/bin/dd \
                        "if=${lock}" iflag=nonblock,nofollow,fullblock \
                        bs=46 count=1 status=none]]
                    return [concat [lineage_test_ssh_prefix] $remote]
                }
                lineage-lock-stat-recheck {
                    set lock "$::test_run_qroot/retirement.v1.lock"
                    set remote [concat $env_prefix [list /usr/bin/stat -Lc \
                        %d:%i:%U:%G:%a:%h:%s:%F -- $lock]]
                    return [concat [lineage_test_ssh_prefix] $remote]
                }
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
                    set format %d:%i:%U:%G:%a:%h:%s:%F
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
            if {$operation eq "lineage-retained-helper-verify"} {
                incr ::lineage_legacy_helper_calls
                harness_die "lineage-legacy-helper-reachable"
            }
            if {[lindex $operation_spec 0] ne "ssh" ||
                [llength $operation_spec] != 5} {
                harness_die "lineage-operation-spec-$operation"
            }
            set actual_spawn_argv [lindex $operation_spec 1]
            set expected_spawn_argv \
                [lineage_test_expected_spawn_argv $operation]
            if {[lrange $actual_spawn_argv 0 end] ne
                    [lrange $expected_spawn_argv 0 end] ||
                [lindex $operation_spec 2] != 2 ||
                [lindex $operation_spec 4] != 600} {
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
        } [lineage_test_terminal_operations] \
            [r2_test_r1_deep_operations] {
            lineage-exists-user-intake lineage-exists-home-qroot
            lineage-exists-run-qroot lineage-exists-receipt-pending
        }]
        if {[llength [r2_test_r1_deep_operations]] != 41 ||
            [llength $terminal_expected] != 84 ||
            $terminal_state ne "TERMINAL" ||
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
                [lrange $terminal_expected 0 79] \
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
        proc lineage_test_failure_prefix {operation} {
            set base [lineage_test_terminal_operations]
            set retained [r2_test_r1_deep_operations]
            set base_index [lsearch -exact $base $operation]
            if {$base_index >= 0} {
                return [concat {
                    lineage-exists-user-intake lineage-exists-home-qroot
                    lineage-exists-run-qroot lineage-exists-receipt-pending
                } [lrange $base 0 $base_index]]
            }
            set retained_index [lsearch -exact $retained $operation]
            if {$retained_index >= 0} {
                return [concat {
                    lineage-exists-user-intake lineage-exists-home-qroot
                    lineage-exists-run-qroot lineage-exists-receipt-pending
                } $base [lrange $retained 0 $retained_index]]
            }
            harness_die "lineage-failure-prefix-$operation"
        }
        set deep_missing 0
        foreach operation [lineage_test_terminal_operations] {
            set ::lineage_scenario terminal-cut
            set ::lineage_fail_operation $operation
            set ::lineage_fail_kind missing
            set ::lineage_operations {}
            set ::lineage_presence_calls [dict create]
            set caught [catch {
                execute_retirement_lineage_gate $values \
                    [string repeat a 64] $password
            } message options]
            set expected_failure_prefix \
                [lineage_test_failure_prefix $operation]
            if {!$caught || ![dict exists $options -errorcode] ||
                [dict get $options -errorcode] ne {B82FAIL 78} ||
                [lrange $::lineage_operations 0 end] ne
                    [lrange $expected_failure_prefix 0 end]} {
                harness_die "lineage-terminal-cut operation=$operation message=$message options=$options operations=$::lineage_operations expected=$expected_failure_prefix"
            }
            incr deep_missing
        }
        set deep_nonzero 0
        foreach operation [concat [lineage_test_terminal_operations] \
                [r2_test_r1_deep_operations]] {
            set ::lineage_scenario terminal-cut
            set ::lineage_fail_operation $operation
            set ::lineage_fail_kind child-nonzero
            set ::lineage_operations {}
            set ::lineage_presence_calls [dict create]
            set caught [catch {
                execute_retirement_lineage_gate $values \
                    [string repeat a 64] $password
            } message options]
            set expected_failure_prefix \
                [lineage_test_failure_prefix $operation]
            if {!$caught || ![dict exists $options -errorcode] ||
                [dict get $options -errorcode] ne {B82FAIL 78} ||
                [lrange $::lineage_operations 0 end] ne
                    [lrange $expected_failure_prefix 0 end]} {
                harness_die "lineage-deep-nonzero operation=$operation message=$message options=$options operations=$::lineage_operations expected=$expected_failure_prefix"
            }
            incr deep_nonzero
        }
        set assertion_malformed 0
        foreach operation [concat {
            lineage-home-readlink lineage-home-stat lineage-home-entries
            lineage-auth-manifest-sha lineage-auth-manifest-pair
        } [r2_test_r1_deep_operations]] {
            set ::lineage_scenario terminal-cut
            set ::lineage_fail_operation $operation
            set ::lineage_fail_kind malformed
            set ::lineage_operations {}
            set ::lineage_presence_calls [dict create]
            set caught [catch {
                execute_retirement_lineage_gate $values \
                    [string repeat a 64] $password
            } message options]
            set expected_failure_prefix \
                [lineage_test_failure_prefix $operation]
            if {!$caught || ![dict exists $options -errorcode] ||
                [dict get $options -errorcode] ne {B82FAIL 78} ||
                [lrange $::lineage_operations 0 end] ne
                    [lrange $expected_failure_prefix 0 end]} {
                harness_die "lineage-malformed operation=$operation message=$message options=$options operations=$::lineage_operations expected=$expected_failure_prefix"
            }
            incr assertion_malformed
        }
        set retained_signals 0
        foreach operation [r2_test_r1_deep_operations] {
            set ::lineage_scenario terminal-cut
            set ::lineage_fail_operation $operation
            set ::lineage_fail_kind signal
            set ::lineage_operations {}
            set ::lineage_presence_calls [dict create]
            set caught [catch {
                execute_retirement_lineage_gate $values \
                    [string repeat a 64] $password
            } message options]
            set expected_failure_prefix \
                [lineage_test_failure_prefix $operation]
            if {!$caught || ![dict exists $options -errorcode] ||
                [dict get $options -errorcode] ne {B82FAIL 78} ||
                [lrange $::lineage_operations 0 end] ne
                    [lrange $expected_failure_prefix 0 end]} {
                harness_die "lineage-retained-signal operation=$operation message=$message options=$options operations=$::lineage_operations expected=$expected_failure_prefix"
            }
            incr retained_signals
        }
        if {$deep_missing != 35 || $deep_nonzero != 76 ||
            $assertion_malformed != 46 || $retained_signals != 41 ||
            $recheck_drifts != 4 || $partial_count != 6 ||
            $::lineage_legacy_helper_calls != 0 ||
            $::credential_reads != 1 || $::lineage_mutation_spawns != 0} {
            harness_die "lineage-summary missing=$deep_missing nonzero=$deep_nonzero malformed=$assertion_malformed retained_signals=$retained_signals legacy_helper_calls=$::lineage_legacy_helper_calls recheck=$recheck_drifts partial=$partial_count credential_reads=$::credential_reads mutation_spawns=$::lineage_mutation_spawns"
        }
        puts "HARNESS_LINEAGE_GATE fresh=PASS terminal=PASS primitives=84 retained_files=19 retained_ops=41 lock_inode_stable=1 partial_states=6 receipt_pending=STOP recheck_drifts=4 deep_missing=35 deep_nonzero=76 retained_malformed=41 retained_signals=41 legacy_helper_calls=0 credential_reads=1 mutation_spawns=0 result=PASS"
    }
    r1-source-reuse {
        if {[llength $arguments] != 3} {
            harness_die "r1-source-reuse-arguments"
        }
        lassign $arguments manifest manifest_sha predecessor_package
        set ::R2_PREDECESSOR_LOCAL_PACKAGE $predecessor_package
        if {[catch {load_manifest $manifest $manifest_sha} values] ||
            [catch {validate_manifest_values $values}] ||
            [catch {r2_load_predecessor_manifest \
                "${predecessor_package}/package-manifest.v1"} \
                predecessor_values]} {
            harness_die "r1-source-reuse-local-authority"
        }
        set full_prewrite [r2_test_prewrite_sequence]
        set r1_expected [lrange $full_prewrite 0 83]
        set predecessor_expected [lrange $full_prewrite 130 177]
        if {[llength $full_prewrite] != 178 ||
            [llength $r1_expected] != 84 ||
            [llength $predecessor_expected] != 48 ||
            [lindex $r1_expected 0] ne "lineage-exists-user-intake" ||
            [lindex $r1_expected 83] ne "lineage-exists-receipt-pending" ||
            [lindex $predecessor_expected 0] ne "package-parent-stat" ||
            [lindex $predecessor_expected 47] ne \
                "r2-ro-old-provision-check"} {
            harness_die "r1-source-reuse-literal-oracle"
        }
        set ::reuse_expected [concat $r1_expected $predecessor_expected]
        set ::reuse_observed {}
        set ::reuse_legacy_helper_calls 0
        set ::reuse_qpackage_deep 0
        set ::reuse_qbootstrap_deep 0
        rename fail transport_original_fail
        proc fail {message code} {
            return -code error -errorcode [list B82FAIL $code] $message
        }
        rename execute_operation_spec transport_original_execute_operation_spec
        proc execute_operation_spec {operation operation_spec password} {
            if {$operation eq "lineage-retained-helper-verify"} {
                incr ::reuse_legacy_helper_calls
                return [list child-failure 79 \
                    {B82_V6_RETIREMENT_ENGINE_STOP reason=retirement-state rc=79 cleanup=0 retained=1} none]
            }
            set ordinal [llength $::reuse_observed]
            set expected [lindex $::reuse_expected $ordinal]
            set expected_prompt [expr {$operation eq "package-parent-stat" ?
                1 : 2}]
            if {$operation ne $expected || [llength $operation_spec] != 5 ||
                [lindex $operation_spec 0] ne "ssh" ||
                [lindex $operation_spec 2] != $expected_prompt ||
                [lindex $operation_spec 4] != 600} {
                harness_die "r1-source-reuse-order ordinal=$ordinal operation=$operation expected=$expected spec=$operation_spec"
            }
            lappend ::reuse_observed $operation
            if {[string match "lineage-q-package-*-*" $operation]} {
                incr ::reuse_qpackage_deep
            }
            if {[string match "lineage-q-bootstrap-*-*" $operation]} {
                incr ::reuse_qbootstrap_deep
            }
            lassign [r2_test_remote_payload $operation] disposition payload policy
            if {$disposition eq "absent"} {
                return [list child-failure 1 "" none]
            }
            set assertion [lindex $operation_spec 3]
            if {$operation ne "r2-ro-old-provision-check" &&
                [catch {assert_output $assertion $payload} reason]} {
                harness_die "r1-source-reuse-output operation=$operation assertion=$assertion payload=$payload reason=$reason"
            }
            return [list ok 0 $payload $policy]
        }
        r2_require_r1_terminal $values $manifest_sha fixture-password \
            source-reuse
        r2_execute_predecessor_gate $values $manifest_sha $predecessor_values \
            fixture-password
        if {$::reuse_observed ne $::reuse_expected ||
            $::reuse_legacy_helper_calls != 0 ||
            $::reuse_qpackage_deep != 34 ||
            $::reuse_qbootstrap_deep != 4} {
            harness_die "r1-source-reuse-summary observed=$::reuse_observed legacy=$::reuse_legacy_helper_calls qpackage=$::reuse_qpackage_deep qbootstrap=$::reuse_qbootstrap_deep"
        }
        puts "HARNESS_R1_SOURCE_REUSE r1_gate=84 qpackage=present qbootstrap=present source_package=present source_bootstrap=present retained_file_checks=38 lock_inode_stable=1 predecessor_deep=48 legacy_helper_calls=0 result=PASS"
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
    r2-prewrite-cuts {
        if {[llength $arguments] != 3} {
            harness_die "r2-prewrite-arguments"
        }
        lassign $arguments manifest manifest_sha predecessor_package
        set ::R2_PREDECESSOR_LOCAL_PACKAGE $predecessor_package
        if {[catch {load_manifest $manifest $manifest_sha} values] ||
            [catch {validate_manifest_values $values}] ||
            [catch {r2_load_predecessor_manifest \
                "${predecessor_package}/package-manifest.v1"} predecessor_values]} {
            harness_die "r2-prewrite-local-authority"
        }
        set ::r2_expected [r2_test_prewrite_sequence]
        if {[llength $::r2_expected] != 178 ||
            [lindex $::r2_expected 177] ne "r2-ro-old-provision-check"} {
            harness_die "r2-prewrite-literal-cardinality"
        }
        set ::r2_raw [r2_test_raw_sequence]
        set ::r2_cut 0
        set ::r2_cut_kind child-nonzero
        set ::r2_observed {}
        set ::r2_mutations {}
        rename exit harness_real_exit
        proc exit {{code 0}} {
            return -code error -errorcode \
                [list R2_TRANSACTION_EXIT $code] "exit-$code"
        }
        rename execute_operation_spec transport_original_execute_operation_spec
        proc execute_operation_spec {operation operation_spec password} {
            set ordinal [llength $::r2_observed]
            set expected_operation [lindex $::r2_expected $ordinal]
            if {$operation ne $expected_operation} {
                harness_die "r2-prewrite-order ordinal=$ordinal actual=$operation expected=$expected_operation"
            }
            if {[llength $operation_spec] != 5 ||
                [lindex $operation_spec 0] ni {ssh scp local} ||
                [lsearch -exact [lindex $operation_spec 1] \
                    /Users/siyixuan/codes-2/wg-mix-ebpf/credientials/192.168.10.82] >= 0} {
                harness_die "r2-prewrite-operation-spec-$operation"
            }
            lappend ::r2_observed $operation
            set spawn_argv [lindex $operation_spec 1]
            if {[lsearch -exact $::r2_raw $operation] >= 0 ||
                [lsearch -exact $spawn_argv /usr/bin/mkdir] >= 0 ||
                [lsearch -exact $spawn_argv /usr/bin/install] >= 0 ||
                [lsearch -exact $spawn_argv /usr/bin/scp] >= 0 ||
                [lsearch -exact $spawn_argv /bin/mv] >= 0 ||
                [lsearch -exact $spawn_argv /bin/rm] >= 0 ||
                [lsearch -exact $spawn_argv --apply] >= 0} {
                lappend ::r2_mutations $operation
            }
            if {$ordinal == $::r2_cut} {
                if {$::r2_cut_kind eq "child-nonzero"} {
                    return [list child-failure 73 "" none]
                }
                fail "child-wait-status" 78
            }
            lassign [r2_test_remote_payload $operation] disposition payload policy
            if {$disposition eq "absent"} {
                return [list child-failure 1 "" none]
            }
            set assertion [lindex $operation_spec 3]
            if {$operation ne "r2-ro-old-provision-check" &&
                [catch {assert_output $assertion $payload} assertion_message]} {
                harness_die "r2-prewrite-output operation=$operation assertion=$assertion payload=$payload reason=$assertion_message"
            }
            if {$operation eq "r2-ro-old-provision-check"} {
                set expected_tail {
                    /bin/bash -p
                    /run/wg-mix-ebpf-source-bootstrap-c8e41d73/provision-ubuntu-test-host.sh
                    --check --expected-address 192.168.10.82
                    --expected-interface ens33
                    --expected-hostname ubuntu-2604-test
                    --expected-kernel 7.0.0-28-generic
                    --expected-machine-id 9db3fb717cc74974b2a6b243d67f67b9
                }
                set actual_tail [lrange $spawn_argv end-14 end]
                if {$actual_tail ne $expected_tail || $assertion ne "provision-check"} {
                    harness_die "r2-prewrite-provision-argv actual=$actual_tail"
                }
            }
            return [list ok 0 $payload $policy]
        }
        set child_nonzero 0
        set child_signal 0
        foreach cut_kind {child-nonzero signal} {
            set ::r2_cut_kind $cut_kind
            for {set cut 0} {$cut < 178} {incr cut} {
                set ::r2_cut $cut
                set ::r2_observed {}
                set ::r2_mutations {}
                unset -nocomplain ::R2_MUTATION_TRACE_ACTIVE \
                    ::R2_MUTATION_TRACE ::R2_MUTATION_INITIAL_PHASE \
                    ::R2_MUTATION_INTAKE_CREATED
                set caught [catch {
                    execute_r2_transaction $values $manifest_sha \
                        $predecessor_values fixture-password
                } message options]
                set expected_rc [expr {
                    $cut_kind eq "signal" || $cut < 84 ? 78 : 73
                }]
                set expected_prefix [lrange $::r2_expected 0 $cut]
                if {!$caught || ![dict exists $options -errorcode] ||
                    [dict get $options -errorcode] ne \
                        [list R2_TRANSACTION_EXIT $expected_rc] ||
                    [lrange $::r2_observed 0 end] ne
                        [lrange $expected_prefix 0 end] ||
                    [llength $::r2_mutations] != 0} {
                    set errorcode [expr {[dict exists $options -errorcode] ?
                        [dict get $options -errorcode] : "missing"}]
                    harness_die "r2-prewrite-cut=$cut kind=$cut_kind rc=$errorcode observed=$::r2_observed mutations=$::r2_mutations message=$message"
                }
                if {$cut_kind eq "child-nonzero"} {
                    incr child_nonzero
                } else {
                    incr child_signal
                }
            }
        }
        if {$child_nonzero != 178 || $child_signal != 178} {
            harness_die "r2-prewrite-summary nonzero=$child_nonzero signal=$child_signal"
        }
        puts "HARNESS_R2_PREWRITE_CUTS primitives=178 cuts=356 mutations=0 child_nonzero=178 child_signal=178 r1_gate=84 authority=13 common=33 predecessor=48 result=PASS"
        harness_real_exit 0
    }
    r2-first-write {
        if {[llength $arguments] != 3} {
            harness_die "r2-first-write-arguments"
        }
        lassign $arguments manifest manifest_sha predecessor_package
        set ::R2_PREDECESSOR_LOCAL_PACKAGE $predecessor_package
        if {[catch {load_manifest $manifest $manifest_sha} values] ||
            [catch {validate_manifest_values $values}] ||
            [catch {r2_load_predecessor_manifest \
                "${predecessor_package}/package-manifest.v1"} predecessor_values]} {
            harness_die "r2-first-write-local-authority"
        }
        set ::r2_expected [r2_test_prewrite_sequence]
        set ::r2_observed {}
        set ::r2_mutations {}
        set ::r2_scp 0
        rename exit harness_real_exit
        proc exit {{code 0}} {
            return -code error -errorcode \
                [list R2_TRANSACTION_EXIT $code] "exit-$code"
        }
        rename execute_operation_spec transport_original_execute_operation_spec
        proc execute_operation_spec {operation operation_spec password} {
            set ordinal [llength $::r2_observed]
            if {$ordinal < 178} {
                set expected_operation [lindex $::r2_expected $ordinal]
            } else {
                set expected_operation r2-raw-intake-mkdir
            }
            if {$operation ne $expected_operation} {
                harness_die "r2-first-write-order ordinal=$ordinal actual=$operation expected=$expected_operation"
            }
            lappend ::r2_observed $operation
            set spawn_argv [lindex $operation_spec 1]
            if {[lindex $operation_spec 0] eq "scp" ||
                [lsearch -exact $spawn_argv /usr/bin/scp] >= 0} {
                incr ::r2_scp
            }
            if {$ordinal == 178} {
                set expected_tail [list /usr/bin/mkdir --mode=0700 -- \
                    /home/siyixuan/wg-mix-ebpf-test/retire-postflight-c8e41d73-f75fe7678cfd-r2.intake]
                if {[lrange $spawn_argv end-3 end] ne $expected_tail ||
                    [lindex $operation_spec 0] ne "ssh" ||
                    [lindex $operation_spec 2] != 1 ||
                    [lindex $operation_spec 3] ne "none"} {
                    harness_die "r2-first-write-argv actual=$spawn_argv"
                }
                lappend ::r2_mutations $operation
                return [list child-failure 73 "" none]
            }
            lassign [r2_test_remote_payload $operation] disposition payload policy
            if {$disposition eq "absent"} {
                return [list child-failure 1 "" none]
            }
            set assertion [lindex $operation_spec 3]
            if {$operation ne "r2-ro-old-provision-check" &&
                [catch {assert_output $assertion $payload} assertion_message]} {
                harness_die "r2-first-write-output operation=$operation reason=$assertion_message"
            }
            return [list ok 0 $payload $policy]
        }
        set caught [catch {
            execute_r2_transaction $values $manifest_sha $predecessor_values \
                fixture-password
        } message options]
        set expected [concat $::r2_expected {r2-raw-intake-mkdir}]
        if {!$caught || ![dict exists $options -errorcode] ||
            [dict get $options -errorcode] ne {R2_TRANSACTION_EXIT 73} ||
            [lrange $::r2_observed 0 end] ne [lrange $expected 0 end] ||
            $::r2_mutations ne {r2-raw-intake-mkdir} || $::r2_scp != 0} {
            set errorcode [expr {[dict exists $options -errorcode] ?
                [dict get $options -errorcode] : "missing"}]
            set mismatch none
            for {set index 0} {$index < [llength $expected]} {incr index} {
                if {[lindex $::r2_observed $index] ne [lindex $expected $index]} {
                    set mismatch "$index:[lindex $::r2_observed $index]!=[lindex $expected $index]"
                    break
                }
            }
            harness_die "r2-first-write rc=$errorcode caught=$caught observed_equal=[expr {$::r2_observed eq $expected}] observed_count=[llength $::r2_observed] expected_count=[llength $expected] mismatch=$mismatch mutation_equal=[expr {$::r2_mutations eq {r2-raw-intake-mkdir}}] scp=$::r2_scp message=$message"
        }
        puts "HARNESS_R2_FIRST_WRITE index=178 ordinal=179 operation=r2-raw-intake-mkdir rc=73 scp=0 result=PASS"
        harness_real_exit 0
    }
    r2-provision-cuts {
        if {[llength $arguments] != 3} {
            harness_die "r2-provision-cuts-arguments"
        }
        lassign $arguments manifest manifest_sha predecessor_package
        set ::R2_PREDECESSOR_LOCAL_PACKAGE $predecessor_package
        if {[catch {load_manifest $manifest $manifest_sha} values] ||
            [catch {validate_manifest_values $values}] ||
            [catch {r2_load_predecessor_manifest \
                "${predecessor_package}/package-manifest.v1"} predecessor_values]} {
            harness_die "r2-provision-cuts-local-authority"
        }
        set ::r2_expected [r2_test_prewrite_sequence]
        set ::r2_raw [r2_test_raw_sequence]
        set ::r2_scenario none
        set ::r2_observed {}
        set ::r2_mutations {}
        set ::r2_scp 0
        rename fail transport_original_fail
        proc fail {message code} {
            return -code error -errorcode [list B82FAIL $code] $message
        }
        rename exit harness_real_exit
        proc exit {{code 0}} {
            return -code error -errorcode \
                [list R2_TRANSACTION_EXIT $code] "exit-$code"
        }
        rename execute_operation_spec transport_original_execute_operation_spec
        proc execute_operation_spec {operation operation_spec password} {
            lappend ::r2_observed $operation
            set spawn_argv [lindex $operation_spec 1]
            if {[lsearch -exact $::r2_raw $operation] >= 0 ||
                [lsearch -exact $spawn_argv /usr/bin/mkdir] >= 0 ||
                [lsearch -exact $spawn_argv /usr/bin/install] >= 0 ||
                [lsearch -exact $spawn_argv /usr/bin/scp] >= 0 ||
                [lsearch -exact $spawn_argv /bin/mv] >= 0 ||
                [lsearch -exact $spawn_argv /bin/rm] >= 0 ||
                [lsearch -exact $spawn_argv --apply] >= 0} {
                lappend ::r2_mutations $operation
            }
            if {[lindex $operation_spec 0] eq "scp"} {
                incr ::r2_scp
            }
            if {$operation eq "stale-stage-root" &&
                $::r2_scenario in {stage-present stage-symlink}} {
                set stage_path /run/wg-mix-ebpf-source-stages/c8e41d73
                set remote [concat [list /usr/bin/sudo --] \
                    [list /usr/bin/env -i \
                        PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C] \
                    [list /usr/bin/test ! -e $stage_path -a ! -L $stage_path]]
                set expected [concat [r2_test_exact_ssh_prefix 1] $remote]
                if {[lindex $operation_spec 0] ne "ssh" ||
                    [lrange $spawn_argv 0 end] ne [lrange $expected 0 end] ||
                    [lindex $operation_spec 2] != 2 ||
                    [lindex $operation_spec 3] ne "none" ||
                    [lindex $operation_spec 4] != 600} {
                    harness_die "r2-stage-spec scenario=$::r2_scenario actual=$operation_spec expected=$expected"
                }
                return [list child-failure 1 "" none]
            }
            if {$operation eq "r2-ro-old-provision-check"} {
                set provisioner \
                    /run/wg-mix-ebpf-source-bootstrap-c8e41d73/provision-ubuntu-test-host.sh
                set remote [concat [list /usr/bin/sudo --] \
                    [list /usr/bin/env -i \
                        PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C] \
                    [list /bin/bash -p $provisioner --check \
                        --expected-address 192.168.10.82 \
                        --expected-interface ens33 \
                        --expected-hostname ubuntu-2604-test \
                        --expected-kernel 7.0.0-28-generic \
                        --expected-machine-id \
                        9db3fb717cc74974b2a6b243d67f67b9]]
                set expected [concat [r2_test_exact_ssh_prefix 1] $remote]
                if {[lindex $operation_spec 0] ne "ssh" ||
                    [lrange $spawn_argv 0 end] ne [lrange $expected 0 end] ||
                    [lindex $operation_spec 2] != 2 ||
                    [lindex $operation_spec 3] ne "provision-check" ||
                    [lindex $operation_spec 4] != 600} {
                    harness_die "r2-provision-spec scenario=$::r2_scenario actual=$operation_spec expected=$expected"
                }
                switch -- $::r2_scenario {
                    child-nonzero {
                        return [list child-failure 73 "" none]
                    }
                    signal { fail "child-wait-status" 78 }
                    initial - iperf3 - malformed - writes1 {
                        set payload [r2_test_provision_payload $::r2_scenario]
                        if {[catch {provision_plan_policy $payload check} policy]} {
                            fail "output-assertion" 78
                        }
                        return [list ok 0 $payload $policy]
                    }
                    default {
                        harness_die "r2-provision-unexpected-scenario-$::r2_scenario"
                    }
                }
            }
            lassign [r2_test_remote_payload $operation] disposition payload policy
            if {$disposition eq "absent"} {
                return [list child-failure 1 "" none]
            }
            set assertion [lindex $operation_spec 3]
            if {[catch {assert_output $assertion $payload} assertion_message]} {
                fail "output-assertion" 78
            }
            return [list ok 0 $payload $policy]
        }
        set stage_count 0
        set provision_count 0
        foreach scenario {
            stage-present stage-symlink initial iperf3 malformed writes1
            child-nonzero signal
        } {
            set ::r2_scenario $scenario
            set ::r2_observed {}
            set ::r2_mutations {}
            set ::r2_scp 0
            foreach variable {
                R2_MUTATION_TRACE_ACTIVE R2_MUTATION_TRACE
                R2_MUTATION_INITIAL_PHASE R2_MUTATION_INTAKE_CREATED
            } {
                catch {unset ::$variable}
            }
            set caught [catch {
                execute_r2_transaction $values $manifest_sha \
                    $predecessor_values fixture-password
            } message options]
            if {$scenario in {stage-present stage-symlink}} {
                set final_index [lsearch -exact $::r2_expected stale-stage-root]
                set expected_error {R2_TRANSACTION_EXIT 1}
                incr stage_count
            } else {
                set final_index 177
                set expected_error [expr {$scenario eq "child-nonzero" ?
                    [list R2_TRANSACTION_EXIT 73] : [list B82FAIL 78]}]
                incr provision_count
            }
            set expected_prefix [lrange $::r2_expected 0 $final_index]
            set trace [expr {[info exists ::R2_MUTATION_TRACE] ?
                $::R2_MUTATION_TRACE : {}}]
            if {!$caught || ![dict exists $options -errorcode] ||
                [dict get $options -errorcode] ne $expected_error ||
                [lrange $::r2_observed 0 end] ne
                    [lrange $expected_prefix 0 end] ||
                [llength $::r2_mutations] != 0 || [llength $trace] != 0 ||
                $::r2_scp != 0} {
                set errorcode [expr {[dict exists $options -errorcode] ?
                    [dict get $options -errorcode] : "missing"}]
                harness_die "r2-provision-cut scenario=$scenario rc=$errorcode observed=$::r2_observed expected=$expected_prefix mutations=$::r2_mutations trace=$trace scp=$::r2_scp message=$message"
            }
        }
        if {$stage_count != 2 || $provision_count != 6} {
            harness_die "r2-provision-summary stage=$stage_count provision=$provision_count"
        }
        puts "HARNESS_R2_PROVISION_CUTS stage_present_symlink=2 provision_initial_iperf3_malformed_writes1_nonzero_signal=6 prewrite_mutations=0 scp=0 result=PASS"
        harness_real_exit 0
    }
    r2-private-surface {
        if {[llength $arguments] != 0} {
            harness_die "r2-private-surface-arguments"
        }
        set private_ro [r2_test_private_read_only]
        set private_raw [r2_test_raw_sequence]
        if {[llength $private_ro] != 96 || [llength $private_raw] != 21} {
            harness_die "r2-private-surface-cardinality ro=[llength $private_ro] raw=[llength $private_raw]"
        }
        set ::credential_reads 0
        set ::spawns 0
        rename fail transport_original_fail
        proc fail {message code} {
            return -code error -errorcode [list B82FAIL $code] $message
        }
        rename read_execute_credential transport_original_read_execute_credential
        proc read_execute_credential {credential_path} {
            incr ::credential_reads
            return fixture-password
        }
        rename execute_operation_spec transport_original_execute_operation_spec
        proc execute_operation_spec {operation operation_spec password} {
            incr ::spawns
            return [list ok 0 "" none]
        }
        set rejections 0
        foreach operation [concat $private_ro $private_raw] {
            foreach action {plan execute} {
                set invocation [list \
                    --manifest /private/tmp/nonexistent-r2-private-manifest \
                    --manifest-sha256 [string repeat a 64] \
                    --credential-path /Users/siyixuan/codes-2/wg-mix-ebpf/credientials/192.168.10.82 \
                    --action $action --operation $operation \
                    --approved-plan-sha256 none]
                set caught [catch {transport_main $invocation} message options]
                if {!$caught || ![dict exists $options -errorcode] ||
                    [dict get $options -errorcode] ne {B82FAIL 65} ||
                    $message ne "private-operation"} {
                    harness_die "r2-private-surface operation=$operation action=$action message=$message options=$options"
                }
                incr rejections
            }
        }
        if {$rejections != 234 || $::credential_reads != 0 || $::spawns != 0 ||
            ![r2_mutation_operation retire-postflight-f75fe7678cfd-r2] ||
            ![r2_read_only_operation verify-postflight-retirement-r2] ||
            [r2_mutation_operation verify-postflight-retirement-r2] ||
            [r2_read_only_operation retire-postflight-f75fe7678cfd-r2]} {
            harness_die "r2-private-surface-summary rejections=$rejections credential=$::credential_reads spawns=$::spawns"
        }
        puts "HERMETIC_R2_PRIVATE_SURFACE public=2 ro=96 raw=21 plan_execute_rejections=234 credential_reads=0 spawns=0 result=PASS"
    }
    r2-precredential {
        if {[llength $arguments] != 3} {
            harness_die "r2-precredential-arguments"
        }
        lassign $arguments manifest manifest_sha predecessor_package
        set ::R2_PREDECESSOR_LOCAL_PACKAGE $predecessor_package
        set ::r2_authority_trace {}
        set ::r2_credential_reads 0
        set ::r2_remote_spawns 0
        rename fail transport_original_fail
        proc fail {message code} {
            return -code error -errorcode [list B82FAIL $code] $message
        }
        rename require_transaction_local_authority \
            production_require_transaction_local_authority
        proc require_transaction_local_authority args {
            lappend ::r2_authority_trace current
            return [production_require_transaction_local_authority {*}$args]
        }
        rename r2_require_predecessor_authority \
            production_r2_require_predecessor_authority
        proc r2_require_predecessor_authority {} {
            lappend ::r2_authority_trace predecessor
            return [production_r2_require_predecessor_authority]
        }
        rename execute_r2_predecessor_controller_verifier \
            production_execute_r2_predecessor_controller_verifier
        proc execute_r2_predecessor_controller_verifier args {
            lappend ::r2_authority_trace controller-seam
            return [production_execute_r2_predecessor_controller_verifier {*}$args]
        }
        rename read_execute_credential production_read_execute_credential
        proc read_execute_credential {credential_path} {
            incr ::r2_credential_reads
            lappend ::r2_authority_trace credential
            fail "r2-test-credential-stop" 91
        }
        rename execute_operation_spec production_execute_operation_spec
        proc execute_operation_spec {operation operation_spec password} {
            incr ::r2_remote_spawns
            harness_die "r2-precredential-remote-spawn-$operation"
        }
        set invocation [list \
            --manifest $manifest --manifest-sha256 $manifest_sha \
            --credential-path /Users/siyixuan/codes-2/wg-mix-ebpf/credientials/192.168.10.82 \
            --action execute --operation retire-postflight-f75fe7678cfd-r2 \
            --approved-plan-sha256 none]
        set caught [catch {transport_main $invocation} message options]
        if {!$caught || ![dict exists $options -errorcode] ||
            [dict get $options -errorcode] ne {B82FAIL 91} ||
            $message ne "r2-test-credential-stop" ||
            $::r2_authority_trace ne \
                {current predecessor controller-seam credential} ||
            $::r2_credential_reads != 1 || $::r2_remote_spawns != 0} {
            harness_die "r2-precredential trace=$::r2_authority_trace credential=$::r2_credential_reads spawns=$::r2_remote_spawns message=$message options=$options"
        }
        puts "HERMETIC_R2_PRECREDENTIAL current=v5/112/20 predecessor=v4/103/17 order=current,predecessor,credential controller_seam=before-credential credential_reads=1 remote_spawns=0 result=PASS"
    }
    r2-authority-prefixes {
        if {[llength $arguments] != 3} {
            harness_die "r2-authority-prefixes-arguments"
        }
        lassign $arguments manifest manifest_sha predecessor_package
        set ::R2_PREDECESSOR_LOCAL_PACKAGE $predecessor_package
        if {[catch {load_manifest $manifest $manifest_sha} values] ||
            [catch {validate_manifest_values $values}] ||
            [catch {r2_load_predecessor_manifest \
                "${predecessor_package}/package-manifest.v1"} predecessor_values]} {
            harness_die "r2-authority-prefixes-local-authority"
        }
        set ::r2_manifest_sha $manifest_sha
        set ::r2_self_sha [dict get $values prepare_stage_root_sh_sha256]
        set ::r2_pending_size 0
        set ::r2_pending_sha \
            e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        set ::r2_foreign none
        set ::r2_operations {}
        rename fail transport_original_fail
        proc fail {message code} {
            return -code error -errorcode [list B82FAIL $code] $message
        }
        rename execute_operation_spec transport_original_execute_operation_spec
        proc execute_operation_spec {operation operation_spec password} {
            lappend ::r2_operations $operation
            if {[llength $operation_spec] != 5 ||
                [lindex $operation_spec 0] ne "ssh"} {
                harness_die "r2-authority-operation-spec-$operation"
            }
            lassign [r2_test_authority_payload $operation] \
                disposition payload policy
            if {$disposition eq "absent"} {
                return [list child-failure 1 "" none]
            }
            set assertion [lindex $operation_spec 3]
            if {[catch {assert_output $assertion $payload} assertion_message]} {
                harness_die "r2-authority-output operation=$operation assertion=$assertion payload=$payload reason=$assertion_message"
            }
            return [list ok 0 $payload $policy]
        }
        set names {
            home-qroot auth-root run-qroot auth-manifest-pending auth-manifest
            auth-self-pending auth-self quarantine-intake quarantine-package
            quarantine-bootstrap lock receipt-pending receipt-final
        }
        set legal [list \
            [list absent {}] \
            [list home-qroot {home-qroot}] \
            [list auth-root {home-qroot auth-root}] \
            [list run-qroot {home-qroot auth-root run-qroot}] \
            [list manifest-pending \
                {home-qroot auth-root run-qroot auth-manifest-pending}] \
            [list manifest-pair \
                {home-qroot auth-root run-qroot auth-manifest-pending auth-manifest}] \
            [list self-pending \
                {home-qroot auth-root run-qroot auth-manifest-pending auth-manifest auth-self-pending}] \
            [list complete \
                {home-qroot auth-root run-qroot auth-manifest-pending auth-manifest auth-self-pending auth-self}]]
        set legal_count 0
        foreach scenario $legal {
            lassign $scenario expected_phase present_names
            set ::r2_present [dict create]
            foreach name $names { dict set ::r2_present $name 0 }
            foreach name $present_names { dict set ::r2_present $name 1 }
            set ::r2_foreign none
            set ::r2_operations {}
            set state [r2_authority_state $values $manifest_sha \
                $predecessor_values fixture-password]
            if {[dict get $state phase] ne $expected_phase ||
                [llength $::r2_operations] < 13} {
                harness_die "r2-authority-legal expected=$expected_phase state=$state operations=$::r2_operations"
            }
            incr legal_count
        }
        set ::r2_present [dict create]
        foreach name $names { dict set ::r2_present $name 0 }
        foreach name {home-qroot auth-root run-qroot auth-manifest-pending auth-self-pending} {
            dict set ::r2_present $name 1
        }
        set ::r2_foreign none
        set pending_pair [r2_authority_state $values $manifest_sha \
            $predecessor_values fixture-password]
        if {[dict get $pending_pair phase] ne "manifest-pending"} {
            harness_die "r2-authority-both-pending-$pending_pair"
        }
        set invalid [list \
            [list auth-without-home {auth-root} none] \
            [list run-without-auth {home-qroot run-qroot} none] \
            [list final-without-pending \
                {home-qroot auth-root run-qroot auth-manifest} none] \
            [list quarantine-before-authority {quarantine-package} none] \
            [list foreign-auth {home-qroot auth-root} auth]]
        set invalid_count 0
        foreach scenario $invalid {
            lassign $scenario label present_names foreign
            set ::r2_present [dict create]
            foreach name $names { dict set ::r2_present $name 0 }
            foreach name $present_names { dict set ::r2_present $name 1 }
            set ::r2_foreign $foreign
            set caught [catch {
                r2_authority_state $values $manifest_sha $predecessor_values \
                    fixture-password
            } message options]
            if {!$caught || ![dict exists $options -errorcode] ||
                [dict get $options -errorcode] ne {B82FAIL 78}} {
                harness_die "r2-authority-invalid label=$label message=$message options=$options"
            }
            incr invalid_count
        }
        set complete_names {
            home-qroot auth-root run-qroot auth-manifest-pending auth-manifest
            auth-self-pending auth-self quarantine-intake quarantine-package
            quarantine-bootstrap lock receipt-final
        }
        set complete_entry_rejects 0
        foreach foreign {
            home auth run home-type auth-type run-type
        } {
            set ::r2_present [dict create]
            foreach name $names { dict set ::r2_present $name 0 }
            foreach name $complete_names { dict set ::r2_present $name 1 }
            set ::r2_foreign $foreign
            set caught [catch {
                r2_authority_state $values $manifest_sha $predecessor_values \
                    fixture-password
            } message options]
            if {!$caught || ![dict exists $options -errorcode] ||
                [dict get $options -errorcode] ne {B82FAIL 78}} {
                harness_die "r2-complete-entry-drift kind=$foreign message=$message options=$options"
            }
            incr complete_entry_rejects
        }
        set prefix_accepts 0
        set prefix_rejects 0
        foreach {name local_name full_sha} [list \
            package-manifest.v1 package-manifest.v1 $manifest_sha \
            prepare-stage-root.sh prepare-stage-root.sh $::r2_self_sha] {
            set local_file "[dict get $values local_package_dir]/${local_name}"
            file lstat $local_file local_stat
            foreach {expected_class pending_size pending_sha} [list \
                empty 0 \
                    e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 \
                prefix 17 [r2_test_file_prefix_sha $local_file 17] \
                exact $local_stat(size) $full_sha] {
                set ::r2_pending_size $pending_size
                set ::r2_pending_sha $pending_sha
                set observed_class [r2_require_auth_pending_prefix $values \
                    $manifest_sha $predecessor_values $name fixture-password]
                if {$observed_class ne $expected_class} {
                    harness_die "r2-pending-prefix name=$name expected=$expected_class actual=$observed_class"
                }
                incr prefix_accepts
            }
            foreach {label pending_size pending_sha} [list \
                nonprefix 17 [string repeat a 64] \
                oversize [expr {$local_stat(size) + 1}] [string repeat b 64]] {
                set ::r2_pending_size $pending_size
                set ::r2_pending_sha $pending_sha
                set caught [catch {
                    r2_require_auth_pending_prefix $values $manifest_sha \
                        $predecessor_values $name fixture-password
                } message options]
                if {!$caught || ![dict exists $options -errorcode] ||
                    [dict get $options -errorcode] ne {B82FAIL 78}} {
                    harness_die "r2-pending-reject name=$name label=$label message=$message options=$options"
                }
                incr prefix_rejects
            }
        }
        if {$legal_count != 8 || $invalid_count != 5 ||
            $complete_entry_rejects != 6 ||
            $prefix_accepts != 6 || $prefix_rejects != 4} {
            harness_die "r2-authority-summary legal=$legal_count invalid=$invalid_count entry_rejects=$complete_entry_rejects accepts=$prefix_accepts rejects=$prefix_rejects"
        }
        puts "HARNESS_R2_AUTHORITY_PREFIXES legal=8 both_pending=manifest-pending invalid=5 foreign=STOP complete_unknown_type_rejects=6 pending_accepts=6 pending_rejects=4 result=PASS"
    }
    r2-raw-sequence {
        if {[llength $arguments] != 3} {
            harness_die "r2-raw-sequence-arguments"
        }
        lassign $arguments manifest manifest_sha predecessor_package
        set ::R2_PREDECESSOR_LOCAL_PACKAGE $predecessor_package
        if {[catch {load_manifest $manifest $manifest_sha} values] ||
            [catch {validate_manifest_values $values}] ||
            [catch {r2_load_predecessor_manifest \
                "${predecessor_package}/package-manifest.v1"} predecessor_values]} {
            harness_die "r2-raw-sequence-local-authority"
        }
        set names {
            home-qroot auth-root run-qroot auth-manifest-pending auth-manifest
            auth-self-pending auth-self quarantine-intake quarantine-package
            quarantine-bootstrap lock receipt-pending receipt-final
        }
        set ::r2_present [dict create]
        foreach name $names { dict set ::r2_present $name 0 }
        set ::r2_foreign none
        set ::r2_manifest_sha $manifest_sha
        set ::r2_self_sha [dict get $values prepare_stage_root_sh_sha256]
        set ::r2_local_package [dict get $values local_package_dir]
        file lstat $manifest manifest_stat
        file lstat "${::r2_local_package}/prepare-stage-root.sh" self_stat
        set ::r2_manifest_size $manifest_stat(size)
        set ::r2_self_size $self_stat(size)
        set ::r2_intake_manifest absent
        set ::r2_intake_self absent
        set ::r2_raw_observed {}
        set ::r2_all_observed {}
        rename exit harness_real_exit
        proc exit {{code 0}} {
            return -code error -errorcode \
                [list R2_TRANSACTION_EXIT $code] "exit-$code"
        }
        rename execute_operation_spec transport_original_execute_operation_spec
        proc execute_operation_spec {operation operation_spec password} {
            lappend ::r2_all_observed $operation
            if {[lsearch -exact [r2_test_raw_sequence] $operation] >= 0} {
                r2_test_validate_raw_spec $operation $operation_spec
                lappend ::r2_raw_observed $operation
                switch -- $operation {
                    r2-raw-intake-mkdir {}
                    r2-raw-scp-manifest { set ::r2_intake_manifest exact }
                    r2-raw-scp-self { set ::r2_intake_self exact }
                    r2-raw-home-qroot-create {
                        dict set ::r2_present home-qroot 1
                    }
                    r2-raw-auth-root-create {
                        dict set ::r2_present auth-root 1
                    }
                    r2-raw-run-qroot-create {
                        dict set ::r2_present run-qroot 1
                    }
                    r2-raw-auth-manifest-install {
                        dict set ::r2_present auth-manifest-pending 1
                    }
                    r2-raw-auth-self-install {
                        dict set ::r2_present auth-self-pending 1
                    }
                    r2-raw-link-auth-manifest {
                        dict set ::r2_present auth-manifest 1
                    }
                    r2-raw-link-auth-self {
                        dict set ::r2_present auth-self 1
                    }
                    r2-raw-helper-mutate {
                        foreach name {
                            quarantine-intake quarantine-package
                            quarantine-bootstrap lock receipt-final
                        } {
                            dict set ::r2_present $name 1
                        }
                    }
                }
                set payload [expr {$operation eq "r2-raw-helper-mutate" ?
                    "B82_V6_RETIREMENT_COMPLETE state=T disposition=advanced namespace_writes=6 same_boot=1" : ""}]
                set assertion [lindex $operation_spec 3]
                if {[catch {assert_output $assertion $payload} assertion_message]} {
                    harness_die "r2-raw-output operation=$operation reason=$assertion_message"
                }
                return [list ok 0 $payload none]
            }
            lassign [r2_test_full_remote_payload $operation] \
                disposition payload policy
            if {$disposition eq "absent"} {
                return [list child-failure 1 "" none]
            }
            set assertion [lindex $operation_spec 3]
            if {$operation ne "r2-ro-old-provision-check" &&
                [catch {assert_output $assertion $payload} assertion_message]} {
                harness_die "r2-raw-readonly-output operation=$operation assertion=$assertion payload=$payload reason=$assertion_message"
            }
            return [list ok 0 $payload $policy]
        }
        set caught [catch {
            execute_r2_transaction $values $manifest_sha $predecessor_values \
                fixture-password
        } state options]
        set expected [r2_test_raw_sequence]
        if {$caught || $state ne "TERMINAL" ||
            [lrange $::r2_raw_observed 0 end] ne [lrange $expected 0 end] ||
            [llength $::r2_raw_observed] != 21 ||
            [dict get $::r2_present receipt-pending] ||
            ![dict get $::r2_present receipt-final]} {
            harness_die "r2-raw-sequence state=$state raw=$::r2_raw_observed options=$options"
        }
        puts "HARNESS_R2_RAW_SEQUENCE leaves=21 order=exact helper=last terminal=PASS result=PASS"
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
  test_matrix_static.py checksum-module-lease.sh
  test-hermetic-checksum-module-lease.sh test_checksum_module_lease_static.py
  wg_mix_faketcp_checksum.c root-fresh-verifier-gate.sh
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
[[ "${RAW_DIRECT_COUNT}" -eq 31 ]] || fail 'raw mutation direct-call cardinality'

RETIRED_OPERATION_REJECTIONS=0
for operation in "${RETIRED_PUBLIC_AND_PRIVATE_OPERATIONS[@]}"; do
  plan_rc=66
  plan_reason=policy
  execute_reason=action-operation
  if [[ "${operation}" == lineage-home-stat ]]; then
    plan_rc=65
    plan_reason=private-operation
    execute_reason=private-operation
  fi
  private_output="$(/usr/bin/expect "${FIXTURE_REVIEW}/locked-transport.exp" \
    --manifest "${BOUND_MANIFEST}" --manifest-sha256 "${BOUND_MANIFEST_SHA}" \
    --credential-path "${CREDENTIAL_PATH}" --action plan --operation "${operation}" \
    --approved-plan-sha256 none 2>&1)"
  private_rc=$?
  [[ "${private_rc}" -eq "${plan_rc}" &&
    "${private_output}" == *"reason=${plan_reason} rc=${plan_rc}"* ]] ||
    fail "retired/private plan operation became reachable: ${operation}: ${private_output}"
  private_output="$(/usr/bin/expect "${FIXTURE_REVIEW}/locked-transport.exp" \
    --manifest /private/tmp/nonexistent-b82-retirement-private-manifest \
    --manifest-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    --credential-path "${CREDENTIAL_PATH}" --action execute --operation "${operation}" \
    --approved-plan-sha256 none 2>&1)"
  private_rc=$?
  [[ "${private_rc}" -eq 65 &&
    "${private_output}" == *"reason=${execute_reason} rc=65"* ]] ||
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
[[ "${PREPARE_SEQUENCE_OUTPUT}" == *'HARNESS_PREPARE_SEQUENCE steps=111 state=AWAIT_APPLY result=PASS'* ]] ||
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
[[ "${LINEAGE_GATE_OUTPUT}" == *'HARNESS_LINEAGE_GATE fresh=PASS terminal=PASS primitives=84 retained_files=19 retained_ops=41 lock_inode_stable=1 partial_states=6 receipt_pending=STOP recheck_drifts=4 deep_missing=35 deep_nonzero=76 retained_malformed=41 retained_signals=41 legacy_helper_calls=0 credential_reads=1 mutation_spawns=0 result=PASS'* ]] ||
  fail "retained retirement lineage gate marker: ${LINEAGE_GATE_OUTPUT}"
LINEAGE_OUTPUT_PTY="$(/usr/bin/expect "${TRANSPORT_HARNESS}" \
  "${FIXTURE_REVIEW}/locked-transport.exp" lineage-output-pty 2>&1)" ||
  fail 'retained retirement lineage output PTY regression'
[[ "${LINEAGE_OUTPUT_PTY}" == *'HARNESS_LINEAGE_OUTPUT_PTY cases=7 boot=PASS lock=PASS invalid_stops=3 child_nonzero=23 signal=STOP raw_suffix=0d0d0a credential_reads=0 network_operations=0 mutation_spawns=0 result=PASS'* &&
  "${LINEAGE_OUTPUT_PTY}" == *'HARNESS_LINE_ENDING_ASSERTIONS boot_positive=3 boot_stops=6 lock_positive=3 lock_stops=6 pty_children=7 raw_suffix=0d0d0a credential_reads=0 network_operations=0 mutation_spawns=0 result=PASS'* ]] ||
  fail "retained retirement lineage output PTY marker: ${LINEAGE_OUTPUT_PTY}"
R1_SOURCE_REUSE_OUTPUT="$(/usr/bin/expect "${TRANSPORT_HARNESS}" \
  "${FIXTURE_REVIEW}/locked-transport.exp" r1-source-reuse \
  "${BOUND_MANIFEST}" "${BOUND_MANIFEST_SHA}" \
  "${R2_PREDECESSOR_CLONE}" 2>&1)" ||
  fail 'R1 terminal and successor source-path reuse regression'
[[ "${R1_SOURCE_REUSE_OUTPUT}" == \
  *'HARNESS_R1_SOURCE_REUSE r1_gate=84 qpackage=present qbootstrap=present source_package=present source_bootstrap=present retained_file_checks=38 lock_inode_stable=1 predecessor_deep=48 legacy_helper_calls=0 result=PASS'* ]] ||
  fail "R1 terminal and successor source-path reuse marker: ${R1_SOURCE_REUSE_OUTPUT}"
PREPARE_LINEAGE_OUTPUT="$(/usr/bin/expect "${TRANSPORT_HARNESS}" \
  "${FIXTURE_REVIEW}/locked-transport.exp" prepare-lineage)" ||
  fail 'prepare lineage placement and first mutation'
[[ "${PREPARE_LINEAGE_OUTPUT}" == *'HARNESS_PREPARE_LINEAGE readonly_prefix=39 first_mutation=package-mkdir mkdir_rc=73 scp=0 credential_reads=1 result=PASS'* ]] ||
  fail "prepare lineage placement marker: ${PREPARE_LINEAGE_OUTPUT}"
R2_PREWRITE_CUTS_OUTPUT="$(/usr/bin/expect "${TRANSPORT_HARNESS}" \
  "${FIXTURE_REVIEW}/locked-transport.exp" r2-prewrite-cuts \
  "${BOUND_MANIFEST}" "${BOUND_MANIFEST_SHA}" "${R2_PREDECESSOR_CLONE}" 2>&1)" ||
  fail 'R2 actual transaction prewrite cut matrix'
[[ "${R2_PREWRITE_CUTS_OUTPUT}" == \
  *'HARNESS_R2_PREWRITE_CUTS primitives=178 cuts=356 mutations=0 child_nonzero=178 child_signal=178 r1_gate=84 authority=13 common=33 predecessor=48 result=PASS'* ]] ||
  fail "R2 actual transaction prewrite marker: ${R2_PREWRITE_CUTS_OUTPUT}"
R2_FIRST_WRITE_OUTPUT="$(/usr/bin/expect "${TRANSPORT_HARNESS}" \
  "${FIXTURE_REVIEW}/locked-transport.exp" r2-first-write \
  "${BOUND_MANIFEST}" "${BOUND_MANIFEST_SHA}" "${R2_PREDECESSOR_CLONE}" 2>&1)" ||
  fail 'R2 first mutation failure harness'
[[ "${R2_FIRST_WRITE_OUTPUT}" == \
  *'HARNESS_R2_FIRST_WRITE index=178 ordinal=179 operation=r2-raw-intake-mkdir rc=73 scp=0 result=PASS'* ]] ||
  fail "R2 first mutation marker: ${R2_FIRST_WRITE_OUTPUT}"
R2_PROVISION_CUTS_OUTPUT="$(/usr/bin/expect "${TRANSPORT_HARNESS}" \
  "${FIXTURE_REVIEW}/locked-transport.exp" r2-provision-cuts \
  "${BOUND_MANIFEST}" "${BOUND_MANIFEST_SHA}" "${R2_PREDECESSOR_CLONE}" 2>&1)" ||
  fail 'R2 stage and predecessor provision cut matrix'
[[ "${R2_PROVISION_CUTS_OUTPUT}" == \
  *'HARNESS_R2_PROVISION_CUTS stage_present_symlink=2 provision_initial_iperf3_malformed_writes1_nonzero_signal=6 prewrite_mutations=0 scp=0 result=PASS'* ]] ||
  fail "R2 stage and provision cut marker: ${R2_PROVISION_CUTS_OUTPUT}"
R2_PRIVATE_SURFACE_OUTPUT="$(/usr/bin/expect "${TRANSPORT_HARNESS}" \
  "${FIXTURE_REVIEW}/locked-transport.exp" r2-private-surface)" ||
  fail 'R2 private transport surface harness'
[[ "${R2_PRIVATE_SURFACE_OUTPUT}" == \
  *'HERMETIC_R2_PRIVATE_SURFACE public=2 ro=96 raw=21 plan_execute_rejections=234 credential_reads=0 spawns=0 result=PASS'* ]] ||
  fail "R2 private transport marker: ${R2_PRIVATE_SURFACE_OUTPUT}"
R2_PRECREDENTIAL_OUTPUT="$(/usr/bin/expect "${TRANSPORT_HARNESS}" \
  "${FIXTURE_REVIEW}/locked-transport.exp" r2-precredential \
  "${BOUND_MANIFEST}" "${BOUND_MANIFEST_SHA}" \
  "${R2_PREDECESSOR_FIXED_PACKAGE}")" ||
  fail 'R2 actual local-authority precredential order'
[[ "${R2_PRECREDENTIAL_OUTPUT}" == \
  *'HERMETIC_R2_PRECREDENTIAL current=v5/112/20 predecessor=v4/103/17 order=current,predecessor,credential controller_seam=before-credential credential_reads=1 remote_spawns=0 result=PASS'* ]] ||
  fail "R2 precredential marker: ${R2_PRECREDENTIAL_OUTPUT}"
R2_AUTHORITY_PREFIXES_OUTPUT="$(/usr/bin/expect "${TRANSPORT_HARNESS}" \
  "${FIXTURE_REVIEW}/locked-transport.exp" r2-authority-prefixes \
  "${BOUND_MANIFEST}" "${BOUND_MANIFEST_SHA}" "${R2_PREDECESSOR_CLONE}")" ||
  fail 'R2 authority prefix classifier harness'
[[ "${R2_AUTHORITY_PREFIXES_OUTPUT}" == \
  *'HARNESS_R2_AUTHORITY_PREFIXES legal=8 both_pending=manifest-pending invalid=5 foreign=STOP complete_unknown_type_rejects=6 pending_accepts=6 pending_rejects=4 result=PASS'* ]] ||
  fail "R2 authority prefix marker: ${R2_AUTHORITY_PREFIXES_OUTPUT}"
R2_RAW_SEQUENCE_OUTPUT="$(/usr/bin/expect "${TRANSPORT_HARNESS}" \
  "${FIXTURE_REVIEW}/locked-transport.exp" r2-raw-sequence \
  "${BOUND_MANIFEST}" "${BOUND_MANIFEST_SHA}" "${R2_PREDECESSOR_CLONE}" 2>&1)" ||
  fail 'R2 actual full mutation orchestration harness'
[[ "${R2_RAW_SEQUENCE_OUTPUT}" == \
  *'HARNESS_R2_RAW_SEQUENCE leaves=21 order=exact helper=last terminal=PASS result=PASS'* ]] ||
  fail "R2 raw sequence marker: ${R2_RAW_SEQUENCE_OUTPUT}"

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
printf 'HERMETIC_TRANSPORT_TRANSACTION raw_direct=31 prepare_steps=111 prewrite_cuts=36 mutation_trace=0 mkdir_failure_scp=0 child_nonzero=stop child_signal=stop generic_scp_bounds=pass\n'

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
[[ "$(/usr/bin/wc -l <"${BOUND_MANIFEST}" | /usr/bin/tr -d ' ')" == 112 ]] ||
  fail 'package-v5 manifest does not contain exactly 112 records'
FIXTURE_C_SOURCE_RELATIVE='kernel/faketcp_checksum/wg_mix_faketcp_checksum.c'
FIXTURE_C_SOURCE_BLOB="$(/usr/bin/git -C "${FIXTURE_REPOSITORY}" rev-parse \
  "${FIXTURE_COMMIT}:${FIXTURE_C_SOURCE_RELATIVE}")" ||
  fail 'checksum C source blob lookup'
FIXTURE_C_TREE_ENTRY="$(/usr/bin/git -C "${FIXTURE_REPOSITORY}" ls-tree \
  "${FIXTURE_COMMIT}" -- "${FIXTURE_C_SOURCE_RELATIVE}")" ||
  fail 'checksum C source tree mode lookup'
[[ "$(manifest_value wg_mix_faketcp_checksum_c_path "${BOUND_MANIFEST}")" == \
    "${FIXTURE_C_SOURCE_RELATIVE}" &&
  "$(manifest_value wg_mix_faketcp_checksum_c_blob "${BOUND_MANIFEST}")" == \
    "${FIXTURE_C_SOURCE_BLOB}" &&
  "$(manifest_value wg_mix_faketcp_checksum_c_sha256 "${BOUND_MANIFEST}")" == \
    "$(sha256_file "${FIXTURE_REPOSITORY}/${FIXTURE_C_SOURCE_RELATIVE}")" &&
  "$(sha256_file "${BOUND_OUTPUT}/wg_mix_faketcp_checksum.c")" == \
    "$(manifest_value wg_mix_faketcp_checksum_c_sha256 "${BOUND_MANIFEST}")" &&
  "${FIXTURE_C_TREE_ENTRY}" == \
    "100644 blob ${FIXTURE_C_SOURCE_BLOB}"$'\t'"${FIXTURE_C_SOURCE_RELATIVE}" ]] ||
  fail 'checksum C source path/blob/SHA/tree-mode binding'
/usr/bin/python3 -B -I -c '
import os
import stat
import sys

value = os.lstat(sys.argv[1])
if (
    not stat.S_ISREG(value.st_mode)
    or stat.S_ISLNK(value.st_mode)
    or stat.S_IMODE(value.st_mode) != 0o600
    or value.st_nlink != 1
):
    raise SystemExit(65)
' "${BOUND_OUTPUT}/wg_mix_faketcp_checksum.c" ||
  fail 'checksum C flat artifact mode/nlink binding'
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
[[ "$(manifest_value format "${BOUND_MANIFEST}")" == 'wg-mix-ebpf-b82-v6-package-v5' &&
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

R2_CONTROLLER_COPY_BUILDER="${TEST_ROOT}/r2-controller-copy-builder.py"
/bin/cat >"${R2_CONTROLLER_COPY_BUILDER}" <<'R2_CONTROLLER_COPY_BUILDER'
import json
import pathlib
import sys

source_path = pathlib.Path(sys.argv[1])
physical_package = pathlib.Path(sys.argv[2])
output_path = pathlib.Path(sys.argv[3])
scenario = sys.argv[4]
source = source_path.read_text(encoding="utf-8")
dispatch_tail = 'main "$@"\n'
if not source.endswith(dispatch_tail):
    raise SystemExit("controller-copy-dispatch-tail")
source = source[:-len(dispatch_tail)]

canonical_package = "/private/tmp/wg-mix-b82-v6-c8e41d73-4f2a9b61-f75fe7678cfd"
canonical_assignment = (
    "readonly R2_PREDECESSOR_PACKAGE='" + canonical_package + "'\n"
)
canonical_manifest_record = (
    "local_package_dir\t" + canonical_package + "\n"
)
if (source.count(canonical_assignment) != 1 or
        source.count(canonical_package) != 3 or
        source.count(canonical_manifest_record) != 1):
    raise SystemExit("controller-copy-canonical-cardinality")

tuple_anchor = ") = sys.argv[1:]\nexpected_manifest = sys.stdin.buffer.read()\n"
if source.count(tuple_anchor) != 1:
    raise SystemExit("controller-copy-python-anchor")
physical_literal = json.dumps(str(physical_package))
mapping = """
) = sys.argv[1:]
_r2_test_physical_package = __PHYSICAL_PACKAGE__
_r2_test_canonical_package = package_name
_r2_test_open = os.open
_r2_test_stat = os.stat
_r2_test_realpath = os.path.realpath


def _r2_test_map_path(path):
    try:
        value = os.fspath(path)
    except TypeError:
        return path
    if value == _r2_test_canonical_package:
        return os.fspath(_r2_test_physical_package)
    return path


def _r2_test_mapped_open(path, flags, mode=0o777, *, dir_fd=None):
    if dir_fd is None:
        path = _r2_test_map_path(path)
        return _r2_test_open(path, flags, mode)
    return _r2_test_open(path, flags, mode, dir_fd=dir_fd)


def _r2_test_mapped_stat(path, *, dir_fd=None, follow_symlinks=True):
    if dir_fd is None:
        path = _r2_test_map_path(path)
        return _r2_test_stat(path, follow_symlinks=follow_symlinks)
    return _r2_test_stat(
        path, dir_fd=dir_fd, follow_symlinks=follow_symlinks
    )


def _r2_test_mapped_realpath(path, *args, **kwargs):
    try:
        value = os.fspath(path)
    except TypeError:
        return _r2_test_realpath(path, *args, **kwargs)
    if value != _r2_test_canonical_package:
        return _r2_test_realpath(path, *args, **kwargs)
    physical = os.fspath(_r2_test_physical_package)
    resolved = _r2_test_realpath(physical, *args, **kwargs)
    if resolved == physical:
        return _r2_test_canonical_package
    return resolved


os.open = _r2_test_mapped_open
os.stat = _r2_test_mapped_stat
os.path.realpath = _r2_test_mapped_realpath
expected_manifest = sys.stdin.buffer.read()
""".replace("__PHYSICAL_PACKAGE__", physical_literal)
source = source.replace(tuple_anchor, mapping, 1)

git_anchor = '    if run_git(("rev-parse", f"{integration_commit}^{{commit}}")) != (\n'
if scenario == "baseline":
    if source.count(git_anchor) != 1:
        raise SystemExit("controller-copy-git-anchor")
elif scenario == "package-swap":
    if source.count(git_anchor) != 1:
        raise SystemExit("controller-copy-git-anchor")
    swap = """    os.rename(
        os.fspath(_r2_test_physical_package),
        os.fspath(_r2_test_physical_package) + ".held",
    )
    os.mkdir(os.fspath(_r2_test_physical_package), 0o700)
"""
    source = source.replace(git_anchor, swap + git_anchor, 1)
elif scenario == "git-child-failure":
    if source.count(git_anchor) != 1:
        raise SystemExit("controller-copy-git-anchor")
    source = source.replace(
        git_anchor,
        '    git_prefix[0] = "/usr/bin/false"\n' + git_anchor,
        1,
    )
elif scenario == "bundle-child-failure":
    bundle_anchor = (
        '    run_git(("bundle", "verify", bundle_argument), failure_rc=67)\n'
    )
    if source.count(bundle_anchor) != 1:
        raise SystemExit("controller-copy-bundle-anchor")
    source = source.replace(
        bundle_anchor,
        '    git_prefix[0] = "/usr/bin/false"\n' + bundle_anchor,
        1,
    )
else:
    raise SystemExit("controller-copy-scenario")

if (source.count(canonical_assignment) != 1 or
        source.count(canonical_package) != 3 or
        source.count(canonical_manifest_record) != 1 or
        source.count("_r2_test_physical_package = ") != 1):
    raise SystemExit("controller-copy-postcondition")
output_path.write_text(source, encoding="utf-8")
print(
    "R2_CONTROLLER_COPY replacements=0 physical_open_injections=1 "
    "canonical_manifest_replacements=0 logical_fixed_occurrences=3"
)
R2_CONTROLLER_COPY_BUILDER
/bin/chmod 0600 "${R2_CONTROLLER_COPY_BUILDER}" ||
  fail 'R2 controller copy builder mode'

R2_CONTROLLER_LOCAL_RUNNER="${TEST_ROOT}/r2-controller-local-runner.sh"
/bin/cat >"${R2_CONTROLLER_LOCAL_RUNNER}" <<'R2_CONTROLLER_LOCAL_RUNNER'
#!/usr/bin/env bash
set -u
set -o pipefail
reader="$1"
current_manifest="$2"
current_manifest_sha="$3"
current_commit="$4"
credential_path="$5"
source "${reader}" || exit $?
parse_arguments() {
  [[ "$1" == verify-r2-predecessor-package ]] || return 64
  MODE="$1"
  MANIFEST="${current_manifest}"
  MANIFEST_SHA256="${current_manifest_sha}"
  INTEGRATION_COMMIT="${current_commit}"
  SUPPLIED_CREDENTIAL_PATH="${credential_path}"
  APPROVED_PLAN_SHA256=none
}
verify_manifest_contract() { return 0; }
derive_approved_plan_path() { APPROVED_PLAN=none; }
transport() { printf 'R2_CONTROLLER_NETWORK_TRIPWIRE\n' >&2; return 99; }
run_operation() { printf 'R2_CONTROLLER_OPERATION_TRIPWIRE\n' >&2; return 99; }
main verify-r2-predecessor-package
R2_CONTROLLER_LOCAL_RUNNER
/bin/chmod 0700 "${R2_CONTROLLER_LOCAL_RUNNER}" ||
  fail 'R2 controller local runner mode'

make_r2_controller_reader() {
  local physical_package="$1" scenario="$2" target="$3" marker
  marker="$(/usr/bin/python3 -B -I "${R2_CONTROLLER_COPY_BUILDER}" \
    "${FIXTURE_REVIEW}/controller.sh" "${physical_package}" "${target}" \
    "${scenario}")" || return $?
  [[ "${marker}" == \
    'R2_CONTROLLER_COPY replacements=0 physical_open_injections=1 canonical_manifest_replacements=0 logical_fixed_occurrences=3' ]] || return 70
  /bin/chmod 0600 "${target}" || return $?
  /bin/bash -n "${target}" || return $?
}

run_r2_controller_reader() {
  /usr/bin/python3 -B -I -c '
import os
import signal
import subprocess
import sys

process = subprocess.Popen(
    sys.argv[1:],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
    start_new_session=True,
)
try:
    output, _ = process.communicate(timeout=4)
except subprocess.TimeoutExpired:
    os.killpg(process.pid, signal.SIGTERM)
    output, _ = process.communicate(timeout=2)
    sys.stdout.write(output)
    raise SystemExit(124)
sys.stdout.write(output)
raise SystemExit(process.returncode)
' /bin/bash "${R2_CONTROLLER_LOCAL_RUNNER}" "$1" "${BOUND_MANIFEST}" \
    "${BOUND_MANIFEST_SHA}" "${FIXTURE_COMMIT}" "$2"
}

R2_CONTROLLER_CREDENTIAL_FIFO="${TEST_ROOT}/r2-controller-credential.fifo"
/usr/bin/mkfifo -m 0600 -- "${R2_CONTROLLER_CREDENTIAL_FIFO}" ||
  fail 'R2 controller credential FIFO'
R2_CONTROLLER_CLONE_READER="${TEST_ROOT}/controller.r2-clone-reader.sh"
make_r2_controller_reader "${R2_PREDECESSOR_CLONE}" baseline \
  "${R2_CONTROLLER_CLONE_READER}" || fail 'R2 clone controller reader'
R2_CONTROLLER_CLONE_OUTPUT="$(run_r2_controller_reader \
  "${R2_CONTROLLER_CLONE_READER}" "${R2_CONTROLLER_CREDENTIAL_FIFO}")" ||
  fail 'R2 clone controller local-only positive'
if [[ "$(/usr/bin/uname -s)" == Darwin ]]; then
  R2_CONTROLLER_CLONE_DEVICE_INODE="$(/usr/bin/stat -f '%d:%i' -- \
    "${R2_PREDECESSOR_CLONE}")" || fail 'R2 clone device inode'
else
  R2_CONTROLLER_CLONE_DEVICE_INODE="$(/usr/bin/stat -Lc '%d:%i' -- \
    "${R2_PREDECESSOR_CLONE}")" || fail 'R2 clone device inode'
fi
R2_CONTROLLER_CLONE_MARKER="B82_V6_CONTROLLER_R2_PREDECESSOR_VERIFIED predecessor_manifest_sha256=${R2_PREDECESSOR_MANIFEST_SHA256} predecessor_commit=${R2_PREDECESSOR_COMMIT} package_device_inode=${R2_CONTROLLER_CLONE_DEVICE_INODE} credential_read=0 network_operations=0"
[[ "${R2_CONTROLLER_CLONE_OUTPUT##*$'\n'}" == \
    "${R2_CONTROLLER_CLONE_MARKER}" &&
  "$(printf '%s\n' "${R2_CONTROLLER_CLONE_OUTPUT}" | \
    /usr/bin/grep -Fxc -- "${R2_CONTROLLER_CLONE_MARKER}")" == 1 &&
  "${R2_CONTROLLER_CLONE_OUTPUT}" != *R2_CONTROLLER_NETWORK_TRIPWIRE* &&
  "${R2_CONTROLLER_CLONE_OUTPUT}" != *R2_CONTROLLER_OPERATION_TRIPWIRE* ]] ||
  fail "R2 clone controller local-only marker: ${R2_CONTROLLER_CLONE_OUTPUT}"

R2_CONTROLLER_MISSING_CREDENTIAL="${TEST_ROOT}/r2-controller-credential.missing"
[[ ! -e "${R2_CONTROLLER_MISSING_CREDENTIAL}" &&
  ! -L "${R2_CONTROLLER_MISSING_CREDENTIAL}" ]] ||
  fail 'R2 controller missing credential fixture'
R2_CONTROLLER_MISSING_CREDENTIAL_OUTPUT="$(run_r2_controller_reader \
  "${R2_CONTROLLER_CLONE_READER}" \
  "${R2_CONTROLLER_MISSING_CREDENTIAL}")" ||
  fail 'R2 clone controller missing-credential positive'
[[ "${R2_CONTROLLER_MISSING_CREDENTIAL_OUTPUT##*$'\n'}" == \
    "${R2_CONTROLLER_CLONE_MARKER}" &&
  "$(printf '%s\n' "${R2_CONTROLLER_MISSING_CREDENTIAL_OUTPUT}" | \
    /usr/bin/grep -Fxc -- "${R2_CONTROLLER_CLONE_MARKER}")" == 1 &&
  "${R2_CONTROLLER_MISSING_CREDENTIAL_OUTPUT}" != \
    *R2_CONTROLLER_NETWORK_TRIPWIRE* &&
  "${R2_CONTROLLER_MISSING_CREDENTIAL_OUTPUT}" != \
    *R2_CONTROLLER_OPERATION_TRIPWIRE* ]] ||
  fail "R2 missing-credential local-only marker: ${R2_CONTROLLER_MISSING_CREDENTIAL_OUTPUT}"

R2_CONTROLLER_PACKAGE_FIFO="${TEST_ROOT}/r2-controller-package.fifo"
/usr/bin/mkfifo -m 0600 -- "${R2_CONTROLLER_PACKAGE_FIFO}" ||
  fail 'R2 controller package FIFO'
R2_CONTROLLER_FIFO_READER="${TEST_ROOT}/controller.r2-fifo-reader.sh"
make_r2_controller_reader "${R2_CONTROLLER_PACKAGE_FIFO}" baseline \
  "${R2_CONTROLLER_FIFO_READER}" || fail 'R2 FIFO controller reader'
R2_CONTROLLER_FIFO_OUTPUT="$(run_r2_controller_reader \
  "${R2_CONTROLLER_FIFO_READER}" "${R2_CONTROLLER_CREDENTIAL_FIFO}" 2>&1)"
R2_CONTROLLER_FIFO_RC=$?
[[ "${R2_CONTROLLER_FIFO_RC}" -eq 66 &&
  "${R2_CONTROLLER_FIFO_OUTPUT}" == *'reason=r2-local-authority rc=66'* &&
  "${R2_CONTROLLER_FIFO_OUTPUT}" != *R2_CONTROLLER_NETWORK_TRIPWIRE* &&
  "${R2_CONTROLLER_FIFO_OUTPUT}" != *R2_CONTROLLER_OPERATION_TRIPWIRE* ]] ||
  fail "R2 FIFO controller verifier did not fail closed: rc=${R2_CONTROLLER_FIFO_RC} output=${R2_CONTROLLER_FIFO_OUTPUT}"

R2_CONTROLLER_SWAP_PACKAGE="${TEST_ROOT}/f75-predecessor-package-swap"
/bin/cp -R -- "${R2_PREDECESSOR_FIXED_PACKAGE}" \
  "${R2_CONTROLLER_SWAP_PACKAGE}" || fail 'R2 path-swap package clone'
R2_CONTROLLER_SWAP_READER="${TEST_ROOT}/controller.r2-swap-reader.sh"
make_r2_controller_reader "${R2_CONTROLLER_SWAP_PACKAGE}" package-swap \
  "${R2_CONTROLLER_SWAP_READER}" || fail 'R2 path-swap controller reader'
R2_CONTROLLER_SWAP_OUTPUT="$(run_r2_controller_reader \
  "${R2_CONTROLLER_SWAP_READER}" "${R2_CONTROLLER_CREDENTIAL_FIFO}" 2>&1)"
R2_CONTROLLER_SWAP_RC=$?
[[ "${R2_CONTROLLER_SWAP_RC}" -eq 66 &&
  "${R2_CONTROLLER_SWAP_OUTPUT}" == *'reason=r2-local-authority rc=66'* &&
  -d "${R2_CONTROLLER_SWAP_PACKAGE}" &&
  -d "${R2_CONTROLLER_SWAP_PACKAGE}.held" &&
  "${R2_CONTROLLER_SWAP_OUTPUT}" != *R2_CONTROLLER_NETWORK_TRIPWIRE* &&
  "${R2_CONTROLLER_SWAP_OUTPUT}" != *R2_CONTROLLER_OPERATION_TRIPWIRE* ]] ||
  fail "R2 scan-to-Git package swap did not fail closed: rc=${R2_CONTROLLER_SWAP_RC} output=${R2_CONTROLLER_SWAP_OUTPUT}"

readonly -a R2_CONTROLLER_PREDECESSOR_FILES=(
  source-4f2a9b61.bundle package-manifest.v1 bind-final-package.sh
  controller.sh prepare-stage-root.sh provision-ubuntu-test-host.sh
  root-matrix-n-r.sh check-realhost-iperf.py test-hermetic-matrix.sh
  test_matrix_static.py checksum-module-lease.sh
  root-fresh-verifier-gate.sh test-hermetic-fresh-verifier-gate.sh
  test_fresh_verifier_gate_static.py realnic_acceptance.py
  test_realnic_acceptance.py test_realnic_acceptance_static.py
)
[[ "${#R2_CONTROLLER_PREDECESSOR_FILES[@]}" -eq 17 ]] ||
  fail 'R2 controller predecessor file oracle cardinality'
R2_CONTROLLER_ARTIFACT_CASE_ROOT="${TEST_ROOT}/r2-controller-artifact-cases"
/bin/mkdir -m 0700 -- "${R2_CONTROLLER_ARTIFACT_CASE_ROOT}" ||
  fail 'R2 controller artifact case root'
R2_CONTROLLER_ARTIFACT_ORDINAL=0
R2_CONTROLLER_ARTIFACT_CUTS=0

make_r2_controller_artifact_case() {
  local label="$1"
  ((R2_CONTROLLER_ARTIFACT_ORDINAL += 1))
  R2_CONTROLLER_CASE_PACKAGE="${R2_CONTROLLER_ARTIFACT_CASE_ROOT}/$(printf '%03d' \
    "${R2_CONTROLLER_ARTIFACT_ORDINAL}")-${label}"
  R2_CONTROLLER_CASE_READER="${R2_CONTROLLER_CASE_PACKAGE}.reader.sh"
  /bin/cp -R -- "${R2_PREDECESSOR_FIXED_PACKAGE}" \
    "${R2_CONTROLLER_CASE_PACKAGE}" || return $?
}

expect_r2_controller_artifact_rc() {
  local label="$1" expected_rc="$2" output rc
  make_r2_controller_reader "${R2_CONTROLLER_CASE_PACKAGE}" baseline \
    "${R2_CONTROLLER_CASE_READER}" ||
    fail "${label}: R2 controller artifact reader"
  output="$(run_r2_controller_reader "${R2_CONTROLLER_CASE_READER}" \
    "${R2_CONTROLLER_CREDENTIAL_FIFO}" 2>&1)"
  rc=$?
  [[ "${rc}" -eq "${expected_rc}" &&
    "${output}" == *"reason=r2-local-authority rc=${expected_rc}"* &&
    "${output}" != *R2_CONTROLLER_NETWORK_TRIPWIRE* &&
    "${output}" != *R2_CONTROLLER_OPERATION_TRIPWIRE* ]] ||
    fail "${label}: expected rc=${expected_rc}, observed rc=${rc}, output=${output}"
  ((R2_CONTROLLER_ARTIFACT_CUTS += 1))
}

for predecessor_name in "${R2_CONTROLLER_PREDECESSOR_FILES[@]}"; do
  case_label="${predecessor_name//./_}"
  case_label="${case_label//-/_}"

  make_r2_controller_artifact_case "${case_label}-content" ||
    fail "${predecessor_name}: R2 content case copy"
  /usr/bin/python3 -B -I -c '
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
payload = path.read_bytes()
if not payload:
    raise SystemExit(90)
path.write_bytes(bytes((payload[0] ^ 1,)) + payload[1:])
' "${R2_CONTROLLER_CASE_PACKAGE}/${predecessor_name}" ||
    fail "${predecessor_name}: R2 same-size content tamper"
  expect_r2_controller_artifact_rc \
    "${predecessor_name}-content" 67

  make_r2_controller_artifact_case "${case_label}-mode" ||
    fail "${predecessor_name}: R2 mode case copy"
  /bin/chmod 0644 \
    "${R2_CONTROLLER_CASE_PACKAGE}/${predecessor_name}" ||
    fail "${predecessor_name}: R2 mode tamper"
  expect_r2_controller_artifact_rc "${predecessor_name}-mode" 66

  make_r2_controller_artifact_case "${case_label}-nlink" ||
    fail "${predecessor_name}: R2 nlink case copy"
  /bin/ln "${R2_CONTROLLER_CASE_PACKAGE}/${predecessor_name}" \
    "${R2_CONTROLLER_CASE_PACKAGE}.external-hardlink" ||
    fail "${predecessor_name}: R2 nlink tamper"
  expect_r2_controller_artifact_rc "${predecessor_name}-nlink" 66

  make_r2_controller_artifact_case "${case_label}-symlink" ||
    fail "${predecessor_name}: R2 symlink case copy"
  /bin/mv -- "${R2_CONTROLLER_CASE_PACKAGE}/${predecessor_name}" \
    "${R2_CONTROLLER_CASE_PACKAGE}.symlink-target" ||
    fail "${predecessor_name}: R2 symlink target move"
  /bin/ln -s "${R2_CONTROLLER_CASE_PACKAGE}.symlink-target" \
    "${R2_CONTROLLER_CASE_PACKAGE}/${predecessor_name}" ||
    fail "${predecessor_name}: R2 symlink tamper"
  expect_r2_controller_artifact_rc "${predecessor_name}-symlink" 66
done
[[ "${R2_CONTROLLER_ARTIFACT_CUTS}" -eq 68 ]] ||
  fail 'R2 controller artifact cut cardinality'
printf 'HERMETIC_R2_CONTROLLER_FILES files=17 content_mode_nlink_symlink_cuts=68 credential_fifo=unread network_tripwire=0 result=PASS\n'

expect_r2_controller_history_rc() {
  local label="$1" expected_rc="$2" scenario="${3:-baseline}" output rc
  make_r2_controller_reader "${R2_CONTROLLER_CASE_PACKAGE}" "${scenario}" \
    "${R2_CONTROLLER_CASE_READER}" ||
    fail "${label}: R2 controller history reader"
  output="$(run_r2_controller_reader "${R2_CONTROLLER_CASE_READER}" \
    "${R2_CONTROLLER_CREDENTIAL_FIFO}" 2>&1)"
  rc=$?
  [[ "${rc}" -eq "${expected_rc}" &&
    "${output}" == *"reason=r2-local-authority rc=${expected_rc}"* &&
    "${output}" != *R2_CONTROLLER_NETWORK_TRIPWIRE* &&
    "${output}" != *R2_CONTROLLER_OPERATION_TRIPWIRE* ]] ||
    fail "${label}: expected rc=${expected_rc}, observed rc=${rc}, output=${output}"
}

R2_CONTROLLER_HISTORY_REF_CUTS=0
make_r2_controller_artifact_case history-ref-ancestor ||
  fail 'R2 predecessor ancestor-ref case copy'
R2_CONTROLLER_HISTORY_PARENT="$(/usr/bin/git -C \
  "${R2_CONTROLLER_CASE_PACKAGE}/history-verification.git" rev-parse \
  "${R2_PREDECESSOR_COMMIT}^")" || fail 'R2 predecessor parent commit'
/usr/bin/git -C "${R2_CONTROLLER_CASE_PACKAGE}/history-verification.git" \
  update-ref refs/heads/history-verified "${R2_CONTROLLER_HISTORY_PARENT}" ||
  fail 'R2 predecessor ancestor-ref mutation'
expect_r2_controller_history_rc history-ref-ancestor 76
((R2_CONTROLLER_HISTORY_REF_CUTS += 1))

R2_CONTROLLER_HISTORY_SHAPE_CUTS=0
make_r2_controller_artifact_case package-extra ||
  fail 'R2 predecessor package-extra case copy'
/usr/bin/touch "${R2_CONTROLLER_CASE_PACKAGE}/unexpected-entry" ||
  fail 'R2 predecessor package-extra mutation'
expect_r2_controller_history_rc package-extra 66
((R2_CONTROLLER_HISTORY_SHAPE_CUTS += 1))

make_r2_controller_artifact_case package-missing ||
  fail 'R2 predecessor package-missing case copy'
/bin/mv -- "${R2_CONTROLLER_CASE_PACKAGE}/controller.sh" \
  "${R2_CONTROLLER_CASE_PACKAGE}.missing-controller" ||
  fail 'R2 predecessor package-missing mutation'
expect_r2_controller_history_rc package-missing 66
((R2_CONTROLLER_HISTORY_SHAPE_CUTS += 1))

make_r2_controller_artifact_case package-mode ||
  fail 'R2 predecessor package-mode case copy'
/bin/chmod 0755 "${R2_CONTROLLER_CASE_PACKAGE}" ||
  fail 'R2 predecessor package-mode mutation'
expect_r2_controller_history_rc package-mode 66
((R2_CONTROLLER_HISTORY_SHAPE_CUTS += 1))

make_r2_controller_artifact_case package-symlink ||
  fail 'R2 predecessor package-symlink case copy'
/bin/mv -- "${R2_CONTROLLER_CASE_PACKAGE}" \
  "${R2_CONTROLLER_CASE_PACKAGE}.symlink-target" ||
  fail 'R2 predecessor package-symlink target move'
/bin/ln -s "${R2_CONTROLLER_CASE_PACKAGE}.symlink-target" \
  "${R2_CONTROLLER_CASE_PACKAGE}" ||
  fail 'R2 predecessor package-symlink mutation'
expect_r2_controller_history_rc package-symlink 66
((R2_CONTROLLER_HISTORY_SHAPE_CUTS += 1))

R2_CONTROLLER_HISTORY_FILE_CUTS=0
for history_name in history-roots.v1 history-objects.v1; do
  history_label="${history_name//./_}"
  history_label="${history_label//-/_}"

  make_r2_controller_artifact_case "${history_label}-content" ||
    fail "${history_name}: R2 history content case copy"
  /usr/bin/python3 -B -I -c '
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
payload = path.read_bytes()
if not payload:
    raise SystemExit(90)
path.write_bytes(bytes((payload[0] ^ 1,)) + payload[1:])
' "${R2_CONTROLLER_CASE_PACKAGE}/${history_name}" ||
    fail "${history_name}: R2 history same-size content tamper"
  expect_r2_controller_history_rc "${history_name}-content" 67
  ((R2_CONTROLLER_HISTORY_FILE_CUTS += 1))

  make_r2_controller_artifact_case "${history_label}-mode" ||
    fail "${history_name}: R2 history mode case copy"
  /bin/chmod 0644 "${R2_CONTROLLER_CASE_PACKAGE}/${history_name}" ||
    fail "${history_name}: R2 history mode tamper"
  expect_r2_controller_history_rc "${history_name}-mode" 66
  ((R2_CONTROLLER_HISTORY_FILE_CUTS += 1))

  make_r2_controller_artifact_case "${history_label}-nlink" ||
    fail "${history_name}: R2 history nlink case copy"
  /bin/ln "${R2_CONTROLLER_CASE_PACKAGE}/${history_name}" \
    "${R2_CONTROLLER_CASE_PACKAGE}.${history_label}.external-hardlink" ||
    fail "${history_name}: R2 history nlink tamper"
  expect_r2_controller_history_rc "${history_name}-nlink" 66
  ((R2_CONTROLLER_HISTORY_FILE_CUTS += 1))

  make_r2_controller_artifact_case "${history_label}-symlink" ||
    fail "${history_name}: R2 history symlink case copy"
  /bin/mv -- "${R2_CONTROLLER_CASE_PACKAGE}/${history_name}" \
    "${R2_CONTROLLER_CASE_PACKAGE}.${history_label}.symlink-target" ||
    fail "${history_name}: R2 history symlink target move"
  /bin/ln -s \
    "${R2_CONTROLLER_CASE_PACKAGE}.${history_label}.symlink-target" \
    "${R2_CONTROLLER_CASE_PACKAGE}/${history_name}" ||
    fail "${history_name}: R2 history symlink tamper"
  expect_r2_controller_history_rc "${history_name}-symlink" 66
  ((R2_CONTROLLER_HISTORY_FILE_CUTS += 1))
done

make_r2_controller_artifact_case history-git-mode ||
  fail 'R2 predecessor history Git mode case copy'
/bin/chmod 0755 \
  "${R2_CONTROLLER_CASE_PACKAGE}/history-verification.git" ||
  fail 'R2 predecessor history Git mode mutation'
expect_r2_controller_history_rc history-git-mode 66
((R2_CONTROLLER_HISTORY_SHAPE_CUTS += 1))

make_r2_controller_artifact_case history-git-extra ||
  fail 'R2 predecessor history Git extra case copy'
/usr/bin/touch \
  "${R2_CONTROLLER_CASE_PACKAGE}/history-verification.git/unexpected-entry" ||
  fail 'R2 predecessor history Git extra mutation'
expect_r2_controller_history_rc history-git-extra 66
((R2_CONTROLLER_HISTORY_SHAPE_CUTS += 1))

make_r2_controller_artifact_case history-git-symlink ||
  fail 'R2 predecessor history Git symlink case copy'
/bin/mv -- "${R2_CONTROLLER_CASE_PACKAGE}/history-verification.git" \
  "${R2_CONTROLLER_CASE_PACKAGE}.history-git-symlink-target" ||
  fail 'R2 predecessor history Git symlink target move'
/bin/ln -s "${R2_CONTROLLER_CASE_PACKAGE}.history-git-symlink-target" \
  "${R2_CONTROLLER_CASE_PACKAGE}/history-verification.git" ||
  fail 'R2 predecessor history Git symlink mutation'
expect_r2_controller_history_rc history-git-symlink 66
((R2_CONTROLLER_HISTORY_SHAPE_CUTS += 1))

make_r2_controller_artifact_case history-git-missing ||
  fail 'R2 predecessor history Git missing case copy'
/bin/mv -- "${R2_CONTROLLER_CASE_PACKAGE}/history-verification.git" \
  "${R2_CONTROLLER_CASE_PACKAGE}.history-git-missing" ||
  fail 'R2 predecessor history Git missing mutation'
expect_r2_controller_history_rc history-git-missing 66
((R2_CONTROLLER_HISTORY_SHAPE_CUTS += 1))

make_r2_controller_artifact_case history-git-object ||
  fail 'R2 predecessor history Git object case copy'
R2_CONTROLLER_PACK_OBJECT="${R2_CONTROLLER_CASE_PACKAGE}/history-verification.git/objects/pack/pack-0bfdc6762b7475de7be2b99a2c291d76a8cab621.pack"
[[ -f "${R2_CONTROLLER_PACK_OBJECT}" && ! -L "${R2_CONTROLLER_PACK_OBJECT}" ]] ||
  fail 'R2 predecessor frozen pack object fixture'
/bin/mv -- "${R2_CONTROLLER_PACK_OBJECT}" \
  "${R2_CONTROLLER_CASE_PACKAGE}.missing-pack-object" ||
  fail 'R2 predecessor history Git object mutation'
expect_r2_controller_history_rc history-git-object 76
((R2_CONTROLLER_HISTORY_SHAPE_CUTS += 1))

make_r2_controller_artifact_case history-git-child ||
  fail 'R2 predecessor history Git child case copy'
expect_r2_controller_history_rc history-git-child 76 git-child-failure
((R2_CONTROLLER_HISTORY_SHAPE_CUTS += 1))

make_r2_controller_artifact_case bundle-child ||
  fail 'R2 predecessor bundle child case copy'
expect_r2_controller_history_rc bundle-child 67 bundle-child-failure
((R2_CONTROLLER_HISTORY_SHAPE_CUTS += 1))

[[ "${R2_CONTROLLER_HISTORY_FILE_CUTS}" -eq 8 &&
  "${R2_CONTROLLER_HISTORY_SHAPE_CUTS}" -eq 11 ]] ||
  fail 'R2 predecessor history evidence/shape cut cardinality'

make_r2_controller_artifact_case history-ref-extra ||
  fail 'R2 predecessor extra-ref case copy'
/usr/bin/git -C "${R2_CONTROLLER_CASE_PACKAGE}/history-verification.git" \
  update-ref refs/heads/foreign "${R2_PREDECESSOR_COMMIT}" ||
  fail 'R2 predecessor extra-ref mutation'
expect_r2_controller_history_rc history-ref-extra 76
((R2_CONTROLLER_HISTORY_REF_CUTS += 1))

R2_CURRENT_HISTORY_REF_PACKAGE="${TEST_ROOT}/r2-current-history-ref-package"
/bin/cp -R -- "${BOUND_OUTPUT}" "${R2_CURRENT_HISTORY_REF_PACKAGE}" ||
  fail 'R2 current history-ref package copy'
R2_CURRENT_HISTORY_PARENT="$(/usr/bin/git -C \
  "${R2_CURRENT_HISTORY_REF_PACKAGE}/history-verification.git" rev-parse \
  "${FIXTURE_COMMIT}^")" || fail 'R2 current parent commit'
/usr/bin/git -C "${R2_CURRENT_HISTORY_REF_PACKAGE}/history-verification.git" \
  update-ref refs/heads/history-verified "${R2_CURRENT_HISTORY_PARENT}" ||
  fail 'R2 current ancestor-ref mutation'
R2_CURRENT_HISTORY_REF_OUTPUT="$(/bin/bash -c '
  source "$1" || exit $?
  MANIFEST="$2"
  MANIFEST_SHA256="$3"
  verify_manifest_contract || exit $?
  LOCAL_PACKAGE_DIR="$4"
  verify_bound_history
' r2-current-history-ref "${CONTROLLER_READER_ONLY}" \
  "${BOUND_MANIFEST}" "${BOUND_MANIFEST_SHA}" \
  "${R2_CURRENT_HISTORY_REF_PACKAGE}" 2>&1)"
R2_CURRENT_HISTORY_REF_RC=$?
[[ "${R2_CURRENT_HISTORY_REF_RC}" -eq 76 ]] ||
  fail "R2 current ancestor-ref did not fail closed: rc=${R2_CURRENT_HISTORY_REF_RC} output=${R2_CURRENT_HISTORY_REF_OUTPUT}"
((R2_CONTROLLER_HISTORY_REF_CUTS += 1))
[[ "${R2_CONTROLLER_HISTORY_REF_CUTS}" -eq 3 ]] ||
  fail 'R2 current/predecessor history-ref cut cardinality'
printf 'HERMETIC_R2_CONTROLLER_HISTORY_REFS predecessor_ancestor=STOP predecessor_extra=STOP current_ancestor=STOP cuts=3 rc=76 credential_reads=0 network_operations=0 result=PASS\n'

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
R2_CONTROLLER_MODE_SEAM="$(/bin/bash -c '
  source "$1" || exit $?
  parse_arguments() { MODE="$1"; }
  verify_manifest_contract() { return 0; }
  derive_approved_plan_path() { return 0; }
  verify_r2_local_authorities() { R2_PREDECESSOR_DEVICE_INODE=71:113; }
  run_operation() { printf "HIGH_LEVEL:%s:%s\n" "$1" "$2"; }
  main verify-r2-predecessor-package || exit $?
  main retire-postflight-f75fe7678cfd-r2 || exit $?
  main verify-postflight-retirement-r2 || exit $?
' controller-r2-mode-seam "${CONTROLLER_READER_ONLY}")" ||
  fail 'controller R2 high-level mode seam'
[[ "${R2_CONTROLLER_MODE_SEAM}" == \
  *"B82_V6_CONTROLLER_R2_PREDECESSOR_VERIFIED predecessor_manifest_sha256=${R2_PREDECESSOR_MANIFEST_SHA256} predecessor_commit=${R2_PREDECESSOR_COMMIT} package_device_inode=71:113 credential_read=0 network_operations=0"* &&
  "${R2_CONTROLLER_MODE_SEAM}" == \
    *$'HIGH_LEVEL:execute:retire-postflight-f75fe7678cfd-r2\nHIGH_LEVEL:execute:verify-postflight-retirement-r2' ]] ||
  fail "controller R2 mode mapping drifted: ${R2_CONTROLLER_MODE_SEAM}"
[[ "$(printf '%s\n' "${R2_CONTROLLER_MODE_SEAM}" | \
    /usr/bin/grep -c '^HIGH_LEVEL:execute:')" -eq 2 &&
  "$(printf '%s\n' "${R2_CONTROLLER_MODE_SEAM}" | \
    /usr/bin/grep -Fc 'B82_V6_CONTROLLER_R2_PREDECESSOR_VERIFIED ')" -eq 1 ]] ||
  fail "controller R2 mode cardinality drifted: ${R2_CONTROLLER_MODE_SEAM}"
R2_PREDECESSOR_VERIFY_OUTPUT="$(/bin/bash "${BOUND_OUTPUT}/controller.sh" \
  verify-r2-predecessor-package --manifest "${BOUND_MANIFEST}" \
  --manifest-sha256 "${BOUND_MANIFEST_SHA}" \
  --credential-path "${CREDENTIAL_PATH}" --approved-plan-sha256 none)" ||
  fail 'controller frozen predecessor local-only verification'
if [[ "$(/usr/bin/uname -s)" == Darwin ]]; then
  R2_PREDECESSOR_DEVICE_INODE="$(/usr/bin/stat -f '%d:%i' -- \
    "${R2_PREDECESSOR_FIXED_PACKAGE}")" || fail 'R2 predecessor identity'
else
  R2_PREDECESSOR_DEVICE_INODE="$(/usr/bin/stat -Lc '%d:%i' -- \
    "${R2_PREDECESSOR_FIXED_PACKAGE}")" || fail 'R2 predecessor identity'
fi
R2_PREDECESSOR_VERIFY_MARKER="B82_V6_CONTROLLER_R2_PREDECESSOR_VERIFIED predecessor_manifest_sha256=${R2_PREDECESSOR_MANIFEST_SHA256} predecessor_commit=${R2_PREDECESSOR_COMMIT} package_device_inode=${R2_PREDECESSOR_DEVICE_INODE} credential_read=0 network_operations=0"
[[ "${R2_PREDECESSOR_VERIFY_OUTPUT##*$'\n'}" == \
    "${R2_PREDECESSOR_VERIFY_MARKER}" &&
  "$(printf '%s\n' "${R2_PREDECESSOR_VERIFY_OUTPUT}" | \
    /usr/bin/grep -Fxc -- "${R2_PREDECESSOR_VERIFY_MARKER}")" == 1 ]] ||
  fail "controller predecessor marker is not exact-last: ${R2_PREDECESSOR_VERIFY_OUTPUT}"
R2_PUBLIC_PLAN_COUNT=0
for operation in retire-postflight-f75fe7678cfd-r2 \
  verify-postflight-retirement-r2; do
  r2_public_plan="$(/usr/bin/expect "${FIXTURE_REVIEW}/locked-transport.exp" \
    --manifest "${BOUND_MANIFEST}" --manifest-sha256 "${BOUND_MANIFEST_SHA}" \
    --credential-path "${CREDENTIAL_PATH}" --action plan --operation "${operation}" \
    --approved-plan-sha256 none)" || fail "R2 public plan ${operation}"
  [[ "${r2_public_plan}" == \
    *"B82_V6_TRANSPORT_PLAN operation=${operation} transport=high-level-fixed credential_read=0 network_operations=0 raw_leaves=unreachable predecessor_format=v4 predecessor_fields=103 predecessor_package_files=17"* ]] ||
    fail "R2 public plan marker ${operation}: ${r2_public_plan}"
  ((R2_PUBLIC_PLAN_COUNT += 1))
done
[[ "${R2_PUBLIC_PLAN_COUNT}" -eq 2 ]] || fail 'R2 public plan cardinality'
printf 'HERMETIC_R2_CONTROLLER_SEAMS public_modes=2 high_level_calls=2 local_only=PASS fixed_positive=1 clone_positive=2 package_fifo=1 artifact_cuts=68 history_cuts=22 path_swaps=1 replacements=0 physical_open_injections=1 canonical_manifest_replacements=0 network_tripwire=0 result=PASS\n'
R2_RECEIPT_TEST_OUTPUT="$(/usr/bin/python3 -B -I -c '
import hashlib
import sys

authority_manifest = "a" * 64
authority_helper = "b" * 64
authority_commit = "c" * 40
lines = (
    ("format", "wg-mix-ebpf-b82-postflight-retirement-terminal-v1"),
    ("retire_id", "c8e41d73-f75fe7678cfd-r2"),
    ("state", "TERMINAL"),
    ("predecessor_commit", "f75fe7678cfdecf08173fd201be5c055417d6e11"),
    ("predecessor_manifest_sha256", "2d6c6caac080b599fbfa0f73c64f6976cf30d1504fc506ebd39c638b2f9449e3"),
    ("predecessor_bundle_sha256", "b74811808e0413714dcf20b8292fe68631f603c0b9a68bc9951af481477b413b"),
    ("predecessor_package_format", "wg-mix-ebpf-b82-v6-package-v4"),
    ("predecessor_manifest_field_count", "103"),
    ("predecessor_package_entry_count", "17"),
    ("predecessor_bootstrap_entry_count", "2"),
    ("authority_manifest_sha256", authority_manifest),
    ("authority_prepare_stage_root_sha256", authority_helper),
    ("authority_integration_commit", authority_commit),
    ("authority_package_format", "wg-mix-ebpf-b82-v6-package-v5"),
    ("authority_manifest_field_count", "112"),
    ("authority_transfer_entry_count", "20"),
    ("prior_retirement_id", "c8e41d73-2c690050ae1d-r1"),
    ("prior_retirement_receipt_sha256", "4c3e9bfd3d4e64f6626abaa43e20cf5e4df6b193395cee6a39953b1c4da7d188"),
    ("failure_cut", "postflight-hermetic-matrix-before-stage-snapshot"),
    ("failure_point", "hermetic-matrix"),
    ("failure_reason", "review-input-is-not-a-regular-file"),
    ("failure_path", "/home/siyixuan/wg-mix-ebpf-test/unpriv-4f2a9b61/test-hermetic-checksum-module-lease.sh"),
    ("failure_rc", "1"),
    ("provision_check", "missing_set=none,writes=0"),
    ("bootstrap_snapshot_state", "absent"),
    ("stage_root_state", "absent"),
    ("source_intake", "/home/siyixuan/wg-mix-ebpf-test/retire-postflight-c8e41d73-f75fe7678cfd-r2.intake"),
    ("source_package", "/home/siyixuan/wg-mix-ebpf-test/unpriv-4f2a9b61"),
    ("source_bootstrap", "/run/wg-mix-ebpf-source-bootstrap-c8e41d73"),
    ("quarantine_intake", "/home/.wg-mix-ebpf-retirement-c8e41d73-f75fe7678cfd-r2/intake"),
    ("quarantine_package", "/home/.wg-mix-ebpf-retirement-c8e41d73-f75fe7678cfd-r2/package"),
    ("quarantine_bootstrap", "/run/wg-mix-ebpf-retirement-c8e41d73-f75fe7678cfd-r2/bootstrap"),
    ("rename_order", "intake,package,bootstrap"),
    ("rename_primitive", "renameat2-RENAME_NOREPLACE-dirfd-v1"),
    ("retention", "no-unlink-no-rmdir-no-copy-fallback"),
)
payload = b"".join(
    key.encode("ascii") + b"\t" + value.encode("ascii") + b"\n"
    for key, value in lines
)
keys = tuple(key for key, _ in lines)
if (
    len(lines) != 35
    or len(set(keys)) != 35
    or len(payload) != 1998
    or payload.count(b"\n") != 35
    or not payload.endswith(b"\n")
    or b"\r" in payload
    or b"\0" in payload
):
    raise SystemExit(65)

def validate(candidate):
    if candidate != payload:
        return False
    if candidate.count(b"\n") != 35 or not candidate.endswith(b"\n"):
        return False
    parsed = candidate[:-1].split(b"\n")
    return tuple(item.split(b"\t", 1)[0].decode("ascii") for item in parsed) == keys

tamper_rejections = 0
offset = 0
for key, value in lines:
    line = (key + "\t" + value + "\n").encode("ascii")
    target = offset + len(key) + 1
    mutated = bytearray(payload)
    mutated[target] = ord("Z") if mutated[target] != ord("Z") else ord("Y")
    if validate(bytes(mutated)):
        raise SystemExit(66)
    tamper_rejections += 1
    offset += len(line)
for malformed in (
    b"\n".join(reversed(payload[:-1].split(b"\n"))) + b"\n",
    payload.replace(b"\n", b"\r\n", 1),
    payload[:101] + b"\0" + payload[101:],
    payload[:-1],
):
    if validate(malformed):
        raise SystemExit(66)
prefix_accepts = sum(payload.startswith(candidate) for candidate in (b"", payload[:997], payload))
prefix_rejects = sum(
    not payload.startswith(candidate)
    for candidate in (b"foreign", payload + b"x")
)
if tamper_rejections != 35 or prefix_accepts != 3 or prefix_rejects != 2:
    raise SystemExit(66)
print(
    "HERMETIC_R2_RECEIPT keys=35 bytes=1998 dynamic=3 "
    f"tamper_rejections={tamper_rejections} prefix_accepts={prefix_accepts} "
    f"prefix_rejects={prefix_rejects} sha256={hashlib.sha256(payload).hexdigest()} result=PASS"
)
')" || fail 'independent R2 receipt oracle'
[[ "${R2_RECEIPT_TEST_OUTPUT}" == \
  HERMETIC_R2_RECEIPT\ keys=35\ bytes=1998\ dynamic=3\ tamper_rejections=35\ prefix_accepts=3\ prefix_rejects=2\ sha256=*\ result=PASS ]] ||
  fail "independent R2 receipt marker: ${R2_RECEIPT_TEST_OUTPUT}"
printf '%s\n' "${R2_RECEIPT_TEST_OUTPUT}"
R2_ENGINE_HARNESS="${TEST_ROOT}/r2-engine-harness.py"
/bin/cat >"${R2_ENGINE_HARNESS}" <<'R2_ENGINE_HARNESS'
import ast
import builtins
import ctypes
import errno
import fcntl
import hashlib
import io
import os
from pathlib import Path
import pwd
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
import traceback
import types


EXPECTED_ENGINE_FUNCTIONS = (
    "stop", "require_absolute", "open_abs_dir", "open_parent", "fd_mnt_id",
    "require_dir_fd", "names_at", "entry_stat", "entry_is_directory",
    "read_all", "sha256_fd", "require_file_at", "require_sized_file_at",
    "parse_manifest_ordered", "require_pair", "same_open_inode",
    "require_host_identity", "require_exact_names", "open_child_dir",
    "require_path_absent", "r1_receipt_bytes", "validate_r1_retained_entries",
    "validate_r1_terminal", "validate_current_manifest_payload",
    "validate_current_authority", "converge_current_authority",
    "validate_intake", "validate_old_package", "validate_old_bootstrap",
    "verify_old_provisioner_check", "regular_present", "classify_state",
    "boot_identity", "write_all", "acquire_retirement_lock",
    "initialize_or_verify_boot_marker", "receipt_bytes", "validate_receipt",
    "validate_pending_receipt", "validate_state_objects",
    "renameat2_noreplace", "rename_directory_noreplace", "publish_receipt",
    "converge_completed_rename", "converge_completed_rename_parents",
    "converge_resumed_state", "converge_terminal", "engine_main",
)
EXPECTED_ENGINE_PAYLOAD_SHA256 = (
    "f027c39a75f8a1bd2126a7175288309ecbf88a62a49d3674a4bba747db0b29ad"
)
EXPECTED_ENGINE_MAIN_SHA256 = (
    "f21d81838d8a18912d140b97ef74ca746bf99bc1152eb027e2c82d4e354e748d"
)
EXPECTED_LEGACY_ENGINE_FUNCTIONS = (
    "stop", "require_absolute", "open_abs_dir", "open_parent", "fd_mnt_id",
    "require_dir_fd", "names_at", "entry_stat", "entry_is_directory",
    "read_all", "sha256_fd", "require_file_at", "parse_manifest",
    "require_pair", "same_open_inode", "require_host_identity",
    "require_exact_names", "open_child_dir", "validate_current_authority",
    "fsync_current_authority", "validate_intake", "validate_old_package",
    "validate_old_bootstrap", "directory_location", "regular_present",
    "classify_state", "boot_identity", "write_all",
    "acquire_retirement_lock", "initialize_or_verify_boot_marker",
    "receipt_bytes", "validate_receipt", "validate_pending_receipt",
    "validate_state_objects", "renameat2_noreplace",
    "rename_directory_noreplace", "publish_receipt",
    "converge_completed_rename", "converge_completed_rename_parents",
    "converge_resumed_state", "converge_terminal", "engine_main",
)
EXPECTED_LEGACY_ENGINE_MAIN_CLOSURE = (
    "stop", "require_absolute", "open_abs_dir", "open_parent", "fd_mnt_id",
    "require_dir_fd", "names_at", "entry_stat", "entry_is_directory",
    "read_all", "sha256_fd", "require_file_at", "parse_manifest",
    "require_pair", "same_open_inode", "require_host_identity",
    "require_exact_names", "open_child_dir", "validate_current_authority",
    "fsync_current_authority", "validate_intake", "validate_old_package",
    "validate_old_bootstrap", "regular_present", "classify_state",
    "boot_identity", "write_all", "acquire_retirement_lock",
    "initialize_or_verify_boot_marker", "receipt_bytes", "validate_receipt",
    "validate_pending_receipt", "validate_state_objects",
    "renameat2_noreplace", "rename_directory_noreplace", "publish_receipt",
    "converge_completed_rename", "converge_completed_rename_parents",
    "converge_resumed_state", "converge_terminal", "engine_main",
)
EXPECTED_LEGACY_ENGINE_ORPHAN_CALLERS = {
    "directory_location": (),
}
EXPECTED_LEGACY_ENGINE_PAYLOAD_SHA256 = (
    "03ff972e4d1e40ff83d683091f392be4519ba81f9020af8851007fa0f74fabfc"
)
EXPECTED_LEGACY_ENGINE_MAIN_SHA256 = (
    "9183ac32c570ba2b7f4e6816c9856d3c124adc221bec9c49506a9f16551fc266"
)
PREDECESSOR_COMMIT = "f75fe7678cfdecf08173fd201be5c055417d6e11"
PREDECESSOR_MANIFEST_SHA256 = (
    "2d6c6caac080b599fbfa0f73c64f6976cf30d1504fc506ebd39c638b2f9449e3"
)
R1_MANIFEST_SHA256 = (
    "c4532671304d30755b1c42bb55f82186d96df3f6c84af73078ca16c3fddfe4e6"
)
R1_SELF_SHA256 = (
    "a4a1c89dcd9f087b79149f52a01346ed6db5c209ad4985bdbb8c9132276c0077"
)
R1_RECEIPT_SHA256 = (
    "4c3e9bfd3d4e64f6626abaa43e20cf5e4df6b193395cee6a39953b1c4da7d188"
)
R1_RETAINED_PACKAGE = Path(
    "/private/tmp/wg-mix-b82-v6-c8e41d73-4f2a9b61-2c690050ae1d"
)
R1_AUTHORITY_PACKAGE = Path(
    "/private/tmp/wg-mix-b82-v6-c8e41d73-4f2a9b61-4bdfdfd90756"
)
BOOT_ID = "01234567-89ab-cdef-0123-456789abcdef"
HOSTNAME = "ubuntu-2604-test"
KERNEL = "7.0.0-28-generic"
MACHINE_ID = "9db3fb717cc74974b2a6b243d67f67b9"

PATHS = {
    "current_manifest":
        "/home/.wg-mix-ebpf-retirement-c8e41d73-f75fe7678cfd-r2/authority/package-manifest.v1",
    "current_manifest_pending":
        "/home/.wg-mix-ebpf-retirement-c8e41d73-f75fe7678cfd-r2/authority/package-manifest.v1.pending",
    "current_self":
        "/home/.wg-mix-ebpf-retirement-c8e41d73-f75fe7678cfd-r2/authority/prepare-stage-root.sh",
    "current_self_pending":
        "/home/.wg-mix-ebpf-retirement-c8e41d73-f75fe7678cfd-r2/authority/prepare-stage-root.sh.pending",
    "user_intake":
        "/home/siyixuan/wg-mix-ebpf-test/retire-postflight-c8e41d73-f75fe7678cfd-r2.intake",
    "home_qroot":
        "/home/.wg-mix-ebpf-retirement-c8e41d73-f75fe7678cfd-r2",
    "auth_root":
        "/home/.wg-mix-ebpf-retirement-c8e41d73-f75fe7678cfd-r2/authority",
    "q_intake":
        "/home/.wg-mix-ebpf-retirement-c8e41d73-f75fe7678cfd-r2/intake",
    "q_package":
        "/home/.wg-mix-ebpf-retirement-c8e41d73-f75fe7678cfd-r2/package",
    "source_package": "/home/siyixuan/wg-mix-ebpf-test/unpriv-4f2a9b61",
    "source_bootstrap": "/run/wg-mix-ebpf-source-bootstrap-c8e41d73",
    "run_qroot":
        "/run/wg-mix-ebpf-retirement-c8e41d73-f75fe7678cfd-r2",
    "q_bootstrap":
        "/run/wg-mix-ebpf-retirement-c8e41d73-f75fe7678cfd-r2/bootstrap",
    "lock":
        "/run/wg-mix-ebpf-retirement-c8e41d73-f75fe7678cfd-r2/retirement.v1.lock",
    "receipt_pending":
        "/run/wg-mix-ebpf-retirement-c8e41d73-f75fe7678cfd-r2/retirement-complete.v1.pending",
    "receipt_final":
        "/run/wg-mix-ebpf-retirement-c8e41d73-f75fe7678cfd-r2/retirement-complete.v1",
}
if len(PATHS) != 16:
    raise AssertionError("fixed-path-cardinality")

PACKAGE_NAMES = (
    "source-4f2a9b61.bundle", "package-manifest.v1", "bind-final-package.sh",
    "controller.sh", "prepare-stage-root.sh", "provision-ubuntu-test-host.sh",
    "root-matrix-n-r.sh", "check-realhost-iperf.py", "test-hermetic-matrix.sh",
    "test_matrix_static.py", "checksum-module-lease.sh",
    "root-fresh-verifier-gate.sh", "test-hermetic-fresh-verifier-gate.sh",
    "test_fresh_verifier_gate_static.py", "realnic_acceptance.py",
    "test_realnic_acceptance.py", "test_realnic_acceptance_static.py",
)
BOOTSTRAP_NAMES = ("prepare-stage-root.sh", "provision-ubuntu-test-host.sh")
R1_ID = "c8e41d73-2c690050ae1d-r1"
R1_HOME_QROOT = "/home/.wg-mix-ebpf-retirement-" + R1_ID
R1_RUN_QROOT = "/run/wg-mix-ebpf-retirement-" + R1_ID
R1_USER_INTAKE = (
    "/home/siyixuan/wg-mix-ebpf-test/retire-prestage-" + R1_ID + ".intake"
)
R1_AUTH_ROOT = R1_HOME_QROOT + "/authority"
R1_Q_INTAKE = R1_HOME_QROOT + "/intake"
R1_Q_PACKAGE = R1_HOME_QROOT + "/package"
R1_Q_BOOTSTRAP = R1_RUN_QROOT + "/bootstrap"
R1_LOCK = R1_RUN_QROOT + "/retirement.v1.lock"
R1_RECEIPT_PENDING = R1_RUN_QROOT + "/retirement-complete.v1.pending"
R1_RECEIPT_FINAL = R1_RUN_QROOT + "/retirement-complete.v1"
R1_PREDECESSOR_COMMIT = "2c690050ae1d69dbd074acfd612faa2b80e29f8a"
R1_PREDECESSOR_MANIFEST_SHA256 = (
    "21f14e1f7e646649fdad864dce23dce2055585962d92bfaba6e71158372c1ebe"
)


def digest(path):
    value = hashlib.sha256()
    with open(path, "rb") as stream:
        while True:
            chunk = stream.read(1 << 20)
            if not chunk:
                break
            value.update(chunk)
    return value.hexdigest()


def extract_and_transform_engine(stager):
    shell = Path(stager).read_text(encoding="utf-8")
    anchor = shell.index("run_r2_retirement_engine() {")
    function_end = shell.index("\nrun_stage() {", anchor)
    function = shell[anchor:function_end]
    if function.count("<<'PY'\n") != 1:
        raise AssertionError("embedded-engine-cardinality")
    begin = function.index("<<'PY'\n") + len("<<'PY'\n")
    end = function.index("\nPY\n", begin)
    payload = function[begin:end]
    if (hashlib.sha256(payload.encode("utf-8")).hexdigest() !=
            EXPECTED_ENGINE_PAYLOAD_SHA256):
        raise AssertionError("embedded-engine-payload-sha256")
    original = ast.parse(payload, filename=str(stager) + ":embedded-r2")
    transformed = ast.parse(payload, filename=str(stager) + ":embedded-r2")
    original_functions = tuple(
        node for node in original.body if isinstance(node, ast.FunctionDef)
    )
    transformed_functions = tuple(
        node for node in transformed.body if isinstance(node, ast.FunctionDef)
    )
    if tuple(node.name for node in original_functions) != EXPECTED_ENGINE_FUNCTIONS:
        raise AssertionError("embedded-engine-function-surface")
    if tuple(node.name for node in transformed_functions) != EXPECTED_ENGINE_FUNCTIONS:
        raise AssertionError("embedded-engine-function-transform-surface")
    engine_main_node = original_functions[-1]
    engine_main_source = ast.get_source_segment(payload, engine_main_node)
    if (engine_main_source is None or
            hashlib.sha256(engine_main_source.encode("utf-8")).hexdigest() !=
            EXPECTED_ENGINE_MAIN_SHA256):
        raise AssertionError("embedded-engine-main-sha256")
    graph = {}
    function_names = set(EXPECTED_ENGINE_FUNCTIONS)
    for node in original_functions:
        graph[node.name] = {
            call.func.id
            for call in ast.walk(node)
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
            and call.func.id in function_names
        }
    closure = set()
    pending = ["engine_main"]
    while pending:
        name = pending.pop()
        if name in closure:
            continue
        closure.add(name)
        pending.extend(graph[name] - closure)
    if closure != function_names:
        raise AssertionError("embedded-engine-main-closure")
    before = {
        node.name: ast.dump(node, include_attributes=False)
        for node in original_functions
    }
    replacements = []
    values = {"ROOT_UID": os.geteuid(), "ROOT_GID": os.getegid()}
    for node in transformed.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name) and target.id in values:
            if (not isinstance(node.value, ast.Constant) or
                    type(node.value.value) is not int or node.value.value != 0):
                raise AssertionError("root-id-assignment-shape")
            node.value = ast.copy_location(ast.Constant(values[target.id]), node.value)
            replacements.append(target.id)
    if replacements != ["ROOT_UID", "ROOT_GID"]:
        raise AssertionError("root-id-assignment-cardinality")
    ast.fix_missing_locations(transformed)
    if len(original.body) != len(transformed.body):
        raise AssertionError("embedded-engine-module-body-cardinality")
    top_level_differences = []
    for original_node, transformed_node in zip(original.body, transformed.body):
        if (isinstance(original_node, ast.Assign) and
                isinstance(transformed_node, ast.Assign) and
                len(original_node.targets) == 1 and
                len(transformed_node.targets) == 1 and
                isinstance(original_node.targets[0], ast.Name) and
                isinstance(transformed_node.targets[0], ast.Name) and
                original_node.targets[0].id == transformed_node.targets[0].id and
                original_node.targets[0].id in values):
            target_name = original_node.targets[0].id
            if (original_node.type_comment != transformed_node.type_comment or
                    not isinstance(original_node.value, ast.Constant) or
                    type(original_node.value.value) is not int or
                    original_node.value.value != 0 or
                    not isinstance(transformed_node.value, ast.Constant) or
                    type(transformed_node.value.value) is not int or
                    transformed_node.value.value != values[target_name]):
                raise AssertionError("production-module-rewrite")
            top_level_differences.append(target_name)
            continue
        if (ast.dump(original_node, include_attributes=False) !=
                ast.dump(transformed_node, include_attributes=False)):
            raise AssertionError("production-module-rewrite")
    if top_level_differences != ["ROOT_UID", "ROOT_GID"]:
        raise AssertionError("production-module-difference-cardinality")
    after = {
        node.name: ast.dump(node, include_attributes=False)
        for node in transformed.body if isinstance(node, ast.FunctionDef)
    }
    if after != before:
        raise AssertionError("production-function-rewrite")
    return compile(transformed, str(stager) + ":embedded-r2", "exec")


def extract_and_transform_legacy_engine(stager):
    shell = Path(stager).read_text(encoding="utf-8")
    anchor = shell.index("run_retirement_engine() {")
    function_end = shell.index("\nrun_stage() {", anchor)
    function = shell[anchor:function_end]
    if function.count("<<'PY'\n") != 1:
        raise AssertionError("legacy-embedded-engine-cardinality")
    begin = function.index("<<'PY'\n") + len("<<'PY'\n")
    end = function.index("\nPY\n", begin)
    payload = function[begin:end]
    if (hashlib.sha256(payload.encode("utf-8")).hexdigest() !=
            EXPECTED_LEGACY_ENGINE_PAYLOAD_SHA256):
        raise AssertionError("legacy-embedded-engine-payload-sha256")
    original = ast.parse(payload, filename=str(stager) + ":embedded-r1")
    transformed = ast.parse(payload, filename=str(stager) + ":embedded-r1")
    original_functions = tuple(
        node for node in original.body if isinstance(node, ast.FunctionDef)
    )
    transformed_functions = tuple(
        node for node in transformed.body if isinstance(node, ast.FunctionDef)
    )
    if (tuple(node.name for node in original_functions) !=
            EXPECTED_LEGACY_ENGINE_FUNCTIONS or
            tuple(node.name for node in transformed_functions) !=
            EXPECTED_LEGACY_ENGINE_FUNCTIONS):
        raise AssertionError("legacy-embedded-engine-function-surface")
    engine_main_node = original_functions[-1]
    engine_main_source = ast.get_source_segment(payload, engine_main_node)
    if (engine_main_source is None or
            hashlib.sha256(engine_main_source.encode("utf-8")).hexdigest() !=
            EXPECTED_LEGACY_ENGINE_MAIN_SHA256):
        raise AssertionError("legacy-embedded-engine-main-sha256")
    function_names = set(EXPECTED_LEGACY_ENGINE_FUNCTIONS)
    graph = {}
    for node in original_functions:
        graph[node.name] = {
            call.func.id
            for call in ast.walk(node)
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
            and call.func.id in function_names
        }
    closure = set()
    pending = ["engine_main"]
    while pending:
        name = pending.pop()
        if name in closure:
            continue
        closure.add(name)
        pending.extend(graph[name] - closure)
    reachable_surface = tuple(
        name for name in EXPECTED_LEGACY_ENGINE_FUNCTIONS if name in closure
    )
    if reachable_surface != EXPECTED_LEGACY_ENGINE_MAIN_CLOSURE:
        raise AssertionError("legacy-embedded-engine-main-closure")
    orphan_callers = {
        orphan: tuple(sorted(
            name for name, callees in graph.items() if orphan in callees
        ))
        for orphan in function_names - closure
    }
    if orphan_callers != EXPECTED_LEGACY_ENGINE_ORPHAN_CALLERS:
        raise AssertionError("legacy-embedded-engine-orphan-callers")
    values = {"ROOT_UID": os.geteuid(), "ROOT_GID": os.getegid()}
    replacements = []
    for node in transformed.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name) and target.id in values:
            if (not isinstance(node.value, ast.Constant) or
                    type(node.value.value) is not int or node.value.value != 0):
                raise AssertionError("legacy-root-id-assignment-shape")
            node.value = ast.copy_location(
                ast.Constant(values[target.id]), node.value)
            replacements.append(target.id)
    if replacements != ["ROOT_UID", "ROOT_GID"]:
        raise AssertionError("legacy-root-id-assignment-cardinality")
    ast.fix_missing_locations(transformed)
    if len(original.body) != len(transformed.body):
        raise AssertionError("legacy-embedded-engine-module-cardinality")
    allowed_differences = []
    for original_node, transformed_node in zip(original.body, transformed.body):
        if (isinstance(original_node, ast.Assign) and
                isinstance(transformed_node, ast.Assign) and
                len(original_node.targets) == 1 and
                len(transformed_node.targets) == 1 and
                isinstance(original_node.targets[0], ast.Name) and
                isinstance(transformed_node.targets[0], ast.Name) and
                original_node.targets[0].id == transformed_node.targets[0].id and
                original_node.targets[0].id in values):
            target_name = original_node.targets[0].id
            if (not isinstance(original_node.value, ast.Constant) or
                    type(original_node.value.value) is not int or
                    original_node.value.value != 0 or
                    not isinstance(transformed_node.value, ast.Constant) or
                    type(transformed_node.value.value) is not int or
                    transformed_node.value.value != values[target_name]):
                raise AssertionError("legacy-production-module-rewrite")
            allowed_differences.append(target_name)
            continue
        if (ast.dump(original_node, include_attributes=False) !=
                ast.dump(transformed_node, include_attributes=False)):
            raise AssertionError("legacy-production-module-rewrite")
    if allowed_differences != ["ROOT_UID", "ROOT_GID"]:
        raise AssertionError("legacy-production-module-differences")
    return compile(transformed, str(stager) + ":embedded-r1", "exec")


def engine_argv(mode, manifest_sha):
    argv = [
        "embedded-r2-engine", mode, PATHS["current_manifest"], manifest_sha,
        PATHS["current_manifest_pending"], PATHS["current_self"],
        PATHS["current_self_pending"], PATHS["user_intake"],
        PATHS["home_qroot"], PATHS["auth_root"], PATHS["q_intake"],
        PATHS["q_package"], PATHS["source_package"],
        PATHS["source_bootstrap"], PATHS["run_qroot"],
        PATHS["q_bootstrap"], PATHS["lock"], PATHS["receipt_pending"],
        PATHS["receipt_final"], PREDECESSOR_COMMIT,
        PREDECESSOR_MANIFEST_SHA256, HOSTNAME, KERNEL, MACHINE_ID,
    ]
    if len(argv) != 24:
        raise AssertionError("engine-argv-cardinality")
    return argv


def legacy_engine_argv():
    argv = [
        "embedded-r1-engine", "verify-retirement",
        R1_AUTH_ROOT + "/package-manifest.v1", R1_MANIFEST_SHA256,
        R1_AUTH_ROOT + "/package-manifest.v1.pending",
        R1_AUTH_ROOT + "/prepare-stage-root.sh",
        R1_AUTH_ROOT + "/prepare-stage-root.sh.pending", R1_SELF_SHA256,
        R1_USER_INTAKE, R1_HOME_QROOT, R1_AUTH_ROOT, R1_Q_INTAKE,
        R1_Q_PACKAGE, PATHS["source_package"], PATHS["source_bootstrap"],
        R1_RUN_QROOT, R1_Q_BOOTSTRAP, R1_LOCK, R1_RECEIPT_PENDING,
        R1_RECEIPT_FINAL, R1_PREDECESSOR_COMMIT,
        R1_PREDECESSOR_MANIFEST_SHA256, HOSTNAME, KERNEL, MACHINE_ID,
    ]
    if len(argv) != 25:
        raise AssertionError("legacy-engine-argv-cardinality")
    return argv


class FakeRenameAt2:
    def __init__(self, real_rename, real_stat, cut_call, cut_phase, cut_kind):
        self.argtypes = None
        self.restype = None
        self.real_rename = real_rename
        self.real_stat = real_stat
        self.cut_call = cut_call
        self.cut_phase = cut_phase
        self.cut_kind = cut_kind
        self.calls = 0

    @staticmethod
    def scalar(value):
        return value.value if hasattr(value, "value") else value

    def interrupt(self, phase):
        if self.calls != self.cut_call or phase != self.cut_phase:
            return
        if self.cut_kind == "exit91":
            raise SystemExit(91)
        if self.cut_kind == "sigterm":
            os.kill(os.getpid(), signal.SIGTERM)
            raise AssertionError("SIGTERM returned")
        raise AssertionError("unknown-cut-kind")

    def __call__(self, source_parent, source_name, destination_parent,
                 destination_name, flags):
        source_parent = int(self.scalar(source_parent))
        destination_parent = int(self.scalar(destination_parent))
        flags = int(self.scalar(flags))
        source_name = os.fsdecode(self.scalar(source_name))
        destination_name = os.fsdecode(self.scalar(destination_name))
        if flags != 1:
            raise AssertionError("renameat2-flags")
        self.calls += 1
        self.interrupt("pre")
        try:
            self.real_stat(
                destination_name, dir_fd=destination_parent,
                follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            ctypes.set_errno(errno.EEXIST)
            return -1
        try:
            self.real_rename(
                source_name, destination_name, src_dir_fd=source_parent,
                dst_dir_fd=destination_parent)
        except OSError as error:
            ctypes.set_errno(error.errno or errno.EIO)
            return -1
        self.interrupt("post")
        return 0


class FakeLibC:
    def __init__(self, renameat2):
        self.renameat2 = renameat2


def install_engine_boundaries(root, cut_call, cut_phase, cut_kind):
    real_os_open = os.open
    real_os_rename = os.rename
    real_os_stat = os.stat
    real_builtin_open = builtins.open
    renameat2 = FakeRenameAt2(
        real_os_rename, real_os_stat, cut_call, cut_phase, cut_kind)
    provision_calls = {"count": 0}

    def mapped_os_open(path, flags, mode=0o777, *, dir_fd=None):
        mapped = path
        if dir_fd is None and os.fsdecode(os.fspath(path)) == "/":
            mapped = os.fspath(root)
        if dir_fd is None:
            return real_os_open(mapped, flags, mode)
        return real_os_open(mapped, flags, mode, dir_fd=dir_fd)

    def synthetic_open(path, mode="r", *args, **kwargs):
        decoded = os.fsdecode(os.fspath(path))
        if decoded == "/etc/machine-id":
            return io.StringIO(MACHINE_ID + "\n")
        if decoded == "/proc/sys/kernel/random/boot_id":
            return io.StringIO(BOOT_ID + "\n")
        match = re.fullmatch(r"/proc/self/fdinfo/([0-9]+)", decoded)
        if match:
            metadata = os.fstat(int(match.group(1)))
            return io.StringIO("mnt_id:\t%s\n" % metadata.st_dev)
        return real_builtin_open(path, mode, *args, **kwargs)

    evidence = (
        b"mode=check\n"
        b"missing_packages=\n"
        b"plan_apt_commands=skipped reason=fixed-package-set-already-installed\n"
        b"plan_complete planned_commands_executed=0 writes=0 automatic_cleanup=0\n"
    )

    def fixed_subprocess_run(argv, **kwargs):
        provision_calls["count"] += 1
        if set(kwargs) != {
                "stdin", "stdout", "stderr", "check", "timeout", "pass_fds",
                "env"}:
            raise AssertionError("provision-run-keyword-surface")
        pass_fds = kwargs["pass_fds"]
        if len(pass_fds) != 1:
            raise AssertionError("provision-run-pass-fds")
        provisioner = pass_fds[0]
        expected = [
            "/bin/bash", "-p", "/proc/self/fd/%s" % provisioner, "--check",
            "--expected-address", "192.168.10.82", "--expected-interface",
            "ens33", "--expected-hostname", HOSTNAME, "--expected-kernel",
            KERNEL, "--expected-machine-id", MACHINE_ID,
        ]
        if list(argv) != expected:
            raise AssertionError("provision-run-argv")
        if (kwargs["stdin"] != subprocess.DEVNULL or
                kwargs["stdout"] != subprocess.PIPE or
                kwargs["stderr"] != subprocess.STDOUT or
                kwargs["check"] is not False or kwargs["timeout"] != 600 or
                kwargs["pass_fds"] != (provisioner,) or
                kwargs["env"] != {
                    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}):
            raise AssertionError("provision-run-contract")
        if not stat.S_ISREG(os.fstat(provisioner).st_mode):
            raise AssertionError("provision-run-descriptor")
        return subprocess.CompletedProcess(argv, 0, stdout=evidence)

    def fixed_cdll(name, *args, **kwargs):
        if name != "libc.so.6" or args or kwargs != {"use_errno": True}:
            raise AssertionError("libc-boundary")
        return FakeLibC(renameat2)

    os.open = mapped_os_open
    os.uname = lambda: types.SimpleNamespace(
        nodename=HOSTNAME, release=KERNEL)
    builtins.open = synthetic_open
    pwd.getpwnam = lambda name: (
        types.SimpleNamespace(pw_uid=os.geteuid(), pw_gid=os.getegid())
        if name == "siyixuan" else (_ for _ in ()).throw(KeyError(name)))
    subprocess.run = fixed_subprocess_run
    ctypes.CDLL = fixed_cdll
    return renameat2, provision_calls


def execute_engine_child(stager, root, mode, manifest_sha, expected_renames,
                         cut_call, cut_phase, cut_kind):
    code = extract_and_transform_engine(stager)
    renameat2, provision_calls = install_engine_boundaries(
        Path(root).resolve(), cut_call, cut_phase, cut_kind)
    sys.argv = engine_argv(mode, manifest_sha)
    exec(code, {"__name__": "__main__", "__file__": "<embedded-r2-engine>"})
    if renameat2.calls != expected_renames:
        raise AssertionError(
            "rename-count:%s:%s" % (renameat2.calls, expected_renames))
    print(
        "HERMETIC_R2_ENGINE_CHILD functions=48 closure=48 argv=24 "
        "root_id_assignments=2 renames=%s provision_checks=%s" %
        (renameat2.calls, provision_calls["count"]), flush=True)


def execute_legacy_engine_child(root):
    legacy_stager = R1_AUTHORITY_PACKAGE / "prepare-stage-root.sh"
    code = extract_and_transform_legacy_engine(legacy_stager)
    renameat2, provision_calls = install_engine_boundaries(
        Path(root).resolve(), 0, "none", "none")
    sys.argv = legacy_engine_argv()
    exec(code, {"__name__": "__main__", "__file__": "<embedded-r1-engine>"})
    raise AssertionError(
        "legacy-engine-unexpected-return:%s:%s" %
        (renameat2.calls, provision_calls["count"]))


def manifest_values(path):
    payload = Path(path).read_bytes()
    if (not payload.endswith(b"\n") or b"\0" in payload or b"\r" in payload):
        raise AssertionError("current-manifest-encoding")
    rows = payload[:-1].split(b"\n")
    values = {}
    for row in rows:
        fields = row.split(b"\t")
        if len(fields) != 2:
            raise AssertionError("current-manifest-row")
        key, value = (item.decode("utf-8", "strict") for item in fields)
        if key in values:
            raise AssertionError("current-manifest-duplicate")
        values[key] = value
    if len(rows) != 112:
        raise AssertionError("current-manifest-field-count")
    fixed = {
        "format": "wg-mix-ebpf-b82-v6-package-v5",
        "remote_package_dir": PATHS["source_package"],
        "target_hostname": HOSTNAME,
        "target_kernel": KERNEL,
        "target_machine_id": MACHINE_ID,
    }
    if any(values.get(key) != value for key, value in fixed.items()):
        raise AssertionError("current-manifest-fixture-contract")
    return payload, values


def virtual(root, logical):
    if not logical.startswith("/"):
        raise AssertionError("virtual-path")
    return Path(root) if logical == "/" else Path(root) / logical[1:]


def mkdir_logical(root, logical):
    path = virtual(root, logical)
    path.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.chmod(path, 0o700)
    return path


def copy_mode(source, destination, mode):
    source = Path(source)
    destination = Path(destination)
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    shutil.copyfile(str(source), str(destination))
    os.chmod(destination, mode)
    if os.lstat(destination).st_nlink != 1:
        raise AssertionError("fixture-copy-nlink")


def make_pair(source, final, pending, mode, fifo=False):
    final = Path(final)
    pending = Path(pending)
    if fifo:
        os.mkfifo(final, mode)
        os.chmod(final, mode)
    else:
        copy_mode(source, final, mode)
    os.link(final, pending)
    first = os.lstat(final)
    second = os.lstat(pending)
    expected_type = stat.S_ISFIFO if fifo else stat.S_ISREG
    if (not expected_type(first.st_mode) or
            (first.st_dev, first.st_ino, first.st_nlink) !=
            (second.st_dev, second.st_ino, 2)):
        raise AssertionError("fixture-authority-pair")


def copy_exact_set(source, destination, names, mode):
    destination = Path(destination)
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.chmod(destination, 0o700)
    for name in names:
        copy_mode(Path(source) / name, destination / name, mode)
    if set(os.listdir(destination)) != set(names):
        raise AssertionError("fixture-copy-exact-set")


def chown_tree_current(root):
    uid = os.geteuid()
    gid = os.getegid()
    entries = [Path(root)] + list(Path(root).rglob("*"))
    for entry in entries:
        os.chown(entry, uid, gid, follow_symlinks=False)


def independent_r1_receipt():
    lines = (
        ("format", "wg-mix-ebpf-b82-prestage-retirement-terminal-v1"),
        ("retire_id", R1_ID),
        ("state", "TERMINAL"),
        ("predecessor_commit", "2c690050ae1d69dbd074acfd612faa2b80e29f8a"),
        ("predecessor_manifest_sha256",
         "21f14e1f7e646649fdad864dce23dce2055585962d92bfaba6e71158372c1ebe"),
        ("predecessor_bundle_sha256",
         "5c53adec58363ec2ff51d9bd5dcd7e467874c839393178491c74b16a8c9f922c"),
        ("authority_manifest_sha256", R1_MANIFEST_SHA256),
        ("authority_prepare_stage_root_sha256", R1_SELF_SHA256),
        ("authority_integration_commit", "4bdfdfd9075669566d5137de4550aefb240d13c4"),
        ("source_intake",
         "/home/siyixuan/wg-mix-ebpf-test/retire-prestage-" + R1_ID + ".intake"),
        ("source_package", PATHS["source_package"]),
        ("source_bootstrap", PATHS["source_bootstrap"]),
        ("quarantine_intake", R1_HOME_QROOT + "/intake"),
        ("quarantine_package", R1_HOME_QROOT + "/package"),
        ("quarantine_bootstrap", R1_RUN_QROOT + "/bootstrap"),
        ("rename_order", "intake,package,bootstrap"),
        ("rename_primitive", "renameat2-RENAME_NOREPLACE-dirfd-v1"),
        ("retention", "no-unlink-no-rmdir-no-copy-fallback"),
    )
    payload = b"".join(
        key.encode("ascii") + b"\t" + value.encode("ascii") + b"\n"
        for key, value in lines)
    if (len(lines) != 18 or len(payload) != 1211 or
            hashlib.sha256(payload).hexdigest() != R1_RECEIPT_SHA256):
        raise AssertionError("independent-r1-receipt")
    return payload


def independent_r2_receipt(current_manifest, current_self):
    manifest_payload, values = manifest_values(current_manifest)
    manifest_sha = hashlib.sha256(manifest_payload).hexdigest()
    self_sha = digest(current_self)
    if values.get("prepare_stage_root_sh_sha256") != self_sha:
        raise AssertionError("current-self-manifest-binding")
    lines = (
        ("format", "wg-mix-ebpf-b82-postflight-retirement-terminal-v1"),
        ("retire_id", "c8e41d73-f75fe7678cfd-r2"),
        ("state", "TERMINAL"),
        ("predecessor_commit", PREDECESSOR_COMMIT),
        ("predecessor_manifest_sha256", PREDECESSOR_MANIFEST_SHA256),
        ("predecessor_bundle_sha256",
         "b74811808e0413714dcf20b8292fe68631f603c0b9a68bc9951af481477b413b"),
        ("predecessor_package_format", "wg-mix-ebpf-b82-v6-package-v4"),
        ("predecessor_manifest_field_count", "103"),
        ("predecessor_package_entry_count", "17"),
        ("predecessor_bootstrap_entry_count", "2"),
        ("authority_manifest_sha256", manifest_sha),
        ("authority_prepare_stage_root_sha256", self_sha),
        ("authority_integration_commit", values["integration_commit"]),
        ("authority_package_format", "wg-mix-ebpf-b82-v6-package-v5"),
        ("authority_manifest_field_count", "112"),
        ("authority_transfer_entry_count", "20"),
        ("prior_retirement_id", R1_ID),
        ("prior_retirement_receipt_sha256", R1_RECEIPT_SHA256),
        ("failure_cut", "postflight-hermetic-matrix-before-stage-snapshot"),
        ("failure_point", "hermetic-matrix"),
        ("failure_reason", "review-input-is-not-a-regular-file"),
        ("failure_path",
         PATHS["source_package"] + "/test-hermetic-checksum-module-lease.sh"),
        ("failure_rc", "1"),
        ("provision_check", "missing_set=none,writes=0"),
        ("bootstrap_snapshot_state", "absent"),
        ("stage_root_state", "absent"),
        ("source_intake", PATHS["user_intake"]),
        ("source_package", PATHS["source_package"]),
        ("source_bootstrap", PATHS["source_bootstrap"]),
        ("quarantine_intake", PATHS["q_intake"]),
        ("quarantine_package", PATHS["q_package"]),
        ("quarantine_bootstrap", PATHS["q_bootstrap"]),
        ("rename_order", "intake,package,bootstrap"),
        ("rename_primitive", "renameat2-RENAME_NOREPLACE-dirfd-v1"),
        ("retention", "no-unlink-no-rmdir-no-copy-fallback"),
    )
    payload = b"".join(
        key.encode("ascii") + b"\t" + value.encode("ascii") + b"\n"
        for key, value in lines)
    keys = tuple(key for key, _ in lines)
    if (len(lines) != 35 or len(set(keys)) != 35 or len(payload) != 1998 or
            payload.count(b"\n") != 35 or not payload.endswith(b"\n") or
            b"\r" in payload or b"\0" in payload):
        raise AssertionError("independent-r2-receipt")
    return manifest_sha, payload


def setup_engine_fixture(root, current_manifest, current_self, predecessor,
                         authority_fifo="none"):
    root = Path(root)
    if authority_fifo not in {"none", "manifest", "self"}:
        raise AssertionError("authority-fifo-kind")
    os.chown(root, os.geteuid(), os.getegid())
    if digest(Path(predecessor) / "package-manifest.v1") != PREDECESSOR_MANIFEST_SHA256:
        raise AssertionError("predecessor-fixture-sha256")
    if (digest(R1_RETAINED_PACKAGE / "package-manifest.v1") !=
            "21f14e1f7e646649fdad864dce23dce2055585962d92bfaba6e71158372c1ebe"):
        raise AssertionError("r1-retained-fixture-sha256")
    if (digest(R1_AUTHORITY_PACKAGE / "package-manifest.v1") !=
            R1_MANIFEST_SHA256 or
            digest(R1_AUTHORITY_PACKAGE / "prepare-stage-root.sh") !=
            R1_SELF_SHA256):
        raise AssertionError("r1-authority-fixture-sha256")
    manifest_sha, receipt = independent_r2_receipt(current_manifest, current_self)

    virtual(root, "/home/siyixuan/wg-mix-ebpf-test").mkdir(
        mode=0o700, parents=True, exist_ok=False)
    virtual(root, "/run").mkdir(mode=0o700, parents=True, exist_ok=False)
    mkdir_logical(root, PATHS["home_qroot"])
    mkdir_logical(root, PATHS["auth_root"])
    mkdir_logical(root, PATHS["run_qroot"])
    make_pair(
        current_manifest, virtual(root, PATHS["current_manifest"]),
        virtual(root, PATHS["current_manifest_pending"]), 0o600,
        fifo=authority_fifo == "manifest")
    make_pair(
        current_self, virtual(root, PATHS["current_self"]),
        virtual(root, PATHS["current_self_pending"]), 0o700,
        fifo=authority_fifo == "self")
    intake = mkdir_logical(root, PATHS["user_intake"])
    copy_mode(current_manifest, intake / "package-manifest.v1", 0o600)
    copy_mode(current_self, intake / "prepare-stage-root.sh", 0o600)
    copy_exact_set(
        predecessor, virtual(root, PATHS["source_package"]),
        PACKAGE_NAMES, 0o600)
    bootstrap = mkdir_logical(root, PATHS["source_bootstrap"])
    for name in BOOTSTRAP_NAMES:
        copy_mode(Path(predecessor) / name, bootstrap / name, 0o700)

    mkdir_logical(root, R1_HOME_QROOT)
    r1_authority = mkdir_logical(root, R1_HOME_QROOT + "/authority")
    r1_intake = mkdir_logical(root, R1_HOME_QROOT + "/intake")
    copy_exact_set(
        R1_RETAINED_PACKAGE, virtual(root, R1_HOME_QROOT + "/package"),
        PACKAGE_NAMES, 0o600)
    mkdir_logical(root, R1_RUN_QROOT)
    r1_bootstrap = mkdir_logical(root, R1_RUN_QROOT + "/bootstrap")
    make_pair(
        R1_AUTHORITY_PACKAGE / "package-manifest.v1",
        r1_authority / "package-manifest.v1",
        r1_authority / "package-manifest.v1.pending", 0o600)
    make_pair(
        R1_AUTHORITY_PACKAGE / "prepare-stage-root.sh",
        r1_authority / "prepare-stage-root.sh",
        r1_authority / "prepare-stage-root.sh.pending", 0o700)
    copy_mode(
        R1_AUTHORITY_PACKAGE / "package-manifest.v1",
        r1_intake / "package-manifest.v1", 0o600)
    copy_mode(
        R1_AUTHORITY_PACKAGE / "prepare-stage-root.sh",
        r1_intake / "prepare-stage-root.sh", 0o600)
    for name in BOOTSTRAP_NAMES:
        copy_mode(R1_RETAINED_PACKAGE / name, r1_bootstrap / name, 0o700)
    r1_lock = virtual(root, R1_RUN_QROOT + "/retirement.v1.lock")
    r1_lock.write_bytes(("boot_id\t" + BOOT_ID + "\n").encode("ascii"))
    os.chmod(r1_lock, 0o600)
    r1_final = virtual(root, R1_RUN_QROOT + "/retirement-complete.v1")
    r1_final.write_bytes(independent_r1_receipt())
    os.chmod(r1_final, 0o600)
    chown_tree_current(root)
    return manifest_sha, receipt


def tree_snapshot(root, logical):
    base = virtual(root, logical)
    if not os.path.lexists(base):
        return ((logical, "absent"),)
    result = []

    def visit(path, relative):
        metadata = os.lstat(path)
        if stat.S_ISDIR(metadata.st_mode):
            kind = "d"
            names = tuple(sorted(os.listdir(path)))
            content = names
        elif stat.S_ISREG(metadata.st_mode):
            kind = "f"
            names = ()
            content = digest(path)
        elif stat.S_ISFIFO(metadata.st_mode):
            kind = "p"
            names = ()
            content = ""
        elif stat.S_ISLNK(metadata.st_mode):
            kind = "l"
            names = ()
            content = os.readlink(path)
        else:
            kind = "?"
            names = ()
            content = ""
        result.append((
            relative, kind, metadata.st_dev, metadata.st_ino,
            stat.S_IMODE(metadata.st_mode), metadata.st_uid, metadata.st_gid,
            metadata.st_nlink, metadata.st_size, content))
        if kind == "d":
            for name in names:
                visit(Path(path) / name, name if relative == "." else relative + "/" + name)

    visit(base, ".")
    return tuple(result)


def r1_snapshot(root):
    return (
        tree_snapshot(root, R1_HOME_QROOT),
        tree_snapshot(root, R1_RUN_QROOT),
    )


def complete_snapshot(root):
    return tree_snapshot(root, "/")


STATE_SIGNATURES = {
    "D": (1, 1, 1, 0, 0, 0, 0, 0),
    "I": (0, 1, 1, 1, 0, 0, 0, 0),
    "S1": (0, 0, 1, 1, 1, 0, 0, 0),
    "S2": (0, 0, 0, 1, 1, 1, 0, 0),
    "S2P": (0, 0, 0, 1, 1, 1, 1, 0),
    "T_CANDIDATE": (0, 0, 0, 1, 1, 1, 0, 1),
}


def typed_present(root, logical, directory):
    path = virtual(root, logical)
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return 0
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(metadata.st_mode):
        raise AssertionError("state-object-type:" + logical)
    return 1


def observe_state(root, expected_receipt, allow_lockless_d=False):
    signature = (
        typed_present(root, PATHS["user_intake"], True),
        typed_present(root, PATHS["source_package"], True),
        typed_present(root, PATHS["source_bootstrap"], True),
        typed_present(root, PATHS["q_intake"], True),
        typed_present(root, PATHS["q_package"], True),
        typed_present(root, PATHS["q_bootstrap"], True),
        typed_present(root, PATHS["receipt_pending"], False),
        typed_present(root, PATHS["receipt_final"], False),
    )
    matches = [name for name, value in STATE_SIGNATURES.items() if value == signature]
    if len(matches) != 1:
        raise AssertionError("independent-state-signature:%r" % (signature,))
    state = matches[0]
    expected_home = {"authority"}
    if state in {"I", "S1", "S2", "S2P", "T_CANDIDATE"}:
        expected_home.add("intake")
    if state in {"S1", "S2", "S2P", "T_CANDIDATE"}:
        expected_home.add("package")
    expected_run = set() if state == "D" and allow_lockless_d else {"retirement.v1.lock"}
    if state in {"S2", "S2P", "T_CANDIDATE"}:
        expected_run.add("bootstrap")
    if state == "S2P":
        expected_run.add("retirement-complete.v1.pending")
    if state == "T_CANDIDATE":
        expected_run.add("retirement-complete.v1")
    if set(os.listdir(virtual(root, PATHS["home_qroot"]))) != expected_home:
        raise AssertionError("independent-home-entries:" + state)
    if set(os.listdir(virtual(root, PATHS["run_qroot"]))) != expected_run:
        raise AssertionError("independent-run-entries:" + state)
    if state != "D" or not allow_lockless_d:
        lock = virtual(root, PATHS["lock"])
        if (stat.S_IMODE(os.lstat(lock).st_mode) != 0o600 or
                lock.read_bytes() != ("boot_id\t" + BOOT_ID + "\n").encode("ascii")):
            raise AssertionError("independent-lock-oracle")
    if state == "S2P" and virtual(root, PATHS["receipt_pending"]).read_bytes() != expected_receipt:
        raise AssertionError("independent-pending-receipt")
    if state == "T_CANDIDATE" and virtual(root, PATHS["receipt_final"]).read_bytes() != expected_receipt:
        raise AssertionError("independent-final-receipt")
    return state


def source_directory_identities(root):
    result = {}
    for name in ("user_intake", "source_package", "source_bootstrap"):
        metadata = os.lstat(virtual(root, PATHS[name]))
        result[name] = (metadata.st_dev, metadata.st_ino)
    return result


def assert_completed_move_identities(root, initial, state):
    completed = []
    if state in {"I", "S1", "S2", "S2P", "T_CANDIDATE"}:
        completed.append(("user_intake", "q_intake"))
    if state in {"S1", "S2", "S2P", "T_CANDIDATE"}:
        completed.append(("source_package", "q_package"))
    if state in {"S2", "S2P", "T_CANDIDATE"}:
        completed.append(("source_bootstrap", "q_bootstrap"))
    for source_name, destination_name in completed:
        metadata = os.lstat(virtual(root, PATHS[destination_name]))
        if (metadata.st_dev, metadata.st_ino) != initial[source_name]:
            raise AssertionError("independent-rename-inode:" + source_name)


def exact_line(output, expected):
    if output.splitlines().count(expected) != 1:
        raise AssertionError("exact-output-line:%s:%s" % (expected, output))


def run_engine_process(stager, current_manifest, current_self, predecessor,
                       root, mode, expected_renames, cut_call=0,
                       cut_phase="none", cut_kind="none", timeout=12.0):
    command = [
        sys.executable, "-B", "-I", str(Path(__file__).resolve()), "child",
        str(stager), str(current_manifest), str(current_self), str(predecessor),
        str(root), mode, str(expected_renames), str(cut_call), cut_phase, cut_kind,
    ]
    try:
        return subprocess.run(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, check=False, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        raise AssertionError(
            "engine-child-timeout:%s:%s" % (mode, error.stdout))


def run_legacy_engine_process(root, timeout=12.0):
    command = [
        sys.executable, "-B", "-I", str(Path(__file__).resolve()),
        "legacy-child", str(root),
    ]
    try:
        return subprocess.run(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, check=False, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        raise AssertionError("legacy-engine-child-timeout:%s" % error.stdout)


def driver(stager, current_manifest, current_self, predecessor, case_root):
    stager = Path(stager)
    current_manifest = Path(current_manifest)
    current_self = Path(current_self)
    predecessor = Path(predecessor)
    case_root = Path(case_root)
    case_root.mkdir(mode=0o700, parents=False, exist_ok=False)
    os.chown(case_root, os.geteuid(), os.getegid())
    extract_and_transform_engine(stager)
    manifest_sha, expected_receipt = independent_r2_receipt(
        current_manifest, current_self)
    case_number = {"value": 0}

    def new_case(label, fifo="none"):
        case_number["value"] += 1
        root = case_root / ("%02d-%s" % (case_number["value"], label))
        root.mkdir(mode=0o700)
        os.chown(root, os.geteuid(), os.getegid())
        observed_sha, observed_receipt = setup_engine_fixture(
            root, current_manifest, current_self, predecessor,
            authority_fifo=fifo)
        if observed_sha != manifest_sha or observed_receipt != expected_receipt:
            raise AssertionError("fixture-oracle-drift")
        return root

    r1_comparisons = 0
    legacy_collision_count = 0
    current_precheck_count = 0
    collision = new_case("legacy-source-reuse-collision")
    collision_before = complete_snapshot(collision)
    collision_r1 = r1_snapshot(collision)
    collision_sources = source_directory_identities(collision)
    legacy = run_legacy_engine_process(collision)
    if legacy.returncode != 79:
        raise AssertionError(
            "legacy-collision-return:%s:%s" %
            (legacy.returncode, legacy.stdout))
    exact_line(
        legacy.stdout,
        "B82_V6_RETIREMENT_ENGINE_STOP reason=retirement-state rc=79 "
        "cleanup=0 retained=1")
    if complete_snapshot(collision) != collision_before:
        raise AssertionError("legacy-collision-tree-write")
    if r1_snapshot(collision) != collision_r1:
        raise AssertionError("legacy-collision-r1-drift")
    r1_comparisons += 1
    legacy_collision_count += 1
    collision_lock_fd = os.open(
        virtual(collision, R1_LOCK), os.O_RDONLY | os.O_NOFOLLOW)
    try:
        fcntl.flock(
            collision_lock_fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        current_precheck = run_engine_process(
            stager, current_manifest, current_self, predecessor, collision,
            "retire-postflight-f75fe7678cfd-r2", -1, 1, "pre", "exit91")
    finally:
        try:
            fcntl.flock(collision_lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(collision_lock_fd)
    if current_precheck.returncode != 91:
        raise AssertionError(
            "current-precheck-return:%s:%s" %
            (current_precheck.returncode, current_precheck.stdout))
    if observe_state(collision, expected_receipt) != "D":
        raise AssertionError("current-precheck-state")
    if source_directory_identities(collision) != collision_sources:
        raise AssertionError("current-precheck-source-identity")
    if r1_snapshot(collision) != collision_r1:
        raise AssertionError("current-precheck-r1-drift")
    r1_comparisons += 1
    current_precheck_count += 1

    baseline = new_case("baseline")
    baseline_r1 = r1_snapshot(baseline)
    baseline_inodes = source_directory_identities(baseline)
    if observe_state(baseline, expected_receipt, allow_lockless_d=True) != "D":
        raise AssertionError("baseline-initial-state")
    result = run_engine_process(
        stager, current_manifest, current_self, predecessor, baseline,
        "retire-postflight-f75fe7678cfd-r2", 4)
    if result.returncode != 0:
        raise AssertionError("baseline-retire:%s:%s" % (result.returncode, result.stdout))
    exact_line(
        result.stdout,
        "B82_V6_RETIREMENT_COMPLETE state=T disposition=advanced "
        "namespace_writes=6 same_boot=1")
    if observe_state(baseline, expected_receipt) != "T_CANDIDATE":
        raise AssertionError("baseline-terminal-state")
    assert_completed_move_identities(baseline, baseline_inodes, "T_CANDIDATE")
    if r1_snapshot(baseline) != baseline_r1:
        raise AssertionError("baseline-r1-invariance")
    r1_comparisons += 1
    baseline_terminal = complete_snapshot(baseline)
    verify = run_engine_process(
        stager, current_manifest, current_self, predecessor, baseline,
        "verify-postflight-retirement-r2", 0)
    if verify.returncode != 0:
        raise AssertionError("baseline-verify:%s:%s" % (verify.returncode, verify.stdout))
    exact_line(
        verify.stdout,
        "B82_V6_RETIREMENT_VERIFIED state=T namespace_writes=0 same_boot=1 "
        "receipt=" + PATHS["receipt_final"])
    if complete_snapshot(baseline) != baseline_terminal:
        raise AssertionError("baseline-verify-namespace-write")
    if r1_snapshot(baseline) != baseline_r1:
        raise AssertionError("baseline-verify-r1-invariance")
    r1_comparisons += 1

    cut_points = (
        (1, "post", "I", 3, 4),
        (2, "post", "S1", 2, 3),
        (3, "post", "S2", 1, 2),
        (4, "pre", "S2P", 1, 1),
        (4, "post", "T_CANDIDATE", 0, 0),
    )
    cut_count = 0
    exit_count = 0
    signal_count = 0
    resume_count = 0
    for call, phase, observed_state, resume_renames, resume_writes in cut_points:
        for kind in ("exit91", "sigterm"):
            root = new_case("cut-%s-%s-%s" % (call, phase, kind))
            before_r1 = r1_snapshot(root)
            initial_inodes = source_directory_identities(root)
            interrupted = run_engine_process(
                stager, current_manifest, current_self, predecessor, root,
                "retire-postflight-f75fe7678cfd-r2", -1, call, phase, kind)
            expected_rc = 91 if kind == "exit91" else -signal.SIGTERM
            if interrupted.returncode != expected_rc:
                raise AssertionError(
                    "cut-return:%s:%s:%s" %
                    (expected_rc, interrupted.returncode, interrupted.stdout))
            if observe_state(root, expected_receipt) != observed_state:
                raise AssertionError("cut-state:" + observed_state)
            assert_completed_move_identities(root, initial_inodes, observed_state)
            if r1_snapshot(root) != before_r1:
                raise AssertionError("cut-r1-invariance")
            r1_comparisons += 1
            resumed = run_engine_process(
                stager, current_manifest, current_self, predecessor, root,
                "retire-postflight-f75fe7678cfd-r2", resume_renames)
            if resumed.returncode != 0:
                raise AssertionError(
                    "resume-return:%s:%s" % (resumed.returncode, resumed.stdout))
            if observed_state == "T_CANDIDATE":
                exact_line(
                    resumed.stdout,
                    "B82_V6_RETIREMENT_COMPLETE state=T "
                    "disposition=verified-existing namespace_writes=0 same_boot=1")
            else:
                exact_line(
                    resumed.stdout,
                    "B82_V6_RETIREMENT_COMPLETE state=T disposition=advanced "
                    "namespace_writes=%s same_boot=1" % resume_writes)
            if observe_state(root, expected_receipt) != "T_CANDIDATE":
                raise AssertionError("resume-terminal-state")
            assert_completed_move_identities(root, initial_inodes, "T_CANDIDATE")
            if r1_snapshot(root) != before_r1:
                raise AssertionError("resume-r1-invariance")
            r1_comparisons += 1
            terminal_snapshot = complete_snapshot(root)
            verified = run_engine_process(
                stager, current_manifest, current_self, predecessor, root,
                "verify-postflight-retirement-r2", 0)
            if verified.returncode != 0:
                raise AssertionError(
                    "cut-verify-return:%s:%s" %
                    (verified.returncode, verified.stdout))
            exact_line(
                verified.stdout,
                "B82_V6_RETIREMENT_VERIFIED state=T namespace_writes=0 "
                "same_boot=1 receipt=" + PATHS["receipt_final"])
            if complete_snapshot(root) != terminal_snapshot:
                raise AssertionError("cut-verify-namespace-write")
            if r1_snapshot(root) != before_r1:
                raise AssertionError("cut-verify-r1-invariance")
            r1_comparisons += 1
            cut_count += 1
            resume_count += 1
            if kind == "exit91":
                exit_count += 1
            else:
                signal_count += 1

    fifo_count = 0
    for fifo, reason in (
            ("manifest", "authority-manifest-pending-metadata"),
            ("self", "authority-self-pending-metadata")):
        root = new_case("authority-%s-fifo" % fifo, fifo=fifo)
        before = complete_snapshot(root)
        before_r1 = r1_snapshot(root)
        started = time.monotonic()
        failed = run_engine_process(
            stager, current_manifest, current_self, predecessor, root,
            "retire-postflight-f75fe7678cfd-r2", 0, timeout=5.0)
        elapsed = time.monotonic() - started
        if failed.returncode != 79 or elapsed >= 5.0:
            raise AssertionError(
                "authority-fifo-return:%s:%s:%s" %
                (fifo, failed.returncode, failed.stdout))
        exact_line(
            failed.stdout,
            "B82_V6_RETIREMENT_ENGINE_STOP reason=%s rc=79 cleanup=0 retained=1" %
            reason)
        if observe_state(root, expected_receipt, allow_lockless_d=True) != "D":
            raise AssertionError("authority-fifo-state")
        if os.path.lexists(virtual(root, PATHS["lock"])):
            raise AssertionError("authority-fifo-lock-write")
        if complete_snapshot(root) != before:
            raise AssertionError("authority-fifo-r2-write")
        if r1_snapshot(root) != before_r1:
            raise AssertionError("authority-fifo-r1-invariance")
        r1_comparisons += 1
        fifo_count += 1

    if (cut_count, exit_count, signal_count, resume_count, fifo_count,
            legacy_collision_count, current_precheck_count,
            r1_comparisons) != (10, 5, 5, 10, 2, 1, 1, 36):
        raise AssertionError("engine-matrix-cardinality")
    print(
        "HERMETIC_R1_SOURCE_REUSE_COLLISION legacy_functions=42 "
        "legacy_argv=25 legacy_rc=79 reason=retirement-state "
        "tree_unchanged=1 "
        "current_r2=pre-rename-concurrent-shared-lock-pass "
        "result=PASS")
    print(
        "HERMETIC_R2_ENGINE states=7 functions=48 argv=24 cuts=10 "
        "exit91=5 sigterm=5 resumes=10 verify_namespace_writes=0 "
        "authority_fifos=2 result=PASS")
    print(
        "HERMETIC_R2_R1_INVARIANCE result=PASS snapshots=36 "
        "objects=authority,intake,package,bootstrap,lock,receipt")


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "legacy-child":
        if len(sys.argv) != 3:
            raise SystemExit(64)
        execute_legacy_engine_child(sys.argv[2])
        return
    if len(sys.argv) >= 2 and sys.argv[1] == "child":
        if len(sys.argv) != 12:
            raise SystemExit(64)
        expected_renames = int(sys.argv[8])
        cut_call = int(sys.argv[9])
        cut_phase = sys.argv[10]
        cut_kind = sys.argv[11]
        if (expected_renames < -1 or expected_renames > 4 or
                cut_call not in {0, 1, 2, 3, 4} or
                cut_phase not in {"none", "pre", "post"} or
                cut_kind not in {"none", "exit91", "sigterm"} or
                ((cut_call == 0) != (cut_phase == "none")) or
                ((cut_call == 0) != (cut_kind == "none"))):
            raise SystemExit(64)
        manifest_sha = digest(sys.argv[3])
        execute_engine_child(
            sys.argv[2], sys.argv[6], sys.argv[7], manifest_sha,
            expected_renames, cut_call, cut_phase, cut_kind)
        return
    if len(sys.argv) != 6:
        raise SystemExit(64)
    driver(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])


main()
R2_ENGINE_HARNESS
/bin/chmod 0600 "${R2_ENGINE_HARNESS}" || fail 'R2 engine harness mode'
R2_ENGINE_TEST_OUTPUT="$(/usr/bin/python3 -B -I "${R2_ENGINE_HARNESS}" \
  "${STAGER}" "${BOUND_MANIFEST}" "${BOUND_OUTPUT}/prepare-stage-root.sh" \
  "${R2_PREDECESSOR_CLONE}" "${TEST_ROOT}/r2-engine-cases")" ||
  fail 'actual embedded R2 engine harness'
[[ "${R2_ENGINE_TEST_OUTPUT}" == \
  *'HERMETIC_R1_SOURCE_REUSE_COLLISION legacy_functions=42 legacy_argv=25 legacy_rc=79 reason=retirement-state tree_unchanged=1 current_r2=pre-rename-concurrent-shared-lock-pass result=PASS'* &&
  "${R2_ENGINE_TEST_OUTPUT}" == \
  *'HERMETIC_R2_ENGINE '*'states=7 functions=48 argv=24 cuts=10 exit91=5 sigterm=5 resumes=10 verify_namespace_writes=0 authority_fifos=2 result=PASS'* &&
  "${R2_ENGINE_TEST_OUTPUT}" == \
  *'HERMETIC_R2_R1_INVARIANCE '*'result=PASS snapshots=36'* ]] ||
  fail "actual embedded R2 engine markers: ${R2_ENGINE_TEST_OUTPUT}"
printf '%s\n' "${R2_ENGINE_TEST_OUTPUT}"
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
[[ "${PACKAGE_TAMPER_CUTS}" -eq 40 ]] || fail 'flat package tamper cut cardinality'
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
printf 'HERMETIC_LOCAL_AUTHORITY package_names=20 package_tamper_cuts=40 forged_triplet=blocked flat_sha=blocked flat_mode=blocked flat_nlink=blocked history=blocked credential_reads=0 spawns=0\n'

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
