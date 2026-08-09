#!/usr/bin/env bash
set -u
set -o pipefail
umask 077

REVIEW_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)" || exit 70
readonly REVIEW_ROOT
REPOSITORY="$(CDPATH= cd -- "${REVIEW_ROOT}/../.." && pwd -P)" || exit 70
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
/bin/mkdir -m 0700 -- "${FIXTURE_REPOSITORY}" || fail 'fixture repository creation'
/usr/bin/git -C "${FIXTURE_REPOSITORY}" init || fail 'fixture Git init'
/usr/bin/git -C "${FIXTURE_REPOSITORY}" config user.name 'Hermetic Controller Test' || fail 'fixture Git name'
/usr/bin/git -C "${FIXTURE_REPOSITORY}" config user.email 'hermetic-controller@example.invalid' || fail 'fixture Git email'
printf 'history-root=%s\n' "${TEST_ROOT##*/}" >"${FIXTURE_REPOSITORY}/history-root.v1" ||
  fail 'fixture history root'
/usr/bin/git -C "${FIXTURE_REPOSITORY}" add -- history-root.v1 || fail 'fixture history root add'
/usr/bin/git -C "${FIXTURE_REPOSITORY}" commit -m 'Hermetic history root' || fail 'fixture history root commit'
/bin/mkdir -p -- "${FIXTURE_REVIEW}" "${FIXTURE_REALNIC}" || fail 'fixture review directory creation'
for name in \
  bind-final-package.sh controller.sh locked-transport.exp prepare-stage-root.sh \
  root-matrix-n-r.sh check-realhost-iperf.py test-hermetic-matrix.sh test_matrix_static.py \
  root-fresh-verifier-gate.sh test-hermetic-fresh-verifier-gate.sh \
  test_fresh_verifier_gate_static.py \
  checksum-module-lease.sh test-hermetic-checksum-module-lease.sh \
  test_checksum_module_lease_static.py test_provision_policy.tcl; do
  /bin/cp -- "${REVIEW_ROOT}/${name}" "${FIXTURE_REVIEW}/${name}" || fail "fixture copy ${name}"
done
for name in realnic_acceptance.py test_realnic_acceptance.py test_realnic_acceptance_static.py; do
  /bin/cp -- "${REALNIC_ROOT}/${name}" "${FIXTURE_REALNIC}/${name}" ||
    fail "fixture copy ${name}"
done
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
[[ "$(manifest_value format "${BOUND_MANIFEST}")" == 'wg-mix-ebpf-b82-v6-package-v3' &&
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

CONTROLLER_ARGS=(
  --manifest "${BOUND_MANIFEST}"
  --manifest-sha256 "${BOUND_MANIFEST_SHA}"
  --credential-path "${CREDENTIAL_PATH}"
)
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
  'B82_V6_REALNIC_APPROVAL_REQUIRED local_plan=explicit approved_plan_sha256=explicit automatic_approval=0' \
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

APPROVED_PLAN="${TEST_ROOT}/reviewed-realnic-plan.json"
printf '%s\n' '{"fixture":"explicitly-reviewed-realnic-plan"}' >"${APPROVED_PLAN}" ||
  fail 'approved plan fixture'
/bin/chmod 0600 "${APPROVED_PLAN}" || fail 'approved plan fixture mode'
APPROVED_PLAN_SHA="$(sha256_file "${APPROVED_PLAN}")" || fail 'approved plan fixture digest'
APPROVED_CONTROLLER_ARGS=(
  "${CONTROLLER_ARGS[@]}"
  --approved-plan "${APPROVED_PLAN}"
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
  --approved-plan none --approved-plan-sha256 none
expect_failure retired-matrix-run-transport /usr/bin/expect "${FIXTURE_REVIEW}/locked-transport.exp" \
  --manifest "${BOUND_MANIFEST}" --manifest-sha256 "${BOUND_MANIFEST_SHA}" \
  --credential-path "${CREDENTIAL_PATH}" --action plan --operation matrix-run \
  --approved-plan none --approved-plan-sha256 none
expect_failure retired-matrix-restore-transport /usr/bin/expect "${FIXTURE_REVIEW}/locked-transport.exp" \
  --manifest "${BOUND_MANIFEST}" --manifest-sha256 "${BOUND_MANIFEST_SHA}" \
  --credential-path "${CREDENTIAL_PATH}" --action plan --operation matrix-restore-tcx \
  --approved-plan none --approved-plan-sha256 none
expect_failure retired-matrix-controller-mode /bin/bash "${FIXTURE_REVIEW}/controller.sh" restore \
  "${CONTROLLER_ARGS[@]}" --restore-cell tcx
expect_failure credential-path-before-spawn /usr/bin/expect "${FIXTURE_REVIEW}/locked-transport.exp" \
  --manifest "${BOUND_MANIFEST}" --manifest-sha256 "${BOUND_MANIFEST_SHA}" \
  --credential-path /private/tmp/not-a-credential --action execute --operation identity-hostname \
  --approved-plan none --approved-plan-sha256 none
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
ABSENT_PLAN="$(/bin/bash "${FIXTURE_REVIEW}/controller.sh" plan "${ABSENT_CONTROLLER_ARGS[@]}")" ||
  fail 'absent controller plan'
[[ "${ABSENT_PLAN}" == *'B82_V6_LEGACY_MATRIX_RETIRED controller_entries=0 historical_recovery=frozen-original-package-before-final-staging'* ]] ||
  fail 'absent WireGuard legacy retirement marker missing'
[[ "${ABSENT_PLAN}" != *'operation=matrix-'* ]] || fail 'absent plan rendered legacy matrix execution'
for operation in fresh-plan fresh-run fresh-restore; do
  [[ "${ABSENT_PLAN}" == *"operation=${operation} transport=ssh credential_read=0 network_operations=0"* ]] ||
    fail "absent WireGuard plan cannot reach ${operation}"
done
[[ "${ABSENT_PLAN}" == *'operation=realnic-plan transport=ssh credential_read=0 network_operations=0'* ]] ||
  fail 'absent WireGuard plan cannot reach realnic-plan'
ABSENT_APPROVED_ARGS=(
  "${ABSENT_CONTROLLER_ARGS[@]}"
  --approved-plan "${APPROVED_PLAN}"
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
  --approved-plan none --approved-plan-sha256 none)" ||
  fail 'absent fresh transport plan'
[[ "${ABSENT_FRESH_TRANSPORT}" == *'credential_read=0 network_operations=0'* &&
  "${ABSENT_FRESH_TRANSPORT}" == *'root-fresh-verifier-gate.sh run --controller-source'* ]] ||
  fail 'absent fresh transport reachability'
expect_failure retired-matrix-run-mode /bin/bash "${FIXTURE_REVIEW}/controller.sh" run \
  "${ABSENT_CONTROLLER_ARGS[@]}"

printf '%s\n' \
  'hermetic v6 full-history binder, explicit toolchain state machine, root-owned bootstrap,' \
  'SSH/SCP/Expect fixed check/apply plans, provision output policy,' \
  'immutable-intake/shallow/failure paths and WireGuard-absent fresh/realNIC reachability: PASS'
printf 'RETAINED_HERMETIC_ROOT path=%s reason=auditable-no-cleanup-test-policy\n' "${TEST_ROOT}"
