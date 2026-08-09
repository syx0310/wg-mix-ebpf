#!/usr/bin/env bash
set -u
set -o pipefail
umask 077

SCRIPT="${1:-}"
HELPER="${2:-}"
STATIC_TEST="${3:-}"
MANIFEST_FIXTURE="${4:-}"
[[ ($# == 3 || $# == 4) &&
  "${SCRIPT}" == /* && -f "${SCRIPT}" && ! -L "${SCRIPT}" &&
  "${HELPER}" == /* && -f "${HELPER}" && ! -L "${HELPER}" &&
  "${STATIC_TEST}" == /* && -f "${STATIC_TEST}" && ! -L "${STATIC_TEST}" ]] || {
  printf 'usage: %s ABSOLUTE_ROOT_FRESH_VERIFIER_GATE ABSOLUTE_MODULE_LEASE_HELPER ABSOLUTE_STATIC_TEST [ABSOLUTE_PACKAGE_MANIFEST]\n' "$0" >&2
  exit 64
}
if [[ -n "${MANIFEST_FIXTURE}" &&
  ("${MANIFEST_FIXTURE}" != /* || ! -f "${MANIFEST_FIXTURE}" ||
    -L "${MANIFEST_FIXTURE}") ]]; then
  printf 'fresh verifier hermetic test failed: optional manifest must be an absolute regular non-symlink file\n' >&2
  exit 64
fi
/bin/bash -n "${SCRIPT}" "${HELPER}" || exit $?
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -B -I "${STATIC_TEST}" "${SCRIPT}" "${HELPER}" ||
  exit $?

FIXTURE="$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/wg-mix-fresh-verifier-plan.XXXXXXXX")" || exit $?
OUTPUT="${FIXTURE}/plan.out"
COMMIT='1111111111111111111111111111111111111111'
MANIFEST_SHA='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
BUNDLE_SHA='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
CONTROLLER_SOURCE='/run/wg-mix-ebpf-source-stages/c8e41d73/source'
MANIFEST='/run/wg-mix-ebpf-source-bootstrap-c8e41d73/package-manifest.v1'
BUNDLE='/run/wg-mix-ebpf-source-bootstrap-c8e41d73/source-4f2a9b61.bundle'

fail() {
  printf 'fresh verifier hermetic test failed: %s; retained=%s\n' "$1" "${FIXTURE}" >&2
  exit 1
}

MANIFEST_KEYS="${FIXTURE}/manifest.keys"
SYNTHETIC_MANIFEST="${FIXTURE}/package-manifest.v1"
TESTABLE_READER="${FIXTURE}/root-fresh-verifier-gate.reader-test.sh"
TAIL_NEWLINE="${FIXTURE}/package-manifest.trailing-newline.v1"
TAIL_NO_NEWLINE="${FIXTURE}/package-manifest.trailing-no-newline.v1"
REORDERED_MANIFEST="${FIXTURE}/package-manifest.reordered.v1"

/usr/bin/awk '
  /^load_manifest_once\(\) \{/ { in_loader = 1; next }
  in_loader && /^}/ { exit }
  in_loader && $1 == "read_manifest_field" { print $2 }
' "${SCRIPT}" >"${MANIFEST_KEYS}" || fail 'extract production manifest keys'
[[ "$(/usr/bin/wc -l <"${MANIFEST_KEYS}" | /usr/bin/tr -d ' ')" == 103 &&
  "$(LC_ALL=C /usr/bin/sort -- "${MANIFEST_KEYS}" | /usr/bin/uniq | /usr/bin/wc -l |
    /usr/bin/tr -d ' ')" == 103 ]] ||
  fail 'production manifest reader is not exactly 103 unique keys'

while IFS= read -r key; do
  [[ -n "${key}" ]] || fail 'empty manifest key extracted'
  if [[ "${key}" == format ]]; then
    value='wg-mix-ebpf-b82-v6-package-v4'
  else
    value="fixture-${key}"
  fi
  printf '%s\t%s\n' "${key}" "${value}"
done <"${MANIFEST_KEYS}" >"${SYNTHETIC_MANIFEST}" || fail 'create package-v4 fixture'

PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -B -I "${STATIC_TEST}" \
  "${SCRIPT}" "${HELPER}" "${SYNTHETIC_MANIFEST}" ||
  fail 'package-v4 fixture does not match the static 103-key schema'
if [[ -n "${MANIFEST_FIXTURE}" ]]; then
  PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -B -I "${STATIC_TEST}" \
    "${SCRIPT}" "${HELPER}" "${MANIFEST_FIXTURE}" ||
    fail 'provided package manifest does not match the package-v4 103-key schema'
fi

/usr/bin/awk '
  /^load_manifest_once\(\) \{/ { in_loader = 1 }
  $0 == "readonly SNAPSHOT_MANIFEST=\"${INTAKE_ROOT}/package-manifest.v1\"" {
    print "readonly SNAPSHOT_MANIFEST=\"${FRESH_TEST_MANIFEST}\""
    replacements++
    next
  }
  in_loader && $0 == "  exec {MANIFEST_FD}<\"${SNAPSHOT_MANIFEST}\" || return 66" {
    print "  MANIFEST_FD=9"
    print "  exec 9<\"${SNAPSHOT_MANIFEST}\" || return 66"
    reader_opens++
    next
  }
  in_loader && /exec \{MANIFEST_FD\}<\&-/ {
    gsub(/exec \{MANIFEST_FD\}<\&-/, "exec 9<\\&-")
    reader_closes++
  }
  { print }
  in_loader && /^}/ { in_loader = 0 }
  END {
    if (replacements != 1 || reader_opens != 1 || reader_closes != 3) exit 65
  }
' "${SCRIPT}" >"${TESTABLE_READER}" || fail 'prepare isolated manifest reader'
/bin/chmod 0700 "${TESTABLE_READER}" || fail 'mode isolated manifest reader'

run_manifest_reader() {
  local manifest="$1" expected_rc="$2" label="$3" rc
  FRESH_TEST_MANIFEST="${manifest}" /bin/bash -c '
    source "$1" || exit $?
    load_manifest_once
    rc=$?
    if ((rc == 0)); then
      [[ "${FORMAT}" == "wg-mix-ebpf-b82-v6-package-v4" ]] || exit 79
    fi
    exit "${rc}"
  ' fresh-manifest-reader "${TESTABLE_READER}"
  rc=$?
  [[ "${rc}" == "${expected_rc}" ]] ||
    fail "${label}: expected rc=${expected_rc}, observed rc=${rc}"
}

run_manifest_reader "${SYNTHETIC_MANIFEST}" 0 'valid package-v4 manifest'
/bin/cp -- "${SYNTHETIC_MANIFEST}" "${TAIL_NEWLINE}" || fail 'copy newline-tail fixture'
printf 'unexpected_tail\tfixture-extra\n' >>"${TAIL_NEWLINE}" ||
  fail 'append newline-tail fixture'
run_manifest_reader "${TAIL_NEWLINE}" 65 '104th newline-terminated record'
/bin/cp -- "${SYNTHETIC_MANIFEST}" "${TAIL_NO_NEWLINE}" ||
  fail 'copy unterminated-tail fixture'
printf 'unexpected_tail\tfixture-extra' >>"${TAIL_NO_NEWLINE}" ||
  fail 'append unterminated-tail fixture'
run_manifest_reader "${TAIL_NO_NEWLINE}" 65 '104th unterminated record'
/usr/bin/awk '
  NR == 1 { first = $0; next }
  NR == 2 { print; print first; next }
  { print }
' "${SYNTHETIC_MANIFEST}" >"${REORDERED_MANIFEST}" || fail 'create reordered fixture'
run_manifest_reader "${REORDERED_MANIFEST}" 65 'reordered manifest keys'
if [[ -n "${MANIFEST_FIXTURE}" ]]; then
  run_manifest_reader "${MANIFEST_FIXTURE}" 0 'provided package-v4 manifest'
fi

run_plan() {
  /bin/bash "${SCRIPT}" plan \
    --controller-source "${CONTROLLER_SOURCE}" \
    --commit "${COMMIT}" \
    --manifest "${MANIFEST}" --manifest-sha256 "${MANIFEST_SHA}" \
    --bundle "${BUNDLE}" --bundle-sha256 "${BUNDLE_SHA}"
}

run_plan >"${OUTPUT}" || fail 'plan returned nonzero'
PLAN="$(/bin/cat -- "${OUTPUT}")" || fail 'read plan'

for expected in \
  'B82_FRESH_VERIFIER_PLAN_ONLY gate_id=fresh-c8e41d73' \
  'operation=fresh-stage-create' \
  'operation=intake-create' \
  'operation=held-fd-noclobber-copy' \
  'snapshot_manifest=/run/wg-mix-ebpf-faketcp-verifier/fresh-c8e41d73/package/package-manifest.v1' \
  'snapshot_bundle=/run/wg-mix-ebpf-faketcp-verifier/fresh-c8e41d73/package/source-4f2a9b61.bundle' \
  'operation=source-clone' \
  'operation=source-shallow' \
  'operation=history-count' \
  'operation=history-roots' \
  'operation=history-objects' \
  'operation=history-fsck' \
  'rev-list --parents --objects --missing=print' \
  'fsck --full --strict --no-dangling' \
  'operation=cache-mkdir' \
  'operation=mod-cache-mkdir' \
  'operation=go-path-mkdir' \
  'operation=go-tmp-mkdir' \
  'operation=go-home-mkdir' \
  'operation=xdg-cache-mkdir' \
  'operation=xdg-config-mkdir' \
  'GOCACHE=/run/wg-mix-ebpf-faketcp-verifier/fresh-c8e41d73/go-cache' \
  'GOMODCACHE=/run/wg-mix-ebpf-faketcp-verifier/fresh-c8e41d73/go-mod-cache' \
  'GOTELEMETRY=off' \
  'build-faketcp-checksum-kmod' \
  'build-faketcp-verifier-launcher-linux-amd64' \
  'test-bpf-object-manifests' \
  'operation=verifier' \
  'run-faketcp-verifier-only.py' \
  'operation=packet-test-run' \
  'TestFakeTCPBPFPacketProbe' \
  'L0 operation=shared-module-lock target=/run/wg-mix-ebpf-source-stages/c8e41d73/checksum-module-lease.v1.lock' \
  'M.load operation=shared-module-load target=wg_mix_faketcp_checksum helper=c8_checksum_module_load' \
  'lease_id=c8e41d73-f3e5c8a1' \
  'EXPLICIT_RESTORE_ONLY.R.lease operation=shared-module-lock' \
  'EXPLICIT_RESTORE_ONLY.R.module operation=shared-module-restore' \
  'EXPLICIT_RESTORE_ONLY.R.kwarn operation=snapshot-kernel-warnings' \
  'helper=c8_checksum_module_restore' \
  'transient_bpf=unpinned' \
  'automatic_cleanup=0' \
  'network_state_mutations=0 dependency_fetch=proxy-only' \
  'credential_read=0 network_state_mutations=0 capability_bits_changed=0'; do
  [[ "${PLAN}" == *"${expected}"* ]] || fail "plan missing ${expected}"
done

[[ "$(/usr/bin/grep -c 'operation=shared-module-load' "${OUTPUT}")" == 1 &&
  "$(/usr/bin/grep -c 'operation=shared-module-restore' "${OUTPUT}")" == 1 ]] ||
  fail 'shared helper module operations are not singular'
[[ "${PLAN}" != *'EXPLICIT_RESTORE_ONLY.R.pre-kwarn'* &&
  "$(/usr/bin/grep -c 'EXPLICIT_RESTORE_ONLY.R.kwarn operation=snapshot-kernel-warnings' \
    "${OUTPUT}")" == 1 ]] || fail 'restore warning plan does not match R.final'
[[ "${PLAN}" != *'rm -rf'* && "${PLAN}" != *'find -delete'* &&
  "${PLAN}" != *'chroot'* && "${PLAN}" != *'nsenter'* &&
  "${PLAN}" != *'/usr/sbin/ip '* && "${PLAN}" != *'/usr/sbin/tc '* ]] ||
  fail 'plan contains an out-of-scope destructive or network operation'
[[ "$(/usr/bin/grep -c 'held-fd-noclobber-copy' "${OUTPUT}")" == 2 ]] ||
  fail 'plan does not snapshot exactly one manifest and bundle held descriptor'

if /bin/bash "${SCRIPT}" run \
  --controller-source "${CONTROLLER_SOURCE}" \
  --commit "${COMMIT}" \
  --manifest "${MANIFEST}" --manifest-sha256 "${MANIFEST_SHA}" \
  --bundle "${BUNDLE}" --bundle-sha256 "${BUNDLE_SHA}" extra >"${FIXTURE}/extra.out" 2>&1; then
  fail 'extra argument was accepted'
fi
if /bin/bash "${SCRIPT}" plan \
  --controller-source /tmp/unreviewed-source \
  --commit "${COMMIT}" \
  --manifest "${MANIFEST}" --manifest-sha256 "${MANIFEST_SHA}" \
  --bundle "${BUNDLE}" --bundle-sha256 "${BUNDLE_SHA}" >"${FIXTURE}/path.out" 2>&1; then
  fail 'unreviewed controller source was accepted'
fi
if /bin/bash "${SCRIPT}" plan \
  --commit "${COMMIT}" \
  --controller-source "${CONTROLLER_SOURCE}" \
  --manifest "${MANIFEST}" --manifest-sha256 "${MANIFEST_SHA}" \
  --bundle "${BUNDLE}" --bundle-sha256 "${BUNDLE_SHA}" >"${FIXTURE}/order.out" 2>&1; then
  fail 'reordered authority arguments were accepted'
fi

printf 'fresh verifier hermetic plan and exact package-v4 manifest test passed; retained=%s\n' \
  "${FIXTURE}"
