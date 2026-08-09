#!/usr/bin/env bash
set -u
set -o pipefail
umask 077

SCRIPT="${1:-}"
HELPER="${2:-}"
[[ "${SCRIPT}" == /* && -f "${SCRIPT}" && ! -L "${SCRIPT}" &&
  "${HELPER}" == /* && -f "${HELPER}" && ! -L "${HELPER}" ]] || {
  printf 'usage: %s ABSOLUTE_ROOT_FRESH_VERIFIER_GATE ABSOLUTE_MODULE_LEASE_HELPER\n' "$0" >&2
  exit 64
}
/bin/bash -n "${SCRIPT}" "${HELPER}" || exit $?

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

printf 'fresh verifier hermetic plan test passed; retained=%s\n' "${FIXTURE}"
