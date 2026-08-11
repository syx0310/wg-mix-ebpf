#!/usr/bin/env bash
set -u
set -o pipefail
umask 077

HELPER="${1:-}"
STATIC_TEST="${2:-}"
MODULE_SOURCE="${3:-}"
readonly HELPER STATIC_TEST MODULE_SOURCE

if (($# != 3)) || [[ "${HELPER}" != /* || "${STATIC_TEST}" != /* ||
  "${MODULE_SOURCE}" != /* ]]; then
  printf 'usage: %s ABSOLUTE_MODULE_LEASE_HELPER ABSOLUTE_STATIC_TEST ABSOLUTE_MODULE_SOURCE\n' \
    "$0" >&2
  exit 64
fi

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit "${2:-1}"
}

for path in "${HELPER}" "${STATIC_TEST}" "${MODULE_SOURCE}"; do
  [[ -f "${path}" && ! -L "${path}" ]] || fail "fixture is not a regular file: ${path}"
done
/bin/bash -n "${HELPER}" "$0" || fail 'Bash syntax gate'
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -I "${STATIC_TEST}" "${HELPER}" "${MODULE_SOURCE}" ||
  fail 'static helper and module ABI gate'
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck --norc --shell=bash -- "${HELPER}" "$0" || fail 'ShellCheck gate'
else
  printf 'SKIP: shellcheck unavailable locally; .82 execution remains shellcheck-gated\n'
fi

# The classifier is production code but pure: execute every accepted state and
# representative invalid/foreign combinations without touching a real module.
# The fixed HELPER path is shape-checked before this test-only dynamic source.
# shellcheck disable=SC1090,SC1091
source "${HELPER}"
for spec in \
  "${C8_CHECKSUM_MODULE_CENTRAL_OBJECT}|${C8_CHECKSUM_MODULE_STAGE_ROOT}/realhost-v6-${C8_CHECKSUM_MODULE_CENTRAL_RESOURCE_ID}|${C8_CHECKSUM_MODULE_CENTRAL_RESOURCE_ID}" \
  "${C8_CHECKSUM_MODULE_CENTRAL_OBJECT}|${C8_CHECKSUM_MODULE_STAGE_ROOT}/routed-evidence-${C8_CHECKSUM_MODULE_ROUTED_RESOURCE_ID}|${C8_CHECKSUM_MODULE_ROUTED_RESOURCE_ID}" \
  "${C8_CHECKSUM_MODULE_STANDALONE_OBJECT}|${C8_CHECKSUM_MODULE_STANDALONE_EVIDENCE}|${C8_CHECKSUM_MODULE_STANDALONE_RESOURCE_ID}" \
  "${C8_CHECKSUM_MODULE_FRESH_OBJECT}|${C8_CHECKSUM_MODULE_FRESH_EVIDENCE}|${C8_CHECKSUM_MODULE_FRESH_RESOURCE_ID}"; do
  IFS='|' read -r object evidence resource <<<"${spec}"
  c8_checksum_module_scope_allowed "${object}" "${evidence}" "${resource}" ||
    fail "scope rejected exact tuple: ${resource}"
done
for spec in \
  "${C8_CHECKSUM_MODULE_STANDALONE_OBJECT}|${C8_CHECKSUM_MODULE_STANDALONE_EVIDENCE}|${C8_CHECKSUM_MODULE_ROUTED_RESOURCE_ID}" \
  "${C8_CHECKSUM_MODULE_STANDALONE_OBJECT}|${C8_CHECKSUM_MODULE_FRESH_EVIDENCE}|${C8_CHECKSUM_MODULE_STANDALONE_RESOURCE_ID}" \
  "${C8_CHECKSUM_MODULE_CENTRAL_OBJECT}|${C8_CHECKSUM_MODULE_STANDALONE_EVIDENCE}|${C8_CHECKSUM_MODULE_STANDALONE_RESOURCE_ID}"; do
  IFS='|' read -r object evidence resource <<<"${spec}"
  if c8_checksum_module_scope_allowed "${object}" "${evidence}" "${resource}"; then
    fail "scope accepted crossed tuple: ${resource}"
  fi
done
for spec in \
  '0 0 0 0|00-clean' \
  '1 0 0 0|00-intent-no-live' \
  '1 0 0 1|10-unreceipted-live' \
  '1 1 0 1|11-owned-live' \
  '1 1 0 0|01-owned-live-absent' \
  '1 0 1 0|00-restored' \
  '1 1 1 0|00-restored'; do
  IFS='|' read -r argv expected <<<"${spec}"
  # Deliberately split the fixed numeric fixture into the four function args.
  # shellcheck disable=SC2086
  actual="$(c8_checksum_module_classify ${argv})" || fail "classifier rejected ${argv}"
  [[ "${actual}" == "${expected}" ]] || fail "classifier ${argv}: ${actual}, want ${expected}"
done
if c8_checksum_module_classify 0 0 0 1 >/dev/stdout 2>&1; then
  fail 'classifier accepted a live module without helper intent'
fi
if c8_checksum_module_classify 1 0 1 1 >/dev/stdout 2>&1; then
  fail 'classifier accepted a live module after unloaded receipt'
fi
if /bin/bash "${HELPER}" >/dev/stdout 2>&1; then
  fail 'source-only helper executed as a command'
fi

printf 'hermetic shared checksum-module exact scopes, ABI and failure-cut classifier: PASS\n'
