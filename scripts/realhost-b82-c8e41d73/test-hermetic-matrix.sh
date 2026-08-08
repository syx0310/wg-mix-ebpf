#!/usr/bin/env bash
set -u
set -o pipefail
umask 077

readonly REVIEW_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
readonly MATRIX="${REVIEW_ROOT}/root-matrix-n-r.sh"
readonly CHECKER="${REVIEW_ROOT}/check-realhost-iperf.py"
readonly STATIC_TEST="${REVIEW_ROOT}/test_matrix_static.py"
readonly COMMIT_FIXTURE='77a15cfa34c10546a9a703596d9dee0deff91a48'
readonly BUNDLE_FIXTURE='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit "${2:-1}"
}

for path in "${MATRIX}" "${CHECKER}" "${STATIC_TEST}"; do
  [[ -f "${path}" && ! -L "${path}" ]] || fail "review input is not a regular file: ${path}"
done

/bin/bash -n "${MATRIX}" "$0" || fail 'bash syntax gate'
/usr/bin/python3 -I -m py_compile "${CHECKER}" "${STATIC_TEST}" || fail 'Python syntax gate'
/usr/bin/python3 -I "${STATIC_TEST}" "${MATRIX}" "${CHECKER}" || fail 'static safety contract'

if command -v shellcheck >/dev/null 2>&1; then
  shellcheck --norc --shell=bash -- "${MATRIX}" "$0" || fail 'ShellCheck gate'
else
  printf 'SKIP: shellcheck unavailable; the .82 unprivileged U gate must run it before sudo\n'
fi

plan_output="$(${MATRIX} plan \
  --source /run/wg-mix-ebpf-source-stages/c8e41d73/source \
  --commit "${COMMIT_FIXTURE}" \
  --bundle /home/siyixuan/wg-mix-ebpf-test/unpriv-4f2a9b61/source-4f2a9b61.bundle \
  --bundle-sha256 "${BUNDLE_FIXTURE}" \
  --interface ens33 --peer-address 47.116.202.155 --peer-port 5201 \
  --soak-seconds 3600 --session-seconds 300 \
  --wg-interface wg0 --wg-local-address 10.200.0.1 \
  --wg-peer-address 10.200.0.2 --restore-cell none)" || fail 'plan-mode expansion'

[[ "${plan_output}" == *'REALHOST_V6_PLAN_ONLY run_id=c8e41d73'* ]] || fail 'plan header missing'
[[ "${plan_output}" == *'WG_MIX_EBPF_RUN_BPFFS_INTEGRATION=1'* ]] || fail 'exact TCX plan missing'
for selector in public-key listen-port fwmark peers endpoints allowed-ips latest-handshakes transfer; do
  [[ "${plan_output}" == *"/usr/bin/wg show wg0 ${selector}"* ]] ||
    fail "exact-interface WireGuard plan missing selector: ${selector}"
done
[[ "${plan_output}" != *'/usr/bin/wg show all '* ]] ||
  fail 'all-interface WireGuard plan was rendered'
[[ "${plan_output}" == *'TestExperimentalFakeTCPRealHostLifecycleIntegration'* ]] || fail 'FakeTCP runtime plan missing'
[[ "${plan_output}" == *'TestFakeTCPRealHostXORTypewordHeaderCompositionIntegration'* ]] || fail 'composition plan missing'
[[ "${plan_output}" == *'TestBaselineExperimentalRealHostMutualExclusionIntegration'* ]] || fail 'mutual exclusion plan missing'
[[ "${plan_output}" == *'R-scoped-soak windows=12 session_seconds=300 total_seconds=3600'* ]] ||
  fail 'bounded soak window plan missing'
[[ "${plan_output}" == *'no_commands_executed=1'* ]] || fail 'plan completion fence missing'

if "${MATRIX}" plan \
  --source /run/wg-mix-ebpf-source-stages/c8e41d73/source \
  --commit c8e41d73 \
  --bundle /home/siyixuan/wg-mix-ebpf-test/unpriv-4f2a9b61/source-4f2a9b61.bundle \
  --bundle-sha256 "${BUNDLE_FIXTURE}" \
  --interface ens33 --peer-address 47.116.202.155 --peer-port 5201 \
  --soak-seconds 3600 --session-seconds 300 \
  --wg-interface wg0 --wg-local-address 10.200.0.1 \
  --wg-peer-address 10.200.0.2 --restore-cell none >/dev/stdout 2>/dev/stderr; then
  fail 'short run ID was accepted as a source commit'
fi

if "${MATRIX}" plan \
  --source /run/wg-mix-ebpf-source-stages/c8e41d73/source \
  --commit "${COMMIT_FIXTURE}" \
  --bundle /home/siyixuan/wg-mix-ebpf-test/unpriv-4f2a9b61/source-4f2a9b61.bundle \
  --bundle-sha256 FINAL_BUNDLE_SHA256_REQUIRED \
  --interface ens33 --peer-address 47.116.202.155 --peer-port 5201 \
  --soak-seconds 3600 --session-seconds 300 \
  --wg-interface wg0 --wg-local-address 10.200.0.1 \
  --wg-peer-address 10.200.0.2 --restore-cell none >/dev/stdout 2>/dev/stderr; then
  fail 'bundle placeholder was accepted'
fi

printf 'hermetic matrix argv and failure-path tests: PASS\n'
