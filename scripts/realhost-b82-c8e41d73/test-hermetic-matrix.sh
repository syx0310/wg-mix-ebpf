#!/usr/bin/env bash
set -u
set -o pipefail
umask 077

readonly REVIEW_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
readonly MATRIX="${REVIEW_ROOT}/root-matrix-n-r.sh"
readonly CHECKER="${REVIEW_ROOT}/check-realhost-iperf.py"
readonly STATIC_TEST="${REVIEW_ROOT}/test_matrix_static.py"
readonly MODULE_LEASE_HELPER="${REVIEW_ROOT}/checksum-module-lease.sh"
readonly MODULE_LEASE_HERMETIC="${REVIEW_ROOT}/test-hermetic-checksum-module-lease.sh"
readonly COMMIT_FIXTURE='77a15cfa34c10546a9a703596d9dee0deff91a48'
readonly BUNDLE_FIXTURE='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit "${2:-1}"
}

for path in "${MATRIX}" "${CHECKER}" "${STATIC_TEST}" \
  "${MODULE_LEASE_HELPER}" "${MODULE_LEASE_HERMETIC}"; do
  [[ -f "${path}" && ! -L "${path}" ]] || fail "review input is not a regular file: ${path}"
done

/bin/bash -n "${MATRIX}" "${MODULE_LEASE_HELPER}" \
  "${MODULE_LEASE_HERMETIC}" "$0" || fail 'bash syntax gate'
/usr/bin/python3 -B -I "${STATIC_TEST}" "${MATRIX}" "${CHECKER}" || fail 'static safety contract'
/bin/bash "${MODULE_LEASE_HERMETIC}" || fail 'shared checksum-module lease contract'

if command -v shellcheck >/dev/null 2>&1; then
  shellcheck --norc --shell=bash -- "${MATRIX}" "${MODULE_LEASE_HELPER}" \
    "${MODULE_LEASE_HERMETIC}" "$0" || fail 'ShellCheck gate'
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
[[ "${plan_output}" == *'B0 argv=/usr/bin/mkdir --mode=0700 -- /run/wg-mix-ebpf-source-stages/c8e41d73/realhost-v6-6bd913ac'* ]] ||
  fail 'bootstrap evidence creation audit plan missing'
[[ "${plan_output}" == *'B1 argv=shell-builtin noclobber-create-and-persist-bootstrap-audit'* ]] ||
  fail 'bootstrap audit-file creation plan missing'
[[ "${plan_output}" == *'REALHOST_V6_MODULE_LEASE helper=/run/wg-mix-ebpf-source-stages/c8e41d73/source/scripts/realhost-b82-c8e41d73/checksum-module-lease.sh lock=/run/wg-mix-ebpf-source-stages/c8e41d73/checksum-module-lease.v1.lock lease_id=c8e41d73-6bd913ac receipt=insmod-rc0-only generation=sysfs,parameter,srcversion,btf'* ]] ||
  fail 'shared module lease plan missing'
[[ "${plan_output}" == *'L0 argv=/usr/bin/flock --exclusive --nonblock MODULE_LEASE_FD'* ]] ||
  fail 'shared module lock argv missing'
[[ "${plan_output}" == *'O2 argv=/usr/sbin/insmod /run/wg-mix-ebpf-source-stages/c8e41d73/source/build/faketcp_checksum_kmod/wg_mix_faketcp_checksum.ko lease_id=c8e41d73-6bd913ac'* ]] ||
  fail 'managed module load token missing'
[[ "${plan_output}" == *'R-full-offload-compare argv=/usr/bin/cmp -s'* ]] ||
  fail 'complete offload restore comparison plan missing'
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

if "${MATRIX}" plan \
  --source /run/wg-mix-ebpf-source-stages/c8e41d73/source \
  --commit "${COMMIT_FIXTURE}" \
  --bundle /home/siyixuan/wg-mix-ebpf-test/unpriv-4f2a9b61/source-4f2a9b61.bundle \
  --bundle-sha256 "${BUNDLE_FIXTURE}" \
  --interface ens33 --peer-address 47.116.202.155 --peer-port 5201 \
  --soak-seconds 3600 --session-seconds 300 \
  --wg-interface . --wg-local-address 10.200.0.1 \
  --wg-peer-address 10.200.0.2 --restore-cell none >/dev/stdout 2>/dev/stderr; then
  fail 'invalid dot WireGuard interface was accepted'
fi

if "${MATRIX}" plan \
  --source /run/wg-mix-ebpf-source-stages/c8e41d73/source \
  --commit "${COMMIT_FIXTURE}" \
  --bundle /home/siyixuan/wg-mix-ebpf-test/unpriv-4f2a9b61/source-4f2a9b61.bundle \
  --bundle-sha256 "${BUNDLE_FIXTURE}" \
  --interface ens33 --peer-address 47.116.202.155 --peer-port 5201 \
  --soak-seconds 3600 --session-seconds 300 \
  --wg-interface wg0 --wg-local-address 999.999.999.999 \
  --wg-peer-address 10.200.0.2 --restore-cell none >/dev/stdout 2>/dev/stderr; then
  fail 'out-of-range WireGuard IPv4 address was accepted'
fi

printf 'hermetic matrix argv and failure-path tests: PASS\n'
