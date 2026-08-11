#!/bin/bash

set -euo pipefail

readonly PATH='/usr/local/go/bin:/usr/bin:/bin'
readonly LC_ALL='C'
readonly STAGE_PREFIX='/var/tmp/wg-mix-ci-test'

export PATH LC_ALL
umask 077

usage() {
  printf '%s\n' \
    'usage: run-b82-ci-validation.sh --run-id <12hex> --commit <40hex>' >&2
  exit 64
}

run_id=''
commit=''
while (($#)); do
  (($# >= 2)) || usage
  case "$1" in
    --run-id) run_id="$2" ;;
    --commit) commit="$2" ;;
    *) usage ;;
  esac
  shift 2
done

[[ "${run_id}" =~ ^[0-9a-f]{12}$ ]] || usage
[[ "${commit}" =~ ^[0-9a-f]{40}$ ]] || usage
[[ "${EUID}" -ne 0 && "$(/usr/bin/id -un)" == 'siyixuan' ]] || {
  printf 'error: CI validation must run as the unprivileged test user\n' >&2
  exit 77
}

readonly stage="${STAGE_PREFIX}-${run_id}"
readonly source="${stage}/source"
readonly runtime="${stage}/go-tmp"
readonly log="${runtime}/ci-validation.log"
readonly result="${runtime}/ci-validation.result"
readonly result_pending="${runtime}/.ci-validation.result.pending"
readonly lock_dir="${runtime}/ci-validation.lock"

[[ -d "${stage}" && ! -L "${stage}" &&
  "$(/usr/bin/readlink -e -- "${stage}")" == "${stage}" &&
  "$(/usr/bin/stat -Lc '%U:%G:%a:%F' -- "${stage}")" == \
    'siyixuan:siyixuan:700:directory' ]] || {
  printf 'error: CI validation stage is not a canonical owned directory\n' >&2
  exit 66
}
for directory in source go-cache go-mod-cache go-path go-tmp; do
  path="${stage}/${directory}"
  [[ -d "${path}" && ! -L "${path}" &&
    "$(/usr/bin/stat -Lc '%U:%G:%a:%F' -- "${path}")" == \
      'siyixuan:siyixuan:700:directory' ]] || {
    printf 'error: CI validation directory is invalid: %s\n' "${path}" >&2
    exit 66
  }
done
[[ "$(/usr/bin/git -C "${source}" rev-parse 'HEAD^{commit}')" == "${commit}" ]] || {
  printf 'error: CI validation source commit drifted\n' >&2
  exit 66
}
readonly stage_device="$(/usr/bin/stat -c '%d' -- "${stage}")"
[[ -z "$(/usr/bin/find "${source}" -xdev \
  \( ! -user siyixuan -o ! -group siyixuan \) -print -quit)" &&
  -z "$(/usr/bin/find "${source}" -xdev -type d \
    -exec /usr/bin/stat -c '%d' -- '{}' + |
    /usr/bin/grep -Fvx "${stage_device}" | /usr/bin/head -n 1)" ]] || {
  printf 'error: CI validation source ownership or filesystem drifted\n' >&2
  exit 66
}
[[ ! -e "${log}" && ! -L "${log}" &&
  ! -e "${result}" && ! -L "${result}" &&
  ! -e "${result_pending}" && ! -L "${result_pending}" ]] || {
  printf 'error: CI validation evidence already exists\n' >&2
  exit 73
}
/usr/bin/mkdir --mode=0700 -- "${lock_dir}"
exec 9>"${lock_dir}/runner.lock"
/usr/bin/flock --exclusive --nonblock 9 || {
  printf 'error: CI validation runner is already active\n' >&2
  exit 73
}
/usr/bin/find "${source}" -xdev -type d \
  -exec /usr/bin/chmod go-w -- '{}' +
/usr/bin/find "${source}" -xdev -type f \
  -exec /usr/bin/chmod go-w -- '{}' +

readonly gocache="${stage}/go-cache"
readonly gomodcache="${stage}/go-mod-cache"
readonly gopath="${stage}/go-path"
readonly gotmp="${stage}/go-tmp"
/usr/bin/mkdir --mode=0700 -- "${runtime}/home"
readonly home="${runtime}/home"
export HOME="${home}"
export GOCACHE="${gocache}"
export GOMODCACHE="${gomodcache}"
export GOPATH="${gopath}"
export GOTMPDIR="${gotmp}"
export TMPDIR="${gotmp}"
export GOENV=off
export GOWORK=off
export GOFLAGS=''
export GO111MODULE=on
export PYTHONDONTWRITEBYTECODE=1

/usr/bin/touch -- "${log}"
/usr/bin/chmod 0600 -- "${log}"

gate_results=()
overall_rc=0

timestamp() {
  /usr/bin/date --iso-8601=seconds
}

render_argv() {
  local argument
  for argument in "$@"; do
    printf ' %q' "${argument}"
  done
}

run_gate() {
  local label="$1"
  shift
  local started finished rc tee_rc
  local -a pipeline_status
  started="$(timestamp)"
  {
    printf 'B82_CI_GATE_BEGIN label=%s timestamp=%s argv=' "${label}" "${started}"
    render_argv "$@"
    printf '\n'
  } >>"${log}"
  set +e
  "$@" 2>&1 | /usr/bin/tee -a "${log}" >/dev/null
  pipeline_status=("${PIPESTATUS[@]}")
  rc="${pipeline_status[0]}"
  tee_rc="${pipeline_status[1]}"
  set -e
  if ((tee_rc != 0)); then
    printf 'error: CI validation evidence write failed: label=%s tee_rc=%d\n' \
      "${label}" "${tee_rc}" >&2
    exit 74
  fi
  finished="$(timestamp)"
  printf 'B82_CI_GATE_END label=%s timestamp=%s rc=%d\n' \
    "${label}" "${finished}" "${rc}" >>"${log}"
  gate_results+=("${label}:${rc}")
  if ((rc != 0)); then
    overall_rc=1
  fi
}

validate_identity() {
  local binary="${source}/bin/wg-mix-ebpf-linux-amd64"
  local identity_json="${runtime}/wg-mix-ebpf-version.json"
  "${binary}" version --json >"${identity_json}"
  /usr/bin/python3 -I -S - "${identity_json}" "${source}" "${commit}" <<'PY'
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

identity_path = Path(sys.argv[1])
source = Path(sys.argv[2])
commit = sys.argv[3]
identity = json.loads(identity_path.read_text())
head = subprocess.check_output(
    ["/usr/bin/git", "-C", str(source), "rev-parse", "HEAD"],
    text=True,
).strip()
embedded = hashlib.sha256(
    (source / "internal/dataplane/embedded/wg_mix_tc.o").read_bytes()
).hexdigest()
if head != commit:
    raise SystemExit(f"source HEAD {head} != frozen commit {commit}")
if identity["source_commit"] != commit:
    raise SystemExit(
        f"binary source commit {identity['source_commit']} != frozen commit {commit}"
    )
if identity["embedded_bpf_object_sha256"] != embedded:
    raise SystemExit("embedded BPF object SHA-256 mismatch")
if not re.fullmatch(r"[0-9a-f]{64}", embedded):
    raise SystemExit(f"invalid BPF SHA-256 {embedded}")
print(
    "B82_CI_IDENTITY_PASS "
    f"commit={commit} embedded_bpf_object_sha256={embedded}"
)
PY
}

dump_abi() {
  (
    cd "${source}"
    "${source}/bin/wg-mix-ebpf-linux-amd64" dump-abi \
      --config configs/example.yaml --offline \
      >"${runtime}/wg-mix-ebpf-abi.json"
  )
}

offline_validate() {
  (
    cd "${source}"
    "${source}/bin/wg-mix-ebpf-linux-amd64" validate \
      --config configs/example.yaml --offline
  )
}

package_artifact() {
  local package_root="${runtime}/package"
  local package_dir="${package_root}/wg-mix-ebpf_linux_amd64"
  local archive="${package_root}/wg-mix-ebpf_linux_amd64.tar.gz"
  /usr/bin/mkdir --mode=0700 -- "${package_root}" "${package_dir}"
  /usr/bin/install -m 0700 -- \
    "${source}/bin/wg-mix-ebpf-linux-amd64" "${package_dir}/wg-mix-ebpf"
  /usr/bin/install -m 0600 -- "${source}/README.md" "${package_dir}/README.md"
  /usr/bin/cp -R -- "${source}/configs" "${package_dir}/configs"
  /usr/bin/tar -C "${package_root}" -czf "${archive}" wg-mix-ebpf_linux_amd64
  /usr/bin/sha256sum -- "${archive}"
}

printf 'B82_CI_VALIDATION_BEGIN run_id=%s commit=%s timestamp=%s\n' \
  "${run_id}" "${commit}" "$(timestamp)" >>"${log}"
run_gate diff-check /usr/bin/git -C "${source}" diff --check HEAD
run_gate bpf-manifests /usr/bin/env CGO_ENABLED=0 \
  /usr/bin/make -C "${source}" test-bpf-object-manifests
run_gate unit /usr/bin/env CGO_ENABLED=0 \
  /usr/bin/make -C "${source}" test-unit
run_gate lint /usr/bin/env CGO_ENABLED=0 \
  /usr/bin/make -C "${source}" test-lint
run_gate race /usr/bin/env CGO_ENABLED=1 \
  /usr/bin/make -C "${source}" test-unit-race
run_gate build-amd64 /usr/bin/make -C "${source}" build-linux-amd64
run_gate identity validate_identity
run_gate build-arm64 /usr/bin/make -C "${source}" build-linux-arm64
run_gate offline-validate offline_validate
run_gate offline-dump-abi dump_abi
run_gate package package_artifact

summary="$(IFS=,; printf '%s' "${gate_results[*]}")"
printf 'B82_CI_VALIDATION_END run_id=%s commit=%s timestamp=%s rc=%d gates=%s\n' \
  "${run_id}" "${commit}" "$(timestamp)" "${overall_rc}" "${summary}" \
  >>"${log}"
printf 'run_id=%s\ncommit=%s\nrc=%d\ngates=%s\n' \
  "${run_id}" "${commit}" "${overall_rc}" "${summary}" >"${result_pending}"
/usr/bin/chmod 0600 -- "${result_pending}"
/usr/bin/mv -T -- "${result_pending}" "${result}"
/usr/bin/sync -f "${result}"
exit "${overall_rc}"
