#!/usr/bin/bash -p
if [[ "$-" != *p* ]]; then
  printf '%s\n' 'error: root-cell requires Bash privileged mode' >&2
  exit 1
fi
set -Eeuo pipefail

readonly SAFE_PATH='/usr/sbin:/usr/bin:/sbin:/bin'
readonly SELF_REL='scripts/realhost-b82-faketcp-backends-v1/root-cell.sh'
readonly RUN_PARENT='/run/wg-mix-ebpf-faketcp-backends-v1'
readonly KFUNC_MODULE='wg_mix_faketcp_checksum'
readonly KPROBE_MODULE='wg_mix_faketcp_checksum_kprobe'
PATH="${SAFE_PATH}"
LC_ALL=C
export PATH LC_ALL
IFS=$' \t\n'
umask 077
unset BASH_ENV CDPATH ENV GLOBIGNORE LD_LIBRARY_PATH LD_PRELOAD PYTHONHOME PYTHONPATH

MODE='' SOURCE='' COMMIT='' RUN_ID='' LABEL='' WG_COUNT=''
ATTACHMENT_BACKEND='' CHECKSUM_BACKEND='' ARTIFACT='' XOR_MODE='' GSO_MODE=''

usage() {
  printf '%s\n' \
    "usage: ${SELF_REL} {plan|run|restore} --source /run/wg-mix-ebpf-source-stages/<8hex>/source --commit <40hex> --run-id <8hex> --label <label> --wg-count <1|2|4> --attachment-backend <tcx|classic_tc> --checksum-backend <kfunc|kprobe> --artifact <modern|legacy_515> --xor <none|prefix|full> --gso <off|on>" >&2
}

fail() {
  printf 'B82_FAKETCP_CELL_STOP run_id=%s label=%s mode=%s stage=%s reason=%s rc=%s evidence=%s\n' \
    "${RUN_ID:-unparsed}" "${LABEL:-unparsed}" "${MODE:-unparsed}" \
    "${STAGE:-argument}" "$1" "${2:-125}" "${EVIDENCE_ROOT:-unallocated}" >&2
  exit "${2:-125}"
}

parse_args() {
  (($# >= 1)) || return 64
  MODE="$1"; shift
  case "${MODE}" in plan|run|restore) ;; *) return 64 ;; esac
  while (($#)); do
    (($# >= 2)) || return 64
    case "$1" in
      --source) SOURCE="$2" ;;
      --commit) COMMIT="$2" ;;
      --run-id) RUN_ID="$2" ;;
      --label) LABEL="$2" ;;
      --wg-count) WG_COUNT="$2" ;;
      --attachment-backend) ATTACHMENT_BACKEND="$2" ;;
      --checksum-backend) CHECKSUM_BACKEND="$2" ;;
      --artifact) ARTIFACT="$2" ;;
      --xor) XOR_MODE="$2" ;;
      --gso) GSO_MODE="$2" ;;
      *) return 64 ;;
    esac
    shift 2
  done
  [[ "${SOURCE}" =~ ^/run/wg-mix-ebpf-source-stages/[0-9a-f]{8}/source$ &&
    "${COMMIT}" =~ ^[0-9a-f]{40}$ && "${COMMIT}" != 0000000000000000000000000000000000000000 &&
    "${RUN_ID}" =~ ^[0-9a-f]{8}$ && "${LABEL}" =~ ^[a-z0-9_-]{1,96}$ &&
    "${WG_COUNT}" =~ ^(1|2|4)$ && "${ATTACHMENT_BACKEND}" =~ ^(tcx|classic_tc)$ &&
    "${CHECKSUM_BACKEND}" =~ ^(kfunc|kprobe)$ && "${ARTIFACT}" =~ ^(modern|legacy_515)$ &&
    "${XOR_MODE}" =~ ^(none|prefix|full)$ && "${GSO_MODE}" =~ ^(off|on)$ ]] || return 65
  [[ ("${CHECKSUM_BACKEND}" == kfunc && "${ARTIFACT}" == modern) ||
    ("${CHECKSUM_BACKEND}" == kprobe && "${ARTIFACT}" == legacy_515) ]] || return 65
}

parse_rc=0
parse_args "$@" || parse_rc=$?
if ((parse_rc != 0)); then usage; exit "${parse_rc}"; fi
stage_id_value="${SOURCE#'/run/wg-mix-ebpf-source-stages/'}"
stage_id_value="${stage_id_value%'/source'}"
readonly STAGE_ID="${stage_id_value}"
readonly STAGE_ROOT="/run/wg-mix-ebpf-source-stages/${STAGE_ID}"
readonly EVIDENCE_ROOT="${RUN_PARENT}/${RUN_ID}"
readonly EVIDENCE="${EVIDENCE_ROOT}/evidence"
readonly OWNER="${EVIDENCE_ROOT}/owner.v1"
readonly MANIFEST="${EVIDENCE_ROOT}/manifest.v1"
readonly ARTIFACT_ROOT="${EVIDENCE_ROOT}/artifacts"
readonly BIN="${ARTIFACT_ROOT}/wg-mix-ebpf"
readonly BASELINE_OBJECT="${ARTIFACT_ROOT}/wg_mix_tc.o"
readonly MODERN_OBJECT="${ARTIFACT_ROOT}/wg_mix_faketcp_experimental.o"
readonly LEGACY_OBJECT="${ARTIFACT_ROOT}/wg_mix_faketcp_legacy_515.o"
readonly CELL_DRIVER="${SOURCE}/scripts/realhost-b82-faketcp-backends-v1/root-netns-cell.sh"
readonly KFUNC_OUTPUT="${ARTIFACT_ROOT}/faketcp_checksum_kmod"
readonly KPROBE_OUTPUT="${ARTIFACT_ROOT}/faketcp_checksum_kprobe_kmod"
readonly KFUNC_OBJECT="${KFUNC_OUTPUT}/${KFUNC_MODULE}.ko"
readonly KPROBE_OBJECT="${KPROBE_OUTPUT}/${KPROBE_MODULE}.ko"
readonly MODULE_LEASE_ID="${STAGE_ID}-${RUN_ID}"
readonly PREFIX="f${RUN_ID}"
readonly NSA="${PREFIX}a" NSR="${PREFIX}r" NSB="${PREFIX}b"
readonly PIN_A="/sys/fs/bpf/wg-mix-ebpf-faketcp-${RUN_ID}-a"
readonly PIN_B="/sys/fs/bpf/wg-mix-ebpf-faketcp-${RUN_ID}-b"
readonly GO_CACHE="${STAGE_ROOT}/go-cache"
readonly GO_MOD_CACHE="${STAGE_ROOT}/go-mod-cache"
readonly GO_PATH="${STAGE_ROOT}/go-path"
readonly GO_TMP="${STAGE_ROOT}/go-tmp"
readonly -a BUILD_ENV=(
  /usr/bin/env -i PATH="${SAFE_PATH}" LC_ALL=C CGO_ENABLED=0 GOENV=off
  GOFLAGS=-mod=readonly GOTOOLCHAIN=local 'GOVCS=*:off'
  GOCACHE="${GO_CACHE}" GOMODCACHE="${GO_MOD_CACHE}" GOPATH="${GO_PATH}"
  GOTMPDIR="${GO_TMP}" TMPDIR="${GO_TMP}" GOWORK=off GO111MODULE=on
  GOPROXY=off GOSUMDB=off
)
STAGE='preflight'

quote_argv() { printf '%q ' "$@"; }

plan() {
  local selected_object module_object module_name
  if [[ "${ARTIFACT}" == modern ]]; then selected_object="${MODERN_OBJECT}"; else selected_object="${LEGACY_OBJECT}"; fi
  if [[ "${CHECKSUM_BACKEND}" == kfunc ]]; then
    module_object="${KFUNC_OBJECT}"; module_name="${KFUNC_MODULE}"
  else
    module_object="${KPROBE_OBJECT}"; module_name="${KPROBE_MODULE}"
  fi
  printf 'B82_FAKETCP_CELL_PLAN run_id=%s label=%s source=%s commit=%s xdp=exact-generic attachment=%s checksum=%s artifact=%s wg_count=%s xor=%s gso=%s\n' \
    "${RUN_ID}" "${LABEL}" "${SOURCE}" "${COMMIT}" "${ATTACHMENT_BACKEND}" \
    "${CHECKSUM_BACKEND}" "${ARTIFACT}" "${WG_COUNT}" "${XOR_MODE}" "${GSO_MODE}"
  printf 'WRITE_SET evidence=%s artifacts=%s stage_caches=%s,%s,%s,%s netns=%s,%s,%s pins=%s,%s module=%s module_object=%s module_lease_id=%s source=frozen-read-only\n' \
    "${EVIDENCE_ROOT}" "${ARTIFACT_ROOT}" \
    "${GO_CACHE}" "${GO_MOD_CACHE}" "${GO_PATH}" "${GO_TMP}" \
    "${NSA}" "${NSR}" "${NSB}" "${PIN_A}" "${PIN_B}" \
    "${module_name}" "${module_object}" "${MODULE_LEASE_ID}"
  printf 'BPF_BUILD argv='; quote_argv "${BUILD_ENV[@]}" /usr/bin/timeout \
    --signal=TERM --kill-after=30s 20m /usr/bin/make --no-print-directory \
    -C "${SOURCE}" CLANG=/usr/bin/clang BPF_OBJECT="${BASELINE_OBJECT}" \
    FAKETCP_EXPERIMENTAL_BPF_OBJECT="${MODERN_OBJECT}" \
    FAKETCP_LEGACY_515_BPF_OBJECT="${LEGACY_OBJECT}" build-bpf \
    build-faketcp-experimental-bpf build-faketcp-legacy-515-bpf; printf '\n'
  printf 'GO_BUILD argv='; quote_argv "${BUILD_ENV[@]}" /usr/bin/timeout \
    --signal=TERM --kill-after=30s 20m /usr/bin/go -C "${SOURCE}" build \
    -trimpath -mod=readonly -buildvcs=false \
    "-ldflags=-X=github.com/syx0310/wg-mix-ebpf/internal/buildinfo.sourceCommit=${COMMIT}" \
    -o "${BIN}" ./cmd/wg-mix-ebpf; printf '\n'
  if [[ "${CHECKSUM_BACKEND}" == kfunc ]]; then
    printf 'MODULE_BUILD argv='; quote_argv /usr/bin/env -i PATH="${SAFE_PATH}" LC_ALL=C \
      /usr/bin/timeout --signal=TERM --kill-after=30s 15m /usr/bin/make \
      --no-print-directory -C "${SOURCE}" FAKETCP_CHECKSUM_KMOD_OUTPUT="${KFUNC_OUTPUT}" \
      FAKETCP_CHECKSUM_KMOD_OBJECT="${KFUNC_OBJECT}" build-faketcp-checksum-kmod; printf '\n'
  else
    printf 'MODULE_BUILD argv='; quote_argv /usr/bin/env -i PATH="${SAFE_PATH}" LC_ALL=C \
      /usr/bin/timeout --signal=TERM --kill-after=30s 15m /usr/bin/make \
      --no-print-directory -C "${SOURCE}" \
      FAKETCP_CHECKSUM_KPROBE_KMOD_OUTPUT="${KPROBE_OUTPUT}" \
      FAKETCP_CHECKSUM_KPROBE_KMOD_OBJECT="${KPROBE_OBJECT}" \
      build-faketcp-checksum-kprobe-kmod; printf '\n'
  fi
  printf 'RUN argv='; quote_argv /bin/bash -p "${CELL_DRIVER}" run \
    --source "${SOURCE}" --commit "${COMMIT}" --run-id "${RUN_ID}" --label "${LABEL}" \
    --wg-count "${WG_COUNT}" --attachment-backend "${ATTACHMENT_BACKEND}" \
    --checksum-backend "${CHECKSUM_BACKEND}" --binary "${BIN}" \
    --baseline-object "${BASELINE_OBJECT}" --modern-object "${MODERN_OBJECT}" \
    --legacy-object "${LEGACY_OBJECT}" --selected-object "${selected_object}" \
    --module-object "${module_object}" --module-lease-id "${MODULE_LEASE_ID}" \
    --xor "${XOR_MODE}" --gso "${GSO_MODE}"; printf '\n'
  printf 'RESTORE argv='; quote_argv /bin/bash -p "$0" restore \
    --source "${SOURCE}" --commit "${COMMIT}" --run-id "${RUN_ID}" --label "${LABEL}" \
    --wg-count "${WG_COUNT}" --attachment-backend "${ATTACHMENT_BACKEND}" \
    --checksum-backend "${CHECKSUM_BACKEND}" --artifact "${ARTIFACT}" \
    --xor "${XOR_MODE}" --gso "${GSO_MODE}"; printf '\n'
}

if [[ "${MODE}" == plan ]]; then plan; exit 0; fi
[[ "${EUID}" -eq 0 && "$(id -g)" -eq 0 ]] || fail root-required 77
[[ -d "${SOURCE}" && ! -L "${SOURCE}" && "$(readlink -e -- "${SOURCE}")" == "${SOURCE}" ]] || fail source-path 79
[[ "$(stat -Lc '%u:%g:%a:%F' -- "${SOURCE}")" == '0:0:700:directory' ]] || fail source-identity 79
source_clean() {
  [[ "$(git -C "${SOURCE}" rev-parse --verify 'HEAD^{commit}')" == "${COMMIT}" ]] || return 1
  git -C "${SOURCE}" diff --quiet "${COMMIT}" -- || return $?
  git -C "${SOURCE}" diff --cached --quiet "${COMMIT}" -- || return $?
  [[ -z "$(git -C "${SOURCE}" status --porcelain=v1 --untracked-files=all)" ]]
}

source_tree_digest() {
  /usr/bin/python3 -B -I - "${SOURCE}" <<'PY'
import hashlib, os, pathlib, stat, sys
root=pathlib.Path(sys.argv[1]); digest=hashlib.sha256()
def visit(path):
    for entry in sorted(os.scandir(path), key=lambda item:item.name):
        if pathlib.Path(path)==root and entry.name==".git": continue
        meta=entry.stat(follow_symlinks=False); rel=os.path.relpath(entry.path,root)
        digest.update(f"{rel}\0{meta.st_mode:o}\0{meta.st_uid}\0{meta.st_gid}\0".encode())
        if stat.S_ISDIR(meta.st_mode): visit(entry.path)
        elif stat.S_ISREG(meta.st_mode):
            with open(entry.path,"rb") as handle:
                for chunk in iter(lambda:handle.read(65536),b""): digest.update(chunk)
        elif stat.S_ISLNK(meta.st_mode): digest.update(os.readlink(entry.path).encode())
        else: raise SystemExit(f"unsupported frozen-source entry: {rel}")
visit(root); print(digest.hexdigest())
PY
}

source_clean || fail source-status-drift 79
SOURCE_DIGEST_BEFORE="$(source_tree_digest)"
[[ "${SOURCE_DIGEST_BEFORE}" =~ ^[0-9a-f]{64}$ ]] || fail source-digest 79
verify_source_immutable() {
  local actual
  source_clean || fail source-status-drift-after-build 79
  actual="$(source_tree_digest)"
  [[ "${actual}" == "${SOURCE_DIGEST_BEFORE}" ]] || fail frozen-source-mutated 79
}
for cache in "${GO_CACHE}" "${GO_MOD_CACHE}" "${GO_PATH}" "${GO_TMP}"; do
  [[ -d "${cache}" && ! -L "${cache}" &&
    "$(stat -Lc '%u:%g:%a:%F' -- "${cache}")" == '0:0:700:directory' ]] ||
    fail "stage-cache:${cache}" 79
done

validate_regular() {
  local path="$1" execute="$2" shape mode
  [[ -f "${path}" && ! -L "${path}" ]] || fail "missing:${path}" 79
  shape="$(stat -Lc '%u:%g:%a:%h:%F' -- "${path}")"
  [[ "${shape}" =~ ^0:0:([0-7]{3,4}):1:regular\ file$ ]] || fail "shape:${path}" 79
  mode="${BASH_REMATCH[1]}"
  (((8#${mode} & 8#22) == 0)) || fail "writable:${path}" 79
  [[ "${execute}" == no ]] || (((8#${mode} & 8#111) != 0)) || fail "not-executable:${path}" 79
}
validate_regular "${CELL_DRIVER}" yes
if [[ "${ARTIFACT}" == modern ]]; then SELECTED_OBJECT="${MODERN_OBJECT}"; else SELECTED_OBJECT="${LEGACY_OBJECT}"; fi
if [[ "${CHECKSUM_BACKEND}" == kfunc ]]; then MODULE_OBJECT="${KFUNC_OBJECT}"; else MODULE_OBJECT="${KPROBE_OBJECT}"; fi

capture_diagnostics() {
  local output="${EVIDENCE}/failure-diagnostics.log" ns
  : >"${output}"
  printf 'COMMAND uname -a\n' >>"${output}"
  uname -a >>"${output}" 2>&1; printf 'RC %s\n' "$?" >>"${output}"
  printf 'COMMAND ip netns list\n' >>"${output}"
  ip netns list >>"${output}" 2>&1; printf 'RC %s\n' "$?" >>"${output}"
  printf 'COMMAND bpftool -j link show\n' >>"${output}"
  bpftool -j link show >>"${output}" 2>&1; printf 'RC %s\n' "$?" >>"${output}"
  printf 'COMMAND bpftool -j prog show\n' >>"${output}"
  bpftool -j prog show >>"${output}" 2>&1; printf 'RC %s\n' "$?" >>"${output}"
  for ns in "${NSA}" "${NSR}" "${NSB}"; do
    if ip netns list | awk '{print $1}' | grep -Fxq -- "${ns}"; then
      printf 'NETNS %s\n' "${ns}" >>"${output}"
      ip -details -statistics -n "${ns}" link show >>"${output}" 2>&1
      ip -n "${ns}" address show >>"${output}" 2>&1
      ip netns exec "${ns}" tc qdisc show >>"${output}" 2>&1
      ip netns exec "${ns}" tc filter show dev under0 ingress >>"${output}" 2>&1
      ip netns exec "${ns}" tc filter show dev under0 egress >>"${output}" 2>&1
      ip netns exec "${ns}" bpftool net >>"${output}" 2>&1
    fi
  done
}

on_error() {
  local rc="$1" line="$2" path
  trap - ERR INT TERM
  set +e
  printf 'FAIL run_id=%s label=%s stage=%s rc=%s line=%s\n' \
    "${RUN_ID}" "${LABEL}" "${STAGE}" "${rc}" "${line}" >"${EVIDENCE}/failure-summary.log"
  capture_diagnostics
  for path in "${EVIDENCE}"/*.log "${EVIDENCE}"/*.json; do
    [[ -f "${path}" && ! -L "${path}" ]] || continue
    printf 'FULL_LOG_BEGIN path=%s\n' "${path}" >&2
    /bin/cat -- "${path}" >&2
    printf 'FULL_LOG_END path=%s\n' "${path}" >&2
  done
  printf 'FAILURE_RESOURCES_RETAINED run_id=%s evidence=%s; invoke exact restore after review\n' \
    "${RUN_ID}" "${EVIDENCE_ROOT}" >&2
  exit "${rc}"
}

root_logged() {
  local phase="$1"; shift
  local out="${EVIDENCE}/${phase}.stdout.log" err="${EVIDENCE}/${phase}.stderr.log" rc
  {
    printf 'timestamp=%s event=start phase=%s argv=' \
      "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${phase}"
    printf '%q ' "$@"
    printf '\nstdout=%s\nstderr=%s\n' "${out}" "${err}"
  } >>"${EVIDENCE}/root-operations.log"
  if "$@" >"${out}" 2>"${err}"; then rc=0; else rc=$?; fi
  printf 'timestamp=%s event=finish phase=%s rc=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${phase}" "${rc}" \
    >>"${EVIDENCE}/root-operations.log"
  return "${rc}"
}

manifest_value() {
  local key="$1"
  awk -F= -v wanted="${key}" '
    $1 == wanted { count++; value=substr($0, length($1)+2) }
    END { if (count != 1 || value == "") exit 1; print value }
  ' "${MANIFEST}"
}

validate_manifest_identity() {
  [[ -f "${MANIFEST}" && ! -L "${MANIFEST}" ]] || fail manifest-missing 79
  [[ "$(manifest_value source_digest)" == "${SOURCE_DIGEST_BEFORE}" &&
    "$(manifest_value module_lease_id)" == "${MODULE_LEASE_ID}" &&
    "$(manifest_value binary_sha256)" == "$(sha256sum -- "${BIN}" | awk '{print $1}')" &&
    "$(manifest_value baseline_sha256)" == "$(sha256sum -- "${BASELINE_OBJECT}" | awk '{print $1}')" &&
    "$(manifest_value modern_sha256)" == "$(sha256sum -- "${MODERN_OBJECT}" | awk '{print $1}')" &&
    "$(manifest_value legacy_sha256)" == "$(sha256sum -- "${LEGACY_OBJECT}" | awk '{print $1}')" &&
    "$(manifest_value module_sha256)" == "$(sha256sum -- "${MODULE_OBJECT}" | awk '{print $1}')" ]] ||
    fail manifest-identity 79
}

restore_exact() {
  [[ -d "${EVIDENCE_ROOT}" && ! -L "${EVIDENCE_ROOT}" &&
    -f "${OWNER}" && ! -L "${OWNER}" &&
    "$(<"${OWNER}")" == "wg-mix-ebpf-faketcp-backends-v1:${RUN_ID}:${COMMIT}" ]] ||
    fail restore-owner 79
  verify_source_immutable
  validate_manifest_identity
  STAGE='restore'
  /bin/bash -p "${CELL_DRIVER}" restore --source "${SOURCE}" --commit "${COMMIT}" \
    --run-id "${RUN_ID}" --label "${LABEL}" --wg-count "${WG_COUNT}" \
    --attachment-backend "${ATTACHMENT_BACKEND}" --checksum-backend "${CHECKSUM_BACKEND}" \
    --binary "${BIN}" --baseline-object "${BASELINE_OBJECT}" \
    --modern-object "${MODERN_OBJECT}" --legacy-object "${LEGACY_OBJECT}" \
    --selected-object "${SELECTED_OBJECT}" --module-object "${MODULE_OBJECT}" \
    --module-lease-id "${MODULE_LEASE_ID}" --xor "${XOR_MODE}" --gso "${GSO_MODE}" \
    >"${EVIDENCE}/restore.stdout.log" 2>"${EVIDENCE}/restore.stderr.log"
  printf 'RESTORE_COMPLETE run_id=%s timestamp=%s\n' "${RUN_ID}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}

if [[ "${MODE}" == restore ]]; then restore_exact; exit 0; fi
[[ ! -e "${EVIDENCE_ROOT}" && ! -L "${EVIDENCE_ROOT}" ]] || fail evidence-exists 79
mkdir --mode=0700 -- "${EVIDENCE_ROOT}"
mkdir --mode=0700 -- "${EVIDENCE}"
mkdir --mode=0700 -- "${ARTIFACT_ROOT}"
printf 'wg-mix-ebpf-faketcp-backends-v1:%s:%s\n' "${RUN_ID}" "${COMMIT}" >"${OWNER}"
trap 'on_error $? $LINENO' ERR
trap 'on_error 130 $LINENO' INT TERM
STAGE='artifact-build'
root_logged bpf-build "${BUILD_ENV[@]}" /usr/bin/timeout --signal=TERM \
  --kill-after=30s 20m /usr/bin/make --no-print-directory -C "${SOURCE}" \
  CLANG=/usr/bin/clang BPF_OBJECT="${BASELINE_OBJECT}" \
  FAKETCP_EXPERIMENTAL_BPF_OBJECT="${MODERN_OBJECT}" \
  FAKETCP_LEGACY_515_BPF_OBJECT="${LEGACY_OBJECT}" build-bpf \
  build-faketcp-experimental-bpf build-faketcp-legacy-515-bpf
root_logged go-build "${BUILD_ENV[@]}" /usr/bin/timeout --signal=TERM \
  --kill-after=30s 20m /usr/bin/go -C "${SOURCE}" build -trimpath \
  -mod=readonly -buildvcs=false \
  "-ldflags=-X=github.com/syx0310/wg-mix-ebpf/internal/buildinfo.sourceCommit=${COMMIT}" \
  -o "${BIN}" ./cmd/wg-mix-ebpf
if [[ "${CHECKSUM_BACKEND}" == kfunc ]]; then
  root_logged module-build /usr/bin/env -i PATH="${SAFE_PATH}" LC_ALL=C \
    /usr/bin/timeout --signal=TERM --kill-after=30s 15m /usr/bin/make \
    --no-print-directory -C "${SOURCE}" FAKETCP_CHECKSUM_KMOD_OUTPUT="${KFUNC_OUTPUT}" \
    FAKETCP_CHECKSUM_KMOD_OBJECT="${KFUNC_OBJECT}" build-faketcp-checksum-kmod
else
  root_logged module-build /usr/bin/env -i PATH="${SAFE_PATH}" LC_ALL=C \
    /usr/bin/timeout --signal=TERM --kill-after=30s 15m /usr/bin/make \
    --no-print-directory -C "${SOURCE}" \
    FAKETCP_CHECKSUM_KPROBE_KMOD_OUTPUT="${KPROBE_OUTPUT}" \
    FAKETCP_CHECKSUM_KPROBE_KMOD_OBJECT="${KPROBE_OBJECT}" \
    build-faketcp-checksum-kprobe-kmod
fi
verify_source_immutable
validate_regular "${BIN}" yes
validate_regular "${BASELINE_OBJECT}" no
validate_regular "${MODERN_OBJECT}" no
validate_regular "${LEGACY_OBJECT}" no
validate_regular "${SELECTED_OBJECT}" no
validate_regular "${MODULE_OBJECT}" no
printf 'format=wg-mix-ebpf-b82-faketcp-backends-v1\nrun_id=%s\nlabel=%s\ncommit=%s\nstage_id=%s\nsource_digest=%s\nxdp=exact-generic\nattachment=%s\nchecksum=%s\nartifact=%s\nwg_count=%s\nxor=%s\ngso=%s\nmodule_lease_id=%s\nbinary_sha256=%s\nbaseline_sha256=%s\nmodern_sha256=%s\nlegacy_sha256=%s\nmodule_sha256=%s\n' \
  "${RUN_ID}" "${LABEL}" "${COMMIT}" "${STAGE_ID}" "${SOURCE_DIGEST_BEFORE}" \
  "${ATTACHMENT_BACKEND}" "${CHECKSUM_BACKEND}" "${ARTIFACT}" "${WG_COUNT}" \
  "${XOR_MODE}" "${GSO_MODE}" "${MODULE_LEASE_ID}" \
  "$(sha256sum -- "${BIN}" | awk '{print $1}')" \
  "$(sha256sum -- "${BASELINE_OBJECT}" | awk '{print $1}')" \
  "$(sha256sum -- "${MODERN_OBJECT}" | awk '{print $1}')" \
  "$(sha256sum -- "${LEGACY_OBJECT}" | awk '{print $1}')" \
  "$(sha256sum -- "${MODULE_OBJECT}" | awk '{print $1}')" >"${MANIFEST}"
validate_manifest_identity
STAGE='cell-run'
/bin/bash -p "${CELL_DRIVER}" run --source "${SOURCE}" --commit "${COMMIT}" \
  --run-id "${RUN_ID}" --label "${LABEL}" --wg-count "${WG_COUNT}" \
  --attachment-backend "${ATTACHMENT_BACKEND}" --checksum-backend "${CHECKSUM_BACKEND}" \
  --binary "${BIN}" --baseline-object "${BASELINE_OBJECT}" \
  --modern-object "${MODERN_OBJECT}" --legacy-object "${LEGACY_OBJECT}" \
  --selected-object "${SELECTED_OBJECT}" --module-object "${MODULE_OBJECT}" \
  --module-lease-id "${MODULE_LEASE_ID}" --xor "${XOR_MODE}" --gso "${GSO_MODE}" \
  >"${EVIDENCE}/cell.stdout.log" 2>"${EVIDENCE}/cell.stderr.log"
verify_source_immutable
STAGE='success-restore'
restore_exact
verify_source_immutable
trap - ERR INT TERM
printf 'B82_FAKETCP_CELL_COMPLETE run_id=%s label=%s evidence=%s\n' "${RUN_ID}" "${LABEL}" "${EVIDENCE_ROOT}"
