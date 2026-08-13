#!/usr/bin/bash -p
if [[ "$-" != *p* ]]; then
  builtin printf '%s\n' 'error: B82 performance matrix requires Bash privileged mode' >&2
  exit 1
fi
set -Eeuo pipefail

readonly SAFE_PATH='/usr/sbin:/usr/bin:/sbin:/bin'
readonly STAGED_NAME='scripts/run-b82-complete-performance-matrix.sh'
readonly TMUX_WRAPPER_NAME='scripts/run-b82-complete-performance-tmux.sh'
readonly PRODUCTION_RUNNER_NAME='scripts/run-b82-production-performance-cell.sh'
readonly REPORTER_NAME='scripts/generate-b82-performance-report.py'
readonly RUN_PARENT='/var/tmp/wg-mix-ebpf-performance-tests'
readonly CELL_COUNT=63 SAMPLE_COUNT=567 REPETITIONS=3 DURATION=3
readonly MATRIX_BUDGET_SECONDS=9000
readonly CELL_BUDGET_SECONDS=130 REPORT_RESERVE_SECONDS=60
readonly KFUNC_MODULE='wg_mix_faketcp_checksum'
readonly KPROBE_MODULE='wg_mix_faketcp_checksum_kprobe'
readonly KPROBE_DEVICE='/dev/wg_mix_faketcp_checksum_kprobe'
readonly MODULE_LOCK="${RUN_PARENT}/checksum-module-lease.v2.lock"
readonly -a PREFIX_LENGTHS=(4 16 64 128 256 512 1024 2048)
PATH="${SAFE_PATH}"; LC_ALL=C; GIT_OPTIONAL_LOCKS=0
export PATH LC_ALL GIT_OPTIONAL_LOCKS
IFS=$' \t\n'; umask 077
unset BASH_ENV CDPATH ENV GLOBIGNORE LD_LIBRARY_PATH LD_PRELOAD \
  PERL5LIB PYTHONHOME PYTHONPATH RUBYLIB XOR_PASSWORD \
  WG_MIX_EBPF_PERFORMANCE_ARTIFACT_ROOT

if [[ "${EUID}" -ne 0 || "$(/usr/bin/id -g)" -ne 0 ]]; then
  echo 'error: run the B82 performance matrix as root' >&2
  exit 1
fi

script_reference="${BASH_SOURCE[0]}"
if [[ "${script_reference}" == /* ]]; then
  script_path="${script_reference}"
elif [[ "${script_reference}" == "${STAGED_NAME}" ]]; then
  script_path="$(builtin pwd -P)/${STAGED_NAME}"
else
  echo 'error: matrix path is not the fixed staged entry' >&2
  exit 1
fi
source_root="${script_path%/"${STAGED_NAME}"}"
if [[ ! "${source_root}" =~ ^/var/tmp/wg-mix-ebpf-source-stages/[0-9a-f]{8}/source$ ]]; then
  echo 'error: matrix must run from a root-owned source stage' >&2
  exit 1
fi
readonly SOURCE_ROOT="${source_root}"
readonly TMUX_WRAPPER="${SOURCE_ROOT}/${TMUX_WRAPPER_NAME}"
readonly PRODUCTION_RUNNER="${SOURCE_ROOT}/${PRODUCTION_RUNNER_NAME}"
readonly REPORTER="${SOURCE_ROOT}/${REPORTER_NAME}"
for executable in "${script_path}" "${TMUX_WRAPPER}" "${PRODUCTION_RUNNER}" "${REPORTER}"; do
  executable_metadata="$(stat -c '%u:%g:%a:%h' -- "${executable}")"
  if [[ ! -f "${executable}" || -L "${executable}" || ! -x "${executable}" ||
    ! "${executable_metadata}" =~ ^0:0:([0-7]{3,4}):1$ ]] ||
    (((8#${BASH_REMATCH[1]:-0} & 8#22) != 0)); then
    echo "error: staged performance executable is unsafe: ${executable}" >&2
    exit 1
  fi
done
unset executable executable_metadata

operation=''
matrix_id=''
restore_backend=''
if (($# >= 1)); then operation="$1"; shift; fi
while (($#)); do
  (($# >= 2)) || { echo 'error: incomplete matrix argument' >&2; exit 2; }
  case "$1" in
    --matrix-id) matrix_id="$2" ;;
    --backend) restore_backend="$2" ;;
    *) echo "error: unknown matrix argument: $1" >&2; exit 2 ;;
  esac
  shift 2
done
if [[ ! "${operation}" =~ ^(plan|run|restore-module)$ ||
  ! "${matrix_id}" =~ ^[0-9a-f]{8}$ ]]; then
  echo "usage: ${STAGED_NAME} {plan|run} --matrix-id <8hex> | restore-module --matrix-id <8hex> --backend <kfunc|kprobe>" >&2
  exit 2
fi
if [[ "${operation}" == restore-module ]]; then
  [[ "${restore_backend}" =~ ^(kfunc|kprobe)$ ]] || exit 2
elif [[ -n "${restore_backend}" ]]; then
  echo 'error: --backend is valid only for restore-module' >&2
  exit 2
fi

readonly MATRIX_ID="${matrix_id}"
readonly MATRIX_ROOT="${RUN_PARENT}/${MATRIX_ID}"
readonly MATRIX_EVIDENCE="${MATRIX_ROOT}/evidence"
readonly ARTIFACT_ROOT="${MATRIX_ROOT}/artifacts"
readonly CHILD_PARENT="${MATRIX_ROOT}/children"
readonly CELL_INDEX="${MATRIX_ROOT}/cells.v1.tsv"
readonly PLAN_INDEX="${MATRIX_ROOT}/plan.v1.tsv"
readonly ARTIFACT_MANIFEST="${MATRIX_ROOT}/artifacts.v1"
stage_id="${SOURCE_ROOT#'/var/tmp/wg-mix-ebpf-source-stages/'}"
stage_id="${stage_id%'/source'}"
readonly STAGE_ID="${stage_id}"
readonly BUILD_CACHE_ROOT="${MATRIX_ROOT}/build-cache"
readonly STAGE_GO_CACHE="/var/tmp/wg-mix-ebpf-source-stages/${STAGE_ID}/go-cache"
readonly GO_CACHE="${STAGE_GO_CACHE}"
readonly GO_MOD_CACHE="/var/tmp/wg-mix-ebpf-source-stages/${STAGE_ID}/go-mod-cache"
readonly GO_PATH="${BUILD_CACHE_ROOT}/go-path"
readonly GO_TMP="${BUILD_CACHE_ROOT}/go-tmp"
readonly GO_OVERLAY="${BUILD_CACHE_ROOT}/frozen-bpf-overlay.json"
COMMIT="$(git -C "${SOURCE_ROOT}" rev-parse --verify 'HEAD^{commit}')"
KERNEL_RELEASE="$(uname -r)"
readonly COMMIT KERNEL_RELEASE
CURRENT_MODULE='none'
CURRENT_CELL='none'

cell_id() {
  local ordinal="$1" label="$2"
  printf '%s' "${MATRIX_ID}:${ordinal}:${label}" | sha256sum | awk '{print substr($1,1,8)}'
}

emit_cells() {
  local callback="$1" ordinal=0 backend checksum artifact size label
  ordinal=$((ordinal + 1)); "${callback}" "${ordinal}" wireguard-baseline wireguard none none none none 0
  for backend in tcx classic_tc; do
    ordinal=$((ordinal + 1)); "${callback}" "${ordinal}" "udp-${backend}-none" udp "${backend}" none baseline none 0
    for size in "${PREFIX_LENGTHS[@]}"; do
      ordinal=$((ordinal + 1)); label="udp-${backend}-prefix-${size}"
      "${callback}" "${ordinal}" "${label}" udp "${backend}" none baseline prefix "${size}"
    done
    ordinal=$((ordinal + 1)); "${callback}" "${ordinal}" "udp-${backend}-full-2048" udp "${backend}" none baseline full 2048
  done
  for backend in tcx classic_tc; do
    ordinal=$((ordinal + 1)); "${callback}" "${ordinal}" "icmp-${backend}-none" icmp "${backend}" none baseline none 0
  done
  for checksum in kfunc kprobe; do
    artifact=modern; [[ "${checksum}" == kprobe ]] && artifact=legacy_515
    for backend in tcx classic_tc; do
      ordinal=$((ordinal + 1)); label="faketcp-${backend}-${checksum}-none"
      "${callback}" "${ordinal}" "${label}" faketcp "${backend}" "${checksum}" "${artifact}" none 0
      for size in "${PREFIX_LENGTHS[@]}"; do
        ordinal=$((ordinal + 1)); label="faketcp-${backend}-${checksum}-prefix-${size}"
        "${callback}" "${ordinal}" "${label}" faketcp "${backend}" "${checksum}" "${artifact}" prefix "${size}"
      done
      ordinal=$((ordinal + 1)); label="faketcp-${backend}-${checksum}-full-2048"
      "${callback}" "${ordinal}" "${label}" faketcp "${backend}" "${checksum}" "${artifact}" full 2048
    done
  done
  [[ "${ordinal}" -eq "${CELL_COUNT}" ]]
}

declare -A observed_cell_run_ids=()
# Invoked by emit_cells through its validated callback name.
# shellcheck disable=SC2317
validate_cell_run_id() {
  local ordinal="$1" label="$2" run_id
  run_id="$(cell_id "${ordinal}" "${label}")"
  if [[ -n "${observed_cell_run_ids[${run_id}]-}" ]]; then
    echo "error: matrix ID produces a duplicate cell run ID: ${run_id}" >&2
    return 79
  fi
  observed_cell_run_ids["${run_id}"]="${ordinal}:${label}"
}
emit_cells validate_cell_run_id
[[ "${#observed_cell_run_ids[@]}" -eq "${CELL_COUNT}" ]] || exit 79
[[ "${SAMPLE_COUNT}" -eq $((CELL_COUNT * REPETITIONS * 3)) &&
  "${DURATION}" -eq 3 ]] || exit 79
unset observed_cell_run_ids

# Invoked by emit_cells through its validated callback name.
# shellcheck disable=SC2317
plan_cell() {
  local ordinal="$1" label="$2" transport="$3" backend="$4" checksum="$5"
  local artifact="$6" cipher="$7" max_bytes="$8" run_id cell_root
  local daemon_scope='none' attachment_scope='none' pin_scope='none'
  local maintenance_scope='none' nft_scope='none' qdisc_scope='none' secret_scope='none'
  run_id="$(cell_id "${ordinal}" "${label}")"
  cell_root="${MATRIX_ROOT}/cells/$(printf '%02d' "${ordinal}")-${label}"
  if [[ "${transport}" != wireguard ]]; then
    daemon_scope="${CHILD_PARENT}/${run_id}/endpoint-{a,b}/{run,var}:/run,/var-private-binds"
    attachment_scope="${backend}:wgp${run_id}{a,b}:under0:{ingress,egress}"
    pin_scope="/sys/fs/bpf/wg-mix-ebpf-performance-${run_id}-{a,b}"
    nft_scope="wgp${run_id}{a,b}:temporary"
    maintenance_scope='/run/.wg-mix-ebpf-daemon.lease.maintenance:shared-flock-owner-record-updates-or-create'
    [[ "${backend}" != classic_tc ]] || \
      qdisc_scope="wgp${run_id}{a,b}:under0:clsact"
    [[ "${transport}" != faketcp ]] || \
      attachment_scope="generic-xdp+${attachment_scope}"
  fi
  [[ "${cipher}" == none ]] || \
    secret_scope="${CHILD_PARENT}/${run_id}/endpoint-{a,b}/run/xor.key:temporary"
  printf 'CELL ordinal=%s label=%s run_id=%s transport=%s attachment=%s checksum=%s artifact=%s cipher=%s max_bytes=%s samples=9\n' \
    "${ordinal}" "${label}" "${run_id}" "${transport}" "${backend}" \
    "${checksum}" "${artifact}" "${cipher}" "${max_bytes}"
  printf 'ARGV /usr/bin/env WG_MIX_EBPF_PERFORMANCE_ARTIFACT_ROOT=%q WG_MIX_EBPF_PERFORMANCE_RUN_PARENT=%q /usr/bin/timeout --foreground --signal=TERM --kill-after=30s 130s /usr/bin/bash -p %q run --run-id %q --label %q --transport %q --backend %q --checksum-backend %q --cipher %q --max-bytes %q\n' \
    "${ARTIFACT_ROOT}" "${CHILD_PARENT}" "${PRODUCTION_RUNNER}" "${run_id}" "${label}" \
    "${transport}" "${backend}" "${checksum}" "${cipher}" "${max_bytes}"
  printf 'WRITE_SET cell=%s child=%s netns=wgp%s{a,r,b} links=wpa%s,wra%s,wpb%s,wrb%s,under0,left0,right0,wg0 router_sysctl=net.ipv4.ip_forward daemon_scope=%s attachments=%s qdisc=%s pins=%s nft_guard=%s secret=%s maintenance_gate=%s\n' \
    "${cell_root}" "${CHILD_PARENT}/${run_id}" "${run_id}" \
    "${run_id}" "${run_id}" "${run_id}" "${run_id}" "${daemon_scope}" \
    "${attachment_scope}" "${qdisc_scope}" "${pin_scope}" "${nft_scope}" \
    "${secret_scope}" "${maintenance_scope}"
  printf 'RESTORE_ARGV /usr/bin/env WG_MIX_EBPF_PERFORMANCE_ARTIFACT_ROOT=%q WG_MIX_EBPF_PERFORMANCE_RUN_PARENT=%q /usr/bin/bash -p %q restore --run-id %q --label %q --transport %q --backend %q --checksum-backend %q --cipher %q --max-bytes %q\n' \
    "${ARTIFACT_ROOT}" "${CHILD_PARENT}" "${PRODUCTION_RUNNER}" "${run_id}" "${label}" \
    "${transport}" "${backend}" "${checksum}" "${cipher}" "${max_bytes}"
}

if [[ "${operation}" == plan ]]; then
  if [[ "$(git -C "${SOURCE_ROOT}" rev-parse --verify 'HEAD^{commit}')" != "${COMMIT}" ||
    -n "$(git -C "${SOURCE_ROOT}" status --porcelain=v1 --untracked-files=all)" ]]; then
    echo 'error: source stage is not an exact clean commit for the read-only plan' >&2
    exit 79
  fi
  bpf_plan_cflags='-O2 -g -Wall -Werror -Wno-unused-function -target bpf'
  if command -v gcc >/dev/null 2>&1 && bpf_plan_multiarch="$(gcc -print-multiarch 2>/dev/null)"; then
    if [[ -n "${bpf_plan_multiarch}" && "${bpf_plan_multiarch}" =~ ^[A-Za-z0-9_.+-]+$ &&
      -d "/usr/include/${bpf_plan_multiarch}" && ! -L "/usr/include/${bpf_plan_multiarch}" ]]; then
      bpf_plan_cflags+=" -I/usr/include/${bpf_plan_multiarch}"
    fi
  fi
  printf 'PERFORMANCE_MATRIX_PLAN matrix_id=%s commit=%s kernel=%s cells=63 samples=567 repetitions=3 duration_seconds=3 tmux_budget_seconds=9000\n' \
    "${MATRIX_ID}" "${COMMIT}" "${KERNEL_RELEASE}"
  printf 'SOURCE_STATE source=%q commit=%s git_clean=1\n' "${SOURCE_ROOT}" "${COMMIT}"
  printf 'MATRIX_ARGV /usr/bin/timeout --foreground --signal=TERM --kill-after=180s 9000s /usr/bin/bash -p %q run --matrix-id %q\n' "${script_path}" "${MATRIX_ID}"
  printf 'TMUX_ARGV /usr/bin/tmux new-session -d -s %q -e %q %q\n' \
    "wgmx-perf-${MATRIX_ID}" "WG_MIX_EBPF_PERFORMANCE_MATRIX_ID=${MATRIX_ID}" \
    "${TMUX_WRAPPER}"
  printf 'MATRIX_WRITE_SET matrix=%s artifacts=%s cells=%s/cells child_parent=%s results=%s/results.v1.json report=%s/report.zh-CN.md build_cache=%s go_overlay=%s stage_go_cache=%s stage_module_cache=%s modules=%s,%s kprobe_device=%s:temporary module_lock=%s\n' \
    "${MATRIX_ROOT}" "${ARTIFACT_ROOT}" "${MATRIX_ROOT}" "${CHILD_PARENT}" \
    "${MATRIX_ROOT}" "${MATRIX_ROOT}" "${BUILD_CACHE_ROOT}" "${GO_OVERLAY}" "${GO_CACHE}" "${GO_MOD_CACHE}" \
    "${KFUNC_MODULE}" "${KPROBE_MODULE}" "${KPROBE_DEVICE}" "${MODULE_LOCK}"
  printf 'ARTIFACT_BUILD_SET binary=%s/bin/wg-mix-ebpf baseline=%s/build/wg_mix_tc.o modern=%s/build/wg_mix_faketcp_experimental.o legacy_515=%s/build/wg_mix_faketcp_legacy_515.o kfunc_module=%s/faketcp_checksum_kmod/%s.ko kprobe_module=%s/faketcp_checksum_kprobe_kmod/%s.ko bpf_cflags=%q\n' \
    "${ARTIFACT_ROOT}" "${ARTIFACT_ROOT}" "${ARTIFACT_ROOT}" "${ARTIFACT_ROOT}" \
    "${ARTIFACT_ROOT}" "${KFUNC_MODULE}" "${ARTIFACT_ROOT}" "${KPROBE_MODULE}" \
    "${bpf_plan_cflags}"
  printf 'MODULE_LOAD_ARGV backend=kfunc /usr/sbin/insmod %q lease_id=%q\n' \
    "${ARTIFACT_ROOT}/faketcp_checksum_kmod/${KFUNC_MODULE}.ko" \
    "${STAGE_ID}-${MATRIX_ID}"
  printf 'MODULE_UNLOAD_ARGV backend=kfunc /usr/sbin/rmmod %q\n' "${KFUNC_MODULE}"
  printf 'MODULE_LOAD_ARGV backend=kprobe /usr/sbin/insmod %q\n' \
    "${ARTIFACT_ROOT}/faketcp_checksum_kprobe_kmod/${KPROBE_MODULE}.ko"
  printf 'MODULE_UNLOAD_ARGV backend=kprobe /usr/sbin/rmmod %q\n' "${KPROBE_MODULE}"
  printf 'MODULE_RESTORE_ARGV /usr/bin/bash -p %q restore-module --matrix-id %q --backend kfunc\n' \
    "${script_path}" "${MATRIX_ID}"
  printf 'MODULE_RESTORE_ARGV /usr/bin/bash -p %q restore-module --matrix-id %q --backend kprobe\n' \
    "${script_path}" "${MATRIX_ID}"
  emit_cells plan_cell
  exit 0
fi

for command_name in bash env git uname stat date sha256sum awk python3 timeout make go \
  gcc clang modinfo insmod rmmod flock chmod mkdir readlink tee cp install pahole; do
  resolved_command="$(command -v "${command_name}")" || {
    echo "error: missing matrix command: ${command_name}" >&2
    exit 1
  }
  if [[ "${resolved_command}" != /* || ! -f "${resolved_command}" ||
    ! -x "${resolved_command}" ]]; then
    echo "error: resolved matrix command is unsafe: ${command_name}=${resolved_command}" >&2
    exit 1
  fi
done
unset command_name resolved_command

bpf_multiarch="$(gcc -print-multiarch)" || {
  echo 'error: gcc cannot report the BPF multiarch include' >&2
  exit 1
}
if [[ -n "${bpf_multiarch}" ]]; then
  if [[ ! "${bpf_multiarch}" =~ ^[A-Za-z0-9_.+-]+$ ||
    ! -d "/usr/include/${bpf_multiarch}" || -L "/usr/include/${bpf_multiarch}" ]]; then
    echo "error: compiler returned an unsafe BPF multiarch include: ${bpf_multiarch}" >&2
    exit 1
  fi
  readonly FROZEN_BPF_CFLAGS="-O2 -g -Wall -Werror -Wno-unused-function -target bpf -I/usr/include/${bpf_multiarch}"
else
  readonly FROZEN_BPF_CFLAGS='-O2 -g -Wall -Werror -Wno-unused-function -target bpf'
fi
unset bpf_multiarch

matrix_logged() {
  local phase="$1"; shift
  local out="${MATRIX_EVIDENCE}/${phase}.stdout.log"
  local err="${MATRIX_EVIDENCE}/${phase}.stderr.log"
  local meta="${MATRIX_EVIDENCE}/${phase}.meta.log" status
  {
    printf 'timestamp=%s event=start phase=%s argv=' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${phase}"
    printf '%q ' "$@"; printf '\nstdout=%s\nstderr=%s\n' "${out}" "${err}"
  } >"${meta}"
  if "$@" >"${out}" 2>"${err}"; then status=0; else status=$?; fi
  printf 'timestamp=%s event=finish phase=%s rc=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${phase}" "${status}" >>"${meta}"
  return "${status}"
}

# Invoked as the recorded command argument to matrix_logged.
# shellcheck disable=SC2317
source_tree_digest() {
  python3 -I - "${SOURCE_ROOT}" <<'PY'
import hashlib
import os
import pathlib
import stat
import sys

root = pathlib.Path(sys.argv[1])
if root.resolve(strict=True) != root or root.is_symlink():
    raise SystemExit("source tree digest root is unsafe")
records = []
total_bytes = 0


def add_record(path: pathlib.Path, kind: str, payload: bytes = b"") -> None:
    global total_bytes
    metadata = path.lstat()
    relative = "." if path == root else path.relative_to(root).as_posix()
    stable_size = 0 if kind == "directory" else metadata.st_size
    record = b"\0".join(
        (
            kind.encode("ascii"),
            os.fsencode(relative),
            f"{stat.S_IMODE(metadata.st_mode):04o}".encode("ascii"),
            str(metadata.st_uid).encode("ascii"),
            str(metadata.st_gid).encode("ascii"),
            str(metadata.st_nlink).encode("ascii"),
            str(stable_size).encode("ascii"),
            hashlib.sha256(payload).hexdigest().encode("ascii"),
        )
    )
    records.append(record)
    total_bytes += len(payload)


add_record(root, "directory")
for current_raw, directory_names, file_names in os.walk(
    root, topdown=True, followlinks=False
):
    current = pathlib.Path(current_raw)
    if current == root:
        # These directories are generated by the reviewed build and every
        # consumed artifact is frozen separately in artifacts.v1.
        directory_names[:] = [
            name for name in directory_names if name not in {".git", "bin", "build"}
        ]
    if current == root / "internal" / "dataplane" / "embedded":
        file_names[:] = [
            name
            for name in file_names
            if name
            not in {
                "wg_mix_tc.o",
                "wg_mix_faketcp.o",
                "wg_mix_faketcp_legacy_515.o",
            }
        ]
    directory_names.sort()
    file_names.sort()
    for name in list(directory_names):
        path = current / name
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            add_record(path, "symlink", os.fsencode(os.readlink(path)))
            directory_names.remove(name)
        elif stat.S_ISDIR(metadata.st_mode):
            add_record(path, "directory")
        else:
            raise SystemExit(f"unsupported source tree directory entry: {path}")
    for name in file_names:
        path = current / name
        metadata = path.lstat()
        if stat.S_ISREG(metadata.st_mode):
            add_record(path, "regular", path.read_bytes())
        elif stat.S_ISLNK(metadata.st_mode):
            add_record(path, "symlink", os.fsencode(os.readlink(path)))
        else:
            raise SystemExit(f"unsupported source tree file entry: {path}")
digest = hashlib.sha256(b"\n".join(sorted(records)) + b"\n").hexdigest()
print(f"source_tree_sha256={digest} entries={len(records)} bytes={total_bytes}")
PY
}

dump_complete_logs() {
  python3 - "${MATRIX_ROOT}" <<'PY'
import pathlib
import stat
import sys

root = pathlib.Path(sys.argv[1])
for path in sorted(root.rglob("*")):
    try:
        metadata = path.lstat()
    except OSError as exc:
        print(f"FULL_LOG_ERROR path={path} error={exc}", file=sys.stderr)
        continue
    if not stat.S_ISREG(metadata.st_mode):
        continue
    if path.suffix not in {".log", ".stderr", ".txt", ".json"} and path.name not in {
        "manifest", "complete", "owner", "artifacts.v1", "failure-summary.log"
    }:
        continue
    print(f"FULL_LOG_BEGIN path={path}", file=sys.stderr)
    try:
        print(path.read_text(encoding="utf-8", errors="replace"), end="", file=sys.stderr)
    except OSError as exc:
        print(f"FULL_LOG_READ_ERROR error={exc}", file=sys.stderr)
    print(f"FULL_LOG_END path={path}", file=sys.stderr)
PY
}

matrix_failure() {
  local status="$1" line="$2"
  trap - ERR INT TERM
  set +e
  printf 'matrix_id=%s\nline=%s\nrc=%s\ncurrent_cell=%s\ncurrent_module=%s\n' \
    "${MATRIX_ID}" "${line}" "${status}" "${CURRENT_CELL}" "${CURRENT_MODULE}" \
    >"${MATRIX_EVIDENCE}/failure-summary.log"
  dump_complete_logs
  printf 'PERFORMANCE_MATRIX_FAILURE matrix_id=%s line=%s rc=%s current_cell=%s current_module=%s root=%s\n' \
    "${MATRIX_ID}" "${line}" "${status}" "${CURRENT_CELL}" "${CURRENT_MODULE}" "${MATRIX_ROOT}" >&2
  printf '%s\n' 'No automatic cell restore, module unload, or evidence cleanup was attempted.' >&2
  exit "${status}"
}

receipt_value() {
  local key="$1" path="$2"
  awk -F= -v wanted="${key}" '$1 == wanted {n++; v=substr($0,length($1)+2)} END {if(n!=1||v=="")exit 79; print v}' "${path}"
}

module_name() {
  if [[ "$1" == kfunc ]]; then
    printf '%s' "${KFUNC_MODULE}"
  else
    printf '%s' "${KPROBE_MODULE}"
  fi
}
module_object() {
  if [[ "$1" == kfunc ]]; then
    printf '%s' "${ARTIFACT_ROOT}/faketcp_checksum_kmod/${KFUNC_MODULE}.ko"
  else
    printf '%s' "${ARTIFACT_ROOT}/faketcp_checksum_kprobe_kmod/${KPROBE_MODULE}.ko"
  fi
}

module_receipt() { printf '%s' "${MATRIX_ROOT}/module-$1-owned.v1"; }
module_intent() { printf '%s' "${MATRIX_ROOT}/module-$1-intent.v1"; }

prepare_module_intent() {
  local backend="$1" name object intent srcversion lease
  name="$(module_name "${backend}")"; object="$(module_object "${backend}")"
  intent="$(module_intent "${backend}")"
  [[ ! -e "${intent}" && ! -L "${intent}" && -f "${object}" && ! -L "${object}" ]] || return 79
  srcversion="$(modinfo -F srcversion -- "${object}")"; srcversion="${srcversion^^}"
  [[ "$(modinfo -F name -- "${object}")" == "${name}" &&
    "${srcversion}" =~ ^[0-9A-F]{8,64}$ ]] || return 79
  lease='none'; [[ "${backend}" == kfunc ]] && lease="${STAGE_ID}-${MATRIX_ID}"
  printf 'format=wg-mix-ebpf-performance-module-intent-v2\nbackend=%s\nmodule=%s\nboot_id=%s\nobject=%s\nobject_sha256=%s\nsrcversion=%s\nlease_id=%s\nstate=prepared\n' \
    "${backend}" "${name}" "$(</proc/sys/kernel/random/boot_id)" "${object}" \
    "$(sha256sum -- "${object}" | awk '{print $1}')" "${srcversion}" "${lease}" \
    >"${intent}"
  CURRENT_MODULE="${backend}:intent"
}

validate_module_intent() {
  local backend="$1" name object intent expected_lease
  name="$(module_name "${backend}")"; object="$(module_object "${backend}")"
  intent="$(module_intent "${backend}")"; expected_lease='none'
  [[ "${backend}" == kfunc ]] && expected_lease="${STAGE_ID}-${MATRIX_ID}"
  [[ -f "${intent}" && ! -L "${intent}" &&
    "$(stat -c '%u:%g:%a:%h' -- "${intent}")" == 0:0:600:1 &&
    "$(awk 'END{print NR}' "${intent}")" == 9 &&
    "$(receipt_value format "${intent}")" == wg-mix-ebpf-performance-module-intent-v2 &&
    "$(receipt_value backend "${intent}")" == "${backend}" &&
    "$(receipt_value module "${intent}")" == "${name}" &&
    "$(receipt_value boot_id "${intent}")" == "$(</proc/sys/kernel/random/boot_id)" &&
    "$(receipt_value object "${intent}")" == "${object}" &&
    "$(receipt_value object_sha256 "${intent}")" == "$(sha256sum -- "${object}" | awk '{print $1}')" &&
    "$(receipt_value lease_id "${intent}")" == "${expected_lease}" ]] || return 79
}

seal_live_module_owned() {
  local backend="$1" name object intent receipt srcversion text_address
  name="$(module_name "${backend}")"; object="$(module_object "${backend}")"
  intent="$(module_intent "${backend}")"; receipt="$(module_receipt "${backend}")"
  validate_module_intent "${backend}"
  [[ -d "/sys/module/${name}" ]] || return 79
  srcversion="$(<"/sys/module/${name}/srcversion")"; srcversion="${srcversion^^}"
  text_address="$(<"/sys/module/${name}/sections/.text")"
  [[ "${srcversion}" == "$(receipt_value srcversion "${intent}")" &&
    "${text_address}" =~ ^0x[0-9a-fA-F]+$ ]] || return 79
  if [[ "${backend}" == kfunc ]]; then
    [[ -r "/sys/kernel/btf/${name}" &&
      -f "/sys/module/${name}/parameters/lease_id" &&
      "$(<"/sys/module/${name}/parameters/lease_id")" == "${STAGE_ID}-${MATRIX_ID}" ]] || return 79
  else
    [[ -c "${KPROBE_DEVICE}" && ! -L "${KPROBE_DEVICE}" &&
      "$(stat -c '%u:%g:%a:%h' -- "${KPROBE_DEVICE}")" == 0:0:600:1 ]] || return 79
  fi
  printf 'format=wg-mix-ebpf-performance-module-owned-v2\nbackend=%s\nmodule=%s\nboot_id=%s\nobject=%s\nobject_sha256=%s\nsrcversion=%s\ntext_address=%s\nintent_sha256=%s\nstate=owned\n' \
    "${backend}" "${name}" "$(</proc/sys/kernel/random/boot_id)" "${object}" \
    "$(sha256sum -- "${object}" | awk '{print $1}')" "${srcversion}" "${text_address}" \
    "$(sha256sum -- "${intent}" | awk '{print $1}')" >"${receipt}"
  validate_module_owned_receipt "${backend}"
  CURRENT_MODULE="${backend}"
}

validate_module_owned_receipt() {
  local backend="$1" name object intent receipt
  name="$(module_name "${backend}")"; object="$(module_object "${backend}")"
  intent="$(module_intent "${backend}")"; receipt="$(module_receipt "${backend}")"
  validate_module_intent "${backend}"
  [[ -f "${receipt}" && ! -L "${receipt}" &&
    "$(stat -c '%u:%g:%a:%h' -- "${receipt}")" == 0:0:600:1 &&
    "$(awk 'END{print NR}' "${receipt}")" == 10 &&
    "$(receipt_value format "${receipt}")" == wg-mix-ebpf-performance-module-owned-v2 &&
    "$(receipt_value backend "${receipt}")" == "${backend}" &&
    "$(receipt_value module "${receipt}")" == "${name}" &&
    "$(receipt_value boot_id "${receipt}")" == "$(</proc/sys/kernel/random/boot_id)" &&
    "$(receipt_value object "${receipt}")" == "${object}" &&
    "$(receipt_value object_sha256 "${receipt}")" == "$(sha256sum -- "${object}" | awk '{print $1}')" &&
    "$(receipt_value srcversion "${receipt}")" == "$(receipt_value srcversion "${intent}")" &&
    "$(receipt_value text_address "${receipt}")" =~ ^0x[0-9a-fA-F]+$ &&
    "$(receipt_value intent_sha256 "${receipt}")" == "$(sha256sum -- "${intent}" | awk '{print $1}')" &&
    "$(receipt_value state "${receipt}")" == owned ]] || return 79
}

validate_live_module_owned() {
  local backend="$1" name receipt live_srcversion
  name="$(module_name "${backend}")"
  receipt="$(module_receipt "${backend}")"
  validate_module_owned_receipt "${backend}"
  [[ -d "/sys/module/${name}" && -f "/sys/module/${name}/srcversion" &&
    -f "/sys/module/${name}/sections/.text" ]] || return 79
  live_srcversion="$(<"/sys/module/${name}/srcversion")"
  live_srcversion="${live_srcversion^^}"
  [[ "$(receipt_value srcversion "${receipt}")" == "${live_srcversion}" &&
    "$(receipt_value text_address "${receipt}")" == "$(<"/sys/module/${name}/sections/.text")" ]] || return 79
  if [[ "${backend}" == kfunc ]]; then
    [[ -r "/sys/kernel/btf/${name}" &&
      -f "/sys/module/${name}/parameters/lease_id" &&
      "$(<"/sys/module/${name}/parameters/lease_id")" == "${STAGE_ID}-${MATRIX_ID}" ]] || return 79
  else
    [[ -c "${KPROBE_DEVICE}" && ! -L "${KPROBE_DEVICE}" &&
      "$(stat -c '%u:%g:%a:%h' -- "${KPROBE_DEVICE}")" == 0:0:600:1 ]] || return 79
  fi
}

validate_artifacts() {
  [[ -f "${ARTIFACT_MANIFEST}" && ! -L "${ARTIFACT_MANIFEST}" ]] || return 79
  python3 - "${ARTIFACT_MANIFEST}" "${ARTIFACT_ROOT}" <<'PY'
import hashlib
import pathlib
import re
import stat
import sys

manifest, root = map(pathlib.Path, sys.argv[1:])
raw = manifest.read_bytes()
if not raw.endswith(b"\n") or b"\0" in raw or b"\r" in raw:
    raise SystemExit(79)
rows = raw[:-1].decode("ascii", "strict").split("\n")
expected = [
    "bin/wg-mix-ebpf",
    "build/wg_mix_tc.o",
    "build/wg_mix_faketcp_experimental.o",
    "build/wg_mix_faketcp_legacy_515.o",
    "faketcp_checksum_kmod/wg_mix_faketcp_checksum.ko",
    "faketcp_checksum_kprobe_kmod/wg_mix_faketcp_checksum_kprobe.ko",
]
if rows[:1] != ["format=wg-mix-ebpf-performance-artifacts-v1"] or len(rows) != 7:
    raise SystemExit(79)
for row, expected_relative in zip(rows[1:], expected, strict=True):
    relative, separator, digest = row.partition("=")
    if relative != expected_relative or separator != "=" or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise SystemExit(79)
    path = root / relative
    metadata = path.lstat()
    expected_mode = 0o500 if relative == "bin/wg-mix-ebpf" else 0o400
    if (
        path.resolve(strict=True) != path
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != expected_mode
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or metadata.st_nlink != 1
    ):
        raise SystemExit(79)
    if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        raise SystemExit(79)
print("artifacts_frozen=6")
PY
}

load_module() {
  local backend="$1" name object receipt
  name="$(module_name "${backend}")"; object="$(module_object "${backend}")"
  receipt="$(module_receipt "${backend}")"
  [[ ! -d "/sys/module/${name}" && ! -e "${receipt}" && -f "${object}" && ! -L "${object}" ]] || return 79
  prepare_module_intent "${backend}"
  if [[ "${backend}" == kfunc ]]; then
    matrix_logged "module-${backend}-load" insmod "${object}" "lease_id=${STAGE_ID}-${MATRIX_ID}"
  else
    matrix_logged "module-${backend}-load" insmod "${object}"
  fi
  seal_live_module_owned "${backend}"
}

unload_module() {
  local backend="$1" name receipt restored refcount live_srcversion
  name="$(module_name "${backend}")"
  receipt="$(module_receipt "${backend}")"
  restored="${MATRIX_ROOT}/module-${backend}-restored.v1"
  validate_module_owned_receipt "${backend}"
  live_srcversion="$(<"/sys/module/${name}/srcversion")"; live_srcversion="${live_srcversion^^}"
  [[ "$(receipt_value srcversion "${receipt}")" == "${live_srcversion}" &&
    "$(receipt_value text_address "${receipt}")" == "$(<"/sys/module/${name}/sections/.text")" ]] || return 79
  if [[ "${backend}" == kfunc ]]; then
    [[ -r "/sys/kernel/btf/${name}" &&
      -f "/sys/module/${name}/parameters/lease_id" &&
      "$(<"/sys/module/${name}/parameters/lease_id")" == "${STAGE_ID}-${MATRIX_ID}" ]] || return 79
  else
    [[ -c "${KPROBE_DEVICE}" && ! -L "${KPROBE_DEVICE}" &&
      "$(stat -c '%u:%g:%a:%h' -- "${KPROBE_DEVICE}")" == 0:0:600:1 ]] || return 79
  fi
  refcount="$(awk -v name="${name}" '$1==name{print $3}' /proc/modules)"
  [[ "${refcount}" == 0 ]] || { echo "error: module ${name} refcount=${refcount}" >&2; return 1; }
  [[ ! -e "${restored}" && ! -L "${restored}" ]] || return 79
  matrix_logged "module-${backend}-unload" rmmod "${name}"
  [[ ! -d "/sys/module/${name}" ]] || return 1
  if [[ "${backend}" == kfunc ]]; then
    [[ ! -e "/sys/kernel/btf/${name}" ]] || return 1
  else
    [[ ! -e "${KPROBE_DEVICE}" && ! -L "${KPROBE_DEVICE}" ]] || return 1
  fi
  printf 'format=wg-mix-ebpf-performance-module-restored-v1\nbackend=%s\nmodule=%s\nowned_sha256=%s\nstate=absent\n' \
    "${backend}" "${name}" "$(sha256sum -- "${receipt}" | awk '{print $1}')" \
    >"${restored}"
  validate_module_restored "${backend}"
  CURRENT_MODULE='none'
}

validate_module_restored() {
  local backend="$1" name receipt intent restored
  name="$(module_name "${backend}")"
  receipt="$(module_receipt "${backend}")"
  intent="$(module_intent "${backend}")"
  restored="${MATRIX_ROOT}/module-${backend}-restored.v1"
  [[ -f "${restored}" && ! -L "${restored}" &&
    "$(stat -c '%u:%g:%a:%h' -- "${restored}")" == 0:0:600:1 &&
    "$(awk 'END{print NR}' "${restored}")" == 5 &&
    "$(receipt_value format "${restored}")" == wg-mix-ebpf-performance-module-restored-v1 &&
    "$(receipt_value backend "${restored}")" == "${backend}" &&
    "$(receipt_value module "${restored}")" == "${name}" &&
    "$(receipt_value state "${restored}")" == absent &&
    ! -d "/sys/module/${name}" ]] || return 79
  if [[ "${backend}" == kfunc ]]; then
    [[ ! -e "/sys/kernel/btf/${name}" ]] || return 79
  else
    [[ ! -e "${KPROBE_DEVICE}" && ! -L "${KPROBE_DEVICE}" ]] || return 79
  fi
  if [[ -e "${receipt}" || -L "${receipt}" ]]; then
    [[ -f "${receipt}" && ! -L "${receipt}" ]] || return 79
    validate_module_owned_receipt "${backend}"
    [[ "$(receipt_value owned_sha256 "${restored}")" == \
      "$(sha256sum -- "${receipt}" | awk '{print $1}')" ]] || return 79
  else
    [[ "$(receipt_value intent_sha256 "${restored}")" == \
      "$(sha256sum -- "${intent}" | awk '{print $1}')" ]] || return 79
  fi
}

validate_module_lock() {
  [[ -f "${MODULE_LOCK}" && ! -L "${MODULE_LOCK}" &&
    "$(stat -c '%u:%g:%a:%h' -- "${MODULE_LOCK}")" == 0:0:600:1 ]] || return 79
}

if [[ "${operation}" == restore-module ]]; then
  [[ -d "${MATRIX_ROOT}" && ! -L "${MATRIX_ROOT}" &&
    -f "${MATRIX_ROOT}/owner" &&
    "$(<"${MATRIX_ROOT}/owner")" == "wg-mix-ebpf-performance:${MATRIX_ID}" ]] || exit 79
  [[ -d "${MATRIX_EVIDENCE}" && ! -L "${MATRIX_EVIDENCE}" ]] || exit 79
  trap 'matrix_failure $? $LINENO' ERR
  validate_module_lock
  exec {module_lock_fd}<>"${MODULE_LOCK}"
  matrix_logged restore-module-lock flock --exclusive --nonblock "${module_lock_fd}"
  validate_artifacts
  validate_module_intent "${restore_backend}"
  if [[ ! -d "/sys/module/$(module_name "${restore_backend}")" ]]; then
    if [[ ! -e "${MATRIX_ROOT}/module-${restore_backend}-restored.v1" &&
      ! -L "${MATRIX_ROOT}/module-${restore_backend}-restored.v1" ]]; then
      restore_receipt="$(module_receipt "${restore_backend}")"
      if [[ -e "${restore_receipt}" || -L "${restore_receipt}" ]]; then
        validate_module_owned_receipt "${restore_backend}"
        printf 'format=wg-mix-ebpf-performance-module-restored-v1\nbackend=%s\nmodule=%s\nowned_sha256=%s\nstate=absent\n' \
          "${restore_backend}" "$(module_name "${restore_backend}")" \
          "$(sha256sum -- "${restore_receipt}" | awk '{print $1}')" \
          >"${MATRIX_ROOT}/module-${restore_backend}-restored.v1"
      else
        printf 'format=wg-mix-ebpf-performance-module-restored-v1\nbackend=%s\nmodule=%s\nintent_sha256=%s\nstate=absent\n' \
          "${restore_backend}" "$(module_name "${restore_backend}")" \
          "$(sha256sum -- "$(module_intent "${restore_backend}")" | awk '{print $1}')" \
          >"${MATRIX_ROOT}/module-${restore_backend}-restored.v1"
      fi
    fi
    validate_module_restored "${restore_backend}"
    printf 'PERFORMANCE_MODULE_RESTORE_COMPLETE matrix_id=%s backend=%s state=already-absent\n' \
      "${MATRIX_ID}" "${restore_backend}"
    exit 0
  fi
  CURRENT_MODULE="${restore_backend}"
  if [[ ! -f "$(module_receipt "${restore_backend}")" ]]; then
    seal_live_module_owned "${restore_backend}"
  fi
  unload_module "${restore_backend}"
  validate_module_restored "${restore_backend}"
  trap - ERR INT TERM
  printf 'PERFORMANCE_MODULE_RESTORE_COMPLETE matrix_id=%s backend=%s state=absent\n' \
    "${MATRIX_ID}" "${restore_backend}"
  exit 0
fi

if [[ ! -d "${RUN_PARENT}" ]]; then mkdir --mode=0700 -- "${RUN_PARENT}"; fi
if [[ -L "${RUN_PARENT}" || "$(stat -c '%u:%g:%a' -- "${RUN_PARENT}")" != 0:0:700 ||
  -e "${MATRIX_ROOT}" || -L "${MATRIX_ROOT}" ]]; then
  echo 'error: performance matrix evidence root is unsafe' >&2
  exit 1
fi
mkdir --mode=0700 -- "${MATRIX_ROOT}" "${MATRIX_EVIDENCE}" "${ARTIFACT_ROOT}" \
  "${ARTIFACT_ROOT}/bin" "${ARTIFACT_ROOT}/build" "${MATRIX_ROOT}/cells" \
  "${CHILD_PARENT}" "${BUILD_CACHE_ROOT}" "${GO_PATH}" "${GO_TMP}"
matrix_started="$(date +%s)"
printf 'wg-mix-ebpf-performance:%s\n' "${MATRIX_ID}" >"${MATRIX_ROOT}/owner"
printf 'format=wg-mix-ebpf-b82-performance-matrix-v2\nkind=matrix\nrun_id=%s\ncommit=%s\nkernel_release=%s\ncells=63\nsamples=567\nrepetitions=3\nduration_seconds=3\ntmux_budget_seconds=9000\nartifact_root=%s\nwrite_set=%s,%s,%s,%s,%s,%s,%s,%s\n' \
  "${MATRIX_ID}" "${COMMIT}" "${KERNEL_RELEASE}" "${ARTIFACT_ROOT}" \
  "${MATRIX_ROOT}" "${CHILD_PARENT}:child-cells" "${MODULE_LOCK}:shared-advisory" \
  "${GO_CACHE}:stage-go-cache" "${GO_MOD_CACHE}:stage-module-cache" "${GO_OVERLAY}:generated" \
  "${KFUNC_MODULE}:temporary" \
  "${KPROBE_MODULE}:temporary" >"${MATRIX_ROOT}/manifest"
printf '%s\n' $'ordinal\tlabel\ttransport\tattachment_backend\tchecksum_backend\tartifact\tcipher\tmax_bytes\trun_id\tevidence' >"${PLAN_INDEX}"
# Invoked by emit_cells through its validated callback name.
# shellcheck disable=SC2317
plan_tsv_cell() {
  local ordinal="$1" label="$2" transport="$3" backend="$4" checksum="$5" artifact="$6" cipher="$7" max_bytes="$8" run_id
  run_id="$(cell_id "${ordinal}" "${label}")"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "${ordinal}" "${label}" "${transport}" "${backend}" "${checksum}" "${artifact}" \
  "${cipher}" "${max_bytes}" "${run_id}" "${CHILD_PARENT}/${run_id}/evidence" >>"${PLAN_INDEX}"
}
emit_cells plan_tsv_cell

trap 'matrix_failure $? $LINENO' ERR
trap 'matrix_failure 130 $LINENO' INT TERM
[[ "$(git -C "${SOURCE_ROOT}" rev-parse --verify 'HEAD^{commit}')" == "${COMMIT}" &&
  -z "$(git -C "${SOURCE_ROOT}" status --porcelain=v1 --untracked-files=all)" ]] || {
  echo 'error: source stage is dirty before build' >&2
  matrix_failure 1 "${LINENO}"
}
for stage_cache in "${GO_CACHE}" "${GO_MOD_CACHE}"; do
  [[ -d "${stage_cache}" && ! -L "${stage_cache}" &&
    "$(stat -c '%u:%g:%a' -- "${stage_cache}")" == 0:0:700 ]] || {
    echo "error: immutable source stage Go cache is missing or unsafe: ${stage_cache}" >&2
    matrix_failure 1 "${LINENO}"
  }
done
unset stage_cache

readonly BUILD_BIN="${ARTIFACT_ROOT}/bin/wg-mix-ebpf"
readonly BUILD_BASELINE="${ARTIFACT_ROOT}/build/wg_mix_tc.o"
readonly BUILD_MODERN="${ARTIFACT_ROOT}/build/wg_mix_faketcp_experimental.o"
readonly BUILD_LEGACY="${ARTIFACT_ROOT}/build/wg_mix_faketcp_legacy_515.o"
readonly BUILD_KFUNC_DIR="${ARTIFACT_ROOT}/faketcp_checksum_kmod"
readonly BUILD_KPROBE_DIR="${ARTIFACT_ROOT}/faketcp_checksum_kprobe_kmod"
readonly -a BUILD_ENV=(/usr/bin/env -i PATH="${SAFE_PATH}" LC_ALL=C CGO_ENABLED=0 GOENV=off \
  GOFLAGS=-mod=readonly GOTOOLCHAIN=local 'GOVCS=*:off' GOPROXY=off GOSUMDB=off \
  GOTELEMETRY=off \
  GOCACHE="${GO_CACHE}" GOMODCACHE="${GO_MOD_CACHE}" GOPATH="${GO_PATH}" \
  GOTMPDIR="${GO_TMP}" TMPDIR="${GO_TMP}" GOWORK=off GO111MODULE=on)
matrix_logged source-tree-before source_tree_digest
matrix_logged bpf-build "${BUILD_ENV[@]}" timeout --signal=TERM --kill-after=30s 20m \
  make --no-print-directory -C "${SOURCE_ROOT}" CLANG=/usr/bin/clang \
  "BPF_CFLAGS=${FROZEN_BPF_CFLAGS}" \
  BPF_OBJECT="${BUILD_BASELINE}" FAKETCP_EXPERIMENTAL_BPF_OBJECT="${BUILD_MODERN}" \
  FAKETCP_LEGACY_515_BPF_OBJECT="${BUILD_LEGACY}" build-bpf \
  build-faketcp-experimental-bpf build-faketcp-legacy-515-bpf
matrix_logged go-overlay python3 -I -c '
import json
import os
import pathlib
import stat
import sys

target = pathlib.Path(sys.argv[1])
originals = [pathlib.Path(value) for value in sys.argv[2:5]]
replacements = [pathlib.Path(value) for value in sys.argv[5:8]]
if target.exists() or target.is_symlink() or target.parent.resolve(strict=True) != target.parent:
    raise SystemExit("unsafe Go overlay target")
original_parent = originals[0].parent
parent_metadata = original_parent.lstat()
if (
    any(path.parent != original_parent for path in originals)
    or original_parent.resolve(strict=True) != original_parent
    or original_parent.is_symlink()
    or not stat.S_ISDIR(parent_metadata.st_mode)
    or parent_metadata.st_uid != 0
    or parent_metadata.st_gid != 0
    or stat.S_IMODE(parent_metadata.st_mode) & 0o022
):
    raise SystemExit("unsafe Go overlay source directory")
for path in originals:
    if path.is_symlink():
        raise SystemExit(f"unsafe Go overlay original: {path}")
    if not path.exists():
        continue
    metadata = path.lstat()
    if (
        path.resolve(strict=True) != path
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or metadata.st_nlink != 1
    ):
        raise SystemExit(f"unsafe Go overlay original: {path}")
for path in replacements:
    metadata = path.lstat()
    if (
        path.resolve(strict=True) != path
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or metadata.st_nlink != 1
    ):
        raise SystemExit(f"unsafe Go overlay replacement: {path}")
document = {
    "Replace": {
        str(original): str(replacement)
        for original, replacement in zip(originals, replacements, strict=True)
    }
}
descriptor = os.open(
    target,
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
    0o600,
)
with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
    json.dump(document, stream, sort_keys=True, separators=(",", ":"))
    stream.write("\n")
replace_count = len(document["Replace"])
print(f"go_overlay={target} replacements={replace_count}")
' "${GO_OVERLAY}" \
  "${SOURCE_ROOT}/internal/dataplane/embedded/wg_mix_tc.o" \
  "${SOURCE_ROOT}/internal/dataplane/embedded/wg_mix_faketcp.o" \
  "${SOURCE_ROOT}/internal/dataplane/embedded/wg_mix_faketcp_legacy_515.o" \
  "${BUILD_BASELINE}" "${BUILD_MODERN}" "${BUILD_LEGACY}"
[[ "$(stat -c '%u:%g:%a:%h' -- "${GO_OVERLAY}")" == 0:0:600:1 ]] ||
  matrix_failure 79 "${LINENO}"
matrix_logged go-build "${BUILD_ENV[@]}" timeout --signal=TERM --kill-after=30s 20m \
  /usr/bin/go build -C "${SOURCE_ROOT}" -trimpath -mod=readonly -buildvcs=false \
  "-overlay=${GO_OVERLAY}" \
  "-ldflags=-X=github.com/syx0310/wg-mix-ebpf/internal/buildinfo.sourceCommit=${COMMIT}" \
  -o "${BUILD_BIN}" ./cmd/wg-mix-ebpf
matrix_logged binary-version "${BUILD_BIN}" version --json
python3 - "${MATRIX_EVIDENCE}/binary-version.stdout.log" "${COMMIT}" \
  "${BUILD_BASELINE}" "${BUILD_MODERN}" "${BUILD_LEGACY}" \
  >"${MATRIX_EVIDENCE}/binary-source-identity.log" <<'PY'
import hashlib
import json
import pathlib
import re
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if document.get("source_commit") != sys.argv[2]:
    raise SystemExit("frozen performance binary source commit is not exact")
for field, raw_path in zip(
    (
        "embedded_bpf_object_sha256",
        "embedded_faketcp_object_sha256",
        "embedded_faketcp_legacy_515_object_sha256",
    ),
    sys.argv[3:],
    strict=True,
):
    expected = hashlib.sha256(pathlib.Path(raw_path).read_bytes()).hexdigest()
    if document.get(field) != expected or not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise SystemExit(f"frozen performance binary {field} differs from the frozen object")
if not isinstance(document.get("bpf_abi_version"), int) or document["bpf_abi_version"] <= 0:
    raise SystemExit("frozen performance binary BPF ABI version is invalid")
print(f"binary_source_commit={sys.argv[2]} embedded_identity=complete")
PY
matrix_logged module-kfunc-build env -i PATH="${SAFE_PATH}" LC_ALL=C timeout \
  --signal=TERM --kill-after=30s 20m make --no-print-directory -C "${SOURCE_ROOT}" \
  KERNEL_RELEASE="${KERNEL_RELEASE}" \
  FAKETCP_CHECKSUM_KMOD_OUTPUT="${BUILD_KFUNC_DIR}" \
  FAKETCP_CHECKSUM_KMOD_OBJECT="${BUILD_KFUNC_DIR}/${KFUNC_MODULE}.ko" build-faketcp-checksum-kmod
matrix_logged module-kprobe-build env -i PATH="${SAFE_PATH}" LC_ALL=C timeout \
  --signal=TERM --kill-after=30s 20m make --no-print-directory -C "${SOURCE_ROOT}" \
  KERNEL_RELEASE="${KERNEL_RELEASE}" \
  FAKETCP_CHECKSUM_KPROBE_KMOD_OUTPUT="${BUILD_KPROBE_DIR}" \
  FAKETCP_CHECKSUM_KPROBE_KMOD_OBJECT="${BUILD_KPROBE_DIR}/${KPROBE_MODULE}.ko" build-faketcp-checksum-kprobe-kmod

printf 'format=wg-mix-ebpf-performance-artifacts-v1\n' >"${ARTIFACT_MANIFEST}"
for relative in bin/wg-mix-ebpf build/wg_mix_tc.o build/wg_mix_faketcp_experimental.o \
  build/wg_mix_faketcp_legacy_515.o \
  "faketcp_checksum_kmod/${KFUNC_MODULE}.ko" \
  "faketcp_checksum_kprobe_kmod/${KPROBE_MODULE}.ko"; do
  artifact="${ARTIFACT_ROOT}/${relative}"
  [[ -f "${artifact}" && ! -L "${artifact}" && "$(readlink -e -- "${artifact}")" == "${artifact}" ]] ||
    matrix_failure 79 "${LINENO}"
  printf '%s=%s\n' "${relative}" "$(sha256sum -- "${artifact}" | awk '{print $1}')" >>"${ARTIFACT_MANIFEST}"
done
chmod 0500 -- "${BUILD_BIN}"
chmod 0400 -- "${BUILD_BASELINE}" "${BUILD_MODERN}" "${BUILD_LEGACY}" \
  "${BUILD_KFUNC_DIR}/${KFUNC_MODULE}.ko" "${BUILD_KPROBE_DIR}/${KPROBE_MODULE}.ko"
validate_artifacts | tee "${MATRIX_EVIDENCE}/artifact-freeze.log"
matrix_logged source-tree-after-build source_tree_digest
source_tree_before="$(<"${MATRIX_EVIDENCE}/source-tree-before.stdout.log")"
source_tree_after_build="$(<"${MATRIX_EVIDENCE}/source-tree-after-build.stdout.log")"
[[ "${source_tree_before}" == "${source_tree_after_build}" ]] || {
  echo 'error: artifact build changed the root-owned source tree' >&2
  matrix_failure 79 "${LINENO}"
}
[[ "$(git -C "${SOURCE_ROOT}" rev-parse --verify 'HEAD^{commit}')" == "${COMMIT}" &&
  -z "$(git -C "${SOURCE_ROOT}" status --porcelain=v1 --untracked-files=all)" ]] ||
  matrix_failure 79 "${LINENO}"

if [[ ! -e "${MODULE_LOCK}" && ! -L "${MODULE_LOCK}" ]]; then
  (set -o noclobber; : >"${MODULE_LOCK}"); chmod 0600 -- "${MODULE_LOCK}"
fi
validate_module_lock
exec {module_lock_fd}<>"${MODULE_LOCK}"
matrix_logged module-lock flock --exclusive --nonblock "${module_lock_fd}"
[[ ! -d "/sys/module/${KFUNC_MODULE}" && ! -d "/sys/module/${KPROBE_MODULE}" &&
  ! -e "${KPROBE_DEVICE}" && ! -L "${KPROBE_DEVICE}" ]] || {
  echo 'error: a performance checksum module or kprobe lease device preexists' >&2
  matrix_failure 1 "${LINENO}"
}

printf '%s\n' $'ordinal\tlabel\ttransport\tattachment_backend\tchecksum_backend\tartifact\tcipher\tmax_bytes\trun_id\tevidence' >"${CELL_INDEX}"
previous_checksum='none'

# Invoked by emit_cells through its validated callback name.
# shellcheck disable=SC2317
run_cell() {
  local ordinal="$1" label="$2" transport="$3" backend="$4" checksum="$5"
  local artifact="$6" cipher="$7" max_bytes="$8" run_id cell_root child_root
  local remaining status direction repetition source_json target_json
  local runner_meta
  local -a runner_argv
  validate_artifacts >"${MATRIX_EVIDENCE}/artifact-check-${ordinal}.log"
  if [[ "${checksum}" != "${previous_checksum}" ]]; then
    if [[ "${previous_checksum}" =~ ^(kfunc|kprobe)$ ]]; then unload_module "${previous_checksum}"; fi
    if [[ "${checksum}" =~ ^(kfunc|kprobe)$ ]]; then load_module "${checksum}"; fi
    previous_checksum="${checksum}"
  fi
  if [[ "${checksum}" =~ ^(kfunc|kprobe)$ ]]; then
    validate_live_module_owned "${checksum}"
  fi
  run_id="$(cell_id "${ordinal}" "${label}")"
  cell_root="${MATRIX_ROOT}/cells/$(printf '%02d' "${ordinal}")-${label}"
  child_root="${CHILD_PARENT}/${run_id}"
  [[ ! -e "${cell_root}" && ! -e "${child_root}" ]] || return 79
  mkdir --mode=0700 -- "${cell_root}" "${cell_root}/raw"
  CURRENT_CELL="${run_id}:${label}"
  remaining=$((MATRIX_BUDGET_SECONDS - ($(date +%s) - matrix_started)))
  ((remaining >= CELL_BUDGET_SECONDS + REPORT_RESERVE_SECONDS)) || {
    echo 'error: insufficient 2.5-hour matrix budget remains for one bounded cell and reporting' >&2
    return 124
  }
  printf 'PERFORMANCE_CELL_START matrix_id=%s ordinal=%s run_id=%s label=%s timestamp=%s\n' \
    "${MATRIX_ID}" "${ordinal}" "${run_id}" "${label}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  runner_meta="${cell_root}/runner.meta.log"
  runner_argv=(env WG_MIX_EBPF_PERFORMANCE_ARTIFACT_ROOT="${ARTIFACT_ROOT}"
    WG_MIX_EBPF_PERFORMANCE_RUN_PARENT="${CHILD_PARENT}"
    timeout --foreground --signal=TERM --kill-after=30s "${CELL_BUDGET_SECONDS}s" bash -p "${PRODUCTION_RUNNER}" run \
    --run-id "${run_id}" --label "${label}" --transport "${transport}" \
    --backend "${backend}" --checksum-backend "${checksum}" --cipher "${cipher}" \
    --max-bytes "${max_bytes}")
  {
    printf 'timestamp=%s event=start matrix_id=%s ordinal=%s run_id=%s label=%s argv=' \
      "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${MATRIX_ID}" "${ordinal}" "${run_id}" "${label}"
    printf '%q ' "${runner_argv[@]}"
    printf '\nstdout=%s\nstderr=%s\n' \
      "${cell_root}/runner.stdout.log" "${cell_root}/runner.stderr.log"
  } >"${runner_meta}"
  if "${runner_argv[@]}" >"${cell_root}/runner.stdout.log" \
    2>"${cell_root}/runner.stderr.log"; then status=0; else status=$?; fi
  printf 'timestamp=%s event=finish matrix_id=%s ordinal=%s run_id=%s label=%s rc=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${MATRIX_ID}" "${ordinal}" "${run_id}" \
    "${label}" "${status}" >>"${runner_meta}"
  printf 'PERFORMANCE_CELL_FINISH matrix_id=%s ordinal=%s run_id=%s label=%s rc=%s timestamp=%s\n' \
    "${MATRIX_ID}" "${ordinal}" "${run_id}" "${label}" "${status}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  ((status == 0)) || return "${status}"
  if [[ "${checksum}" =~ ^(kfunc|kprobe)$ ]]; then
    validate_live_module_owned "${checksum}"
  fi
  CURRENT_CELL="${run_id}:${label}:runner-complete-clean"
  [[ -f "${child_root}/manifest" && ! -L "${child_root}/manifest" &&
    "$(receipt_value format "${child_root}/manifest")" == \
      wg-mix-ebpf-b82-production-performance-v1 &&
    "$(receipt_value run_id "${child_root}/manifest")" == "${run_id}" &&
    "$(receipt_value label "${child_root}/manifest")" == "${label}" &&
    "$(receipt_value transport "${child_root}/manifest")" == "${transport}" &&
    "$(receipt_value backend "${child_root}/manifest")" == "${backend}" &&
    "$(receipt_value checksum_backend "${child_root}/manifest")" == "${checksum}" &&
    "$(receipt_value artifact "${child_root}/manifest")" == "${artifact}" &&
    "$(receipt_value cipher "${child_root}/manifest")" == "${cipher}" &&
    "$(receipt_value max_bytes "${child_root}/manifest")" == "${max_bytes}" &&
    -f "${child_root}/complete" && ! -L "${child_root}/complete" &&
    "$(receipt_value format "${child_root}/complete")" == \
      wg-mix-ebpf-b82-production-performance-complete-v1 &&
    "$(receipt_value run_id "${child_root}/complete")" == "${run_id}" &&
    "$(receipt_value manifest_sha256 "${child_root}/complete")" == \
      "$(sha256sum -- "${child_root}/manifest" | awk '{print $1}')" &&
    "$(receipt_value active_resources "${child_root}/complete")" == absent &&
    "$(receipt_value sensitive_files "${child_root}/complete")" == absent &&
    -d "${child_root}/evidence" && ! -L "${child_root}/evidence" ]] || return 79
  for direction in forward reverse bidir; do
    for repetition in 1 2 3; do
      source_json="${child_root}/evidence/iperf-${direction}-r${repetition}-client.json"
      target_json="${cell_root}/raw/iperf-${direction}-r${repetition}.json"
      [[ -f "${source_json}" && ! -L "${source_json}" ]] || return 79
      /bin/cp --reflink=auto -- "${source_json}" "${target_json}"
    done
  done
  printf 'ordinal=%s\nlabel=%s\ntransport=%s\nattachment_backend=%s\nchecksum_backend=%s\nartifact=%s\ncipher=%s\nmax_bytes=%s\nrun_id=%s\nevidence=%s\nsamples=9\nstate=complete\n' \
    "${ordinal}" "${label}" "${transport}" "${backend}" "${checksum}" "${artifact}" \
    "${cipher}" "${max_bytes}" "${run_id}" "${child_root}/evidence" >"${cell_root}/cell.v1"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "${ordinal}" "${label}" "${transport}" "${backend}" "${checksum}" "${artifact}" \
    "${cipher}" "${max_bytes}" "${run_id}" "${child_root}/evidence" >>"${CELL_INDEX}"
  CURRENT_CELL='none'
}

printf 'PERFORMANCE_MATRIX_START matrix_id=%s cells=63 samples=567 repetitions=3 duration_seconds=3 tmux_budget_seconds=9000 timestamp=%s\n' \
  "${MATRIX_ID}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
emit_cells run_cell
if [[ "${previous_checksum}" =~ ^(kfunc|kprobe)$ ]]; then unload_module "${previous_checksum}"; fi
validate_module_restored kfunc
validate_module_restored kprobe
validate_artifacts >"${MATRIX_EVIDENCE}/artifact-check-final.log"
matrix_logged source-tree-final source_tree_digest
source_tree_final="$(<"${MATRIX_EVIDENCE}/source-tree-final.stdout.log")"
[[ "${source_tree_before}" == "${source_tree_final}" ]] || {
  echo 'error: performance cells changed the root-owned source tree' >&2
  matrix_failure 79 "${LINENO}"
}
[[ "$(git -C "${SOURCE_ROOT}" rev-parse --verify 'HEAD^{commit}')" == "${COMMIT}" &&
  -z "$(git -C "${SOURCE_ROOT}" status --porcelain=v1 --untracked-files=all)" ]] || {
  echo 'error: source stage changed during the performance matrix' >&2
  matrix_failure 79 "${LINENO}"
}
matrix_logged report-generate python3 -B -I "${REPORTER}" --matrix-root "${MATRIX_ROOT}" --source-root "${SOURCE_ROOT}"
results_sha="$(sha256sum -- "${MATRIX_ROOT}/results.v1.json" | awk '{print $1}')"
report_sha="$(sha256sum -- "${MATRIX_ROOT}/report.zh-CN.md" | awk '{print $1}')"
printf 'format=wg-mix-ebpf-b82-production-performance-complete-v2\nrun_id=%s\nmanifest_sha256=%s\nartifacts_sha256=%s\nresults_sha256=%s\nreport_sha256=%s\ncells=63\nsamples=567\nactive_resources=absent\nsensitive_files=absent\n' \
  "${MATRIX_ID}" "$(sha256sum -- "${MATRIX_ROOT}/manifest" | awk '{print $1}')" \
  "$(sha256sum -- "${ARTIFACT_MANIFEST}" | awk '{print $1}')" "${results_sha}" "${report_sha}" \
  >"${MATRIX_ROOT}/complete"
trap - ERR INT TERM
printf 'PERFORMANCE_MATRIX_COMPLETE matrix_id=%s cells=63 samples=567 report=%s timestamp=%s\n' \
  "${MATRIX_ID}" "${MATRIX_ROOT}/report.zh-CN.md" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
