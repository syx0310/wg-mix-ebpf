#!/usr/bin/bash -p
if [[ "$-" != *p* ]]; then
  printf '%s\n' 'error: diagnose-retained-tcp-drop requires Bash privileged mode' >&2
  exit 1
fi
set -Eeuo pipefail

readonly SAFE_PATH='/usr/sbin:/usr/bin:/sbin:/bin'
readonly RUN_PARENT='/var/tmp/wg-mix-ebpf-faketcp-backends-v1'
PATH="${SAFE_PATH}"; LC_ALL=C; export PATH LC_ALL
IFS=$' \t\n'; umask 077
unset BASH_ENV CDPATH ENV GLOBIGNORE LD_LIBRARY_PATH LD_PRELOAD PYTHONHOME PYTHONPATH

stop() {
  local reason="$1" rc="${2:-79}"
  printf 'DIAGNOSTIC_STOP reason=%s rc=%s\n' "${reason}" "${rc}" >&2
  exit "${rc}"
}

MODE="${1-}"
[[ "${MODE}" =~ ^(plan|run)$ ]] || stop mode 64
shift
SOURCE='' SOURCE_COMMIT='' RUN_COMMIT='' RUN_ID=''
while (($#)); do
  (($# >= 2)) || stop arguments 64
  case "$1" in
    --source) SOURCE="$2" ;;
    --source-commit) SOURCE_COMMIT="$2" ;;
    --run-commit) RUN_COMMIT="$2" ;;
    --run-id) RUN_ID="$2" ;;
    *) stop arguments 64 ;;
  esac
  shift 2
done

[[ "${SOURCE}" =~ ^/var/tmp/wg-mix-ebpf-source-stages/[0-9a-f]{8}/source$ &&
  "${SOURCE_COMMIT}" =~ ^[0-9a-f]{40}$ && "${RUN_COMMIT}" =~ ^[0-9a-f]{40}$ &&
  "${RUN_ID}" =~ ^[0-9a-f]{8}$ ]] || stop argument-values 65

readonly ROOT="${RUN_PARENT}/${RUN_ID}"
readonly EVIDENCE="${ROOT}/evidence"
readonly OWNER="${ROOT}/owner.v1"
readonly MANIFEST="${ROOT}/manifest.v1"
readonly NSA="f${RUN_ID}a"
readonly NSB="f${RUN_ID}b"
readonly TARGET='10.82.10.2'
readonly PORT='5201'
readonly TRACE_OUT="${EVIDENCE}/tcp-drop-trace.stdout.log"
readonly TRACE_ERR="${EVIDENCE}/tcp-drop-trace.stderr.log"
readonly CLIENT_OUT="${EVIDENCE}/tcp-drop-client.stdout.log"
readonly CLIENT_ERR="${EVIDENCE}/tcp-drop-client.stderr.log"
readonly SERVER_OUT="${EVIDENCE}/tcp-drop-server.stdout.log"
readonly SERVER_ERR="${EVIDENCE}/tcp-drop-server.stderr.log"
readonly PCAP_A="${EVIDENCE}/tcp-drop-wg-a.pcap"
readonly PCAP_B="${EVIDENCE}/tcp-drop-wg-b.pcap"
readonly PCAP_UNDERLAY_A="${EVIDENCE}/tcp-drop-underlay-a.pcap"
readonly PCAP_A_LOG="${EVIDENCE}/tcp-drop-wg-a.read.log"
readonly PCAP_B_LOG="${EVIDENCE}/tcp-drop-wg-b.read.log"
readonly PCAP_UNDERLAY_A_LOG="${EVIDENCE}/tcp-drop-underlay-a.read.log"
readonly PCAP_A_STDOUT="${EVIDENCE}/tcp-drop-wg-a.capture.stdout.log"
readonly PCAP_A_STDERR="${EVIDENCE}/tcp-drop-wg-a.capture.stderr.log"
readonly PCAP_B_STDOUT="${EVIDENCE}/tcp-drop-wg-b.capture.stdout.log"
readonly PCAP_B_STDERR="${EVIDENCE}/tcp-drop-wg-b.capture.stderr.log"
readonly PCAP_UNDERLAY_A_STDOUT="${EVIDENCE}/tcp-drop-underlay-a.capture.stdout.log"
readonly PCAP_UNDERLAY_A_STDERR="${EVIDENCE}/tcp-drop-underlay-a.capture.stderr.log"
readonly PRE_LINK_A_LOG="${EVIDENCE}/tcp-drop-pre-link-a.log"
readonly PRE_LINK_B_LOG="${EVIDENCE}/tcp-drop-pre-link-b.log"
readonly PRE_ROUTE_A_LOG="${EVIDENCE}/tcp-drop-pre-route-a.log"
readonly POST_LINK_A_LOG="${EVIDENCE}/tcp-drop-post-link-a.log"
readonly POST_LINK_B_LOG="${EVIDENCE}/tcp-drop-post-link-b.log"
readonly MAPS_A_BEFORE="${EVIDENCE}/tcp-drop-maps-a-before.json"
readonly MAPS_B_BEFORE="${EVIDENCE}/tcp-drop-maps-b-before.json"
readonly MAPS_A_AFTER="${EVIDENCE}/tcp-drop-maps-a-after.json"
readonly MAPS_B_AFTER="${EVIDENCE}/tcp-drop-maps-b-after.json"
readonly OPERATIONS="${EVIDENCE}/tcp-drop-diagnostic.operations.log"
readonly SUMMARY="${EVIDENCE}/tcp-drop-diagnostic.summary.v1"
readonly -a OUTPUT_TARGETS=(
  "${TRACE_OUT}" "${TRACE_ERR}" "${CLIENT_OUT}" "${CLIENT_ERR}"
  "${SERVER_OUT}" "${SERVER_ERR}" "${PCAP_A}" "${PCAP_B}" "${PCAP_UNDERLAY_A}"
  "${PCAP_A_LOG}" "${PCAP_B_LOG}" "${PCAP_UNDERLAY_A_LOG}"
  "${PCAP_A_STDOUT}" "${PCAP_A_STDERR}"
  "${PCAP_B_STDOUT}" "${PCAP_B_STDERR}" "${PRE_LINK_A_LOG}" "${PRE_LINK_B_LOG}"
  "${PCAP_UNDERLAY_A_STDOUT}" "${PCAP_UNDERLAY_A_STDERR}"
  "${PRE_ROUTE_A_LOG}" "${POST_LINK_A_LOG}" "${POST_LINK_B_LOG}"
  "${MAPS_A_BEFORE}" "${MAPS_B_BEFORE}" "${MAPS_A_AFTER}" "${MAPS_B_AFTER}"
  "${OPERATIONS}" "${SUMMARY}"
)

receipt_value() {
  local key="$1" path="$2"
  awk -F= -v wanted="${key}" '
    $1 == wanted { count++; value=substr($0, length($1)+2) }
    END { if (count != 1 || value == "") exit 1; print value }
  ' "${path}"
}

[[ "${EUID}" -eq 0 && "$(id -g)" -eq 0 ]] || stop root-identity
[[ -d "${SOURCE}" && ! -L "${SOURCE}" &&
  "$(readlink -e -- "${SOURCE}")" == "${SOURCE}" ]] || stop source-shape
[[ "$(git -C "${SOURCE}" rev-parse HEAD)" == "${SOURCE_COMMIT}" ]] || stop source-commit
[[ -z "$(git -C "${SOURCE}" status --porcelain=v1 --untracked-files=all)" ]] || stop source-dirty
[[ -d "${ROOT}" && ! -L "${ROOT}" && "$(readlink -e -- "${ROOT}")" == "${ROOT}" &&
  "$(stat -Lc '%u:%g:%a:%F' -- "${ROOT}")" == '0:0:700:directory' ]] || stop run-root-shape
[[ -d "${EVIDENCE}" && ! -L "${EVIDENCE}" &&
  "$(readlink -e -- "${EVIDENCE}")" == "${EVIDENCE}" &&
  "$(stat -Lc '%u:%g:%a:%F' -- "${EVIDENCE}")" == '0:0:700:directory' ]] || stop evidence-shape
[[ -f "${OWNER}" && ! -L "${OWNER}" &&
  "$(stat -Lc '%u:%g:%a:%h:%F' -- "${OWNER}")" == '0:0:600:1:regular file' &&
  "$(<"${OWNER}")" == "wg-mix-ebpf-faketcp-backends-v1:${RUN_ID}:${RUN_COMMIT}" ]] || stop owner-contract
[[ -f "${MANIFEST}" && ! -L "${MANIFEST}" &&
  "$(stat -Lc '%u:%g:%a:%h:%F' -- "${MANIFEST}")" == '0:0:600:1:regular file' ]] || stop manifest-shape
[[ "$(receipt_value format "${MANIFEST}")" == 'wg-mix-ebpf-b82-faketcp-backends-v1' &&
  "$(receipt_value run_id "${MANIFEST}")" == "${RUN_ID}" &&
  "$(receipt_value commit "${MANIFEST}")" == "${RUN_COMMIT}" &&
  "$(receipt_value wg_count "${MANIFEST}")" == '1' &&
  "$(receipt_value attachment "${MANIFEST}")" == 'tcx' &&
  "$(receipt_value checksum "${MANIFEST}")" == 'kfunc' &&
  "$(receipt_value xor "${MANIFEST}")" == 'none' &&
  "$(receipt_value gso "${MANIFEST}")" == 'off' ]] || stop manifest-contract
[[ ! -e "${ROOT}/restored.v1" && ! -L "${ROOT}/restored.v1" ]] || stop already-restored
[[ -e "/run/netns/${NSA}" && ! -L "/run/netns/${NSA}" &&
  -e "/run/netns/${NSB}" && ! -L "/run/netns/${NSB}" ]] || stop netns-identity

for target in "${OUTPUT_TARGETS[@]}"; do
  [[ ! -e "${target}" && ! -L "${target}" ]] || stop evidence-target-exists
done
unset target

for command_name in bpftrace bpftool ip iperf3 python3 ss tcpdump timeout; do
  if ! command -v "${command_name}" >/dev/null; then
    printf 'missing_command=%s\n' "${command_name}" >&2
    stop missing-command 69
  fi
done
unset command_name

printf 'mode=%s\nhostname=%s\nboot_id=%s\nsource=%s\nsource_commit=%s\nrun_id=%s\nrun_commit=%s\n' \
  "${MODE}" "$(hostname)" "$(</proc/sys/kernel/random/boot_id)" "${SOURCE}" \
  "${SOURCE_COMMIT}" "${RUN_ID}" "${RUN_COMMIT}"
printf 'netns_a=%s\nnetns_b=%s\ntarget=%s\nport=%s\n' "${NSA}" "${NSB}" "${TARGET}" "${PORT}"
for target in "${OUTPUT_TARGETS[@]}"; do printf 'write_target=%s\n' "${target}"; done
printf 'network_write=bounded-iperf3-tcp-session\nbpf_write=unlinked-bpftrace-tracepoint-owner\n'
printf 'process_bound=all-child-processes-timeout-at-most-10s\ncleanup=none\n'
[[ "${MODE}" == run ]] || exit 0

printf 'hostname=%s\nboot_id=%s\nsource=%s\nsource_commit=%s\nrun_commit=%s\nrun_id=%s\nnetns_a=%s\nnetns_b=%s\ntarget=%s\nport=%s\n' \
  "$(hostname)" "$(</proc/sys/kernel/random/boot_id)" "${SOURCE}" "${SOURCE_COMMIT}" \
  "${RUN_COMMIT}" "${RUN_ID}" "${NSA}" "${NSB}" "${TARGET}" "${PORT}" >"${OPERATIONS}"

log_readonly() {
  local phase="$1"; shift
  local out="${EVIDENCE}/tcp-drop-${phase}.log" rc
  [[ ! -e "${out}" && ! -L "${out}" ]] || return 79
  printf 'timestamp=%s event=start phase=%s argv=' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${phase}" >>"${OPERATIONS}"
  printf '%q ' "$@" >>"${OPERATIONS}"
  printf '\noutput=%s\n' "${out}" >>"${OPERATIONS}"
  if "$@" >"${out}" 2>&1; then rc=0; else rc=$?; fi
  printf 'timestamp=%s event=finish phase=%s rc=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${phase}" "${rc}" >>"${OPERATIONS}"
  return "${rc}"
}

log_readonly pre-link-a ip netns exec "${NSA}" ip -s -details link show dev wg0
log_readonly pre-link-b ip netns exec "${NSB}" ip -s -details link show dev wg0
log_readonly pre-route-a ip netns exec "${NSA}" ip route get "${TARGET}" from 10.82.10.1

capture_runtime_maps() {
  local role="$1" output="$2" pid_file="${ROOT}/daemon-${role}.pid" netns="${NSA}"
  local pid expected_netns actual_netns
  [[ "${role}" == b ]] && netns="${NSB}"
  [[ -f "${pid_file}" && ! -L "${pid_file}" &&
    "$(stat -Lc '%u:%g:%a:%h:%F' -- "${pid_file}")" == '0:0:600:1:regular file' ]] || stop daemon-pid-file
  pid="$(<"${pid_file}")"
  [[ "${pid}" =~ ^[1-9][0-9]*$ && -d "/proc/${pid}" &&
    "$(readlink -e -- "/proc/${pid}/exe")" == "${ROOT}/artifacts/wg-mix-ebpf" ]] || stop daemon-process
  expected_netns="$(stat -Lc '%d:%i' -- "/run/netns/${netns}")"
  actual_netns="$(stat -Lc '%d:%i' -- "/proc/${pid}/ns/net")"
  [[ "${actual_netns}" == "${expected_netns}" ]] || stop daemon-netns
  timeout --signal=TERM --kill-after=2s 10s python3 - "${pid}" "${output}" <<'PY'
import json
import pathlib
import re
import subprocess
import sys

pid = int(sys.argv[1])
output = pathlib.Path(sys.argv[2])
map_ids = set()
for entry in pathlib.Path(f"/proc/{pid}/fdinfo").iterdir():
    try:
        text = entry.read_text(encoding="ascii")
    except OSError:
        continue
    match = re.search(r"^map_id:\s+([1-9][0-9]*)$", text, re.MULTILINE)
    if match:
        map_ids.add(int(match.group(1)))

records = []
for map_id in sorted(map_ids):
    shown = subprocess.run(
        ["bpftool", "-j", "map", "show", "id", str(map_id)],
        check=True,
        text=True,
        capture_output=True,
        timeout=3,
    )
    info = json.loads(shown.stdout)
    name = str(info.get("name", ""))
    if name not in {"stats_map", "faketcp_stats_m", "faketcp_session", "faketcp_egress"}:
        continue
    dumped = subprocess.run(
        ["bpftool", "-j", "map", "dump", "id", str(map_id)],
        check=True,
        text=True,
        capture_output=True,
        timeout=3,
    )
    records.append({"id": map_id, "info": info, "entries": json.loads(dumped.stdout)})

names = {str(record["info"].get("name", "")) for record in records}
if not {"stats_map", "faketcp_stats_m"}.issubset(names):
    raise SystemExit(f"missing required stats maps: found={sorted(names)}")
output.write_text(json.dumps(records, sort_keys=True, indent=2) + "\n", encoding="utf-8")
PY
}

capture_runtime_maps a "${MAPS_A_BEFORE}"
capture_runtime_maps b "${MAPS_B_BEFORE}"

readonly BPFTRACE_PROGRAM='BEGIN { printf("TRACE_READY\\n"); } tracepoint:skb:kfree_skb /args->protocol == 2048/ { printf("ts=%llu pid=%d comm=%s location=%s reason=%d\\n", nsecs, pid, comm, ksym(args->location), args->reason); } interval:s:8 { exit(); }'

timeout --signal=TERM --kill-after=2s 10s bpftrace -q -e "${BPFTRACE_PROGRAM}" \
  >"${TRACE_OUT}" 2>"${TRACE_ERR}" &
trace_pid=$!
printf 'timestamp=%s event=start phase=kfree-trace pid=%s argv=timeout 10s bpftrace <fixed-program>\nstdout=%s\nstderr=%s\n' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${trace_pid}" "${TRACE_OUT}" "${TRACE_ERR}" >>"${OPERATIONS}"

ready=0
for _ in {1..100}; do
  if grep -Fxq -- TRACE_READY "${TRACE_OUT}"; then ready=1; break; fi
  [[ -d "/proc/${trace_pid}" ]] || break
  sleep 0.05
done
if ((ready != 1)); then
  if wait "${trace_pid}"; then trace_rc=0; else trace_rc=$?; fi
  printf 'timestamp=%s event=finish phase=kfree-trace rc=%s ready=0\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${trace_rc}" >>"${OPERATIONS}"
  stop trace-not-ready 1
fi

timeout --signal=TERM --kill-after=1s 9s ip netns exec "${NSA}" \
  tcpdump -U -nn -i wg0 -w "${PCAP_A}" >"${PCAP_A_STDOUT}" \
  2>"${PCAP_A_STDERR}" &
pcap_a_pid=$!
timeout --signal=TERM --kill-after=1s 9s ip netns exec "${NSB}" \
  tcpdump -U -nn -i wg0 -w "${PCAP_B}" >"${PCAP_B_STDOUT}" \
  2>"${PCAP_B_STDERR}" &
pcap_b_pid=$!
timeout --signal=TERM --kill-after=1s 9s ip netns exec "${NSA}" \
  tcpdump -U -nn -i under0 -w "${PCAP_UNDERLAY_A}" >"${PCAP_UNDERLAY_A_STDOUT}" \
  2>"${PCAP_UNDERLAY_A_STDERR}" &
pcap_underlay_a_pid=$!

timeout --signal=TERM --kill-after=1s 9s ip netns exec "${NSB}" \
  iperf3 -s -1 -p "${PORT}" -J >"${SERVER_OUT}" 2>"${SERVER_ERR}" &
server_pid=$!
printf 'timestamp=%s event=start phase=server pid=%s argv=timeout 9s ip netns exec %s iperf3 -s -1 -p %s -J\nstdout=%s\nstderr=%s\n' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${server_pid}" "${NSB}" "${PORT}" \
  "${SERVER_OUT}" "${SERVER_ERR}" >>"${OPERATIONS}"

server_ready=0
for _ in {1..100}; do
  if ip netns exec "${NSB}" ss -H -lnt "sport = :${PORT}" | grep -q .; then
    server_ready=1
    break
  fi
  [[ -d "/proc/${server_pid}" ]] || break
  sleep 0.05
done
if ((server_ready != 1)); then
  if wait "${server_pid}"; then server_rc=0; else server_rc=$?; fi
  if wait "${pcap_a_pid}"; then pcap_a_rc=0; else pcap_a_rc=$?; fi
  if wait "${pcap_b_pid}"; then pcap_b_rc=0; else pcap_b_rc=$?; fi
  if wait "${pcap_underlay_a_pid}"; then pcap_underlay_a_rc=0; else pcap_underlay_a_rc=$?; fi
  if wait "${trace_pid}"; then trace_rc=0; else trace_rc=$?; fi
  printf 'server_rc=%s pcap_a_rc=%s pcap_b_rc=%s pcap_underlay_a_rc=%s trace_rc=%s\n' \
    "${server_rc}" "${pcap_a_rc}" "${pcap_b_rc}" "${pcap_underlay_a_rc}" \
    "${trace_rc}" >>"${OPERATIONS}"
  stop server-not-ready 1
fi

printf 'timestamp=%s event=start phase=client argv=timeout 7s ip netns exec %s iperf3 -c %s -p %s --connect-timeout 3000 -t 1 -P 1 -J\nstdout=%s\nstderr=%s\n' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${NSA}" "${TARGET}" "${PORT}" \
  "${CLIENT_OUT}" "${CLIENT_ERR}" >>"${OPERATIONS}"
if timeout --signal=TERM --kill-after=1s 7s ip netns exec "${NSA}" \
  iperf3 -c "${TARGET}" -p "${PORT}" --connect-timeout 3000 -t 1 -P 1 -J \
  >"${CLIENT_OUT}" 2>"${CLIENT_ERR}"; then
  client_rc=0
else
  client_rc=$?
fi
printf 'timestamp=%s event=finish phase=client rc=%s\n' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${client_rc}" >>"${OPERATIONS}"

if wait "${server_pid}"; then server_rc=0; else server_rc=$?; fi
if wait "${pcap_a_pid}"; then pcap_a_rc=0; else pcap_a_rc=$?; fi
if wait "${pcap_b_pid}"; then pcap_b_rc=0; else pcap_b_rc=$?; fi
if wait "${pcap_underlay_a_pid}"; then pcap_underlay_a_rc=0; else pcap_underlay_a_rc=$?; fi
if wait "${trace_pid}"; then trace_rc=0; else trace_rc=$?; fi

printf 'timestamp=%s event=finish phase=server rc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${server_rc}" >>"${OPERATIONS}"
printf 'timestamp=%s event=finish phase=pcap-a rc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${pcap_a_rc}" >>"${OPERATIONS}"
printf 'timestamp=%s event=finish phase=pcap-b rc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${pcap_b_rc}" >>"${OPERATIONS}"
printf 'timestamp=%s event=finish phase=pcap-underlay-a rc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${pcap_underlay_a_rc}" >>"${OPERATIONS}"
printf 'timestamp=%s event=finish phase=kfree-trace rc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${trace_rc}" >>"${OPERATIONS}"

[[ "${pcap_a_rc}" -eq 124 && "${pcap_b_rc}" -eq 124 &&
  "${pcap_underlay_a_rc}" -eq 124 && "${trace_rc}" -eq 0 ]] || stop child-status 1
tcpdump -nn -tttt -vvv -r "${PCAP_A}" >"${PCAP_A_LOG}" 2>&1
tcpdump -nn -tttt -vvv -r "${PCAP_B}" >"${PCAP_B_LOG}" 2>&1
tcpdump -nn -tttt -vvv -r "${PCAP_UNDERLAY_A}" >"${PCAP_UNDERLAY_A_LOG}" 2>&1
log_readonly post-link-a ip netns exec "${NSA}" ip -s -details link show dev wg0
log_readonly post-link-b ip netns exec "${NSB}" ip -s -details link show dev wg0
capture_runtime_maps a "${MAPS_A_AFTER}"
capture_runtime_maps b "${MAPS_B_AFTER}"

printf 'format=wg-mix-ebpf-retained-tcp-drop-diagnostic-v1\nrun_id=%s\nclient_rc=%s\nserver_rc=%s\ntrace_rc=%s\npcap_a_rc=%s\npcap_b_rc=%s\npcap_underlay_a_rc=%s\ncompleted=%s\n' \
  "${RUN_ID}" "${client_rc}" "${server_rc}" "${trace_rc}" "${pcap_a_rc}" \
  "${pcap_b_rc}" "${pcap_underlay_a_rc}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"${SUMMARY}"
printf 'DIAGNOSTIC_COMPLETE run_id=%s client_rc=%s server_rc=%s\n' \
  "${RUN_ID}" "${client_rc}" "${server_rc}"
