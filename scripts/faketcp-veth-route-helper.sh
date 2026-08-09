#!/usr/bin/env bash
set -u
set -o pipefail
umask 077

readonly ROUTE_A_DESTINATION='10.0.0.2/32'
readonly ROUTE_B_DESTINATION='10.0.0.1/32'
readonly ROUTE_A_METRIC='42760'
readonly ROUTE_B_METRIC='42761'
readonly ROUTE_PROTOCOL='99'

MODE=''
RUN_ID=''
RESOURCE_ID=''
IFINDEX_A=''
IFINDEX_B=''
VETH_A=''
VETH_B=''
VETH_A_ALIAS=''
VETH_B_ALIAS=''
EVIDENCE_ROOT=''
AUDIT_LOG=''
OWNER_MARKER=''
INITIAL_NETNS=''

usage() {
	printf '%s\n' \
		'usage: faketcp-veth-route-helper.sh {plan|install|restore}' \
		'  --run-id 8-lowercase-hex --resource-id 8-lowercase-hex' \
		'  --ifindex-a positive-integer --ifindex-b positive-integer' >&2
}

fail() {
	printf 'FAKETCP_VETH_ROUTE_STOP run_id=%s resource_id=%s reason=%s rc=%s; no automatic teardown\n' \
		"${RUN_ID:-unset}" "${RESOURCE_ID:-unset}" "$1" "${2:-125}" >&2
	exit "${2:-125}"
}

parse_arguments() {
	(($# >= 1)) || return 64
	MODE="$1"
	shift
	case "${MODE}" in
		plan | install | restore) ;;
		*) return 64 ;;
	esac
	while (($# > 0)); do
		(($# >= 2)) || return 64
		case "$1" in
			--run-id) RUN_ID="$2" ;;
			--resource-id) RESOURCE_ID="$2" ;;
			--ifindex-a) IFINDEX_A="$2" ;;
			--ifindex-b) IFINDEX_B="$2" ;;
			*) return 64 ;;
		esac
		shift 2
	done
	[[ "${RUN_ID}" =~ ^[0-9a-f]{8}$ && ! "${RUN_ID}" =~ ^0{8}$ &&
		"${RESOURCE_ID}" =~ ^[0-9a-f]{8}$ && ! "${RESOURCE_ID}" =~ ^0{8}$ &&
		"${IFINDEX_A}" =~ ^[1-9][0-9]*$ && "${IFINDEX_B}" =~ ^[1-9][0-9]*$ &&
		"${IFINDEX_A}" != "${IFINDEX_B}" ]] || return 65
	VETH_A="wg${RUN_ID:0:5}a"
	VETH_B="wg${RUN_ID:0:5}b"
	VETH_A_ALIAS="wg-mix-ebpf:${RUN_ID}:a"
	VETH_B_ALIAS="wg-mix-ebpf:${RUN_ID}:b"
	EVIDENCE_ROOT="/run/wg-mix-ebpf-source-stages/${RUN_ID}/veth-evidence-${RESOURCE_ID}"
	AUDIT_LOG="${EVIDENCE_ROOT}/faketcp-route-audit.log"
	OWNER_MARKER="${EVIDENCE_ROOT}/faketcp-route-owner.v1"
}

quote_argv() {
	printf '%q ' "$@"
}

render_plan() {
	printf 'FAKETCP_VETH_ROUTE_PLAN run_id=%s resource_id=%s write_set=main-table:%s,%s veth=%s,%s\n' \
		"${RUN_ID}" "${RESOURCE_ID}" "${ROUTE_A_DESTINATION}" "${ROUTE_B_DESTINATION}" \
		"${VETH_A}" "${VETH_B}"
	printf 'install.a argv='
	quote_argv /usr/sbin/ip -4 route add "${ROUTE_A_DESTINATION}" table main \
		dev "${VETH_A}" proto "${ROUTE_PROTOCOL}" scope link metric "${ROUTE_A_METRIC}"
	printf '\ninstall.b argv='
	quote_argv /usr/sbin/ip -4 route add "${ROUTE_B_DESTINATION}" table main \
		dev "${VETH_B}" proto "${ROUTE_PROTOCOL}" scope link metric "${ROUTE_B_METRIC}"
	printf '\nrestore.b argv='
	quote_argv /usr/sbin/ip -4 route del "${ROUTE_B_DESTINATION}" table main \
		dev "${VETH_B}" proto "${ROUTE_PROTOCOL}" scope link metric "${ROUTE_B_METRIC}"
	printf '\nrestore.a argv='
	quote_argv /usr/sbin/ip -4 route del "${ROUTE_A_DESTINATION}" table main \
		dev "${VETH_A}" proto "${ROUTE_PROTOCOL}" scope link metric "${ROUTE_A_METRIC}"
	printf '\nFAKETCP_VETH_ROUTE_PLAN_COMPLETE commands_are_review_templates=1 no_commands_executed=1\n'
}

validate_evidence_root() {
	local canonical metadata
	[[ -d "${EVIDENCE_ROOT}" && ! -L "${EVIDENCE_ROOT}" ]] || return 78
	canonical="$(/usr/bin/readlink -e -- "${EVIDENCE_ROOT}")" || return $?
	[[ "${canonical}" == "${EVIDENCE_ROOT}" ]] || return 79
	metadata="$(/usr/bin/stat -Lc '%u:%g:%a:%F' -- "${EVIDENCE_ROOT}")" || return $?
	[[ "${metadata}" == '0:0:700:directory' ]] || return 79
}

validate_veth() {
	local name="$1" ifindex="$2" alias="$3" observed_ifindex observed_alias
	[[ -d "/sys/class/net/${name}" && ! -L "/sys/class/net/${name}/ifindex" ]] || return 78
	observed_ifindex="$(/usr/bin/cat -- "/sys/class/net/${name}/ifindex")" || return $?
	observed_alias="$(/usr/bin/cat -- "/sys/class/net/${name}/ifalias")" || return $?
	[[ "${observed_ifindex}" == "${ifindex}" && "${observed_alias}" == "${alias}" ]]
}

audit_line() {
	local event="$1" step="$2" target="$3" rc="$4" rendered="$5" timestamp
	local -a status
	timestamp="$(/usr/bin/date -u '+%Y-%m-%dT%H:%M:%SZ')" || return $?
	printf 'utc=%q event=%q step=%q target=%q rc=%q argv=%q\n' \
		"${timestamp}" "${event}" "${step}" "${target}" "${rc}" "${rendered}" |
		/usr/bin/tee -a "${AUDIT_LOG}"
	status=("${PIPESTATUS[@]}")
	((${#status[@]} == 2 && status[0] == 0 && status[1] == 0))
}

run_step() {
	local step="$1" target="$2" rendered rc
	shift 2
	rendered="$(quote_argv "$@")" || return $?
	audit_line start "${step}" "${target}" not-run "${rendered}" || return $?
	"$@"
	rc=$?
	audit_line finish "${step}" "${target}" "${rc}" "${rendered}" || return $?
	return "${rc}"
}

capture_step() {
	local step="$1" target="$2" path="$3" rendered rc
	shift 3
	[[ "${path}" == "${EVIDENCE_ROOT}/"* && "${path#${EVIDENCE_ROOT}/}" != */* &&
		! -e "${path}" && ! -L "${path}" ]] || return 78
	rendered="$(quote_argv "$@")>$(quote_argv "${path}")" || return $?
	audit_line start "${step}" "${target}" not-run "${rendered}" || return $?
	set -o noclobber
	"$@" >"${path}" 2>&1
	rc=$?
	set +o noclobber
	audit_line finish "${step}" "${target}" "${rc}" "${rendered}" || return $?
	return "${rc}"
}

write_once() {
	local path="$1" rendered rc
	shift
	[[ "${path}" == "${EVIDENCE_ROOT}/"* && "${path#${EVIDENCE_ROOT}/}" != */* &&
		! -e "${path}" && ! -L "${path}" ]] || return 78
	rendered="$(quote_argv shell-builtin printf '%s\\n' "$@")>$(quote_argv "${path}")" || return $?
	audit_line start write-once "${path}" not-run "${rendered}" || return $?
	set -o noclobber
	printf '%s\n' "$@" >"${path}"
	rc=$?
	set +o noclobber
	audit_line finish write-once "${path}" "${rc}" "${rendered}" || return $?
	return "${rc}"
}

route_listing() {
	local destination="$1" path="$2" step="$3"
	capture_step "${step}" "main:${destination}" "${path}" \
		/usr/sbin/ip -4 -j route show table main exact "${destination}"
}

validate_route_absent() {
	local label="$1" path="$2"
	run_step "validate-absent-${label}" "${path}" /usr/bin/jq -e \
		'type == "array" and length == 0' "${path}"
}

validate_route_owned() {
	local label="$1" path="$2" destination="$3" name="$4" metric="$5"
	run_step "validate-owned-${label}" "${path}" /usr/bin/jq -e \
		--arg destination "${destination%/32}" --arg device "${name}" \
		--arg protocol "${ROUTE_PROTOCOL}" --argjson metric "${metric}" \
		'type == "array" and length == 1 and
		 .[0].dst == $destination and .[0].dev == $device and
		 (.[0].protocol | tostring) == $protocol and .[0].scope == "link" and
		 .[0].metric == $metric and (.[0] | has("gateway") | not) and
		 (.[0] | has("via") | not) and (.[0] | has("multipath") | not) and
		 (.[0] | has("mtu") | not)' "${path}"
}

expected_owner() {
	printf 'format=wg-mix-faketcp-veth-route-owner-v1\nrun_id=%s\nresource_id=%s\nnetns=%s\na=%s:%s:%s\nb=%s:%s:%s' \
		"${RUN_ID}" "${RESOURCE_ID}" "${INITIAL_NETNS}" \
		"${VETH_A}" "${IFINDEX_A}" "${VETH_A_ALIAS}" \
		"${VETH_B}" "${IFINDEX_B}" "${VETH_B_ALIAS}"
}

install_routes() {
	local owner
	[[ ! -e "${AUDIT_LOG}" && ! -L "${AUDIT_LOG}" ]] || fail audit-exists 78
	set -o noclobber
	: >"${AUDIT_LOG}"
	set +o noclobber
	INITIAL_NETNS="$(/usr/bin/readlink /proc/self/ns/net)" || fail netns-read
	validate_veth "${VETH_A}" "${IFINDEX_A}" "${VETH_A_ALIAS}" || fail veth-a-identity 79
	validate_veth "${VETH_B}" "${IFINDEX_B}" "${VETH_B_ALIAS}" || fail veth-b-identity 79
	route_listing "${ROUTE_A_DESTINATION}" "${EVIDENCE_ROOT}/faketcp-route-a-before.out" snapshot-a || fail snapshot-a
	route_listing "${ROUTE_B_DESTINATION}" "${EVIDENCE_ROOT}/faketcp-route-b-before.out" snapshot-b || fail snapshot-b
	validate_route_absent a-before "${EVIDENCE_ROOT}/faketcp-route-a-before.out" || fail route-preexisting-a 78
	validate_route_absent b-before "${EVIDENCE_ROOT}/faketcp-route-b-before.out" || fail route-preexisting-b 78
	owner="$(expected_owner)" || fail render-owner
	write_once "${OWNER_MARKER}" "${owner}" || fail owner-marker
	write_once "${EVIDENCE_ROOT}/faketcp-route-a-intent.v1" "destination=${ROUTE_A_DESTINATION}" "ifindex=${IFINDEX_A}" || fail intent-a
	run_step add-a "main:${ROUTE_A_DESTINATION}" /usr/sbin/ip -4 route add \
		"${ROUTE_A_DESTINATION}" table main dev "${VETH_A}" proto "${ROUTE_PROTOCOL}" \
		scope link metric "${ROUTE_A_METRIC}" || fail add-a
	route_listing "${ROUTE_A_DESTINATION}" "${EVIDENCE_ROOT}/faketcp-route-a-installed.out" verify-add-a || fail list-add-a
	validate_route_owned a-installed "${EVIDENCE_ROOT}/faketcp-route-a-installed.out" \
		"${ROUTE_A_DESTINATION}" "${VETH_A}" "${ROUTE_A_METRIC}" || fail verify-add-a 79
	write_once "${EVIDENCE_ROOT}/faketcp-route-a-installed.v1" 'state=installed' || fail marker-a
	write_once "${EVIDENCE_ROOT}/faketcp-route-b-intent.v1" "destination=${ROUTE_B_DESTINATION}" "ifindex=${IFINDEX_B}" || fail intent-b
	run_step add-b "main:${ROUTE_B_DESTINATION}" /usr/sbin/ip -4 route add \
		"${ROUTE_B_DESTINATION}" table main dev "${VETH_B}" proto "${ROUTE_PROTOCOL}" \
		scope link metric "${ROUTE_B_METRIC}" || fail add-b
	route_listing "${ROUTE_B_DESTINATION}" "${EVIDENCE_ROOT}/faketcp-route-b-installed.out" verify-add-b || fail list-add-b
	validate_route_owned b-installed "${EVIDENCE_ROOT}/faketcp-route-b-installed.out" \
		"${ROUTE_B_DESTINATION}" "${VETH_B}" "${ROUTE_B_METRIC}" || fail verify-add-b 79
	write_once "${EVIDENCE_ROOT}/faketcp-route-b-installed.v1" 'state=installed' || fail marker-b
	printf 'FAKETCP_VETH_ROUTE_INSTALLED run_id=%s resource_id=%s routes=2\n' "${RUN_ID}" "${RESOURCE_ID}"
}

restore_one_route() {
	local label="$1" destination="$2" name="$3" metric="$4" installed="$5" removed="$6"
	[[ -f "${installed}" && ! -L "${installed}" && ! -e "${removed}" && ! -L "${removed}" ]] || return 78
	route_listing "${destination}" "${EVIDENCE_ROOT}/faketcp-route-${label}-restore-before.out" "restore-list-${label}" || return $?
	validate_route_owned "${label}-restore" "${EVIDENCE_ROOT}/faketcp-route-${label}-restore-before.out" \
		"${destination}" "${name}" "${metric}" || return $?
	run_step "delete-${label}" "main:${destination}" /usr/sbin/ip -4 route del \
		"${destination}" table main dev "${name}" proto "${ROUTE_PROTOCOL}" \
		scope link metric "${metric}" || return $?
	route_listing "${destination}" "${EVIDENCE_ROOT}/faketcp-route-${label}-restore-after.out" "restore-verify-${label}" || return $?
	validate_route_absent "${label}-restore" "${EVIDENCE_ROOT}/faketcp-route-${label}-restore-after.out" || return $?
	write_once "${removed}" 'state=removed'
}

restore_routes() {
	local owner observed
	[[ -f "${AUDIT_LOG}" && ! -L "${AUDIT_LOG}" && -f "${OWNER_MARKER}" &&
		! -L "${OWNER_MARKER}" ]] || fail restore-evidence-missing 78
	INITIAL_NETNS="$(/usr/bin/readlink /proc/self/ns/net)" || fail netns-read
	validate_veth "${VETH_A}" "${IFINDEX_A}" "${VETH_A_ALIAS}" || fail veth-a-identity 79
	validate_veth "${VETH_B}" "${IFINDEX_B}" "${VETH_B_ALIAS}" || fail veth-b-identity 79
	owner="$(expected_owner)" || fail render-owner
	observed="$(/usr/bin/cat -- "${OWNER_MARKER}")" || fail read-owner
	[[ "${observed}" == "${owner}" ]] || fail owner-drift 79
	if [[ -e "${EVIDENCE_ROOT}/faketcp-route-b-installed.v1" ]]; then
		restore_one_route b "${ROUTE_B_DESTINATION}" "${VETH_B}" "${ROUTE_B_METRIC}" \
			"${EVIDENCE_ROOT}/faketcp-route-b-installed.v1" \
			"${EVIDENCE_ROOT}/faketcp-route-b-removed.v1" || fail restore-b
	fi
	if [[ -e "${EVIDENCE_ROOT}/faketcp-route-a-installed.v1" ]]; then
		restore_one_route a "${ROUTE_A_DESTINATION}" "${VETH_A}" "${ROUTE_A_METRIC}" \
			"${EVIDENCE_ROOT}/faketcp-route-a-installed.v1" \
			"${EVIDENCE_ROOT}/faketcp-route-a-removed.v1" || fail restore-a
	fi
	write_once "${EVIDENCE_ROOT}/faketcp-routes-restored.v1" 'state=restored' || fail restored-marker
	printf 'FAKETCP_VETH_ROUTE_RESTORED run_id=%s resource_id=%s\n' "${RUN_ID}" "${RESOURCE_ID}"
}

parse_arguments "$@" || { usage; exit 64; }
if [[ "${MODE}" == plan ]]; then
	render_plan
	exit 0
fi
((EUID == 0)) || fail root-required 77
validate_evidence_root || fail evidence-root 79
case "${MODE}" in
	install) install_routes ;;
	restore) restore_routes ;;
esac
