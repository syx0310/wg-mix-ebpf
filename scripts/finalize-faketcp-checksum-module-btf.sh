#!/usr/bin/bash
set -Eeuo pipefail

readonly SAFE_PATH="/usr/sbin:/usr/bin:/sbin:/bin"
PATH="${SAFE_PATH}"
LC_ALL=C
export PATH LC_ALL
IFS=$' \t\n'
umask 077
unset BASH_ENV CDPATH ENV GLOBIGNORE LD_LIBRARY_PATH LD_PRELOAD \
  PERL5LIB PYTHONHOME PYTHONPATH RUBYLIB

usage() {
  echo "usage: $0 --kernel-build <absolute-dir> --vmlinux-btf <absolute-file> --module <absolute-ko>" >&2
  exit 2
}

if (($# != 6)) || [[ "$1" != "--kernel-build" || "$3" != "--vmlinux-btf" ||
  "$5" != "--module" ]]; then
  usage
fi
kernel_build="$2"
vmlinux_btf="$4"
module="$6"
for path in "${kernel_build}" "${vmlinux_btf}" "${module}"; do
  [[ "${path}" == /* && "${path}" != *$'\n'* && "${path}" != *$'\r'* ]] || usage
done

kernel_build="$(readlink -e -- "${kernel_build}")"
vmlinux_btf="$(readlink -e -- "${vmlinux_btf}")"
module="$(readlink -e -- "${module}")"
readonly kernel_build vmlinux_btf module
gen_btf="$(readlink -e -- "${kernel_build}/scripts/gen-btf.sh")"
resolve_btfids="$(readlink -e -- \
  "${kernel_build}/tools/bpf/resolve_btfids/resolve_btfids")"
readonly gen_btf resolve_btfids

if [[ ! -d "${kernel_build}" || -L "${kernel_build}" ||
  ! "${kernel_build}" =~ ^/usr/src/linux-headers-[A-Za-z0-9._+-]+$ ||
  ! -f "${vmlinux_btf}" || -L "${vmlinux_btf}" || ! -r "${vmlinux_btf}" ||
  ! -f "${module}" || -L "${module}" || ! -w "${module}" ||
  "$(stat -Lc '%h:%F' -- "${vmlinux_btf}")" != "1:regular file" ||
  "$(stat -Lc '%h:%F' -- "${module}")" != "1:regular file" ||
  ! "${gen_btf}" =~ ^/usr/src/linux-headers-[A-Za-z0-9._+-]+/scripts/gen-btf\.sh$ ||
  ! -f "${gen_btf}" || -L "${gen_btf}" || ! -x "${gen_btf}" ||
  ! "${resolve_btfids}" =~ ^/usr/src/linux-headers-[A-Za-z0-9._+-]+/tools/bpf/resolve_btfids/resolve_btfids$ ||
  ! -f "${resolve_btfids}" || -L "${resolve_btfids}" || ! -x "${resolve_btfids}" ||
  ! -x /usr/bin/pahole || ! -x /usr/bin/objcopy || ! -x /usr/bin/readelf ]]; then
  echo "error: FakeTCP module BTF inputs or tools are unsafe" >&2
  exit 1
fi

module_srcversion_before="$(/usr/sbin/modinfo -F srcversion -- "${module}")"
module_sha256_before="$(sha256sum -- "${module}" | awk '{print $1}')"
vmlinux_sha256="$(sha256sum -- "${vmlinux_btf}" | awk '{print $1}')"
if [[ ! "${module_srcversion_before}" =~ ^[0-9A-Fa-f]{8,64}$ ||
  ! "${module_sha256_before}" =~ ^[0-9a-f]{64}$ ||
  ! "${vmlinux_sha256}" =~ ^[0-9a-f]{64}$ ]]; then
  echo "error: FakeTCP module BTF input identity is invalid" >&2
  exit 1
fi

if /usr/bin/readelf --sections --wide -- "${module}" |
  /usr/bin/awk '$2 == ".BTF" { found++ } END { exit(found == 1 ? 0 : 1) }'; then
  state="already-present"
else
  readonly pahole_flags="--btf_features=encode_force,var,float,enum64,decl_tag,type_tag,optimized_func,consistent_func,decl_tag_kfuncs --btf_features=attributes --lang_exclude=rust"
  readonly resolve_flags="--fatal_warnings --distill_base"
  /usr/bin/env -i PATH="${SAFE_PATH}" LC_ALL=C \
    objtree="${kernel_build}" CONFIG_SHELL=/bin/sh KBUILD_VERBOSE=0 \
    PAHOLE=/usr/bin/pahole PAHOLE_FLAGS="${pahole_flags}" \
    RESOLVE_BTFIDS="${resolve_btfids}" RESOLVE_BTFIDS_FLAGS="${resolve_flags}" \
    OBJCOPY=/usr/bin/objcopy \
    "${gen_btf}" --btf_base "${vmlinux_btf}" "${module}"
  state="generated"
fi

module_srcversion_after="$(/usr/sbin/modinfo -F srcversion -- "${module}")"
module_sha256_after="$(sha256sum -- "${module}" | awk '{print $1}')"
btf_sections="$(/usr/bin/readelf --sections --wide -- "${module}" |
  /usr/bin/awk '$2 == ".BTF" || $2 == ".BTF.base" || $2 == ".BTF_ids" { print $2 }')"
if [[ "${module_srcversion_after}" != "${module_srcversion_before}" ||
  ! "${module_sha256_after}" =~ ^[0-9a-f]{64}$ ||
  "$(/usr/bin/printf '%s\n' "${btf_sections}" | /usr/bin/awk '
    $0 == ".BTF" { btf++ }
    $0 == ".BTF.base" { base++ }
    $0 == ".BTF_ids" { ids++ }
    END { print btf ":" base ":" ids }
  ')" != "1:1:1" ]]; then
  echo "error: finalized FakeTCP module BTF identity is invalid" >&2
  exit 1
fi

printf 'FAKETCP_CHECKSUM_MODULE_BTF state=%s module_sha256_before=%s module_sha256_after=%s vmlinux_btf_sha256=%s srcversion=%s sections=BTF,BTF.base,BTF_ids result=PASS\n' \
  "${state}" "${module_sha256_before}" "${module_sha256_after}" \
  "${vmlinux_sha256}" "${module_srcversion_after^^}"
