#!/usr/bin/env python3
"""Static fail-closed contracts for the Linux 5.15 kretprobe bridge."""

from pathlib import Path
import re
import sys


SOURCE_PATH = Path(__file__).with_name("wg_mix_faketcp_checksum_kprobe.c")
UAPI_PATH = Path(__file__).with_name("wg_mix_faketcp_checksum_kprobe_uapi.h")
SOURCE = SOURCE_PATH.read_text(encoding="utf-8")
UAPI = UAPI_PATH.read_text(encoding="utf-8")
FAILURES: list[str] = []


def require(fragment: str, reason: str) -> None:
    if fragment not in SOURCE:
        FAILURES.append(f"missing {reason}: {fragment!r}")


def require_order(first: str, second: str, reason: str) -> None:
    first_offset = SOURCE.find(first)
    second_offset = SOURCE.find(second)
    if first_offset < 0 or second_offset < 0 or first_offset >= second_offset:
        FAILURES.append(f"invalid order for {reason}")


# TC's __sk_buff.cb maps to qdisc_skb_cb(skb)->data, not struct sk_buff::cb.
require("#include <linux/filter.h>", "Linux 5.15 BPF skb accessor header")
require("u8 *cb = bpf_skb_cb(skb);", "descriptor snapshot via bpf_skb_cb")
require(
    "memcmp(bpf_skb_cb(skb), descriptor->raw_cb,",
    "descriptor comparison via bpf_skb_cb",
)
require("memset(bpf_skb_cb(skb), 0,", "descriptor clear via bpf_skb_cb")
require(
    "BUILD_BUG_ON(WG_MIX_FAKETCP_KPROBE_DESCRIPTOR_SIZE > BPF_SKB_CB_LEN);",
    "descriptor bound against the TC BPF cb length",
)
if re.search(r"\bskb\s*->\s*cb\b", SOURCE):
    FAILURES.append("raw struct sk_buff::cb access is forbidden")

# Every open file description gets a fresh health epoch.
require("u64 errors_baseline;", "per-lease errors baseline")
require("u64 nmissed_baseline;", "per-lease nmissed baseline")
require(
    "lease->errors_baseline = atomic64_read(&wg_mix_faketcp_errors);",
    "errors baseline snapshot at open",
)
require(
    "lease->nmissed_baseline = wg_mix_faketcp_nmissed();",
    "nmissed baseline snapshot at open",
)
require(
    "wg_mix_faketcp_nmissed(), lease->nmissed_baseline",
    "per-lease nmissed delta",
)
require(
    "atomic64_read(&wg_mix_faketcp_errors), lease->errors_baseline",
    "per-lease errors delta",
)
require(
    "READ_ONCE(wg_mix_faketcp_probes_ready) && !nmissed && !errors",
    "health based on per-lease deltas",
)

# kretprobe capacity must scale at module init, never in a static initializer.
require("unsigned int cpu_ids = nr_cpu_ids;", "Linux 5.15 CPU-count API")
require(
    "max_t(unsigned int, WG_MIX_FAKETCP_KPROBE_MAXACTIVE,\n"
    "\t\t\t 2U * cpu_ids)",
    "maxactive lower bound and CPU scaling",
)
require(
    "wg_mix_faketcp_change_type_probe.maxactive = (int)maxactive;",
    "change_type dynamic maxactive",
)
require(
    "wg_mix_faketcp_change_proto_probe.maxactive = (int)maxactive;",
    "change_proto dynamic maxactive",
)
if re.search(r"^\s*\.maxactive\s*=", SOURCE, re.MULTILINE):
    FAILURES.append("maxactive must not use a runtime-dependent static initializer")
require_order(
    "ret = wg_mix_faketcp_configure_maxactive();",
    "ret = register_kretprobes(",
    "dynamic maxactive configuration before probe registration",
)

# Keep the module warning-clean across the supported 5.15 and 7.x headers.
require(
    "(struct wg_mix_faketcp_change_type_parameters *)ri->data;",
    "typed change_type kretprobe private data",
)
require(
    "(struct wg_mix_faketcp_change_proto_parameters *)ri->data;",
    "typed change_proto kretprobe private data",
)
require(
    "wg_mix_faketcp_counter_delta(u64 current_value, u64 baseline)",
    "counter parameter that cannot collide with the kernel current macro",
)
require(".llseek = noop_llseek,", "portable non-mutating ioctl-device llseek")
if "u64 current," in SOURCE or ".llseek = no_llseek," in SOURCE:
    FAILURES.append("removed Linux 7.x-incompatible identifiers are forbidden")

# Keep known syntax/comment regressions from returning during concurrent edits.
if re.search(r"return\s+0;\s*return\s+0;", SOURCE):
    FAILURES.append("duplicate consecutive return 0 statements")
if "ordinary BPF traffic neither" in SOURCE:
    FAILURES.append("entry-handler comment must not overstate maxactive behavior")
if "Errors and\n * nmissed are deltas since this open file description" not in UAPI:
    FAILURES.append("UAPI must document errors/nmissed as per-open deltas")

if FAILURES:
    print(f"FAIL: {SOURCE_PATH}", file=sys.stderr)
    for failure in FAILURES:
        print(f"  - {failure}", file=sys.stderr)
    raise SystemExit(1)

print(f"PASS: {SOURCE_PATH}")
