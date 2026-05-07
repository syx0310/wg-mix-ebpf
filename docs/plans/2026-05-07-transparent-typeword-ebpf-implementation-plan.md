# Transparent WireGuard Type Word eBPF 实现 Plan

状态：实现计划。测试计划后续单独补充。

## 1. 目标边界

本项目实现一个透明 WireGuard `type_word` transform layer：

```text
standard kernel WireGuard + eBPF
  <-> Internet
  <-> standard kernel WireGuard + eBPF
```

数据面只做：

```text
egress: standard type_word -> mixed type_word
ingress: mixed type_word -> standard type_word
```

明确不做：

```text
DDNS
peer endpoint refresh
wg set / wg syncconf
WireGuard config 修改
IP/UDP 地址改写
IP/UDP 端口改写
native wireguard-mix direct interop
```

原因：native `wireguard-mix` 在 WireGuard 实现内部使用 mixed `type_word` 参与 MAC 计算；本项目是在标准 kernel WireGuard 算完 MAC 后改线上前 4 字节，接收端必须先由 eBPF 还原为标准值，才能交给标准 WireGuard 验证。

## 2. 硬性 Invariant

```text
只改 WireGuard UDP payload 前 4 字节。
不改外层 IP 地址。
不改 UDP 源端口或目的端口。
不改 sender_index / receiver_index / counter / MAC / ciphertext。
不把 peer endpoint / AllowedIPs / latest handshake 放进 BPF dataplane。
profile 必须是 standard <-> mixed 的双向一一映射。
双方必须部署同一套 transparent eBPF transform。
```

## 3. 配置草案

```yaml
version: 1
mode: transparent-typeword

underlays:
  - name: wan
    type: openwrt-interface

  - name: pppoe-wan
    type: netdev

wireguards:
  - name: wg0
    profile: mix-default

  - name: wg1
    config: /opt/wireguard/wg1.conf
    profile: mix-alt

profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
    index:
      mode: none

  mix-alt:
    type_word:
      initiation: 0xf658c2e6
      response: 0x0686b1d0
      cookie_reply: 0x075ae5e0
      transport_data: 0x13dff06b
    index:
      mode: none

fwmark_policy:
  mode: config-required

runtime:
  poll_interval: 5s
  require_nonzero_fwmark: true
  strict_runtime_fwmark: true
  allow_zero_fwmark_fallback: false

startup_guard:
  mode: nft-temporary-drop
  egress:
    match: fwmark
  ingress:
    match: config-listen-port-if-present
    random_listen_port_behavior: best-effort

underlay_overlap_policy: reject

policy:
  non_managed_udp: pass

  managed_egress_map_miss: drop
  managed_egress_bad_type: drop
  managed_egress_bad_length: drop
  egress_managed_ipv6_ext_header: drop

  managed_ingress_map_miss: pass
  managed_ingress_bad_type: drop
  managed_ingress_bad_length: drop
  ingress_managed_ipv6_ext_header: pass

  ipv4_first_fragment: drop
  ipv4_non_first_fragment:
    ingress: pass
    egress_if_managed_fwmark: drop
    optional_drop_all_on_underlay: false
  ipv6_fragment: drop

  startup_fail_mode: fail_closed_for_managed_flows
```

`wireguards[].config` 未指定时默认读取：

```text
/etc/wireguard/<name>.conf
```

配置原则：

```text
不要在 wg-mix-ebpf 配置中重复 WireGuard 原生字段。
WireGuard 原生字段从 wg config 或运行态读取。
缺失必要 WireGuard 原生字段时按 policy 报错或拒绝管理。
```

## 4. FwMark 来源策略

生产默认：

```yaml
fwmark_policy:
  mode: config-required
```

语义：

```text
必须从 WireGuard config 的 [Interface] 读取 FwMark。
config 缺失 FwMark 时 log error。
require_nonzero_fwmark=true 且 FwMark 为 0/off 时 log error。
strict_runtime_fwmark=true 时，config FwMark 与 runtime FirewallMark 不一致视为 error。
agent 不修改 FwMark。
dataplane map 使用 runtime FirewallMark。
```

可选兼容模式：

```yaml
fwmark_policy:
  mode: runtime-accepted
```

语义：

```text
config 缺失 FwMark 也允许。
只要 runtime FirewallMark 非零即可管理。
status 标记该接口为 runtime-derived fwmark。
```

OpenWrt 适配模式：

```yaml
fwmark_policy:
  mode: openwrt-uci
```

语义：

```text
从 UCI/netifd 派生期望 FwMark。
不强依赖 /etc/wireguard/<name>.conf。
运行态 FirewallMark 仍是 dataplane source of truth。
```

MVP 默认只实现 `config-required`，其余模式保留 schema 和错误提示。

## 5. 运行态信息分类

进入 BPF map：

```text
runtime ListenPort
runtime FirewallMark
wg_if_id
profile_id
underlay ifindex
generation
```

不进入 BPF map：

```text
peer Endpoint
peer LastHandshakeTime
peer rx/tx counters
AllowedIPs
DDNS hostname
```

`status` 可以读取并展示 peer 信息，但 peer 信息不得驱动 dataplane rule 生成、reload 或 BPF map 更新。

## 6. Type Word 定义

WireGuard UDP payload 前 4 字节按 wire little-endian `uint32` 定义。

标准值：

```text
initiation      0x00000001
response        0x00000002
cookie_reply    0x00000003
transport_data  0x00000004
```

`wireguard-mix-wire-values-v1` 是本项目固定内置常量，不随上游 `wireguard-mix` 漂移。它只表示复用一组线上 `type_word` 常量，不表示可以和 native `wireguard-mix` 直接互通。

BPF 实现要求：

```text
读取后 le32_to_cpu。
写入前 cpu_to_le32。
或直接按 4 个 u8 比较/写入。
禁止直接用 host-endian 常量比较 packet memory。
```

Profile 校验：

```text
standard type_word 固定为 1/2/3/4。
mixed type_word 必须 4 个互不相同。
mixed type_word 默认不得等于 1/2/3/4，除非显式 allow_passthrough。
standard_to_mixed 与 mixed_to_standard 必须互为逆映射。
```

## 7. BPF Maps

```text
control_map
  active_generation
  abi_version
  flags

profile_map
  profile_id ->
    generation
    standard_to_mixed[4]
    mixed_to_standard[4]
    policy_flags

managed_fwmark_map
  fwmark + underlay_ifindex/wildcard ->
    generation
    action_on_rule_miss

egress_rule_map
  family/wildcard + fwmark + src_port + underlay_ifindex/wildcard ->
    generation
    profile_id
    wg_if_id
    action

ingress_listener_map
  family + dst_port + underlay_ifindex/wildcard ->
    generation
    profile_id
    wg_if_id
    action

stats_map
  BPF_MAP_TYPE_PERCPU_ARRAY
  counters by direction/action/reason/profile
```

`managed_fwmark_map` 用途：

```text
实现 managed_egress_map_miss: drop。
在 egress_rule_map miss 时判断该 mark 是否受管。
runtime ListenPort 未 ready 时可先按 managed FwMark fail closed。
startup guard 和 egress 泄漏保护共用同一语义。
```

查找优先级固定：

```text
先查 exact underlay_ifindex。
再查 wildcard underlay。
```

Validate 必须拒绝同一 generation 内的歧义规则。例如 exact underlay 和 wildcard underlay 对同一端口/mark 映射到不同 profile 时，除非显式允许并遵循固定优先级，否则报错。

## 8. 数据面流程

Egress：

```text
TC egress on underlay
  -> parse link type
  -> parse IPv4/IPv6 + UDP
  -> detect fragment/ext header
  -> match runtime FirewallMark + UDP src_port + underlay_ifindex
  -> if rule miss, check managed_fwmark_map
  -> managed miss: drop/pass by policy
  -> validate WG payload length
  -> rewrite standard type_word -> mixed type_word
  -> update UDP checksum
  -> pass
```

Ingress：

```text
TC ingress on underlay
  -> parse link type
  -> parse IPv4/IPv6 + UDP
  -> detect fragment/ext header
  -> match UDP dst_port + underlay_ifindex
  -> validate WG payload length
  -> rewrite mixed type_word -> standard type_word
  -> update UDP checksum
  -> pass
```

Ingress 不看 peer endpoint。

## 9. WG 长度校验

```text
handshake initiation: UDP payload length == 148
handshake response: UDP payload length == 92
cookie reply: UDP payload length == 64
transport data: UDP payload length >= 32
transport data: (UDP payload length - 32) % 16 == 0
```

## 10. Checksum / SKB 约束

实现要求：

```text
读取 type_word 可用 direct packet access。
写入优先用 bpf_skb_store_bytes()。
必要时用 bpf_skb_pull_data() 处理 non-linear skb。
只改 4 字节时用 bpf_l4_csum_replace() 做增量更新。
不要同时手工 checksum 和 BPF_F_RECOMPUTE_CSUM 重复更新。
helper 调用后必须重新校验 packet pointer。
bpf_skb_pull_data() 只在必要时调用，不默认调用。
```

Checksum 策略：

```text
IPv4 UDP checksum == 0:
  不调用 l4 checksum replace，直接 store type_word，默认保持 0。

IPv6 UDP checksum == 0:
  drop + counter，因为 IPv6 UDP checksum 必须有效。
```

Offload/GSO/GRO 属于必须实测的工程风险，不在 BPF 逻辑中假设某个 NIC 行为。

## 11. Fragment / IPv6 Extension

MVP 不支持 outer fragmentation transform。

策略：

```text
IPv4 first fragment:
  如果能解析 UDP 且命中 managed rule，按 ipv4_first_fragment 策略处理。

IPv4 non-first fragment:
  ingress 默认 pass + counter。
  egress 如果能依赖 managed fwmark，默认 drop + counter。
  可选 drop_all_on_underlay 作为更强生产保护。

IPv6 Fragment Header:
  默认 drop + counter。

IPv6 Hop-by-Hop / Routing / Destination / AH / ESP / unknown:
  egress managed 默认 drop + counter，避免泄漏 standard type_word。
  ingress 默认 pass + counter，生产可配置为 drop。
```

文档要求通过 WireGuard MTU / underlay MTU 避免外层 UDP 分片。

## 12. Startup Guard

`fail_closed_for_managed_flows` 必须有实际机制。

支持三种模式：

```text
ordered-service:
  agent 先 attach BPF 和填充 maps，再启动或放行 WireGuard。

nft-temporary-drop:
  agent ready 前用 nft/iptables 临时 drop 受管 wg fwmark/listen_port 流量。
  BPF ready 后移除 guard。

best-effort:
  不保证启动窗口不泄漏，仅开发测试使用。
```

生产默认：

```yaml
startup_guard:
  mode: nft-temporary-drop
```

nft guard 语义：

```text
egress:
  BPF ready 前 drop meta mark == managed FwMark 的 outgoing UDP。

ingress:
  如果 config ListenPort 存在，临时 drop UDP dst port == config ListenPort。
  如果 config ListenPort 缺失或 runtime 使用随机端口，ingress guard 为 best-effort。
```

Crash 行为：

```text
agent 启动时先清理本 agent 旧 nft table。
guard 使用专用 table/chain/comment。
BPF ready 后事务性删除 guard。
如果 agent 在 BPF ready 前崩溃，guard 保留，fail closed。
如果 agent 在 BPF ready 后崩溃，BPF filter 仍在，guard 已删除。
```

## 13. Reload / Reconcile

命令：

```bash
wg-mix-ebpf validate
wg-mix-ebpf reload
wg-mix-ebpf status
wg-mix-ebpf dump
wg-mix-ebpf detach
```

Reload 做：

```text
重新读取 agent config。
按 fwmark_policy 读取/校验 WireGuard FwMark。
重新读取本机运行态 ListenPort / FirewallMark / link state。
校验 config/derived FwMark 与 runtime FirewallMark。
重新解析 underlay 当前 ifname/ifindex。
使用 generation 原子切换 maps。
underlay 变化时增量 attach/detach。
```

Reload 不做：

```text
不修改 WireGuard config。
不执行 wg set。
不执行 wg syncconf。
不重启 wg interface。
不解析 DDNS。
不更新 peer endpoint。
不因 peer endpoint 变化更新 BPF maps。
```

Reload 失败语义：

```text
reload 是 prepare -> validate -> attach/update inactive generation -> commit。
commit 前失败：保留旧 active_generation。
commit 后失败：进入 degraded 状态，不能半切。
任何 validate / runtime reconcile / attach / map write 失败，都不得清空当前 active generation。
```

Generation 流程：

```text
写新 generation profile entries。
写新 generation managed_fwmark/egress/ingress entries。
确认 attach state。
更新 active_generation。
BPF 校验 entry.generation == active_generation。
清理旧 generation。
```

Profile 变更策略：

```text
MVP: profile 变更是破坏性操作，需要两端维护窗口协调 reload。
P1: 支持 ingress dual-accept rolling profile rotation。
```

P1 预留结构：

```text
ingress_profile_set_map
  listener -> accepted profile set

egress_rule_map
  rule -> single active egress profile
```

## 14. OpenWrt / Underlay Parser

Underlay 支持：

```text
openwrt-interface
netdev
```

Parser/attach 矩阵：

```text
Ethernet netdev:
  parse Ethernet + optional VLAN + IPv4/IPv6

VLAN netdev:
  优先按 skb protocol / network header 解析，实测确认

PPPoE logical netdev:
  优先 attach 到 pppoe-wan，按 skb protocol / network header 解析 IP

Physical PPPoE carrier:
  fallback，不作为 MVP 默认；需要 PPPoE header parser

Bridge:
  仅确认 WG outer packet 实际经过该 bridge 时 attach

wwan/tun-like:
  按 skb protocol / network header 解析，按平台实测归类
```

实现不假设固定 L2 偏移，结合 `skb->protocol`、link type 和 relative load helper。

Underlay overlap validate：

```text
默认 underlay_overlap_policy: reject。
同一条实际路径上，只允许一个 transform attach 点。
OpenWrt interface 解析出的 netdev 与显式 netdev 重复时去重。
PPPoE 场景优先 attach 到 pppoe-wan 这类 L3-ish 逻辑设备。
物理 PPPoE carrier 只作为 fallback，不与 pppoe-wan 同时启用 transform。
```

调试预留：

```yaml
underlay_overlap_policy: allow_parse_only_lower
```

语义：

```text
上层逻辑设备做 transform。
下层物理设备只统计，不 rewrite。
```

Attach/detach 约束：

```text
只管理本 agent 创建的 TC filter handle。
detach 只删除本 agent 的 filter，不删除整个 clsact qdisc。
避免误删 SQM/Cilium/netem/其他 TC BPF。
```

## 15. Netns 与本机 NAT 假设

MVP 假设：

```text
WireGuard UDP socket 位于 agent 所在 netns。
underlay TC attach 也在同一 netns。
不支持 moved WireGuard interface / cross-netns socket 场景。
```

配置预留：

```yaml
wireguards:
  - name: wg0
    netns: root
```

P1 可以支持进入指定 netns 读取 wg device、解析 underlay、attach TC。

本机 NAT/mark 假设：

```text
本 agent 不支持本机防火墙在 underlay TC egress 前改写 WireGuard outer UDP src_port。
本 agent 不支持本机防火墙在 underlay TC egress 前清除或覆盖 skb mark。
```

如果必须兼容本机 mark 覆盖或源端口改写，需要单独设计更强的 profile/interface 标识方式。

## 16. Feature Probe / Loader

MVP loader：

```text
cilium/ebpf + bpf2go
```

启动探测：

```text
bpf syscall
TC SCHED_CLS
clsact
ingress/egress attach
kmod-sched-bpf / cls_bpf / act_bpf
BPF JIT
架构和 endian object 支持
```

支持矩阵：

```text
MVP cross-platform = Ubuntu/Arch/OpenWrt on x86_64/aarch64。
Tier 1: x86_64, aarch64
Tier 2: riscv64/loong64/其他 64-bit，需实测
MVP 不支持: mips32/armv7 32-bit OpenWrt
```

如需 32-bit OpenWrt，后续单独设计 loader/verifier 兼容方案。

## 17. 实现里程碑

```text
1. 固化 MVP 边界和 non-goals。
2. 定义 config schema、profile ABI、policy、stats reason、generation。
3. 实现 WireGuard config parser，按 fwmark_policy 读取/校验 FwMark。
4. 实现 validate：FwMark 必填/非零/runtime 一致、type_word 唯一、underlay 无歧义。
5. 接入 wgctrl，读取本机 runtime ListenPort / FirewallMark / link state。
6. 实现 managed_fwmark_map 与 egress fail-closed 语义。
7. 实现 OpenWrt/netdev underlay resolver 和 overlap validate。
8. 实现 startup guard。
9. 实现 BPF IPv4 parser、UDP parser、WG length validation。
10. 实现 BPF IPv6 普通 UDP parser 和 ext/fragment 策略。
11. 实现 type_word rewrite 和 checksum 修正。
12. 实现 egress / ingress maps 与 exact/wildcard 查找。
13. 实现 per-CPU stats。
14. 实现 TC attach/detach，不误删其他 TC filter。
15. 实现 reload generation 切换和失败保留旧 generation。
16. 实现 status/dump/validate/reload/detach CLI。
17. 后续单独编写测试 plan，覆盖 netns、OpenWrt、fragment、offload、performance。
```

## 18. 后续测试 Plan 提醒

测试计划不在本文展开，但实现时需要为以下测试预留可观测性：

```text
standard WG + eBPF <-> standard WG + eBPF 正向互通
standard WG + eBPF <-> native wireguard-mix 负向握手失败
IPv4 / IPv6
固定 ListenPort / 随机 ListenPort
config 缺失 FwMark / FwMark=0/off / runtime 不一致
managed egress map miss fail-closed
underlay overlap / parse_only / double rewrite 防护
startup guard crash 行为
profile 破坏性切换
OpenWrt eth0 / eth0.2 / pppoe-wan / br-wan / ifindex 重拨变化
checksum offload on/off
GSO/GRO on/off
IPv4 first fragment / IPv4 non-first fragment / IPv6 Fragment Header
big-endian BPF object 构建和 map ABI 测试
本机 nft mark overwrite / src port rewrite 负向测试
性能测试：无 BPF、parse only、rewrite+checksum、stats on/off
```
