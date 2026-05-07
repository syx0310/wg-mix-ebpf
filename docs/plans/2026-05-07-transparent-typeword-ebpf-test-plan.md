# Transparent WireGuard Type Word eBPF 测试 Plan

状态：测试计划。当前机器仅进行单元测试与本地可模拟测试；真机、OpenWrt、offload、性能和长稳调试将在其他机器执行。

关联实现计划：

```text
docs/plans/2026-05-07-transparent-typeword-ebpf-implementation-plan.md
```

## 1. 测试目标

本测试计划围绕实现计划的 MVP 边界展开：

```text
只做透明 WireGuard UDP payload 前 4 字节 type_word 双向 transform。
不改 IP/UDP tuple。
不处理 DDNS。
不处理 peer endpoint refresh。
不修改 WireGuard config。
不支持 native wireguard-mix direct interop。
```

测试目标：

```text
协议正确性：
  standard kernel WireGuard + eBPF <-> standard kernel WireGuard + eBPF 可正常握手和传输。

边界正确性：
  eBPF 只改 UDP payload 前 4 字节，不改 IP/UDP 地址端口、index、counter、MAC、ciphertext。

fail-closed 正确性：
  受管 egress 在 map miss、bad type、bad length、unsupported IPv6 extension、fragment 等情况下不泄漏 standard type_word。

控制面正确性：
  config parser、FwMark policy、runtime state reconcile、generation、startup guard、attach/detach 符合实现计划。

平台正确性：
  MVP 以 x86_64/aarch64 64-bit Linux 为主；mips32/armv7 OpenWrt 不属于 MVP。

OpenWrt underlay 正确性：
  netdev/openwrt-interface/VLAN/PPPoE/bridge/ifindex 变化/overlap policy 在外部 OpenWrt 环境验证。

稳定性和性能：
  外部机器验证 offload、GSO/GRO、reload、crash、长稳和性能。
```

## 2. 测试分层

| 层级 | 名称 | 当前机器执行 | 目标环境 | 说明 |
| --- | --- | --- | --- | --- |
| L0 | 单元测试 | 是 | 当前机器 | 不依赖 root、内核 TC、真实 WireGuard |
| L1 | 本地可模拟测试 | 视实现情况 | 当前机器 | 可包括 mock、纯 Go packet builder、ABI 检查 |
| L2 | BPF packet/verifier | 否 | Linux root VM | 需要 Linux BPF/TC/test-run 能力 |
| L3 | netns 集成 | 否 | Linux root VM | 需要 network namespace、WireGuard、tc |
| L4 | VM OS 矩阵 | 否 | 外部 VM 池 | Ubuntu/Arch/OpenWrt x86_64/aarch64 |
| L5 | 真机/OpenWrt/offload | 否 | 外部真机 | 物理 NIC、PPPoE、VLAN、GRO/GSO/offload |
| L6 | 长稳/性能 | 否 | 外部真机或 VM | 24h/72h、benchmark、故障注入 |

当前机器只要求完成 L0，若后续实现提供无特权 mock/synthetic 工具，可补充 L1。

## 3. 当前机器测试范围

当前机器只做：

```text
Go 单元测试。
配置解析测试。
WireGuard config parser 测试。
profile/type_word 测试。
map key/value ABI 纯结构测试。
runtime reconcile mock 测试。
startup guard 规则生成 mock 测试。
underlay resolver mock 测试。
attach/detach 计划生成 mock 测试。
pcap/synthetic packet helper 的纯函数测试。
```

当前机器不做：

```text
真实 BPF load。
真实 TC attach。
真实 WireGuard tunnel。
network namespace 集成。
OpenWrt underlay 实测。
物理 NIC offload/GSO/GRO。
性能 benchmark。
长稳。
native wireguard-mix 负向互通。
```

## 4. 当前机器单元测试计划

### 4.1 Config Parser

| ID | 测试项 | 输入 | 期望 |
| --- | --- | --- | --- |
| U-CONF-001 | 默认 wg config 路径 | `wireguards[].config` 缺失 | 展开为 `/etc/wireguard/<name>.conf` |
| U-CONF-002 | 显式 wg config 路径 | `/opt/wireguard/wg1.conf` | 正确读取 |
| U-CONF-003 | FwMark 十六进制 | `FwMark = 0x10000002` | 解析为 uint32 |
| U-CONF-004 | FwMark 十进制 | `FwMark = 268435458` | 解析为相同 uint32 |
| U-CONF-005 | FwMark 缺失 | `config-required` | validate error |
| U-CONF-006 | FwMark 为 `0` | `require_nonzero_fwmark=true` | validate error |
| U-CONF-007 | FwMark 为 `off` | `require_nonzero_fwmark=true` | validate error |
| U-CONF-008 | ListenPort 缺失 | config 无 ListenPort | 不报错，等待 runtime |
| U-CONF-009 | 不泄漏私钥 | config 含 `PrivateKey` | 日志/status 不出现私钥 |
| U-CONF-010 | 未实现 policy | `runtime-accepted` / `openwrt-uci` | schema 可识别，MVP 返回明确 unsupported |
| U-CONF-011 | 注释与空行 | wg config 含注释、空行 | 正确跳过 |
| U-CONF-012 | 大小写和空格 | `FwMark= 0x1` / `FwMark =0x1` | 正确解析或明确报错 |

### 4.2 Profile / Type Word

| ID | 测试项 | 期望 |
| --- | --- | --- |
| U-PROF-001 | 标准 type_word 固定 | standard side 固定为 `1/2/3/4` |
| U-PROF-002 | mixed 值唯一 | 4 个 mixed 值重复时报错 |
| U-PROF-003 | mixed 等于 standard | 默认报错，除非显式 `allow_passthrough` |
| U-PROF-004 | 双向映射互逆 | `standard_to_mixed` 与 `mixed_to_standard` 不互逆时报错 |
| U-PROF-005 | little-endian wire value | `0xf658c2e6` 对应 wire bytes `e6 c2 58 f6` |
| U-PROF-006 | preset 固定版本 | `wireguard-mix-wire-values-v1` 不依赖上游运行态 |
| U-PROF-007 | ABI version mismatch | validate/load 返回明确错误 |
| U-PROF-008 | index mode | MVP 只接受 `none`，其他值返回 unsupported |

### 4.3 Rule / Map 生成

| ID | 测试项 | 期望 |
| --- | --- | --- |
| U-MAP-001 | egress rule key | 包含 family、fwmark、src_port、underlay_ifindex |
| U-MAP-002 | ingress listener key | 包含 family、dst_port、underlay_ifindex |
| U-MAP-003 | exact underlay 优先 | exact 命中优先于 wildcard |
| U-MAP-004 | wildcard fallback | exact miss 后命中 wildcard |
| U-MAP-005 | exact/wildcard 冲突 | validate reject 或按固定优先级无歧义 |
| U-MAP-006 | managed_fwmark_map | egress rule miss 时可识别 managed mark |
| U-MAP-007 | same fwmark group | 同 FwMark + 不同 src_port 可区分不同 wg |
| U-MAP-008 | 多 wg / 多 profile | 生成无歧义 entries |
| U-MAP-009 | generation tag | 所有 map value 写入新 generation |
| U-MAP-010 | active_generation commit | commit 前失败不影响旧 active |
| U-MAP-011 | managed miss action | managed mark + rule miss 生成 drop policy |

### 4.4 Runtime Reconcile Mock

使用 mock wgctrl、mock netlink、mock OpenWrt resolver。

| ID | 场景 | 期望 |
| --- | --- | --- |
| U-RT-001 | wg interface 不存在 | 不写 active map，status 标记 missing |
| U-RT-002 | wg down | 跳过或 error，按 policy |
| U-RT-003 | runtime ListenPort 变化 | 生成新 ingress/egress port rule |
| U-RT-004 | runtime FirewallMark 与 config 不一致 | strict 模式 reload fail，旧 generation 保留 |
| U-RT-005 | underlay ifindex 变化 | 生成 detach old / attach new plan |
| U-RT-006 | peer endpoint 变化 | 不触发 BPF map 更新 |
| U-RT-007 | peer LastHandshake 变化 | 只影响 status，不影响 dataplane |
| U-RT-008 | reload 中 map write 失败 | 旧 generation 保留 |
| U-RT-009 | attach 失败 | 旧 generation 保留 |
| U-RT-010 | commit 后异常 | status 进入 degraded，不半清空 |

### 4.5 Startup Guard Mock

| ID | 场景 | 期望 |
| --- | --- | --- |
| U-GUARD-001 | nft-temporary-drop 生成 | egress 匹配 managed FwMark |
| U-GUARD-002 | config ListenPort 存在 | ingress 临时 drop UDP dst port |
| U-GUARD-003 | random ListenPort | ingress best-effort 标记清晰 |
| U-GUARD-004 | agent 启动清理旧 table | 只清理本 agent table |
| U-GUARD-005 | BPF ready 后删除 guard | 事务性删除 |
| U-GUARD-006 | ready 前 crash | guard 保留 |
| U-GUARD-007 | ready 后 crash | BPF filter 仍在，guard 已删除 |
| U-GUARD-008 | 多 managed FwMark | 生成多条 egress guard 规则 |

### 4.6 Underlay Resolver Mock

| ID | 场景 | 期望 |
| --- | --- | --- |
| U-UND-001 | `type: netdev` | 解析 ifname/ifindex |
| U-UND-002 | `type: openwrt-interface` | 解析到当前 l3_device |
| U-UND-003 | OpenWrt wan -> pppoe-wan | link_type 正确 |
| U-UND-004 | VLAN netdev | 标记 VLAN / network-header parse |
| U-UND-005 | bridge | 标记 bridge，仅确认路径时 attach |
| U-UND-006 | overlap: wan + pppoe-wan | reject 或 dedupe |
| U-UND-007 | overlap: pppoe-wan + lower eth | 默认 reject |
| U-UND-008 | allow_parse_only_lower | lower 只统计不 rewrite |
| U-UND-009 | ifindex 重拨变化 | 生成增量 attach/detach |
| U-UND-010 | 无效 underlay | validate error |

### 4.7 Attach / Detach Plan Mock

| ID | 场景 | 期望 |
| --- | --- | --- |
| U-TC-001 | clsact 已存在 | 不计划删除已有 qdisc |
| U-TC-002 | 其他 TC filter 存在 | 不误删 |
| U-TC-003 | attach 本 agent handle | handle/priority 可追踪 |
| U-TC-004 | detach | 只删除本 agent filter |
| U-TC-005 | attach ingress/egress | 两方向均存在 |
| U-TC-006 | attach 失败回滚 | 旧状态保留 |

### 4.8 Packet Helper Pure Function

这些测试不加载 BPF，只测试 Go 侧 packet builder / parser / pcap verifier helper。

| ID | 场景 | 期望 |
| --- | --- | --- |
| U-PKT-001 | 读取 UDP payload 前 4 字节 | 返回 wire little-endian type_word |
| U-PKT-002 | 验证 mixed type_word | pcap helper 可识别 mixed 值 |
| U-PKT-003 | 验证 standard 泄漏 | helper 可扫描 `01/02/03/04 00 00 00` |
| U-PKT-004 | IP/UDP tuple 对比 | rewrite 前后 tuple 不变 |
| U-PKT-005 | IPv4 UDP checksum helper | 可验证 checksum |
| U-PKT-006 | IPv6 UDP checksum helper | 可验证 checksum |
| U-PKT-007 | WG 长度分类 | 148/92/64/32+16n 分类正确 |

## 5. 当前机器建议自动化目标

当前机器建议先提供：

```bash
make test-unit
make test-unit-race
make test-lint
make test-config
make test-profile
make test-reconcile
```

如果实现中有纯 Go packet helper：

```bash
make test-packet-helper
```

当前机器不要求这些目标真实可运行：

```bash
make test-bpf-pkt
make test-netns
make test-openwrt-vm
make test-hw
make bench
make soak
```

这些目标可以先在 Makefile 中保留为外部环境目标，并在缺少 Linux/root/BPF 能力时输出明确 skip 原因。

## 6. 外部 Linux VM 测试计划

以下测试不在当前机器执行。

### 6.1 BPF Packet-Level

优先使用 kernel BPF program test-run；如果 TC SCHED_CLS test-run 不可用，则 fallback 到 netns + tc attach + veth 发包。

必须覆盖：

```text
IPv4 egress standard -> mixed
IPv4 ingress mixed -> standard
IPv6 egress standard -> mixed
IPv6 ingress mixed -> standard
egress rule hit
egress rule miss + managed_fwmark hit -> drop
egress rule miss + unmanaged fwmark -> pass
ingress listener hit
ingress listener miss -> pass
generation mismatch
exact/wildcard priority
bad length drop
IPv4 checksum nonzero update
IPv4 checksum zero keep zero
IPv6 checksum zero drop
IPv4 first fragment drop
IPv4 non-first ingress pass + counter
IPv4 non-first egress managed drop + counter
IPv6 Fragment Header drop
IPv6 extension egress managed drop
IPv6 extension ingress pass + counter
Ethernet/VLAN/PPPoE logical/bridge/tun-like parser policy
```

### 6.2 Netns Integration

拓扑：

```text
nsA                    nsR                         nsB
wg0                    router                      wg0
vethA <-------------> vethRA   vethRB <----------> vethB
```

必须覆盖：

```text
IPv4 outer + fixed ListenPort
IPv6 outer + fixed ListenPort
IPv4 outer + random ListenPort
IPv6 outer + random ListenPort
inner IPv4 over WG
inner IPv6 over WG
rekey
PersistentKeepalive
A 开 eBPF，B 不开 eBPF，握手失败
profile mismatch，握手失败
egress map miss drop，pcap 不出现 standard type_word
multi wg
same FwMark + different ListenPort
reload success
reload failure preserve old generation
runtime ListenPort change
runtime FwMark mismatch strict fail
underlay ifindex rebuild
peer endpoint change 不改变 BPF generation
startup guard ready 前/后 crash 行为
detach 只删本 agent filter
```

## 7. 外部 VM OS 矩阵

推荐 VM 模板：

```text
2 x Ubuntu x86_64
2 x Arch x86_64
2 x OpenWrt x86_64
1 x Linux/OpenWrt router x86_64
2 x Ubuntu/OpenWrt aarch64 endpoint
```

每个场景最多并发 3 台 VM：

```text
endpoint A + router/impairment + endpoint B
```

必跑 pairing：

| ID | A | Router | B | 频率 |
| --- | --- | --- | --- | --- |
| V-OS-001 | Ubuntu x86_64 | Linux x86_64 | Ubuntu x86_64 | nightly |
| V-OS-002 | Arch x86_64 | Linux x86_64 | Arch x86_64 | nightly |
| V-OS-003 | Ubuntu x86_64 | Linux x86_64 | Arch x86_64 | nightly |
| V-OS-004 | Ubuntu x86_64 | Linux/OpenWrt x86_64 | OpenWrt x86_64 | nightly |
| V-OS-005 | OpenWrt x86_64 | Linux/OpenWrt x86_64 | OpenWrt x86_64 | release |
| V-OS-006 | Ubuntu aarch64 | Linux/OpenWrt router | Ubuntu aarch64 | release |
| V-OS-007 | Ubuntu x86_64 | Linux/OpenWrt router | OpenWrt aarch64 | release |
| V-OS-008 | OpenWrt aarch64 | Linux/OpenWrt router | OpenWrt aarch64 | release 或真机替代 |

## 8. 外部 OpenWrt 专项

以下测试在 OpenWrt VM 或真机执行。

```text
type: netdev + eth0
type: openwrt-interface + wan
wan -> pppoe-wan resolver
eth0.2 VLAN
br-wan
pppoe-wan logical netdev
wan + pppoe-wan overlap reject/dedupe
pppoe reconnect ifindex change
hotplug event triggers reconcile
kmod 缺失 feature probe error
BPF JIT unavailable warning/degraded
OpenWrt endpoint <-> Linux endpoint
OpenWrt <-> OpenWrt
CPU-bound throughput baseline
24h long-run
```

## 9. 外部真机 / Offload / 性能

推荐真机：

```text
2 台 x86_64 Linux 主机，至少 2 个物理网口。
1 台 OpenWrt aarch64 或 x86_64 路由器。
1 台第二 OpenWrt 设备，最好不同 SoC/网卡。
```

最低真机：

```text
2 台 x86_64 Linux 主机 + 1 台 OpenWrt 设备。
```

必须覆盖：

```text
checksum offload on/off
GRO on/off
GSO on/off
TSO on/off
veth vs virtio vs physical NIC
PPPoE
VLAN
IPv6
baseline standard WireGuard
tc pass-only
parse-only
rewrite+checksum
rewrite+checksum+stats
map miss flood
bad packet flood
multi-wg
OpenWrt CPU-bound
```

性能指标：

```text
throughput
pps
CPU user/system/softirq
latency p50/p95/p99
packet loss
WireGuard rx/tx counters
BPF stats counters
drops by reason
reload interruption time
map entry count
agent RSS
```

初期只设 warning 门槛：

```text
x86_64 rewrite+checksum 相比 baseline 吞吐下降 >10%: warning
x86_64 rewrite+checksum+stats 相比 baseline 下降 >15%: warning
OpenWrt 下降 >25%: warning
任何 correctness failure: fail
任何 standard type_word 泄漏: fail
```

## 10. 外部长稳和故障注入

```text
steady iperf UDP/TCP 24h
low-rate keepalive 24h
每 5 分钟 reload，持续 4h
每 10 分钟 underlay ifindex 重建，持续 4h
agent kill/restart，持续 4h
OpenWrt PPPoE 重拨，持续 4h
map entry leak 24h
stats overflow/rollover 24h
```

通过标准：

```text
无 tunnel 长时间中断。
无 unexpected standard type_word 泄漏。
无 map entry 持续增长。
无异常 drop counter 激增。
reload/reconcile 后可自动恢复。
```

## 11. 安全 / 泄漏验证

核心目标：

```text
受管 egress 绝不能在线上泄漏 standard WireGuard type_word。
```

必须验证：

```text
agent 未启动但 startup guard 开启，无 standard 泄漏。
BPF 未 attach，guard drop。
map 空，managed_fwmark drop。
egress_rule miss，drop。
bad standard type，drop。
bad length，drop。
IPv6 ext unsupported egress，drop。
fragment egress，drop。
reload 半更新，不泄漏。
profile mismatch，握手失败且不泄漏 standard。
detach 是显式用户操作，status 提示风险。
other TC filters 不被误删。
```

pcap verifier 需要支持：

```text
从 UDP payload offset 读取前 4 字节。
验证 mixed type_word。
扫描 standard type_word: 01 00 00 00 / 02 00 00 00 / 03 00 00 00 / 04 00 00 00。
验证 IP/UDP tuple 未变化。
验证 IPv4/IPv6 checksum。
```

## 12. 必需观测性

为了让测试可自动判定，实现必须提供：

```text
status 显示 active_generation。
status 显示每个 wg 的 runtime ListenPort / FirewallMark。
status 显示每个 underlay 的 ifindex / attach state / link_type。
dump 显示 profile_map。
dump 显示 egress_rule_map。
dump 显示 ingress_listener_map。
dump 显示 managed_fwmark_map。
stats 显示 per-CPU 聚合 counters。
stats 按 direction/action/reason/profile 输出。
startup guard 状态可见。
reload 失败原因可见。
degraded 状态可见。
```

## 13. 推荐自动化目标

当前机器目标：

```bash
make test-unit
make test-unit-race
make test-lint
make test-config
make test-profile
make test-reconcile
make test-packet-helper
```

外部 Linux VM 目标：

```bash
make test-bpf-pkt
make test-netns
make test-netns-full
```

外部 VM / OpenWrt / 真机目标：

```bash
make test-vm
make test-openwrt-vm
make test-hw
make bench
make soak
```

目标行为：

```text
在缺少 Linux/root/BPF/TC/OpenWrt/硬件能力时，外部目标必须输出明确 skip 原因。
不能在当前机器上把外部能力缺失误判为测试失败。
```

## 14. CI 分级建议

每次提交：

```text
test-unit
test-config
test-profile
test-reconcile
test-packet-helper
```

PR 合并前：

```text
test-unit-race
test-lint
外部 Linux VM: test-bpf-pkt smoke
外部 Linux VM: test-netns smoke
```

Nightly：

```text
VM OS matrix
OpenWrt VM
NAT / endpoint change 不影响 BPF generation
performance quick
```

Release candidate：

```text
完整 VM matrix
真机 OpenWrt
真机 offload/GSO/GRO
24h soak
native wireguard-mix negative
performance report
```
