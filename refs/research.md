## 结论先说

**方案 1 的入站反改写最佳实现不是“直接读 wg 接口对端 IP + 入站端口”作为唯一识别条件。**

最佳方案应是：

**入站：线上目的端口/地址静态监听表为主，动态 flow-state 为辅，peer endpoint / WireGuard index 只作为辅助增强。**

**出站：可以让一组 wg 接口共用一个 FwMark；但更推荐“同一组使用同一 group mark，高低位编码 iface id”的方式，而不是所有接口完全相同 mark。** 这样既能按组统一改写，又能保留接口级、peer 级扩展能力。

---

# 1. 入站反改写为什么不能主要靠 FwMark

WireGuard 的 `FwMark` 是给 **WireGuard UDP socket 发出的外层出站包**设置的 32-bit mark，不是入站包天然携带的标识。`wg(8)` 对 FwMark 的描述就是 outgoing packets；入站 TC ingress 上看到的包通常没有这个 WireGuard FwMark。([man7.org][1])

TC BPF 能读 `skb->mark`，这个 mark 是 Linux 网络子系统中携带策略元数据的 32-bit tag；但这不代表 WireGuard 会给入站包自动打上对应 wg 接口的 mark。([eBPF 文档][2])

所以，方案 1 的入站识别应基于**线上包头本身**：

```text
ingress_ifindex
+ IP family
+ 线上 dst_addr / dst_port
+ 线上 src_addr / src_port
+ UDP payload 中的 WireGuard message_type / 长度 / 可选改写 tag
+ 动态状态表
```

而不是基于 `skb->mark == wg_fwmark`。

---

# 2. “直接读 wg 接口的对端 IP + 入站端口识别”是否可行

要先区分 WireGuard 里两个容易混淆的“对端 IP”。

## 2.1 如果“对端 IP”指 AllowedIPs：不适合作为入站 BPF 识别条件

`AllowedIPs` 是隧道内地址选择与校验规则，用于判断某个 peer 允许哪些内层源地址、以及外发内层流量路由到哪个 peer。([man7.org][1])

但在 TC ingress 反改写发生时，包还是 **WireGuard 外层 UDP 加密包**，隧道内 IP 还没有被 WireGuard 解密出来。eBPF 不能在这个阶段看到 peer 的内层 IP。

所以：

```text
wg peer AllowedIPs + 入站端口
```

不能作为入站反改写的主识别方式。

## 2.2 如果“对端 IP”指 Peer Endpoint：可以用，但不应作为唯一条件

WireGuard peer 的 `Endpoint` 是外层 UDP endpoint。这个值可以由 Go agent 通过 WireGuard 控制接口读取，然后写入 BPF map。

但它有几个问题：

**第一，Endpoint 可能为空。**
服务端场景下，peer 可能没有预配置 endpoint，等待客户端首次握手。

**第二，Endpoint 会自动更新。**
WireGuard 文档说明，peer endpoint 会更新为“最近一次通过认证的数据包”的源 IP 和端口。([man7.org][1]) 这对 NAT、漫游非常重要，但也意味着你不能把初始配置里的 endpoint 当成永久稳定值。

**第三，有循环依赖。**
如果入站反改写依赖“WireGuard 已经认证并更新后的 endpoint”，但这个包必须先被反改写才能进入 WireGuard 完成认证，那么首包就无法可靠处理。

因此，`Peer Endpoint + 入站端口` 可以作为**静态 peer 优化条件**，但不应是入站首包的唯一识别方式。

---

# 3. 入站反改写的最佳数据面设计

推荐使用三层匹配：

```text
第一层：静态 listener map
第二层：动态 flow-state map
第三层：可选 endpoint / index 辅助表
```

## 3.1 第一层：静态 listener map，负责首包和通用入站

这是最重要的一层。

入站 BPF 程序挂在 underlay 接口的 TC ingress。TC BPF 可以挂载在 ingress / egress qdisc，并通过 BPF map 接收用户态下发的策略。([man7.org][3])

静态 listener map 的 key 建议是：

```text
IP family
+ ingress_ifindex 或 underlay group id
+ 线上 dst_addr，可支持 wildcard
+ 线上 dst_port
+ 可选 profile id / tag
```

value 是：

```text
rule_id
wg_if_id
rewrite_group_id
原始 WireGuard listen_addr
原始 WireGuard listen_port
WireGuard header 反改写规则
源 tuple 是否也反改写
```

入站包只要命中这个表，就可以完成最小必要反改写：

```text
线上 dst_port  -> 本机 wg ListenPort
线上 dst_addr  -> 本机 wg socket 绑定地址，通常可为 wildcard/local addr
线上 WG header -> 原始 WireGuard header
```

WireGuard 的包都跑 UDP，握手包和数据包都有固定的 message_type / index / counter 等字段；例如握手 initiation 的 `message_type = 1`，response 的 `message_type = 2`，data packet 的 `message_type = 4`。([WireGuard][4])

因此，入站 BPF 可以先做轻量校验：

```text
是否 UDP
是否命中线上 dport
UDP payload 长度是否像 WG 包
message_type 是否是线上改写后的合法值
```

然后再反改写。

### 最佳实践

**给每个 rewrite group 或每个 wg 接口分配唯一的“线上入站端口”。**

例如：

```text
wg0 原始 ListenPort = 51820，线上端口 = 443
wg1 原始 ListenPort = 51821，线上端口 = 8443
wg2 原始 ListenPort = 51822，线上端口 = 2053
```

这样入站首包不需要知道 peer endpoint，也不怕 NAT、漫游、动态源端口变化。

这是性能和可靠性最好的方案。

---

## 3.2 第二层：动态 flow-state map，负责已知会话和复杂改写

动态 flow-state map 的 key 可以是线上 5-tuple：

```text
family
+ ingress_ifindex
+ online_src_addr
+ online_src_port
+ online_dst_addr
+ online_dst_port
```

value 是：

```text
rule_id
wg_if_id
原始 local dst_addr / dst_port
原始或期望的 peer src_addr / src_port
header 反改写参数
last_seen
flags
```

这个表主要用于这些场景：

```text
1. 多个 wg 接口共享同一个线上端口，但 peer endpoint 是固定的
2. 出站曾经建立过映射，入站返回包按状态反改写
3. 源端口、源地址也参与改写，需要恢复
4. 某些 profile 有 per-peer / per-session 改写参数
```

但要注意：不要在每个未认证入站握手包上无条件创建大状态。WireGuard 协议本身就强调，服务端不应在未认证首包上分配易被滥用的状态。([WireGuard][4])

更好的做法是：

```text
入站 initiation：
  命中 listener map 后直接反改写并放行；
  不创建重状态，最多更新轻量计数。

出站 response / data：
  说明 WireGuard 已经接受或正在使用该 peer；
  这时再创建或刷新 flow-state。
```

这样可以降低 spoofed UDP flood 对 BPF map 的压力。

---

## 3.3 第三层：可选 WireGuard index map，用于端口共享场景

WireGuard 的部分消息里有明文 index 字段：

```text
handshake_response:
  sender_index
  receiver_index

data packet:
  receiver_index
```

协议文档里 response 包包含 `sender_index` 和 `receiver_index`，data 包包含 `receiver_index`。([WireGuard][4])

因此可以做一个辅助 index map：

```text
receiver_index -> rule_id / wg_if_id / profile_id
```

它的用途是：

```text
1. 客户端出站 initiation 时，记录本端 sender_index
2. 入站 response 时，根据 receiver_index 找回 rule
3. 服务端出站 response 时，记录本端 sender_index
4. 后续入站 data packet 根据 receiver_index 找 rule
```

但它不能解决所有问题。

**服务端收到客户端第一个 handshake initiation 时，包里只有客户端 sender_index，没有服务端 receiver_index。** 如果多个 wg 接口共享同一个线上端口、同一个本地地址、并且 peer endpoint 也无法区分，那么第一包无法靠 WireGuard index 判断应该送到哪个 wg 接口。

所以 index map 只能作为端口共享后的增强手段，不能替代唯一线上监听端口。

---

# 4. 入站识别方案推荐排序

| 入站识别方式                                     |  是否推荐 | 适用场景              | 问题                               |
| ------------------------------------------ | ----: | ----------------- | -------------------------------- |
| **线上 dst_port / dst_addr 静态 listener map** |  强烈推荐 | 首包、漫游、NAT、多 peer  | 需要规划唯一线上端口或地址                    |
| 线上 5-tuple flow-state                      |    推荐 | 已建立流、复杂改写、固定 peer | 首包依赖静态规则                         |
| Peer Endpoint + 入站端口                       | 可作为辅助 | 固定公网 peer         | NAT / roaming / endpoint 自动更新时不稳 |
| WireGuard receiver_index map               | 可作为增强 | 握手后 data 包归属      | 不能解决服务端首个 initiation             |
| AllowedIPs / 对端隧道 IP                       |   不推荐 | 无                 | 入站加密阶段不可见                        |

---

# 5. 入站反改写时，源地址/源端口要不要恢复

这里要分清“必须恢复”和“可选恢复”。

## 必须恢复

这些字段必须在进入 WireGuard UDP socket 前恢复：

```text
本机目的端口：线上端口 -> wg ListenPort
本机目的地址：线上地址 -> wg socket 可接收的本地地址
WireGuard 固定 header：message_type / reserved / index 等被改写字段
UDP / IP checksum
```

如果目的端口不恢复，包进不了正确的 WireGuard UDP socket。
如果 WireGuard message_type / reserved 等字段被改写后不恢复，WireGuard 无法按原协议解析或认证。

eBPF 可以用 `bpf_skb_store_bytes()` 写包内容，并配合 L3/L4 checksum helper 做增量校验和修正。([man7.org][5])

## 源地址/源端口是否恢复：建议做成 profile 选项

### 模式 A：透明 canonical 模式

入站时同时恢复：

```text
online src_addr/src_port -> canonical peer src_addr/src_port
```

优点：

```text
WireGuard 内核完全看不到线上改写
endpoint 看起来稳定
适合静态公网对端
```

缺点：

```text
不适合 NAT / roaming
需要可靠状态表
可能影响 WireGuard endpoint 自动学习
```

### 模式 B：NAT / roaming 友好模式

入站只恢复本地目的端和 WG header，不恢复源端：

```text
online src_addr/src_port 保持不变
online dst_addr/dst_port -> local wg addr/listen_port
WG header -> 原始 header
```

优点：

```text
WireGuard 可以继续学习真实线上来源
更适合 NAT、移动网络、动态端口
```

缺点：

```text
出站 rewrite 逻辑要接受 WireGuard endpoint 已经是线上 endpoint
不能假设 wg 内核看到的是 canonical peer endpoint
```

如果目标是跨 OpenWrt / Ubuntu / Arch 且支持 NAT 和移动 endpoint，我建议默认采用 **模式 B**，只有静态站点互联场景才启用模式 A。

---

# 6. 出站是否可以一组接口共用一个 FwMark

可以。

WireGuard 的 FwMark 是 32-bit 值，配置在 interface 级别，用于它发出的外层 UDP 包。([man7.org][1]) 多个 wg 接口可以配置同一个 FwMark，TC egress BPF 在 underlay 出口看到 `skb->mark` 后，按这个 mark 选择改写 profile。

例如：

```text
wg0, wg1, wg2 -> FwMark = 0x10000000 -> rewrite group A
wg3, wg4      -> FwMark = 0x20000000 -> rewrite group B
wg5           -> FwMark = 0x30000000 -> rewrite group C
```

这样可以实现：

```text
一组接口共用一个改写策略
多组接口使用不同改写策略
一个 BPF 程序挂在所有 underlay 接口上
通过 BPF map 动态更新 group -> profile
```

## 但完全相同 FwMark 会丢失接口身份

如果 `wg0` 和 `wg1` 使用完全相同的 FwMark，那么 egress BPF 单靠 mark 不知道这个包来自 wg0 还是 wg1。

它还可以继续用这些字段区分：

```text
原始 UDP src_port，也就是 wg ListenPort
原始 UDP dst_addr/dst_port，也就是 peer Endpoint
本机 src_addr
出站 underlay ifindex
WireGuard message_type / index 状态
```

但如果出现这种情况：

```text
wg0 和 wg1 使用同一个 FwMark
wg0 和 wg1 使用同一个 ListenPort
wg0 和 wg1 peer Endpoint 也相同或不可区分
```

那出站就无法可靠判断应该套用哪个接口级规则。

因此：

**如果一组接口完全使用同一个改写策略，可以共用同一个 FwMark。**
**如果未来需要按接口、peer、endpoint 做差异化，最好不要让整组接口完全同 mark。**

---

# 7. 更推荐的 FwMark 编码方式

推荐把 32-bit FwMark 分成几段：

```text
高位：magic / namespace
中位：rewrite group id
低位：wg interface id 或 peer hint
```

例如概念上：

```text
0xA GGG IIII
```

含义：

```text
A    = 本程序专用 magic，防止误匹配别的 mark
GGG  = rewrite group id
IIII = interface id 或实例 id
```

然后：

```text
BPF 用 group id 选择统一改写 profile
BPF 用 iface id 做接口级覆盖或统计
Linux ip rule 可用 fwmark/mask 只匹配 group 部分
```

`ip rule` 支持 `fwmark FWMARK[/MASK]` 这种带 mask 的选择器。([man7.org][6]) 这意味着策略路由也可以只看 group 位，而不需要每个接口单独写一条 rule。

这比“整组接口完全相同 FwMark”更稳。

---

# 8. 多组接口改写的推荐控制面结构

Go agent 里建议把配置抽象成：

```text
rewrite_group
  group_id
  fwmark_mask / fwmark_value
  underlay_ifaces
  transform_profile
  ingress_listeners
  source_restore_mode
  interfaces[]
```

每个 wg interface 有：

```text
wg_name
wg_if_id
fwmark
listen_port
peers
group_id
```

每个 peer 可选：

```text
public_key
endpoint
allowed_ips
peer_specific_profile
```

BPF map 则拆成：

```text
mark_group_map:
  normalized_group_id -> transform_profile

iface_map:
  wg_if_id -> wg metadata

egress_peer_map:
  group_id + dst_addr + dst_port + src_port -> peer/profile/rule

ingress_listener_map:
  online dst_addr + online dst_port + ingress_ifindex -> rule

ingress_flow_state_lru:
  online 5-tuple -> reverse rule

index_state_lru:
  receiver_index -> rule
```

这样可以同时支持：

```text
一组 wg 接口统一改写
不同组不同改写
同组内接口级例外
同组内 peer 级例外
入站首包静态识别
入站已知流状态识别
```

---

# 9. 我建议的最终方案

## 入站

首选：

```text
underlay TC ingress
  -> UDP/WG 轻量校验
  -> 先查 flow-state
  -> 再查 listener map
  -> 命中后反改写本地 dst_addr/dst_port 和 WG header
  -> 按 profile 决定是否恢复 src_addr/src_port
  -> 修正 checksum
  -> 放行给 WireGuard socket
```

入站首包不要依赖 peer endpoint。
入站首包最好靠唯一线上端口或线上地址识别。

## 出站

推荐：

```text
每个 wg 接口设置 FwMark
FwMark 中编码 group id + iface id
underlay TC egress 根据 group id 选择改写 profile
根据 iface id / endpoint / peer rule 做细分
出站改写后按需写入 flow-state / index-state
```

如果你确认同一组接口永远使用完全相同的改写规则，也不需要接口级区分，那么可以让这一组接口使用完全相同的 FwMark。

但工程上更优的是：

```text
同组 mark 可 mask 匹配
接口 mark 仍保持唯一
```

也就是：

```text
不是：
  wg0 = 0x10000000
  wg1 = 0x10000000

而是：
  wg0 = 0x10000001
  wg1 = 0x10000002

BPF / ip rule 按：
  0x10000000 / 0xffff0000
```

这样既能做到“按组改写”，又不会丢失接口身份。

---

## 最短建议

**入站反改写：用“唯一线上监听端口/地址 + listener map”做首包识别，用 flow-state 和 endpoint/index 做辅助，不要把 wg peer IP 当主键。**

**出站分组：可以一组接口一个 FwMark，但最佳实践是 FwMark 编码 group id + iface id，然后用 mask 做组匹配。**

[1]: https://man7.org/linux/man-pages/man8/wg.8.html "wg(8) - Linux manual page"
[2]: https://docs.ebpf.io/linux/program-context/__sk_buff/ "Program context '__sk_buff' - eBPF Docs"
[3]: https://man7.org/linux/man-pages/man8/tc-bpf.8.html "tc-bpf(8) - Linux manual page"
[4]: https://www.wireguard.com/protocol/ "Protocol & Cryptography - WireGuard"
[5]: https://man7.org/linux/man-pages/man7/bpf-helpers.7.html "bpf-helpers(7) - Linux manual page"
[6]: https://man7.org/linux/man-pages/man8/ip-rule.8.html "ip-rule(8) - Linux manual page"
