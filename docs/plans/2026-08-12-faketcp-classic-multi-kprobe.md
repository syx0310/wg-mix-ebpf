# FakeTCP TCX/classic、多 WireGuard 与旧内核兼容计划

日期：2026-08-12

## 目标合同

本批工作扩展 FakeTCP 的生产实现，不改变 FakeTCP 的 on-wire 格式，也不取消
现有 exact generic XDP ingress。目标由三个互相独立的选择维度组成：

| 维度 | 生产选项 | 固定约束 |
| --- | --- | --- |
| ingress 早期入口 | exact generic XDP | FakeTCP 始终保留；不做 driver XDP、libxdp chaining 或 replace |
| TC attach backend | `tcx`、`classic_tc` | ingress/egress 必须使用同一种后端；`auto` 只在首写前解析 |
| checksum bridge | `kfunc`、`kprobe` | kfunc 优先；kprobe 是旧内核兼容路径，不是运行时静默降级 |
| WireGuard 数量 | 单个、多个 | 每个 session/policy/event 必须以 WGID 隔离 |

应形成的主要组合：

```text
modern: exact generic XDP + TCX       + kfunc  + 1..N WireGuard
modern: exact generic XDP + classic TC + kfunc  + 1..N WireGuard
legacy: exact generic XDP + classic TC + kprobe + 1..N WireGuard
```

Linux 5.15 不因 kprobe 获得 TCX。旧内核路径仍是 classic TC；kprobe 只替代
checksum/GSO bridge。任何一个能力探测出现非“明确不支持”的错误，都必须在网络首写
前返回原始错误，不得继续尝试另一个后端掩盖故障。

## 不变项

* FakeTCP 仍然是 IPv4、packet-oriented TCP-shaped transport，不变成 TCP 字节流。
* exact generic XDP 对 managed TCP-shaped ingress 做 session/control admission；TC ingress
  完成 TCP-shaped 到 WireGuard UDP 的转换。
* 固定非零 WireGuard `ListenPort`、启动 guard、managed-flow fail-closed 继续保留。
* XDP 共存合同不放宽：发现已有 owner 时在首写前拒绝，不替换 foreign program。
* kprobe 不消除内核模块依赖；它只消除旧内核对 module BTF/kfunc 注册能力的依赖。
* UDP、ICMP 的既有行为、ABI 和 attachment backend 选择不得被 FakeTCP 扩展改变。

## 实施顺序

### 1. 后端选择与可观测性

将 attach backend、checksum backend 和 BPF artifact 选择拆开。解析后的结果进入
desired key、resident status、doctor 输出和日志。选择必须发生在 guard 安装、旧 dataplane
detach、map 写入和 attach 之前。

`attachment_backend: auto` 的目标规则：

1. 若存在且验证通过的本项目 FakeTCP classic durable owner，保持 classic sticky；
2. 否则 exact TCX capability 成功时选择 TCX；
3. TCX 明确不支持时选择 classic TC；
4. 权限、参数、内核返回异常或探测结果不完整时直接失败。

checksum backend 的目标规则：kfunc 能力完整时优先 kfunc；只有 kfunc 被明确判定为不支持
且 kprobe module 的符号、lease、health、artifact ABI 全部匹配时才选择 kprobe。选择后运行
期间不切换。

### 2. FakeTCP classic TC 基础闭环

复用 durable classic TC owner/journal，把 FakeTCP ingress/egress programs 作为一笔可恢复
事务挂载。XDP 仍由 resident process 持有 exact link FD。status 同时报告：

* 解析后的 `attachment_backend`；
* XDP ifindex/link ID/program ID/mode；
* TCX link/program ID，或 classic parent/priority/handle/program ID；
* generation、incarnation、barrier、object SHA-256 和健康状态。

same-key reload 必须保持 identity；changed-key reload 必须串行替换且不留下旧 ID。daemon
异常退出后，classic filters 由 journal 精确识别并由下一次 reconcile 恢复或回收；不得依赖
进程 FD 自动消失的 TCX 语义。

### 3. 多 FakeTCP WireGuard

生产 runtime 使用已有 EngineRouter 思路按 WGID 路由 slow path。session key、claim、event、
policy 和 snapshot 的 Go/C ABI 均显式携带 WGID；不同 WG 即使其余 session 字段完全相同也
不能命中同一状态。

一个 underlay 只挂一组 XDP 与一组 TC ingress/egress programs。BPF maps 根据 underlay、
managed port 和 WGID 分流，不为每个 WireGuard 重复 attach。配置允许一个 daemon 管理多个
FakeTCP WireGuard；每个接口仍要求固定且运行时一致的非零 ListenPort。端口或路由歧义必须
在首写前给出包含两个冲突接口名的完整错误。

### 4. Linux 5.15 BPF artifact

新增独立 legacy artifact，不让 modern object 因旧 verifier 约束永久退化。旧对象替换
`bpf_loop` 等 5.15 不可用依赖，保持 type-word、XOR prefix/full、GSO 和多 WG ABI 一致。
modern/legacy manifests 必须分别绑定程序、map ABI、build flags 和 SHA-256，loader 不得把
一个对象当成另一个对象的兼容替代。

legacy artifact 在目标 5.15 verifier 真正 load 成功前只能标记为 build-ready，不能在文档
中宣称 Linux 5.15 已验证。

### 5. kprobe checksum bridge

kfunc 保持默认实现。kprobe module 使用明确失败的 helper trigger 加 kretprobe，实现与
kfunc 相同的 prepare/commit 合同：

* daemon 持有本 runtime 的 module lease FD 与固定 cookie，runtime 活跃期间模块不能卸载；
* module 支持多个并行 lease/cookie，使同一主机上的多个 resident runtime 能并存；
* 每次 trigger 同时验证 operation magic、随机 cookie、短生命周期 skb 描述符和 packet
  shape；
* 未命中 probe 时 helper 原始错误必须使 managed packet fail closed；
* prepare/commit 命中、拒绝、descriptor 错误和 `nmissed` 必须可观测；
* `nmissed != 0` 或 module/lease/ABI 漂移使 runtime unhealthy，不得继续报告 active；
* full GSO commit 必须与 kfunc 的 sequence/ack/window、checksum 和 GSO metadata 结果一致。

kprobe 首批生产支持以 x86_64 Linux 5.15 为强制门。aarch64 只有在对应内核符号和真实
主机测试完成后再加入已验证矩阵。

## B82 验收矩阵

版本化入口位于 `scripts/realhost-b82-faketcp-backends-v1/`。它只允许从 root-owned source
stage 执行高权限部分；源码 commit、artifact SHA-256、kernel/boot ID、展开后的非秘密 argv、
stdout、stderr 和退出码写入本 run 专属 evidence。错误时一次性采集完整现场并停止后续
写操作，不截断 stderr，不自动猜测清理。

source stage 在矩阵期间只读。每个 cell 把 baseline/modern/legacy BPF objects、Go binary
和所选 module 全部写到本 cell 的 `artifacts/`；不执行会重写 source 内 embedded objects
的默认 `make build`。每格在构建前后、netns cell 后和恢复后同时核对 Git clean/commit 与
非 `.git` 全树 digest。kfunc module load 的 `lease_id` 固定为
`<8hex-stage-id>-<8hex-cell-run-id>`，并进入 manifest、owner receipt 和 restore identity。

短时验收固定为 12 cells：`WG 1/2/4 × TCX/classic TC × kfunc/kprobe`。
为控制低带宽主机的运行时长，XOR/GSO 代表点按 WG 数固定，且每个 attach/checksum
组合都会覆盖三种 payload 形态：

| WG 数 | XOR | GSO | 重点证明 |
| ---: | --- | --- | --- |
| 1 | none | off | 普通 skb、exact attachment/status identity |
| 2 | prefix 128 | on | 多 WG 隔离、并发流量、GSO counters |
| 4 | full 2048 | on | aggregate quota、多 WG 隔离、并发流量、GSO counters |

其中发布必需代表组合至少包括 TCX+kfunc+modern、classic TC+kfunc+modern、
classic TC+kprobe+legacy。TCX+kprobe 也保留为正交组合测试；Linux 5.15 在首写前把
TCX cells 分类为 `SKIP_UNSUPPORTED`、classic+kfunc 分类为
`REJECT_UNSUPPORTED`，只运行 classic+kprobe+legacy。

每种组合还必须执行：

* 每个 WG 独立流量和同时跨 WG 的并发流量；
* 2 WG 与 4 WG 的同四元组 session ABI 隔离测试；
* receiver-side capture 禁止 raw WireGuard UDP 泄漏；
* XOR `none`、推荐 prefix 长度和 full payload；
* 普通 skb、目标 GSO shape、PMTU/MTU 边界和 checksum counters；
* same-key reload、changed-key reload、daemon crash/restart；
* classic journal 恢复、kprobe trigger miss/lease loss/nmissed 故障注入；
* 成功后逐项证明本 run 的 netns、links、filters、pins 和 module lease 已清理。

B82 当前新内核可以完成 modern 组合和 kprobe 行为测试，但不能单独证明 Linux 5.15
兼容。最终 5.15 gate 必须在 B82 上的受控 5.15 启动环境/虚拟机完成；不得用新内核加载
legacy object 的结果冒充 5.15 通过。

## 发布门

下列条件全部满足后才能把新增组合标记为 production-supported：

1. Go/BPF/kernel module ABI 与 manifests 的静态测试通过；
2. modern 和 legacy objects 在各自目标 verifier load 成功；
3. B82 对应矩阵全部通过并保留完整 evidence；
4. 2/4 WG 同四元组隔离、GSO、reload/crash recovery 均有运行证据；
5. classic/kprobe 失败均 fail closed，且恢复后无 foreign 或本 run 资源残留；
6. 中文验收报告记录 commit、artifact digest、内核、每个 cell 结果和未覆盖项。

未通过的单个组合应按三维能力矩阵单独标记，不阻止已经闭合的其他组合发布，也不得由
`auto` 静默选择到未通过组合。
