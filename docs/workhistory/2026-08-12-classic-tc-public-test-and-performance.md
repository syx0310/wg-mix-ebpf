# 传统 TC、TCX 公网测试与 B82 性能报告 — 2026-08-12

## 结论摘要

当前版本已经同时支持 `classic_tc`（传统 TC）和 `tcx` 两种挂载后端，并在
`192.168.10.82` 上完成了 2 个后端 × 3 种数据模式的真实 BPF/WireGuard 性能矩阵：

* 6 个测试单元全部通过，所有流量均为 0 TCP 重传，Jain 公平性均为 1.000000；
* baseline 下 TCX 比传统 TC 快 0.90%–5.10%，双向汇总快 4.67%；
* XOR-prefix 下结果有方向性波动：传统 TC 的两个单向结果更高，TCX 的双向汇总高
  3.44%；
* XOR-full 下两个后端非常接近，TCX 双向汇总高 2.98%；
* 性能主要由 XOR 处理范围决定，而不是由 TCX/传统 TC 的挂载方式决定；
* 82 测试结束后没有测试接口、netns anchor 或测试 BPF link 残留。

这些结果是每个单元一次 15 秒实测，用于当前版本的工程对比，不应当解释为多轮统计
基准。若要做发布级性能承诺，建议后续每格至少重复 5 次并报告中位数和 P95。

## 测试版本与产物

本轮矩阵使用提交：

`288ae3dce8ac7bd9c51237210b52c2691ab541f0`

82 上的 root-owned source stage 为 `d3063b6e`，关键产物如下：

* `wg-mix-ebpf` SHA-256：
  `a0fd3b385c78c8325cbff9ef639fa364e633b67a0e600bdd6efd8fffddc13e2e`；
* BPF object SHA-256：
  `3473c46a4642d974a4496a78e6804186eaf101646eb53e32758af0848d0c4da2`；
* netns anchor SHA-256：
  `caf9dc942e80a82a4cb3b3e491bae043907c2ad3e3d9bed50ff77e2d1f22a326`；
* smoke 脚本 SHA-256：
  `8aa96d4245ab88a477c3a187108d901af9501d41be073e919e18b097cade6d0b`；
* private mount namespace launcher SHA-256：
  `e6ffd4685b5c42b88db0b4368e81b167972211b4d05f653c07d3c03d054f2a61`。

Linux、BPF、恢复和性能测试均在 `192.168.10.82` 上执行；本批次没有使用本地
Docker 或 Podman。

## 性能矩阵方法

每个单元都创建隔离的 private mount namespace 和三个匿名 network namespace，真实
加载当前 BPF object，并在 WireGuard 隧道两端分别挂载指定后端。

统一参数：

* IPv4 underlay，underlay MTU 2200；
* 性能流量 WireGuard MTU 1420；
* iperf3 单流，正向、反向、双向各 15 秒；
* 最低接收量 1 MiB，最大允许重传数 0，最低 Jain 公平性 0.90；
* 每侧抓包上限 128 个包；
* inner GSO 记录，outer GSO 观察；
* baseline：不启用 XOR；
* XOR-prefix：`wg-payload-prefix`，`max_bytes=128`；
* XOR-full：`wg-payload-full`，`max_bytes=2048`。

XOR-full 还包含 1900 字节、DF 置位的大包功能探针，因此建链初始 WG MTU 使用 2000；
进入 iperf3 矩阵后仍切换到与其他单元一致的 MTU 1420。该差异只服务于功能探针，
不改变性能流量口径。

## 实测结果

吞吐单位均为 Mbit/s。双向列同时列出两个方向及其汇总值。

| 模式 | 后端 | 正向 | 反向 | 双向（正向 + 反向 = 汇总） | 重传 | Jain 公平性 | 运行 ID |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| baseline | TCX | 1356.29 | 1348.58 | 1299.74 + 1254.10 = 2553.84 | 0 | 1.000000 | `053d3de1` |
| baseline | 传统 TC | 1290.42 | 1336.60 | 1193.88 + 1245.95 = 2439.83 | 0 | 1.000000 | `9c3ff06f` |
| XOR-prefix | TCX | 1000.94 | 1051.60 | 1140.08 + 1133.16 = 2273.24 | 0 | 1.000000 | `bbe72c35` |
| XOR-prefix | 传统 TC | 1220.01 | 1201.64 | 1101.25 + 1096.35 = 2197.60 | 0 | 1.000000 | `810de9bf` |
| XOR-full | TCX | 722.20 | 791.45 | 679.88 + 690.78 = 1370.66 | 0 | 1.000000 | `92310063` |
| XOR-full | 传统 TC | 724.17 | 741.31 | 665.61 + 665.40 = 1331.01 | 0 | 1.000000 | `af3e8354` |

### TCX 相对传统 TC

正数表示 TCX 更快，负数表示传统 TC 更快。

| 模式 | 正向 | 反向 | 双向汇总 |
| --- | ---: | ---: | ---: |
| baseline | +5.10% | +0.90% | +4.67% |
| XOR-prefix | -17.96% | -12.49% | +3.44% |
| XOR-full | -0.27% | +6.76% | +2.98% |

### 各模式相对自身 baseline

| 后端 / 模式 | 正向 | 反向 | 双向汇总 |
| --- | ---: | ---: | ---: |
| TCX / XOR-prefix | -26.20% | -22.02% | -10.99% |
| 传统 TC / XOR-prefix | -5.46% | -10.10% | -9.93% |
| TCX / XOR-full | -46.75% | -41.31% | -46.33% |
| 传统 TC / XOR-full | -43.88% | -44.54% | -45.45% |

### CPU 与时延观察

iperf3 客户端记录显示：

* baseline 单向发送端总 CPU 约 6.30%–6.35%，接收端约 33.38%–33.86%；
* baseline 双向两端总 CPU 约 30.29%–31.05%；
* XOR-prefix 双向两端总 CPU 约 29.59%–30.45%；
* XOR-full 双向两端总 CPU 约 23.96%–25.28%，但其吞吐也明显下降；
* 正向单流平均 RTT：TCX/传统 TC baseline 分别为 1.566/1.558 ms，
  XOR-prefix 为 1.923/1.521 ms，XOR-full 为 1.785/1.669 ms。

CPU 百分比不能脱离吞吐直接比较效率；本轮主要结论仍以接收吞吐、重传和公平性为准。

## 结果解读

baseline 中 TCX 有小幅优势，符合减少传统 qdisc/filter 路径开销的预期，但差距只有
个位数百分比。XOR-full 下两种后端的差距也只有约 0%–7%，说明主要成本来自 full
payload 的分段 XOR 处理，而不是 attach backend。

XOR-prefix 的两个单向结果出现传统 TC 明显高于 TCX、但双向汇总反而 TCX 略高的情况，
更像单次运行中的调度、CPU 频率和方向性抖动，不能据此认定传统 TC 在 prefix 模式下
必然更快。需要多轮重复测量才能给出统计结论。

## 失败记录与恢复

第一次 TCX XOR-full 运行 `5f630851` 错把初始 WG MTU 设成 1420，同时执行 1900 字节
DF 大包探针。完整错误为：

```text
ping: sendmsg: Message too long
```

该错误发生在大包功能探针，早于 iperf3 性能流量，不是 BPF verifier、TCX attach 或
XOR 数据面失败。失败 trap 按设计没有自动删除现场。

现场的三个 netns anchor 和两个 tcpdump 进程在有界寿命结束后均已退出。随后使用提交
内的恢复脚本（SHA-256
`cd8e595bf2833b8325507c04d0865bdfa9837d2605e78f416be3569059ad7aed`）执行：

* 只读 plan：`files=40 mount=absent anchors=absent mutation=0`；
* 正式恢复：`root=absent receipt=absent`；
* 后置验证：运行根和恢复回执都不存在。

修正为初始 WG MTU 2000、性能流量 MTU 1420 后，TCX 和传统 TC 的 XOR-full 均通过。

## 测试后资源状态

6 个成功单元都完成了精确 detach、停止匿名 netns anchor、卸载 private bpffs、删除密钥
和测试网络对象。82 的最终只读核对结果：

* 宿主网络接口仅有原有的 `lo` 和 `ens33`；
* `/run/netns` 不存在；
* 没有 `wg-mix-ebpf-netns-anchor` 进程；
* `bpftool link show` 只剩机器原有的 cgroup sysctl link，没有本轮 TCX link；
* 6 个运行根仅保留 manifest、owner/creation 记录和 evidence 目录，不含私钥或活动资源。

## 公网双机测试结论

独立公网测试在 `192.168.10.82` 使用 TCX，在 5.15 内核的
`47.116.202.155` 使用生产 `classic_tc` 后端。两端都成功完成 BPF 加载和挂载，并进入
有界流量阶段；随后因为公网端没有收到 WireGuard initiation 而停止。

82 约每 5 秒发出一次 UDP/31155 握手，共观察到 17 次；公网端抓包看到 0 个匹配包，
且公网端本机防火墙已允许该流量。因此结果更符合阿里云 EIP/安全组未放行 UDP/31155，
而不是 classic TC loader、BPF verifier 或内核兼容失败。

显式 cleanup 已完成：两台机器均无测试 WireGuard 接口、本次 BPF pin、run root 或 intake
目录。公网机原有共享 `clsact` 保留，ingress/egress filter 均为 0。下一次公网端到端
流量验证应先放通 UDP/31155。

## CI 说明

此前 GitHub Actions 的 baseline 构建失败，是 FakeTCP 专用函数在 baseline 配置下被
`-Wall -Werror` 判为未使用。baseline BPF 构建现已添加
`-Wno-unused-function`；experimental 构建继续保持严格警告策略。详细编译与 verifier
记录见 `docs/workhistory/2026-08-11-public-bpf-and-ci-findings.md`。
