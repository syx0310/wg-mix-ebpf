# B82 完整性能矩阵计划

目标是在 `192.168.10.82` 上以同一套隔离 netns/WireGuard 拓扑比较原生
WireGuard、TCX 和传统 TC，并对常用 XOR 处理长度做短时多轮采样。

## 固定矩阵

* 原生 WireGuard：不加载 BPF，1 格；
* UDP + TCX、UDP + 传统 TC：无 XOR、`wg-payload-prefix`（`max_bytes`
  为 `4/16/64/128/256/512/1024/2048`）及
  `wg-payload-full/max_bytes=2048`，共 20 格；
* ICMP + TCX、ICMP + 传统 TC：仅无 XOR，共 2 格；
* FakeTCP 始终保留 exact generic XDP，并覆盖
  `TCX/传统 TC × kfunc/kprobe × 无 XOR/上述 8 个 prefix/full-2048`，
  共 40 格；kfunc 使用 modern 对象，kprobe 使用 Linux 5.15 legacy 对象。

精确合计为 `1 + 20 + 2 + 40 = 63` 格、`63 × 3 方向 × 3 次 = 567`
份客户端 iperf3 JSON。ICMP 不制造未支持的 XOR 组合。XOR 密钥派生和 key 长度
保持生产默认值，只改变实际处理的 payload 字节上限。

## 统一采样参数

* IPv4 underlay，underlay MTU 2200；
* 性能流量 WireGuard MTU 1420；
* iperf3 单流；正向、反向、双向；
* 每个方向 3 秒，每个配置重复 3 次；
* 每个样本检查接收量，记录重传和 Jain 公平性；
* 中文报告按正向、反向、双向汇总输出均值、总体标准差、最小值、最大值、
  重传和 Jain；双向先按同轮正反吞吐相加，重传不重复计算双向分项。

## 执行与清理

只在 82 上执行 Linux、BPF 和网络测试。本机只做格式化、静态检查、交叉编译、
结果汇总和文档生成。矩阵只构建一次 binary、baseline/modern/legacy BPF 和两个
内核模块，随后以 SHA-256 冻结并逐格复核。binary 使用只读 Go overlay 嵌入三份
冻结 BPF 对象，不能通过 `prepare-embedded-bpf` 改写 source stage。

入口顺序固定为“进入 endpoint netns → 创建 private mountns → 验证 netns 身份 →
bind endpoint 路径 → 挂载 private bpffs → 直接执行常驻 daemon”。成功路径完成精确
detach、netns 停止和 private bpffs 卸载。失败时停止后续配置，一次输出完整日志并
保留 owner-bound 现场；不自动清理，使用 plan 输出中的显式 cell/module restore argv。

`plan` 为只读操作，输出全部 63 格、每格完整 argv、write-set、restore argv，以及
`tmux + timeout 9000s` 的运行 argv。矩阵内每格另有 130 秒硬界限并为报告留出预算。

最终只读核对活动 netns、测试接口、BPF link/pin、模块和 source stage；结果写入中文
工作记录，提交、合并到 `main` 并 push。

FakeTCP 单元另需先通过 verifier、真实 generic-XDP/TCX/classic TC 生命周期、
kfunc/kprobe lease、offload/MTU/GSO/slow-path 与回滚门；性能数字不能替代这些正确性
证据。所有原始 stdout/stderr/退出码一次性写入本次运行专属 evidence，只遮蔽密码、
私钥和 ownership token。
