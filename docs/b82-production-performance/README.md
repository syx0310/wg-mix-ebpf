# B82 production 性能矩阵

这套入口只用于 `192.168.10.82` 的隔离 network namespace 性能测试，不修改物理
网卡。必须先把一个 clean commit 放入 root-owned source stage，再从该 stage 调用脚本；
禁止直接对用户 checkout 执行 `sudo`。

## 覆盖范围

矩阵固定为 63 格、567 份客户端 iperf3 JSON：原生 WireGuard 1 格，UDP 的
`TCX/传统 TC × 10 种 XOR` 共 20 格，ICMP 的 `TCX/传统 TC × 无 XOR` 共 2 格，
FakeTCP 的 `TCX/传统 TC × kfunc/kprobe × 10 种 XOR` 共 40 格。每格执行正向、
反向、双向，各 3 次、每次 3 秒。FakeTCP 始终使用 exact generic XDP；kfunc 选择
modern 对象，kprobe 选择 Linux 5.15 legacy 对象。

这 63 格是性能维度，不重复完整功能验收矩阵；每个 production cell 仍会验证真实
attachment/status、FakeTCP resident lifecycle、classic journal/kprobe lease、外层协议、
同键/改键 reload 与停止后的 exact BPF ID 消失。流量结束后会再做 daemon-side 同键
health reload：kprobe 会复核该 runtime 所持 lease 的 errors/nmissed 增量和 cookie 连续性，
同时要求 BPF identity 不变。82 上应先通过独立的功能/verifier
验收，再运行本矩阵。

## 审阅和执行

先运行只读计划并保存完整输出：

```bash
/usr/bin/bash -p scripts/run-b82-complete-performance-matrix.sh \
  plan --matrix-id <8位小写十六进制ID>
```

计划逐格列出完整 argv、write-set、显式 cell restore，以及 kfunc/kprobe module
restore。实际执行必须直接使用计划给出的 `TMUX_ARGV`；外层预算为 9000 秒，每格
另有 130 秒边界。tmux 只接收无参数的版本化 wrapper，并通过 tmux environment
传入受限 matrix ID，避免拼接多层 `sh -c` 命令。矩阵仅构建一次 binary、三种 BPF 对象和两个 checksum module，
按 SHA-256 冻结后复用。binary 通过只读 Go overlay 嵌入这三份冻结 BPF 对象，避免
`prepare-embedded-bpf` 回写 source stage；构建后再逐项核对 binary 报告的 embedded SHA。
构建前、artifact 冻结后和 63 格结束后还会比较排除 `.git` 的完整 source tree
内容/元数据 digest；Go telemetry 显式关闭，source stage 不能成为隐含 write-set。

模块阶段为 `kfunc load → 20 个 FakeTCP/kfunc cell → kfunc unload → kprobe load →
20 个 FakeTCP/kprobe cell → kprobe unload`。每次 load 前写 intent，加载后写 exact
owned receipt；只有 refcount 为 0 且 live module identity 与 receipt 一致时才卸载。

成功后，matrix root 中包含 `results.v1.json`、中文 `report.zh-CN.md`、63 个规范化
cell 目录及全部 567 个原始客户端 JSON。用
`export-b82-production-performance-evidence.sh` 导出已完成矩阵，再用
`cleanup-b82-production-performance-evidence.py` 在校验导出 SHA-256 后精确删除该次
evidence；导出文件不会被删除。

matrix root 固定在 `/var/tmp/wg-mix-ebpf-performance-tests/<matrix-id>`，使用 82 的
持久根文件系统承载 artifact 和 evidence，不占用容量较小的 `/run` tmpfs。各 endpoint
自己的 `/run/wg-mix-ebpf` 仍由其私有 mount namespace 精确 bind，运行时语义不变。

中文报告的吞吐格式为“均值 ± 总体标准差（最小–最大） Mbit/s”。双向汇总先按同一轮
正反向相加再统计；重传只计正向、反向及双向 aggregate，避免再累加双向分项；Jain
显示三组均值的平均和三组最低值中的最小值。JSON 保留未舍入数值及 567 个原始文件
的 SHA-256。

## 失败处理

任一阶段失败都会停止后续写操作、输出完整 stdout/stderr/状态诊断，并保留本次
owner-bound 现场。脚本不会在失败 trap 中自动删除 namespace、BPF、pin 或 module。
先保存日志并检查现场，再逐条使用只读计划中该 cell 的 `RESTORE_ARGV`；确认所有
cell 已恢复后，才使用对应的 `MODULE_RESTORE_ARGV`。不得用通配符或递归删除替代
这些显式恢复入口。

本地只允许运行 `bash -n`、Python AST、
`scripts/test_b82_production_performance_static.py` 和差异检查；Linux/BPF/netns 实测
统一放在 82。
