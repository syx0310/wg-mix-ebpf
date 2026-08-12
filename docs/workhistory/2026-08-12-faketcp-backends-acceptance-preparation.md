# FakeTCP 多后端与多 WireGuard 验收准备 — 2026-08-12

## 本批文档结果

生产合同已拆成互相独立的三个选择维度：

```text
XDP ingress: exact generic（始终保留）
TC stage:    TCX | classic TC
checksum:    kfunc | kprobe
instances:   1 | N FakeTCP WireGuard
```

配置、兼容性、架构、构建和运维文档已同步以下目标：

* `runtime.checksum_backend: auto|kfunc|kprobe`；
* modern/legacy FakeTCP artifacts 独立 manifest 和 selector；
* classic TC 与 TCX 均保留 exact generic XDP；
* session key 通过 WGID 隔离，多 WireGuard 共用每 underlay 的 attachment；
* kprobe 使用 per-runtime FD lease 与固定 cookie，module 支持多个并行 lease；
* `auto` 只在首写前选择，运行中不静默 fallback；
* kprobe 的 `nmissed`、errors、lease 或 ABI 漂移均进入 unhealthy。

## 新版 B82 入口

新增 `scripts/realhost-b82-faketcp-backends-v1/`：

* `matrix.py`：12-cell 编排、5.15 capability 分类和矩阵级完整日志；
* `root-cell.sh`：root-owned source/commit/artifact 检查、构建、写集审计、失败取证和成功恢复；
* `root-netns-cell.sh`：单 cell 的 3-netns、1/2/4 WG、resident daemon、流量、status、session map 与 crash recovery；
* `test_matrix_static.py`：矩阵、脚本语法、日志、清理边界和禁止操作的静态合同。

固定 cell 为：

```text
WG 1/2/4 × TCX/classic TC × kfunc/kprobe = 12
WG1: XOR none, GSO off
WG2: XOR prefix 128, GSO on
WG4: XOR full 2048, GSO on
```

每端在同一隔离 underlay 中创建 `wg0..wgN`，为每个 WG 使用独立固定
ListenPort、fwmark、隧道地址和 peer。每个 WG 显式使用 session 2048、half-open 256、
source-ledger 512、pending-flow 128、pending-bytes 131072 等固定配额；4 WG 聚合值仍严格低于
全部共享实现上限。每个 WG 分别执行指定接口 ping 和短时 iperf，再同时执行跨 WG ping；GSO
cell 要求 managed/rewrite GSO counters 实际增长。outer pcap 必须看到 FakeTCP 并禁止
managed raw WireGuard UDP。

隔离证据分成两部分：真实流量后从 daemon exact map IDs 定位 session map，要求 32-byte
key 中 WGID `1..N` 均出现且 reserved bytes 全零；同时在 82 执行同网络四元组、不同
WGID 的 EngineRouter 精确分发测试。真实 WireGuard socket 因 managed ListenPort 必须唯一，
不能在一个 underlay 上合法绑定完全相同的端口四元组，因此没有伪造一个不可运行的网络
拓扑。

每格还执行 same-key reload、endpoint A 的预期 `SIGKILL`、resident daemon 重建和每 WG
恢复后流量。classic TC cell 由该过程覆盖 durable journal/filter 恢复；TCX cell覆盖
process-owned link 重建。

## 写集和失败规则

单 cell 允许的主机写集为：

* `/run/wg-mix-ebpf-faketcp-backends-v1/<run-id>` 下的 evidence、endpoint runtime 和 receipt；
* 本 cell evidence 下的 `artifacts/`（三个 BPF objects、Go binary、所选 module）与 stage
  专属 Go caches；source stage 保持只读并以 Git identity + 全树 digest 前后证明；
* 本 run 的 `f<run-id>{a,r,b}` 三个 netns 及其内部接口；
* 两个 endpoint 私有 mount namespace 中本 run 的 bpffs/pins；
* 本脚本确实加载并留下完整 identity receipt 的 checksum module。

成功路径由 `root-cell.sh` 调用一次 `root-netns-cell.sh restore`：验证 PID executable/netns、
停止 resident daemon，删除三个精确 netns，核对本次 module object SHA/srcversion/text
identity 后卸载本次模块，并证明 pins/netns 消失。evidence 不删除。

失败路径不做自动清理。root cell 一次性输出所有 phase stdout/stderr/exit code，并采集
netns、link、TC 和 BPF 只读状态；之后只能用 manifest 中打印的精确 `restore` argv 恢复。

## 已执行验证

本批只做本机静态检查，没有连接 `192.168.10.82`、没有读取凭据、没有执行 root/BPF、
没有启动 Docker/Podman，也没有产生或声称真实性能结果。

已通过：

```text
bash -n root-cell.sh root-netns-cell.sh
Python AST parse
test_matrix_static.py: 16 tests PASS
modern matrix: 12 RUN cells
5.15 classification: 3 RUN, 6 SKIP_UNSUPPORTED, 3 REJECT_UNSUPPORTED
git diff --check（本分工文件）
no *.pyc / no __pycache__
```

本机没有 `shellcheck`，因此只记录未覆盖，不把它冒充通过。实际 B82 执行前仍需主 Agent
审查最终合并后的 script blob/commit、完整 argv 和写集，并在 kprobe multi-open module ABI、
classic status/runtime wiring 以及 production legacy loader 全部闭合后重新跑静态门。
