# B82 63 格完整性能矩阵实现

本批次把 82 性能方案从旧的 33 格扩展为 63 格、567 份客户端采样，并将所有模式
统一到轻量 production cell，而不是复用较重的通用 smoke 套件。

## 已完成

* 精确配置集合：原生 WireGuard 1 格、UDP 20 格、ICMP 2 格、FakeTCP 40 格；
* FakeTCP 覆盖 TCX/传统 TC、kfunc/kprobe、modern/Linux 5.15 legacy 对象和 10 种
  XOR 形态，并保持 exact generic XDP、常驻 daemon、临时 nft guard 和 fail-closed；
* production cell 修正 private bpffs 顺序，并验证 TCX/classic attachment、checksum
  backend、kprobe lease（含流量后 errors/nmissed/cookie 健康复核）、classic durable journal、
  重载/崩溃恢复和停止后的 exact ID 消失；
* 矩阵一次构建并冻结 6 个 artifact，在每格前后复核 SHA-256；kfunc/kprobe 模块按阶段
  切换，保留 intent/owned/restored receipt，失败不自动卸载；Go binary 使用只读 overlay
  嵌入已冻结的三份 BPF 对象，不回写 clean source stage，并以三阶段完整 tree digest
  证明 source 未变；
* 失败时完整输出所有日志并保留现场；plan 输出每格完整 argv/write-set/restore argv，
  run 使用 9000 秒 tmux 预算；tmux 通过无参数版本化 wrapper 启动，不拼接高权限
  多层 shell 命令；
* 新增中文 Markdown/JSON 报告生成器，计算均值、总体标准差、最小/最大、重传和 Jain；
  双向吞吐按同轮相加，重传不重复计算双向分项；
* exporter/cleanup 支持 v2 matrix proof，绑定 artifact/results/report digest，并提高到足以
  容纳 63 个完整子 evidence 的有界清理规模；
* matrix artifact/evidence 根固定迁移到 `/var/tmp/wg-mix-ebpf-performance-tests`，避免
  63 格运行耗尽 82 容量较小的 `/run` tmpfs；endpoint 私有 `/run` bind 不变；
* 增加专用 README，明确只读 plan、tmux 执行、失败保留、显式 cell/module restore 和
  export 后精确 cleanup 流程；
* 新增 16 项 static/synthetic 测试（含完整 63 格/567 JSON 中文报告生成）并接入
  Makefile lint/smoke helper。

## 静态验证结果

本机以 `PYTHONDONTWRITEBYTECODE=1` 运行专用测试，16/16 通过；该测试实际构造 63 个
cell、567 份 iperf3 客户端 JSON，并生成/校验中文 Markdown 与规范化 JSON。完整 helper
套件为 32 项（5 项按平台条件跳过）、5 项、3 项和 16 项，全部通过。matrix、tmux
wrapper、production cell 和 exporter 四个 Bash 脚本通过 `bash -n`，三个 Python 文件
通过 AST parse，`git diff --check` 通过，工作树中没有 `.pyc` 或 `__pycache__`。本机没有
shellcheck，因此仅在 Makefile 中接入了可用时执行的 gate，未宣称本地 shellcheck 已运行。

## 验证边界

本机仅执行 bash 语法、Python AST、静态/合成统计测试和差异检查；没有连接 82、没有
在本机启动容器或执行 Linux/BPF/netns。真实 63 格运行应在冻结提交进入 82 的 root-owned
source stage 后，先审阅只读 plan，再按计划放入 tmux。
