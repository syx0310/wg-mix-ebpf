# B82 完整性能矩阵计划

目标是在 `192.168.10.82` 上以同一套隔离 netns/WireGuard 拓扑比较纯
WireGuard、TCX 和传统 TC，并对常用 XOR 处理长度做短时多轮采样。

## 固定矩阵

* 纯 WireGuard：不加载 BPF；
* UDP + TCX、UDP + 传统 TC：无 XOR；
* UDP + TCX、UDP + 传统 TC：`wg-payload-prefix`，`max_bytes` 分别为
  `4/16/64/128/256/512/1024/2048`；
* UDP + TCX、UDP + 传统 TC：`wg-payload-full`，`max_bytes=2048`；
* ICMP + TCX、ICMP + 传统 TC：无 XOR；
* FakeTCP + TCX + generic XDP：无 XOR、上述 8 个 prefix 长度、
  `wg-payload-full/max_bytes=2048`。

共 33 个配置。FakeTCP 生产合同不支持传统 TC，因此不伪造 FakeTCP/classic
结果。XOR 密钥派生和 key 长度保持生产默认值，只改变实际处理的 payload字节上限。

## 统一采样参数

* IPv4 underlay，underlay MTU 2200；
* 性能流量 WireGuard MTU 1420；
* iperf3 单流；正向、反向、双向；
* 每个方向 3 秒，每个配置重复 3 次；
* 每个样本继续检查接收量、重传和 Jain 公平性；
* 输出每组样本的均值、总体标准差、最小值和最大值。

## 执行与清理

只在 82 上执行 Linux、BPF 和网络测试。本机只做格式化、静态检查、交叉编译、
结果汇总和文档生成。每个配置使用现有 private mount namespace 入口和随机 run ID；
成功路径必须完成精确 detach、netns 停止和 private bpffs 卸载。失败时停止后续配置，
保留完整脱敏日志与 owner-bound 现场，不自动猜测清理。

最终只读核对活动 netns、测试接口、BPF link/pin 和 source stage；结果写入中文
工作记录，提交、合并到 `main` 并 push。

FakeTCP 单元另需先通过管理员预置 checksum kfunc module、verifier、真实
generic-XDP/TCX 生命周期、offload/MTU/GSO/slow-path 与回滚门；性能数字不能替代这些
正确性证据。所有原始 stdout/stderr/退出码一次性写入本次运行专属本地 evidence，
只遮蔽密码、私钥和 ownership token。
