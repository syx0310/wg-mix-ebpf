# B82 完整性能矩阵计划

目标是在 `192.168.10.82` 上以同一套隔离 netns/WireGuard 拓扑比较纯
WireGuard、TCX 和传统 TC，并对常用 XOR 处理长度做短时多轮采样。

## 固定矩阵

* 纯 WireGuard：不加载 BPF；
* TCX、传统 TC：无 XOR；
* TCX、传统 TC：`wg-payload-prefix`，`max_bytes` 分别为
  `4/16/64/128/256/512/1024/2048`；
* TCX、传统 TC：`wg-payload-full`，`max_bytes=2048`。

共 21 个配置。XOR 密钥派生和 key 长度保持生产默认值，只改变实际处理的 payload
字节上限。

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
