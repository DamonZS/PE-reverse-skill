# P11 完整源码重构最终验收

P11 只接受全新隔离环境中的生产链实证。单元测试、注入 runner、固定响应服务、已有工作区产物和手工修改 JSON 均不能作为通过证据。

运行：

```powershell
pwsh -File scripts/accept_p11.ps1
```

机器证据写入 `reports/p11-acceptance.json`，并绑定 Git HEAD、脏工作树源码内容摘要、镜像 ID、工具版本、样本源码哈希、样本二进制哈希和 ZIP 哈希。样本源码只存在于临时 ground-truth 目录，重构容器只能读取编译产物、公开行为规范和公开资源。

验收必须同时证明：

1. 上传 ZIP 后通过平台生产 API/worker 或 `archive_reconstruct` 生产入口执行，未调用测试 callback。
2. 真实 OpenAI-compatible 模型至少完成一次逐模块推理，调用数和 Token 均大于零。
3. 提取、反编译、知识图谱、模型补全、工程清单、依赖锁、隔离构建均有带哈希 artifact。
4. 构建阶段和行为阶段网络为 `none`；只有模型调用阶段允许访问 provider。
5. 行为验证使用真实子进程，`runner_injected=false`、`real_subprocess=true`、`shell=false`，至少比较退出码、stdout、stderr 和一个输出文件。
6. P0 六项门禁全部为 true，并由可信 artifact loader 派生 `complete_buildable=true`。
7. P1 审计逐项列出 skill、tool、script、provider 与 GitHub tool 的发现和 smoke 状态，目录覆盖率不能替代 live readiness。

## 最新生产验收

2026-07-25 的全新隔离运行已通过，机器报告为 `reports/p11-acceptance.json`，绑定工件目录 `reports/p11-artifacts-af887ea1f7f844f18904adcc9b7d9445`。本轮使用外部 `gpt-5.6-terra`，未启用本地模型回退；模型完成 2 次真实调用、产生 2 次源码修改并消耗 23,302 Token。知识图谱包含 27 个节点和 30 条边，隔离构建通过，真实子进程完成退出码、stdout、stderr 和输出文件共 4 项行为比较。

生产 worker 保持 `network=none`，模型请求只经控制面 broker 发出。报告与可信工件均派生出 `complete_buildable=true`，阻断项为空。该结论证明受支持的授权归档重构闭环，不自动提升需要真实设备、签名凭据、驱动、DMA 硬件或其他平台目标的独立 capability 状态。
