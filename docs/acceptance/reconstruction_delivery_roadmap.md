# 完整源码重构长期任务

目标是从授权的二进制或压缩包产出可实际构建的重构工程，并且只在编译和行为验证均通过后标记 `complete_buildable=true`。

## 阶段与当前状态

| 顺序 | 阶段 | 状态 | 进入条件 | 完成证据 |
| --- | --- | --- | --- | --- |
| 0 | 平台生产化基础 | 已验收 | 无 | `reports/p10-acceptance.json`、Go/前端/备份测试通过 |
| 1 | 解包、反编译、资源提取与证据归档 | 已验收 | 已上传授权样本 | P11 archive manifest、capability plan、工具证据与哈希 |
| 2 | 知识图谱建立模块关系 | 已验收 | 阶段 1 产生模块与证据 | `docs/reconstruction-graph.json`，27 节点、30 条边 |
| 3 | 模型逐模块理解和源码补全 | 已验收 | 阶段 2 图谱可用，模型 Provider 已配置 | 外部 `gpt-5.6-terra` 真实调用、2 次源码修改、23,302 Token |
| 4 | 工程结构、依赖锁定与实际编译 | 已验收 | 阶段 3 无未解决结构阻塞 | manifest、dependency lock、隔离真实构建通过 |
| 5 | 编译错误反馈与模型修复循环 | 已实现并验证 | 阶段 4 发生可诊断编译失败 | 有界诊断反馈、模型修复、重新构建和回滚测试；成功首编时不强制制造失败 |
| 6 | 原程序与重构程序行为对比 | 已验收 | 已提供可执行的授权行为规范或 fixture | 真实子进程完成退出码、stdout、stderr、输出文件 4 项比较 |
| 7 | 完整可构建发布 | 已验收 | 阶段 4、5、6 全部通过 | P11 报告及可信工件均为 `complete_buildable=true` |

## 监控规则

- 每个任务运行必须保留 archive manifest、工具调用结果、artifact 哈希、知识图谱、模型调用审计、构建和行为验证报告。
- capability plan 必须记录目标文件哈希、声明产物、缺失产物以及文件或目录树的确定性 SHA-256；知识图谱必须保留 `BinaryTarget -> ToolStage -> EvidenceArtifact` 来源链。
- 模型源码修改必须至少引用一个当前模块源码文件，并可引用当前模块图谱中的真实节点或边；未知证据 ID 必须拒绝。
- 只有所有模块模型调用均为 `executed` 时模型阶段才可完成；成功与 `dependency-gated` 混合时必须标记为 `partial` 并阻止构建放行。
- 所有分析、构建和行为 worker 保持 `--network none`；模型请求由控制面 broker 发出，密钥不进入 worker。
- 失败、超时、外部工具缺失、模型未配置或没有行为规范必须显示为 `failed`、`timed_out` 或 `dependency-gated`，不能以成功替代。
- 阶段 7 只能由验证结果驱动；存在结构阻塞、未锁定依赖、编译失败、行为不匹配或无真实样本验收时，状态保持未完成。
- 每次发布前运行 `go test ./... -count=1`、前端测试与构建、`tests/test_platform_backup.py`，并更新对应验收报告。

## 生产结论与外部门禁

2026-07-25 的 P11 全新隔离验收已通过，证据位于 `reports/p11-acceptance.json` 和 `reports/p11-artifacts-af887ea1f7f844f18904adcc9b7d9445`。该结果关闭受支持授权归档的完整源码重构主链路。

以下依赖仍按具体目标逐任务检查；缺失时不得复用上述通过结果：

- 授权的代表性样本与可重复行为 fixture。
- 已启用的 `openai_compatible` Provider、模型名和 API 凭据；未配置时模型阶段必须保持 `dependency-gated`。
- 与目标语言/平台匹配的真实反编译、SDK、编译器和签名工具链。
