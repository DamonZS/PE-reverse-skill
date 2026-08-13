# RE Agent 工作流门闩（静态↔动态）

> 来源启发：binary-re 阶段划分、社区 RE skill（Frida/r2/Ghidra/IDA 循环）、Cerberus 三头环（静/动/插桩）  
> 日期：2026-07-17  
> 适用：`reverse-engineering/`、`ida-reverse/`、`radare2/`、与 cre 角色交接

## 0. 启动

```text
□ scope.md：offline 样本路径 或 授权设备/靶机
□ tool-index：file/strings/r2/ida/frida 等实际路径
□ 角色：cre（ops/role-map）
```

## 1. Triage（5–15 分钟）

```text
□ file / DIE / 熵 / 壳特征
□ strings / rabin2 -z 捡漏
□ 架构/链接/是否 .NET/Go/Rust/加壳
□ MUST 导入/导出表：rabin2 -i / -E（或 IDA imports / 等价物）
□ 产出：E-triage（MUST 含 imports 分类摘要：网络/文件/加密/注入/注册表）+ 假设清单（勿过早下结论）
```

**阶段门闩（Triage → Static/Dynamic）**：E-triage 中未记录 imports 摘要前，MUST NOT 进入 Dynamic，也 MUST NOT 声称「基础分诊完成」。导入表解析失败时仍 MUST 把失败输出写入 Evidence，不得跳过。用户要求「重做导入表检查」时 MUST 重做 imports 步骤本身，禁止改换其他分析步骤。

## 2. Static

| 工具 | 何时 |
|------|------|
| radare2 / rabin2 | 快速函数/导入/字符串（imports 已在 Triage MUST 完成） |
| IDA / Ghidra（MCP 或 headless） | 深挖、交叉引用、类型；survey 阶段复核 imports 分类 |
| jadx / dnSpy | Android / .NET |
| OLLVM 文档 | 控制流平坦化怀疑 |

```text
□ 确认 E-imports / E-triage 已含导入表 Evidence（缺失则先补，禁止后置）
□ 定位关键函数（加密/校验/网络/授权）
□ 记录地址/符号 → Evidence
□ 一条路不通 → 换工具（IDA?r2?Ghidra）
```

**无 MCP 时**：可用导出反编译文本再分析（对照 P4nda0s reverse-skills / IDA-NO-MCP 思路），仍写 Evidence 路径。

## 3. Dynamic

```text
□ Frida / gdb / emulator：验证静态假设
□ 反调试/反 Frida → reverse-engineering/anti-analysis
□ Android：root 检测 / SSL pinning 绕过脚本按需生成，**须在授权设备**
□ 崩溃日志驱动下一轮 hook（自适应循环）
```

## 4. Synthesis

```text
□ Finding：算法/校验逻辑/可利用点
□ Path：callflow 或 solve 步骤挂 E-*
□ 报告 docs-generator + 可选图
□ field-journal 脱敏
```

## 5. 与「堆 RE skill 插件」的差异

- 本包用 **阶段门闩 + tool-index**，不默认启用 Hex-Rays「unsafe 全自动执行」类插件  
- 动态插桩默认 **offline/lab** network_profile  