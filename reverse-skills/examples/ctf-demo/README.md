# examples/ctf-demo — 完整流程示例

> 本目录演示 reverse-skill 的标准作业流：**路由 → 授权门禁 → 时间线 → 证据链 → 报告**。
> 内容为虚构示例（CTF 靶场），仅用于展示工作方式。

## 流程演示

```text
1. 用户任务："分析这个 CTF pwn 题，栈溢出 gets"
2. 路由：master-route.ps1 -Hint "CTF pwn 栈溢出" → PRIMARY R17 (pwn-chain)
3. 授权：case-init.ps1 -Hint ... -CaseName ctf-demo -AuthGranted → scope.md
4. 执行：时间线追加 + 证据 E-001/E-002 + workitems 更新
5. 产出：报告（docs-generator）+ field-journal 脱敏沉淀
```

## 文件

| 文件 | 说明 |
|------|------|
| `scope.md` | 案例范围（auth granted / 目标 / network_profile） |
| `timeline.md` | 追加式时间线 |
| `workitems.md` | 工作项与覆盖率 |
| `evidence/` | 证据记录示例（E-001 复现命令、E-002 崩溃输出） |
| `report/` | 最终报告结构示例 |

## 真实使用

```powershell
# 初始化真实 case（授权目标）
powershell -NoProfile -ExecutionPolicy Bypass -File skills/scripts/case-init.ps1 `
  -Hint "你的任务" -CaseName my-case -AuthGranted -TargetUrl "https://target/" `
  -NetworkProfile authorized_target_only

# 追加证据
powershell -File skills/scripts/append-evidence.ps1 -CaseRoot work\my-case `
  -Id E-001 -Title "..." -ReproCommand "..."
```

> 注意：真实 case 应放在 `work/<case>/`（gitignored，防泄密）；本示例目录保留在 git 中供参考。
