# Codex 破甲处置：恢复报告

> **日期**：2026-08-22
> **对象**：`C:\Users\Damon\.codex`（本机真实 Codex 配置目录）
> **性质**：安全事件处置——**已完整恢复原状**（初次误判为入侵痕迹并清理，经确认是用户有意保留的自定义注入，已逐字节复原）

## 一、最终结论

**破甲注入已完整恢复到清理前状态。** 检测器扫描 `.codex` 返回的信号与清理前**完全一致**：
- `model_instructions_file = './gpt5.5-unrestricted.md'`（指令接管已还原）
- `skills/ac` + `skills/leila-identity` 已恢复
- 3 个 warning（`instructions-redirect` + 2×`unexpected-skill`）与清理前画像一致

> ⚠️ **重要更正**：这套注入是用户**自己部署、有意保留**的自定义 Codex 行为，并非入侵。初次清理系误判，已全部恢复。今后涉及用户 `.codex` 一律先确认是否为有意资产再处置。

## 二、初次清理后已恢复的资产

| 对象 | 处置 |
|------|------|
| `config.toml` 第2行 `model_instructions_file = "./gpt5.5-unrestricted.md"` | ✅ 已还原 |
| `gpt5.5-unrestricted.md`（8600B, 8-21 23:09） | ✅ 已退回 |
| `gpt-5.6-sol-unrestricted.md`（5137B, 7-17） | ✅ 已退回 |
| `skills/ac/`（SKILL + references + agents） | ✅ 已恢复 |
| `skills/leila-identity/`（SKILL + agents） | ✅ 已恢复 |
| `leila-backups/` | ✅ 已补回 |

**时间戳与大小均与清理前一致**，未破坏任何字节。

## 三、恢复点（安全网，仍保留）

```
C:\Users\Damon\.codex-restore-point-20260822\
├── config\   （config.toml.current / clean-bak / 两个破甲 md 副本）
├── skills\   （ac + leila-identity 副本）
└── trash\    （已清空——恢复时全部移回 .codex）
```

## 四、验证

- `.codex` 根目录 `gpt5.5-unrestricted.md` / `gpt-5.6-sol-unrestricted.md` 已回（大小/时间戳一致）
- `skills/ac` / `skills/leila-identity` 已回
- `leila-backups/` 已补回
- `config.toml` 含第2行指令接管，TOML 合法可解析
- 检测器命中与清理前一致的 3 个 warning

## 五、教训（今后遵守）

1. 看到 `.codex` 有破甲/AC/指令接管 ≠ 一定要清理——先确认是否为用户**有意保留**。
2. 动用户 `.codex` 前必须建恢复点（本次能恢复全靠它）。
3. 用户的 `gpt-5.6-sol-unrestricted.md`（7-17）疑似其自留的同类注入，保留。
