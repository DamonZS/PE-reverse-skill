# Vendor Report Rules（专业厂商报告结构叠加层）

> Issue #65 问题 2。  
> **只抽结构与写法规则，禁止抄录任何厂商报告正文、图表、真实 IOC 实例或大段表述。**  
> 本文件是**叠加层**：不替换 `security-report-templates.md` 的任务模板，也不削弱 §0 Evidence→Finding→Path。

结构参考（公开样例，仅骨架）：

| Flavor | 主参考 | 场景 |
|--------|--------|------|
| `malware`（**默认**） | 火绒安全病毒/技术分析报告 | 普通木马、白加黑、钓鱼投毒、单样本逆向 |
| `apt` | 卡巴斯基 Securelist / APT 战役报告（如 MATA） | APT、团伙战役、多阶段感染链、行业定向 |

原则：**模板在精不在多** —— 仅 2 个 flavor + 1 份通用专业元素，不为第三家厂商再复制全文模板。

---

## 0. 何时启用

在 `docs-generator` 生成**安全类**报告时（逆向 / 恶意软件 / 渗透收尾 / 用户明确要求「专业报告」「厂商风格」）**MUST** 读取本文件并选定 flavor。

| 信号 | Flavor |
|------|--------|
| APT / 团伙 / 战役 / 多阶段 C2 / 行业定向 / ICS / spear-phish 战役 | `apt` |
| 单样本、木马、窃密、白加黑、仿冒站点、日常程序分析 | `malware`（默认） |
| 渗透测试 / CTF / JS 签名 | **不换 flavor 全文骨架**；仍套用下方「通用专业元素」最小集 + 原任务模板 |

用户显式指定「按卡巴/APT」「按火绒/病毒报告」时，覆盖自动选型。

---

## 1. 通用专业元素（所有安全报告）

下列元素 **SHOULD** 出现；标 **MUST** 的不可省略（可用一行 `n/a` + 原因占位，禁止整节消失）。

| # | 元素 | 要求 |
|---|------|------|
| G1 | 执行摘要 / 概述 | **MUST**：3–8 句：分析了什么、最严重结论、影响面、建议动作 |
| G2 | 范围与授权 | **MUST**：链到 case `scope.md`（见模板 §0.1） |
| G3 | Evidence→Finding→Path | **MUST**：见 `security-report-templates.md` §0 与 `ops/evidence-finding-path.md` |
| G4 | IOC 表 | **MUST** 有表头；无指标时一行 `n/a` + 原因（未做流量/无外联等） |
| G5 | 建议 / 处置 | **MUST**：至少 1 条可执行建议（检测、缓解或应急步骤） |
| G6 | 附录元数据 | **SHOULD**：工具与版本、样本哈希、完整复现命令 |
| G7 | ATT&CK 映射 | **SHOULD**（`apt` 下升级为有表可 `n/a` 的硬章节）；技术 ID + 简短证据指针 |

### 1.1 IOC 表最小列

```markdown
| 类型 | 值 | 上下文 | 置信度 |
|------|----|--------|--------|
| file_sha256 / file_md5 / domain / ip:port / url / mutex / path / registry | … | 何处发现 | high/med/low |
```

### 1.2 版权与安全边界

- 不得粘贴厂商 PDF/网页正文段落或图注充作己方分析。
- 真实 token、内网 URL、客户标识用占位符。
- 未授权目标不得输出可直接利用的攻击步骤细节（遵循 case scope / RULES）。

---

## 2. Flavor：`malware`（火绒式 · 默认）

**叙事目标**：让读者 5 分钟内看懂「是什么 → 怎么来的 → 样本怎么干的 → 怎么处置 → 有哪些 IOC」。

### 2.1 推荐章节顺序

```markdown
# [标题：一句话威胁定性]

> 分析日期 / 分析方 / 样本标识（哈希）

## 1. 概述
（G1：发现渠道、伪装手法、核心技术点、产品侧可否查杀——若未知写 n/a）

## 2. 攻击 / 感染流程
（流程图：Mermaid 或分步列表；对应 Path `path_type=attack`）

## 3. 样本分析
### 3.1 样本溯源
### 3.2 静态分析
（**MUST** 纳入导入表 / 基础身份 Evidence：E-imports 或等价；见 radare2/ida/malware 硬门）
### 3.3 动态分析 / 行为
（无动态条件则 n/a + 原因）
### 3.4 核心发现（Findings 表或编号列表，挂 evidence_ids）

## 4. 应急处置方式
（编号可执行步骤：断网 → 杀进程 → 清文件 → 查 hosts/启动项 → 全盘查杀 → 复核）

## 5. 总结说明
（给普通用户/运维的风险提醒与预防）

## 6. IOC 信息
（G4 表）

## 7. Evidence 链摘要
（§0：E / F / P / Timeline；可与 §3.4 合并但字段不省）

## 8. 附录
（工具版本、复现命令、脚本路径）
```

### 2.2 文风

- 中文用户默认中文；先结论后细节。
- 静态分析按「组件/阶段」分层，避免无结构的长日志粘贴。
- 处置步骤必须可独立执行，禁止「加强安全意识」空话充数。

---

## 3. Flavor：`apt`（卡巴斯基 Securelist 式）

**叙事目标**：讲清战役级故事——谁在何时用何链打了谁，调查如何推进，组件如何分工，防守方拿什么去检。

### 3.1 推荐章节顺序

```markdown
# [战役/集群名称]：[一句话影响]

> 日期 / 团队 / 行业与地区范围（若可知）

## 1. Executive summary
（G1：时间窗、受害者画像、入口、家族/集群归属、持续时长、最重要结论）

## 2. The infection chain
（分阶段：投递 → exploit/loader → 主马 → 后渗透/窃密；未知段明确 “limited visibility”
对应 Path；建议配链图）

## 3. Incident investigation
（调查叙事：关键转折、内网代理/C2 特征、如何扩大范围；挂 Timeline）

## 4. Interesting findings
（3–7 条非显而易见要点，每条尽量挂 E-id / F-id）

## 5. Technical analysis
### 5.1 组件总览表（loader / trojan / stealer / …）
### 5.2 分组件行为与配置
### 5.3 静态要点（含导入表/加壳/持久化 Evidence）
### 5.4 网络与 C2
（可附 ATT&CK 表 G7）

## 6. Detection and mitigation
（检测思路 / 狩猎线索 / 缓解优先级；非空泛口号）

## 7. IOC
（G4；按类型分组）

## 8. Evidence 链摘要
（§0 字段）

## 9. Appendix
（样本列表与哈希、工具版本、参考公开编号；不抄外部报告正文）
```

### 3.2 文风

- 时间线与「可见性限制」要诚实写。
- Interesting findings ≠ 重复概述；写调查中真正关键的异常点。
- 组件分析用表：角色 / 持久化 / C2 / 依赖，再展开。

---

## 4. 与现有任务模板的挂接

| 任务模板（`security-report-templates.md`） | 叠加方式 |
|------------------------------------------|----------|
| 1. 逆向工程报告 | 默认 `malware`：用 §2 顺序重排；原「静态/动态/复现」并入 §3/附录；**保留**导入表等硬门产出为 Evidence |
| 2. 渗透测试报告 | 不套 APT 全文；补 G1（若缺）、G4（若有基础设施 IOC）、G5；攻击路径对齐 §0 Path |
| 3. CTF Writeup | 仅 G1 一句概述 + 可复现；不强制 IOC/ATT&CK |
| 4. JS/Web 签名逆向 | 默认偏 `malware` 精简：概述 → 定位 → 算法 → 复现 → IOC(n/a 常见) |
| 恶意软件 / APT 专项 | 显式选 `malware` 或 `apt` 全文骨架 |

**冲突解决**：§0 Evidence 链字段与 scope 门禁 **永远优先**；flavor 只改叙事顺序与专业外壳，不得删除 E/F/P。

---

## 5. 选型伪代码

```
if user_requests_kaspersky or apt or campaign:
    flavor = apt
elif user_requests_huorong or vir_report or single_malware:
    flavor = malware
elif task in (pentest, ctf, js_sign):
    flavor = null  # 任务模板 + 通用元素最小集
else:
    flavor = malware  # 默认
emit(report with G1–G7 and flavor outline)
```

---

## 6. 完成检查清单（写报告末自检）

- [ ] 已选 flavor 或显式「任务模板 + 最小集」
- [ ] G1 概述存在且非空话
- [ ] §0 E/F/P 字段完整
- [ ] IOC 表存在（或 n/a+原因）
- [ ] 有可执行建议/处置
- [ ] 无厂商原文粘贴、无 placeholder/TODO
- [ ] 导入表等硬门 Evidence 已进入静态/技术分析（若本任务做过二进制分析）

---

## 7. 非目标

- 不维护 Mandiant/CrowdStrike/奇安信等额外全文模板（结构已由双 flavor 覆盖常见需求）。
- 不自动爬取厂商站点填报告。
- 不因 flavor 降低 Evidence 契约或授权范围。