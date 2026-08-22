# AGENTS.md

本文件是仓库内 coding agent 的执行入口。项目术语以根目录 `CONTEXT.md` 为准；实现状态以源码、配置和测试为准；README 与验收文档用于理解产品目标和已验证边界。

## 项目定位

PE Reverse Analyzer 是一个面向逆向分析、软件安全研究和源码重构的本地优先平台。目标不是只输出反编译文本，而是把样本、分析计划、工具执行、证据、知识图谱、源码工程、真实构建和行为比较组织为可追溯流程。

当前仓库同时包含四类交付物：

1. **分析内核**：Python 包 `reverse_analyzer`，提供 CLI、静态/动态/GUI 分析、Provider/Capability、证据清单、PE/APK/协议处理、补丁和源码重构。
2. **生产平台**：Go 控制面、React 中文工作台、PostgreSQL 持久化和隔离 Runner，承载上传、Experiment/Flow、模型 Provider、知识库、制品、构建、补丁、终端与访问控制。
3. **技能路由包**：`reverse-skills/skills/`，供 AI 客户端按目标、意图和工具条件选择逆向工作流；它可独立使用，也被平台目录索引。
4. **跨平台指令部署**：`reverse_analyzer/instructions/`，把同一份品牌化「拓扑」破甲指令注入 Codex / Claude / Cursor / WorkBuddy 四个平台的适配层；CLI 为 `reverse-instruct`，内容复用 `topo-ac-unrestricted` / `gpt5.5-unrestricted.md` 破甲主弹药。

完整源码重构主链路为：

```text
样本/归档上传
  -> 解包、反编译、资源与静态证据
  -> 知识图谱与模块关系
  -> 模型逐模块理解和源码修改
  -> 工程结构与依赖锁定
  -> 隔离真实构建
  -> 编译诊断与有界修复
  -> 原程序/重构程序行为比较
  -> 可信工件门禁派生 complete_buildable
```

`complete_buildable=true` 只表示当前受支持目标已通过结构、依赖、构建和行为门禁，不表示逐字恢复编译前原始源码，也不能替代其他平台、设备或签名环境的独立验收。详细门禁见 `docs/acceptance/p11_complete_reconstruction.md`。

## 运行架构

```text
Browser
  -> Go Control Plane :8090
       -> PostgreSQL（生产元数据、租户、审计、知识、Provider）
       -> Workspace Volume（上传、日志、制品、源码、补丁、报告）
       -> Runner API :8091
            -> Docker/Podman 隔离 Worker
                 -> python -m reverse_analyzer ...
                 -> archive_reconstruct / web_patch_bridge / CMake build
       -> Provider Broker
            -> 外部 OpenAI-compatible 模型

Go Control Plane 同时提供 frontend/dist 静态文件和 /api/* JSON/SSE 接口。
```

关键运行原则：

- Go 是 Web/API、认证、持久化和任务编排的事实入口；Python 不再承担生产 Web 服务。
- Worker 默认只读根文件系统、丢弃 capabilities、启用 `no-new-privileges`、限制 CPU/内存/PID，并默认 `network=none`。
- 模型请求由 Go Provider Broker 发出；密钥不进入分析或构建 Worker。
- 创建 Experiment 只产生计划。实际分析必须提交确认短语 `EXECUTE_LOCAL_ANALYSIS`。
- 生产模式强制 PostgreSQL、认证和远程 Runner；持久化不可用时 readiness 降级，不回退到本地 JSON。
- 本地非生产模式可把 Experiment 保存为 `experiments/<id>.json`、事件保存为 `experiments/<id>/events.jsonl`。

部署关系见 `Dockerfile`、`Dockerfile.runner`、`deploy/compose.production.yml` 和 `docs/web-deployment.md`。生产站点为 `https://pe.toporeduce.cn`；远程代码知识图谱端点为 `https://pe.toporeduce.cn/codegraph/rpc`。

## 核心对象

不要混用以下三套对象：

### 平台 Experiment

定义在 `cmd/reverse-analyzer-server/main.go`，是 Web 平台的持久化任务聚合根，包含：

- 样本、选项、状态、历史、制品与错误；
- `ReconstructionState`：分析、源码、结构、依赖、构建、行为和 `complete_buildable` 门禁；
- `OrchestrationState`：Flow、Task、Subtask、ToolCall 与最后事件序号；
- 追加式 `Event`：sequence、type、status、message、data，通过 SSE 推送给前端。

Experiment 状态变化必须同步更新持久化、事件和编排快照。控制面重启时遗留 `running` 任务会转为 `failed`，并要求重新生成构建与行为证据。

### Python Session / Flow

定义在 `reverse_analyzer/core/`、`runtime/` 和 `cli.py`，用于 CLI 与分析内核中的工具、Provider、审计和工件编排。它不是 Go 平台 Experiment 的数据库模型；二者通过命令参数、JSON、文件和事件连接。

### 技能 Case

由 `reverse-skills/skills/scripts/case-init.py` 创建，结构为 `case.json`、`notes.md`、`evidence/`、`reports/`，用于 AI 技能工作流的本地证据记录。它不是平台 Experiment，也不是 Python Session。修改 Case schema 时同步检查 `case-review` 脚本和相关测试。

## 关键事实源

| 主题 | 事实源 | 说明 |
| --- | --- | --- |
| 项目术语 | `CONTEXT.md` | Case、Plan、Skill、Tool index、Evidence 等共享词汇。 |
| Python CLI | `reverse_analyzer/cli.py`、`reverse_analyzer/__main__.py`、`pyproject.toml` | `reverse-analyzer` 与 `python -m reverse_analyzer` 入口。 |
| Go API 与模型 | `cmd/reverse-analyzer-server/main.go` | 路由、Experiment、编排、事件、worker 和静态前端服务。 |
| RBAC | `cmd/reverse-analyzer-server/auth.go` | `viewer`、`analyst`、`admin` 权限和 workspace 约束。 |
| 数据库迁移 | `cmd/reverse-analyzer-server/migrations/*.sql` | `database.go` 内嵌并按连续版本执行；`schema.sql` 不是运行时迁移事实源。 |
| Runner 边界 | `cmd/reverse-analyzer-runner/main.go` | 允许的 job kind、参数、环境变量、容器限制与输出协议。 |
| Provider 配置 | `cmd/reverse-analyzer-server/providers.go`、`provider_broker.go` | 平台 Provider、模型协议、优先级、密钥槽与用量。 |
| Python 运行目录 | `reverse_analyzer/config.py` | workspace、knowledge、sessions、reports 的环境变量规则。 |
| 证据清单 | `reverse_analyzer/evidence/manifest.py` | 显式声明工件、相对路径、SHA-256、不可用阶段和验证规则。 |
| 技能路由 | `reverse-skills/skills/config/routing.json` | 技能工作流唯一事实源。 |
| 跨平台指令部署 | `reverse_analyzer/instructions/`（`adapter.py`、`platforms/*`、`registry.py`、`cli.py`） | `reverse-instruct` list/describe/inspect/deploy/restore；四平台适配器（Codex/Claude/Cursor/WorkBuddy）与统一安全模型。 |
| 技能工具契约 | `reverse-skills/skills/config/tool-manifest.json` | 工具 ID、依赖和执行边界。 |
| 技能导航 | `reverse-skills/skills/INDEX.md` | 生成文件，只用于导航。 |
| 前端契约 | `frontend/src/App.tsx`、`frontend/src/api/catalog.ts` | API DTO、页面状态、SSE 消费和目录归一化。 |
| 生产部署 | `deploy/compose.production.yml`、`Dockerfile*` | Web、PostgreSQL、Runner、卷、secret 和容器边界。 |
| 生产验收 | `docs/acceptance/p10_platform_production.md` | 多租户、迁移、审计、备份恢复和生产门禁。 |
| 重构验收 | `docs/acceptance/p11_complete_reconstruction.md` | 真实模型、隔离构建、行为比较和可信工件门禁。 |

`README.md` 描述面向用户的能力与命令；`docs/skill_parity_matrix.md` 描述能力实现状态；`.understand-anything/knowledge-graph.json` 和 `docs/项目知识图谱.md` 用于跨模块导航。事实冲突时，优先级为：源码/配置/测试 > 当前验收报告 > README/知识图谱 > 历史工作记录。

## 模块导航

### Python 分析内核

- `reverse_analyzer/cli.py`：CLI 参数、分析生命周期和 Provider 调度。
- `reverse_analyzer/core/`：Session、Flow/Task/Subtask、Capability DTO、审计和 IR 基础模型。
- `reverse_analyzer/runtime/`、`reverse_analyzer/agent/`：实验运行时、规则式 Agent 和工具编排。
- `reverse_analyzer/tools/`：静态分析、Android、协议、内存、GUI、patch 等无状态工具入口。
- `reverse_analyzer/providers/`：需要生命周期、外部依赖或运行时状态的能力实现。
- `reverse_analyzer/evidence/`：证据 manifest、来源链和校验。
- `reverse_analyzer/source/`、`source_reconstruction.py`：工程生成、依赖、构建和行为验证。
- `reverse_analyzer/patch/`：补丁计划；底层事务写入逻辑位于工具层。
- `reverse_analyzer/report/`、`knowledge/`、`dashboard.py`：报告、知识演化和可视化数据。

Provider 生命周期保持：

```text
supports -> plan -> validate -> execute -> optional rollback -> collect_artifacts
```

每一阶段都应保留明确状态和审计；缺失依赖不得伪装成成功。

### 跨平台指令部署

- `reverse_analyzer/instructions/adapter.py`：`PlatformAdapter` ABC（deploy/inspect/restore/describe/default_target）、`DeployPlan`/`Operation`/`EvidenceEntry` 数据类，以及 `atomic_write`/`confine`/`backup_existing`/`sha256_*` 安全工具与常量（`INSTRUCTION_PROFILE="topo-ac-unrestricted"`、`IDENTITY_WORD="拓扑"` 等）。
- `reverse_analyzer/instructions/platforms/`：四平台适配器——`codex.py`（`config.toml model_instructions_file`）、`claude.py`（`settings.json hooks.UserPromptSubmit` stdout + `CLAUDE.md` 兜底）、`cursor.py`（`.cursor/rules/topo.ac.mdc` alwaysApply）、`workbuddy.py`（`topo-ac-unrestricted` skill 触发包）。
- `reverse_analyzer/instructions/registry.py`：平台注册表 + `deploy`/`inspect`/`restore` 调度 + `trea→cursor` 别名。
- `reverse_analyzer/instructions/cli.py` / `__main__.py`：`reverse-instruct` CLI（list/describe/inspect/deploy/restore），已注册进 `pyproject.toml`。

**约定**：describe 的 Operation 列表必须与 deploy 实际写入完全一致（Codex 为 7 文件）；Claude 路径约定为顶层 `instruction.md` + `hooks/instruction-inject.sh`（禁止拼成 `.claude/.claude/` 双重目录）；Claude hook 脚本用纯 bash `cat "$_INSTR"`，不依赖 python；Windows 下禁用 `subprocess.run(..., text=True)` 解码含中文的 bash 输出（须显式 `encoding="utf-8"`）。

### Go 控制面

- `cmd/reverse-analyzer-server/main.go`：服务入口、路由、Experiment/事件、源码与制品操作、构建和终端。
- `cmd/reverse-analyzer-server/auth.go`：认证、角色权限和 workspace 隔离。
- `cmd/reverse-analyzer-server/database.go`、`cmd/reverse-analyzer-server/migrations/`：PostgreSQL 初始化和迁移。
- `cmd/reverse-analyzer-server/audit.go`：审计事件与 outbox；写操作与审计完整性相关。
- `cmd/reverse-analyzer-server/providers.go`、`cmd/reverse-analyzer-server/provider_broker.go`：Provider 管理和模型请求代理。
- `cmd/reverse-analyzer-server/ai_patch.go`：模型生成的可审查源码修改计划。
- `cmd/reverse-analyzer-runner/main.go`：独立隔离执行服务。

新增 API 时同时定义：HTTP 方法、权限、workspace 边界、审计描述、错误状态、持久化行为和 Go 回归测试。

### 前端工作台

- `frontend/src/main.tsx`：React 入口。
- `frontend/src/App.tsx`：当前主要 UI、DTO、状态、API 调用和流程详情；尚未拆成路由或全局状态库。
- `frontend/src/api/catalog.ts`：平台目录响应兼容和归一化。
- `frontend/src/styles.css`：全局变量、布局、组件和响应式样式。

主要视图为态势总览、流程工作台、平台目录、模型服务、环境验收、知识库和访问控制。典型工作流是上传 -> 创建 Experiment -> 明确确认执行 -> SSE 跟踪 -> 查看编排、日志和制品 -> 源码/构建/补丁操作。

前端使用同源 `/api`，Token 存于 `localStorage.reverseAnalyzerWebToken` 并以 Bearer Token 发送。修改 Go JSON/SSE 契约时必须同步 `App.tsx` 类型、消费逻辑和 Go 测试。

### 技能路由体系

- 总入口：`reverse-skills/skills/SKILL.md`。
- 路由：`reverse-skills/skills/scripts/master-route.py` 或 `python -m reverse_analyzer skills route ...`。
- `routing.json` 决定 master skill、顺序 stages、subskills 和 tools。
- `tool-manifest.json` 声明工具契约；`INDEX.md` 由脚本生成。
- 修改技能、路由或工具记录后，重新生成索引并运行严格校验。

## 开始工作

1. 读 `CONTEXT.md`，确定本次任务使用的平台 Experiment、Python Session 还是技能 Case。
2. 涉及架构或跨模块行为时读取 `docs/adr/`；目录不存在时继续，不为占位创建 ADR。
3. 执行 `git status --short`，识别并保留用户已有改动。
4. 从“关键事实源”和“模块导航”定位生产代码、消费方与邻近测试。
5. 先建立可观察的失败或验收条件，再实施最小完整改动。
6. 按影响范围运行验证；完成标准是代码、契约、证据状态和文档保持一致。

## 实现规则

- 变更保持在现有模块所有权内；跨 Python、Go、前端的协议调整同步更新生产方、消费方和测试。
- 结构化配置使用 JSON、SQL 或语言解析器处理；避免用文本替换模拟结构化编辑。
- 数据库变化通过新的连续迁移表达，并覆盖首次初始化和旧版本升级；已发布迁移保持不可变。
- 技能变更先更新 `routing.json` 或 `tool-manifest.json`，再生成 `INDEX.md`。
- Evidence 只收录调用方显式声明的工件；存在的文件记录 SHA-256 和大小，缺失阶段保留 provenance，不生成虚假哈希。
- `complete_buildable` 由可信工件和门禁派生，不由 UI、手工 JSON 或单一成功状态直接设置。
- 路径操作必须保持在 workspace 内；涉及 symlink、归档解包、上传和源码文件 API 时覆盖逃逸测试。
- 普通单元测试保持离线、确定性和可重复。Live/E2E、真实设备、外部模型和部署验收只在任务需要且环境明确配置时执行。
- 密钥通过环境变量、secret file 或既有凭据机制注入，不写入源码、测试夹具、日志、报告或提交内容。
- 生成目录 `reports/`、`.reverse_analyzer/`、`experiments/`、`uploads/`、`frontend/dist/`、`node_modules/` 和 `__pycache__/` 不作为源码手工维护。

## 验证矩阵

按影响选择最小充分集合；共享契约、持久化、权限、Runner、发布链路或跨模块改动使用完整集合。

### Python 内核

```powershell
python -m compileall reverse_analyzer tests
python -m unittest discover -s tests -v
```

在 Windows WorkBuddy 环境中，宿主注入的 `ACC_PRODUCT_CONFIG_V3` 可能超过单环境变量 32767 字符限制，导致 `patch.dict(os.environ, ...)`、SSL/OpenAI 子进程测试出现连锁错误。遇到该情况时从测试进程环境移除该非项目变量后重跑，例如 Git Bash 使用 `env -u ACC_PRODUCT_CONFIG_V3 python -m unittest discover -s tests -v`；不要把这些测试改成 skip。

### Go 控制面与 Runner

```powershell
go test ./... -count=1
```

涉及 PostgreSQL 时设置测试数据库后补充：

```powershell
go test ./cmd/reverse-analyzer-server -run PostgreSQL -count=1
```

### 前端

```powershell
npm --prefix frontend run build
```

`frontend/package.json` 声明了 `npm test`，当前仓库已有 `frontend/tests/rbac-ui.test.mjs`；涉及前端行为或 API 契约时运行该测试，并同时运行生产构建。新增测试文件时保持 `frontend/tests/*.test.mjs` 命名约定。

### 技能与路由

```powershell
python reverse-skills/skills/scripts/refresh-skill-index.py
python reverse-skills/skills/scripts/verify-skill-suite.py --strict-index
```

涉及 PowerShell 治理脚本时，在 Windows 环境补充相应的 routing coherence 和 routing tests。

### 发布门禁

发布相关改动至少覆盖 Go 全量测试、前端构建、`tests/test_platform_backup.py` 和对应 P10/P11 验收脚本。真实验收会写入 `reports/`；不要在普通代码改动中复用历史报告冒充当前通过。

### 收尾

```powershell
git diff --check
```

最终说明运行了哪些验证、哪些未运行及原因。

## Issue Tracker

Issues 使用 GitHub Issues，外部 PR 不作为需求入口。创建、读取、评论和关闭 Issue 的具体约定见 `docs/agents/issue-tracker.md`。

## Domain Docs

本仓库采用 single-context 布局：先读根目录 `CONTEXT.md`，按改动读取 `docs/adr/`。术语、文档消费方式和 ADR 冲突处理见 `docs/agents/domain.md`。
