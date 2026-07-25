# P10 多用户、持久化与部署恢复验收

验收日期：2026-07-25

## 已实现能力

- 生产模式强制使用 PostgreSQL 与认证；数据库不可用时 readiness 降级，不回退到文件存储。
- 数据库迁移按连续版本在事务与 advisory lock 下执行，当前迁移版本为 8。
- workspace、用户、API token、实验、事件、知识、provider、artifact 和审计数据均执行租户隔离。
- 迁移 006 在数据库层保护维护冻结：INSERT 检查 NEW，DELETE 检查 OLD，UPDATE 同时检查 OLD 与 NEW；跨 workspace 移动任一侧冻结都会以 SQLSTATE `55000` 拒绝。
- 迁移 007 提供可恢复审计 outbox，保存 event ID、主体、角色、来源 IP、动作、资源、结果、状态码、详情和 request ID。
- 迁移 008 为 `audit_outbox` 安装直接基于 `workspace_id` 的 OLD/NEW 维护冻结 guard；`audit_events` 与 outbox 在冻结期间均禁止写入，投递不能更新 `delivered_at`。
- outbox 消费使用 `FOR UPDATE SKIP LOCKED`，按 event ID 幂等投递；服务启动与审计响应提交前均尝试重放，失败保留 pending 并使 `/readyz` 降级。
- execute、cancel、retry 的事务上下文已传入审计 trigger，业务变更与 outbox 记录同事务提交。
- 备份仅导出指定 workspace；恢复的 tenant CSV、`schema_migrations` 插入与校验、序列修复均在单个 psql 会话和单一事务中完成，任一步失败都会整体回滚。
- 生产 Compose 包含 PostgreSQL 健康检查、持久卷、非 root Web 用户、只读根文件系统、cap drop、tmpfs 和停止宽限期。
- 验收脚本记录 Git tree、二进制 diff、普通与 ignored 未跟踪文件内容组成的稳定 SHA-256；仅排除证据文件和明确生成/运行目录，且在证据中逐条记录 pattern、理由和文件数。验收前后摘要不同即失败。
- 验收临时容器使用随机精确名称，并在 finally 中通过 `docker rm -f <精确名称>` 清理，不影响现有容器。

## 自动验收结果

```text
go test ./... -count=1
passed

python -m pytest tests/test_platform_backup.py -q
4 passed

npm test -- --run
3 passed

npm run build
TypeScript + Vite production build passed

powershell -ExecutionPolicy Bypass -File scripts/accept_p10.ps1
status: passed
image_build: passed
postgres_migrations_isolation_recovery: passed
production_health: ready, storage=postgresql
backup_restore_staging: passed
two_workspace_isolation: restored=1, other=0, other secret absent
restore_transaction_fault_rollback: tenant_rows=0, migration_rows=0
dirty_content_untracked_change_detection: passed
```

真实 PostgreSQL 验收覆盖跨 workspace OLD/NEW 冻结拒绝、审计 outbox 重启重放、完整主体信息、单 event 幂等投递，以及冻结期间 `deliverAuditOutbox` 更新 `delivered_at` 被拒绝。备份恢复覆盖 staging 数据库与工作区；重复迁移版本故障注入发生在 tenant COPY 之后，并证明 tenant 与迁移账本均为 0 行。

## 可追溯证据

机器可读结果位于 `reports/p10-acceptance.json`，记录：

- Git HEAD、dirty 状态以及 `git-tree+binary-diff+all-untracked-sha256-v2` 内容摘要和带理由的排除清单；
- 镜像 ID、Docker/Go/Python/PostgreSQL 版本和随机端口；
- 备份 manifest SHA-256；
- 镜像构建、PostgreSQL 测试、租户备份和恢复命令的退出码与输出 SHA-256。

本次 live 验收状态为 `passed`，验收前后工作区内容摘要一致，随机验收容器无残留。

## 外部门禁

- GitHub/Google OAuth 的生产验收仍需部署方提供正式客户端凭据、域名和 TLS 证书。
- 真实授权样本、设备、调试器、模型凭据及完整行为对比属于后续源码重构验收；这些验证通过后才能设置 `complete_buildable`，不计入 P10 平台生产门禁。
