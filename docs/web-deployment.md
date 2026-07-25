# Go Web 服务部署

平台现在由一个 Go 服务统一提供 Web 前端、HTTP API、Flow 编排、事件、认证、Provider 管理和 worker 调度。Python 不再提供 Web 服务，只作为逆向分析执行内核，由 Go worker 在明确确认后调用。

## 本地运行

```powershell
npm run build --prefix frontend
$env:REVERSE_ANALYZER_WORKSPACE = "D:\Project\pe-reverse-analyzer-main"
$env:REVERSE_ANALYZER_FRONTEND_DIR = "D:\Project\pe-reverse-analyzer-main\frontend\dist"
go run ./cmd/reverse-analyzer-server
```

访问 `http://127.0.0.1:8090/`。

## 认证与权限

兼容模式使用 `REVERSE_ANALYZER_WEB_TOKEN`，该令牌拥有管理员权限。生产环境可在 `.reverse_analyzer/auth.json` 登记哈希令牌，并为令牌设置 `viewer`、`analyst` 或 `admin` 角色和工作区范围。

首次启用 PostgreSQL 时，必须设置一个非空 `REVERSE_ANALYZER_WEB_TOKEN` 作为管理员引导令牌。登录后可在“访问控制”页面签发数据库令牌；确认新管理员令牌可用后，可以移除环境引导令牌并重启服务。空数据库不会自动创建默认密码或绕过认证。

当前项目没有内置生产级登录认证页面、MFA 或完整 SSO 会话管理。Go 服务已实现 GitHub/Google OAuth 起始与回调接口：配置 `REVERSE_ANALYZER_GITHUB_CLIENT_ID`、`REVERSE_ANALYZER_GITHUB_CLIENT_SECRET` 或对应的 Google 变量，并通过 `REVERSE_ANALYZER_PUBLIC_URL` 指定公开回调地址后才会启用。OAuth 回调会签发平台令牌并交给前端保存；公网生产部署仍应继续使用统一身份网关和 TLS。

服务收到 `SIGINT` 或 `SIGTERM` 时会停止接收请求、取消运行中的 worker，并关闭 PostgreSQL 连接。Flow 事件通过带认证的 SSE 流实时送达前端，断开页面连接不会取消后台任务。

## Docker Compose

```powershell
docker compose up --build reverse-analyzer-web
```

默认只映射 `127.0.0.1:8090:8090`。没有完成反向代理、TLS 和认证配置前，不要直接把 8090 暴露到公网。

启用 PostgreSQL/pgvector 服务：

```powershell
docker compose --profile postgres up --build
```

例如：

```powershell
$env:REVERSE_ANALYZER_WEB_TOKEN = "replace-with-a-long-random-bootstrap-token"
$env:REVERSE_ANALYZER_DATABASE_URL = "postgres://reverse_analyzer:change-me@reverse-analyzer-postgres:5432/reverse_analyzer?sslmode=disable"
docker compose --profile postgres up --build
```

Provider 配置在“Provider 管理”页面维护，并存入当前工作区或 PostgreSQL。平台只保存密钥对应的环境变量名，不保存明文 API Key；实际密钥必须注入 Go 服务环境。连接测试由管理员显式触发，OpenAI-compatible 分析请求由 Go worker 传入受控 Python 分析引擎。

可使用同一数据库连接运行门控集成测试：

```powershell
$env:REVERSE_ANALYZER_DATABASE_URL = "postgres://reverse_analyzer:change-me@127.0.0.1:5433/reverse_analyzer?sslmode=disable"
go test ./cmd/reverse-analyzer-server -run PostgreSQL
```

## 隔离 worker

设置以下变量后，Go worker 会通过 Docker 或 Podman 启动受限分析容器：

```powershell
$env:REVERSE_ANALYZER_SANDBOX_RUNTIME = "docker"
$env:REVERSE_ANALYZER_SANDBOX_IMAGE = "reverse-analyzer:web"
```

容器默认丢弃 Linux capabilities、启用 `no-new-privileges`、禁用网络，并限制 CPU、内存、PID 和执行时间。Flow 仍需提交确认短语 `EXECUTE_LOCAL_ANALYSIS` 才会执行。

## 安全边界

- 上传文件只写入工作区，不自动执行。
- 路径必须位于配置的工作区内。
- 动态执行必须经过人工显式确认。
- 外部工具被发现不代表已经通过真实目标验收。
- 真实设备、驱动、证书、VLM 凭据和授权样本仍需要独立验收证据。
